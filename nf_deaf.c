#define pr_fmt(fmt) "%s: " fmt, __func__

#include <linux/bitfield.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>

#define MARK_MAGIC	GENMASK(31, 16)
#define MARK_WR_ACKSEQ	BIT(15)
#define MARK_WR_SEQ	BIT(14)
#define MARK_WR_CHKSUM	BIT(13)
#define MARK_REPEAT	GENMASK(12, 10)
#define MARK_DELAY	GENMASK(9, 5)
#define MARK_TTL	GENMASK(4, 0)

#define PAYLOAD_LEN 42

struct nf_deaf_skb_cb {
	union {
		struct inet_skb_parm _4;
		struct inet6_skb_parm _6;
	};
	struct net *net;
	struct sock *sk;
	int (*okfn)(struct net *, struct sock *, struct sk_buff *);
};
#define NF_DEAF_SKB_CB(skb) ((struct nf_deaf_skb_cb *)(skb)->cb)

struct nf_deaf_timer {
	struct list_head list;
	struct timer_list timer;
};

static DEFINE_PER_CPU(struct nf_deaf_timer, skb_tx_timer);

static unsigned int
nf_deaf_postrouting_hook4(void *priv, struct sk_buff *skb,
			  const struct nf_hook_state *state);
static unsigned int
nf_deaf_postrouting_hook6(void *priv, struct sk_buff *skb,
			  const struct nf_hook_state *state);

static void
nf_deaf_tcp_init(struct tcphdr *th, const struct tcphdr *oth,
		 bool corrupt_seq, bool corrupt_ackseq)
{
	__be16 *data;

	th->source = oth->source;
	th->dest = oth->dest;
	if (corrupt_seq)
		th->seq = oth->seq ^ htonl(BIT(31));
	else
		th->seq = oth->seq;

	if (corrupt_ackseq)
		th->ack_seq = oth->ack_seq ^ htonl(BIT(31));
	else
		th->ack_seq = oth->ack_seq;

	th->res1 = 0;
	th->doff = 10;
	tcp_flag_byte(th) = tcp_flag_byte(oth);
	th->check = 0;
	th->urg_ptr = 0;

	data = (void *)th + sizeof(*th);
	*data = htons(0x1312);
}

static struct sk_buff *
nf_deaf_alloc_and_init_skb(const struct sk_buff *oskb, unsigned int l3hdrsize)
{
	struct dst_entry *dst;
	struct sk_buff *skb;

	skb = alloc_skb(LL_MAX_HEADER + l3hdrsize + PAYLOAD_LEN + 32, GFP_ATOMIC);
	if (unlikely(!skb))
		return NULL;

	skb_reserve(skb, LL_MAX_HEADER);
	__skb_put(skb, l3hdrsize + PAYLOAD_LEN);
	skb_copy_queue_mapping(skb, oskb);
	dst = dst_clone(skb_dst(oskb));
	skb->dev = dst->dev;
	skb_dst_set(skb, dst);
	skb_reset_network_header(skb);
	skb_set_transport_header(skb, l3hdrsize);

	return skb;
}

static int
nf_deaf_send_generated_skb(struct sk_buff *skb,
			   const struct nf_hook_state *state, u32 repeat)
{
	int i;

	for (i = 0; i < repeat; i++) {
		struct sk_buff *nskb;

		nskb = skb_clone(skb, GFP_ATOMIC);
		if (unlikely(!nskb))
			break;

		if (unlikely(state->okfn(state->net, state->sk, nskb)))
			break;
	}

	return state->okfn(state->net, state->sk, skb);
}

static void
nf_deaf_timer_resched(struct timer_list *timer, unsigned long tick)
{
	timer->expires = tick + jiffies;
	add_timer(timer);
}

static void
nf_deaf_enqueue_skb(struct sk_buff *skb, const struct nf_hook_state *state,
		    unsigned long delay)
{
	struct nf_deaf_timer *percpu_timer = this_cpu_ptr(&skb_tx_timer);
	struct timer_list *timer = &percpu_timer->timer;
	struct list_head *list = &percpu_timer->list;

	if (unlikely(list_empty(list)))
		nf_deaf_timer_resched(timer, delay);

	skb->skb_mstamp_ns = get_jiffies_64() + delay;
	BUILD_BUG_ON(sizeof(*NF_DEAF_SKB_CB(skb)) > sizeof(skb->cb));
	NF_DEAF_SKB_CB(skb)->net = state->net;
	NF_DEAF_SKB_CB(skb)->sk = state->sk;
	NF_DEAF_SKB_CB(skb)->okfn = state->okfn;
	list_add_tail(&skb->list, list);
}

static void
nf_deaf_send_queued_skb(struct sk_buff *skb)
{
#if IS_ENABLED(CONFIG_NF_CONNTRACK)
	struct net *net = NF_DEAF_SKB_CB(skb)->net;
	struct nf_hook_entries *entries;
	struct nf_hook_entry *entry;
	struct nf_hook_state state;
	unsigned int ret;

	switch (skb->protocol) {
	case htons(ETH_P_IP):
		entries = rcu_dereference(net->nf.hooks_ipv4[NF_INET_POST_ROUTING]);
		entry = &entries->hooks[entries->num_hook_entries - 1];
		if (entry->hook == nf_deaf_postrouting_hook4) {
			goto skip;
		} else {
			state.pf = NFPROTO_IPV4;
		}
		break;
	case htons(ETH_P_IPV6):
		entries = rcu_dereference(net->nf.hooks_ipv6[NF_INET_POST_ROUTING]);
		entry = &entries->hooks[entries->num_hook_entries - 1];
		if (entry->hook == nf_deaf_postrouting_hook6) {
			goto skip;
		} else {
			state.pf = NFPROTO_IPV6;
		}
		break;
	default:
		WARN_ON_ONCE(1);
		kfree_skb(skb);
		return;
	}
	state.hook = NF_INET_POST_ROUTING;
	state.in = skb->dev;
	state.out = skb_dst(skb)->dev;
	state.sk = NF_DEAF_SKB_CB(skb)->sk;
	state.net = NF_DEAF_SKB_CB(skb)->net;
	state.okfn = NF_DEAF_SKB_CB(skb)->okfn;
	ret = nf_hook_entry_hookfn(entry, skb, &state);
	switch (ret & NF_VERDICT_MASK) {
	case NF_ACCEPT:
		break;
	case NF_DROP:
	case NF_QUEUE:
		kfree_skb(skb);
		fallthrough;
	default:
		return;
	}

skip:
#endif	/* CONFIG_NF_CONNTRACK */
	NF_DEAF_SKB_CB(skb)->okfn(NF_DEAF_SKB_CB(skb)->net,
				  NF_DEAF_SKB_CB(skb)->sk, skb);
}

static void
nf_deaf_dequeue_skb(struct timer_list *timer)
{
	struct nf_deaf_timer *percpu_timer = from_timer(percpu_timer, timer, timer);
	struct list_head *list = &percpu_timer->list;
	struct sk_buff *skb, *tmp;
	u64 now;

	now = get_jiffies_64();
	list_for_each_entry_safe(skb, tmp, list, list) {
		if (unlikely(time_after64(skb->skb_mstamp_ns, now))) {
			nf_deaf_timer_resched(timer, skb->skb_mstamp_ns - now);
			break;
		}

		__list_del_entry(&skb->list);
		// Must set to NULL, or TC won't be happy
		skb->list.prev = NULL;
		skb->list.next = NULL;
		nf_deaf_send_queued_skb(skb);
	}
}

static int
nf_deaf_xmit4(const struct sk_buff *oskb, const struct iphdr *oiph,
	      const struct tcphdr *oth, const struct nf_hook_state *state)
{
	bool corrupt_checksum, corrupt_seq, corrupt_ackseq;
	struct sk_buff *skb;
	struct iphdr *iph;
	struct tcphdr *th;
	u32 repeat;
	u8 ttl;

	skb = nf_deaf_alloc_and_init_skb(oskb, sizeof(*iph));
	if (unlikely(!skb))
		return -ENOMEM;

	corrupt_checksum = oskb->mark & MARK_WR_CHKSUM;
	corrupt_seq = oskb->mark & MARK_WR_SEQ;
	corrupt_ackseq = oskb->mark & MARK_WR_ACKSEQ;
	ttl = FIELD_GET(MARK_TTL, oskb->mark);
	repeat = FIELD_GET(MARK_REPEAT, oskb->mark);
	skb->protocol = htons(ETH_P_IP);
	IPCB(skb)->iif = IPCB(oskb)->iif;
	IPCB(skb)->flags = IPCB(oskb)->flags;
	// copy old IP header, but change tot_len
	iph = ip_hdr(skb);
	*iph = *oiph;
	iph->check = 0;
	iph->ihl = 5;
	iph->tot_len = htons(sizeof(*iph) + PAYLOAD_LEN);
	iph->ttl = ttl ?: iph->ttl;
	iph->check = ip_fast_csum(iph, iph->ihl);

	th = (void *)iph + sizeof(*iph);
	nf_deaf_tcp_init(th, oth, corrupt_seq, corrupt_ackseq);

	th->check = ~tcp_v4_check(PAYLOAD_LEN, iph->saddr, iph->daddr, 0);
	if (corrupt_checksum)
		th->check++;

	skb->ip_summed = CHECKSUM_PARTIAL;
	skb->csum_start = (unsigned char *)th - skb->head;
	skb->csum_offset = offsetof(struct tcphdr, check);

	return nf_deaf_send_generated_skb(skb, state, repeat);
}

static int
nf_deaf_xmit6(const struct sk_buff *oskb, const struct ipv6hdr *oip6h,
	      const struct tcphdr *oth, const struct nf_hook_state *state)
{
	bool corrupt_checksum, corrupt_seq, corrupt_ackseq;
	struct sk_buff *skb;
	struct ipv6hdr *ip6h;
	struct tcphdr *th;
	u32 repeat;
	u8 ttl;

	skb = nf_deaf_alloc_and_init_skb(oskb, sizeof(*ip6h));
	if (unlikely(!skb))
		return -ENOMEM;

	corrupt_checksum = oskb->mark & MARK_WR_CHKSUM;
	corrupt_seq = oskb->mark & MARK_WR_SEQ;
	corrupt_ackseq = oskb->mark & MARK_WR_ACKSEQ;
	ttl = FIELD_GET(MARK_TTL, oskb->mark);
	repeat = FIELD_GET(MARK_REPEAT, oskb->mark);
	skb->protocol = htons(ETH_P_IPV6);
	IP6CB(skb)->iif = IP6CB(oskb)->iif;
	IP6CB(skb)->flags = IP6CB(oskb)->flags;
	// copy old IP header, but change payload_len
	ip6h = ipv6_hdr(skb);
	*ip6h = *oip6h;
	ip6h->payload_len = htons(PAYLOAD_LEN);
	ip6h->hop_limit = ttl ?: ip6h->hop_limit;

	th = (void *)ip6h + sizeof(*ip6h);
	nf_deaf_tcp_init(th, oth, corrupt_seq, corrupt_ackseq);
	th->check = csum_ipv6_magic(&ip6h->saddr, &ip6h->daddr, PAYLOAD_LEN,
				    IPPROTO_TCP, csum_partial(th, PAYLOAD_LEN,
							      0));
	if (corrupt_checksum)
		th->check++;

	return nf_deaf_send_generated_skb(skb, state, repeat);
}

static unsigned int
nf_deaf_postrouting_hook4(void *priv, struct sk_buff *skb,
			  const struct nf_hook_state *state)
{
	struct iphdr *iph;
	struct tcphdr *th;
	u32 delay;

	if (likely(FIELD_GET(MARK_MAGIC, skb->mark) != 0xdeaf))
		return NF_ACCEPT;

	iph = ip_hdr(skb);
	if (unlikely(iph->protocol != IPPROTO_TCP))
		return NF_ACCEPT;

	if (unlikely(iph->frag_off & htons(IP_MF | IP_OFFSET)))
		return NF_ACCEPT;

	if (unlikely(!pskb_may_pull(skb, skb_transport_offset(skb) + sizeof(*th))))
		return NF_DROP;

	iph = ip_hdr(skb);
	th = tcp_hdr(skb);

	if (unlikely(nf_deaf_xmit4(skb, iph, th, state)))
		return NF_DROP;

	delay = FIELD_GET(MARK_DELAY, skb->mark);
	if (unlikely(!delay))
		return NF_ACCEPT;

	nf_deaf_enqueue_skb(skb, state, delay);
	return NF_STOLEN;
}

static unsigned int
nf_deaf_postrouting_hook6(void *priv, struct sk_buff *skb,
			  const struct nf_hook_state *state)
{
	struct ipv6hdr *ip6h;
	struct tcphdr *th;
	u32 delay;

	if (likely(FIELD_GET(MARK_MAGIC, skb->mark) != 0xdeaf))
		return NF_ACCEPT;

	ip6h = ipv6_hdr(skb);
	if (unlikely(ip6h->nexthdr != NEXTHDR_TCP))
		return NF_ACCEPT;

	if (unlikely(!pskb_may_pull(skb, skb_transport_offset(skb) + sizeof(*th))))
		return NF_DROP;

	ip6h = ipv6_hdr(skb);
	th = tcp_hdr(skb);

	if (unlikely(nf_deaf_xmit6(skb, ip6h, th, state)))
		return NF_DROP;

	delay = FIELD_GET(MARK_DELAY, skb->mark);
	if (unlikely(!delay))
		return NF_ACCEPT;

	nf_deaf_enqueue_skb(skb, state, delay);
	return NF_STOLEN;
}

static const struct nf_hook_ops nf_deaf_postrouting_hooks[] = {
	{
		.hook		= nf_deaf_postrouting_hook4,
		.pf		= NFPROTO_IPV4,
		.hooknum	= NF_INET_POST_ROUTING,
		.priority	= NF_IP_PRI_CONNTRACK_CONFIRM - 1,
	},
	{
		.hook		= nf_deaf_postrouting_hook6,
		.pf		= NFPROTO_IPV6,
		.hooknum	= NF_INET_POST_ROUTING,
		.priority	= NF_IP6_PRI_LAST - 1,
	},
};

static int __init nf_deaf_init(void)
{
	int i;

	for_each_possible_cpu(i) {
		struct nf_deaf_timer *percpu_timer = per_cpu_ptr(&skb_tx_timer, i);

		INIT_LIST_HEAD(&percpu_timer->list);
		timer_setup(&percpu_timer->timer, nf_deaf_dequeue_skb, TIMER_PINNED);
	}

	return nf_register_net_hooks(&init_net, nf_deaf_postrouting_hooks, ARRAY_SIZE(nf_deaf_postrouting_hooks));
}
module_init(nf_deaf_init);

static void __exit nf_deaf_exit(void)
{
	int i;

	nf_unregister_net_hooks(&init_net, nf_deaf_postrouting_hooks, ARRAY_SIZE(nf_deaf_postrouting_hooks));

	for_each_possible_cpu(i)
		del_timer_sync(&per_cpu_ptr(&skb_tx_timer, i)->timer);
}
module_exit(nf_deaf_exit);

MODULE_LICENSE("GPL");