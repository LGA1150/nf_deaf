Netfilter: Desynchronizing Evasion Against Filters

A tool to inject a bogus request into a TCP stream, useful for evading IDS.

Usage:
1. Build and install the module.  
[How to Build External Modules](https://www.kernel.org/doc/html/latest/kbuild/modules.html)
2. Customize the inject buffer at `/sys/kernel/debug/nf_deaf/buf`. You can use `vi` or `cat`.
3. Use iptables or nftables to mark the packet to be processed
   mark format: `0xdeafNNNN`, where:
   `[31:16]` - the magic number `0xdeaf`  
   `[15]` - whether to corrupt ACK SEQ  
   `[14]` - whether to corrupt SEQ  
   `[13]` - whether to corrupt TCP checksum  
   `[12:10]` - send the injected packets for `<num>` more times  
   `[9:5]` - delay the original packets for `<num>` jiffies  
   `[4:0]` - TTL of injected packets  

[:heart: Support my work on GitHub Sponsors](https://github.com/sponsors/LGA1150)
