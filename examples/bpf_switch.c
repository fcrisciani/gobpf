#include <bcc/proto.h>

struct eth_key {
  u64 mac;
};
struct ip_key {
  u32 ip;
};

#define ETH_ARP 0x0806

BPF_HASH(mac2if, struct eth_key, int);
BPF_HASH(ip2mac, struct ip_key, struct eth_key);

int handle_egress(struct __sk_buff *skb) {
  bpf_trace_printk("egress");
  u8 *cursor = 0;
  struct ethernet_t *ethernet = cursor_advance(cursor, sizeof(*ethernet));

  bpf_trace_printk("egress got packet from %x to %x proto %x\n",
                   ethernet->src, ethernet->dst, ethernet->type);
  struct eth_key l2dst = {ethernet->dst};
  if (l2dst.mac == 0xffFFffFFffFF && ethernet->type == ETH_ARP) {
    // try to resolve the destination by ip
    struct arp_t *arp = cursor_advance(cursor, sizeof(*arp));
    struct ip_key target_ip = {arp->tpa};
    struct eth_key* l = ip2mac.lookup(&target_ip);
    if (l) {
      bpf_trace_printk("egress FOUND arp destination %d\n", *l);
      // rewrite destination mac
      l2dst.mac = l->mac;
    } else {
      bpf_trace_printk("egress FAILED arp\n");
      return 1;
    }
  }

	int* v = mac2if.lookup(&l2dst);
	if (v) {
		bpf_trace_printk("egress lookup GOOD send to %d\n", *v);
		bpf_clone_redirect(skb, *v, 0/*egress*/);
	} else {
		bpf_trace_printk("egress lookup FAILED send to 2\n");
		//bpf_clone_redirect(skb, 2, 1/*ingress*/);
	}

  return 1;
}
