#include <assert.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/pkt_cls.h>
#include <linux/types.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <stdbool.h>

#include "bpf_endian.h"
#include "bpf_helpers.h"
#include "helpers.h"

struct bpf_elf_map SEC("maps") DEBUGS_MAP = {
    .type = BPF_MAP_TYPE_ARRAY,
    .size_key = sizeof(unsigned int),
    .size_value = sizeof(bool),
    .pinning = PIN_GLOBAL_NS,
    .max_elem = 1,
};

/*
 * Check whether the debug flag is set via user space.
 */
bool is_debug(void);

forced_inline bool is_debug() {
  int index = 0;  // the map has size of 1 so index is always 0
  bool *value = (bool *)bpf_map_lookup_elem(&DEBUGS_MAP, &index);
  if (!value) {
    return false;
  }
  return *value;
}

#define bpf_debug_printk(fmt, ...)                               \
  ({                                                             \
    if (unlikely(is_debug())) {                                  \
      char ____fmt[] = fmt;                                      \
      bpf_trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__); \
    }                                                            \
  })

/*
 * The Internet Protocol (IP) is defined in RFC 791.
 * The RFC specifies the format of the IP header.
 * In the header there is the IHL (Internet Header Length) field which is 4bit
 * long
 * and specifies the header length in 32bit words.
 * The IHL field can hold values from 0 (Binary 0000) to 15 (Binary 1111).
 * 15 * 32bits = 480bits = 60 bytes
 */
#define MAX_IP_HDR_LEN 60

static_assert(sizeof(struct ethhdr) == ETH_HLEN,
              "ethernet header size does not match.");

/*
 * Since packet handling and printk can be interleaved, this will
 * add a unique identifier for an individual invocation so you can grep the
 * request identifier and see the log messags in isolation.
 *
 * This is a macro because in a real-example you might want to make this
 * a no-op for non-debug builds to avoid the cost of the call.
 */
#define DEBUG(x, ...) bpf_debug_printk(x, ##__VA_ARGS__)

#define DEBUG_ENCAP(id, x, ...) DEBUG("[encap][%u]" x, id, ##__VA_ARGS__)

/*
 * Entry point for the encapsulation & decapsulation eBPF
 * __sk_buff is a "shadow" struct of the internal sk_buff.
 * You can read more about how sk_buff works at:
 * http://vger.kernel.org/~davem/skb_data.html
 * @skb the socket buffer struct
 */
int ipip_encap_filter(struct __sk_buff *skb);

static __always_inline int get_sport(void *data, void *data_end,
                                     __u8 protocol) {
  struct tcphdr *th;
  struct udphdr *uh;

  switch (protocol) {
    case IPPROTO_TCP:
      th = (struct tcphdr *)data;
      if ((void *)(th + 1) > data_end) return -1;
      return th->source;
    case IPPROTO_UDP:
      uh = (struct udphdr *)data;
      if ((void *)(uh + 1) > data_end) return -1;
      return uh->source;
    default:
      return 0;
  }
}

SEC("ipip_encap") int ipip_encap_filter(struct __sk_buff *skb) {
  // Generate a unique request id so we can identify each flow in
  // the trace logs
  unsigned long long request_id = bpf_get_prandom_u32();

  /*
   * the redundant casts are needed according to the documentation.
   * possibly for the BPF verifier.
   * https://www.spinics.net/lists/xdp-newbies/msg00181.html
   */
  void *data_end = (void *)(long)skb->data_end;
  void *data = (void *)(long)skb->data;
  struct iphdr *iph = (struct iphdr *)(data);

  if ((void *)(iph + 1) > data_end) {
    DEBUG_ENCAP(request_id, "socket buffer struct was malformed.\n");
    return BPF_DROP;
  }

  DEBUG_ENCAP(request_id, "casted to ip header.\n");

  // multiply ip header by 4 (bytes) to get the number of bytes of the header.
  int iph_len = iph->ihl << 2;
  if (iph_len > MAX_IP_HDR_LEN) {
    DEBUG_ENCAP(request_id, "ip header is too long: %d\n", iph_len);
    return BPF_DROP;
  }

  DEBUG_ENCAP(request_id, "calculated ip header length.\n");

  int sport = get_sport(iph, data_end, iph->protocol);
  if (sport == -1) return BPF_DROP;

  // if (iph->daddr != htonl(0xac1f03c8)) return TC_ACT_OK;

  if (sport == 22)  // SSH
    return BPF_OK;

  struct iphdr outer_iph = {0};
  int err;

  outer_iph.ihl = 5;
  outer_iph.version = 4;
  outer_iph.ttl = 0x40;
  outer_iph.protocol = IPPROTO_IPIP;
  outer_iph.saddr = iph->saddr;
  outer_iph.daddr = bpf_htonl(0xac1f012b);
  outer_iph.tot_len = bpf_htons((__u16)skb->len + sizeof(outer_iph));

  err =
      bpf_lwt_push_encap(skb, BPF_LWT_ENCAP_IP, &outer_iph, sizeof(outer_iph));
  if (err) return BPF_DROP;

  return BPF_LWT_REROUTE;
}

static char _license[] SEC("license") = "GPL";
