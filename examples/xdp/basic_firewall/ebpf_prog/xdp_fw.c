// Copyright (c) 2019 Dropbox, Inc.
// Full license can be found in the LICENSE file.

// Basic XDP firewall (IPv4 blacklisting)
//

#include "bpf_helpers.h"
#include "bpf_endian.h"

#define MAX_RULES   16

enum {
       BPF_F_NO_PREALLOC = (1U << 0),
};

struct ip4_trie_key {
       __u32 prefixlen;
       __u8 addr[4];
};


// Ethernet header
struct ethhdr {
  __u8 h_dest[6];
  __u8 h_source[6];
  __u16 h_proto;
} __attribute__((packed));

// IPv4 header
struct iphdr {
  __u8 ihl : 4;
  __u8 version : 4;
  __u8 tos;
  __u16 tot_len;
  __u16 id;
  __u16 frag_off;
  __u8 ttl;
  __u8 protocol;
  __u16 check;
  __u32 saddr;
  __u32 daddr;
} __attribute__((packed));

// TCP header
struct tcphdr {
  __u16 source;
  __u16 dest;
  __u32 seq;
  __u32 ack_seq;
  union {
    struct {
      // Field order has been converted LittleEndiand -> BigEndian
      // in order to simplify flag checking (no need to ntohs())
      __u16 ns : 1,
      reserved : 3,
      doff : 4,
      fin : 1,
      syn : 1,
      rst : 1,
      psh : 1,
      ack : 1,
      urg : 1,
      ece : 1,
      cwr : 1;
    };
  };
  __u16 window;
  __u16 check;
  __u16 urg_ptr;
};

BPF_MAP_DEF(blacklist) = {
    .map_type = BPF_MAP_TYPE_LPM_TRIE,
    .key_size = sizeof(struct ip4_trie_key),
    .value_size = sizeof(__u32),
    .max_entries = MAX_RULES,
    .map_flags = BPF_F_NO_PREALLOC,
    .persistent_path = "/sys/fs/bpf/blacklist",
};
BPF_MAP_ADD(blacklist);

BPF_MAP_DEF(dvbs) = {
    .map_type = BPF_MAP_TYPE_LPM_TRIE,
    .key_size = sizeof(struct ip4_trie_key),
    .value_size = sizeof(__u32),
    .max_entries = MAX_RULES,
    .map_flags = BPF_F_NO_PREALLOC,
};
BPF_MAP_ADD(dvbs);

// XDP program //
SEC("xdp")
int firewall(struct xdp_md *ctx) {
  void *data_end = (void *)(long)ctx->data_end;
  void *data = (void *)(long)ctx->data;

  // Only IPv4 supported for this example
  struct ethhdr *ether = data;
  if (data + sizeof(*ether) > data_end) {
    // Malformed Ethernet header
    return XDP_ABORTED;
  }

  if (ether->h_proto != 0x08U) {  // htons(ETH_P_IP) -> 0x08U
    // Non IPv4 traffic
    return XDP_PASS;
  }

  data += sizeof(*ether);
  struct iphdr *ip = data;
  if (data + sizeof(*ip) > data_end) {
    // Malformed IPv4 header
    return XDP_ABORTED;
  }

    // L4
  if (ip->protocol != 0x06) {  // IPPROTO_TCP -> 6
    // Non TCP
    return XDP_PASS;
  }
  data += ip->ihl * 4;
  struct tcphdr *tcp = data;
  if (data + sizeof(*tcp) > data_end) {
    return XDP_ABORTED;
  }

  struct {
    __u32 prefixlen;
    __u32 saddr;
  } key;

  key.prefixlen = 32;
  key.saddr = ip->saddr;

  __u64 *blocked = 0;

  // Lookup SRC IP in blacklisted IPs
  if (tcp->dest == bpf_htons(8080)) { // block port 8080
	if ( !(blocked = bpf_map_lookup_elem(&blacklist, &key)) )
		return XDP_DROP;
	else if ( ! (blocked = bpf_map_lookup_elem(&dvbs, &key)) )
		return XDP_DROP;
 }

  return XDP_PASS;
}

char _license[] SEC("license") = "GPLv2";
