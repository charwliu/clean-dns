#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_pppox.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <linux/ipv6.h>
#include <linux/ip.h>
#include <linux/pkt_cls.h>
#include <stdint.h>
#include <stdbool.h>

#define _AA (1 << 10)
#define _AD (1 << 5)
#define PPP_IP (0x21)
#define PPP_IP6 (0x57)

char __license[] SEC("license") = "GPL";

/* Map for blocking IP addresses from userspace */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(key_size, sizeof(__u32));
    __type(value,  sizeof(__u32));
    __uint(max_entries, 1);
} flowlabel_map SEC(".maps");

/* Ingress hook - handle incoming packets */
SEC("tc")
int tc_ingress(struct __sk_buff *skb) {
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;
    uint16_t daddr16[8],saddr16[8];
    int h_proto, l4proto;

    int hdrsize = sizeof(struct ethhdr);
    if (data + hdrsize > data_end) {
        return TC_ACT_SHOT;
    }
    struct ethhdr *eth = data;
    h_proto = bpf_ntohs(eth->h_proto); 

    if (h_proto == ETH_P_PPP_SES) {
	struct pppoe_hdr *pppoe;
	pppoe = (void*)(eth + 1);
	if ((void*)pppoe + PPPOE_SES_HLEN > data_end) {
            return TC_ACT_SHOT;
	}
	h_proto = bpf_ntohs(pppoe->tag[0].tag_type);
	switch (h_proto) {
	case PPP_IP:
	    h_proto = ETH_P_IP;
	    break;
	case PPP_IP6:
	    h_proto = ETH_P_IPV6;
	    break;
	default:
	    return TC_ACT_OK;
	}
	hdrsize += PPPOE_SES_HLEN;
    } else if (h_proto == ETH_P_PPP_DISC) {
        return TC_ACT_OK;
    }

    if (h_proto == ETH_P_IP) {
        struct iphdr iph;
        bpf_skb_load_bytes(skb, hdrsize, &iph, sizeof(struct iphdr));

        l4proto = iph.protocol;
	uint32_t saddr = iph.saddr;
        int iphsize = iph.ihl * 4;
	int ipid = iph.id;
	int frag_off = iph.frag_off;

	if (l4proto != IPPROTO_UDP) {
	    return TC_ACT_OK;
	}
        if (saddr != 0x08080808 && saddr != 0x04040808) {
	    return TC_ACT_OK;
	}
	// drop if id is 0
	if (ipid == 0) {
	    bpf_printk("[ingress]*** dropped due to id == 0: %0x", saddr);
	    return TC_ACT_SHOT;
	}
	// drop if flag is 0x40 (Don't fragment)
        if (frag_off & 0x40) {
            bpf_printk("[ingress]*** dropped due to flag is 0x40: %0x", frag_off);
	    return TC_ACT_SHOT;
        }
	hdrsize += iphsize;
    } else if (h_proto == ETH_P_IPV6) {
        struct ipv6hdr ip6h;
        bpf_skb_load_bytes(skb, hdrsize, &ip6h, sizeof(struct ipv6hdr));
        l4proto = ip6h.nexthdr;
        if (l4proto != IPPROTO_UDP) {
            return TC_ACT_OK;
        }
        uint32_t flowlabel = (uint32_t)(ip6h.flow_lbl[0]) << 16 | (uint32_t)(ip6h.flow_lbl[1]) << 8 | (uint32_t)(ip6h.flow_lbl[2]);
        for (int i = 0; i < 8; i++) {
            daddr16[i] = bpf_ntohs(ip6h.daddr.in6_u.u6_addr16[i]);
            saddr16[i] = bpf_ntohs(ip6h.saddr.in6_u.u6_addr16[i]);
        }
        if (saddr16[7] != 0x8888 && saddr16[7] != 0x8844) {
            return TC_ACT_OK;
        }
        uint32_t key = ((uint32_t)daddr16[7])<<16 | (uint32_t)saddr16[7];
        void* rec = bpf_map_lookup_elem(&flowlabel_map, &key);
        if (rec) {
	    if (flowlabel == *(uint32_t*)rec) {
	    	bpf_printk("[ingress]*** dropped due to flowlabel duplicated: %0lx", *(uint32_t*)rec);
		return TC_ACT_SHOT;	
	    }
        }
        if (flowlabel == 0) {
    	    bpf_printk("[ingress]*** dropped due to flowlable is zero: flowlabel: %0lx", flowlabel) ;
	    return TC_ACT_SHOT;	
        }
        hdrsize += sizeof(struct ipv6hdr);
    } else {
        return TC_ACT_OK;
    }
    struct udphdr udph;
    bpf_skb_load_bytes(skb, hdrsize, &udph, sizeof(struct udphdr));
    
    if (udph.source != bpf_htons(53)) {
        return TC_ACT_OK;
    }
    uint8_t *udp_data = (uint8_t*)(long)((&udph) + 1);
    uint8_t *udp_end = (uint8_t*) (long)(skb->data_end);
    if (udp_data + 10 > udp_end) {
        return TC_ACT_OK;
    }
    // pass if the dns packet has multiple answers
    if (udp_data[6] != 0 || udp_data[7] > 1) {
        // Answer RRs != 1
        return TC_ACT_OK;
    }
    // pass if the dns packet has authority answer
    if (udp_data[8] != 0 || udp_data[9] != 0) {
        // Authority RRs != 0
        return TC_ACT_OK;
    }
    uint16_t flags = ((uint16_t)udp_data[2])<<8 | (uint16_t)(udp_data[3]);
    // drop if dns flag has Authoritative mark
    if (flags & _AA) {
        bpf_printk("[ingress]*** dropped due to flags has authoriative mark: %0x", flags);
        return TC_ACT_SHOT;
    }

    return TC_ACT_OK;
}

/* Egress hook - handle outgoing packets */
SEC("tc")
int tc_egress(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    int i, h_proto, l4proto;
    uint16_t daddr16[8],saddr16[8];
    struct pppoe_hdr *pppoe;

    int hdrsize = sizeof(struct ethhdr);
    if (data + hdrsize > data_end) {
        return TC_ACT_SHOT;
    }
    struct ethhdr *eth = data;
    h_proto = bpf_ntohs(eth->h_proto); 

    if (h_proto == ETH_P_PPP_SES) {
	pppoe = (void*)(eth + 1);
	if ((void*)pppoe + PPPOE_SES_HLEN > data_end) {
	   return TC_ACT_SHOT;
	}
	h_proto = bpf_ntohs(pppoe->tag[0].tag_type);
	switch (h_proto) {
	case PPP_IP:
	    h_proto = ETH_P_IP;
	    break;
	case PPP_IP6:
	    h_proto = ETH_P_IPV6;
	    break;
	default:
            return TC_ACT_OK;
	}
	hdrsize += PPPOE_SES_HLEN;
    } else if (h_proto == ETH_P_PPP_DISC) {
        return TC_ACT_OK;
    }

    if (h_proto != ETH_P_IPV6) {
        return TC_ACT_OK;
    }

    struct ipv6hdr ip6h;

    bpf_skb_load_bytes(skb, hdrsize, &ip6h, sizeof(struct ipv6hdr));
    l4proto = ip6h.nexthdr;
    if (l4proto != IPPROTO_UDP) {
        return TC_ACT_OK;
    }
    uint32_t flowlabel = (uint32_t)(ip6h.flow_lbl[0]) << 16 | (uint32_t)(ip6h.flow_lbl[1]) << 8 | (uint32_t)(ip6h.flow_lbl[2]);
    for (i = 0; i < 8; i++) {
        daddr16[i] = bpf_ntohs(ip6h.daddr.in6_u.u6_addr16[i]);
        saddr16[i] = bpf_ntohs(ip6h.saddr.in6_u.u6_addr16[i]);
    }

    if (daddr16[7] != 0x8888 && daddr16[7] != 0x8844) {
        return TC_ACT_OK;
    }
    uint32_t key = ((uint32_t)saddr16[7])<<16 | (uint32_t)daddr16[7];
    if (bpf_map_update_elem(&flowlabel_map, &key, &flowlabel, BPF_NOEXIST) == 0 ) {
        bpf_printk("[egress] google dst: [%0x:%0x:%0x:%0x:%0x:%0x:%0x:%0x]: flowlabel: %0lx",
           daddr16[0], daddr16[1], daddr16[2], daddr16[3],
           daddr16[4], daddr16[5], daddr16[6], daddr16[7], flowlabel) ;
    }
    return TC_ACT_OK;
}

SEC("xdp")
int clean_dns(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth;
    struct ipv6hdr *ip6h;
    struct iphdr *iph;
    struct udphdr *udph;
    uint16_t flags;
    uint32_t saddr;
    uint16_t saddr16[8];
    uint16_t daddr16[8];
    int i;

    int h_proto, l4proto;

    /* Parse Ethernet and IP/IPv6 headers */
    int hdrsize = sizeof(struct ethhdr);
    if (data + hdrsize > data_end) {
	return XDP_DROP;
    }
    eth = data;
    h_proto = bpf_ntohs(eth->h_proto); 

    if (h_proto == ETH_P_PPP_SES) {
	struct pppoe_hdr *pppoe;
	pppoe = (void*)(eth + 1);
	if ((void*)pppoe + PPPOE_SES_HLEN > data_end) {
	   return XDP_DROP;
	}
	h_proto = bpf_ntohs(pppoe->tag[0].tag_type);
	switch (h_proto) {
	case PPP_IP:
	    h_proto = ETH_P_IP;
	    break;
	case PPP_IP6:
	    h_proto = ETH_P_IPV6;
	    break;
	default:
            return XDP_PASS;
	}
	hdrsize += PPPOE_SES_HLEN;
    } else if (h_proto == ETH_P_PPP_DISC) {
        return XDP_PASS;
    }

    if (h_proto == ETH_P_IP) {
        iph = data + hdrsize;
        if ((void*)(iph + 1) > data_end) {
            return XDP_DROP;
        }
        hdrsize = iph->ihl * 4;
        /* Sanity check packet field is valid */
        if (hdrsize < sizeof(struct iphdr)) {
            return XDP_DROP;
        }
        /* Variable-length IPv4 header, need to use byte-based arithmetic */
        if ((void*)iph + hdrsize > data_end) {
            return XDP_DROP;
        }
        l4proto = iph->protocol;

        if (l4proto != IPPROTO_UDP) {
            return XDP_PASS;
        }
	saddr = iph->saddr;
        if (saddr != 0x08080808 && saddr != 0x04040808) {
            return XDP_PASS;
        }
        // drop if id is 0
        if (iph->id == 0) {
            bpf_printk("[xdp]*** dropped due to id is zero: %0x", iph->saddr);
            return XDP_DROP;
        }
        // drop if flag is 0x40 (Don't fragment)
        if (iph->frag_off & 0x40) {
            bpf_printk("[xdp]*** dropped duto to flag is DF: %0x", iph->frag_off);
	    return XDP_DROP;
        }
    } else if (h_proto == ETH_P_IPV6)  {
        ip6h = data + hdrsize;
        if ((void*)(ip6h + 1) > data_end) {
	    return XDP_DROP;
        }
        l4proto = ip6h->nexthdr;
        if (l4proto != IPPROTO_UDP) {
            return XDP_PASS;
        }
	for (i = 0; i < 8; i ++) {
	    daddr16[i] = bpf_ntohs(ip6h->daddr.in6_u.u6_addr16[i]);
            saddr16[i] = bpf_ntohs(ip6h->saddr.in6_u.u6_addr16[i]);
	}
	uint32_t flowlabel = (uint32_t)(ip6h->flow_lbl[0]) << 16 | (uint32_t)(ip6h->flow_lbl[1]) << 8 | (uint32_t)(ip6h->flow_lbl[2]);

        if (saddr16[7] != 0x8888 && saddr16[7] != 0x8844) {
            return XDP_PASS;
        }

        uint32_t key = ((uint32_t)daddr16[7])<<16 | (uint32_t)saddr16[7];
        void* rec = bpf_map_lookup_elem(&flowlabel_map, &key);
        if (rec) {
	    if (flowlabel == *(uint32_t*)rec) {
	    	bpf_printk("[xdp]*** dropped due to flowlabel duplicated: %0lx", *(uint32_t*)rec);
	        return XDP_DROP;
	    }
        }
	if (flowlabel == 0) {
            bpf_printk("[xdp]*** dropped due to flowlabel is zero: %0x", flowlabel);
	    return XDP_DROP;
	}
	hdrsize = sizeof(struct ipv6hdr);
    } else {
        return XDP_PASS;
    }

    udph = data + hdrsize;
    if ((void*)(udph + 1) > data_end) {
        return XDP_PASS;
    }

    if (bpf_ntohs(udph->len) - sizeof(struct udphdr) < 0) {
        return XDP_PASS;
    }

    if (udph->source != bpf_htons(53)) {
        return XDP_PASS;
    }

    // get first 10 bytes of udp data (7,8 is Answer RRs, 8, 9 is Authority RRs)
    uint8_t *udp_data = (uint8_t *)(long)(udph+1);
    uint8_t *udp_data_end = (uint8_t *)(long)ctx->data_end;
    if (udp_data + 10 > udp_data_end) {
        return XDP_DROP;
    }
    // pass if the dns packet has multiple answers
    if (udp_data[6] != 0 || udp_data[7] > 1) {
        // Answer RRs != 1
        return XDP_PASS;
    }
    // pass if the dns packet has authority answer
    if (udp_data[8] != 0 || udp_data[9] != 0) {
        // Authority RRs != 0
        return XDP_PASS;
    } 
    flags = ((uint16_t)udp_data[2])<<8 | (uint16_t)(udp_data[3]);
    // bpf_printk("flags = %0x", flags);
    // drop if dns flag has Authoritative mark
    if (flags & _AA) {
        bpf_printk("[xdp]*** dropped due to flags has authoriative mark: %0x", flags);
        return XDP_DROP;
    }
    return XDP_PASS;
}

