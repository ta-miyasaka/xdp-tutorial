/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/seg6.h>
#include <linux/seg6_local.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// net/ipv6.h
#define NEXTHDR_ROUTING		43	/* Routing header. */

// The parsing helper functions from the packet01 lesson have moved here
#include "../common/parsing_helpers.h"

/* Defines xdp_stats_map */
#include "../common/xdp_stats_kern_user.h"
#include "../common/xdp_stats_kern.h"

/* Pops the outermost VLAN tag off the packet. Returns the popped VLAN ID on
 * success or -1 on failure.
 */
static __always_inline int vlan_tag_pop(struct xdp_md *ctx, struct ethhdr *eth)
{
	/*
	void *data_end = (void *)(long)ctx->data_end;
	struct ethhdr eth_cpy;
	struct vlan_hdr *vlh;
	__be16 h_proto;
	*/
	int vlid = -1;

	/* Check if there is a vlan tag to pop */

	/* Still need to do bounds checking */

	/* Save vlan ID for returning, h_proto for updating Ethernet header */

	/* Make a copy of the outer Ethernet header before we cut it off */

	/* Actually adjust the head pointer */

	/* Need to re-evaluate data *and* data_end and do new bounds checking
	 * after adjusting head
	 */

	/* Copy back the old Ethernet header and update the proto type */


	return vlid;
}

/* Pushes a new VLAN tag after the Ethernet header. Returns 0 on success,
 * -1 on failure.
 */
static __always_inline int vlan_tag_push(struct xdp_md *ctx,
					 struct ethhdr *eth, int vlid)
{
	return 0;
}

/* Implement assignment 1 in this section */
SEC("xdp_port_rewrite")
int xdp_port_rewrite_func(struct xdp_md *ctx)
{
	int action = XDP_PASS;
	int eth_type, ip_type;
	struct ethhdr *eth;
	struct iphdr *iphdr;
	struct ipv6hdr *ipv6hdr;
	struct udphdr *udphdr;
	struct tcphdr *tcphdr;
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct hdr_cursor nh = { .pos = data };

	eth_type = parse_ethhdr(&nh, data_end, &eth);
	if (eth_type < 0) {
		action = XDP_ABORTED;
		goto out;
	}

	if (eth_type == bpf_htons(ETH_P_IP)) {
		ip_type = parse_iphdr(&nh, data_end, &iphdr);
	} else if (eth_type == bpf_htons(ETH_P_IPV6)) {
		ip_type = parse_ip6hdr(&nh, data_end, &ipv6hdr);
	} else {
		goto out;
	}

	if (ip_type == IPPROTO_UDP) {
		if (parse_udphdr(&nh, data_end, &udphdr) < 0) {
			action = XDP_ABORTED;
			goto out;
		}
		udphdr->dest = bpf_htons(bpf_ntohs(udphdr->dest) - 1);
	} else if (ip_type == IPPROTO_TCP) {
		if (parse_tcphdr(&nh, data_end, &tcphdr) < 0) {
			action = XDP_ABORTED;
			goto out;
		}
		tcphdr->dest = bpf_htons(bpf_ntohs(tcphdr->dest) - 1);
	}

out:
	return xdp_stats_record_action(ctx, action);
}

/* VLAN swapper; will pop outermost VLAN tag if it exists, otherwise push a new
 * one with ID 1. Use this for assignments 2 and 3.
 */
SEC("xdp_vlan_swap")
int xdp_vlan_swap_func(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;

	/* These keep track of the next header type and iterator pointer */
	struct hdr_cursor nh;
	int nh_type;
	nh.pos = data;

	struct ethhdr *eth;
	nh_type = parse_ethhdr(&nh, data_end, &eth);
	if (nh_type < 0)
		return XDP_PASS;

	/* Assignment 2 and 3 will implement these. For now they do nothing */
	if (proto_is_vlan(eth->h_proto))
		vlan_tag_pop(ctx, eth);
	else
		vlan_tag_push(ctx, eth, 1);

	return XDP_PASS;
}

/* SRv6 Encapsulation */
static __always_inline int srv6_encapsulation(struct xdp_md *ctx, struct ethhdr *eth)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct ethhdr eth_cpy;
	struct ipv6hdr *inner_ipv6;
	struct iphdr *inner_ipv4;
	struct ipv6hdr *outer_ipv6;
	struct ipv6_sr_hdr *srh;
	struct in6_addr *first_sid;

	struct in6_addr outer_src_ipv6 = {
		.in6_u = {
			.u6_addr8 = {
			0x20, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			}
		}
	};
	struct in6_addr outer_dst_ipv6 = {
		.in6_u = {
			.u6_addr8 = {
			0x20, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
			}
		}
	};

	__u8 srh_next_proto;
	__u8 srh_len;
	__be16 inner_len;

	if (eth->h_proto == bpf_htons(ETH_P_IP)){
		inner_ipv4 = eth + 1;
		inner_len = bpf_ntohs(inner_ipv4->tot_len);
		srh_next_proto = IPPROTO_IPIP;
	}else if (eth->h_proto == bpf_htons(ETH_P_IPV6))
	{
		inner_ipv6 = eth + 1;
		inner_len = bpf_ntohs(inner_ipv6->payload_len);
		srh_next_proto = IPPROTO_IPV6;
	}else
	{
		return -1;
	}

	/* First copy the original Ethernet header */
	__builtin_memcpy(&eth_cpy, eth, sizeof(eth_cpy));

	// Add the SRv6 encapsulation field
	// In this implementation only support one SID contained in SRH
	srh_len = sizeof(struct ipv6_sr_hdr) + sizeof(struct in6_addr) * 1;

	if(bpf_xdp_adjust_head(ctx, 0 - (int)(sizeof(struct ip6hdr)+srh_len))
		return -1;

	/* Need to re-evaluate data_end and data after head adjustment, and
	 * bounds check, even though we know there is enough space (as we
	 * increased it).
	 */
	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;
	eth = data;

	outer_ipv6 = eth + 1;
	srh = outer_ipv6 + 1;
	first_sid = srh + 1;

	/* Copy the original ether header to the new SRv6 packet */
	__builtin_memcpy(eth, &eth_cpy, sizeof(eth_cpy));
	eth->h_proto = bpf_htons(ETH_P_IPV6);

	/* Create the outer IPv6 header */
	outer_ipv6->version = 6;
	outer_ipv6->priority = 0;
	outer_ipv6->nexthdr = NEXTHDR_ROUTING;
	outer_ipv6->hop_limit = 64;
	outer_ipv6->payload_len = bpf_htons(srh_len + inner_len);
	outer_ipv6->daaddr = outer_dst_ipv6;
	outer_ipv6->saaddr = outer_src_ipv6;

	/* Create the SRH */
	srh->nexthdr = srh_next_proto;
	srh->hdrlen = (srh_len / 8 - 1);
	srh->type = 4;
	srh->segments_left = 0;
	srh->first_segment = 0;
	srh->flags = 0;

	__builtin_memcpy(first_sid, &outer_dst_ipv6, sizeof(struct in6_addr));
	
	return 0;
}

/* Solution to the parsing exercise in lesson packet01. Handles VLANs and legacy
 * IP (via the helpers in parsing_helpers.h).
 */
SEC("xdp_packet_parser")
int  xdp_parser_func(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;

	/* Default action XDP_PASS, imply everything we couldn't parse, or that
	 * we don't want to deal with, we just pass up the stack and let the
	 * kernel deal with it.
	 */
	__u32 action = XDP_PASS; /* Default action */

	/* These keep track of the next header type and iterator pointer */
	struct hdr_cursor nh;
	int nh_type;
	nh.pos = data;

	struct ethhdr *eth;

	/* Packet parsing in steps: Get each header one at a time, aborting if
	 * parsing fails. Each helper function does sanity checking (is the
	 * header type in the packet correct?), and bounds checking.
	 */
	nh_type = parse_ethhdr(&nh, data_end, &eth);

	if (nh_type == bpf_htons(ETH_P_IPV6)) {
		struct ipv6hdr *ip6h;
		struct icmp6hdr *icmp6h;

		nh_type = parse_ip6hdr(&nh, data_end, &ip6h);
		if (nh_type != IPPROTO_ICMPV6)
			goto out;

		nh_type = parse_icmp6hdr(&nh, data_end, &icmp6h);
		if (nh_type != ICMPV6_ECHO_REQUEST)
			goto out;

		if (bpf_ntohs(icmp6h->icmp6_sequence) % 2 == 0)
			action = XDP_DROP;

	} else if (nh_type == bpf_htons(ETH_P_IP)) {
		struct iphdr *iph;
		struct icmphdr *icmph;

		nh_type = parse_iphdr(&nh, data_end, &iph);
		if (nh_type != IPPROTO_ICMP)
			goto out;

		nh_type = parse_icmphdr(&nh, data_end, &icmph);
		if (nh_type != ICMP_ECHO)
			goto out;

		if (bpf_ntohs(icmph->un.echo.sequence) % 2 == 0)
			action = XDP_DROP;
	}
 out:
	return xdp_stats_record_action(ctx, action);
}

/* Solution to the parsing exercise in lesson packet01. Handles VLANs and legacy
 * IP (via the helpers in parsing_helpers.h).
 */
SEC("srv6_encapsulation")
int  xdp_srv6_encapsulation(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;

	/* Default action XDP_PASS, imply everything we couldn't parse, or that
	 * we don't want to deal with, we just pass up the stack and let the
	 * kernel deal with it.
	 */
	__u32 action = XDP_PASS; /* Default action */

	/* These keep track of the next header type and iterator pointer */
	struct hdr_cursor nh;
	int nh_type;
	nh.pos = data;

	struct ethhdr *eth;

	/* Packet parsing in steps: Get each header one at a time, aborting if
	 * parsing fails. Each helper function does sanity checking (is the
	 * header type in the packet correct?), and bounds checking.
	 */
	nh_type = parse_ethhdr(&nh, data_end, &eth);

	if (nh_type == bpf_htons(ETH_P_IPV6)) {
		struct ipv6hdr *ip6h;
		struct icmp6hdr *icmp6h;

		if (srv6_encapsulation(ctx,eth)<0) {
			action = XDP_DROP;
			goto out;
		}

	} else if (nh_type == bpf_htons(ETH_P_IP)) {
		struct iphdr *iph;
		struct icmphdr *icmph;

		nh_type = parse_iphdr(&nh, data_end, &iph);
		if (nh_type != IPPROTO_ICMP)
			goto out;

		nh_type = parse_icmphdr(&nh, data_end, &icmph);
		if (nh_type != ICMP_ECHO)
			goto out;

		if (bpf_ntohs(icmph->un.echo.sequence) % 2 == 0)
			action = XDP_DROP;
	}
 out:
	return xdp_stats_record_action(ctx, action);
}

char _license[] SEC("license") = "GPL";
