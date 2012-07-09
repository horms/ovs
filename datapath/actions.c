/*
 * Copyright (c) 2007-2012 Nicira, Inc.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/skbuff.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/openvswitch.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in6.h>
#include <linux/if_arp.h>
#include <linux/if_vlan.h>
#include <net/ip.h>
#include <net/checksum.h>
#include <net/dsfield.h>

#include "checksum.h"
#include "datapath.h"
#include "vlan.h"
#include "vport.h"

static int do_execute_actions(struct datapath *dp, struct sk_buff *skb,
			const struct nlattr *attr, int len, bool keep_skb);

static int make_writable(struct sk_buff *skb, int write_len)
{
	if (!skb_cloned(skb) || skb_clone_writable(skb, write_len))
		return 0;

	return pskb_expand_head(skb, 0, 0, GFP_ATOMIC);
}

/* remove VLAN header from packet and update csum accrodingly. */
static int __pop_vlan_tci(struct sk_buff *skb, __be16 *current_tci)
{
	struct vlan_hdr *vhdr;
	int err;

	err = make_writable(skb, VLAN_ETH_HLEN);
	if (unlikely(err))
		return err;

	if (get_ip_summed(skb) == OVS_CSUM_COMPLETE)
		skb->csum = csum_sub(skb->csum, csum_partial(skb->data
					+ ETH_HLEN, VLAN_HLEN, 0));

	vhdr = (struct vlan_hdr *)(skb->data + ETH_HLEN);
	*current_tci = vhdr->h_vlan_TCI;

	memmove(skb->data + VLAN_HLEN, skb->data, 2 * ETH_ALEN);
	__skb_pull(skb, VLAN_HLEN);

	vlan_set_encap_proto(skb, vhdr);
	skb->mac_header += VLAN_HLEN;
	skb_reset_mac_len(skb);

	return 0;
}

static int pop_vlan(struct sk_buff *skb)
{
	__be16 tci;
	int err;

	if (likely(vlan_tx_tag_present(skb))) {
		vlan_set_tci(skb, 0);
	} else {
		if (unlikely((skb->protocol != htons(ETH_P_8021Q) &&
					  skb->protocol != htons(ETH_P_8021AD)) ||
					  skb->len < VLAN_ETH_HLEN))
			return 0;

		err = __pop_vlan_tci(skb, &tci);
		if (err)
			return err;
	}
	/* move next vlan tag to hw accel tag */
	if (likely((skb->protocol != htons(ETH_P_8021Q) &&
				skb->protocol != htons(ETH_P_8021AD)) ||
				skb->len < VLAN_ETH_HLEN))
		return 0;

	err = __pop_vlan_tci(skb, &tci);
	if (unlikely(err))
		return err;

	__vlan_hwaccel_put_tag(skb, ntohs(tci));
	return 0;
}

static int push_vlan(struct sk_buff *skb, const struct ovs_action_push_vlan *vlan)
{
	if (unlikely(vlan_tx_tag_present(skb))) {
		u16 current_tag;

		/* push down current VLAN tag */
		current_tag = vlan_tx_tag_get(skb);

		if (skb->protocol == htons(ETH_P_8021AD)) {
			if (!__vlan_put_qinq_tag(skb, current_tag))
				return -ENOMEM;
		} else {
			if (!__vlan_put_tag(skb, current_tag))
				return -ENOMEM;
		}

		if (get_ip_summed(skb) == OVS_CSUM_COMPLETE)
			skb->csum = csum_add(skb->csum, csum_partial(skb->data
					+ ETH_HLEN, VLAN_HLEN, 0));

	}
	__vlan_hwaccel_put_tag(skb, ntohs(vlan->vlan_tci) & ~VLAN_TAG_PRESENT);
	vlan_set_tpid(skb, vlan->vlan_tpid);
	return 0;
}

/* Get mpls tc from mpls label stack entry. */
u8 mpls_lse_to_tc(__be32 mpls_lse)
{
	return (ntohl(mpls_lse) & MPLS_TC_MASK) >> MPLS_TC_SHIFT;
}

/* Get mpls ttl from mpls label stack entry. */
u8 mpls_lse_to_ttl(__be32 mpls_lse)
{
	return (ntohl(mpls_lse) & MPLS_TTL_MASK) >> MPLS_TTL_SHIFT;
}

/* Determine where MPLS header starts
 * assumes mac_header is already set. */
static char *get_mpls_hdr(const struct sk_buff *skb)
{
	struct ethhdr *eth;
	int nh_ofs;
	__be16 dl_type = 0;

	eth = eth_hdr(skb);
	nh_ofs = sizeof(struct ethhdr);
	if (likely(ntohs(eth->h_proto) >= ETH_TYPE_MIN))
		dl_type = eth->h_proto;

	/* Check for a VLAN tag. */
	while ((dl_type == htons(ETH_P_8021Q) ||
			dl_type == htons(ETH_P_8021AD)) &&
			skb->len >= nh_ofs + sizeof(struct vlan_hdr)) {
		struct vlan_hdr *vh = (struct vlan_hdr*)(skb->data + nh_ofs);
		dl_type = vh->h_vlan_encapsulated_proto;
		nh_ofs += sizeof(struct vlan_hdr);
	}

	return skb_mac_header(skb) + nh_ofs;
}

/* Determine where second MPLS header starts
 * assumes mac_header is already set. */
static char *get_next_mpls_hdr(const struct sk_buff *skb)
{
	struct ethhdr *eth;
	int nh_ofs;
	__be16 dl_type = 0;

	eth = eth_hdr(skb);
	nh_ofs = sizeof(struct ethhdr);
	if (likely(ntohs(eth->h_proto) >= ETH_TYPE_MIN))
		dl_type = eth->h_proto;

	/* Check for a VLAN tag. */
	while ((dl_type == htons(ETH_P_8021Q) ||
			dl_type == htons(ETH_P_8021AD)) &&
			skb->len >= nh_ofs + sizeof(struct vlan_hdr)) {
		struct vlan_hdr *vh = (struct vlan_hdr*)(skb->data + nh_ofs);
		dl_type = vh->h_vlan_encapsulated_proto;
		nh_ofs += sizeof(struct vlan_hdr);
	}

	if ((dl_type == htons(ETH_P_MPLS_UC) ||
		 dl_type == htons(ETH_P_MPLS_MC)) &&
		 skb->len >= nh_ofs + sizeof(struct mpls_hdr)) {
		nh_ofs += sizeof(struct mpls_hdr);
	}

	return skb_mac_header(skb) + nh_ofs;
}

/* Get ethertype from the header. */
static __be16 get_ethertype(struct sk_buff *skb)
{
	struct ethhdr *eth = eth_hdr(skb);
	__be16 eth_type = htons(0);
	if (likely(ntohs(eth->h_proto) >= ETH_TYPE_MIN)) {
		if (eth->h_proto == htons(ETH_P_8021Q) ||
			eth->h_proto == htons(ETH_P_8021AD)) {
			eth_type = *(__be16 *)(get_mpls_hdr(skb) - 2);
			return eth_type;
		} else {
			return eth->h_proto;
		}
	} else {
		return eth_type;
	}
}

/* Set ethertype in the header. */
static void set_ethertype(struct sk_buff *skb, __be16 eth_type)
{
	struct ethhdr *eth = eth_hdr(skb);
	if (likely(ntohs(eth->h_proto) >= ETH_TYPE_MIN)) {
		if (eth->h_proto != htons(ETH_P_8021Q) &&
			eth->h_proto != htons(ETH_P_8021AD)) {
			skb->protocol = eth->h_proto = eth_type;
        } else {
			/* 2 bytes before L2.5(MPLS) or L3 header is the
			 * original ethertype.
			 */
			memcpy((void *)(get_mpls_hdr(skb) - 2), (void *)&eth_type, 2);
		}
	}
}

/* Set outermost MPLS ttl of the MPLS Label stack. */
static void
set_mpls_lse_ttl(__be32 *mpls_lse, __be32 ttl)
{
    *mpls_lse &= ~htonl(MPLS_TTL_MASK);
    *mpls_lse |= ttl & htonl(MPLS_TTL_MASK);
}

/* Get mpls label from mpls label stack entry. */
static u32 mpls_lse_to_label(__be32 mpls_lse)
{
	return (ntohl(mpls_lse) & MPLS_LABEL_MASK) >> MPLS_LABEL_SHIFT;
}

/* Set mpls lse values. */
static void set_mpls_lse_values(__be32 *value, u8 ttl, u8 tos,
								u32 label, u8 stack)
{
	*value =  htonl((stack << MPLS_STACK_SHIFT) |
					(ttl << MPLS_TTL_SHIFT) |
					(tos << MPLS_TC_SHIFT) |
					(label << MPLS_LABEL_SHIFT));
}

/* Get ttl, tos and label associated with L3/L2.5. */
static void get_label_ttl_and_tos(struct sk_buff *skb, __be16 eth_type,
								  u8 *ttl, u8 *tos, u32 *label)
{
	__be32 mpls_lse = htonl(0);

	switch (ntohs(eth_type)) {
	case ETH_P_IP:
		*ttl = ip_hdr(skb)->ttl;
		*tos = (ipv4_get_dsfield(ip_hdr(skb)) >> 2) & 0x07;
		*label = 0; /* IPV4 Explicit NULL label */
	    break;

	case ETH_P_IPV6:
		*ttl = ipv6_hdr(skb)->hop_limit;
		*tos = ipv6_get_dsfield(ipv6_hdr(skb)) & 0x07;
		*label = 2; /* IPV6 Explicit NULL label */
	    break;

	case ETH_P_MPLS_UC:
	case ETH_P_MPLS_MC:
		mpls_lse = *((__be32 *)get_mpls_hdr(skb));
		*ttl = mpls_lse_to_ttl(mpls_lse);
		*tos = mpls_lse_to_tc(mpls_lse);
		*label = mpls_lse_to_label(mpls_lse);
	    break;

	default:
		*ttl = 64;
		*tos = 0;
		*label = 0;
	    break;
	}
}

/* Remove the top label in the MPLS label stack. */
static void pop_mpls_lse(struct sk_buff *skb, struct mpls_hdr *mpls_h)
{
	u32 offset = (uintptr_t)get_mpls_hdr(skb) - (uintptr_t)skb->data;

	/* Move everything up to L2.5 up 4 bytes. */
	memmove((void *)skb->data + sizeof(struct mpls_hdr), skb->data, offset);

	/* Pull offset + size. */
	skb_pull(skb, sizeof(struct mpls_hdr));

	/* Reset poniter to L2. */
	skb_reset_mac_header(skb);
}

/* Add an MPLS label to the top off the label stack. */
static int push_mpls_lse(struct sk_buff *skb, struct mpls_hdr *mpls_h)
{
	/* Bytes before L2.5. */
	u32 offset = (uintptr_t)get_mpls_hdr(skb) - (uintptr_t)skb->data;

	/* Make sure there's room. */
	if (skb_cow_head(skb, MPLS_HLEN) < 0) {
		kfree_skb(skb);
		return 1;
	}

	/* Make room for new label by adding 4 bytes. */
	skb_push(skb, MPLS_HLEN);

	/* Reset pointer to L2. */
	skb_reset_mac_header(skb);

	/* Move L2 header + vlan(if any) to make room for new label. */
	memmove((void *)skb->data, (void *)skb->data + MPLS_HLEN, offset);

	*((__be32*)get_mpls_hdr(skb)) = mpls_h->mpls_lse;
	return 0;
}

/* Pop MPLS header from a packet. */
static int pop_mpls(struct sk_buff *skb,
                    __be16 pop_ethertype)
{
	struct ethhdr *eth;
	struct mpls_hdr mpls_h;
	__be16 eth_proto;

	eth_proto = get_ethertype(skb);

	eth = eth_hdr(skb);
	if (eth_proto == htons(ETH_P_MPLS_UC) ||
		eth_proto == htons(ETH_P_MPLS_MC)) {

		/* Grab the MLPS label at the top of the stack. */
		mpls_h.mpls_lse = *((__be32*)get_mpls_hdr(skb));
		pop_mpls_lse(skb, &mpls_h);

		if (mpls_h.mpls_lse & htonl(MPLS_STACK_MASK)) {
			set_ethertype(skb, pop_ethertype);
		}
		/* Calculate csum since mpls label stack entry is modified. */
		if (get_ip_summed(skb) == OVS_CSUM_COMPLETE) {
			skb->csum = csum_sub(skb->csum,
						csum_partial(skb->data + ETH_HLEN, MPLS_HLEN, 0));
		}
	}
	return 0;
}

/* Push a new MPLS header onto packet. */
static int push_mpls(struct sk_buff *skb,
                     __be16 push_ethertype)
{
	struct mpls_hdr mpls_h;
	__be16 eth_proto;
	u32 label;
	u8 ttl, tos;

	eth_proto = get_ethertype(skb);

	get_label_ttl_and_tos(skb, eth_proto, &ttl, &tos, &label);

	/* First check whether there is another label on the stack. */
	if (eth_proto == htons(ETH_P_MPLS_UC) ||
		eth_proto == htons(ETH_P_MPLS_MC)) {
		set_mpls_lse_values(&mpls_h.mpls_lse, ttl, tos, label, 0);
	} else {
		/* IPV4/IPv6, VLAN, QinQ or could be vpls. */
		set_mpls_lse_values(&mpls_h.mpls_lse, ttl, tos, label, 1);
	}

	/* push the new label. */
	if (!push_mpls_lse(skb, &mpls_h)) {
		/* Also change the Ethertype to MPLS. */
		set_ethertype(skb, push_ethertype);
		/* Calculate csum since mpls label stack entry is modified. */
		if (get_ip_summed(skb) == OVS_CSUM_COMPLETE) {
			skb->csum = csum_sub(skb->csum,
						csum_partial(skb->data + ETH_HLEN, MPLS_HLEN, 0));
		}
		return 0;
	}
	return 1;
}

/* Change MPLS label stack entry. */
static int set_mpls_lse(struct sk_buff *skb, __be32 mpls_lse)
{
	__be16 eth_proto;
	eth_proto = get_ethertype(skb);

	if (eth_proto == htons(ETH_P_MPLS_UC) ||
		eth_proto == htons(ETH_P_MPLS_MC)) {

		*((__be32 *)get_mpls_hdr(skb)) = mpls_lse;
		/* Update checksum since mple label stack entry is modified. */
		if (get_ip_summed(skb) == OVS_CSUM_COMPLETE) {
			skb->csum = csum_sub(skb->csum,
						csum_partial(skb->data + ETH_HLEN, MPLS_HLEN, 0));
		}
	}

	return 0;
}

/* Decrement MPLS TTL in the packet. */
static int dec_mpls_ttl(struct sk_buff *skb, u8 new_ttl)
{
	struct mpls_hdr mpls_h;
	__be16 eth_proto;

	eth_proto = get_ethertype(skb);

	if (eth_proto == htons(ETH_P_MPLS_UC) ||
		eth_proto == htons(ETH_P_MPLS_MC)) {

		mpls_h.mpls_lse = *((__be32 *)get_mpls_hdr(skb));
		set_mpls_lse_ttl(&mpls_h.mpls_lse, htonl(new_ttl));
		*((__be32 *)get_mpls_hdr(skb)) = mpls_h.mpls_lse;

		/* Calculate csum since mpls label stack entry is modified. */
		if (get_ip_summed(skb) == OVS_CSUM_COMPLETE) {
			skb->csum = csum_sub(skb->csum,
						csum_partial(skb->data + ETH_HLEN, MPLS_HLEN, 0));
		}
	}
	return 0;
}

/* Helper function to copy MPLS TTL inwards. */
static void copy_ttl_in(struct sk_buff *skb, u8 new_ttl)
{
	struct mpls_hdr mpls_nh;
	mpls_nh.mpls_lse = *((__be32 *)get_next_mpls_hdr(skb));
	set_mpls_lse_ttl(&mpls_nh.mpls_lse, htonl(new_ttl));
	*((__be32 *)get_next_mpls_hdr(skb)) = mpls_nh.mpls_lse;
}

/* Copy MPLS TTL into IP/MPLS TTL. */
static int copy_mpls_ttl_in(struct sk_buff *skb, u8 new_ttl)
{
	struct mpls_hdr mpls_h;
	__be16 eth_proto;

	eth_proto = get_ethertype(skb);

	if (eth_proto == htons(ETH_P_MPLS_UC) ||
		eth_proto == htons(ETH_P_MPLS_MC)) {
		mpls_h.mpls_lse = *((__be32 *)get_mpls_hdr(skb));
		if (mpls_h.mpls_lse & htonl(MPLS_STACK_MASK)) {
			if (ip_hdr(skb)->version == 4) {
				csum_replace2(&ip_hdr(skb)->check, htons(ip_hdr(skb)->ttl << 8),
							  htons(new_ttl << 8));
				ip_hdr(skb)->ttl = new_ttl;
			} else if (ipv6_hdr(skb)->version == 6) {
				ipv6_hdr(skb)->hop_limit = new_ttl;
			}
		} else {
			copy_ttl_in(skb, new_ttl);
		}
		/* Calculate csum since mpls label stack entry is modified. */
		if (get_ip_summed(skb) == OVS_CSUM_COMPLETE) {
			skb->csum = csum_sub(skb->csum,
						csum_partial(skb->data + ETH_HLEN, MPLS_HLEN, 0));
		}
	}
	return 0;
}

/* Copy IP/MPLS TTL into outer MPLS header. */
static int copy_mpls_ttl_out(struct sk_buff *skb, u8 new_ttl)
{
	struct mpls_hdr mpls_h;
	__be16 eth_proto;

	eth_proto = get_ethertype(skb);

	if (eth_proto == htons(ETH_P_MPLS_UC) ||
		eth_proto == htons(ETH_P_MPLS_MC)) {
		mpls_h.mpls_lse = *((__be32 *)get_mpls_hdr(skb));
		set_mpls_lse_ttl(&mpls_h.mpls_lse, htonl(new_ttl));
		*((__be32 *)get_mpls_hdr(skb)) = mpls_h.mpls_lse;

		/* Calculate csum since mpls label stack entry is modified. */
		if (get_ip_summed(skb) == OVS_CSUM_COMPLETE) {
			skb->csum = csum_sub(skb->csum,
						csum_partial(skb->data + ETH_HLEN, MPLS_HLEN, 0));
		}
	}
	return 0;
}

static int set_eth_addr(struct sk_buff *skb,
			const struct ovs_key_ethernet *eth_key)
{
	int err;
	err = make_writable(skb, ETH_HLEN);
	if (unlikely(err))
		return err;

	memcpy(eth_hdr(skb)->h_source, eth_key->eth_src, ETH_ALEN);
	memcpy(eth_hdr(skb)->h_dest, eth_key->eth_dst, ETH_ALEN);

	return 0;
}

static void set_ip_addr(struct sk_buff *skb, struct iphdr *nh,
				__be32 *addr, __be32 new_addr)
{
	int transport_len = skb->len - skb_transport_offset(skb);

	if (nh->protocol == IPPROTO_TCP) {
		if (likely(transport_len >= sizeof(struct tcphdr)))
			inet_proto_csum_replace4(&tcp_hdr(skb)->check, skb,
						 *addr, new_addr, 1);
	} else if (nh->protocol == IPPROTO_UDP) {
		if (likely(transport_len >= sizeof(struct udphdr))) {
			struct udphdr *uh = udp_hdr(skb);

			if (uh->check ||
			    get_ip_summed(skb) == OVS_CSUM_PARTIAL) {
				inet_proto_csum_replace4(&uh->check, skb,
							 *addr, new_addr, 1);
				if (!uh->check)
					uh->check = CSUM_MANGLED_0;
			}
		}
	}

	csum_replace4(&nh->check, *addr, new_addr);
	skb_clear_rxhash(skb);
	*addr = new_addr;
}

static void set_ip_ttl(struct sk_buff *skb, struct iphdr *nh, u8 new_ttl)
{
	csum_replace2(&nh->check, htons(nh->ttl << 8), htons(new_ttl << 8));
	nh->ttl = new_ttl;
}

static int set_ipv4(struct sk_buff *skb, const struct ovs_key_ipv4 *ipv4_key)
{
	struct iphdr *nh;
	int err;

	err = make_writable(skb, skb_network_offset(skb) +
				 sizeof(struct iphdr));
	if (unlikely(err))
		return err;

	nh = ip_hdr(skb);

	if (ipv4_key->ipv4_src != nh->saddr)
		set_ip_addr(skb, nh, &nh->saddr, ipv4_key->ipv4_src);

	if (ipv4_key->ipv4_dst != nh->daddr)
		set_ip_addr(skb, nh, &nh->daddr, ipv4_key->ipv4_dst);

	if (ipv4_key->ipv4_tos != nh->tos)
		ipv4_change_dsfield(nh, 0, ipv4_key->ipv4_tos);

	if (ipv4_key->ipv4_ttl != nh->ttl)
		set_ip_ttl(skb, nh, ipv4_key->ipv4_ttl);

	return 0;
}

/* Must follow make_writable() since that can move the skb data. */
static void set_tp_port(struct sk_buff *skb, __be16 *port,
			 __be16 new_port, __sum16 *check)
{
	inet_proto_csum_replace2(check, skb, *port, new_port, 0);
	*port = new_port;
	skb_clear_rxhash(skb);
}

static void set_udp_port(struct sk_buff *skb, __be16 *port, __be16 new_port)
{
	struct udphdr *uh = udp_hdr(skb);

	if (uh->check && get_ip_summed(skb) != OVS_CSUM_PARTIAL) {
		set_tp_port(skb, port, new_port, &uh->check);

		if (!uh->check)
			uh->check = CSUM_MANGLED_0;
	} else {
		*port = new_port;
		skb_clear_rxhash(skb);
	}
}

static int set_udp(struct sk_buff *skb, const struct ovs_key_udp *udp_port_key)
{
	struct udphdr *uh;
	int err;

	err = make_writable(skb, skb_transport_offset(skb) +
				 sizeof(struct udphdr));
	if (unlikely(err))
		return err;

	uh = udp_hdr(skb);
	if (udp_port_key->udp_src != uh->source)
		set_udp_port(skb, &uh->source, udp_port_key->udp_src);

	if (udp_port_key->udp_dst != uh->dest)
		set_udp_port(skb, &uh->dest, udp_port_key->udp_dst);

	return 0;
}

static int set_tcp(struct sk_buff *skb, const struct ovs_key_tcp *tcp_port_key)
{
	struct tcphdr *th;
	int err;

	err = make_writable(skb, skb_transport_offset(skb) +
				 sizeof(struct tcphdr));
	if (unlikely(err))
		return err;

	th = tcp_hdr(skb);
	if (tcp_port_key->tcp_src != th->source)
		set_tp_port(skb, &th->source, tcp_port_key->tcp_src, &th->check);

	if (tcp_port_key->tcp_dst != th->dest)
		set_tp_port(skb, &th->dest, tcp_port_key->tcp_dst, &th->check);

	return 0;
}

static int do_output(struct datapath *dp, struct sk_buff *skb, int out_port)
{
	struct vport *vport;

	if (unlikely(!skb))
		return -ENOMEM;

	vport = ovs_vport_rcu(dp, out_port);
	if (unlikely(!vport)) {
		kfree_skb(skb);
		return -ENODEV;
	}

	ovs_vport_send(vport, skb);
	return 0;
}

static int output_userspace(struct datapath *dp, struct sk_buff *skb,
			    const struct nlattr *attr)
{
	struct dp_upcall_info upcall;
	const struct nlattr *a;
	int rem;

	upcall.cmd = OVS_PACKET_CMD_ACTION;
	upcall.key = &OVS_CB(skb)->flow->key;
	upcall.userdata = NULL;
	upcall.pid = 0;

	for (a = nla_data(attr), rem = nla_len(attr); rem > 0;
		 a = nla_next(a, &rem)) {
		switch (nla_type(a)) {
		case OVS_USERSPACE_ATTR_USERDATA:
			upcall.userdata = a;
			break;

		case OVS_USERSPACE_ATTR_PID:
			upcall.pid = nla_get_u32(a);
			break;
		}
	}

	return ovs_dp_upcall(dp, skb, &upcall);
}

static int sample(struct datapath *dp, struct sk_buff *skb,
		  const struct nlattr *attr)
{
	const struct nlattr *acts_list = NULL;
	const struct nlattr *a;
	int rem;

	for (a = nla_data(attr), rem = nla_len(attr); rem > 0;
		 a = nla_next(a, &rem)) {
		switch (nla_type(a)) {
		case OVS_SAMPLE_ATTR_PROBABILITY:
			if (net_random() >= nla_get_u32(a))
				return 0;
			break;

		case OVS_SAMPLE_ATTR_ACTIONS:
			acts_list = a;
			break;
		}
	}

	return do_execute_actions(dp, skb, nla_data(acts_list),
						 nla_len(acts_list), true);
}

static int execute_set_action(struct sk_buff *skb,
				 const struct nlattr *nested_attr)
{
	int err = 0;

	switch (nla_type(nested_attr)) {
	case OVS_KEY_ATTR_PRIORITY:
		skb->priority = nla_get_u32(nested_attr);
		break;

	case OVS_KEY_ATTR_TUN_ID:
		OVS_CB(skb)->tun_id = nla_get_be64(nested_attr);
		break;

	case OVS_KEY_ATTR_ETHERNET:
		err = set_eth_addr(skb, nla_data(nested_attr));
		break;

	case OVS_KEY_ATTR_IPV4:
		err = set_ipv4(skb, nla_data(nested_attr));
		break;

	case OVS_KEY_ATTR_TCP:
		err = set_tcp(skb, nla_data(nested_attr));
		break;

	case OVS_KEY_ATTR_UDP:
		err = set_udp(skb, nla_data(nested_attr));
		break;
	}

	return err;
}

/* Execute a list of actions against 'skb'. */
static int do_execute_actions(struct datapath *dp, struct sk_buff *skb,
			const struct nlattr *attr, int len, bool keep_skb)
{
	/* Every output action needs a separate clone of 'skb', but the common
	 * case is just a single output action, so that doing a clone and
	 * then freeing the original skbuff is wasteful.  So the following code
	 * is slightly obscure just to avoid that. */
	int prev_port = -1;
	const struct nlattr *a;
	int rem;

	for (a = attr, rem = len; rem > 0;
	     a = nla_next(a, &rem)) {
		int err = 0;

		if (prev_port != -1) {
			do_output(dp, skb_clone(skb, GFP_ATOMIC), prev_port);
			prev_port = -1;
		}

		switch (nla_type(a)) {
		case OVS_ACTION_ATTR_OUTPUT:
			prev_port = nla_get_u32(a);
			break;

		case OVS_ACTION_ATTR_USERSPACE:
			output_userspace(dp, skb, a);
			break;

		case OVS_ACTION_ATTR_PUSH_VLAN:
			err = push_vlan(skb, nla_data(a));
			if (unlikely(err)) /* skb already freed. */
				return err;
			break;

		case OVS_ACTION_ATTR_POP_VLAN:
			err = pop_vlan(skb);
			break;

		case OVS_ACTION_ATTR_PUSH_MPLS:
			err = push_mpls(skb, nla_get_be16(a));
			if (unlikely(err)) /* skb already freed. */
				return err;
			break;

		case OVS_ACTION_ATTR_POP_MPLS:
			err = pop_mpls(skb, nla_get_be16(a));
			break;

		case OVS_ACTION_ATTR_SET_MPLS_LSE:
			err = set_mpls_lse(skb, nla_get_be32(a));
			break;

		case OVS_ACTION_ATTR_DEC_MPLS_TTL:
			err = dec_mpls_ttl(skb, nla_get_u8(a));
			break;

		case OVS_ACTION_ATTR_COPY_TTL_IN:
			err = copy_mpls_ttl_in(skb, nla_get_u8(a));
			break;

		case OVS_ACTION_ATTR_COPY_TTL_OUT:
			err = copy_mpls_ttl_out(skb, nla_get_u8(a));
			break;

		case OVS_ACTION_ATTR_SET:
			err = execute_set_action(skb, nla_data(a));
			break;

		case OVS_ACTION_ATTR_SAMPLE:
			err = sample(dp, skb, a);
			break;
		}

		if (unlikely(err)) {
			kfree_skb(skb);
			return err;
		}
	}

	if (prev_port != -1) {
		if (keep_skb)
			skb = skb_clone(skb, GFP_ATOMIC);

		do_output(dp, skb, prev_port);
	} else if (!keep_skb)
		consume_skb(skb);

	return 0;
}

/* We limit the number of times that we pass into execute_actions()
 * to avoid blowing out the stack in the event that we have a loop. */
#define MAX_LOOPS 5

struct loop_counter {
	u8 count;		/* Count. */
	bool looping;		/* Loop detected? */
};

static DEFINE_PER_CPU(struct loop_counter, loop_counters);

static int loop_suppress(struct datapath *dp, struct sw_flow_actions *actions)
{
	if (net_ratelimit())
		pr_warn("%s: flow looped %d times, dropping\n",
				ovs_dp_name(dp), MAX_LOOPS);
	actions->actions_len = 0;
	return -ELOOP;
}

/* Execute a list of actions against 'skb'. */
int ovs_execute_actions(struct datapath *dp, struct sk_buff *skb)
{
	struct sw_flow_actions *acts = rcu_dereference(OVS_CB(skb)->flow->sf_acts);
	struct loop_counter *loop;
	int error;

	/* Check whether we've looped too much. */
	loop = &__get_cpu_var(loop_counters);
	if (unlikely(++loop->count > MAX_LOOPS))
		loop->looping = true;
	if (unlikely(loop->looping)) {
		error = loop_suppress(dp, acts);
		kfree_skb(skb);
		goto out_loop;
	}

	OVS_CB(skb)->tun_id = 0;
	error = do_execute_actions(dp, skb, acts->actions,
					 acts->actions_len, false);

	/* Check whether sub-actions looped too much. */
	if (unlikely(loop->looping))
		error = loop_suppress(dp, acts);

out_loop:
	/* Decrement loop counter. */
	if (!--loop->count)
		loop->looping = false;

	return error;
}
