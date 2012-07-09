/*
 * Copyright (c) 2009, 2010, 2011, 2012 Nicira, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <config.h>
#include "packets.h"
#include <assert.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <stdlib.h>
#include "byte-order.h"
#include "csum.h"
#include "flow.h"
#include "dynamic-string.h"
#include "ofpbuf.h"

const struct in6_addr in6addr_exact = IN6ADDR_EXACT_INIT;

/* Parses 's' as a 16-digit hexadecimal number representing a datapath ID.  On
 * success stores the dpid into '*dpidp' and returns true, on failure stores 0
 * into '*dpidp' and returns false.
 *
 * Rejects an all-zeros dpid as invalid. */
bool
dpid_from_string(const char *s, uint64_t *dpidp)
{
    *dpidp = (strlen(s) == 16 && strspn(s, "0123456789abcdefABCDEF") == 16
              ? strtoull(s, NULL, 16)
              : 0);
    return *dpidp != 0;
}

/* Returns true if 'ea' is a reserved multicast address, that a bridge must
 * never forward, false otherwise.  Includes some proprietary vendor protocols
 * that shouldn't be forwarded as well.
 *
 * If you change this function's behavior, please update corresponding
 * documentation in vswitch.xml at the same time. */
bool
eth_addr_is_reserved(const uint8_t ea[ETH_ADDR_LEN])
{
    struct masked_eth_addr {
        uint8_t ea[ETH_ADDR_LEN];
        uint8_t mask[ETH_ADDR_LEN];
    };

    static struct masked_eth_addr mea[] = {
        { /* STP, IEEE pause frames, and other reserved protocols. */
            {0x01, 0x08, 0xc2, 0x00, 0x00, 0x00},
            {0xff, 0xff, 0xff, 0xff, 0xff, 0xf0}},

        { /* VRRP IPv4. */
            {0x00, 0x00, 0x5e, 0x00, 0x01, 0x00},
            {0xff, 0xff, 0xff, 0xff, 0xff, 0x00}},

        { /* VRRP IPv6. */
            {0x00, 0x00, 0x5e, 0x00, 0x02, 0x00},
            {0xff, 0xff, 0xff, 0xff, 0xff, 0x00}},

        { /* HSRPv1. */
            {0x00, 0x00, 0x0c, 0x07, 0xac, 0x00},
            {0xff, 0xff, 0xff, 0xff, 0xff, 0x00}},

        { /* HSRPv2. */
            {0x00, 0x00, 0x0c, 0x9f, 0xf0, 0x00},
            {0xff, 0xff, 0xff, 0xff, 0xf0, 0x00}},

        { /* GLBP. */
            {0x00, 0x07, 0xb4, 0x00, 0x00, 0x00},
            {0xff, 0xff, 0xff, 0x00, 0x00, 0x00}},

        { /* Extreme Discovery Protocol. */
            {0x00, 0xE0, 0x2B, 0x00, 0x00, 0x00},
            {0xff, 0xff, 0xff, 0xff, 0xf0, 0x00}},

        { /* Cisco Inter Switch Link. */
            {0x01, 0x00, 0x0c, 0x00, 0x00, 0x00},
            {0xff, 0xff, 0xff, 0xff, 0xff, 0xff}},

        { /* Cisco protocols plus others following the same pattern:
           *
           * CDP, VTP, DTP, PAgP  (01-00-0c-cc-cc-cc)
           * Spanning Tree PVSTP+ (01-00-0c-cc-cc-cd)
           * STP Uplink Fast      (01-00-0c-cd-cd-cd) */
            {0x01, 0x00, 0x0c, 0xcc, 0xcc, 0xcc},
            {0xff, 0xff, 0xff, 0xfe, 0xfe, 0xfe}}};

    size_t i;

    for (i = 0; i < ARRAY_SIZE(mea); i++) {
        if (eth_addr_equal_except(ea, mea[i].ea, mea[i].mask)) {
            return true;
        }
    }
    return false;
}

bool
eth_addr_from_string(const char *s, uint8_t ea[ETH_ADDR_LEN])
{
    if (sscanf(s, ETH_ADDR_SCAN_FMT, ETH_ADDR_SCAN_ARGS(ea))
        == ETH_ADDR_SCAN_COUNT) {
        return true;
    } else {
        memset(ea, 0, ETH_ADDR_LEN);
        return false;
    }
}

/* Fills 'b' with a Reverse ARP packet with Ethernet source address 'eth_src'.
 * This function is used by Open vSwitch to compose packets in cases where
 * context is important but content doesn't (or shouldn't) matter.
 *
 * The returned packet has enough headroom to insert an 802.1Q VLAN header if
 * desired. */
void
compose_rarp(struct ofpbuf *b, const uint8_t eth_src[ETH_ADDR_LEN])
{
    struct eth_header *eth;
    struct rarp_header *rarp;

    ofpbuf_clear(b);
    ofpbuf_prealloc_tailroom(b, ETH_HEADER_LEN + VLAN_HEADER_LEN
                             + RARP_HEADER_LEN);
    ofpbuf_reserve(b, VLAN_HEADER_LEN);
    eth = ofpbuf_put_uninit(b, sizeof *eth);
    memcpy(eth->eth_dst, eth_addr_broadcast, ETH_ADDR_LEN);
    memcpy(eth->eth_src, eth_src, ETH_ADDR_LEN);
    eth->eth_type = htons(ETH_TYPE_RARP);

    rarp = ofpbuf_put_uninit(b, sizeof *rarp);
    rarp->hw_addr_space = htons(ARP_HTYPE_ETH);
    rarp->proto_addr_space = htons(ETH_TYPE_IP);
    rarp->hw_addr_length = ETH_ADDR_LEN;
    rarp->proto_addr_length = sizeof rarp->src_proto_addr;
    rarp->opcode = htons(RARP_REQUEST_REVERSE);
    memcpy(rarp->src_hw_addr, eth_src, ETH_ADDR_LEN);
    rarp->src_proto_addr = htonl(0);
    memcpy(rarp->target_hw_addr, eth_src, ETH_ADDR_LEN);
    rarp->target_proto_addr = htonl(0);
}

/* Insert VLAN header according to given TCI. Packet passed must be Ethernet
 * packet.  Ignores the CFI bit of 'tci' using 0 instead.
 *
 * Also sets 'packet->l2' to point to the new Ethernet header. */
void
eth_push_vlan(struct ofpbuf *packet, ovs_be16 tci, ovs_be16 tpid)
{
    struct eth_header *eh = packet->data;
    struct vlan_eth_header *veh;

    /* Insert new 802.1Q or 802.1AD header. */
    struct vlan_eth_header tmp;
    memcpy(tmp.veth_dst, eh->eth_dst, ETH_ADDR_LEN);
    memcpy(tmp.veth_src, eh->eth_src, ETH_ADDR_LEN);
    tmp.veth_type = tpid;
    tmp.veth_tci = tci & htons(~VLAN_CFI);
    tmp.veth_next_type = eh->eth_type;

    veh = ofpbuf_push_uninit(packet, VLAN_HEADER_LEN);
    memcpy(veh, &tmp, sizeof tmp);

    packet->l2 = packet->data;
}

/* Removes outermost VLAN header (if any is present) from 'packet'.
 *
 * 'packet->l2' must initially point to 'packet''s Ethernet header. */
void
eth_pop_vlan(struct ofpbuf *packet)
{
    struct vlan_eth_header *veh = packet->l2;
    if (packet->size >= sizeof *veh
        && (veh->veth_type == htons(ETH_TYPE_VLAN) ||
            veh->veth_type == htons(ETH_TYPE_VLAN_8021AD))) {
        struct eth_header tmp;

        memcpy(tmp.eth_dst, veh->veth_dst, ETH_ADDR_LEN);
        memcpy(tmp.eth_src, veh->veth_src, ETH_ADDR_LEN);
        tmp.eth_type = veh->veth_next_type;

        ofpbuf_pull(packet, VLAN_HEADER_LEN);
        packet->l2 = (char*)packet->l2 + VLAN_HEADER_LEN;
        memcpy(packet->data, &tmp, sizeof tmp);
    }
}

/* Set ethertype of the packet. */
static void
set_ethertype(struct ofpbuf *packet, ovs_be16 eth_type)
{
    struct eth_header *eh = packet->data;

    if (eh->eth_type == htons(ETH_TYPE_VLAN) ||
        eh->eth_type == htons(ETH_TYPE_VLAN_8021AD)) {
        /* ethtype for VLAN packets is at L3_offset - 2 bytes. */
        ovs_be16 *next_ethtype;
        next_ethtype = (ovs_be16 *)((char *)packet->l3 - 2);
        *next_ethtype = eth_type;
    } else {
        eh->eth_type = eth_type;
    }
}

/* Get ethertype of the packet. */
static ovs_be16
get_ethertype(struct ofpbuf *packet)
{
    struct eth_header *eh = packet->data;
    char *mh = packet->l2_5;
    ovs_be16 *ethtype = NULL;

    if (eh->eth_type == htons(ETH_TYPE_VLAN) ||
        eh->eth_type == htons(ETH_TYPE_VLAN_8021AD)) {
        if (mh != NULL) {
            ethtype = (ovs_be16 *)(mh - 2);
        } else {
            ethtype = (ovs_be16 *)((char *)packet->l3 - 2);
        }
        return *ethtype;
    } else {
        return eh->eth_type;
    }
}

/* Extract ttl and tos from ipv4 or ipv6 header
   for non-IP pick default value. */
static int
get_label_ttl_and_tos(struct ofpbuf* packet, uint8_t *ttl,
                      uint8_t *tos, uint8_t *label)
{
    struct eth_header *eh = packet->data;
    struct ip_header *ih = packet->l3;
    struct ip6_hdr   *ih6 = packet->l3;
    struct mpls_hdr *mh = packet->l2_5;
    ovs_be16 ethtype = htons(0);

    if (packet->size < sizeof *eh + sizeof *ih) {
        return 0;
    }

    ethtype = get_ethertype(packet);

    switch (ntohs(ethtype)) {

    case ETH_TYPE_IP:
        *ttl = ih->ip_ttl;
        *tos = IP_DSCP(ih->ip_tos) & 0x07;
        *label = 0; /* IPV4 Explicit Null label. */
	break;

    case ETH_TYPE_IPV6:
        *ttl = ih6->ip6_hlim;
        *tos = IP6_TC(ntohl(ih6->ip6_flow)) & 0x07;
        *label = 2; /* IPV6 Explicit Null label. */
	break;

    case ETH_TYPE_MPLS:
    case ETH_TYPE_MPLS_MCAST:
        *ttl = mpls_lse_to_ttl(mh->mpls_lse);
        *tos = mpls_lse_to_tc(mh->mpls_lse);
        *label = mpls_lse_to_label(mh->mpls_lse);
	break;

    default:
        *ttl = 64;
        *tos = 0;
        *label = 0; /* default label. */
	break;
    }
    return 1;
}

/* Set MPLS tag time-to-live. */
static void
set_mpls_lse_ttl(ovs_be32 *tag, ovs_be32 ttl)
{
    *tag &= ~htonl(MPLS_TTL_MASK);
    *tag |= ttl & htonl(MPLS_TTL_MASK);
}

/* Set MPLS tag traffic-class. */
static void
set_mpls_lse_tc(ovs_be32 *tag, ovs_be32 tc)
{
    *tag &= ~htonl(MPLS_TC_MASK);
    *tag |= tc & htonl(MPLS_TC_MASK);
}

/* Set MPLS tag label. */
static void
set_mpls_lse_label(ovs_be32 *tag, ovs_be32 label)
{
    *tag &= ~htonl(MPLS_LABEL_MASK);
    *tag |= label & htonl(MPLS_LABEL_MASK);
}

/* Set MPLS tag stack. */
static void
set_mpls_lse_stack(ovs_be32 *tag, ovs_be32 stack)
{
    *tag &= ~htonl(MPLS_STACK_MASK);
    *tag |= stack & htonl(MPLS_STACK_MASK);
}

/* Set MPLS lse from actions. */
static void
set_new_mpls_lse(struct mpls_hdr *mh, ovs_be32 mpls_lse)
{
    set_mpls_lse_label(&mh->mpls_lse, mpls_lse);
    set_mpls_lse_ttl(&mh->mpls_lse, mpls_lse);
    set_mpls_lse_tc(&mh->mpls_lse, mpls_lse);
}

/* Set MPLS label, MPLS TC, MPLS ttl and MPLS stack. */
static void
set_mpls_lse_values(ovs_be32 *tag, uint8_t ttl, uint8_t stack,
                    uint8_t tc, uint32_t label)
{
    set_mpls_lse_ttl(tag, htonl(ttl << MPLS_TTL_SHIFT));
    set_mpls_lse_tc(tag, htonl(tc << MPLS_TC_SHIFT));
    set_mpls_lse_label(tag, htonl(label << MPLS_LABEL_SHIFT));
    set_mpls_lse_stack(tag, htonl(stack << MPLS_STACK_SHIFT));
}

/* Adjust L2 and L2.5 data after pushing new mpls shim header. */
static void
push_mpls_lse(struct ofpbuf *packet, struct mpls_hdr *mh)
{
    char * header;
    size_t len;
    header = ofpbuf_push_uninit(packet, MPLS_HLEN);
    len = (char*)packet->l2_5 - (char*)packet->l2;
    memmove(header, packet->l2, len);
    memcpy((char*)header + len, mh, sizeof *mh);
    packet->l2 = (char*)packet->l2 - MPLS_HLEN;
    packet->l2_5 = (char*)packet->l2_5 - MPLS_HLEN;
}

/* Decrement MPLS TTL from the packet.
 * 'packet->l2_5' must initially point to 'packet''s MPLS Label stack. */
void
dec_mpls_ttl(struct ofpbuf *packet, uint8_t new_ttl)
{
    ovs_be16 eth_type = htons(0);
    struct eth_header *eh = packet->data;
    struct mpls_hdr *mh = packet->l2_5;

    if (packet->size < sizeof *eh) {
        return;
    }

    /* Packet type should be mpls to decrement ttl. */
    eth_type = get_ethertype(packet);

    if (eth_type == htons(ETH_TYPE_MPLS) ||
        eth_type == htons(ETH_TYPE_MPLS_MCAST)) {

        /* Update decremented ttl into mpls header. */
        set_mpls_lse_ttl(&mh->mpls_lse, htonl(new_ttl << MPLS_TTL_SHIFT));
    }
}

/* Copy MPLS TTL from the packet either ipv4/ipv6.
 * 'packet->l2_5' must initially point to 'packet''s MPLS Label stack. */
void
copy_mpls_ttl_in(struct ofpbuf *packet, uint8_t new_ttl)
{
    struct eth_header *eh = packet->data;
    struct mpls_hdr *mh = packet->l2_5;
    struct ip_header *ih = packet->l3;
    struct ip6_hdr *ih6 = packet->l3;
    ovs_be16 eth_type = htons(0);
    size_t hdr_size = sizeof *eh + sizeof *mh + sizeof *ih;

    if (packet->size < hdr_size) {
        return;
    }

    /* Packet type should be mpls to copy ttl to l3. */
    eth_type = get_ethertype(packet);
    if (eth_type == htons(ETH_TYPE_MPLS) ||
        eth_type == htons(ETH_TYPE_MPLS_MCAST)) {

        /* If bottom of the stack handle IP checksum. */
        if (mh->mpls_lse & htonl(MPLS_STACK_MASK)) {
            if (IP_VER(ih->ip_ihl_ver) == IP_VERSION) {
                /* Change the ip checksum. */
                uint8_t *field = &ih->ip_ttl;
                ih->ip_csum = recalc_csum16(ih->ip_csum,
                                 htons(*field << 8), htons(new_ttl << 8));
                ih->ip_ttl = new_ttl;
            } else if (IP6_VER(ih6->ip6_vfc) == IP6_VERSION) {
                ih6->ip6_hlim = new_ttl;
            }
        } else {
            struct mpls_hdr *mh2;
            mh2 = (struct mpls_hdr *)((char *) packet->l2_5 + sizeof *mh);
            set_mpls_lse_ttl(&mh2->mpls_lse, htonl(new_ttl << MPLS_TTL_SHIFT));
        }
    }
}

/* Copy MPLS TTL to the packet layer3 only ipv4/ipv6.
 * 'packet->l2_5' must initially point to 'packet''s MPLS Label stack. */
void
copy_mpls_ttl_out(struct ofpbuf *packet, uint8_t new_ttl)
{
    struct eth_header *eh = packet->data;
    struct mpls_hdr *mh = packet->l2_5;
    struct ip_header *ih = packet->l3;
    struct ip6_hdr   *ih6 = packet->l3;
    ovs_be16 eth_type = htons(0);
    size_t hdr_size = sizeof *eh + sizeof *mh + sizeof *ih;

    /* TTL sent from ofproto-dpif.c is not the correct one,
     * hence ignore it. */
    if (packet->size < hdr_size) {
        return;
    }

    /* Packet type should me mpls to copy ttl from l3. */
    eth_type = get_ethertype(packet);
    if (eth_type == htons(ETH_TYPE_MPLS) ||
        eth_type == htons(ETH_TYPE_MPLS_MCAST)) {

        /* If bottom of the stack copy from l3. */
        if (mh->mpls_lse & htonl(MPLS_STACK_MASK)) {
            uint8_t nh_ttl;
            /* Get ipv4 or ipv6 or default ttl. */
            if (IP_VER(ih->ip_ihl_ver) == IP_VERSION) {
                nh_ttl = ih->ip_ttl;
            } else if (IP6_VER(ih6->ip6_vfc) == IP6_VERSION) {
                nh_ttl = ih6->ip6_hlim;
            } else {
                nh_ttl = 64; /* Default ttl for non-IP. */
            }
            set_mpls_lse_ttl(&mh->mpls_lse, htonl(nh_ttl << MPLS_TTL_SHIFT));
        } else {
            struct mpls_hdr *mh2;
            mh2 = (struct mpls_hdr *)((char *) packet->l2_5 + sizeof *mh);
            new_ttl = mpls_lse_to_ttl(mh2->mpls_lse);
            set_mpls_lse_ttl(&mh->mpls_lse, htonl(new_ttl << MPLS_TTL_SHIFT));
        }
    }
}

/* Set MPLS label stack entry to outermost MPLS header.*/
void
set_mpls_lse(struct ofpbuf *packet, ovs_be32 mpls_lse)
{
    struct eth_header *eh = packet->data;
    struct mpls_hdr *mh = packet->l2_5;
    ovs_be16 eth_type = htons(0);

    if (packet->size < sizeof *eh) {
        return;
    }

    /* Packet type should me mpls to set label stack entry. */
    eth_type = get_ethertype(packet);
    if (eth_type == htons(ETH_TYPE_MPLS) ||
        eth_type == htons(ETH_TYPE_MPLS_MCAST)) {
        /* Update mpls label stack entry. */
        set_new_mpls_lse(mh, mpls_lse);
    }
}

/* Push MPLS label stack entry onto packet. */
void
push_mpls(struct ofpbuf *packet, ovs_be16 ethtype)
{
    struct eth_header *eh = packet->data;
    uint8_t nh_ttl, nh_tos, label;
    ovs_be16 eth_type = htons(0);

    if (packet->size < sizeof *eh ||
        (ethtype != htons(ETH_TYPE_MPLS) &&
         ethtype != htons(ETH_TYPE_MPLS_MCAST))) {
        return;
    }

    /* Get the packet ether_type. */
    eth_type = get_ethertype(packet);

    /* Get Label, time-to-live and tos from L3 or L2.5. */
    if (get_label_ttl_and_tos(packet, &nh_ttl, &nh_tos, &label)) {
        struct mpls_hdr mh;

        if (eth_type == htons(ETH_TYPE_MPLS) ||
            eth_type == htons(ETH_TYPE_MPLS_MCAST)) {
            set_mpls_lse_values(&mh.mpls_lse, nh_ttl, 0, nh_tos, label);
        } else {
            /* Set ethtype and mpls label stack entry. */
            set_ethertype(packet, ethtype);
            set_mpls_lse_values(&mh.mpls_lse, nh_ttl, 1, nh_tos, label);
            packet->l2_5 = packet->l3;
        }
        /* Push new MPLS shim header onto packet. */
        push_mpls_lse(packet, &mh);
    }
}

/* Pop outermost MPLS label stack entry from packet. */
void
pop_mpls(struct ofpbuf *packet, ovs_be16 ethtype)
{
    struct eth_header *eh = packet->data;
    struct mpls_hdr *mh = NULL;
    ovs_be16 eth_type = htons(0);

    if (packet->size < sizeof *eh + sizeof *mh)
        return;

    eth_type = get_ethertype(packet);

    if (eth_type == htons(ETH_TYPE_MPLS) ||
        eth_type == htons(ETH_TYPE_MPLS_MCAST)) {
        size_t len;
        mh = packet->l2_5;
        len = (char*)packet->l2_5 - (char*)packet->l2;
        /* If bottom of the stack set ethertype. */
        if (mh->mpls_lse & htonl(MPLS_STACK_MASK)) {
            packet->l3 = packet->l2_5;
            packet->l2_5 = NULL;
            set_ethertype(packet, ethtype);
        } else {
            packet->l2_5 = (char*)packet->l2_5 + MPLS_HLEN;
        }
        /* Shift the l2 header forward. */
        memmove((char*)packet->data + MPLS_HLEN, packet->data, len);
        packet->size -= MPLS_HLEN;
        packet->data = (char*)packet->data + MPLS_HLEN;
        packet->l2 = (char*)packet->l2 + MPLS_HLEN;
    }
}

/* Converts hex digits in 'hex' to an Ethernet packet in '*packetp'.  The
 * caller must free '*packetp'.  On success, returns NULL.  On failure, returns
 * an error message and stores NULL in '*packetp'. */
const char *
eth_from_hex(const char *hex, struct ofpbuf **packetp)
{
    struct ofpbuf *packet;

    packet = *packetp = ofpbuf_new(strlen(hex) / 2);

    if (ofpbuf_put_hex(packet, hex, NULL)[0] != '\0') {
        ofpbuf_delete(packet);
        *packetp = NULL;
        return "Trailing garbage in packet data";
    }

    if (packet->size < ETH_HEADER_LEN) {
        ofpbuf_delete(packet);
        *packetp = NULL;
        return "Packet data too short for Ethernet";
    }

    return NULL;
}

void
eth_format_masked(const uint8_t eth[ETH_ADDR_LEN],
                  const uint8_t mask[ETH_ADDR_LEN], struct ds *s)
{
    ds_put_format(s, ETH_ADDR_FMT, ETH_ADDR_ARGS(eth));
    if (mask && !eth_mask_is_exact(mask)) {
        ds_put_format(s, "/"ETH_ADDR_FMT, ETH_ADDR_ARGS(mask));
    }
}

void
eth_addr_bitand(const uint8_t src[ETH_ADDR_LEN],
                const uint8_t mask[ETH_ADDR_LEN],
                uint8_t dst[ETH_ADDR_LEN])
{
    int i;

    for (i = 0; i < ETH_ADDR_LEN; i++) {
        dst[i] = src[i] & mask[i];
    }
}

/* Given the IP netmask 'netmask', returns the number of bits of the IP address
 * that it specifies, that is, the number of 1-bits in 'netmask'.
 *
 * If 'netmask' is not a CIDR netmask (see ip_is_cidr()), the return value will
 * still be in the valid range but isn't otherwise meaningful. */
int
ip_count_cidr_bits(ovs_be32 netmask)
{
    return 32 - ctz(ntohl(netmask));
}

void
ip_format_masked(ovs_be32 ip, ovs_be32 mask, struct ds *s)
{
    ds_put_format(s, IP_FMT, IP_ARGS(&ip));
    if (mask != htonl(UINT32_MAX)) {
        if (ip_is_cidr(mask)) {
            ds_put_format(s, "/%d", ip_count_cidr_bits(mask));
        } else {
            ds_put_format(s, "/"IP_FMT, IP_ARGS(&mask));
        }
    }
}


/* Stores the string representation of the IPv6 address 'addr' into the
 * character array 'addr_str', which must be at least INET6_ADDRSTRLEN
 * bytes long. */
void
format_ipv6_addr(char *addr_str, const struct in6_addr *addr)
{
    inet_ntop(AF_INET6, addr, addr_str, INET6_ADDRSTRLEN);
}

void
print_ipv6_addr(struct ds *string, const struct in6_addr *addr)
{
    char *dst;

    ds_reserve(string, string->length + INET6_ADDRSTRLEN);

    dst = string->string + string->length;
    format_ipv6_addr(dst, addr);
    string->length += strlen(dst);
}

void
print_ipv6_masked(struct ds *s, const struct in6_addr *addr,
                  const struct in6_addr *mask)
{
    print_ipv6_addr(s, addr);
    if (mask && !ipv6_mask_is_exact(mask)) {
        if (ipv6_is_cidr(mask)) {
            int cidr_bits = ipv6_count_cidr_bits(mask);
            ds_put_format(s, "/%d", cidr_bits);
        } else {
            ds_put_char(s, '/');
            print_ipv6_addr(s, mask);
        }
    }
}

struct in6_addr ipv6_addr_bitand(const struct in6_addr *a,
                                 const struct in6_addr *b)
{
    int i;
    struct in6_addr dst;

#ifdef s6_addr32
    for (i=0; i<4; i++) {
        dst.s6_addr32[i] = a->s6_addr32[i] & b->s6_addr32[i];
    }
#else
    for (i=0; i<16; i++) {
        dst.s6_addr[i] = a->s6_addr[i] & b->s6_addr[i];
    }
#endif

    return dst;
}

/* Returns an in6_addr consisting of 'mask' high-order 1-bits and 128-N
 * low-order 0-bits. */
struct in6_addr
ipv6_create_mask(int mask)
{
    struct in6_addr netmask;
    uint8_t *netmaskp = &netmask.s6_addr[0];

    memset(&netmask, 0, sizeof netmask);
    while (mask > 8) {
        *netmaskp = 0xff;
        netmaskp++;
        mask -= 8;
    }

    if (mask) {
        *netmaskp = 0xff << (8 - mask);
    }

    return netmask;
}

/* Given the IPv6 netmask 'netmask', returns the number of bits of the IPv6
 * address that it specifies, that is, the number of 1-bits in 'netmask'.
 * 'netmask' must be a CIDR netmask (see ipv6_is_cidr()).
 *
 * If 'netmask' is not a CIDR netmask (see ipv6_is_cidr()), the return value
 * will still be in the valid range but isn't otherwise meaningful. */
int
ipv6_count_cidr_bits(const struct in6_addr *netmask)
{
    int i;
    int count = 0;
    const uint8_t *netmaskp = &netmask->s6_addr[0];

    for (i=0; i<16; i++) {
        if (netmaskp[i] == 0xff) {
            count += 8;
        } else {
            uint8_t nm;

            for(nm = netmaskp[i]; nm; nm <<= 1) {
                count++;
            }
            break;
        }

    }

    return count;
}

/* Returns true if 'netmask' is a CIDR netmask, that is, if it consists of N
 * high-order 1-bits and 128-N low-order 0-bits. */
bool
ipv6_is_cidr(const struct in6_addr *netmask)
{
    const uint8_t *netmaskp = &netmask->s6_addr[0];
    int i;

    for (i=0; i<16; i++) {
        if (netmaskp[i] != 0xff) {
            uint8_t x = ~netmaskp[i];
            if (x & (x + 1)) {
                return false;
            }
            while (++i < 16) {
                if (netmaskp[i]) {
                    return false;
                }
            }
        }
    }

    return true;
}

/* Populates 'b' with an Ethernet II packet headed with the given 'eth_dst',
 * 'eth_src' and 'eth_type' parameters.  A payload of 'size' bytes is allocated
 * in 'b' and returned.  This payload may be populated with appropriate
 * information by the caller.  Sets 'b''s 'l2' and 'l3' pointers to the
 * Ethernet header and payload respectively.
 *
 * The returned packet has enough headroom to insert an 802.1Q VLAN header if
 * desired. */
void *
eth_compose(struct ofpbuf *b, const uint8_t eth_dst[ETH_ADDR_LEN],
            const uint8_t eth_src[ETH_ADDR_LEN], uint16_t eth_type,
            size_t size)
{
    void *data;
    struct eth_header *eth;

    ofpbuf_clear(b);

    ofpbuf_prealloc_tailroom(b, ETH_HEADER_LEN + VLAN_HEADER_LEN + size);
    ofpbuf_reserve(b, VLAN_HEADER_LEN);
    eth = ofpbuf_put_uninit(b, ETH_HEADER_LEN);
    data = ofpbuf_put_uninit(b, size);

    memcpy(eth->eth_dst, eth_dst, ETH_ADDR_LEN);
    memcpy(eth->eth_src, eth_src, ETH_ADDR_LEN);
    eth->eth_type = htons(eth_type);

    b->l2 = eth;
    b->l3 = data;

    return data;
}

static void
packet_set_ipv4_addr(struct ofpbuf *packet, ovs_be32 *addr, ovs_be32 new_addr)
{
    struct ip_header *nh = packet->l3;

    if (nh->ip_proto == IPPROTO_TCP && packet->l7) {
        struct tcp_header *th = packet->l4;

        th->tcp_csum = recalc_csum32(th->tcp_csum, *addr, new_addr);
    } else if (nh->ip_proto == IPPROTO_UDP && packet->l7) {
        struct udp_header *uh = packet->l4;

        if (uh->udp_csum) {
            uh->udp_csum = recalc_csum32(uh->udp_csum, *addr, new_addr);
            if (!uh->udp_csum) {
                uh->udp_csum = htons(0xffff);
            }
        }
    }
    nh->ip_csum = recalc_csum32(nh->ip_csum, *addr, new_addr);
    *addr = new_addr;
}

/* Modifies the IPv4 header fields of 'packet' to be consistent with 'src',
 * 'dst', 'tos', and 'ttl'.  Updates 'packet''s L4 checksums as appropriate.
 * 'packet' must contain a valid IPv4 packet with correctly populated l[347]
 * markers. */
void
packet_set_ipv4(struct ofpbuf *packet, ovs_be32 src, ovs_be32 dst,
                uint8_t tos, uint8_t ttl)
{
    struct ip_header *nh = packet->l3;

    if (nh->ip_src != src) {
        packet_set_ipv4_addr(packet, &nh->ip_src, src);
    }

    if (nh->ip_dst != dst) {
        packet_set_ipv4_addr(packet, &nh->ip_dst, dst);
    }

    if (nh->ip_tos != tos) {
        uint8_t *field = &nh->ip_tos;

        nh->ip_csum = recalc_csum16(nh->ip_csum, htons((uint16_t) *field),
                                    htons((uint16_t) tos));
        *field = tos;
    }

    if (nh->ip_ttl != ttl) {
        uint8_t *field = &nh->ip_ttl;

        nh->ip_csum = recalc_csum16(nh->ip_csum, htons(*field << 8),
                                    htons(ttl << 8));
        *field = ttl;
    }
}

static void
packet_set_port(ovs_be16 *port, ovs_be16 new_port, ovs_be16 *csum)
{
    if (*port != new_port) {
        *csum = recalc_csum16(*csum, *port, new_port);
        *port = new_port;
    }
}

/* Sets the TCP source and destination port ('src' and 'dst' respectively) of
 * the TCP header contained in 'packet'.  'packet' must be a valid TCP packet
 * with its l4 marker properly populated. */
void
packet_set_tcp_port(struct ofpbuf *packet, ovs_be16 src, ovs_be16 dst)
{
    struct tcp_header *th = packet->l4;

    packet_set_port(&th->tcp_src, src, &th->tcp_csum);
    packet_set_port(&th->tcp_dst, dst, &th->tcp_csum);
}

/* Sets the UDP source and destination port ('src' and 'dst' respectively) of
 * the UDP header contained in 'packet'.  'packet' must be a valid UDP packet
 * with its l4 marker properly populated. */
void
packet_set_udp_port(struct ofpbuf *packet, ovs_be16 src, ovs_be16 dst)
{
    struct udp_header *uh = packet->l4;

    if (uh->udp_csum) {
        packet_set_port(&uh->udp_src, src, &uh->udp_csum);
        packet_set_port(&uh->udp_dst, dst, &uh->udp_csum);

        if (!uh->udp_csum) {
            uh->udp_csum = htons(0xffff);
        }
    } else {
        uh->udp_src = src;
        uh->udp_dst = dst;
    }
}

/* If 'packet' is a TCP packet, returns the TCP flags.  Otherwise, returns 0.
 *
 * 'flow' must be the flow corresponding to 'packet' and 'packet''s header
 * pointers must be properly initialized (e.g. with flow_extract()). */
uint8_t
packet_get_tcp_flags(const struct ofpbuf *packet, const struct flow *flow)
{
    if ((flow->dl_type == htons(ETH_TYPE_IP) ||
         flow->dl_type == htons(ETH_TYPE_IPV6)) &&
        flow->nw_proto == IPPROTO_TCP && packet->l7) {
        const struct tcp_header *tcp = packet->l4;
        return TCP_FLAGS(tcp->tcp_ctl);
    } else {
        return 0;
    }
}

/* Appends a string representation of the TCP flags value 'tcp_flags'
 * (e.g. obtained via packet_get_tcp_flags() or TCP_FLAGS) to 's', in the
 * format used by tcpdump. */
void
packet_format_tcp_flags(struct ds *s, uint8_t tcp_flags)
{
    if (!tcp_flags) {
        ds_put_cstr(s, "none");
        return;
    }

    if (tcp_flags & TCP_SYN) {
        ds_put_char(s, 'S');
    }
    if (tcp_flags & TCP_FIN) {
        ds_put_char(s, 'F');
    }
    if (tcp_flags & TCP_PSH) {
        ds_put_char(s, 'P');
    }
    if (tcp_flags & TCP_RST) {
        ds_put_char(s, 'R');
    }
    if (tcp_flags & TCP_URG) {
        ds_put_char(s, 'U');
    }
    if (tcp_flags & TCP_ACK) {
        ds_put_char(s, '.');
    }
    if (tcp_flags & 0x40) {
        ds_put_cstr(s, "[40]");
    }
    if (tcp_flags & 0x80) {
        ds_put_cstr(s, "[80]");
    }
}
