/*
 * Copyright (c) 2016 Nicira, Inc.
 * Copyright (c) 2016 Red Hat, Inc.
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

#include "netdev-native-tnl.h"

#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <sys/ioctl.h>

#include <stdlib.h>
#include <sys/time.h>

#include "byte-order.h"
#include "csum.h"
#include "dp-packet.h"
#include "netdev.h"
#include "netdev-vport.h"
#include "netdev-vport-private.h"
#include "odp-netlink.h"
#include "packets.h"
#include "seq.h"
#include "unaligned.h"
#include "unixctl.h"
#include "util.h"
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(native_tnl);
static struct vlog_rate_limit err_rl = VLOG_RATE_LIMIT_INIT(60, 5);

#define VXLAN_HLEN   (sizeof(struct udp_header) +         \
                      sizeof(struct vxlanhdr))

#define GENEVE_BASE_HLEN   (sizeof(struct udp_header) +         \
                            sizeof(struct genevehdr))

#define GTPU_HLEN   (sizeof(struct udp_header) +        \
                     sizeof(struct gtpuhdr))

uint16_t tnl_udp_port_min = 32768;
uint16_t tnl_udp_port_max = 61000;

void *
netdev_tnl_ip_extract_tnl_md(struct dp_packet *packet, struct flow_tnl *tnl,
                  unsigned int *hlen)
{
    void *nh;
    struct ip_header *ip;
    struct ovs_16aligned_ip6_hdr *ip6;
    void *l4;
    int l3_size;

    nh = dp_packet_l3(packet);
    ip = nh;
    ip6 = nh;
    l4 = dp_packet_l4(packet);

    if (!nh || !l4) {
        return NULL;
    }

    *hlen = sizeof(struct eth_header);

    l3_size = dp_packet_size(packet) -
              ((char *)nh - (char *)dp_packet_data(packet));

    if (IP_VER(ip->ip_ihl_ver) == 4) {

        ovs_be32 ip_src, ip_dst;

        /* A packet coming from a network device might have the
         * csum already checked. In this case, skip the check. */
        if (OVS_UNLIKELY(!dp_packet_ip_checksum_good(packet))
            && !dp_packet_hwol_tx_ip_csum(packet)) {
            if (csum(ip, IP_IHL(ip->ip_ihl_ver) * 4)) {
                VLOG_WARN_RL(&err_rl, "ip packet has invalid checksum");
                return NULL;
            }
        }

        if (ntohs(ip->ip_tot_len) > l3_size) {
            VLOG_WARN_RL(&err_rl, "ip packet is truncated (IP length %d, actual %d)",
                         ntohs(ip->ip_tot_len), l3_size);
            return NULL;
        }
        if (IP_IHL(ip->ip_ihl_ver) * 4 > sizeof(struct ip_header)) {
            VLOG_WARN_RL(&err_rl, "ip options not supported on tunnel packets "
                         "(%d bytes)", IP_IHL(ip->ip_ihl_ver) * 4);
            return NULL;
        }

        ip_src = get_16aligned_be32(&ip->ip_src);
        ip_dst = get_16aligned_be32(&ip->ip_dst);

        tnl->ip_src = ip_src;
        tnl->ip_dst = ip_dst;
        tnl->ip_tos = ip->ip_tos;
        tnl->ip_ttl = ip->ip_ttl;

        *hlen += IP_HEADER_LEN;

    } else if (IP_VER(ip->ip_ihl_ver) == 6) {
        ovs_be32 tc_flow = get_16aligned_be32(&ip6->ip6_flow);

        memcpy(tnl->ipv6_src.s6_addr, ip6->ip6_src.be16, sizeof ip6->ip6_src);
        memcpy(tnl->ipv6_dst.s6_addr, ip6->ip6_dst.be16, sizeof ip6->ip6_dst);

        tnl->ip_tos = ntohl(tc_flow) >> 20;
        tnl->ip_ttl = ip6->ip6_hlim;

        *hlen += packet->l4_ofs - packet->l3_ofs;

    } else {
        VLOG_WARN_RL(&err_rl, "ipv4 packet has invalid version (%d)",
                     IP_VER(ip->ip_ihl_ver));
        return NULL;
    }

    return l4;
}

/* Pushes the 'size' bytes of 'header' into the headroom of 'packet',
 * reallocating the packet if necessary.  'header' should contain an Ethernet
 * header, followed by an IPv4 header (without options), and an L4 header.
 *
 * This function sets the IP header's ip_tot_len field (which should be zeroed
 * as part of 'header') and puts its value into '*ip_tot_size' as well.  Also
 * updates IP header checksum if not offloaded, as well as the l3 and l4
 * offsets in the 'packet'.
 *
 * Return pointer to the L4 header added to 'packet'. */
void *
netdev_tnl_push_ip_header(struct dp_packet *packet, const void *header,
                          int size, int *ip_tot_size, ovs_be32 ipv6_label)
{
    struct eth_header *eth;
    struct ip_header *ip;
    struct ovs_16aligned_ip6_hdr *ip6;

    eth = dp_packet_push_uninit(packet, size);
    *ip_tot_size = dp_packet_size(packet) - sizeof (struct eth_header);

    memcpy(eth, header, size);
    /* The encapsulated packet has type Ethernet. Adjust dp_packet. */
    packet->packet_type = htonl(PT_ETH);
    dp_packet_reset_offsets(packet);
    packet->l3_ofs = sizeof (struct eth_header);

    if (netdev_tnl_is_header_ipv6(header)) {
        ip6 = netdev_tnl_ipv6_hdr(eth);
        *ip_tot_size -= IPV6_HEADER_LEN;
        ip6->ip6_plen = htons(*ip_tot_size);
        packet_set_ipv6_flow_label(&ip6->ip6_flow, ipv6_label);
        packet->l4_ofs = dp_packet_size(packet) - *ip_tot_size;

        if (dp_packet_hwol_is_tunnel_geneve(packet) ||
            dp_packet_hwol_is_tunnel_vxlan(packet)) {
            dp_packet_hwol_set_tx_outer_ipv6(packet);
        } else {
            dp_packet_hwol_set_tx_ipv6(packet);
        }

        dp_packet_ol_reset_ip_csum_good(packet);
        return ip6 + 1;
    } else {
        ip = netdev_tnl_ip_hdr(eth);
        ip->ip_tot_len = htons(*ip_tot_size);
        /* Postpone checksum to when the packet is pushed to the port. */
        if (dp_packet_hwol_is_tunnel_geneve(packet) ||
            dp_packet_hwol_is_tunnel_vxlan(packet)) {
            dp_packet_hwol_set_tx_outer_ipv4(packet);
            dp_packet_hwol_set_tx_outer_ipv4_csum(packet);
        } else {
            dp_packet_hwol_set_tx_ipv4(packet);
            dp_packet_hwol_set_tx_ip_csum(packet);
        }

        dp_packet_ol_reset_ip_csum_good(packet);
        *ip_tot_size -= IP_HEADER_LEN;
        packet->l4_ofs = dp_packet_size(packet) - *ip_tot_size;
        return ip + 1;
    }
}

static void *
udp_extract_tnl_md(struct dp_packet *packet, struct flow_tnl *tnl,
                   unsigned int *hlen)
{
    struct udp_header *udp;

    udp = netdev_tnl_ip_extract_tnl_md(packet, tnl, hlen);
    if (!udp) {
        return NULL;
    }

    if (udp->udp_csum) {
        if (OVS_UNLIKELY(!dp_packet_l4_checksum_good(packet))) {
            uint32_t csum;
            if (netdev_tnl_is_header_ipv6(dp_packet_data(packet))) {
                csum = packet_csum_pseudoheader6(dp_packet_l3(packet));
            } else {
                csum = packet_csum_pseudoheader(dp_packet_l3(packet));
            }

            csum = csum_continue(csum, udp, dp_packet_size(packet) -
                                 ((const unsigned char *)udp -
                                  (const unsigned char *)dp_packet_eth(packet)
                                 ));
            if (csum_finish(csum)) {
                return NULL;
            }
        }
        tnl->flags |= FLOW_TNL_F_CSUM;
    }

    tnl->tp_src = udp->udp_src;
    tnl->tp_dst = udp->udp_dst;

    return udp + 1;
}

/* Calculate inner l2 l3 l4 len as tunnel outer header is not
 * encapsulated now. */
static void
dp_packet_tnl_ol_process(const struct netdev *netdev,
                             struct dp_packet *packet,
                             const struct ovs_action_push_tnl *data)
{
    struct udp_header *udp = NULL;
    uint8_t opt_len = 0;
    struct eth_header *eth = NULL;
    struct ip_header *ip = NULL;
    struct genevehdr *gnh = NULL;

    /* l2 l3 l4 len refer to inner len, tunnel outer
     * header is not encapsulated here. */
   if (dp_packet_hwol_l4_mask(packet)) {
       ip = dp_packet_l3(packet);

        if (ip->ip_proto == IPPROTO_TCP) {
            struct tcp_header *th = dp_packet_l4(packet);
            dp_packet_set_l4_len(packet, TCP_OFFSET(th->tcp_ctl) * 4);
        } else if (ip->ip_proto == IPPROTO_UDP) {
            dp_packet_set_l4_len(packet, UDP_HEADER_LEN);
        } else if (ip->ip_proto == IPPROTO_SCTP) {
            dp_packet_set_l4_len(packet, SCTP_HEADER_LEN);
        }

        dp_packet_set_l3_len(packet, (char *) dp_packet_l4(packet) -
                              (char *) dp_packet_l3(packet));

        if (!strcmp(netdev_get_type(netdev), "geneve") ||
            !strcmp(netdev_get_type(netdev), "vxlan")) {

            if (IP_VER(ip->ip_ihl_ver) == 4) {
                dp_packet_hwol_set_tx_ipv4(packet);
                dp_packet_hwol_tx_ip_csum(packet);
            } else if (IP_VER(ip->ip_ihl_ver) == 6) {
                dp_packet_hwol_set_tx_ipv6(packet);
            }
        }

        /* Attention please, tunnel inner l2 len is consist of udp header
         * len and tunnel header len and inner l2 len. */
        if (!strcmp(netdev_get_type(netdev), "geneve")) {
            eth = (struct eth_header *)(data->header);
            ip = (struct ip_header *)(eth + 1);
            udp = (struct udp_header *)(ip + 1);
            gnh = (struct genevehdr *)(udp + 1);
            opt_len = gnh->opt_len * 4;
            dp_packet_hwol_set_tunnel_geneve(packet);
            dp_packet_set_l2_len(packet, (char *) dp_packet_l3(packet) -
                              (char *) dp_packet_eth(packet) +
                              GENEVE_BASE_HLEN + opt_len);

            packet->inner_l3_ofs = packet->l3_ofs + GENEVE_BASE_HLEN + opt_len;
            packet->inner_l4_ofs = packet->l4_ofs + GENEVE_BASE_HLEN + opt_len;

        } else if (!strcmp(netdev_get_type(netdev), "vxlan")) {
            dp_packet_hwol_set_tunnel_vxlan(packet);
            dp_packet_set_l2_len(packet, (char *) dp_packet_l3(packet) -
                              (char *) dp_packet_eth(packet) +
                              VXLAN_HLEN);

            packet->inner_l3_ofs = packet->l3_ofs + VXLAN_HLEN;
            packet->inner_l4_ofs = packet->l4_ofs + VXLAN_HLEN;
        }
    }
}

void
netdev_tnl_push_udp_header(const struct netdev *netdev,
                           struct dp_packet *packet,
                           const struct ovs_action_push_tnl *data)
{
    struct udp_header *udp;
    int ip_tot_size;

    dp_packet_tnl_ol_process(netdev, packet, data);
    udp = netdev_tnl_push_ip_header(packet, data->header, data->header_len,
                                    &ip_tot_size, 0);

    /* set udp src port */
    udp->udp_src = netdev_tnl_get_src_port(packet);
    udp->udp_len = htons(ip_tot_size);

    if (udp->udp_csum) {
        dp_packet_ol_reset_l4_csum_good(packet);
        if (dp_packet_hwol_is_tunnel_geneve(packet) ||
            dp_packet_hwol_is_tunnel_vxlan(packet)) {
            dp_packet_hwol_set_outer_udp_csum(packet);
        } else {
            dp_packet_hwol_set_csum_udp(packet);
        }
    } else {
            dp_packet_ol_set_l4_csum_good(packet);
    }

    packet->inner_l3_ofs += packet->l4_ofs;
    packet->inner_l4_ofs += packet->l4_ofs;

}

static void *
eth_build_header(struct ovs_action_push_tnl *data,
                 const struct netdev_tnl_build_header_params *params)
{
    uint16_t eth_proto = params->is_ipv6 ? ETH_TYPE_IPV6 : ETH_TYPE_IP;
    struct eth_header *eth;

    memset(data->header, 0, sizeof data->header);

    eth = (struct eth_header *)data->header;
    eth->eth_dst = params->dmac;
    eth->eth_src = params->smac;
    eth->eth_type = htons(eth_proto);
    data->header_len = sizeof(struct eth_header);
    return eth + 1;
}

void *
netdev_tnl_ip_build_header(struct ovs_action_push_tnl *data,
                           const struct netdev_tnl_build_header_params *params,
                           uint8_t next_proto, ovs_be32 ipv6_label)
{
    void *l3;

    l3 = eth_build_header(data, params);
    if (!params->is_ipv6) {
        ovs_be32 ip_src = in6_addr_get_mapped_ipv4(params->s_ip);
        struct ip_header *ip;

        ip = (struct ip_header *) l3;

        ip->ip_ihl_ver = IP_IHL_VER(5, 4);
        ip->ip_tos = params->flow->tunnel.ip_tos;
        ip->ip_ttl = params->flow->tunnel.ip_ttl;
        ip->ip_proto = next_proto;
        put_16aligned_be32(&ip->ip_src, ip_src);
        put_16aligned_be32(&ip->ip_dst, params->flow->tunnel.ip_dst);

        ip->ip_frag_off = (params->flow->tunnel.flags & FLOW_TNL_F_DONT_FRAGMENT) ?
                          htons(IP_DF) : 0;

        /* The checksum will be calculated when the headers are pushed
         * to the packet if offloading is not enabled. */

        data->header_len += IP_HEADER_LEN;
        return ip + 1;
    } else {
        struct ovs_16aligned_ip6_hdr *ip6;

        ip6 = (struct ovs_16aligned_ip6_hdr *) l3;

        put_16aligned_be32(&ip6->ip6_flow, htonl(6 << 28) |
                           htonl(params->flow->tunnel.ip_tos << 20) |
                           (ipv6_label & htonl(IPV6_LABEL_MASK)));
        ip6->ip6_hlim = params->flow->tunnel.ip_ttl;
        ip6->ip6_nxt = next_proto;
        memcpy(&ip6->ip6_src, params->s_ip, sizeof(ovs_be32[4]));
        memcpy(&ip6->ip6_dst, &params->flow->tunnel.ipv6_dst, sizeof(ovs_be32[4]));

        data->header_len += IPV6_HEADER_LEN;
        return ip6 + 1;
    }
}

static void *
udp_build_header(const struct netdev_tunnel_config *tnl_cfg,
                 struct ovs_action_push_tnl *data,
                 const struct netdev_tnl_build_header_params *params)
{
    struct udp_header *udp;

    udp = netdev_tnl_ip_build_header(data, params, IPPROTO_UDP, 0);
    udp->udp_dst = tnl_cfg->dst_port;

    if (params->is_ipv6 || params->flow->tunnel.flags & FLOW_TNL_F_CSUM) {
        /* Write a value in now to mark that we should compute the checksum
         * later. 0xffff is handy because it is transparent to the
         * calculation. */
        udp->udp_csum = htons(0xffff);
    }
    data->header_len += sizeof *udp;
    return udp + 1;
}

static int
gre_header_len(ovs_be16 flags)
{
    int hlen = 4;

    if (flags & htons(GRE_CSUM)) {
        hlen += 4;
    }
    if (flags & htons(GRE_KEY)) {
        hlen += 4;
    }
    if (flags & htons(GRE_SEQ)) {
        hlen += 4;
    }
    return hlen;
}

static int
parse_gre_header(struct dp_packet *packet,
                 struct flow_tnl *tnl)
{
    const struct gre_base_hdr *greh;
    ovs_16aligned_be32 *options;
    int hlen;
    unsigned int ulen;
    uint16_t greh_protocol;

    greh = netdev_tnl_ip_extract_tnl_md(packet, tnl, &ulen);
    if (!greh) {
        return -EINVAL;
    }

    if (greh->flags & ~(htons(GRE_CSUM | GRE_KEY | GRE_SEQ))) {
        return -EINVAL;
    }

    hlen = ulen + gre_header_len(greh->flags);
    if (hlen > dp_packet_size(packet)) {
        return -EINVAL;
    }

    options = (ovs_16aligned_be32 *)(greh + 1);
    if (greh->flags & htons(GRE_CSUM)) {
        ovs_be16 pkt_csum;

        pkt_csum = csum(greh, dp_packet_size(packet) -
                              ((const unsigned char *)greh -
                               (const unsigned char *)dp_packet_eth(packet)));
        if (pkt_csum) {
            return -EINVAL;
        }
        tnl->flags = FLOW_TNL_F_CSUM;
        options++;
    }

    if (greh->flags & htons(GRE_KEY)) {
        tnl->tun_id = be32_to_be64(get_16aligned_be32(options));
        tnl->flags |= FLOW_TNL_F_KEY;
        options++;
    }

    if (greh->flags & htons(GRE_SEQ)) {
        options++;
    }

    /* Set the new packet type depending on the GRE protocol field. */
    greh_protocol = ntohs(greh->protocol);
    if (greh_protocol == ETH_TYPE_TEB) {
        packet->packet_type = htonl(PT_ETH);
    } else if (greh_protocol >= ETH_TYPE_MIN) {
        /* Allow all GRE protocol values above 0x5ff as Ethertypes. */
        packet->packet_type = PACKET_TYPE_BE(OFPHTN_ETHERTYPE, greh_protocol);
    } else {
        return -EINVAL;
    }

    return hlen;
}

struct dp_packet *
netdev_gre_pop_header(struct dp_packet *packet)
{
    const void *data_dp = dp_packet_data(packet);
    struct pkt_metadata *md = &packet->md;
    struct flow_tnl *tnl = &md->tunnel;
    int hlen = sizeof(struct eth_header) + 4;

    ovs_assert(data_dp);

    hlen += netdev_tnl_is_header_ipv6(data_dp) ?
            IPV6_HEADER_LEN : IP_HEADER_LEN;

    pkt_metadata_init_tnl(md);
    if (hlen > dp_packet_size(packet)) {
        goto err;
    }

    hlen = parse_gre_header(packet, tnl);
    if (hlen < 0) {
        goto err;
    }

    dp_packet_reset_packet(packet, hlen);

    return packet;
err:
    dp_packet_delete(packet);
    return NULL;
}

void
netdev_gre_push_header(const struct netdev *netdev,
                       struct dp_packet *packet,
                       const struct ovs_action_push_tnl *data)
{
    struct netdev_vport *dev = netdev_vport_cast(netdev);
    struct gre_base_hdr *greh;
    int ip_tot_size;

    greh = netdev_tnl_push_ip_header(packet, data->header, data->header_len,
                                     &ip_tot_size, 0);

    if (greh->flags & htons(GRE_CSUM)) {
        ovs_be16 *csum_opt = (ovs_be16 *) (greh + 1);
        *csum_opt = csum(greh, ip_tot_size);
    }

    if (greh->flags & htons(GRE_SEQ)) {
        /* Last 4 byte is GRE seqno */
        int seq_ofs = gre_header_len(greh->flags) - 4;
        ovs_16aligned_be32 *seq_opt =
            ALIGNED_CAST(ovs_16aligned_be32 *, (char *)greh + seq_ofs);
        put_16aligned_be32(seq_opt, htonl(atomic_count_inc(&dev->gre_seqno)));
    }
}

int
netdev_gre_build_header(const struct netdev *netdev,
                        struct ovs_action_push_tnl *data,
                        const struct netdev_tnl_build_header_params *params)
{
    const struct netdev_tunnel_config *tnl_cfg;
    struct gre_base_hdr *greh;
    ovs_16aligned_be32 *options;
    unsigned int hlen;

    greh = netdev_tnl_ip_build_header(data, params, IPPROTO_GRE, 0);

    if (params->flow->packet_type == htonl(PT_ETH)) {
        greh->protocol = htons(ETH_TYPE_TEB);
    } else if (pt_ns(params->flow->packet_type) == OFPHTN_ETHERTYPE) {
        greh->protocol = pt_ns_type_be(params->flow->packet_type);
    } else {
        return EINVAL;
    }
    greh->flags = 0;

    options = (ovs_16aligned_be32 *) (greh + 1);
    if (params->flow->tunnel.flags & FLOW_TNL_F_CSUM) {
        greh->flags |= htons(GRE_CSUM);
        put_16aligned_be32(options, 0);
        options++;
    }

    tnl_cfg = netdev_get_tunnel_config(netdev);

    if (tnl_cfg->out_key_present) {
        greh->flags |= htons(GRE_KEY);
        put_16aligned_be32(options, be64_to_be32(params->flow->tunnel.tun_id));
        options++;
    }

    if (tnl_cfg->set_seq) {
        greh->flags |= htons(GRE_SEQ);
        /* seqno is updated at push header */
        options++;
    }

    hlen = (uint8_t *) options - (uint8_t *) greh;

    data->header_len += hlen;
    if (!params->is_ipv6) {
        data->tnl_type = OVS_VPORT_TYPE_GRE;
    } else {
        data->tnl_type = OVS_VPORT_TYPE_IP6GRE;
    }
    return 0;
}

struct dp_packet *
netdev_erspan_pop_header(struct dp_packet *packet)
{
    const struct gre_base_hdr *greh;
    const struct erspan_base_hdr *ersh;
    struct pkt_metadata *md = &packet->md;
    struct flow_tnl *tnl = &md->tunnel;
    int hlen = sizeof(struct eth_header);
    unsigned int ulen;
    uint16_t greh_protocol;

    hlen += netdev_tnl_is_header_ipv6(dp_packet_data(packet)) ?
            IPV6_HEADER_LEN : IP_HEADER_LEN;

    pkt_metadata_init_tnl(md);
    if (hlen > dp_packet_size(packet)) {
        goto err;
    }

    greh = netdev_tnl_ip_extract_tnl_md(packet, tnl, &ulen);
    if (!greh) {
        goto err;
    }

    greh_protocol = ntohs(greh->protocol);
    if (greh_protocol != ETH_TYPE_ERSPAN1 &&
        greh_protocol != ETH_TYPE_ERSPAN2) {
        goto err;
    }

    if (greh->flags & ~htons(GRE_SEQ)) {
        goto err;
    }

    ersh = ERSPAN_HDR(greh);
    tnl->tun_id = be16_to_be64(htons(get_sid(ersh)));
    tnl->erspan_ver = ersh->ver;

    if (ersh->ver == 1) {
        ovs_16aligned_be32 *index = ALIGNED_CAST(ovs_16aligned_be32 *,
                                                 ersh + 1);
        tnl->erspan_idx = ntohl(get_16aligned_be32(index));
        tnl->flags |= FLOW_TNL_F_KEY;
        hlen = ulen + ERSPAN_GREHDR_LEN + sizeof *ersh + ERSPAN_V1_MDSIZE;
    } else if (ersh->ver == 2) {
        struct erspan_md2 *md2 = ALIGNED_CAST(struct erspan_md2 *, ersh + 1);
        tnl->erspan_dir = md2->dir;
        tnl->erspan_hwid = get_hwid(md2);
        tnl->flags |= FLOW_TNL_F_KEY;
        hlen = ulen + ERSPAN_GREHDR_LEN + sizeof *ersh + ERSPAN_V2_MDSIZE;
    } else {
        VLOG_WARN_RL(&err_rl, "ERSPAN version error %d", ersh->ver);
        goto err;
    }

    if (hlen > dp_packet_size(packet)) {
        goto err;
    }

    dp_packet_reset_packet(packet, hlen);

    return packet;
err:
    dp_packet_delete(packet);
    return NULL;
}

void
netdev_erspan_push_header(const struct netdev *netdev,
                          struct dp_packet *packet,
                          const struct ovs_action_push_tnl *data)
{
    struct netdev_vport *dev = netdev_vport_cast(netdev);
    struct erspan_base_hdr *ersh;
    struct gre_base_hdr *greh;
    struct erspan_md2 *md2;
    int ip_tot_size;

    greh = netdev_tnl_push_ip_header(packet, data->header, data->header_len,
                                     &ip_tot_size, 0);

    /* update GRE seqno */
    ovs_16aligned_be32 *seqno = (ovs_16aligned_be32 *) (greh + 1);
    put_16aligned_be32(seqno, htonl(atomic_count_inc(&dev->gre_seqno)));

    /* update v2 timestamp */
    if (greh->protocol == htons(ETH_TYPE_ERSPAN2)) {
        ersh = ERSPAN_HDR(greh);
        md2 = ALIGNED_CAST(struct erspan_md2 *, ersh + 1);
        put_16aligned_be32(&md2->timestamp, get_erspan_ts(ERSPAN_100US));
    }
}

int
netdev_erspan_build_header(const struct netdev *netdev,
                           struct ovs_action_push_tnl *data,
                           const struct netdev_tnl_build_header_params *params)
{
    const struct netdev_tunnel_config *tnl_cfg;
    struct gre_base_hdr *greh;
    struct erspan_base_hdr *ersh;
    unsigned int hlen;
    uint32_t tun_id;
    int erspan_ver;
    uint16_t sid;

    greh = netdev_tnl_ip_build_header(data, params, IPPROTO_GRE, 0);
    ersh = ERSPAN_HDR(greh);

    tun_id = ntohl(be64_to_be32(params->flow->tunnel.tun_id));
    /* ERSPAN only has 10-bit session ID */
    if (tun_id & ~ERSPAN_SID_MASK) {
        return EINVAL;
    } else {
        sid = (uint16_t) tun_id;
    }

    tnl_cfg = netdev_get_tunnel_config(netdev);

    if (tnl_cfg->erspan_ver_flow) {
        erspan_ver = params->flow->tunnel.erspan_ver;
    } else {
        erspan_ver = tnl_cfg->erspan_ver;
    }

    if (erspan_ver == 1) {
        greh->protocol = htons(ETH_TYPE_ERSPAN1);
        greh->flags = htons(GRE_SEQ);
        ersh->ver = 1;
        set_sid(ersh, sid);

        uint32_t erspan_idx = (tnl_cfg->erspan_idx_flow
                          ? params->flow->tunnel.erspan_idx
                          : tnl_cfg->erspan_idx);
        put_16aligned_be32(ALIGNED_CAST(ovs_16aligned_be32 *, ersh + 1),
                           htonl(erspan_idx));

        hlen = ERSPAN_GREHDR_LEN + sizeof *ersh + ERSPAN_V1_MDSIZE;
    } else if (erspan_ver == 2) {
        struct erspan_md2 *md2 = ALIGNED_CAST(struct erspan_md2 *, ersh + 1);

        greh->protocol = htons(ETH_TYPE_ERSPAN2);
        greh->flags = htons(GRE_SEQ);
        ersh->ver = 2;
        set_sid(ersh, sid);

        md2->sgt = 0; /* security group tag */
        md2->gra = 0;
        put_16aligned_be32(&md2->timestamp, 0);

        if (tnl_cfg->erspan_hwid_flow) {
            set_hwid(md2, params->flow->tunnel.erspan_hwid);
        } else {
            set_hwid(md2, tnl_cfg->erspan_hwid);
        }

        if (tnl_cfg->erspan_dir_flow) {
            md2->dir = params->flow->tunnel.erspan_dir;
        } else {
            md2->dir = tnl_cfg->erspan_dir;
        }

        hlen = ERSPAN_GREHDR_LEN + sizeof *ersh + ERSPAN_V2_MDSIZE;
    } else {
        VLOG_WARN_RL(&err_rl, "ERSPAN version error %d", tnl_cfg->erspan_ver);
        return EINVAL;
    }

    data->header_len += hlen;

    if (params->is_ipv6) {
        data->tnl_type = OVS_VPORT_TYPE_IP6ERSPAN;
    } else {
        data->tnl_type = OVS_VPORT_TYPE_ERSPAN;
    }
    return 0;
}

struct dp_packet *
netdev_gtpu_pop_header(struct dp_packet *packet)
{
    struct pkt_metadata *md = &packet->md;
    struct flow_tnl *tnl = &md->tunnel;
    struct gtpuhdr *gtph;
    unsigned int gtpu_hlen;
    unsigned int hlen;

    ovs_assert(packet->l3_ofs > 0);
    ovs_assert(packet->l4_ofs > 0);

    pkt_metadata_init_tnl(md);
    if (GTPU_HLEN > dp_packet_l4_size(packet)) {
        goto err;
    }

    gtph = udp_extract_tnl_md(packet, tnl, &hlen);
    if (!gtph) {
        goto err;
    }

    tnl->gtpu_flags = gtph->md.flags;
    tnl->gtpu_msgtype = gtph->md.msgtype;
    tnl->tun_id = be32_to_be64(get_16aligned_be32(&gtph->teid));

    if (tnl->gtpu_msgtype == GTPU_MSGTYPE_GPDU) {
        struct ip_header *ip;

        if (gtph->md.flags & GTPU_S_MASK) {
            gtpu_hlen = GTPU_HLEN + sizeof(struct gtpuhdr_opt);
        } else {
            gtpu_hlen = GTPU_HLEN;
        }
        ip = ALIGNED_CAST(struct ip_header *, (char *)gtph + gtpu_hlen);

        if (IP_VER(ip->ip_ihl_ver) == 4) {
            packet->packet_type = htonl(PT_IPV4);
        } else if (IP_VER(ip->ip_ihl_ver) == 6) {
            packet->packet_type = htonl(PT_IPV6);
        } else {
            VLOG_WARN_RL(&err_rl, "GTP-U: Receive non-IP packet.");
        }
        dp_packet_reset_packet(packet, hlen + gtpu_hlen);
    } else {
        /* non-GPDU GTP-U messages, ex: echo request, end marker.
         * Users should redirect these packets to controller, or.
         * any application that handles GTP-U messages, so keep
         * the original packet.
         */
        packet->packet_type = htonl(PT_ETH);
        VLOG_WARN_ONCE("Receive non-GPDU msgtype: %"PRIu8,
                       gtph->md.msgtype);
    }

    return packet;

err:
    dp_packet_delete(packet);
    return NULL;
}

void
netdev_gtpu_push_header(const struct netdev *netdev,
                        struct dp_packet *packet,
                        const struct ovs_action_push_tnl *data)
{
    struct netdev_vport *dev = netdev_vport_cast(netdev);
    struct udp_header *udp;
    struct gtpuhdr *gtpuh;
    int ip_tot_size;
    unsigned int payload_len;

    payload_len = dp_packet_size(packet);
    udp = netdev_tnl_push_ip_header(packet, data->header, data->header_len,
                                    &ip_tot_size, 0);
    udp->udp_src = netdev_tnl_get_src_port(packet);
    udp->udp_len = htons(ip_tot_size);
    /* Postpone checksum to the egress netdev. */
    dp_packet_hwol_set_csum_udp(packet);
    dp_packet_ol_reset_l4_csum_good(packet);

    gtpuh = ALIGNED_CAST(struct gtpuhdr *, udp + 1);

    if (gtpuh->md.flags & GTPU_S_MASK) {
        ovs_be16 *seqno = ALIGNED_CAST(ovs_be16 *, gtpuh + 1);
        *seqno = htons(atomic_count_inc(&dev->gre_seqno));
        payload_len += sizeof(struct gtpuhdr_opt);
    }
    gtpuh->len = htons(payload_len);
}

int
netdev_gtpu_build_header(const struct netdev *netdev,
                         struct ovs_action_push_tnl *data,
                         const struct netdev_tnl_build_header_params *params)
{
    const struct netdev_tunnel_config *tnl_cfg;
    struct gtpuhdr *gtph;
    unsigned int gtpu_hlen;

    tnl_cfg = netdev_get_tunnel_config(netdev);

    gtph = udp_build_header(tnl_cfg, data, params);

    /* Set to default if not set in flow. */
    gtph->md.flags = params->flow->tunnel.gtpu_flags ?
                     params->flow->tunnel.gtpu_flags : GTPU_FLAGS_DEFAULT;
    gtph->md.msgtype = params->flow->tunnel.gtpu_msgtype ?
                       params->flow->tunnel.gtpu_msgtype : GTPU_MSGTYPE_GPDU;
    put_16aligned_be32(&gtph->teid,
                       be64_to_be32(params->flow->tunnel.tun_id));

    gtpu_hlen = sizeof *gtph;
    if (tnl_cfg->set_seq) {
        gtph->md.flags |= GTPU_S_MASK;
        gtpu_hlen += sizeof(struct gtpuhdr_opt);
    }

    data->header_len += gtpu_hlen;
    data->tnl_type = OVS_VPORT_TYPE_GTPU;

    return 0;
}

int
netdev_srv6_build_header(const struct netdev *netdev,
                         struct ovs_action_push_tnl *data,
                         const struct netdev_tnl_build_header_params *params)
{
    const struct netdev_tunnel_config *tnl_cfg;
    const struct in6_addr *segs;
    struct srv6_base_hdr *srh;
    struct in6_addr *s;
    ovs_be16 dl_type;
    int nr_segs;
    int i;

    tnl_cfg = netdev_get_tunnel_config(netdev);
    if (tnl_cfg->srv6_num_segs) {
        nr_segs = tnl_cfg->srv6_num_segs;
        segs = tnl_cfg->srv6_segs;
    } else {
        /*
         * If explicit segment list setting is omitted, tunnel destination
         * is considered to be the first segment list.
         */
        nr_segs = 1;
        segs = &params->flow->tunnel.ipv6_dst;
    }

    if (!ipv6_addr_equals(&segs[0], &params->flow->tunnel.ipv6_dst)) {
        return EINVAL;
    }

    /* Writes the netdev_srv6_flowlabel enum value to the ipv6
     * flowlabel field. It must later be replaced by a valid value
     * in the header push. */
    srh = netdev_tnl_ip_build_header(data, params, IPPROTO_ROUTING,
                                     htonl(tnl_cfg->srv6_flowlabel));

    srh->rt_hdr.segments_left = nr_segs - 1;
    srh->rt_hdr.type = IPV6_SRCRT_TYPE_4;
    srh->rt_hdr.hdrlen = 2 * nr_segs;
    srh->last_entry = nr_segs - 1;
    srh->flags = 0;
    srh->tag = 0;

    dl_type = params->flow->dl_type;
    if (dl_type == htons(ETH_TYPE_IP)) {
        srh->rt_hdr.nexthdr = IPPROTO_IPIP;
    } else if (dl_type == htons(ETH_TYPE_IPV6)) {
        srh->rt_hdr.nexthdr = IPPROTO_IPV6;
    } else {
        return EOPNOTSUPP;
    }

    s = ALIGNED_CAST(struct in6_addr *,
                     (char *) srh + sizeof *srh);
    for (i = 0; i < nr_segs; i++) {
        /* Segment list is written to the header in reverse order. */
        memcpy(s, &segs[nr_segs - i - 1], sizeof *s);
        s++;
    }

    data->header_len += sizeof *srh + 8 * srh->rt_hdr.hdrlen;
    data->tnl_type = OVS_VPORT_TYPE_SRV6;

    return 0;
}

void
netdev_srv6_push_header(const struct netdev *netdev OVS_UNUSED,
                        struct dp_packet *packet,
                        const struct ovs_action_push_tnl *data)
{
    struct ovs_16aligned_ip6_hdr *inner_ip6, *outer_ip6;
    enum netdev_srv6_flowlabel srv6_flowlabel;
    ovs_be32 ipv6_label = 0;
    int ip_tot_size;
    uint32_t flow;

    inner_ip6 = dp_packet_l3(packet);
    outer_ip6 = netdev_tnl_ipv6_hdr((void *) data->header);
    srv6_flowlabel = ntohl(get_16aligned_be32(&outer_ip6->ip6_flow)) &
                     IPV6_LABEL_MASK;

    switch (srv6_flowlabel) {
    case SRV6_FLOWLABEL_COPY:
        flow = ntohl(get_16aligned_be32(&inner_ip6->ip6_flow));
        ipv6_label = (flow >> 28) == 6 ? htonl(flow & IPV6_LABEL_MASK) : 0;
        break;

    case SRV6_FLOWLABEL_ZERO:
        ipv6_label = 0;
        break;

    case SRV6_FLOWLABEL_COMPUTE:
        ipv6_label = htonl(dp_packet_get_rss_hash(packet) & IPV6_LABEL_MASK);
        break;
    }

    netdev_tnl_push_ip_header(packet, data->header,
                              data->header_len, &ip_tot_size, ipv6_label);
}

struct dp_packet *
netdev_srv6_pop_header(struct dp_packet *packet)
{
    const struct ovs_16aligned_ip6_hdr *nh = dp_packet_l3(packet);
    size_t size = dp_packet_l3_size(packet) - IPV6_HEADER_LEN;
    struct pkt_metadata *md = &packet->md;
    struct flow_tnl *tnl = &md->tunnel;
    const struct ip6_rt_hdr *rt_hdr;
    uint8_t nw_proto = nh->ip6_nxt;
    const void *data = nh + 1;
    uint8_t nw_frag = 0;
    unsigned int hlen;

    /*
     * Verifies that the routing header is present in the IPv6
     * extension headers and that its type is SRv6.
     */
    if (!parse_ipv6_ext_hdrs(&data, &size, &nw_proto, &nw_frag,
                             NULL, &rt_hdr)) {
        goto err;
    }

    if (!rt_hdr || rt_hdr->type != IPV6_SRCRT_TYPE_4) {
        goto err;
    }

    if (rt_hdr->segments_left > 0) {
        VLOG_WARN_RL(&err_rl, "invalid srv6 segments_left=%d\n",
                     rt_hdr->segments_left);
        goto err;
    }

    if (rt_hdr->nexthdr == IPPROTO_IPIP) {
        packet->packet_type = htonl(PT_IPV4);
    } else if (rt_hdr->nexthdr == IPPROTO_IPV6) {
        packet->packet_type = htonl(PT_IPV6);
    } else {
        goto err;
    }

    pkt_metadata_init_tnl(md);
    netdev_tnl_ip_extract_tnl_md(packet, tnl, &hlen);
    dp_packet_reset_packet(packet, hlen);

    return packet;
err:
    dp_packet_delete(packet);
    return NULL;
}

struct dp_packet *
netdev_vxlan_pop_header(struct dp_packet *packet)
{
    struct pkt_metadata *md = &packet->md;
    struct flow_tnl *tnl = &md->tunnel;
    struct vxlanhdr *vxh;
    unsigned int hlen;
    ovs_be32 vx_flags;
    enum packet_type next_pt = PT_ETH;

    ovs_assert(packet->l3_ofs > 0);
    ovs_assert(packet->l4_ofs > 0);

    pkt_metadata_init_tnl(md);
    if (VXLAN_HLEN > dp_packet_l4_size(packet)) {
        goto err;
    }

    vxh = udp_extract_tnl_md(packet, tnl, &hlen);
    if (!vxh) {
        goto err;
    }

    vx_flags = get_16aligned_be32(&vxh->vx_flags);
    if (vx_flags & htonl(VXLAN_HF_GPE)) {
        vx_flags &= htonl(~VXLAN_GPE_USED_BITS);
        /* Drop the OAM packets */
        if (vxh->vx_gpe.flags & VXLAN_GPE_FLAGS_O) {
            goto err;
        }
        switch (vxh->vx_gpe.next_protocol) {
        case VXLAN_GPE_NP_IPV4:
            next_pt = PT_IPV4;
            break;
        case VXLAN_GPE_NP_IPV6:
            next_pt = PT_IPV6;
            break;
        case VXLAN_GPE_NP_NSH:
            next_pt = PT_NSH;
            break;
        case VXLAN_GPE_NP_ETHERNET:
            next_pt = PT_ETH;
            break;
        default:
            goto err;
        }
    }

    if (vx_flags != htonl(VXLAN_FLAGS) ||
       (get_16aligned_be32(&vxh->vx_vni) & htonl(0xff))) {
        VLOG_WARN_RL(&err_rl, "invalid vxlan flags=%#x vni=%#x\n",
                     ntohl(vx_flags),
                     ntohl(get_16aligned_be32(&vxh->vx_vni)));
        goto err;
    }
    tnl->tun_id = htonll(ntohl(get_16aligned_be32(&vxh->vx_vni)) >> 8);
    tnl->flags |= FLOW_TNL_F_KEY;

    packet->packet_type = htonl(next_pt);
    dp_packet_reset_packet(packet, hlen + VXLAN_HLEN);
    if (next_pt != PT_ETH) {
        packet->l3_ofs = 0;
    }

    return packet;
err:
    dp_packet_delete(packet);
    return NULL;
}

int
netdev_vxlan_build_header(const struct netdev *netdev,
                          struct ovs_action_push_tnl *data,
                          const struct netdev_tnl_build_header_params *params)
{
    const struct netdev_tunnel_config *tnl_cfg;
    struct vxlanhdr *vxh;

    tnl_cfg = netdev_get_tunnel_config(netdev);

    vxh = udp_build_header(tnl_cfg, data, params);

    if (tnl_cfg->exts & (1 << OVS_VXLAN_EXT_GPE)) {
        put_16aligned_be32(&vxh->vx_flags, htonl(VXLAN_FLAGS | VXLAN_HF_GPE));
        put_16aligned_be32(&vxh->vx_vni,
                           htonl(ntohll(params->flow->tunnel.tun_id) << 8));
        if (params->flow->packet_type == htonl(PT_ETH)) {
            vxh->vx_gpe.next_protocol = VXLAN_GPE_NP_ETHERNET;
        } else if (pt_ns(params->flow->packet_type) == OFPHTN_ETHERTYPE) {
            switch (pt_ns_type(params->flow->packet_type)) {
            case ETH_TYPE_IP:
                vxh->vx_gpe.next_protocol = VXLAN_GPE_NP_IPV4;
                break;
            case ETH_TYPE_IPV6:
                vxh->vx_gpe.next_protocol = VXLAN_GPE_NP_IPV6;
                break;
            case ETH_TYPE_NSH:
                vxh->vx_gpe.next_protocol = VXLAN_GPE_NP_NSH;
                break;
            case ETH_TYPE_TEB:
                vxh->vx_gpe.next_protocol = VXLAN_GPE_NP_ETHERNET;
                break;
            default:
                return EINVAL;
            }
        } else {
            return EINVAL;
        }
    } else {
        put_16aligned_be32(&vxh->vx_flags, htonl(VXLAN_FLAGS));
        put_16aligned_be32(&vxh->vx_vni,
                           htonl(ntohll(params->flow->tunnel.tun_id) << 8));
    }

    data->header_len += sizeof *vxh;
    data->tnl_type = OVS_VPORT_TYPE_VXLAN;
    return 0;
}

struct dp_packet *
netdev_geneve_pop_header(struct dp_packet *packet)
{
    struct pkt_metadata *md = &packet->md;
    struct flow_tnl *tnl = &md->tunnel;
    struct genevehdr *gnh;
    unsigned int hlen, opts_len, ulen;

    pkt_metadata_init_tnl(md);
    if (GENEVE_BASE_HLEN > dp_packet_l4_size(packet)) {
        VLOG_WARN_RL(&err_rl, "geneve packet too small: min header=%u packet size=%"PRIuSIZE"\n",
                     (unsigned int)GENEVE_BASE_HLEN, dp_packet_l4_size(packet));
        goto err;
    }

    gnh = udp_extract_tnl_md(packet, tnl, &ulen);
    if (!gnh) {
        goto err;
    }

    opts_len = gnh->opt_len * 4;
    hlen = ulen + GENEVE_BASE_HLEN + opts_len;
    if (hlen > dp_packet_size(packet)) {
        VLOG_WARN_RL(&err_rl, "geneve packet too small: header len=%u packet size=%u\n",
                     hlen, dp_packet_size(packet));
        goto err;
    }

    if (gnh->ver != 0) {
        VLOG_WARN_RL(&err_rl, "unknown geneve version: %"PRIu8"\n", gnh->ver);
        goto err;
    }

    if (gnh->proto_type != htons(ETH_TYPE_TEB)) {
        VLOG_WARN_RL(&err_rl, "unknown geneve encapsulated protocol: %#x\n",
                     ntohs(gnh->proto_type));
        goto err;
    }

    tnl->flags |= gnh->oam ? FLOW_TNL_F_OAM : 0;
    tnl->tun_id = htonll(ntohl(get_16aligned_be32(&gnh->vni)) >> 8);
    tnl->flags |= FLOW_TNL_F_KEY;

    memcpy(tnl->metadata.opts.gnv, gnh->options, opts_len);
    tnl->metadata.present.len = opts_len;
    tnl->flags |= FLOW_TNL_F_UDPIF;

    packet->packet_type = htonl(PT_ETH);
    dp_packet_reset_packet(packet, hlen);

    return packet;
err:
    dp_packet_delete(packet);
    return NULL;
}

int
netdev_geneve_build_header(const struct netdev *netdev,
                           struct ovs_action_push_tnl *data,
                           const struct netdev_tnl_build_header_params *params)
{
    struct genevehdr *gnh;
    int opt_len;
    bool crit_opt;

    gnh = udp_build_header(netdev_get_tunnel_config(netdev), data, params);

    put_16aligned_be32(&gnh->vni, htonl(ntohll(params->flow->tunnel.tun_id) << 8));

    opt_len = tun_metadata_to_geneve_header(&params->flow->tunnel,
                                            gnh->options, &crit_opt);

    gnh->opt_len = opt_len / 4;
    gnh->oam = !!(params->flow->tunnel.flags & FLOW_TNL_F_OAM);
    gnh->critical = crit_opt ? 1 : 0;
    gnh->proto_type = htons(ETH_TYPE_TEB);

    data->header_len += sizeof *gnh + opt_len;
    data->tnl_type = OVS_VPORT_TYPE_GENEVE;
    return 0;
}


void
netdev_tnl_egress_port_range(struct unixctl_conn *conn, int argc,
                             const char *argv[], void *aux OVS_UNUSED)
{
    int val1, val2;

    if (argc < 3) {
        struct ds ds = DS_EMPTY_INITIALIZER;

        ds_put_format(&ds, "Tunnel UDP source port range: %"PRIu16"-%"PRIu16"\n",
                            tnl_udp_port_min, tnl_udp_port_max);

        unixctl_command_reply(conn, ds_cstr(&ds));
        ds_destroy(&ds);
        return;
    }

    if (argc != 3) {
        return;
    }

    val1 = atoi(argv[1]);
    if (val1 <= 0 || val1 > UINT16_MAX) {
        unixctl_command_reply(conn, "Invalid min.");
        return;
    }
    val2 = atoi(argv[2]);
    if (val2 <= 0 || val2 > UINT16_MAX) {
        unixctl_command_reply(conn, "Invalid max.");
        return;
    }

    if (val1 > val2) {
        tnl_udp_port_min = val2;
        tnl_udp_port_max = val1;
    } else {
        tnl_udp_port_min = val1;
        tnl_udp_port_max = val2;
    }
    seq_change(tnl_conf_seq);

    unixctl_command_reply(conn, "OK");
}
