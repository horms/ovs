/*
 * Copyright (c) 2012 Nicira, Inc.
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <features.h>
#ifndef __aligned_u64
#define __aligned_u64 __u64 __attribute__((aligned(8)))
#endif
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <arpa/inet.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include "csum.h"
#include "packets.h"

#define PKT_LENGTH	     512
#define ETH_DST_ADDR_OFF     0
#define ETH_SRC_ADDR_OFF     ETH_DST_ADDR_OFF  + ETH_ALEN
#define ETH_TYPE_ADDR_OFF    ETH_SRC_ADDR_OFF  + ETH_ALEN
#define VLAN_TPID_ADDR_OFF   ETH_TYPE_ADDR_OFF
#define VLAN_VID_ADDR_OFF    VLAN_TPID_ADDR_OFF + 2
#define VLAN_TYPE_ADDR_OFF   VLAN_VID_ADDR_OFF + 2
#define MPLS_HDR_ADDR_OFF    ETH_TYPE_ADDR_OFF + 2
#define IP_HDR_ADDR_OFF      MPLS_HDR_ADDR_OFF + 4

struct vlan_hdr {
    uint16_t value;
};

static int
create_sock (int proto)
{
    int sock_fd;

    if ((sock_fd = socket(AF_PACKET, SOCK_RAW, proto)) == -1) {
        perror("Error creating socket: ");
        exit(-1);
    }
    return sock_fd;
}

static int
bind_sock (char *device, int sock_fd, int protocol)
{

    struct sockaddr_ll sll;
    struct ifreq ifr;
    bzero(&sll, sizeof(sll));
    bzero(&ifr, sizeof(ifr));

    /* First Get the Interface Index  */
    strncpy((char *)ifr.ifr_name, device, IFNAMSIZ);
    if ((ioctl(sock_fd, SIOCGIFINDEX, &ifr)) == -1) {
        printf("Error getting Interface index !\n");
        exit(-1);
    }

    /* Bind socket to this interface */
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = ifr.ifr_ifindex;
    sll.sll_protocol = htons(protocol);

    if ((bind(sock_fd, (struct sockaddr *)&sll, sizeof(sll)))== -1) {
        perror("Error binding socket to interface\n");
        exit(-1);
    }

    return 1;
}

static int
send_pkt (int sock_fd, uint8_t *pkt, int pkt_len)
{
    int sent = 0;

    /* A simple write on the socket ..thats all it takes ! */

    if ((sent = write(sock_fd, pkt, pkt_len)) != pkt_len) {
        return 0;
    }
    return 1;
}

static void
write_ether_type (uint8_t *pkt, uint16_t eth_type)
{
    ovs_be16 tmp_eth_type;
    tmp_eth_type = htons(eth_type);
    memcpy((void*)pkt, (void*)&tmp_eth_type, 2);
}

static void
write_ether_hdr (uint8_t *pkt, uint16_t eth_type)
{
    ovs_be16 tmp_eth_type;
    /*MAC address of the host*/
    uint8_t src_mac[ETH_ALEN] = {0x00, 0x27, 0x13, 0x67, 0xb9, 0x9b};

    /*gateway MAC address*/
    uint8_t dest_mac[ETH_ALEN] = {0x00, 0x1f, 0x9e, 0x2a, 0x7f, 0xdd};

    tmp_eth_type = htons(eth_type);

    memcpy((void*)(pkt + ETH_DST_ADDR_OFF), (void*)dest_mac, ETH_ALEN);
    memcpy((void*)(pkt + ETH_SRC_ADDR_OFF), (void*)src_mac, ETH_ALEN);
    memcpy((void*)(pkt + ETH_TYPE_ADDR_OFF), (void*)&tmp_eth_type, 2);
}

static void
write_vlan_hdr (uint8_t *pkt, uint16_t vid, uint16_t pcp, uint16_t id)
{
    struct vlan_hdr vlan_h;
    ovs_be16 vlan_raw;
    ovs_be16 tpid = htons(id);

    vlan_h.value = ((vid << VLAN_VID_SHIFT) & VLAN_VID_MASK) |
                   ((pcp << VLAN_PCP_SHIFT) & VLAN_PCP_MASK);

    vlan_raw = htons(vlan_h.value);

    memcpy((void*)pkt, (void *)&tpid, 2);
    memcpy((void*)(pkt+2), (void *) &vlan_raw, 2);
}

static void
write_mpls_hdr (uint8_t *pkt, uint32_t label,
                uint32_t tc, uint32_t s, uint32_t ttl)
{
    struct mpls_hdr mpls_h;

    mpls_h.mpls_lse = htonl(((ttl << MPLS_TTL_SHIFT) &  MPLS_TTL_MASK)  |
                            ((tc << MPLS_TC_SHIFT) & MPLS_TC_MASK)      |
                            ((s << MPLS_STACK_SHIFT) & MPLS_STACK_MASK) |
                            ((label << MPLS_LABEL_SHIFT) & MPLS_LABEL_MASK));

    memcpy((void*)(pkt), (void *) &mpls_h.mpls_lse, 4);
}

static void
write_ip_hdr (uint8_t *pkt, uint16_t ip_pkt_len)
{
     uint8_t ip_hdr[20] = { 0x45, 0x07, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00,
                            0x10, 0x11, 0xa3, 0xfc,
                            0x0a, 0x75, 0x2e, 0xc8,
                            0x0a, 0x75, 0x2e, 0xc1};

    ip_hdr[2] = (0xFF00 & ip_pkt_len) >> 8;
    ip_hdr[3] = 0x00FF & ip_pkt_len;

    memcpy((void *)(pkt), (void *) &ip_hdr, 20);
}

static void
write_udp_hdr (uint8_t *pkt, uint16_t udp_len)
{
    uint8_t udp_hdr[8] = {0x0F, 0x00, 0x0F, 0x00,
                          0x00, 0x00, 0x00, 0x00};
    udp_hdr[4] = (0xFF00 & udp_len) >> 8;
    udp_hdr[5] = (0x00FF & udp_len);
    memcpy((void *)(pkt), (void *) &udp_hdr, 8);
}

static void
write_ip_csum (uint8_t *pkt, uint16_t len)
{
    /* len should be just the length of the header */
    ovs_be16 ip_csum = 0;

    /* initialize the ip checksum field to 0 for
     * purposes of calculating the header */
    memcpy(pkt + 10, &ip_csum, 2);

    /* appears to return in network byte order somehow */
    ip_csum = csum(pkt, len);
    memcpy(pkt + 10, &ip_csum, 2);
}

/* argv[1] is the device e.g. eth0
   argv[2] is the number of pkts to send
*/
int
main (int argc, char **argv)
{

    int sock_fd;
    uint8_t pkt[PKT_LENGTH];
    uint8_t *pkt_pos = pkt;
    uint8_t *ip_pos;
    uint32_t label = 101, tc = 4, ttl = 10;
    uint16_t vid = 101, pcp = 4;
    uint32_t num_of_pkts, num_labels;
    uint16_t i = 0;
    char *str = "FEEDFACE", type[5];

    if (argc != 5) {
        printf("usage: %s <device> <# pkts> <#labels> <type=vlan/mpls>\n", argv[0]);
        return -1;
    }

    num_of_pkts = atoi(argv[2]);

    strncpy(type, argv[argc-1], 5);

    /* Set the magic data 0xfeedface */
    for (i = 0; i < PKT_LENGTH; i+=8) {
        memcpy((void*)(pkt + i), (void*)str, 8);
    }

    num_labels = atoi(argv[3]);

    if (!strcmp(type, "vlan")) {
        write_ether_hdr(pkt_pos, ETH_TYPE_IP);
        pkt_pos += ETH_TYPE_ADDR_OFF;
        for (i = 0; i < num_labels; i++) {
            if (i == 1 || num_labels == 1) {
                write_vlan_hdr(pkt_pos, vid++, pcp++, ETH_TYPE_VLAN);
            }
            else {
                write_vlan_hdr(pkt_pos, vid++, pcp++, ETH_TYPE_VLAN);
            }
            pkt_pos += 4;
        }
        write_ether_type(pkt_pos, ETH_TYPE_IP);
        pkt_pos+=2;
    } else {
        write_ether_hdr(pkt_pos, ETH_TYPE_MPLS);
        pkt_pos += MPLS_HDR_ADDR_OFF;
        for (i = 0; i < num_labels; i++) {
            if (i == num_labels - 1) {
                write_mpls_hdr(pkt_pos, label++, tc, 1, ttl++);
            } else {
                write_mpls_hdr(pkt_pos, label++, tc, 0, ttl++);
            }
            pkt_pos += 4;
        }
    }

    ip_pos = pkt_pos;
    write_ip_hdr(pkt_pos, PKT_LENGTH - (ip_pos - pkt));
    pkt_pos += 20;

    write_udp_hdr(pkt_pos, PKT_LENGTH -(pkt_pos - pkt));
    pkt_pos += 8;

    write_ip_csum(ip_pos, 20);

    /* Create the socket */
    sock_fd = create_sock(ETH_P_ALL);

    /* Bind socket to interface */
    bind_sock(argv[1], sock_fd, ETH_P_ALL);

    while ((num_of_pkts--) > 0) {
        if (!send_pkt(sock_fd, pkt, PKT_LENGTH)) {
            perror("Error sending pkt");
            printf("\n\n");
            break;
        }
    }
    printf("\nPrinting packet\n");
    for (i = 0; i < 50; i++)
        printf("%x ", pkt[i]);
    if (num_of_pkts == -1)
        printf("Packets sent successfully\n");

    close(sock_fd);
    return 0;
}
