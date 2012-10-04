#ifndef __LINUX_GSO_WRAPPER_H
#define __LINUX_GSO_WRAPPER_H

#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <net/protocol.h>

#include "datapath.h"

struct ovs_gso_cb {
	struct ovs_skb_cb dp_cb;
	sk_buff_data_t	inner_network_header;
	sk_buff_data_t	inner_mac_header;
	void (*fix_segment)(struct sk_buff *);
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,11,0)
	__be16			inner_protocol;
#endif
};
#define OVS_GSO_CB(skb) ((struct ovs_gso_cb *)(skb)->cb)

#define skb_inner_network_header rpl_skb_inner_network_header

#ifdef NET_SKBUFF_DATA_USES_OFFSET
#define skb_inner_network_header rpl_skb_inner_network_header
static inline unsigned char *skb_inner_network_header(const struct sk_buff *skb)
{
	return skb->head + OVS_GSO_CB(skb)->inner_network_header;
}

#define skb_inner_mac_header rpl_skb_inner_mac_header
static inline unsigned char *skb_inner_mac_header(const struct sk_buff *skb)
{
	return skb->head + OVS_GSO_CB(skb)->inner_mac_header;
}

#else

#define skb_inner_network_header rpl_skb_inner_network_header
static inline unsigned char *skb_inner_network_header(const struct sk_buff *skb)
{
	return OVS_GSO_CB(skb)->inner_network_header;
}

#define skb_inner_mac_header rpl_skb_inner_mac_header
static inline unsigned char *skb_inner_mac_header(const struct sk_buff *skb)
{
	return OVS_GSO_CB(skb)->inner_mac_header;
}

#endif

#define skb_inner_network_offset rpl_skb_inner_network_offset
static inline int skb_inner_network_offset(const struct sk_buff *skb)
{
	return skb_inner_network_header(skb) - skb->data;
}

#define skb_inner_mac_offset rpl_skb_inner_mac_offset
static inline int skb_inner_mac_offset(const struct sk_buff *skb)
{
	return skb_inner_mac_header(skb) - skb->data;
}

#define skb_reset_inner_headers rpl_skb_reset_inner_headers
static inline void skb_reset_inner_headers(struct sk_buff *skb)
{
	BUILD_BUG_ON(sizeof(struct ovs_gso_cb) > FIELD_SIZEOF(struct sk_buff, cb));
	OVS_GSO_CB(skb)->inner_network_header = skb->network_header;
	OVS_GSO_CB(skb)->inner_mac_header = skb->mac_header;

	OVS_GSO_CB(skb)->fix_segment = NULL;
}

#define ip_local_out rpl_ip_local_out
int ip_local_out(struct sk_buff *skb);

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,11,0)
static inline void ovs_skb_init_inner_protocol(struct sk_buff *skb) {
	OVS_GSO_CB(skb)->inner_protocol = htons(0);
}

static inline void ovs_skb_set_inner_protocol(struct sk_buff *skb,
					      __be16 ethertype) {
	OVS_GSO_CB(skb)->inner_protocol = ethertype;
}

static inline __be16 ovs_skb_get_inner_protocol(struct sk_buff *skb)
{
	return OVS_GSO_CB(skb)->inner_protocol;
}

#else

static inline void ovs_skb_init_inner_protocol(struct sk_buff *skb) {
	/* Nothing to do. The inner_protocol is either zero or
	 * has been set to a value by another user.
	 * Either way it may be considered initialised.
	 */
}

static inline void ovs_skb_set_inner_protocol(struct sk_buff *skb,
					      __be16 ethertype)
{
	skb->inner_protocol = ethertype;
}

static inline __be16 ovs_skb_get_inner_protocol(struct sk_buff *skb)
{
	return skb->inner_protocol;
}
#endif

#endif
