/*
 * Copyright (c) 2008, 2009, 2010, 2011, 2012, 2013, 2014, 2015, 2016, 2017 Nicira, Inc.
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
#ifndef FLOW_H
#define FLOW_H 1

#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/icmp6.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include "bitmap.h"
#include "byte-order.h"
#include "openvswitch/compiler.h"
#include "openflow/nicira-ext.h"
#include "openflow/openflow.h"
#include "openvswitch/flow.h"
#include "packets.h"
#include "hash.h"
#include "util.h"

struct dpif_flow_stats;
struct dpif_flow_attrs;
struct ds;
struct flow_wildcards;
struct minimask;
struct dp_packet;
struct ofputil_port_map;
struct pkt_metadata;
struct match;

/* Some flow fields are mutually exclusive or only appear within the flow
 * pipeline.  IPv6 headers are bigger than IPv4 and MPLS, and IPv6 ND packets
 * are bigger than TCP,UDP and IGMP packets. */
#define FLOW_MAX_PACKET_U64S (FLOW_U64S                                   \
    /* Unused in datapath */  - FLOW_U64_SIZE(regs)                       \
                              - FLOW_U64_SIZE(metadata)                   \
    /* L2.5/3 */              - FLOW_U64_SIZE(nw_src)  /* incl. nw_dst */ \
                              - FLOW_U64_SIZE(mpls_lse)                   \
    /* L4 */                  - FLOW_U64_SIZE(tp_src)                     \
                             )

extern const uint8_t flow_segment_u64s[];

/* Configured maximum VLAN headers. */
extern int flow_vlan_limit;

#define FLOW_U64_OFFSET(FIELD)                          \
    (offsetof(struct flow, FIELD) / sizeof(uint64_t))
#define FLOW_U64_OFFREM(FIELD)                          \
    (offsetof(struct flow, FIELD) % sizeof(uint64_t))

/* Number of 64-bit units spanned by a 'FIELD'. */
#define FLOW_U64_SIZE(FIELD)                                            \
    DIV_ROUND_UP(FLOW_U64_OFFREM(FIELD) + MEMBER_SIZEOF(struct flow, FIELD), \
                 sizeof(uint64_t))

void flow_extract(struct dp_packet *, struct flow *);

void flow_zero_wildcards(struct flow *, const struct flow_wildcards *);
void flow_unwildcard_tp_ports(const struct flow *, struct flow_wildcards *);
void flow_get_metadata(const struct flow *, struct match *flow_metadata);
struct netdev *flow_get_tunnel_netdev(struct flow_tnl *tunnel);

const char *ct_state_to_string(uint32_t state);
uint32_t ct_state_from_string(const char *);
bool parse_ct_state(const char *state_str, uint32_t default_state,
                    uint32_t *ct_state, struct ds *);
bool validate_ct_state(uint32_t state, struct ds *);
void flow_clear_conntrack(struct flow *);

char *flow_to_string(const struct flow *, const struct ofputil_port_map *);
void format_flags(struct ds *ds, const char *(*bit_to_string)(uint32_t),
                  uint32_t flags, char del);
void format_flags_masked(struct ds *ds, const char *name,
                         const char *(*bit_to_string)(uint32_t),
                         uint32_t flags, uint32_t mask, uint32_t max_mask);
void format_packet_type_masked(struct ds *, ovs_be32 value, ovs_be32 mask);
int parse_flags(const char *s, const char *(*bit_to_string)(uint32_t),
                char end, const char *field_name, char **res_string,
                uint32_t *res_flags, uint32_t allowed, uint32_t *res_mask);

void flow_format(struct ds *, const struct flow *,
                 const struct ofputil_port_map *);
void flow_print(FILE *, const struct flow *, const struct ofputil_port_map *);
static inline int flow_compare_3way(const struct flow *, const struct flow *);
static inline bool flow_equal(const struct flow *, const struct flow *);
static inline size_t flow_hash(const struct flow *, uint32_t basis);

void flow_set_dl_vlan(struct flow *, ovs_be16 vid, int id);
void flow_fix_vlan_tpid(struct flow *);
void flow_set_vlan_vid(struct flow *, ovs_be16 vid);
void flow_set_vlan_pcp(struct flow *, uint8_t pcp, int id);

void flow_limit_vlans(int vlan_limit);
int flow_count_vlan_headers(const struct flow *);
void flow_skip_common_vlan_headers(const struct flow *a, int *p_an,
                                   const struct flow *b, int *p_bn);
void flow_pop_vlan(struct flow*, struct flow_wildcards*);
void flow_push_vlan_uninit(struct flow*, struct flow_wildcards*);

int flow_count_mpls_labels(const struct flow *, struct flow_wildcards *);
int flow_count_common_mpls_labels(const struct flow *a, int an,
                                  const struct flow *b, int bn,
                                  struct flow_wildcards *wc);
void flow_push_mpls(struct flow *, int n, ovs_be16 mpls_eth_type,
                    struct flow_wildcards *, bool clear_flow_L3);
bool flow_pop_mpls(struct flow *, int n, ovs_be16 eth_type,
                   struct flow_wildcards *);
void flow_set_mpls_label(struct flow *, int idx, ovs_be32 label);
void flow_set_mpls_ttl(struct flow *, int idx, uint8_t ttl);
void flow_set_mpls_tc(struct flow *, int idx, uint8_t tc);
void flow_set_mpls_bos(struct flow *, int idx, uint8_t stack);
void flow_set_mpls_lse(struct flow *, int idx, ovs_be32 lse);

void flow_compose(struct dp_packet *, const struct flow *,
                  const void *l7, size_t l7_len);
void packet_expand(struct dp_packet *, const struct flow *, size_t size);

bool parse_ipv6_ext_hdrs(const void **datap, size_t *sizep, uint8_t *nw_proto,
                         uint8_t *nw_frag,
                         const struct ovs_16aligned_ip6_frag **frag_hdr,
                         const struct ip6_rt_hdr **rt_hdr);
bool parse_nsh(const void **datap, size_t *sizep, struct ovs_key_nsh *key);
uint16_t parse_tcp_flags(struct dp_packet *packet, ovs_be16 *dl_type_p,
                         uint8_t *nw_frag_p, ovs_be16 *first_vlan_tci_p);

static inline uint64_t
flow_get_xreg(const struct flow *flow, int idx)
{
    return ((uint64_t) flow->regs[idx * 2] << 32) | flow->regs[idx * 2 + 1];
}

static inline void
flow_set_xreg(struct flow *flow, int idx, uint64_t value)
{
    flow->regs[idx * 2] = value >> 32;
    flow->regs[idx * 2 + 1] = value;
}

static inline ovs_u128
flow_get_xxreg(const struct flow *flow, int idx)
{
    ovs_u128 value;

    value.u64.hi = (uint64_t) flow->regs[idx * 4] << 32;
    value.u64.hi |= flow->regs[idx * 4 + 1];
    value.u64.lo = (uint64_t) flow->regs[idx * 4 + 2] << 32;
    value.u64.lo |= flow->regs[idx * 4 + 3];

    return value;
}

static inline void
flow_set_xxreg(struct flow *flow, int idx, ovs_u128 value)
{
    flow->regs[idx * 4] = value.u64.hi >> 32;
    flow->regs[idx * 4 + 1] = value.u64.hi;
    flow->regs[idx * 4 + 2] = value.u64.lo >> 32;
    flow->regs[idx * 4 + 3] = value.u64.lo;
}

static inline int
flow_compare_3way(const struct flow *a, const struct flow *b)
{
    return memcmp(a, b, sizeof *a);
}

static inline bool
flow_equal(const struct flow *a, const struct flow *b)
{
    return !flow_compare_3way(a, b);
}

static inline size_t
flow_hash(const struct flow *flow, uint32_t basis)
{
    return hash_bytes64((const uint64_t *)flow, sizeof *flow, basis);
}

static inline uint16_t
ofp_to_u16(ofp_port_t ofp_port)
{
    return (OVS_FORCE uint16_t) ofp_port;
}

static inline uint32_t
odp_to_u32(odp_port_t odp_port)
{
    return (OVS_FORCE uint32_t) odp_port;
}

static inline uint32_t
ofp11_to_u32(ofp11_port_t ofp11_port)
{
    return (OVS_FORCE uint32_t) ofp11_port;
}

static inline ofp_port_t
u16_to_ofp(uint16_t port)
{
    return OFP_PORT_C(port);
}

static inline odp_port_t
u32_to_odp(uint32_t port)
{
    return ODP_PORT_C(port);
}

static inline ofp11_port_t
u32_to_ofp11(uint32_t port)
{
    return OFP11_PORT_C(port);
}

static inline uint32_t
hash_ofp_port(ofp_port_t ofp_port)
{
    return hash_int(ofp_to_u16(ofp_port), 0);
}

static inline uint32_t
hash_odp_port(odp_port_t odp_port)
{
    return hash_int(odp_to_u32(odp_port), 0);
}

uint32_t flow_hash_5tuple(const struct flow *flow, uint32_t basis);
uint32_t flow_hash_symmetric_l4(const struct flow *flow, uint32_t basis);
uint32_t flow_hash_symmetric_l2(const struct flow *flow, uint32_t basis);
uint32_t flow_hash_symmetric_l3l4(const struct flow *flow, uint32_t basis,
                         bool inc_udp_ports );
uint32_t flow_hash_symmetric_l3(const struct flow *flow, uint32_t basis);

/* Initialize a flow with random fields that matter for nx_hash_fields. */
void flow_random_hash_fields(struct flow *);
void flow_mask_hash_fields(const struct flow *, struct flow_wildcards *,
                           enum nx_hash_fields);
uint32_t flow_hash_fields(const struct flow *, enum nx_hash_fields,
                          uint16_t basis);
const char *flow_hash_fields_to_str(enum nx_hash_fields);
bool flow_hash_fields_valid(enum nx_hash_fields);

uint32_t flow_hash_in_wildcards(const struct flow *,
                                const struct flow_wildcards *,
                                uint32_t basis);

bool flow_equal_except(const struct flow *a, const struct flow *b,
                       const struct flow_wildcards *);

/* Bitmap for flow values.  For each 1-bit the corresponding flow value is
 * explicitly specified, other values are zeroes.
 *
 * map_t must be wide enough to hold any member of struct flow. */
typedef unsigned long long map_t;
#define MAP_T_BITS (sizeof(map_t) * CHAR_BIT)
#define MAP_1 (map_t)1
#define MAP_MAX TYPE_MAXIMUM(map_t)

#define MAP_IS_SET(MAP, IDX) ((MAP) & (MAP_1 << (IDX)))

/* Iterate through the indices of all 1-bits in 'MAP'. */
#define MAP_FOR_EACH_INDEX(IDX, MAP)            \
    ULLONG_FOR_EACH_1(IDX, MAP)

#define FLOWMAP_UNITS DIV_ROUND_UP(FLOW_U64S, MAP_T_BITS)

struct flowmap {
    map_t bits[FLOWMAP_UNITS];
};

#define FLOWMAP_EMPTY_INITIALIZER { { 0 } }

static inline void flowmap_init(struct flowmap *);
static inline bool flowmap_equal(struct flowmap, struct flowmap);
static inline bool flowmap_is_set(const struct flowmap *, size_t idx);
static inline bool flowmap_are_set(const struct flowmap *, size_t idx,
                                   unsigned int n_bits);
static inline void flowmap_set(struct flowmap *, size_t idx,
                               unsigned int n_bits);
static inline void flowmap_clear(struct flowmap *, size_t idx,
                                 unsigned int n_bits);
static inline struct flowmap flowmap_or(struct flowmap, struct flowmap);
static inline struct flowmap flowmap_and(struct flowmap, struct flowmap);
static inline bool flowmap_is_empty(struct flowmap);
static inline unsigned int flowmap_n_1bits(struct flowmap);

#define FLOWMAP_HAS_FIELD(FM, FIELD)                                    \
    flowmap_are_set(FM, FLOW_U64_OFFSET(FIELD), FLOW_U64_SIZE(FIELD))

#define FLOWMAP_SET(FM, FIELD)                                      \
    flowmap_set(FM, FLOW_U64_OFFSET(FIELD), FLOW_U64_SIZE(FIELD))

#define FLOWMAP_SET__(FM, FIELD, SIZE)                  \
    flowmap_set(FM, FLOW_U64_OFFSET(FIELD),             \
                DIV_ROUND_UP(SIZE, sizeof(uint64_t)))

/* XXX: Only works for full 64-bit units. */
#define FLOWMAP_CLEAR(FM, FIELD)                                        \
    BUILD_ASSERT_DECL(FLOW_U64_OFFREM(FIELD) == 0);                     \
    BUILD_ASSERT_DECL(sizeof(((struct flow *)0)->FIELD) % sizeof(uint64_t) == 0); \
    flowmap_clear(FM, FLOW_U64_OFFSET(FIELD), FLOW_U64_SIZE(FIELD))

/* Iterate through all units in 'FMAP'. */
#define FLOWMAP_FOR_EACH_UNIT(UNIT)                     \
    for ((UNIT) = 0; (UNIT) < FLOWMAP_UNITS; (UNIT)++)

/* Iterate through all map units in 'FMAP'. */
#define FLOWMAP_FOR_EACH_MAP(MAP, FLOWMAP)                              \
    for (size_t unit__ = 0;                                       \
         unit__ < FLOWMAP_UNITS && ((MAP) = (FLOWMAP).bits[unit__], true); \
         unit__++)

struct flowmap_aux;
static inline bool flowmap_next_index(struct flowmap_aux *, size_t *idx);

#define FLOWMAP_AUX_INITIALIZER(FLOWMAP) { .unit = 0, .map = (FLOWMAP) }

/* Iterate through all struct flow u64 indices specified by 'MAP'.  This is a
 * slower but easier version of the FLOWMAP_FOR_EACH_MAP() &
 * MAP_FOR_EACH_INDEX() combination. */
#define FLOWMAP_FOR_EACH_INDEX(IDX, MAP)                            \
    for (struct flowmap_aux aux__ = FLOWMAP_AUX_INITIALIZER(MAP);   \
         flowmap_next_index(&aux__, &(IDX));)

/* Flowmap inline implementations. */
static inline void
flowmap_init(struct flowmap *fm)
{
    memset(fm, 0, sizeof *fm);
}

static inline bool
flowmap_equal(struct flowmap a, struct flowmap b)
{
    return !memcmp(&a, &b, sizeof a);
}

static inline bool
flowmap_is_set(const struct flowmap *fm, size_t idx)
{
    return (fm->bits[idx / MAP_T_BITS] & (MAP_1 << (idx % MAP_T_BITS))) != 0;
}

/* Returns 'true' if any of the 'n_bits' bits starting at 'idx' are set in
 * 'fm'.  'n_bits' can be at most MAP_T_BITS. */
static inline bool
flowmap_are_set(const struct flowmap *fm, size_t idx, unsigned int n_bits)
{
    map_t n_bits_mask = (MAP_1 << n_bits) - 1;
    size_t unit = idx / MAP_T_BITS;

    idx %= MAP_T_BITS;

    if (fm->bits[unit] & (n_bits_mask << idx)) {
        return true;
    }
    /* The seemingly unnecessary bounds check on 'unit' is a workaround for a
     * false-positive array out of bounds error by GCC 4.9. */
    if (unit + 1 < FLOWMAP_UNITS && idx + n_bits > MAP_T_BITS) {
        /* Check the remaining bits from the next unit. */
        return fm->bits[unit + 1] & (n_bits_mask >> (MAP_T_BITS - idx));
    }
    return false;
}

/* Set the 'n_bits' consecutive bits in 'fm', starting at bit 'idx'.
 * 'n_bits' can be at most MAP_T_BITS. */
static inline void
flowmap_set(struct flowmap *fm, size_t idx, unsigned int n_bits)
{
    map_t n_bits_mask = (MAP_1 << n_bits) - 1;
    size_t unit = idx / MAP_T_BITS;

    idx %= MAP_T_BITS;

    fm->bits[unit] |= n_bits_mask << idx;
    /* The seemingly unnecessary bounds check on 'unit' is a workaround for a
     * false-positive array out of bounds error by GCC 4.9. */
    if (unit + 1 < FLOWMAP_UNITS && idx + n_bits > MAP_T_BITS) {
        /* 'MAP_T_BITS - idx' bits were set on 'unit', set the remaining
         * bits from the next unit. */
        fm->bits[unit + 1] |= n_bits_mask >> (MAP_T_BITS - idx);
    }
}

/* Clears the 'n_bits' consecutive bits in 'fm', starting at bit 'idx'.
 * 'n_bits' can be at most MAP_T_BITS. */
static inline void
flowmap_clear(struct flowmap *fm, size_t idx, unsigned int n_bits)
{
    map_t n_bits_mask = (MAP_1 << n_bits) - 1;
    size_t unit = idx / MAP_T_BITS;

    idx %= MAP_T_BITS;

    fm->bits[unit] &= ~(n_bits_mask << idx);
    /* The seemingly unnecessary bounds check on 'unit' is a workaround for a
     * false-positive array out of bounds error by GCC 4.9. */
    if (unit + 1 < FLOWMAP_UNITS && idx + n_bits > MAP_T_BITS) {
        /* 'MAP_T_BITS - idx' bits were cleared on 'unit', clear the
         * remaining bits from the next unit. */
        fm->bits[unit + 1] &= ~(n_bits_mask >> (MAP_T_BITS - idx));
    }
}

/* OR the bits in the flowmaps. */
static inline struct flowmap
flowmap_or(struct flowmap a, struct flowmap b)
{
    struct flowmap map;
    size_t unit;

    FLOWMAP_FOR_EACH_UNIT (unit) {
        map.bits[unit] = a.bits[unit] | b.bits[unit];
    }
    return map;
}

/* AND the bits in the flowmaps. */
static inline struct flowmap
flowmap_and(struct flowmap a, struct flowmap b)
{
    struct flowmap map;
    size_t unit;

    FLOWMAP_FOR_EACH_UNIT (unit) {
        map.bits[unit] = a.bits[unit] & b.bits[unit];
    }
    return map;
}

static inline bool
flowmap_is_empty(struct flowmap fm)
{
    map_t map;

    FLOWMAP_FOR_EACH_MAP (map, fm) {
        if (map) {
            return false;
        }
    }
    return true;
}

static inline unsigned int
flowmap_n_1bits(struct flowmap fm)
{
    unsigned int n_1bits = 0;
    size_t unit;

    FLOWMAP_FOR_EACH_UNIT (unit) {
        n_1bits += count_1bits(fm.bits[unit]);
    }
    return n_1bits;
}

struct flowmap_aux {
    size_t unit;
    struct flowmap map;
};

static inline bool
flowmap_next_index(struct flowmap_aux *aux, size_t *idx)
{
    for (;;) {
        map_t *map = &aux->map.bits[aux->unit];
        if (*map) {
            *idx = aux->unit * MAP_T_BITS + raw_ctz(*map);
            *map = zero_rightmost_1bit(*map);
            return true;
        }
        if (++aux->unit >= FLOWMAP_UNITS) {
            return false;
        }
    }
}


/* Compressed flow. */

/* A sparse representation of a "struct flow".
 *
 * A "struct flow" is fairly large and tends to be mostly zeros.  Sparse
 * representation has two advantages.  First, it saves memory and, more
 * importantly, minimizes the number of accessed cache lines.  Second, it saves
 * time when the goal is to iterate over only the nonzero parts of the struct.
 *
 * The map member hold one bit for each uint64_t in a "struct flow".  Each
 * 0-bit indicates that the corresponding uint64_t is zero, each 1-bit that it
 * *may* be nonzero (see below how this applies to minimasks).
 *
 * The values indicated by 'map' always follow the miniflow in memory.  The
 * user of the miniflow is responsible for always having enough storage after
 * the struct miniflow corresponding to the number of 1-bits in maps.
 *
 * Elements in values array are allowed to be zero.  This is useful for "struct
 * minimatch", for which ensuring that the miniflow and minimask members have
 * same maps allows optimization.  This allowance applies only to a miniflow
 * that is not a mask.  That is, a minimask may NOT have zero elements in its
 * values.
 *
 * A miniflow is always dynamically allocated so that the maps are followed by
 * at least as many elements as there are 1-bits in maps. */
struct miniflow {
    struct flowmap map;
    /* Followed by:
     *     uint64_t values[n];
     * where 'n' is miniflow_n_values(miniflow). */
};
BUILD_ASSERT_DECL(sizeof(struct miniflow) % sizeof(uint64_t) == 0);

#define MINIFLOW_VALUES_SIZE(COUNT) ((COUNT) * sizeof(uint64_t))

static inline uint64_t *miniflow_values(struct miniflow *mf)
{
    return (uint64_t *)(mf + 1);
}

static inline const uint64_t *miniflow_get_values(const struct miniflow *mf)
{
    return (const uint64_t *)(mf + 1);
}

struct pkt_metadata;

/* The 'dst' must follow with buffer space for FLOW_U64S 64-bit units.
 * 'dst->map' is ignored on input and set on output to indicate which fields
 * were extracted. */
void miniflow_extract(struct dp_packet *packet, struct miniflow *dst);
void miniflow_map_init(struct miniflow *, const struct flow *);
void flow_wc_map(const struct flow *, struct flowmap *);
size_t miniflow_alloc(struct miniflow *dsts[], size_t n,
                      const struct miniflow *src);
void miniflow_init(struct miniflow *, const struct flow *);
void miniflow_clone(struct miniflow *, const struct miniflow *,
                    size_t n_values);
struct miniflow * miniflow_create(const struct flow *);

void miniflow_expand(const struct miniflow *, struct flow *);

static inline uint64_t flow_u64_value(const struct flow *flow, size_t index)
{
    return ((uint64_t *)flow)[index];
}

static inline uint64_t *flow_u64_lvalue(struct flow *flow, size_t index)
{
    return &((uint64_t *)flow)[index];
}

static inline size_t
miniflow_n_values(const struct miniflow *flow)
{
    return flowmap_n_1bits(flow->map);
}

struct flow_for_each_in_maps_aux {
    const struct flow *flow;
    struct flowmap_aux map_aux;
};

static inline bool
flow_values_get_next_in_maps(struct flow_for_each_in_maps_aux *aux,
                             uint64_t *value)
{
    size_t idx;

    if (flowmap_next_index(&aux->map_aux, &idx)) {
        *value = flow_u64_value(aux->flow, idx);
        return true;
    }
    return false;
}

/* Iterate through all flow u64 values specified by 'MAPS'. */
#define FLOW_FOR_EACH_IN_MAPS(VALUE, FLOW, MAPS)            \
    for (struct flow_for_each_in_maps_aux aux__             \
             = { (FLOW), FLOWMAP_AUX_INITIALIZER(MAPS) };   \
         flow_values_get_next_in_maps(&aux__, &(VALUE));)

struct mf_for_each_in_map_aux {
    size_t unit;             /* Current 64-bit unit of the flowmaps
                                being processed. */
    struct flowmap fmap;     /* Remaining 1-bits corresponding to the
                                64-bit words in 'values' */
    struct flowmap map;      /* Remaining 1-bits corresponding to the
                                64-bit words of interest. */
    const uint64_t *values;  /* 64-bit words corresponding to the
                                1-bits in 'fmap'. */
};

/* Get the data from 'aux->values' corresponding to the next lowest 1-bit
 * in 'aux->map', given that 'aux->values' points to an array of 64-bit
 * words corresponding to the 1-bits in 'aux->fmap', starting from the
 * rightmost 1-bit.
 *
 * Returns 'true' if the traversal is incomplete, 'false' otherwise.
 * 'aux' is prepared for the next iteration after each call.
 *
 * This is used to traverse through, for example, the values in a miniflow
 * representation of a flow key selected by non-zero 64-bit words in a
 * corresponding subtable mask. */
static inline bool
mf_get_next_in_map(struct mf_for_each_in_map_aux *aux,
                   uint64_t *value)
{
    map_t *map, *fmap;
    map_t rm1bit;

    /* Skip empty map units. */
    while (OVS_UNLIKELY(!*(map = &aux->map.bits[aux->unit]))) {
        /* Skip remaining data in the current unit before advancing
         * to the next. */
        aux->values += count_1bits(aux->fmap.bits[aux->unit]);
        if (++aux->unit == FLOWMAP_UNITS) {
            return false;
        }
    }

    rm1bit = rightmost_1bit(*map);
    *map -= rm1bit;
    fmap = &aux->fmap.bits[aux->unit];

    /* If the rightmost 1-bit found from the current unit in 'aux->map'
     * ('rm1bit') is also present in 'aux->fmap', store the corresponding
     * value from 'aux->values' to '*value', otherwise store 0. */
    if (OVS_LIKELY(*fmap & rm1bit)) {
        /* Skip all 64-bit words in 'values' preceding the one corresponding
         * to 'rm1bit'. */
        map_t trash = *fmap & (rm1bit - 1);

        /* Avoid resetting 'fmap' and calling count_1bits() when trash is
         * zero. */
        if (trash) {
            *fmap -= trash;
            aux->values += count_1bits(trash);
        }

        *value = *aux->values;
    } else {
        *value = 0;
    }
    return true;
}

/* Iterate through miniflow u64 values specified by 'FLOWMAP'. */
#define MINIFLOW_FOR_EACH_IN_FLOWMAP(VALUE, FLOW, FLOWMAP)          \
    for (struct mf_for_each_in_map_aux aux__ =                      \
        { 0, (FLOW)->map, (FLOWMAP), miniflow_get_values(FLOW) };   \
         mf_get_next_in_map(&aux__, &(VALUE));)

/* This can be used when it is known that 'idx' is set in 'map'. */
static inline const uint64_t *
miniflow_values_get__(const uint64_t *values, map_t map, size_t idx)
{
    return values + count_1bits(map & ((MAP_1 << idx) - 1));
}

/* This can be used when it is known that 'u64_idx' is set in
 * the map of 'mf'. */
static inline const uint64_t *
miniflow_get__(const struct miniflow *mf, size_t idx)
{
    const uint64_t *values = miniflow_get_values(mf);
    const map_t *map = mf->map.bits;

    while (idx >= MAP_T_BITS) {
        idx -= MAP_T_BITS;
        values += count_1bits(*map++);
    }
    return miniflow_values_get__(values, *map, idx);
}

#define MINIFLOW_IN_MAP(MF, IDX) flowmap_is_set(&(MF)->map, IDX)

/* Get the value of the struct flow 'FIELD' as up to 8 byte wide integer type
 * 'TYPE' from miniflow 'MF'. */
#define MINIFLOW_GET_TYPE(MF, TYPE, FIELD)                              \
    (BUILD_ASSERT(sizeof(TYPE) == sizeof(((struct flow *)0)->FIELD)),   \
     BUILD_ASSERT_GCCONLY(__builtin_types_compatible_p(TYPE, typeof(((struct flow *)0)->FIELD))), \
     MINIFLOW_GET_TYPE__(MF, TYPE, FIELD))

/* Like MINIFLOW_GET_TYPE, but without checking that TYPE is the correct width
 * for FIELD.  (This is useful for deliberately reading adjacent fields in one
 * go.)  */
#define MINIFLOW_GET_TYPE__(MF, TYPE, FIELD)                            \
    (MINIFLOW_IN_MAP(MF, FLOW_U64_OFFSET(FIELD))                        \
     ? ((OVS_FORCE const TYPE *)miniflow_get__(MF, FLOW_U64_OFFSET(FIELD))) \
     [FLOW_U64_OFFREM(FIELD) / sizeof(TYPE)]                            \
     : 0)

#define MINIFLOW_GET_U128(FLOW, FIELD)                                  \
    (ovs_u128) { .u64 = {                                               \
            (MINIFLOW_IN_MAP(FLOW, FLOW_U64_OFFSET(FIELD)) ?            \
             *miniflow_get__(FLOW, FLOW_U64_OFFSET(FIELD)) : 0),        \
            (MINIFLOW_IN_MAP(FLOW, FLOW_U64_OFFSET(FIELD) + 1) ?        \
             *miniflow_get__(FLOW, FLOW_U64_OFFSET(FIELD) + 1) : 0) } }

#define MINIFLOW_GET_U8(FLOW, FIELD)            \
    MINIFLOW_GET_TYPE(FLOW, uint8_t, FIELD)
#define MINIFLOW_GET_U16(FLOW, FIELD)           \
    MINIFLOW_GET_TYPE(FLOW, uint16_t, FIELD)
#define MINIFLOW_GET_BE16(FLOW, FIELD)          \
    MINIFLOW_GET_TYPE(FLOW, ovs_be16, FIELD)
#define MINIFLOW_GET_U32(FLOW, FIELD)           \
    MINIFLOW_GET_TYPE(FLOW, uint32_t, FIELD)
#define MINIFLOW_GET_BE32(FLOW, FIELD)          \
    MINIFLOW_GET_TYPE(FLOW, ovs_be32, FIELD)
#define MINIFLOW_GET_U64(FLOW, FIELD)           \
    MINIFLOW_GET_TYPE(FLOW, uint64_t, FIELD)
#define MINIFLOW_GET_BE64(FLOW, FIELD)          \
    MINIFLOW_GET_TYPE(FLOW, ovs_be64, FIELD)

static inline uint64_t miniflow_get(const struct miniflow *,
                                    unsigned int u64_ofs);
static inline uint32_t miniflow_get_u32(const struct miniflow *,
                                        unsigned int u32_ofs);
static inline ovs_be32 miniflow_get_be32(const struct miniflow *,
                                         unsigned int be32_ofs);
static inline uint16_t miniflow_get_vid(const struct miniflow *, size_t);
static inline uint16_t miniflow_get_tcp_flags(const struct miniflow *);
static inline ovs_be64 miniflow_get_metadata(const struct miniflow *);
static inline uint64_t miniflow_get_tun_metadata_present_map(
    const struct miniflow *);
static inline uint32_t miniflow_get_recirc_id(const struct miniflow *);
static inline uint32_t miniflow_get_dp_hash(const struct miniflow *);
static inline ovs_be32 miniflow_get_ports(const struct miniflow *);

bool miniflow_equal(const struct miniflow *a, const struct miniflow *b);
bool miniflow_equal_in_minimask(const struct miniflow *a,
                                const struct miniflow *b,
                                const struct minimask *);
bool miniflow_equal_flow_in_minimask(const struct miniflow *a,
                                     const struct flow *b,
                                     const struct minimask *);
uint32_t miniflow_hash_5tuple(const struct miniflow *flow, uint32_t basis);


/* Compressed flow wildcards. */

/* A sparse representation of a "struct flow_wildcards".
 *
 * See the large comment on struct miniflow for details.
 *
 * Note: While miniflow can have zero data for a 1-bit in the map,
 * a minimask may not!  We rely on this in the implementation. */
struct minimask {
    struct miniflow masks;
};

void minimask_init(struct minimask *, const struct flow_wildcards *);
struct minimask * minimask_create(const struct flow_wildcards *);
void minimask_combine(struct minimask *dst,
                      const struct minimask *a, const struct minimask *b,
                      uint64_t storage[FLOW_U64S]);

void minimask_expand(const struct minimask *, struct flow_wildcards *);

static inline uint32_t minimask_get_u32(const struct minimask *,
                                        unsigned int u32_ofs);
static inline ovs_be32 minimask_get_be32(const struct minimask *,
                                         unsigned int be32_ofs);
static inline uint16_t minimask_get_vid_mask(const struct minimask *, size_t);
static inline ovs_be64 minimask_get_metadata_mask(const struct minimask *);

bool minimask_equal(const struct minimask *a, const struct minimask *b);
bool minimask_has_extra(const struct minimask *, const struct minimask *);


/* Returns true if 'mask' matches every packet, false if 'mask' fixes any bits
 * or fields. */
static inline bool
minimask_is_catchall(const struct minimask *mask)
{
    /* For every 1-bit in mask's map, the corresponding value is non-zero,
     * so the only way the mask can not fix any bits or fields is for the
     * map the be zero. */
    return flowmap_is_empty(mask->masks.map);
}

/* Returns the uint64_t that would be at byte offset '8 * u64_ofs' if 'flow'
 * were expanded into a "struct flow". */
static inline uint64_t miniflow_get(const struct miniflow *flow,
                                    unsigned int u64_ofs)
{
    return MINIFLOW_IN_MAP(flow, u64_ofs) ? *miniflow_get__(flow, u64_ofs) : 0;
}

static inline uint32_t miniflow_get_u32(const struct miniflow *flow,
                                        unsigned int u32_ofs)
{
    uint64_t value = miniflow_get(flow, u32_ofs / 2);

#if WORDS_BIGENDIAN
    return (u32_ofs & 1) ? value : value >> 32;
#else
    return (u32_ofs & 1) ? value >> 32 : value;
#endif
}

static inline ovs_be32 miniflow_get_be32(const struct miniflow *flow,
                                         unsigned int be32_ofs)
{
    return (OVS_FORCE ovs_be32)miniflow_get_u32(flow, be32_ofs);
}

/* Returns the VID within the vlan_tci member of the "struct flow" represented
 * by 'flow'. */
static inline uint16_t
miniflow_get_vid(const struct miniflow *flow, size_t n)
{
    if (n < FLOW_MAX_VLAN_HEADERS) {
        union flow_vlan_hdr hdr = {
            .qtag = MINIFLOW_GET_BE32(flow, vlans[n].qtag)
        };
        return vlan_tci_to_vid(hdr.tci);
    }
    return 0;
}

/* Returns the uint32_t that would be at byte offset '4 * u32_ofs' if 'mask'
 * were expanded into a "struct flow_wildcards". */
static inline uint32_t
minimask_get_u32(const struct minimask *mask, unsigned int u32_ofs)
{
    return miniflow_get_u32(&mask->masks, u32_ofs);
}

static inline ovs_be32
minimask_get_be32(const struct minimask *mask, unsigned int be32_ofs)
{
    return (OVS_FORCE ovs_be32)minimask_get_u32(mask, be32_ofs);
}

/* Returns the VID mask within the vlan_tci member of the "struct
 * flow_wildcards" represented by 'mask'. */
static inline uint16_t
minimask_get_vid_mask(const struct minimask *mask, size_t n)
{
    return miniflow_get_vid(&mask->masks, n);
}

/* Returns the value of the "tcp_flags" field in 'flow'. */
static inline uint16_t
miniflow_get_tcp_flags(const struct miniflow *flow)
{
    return ntohs(MINIFLOW_GET_BE16(flow, tcp_flags));
}

/* Returns the value of the OpenFlow 1.1+ "metadata" field in 'flow'. */
static inline ovs_be64
miniflow_get_metadata(const struct miniflow *flow)
{
    return MINIFLOW_GET_BE64(flow, metadata);
}

/* Returns the bitmap that indicates which tunnel metadata fields are present
 * in 'flow'. */
static inline uint64_t
miniflow_get_tun_metadata_present_map(const struct miniflow *flow)
{
    return MINIFLOW_GET_U64(flow, tunnel.metadata.present.map);
}

/* Returns the recirc_id in 'flow.' */
static inline uint32_t
miniflow_get_recirc_id(const struct miniflow *flow)
{
    return MINIFLOW_GET_U32(flow, recirc_id);
}

/* Returns the dp_hash in 'flow.' */
static inline uint32_t
miniflow_get_dp_hash(const struct miniflow *flow)
{
    return MINIFLOW_GET_U32(flow, dp_hash);
}

/* Returns the 'tp_src' and 'tp_dst' fields together as one piece of data. */
static inline ovs_be32
miniflow_get_ports(const struct miniflow *flow)
{
    return MINIFLOW_GET_TYPE__(flow, ovs_be32, tp_src);
}

/* Returns the mask for the OpenFlow 1.1+ "metadata" field in 'mask'.
 *
 * The return value is all-1-bits if 'mask' matches on the whole value of the
 * metadata field, all-0-bits if 'mask' entirely wildcards the metadata field,
 * or some other value if the metadata field is partially matched, partially
 * wildcarded. */
static inline ovs_be64
minimask_get_metadata_mask(const struct minimask *mask)
{
    return MINIFLOW_GET_BE64(&mask->masks, metadata);
}

/* Perform a bitwise OR of miniflow 'src' flow data specified in 'subset' with
 * the equivalent fields in 'dst', storing the result in 'dst'.  'subset' must
 * be a subset of 'src's map. */
static inline void
flow_union_with_miniflow_subset(struct flow *dst, const struct miniflow *src,
                                struct flowmap subset)
{
    uint64_t *dst_u64 = (uint64_t *) dst;
    const uint64_t *p = miniflow_get_values(src);
    map_t map;

    FLOWMAP_FOR_EACH_MAP (map, subset) {
        size_t idx;

        MAP_FOR_EACH_INDEX(idx, map) {
            dst_u64[idx] |= *p++;
        }
        dst_u64 += MAP_T_BITS;
    }
}

/* Perform a bitwise OR of miniflow 'src' flow data with the equivalent
 * fields in 'dst', storing the result in 'dst'. */
static inline void
flow_union_with_miniflow(struct flow *dst, const struct miniflow *src)
{
    flow_union_with_miniflow_subset(dst, src, src->map);
}

static inline bool is_ct_valid(const struct flow *flow,
                               const struct flow_wildcards *mask,
                               struct flow_wildcards *wc)
{
    /* Matches are checked with 'mask' and without 'wc'. */
    if (mask && !wc) {
        /* Must match at least one of the bits that implies a valid
         * conntrack entry, or an explicit not-invalid. */
        return flow->ct_state & (CS_NEW | CS_ESTABLISHED | CS_RELATED
                                 | CS_REPLY_DIR | CS_SRC_NAT | CS_DST_NAT)
            || (flow->ct_state & CS_TRACKED
                && mask->masks.ct_state & CS_INVALID
                && !(flow->ct_state & CS_INVALID));
    }
    /* Else we are checking a fully extracted flow, where valid CT state always
     * has either 'new', 'established', or 'reply_dir' bit set. */
#define CS_VALID_MASK (CS_NEW | CS_ESTABLISHED | CS_REPLY_DIR)
    if (wc) {
        wc->masks.ct_state |= CS_VALID_MASK;
    }
    return flow->ct_state & CS_VALID_MASK;
}

static inline void
pkt_metadata_from_flow(struct pkt_metadata *md, const struct flow *flow)
{
    /* Update this function whenever struct flow changes. */
    BUILD_ASSERT_DECL(FLOW_WC_SEQ == 42);

    md->recirc_id = flow->recirc_id;
    md->dp_hash = flow->dp_hash;
    flow_tnl_copy__(&md->tunnel, &flow->tunnel);
    md->skb_priority = flow->skb_priority;
    md->pkt_mark = flow->pkt_mark;
    md->in_port = flow->in_port;
    md->ct_state = flow->ct_state;
    md->ct_zone = flow->ct_zone;
    md->ct_mark = flow->ct_mark;
    md->ct_label = flow->ct_label;

    md->ct_orig_tuple_ipv6 = false;
    if (flow->dl_type && is_ct_valid(flow, NULL, NULL)) {
        if (flow->dl_type == htons(ETH_TYPE_IP)) {
            md->ct_orig_tuple.ipv4 = (struct ovs_key_ct_tuple_ipv4) {
                flow->ct_nw_src,
                flow->ct_nw_dst,
                flow->ct_tp_src,
                flow->ct_tp_dst,
                flow->ct_nw_proto,
            };
        } else if (flow->dl_type == htons(ETH_TYPE_IPV6)) {
            md->ct_orig_tuple_ipv6 = true;
            md->ct_orig_tuple.ipv6 = (struct ovs_key_ct_tuple_ipv6) {
                flow->ct_ipv6_src,
                flow->ct_ipv6_dst,
                flow->ct_tp_src,
                flow->ct_tp_dst,
                flow->ct_nw_proto,
            };
        } else {
            /* Reset ct_orig_tuple for other types. */
            memset(&md->ct_orig_tuple, 0, sizeof md->ct_orig_tuple);
        }
    } else {
        memset(&md->ct_orig_tuple, 0, sizeof md->ct_orig_tuple);
    }
}

/* Often, during translation we need to read a value from a flow('FLOW') and
 * unwildcard the corresponding bits in the wildcards('WC').  This macro makes
 * it easier to do that. */

#define FLOW_WC_GET_AND_MASK_WC(FLOW, WC, FIELD) \
    (((WC) ? WC_MASK_FIELD(WC, FIELD) : NULL), ((FLOW)->FIELD))

static inline bool is_ethernet(const struct flow *flow,
                               struct flow_wildcards *wc)
{
    if (wc) {
        WC_MASK_FIELD(wc, packet_type);
    }
    return flow->packet_type == htonl(PT_ETH);
}

static inline ovs_be16 get_dl_type(const struct flow *flow)
{
    if (flow->packet_type == htonl(PT_ETH)) {
        return flow->dl_type;
    } else if (pt_ns(flow->packet_type) == OFPHTN_ETHERTYPE) {
        return pt_ns_type_be(flow->packet_type);
    } else {
        return htons(FLOW_DL_TYPE_NONE);
    }
}

static inline bool is_vlan(const struct flow *flow,
                           struct flow_wildcards *wc)
{
    if (!is_ethernet(flow, wc)) {
        return false;
    }
    if (wc) {
        WC_MASK_FIELD_MASK(wc, vlans[0].tci, htons(VLAN_CFI));
    }
    return (flow->vlans[0].tci & htons(VLAN_CFI)) != 0;
}

static inline bool is_ip_any(const struct flow *flow)
{
    return dl_type_is_ip_any(get_dl_type(flow));
}

static inline bool is_ip_proto(const struct flow *flow, uint8_t ip_proto,
                               struct flow_wildcards *wc)
{
    if (is_ip_any(flow)) {
        if (wc) {
            WC_MASK_FIELD(wc, nw_proto);
        }
        return flow->nw_proto == ip_proto;
    }
    return false;
}

static inline bool is_tcp(const struct flow *flow,
                          struct flow_wildcards *wc)
{
    return is_ip_proto(flow, IPPROTO_TCP, wc);
}

static inline bool is_udp(const struct flow *flow,
                          struct flow_wildcards *wc)
{
    return is_ip_proto(flow, IPPROTO_UDP, wc);
}

static inline bool is_sctp(const struct flow *flow,
                           struct flow_wildcards *wc)
{
    return is_ip_proto(flow, IPPROTO_SCTP, wc);
}

static inline bool is_icmpv4(const struct flow *flow,
                             struct flow_wildcards *wc)
{
    if (get_dl_type(flow) == htons(ETH_TYPE_IP)) {
        if (wc) {
            memset(&wc->masks.nw_proto, 0xff, sizeof wc->masks.nw_proto);
        }
        return flow->nw_proto == IPPROTO_ICMP;
    }
    return false;
}

static inline bool is_icmpv6(const struct flow *flow,
                             struct flow_wildcards *wc)
{
    if (get_dl_type(flow) == htons(ETH_TYPE_IPV6)) {
        if (wc) {
            memset(&wc->masks.nw_proto, 0xff, sizeof wc->masks.nw_proto);
        }
        return flow->nw_proto == IPPROTO_ICMPV6;
    }
    return false;
}

static inline bool is_nd(const struct flow *flow,
                         struct flow_wildcards *wc)
{
    if (is_icmpv6(flow, wc)) {
        if (wc) {
            memset(&wc->masks.tp_dst, 0xff, sizeof wc->masks.tp_dst);
        }
        if (flow->tp_dst != htons(0)) {
            return false;
        }

        if (wc) {
            memset(&wc->masks.tp_src, 0xff, sizeof wc->masks.tp_src);
        }
        return (flow->tp_src == htons(ND_NEIGHBOR_SOLICIT) ||
                flow->tp_src == htons(ND_NEIGHBOR_ADVERT));
    }
    return false;
}

static inline bool is_arp(const struct flow *flow)
{
    return (flow->dl_type == htons(ETH_TYPE_ARP));
}

static inline bool is_garp(const struct flow *flow,
                           struct flow_wildcards *wc)
{
    if (is_arp(flow)) {
        return (FLOW_WC_GET_AND_MASK_WC(flow, wc, nw_src) ==
                FLOW_WC_GET_AND_MASK_WC(flow, wc, nw_dst));
    }

    return false;
}

static inline bool is_igmp(const struct flow *flow, struct flow_wildcards *wc)
{
    if (get_dl_type(flow) == htons(ETH_TYPE_IP)) {
        if (wc) {
            memset(&wc->masks.nw_proto, 0xff, sizeof wc->masks.nw_proto);
        }
        return flow->nw_proto == IPPROTO_IGMP;
    }
    return false;
}

static inline bool is_mld(const struct flow *flow,
                          struct flow_wildcards *wc)
{
    if (is_icmpv6(flow, wc)) {
        if (wc) {
            memset(&wc->masks.tp_src, 0xff, sizeof wc->masks.tp_src);
        }
        return (flow->tp_src == htons(MLD_QUERY)
                || flow->tp_src == htons(MLD_REPORT)
                || flow->tp_src == htons(MLD_DONE)
                || flow->tp_src == htons(MLD2_REPORT));
    }
    return false;
}

static inline bool is_mld_query(const struct flow *flow,
                                struct flow_wildcards *wc)
{
    if (is_icmpv6(flow, wc)) {
        if (wc) {
            memset(&wc->masks.tp_src, 0xff, sizeof wc->masks.tp_src);
        }
        return flow->tp_src == htons(MLD_QUERY);
    }
    return false;
}

static inline bool is_mld_report(const struct flow *flow,
                                 struct flow_wildcards *wc)
{
    return is_mld(flow, wc) && !is_mld_query(flow, wc);
}

static inline bool is_stp(const struct flow *flow)
{
    return (flow->dl_type == htons(FLOW_DL_TYPE_NONE)
            && eth_addr_equals(flow->dl_dst, eth_addr_stp));
}

/* Returns true if flow->tp_dst equals 'port'.  If 'wc' is nonnull, sets
 * appropriate bits in wc->masks.tp_dst to account for the test.
 *
 * The caller must already have ensured that 'flow' is a protocol for which
 * tp_dst is relevant. */
static inline bool tp_dst_equals(const struct flow *flow, uint16_t port,
                                 struct flow_wildcards *wc)
{
    uint16_t diff = port ^ ntohs(flow->tp_dst);
    if (wc) {
        if (diff) {
            /* Set mask for the most significant mismatching bit. */
            int ofs = raw_clz64((uint64_t) diff << 48); /* range [0,15] */
            wc->masks.tp_dst |= htons(0x8000 >> ofs);
        } else {
            /* Must match all bits. */
            wc->masks.tp_dst = OVS_BE16_MAX;
        }
    }
    return !diff;
}

#endif /* flow.h */
