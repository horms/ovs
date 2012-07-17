/*
 * Copyright (c) 2008, 2009, 2010, 2011, 2012 Nicira Networks.
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
#include "ofp-actions.h"
#include "autopath.h"
#include "bundle.h"
#include "byte-order.h"
#include "compiler.h"
#include "dynamic-string.h"
#include "learn.h"
#include "meta-flow.h"
#include "multipath.h"
#include "nx-match.h"
#include "ofp-util.h"
#include "ofpbuf.h"
#include "set-field.h"
#include "vlog.h"

VLOG_DEFINE_THIS_MODULE(ofp_actions);

static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);


/* Converting OpenFlow 1.0 to ofpacts. */

static enum ofperr
output_from_openflow10(const struct ofp10_action_output *oao,
                       struct ofpbuf *out)
{
    struct ofpact_output *output;

    output = ofpact_put_OUTPUT(out);
    output->port = ntohs(oao->port);
    output->max_len = ntohs(oao->max_len);

    return ofputil_check_output_port(output->port, OFPP_MAX);
}

static enum ofperr
enqueue_from_openflow10(const struct ofp_action_enqueue *oae,
                        struct ofpbuf *out)
{
    struct ofpact_enqueue *enqueue;

    enqueue = ofpact_put_ENQUEUE(out);
    enqueue->port = ntohs(oae->port);
    enqueue->queue = ntohl(oae->queue_id);
    if (enqueue->port >= OFPP_MAX && enqueue->port != OFPP_IN_PORT
        && enqueue->port != OFPP_LOCAL) {
        return OFPERR_OFPBAC_BAD_OUT_PORT;
    }
    return 0;
}

static void
resubmit_from_openflow(const struct nx_action_resubmit *nar,
                       struct ofpbuf *out)
{
    struct ofpact_resubmit *resubmit;

    resubmit = ofpact_put_RESUBMIT(out);
    resubmit->ofpact.compat = OFPUTIL_NXAST_RESUBMIT;
    resubmit->in_port = ntohs(nar->in_port);
    resubmit->table_id = 0xff;
}

static enum ofperr
resubmit_table_from_openflow(const struct nx_action_resubmit *nar,
                             struct ofpbuf *out)
{
    struct ofpact_resubmit *resubmit;

    if (nar->pad[0] || nar->pad[1] || nar->pad[2]) {
        return OFPERR_OFPBAC_BAD_ARGUMENT;
    }

    resubmit = ofpact_put_RESUBMIT(out);
    resubmit->ofpact.compat = OFPUTIL_NXAST_RESUBMIT_TABLE;
    resubmit->in_port = ntohs(nar->in_port);
    resubmit->table_id = nar->table;
    return 0;
}

static enum ofperr
output_reg_from_openflow(const struct nx_action_output_reg *naor,
                         struct ofpbuf *out)
{
    struct ofpact_output_reg *output_reg;

    if (!is_all_zeros(naor->zero, sizeof naor->zero)) {
        return OFPERR_OFPBAC_BAD_ARGUMENT;
    }

    output_reg = ofpact_put_OUTPUT_REG(out);
    output_reg->src.field = mf_from_nxm_header(ntohl(naor->src));
    output_reg->src.ofs = nxm_decode_ofs(naor->ofs_nbits);
    output_reg->src.n_bits = nxm_decode_n_bits(naor->ofs_nbits);
    output_reg->max_len = ntohs(naor->max_len);

    return mf_check_src(&output_reg->src, NULL);
}

static void
fin_timeout_from_openflow(const struct nx_action_fin_timeout *naft,
                          struct ofpbuf *out)
{
    struct ofpact_fin_timeout *oft;

    oft = ofpact_put_FIN_TIMEOUT(out);
    oft->fin_idle_timeout = ntohs(naft->fin_idle_timeout);
    oft->fin_hard_timeout = ntohs(naft->fin_hard_timeout);
}

static void
controller_from_openflow(const struct nx_action_controller *nac,
                         struct ofpbuf *out)
{
    struct ofpact_controller *oc;

    oc = ofpact_put_CONTROLLER(out);
    oc->max_len = ntohs(nac->max_len);
    oc->controller_id = ntohs(nac->controller_id);
    oc->reason = nac->reason;
}

static void
note_from_openflow(const struct nx_action_note *nan, struct ofpbuf *out)
{
    struct ofpact_note *note;
    unsigned int length;

    length = ntohs(nan->len) - offsetof(struct nx_action_note, note);
    note = ofpact_put(out, OFPACT_NOTE,
                      offsetof(struct ofpact_note, data) + length);
    note->length = length;
    memcpy(note->data, nan->note, length);
}

static enum ofperr
decode_nxast_action(const union ofp_action *a, enum ofputil_action_code *code)
{
    const struct nx_action_header *nah = (const struct nx_action_header *) a;
    uint16_t len = ntohs(a->header.len);

    if (len < sizeof(struct nx_action_header)) {
        return OFPERR_OFPBAC_BAD_LEN;
    } else if (a->vendor.vendor != CONSTANT_HTONL(NX_VENDOR_ID)) {
        return OFPERR_OFPBAC_BAD_VENDOR;
    }

    switch (nah->subtype) {
#define NXAST_ACTION(ENUM, STRUCT, EXTENSIBLE, NAME)    \
        case CONSTANT_HTONS(ENUM):                      \
            if (EXTENSIBLE                              \
                ? len >= sizeof(struct STRUCT)          \
                : len == sizeof(struct STRUCT)) {       \
                *code = OFPUTIL_##ENUM;                 \
                return 0;                               \
            } else {                                    \
                return OFPERR_OFPBAC_BAD_LEN;           \
            }                                           \
            NOT_REACHED();
#include "ofp-util.def"

    case CONSTANT_HTONS(NXAST_SNAT__OBSOLETE):
    case CONSTANT_HTONS(NXAST_DROP_SPOOFED_ARP__OBSOLETE):
    default:
        return OFPERR_OFPBAC_BAD_TYPE;
    }
}

/* Parses 'a' to determine its type.  On success stores the correct type into
 * '*code' and returns 0.  On failure returns an OFPERR_* error code and
 * '*code' is indeterminate.
 *
 * The caller must have already verified that 'a''s length is potentially
 * correct (that is, a->header.len is nonzero and a multiple of sizeof(union
 * ofp_action) and no longer than the amount of space allocated to 'a').
 *
 * This function verifies that 'a''s length is correct for the type of action
 * that it represents. */
static enum ofperr
decode_openflow10_action(const union ofp_action *a,
                         enum ofputil_action_code *code)
{
    switch (a->type) {
    case CONSTANT_HTONS(OFPAT10_VENDOR):
        return decode_nxast_action(a, code);

#define OFPAT10_ACTION(ENUM, STRUCT, NAME)                          \
        case CONSTANT_HTONS(ENUM):                                  \
            if (a->header.len == htons(sizeof(struct STRUCT))) {    \
                *code = OFPUTIL_##ENUM;                             \
                return 0;                                           \
            } else {                                                \
                return OFPERR_OFPBAC_BAD_LEN;                       \
            }                                                       \
            break;
#include "ofp-util.def"

    default:
        return OFPERR_OFPBAC_BAD_TYPE;
    }
}

static enum ofperr
ofpact_from_nxast(const union ofp_action *a, enum ofputil_action_code code,
                  struct ofpbuf *out)
{
    const struct nx_action_resubmit *nar;
    const struct nx_action_set_tunnel *nast;
    const struct nx_action_set_queue *nasq;
    const struct nx_action_note *nan;
    const struct nx_action_set_tunnel64 *nast64;
    const struct nx_action_push_vlan *napv;
    struct ofpact_tunnel *tunnel;
    enum ofperr error = 0;

    switch (code) {
    case OFPUTIL_ACTION_INVALID:
#define OFPAT10_ACTION(ENUM, STRUCT, NAME) case OFPUTIL_##ENUM:
#define OFPAT11_ACTION(ENUM, STRUCT, NAME) case OFPUTIL_##ENUM:
#define OFPIT11_ACTION(ENUM, STRUCT, NAME) case OFPUTIL_##ENUM:
#define OFPAT12_ACTION(ENUM, STRUCT, NAME) case OFPUTIL_##ENUM:
#include "ofp-util.def"
        NOT_REACHED();

    case OFPUTIL_NXAST_RESUBMIT:
        resubmit_from_openflow((const struct nx_action_resubmit *) a, out);
        break;

    case OFPUTIL_NXAST_SET_TUNNEL:
        nast = (const struct nx_action_set_tunnel *) a;
        tunnel = ofpact_put_SET_TUNNEL(out);
        tunnel->ofpact.compat = code;
        tunnel->tun_id = ntohl(nast->tun_id);
        break;

    case OFPUTIL_NXAST_SET_QUEUE:
        nasq = (const struct nx_action_set_queue *) a;
        ofpact_put_SET_QUEUE(out)->queue_id = ntohl(nasq->queue_id);
        break;

    case OFPUTIL_NXAST_POP_QUEUE:
        ofpact_put_POP_QUEUE(out);
        break;

    case OFPUTIL_NXAST_REG_MOVE:
        error = nxm_reg_move_from_openflow(
            (const struct nx_action_reg_move *) a, out);
        break;

    case OFPUTIL_NXAST_REG_LOAD:
        error = nxm_reg_load_from_openflow(
            (const struct nx_action_reg_load *) a, out);
        break;

    case OFPUTIL_NXAST_NOTE:
        nan = (const struct nx_action_note *) a;
        note_from_openflow(nan, out);
        break;

    case OFPUTIL_NXAST_SET_TUNNEL64:
        nast64 = (const struct nx_action_set_tunnel64 *) a;
        tunnel = ofpact_put_SET_TUNNEL(out);
        tunnel->ofpact.compat = code;
        tunnel->tun_id = ntohll(nast64->tun_id);
        break;

    case OFPUTIL_NXAST_MULTIPATH:
        error = multipath_from_openflow((const struct nx_action_multipath *) a,
                                        ofpact_put_MULTIPATH(out));
        break;

    case OFPUTIL_NXAST_AUTOPATH:
        error = autopath_from_openflow((const struct nx_action_autopath *) a,
                                       ofpact_put_AUTOPATH(out));
        break;

    case OFPUTIL_NXAST_BUNDLE:
    case OFPUTIL_NXAST_BUNDLE_LOAD:
        error = bundle_from_openflow((const struct nx_action_bundle *) a, out);
        break;

    case OFPUTIL_NXAST_OUTPUT_REG:
        error = output_reg_from_openflow(
            (const struct nx_action_output_reg *) a, out);
        break;

    case OFPUTIL_NXAST_RESUBMIT_TABLE:
        nar = (const struct nx_action_resubmit *) a;
        error = resubmit_table_from_openflow(nar, out);
        break;

    case OFPUTIL_NXAST_LEARN:
        error = learn_from_openflow((const struct nx_action_learn *) a, out);
        break;

    case OFPUTIL_NXAST_EXIT:
        ofpact_put_EXIT(out);
        break;

    case OFPUTIL_NXAST_DEC_TTL:
        ofpact_put_DEC_TTL(out);
        break;

    case OFPUTIL_NXAST_FIN_TIMEOUT:
        fin_timeout_from_openflow(
            (const struct nx_action_fin_timeout *) a, out);
        break;

    case OFPUTIL_NXAST_CONTROLLER:
        controller_from_openflow((const struct nx_action_controller *) a, out);
        break;

    case OFPUTIL_NXAST_PUSH_VLAN:
        napv = (const struct nx_action_push_vlan *) a;
        ofpact_put_PUSH_VLAN(out)->tpid = napv->tpid;
        break;
    }

    return error;
}

static enum ofperr
ofpact_from_openflow10(const union ofp_action *a, struct ofpbuf *out)
{
    enum ofputil_action_code code;
    enum ofperr error;

    error = decode_openflow10_action(a, &code);
    if (error) {
        return error;
    }

    switch (code) {
    case OFPUTIL_ACTION_INVALID:
#define OFPAT11_ACTION(ENUM, STRUCT, NAME) case OFPUTIL_##ENUM:
#define OFPIT11_ACTION(ENUM, STRUCT, NAME) case OFPUTIL_##ENUM:
#define OFPAT12_ACTION(ENUM, STRUCT, NAME) case OFPUTIL_##ENUM:
#include "ofp-util.def"
        NOT_REACHED();

    case OFPUTIL_OFPAT10_OUTPUT:
        return output_from_openflow10(&a->output10, out);

    case OFPUTIL_OFPAT10_SET_VLAN_VID:
        if (a->vlan_vid.vlan_vid & ~htons(0xfff)) {
            return OFPERR_OFPBAC_BAD_ARGUMENT;
        }
        ofpact_put_SET_VLAN_VID(out)->vlan_vid = ntohs(a->vlan_vid.vlan_vid);
        break;

    case OFPUTIL_OFPAT10_SET_VLAN_PCP:
        if (a->vlan_pcp.vlan_pcp & ~7) {
            return OFPERR_OFPBAC_BAD_ARGUMENT;
        }
        ofpact_put_SET_VLAN_PCP(out)->vlan_pcp = a->vlan_pcp.vlan_pcp;
        break;

    case OFPUTIL_OFPAT10_STRIP_VLAN:
        ofpact_put_STRIP_VLAN(out);
        break;

    case OFPUTIL_OFPAT10_SET_DL_SRC:
        memcpy(ofpact_put_SET_ETH_SRC(out)->mac,
               ((const struct ofp_action_dl_addr *) a)->dl_addr, ETH_ADDR_LEN);
        break;

    case OFPUTIL_OFPAT10_SET_DL_DST:
        memcpy(ofpact_put_SET_ETH_DST(out)->mac,
               ((const struct ofp_action_dl_addr *) a)->dl_addr, ETH_ADDR_LEN);
        break;

    case OFPUTIL_OFPAT10_SET_NW_SRC:
        ofpact_put_SET_IPV4_SRC(out)->ipv4 = a->nw_addr.nw_addr;
        break;

    case OFPUTIL_OFPAT10_SET_NW_DST:
        ofpact_put_SET_IPV4_DST(out)->ipv4 = a->nw_addr.nw_addr;
        break;

    case OFPUTIL_OFPAT10_SET_NW_TOS:
        if (a->nw_tos.nw_tos & ~IP_DSCP_MASK) {
            return OFPERR_OFPBAC_BAD_ARGUMENT;
        }
        ofpact_put_SET_IPV4_DSCP(out)->dscp = a->nw_tos.nw_tos;
        break;

    case OFPUTIL_OFPAT10_SET_TP_SRC:
        ofpact_put_SET_L4_SRC_PORT(out)->port = ntohs(a->tp_port.tp_port);
        break;

    case OFPUTIL_OFPAT10_SET_TP_DST:
        ofpact_put_SET_L4_DST_PORT(out)->port = ntohs(a->tp_port.tp_port);

        break;

    case OFPUTIL_OFPAT10_ENQUEUE:
        error = enqueue_from_openflow10((const struct ofp_action_enqueue *) a,
                                        out);
        break;

#define NXAST_ACTION(ENUM, STRUCT, EXTENSIBLE, NAME) case OFPUTIL_##ENUM:
#include "ofp-util.def"
	return ofpact_from_nxast(a, code, out);
    }

    return error;
}

static inline union ofp_action *
action_next(const union ofp_action *a)
{
    return ((union ofp_action *) (void *)
            ((uint8_t *) a + ntohs(a->header.len)));
}

static inline bool
action_is_valid(const union ofp_action *a, size_t n_actions)
{
    uint16_t len = ntohs(a->header.len);
    return (!(len % OFP_ACTION_ALIGN)
            && len >= sizeof *a
            && len / sizeof *a <= n_actions);
}

/* This macro is careful to check for actions with bad lengths. */
#define ACTION_FOR_EACH(ITER, LEFT, ACTIONS, N_ACTIONS)                 \
    for ((ITER) = (ACTIONS), (LEFT) = (N_ACTIONS);                      \
         (LEFT) > 0 && action_is_valid(ITER, LEFT);                     \
         ((LEFT) -= ntohs((ITER)->header.len) / sizeof(union ofp_action), \
          (ITER) = action_next(ITER)))

static enum ofperr
ofpacts_from_openflow(const union ofp_action *in, size_t n_in,
                      struct ofpbuf *out,
                      enum ofperr (ofpact_from_openflow)(
                          const union ofp_action *a, struct ofpbuf *out))
{
    const union ofp_action *a;
    size_t left;

    ACTION_FOR_EACH (a, left, in, n_in) {
        enum ofperr error = ofpact_from_openflow(a, out);
        if (error) {
            VLOG_WARN_RL(&rl, "bad action at offset %td (%s)",
                         (a - in) * sizeof *a, ofperr_get_name(error));
            return error;
        }
    }
    if (left) {
        VLOG_WARN_RL(&rl, "bad action format at offset %zu",
                     (n_in - left) * sizeof *a);
        return OFPERR_OFPBAC_BAD_LEN;
    }

    ofpact_put_END(out);

    return 0;
}

static enum ofperr
ofpacts_from_openflow10(const union ofp_action *in, size_t n_in,
                        struct ofpbuf *out)
{
    return ofpacts_from_openflow(in, n_in, out, ofpact_from_openflow10);
}

/* Attempts to convert 'actions_len' bytes of OpenFlow actions from the front
 * of 'openflow' into ofpacts.  On success, replaces any existing content in
 * 'ofpacts' by the converted ofpacts; on failure, clears 'ofpacts'.  Returns 0
 * if successful, otherwise an OpenFlow error.
 *
 * This function does not check that the actions are valid in a given context.
 * The caller should do so, with ofpacts_check(). */
enum ofperr
ofpacts_pull_openflow10(struct ofpbuf *openflow, unsigned int actions_len,
                        struct ofpbuf *ofpacts)
{
    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
    const union ofp_action *actions;
    enum ofperr error;

    ofpbuf_clear(ofpacts);

    if (actions_len % OFP_ACTION_ALIGN != 0) {
        VLOG_WARN_RL(&rl, "OpenFlow message actions length %u is not a "
                     "multiple of %d", actions_len, OFP_ACTION_ALIGN);
        return OFPERR_OFPBRC_BAD_LEN;
    }

    actions = ofpbuf_try_pull(openflow, actions_len);
    if (actions == NULL) {
        VLOG_WARN_RL(&rl, "OpenFlow message actions length %u exceeds "
                     "remaining message length (%zu)",
                     actions_len, openflow->size);
        return OFPERR_OFPBRC_BAD_LEN;
    }

    error = ofpacts_from_openflow10(actions, actions_len / OFP_ACTION_ALIGN,
                                    ofpacts);
    if (error) {
        ofpbuf_clear(ofpacts);
    }
    return 0;
}

/* OpenFlow 1.1 actions. */

/* Parses 'a' to determine its type.  On success stores the correct type into
 * '*code' and returns 0.  On failure returns an OFPERR_* error code and
 * '*code' is indeterminate.
 *
 * The caller must have already verified that 'a''s length is potentially
 * correct (that is, a->header.len is nonzero and a multiple of sizeof(union
 * ofp_action) and no longer than the amount of space allocated to 'a').
 *
 * This function verifies that 'a''s length is correct for the type of action
 * that it represents. */
static enum ofperr
decode_openflow11_action(const union ofp_action *a,
                         enum ofputil_action_code *code)
{
    switch (a->type) {
    case CONSTANT_HTONS(OFPAT11_EXPERIMENTER):
        return decode_nxast_action(a, code);

#define OFPAT11_ACTION(ENUM, STRUCT, NAME)                          \
        case CONSTANT_HTONS(ENUM):                                  \
            if (a->header.len == htons(sizeof(struct STRUCT))) {    \
                *code = OFPUTIL_##ENUM;                             \
                return 0;                                           \
            } else {                                                \
                return OFPERR_OFPBAC_BAD_LEN;                       \
            }                                                       \
            break;
#include "ofp-util.def"

    default:
        return OFPERR_OFPBAC_BAD_TYPE;
    }
}

static enum ofperr
output_from_openflow11(const struct ofp11_action_output *oao,
                       struct ofpbuf *out)
{
    struct ofpact_output *output;
    enum ofperr error;

    output = ofpact_put_OUTPUT(out);
    output->max_len = ntohs(oao->max_len);

    error = ofputil_port_from_ofp11(oao->port, &output->port);
    if (error) {
        return error;
    }

    return ofputil_check_output_port(output->port, OFPP_MAX);
}

static enum ofperr
ofpact_from_openflow11(const union ofp_action *a, struct ofpbuf *out)
{
    enum ofputil_action_code code;
    enum ofperr error;

    error = decode_openflow11_action(a, &code);
    if (error) {
        return error;
    }

    switch (code) {
    case OFPUTIL_ACTION_INVALID:
#define OFPAT10_ACTION(ENUM, STRUCT, NAME) case OFPUTIL_##ENUM:
#define OFPIT11_ACTION(ENUM, STRUCT, NAME) case OFPUTIL_##ENUM:
#define OFPAT12_ACTION(ENUM, STRUCT, NAME) case OFPUTIL_##ENUM:
#include "ofp-util.def"
        NOT_REACHED();

    case OFPUTIL_OFPAT11_OUTPUT:
        return output_from_openflow11((const struct ofp11_action_output *) a,
                                      out);

    case OFPUTIL_OFPAT11_SET_VLAN_VID:
        if (a->vlan_vid.vlan_vid & ~htons(0xfff)) {
            return OFPERR_OFPBAC_BAD_ARGUMENT;
        }
        ofpact_put_SET_VLAN_VID(out)->vlan_vid = ntohs(a->vlan_vid.vlan_vid);
        break;

    case OFPUTIL_OFPAT11_SET_VLAN_PCP:
        if (a->vlan_pcp.vlan_pcp & ~7) {
            return OFPERR_OFPBAC_BAD_ARGUMENT;
        }
        ofpact_put_SET_VLAN_PCP(out)->vlan_pcp = a->vlan_pcp.vlan_pcp;
        break;

    case OFPUTIL_OFPAT11_SET_DL_SRC:
        memcpy(ofpact_put_SET_ETH_SRC(out)->mac,
               ((const struct ofp_action_dl_addr *) a)->dl_addr, ETH_ADDR_LEN);
        break;

    case OFPUTIL_OFPAT11_SET_DL_DST:
        memcpy(ofpact_put_SET_ETH_DST(out)->mac,
               ((const struct ofp_action_dl_addr *) a)->dl_addr, ETH_ADDR_LEN);
        break;

    case OFPUTIL_OFPAT11_SET_NW_SRC:
        ofpact_put_SET_IPV4_SRC(out)->ipv4 = a->nw_addr.nw_addr;
        break;

    case OFPUTIL_OFPAT11_SET_NW_DST:
        ofpact_put_SET_IPV4_DST(out)->ipv4 = a->nw_addr.nw_addr;
        break;

    case OFPUTIL_OFPAT11_SET_NW_TOS:
        if (a->nw_tos.nw_tos & ~IP_DSCP_MASK) {
            return OFPERR_OFPBAC_BAD_ARGUMENT;
        }
        ofpact_put_SET_IPV4_DSCP(out)->dscp = a->nw_tos.nw_tos;
        break;

    case OFPUTIL_OFPAT11_SET_TP_SRC:
        ofpact_put_SET_L4_SRC_PORT(out)->port = ntohs(a->tp_port.tp_port);
        break;

    case OFPUTIL_OFPAT11_SET_TP_DST:
        ofpact_put_SET_L4_DST_PORT(out)->port = ntohs(a->tp_port.tp_port);
        break;

    case OFPUTIL_OFPAT11_SET_MPLS_LABEL: {
        struct ofp11_action_mpls_label *oaml =
            (struct ofp11_action_mpls_label *)a;
        ofpact_put_SET_MPLS_LABEL(out)->mpls_label = oaml->mpls_label;
        break;
    }

    case OFPUTIL_OFPAT11_SET_MPLS_TC: {
        struct ofp11_action_mpls_tc *oamt = (struct ofp11_action_mpls_tc *)a;
        ofpact_put_SET_MPLS_TC(out)->mpls_tc = oamt->mpls_tc;
        break;
    }

    case OFPUTIL_OFPAT11_SET_MPLS_TTL: {
        struct ofp11_action_mpls_ttl *oasmt =
            (struct ofp11_action_mpls_ttl *)a;
        ofpact_put_SET_MPLS_TTL(out)->mpls_ttl = oasmt->mpls_ttl;
        break;
    }

    case OFPUTIL_OFPAT11_DEC_MPLS_TTL:
        ofpact_put_DEC_MPLS_TTL(out);
        break;

    case OFPUTIL_OFPAT11_PUSH_VLAN: {
        struct ofp11_action_push *oap = (struct ofp11_action_push *)a;
        ofpact_put_PUSH_VLAN(out)->tpid = oap->ethertype;
        break;
    }

    case OFPUTIL_OFPAT11_POP_VLAN: {
        ofpact_put_POP_VLAN(out);
        break;
    }

    case OFPUTIL_OFPAT11_PUSH_MPLS: {
        struct ofp11_action_push *oap = (struct ofp11_action_push *)a;
        ofpact_put_PUSH_MPLS(out)->ethertype = oap->ethertype;
        break;
    }

    case OFPUTIL_OFPAT11_POP_MPLS: {
        struct ofp11_action_pop_mpls *oapm = (struct ofp11_action_pop_mpls *)a;
        ofpact_put_POP_MPLS(out)->ethertype = oapm->ethertype;
        break;
    }

    case OFPUTIL_OFPAT11_COPY_TTL_OUT:
        ofpact_put_COPY_TTL_OUT(out);
        break;

    case OFPUTIL_OFPAT11_COPY_TTL_IN:
        ofpact_put_COPY_TTL_IN(out);
        break;

#define NXAST_ACTION(ENUM, STRUCT, EXTENSIBLE, NAME) case OFPUTIL_##ENUM:
#include "ofp-util.def"
        return ofpact_from_nxast(a, code, out);
    }

    return error;
}

static enum ofperr
ofpacts_from_openflow11(const union ofp_action *in, size_t n_in,
                        struct ofpbuf *out)
{
    return ofpacts_from_openflow(in, n_in, out, ofpact_from_openflow11);
}

static enum ofperr
decode_openflow12_action(const union ofp_action *a,
                         enum ofputil_action_code *code)
{
    /* set_field has variable length.
     * This just checks if struct is available. The more check will be done
     * by set_field_from_openflow()
     */
    if (a->type == CONSTANT_HTONS(OFPAT12_SET_FIELD)) {
        if (ntohs(a->header.len) >= sizeof(struct ofp12_action_set_field)) {
            *code = OFPUTIL_OFPAT12_SET_FIELD;
            return 0;
        }
        return OFPERR_OFPBAC_BAD_LEN;
    }

    switch (a->type) {
    case CONSTANT_HTONS(OFPAT12_EXPERIMENTER):
        return decode_nxast_action(a, code);

#define OFPAT12_ACTION(ENUM, STRUCT, NAME)                          \
        case CONSTANT_HTONS(ENUM):                                  \
            if (a->header.len == htons(sizeof(struct STRUCT))) {    \
                *code = OFPUTIL_##ENUM;                             \
                return 0;                                           \
            } else {                                                \
                return OFPERR_OFPBAC_BAD_LEN;                       \
            }                                                       \
            break;
#include "ofp-util.def"

    default:
        return OFPERR_OFPBAC_BAD_TYPE;
    }
}

static enum ofperr
ofpact_from_openflow12(const union ofp_action *a, struct ofpbuf *out)
{
    /* XXX */
    enum ofputil_action_code code;
    enum ofperr error;

    error = decode_openflow12_action(a, &code);
    if (error) {
        return error;
    }

    switch (code) {
    case OFPUTIL_ACTION_INVALID:
#define OFPAT10_ACTION(ENUM, STRUCT, NAME) case OFPUTIL_##ENUM:
#define OFPAT11_ACTION(ENUM, STRUCT, NAME) case OFPUTIL_##ENUM:
#define OFPIT11_ACTION(ENUM, STRUCT, NAME) case OFPUTIL_##ENUM:
#include "ofp-util.def"
        NOT_REACHED();

    case OFPUTIL_OFPAT12_COPY_TTL_OUT:
        ofpact_put_COPY_TTL_OUT(out);
        break;

    case OFPUTIL_OFPAT12_COPY_TTL_IN:
        ofpact_put_COPY_TTL_IN(out);
        break;

    case OFPUTIL_OFPAT12_SET_MPLS_TTL: {
        struct ofp11_action_mpls_ttl *oasmt =
            (struct ofp11_action_mpls_ttl *)a;
        ofpact_put_SET_MPLS_TTL(out)->mpls_ttl = oasmt->mpls_ttl;
        break;
    }

    case OFPUTIL_OFPAT12_DEC_MPLS_TTL:
        ofpact_put_DEC_MPLS_TTL(out);
        break;

    case OFPUTIL_OFPAT12_PUSH_VLAN: {
        struct ofp11_action_push *oap = (struct ofp11_action_push *)a;
        ofpact_put_PUSH_VLAN(out)->tpid = oap->ethertype;
        break;
    }

    case OFPUTIL_OFPAT12_POP_VLAN: {
        ofpact_put_POP_VLAN(out);
        break;
    }

    case OFPUTIL_OFPAT12_PUSH_MPLS: {
        struct ofp11_action_push *oap = (struct ofp11_action_push *)a;
        ofpact_put_PUSH_MPLS(out)->ethertype = oap->ethertype;
        break;
    }

    case OFPUTIL_OFPAT12_POP_MPLS: {
        struct ofp11_action_pop_mpls *oapm = (struct ofp11_action_pop_mpls *)a;
        ofpact_put_POP_MPLS(out)->ethertype = oapm->ethertype;
        break;
    }

    case OFPUTIL_OFPAT12_OUTPUT:
        return output_from_openflow11((const struct ofp11_action_output *) a,
                                      out);

    case OFPUTIL_OFPAT12_SET_FIELD:
        return set_field_from_openflow(
            (const struct ofp12_action_set_field *)a, out);

#define NXAST_ACTION(ENUM, STRUCT, EXTENSIBLE, NAME) case OFPUTIL_##ENUM:
#include "ofp-util.def"
        return ofpact_from_nxast(a, code, out);
    }

    return error;
}

static enum ofperr
ofpacts_from_openflow12(const union ofp_action *in, size_t n_in,
                        struct ofpbuf *out)
{
    return ofpacts_from_openflow(in, n_in, out, ofpact_from_openflow12);
}

/* OpenFlow 1.1 instructions. */

#define OVS_INSTRUCTIONS                                    \
    DEFINE_INST(OFPIT11_GOTO_TABLE,                         \
                ofp11_instruction_goto_table,     false,    \
                "goto_table")                               \
                                                            \
    DEFINE_INST(OFPIT11_WRITE_METADATA,                     \
                ofp11_instruction_write_metadata, false,    \
                "write_metadata")                           \
                                                            \
    DEFINE_INST(OFPIT11_WRITE_ACTIONS,                      \
                ofp11_instruction_actions,        true,     \
                "write_actions")                            \
                                                            \
    DEFINE_INST(OFPIT11_APPLY_ACTIONS,                      \
                ofp11_instruction_actions,        true,     \
                "apply_actions")                            \
                                                            \
    DEFINE_INST(OFPIT11_CLEAR_ACTIONS,                      \
                ofp11_instruction,                false,    \
                "clear_actions")

enum ovs_instruction_type {
#define DEFINE_INST(ENUM, STRUCT, NAME, EXTENSIBLE) OVSINST_##ENUM,
    OVS_INSTRUCTIONS
#undef DEFINE_INST
};

enum {
#define DEFINE_INST(ENUM, STRUCT, NAME, EXTENSIBLE) + 1
    N_OVS_INSTRUCTIONS = OVS_INSTRUCTIONS
#undef DEFINE_INST
};

static inline struct ofp11_instruction *
instruction_next(const struct ofp11_instruction *inst)
{
    return ((struct ofp11_instruction *) (void *)
            ((uint8_t *) inst + ntohs(inst->len)));
}

static inline bool
instruction_is_valid(const struct ofp11_instruction *inst,
                     size_t n_instructions)
{
    uint16_t len = ntohs(inst->len);
    return (!(len % OFP11_INSTRUCTION_ALIGN)
            && len >= sizeof *inst
            && len / sizeof *inst <= n_instructions);
}

/* This macro is careful to check for instructions with bad lengths. */
#define INSTRUCTION_FOR_EACH(ITER, LEFT, INSTRUCTIONS, N_INSTRUCTIONS)  \
    for ((ITER) = (INSTRUCTIONS), (LEFT) = (N_INSTRUCTIONS);            \
         (LEFT) > 0 && instruction_is_valid(ITER, LEFT);                \
         ((LEFT) -= (ntohs((ITER)->len)                                 \
                     / sizeof(struct ofp11_instruction)),               \
          (ITER) = instruction_next(ITER)))

static enum ofperr
decode_openflow11_instruction(const struct ofp11_instruction *inst,
                              enum ovs_instruction_type *type)
{
    uint16_t len = ntohs(inst->len);

    switch (inst->type) {
    case CONSTANT_HTONS(OFPIT11_EXPERIMENTER):
        return OFPERR_OFPBIC_BAD_EXPERIMENTER;

#define DEFINE_INST(ENUM, STRUCT, NAME, EXTENSIBLE)     \
        case CONSTANT_HTONS(ENUM):                      \
            if (EXTENSIBLE                              \
                ? len >= sizeof(struct STRUCT)          \
                : len == sizeof(struct STRUCT)) {       \
                *type = OVSINST_##ENUM;                 \
                return 0;                               \
            } else {                                    \
                return OFPERR_OFPBAC_BAD_LEN;           \
            }
OVS_INSTRUCTIONS
#undef DEFINE_INST

    default:
        return OFPERR_OFPBIC_UNKNOWN_INST;
    }
}

static enum ofperr
decode_openflow11_instructions(const struct ofp11_instruction insts[],
                               size_t n_insts,
                               const struct ofp11_instruction *out[])
{
    const struct ofp11_instruction *inst;
    size_t left;

    memset(out, 0, N_OVS_INSTRUCTIONS * sizeof *out);
    INSTRUCTION_FOR_EACH (inst, left, insts, n_insts) {
        enum ovs_instruction_type type;
        enum ofperr error;

        error = decode_openflow11_instruction(inst, &type);
        if (error) {
            return error;
        }

        if (out[type]) {
            return OFPERR_NXBIC_DUP_TYPE;
        }
        out[type] = inst;
    }

    if (left) {
        VLOG_WARN_RL(&rl, "bad instruction format at offset %zu",
                     (n_insts - left) * sizeof *inst);
        return OFPERR_OFPBIC_BAD_LEN;
    }
    return 0;
}

static void
get_actions_from_instruction(const struct ofp11_instruction *inst,
                         const union ofp_action **actions,
                         size_t *n_actions)
{
    *actions = (const union ofp_action *) (inst + 1);
    *n_actions = (ntohs(inst->len) - sizeof *inst) / OFP11_INSTRUCTION_ALIGN;
}

static enum ofperr
ofpacts_pull_inst_actions(uint8_t ofp_version,
                          const struct ofp11_instruction *inst,
                          struct ofpbuf *ofpacts)
{
    const union ofp_action *actions;
    size_t n_actions;
    enum ofperr error;
    struct ofpbuf *tmp = ofpbuf_new(1024 / 8); /* TODO:XXX 1024/8
                                                * same to handle_flow_mod()
                                                */
    struct ofpact_inst_actions *inst_actions;

    get_actions_from_instruction(inst, &actions, &n_actions);
    if (ofp_version == OFP12_VERSION) {
        error = ofpacts_from_openflow12(actions, n_actions, tmp);
    } else if (ofp_version == OFP11_VERSION) {
        error = ofpacts_from_openflow11(actions, n_actions, tmp);
    } else {
        NOT_REACHED();
    }
    if (error) {
        goto exit;
    }

    ofpbuf_prealloc_tailroom(ofpacts, sizeof(*inst_actions) + tmp->size);
    if (inst->type == CONSTANT_HTONS(OFPIT11_APPLY_ACTIONS)) {
        inst_actions = ofpact_put_APPLY_ACTIONS(ofpacts);
    } else if (inst->type == CONSTANT_HTONS(OFPIT11_WRITE_ACTIONS)){
        inst_actions = ofpact_put_WRITE_ACTIONS(ofpacts);
    } else {
        NOT_REACHED();
    }
    ofpbuf_put(ofpacts, tmp->data, tmp->size);
    ofpact_update_len(ofpacts, &inst_actions->ofpact);
exit:
    ofpbuf_delete(tmp);
    return error;
}


enum ofperr
ofpacts_pull_openflow11_actions(uint8_t ofp_version, struct ofpbuf *openflow,
                                unsigned int actions_len,
                                struct ofpbuf *ofpacts)
{
    const union ofp_action *actions;
    size_t n_actions = actions_len / OFP11_INSTRUCTION_ALIGN;
    enum ofperr error;

    ofpbuf_clear(ofpacts);

    if (actions_len % OFP11_INSTRUCTION_ALIGN != 0) {
        VLOG_WARN_RL(&rl, "OpenFlow message actions length %u is not a "
                     "multiple of %d", actions_len, OFP11_INSTRUCTION_ALIGN);
        error = OFPERR_OFPBRC_BAD_LEN;
        goto exit;
    }

    actions = ofpbuf_try_pull(openflow, actions_len);
    if (actions == NULL) {
        VLOG_WARN_RL(&rl, "OpenFlow message actions length %u exceeds "
                     "remaining message length (%zu)",
                     actions_len, openflow->size);
        error = OFPERR_OFPBRC_BAD_LEN;
        goto exit;
    }

    switch (ofp_version) {
    case OFP12_VERSION:
        error = ofpacts_from_openflow12(actions, n_actions, ofpacts);
        break;
    case OFP11_VERSION:
        error = ofpacts_from_openflow11(actions, n_actions, ofpacts);
        break;
    default:
        NOT_REACHED();
    }

exit:
    if (error) {
        ofpbuf_clear(ofpacts);
    }
    return error;
}

enum ofperr
ofpacts_pull_openflow11_instructions(uint8_t ofp_version,
                                     struct ofpbuf *openflow,
                                     unsigned int instructions_len,
                                     struct ofpbuf *ofpacts)
{
    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
    const struct ofp11_instruction *instructions;
    const struct ofp11_instruction *insts[N_OVS_INSTRUCTIONS];
    enum ofperr error;

    ofpbuf_clear(ofpacts);

    if (instructions_len % OFP11_INSTRUCTION_ALIGN != 0) {
        VLOG_WARN_RL(&rl, "OpenFlow message instructions length %u is not a "
                     "multiple of %d",
                     instructions_len, OFP11_INSTRUCTION_ALIGN);
        error = OFPERR_OFPBRC_BAD_LEN;
        goto exit;
    }

    instructions = ofpbuf_try_pull(openflow, instructions_len);
    if (instructions == NULL) {
        VLOG_WARN_RL(&rl, "OpenFlow message instructions length %u exceeds "
                     "remaining message length (%zu)",
                     instructions_len, openflow->size);
        error = OFPERR_OFPBRC_BAD_LEN;
        goto exit;
    }

    error = decode_openflow11_instructions(
        instructions, instructions_len / OFP11_INSTRUCTION_ALIGN,
        insts);
    if (error) {
        goto exit;
    }

    /* TODO:XXX insts[OVSINST_OFPIT13_METER] */
    /* TODO:XXX insts[OVSINST_OFPIT11_APPLY_ACTIONS] */
    if (insts[OVSINST_OFPIT11_APPLY_ACTIONS]) {
        error = ofpacts_pull_inst_actions(
            ofp_version, insts[OVSINST_OFPIT11_APPLY_ACTIONS], ofpacts);
        if (error) {
            goto exit;
        }
    }
    if (insts[OVSINST_OFPIT11_CLEAR_ACTIONS]) {
        ofpact_put_CLEAR_ACTIONS(ofpacts);
    }
    if (insts[OVSINST_OFPIT11_WRITE_ACTIONS]) {
        error = ofpacts_pull_inst_actions(
            ofp_version, insts[OVSINST_OFPIT11_WRITE_ACTIONS], ofpacts);
        if (error) {
            goto exit;
        }
    }
    /* TODO:XXX insts[OVSINST_OFPIT11_WRITE_METADATA] */
    if (insts[OVSINST_OFPIT11_GOTO_TABLE]) {
        struct ofp11_instruction_goto_table *oigt =
            (struct ofp11_instruction_goto_table *)
            insts[OVSINST_OFPIT11_GOTO_TABLE];
        struct ofpact_resubmit *resubmit = ofpact_put_RESUBMIT(ofpacts);
        resubmit->ofpact.compat = OFPUTIL_OFPIT11_GOTO_TABLE;
        resubmit->in_port = OFPP_IN_PORT;
        resubmit->table_id = oigt->table_id;
    }

    ofpact_put_END(ofpacts);

    if (insts[OVSINST_OFPIT11_WRITE_METADATA]) {
        error = OFPERR_OFPBIC_UNSUP_INST;
        goto exit;
    }

exit:
    if (error) {
        ofpbuf_clear(ofpacts);
    }
    return error;
}

static enum ofperr ofpacts_check__(const struct ofpact ofpacts[],
                                   const struct flow *flow, int max_ports,
                                   bool allow_inst);

static enum ofperr
ofpact_check__(const struct ofpact *a, const struct flow *flow, int max_ports,
               bool allow_inst)
{
    const struct ofpact_enqueue *enqueue;
    struct ofpact_inst_actions *inst_actions;
    ovs_be16 etype;
    ovs_be32 mpls_label;
    uint8_t mpls_tc, mpls_ttl;
    ovs_be16 vtpid;

    switch (a->type) {
    case OFPACT_END:
        return 0;

    case OFPACT_OUTPUT:
        return ofputil_check_output_port(ofpact_get_OUTPUT(a)->port,
                                         max_ports);

    case OFPACT_CONTROLLER:
        return 0;

    case OFPACT_ENQUEUE:
        enqueue = ofpact_get_ENQUEUE(a);
        if (enqueue->port >= max_ports && enqueue->port != OFPP_IN_PORT
            && enqueue->port != OFPP_LOCAL) {
            return OFPERR_OFPBAC_BAD_OUT_PORT;
        }
        return 0;

    case OFPACT_OUTPUT_REG:
        return mf_check_src(&ofpact_get_OUTPUT_REG(a)->src, flow);

    case OFPACT_BUNDLE:
        return bundle_check(ofpact_get_BUNDLE(a), max_ports, flow);

    case OFPACT_SET_VLAN_VID:
    case OFPACT_SET_VLAN_PCP:
    case OFPACT_STRIP_VLAN:
    case OFPACT_SET_ETH_SRC:
    case OFPACT_SET_ETH_DST:
    case OFPACT_SET_IPV4_SRC:
    case OFPACT_SET_IPV4_DST:
    case OFPACT_SET_IPV4_DSCP:
    case OFPACT_SET_L4_SRC_PORT:
    case OFPACT_SET_L4_DST_PORT:
        return 0;

    case OFPACT_REG_MOVE:
        return nxm_reg_move_check(ofpact_get_REG_MOVE(a), flow);

    case OFPACT_REG_LOAD:
        return nxm_reg_load_check(ofpact_get_REG_LOAD(a), flow);

    case OFPACT_DEC_TTL:
    case OFPACT_SET_TUNNEL:
    case OFPACT_SET_QUEUE:
    case OFPACT_POP_QUEUE:
    case OFPACT_FIN_TIMEOUT:
        return 0;

    case OFPACT_RESUBMIT:
        if (!allow_inst && a->compat == OFPUTIL_OFPIT11_GOTO_TABLE) {
            NOT_REACHED();
        }
        return 0;

    case OFPACT_LEARN:
        return learn_check(ofpact_get_LEARN(a), flow);

    case OFPACT_MULTIPATH:
        return multipath_check(ofpact_get_MULTIPATH(a), flow);

    case OFPACT_AUTOPATH:
        return autopath_check(ofpact_get_AUTOPATH(a), flow);

    case OFPACT_NOTE:
    case OFPACT_EXIT:
        return 0;

    case OFPACT_PUSH_MPLS:
        etype = ofpact_get_PUSH_MPLS(a)->ethertype;
        if (etype != htons(ETH_TYPE_MPLS) &&
            etype != htons(ETH_TYPE_MPLS_MCAST)) {
            return OFPERR_OFPBAC_BAD_ARGUMENT;
        }
        return 0;

    case OFPACT_POP_MPLS:
        etype = ofpact_get_POP_MPLS(a)->ethertype;
        if (etype == htons(ETH_TYPE_MPLS) ||
            etype == htons(ETH_TYPE_MPLS_MCAST)) {
            return OFPERR_OFPBAC_BAD_ARGUMENT;
        }
        return 0;

    case OFPACT_SET_MPLS_LABEL:
        mpls_label = ofpact_get_SET_MPLS_LABEL(a)->mpls_label;
        if (mpls_label & ~htonl(MPLS_LABEL_MASK >> MPLS_LABEL_SHIFT)) {
            return OFPERR_OFPBAC_BAD_ARGUMENT;
        }
        return 0;

    case OFPACT_SET_MPLS_TC:
        mpls_tc = ofpact_get_SET_MPLS_TC(a)->mpls_tc;
        if (mpls_tc & ~(MPLS_TC_MASK >> MPLS_TC_SHIFT)) {
            return OFPERR_OFPBAC_BAD_ARGUMENT;
        }
        return 0;

    case OFPACT_SET_MPLS_TTL:
        mpls_ttl = ofpact_get_SET_MPLS_TTL(a)->mpls_ttl;
        if (mpls_ttl == 0 || mpls_ttl == 1) {
            return OFPERR_OFPBAC_BAD_ARGUMENT;
        }
        return 0;

    case OFPACT_COPY_TTL_OUT:
    case OFPACT_COPY_TTL_IN:
    case OFPACT_DEC_MPLS_TTL:
        return 0;

    case OFPACT_PUSH_VLAN:
        vtpid = ofpact_get_PUSH_VLAN(a)->tpid;
        if (vtpid != htons(ETH_TYPE_VLAN) &&
            vtpid != htons(ETH_TYPE_VLAN_8021AD)) {
            return OFPERR_OFPBAC_BAD_ARGUMENT;
        }
        return 0;

    case OFPACT_POP_VLAN:
        ofpact_get_POP_VLAN(a);
        return 0;

    case OFPACT_APPLY_ACTIONS:
        if (!allow_inst) {
            NOT_REACHED();
        }
        inst_actions = ofpact_get_APPLY_ACTIONS(a);
        return ofpacts_check__(inst_actions->ofpacts, flow, max_ports, false);

    case OFPACT_WRITE_ACTIONS:
        if (!allow_inst) {
            NOT_REACHED();
        }
        inst_actions = ofpact_get_WRITE_ACTIONS(a);
        return ofpacts_check__(inst_actions->ofpacts, flow, max_ports, false);

    case OFPACT_CLEAR_ACTIONS:
        return 0;

    default:
        NOT_REACHED();
    }
}

/* Checks that the actions in 'ofpacts' (terminated by OFPACT_END) are
 * appropriate for a packet with the prerequisites satisfied by 'flow' in a
 * switch with no more than 'max_ports' ports. */
static enum ofperr
ofpacts_check__(const struct ofpact ofpacts[],
                const struct flow *flow, int max_ports, bool allow_inst)
{
    const struct ofpact *a;

    OFPACT_FOR_EACH (a, ofpacts) {
        enum ofperr error = ofpact_check__(a, flow, max_ports, allow_inst);
        if (error) {
            return error;
        }
    }

    return 0;
}
enum ofperr
ofpacts_check(const struct ofpact ofpacts[],
              const struct flow *flow, int max_ports)
{
    return ofpacts_check__(ofpacts, flow, max_ports, true);
}

/* Converting ofpacts to Nicira OpenFlow extensions. */

static void
ofpact_output_reg_to_nxast(const struct ofpact_output_reg *output_reg,
                                struct ofpbuf *out)
{
    struct nx_action_output_reg *naor = ofputil_put_NXAST_OUTPUT_REG(out);

    naor->ofs_nbits = nxm_encode_ofs_nbits(output_reg->src.ofs,
                                           output_reg->src.n_bits);
    naor->src = htonl(output_reg->src.field->nxm_header);
    naor->max_len = htons(output_reg->max_len);
}

static void
ofpact_resubmit_to_nxast(const struct ofpact_resubmit *resubmit,
                         struct ofpbuf *out)
{
    struct nx_action_resubmit *nar;

    if (resubmit->table_id == 0xff
        && resubmit->ofpact.compat != OFPUTIL_NXAST_RESUBMIT_TABLE) {
        nar = ofputil_put_NXAST_RESUBMIT(out);
    } else {
        nar = ofputil_put_NXAST_RESUBMIT_TABLE(out);
        nar->table = resubmit->table_id;
    }
    nar->in_port = htons(resubmit->in_port);
}

static void
ofpact_set_tunnel_to_nxast(const struct ofpact_tunnel *tunnel,
                           struct ofpbuf *out)
{
    uint64_t tun_id = tunnel->tun_id;

    if (tun_id <= UINT32_MAX
        && tunnel->ofpact.compat != OFPUTIL_NXAST_SET_TUNNEL64) {
        ofputil_put_NXAST_SET_TUNNEL(out)->tun_id = htonl(tun_id);
    } else {
        ofputil_put_NXAST_SET_TUNNEL64(out)->tun_id = htonll(tun_id);
    }
}

static void
ofpact_note_to_nxast(const struct ofpact_note *note, struct ofpbuf *out)
{
    size_t start_ofs = out->size;
    struct nx_action_note *nan;
    unsigned int remainder;
    unsigned int len;

    nan = ofputil_put_NXAST_NOTE(out);
    out->size -= sizeof nan->note;

    ofpbuf_put(out, note->data, note->length);

    len = out->size - start_ofs;
    remainder = len % OFP_ACTION_ALIGN;
    if (remainder) {
        ofpbuf_put_zeros(out, OFP_ACTION_ALIGN - remainder);
    }
    nan = (struct nx_action_note *)((char *)out->data + start_ofs);
    nan->len = htons(out->size - start_ofs);
}

static void
ofpact_controller_to_nxast(const struct ofpact_controller *oc,
                           struct ofpbuf *out)
{
    struct nx_action_controller *nac;

    nac = ofputil_put_NXAST_CONTROLLER(out);
    nac->max_len = htons(oc->max_len);
    nac->controller_id = htons(oc->controller_id);
    nac->reason = oc->reason;
}

static void
ofpact_fin_timeout_to_nxast(const struct ofpact_fin_timeout *fin_timeout,
                            struct ofpbuf *out)
{
    struct nx_action_fin_timeout *naft = ofputil_put_NXAST_FIN_TIMEOUT(out);
    naft->fin_idle_timeout = htons(fin_timeout->fin_idle_timeout);
    naft->fin_hard_timeout = htons(fin_timeout->fin_hard_timeout);
}

static void
ofpact_to_nxast(const struct ofpact *a, struct ofpbuf *out)
{
    switch (a->type) {
    case OFPACT_CONTROLLER:
        ofpact_controller_to_nxast(ofpact_get_CONTROLLER(a), out);
        break;

    case OFPACT_OUTPUT_REG:
        ofpact_output_reg_to_nxast(ofpact_get_OUTPUT_REG(a), out);
        break;

    case OFPACT_BUNDLE:
        bundle_to_openflow(ofpact_get_BUNDLE(a), out);
        break;

    case OFPACT_REG_MOVE:
        nxm_reg_move_to_openflow(ofpact_get_REG_MOVE(a), out);
        break;

    case OFPACT_REG_LOAD:
        nxm_reg_load_to_openflow(ofpact_get_REG_LOAD(a), out);
        break;

    case OFPACT_DEC_TTL:
        ofputil_put_NXAST_DEC_TTL(out);
        break;

    case OFPACT_SET_TUNNEL:
        ofpact_set_tunnel_to_nxast(ofpact_get_SET_TUNNEL(a), out);
        break;

    case OFPACT_SET_QUEUE:
        ofputil_put_NXAST_SET_QUEUE(out)->queue_id
            = htonl(ofpact_get_SET_QUEUE(a)->queue_id);
        break;

    case OFPACT_POP_QUEUE:
        ofputil_put_NXAST_POP_QUEUE(out);
        break;

    case OFPACT_FIN_TIMEOUT:
        ofpact_fin_timeout_to_nxast(ofpact_get_FIN_TIMEOUT(a), out);
        break;

    case OFPACT_RESUBMIT:
        ofpact_resubmit_to_nxast(ofpact_get_RESUBMIT(a), out);
        break;

    case OFPACT_LEARN:
        learn_to_openflow(ofpact_get_LEARN(a), out);
        break;

    case OFPACT_MULTIPATH:
        multipath_to_openflow(ofpact_get_MULTIPATH(a), out);
        break;

    case OFPACT_AUTOPATH:
        autopath_to_openflow(ofpact_get_AUTOPATH(a), out);
        break;

    case OFPACT_NOTE:
        ofpact_note_to_nxast(ofpact_get_NOTE(a), out);
        break;

    case OFPACT_EXIT:
        ofputil_put_NXAST_EXIT(out);
        break;

    case OFPACT_PUSH_VLAN:
        ofputil_put_NXAST_PUSH_VLAN(out)->tpid = ofpact_get_PUSH_VLAN(a)->tpid;
        break;

    case OFPACT_END:
    case OFPACT_OUTPUT:
    case OFPACT_ENQUEUE:
    case OFPACT_SET_VLAN_VID:
    case OFPACT_SET_VLAN_PCP:
    case OFPACT_STRIP_VLAN:
    case OFPACT_SET_ETH_SRC:
    case OFPACT_SET_ETH_DST:
    case OFPACT_SET_IPV4_SRC:
    case OFPACT_SET_IPV4_DST:
    case OFPACT_SET_IPV4_DSCP:
    case OFPACT_SET_L4_SRC_PORT:
    case OFPACT_SET_L4_DST_PORT:
    case OFPACT_APPLY_ACTIONS:
    case OFPACT_CLEAR_ACTIONS:
    case OFPACT_WRITE_ACTIONS:
    case OFPACT_SET_MPLS_LABEL:
    case OFPACT_SET_MPLS_TC:
    case OFPACT_SET_MPLS_TTL:
    case OFPACT_DEC_MPLS_TTL:
    case OFPACT_PUSH_MPLS:
    case OFPACT_POP_MPLS:
    case OFPACT_POP_VLAN:
    case OFPACT_COPY_TTL_OUT:
    case OFPACT_COPY_TTL_IN:
        NOT_REACHED();
    }
}

/* Converting ofpacts to OpenFlow 1.0. */

static void
ofpact_output_to_openflow10(const struct ofpact_output *output,
                            struct ofpbuf *out)
{
    struct ofp10_action_output *oao;

    oao = ofputil_put_OFPAT10_OUTPUT(out);
    oao->port = htons(output->port);
    oao->max_len = htons(output->max_len);
}

static void
ofpact_enqueue_to_openflow10(const struct ofpact_enqueue *enqueue,
                             struct ofpbuf *out)
{
    struct ofp_action_enqueue *oae;

    oae = ofputil_put_OFPAT10_ENQUEUE(out);
    oae->port = htons(enqueue->port);
    oae->queue_id = htonl(enqueue->queue);
}

static void
ofpact_to_openflow10(const struct ofpact *a, struct ofpbuf *out)
{
    switch (a->type) {
    case OFPACT_END:
    case OFPACT_APPLY_ACTIONS:
    case OFPACT_CLEAR_ACTIONS:
    case OFPACT_WRITE_ACTIONS:
        NOT_REACHED();

    case OFPACT_OUTPUT:
        ofpact_output_to_openflow10(ofpact_get_OUTPUT(a), out);
        break;

    case OFPACT_ENQUEUE:
        ofpact_enqueue_to_openflow10(ofpact_get_ENQUEUE(a), out);
        break;

    case OFPACT_SET_VLAN_VID:
        ofputil_put_OFPAT10_SET_VLAN_VID(out)->vlan_vid
            = htons(ofpact_get_SET_VLAN_VID(a)->vlan_vid);
        break;

    case OFPACT_SET_VLAN_PCP:
        ofputil_put_OFPAT10_SET_VLAN_PCP(out)->vlan_pcp
            = ofpact_get_SET_VLAN_PCP(a)->vlan_pcp;
        break;

    case OFPACT_STRIP_VLAN:
        ofputil_put_OFPAT10_STRIP_VLAN(out);
        break;

    case OFPACT_SET_ETH_SRC:
        memcpy(ofputil_put_OFPAT10_SET_DL_SRC(out)->dl_addr,
               ofpact_get_SET_ETH_SRC(a)->mac, ETH_ADDR_LEN);
        break;

    case OFPACT_SET_ETH_DST:
        memcpy(ofputil_put_OFPAT10_SET_DL_DST(out)->dl_addr,
               ofpact_get_SET_ETH_DST(a)->mac, ETH_ADDR_LEN);
        break;

    case OFPACT_SET_IPV4_SRC:
        ofputil_put_OFPAT10_SET_NW_SRC(out)->nw_addr
            = ofpact_get_SET_IPV4_SRC(a)->ipv4;
        break;

    case OFPACT_SET_IPV4_DST:
        ofputil_put_OFPAT10_SET_NW_DST(out)->nw_addr
            = ofpact_get_SET_IPV4_DST(a)->ipv4;
        break;

    case OFPACT_SET_IPV4_DSCP:
        ofputil_put_OFPAT10_SET_NW_TOS(out)->nw_tos
            = ofpact_get_SET_IPV4_DSCP(a)->dscp;
        break;

    case OFPACT_SET_L4_SRC_PORT:
        ofputil_put_OFPAT10_SET_TP_SRC(out)->tp_port
            = htons(ofpact_get_SET_L4_SRC_PORT(a)->port);
        break;

    case OFPACT_SET_L4_DST_PORT:
        ofputil_put_OFPAT10_SET_TP_DST(out)->tp_port
            = htons(ofpact_get_SET_L4_DST_PORT(a)->port);
        break;

    case OFPACT_CONTROLLER:
    case OFPACT_OUTPUT_REG:
    case OFPACT_BUNDLE:
    case OFPACT_REG_MOVE:
    case OFPACT_REG_LOAD:
    case OFPACT_DEC_TTL:
    case OFPACT_SET_TUNNEL:
    case OFPACT_SET_QUEUE:
    case OFPACT_POP_QUEUE:
    case OFPACT_FIN_TIMEOUT:
    case OFPACT_RESUBMIT:
    case OFPACT_LEARN:
    case OFPACT_MULTIPATH:
    case OFPACT_AUTOPATH:
    case OFPACT_NOTE:
    case OFPACT_EXIT:
    case OFPACT_SET_MPLS_LABEL:
    case OFPACT_SET_MPLS_TC:
    case OFPACT_SET_MPLS_TTL:
    case OFPACT_DEC_MPLS_TTL:
    case OFPACT_PUSH_MPLS:
    case OFPACT_POP_VLAN:
    case OFPACT_POP_MPLS:
    case OFPACT_PUSH_VLAN:
        ofpact_to_nxast(a, out);
        break;


    case OFPACT_COPY_TTL_OUT:
    case OFPACT_COPY_TTL_IN:
        /* TODO:XXX return error */
        NOT_REACHED();
        break;
    }
}

/* Converts the ofpacts in 'ofpacts' (terminated by OFPACT_END) into OpenFlow
 * 1.0 actions in 'openflow', appending the actions to any existing data in
 * 'openflow'. */
void
ofpacts_to_openflow10(const struct ofpact ofpacts[], struct ofpbuf *openflow)
{
    const struct ofpact *a;

    OFPACT_FOR_EACH (a, ofpacts) {
        ofpact_to_openflow10(a, openflow);
    }
}

/* Converting ofpacts to OpenFlow 1.1. */

static void
ofpact_output_to_openflow11(const struct ofpact_output *output,
                            struct ofpbuf *out)
{
    struct ofp11_action_output *oao;

    oao = ofputil_put_OFPAT11_OUTPUT(out);
    oao->port = ofputil_port_to_ofp11(output->port);
    oao->max_len = htons(output->max_len);
}

static void
ofpact_to_openflow11_common(const struct ofpact *a, struct ofpbuf *out)
{
    switch (a->type) {
    case OFPACT_OUTPUT:
        return ofpact_output_to_openflow11(ofpact_get_OUTPUT(a), out);

    case OFPACT_ENQUEUE:
        /* XXX */
        break;

    case OFPACT_PUSH_VLAN:
        ofputil_put_OFPAT11_PUSH_VLAN(out)->ethertype =
            ofpact_get_PUSH_VLAN(a)->tpid;
        break;

    case OFPACT_POP_VLAN:
        ofputil_put_OFPAT11_POP_VLAN(out);
        break;

    case OFPACT_SET_MPLS_TTL:
        ofputil_put_OFPAT11_SET_MPLS_TTL(out)->mpls_ttl =
            ofpact_get_SET_MPLS_TTL(a)->mpls_ttl;
        break;

    case OFPACT_DEC_MPLS_TTL:
        ofputil_put_OFPAT11_DEC_MPLS_TTL(out);
        break;

    case OFPACT_PUSH_MPLS:
        ofputil_put_OFPAT11_PUSH_MPLS(out)->ethertype =
            ofpact_get_PUSH_MPLS(a)->ethertype;
        break;

    case OFPACT_POP_MPLS:
        ofputil_put_OFPAT11_POP_MPLS(out)->ethertype =
            ofpact_get_POP_MPLS(a)->ethertype;
        break;

    case OFPACT_COPY_TTL_OUT:
        ofputil_put_OFPAT11_COPY_TTL_OUT(out);
        break;

    case OFPACT_COPY_TTL_IN:
        ofputil_put_OFPAT11_COPY_TTL_IN(out);
        break;

    /* TODO: more actions OFPAT_DEC_NW_TTL (and OFPAT_SET_NW_TTL) */

    case OFPACT_END:
    case OFPACT_CONTROLLER:
    case OFPACT_OUTPUT_REG:
    case OFPACT_BUNDLE:
    case OFPACT_SET_VLAN_VID:
    case OFPACT_SET_VLAN_PCP:
    case OFPACT_STRIP_VLAN:
    case OFPACT_SET_ETH_SRC:
    case OFPACT_SET_ETH_DST:
    case OFPACT_SET_IPV4_SRC:
    case OFPACT_SET_IPV4_DST:
    case OFPACT_SET_IPV4_DSCP:
    case OFPACT_SET_L4_SRC_PORT:
    case OFPACT_SET_L4_DST_PORT:
    case OFPACT_REG_MOVE:
    case OFPACT_REG_LOAD:
    case OFPACT_DEC_TTL:
    case OFPACT_SET_MPLS_LABEL:
    case OFPACT_SET_MPLS_TC:
    case OFPACT_SET_TUNNEL:
    case OFPACT_SET_QUEUE:
    case OFPACT_POP_QUEUE:
    case OFPACT_FIN_TIMEOUT:
    case OFPACT_RESUBMIT:
    case OFPACT_LEARN:
    case OFPACT_MULTIPATH:
    case OFPACT_AUTOPATH:
    case OFPACT_NOTE:
    case OFPACT_EXIT:
    case OFPACT_APPLY_ACTIONS:
    case OFPACT_CLEAR_ACTIONS:
    case OFPACT_WRITE_ACTIONS:
    default:
        NOT_REACHED();
    }
}

static void
ofpact_to_openflow11(const struct ofpact *a, struct ofpbuf *out)
{
    switch (a->type) {
    case OFPACT_END:
    case OFPACT_APPLY_ACTIONS:
    case OFPACT_CLEAR_ACTIONS:
    case OFPACT_WRITE_ACTIONS:
        NOT_REACHED();

    case OFPACT_OUTPUT:
    case OFPACT_ENQUEUE:
    case OFPACT_SET_MPLS_TTL:
    case OFPACT_DEC_MPLS_TTL:
    case OFPACT_PUSH_VLAN:
    case OFPACT_POP_VLAN:
    case OFPACT_PUSH_MPLS:
    case OFPACT_POP_MPLS:
    case OFPACT_COPY_TTL_OUT:
    case OFPACT_COPY_TTL_IN:
        return ofpact_to_openflow11_common(a, out);

    case OFPACT_SET_VLAN_VID:
        ofputil_put_OFPAT11_SET_VLAN_VID(out)->vlan_vid
            = htons(ofpact_get_SET_VLAN_VID(a)->vlan_vid);
        break;

    case OFPACT_SET_VLAN_PCP:
        ofputil_put_OFPAT11_SET_VLAN_PCP(out)->vlan_pcp
            = ofpact_get_SET_VLAN_PCP(a)->vlan_pcp;
        break;

    case OFPACT_STRIP_VLAN:
        /* XXX */
        break;

    case OFPACT_SET_ETH_SRC:
        memcpy(ofputil_put_OFPAT11_SET_DL_SRC(out)->dl_addr,
               ofpact_get_SET_ETH_SRC(a)->mac, ETH_ADDR_LEN);
        break;

    case OFPACT_SET_ETH_DST:
        memcpy(ofputil_put_OFPAT11_SET_DL_DST(out)->dl_addr,
               ofpact_get_SET_ETH_DST(a)->mac, ETH_ADDR_LEN);
        break;

    case OFPACT_SET_IPV4_SRC:
        ofputil_put_OFPAT11_SET_NW_SRC(out)->nw_addr
            = ofpact_get_SET_IPV4_SRC(a)->ipv4;
        break;

    case OFPACT_SET_IPV4_DST:
        ofputil_put_OFPAT11_SET_NW_DST(out)->nw_addr
            = ofpact_get_SET_IPV4_DST(a)->ipv4;
        break;

    case OFPACT_SET_IPV4_DSCP:
        ofputil_put_OFPAT11_SET_NW_TOS(out)->nw_tos
            = ofpact_get_SET_IPV4_DSCP(a)->dscp;
        break;

    case OFPACT_SET_L4_SRC_PORT:
        ofputil_put_OFPAT11_SET_TP_SRC(out)->tp_port
            = htons(ofpact_get_SET_L4_SRC_PORT(a)->port);
        break;

    case OFPACT_SET_L4_DST_PORT:
        ofputil_put_OFPAT11_SET_TP_DST(out)->tp_port
            = htons(ofpact_get_SET_L4_DST_PORT(a)->port);
        break;

    case OFPACT_CONTROLLER:
    case OFPACT_OUTPUT_REG:
    case OFPACT_BUNDLE:
    case OFPACT_REG_MOVE:
    case OFPACT_REG_LOAD:
    case OFPACT_DEC_TTL:
    case OFPACT_SET_MPLS_LABEL:
    case OFPACT_SET_MPLS_TC:
    case OFPACT_SET_TUNNEL:
    case OFPACT_SET_QUEUE:
    case OFPACT_POP_QUEUE:
    case OFPACT_FIN_TIMEOUT:
    case OFPACT_RESUBMIT:
    case OFPACT_LEARN:
    case OFPACT_MULTIPATH:
    case OFPACT_AUTOPATH:
    case OFPACT_NOTE:
    case OFPACT_EXIT:
        ofpact_to_nxast(a, out);
        break;
    }
}

static void
ofpact_to_openflow12(const struct ofpact *a, struct ofpbuf *out)
{
    switch (a->type) {
    case OFPACT_END:
    case OFPACT_SET_VLAN_VID:
    case OFPACT_SET_VLAN_PCP:
    case OFPACT_STRIP_VLAN:
    case OFPACT_SET_ETH_SRC:
    case OFPACT_SET_ETH_DST:
    case OFPACT_SET_IPV4_SRC:
    case OFPACT_SET_IPV4_DST:
    case OFPACT_SET_IPV4_DSCP:
    case OFPACT_SET_L4_SRC_PORT:
    case OFPACT_SET_L4_DST_PORT:
    case OFPACT_APPLY_ACTIONS:
    case OFPACT_CLEAR_ACTIONS:
    case OFPACT_WRITE_ACTIONS:
        NOT_REACHED();

    case OFPACT_OUTPUT:
    case OFPACT_ENQUEUE:
    case OFPACT_SET_MPLS_TTL:
    case OFPACT_DEC_MPLS_TTL:
    case OFPACT_PUSH_VLAN:
    case OFPACT_POP_VLAN:
    case OFPACT_PUSH_MPLS:
    case OFPACT_POP_MPLS:
    case OFPACT_COPY_TTL_OUT:
    case OFPACT_COPY_TTL_IN:
        return ofpact_to_openflow11_common(a, out);

    case OFPACT_CONTROLLER:
    case OFPACT_OUTPUT_REG:
    case OFPACT_BUNDLE:
    case OFPACT_REG_MOVE:
    case OFPACT_REG_LOAD:
    case OFPACT_DEC_TTL:
    case OFPACT_SET_TUNNEL:
    case OFPACT_SET_QUEUE:
    case OFPACT_POP_QUEUE:
    case OFPACT_FIN_TIMEOUT:
    case OFPACT_RESUBMIT:
    case OFPACT_LEARN:
    case OFPACT_MULTIPATH:
    case OFPACT_AUTOPATH:
    case OFPACT_NOTE:
    case OFPACT_EXIT:
    case OFPACT_SET_MPLS_LABEL:
    case OFPACT_SET_MPLS_TC:
        ofpact_to_nxast(a, out);
        break;
    }
}

static void
ofpacts_to_inst_actions(const struct ofpact ofpacts[],
                        struct ofpbuf *openflow,
                        enum ofp11_instruction_type type,
                        void (*ofpact_to_openflow)(
                            const struct ofpact *a, struct ofpbuf *out))
{
    size_t start_len;
    struct ofp11_instruction_actions *oia;
    const struct ofpact *a;

    start_len = openflow->size;
    oia = ofpbuf_put_uninit(openflow, sizeof *oia);
    oia->type = htons(type);
    memset(oia->pad, 0, sizeof oia->pad);

    OFPACT_FOR_EACH (a, ofpacts) {
        assert(!ofpact_is_instruction(a));
        ofpact_to_openflow(a, openflow);
    }

    oia = ofpbuf_at_assert(openflow, start_len, sizeof *oia);
    oia->len = htons(openflow->size - start_len);
}

/* Converts the ofpacts in 'ofpacts' (terminated by OFPACT_END) into OpenFlow
 * 1.1 actions in 'openflow', appending the actions to any existing data in
 * 'openflow'. */
static void
ofpacts_insts_to_openflow11__(const struct ofpact *ofpacts,
                              struct ofpbuf *openflow,
                              void (*ofpact_to_openflow)(
                                  const struct ofpact *a, struct ofpbuf *out))
{
    size_t start_len = openflow->size;
    struct ofp11_instruction_actions *oia;

    switch (ofpacts[0].type) {
    case OFPACT_END:
        break;

    case OFPACT_RESUBMIT: {
        struct ofpact_resubmit *resubmit;
        struct ofp11_instruction_goto_table *oigt;

        resubmit = ofpact_get_RESUBMIT(ofpacts);
        assert(resubmit->in_port == OFPP_IN_PORT);
        assert(resubmit->ofpact.compat == OFPUTIL_OFPIT11_GOTO_TABLE);

        oigt = ofpbuf_put_uninit(openflow, sizeof *oigt);
        oigt->type = htons(OFPIT11_GOTO_TABLE);
        oigt->len = htons(openflow->size - start_len);
        oigt->table_id = resubmit->table_id;
        memset(oigt->pad, 0, sizeof oigt->pad);
        break;
    }

    case OFPACT_WRITE_ACTIONS:
    case OFPACT_APPLY_ACTIONS: {
        const struct ofpact_inst_actions *inst_actions;
        enum ofp11_instruction_type type;

        if (ofpacts[0].type == OFPACT_WRITE_ACTIONS) {
            inst_actions = ofpact_get_WRITE_ACTIONS(ofpacts);
            type = OFPIT11_WRITE_ACTIONS;
        } else {
            inst_actions = ofpact_get_APPLY_ACTIONS(ofpacts);
            type = OFPIT11_APPLY_ACTIONS;
        }
        ofpacts_to_inst_actions(inst_actions->ofpacts, openflow, type,
                                ofpact_to_openflow);
        break;
    }

    case OFPACT_CLEAR_ACTIONS:
        oia = ofpbuf_put_uninit(openflow, sizeof *oia);
        oia->type = htons(OFPIT11_CLEAR_ACTIONS);
        oia->len = htons(openflow->size - start_len);
        memset(oia->pad, 0, sizeof oia->pad);
        break;

    /* FIXME: write-metadata, experimenter, meter */

    case OFPACT_OUTPUT:
    case OFPACT_CONTROLLER:
    case OFPACT_ENQUEUE:
    case OFPACT_OUTPUT_REG:
    case OFPACT_BUNDLE:
    case OFPACT_SET_VLAN_VID:
    case OFPACT_SET_VLAN_PCP:
    case OFPACT_STRIP_VLAN:
    case OFPACT_SET_ETH_SRC:
    case OFPACT_SET_ETH_DST:
    case OFPACT_SET_IPV4_SRC:
    case OFPACT_SET_IPV4_DST:
    case OFPACT_SET_IPV4_DSCP:
    case OFPACT_SET_L4_SRC_PORT:
    case OFPACT_SET_L4_DST_PORT:
    case OFPACT_REG_MOVE:
    case OFPACT_REG_LOAD:
    case OFPACT_DEC_TTL:
    case OFPACT_SET_TUNNEL:
    case OFPACT_SET_QUEUE:
    case OFPACT_POP_QUEUE:
    case OFPACT_FIN_TIMEOUT:
    case OFPACT_LEARN:
    case OFPACT_MULTIPATH:
    case OFPACT_AUTOPATH:
    case OFPACT_NOTE:
    case OFPACT_EXIT:
    case OFPACT_COPY_TTL_OUT:
    case OFPACT_COPY_TTL_IN:
    case OFPACT_SET_MPLS_LABEL:
    case OFPACT_SET_MPLS_TC:
    case OFPACT_SET_MPLS_TTL:
    case OFPACT_DEC_MPLS_TTL:
    case OFPACT_PUSH_MPLS:
    case OFPACT_POP_MPLS:
    case OFPACT_PUSH_VLAN:
    case OFPACT_POP_VLAN:
    default:
        NOT_REACHED();
    }
}

void
ofpacts_insts_to_openflow11(uint8_t ofp_version,
                            const struct ofpact ofpacts[],
                            struct ofpbuf *openflow)
{
    const struct ofpact *a;
    void (*ofpact_to_openflow)(const struct ofpact *a, struct ofpbuf *out);

    if (ofp_version == OFP11_VERSION) {
        ofpact_to_openflow = ofpact_to_openflow11;
    } else if (ofp_version == OFP12_VERSION) {
        ofpact_to_openflow = ofpact_to_openflow12;
    } else {
        NOT_REACHED();
    }

    if (!ofpact_is_instruction(ofpacts)) {
        ofpacts_to_inst_actions(ofpacts, openflow, OFPIT11_APPLY_ACTIONS,
                                ofpact_to_openflow);
        return;
    }

    OFPACT_FOR_EACH(a, ofpacts) {
        assert(ofpact_is_instruction(a) || a->type == OFPACT_END);
        ofpacts_insts_to_openflow11__(a, openflow, ofpact_to_openflow);
    }
}

/* Returns true if 'action' outputs to 'port', false otherwise. */
static bool
ofpact_outputs_to_port(const struct ofpact *ofpact, uint16_t port)
{
    switch (ofpact->type) {
    case OFPACT_OUTPUT:
        return ofpact_get_OUTPUT(ofpact)->port == port;
    case OFPACT_ENQUEUE:
        return ofpact_get_ENQUEUE(ofpact)->port == port;
    case OFPACT_CONTROLLER:
        return port == OFPP_CONTROLLER;

    case OFPACT_END:
    case OFPACT_OUTPUT_REG:
    case OFPACT_BUNDLE:
    case OFPACT_SET_VLAN_VID:
    case OFPACT_SET_VLAN_PCP:
    case OFPACT_STRIP_VLAN:
    case OFPACT_SET_ETH_SRC:
    case OFPACT_SET_ETH_DST:
    case OFPACT_SET_IPV4_SRC:
    case OFPACT_SET_IPV4_DST:
    case OFPACT_SET_IPV4_DSCP:
    case OFPACT_SET_L4_SRC_PORT:
    case OFPACT_SET_L4_DST_PORT:
    case OFPACT_REG_MOVE:
    case OFPACT_REG_LOAD:
    case OFPACT_DEC_TTL:
    case OFPACT_SET_TUNNEL:
    case OFPACT_SET_QUEUE:
    case OFPACT_POP_QUEUE:
    case OFPACT_FIN_TIMEOUT:
    case OFPACT_RESUBMIT:
    case OFPACT_LEARN:
    case OFPACT_MULTIPATH:
    case OFPACT_AUTOPATH:
    case OFPACT_NOTE:
    case OFPACT_EXIT:
    case OFPACT_COPY_TTL_OUT:
    case OFPACT_COPY_TTL_IN:
    case OFPACT_SET_MPLS_LABEL:
    case OFPACT_SET_MPLS_TC:
    case OFPACT_SET_MPLS_TTL:
    case OFPACT_DEC_MPLS_TTL:
    case OFPACT_PUSH_VLAN:
    case OFPACT_POP_VLAN:
    case OFPACT_PUSH_MPLS:
    case OFPACT_POP_MPLS:
    case OFPACT_APPLY_ACTIONS:
    case OFPACT_CLEAR_ACTIONS:
    case OFPACT_WRITE_ACTIONS:
    default:
        return false;
    }
}

/* Returns true if any action in 'ofpacts' outputs to 'port', false
 * otherwise. */
bool
ofpacts_output_to_port(const struct ofpact *ofpacts, uint16_t port)
{
    const struct ofpact *a;

    OFPACT_FOR_EACH (a, ofpacts) {
        if (ofpact_outputs_to_port(a, port)) {
            return true;
        }
    }

    return false;
}

bool
ofpacts_equal(const struct ofpact *a, size_t a_len,
              const struct ofpact *b, size_t b_len)
{
    return a_len == b_len && !memcmp(a, b, a_len);
}

/* Formatting ofpacts. */
static void ofpacts_format__(const struct ofpact *ofpacts, struct ds *string);

static void
print_note(const struct ofpact_note *note, struct ds *string)
{
    size_t i;

    ds_put_cstr(string, "note:");
    for (i = 0; i < note->length; i++) {
        if (i) {
            ds_put_char(string, '.');
        }
        ds_put_format(string, "%02"PRIx8, note->data[i]);
    }
}

static void
print_fin_timeout(const struct ofpact_fin_timeout *fin_timeout,
                  struct ds *s)
{
    ds_put_cstr(s, "fin_timeout(");
    if (fin_timeout->fin_idle_timeout) {
        ds_put_format(s, "idle_timeout=%"PRIu16",",
                      fin_timeout->fin_idle_timeout);
    }
    if (fin_timeout->fin_hard_timeout) {
        ds_put_format(s, "hard_timeout=%"PRIu16",",
                      fin_timeout->fin_hard_timeout);
    }
    ds_chomp(s, ',');
    ds_put_char(s, ')');
}

static void
ofpact_format(const struct ofpact *a, struct ds *s)
{
    const struct ofpact_enqueue *enqueue;
    const struct ofpact_resubmit *resubmit;
    const struct ofpact_autopath *autopath;
    const struct ofpact_controller *controller;
    const struct ofpact_tunnel *tunnel;
    const struct ofpact_inst_actions *inst_actions;
    uint16_t port;

    switch (a->type) {
    case OFPACT_END:
        NOT_REACHED();

    case OFPACT_OUTPUT:
        port = ofpact_get_OUTPUT(a)->port;
        if (port < OFPP_MAX) {
            ds_put_format(s, "output:%"PRIu16, port);
        } else {
            ofputil_format_port(port, s);
            if (port == OFPP_CONTROLLER) {
                ds_put_format(s, ":%"PRIu16, ofpact_get_OUTPUT(a)->max_len);
            }
        }
        break;

    case OFPACT_CONTROLLER:
        controller = ofpact_get_CONTROLLER(a);
        if (controller->reason == OFPR_ACTION &&
            controller->controller_id == 0) {
            ds_put_format(s, "CONTROLLER:%"PRIu16,
                          ofpact_get_CONTROLLER(a)->max_len);
        } else {
            enum ofp_packet_in_reason reason = controller->reason;

            ds_put_cstr(s, "controller(");
            if (reason != OFPR_ACTION) {
                ds_put_format(s, "reason=%s,",
                              ofputil_packet_in_reason_to_string(reason));
            }
            if (controller->max_len != UINT16_MAX) {
                ds_put_format(s, "max_len=%"PRIu16",", controller->max_len);
            }
            if (controller->controller_id != 0) {
                ds_put_format(s, "id=%"PRIu16",", controller->controller_id);
            }
            ds_chomp(s, ',');
            ds_put_char(s, ')');
        }
        break;

    case OFPACT_ENQUEUE:
        enqueue = ofpact_get_ENQUEUE(a);
        ds_put_format(s, "enqueue:");
        ofputil_format_port(enqueue->port, s);
        ds_put_format(s, "q%"PRIu32, enqueue->queue);
        break;

    case OFPACT_OUTPUT_REG:
        ds_put_cstr(s, "output:");
        mf_format_subfield(&ofpact_get_OUTPUT_REG(a)->src, s);
        break;

    case OFPACT_BUNDLE:
        bundle_format(ofpact_get_BUNDLE(a), s);
        break;

    case OFPACT_SET_VLAN_VID:
        ds_put_format(s, "mod_vlan_vid:%"PRIu16,
                      ofpact_get_SET_VLAN_VID(a)->vlan_vid);
        break;

    case OFPACT_SET_VLAN_PCP:
        ds_put_format(s, "mod_vlan_pcp:%"PRIu8,
                      ofpact_get_SET_VLAN_PCP(a)->vlan_pcp);
        break;

    case OFPACT_STRIP_VLAN:
        ds_put_cstr(s, "strip_vlan");
        break;

    case OFPACT_SET_ETH_SRC:
        ds_put_format(s, "mod_dl_src:"ETH_ADDR_FMT,
                      ETH_ADDR_ARGS(ofpact_get_SET_ETH_SRC(a)->mac));
        break;

    case OFPACT_SET_ETH_DST:
        ds_put_format(s, "mod_dl_dst:"ETH_ADDR_FMT,
                      ETH_ADDR_ARGS(ofpact_get_SET_ETH_DST(a)->mac));
        break;

    case OFPACT_SET_IPV4_SRC:
        ds_put_format(s, "mod_nw_src:"IP_FMT,
                      IP_ARGS(&ofpact_get_SET_IPV4_SRC(a)->ipv4));
        break;

    case OFPACT_SET_IPV4_DST:
        ds_put_format(s, "mod_nw_dst:"IP_FMT,
                      IP_ARGS(&ofpact_get_SET_IPV4_DST(a)->ipv4));
        break;

    case OFPACT_SET_IPV4_DSCP:
        ds_put_format(s, "mod_nw_tos:%d", ofpact_get_SET_IPV4_DSCP(a)->dscp);
        break;

    case OFPACT_SET_L4_SRC_PORT:
        ds_put_format(s, "mod_tp_src:%d", ofpact_get_SET_L4_SRC_PORT(a)->port);
        break;

    case OFPACT_SET_L4_DST_PORT:
        ds_put_format(s, "mod_tp_dst:%d", ofpact_get_SET_L4_DST_PORT(a)->port);
        break;

    case OFPACT_REG_MOVE:
        nxm_format_reg_move(ofpact_get_REG_MOVE(a), s);
        break;

    case OFPACT_REG_LOAD:
        nxm_format_reg_load(ofpact_get_REG_LOAD(a), s);
        break;

    case OFPACT_DEC_TTL:
        ds_put_cstr(s, "dec_ttl");
        break;

    case OFPACT_SET_TUNNEL:
        tunnel = ofpact_get_SET_TUNNEL(a);
        ds_put_format(s, "set_tunnel%s:%#"PRIx64,
                      (tunnel->tun_id > UINT32_MAX
                       || a->compat == OFPUTIL_NXAST_SET_TUNNEL64 ? "64" : ""),
                      tunnel->tun_id);
        break;

    case OFPACT_SET_QUEUE:
        ds_put_format(s, "set_queue:%"PRIu32,
                      ofpact_get_SET_QUEUE(a)->queue_id);
        break;

    case OFPACT_POP_QUEUE:
        ds_put_cstr(s, "pop_queue");
        break;

    case OFPACT_FIN_TIMEOUT:
        print_fin_timeout(ofpact_get_FIN_TIMEOUT(a), s);
        break;

    case OFPACT_RESUBMIT:
        resubmit = ofpact_get_RESUBMIT(a);
        if (resubmit->ofpact.compat == OFPUTIL_OFPIT11_GOTO_TABLE) {
            ds_put_format(s, "goto_table:%"PRIu8, resubmit->table_id);
        } else if (resubmit->in_port != OFPP_IN_PORT &&
                   resubmit->table_id == 255) {
            ds_put_format(s, "resubmit:%"PRIu16, resubmit->in_port);
        } else {
            ds_put_format(s, "resubmit(");
            if (resubmit->in_port != OFPP_IN_PORT) {
                ofputil_format_port(resubmit->in_port, s);
            }
            ds_put_char(s, ',');
            if (resubmit->table_id != 255) {
                ds_put_format(s, "%"PRIu8, resubmit->table_id);
            }
            ds_put_char(s, ')');
        }
        break;

    case OFPACT_LEARN:
        learn_format(ofpact_get_LEARN(a), s);
        break;

    case OFPACT_MULTIPATH:
        multipath_format(ofpact_get_MULTIPATH(a), s);
        break;

    case OFPACT_AUTOPATH:
        autopath = ofpact_get_AUTOPATH(a);
        ds_put_format(s, "autopath(%u,", autopath->port);
        mf_format_subfield(&autopath->dst, s);
        ds_put_char(s, ')');
        break;

    case OFPACT_NOTE:
        print_note(ofpact_get_NOTE(a), s);
        break;

    case OFPACT_EXIT:
        ds_put_cstr(s, "exit");
        break;

    case OFPACT_COPY_TTL_OUT:
        ds_put_cstr(s, "copy_ttl_out");
        break;

    case OFPACT_COPY_TTL_IN:
        ds_put_cstr(s, "copy_ttl_in");
        break;

    case OFPACT_SET_MPLS_LABEL:
        ds_put_format(s, "set_mpls_label:%"PRIu32,
                      ntohl(ofpact_get_SET_MPLS_LABEL(a)->mpls_label));
        break;

    case OFPACT_SET_MPLS_TC:
        ds_put_format(s, "set_mpls_tc:%"PRIu8,
                      ofpact_get_SET_MPLS_TC(a)->mpls_tc);
        break;

    case OFPACT_SET_MPLS_TTL:
        ds_put_format(s, "set_mpls_ttl:%"PRIu8,
                      ofpact_get_SET_MPLS_TTL(a)->mpls_ttl);
        break;

    case OFPACT_DEC_MPLS_TTL:
        ds_put_cstr(s, "dec_mpls_ttl");
        break;

    case OFPACT_PUSH_MPLS:
        ds_put_format(s, "push_mpls:0x%"PRIx16,
                      ntohs(ofpact_get_PUSH_MPLS(a)->ethertype));
        break;

    case OFPACT_POP_MPLS:
        ds_put_format(s, "pop_mpls:0x%"PRIx16,
                      ntohs(ofpact_get_POP_MPLS(a)->ethertype));
        break;

    case OFPACT_PUSH_VLAN:
        ds_put_format(s, "push_vlan:0x%"PRIx16,
                      ntohs(ofpact_get_PUSH_VLAN(a)->tpid));
        break;

    case OFPACT_POP_VLAN:
        ds_put_format(s, "pop_vlan");
        break;

    case OFPACT_APPLY_ACTIONS:
        ds_put_cstr(s, "apply_actions(");
        inst_actions = ofpact_get_APPLY_ACTIONS(a);
        ofpacts_format__(inst_actions->ofpacts, s);
        ds_put_cstr(s, ")");
        break;

    case OFPACT_CLEAR_ACTIONS:
        ds_put_cstr(s, "clear_actions");
        break;

    case OFPACT_WRITE_ACTIONS:
        ds_put_cstr(s, "write_actions(");
        inst_actions = ofpact_get_WRITE_ACTIONS(a);
        ofpacts_format__(inst_actions->ofpacts, s);
        ds_put_cstr(s, ")");
        break;
    }
}

bool
ofpact_is_instruction(const struct ofpact *a)
{
    return
        a->type == OFPACT_APPLY_ACTIONS ||
        a->type == OFPACT_CLEAR_ACTIONS ||
        a->type == OFPACT_WRITE_ACTIONS ||
        (a->type == OFPACT_RESUBMIT &&
         a->compat == OFPUTIL_OFPIT11_GOTO_TABLE);
    /* TODO:XXX meter, write_metadata */
}

static void
ofpacts_format__(const struct ofpact *ofpacts, struct ds *string)
{
    if (ofpacts->type == OFPACT_END) {
        ds_put_cstr(string, "drop");
    } else {
        const struct ofpact *a;

        OFPACT_FOR_EACH (a, ofpacts) {
            if (a != ofpacts) {
                ds_put_cstr(string, ",");
            }
            ofpact_format(a, string);
        }
    }
}

/* Appends a string representing the actions in 'ofpacts' (terminated by
 * OFPACT_END) to 'string'. */
void
ofpacts_format(const struct ofpact *ofpacts, struct ds *string)
{
    ds_put_cstr(string, "actions=");
    ofpacts_format__(ofpacts, string);
}

/* Internal use by helpers. */

void *
ofpact_put(struct ofpbuf *ofpacts, enum ofpact_type type, size_t len)
{
    struct ofpact *ofpact;
    unsigned int rem;

    rem = ofpacts->size % OFPACT_ALIGNTO;
    if (rem) {
        ofpbuf_put_zeros(ofpacts, OFPACT_ALIGNTO - rem);
    }

    ofpact = ofpacts->l2 = ofpbuf_put_uninit(ofpacts, len);
    ofpact_init(ofpact, type, len);
    return ofpact;
}

void
ofpact_init(struct ofpact *ofpact, enum ofpact_type type, size_t len)
{
    memset(ofpact, 0, len);
    ofpact->type = type;
    ofpact->compat = OFPUTIL_ACTION_INVALID;
    ofpact->len = len;
}

/* Updates 'ofpact->len' to the number of bytes in the tail of 'ofpacts'
 * starting at 'ofpact'.
 *
 * This is the correct way to update a variable-length ofpact's length after
 * adding the variable-length part of the payload.  (See the large comment
 * near the end of ofp-actions.h for more information.) */
void
ofpact_update_len(struct ofpbuf *ofpacts, struct ofpact *ofpact)
{
    assert(ofpact == ofpacts->l2);
    ofpact->len = (char *) ofpbuf_tail(ofpacts) - (char *) ofpact;
}

void
ofpact_nest(struct ofpbuf *ofpacts, const struct ofpact *ofpact)
{
    assert(ofpact == ofpacts->l2);
    assert(ofpacts->l3 == NULL);
    ofpacts->l3 = ofpacts->l2;
}

struct ofpact *
ofpact_unnest(struct ofpbuf *ofpacts)
{
    struct ofpact *ofpact;
    assert(ofpacts->l2 != NULL);
    assert(ofpacts->l3 != NULL);
    assert(ofpacts->l3 < ofpacts->l2);

    ofpact = ofpacts->l3;
    ofpacts->l2 = ofpacts->l3;
    ofpacts->l3 = NULL;
    return ofpact;
}
