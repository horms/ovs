/*
 * Copyright (c) 2012 Isaku Yamahata <yamahata at private email ne jp>
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

#include <string.h>

#include "dynamic-string.h"
#include "meta-flow.h"
#include "nx-match.h"
#include "odp-util.h"
#include "ofp-actions.h"
#include "ofpbuf.h"
#include "openflow/openflow.h"
#include "openvswitch/types.h"
#include "set-field.h"

void
set_field_init(struct ofpact_reg_load *load, const struct mf_field *mf)
{
    load->ofpact.compat = OFPUTIL_OFPAT12_SET_FIELD;
    load->dst.field = mf;
    load->dst.ofs = 0;
    load->dst.n_bits = mf->n_bits;
}

enum ofperr
set_field_check(const struct ofpact_reg_load *load,
                const struct flow *flow OVS_UNUSED /* TODO:XXX */)
{
    const struct mf_field *mf = load->dst.field;
    assert(load->ofpact.compat == OFPUTIL_OFPAT12_SET_FIELD);

    if (!mf->oxm_writable) {
        return OFPERR_OFPBAC_BAD_ARGUMENT;
    }
    if (!mf_is_value_valid(mf, &load->value)) {
        return OFPERR_OFPBAC_BAD_ARGUMENT;
    }
#if 0
    /* TODO:XXX mf_are_prereqs_ok() needs enhancement.
     * e.g. push_mpls, set_mpls (push followed by set)
     * the check for set_mpls needs to see not only ethertype of the flow
     * but also if preceding set_mpls exits
     */
    if (flow && !mf_are_prereqs_ok(mf, flow)) {
        return OFPERR_OFPBAC_BAD_ARGUMENT;
    }
#endif

    return 0;
}

enum ofperr
set_field_from_openflow(
    const struct ofp12_action_set_field * oasf, struct ofpbuf *ofpacts)
{
    uint16_t len = ntohs(oasf->len);
    ovs_be32 *p = (ovs_be32*)oasf->field;
    uint32_t oxm_header = ntohl(*p);
    uint8_t oxm_length = NXM_LENGTH(oxm_header);
    struct ofpact_reg_load *load;
    const struct mf_field *mf;
    int i;

    /* ofp12_action_set_field is padded to 64 bits by zero */
    if (len != ROUND_UP(sizeof(*oasf) + oxm_length, 8)) {
        return OFPERR_OFPBAC_BAD_ARGUMENT;
    }
    for (i = sizeof(*oasf) + oxm_length; i < len; i++) {
        if (((const char*)oasf)[i]) {
            return OFPERR_OFPBAC_BAD_ARGUMENT;
        }
    }

    if (NXM_HASMASK(oxm_header)) {
        return OFPERR_OFPBAC_BAD_ARGUMENT;
    }
    mf = mf_from_nxm_header(oxm_header);
    if (!mf || mf->oxm_header == 0) {
        return OFPERR_OFPBAC_BAD_ARGUMENT;
    }
    load = ofpact_put_REG_LOAD(ofpacts);
    set_field_init(load, mf);
    memcpy(&load->value, oasf + 1, mf->n_bytes);

    return nxm_reg_load_check(load, NULL);
}

void
set_field_to_openflow(const struct ofpact_reg_load *load,
                      struct ofpbuf *openflow)
{
    const struct mf_field *mf = load->dst.field;
    struct ofp12_action_set_field *oasf;
    ovs_be32* oxm_header;
    uint16_t len;
    uint16_t roundup;
    assert(load->ofpact.compat == OFPUTIL_OFPAT12_SET_FIELD);

    len = sizeof(*oasf) + mf->n_bytes;
    /* ofp12_action_set_field is padded to align 8 bytes */
    roundup = ROUND_UP(len, 8);

    oasf = ofputil_put_OFPAT12_SET_FIELD(openflow);
    oxm_header = (ovs_be32*)oasf->field;
    *oxm_header = htonl(mf->oxm_header);
    oasf->len = htons(roundup);

    ofpbuf_put(openflow, &load->value, mf->n_bytes);
    ofpbuf_put_zeros(openflow, roundup - len);
}

void
set_field_format(const struct ofpact_reg_load *load, struct ds *s)
{
    const struct mf_field *mf = load->dst.field;
    assert(load->ofpact.compat == OFPUTIL_OFPAT12_SET_FIELD);
    ds_put_format(s, "set_field:");
    mf_format(mf, &load->value, NULL, s);
    ds_put_format(s, "->%s", mf->name);
}

void
set_field_parse(const char *arg, struct ofpbuf *ofpacts)
{
    char *orig = xstrdup(arg);
    struct ofpact_reg_load *load = ofpact_put_REG_LOAD(ofpacts);
    char *value;
    char *delim;
    char *key;
    const struct mf_field *mf;
    const char *error;

    value = orig;
    delim = strstr(orig, "->");
    if (!delim) {
        ovs_fatal(0, "%s: missing `->'", orig);
    }
    if (strlen(delim) <= strlen("->")) {
        ovs_fatal(0, "%s: missing field name following `->'", orig);
    }

    key = delim + strlen("->");
    mf = mf_parse_oxm_name(key);
    if (!mf) {
        ovs_fatal(0, "%s is not valid oxm field name", key);
    }
    if (!mf->oxm_writable) {
        ovs_fatal(0, "%s is not allowed to set", key);
    }

    delim[0] = '\0';
    error = mf_parse_value(mf, value, &load->value);
    if (error) {
        ovs_fatal(0, "%s", error);
    }
    if (!mf_is_value_valid(mf, &load->value)) {
        ovs_fatal(0, "%s is not valid valid for field %s", value, key);
    }
    set_field_init(load, mf);
    free(orig);
}
