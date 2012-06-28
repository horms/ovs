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

#ifndef SET_FIELD_H
#define SET_FIELD_H 1

struct ds;
struct ofpact_reg_load;
struct ofpbuf;

void set_field_init(struct ofpact_reg_load *load, const struct mf_field *mf);
enum ofperr set_field_check(const struct ofpact_reg_load *load,
                            const struct flow *flow);
enum ofperr set_field_from_openflow(const struct ofp12_action_set_field * oasf,
                                    struct ofpbuf *ofpacts);
void set_field_to_openflow(const struct ofpact_reg_load *load,
                           struct ofpbuf *openflow);
void set_field_parse(const char *arg, struct ofpbuf *ofpacts);
void set_field_format(const struct ofpact_reg_load *load, struct ds *s);

#endif /* SET_FIELD_H */
