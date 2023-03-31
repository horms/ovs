/* Copyright (c) 2009, 2010, 2017, 2019 Nicira, Inc.
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

#ifndef OVSDB_TRANSACTION_H
#define OVSDB_TRANSACTION_H 1

#include <stdbool.h>
#include "compiler.h"

struct json;
struct ovsdb;
struct ovsdb_schema;
struct ovsdb_table;
struct uuid;

struct ovsdb_txn *ovsdb_txn_create(struct ovsdb *);
void ovsdb_txn_set_txnid(const struct uuid *, struct ovsdb_txn *);
const struct uuid *ovsdb_txn_get_txnid(const struct ovsdb_txn *);
void ovsdb_txn_abort(struct ovsdb_txn *);

bool ovsdb_txn_precheck_prereq(const struct ovsdb *db);
struct ovsdb_error *ovsdb_txn_replay_commit(struct ovsdb_txn *)
    OVS_WARN_UNUSED_RESULT;
struct ovsdb_txn_progress *ovsdb_txn_propose_commit(struct ovsdb_txn *,
                                                    bool durable)
    OVS_WARN_UNUSED_RESULT;
struct ovsdb_error *ovsdb_txn_propose_commit_block(struct ovsdb_txn *,
                                                   bool durable)
    OVS_WARN_UNUSED_RESULT;
void ovsdb_txn_complete(struct ovsdb_txn *);

struct ovsdb_txn_progress *ovsdb_txn_propose_schema_change(
    struct ovsdb *, const struct ovsdb_schema *, const struct json *data);

bool ovsdb_txn_progress_is_complete(const struct ovsdb_txn_progress *);
const struct ovsdb_error *ovsdb_txn_progress_get_error(
    const struct ovsdb_txn_progress *);
void ovsdb_txn_progress_destroy(struct ovsdb_txn_progress *);

struct ovsdb_row *ovsdb_txn_row_modify(struct ovsdb_txn *,
                                       const struct ovsdb_row *);
void ovsdb_txn_row_insert(struct ovsdb_txn *, struct ovsdb_row *);
void ovsdb_txn_row_delete(struct ovsdb_txn *, const struct ovsdb_row *);

bool ovsdb_txn_may_create_row(const struct ovsdb_table *,
                              const struct uuid *row_uuid);

typedef bool ovsdb_txn_row_cb_func(const struct ovsdb_row *old,
                                   const struct ovsdb_row *new,
                                   const unsigned long int *changed,
                                   void *aux);
void ovsdb_txn_for_each_change(const struct ovsdb_txn *,
                               ovsdb_txn_row_cb_func *, void *aux);

void ovsdb_txn_add_comment(struct ovsdb_txn *, const char *);
const char *ovsdb_txn_get_comment(const struct ovsdb_txn *);
void ovsdb_txn_history_run(struct ovsdb *);
void ovsdb_txn_history_init(struct ovsdb *, bool need_txn_history);
void ovsdb_txn_history_destroy(struct ovsdb *);

#endif /* ovsdb/transaction.h */
