/* Copyright (c) 2009, 2010, 2011, 2012, 2013, 2016, 2017 Nicira, Inc.
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

#include "file.h"

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

#include "bitmap.h"
#include "column.h"
#include "log.h"
#include "openvswitch/json.h"
#include "lockfile.h"
#include "ovsdb.h"
#include "ovsdb-error.h"
#include "row.h"
#include "socket-util.h"
#include "storage.h"
#include "table.h"
#include "timeval.h"
#include "transaction.h"
#include "unixctl.h"
#include "uuid.h"
#include "util.h"
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(ovsdb_file);

/* A transaction being converted to JSON for writing to a file. */
struct ovsdb_file_txn {
    struct json *json;          /* JSON for the whole transaction. */
    struct json *table_json;    /* JSON for 'table''s transaction. */
    struct ovsdb_table *table;  /* Table described in 'table_json'.  */
};

static void ovsdb_file_txn_init(struct ovsdb_file_txn *);
static void ovsdb_file_txn_add_row(struct ovsdb_file_txn *,
                                   const struct ovsdb_row *old,
                                   const struct ovsdb_row *new,
                                   const unsigned long int *changed,
                                   bool allow_shallow_copies);

/* If set to 'true', file transactions will contain difference between
 * datums of old and new rows and not the whole new datum for the column. */
static bool use_column_diff = true;

static void
ovsdb_file_column_diff_enable(struct unixctl_conn *conn, int argc OVS_UNUSED,
                              const char *argv[] OVS_UNUSED,
                              void *arg OVS_UNUSED)
{
    use_column_diff = true;
    unixctl_command_reply(conn, NULL);
}

void
ovsdb_file_column_diff_disable(void)
{
    if (!use_column_diff) {
        return;
    }
    use_column_diff = false;
    unixctl_command_register("ovsdb/file/column-diff-enable", "",
                             0, 0, ovsdb_file_column_diff_enable, NULL);
}

static struct ovsdb_error *
ovsdb_file_update_row_from_json(struct ovsdb_row *row, bool converting,
                                bool row_contains_diff,
                                const struct json *json)
{
    struct ovsdb_table_schema *schema = row->table->schema;
    struct ovsdb_error *error;
    struct shash_node *node;

    if (json->type != JSON_OBJECT) {
        return ovsdb_syntax_error(json, NULL, "row must be JSON object");
    }

    SHASH_FOR_EACH (node, json_object(json)) {
        const char *column_name = node->name;
        const struct ovsdb_column *column;
        struct ovsdb_datum datum;

        column = ovsdb_table_schema_get_column(schema, column_name);
        if (!column) {
            if (converting) {
                continue;
            }
            return ovsdb_syntax_error(json, "unknown column",
                                      "No column %s in table %s.",
                                      column_name, schema->name);
        }

        error = ovsdb_datum_from_json(&datum, &column->type, node->data, NULL);
        if (error) {
            return error;
        }
        if (row_contains_diff
            && !ovsdb_datum_is_default(&row->fields[column->index],
                                       &column->type)) {
            error = ovsdb_datum_apply_diff_in_place(
                                           &row->fields[column->index],
                                           &datum, &column->type);
            ovsdb_datum_destroy(&datum, &column->type);
            if (error) {
                return error;
            }
        } else {
            ovsdb_datum_swap(&row->fields[column->index], &datum);
            ovsdb_datum_destroy(&datum, &column->type);
        }
    }

    return NULL;
}

static struct ovsdb_error *
ovsdb_file_txn_row_from_json(struct ovsdb_txn *txn, struct ovsdb_table *table,
                             bool converting, bool row_contains_diff,
                             const struct uuid *row_uuid, struct json *json)
{
    const struct ovsdb_row *row = ovsdb_table_get_row(table, row_uuid);
    if (json->type == JSON_NULL) {
        if (!row) {
            return ovsdb_syntax_error(NULL, NULL, "transaction deletes "
                                      "row "UUID_FMT" that does not exist",
                                      UUID_ARGS(row_uuid));
        }
        ovsdb_txn_row_delete(txn, row);
        return NULL;
    } else if (row) {
        return ovsdb_file_update_row_from_json(ovsdb_txn_row_modify(txn, row),
                                               converting, row_contains_diff,
                                               json);
    } else {
        struct ovsdb_error *error;
        struct ovsdb_row *new;

        new = ovsdb_row_create(table);
        *ovsdb_row_get_uuid_rw(new) = *row_uuid;
        error = ovsdb_file_update_row_from_json(new, converting,
                                                row_contains_diff, json);
        if (error) {
            ovsdb_row_destroy(new);
        } else {
            ovsdb_txn_row_insert(txn, new);
        }
        return error;
    }
}

static struct ovsdb_error *
ovsdb_file_txn_table_from_json(struct ovsdb_txn *txn,
                               struct ovsdb_table *table,
                               bool converting,
                               bool row_contains_diff,
                               struct json *json)
{
    struct shash_node *node;

    if (json->type != JSON_OBJECT) {
        return ovsdb_syntax_error(json, NULL, "object expected");
    }

    SHASH_FOR_EACH (node, json->object) {
        const char *uuid_string = node->name;
        struct json *txn_row_json = node->data;
        struct ovsdb_error *error;
        struct uuid row_uuid;

        if (!uuid_from_string(&row_uuid, uuid_string)) {
            return ovsdb_syntax_error(json, NULL, "\"%s\" is not a valid UUID",
                                      uuid_string);
        }

        error = ovsdb_file_txn_row_from_json(txn, table, converting,
                                             row_contains_diff,
                                             &row_uuid, txn_row_json);
        if (error) {
            return error;
        }
    }

    return NULL;
}

/* Converts 'json' to an ovsdb_txn for 'db', storing the new transaction in
 * '*txnp'.  Returns NULL if successful, otherwise an error.
 *
 * If 'converting' is true, then unknown table and column names are ignored
 * (which can ease upgrading and downgrading schemas); otherwise, they are
 * treated as errors. */
struct ovsdb_error *
ovsdb_file_txn_from_json(struct ovsdb *db, const struct json *json,
                         bool converting, struct ovsdb_txn **txnp)
{
    struct ovsdb_error *error;
    struct shash_node *node;
    struct ovsdb_txn *txn;

    *txnp = NULL;

    if (json->type != JSON_OBJECT) {
        return ovsdb_syntax_error(json, NULL, "object expected");
    }

    struct json *is_diff = shash_find_data(json->object, "_is_diff");
    bool row_contains_diff = false;

    if (is_diff && is_diff->type == JSON_TRUE) {
        row_contains_diff = true;
    }

    txn = ovsdb_txn_create(db);
    SHASH_FOR_EACH (node, json->object) {
        const char *table_name = node->name;
        struct json *node_json = node->data;
        struct ovsdb_table *table;

        table = shash_find_data(&db->tables, table_name);
        if (!table) {
            if (!strcmp(table_name, "_date")
                && node_json->type == JSON_INTEGER) {
                continue;
            } else if (!strcmp(table_name, "_is_diff")
                       && (node_json->type == JSON_TRUE
                           || node_json->type == JSON_FALSE)) {
                continue;
            } else if (!strcmp(table_name, "_comment") || converting) {
                continue;
            }

            error = ovsdb_syntax_error(json, "unknown table",
                                       "No table named %s.", table_name);
            goto error;
        }

        error = ovsdb_file_txn_table_from_json(txn, table, converting,
                                               row_contains_diff, node_json);
        if (error) {
            goto error;
        }
    }
    *txnp = txn;
    return NULL;

error:
    ovsdb_txn_abort(txn);
    return error;
}

static struct ovsdb_error * OVS_WARN_UNUSED_RESULT
ovsdb_convert_table(struct ovsdb_txn *txn,
                    const struct ovsdb_table *src_table,
                    struct ovsdb_table *dst_table)
{
    const struct ovsdb_column **dst_columns;
    struct ovsdb_error *error = NULL;
    const struct ovsdb_row *src_row;
    unsigned long *src_equal;
    struct shash_node *node;
    size_t n_src_columns;

    n_src_columns = shash_count(&src_table->schema->columns);
    src_equal = bitmap_allocate(n_src_columns);
    dst_columns = xzalloc(n_src_columns * sizeof *dst_columns);

    SHASH_FOR_EACH (node, &src_table->schema->columns) {
        const struct ovsdb_column *src_column = node->data;

        if (src_column->index == OVSDB_COL_UUID ||
            src_column->index == OVSDB_COL_VERSION) {
            continue;
        }

        const struct ovsdb_column *dst_column =
            shash_find_data(&dst_table->schema->columns, src_column->name);

        if (!dst_column) {
            continue;
        }

        dst_columns[src_column->index] = dst_column;

        if (ovsdb_type_equals(&src_column->type, &dst_column->type)) {
            bitmap_set1(src_equal, src_column->index);
        }
    }

    HMAP_FOR_EACH (src_row, hmap_node, &src_table->rows) {
        struct ovsdb_row *dst_row = ovsdb_row_create(dst_table);
        *ovsdb_row_get_uuid_rw(dst_row) = *ovsdb_row_get_uuid(src_row);

        SHASH_FOR_EACH (node, &src_table->schema->columns) {
            const struct ovsdb_column *src_column = node->data;
            const struct ovsdb_column *dst_column;

            dst_column = dst_columns[src_column->index];
            if (!dst_column) {
                continue;
            }

            ovsdb_datum_destroy(&dst_row->fields[dst_column->index],
                                &dst_column->type);

            if (bitmap_is_set(src_equal, src_column->index)) {
                /* This column didn't change - no need to convert. */
                ovsdb_datum_clone(&dst_row->fields[dst_column->index],
                                  &src_row->fields[src_column->index]);
                continue;
            }

            error = ovsdb_datum_convert(
                &dst_row->fields[dst_column->index], &dst_column->type,
                &src_row->fields[src_column->index], &src_column->type);
            if (error) {
                ovsdb_datum_init_empty(&dst_row->fields[dst_column->index]);
                ovsdb_row_destroy(dst_row);
                goto exit;
            }
        }

        ovsdb_txn_row_insert(txn, dst_row);
    }

exit:
    free(dst_columns);
    bitmap_free(src_equal);
    return error;
}

/* Copies the data in 'src', converts it into the schema specified in
 * 'new_schema', and puts it into a newly created, unbacked database, and
 * stores a pointer to the new database in '*dstp'.  Returns null if
 * successful, otherwise an error; on error, stores NULL in '*dstp'. */
struct ovsdb_error * OVS_WARN_UNUSED_RESULT
ovsdb_convert(const struct ovsdb *src, const struct ovsdb_schema *new_schema,
              struct ovsdb **dstp)
{
    struct ovsdb *dst = ovsdb_create(ovsdb_schema_clone(new_schema),
                                     ovsdb_storage_create_unbacked(NULL));
    struct ovsdb_txn *txn = ovsdb_txn_create(dst);
    struct ovsdb_error *error = NULL;

    struct shash_node *node;
    SHASH_FOR_EACH (node, &src->tables) {
        const char *table_name = node->name;
        struct ovsdb_table *src_table = node->data;
        struct ovsdb_table *dst_table = shash_find_data(&dst->tables,
                                                        table_name);
        if (!dst_table) {
            continue;
        }

        error = ovsdb_convert_table(txn, src_table, dst_table);
        if (error) {
            goto error;
        }
    }

    error = ovsdb_txn_replay_commit(txn);
    if (error) {
        txn = NULL;            /* ovsdb_txn_replay_commit() already aborted. */
        goto error;
    }

    *dstp = dst;
    return NULL;

error:
    ovsdb_destroy(dst);
    if (txn) {
        ovsdb_txn_abort(txn);
    }
    *dstp = NULL;
    return error;
}

static bool
ovsdb_file_change_cb(const struct ovsdb_row *old,
                     const struct ovsdb_row *new,
                     const unsigned long int *changed,
                     void *ftxn_)
{
    struct ovsdb_file_txn *ftxn = ftxn_;
    ovsdb_file_txn_add_row(ftxn, old, new, changed, true);
    return true;
}

/* Converts the database into transaction JSON representation.
 * If 'allow_shallow_copies' is false, makes sure that all the JSON
 * objects in the resulted transaction JSON are separately allocated
 * objects and not shallow clones of JSON objects already existing
 * in the database.  Useful when multiple threads are working on the
 * same database object. */
struct json *
ovsdb_to_txn_json(const struct ovsdb *db, const char *comment,
                  bool allow_shallow_copies)
{
    struct ovsdb_file_txn ftxn;

    ovsdb_file_txn_init(&ftxn);

    struct shash_node *node;
    SHASH_FOR_EACH (node, &db->tables) {
        const struct ovsdb_table *table = node->data;
        const struct ovsdb_row *row;

        HMAP_FOR_EACH (row, hmap_node, &table->rows) {
            ovsdb_file_txn_add_row(&ftxn, NULL, row, NULL,
                                   allow_shallow_copies);
        }
    }

    return ovsdb_file_txn_annotate(ftxn.json, comment);
}

/* Returns 'txn' transformed into the JSON format that is used in OVSDB files.
 * (But the caller must use ovsdb_file_txn_annotate() to add the _comment and
 * _date members.)  If 'txn' doesn't actually change anything, returns NULL */
struct json *
ovsdb_file_txn_to_json(const struct ovsdb_txn *txn)
{
    struct ovsdb_file_txn ftxn;

    ovsdb_file_txn_init(&ftxn);
    ovsdb_txn_for_each_change(txn, ovsdb_file_change_cb, &ftxn);
    return ftxn.json;
}

struct json *
ovsdb_file_txn_annotate(struct json *json, const char *comment)
{
    if (!json) {
        json = json_object_create();
    }
    if (comment) {
        json_object_put_string(json, "_comment", comment);
    }
    if (use_column_diff) {
        json_object_put(json, "_is_diff", json_boolean_create(true));
    }
    json_object_put(json, "_date", json_integer_create(time_wall_msec()));
    return json;
}

static void
ovsdb_file_txn_init(struct ovsdb_file_txn *ftxn)
{
    ftxn->json = NULL;
    ftxn->table_json = NULL;
    ftxn->table = NULL;
}

static void
ovsdb_file_txn_add_row(struct ovsdb_file_txn *ftxn,
                       const struct ovsdb_row *old,
                       const struct ovsdb_row *new,
                       const unsigned long int *changed,
                       bool allow_shallow_copies)
{
    struct json *row;

    if (!new) {
        row = json_null_create();
    } else {
        struct shash_node *node;

        row = old ? NULL : json_object_create();
        SHASH_FOR_EACH (node, &new->table->schema->columns) {
            const struct ovsdb_column *column = node->data;
            const struct ovsdb_type *type = &column->type;
            unsigned int idx = column->index;
            struct ovsdb_datum datum;
            struct json *column_json;

            if (idx != OVSDB_COL_UUID && column->persistent
                && (old
                    ? bitmap_is_set(changed, idx)
                    : !ovsdb_datum_is_default(&new->fields[idx], type)))
            {
                if (old && use_column_diff) {
                    ovsdb_datum_diff(&datum, &old->fields[idx],
                                     &new->fields[idx], type);
                    if (allow_shallow_copies) {
                        column_json = ovsdb_datum_to_json(&datum, type);
                    } else {
                        column_json = ovsdb_datum_to_json_deep(&datum, type);
                    }
                    ovsdb_datum_destroy(&datum, type);
                } else {
                    if (allow_shallow_copies) {
                        column_json = ovsdb_datum_to_json(
                                            &new->fields[idx], type);
                    } else {
                        column_json = ovsdb_datum_to_json_deep(
                                            &new->fields[idx], type);
                    }
                }
                if (!row) {
                    row = json_object_create();
                }
                json_object_put(row, column->name, column_json);
            }
        }
    }

    if (row) {
        struct ovsdb_table *table = NULL;
        if (new) {
            table = new->table;
        } else if (old) {
            table = old->table;
        }
        char uuid[UUID_LEN + 1];

        if (table != ftxn->table) {
            /* Create JSON object for transaction overall. */
            if (!ftxn->json) {
                ftxn->json = json_object_create();
            }

            /* Create JSON object for transaction on this table. */
            ftxn->table_json = json_object_create();
            if (table) {
                ftxn->table = table;
                json_object_put(ftxn->json, table->schema->name,
                                ftxn->table_json);
            }
        }

        /* Add row to transaction for this table. */
        if (new) {
            snprintf(uuid, sizeof uuid,
                     UUID_FMT, UUID_ARGS(ovsdb_row_get_uuid(new)));
            json_object_put(ftxn->table_json, uuid, row);
        } else if (old) {
            snprintf(uuid, sizeof uuid,
                     UUID_FMT, UUID_ARGS(ovsdb_row_get_uuid(old)));
            json_object_put(ftxn->table_json, uuid, row);
        }
    }
}

static struct ovsdb *
ovsdb_file_read__(const char *filename, bool rw,
                  struct ovsdb_schema *new_schema)
{
    struct ovsdb_storage *storage = ovsdb_storage_open_standalone(filename,
                                                                  rw);
    struct ovsdb_schema *schema = ovsdb_storage_read_schema(storage);
    if (new_schema) {
        ovsdb_schema_destroy(schema);
        schema = new_schema;
    }
    struct ovsdb *ovsdb = ovsdb_create(schema, storage);
    for (;;) {
        /* Read a transaction.  Bail if end-of-file. */
        struct json *txn_json;
        struct ovsdb_schema *schema2;
        struct ovsdb_error *error = ovsdb_storage_read(storage, &schema2,
                                                       &txn_json, NULL);
        if (error) {
            ovs_fatal(0, "%s", ovsdb_error_to_string_free(error));
        }
        ovs_assert(!schema2);
        if (!txn_json) {
            break;
        }

        /* Apply transaction to database. */
        struct ovsdb_txn *txn;
        error = ovsdb_file_txn_from_json(ovsdb, txn_json, new_schema != NULL,
                                         &txn);
        if (error) {
            ovs_fatal(0, "%s", ovsdb_error_to_string_free(error));
        }
        json_destroy(txn_json);

        error = ovsdb_txn_replay_commit(txn);
        if (error) {
            ovsdb_error_destroy(error);
            ovsdb_storage_unread(storage);
            break;
        }
    }
    return ovsdb;
}

/* Reads 'filename' as a standalone database.  Returns the new database.  On
 * error, prints a message on stderr and terminates the process.
 *
 * If 'rw' is true, opens the database for read/write access, otherwise
 * read-only.
 *
 * Consumes 'schema'. */
struct ovsdb *
ovsdb_file_read(const char *filename, bool rw)
{
    return ovsdb_file_read__(filename, rw, NULL);
}

/* Reads 'filename' as a standalone database, using 'schema' in place of the
 * schema embedded in the file.  Returns the new database.  On error,
 * prints a message on stderr and terminates the process.
 *
 * Consumes 'schema'. */
struct ovsdb *
ovsdb_file_read_as_schema(const char *filename, struct ovsdb_schema *schema)
{
    return ovsdb_file_read__(filename, false, schema);
}
