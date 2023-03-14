/* Copyright (c) 2009, 2010, 2011, 2012, 2013, 2014, 2016 Nicira, Inc.
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
#include "row.h"
#include "sset.h"
#include "table.h"
#include "ovsdb-util.h"
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(ovsdb_util);

void
ovsdb_util_clear_column(struct ovsdb_row *row, const char *column_name)
{
    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);
    const struct ovsdb_table_schema *schema = row->table->schema;
    const struct ovsdb_column *column;

    column = ovsdb_table_schema_get_column(schema, column_name);
    if (!column) {
        VLOG_DBG_RL(&rl, "Table `%s' has no `%s' column",
                    schema->name, column_name);
        return;
    }

    if (column->type.n_min) {
        if (!VLOG_DROP_DBG(&rl)) {
            char *type_name = ovsdb_type_to_english(&column->type);
            VLOG_DBG("Table `%s' column `%s' has type %s, which requires "
                     "a value, but an attempt was made to clear it",
                     schema->name, column_name, type_name);
            free(type_name);
        }
        return;
    }

    struct ovsdb_datum *datum = &row->fields[column->index];
    if (datum->n) {
        ovsdb_datum_destroy(datum, &column->type);
        ovsdb_datum_init_empty(datum);
    }
}

struct ovsdb_datum *
ovsdb_util_get_datum(struct ovsdb_row *row, const char *column_name,
                    const enum ovsdb_atomic_type key_type,
                    const enum ovsdb_atomic_type value_type,
                    const size_t n_max)
{
    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);
    const struct ovsdb_table_schema *schema = row->table->schema;
    const struct ovsdb_column *column;

    column = ovsdb_table_schema_get_column(schema, column_name);
    if (!column) {
        VLOG_DBG_RL(&rl, "Table `%s' has no `%s' column",
                    schema->name, column_name);
        return NULL;
    }

    if (column->type.key.type != key_type
        || column->type.value.type != value_type
        || column->type.n_max != n_max) {
        if (!VLOG_DROP_DBG(&rl)) {
            char *type_name = ovsdb_type_to_english(&column->type);
            VLOG_DBG("Table `%s' column `%s' has type %s, not expected "
                     "key type %s, value type %s, max elements %"PRIuSIZE".",
                     schema->name, column_name, type_name,
                     ovsdb_atomic_type_to_string(key_type),
                     ovsdb_atomic_type_to_string(value_type),
                     n_max);
            free(type_name);
        }
        return NULL;
    }

    return &row->fields[column->index];
}

/* Read string-string key-values from a map.  Returns the value associated with
 * 'key', if found, or NULL */
const char *
ovsdb_util_read_map_string_column(const struct ovsdb_row *row,
                                  const char *column_name,
                                  const char *key)
{
    const struct ovsdb_datum *datum;
    union ovsdb_atom *atom_key = NULL, *atom_value = NULL;
    size_t i;

    datum = ovsdb_util_get_datum(CONST_CAST(struct ovsdb_row *, row),
                                 column_name, OVSDB_TYPE_STRING,
                                 OVSDB_TYPE_STRING, UINT_MAX);

    if (!datum) {
        return NULL;
    }

    for (i = 0; i < datum->n; i++) {
        atom_key = &datum->keys[i];
        if (!strcmp(atom_key->s->string, key)) {
            atom_value = &datum->values[i];
            break;
        }
    }

    return atom_value ? atom_value->s->string : NULL;
}

/* Read string-uuid key-values from a map.  Returns the row associated with
 * 'key', if found, or NULL */
const struct ovsdb_row *
ovsdb_util_read_map_string_uuid_column(const struct ovsdb_row *row,
                                       const char *column_name,
                                       const char *key)
{
    const struct ovsdb_column *column
        = ovsdb_table_schema_get_column(row->table->schema, column_name);
    if (!column ||
        column->type.key.type != OVSDB_TYPE_STRING ||
        column->type.value.type != OVSDB_TYPE_UUID) {
        return NULL;
    }

    const struct ovsdb_table *ref_table = column->type.value.uuid.refTable;
    if (!ref_table) {
        return NULL;
    }

    const struct ovsdb_datum *datum = &row->fields[column->index];
    for (size_t i = 0; i < datum->n; i++) {
        union ovsdb_atom *atom_key = &datum->keys[i];
        if (!strcmp(atom_key->s->string, key)) {
            const union ovsdb_atom *atom_value = &datum->values[i];
            return ovsdb_table_get_row(ref_table, &atom_value->uuid);
        }
    }
    return NULL;
}

const union ovsdb_atom *
ovsdb_util_read_column(const struct ovsdb_row *row, const char *column_name,
                       enum ovsdb_atomic_type type)
{
    const struct ovsdb_datum *datum;

    datum = ovsdb_util_get_datum(CONST_CAST(struct ovsdb_row *, row),
                                 column_name, type, OVSDB_TYPE_VOID, 1);
    return datum && datum->n ? datum->keys : NULL;
}

bool
ovsdb_util_read_integer_column(const struct ovsdb_row *row,
                               const char *column_name,
                               long long int *integerp)
{
    const union ovsdb_atom *atom;

    atom = ovsdb_util_read_column(row, column_name, OVSDB_TYPE_INTEGER);
    *integerp = atom ? atom->integer : 0;
    return atom != NULL;
}

bool
ovsdb_util_read_string_column(const struct ovsdb_row *row,
                              const char *column_name, const char **stringp)
{
    const union ovsdb_atom *atom;

    atom = ovsdb_util_read_column(row, column_name, OVSDB_TYPE_STRING);
    *stringp = atom ? atom->s->string : NULL;
    return atom != NULL;
}

bool
ovsdb_util_read_bool_column(const struct ovsdb_row *row,
                            const char *column_name, bool *boolp)
{
    const union ovsdb_atom *atom;

    atom = ovsdb_util_read_column(row, column_name, OVSDB_TYPE_BOOLEAN);
    *boolp = atom ? atom->boolean : false;
    return atom != NULL;
}

bool
ovsdb_util_read_uuid_column(const struct ovsdb_row *row,
                            const char *column_name, struct uuid *uuid)
{
    const union ovsdb_atom *atom;

    atom = ovsdb_util_read_column(row, column_name, OVSDB_TYPE_UUID);
    *uuid = atom ? atom->uuid : UUID_ZERO;
    return atom != NULL;
}

static void
ovsdb_util_write_singleton(struct ovsdb_row *row, const char *column_name,
                           const union ovsdb_atom *atom,
                           enum ovsdb_atomic_type type)
{
    const struct ovsdb_column *column;
    struct ovsdb_datum *datum;

    column = ovsdb_table_schema_get_column(row->table->schema, column_name);
    datum = ovsdb_util_get_datum(row, column_name, type, OVSDB_TYPE_VOID, 1);
    if (!datum) {
        return;
    }

    ovsdb_datum_unshare(datum, &column->type);

    if (datum->n == 1) {
        if (ovsdb_atom_equals(&datum->keys[0], atom, type)) {
            return;
        }
        ovsdb_atom_destroy(&datum->keys[0], type);
    } else {
        ovsdb_datum_destroy(datum, &column->type);
        datum->n = 1;
        datum->keys = xmalloc(sizeof *datum->keys);
        datum->values = NULL;
        datum->refcnt = NULL;
    }
    ovsdb_atom_clone(&datum->keys[0], atom, type);
}

void
ovsdb_util_write_integer_column(struct ovsdb_row *row,
                                const char *column_name,
                                long long int integer)
{
    const union ovsdb_atom atom = { .integer = integer };
    ovsdb_util_write_singleton(row, column_name, &atom, OVSDB_TYPE_INTEGER);
}

void
ovsdb_util_write_bool_column(struct ovsdb_row *row, const char *column_name,
                             bool value)
{
    const union ovsdb_atom atom = { .boolean = value };
    ovsdb_util_write_singleton(row, column_name, &atom, OVSDB_TYPE_BOOLEAN);
}

void
ovsdb_util_write_uuid_column(struct ovsdb_row *row, const char *column_name,
                             const struct uuid *uuid)
{
    if (uuid) {
        const union ovsdb_atom atom = { .uuid = *uuid };
        ovsdb_util_write_singleton(row, column_name, &atom, OVSDB_TYPE_UUID);
    } else {
        ovsdb_util_clear_column(row, column_name);
    }
}

void
ovsdb_util_write_string_column(struct ovsdb_row *row, const char *column_name,
                               const char *string)
{
    if (string) {
        union ovsdb_atom atom = {
            .s = ovsdb_atom_string_create(CONST_CAST(char *, string)) };
        ovsdb_util_write_singleton(row, column_name, &atom, OVSDB_TYPE_STRING);
        ovsdb_atom_destroy(&atom, OVSDB_TYPE_STRING);
    } else {
        ovsdb_util_clear_column(row, column_name);
    }
}

void
ovsdb_util_write_string_string_column(struct ovsdb_row *row,
                                      const char *column_name,
                                      char **keys, char **values, size_t n)
{
    const struct ovsdb_column *column;
    struct ovsdb_datum *datum;
    size_t i;

    column = ovsdb_table_schema_get_column(row->table->schema, column_name);
    if (!column) {
        VLOG_ERR("No %s column present in the %s table",
                 column_name, row->table->schema->name);
        for (i = 0; i < n; i++) {
            free(keys[i]);
            free(values[i]);
        }
        return;
    }
    datum = ovsdb_util_get_datum(row, column_name, OVSDB_TYPE_STRING,
                                OVSDB_TYPE_STRING, UINT_MAX);
    if (!datum) {
        for (i = 0; i < n; i++) {
            free(keys[i]);
            free(values[i]);
        }
        return;
    }

    /* Free existing data. */
    ovsdb_datum_destroy(datum, &column->type);

    /* Allocate space for new values. */
    datum->n = n;
    datum->keys = xmalloc(n * sizeof *datum->keys);
    datum->values = xmalloc(n * sizeof *datum->values);
    datum->refcnt = NULL;

    for (i = 0; i < n; ++i) {
        datum->keys[i].s = ovsdb_atom_string_create_nocopy(keys[i]);
        datum->values[i].s = ovsdb_atom_string_create_nocopy(values[i]);
    }

    /* Sort and check constraints. */
    ovsdb_datum_sort_assert(datum, &column->type);
}
