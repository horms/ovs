/*
 * Copyright (c) 2009-2012, 2014-2017 Nicira, Inc.
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

#include "openvswitch/json.h"

#include <ctype.h>
#include <errno.h>
#include <float.h>
#include <limits.h>
#include <string.h>

#include "cooperative-multitasking.h"
#include "openvswitch/dynamic-string.h"
#include "hash.h"
#include "json.h"
#include "openvswitch/shash.h"
#include "unicode.h"
#include "util.h"
#include "uuid.h"

/* Non-public JSSF_* flags.  Must not overlap with public ones defined
 * in include/openvswitch/json.h. */
enum {
    JSSF_YIELD = 1 << 7,
};

/* The type of a JSON token. */
enum json_token_type {
    T_EOF = 0,
    T_BEGIN_ARRAY = '[',
    T_END_ARRAY = ']',
    T_BEGIN_OBJECT = '{',
    T_END_OBJECT = '}',
    T_NAME_SEPARATOR = ':',
    T_VALUE_SEPARATOR = ',',
    T_FALSE = UCHAR_MAX + 1,
    T_NULL,
    T_TRUE,
    T_INTEGER,
    T_REAL,
    T_STRING
};

/* A JSON token.
 *
 * RFC 4627 doesn't define a lexical structure for JSON but I believe this to
 * be compliant with the standard.
 */
struct json_token {
    enum json_token_type type;
    union {
        double real;
        long long int integer;
        const char *string;
    };
};

enum json_lex_state {
    JSON_LEX_START,             /* Not inside a token. */
    JSON_LEX_NUMBER,            /* Reading a number. */
    JSON_LEX_KEYWORD,           /* Reading a keyword. */
    JSON_LEX_STRING,            /* Reading a quoted string. */
    JSON_LEX_ESCAPE             /* In a quoted string just after a "\". */
};

enum json_parse_state {
    JSON_PARSE_START,           /* Beginning of input. */
    JSON_PARSE_END,             /* End of input. */

    /* Objects. */
    JSON_PARSE_OBJECT_INIT,     /* Expecting '}' or an object name. */
    JSON_PARSE_OBJECT_NAME,     /* Expecting an object name. */
    JSON_PARSE_OBJECT_COLON,    /* Expecting ':'. */
    JSON_PARSE_OBJECT_VALUE,    /* Expecting an object value. */
    JSON_PARSE_OBJECT_NEXT,     /* Expecting ',' or '}'. */

    /* Arrays. */
    JSON_PARSE_ARRAY_INIT,      /* Expecting ']' or a value. */
    JSON_PARSE_ARRAY_VALUE,     /* Expecting a value. */
    JSON_PARSE_ARRAY_NEXT       /* Expecting ',' or ']'. */
};

struct json_parser_node {
    struct json *json;
};

/* A JSON parser. */
struct json_parser {
    int flags;

    /* Lexical analysis. */
    enum json_lex_state lex_state;
    struct ds buffer;           /* Buffer for accumulating token text. */
    int line_number;
    int column_number;
    int byte_number;

    /* Parsing. */
    enum json_parse_state parse_state;
#define JSON_MAX_HEIGHT 1000
    struct json_parser_node *stack;
    size_t height, allocated_height;
    char *member_name;

    /* Parse status. */
    bool done;
    char *error;                /* Error message, if any, null if none yet. */
};

static struct json *json_create(enum json_type type);
static void json_parser_input(struct json_parser *, struct json_token *);

static void json_error(struct json_parser *p, const char *format, ...)
    OVS_PRINTF_FORMAT(2, 3);

const char *
json_type_to_string(enum json_type type)
{
    switch (type) {
    case JSON_NULL:
        return "null";

    case JSON_FALSE:
        return "false";

    case JSON_TRUE:
        return "true";

    case JSON_OBJECT:
        return "object";

    case JSON_ARRAY:
        return "array";

    case JSON_INTEGER:
    case JSON_REAL:
        return "number";

    case JSON_STRING:
        return "string";

    case JSON_SERIALIZED_OBJECT:
    case JSON_N_TYPES:
    default:
        return "<invalid>";
    }
}

/* Functions for manipulating struct json. */

struct json *
json_null_create(void)
{
    return json_create(JSON_NULL);
}

struct json *
json_boolean_create(bool b)
{
    return json_create(b ? JSON_TRUE : JSON_FALSE);
}

struct json *
json_string_create_nocopy(char *s)
{
    struct json *json = json_create(JSON_STRING);
    json->string = s;
    return json;
}

struct json *
json_string_create(const char *s)
{
    return json_string_create_nocopy(xstrdup(s));
}

struct json *
json_serialized_object_create(const struct json *src)
{
    struct json *json = json_create(JSON_SERIALIZED_OBJECT);
    json->string = json_to_string(src, JSSF_SORT);
    return json;
}

struct json *
json_serialized_object_create_with_yield(const struct json *src)
{
    struct json *json = json_create(JSON_SERIALIZED_OBJECT);
    json->string = json_to_string(src, JSSF_SORT | JSSF_YIELD);
    return json;
}

struct json *
json_array_create_empty(void)
{
    struct json *json = json_create(JSON_ARRAY);
    json->array.elems = NULL;
    json->array.n = 0;
    json->array.n_allocated = 0;
    return json;
}

void
json_array_add(struct json *array_, struct json *element)
{
    struct json_array *array = json_array(array_);
    if (array->n >= array->n_allocated) {
        array->elems = x2nrealloc(array->elems, &array->n_allocated,
                                  sizeof *array->elems);
    }
    array->elems[array->n++] = element;
}

void
json_array_trim(struct json *array_)
{
    struct json_array *array = json_array(array_);
    if (array->n < array->n_allocated){
        array->n_allocated = array->n;
        array->elems = xrealloc(array->elems, array->n * sizeof *array->elems);
    }
}

struct json *
json_array_create(struct json **elements, size_t n)
{
    struct json *json = json_create(JSON_ARRAY);
    json->array.elems = elements;
    json->array.n = n;
    json->array.n_allocated = n;
    return json;
}

struct json *
json_array_create_1(struct json *elem0)
{
    struct json **elems = xmalloc(sizeof *elems);
    elems[0] = elem0;
    return json_array_create(elems, 1);
}

struct json *
json_array_create_2(struct json *elem0, struct json *elem1)
{
    struct json **elems = xmalloc(2 * sizeof *elems);
    elems[0] = elem0;
    elems[1] = elem1;
    return json_array_create(elems, 2);
}

struct json *
json_array_create_3(struct json *elem0, struct json *elem1, struct json *elem2)
{
    struct json **elems = xmalloc(3 * sizeof *elems);
    elems[0] = elem0;
    elems[1] = elem1;
    elems[2] = elem2;
    return json_array_create(elems, 3);
}

bool
json_array_contains_string(const struct json *json, const char *str)
{
    ovs_assert(json->type == JSON_ARRAY);

    for (size_t i = 0; i < json->array.n; i++) {
        const struct json *elem = json->array.elems[i];

        if (elem->type == JSON_STRING && !strcmp(json_string(elem), str)) {
            return true;
        }
    }
    return false;
}

struct json *
json_object_create(void)
{
    struct json *json = json_create(JSON_OBJECT);
    json->object = xmalloc(sizeof *json->object);
    shash_init(json->object);
    return json;
}

struct json *
json_integer_create(long long int integer)
{
    struct json *json = json_create(JSON_INTEGER);
    json->integer = integer;
    return json;
}

struct json *
json_real_create(double real)
{
    struct json *json = json_create(JSON_REAL);
    json->real = real;
    return json;
}

void
json_object_put(struct json *json, const char *name, struct json *value)
{
    json_destroy(shash_replace(json->object, name, value));
}

void
json_object_put_nocopy(struct json *json, char *name, struct json *value)
{
    json_destroy(shash_replace_nocopy(json->object, name, value));
}

void
json_object_put_string(struct json *json, const char *name, const char *value)
{
    json_object_put(json, name, json_string_create(value));
}

void OVS_PRINTF_FORMAT(3, 4)
json_object_put_format(struct json *json,
                       const char *name, const char *format, ...)
{
    va_list args;
    va_start(args, format);
    json_object_put(json, name,
                    json_string_create_nocopy(xvasprintf(format, args)));
    va_end(args);
}

const char *
json_string(const struct json *json)
{
    ovs_assert(json->type == JSON_STRING);
    return json->string;
}

const char *
json_serialized_object(const struct json *json)
{
    ovs_assert(json->type == JSON_SERIALIZED_OBJECT);
    return json->string;
}

struct json_array *
json_array(const struct json *json)
{
    ovs_assert(json->type == JSON_ARRAY);
    return CONST_CAST(struct json_array *, &json->array);
}

struct shash *
json_object(const struct json *json)
{
    ovs_assert(json->type == JSON_OBJECT);
    return CONST_CAST(struct shash *, json->object);
}

bool
json_boolean(const struct json *json)
{
    ovs_assert(json->type == JSON_TRUE || json->type == JSON_FALSE);
    return json->type == JSON_TRUE;
}

double
json_real(const struct json *json)
{
    ovs_assert(json->type == JSON_REAL || json->type == JSON_INTEGER);
    return json->type == JSON_REAL ? json->real : json->integer;
}

int64_t
json_integer(const struct json *json)
{
    ovs_assert(json->type == JSON_INTEGER);
    return json->integer;
}

static void json_destroy_object(struct shash *object, bool yield);
static void json_destroy_array(struct json_array *array, bool yield);

/* Frees 'json' and everything it points to, recursively. */
void
json_destroy__(struct json *json, bool yield)
{
    switch (json->type) {
    case JSON_OBJECT:
        json_destroy_object(json->object, yield);
        break;

    case JSON_ARRAY:
        json_destroy_array(&json->array, yield);
        break;

    case JSON_STRING:
    case JSON_SERIALIZED_OBJECT:
        free(json->string);
        break;

    case JSON_NULL:
    case JSON_FALSE:
    case JSON_TRUE:
    case JSON_INTEGER:
    case JSON_REAL:
        break;

    case JSON_N_TYPES:
        OVS_NOT_REACHED();
    }
    free(json);
}

static void
json_destroy_object(struct shash *object, bool yield)
{
    struct shash_node *node;

    if (yield) {
        cooperative_multitasking_yield();
    }

    SHASH_FOR_EACH_SAFE (node, object) {
        struct json *value = node->data;

        if (yield) {
            json_destroy_with_yield(value);
        } else {
            json_destroy(value);
        }
        shash_delete(object, node);
    }
    shash_destroy(object);
    free(object);
}

static void
json_destroy_array(struct json_array *array, bool yield)
{
    size_t i;

    if (yield) {
        cooperative_multitasking_yield();
    }

    for (i = 0; i < array->n; i++) {
        if (yield) {
            json_destroy_with_yield(array->elems[i]);
        } else {
            json_destroy(array->elems[i]);
        }
    }
    free(array->elems);
}

static struct json *json_deep_clone_object(const struct shash *object);
static struct json *json_deep_clone_array(const struct json_array *array);

/* Returns a deep copy of 'json'. */
struct json *
json_deep_clone(const struct json *json)
{
    switch (json->type) {
    case JSON_OBJECT:
        return json_deep_clone_object(json->object);

    case JSON_ARRAY:
        return json_deep_clone_array(&json->array);

    case JSON_STRING:
        return json_string_create(json->string);

    case JSON_SERIALIZED_OBJECT:
        return json_serialized_object_create(json);

    case JSON_NULL:
    case JSON_FALSE:
    case JSON_TRUE:
        return json_create(json->type);

    case JSON_INTEGER:
        return json_integer_create(json->integer);

    case JSON_REAL:
        return json_real_create(json->real);

    case JSON_N_TYPES:
    default:
        OVS_NOT_REACHED();
    }
}

struct json *
json_nullable_clone(const struct json *json)
{
    return json ? json_clone(json) : NULL;
}

static struct json *
json_deep_clone_object(const struct shash *object)
{
    struct shash_node *node;
    struct json *json;

    json = json_object_create();
    SHASH_FOR_EACH (node, object) {
        struct json *value = node->data;
        json_object_put(json, node->name, json_deep_clone(value));
    }
    return json;
}

static struct json *
json_deep_clone_array(const struct json_array *array)
{
    struct json **elems;
    size_t i;

    elems = xmalloc(array->n * sizeof *elems);
    for (i = 0; i < array->n; i++) {
        elems[i] = json_deep_clone(array->elems[i]);
    }
    return json_array_create(elems, array->n);
}

static size_t
json_hash_object(const struct shash *object, size_t basis)
{
    const struct shash_node **nodes;
    size_t n, i;

    nodes = shash_sort(object);
    n = shash_count(object);
    for (i = 0; i < n; i++) {
        const struct shash_node *node = nodes[i];
        basis = hash_string(node->name, basis);
        basis = json_hash(node->data, basis);
    }
    free(nodes);
    return basis;
}

static size_t
json_hash_array(const struct json_array *array, size_t basis)
{
    size_t i;

    basis = hash_int(array->n, basis);
    for (i = 0; i < array->n; i++) {
        basis = json_hash(array->elems[i], basis);
    }
    return basis;
}

size_t
json_hash(const struct json *json, size_t basis)
{
    switch (json->type) {
    case JSON_OBJECT:
        return json_hash_object(json->object, basis);

    case JSON_ARRAY:
        return json_hash_array(&json->array, basis);

    case JSON_STRING:
    case JSON_SERIALIZED_OBJECT:
        return hash_string(json->string, basis);

    case JSON_NULL:
    case JSON_FALSE:
    case JSON_TRUE:
        return hash_int(json->type << 8, basis);

    case JSON_INTEGER:
        return hash_int(json->integer, basis);

    case JSON_REAL:
        return hash_double(json->real, basis);

    case JSON_N_TYPES:
    default:
        OVS_NOT_REACHED();
    }
}

static bool
json_equal_object(const struct shash *a, const struct shash *b)
{
    struct shash_node *a_node;

    if (shash_count(a) != shash_count(b)) {
        return false;
    }

    SHASH_FOR_EACH (a_node, a) {
        struct shash_node *b_node = shash_find(b, a_node->name);
        if (!b_node || !json_equal(a_node->data, b_node->data)) {
            return false;
        }
    }

    return true;
}

static bool
json_equal_array(const struct json_array *a, const struct json_array *b)
{
    size_t i;

    if (a->n != b->n) {
        return false;
    }

    for (i = 0; i < a->n; i++) {
        if (!json_equal(a->elems[i], b->elems[i])) {
            return false;
        }
    }

    return true;
}

bool
json_equal(const struct json *a, const struct json *b)
{
    if (a == b) {
        return true;
    } else if (!a || !b) {
        return false;
    } else if (a->type != b->type) {
        return false;
    }

    switch (a->type) {
    case JSON_OBJECT:
        return json_equal_object(a->object, b->object);

    case JSON_ARRAY:
        return json_equal_array(&a->array, &b->array);

    case JSON_STRING:
    case JSON_SERIALIZED_OBJECT:
        return !strcmp(a->string, b->string);

    case JSON_NULL:
    case JSON_FALSE:
    case JSON_TRUE:
        return true;

    case JSON_INTEGER:
        return a->integer == b->integer;

    case JSON_REAL:
        return a->real == b->real;

    case JSON_N_TYPES:
    default:
        OVS_NOT_REACHED();
    }
}

/* Lexical analysis. */

static void
json_lex_keyword(struct json_parser *p)
{
    struct json_token token;
    const char *s;

    s = ds_cstr(&p->buffer);
    if (!strcmp(s, "false")) {
        token.type = T_FALSE;
    } else if (!strcmp(s, "true")) {
        token.type = T_TRUE;
    } else if (!strcmp(s, "null")) {
        token.type = T_NULL;
    } else {
        json_error(p, "invalid keyword '%s'", s);
        return;
    }
    json_parser_input(p, &token);
}

static void
json_lex_number(struct json_parser *p)
{
    const char *cp = ds_cstr(&p->buffer);
    unsigned long long int significand = 0;
    struct json_token token;
    bool imprecise = false;
    bool negative = false;
    int pow10 = 0;

    /* Leading minus sign. */
    if (*cp == '-') {
        negative = true;
        cp++;
    }

    /* At least one integer digit, but 0 may not be used as a leading digit for
     * a longer number. */
    significand = 0;
    if (*cp == '0') {
        cp++;
        if (isdigit((unsigned char) *cp)) {
            json_error(p, "leading zeros not allowed");
            return;
        }
    } else if (isdigit((unsigned char) *cp)) {
        do {
            if (significand <= ULLONG_MAX / 10) {
                significand = significand * 10 + (*cp - '0');
            } else {
                pow10++;
                if (*cp != '0') {
                    imprecise = true;
                }
            }
            cp++;
        } while (isdigit((unsigned char) *cp));
    } else {
        json_error(p, "'-' must be followed by digit");
        return;
    }

    /* Optional fraction. */
    if (*cp == '.') {
        cp++;
        if (!isdigit((unsigned char) *cp)) {
            json_error(p, "decimal point must be followed by digit");
            return;
        }
        do {
            if (significand <= ULLONG_MAX / 10) {
                significand = significand * 10 + (*cp - '0');
                pow10--;
            } else if (*cp != '0') {
                imprecise = true;
            }
            cp++;
        } while (isdigit((unsigned char) *cp));
    }

    /* Optional exponent. */
    if (*cp == 'e' || *cp == 'E') {
        bool negative_exponent = false;
        int exponent;

        cp++;
        if (*cp == '+') {
            cp++;
        } else if (*cp == '-') {
            negative_exponent = true;
            cp++;
        }

        if (!isdigit((unsigned char) *cp)) {
            json_error(p, "exponent must contain at least one digit");
            return;
        }

        exponent = 0;
        do {
            if (exponent >= INT_MAX / 10) {
                goto bad_exponent;
            }
            exponent = exponent * 10 + (*cp - '0');
            cp++;
        } while (isdigit((unsigned char) *cp));

        if (negative_exponent) {
            if (pow10 < INT_MIN + exponent) {
                goto bad_exponent;
            }
            pow10 -= exponent;
        } else {
            if (pow10 > INT_MAX - exponent) {
                goto bad_exponent;
            }
            pow10 += exponent;
        }
    }

    if (*cp != '\0') {
        json_error(p, "syntax error in number");
        return;
    }

    /* Figure out number.
     *
     * We suppress negative zeros as a matter of policy. */
    if (!significand) {
        token.type = T_INTEGER;
        token.integer = 0;
        json_parser_input(p, &token);
        return;
    }

    if (!imprecise) {
        while (pow10 > 0 && significand < ULLONG_MAX / 10) {
            significand *= 10;
            pow10--;
        }
        while (pow10 < 0 && significand % 10 == 0) {
            significand /= 10;
            pow10++;
        }
        if (pow10 == 0
            && significand <= (negative
                               ? (unsigned long long int) LLONG_MAX + 1
                               : LLONG_MAX)) {
            token.type = T_INTEGER;
            token.integer = negative ? -significand : significand;
            json_parser_input(p, &token);
            return;
        }
    }

    token.type = T_REAL;
    if (!str_to_double(ds_cstr(&p->buffer), &token.real)) {
        json_error(p, "number outside valid range");
        return;
    }
    /* Suppress negative zero. */
    if (token.real == 0) {
        token.real = 0;
    }
    json_parser_input(p, &token);
    return;

bad_exponent:
    json_error(p, "exponent outside valid range");
}

static const char *
json_lex_4hex(const char *cp, const char *end, int *valuep)
{
    unsigned int value;
    bool ok;

    if (cp + 4 > end) {
        return "quoted string ends within \\u escape";
    }

    value = hexits_value(cp, 4, &ok);
    if (!ok) {
        return "malformed \\u escape";
    }
    if (!value) {
        return "null bytes not supported in quoted strings";
    }
    *valuep = value;
    return NULL;
}

static const char *
json_lex_unicode(const char *cp, const char *end, struct ds *out)
{
    const char *error;
    int c0, c1;

    error = json_lex_4hex(cp, end, &c0);
    if (error) {
        ds_clear(out);
        ds_put_cstr(out, error);
        return NULL;
    }
    cp += 4;
    if (!uc_is_leading_surrogate(c0)) {
        ds_put_utf8(out, c0);
        return cp;
    }

    if (cp + 2 > end || *cp++ != '\\' || *cp++ != 'u') {
        ds_clear(out);
        ds_put_cstr(out, "malformed escaped surrogate pair");
        return NULL;
    }

    error = json_lex_4hex(cp, end, &c1);
    if (error) {
        ds_clear(out);
        ds_put_cstr(out, error);
        return NULL;
    }
    cp += 4;
    if (!uc_is_trailing_surrogate(c1)) {
        ds_clear(out);
        ds_put_cstr(out, "second half of escaped surrogate pair is not "
                    "trailing surrogate");
        return NULL;
    }

    ds_put_utf8(out, utf16_decode_surrogate_pair(c0, c1));
    return cp;
}

bool
json_string_unescape(const char *in, size_t in_len, char **outp)
{
    const char *end = in + in_len;
    bool ok = false;
    struct ds out;

    ds_init(&out);
    ds_reserve(&out, in_len);
    while (in < end) {
        if (*in == '"') {
            ds_clear(&out);
            ds_put_cstr(&out, "quoted string may not include unescaped \"");
            goto exit;
        }
        if (*in != '\\') {
            ds_put_char(&out, *in++);
            continue;
        }

        in++;
        if (in >= end) {
            /* The JSON parser will never trigger this message, because its
             * lexer will never pass in a string that ends in a single
             * backslash, but json_string_unescape() has other callers that
             * are not as careful.*/
            ds_clear(&out);
            ds_put_cstr(&out, "quoted string may not end with backslash");
            goto exit;
        }
        switch (*in++) {
        case '"': case '\\': case '/':
            ds_put_char(&out, in[-1]);
            break;

        case 'b':
            ds_put_char(&out, '\b');
            break;

        case 'f':
            ds_put_char(&out, '\f');
            break;

        case 'n':
            ds_put_char(&out, '\n');
            break;

        case 'r':
            ds_put_char(&out, '\r');
            break;

        case 't':
            ds_put_char(&out, '\t');
            break;

        case 'u':
            in = json_lex_unicode(in, end, &out);
            if (!in) {
                goto exit;
            }
            break;

        default:
            ds_clear(&out);
            ds_put_format(&out, "bad escape \\%c", in[-1]);
            goto exit;
        }
    }
    ok = true;

exit:
    *outp = ds_cstr(&out);
    return ok;
}

void
json_string_escape(const char *in, struct ds *out)
{
    struct json json = {
        .type = JSON_STRING,
        .string = CONST_CAST(char *, in),
    };
    json_to_ds(&json, 0, out);
}

static void
json_parser_input_string(struct json_parser *p, const char *s)
{
    struct json_token token;

    token.type = T_STRING;
    token.string = s;
    json_parser_input(p, &token);
}

static void
json_lex_string(struct json_parser *p)
{
    const char *raw = ds_cstr(&p->buffer);
    if (!strchr(raw, '\\')) {
        json_parser_input_string(p, raw);
    } else {
        char *cooked;

        if (json_string_unescape(raw, strlen(raw), &cooked)) {
            json_parser_input_string(p, cooked);
        } else {
            json_error(p, "%s", cooked);
        }

        free(cooked);
    }
}


/* Parsing. */

/* Parses 'string' as a JSON object or array and returns a newly allocated
 * 'struct json'.  The caller must free the returned structure with
 * json_destroy() when it is no longer needed.
 *
 * 'string' must be encoded in UTF-8.
 *
 * If 'string' is valid JSON, then the returned 'struct json' will be either an
 * object (JSON_OBJECT) or an array (JSON_ARRAY).
 *
 * If 'string' is not valid JSON, then the returned 'struct json' will be a
 * string (JSON_STRING) that describes the particular error encountered during
 * parsing.  (This is an acceptable means of error reporting because at its top
 * level JSON must be either an object or an array; a bare string is not
 * valid.) */
struct json *
json_from_string(const char *string)
{
    struct json_parser *p = json_parser_create(JSPF_TRAILER);
    json_parser_feed(p, string, strlen(string));
    return json_parser_finish(p);
}

/* Parses data of JSON_SERIALIZED_OBJECT to the real JSON. */
struct json *
json_from_serialized_object(const struct json *json)
{
    ovs_assert(json->type == JSON_SERIALIZED_OBJECT);
    return json_from_string(json->string);
}

/* Reads the file named 'file_name', parses its contents as a JSON object or
 * array, and returns a newly allocated 'struct json'.  The caller must free
 * the returned structure with json_destroy() when it is no longer needed.
 *
 * The file must be encoded in UTF-8.
 *
 * See json_from_string() for return value semantics.
 */
struct json *
json_from_file(const char *file_name)
{
    struct json *json;
    FILE *stream;

    stream = fopen(file_name, "r");
    if (!stream) {
        return json_string_create_nocopy(
            xasprintf("error opening \"%s\": %s", file_name,
                      ovs_strerror(errno)));
    }
    json = json_from_stream(stream);
    fclose(stream);

    return json;
}

/* Parses the contents of 'stream' as a JSON object or array, and returns a
 * newly allocated 'struct json'.  The caller must free the returned structure
 * with json_destroy() when it is no longer needed.
 *
 * The file must be encoded in UTF-8.
 *
 * See json_from_string() for return value semantics.
 */
struct json *
json_from_stream(FILE *stream)
{
    struct json_parser *p;
    struct json *json;

    p = json_parser_create(JSPF_TRAILER);
    for (;;) {
        char buffer[BUFSIZ];
        size_t n;

        n = fread(buffer, 1, sizeof buffer, stream);
        if (!n || json_parser_feed(p, buffer, n) != n) {
            break;
        }
    }
    json = json_parser_finish(p);

    if (ferror(stream)) {
        json_destroy(json);
        json = json_string_create_nocopy(
            xasprintf("error reading JSON stream: %s", ovs_strerror(errno)));
    }

    return json;
}

struct json_parser *
json_parser_create(int flags)
{
    struct json_parser *p = xzalloc(sizeof *p);
    p->flags = flags;
    return p;
}

static inline void ALWAYS_INLINE
json_parser_account_byte(struct json_parser *p, unsigned char c)
{
    p->byte_number++;
    if (OVS_UNLIKELY(c == '\n')) {
        p->column_number = 0;
        p->line_number++;
    } else {
        p->column_number++;
    }
}

size_t
json_parser_feed(struct json_parser *p, const char *input, size_t n)
{
    size_t token_start = 0;
    size_t i;

    for (i = 0; !p->done && i < n; ) {
        bool consumed = true;

        const char *start_p = &input[token_start];
        unsigned char c = input[i];
        struct json_token token;

        switch (p->lex_state) {
        case JSON_LEX_START:
            switch (c) {
            case ' ': case '\t': case '\n': case '\r':
                /* Nothing to do. */
                token_start = i + 1;
                break;

            case 'a': case 'b': case 'c': case 'd': case 'e':
            case 'f': case 'g': case 'h': case 'i': case 'j':
            case 'k': case 'l': case 'm': case 'n': case 'o':
            case 'p': case 'q': case 'r': case 's': case 't':
            case 'u': case 'v': case 'w': case 'x': case 'y':
            case 'z':
                p->lex_state = JSON_LEX_KEYWORD;
                token_start = i;
                break;

            case '[': case '{': case ']': case '}': case ':': case ',':
                token.type = c;
                json_parser_input(p, &token);
                token_start = i + 1;
                break;

            case '-':
            case '0': case '1': case '2': case '3': case '4':
            case '5': case '6': case '7': case '8': case '9':
                p->lex_state = JSON_LEX_NUMBER;
                token_start = i;
                break;

            case '"':
                p->lex_state = JSON_LEX_STRING;
                token_start = i + 1;
                break;

            default:
                if (isprint(c)) {
                    json_error(p, "invalid character '%c'", c);
                } else {
                    json_error(p, "invalid character U+%04x", c);
                }
                break;
            }
            break;

        case JSON_LEX_KEYWORD:
            if (!isalpha((unsigned char) c)) {
                ds_put_buffer(&p->buffer, start_p, i - token_start);
                json_lex_keyword(p);
                consumed = false;
                break;
            }
            break;

        case JSON_LEX_NUMBER:
            if (!strchr(".0123456789eE-+", c)) {
                ds_put_buffer(&p->buffer, start_p, i - token_start);
                json_lex_number(p);
                consumed = false;
                break;
            }
            break;

        case JSON_LEX_STRING:
            if (c == '\\') {
                p->lex_state = JSON_LEX_ESCAPE;
            } else if (c == '"') {
                ds_put_buffer(&p->buffer, start_p, i - token_start);
                json_lex_string(p);
            } else if (c < 0x20) {
                json_error(p, "U+%04X must be escaped in quoted string", c);
            }
            break;

        case JSON_LEX_ESCAPE:
            p->lex_state = JSON_LEX_STRING;
            break;

        default:
            ovs_abort(0, "unexpected lexer state");
        }

        if (consumed) {
            json_parser_account_byte(p, c);
            i++;
        }
    }

    if (!p->done) {
        ds_put_buffer(&p->buffer, &input[token_start], i - token_start);
    }
    return i;
}

bool
json_parser_is_done(const struct json_parser *p)
{
    return p->done;
}

struct json *
json_parser_finish(struct json_parser *p)
{
    struct json *json;

    switch (p->lex_state) {
    case JSON_LEX_START:
        break;

    case JSON_LEX_STRING:
    case JSON_LEX_ESCAPE:
        json_error(p, "unexpected end of input in quoted string");
        break;

    case JSON_LEX_NUMBER:
    case JSON_LEX_KEYWORD:
        json_parser_feed(p, " ", 1);
        break;
    }

    if (p->parse_state == JSON_PARSE_START) {
        json_error(p, "empty input stream");
    } else if (p->parse_state != JSON_PARSE_END) {
        json_error(p, "unexpected end of input");
    }

    if (!p->error) {
        ovs_assert(p->height == 1);
        ovs_assert(p->stack[0].json != NULL);
        json = p->stack[--p->height].json;
    } else {
        json = json_string_create_nocopy(p->error);
        p->error = NULL;
    }

    json_parser_abort(p);

    return json;
}

void
json_parser_abort(struct json_parser *p)
{
    if (p) {
        ds_destroy(&p->buffer);
        if (p->height) {
            json_destroy(p->stack[0].json);
        }
        free(p->stack);
        free(p->member_name);
        free(p->error);
        free(p);
    }
}

static struct json_parser_node *
json_parser_top(struct json_parser *p)
{
    return &p->stack[p->height - 1];
}

static void
json_parser_put_value(struct json_parser *p, struct json *value)
{
    struct json_parser_node *node = json_parser_top(p);
    if (node->json->type == JSON_OBJECT) {
        json_object_put_nocopy(node->json, p->member_name, value);
        p->member_name = NULL;
    } else if (node->json->type == JSON_ARRAY) {
        json_array_add(node->json, value);
    } else {
        OVS_NOT_REACHED();
    }
}

static void
json_parser_push(struct json_parser *p,
                 struct json *new_json, enum json_parse_state new_state)
{
    if (p->height < JSON_MAX_HEIGHT) {
        struct json_parser_node *node;

        if (p->height >= p->allocated_height) {
            p->stack = x2nrealloc(p->stack, &p->allocated_height,
                                  sizeof *p->stack);
        }

        if (p->height > 0) {
            json_parser_put_value(p, new_json);
        }

        node = &p->stack[p->height++];
        node->json = new_json;
        p->parse_state = new_state;
    } else {
        json_destroy(new_json);
        json_error(p, "input exceeds maximum nesting depth %d",
                   JSON_MAX_HEIGHT);
    }
}

static void
json_parser_push_object(struct json_parser *p)
{
    json_parser_push(p, json_object_create(), JSON_PARSE_OBJECT_INIT);
}

static void
json_parser_push_array(struct json_parser *p)
{
    json_parser_push(p, json_array_create_empty(), JSON_PARSE_ARRAY_INIT);
}

static void
json_parse_value(struct json_parser *p, struct json_token *token,
                 enum json_parse_state next_state)
{
    struct json *value;

    switch (token->type) {
    case T_FALSE:
        value = json_boolean_create(false);
        break;

    case T_NULL:
        value = json_null_create();
        break;

    case T_TRUE:
        value = json_boolean_create(true);
        break;

    case '{':
        json_parser_push_object(p);
        return;

    case '[':
        json_parser_push_array(p);
        return;

    case T_INTEGER:
        value = json_integer_create(token->integer);
        break;

    case T_REAL:
        value = json_real_create(token->real);
        break;

    case T_STRING:
        value = json_string_create(token->string);
        break;

    case T_EOF:
    case '}':
    case ']':
    case ':':
    case ',':
    default:
        json_error(p, "syntax error expecting value");
        return;
    }

    json_parser_put_value(p, value);
    p->parse_state = next_state;
}

static void
json_parser_pop(struct json_parser *p)
{
    struct json_parser_node *node;

    /* Conserve memory. */
    node = json_parser_top(p);
    if (node->json->type == JSON_ARRAY) {
        json_array_trim(node->json);
    }

    /* Pop off the top-of-stack. */
    if (p->height == 1) {
        p->parse_state = JSON_PARSE_END;
        if (!(p->flags & JSPF_TRAILER)) {
            p->done = true;
        }
    } else {
        p->height--;
        node = json_parser_top(p);
        if (node->json->type == JSON_ARRAY) {
            p->parse_state = JSON_PARSE_ARRAY_NEXT;
        } else if (node->json->type == JSON_OBJECT) {
            p->parse_state = JSON_PARSE_OBJECT_NEXT;
        } else {
            OVS_NOT_REACHED();
        }
    }
}

static void
json_parser_input(struct json_parser *p, struct json_token *token)
{
    switch (p->parse_state) {
    case JSON_PARSE_START:
        if (token->type == '{') {
            json_parser_push_object(p);
        } else if (token->type == '[') {
            json_parser_push_array(p);
        } else {
            json_error(p, "syntax error at beginning of input");
        }
        break;

    case JSON_PARSE_END:
        json_error(p, "trailing garbage at end of input");
        break;

    case JSON_PARSE_OBJECT_INIT:
        if (token->type == '}') {
            json_parser_pop(p);
            break;
        }
        /* Fall through. */
    case JSON_PARSE_OBJECT_NAME:
        if (token->type == T_STRING) {
            p->member_name = xstrdup(token->string);
            p->parse_state = JSON_PARSE_OBJECT_COLON;
        } else {
            json_error(p, "syntax error parsing object expecting string");
        }
        break;

    case JSON_PARSE_OBJECT_COLON:
        if (token->type == ':') {
            p->parse_state = JSON_PARSE_OBJECT_VALUE;
        } else {
            json_error(p, "syntax error parsing object expecting ':'");
        }
        break;

    case JSON_PARSE_OBJECT_VALUE:
        json_parse_value(p, token, JSON_PARSE_OBJECT_NEXT);
        break;

    case JSON_PARSE_OBJECT_NEXT:
        if (token->type == ',') {
            p->parse_state = JSON_PARSE_OBJECT_NAME;
        } else if (token->type == '}') {
            json_parser_pop(p);
        } else {
            json_error(p, "syntax error expecting '}' or ','");
        }
        break;

    case JSON_PARSE_ARRAY_INIT:
        if (token->type == ']') {
            json_parser_pop(p);
            break;
        }
        /* Fall through. */
    case JSON_PARSE_ARRAY_VALUE:
        json_parse_value(p, token, JSON_PARSE_ARRAY_NEXT);
        break;

    case JSON_PARSE_ARRAY_NEXT:
        if (token->type == ',') {
            p->parse_state = JSON_PARSE_ARRAY_VALUE;
        } else if (token->type == ']') {
            json_parser_pop(p);
        } else {
            json_error(p, "syntax error expecting ']' or ','");
        }
        break;

    default:
        ovs_hard_stop();
    }

    p->lex_state = JSON_LEX_START;
    ds_clear(&p->buffer);
}

static struct json *
json_create(enum json_type type)
{
    struct json *json = xmalloc(sizeof *json);
    json->type = type;
    json->count = 1;
    return json;
}

static void
json_error(struct json_parser *p, const char *format, ...)
{
    if (!p->error) {
        struct ds msg;
        va_list args;

        ds_init(&msg);
        ds_put_format(&msg, "line %d, column %d, byte %d: ",
                      p->line_number, p->column_number, p->byte_number);
        va_start(args, format);
        ds_put_format_valist(&msg, format, args);
        va_end(args);

        p->error = ds_steal_cstr(&msg);

        p->done = true;
    }
}

#define SPACES_PER_LEVEL 2

struct json_serializer {
    struct ds *ds;
    int depth;
    int flags;
};

static void json_serialize(const struct json *, struct json_serializer *);
static void json_serialize_object(const struct shash *object,
                                  struct json_serializer *);
static void json_serialize_array(const struct json_array *,
                                 struct json_serializer *);
static void json_serialize_string(const char *, struct ds *);

/* Converts 'json' to a string in JSON format, encoded in UTF-8, and returns
 * that string.  The caller is responsible for freeing the returned string,
 * with free(), when it is no longer needed.
 *
 * If 'flags' contains JSSF_PRETTY, the output is pretty-printed with each
 * nesting level introducing an additional indentation.  Otherwise, the
 * returned string does not contain any new-line characters.
 *
 * If 'flags' contains JSSF_SORT, members of objects in the output are sorted
 * in bytewise lexicographic order for reproducibility.  Otherwise, members of
 * objects are output in an indeterminate order.
 *
 * The returned string is valid JSON only if 'json' represents an array or an
 * object, since a bare literal does not satisfy the JSON grammar. */
char *
json_to_string(const struct json *json, int flags)
{
    struct ds ds;

    ds_init(&ds);
    json_to_ds(json, flags, &ds);
    return ds_steal_cstr(&ds);
}

/* Same as json_to_string(), but the output is appended to 'ds'. */
void
json_to_ds(const struct json *json, int flags, struct ds *ds)
{
    struct json_serializer s;

    s.ds = ds;
    s.depth = 0;
    s.flags = flags;
    json_serialize(json, &s);
}

static void
json_serialize(const struct json *json, struct json_serializer *s)
{
    struct ds *ds = s->ds;

    switch (json->type) {
    case JSON_NULL:
        ds_put_cstr(ds, "null");
        break;

    case JSON_FALSE:
        ds_put_cstr(ds, "false");
        break;

    case JSON_TRUE:
        ds_put_cstr(ds, "true");
        break;

    case JSON_OBJECT:
        json_serialize_object(json->object, s);
        break;

    case JSON_ARRAY:
        json_serialize_array(&json->array, s);
        break;

    case JSON_INTEGER:
        ds_put_format(ds, "%lld", json->integer);
        break;

    case JSON_REAL:
        ds_put_format(ds, "%.*g", DBL_DIG, json->real);
        break;

    case JSON_STRING:
        json_serialize_string(json->string, ds);
        break;

    case JSON_SERIALIZED_OBJECT:
        ds_put_cstr(ds, json->string);
        break;

    case JSON_N_TYPES:
    default:
        OVS_NOT_REACHED();
    }
}

static void
indent_line(struct json_serializer *s)
{
    if (s->flags & JSSF_PRETTY) {
        ds_put_char(s->ds, '\n');
        ds_put_char_multiple(s->ds, ' ', SPACES_PER_LEVEL * s->depth);
    }
}

static void
json_serialize_object_member(size_t i, const struct shash_node *node,
                             struct json_serializer *s)
{
    struct ds *ds = s->ds;

    if (i) {
        ds_put_char(ds, ',');
        indent_line(s);
    }

    json_serialize_string(node->name, ds);
    ds_put_char(ds, ':');
    if (s->flags & JSSF_PRETTY) {
        ds_put_char(ds, ' ');
    }
    json_serialize(node->data, s);
}

static void
json_serialize_object(const struct shash *object, struct json_serializer *s)
{
    struct ds *ds = s->ds;

    ds_put_char(ds, '{');

    s->depth++;
    indent_line(s);

    if (s->flags & JSSF_YIELD) {
        cooperative_multitasking_yield();
    }

    if (s->flags & JSSF_SORT) {
        const struct shash_node **nodes;
        size_t n, i;

        nodes = shash_sort(object);
        n = shash_count(object);
        for (i = 0; i < n; i++) {
            json_serialize_object_member(i, nodes[i], s);
        }
        free(nodes);
    } else {
        struct shash_node *node;
        size_t i;

        i = 0;
        SHASH_FOR_EACH (node, object) {
            json_serialize_object_member(i++, node, s);
        }
    }

    ds_put_char(ds, '}');
    s->depth--;
}

static void
json_serialize_array(const struct json_array *array, struct json_serializer *s)
{
    struct ds *ds = s->ds;
    size_t i;

    ds_put_char(ds, '[');
    s->depth++;

    if (s->flags & JSSF_YIELD) {
        cooperative_multitasking_yield();
    }

    if (array->n > 0) {
        indent_line(s);

        for (i = 0; i < array->n; i++) {
            if (i) {
                ds_put_char(ds, ',');
                indent_line(s);
            }
            json_serialize(array->elems[i], s);
        }
    }

    s->depth--;
    ds_put_char(ds, ']');
}

static const char *chars_escaping[256] = {
        "\\u0000", "\\u0001", "\\u0002", "\\u0003", "\\u0004", "\\u0005", "\\u0006", "\\u0007",
        "\\b", "\\t", "\\n", "\\u000b", "\\f", "\\r", "\\u000e", "\\u000f",
        "\\u0010", "\\u0011", "\\u0012", "\\u0013", "\\u0014", "\\u0015", "\\u0016", "\\u0017",
        "\\u0018", "\\u0019", "\\u001a", "\\u001b", "\\u001c", "\\u001d", "\\u001e", "\\u001f",
        " ", "!", "\\\"", "#", "$", "%", "&", "'",
        "(", ")", "*", "+", ",", "-", ".", "/",
        "0", "1", "2", "3", "4", "5", "6", "7",
        "8", "9", ":", ";", "<", "=", ">", "?",
        "@", "A", "B", "C", "D", "E", "F", "G",
        "H", "I", "J", "K", "L", "M", "N", "O",
        "P", "Q", "R", "S", "T", "U", "V", "W",
        "X", "Y", "Z", "[", "\\\\", "]", "^", "_",
        "`", "a", "b", "c", "d", "e", "f", "g",
        "h", "i", "j", "k", "l", "m", "n", "o",
        "p", "q", "r", "s", "t", "u", "v", "w",
        "x", "y", "z", "{", "|", "}", "~", "\x7f",
        "\x80", "\x81", "\x82", "\x83", "\x84", "\x85", "\x86", "\x87",
        "\x88", "\x89", "\x8a", "\x8b", "\x8c", "\x8d", "\x8e", "\x8f",
        "\x90", "\x91", "\x92", "\x93", "\x94", "\x95", "\x96", "\x97",
        "\x98", "\x99", "\x9a", "\x9b", "\x9c", "\x9d", "\x9e", "\x9f",
        "\xa0", "\xa1", "\xa2", "\xa3", "\xa4", "\xa5", "\xa6", "\xa7",
        "\xa8", "\xa9", "\xaa", "\xab", "\xac", "\xad", "\xae", "\xaf",
        "\xb0", "\xb1", "\xb2", "\xb3", "\xb4", "\xb5", "\xb6", "\xb7",
        "\xb8", "\xb9", "\xba", "\xbb", "\xbc", "\xbd", "\xbe", "\xbf",
        "\xc0", "\xc1", "\xc2", "\xc3", "\xc4", "\xc5", "\xc6", "\xc7",
        "\xc8", "\xc9", "\xca", "\xcb", "\xcc", "\xcd", "\xce", "\xcf",
        "\xd0", "\xd1", "\xd2", "\xd3", "\xd4", "\xd5", "\xd6", "\xd7",
        "\xd8", "\xd9", "\xda", "\xdb", "\xdc", "\xdd", "\xde", "\xdf",
        "\xe0", "\xe1", "\xe2", "\xe3", "\xe4", "\xe5", "\xe6", "\xe7",
        "\xe8", "\xe9", "\xea", "\xeb", "\xec", "\xed", "\xee", "\xef",
        "\xf0", "\xf1", "\xf2", "\xf3", "\xf4", "\xf5", "\xf6", "\xf7",
        "\xf8", "\xf9", "\xfa", "\xfb", "\xfc", "\xfd", "\xfe", "\xff"
};

static void
json_serialize_string(const char *string, struct ds *ds)
{
    uint8_t c;
    uint8_t c2;
    size_t count;
    const char *escape;
    const char *start;

    ds_put_char(ds, '"');
    count = 0;
    start = string;
    while ((c = *string++) != '\0') {
        if (c >= ' ' && c != '"' && c != '\\') {
            count++;
        } else {
            if (count) {
                ds_put_buffer(ds, start, count);
                count = 0;
            }
            start = string;
            escape = chars_escaping[c];
            while ((c2 = *escape++) != '\0') {
                ds_put_char(ds, c2);
            }
        }
    }
    if (count) {
        ds_put_buffer(ds, start, count);
    }
    ds_put_char(ds, '"');
}
