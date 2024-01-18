/*
 * Copyright (c) 2008, 2009, 2010, 2011, 2013, 2014 Nicira, Inc.
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
#include "command-line.h"
#include <getopt.h>
#include <limits.h>
#include <stdlib.h>
#include "svec.h"
#include "openvswitch/dynamic-string.h"
#include "ovs-thread.h"
#include "util.h"
#include "openvswitch/vlog.h"
#include "openvswitch/json.h"

VLOG_DEFINE_THIS_MODULE(command_line);

/* Given the GNU-style long options in 'options', returns a string that may be
 * passed to getopt() with the corresponding short options.  The caller is
 * responsible for freeing the string. */
char *
ovs_cmdl_long_options_to_short_options(const struct option options[])
{
    char short_options[UCHAR_MAX * 3 + 1];
    char *p = short_options;

    for (; options->name; options++) {
        const struct option *o = options;
        if (o->flag == NULL && o->val > 0 && o->val <= UCHAR_MAX) {
            *p++ = o->val;
            if (o->has_arg == required_argument) {
                *p++ = ':';
            } else if (o->has_arg == optional_argument) {
                *p++ = ':';
                *p++ = ':';
            }
        }
    }
    *p = '\0';

    return xstrdup(short_options);
}

const char *
ovs_output_fmt_to_string(enum ovs_output_fmt fmt)
{
    switch (fmt) {
    case OVS_OUTPUT_FMT_TEXT:
        return "text";

    case OVS_OUTPUT_FMT_JSON:
        return "json";

    default:
        return NULL;
    }
}

struct json *
ovs_output_fmt_to_json(enum ovs_output_fmt fmt)
{
    const char *string = ovs_output_fmt_to_string(fmt);
    return string ? json_string_create(string) : NULL;
}

bool
ovs_output_fmt_from_string(const char *string, enum ovs_output_fmt *fmt)
{
    if (!strcmp(string, "text")) {
        *fmt = OVS_OUTPUT_FMT_TEXT;
    } else if (!strcmp(string, "json")) {
        *fmt = OVS_OUTPUT_FMT_JSON;
    } else {
        return false;
    }
    return true;
}

static char * OVS_WARN_UNUSED_RESULT
build_short_options(const struct option *long_options)
{
    char *tmp, *short_options;

    tmp = ovs_cmdl_long_options_to_short_options(long_options);
    short_options = xasprintf("+:%s", tmp);
    free(tmp);

    return short_options;
}

static const struct option *
find_option_by_value(const struct option *options, int value)
{
    const struct option *o;

    for (o = options; o->name; o++) {
        if (o->val == value) {
            return o;
        }
    }
    return NULL;
}

/* Parses options set using environment variable.  The caller specifies the
 * supported options in environment variable.  On success, adds the parsed
 * env variables in 'argv', the number of options in 'argc', and returns argv.
 *  */
char **
ovs_cmdl_env_parse_all(int *argcp, char *argv[], const char *env_options)
{
    ovs_assert(*argcp > 0);

    struct svec args = SVEC_EMPTY_INITIALIZER;
    svec_add(&args, argv[0]);
    if (env_options) {
        svec_parse_words(&args, env_options);
    }
    for (int i = 1; i < *argcp; i++) {
        svec_add(&args, argv[i]);
    }
    svec_terminate(&args);

    *argcp = args.n;
    return args.names;
}

/* Parses the command-line options in 'argc' and 'argv'.  The caller specifies
 * the supported options in 'options'.  On success, stores the parsed options
 * in '*pop', the number of options in '*n_pop', and returns NULL.  On failure,
 * returns an error message and zeros the output arguments. */
char * OVS_WARN_UNUSED_RESULT
ovs_cmdl_parse_all(int argc, char *argv[],
                   const struct option *options,
                   struct ovs_cmdl_parsed_option **pop, size_t *n_pop)
{
    /* Count number of options so we can have better assertions later. */
    size_t n_options OVS_UNUSED = 0;
    while (options[n_options].name) {
        n_options++;
    }

    char *short_options = build_short_options(options);

    struct ovs_cmdl_parsed_option *po = NULL;
    size_t allocated_po = 0;
    size_t n_po = 0;

    char *error;

    optind = 0;
    opterr = 0;
    for (;;) {
        int idx = -1;
        int c = getopt_long(argc, argv, short_options, options, &idx);
        switch (c) {
        case -1:
            *pop = po;
            *n_pop = n_po;
            free(short_options);
            return NULL;

        case 0:
            /* getopt_long() processed the option directly by setting a flag
             * variable.  This is probably undesirable for use with this
             * function. */
            OVS_NOT_REACHED();

        case '?':
            if (optopt && find_option_by_value(options, optopt)) {
                error = xasprintf("option '%s' doesn't allow an argument",
                                  argv[optind - 1]);
            } else if (optopt) {
                error = xasprintf("unrecognized option '%c'", optopt);
            } else {
                error = xasprintf("unrecognized option '%s'",
                                  argv[optind - 1]);
            }
            goto error;

        case ':':
            error = xasprintf("option '%s' requires an argument",
                              argv[optind - 1]);
            goto error;

        default:
            if (n_po >= allocated_po) {
                po = x2nrealloc(po, &allocated_po, sizeof *po);
            }
            if (idx == -1) {
                po[n_po].o = find_option_by_value(options, c);
            } else {
                ovs_assert(idx >= 0 && idx < n_options);
                po[n_po].o = &options[idx];
            }
            po[n_po].arg = optarg;
            n_po++;
            break;
        }
    }
    OVS_NOT_REACHED();

error:
    free(po);
    *pop = NULL;
    *n_pop = 0;
    free(short_options);
    return error;
}

/* Given the 'struct ovs_cmdl_command' array, prints the usage of all commands. */
void
ovs_cmdl_print_commands(const struct ovs_cmdl_command commands[])
{
    struct ds ds = DS_EMPTY_INITIALIZER;

    ds_put_cstr(&ds, "The available commands are:\n");
    for (; commands->name; commands++) {
        const struct ovs_cmdl_command *c = commands;
        ds_put_format(&ds, "  %-23s %s\n", c->name, c->usage ? c->usage : "");
    }
    printf("%s", ds.string);
    ds_destroy(&ds);
}

/* Given the GNU-style options in 'options', prints all options. */
void
ovs_cmdl_print_options(const struct option options[])
{
    struct ds ds = DS_EMPTY_INITIALIZER;

    for (; options->name; options++) {
        const struct option *o = options;
        const char *arg = o->has_arg == required_argument ? "ARG" : "[ARG]";

        ds_put_format(&ds, "--%s%s%s\n", o->name, o->has_arg ? "=" : "",
                      o->has_arg ? arg : "");
        if (o->flag == NULL && o->val > 0 && o->val <= UCHAR_MAX) {
            ds_put_format(&ds, "-%c %s\n", o->val, o->has_arg ? arg : "");
        }
    }
    printf("%s", ds.string);
    ds_destroy(&ds);
}

static void
ovs_cmdl_run_command__(struct ovs_cmdl_context *ctx,
                       const struct ovs_cmdl_command commands[],
                       bool read_only)
{
    const struct ovs_cmdl_command *p;

    if (ctx->argc < 1) {
        ovs_fatal(0, "missing command name; use --help for help");
    }

    for (p = commands; p->name != NULL; p++) {
        if (!strcmp(p->name, ctx->argv[0])) {
            int n_arg = ctx->argc - 1;
            if (n_arg < p->min_args) {
                VLOG_FATAL( "'%s' command requires at least %d arguments",
                            p->name, p->min_args);
            } else if (n_arg > p->max_args) {
                VLOG_FATAL("'%s' command takes at most %d arguments",
                           p->name, p->max_args);
            } else {
                if (p->mode == OVS_RW && read_only) {
                    VLOG_FATAL("'%s' command does not work in read only mode",
                               p->name);
                }
                p->handler(ctx);
                if (ferror(stdout)) {
                    VLOG_FATAL("write to stdout failed");
                }
                if (ferror(stderr)) {
                    VLOG_FATAL("write to stderr failed");
                }
                return;
            }
        }
    }

    VLOG_FATAL("unknown command '%s'; use --help for help", ctx->argv[0]);
}

/* Runs the command designated by argv[0] within the command table specified by
 * 'commands', which must be terminated by a command whose 'name' member is a
 * null pointer.
 *
 * Command-line options should be stripped off, so that a typical invocation
 * looks like:
 *    struct ovs_cmdl_context ctx = {
 *        .argc = argc - optind,
 *        .argv = argv + optind,
 *    };
 *    ovs_cmdl_run_command(&ctx, my_commands);
 * */
void
ovs_cmdl_run_command(struct ovs_cmdl_context *ctx,
                     const struct ovs_cmdl_command commands[])
{
    ovs_cmdl_run_command__(ctx, commands, false);
}

void
ovs_cmdl_run_command_read_only(struct ovs_cmdl_context *ctx,
                               const struct ovs_cmdl_command commands[])
{
    ovs_cmdl_run_command__(ctx, commands, true);
}

/* Process title. */

#ifdef __linux__
static struct ovs_mutex proctitle_mutex = OVS_MUTEX_INITIALIZER;

/* Start of command-line arguments in memory. */
static char *argv_start OVS_GUARDED_BY(proctitle_mutex);

/* Number of bytes of command-line arguments. */
static size_t argv_size OVS_GUARDED_BY(proctitle_mutex);

/* Saved command-line arguments. */
static char *saved_proctitle OVS_GUARDED_BY(proctitle_mutex);

/* Prepares the process so that proctitle_set() can later succeed.
 *
 * This modifies the argv[] array so that it no longer points into the memory
 * that it originally does.  Later, proctitle_set() might overwrite that
 * memory.  That means that this function should be called before anything else
 * that accesses the process's argv[] array.  Ideally, it should be called
 * before anything else, period, at the very beginning of program
 * execution.  */
void
ovs_cmdl_proctitle_init(int argc, char **argv)
{
    int i;

    assert_single_threaded();
    if (!argc || !argv[0]) {
        /* This situation should never occur, but... */
        return;
    }

    ovs_mutex_lock(&proctitle_mutex);
    /* Specialized version of first loop iteration below. */
    argv_start = argv[0];
    argv_size = strlen(argv[0]) + 1;
    argv[0] = xstrdup(argv[0]);

    for (i = 1; i < argc; i++) {
        size_t size = strlen(argv[i]) + 1;

        /* Add (argv[i], strlen(argv[i])+1) to (argv_start, argv_size). */
        if (argv[i] + size == argv_start) {
            /* Arguments grow downward in memory. */
            argv_start -= size;
            argv_size += size;
        } else if (argv[i] == argv_start + argv_size) {
            /* Arguments grow upward in memory. */
            argv_size += size;
        } else {
            /* Arguments not contiguous.  (Is this really Linux?) */
        }

        /* Copy out the old argument so we can reuse the space. */
        argv[i] = xstrdup(argv[i]);
    }
    ovs_mutex_unlock(&proctitle_mutex);
}

/* Changes the name of the process, as shown by "ps", to the program name
 * followed by 'format', which is formatted as if by printf(). */
void
ovs_cmdl_proctitle_set(const char *format, ...)
{
    va_list args;
    int n;

    ovs_mutex_lock(&proctitle_mutex);
    if (!argv_start || argv_size < 8) {
        goto out;
    }

    if (!saved_proctitle) {
        saved_proctitle = xmemdup(argv_start, argv_size);
    }

    va_start(args, format);
    n = snprintf(argv_start, argv_size, "%s: ", program_name);
    if (n < argv_size) {
        n += vsnprintf(argv_start + n, argv_size - n, format, args);
    }
    if (n >= argv_size) {
        /* The name is too long, so add an ellipsis at the end. */
        strcpy(&argv_start[argv_size - 4], "...");
    } else {
        /* Fill the extra space with null bytes, so that trailing bytes don't
         * show up in the command line. */
        memset(&argv_start[n], '\0', argv_size - n);
    }
    va_end(args);

out:
    ovs_mutex_unlock(&proctitle_mutex);
}

/* Restores the process's original command line, as seen by "ps". */
void
ovs_cmdl_proctitle_restore(void)
{
    ovs_mutex_lock(&proctitle_mutex);
    if (saved_proctitle) {
        memcpy(argv_start, saved_proctitle, argv_size);
        free(saved_proctitle);
        saved_proctitle = NULL;
    }
    ovs_mutex_unlock(&proctitle_mutex);
}
#else  /* !__linux__ */
/* Stubs that don't do anything on non-Linux systems. */

void
ovs_cmdl_proctitle_init(int argc OVS_UNUSED, char **argv OVS_UNUSED)
{
}

#if !(defined(__FreeBSD__) || defined(__NetBSD__))
/* On these platforms we #define this to setproctitle. */
void
ovs_cmdl_proctitle_set(const char *format OVS_UNUSED, ...)
{
}
#endif

void
ovs_cmdl_proctitle_restore(void)
{
}
#endif  /* !__linux__ */
