/*
 * Copyright (c) 2008, 2009, 2010, 2011, 2012, 2014 Nicira, Inc.
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

#include <errno.h>
#include <getopt.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "command-line.h"
#include "daemon.h"
#include "dirs.h"
#include "openvswitch/dynamic-string.h"
#include "jsonrpc.h"
#include "process.h"
#include "timeval.h"
#include "svec.h"
#include "unixctl.h"
#include "util.h"
#include "openvswitch/vlog.h"

static void usage(void);

/* Parsed command line args. */
struct cmdl_args {
    enum ovs_output_fmt format;
    char *target;
};

static struct cmdl_args *cmdl_args_create(void);
static void cmdl_args_destroy(struct cmdl_args *);
static struct cmdl_args *parse_command_line(int argc, char *argv[]);
static struct jsonrpc *connect_to_target(const char *target);

int
main(int argc, char *argv[])
{
    char *cmd_result, *cmd_error;
    struct jsonrpc *client;
    char *cmd, **cmd_argv;
    struct cmdl_args *args;
    int cmd_argc;
    int error;
    struct svec opt_argv = SVEC_EMPTY_INITIALIZER;

    set_program_name(argv[0]);

    /* Parse command line and connect to target. */
    args = parse_command_line(argc, argv);
    client = connect_to_target(args->target);

    /* Transact options request (if required) and process reply */
    if (args->format != OVS_OUTPUT_FMT_TEXT) {
        svec_add(&opt_argv, "--format");
        svec_add(&opt_argv, ovs_output_fmt_to_string(args->format));
    }
    svec_terminate(&opt_argv);

    if (opt_argv.n > 0) {
        error = unixctl_client_transact(client, "set-options",
                                        opt_argv.n, opt_argv.names,
                                        &cmd_result, &cmd_error);

        if (error) {
            ovs_fatal(error, "%s: transaction error", args->target);
        }

        if (cmd_error) {
            jsonrpc_close(client);
            fputs(cmd_error, stderr);
            ovs_error(0, "%s: server returned an error", args->target);
            exit(2);
        }

        free(cmd_result);
        free(cmd_error);
    }
    svec_destroy(&opt_argv);

    /* Transact command request and process reply. */
    cmd = argv[optind++];
    cmd_argc = argc - optind;
    cmd_argv = cmd_argc ? argv + optind : NULL;
    error = unixctl_client_transact(client, cmd, cmd_argc, cmd_argv,
                                    &cmd_result, &cmd_error);
    if (error) {
        ovs_fatal(error, "%s: transaction error", args->target);
    }

    if (cmd_error) {
        jsonrpc_close(client);
        fputs(cmd_error, stderr);
        ovs_error(0, "%s: server returned an error", args->target);
        exit(2);
    } else if (cmd_result) {
        fputs(cmd_result, stdout);
    } else {
        OVS_NOT_REACHED();
    }

    cmdl_args_destroy(args);
    jsonrpc_close(client);
    free(cmd_result);
    free(cmd_error);
    return 0;
}

static void
usage(void)
{
    printf("\
%s, for querying and controlling Open vSwitch daemon\n\
usage: %s [TARGET] COMMAND [ARG...]\n\
Targets:\n\
  -t, --target=TARGET  pidfile or socket to contact\n\
Common commands:\n\
  list-commands      List commands supported by the target\n\
  version            Print version of the target\n\
  vlog/list          List current logging levels\n\
  vlog/list-pattern  List logging patterns for each destination.\n\
  vlog/set [SPEC]\n\
      Set log levels as detailed in SPEC, which may include:\n\
      A valid module name (all modules, by default)\n\
      'syslog', 'console', 'file' (all destinations, by default))\n\
      'off', 'emer', 'err', 'warn', 'info', or 'dbg' ('dbg', bydefault)\n\
  vlog/reopen        Make the program reopen its log file\n\
Other options:\n\
  --timeout=SECS     wait at most SECS seconds for a response\n\
  -f, --format=FMT   Output format. One of: 'json', or 'text'\n\
                     ('text', by default)\n\
  -h, --help         Print this helpful information\n\
  -V, --version      Display ovs-appctl version information\n",
           program_name, program_name);
    exit(EXIT_SUCCESS);
}

static struct cmdl_args *
cmdl_args_create(void) {
    struct cmdl_args *args = xmalloc(sizeof *args);

    args->format = OVS_OUTPUT_FMT_TEXT;
    args->target = NULL;

    return args;
}

static void
cmdl_args_destroy(struct cmdl_args *args) {
    if (args->target) {
        free(args->target);
    }

    free(args);
}

static struct cmdl_args *
parse_command_line(int argc, char *argv[])
{
    enum {
        OPT_START = UCHAR_MAX + 1,
        VLOG_OPTION_ENUMS
    };
    static const struct option long_options[] = {
        {"target", required_argument, NULL, 't'},
        {"execute", no_argument, NULL, 'e'},
        {"format", required_argument, NULL, 'f'},
        {"help", no_argument, NULL, 'h'},
        {"option", no_argument, NULL, 'o'},
        {"version", no_argument, NULL, 'V'},
        {"timeout", required_argument, NULL, 'T'},
        VLOG_LONG_OPTIONS,
        {NULL, 0, NULL, 0},
    };
    char *short_options_ = ovs_cmdl_long_options_to_short_options(long_options);
    char *short_options = xasprintf("+%s", short_options_);

    struct cmdl_args *args = cmdl_args_create();
    int e_options;
    unsigned int timeout = 0;

    e_options = 0;
    for (;;) {
        int option;

        option = getopt_long(argc, argv, short_options, long_options, NULL);
        if (option == -1) {
            break;
        }
        switch (option) {
        case 't':
            if (args->target) {
                ovs_fatal(0, "-t or --target may be specified only once");
            }
            args->target = xstrdup(optarg);
            break;

        case 'e':
            /* We ignore -e for compatibility.  Older versions specified the
             * command as the argument to -e.  Since the current version takes
             * the command as non-option arguments and we say that -e has no
             * arguments, this just works in the common case. */
            if (e_options++) {
                ovs_fatal(0, "-e or --execute may be speciifed only once");
            }
            break;

        case 'f':
            if (!ovs_output_fmt_from_string(optarg, &args->format)) {
                ovs_fatal(0, "value %s on -f or --format is invalid", optarg);
            }
            break;

        case 'h':
            usage();
            break;

        case 'o':
            ovs_cmdl_print_options(long_options);
            exit(EXIT_SUCCESS);

        case 'T':
            if (!str_to_uint(optarg, 10, &timeout) || !timeout) {
                ovs_fatal(0, "value %s on -T or --timeout is invalid", optarg);
            }
            break;

        case 'V':
            ovs_print_version(0, 0);
            exit(EXIT_SUCCESS);

        VLOG_OPTION_HANDLERS

        case '?':
            exit(EXIT_FAILURE);

        default:
            OVS_NOT_REACHED();
        }
    }
    free(short_options_);
    free(short_options);

    ctl_timeout_setup(timeout);

    if (optind >= argc) {
        ovs_fatal(0, "at least one non-option argument is required "
                  "(use --help for help)");
    }

    if (!args->target) {
        args->target = xstrdup("ovs-vswitchd");
    }
    return args;
}

static struct jsonrpc *
connect_to_target(const char *target)
{
    struct jsonrpc *client;
    char *socket_name;
    int error;

#ifndef _WIN32
    if (target[0] != '/') {
        char *pidfile_name;
        pid_t pid;

        pidfile_name = xasprintf("%s/%s.pid", ovs_rundir(), target);
        pid = read_pidfile(pidfile_name);
        if (pid < 0) {
            ovs_fatal(-pid, "cannot read pidfile \"%s\"", pidfile_name);
        }
        free(pidfile_name);
        socket_name = xasprintf("%s/%s.%ld.ctl",
                                ovs_rundir(), target, (long int) pid);
#else
    /* On windows, if the 'target' contains ':', we make an assumption that
     * it is an absolute path. */
    if (!strchr(target, ':')) {
        socket_name = xasprintf("%s/%s.ctl", ovs_rundir(), target);
#endif
    } else {
        socket_name = xstrdup(target);
    }

    error = unixctl_client_create(socket_name, &client);
    if (error) {
        ovs_fatal(error, "cannot connect to \"%s\"", socket_name);
    }
    free(socket_name);

    return client;
}

