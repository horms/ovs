# Copyright (c) 2012 Nicira, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import argparse

import ovs.daemon
import ovs.unixctl
import ovs.unixctl.server
import ovs.util

vlog = ovs.vlog.Vlog("test-unixctl")
exiting = False


def unixctl_exit(conn, unused_argv, unused_fmt, aux):
    assert aux == "aux_exit"
    global exiting

    exiting = True
    conn.reply(None)


def unixctl_echo(conn, argv, unused_fmt, aux):
    assert aux == "aux_echo"
    conn.reply(str(argv))


def unixctl_echo_error(conn, argv, unused_fmt, aux):
    assert aux == "aux_echo_error"
    conn.reply_error(str(argv))


def unixctl_log(conn, argv, unused_fmt, unused_aux):
    vlog.info(str(argv[0]))
    conn.reply(None)


def unixctl_block(conn, unused_argv, unused_fmt, unused_aux):
    pass


def main():
    parser = argparse.ArgumentParser(
        description="Open vSwitch unixctl test program for Python")
    parser.add_argument("--unixctl", help="UNIXCTL socket location or 'none'.")

    ovs.daemon.add_args(parser)
    ovs.vlog.add_args(parser)
    args = parser.parse_args()
    ovs.daemon.handle_args(args)
    ovs.vlog.handle_args(args)

    ovs.daemon.daemonize_start()
    error, server = ovs.unixctl.server.UnixctlServer.create(args.unixctl)
    if error:
        ovs.util.ovs_fatal(error, "could not create unixctl server at %s"
                           % args.unixctl, vlog)

    ovs.unixctl.command_register("exit", "", 0, 0, ovs.util.OutputFormat.TEXT,
                                 unixctl_exit, "aux_exit")
    ovs.unixctl.command_register("echo", "[arg ...]", 1, 2,
                                 ovs.util.OutputFormat.TEXT, unixctl_echo,
                                 "aux_echo")
    ovs.unixctl.command_register("log", "[arg ...]", 1, 2,
                                 ovs.util.OutputFormat.TEXT, unixctl_log,
                                 None)
    ovs.unixctl.command_register("echo_error", "[arg ...]", 1, 2,
                                 ovs.util.OutputFormat.TEXT,
                                 unixctl_echo_error, "aux_echo_error")
    ovs.unixctl.command_register("block", "", 0, 0, ovs.util.OutputFormat.TEXT,
                                 unixctl_block, None)
    ovs.daemon.daemonize_complete()

    vlog.info("Entering run loop.")
    poller = ovs.poller.Poller()
    while not exiting:
        server.run()
        server.wait(poller)
        if exiting:
            poller.immediate_wake()
        poller.block()
    server.close()


if __name__ == '__main__':
    main()
