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
import sys

import ovs.daemon
import ovs.unixctl
import ovs.unixctl.client
import ovs.util
import ovs.vlog
from ovs.fatal_signal import signal_alarm


def connect_to_target(target):
    error, str_result = ovs.unixctl.socket_name_from_target(target)
    if error:
        ovs.util.ovs_fatal(error, str_result)
    else:
        socket_name = str_result

    error, client = ovs.unixctl.client.UnixctlClient.create(socket_name)
    if error:
        ovs.util.ovs_fatal(error, "cannot connect to \"%s\"" % socket_name)

    return client


def main():
    parser = argparse.ArgumentParser(description="Python Implementation of"
                                     " ovs-appctl.")
    parser.add_argument("-t", "--target", default="ovs-vswitchd",
                        help="pidfile or socket to contact")

    parser.add_argument("command", metavar="COMMAND",
                        help="Command to run.")
    parser.add_argument("argv", metavar="ARG", nargs="*",
                        help="Arguments to the command.")
    parser.add_argument("-T", "--timeout", metavar="SECS",
                        help="wait at most SECS seconds for a response")
    parser.add_argument("-f", "--format", metavar="FMT",
                        help="Output format.", default="text",
                        choices=[fmt.name.lower()
                                 for fmt in ovs.util.OutputFormat])
    args = parser.parse_args()

    signal_alarm(int(args.timeout) if args.timeout else None)

    ovs.vlog.Vlog.init()
    target = args.target
    format = ovs.util.OutputFormat[args.format.upper()]
    client = connect_to_target(target)

    if format != ovs.util.OutputFormat.TEXT:
        err_no, error, _ = client.transact(
            "set-options", ["--format", args.format])

        if err_no:
            ovs.util.ovs_fatal(err_no, "%s: transaction error" % target)
        elif error is not None:
            sys.stderr.write(error)
            ovs.util.ovs_error(0, "%s: server returned an error" % target)
            sys.exit(2)

    err_no, error, result = client.transact(args.command, args.argv)
    client.close()

    if err_no:
        ovs.util.ovs_fatal(err_no, "%s: transaction error" % target)
    elif error is not None:
        sys.stderr.write(error)
        ovs.util.ovs_error(0, "%s: server returned an error" % target)
        sys.exit(2)
    else:
        assert result is not None
        sys.stdout.write(result)


if __name__ == '__main__':
    main()
