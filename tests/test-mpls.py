# Copyright (c) 2013 Joe Stringer
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
import subprocess
import sys

from collections import defaultdict

MAC_PREFIX = '60667777'
FINAL_ACTION = 'CONTROLLER:65535'

MONITOR_LOG='ofctl_monitor.log'
OVSTEST_COMMANDS={
        'add' : ['ovs-ofctl', 'add-flow', 'br0'],
        'monitor' : ['ovs-ofctl', '-m', 'monitor', 'br0', '65534', '-P', 'nxm',
                     '--detach', '--no-chdir', '--pidfile', '--verbose'],
        'send' : ['ovs-appctl', 'netdev-dummy/receive', 'p1'],
        'stop' : ['ovs-appctl', '-t', 'ovs-ofctl', 'exit'],
        'dump' : ['ovs-ofctl', 'dump-flows', 'br0']}

MPLS_TYPES = [0x8847, 0x8848]
IP_TYPES = [0x0800]
ALL_TYPES = IP_TYPES+MPLS_TYPES

PKT_INDEX_L2 = 0
PKT_INDEX_ETHERTYPE = 1
PKT_INDEX_L2_5 = 2
PKT_INDEX_L3 = 3

EXAMPLE_PKT=['505400000007606666660410','0800','', '4500002c00000000ff063a78' \
        'c0a80001c0a80002005000000000002a0000002a5000271077440000484f47450000']

ETHERTYPE_LEN = 4 # Ethernet ethertype is 2 octets long
ETHADDR_LEN = 12 # Ethernet addresses are 6 octets long
LSE_LEN = 8 # MPLS labels are 4 octets long
LABEL_LEN = 6 # The label is the highest 20 bits
TTL_LEN = 2 # IP and MPLS TTL are both 1 octet long
CSUM_LEN = 2 # IPv4 Checksums are 2 octets long

ETHERTYPE_OFFSET = len(EXAMPLE_PKT[PKT_INDEX_L2])
ETH_SRC_OFFSET = 12
L2_5_OFFSET = ETHERTYPE_OFFSET + len(EXAMPLE_PKT[PKT_INDEX_ETHERTYPE])
L3_OFFSET = L2_5_OFFSET
MPLS_TTL_OFFSET = L2_5_OFFSET + LSE_LEN - TTL_LEN
IP_TTL_OFFSET = L3_OFFSET + 16 # TTL is the 9th octet in an IPv4 packet.
IP_CSUM_OFFSET = L3_OFFSET + 20 # CSUM begins at the 11th octet in IPv4.

class Action():
    '''OpenFlow action.

    Action handles the pre and post conditions of an OpenFlow action and stores
    whether or not it is expected to cause recirculation.
    '''
    def __init__(self, name='', pre=[], post=[], recirculate=1, depth=0):
        self.name = name
        self.pre = pre
        self.post = post
        self.recirculate = recirculate
        self.depth = depth

    def __eq__(self, other):
        if self.name != other.name:
            return False

        test_set = set(self.pre) & set(other.pre)
        if len(self.pre) != len(test_set):
            return False

        test_set = set(self.post) & set(other.post)
        if len(self.post) != len(test_set):
            return False

        if self.recirculate != other.recirculate:
            return False

        return True

    def __ne__(self, other):
        return not self.__eq__(other)

    def __str__(self):
        result = ''
        just = 24
        result = self.name.ljust(just) + str(self.pre).ljust(just) + \
            str(self.post).ljust(just) + str(self.recirculate)
        return result

    def execute(self, packet):
        ethertype = packet[ETHERTYPE_OFFSET:L2_5_OFFSET]

        if 'push' in self.name:
            label = 0
            bottom = 0
            ttl = 0xFF
            if int(ethertype, 16) in IP_TYPES:
                ttl_offset = IP_TTL_OFFSET
                bottom = 1
            else:
                ttl_offset = MPLS_TTL_OFFSET
                label = int(packet[L2_5_OFFSET:L2_5_OFFSET + LABEL_LEN], 16)
                label >>= 4
            ttl = int(packet[ttl_offset:ttl_offset+TTL_LEN], 16)
            lse = lse_str(label, ttl, bottom)
            packet = str_substitute(packet, L2_5_OFFSET, 0, lse)
        elif 'pop' in self.name:
            packet = str_substitute(packet, L2_5_OFFSET, LSE_LEN, '')
        else:
            ttl_offset = 0
            if 'CONTROLLER' not in self.name:
                # Not Controller -> dec_ttl or dec_mpls_ttl
                if 'mpls' in self.name:
                    ttl_offset = MPLS_TTL_OFFSET
                else:
                    # IPv4 TTL
                    ttl_offset = IP_TTL_OFFSET

                    # We can get away with just incrementing the first byte
                    # in the checksum, because we only decrement the TTL.
                    csum = packet[IP_CSUM_OFFSET:IP_CSUM_OFFSET+CSUM_LEN]
                    new_csum = int(csum, 16) + 1
                    packet = str_substitute(packet, IP_CSUM_OFFSET, CSUM_LEN,
                                            hex_str(new_csum, CSUM_LEN))

                new_ttl = int(packet[ttl_offset:ttl_offset+TTL_LEN], 16) - 1
                packet = str_substitute(packet, ttl_offset, TTL_LEN,
                                        hex_str(new_ttl, TTL_LEN))

        if self.depth != 0:
            ethertype = hex_str(self.post[0])
        packet = str_substitute(packet, ETHERTYPE_OFFSET, ETHERTYPE_LEN,
                                ethertype)

        return packet

class ActionList(list):
    '''A list of Action objects.

    ActionList will be used to generate test conditions including the input
    and output packets for the given list of actions.
    '''
    def __init__(self, *args, **kwargs):
        list.__init__(self)
        self.maxdepth = 0
        self.recirculation = 0
        self.types_index = 0
        self.types_map = defaultdict(lambda: ALL_TYPES)

        for action in args:
            self.set_dependencies(action.depth, action.pre, action.post)
            self.append(action)

        if 'actionlist' in kwargs:
            al = kwargs['actionlist']
            self += al[0:len(al)]
            self.maxdepth = al.maxdepth
            self.recirculation = al.recirculation
            self.types_index = al.types_index
            self.types_map = al.types_map.copy()

    def __eq__(self, other):
        if self.maxdepth != other.maxdepth:
            return False
        if self.recirculation != other.recirculation:
            return False
        if self.types_index != other.types_index:
            return False
        if not self.types_map.__eq__(other.types_map):
            return False
        return list.__eq__(self, other)

    def __ne__(self, other):
        return not self.__eq__(other)

    def __str__(self):
        return '\n' + ','.join([a.name for a in self[0:len(self)]]) + '\n' + \
                str(self.types_map) + '\nMax Depth: ' + str(self.maxdepth)

    def format_match(self, addr):
        return 'dl_src=%s,dl_type=0x%s' % (format_mac(addr),
                                         self.base_ethertype())

    def generate_flow(self, index=0):
        addr = MAC_PREFIX + hex_str(index)
        return 'cookie=' + hex(index) + ' ' + self.format_match(addr) + \
               ' actions=' + ','.join([a.name for a in self[:]])

    def base_ethertype(self):
        ethertype = iter(self.types_map[0]).next()
        return hex_str(ethertype)

    def pkt_pre(self):
        result = []
        index = 0
        for index in range(0, self.maxdepth, -1):
            bottom = 0
            if index == self.maxdepth + 1:
                bottom = 1
            result.append(lse_str(-index, bottom=bottom))
        return ''.join(result)

    def generate_in_packet(self, index=0):
        addr = MAC_PREFIX + hex_str(index)
        eth_addrs = str_substitute(EXAMPLE_PKT[PKT_INDEX_L2], ETH_SRC_OFFSET,
                                   ETHADDR_LEN, addr)

        result = EXAMPLE_PKT[:]
        result[PKT_INDEX_L2] = eth_addrs
        result[PKT_INDEX_ETHERTYPE] = self.base_ethertype()
        result[PKT_INDEX_L2_5] = self.pkt_pre()
        return ''.join(result)

    def generate_out_packet(self, in_pkt):
        result = in_pkt[:]
        for act in self[0:len(self)]:
            result = act.execute(result)
        return result

    def set_dependencies(self, direction, pre, post):
        pre_index = self.types_index
        post_index = pre_index + direction

        pre_intersection = set(self.types_map[pre_index]) & set(pre)
        post_intersection = set(self.types_map[post_index]) & set(post)

        # Track the depth and expected protocols after the given action
        self.types_map[pre_index] = pre_intersection
        self.types_map[post_index] = post_intersection
        self.types_index += direction
        if self.types_index < self.maxdepth:
            self.maxdepth = self.types_index

    def check_dependencies(self, direction, pre, post):
        pre_index = self.types_index
        post_index = pre_index + direction

        # Check pre-conditions
        pre_intersection = set(self.types_map[pre_index]) & set(pre)
        if len(pre_intersection) == 0:
            return False

        # Check post-conditions
        post_intersection = set(self.types_map[post_index]) & set(post)
        if direction < 0:
            if len(post_intersection) == 0:
                return False

        return True

    def append(self, action):
        self += [action]
        self.recirculation += action.recirculate

    def try_append(self, action, recirculation):
        '''Only append if the action is valid after all other actions.

        Returns True if the action is appended, False if not.
        '''
        last_action = self[-1]

        if action.recirculate == 0:
            if action.recirculate == last_action.recirculate:
                return False
        elif self.recirculation == recirculation:
            return False

        if self.check_dependencies(action.depth, action.pre, action.post):
            self.set_dependencies(action.depth, action.pre, action.post)
            self.append(action)
            return True

        return False

def construct_base_actions(alist=ActionList()):
    alist.append(Action('dec_mpls_ttl', MPLS_TYPES, MPLS_TYPES, recirculate=0))
    alist.append(Action('dec_ttl', IP_TYPES, IP_TYPES, recirculate=0))

    for t in ALL_TYPES:
        ttype = hex_str(t)
        alist.append(Action('pop_mpls:0x'+ttype, MPLS_TYPES, [t], depth=-1))
        if t in MPLS_TYPES:
            alist.append(Action('push_mpls:0x'+ttype, ALL_TYPES, [t], depth=1))

    return alist

def str_substitute(string, start, length, content):
    return string[:start] + content + string[start+length:]

def hex_str(val, strlen=ETHERTYPE_LEN):
    '''Return a "strlen"-length hex string of the given value'''
    if val < 0:
        val = (2 ** (strlen << 2)) + val
    result = str(hex(val))[2:].rstrip('L')
    return format(val, '0'+str(strlen)+'x')

def lse_str(label, ttl=0xff, bottom=0):
    label &= 0xffffff
    value = label << 12
    value += bottom << 8
    value += ttl
    return hex_str(value, strlen=LSE_LEN)

def insert_char(string, char, c):
    return char.join([string[i:i+c] for i in range(0, len(string), c)])

def insert_spaces(string):
    return insert_char(string, ' ', 2)

def format_mac(mac):
    return insert_char(mac, ':', 2)

def format_packet(packet):
    result = []
    for c in range(0, len(packet), 32):
        byte = c>>1
        line = []
        line.append(hex_str(byte, 8))
        line.append('  ')
        line.append(insert_spaces(packet[c:c+16]))
        if c+16 <= len(packet):
            line.append('-')
            line.append(insert_spaces(packet[c+16:c+32]))
        result.append(''.join(line))
    return '\n'.join(result)

def permutations(base_actions, recirculation):
    '''Generate rules with the given number of recirculations'''
    current = []
    result = []

    for act in base_actions:
        current.append(ActionList(act))

    while len(current) > 0:
        al = current.pop()

        # Include rules that already meet the recirculation criteria.
        if al.recirculation == recirculation:
            result.append(ActionList(actionlist=al))
            result[-1].append(Action(FINAL_ACTION, recirculate=0))

        # Try constructing more complex rules. Not all actions will increase
        # the number of recirculations for the given ActionList.
        for act in base_actions:
            new_list = ActionList(actionlist=al)
            if new_list.try_append(act, recirculation):
                current.append(new_list)

    return result

def error(pre_string, flow, index, in_pkt, expout, output=[]):
    result = [pre_string, '',
            'Flow rule:', flow, '',
            'Input packet:', format_packet(in_pkt), '',
            'Expected output:', '\n'.join(expout), '']

    if len(output) == 0:
        result.append('No output observed.')
    else:
        result.append('Observed output:')
        for line in output:
            result.append(line)
        result.append('')

    diff = min(len(output), len(expout))
    if diff > 0:
        result.append('Difference:')
        for i in range(diff):
            if expout[i] != output[i]:
                result.append('-' + expout[i])
                result.append('+' + output[i])
                result.append('')
    if output == []:
        trail = 'No packet was forwarded to the controller.'
    sys.stderr.write('\n'.join(result))
    sys.exit(1)

def parse_args(args):
    parser = argparse.ArgumentParser(
            description='MPLS recirculation test utility for Python.',
            formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('recirculation', nargs='?', type=int, default=1,
                        help='Number of recirculations in generated rules')
    parser.add_argument('offset', nargs='?', type=int, default=0,
                        help='Begin with this test')
    parser.add_argument('num_tests', nargs='?', type=int, default=50,
                        help='Conduct this number of tests')
    return parser.parse_args(args)

def main(argv):
    args = parse_args(argv[1:])

    # Basic permutations of push/pop mpls, dec mpls/ip ttl, one recirculation
    base_actions = construct_base_actions()
    rules = permutations(base_actions, args.recirculation)

    if args.offset > len(rules):
        sys.stderr.write('offset (%d) is higher than number of rules (%d)' %
                         (args.offset, len(rules)))
        sys.exit(1)
    max_test = min(args.offset+args.num_tests, len(rules))

    for index in range(args.offset, max_test):
        rule = rules[index]
        flow = rule.generate_flow(index)

        add_cmd = OVSTEST_COMMANDS['add'][:]
        add_cmd.append(flow)
        subprocess.check_call(add_cmd)

        in_pkt = rule.generate_in_packet(index)
        out_pkt = rule.generate_out_packet(in_pkt)

        expout = []
        MAX_PACKETS = 3
        for i in range(MAX_PACKETS):
            expout += format_packet(out_pkt).split('\n')

        with open(MONITOR_LOG, 'w+') as log:
            subprocess.check_call(OVSTEST_COMMANDS['monitor'], stderr=log)
            for i in range(MAX_PACKETS):
                command = OVSTEST_COMMANDS['send'][:]
                command.append(in_pkt)
                try:
                    subprocess.check_call(command)
                except subprocess.CalledProcessError as err:
                    error('Failed to send packet to datapath: %s' % (str(err)),
                          flow, index, in_pkt, expout)
            subprocess.check_call(OVSTEST_COMMANDS['stop'])

            log.seek(0)
            output = []
            for line in log:
                if line[0] != '0':
                    continue
                output.append(line.rstrip())

            output_difference = set(expout) ^ set(output)
            if len(output_difference) > 0:
                error('MPLS test case %d failed' % (index), flow, index,
                      in_pkt, expout, output)

if __name__ == '__main__':
    main(sys.argv)
