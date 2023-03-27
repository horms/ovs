..
      Licensed under the Apache License, Version 2.0 (the "License"); you may
      not use this file except in compliance with the License. You may obtain
      a copy of the License at

          http://www.apache.org/licenses/LICENSE-2.0

      Unless required by applicable law or agreed to in writing, software
      distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
      WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
      License for the specific language governing permissions and limitations
      under the License.

      Convention for heading levels in Open vSwitch documentation:

      =======  Heading 0 (reserved for the title in a document)
      -------  Heading 1
      ~~~~~~~  Heading 2
      +++++++  Heading 3
      '''''''  Heading 4

      Avoid deeper levels because they do not render well.

========================================
Userspace Datapath - Checksum Offloading
========================================

This document explains the internals of Open vSwitch support for checksum
offloading in the userspace datapath.

Design
------

Open vSwitch strives to forward packets as they arrive regardless of whether
the checksum is correct or not. OVS is not responsible for fixing external
checksum issues.

The checksum calculation can be offloaded to the NIC when the packet's checksum
is verified, known to be good, or known to be destined for an interface that
will recalculate the checksum anyways.

In other cases, OVS will update the checksum if packet contents is modified in
a way that would also invalidate the checksum and the checksum status is not
known.

For example, OVS can accept a packet with a corrupted IP checksum, and a flow
rule can change the IP destination address to another address. In that case,
OVS needs to partially recompute the checksum instead of offloading or
calculate all of it again which would fix the existing issue.

The interface (internally referred to as a netdev) can set flags indicating if
the checksum is good or bad. The checksum is considered unverified if no flag
is set.

When packets ingress into the datapath with good checksum, OVS should enable
checksum offload by default. This allows the data path to postpone checksum
updates until the packet egress the data path.

When a packet egress the datapath, the packet flags and the egress interface
flags are verified to make sure all required NIC offload features to send out
the packet are available. If not, the data path will fall back to equivalent
software implementation.


Interface (a.k.a. Netdev)
-------------------------

When the interface initiates, it should set the flags to tell the datapath
which offload features are supported. For example, if the driver supports IP
checksum offloading, then netdev->ol_flags should set the flag
NETDEV_TX_OFFLOAD_IPV4_CKSUM.


Rules
-----

1) OVS should strive to forward all packets regardless of checksum.

2) OVS must not correct a bad packet checksum.

3) Packet with flag DP_PACKET_OL_RX_IP_CKSUM_GOOD means that the IP checksum is
   present in the packet and it is good.

4) Packet with flag DP_PACKET_OL_RX_IP_CKSUM_BAD means that the IP checksum is
   present in the packet and it is bad. Extra care should be taken to not fix
   the packet during data path processing.

5) The ingress packet parser can only set DP_PACKET_OL_TX_IP_CKSUM if the
   packet has DP_PACKET_OL_RX_IP_CKSUM_GOOD to not violate rule #2.

6) Packet with flag DP_PACKET_OL_TX_IPV4 is an IPv4 packet.

7) Packet with flag DP_PACKET_OL_TX_IPV6 is an IPv6 packet.

8) Packet with flag DP_PACKET_OL_TX_IP_CKSUM tells the datapath to skip
   updating the IP checksum if the packet is modified. The IP checksum will be
   calculated by the egress interface if that supports IP checksum offload,
   otherwise the IP checksum will be performed in software before handing over
   the packet to the interface.

9) When there are modifications to the packet that requires a checksum update,
   the datapath needs to remove the DP_PACKET_OL_RX_IP_CKSUM_GOOD flag,
   otherwise the checksum is assumed to be good in the packet.
