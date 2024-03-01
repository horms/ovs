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

=========================================
Integration Guide for Centralized Control
=========================================

This document describes how to integrate Open vSwitch onto a new platform to
expose the state of the switch and attached devices for centralized control.
(If you are looking to port the switching components of Open vSwitch to a new
platform, refer to :doc:`porting`)  The focus of this guide is on hypervisors,
but many of the interfaces are useful for hardware switches, as well.

The externally visible interface to this integration is platform-agnostic.  We
encourage anyone who integrates Open vSwitch to use the same interface, because
keeping a uniform interface means that controllers require less customization
for individual platforms (and perhaps no customization at all).

Integration centers around the Open vSwitch database and mostly involves the
``external_ids`` columns in several of the tables.  These columns are not
interpreted by Open vSwitch itself.  Instead, they provide information to a
controller that permits it to associate a database record with a more
meaningful entity.  In contrast, the ``other_config`` column is used to
configure behavior of the switch.  The main job of the integrator, then, is to
ensure that these values are correctly populated and maintained.

An integrator sets the columns in the database by talking to the ovsdb-server
daemon.  A few of the columns can be set during startup by calling the ovs-ctl
tool from inside the startup scripts.  The ``rhel/etc_init.d_openvswitch``
script provides examples of its use, and the ovs-ctl(8) manpage contains
complete documentation.  At runtime, ovs-vsctl can be used to set columns in
the database.

Python and C bindings to the database are provided if deeper integration with a
program are needed.  More information on the python bindings is available at
``python/ovs/db/idl.py``.  Information on the C bindings is available at
``lib/ovsdb-idl.h``.

The following diagram shows how integration scripts fit into the Open vSwitch
architecture:

::

    Diagram

             +----------------------------------------+
             |           Controller Cluster           +
             +----------------------------------------+
                                 |
                                 |
    +----------------------------------------------------------+
    |                            |                             |
    |             +--------------+---------------+             |
    |             |                              |             |
    |   +-------------------+           +------------------+   |
    |   |   ovsdb-server    |-----------|   ovs-vswitchd   |   |
    |   +-------------------+           +------------------+   |
    |             |                              |             |
    |  +---------------------+                   |             |
    |  | Integration scripts |                   |             |
    |  +---------------------+                   |             |
    |                                            |   Userspace |
    |----------------------------------------------------------|
    |                                            |      Kernel |
    |                                            |             |
    |                                 +---------------------+  |
    |                                 |  OVS Kernel Module  |  |
    |                                 +---------------------+  |
    +----------------------------------------------------------+

A description of the most relevant fields for integration follows.  By setting
these values, controllers are able to understand the network and manage it more
dynamically and precisely.  For more details about the database and each
individual column, please refer to the ovs-vswitchd.conf.db(5) manpage.

``Open_vSwitch`` table
----------------------

The ``Open_vSwitch`` table describes the switch as a whole.  The
``system_type`` and ``system_version`` columns identify the platform to the
controller.  The ``external_ids:system-id`` key uniquely identifies the
physical host.  This key allows controllers to distinguish
between multiple hypervisors.

Most of this configuration can be done with the ovs-ctl command at startup.
For example:

::

    $ ovs-ctl --system-type="KVM" --system-version="4.18.el8_6" \
        --system-id="${UUID}" "${other_options}" start

Alternatively, the ovs-vsctl command may be used to set a particular value at
runtime.  For example:

::

    $ ovs-vsctl set open_vswitch . external-ids:system-id='"${UUID}"'

The ``other_config:enable-statistics`` key may be set to ``true`` to have OVS
populate the database with statistics (e.g., number of CPUs, memory, system
load) for the controller's use.

Bridge table
------------

The Bridge table describes individual bridges within an Open vSwitch instance.
The ``external-ids:bridge-id`` key uniquely identifies a particular bridge.

For example, to set the identifier for bridge "br0", the following command can
be used:

::

    $ ovs-vsctl set Bridge br0 external-ids:bridge-id='"${UUID}"'

The MAC address of the bridge may be manually configured by setting it with the
``other_config:hwaddr`` key.  For example:

::

    $ ovs-vsctl set Bridge br0 other_config:hwaddr="12:34:56:78:90:ab"

Interface table
---------------

The Interface table describes an interface under the control of Open vSwitch.
The ``external_ids`` column contains keys that are used to provide additional
information about the interface:

attached-mac

  This field contains the MAC address of the device attached to the interface.
  On a hypervisor, this is the MAC address of the interface as seen inside a
  VM.  It does not necessarily correlate to the host-side MAC address.

iface-id

  This field uniquely identifies the interface.  In hypervisors, this allows
  the controller to follow VM network interfaces as VMs migrate.  A well-chosen
  identifier should also allow an administrator or a controller to associate
  the interface with the corresponding object in the VM management system.

iface-status

  In a hypervisor, there are situations where there are multiple interface
  choices for a single virtual ethernet interface inside a VM.  Valid values
  are "active" and "inactive".  A complete description is available in the
  ovs-vswitchd.conf.db(5) manpage.

vm-id

  This field uniquely identifies the VM to which this interface belongs.  A
  single VM may have multiple interfaces attached to it.

As in the previous tables, the ovs-vsctl command may be used to configure the
values.  For example, to set the ``iface-id`` on eth0, the following command
can be used:

::

    $ ovs-vsctl set Interface eth0 external-ids:iface-id='"${UUID}"'


HA for OVN DB servers using pacemaker
-------------------------------------

The ovsdb servers can work in either active or backup mode. In backup mode, db
server will be connected to an active server and replicate the active servers
contents. At all times, the data can be transacted only from the active server.
When the active server dies for some reason, entire OVN operations will be
stalled.

`Pacemaker <http://clusterlabs.org/pacemaker.html>`__ is a cluster resource
manager which can manage a defined set of resource across a set of clustered
nodes. Pacemaker manages the resource with the help of the resource agents.
One among the resource agent is `OCF
<https://clusterlabs.org/pacemaker/doc/2.1/Pacemaker_Administration/html/agents.html>`__

OCF is nothing but a shell script which accepts a set of actions and returns an
appropriate status code.

With the help of the OCF resource agent ovn/utilities/ovndb-servers.ocf, one
can defined a resource for the pacemaker such that pacemaker will always
maintain one running active server at any time.

After creating a pacemaker cluster, use the following commands to create one
active and multiple backup servers for OVN databases::

    $ pcs resource create ovndb_servers ocf:ovn:ovndb-servers \
         master_ip=x.x.x.x \
         ovn_ctl=<path of the ovn-ctl script> \
         op monitor interval="10s" \
         op monitor role=Master interval="15s"
    $ pcs resource master ovndb_servers-master ovndb_servers \
        meta notify="true"

The `master_ip` and `ovn_ctl` are the parameters that will be used by the OCF
script. `ovn_ctl` is optional, if not given, it assumes a default value of
/usr/share/openvswitch/scripts/ovn-ctl. `master_ip` is the IP address on which
the active database server is expected to be listening, the slave node uses it
to connect to the master node. You can add the optional parameters
'nb_master_port', 'nb_master_protocol', 'sb_master_port', 'sb_master_protocol'
to set the protocol and port.

Whenever the active server dies, pacemaker is responsible to promote one of the
backup servers to be active. Both ovn-controller and ovn-northd needs the
ip-address at which the active server is listening. With pacemaker changing the
node at which the active server is run, it is not efficient to instruct all the
ovn-controllers and the ovn-northd to listen to the latest active server's
ip-address.

This problem can be solved by two ways:

1. By using a native ocf resource agent ``ocf:heartbeat:IPaddr2``.  The IPAddr2
resource agent is just a resource with an ip-address. When we colocate this
resource with the active server, pacemaker will enable the active server to be
connected with a single ip-address all the time. This is the ip-address that
needs to be given as the parameter while creating the `ovndb_servers` resource.

Use the following command to create the IPAddr2 resource and colocate it
with the active server::

    $ pcs resource create VirtualIP ocf:heartbeat:IPaddr2 ip=x.x.x.x \
        op monitor interval=30s
    $ pcs constraint order promote ovndb_servers-master then VirtualIP
    $ pcs constraint colocation add VirtualIP with master ovndb_servers-master \
        score=INFINITY

2. Using load balancer vip ip as a master_ip.  In order to use this feature,
one needs to use listen_on_master_ip_only to no.  Current code for load
balancer have been tested to work with tcp protocol and needs to be
tested/enhanced for ssl. Using load balancer, standby nodes will not listen on
nb and sb db ports so that load balancer will always communicate to the active
node and all the traffic will be sent to active node only.  Standby will
continue to sync using LB VIP IP in this case.

Use the following command to create pcs resource using LB VIP IP::

    $ pcs resource create ovndb_servers ocf:ovn:ovndb-servers \
         master_ip="<load_balance_vip_ip>" \
         listen_on_master_ip_only="no" \
         ovn_ctl=<path of the ovn-ctl script> \
         op monitor interval="10s" \
         op monitor role=Master interval="15s"
    $ pcs resource master ovndb_servers-master ovndb_servers \
        meta notify="true"
