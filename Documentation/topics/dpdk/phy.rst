..
      Copyright 2018, Red Hat, Inc.

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

===================
DPDK Physical Ports
===================

The netdev datapath allows attaching of DPDK-backed physical interfaces in
order to provide high-performance ingress/egress from the host.

.. important::

   To use any DPDK-backed interface, you must ensure your bridge is configured
   correctly. For more information, refer to :doc:`bridge`.

.. versionchanged:: 2.7.0

   Before Open vSwitch 2.7.0, it was necessary to prefix port names with a
   ``dpdk`` prefix. Starting with 2.7.0, this is no longer necessary.

.. todo::

   Add an example for multiple ports share the same bus slot function.

Quick Example
-------------

This example demonstrates how to bind two ``dpdk`` ports, bound to physical
interfaces identified by hardware IDs ``0000:01:00.0`` and ``0000:01:00.1``, to
an existing bridge called ``br0``::

    $ ovs-vsctl add-port br0 dpdk-p0 \
       -- set Interface dpdk-p0 type=dpdk options:dpdk-devargs=0000:01:00.0
    $ ovs-vsctl add-port br0 dpdk-p1 \
       -- set Interface dpdk-p1 type=dpdk options:dpdk-devargs=0000:01:00.1

For the above example to work, the two physical interfaces must be bound to
the DPDK poll-mode drivers in userspace rather than the traditional kernel
drivers. See the `binding NIC drivers <dpdk-binding-nics>` section for details.

.. _dpdk-binding-nics:

Binding NIC Drivers
-------------------

DPDK operates entirely in userspace and, as a result, requires use of its own
poll-mode drivers in user space for physical interfaces and a passthrough-style
driver for the devices in kernel space.

There are two different tools for binding drivers: :command:`driverctl` which
is a generic tool for persistently configuring alternative device drivers, and
:command:`dpdk-devbind` which is a DPDK-specific tool and whose changes do not
persist across reboots. In addition, there are two options available for this
kernel space driver - VFIO (Virtual Function I/O) and UIO (Userspace I/O) -
along with a number of drivers for each option. We will demonstrate examples of
both tools and will use the ``vfio-pci`` driver, which is the more secure,
robust driver of those available. More information can be found in the
`DPDK drivers documentation`_.

To list devices using :command:`driverctl`, run::

    $ driverctl -v list-devices | grep -i net
    0000:07:00.0 igb (I350 Gigabit Network Connection (Ethernet Server Adapter I350-T2))
    0000:07:00.1 igb (I350 Gigabit Network Connection (Ethernet Server Adapter I350-T2))

You can then bind one or more of these devices using the same tool::

    $ driverctl set-override 0000:07:00.0 vfio-pci

Alternatively, to list devices using :command:`dpdk-devbind`, run::

    $ dpdk-devbind --status
    Network devices using DPDK-compatible driver
    ============================================
    <none>

    Network devices using kernel driver
    ===================================
    0000:07:00.0 'I350 Gigabit Network Connection 1521' if=enp7s0f0 drv=igb unused=igb_uio
    0000:07:00.1 'I350 Gigabit Network Connection 1521' if=enp7s0f1 drv=igb unused=igb_uio

    Other Network devices
    =====================
    ...

Once again, you can then bind one or more of these devices using the same
tool::

    $ dpdk-devbind --bind=vfio-pci 0000:07:00.0

.. versionchanged:: 2.6.0

   Open vSwitch 2.6.0 added support for DPDK 16.07, which in turn renamed the
   former ``dpdk_nic_bind`` tool to ``dpdk-devbind``.

For more information, refer to the `DPDK drivers documentation`_.

.. _DPDK drivers documentation: https://doc.dpdk.org/guides-23.11/linux_gsg/linux_drivers.html

.. _dpdk-phy-multiqueue:

Multiqueue
----------

Poll Mode Driver (PMD) threads are the threads that do the heavy lifting for
userspace switching. Correct configuration of PMD threads and the Rx
queues they utilize is a requirement in order to deliver the high-performance
possible with DPDK acceleration. It is possible to configure multiple Rx queues
for ``dpdk`` ports, thus ensuring this is not a bottleneck for performance. For
information on configuring PMD threads, refer to :doc:`pmd`.

Traffic Rx Steering
-------------------

.. warning:: This feature is experimental.

Some control protocols are used to maintain link status between forwarding
engines. In SDN environments, these packets share the same physical network
with the user data traffic.

When the system is not sized properly, the PMD threads may not be able to
process all incoming traffic from the configured Rx queues. When a signaling
packet of such protocols is dropped, it can cause link flapping, worsening the
situation.

Some physical NICs can be programmed to put these protocols in a dedicated
hardware Rx queue using the rte_flow__ API.

__ https://doc.dpdk.org/guides-23.11/prog_guide/rte_flow.html

.. warning::

   This feature is not compatible with all NICs. Refer to the DPDK
   `compatibility matrix`__ and vendor documentation for more details.

   __ https://doc.dpdk.org/guides-23.11/nics/overview.html

Rx steering must be enabled for specific protocols per port. The
``rx-steering`` option takes one of the following values:

``rss``
   Do regular RSS on all configured Rx queues. This is the default behaviour.

``rss+lacp``
   Do regular RSS on all configured Rx queues. An extra Rx queue is configured
   for LACP__ packets (ether type ``0x8809``).

   __ https://www.ieee802.org/3/ad/public/mar99/seaman_1_0399.pdf

Example::

   $ ovs-vsctl add-port br0 dpdk-p0 -- set Interface dpdk-p0 type=dpdk \
        options:dpdk-devargs=0000:01:00.0 options:n_rxq=2 \
        options:rx-steering=rss+lacp

.. note::

   If multiple Rx queues are already configured, regular hash-based RSS
   (Receive Side Scaling) queue balancing is done on all but the extra Rx
   queue.

.. tip::

   You can check if Rx steering is supported on a port with the following
   command::

      $ ovs-vsctl get interface dpdk-p0 status
      {..., rss_queues="0-1", rx_steering_queue="2"}

   This will also show in ``ovs-vswitchd.log``::

      INFO|dpdk-p0: rx-steering: redirecting lacp traffic to queue 2
      INFO|dpdk-p0: rx-steering: applying rss on queues 0-1

   If the hardware does not support redirecting the specified protocols to
   a dedicated queue, it will be explicit::

      $ ovs-vsctl get interface dpdk-p0 status
      {..., rx-steering=unsupported}

   More details can often be found in ``ovs-vswitchd.log``::

      WARN|dpdk-p0: rx-steering: failed to add lacp flow: Unsupported pattern

To disable Rx steering on a port, use the following command::

   $ ovs-vsctl remove Interface dpdk-p0 options rx-steering

You can see that it has been disabled in ``ovs-vswitchd.log``::

   INFO|dpdk-p0: rx-steering: default rss

.. warning::

   This feature is mutually exclusive with ``other-config:hw-offload`` as it
   may conflict with the offloaded flows. If both are enabled, ``rx-steering``
   will fall back to default ``rss`` mode.

.. _dpdk-phy-flow-control:

Flow Control
------------

Flow control can be enabled only on DPDK physical ports. To enable flow control
support at Tx side while adding a port, run::

    $ ovs-vsctl add-port br0 dpdk-p0 -- set Interface dpdk-p0 type=dpdk \
        options:dpdk-devargs=0000:01:00.0 options:tx-flow-ctrl=true

Similarly, to enable Rx flow control, run::

    $ ovs-vsctl add-port br0 dpdk-p0 -- set Interface dpdk-p0 type=dpdk \
        options:dpdk-devargs=0000:01:00.0 options:rx-flow-ctrl=true

To enable flow control auto-negotiation, run::

    $ ovs-vsctl add-port br0 dpdk-p0 -- set Interface dpdk-p0 type=dpdk \
        options:dpdk-devargs=0000:01:00.0 options:flow-ctrl-autoneg=true

To turn on the Tx flow control at run time for an existing port, run::

    $ ovs-vsctl set Interface dpdk-p0 options:tx-flow-ctrl=true

The flow control parameters can be turned off by setting ``false`` to the
respective parameter. To disable the flow control at Tx side, run::

    $ ovs-vsctl set Interface dpdk-p0 options:tx-flow-ctrl=false

Rx Checksum Offload
-------------------

By default, DPDK physical ports are enabled with Rx checksum offload.

Rx checksum offload can offer performance improvement only for tunneling
traffic in OVS-DPDK because the checksum validation of tunnel packets is
offloaded to the NIC. Also enabling Rx checksum may slightly reduce the
performance of non-tunnel traffic, specifically for smaller size packet.

.. _port-hotplug:

Hotplugging
-----------

OVS supports port hotplugging, allowing the use of physical ports that were not
bound to DPDK when ovs-vswitchd was started.

.. warning::

    This feature is not compatible with all NICs. Refer to vendor documentation
    for more information.

.. important::

   Ports must be bound to DPDK. Refer to :ref:`dpdk-binding-nics` for more
   information.

To *hotplug* a port, simply add it like any other port::

    $ ovs-vsctl add-port br0 dpdkx -- set Interface dpdkx type=dpdk \
        options:dpdk-devargs=0000:01:00.0

Ports can be detached using the ``del-port`` command::

    $ ovs-vsctl del-port dpdkx

This should both delete the port and detach the device. If successful, you
should see an ``INFO`` log. For example::

    INFO|Device '0000:04:00.1' has been detached

If the log is not seen then the port can be detached like so::

    $ ovs-appctl netdev-dpdk/detach 0000:01:00.0

.. warning::

    Detaching should not be done if a device is known to be non-detachable, as
    this may cause the device to behave improperly when added back with
    add-port. The Chelsio Terminator adapters which use the cxgbe driver seem
    to be an example of this behavior; check the driver documentation if this
    is suspected.

Hotplugging with IGB_UIO
~~~~~~~~~~~~~~~~~~~~~~~~

.. important::

   As of DPDK v20.11 IGB_UIO has been deprecated and is no longer built as
   part of the default DPDK library. Below is intended for those who wish
   to use IGB_UIO outside of the standard DPDK build from v20.11 onwards.

As of DPDK v19.11, default igb_uio hotplugging behavior changed from
previous DPDK versions.

From DPDK v19.11 onwards, if no device is bound to igb_uio when OVS is
launched then the IOVA mode may be set to virtual addressing for DPDK.
This is incompatible for hotplugging with igb_uio.

To hotplug a port with igb_uio in this case, DPDK must be configured to use
physical addressing for IOVA mode. For more information regarding IOVA modes
in DPDK please refer to the `DPDK IOVA Mode Detection`__.

__ https://doc.dpdk.org/guides-23.11/prog_guide/env_abstraction_layer.html#iova-mode-detection

To configure OVS DPDK to use physical addressing for IOVA::

    $ ovs-vsctl --no-wait set Open_vSwitch . \
        other_config:dpdk-extra="--iova-mode=pa"

.. note::

   Changing IOVA mode requires restarting the ovs-vswitchd application.

.. _representors:

Representors
------------

DPDK representors enable configuring a phy port to a guest (VM) machine.

OVS resides in the hypervisor which has one or more physical interfaces also
known as the physical functions (PFs). If a PF supports SR-IOV it can be used
to enable communication with the VMs via Virtual Functions (VFs).
The VFs are virtual PCIe devices created from the physical Ethernet controller.

DPDK models a physical interface as a rte device on top of which an eth
device is created.
DPDK (version 18.xx) introduced the representors eth devices.
A representor device represents the VF eth device (VM side) on the hypervisor
side and operates on top of a PF.
Representors are multi devices created on top of one PF.

For more information, refer to the `DPDK documentation`__.

__ https://doc.dpdk.org/guides-23.11/prog_guide/switch_representation.html#port-representors

Prior to port representors there was a one-to-one relationship between the PF
and the eth device. With port representors the relationship becomes one PF to
many eth devices.
In case of two representors ports, when one of the ports is closed - the PCI
bus cannot be detached until the second representor port is closed as well.

.. _representors-configuration:

When configuring a PF-based port, OVS traditionally assigns the device PCI
address in devargs. For an existing bridge called ``br0`` and PCI address
``0000:08:00.0`` an ``add-port`` command is written as::

    $ ovs-vsctl add-port br0 dpdk-pf -- set Interface dpdk-pf type=dpdk \
       options:dpdk-devargs=0000:08:00.0

When configuring a VF-based port, DPDK uses an extended devargs syntax which
has the following format::

    BDBF,representor=<representor identifier>

This syntax shows that a representor is an enumerated eth device (with
a representor identifier) which uses the PF PCI address.
The following commands add representors of VF 3 and 5 using PCI device address
``0000:08:00.0``::

    $ ovs-vsctl add-port br0 dpdk-rep3 -- set Interface dpdk-rep3 type=dpdk \
       options:dpdk-devargs=0000:08:00.0,representor=vf3

    $ ovs-vsctl add-port br0 dpdk-rep5 -- set Interface dpdk-rep5 type=dpdk \
       options:dpdk-devargs=0000:08:00.0,representor=vf5

.. important::

   Representors ports are configured prior to OVS invocation and independently
   of it, or by other means as well. Please consult a NIC vendor instructions
   on how to establish representors.

.. _multi-dev-configuration:

**Intel NICs ixgbe and i40e**

In the following example we create one representor on PF address
``0000:05:00.0``. Once the NIC is bounded to a DPDK compatible PMD the
representor is created::

    # echo 1 > /sys/bus/pci/devices/0000\:05\:00.0/max_vfs

**Mellanox NICs ConnectX-4, ConnectX-5 and ConnectX-6**

In the following example we create two representors on PF address
``0000:05:00.0`` and net device name ``enp3s0f0``.

- Ensure SR-IOV is enabled on the system.

Enable IOMMU in Linux by adding ``intel_iommu=on`` to kernel parameters, for
example, using GRUB (see /etc/grub/grub.conf).

- Verify the PF PCI address prior to representors creation::

    # lspci | grep Mellanox
    05:00.0 Ethernet controller: Mellanox Technologies MT27700 Family [ConnectX-4]
    05:00.1 Ethernet controller: Mellanox Technologies MT27700 Family [ConnectX-4]

- Create the two VFs on the compute node::

    # echo 2 > /sys/class/net/enp3s0f0/device/sriov_numvfs

 Verify the VFs creation::

    # lspci | grep Mellanox
    05:00.0 Ethernet controller: Mellanox Technologies MT27700 Family [ConnectX-4]
    05:00.1 Ethernet controller: Mellanox Technologies MT27700 Family [ConnectX-4]
    05:00.2 Ethernet controller: Mellanox Technologies MT27700 Family [ConnectX-4 Virtual Function]
    05:00.3 Ethernet controller: Mellanox Technologies MT27700 Family [ConnectX-4 Virtual Function]

- Unbind the relevant VFs 0000:05:00.2..0000:05:00.3::

    # echo 0000:05:00.2 > /sys/bus/pci/drivers/mlx5_core/unbind
    # echo 0000:05:00.3 > /sys/bus/pci/drivers/mlx5_core/unbind

- Change e-switch mode.

The Mellanox NIC has an e-switch on it. Change the e-switch mode from
legacy to switchdev using the PF PCI address::

    # sudo devlink dev eswitch set pci/0000:05:00.0 mode switchdev

This will create the VF representors network devices in the host OS.

- After setting the PF to switchdev mode bind back the relevant VFs::

    # echo 0000:05:00.2 > /sys/bus/pci/drivers/mlx5_core/bind
    # echo 0000:05:00.3 > /sys/bus/pci/drivers/mlx5_core/bind

- Restart Open vSwitch

To verify representors correct configuration, execute::

    $ ovs-vsctl show

and make sure no errors are indicated.

.. _vendor_configuration:

Port representors are an example of multi devices. There are NICs which support
multi devices by other methods than representors for which a generic devargs
syntax is used. The generic syntax is based on the device mac address::

    class=eth,mac=<MAC address>

For example, the following command adds a port to a bridge called ``br0`` using
an eth device whose mac address is ``00:11:22:33:44:55``::

    $ ovs-vsctl add-port br0 dpdk-mac -- set Interface dpdk-mac type=dpdk \
       options:dpdk-devargs="class=eth,mac=00:11:22:33:44:55"

Representor specific configuration
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

In some topologies, a VF must be configured before being assigned to a
guest (VM) machine.  This configuration is done through VF-specific fields
in the ``options`` column of the ``Interface`` table.

.. important::

   Some DPDK port use `bifurcated drivers`_, which means that a kernel
   netdevice remains when Open vSwitch is stopped.

   In such case, any configuration applied to a VF would remain set on the
   kernel netdevice, and be inherited from it when Open vSwitch is restarted,
   even if the options described in this section are unset from Open vSwitch.

.. _bifurcated drivers: https://doc.dpdk.org/guides-23.11/linux_gsg/linux_drivers.html#bifurcated-driver

- Configure the VF MAC address::

    $ ovs-vsctl set Interface dpdk-rep0 options:dpdk-vf-mac=00:11:22:33:44:55

The requested MAC address is assigned to the port and is listed as part of
its options::

    $ ovs-appctl dpctl/show
    [...]
      port 3: dpdk-rep0 (dpdk: ..., dpdk-vf-mac=00:11:22:33:44:55, ...)

    $ ovs-vsctl show
    [...]
            Port dpdk-rep0
                Interface dpdk-rep0
                    type: dpdk
                    options: {dpdk-devargs="<representor devargs>", dpdk-vf-mac="00:11:22:33:44:55"}

    $ ovs-vsctl get Interface dpdk-rep0 status
    {dpdk-vf-mac="00:11:22:33:44:55", ...}

    $ ovs-vsctl list Interface dpdk-rep0 | grep 'mac_in_use\|options'
    mac_in_use          : "00:11:22:33:44:55"
    options             : {dpdk-devargs="<representor devargs>", dpdk-vf-mac="00:11:22:33:44:55"}

The value listed as ``dpdk-vf-mac`` is only a request from the user and is
possibly not yet applied.

When the requested configuration is successfully applied to the port,
this MAC address is then also shown in the column ``mac_in_use`` of
the ``Interface`` table.  On failure however, ``mac_in_use`` will keep its
previous value, which will thus differ from ``dpdk-vf-mac``.

Jumbo Frames
------------

DPDK physical ports can be configured to use Jumbo Frames. For more
information, refer to :doc:`jumbo-frames`.

.. _lsc-detection:

Link State Change (LSC) detection configuration
-----------------------------------------------

There are two methods to get the information when Link State Change (LSC)
happens on a network interface: by polling or interrupt.

Configuring the lsc detection mode has no direct effect on OVS itself,
instead it configures the NIC how it should handle link state changes.
Processing the link state update request triggered by OVS takes less time
using interrupt mode, since the NIC updates its link state in the
background, while in polling mode the link state has to be fetched from
the firmware every time to fulfil this request.

Note that not all PMD drivers support LSC interrupts.

The default configuration is polling mode. To set interrupt mode, option
``dpdk-lsc-interrupt`` has to be set to ``true``.

Command to set interrupt mode for a specific interface::
    $ ovs-vsctl set interface <iface_name> options:dpdk-lsc-interrupt=true

Command to set polling mode for a specific interface::
    $ ovs-vsctl set interface <iface_name> options:dpdk-lsc-interrupt=false
