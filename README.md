# Do Not Use - Testing Only

----

# TEMP WIP for:

 - https://bugs.launchpad.net/charm-helpers/+bug/1611134

---

Overview
========

This charm provides Nova Compute, the OpenStack compute service. It's target
platform is Ubuntu (preferably LTS) + Openstack.

Usage
=====

The following interfaces are provided:

  - cloud-compute - Used to relate (at least) with one or more of
    nova-cloud-controller, glance, ceph, cinder, mysql, ceilometer-agent,
    rabbitmq-server, neutron

  - nrpe-external-master - Used to generate Nagios checks.

Database
========

Nova compute only requires database access if using nova-network. If using
Neutron, no direct database access is required and the shared-db relation need
not be added.

Networking
==========

This charm support nova-network (legacy) and Neutron networking.

Storage
=======

This charm supports a number of different storage backends depending on
your hypervisor type and storage relations.

NFV support
===========

This charm (in conjunction with the nova-cloud-controller and neutron-api charms)
supports use of nova-compute nodes configured for use in Telco NFV deployments;
specifically the following configuration options (yaml excerpt):

```yaml
nova-compute:
  hugepages: 60%
  vcpu-pin-set: "^0,^2"
  reserved-host-memory: 1024
  pci-passthrough-whitelist: {"vendor_id":"1137","product_id":"0071","address":"*:0a:00.*","physical_network":"physnet1"}
```

In this example, compute nodes will be configured with 60% of available RAM for
hugepage use (decreasing memory fragmentation in virtual machines, improving
performance), and Nova will be configured to reserve CPU cores 0 and 2 and
1024M of RAM for host usage and use the supplied PCI device whitelist as
PCI devices that as consumable by virtual machines, including any mapping to
underlying provider network names (used for SR-IOV VF/PF port scheduling with
Nova and Neutron's SR-IOV support).

The vcpu-pin-set configuration option is a comma-separated list of physical
CPU numbers that virtual CPUs can be allocated to by default. Each element
should be either a single CPU number, a range of CPU numbers, or a caret
followed by a CPU number to be excluded from a previous range. For example:

```yaml
vcpu-pin-set: "4-12,^8,15"
```

The pci-passthrough-whitelist configuration must be specified as follows:

A JSON dictionary which describe a whitelisted PCI device. It should take
the following format:

```
["device_id": "<id>",] ["product_id": "<id>",]
["address": "[[[[<domain>]:]<bus>]:][<slot>][.[<function>]]" |
"devname": "PCI Device Name",]
{"tag": "<tag_value>",}
```

  where '[' indicates zero or one occurrences, '{' indicates zero or multiple
  occurrences, and '|' mutually exclusive options. Note that any missing
  fields are automatically wildcarded. Valid examples are:

```
pci-passthrough-whitelist: {"devname":"eth0", "physical_network":"physnet"}

pci-passthrough-whitelist: {"address":"*:0a:00.*"}

pci-passthrough-whitelist: {"address":":0a:00.", "physical_network":"physnet1"}

pci-passthrough-whitelist: {"vendor_id":"1137", "product_id":"0071"}

pci-passthrough-whitelist: {"vendor_id":"1137", "product_id":"0071", "address": "0000:0a:00.1", "physical_network":"physnet1"}
```

  The following is invalid, as it specifies mutually exclusive options:

```
pci-passthrough-whitelist: {"devname":"eth0", "physical_network":"physnet", "address":"*:0a:00.*"}
```

A JSON list of JSON dictionaries corresponding to the above format. For
example:

```
pci-passthrough-whitelist: [{"product_id":"0001", "vendor_id":"8086"}, {"product_id":"0002", "vendor_id":"8086"}]`
```

The [OpenStack advanced networking documentation](http://docs.openstack.org/mitaka/networking-guide/adv-config-sriov.html)
provides further details on whitelist configuration and how to create instances
with Neutron ports wired to SR-IOV devices.
