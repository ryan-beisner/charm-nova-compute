Overview
========

This charm provides Nova Compute, the Openstack compute service. It's target
platform is Ubuntu (preferably LTS) + Openstack.

Usage
=====

The following interfaces are provided:

  - cloud-compute - Used to relate (at least) with one or more of
    nova-cloud-controller, glance, ceph, cinder, mysql, ceilometer-agent,
    rabbitmq-server, neutron

  - nrpe-external-master - Used to generate Nagios checks.

Database
--------

Nova compute only requires database access if using nova-network. If using
Neutron, no direct database access is required and the shared-db relation need
not be added.

Networking
----------
This charm support nova-network (legacy) and Neutron networking.

Storage
-------
This charm supports a number of different storage backends depending on
your hypervisor type and storage relations.
