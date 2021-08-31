<!-- omit in toc -->
# pam_firewall

Configures firewall rules using the [firewall] module for Puppet Application Manager.

* [Description](#description)
* [Usage](#usage)
  * [HA cluster](#ha-cluster)
  * [Application ports](#application-ports)
  * [Subnets](#subnets)

## Description

This module configures firewall rules using the [firewall] module for Puppet Application Manager (PAM) installed on Puppet-supported Kubernetes.

The `preserve-iptables-config` option should be supplied while installing PAM to leave the `iptables` service enabled, as in `bash -s preserve-iptables-config`. The PAM installation must be run after applying this module to ensure Kubernetes firewall rules are registered with the `iptables` service.

It specifically avoids purging foreign rules and chains created by Kubernetes. It also exposes ports to cluster members that need access (currently treats primary and secondary nodes identically) and exposes application ports globally.

## Usage

The module declares a single class that can be applied to your cluster members.

The defaults work for a [Standalone] install

    include ::firewall
    include ::pam_firewall

An [example](examples/init.pp) is provided that demonstrates using this while locking down most other inbound access. You can run it with [Bolt]

    bolt module install
    bolt apply examples/init.pp --run-as root --targets $target

Note that this module ensures firewall rules created by Kubernetes remain if purging unknown rules in firewall chains and unknown firewall chains with

    Firewallchain {
        purge => true,
    }
    resources { 'firewallchain':
        purge => true,
    }

but not if purging all unknown firewall rules with

    resources { 'firewall':
        purge => true,
    }

### HA cluster

If installing an HA cluster, you'll need to provide `cluster_nodes` for all members to enable intra-cluster communication

    include ::firewall
    class {'::pam_firewall':
        cluster_nodes => ['10.20.0.1', '10.20.0.2', '10.20.0.3'],
    }

### Application ports

You can also override `app_ports` to be more restrictive if not using all ports. For example, port 9001 is only used by CD4PE in an offline install, and port 8000 is only used by CD4PE for webhooks

    include ::firewall
    class {'::pam_firewall':
        app_ports => [443],
    }

### Subnets

If you need to override pod and/or service subnets for a PAM install, you'll also need to provide those here

    include ::firewall
    class {'::pam_firewall':
        pod_subnet     => '10.48.0.0/24',
        service_subnet => '10.48.1.0/24',
    }

### Managing common firewall chains

If you manage common firewall chains explicitly and purge unknown rules, such as

    firewallchain {'OUTPUT:filter:IPv4']:
        policy => 'drop',
        purge  => true,
    }

you'll need to disable this module's management of those chains and ignore foreign rules to avoid
deleting rules created by Kubernetes

    include ::firewall
    class {'::pam_firewall':
        manage_common_chains => false,
    }

    firewallchain {'OUTPUT:filter:IPv4']:
        policy         => 'drop',
        purge          => true,
        ignore_foreign => true
    }

[firewall]: https://forge.puppet.com/modules/puppetlabs/firewall
[Standalone]: https://puppet.com/docs/continuous-delivery/4.x/pam/pam-node-arch.html
[Bolt]: http://pup.pt/installbolt
