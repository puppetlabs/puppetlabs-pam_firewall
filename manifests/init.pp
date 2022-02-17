# Firewall rules for Puppet Application Manager (PAM) and its applications on
# Puppet-supported Kubernetes.
#
# @param cluster_nodes
#   Nodes in a cluster that need access to etcd, weave, and kubelet.
#   Default works for Standalone architectures.
#
# @param app_ports
#   Specific application ports that need to be exposed. Default includes all
#   possible ports.
#
# @param pod_subnet
#   The Kubernetes pod subnet selected when installing PAM. Default matches the
#   default for Puppet-supported Kubernetes.
#
# @param service_subnet
#   The Kubernetes service subnet selected when installing PAM. Default
#   matches the default for Puppet-supported Kubernetes.
#
# @param manage_common_chains
#   These rules set `ignore_foreign=true` on common chains like
#   INPUT/OUTPUT/FORWARD:filter:IPv4, PREROUTING/INPUT/OUTPUT/POSTROUTING:nat/mangle:IPv4,
#   and PREROUTING/OUTPUT:raw:IPv4. If managing these chains yourself, set
#   this to false; if you purge unknown firewall rules, set `ignore_foreign=true`
#   on these chains so Kubernetes rules aren't removed.
class pam_firewall (
  Array[String] $cluster_nodes = [$::ipaddress],
  Array[Variant[String, Integer]] $app_ports = [80, 443, 8000, 9001],
  String $pod_subnet = '10.32.0.0/22',
  String $service_subnet = '10.96.0.0/22',
  Boolean $manage_common_chains = true,
) {
  # Avoid mangling Kubernetes rules in these chains.
  Firewallchain {
    ignore_foreign => true,
  }

  if $manage_common_chains {
    firewallchain { 'INPUT:filter:IPv4':
    }

    firewallchain { 'OUTPUT:filter:IPv4':
    }

    firewallchain { 'FORWARD:filter:IPv4':
    }

    ['PREROUTING', 'INPUT', 'OUTPUT', 'POSTROUTING'].each |$chain| {
      firewallchain { "${chain}:nat:IPv4":
      }
      firewallchain { "${chain}:mangle:IPv4":
      }
    }

    ['PREROUTING', 'OUTPUT'].each |$chain| {
      firewallchain { "${chain}:raw:IPv4":
      }
    }
  }

  # Avoid purging Kubernetes chains.
  firewallchain { [
    'CNI-HOSTPORT-MASQ:nat:IPv4',
    'CNI-HOSTPORT-SETMARK:nat:IPv4',
    'DOCKER-ISOLATION-STAGE-1:filter:IPv4',
    'DOCKER-ISOLATION-STAGE-2:filter:IPv4',
    'DOCKER-USER:filter:IPv4',
    'DOCKER:filter:IPv4',
    'DOCKER:nat:IPv4',
    'KUBE-FIREWALL:filter:IPv4',
    'KUBE-FIREWALL:nat:IPv4',
    'KUBE-FORWARD:filter:IPv4',
    'KUBE-KUBELET-CANARY:filter:IPv4',
    'KUBE-KUBELET-CANARY:mangle:IPv4',
    'KUBE-KUBELET-CANARY:nat:IPv4',
    'KUBE-LOAD-BALANCER:nat:IPv4',
    'KUBE-MARK-DROP:nat:IPv4',
    'KUBE-MARK-MASQ:nat:IPv4',
    'KUBE-NODE-PORT:nat:IPv4',
    'KUBE-POSTROUTING:nat:IPv4',
    'KUBE-SERVICES:nat:IPv4',
    'WEAVE-CANARY:filter:IPv4',
    'WEAVE-CANARY:mangle:IPv4',
    'WEAVE-CANARY:nat:IPv4',
    'WEAVE-IPSEC-IN-MARK:mangle:IPv4',
    'WEAVE-IPSEC-IN:filter:IPv4',
    'WEAVE-IPSEC-IN:mangle:IPv4',
    'WEAVE-IPSEC-OUT-MARK:mangle:IPv4',
    'WEAVE-IPSEC-OUT:mangle:IPv4',
    'WEAVE-NPC-DEFAULT:filter:IPv4',
    'WEAVE-NPC-EGRESS-ACCEPT:filter:IPv4',
    'WEAVE-NPC-EGRESS-CUSTOM:filter:IPv4',
    'WEAVE-NPC-EGRESS-DEFAULT:filter:IPv4',
    'WEAVE-NPC-EGRESS:filter:IPv4',
    'WEAVE-NPC-INGRESS:filter:IPv4',
    'WEAVE-NPC:filter:IPv4',
    'KUBE-NODE-PORT:filter:IPv4',
    'KUBE-MARK-DROP:nat:IPv6',
    'KUBE-SERVICES:nat:IPv6',
    'KUBE-POSTROUTING:nat:IPv6',
    'KUBE-FIREWALL:nat:IPv6',
    'KUBE-NODE-PORT:nat:IPv6',
    'KUBE-LOAD-BALANCER:nat:IPv6',
    'KUBE-MARK-MASQ:nat:IPv6',
    'KUBE-FORWARD:filter:IPv6',
    'KUBE-NODE-PORT:filter:IPv6',
    'KUBE-FIREWALL:filter:IPv6',
    'KUBE-KUBELET-CANARY:filter:IPv6',
    'WEAVE:nat:IPv4' ]:
    ensure => present,
    purge  => false,
  }

  # Rules for external services.
  firewall { '110 allow tcp port 8800 for Admin Console UI':
    ensure => present,
    dport  => 8800,
    proto  => 'tcp',
    action => 'accept',
  }

  firewall { '110 allow tcp app ports':
    ensure => present,
    dport  => $app_ports,
    proto  => 'tcp',
    action => 'accept',
  }

  firewall { '110 allow tcp port 6443 for Kubernetes API':
    ensure => present,
    dport  => 6443,
    proto  => 'tcp',
    action => 'accept',
  }

  # Rules for intra-cluster communication
  $cluster_nodes.each |$node| {
    firewall { "110 allow tcp port 2379-2380 from ${node} for etcd":
      ensure => present,
      source => $node,
      dport  => [2379, 2380],
      proto  => 'tcp',
      action => 'accept',
    }

    firewall { "110 allow tcp port 6783 from ${node} for Weave":
      ensure => present,
      source => $node,
      dport  => 6783,
      proto  => 'tcp',
      action => 'accept',
    }

    firewall { "110 allow udp ports 6783-6784 from ${node} for Weave":
      ensure => present,
      source => $node,
      dport  => [6783, 6784],
      proto  => 'udp',
      action => 'accept',
    }

    firewall { "110 allow tcp port 10250 from ${node} for Kubelet":
      ensure => present,
      source => $node,
      dport  => 10250,
      proto  => 'tcp',
      action => 'accept',
    }
  }

  # Allow communication between pods/services routed via iptables/ipvs.
  firewall { '110 allow pod network':
    ensure => present,
    source => $pod_subnet,
    proto  => 'all',
    action => 'accept',
  }

  firewall { '110 allow service network':
    ensure => present,
    source => $service_subnet,
    proto  => 'all',
    action => 'accept',
  }
}
