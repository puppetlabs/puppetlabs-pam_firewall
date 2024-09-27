include firewall

firewall { '000 accept all icmp':
  proto => 'icmp',
  jump  => 'accept',
}
-> firewall { '001 accept all to lo interface':
  proto   => 'all',
  iniface => 'lo',
  action  => 'accept',
}
-> firewall { '002 accept related established rules':
  proto => 'all',
  state => ['RELATED', 'ESTABLISHED'],
  jump  => 'accept',
}
-> firewall { '003 accept inbound SSH':
  dport => 22,
  proto => 'tcp',
  jump  => 'accept',
}

Firewallchain {
  purge => true,
}

resources { 'firewallchain':
  purge => true,
}

include pam_firewall

firewall { '899 drop broadcast':
  action   => 'drop',
  dst_type => 'BROADCAST',
  proto    => 'all',
}

firewall { '900 INPUT denies get logged':
  jump       => 'LOG',
  log_level  => '4',
  log_prefix => 'iptables denied: ',
  proto      => 'all',
  limit      => '30/min',
}

firewall { '999 drop all':
  proto => 'all',
  jump  => 'accept',
}
