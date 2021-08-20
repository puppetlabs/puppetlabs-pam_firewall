# frozen_string_literal: true

require 'spec_helper'

describe 'pam_firewall' do
  on_supported_os.each do |os, os_facts|
    context "on #{os}" do
      let(:facts) { os_facts }

      it { is_expected.to compile }

      it { is_expected.to contain_firewallchain('INPUT:filter:IPv4').with('ignore_foreign' => true) }
      it { is_expected.to contain_firewallchain('OUTPUT:filter:IPv4').with('ignore_foreign' => true) }
      it { is_expected.to contain_firewallchain('FORWARD:filter:IPv4').with('ignore_foreign' => true) }
      it { is_expected.to contain_firewallchain('PREROUTING:nat:IPv4').with('ignore_foreign' => true) }
      it { is_expected.to contain_firewallchain('INPUT:nat:IPv4').with('ignore_foreign' => true) }
      it { is_expected.to contain_firewallchain('OUTPUT:nat:IPv4').with('ignore_foreign' => true) }
      it { is_expected.to contain_firewallchain('POSTROUTING:nat:IPv4').with('ignore_foreign' => true) }
      it { is_expected.to contain_firewallchain('PREROUTING:raw:IPv4').with('ignore_foreign' => true) }
      it { is_expected.to contain_firewallchain('OUTPUT:raw:IPv4').with('ignore_foreign' => true) }

      it {
        is_expected.to contain_firewall('110 allow tcp port 2379-2380 from 172.16.254.254 for etcd').with(
          'ensure' => 'present',
          'source' => '172.16.254.254',
          'dport'  => [2_379, 2_380],
          'proto'  => 'tcp',
          'action' => 'accept',
        )
      }

      it {
        is_expected.to contain_firewall('110 allow tcp port 6783 from 172.16.254.254 for Weave').with(
          'ensure' => 'present',
          'source' => '172.16.254.254',
          'dport'  => 6_783,
          'proto'  => 'tcp',
          'action' => 'accept',
        )
      }

      it {
        is_expected.to contain_firewall('110 allow udp ports 6783-6784 from 172.16.254.254 for Weave').with(
          'ensure' => 'present',
          'source' => '172.16.254.254',
          'dport'  => [6_783, 6_784],
          'proto'  => 'udp',
          'action' => 'accept',
        )
      }

      it {
        is_expected.to contain_firewall('110 allow tcp port 10250 from 172.16.254.254 for Kubelet').with(
          'ensure' => 'present',
          'source' => '172.16.254.254',
          'dport'  => 10_250,
          'proto'  => 'tcp',
          'action' => 'accept',
        )
      }
    end

    context 'with 2 nodes' do
      let(:facts) { os_facts }
      let(:params) { { 'cluster_nodes' => ['172.16.0.0', '172.16.0.1'] } }

      it { is_expected.to compile }

      it {
        is_expected.to contain_firewall('110 allow tcp port 2379-2380 from 172.16.0.0 for etcd').with(
          'ensure' => 'present',
          'source' => '172.16.0.0',
          'dport'  => [2_379, 2_380],
          'proto'  => 'tcp',
          'action' => 'accept',
        )
      }

      it {
        is_expected.to contain_firewall('110 allow tcp port 6783 from 172.16.0.0 for Weave').with(
          'ensure' => 'present',
          'source' => '172.16.0.0',
          'dport'  => 6_783,
          'proto'  => 'tcp',
          'action' => 'accept',
        )
      }

      it {
        is_expected.to contain_firewall('110 allow udp ports 6783-6784 from 172.16.0.0 for Weave').with(
          'ensure' => 'present',
          'source' => '172.16.0.0',
          'dport'  => [6_783, 6_784],
          'proto'  => 'udp',
          'action' => 'accept',
        )
      }

      it {
        is_expected.to contain_firewall('110 allow tcp port 10250 from 172.16.0.0 for Kubelet').with(
          'ensure' => 'present',
          'source' => '172.16.0.0',
          'dport'  => 10_250,
          'proto'  => 'tcp',
          'action' => 'accept',
        )
      }

      it {
        is_expected.to contain_firewall('110 allow tcp port 2379-2380 from 172.16.0.1 for etcd').with(
          'ensure' => 'present',
          'source' => '172.16.0.1',
          'dport'  => [2_379, 2_380],
          'proto'  => 'tcp',
          'action' => 'accept',
        )
      }

      it {
        is_expected.to contain_firewall('110 allow tcp port 6783 from 172.16.0.1 for Weave').with(
          'ensure' => 'present',
          'source' => '172.16.0.1',
          'dport'  => 6_783,
          'proto'  => 'tcp',
          'action' => 'accept',
        )
      }

      it {
        is_expected.to contain_firewall('110 allow udp ports 6783-6784 from 172.16.0.1 for Weave').with(
          'ensure' => 'present',
          'source' => '172.16.0.1',
          'dport'  => [6_783, 6_784],
          'proto'  => 'udp',
          'action' => 'accept',
        )
      }

      it {
        is_expected.to contain_firewall('110 allow tcp port 10250 from 172.16.0.1 for Kubelet').with(
          'ensure' => 'present',
          'source' => '172.16.0.1',
          'dport'  => 10_250,
          'proto'  => 'tcp',
          'action' => 'accept',
        )
      }
    end

    context 'with limited app ports' do
      let(:facts) { os_facts }
      let(:params) { { 'app_ports' => [443] } }

      it { is_expected.to compile }
      it {
        is_expected.to contain_firewall('110 allow tcp app ports').with(
          'ensure' => 'present',
          'dport'  => [443],
          'proto'  => 'tcp',
          'action' => 'accept',
        )
      }
    end

    context 'with subnets' do
      let(:facts) { os_facts }
      let(:params) do
        {
          'pod_subnet'     => '10.48.0.0/24',
          'service_subnet' => '10.48.1.0/24',
        }
      end

      it { is_expected.to compile }
      it {
        is_expected.to contain_firewall('110 allow pod network').with(
          'ensure' => 'present',
          'source' => '10.48.0.0/24',
          'proto'  => 'all',
          'action' => 'accept',
        )
      }
      it {
        is_expected.to contain_firewall('110 allow service network').with(
          'ensure' => 'present',
          'source' => '10.48.1.0/24',
          'proto'  => 'all',
          'action' => 'accept',
        )
      }
    end

    context 'without common firewallchains' do
      let(:facts) { os_facts }
      let(:params) { { 'manage_common_chains' => false } }

      it { is_expected.not_to contain_firewallchain('INPUT:filter:IPv4') }
      it { is_expected.not_to contain_firewallchain('OUTPUT:filter:IPv4') }
      it { is_expected.not_to contain_firewallchain('FORWARD:filter:IPv4') }
      it { is_expected.not_to contain_firewallchain('PREROUTING:nat:IPv4') }
      it { is_expected.not_to contain_firewallchain('INPUT:nat:IPv4') }
      it { is_expected.not_to contain_firewallchain('OUTPUT:nat:IPv4') }
      it { is_expected.not_to contain_firewallchain('POSTROUTING:nat:IPv4') }
      it { is_expected.not_to contain_firewallchain('PREROUTING:raw:IPv4') }
      it { is_expected.not_to contain_firewallchain('OUTPUT:raw:IPv4') }
    end
  end
end
