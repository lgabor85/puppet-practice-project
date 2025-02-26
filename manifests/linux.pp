# This profile is made for Ubuntu 22.04.5 LTS hosts
# It Manages the following:
# - Puppet Agent
# - ntp
# - rsyslog
# - user account with ssh keys
# - basic DNS setup
#
# Class: profile::linux
#
# This class configures various services and packages for Ubuntu 22.04.5 LTS hosts.
#
# Parameters:
#   None
#
# Example usage:
#   include profile::linux
#

class profile::linux {
  include profile::puppet::agent
  include profile::linux::logrotate

  # Configure mailserver for non-smtp servers
  unless $facts['networking']['hostname'] =~ /^.*smtp.*/ {
    $relayserver = lookup('general::smtpserver')
    class { 'postfix':
      mydomain   => $facts['networking']['fqdn'],
      smtp_relay => false,
      relay_host => "[${relayserver}]",
    }
  }

  $other_packages = [
    'kibana', 'elasticsearch', 'ncpa', 'logstash', 'WALinuxAgent', 'walinuxagent', 'influxdb', 'telegraf', 'grafana', 'mongodb-org',
    'mongodb-org-mongos', 'mongodb-org-server', 'mongodb-org-shell', 'mongodb-org-tools', 'haproxy', 'keepalived',
    'cassandra30', 'java-1.8.0-openjdk*',
  ]

  case $facts['os']['family'] {
    'Debian': {
      class { 'ntp':
        servers => lookup('ntp::servers'),
      }

      # Ensure Node.js is installed
      class { 'nodejs':
        manage_package_repo       => false,
        nodejs_dev_package_ensure => installed,
        npm_package_ensure        => installed,
      }

      # Configure apt unattended upgrades
      include apt
      class { 'unattended_upgrades':
        mail            => {
          'to'            => 'laagabinl@gmail.com',
          'only_on_error' => false,
        },
        sender          => lookup('apt_unattended_upgrade::from_email',
        'default_value' => 'laagabinl@gmail.com'),
        blacklist       => $other_packages,
        origins         => ["${distro_id}:${distro_codename}", "${distro_id}:${distro_codename}-security", "${distro_id}:${distro_codename}-updates"],
      }

      each($other_packages) |$package| {
        exec { "blcklist-${package}":
          command  => "apt-mark hold ${package}",
          provider => 'shell',
          path     => ['/bin', '/usr/bin', '/sbin', '/usr/sbin', '/usr/local/bin'],
          onlyif   => "dpkg -l | grep ${package}",
        }
      }

      service { 'systemd-resolved':
        ensure => running,
        enable => true,
      }
      file_line { 'disable_dnsstublistener':
        ensure => 'present',
        path   => '/etc/systemd/resolved.conf',
        line   => 'DNSStubListener=no',
        match  => '^#DNSStubListener=yes',
        notify => Service['systemd-resolved'],
      }
      file { '/etc/resolv.conf':
        ensure => 'link',
        target => '/run/systemd/resolve/resolv.conf',
      }

      class { 'rsyslog':
        preserve_fqdn => true,
      }

      if $facts['os']['name'] == 'Ubuntu' {
        include netplan
      }

      # Ensure auditd for SIEM on Debian/Ubuntu (enabled by default on CentOS)
      package { 'auditd':
        ensure => installed,
      }
    }
    default: {
      fail('Operating system not supported')
    }
  }

  group { 'add_wheel_group':
    ensure => present,
    name   => 'wheel',
  }

  class { 'rsyslog::client':
    log_remote     => true,
    server         => lookup('log::servers'),
    port           => '20514',
    remote_type    => 'relp',
    log_local      => true,
    log_auth_local => true,
  }

  # Remove duplicate config file to prevent duplicate remote log entries
  file { 'Remove stale /etc/rsyslog.d/client.conf (rsyslog::client manages the 00_client.conf file)':
    ensure => absent,
    path   => '/etc/rsyslog.d/client.conf',
  }

  # Send only severity "crit" and higher to console, so the console is usable when you need it
  sysctl { 'kernel.printk': value => '3 4 1 3' }

  # Create accounts with authorized ssh key and optional console password
  $accounts = lookup('profile::linux::accounts')
  $accounts.each |String $account, Hash $attributes| {
    accounts::user { $account:
      * => $attributes,
    }
  }

  # Implement sudo
  file { '/etc/sudoers.d/gaborl':
    ensure => file,
    owner  => 'root',
    group  => 'root',
    mode   => '0440',
    source => 'puppet:///modules/profile/topdesk_sudo',
  }

  # Make sure we can't logon with root @ ssh
  file { '/etc/ssh/sshd_config':
    ensure => file,
    owner  => 'root',
    group  => 'root',
    mode   => '0600',
    source => 'puppet:///modules/profile/sshd_config',
    notify => Service['sshd'],
  }
  service { 'sshd':
    ensure => running,
    enable => true,
  }

  include wget
}
