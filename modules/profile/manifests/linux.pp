class profile::linux {
  include profile::puppet::agent
  include profile::linux::logrotate
  include nagiosagent

  unless $::hostname =~ /^.*smtp.*/ {
    $relayserver = lookup('general::smtpserver')
    class { 'postfix':
      mydomain   => $::fqdn,
      smtp_relay => false,
      relay_host => "[${relayserver}]",
    }
  }

  $kubernetes_packages  = ['kubeadm','kubelet','kubectl','flannel','docker-ce', 'docker-ce-selinux','docker-engine','docker-engine-selinux',
                          'kubernetes-cni','etcd', 'kube-proxy', 'container-selinux', 'containerd.io', 'containerd']
  $other_packages       = ['kibana','elasticsearch','ncpa','logstash','WALinuxAgent','walinuxagent','influxdb','telegraf','grafana','mongodb-org',
                          'mongodb-org-mongos','mongodb-org-server','mongodb-org-shell','mongodb-org-tools','haproxy','keepalived',
                          'cassandra30','java-1.8.0-openjdk*']

  $regexmonhosts        = '/^([[:lower:]]{2}\d[cs]\d{2}mon\d{2}|nl2mon01|nl1mon01|^[[:lower:]]{2}\dnag\d+)/'

  case $facts['os']['family'] {
    'Debian': {
      class { 'ntp':
        servers  => lookup('ntp::servers'),
      }
      include apt
      class { 'unattended_upgrades':
        mail      => {
          'to'            => 'saasops@topdesk.com',
          'only_on_error' => false,
        },
        sender    => lookup('apt_unattended_upgrade::from_email', 'default_value' => 'aptunattendedupgrade@topdesk.net'),
        blacklist => $kubernetes_packages + $other_packages,
        origins   => ['${distro_id}:${distro_codename}', '${distro_id}:${distro_codename}-security', '${distro_id}:${distro_codename}-updates'],
      }

      each(concat($kubernetes_packages, $other_packages)) |$package| {
        exec {"blcklist-${package}":
          command  => "apt-mark hold ${package}",
          provider => 'shell',
          path     => ['/bin', '/usr/bin', '/sbin', '/usr/sbin', '/usr/local/bin'],
          onlyif   => "dpkg -l | grep ${package}",
        }
      }

      service { 'systemd-resolved':
        ensure => running,
        enable => true
      }
      file_line { 'disable_dnsstublistener':
        ensure => 'present',
        path   => '/etc/systemd/resolved.conf',
        line   => 'DNSStubListener=no',
        match  => '^#DNSStubListener=yes',
        notify => Service['systemd-resolved']
      }
      file { '/etc/resolv.conf':
        ensure => 'link',
        target => '/run/systemd/resolve/resolv.conf'
      }

      class { 'rsyslog':
        preserve_fqdn => true,
      }

      if $facts['os']['name'] == 'Ubuntu' {
        include netplan
      }
      package { 'auditd':
        ensure => present,
      }
    }
    'RedHat': {
      include epel
      package {'iptables-utils':
        ensure => present,
      }
      package {['cockpit', 'cockpit-ws']:
        ensure => absent,
      }

      $kp = join($kubernetes_packages, ' ')
      $op = join($other_packages, ' ')

      file_line { 'exclude':
        ensure            => 'absent',
        path              => '/etc/yum.conf',
        match             => '^exclude=',
        match_for_absence => true,
      }

      if $facts['os']['release']['major'] == '7' {
        file { '/etc/yum/yum-cron.conf_dailyupdate' :
        ensure => absent,
        }

        file { '/etc/yum/schedules/' :
        ensure => directory,
        }

        file { '/etc/yum/schedules/yum-cron_dailyupdate':
          ensure => file,
          path   => '/etc/yum/schedules/yum-cron_dailyupdate',
          source => 'puppet:///modules/profile/linux/yum-cron_dailyupdate',
          owner  => 'root',
          group  => 'root',
          mode   => '0755',
        }
        class { '::yum_cron':
          ensure           => present,
          apply_updates    => true,
          exclude_packages => [$kubernetes_packages, $other_packages],
          mailto           => lookup('general::mail_receiver_cc'),
          randomwait       => '60',
          debug_level      => '-1',
          extra_configs    => {
            'email/email_from'  => { 'value' => 'yum-cron@topdesk.net'},
            'emitters/emit_via' => { 'value' => 'email'},
          }
        }

        cron { 'yum-cron daily update schedule':
              ensure  => 'absent',
        }

        case $::hostname {
          $regexmonhosts:{
            cron { 'yum_cron':
              ensure  => 'present',
              command => '/etc/yum/schedules/yum-cron_dailyupdate',
              hour    => 13,
              minute  => 30,
              weekday => '*',
            }
          }
          default: {
            cron { 'yum_cron':
              ensure  => 'present',
              command => '/etc/yum/schedules/yum-cron_dailyupdate',
              hour    => 00,
              minute  => 30,
              weekday => '*',
            }
          }
        }
        class { 'ntp':
          servers  => lookup('ntp::servers'),
        }
      }
      else {
        package { ['chrony', 'bc']:
          ensure => present,
        }
        -> file { '/etc/chrony.conf':
        ensure  => file,
        content => epp('profile/linux/chrony.conf.epp', {
          'servers' => lookup('ntp::servers')
          }),
        notify  => Service['chronyd'],
        }
        -> service { 'chronyd':
          ensure => running,
          enable => true,
        }
        package{ 'dnf-automatic':
          ensure => present,
        }
        -> file { '/etc/dnf/automatic.conf':
        ensure  => file,
        content => epp('profile/linux/automatic.conf.epp', {
          'email_from' => lookup('yumautoupdate::from_email'),
          'exclude'    => [$kubernetes_packages, $other_packages]
          })
        }

        service { 'dnf-automatic.timer':
          ensure  => running,
          enable  => true,
          flags   => '--now',
          require => Package['dnf-automatic'],
        }

        if $::hostname =~ $regexmonhosts {
          file_line { 'timer-mon':
            ensure => 'present',
            path   => '/usr/lib/systemd/system/dnf-automatic.timer',
            line   => 'OnCalendar=*-*-* 12:30',
            match  => '^OnCalendar=',
          }
            ~> exec { 'autoupdate-systemd-reload':
                command     => 'systemctl daemon-reload',
                path        => [ '/usr/bin', '/bin', '/usr/sbin' ],
                refreshonly => true,
          }
        }
        else {
          file_line { 'timer-mon':
            ensure => 'present',
            path   => '/usr/lib/systemd/system/dnf-automatic.timer',
            line   => 'OnCalendar=*-*-* 00:30',
            match  => '^OnCalendar=',
        }
          ~> exec { 'autoupdate-systemd-reload':
                command     => 'systemctl daemon-reload',
                path        => [ '/usr/bin', '/bin', '/usr/sbin' ],
                refreshonly => true,
          }
        }
      }
    }
    default:{
      fail('Operating system not supported')
    }
  }

  yumrepo { 'TOPdesk':
    ensure => absent,
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

  file { 'Remove stale /etc/rsyslog.d/client.conf (rsyslog::client manages the 00_client.conf file)':
    ensure => absent,
    path   => '/etc/rsyslog.d/client.conf',
  }

  sysctl { 'kernel.printk': value => '3 4 1 3' }

  $foxit_ids_domain_enabled = lookup('td_splunk_forwarder::foxit_ids_domain_enabled', {'default_value'=>false})
  $foxit_ids_server_enabled = lookup('td_splunk_forwarder::foxit_ids_server_enabled', {'default_value'=>true})
  if (($foxit_ids_domain_enabled) and ($foxit_ids_server_enabled)) {
    rsyslog::imfile { 'audit-imfile':
      file_name     => '/var/log/audit/audit.log',
      file_tag      => 'audit_log',
      file_facility => 'local5',
    }
    file { 'Ensure profile.d script for logging bash history':
      ensure => file,
      path   => '/etc/profile.d/log_bash_history.sh',
      owner  => 'root',
      group  => 'root',
      mode   => '0644',
      source => 'puppet:///modules/profile/td_splunkforwarder/log_bash_history.sh',
    }
    file { 'Place rsyslog client config for Fox-IT SIEM Splunk Forwarder':
      ensure  => file,
      path    => '/etc/rsyslog.d/splunk_forwarder_client.conf',
      owner   => 'root',
      group   => 'root',
      mode    => '0600',
      content => epp('profile/td_splunkforwarder/td_splunk_forwarder_rsyslog_client.conf.epp', {'splunk_forwarder' => lookup('td_splunk_forwarder::splunk_forwarder_linux')}),
      notify  => Service['rsyslog'],
    }
  }

  class { 'firewall': }

  Firewall {
    require         => Class['profile::firewall::pre'],
    before          => Class['profile::firewall::post'],
  }
  class { ['profile::firewall::pre', 'profile::firewall::post']: }

  exec { 'set_timezone_to_Europe/Amsterdam':
    command  => 'timedatectl set-timezone Europe/Amsterdam',
    provider => 'shell',
    path     => ['/bin', '/usr/bin', '/sbin', '/usr/sbin', '/usr/local/bin'],
    onlyif   => 'timezone=$(timedatectl status | grep "Time zone: Europe/Amsterdam"); if [[ -z "$timezone" ]]; then exit 0; else exit 1; fi;'
  }

  $hosting_provider = lookup('general::hosting_provider')
  case $hosting_provider {
    default: {
      package{ 'open-vm-tools':
        ensure => present,
      }
      -> service { 'vmtoolsd':
        ensure => running,
        enable => true,
      }
    }
    'azure': {

    }
  }
  package{ 'psmisc':
    ensure => present,
  }

  $linux_domain_join = lookup('linux::domain_join', { 'default_value' => false })
  if $linux_domain_join {
    $domain = $facts['networking']['domain']
    $domain_join_user = lookup('linux::domain_join_user')
    $domain_join_password = lookup('linux::domain_join_password')
    $domain_join_ou = lookup('linux::domain_join_ou', { 'default_value' => 'OU=Linux servers,OU=SAAS' })
    $fqdn = $facts['networking']['fqdn']
    $hostname = regsubst($fqdn, '\..*$', '')
    $os_name_and_release = "${facts['os']['name']}_${facts['os']['release']['major']}"
    case $os_name_and_release {
      'Ubuntu_20.04': {
        package { ['realmd', 'adcli']:
          ensure => installed,
        }
        exec { 'Set hostname to fqdn':
          command  => "hostnamectl set-hostname ${fqdn}",
          provider => 'shell',
          path     => ['/bin', '/usr/bin', '/sbin', '/usr/sbin', '/usr/local/bin'],
          unless   => "adcli testjoin --domain=${domain} || hostname | grep -q ^${fqdn}\$",
          require  => Package['realmd', 'adcli'],
        }
        exec { 'Join VM to domain':
          command  => Sensitive("echo ${domain_join_password} | realm join --user=${domain_join_user} --computer-ou=\"${domain_join_ou}\" ${domain}"),
          provider => 'shell',
          path     => ['/bin', '/usr/bin', '/sbin', '/usr/sbin', '/usr/local/bin'],
          unless   => "adcli testjoin --domain=${domain} || hostname | grep -qv ^${fqdn}\$",
          require  => Exec['Set hostname to fqdn'],
        }
        exec { 'Set hostname from fqdn back to hostname':
          command  => "hostnamectl set-hostname ${hostname}",
          provider => 'shell',
          path     => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
          onlyif   => "adcli testjoin --domain=${domain} && hostname | grep -q ^${fqdn}\$",
          require  => Exec['Join VM to domain'],
        }
      }
      'CentOS_7': {
        package { ['realmd', 'adcli', 'oddjob', 'oddjob-mkhomedir', 'sssd', 'samba-common-tools']:
          ensure => installed,
        }
        exec { 'Join VM to domain':
          command  => Sensitive("echo ${domain_join_password} | realm join --user=${domain_join_user} --computer-ou=\"${domain_join_ou}\" ${domain}"),
          provider => 'shell',
          path     => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
          unless   => 'adcli testjoin',
          require  => Package['realmd', 'adcli', 'oddjob', 'oddjob-mkhomedir', 'sssd', 'samba-common-tools'],
        }
      }
      default: {
        notify { "OS name and major release ${os_name_and_release} not supported for domain join.": }
      }
    }
  }

  if lookup('linux::create_ansibleuser','default_value'=> false) == true {
    accounts::user {'ansible':
      ensure  => 'present',
      groups  => ['wheel'],
      sshkeys => lookup({'name' => 'linux::ansibleuser::sshkeys','default_value' => 'empty'}),
    }
  }

  $accounts = lookup('profile::linux::accounts')
  $accounts.each |String $account, Hash $attributes| {
    Resource['accounts::user'] {
      $account: * => $attributes;
      default:  * => {
        ensure => present,
        groups => ['wheel'],
      };
    }
  }

  file {'/etc/sudoers.d/topdesk':
    ensure => file,
    owner  => 'root',
    group  => 'root',
    mode   => '0440',
    source => 'puppet:///modules/profile/topdesk_sudo'
  }
  file {'/etc/ssh/sshd_config':
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
  ca_cert::ca { 'saasrca01':
    ensure => 'trusted',
    source => 'puppet:///modules/profile/ca_cert/saasrca01-ca.crt',
  }
  ca_cert::ca { 'acc.loc-root-ca':
    ensure => 'trusted',
    source => 'puppet:///modules/profile/ca_cert/acc.loc-root-ca.crt',
  }
  ca_cert::ca { 'ac1ca01.acc.loc_acc-AC1CA01-CA-1':
    ensure => 'trusted',
    source => 'puppet:///modules/profile/ca_cert/ac1ca01.acc.loc_acc-AC1CA01-CA-1.crt',
  }
  ca_cert::ca { 'general_im':
    ensure => 'trusted',
    source => 'puppet:///modules/profile/ca_cert/general_im.crt',
  }

  include wget
}