#!/bin/bash

export DEBIAN_FRONTEND=noninteractive

PREREQUISITE_PACKAGES=

OBSOLETE_PACKAGES=

print_status() {
  echo
  echo "## $1"
  echo
}

bail() {
  echo 'Error executing command, exiting...'
  exit 1
}

exec_cmd_nobail() {
  echo "+ $1"
  bash -c "$1"
}

exec_cmd() {
  exec_cmd_nobail "$1" || bail
}

apt_install() {
  if [[ -x "/usr/bin/aptitude" ]]; then
    exec_cmd "aptitude install -y $1 > /dev/null 2>&1"
  else
    exec_cmd "apt install -y $1 > /dev/null 2>&1"
  fi
}

apt_purge() {
  if [[ -x "/usr/bin/aptitude" ]]; then
    exec_cmd "aptitude purge -y $1 > /dev/null 2>&1"
  else
    exec_cmd "apt purge -y $1 > /dev/null 2>&1"
  fi
}

apt_update() {
  if [[ -x "/usr/bin/aptitude" ]]; then
    exec_cmd "aptitude update"
  else
    exec_cmd "apt update"
  fi
}

apt_key() {
  if [[ -n "$1" ]]; then
    if [[ -x "/usr/bin/curl" ]]; then
      exec_cmd "curl -sS $1 | apt-key add -"
    else
      exec_cmd "wget -qO- $1 | apt-key add -"
    fi
  fi
}

apt_clean() {
  if [[ -x "/usr/bin/aptitude" ]]; then
    exec_cmd "aptitude update"
  else
    exec_cmd "apt update"
  fi
}

conf() {
  if [[ ! -f "$1" && -n "$2" ]]; then
    exec_cmd "cat > $1 $2"
  fi
}

tmp() {
  if [[ -f "$1" ]]; then
    exec_cmd "rm $1"
  fi

  if [[ -n "$2" ]]; then
    exec_cmd "cat > $1 $2"
  fi
}

apt_conf() {
  conf "$1" "$2"
}

apt_pref() {
  conf "$1" "$2"
}

apt_repo() {
  apt_key "$3"
  conf "$1" "$2"
}

apt_upgrade() {
  if [[ -x "/usr/bin/aptitude" ]]; then
    exec_cmd "aptitude -y safe-upgrade > /dev/null 2>&1"
  else
    exec_cmd "apt upgrade -y > /dev/null 2>&1"
  fi
}

# check for specific package
# Return values:
#  0 - package is installed
#  1 - package is not installed, it is available in package repository
#  2 - package is not installed, it is not available in package repository
package_installed() {
  if dpkg-query -s "$1" 1>/dev/null 2>&1; then
    return 0 # package is installed
  else
    if apt-cache show "$1" 1>/dev/null 2>&1; then
      return 1 # package is not installed, it is available in package repository
    else
      return 2 # package is not installed, it is not available in package repository
    fi
  fi
}

user_exists() {
  if id -u "$1" 1>/dev/null 2>&1; then
    return 0 # user exists
  else
    return 1 # user not exists
  fi
}

directory_not_empty() {
  if [[ $(ls -A "$1") ]]; then
    return 0 # directory not empty
  else
    return 1 # directory empty
  fi
}

debfoster_update() {
  if [[ -x "/usr/bin/debfoster" ]]; then
    exec_cmd "debfoster -q"
  fi
}

install_packages() {
  packages_to_install=
  if [[ -n "$1" ]]; then
    for package in $1; do
      if ! package_installed "${package}"; then
        packages_to_install="${packages_to_install} ${package}"
      fi
    done
  fi

  if [[ -n "${packages_to_install}" ]]; then
    apt_install "${packages_to_install}"
  fi
}

purge_packages() {
  packages_to_purge=
  if [[ -n "$1" ]]; then
    for package in $1; do
      if package_installed "${package}"; then
        packages_to_purge="${packages_to_purge} ${package}"
      fi
    done
  fi

  if [[ -n "${packages_to_purge}" ]]; then
    apt_purge "${packages_to_purge}"
  fi
}

prerequisite_packages() {
  install_packages "${PREREQUISITE_PACKAGES}"
}

obsolete_packages() {
  purge_packages "${OBSOLETE_PACKAGES}"
}

install_unbound() {
  install_packages "unbound"
}

configure_unbound() {
  if package_installed "unbound"; then
    if [[ -f "/etc/unbound/unbound.conf.d/unbound.conf" ]]; then
      exec_cmd "rm /etc/unbound/unbound.conf.d/unbound.conf"
    fi

    if [[ -f "/var/lib/unbound/root.hints" ]]; then
      exec_cmd "rm /var/lib/unbound/root.hints"
    fi

    exec_cmd "wget https://www.internic.net/domain/named.root -O /var/lib/unbound/root.hints"

    conf "/etc/unbound/unbound.conf.d/unbound.conf" "<<EOF
# The server clause sets the main parameters.
server:
	# whitespace is not necessary, but looks cleaner.

	# verbosity number, 0 is least verbose. 1 is default.
	verbosity: 1

	# number of threads to create. 1 disables threading.
	num-threads: 4

	# specify the interfaces to answer queries from by ip-address.
	# The default is to listen to localhost (127.0.0.1 and ::1).
	# specify 0.0.0.0 and ::0 to bind to all available interfaces.
	# specify every interface[@port] on a new 'interface:' labelled line.
	# The listen interfaces are not changed on reload, only on restart.
	# interface: 192.0.2.153
	# interface: 192.0.2.154
	# interface: 192.0.2.154@5003
	# interface: 2001:DB8::5
	interface: 0.0.0.0

	# the amount of memory to use for the message cache.
	# plain value in bytes or you can append k, m or G. default is \"4Mb\".
	msg-cache-size: 128m

	# the number of slabs to use for the message cache.
	# the number of slabs must be a power of 2.
	# more slabs reduce lock contention, but fragment memory usage.
	msg-cache-slabs: 8

	# the amount of memory to use for the RRset cache.
	# plain value in bytes or you can append k, m or G. default is \"4Mb\".
	rrset-cache-size: 256m

	# the number of slabs to use for the RRset cache.
	# the number of slabs must be a power of 2.
	# more slabs reduce lock contention, but fragment memory usage.
	rrset-cache-slabs: 8

	# the time to live (TTL) value lower bound, in seconds. Default 0.
	# If more than an hour could easily give trouble due to stale data.
	cache-min-ttl: 3600

	# the time to live (TTL) value cap for RRsets and messages in the
	# cache. Items are not cached for longer. In seconds.
	cache-max-ttl: 86400

	# the number of slabs to use for the Infrastructure cache.
	# the number of slabs must be a power of 2.
	# more slabs reduce lock contention, but fragment memory usage.
	infra-cache-slabs: 8

	# control which clients are allowed to make (recursive) queries
	# to this server. Specify classless netblocks with /size and action.
	# By default everything is refused, except for localhost.
	# Choose deny (drop message), refuse (polite error reply),
	# allow (recursive ok), allow_setrd (recursive ok, rd bit is forced on),
	# allow_snoop (recursive and nonrecursive ok)
	# deny_non_local (drop queries unless can be answered from local-data)
	# refuse_non_local (like deny_non_local but polite error reply).
	# access-control: 0.0.0.0/0 refuse
	# access-control: 127.0.0.0/8 allow
	# access-control: ::0/0 refuse
	# access-control: ::1 allow
	# access-control: ::ffff:127.0.0.1 allow
	access-control: 192.168.0.0/16 allow

	# file to read root hints from.
	# get one from https://www.internic.net/domain/named.cache
	root-hints: \"/var/lib/unbound/root.hints\"

	# enable to not answer id.server and hostname.bind queries.
	hide-identity: yes

	# enable to not answer version.server and version.bind queries.
	hide-version: yes

	# Harden against out of zone rrsets, to avoid spoofing attempts.
	harden-glue: yes

	# Harden against receiving dnssec-stripped data. If you turn it
	# off, failing to validate dnskey data for a trustanchor will
	# trigger insecure mode for that zone (like without a trustanchor).
	# Default on, which insists on dnssec data for trust-anchored zones.
	harden-dnssec-stripped: yes

	# Use 0x20-encoded random bits in the query to foil spoof attempts.
	# This feature is an experimental implementation of draft dns-0x20.
	use-caps-for-id: yes

	# Enforce privacy of these addresses. Strips them away from answers.
	# It may cause DNSSEC validation to additionally mark it as bogus.
	# Protects against 'DNS Rebinding' (uses browser as network proxy).
	# Only 'private-domain' and 'local-data' names are allowed to have
	# these private addresses. No default.
	# private-address: 10.0.0.0/8
	# private-address: 172.16.0.0/12
	# private-address: 192.168.0.0/16
	# private-address: 169.254.0.0/16
	# private-address: fd00::/8
	# private-address: fe80::/10
	# private-address: ::ffff:0:0/96
	private-address: 192.168.0.0/16

	# Allow the domain (and its subdomains) to contain private addresses.
	# local-data statements are allowed to contain private addresses too.
	# private-domain: \"example.com\"

	# If nonzero, unwanted replies are not only reported in statistics,
	# but also a running total is kept per thread. If it reaches the
	# threshold, a warning is printed and a defensive action is taken,
	# the cache is cleared to flush potential poison out of it.
	# A suggested value is 10000000, the default is 0 (turned off).
	unwanted-reply-threshold: 10000

	# if yes, perform prefetching of almost expired message cache entries.
	prefetch: yes

	# Should additional section of secure message also be kept clean of
	# unsecure data. Useful to shield the users of this validator from
	# potential bogus data in the additional section. All unsigned data
	# in the additional section is removed from secure messages.
	val-clean-additional: yes

	# the number of slabs to use for the key cache.
	# the number of slabs must be a power of 2.
	# more slabs reduce lock contention, but fragment memory usage.
	key-cache-slabs: 8

# Stub zones.
# Create entries like below, to make all queries for 'example.com' and
# 'example.org' go to the given list of nameservers. list zero or more
# nameservers by hostname or by ipaddress. If you set stub-prime to yes,
# the list is treated as priming hints (default is no).
# With stub-first yes, it attempts without the stub if it fails.
# Consider adding domain-insecure: name and local-zone: name nodefault
# to the server: section if the stub is a locally served zone.
# stub-zone:
#	name: \"example.com\"
#	stub-addr: 192.0.2.68
#	stub-prime: no
#	stub-first: no
#	stub-tls-upstream: no
#	stub-no-cache: no
# stub-zone:
#	name: \"example.org\"
#	stub-host: ns.example.com.

# Forward zones
# Create entries like below, to make all queries for 'example.com' and
# 'example.org' go to the given list of servers. These servers have to handle
# recursion to other nameservers. List zero or more nameservers by hostname
# or by ipaddress. Use an entry with name \".\" to forward all queries.
# If you enable forward-first, it attempts without the forward if it fails.
# forward-zone:
# 	name: \"example.com\"
# 	forward-addr: 192.0.2.68
# 	forward-addr: 192.0.2.73@5355  # forward to port 5355.
# 	forward-first: no
# 	forward-tls-upstream: no
#	forward-no-cache: no
# forward-zone:
# 	name: \"example.org\"
# 	forward-host: fwd.example.com
forward-zone:
	name: \".\"
	forward-addr: 1.0.0.1@53#cloudflare
	forward-addr: 1.1.1.1@53#cloudflare
	forward-addr: 8.8.8.8@53#google
	forward-addr: 8.8.4.4@53#google
	forward-addr: 9.9.9.9@53#quad9
	forward-addr: 149.112.112.112@53#quad9
EOF"
  fi
}

restart_unbound() {
  exec_cmd "systemctl restart unbound.service"
}

setup() {
  if [[ $EUID -ne 0 ]]; then
    exit 1
  fi

  prerequisite_packages
  debfoster_update

  obsolete_packages
  debfoster_update

  install_unbound
  debfoster_update
  configure_unbound
  restart_unbound
}

if [[ $# -ne 0 ]]; then
  bail
fi

setup
