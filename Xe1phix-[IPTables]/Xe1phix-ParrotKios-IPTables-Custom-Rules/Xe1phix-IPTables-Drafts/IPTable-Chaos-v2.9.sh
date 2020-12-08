#!/bin/bash
# Bastion Host IPTables Script
# VARIABLES - Change these to match your environment.
# Location of the binaries
IPT="/sbin/iptables"
IP6T="/sbin/ip6tables"
inet6=
inet=
SYSCTL="/sbin/sysctl"
IPTABLESSAVE=/sbin/iptables-save
IPTABLESRESTORE=/sbin/iptables-restore

MODPROBE=/sbin/modprobe
# Loopback Interface
LOOPBACK="lo"
# Define External Network
EXT_INTER="eth0"

/etc/network/if-pre-up.d/wireless-tools

	echo -n "Verifying ethernet interface existence..."
	# Verify ethernet interface exist.
	if ! ifconfig ${ETHER_INTF}: >/dev/null 2>&1; then
		echo "Error: interface ${ETHER_INTF} does not exist"
		exit 1
	fi
	ifconfig ${ETHER_INTF} up || exit 1
	echo "done"



		echo "Currently active devices:"
		echo `/sbin/ifconfig | grep ^[a-z] | awk '{print $1}'`



if [ -z "${2}" ]; then
    link_status=`ip link show $1 2>/dev/null`
    if [ -n "${link_status}" ]; then
        if echo "${link_status}" | grep -q UP; then
            boot_mesg "Bringing down the ${1} interface..."
            ip link set ${1} down
            evaluate_retval



[ -n "$ROOT_USER" ] || ROOT_USER="$(id -u root)"
[ -n "$TOR_USER" ] || TOR_USER="$(id -u debian-tor)"






SOCKS_PORT_TOR_DEFAULT="9050"
FLASHPROXY_PORT="9000"
CONTROL_PORT_FILTER_PROXY_PORT="9052"

SOCKS_PORT_IRC="9101"
SOCKS_PORT_TORBIRDY="9102"
SOCKS_PORT_APT_GET="9104"
[ -n "$SOCKS_PORT_IM" ] || SOCKS_PORT_IM="9103"
[ -n "$SOCKS_PORT_APT_GET" ] || SOCKS_PORT_APT_GET="9104"
[ -n "$SOCKS_PORT_GPG" ] || SOCKS_PORT_GPG="9105"
[ -n "$SOCKS_PORT_SSH" ] || SOCKS_PORT_SSH="9106"
[ -n "$SOCKS_PORT_GIT" ] || SOCKS_PORT_GIT="9107"
[ -n "$SOCKS_PORT_SDWDATE" ] || SOCKS_PORT_SDWDATE="9108"
[ -n "$SOCKS_PORT_WGET" ] || SOCKS_PORT_WGET="9109"
[ -n "$SOCKS_PORT_WHONIXCHECK" ] || SOCKS_PORT_WHONIXCHECK="9110"
[ -n "$SOCKS_PORT_BITCOIN" ] || SOCKS_PORT_BITCOIN="9111"
[ -n "$SOCKS_PORT_PRIVOXY" ] || SOCKS_PORT_PRIVOXY="9112"
[ -n "$SOCKS_PORT_POLIPO" ] || SOCKS_PORT_POLIPO="9113"
[ -n "$SOCKS_PORT_WHONIX_NEWS" ] || SOCKS_PORT_WHONIX_NEWS="9114"
[ -n "$SOCKS_PORT_TBB_DOWNLOAD" ] || SOCKS_PORT_TBB_DOWNLOAD="9115"
[ -n "$SOCKS_PORT_TBB_GPG" ] || SOCKS_PORT_TBB_GPG="9116"
[ -n "$SOCKS_PORT_CURL" ] || SOCKS_PORT_CURL="9117"
[ -n "$SOCKS_PORT_RSS" ] || SOCKS_PORT_RSS="9118"
[ -n "$SOCKS_PORT_TORCHAT" ] || SOCKS_PORT_TORCHAT="9119"
[ -n "$SOCKS_PORT_MIXMASTERUPDATE" ] || SOCKS_PORT_MIXMASTERUPDATE="9120"
[ -n "$SOCKS_PORT_MIXMASTER" ] || SOCKS_PORT_MIXMASTER="9121"
[ -n "$SOCKS_PORT_KDE" ] || SOCKS_PORT_KDE="9122"
[ -n "$SOCKS_PORT_GNOME" ] || SOCKS_PORT_GNOME="9123"
[ -n "$SOCKS_PORT_APTITUDE" ] || SOCKS_PORT_APTITUDE="9124"
[ -n "$SOCKS_PORT_YUM" ] || SOCKS_PORT_YUM="9125"
[ -n "$SOCKS_PORT_TBB_DEFAULT" ] || SOCKS_PORT_TBB_DEFAULT="9150"

# Whonix-Gateway Ports:
DNS_PORT_GATEWAY="5400"
TRANS_PORT_GATEWAY="9041"

# Whonix-Workstation Ports:
DNS_PORT_WORKSTATION="5300"
TRANS_PORT_WORKSTATION="9040"

## Transparent Proxy Ports for Whonix-Workstation
[ -n "$TRANS_PORT_WORKSTATION" ] || TRANS_PORT_WORKSTATION="9040"
[ -n "$DNS_PORT_WORKSTATION" ] || DNS_PORT_WORKSTATION="5300"

## Transparent Proxy Ports for Whonix-Gateway
[ -n "$TRANS_PORT_GATEWAY" ] || TRANS_PORT_GATEWAY="9041"
[ -n "$DNS_PORT_GATEWAY" ] || DNS_PORT_GATEWAY="5400"

## Control Port Filter Proxy Port
[ -n "$CONTROL_PORT_FILTER_PROXY_PORT" ] || CONTROL_PORT_FILTER_PROXY_PORT="9052"

## Flash Proxy Port
[ -n "$FLASHPROXY_PORT" ] || FLASHPROXY_PORT="9000"

## Socks Ports for per application circuits.
[ -n "$SOCKS_PORT_TOR_DEFAULT" ] || SOCKS_PORT_TOR_DEFAULT="9050"
[ -n "$SOCKS_PORT_TB" ] || SOCKS_PORT_TB="9100"
[ -n "$SOCKS_PORT_IRC" ] || SOCKS_PORT_IRC="9101"
[ -n "$SOCKS_PORT_TORBIRDY" ] || SOCKS_PORT_TORBIRDY="9102"
[ -n "$SOCKS_PORT_IM" ] || SOCKS_PORT_IM="9103"
[ -n "$SOCKS_PORT_APT_GET" ] || SOCKS_PORT_APT_GET="9104"
[ -n "$SOCKS_PORT_GPG" ] || SOCKS_PORT_GPG="9105"
[ -n "$SOCKS_PORT_SSH" ] || SOCKS_PORT_SSH="9106"
[ -n "$SOCKS_PORT_GIT" ] || SOCKS_PORT_GIT="9107"
[ -n "$SOCKS_PORT_SDWDATE" ] || SOCKS_PORT_SDWDATE="9108"
[ -n "$SOCKS_PORT_WGET" ] || SOCKS_PORT_WGET="9109"
[ -n "$SOCKS_PORT_WHONIXCHECK" ] || SOCKS_PORT_WHONIXCHECK="9110"
[ -n "$SOCKS_PORT_BITCOIN" ] || SOCKS_PORT_BITCOIN="9111"
[ -n "$SOCKS_PORT_PRIVOXY" ] || SOCKS_PORT_PRIVOXY="9112"
[ -n "$SOCKS_PORT_POLIPO" ] || SOCKS_PORT_POLIPO="9113"
[ -n "$SOCKS_PORT_WHONIX_NEWS" ] || SOCKS_PORT_WHONIX_NEWS="9114"
[ -n "$SOCKS_PORT_TBB_DOWNLOAD" ] || SOCKS_PORT_TBB_DOWNLOAD="9115"
[ -n "$SOCKS_PORT_TBB_GPG" ] || SOCKS_PORT_TBB_GPG="9116"
[ -n "$SOCKS_PORT_CURL" ] || SOCKS_PORT_CURL="9117"
[ -n "$SOCKS_PORT_RSS" ] || SOCKS_PORT_RSS="9118"
[ -n "$SOCKS_PORT_TORCHAT" ] || SOCKS_PORT_TORCHAT="9119"
[ -n "$SOCKS_PORT_MIXMASTERUPDATE" ] || SOCKS_PORT_MIXMASTERUPDATE="9120"
[ -n "$SOCKS_PORT_MIXMASTER" ] || SOCKS_PORT_MIXMASTER="9121"
[ -n "$SOCKS_PORT_KDE" ] || SOCKS_PORT_KDE="9122"
[ -n "$SOCKS_PORT_GNOME" ] || SOCKS_PORT_GNOME="9123"
[ -n "$SOCKS_PORT_APTITUDE" ] || SOCKS_PORT_APTITUDE="9124"
[ -n "$SOCKS_PORT_YUM" ] || SOCKS_PORT_YUM="9125"
[ -n "$SOCKS_PORT_TBB_DEFAULT" ] || SOCKS_PORT_TBB_DEFAULT="9150"




if [ -d "" ]; then

###########################
## NON_TOR_GATEWAY
###########################

if [ "$NON_TOR_GATEWAY" = "" ]; then
   if [ -d "/usr/lib/qubes" ]; then
      NON_TOR_GATEWAY="\
         127.0.0.0-127.0.0.24 \
         10.137.0.0-10.137.255.255 \
      "
   else
      ## 10.0.2.2-10.0.2.24: VirtualBox DHCP
      NON_TOR_GATEWAY="\
         127.0.0.0-127.0.0.24 \
         192.168.0.0-192.168.0.24 \
         192.168.1.0-192.168.1.24 \
         10.152.152.0-10.152.152.24 \
         10.0.2.2-10.0.2.24 \
      "
   fi
fi



VPN_INTERFACE="tun0"
VPN_SERVERS="198.252.153.26"







EXT_ADDR="220.240.52.228"
# Define External Servers
EXT_NTP1="clock3.redhat.com"
EXT_NTP2="ntp.public.otago.ac.nz"
# Define Internal Network
Ethernet="eth0"
interface="wlan0"
interface2="wlan1"
interface3="wlan2"

INT_ADDR="192.168.0.100"
INT_NET="192.168.0.0/24"
# Define Internal Servers
INT_SMTP="192.168.0.20"
INT_DNS1="192.168.0.10"
INT_DNS2="192.168.0.11"


LOG="LOG --log-level debug --log-tcp-sequence --log-tcp-options"
LOG="$LOG --log-ip-options"



# Load kernel modules first
$MODPROBE ip_conntrack_ftp
$MODPROBE ip_conntrack_irc

modprobe ip_tables
modprobe ip_conntrack_ftp
# Set Kernel Parameters
/sbin/sysctl -q -w net/ipv4/conf/all/accept_redirects="0"
/sbin/sysctl -q -w net/ipv4/conf/all/accept_source_route="0"
/sbin/sysctl -q -w net/ipv4/conf/all/log_martians="1"
/sbin/sysctl -q -w net/ipv4/conf/all/rp_filter="1"
/sbin/sysctl -q -w net/ipv4/icmp_echo_ignore_all="0"
/sbin/sysctl -q -w net/ipv4/icmp_echo_ignore_broadcasts="1"
/sbin/sysctl -q -w net/ipv4/icmp_ignore_bogus_error_responses="0"
/sbin/sysctl -q -w net/ipv4/ip_forward="0"
/sbin/sysctl -q -w net/ipv4/tcp_syncookies="1"
dev.cdrom.check_media="1"
kernel.kptr_restric=
	- CONFIG_IP_SET_HASH_IPPORT
	- CONFIG_IP_SET_HASH_NET
	- CONFIG_IP_NF_TARGET_MASQUERADE
	- CONFIG_IP_NF_TARGET_REJECT
	- CONFIG_NETFILTER_XT_TARGET_LOG
	- CONFIG_NF_CONNTRACK_IPV4
	
	


if [ -e /sbin/iptables ]; then
    IPTABLES=/sbin/iptables
else
    IPTABLES=/usr/sbin/iptables
fi






echo "Querying iptables status (via iptables --list)..."
$IPTABLES --line-numbers -v --list

echo "Listing Your Rules"
iptables -L INPUT -n --line-numbers
echo "displayed all the rules from all chains."
iptables -L -n --line-numbers
echo "shows the rules contained in the nat table"
iptables -t nat -L
echo "view the POSTROUTING chain in the nat table"
iptables -t nat -L POSTROUTING
echo "Displaying Rules and Their Counters"
iptables -L -v
ipchains -L -v



$IPTABLES -t nat -P PREROUTING DROP
$IPTABLES -t nat -P OUTPUT DROP
$IPTABLES -t nat -P POSTROUTING DROP

$IPTABLES -t mangle -P PREROUTING DROP
$IPTABLES -t mangle -P INPUT DROP
$IPTABLES -t mangle -P FORWARD DROP
$IPTABLES -t mangle -P OUTPUT DROP
$IPTABLES -t mangle -P POSTROUTING DROP


/sbin/iptables -t nat -F
/sbin/iptables -t nat -P PREROUTING DROP
/sbin/iptables -t nat -P INPUT DROP
/sbin/iptables -t nat -P OUTPUT DROP
/sbin/iptables -t nat -P POSTROUTING DROP

# Flush all Rules
/sbin/ip6tables -F
iptables -F
iptables -X
/sbin/ip6tables -X
iptables -t nat -F
iptables -t nat -X
iptables -t mangle -F
iptables -t mangle -X

#Set Policies
/sbin/iptables --policy INPUT DROP
/sbin/iptables --policy OUTPUT DROP
/sbin/iptables --policy FORWARD DROP

for iface in `ls /proc/sys/net/ipv6/conf/{wlan*,eth0,default,all}/disable_ipv6 2> /dev/null`; do
        echo "1" > $iface
    done

    # completely disable ipv6
/sbin/ip6tables -F
/sbin/ip6tables -P INPUT DROP
/sbin/ip6tables -P OUTPUT DROP
/sbin/ip6tables -P FORWARD DROP
/sbin/ip6tables -A INPUT -j REJECT
/sbin/ip6tables -A OUTPUT -j REJECT
/sbin/ip6tables -A FORWARD -j REJECT
/sbin/iptables -A OUTPUT --out-interface "$interface" -j REJECT
/sbin/iptables -A OUTPUT --out-interface "$interface" -j DROP
/sbin/iptables -A INPUT --in-interface "$interface" -j DROP
/sbin/iptables -A INPUT --in-interface "$interface" -j REJECT
/sbin/iptables -A OUTPUT --out-interface lo -j DROP
/sbin/iptables -A OUTPUT --in-interface lo -j DROP
/sbin/iptables -A INPUT --in-interface lo -j DROP
/sbin/iptables -A INPUT --out-interface lo -j REJECT
/sbin/ip6tables 
/sbin/ip6tables -A INPUT --in-interface lo -j DROP
/sbin/ip6tables -A OUTPUT --out-interface lo -j DROP
/sbin/ip6tables -A INPUT --in-interface lo -j REJECT
/sbin/ip6tables -A OUTPUT --out-interface lo -j REJECT
/sbin/ip6tables -t nat -A PREROUTING -j DROP
/sbin/ip6tables -t nat -A PREROUTING -j REJECT
/sbin/ip6tables -t nat -A POSTROUTING -j DROP
/sbin/ip6tables -t nat -A POSTROUTING -j REJECT
/sbin/ip6tables -t nat -A FORWARD -j DROP
/sbin/ip6tables -t nat -A FORWARD -j REJECT



	if [ $ipv6_available -eq 0 ]; then
		${fwcmd} add 400 deny all from any to ::1
		${fwcmd} add 500 deny all from ::1 to any
	fi
}

fe80::/10
 ff02::/16
fc00::/7
fec0::/10
::ffff:0.0.0.0/96

# prevent kernel bug transproxy leak
# https://lists.torproject.org/pipermail/tor-talk/2014-March/032507.html
/sbin/iptables -A OUTPUT -m conntrack --ctstate INVALID -j LOG --log-prefix "Transproxy ctstate leak blocked: " --log-uid
/sbin/iptables -A OUTPUT -m conntrack --ctstate INVALID -j DROP
/sbin/iptables -A OUTPUT -m state --state INVALID -j LOG --log-prefix "Transproxy state leak blocked: " --log-uid
/sbin/iptables -A OUTPUT -m state --state INVALID -j DROP
/sbin/iptables -A INPUT -m state --state ESTABLISHED -j DROP
/sbin/ip6tables -A INPUT -m state --state ESTABLISHED -j DROP
/sbin/iptables -A 
iptables -A INPUT 
iptables -A OUTPUT 
iptables -A FORWARD
/sbin/iptables -t nat -A
iptables -t mangle -A 


INPUT -d 127.0.0.0/255.0.0.0 -i ! lo -p tcp -j DROP
 -m state --state RELATED,ESTABLISHED -j ACCEPT

INPUT -d 192.168.100.25 -p tcp -m tcp --dport 22 -j LOG --log-prefix "ssh:"

iptables -A SSH -m limit --limit 3/min --limit-burst 3 -j ACCEPT
iptables -P SSH DROP





::1/128
/sbin/iptables -A OUTPUT ! -o lo ! -d 127.0.0.1 ! -s 127.0.0.1 -p tcp -m tcp --tcp-flags ACK,FIN ACK,FIN -j LOG --log-prefix "Transproxy leak blocked: " --log-uid
/sbin/iptables -A OUTPUT ! -o lo ! -d 127.0.0.1 ! -s 127.0.0.1 -p tcp -m tcp --tcp-flags ACK,RST ACK,RST -j LOG --log-prefix "Transproxy leak blocked: " --log-uid
/sbin/iptables -A OUTPUT ! -o lo ! -d 127.0.0.1 ! -s 127.0.0.1 -p tcp -m tcp --tcp-flags ACK,FIN ACK,FIN -j DROP
/sbin/iptables -A OUTPUT ! -o lo ! -d 127.0.0.1 ! -s 127.0.0.1 -p tcp -m tcp --tcp-flags ACK,RST ACK,RST -j DROP

## DROP PACKETS WITH INCOMING FRAGMENTS. THIS ATTACK ONCE RESULTED IN KERNEL PANICS
iptables -A INPUT -f -j DROP
/sbin/iptables -A INPUT -i lo -j DROP
## DROP INVALID
iptables -A INPUT -m state --state INVALID -j DROP
## DROP INCOMING MALFORMED XMAS PACKETS
iptables -A INPUT -p tcp --tcp-flags ALL ALL -j DROP
## DROP INVALID SYN PACKETS
iptables -A INPUT -p tcp --tcp-flags ALL ACK,RST,SYN,FIN -j DROP
iptables -A INPUT -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP
iptables -A INPUT -p tcp --tcp-flags SYN,RST SYN,RST -j DROP

## DROP INCOMING MALFORMED NULL PACKETS
iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP


iptables -I FORWARD 1 -p tcp --dport 80 -m state --state ESTABLISHED -m string --string "/etc/shadow" --algo bm -j LOG --log-prefix "ETC_SHADOW "

iptables -I FORWARD 1 -p tcp --dport 443 -m state --state ESTABLISHED -m string --string "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" -j LOG --log-prefix "SSL OVERFLOW "

iptables -I FORWARD 1 -p tcp --dport 21 -m state --state ESTABLISHED -m string --string "site" --algo bm -m string --string "chown" --algo bm -m length --length 140 -j LOG --log-prefix "CHOWN OVERFLOW "

iptables -I FORWARD 1 -p tcp --dport 1433 -m state --state ESTABLISHED -m string --hex-string "'|00|" --algo bm -m string --hex-string "-|00|-|00|" --algo bm -j LOG --log-prefix "SQL INJECTION COMMENT "

iptables -I FORWARD 1 -p tcp -m state --state ESTABLISHED -m string --hex-string "RemoteNC Control Password|3A|" --algo bm -j LOG --log-ip-options --log-tcp-options --log-prefix "FSSNIFFER BACKDOOR "

iptables -I FORWARD 1 -p tcp --dport 25 -m state --state ESTABLISHED -m string --string "http://196.41.X.X/sys/" --algo bm -m string --hex-string "window.status=|27|https://www.citibank.com" -j LOG --log-prefix "CITIBANK PHISH "



# Do some rudimentary anti-IP-spoofing drops
$IPTABLES -A INPUT -s 255.0.0.0/8 -j LOG --log-prefix "Spoofed source IP!"



#Catch portscanners
einfo "Creating portscan detection chain"
$IPTABLES -N check-flags
$IPTABLES -F check-flags
$IPTABLES -A check-flags -p tcp --tcp-flags ALL FIN,URG,PSH -m limit \
--limit 5/minute -j LOG --log-level alert --log-prefix "NMAP-XMAS:"
$IPTABLES -A check-flags -p tcp --tcp-flags ALL FIN,URG,PSH -j DROP
$IPTABLES -A check-flags -p tcp --tcp-flags ALL ALL -m limit --limit \
5/minute -j LOG --log-level 1 --log-prefix "XMAS:"
$IPTABLES -A check-flags -p tcp --tcp-flags ALL ALL -j DROP
$IPTABLES -A check-flags -p tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG \
-m limit --limit 5/minute -j LOG --log-level 1 --log-prefix "XMAS-PSH:"
$IPTABLES -A check-flags -p tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG -j DROP






$IPTABLES -A check-flags -p tcp --tcp-flags ALL NONE -m limit \
--limit 5/minute -j LOG --log-level 1 --log-prefix "NULL_SCAN:"
$IPTABLES -A check-flags -p tcp --tcp-flags ALL NONE -j DROP
$IPTABLES -A check-flags -p tcp --tcp-flags SYN,RST SYN,RST -m limit \
--limit 5/minute -j LOG --log-level 5 --log-prefix "SYN/RST:"
$IPTABLES -A check-flags -p tcp --tcp-flags SYN,RST SYN,RST -j DROP
$IPTABLES -A check-flags -p tcp --tcp-flags SYN,FIN SYN,FIN -m limit \
--limit 5/minute -j LOG --log-level 5 --log-prefix "SYN/FIN:"
$IPTABLES -A check-flags -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP









0.0.0.0/8 -j LOG --log-prefix "Spoofed source"

$IPTABLES -A INPUT -s 255.0.0.0/8 -j DROP
$IPTABLES -A INPUT -s 0.0.0.0/8 -j LOG --log-prefix "Spoofed source IP!"
$IPTABLES -A INPUT -s 0.0.0.0/8 -j DROP
$IPTABLES -A INPUT -s 127.0.0.0/8 -j LOG --log-prefix "Spoofed source IP!"
$IPTABLES -A INPUT -s 127.0.0.0/8 -j DROP
$IPTABLES -A INPUT -s 192.168.0.0/16 -j LOG --log-prefix "Spoofed source IP!"
$IPTABLES -A INPUT -s 192.168.0.0/16 -j DROP
$IPTABLES -A INPUT -s 172.16.0.0/12 -j LOG --log-prefix " Spoofed source IP!"
$IPTABLES -A INPUT -s 172.16.0.0/12 -j DROP
$IPTABLES -A INPUT -s 10.0.0.0/8 -j LOG --log-prefix " Spoofed source IP!"
$IPTABLES -A INPUT -s 10.0.0.0/8 -j DROP
$IPTABLES -A INPUT -s 208.13.201.2 -j LOG --log-prefix "Spoofed Woofgang!"
$IPTABLES -A INPUT -s 208.13.201.2 -j DROP




# Delete all User-created Chains
$IPT -X
# Allow access to the Loopback host

 -A INPUT -i "$VPN_INTERFACE" -j DENY

/sbin/iptables -A INPUT  -i lo -j DENY
/sbin/iptables -A OUTPUT -o lo -j DENY
$IPT -A INPUT -i lo -j DROP
ip6tables -A INPUT -i $LOOPBACK -j DROP
$IPT -A OUTPUT -o $LOOPBACK -j DROP
ip6tables -A OUTPUT -o $LOOPBACK -j DROP
iptables -A INPUT ! -i lo -d 127.0.0.1/8 -j DROP
iptables -A INPUT -j DROP
ipv6tables -A INPUT -j DROP


/sbin/iptables -t nat    --delete-chain
/sbin/iptables -t mangle --delete-chain

## Reject anything not explicitly allowed above.
## Drop is better than reject here, because ...
iptables -A INPUT -j DROP


## Log.
iptables -A FORWARD -j LOG --log-prefix "Firewall blocked forward4: "
iptables -A OUTPUT -j LOG --log-prefix "Firewall blocked output4: "
iptables -A INPUT -j LOG --log-prefix "Firewall blocked input4: "

## Reject everything.
iptables -A FORWARD -j REJECT --reject-with icmp-admin-prohibited

--checksum-fill
# create audit records for packets hitting the target
iptables -A AUDIT_DROP -j AUDIT --type drop
iptables -A INPUT -p sctp --dport 80 -j DROP

iptables -A INPUT -p sctp --chunk-types any DATA,INIT -j DROP

######################################
## IPv4 DROP INVALID INCOMING PACKAGES
######################################

echo "## DROP INVALID"
/sbin/iptables -A INPUT -m conntrack --ctstate INVALID -j DROP
/sbin/iptables -A INPUT -m state --state INVALID -j DROP
/sbin/iptables -A INPUT -m state --state INVALID -j LOG --log-prefix "DROP INVALID " --log-tcp-options --log-ip-options
/sbin/iptables -A INPUT -m state --state INVALID -j DROP
/sbin/iptables -A INPUT -s ! 192.168.10.0/255.255.255.0 -i eth1 -j LOG --log-prefix "SPOOFED PKT "
/sbin/iptables -A INPUT -s ! 192.168.10.0/255.255.255.0 -i eth1 -j DROP

iptables -I OUTPUT 1 -d target -p tcp --tcp-flags RST RST -j DROP


iptables -A INPUT -m state --state NEW,ESTABLISHED -j DROP
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j DROP
iptables -A OUTPUT -m state --state NEW,ESTABLISHED -j DROP
iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j DROP
iptables -A FORWARD -m state --state NEW,ESTABLISHED -j DROP
iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j DROP


ESTABLISHED
echo "## DROP INVALID SYN PACKETS"
/sbin/iptables -A INPUT -p tcp --tcp-flags ALL ACK,RST,SYN,FIN -j DROP
/sbin/iptables -A INPUT -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP
/sbin/iptables -A INPUT -p tcp --tcp-flags SYN,RST SYN,RST -j DROP

echo "## DROP PACKETS WITH INCOMING FRAGMENTS. "
echo "THIS ATTACK ONCE RESULTED IN KERNEL PANICS"
/sbin/iptables  -A INPUT -f -j DROP

echo "## DROP INCOMING MALFORMED XMAS PACKETS"
/sbin/iptables -A INPUT -p tcp --tcp-flags ALL ALL -j DROP

echo "## DROP INCOMING MALFORMED NULL PACKETS"
/sbin/iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP


Create ICMP Incoming Chain
$IPT -N ICMP_IN
# Pass ICMP Incoming Traffic to the ICMP Incoming Chain
$IPT -A INPUT -p icmp -j ICMP_IN
# Rules for ICMP Incoming Traffic
$IPT -A ICMP_IN -i $EXT_INTER -p icmp --icmp-type 0 -m state --state ➥
ESTABLISHED,RELATED -j ACCEPT
$IPT -A ICMP_IN -i $EXT_INTER -p icmp --icmp-type 3 -m state --state ➥
ESTABLISHED,RELATED -j ACCEPT
$IPT -A ICMP_IN -i $EXT_INTER -p icmp --icmp-type 11 -m state --state ➥
ESTABLISHED,RELATED -j ACCEPT
$IPT -A ICMP_IN -i $EXT_INTER -p icmp -j LOG --log-prefix ➥
"IPT: ICMP_IN " $IPT -A ICMP_IN -i $EXT_INTER -p icmp -j DROP
# Create ICMP Outgoing Chain
$IPT -N ICMP_OUT
# Pass ICMP Outgoing Traffic to the ICMP Outgoing Chain
$IPT -A OUTPUT -p icmp -j ICMP_OUT
# Rules for ICMP
$IPT -A ICMP_OUT
NEW -j ACCEPT
$IPT -A ICMP_OUT
$IPT -A ICMP_OUT
Outgoing Traffic
-o $EXT_INTER -p icmp --icmp-type 8 -m state --state ➥
-o $EXT_INTER -p icmp -j LOG --log-prefix "IPT: ICMP_OUT "
-o $EXT_INTER -p icmp -j DROP
# Create Bad Sources Chain
$IPT -N BAD_SOURCES
# Pass traffic with bad source addresses to the Bad Sources Chain
$IPT -A INPUT -j BAD_SOURCES
# Rules for traffic with bad source addresses
# Drop incoming traffic allegedly from our own host
$IPT -A BAD_SOURCES -i $INT_INTER -s $INT_ADDR -j DROP
$IPT -A BAD_SOURCES -i $EXT_INTER -s $EXT_ADDR -j DROP
# Drop outgoing traffic not from our own host
$IPT -A BAD_SOURCES -o $INT_INTER -s ! $INT_ADDR -j DROP
$IPT -A BAD_SOURCES -o $EXT_INTER -s ! $EXT_ADDR -j DROP
# Drop traffic from
$IPT -A BAD_SOURCES
$IPT -A BAD_SOURCES
$IPT -A BAD_SOURCES
$IPT -A BAD_SOURCES
$IPT -A BAD_SOURCES
$IPT -A BAD_SOURCES
$IPT -A BAD_SOURCES
$IPT -A BAD_SOURCES
$IPT -A BAD_SOURCES
$IPT -A BAD_SOURCES
$IPT -A BAD_SOURCES
other bad sources
-s 168.254.0.0/16 -j DROP
-i $EXT_INTER -s 10.0.0.0/8 -j DROP
-i $EXT_INTER -s 172.16.0.0/12 -j DROP
-i $EXT_INTER -s 192.168.0.0/16 -j DROP
-i $EXT_INTER -s 192.0.2.0/24 -j DROP
-i $EXT_INTER -s 224.0.0.0/4 -j DROP
-i $EXT_INTER -s 240.0.0.0/5 -j DROP
-i $EXT_INTER -s 248.0.0.0/5 -j DROP
-i $EXT_INTER -s 127.0.0.0/8 -j DROP
-i $EXT_INTER -s 255.255.255.255/32 -j DROP
-i $EXT_INTER -s 0.0.0.0/8 -j DROP


# Create Bad Flags Chain
$IPT -N BAD_FLAGS
# Pass traffic with bad flags to the Bad Flags Chain
$IPT -A INPUT -p tcp -j BAD_FLAGS
# Rules for traffic with bad flags
$IPT -A BAD_FLAGS -p tcp --tcp-flags SYN,FIN SYN,FIN -j LOG --log-prefix "IPT: Bad SF Flag "
$IPT -A BAD_FLAGS -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP
$IPT -A BAD_FLAGS -p tcp --tcp-flags SYN,RST SYN,RST -j LOG --log-prefix "IPT: Bad SR Flag "
$IPT -A BAD_FLAGS -p tcp --tcp-flags SYN,RST SYN,RST -j DROP
$IPT -A BAD_FLAGS -p tcp --tcp-flags SYN,FIN,PSH SYN,FIN,PSH -j LOG --log-prefix "IPT: Bad SFP Flag "
$IPT -A BAD_FLAGS -p tcp --tcp-flags SYN,FIN,PSH SYN,FIN,PSH -j DROP
$IPT -A BAD_FLAGS -p tcp --tcp-flags SYN,FIN,RST SYN,FIN,RST -j LOG --log-prefix "IPT: Bad SFR Flag "
$IPT -A BAD_FLAGS -p tcp --tcp-flags SYN,FIN,RST SYN,FIN,RST -j DROP
$IPT -A BAD_FLAGS -p tcp --tcp-flags SYN,FIN,RST,PSH SYN,FIN,RST,PSH -j LOG --log-prefix "IPT: Bad SFRP Flag "
$IPT -A BAD_FLAGS -p tcp --tcp-flags SYN,FIN,RST,PSH SYN,FIN,RST,PSH -j DROP
$IPT -A BAD_FLAGS -p tcp --tcp-flags FIN FIN -j LOG --log-prefix "IPT: Bad F Flag "
$IPT -A BAD_FLAGS -p tcp --tcp-flags FIN FIN -j DROP
$IPT -A BAD_FLAGS -p tcp --tcp-flags ALL NONE -j LOG --log-prefix "IPT: Null Flag "
$IPT -A BAD_FLAGS -p tcp --tcp-flags ALL NONE -j DROP
$IPT -A BAD_FLAGS -p tcp --tcp-flags ALL ALL -j LOG --log-prefix "IPT: All Flags "
$IPT -A BAD_FLAGS -p tcp --tcp-flags ALL ALL -j DROP
$IPT -A BAD_FLAGS -p tcp --tcp-flags ALL FIN,URG,PSH -j LOG --log-prefix "IPT: Nmap:Xmas Flags "
$IPT -A BAD_FLAGS -p tcp --tcp-flags ALL FIN,URG,PSH -j DROP
$IPT -A BAD_FLAGS -p tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG -j LOG --log-prefix "IPT: Merry Xmas Flags "
$IPT -A BAD_FLAGS -p tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG -j DROP
# Prevent SYN Flooding
$IPT -A INPUT -i $EXT_INTER -p tcp --syn -m limit --limit 5/second -j ACCEPT
# Log and Drop Traffic in the INVALID state
$IPT -A INPUT -m state --state INVALID -j LOG --log-prefix "IPT: INV_STATE "
$IPT -A INPUT -m state --state INVALID -j DROP
# Log and Drop Fragmented Traffic
$IPT -A INPUT -f -j LOG --log-prefix "IPT: Frag "
$IPT -A INPUT -f -j DROP
# Bastion Host Service Rules
iptables –A INPUT –i eth0 –s 0/0–p tcp --dport 80 –j LOG
iptables –A INPUT –i eth0 –s 0/0–p tcp --dport 80 –j REJECT


# Internet SMTP Rules
$IPT -A INPUT -i $EXT_INTER -p tcp --dport smtp -m state --state NEW,ESTABLISHED -j ACCEPT
$IPT -A OUTPUT -o $EXT_INTER -p tcp --sport smtp -m state --state NEW,ESTABLISHED -j ACCEPT
# Internal Network SMTP Rules
$IPT -A INPUT -i $INT_INTER -p tcp -s $INT_SMTP --sport smtp -m state --state NEW,ESTABLISHED -j ACCEPT
$IPT -A OUTPUT -o $INT_INTER -p tcp -d $INT_SMTP --dport smtp -m state --state NEW,ESTABLISHED -j ACCEPT
# Internet DNS Rules
$IPT -A INPUT -i $EXT_INTER -p udp --dport domain -m state --state NEW,ESTABLISHED -j ACCEPT
$IPT -A INPUT -i $EXT_INTER -p tcp --dport domain -m state --state NEW,ESTABLISHED -j ACCEPT
$IPT -A OUTPUT -o $EXT_INTER -p udp --sport domain -m state --state NEW,ESTABLISHED -j ACCEPT
$IPT -A OUTPUT -o $EXT_INTER -p tcp --sport domain -m state --state NEW,ESTABLISHED –j ACCEPT
# Internal Network Incoming DNS Rules
$IPT -A INPUT -i $INT_INTER -p udp -s --state NEW,ESTABLISHED -j ACCEPT
$IPT -A INPUT -i $INT_INTER -p udp -s --state NEW,ESTABLISHED -j ACCEPT
$IPT -A INPUT -i $INT_INTER -p tcp -s --state NEW,ESTABLISHED -j ACCEPT
$IPT -A INPUT -i $INT_INTER -p tcp -s --state NEW,ESTABLISHED -j ACCEPT
$INT_DNS1 --dport domain -m state ➥
$INT_DNS2 --dport domain -m state ➥
$INT_DNS1 --dport domain -m state ➥
# Internal Network Outgoing DNS Rules
$IPT -A OUTPUT -o $INT_INTER -p udp -d
--state NEW,ESTABLISHED -j ACCEPT
$IPT -A OUTPUT -o $INT_INTER -p udp -d
--state NEW,ESTABLISHED -j ACCEPT
$IPT -A OUTPUT -o $INT_INTER -p tcp -d
--state NEW,ESTABLISHED -j ACCEPT
$IPT -A OUTPUT -o $INT_INTER -p tcp -d
--state NEW,ESTABLISHED -j ACCEPT
$INT_DNS2 --dport domain -m state ➥
$INT_DNS1 --sport domain -m state ➥
$INT_DNS2 --sport domain -m state ➥
$INT_DNS1 --sport domain -m state ➥
$INT_DNS2 --sport domain -m state ➥
# Internet NTP Rules
$IPT -A INPUT -i $EXT_INTER -p udp -s $EXT_NTP1 --dport ntp -m state ➥
--state ESTABLISHED -j ACCEPT
$IPT -A INPUT -i $EXT_INTER -p udp -s $EXT_NTP2 --dport ntp -m state ➥
--state ESTABLISHED -j ACCEPT
$IPT -A OUTPUT -o $EXT_INTER -p udp -d $EXT_NTP1 --sport ntp -m state ➥
--state NEW,ESTABLISHED -j ACCEPT
$IPT -A OUTPUT -o $EXT_INTER -p udp -d $EXT_NTP2 --sport ntp -m state ➥
--state NEW,ESTABLISHED -j ACCEPT
# Internal Network NTP Rules
$IPT -A INPUT -i $INT_INTER -p udp -s $INT_NET --dport ntp -m state ➥
--state NEW,ESTABLISHED -j ACCEPT
$IPT -A OUTPUT -o $INT_INTER -p udp -d $INT_NET --sport ntp -m state ➥
--state ESTABLISHED -j ACCEPT
# Internal Network SSH Rules
$IPT -A INPUT -i $INT_INTER -p tcp -s $INT_NET --dport ssh -m state ➥
--state NEW,ESTABLISHED -j ACCEPT
$IPT -A OUTPUT -o $INT_INTER -p tcp -d $INT_NET --sport ssh -m state ➥
--state ESTABLISHED -j ACCEPT


# Enable IP spoofing protection (i.e. source address verification)
for i in /proc/sys/net/ipv4/conf/*/rp_filter; do echo 1 > $i; done

echo "# Protect against SYN flood attacks "
echo 1 > /proc/sys/net/ipv4/tcp_syncookies


# Disable proxy_arp. Should not be needed, usually.
for i in /proc/sys/net/ipv4/conf/*/proxy_arp; do echo 0 > $i; done

# Enable secure redirects, i.e. only accept ICMP redirects for gateways
# listed in the default gateway list.
for i in /proc/sys/net/ipv4/conf/*/secure_redirects; do echo 1 > $i; done


# Log packets with impossible addresses.
for i in /proc/sys/net/ipv4/conf/*/log_martians; do echo 1 > $i; done

# Don't log invalid responses to broadcast frames, they just clutter the logs.
echo 1 > /proc/sys/net/ipv4/icmp_ignore_bogus_error_responses

# Don't accept or send ICMP redirects.
for i in /proc/sys/net/ipv4/conf/*/accept_redirects; do echo 0 > $i; done
for i in /proc/sys/net/ipv4/conf/*/send_redirects; do echo 0 > $i; done




nmcli c a ifname eth0 type ethernet -- ipv4.method disabled ipv6.method link-local
non-interactively adds a connection that will use eth0 Ethernet interface and only have an IPv6
rlink-local address configured.






nmcli -f GENERAL,WIFI-PROPERTIES dev show wlan
set ipv4.dns 8.8.8.8 8.8.4.4
vmcli
nmcli
nmcli status n[etworking] 
nmcli help
rfkill list
nmcli help
nmcli n[etworking]
nmcli 
pluma /etc/NetworkManager/NetworkManager.conf
cat /etc/dhcp/dhclient-exit-hooks.d/rfc3442-classless-routes 







echo "## ================================================================= ##"
echo -e "\tSilently dropping all the broadcasted packets..."
echo "## ================================================================= ##"
echo "## -------------------------------------------------------------------------------------------- ##"
echo "DROP       all  --  anywhere             anywhere           PKTTYPE = broadcast"
echo "## -------------------------------------------------------------------------------------------- ##
iptables -A INPUT -m pkttype --pkt-type broadcast -j DROP			# --> to all Broadcast Packets


echo "## ================================================================= ##"
echo -e "\tSilently drop all the packets with host pkt-type packets..."
echo "## ================================================================= ##"
iptables -A INPUT -m pkttype --pkt-type host -j DROP				# --> to individuals


echo "## ================================================================= ##"
## echo -e "\tmatch packet type where packet type is _______.'
echo "## ================================================================= ##"
## iptables -A INPUT -m pkttype --pkt-type [!] packettype -j DROP		# --> match packet type 


echo "## ================================================================= ##"
echo -e "\t\t limit the number of parallel HTTP "
echo -e "\t\t connectionsmade by a single IP address to 4:"
echo "## ================================================================= ##"
echo 
echo "## ==================== Example output.. ============================ ##"
echo 
echo "## -------------------------------------------------------------------------------------------- ##"
echo "REJECT   tcp  --  anywhere  anywhere     tcp dpt:http flags:SYN,RST,ACK/SYN #conn/32 > 4 reject-with icmp-port-unreachable"
echo "## -------------------------------------------------------------------------------------------- ##"
iptables -A INPUT -p tcp --syn --dport http -m iplimit --iplimit-above 4 -j REJECT




echo "## ================================================================= ##"
echo -e "\tlimit the number of parallel connections made by a whole class A:"
echo "## ================================================================= ##"
## iptables -A INPUT -p tcp --syn --dport http -m iplimit --iplimit-mask 8 --iplimit-above 4 -j REJECT
echo
echo "## ==================== Example output.. ============================ ##"
echo 
echo "## -------------------------------------------------------------------------------------------- ##"
echo "REJECT   tcp  --  anywhere  anywhere     tcp dpt:http flags:SYN,RST,ACK/SYN #conn/8 > 4 reject-with icmp-port-unreachablea"
echo "## -------------------------------------------------------------------------------------------- ##"




echo "drop all the pings with a packet size greater than 85 bytes:"
iptables -A INPUT -p icmp --icmp-type echo-request -m length --length 86:0xffff -j DROP



     --source-ports port[,port:port,port...]
        -> match source port(s)

     --sports port[,port:port,port...]
        -> match source port(s)

     --destination-ports port[,port:port,port...]
        -> match destination port(s)

     --dports port[,port:port,port...]
        -> match destination port(s)

     --ports port[,port:port,port]
        -> match both source and destination port(s)



timestamp (ts) flag
record route(rr) flag
router-alert (ra)


read only packets matching 'ip proto 6'

   bpf
       Match using Linux Socket Filter. Expects a BPF program in decimal format. This is the format generated  by  the
       nfbpf_compile utility.

       --bytecode code
              Pass the BPF byte code format 
echo "## ================================================================= ##"
echo -e "\t:"
echo "## ================================================================= ##"
echo 
echo "## -------------------------------------------------------------------------------------------- ##"
echo ""
echo "## -------------------------------------------------------------------------------------------- ##"

echo "## ================================================================= ##"
echo ":"
echo "## ================================================================= ##"
echo
echo "## -------------------------------------------------------------------------------------------- ##"
echo "\t"
echo "\t"
echo "## -------------------------------------------------------------------------------------------- ##"

echo "## ================================================================= ##"
echo ":"
echo "## ================================================================= ##"
echo
echo "## -------------------------------------------------------------------------------------------- ##"
echo "\t"
echo "\t"
echo "## -------------------------------------------------------------------------------------------- ##"

echo "## -------------------------------------------------------------------------------------------- ##"


echo "## -------------------------------------------------------------------------------------------- ##"
echo "\t\tDROP       all  --  anywhere             anywhere            IPV4OPTS RR"
echo "\t\tDROP       all  --  anywhere             anywhere            IPV4OPTS TS"
echo "## -------------------------------------------------------------------------------------------- ##"
iptables -A INPUT -m ipv4options --rr -j DROP
iptables -A INPUT -m ipv4options --ts -j DROP


echo "## ================================================================= ##"
echo "drop all packets that have the record-route or the timestamp IP option set:"
echo "## ================================================================= ##"
echo
echo "## -------------------------------------------------------------------------------------------- ##"
echo "\t\tDROP       all  --  anywhere             anywhere            IPV4OPTS RR"
echo "\t\tDROP       all  --  anywhere             anywhere            IPV4OPTS TS"
echo "## -------------------------------------------------------------------------------------------- ##"



echo "## ================================================================= ##"
echo -e "conntrack match module whic allows you to match on additional conntrack information"
echo "## ================================================================= ##"
echo
echo "## -------------------------------------------------------------------------------------------- ##"
echo "ACCEPT     all  --  anywhere             anywhere           ctstate RELATED"
echo "## -------------------------------------------------------------------------------------------- ##"
iptables -A FORWARD -m conntrack --ctstate RELATED --ctproto tcp -j ACCEPT

 [!] --src-type  		##  Matches if the source address is of given type
 [!] --dst-type 		## Matches if the destination address is of given type

echo "## ================================================================= ##"
echo -e "\t:"
echo "## ================================================================= ##"
echo 
echo "## -------------------------------------------------------------------------------------------- ##"
echo ""
echo "## -------------------------------------------------------------------------------------------- ##"


     [!] --ctstate [INVALID|ESTABLISHED|NEW|RELATED|SNAT|DNAT][,...]
        -> State(s) to match. The "new" `SNAT' and `DNAT' states are
        virtual ones, matching if the original source address differs
        from the reply destination, or if the original destination
        differs from the reply source.


ufw enable
ufw logging full
ufw disable
ufw --force reset
ufw enable
ufw deny in from any to any port 20
ufw deny in from any to any port 21
ufw deny in from any to any port 22
ufw deny in from any to any port 25
ufw deny in from any to any port 80
ufw deny in from any to any port 443
ufw deny in from any to any port 8080
ufw deny in from any to any port 9050
ufw deny in proto tcp from any to any port 135,139,445
ufw deny  proto tcp from any port 135,139,445 to any
ufw deny in proto udp from any to any port 137,138
ufw deny  proto udp from any port 137,138 to any
ufw deny out proto tcp from any to any port 135,139,445
ufw deny  proto tcp from any port 135,139,445 to any
ufw deny out proto udp from any to any port 137,138
ufw deny  proto udp from any port 137,138 to any
ufw deny out nfs
ufw deny in nfs
ufw deny in imap
ufw deny out imap
ufw deny out imap
ufw deny out ftp
ufw deny in ftp
ufw deny in proto tcp from any to any port 5900
ufw deny out proto tcp from any to any port 5900
ufw deny out 631
ufw deny in 631
ufw deny in smtp
ufw deny out smtp
ufw deny out pop3
ufw deny in pop3
ufw deny in https
ufw deny out https
ufw deny out http
ufw deny in http
ufw deny in from any to any port 41
ufw deny out from any to any port 41
ufw deny out from any to any port 132
ufw deny in from any to any port 132
ufw deny in from any to any port 2
ufw deny out from any to any port 2
ufw deny out from any to any port 58
ufw deny in from any to any port 58













#==================== config ====================
ECHO=/bin/echo
IPTABLES=/sbin/iptables
#================== end config ==================


###
############ Create fwsnort iptables chains. ############
###
$IPTABLES -N FWSNORT_FORWARD 2> /dev/null
$IPTABLES -F FWSNORT_FORWARD

$IPTABLES -N FWSNORT_FORWARD_ESTAB 2> /dev/null
$IPTABLES -F FWSNORT_FORWARD_ESTAB

$IPTABLES -N FWSNORT_INPUT 2> /dev/null
$IPTABLES -F FWSNORT_INPUT

$IPTABLES -N FWSNORT_INPUT_ESTAB 2> /dev/null
$IPTABLES -F FWSNORT_INPUT_ESTAB

$IPTABLES -N FWSNORT_OUTPUT 2> /dev/null
$IPTABLES -F FWSNORT_OUTPUT

$IPTABLES -N FWSNORT_OUTPUT_ESTAB 2> /dev/null
$IPTABLES -F FWSNORT_OUTPUT_ESTAB


###
############ Add IP/network WHITELIST rules. ############
###
$IPTABLES -A FWSNORT_FORWARD -s 192.168.10.4 -j RETURN
$IPTABLES -A FWSNORT_FORWARD -d 192.168.10.4 -j RETURN
$IPTABLES -A FWSNORT_INPUT -s 192.168.10.4 -j RETURN
$IPTABLES -A FWSNORT_OUTPUT -d 192.168.10.4 -j RETURN

###
############ Add IP/network BLACKLIST rules. ############
###
$IPTABLES -A FWSNORT_FORWARD -s 192.168.10.203 -j DROP
$IPTABLES -A FWSNORT_FORWARD -d 192.168.10.203 -j DROP
$IPTABLES -A FWSNORT_INPUT -s 192.168.10.203 -j DROP
$IPTABLES -A FWSNORT_OUTPUT -d 192.168.10.203 -j DROP

###
############ Inspect ESTABLISHED tcp connections. ############
###
$IPTABLES -A FWSNORT_FORWARD -p tcp -m state --state ESTABLISHED -j FWSNORT_FORWARD_ESTAB
$IPTABLES -A FWSNORT_INPUT -p tcp -m state --state ESTABLISHED -j FWSNORT_INPUT_ESTAB
$IPTABLES -A FWSNORT_OUTPUT -p tcp -m state --state ESTABLISHED -j FWSNORT_OUTPUT_ESTAB

###
############ web-attacks.rules ############
###
$ECHO "[+] Adding web-attacks rules."

### alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"WEB-ATTACKS /usr/bin/id command attempt"; flow:to_server,established; content:"/usr/bin/id"; nocase; classtype:web-application-attack; sid:1332; rev:5;)
$IPTABLES -A FWSNORT_FORWARD_ESTAB -d 192.168.10.0/24 -p tcp --dport 80 -m string --string "/usr/bin/id" --algo bm -m comment --comment "sid:1332; msg:WEB-ATTACKS /usr/bin/id command attempt; classtype:web-application-attack; rev:5; FWS:1.0.1;" -j LOG --log-ip-options --log-tcp-options --log-prefix "[1] SID1332 ESTAB "
$IPTABLES -A FWSNORT_INPUT_ESTAB -p tcp --dport 80 -m string --string "/usr/bin/id" --algo bm -m comment --comment "sid:1332; msg:WEB-ATTACKS /usr/bin/id command attempt; classtype:web-application-attack; rev:5; FWS:1.0.1;" -j LOG --log-ip-options --log-tcp-options --log-prefix "[1] SID1332 ESTAB "

### alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"WEB-ATTACKS chmod command attempt"; flow:to_server,established; content:"/bin/chmod"; nocase; classtype:web-application-attack; sid:1336; rev:5;)
$IPTABLES -A FWSNORT_FORWARD_ESTAB -d 192.168.10.0/24 -p tcp --dport 80 -m string --string "/bin/chmod" --algo bm -m comment --comment "sid:1336; msg:WEB-ATTACKS chmod command attempt; classtype:web-application-attack; rev:5; FWS:1.0.1;" -j LOG --log-ip-options --log-tcp-options --log-prefix "[2] SID1336 ESTAB "
$IPTABLES -A FWSNORT_INPUT_ESTAB -p tcp --dport 80 -m string --string "/bin/chmod" --algo bm -m comment --comment "sid:1336; msg:WEB-ATTACKS chmod command attempt; classtype:web-application-attack; rev:5; FWS:1.0.1;" -j LOG --log-ip-options --log-tcp-options --log-prefix "[2] SID1336 ESTAB "

### alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"WEB-ATTACKS chown command attempt"; flow:to_server,established; content:"/chown"; nocase; classtype:web-application-attack; sid:1338; rev:6;)
$IPTABLES -A FWSNORT_FORWARD_ESTAB -d 192.168.10.0/24 -p tcp --dport 80 -m string --string "/chown" --algo bm -m comment --comment "sid:1338; msg:WEB-ATTACKS chown command attempt; classtype:web-application-attack; rev:6; FWS:1.0.1;" -j LOG --log-ip-options --log-tcp-options --log-prefix "[3] SID1338 ESTAB "
$IPTABLES -A FWSNORT_INPUT_ESTAB -p tcp --dport 80 -m string --string "/chown" --algo bm -m comment --comment "sid:1338; msg:WEB-ATTACKS chown command attempt; classtype:web-application-attack; rev:6; FWS:1.0.1;" -j LOG --log-ip-options --log-tcp-options --log-prefix "[3] SID1338 ESTAB "

### alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"WEB-ATTACKS chsh command attempt"; flow:to_server,established; content:"/usr/bin/chsh"; nocase; classtype:web-application-attack; sid:1339; rev:5;)
$IPTABLES -A FWSNORT_FORWARD_ESTAB -d 192.168.10.0/24 -p tcp --dport 80 -m string --string "/usr/bin/chsh" --algo bm -m comment --comment "sid:1339; msg:WEB-ATTACKS chsh command attempt; classtype:web-application-attack; rev:5; FWS:1.0.1;" -j LOG --log-ip-options --log-tcp-options --log-prefix "[4] SID1339 ESTAB "
$IPTABLES -A FWSNORT_INPUT_ESTAB -p tcp --dport 80 -m string --string "/usr/bin/chsh" --algo bm -m comment --comment "sid:1339; msg:WEB-ATTACKS chsh command attempt; classtype:web-application-attack; rev:5; FWS:1.0.1;" -j LOG --log-ip-options --log-tcp-options --log-prefix "[4] SID1339 ESTAB "

### alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"WEB-ATTACKS /usr/bin/gcc command attempt"; flow:to_server,established; content:"/usr/bin/gcc"; nocase; classtype:web-application-attack; sid:1341; rev:5;)
$IPTABLES -A FWSNORT_FORWARD_ESTAB -d 192.168.10.0/24 -p tcp --dport 80 -m string --string "/usr/bin/gcc" --algo bm -m comment --comment "sid:1341; msg:WEB-ATTACKS /usr/bin/gcc command attempt; classtype:web-application-attack; rev:5; FWS:1.0.1;" -j LOG --log-ip-options --log-tcp-options --log-prefix "[5] SID1341 ESTAB "
$IPTABLES -A FWSNORT_INPUT_ESTAB -p tcp --dport 80 -m string --string "/usr/bin/gcc" --algo bm -m comment --comment "sid:1341; msg:WEB-ATTACKS /usr/bin/gcc command attempt; classtype:web-application-attack; rev:5; FWS:1.0.1;" -j LOG --log-ip-options --log-tcp-options --log-prefix "[5] SID1341 ESTAB "

### alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"WEB-ATTACKS gcc command attempt"; flow:to_server,established; content:"gcc%20-o"; nocase; classtype:web-application-attack; sid:1342; rev:5;)
$IPTABLES -A FWSNORT_FORWARD_ESTAB -d 192.168.10.0/24 -p tcp --dport 80 -m string --string "gcc%20-o" --algo bm -m comment --comment "sid:1342; msg:WEB-ATTACKS gcc command attempt; classtype:web-application-attack; rev:5; FWS:1.0.1;" -j LOG --log-ip-options --log-tcp-options --log-prefix "[6] SID1342 ESTAB "
$IPTABLES -A FWSNORT_INPUT_ESTAB -p tcp --dport 80 -m string --string "gcc%20-o" --algo bm -m comment --comment "sid:1342; msg:WEB-ATTACKS gcc command attempt; classtype:web-application-attack; rev:5; FWS:1.0.1;" -j LOG --log-ip-options --log-tcp-options --log-prefix "[6] SID1342 ESTAB "

### alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"WEB-ATTACKS netcat command attempt"; flow:to_server,established; content:"nc%20"; nocase; classtype:web-application-attack; sid:1360; rev:5;)
$IPTABLES -A FWSNORT_FORWARD_ESTAB -d 192.168.10.0/24 -p tcp --dport 80 -m string --string "nc%20" --algo bm -m comment --comment "sid:1360; msg:WEB-ATTACKS netcat command attempt; classtype:web-application-attack; rev:5; FWS:1.0.1;" -j LOG --log-ip-options --log-tcp-options --log-prefix "[7] SID1360 ESTAB "
$IPTABLES -A FWSNORT_INPUT_ESTAB -p tcp --dport 80 -m string --string "nc%20" --algo bm -m comment --comment "sid:1360; msg:WEB-ATTACKS netcat command attempt; classtype:web-application-attack; rev:5; FWS:1.0.1;" -j LOG --log-ip-options --log-tcp-options --log-prefix "[7] SID1360 ESTAB "
$ECHO "    Rules added: 14"

###
############ Jump traffic to the fwsnort chains. ############
###
$IPTABLES -D FORWARD -i ! lo -j FWSNORT_FORWARD 2> /dev/null
$IPTABLES -I FORWARD 1 -i ! lo -j FWSNORT_FORWARD
$IPTABLES -D INPUT -i ! lo -j FWSNORT_INPUT 2> /dev/null
$IPTABLES -I INPUT 1 -i ! lo -j FWSNORT_INPUT
$IPTABLES -D OUTPUT -o ! lo -j FWSNORT_OUTPUT 2> /dev/null
$IPTABLES -I OUTPUT 1 -o ! lo -j FWSNORT_OUTPUT




}

showstatus() {
	ebegin "Status"
	$IPTABLES -L -n -v --line-numbers
	einfo "NAT status"
	$IPTABLES -L -n -v --line-numbers -t nat
	eend $?
}

panic() {
	ebegin "Setting panic rules"
	$IPTABLES -F
	$IPTABLES -X
	$IPTABLES -t nat -F
	$IPTABLES -P FORWARD DROP
	$IPTABLES -P INPUT DROP
	$IPTABLES -P OUTPUT DROP
	$IPTABLES -A INPUT -i lo -j ACCEPT
	$IPTABLES -A OUTPUT -o lo -j ACCEPT
	eend $?
}

save() {
	ebegin "Saving Firewall rules"
	$IPTABLESSAVE > $FIREWALL
	eend $?

}

restore() {
	ebegin "Restoring Firewall rules"
	$IPTABLESRESTORE < $FIREWALL
	eend $?
}


}

restart() {
	svc_stop; svc_start

}
showoptions() {
	echo "Usage: $0 {start|save|restore|panic|stop|restart|showstatus}"
	echo "start)		will restore setting if exists else force rules"
	echo "stop)			delete all rules and set all to accept"
	echo "rules)		force settings of new rules"
	echo "save)			will store settings in ${FIREWALL}"
	echo "restore)		will restore settings from ${FIREWALL}"
	echo "showstatus) 	Shows the status"
}



# auto eth0
# iface eth0 inet manual
# 	up ifconfig $IFACE 0.0.0.0 up
#       up ip link set $IFACE promisc on
#       down ip link set $IFACE promisc off
#       down ifconfig $IFACE down




$ECHO "[+] Finished."
### EOF ###
