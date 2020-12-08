#!/bin/sh
echo "## ================================================================================================== ##"
echo "# PortableFaggotWall.sh (BrownTown Offical)"
echo "# "
echo "## ************************************************************************************************** ##"
echo -e "\t## >> ## This Shell Script Was Written With The Intent To Subvert NSA & Malicous Governments."
echo -e "\t## >> ## As Well As Harden Your Linux Configurations, Relieve Some Anxieties"
echo -e "\t## >> ## I Would Love To Thank:"
echo -e "\t\t## >> Jacob Appelbaum (A Living Example of A True Activist)"
echo -e "\t\t## >> Whonix ()"
echo -e "\t\t## >> jon schipp (For Inspiring Me To Get My Linux+ Certification)"
echo -e "\t\t## And The Countless Others In The Linux Community That Inspired Me To Make Something of Myself"
echo "## ************************************************************************************************** ##"
## 
## #######
## ## Colors
## ################### =============== ## 
## Basic_Green 		=	"\033[0;32m"
## Green			=	"\033[1;32m"
## Green_Underline	=	"\033[4;32m"
## Basic_Yellow		=	"\033[0;33m"
## Yellow 			=	"\033[1;33m"
## White			=	"\033[0;37m"
## WhiteB			=	"\033[1;37m"
## Basic_Red		=	"\033[0;31m"
## Red				=	"\033[1;31m"
## Cyan				=	"\033[1;36m"
## Basic_Cyan		=	"\033[0;36m"
## Blue				=	"\033[1;34m"
## Basic_Blue		=	"\033[0;34m"
## Light_Blue		=	"\033[0;94m"
## Blue_Underline	=	"\033[4;34m"
## Default			=	"\033[0m"
## Underline		=	"\033[4;32m"
## ################### =============== ## 
## 
##
## ==================================================================================== ##
RED="\033[01;31m"     		# Warning
DARKGREEN="\033[0;32m"		# Dark Green
FADEDSKYBLUE="\033[01;36m"	# Dark Green
SWAMPGREEN="\033[0;32m"		# Dark Green
PURPLUE="\033[0;34m"		# Dark Green
YELLOW="\033[01;33m"   		# Warnings/Information
BLUE="\033[01;34m"     		# Heading
PURPLE="\033[0;35m"			# Purple
SKYBLUE="\033[0;36m"		# SkyBlue
PEACH="\033[0;37m"			# Peach
PINK="\033[01;35m"			# Pink
ORANGE="\033[01;33m"		# Orange Txt
GRAY="\033[01;34m"			# Gray
BLOODRED="\033[01;38m"		# Blood Red
BRIGHTPEACH="\033[01;39m"	# Bright Peach
PINK="\033[01;35m"			# Pink
BLACK="\033[0;30m"			# Black Txt
## ==================================================================================== ##
FORGRAY="\033[0;40m"		# Grayish/white forground
FORRED="\033[0;41m"			# Red Forground
FORYELLOW="\033[0;42m"		# Yellow Forground, Green Txt
FORORANGE="\033[0;43m"		# Orange Forground
BOLD="\033[01;01m"    		# Highlight
UNDERLINE="\[0;4m"
REVERSE="\[0;7m"
BLINK="\[0;5m"
RESET="\033[00m"      	 	# Normal
## ==================================================================================== ##
echo -e "\t\t Now Processing User Capabilities For This Script..."
## ==================================================================================== ##



UID=$(/usr/bin/id | /bin/sed -e 's/uid=\([0-9][0-9]*\).*$/\1/')

if [ $UID -ne 0 ]; then
	printf "Must Be Run As Root."
else
	echo "The Current user is $USER"
	exit 1
fi
echo "## ==================================================================================== ##"
echo -e "\t\t\tDetermining Operating System Specifications..."
echo "## ==================================================================================== ##"
if [ $(uname) != "Linux" ]; then
	printf "Currently Running on Linux"
else
	printf "This Only Works On Linux Dipshit."
	exit 1
fi


if [ uname -m = x86_64 ]: then
	OS_ARCH="$(uname -m)"
else
	OS_ARCH="i386"
elif [ dpkg --print-architecture = amd64 ]; then
	echo "You Are Using An AMD 64Bit Processor"
	OS_CPU="amd64"
else
	echo "You Are Using An Intel Processor"
	OS_CPU="i386"
fi





echo '## ==================================================================================== ##'
echo -e "\tDefining Essential Environmental Variables For The Script..."
echo '## ==================================================================================== ##'

## VARIABLES - Redefine To atch Your Environment.
## Location of the binaries
IFCONFIG="/sbin/ifconfig" 
IPTABLES="/sbin/iptables"
IP6TABLES="/sbin/ip6tables"
ARPTABLES="/usr/sbin/arptables"
EBTABLES="/usr/sbin/ebtables"
MODPROBE="/sbin/modprobe"
SYSCTL="/sbin/sysctl"
IPTABLES_SAVE="$IPTABLES-save"
IPTABLES_RESTORE="$IPTABLES-restore"
IP6TABLES_SAVE="$IP6TABLES-save"
IP6TABLES_RESTORE="$IP6TABLES-restore"


# Logging options.
#------------------------------------------------------------------------------
LOG="LOG --log-level debug --log-tcp-sequence --log-tcp-options"
LOG="$LOG --log-ip-options"


STAT="/usr/bin/stat"
STATSYNTAX="--format=[%A]:[%n]:[%a]:[%u:%U:%g:%G]:[%s]:[%F] "
SourcesList="/etc/apt/sources.list"


FWSNORT="/usr/sbin/fwsnort"
UPDATE_RULES_URL="http://rules.emergingthreats.net/open/snort-2.9.0/emerging-all.rules"

RULES_DIR="$CONF_DIR/snort_rules"
FWSNORT_SAVE_EXEC_FILE="$STATE_DIR/fwsnort.sh"		    ### main fwsnort.sh script
FWSNORT_SAVE_FILE="$STATE_DIR/fwsnort.save"				### main fwsnort.save file
IPT_BACKUP_SAVE_FILE="$STATE_DIR/iptables.save"			### iptables policy backup
FWSNORT_ARCHIVE="/var/lib/fwsnort/archive/"
FWSNORT_LOG="/var/log/fwsnort/fwsnort.log"


setup_environment() {
	REPO="git://github.com/HardenedBSD/hardenedBSD.git"
	BRANCH="hardened/current/master"
	UNSIGNED=0
	PRIVKEY="/usr/share/keys/updater/private/updater.key"
	PUBKEY="/usr/share/keys/updater/certs/updater.crt"
	SIGNBIN="/usr/bin/openssl"
	 KERNELS="HARDENEDBSD"
	SRCDIR="/usr/src"
	STAGEDIR="/builds/updater/stage"
	OUTPUTDIR="/builds/updater/output"
	CHROOTDIR="/builds/updater/chroot"


IPADDR=$(ifconfig wlan0 | grep netmask | cut -c14-26)
NETMASK=$(ifconfig wlan0 | grep netmask | cut -c27-48)
BROADCAT=$(ifconfig wlan0 | grep netmask | cut -c51-73)

MACADDR=$(ifconfig -a | grep ether | cut -c15-31)
TxPower=$(iwconfig wlan0 | grep Tx-Power | cut -c65-70)






GPGImport="gpg --keyid-format long --import $GPGKey.(pub|key|asc)






## cat /usr/share/doc/fwsnort/README
## cat /usr/share/doc/fwsnort/README.Debian


if 
## fwsnort --update-rules
## dpkg-reconfigure fwsnort



fwsnort --snort-rdir /etc/snort/rules,/etc/fwsnort/snort_rules




if [ ! -x /sbin/iptables ]; then
exit 0
fi

## ==================================================================================== ##

NumProcessors="$(grep -c '^processor' /proc/cpuinfo)"



echo "Today Is $(date +'%A, %B %d, %Y')"
## echo "The Current Date Is: $(date +%D)"


echo "Initialization Timestamp: $(date +%r)"



echo "## ================================================================= ##"
echo -e "\t\t[+] If Folder Doesn't Exist, Create It...."
echo "## ================================================================= ##"
if [ ! -d /home/$USER/TEMP_DIR/ ]; then
	TEMP_DIR=`mktemp -d /home/$USER/HCL.XXXXXXXXXX`			
	## TEMP_DIR=`mktemp --tmpdir -d HCL.XXXXXXXXXX`
	## TEMP_FILE=$(mktemp "~/TEMP_DIR/${file}.XXXXXXX")


cat -vET /etc/os-release >> $TEMP_DIR/os-release
cat -vET /etc/lsb-release >> $TEMP_DIR/lsb-release
cat -vET /proc/cpuinfo >> $TEMP_DIR/cpuinfo

(who --boot; who --all; who --mesg; who --ips; who -T; who --dead; who -b -d --login -p -r -t -T -u) > $TEMP_DIR/who.txt


echo "## ================================================================= ##"
echo -e "\t\t[+] Timestamping Diagnotic/Debugging Report Result Files..."
echo "## ================================================================= ##"
echo "${BLOODRED}Script Execution Time Stamp is: $(date +'%A, %B %d, %Y')${RESET}"





echo "###############################################################"
echo -e "\t [+] Establish Hardware Interface Environment Variables:"
echo "###############################################################"



## Your Loopback Interface:
LOOPBACK="lo"
## Your First Ethernet Interface:
ETHER="eth0"
## Your First (Possibly Internal) Wireless Card
IFACE="wlan0"
## Your Secondary (Most Likely External USB) Wireless Card
ALPHA="wlan1"
## If Applicable, The Second External Wireless Card
ALPHA2="wlan2"


VPN="tun0"


## ==================================================================================== ##
echo
#   The Internet Assigned Numbers Authority (IANA) has reserved the
#   following three blocks of the IP address space for private internets:
#
#     10.0.0.0        -   10.255.255.255  (10/8 prefix)
#     172.16.0.0      -   172.31.255.255  (172.16/12 prefix)
#     192.168.0.0     -   192.168.255.255 (192.168/16 prefix)

LOOPBACK_ADDR="127.0.0.0/8"				# Reserved loopback addr range
CLASS_A="10.0.0.0/8"				# Class A private networks
CLASS_B="172.16.0.0/12"				# Class B private networks
CLASS_C="192.168.0.0/16"			# Class C private networks
CLASS_D_MULTICAST="224.0.0.0/4"			# Class D multicast addr
CLASS_E_RESERVED_NET="240.0.0.0/5"		# Class E reserved addr
BROADCAST_SRC="0.0.0.0"				# Broadcast source addr
BROADCAST_DEST="255.255.255.255"		# Broadcast destination addr
PRIVPORTS="0:1023"				# Privileged port range
UNPRIVPORTS="1024:"				# Unprivileged port range


I2P_PORTS="2827 3456 4444 4445 6668 7622 7650 7651 7654 7656 7657 7658 7659 7660 7661 7662 8998"



ipset create foo hash:net,iface

ipset add foo 192.168.0/24,eth0

ipset add foo 10.1.0.0/16,eth1

ipset test foo 192.168.0/24,eth0


--dump --file --append

--msg [on
--msglevel
--append
--background
--underline on

terminfo
klogd
echo
#********************************
# END OF USER VARIABLE SECTION
#********************************


ACTIVE_IFACE=

if [ -z "${2}" ]; then
    link_status=`ip link show $ACTIVE_IFACE 2>/dev/null`
    if [ -n "${link_status}" ]; then
        if echo "${link_status}" | grep -q UP; then
            boot_mesg "Bringing down the ${1} interface..."
            ip link set ${1} down
            evaluate_retval




echo
echo "## =========================================== ##"
echo -e "\t[+] Killing Eth0... "
echo "## =========================================== ##"
$IFCONFIG $ETHER down
ip link set $ETHER down
echo
## 
echo "## ============================================================================== ##"
echo -e "\t\tSpoofing Eth0 Interface"
echo "## ============================================================================== ##"
## 
## ======================================================================================== ##
ifconfig eth0 hw ether 00:30:65:e4:98:27
ip link set dev eth0 address 00:30:65:e4:98:27
#$(/sbin/ifconfig wlan0 down)
$IFCONFIG $IFACE down
ip link set $IFACE down
echo "## ============================================================================== ##"
echo -e "\t\tSpoofing Wlan0 Interface..."
echo "## ============================================================================== ##"
ip link set dev $IFACE address 00:30:65:39:2e:77
ifconfig $IFACE hw ether 00:30:65:39:2e:77

echo "## ============================================================================== ##"
echo -e "\t\tSpoofing Wlan1 Interface..."
echo "## ============================================================================== ##"
## 
## ======================================================================================== ##
if [ -d /sys/class/net/wlan1/ ]; then
	$(/sbin/ifconfig wlan1 down)
	$IFCONFIG $ALPHA down
	ip link set $ALPHA down
	ifconfig wlan1 hw ether 00:30:65:35:2e:37
	ip link set dev wlan1 address 00:30:65:35:2e:37
else
	echo -e "\t\t Wlan1 Doesnt Exist..."
fi
echo "## ============================================================================== ##"
echo -e "\t\tSpoofing Wlan2 Interface..."
echo "## ============================================================================== ##"
## 
## ======================================================================================== ##
if [ -d /sys/class/net/wlan2/ ]; then
	$(/sbin/ifconfig wlan1 down)
	$IFCONFIG $ALPHA2 down
	ip link set $ALPHA2 down
	ifconfig wlan2 hw ether 00:30:65:35:2e:37
	ip link set dev wlan2 address 00:30:65:35:2e:37
else
	echo -e "\t\t Wlan2 Doesnt Exist..."
fi
#############################################################################################
echo "## ============================================================================== ##"
echo -e "\t\t [+] Killing Networking For A Second..."
echo "## ============================================================================== ##"
#############################################################################################


TcpdumpWlanStatus=$(tcpdump -L -i wlan0)
TcpdumpEthStatus=$(tcpdump -L -i eth0)


NetworkManagerState=$(cat /var/lib/NetworkManager/NetworkManager.state)

NMNetworkingEnabled=$(cat $NetworkManagerState | grep NetworkingEnabled | cut -c19-23)
NMWirelessEnabled=$(cat $NetworkManagerState | grep WirelessEnabled | cut -c17-20)
NMWWANEnabled=$(cat $NetworkManagerState | grep WWANEnabled | cut -c12-16)


cat /var/lib/NetworkManager/NetworkManager.state  | grep NetworkingEnabled | cut -c19-23

# Check that networking is up.
[ ${NMNetworkingEnabled} = "false" ] && exit 0
	else




# Check that networking is up.
[ "$NETWORKING" = "no" ] && exit 0



echo "## ============================================================================== ##"
echo -e "\t\t [+] Killing Networking For A Second..."
echo "## ============================================================================== ##"
systemctl disable networking
service networking stop
echo
#############################################################################################

echo "## ============================================================================== ##"
echo -e "\t\t [+] Checking Status of Network Manager..."
echo "## ============================================================================== ##"
if [ ${NMWirelessEnabled} = "false" ] && exit 0
	else
echo "## ============================================================================== ##"
echo -e "\t\t [+] Killing Network Manager..."
echo "## ============================================================================== ##"
systemctl disable NetworkManager
service NetworkManager stop
echo
echo
echo "## ============================================================================== ##"
echo -e "\t [+] Checking If Necessary Kernel Modules Are Currently Loaded..."
echo "## ============================================================================== ##"


/sys/module/x_tables/
xt_addrtype/
xt_conntrack/
xt_limit/
xt_LOG/
xt_tcpudp/


# lsmod | grep {ip,ip6,arp,eb}_tables
lsmod | grep ip_tables | cut -c1-15
lsmod | grep x_tables | cut -c1-15
lsmod | grep nf_defrag_ipv4 | cut -c1-15
lsmod | grep nf_conntrack | cut -c1-15
lsmod | grep nf_conntrack_ipv4 | cut -c1-15
lsmod | grep nfnet | cut -c1-15
# modinfo /lib/modules/4.7.0-parrot-amd64/kernel/net/ipv6/*
# modinfo /lib/modules/4.7.0-parrot-amd64/kernel/net/ipv4/*
# modinfo /lib/modules/4.7.0-parrot-amd64/kernel/net/bridge/netfilter/*

echo "## ============================================================================== ##"
echo -e "\t [+] Dumping Loaded Kernels Modules Configs, Depends, Desc, & Parameters..."
echo "## ============================================================================== ##"
modprobe --verbose --syslog --showconfig >> $TEMP_DIR/ModprobeConf.txt && cat $TEMP_DIR/ModprobeConf.txt
modprobe --verbose--show-depends --syslog >> $TEMP_DIR/ModprobeDepends.txt && cat $TEMP_DIR/ModprobeDepends.txt
modprobe --verbose--resolve-alias --syslog >> $TEMP_DIR/ModprobeAlias.txt && cat $TEMP_DIR/ModprobeAlias.txt
modprobe --showconfig >> $TEMP_DIR/ModprobeConfig2.txt
echo "## ============================================================================== ##"
echo -e "\t [+] Dumping Loaded Kernels Modules Description, Author, & Parameters..."
echo "## ============================================================================== ##"
modinfo -a -d -l -p -n  >> $TEMP_DIR/modinfo.txt            ## author, description, license.  parm and filename
modinfo -k --field


if [ $var -gt $var2 ];then					## INTEGER1 is greater than INTEGER2
 

# while [ $# -gt 0 ]; do
#   case "$1" in              


CONFIG_NETFILTER_NETLINK_LOG=m
CONFIG_NF_LOG_COMMON=m
CONFIG_NFT_LOG=m
CONFIG_NETFILTER_XT_TARGET_LOG=m
CONFIG_NETFILTER_XT_TARGET_NFLOG=m
CONFIG_NF_LOG_ARP=m
CONFIG_NF_LOG_IPV4=m
CONFIG_NF_LOG_IPV6=m
CONFIG_NF_LOG_BRIDGE=m


FEATURE_UNIX_LOCAL				# Enable Unix domain socket support
FEATURE_PREFER_IPV4_ADDRESS		# Prefer IPv4 addresses from DNS queries




echo "## ============================================================================== ##"
echo -e "\t\t\t[+] Loading Required Modprobe Modules..."
echo "## ============================================================================== ##"
$MODPROBE ip_tables
$MODPROBE ip_conntrack		# /lib/modules/4.7.0-parrot-amd64/kernel/net/netfilter/nf_conntrack.ko
$MODPROBE iptable_filter
$MODPROBE iptable_mangle
$MODPROBE iptable_nat
$MODPROBE nf_conntrack_tftp
$MODPROBE nf_nat_tftp
$MODPROBE ipt_LOG
$MODPROBE ipt_limit
$MODPROBE ipt_state
# $MODPROBE cnf_conntrack_checksum		# ls /lib/modules/4.7.0-parrot-amd64/kernel/net/netfilter/
# $MODPROBE nf_conntrack_log_invalid	# ls /lib/modules/4.7.0-parrot-amd64/kernel/net/
# $MODPROBE nf_conntrack_ipv6			# ls /lib/modules/4.7.0-parrot-amd64/kernel/net/ipv6/netfilter/
# $MODPROBE nf_log_ipv6					# ls /lib/modules/4.7.0-parrot-amd64/kernel/net/ipv6
# 
#
# 2.2 Non-Required modules
#
#/sbin/modprobe ipt_owner
#/sbin/modprobe ipt_REJECT
#/sbin/modprobe ipt_MASQUERADE

echo "## ============================================================================== ##"
echo -e "\t\t[+] Enabling Support For Connection Tracking of FTP And IRC..."
echo "## ============================================================================== ##"
$MODPROBE ip_conntrack_ftp
$MODPROBE ip_conntrack_irc

## 
## 
echo "## ============================================================================== ##"
echo -e "\t\t[+] Displaying OS (Type|Release|Version) From /Proc/Sys/Kernel"
echo "## ============================================================================== ##"
OSType="/proc/sys/kernel/ostype" 
OSRelease="/proc/sys/kernel/osrelease"
KernelVersion="/proc/sys/kernel/version"
systemctl show-environment


echo "## ============================================================================== ##"
echo -e "\t\t[+] Defining Temporary Home Directory..."
echo "## ============================================================================== ##"
# if [ $USER = root ];then
# 	echo "What Home Directory Would You Like To Define?"
# 	read line
# env | grep HOME


User="echo $USER"
FaggotHomeDir="/home/$USER"
basedir=${FAGGOTHOMEDIR:=$FaggotHomeDir}

echo "## ============================================================================== ##"
echo -e "\t\t[+] Defining UDev Variables With Attribute Walk..."
echo "## ============================================================================== ##"
udevadm info --attribute-walk --name=/dev/sda >> $TEMP_DIR/udevsda.txt && cat $TEMP_DIR/udevsda.txt



echo "## ============================================================================== ##"
echo -e "\t\t[+] Find Out What Shells Are Currently In Use On The System"
echo -e "\t\t[+] As Well As How Many Users Use Each"
echo "## ============================================================================== ##"
cat /etc/passwd | awk -F: '{print $NF}' | sort | uniq -c | sort -rn >> $TEMP_DIR/



## ==================================================================================== ##
# LD_LIBRARY_PATH=""
# LD_PRELOAD=""							## list  of ELF shared objects to be loaded before all others.
# ldsoconf="/etc/ld.so.conf"			## File  containing  a  list  of Library directories
# ldso="/lib/ld.so"						## Runtime dynamic linker That resolving shared object dependencies
# dSoCache="/etc/ld.so.cache"			## File containing an ordered list of libraries
# ldLinuxso="/lib/ld-linux.so.{1,2}"	## ELF dynamic linker/loader
## ==================================================================================== ##
# /sbin/sysctl -a --pattern 'net.ipv4.conf.(eth|wlan)0.arp'
# /sbin/sysctl -a --pattern 'net.ipv4.conf.(eth|wlan)(0|1)'
# /sbin/sysctl -a --pattern 'net.ipv6.conf.(eth|wlan)(0|1)'
## ==================================================================================== ##
# for i in ; do echo 1 > $i; done
# for i in ; do echo 1 > $i; done
echo "## ============================================================================== ##"
echo -e "\tHardening /proc/sys/kernel/kptr_restrict {Value: 2}"
echo -e "\tkernel pointers printed using the %pK format specifier will be"
echo -e "\treplaced with zeros regardless of the user's  capabilities"
echo "## ============================================================================== ##"
for i in /proc/sys/kernel/kptr_restrict; do echo 2 > $i; done
echo
echo "## ============================================================================== ##"
echo -e "\t\t\tHardening kernel syslog contents..."
echo "## ============================================================================== ##"
for i in /proc/sys/kernel/dmesg_restrict; do echo 1 > $i; done
echo
echo "## ============================================================================== ##"
echo -e "\t\t\t{+} Enabling Kernel Stack Tracer..."
echo "## ============================================================================== ##"
sysctl -w kernel.stack_tracer_enabled="1"
echo "## ============================================================================== ##"
echo -e "\t\t\tForcing cdroms To Check Media Integrity..."
echo "## ============================================================================== ##"

if [ -e /lib/udev/rules.d/60-cdrom_id.rules ]
then
	mkdir -p "${DESTDIR}/lib/udev/rules.d"
	cp -p /lib/udev/rules.d/60-cdrom_id.rules "${DESTDIR}/lib/udev/rules.d"
fi

sysctl -w dev.cdrom.check_media="1"
echo "## ============================================================================== ##"
echo -e "\t\t\tModifying cdrom To AutoEject..."
echo "## ============================================================================== ##"
sysctl -w dev.cdrom.autoeject="1"
echo
echo "## ============================================================================== ##"
echo -e "\t\t\t{+} Enabling Kernels Use of PID's..."
echo "## ============================================================================== ##"
sysctl -q -w kernel.core_uses_pid="1"   # Controls whether core dumps will append the PID to the core filename
echo
echo
## 
## 
# kernel.pid_max
# kernel.pty.max = 4096
# kernel.pty.nr = 12
# kernel.stack_tracer_enabled = 0
# kernel.sysctl_writes_strict = 1
# kernel.yama.ptrace_scope
# kernel.tracepoint_printk = 0
# kernel.unknown_nmi_panic = 0
# kernel.unprivileged_bpf_disabled = 0
# kernel.unprivileged_userns_clone = 0
# /proc/sys/net/core/bpf_jit_enable
## 
## 
# echo "## ============================================================================== ##"
# echo -e "\t\t[+] Enables a system-wide task dump (excluding kernel threads) to be"
# echo -e "\t\t[+] produced when  the  kernel performs an OOM-killing {The default value is 0}"
# echo "## ============================================================================== ##"
# /proc/sys/vm/oom_dump_tasks
## 
## 
# echo "## ============================================================================== ##"
# echo -e "\t\t[+] /proc/pid/numa_maps is an extension based on maps, showing the memory
# echo -e "\t\t[+] locality and binding policy, as well as the memory usage (in pages) of each mapping.
# echo "## ============================================================================== ##"
## 
## 
# echo "## ============================================================================== ##"
# echo -e "\t\t[+] To Free PageCache, Use:"
# echo "## ============================================================================== ##"
# for i in /proc/sys/vm/drop_caches; do echo 1 > $i; done
# echo
# echo
# echo "## ============================================================================== ##"
# echo -e "\t\t[+] To Free Dentries And Inodes, Use:"
# echo "## ============================================================================== ##"
# for i in /proc/sys/vm/drop_caches; do echo 2 > $i; done
# echo
# echo
# echo "## ============================================================================== ##"
# echo -e "\t\t[+] To Free PageCache, Dentries And Inodes, Use:"
# echo "## ============================================================================== ##"
# for i in /proc/sys/vm/drop_caches; do echo 3 > $i; done
# echo
# echo
echo "## ============================================================================== ##"
echo -e "\t\t\t[+] Disabling Bootp_Relay, Insecure In The Right 
echo "## ============================================================================== ##"
for i in /proc/sys/net/ipv4/conf/*/bootp_relay; do echo 0 > $i; done
echo
echo "## ============================================================================== ##"
echo -e "\t\t\t[+] Enabling Bad Error Message Protection..."
echo "## ============================================================================== ##"
sysctl -w net.ipv4.icmp_ignore_bogus_error_responses=1
echo
echo "## ============================================================================== ##"
echo -e "\t[+] Enable IP Spoofing Protection (i.e. Source Address Verification)"
echo "## ============================================================================== ##"
##
if [ "/proc/sys/net/ipv4/conf/all/rp_filter" = "0" ]; then
	if [ -e /proc/sys/net/ipv4/conf/all/rp_filter ]; then
        echo -n "Setting up IP spoofing protection..."
		for i in /proc/sys/net/ipv4/conf/*/rp_filter; do
        echo 1 > $i
        	done
        rpfilt="cat /proc/sys/net/ipv4/conf/all/rp_filter"
		echo "/proc/sys/net/ipv4/conf/all/rp_filter:$rpfilt"
	else
        echo "WARNING: Errors Encountered While Trying To Enable IP Spoofing Protection!"
	fi
fi

 "## +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-++-+-+-+-+-+-+-+-+-+-+ ##"


echo "## ============================================================================== ##"
echo -e "\t\t\t[+] Modifying The Tcp_Max_Syn_Backlog Parameter To 2048..."
echo "## ============================================================================== ##"
echo "## ----------------------------------------------------------------------------------------------------- ##"
echo -e "\t [?] This parameter defines how many half-open connections"
echo -e "\t [?] can be retained by the backlog queue."

echo -e "\t Half-open connections are Connections In Which:"
echo "##=~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~=##"
echo -e "\t\t[?]> A SYN packet has been received"
echo -e "\t\t[?]> A SYN/ACK packet has been sent"
echo -e "\t\t[?]> And an ACK packet has not yet been received."
echo "##=~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~=##"
echo
echo "## ------------------------------------------------------------------------------------------ ##"
echo -e "\t Once the backlog value has been reached, the system cannot receive any "
echo -e "\t more connections until the existing ones are either established or timed out."
echo "## ------------------------------------------------------------------------------------------ ##"
sysctl -w net.ipv4.tcp_max_syn_backlog="2048"


echo "## ============================================================================== ##"
echo -e "\t\t\t[+] Modifying The Tcp_Synack_Retries Parameter To 3..."
echo "## ============================================================================== ##"
echo
echo "## ------------------------------------------------------------------- ##"
echo -e "\t [?] This parameter controls the number of SYN/ACK retransmissions."
echo -e "\t\t\t The following values apply:"
echo "##=~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~=##"
echo -e "\t\t[?]> value = 5 (3 minutes)"
echo -e "\t\t[?]> value = 3 (45 seconds)"
echo -e "\t\t[?]> value = 2 (21 seconds)"
echo -e "\t\t[?]> value = 1 (9 seconds)"
echo "##=~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~=##"
echo
echo "## --------------------------------------------------------------------------------------------------- ##"
echo -e "\t Be Careful not to set the values too low"
echo -e "\t as low values will create a denial of service by design."

echo -e "\t If legitimate network traffic from remote destinations takes longer "
echo -e "\t to traverse the Internet than the configured retransmission value."
echo "## --------------------------------------------------------------------------------------------------- ##"
sysctl -w net.ipv4.tcp_ synack_retries="3"
echo
echo

sysctl -w /proc/sys/fs/suid_dumpable="0"


proc/sys/kernel/acct


echo "## ============================================================================== ##"
echo -e "\t\t\t[+] Ignoring IMCP Echo Broadcasts..."
echo "## ============================================================================== ##"
echo "## ----------------------------------------------------------------------------------------------------- ##"
echo -e "\tIgnores only ICMP messages sent to broadcast or multicast addresses."
echo -e "\tThis significantly reduces the risk of a host being targeted by a smurf attack."
echo "## ----------------------------------------------------------------------------------------------------- ##"
sysctl -w net/ipv4/icmp_echo_ignore_broadcasts ="1"
echo
echo
# echo "## ============================================================================== ##"
# echo -e "\t\t\t[+] Adjusting ICMP Rate Limit..."
# echo "## ============================================================================== ##"
# cat /proc/sys/net/ipv6/icmp/ratelimit 
echo
echo

# net.core.bpf_jit_enable = 1
# net.core.bpf_jit_harden = 1
# kernel.yama.ptrace_scope
# sysctl -w kernel.stack_tracer_enabled="1"
# sysctl -w dev.cdrom.info="1"


## ============================================================================== ##
# if [ "${ENABLE_SRC_ADDR_VERIFY}" = "Y" ]; then
# for i in /proc/sys/net/ipv4/conf/*/rp_filter; do echo 1 > $i; done
## ============================================================================== ##
echo
echo "## ============================================================================== ##"
echo -e "\t\t\t[+] Protect against SYN flood attacks "
echo "## ============================================================================== ##"
echo 1 > /proc/sys/net/ipv4/tcp_syncookies
echo
echo "## ============================================================================== ##"
echo -e "\t\t\t[+] Disable proxy_arp. Should not be needed, usually."
echo "## ============================================================================== ##"
for i in /proc/sys/net/ipv4/conf/*/proxy_arp; do echo 0 > $i; done
echo
echo
echo "## ============================================================================== ##"
echo -e "\t\t\t[+] Enable secure redirects, i.e. only accept ICMP redirects for gateways"
echo -e "\t\t\t\tlisted in the default gateway list."
echo "## ============================================================================== ##"
for i in /proc/sys/net/ipv4/conf/*/secure_redirects; do echo 1 > $i; done
echo
echo
echo "## ============================================================================== ##"
echo -e "\t\t\t[+] Logging Packets With Impossible Addresses..."
echo "## ============================================================================== ##"
for i in /proc/sys/net/ipv4/conf/*/log_martians; do echo 1 > $i; done
echo
echo
echo

echo "## ============================================================================== ##"
echo -e "\t\t\t[+] Disabling IPv4 automatic defragmentation..."
echo "## ============================================================================== ##"
if [ -f /proc/sys/net/ipv4/ip_always_defrag ]; then
	        if [ `cat /proc/sys/net/ipv4/ip_always_defrag` != 0 ]; then
				sysctl -w net.ipv4.ip_always_defrag=0
			fi
fi
echo
echo
echo "## ============================================================================== ##"
echo -e "\t\t\t[+] Enabling rp_filter for All Interfaces..."
echo "## ============================================================================== ##"
echo "## ----------------------------------------------------------------------------------------------------- ##"
echo -e "\tThis parameter controls reverse path filtering"
echo -e "\tThis tries to ensure packets use legitimate source addresses."
echo -e "\tWhen it is turned on, then incoming packets whose routing table entry for the"
echo -e "\tsource address does not match the interface they are coming in on are rejected."
echo -e "\tThis can prevent some IP spoofing attacks."
echo "## ----------------------------------------------------------------------------------------------------- ##"
for interface in /proc/sys/net/ipv4/conf/*/rp_filter; do
	/bin/echo "1" > ${interface}
done
echo "## ============================================================================== ##"
echo -e "\t\t\t[+] Double Check The RP Filter Was Enabled On ALL Interfaces..."
echo "## ============================================================================== ##"
cat /proc/sys/net/ipv4/conf/*/rp_filter
echo
echo
echo "## ============================================================================== ##"
echo -e "\t\t\t[+] Don't accept or send ICMP redirects."
echo "## ============================================================================== ##"
echo "## ----------------------------------------------------------------------------------------------------- ##"
echo -e "\tThe accept_redirects parameter determines whether your system accepts ICMP redirects."
echo -e "\tICMP redirects are used to tell routers or hosts that there is a faster "
echo -e "\tor less congested way to send the packets to specific hosts or networks."
echo "## ----------------------------------------------------------------------------------------------------- ##"
for i in /proc/sys/net/ipv4/conf/*/accept_redirects; do echo 0 > $i; done
for i in /proc/sys/net/ipv4/conf/*/send_redirects; do echo 0 > $i; done
echo
echo "## ============================================================================== ##"
echo -e "\t\t\t[+] Disabling IPv6..."
echo "## ============================================================================== ##"
echo 1 > /proc/sys/net/ipv6/conf/default/disable_ipv6
echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6
echo
echo "## ============================================================================== ##"
echo -e '\t\t'{BLOODRED}'Disabling IPV6...''{RESET}'
echo "## ============================================================================== ##"
for i in /sys/module/ipv6/parameters/disable; do echo 1 > $i; done
for i in /sys/module/ipv6/parameters/disable_ipv6; do echo 1 > $i; done
echo
echo
IPV6ACCEPTDAD=$(cat /proc/sys/net/ipv6/conf/all/disable_ipv6)
if [ $ACCEPTDAD = 1 ]; then
	sysctl -w net.ipv6.conf.all.accept_dad="0"
else
	echo -e "\t\t\t[+] IPV6 Accept Dad Is'nt Enabled, No Need To Customize The Sysctl Rule..."
fi
echo
echo
IPV6ACCEPTRA=$(cat /proc/sys/net/ipv6/conf/all/accept_ra)
if [ $IPV6ACCEPTRA = 1 ]; then
	sysctl -w net.ipv6.conf.all.accept_ra="0"
else
	echo -e "\t\t\t[+] IPV6 Accept Router Avertisement Is'nt Enabled, No Need To Customize The Sysctl Rule..."
fi
echo
echo
IPV6DADTRANSMITS=$(cat /proc/sys/net/ipv6/conf/all/dad_transmits)
if [ $IPV6DADTRANSMITS = 1 ]; then
	sysctl -w net.ipv6.conf.all.dad_transmits="0"
else
	echo -e "\t\t\t[±] IPV6 Dad Transmits Is'nt Enabled, No Need To Customize The Sysctl Rule..."
fi
echo
echo
IPV6DADTRANSMITS=$(cat /proc/sys/net/ipv6/conf/all/accept_redirects)
if [ $IPV6DADTRANSMITS = 1 ]; then
	sysctl -w net.ipv6.conf.all.accept_redirects="0"
else
	echo -e "\t\t\t[+] IPV6 Accept Redirects Is'nt Enabled, No Need To Customize The Sysctl Rule..."
fi
echo
echo
IPV6DADTRANSMITS=$(cat /proc/sys/net/ipv6/conf/all/accept_redirects)
if [ $IPV6DADTRANSMITS = 1 ]; then
	sysctl -w net.ipv6.conf.all.accept_redirects="0"
else
	echo -e "\t\t\t[+] IPV6 Accept Redirects Is'nt Enabled, No Need To Customize The Sysctl Rule..."
fi
echo
echo
IPV6DADTRANSMITS=$(cat /proc/sys/net/ipv6/conf/all/accept_redirects)
if [ $IPV6DADTRANSMITS = 1 ]; then
	sysctl -w net.ipv6.conf.all.accept_redirects="0"
else
	echo -e "\t\t\t[+] IPV6 Accept Redirects Is'nt Enabled, No Need To Customize The Sysctl Rule..."
fi
echo
sysctl -w net.ipv6.conf.all.accept_ra_mtu="0"
sysctl -w net.ipv6.conf.all.autoconf="0"
sysctl -w net.ipv6.conf.all.disable_ipv6="1"
# sysctl -w net.ipv6.conf.all.accept_dad="0"
# sysctl -w net.ipv6.conf.all.accept_dad="0"
# sysctl -w net.ipv6.conf.all.accept_ra="0"
# sysctl -w net.ipv6.conf.all.accept_redirects="0"
sysctl -w net.ipv6.conf.all.accept_dad="0"
sysctl -w net.ipv6.conf.all.accept_ra="0"
sysctl -w net.ipv6.conf.all.accept_ra_defrtr="0"
sysctl -w net.ipv6.conf.all.accept_ra_pinfo="0"
sysctl -w net.ipv6.conf.all.accept_ra_rt_info_max_plen="0"
sysctl -w net.ipv6.conf.all.accept_ra_rtr_pref="0"
sysctl -w net.ipv6.conf.all.accept_redirects="0"
sysctl -w net.ipv6.conf.all.accept_source_route="0"
echo
# echo "faggot" > /proc/sys/kernel/hostname
# echo "## ============================================================================== ##"
# echo -e "\t\t\t[+] Modifying Local Port Range..."
# echo "## ============================================================================== ##"
# cat /proc/sys/net/ipv4/ip_local_port_range
echo
## echo "## ============================================================================== ##"
## echo -e "\t\t\t[+] Changing TW Socket Reuse & Recycling Time-Wait Values..."
## echo "## ============================================================================== ##"
## echo -e "\t[+] Warning: This may cause dropped frames with load-balancing and NATs,
## echo -e "\t[+] only use this for a server that communicates only over your local network.
## sysctl -w net.ipv4.tcp_tw_reuse = 1
## sysctl -w net.ipv4.tcp_tw_recycle = 1
echo


echo "## ############################################################################## ##"
echo "## ============================================================================== ##"
echo -e "\t\t\t[+] Hardening Ulimit Configurations..."
echo "## ============================================================================== ##"
echo "## ############################################################################## ##"
echo
echo
echo "## ============================================================================== ##"
echo -e "\t\t\t[+] Modifying User Process Limits..."
echo "## ============================================================================== ##"

if [ -e /etc/security/limits.conf ]; then
	if [ -e /proc/sys/net/ipv4/conf/all/rp_filter ]; then
        echo -n "Setting up IP spoofing protection..."
		for i in /proc/sys/net/ipv4/conf/*/rp_filter; do
        echo 1 > $i
        	done
        rpfilt="cat /proc/sys/net/ipv4/conf/all/rp_filter"
		echo "/proc/sys/net/ipv4/conf/all/rp_filter:$rpfilt"
	else
        echo "WARNING: errors encountered while trying to enable IP spoofing protection!"
	fi
fi

echo "*   hard    nproc   250              # Limit user processes " >> /etc/security/limits.conf
echo
echo
echo "## ============================================================================== ##"
echo -e "\t\t\t[+] noexec_user_stack"
echo "## ============================================================================== ##"
sysctl -w noexec_user_stack="1"
set noexec_user_stack=1
echo "## ============================================================================== ##"
echo -e "\t\t\t[+] noexec_usr_stack_log"
echo "## ============================================================================== ##"
sysctl -w noexec_usr_stack_log="1"
set noexec_usr_stack_log=1
echo
echo
sysctl -w kernel.randomize_va_space="2"
echo
echo


echo "## ============================================================================== ##"
echo -e "\t\t[+] Checking Value of Kernel Secure Level..."
echo -e "\t\t[+] Modifying Parameter Value If Value isnt 2..."
echo "## ============================================================================== ##"
SECURELEVEL=$(cat /sys/kernel/security/securelevel)
if [ $SECURELEVEL = 0 ];then 
	echo 2 > /sys/kernel/security/securelevel			# sysctl -w kern.securelevel="2"
	echo -e "\t\t\t[+] Kernel Secure Level Is Now 2..."
else
	echo -e "\t\t\t[+] Kernel Secure Level Is 2, No Need To Change It..."
	echo 
fi
echo

echo "## ============================================================================== ##"
echo -e "\t\t\t[+] Setting Dmesg Restrict To 0..."
echo "## ============================================================================== ##"
# DMESGRESTRICT=$(cat )
sysctl -w kernel.dmesg_restrict="0"
echo
echo

echo "## ============================================================================== ##"
echo -e "\t\t\t[+] Modifying Kernel Kptr_Restrict Value To 1..."
echo "## ============================================================================== ##"
sysctl -w kernel.kptr_restrict="1"
echo
echo
echo "## ============================================================================== ##"
echo -e "\t\t\t[+] Enabling ExecShield Protection..."
echo "## ============================================================================== ##"
sysctl -w kernel.exec-shield="1"
set kernel.exec-shield="1"
echo
echo
echo "## ============================================================================== ##"
echo -e "\t\t\t[+] Enabling Kernels Use of PIDs..."
echo "## ============================================================================== ##"
sysctl -q -w kernel.core_uses_pid="1"
echo
echo
if [ -e "/etc/sysctl.conf" ]; then
	echo "## ============================================================================== ##"
	echo -e "\t\t\t[+] /etc/sysctl.conf Exists!"
	echo "## ============================================================================== ##"
		else
			echo "# Do not accept ICMP redirects (prevent MITM attacks)" >> /etc/sysctl.conf
			echo "net.ipv4.conf.all.accept_redirects=0" >> /etc/sysctl.conf
			echo "net.ipv6.conf.all.accept_redirects=0" >> /etc/sysctl.conf
			echo -e "\n\n"
			echo "## TCP SYN cookie protection (default)" >> /etc/sysctl.conf
			echo "## helps protect against SYN flood attacks" >> /etc/sysctl.conf
			echo "## only kicks in when net.ipv4.tcp_max_syn_backlog is reached" >> /etc/sysctl.conf
			echo "net.ipv4.tcp_syncookies=1" >> /etc/sysctl.conf
			echo -e "\n\n" >> /etc/sysctl.conf
			echo "#net.ipv6.conf.default.accept_redirects=0" >> /etc/sysctl.conf
			echo -e "\n\n" >> /etc/sysctl.conf
			echo "net.ipv4.tcp_timestamps=0" >> /etc/sysctl.conf
			echo -e "\n\n" >> /etc/sysctl.conf
			echo "net.ipv4.conf.default.log_martians=1" >> /etc/sysctl.conf
			echo -e "\n\n" >> /etc/sysctl.conf
			echo "net.ipv4.icmp_echo_ignore_broadcasts=1" >> /etc/sysctl.conf
			echo -e "\n\n" >> /etc/sysctl.conf
			echo "net.ipv4.conf.all.forwarding=0" >> /etc/sysctl.conf
			echo -e "\n\n" >> /etc/sysctl.conf
			echo "net.ipv4.conf.all.rp_filter=1" >> /etc/sysctl.conf
			echo -e "\n\n" >> /etc/sysctl.conf
			echo "net.ipv4.tcp_max_syn_backlog=1280" >> /etc/sysctl.conf
			echo -e "\n\n" >> /etc/sysctl.conf
			echo "kernel.core_uses_pid=1" >> /etc/sysctl.conf   						# Controls whether core dumps will append the PID to the core filename
			echo -e "\n\n" >> /etc/sysctl.conf
			echo "kernel.sysrq=0" >> /etc/sysctl.conf
			echo -e "\n\n" >> /etc/sysctl.conf
			echo "kernel.randomize_va_space=2" >> /etc/sysctl.conf
			echo "kern.securelevel=1" >> /etc/sysctl.conf
			echo "" >> /etc/sysctl.conf
			echo "" >> /etc/sysctl.conf
			echo "" >> /etc/sysctl.conf
			echo -e "\n\n" >> /etc/sysctl.conf
			echo "## ignore all pings" >> /etc/sysctl.conf
			echo "net.ipv4.icmp_echo_ignore_all=1" >> /etc/sysctl.conf
			echo -e "\n\n" >> /etc/sysctl.conf
			echo "## Do not send ICMP redirects (we are not a router)" >> /etc/sysctl.conf
			echo "net.ipv4.conf.all.send_redirects = 0" >> /etc/sysctl.conf
			echo -e "\n\n" >> /etc/sysctl.conf
			echo "## Do not accept IP source route packets (we are not a router)" >> /etc/sysctl.conf
			echo "net.ipv4.conf.all.accept_source_route = 0" >> /etc/sysctl.conf
			echo "net.ipv6.conf.all.accept_source_route = 0" >> /etc/sysctl.conf
			echo -e "\n\n" >> /etc/sysctl.conf
			echo "## Log Martian Packets" >> /etc/sysctl.conf
			echo "net.ipv4.conf.all.log_martians = 1" >> /etc/sysctl.conf
			echo -e "\n\n" >> /etc/sysctl.conf
			echo "kernel.exec-shield = 1" >> /etc/sysctl.conf
			# echo " = 1" >> /etc/sysctl.conf
			# echo " = 1" >> /etc/sysctl.conf
			# echo " = 1" >> /etc/sysctl.conf
			# echo " = 1" >> /etc/sysctl.conf
			# echo " = 1" >> /etc/sysctl.conf
fi
echo -e "## ============================================================================== ##"
echo -e "\t\t\t[+] Applying Sysctl Changes..."
echo -e "## ============================================================================== ##"
sysctl -p


chmod 0644 /etc/sysctl.conf 
chown root:root /etc/sysctl.conf

# /lib/systemd/systemd-sysctl --prefix kernel.core_pattern			# Update coredump handler configuration
# /lib/systemd/systemd-sysctl 50-coredump.conf						# Update coredump handler configuration according to a specific file
echo


if [ ! -x /sbin/$IPTABLES ]; then
    echo $"${IPTABLES}: /sbin/$IPTABLES does not exist."
    exit 5
fi



## echo "## ============================================================================== ##"
## echo -e "\t\t\t[+] Flushing existing iptables rules..."
## echo "## ============================================================================== ##"

flush_delete()
{
	/sbin/iptables -F
/sbin/iptables -t nat -F
/sbin/iptables -t mangle -F
/sbin/iptables -X
/sbin/iptables -t nat -X
/sbin/iptables -t mangle -X
/sbin/iptables -Z
	echo "[*] Flushing existing iptables rules..."
		$IPTABLES -F
		$IPTABLES -F -t nat
		$IPTABLES -F -t mangle
		$IPTABLES -t nat -X
		$IPTABLES -t mangle -X
		$IPTABLES -X
		$IPTABLES -Z
## 
## ======================================================================================== ##

echo -e "## ============================================================================== ##"
echo -e "\t[+] flush existing rules and set chain policy setting to DROP..."
echo -e "## ============================================================================== ##"

function block_everything()
{
	$IPTABLES -P INPUT DROP
	$IPTABLES -P OUTPUT DROP
	$IPTABLES -P FORWARD DROP
}

## ======================================================================================== ##
## 
echo
echo "## ============================================================================== ##"
echo -e "\t[+] This Policy Does Not Handle IPv6 Traffic Besides Dropping It..."
echo "## ============================================================================== ##"
echo
echo
echo
echo "[+]=====================================================================[+]"
echo -e "\t\t [+] Allow Traffic on The Loopback Interface..."
echo "[+]=====================================================================[+]"
## 
## ======================================================================================== ##
$IPTABLES -A INPUT -i $LOOPBACK -m comment --comment "Allow Input Loopback Connections" -j ACCEPT
$IPTABLES -A OUTPUT -o $LOOPBACK -m comment --comment "Allow Output Loopback Connections" -j ACCEPT
## ======================================================================================== ##
## 
echo "[+]=====================================================================[+]"
echo -e "\t\t [+] Blocking All Traffic on The Loopback Interface..."
echo "[+]=====================================================================[+]"
## 
## ===================================================================================================== ##
$IP6TABLES -A INPUT -i $LOOPBACK -m comment --comment "Deny Input IPV6 Loopback Connections" -j DENY
$IP6TABLES -A OUTPUT -o $LOOPBACK -m comment --comment "Deny Output IPV6 Loopback Connections" -j DENY
## ===================================================================================================== ##
## 
echo "[+]=====================================================================[+]"
echo -e "\t\t Establishing Your Custom Logging Prefixes..."
echo "[+]=====================================================================[+]"
## 
## ======================================================================================== ##
$IP6TABLES -A INPUT -j LOG --log-prefix "Blocked INPUT IPV6: "
$IP6TABLES -A OUTPUT -j LOG --log-prefix "Blocked OUTPUT IPV6: "
$IP6TABLES -A FORWARD -j LOG --log-prefix "Blocked FORWARD IPV6: "
## ======================================================================================== ##
## 
echo "## ============================================================================== ##"
echo -e "\t\t\t[+] Disabling IPv6 traffic..."
echo "## ============================================================================== ##"
## 
## ======================================================================================== ##
$IP6TABLES -P INPUT DROP
$IP6TABLES -P OUTPUT DROP
$IP6TABLES -P FORWARD DROP
## ======================================================================================== ##
## 
echo "## ============================================================================== ##"
echo -e "\t\t\t[+] Creating Bad Flags Chain..."
echo "## ============================================================================== ##"
## 
## ======================================================================================== ##
$IPTABLES -N LOG_DROP
## ======================================================================================== ##
## 
echo "## ============================================================================== ##"
echo -e "\t\t[+] Pass traffic with bad flags to the Bad Flags Chain"
echo "## ============================================================================== ##"
## 
## ======================================================================================== ##
$IPTABLES -A INPUT -p tcp -j LOG_DROP
## ======================================================================================== ##
## 
echo "## ============================================================================== ##"
echo -e "\t\t[+] Droping bad TCP/UDP Combinations..."
echo "## ============================================================================== ##"
## 
## ======================================================================================== ##
$IPTABLES -A INPUT -p tcp --dport 0 -j DROP
$IPTABLES -A INPUT -p udp --dport 0 -j DROP
$IPTABLES -A INPUT -p tcp --tcp-flags ALL NONE -j DROP
$IPTABLES -A INPUT -p tcp --tcp-flags ALL ALL -j DROP
## ======================================================================================== ##
## 
# echo "## ============================================================================== ##"
# echo -e "\t\t[+] Dropping INPUT From Specific Sources..."
# echo "## ============================================================================== ##"
## 
## ======================================================================================== ##
# $IPTABLES -A INPUT -i wlan0 -s 0.0.0.0/8 -j DROP
# $IPTABLES -A INPUT -i wlan0 -s 127.0.0.1/8 -j DROP
# $IPTABLES -A INPUT -i wlan0 -s 10.0.0.0/8 -j DROP
# $IPTABLES -A INPUT -i wlan0 -s 192.168.0.0/16 -j DROP
# $IPTABLES -A INPUT -i wlan0 -s 172.16.0.0/12 -j DROP
# $IPTABLES -A INPUT -i wlan0 -s 224.0.0.0/4 -j DROP
## ======================================================================================== ##
## 

# echo "## ============================================================================== ##"
# echo -e "\t\t\t [?] set host machine as a NAT router"
# echo "## ============================================================================== ##"
# 
# $IPTABLES -t nat -A POSTROUTING -s 192.168.1.0/255.255.255.0 -o eth0 -j SNAT --to-source 192.168.0.5
## ======================================================================================== ##

## 
iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE


echo "## ============================================================================== ##"
echo -e "\t\t\t[+] DROP INVALID Packets"
echo "## ============================================================================== ##"
##
## ======================================================================================== ##
# drop invalid incoming traffic
$IPTABLES -A INPUT -m state --state INVALID -j DROP

# Drop invalid outgoing traffic, too.
$IPTABLES -A OUTPUT -m state --state INVALID -j DROP

# If we would use NAT, INVALID packets would pass - BLOCK them anyways
$IPTABLES -A FORWARD -m state --state INVALID -j DROP
## ======================================================================================== ##
## 


ufw allow to 10.0.0.1 proto ipv6

echo "## ============================================================================== ##"
echo -e "\t\t[+] Dropping Incoming Malformed XMAS Packets..."
echo "## ============================================================================== ##"
echo "## "
echo "## ======================================================================================== ##"
$IPTABLES -A INPUT -p tcp --tcp-flags ALL ALL -j DROP
echo "## ======================================================================================== ##"
echo "## "
echo
echo



echo "## ================================================================================ ##"
echo -e "\t\t [?] The Structure of A TCP Header Without Options:"
echo "## ================================================================================ ##"
echo -e "\t\t 0                            15                              31 "
echo -e "\t\t-----------------------------------------------------------------"
echo -e "\t\t|          source port          |       destination port        |"
echo -e "\t\t-----------------------------------------------------------------"
echo -e "\t\t|                        sequence number                        |"
echo -e "\t\t-----------------------------------------------------------------"
echo -e "\t\t|                     acknowledgment number                     |"
echo -e "\t\t-----------------------------------------------------------------"
echo -e "\t\t|  HL   | rsvd  |C|E|U|A|P|R|S|F|        window size            |"
echo -e "\t\t-----------------------------------------------------------------"
echo -e "\t\t|         TCP checksum          |       urgent pointer          |"
echo -e "\t\t-----------------------------------------------------------------"
echo "## ================================================================================ ##"



echo "## =============================================================================================== ##"
echo -e "\t [?] A  TCP header usually holds 20 octets of data, unless options are present."
echo -e "\t\t --> The first line of the graph contains octets 0 - 3"
echo -e "\t\t --> The second line shows octets 4 - 7"
echo "## =============================================================================================== ##"
echo -e "\t [?] Starting to count with 0, the relevant TCP control bits are contained in octet 13:"
echo "## =============================================================================================== ##"
echo
echo
echo "## =============================================================== ##"
echo "## ================= NMap Packet Fingerprinting: ================= ##"
echo "## =============================================================== ##"
echo -e "\t\t[?] Tseq is the TCP sequenceability test"
echo -e "\t\t[?] T1 is a SYN packet with a bunch of TCP options to open port"
echo -e "\t\t[?] T2 is a NULL packet w/options to open port"
echo -e "\t\t[?] T3 is a SYN|FIN|URG|PSH packet w/options to open port"
echo -e "\t\t[?] T4 is an ACK to open port w/options"
echo -e "\t\t[?] T5 is a SYN to closed port w/options"
echo -e "\t\t[?] T6 is an ACK to closed port w/options"
echo -e "\t\t[?] T7 is a FIN|PSH|URG to a closed port w/options"
echo -e "\t\t[?] PU is a UDP packet to a closed port"
echo "## =============================================================== ##"


echo "## ========================================================================= ##"
echo "## ========================================================================= ##"
echo -e "\t\t\t 0             7|             15|             23|             31 "
echo -e "\t\t\t----------------|---------------|---------------|----------------"
echo -e "\t\t\t|  HL   | rsvd  |C|E|U|A|P|R|S|F|        window size            |"
echo -e "\t\t\t----------------|---------------|---------------|----------------"
echo -e "\t\t\t|               |  13th octet   |               |               |"

echo
echo "## ========================================================================= ##"
echo
echo -e "\t\tLets have a closer look at octet no. 13:"
echo
echo "## ========================================================================= ##"
echo -e "\t\t\t|               |"
echo -e "\t\t\t|---------------|"
echo -e "\t\t\t|C|E|U|A|P|R|S|F|"
echo -e "\t\t\t|---------------|"
echo -e "\t\t\t|7   5   3     0|"
echo "## =========================================================================================== ##"
echo "These are the TCP control bits we are interested in.  We have numbered the  bits  in  this"
echo "octet  from  0  to  7, right to left, so the PSH bit is bit number 3, while the URG bit is"
echo "## =========================================================================================== ##"
echo
echo "## ============================================================================== ##"
echo -e "\t\t\t[+] Dropping Invalid SYN Packets..."
echo "## ============================================================================== ##"
## 
## ======================================================================================== ##
$IPTABLES -A INPUT -p tcp --tcp-flags ALL ACK,RST,SYN,FIN -j DROP
$IPTABLES -A INPUT -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP
$IPTABLES -A INPUT -p tcp --tcp-flags SYN,RST SYN,RST -j DROP
## ======================================================================================== ##
## 
echo
echo
echo "## ============================================================================== ##"
echo -e "\t\t[+] Dropping Incoming Malformed NULL Packets..."
echo "## ============================================================================== ##"
## 
## ======================================================================================== ##
$IPTABLES -A INPUT -p tcp --tcp-flags ALL NONE -j DROP
## ======================================================================================== ##
## 
# echo "## ============================================================================== ##"
# echo -e "\t\t\t[+] Applying Anti-Spoofing Rules..."
# echo "## ============================================================================== ##"
# $IPTABLES -A INPUT -i $IFACE ! -s $INT_NET -j LOG --log-prefix "SPOOFED PKT "
# $IPTABLES -A INPUT -i $IFACE ! -s $INT_NET -j DROP
echo
echo
echo "###################################################################################"
echo "[+]=====================================================================[+]"
echo -e "\t\t\t Primary ICMP Types"
echo "[+]=====================================================================[+]"
echo -e "\t\t\t## || 0: Echo-Reply (Pong)         || ##"
echo -e "\t\t\t## || 3: Destination-Unreachable,  || ##"
echo -e "\t\t\t## || ============================ || ##"
echo "            ||     == > Port-Unreachable	  || ##"
echo "            ||	 == > Fragmentation-Needed|| ##"
echo -e "\t\t\t## || ============================ || ##"
echo -e "\t\t\t## || 4: Source-Quench             || ##"
echo -e "\t\t\t## || 5: Redirect                  || ##"
echo -e "\t\t\t## || 8: Echo-Request (Ping)       || ##"
echo -e "\t\t\t## || 11: Time-Exceeded            || ##"
echo -e "\t\t\t## || 12: Parameter-Problem        || ##"
echo "[+]=====================================================================[+]"
echo "###################################################################################"
echo
##########
# icmp types
#
#  0    Echo Reply                               [RFC792]
#  1    Unassigned                                  [JBP]
#  2    Unassigned                                  [JBP]
#  3    Destination Unreachable                  [RFC792]
#  4    Source Quench                            [RFC792]
#  5    Redirect                                 [RFC792]
#  6    Alternate Host Address                      [JBP]
#  7    Unassigned                                  [JBP]
#  8    Echo                                     [RFC792]
#  9    Router Advertisement                    [RFC1256]
# 10    Router Solicitation                     [RFC1256]
# 11    Time Exceeded                            [RFC792]
# 12    Parameter Problem                        [RFC792]
# 13    Timestamp                                [RFC792]
# 14    Timestamp Reply                          [RFC792]
# 15    Information Request                      [RFC792]
# 16    Information Reply                        [RFC792]
# 17    Address Mask Request                     [RFC950]
# 18    Address Mask Reply                       [RFC950]
# 19    Reserved (for Security)                    [Solo]
# 20-29 Reserved (for Robustness Experiment)        [ZSu]
# 30    Traceroute                              [RFC1393]
# 31    Datagram Conversion Error               [RFC1475]
# 32     Mobile Host Redirect              [David Johnson]
# 33     IPv6 Where-Are-You                 [Bill Simpson]
# 34     IPv6 I-Am-Here                     [Bill Simpson]
# 35     Mobile Registration Request        [Bill Simpson]
# 36     Mobile Registration Reply          [Bill Simpson]
# 37     Domain Name Request                     [Simpson]
# 38     Domain Name Reply                       [Simpson]
# 39     SKIP                                    [Markson]
# 40     Photuris                                [Simpson]
# 41-255 Reserved                                   [JBP]
##########
echo
echo "[+]=====================================================================[+]"
echo -e "\t\t\t[+] Blocking INCOMING ICMP Pings..."
echo "[+]=====================================================================[+]"
echo
echo
echo -e "\t\t__________________________________________"
echo
echo -e "\t\t\t[+] Required ICMP Packets:"
echo -e "\t\t__________________________________________"
echo
echo -e "\t\t<{&}===================================={&}>"
echo -e "\t\t     || • Destination-Unreachable(3) ||"
echo -e "\t\t     || • Source-Quench(4)           ||"
echo -e "\t\t     || • Time-Exceeded(11)          ||"
echo -e "\t\t<{&}===================================={&}>"
echo
echo "[+]=====================================================================[+]"


$ICMP_TYPE


## 
## ======================================================================================== ##

icmp_ratelimit

PROTO="icmp"
if [ "$ICMP_LIM" == "" ]; then
	ICMP_LIM=0
fi
if [ "$(echo $ICMP_LIM | tr '/' ' ' | awk '{print$1}')" -gt "0" ]; then
	ICMP_EARGS="-m limit --limit $ICMP_LIM"
else
	ICMP_EARGS=""
	
	
-m limit --limit $ICMP_LIM


$IPT -A INPUT -p icmp --icmp-type $ICMP_TYPE -d $VNET  -s 0/0 $ICMP_EARGS -j ACCEPT
                  eout "{glob} opening inbound $PROTO type $i on $VNET"

done
fi


$IPTABLES -A INPUT -p icmp -m icmp --icmp-type 3 -j ACCEPT
$IPTABLES -A INPUT -p icmp -m icmp --icmp-type 4 -j ACCEPT
$IPTABLES -A INPUT -p icmp -m icmp --icmp-type 11 -j ACCEPT
## ======================================================================================== ##
## 
echo "[+]====================================================================================[+]"
echo -e "\tFor ping and traceroute you want echo-request(8) and echo-reply(0) enabled:"
echo -e "\tYou might be able to disable them, but it would probably break things."
echo "[+]====================================================================================[+]"
## 
## ======================================================================================== ##
$IPTABLES -A INPUT -p icmp -m icmp --icmp-type 0 -j ACCEPT
$IPTABLES -A INPUT -p icmp -m icmp --icmp-type 8 -j ACCEPT
$IPTABLES -A OUTPUT -m conntrack --ctstate INVALID -j REJECT --reject-with icmp-admin-prohibited
$IPTABLES -A OUTPUT -m state --state INVALID -j REJECT --reject-with icmp-admin-prohibited
#$IPTABLES  -A OUTPUT ! -o lo ! -d 127.0.0.1 ! -s 127.0.0.1 -p tcp -m tcp --tcp-flags ACK,FIN ACK,FIN -j REJECT --reject-with icmp-admin-prohibited
#$IPTABLES -A OUTPUT ! -o lo ! -d 127.0.0.1 ! -s 127.0.0.1 -p tcp -m tcp --tcp-flags ACK,RST ACK,RST -j REJECT --reject-with icmp-admin-prohibited
## ======================================================================================== ##
## 

iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 1/s -j ACCEPT



# First, drop all fragmented ICMP packets (almost always malicious).
$IPTABLES -A INPUT -p icmp --fragment -j DROPLOG
$IPTABLES -A OUTPUT -p icmp --fragment -j DROPLOG
$IPTABLES -A FORWARD -p icmp --fragment -j DROPLOG


# IPv6 Neighbor Discovery (icmp-type 133-137)
-A INPUT -p ipv6-icmp --icmpv6-type 133 -m hl --hl-eq 255 -j ACCEPT
-A INPUT -p ipv6-icmp --icmpv6-type 134 -m hl --hl-eq 255 -j ACCEPT
-A INPUT -p ipv6-icmp --icmpv6-type 135 -m hl --hl-eq 255 -j ACCEPT
-A INPUT -p ipv6-icmp --icmpv6-type 136 -m hl --hl-eq 255 -j ACCEPT
-A INPUT -p ipv6-icmp --icmpv6-type 137 -m hl --hl-eq 255 -j ACCEPT
-A INPUT -p ipv6-icmp -j LOG --log-prefix "Dropped ICMPv6 Packets "
-A INPUT -p ipv6 -j DROP

# Drop any other ICMP traffic.
$IPTABLES -A INPUT -p icmp -j DROPLOG
$IPTABLES -A OUTPUT -p icmp -j DROPLOG
$IPTABLES -A FORWARD -p icmp -j DROPLOG

echo "[+]=====================================================================[+]"
echo -e "\t\t\tDROP INVALID SYN PACKETS..."
echo "[+]=====================================================================[+]"
## 
## ======================================================================================== ##
$IPTABLES -A OUTPUT -p tcp --tcp-flags ALL ACK,RST,SYN,FIN -j REJECT --reject-with icmp-admin-prohibited
$IPTABLES -A OUTPUT -p tcp --tcp-flags SYN,FIN SYN,FIN -j REJECT --reject-with icmp-admin-prohibited
$IPTABLES -A OUTPUT -p tcp --tcp-flags SYN,RST SYN,RST -j REJECT --reject-with icmp-admin-prohibited
## ======================================================================================== ##
## 
echo "[+]=====================================================================[+]"
echo -e "\t\t\tDROP PACKETS WITH INCOMING FRAGMENTS. "
echo -e "\t\t\tTHIS ATTACK ONCE RESULTED IN KERNEL PANICS"
echo "[+]=====================================================================[+]"
$IPTABLES -A OUTPUT -f -j REJECT --reject-with icmp-admin-prohibited
## ======================================================================================== ##
## 
echo "[+]=====================================================================[+]"
echo -e "\t\t\tDROP INCOMING MALFORMED XMAS PACKETS..."
echo "[+]=====================================================================[+]"
## 
## ======================================================================================== ##
$IPTABLES -A OUTPUT -p tcp --tcp-flags ALL ALL -j REJECT --reject-with icmp-admin-prohibited
## ======================================================================================== ##
## 
echo "[+]=====================================================================[+]"
echo -e "\t\t\tDROP INCOMING MALFORMED NULL PACKETS"
echo "[+]=====================================================================[+]"
## 
## ======================================================================================== ##
$IPTABLES -A OUTPUT -p tcp --tcp-flags ALL NONE -j REJECT --reject-with icmp-admin-prohibited
## ======================================================================================== ##
## 
echo "[+]=====================================================================[+]"
echo -e "\t\t\tRejecting All Other ICMP Types..."
echo "[+]=====================================================================[+]"
## 
## ======================================================================================== ##
$IPTABLES -A INPUT -p icmp -m limit --limit 10/min --limit-burst 1000 -j LOG --log-prefix "iptables: ICMP !0/3/4/8/11: " --log-level 7 
$IPTABLES -A INPUT -p icmp -j REJECT --reject-with icmp-host-unreachable
## ======================================================================================== ##
## 
echo "## ============================================================================== ##"
echo -e "\t[+] Dropping All The Pings With A Packet Size Greater Than 85 Bytes..."
echo "## ============================================================================== ##"
## 
## ======================================================================================== ##
$IPTABLES -A INPUT -p icmp --icmp-type echo-request -m length --length 86:0xffff -j DROP
$IPTABLES -A INPUT -p icmp --icmp-type echo-request -m length --length 86:0xffff -j LOG --log-prefix "Ping Packet Size Larger Than 85 Bytes: " --log-level 7
## ======================================================================================== ##
## 
# echo "## ================================================================= ##"
# echo -e "\tlimit the number of parallel connections made by a whole class A:"
# echo "## ================================================================= ##"
## iptables -A INPUT -p tcp --syn --dport http -m iplimit --iplimit-mask 8 --iplimit-above 4 -j REJECT
echo

## iptables -A OUTPUT -p tcp --sport 80 -m cgroup ! --path service/http-server -j DROP
## iptables -A OUTPUT -p tcp --sport 80 -m cgroup ! --cgroup 1 -j DROP


echo
# echo "## ================================================================= ##"
# echo -e "\tSilently dropping all the broadcasted packets..."
# echo "## ================================================================= ##"
# echo "## -------------------------------------------------------------------------------------------- ##"
# echo "DROP       all  --  anywhere             anywhere           PKTTYPE = broadcast"
# echo "## -------------------------------------------------------------------------------------------- ##
# iptables -A INPUT -m pkttype --pkt-type broadcast -j DROP			# --> to all Broadcast Packets
echo
# echo "## ================================================================= ##"
# echo -e "\tAllows you to add comments (up to 256 characters) to any rule..."
# echo "## ================================================================= ##"
# iptables -A INPUT -i eth1 -m comment --comment "my local LAN"
echo
echo "## ============================================================================== ##"
echo -e "\t\t\t[+] Creating Bad Flags Chain..."
echo "## ============================================================================== ##"
##
$IPTABLES -N BAD_FLAGS
$IPTABLES -N LOG_DROP
## ======================================================================================== ##
## 
echo
echo "## ============================================================================== ##"
echo -e "\t\t[+] Pass traffic with bad flags to the Bad Flags Chain"
echo "## ============================================================================== ##"
$IPTABLES -A INPUT -p tcp -j BAD_FLAGS
$IPTABLES -A INPUT -p tcp -j LOG_DROP
## ======================================================================================== ##
## 
echo
echo "## ============================================================================== ##"
echo -e "\t\t\t[+] Rules for traffic with bad flags..."
echo "## ============================================================================== ##"
$IPTABLES -A BAD_FLAGS -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP
$IPTABLES -A BAD_FLAGS -p tcp --tcp-flags SYN,RST SYN,RST -j LOG --log-prefix "Bad SR Flag: "
$IPTABLES -A BAD_FLAGS -p tcp --tcp-flags SYN,RST SYN,RST -j DROP
$IPTABLES -A BAD_FLAGS -p tcp --tcp-flags SYN,FIN,PSH SYN,FIN,PSH -j LOG --log-prefix "Bad SFP Flag: "
$IPTABLES -A BAD_FLAGS -p tcp --tcp-flags SYN,FIN,PSH SYN,FIN,PSH -j DROP
$IPTABLES -A BAD_FLAGS -p tcp --tcp-flags SYN,FIN,RST SYN,FIN,RST -j LOG --log-prefix "Bad SFR Flag: "
$IPTABLES -A BAD_FLAGS -p tcp --tcp-flags SYN,FIN,RST SYN,FIN,RST -j DROP
$IPTABLES -A BAD_FLAGS -p tcp --tcp-flags SYN,FIN,RST,PSH SYN,FIN,RST,PSH -j LOG --log-prefix "Bad SFRP Flag: "
$IPTABLES -A BAD_FLAGS -p tcp --tcp-flags SYN,FIN,RST,PSH SYN,FIN,RST,PSH -j DROP
$IPTABLES -A BAD_FLAGS -p tcp --tcp-flags FIN FIN -j LOG --log-prefix "Bad F Flag: "
$IPTABLES -A BAD_FLAGS -p tcp --tcp-flags FIN FIN -j DROP
$IPTABLES -A BAD_FLAGS -p tcp --tcp-flags ALL NONE -j LOG --log-prefix "Null Flag: "
$IPTABLES -A BAD_FLAGS -p tcp --tcp-flags ALL NONE -j DROP
$IPTABLES -A BAD_FLAGS -p tcp --tcp-flags ALL ALL -j LOG --log-prefix "All Flags: "
$IPTABLES -A BAD_FLAGS -p tcp --tcp-flags ALL ALL -j DROP
$IPTABLES -A BAD_FLAGS -p tcp --tcp-flags ALL FIN,URG,PSH -j LOG --log-prefix "Nmap:Xmas Flags: "
$IPTABLES -A BAD_FLAGS -p tcp --tcp-flags ALL FIN,URG,PSH -j DROP
$IPTABLES -A BAD_FLAGS -p tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG -j LOG --log-prefix "Merry Xmas Flags: "
$IPTABLES -A BAD_FLAGS -p tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG -j DROP
## ======================================================================================== ##
## 



##-=============================-##
##   IPTables - Dropbox Rules:
##-=============================-##
# iptables -A INPUT -p tcp --dport 17500 -j REJECT --reject-with icmp-port-unreachable
# iptables -R INPUT 1 -p tcp --dport 17500 ! -s 10.0.0.85 -j REJECT --reject-with icmp-port-unreachable
# iptables -I INPUT -p tcp --dport 17500 -s 10.0.0.85 -j ACCEPT -m comment --comment "Friendly Dropbox"
# iptables -R INPUT 2 -p tcp --dport 17500 -j REJECT --reject-with icmp-port-unreachable



echo "## ========================================================== ##"
echo -e "\t\t [+] Create A IPTables Chain That Log Drops: "
echo "## ========================================================== ##"
echo 
echo 
echo "## ================================================-##"
echo "     [+] Create: The Log-Drop IPTables Chain:         "
echo "## ================================================-##"
iptables -N logdrop


echo "##-=============================================================-##"
echo "     1). Establish A Burst Limit. If Limit is Violated Then;       "
echo "     2). Log-Drop Connection, and Mark Stream As Invalid:          "
echo "##-=============================================================-##"
iptables -A logdrop -m limit --limit 5/m --limit-burst 10 -j LOG
iptables -A logdrop -j DROP
iptables -A INPUT -m conntrack --ctstate INVALID -j logdrop
iptables -A logdrop -m limit --limit 5/m --limit-burst 10 -j LOG


echo "## ================================================================-##"
echo "    [+] Examine the Journalctls Logged data For # of Connections      "
echo "    [+] Also check if the connection was successful.                  "
echo "## ================================================================-##"
journalctl -k | grep "IN=.*OUT=.*" | less




echo
echo
echo "## ============================================================================== ##"
echo -e "\t\t\t[+] Preventing SYN Flooding..."
echo "## ============================================================================== ##"

##
## ======================================================================================== ##
$IPTABLES -A INPUT -i wlan0 -p tcp --syn -m limit --limit 5/second -j ACCEPT
## ======================================================================================== ##
## 

echo "## ============================================================================== ##"
echo -e "\t\t [+] Replace the client host MAC address field in "
echo -e "\t\t [+] The DHCP message with the given MAC address. "
echo "## ============================================================================== ##"


iptables -t mangle -A FORWARD -p udp --dport 67 -m physdev --physdev-in vmnet1 -m dhcpmac --mac 00:50:56:00:00:00/24 -j DHCPMAC --set-mac ab:cd:ef:00:00:00/24

iptables -t mangle -A FORWARD -p udp --dport 68 -m physdev --physdev-out vmnet1 -m dhcpmac --mac ab:cd:ef:00:00:00/24 -j DHCPMAC --set-mac 00:50:56:00:00:00/24


echo "## ============================================================================== ##"
echo -e "\t\t [+] Logging NULL Vuln Scanning of Ports
echo "## ============================================================================== ##"
$IPTABLES -j LOG --log-level 1 --log-prefix "Portscan NULL_SCAN:"






echo "## ============================================================================== ##"
echo -e "\t\t [?] Match packets which use port 22, to trigger LED lights." 
echo "## ============================================================================== ##"
$IPTABLES  -A INPUT -p tcp --dport 22 -j LED --led-trigger-id ssh

echo "## ============================================================================== ##"
echo -e "\t\t [?] Write the netfilter-ssh trigger rule to /sys"
echo "## ============================================================================== ##"
echo netfilter-ssh >/sys/class/leds/ath9k-phy0/trigger





echo "## ============================================================================== ##"
echo -e "\t\t [?] Dropping STUN (WebRTC) requests..."
echo "## ============================================================================== ##"
$IPTABLES -A OUTPUT -p udp --dport 3478 -j DROP
$IPTABLES -A OUTPUT -p udp --dport 3479 -j DROP
$IPTABLES -A OUTPUT -p tcp --dport 3478 -j DROP
$IPTABLES -A OUTPUT -p tcp --dport 3479 -j DROP









iptables -I FORWARD 1 -p tcp --dport 1433 -m state --state ESTABLISHED -m string --hex-string "'|00|" --algo bm -m string --hex-string "-|00|-|00|" --algo bm -j LOG --log-prefix "SQL INJECTION COMMENT "


iptables -I FORWARD 1 -p tcp --dport 21 -m state --state
ESTABLISHED -m string --string "site" --algo bm -m string --string "chown"
--algo bm -m length --length 140 -j LOG --log-prefix "CHOWN OVERFLOW "


$IPTABLES -A FWSNORT_FORWARD -d 192.168.10.0/24 -p udp --dport 27444 -m string
--string "l44adsl" --algo bm -m comment --comment "sid:237; msg: DDOS Trin00
Master to Daemon default password attempt; classtype: attempted-dos; reference:
arachnids,197; rev: 2; FWS:1.0;" -j LOG --log-ip-options --log-prefix "[1]
SID237 "

iptables -I FORWARD 1 -p tcp --dport 1433 -m state --state
ESTABLISHED -m string --hex-string "'|00|" --algo bm -m string --hex-string
"-|00|-|00|" --algo bm -j LOG --log-prefix "SQL INJECTION COMMENT "


iptables -I FORWARD 1 -p tcp --dport 21 -m state --state ESTABLISHED -m string --string "site" --algo bm -m string --string "chown" --algo bm -m length --length 140 -j LOG --log-prefix "CHOWN OVERFLOW "


iptables -I FORWARD 1 -p tcp --dport 443 -m state --state ESTABLISHED -m string --string "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" -j LOG --log-prefix "SSL OVERFLOW "

iptables -I FORWARD 1 -p tcp --dport 80 -m state --state ESTABLISHED -m string --string "/etc/shadow" --algo bm -j LOG --log-prefix "ETC_SHADOW "



iptables -I INPUT 1 -p udp --dport 5002 -m string --hex-string "|a7a7a7a7a7a7a7a7a7a7|" --algo bm -j LOG --log-prefix "YEN "
## tail /var/log/messages | grep YEN


iptables -I FORWARD 1 -p tcp --syn -m limit --limit 1/s -j ACCEPT


echo "## ============================================================================== ##"
echo "detects when the string "/bin/sh" is directed at a DNS server over UDP port 53:"
echo "## ============================================================================== ##"
iptables -A FORWARD -p udp --dport 53 -m string --string "/bin/sh" --algo bm -j LOG --log-prefix "SID100001 "


echo "## ============================================================================== ##"
echo "Drops all TCP packets destined for port 80 that contain the string "
echo "/etc/passwd in the packet payload anywhere after the hundredth byte:"
echo "## ============================================================================== ##"
iptables -A INPUT -p tcp --dport 80 -m string --string "/etc/passwd" --from 100 --algo bm -j DROP

echo "## ============================================================================== ##"
echo "drop all TCP packets destined for port 80 that contain the string "
echo "/etc/passwd within the packet payload anywhere before the thousandth byte:"
echo "## ============================================================================== ##"
iptables -A INPUT -p tcp --dport 80 -m string --string "/etc/passwd" --to 1000 --algo bm -j DROP

echo "## ============================================================================== ##"
echo "Log all TCP packets that have both the SYN and FIN flags set"
echo "## ============================================================================== ##"
iptables -A INPUT -p tcp --tcp-flags ALL SYN,FIN -j LOG --log-prefix "SCAN SYN FIN "

echo "## ============================================================================== ##"
drops all ICMP source-quench
echo "## ============================================================================== ##"
iptables -A INPUT -p icmp --icmp-type 4/0 -j DROP

echo "## ============================================================================== ##"
echo -e "\t\t[+] Detecting and logging all IP packets with a TTL value of zero.."
echo "## ============================================================================== ##"
iptables -A INPUT -p ip -m ttl --ttl-eq 0 -j LOG --log-prefix "ZERO TTL TRAFFIC "

echo "## ============================================================================== ##"
echo -e "\t\t[+] Logging all IP packets that have a TOS value of 16 (Minimize-Delay)"
echo "## ============================================================================== ##"
iptables -A INPUT -p ip -m tos --tos 16 -j LOG --log-prefix "MIN-DELAY TOS "	
iptables -I INPUT 1 -p tcp --dport 15104 -j LOG --log-tcp-options --log-tcp-sequence

## tail /var/log/messages | grep 15104


$IPTABLES -A FWSNORT_FORWARD -d 192.168.10.0/24 -p tcp --sport ! 80 -m string --hex-string "|90 90 90 E8 C0 FF FF FF|/bin/sh" --algo bm -m comment --comment "sid:652; msg: SHELLCODE Linux shellcode; classtype: shellcode-detect; reference: arachnids,343; rev: 9; FWS:1.0;" -j LOG --log-ip-options --log-tcp-options --log-prefix "[1] SID652 "

fwsnort --snort-sid 2002763
fwsnort --snort-sid 2002763 --ipt-reject
fwsnort --snort-sids 2001842

$IPTABLES -A FWSNORT_FORWARD_ESTAB -s 192.168.10.0/24 -p tcp --dport 80 -m
string --string ".php?p=" --algo bm -m string --string "?machineid=" --algo
bm -m string --string "&connection=" --algo bm -m string --string "&iplan="
--algo bm -m comment --comment "sid:2002763; msg: BLEEDING-EDGE TROJAN
Dumador Reporting User Activity; classtype: trojan-activity; reference:
url,www.norman.com/Virus/Virus_descriptions/24279/; rev: 2; FWS:1.0;" -j LOG
--log-ip-options --log-tcp-options --log-prefix "[1] SID2002763 ESTAB "


$IPTABLES -A FWSNORT_FORWARD -p udp --dport 53 -m string --hex-string " 05|
7sir7|03|com" --algo bm -m comment --comment "sid:2001842; msg:BLEEDING-EDGE
Possible DNS Lookup for DNS Poisoning Domain 7sir7.com; classtype:misc-
activity; reference:url,isc.sans.org/diary.php?date=2005-04-07; rev:3;
FWS:1.0;" -j LOG --log-ip-options --log-prefix "[1] SID2001842 "


$IPTABLES -A FWSNORT_FORWARD_ESTAB -p tcp --dport 80 -m string --string
"/Setup.php" --algo bm -m comment --comment "sid:2281; msg: WEB-PHP Setup.php
access; classtype: web-application-activity; reference: bugtraq,9057; rev: 2;
FWS:1.0;" -j LOG --log-ip-options --log-tcp-options --log-prefix "[1] SID2281
ESTAB "


$IPTABLES -A FWSNORT_FORWARD_ESTAB -p tcp --dport 80 -m string --string
"/Setup.php" --algo bm -m comment --comment "msg: WEB-PHP Setup.php access;
classtype: web-application-activity; reference: bugtraq,9057; rev: 2;
FWS:1.0;" -j LOG --log-ip-options --log-tcp-options --log-prefix "[1] DRP
SID2281 ESTAB "

$IPTABLES -A FWSNORT_FORWARD_ESTAB -p tcp --dport 80 -m string --string "/Setup.php" --algo bm -j DROP








#
# In Microsoft Networks you will be swamped by broadcasts. These lines
# will prevent them from showing up in the logs.
#

$IPTABLES -A udp_packets -p UDP -i $INET_IFACE --destination-port 135:139 -j DROP



echo
echo "## ============================================================================== ##"
echo -e "\t\t\t[+] Log and Drop Traffic in the INVALID state..."
echo "## ============================================================================== ##"
$IPTABLES -A INPUT -m state --state INVALID -j LOG --log-prefix "INVALID: "
$IPTABLES -A INPUT -m state --state INVALID -j DROP
## ======================================================================================== ##
## 

echo "## ============================================================================== ##"
echo -e "\t\t\t [+] Rejecting Access to Telnet..."
echo "## ============================================================================== ##"
echo "## ------------------------------------------------------------------------------ ##"
echo -e "\t\t [?] Do not allow a local user to connect to a remote Telnet"
echo "## ------------------------------------------------------------------------------ ##"
$IPTABLES -A OUTPUT -p tcp --dport telnet --jump REJECT
$IPTABLES -A INPUT -p udp --destination-port 514 -j LOG --log-prefix "SMTP client Attempt"
echo
echo "## ============================================================================== ##"
echo -e "\t\t[+] Accepting INPUT TCP/UDP 53, TCP 80, and TCP 443..."
echo "## ============================================================================== ##"
echo
echo "## ======================================================================================== ##"
echo -e "\t\t [+] Accepting INPUT SMTP clients {Port 25}..."
echo "## ======================================================================================== ##"
$IPTABLES -A INPUT -p tcp --dport 25 -j ACCEPT				# STMP Port
echo "## ======================================================================================== ##"
$IPTABLES -A INPUT -p udp --destination-port 514 -j LOG --log-prefix "SMTP client Attempt"





mac=`arp $ip | grep ether | awk '{ print $3 }'`

iptables -A INPUT -m mac --mac-source $mac -j DROP
								clear
								echo -e "\nClient with mac address $mac is now blocked.\n"
								echo -e "We will continue monitoring for changes in clients\n\n"






echo "#######################################################################################################"
echo "########## Postfix Submission Port 587 is currently commented out due to its lack of use ##############"
echo "## ==== If You want to allow the Postfix protocol on port 587, simple just uncomment the hashes ==== ##"
echo "## ================================================================================================= ##"
echo -e "\t\t [+] Accepting INPUT [Postfix Submission] {Port 587}..."
echo "## ================================================================================================= ##"
echo "## $IPTABLES -A INPUT -m state --state NEW -m tcp -p tcp --dport 587 -j ACCEPT"									
echo "## $IPTABLES -A INPUT -m state --state NEW -m udp -p udp --dport 587 -j ACCEPT"
echo "#######################################################################################################"



$IPTABLES -A udp_packets -p UDP -s 0/0 --source-port 53 -j ACCEPT
if [ $DHCP == "yes" ] ; then
	$IPTABLES -A udp_packets -p UDP -s $DHCP_SERVER --sport 67  --dport 68 -j ACCEPT
fi


#
# Special rule for DHCP requests from LAN, which are not caught properly 
# otherwise.
#

$IPTABLES -A INPUT -p UDP -i $LAN_IFACE --dport 67 --sport 68 -j ACCEPT




echo "## ======================================================================================== ##"
echo -e "\t\t [+] Accepting INPUT TCP DNS {Port 53}..."
echo "## ======================================================================================== ##"
$IPTABLES -A INPUT -p tcp --dport 53 -j ACCEPT				# TCP DNS Port
echo "## ======================================================================================== ##"
echo -e "\t\t [+] Accepting INPUT UDP DNS {Port 53}..."
echo "## ======================================================================================== ##"
$IPTABLES -A INPUT -p udp --dport 53 -j ACCEPT				# UDP DNS Port






#
# If you have a Microsoft Network on the outside of your firewall, you may
# also get flooded by Multicasts. We drop them so we do not get flooded by
# logs
#

$IPTABLES -A INPUT -i $INET_IFACE -d 224.0.0.0/8 -j DROP


# We don't care about Milkosoft, Drop SMB/CIFS/etc..
$IPTABLES -A INPUT -p tcp -m multiport --dports 135,137,138,139,445,1433,1434 -j DROP
$IPTABLES -A INPUT -p udp -m multiport --dports 135,137,138,139,445,1433,1434 -j DROP





echo "#######################################################################################################"
echo "########### The Kerberos Protocol Port 88 is commented out due to its lack of use #####################"
echo "## ==== If You want to allow the Kerberos protocol on port 88, simple just uncomment the hashes ==== ##"
echo "## ================================================================================================= ##"
echo -e "\t\t [+] Kerberos Authentication (IdM/IPA) {Port 88}..."
echo "## ================================================================================================= ##"
echo "## $IPTABLES -A INPUT -m state --state NEW -m tcp -p tcp --dport 88 -j ACCEPT"									## Kerberos Authentication (IdM/IPA) Port 88
echo "## $IPTABLES -A INPUT -m state --state NEW -m udp -p udp --dport 88 -j ACCEPT"
echo "#######################################################################################################"



echo "## ======================================================================================== ##"
echo -e "\t\t [+] Accepting INPUT NTP Server {Port 123}..."
echo "## ======================================================================================== ##"
#-A INPUT -m state --state NEW -m tcp -p tcp --dport 123 -j ACCEPT

#-A INPUT -m state --state NEW -m udp -p udp --dport 123 -j ACCEPT

## $IPTABLES -A INPUT -m state --state NEW -m tcp -p tcp --dport 123 -j ACCEPT
## $IPTABLES -A INPUT -p tcp --destination-port 123 -j LOG --log-prefix "NTP TCP Port 123 Probed..."
## $IPTABLES -A INPUT -m state --state NEW -m udp -p udp --dport 123 -j ACCEPT
## $IPTABLES -A INPUT -p udp --destination-port 123 -j LOG --log-prefix "NTP UDP Port 123 Probed..."



#######################################################################################################
################ The  Protocol/Port # is commented out due to its lack of use #########################
## ======= If You want to allow the  protocol on port  , simple just uncomment the hashes ========== ##
echo "## ======================================================================================== ##"
echo -e "\t\t [+] Accepting INPUT LDAP (IdM/IPA) {Port 389}..."
echo "## ======================================================================================== ##"
## $IPTABLES -A INPUT -m state --state NEW -m tcp -p tcp --dport 389 -j ACCEPT
## $IPTABLES -A INPUT -p tcp --destination-port  -j LOG --log-prefix "LDAP IdM/IPA TCP Port 389 Attempted"
## $IPTABLES -A INPUT -m state --state NEW -m udp -p udp --dport 389 -j ACCEPT
## $IPTABLES -A INPUT -p udp --destination-port  -j LOG --log-prefix "LDAP IdM/IPA UDP Port 389 Attempted"




#######################################################################################################
################ The  Protocol/Port # is commented out due to its lack of use #########################
## ======= If You want to allow the  protocol on port  , simple just uncomment the hashes ========== ##
## echo "## ======================================================================================== ##"
## echo -e "\t\t [+] Accepting INPUT  {Port }..."
## echo "## ======================================================================================== ##"
## $IPTABLES -A INPUT -m state --state NEW -m tcp -p tcp --dport  -j ACCEPT
## $IPTABLES -A INPUT -p tcp --destination-port  -j LOG --log-prefix " TCP Port  Attempted"
## $IPTABLES -A INPUT -m state --state NEW -m udp -p udp --dport  -j ACCEPT
## $IPTABLES -A INPUT -p udp --destination-port  -j LOG --log-prefix "  UDP Port  Attempted"
#######################################################################################################


echo "## ======================================================================================== ##"
echo -e "\t\t [+] Accepting INPUT  {Port }..."
echo "## ======================================================================================== ##"
## $IPTABLES -A INPUT -m state --state NEW -m tcp -p tcp --dport  -j ACCEPT
## $IPTABLES -A INPUT -p tcp --destination-port  -j LOG --log-prefix " TCP Port  Attempted"
## $IPTABLES -A INPUT -m state --state NEW -m udp -p udp --dport  -j ACCEPT
## $IPTABLES -A INPUT -p udp --destination-port  -j LOG --log-prefix "  UDP Port  Attempted"





#######################################################################################################
################ The  Protocol/Port # is commented out due to its lack of use #########################
## ======= If You want to allow the  protocol on port  , simple just uncomment the hashes ========== ##
## echo "## ======================================================================================== ##"
## echo -e "\t\t [+] Accepting INPUT  {Port }..."
## echo "## ======================================================================================== ##"
## $IPTABLES -A INPUT -m state --state NEW -m tcp -p tcp --dport  -j ACCEPT
## $IPTABLES -A INPUT -p tcp --destination-port  -j LOG --log-prefix " TCP Port  Attempted"
## $IPTABLES -A INPUT -m state --state NEW -m udp -p udp --dport  -j ACCEPT
## $IPTABLES -A INPUT -p udp --destination-port  -j LOG --log-prefix "  UDP Port  Attempted"
#######################################################################################################





#######################################################################################################
################ The  Protocol/Port # is commented out due to its lack of use #########################
## ======= If You want to allow the  protocol on port  , simple just uncomment the hashes ========== ##
## echo "## ======================================================================================== ##"
## echo -e "\t\t [+] Accepting INPUT  {Port }..."
## echo "## ======================================================================================== ##"
## $IPTABLES -A INPUT -m state --state NEW -m tcp -p tcp --dport  -j ACCEPT
## $IPTABLES -A INPUT -p tcp --destination-port  -j LOG --log-prefix " TCP Port  Attempted"
## $IPTABLES -A INPUT -m state --state NEW -m udp -p udp --dport  -j ACCEPT
## $IPTABLES -A INPUT -p udp --destination-port  -j LOG --log-prefix "  UDP Port  Attempted"
#######################################################################################################












echo "## ======================================================================================== ##"
echo -e "\t\t [+] Accepting INPUT  {Port }..."
echo "## ======================================================================================== ##"


echo "## ======================================================================================== ##"
echo -e "\t\t [+] Accepting INPUT TCP HTTP {Port 80}..."
echo "## ======================================================================================== ##"
$IPTABLES -A INPUT -p tcp --dport 80 -j ACCEPT				# HTTP Port
echo "## ======================================================================================== ##"
echo -e "\t\t [+] Accepting INPUT TCP HTTPS {Port 443}..."
echo "## ======================================================================================== ##"
$IPTABLES -A INPUT -p tcp --dport 443 -j ACCEPT				# HTTPS Port
## ======================================================================================== ##


echo "## ======================================================================================== ##"
echo -e "\t [+] Accepting INPUT Kerberos Authentication - kpasswd (IdM/IPA) {Port 464}..."
echo "## ======================================================================================== ##"
## $IPTABLES -A INPUT -m state --state NEW -m tcp -p tcp --dport 464 -j ACCEPT
## $IPTABLES -A INPUT -m state --state NEW -m udp -p udp --dport 464 -j ACCEPT


echo "## ======================================================================================== ##"
echo -e "\t\t [+] Accepting INPUT SYSLOG client {Port 514}..."
echo "## ======================================================================================== ##"
$IPTABLES -A OUTPUT -o $IFACE -p udp -s $IPADDR --source-port 514 -d $SYSLOG_SERVER --destination-port $UNPRIVPORTS -j ACCEPT
$IPTABLES -A INPUT -p udp --destination-port 514 -j LOG --log-prefix "SYSLOG client Attempt"
## ======================================================================================== ##

syslog-tls            6514/tcp


hkp                   11371

mdns                  5353
microsoft-ds          445
bgp                   179
netbios-ns            137/tcp
netbios-ns            137/udp
netbios-dgm           138/tcp
netbios-dgm           138/udp
netbios-ssn           139/tcp
netbios-ssn           139/udp



finger                79
whois                 43
nessus                1241

ipsec-nat-t           4500/udp
sftp                  115

l2f                   1701/tcp l2tp
l2f                   1701/udp l2tp

gnunet                2086/tcp
openvpn               1194
socks                 1080
irc                   194
ircs                  994

rsync                 873


dhcpv6-client         546/tcp
dhcpv6-client         546/udp
dhcpv6-server         547/tcp
dhcpv6-server         547/udp


ftp-data              20/tcp
ftp                   21/tcp





echo "#######################################################################################################"
echo "########## Postfix SMTPS Port 465 is currently commented out due to its lack of use ###################"
echo "## ==== If You want to allow the Postfix protocol on port 465, simple just uncomment the hashes ==== ##"
echo "## ================================================================================================= ##"
echo -e "\t\t [+] Accepting INPUT [Postfix SMTPS] {Port 465}..."
echo "## ================================================================================================= ##"
echo "## $IPTABLES -A INPUT -m state --state NEW -m tcp -p tcp --dport 465 -j ACCEPT"								
echo "## $IPTABLES -A INPUT -m state --state NEW -m udp -p udp --dport 465 -j ACCEPT"
echo "#######################################################################################################"




iptables -I FORWARD 1 -p tcp --dport 1433 -m state --state
ESTABLISHED -m string --hex-string "'|00|" --algo bm -m string --hex-string
"-|00|-|00|" --algo bm -j LOG --log-prefix "SQL INJECTION COMMENT "


OUTPUT -o eth0 -m owner --uid-owner 1000 -j ACCEPT
OUTPUT -o eth0 -m owner --uid-owner 0 -j ACCEPT
OUTPUT -o wlan0 -m owner --uid-owner root -j ACCEPT
OUTPUT -o wlan0 -m owner --uid-owner faggot 
OUTPUT -o wlan0 -­m owner --­­gid-­owner net -j ACCEPT
OUTPUT -o wlan0 -­m owner --­­gid-­owner net -j ACCEPT


/sbin/iptables -A OUTPUT -p TCP -m owner --pid-owner $PID -j ACCEPT





* Add new fib expression, which can be used to obtain the output
interface from the route table based on either source or destination
address of a packet. This can be used to e.g. add reverse path
filtering, eg. drop if not coming from the same interface packet
arrived on:


# nft add rule x prerouting fib saddr . iif oif eq 0 drop



# NTP server modification permission to ntpd user only (or root in pre-DNS phase)
iptables -A OUTPUT -o lo -p udp -m owner --uid-owner root -d 127.0.0.1 --dport ntp -j ACCEPT
iptables -A OUTPUT -o lo -p udp -m owner --uid-owner ntp  -d 127.0.0.1 --dport ntp -j ACCEPT
iptables -A OUTPUT -o lo -p udp                           -d 127.0.0.1 --dport ntp -j LOGREJECT

# Hidden service server access only for Tor
iptables -A OUTPUT -o lo -p tcp -m owner --uid-owner tor      --syn -d 127.0.0.1 --dport 9080 -j ACCEPT
iptables -A OUTPUT       -p tcp                               --syn -d 127.0.0.1 --dport 9080 -j LOGREJECT

# Privoxy access only for main user and cables daemon
iptables -A OUTPUT -o lo -p tcp -m owner --uid-owner ${luser} --syn -d 127.0.0.1 --dport 8118 -j ACCEPT
iptables -A OUTPUT -o lo -p tcp -m owner --uid-owner ${cable} --syn -d 127.0.0.1 --dport 8118 -j ACCEPT
iptables -A OUTPUT       -p tcp                               --syn -d 127.0.0.1 --dport 8118 -j LOGREJECT

# Tor access via SOCKS only for main user and Privoxy
iptables -A OUTPUT -o lo -p tcp -m owner --uid-owner tor --syn -d 127.0.0.1 --dport 9050 -j ACCEPT

debian-tor
onioncat
iptables -A OUTPUT -o lo -p tcp -m owner --uid-owner privoxy  --syn -d 127.0.0.1 --dport 9050 -j ACCEPT
iptables -A OUTPUT       -p tcp                               --syn -d 127.0.0.1 --dport 9050 -j LOGREJECT

# Tor control port access only for Tor user
iptables -A OUTPUT -o lo -p tcp -m owner --uid-owner tor      --syn -d 127.0.0.1 --dport 9051 -j ACCEPT
iptables -A OUTPUT       -p tcp                               --syn -d 127.0.0.1 --dport 9051 -j LOGREJECT

i2psvc


#_____ TAHOE LAFS _____
/sbin/iptables -t nat -A PREROUTING -p tcp --dport 3456 -j REDIRECT --to-port 80



echo "## ======================================================================================== ##"
echo -e "\t\t [+] Accepting INPUT IRC client {Port 6667}..."
echo "## ======================================================================================== ##"
$IPTABLES -A INPUT -p tcp --dport 6667 -j ACCEPT			# IRC Port
$IPTABLES -A INPUT -p tcp --destination-port 6667 -j LOG --log-prefix "SSL IRC Attempt"
echo "## ======================================================================================== ##"
echo -e "\t\t [+] Accepting INPUT SSL IRC client {Port 6697}..."
echo "## ======================================================================================== ##"
$IPTABLES -A INPUT -p tcp --dport 6697 -j ACCEPT			# IRC Port
$IPTABLES -A INPUT -p tcp --destination-port 6697 -j LOG --log-prefix "SSL IRC Attempt"
echo "## ======================================================================================== ##"
echo -e "\t\t [+] Transparently Forward All Outbound Traffic To The Squid Daemon"
echo "## ======================================================================================== ##"
$IPTABLES -t nat -A PREROUTING -p tcp --dport 80 -j DNAT --to proxyhost:3128
$IPTABLES -t nat -A PREROUTING -p tcp --dport 443 -j DNAT --to proxyhost:3128


# this line enables transparent http-proxying for the internal network:
           proto tcp if eth0 daddr ! 192.168.0.0/255.255.255.0
               dport http REDIRECT to-ports 3128;



echo "## ======================================================================================== ##"
echo -e "\t\t [+] [qBittorrent] BitTorrent Client Port:(6881)"
echo "## ======================================================================================== ##"




echo "## ======================================================================================== ##"
echo -e "\t [+] [KTorrent] BitTorrent Client TCP Port:(6881) & UDP Port:(4444)"
echo "## ======================================================================================== ##"



echo "## ======================================================================================== ##"
echo -e "\t\t\t [+] [Deluge] BitTorrent Client TCP Port:(6881/6891)"
echo "## ======================================================================================== ##"



echo "## ======================================================================================== ##"
echo -e "\t\t\t [+] [Transmission] BitTorrent Client TCP Port:(51413)"
echo "## ======================================================================================== ##"



echo "## ======================================================================================== ##"
echo -e "\t\t\t [+] [Transmission] Daemon TCP Port:(9091)"
echo "## ======================================================================================== ##"



  ##############################################################################
  # drop SSDP packets                                                          #
  ##############################################################################
  iptables -t filter -A INPUT -d 239.255.255.250 -p udp -m udp --dport 1900 -j LOGNDROP



echo "## ======================================================================================== ##"
echo -e "\t\t\t [+] [MSN Chat] \tTCP Ports:(1863|6891):(6900|6901)"
echo "## ======================================================================================== ##"



echo "## ======================================================================================== ##"
echo -e "\t\t\t [+] [MSN Chat] (SSL) Port:(443/tcp)"
echo "## ======================================================================================== ##"


echo "## ======================================================================================== ##"
echo -e "\t\t\t [+] [AIM Talk] Port:(5190/tcp)"
echo "## ======================================================================================== ##"



echo "## ======================================================================================== ##"
echo -e "\t\t\t [+] [Yahoo Chat] Port:(5050/tcp)"
echo "## ======================================================================================== ##"


echo "## ======================================================================================== ##"
echo -e "\t\t\t [+] [XMPP] (Jabber & Google Talk) \tTCP Ports:(5222|5269)"
echo "## ======================================================================================== ##"






## ======================================================================================== ##
# $IPTABLES -A INPUT -p tcp --dport 51413 -j ACCEPT			# Torrent Port
## ======================================================================================== ##


echo
echo
echo "## ============================================================================== ##"
echo -e "\t[+] Allowing OUTPUT SSH (22) DNS (53), HTTP (80), and HTTPS (443)..."
echo "## ============================================================================== ##"
##
## ======================================================================================== ##
##

echo "## ============================================================================== ##"
echo -e "\t[+] Allowing Outbound SSH/SCP/SFTP Access {Port 22}..."
echo "## ============================================================================== ##"
$IPTABLES -A OUTPUT -p tcp --dport 22 -j ACCEPT					# SSH/SCP/SFTP Port
echo "## ======================================================================================== ##"
echo -e "\t\t [+] Allowing Outbound SMTP clients {Port 25}..."
echo "## ======================================================================================== ##"
$IPTABLES -A OUTPUT -p tcp --dport 25 -j ACCEPT					# STMP Port
echo "## ======================================================================================== ##"
echo -e "\t\t [+] Accepting INPUT TCP DNS {Port 53}..."
echo "## ======================================================================================== ##"
$IPTABLES -A OUTPUT -p tcp --dport 53 -j ACCEPT					# TCP DNS Port
echo "## ======================================================================================== ##"
echo -e "\t\t [+] Accepting INPUT UDP DNS {Port 53}..."
echo "## ======================================================================================== ##"
$IPTABLES -A OUTPUT -p udp --dport 53 -j ACCEPT					# UDP DNS Port
echo "## ======================================================================================== ##"
echo -e "\t\t [+] Accepting INPUT TCP HTTP {Port 80}..."
echo "## ======================================================================================== ##"
$IPTABLES -A OUTPUT -p tcp --dport 80 -j ACCEPT					# HTTP Port
echo "## ======================================================================================== ##"
echo -e "\t\t [+] Accepting INPUT TCP HTTPS {Port 443}..."
echo "## ======================================================================================== ##"
$IPTABLES -A OUTPUT -p tcp --dport 443 -j ACCEPT				# HTTPS Port
echo "## ======================================================================================== ##"
echo -e "\t\t [+] Allowing Outbound IRC {Port 6667} & SIRC {Port 6669}..."
echo "## ======================================================================================== ##"
$IPTABLES -A OUTPUT -p tcp --dport 6667 -j ACCEPT				# IRC Port
$IPTABLES -A OUTPUT -p tcp --dport 6669 -j ACCEPT				# SIRC Port
echo "## ======================================================================================== ##"
echo -e "\t [+] Invoking Log Prefix "SSL IRC Attempt" For All Connections To Port 6669..."
echo "## ======================================================================================== ##"
$IPTABLES -A OUTPUT -p tcp --destination-port 6669 -j LOG --log-prefix "SSL IRC Attempt"
## ======================================================================================== ##
# $IPTABLES -A OUTPUT -p tcp --dport 51413 -j ACCEPT			# Torrent Port
## ======================================================================================== ##
echo
echo

#### TOMCAT
#-A INPUT -m state --state NEW -m tcp -p tcp --dport 8080 -j ACCEPT
#-A INPUT -m state --state NEW -m tcp -p tcp --dport 8443 -j ACCEPT



        # Operation ufw_before  ufw_after   profile_before  profile_after
        #     +         A         A+B             A               A+B   <-- A completed from profile_before | B completed from parameters
        #     -        A+B         A             A+B               A    
        #     x        A+B        A+C            A+B              A+C   <-- A completed from profile_before | C completed from parameters
        # We have here profile_before + ufw_after + parameters > Just complete!

 

# quickly process packets for which we already have a connection
echo "iptables -A ufw-before-input -m state --state RELATED,ESTABLISHED -j ACCEPT" > /etc/ufw/before.rules 
-A ufw-before-output -m state --state RELATED,ESTABLISHED -j ACCEPT
Add these this line: ­A ufw­before­input ­j LOG ­­log­level warn
-A ufw-before-output -m state --state RELATED,ESTABLISHED -j ACCEPT
-A ufw-before-input -j LOG --log-level warn


ufw deny in on eth0 to 224.0.0.1 proto igmp
ufw route allow in on eth1 out on eth2
ufw route allow in on eth0 out on eth1 to 12.34.45.67 port 80 proto tcp

ufw status numbered
ufw app update --add-new 



iptables -t nat -A POSTROUTING -o $INET_IFACE -j SNAT --to-source $INET_IP





Extended Berkeley Packet Filter ( eBPF )




		echo "Applying $IPTABLES firewall rules"


echo "## ============================================================================== ##"
echo -e "\t\t\t[+] Invoking INPUT State Table..."
echo "## ============================================================================== ##"
## 
## ======================================================================================== ##
$IPTABLES -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
$IPTABLES -A INPUT -j DROP
## ======================================================================================== ##
## 
echo
echo "## ============================================================================== ##"
echo -e "\t\t\t[+] Invoking OUTPUT State Table..."
echo "## ============================================================================== ##"
## 
## ======================================================================================== ##
$IPTABLES -A OUTPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
$IPTABLES -A OUTPUT -j DROP
## ======================================================================================== ##
## 
echo
echo
echo "## ============================================================================== ##"
echo -e "\t\t\t\t[+] QubesOS IPTables:"
echo "## ============================================================================== ##"
if [ uname -n = amnesia ]; then
	if [ "$qubes_vm_type" = "NetVM" ] || [ "$qubes_vm_type" = "ProxyVM" ]; then


echo "## ============================================================================== ##"
echo -e "\t\t\t\t [+] QubesOS IPTables:"
echo "## ============================================================================== ##"
if [ uname -n = qubes ]; then
	if [ "$qubes_vm_type" = "NetVM" ] || [ "$qubes_vm_type" = "ProxyVM" ]; then
		echo "## ==================================================================================== ##"
		echo -e "\t\t [+] Allow connections from port 8082 of internal vif interface for tinyproxy"
		echo "## ==================================================================================== ##"
		echo "## ------------------------------------------------------------------------------------ ##"
		echo -e "\t\t [?] Tinyproxy is responsible to handle TemplateVMs updates."
		echo "## ------------------------------------------------------------------------------------ ##"
		$IPTABLES -A INPUT -i "$INT_IF" -p tcp -m tcp --dport 8082 -j ACCEPT
		$IPTABLES -A OUTPUT -o "$INT_IF" -p tcp -m tcp --sport 8082 -j ACCEPT
		echo "## ==================================================================================== ##"
		echo -e "\t\t [?]Qubes pre-routing. Will be able to intercept traffic "
		echo -e "\t\t\t  destined for 10.137.255.254 to be re-routed to tinyproxy."
		echo "## ============================================================================== ##"
		## 
		## ======================================================================================== ##
		$IPTABLES -t nat -N PR-QBS-SERVICES
		$IPTABLES -t nat -A PREROUTING -j PR-QBS-SERVICES
		## ======================================================================================== ##
		## 
		echo "## ============================================================================== ##"
		echo -e "\t\t [+] Redirect Traffic Destined For 10.137.255.154 to port 8082 (tinyproxy)."
		echo "## ============================================================================== ##"
		## 
		## ================================================================================================ ##
		$IPTABLES -t nat -A PR-QBS-SERVICES -d 10.137.255.254/32 -i "$INT_IF" -p tcp -m tcp --dport 8082 -j REDIRECT
		## ================================================================================================ ##
		## 
		echo "## ========================================================================================== ##"
		echo -e "\t\t '\033[01;38m'[+] Forward tinyproxy output to port 5300/9040 on internal (Tor) interface (eth1) "
		echo -e "\t\t To Be Able To connect to Internet (via Tor) to proxy updates for TemplateVM."
		echo "## ========================================================================================== ##"
		## 
		## ======================================================================================== ##
		$IPTABLES -t nat -A OUTPUT -p udp -m owner --uid-owner tinyproxy -m conntrack --ctstate NEW -j DNAT --to "127.0.0.1:${DNS_PORT_GATEWAY}"
		$IPTABLES -t nat -A OUTPUT -p tcp -m owner --uid-owner tinyproxy -m conntrack --ctstate NEW -j DNAT --to "127.0.0.1:${TRANS_PORT_GATEWAY}"
else
		echo "## ============================================================================== ##"
		echo -e "\t\t [!] Current Running Machine Isn't QubesOS, [!] Skipping... [!]"
		echo "## ============================================================================== ##"
	fi
fi

if [ "$qubes_vm_type" = "TemplateVM" ]; then
	echo -e "\t\t[+] Allow access to Qubes update proxy"
	$IPTABLES -A OUTPUT -o "$EXT_IF" -p tcp -m tcp --dport 8082 -j ACCEPT
fi
## 
## ======================================================================================== ##
#
#
# if $TahoeLAFSActive ; then
# 	$IPTABLES -A INPUT -p tcp --dport $TAHOE_PORT -j ACCEPT
# fi
#




echo "## ======================================================================================= ##"
echo -e "\t\t\t[+] Enabling an Oz profile..."
echo "## ======================================================================================= ##"



echo "## ======================================================================================= ##"
echo -e "\t\t [?] Oz profiles can be found in the following directory:"
echo "## ======================================================================================= ##"
##
## ======================================== ##
OzProfiles="/var/lib/oz/cells.d/"
OzProfilesDir="/var/lib/oz/cells.d/"
## ======================================== ##
## 
echo "## "
echo "## =========================== ##"
echo $OzProfiles
echo $OzProfilesDir
echo "## =========================== ##"
echo "## "




networkctl list

echo "## ============================================================================== ##"
iwconfig eth0 nickname "Rape-Tyme!"
iwconfig wlan0 nickname "moar bass than space"
echo "## ============================================================================== ##"
echo -e "\t\t\t [+] Setting The Tansmitting Power In dBm:"
echo "## ============================================================================== ##"
## 
## ======================================================================================== ##

unset WIRELESS_REGDOM


touch /etc/conf.d/wireless-regdom


[ -n "${WIRELESS_REGDOM}" ] && iw reg set ${WIRELESS_REGDOM}


iw reg set US
iwconfig wlan1 txpower 25
iwconfig wlan0 txpower 20
echo "## ===================================================================== ##"
echo -e "\t [!] WARNING Anonymity Holes in 802.11 drivers and default, hidden,"
echo -e "\t\t [+] Disabling the Network ID checking (NWID promiscuous) with off..."
echo -e "\t\t Auto De-Anon Structured Packets..."
echo "## ===================================================================== ##"
echo -e "\t\t\t [?] Hacking To correct this issue..."
echo "## ===================================================================== ##"d
iwconfig eth0 nwid off
## ======================================================================================== ##

echo
echo "## ============================================================================== ##"
echo -e "\t\t\t [+] Spoofing Wlan1 Interface"
echo "## ============================================================================== ##"
## 
## ======================================================================================== ##
ifconfig wlan1 hw ether 00:30:65:35:2e:37
ip link set dev wlan1 address 00:30:65:35:2e:37
## ======================================================================================== ##
## 
echo
echo "## ============================================================================== ##"
echo -e "\t\t\t [+] Spoofing Wlan1 Interface"
echo "## ============================================================================== ##"
## 
## ======================================================================================== ##
if [ -d /sys/class/net/wlan1/ ]; then
	ifconfig wlan1 hw ether 00:30:65:35:2e:37
	ip link set dev wlan1 address 00:30:65:35:2e:37
else
	echo -e "\t [!] Wlan1 Doesnt Exist..."
fi
## ======================================================================================== ##
## 
echo "## ============================================================================== ##"
echo -e "\t\t\t [+] Spoofing Wlan1 Interface"
echo "## ============================================================================== ##"
## 
## ======================================================================================== ##
if [ -d /sys/class/net/wlan1/ ]; then
	ifconfig wlan1 hw ether 00:30:65:35:2e:37
	ip link set dev wlan1 address 00:30:65:35:2e:37
else
	echo -e "\t\t Wlan1 Doesnt Exist..."
fi
## ======================================================================================== ##
## 
echo



/usr/sbin/apf --start 

aa-status --verbose






    UFW_PATH    = '/usr/sbin/ufw'
    UFW_DEFAULT = '/etc/default/ufw'
    UFW_CONF    = '/etc/ufw/ufw.conf'
    UFW_SYSCTL  = '/etc/ufw/sysctl.conf'
    GUFW_PATH   = '/etc/gufw'
    GUFW_CFG    = '/etc/gufw/gufw.cfg'
    GUFW_LOG    = '/var/log/gufw.log'




Start and enable UFW's systemd unit:



sudo systemctl start ufw
sudo systemctl enable ufw

sudo ufw enable
sudo ufw logging on

ufw default allow outgoing
ufw default deny incoming


iptables -m set --match-set a src,dst -j SET --add-set b src,dst



# quickly process packets for which we already have a connection
-A ufw-before-input -m state --state RELATED,ESTABLISHED -j ACCEPT
-A ufw-before-output -m state --state RELATED,ESTABLISHED -j ACCEPT

-A ufw-before-output -m state --state RELATED,ESTABLISHED -j ACCEPT
-A ufw-before-input -j LOG --log-level warn


iptables -A FORWARD -i eth0 -o eth1 -j LOG 		## Add a rule to log all packets entering 
												## the system via eth0 and exiting via eth1


for SERVICE in
       acpid                      \

       
                   \
;
do
      if [ -e /etc/init.d/$SERVICE ]; then
            # Doing business this way causes less needless errors that a
            # reviewer of the hardening process doesnt need to deal with.
            /sbin/service $SERVICE stop
            /sbin/chkconfig --level 12345 $SERVICE off
      else
            echo "SERVICE doesn't exist on this system ($SERVICE)."
      fi
done








systemctl disable bluetooth.service
echo "####################################################"

systemctl stop httpd
# systemctl disable httpd
chkconfig --del httpd

# Killing apache2
# service apache2 stop
# /sbin/init.d/apache stop
# /etc/init.d/apache2 stop
# /etc/init.d/apache2 disable
# update-rc.d apache2 stop
# update-rc.d apache2 disable
# update-rc.d apache2 remove
echo "####################################################"
# Killing postgresql
# service postgresql stop
# /etc/init.d/postgresql stop
# /etc/init.d/postgresql disable
# service postgresql disable
# update-rc.d postgresql stop
# update-rc.d postgresql disable
# update-rc.d postgresql remove
echo "####################################################"
# Killing Mysql
# service mysql stop
# /etc/init.d/mysql stop
# service mysql disable
# /etc/init.d/mysql disable
# update-rc.d mysql disable
# update-rc.d mysql stop
# update-rc.d mysql remove
echo "####################################################"

echo "####################################"
          echo "Killing bluetooth"
echo "####################################"
service bluetooth stop
service bluetooth disable

/etc/init.d/bluetooth stop
/etc/init.d/bluetooth disable

update-rc.d bluetooth stop
update-rc.d bluetooth disable
update-rc.d bluetooth remove

systemctl stop bluetooth.service
systemctl disable bluetooth.service
systemctl mask bluetooth.service

systemctl stop bluetooth.target
systemctl disable bluetooth.target
systemctl mask bluetooth.target


echo "## ============================================================================== ##"
echo -e "\t\tStarting Metworking Services Again"
echo "## ============================================================================== ##"
service networking start
service NetworkManager start
## ======================================================================================== ##
## 
echo
echo
echo "## ============================================================================== ##"
echo -e "\t\t\t  Restoring Networking Interfaces..."
echo "## ============================================================================== ##"
## 
## ======================================================================================== ##
echo " Starting lo... "
ifconfig $LOOPBACK up
echo " Starting eth0... "
ifconfig $ETHER up
echo "Starting Wlan0... "
ifconfig $IFACE up
## ======================================================================================== ##
## 

networkctl show

networkctl status

WIRELESS_REGDOM="$(iw reg get)"

echo
echo "## ============================================================================== ##" | tee >> $TEMP_DIR/iw.txt
echo -e "\t\t\tAquiring List of Access Points in range..." | tee >> $TEMP_DIR/iw.txt
echo "## ============================================================================== ##" | tee >> $TEMP_DIR/iw.txt
iwlist wlan0 accesspoint | tee >> $TEMP_DIR/iw.txt
echo "## ============================================================================== ##" | tee >> $TEMP_DIR/iw.txt
echo -e "\t\tProcessing Wireless event capability information..." | tee >> $TEMP_DIR/iw.txt
echo "## ============================================================================== ##" | tee >> $TEMP_DIR/iw.txt
iwlist wlan0 event >> $TEMP_DIR/iw.txt
echo "## ============================================================================== ##" | tee >> $TEMP_DIR/iw.txt
echo -e "\t\tListing the various Power Management attributes and modes of the device..." | tee >> $TEMP_DIR/iw.txt
echo "## ============================================================================== ##" | tee >> $TEMP_DIR/iw.txt
iwlist wlan0 power | tee >> $TEMP_DIR/iw.txt
echo "## ============================================================================== ##" | tee >> $TEMP_DIR/iw.txt
echo -e "\t\tProcessing List the various Transmit Powers available on the device:" | tee >> $TEMP_DIR/iw.txt
echo "## ============================================================================== ##" | tee >> $TEMP_DIR/iw.txt
iwlist wlan0 txpower | tee >> $TEMP_DIR/iw.txt
echo "## ============================================================================== ##" | tee >> $TEMP_DIR/iw.txt
echo -e "\t\tQuerying List the modules supported by device & currently enabled..." | tee >> $TEMP_DIR/iw.txt
echo "## ============================================================================== ##" | tee >> $TEMP_DIR/iw.txt
iwlist wlan0 modu | tee >> $TEMP_DIR/iw.txt
echo "## ============================================================================== ##" | tee >> $TEMP_DIR/iw.txt
echo -e "\t\tList the transmit retry limits and retry lifetime on the device:" | tee >> $TEMP_DIR/iw.txt
echo "## ============================================================================== ##" | tee >> $TEMP_DIR/iw.txt
iwlist wlan0 retry | tee >> $TEMP_DIR/iw.txt
echo "## ============================================================================== ##" | tee >> $TEMP_DIR/iw.txt
echo -e "\t\tList the Generic Information Elements set in the device (used for WPA support):" | tee >> $TEMP_DIR/iw.txt
echo "## ============================================================================== ##" | tee >> $TEMP_DIR/iw.txt
iwlist wlan0 genie | tee >> $TEMP_DIR/iw.txt
echo "## ============================================================================== ##" | tee >> $TEMP_DIR/iw.txt
echo -e "\t\tProcessing List the bit-rates supported by the device..." | tee >> $TEMP_DIR/iw.txt
echo "## ============================================================================== ##" | tee >> $TEMP_DIR/iw.txt

echo "## ============================================================================== ##" | tee >> $TEMP_DIR/iw.txt
echo -e "\t\tProcessing List of Capabilities Made Available By The Hardware..." | tee >> $TEMP_DIR/iw.txt
echo "## ============================================================================== ##" | tee >> $TEMP_DIR/iw.txt
iw dev info | tee >> $TEMP_DIR/iw.txt

echo "## ============================================================================== ##" | tee >> $TEMP_DIR/iw.txt
echo -e "\t\tObtaining List of Capabilities Made Available By The Hardware..." | tee >> $TEMP_DIR/iw.txt
echo "## ============================================================================== ##" | tee >> $TEMP_DIR/iw.txt



list  of available frequencies in the device and the number of defined channels.
iwlist wlan0 frequency

iwlist wlan0 event

echo "## ============================================================================== ##" | tee >> $TEMP_DIR/iw.txt
echo -e "\t\tObtaining Current Wireless regulatory domain <ISO/IEC 3166-1 alpha2>" | tee >> $TEMP_DIR/iw.txt
echo "## ============================================================================== ##" | tee >> $TEMP_DIR/iw.txt
iw reg get

if [ $WIRELESS_REGDOM -et iw reg set ${WIRELESS_REGDOM}
iw reg set US


iw list >> $TEMP_DIR/iw.txt

iw wlan0 info
iw wlan0 set name Fagginator

ip link show wlan0 >> $TEMP_DIR/iplink.txt




tc-connmark
tc-xt



xt_pknock
tc-route
flowtop
ulogd
xtables-multi

apf
fwcheck_psad
ebtables-compat
iptables-compat
iptables-extensions
xtables-addons
xtables-compat
xtables-compat-multi
xtables-multi
iptaccount



http://inai.de/documents/Netfilter_Modules.pdf








## echo "## ============================================================================== ##"
## iw wlan0 scan dump -u				## Dump the current scan results
## echo "## ============================================================================== ##"
## iw wlan0 survey dump					## List all gathered channel survey data
## echo "## ============================================================================== ##"
## iw wlan0 station dump				## List all stations known, AP on interfaces
## echo "## ============================================================================== ##"
## iw wlan0 station get <MAC address>	## Get information for a specific station.
## echo "## ============================================================================== ##"
## iw wlan0 event						## Monitor events from the kernel
## echo "## ============================================================================== ##"




echo
echo "####################################################"
echo "Disable The Network ID Checking (NWID promiscuous)"
echo "####################################################"
iwconfig wlan0 nwid off
echo "## ============================================================================== ##"
echo -e "\t\tShowing Classes As ASCII Graph With Stats Info Under Each Class..."
echo "## ============================================================================== ##"
tc -g -s class show dev wlan0

iptables-compat
ip6tables-compat
arptables-compat

ebtables-compat


nft list ruleset



nf_tables





accept all packets going out on loopback interface:
nft insert rule filter output oif lo accept


accept all incoming packets of an established connection:nft ins
nft insert rule filter input ct state established accept


create some chains
nft ­f files/nftables/ipv6­filter


accept dynamic IPv6 configuration and neighbor discovery, one can use:
nft add rule ip6 filter input icmpv6 type nd­neighbor­solicit accept
nft add rule ip6 filter input icmpv6 type nd­router­advert accept


## 
## ======================================================================================== ##
# mkdir -p /var/log/journal
# systemd-tmpfiles --create --prefix /var/log/journal
# chgrp systemd-journal /var/log/journal
# chmod 2775 /var/log/journal
# systemctl restart systemd-journald.service
# setfacl -Rnm g:wheel:rx,d:g:wheel:rx,g:adm:rx,d:g:adm:rx /var/log/journal/
# journalctl --rotate
# journalctl --sync
## ======================================================================================== ##
## 
## 
## ======================================================================================== ##
if [ -e /etc/lilo.conf ]; then
	chown root:root /etc/lilo.conf
	chmod 0600 /etc/lilo.conf
else
	echo -e "\t\t'${BLOODRED}'[!]'${RESET}'No Lilo.conf File To Be Found..."
fi
## ======================================================================================== ##
if [ -e /etc/grub.conf ]; then
	chown root:root /etc/grub.conf
	chmod 0600 /etc/grub.conf
else
	echo -e "\t\t'${BLOODRED}'[!]'${RESET}'No /etc/grub.conf File To Be Found..."
fi
## ======================================================================================== ##



ls -l /bin/ping
cp /bin/ping /tmp ;ls -l /tmp/ping



setcap cap_net_raw=p /tmp/ping
getcap /tmp/ping



echo "## ============================================================================== ##"
echo -e "\t\t\t[+] Set umask"
echo "## ============================================================================== ##"
# umask ${OPTION_UMASK}
# 	if [ $? -eq 0 ]; then
#         echo "[V] Setting umask to ${OPTION_UMASK}"
#     else
#         echo "[X] Could not set umask"
#         ExitFatal
# 	fi
echo "## ============================================================================== ##"
echo -e "\t\t\t[+] turn off core dumps:"
echo "## ============================================================================== ##"
ulimit -c 0
echo "## ============================================================================== ##"
echo -e "\t\t\t[+] show all of your user limit settings:"
echo "## ============================================================================== ##"
ulimit -a
## ======================================================================================== ##
## 
	echo "Usage: /etc/init.d/networking {start|stop|reload|restart|force-reload}"

echo "## ============================================================================== ##"
echo -e "\t[+] Is There A Directory For IPTable Rules? If Not, Make One..."
echo "## ============================================================================== ##"
if [ -d /etc/iptables ];then
	echo -e "\t\t\tDirectory /etc/iptables/ Exists!"
else
	mkdir --verbose --mode=0644 /etc/iptables
fi




# chkconfig --list iptables | grep :on

echo "########################################################################################"
echo "## ============================================================================== ##"
echo -e "\t[+] Create Local Honeypot On Telnet Port 22 By Broadcasting /dev/urandom"
echo "## ============================================================================== ##"
echo "\t + ------------------------------------------------------------------------------ + "
echo -e "\t\t Added for the creativity, commented out"
echo "\t + ------------------------------------------------------------------------------ + "
echo "## (cat /dev/urandom | nc -nl 22) &"
echo "\t + ------------------------------------------------------------------------------ + "
echo "########################################################################################"
echo
echo
echo
echo "## ============================================================================== ##"
echo -e "\t\t\t [+] Concatenate Newly Established IPTable Filter Rules ..."
echo "## ============================================================================== ##"
iptables -v -L -x -n; echo; echo
echo "## ============================================================================== ##"
echo -e "\t\t\t [+] Concatenate Newly Established IPTable NAT Rules ..."
echo "## ============================================================================== ##"
iptables -t nat -v -L -x -n
echo "## ============================================================================== ##"
echo -e "\t\t\t [+] Concatenate Newly Established IPTable Mangle Rules ..."
echo "## ============================================================================== ##"
iptables -t mangle -v -L -x -n





	      	/sbin/route add -$type $dest $netmask $mask $gw $gateway
	   done
	fi    

chkconfig resolvconf on
chkconfig networking on
chkconfig network-manager on
chkconfig syslog-ng on


service networking start
service NetworkManager start








if [ $EXITVALUE != 0 ]; then
/usr/bin/logger -t logrotate "ALERT exited abnormally with [$EXITVALUE]"

### default OUTPUT LOG rule
$IPTABLES -A OUTPUT -o ! lo -j LOG --log-prefix "DROP " --log-ip-options --log-tcp-options

echo "## ============================================================================== ##"
echo -e "\t[+] Saving IPTable Rules, And Redirecting To /etc/iptables/iptables.rules"
echo "## ============================================================================== ##"
$IPTABLESSAVE > /etc/iptables/iptables.rules

iptables-save > /root/ipt.save
cat /root/ipt.save | iptables-restore

	post-up /sbin/iptables-restore /etc/iptables.save

systemctl start paxctld
systemctl status paxctld

touch /etc/sysctl.d/05‐grsecurity.conf
pluma /etc/sysctl.d/05‐grsecurity.conf
sysctl --load=/etc/sysctl.d/05‐grsecurity.conf


pluma /etc/sysctl.d/05‐grsecurity.conf

sysctl -a | grep grsec
sysctl --load=/etc/sysctl.d/05‐grsecurity.conf



echo "Are you installing on (K)DE, (X)fce, or (O)ther?"
echo ""
read a
if [[ $a == [Xx] ]]; then

read -sn 1 -p "Press any key to continue"


#############################
##### Logging subsystem #####
#############################




echo "ipt_LOG" >/proc/sys/net/netfilter/nf_log/2




if [ $EXITVALUE != 0 ]; then
/usr/bin/logger -t logrotate "ALERT exited abnormally with [$EXITVALUE]"





##############################################################################################################

#
# Main
#
main() {
clear
cat /etc/motd

if [ ! -d /$user/data ]; then
     mkdir -p /$user/data
fi

echo -e "\e[1;34mRECON\e[0m"
echo "1.  Domain"
echo "2.  Person"
echo "3.  Parse salesforce"
echo
echo -e "\e[1;34mSCANNING\e[0m"
echo "4.  Generate target list"
echo "5.  CIDR"
echo "6.  List"
echo "7.  IP, Range or URL"
echo
echo -e "\e[1;34mWEB\e[0m"
echo "8.  Open multiple tabs in Iceweasel"
echo "9.  Nikto"
echo "10. SSL"
echo
echo -e "\e[1;34mMISC\e[0m"
echo "11. Crack WiFi"
echo "12. Parse XML"
echo "13. Start a Metasploit listener"
echo "14. Update"
echo "15. Exit"
echo
echo -n "Choice: "
read choice

case $choice in
     1) f_domain;;
     2) f_person;;
     3) f_salesforce;;
     4) f_generateTargetList;;
     5) f_cidr;;
     6) f_list;;
     7) f_single;;
     8) f_multitabs;;
     9) f_nikto;;
     10) f_ssl;;
     11) f_runlocally && /opt/discover/crack-wifi.sh;;
     12) f_parse;;
     13) f_listener;;
     14) /opt/discover/update.sh && exit;;
     15) clear && exit;;
     97) f_parse_recon_ng;;
     98) f_recon-ng;;
     99) f_updates;;
     *) f_error;;
esac
}
while true; do f_main; done
