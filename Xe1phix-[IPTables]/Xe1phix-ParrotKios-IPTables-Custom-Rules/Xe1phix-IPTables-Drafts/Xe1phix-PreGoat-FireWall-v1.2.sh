#!/bin/sh
################################################################
# FaggotWall.sh
# 
################################################################
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
FORGRAY="\033[0;40m"	# Grayish/white forground
FORRED="\033[0;41m"		# Red Forground
FORYELLOW="\033[0;42m"	# Yellow Forground, Green Txt
FORORANGE="\033[0;43m"	# Orange Forground
BOLD="\033[01;01m"     # Highlight
RESET="\033[00m"       # Normal
## ==================================================================================== ##
##

echo "## ============================================================================== ##"

if [ $(id -u) -ne 0 ]; then
	printf "Must be run as root."
	exit 1
fi

echo "## ============================================================================== ##"

if [ $(uname) != "Linux" ]; then
	printf "Sorry, this only works for Linux."
	exit 1
fi


echo "## ============================================================================== ##"





if [ uname -m = x86_64 ]: then
	

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

ARCHLIST=

    if [[ "$OS_ARCH" == *"arm"* ]]; then
	CPU_ARCH="linux-armv5"
    elif [[ "$OS_ARCH" == *"ppc"* ]]; then
	CPU_ARCH="linux-ppc"
    elif [[ "$OS_ARCH" == *"x86_64"* ]]; then
	CPU_ARCH="linux64"
    else
	CPU_ARCH="linux"
    fi

setarch --list
uname26
linux32
linux64
i386
i486
i586
i686
athlon
x86_64










# if [[ "$(uname -m)" == "x86_64" ]]; then
if [[ "$(/bin/uname --machine |cut -d '.' -f-3)" == "x86_64" ]]; then
	printf "64 bit system"
else
	printf "32 bit system"

echo "## ============================================================================== ##"


echo "Is This A Live Persistence?"

persist=(awk '/\/(lib\/live\/mount|live)\/persistence/ { print $2 }' /proc/mounts)

if [[ "$persist" == /lib/live/mount/* ]]; then
	live_persistence="yes"


echo "## ============================================================================== ##"


echo "Welcome To Faggot Linux"  | /usr/games/cowsay -f sodomized-sheep > /etc/issue.net

declare
variables

complete
compgen
command
continue [n]
compopt
getopts
trap
return [n]
shopt
eval
exec


exit [n]                     type [-afptP] name [name >
 export [-fn] [name[=value]>
read [-ers] [-a array]

shift [n]


for (( i = 0; i < ${1:10}; i++ )); do\n\t${0:#statements}\ndone
function …	function ${1:name}(${2:parameter}) {\n\t${3:#statements}\n}
if … fi	if ${2:[[ ${1:condition} ]]}; then\n\t${0:#statements}\nfi

until	until … done	until ${2:[[ ${1:condition} ]]}; do\n\t${0:#statements}\ndone

while	while … done	while ${2:[[ ${1:condition} ]]}; do\n\t${0:#statements}\ndone

case ${1:word} in\n\t${2:pattern} )\n\t\t$0;;\nesac

elif …	elif ${2:[[ ${1:condition} ]]}; then\n\t${0:#statements}

shopt -u restricted_shell
############################################################################################
echo "## ============================================================================== ##"
############################################################################################



IFCONFIG=/sbin/ifconfig
IPTABLES=/sbin/iptables
IP6TABLES=/sbin/ip6tables
MODPROBE=/sbin/modprobe
SYSCTL=/sbin/sysctl 
IPTABLESSAVE="/sbin/iptables-save"
IPTABLESRESTORE="/sbin/iptables-restore"

KernelVersion='dpkg -l | grep linux-image | grep -v meta | sort -t '.' -k 2 -g | tail -n 1 | grep "$(uname -r)" | cut -c5-34'


############################################################################################
echo "## ============================================================================== ##"
############################################################################################
## Link types:
## --> 		vlan - 802.1q tagged virtual LAN interface
## --> 		veth - Virtual ethernet interface
## --> 		vcan - Virtual Local CAN interface
## --> 		dummy - Dummy network interface
## --> 		ifb - Intermediate Functional Block device
## --> 		macvlan - virtual interface base on link layer address (MAC)
## --> 		can - Controller Area Network interface
## --> 		bridge - Ethernet Bridge device



CLASS_A="10.0.0.0/8"                # Class A private networks
CLASS_B="172.16.0.0/12"             # Class B private networks
CLASS_C="192.168.0.0/16"            # Class C private networks
CLASS_D_MULTICAST="224.0.0.0/4"         # Class D multicast addr
CLASS_E_RESERVED_NET="240.0.0.0/5"      # Class E reserved addr
BROADCAST_SRC="0.0.0.0"             # Broadcast source addr
BROADCAST_DEST="255.255.255.255"        # Broadcast destination addr




IPADDR=$(ifconfig wlan0 | grep netmask | cut -c14-26)
NETMASK=$(ifconfig wlan0 | grep netmask | cut -c27-48)
BROADCAT=$(ifconfig wlan0 | grep netmask | cut -c51-73)

MACADDR=$(ifconfig -a | grep ether | cut -c15-31)
TxPower=$(iwconfig wlan0 | grep Tx-Power | cut -c65-70)
IWSyntax=$(iw --help | cut -c2-199 | grep "dev <devname>")
SIZE=$[ $(cat /sys/$DEVPATH/size) * 512 ]


cat /sys/dev/block/*/*/uevent | grep DEVNAME | cut -c9-199

if fgrep -q $DEVNAME /proc/mounts; then
    xs_remove
    exit 0
fi
# ... and used by device-mapper
if [ -n "`ls -A /sys/$DEVPATH/holders 2> /dev/null`" ]; then
    xs_remove
    exit 0
fi
# ... and used device-mapper devices
if [ -n "$DM_NAME" ] && /sbin/dmsetup info "$DM_NAME" | grep -q "^Open count:.*[1-9]"; then
    xs_remove
    exit 0
fi





stop_and_disable_NM() {
   for s in NetworkManager-dispatcher.service \
            NetworkManager-wait-online.service \
            NetworkManager.service; do
       systemctl stop "${s}"
       systemctl disable "${s}"
       systemctl mask "${s}"
   done
   log "Networking disabled"
}





get_mac ()
{
	mac=""

	for adaptor in /sys/class/net/*
	do
		status="$(cat ${adaptor}/iflink)"

		if [ "${status}" -eq 2 ]
		then
			mac="$(cat ${adaptor}/address)"
			mac="$(echo ${mac} | sed 's/:/-/g' | tr '[a-z]' '[A-Z]')"
		fi
	done

	echo ${mac}
}

is_luks_partition ()
{
	device="${1}"
	/sbin/cryptsetup isLuks "${device}" 1>/dev/null 2>&1
}

is_active_luks_mapping ()
{
	device="${1}"
	/sbin/cryptsetup status "${device}" 1>/dev/null 2>&1
}

get_luks_backing_device ()
{
	device=${1}
	cryptsetup status ${device} 2> /dev/null | \
		awk '{if ($1 == "device:") print $2}'
}




wpa_background (8)   - Background information on Wi-Fi Protected Access and IEEE 802.11i
x86_64-linux-gnu-objdump (1) - display information from object files.
x86_64-linux-gnu-readelf (1) - Displays information about ELF files.

xdpyinfo
xfs_info


wlancfg query dev
wlancfg show dev [all]
wlancfg set dev
wlancfg list





			# if configuration of device worked we should have an assigned
			# IP address, if so let's use the device as $DEVICE for later usage.
			# simple and primitive approach which seems to work fine
			if ifconfig $dev | grep -q 'inet.*addr:'
			then
				export DEVICE="$dev"
				break
			fi
		done
	else
		for interface in ${DEVICE}; do

		for device in /sys/class/net/*
		do
			if [ -f "$device/address" ]
			then
			current_mac=$(cat "$device/address")

		if [ -n "${interface}" ]
		then
			HWADDR="$(cat /sys/class/net/*/address)"
		fi









	for i in $interfaces; do



if [ ! -x /sbin/brctl ]
then
  exit 0
fi


# Previous work (create the interface)
if [ "$MODE" = "start" ] && [ ! -d /sys/class/net/$IFACE ]; then
  brctl addbr $IFACE || exit 1
  if [ "$IF_BRIDGE_HW" ]; then
    ip link set dev $IFACE address $IF_BRIDGE_HW
  fi


if [ "$MODE" = "stop" ];  then
  ip link set dev $IFACE down || exit 1
fi

    if [ "$MODE" = "start" ] && [ ! -d /sys/class/net/$IFACE/brif/$port ]; then
      if [ -x /etc/network/if-pre-up.d/vlan ]; then
        env IFACE=$port /etc/network/if-pre-up.d/vlan
      fi

if [ "$MODE" = "stop" ] && [ -d /sys/class/net/$IFACE/brif/$port ];  then
      ip link set dev $port down && brctl delif $IFACE $port && \
        if [ -x /etc/network/if-post-down.d/vlan ]; then
          env IFACE=$port /etc/network/if-post-down.d/vlan
        fi


# We finish setting up the bridge
if [ "$MODE" = "start" ] ; then
fi


  # We activate the bridge
  ip link set dev $IFACE up

# Finally we destroy the interface
elif [ "$MODE" = "stop" ];  then

  brctl delbr $IFACE



      if [ -f /proc/sys/net/ipv6/conf/$port/disable_ipv6 ]
      then
        echo 1 > /proc/sys/net/ipv6/conf/$port/disable_ipv6



if [ "$IPADDR" = "192.168.0.*" ]
then
	echo "Currently Enrolled In A Class C Network"
	

if [ "$IPADDR" != "172.16.0.*" ]
			then
	echo "Currently Enrolled In A Class B Network"

if [ "$IPADDR" != "10.0.0.*" ]
			then
	echo "Currently Enrolled In A Class A Network"


############################################################################################
echo "## ============================================================================== ##"
############################################################################################
/var/log/sysstat/saDD
/var/log/sysstat/saYYYYMMDD
############################################################################################
echo "## ============================================================================== ##"
############################################################################################

############################################################################################
echo "## ============================================================================== ##"
############################################################################################
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

############################################################################################
echo "## ============================================================================== ##"
############################################################################################

############################################################################################
echo "## ============================================================================== ##"
############################################################################################



=`mktemp ${MC_TMPDIR:-/tmp}/mail.XXXXXX` || exit 1
tempfile=$(mktemp "${file}.XXXXXXX")

TEMP_DIR=`mktemp --tmpdir -d HCL.XXXXXXXXXX`
cat /etc/os-release > $TEMP_DIR/os-release
cat /proc/cpuinfo > $TEMP_DIR/cpuinfo
lspci -nnvk > $TEMP_DIR/lspci
cat /proc/scsi/scsi > $TEMP_DIR/scsi
sudo dmidecode > $TEMP_DIR/dmidecode
info > $TEMP_DIR/xl-info
dmesg > $TEMP_DIR/dmesg


############################################################################################
echo "## ============================================================================== ##"
############################################################################################
## 
## ==================================================================================== ##
echo "## ================================================================= ##"
echo -e '\t\t'${PURPLUE}'[+]'${RESET}'Contructing Service Port Environment Variables...'
echo "## ================================================================= ##"
## ==================================================================================== ##
## 
## ==================================================================================== ##
SOCKS4a="127.0.0.1:1080"
export SOCKS4a="127.0.0.1:1080"
SOCKS5="127.0.0.1:9050"
export SOCKS5="127.0.0.1:9050"
I2PHTTP="http://127.0.0.1:4444"
export I2PHTTP="http://127.0.0.1:4444"
I2PHTTPS="https://127.0.0.1:4445"
export I2PHTTPS="https://127.0.0.1:4445"
OpenVasAdministrator="http://127.0.0.1:9393"        # openvasad -a 127.0.0.1 -p 9393
export OpenVasAdministrator="http://127.0.0.1:9393"
Nessus="https://127.0.0.1:8834"
export Nessus="https://127.0.0.1:8834"
Nexpose="https://127.0.0.1:3780"
export Nexpose="https://127.0.0.1:3780"
MSF="https://127.0.0.1:3790"                            # Metasploit UI
export MSF="https://127.0.0.1:3790"
BeEF="http://127.0.0.1:3000/ui/panel"
export BeEF="http://127.0.0.1:3000/ui/panel"
GSAD="http://127.0.0.1:9392"                            # gsad --http-only --listen=127.0.0.1 -p 9392
export GSAD="http://127.0.0.1:9392"
OpenVasManager="http://127.0.0.1:9390"                  # openvasmd -p 9390 -a 127.0.0.1
export OpenVasManager="http://127.0.0.1:9390"
I2PWebserver="http://127.0.0.1:7658"
export I2PWebserver="http://127.0.0.1:7658"
## ==================================================================================== ##
echo
echo
############################################################################################
echo "## ============================================================================== ##"
############################################################################################
echo
echo "## ============================================================================== ##"
bash --version | head -n1 | cut -d" " -f2-4
echo "/bin/sh -> `readlink -f /bin/sh`"
echo -n "Binutils: "; ld --version | head -n1 | cut -d" " -f3-
echo "## ============================================================================== ##"
/dev/mapper/control
/dev/mapper/parrot--vg-root
/dev/mapper/parrot--vg-swap_1
/dev/mapper/sda5_crypt

DEVPATH=$(cat -A /sys/block/*/uevent | grep DEVNAME)
/usr/share/vboot/devkeys-acc/key.versions
/usr/share/vboot/devkeys-pkc/key.versions
/usr/share/vboot/devkeys/key.versions

systemctl show-environment
systemctl show >> systemctl.show.txt && cat systemctl.show.txt


udevadm info /dev/sda | grep ID_SERIAL

export LANG=en_US.UTF-8
export LC_ALL=en_US.UTF-8
export TZ=:/usr/share/zoneinfo/US/Mountain
Sources=/etc/apt/sources.list
#############################################################################################
echo "## ============================================================================== ##"
echo -e "\t [+] Establish Hardware Interface Environment Variables:"
echo "## ================================================================= ##"
#############################################################################################

/usr/sbin/fwsnort
/usr/sbin/snort
/usr/sbin/snort-stat

/etc/fwsnort/fwsnort.conf
/etc/psad/psad.conf
/etc/oinkmaster.conf
/etc/sagan-rules/
/etc/sagan.conf
/etc/snort/rules/
/etc/snort/snort.conf
/etc/squid/squid.conf

SSHD_CONFIG='/etc/ssh/sshd_config'
SSHAGENTID='eval $(ssh-agent)'



INTERFACES=`cat "/proc/net/dev" | egrep "(eth|bond|wlan|br|ath|bge|mon|fe)[0-9]+" | awk '{print $1}' | cut -d\: -f1 |sort`


NUM_INTERFACES=`echo $INTERFACES | wc -w`
Sysctl=/sbin/sysctl
Home=/home/poozer
Service=/usr/sbin/service

# Loopback Interface
LOOPBACK=lo
ETHER=eth0
Eth0Mac=$(cat < /sys/class/net/eth0/address)
IFACE=wlan0
Wlan0Mac=$(cat < /sys/class/net/wlan0/address)
IpWlan0Mac=$(ip -o link show dev wlan0 | cut -c116-132)
WlanPhy80211Addr=$(cat </sys/class/net/wlan0/phy80211/address)
ALPHA=wlan1
Wlan0Mac=$(cat < /sys/class/net/wlan1/address)
ALPHA2=wlan2
EthOperState=$(cat /sys/class/net/eth0/device/net/eth0/operstate)
WlanOperState=$(cat /sys/class/net/wlan0/device/net/wlan0/operstate)
Wlan1OperState=$(cat /sys/class/net/wlan1/device/net/wlan1/operstate)
Wlan0Dir=/sys/class/net/wlan0
Wlan1Dir=/sys/class/net/wlan1
Wlan2Dir=/sys/class/net/wlan2

echo "## ============================================================================== ##"
echo -e "\t\t[+] Killing Networking Interfaces"
echo "## ============================================================================== ##"
echo
echo
# echo "## =========================================== ##"
# echo -e "\t[+] Killing Loopback... "
# echo "## =========================================== ##"
# $IFCONFIG $LOOPBACK down
echo "## =========================================== ##"
echo -e "\t[+] Killing eth0... "
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
## ======================================================================================== ##
## 
echo
echo "## ########################################################################################################## ##"
echo "## ========================================================================================================== ##"
echo "## ########################################################################################################## ##"
echo
echo
if [ -d /sys/class/net/wlan0 ]; then
	echo -e "\t\t [+] Wlan0 Exists!"
else
	echo "## ================================================================= ##"
	echo -e "\t\t [+] Wlan0 Currently Does Not Exist..."
	echo "## ================================================================= ##"
fi
/run/network/ifstate
echo "## ================================================================= ##"
echo -e "\t\t [+] Is Wlan0 Up?..."
echo "## ================================================================= ##"
if [ "$(cat /sys/class/net/wlan0/operstate)" = up ]; then 
	echo "## =========================================== ##"
	echo -e "\t[+] Wlan0 Is Active, Killing wlan0... "
	echo "## =========================================== ##"
	$(/sbin/ifconfig wlan0 down)
	$IFCONFIG $IFACE down
	ip link set $IFACE down
	# iwconfig $IFACE ap off
	# iwconfig $IFACE txpower off
	# iwconfig $IFACE power off
elif [ "$(cat /sys/class/net/wlan0/operstate)" = down ]; then		## if [ $IFACEOperState = down ]; then
	echo "## ================================================================= ##"
	echo -e "\t\t [+] Wlan0 Is Currently Down..."
	echo "## ================================================================= ##"
fi
echo 
echo "## ============================================================================== ##"
echo -e "\t\tSpoofing Wlan0 Interface"
echo "## ============================================================================== ##"
## 
## ======================================================================================== ##
# ifconfig wlan0 hw ether 00:40:96:f4:34:67
ip link set dev $IFACE address 00:30:65:39:2e:77
ifconfig $IFACE hw ether 00:30:65:39:2e:77
cat /sys/class/net/$IFACE/address
# echo '00:30:65:39:2e:77' > /sys/class/net/wlan0/address
# for i in /sys/class/net/wlan0/address; do echo 00:30:65:39:2e:77 > $i; done
## ======================================================================================== ##
## 

echo
echo "## ########################################################################################################## ##"
echo "## ========================================================================================================== ##"
echo "## ########################################################################################################## ##"
echo
if [ -d /sys/class/net/wlan1 ]; then
	echo -e "\t\t [+] wlan1 Exists!"
else
	echo "## ================================================================= ##"
	echo -e "\t\t [+] wlan1 Currently Does Not Exist..."
	echo "## ================================================================= ##"
fi

echo "## ================================================================= ##"
echo -e "\t\t [+] Is wlan1 Up?..."
echo "## ================================================================= ##"
if [ "$(cat /sys/class/net/wlan1/operstate)" = up ]; then 
	echo "## =========================================== ##"
	echo -e "\t[+] wlan1 Is Active, Killing wlan1... "
	echo "## =========================================== ##"
	$(/sbin/ifconfig wlan1 down)
	$IFCONFIG $ALPHA down
	ip link set $ALPHA down
	# iwconfig $ALPHA ap off
	# iwconfig $ALPHA txpower off
	# iwconfig $ALPHA power off
elif [ "$(cat /sys/class/net/wlan1/operstate)" = down ]; then		## if [ $IFACEOperState = down ]; then
	echo "## ================================================================= ##"
	echo -e "\t\t [+] wlan1 Is Currently Down..."
	echo "## ================================================================= ##"
fi
echo 
echo "## ============================================================================== ##"
echo -e "\t\tSpoofing wlan1 Interface"
echo "## ============================================================================== ##"
## 
## ======================================================================================== ##
# ifconfig wlan1 hw ether 00:40:96:f4:34:67
ip link set dev $ALPHA address 00:30:65:39:2e:77
ifconfig $ALPHA hw ether 00:30:65:39:2e:77
cat /sys/class/net/$ALPHA/address
# echo '00:30:65:39:2e:77' > /sys/class/net/wlan1/address
# for i in /sys/class/net/wlan1/address; do echo 00:30:65:39:2e:77 > $i; done
## ======================================================================================== ##
## 
echo
echo "## ########################################################################################################## ##"
echo "## ========================================================================================================== ##"
echo "## ########################################################################################################## ##"
echo
echo "## ================================================================= ##"
echo -e "\t\t [+] Checking To See If Wlan2 Exists..."
echo "## ================================================================= ##"
echo
echo
if [ -d /sys/class/net/wlan2 ]; then
	echo -e "\t\t [+] wlan2 Exists!"
else
	echo "## ================================================================= ##"
	echo -e "\t\t [+] wlan2 Currently Does Not Exist..."
	echo "## ================================================================= ##"
fi

echo "## ================================================================= ##"
echo -e "\t\t [+] Is wlan2 Up?..."
echo "## ================================================================= ##"
if [ "$(cat /sys/class/net/wlan2/operstate)" = up ]; then 
	echo "## =========================================== ##"
	echo -e "\t[+] wlan2 Is Active, Killing wlan2... "
	echo "## =========================================== ##"
	$(/sbin/ifconfig wlan2 down)
	$IFCONFIG $ALPHA2 down
	ip link set $ALPHA2 down
	# iwconfig $ALPHA2 ap off
	# iwconfig $ALPHA2 txpower off
	# iwconfig $ALPHA2 power off
elif [ "$(cat /sys/class/net/wlan2/operstate)" = down ]; then		## if [ $IFACEOperState = down ]; then
	echo "## ================================================================= ##"
	echo -e "\t\t [+] wlan2 Is Currently Down..."
	echo "## ================================================================= ##"
fi
echo 
echo "## ============================================================================== ##"
echo -e "\t\tSpoofing wlan2 Interface"
echo "## ============================================================================== ##"
## 
## ======================================================================================== ##
# ifconfig wlan2 hw ether 00:40:96:f4:34:67
ip link set dev wlan2 address 00:30:65:39:2e:77
ifconfig wlan2 hw ether 00:30:65:39:2e:77
cat /sys/class/net/wlan2/address
# echo '00:30:65:39:2e:77' > /sys/class/net/wlan2/address
# for i in /sys/class/net/wlan2/address; do echo 00:30:65:39:2e:77 > $i; done
## ======================================================================================== ##
## echo
echo "## ########################################################################################################## ##"
echo "## ========================================================================================================== ##"
echo "## ########################################################################################################## ##"
echo
#############################################################################################
echo "## ============================================================================== ##"
echo -e "\t\t [+] Killing Networking For A Second..."
echo "## ============================================================================== ##"
#############################################################################################
service networking stop
service NetworkManager stop
#############################################################################################
echo "## ============================================================================== ##"
echo -e "\t\t [+] Using RFkill To Block Bluetooth, GPS, And NFC..."
echo "## ============================================================================== ##"
#############################################################################################
set -e
if [ -e /usr/sbin/rfkill ]; then
	rfkill block all
for devtype in wifi wwan wimax ; do
   rfkill unblock "$devtype"
done
echo
echo
###########################################################################
# /sys/class/net/wlan0/device/net/wlan0/broadcast
# /sys/class/net/wlan0/device/net/wlan0/mtu
###########################################################################
# cat /sys/class/net/wlan0/device/net/wlan0/device/power/control 
# cat /sys/class/net/wlan0/device/net/wlan0/device/power/async 
# cat /sys/class/net/wlan0/device/net/wlan0/device/power/runtime_status 
###########################################################################
echo "## ================================================================= ##"
echo -e "\t\t [+] list  of  available frequencies"
echo "## ================================================================= ##"
iwlist wlan0 frequency  	 			## iwlist wlan0 channel 
echo
echo "## ================================================================= ##"
echo -e "\t\t [+] List the bit-rates supported by the device"
echo "## ================================================================= ##"
iwlist wlan0 rate 	 			## iwlist wlan0 bitrate 		
echo
echo "## ================================================================= ##"
echo -e "\t\t [+] List the encryption key sizes supported "
echo -e "\t\t and list all the encryption keys set in the device"
echo "## ================================================================= ##"
iwlist wlan0 encryption 			## iwlist wlan0 keys
echo
echo "## ================================================================= ##"
echo -e "\t\t [+] List the various Power Management attributes and modes"
echo "## ================================================================= ##"
iwlist wlan0 power
echo "## ================================================================= ##"
echo -e "\t\t [+] List the various Transmit Powers available on the device"
echo "## ================================================================= ##"
iwlist wlan0 txpower 
echo
echo "## ================================================================= ##"
echo -e "\t\t [+] List the transmit retry limits and retry lifetime on the device"
echo "## ================================================================= ##"
iwlist wlan0 retry 
echo
echo "## ================================================================= ##"
echo -e "\t\t [+] list of Access Points in range"
echo "## ================================================================= ##"
iwlist wlan0 ap  			## iwlist wlan0 accesspoints 
##  						## iwlist wlan0 peers 
echo
echo "## ================================================================= ##"
echo -e "\t\t [+] List the wireless events supported by the device"
echo "## ================================================================= ##"
iwlist wlan0 event
echo "## ================================================================= ##"
echo -e "\t\t [+] List the WPA authentication parameters currently set"
echo "## ================================================================= ##"
iwlist wlan0 auth
echo "## ================================================================= ##"
echo -e "\t\t [+] List all the WPA encryption keys set in the device"
echo "## ================================================================= ##"
iwlist wlan0 wpakeys 
echo "## ================================================================= ##"
echo -e "\t\t [+] List the Generic Information Elements"
echo -e "\t\t set in the device (used for WPA support)"
echo "## ================================================================= ##"
iwlist wlan0 genie
echo "## ================================================================= ##"
echo -e "\t\t [+] List the modulations supported by the device"
echo "## ================================================================= ##"
iwlist wlan0 modulation
echo
echo "## ########################################################################################################## ##"
echo "## ========================================================================================================== ##"
echo "## ########################################################################################################## ##"
echo
echo "## ================================================================= ##"
echo
# if [[ "${USE_WITH_TOR}" == 1 ]]; then
#	cd ${HOME} && \
#		torsocks wget -q --progress=bar -U $USER_AGENT \
#			--secure-protocol=TLSv1 --ca-certificate=
echo
echo "## ########################################################################################################## ##"
echo "## ========================================================================================================== ##"
echo "## ########################################################################################################## ##"
echo
echo "## ================================================================= ##"
echo -e "\t\t [+] Setting I2P Environment Variables..."
echo "## ================================================================= ##"
##
## 
## ==================================================================================== ##
I2pMonotone="8998"
export I2pMonotone="8998"
## ==================================================================================== ##
I2PHttpPort="4444"
export I2PHttpPort="4444"
## ==================================================================================== ##
I2PHttpsPort="4445"
export I2PHttpsPort="4445"
## ==================================================================================== ##
TAHOE_PORT="3456"
export TAHOE_PORT="3456"
## ==================================================================================== ##
I2pPostmanPop3="7660"
export I2pPostmanPop3="7660"
## ==================================================================================== ##
I2pPostmanSTMP="7659"
export I2pPostmanSTMP="7659"
## ==================================================================================== ##
Irc2PPort="6668"
export Irc2PPort="6668"
## ==================================================================================== ##
I2PWebserverPort="7658"
export I2PWebserverPort="7658"
## ==================================================================================== ##
I2pLocalControlChannelServiceWrapper="32000"
export I2pLocalControlChannelServiceWrapper="32000"
## ==================================================================================== ##
I2pLocalconnectionServiceWrapper="31000"
export I2pLocalconnectionServiceWrapper="31000"
## ==================================================================================== ##
I2pIrc="6668"
export I2pIrc="6668"
## ==================================================================================== ##
SSDPSearchResponseListener="7653"				## UPnP_SSDP_UDP
export SSDPSearchResponseListener="7653"
## ==================================================================================== ##
TCPEventListener="7652"							## UPnP HTTP TCP
export TCPEventListener="7652"
## ==================================================================================== ##
I2pBobBridge="2827"
export I2pBobBridge="2827"
## ==================================================================================== ##
I2pSSDPMulticastListener="1900"			## UPnP SSDP UDP
export I2pSSDPMulticastListener="1900"
## ==================================================================================== ##
I2pClientProtocolPort="7654"
export I2pClientProtocolPort="7654"
## ==================================================================================== ##
I2pUdpSAMBridge="7655"
export I2pUdpSAMBridge="7655"
## ==================================================================================== ##
I2pSAMBridge="7656"
export I2pSAMBridge="7656"
## ==================================================================================== ##

echo "## ================================================================= ##"
echo -e "\t\t [+] Setting Tor Environment Variables..."
echo "## ================================================================= ##"
## 
## ==================================================================================== ##
TorifiedDNSSocket="5353"
export TorifiedDNSSocket="5353"
## ==================================================================== ##
TailsSpecificSocksPort="9062"
export TailsSpecificSocksPort="9062"				## IsolateDestAddr IsolateDestPort
## ==================================================================== ##
TOR_CONTROL_PORT="9051"
export TOR_CONTROL_PORT="9051"
## ==================================================================== ##
TOR_DNS_PORT="5353"
export TOR_DNS_PORT="5353"
## ==================================================================== ##
TOR_TRANS_PORT="9040"
export TOR_TRANS_PORT="9040"
## ==================================================================== ##
TRANSPROXY_USER="anon"
export TRANSPROXY_USER="anon"
## ==================================================================================== ##
## 
echo "## ================================================================= ##"
echo -e "\t\t [+] Setting SOCKS5 Environment Variables..."
echo "## ================================================================= ##"

echo "## ================================================================= ##"
echo -e "\t\t [+] Setting Other Services Environment Variables..."
echo "## ================================================================= ##"
##
## 
## ==================================================================================== ##
CUPS_PORT="631"
SMTPSPort="465"						## SMTP over TLS
SMTP_PORT="25"
SSH_PORT="22"
SSH_ALT_PORT="2222"

SQUID_PORT="3128"				# Squid port
BITTORRENT_TRACKER="6881"
hkpsPoolSksKeyserverPort="11371"
MonkeysphereValidationAgent="6136"
## ==================================================================================== ##
## 
# [ -n "$" ] || 
# [ -n "$" ] || 
## ==================================================================================== ##
## 
Curlopt="--tlsv1.3 --verbose --ssl-reqd --progress-bar"
Wget="wget -q -O - "
## ==================================================================================== ##
## 
echo "## ============================================================================== ##"
echo -e "\t\t\t[+] Setting GPG Main Options In Environment Variables..."
echo "## ============================================================================== ##"
# See also some useful OpenPGP maintenance scripts:
#
#   - git://lair.fifthhorseman.net/~mjgoins/cur
#   - https://gitorious.org/key-report
#   - https://github.com/ilf/gpg-maintenance.git
#   - https://github.com/EtiennePerot/parcimonie.sh
#   - https://gaffer.ptitcanardnoir.org/intrigeri/code/parcimonie/


# cd /home/directory/where/you/saved/the/file (change for the right path)
# cp gnupg-ccid.rules /etc/udev/gnupg-ccid.rules
# cp gnupg-ccid /etc/udev/scripts/gnupg-ccid
# chmod +x /etc/udev/scripts/gnupg-ccid
# ln -s /etc/udev/gnupg-ccid.rules /etc/udev/rules.d/gnupg-ccid.rules


## 
## ==================================================================================== ##
GnupgHome="/home/faggot/.gnupg/"
GnupgGenKey="gpg2 --enable-large-rsa --full-gen-key"
GnupgRecvKeys="--recv-keys"
GnupgAptKeyAdd=$(apt-key add) 
GnupgExport="--export 0x"
GnupgKeyAdd=" | sudo apt-key add - "
GnupgListKeys="--list-keys --with-fingerprint"
GnupgKeyImport="--keyid-format 0xlong --import"
GnupgVerify="--keyid-format 0xlong --verify"
GnupgFingerprint="--fingerprint 0x"
GnupgKeyServerPrints="gpg2 --print-pka-records --print-dane-records"
## ==================================================================================== ##
## 
echo "## ============================================================================== ##"
echo -e "\t\t\t[+] Setting GPG KeyServers..."
echo "## ============================================================================== ##"
## 
## ==================================================================================== ##
GPGKeyServer="--keyserver hkps://hkps.pool.sks-keyservers.net"
GnupgRiseupKeyserver="--keyserver keys.riseup.net"
GnupgUbuntuKeyserver="--keyserver hkp://keyserver.ubuntu.com"
GnupgSksXhkpKeyserver="--keyserver x-hkp://pool.sks-keyservers.net"
GnupgSksHkpsKeyserver="--keyserver hkps://hkps.pool.sks-keyservers.net"
GnupgPGPNetKeyserver="--keyserver subkeys.pgp.net"
GnupgNetKeyserver="--keyserver keys.gnupg.net"
## ==================================================================================== ##
## 
echo "## ============================================================================== ##"
echo -e "\t\t\t[+] Setting GPG Defaults & Preferences..."
echo "## ============================================================================== ##"
## 
## ==================================================================================== ##
GnupgDefaultKeyserver="--default-keyserver-url hkps://hkps.pool.sks-keyservers.net"
declare -r SKS_CA="sks-keyservers.netCA.pem"
GPGOnionKeyServer="--keyserver hkp://qdigse2yzvuglcix.onion"
KeyServerOpts="verbose verbose verbose no-include-revoked no-include-disabled no-auto-key-retrieve no-honor-keyserver-url no-honor-pka-record include-subkeys no-include-attributes"
GnupgListOpt="--list-options no-show-photos show-uid-validity no-show-unusable-uids no-show-unusable-subkeys show-notations show-user-notations show-policy-urls show-keyserver-urls show-sig-expire show-sig-subpackets"
GnupgVerifyOpt="--verify-options no-show-photos show-uid-validity show-notations show-user-notations show-policy-urls show-keyserver-urls pka-lookups pka-trust-increase"
GnupgCertDigestAlgo="--cert-digest-algo SHA512"
GnupgDigestAlgo="--digest-algo SHA512"
GnupgKeyFormat="--keyid-format 0xlong"
GnupgDefaultPrefList="--default-preference-list SHA512 SHA384 SHA256 AES256 ZLIB ZIP Uncompressed"
GnupgCipherPref="--personal-cipher-preferences AES256"
GnupgDigestPref="--personal-digest-preferences SHA512 SHA384 SHA256"
GnupgCompressPref="--personal-compress-preferences ZLIB ZIP"
GnupgCompressLvl="--compress-level 9"
UpdateDB="--update-trustdb"
## ==================================================================================== ##
## 
echo "## ============================================================================== ##"
echo -e "\t\t\t[+] Securing Gnupg Keys Storage..."
echo "## ============================================================================== ##"
## 
## ==================================================================================== ##
GnupgKeyServeropt="--s2k-cipher-algo AES256"
Gnupgs2kDigest="--s2k-digest-algo SHA512"			## use this one to mangle the passphrases:
Gnupgs2kMode="--s2k-mode 3"
Gnupgs2kCount="--s2k-count xxxxxx"
GnupgSecMem="--require-secmem"		## Don't run if we can't secure mempages
## ==================================================================================== ##
## 

GNUPGHOME
gpgconf --list-dirs
gpgconf --list-options
gpgconf --change-options
gpgconf --check-options
gpgconf --list-components
gpgconf --list-options scdaemon
gpgconf --list-options pinentry
gpgconf --list-options gpg
gpgconf --list-options gpg-agent
gpgconf --check-options Security

gpg --gpgconf-list
gpg --homedir 
gpg --auto-check-trustdb
gpg --auto-key-locate
gpg --list-config
gpg --primary-keyring

apt-key update

GPGClearSigRelease=$(gpg --clearsign -o InRelease Release)
GPGClearSigReleaseSig=$(gpg -abs -o Release.gpg Release)



  $GPG --homedir "$GnuPGHome" --gen-key --batch <<EOF
    Key-Type: RSA
    Key-Length: 4096
    Subkey-Type: ELG-E
    Subkey-Length: 4096
    Name-Real: $GnuPGID
    Name-Email: $GnuPGEmail
    Expire-Date: 6m
    Passphrase: $passphrase
    %commit
EOF


generate_master_key() {
	# Generate the master key, which will be in both pubring and secring
	"${GPG_PACMAN[@]}" --gen-key --batch <<EOF
%echo Generating pacman keyring master key...
Key-Type: RSA
Key-Length: 2048
Key-Usage: sign
Name-Real: Pacman Keyring Master Key
Name-Email: pacman@localhost
Expire-Date: 0
%no-protection
%commit
%echo Done
EOF




sig,.md5sum}
$LATESTDL{,.DIGESTS.asc,.DIGESTS}
CACertFile="/etc/ssl/certs/ca-certificate.crt"
hkpsSksCACertFile="/etc/ssl/certs/hkps.pool.sks-keyservers.net.pem"
## keyserver-options http-proxy=socks5-hostname://127.0.0.1:9050
## keyserver-options no-try-dns-srv
# gpg2 $GPGKeyServer $GnupgRecvKeys 0x
##

gpg_exit_code="0"

gpg \
   --no-options \
   --no-emit-version \
   --no-comments \
   --display-charset utf-8 \
   $GPGOnionKeyServer \

#   --keyserver hkp://qdigse2yzvuglcix.onion \
   $GnupgDefaultKeyserver \
#	--default-keyserver-url hkps://hkps.pool.sks-keyservers.net
   $GnupgCertDigestAlgo \
#	--cert-digest-algo SHA512 \
   $GnupgDigestAlgo \
#	--digest-algo SHA512 \
   $GnupgDefaultKeyserver \
#   --default-keyserver-url hkps://hkps.pool.sks-keyservers.net
   $KeyServerOpts \
#   --keyserver-options verbose verbose verbose no-include-revoked no-include-disabled no-auto-key-retrieve no-honor-keyserver-url no-honor-pka-record include-subkeys no-include-attributes
   $GnupgListOpt \
#   --list-options no-show-photos show-uid-validity no-show-unusable-uids no-show-unusable-subkeys show-notations show-user-notations show-policy-urls show-keyserver-urls show-sig-expire show-sig-subpackets
   $GnupgVerifyOpt \
#   --verify-options no-show-photos show-uid-validity show-notations show-user-notations show-policy-urls show-keyserver-urls pka-lookups pka-trust-increase
   $GnupgKeyFormat \
#	--keyid-format 0xlong \
   $GnupgDefaultPrefList \
#	--default-preference-list SHA512 SHA384 SHA256 AES256 ZLIB ZIP Uncompressed \
   $GnupgCipherPref \
#	--personal-cipher-preferences AES256 \
   $GnupgDigestPref \
#	--personal-digest-preferences SHA512 SHA384 SHA256 \
   $GnupgCompressPref \
#	--personal-compress-preferences ZLIB ZIP \
   $GnupgCompressLvl \
#	--compress-level 9 \
   $GnupgKeyServeropt \
#   --s2k-cipher-algo AES256
   $Gnupgs2kDigest \
#   --s2k-digest-algo SHA512			## use this one to mangle the passphrases:
   $Gnupgs2kMode \
#   --s2k-mode 3
   $Gnupgs2kCount \
#   --s2k-count xxxxxx
   $GnupgSecMem \
#   --require-secmem		## Don't run if we can't secure mempages

#   --sig-notation issuer-fpr@notations.openpgp.fifthhorseman.net=%g \
#   --no-default-keyring \
   ${1+"$@"}

gpg_exit_code="$?"

if [ "$gpg_exit_code" = "0" ]; then
   true "${bold}INFO: End of: $BASH_SOURCE | $whonix_build_error_counter error(s) detected. (benchmark: skipped)${reset}"
else
   true "${bold}${red}INFO: End of: $BASH_SOURCE ERROR detected. (benchmark: skipped)${reset}"
fi

exit "$gpg_exit_code"

## ==================================================================================== ##
gpg2 $GPGKeyServer $GnupgRecvKeys 0x916B8D99C38EAF5E8ADC7A2A8D66066A2EEACCDA
gpg2 $GPGKeyServer $GnupgRecvKeys 0x9B157153925C303A42253AFB9C131AD3713AAEEF
gpg2 $GPGKeyServer $GnupgRecvKeys 0x44C6513A8E4FB3D30875F758ED444FF07D8D0BF6
gpg2 $GPGKeyServer $GnupgRecvKeys 0xBD1265FD4954C40AEBCBF5D75BF72F42D0952C5A
gpg2 $GPGKeyServer $GnupgRecvKeys 0x3E233DAE06747F9E0C64D1758CF6E896B3C01B09
gpg2 $GPGKeyServer $GnupgRecvKeys 0x4456EBBEC80563FE57E6B310415576BAA76E0BED
gpg2 $GPGKeyServer $GnupgRecvKeys 0x7840E7610F28B904753549D767ECE5605BCF1346
gpg2 $GPGKeyServer $GnupgRecvKeys 0x2D3D2D03910C6504C1210C65EE60C0C8EE7256A8
gpg2 $GPGKeyServer $GnupgRecvKeys 0xEF6E286DDA85EA2A4BA7DE684E2C6E8793298290
gpg2 $GPGKeyServer $GnupgRecvKeys 0x8738A680B84B3031A630F2DB416F061063FEE659
gpg2 $GPGKeyServer $GnupgRecvKeys 0xA3C4F0F979CAA22CDBA8F512EE8CBC9E886DDD89
gpg2 $GPGKeyServer $GnupgRecvKeys 0xED6D65271AACF0FF15D123036FB2A1C265FFB764
gpg2 $GPGKeyServer $GnupgRecvKeys 0x0A6A58A14B5946ABDE18E207A3ADB67A2CDB8B35
gpg2 $GPGKeyServer $GnupgRecvKeys 0x0D24B36AA9A2A651787876451202821CBE2CD9C1
gpg2 $GPGKeyServer $GnupgRecvKeys 0x4A90646C0BAED9D456AB3111E5B81856D0220E4B
gpg2 $GPGKeyServer $GnupgRecvKeys 0xB1172656DFF983C3042BC699EB5A896A28988BF5
gpg2 $GPGKeyServer $GnupgRecvKeys 0xF65CE37F04BA5B360AE6EE17C218525819F78451
gpg2 $GPGKeyServer $GnupgRecvKeys 0x13EBBDBEDE7A12775DFDB1BABB572E0E2D182910
gpg2 $GPGKeyServer $GnupgRecvKeys 0x2D3D2D03910C6504C1210C65EE60C0C8EE7256A8
gpg2 $GPGKeyServer $GnupgRecvKeys 0x3E233DAE06747F9E0C64D1758CF6E896B3C01B09
gpg2 $GPGKeyServer $GnupgRecvKeys 0x4456EBBEC80563FE57E6B310415576BAA76E0BED
gpg2 $GPGKeyServer $GnupgRecvKeys 0x4844b1fd45f5a68744fa28d2f3e3b61a3cf83b95		## kytv@mail.i2p
gpg2 $GPGKeyServer $GnupgRecvKeys 0x4E0791268F7C67EABE88F1B03043E2B7139A768E
gpg2 $GPGKeyServer $GnupgRecvKeys 0x647F28654894E3BD457199BE38DBBDC86092693E
gpg2 $GPGKeyServer $GnupgRecvKeys 0x7840E7610F28B904753549D767ECE5605BCF1346
gpg2 $GPGKeyServer $GnupgRecvKeys 0x81DDBD614603A7A66C919E6296D5CD8C8B4EDA79
gpg2 $GPGKeyServer $GnupgRecvKeys 0x843938DF228D22F7B3742BC0D94AA3F0EFE21092
gpg2 $GPGKeyServer $GnupgRecvKeys 0x8738A680B84B3031A630F2DB416F061063FEE659
gpg2 $GPGKeyServer $GnupgRecvKeys 0x97C6EEFB60D38EA4C1BE33FFABE0C319DF0A0A1A
gpg2 $GPGKeyServer $GnupgRecvKeys 0xA1BD8E9D78F7FE5C3E65D8AF8B48AD6246925553
gpg2 $GPGKeyServer $GnupgRecvKeys 0xA3C4F0F979CAA22CDBA8F512EE8CBC9E886DDD89
gpg2 $GPGKeyServer $GnupgRecvKeys 0xA490D0F4D311A4153E2BB7CADBB802B258ACD84F
gpg2 $GPGKeyServer $GnupgRecvKeys 0xB55E70A95AC79474504C30D0DA11364B4760E444
gpg2 $GPGKeyServer $GnupgRecvKeys 0xB65FA586D190CD331F5F3369FB811DBD69DA1A8C
gpg2 $GPGKeyServer $GnupgRecvKeys 0xBD1265FD4954C40AEBCBF5D75BF72F42D0952C5A
gpg2 $GPGKeyServer $GnupgRecvKeys 0xC2E34CFC13C62BD92C7579B56B8AAEB1F1F5C9B5
gpg2 $GPGKeyServer $GnupgRecvKeys 0xC5986B4F1257FFA86632CBA746181433FBB75451
gpg2 $GPGKeyServer $GnupgRecvKeys 0xC963C21D63564E2B10BB335B29846B3C683686CC
gpg2 $GPGKeyServer $GnupgRecvKeys 0xD99EAC7379A850BCE47DA5F29E6438C817072058
gpg2 $GPGKeyServer $GnupgRecvKeys 0xDCD05B71EAB94199527F44ACDB6B8C1F96D8BF6D
gpg2 $GPGKeyServer $GnupgRecvKeys 0xE27344C4BD24BEDFE4F4C741803FEFB7F4B85E0F
gpg2 $GPGKeyServer $GnupgRecvKeys 0xED6D65271AACF0FF15D123036FB2A1C265FFB764
gpg2 $GPGKeyServer $GnupgRecvKeys 0xEF6E286DDA85EA2A4BA7DE684E2C6E8793298290
## ==================================================================================== ##
##
echo "## ########################################################################################################## ##"
echo "## ========================================================================================================== ##"
echo "## ########################################################################################################## ##"
##
## ==================================================================================== ##
gpg2 $GPGKeyServer $GnupgRecvKeys 0x$DebTorprojectOrgGPGKey
gpg2 $GPGKeyServer $GnupgRecvKeys 0x$ErinnClarkDepreciatedGPGKey
gpg2 $GPGKeyServer $GnupgRecvKeys 0x$ErinnClarkStableGPGKey
gpg2 $GPGKeyServer $GnupgRecvKeys 0x$GentooAutomatedWeeklyReleaseGPGKey
gpg2 $GPGKeyServer $GnupgRecvKeys 0x$GentooPortageSnapshotGPGKey
gpg2 $GPGKeyServer $GnupgRecvKeys 0x$GentooReleaseSigningGPGKey
gpg2 $GPGKeyServer $GnupgRecvKeys 0x$I2PDebianRepoGPGKey
gpg2 $GPGKeyServer $GnupgRecvKeys 0x$IsisLovecruftGPGKey
gpg2 $GPGKeyServer $GnupgRecvKeys 0x$KillYourTvDebianRepoGPGKey
gpg2 $GPGKeyServer $GnupgRecvKeys 0x$KillYourTVDepreciated2GPGKey
gpg2 $GPGKeyServer $GnupgRecvKeys 0x$KillYourTVDepreciatedGPGKey
gpg2 $GPGKeyServer $GnupgRecvKeys 0x$KillYourTvGPGKey
gpg2 $GPGKeyServer $GnupgRecvKeys 0x$LinuxKernelStableReleaseGPGKey
gpg2 $GPGKeyServer $GnupgRecvKeys 0x$MikePerryGPGKey
gpg2 $GPGKeyServer $GnupgRecvKeys 0x$NicolasVigierTBBBuildsGPGKey
gpg2 $GPGKeyServer $GnupgRecvKeys 0x$OpenwallGPGKey
gpg2 $GPGKeyServer $GnupgRecvKeys 0x$PhrackGPGKey
gpg2 $GPGKeyServer $GnupgRecvKeys 0x$RiseupGPGKey
gpg2 $GPGKeyServer $GnupgRecvKeys 0x$RogerDingledine2GPGKey
gpg2 $GPGKeyServer $GnupgRecvKeys 0x$RogerDingledineGPGKey
gpg2 $GPGKeyServer $GnupgRecvKeys 0x$SqueezeGPGKey
gpg2 $GPGKeyServer $GnupgRecvKeys 0x$SubgraphOS
gpg2 $GPGKeyServer $GnupgRecvKeys 0x$TailsDevelopersGPGKey
gpg2 $GPGKeyServer $GnupgRecvKeys 0x$TailsDevGPGKey
gpg2 $GPGKeyServer $GnupgRecvKeys 0x$TailsRPMGPGKey
gpg2 $GPGKeyServer $GnupgRecvKeys 0x$TorBrowserDevGPGKey
gpg2 $GPGKeyServer $GnupgRecvKeys 0x$UbuntuISO2GPGKey
gpg2 $GPGKeyServer $GnupgRecvKeys 0x$UbuntuISOGPGKey
gpg2 $GPGKeyServer $GnupgRecvKeys 0x$WheezyStableGPGKey
gpg2 $GPGKeyServer $GnupgRecvKeys 0x$zzzI2PDevGPGKey
gpg2 $GPGKeyServer $GnupgRecvKeys 0x$zzzOnI2pStableGPGKey
gpg2 $GPGKeyServer $GnupgRecvKeys 0x$EchelonGPGKeyFingerprint
gpg2 $GPGKeyServer $GnupgRecvKeys 0x$FrozenboxDevTeamGPGKey
gpg2 $GPGKeyServer $GnupgRecvKeys 0x$FrozenboxNetSigningOnlyGPGKey
gpg2 $GPGKeyServer $GnupgRecvKeys 0x$GrsecurityGPGKey
gpg2 $GPGKeyServer $GnupgRecvKeys 0x$KaliRepositoryGPGKey
gpg2 $GPGKeyServer $GnupgRecvKeys 0x$MeehGPGKeyFingerprint
gpg2 $GPGKeyServer $GnupgRecvKeys 0x$OracleVboxGPGKey
gpg2 $GPGKeyServer $GnupgRecvKeys 0x$ParrotSecGPGKey
gpg2 $GPGKeyServer $GnupgRecvKeys 0x$PirateLinuxGPGKey
gpg2 $GPGKeyServer $GnupgRecvKeys 0x$QubesMasterGPGKey
gpg2 $GPGKeyServer $GnupgRecvKeys 0x$RiseUpGnupgFPR
gpg2 $GPGKeyServer $GnupgRecvKeys 0x$sheireenParrotSecGPGKey
gpg2 $GPGKeyServer $GnupgRecvKeys 0x$SpongeGPGKeyFingerprint
gpg2 $GPGKeyServer $GnupgRecvKeys 0x$WelterdeGPGKeyFingerprint
gpg2 $GPGKeyServer $GnupgRecvKeys 0x$WhonixGPGKey
gpg2 $GPGKeyServer $GnupgRecvKeys 0x$zzzGPGKeyFingerprint
gpg2 $GPGKeyServer $GnupgRecvKeys 0x$AdrelanosGPGKey
## ==================================================================================== ##
##
echo "## ########################################################################################################## ##"
echo "## ========================================================================================================== ##"
echo "## ########################################################################################################## ##"
# gpg2 $GnupgExport  $GnupgKeyAdd
## 
## 
SHA1="openssl dgst -sha1"
SHA256="openssl dgst -sha256"
SHA512="openssl dgst -sha512"
## 
## 
echo "## ========================================================================= ##"
echo -e "\t\tDownload the SSL cerificates for *.riseup.net and check their fingerprints:"
echo "## ========================================================================= ##"
##
## 
## ==================================================================================== ##
RiseUpCertHTML='https://help.riseup.net/en/security/network-security/certificates/riseup-signed-certificate-fingerprints.txt'
RiseUpGnupgFPR=4E0791268F7C67EABE88F1B03043E2B7139A768E
RiseUpKeyserver='hkp://keys.mayfirst.org'
RiseUpMainCert='riseup.net'
RiseUpStatusCert='status.riseup.net'
## ==================================================================================== ##
echo
echo
echo "## ============================================================================== ##"
echo -e "\t\t\t[+] Appending ParrotSec Repo & GPG Keys Variables..."
echo "## ============================================================================== ##"
##
## 
## ==================================================================================== ##
ParrotSecSecurityRepo="deb http://archive.parrotsec.org/mirrors/parrot stable-security main contrib non-free"
ParrotSecMainRepo="deb http://euro3.archive.parrotsec.org/parrotsec stable main contrib non-free"
## ===================================================================================== ##
FrozenboxDevTeamGPGKey="B35050593C2F765640E6DDDB97CAA129F4C6B9A4"
ParrotSecGPGKey="C07B79F43025772903D19385042FB0305F53BE86"
sheireenParrotSecGPGKey="D9AA2A5D8FC42717EED85EC126096AE9CBD7FB08"
FrozenboxNetSigningOnlyGPGKey="C686553B9795FA72214DE39CD7427F070F4FC7A6"
## ==================================================================================== ##
# gpg --keyserver https://pgp.mit.edu/pks/lookup?op=get&search=0x042FB0305F53BE86
# gpg --keyserver https://pgp.mit.edu/pks/lookup?op=vindex&search=0x042FB0305F53BE86
# gpg --keyserver https://pgp.mit.edu/pks/lookup?op=get&search=0x97CAA129F4C6B9A4
# gpg --keyserver https://pgp.mit.edu/pks/lookup?op=vindex&search=0x97CAA129F4C6B9A4
# gpg --keyserver http://archive.parrotsec.org/parrot-keyring.gpg
# gpg --keyserver https://pgp.mit.edu/pks/lookup?op=vindex&search=0xD7427F070F4FC7A6
## ==================================================================================== ##
SubgraphOS="B55E70A95AC79474504C30D0DA11364B4760E444"
## ==================================================================================== ##
GentooReleaseSigningGPGKey="D99EAC7379A850BCE47DA5F29E6438C817072058"
GentooPortageSnapshotGPGKey="DCD05B71EAB94199527F44ACDB6B8C1F96D8BF6D"
GentooAutomatedWeeklyReleaseGPGKey="13EBBDBEDE7A12775DFDB1BABB572E0E2D182910"
## ==================================================================================== ##
RiseupGPGKey="4E0791268F7C67EABE88F1B03043E2B7139A768E"
WheezyStableGPGKey="ED6D65271AACF0FF15D123036FB2A1C265FFB764"
SqueezeGPGKey="A1BD8E9D78F7FE5C3E65D8AF8B48AD6246925553"
## ==================================================================================== ##
UbuntuISOGPGKey="843938DF228D22F7B3742BC0D94AA3F0EFE21092"
UbuntuISO2GPGKey="C5986B4F1257FFA86632CBA746181433FBB75451"
OpenwallGPGKey="81DDBD614603A7A66C919E6296D5CD8C8B4EDA79"
## ==================================================================================== ##
ErinnClarkStableGPGKey="C2E34CFC13C62BD92C7579B56B8AAEB1F1F5C9B5"
TailsDevGPGKey="0D24B36AA9A2A651787876451202821CBE2CD9C1"
TailsDevelopersGPGKey="A490D0F4D311A4153E2BB7CADBB802B258ACD84F"
TailsRPMGPGKey="E27344C4BD24BEDFE4F4C741803FEFB7F4B85E0F"
DebTorprojectOrgGPGKey="A3C4F0F979CAA22CDBA8F512EE8CBC9E886DDD89"
ErinnClarkDepreciatedGPGKey="8738A680B84B3031A630F2DB416F061063FEE659"
TorBrowserDevGPGKey="EF6E286DDA85EA2A4BA7DE684E2C6E8793298290"
MikePerryGPGKey="C963C21D63564E2B10BB335B29846B3C683686CC"
## ==================================================================================== ##
KillYourTvGPGKey="BD1265FD4954C40AEBCBF5D75BF72F42D0952C5A"
KillYourTvDebianRepoGPGKey="3E233DAE06747F9E0C64D1758CF6E896B3C01B09"
KillYourTVDepreciatedGPGKey="97C6EEFB60D38EA4C1BE33FFABE0C319DF0A0A1A"
KillYourTVDepreciated2GPGKey="4844b1fd45f5a68744fa28d2f3e3b61a3cf83b95"		## kytv@mail.i2p
## ==================================================================================== ##
zzzOnI2pStableGPGKey="2D3D2D03910C6504C1210C65EE60C0C8EE7256A8"
I2PDebianRepoGPGKey="7840E7610F28B904753549D767ECE5605BCF1346"
zzzI2PDevGPGKey="4456EBBEC80563FE57E6B310415576BAA76E0BED"
## ==================================================================================== ##
IsisLovecruftGPGKey="0A6A58A14B5946ABDE18E207A3ADB67A2CDB8B35"
PhrackGPGKey="B65FA586D190CD331F5F3369FB811DBD69DA1A8C"
LinuxKernelStableReleaseGPGKey="647F28654894E3BD457199BE38DBBDC86092693E"
## ==================================================================================== ##
NicolasVigierTBBBuildsGPGKey="0x4A90646C0BAED9D456AB3111E5B81856D0220E4B"
RogerDingledineGPGKey="0xB1172656DFF983C3042BC699EB5A896A28988BF5"
RogerDingledine2GPGKey="0xF65CE37F04BA5B360AE6EE17C218525819F78451"
## ==================================================================================== ##
echo
echo "## ============================================================================== ##"
echo -e "\t\t\t[+] Debian Wheezy Stable Repo..."
echo "## ============================================================================== ##"
##
## 
## ==================================================================================== ##
DebianWheezyTestingRepo="deb http://http.us.debian.org/debian/ testing main contrib non-free"
DebianWheezyTestingRepoOverTor="deb tor+http://ftp.us.debian.org/debian/ testing main contrib non-free"
WheezyStableProposedUpdatesRepo="deb http://ftp.us.debian.org/debian/ wheezy-proposed-updates main non-free contrib"
DebianWheezyMainStableRepo="deb http://http.us.debian.org/debian/ stable main contrib non-free"
DebianWheezyStableUpdatesRepo="deb http://ftp.us.debian.org/debian/ stable-updates main contrib non-free"
DebianWheezySecurityRepo="deb http://security.debian.org/ wheezy/updates main contrib non-free"
## ==================================================================================== ##
echo
echo "## ============================================================================== ##"
echo -e "\t\t\t[+] Kali Security Repo..."
echo "## ============================================================================== ##"
##
## 
## ==================================================================================== ##
KaliRepositoryGPGKey="44C6513A8E4FB3D30875F758ED444FF07D8D0BF6"
KaliSanaRepo="deb http://http.kali.org/kali sana main non-free contrib"
KaliRollingRepo="deb http://http.kali.org/kali kali-rolling main contrib non-free"
KaliSanaRepo="deb http://security.kali.org/kali-security sana/updates main contrib non-free"
KaliSanaRepo="deb http://http.kali.org/kali sana main non-free contrib"
KaliMotoRepo="deb http://old.kali.org/kali moto main non-free contrib"
KaliSecurityRepoOverTor="deb tor+http://security.kali.org/kali-security kali/updates main contrib non-free"
KaliSecurityRepo="deb http://security.kali.org/kali-security kali/updates main contrib non-free"
KaliBleedingEdgeRepoOverTor="deb http://repo.kali.org/kali kali-bleeding-edge main"
## ==================================================================================== ##
echo
echo "## ============================================================================== ##"
echo -e "\t\t\t[+]  Invoking Tor Project Repository & GPGKey Variables..."
echo "## ============================================================================== ##"
##
## 
## ==================================================================================== ##
TorProjectRepo="deb http://deb.torproject.org/torproject.org wheezy main"
TorProjectRepoOverTor="deb tor+http://deb.torproject.org/torproject.org wheezy main"
## ==================================================================================== ##
TailsRepoOverTor="deb tor+http://deb.tails.boum.org/ 1.5 main"
## ==================================================================================== ##
echo
echo "## ============================================================================== ##"
echo -e "\t\t\t[+] I2P & KillYourTV Keys, Crt, Keyring, Repo Environment Variables..."
echo "## ============================================================================== ##"
##
## 
## ==================================================================================== ##
I2PPublicKeyURL="https://geti2p.net/_static/debian-repo.pub"
I2PDebianWheezyRepo="deb http://deb.i2p2.no/ stable main"
I2PPublicKeyFile="debian-repo.pub"
I2pSiteKey="i2p-debian-repo.key.asc"
KillYourTVDarknetIRCCertFileURL="http://killyourtv.i2p/ircserver/kytv-cacert.pem"
KillYourTVDarknetIRCCertFileDir="/usr/local/share/ca-certificates/"
KillYourTVDarknetIRCCertFile="kytv-cacert.crt"
KillYourTVKeyring="kytv-archive-keyring.gpg"
## ==================================================================================== ##
WelterdeGPGKeyFingerprint="aae785027c240ebbb0a883fd8ebcf8d6ecee4104"	## dev@welterde.de
EchelonGPGKeyFingerprint="6c728b0ffed3c2bf7fb0f3c583b30f966d9bacd5"		## echelon2@mail.i2p
MeehGPGKeyFingerprint="de9d196e8057e1629178edbfa1ed754c648d7340"		## meeh@mail.i2p
SpongeGPGKeyFingerprint="1092773c40f5813b9179d52a8ab7b499b9554da3"		## sponge@mail.i2p
zzzGPGKeyFingerprint="896e399990704373125f782ae2ee19b6611ac612"			## zzz@mail.i2p
## ==================================================================================== ##
# echo
# echo "## ============================================================================== ##"
# echo -e "\t\t\t[+] Invoking  Repository & GPGKey Variables..."
# echo "## ============================================================================== ##"
## 
## 
echo "## ============================================================================== ##"
echo -e "\t\t\t[+] Invoking Pirate Linux Repository & GPGKey Variables..."
echo "## ============================================================================== ##"
##
## ==================================================================================== ##
PirateLinuxRepo="deb http://piratelinux.org/repo/deb/ stable main"
PirateLinuxGPGKey="B6AC822C451D63046A2849E97DB7011CD53B5647"
## ==================================================================================== ##
## 
echo "## ============================================================================== ##"
echo -e "\t\t\t[+] Invoking Whonix Repository & GPGKey Variables..."
echo "## ============================================================================== ##"
## 
## ==================================================================================== ##
WhonixAptRepository="deb http://sourceforge.net/projects/whonixdevelopermetafiles/files/internal/ wheezy main"
WhonixGPGKey="9B157153925C303A42253AFB9C131AD3713AAEEF"
AdrelanosGPGKey="916B8D99C38EAF5E8ADC7A2A8D66066A2EEACCDA"
## ==================================================================================== ##
## 
echo "## ============================================================================== ##"
echo -e "\t\t\t[+] Invoking Virtualbox Repository & GPGKey Variables..."
echo "## ============================================================================== ##"
##
## 
## ==================================================================================== ##OracleVbox2016GPGKey="B9F8D658297AF3EFC18D5CDFA2F683C52980AECF"
OracleVboxGPGKey="7B0FAB3A13B907435925D9C954422A4B98AB5139"
OracleVbox2016GPGKeyFile="oracle_vbox_2016.asc"
OracleVboxGPGKeyFile="oracle_vbox.asc"
OracleVbox2016URL="https://www.virtualbox.org/download/oracle_vbox_2016.asc -O- | sudo apt-key add -"
OracleVboxURL="https://www.virtualbox.org/download/oracle_vbox.asc"
VirtualboxWheezyRepo="deb http://download.virtualbox.org/virtualbox/debian wheezy contrib"
## ==================================================================================== ##
## 
echo "## ============================================================================== ##"
echo -e "\t\t\t[+] Cloning QubesOS Github Signing Keys..."
echo "## ============================================================================== ##"
##
## 
## ==================================================================================== ##
# git clone https://github.com/QubesOS/qubes-secpack.git
# gpg --import qubes-secpack/keys/*/*
# curl https://keys.qubes-os.org/keys/qubes-master-signing-key.asc
# gpg --keyserver pool.sks-keyservers.net --recv-keys 0x427F11FD0FAA4B080123F01CDDFA1A3E36879494
QubesMasterGPGKey="427F11FD0FAA4B080123F01CDDFA1A3E36879494"
gpg --export 0x427F11FD0FAA4B080123F01CDDFA1A3E36879494 | sudo apt-key add -
## ==================================================================================== ##
## 
echo "## ============================================================================== ##"
echo -e "\t\t\t[+] Debian Wheezy Stable Over Tor Repo..."
echo "## ============================================================================== ##"
##
## 
## ==================================================================================== ##
DebianWheezyMainStableOverTorRepo="deb tor+http://ftp.us.debian.org/debian/ wheezy main contrib non-free"
DebianWheezyStableUpdatesOverTorRepo="deb tor+http://ftp.us.debian.org/debian/ stable-updates main contrib non-free"
DebianWheezyUpdatesOverTorRepo="deb tor+http://security.debian.org/ wheezy/updates main contrib non-free"
## ==================================================================================== ##
## 
echo "## ============================================================================== ##"
echo -e "\t\t\t[+] Invoking Grsecurity Repository & GPGKey Variables..."
echo "## ============================================================================== ##"
##
## 
## ==================================================================================== ##GrsecurityRepo="deb http://www.grsecurity.net/debian stable main"
GrsecurityGPGKeyUrl="https://grsecurity.net/spender‐gpg‐key.asc"
GrsecurityGPGKeyFile="spender‐gpg‐key.asc"
GrsecurityGPGKey="DE9452CE46F42094907F108B44D1C0F82525FE49"
# gpg ‐‐verify ‐‐multifile grsecurity* gradm* paxctld*
## ==================================================================================== ##
## 
echo "## ============================================================================== ##"
echo -e "\t\t\t[+] ..."
echo "## ============================================================================== ##"
##


# gpg --keyserver pool.sks-keyservers.net --recv-keys 0x0482D84022F52DF1C4E7CD43293ACD0907D9495A
# gpg --export 0482D84022F52DF1C4E7CD43293ACD0907D9495A | sudo apt-key add -
# https://alpinelinux.org/keys/ncopa.asc
# gpg --import ncopa.asc
## 
## ==================================================================================== ##
KernelRepo="deb http://mirrors.kernel.org/debian/ stable main"
## ==================================================================================== ##
## 
## ==================================================================================== ##
FreeBSDRepo="deb http://pkg.FreeBSD.org/${ABI}/latest"
## ==================================================================================== ##
## 
echo "## ============================================================================== ##"
echo -e "\t\t\t[+] ..."
echo "## ============================================================================== ##"
##
## 
## ==================================================================================== ##
PentooHardenedRepo="http://mirror.switch.ch/ftp/mirror/pentoo/Packages/amd64-hardened/"
## ==================================================================================== ##
## 
echo "## ============================================================================== ##"
echo -e "\t\t\t[+] Android Repositories & GPG Keys:"
echo "## ============================================================================== ##"
FDroidMainRepo="https://f-droid.org/repo"
FDroidPlayStore="https://microg.org/fdroid/repo"
FDroidPlayStoreArchive="https://microg.org/fdroid/repo"
SignalTextSecureBuilds="https://microg.org/fdroid/archive"
echo "[+]=====================================================================[+]"
GuardianProjectMainRepo="https://guardianproject.info/fdroid/repo"
export GuardianProjectMainRepo="https://guardianproject.info/fdroid/repo"
echo "[+]=====================================================================[+]"
GuardianProjectAWS="https://s3.amazonaws.com/guardianproject/fdroid/repo"
export GuardianProjectAWS="https://s3.amazonaws.com/guardianproject/fdroid/repo"
echo "[+]=====================================================================[+]"
TorHiddenServiceFDroidRepo="http://bdf2wcxujkg6qqff.onion/fdroid/repo"
export TorHiddenServiceFDroidRepo="http://bdf2wcxujkg6qqff.onion/fdroid/repo"
echo "[+]=====================================================================[+]"
FDroidIOFrontend="https://f-droid.i2p.io/repo/"
export FDroidIOFrontend="https://f-droid.i2p.io/repo/"
echo "[+]=====================================================================[+]"
FDroidArchive="https://f-droid.org/archive"
export FDroidArchive="https://f-droid.org/archive"
echo "[+]=====================================================================[+]"
FDroidClientGitRepo="https://gitlab.com/fdroid/fdroidclient"
export FDroidClientGitRepo="https://gitlab.com/fdroid/fdroidclient"
echo "[+]=====================================================================[+]"
echo "GPG signing key: "F-Droid <admin@f-droid.org>" "
echo "Primary key fingerprint: 37D2 C987 89D8 3119 4839 4E3E 41E7 044E 1DBA 2E89"
echo "Subkey fingerprint: 802A 9799 0161 1234 6E1F EFF4 7A02 9E54 DD5D CE7A"
echo "[+]==================================================================================================[+]"
echo "git tags signed by "Daniel Martí <mvdan@mvdan.cc>" aka "Daniel Martí <mvdan@fsfe.org>" with fingerprint: "
echo "A9DA 13CD F7A1 4ACD D3DE E530 F4CA FFDB 4348 041C"
echo "[+]==================================================================================================[+]"
# FDroidAPKSigningKey=""
echo "FDroid Certificate fingerprints:"
echo "  MD5:  17:C5:5C:62:80:56:E1:93:E9:56:44:E9:89:79:27:86"
echo "  SHA1: 05:F2:E6:59:28:08:89:81:B3:17:FC:9A:6D:BF:E0:4B:0F:A1:3B:4E"
echo "  SHA256: 43:23:8D:51:2C:1E:5E:B2:D6:56:9F:4A:3A:FB:F5:52:34:18:B8:2E:0A:3E:D1:55:27:70:AB:B9:A9:C9:CC:AB"
echo "[+]==================================================================================================[+]"
echo





#
# Start rsyslog if not currently running
#
/sbin/service rsyslog start


/lib/modprobe.d/*.conf

/etc/modprobe.d/*.conf
/run/modprobe.d/*.conf 
/lib/modules/modules.dep

/lib/modules/modules.dep.bin
/usr/lib/depmod.d/*.conf
/etc/depmod.d/*.conf
/run/depmod.d/*.conf#7C00FF










echo "## ============================================================================== ##"
echo -e "\t\t\t[+] Loading Required Modprobe Modules..."
echo "## ============================================================================== ##"
$MODPROBE ip_tables
$MODPROBE ip_conntrack
$MODPROBE iptable_filter
$MODPROBE iptable_mangle
$MODPROBE iptable_nat
$MODPROBE ipt_LOG
$MODPROBE ipt_limit
$MODPROBE ipt_state
#
# 2.2 Non-Required modules
#
#/sbin/modprobe ipt_owner
#/sbin/modprobe ipt_REJECT
#/sbin/modprobe ipt_MASQUERADE
#/sbin/modprobe ip_conntrack_ftp
#/sbin/modprobe ip_conntrack_irc
#/sbin/modprobe ip_nat_ftp
#/sbin/modprobe ip_nat_irc
## 
## 
/sbin/modprobe
ip_conntrack_rsh

add the following lines to /etc/modules.conf


add options ip_conntrack_rsh ports=514,7937



echo "## ============================================================================== ##"
echo -e "\t\t[+] Displaying OS (Type|Release|Version) From /Proc/Sys/Kernel"
echo "## ============================================================================== ##"
OSType="/proc/sys/kernel/ostype" 
OSRelease="/proc/sys/kernel/osrelease"
KernelVersion="/proc/sys/kernel/version"
## 
## ==================================================================================== ##
KernelConfig="/boot/config-`uname -r`"
export KernelConfig="/boot/config-`uname -r`"
SystemMap="System.map-`uname -r`"
export SystemMap="System.map-`uname -r`"
vmlinuz="vmlinuz-`uname -r`"
export vmlinuz="vmlinuz-`uname -r`"
Initrd="initrd.img-`uname -r`"
export Initrd="initrd.img-`uname -r`"
LinuxHeaders="/usr/src/linux-headers-`uname -r`"
export LinuxHeaders="/usr/src/linux-headers-`uname -r`"
KERNEL_DIR="/usr/src/linux-headers-$(uname -r)"
export KERNEL_DIR="/usr/src/linux-headers-$(uname -r)"
KernInclude="/usr/src/linux-headers-`uname -r`/include"
export KernInclude="/usr/src/linux-headers-`uname -r`/include"
UsrInclude="/usr/include/"
export UsrInclude="/usr/include/"
ModuleDir="/lib/modules/`uname -r`"
export ModuleDir="/lib/modules/`uname -r`"
## ==================================================================================== ##
## 
## ==================================================================================== ##
# LD_LIBRARY_PATH=""
# LD_PRELOAD=""					## list  of ELF shared objects to be loaded before all others.
# ldsoconf="/etc/ld.so.conf"	## File  containing  a  list  of Library directories
# ldso="/lib/ld.so"				## Runtime dynamic linker That resolving shared object dependencies
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
accept_dad
accept_ra
accept_ra_defrtr
accept_ra_from_local
accept_ra_min_hop_limit
accept_ra_mtu
accept_ra_pinfo
accept_ra_rt_info_max_plen
accept_ra_rtr_pref
accept_redirects
accept_source_route
autoconf
dad_transmits
disable_ipv6
drop_unicast_in_l2_multicast
drop_unsolicited_na
force_mld_version
force_tllao
forwarding
hop_limit
ignore_routes_with_linkdown
keep_addr_on_down
max_addresses
max_desync_factor
mc_forwarding
mldv1_unsolicited_report_interval
mldv2_unsolicited_report_interval
sysctl -w /proc/sys/net/ipv6/conf/all/mtu
net.ipv4.conf.all
net
/proc/sys/net/ipv6/conf/all
.all
.proc.sys.net.ipv6.conf.all.mtu
sysctl -w net.ipv4.conf.all
/proc/sys/net/ipv4/conf/
/proc/sys/net/ipv4/conf/*

bootp_relay


net
net.ipv6.conf.all
ndisc_notify
optimistic_dad
proxy_ndp
regen_max_retry
router_probe_interval
router_solicitation_delay
router_solicitation_interval
router_solicitations
stable_secret
suppress_frag_ndisc
temp_prefered_lft
temp_valid_lft
use_oif_addrs_only
use_optimistic
use_tempaddr

echo "## ============================================================================== ##"
echo -e '\t\t'{BLOODRED}'''{RESET}'
echo "## ============================================================================== ##"

echo -e '\t\t'{FORRED}' ''{RESET}'
echo "## ============================================================================== ##"
echo -e '\t\t'{BLOODRED}'Log and drop "Martian" packets''{RESET}'
echo -e '\t\t'{FORRED}'A "Martian" packet is one for which the host''{RESET}'
echo -e '\t\t'{FORRED}'does not have a route back to the source IP address''{RESET}'
echo "## ============================================================================== ##"
sysctl -w net.ipv4.conf.all.log_martians=1
# for i in /proc/sys/net/*; do echo 1 > $i; done

echo -e '\t\t'{FORRED}' ''{RESET}'
echo "## ============================================================================== ##"
echo -e '\t\t'{BLOODRED}'''{RESET}'
echo -e '\t\t'{FORRED}' ''{RESET}'
echo "## ============================================================================== ##"

echo "## ============================================================================== ##"
echo -e '\t\t'{BLOODRED}'''{RESET}'
echo -e '\t\t'{FORRED}' ''{RESET}'
echo "## ============================================================================== ##"
/proc/sys/net/core/bpf_jit_enable
echo "## ============================================================================== ##"
echo -e '\t\t'{BLOODRED}'''{RESET}'
echo -e '\t\t'{FORRED}' ''{RESET}'
echo "## ============================================================================== ##"

echo "## ============================================================================== ##"
echo -e '\t\t'{BLOODRED}'''{RESET}'
echo -e '\t\t'{FORRED}' ''{RESET}'
echo "## ============================================================================== ##"

echo "## ============================================================================== ##"
echo -e '\t\t'{BLOODRED}'Disabling IPV6...''{RESET}'
echo -e '\t\t'{FORRED}' ''{RESET}'
echo "## ============================================================================== ##"
for i in /sys/module/ipv6/parameters/disable; do echo 1 > $i; done
for i in /sys/module/ipv6/parameters/disable_ipv6; do echo 1 > $i; done

sysctl -w net.link.ether.inet.max_age=1200

sysctl -w net.ipv4.conf.all.accept_redirects=0
sysctl -w net.ipv6.conf.all.accept_redirects=0
sysctl -w net.ipv4.conf.all.send_redirects=0
sysctl -w net.ipv6.conf.all.send_redirects=0
sysctl -w net.ipv4.conf.all.accept_source_route=0
sysctl -w net.ipv4.conf.all.forwarding=0
sysctl -w net.ipv4.conf.all.mc_forwarding=0

# echo 1 > /sys/module/acpi/parameters/aml_debug_output

echo -e '\t\t'{BLOODRED}'''{RESET}'
sysctl -w net.ipv4.tcp_max_syn_backlog=1280

echo "## ============================================================================== ##"
echo -e '\t\t'{BLOODRED}'Use TCP SYN Cookies (Linux and BSD only)''{RESET}'
TCP Syn Cookies, the kernel does not really allocate the TCP buffers unless the 
servers ACK/SYN packet gets an ACK back, meaning that it was a legitimate request.
sysctl -w net.ipv4.tcp_syncookies=1

echo -e '\t\t'{BLOODRED}'Reduce the amount of time a closing TCP circuit can stay in the TIME_WAIT state
sysctl -w net.ipv4.tcp_fin_timeout=5		
echo -e "\tHardening /proc/sys/kernel/kptr_restrict {Value: 2}"'{RESET}'
echo -e "\tkernel pointers printed using the %pK format specifier will be"
echo -e "\treplaced with zeros regardless of the user's  capabilities"
echo "## ============================================================================== ##"
for i in /proc/sys/kernel/kptr_restrict; do echo 2 > $i; done
echo
echo "## ============================================================================== ##"
echo -e '\t\t'{BLOODRED}'Hardening kernel syslog contents"'{RESET}'
echo "## ============================================================================== ##"
for i in /proc/sys/kernel/dmesg_restrict; do echo 1 > $i; done
echo
echo "## ============================================================================== ##"
echo -e "\t\t\tEnabling Kernel Stack Tracer"
echo "## ============================================================================== ##"
sysctl -w kernel.stack_tracer_enabled="1"
echo "## ============================================================================== ##"
echo -e "\t\t\tcdrom.check_media"
echo "## ============================================================================== ##"
sysctl -w dev.cdrom.check_media="1"
echo "## ============================================================================== ##"
echo -e "\t\t\tCDROM AutoEject..."
echo "## ============================================================================== ##"
sysctl -w dev.cdrom.autoeject="1"
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
# echo -e "\t\t[+] To free pagecache, use:"
# echo "## ============================================================================== ##"
# for i in /proc/sys/vm/drop_caches; do echo 1 > $i; done
# echo
# echo
# echo "## ============================================================================== ##"
# echo -e "\t\t[+] To free dentries and inodes, use:"
# echo "## ============================================================================== ##"
# for i in /proc/sys/vm/drop_caches; do echo 2 > $i; done
# echo
# echo
# echo "## ============================================================================== ##"
# echo -e "\t\t[+] To free pagecache, dentries and inodes, use:"
# echo "## ============================================================================== ##"
# for i in /proc/sys/vm/drop_caches; do echo 3 > $i; done
# echo
# echo
echo "## ============================================================================== ##"
echo -e "\t\t\t[+] Enabling bad error message Protection..."
echo "## ============================================================================== ##"
sysctl -w net.ipv4.icmp_ignore_bogus_error_responses=1
echo
echo "## ============================================================================== ##"
echo -e "\t[+] Enable IP spoofing protection (i.e. source address verification)"
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
        echo "WARNING: errors encountered while trying to enable IP spoofing protection!"
	fi
fi
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
echo -e "\t\t\t[+] Log packets with impossible addresses."
echo "## ============================================================================== ##"
for i in /proc/sys/net/ipv4/conf/*/log_martians; do echo 1 > $i; done
echo
echo
echo "## ============================================================================== ##"
echo -e "\t\t\t[+] Don't accept or send ICMP redirects."
echo "## ============================================================================== ##"
for i in /proc/sys/net/ipv4/conf/*/accept_redirects; do echo 0 > $i; done
for i in /proc/sys/net/ipv4/conf/*/send_redirects; do echo 0 > $i; done
echo
echo "## ============================================================================== ##"
echo -e "\t\t\t[+] Disabling IPv6..."
echo "## ============================================================================== ##"
echo 1 > /proc/sys/net/ipv6/conf/default/disable_ipv6
echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6
echo
echo

/proc/sys/net/ipv6/conf/default/use_tempaddr

/sbin/sysctl -a --pattern 'net.ipv(4|6).conf.*' >> ~/sysctlconf.txt


# echo "## ============================================================================== ##"
# echo -e "\t\t\t[+] Modifying Local Port Range..."
# echo "## ============================================================================== ##"
# cat /proc/sys/net/ipv4/ip_local_port_range
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
sysctl -w kern.securelevel="2"
sysctl -w kernel.kptr_restrict="1"
echo "## ============================================================================== ##"
echo -e "\t\t\t[+] Enable ExecShield protection"
echo "## ============================================================================== ##"
sysctl -w -q kernel.exec-shield="1"
set kernel.exec-shield="1"
echo "## ============================================================================== ##"
echo -e "\t\t\t[+] Enabling kernels use of pids"
echo "## ============================================================================== ##"
sysctl -q -w kernel.core_uses_pid="1"
sysctl -w kernel.randomize_va_space="2"
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
			echo "net.ipv4.tcp_syncookies=1" >> /etc/sysctl.conf
			echo "#lynis recommendations" >> /etc/sysctl.conf
			echo "#net.ipv6.conf.default.accept_redirects=0" >> /etc/sysctl.conf
			echo "net.ipv4.tcp_timestamps=0" >> /etc/sysctl.conf
			echo "net.ipv4.conf.default.log_martians=1" >> /etc/sysctl.conf
			echo "net.ipv4.icmp_echo_ignore_broadcasts=1" >> /etc/sysctl.conf
			echo "net.ipv4.conf.all.forwarding=0" >> /etc/sysctl.conf
			echo "net.ipv4.conf.all.rp_filter=1" >> /etc/sysctl.conf
			echo "net.ipv4.tcp_max_syn_backlog=1280" >> /etc/sysctl.conf
			echo "kernel.core_uses_pid=1" >> /etc/sysctl.conf   						# Controls whether core dumps will append the PID to the core filename
			echo "kernel.sysrq=0" >> /etc/sysctl.conf
			echo "kernel.randomize_va_space=2" >> /etc/sysctl.conf
			echo "kern.securelevel=1" >> /etc/sysctl.conf
			echo "" >> /etc/sysctl.conf
			echo "" >> /etc/sysctl.conf
			echo "" >> /etc/sysctl.conf
			echo "#ignore all ping" >> /etc/sysctl.conf
			echo "net.ipv4.icmp_echo_ignore_all=1" >> /etc/sysctl.conf
			echo "# Do not send ICMP redirects (we are not a router)" >> /etc/sysctl.conf
			echo "net.ipv4.conf.all.send_redirects = 0" >> /etc/sysctl.conf
			echo "# Do not accept IP source route packets (we are not a router)" >> /etc/sysctl.conf
			echo "net.ipv4.conf.all.accept_source_route = 0" >> /etc/sysctl.conf
			echo "net.ipv6.conf.all.accept_source_route = 0" >> /etc/sysctl.conf
			echo "# Log Martian Packets" >> /etc/sysctl.conf
			echo "net.ipv4.conf.all.log_martians = 1" >> /etc/sysctl.conf
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
echo
echo -e "## ============================================================================== ##"
echo -e "\t[+] flush existing rules and set chain policy setting to DROP..."
echo -e "## ============================================================================== ##"
echo
echo
echo "## ============================================================================== ##"
echo -e "\t\t\t[+] Flushing existing iptables rules..."
echo "## ============================================================================== ##"
## 
## ======================================================================================== ##
$IPTABLES -F
$IPTABLES -F -t nat
$IPTABLES -F -t mangle
$IPTABLES -t nat -X
$IPTABLES -t mangle -X
$IPTABLES -X
$IPTABLES -P INPUT DROP
$IPTABLES -P OUTPUT DROP
$IPTABLES -P FORWARD DROP
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
$IPTABLES -A INPUT -i $LOOPBACK -j ACCEPT
$IPTABLES -A OUTPUT -o $LOOPBACK -j ACCEPT
## ======================================================================================== ##
## 
echo "[+]=====================================================================[+]"
echo -e "\t\t [+] Blocking All Traffic on The Loopback Interface..."
echo "[+]=====================================================================[+]"
## 
## ======================================================================================== ##
$IP6TABLES -A INPUT -i $LOOPBACK -j DENY
$IP6TABLES -A OUTPUT -o $LOOPBACK -j DENY
## ======================================================================================== ##
## 
echo "[+]=====================================================================[+]"
echo -e "\t\t Establish Your Custom Logging Prefixes:"
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


$IPTABLES -N LOG_REJECT		# Define custom chains

## ======================================================================================== ##
## 
echo "## ============================================================================== ##"
echo -e "\t\t[+] Pass traffic with bad flags to the Bad Flags Chain"
echo "## ============================================================================== ##"
## 
## ======================================================================================== ##
$IPTABLES -A INPUT -p tcp -j LOG_DROP
$IPTABLES -A INPUT -p tcp -j LOG_REJECT
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
echo "## ============================================================================== ##"
echo -e "\t\t\t[+] DROP INVALID Packets"
echo "## ============================================================================== ##"
##
## ======================================================================================== ##
$IPTABLES -A INPUT -m state --state INVALID -j DROP
## ======================================================================================== ##
## 
echo "## ============================================================================== ##"
echo -e "\t\t[+] Dropping Incoming Malformed XMAS Packets..."
echo "## ============================================================================== ##"
##
## ======================================================================================== ##
$IPTABLES -A INPUT -p tcp --tcp-flags ALL ALL -j DROP
## ======================================================================================== ##
## 
echo
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
# $IPTABLES -A INPUT -i $IFACE ! -s $CLASS_C -j LOG --log-prefix "SPOOFED PKT "
# $IPTABLES -A INPUT -i $IFACE ! -s $CLASS_C -j DROP
echo
echo
echo "###################################################################################"
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
## 
## ======================================================================================== ##
$IPTABLES -A INPUT -p icmp -m icmp --icmp-type 3 -j ACCEPT
$IPTABLES -A INPUT -p icmp -m icmp --icmp-type 4 -j ACCEPT
$IPTABLES -A INPUT -p icmp -m icmp --icmp-type 11 -j ACCEPT

# $IPTABLES -A INPUT  -p icmp --icmp-type destination-unreachable -m state --state ESTABLISHED,RELATED -j ACCEPT
# $IPTABLES -A INPUT  -p icmp --icmp-type time-exceeded           -m state --state ESTABLISHED,RELATED -j ACCEPT
# $IPTABLES -A INPUT  -p icmp --icmp-type source-quench           -m state --state ESTABLISHED,RELATED -j ACCEPT
# $IPTABLES -A INPUT  -p icmp --icmp-type parameter-problem       -m state --state ESTABLISHED,RELATED -j ACCEPT


# Allow rate-limited incoming unicast ICMP ping, and related echo reply
# $IPTABLES -A INPUT  -p icmp --icmp-type echo-request -m addrtype --dst-type LOCAL -m limit --limit 20/minute -j ACCEPT
# $IPTABLES -A OUTPUT -p icmp --icmp-type echo-reply   -m state --state ESTABLISHED,RELATED -j ACCEPT


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


echo "[+]=====================================================================[+]"
echo -e "\t\t\t[+] Setting up OUTPUT chain..."
echo "[+]=====================================================================[+]"
echo
echo "[+]=====================================================================[+]"
echo -e "\t\t\t[+] Killing INVALID OUTPUT Packets..."
echo "[+]=====================================================================[+]"
$IPTABLES -A OUTPUT -m conntrack --ctstate INVALID -j REJECT --reject-with icmp-admin-prohibited
$IPTABLES -A OUTPUT -m state --state INVALID -j REJECT --reject-with icmp-admin-prohibited


echo "[+]=====================================================================[+]"
echo -e "\t\t\t[+] default OUTPUT LOG rule"
echo "[+]=====================================================================[+]"


$IPTABLES -A OUTPUT -m state --state INVALID -j LOG --log-prefix "DROP INVALID " --log-ip-options --log-tcp-options
$IPTABLES -A OUTPUT -m state --state INVALID -j DROP
$IPTABLES -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
$IPTABLES -A OUTPUT -o ! lo -j LOG --log-prefix "DROP " --log-ip-options --log-tcp-options

#$IPTABLES  -A OUTPUT ! -o lo ! -d 127.0.0.1 ! -s 127.0.0.1 -p tcp -m tcp --tcp-flags ACK,FIN ACK,FIN -j REJECT --reject-with icmp-admin-prohibited
#$IPTABLES -A OUTPUT ! -o lo ! -d 127.0.0.1 ! -s 127.0.0.1 -p tcp -m tcp --tcp-flags ACK,RST ACK,RST -j REJECT --reject-with icmp-admin-prohibited
## ======================================================================================== ##
## 
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
-A INPUT -j REJECT --reject-with icmp-host-prohibited
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
# echo
# echo
# echo "## ================================================================= ##"
# echo -e "\tSilently dropping all the broadcasted packets..."
# echo "## ================================================================= ##"
# echo "## -------------------------------------------------------------------------------------------- ##"
# echo "DROP       all  --  anywhere             anywhere           PKTTYPE = broadcast"
# echo "## -------------------------------------------------------------------------------------------- ##
# iptables -A INPUT -m pkttype --pkt-type broadcast -j DROP			# --> to all Broadcast Packets
echo
echo

echo "[+]=====================================================================[+]"
echo -e "\t\t\t[+] Setting up FORWARD chain..."
echo "[+]=====================================================================[+]"

echo "[+]=====================================================================[+]"
echo -e "\t\t\t[+] Establishing state tracking rules..."
echo "[+]=====================================================================[+]"
$IPTABLES -A FORWARD -m state --state INVALID -j LOG --log-prefix "DROP INVALID " --log-ip-options --log-tcp-options
$IPTABLES -A FORWARD -m state --state INVALID -j DROP
$IPTABLES -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT


$IPTABLES -A FORWARD -p tcp -i wlan0 -s $INT_NET --dport 21 --syn -m state --state NEW -j ACCEPT
# $IPTABLES -A FORWARD -p tcp -i wlan0 -s $INT_NET --dport 22 --syn -m state --state NEW -j ACCEPT
$IPTABLES -A FORWARD -p tcp -i wlan0 -s $INT_NET --dport 25 --syn -m state --state NEW -j ACCEPT

# DNAT port 80 request comming from LAN systems to squid 3128 ($SQUID_PORT) aka transparent proxy
$IPTABLES ­-t nat ­-A PREROUTING ­-i $LAN_IN ­-p tcp ­­--­­dport 80 -­j DNAT ­­to $SQUID_SERVER:$SQUID_PORT
## Send incoming port-80 web traffic to our squid (transparent) proxy

$IPTABLES -t nat -A PREROUTING -i eth1 -p tcp --dport 80 -j REDIRECT --to-port 3128

## Change source addresses to 1.2.3.4, 1.2.3.5 or 1.2.3.6

$IPTABLES -t nat -A POSTROUTING -o wlan0 -j SNAT --to 192.168.0.7-192.168.0.25
$IPTABLES -t nat -A POSTROUTING -o wlan0 -j SNAT --to 
-A FORWARD -j REJECT --reject-with icmp-host-prohibited
$IPTABLES ­-t nat ­-A PREROUTING ­-i $INTERNET ­-p tcp --­­dport 80 ­-j REDIRECT --­­to­port $SQUID_PORT

$IPTABLES -A FORWARD -p tcp -i wlan0 -s $INT_NET --dport  --syn -m state --state NEW -j ACCEPT
$IPTABLES -A FORWARD -p tcp -i wlan0 -s $INT_NET --dport  --syn -m state --state NEW -j ACCEPT
$IPTABLES -A FORWARD -p tcp -i wlan0 -s $INT_NET --dport  --syn -m state --state NEW -j ACCEPT
$IPTABLES -A FORWARD -p tcp -i wlan0 -s $INT_NET --dport  --syn -m state --state NEW -j ACCEPT

### default log rule
$IPTABLES -A FORWARD -i ! lo -j LOG --log-prefix "DROP " --log-ip-options --log-tcp-options

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
echo
echo
echo "## ============================================================================== ##"
echo -e "\t\t\t[+] Preventing SYN Flooding..."
echo "## ============================================================================== ##"
$IPTABLES -A INPUT -i wlan0 -p tcp --syn -m limit --limit 5/second -j ACCEPT
## ======================================================================================== ##
## 
echo
echo "## ============================================================================== ##"
echo -e "\t\t\t[+] Log and Drop Traffic in the INVALID state..."
echo "## ============================================================================== ##"
$IPTABLES -A INPUT -m state --state INVALID -j LOG --log-prefix "INVALID: " --log-ip-options --log-tcp-options
$IPTABLES -A INPUT -m state --state INVALID -j DROP
## ======================================================================================== ##

echo "## ============================================================================== ##"
echo -e "\t\t\t[+] Applying Default INPUT LOG rule..."
echo "## ============================================================================== ##"
$IPTABLES -A INPUT -i ! lo -j LOG --log-prefix "DROP " --log-ip-options --log-tcp-options
## ======================================================================================== ##
## 
echo
echo "## ============================================================================== ##"
echo -e "\t\t[+] Accepting INPUT TCP/UDP 53, TCP 80, and TCP 443..."
echo "## ============================================================================== ##"
## ======================================================================================== ##
echo -e "\t\t [+] Accepting INPUT SMTP clients {Port 25}..."
$IPTABLES -A INPUT -p tcp --dport 25 -j ACCEPT				# STMP Port
## ======================================================================================== ##
$IPTABLES -A INPUT -p udp --destination-port 514 -j LOG --log-prefix "SMTP client Attempt"
## ======================================================================================== ##
echo -e "\t\t [+] Accepting INPUT TCP DNS {Port 53}..."
$IPTABLES -A INPUT -p tcp --dport 53 -j ACCEPT				# TCP DNS Port
echo -e "\t\t [+] Accepting INPUT UDP DNS {Port 53}..."
$IPTABLES -A INPUT -p udp --dport 53 -j ACCEPT				# UDP DNS Port
## ======================================================================================== ##
echo -e "\t\t [+] Accepting INPUT TCP HTTP {Port 80}..."
$IPTABLES -A INPUT -p tcp --dport 80 -j ACCEPT				# HTTP Port
echo -e "\t\t [+] Accepting INPUT TCP HTTPS {Port 443}..."
$IPTABLES -A INPUT -p tcp --dport 443 -j ACCEPT				# HTTPS Port
## ======================================================================================== ##
echo -e "\t\t [+] Accepting INPUT SYSLOG client {Port 514}..."
$IPTABLES -A OUTPUT -o $IFACE -p udp -s $IPADDR --source-port 514 -d $SYSLOG_SERVER --destination-port $UNPRIVPORTS -j ACCEPT
$IPTABLES -A INPUT -p udp --destination-port 514 -j LOG --log-prefix "SYSLOG client Attempt"
## ======================================================================================== ##
echo -e "\t\t [+] Accepting INPUT IRC client {Port 6667}..."
$IPTABLES -A INPUT -p tcp --dport 6667 -j ACCEPT			# IRC Port
$IPTABLES -A INPUT -p tcp --destination-port 6667 -j LOG --log-prefix "SSL IRC Attempt"
echo -e "\t\t [+] Accepting INPUT SSL IRC client {Port 6669}..."
$IPTABLES -A INPUT -p tcp --dport 6669 -j ACCEPT			# IRC Port
$IPTABLES -A INPUT -p tcp --destination-port 6669 -j LOG --log-prefix "SSL IRC Attempt"
## ======================================================================================== ##
# $IPTABLES -A INPUT -p tcp --dport 51413 -j ACCEPT			# Torrent Port
## ======================================================================================== ##
echo
echo
echo "## ============================================================================== ##"
echo -e "\t[+] Accepting OUTPUT SSH (22) DNS (53), HTTP (80), and HTTPS (443)..."
echo "## ============================================================================== ##"
##
## ======================================================================================== ##
$IPTABLES -A OUTPUT -p tcp --dport 22 -j ACCEPT					# SSH Port
## ======================================================================================== ##
echo -e "\t\t [+] Accepting OUTPUT SMTP clients {Port 25}..."
$IPTABLES -A OUTPUT -p tcp --dport 25 -j ACCEPT					# STMP Port
## ======================================================================================== ##
echo -e "\t\t [+] Accepting INPUT TCP DNS {Port 53}..."
$IPTABLES -A OUTPUT -p tcp --dport 53 -j ACCEPT					# TCP DNS Port
echo -e "\t\t [+] Accepting INPUT UDP DNS {Port 53}..."
$IPTABLES -A OUTPUT -p udp --dport 53 -j ACCEPT					# UDP DNS Port
## ======================================================================================== ##
echo -e "\t\t [+] Accepting INPUT TCP HTTP {Port 80}..."
$IPTABLES -A OUTPUT -p tcp --dport 80 -j ACCEPT					# HTTP Port
echo -e "\t\t [+] Accepting INPUT TCP HTTPS {Port 443}..."
$IPTABLES -A OUTPUT -p tcp --dport 443 -j ACCEPT				# HTTPS Port
## ======================================================================================== ##
$IPTABLES -A OUTPUT -p tcp --dport 6667 -j ACCEPT				# IRC Port
$IPTABLES -A OUTPUT -p tcp --dport 6669 -j ACCEPT			# IRC Port
$IPTABLES -A OUTPUT -p tcp --destination-port 6669 -j LOG --log-prefix "SSL IRC Attempt"




echo "## ================================================================= ##"
echo -e "\t\t [+] Setting I2P Environment Variables..."
echo "## ================================================================= ##"




echo "## ================================================================= ##"
echo -e "\t\t [+] Setting Tor Environment Variables..."
echo "## ================================================================= ##"
## 
## ==================================================================================== ##
TorifiedDNSSocket="5353"
export TorifiedDNSSocket="5353"
## ==================================================================== ##
TailsSpecificSocksPort="9062"
export TailsSpecificSocksPort="9062"				## IsolateDestAddr IsolateDestPort
## ==================================================================== ##
TOR_CONTROL_PORT="9051"
export TOR_CONTROL_PORT="9051"
## ==================================================================== ##
TOR_DNS_PORT="5353"
export TOR_DNS_PORT="5353"
## ==================================================================== ##
TOR_TRANS_PORT="9040"
export TOR_TRANS_PORT="9040"
## ==================================================================== ##
TRANSPROXY_USER="anon"
export TRANSPROXY_USER="anon"
## ==================================================================================== ##
## 
echo "## ================================================================= ##"
echo -e "\t\t [+] Setting SOCKS5 Environment Variables..."
echo "## ================================================================= ##"
##
## 
## ==================================================================================== ##

# ReachableAddresses ports in /etc/tor/torrc [uid=tor]
# (allow high ports in order to support most bridges)
torports=80,443,1024:65535

# VPN TCP/UDP server ports (PPTP, OpenVPN, Cisco) [uid=root]
vpntports=https,imaps,1723,openvpn,10000
vpnuports=openvpn,1149,isakmp,ipsec-nat-t,10000


TorSOCKS4a="1080"
TorSOCKS5="9050"							## IsolateDestAddr IsolateDestPort
CONTROL_PORT_FILTER_PROXY_PORT="9052"
TorMUASocksPort="9061"				##IsolateDestAddr
TorBrowserSocksPort="9150"
SOCKS_PORT_IRC="9101"
SOCKS_PORT_TORBIRDY="9102"
SOCKS_PORT_APT_GET="9104"
SOCKS_PORT_TOR_DEFAULT="9050"
SOCKS_PORT_IM="9103"
SOCKS_PORT_APT_GET="9104"
SOCKS_PORT_GPG="9105"
SOCKS_PORT_SSH="9106"
SOCKS_PORT_GIT="9107"
SOCKS_PORT_SDWDATE="9108"
SOCKS_PORT_WGET="9109"
SOCKS_PORT_WHONIXCHECK="9110"
SOCKS_PORT_BITCOIN="9111"
SOCKS_PORT_PRIVOXY="9112"
SOCKS_PORT_POLIPO="9113"
SOCKS_PORT_WHONIX_NEWS="9114"
SOCKS_PORT_TBB_DOWNLOAD="9115"
SOCKS_PORT_TBB_GPG="9116"
SOCKS_PORT_CURL="9117"
SOCKS_PORT_RSS="9118"
SOCKS_PORT_TORCHAT="9119"
SOCKS_PORT_MIXMASTERUPDATE="9120"
SOCKS_PORT_MIXMASTER="9121"
SOCKS_PORT_KDE="9122"
SOCKS_PORT_GNOME="9123"
SOCKS_PORT_APTITUDE="9124"
SOCKS_PORT_YUM="9125"
SOCKS_PORT_TBB_DEFAULT="9150"
## ==================================================================================== ##
export TorSOCKS4a="1080"
export TorSOCKS5="9050"							## IsolateDestAddr IsolateDestPort
export CONTROL_PORT_FILTER_PROXY_PORT="9052"
export TorMUASocksPort="9061"					## IsolateDestAddr
export TorBrowserSocksPort="9150"
export SOCKS_PORT_IRC="9101"
export SOCKS_PORT_TORBIRDY="9102"
export SOCKS_PORT_APT_GET="9104"
export SOCKS_PORT_TOR_DEFAULT="9050"
export SOCKS_PORT_IM="9103"
export SOCKS_PORT_APT_GET="9104"
export SOCKS_PORT_GPG="9105"
export SOCKS_PORT_SSH="9106"
export SOCKS_PORT_GIT="9107"
export SOCKS_PORT_SDWDATE="9108"
export SOCKS_PORT_WGET="9109"
export SOCKS_PORT_WHONIXCHECK="9110"
export SOCKS_PORT_BITCOIN="9111"
export SOCKS_PORT_PRIVOXY="9112"
export SOCKS_PORT_POLIPO="9113"
export SOCKS_PORT_WHONIX_NEWS="9114"
export SOCKS_PORT_TBB_DOWNLOAD="9115"
export SOCKS_PORT_TBB_GPG="9116"
export SOCKS_PORT_CURL="9117"
export SOCKS_PORT_RSS="9118"
export SOCKS_PORT_TORCHAT="9119"
export SOCKS_PORT_MIXMASTERUPDATE="9120"
export SOCKS_PORT_MIXMASTER="9121"
export SOCKS_PORT_KDE="9122"
export SOCKS_PORT_GNOME="9123"
export SOCKS_PORT_APTITUDE="9124"
export SOCKS_PORT_YUM="9125"
export SOCKS_PORT_TBB_DEFAULT="9150"
## ==================================================================================== ##
## 


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
iptables -A OUTPUT -o lo -p tcp -m owner --uid-owner ${luser} --syn -d 127.0.0.1 --dport 9050 -j ACCEPT
iptables -A OUTPUT -o lo -p tcp -m owner --uid-owner privoxy  --syn -d 127.0.0.1 --dport 9050 -j ACCEPT
echo -e "\t\tAllowing OUTBOUND TorBrowserSocksPort For The User ${TorUser}"

iptables -A OUTPUT -o lo -p tcp -m owner --uid-owner ${luser} --syn -d 127.0.0.1 --dport 9150 -j ACCEPT				
export TorBrowserSocksPort="9150"
iptables -A OUTPUT       -p tcp                               --syn -d 127.0.0.1 --dport 9050 -j LOGREJECT

# Tor control port access only for Tor user
iptables -A OUTPUT -o lo -p tcp -m owner --uid-owner tor      --syn -d 127.0.0.1 --dport 9051 -j ACCEPT
iptables -A OUTPUT       -p tcp                               --syn -d 127.0.0.1 --dport 9051 -j LOGREJECT


RDP
3389/tcp

Transparent Proxy
8081

VNC
5900/tcp


VNC http server display :0
5800/tcp


Windows Messenger Assistance
3389/tcp

Dropbox 	
http|https|17500

Dropbox LanSync
17500


MySQL
3306/tcp


SAMBA
137,138/udp|139,445/tcp

UPnP
1900/udp|5431|49152|80

NFS
2049,111/tcp|2049,111/udp

rsync daemon
873/tcp

GNUnet
1080,2086


UPnP
1900/udp|5431|49152|80

IMAPS
993/tcp

Postfix Mail Server SMTPS
465/tcp

syslog-tls	6514/tcp			# Syslog over TLS [RFC5425]
hkp		11371/tcp			# OpenPGP HTTP Keyserver
hkp		11371/udp
mysql-proxy	6446/tcp			# MySQL Proxy
mysql-proxy	6446/udp
gnutella-svc	6346/tcp			# gnutella
gnutella-svc	6346/udp
gnutella-rtr	6347/tcp			# gnutella
gnutella-rtr	6347/udp
aol		5190/tcp			# AIM
aol		5190/udp
xmpp-client	5222/tcp	jabber-client	# Jabber Client Connection
xmpp-client	5222/udp	jabber-client
xmpp-server	5269/tcp	jabber-server	# Jabber Server Connection
xmpp-server	5269/udp	jabber-server
cfengine	5308/tcp
cfengine	5308/udp
mdns		5353/tcp			# Multicast DNS
mdns		5353/udp
postgresql	5432/tcp	postgres	# PostgreSQL Database
postgresql	5432/udp	postgres
ipsec-nat-t	4500/udp			# IPsec NAT-Traversal [RFC3947]
svn		3690/tcp	subversion	# Subversion protocol
svn		3690/udp	subversion
mysql		3306/tcp
mysql		3306/udp
nfs		2049/tcp			# Network File System
nfs		2049/udp			# Network File System
gnunet		2086/tcp
gnunet		2086/udp
socks		1080/tcp			# socks proxy server
socks		1080/udp
rsync		873/tcp
rsync		873/udp
ftps-data	989/tcp				# FTP over SSL (data)
ftps		990/tcp
telnets		992/tcp				# Telnet over SSL
telnets		992/udp
imaps		993/tcp				# IMAP over SSL
imaps		993/udp
ircs		994/tcp				# IRC over SSL
ircs		994/udp
pop3s		995/tcp				# POP-3 over SSL
pop3s		995/udp
dhcpv6-client	546/tcp
dhcpv6-client	546/udp
dhcpv6-server	547/tcp
dhcpv6-server	547/udp
submission	587/tcp				# Submission [RFC4409]
submission	587/udp
ldaps		636/tcp				# LDAP over SSL
ldaps		636/udp
openvpn		1194/tcp
openvpn		1194/udp
nessus		1241/tcp			# Nessus vulnerability
nessus		1241/udp			#  assessment scanner
microsoft-ds	445/tcp				# Microsoft Naked CIFS
microsoft-ds	445/udp
ldap		389/tcp			# Lightweight Directory Access Protocol
ldap		389/udp
imap3		220/tcp				# Interactive Mail Access
imap3		220/udp				# Protocol v3
irc		194/tcp				# Internet Relay Chat
irc		194/udp
netbios-ns	137/tcp				# NETBIOS Name Service
netbios-ns	137/udp
netbios-dgm	138/tcp				# NETBIOS Datagram Service
netbios-dgm	138/udp
netbios-ssn	139/tcp				# NETBIOS session service
netbios-ssn	139/udp
imap2		143/tcp		imap		# Interim Mail Access P 2 and 4
imap2		143/udp		imap
snmp		161/tcp				# Simple Net Mgmt Protocol
snmp		161/udp
pop2		109/tcp		postoffice pop-2 # POP version 2
pop2		109/udp		pop-2
pop3		110/tcp		pop-3		# POP version 3
pop3		110/udp		pop-3
sunrpc		111/tcp		portmapper	# RPC 4.0 portmapper
sunrpc		111/udp		portmapper
auth		113/tcp		authentication tap ident
sftp		115/tcp
uucp-path	117/tcp
nntp		119/tcp		readnews untp	# USENET News Transfer Protocol
ntp		123/tcp
ntp		123/udp				# Network Time Protocol
bootps		67/tcp				# BOOTP server
bootps		67/udp
bootpc		68/tcp				# BOOTP client
bootpc		68/udp
tftp		69/udp
ftp-data	20/tcp
ftp		21/tcp
echo		7/tcp
echo		7/udp
discard		9/tcp		sink null
discard		9/udp		sink null
systat		11/tcp		users
daytime		13/tcp
daytime		13/udp
netstat		15/tcp
ORACLE_PORTS 1024
finger		79/tcp
kerberos	88/tcp		kerberos5 krb5 kerberos-sec	# Kerberos v5
kerberos	88/udp		kerberos5 krb5 kerberos-sec	# Kerberos v5

ms-sql-s	1433/tcp			# Microsoft SQL Server
ms-sql-s	1433/udp
ms-sql-m	1434/tcp			# Microsoft SQL Monitor
ms-sql-m	1434/udp
ipv6-icmp 58	IPv6-ICMP	# ICMP for IPv6
ipv6-nonxt 59	IPv6-NoNxt	# No Next Header for IPv6
ipv6-opts 60	IPv6-Opts	# Destination Options for IPv6
igmp	2	IGMP		# Internet Group Management
ipv6	41	IPv6		# Internet Protocol, version 6
ipv6-route 43	IPv6-Route	# Routing Header for IPv6
ipv6-frag 44	IPv6-Frag	# Fragment Header for IPv6
hopopt	0	HOPOPT		# IPv6 Hop-by-Hop Option [RFC1883]
icmp	1	ICMP		# internet control message protocol
igmp	2	IGMP		# Internet Group Management

## ======================================================================================== ##
# $IPTABLES -A OUTPUT -p tcp --dport 51413 -j ACCEPT			# Torrent Port
## ======================================================================================== ##
echo

###### forwarding ######
echo "[+] Enabling IP forwarding..."
echo 1 > /proc/sys/net/ipv4/ip_forward
echo
echo "## ============================================================================== ##"
echo -e "\t\t\t[+] Invoking INPUT State Table..."
echo "## ============================================================================== ##"
## 
## ======================================================================================== ##
$IPTABLES -A INPUT -m state  --state RELATED,ESTABLISHED -j ACCEPT
$IPTABLES -A INPUT -j DROP
## ======================================================================================== ##
## 
echo
echo "## ============================================================================== ##"
echo -e "\t\t\t[+] Invoking OUTPUT State Table..."
echo "## ============================================================================== ##"
## 
## ======================================================================================== ##
$IPTABLES -A OUTPUT -m state  --state RELATED,ESTABLISHED -j ACCEPT
$IPTABLES -A OUTPUT -j DROP
## ======================================================================================== ##
## 

echo -n "Are You Currently Running Qubes or Tails?"
read AnonOS

# Check for no response
if [ -z $domain ]; then
     echo
     echo "You did not enter a domain."
     exit
fi

echo
echo "Starting recon on $domain."
echo
read -p "Press <enter> to continue."



echo
echo
echo "## ============================================================================== ##"
echo -e "\t\t\t\t[+] QubesOS IPTables:"
echo "## ============================================================================== ##"
if [ uname -n = qubes ]; then
	if [ "$qubes_vm_type" = "NetVM" ] || [ "$qubes_vm_type" = "ProxyVM" ]; then
		echo "## ============================================================================== ##"
		echo -e "\t\t Allow connections from port 8082 of internal vif interface for tinyproxy"
		echo -e "\t\t tinyproxy is responsible to handle TemplateVMs updates."
		echo "## ============================================================================== ##"
		$IPTABLES -A INPUT -i "$INT_IF" -p tcp -m tcp --dport 8082 -j ACCEPT
		$IPTABLES -A OUTPUT -o "$INT_IF" -p tcp -m tcp --sport 8082 -j ACCEPT
		echo "## ============================================================================== ##"
		echo -e "\t\tQubes pre-routing. Will be able to intercept traffic "
		echo -e "\t\tdestined for 10.137.255.254 to be re-routed to tinyproxy."
		echo "## ============================================================================== ##"
		## 
		## ======================================================================================== ##
		$IPTABLES -t nat -N PR-QBS-SERVICES
		$IPTABLES -t nat -A PREROUTING -j PR-QBS-SERVICES
		## ======================================================================================== ##
		## 
		echo "## ============================================================================== ##"
		echo -e "\t\tRedirects traffic destined for 10.137.255.154 to port 8082 (tinyproxy)."
		echo "## ============================================================================== ##"
		## 
		## ======================================================================================== ##
		$IPTABLES -t nat -A PR-QBS-SERVICES -d 10.137.255.254/32 -i "$INT_IF" -p tcp -m tcp --dport 8082 -j REDIRECT
		echo "## ============================================================================== ##"
		echo -e "\t\tForward tinyproxy output to port 5300/9040 on internal (Tor) interface (eth1) to be"
		echo -e "\t\table to connect to Internet (via Tor) to proxy updates for TemplateVM."
		echo "## ============================================================================== ##"
		## 
		## ======================================================================================== ##
		$IPTABLES -t nat -A OUTPUT -p udp -m owner --uid-owner tinyproxy -m conntrack --ctstate NEW -j DNAT --to "127.0.0.1:${DNS_PORT_GATEWAY}"
		$IPTABLES -t nat -A OUTPUT -p tcp -m owner --uid-owner tinyproxy -m conntrack --ctstate NEW -j DNAT --to "127.0.0.1:${TRANS_PORT_GATEWAY}"
else
		echo "## ============================================================================== ##"
		echo -e "\t\tCurrent Running Machine Isn't QubesOS, Skipping"
		echo "## ============================================================================== ##"
	fi
fi

		elif [ "$qubes_vm_type" = "TemplateVM" ]; then
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

## echo "## ============================================================================== ##"
## echo -e "\t [+] Attach a u32 filter to the ingress qdisc matching ICMP replies"
## echo -e "\t [+] and using the xt action to make the kernel yell 'PONG' each time"
## echo "## ============================================================================== ##"
## 
## tc qdisc add dev eth0 ingress
## tc filter add dev eth0 parent ffff: proto ip u32 \
## 	match ip protocol 1 0xff \
## 	match ip icmp_type 0 0xff 
## 	action xt -j LOG --log-prefix PONG
## 
## 
echo "## ============================================================================== ##"
iwconfig eth0 nickname "Rape-Tyme!"
iwconfig wlan0 nickname "moar bass than space"
echo "## ============================================================================== ##"
echo -e "\t\tSetting The Tansmitting Power In dBm:"
echo "## ============================================================================== ##"
## 
## ======================================================================================== ##
iw reg set US
iwconfig wlan1 txpower 25
iwconfig wlan0 txpower 20
echo "##################################################################"
echo "\tWARNING Anonymity Holes in 802.11 drivers and default, hidden,"
echo "\tDisable the Network ID checking (NWID promiscuous) with off..."
echo "\t\tAuto De-Anon Structured Packets..."
echo "###########################################"
echo " Hacking To correct this issue..."
echo "########################################"
iwconfig eth0 nwid off
## ======================================================================================== ##

echo
echo "## ============================================================================== ##"
echo -e "\t\tSpoofing Wlan1 Interface"
echo "## ============================================================================== ##"
## 
## ======================================================================================== ##
ifconfig wlan1 hw ether 00:30:65:35:2e:37
ip link set dev wlan1 address 00:30:65:35:2e:37
## ======================================================================================== ##
## 
echo
echo "## ============================================================================== ##"
echo -e "\t\tSpoofing Wlan1 Interface"
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
echo "## ============================================================================== ##"
echo -e "\t\tSpoofing Wlan1 Interface"
echo "## ============================================================================== ##"
## 
## ======================================================================================== ##
if [ -d /sys/class/net/wlan2/ ]; then
	ifconfig wlan1 hw ether 00:30:65:35:2e:37
	ip link set dev wlan1 address 00:30:65:35:2e:37
		else
	echo -e "\t\t Wlan1 Doesnt Exist..."
fi
## ======================================================================================== ##
## 
echo
echo "## ============================================================================== ##"
echo -e "\t\tStarting Metworking Services Again"
echo "## ============================================================================== ##"
service networking start
service NetworkManager start
## ======================================================================================== ##
## 


systemctl --all list-unit-files | grep stunnel4
systemctl --all list-unit-files | grep postgresql
systemctl --all list-unit-files | grep 
systemctl --all list-unit-files | grep 
systemctl --all list-unit-files | grep 
systemctl list-dependencies

systemd-journald-dev-log.socket
systemd-journald.service
systemd-journald-audit.socket
systemd-journald-dev-log.socket
systemd-journald.socket
systemd-sysctl.service
/lib/systemd/systemd-journald

redis-server
redsocks
rsync
rsyslog
samba
samba-ad-dc
smbd
ssh
apache-htcacheclean
apache2
arpwatch
bluetooth
clamav-daemon
clamav-freshclam
mysql
network-manager
networking
nmbd
ntp
openvpn
paxctld
polipo
postfix
i2p
tor
samba


import-environment
dbus-daemon --session


import-environment

systemd-resolve


mate-services-admin (1) - Services Administration Tool
mate-services-admin-pkexec (1) - Services Administration Tool


systemctl --all list-unit-files is-enabled
| grep ssh
--show-types
--show-types, --all, and --state=
systemctl status

systemctl set-property foobar.service CPUShares=777
 --all
systemctl show --all

--list-timers
ssh.service
ssh@.service
sshd.service
ssh.socket
systemctl --all list-unit-files | grep daemon


systemctl --all list-unit-files | grep manager
systemctl list-units | grep
systemctl list-sockets | grep
systemctl list-timers | grep

systemctl show-environment                        # Dump environment


syslog-ng.service(dead) (aliases: syslog.service)
nfs-common.service


ufw.service(exited)
systemd-tmpfiles-setup.service(exited)
systemd-update-utmp.service
sys-subsystem-net-devices-eth0.device
sys-subsystem-net-devices-wlan0.device
list-jobs

enabled-runtime
linked-runtime

systemctl set-property foobar.service 

journalctl --unit=

journalctl --user-unit=

systemctl stop sshd@*.service



echo
echo
echo "## ============================================================================== ##"
echo -e "\t\t\tKilling Networking Interface..."
echo "## ============================================================================== ##"
## 
## ======================================================================================== ##
echo " Killing lo... "
ifconfig $LOOPBACK up
echo " Killing eth0... "
ifconfig $ETHER up
echo "Starting Wlan0... "
ifconfig $IFACE up
## ======================================================================================== ##
## 

if [ $(nm-tool|grep State|cut -f2 -d' ') == "connected" ]; then
	echo "Whatever you want to do if the network is online"
else
	echo "Whatever you want to do if the network is offline - note, this and the else above are optional"
fi


echo
echo "## ============================================================================== ##"
echo -e "\t\t\tList of Access Points in range:"
echo "## ============================================================================== ##"
iwlist wlan0 accesspoint
echo "## ============================================================================== ##"
echo -e "\t\twireless event capability information:"
echo "## ============================================================================== ##"
iwlist wlan0 event
echo "## ============================================================================== ##"
echo -e "\t\tList the various Power Management attributes and modes of the device:"
echo "## ============================================================================== ##"
iwlist wlan0 power
echo "## ============================================================================== ##"
echo -e "\t\tList the various Transmit Powers available on the device:"
echo "## ============================================================================== ##"
iwlist wlan0 txpower
echo "## ============================================================================== ##"
echo -e "\t\tList the modulations supported by the device and the modulations currently enabled:"
echo "## ============================================================================== ##"
iwlist wlan0 modu
echo "## ============================================================================== ##"
echo -e "\t\tList the transmit retry limits and retry lifetime on the device:"
echo "## ============================================================================== ##"
iwlist wlan0 retry
echo "## ============================================================================== ##"
echo -e "\t\tList the Generic Information Elements set in the device (used for WPA support):"
echo "## ============================================================================== ##"
iwlist wlan0 genie
echo "## ============================================================================== ##"
echo -e "\t\tList the modulations supported by the device and the modulations currently enabled:"
echo "## ============================================================================== ##"
iwlist wlan0 modu
echo "## ============================================================================== ##"
echo -e "\t\tList the bit-rates supported by the device:"
echo "## ============================================================================== ##"
iw dev info
echo "####################################################"
echo "Disable The Network ID Checking (NWID promiscuous)"
echo "####################################################"
iwconfig eth0 nwid off
echo "## ============================================================================== ##"
echo -e "\t\tShowing Classes As ASCII Graph With Stats Info Under Each Class...
echo "## ============================================================================== ##"
tc -g -s class show dev wlan0
## ======================================================================================== ##
## 
echo "## ============================================================================== ##"
echo -e "\t\t"
echo "## ============================================================================== ##"
echo
echo "## ============================================================================== ##"
echo -e "\t\t"
echo "## ============================================================================== ##"
echo -e "\t\t\tShowing Networking Interface Statistics..."
echo "## ============================================================================== ##"
## 
## ======================================================================================== ##
mkdir -p /var/log/journal
systemd-tmpfiles --create --prefix /var/log/journal
chgrp systemd-journal /var/log/journal
chmod 2775 /var/log/journal
# systemctl restart systemd-journald.service
setfacl -Rnm g:wheel:rx,d:g:wheel:rx,g:adm:rx,d:g:adm:rx /var/log/journal/
journalctl --rotate
# journalctl --sync

/usr/lib/systemd/*.conf.d/


/etc/systemd/journald.conf

/etc/systemd/journald.conf.d/*.conf

/run/systemd/journald.conf.d/*.conf

/usr/lib/systemd/journald.conf.d/*.conf
systemd-journald.service
journalctl --setup-keys

## ======================================================================================== ##
## 
## 
## ======================================================================================== ##
if [ -e /etc/lilo.conf ]; then
	chown root:root /etc/lilo.conf
	chmod 0600 /etc/lilo.conf
else
	echo -e "\t\t${BLOODRED} [!] File: /etc/Lilo.conf File To Be Found...${RESET}"
fi
## ======================================================================================== ##
if [ -e /etc/grub.conf ]; then
	chown root:root /etc/grub.conf
	chmod 0600 /etc/grub.conf
else
	echo -e "\t\t${BLOODRED} [!] File: [ /etc/grub.conf ] Could Not Be Found...${RESET}"
fi
## ======================================================================================== ##
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
echo -e "\t\t\t[+] Turn off core dumps:"
echo "## ============================================================================== ##"
ulimit -c 0
echo "## ============================================================================== ##"
echo -e "\t\t\t[+] show all of your user limit settings:"
echo "## ============================================================================== ##"
ulimit -a
## ======================================================================================== ##
## 
# apt-key add $GPGKey.pub
# GPGImport="gpg --keyid-format long --import $GPGKey.(pub|key|asc)
# gpg --keyid-format long --verify 
echo "## ============================================================================== ##"
echo -e "\t[+] Saving IPTable Rules, And Redirecting To /etc/iptables/iptables.rules"
echo "## ============================================================================== ##"
$IPTABLESSAVE > /etc/iptables/iptables.rules
