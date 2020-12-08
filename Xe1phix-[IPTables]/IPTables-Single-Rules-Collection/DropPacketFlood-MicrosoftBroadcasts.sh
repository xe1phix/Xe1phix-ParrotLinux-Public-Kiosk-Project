#!/bin/sh
## 
##~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~##
## DropPacketFlood-MicrosoftBroadcasts.sh
##~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~##
## 

SYSCTL=/sbin/sysctl 
MODPROBE=/sbin/modprobe
IPTABLES=/sbin/iptables
IP6TABLES=/sbin/ip6tables
IPTABLES_SAVE="$IPTABLES-save"
IPTABLESRESTORE="$IPTABLES-restore"

LOOPBACK=lo
ETHER=eth0
Eth0Mac=$(cat < /sys/class/net/eth0/address)
IFACE=wlan0
Wlan0Mac=$(cat < /sys/class/net/wlan0/address)

echo
echo "## ================================================================================ ##"
echo "    [?] In Microsoft Networks you will be swamped by broadcasts. 						"
echo "    [?] These rules will prevent Windows broadcasts from showing up in your logs.		"
echo "## ================================================================================ ##"
echo

## 
## ======================================================================================== ##
$IPTABLES -A udp_packets -p UDP -i $ETHER --destination-port 135:139 -j DROP
$IPTABLES -A udp_packets -p UDP -i $IFACE --destination-port 135:139 -j DROP
## ======================================================================================== ##
## 

