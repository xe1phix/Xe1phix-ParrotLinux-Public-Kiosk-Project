#!/bin/bash
##~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~##
## SilentlyDropAllBroadcastPackets.sh	##
##~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~##
## 
## 
SYSCTL=/sbin/sysctl 
MODPROBE=/sbin/modprobe
IPTABLES=/sbin/iptables
IP6TABLES=/sbin/ip6tables
IPTABLES_SAVE="$IPTABLES-save"
IPTABLESRESTORE="$IPTABLES-restore"
echo
echo "##-============================================================================================-##"
echo -e "\t\t [+] Silently dropping all the broadcasted packets..."
echo "##-============================================================================================-##"
echo "## -------------------------------------------------------------------------------------------- ##"
echo "     DROP       all  --  anywhere             anywhere           PKTTYPE = broadcast"
echo "## -------------------------------------------------------------------------------------------- ##
$IPTABLES -A INPUT -m pkttype --pkt-type broadcast -j DROP			## --> to all Broadcast Packets

