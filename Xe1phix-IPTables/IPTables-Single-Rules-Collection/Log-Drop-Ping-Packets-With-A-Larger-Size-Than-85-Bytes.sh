#!/bin/bash
##~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~##
## Log-Drop-Ping-Packets-With-A-Larger-Size-Than-85-Bytes.sh	##
##~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~##
## 
## 
SYSCTL=/sbin/sysctl 
MODPROBE=/sbin/modprobe
IPTABLES=/sbin/iptables
IP6TABLES=/sbin/ip6tables
IPTABLES_SAVE="$IPTABLES-save"
IPTABLESRESTORE="$IPTABLES-restore"


## 
echo "## ============================================================================== ##"
echo -e "\t[+] Dropping All The Pings With A Packet Size Greater Than 85 Bytes..."
echo "## ============================================================================== ##"
## 
## ======================================================================================== ##
$IPTABLES -A INPUT -p icmp --icmp-type echo-request -m length --length 86:0xffff -j LOG --log-prefix "Ping Packet Size Larger Than 85 Bytes: " --log-level 7
$IPTABLES -A INPUT -p icmp --icmp-type echo-request -m length --length 86:0xffff -j DROP
## ======================================================================================== ##
## 
