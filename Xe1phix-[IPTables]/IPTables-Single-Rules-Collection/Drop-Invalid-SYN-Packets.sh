#!/bin/bash
##~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~##
## Drop-Invalid-SYN-Packets.sh	##
##~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~##
## 
## 
SYSCTL=/sbin/sysctl 
MODPROBE=/sbin/modprobe
IPTABLES=/sbin/iptables
IP6TABLES=/sbin/ip6tables
IPTABLES_SAVE="$IPTABLES-save"
IPTABLESRESTORE="$IPTABLES-restore"




echo "[+]=====================================================================[+]"
echo -e "\t\t\t DROP INVALID SYN PACKETS..."
echo "[+]=====================================================================[+]"

## 
## ========================================================================================================== ##
$IPTABLES -A OUTPUT -p tcp --tcp-flags ALL ACK,RST,SYN,FIN -j REJECT --reject-with icmp-admin-prohibited
$IPTABLES -A OUTPUT -p tcp --tcp-flags SYN,FIN SYN,FIN -j REJECT --reject-with icmp-admin-prohibited
$IPTABLES -A OUTPUT -p tcp --tcp-flags SYN,RST SYN,RST -j REJECT --reject-with icmp-admin-prohibited
## ========================================================================================================== ##
## 

