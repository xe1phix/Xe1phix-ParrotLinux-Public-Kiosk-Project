#!/bin/bash
##~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~##
## Limit-Number-of-Parallel-Connections-Made-By-A-Whole-Class-A.sh	##
##~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~##
## 
## 
SYSCTL=/sbin/sysctl 
MODPROBE=/sbin/modprobe
IPTABLES=/sbin/iptables
IP6TABLES=/sbin/ip6tables
IPTABLES_SAVE="$IPTABLES-save"
IPTABLESRESTORE="$IPTABLES-restore"

## 
# echo "## ======================================================================== ##"
# echo -e "\t Limit the number of parallel connections made by a whole class A:"
# echo "## ======================================================================== ##"
## 
$IPTABLES -A INPUT -p tcp --syn --dport http -m iplimit --iplimit-mask 8 --iplimit-above 4 -j REJECT

