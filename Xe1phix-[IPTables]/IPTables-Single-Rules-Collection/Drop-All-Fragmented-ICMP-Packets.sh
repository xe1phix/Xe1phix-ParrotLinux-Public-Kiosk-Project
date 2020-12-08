#!/bin/bash
##~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~##
## Drop-All-Fragmented-ICMP-Packets.sh	##
##~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~##
## 
## 
SYSCTL=/sbin/sysctl 
MODPROBE=/sbin/modprobe
IPTABLES=/sbin/iptables
IP6TABLES=/sbin/ip6tables
IPTABLES_SAVE="$IPTABLES-save"
IPTABLESRESTORE="$IPTABLES-restore"


# First, drop all fragmented ICMP packets (almost always malicious).
$IPTABLES -A INPUT -p icmp --fragment -j DROPLOG
$IPTABLES -A OUTPUT -p icmp --fragment -j DROPLOG
$IPTABLES -A FORWARD -p icmp --fragment -j DROPLOG

