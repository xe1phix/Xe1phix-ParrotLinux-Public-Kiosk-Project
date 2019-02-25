#!/bin/sh
## --------------------- ##
## BlockSMURFAttacks.sh
## --------------------- ##

#Prevent SMURF attacks
$IPTABLES -A INPUT -p icmp -m icmp --icmp-type address-mask-request -j DROP
$IPTABLES -A INPUT -p icmp -m icmp --icmp-type timestamp-request -j DROP
$IPTABLES -A INPUT -p icmp -m limit --limit 2/second --limit-burst 2 -j ACCEPT
$IP6TABLES -A INPUT -p icmpv6 -m limit --limit 2/second --limit-burst 2 -j ACCEPT
