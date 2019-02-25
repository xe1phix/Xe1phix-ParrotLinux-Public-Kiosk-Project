#!/bin/sh
## ------------------ ##
## FlushIPTables.sh
## ------------------ ##


## flush and reset iptables
/sbin/iptables -F
/sbin/iptables -t nat -F
/sbin/iptables -t mangle -F
/sbin/iptables -t nat -X
/sbin/iptables -t mangle -X
/sbin/iptables -Z
/sbin/iptables -X

## Flush old rules.
/sbin/ip6tables -F
/sbin/ip6tables -X
/sbin/ip6tables -t mangle -F
/sbin/ip6tables -t mangle -X

## Policy DROP for all traffic as fallback.
/sbin/iptables -P INPUT DROP
/sbin/iptables -P FORWARD ACCEPT
/sbin/iptables -P OUTPUT ACCEPT

## Drop/reject all IPv6 Traffic:
/sbin/ip6tables -A INPUT -j DROP
/sbin/ip6tables -A OUTPUT -j REJECT
/sbin/ip6tables -A FORWARD -j REJECT

