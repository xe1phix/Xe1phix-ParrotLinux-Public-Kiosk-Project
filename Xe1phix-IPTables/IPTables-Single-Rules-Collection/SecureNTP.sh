#!/bin/sh
## --------------- ##
## SecureNTP.sh
## --------------- ##
## NTP1='nslookup 1.debian.pool.ntp.org | grep Address | cut -c10-199'

NTP0='nslookup 0.debian.pool.ntp.org'
NTP1='nslookup 1.debian.pool.ntp.org'
NTP2='nslookup 2.debian.pool.ntp.org'
NTP3='nslookup 3.debian.pool.ntp.org'


## Force a specific NTP (e.g. ntp0.fau.de)
$IPTABLES -t nat -A OUTPUT -p tcp --dport 123 -j DNAT --to-destination $NTP0:123
$IPTABLES -t nat -A OUTPUT -p udp --dport 123 -j DNAT --to-destination $NTP1:123
$IPTABLES -t nat -A OUTPUT -p udp --dport 123 -j DNAT --to-destination $NTP2:123
$IPTABLES -t nat -A OUTPUT -p udp --dport 123 -j DNAT --to-destination $NTP3:123
