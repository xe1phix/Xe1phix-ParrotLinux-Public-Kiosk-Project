#!/bin/sh
##  IPTables-AFWall-Orbot-Transparent-Proxy.sh

IPTABLES=/system/bin/iptables

# Example config
# lo = 127.0.0.1
# UID 10001
# Orbot Port (default) 9040
# Allow DNS (Port 53) 

$IPTABLES -t filter -A OUTPUT -m owner --uid-owner 10001 -o lo -j ACCEPT
$IPTABLES -t nat -A OUTPUT -p tcp ! -o lo ! -d 127.0.0.1 ! -s 127.0.0.1 -m owner --uid-owner 10001 -m tcp --syn -j REDIRECT --to-ports 9040
$IPTABLES -t nat -A OUTPUT -p udp -m owner --uid-owner 10001 -m udp --dport 53 -j REDIRECT --to-ports 5400
$IPTABLES -t filter -A OUTPUT -m owner --uid-owner 10001 ! -o lo ! -d 127.0.0.1 ! -s 127.0.0.1 -j REJECT
