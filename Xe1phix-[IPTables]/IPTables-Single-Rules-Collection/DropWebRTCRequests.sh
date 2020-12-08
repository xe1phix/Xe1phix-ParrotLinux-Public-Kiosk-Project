#!/bin/sh
## 
##~=~=~=~=~=~=~=~=~=~=~=~=~=~##
## DropWebRTCRequests.sh
##~=~=~=~=~=~=~=~=~=~=~=~=~=~##
## 
IPTABLES=/sbin/iptables


echo "## ================================================== ##"
echo -e "\t\t [?] Dropping STUN (WebRTC) requests..."
echo "## ================================================== ##"
$IPTABLES -A OUTPUT -p udp --dport 3478 -j DROP
$IPTABLES -A OUTPUT -p udp --dport 3479 -j DROP
$IPTABLES -A OUTPUT -p tcp --dport 3478 -j DROP
$IPTABLES -A OUTPUT -p tcp --dport 3479 -j DROP

