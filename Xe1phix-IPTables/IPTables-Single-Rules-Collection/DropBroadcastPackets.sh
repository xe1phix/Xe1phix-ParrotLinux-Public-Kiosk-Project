#!/bin/sh
## ====================================== ##
## DropBroadcastPackets.sh
## ====================================== ##

echo "## ====================================================== ##"
echo -e "\t\t [+] Silently drop all the broadcasted packets:"
echo "## ====================================================== ##"
iptables -A INPUT -m pkttype --pkt-type broadcast -j DROP
