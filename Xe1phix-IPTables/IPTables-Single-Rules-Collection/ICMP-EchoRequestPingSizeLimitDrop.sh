#!/bin/sh
## ====================================== ##
## ICMP-EchoRequestPingSizeLimitDrop.sh
## ====================================== ##

echo "## ====================================================== ##"
echo -e "\t\t Dropping all the pings with a packet "
echo -e "\t\t   Size greater than 85 bytes..."
echo "## ====================================================== ##"
iptables -A INPUT -p icmp --icmp-type echo-request -m length --length 86:0xffff -j DROP
