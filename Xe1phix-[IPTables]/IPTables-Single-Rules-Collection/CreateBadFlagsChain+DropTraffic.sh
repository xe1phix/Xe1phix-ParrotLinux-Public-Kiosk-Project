#!/bin/sh
## 
## CreateBadFlagsChain+DropTraffic.sh
## 
echo
echo "## ============================================================================== ##"
echo -e "\t\t\t[+] Creating Bad Flags Chain..."
echo "## ============================================================================== ##"
##
$IPTABLES -N BAD_FLAGS
$IPTABLES -N LOG_DROP
## ======================================================================================== ##
## 
echo
echo "## ============================================================================== ##"
echo -e "\t\t[+] Pass traffic with bad flags to the Bad Flags Chain"
echo "## ============================================================================== ##"
$IPTABLES -A INPUT -p tcp -j BAD_FLAGS
$IPTABLES -A INPUT -p tcp -j LOG_DROP
## ======================================================================================== ##
## 
echo
echo "## ============================================================================== ##"
echo -e "\t\t\t[+] Rules for traffic with bad flags..."
echo "## ============================================================================== ##"
$IPTABLES -A BAD_FLAGS -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP
$IPTABLES -A BAD_FLAGS -p tcp --tcp-flags SYN,RST SYN,RST -j LOG --log-prefix "Bad SR Flag: "
$IPTABLES -A BAD_FLAGS -p tcp --tcp-flags SYN,RST SYN,RST -j DROP
$IPTABLES -A BAD_FLAGS -p tcp --tcp-flags SYN,FIN,PSH SYN,FIN,PSH -j LOG --log-prefix "Bad SFP Flag: "
$IPTABLES -A BAD_FLAGS -p tcp --tcp-flags SYN,FIN,PSH SYN,FIN,PSH -j DROP
$IPTABLES -A BAD_FLAGS -p tcp --tcp-flags SYN,FIN,RST SYN,FIN,RST -j LOG --log-prefix "Bad SFR Flag: "
$IPTABLES -A BAD_FLAGS -p tcp --tcp-flags SYN,FIN,RST SYN,FIN,RST -j DROP
$IPTABLES -A BAD_FLAGS -p tcp --tcp-flags SYN,FIN,RST,PSH SYN,FIN,RST,PSH -j LOG --log-prefix "Bad SFRP Flag: "
$IPTABLES -A BAD_FLAGS -p tcp --tcp-flags SYN,FIN,RST,PSH SYN,FIN,RST,PSH -j DROP
$IPTABLES -A BAD_FLAGS -p tcp --tcp-flags FIN FIN -j LOG --log-prefix "Bad F Flag: "
$IPTABLES -A BAD_FLAGS -p tcp --tcp-flags FIN FIN -j DROP
$IPTABLES -A BAD_FLAGS -p tcp --tcp-flags ALL NONE -j LOG --log-prefix "Null Flag: "
$IPTABLES -A BAD_FLAGS -p tcp --tcp-flags ALL NONE -j DROP
$IPTABLES -A BAD_FLAGS -p tcp --tcp-flags ALL ALL -j LOG --log-prefix "All Flags: "
$IPTABLES -A BAD_FLAGS -p tcp --tcp-flags ALL ALL -j DROP
$IPTABLES -A BAD_FLAGS -p tcp --tcp-flags ALL FIN,URG,PSH -j LOG --log-prefix "Nmap:Xmas Flags: "
$IPTABLES -A BAD_FLAGS -p tcp --tcp-flags ALL FIN,URG,PSH -j DROP
$IPTABLES -A BAD_FLAGS -p tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG -j LOG --log-prefix "Merry Xmas Flags: "
$IPTABLES -A BAD_FLAGS -p tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG -j DROP
## ======================================================================================== ##
## 
