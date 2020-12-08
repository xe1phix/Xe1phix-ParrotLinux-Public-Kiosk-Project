#!/bin/sh
## 
##-===============================================-##
##  [+] Block Incoming Traffic From India (IN)
##-===============================================-##
iptables -I INPUT -m geoip --src-cc IN -j DROP
