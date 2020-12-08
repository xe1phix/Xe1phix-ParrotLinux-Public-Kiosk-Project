#!/bin/sh
## 
##-=========================================-##
##  [+] Block All Incoming Non-US Traffic:
##-=========================================-##
iptables -I INPUT -m geoip ! --src-cc US -j DROP
