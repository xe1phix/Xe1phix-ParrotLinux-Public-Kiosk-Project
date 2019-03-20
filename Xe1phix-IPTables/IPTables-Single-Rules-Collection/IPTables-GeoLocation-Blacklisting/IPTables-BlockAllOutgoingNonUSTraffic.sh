#!/bin/sh
## 
##-=========================================-##
##  [+] Block All Outgoing Non-US Traffic:
##-=========================================-##
iptables -I OUTPUT -m geoip ! --src-cc US -j DROP
