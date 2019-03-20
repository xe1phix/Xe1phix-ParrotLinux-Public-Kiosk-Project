#!/bin/sh
## 
##-=========================================-##
##  [+] Block All Incoming Non-US Traffic:
##-=========================================-##
firewall-cmd --direct --add-rule ipv4 filter INPUT 0 -m geoip ! --src-cc US -j DROP

