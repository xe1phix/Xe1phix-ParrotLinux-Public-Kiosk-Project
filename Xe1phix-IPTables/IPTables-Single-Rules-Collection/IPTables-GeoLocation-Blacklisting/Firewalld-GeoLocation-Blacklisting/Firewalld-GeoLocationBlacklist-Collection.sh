#!/bin/sh
## 
##-=========================================-##
##  [+] Block All Incoming Non-US Traffic:
##-=========================================-##
firewall-cmd --direct --add-rule ipv4 filter INPUT 0 -m geoip ! --src-cc US -j DROP

##-=================================================-##
##  [+] Block Outgoing Traffic Going To India (IN)
##-=================================================-##
firewall-cmd --direct --add-rule ipv4 filter OUTPUT 0 -m geoip --dst-cc IN -j DROP

##-==============================================-##
##  [+] Block Incoming Traffic From India (IN)
##-==============================================-##
firewall-cmd --direct --add-rule ipv4 filter INPUT 0 -m geoip --src-cc IN -j DROP

##-=======================================================-##
##  [+] Block Anything Coming From China Using Firewalld:
##-=======================================================-##
firewall-cmd --direct --add-rule ipv4 filter INPUT 0 -m geoip --dst-cc CN -j DROP
