#!/bin/sh
## 
##-=====================-##
##  [+] SYN Flooding 
##-=====================-##
## 
## ------------------------------------------------ ##
##  [?] Block The Attack By Limiting The 
##      Incoming TCP Connection Request Packets:
## ------------------------------------------------ ##
iptables -A INPUT -p tcp -m state --state NEW -m limit --limit 2/second --limit-burst 2 -j ACCEPT

## Drop All Other Packets That Do Not Match Above Rule:
iptables -A INPUT –p tcp –m state --state NEW –j DROP
