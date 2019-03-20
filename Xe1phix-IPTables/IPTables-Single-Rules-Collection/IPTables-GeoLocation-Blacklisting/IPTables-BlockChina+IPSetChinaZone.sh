#!/bin/sh
## 
##-===========================================-##
##  [+] IPTables-BlockChina+IPSetChinaZone.sh
##-===========================================-##

##-=======================================================-##
##  [+] Block Anything Coming From China Using IPTables:
##-=======================================================-##
iptables-A INPUT -p tcp -m set --match-set china src -j DROP

##-=============================-##
##  [+] Create The IPSet List:
##-=============================-##
ipset -N china hash:net

##-=========================================-##
##  [+] Pull the latest IP set for China:
##-=========================================-##
wget -P . http://www.ipdeny.com/ipblocks/data/countries/cn.zone

##-===========================================================================-##
##  [+] Add each IP address from the downloaded list into the ipset 'china'
##-===========================================================================-##
for i in $(cat /etc/cn.zone ); do ipset -A china $i; done
