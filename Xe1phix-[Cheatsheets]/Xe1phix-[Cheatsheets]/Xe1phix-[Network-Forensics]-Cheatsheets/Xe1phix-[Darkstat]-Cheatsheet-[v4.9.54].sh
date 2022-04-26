#!/bin/sh


##-===============================================-##
##   [+] Gather statistics on the eth0 interface:
##-===============================================-##
darkstat -i eth0


##-============================-##
##   [+] Ignore ARP traffic:
##-============================-##
darkstat -i eth0 -f "not arp"


##-=====================-##
##   [+] SSH traffic:
##-=====================-##
darkstat -i eth0 -f "port 22"


##-=========================-##
##   [+] OpenVPN traffic:
##-=========================-##
darkstat -i eth0 -f "port 1194"


##-===========================================-##
##   [+] Show hex dumps of received traffic
##-===========================================-##
darkstat --verbose -i eth0 --hexdump


##-===========================-##
##   [+] Show HTTP traffic
##-===========================-##
darkstat -i eth0 -p 80


##-=======================================================-##
##   [+] dont account for traffic between internal IPs:
##-=======================================================-##
darkstat -i eth0 -f "not (src net 192.168.0 and dst net 192.168.0)"


##-=================================================================-##
##   [+] graph all traffic entering and leaving the local network
##-=================================================================-##
darkstat -i eth0 -l 192.168.1.0/255.255.255.0


##-===============================================-##
##   [+] import a darkstat database
##-===============================================-##
darkstat --verbose --import $File


##-===============================================-##
##   [+] export in-memory darkstat database
##-===============================================-##
darkstat --verbose --export $File


##-======================================================-##
##   [+] Export hex dumps of received traffic to file:
##-======================================================-##
darkstat --verbose -i eth0 --hexdump --export $File


## ---------------------------------------------------------------- ##
##  [?] account for traffic on the Internet-facing  interface,
##  [?] but only  serve  web pages to our private local network
##  [?] where we have the IP address 192.168.0.1:
## ---------------------------------------------------------------- ##
darkstat -i eth0 -b 192.168.0.1



##-==================================================-##
##   [+] serve web pages on the standard HTTP port:
##-==================================================-##
darkstat -i eth0 -p 80



##-========================================================-##
##   [+] don't account for traffic between internal IPs:
##-========================================================-##
darkstat -i eth0 -f "not (src net 192.168.0 and dst net 192.168.0)"



## ---------------------------------------------------------------------- ##
##  [?] We have a network consisting of a gateway server (192.168.1.1)
##  [?] and a few  workstations (192.168.1.2,  192.168.1.3,  etc.)
## ---------------------------------------------------------------------- ##
##  [?] graph all traffic entering and leaving the local network,
##  [?] not just the gateway server (which is running darkstat):
## ---------------------------------------------------------------------- ##
darkstat -i eth0 -l 192.168.1.0/255.255.255.0



