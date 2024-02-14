#!/bin/sh


##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##
##     [+] Naabu - Port Scanning + Attack Surface Discovery
##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##



naabu -scan-all-ips $Domain

naabu -proxy $Proxy
naabu -passive
naabu -host-discovery
naabu -debug
naabu -verbose
naabu -top-ports-100
naabu -top-ports-1000
naabu -p -
naabu -list $File

echo $ASN | naabu -p 80,443
echo $Domain | naabu -silent | httpx -silent
echo $Domain | dnsx -resp-only -a -aaaa -silent | naabu -p 80 -silent
echo $Domain | naabu -p 80 -ip-version 6
echo $Domain | naabu -ip-version 4,6 -scan-all-ips -p 80 -silent


## -------------------------------------------------------------------- ##
      naabu -arp $IP            ## ARP Ping
## -------------------------------------------------------------------- ##
      naabu -pe $IP            ## ICMP Echo Ping
## -------------------------------------------------------------------- ##
      naabu -pp $IP            ## ICMP Timestamp Ping
## -------------------------------------------------------------------- ##
      naabu -pm $IP            ## ICMP Address Mask Ping
## -------------------------------------------------------------------- ##
      naabu -nd $IP            ## IPv6 Neighbor Discovery
## -------------------------------------------------------------------- ##
      naabu -rev-ptr $Domain   ## Reverse PTR Lookup For input IPs
## -------------------------------------------------------------------- ##


naabu -host $IP
naabu -json
-csv


$HOME/.config/naabu/config.yaml
