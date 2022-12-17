#!/bin/sh
## -------------------------------------------------------------------------------------------------------- ##
##  [?] dnsmap - DNS Network Mapper
##  [?] dnsmap - scan for subdomains using bruteforcing techniques
##  [?] dnsmap - scans a domain for common subdomains using a built-in or an external wordlist
## -------------------------------------------------------------------------------------------------------- ##v


##-================-##
##  [+] DNSMap
##-================-##
dnsmap -w $File.txt $Domain


##-==================================-##
##  [+] 
##-==================================-##
dnsmap $Domain -r $Results.txt


##-==================================-##
##  [+] 
##-==================================-##
dnsmap $Domain -w $Wordlist.txt -r $Results.txt


##-==================================-##
##  [+] 
##-==================================-##
dnsmap $Domain -r /tmp/ -d 3000


##-==================================-##
##  [+] 
##-==================================-##
dnsmap $Domain -c $Results.csv



##-================-##
##  [+] DNSMap
##-================-##
dnsmap -w $File.txt $Domain



##-=====================================================-##
##  [+] bruteforcing a list of target domains in bulk 
##  [+] saving all results inside a directory:
##-=====================================================-##
dnsmap-bulk $Domains.txt /tmp/results/

