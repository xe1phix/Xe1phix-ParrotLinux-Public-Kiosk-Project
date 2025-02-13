#!/bin/sh

##-=======================================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-=======================================================================-##
## 	 [+] HackerTarget API - OSINT - Domain + ASN + Netblock Enumeration
##-=======================================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-=======================================================================-##



## -------------------------------------------------------------------------------------------------------- ##
      curl https://api.hackertarget.com/aslookup/?q=$ASN                ## ASN Lookup
## -------------------------------------------------------------------------------------------------------- ##
      curl https://api.hackertarget.com/whois/?q=$Domain                ## Whois Lookup
## -------------------------------------------------------------------------------------------------------- ##
      curl https://api.hackertarget.com/nping/?q=$1
## -------------------------------------------------------------------------------------------------------- ##
      curl https://api.hackertarget.com/findshareddns/?q=$1
## -------------------------------------------------------------------------------------------------------- ##
      curl https://api.hackertarget.com/nmap/?q=$1
## -------------------------------------------------------------------------------------------------------- ##
      curl https://api.hackertarget.com/geoip/?q=$1
## -------------------------------------------------------------------------------------------------------- ##
      curl https://api.hackertarget.com/zonetransfer/?q=$1
## -------------------------------------------------------------------------------------------------------- ##
      curl https://api.hackertarget.com/httpheaders/?q=$1
## -------------------------------------------------------------------------------------------------------- ##
      curl https://api.hackertarget.com/hostsearch/?q=$1
## -------------------------------------------------------------------------------------------------------- ##
      curl https://api.hackertarget.com/dnslookup/?q=$1
## -------------------------------------------------------------------------------------------------------- ##
      curl https://api.hackertarget.com/reversedns/?q=$IP
## -------------------------------------------------------------------------------------------------------- ##
      curl https://api.hackertarget.com/mtr/?q=$1
## -------------------------------------------------------------------------------------------------------- ##
      curl https://api.hackertarget.com/subnetcalc/?q=$1
## -------------------------------------------------------------------------------------------------------- ##
      curl https://api.hackertarget.com/nmap/?q=$1
## -------------------------------------------------------------------------------------------------------- ##
      curl https://api.hackertarget.com/pagelinks/?q=$URL
## -------------------------------------------------------------------------------------------------------- ##


##-==================================================-##
##   [+] HackerTarget - 
##-==================================================-##
curl -s "https://api.hackertarget.com/hostsearch/?q=$1" | cut -d ',' -f1 | sort -u


##-==================================================-##
##   [+] HackerTarget - 
##-==================================================-##
curl http://api.hackertarget.com/hostsearch/?q=$1 -m 30 | sed 's/,/ /' | awk '{print $1}' | grep "$target" >> /tmp/onlineFoundSubdomains



