#!/bin/sh
##-======================================-##
##   [+] Xe1phix-[Host]-Cheatsheet.sh
##-======================================-##



## ----------------------------------------------------------------------------- ##
	    host -t ns $Domain                  ## Show name servers 
	    host -t mx $Domain                  ## Show mail servers
	    host -t CNAME $Domain               ## CNAME Records
	    host -t SOA $Domain                 ## SOA Records
	    host -t TXT $Domain                 ## TXT Records
	    host -t DNSKEY $Domain              ## DNSKEY Records
	    host -t AXFR $Domain                ## AXFR Records
## ----------------------------------------------------------------------------- ##
	    host -l $Domain $NameServer         ## Zone transfer
## ----------------------------------------------------------------------------- ##
	    host -C $Domain						## SOA Records
## ----------------------------------------------------------------------------- ##
	    host -a $Domain                     ## All Query Types
	    host -v -t ANY $Domain              ## enables verbose output
## ----------------------------------------------------------------------------- ##
	    host -d $Domain                     ## print debugging traces
## ----------------------------------------------------------------------------- ##
	    host -4 $Domain                     ## use IPv4 query transport only
## ----------------------------------------------------------------------------- ##
	    host -6 $Domain                     ## use IPv6 query transport only
## ----------------------------------------------------------------------------- ##




## ----------------------------------------------------------------------------------------- ##
##   [?] performs a zone transfer of zone name 
##       and prints out the NS, PTR, and address records (A/AAAA).
## ----------------------------------------------------------------------------------------- ##
