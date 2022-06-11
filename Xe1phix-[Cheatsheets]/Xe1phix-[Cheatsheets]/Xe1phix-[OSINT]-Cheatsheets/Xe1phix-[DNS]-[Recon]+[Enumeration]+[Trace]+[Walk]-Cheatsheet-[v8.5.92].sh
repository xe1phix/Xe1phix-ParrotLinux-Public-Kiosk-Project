#!/bin/sh
##-==========================================================================-##
##   [+] Xe1phix-[DNS]-[Recon]+[Enumeration]+[Trace]+[Walk]-Cheatsheet.sh
##-==========================================================================-##


dnsrecon -d $Domain.com -t axfr @ns2.$Domain.com


dnsenum $Domain.com


dnsrecon -d $Domain --lifetime 10 -t brt -D usr/share/dnsrecon/namelist.txt -x sina.xml



##-==================================================-##
##  [+] Dnsrecon DNS Brute Force

dnsrecon -d TARGET -D /usr/share/wordlists/dnsmap.txt -t std --xml ouput.xml



dnsenum -f /usr/share/dnsenum/dns.txt -dnsserver 8.8.8.8 $Domain -o $Domain.xml



##-======================================-##
##  [+] Dnsrecon DNS List of $Domain
##-======================================-##
dnsrecon -d $Domain -t axfr



##-=================-##
##  [+] DNSEnum
##-=================-##
dnsenum $Domain





##-=====================================================================-##
##   [+] Search for the A record of $Domain on your local nameserver:
##-=====================================================================-##
dnstracer $Domain


##-=====================================================================-##
##   [+] Search for the MX record of $Domain on the root-nameservers:
##-=====================================================================-##
dnstracer "-s" . "-q" mx $Domain


##-=================================================================-##
##   [+] Search for the PTR record (hostname) of 212.204.230.141:
##-=================================================================-##
dnstracer "-q" ptr 141.230.204.212.in-addr.arpa


##-========================-##
##   [+] IPv6 addresses:
##-========================-##
dnstracer "-q" ptr "-s" . "-o" 2.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.6.4.0.2.0.0.0.0.8.b.0.e.f.f.3.ip6.int



##-=================================================================-##
##   [+] 
##-=================================================================-##
dnstop -l 3 eth0




dnswalk $Domain

## ------------------------------------------------------------- ##
##   [?] Print debugging and 'status' information to stderr
## ------------------------------------------------------------- ##


									## ----------------------------------------------------------- ##
dnswalk -r -d $* $Domain.		## Recursively descend sub-domains of the specified domain.
									## Print debugging and 'status' information to stderr
									## ----------------------------------------------------------- ##

									## ---------------------------------------------------- ##
dnswalk -F $Domain					## perform "fascist" checking
									## ---------------------------------------------------- ##
									##  [?] When checking an A record, 
									##      compare the PTR name for each IP address 
									##      with the forward name and report mismatches.
									## ---------------------------------------------------- ##
									
dmitry -p $Domain -f -b



dmitry -iwnse $Domain






##-================-##
##  [+] DNSMap
##-================-##
dnsmap -w $File.txt $Domain


## ----------------------------------------------------------- ##
##   [+] DNSenum - enumerate various DNS records, such as:
##                 NS, MX, SOA, and PTR records. 
##   [?] DNSenum also tries to perform DNS zone transfer
## ----------------------------------------------------------- ##

dnsenum -p 5 -s 20 $Domain
dnsenum -f $File.txt $Domain
dnsenum -o dnsenum_info $Domain

dnsenum --enum -f $File.txt --update a -r $URL






dnsrecon -d $Domain -D /usr/share/wordlists/$File.txt -t std --xml $File.xml



## --------------------------------------------------------------------------------------- ##
    dnsrecon -t rvs -i 192.1.1.1,192.1.1.20         ## Reverse lookup for IP range:
## --------------------------------------------------------------------------------------- ##
    dnsrecon -t std -d $Domain                      ## Retrieve standard DNS records:
## --------------------------------------------------------------------------------------- ##
    dnsrecon -t brt -d $Domain -w $Hosts.txt	    ## Enumerate subdornains:
## --------------------------------------------------------------------------------------- ##
    dnsrecon -d $Domain -t axfr                     ## DNS zone transfer:
## --------------------------------------------------------------------------------------- ##
    dnsrecon --type snoop -n $Server -D $Dict		## Cache Snooping
## --------------------------------------------------------------------------------------- ##
    dnsrecon -d $Host -t zonewalk                   ## Zone Walking
## --------------------------------------------------------------------------------------- ##
    dnsrecon.py -d $Domain -D $Dict -t brt          ## Domain Brute-Force
## --------------------------------------------------------------------------------------- ##
dnsrecon.py -t brt,std,axfr -D /pentest/enumeration/dns/dnsrecon/namelist.txt -d $target



##-=======================================-##
##  [+] DNSRecon - DNS Brute Force Scan
##-=======================================-##
dnsrecon -t brt -d $Domain -D /$Dir/$File.txt



fierce -dns $URL


##-==============================================-##
##   [+] Run massdns to determine online hosts
##-==============================================-##
massdns -r $RESOLVERS -q -t A -o -S -w $File.out $File-merged.txt
cat $File.out | awk '{print $1}' | sed 's/\.$//' | sort -u > $File-online.txt


massdns -r lists/resolvers.txt -t A -q -o S $File.txt


## --------------------------------------------- ##
##  [?] Enumerates a domain for DNS entries
## --------------------------------------------- ##
dnsdict6 -4 -d -t 16 -e -x $Domain


dnscan.py --domain $Domain --wordlist $File


dnscan -d $Target -w $Domains QUICK -o $Dir/domains-dnscan-$Target.txt



