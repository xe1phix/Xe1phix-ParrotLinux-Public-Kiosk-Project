#!/bin/sh

##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##
##   	[+] bbot - Enum + Recon + API - Pentesting
##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##



##-========================================================-##
##   [+] bbot - Perform Full Subdomain Enumeration
##-========================================================-##
bbot -t $Domain -f subdomain-enum 


##-=============================================================-##
##   [+] bbot - Perform Web Scan - wappalyzer, robots.txt, etc
##-=============================================================-##
bbot -t $Domain -f subdomain-enum web-basic


##-========================================================-##
##   [+] bbot - Perform Passive Subdomain Enumeration 
##-========================================================-##
bbot -t $Domain -f subdomain-enum -rf passive


##-========================================================-##
##   [+] bbot - Web Spider - 
##-========================================================-##
bbot -t $Domain -m httpx robots badsecrets -c web_spider_distance=2 web_spider_depth=1


##-========================================================-##
##   [+] bbot - 
##-========================================================-##
bbot -t $Domain -f subdomain-enum email-enum cloud-enum web-basic -m nmap gowitness nuclei --allow-deatdly




## ------------------------------------------------------------------ ##
##      [?]  Port-scan every subdomain
##      [?]  screenshot every webpage
##      [?]  output to current directory
## ------------------------------------------------------------------ ##
bbot -t $Domain -f subdomain-enum -m nmap gowitness -n my_scan -o .


##-=========≈=≈=================================-##
##    [+] bbot - Subdomains + basic web scan:
##-=========≈=≈=================================-##
## ------------------------------------------------------------------ ##
##      [?]  includes wappalyzer, robots.txt,
##      [?]  and other non-intrusive web modules
## ------------------------------------------------------------------ ##
bbot -t $Domain -f subdomain-enum web-basic


##-============================-##
##    [+] bbot - Web spider:
##-============================-##
## ------------------------------------------------------------------ ##
##   [?] Crawl $Domain
##   [?] max depth of 2 
##   [?] auto extract emails, secrets, etc.
## ------------------------------------------------------------------ ##
bbot -t $Domain -m httpx robots badsecrets secretsdb -c web_spider_distance=2 web_spider_depth=2


##-====================================================-##
##     [+] bbot - Everything everywhere all at once:
##-====================================================-##
## ------------------------------------------------------------------ ##
##     [?]  Subdomains, emails, web scan,
##     [?]  cloud buckets, port scan, 
##     [?]  web screenshots, nuclei
## ------------------------------------------------------------------ ##
bbot -t  $Domain -f subdomain-enum email-enum cloud-enum web-basic -m nmap gowitness nuclei --allow-deadly




~/.config/bbot/secrets.yml

