#!/bin/sh

## ------------------------------------------------------------------------------------------ ##
##    altdns -i $InFile                  ## [?] List of subdomains input
## ------------------------------------------------------------------------------------------ ##
##    altdns --wordlist $File            ## [?] List of words to alter the subdomains with
## ------------------------------------------------------------------------------------------ ##
##    altdns --resolve                   ## [?] Resolve all altered subdomains
## ------------------------------------------------------------------------------------------ ##
##    altdns --dnsserver $IP             ## [?] IP address of resolver
## ------------------------------------------------------------------------------------------ ##
##    altdns --save $File                ## [?] File to save resolved altered subdomains
## ------------------------------------------------------------------------------------------ ##
##    altdns --threads $NumThreads       ## [?] Amount of threads to run simultaneously
## ------------------------------------------------------------------------------------------ ##



altdns -l ~/urls.txt -o $File.txt





altdns --input /$Dir/$Domains.txt --output $OutFile --wordlist 



altdns cat resolved_results



altdns -i ../dir$domain/domains.txt -o ../dir$domain/altdns_data_output.txt  -r -s ../dir$domain/altdns_domains.txt



altdns --input /$Dir/$Domains.txt --output $OutFile -w $PermList -r -s $Results.txt

