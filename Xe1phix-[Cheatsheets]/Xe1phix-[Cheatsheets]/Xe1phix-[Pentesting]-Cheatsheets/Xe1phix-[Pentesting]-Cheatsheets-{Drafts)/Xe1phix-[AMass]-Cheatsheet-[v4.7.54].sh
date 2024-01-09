#!/bin/sh

##    [+]

Attack Surface Mapping and Asset Discovery tool


##-============================-##
##  [+]
##-============================-##
amass enum -list


##-======================================-##
##  [+] Enumerate Domain + Source + IP
##-======================================-##
amass enum -src -ip -d $URL


##-============================-##
##  [+]
##-============================-##
amass enum -src -brute -d $Domain -o $File


##-============================-##
##  [+]
##-============================-##
amass intel -whois -ip -src -d $Domain -o $File


##-========================================-##
##  [+] Passively Search For Subdomains:
##-========================================-##
amass enum -passive -d $Domain -src


##-=====================================-##
##  [+] Active Subdomain Bruteforcing:
##-=====================================-##
amass enum -active -d $Domain -brute -w $File -src -ip -dir $Dir -config $File -o $File


##-=========================-##
##  [+] DNS Enumeration:
##-=========================-##
amass enum -v -src -ip -brute -d $Domain



amass enum -d $Domain



amass intel -whois -d $Domain
amass intel -active 172.21.0.0-64 -p 80,443,8080,8443
amass intel -ipv4 -whois -d $Domain
amass intel -ipv6 -whois -d $Domain


##-========================================-##
##  [+] Discover Targets for Enumeration:
##-========================================-##
amass intel -d $Domain

Find root domains related to a domain:
amass intel -d $Domain -whois

Find ASNs belonging to an organisation:
amass intel -org '$OrgName'


amass intel -active -addr

Find root domains belonging to a given Autonomous System Number:
amass intel -active -asn $ASN -ip -src


amass intel -log amass.log -whois



amass -src -ip -active -exclude crtsh -d $Domain
amass -src -ip -active -brute --min-for-recursive 3 -exclude crtsh -w $Wordlist -d $Domain


amass enum -src -ip -d $Domain



##-========================================-##
##  [+] GATHERING REVERSE WHOIS DNS SUBDOMAINS VIA AMASS
##-========================================-##
amass intel -whois -d $Domain > $LOOT_DIR/domains/domains-$Domain-reverse-whois.txt



##-========================================-##
##  [+]
##-========================================-##
amass enum -config /path/to/config.ini -passive -o amass_subs.txt -d $Domain



##-===================================-##
##    [+] Double checking for subdomains
##    [+] with amass and certspotter.
##-===================================-##
amass enum -d $Domain | tee -a $Domain/recon/final1.txt


##-===============================================-##
##   [+] Typical parameters for DNS enumeration:
##-===============================================-##
amass enum -v -src -ip -brute -min-for-recursive 2 -d $Domain





amass -src -ip -active -exclude crtsh -d $DOMAIN
amass -src -ip -active -brute --min-for-recursive 3 -exclude crtsh -w $WORDLIST -d $DOMAIN




##-=====================================-##
##  [+] Visualize Enumeration Results:
##-=====================================-##


##-===================================================-##
##  [+] Visualize Enumeration Results Using Maltego:
##-===================================================-##
amass viz -maltego




##-===================================================-##
##   [+] Importing OWASP Amass Results into Maltego
##-===================================================-##


##-===============================================-##
##     [+] Convert the Amass data into a
##     [+] Maltego graph table CSV file:
##-===============================================-##
amass viz -maltego





amass dns




