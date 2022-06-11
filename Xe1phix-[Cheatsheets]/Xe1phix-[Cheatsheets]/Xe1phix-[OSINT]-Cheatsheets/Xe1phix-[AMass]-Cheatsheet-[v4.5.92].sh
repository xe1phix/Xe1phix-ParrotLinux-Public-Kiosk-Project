#!/bin/sh

##-============================-##
##  [+]
##-============================-##
amass enum -list


##-============================-##
##  [+]
##-============================-##
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



##-=====================================-##
##  [+] Visualize Enumeration Results:
##-=====================================-##


##-===================================================-##
##  [+] Visualize Enumeration Results Using Maltego:
##-===================================================-##
amass viz -maltego


##-========================================-##
##  [+] Discover Targets for Enumeration:
##-========================================-##
amass intel -d $Domain


amass intel -d $Domain -whois


amass intel -org '$OrgName'


amass intel -active -asn $ASN -ip

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



##-===================================================-##
##   [+] Importing OWASP Amass Results into Maltego
##-===================================================-##


##-===============================================-##
##     [+] Convert the Amass data into a
##     [+] Maltego graph table CSV file:
##-===============================================-##
amass viz -maltego



