header-only
identify 
+short
+trace


host -v
host -m record
host -m trace
host -t AXFR
host -t CNAME
host -t NS
host -t SOA
host -t TXT
host -t DNSKEY
host -t MX
-v -t ANY
host -l -a                   ## zone transfer of zone name - print all records in the zone

delv
dnsrecon
dnswalk
dnstracer
mdig





dnstracer -o      Enable overview of received answers at the end

dnstracer -q 
dnstracer -q a 
dnstracer -q aaaa
dnstracer -q a6
dnstracer -q soa
dnstracer -q cname
dnstracer -q hinfo
dnstracer -q mx
dnstracer -q ns
dnstracer -q txt
dnstracer -q ptr



dnstracer -r $Retries               ## Number of retries for DNS requests, default 3.

dnstracer -s $Server                ## 

dnstracer -v                        ## Be verbose on what sent or received.

dnstracer -4                        ## Use only IPv4 servers, dont query IPv6 servers

dnstracer -c                        ## Disable local caching

dnstracer -S $SourceAddr            ## Use this as source-address for the outgoing packets.



Search for the PTR record (hostname) of 212.204.230.141:

dnstracer "-q" ptr 141.230.204.212.in-addr.arpa



Search for the MX record of $Domain on the root-nameservers:

dnstracer "-s" . "-q" mx $Domain









echo DNS servers for $1:
nslookup -type=any $1 | grep nameserver | cut -d  "=" -f2 | cut -d " " -f2 | rev | cut -c2- | rev | tee $1_dnsservers.txt



echo Mail servers for $1:
nslookup -type=mx $1 | grep mail | cut -d "=" -f2 | cut -d " " -f2,3 | tee $1_mxrecords.txt





echo TXT records for $1:
nslookup -type=txt $1 | grep "text" | cut -d "=" -f2,3 | tee $1_txtrecords.txt




for i in $(cat $1_dnsservers.txt); do
  echo " ";
  echo Attempting Zone Transfer on $i | tee -a $1_zonetransfer.txt;
  dig AXFR $1 $ns | tee -a $1_zonetransfer.txt;
done




echo Performing Google Dorks, Shodan HQ, WHOIS Lookups on $1: Opening FireFox...
firefox -new-tab -url http://whois.sc/$1 -new-tab -url http://www.google.com/search?q=site%3A$1 -new-tab -url http://www.google.com/search?q=site%3A$1+type%3Apdf -new-tab -url http://www.google.com/search?q=site%3A$1+type%3Axls -new-tab -url http://www.google.com/search?q=site%3A$1+type%3Axlsx -new-tab -url http://www.google.com/search?q=site%3A$1+type%3Acsv -new-tab -url http://www.google.com/search?q=site%3A$1+type%3Atxt -new-tab -url http://www.google.com/search?q=site%3A$1+type%3Adb -new-tab -url https://www.shodan.io/search?query=$1 -new-tab -url https://www.shodan.io/search?query=$domain &
exit 0














# Get the name servers
NAME_SERVERS=($(host -t ns $DOMAIN | awk '{print substr($4, 1, length($4)-1)}'))

# Attempt zone transfer
for nameserver in "${NAME_SERVERS[@]}"; do
    host -l $DOMAIN $nameserver
done



while read -r prefix; do
    SUB_DOMAIN="${prefix}.${DOMAIN}"
    host "${SUB_DOMAIN}" | grep "has address" | cut -d" " -f1,4
done < "${SUBDOMAIN_LIST_FILE}"











GATHERING ULTATOOLS DNS INFO


curl -s https://www.ultratools.com/tools/ipWhoisLookupResult\?ipAddress\=$TARGET | grep -A2 label | grep -v input | grep span | cut -d">" -f2 | cut -d"<" -f1 | sed 's/\&nbsp\;//g' 2> /dev/null | tee $LOOT_DIR/osint/ultratools-$TARGET.txt 2> /dev/null



GATHERING DNS INFO

wget -q http://www.intodns.com/$TARGET -O $LOOT_DIR/osint/intodns-$TARGET.html 2> /dev/null
echo -e "$OKRED[+]$RESET Report saved to: $LOOT_DIR/osint/intodns-$TARGET.html"





GATHERING THEHARVESTER OSINT INFO

$THEHARVESTER_PATH -d $TARGET -l 100 -b all 2> /dev/null | tee $LOOT_DIR/osint/theharvester-$TARGET.txt 2> /dev/null  $RESET"


theharvester -d $TARGET -l 100 -b all 2> /dev/null | tee $LOOT_DIR/osint/theharvester-$TARGET.txt 2> /dev/null







GATHERING EMAILS FROM EMAIL-FORMAT.COM

curl -s https://www.email-format.com/d/$TARGET| grep @$TARGET | grep -v div | sed "s/\t//g" | sed "s/ //g" 2> /dev/null | tee $LOOT_DIR/osint/email-format-$TARGET.txt 2> /dev/null 



[`date +"%Y-%m-%d](%H:%M)











GATHERING DNS ALTERATIONS

urlcrazy $TARGET 2> /dev/null | tee $LOOT_DIR/osint/urlcrazy-$TARGET.txt 2> /dev/null






COLLECTING OSINT FROM ONLINE DOCUMENTS



metagoofil -d $TARGET -t doc,pdf,xls,csv,txt -l 25 -n 25 -o $LOOT_DIR/osint/ -f $LOOT_DIR/osint/$TARGET.html 2> /dev/null | tee $LOOT_DIR/osint/metagoofil-$TARGET.txt 2> /dev/null



metagoofil.py -d $TARGET -t doc,pdf,xls,csv,txt -l 100 -n 100 -o $LOOT_DIR/osint/ -f $LOOT_DIR/osint/$TARGET.html 2> /dev/null | tee $LOOT_DIR/osint/metagoofil-$TARGET.txt 2> /dev/null 









GATHERING EMAILS VIA HUNTER.IO


curl -s "https://api.hunter.io/v2/domain-search?domain=$TARGET&api_key=$HUNTERIO_KEY" | egrep "name|value|domain|company|uri|position|phone" 2> /dev/null | tee $LOOT_DIR/osint/hunterio-$TARGET.txt 2> /dev/null




msfconsole -x "use auxiliary/gather/search_email_collector; set DOMAIN $TARGET; run; exit y" | tee $LOOT_DIR/osint/msf-emails-$TARGET.txt 2> /dev/null




•?((¯°·._.• Finished OSINT scan: $TARGET (`date +"%Y-%m-%d %H:%M"`) •._.·°¯))؟•"








wget https://raw.githubusercontent.com/rbsec/dnscan/master/subdomains-10000.txt



https://github.com/rbsec/dnscan




ip=$(host $target | head -n 1 | awk '{print $4}')
range=$(whois $ip | grep -E 'NetRange|inetnum' | awk '{print $2,$3,$4}')

the target IP is: $ip 

echo "checking if range is available..."
echo "IP Range: $Range"





Searching for subdomains DNS + small brute (pkey.in | hackertarget.com | virustotal.com)


curl https://www.pkey.in/tools-i/search-subdomains -H 'User-Agent: Mozilla/5.0 (Mobile; rv:49.0) Gecko/49.0 Firefox/49.0' --data "zone=$target&submit=" --insecure -m 30 | grep "border-left-style: none;" | cut -d '>' -f2 | cut -d '<' -f1 | grep -F . | uniq | sed 's/\.$//' | grep "$target" > /tmp/onlineFoundSubdomains

curl http://api.hackertarget.com/hostsearch/?q=$target -m 30 | sed 's/,/ /' | awk '{print $1}' | grep "$target" >> /tmp/onlineFoundSubdomains

curl https://www.virustotal.com/en/domain/$target/information/ -H 'Host: www.virustotal.com' -H 'User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:45.0) Gecko/20100101 Firefox/45.0' -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' -H 'Accept-Language: en-US,en;q=0.5' --compressed -m 30 | grep information | grep "$target" | awk '{print $3}' | sed 's/\// /g' | awk '{print $4}' >> /tmp/onlineFoundSubdomains



echo -e "## -------------- Online Found Subdomains ------------------- ##"

onlineSub=$(cat /tmp/onlineFoundSubdomains | sort | uniq)
echo "$onlineSub"







echo -n "[+] Requesting IP"
myip=$(dig +short myip.opendns.com @resolver1.opendns.com)






# creating target list
	
rangeIp="$(echo "$range" | awk '{print $1}')"	
























































darkstat
dnschef
dnsenum
sslyze
sslscan
fierce
ssldump

openssl-s_client
certtool
ocsp
openssl-ocsp
openssl-verify
openssl-x509
danetool

gnutls-cli
gnutls-cli-debug
ocsptool
p11tool
psktool
srptool
tpmtool




Dump HTTP header using wget

wget --server-response --spider 




 Retrieve the size of a file on a server 

wget --spider $URL 2>&1 | awk '/Length/ {print $2}'






















 Expand shortened URLs 

expandurl() { curl -sIL $1 | grep ^Location; }





Outgoing IP of server

dig +short @resolver1.opendns.com myip.opendns.com



hostname --ip-address 
hostname --all-ip-addresses

hostname hostname G--file file
hostname --fqdn
hostname --all-fqdns
hostname --long
--domain



dnswalk $Domain

dnsrecon -t axfr -d $Domain

dnsrecon -a --domain  $Domain           ## Perform AXFR with standard enumeration.
dnsrecon -s --domain  $Domain           ## Perform a reverse lookup of IPv4 ranges in the SPF record with standard enumeration.

dnsrecon -w  --domain  $Domain          ## Perform deep whois record analysis and reverse lookuof IP ranges

dnsrecon -z  --domain  $Domain          ## Performs a DNSSEC zone walk


dnsrecon --domain 
dnsrecon --name_server 
dnsrecon --range 
dnsrecon --type


dnsrecon --type $Type --domain  $Domain






i.4cdn.org

http://is2.4chan.org/gif/1576524970965.gif



wget $Link -qO - | sed 's/\ /\n/g' | grep -e gif -e webm | grep href | sed 's/href\=\"/http:/g' | sed 's/"//g' | uniq | xargs wget

wget https://boards.4chan.org/gif/thread/16126962 -qO - | sed 's/\ /\n/g' | grep -e gif -e webm | grep href | sed 's/href\=\"/http:/g' | sed 's/"//g' | uniq | xargs wget

















Network Reconnaissance Tools

    ACLight - Script for advanced discovery of sensitive Privileged Accounts - includes Shadow Admins.
    CloudFail - Unmask server IP addresses hidden behind Cloudflare by searching old database records and detecting misconfigured DNS.
    DNSDumpster - Online DNS recon and search service.
    Mass Scan - TCP port scanner, spews SYN packets asynchronously, scanning entire Internet in under 5 minutes.
    ScanCannon - Python script to quickly enumerate large networks by calling masscan to quickly identify open ports and then nmap to gain details on the systems/services on those ports.
    XRay - Network (sub)domain discovery and reconnaissance automation tool.
    dnsenum - Perl script that enumerates DNS information from a domain, attempts zone transfers, performs a brute force dictionary style attack, and then performs reverse look-ups on the results.
    dnsmap - Passive DNS network mapper.
    dnsrecon - DNS enumeration script.
    dnstracer - Determines where a given DNS server gets its information from, and follows the chain of DNS servers.
    fierce - Python3 port of the original fierce.pl DNS reconnaissance tool for locating non-contiguous IP space.
    nmap - Free security scanner for network exploration & security audits.
    passivedns-client - Library and query tool for querying several passive DNS providers.
    passivedns - Network sniffer that logs all DNS server replies for use in a passive DNS setup.
    scanless - Utility for using websites to perform port scans on your behalf so as not to reveal your own IP.
    smbmap - Handy SMB enumeration tool.
    zmap - Open source network scanner that enables researchers to easily perform Internet-wide network studies.










Transport Layer Security Tools

    SSLyze - Fast and comprehensive TLS/SSL configuration analyzer to help identify security mis-configurations.
    crackpkcs12 - Multithreaded program to crack PKCS#12 files (.p12 and .pfx extensions), such as TLS/SSL certificates.
    testssl.sh - Command line tool which checks a server's service on any port for the support of TLS/SSL ciphers, protocols as well as some cryptographic flaws.
    tls_prober - Fingerprint a server's SSL/TLS implementation.





OSINT Tools

    DataSploit - OSINT visualizer utilizing Shodan, Censys, Clearbit, EmailHunter, FullContact, and Zoomeye behind the scenes.
    GyoiThon - GyoiThon is an Intelligence Gathering tool using Machine Learning.
    Intrigue - Automated OSINT & Attack Surface discovery framework with powerful API, UI and CLI.
    Maltego - Proprietary software for open source intelligence and forensics, from Paterva.
    PacketTotal - Simple, free, high-quality packet capture file analysis facilitating the quick detection of network-borne malware (using Bro and Suricata IDS signatures under the hood).
    Skiptracer - OSINT scraping framework that utilizes basic Python webscraping (BeautifulSoup) of PII paywall sites to compile passive information on a target on a ramen noodle budget.
    Sn1per - Automated Pentest Recon Scanner.
    Spiderfoot - Multi-source OSINT automation tool with a Web UI and report visualizations.
    creepy - Geolocation OSINT tool.
    gOSINT - OSINT tool with multiple modules and a telegram scraper.
    image-match - Quickly search over billions of images.
    recon-ng - Full-featured Web Reconnaissance framework written in Python.
    sn0int - Semi-automatic OSINT framework and package manager.





Data broker and search engine services

    Hunter.io - Data broker providing a Web search interface for discovering the email addresses and other organizational details of a company.
    Threat Crowd - Search engine for threats.
    Virus Total - Free service that analyzes suspicious files and URLs and facilitates the quick detection of viruses, worms, trojans, and all kinds of malware.
    surfraw - Fast UNIX command line interface to a variety of popular WWW search engines.

Dorking tools

    BinGoo - GNU/Linux bash based Bing and Google Dorking Tool.
    dorkbot - Command-line tool to scan Google (or other) search results for vulnerabilities.
    github-dorks - CLI tool to scan GitHub repos/organizations for potential sensitive information leaks.
    GooDork - Command line Google dorking tool.
    Google Hacking Database - Database of Google dorks; can be used for recon.
    dork-cli - Command line Google dork tool.
    dorks - Google hack database automation tool.
    fast-recon - Perform Google dorks against a domain.
    pagodo - Automate Google Hacking Database scraping.
    snitch - Information gathering via dorks.



Metadata harvesting and analysis

    FOCA (Fingerprinting Organizations with Collected Archives) - Automated document harvester that searches Google, Bing, and DuckDuckGo to find and extrapolate internal company organizational structures.
    metagoofil - Metadata harvester.
    theHarvester - E-mail, subdomain and people names harvester.

Network device discovery tools

    AQUATONE - Subdomain discovery tool utilizing various open sources producing a report that can be used as input to other tools.
    Censys - Collects data on hosts and websites through daily ZMap and ZGrab scans.
    OWASP Amass - Subdomain enumeration via scraping, web archives, brute forcing, permutations, reverse DNS sweeping, TLS certificates, passive DNS data sources, etc.
    Shodan - World's first search engine for Internet-connected devices.
    ZoomEye - Search engine for cyberspace that lets the user find specific network components.



Online Open Sources Intelligence (OSINT) Resources

    CertGraph - Crawls a domain's SSL/TLS certificates for its certificate alternative names.
    GhostProject - Searchable database of billions of cleartext passwords, partially visible for free.
    Intel Techniques - Collection of OSINT tools. Menu on the left can be used to navigate through the categories.
    NetBootcamp OSINT Tools - Collection of OSINT links and custom Web interfaces to other services.
    OSINT Framework - Collection of various OSINT tools broken out by category.
    WiGLE.net - Information about wireless networks world-wide, with user-friendly desktop and web applications.







Online Penetration Testing Resources

Metasploit Unleashed - Free Offensive Security Metasploit course.
PENTEST-WIKI - Free online security knowledge library for pentesters and researchers.

Penetration Testing Execution Standard (PTES) - Documentation designed to provide a common language and scope for performing and reporting the results of a penetration test.
Penetration Testing Framework (PTF) - Outline for performing penetration tests compiled as a general framework usable by vulnerability analysts and penetration testers alike.
XSS-Payloads - Resource dedicated to all things XSS (cross-site), including payloads, tools, games, and documentation.












