#!/bin/bash
#title           :	kali_information-gathering.sh
#description     :	This script will create a technical security information gathering report on kali linux.
#author          :	Henry den Hengst
#date            :	20 October 2015
#version         :	0.1 (pseudoscripting fase)
#usage           :	bash kali_information-gathering.sh
#URL             :	-
#user_password   :	-
#notes           :	This script is not intended to be a perfect information gathering test. It's intended to be used to
#	    		create a technical security baseline report about the security situation of a certain envirronment. 
#			Depending on the outcome it can be advised or not to have an additional manual information gathering test.
#bash_version    :	-
#credits_source  :	http://tools.kali.org/tools-listing 
#
#
# VARIABLES DECLARATION:
IP001 = "192.168.0.1"
IP002 = "192.168.10.150"
MAC001 = "00:1E:F7:28:9C:8e"
DOMAIN001 = "microsoft.com"
DOMAIN002 = "example.com"
#
#
# TOOLS:
#
# CaseFile
# CaseFile is the little brother to Maltego. It targets a unique market of ‘offline’ analysts whose primary sources of information are not gained from the open-source intelligence side or can be programmatically queried. We see these people as investigators and analysts who are working ‘on the ground’, getting intelligence from other people in the team and building up an information map of their investigation.
# CaseFile gives you the ability to quickly add, link and analyze data having the same graphing flexibility and performance as Maltego without the use of transforms. CaseFile is roughly a third of the price of Maltego.
# What does CaseFile do? CaseFile is a visual intelligence application that can be used to determine the relationships and real world links between hundreds of different types of information. It gives you the ability to quickly view second, third and n-th order relationships and find links otherwise undiscoverable with other types of intelligence tools. CaseFile comes bundled with many different types of entities that are commonly used in investigations allowing you to act quickly and efficiently. CaseFile also has the ability to add custom entity types allowing you to extend the product to your own data sets.
# What can CaseFile do for me? CaseFile can be used for the information gathering, analytics and intelligence phases of almost all types of investigates, from IT Security, Law enforcement and any data driven work. It will save you time and will allow you to work more accurately and smarter. CaseFile has the ability to visualise datasets stored in CSV, XLS and XLSX spreadsheet formats. We are not marketing people. Sorry. CaseFile aids you in your thinking process by visually demonstrating interconnected links between searched items. If access to “hidden” information determines your success, CaseFile can help you discover it.
#
# run multiple programs by using "prog1" &
casefile &
#
# Cookie Cadger
# Cookie Cadger helps identify information leakage from applications that utilize insecure HTTP GET requests.
# Web providers have started stepping up to the plate since Firesheep was released in 2010. Today, most major websites can provide SSL/TLS during all transactions, preventing cookie data from leaking over wired Ethernet or insecure Wi-Fi. But the fact remains that Firesheep was more of a toy than a tool. Cookie Cadger is the first open-source pen-testing tool ever made for intercepting and replaying specific insecure HTTP GET requests into a browser.
# Cookie Cadgers Request Enumeration Abilities. Cookie Cadger is a graphical utility which harnesses the power of the Wireshark suite and Java to provide a fully cross-platform, entirely open- source utility which can monitor wired Ethernet, insecure Wi-Fi, or load a packet capture file for offline analysis.
#
# run multiple programs by using "prog2" &
cookie-cadger &
#
# Ghost Phisher
# Ghost Phisher is a Wireless and Ethernet security auditing and attack software program written using the Python Programming Language and the Python Qt GUI library, the program is able to emulate access points and deploy.
#
# run multiple programs by using "prog3" &
ghost-phisher &
#
# Recon-ng
# Recon-ng is a full-featured Web Reconnaissance framework written in Python. Complete with independent modules, database interaction, built in convenience functions, interactive help, and command completion, Recon-ng provides a powerful environment in which open source web-based reconnaissance can be conducted quickly and thoroughly.
# Recon-ng has a look and feel similar to the Metasploit Framework, reducing the learning curve for leveraging the framework. However, it is quite different. Recon-ng is not intended to compete with existing frameworks, as it is designed exclusively for web-based open source reconnaissance. If you want to exploit, use the Metasploit Framework. If you want to Social Engineer, us the Social Engineer Toolkit. If you want to conduct reconnaissance, use Recon-ng! See the Usage Guide for more information.
# Recon-ng is a completely modular framework and makes it easy for even the newest of Python developers to contribute. Each module is a subclass of the “module” class. The “module” class is a customized “cmd” interpreter equipped with built-in functionality that provides simple interfaces to common tasks such as standardizing output, interacting with the database, making web requests, and managing API keys. Therefore, all the hard work has been done. Building modules is simple and takes little more than a few minutes. 
#
# run multiple programs by using "prog4" &
recon-ng  &
#
# SET
# The Social-Engineer Toolkit is an open-source penetration testing framework designed for Social-Engineering. SET has a number of custom attack vectors that allow you to make a believable attack in a fraction of the time.
#
# run multiple programs by using "prog5" &
setoolkit &
#
# Wireshark
# Wireshark is the world’s foremost network protocol analyzer. It lets you see what’s happening on your network at a microscopic level. It is the de facto (and often de jure) standard across many industries and educational institutions. Wireshark development thrives thanks to the contributions of networking experts across the globe. It is the continuation of a project that started in 1998.
# WIRESHARK USAGE EXAMPLE
#
# run multiple programs by using "prog6" &
wireshark &
#
#
#
# SCRIPTS:
#
# accceck
# The tool is designed as a password dictionary attack tool that targets windows authentication via the SMB protocol. It is really a wrapper script around the ‘smbclient’ binary, and as a result is dependent on it for its execution.
#
### MAKE SURE THAT smb-ips.txt IS THERE AND REPRESENTATIVE, HOW?
acccheck.pl -T smb-ips.txt -v >> INFORMATION_GATHERING.txt
#
# Wireshark
# Wireshark is the world’s foremost network protocol analyzer. It lets you see what’s happening on your network at a microscopic level. It is the de facto (and often de jure) standard across many industries and educational institutions. Wireshark development thrives thanks to the contributions of networking experts across the globe. It is the continuation of a project that started in 1998.
# TSHARK USAGE EXAMPLE
tshark -f "tcp port 80" -i eth0
#
# ace-voip / ACE v1.0: Automated Corporate (Data) Enumerator
# ACE (Automated Corporate Enumerator) is a simple yet powerful VoIP Corporate Directory enumeration tool that mimics the behavior of an IP Phone in order to download the name and extension entries that a given phone can display on its screen interface. In the same way that the “corporate directory” feature of VoIP hardphones enables users to easily dial by name via their VoIP handsets, ACE was developed as a research idea born from “VoIP Hopper” to automate VoIP attacks that can be targeted against names in an enterprise Directory. The concept is that in the future, attacks will be carried out against users based on their name, rather than targeting VoIP traffic against random RTP audio streams or IP addresses. ACE works by using DHCP, TFTP, and HTTP in order to download the VoIP corporate directory. It then outputs the directory to a text file, which can be used as input to other VoIP assessment tools.
# Usage: ace [-i interface] [ -m mac address ] [ -t tftp server ip address | -c cdp mode | -v voice vlan id | -r vlan interface | -d verbose mode ]
# -i (Mandatory) Interface for sniffing/sending packets
# -m (Mandatory) MAC address of the victim IP phone
# -t (Optional) tftp server ip address
# -c (Optional) 0 CDP sniff mode, 1 CDP spoof mode
# -v (Optional) Enter the voice vlan ID
# -r (Optional) Removes the VLAN interface
# -d (Optional) Verbose | debug mode
# 
# Usage requires MAC Address of IP Phone supplied with -m option, Usage: 
ace -t -m 
#
# Mode to automatically discover TFTP Server IP via DHCP Option 150 (-m), Example: 
ace -i eth0 -m 00:1E:F7:28:9C:8e
# 
# Mode to specify IP Address of TFTP Server Example: 
ace -i eth0 -t 192.168.10.150 -m 00:1E:F7:28:9C:8e
#
# Mode to specify the Voice VLAN ID Example: 
ace -i eth0 -v 96 -m 00:1E:F7:28:9C:8E
# 
# Verbose mode Example: 
ace -i eth0 -v 96 -m 00:1E:F7:28:9C:8E -d
# 
# Mode to remove vlan interface Example: 
ace -r eth0.96
# 
# Mode to auto-discover voice vlan ID in the listening mode for CDP Example: 
ace -i eth0 -c 0 -m 00:1E:F7:28:9C:8E
# 
# Mode to auto-discover voice vlan ID in the spoofing mode for CDP Example: 
ace -i eth0 -c 1 -m 00:1E:F7:28:9C:8E
#
# Amap
# Amap was the first next-generation scanning tool for pentesters. It attempts to identify applications even if they are running on a different port than normal. It also identifies non-ascii based applications. This is achieved by sending trigger packets, and looking up the responses in a list of response strings.
#
amap -bqv 192.168.1.15 80
#
# Automater
# Automater is a URL/Domain, IP Address, and Md5 Hash OSINT tool aimed at making the analysis process easier for intrusion Analysts. Given a target (URL, IP, or HASH) or a file full of targets Automater will return relevant results from sources like the following: IPvoid.com, Robtex.com, Fortiguard.com, unshorten.me, Urlvoid.com, Labs.alienvault.com, ThreatExpert, VxVault, and VirusTotal.
#
automater -s robtex 50.116.53.73
#
# bing-ip2hosts
# Bing.com is a search engine owned by Microsoft formerly known as MSN Search and Live Search. It has a unique feature to search for websites hosted on a specific IP address. Bing-ip2hosts uses this feature to enumerate all hostnames which Bing has indexed for a specific IP address. This technique is considered best practice during the reconnaissance phase of a penetration test in order to discover a larger potential attack surface. Bing-ip2hosts is written in the Bash scripting language for Linux. This uses the mobile interface and no API key is required.
#
bing-ip2hosts -p microsoft.com
bing-ip2hosts -p 173.194.33.80
#
# braa
# Braa is a mass snmp scanner. The intended usage of such a tool is of course making SNMP queries – but unlike snmpget or snmpwalk from net-snmp, it is able to query dozens or hundreds of hosts simultaneously, and in a single process. Thus, it consumes very few system resources and does the scanning VERY fast.
# Braa implements its OWN snmp stack, so it does NOT need any SNMP libraries like net-snmp. The implementation is very dirty, supports only several data types, and in any case cannot be stated ‘standard-conforming’! It was designed to be fast, and it is fast. For this reason (well, and also because of my laziness ;), there is no ASN.1 parser in braa – you HAVE to know the numerical values of OID’s (for instance .1.3.6.1.2.1.1.5.0 instead of system.sysName.0).
#
braa public@192.168.1.215:.1.3.6.*
#
# CDPSnarf
# CDPSnarf is a network sniffer exclusively written to extract information from CDP packets. It provides all the information a “show cdp neighbors detail” command would return on a Cisco router and even more.
#
cdpsnarf -i eth0 -w cdpsnarf.pcap
#
# cisco-torch
# Cisco Torch mass scanning, fingerprinting, and exploitation tool was written while working on the next edition of the “Hacking Exposed Cisco Networks”, since the tools available on the market could not meet our needs. The main feature that makes Cisco-torch different from similar tools is the extensive use of forking to launch multiple scanning processes on the background for maximum scanning efficiency. Also, it uses several methods of application layer fingerprinting simultaneously, if needed. We wanted something fast to discover remote Cisco hosts running Telnet, SSH, Web, NTP and SNMP services and launch dictionary attacks against the services discovered.
cisco-torch -A 192.168.99.202
#
# copy-router-config
# Copies configuration files from Cisco devices running SNMP.
# COPY-ROUTER-CONFIG USAGE EXAMPLE
copy-router-config.pl 192.168.1.1 192.168.1.15 private
# MERGE-ROUTER-CONFIG USAGE EXAMPLE(S)
merge-router-config.pl 192.168.1.1 192.168.1.15 private
#
# DMitry
# DMitry (Deepmagic Information Gathering Tool) is a UNIX/(GNU)Linux Command Line Application coded in C. DMitry has the ability to gather as much information as possible about a host. Base functionality is able to gather possible subdomains, email addresses, uptime information, tcp port scan, whois lookups, and more.
dmitry -winsepo example.txt example.com
#
# dnmap
# dnmap is a framework to distribute nmap scans among several clients. It reads an already created file with nmap commands and send those commands to each client connected to it. The framework use a client/server architecture. The server knows what to do and the clients do it. All the logic and statistics are managed in the server. Nmap output is stored on both server and client. Usually you would want this if you have to scan a large group of hosts and you have several different internet connections (or friends that want to help you).
# DNMAP_SERVER USAGE EXAMPLE
echo "nmap -F 192.168.1.0/24 -v -n -oA sub1" >> dnmap.txt
echo "nmap -F 192.168.0.0/24 -v -n -oA sub0" >> dnmap.txt
dnmap_server -f dnmap.txt
# DNMAP_CLIENT USAGE EXAMPLE
dnmap_client -s 192.168.1.15 -a dnmap-client1
#
# dnsenum
# Multithreaded perl script to enumerate DNS information of a domain and to discover non-contiguous ip blocks.
dnsenum --noreverse -o mydomain.xml example.com
#
# dnsmap
# dnsmap was originally released back in 2006 and was inspired by the fictional story “The Thief No One Saw” by Paul Craig, which can be found in the book “Stealing the Network – How to 0wn the Box”.
# dnsmap is mainly meant to be used by pentesters during the information gathering/enumeration phase of infrastructure security assessments. During the enumeration stage, the security consultant would typically discover the target company’s IP netblocks, domain names, phone numbers, etc …
# Subdomain brute-forcing is another technique that should be used in the enumeration stage, as it’s especially useful when other domain enumeration techniques such as zone transfers don’t work (I rarely see zone transfers being publicly allowed these days by the way).
#
# DNSMAP USAGE EXAMPLE
dnsmap example.com -w /usr/share/wordlists/dnsmap.txt
#
# DNSMAP-BULK USAGE EXAMPLE
echo "example.com" >> domains.txt
echo "example.org" >> domains.txt
dnsmap-bulk.sh domains.txt
#
# DNSRecon
# DNSRecon provides the ability to perform: Check all NS Records for Zone Transfers, Enumerate General DNS Records for a given Domain (MX, SOA, NS, A, AAAA, SPF and TXT), Perform common SRV Record Enumeration. Top Level Domain (TLD) Expansion, Check for Wildcard Resolution, Brute Force subdomain and host A and AAAA records given a domain and a wordlist, Perform a PTR Record lookup for a given IP Range or CIDR, Check a DNS Server Cached records for A, AAAA and CNAME Records provided a list of host records in a text file to check, Enumerate Common mDNS records in the Local Network Enumerate Hosts and Subdomains using Google.
#
dnsrecon -d example.com -D /usr/share/wordlists/dnsmap.txt -t std --xml dnsrecon.xml
#
# dnstracer
# dnstracer determines where a given Domain Name Server (DNS) gets its information from for a given hostname, and follows the chain of DNS servers back to the authoritative answer.
#
dnstracer -r 3 -v example.com
#
# dnswalk
# dnswalk is a DNS debugger. It performs zone transfers of specified domains, and checks the database in numerous ways for internal consistency, as well as accuracy.
#
dnswalk example.com
#
dnswalk -r -d example.com
#
# DotDotPwn
# It’s a very flexible intelligent fuzzer to discover traversal directory vulnerabilities in software such as HTTP/FTP/TFTP servers, Web platforms such as CMSs, ERPs, Blogs, etc. Also, it has a protocol-independent module to send the desired payload to the host and port specified. On the other hand, it also could be used in a scripting way using the STDOUT module. It’s written in perl programming language and can be run either under *NIX or Windows platforms. It’s the first Mexican tool included in BackTrack Linux (BT4 R2).
#
dotdotpwn.pl -m http -h 192.168.1.1 -M GET
#
# enum4linux
A Linux alternative to enum.exe for enumerating data from Windows and Samba hosts. Enum4linux is a tool for enumerating information from Windows and Samba systems. It attempts to offer similar functionality to enum.exe formerly available from www.bindview.com. It is written in Perl and is basically a wrapper around the Samba tools smbclient, rpclient, net and nmblookup. The tool usage can be found below followed by examples, previous versions of the tool can be found at the bottom of the page.
#
enum4linux -U -o 192.168.1.200
#
# enumIAX
# enumIAX is an Inter Asterisk Exchange protocol username brute-force enumerator. enumIAX may operate in two distinct modes; Sequential Username Guessing or Dictionary Attack.
#
enumiax -d /usr/share/wordlists/metasploit/unix_users.txt 192.168.1.1
#
# exploitdb
# Searchable archive from The Exploit Database.
#
searchsploit oracle windows remote
#
# Fierce
# First what Fierce is not. Fierce is not an IP scanner, it is not a DDoS tool, it is not designed to scan the whole Internet or perform any un-targeted attacks. It is meant specifically to locate likely targets both inside and outside a corporate network. Only those targets are listed (unless the -nopattern switch is used). No exploitation is performed (unless you do something intentionally malicious with the -connect switch). Fierce is a reconnaissance tool. Fierce is a PERL script that quickly scans domains (usually in just a few minutes, assuming no network lag) using several tactics.
#
fierce -dns example.com
#
# Firewalk
Firewalk is an active reconnaissance network security tool that attempts to determine what layer 4 protocols a given IP forwarding device will pass. Firewalk works by sending out TCP or UDP packets with a TTL one greater than the targeted gateway. If the gateway allows the traffic, it will forward the packets to the next hop where they will expire and elicit an ICMP_TIME_EXCEEDED message. If the gateway hostdoes not allow the traffic, it will likely drop the packets on the floor and we will see no response.
# To get the correct IP TTL that will result in expired packets one beyond the gateway we need to ramp up hop-counts. We do this in the same manner that traceroute works. Once we have the gateway hopcount (at that point the scan is said to be `bound`) we can begin our scan.
# It is significant to note the fact that the ultimate destination host does not have to be reached. It just needs to be somewhere downstream, on the other side of the gateway, from the scanning host.
#
firewalk -S8079-8081  -i eth0 -n -pTCP 192.168.1.1 192.168.0.1
#
# fragroute
# fragroute intercepts, modifies, and rewrites egress traffic destined for a specified host, implementing most of the attacks described in the Secure Networks “Insertion, Evasion, and Denial of Service: Eluding Network Intrusion Detection” paper of January 1998.
# It features a simple ruleset language to delay, duplicate, drop, fragment, overlap, print, reorder, segment, source-route, or otherwise monkey with all outbound packets destined for a target host, with minimal support for randomized or probabilistic behaviour.
# This tool was written in good faith to aid in the testing of network intrusion detection systems, firewalls, and basic TCP/IP stack behaviour. Please do not abuse this software.
#
# FRAGROUTE USAGE EXAMPLE
fragroute 192.168.1.123
# FRAGTEST USAGE EXAMPLE
fragtest ip-tracert frag-new 192.168.1.123
#
# fragrouter
# Fragrouter is a network intrusion detection evasion toolkit. It implements most of the attacks described in the Secure Networks “Insertion, Evasion, and Denial of Service: Eluding Network Intrusion Detection” paper of January 1998.
# This program was written in the hopes that a more precise testing methodology might be applied to the area of network intrusion detection, which is still a black art at best.
# Conceptually, fragrouter is just a one-way fragmenting router – IP packets get sent from the attacker to the fragrouter, which transforms them into a fragmented data stream to forward to the victim.
#
fragrouter -i eth0 -F1
#
# GoLismero
# GoLismero is an open source framework for security testing. It’s currently geared towards web security, but it can easily be expanded to other kinds of scans.
#
golismero scan -i /root/port80.xml -o sub1-port80.html
#
# goofile
# Use this tool to search for a specific file type in a given domain.
#
goofile -d kali.org -f pdf
#
# hping3
# hping is a command-line oriented TCP/IP packet assembler/analyzer. The interface is inspired to the ping(8) unix command, but hping isn’t only able to send ICMP echo requests. It supports TCP, UDP, ICMP and RAW-IP protocols, has a traceroute mode, the ability to send files between a covered channel, and many other features.
# While hping was mainly used as a security tool in the past, it can be used in many ways by people that don’t care about security to test networks and hosts. A subset of the stuff you can do using hping: Firewall testing, Advanced port scanning, Network testing, using different protocols, TOS, fragmentation, Manual path MTU discovery, Advanced traceroute, under all the supported protocols, Remote OS fingerprinting, Remote uptime guessing, TCP/IP stacks auditing, hping can also be useful to students that are learning TCP/IP.
#
hping3 --traceroute -V -1 www.example.com
#
# InTrace
# InTrace is a traceroute-like application that enables users to enumerate IP hops exploiting existing TCP connections, both initiated from local network (local system) or from remote hosts. It could be useful for network reconnaissance and firewall bypassing.
#
intrace -h www.example.com -p 80 -s 4
#
# iSMTP
# Test for SMTP user enumeration (RCPT TO and VRFY), internal spoofing, and relay.
#
ismtp -f smtp-ips.txt -e /usr/share/wordlists/metasploit/unix_users.txt
#
# lbd
# lbd (load balancing detector) detects if a given domain uses DNS and/or HTTP Load-Balancing (via Server: and Date: header and diffs between server answers).
#
lbd example.com
#
# Maltego Teeth
# Maltego is a unique platform developed to deliver a clear threat picture to the environment that an organization owns and operates. Maltego’s unique advantage is to demonstrate the complexity and severity of single points of failure as well as trust relationships that exist currently within the scope of your infrastructure.
# The unique perspective that Maltego offers to both network and resource based entities is the aggregation of information posted all over the internet – whether it’s the current configuration of a router poised on the edge of your network or the current whereabouts of your Vice President on his international visits, Maltego can locate, aggregate and visualize this information.
#
cat /opt/Teeth/README.txt 
#
# masscan
# This is the fastest Internet port scanner. It can scan the entire Internet in under 6 minutes, transmitting 10 million packets per second. It produces results similar to nmap, the most famous port scanner. Internally, it operates more like scanrand, unicornscan, and ZMap, using asynchronous transmission. The major difference is that it’s faster than these other scanners. In addition, it’s more flexible, allowing arbitrary address ranges and port ranges.
# NOTE: masscan uses a custom TCP/IP stack. Anything other than simple port scans will cause conflict with the local TCP/IP stack. This means you need to either use the -S option to use a separate IP address, or configure your operating system to firewall the ports that masscan uses.
#
masscan -p22,80,445 192.168.1.0/24
#
# Metagoofil
# Metagoofil is an information gathering tool designed for extracting metadata of public documents (pdf,doc,xls,ppt,docx,pptx,xlsx) belonging to a target company. Metagoofil will perform a search in Google to identify and download the documents to local disk and then will extract the metadata with different libraries like Hachoir, PdfMiner? and others. With the results it will generate a report with usernames, software versions and servers or machine names that will help Penetration testers in the information gathering phase.
#
metagoofil -d kali.org -t pdf -l 100 -n 25 -o kalipdf -f kalipdf.html
#
# Miranda
# Miranda is a Python-based Universal Plug-N-Play client application designed to discover, query and interact with UPNP devices, particularly Internet Gateway Devices (aka, routers). It can be used to audit UPNP-enabled devices on a network for possible vulnerabilities.
#
miranda -i eth0 -v
#
# Nmap
# Nmap (“Network Mapper”) is a free and open source (license) utility for network discovery and security auditing. Many systems and network administrators also find it useful for tasks such as network inventory, managing service upgrade schedules, and monitoring host or service uptime. Nmap uses raw IP packets in novel ways to determine what hosts are available on the network, what services (application name and version) those hosts are offering, what operating systems (and OS versions) they are running, what type of packet filters/firewalls are in use, and dozens of other characteristics. It was designed to rapidly scan large networks, but works fine against single hosts. Nmap runs on all major computer operating systems, and official binary packages are available for Linux, Windows, and Mac OS X. In addition to the classic command-line Nmap executable, the Nmap suite includes an advanced GUI and results viewer (Zenmap), a flexible data transfer, redirection, and debugging tool (Ncat), a utility for comparing scan results (Ndiff), and a packet generation and response analysis tool (Nping).
#
nmap -v -A -sV 192.168.1.1
nping --tcp -p 22 --flags syn --ttl 2 192.168.1.1
ndiff yesterday.xml today.xml
ncat -v --exec "/bin/bash" --allow 192.168.1.123 -l 4444 --keep-open
#
# ntop
# ntop is a tool that shows the network usage, similar to what the popular top Unix command does. ntop is based on pcapture (ftp://ftp.ee.lbl.gov/pcapture.tar.Z) and it has been written in a portable way in order to virtually run on every Unix platform.
# ntop can be used in both interactive or web mode. In the first case, ntop displays the network status on the user’s terminal whereas in web mode a web browser (e.g. netscape) can attach to ntop (that acts as a web server) and get a dump of the network status. In the latter case, ntop can be seen as a simple RMON-like agent with an embedded web interface.
# ntop uses libpcap, a system-independent interface for user-level packet capture.
ntop -B "src host 192.168.1.1"
#
# p0f
# P0f is a tool that utilizes an array of sophisticated, purely passive traffic fingerprinting mechanisms to identify the players behind any incidental TCP/IP communications (often as little as a single normal SYN) without interfering in any way. Version 3 is a complete rewrite of the original codebase, incorporating a significant number of improvements to network-level fingerprinting, and introducing the ability to reason about application-level payloads (e.g., HTTP).
#
p0f -i eth0 -p -o /tmp/p0f.log
#
# Parsero
# Parsero is a free script written in Python which reads the Robots.txt file of a web server and looks at the Disallow entries. The Disallow entries tell the search engines what directories or files hosted on a web server mustn’t be indexed. For example, “Disallow: /portal/login” means that the content on www.example.com/portal/login it’s not allowed to be indexed by crawlers like Google, Bing, Yahoo… This is the way the administrator have to not share sensitive or private information with the search engines. But sometimes these paths typed in the Disallows entries are directly accessible by the users without using a search engine, just visiting the URL and the Path, and sometimes they are not available to be visited by anybody… Because it is really common that the administrators write a lot of Disallows and some of them are available and some of them are not, you can use Parsero in order to check the HTTP status code of each Disallow entry in order to check automatically if these directories are available or not. Also, the fact the administrator write a robots.txt, it doesn’t mean that the files or directories typed in the Dissallow entries will not be indexed by Bing, Google, Yahoo… For this reason, Parsero is capable of searching in Bing to locate content indexed without the web administrator authorization. Parsero will check the HTTP status code in the same way for each Bing result.
#
parsero -u www.bing.com -sb
#
# smtp-user-enum
# smtp-user-enum is a tool for enumerating OS-level user accounts on Solaris via the SMTP service (sendmail). Enumeration is performed by inspecting the responses to VRFY, EXPN and RCPT TO commands. It could be adapted to work against other vulnerable SMTP daemons, but this hasn’t been done as of v1.0.
#
smtp-user-enum -M VRFY -u root -t 192.168.1.25
#
# snmpcheck
# Like to snmpwalk, snmpcheck allows you to enumerate the SNMP devices and places the output in a very human readable friendly format. It could be useful for penetration testing or systems monitoring. Distributed under GPL license and based on “Athena-2k” script by jshaw.
#
snmpcheck -t 192.168.1.2 -c public
#
# sslcaudit
The goal of sslcaudit project is to develop a utility to automate testing SSL/TLS clients for resistance against MITM attacks. It might be useful for testing a thick client, a mobile application, an appliance, pretty much anything communicating over SSL/TLS over TCP.
#
sslcaudit -l 0.0.0.0:443 -v 1
#
# SSLsplit
# SSLsplit is a tool for man-in-the-middle attacks against SSL/TLS encrypted network connections. Connections are transparently intercepted through a network address translation engine and redirected to SSLsplit. SSLsplit terminates SSL/TLS and initiates a new SSL/TLS connection to the original destination address, while logging all data transmitted. SSLsplit is intended to be useful for network forensics and penetration testing.
# SSLsplit supports plain TCP, plain SSL, HTTP and HTTPS connections over both IPv4 and IPv6. For SSL and HTTPS connections, SSLsplit generates and signs forged X509v3 certificates on-the-fly, based on the original server certificate subject DN and subjectAltName extension. SSLsplit fully supports Server Name Indication (SNI) and is able to work with RSA, DSA and ECDSA keys and DHE and ECDHE cipher suites. SSLsplit can also use existing certificates of which the private key is available, instead of generating forged ones. SSLsplit supports NULL-prefix CN certificates and can deny OCSP requests in a generic way. SSLsplit removes HPKP response headers in order to prevent public key pinning.
# 
sslsplit -D -l connections.log -j /tmp/sslsplit/ -S /tmp/ -k ca.key -c ca.crt ssl 0.0.0.0 8443 tcp 0.0.0.0 8080
#
# sslstrip
# sslstrip is a tool that transparently hijacks HTTP traffic on a network, watch for HTTPS links and redirects, and then map those links into look-alike HTTP links or homograph-similar HTTPS links. It also supports modes for supplying a favicon which looks like a lock icon, selective logging, and session denial.
#
sslstrip -w sslstrip.log -l 8080
#
# SSLyze
# SSLyze is a Python tool that can analyze the SSL configuration of a server by connecting to it. It is designed to be fast and comprehensive, and should help organizations and testers identify misconfigurations affecting their SSL servers.
#
sslyze --regular www.example.com
#
# THC-IPV6
# A complete tool set to attack the inherent protocol weaknesses of IPV6 and ICMP6, and includes an easy to use packet factory library.
#
# ADDRESS6 USAGE EXAMPLE
address6 fe80::76d4:35ff:fe4e:39c8
# ALIVE6 USAGE EXAMPLE
alive6 eth0
# DETECT-NEW-IP6 USAGE EXAMPLE
detect-new-ip6 eth0
# DNSDICT6 USAGE EXAMPLE
dnsdict6 example.com
#
# theHarvester
# The objective of this program is to gather emails, subdomains, hosts, employee names, open ports and banners from different public sources like search engines, PGP key servers and SHODAN computer database.
# This tool is intended to help Penetration testers in the early stages of the penetration test in order to understand the customer footprint on the Internet. It is also useful for anyone that wants to know what an attacker can see about their organization.
theharvester -d kali.org -l 500 -b google
#
# TLSSLed
# TLSSLed is a Linux shell script whose purpose is to evaluate the security of a target SSL/TLS (HTTPS) web server implementation. It is based on sslscan, a thorough SSL/TLS scanner that is based on the openssl library, and on the “openssl s_client” command line tool. The current tests include checking if the target supports the SSLv2 protocol, the NULL cipher, weak ciphers based on their key length (40 or 56 bits), the availability of strong ciphers (like AES), if the digital certificate is MD5 signed, and the current SSL/TLS renegotiation capabilities.
#
tlssled 192.168.1.1 443
#
# URLCrazy
# Generate and test domain typos and variations to detect and perform typo squatting, URL hijacking, phishing, and corporate espionage.
#
urlcrazy -k dvorak -r example.com
#
# WOL-E
# WOL-E is a suite of tools for the Wake on LAN feature of network attached computers, this is now enabled by default on many Apple computers.
#
wol-e -f
#
# Xplico
# The goal of Xplico is extract from an internet traffic capture the applications data contained. For example, from a pcap file Xplico extracts each email (POP, IMAP, and SMTP protocols), all HTTP contents, each VoIP call (SIP, MGCP, H323), FTP, TFTP, and so on. Xplico is not a network protocol analyzer.
#
xplico -m rltm -i eth0
