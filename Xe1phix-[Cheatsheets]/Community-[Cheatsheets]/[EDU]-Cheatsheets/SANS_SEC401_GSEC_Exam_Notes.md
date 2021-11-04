# Defensible Network Architecture
C:\> ncpa.cpl on cmd prompt on Windows displays Ethernet network settings
To limit the number of ping echo requests, we can use -n in Windows and -c in Linux.
Network Architecture:
Conceptual design: High level, includes core components, black-box diagram, high level systems behavior
Logical design: logical function, more detailed, w/ relationships, for developers & architects, w/ services, apps
Physical design: last before implementation, w/ Hardware, OS, patches, version, locations, physical limitations
Threat enumeration: Process of tracking and understanding critical threats to network or system (List threat agents, Attack methods, system-level objectives)
    Cyber espionage: Not about money, well-funded, APTs | Computer Activist or Hacktivist: do not cover tracks, world must know breach, uncover or expose orgs
Attacks against network devices:
Attacks on Router: DoS | DDoS | Packet sniffing | Packet misrouting (malicious code injected to misroute packets) | Routing table poisoning    		 (Malicious insider / disgruntled employee)
Attacks against Switches:
-	CDP manipulation (Cisco Discovery Protocol): Enabled by default on Cisco switches and are in clear. Attacker analyzes and gains info on n/w device. Then exploits known vulns. Soln: Disable CDP on non-mgmt interface.
-	MAC flooding: Memory table is flooded w/ fictious MAC addresses. Overwhelms storage capacity, switch becomes hub. 
-	DHCP spoofing: MITM for DHCP requests and respond with attacker’s IP as default gateway
-	STP (Spanning Tree Protocol) attacks: STP allows switches to identify each other and prevent communication loops (agree upon re-configurations necessary). Attacks on STP create network loop and therefore DoS.
-	VLAN hopping: Attacker generates fictious characteristics of n/w packet that goes to another VLAN bypassing isolation and segmentation
-	Telnet attack: Distributed SYN attack on telnet (default installed on Windows today, but removed in future)
Network topologies:
Physical: How n/w is connected, how data flows, wired or wireless, star topology common
Logical: Communication on wires, meaning of data exchanges, language used in communication, etc.
A single logical topology can be used with multiple physical topologies.
-	Ethernet is the most common logical topology | chunk of data transmitted is frame 
o	CSMA/CD (Carrier sense multiple access with collision detection) -> check wire before placing frame
o	Full duplex (send and receive simultaneously) 
Network design:
Segmentation: performance & security benefits | multi-layered defense | Least privilege | Whitelisting | Based on requirements
Protected enclave: Defined by common set of security policies (by confidentiality, integrity, availability)
Software defined networking (SDN): Virtual machine or storage / micro-segmentation
Data flow/NetFlow analysis: Method of collecting data on IP traffic characteristics. Provides 24x7 account of n/w activity.
Network sections: Public | Semi-Public (DMZ, contains bastion hosts) | Middleware | Private

# Networking and Protocols
3 purposes for communication protocols: 
-	Standardize the format | specify order or timing | allow parties to determine meaning of communication
OSI 7 layers:  vs TCP/IP: Network layer (1,2) -> Internet layer(3) -> Transport layer(4) -> Application layer (5,6,7)
-	Physical: electrical pulses on wire, radio waves, light pulses of fiber, conn specific info between interface h/w and network cable and voltage regulation
-	Data link: Connects physical part with abstract part
-	Network: n/w address scheme and connectivity of multiple n/w segments
-	Transport: Interaction with data and prepares for its transmission on n/w. End to end reliability needs to be ensured. Handles sequencing of packets in transmission
-	Session: Establishment and maintenance of connection between two systems
-	Presentation: data format sent from one side is received as useful to other side (e.g. compress/decompress)
-	Application: Interacts with application to determine which n/w services are required
Encapsulation (as we go down) and decapsulation (as we go up)
IP (internet protocol): Deals with transmission of packets between endpoints
IPv4 (4.2b unique 32-bit addresses) | IPv6: (340 undecillion 128-bit addresses, Quality of Service offered in the protocol itself)
IPv4 Header: Version (4, but has 16 possible values), IHL (Size), Type of Service (Quality: Importance of delivery, mostly set to 0, Differentiated Services (DS) and Explicit Congestion Notification (ECN)), Total Length (Total packet size), Identification (unique per packet, covert channels use this field), Flags (3 bit), Fragment offset (13 bit, big packet sent as multiple packets with same ID value), TTL (hops / expiry, prevent infinite loop), Protocol (17 for UDP, 6 for TCP, 1 for ICMP), Header checksum (math to check accidently modified packets), Source IP (32 bits), Destination IP (32 bits), Options (optional, up to 40 bytes, with 4byte scale)
IPv6 Header: Version (6), Traffic class & Flow Label (equal to Type of Service in IPv4), Payload length (equal to Total Length in IPv4), Next Header (Equal to Protocol in IPv4), Hop Limit (how many router hops can it go thru, equal to TTL), Source IP (128 bits), Destination IP (128 bits).
-	Benefits of IPv6: Tunneling (IPv6 over IPv4), Translation (IPv4 over IPv6), Authn of endpoints, Encryption

ICMP Header: Type (1 byte), Code (1 byte), ICMP Checksum (2 bytes), ICMP Payload (variable length)
-	Tied to IP version (ICMPv6 for IPv6)
-	Type value: 5 makes MITM possible (attack); It is about redirecting away from trusted channel

TCP: 3-way handshake using SYN, SYN/ACK, ACK by use of ISN (Initial Sequence Numbers). Client uses >= 1024 ports (ephemeral) and server uses <=1023 ports (reserved)
TCP graceful 4-way handshake to close session: FIN, ACK, FIN, ACK | Abrupt: RST/ACK from either side (Client or server) 
-	TCP Header: Source port, Destination port, Sequence number, Acknowledgement number, Data offset (header length), Flags (status of connection, SYN, ACK, RST (Abrupt finish), PSH, FIN (graceful finish), URG, ECE, CWR (congestion)), Window size (flow control),  Checksum, Urgent pointer, Options (up to 40 bytes, need to decode to know start & end).

UDP: DNS (53), Bootp (67,68, Auto load OS from n/w during startup), TFTP (69, No Authn, No Encryption, Inter-device file transfer, mostly for routers and switches configuration files), NTP (123), NBT (137-139), SNMP (161,162), NFS (2049, Network File System, file sharing for UNIX based)
-	UDP Header: Source port (2 bytes), Destination port (2 bytes), Length (2 bytes, Datagram length: UDP header+payload), Checksum (2 bytes) and Data (variable length) 

tcpdump: dependent on libpcap packet capture utility / Not a protocol-analysis tool (-s0 sets to default snapshot length is 262,144 bytes)
-	X: gives both ASCII and Hexadecimal values in output
Network device security
Hub: Operates at Physical layer, just replicates, no security
Bridges & Switches: Operate at Data link layer, verifies MAC addresses before forwarding packets
Routers: Operate at network layer, enables communication from one network to another

Sniffers: tcpdump (initial triage) | wireshark (detailed analysis/packet decoding, a protocol analyzer) | snort (NIDS to determine scope of compromise) | dsniff (useful for sniff on switch by abusing ARP & MITM) | kismet (wireless n/w sniffer and IDS)

ARP: Broadcasting IP to ask for MAC address (48 bit). 
Router IOS (internetwork operating system) to be kept updated.
-	Source routing: Allowing IP packets to specify routing (attackers can advantage of this)
-	Directed broadcast: is to specific IP like 10.1.1.255 for 10.1.1.0/24 network & Limited broadcast is 255.255.255.255
-	Telnet or SSH: 
Hardening Switches: Create VLAN (a software form of Bridge devices) and add NAC (n/w access control lists) for communication between VLANs.
-	NAC can dynamically allocate VLANs, performs health checks of systems (installed patches, baseline checks) and authenticate user or systems
-	802.1X: Network level authentication (to allow only authorized systems to connect to switch): Both wired and wireless.
Network security devices
Firewall: Types: Packet (network layer, but relies on TCP flags to determine state of connection. E.g. Packet with ACK flag is assumed as pre-established connection and goes thru) | Stateful (Transport layer, has state table with source ip,port and dest ip,port) | Proxy or Application Gateway (Application layer, has user session information) | Circuit level gateways: Monitor TCP cons (not payload) to determine legitimate. 

Data diodes: Semiconductor device w/ 2 terminals, w/ flow of current in uni-direction (e.g. flow from public to secret)
Unidirectional gateways (often used in Industrial control systems), multiple network cards / physically one-way capability

NIDS: Alerts are generated from EOI (Events of Interest). Must analyze is alerts: TP/FP/TN/FN: A false negative is breach
Uses signature (pattern matching, rules applied, alerts when matches are found, flexibility in rules is imp), anomaly (Baseline of network is performed, flags anomalous conditions in traffic, can catch zero-day), application/protocol analysis (know app logic, not normal protocol is flagged, difficult to impl) to detect intrusions
-	Deep (slow, stateful tracking, all fields w/ variable-length fields) vs Shallow (fast, header + limited payload) inspection
-	Attackers try to denormalize traffic to evade detection (IDS normalize data for known protocols)
-	Can be more aggressive in detecting attacks than preventive
-	But… cannot analyze encrypted traffic, very costly, Quantity vs quality of signatures, performance limitations w/ analysis
Snort: Open source IDS, Flexible for custom rules, Options: Pass, Log, Alert, Activate, Dynamic; Run options: Sniff-Only, IDS
      /etc/snort/snort.conf      &      /etc/snort/rules   & /var/log/snort/alert (cat alert) and /var/log/snort/snort.log (xxd snort.log)
-	TFTP (UDP port: 69),  snort content: 00 01 means TFTP GET req and 00 02 means TFTP PUT req  (content: !”|00|”; )
$snort -c /etc/snort/snort.conf -r  /root/Labs/401.3/snort/snort.pcap -A full

Key points for IDS: 
-	Train ops staff, high end skill | Buy mgmt. console & populate with passive sniffer | Consider a SIEM solution | Be prepared with IR and supportive policies  | ROI calculation, inhouse or outsourced IDS     
New dev in NIDS: False positive reduction by OS identification, IDS for WiFi, Integration with n/w devices, alert priority by vuln scan 
IPS: Network IPS (NIPS) or Host IPS (HIPS), a supplement to IDS (not a replacement). 
-	Deployed behind a f/w, NIPS can also detect infected internal hosts.
-	Uses custom ASIC (App specific integrated circuits) for high-speed analysis with complex inspection
-	Hierarchical rule classification schemes are used to classify and identify traffic
-	IPS cannot identify as many attacks as IDS, due to false positives issues
New dev in NIPS: Better thruput & response times (near realtime analysis), Automate analysis and signature update, passive analysis (network architecture/OS/vuln info learning mode), Protocol srubbing / rate limiting / policy enforcement

Internet -> Router (Block invalid IP) -> NIPS -> Firewall (stateful) -> NIDS -> HIDS -> Application controls

Virtualization and Cloud Security
Virtualization: Ability to emulate hardware using software | Component that abstracts and emulates hardware is Hypervisor
How virtualization helps security: Isolation (OS and app), Resiliency and High availability, Automation, Data governance, Virtual appliance, Forensic analysis.
How virtualization hinders security: Not 100% separated physically, Resource sharing, Direct memory access

## Attacks on Virtualization: 
Hyperjacking: Taking control of the hypervisor in order to gain access to multiple VMs that may be running
VM escape: An attacker is able to elevate out of the VM and access the hypervisor 
| DoS | Isolation Errors | Inherent vulnerabilities |
Hyper jumping: When an attacker is able to elevate out of one VM and access another VM that is hosted on the same physical system
Rowhammer: An attacker is able to escalate privileges and escape out of the virtual machine environment by exploiting hardware on the physical system.
Blue Pill: Uses rootkits that manipulates the kernel mode of the host machine to provide root level permissions for the attacker.

Defenses: Logical isolation, Patching, Physical isolation, Separate NICs, Separate hosts, Private VLANs
Multi-type Hypervisors: Type 1 or bare-metal (H/w – hypervisor – guest OS), Type 2 (H/w – Host OS – hypervisor – Guest OS), Common VMs
-	Monitor Hypervisors using: Virtual Machine Introspection
Cloud Data Security: Content discovery, volume storage encryption, object storage encryption
Attacks on Cloud Infrastructure: VM traffic sniffing, Insecure crypto (keys storage?), API attacks, Shared Infra, Hardware flaws, DoS, Supply chain attacks, Insider threat, Account Hijacking
-	Security in Cloud: Based on contractual SLAs, reviewing reports, and oversight

# Wireless Network Security
802.3 (Wired) and 802.11 (part 11 of 802 standard from IEEE) is wireless
802.11b: 2.4 GHz | Ratified in 1999, Incorporated into 802.11 in 2007 | max theoretical bandwidth: 11 Mbps
802.11a: 5Ghz | Ratified in 1999, Incorporated into 802.11 in 2007 | max theoretical bandwidth: 54 Mbps
802.11g: 2.4Ghz | Ratified in 2003, Incorporated into 802.11 in 2007 | max theoretical bandwidth: 54 Mbps
802.11n (WiFi4): 2.4 GHz (+5Ghz) | Signal reflection & MIMO | Max bandwidth: 100 Mbps | increased perf, throughput & range
802.11ac (WiFi5): 5Ghz | Ratified in 2013, Incorporated in 2016 | Min 1Gbps in multilink/multiclient | Min 500Mbps for single-link (can even support 6.77 Gbps)  multiple radios on wireless device
802.11ax (WiFi6): 6Ghz | Not ratified yet| Aggregated bandwidth of 11 Gbps
Do not use WEP (40bit key to 128 bit key, could predict next encryption key, uses RC4 and IV limited to 24 bits by replaying captured traffic to generate good sampling of IVs that is needed for aircrack-ng to crack the WEP key) 
WPA (uses Temporal Key Integrity Protocol (TKIP) with RC4 encryption | Added Message Integrity Check (MIC) in WPA). In 2009, WPA is deprecated. Wi-Fi Alliance came to replace WEP and also to standardize Wi-Fi device purchases.

Can use WPA2 (or RSN, Robust Secure Network), supports AES128/AES256 (4-way handshake for key exchange); 
-	WPA2 security issue: Research project named: KRACK (Key Reinstallation Issue) / Key of all 0s.
WPA3 is coming (individualized data encryption, Robust pre-shared key protection, better IOT support, 192bit DoD approved encryption, 128bit also possible, SAE generates unique per client keys, Dragonfly handshake, OWE (opportunistic wireless encryption) | Wi-Fi 6 compatible devices must support WPA3
Attacks on WPA3: Dragonblood  (downgrade to WPA2 using evil twin) | Side channel vuln (offline password guessing)
aircrack-ng: Primary cracking tool | aireplay-ng: Injecting & replaying wireless frames | airmon-ng: enable/disable wireless interface monitoring | airodump-ng: capture wireless frames

Best defense for Wi-Fi noise: early detection, timely response, and in worst case, fall back to wired network.
Wireless network scanning: Kismet
-	Free Linux WLAN analysis tool, completely passive and cannot be detected when used, supports advanced GPS, Used for Wardriving, Vuln scan, or as WLAN IDS tool

Limitations to Wi-Fi encryption:
a.	MAC address cannot be encrypted (MAC spoof possible)
b.	Management frames cannot be encrypted
c.	Data encryption between wireless client and wireless access point only; after that it stays unencrypted

Wi-Fi pineapple: De-authenticate and spoof a legitimate network.
MAC-filtering for Wi-Fi, not for true security, but protects from certain users. Worth using it.
Do not stop broadcasting of Wi-Fi SSID. 
Wi-Fi Protected Setup (WPS): Router shares all security settings with the connecting client PC
	PIN mode, Push-Button mode, Near-Field communication or USB modes
WarXing: Wardriving / Warwalking / Warparking / Warsitting / Warflying / Warbiking, etc.
Personal Area Network (PAN)        (!= Private) (Personal is in terms of proximity)
Bluetooth (802.15): (Coverage limited but security point of view: ASSUME UNLIMITED DISTANCE)
Class 1: 100 mW : 100 Meters| Class 2: 2.5 mW : 10 Meters | Class 3: 1 mW : 1 Meter (original / initial one)
	Cell phone headsets use Class 2
Piconet: Connecting the Bluetooth devices together
Bluetooth profiles describe which services are offered. Biggest concern is that Bluetooth is always ON.
BlueBorne: Vendor impl issues (RCE, Info disclosure like encryption keys). Impact: Billions of devices (Android, Win, Mobiles)
-	Must disable unnecessary Bluetooth profiles (via central mgmt. systems like Active Directory) 
SSP: Secure Simple Pairing (4.1 and later); Uses Elliptical Curve Diffie-Hellman (ECDH) for key exchange
AES256 bit encryption in 4.1 version and above; Bluetooth WarXing: Blue Hydra tool
Four Types: Numeric comparison | Passkey entry (manual) -> use 16 digits | Just works | Out of band (NFC)
Zigbee: low-cost / low-power / runs on battery (life expectancy in years) / automation technology / security is in standards / low-data rate / short range (most common standard for IOT)  | AES/CCM is the Zigbee’s encryption algorithm.
-	Home automation | Medical data collection | Industrial control systems
-	Collect information and control tasks
NFC: Close proximity of 1 to 2 inches | NFC Forum, non-profit org, working to increase interoperability & standards), NFC security is set by vendors
RFID: Unique ID of object w/ location and movement. RFID tags in close proximity with RFID readers, provide unique serial nbr. | Can identify/track humans at distance | Chip in passports | Cloning of tags is possible / impersonation | Bigger range than NFC
5G: High bandwidth (multi-gigabit) | Low latency | ITU (International Telecom Union), authority | Self-driving cars, IoT, etc.
IOT: Devices are computers with RAM, storage, software code, and an OS. Can leverage: Wi-Fi, Bluetooth, Zigbee, 5G, etc.

# Defense in Depth
Prevention is ideal but detection is a must. However, detection without response has minimal value.
Perimeter – Network – Host – Application – Data
Threats x vulnerabilities = Risk = Likelihood x impact
Security and functionality are inversely proportional.
4 approaches for Defense in Depth: 
-	Uniform protection: Everything gets same form of protection, vulnerable to insiders, weakest
-	Protected Enclaves: Additional protection for assets segmented from rest of internal systems (F/w, VLAN, NACLs, etc.)
-	Information-Centric: Network – host – application – data or info (identify & protect useful data), check data leaving org 
-	Vector-Oriented: Considering threat vector / a form of bridge (stop capability of threat to use the threat. E.g. autorun)

Configuration management: Establishing a known baseline condition and managing that condition
Access control: Data classification + Managing access + Controlling access
-	Data classification: responsibility of owner | Two categories: Military and Commercial

Data Classification roles:
Identify roles, Identify classification & label criteria, Owner classifies the data (review by supervisor), Identify exception to classification policy, Specify controls for classification level, Identify declassification, destruction, or transference procedures, Include an enterprise awareness program on data classification
Access Control
Identity, Authentication, Authorization, Accountability, Least privilege, Need to know, Separation of duties, Rotation of duties, 
DAC, MAC (subjects have clearances), RBAC (group membership or job function), Ruleset Based AC (RSBAC, e.g. firewall rules), List-based (permitted users per object), Token-based (permitted objects for each user).
-	Look for privilege creep issues
Account administration (onboarding), Maintenance (review of errors), Monitoring (audit for failures), Revocation (off-boarding)
Single SignOn (w/ MFA) is the reason for Windows computers to not salt the password hashes (Except NTLMv2, which uses Domain name, server challenge, and other variables to randomize final hash)

Strength of password hash:
Quality of algo, Key length, CPU cycles, Character set support, Password length
[password attacks] Dictionary (legal, medical, sports, IT, etc.) attack, Hybrid attack, Brute force attack, Pre-computation brute force (rainbow tables) attack
-	John The Ripper (Linux/Unix password cracking) | Cain and Abel
-	Rainbow tables (trade CPU for memory)

John the Ripper (not useful for long password cracking jobs)
	unshadow script will combine /etc/passwd and /etc/shadow into single file suitable for cracking by the tool
	john.conf in linux and john.ini in windows
	Crack modes: Single (uses GECOS data from /etc/passwd), Wordlist (/usr/share/john/password.lst), Incremental (brute force), External (own C code), Default (single->wordlist->I)
	john.pot file stores cracked passwords (hash + cleartext) under ‘run’ directory (--show command)
	john.rec file stores current run status. This file is used during crash recovery. Is undocumented on-purpose
	/root/.john/john.log contains cracked passwords (grep Cracked /root/.john/john.log) & other log information like mode (grep Proceed /root/.john/john.log) used to crack (single, wordlist, etc.)
	To know the status of run (press any key): John displays:
o	Number of guessed passwords so far, Time of scan, percentage of completion, combinations per sec, Range of passwords trying so far
	./john –test will give speed of a given system in cracking password hash routines that john can handle
Support distributed cracking via OpenMP (Open Multi Processing) API and MPT (Message Passing Interface)

Cain & Abel: (Installed on Windows)
-	Used for password cracking and also for sniffing, VOIP capture and RTP stream replay, RDP attacks, etc.
-	Tool cannot run with Antivirus turned ON.

# Security Policy
Security anarchy: No policy or an ineffective policy
Only executives can change corporate culture | Contradictions must be avoided in policies.
Mission statement: Is the risk tolerance in your org aligned with corporate culture?
Policies, standards (policy equivalent for technology) and procedures are mandatory.
A policy includes: Purpose, related docs for reference, cancellation or expiration, background, scope, policy statement, responsibility, action (very careful about exceptions): 
-	Must meet SMART objectives (Specific, Measurable, Achievable, Realistic, Timebound)
Program policy: overall tone of organization security posture (w/ guidance on enacting with other policies, who is responsible)
Issue specific policy: To address specific needs like NDA, Copyright, Pwd procedures, internet usage. Broader than system policy but not program; email policy with file types, etc.
System specific policy:  to that that generic policies could not be applied.

Steps to issue the policy: State the issue, Identify players, Find all relevant docs, define the policy, identify penalties for non-compliance (check collective bargaining from labor unions), make sure policy is enforceable, submit it for review and approval

Innocent infringement: Owner of doc/info/image must display copyright information
CIS Controls (old name: Critical Security Controls, CSC): 20 controls
Three control families: System (1-10) | Network (11-15) | Application (16-20)  Gives the ‘HOW’ part, not just ‘WHAT’ part.
Key rules: Each control must map to a known attack | Offense must inform Defense
Top 5: App whitelisting, Patch app, Patch OS, Reduce admin users, Secure baseline configurations
#2: Ensure internal workstations have authorized list of software (whitelisting): Facebook, Apple & Microsoft faced issue in 2013

# CIS Controls 

CIS Controls guiding principles:
-	Defenses should be automated for deployment and measurement of the same
-	To address latest attacks, specific technical activities should be undertaken to produce more consistent defense
-	Root cause problems must be fixed to ensure prevention or detection of attacks
-	Guidelines must exist to measure effectiveness of security implementations, with common language to express risk

CIS Control ERD (Entity relationship diagram): 
Malicious code and exploit mitigation
Reconnaissance – enumeration – penetration
Wannacry: C,I,A attack | A worm (not a virus) | Not a zero-day, patch was available 4 months before attack | Eternal Blue and DoublePulsar: both tools developed by NSA | 3 commands: ping, kill, exec

Attack steps: Reconnaissance, Scanning, Gaining access (vuln system, phishing, social engg, physical access), Maintaining access (backdoors, persistence process, creating accounts, covert channels), Covering tracks (rootkits, security logs, file manipulation)

Buffer overflow defenses: Run latest version of s/w, patch updates, run vuln scan, Impl IPS & WAF, Validate input
Secure Web Communications
Cookies: persistent/text file/database   |    non-persistent / session / in-memory
HTTP Authn: Basic – cleartext, base64 encoded | Digest mode – MD5 hash of password
Web App possess triple threat: OS security, Web Server security, Application security
Vulnerability Scanning and Penetration Testing
ROI (%) = (gain – expenditure) / (expenditure) X 100
ROSI: Return on Security Investment: Generally tied to cost effective method of reducing a critical risk

Threats: Protects against most likely or most worrisome based on: IP, Business goals, Validated data, History
-	Primary threats: malware, Insider threat, APTs (Stealth), Natural disaster, Terrorism
-	Traditional threats (automated, consistent, opportunistic)

hping3: A TCP version of ping; Use it for good reasons (defensive side) to
-	Test f/w rules, Test n/w performance, Remotely fingerprint OS, Audit TCP/IP packets, Transfer files across f/w, check host is alive
$ hping3 <targetip> -S -p 80 -a <spoofed_source_ip>     (check each port, never have alert on that)
     Modes: --rawip, --icmp, --udp, --scan, --listen    |  --spoof or -a, --rand-dest, --rand-source, --ttl or -t, --winid, --rel, --frag
     -s (source port), -p (destination port), -w (window size), -b (bad checksum), -S (SYN flag), -A (ACK flag)
Pen testing: Most common problem is that pen test team doesn’t focus on correct areas / look for rules of engagement 
Pen test approach: Determine scope, Info gathering, Scanning, Enumeration, Exploitation
Pen test techniques: war dailing, war driving, sniffing, eavesdropping, dumpster diving, social engineering
Social engineering types: Human-based (urgency, third-person authorization), Computer-based (pop-up windows, mail attach)
-	Defense: Good policies, train users, procedures for granting access and report violations, remove attack vector
 
nmap: --packet-trace options will show the step-by-step communication from tool to target on command prompt window
-	NSE: /usr/share/nmap/scripts/            (written in Lua language)

# End point security
Foundations for effective security: Asset inventory | Config management | Change control
Baseline: type & amount of n/w traffic, type & number of logs generated, resource utilized by systems, access times / length of access, current state and configuration of server
1.	Antivirus (truly called Anti-malware) solution: looks for virus, worms, scans files, attachments, emails, web content, etc.
a.	Antivirus, Antitrojan, Antispyware, AntiAdware, Antimalware, etc.
2.	Host based Firewalls: E.g. when employee travels w/ Laptop, the asset must stay protected.
a.	Packet filter (stateful), App control and OS control. 
b.	Focus on desktop lockdown including personal firewalls
3.	File integrity checking: List of critical file changes to be monitored, HIDS calculates hash of such files (hash updated after authorized changes)
4.	Log monitoring: Inclusive (looking for specific security activity in huge list) or Exclusive (Removing unwanted lists and keep only security items)
5.	Application whitelisting: Authorized apps & associated file hashes are periodically verified (passive/alert or active/block)

HIDS network monitoring: Monitoring n/w traffic into host / listens on all interfaces (Ethernet, Wireless, VPN, etc.) / signature analysis / inbound + outbound (pivoting, C&C, recon, etc.). / Mostly last line of defense, as other devices like NIDS may have failed to alert
New dev in HIDS: Monitoring change at app level, Protect website with HIDS, Data feed into SIEM, Migration to HIPS
HIPS: Can stop attack techniques (known & unknown), In-depth protection requires how app works, Anomaly analysis can stop unknown attacks, protection for travelling laptops / Not a replacement for system patching or Antivirus tools on hosts, App behavior monitoring
HIPS guidelines: Maintain req docs & test procedures for HIPS s/w selection, Central policy for controlling block rules, etc.
New dev in HIPS: zero-day attacks, App shielding, Dynamic rule creation based on observed behavior, etc.
SIEM / Log management (not a technology, not a product, it’s a process & people)
Prepare: Build a Linux server, Deploy on n/w, Allow ports (TCP/22/SSH, UDP/514/less secure, TCP/601/TCP, TCP/6514/TLS)
Operate: Forward syslogs to that server, Configure syslog.conf, Configure logrotate.conf to retain (received+local) for 120 days
Lack of accepted log standard  (that’s why log normalized first and then correlated)                                          
Priority managing logs: Firewalls, network gear -> Other n/w security devices logs -> Servers (Unix, then Win) -> Mail, Web -> Databases -> Applications (difficult) -> Desktops
Reports to generate from Logs data: Authn/Atuz, Changes, N/w activity, Resource access, Malware activity, Failures, Analytics

Collect logs using: Syslog (https://github.com/syslog-ng/syslog-ng) | Store logs using MySQL | Search logs using grep, Splunk, Log parser | Correlate and alert using OSSEC, OSSIM, sec, nbs, logwatch, etc.

SIEM Tools: Splunk (scalable, win & linux agents, Index any source, Ad hoc searches, Built from open source) |
Alien Vault (Offers SIEM, File integrity, HIDS, NIDS, Vuln Scan, Access to open-threat feed) | LogRhythm (high-end SIEM, Artificial Intelligence in log parsing based on Math, File Integrity, Complex to configure & maintain, License: Messages per second) | QRadar (IBM, AI, Advanced sense analytics, simple to maintain, Analyzes threats, NetFlow, Vuln, Logs, N/w Packets) | Logstash (Open source, No GUI / uses Kibana, no automatic anomaly detection) | Graylog2 (open source, built-in dashboard, log mgmt. + correlation, Pay for support) | LOGalyze (Open source, easy to deploy, built in dashboard, reporting, search,”do it yourself”).

Real time tasks: outbreak of malware, reliable intrusion evidence, Significant abuse of internal n/w, critical service loss, data theft
Daily tasks: Unauthz config changes, service off, Intrusion evidence, login failures, Malware (minor to medium), summary of tasks
Weekly tasks: Review of log trends, Routine creation/removal of accounts, Device/network changes, Summary of medium attacks
Monthly tasks: Review long-term n/w and system log trends, Summary of policy violations, resource usage, security tech perf
Quarterly tasks: Audit reports, Long-term trends of log data, infra changes, review log mgmt. system performance
Annually tasks: Performance: Log policies/retention/archival/longest term trends of log data, next year budget, new regulations

Active Defense (get legal advice, written permissions) / Offensive countermeasures
Interact with adversary after they break into the organization / to make things more difficult, more money, more time for the offense or adversary   Plan – Execute – Review – Repeat 
Types of active defense: Deception (honeypots, decoy servers, False DNS entries) | Attribution (identify attacker using ActiveX, trace-back mechanism, or beaconing software) | Attack back (illegal)
-	Honeypots: Systems with no legal purpose, only to divert attackers to slow down or make things difficult
o	Honeypot(system), Honeynet(network), HoneyTokens(files or folders) | research honeypot (w/weakness), production honeypot (hardended, replica of real production, recommended)
-	Honeycreds: fake creds/accounts, can be used for alerting when someone uses those to login, monitor & limit damage
-	Jailed environments: A virtual machine, a container, A chroot
-	False headers: E.g. Server attribute in HTTP response header
-	Decoy IP and ports: during the process of identifying active hosts and ports, redirect adversary to Decoy IPs / Ports
-	Tarpits: Goal of slowing down or using all attacker resources, Manipulate window size in TCP packet to set to low
-	Bogus DNS entries: Can also be achieved with host file entries
Tools to achieve Active Defense:
1.	ADHD: Active Defense Harbinger Distribution (ADHD): To learn how to deploy the AD capability in an organization
2.	Artillery: Python, Honeypot, Filesystem monitor, Threat intelligence feeds | Focused on early warning but do deception
3.	BearTrap: Ruby, Part of ADHD, Decoy/False IPs and Ports to block attacker’s IP address
4.	Decloack (Attribution): Discover attacker’s true IP, Uses flash/applets, part of IR or threat hunting activities
5.	Honey Badger (Attribution): Determine physical location of system, Uses geolocation, WiFi, IP address, pretends as admin GUI & runs applet
6.	Nova: Network Obfuscation and Virtualization Anti-Reconnaissance: Centralized mgmt. of other tools, Launces VMs.

# Cryptography
Cryptology: Cryptography + Cryptanalysis
Symmetric:
-	Stream cipher: RC4, SEAL, WAKE
-	Block cipher: DES (64bit block, 56bit key, not group based), 3DES(168bit key), RC2, RC5, IDEA, Blowfish, Rijndael (AES)
o	Double DES: Meet-in-middle attack, 57bit key
o	4 AES transformations: AddRoundKey (XOR), SubBytes (byte-for-byte u/ S-box), ShiftRows (left circular shift of rows), MixColumns (math transform each column)
o	Techniques used: Substitution (XOR, Rotation [Caesar ROT3, Usenet ROT13], Arbitrary substitution (repeated entries found without a pattern, function is the Key)), Permutation, Hybrid     Generally broken with frequency analysis
Asymmetric:
-	Discrete log: DSA, ECC/ECDSA, Diffie-Hellman, El Gamal (discrete logarithm)
o	ECC has low power / fast / mobiles, ATM, electronic cash, etc.
-	Factoring: RSA (used in IE browser), LUC
Hashing: MD2, MD4(16B), MD5(16B), RIPEMD(20B), SHA1(20B), SHA2(256b,512b), SHA3, Whirlpool (64B)
-	Hash collisions are based on birthday attack (23 people, 50% chance for 2 guys)
Key management: ISA/KMP, SKIP, Diffie-Hellman, IKE
Snake Oil: An idea of no value but promoted as solution to a problem
Work factor: Time taken to decrypt an encrypted message
	(Key length, Randomness, Algorithm strength, Avalanche effect)
	The infinity work factor does not exist
Moore’s Law: Processing power can be doubled roughly every 2 years
Avalanche effect: Small change in input leads to significant change in output (e.g. hashing)
Preimage attack: Predictable collision in hash
Mixcolumns: Permutation function on columns of text
Shiftrows: Rotational substitution function | Sub bytes: Arbitrary substitution function
Addroundkey: XOR function that modifies the key for each round
Steganography: Hide in images (bmp, png, gif, jpg), word docs, txt files, machine generates images (fractals) in “host”
-	Tools: Image Steganography https://archive.codeplex.com/?p=imagesteganography
-	Histograms: very flat for encrypted | non-uniform for normal text
-	Types: Injection (increases file size, comments in html), Substitution (limits apply to data hidden), File generation (spammimic)
-	Tools to detect: StegExpose, StegSecret   (by use of least significant bits)
-	Pre-Scale option increased the size by 4 times.
We are looking for intractable problems (hard problems, cannot be solved in polynomial time).
RSA: Based on large integer divided into prime factors / ~1000 times slower than DES / 
Cryptanalysis: 
  Attacks: Analytic (mostly symmetric algos), Statistical, Differential (asym algo), Linear (asym algo), Differential Linear (asym algo)

# Applied Cryptography
Data in motion:
-	VPN (not idea for financial, medical and other real-time operations), most vpn devices are IPSec compliant RFC2401
o	Client-to-site (transport): Data encrypted, IP header in cleartext, IPSec header is added in clear
o	Site-to-site (tunnel): Data+ IP header is encrypted, New IP header added in clear, IPSec header is added in clear
-	IPSec: AH (Origin Authn+ No confidentiality+ integiry, AntiReplay w/ 32bit seq nbr, does work when both PC use private IPs, TTL no authn) & ESP (IPv4 header no authn, Data encryption + Origin Authn + integrity, can off encryption using NULL algo)
-	HTTPS is end-to-end encryption
Data at rest:
-	GNU Privacy Guard (GPG): Encrypts files/folders on hard drives, sent in emails; Privacy in public communication
o	Encrypt, Decrypt, Sign, Verify
o	GNU Privacy Assistant (GPA), a GUI for GPG
-	Data encryption
-	Full disk encryption: Data is encrypted and decrypted in RAM. Always stays encrypted on storage/disk level.
o	MAC: FileVault; Linux: LUKS; Windows: BitLocker

# Key management
-	PKI (Certificate: registration, creation, distribution, validation, key recovery, expiration, revocation)
o	Used for S/MIME, Partial or whole disk encryption, Code and driver signing, User authn, IPSec & VPN, Wireless authn, NAC/NAP (protection), Digital signature, mitigates impersonation
o	Registration: before cert is issued | Initialization: copy of root’s ca, pub/pri key generate | Certification: CA issues the cert, stored
-	Digital certificates: Extensions: can limit the use of a public/private key pair
-	CA: Hosts OCSP (Request status by individual serial number), has lower bandwidth and storage requirements
Generating key pairs: Algo: Diffie-Hellman/DSA or RSA, Key length/size, Key expiration
IH
Incident: Adverse event in an information system or network / implies harm or attempt to harm
Event: Observable occurrence in a system or network (System boot sequence, system crash, packet flooding in n/w)
	Corroborating evidence: one that supports original evidence

Incident Handling: (first-aid) Action plan for dealing with misuse of computer systems and networks (e.g. social eng, insider threat, targeted malware, automated malware, worms (segment,multi-exploit/multi-platform,patching required):   e.g.   Intrusion | Malicious code infection | Cyber theft | Denial of service | other security related events 
•	Preparation: (get the team ready to handle incidents) out-of-band communication, mgmt. support, contacts, DRP update, Escrow pwd/keys, checklist, jump bag
•	Identification: IDS alerts, failed or unexplained events, system reboots, poor performance, Alert early, determine event or incident
•	Containment: Stop the bleeding!
•	Eradication: Remove the malware & attacker and also fix the root cause, improve defenses, restore from backups
•	Recovery: Monitoring phase, system back in production, validate with business teams, run UAT, attacker returning?
•	Lessons learnt: Document what happened, conduct meeting (within 2 weeks) to review IR report, Fix policies, etc.
BIA / BCP & DRP
Lifecycle: Project initiation -> Risk analysis (identify vulns) -> BIA (priority for recovery) -> build the plan (dev) -> test & validate plan (exercises) -> Modify/Update plans (improvements) -> Approve & impl plan (mgmt. signoff & awareness training)

BCP: Availability of critical business processes / long term impact to business / identify and fix before they occur / includes DR
DRP: Recovery of IT systems during a disaster or other disruption event / Recovery of datacenter, business ops, locations, processes

DR planning process: Management awareness -> planning committee -> risk assessment -> process priority establishment -> recover strategies -> testing criteria
Mistakes in DR: Lack of public relations planning, Lack of security controls, Lack of communication, Lack of plan ownership/updates, Lack of prioritization, Limited scope, Lack of BCP testing, Inadequate insurance, etc.
-	Cloud DR: Cloud service providers already offer DR services that enable rapid recovery of IT systems and data
-	Mobility DR Kit: Solar charger, Unlocked smartphones, SIM cards that are ready to active, Charged battery banks
o	Waterproof, fireproof, and properly secured
Risk Management
SLE = EF x AV   |    ALE = SLE x ARO
Safeguards: Host-based solutions, Network-based solutions, preventive and Detective measures, Logging, Data-focused controls
Threat sources: External network, External business partner, Internal network, Internal host, From malicious code

# Windows Security
Identify cmd line for runing process: wmic process list full | findstr /I commandline OR wmic /output:process.html process list full /format:htable
3 classes of Windows: Client, Server, Embedded     | License: OEM license (bound to hardware)|Home,Pro,Business(not bound)
Client OS: XP, Vista, 7, 8, 10 (Personal: Starter, Home, Ultimate | Work editions: Business, Pro, Enterprise)
Platforms: AMD or Intel, ARM64 (longer battery life & less costly w/ ARM, Windows Phone uses ARM, has x86/x64 emulator)
Server OS: NT 4.0 Server, Server 2000, 2003, 2008 (last for 32bit), 2012, 2016, 2019, Hyper-V Server (Free) | (R1=RTM, R2)
-	Editions: Standard (merge w/ Enterprise), Enterprise (removed from server 2012), Datacenter (different scalability & fault tolerance)
-	Server roles (big): Domain controller, Hyper-V virtualization (VMs & Container), RDP, DirectAccess & VPN, File & Print services, DHCP server, DNS Server, Network Policy Server (RADIUS), Web (HTTP) server | Server Features: small e.g. support for BitLocker disk enc.
-	Small Business Server or Win Essentials for small office (<25people) | (Windows storage server for OEM license)
-	Windows Server Installation options: Server core and Server nano (not editions of Windows)
-	Server license model: Client Access License (CALs), VM instance rights, per-user/per-device access for RDS, per-core for SQL server, etc.
Windows IoT: Windows 10: For ICS/SCADA equipment, Retail POS, MRI scanners, Robotics, Digital signs, Drones, 3D printers, etc.
-	Runs of Raspberry Pi (Free Win license), MinnowBoard, and Arduino devices. Supports x86, x64, ARM CPUs.
-	Windows + Android, internal is mostly Linux   (free Windows license on tablets 9 inch or less)
WORKGROUP mode (~50 pc) / standalones (~10 pc) / No Domain controller / Local accounts
Local Administrator account always works for ‘pass the hash’ 
Windows Enterprise license is called: site license or software assurance license.
Security ID numbers (SID): Windows uses SID when enforcing permissions and privileges, not usernames
	wmic useraccount get name,sid		(All users, groups and computers have SID)
Security Access Token (SAT): Like a Driver’s license, created at user login and valid until user logout, SAT is attached is every Windows process we start. Windows uses SAT to verify permissions before allowing attempted actions.  Never sent over n/w.
whoami /all /fo list      (Contains: SID of user, SID of all groups, list of privileges)
Standalone computers don’t trust SAT of another machine, that why we need Domain Controller (KDC)
Multi-master replication Vs Read Only Domain Controllers (RODC): RODC controllers cache only the group credentials that admin specifies, and they are tracked so that specific users are forced to change passwords, when compromised.
-	RODC that use BitLocker & TPM are better for remote offices / Server core is better option too.

What is in an AD domain? User acct properties & pwds, Groups & memberships, Computer properties & pwds, Domain names & trust relationships, Kerberos master keys, Digital certs & certificate trust lists, OU & its members, LANs & IP subnets in org, AD replica links & settings, Shared printer location (UNC path), Exchange server directory info, GPO, Any custom data we want.

## Kerberos 
It is a form of default authentication exchange (between computers and domain controllers); If fail, fallback to NTLM
-	Kerberos ticket contains SID of user and SID of user groups, both encrypted w/ user’s password and special keys
-	NTLM (authn before Kerberos), is used in workgroups. Can disable NTLM from Win7 (NTLMv1, vuln to sniff&crack, Cain)
-	Kerberos is faster than NTLM and scales better in large environments.
Kerberos is available when any of the protocols is used: SMB/CIFS, RPC, LDAP, HTTP, Dynamic DNS Secure updates, IPSec IKE, PowerShell Remoting (WSMAN).

Risks in Kerberos:
1.	Attacker capturing packets on initial exchange between user and DC (KDC). The initial ticket request is encrypted with user’s password. Vulnerable to brute force, if password is weak. 
2.	Attacker stealing copy of special encryption keys from compromised replica DC. This will enable to issue ticket as any user in the domain.
3.	No expiration in tickets provided by KDC to user, in order to access a server or file share, etc.

NTLM is “I need to ask your mother” authentication. NTLMv1 sends encrypted password hashes to server, which then checks with DC to verify them. If verified, server creates SAT.
-	Cain can be used to sniff the initial password hash exchange and crack them in less than a day
-	NTLM has performance, scalability and security issues. 
-	Starting from Win 2008 & Win 7, we use GPO to disable NTLM, which puts Kerberos and cert authentication only.

Forests and Trust:  	(cross-domain replication in a forest is possible but not cross-forest replication)
-	Cross domains are linked w/ ‘trusts’ for SSO purpose & resource sharing. Share Single schema & Config naming context
AD Forest: One or more domains, inter-domain replication, 1-way or 2-way transitive trust (transitive) in forest domains (> Win Server 2003)
    Global catalog servers: Special DC that replicate across domains | Global Catalog (GC): Portion of AD data replicated in a forest

Group Policy: For Windows configuration mgmt..: Password policy, Lockout policy, Kerberos policy, Audit policy, NTFS permissions, Event logs, IPSec settings, startup options, services permissions, registry key permissions & settings
-	GPO (objects) are downloaded and applied at bootup, logon, and roughly every 90 to 120 min after that
In ProcessHacker.exe tool -> Double click on a process and click on ‘Token’ tab to know the SAT information.
Windows as a Service = Continuous updates
End of support: Windows 7 – Jan 2020 | Win 10 (2015) – Oct 2025 | Server 2008 – Jan 2020 | Server 2012 – Oct 2023 | Server 2016 – Jan 2027
Feature updates: Large new service or app changes, changes Win version (once every 180 days)
Quality updates: Small improvements / bug fixes (once every 30 days)
-	Security updates are rolled out on all or nothing package that fixed many bugs at one shot (cumulative)
-	Updates are searchable in Security Update Guide https://portal.msrc.microsoft.com/en-us/security-guidance
Servicing channels: delay the windows updates/installations: Semi-Annual (30days/quality update, 365days/feature update) | Windows insider (updates while still in dev, early testing) | Long-term channel (no feature updates/mostly entire OS update, once a month quality updates, Volume license, mostly Enterprise editions)
-	Home users can hit pause button

## WSUS: 
Windows Server Update Services: Built into Windows server as an IIS web application; Clients can download either from WSUS server or from Microsoft; 
Third-party patch management: IBM end point mgr, Symantec Altris , Gravity Storm, Ivanti, etc.
SCCM: System Center Configuration Manager: From Microsoft, Licensed, Includes pushing a s/w to a client/server
Windows Access Controls
File systems: CDFS, FAT, FAT32, exFAT, ReFS, NTFS (default).    
-	NTFS features: Permissions, Auditing, Encryption, Compression, Transactions, Max size: 8 PB
-	When user is assigned to multiple groups, permissions are added. If there is a DENY in one of them, overall it is DENY
DAC: Giving permissions in Windows to a folder: Recommended: ‘Modify and below’. ‘Full Permissions’ means the ability to change permissions.
AGULP: Accounts -> Global groups -> Universal groups -> Local groups <- Permissions & Rights
Default shares: ADMIN$ (windows OS files), C$, IPC$ (inter process communication)  $ indicates hidden
NTFS permissions vs Share permissions:
NTFS permissions: Full control, Modify (delete is allowed), Read & execute (no display of all content), List folder contents (List all content & execution also possible), Read (cannot list content but can open specific file), Write
-	NTFS takes maximum of read/write permissions. But if deny is listed as overlap, then overall permission is denied
Share permissions: Full control, Change (read/write/execute/delete), Read (folder contents and opening files)
-	Share permissions can be more restrictive than a NTFS permission (limiting # of connections to a folder) (but can generally apply to NTFS, FAT, FAT32, etc.)
When both NTFS and Share permissions are for same user, most restrictive ones apply.
By default, Registry editing is possible remotely. Need to disable this.
5 key points on Privileges
1.	Privileges are managed per computer (e.g. shutdown, restart), whereas permissions are managed per object
Privileges can be known by command: >whoami /priv
2.	Possible restrictions that we can apply (as best practices on defense):
-	Allow Log On locally (means a decision whether to allow to login by physically being present at workstation and using attached keyboard)
-	Allow Access to this computer from network (means a decision whether to allow remote access or not)
-	Allow login through remote desktop services
3.	Take ownership of files and folders.
4.	Backup files and directories + restore files and directories
5.	Debug programs http://ollydbg.de/ (attaching a process in memory, DLL injection, Developers use for troubleshooting)
a.	Cain uses DLL injection to dump password hashes and OS’s LSA secrets data

BitLocker: Sectors encrypted with AES 128 or 256 bit. Boot up integrity checking with TPM (chip in motherboard, also used to encrypt biometric data, vuln to cold-boot attack), Supports USB, & Thunderbolt devices, Emergency recovery PIN, Supports some self-encrypting hard drives
-	Can enforce using gpedit.msc
-	Recovery from BitLocker: Backup recovery password (48 digit number) in Active Directory using Group Policy. This can decrypt even if TPM is damanged, PIN is lost or USB token is lost
Alternative to TPM: Unified Extensible Firmware Interface (UEFI), replaces old BIOS firmware, must be built into motherboard, UEFI Secure Boot: cryptographic process with keys (can do sig. sign to check integrity of OS bootup files, can load antivirus at bootup)
Enforcing Security Policy
Security templates (.inf files, opened w/ text editors)
Password policy  | Lockout policy | Audit policy | Privileges | Event log settings | NTFS permissions | Group memberships | Service startup | Registry permissions
Green tick just means the computer configuration matches the Microsoft recommendation
Red cross just means the configuration doesn’t match (not necessarily good or bad)
Different sources of security guidance: 
-	Microsoft security baselines guides, Guides from US Gov (DoD, NIST, NSA) & CIS
SCA (Security Configuration and Analysis) tool: Applies a template to computer OR Compares a template to computer’s setting
-	Cannot be done remotely over network, must be local
-	There is no undo feature in this, so be careful
-	secedit.exe is the command line version for the SCA (GUI based)
Group Policy Object (GPO): Local Computer Policy (applies even when no one is logged in) & User Configuration (applies to specific user’s desktop)  these are stored on AD domain controllers, downloaded every 90-120 min (local–site–domain-OU, as preference):   Login/Logout scripts can be added: Powershell, VBScript, Jscript
-	GPOs are managed using GPMC (Group Policy Management Console), must undergo change control, test before deploy
-	Checklist of GPOs:
o	Pwd policy (max 127 chars), Act lockout policy, Anonymous access policy, Kerberos & NTLMv2, Guest a/c, Protecting admin account, Edge Firefox & Chrome, Adobe reader, Administrative template settings
ADM templates (.admx)  Administrative Templates  User friendly registry editor
Credential guard: Protects from Mimikatz & kernel-mode  malware for credentials in memory.
-	Must have UEFI, in secure boot, Win 10, Server 2016, Hyper-V enabled, Enterprise or Education (not Pro version)
Local Administrator Password Solution (LAPS): Local account passwords of domain joined computers. Pwds are stored in AD.
AppLocker: Regulates processes & scripts that user are permitted to launch, limited to Enterprise & Education (Not Pro/Home)
-	Can help to defend against virus,worm,trojans,hacking tools. 
Controlled folder access: Setting in Windows 10 for protection against Ransomware attack.
User Account Control (UAC): We can change setting in Group Policy from asking a prompt to asking a credential.
Windows sandbox for Malware isolation: Install & run apps in containers. Changes are discarded, when sandbox is closed.  

## Network Services and Cloud Computing
Server core: Removes graphical and enables command line shell, and can launch powershell.
Server nano: Smaller than server core. 110mb base image. Run as container, not VM. Cannot be patched, replaced with new container. Run’s headless / enables interface only for basic firewall changes for remote administration.

Server manager: Roles (IIS Domain controller, DNS, RADIUS, etc.) and Features (BitLocker, Telnet client, .NET, etc.)
-	Tool with dependencies (added and removed with roles and features)
-	A small GUI for servers (instead of desktops), built in PowerShell behind.
Disabling a Windows service: Services tool (msconfig), Security template, GPO, PowerShell, SC.exe (may not be installed on all PC)
Windows computer checks domain to IP in the order of (fall back in case of failures):
1.	DNS (Domain Name Service) server (Attack Tool: Responder)
2.	LLMNR (Link-Local Multicast Name Resolution): (Attack Tool: Responder that can harvest credentials)
3.	NBT-NS (NetBIOS Name Service) (Attack Tool: Responder, python: Responder.py -I eth0)
NetBIOS: Null user sessions do not require NetBIOS.
SMB: TCP 139(NetBIOS)/445 (CIFS, if no NetBIOS) | RPC: TPC/135 | LDAP: TCP 389/636/3268/3269  | Kerberos: TCP/UDP/88
DNS: TCP/UDP/53  |   RDP: TCP/UDP/3389  | SQL Server: TCP/UDP/1433/1434 (Win or Linux)   | 
NetBIOS: TCP/UDP137, UDP138, TCP/139, TCP/UDP/1512, TCP/42   | IPSec: UDP/500/4500 for IKE, Protocols 50,51 for ESP,AH

## Window Defender firewall  
(Logs in W3C extended format, w/ ports, byte size, TCP flags, TCP SYN,ACK nbrs, Window size, ICMP type)
Pros: Built-in, free, enabled by default, stateful packet filter, per-app/per-service rules, IPv4/IPv6 support, ingress/egress filter, Manage via GPO, Cmd line mgmt. w/ PowerShell or netsh.exe
Cons: No central logging or alerting, No IDS feature, No user behavior monitoring, Complex
Network profiles: Domain (Selects automatically when AD is available), Public (coffee shop, hotel, airport), Private (home, office)
-	Different firewall rules for different profiles.
Firewall management: GPO, PowerShell, Netsh.exe
IPSec built into Windows (Defender Firewall with Advanced security)
-	Firewall-IPSec integration: Secure Connection (Mutual authn & packet sign) & Require Encryption (authn & encryption)
IPSec Pros: Mutual authn w/ Kerberos or certificates, 256b AES packet encrypt, Packet sign for integrity & proof of origin
> Get-Help -Full NetIPSecRule
> Get-Help *IPsec*
> netsh advfirewall consec /?
- Can enable IPSec on all computers but don’t require it (it will fallback to plaintext). Require is only for servers in OU, for SMB
Securing Windows IIS
Avoid joining to AD domain | Use preferably with server core or nano
IIS can have TLS certificate setup per web page of application
User authn: Anonymous, Non-anonymous (Basic, Digest, NTLM, Kerberos, User certificate, Forms)
Can block requests by source IPs (but combine with restricting at user authn level)

## Remote Desktop Services (RDS)   Client app: mstsc.exe
RDS != RDP.    RDS enables remote control of graphical desktop. 
To avoid spying by administrators into our PCs, we can use the ‘Remote assistance’ feature. This enables approval to connect.
Best practices: Restrict at perimeter firewall TCP/UDP/3389
Microsoft Cloud
Azure (Cloud Provider) | OneDrive (Storage as a Service, File storage) | Office365 (Software as a Service)
Azure AD Connect: Free tool, Sync Azure AD with on-premise AD, SSO to Office 365, on-premise servers | Sync passwords
Azure Admin role = Admin global group in AD // Powerful over all assets in Azure

## Automation, Auditing & Forensics
Windows PowerShell (from Win7): Just Enough Admin (JEA) for remote/records cmds to textual log files for threat hunting / forensics
-	Replaced by latest: PowerShell Core. Runs on Win/Linux/MAC, open-source, Few cmdlets for now, not default installed

## Windows configuration tools:
	wmic, netsh, getmac, ipconfig, route, net, netstat, nbtstat, schtasks (user creds are saved in cleartext in schedulers), secedit (cmd line for SCA, policy enforcement with inf files), auditpol (verify), gpedit (enable audit), compmgmt, 
Windows subsystem for Linux (WSL)
	Run Linux executables and scripts on Windows without a VM or emulator, must enable it, not install by default

Can push scripts at GPO / OU level (e.g. Startup script, Shutdown script, run as system | Logon or Logoff script, runas user)
Windows Event viewer logs:  Application logs, System, Security, Directory service, DNS Server, File replication service, and 200 more…           2 step for auditing: 1. Enable the auditing, 2. Configure what to audit (SACL)
>powershell Get-WinEvent 
Forensics snapshots are text files, not binary images
-	Data to look at: File hashes, User accounts, Group memberships, Shared folders, Account policies, Privileges, Processes, Device drivers, Service settings, Network configuration, Listening ports, Environment variables, Registry values, NTFS DACLs, IIS configuration files
o	Use snapshot.ps1 
Windows commands
>gpedit.msc   // group policy editor
>msconfig.msc   // Windows services
>lusrmgr.msc    // List of users and groups
>wmic useraccount get name,sid    // GET SID of all users (local or cloud based)
>whoami /all /fo list     //SID of user and associated groups, along with privileges
>whoami /priv     //list of user privileges
>wmic /node:<server> share list brief    //show shares in remote server

## Powershell:
>Get-Content .\<file> | Select-String -Pattern "<text-to-search>"
>Get-Process -Name lsass | Format-List *   //gives details on lsass process running in Windows
>Get-Process | Select-Object Name,Id,Path | Export-Csv -Path list.csv    //export processes to CSV file
>Get-Service | Select-Object DisplayName,Status | ConvertTo-Html | Out-File -FilePath services.html   //export services to html
>dir .\<filename> | Format-List *     //to know details of a file in Windows (equivalent of $file <filename> in Linux)
>dir | Sort-Object CreationTime | Select-Object CreationTime,FullName    //to display by sorted date and time of creation
>Copy-Item -Path .\<file> -Destination .\<file>  	//to copy a file to another location or name
>Get-FileHash -Algorithm SHA1 -Path *  | Out-GridView	//to get hashvalue of files in a directory as grid view
>get-wmiobject -query "SELECT * FROM Win32_BIOS		//wmi objects are in SQL format
>Get-WinEvent -ListLog * | Select-Object LogName -ComputerName LocalHost  	//must be admin group member on remote computer

# Linux Security
## Linux Security: Structure, Permissions and Access
Main distributions: Ubuntu, Fedora    |   Cygwin for Windows 	| MacOS (BSD, XNU kernel, N/w services disabled by default)
Ubuntu: Based on Debian | Ubuntu as Desktop, Server, IoT, Cloud | APT-based package mgmt. | F/w disabled by default
Fedora: Based on RedHat | Installer decides workstation or server | RPM-based package mgmt. | F/w enabled by default
Cygwin: Not Linux | Not Linux emulator | compiles server s/w for Windows | Scripting within Windows | Win can interact with Linux
MacOS security features: Pwd assistant & strong pwd, File Vault (128b AES), OpenSSH, Sandboxing, Encrypted backups, Automatic updates, Gatekeeper to protect apps, Privacy controls, iCloud chain, Runtime protection, Anti-Phishing, iCloud device location
-	Securing MacOS: Turn ON f/w, Disable unwanted services, Limit service sharing, Setup secure file sharing, Monitor access lists, Use pwd assistant for strong authn
Mobile device security: Android: 69% share, iOS: 25% share. 
Android security: Android Oreo focused on security, now multi-layer security
-	App Security (tested before release), Active scanning (running apps are monitoring), Android Pay (no expose credit card), Virtual sandbox (critical data is not exposed to apps), Device mgr (locating & wiping remote devices), Encryption (built-in, crypto for data at rest and transit)
iOS security: Security into architecture, Key security cannot be disabled or turned off. 
-	System security, Encrypted and data protection, Network security, App Security, Apple Pay, Internet services (backup + secure communication), Device control, Privacy controls (e.g. location services)
Linux commands:
ls, ls -l, ls -la, cd, mv, chmod, mkdir, rmdir, rm, cp
Windows:	dir /w, dir, dir /a, cd, rename, attrib, md, rd, del, copy

Hardware -> Kernel -> userland
Shells: UNIX->sh (Bourne),csh(C shell),bash (Bourne-Again), ksh (Korn), tcsh (exTended)  | DOS->Command.com   | 
Windows->cmd.exe, powershell.exe
Kernel services: Filesystem, Low-level network protocol (IP), Memory and process mgmt.

/				(root file system, top of hierarchy)			/boot 	(static bootfiles)
/dev, /devices			(files that talk to system devices)			/etc  	(configuration files)
/usr				(primary OS directory, read-only)			/lib  	(shared libraries)
/var				(contains log files, queues, etc)			/opt	(optional packages)
/bin, /usr/bin, /usr/local, /opt	(executable programs, some SIUD, SGID, binaries)	/proc	(kernel & process files)
/home, /export/home		(user home directories)				/sbin 	(sys admin binaries)

.config(settings & info on Unix Win programs)|.ssh(user’s secure shell)|.profile(env variables)|.bash_profile(bash shell)|.rhosts(users to ssh w/o pwd)

Filesystem security options: ro: (Filesystem is mounted read only) | nosuid: (SUID/SGID bits are ignored on all programs in filesystem) | nodev: (special device files won’t work)
SUID: File execute with privileges of file’s user   & SGID: Temporarily grant user file group permissions
LUKS (Linux Unified Key Setup): Whole disk encryption on Linux filesystem / Secure against low entropy attacks / Free

su vs sudo: su requires root password | sudo requires current user password and user must be in sudoers file (with specific cmds)

Linux Permissions: Symbolic (RWX) & Absolute (numbers)
World writable directories: /tmp
umask -> sets default permissions when creating files
chmod -> changes permissions
chown/chgrp -> change ownership & group

Two class of users in Linux
-	Normal users (
-	Super user (UID=0, root, multiple UID=0 possible, controls all files, process, devices)
 
shadow:

/etc/default/useradd    and     /etc/login.defs (login tries by user, default home path, pwd hash algo, etc.)
/etc/pam.d (pluggable authn modules): 4 mgmt groups (Authentication, Passwords, Sessions, Accounts)
-	Enforce strong passwords: /etc/pam.d/system-auth file. 
o	password requisite /lib/security/$ISA/pam_cracklib.so retry=3 minlen=8 lcredit=-1 ucredit=-1 dcredit=-1 ocredit=-1
-	Restrict use of previous passwords
o	password requisite /lib/security/$ISA/pam_pwquality.so retry=3 minlen=8 lcredit=-1 ucredit=-1 dcredit=-1 ocredit=-1 difok=3
	difok  = number of characters that must be different from the old password
o	password sufficient /lib/security/$ISA/pam_pwhistory.so use_authtok sha512 shadow remember=6
-	Locking user account after too many login failures
o	account required /lib/security/$ISA/pam_tally.so per_user deny=5 no_magic_root reset
	no_magic_root   not to lock root account    |   
	per_user -> keeps an account of each individual use
	faillog -u <user>   // list the current number of bad logins
	faillog -u <user> -r   //unlocks the account
	faillog -u <user> -m -1 //turn off locking of a particular user
	passwd -l <user> or passwd -L <user>  // unlock the user
	passwd -u <user> or passwd -U <user> // unlock the user
Hardening and Securing Linux services
When a Linux/Unix system starts, init (also known as System-V style init, starts as PID=1) is the first process to start. Deals with services only during startup and shutdown.
-	Runlevel0 = shutdown the system; Runlevel1 = single user mode; Runlevel2 = multi user mode; Runlevel3 = multi user mode with networking; Runlevel5 = GUI; Runlevel6 = system reboot

upstart: optional add-on to init; parallel booting of services; live system changes; monitor status of service;
-	Has jobs, events, emitting-events (chained process of events before second job starts); 
systemd: replaces initd; user-friendly & robust; Full system & service mgr, Software suite/platform, interface for kernel functionality.
-	Supports parallel processing, monitors services after boot, restarts crashed services, supports device hot plugging (no reboot required, uptime is key), SELinux integration
Issues with systemd:
1.	binary logging (journald)
not syslog, so no grep.
2.	No cron. Replaced by 
Calendar times
3.	BSD doesn’t support it
systemd, logind, journald, networkd, user session

Cron (Chronology): crontab / cron tables to store jobs to run:  /etc/crontab (min hour dom mon dow user	command)
-	crond in sync with system clock
m = 0-59  |  h = 0-23  |  dom = 1-31  |  m = 1-12  |  dow = 0-7  (0,7 is Sunday)

## Linux Configuration Management
Package reductions in Linux: E.g. Use of XFCE instead of GNOME   (X11* can be removed from Linux)
Puppet: Ruby, some support for Windows, based on DMTF (distributed mgmt. task framework)
CFEngine: very old; easy to use; Automation framework for monitoring & compliance; moved from local to cloud based
Ansible: Uses web-based, JSON or JS based communication, free, nodes via SSH, controlling m/c for orchestration & mgmt.
Chef: open source, Infra-as-code, Chef dev kit, Chef server, Chef client
SaltStack: Config & mgmt. of datacenter, infra and apps, scalable/intelligent/modular, fast remote execution engine
-	Modules: Execution modules, State modules, Grains, Renderer modules, Returners, Runners
-	IoT, SDN, DevOps, Compliance, Microservices, Big Data, Cloud Ops, IT OpsHPC, etc.

## Linux Hardening
Default installation of Linux is not necessarily secure. Bastille Linux Hardening: https://sourceforge.net/projects/bastille-linux/ 
Lynis: Audit against Basel II, GLBA, HIPPA, PCIDSS, SOX; Checks: Authn methods, SSL certs, Outdated s/w, Users w/o pwd, F/w audit
To close unnecessary ports:  
/etc/inetd.conf  (comment out with #)  |  /etc/xinetd.conf  (set disable to yes) |  /etc/rc.conf  (Comment out OR change YES/NO)

SSH multi-factor authn: SSH Keys, Google Authenticator, FreeOTP, Authy, Duo 
-	SSH key mgmt.: KeyBox web-based SSH manager w/ Google Authn/FreeOTP (roles, keys, sessions), Puppet (Keys)

sysctl hardening:
-	To modify kernel settings at runtime, shows n/w and system settings;
o	IPv4, IPv6, Exec Shield, Network attack preventions, Logging attacks, Address space layout randomization
-	sysctl -a shows all variables for the system
-	/etc/sysctl.conf file has configuration information
o	Disable source routing (spoofing) by setting: “net.ipv4.conf.all.accept_source_route” to 0 in above conf file
-	IPv6 setting in sysctl: Disable router advertisement, Enable privacy extn, Rate limiting (milliseconds, default 1000)
-	ASRL (Address space resolution layout): Memory address space randomizer, makes buffer overflow much harder
o	Remove setarch utility (ASLR can be disabled per application with setarch)

Disabling unneeded Kernel modules w/ Modprobe
-	Modproble is used to add or remote LKM (Loadable Kernel Module) to/from kernel   (/etc/modprobe.d/ directory)
-	To search for disabled modules: find /lib/modules/`uname -r` -name *modulename*

Disable dynamic loading after boot
-	Linux kernel has built-in + loadable kernel modules (due to flexibility for kernel); 
-	Risk of this being enabled is a rootkit
-	sysctl parameter: kernel.modules_disabled=1  
 
OS enhancements for security
SELinux, a LKM (Loadable Kernel Module), with Mandatory Access Control mechanism, provides access control policies (separates policies and enforcement, controls process initialization/inheritance/execution), Least privilege principle
-	With DAC in Linux & default as DENY access, then SELinux has no role to play.
-	With DAC in Linux & default as ALLOW, SELinux applies as Multi-Level security (MLS, s0, Bell-LaPadula, used in LSPP Labeled Security Protection Profile) and Multi-Category Security (MCS, c0/c1/c2/c3): 
o	s0:c0=Company Confidential | s0:c1=Patient Record | s0:c2=Unclassified | s0:c3=Top Secret | s0:c1,c3=Company confidential Redhat 

Grsecurity: Set of patches for UNIX kernel to increase security; 
Role-based access control with Gradm tool, Impl. Least privilege, 
PaX memory protection w/ Paxctld [memory overwriting, memory corruption, 
malicious code execution, code order mismatch] , 
File system hardening, Kernel auditing, Trusted Path Execution (TPE)
-	gradm -F -L /etc/grsec/learning.logs -O /etc/grsec/policy

  Pros: works with most distros, rule mgmt., rule inheritance, policy syntax support, RAP (Reuse Attack Protector)
  Cons: All policies in one file, gradm doesn’t write rules, Unfriendly in learning mode, not open source anymore, now expensive

AppArmor: Linux kernel module, better than SELinux, behavior-based & dynamic protection, restricts program’s resource access & privilege level (per application), many default policies, static-analysis & learning tools provided, handles zero-day attacks.
 
Logging in Linux / UNIX
Log editing: /etc/sysctl.conf   AND  /var/log/secure, /var/log/messages, /var/log/httpd/error_log, etc.
 (Generally written in ASCII)

/var/run/utmp (currently logged in users, terminal used, boot time, current state of system) | /var/log/wtmp (historical data / past user logins) | /var/log/btmp (bad/failed logins for failed attemps) | /var/log/lastlog (login ID, port, time of last login) | 
-	Not in ASCII (need tools f/ Packet storm security to edit)
-	utmpdump /var/run/utmp
o	ut_type, ut_pid, ut_id (terminal name), ut_user, ut_line (device name or tty or /dev), ut_host, ut_addr_v6, ut_time or ut_tv.tv_sec
-	last -f /var/log/wtmp     &  last -f /var/run/utmp

dmesg (display or driver message, kernel ring buffer) | /var/log/messages (global syslog messages), maillog (sendmail), secure (SSH logins, failed pwds, sshd logouts, invalid user accounts, break-in attempts, authn failures, etc.)
(Generally written in ASCII)
Syslog contents: (UDP port 514) | Facility codes:

Severity levels:  
Syslog security by default: No authn, no encryption, no replay prevention, DoS possible, Unreliable delivery, prioritization/differentiation
-	can be configured to use TCP

syslog.conf example:      destination auth.* 	{file(“/var/log/auth.log”);};
syslog-ng: replacement to syslog / enhanced with security / additional filtering / sends data with TCP
 chkconfig --del syslog    &&    chkconfig --add syslog-ng

rsyslogd:local & remote logging (via TLS, end-to-end encryption), syslog.conf, buffering, IETF syslog, regex for advanced filtering, /etc/rsyslog.conf  or   /etc/rsyslog.d/*.conf                    (custom file with -f parameter)

 Logrotate: /etc/logrorate.conf    (Directives: daily,weekly,monthly,size,  missingok,  rorate <n>, create <perms><owner><group>)
-	remove /etc/cron.daily/syslogd    (compression and emailing files possible)

Centralized Logging: Protects from log wiping, DoS possible due to lot of logs, Huge disk space, 1 pc with lot of sensitive data

auditd: Kernel module, cmd execution logging, CIS recommendation, File&Directory access logging, audit.rules & auditctl
-	Tools to review logs: ausearch (-m, --start, -k, -a, -f), aureport (--failed, -x --summary), autrace /usr/bin/find
auditctl -l (list all rules), -s (status), -b (max buffer), -f (failure flag 0,1,2), -R (read rules), -a (action&filter, used with -S), -D (delete all rules)

Security Utilities
Security is about visibility, baselining and automation
Linux commands:
$file <filename>  // show the properties of file by content, extension, etc.
$display <image>  // opens up the image in desktop mode to view it
$strings <filename>  // displays each string of printable characters from file
$touch <file>   //create or update file
$ln -s <file> <link>   //create symbolic link from file
$diff <file1> <file2>  //compare the contents of file1 and file and display differences
$cat /etc/passwd | cut -f6 -d ":"| sort -n | uniq -c //cut from file + display field 6 w/ delimiter : + sort by number + display unique count of each entry
$cat <file> | grep -v “text”   //remove the line from the output and displays the remaining entries from file

netstat   [-a (all ports), -l (listening ports), at (tcp), -au (udp), -s (stats) ]  // N/w connections, routing tables, Interface stats, Connections
ps  -ef   OR ps -C apache2 OR ps --sort=pcpu      //shows all running process, CPU info, memory usage, command name
top   //dynamic real time view of what’s running on system, processes  (type z or c, shift-p to sort by CPU utilization)
tail   // 10 lines by default  (/var/log/messages)    (-s refresh rate,  -c bytes to display, -f output appended content)
File Integrity Checking
Tripwire: Opensource & Commercial | File integrity checking | Writes to logs | Secure portable DB w/ file & directory attributes (permissions, ownerships, & hashes) | SHA hashes for verification | EDR (Enterprise Detection & response) capability via IDS w/ integrity checks 
Samhain: Open source (Install on Linux) | File integrity + Detection of rogue executables w/ SUID + Rootkit detection + Port mirroring + Log file analysis & correlation | Central manage and control | HIDS, Can prevent host based attacks, Monitor multiple hosts
OSSEC: Open source | Multi-platform | Integrates w/ HIDS & w/ SIEM | Comprehensive protection | File integrity checking, Log monitoring, Rootcheck, Process monitoring, active email alerts & alert logs | Can be used during IH to find IoC.

## Linux Firewalls
Both network and host-based firewall can be put on Linux.      http://fwbuilder.sourceforge.net/ 
iptables: OSI layer 3 and 4, Stateful, NAT capability.    Flush all existing rules: iptables -F
Drop all packets:  iptables -P INPUT DROP        &&      iptables -P OUTPUT DROP && iptables -P FORWARD DROP
Accept from localhost: iptables -A INPUT -I lo -j ACCEPT && iptables -A OUTPUT -o lo -j ACCEPT
Allow SSH connection initiated from this system:
   iptables -A INPUT -p tcp –dport 22 -j ACCEPT    && iptables -A INPUT -p tcp -m state –state ESTABLISHED -j ACCEPT &&      iptables -A INPUT -p udp -m state –state ESTABLISHED -j ACCEPT && iptables -A INPUT -p icmp -m state –state ESTABLISHED -j ACCEPT

Outbound any TCP, UDP, ICMP is ok:
     iptables -A OUTPUT -p tcp -m state –state NEW,ESTABLISHED -j ACCEPT
     iptables -A OUTPUT -p udp -m state –state NEW,ESTABLISHED -j ACCEPT
     iptables -A OUTPUT -p icmp -m state –state NEW,ESTABLISHED -j ACCEPT

-A = APPEND   |  -j = JUMP  |  -L = LIST | --state: NEW,RELATED,ESTABLISHED,INVALID | -m = LIMIT (match) | -d = DESTINATION (web,mail,dns) | -s = SOURCE (web,mail,dns)
firewalld (dynamically managed Linux firewall)
Different trust levels for different network interfaces; Uses D-Bus interface; 
-	firewalld uses firewall-cmd, firewallctl, firewall-config, firewall-applet
-	It is default firewall management tool in RHEL7, CentOS7, Fedora18 and newer 
-	Timed firewall rules, Ipv4 and Ipv6 supported, Logging of denied packets, Whitelisting of apps, Auto load LKM, Puppet integration, GUI based config management
nftables
Replaces netfilter. Less code duplication and high thruput, Configured with nft, subsystem of linux kernel; stateless packet filter
-	nft add rule ip filter output ip daddr 10.10.10.10 drop

## Linux Rootkits
Look for symptoms; rkhunter (Rootkit Hunter): Detects Rootkits, Backdoors, Local exploits by comparing SHA1 hashes of files in UNIX system, searches default directories where rootkits are generally stored, wrong permissions, hidden files, suspicious strings in kernel modules, special tests for Linux and FreeBSD. MUST RUN update command to get latest signatures (rkhunter –update). 
$rkhunter –propupd  //will create baseline with critical files set to monitor
$rkhunter -c –enable all –disable none   //to check the system and review the log from /var/log/rkhunter.log
-	Can email you alerts, capable of whitelisting, false positive possible

chkrootkit: checks for suspicious process and known bad files; command to run scan is: chkrootkit 
-	Uses strings and grep commands to check signatures and compare with /proc filesystem and ps command 
-	Bind shell infected on port 465
Linux chroot (jailed environment)
To isolate apps to particular directory; Apps that have built-in chroot: TFTP, (anonymous) FTP, BIND, SSH
Apache has chroot wrapper program. 
-	Apps with complex dependencies have difficulty in using chroot()  | double patching problem (at source & at copy)
-	TFTP is chroot to /tftpboot
Linux LXC/Containers
LXC: Creation/distribution of containers, middleground between chroot and virtual env. Uses kernel features: Namespaces (ipc, uts, mount, pid, network, user), AppArmor, SELinux, seccomp policies, chroots (w/ pivot_root), Kernel capabilities, C groups
-	Original Linux Containers

cgroups: Developed by Google, isolation of system resources (CPU and Memory), Control resources for a group of processes
namespaces: Developed by IBM, obtain a& present system resources to applications, Make appear resources to be dedicated to applications, isolation for single process.

Docker: Single application LXC container. Single process and stateless. Originally extracted from LXC, but later moved away to Go language’s libcontainer.

Linux-Vserver: Virtualization in Linux; Uses segmented routing, chroot, extended quotas, open source.
Linux Package management (apt) / Advanced Package Tool  (for Debian: dpkg)
Features: Download validation, Install dependencies, binary format, standard location for installations, User experience components, Verification of installations
apt install <package-name> | apt remove <package-name> | apt update | apt upgrade

*** END OF DOCUMENT ***
