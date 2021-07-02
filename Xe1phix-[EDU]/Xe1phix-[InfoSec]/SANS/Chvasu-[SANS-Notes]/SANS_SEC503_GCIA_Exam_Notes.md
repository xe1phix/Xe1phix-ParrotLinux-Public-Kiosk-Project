# BOOK-1: Why Packets?		(2/6)
“A trained analyst uses an alert as a starting point, not as a final assessment”
Analysis: Packets or protocols broken down into constituent bits and bytes to understand how they behave.
Hypothesize: Taking analysis and positing something about it. E.g. motivation of attacker, cause of behavior, tool being used, etc.
Synthesize: pulling together disparate facts or elements to create something new.
Report: Document findings

Nmap on local subnet performs ARP ping whereas on actual subnet performs ICMP ping. ICMP tunnel can be done using a tool called: ptunnel.

Possible options of tool used by attacker: Basic ping tool | Well-known widely used tool (older) | Less-known newer tool | Unknown tool
-	Tool used by attacker can give the analyst a hint on adversary’s skill

An alert has much value to investigate considering the timeline (situation of attacker control on internal systems). 

# BOOK-1: Concepts of TCP/IP		(3/6)
TCP/IP is what we run | OSI is what we talk about it
TCP/IP was officially cut-over on Jan 1st 1983. 
Process of adding headers as we pass down the TCP/IP stack is called: Encapsulation. Decapsulation or de-encapsulation, refers to the reverse process (need protocol and its length info during this process).

802.3 Ethernet II Header are fixed size (14-byte) | Implied length | CSMA/CD
IPv4 header standard length: 20-bytes; but with options; IPv4 header length can go up to 60-bytes. 
Total IP packet length – IP header length – TCP header length = data length

Bit = 0, 1 (smallest unit) | Nibble = 4 bits or 1 hexadecimal digit (0-9, A-F) | Byte = 2 nibbles or 2 hexadecimal digits or 8 bits | Word = 2 bytes or 16 bits or 4 hexadecimal digits | Double word = 4 bytes | Quad word = 8 bytes
-	Quad word is used in IPv6
-	Definition of Word is different for network people and systems engineering people.

IPv4 header: e.g. First line: 4500 003A => means: 4 = IPv4 version | 5 = IHL (double words, 32-bit sets) | 00 = TOS | 003A = Total Length of datagram/packet

TCP Options: A NOP pads either a single TCP option and/or an entire set of TCP options to fall on a 4-byte boundary, if necessary. 
Expected behavior of protocols can be found at: https://www.rfc-editor.org/
RFC793 = TCP | RFC768 = UDP | RFC791 = IP | RFC792 = ICMP | RFC2460 = IPv6
Implementations of RFC vary mainly due to the fact that many of the RFCs are notoriously hard to read or understand / ambiguous. A particular RFC may not cover all aspects of a protocol. When updates happen, implementors may not change their implementations quickly.
-	Language used in the RFC is the biggest problem. (Must, Must Not, Should, Should Not): RFC2119

NO WAY to guarantee universal acceptance and compliance of any of the protocols.

$tcpdump -c 2 (show first two packets) | -t (don’t display packet time) | -v (verbose, gives TTL, protocol info) | -e (mac address, ethernet header) | 

# BOOK-1: Introduction to Wireshark		(4/6)
Features: Sniff-live traffic | Read from pcap | Follow TCP/UDP streams and turn in to conversations | Examine packet layers | Drill into protocols, fields, values | Select packets based on protocol, field values or content | High-level overview of traffic | Export web objects for detailed analysis

Use tcpdump to find and isolate packets/sessions/events of interest
Use Wireshark to inspect details
Wireshark GUI: Packets list pane -> Packet details pane -> Packet bytes pane
Capture Map -> feature on Wireshark that shows different colors used on packets list pane. 
-	Colors do not mean anything (red is not bad, etc.). Every color is configurable. E.g. RST packets are shown as RED but doesn’t mean bad.

Statistics menu on Wireshark can provide details (e.g. protocol specific packets, IPv4 packets, etc.)
-	E.g. Statistics -> Capture File Properties shows first packet, last packet, etc. & 
-	Statistics -> Protocol Hierarchy shows list of all protocols and hierarchy in the packet file (the same can also be obtained using capinfos tool)
-	Statistics -> Conversations shows list of SRC_IP, ports, DST_IP, ports and number of packets, bytes exchanged (A to B and B to A) for Ethernet level or IP level OR TCP/UDP specific, etc.

Analyze menu on Wireshark can apply filters, follow TCP streams, etc. 
-	RED color: Client to Server request | Blue color: Server to client response (in TCP/HTTP stream follow)
-	Automatically applies the associated filter, when streaming TCP or HTTP (e.g. tcp.stream eq 0)

Edit -> Find a Packet OR CNTL-F to find a packet.
-	Search by “Packet bytes” not using the default “Packet list” options

# BOOK-1: Network Access/Link Layer		(5/6)
802.3 = Ethernet | 802.11 = Wireless | 802.15.1 = Bluetooth
The committee first met in 1980, February, hence the name 802.

Ethernet II -> 14-byte header + variable size payload + 4-byte CRC
Header = 6-byte destination MAC + 6-byte source MAC + 2-byte ethernet type 
Ether Type = IPv4: 0x0800 | IPv6: 0x86DD | ARP: 0x0806 | VLAN: 0x8100
Payload = Data that followed Ether Type = max 1500 bytes (MTU) & min 46 bytes (for collision detection to work)
-	Total max possible Ethernet frame length will be: 14 + 1500 + 4 = 1518 bytes
-	Total min possible Ethernet frame length will be: 14 + 46 + 4 = 64 bytes 
o	If payload is less than 46 bytes, it must be padded	(Late Collision might happen)
CRC is not found in sniffers like tcpdump, Wireshark, etc. CRC is used to detect frame corruption. Network card will not forward the frame, when CRC detects corruption.

In 802.2 (old ethernet, SNAP/LLC): Ether type field is a length field. This is the only difference. Header is same.

Specifically, for VLAN Header: VLAN tagging happens by segregating traffic on link layer (802.1Q VTP, VLAN Tagging Protocol). It is recommended to strip the VLAN tags before frame reaches IDS.
-	VLAN tab is inserted between source MAC and Ether type field, followed by TCI (Tag Control Info, 12-bit VID, VLAN Identifier and some metadata)

IP to MAC translation -> Internet layer to Network access layer 
-	In IPv4, it’s ARP | In IPv6, Neighbor Solicitation (request for MAC) / Advertisement (to send response)
ARP (0x0806) has been replaced by NDP (Neighbor Discovery Protocol) in IPv6.
-	Broadcast ARP request has unicast ARP response
-	In ARP, Destination MAC is ff:ff:ff:ff:ff:ff but inside the packet, the target MAC is 00:00:00:00:00:00

Within a Switch, there is a CAM (Content Addressable Memory) table that caches ARP data.

Gratuitous ARP: Request sent with same IP/MAC as source and as destination to check for duplicates on the network | Wireshark clearly shows it as 	gratuitous ARP, when this happens.
-	Can be spoofed as well [Wireshark adds square-brackets to show its interpretation]
Protection against ARP spoof is not easy | Configure switches to enforce BPDU guard or alerting us | Can prevent ARP spoof or cache poisoning using Hardware port security
-	Attacker can use dsniff tool to send requests with same IP but different source MAC to switch, which fails and converts into Hub (as CAM table is full and becomes unusable)

# BOOK-1: The IP Layer		(6/6)
IP: Unreliable protocol | Version: 1 nibble | If IP version field is invalid, the receiving host silently discards it without any error message sent to sending host| 4 and 6 are good values in this field | IPv5 is reserved for Internet Stream Protocol

IHL: 1 nibble | Indicates only length of IP header, not full frame | If IP options is used, IHL is higher than 5 (i.e. >20 bytes) | First step in decapsulation is to calculate header length | It is low-order nibble of 0-offset byte | Max possible value is 1111 (in binary) or 0xf (in Hex) or 15 (in decimal). This is equal to 60 bytes total Header length. This means, 20 bytes for actual header and 40 bytes for options field | IHL number if number of double-words (multiply IHL value by 4 to get total IP header bytes)
-	Different IP options: https://www.iana.org/assignments/ip-parameters/ip-parameters.xhtml
-	0x07 in 20th offset of IP Options indicates ‘record route’. This collects router’s IP on the packet travel path
(this can collect max 9 router’s IP, due to size limit of 40 bytes to Options field, as 4 bytes are used by Options)

IP Type of Service (TOS): 1 byte | Lower precedence packets to get dropped when router becomes overwhelmed | Used to make intelligent routing decisions (cost, delay, reliability, throughput)
-	Precedence (3 bits) | Delay (1 bit) | Throughput (1 bit) | Reliability (1 bit) | Cost (1 bit) | Reserved (1 bit)
IP Differentiated Services Byte: Modern method to utilize ToS byte (RFC2474) | DS Codepoint (6 bits, precedence indicator e.g. Assured Forwarding (AF)) + ECN (2 bits) Explicit Congestion Notification (00=No ECN, 01=ECN aware, 10=ECN aware, 11=Congestion experienced)
-	To properly use this, hosts provide ECN Capable Transport (ECT). In that case, routers update ECN to 11 during congestion to notify hosts.

IP Packet Length: 2 bytes | IP header (w/ Options) + TCP/UDP header + Data | Total length | 1500 bytes MTU

IP Identification: 2 bytes | value increases by 1 for each new packet sent (modern impl. randomize it, sequential IP_ID value useful for idle scanning) | Only used during fragmentation | set to 0, if DF (Don’t Fragment) flag is set
-	Idle scanning: Attacker pings the target, a few times, to read the IP ID value. Then spoofs target’s IP to send a SYN packet to another system. That system sends SYN/ACK to the target and target responds with RST/ACK along with new IP_ID. Then attacker pings again the target to realize that IP_ID is not incremental by a number, which confirms the port is open on target.

IP TTL: 1 byte | Max router distance possible is 255 | “ICMP time exceeded in transit” when TTL becomes 0

IP Protocol: 1 byte | Type of embedded protocol | Most common: 1=ICMP, 6=TCP, 17=UDP

IP Checksum: 2 bytes | Ensure packet data remains unchanged in transit | IDS/IPS/receiving-host must discard, if invalid | Practically speaking, checksum validation is generally not done in router, but done at IDS/IPS and host
-	If done at router, invalid checksum packets are discarded; If valid, TTL is decremented by router and re-compute checksum and forwards to next hop | e.g. 0x0000 is invalid checksum value
-	For Iv6, checksum is not computed at router (they are eliminated altogether)

Source IP and Destination IP: 4 bytes each
-	For inbound packets: source IP cannot be localhost/private ip/reserved ip/multicast ip | destination ip must only be our network and not broadcast ip
-	For outbound packets: source IP cannot be localhost/multicast/reserved/or not our internal IP | Destination IP cannot be multicast/reserved/private IP | Destination that appears to be broadcast or our own IP must be discarded

IP Options: source routing (strict [all routers] & loose [some routers]), record route, record timestamp, etc. | must be 4-byte boundary | mostly obsolete, used for troubleshooting | Many sites block packets that have IP options field set

IP Fragmentation: Always evil except Microsoft’s EDNS packets (that leads to IP fragmentation) | Someone is trying to hide, or something is misconfigured, or someone is attacking us
-	Data is fragmented with headers being copied (w/ minor changes) over to each fragment
-	Each fragment has same IP_ID value (called Fragment ID)
-	Fragment offset is used to determine the chronology (order of reassembly by receiving host)
o	Which position / where to set the fragmented data part while re-assembling it
o	Value must be multiplied by 8 (i.e. except final fragment, other fragments are multiple of 8)
-	1-bit MF (More Fragment) flag informs the receiving host whether more fragments are arriving
o	X=Reserved bit | D=Don’t fragment (DF) | M=More fragments (MF)
	Sending host sets DF flag to inform router not to fragment it; if fragmentation is req. packet will be discarded
	MTU Path Discovery: Host that dropped the packet due to need for fragmentation, will send MTU information in return, along with ICMP error message. Sending host understands the MTU needs and thus sends packets with <= MTU. 
•	This is done to avoid fragmentation overall.
Wireshark will not tell the protocol name, until it successfully re-assembles the packets, whereas
tcpdump shows the protocol name and type on 1st fragmented packet and shows only protocol name on other fragments.
VPN is one reason IP fragmentation can happen accidently (DF bit is not useful in case, as entire IP header is also encrypted in a VPN. This adds IPSEC header on top of encrypted content).

MSS clamping: Max Segment Size is the MTU but for TCP | Some VPN gateways forces endpoints to use a smaller MSS, which avoids the fragmentation except for UDP-based NFS traffic
IPv6
IPv6 header: IPv6 header is fixed size of 40 bytes | No checksum, fragmentation, flags, Options, IP ID, IHL fields | Payload size varies by data | 128-bits addresses | Main difference with IPv4 is the routing itself | TTL = Hop | Type of Service = Traffic class | Protocol = Next Header | Flow Label field is added
-	IPv6 can contain multiple extension headers: one for options, another for fragmentation, etc.

IPv6 address components: Prefix: used for routing | Subnet ID: Indicates subnet with hosts (flat network has this set to 0s) | Interface ID: one per n/w interface, derived from MAC address (EUI-64).
-	Interface ID = upper 24-bits of MAC address (OUI) + FF FE + lower 24-bits of MAC address (unique ID) 
-	First letter in an IPv6 start with 2 or 3, to be routable globally (global unicast addresses)

Source IPv6 and Destination IPv6: 128 bits / 16 bytes each
-	Inbound: source IPv6 cannot be from own network | Source IP that doesn’t start with 2 or 3 | Source IP is not our network publicly routable IPv6 address | destination IP has to be globally routable (start with 2 or 3) and must be own routable IP
-	Outbound: Source IP must be from our network and must be starting with 2 or 3 | Destination IP must be starting with 2 or 3
Teredo: Bad way to route IPv6 over UDP!

In IPv6, max payload is 65535 + 40 (header) = 65575 bytes

Next Header = 6 (TCP) and 17 (UDP) and 58 (ICMPv6)
In IPv6, TCP Max Segment Size (MSS) value of 65535 OR 
UDP length value of 0, indicates jumbogram.

In ICMPv6, type<128: Errors. Must route
type=128 or 129: Echo req/resp, may route
type>130: Must not route
			        ff02::1 => multicast address for all hosts
HOST-to-HOST
In IPv6, ARP doesn’t exist. It’s ICMPv6’s NDP (Neighbor Discovery Protocol), RFC2461
NDP = Neighbor Solicitation (type:135), sent to all hosts & Neighbor Advertisement (type:136) as response
-	NS is multicast (sending to specific set of systems, via channel) and not broadcast (sending to everyone)
-	In Ethernet layer, destination MAC would begin with 33:33:

IPv6 uses host-router Neighbor Discovery to determine Next Hop. If same as originating one (prefix), it’s LAN!
-	Caching is done, similar to IPv4, for efficiency reasons

DAD: Duplicate Address Detection: ensures two devices do not have same IPv6 address 

HOST-to-ROUTER
IPv6 uses Router Solicitation (type:133) for host to router and Router Advertisement (type:134) for response (even if Solicitation request is sent to all hosts). This confirms the router’s IP/MAC info.

Address Autoconfiguration provides stateless address configuration (temporary). DHCPv6 provides stateful one.

Router Lifetime is number of seconds the information in 
Router Advertisement should be kept by client

Neighbor Discovery Attacks:
•	Neighbor Solicitation spoof: Just like ARP reply in IPv4
•	DoS: Respond to NS with non-existent link address
•	Neighbor Unreachable Detection: Spoof response to NS that address is not reachable
•	Duplicate address detection: Spoof response to NS that address is already taken
•	Router Solicitation: Spoof router advertisement to indicate attacker’s IP is next-hop router

Privacy Extensions randomize lower 64-bit of the IPv6 address | mostly useful in residential, not much in enterprise | Expiration of address can be set with some timer as well (to change it after certain time)

Extension headers are chained between IP header and payload.
e.g. source routing (hop-by-hop), fragment, etc.
RFC2460

Some extension headers are fragmentable and some aren’t.
(fragmentable and unfragmentable)

Router’s drop large IPv6 packets (with ICMPv6: Packet Too Big message) & expects sending hosts to fragment it.
IPv6 minimum supported MTU is 1280 bytes
IPv6 tunnel broker: Hurricane Electric Internet services | non-production use | real-world like test use | IPv6 subnet assigned for test

# BOOK-2: Wireshark Display Filters	(1/5)
Wireshark display filters represent high-level analysis, whereas tcpdump filters represent low-level analysis.
contains: Filter that limits to view only packets that match the expression
Find Packet: Doesn’t change current view of packets | Jumps to next packet that matches search
matches: used for regexp searches
Analyze  Display Filters OR Blue ribbon -> Manage Display Filters
Do NOT use ip.addr != 65.55.11.78 and instead use not(ip.addr == 65.55.11.78) 
Analyze  Display Filter Expression allows us to search for protocol (e.g. IP) and provide any field values
Apply as Filter (available at packets pane and packet details pane and Statistics->protocol hierarchy)
Prepare as Filter: Not actively applying it but getting it ready with different combinations
Retrieve previous filters: File -> Open Recent | .config/wireshark/recent_common | Ribbon on filter
Edit  Mark All Displayed can be useful when TCP stream is done and filter is applied. Then we can export!
-	Saving or exporting marked packets will also save the ‘marking’ (part of metadata)

# BOOK-2: Writing tcpdump Filters	(2/5)
Uses BPF (Berkeley Packet Filter) | Can use filters like ip[9]==0x06 or tcp | udp[0:2]
-	protocol[displacement]
Bit Masking: masking with 0000 1111 (0x0f) | Logical AND (&) operation
-	three categories of filters: Most exclusive (e.g. tcp[13] = 0x03) | Less exclusive (e.g. tcp[13] & 0x03 = 0x03) | Least exclusive (e.g. tcp[13] & 0x03 != 0)
For higher-order nibble: 
tcp[12]/16 or tcp[12] >> 4    both are same. First one is division by 16, second one is  “right-shift”
     either it is /16 or right-shift, the lower-order nibble bits are moved into bit-bucket (kind of removed).
Outbound network: (dst net 172.16/12 or dst net 10.200.200.0/24 or dst net 192.168/16)
BPF in IPv6 is incomplete | Only supports ipv6 headers but not underlying protocols | ip6[6]=6 | icmp6
-	cannot use tcp[13]=2 in IPv6 as BPF

# BOOK-2: TCP		(3/5)
Full-duplex | Reliable protocol (unlike IP, UDP, ICMP) during data transmission (not at connection establishment) | Segments (Header + Data) | Sessions (w/ chronology on how it begins, exchanged and ends) | Unicast connection | >90% of internet traffic in TCP today | segmentation happens in TCP (like fragmentation in IP)
-	can detect out-of-order, missing, desync problems
In UDP, reliability becomes the problem of the programmer

TCP Ports: 16 bit each | 0 is valid port, but not open socket on host | Source port (ephemeral, 1024-65535) | Destination port (well-known, <1024)
Source port mutation: same source port being used for connection with
different destination ports (e.g. nmap scan)
Destination port mutation: same destination port being used in connection
from different source port (e.g. hping3 tool)
-	this scan helps to check target is alive (RST packet sent in response)

TCP Sequence numbers: 32 bit | used to order different streams of TCP segments received | ACK in response = SEQ + Number of bytes sent | By RFC, SYN and FIN count as 1 byte in the connection
-	ISN (Initial Sequence Number) is used to determine the zero-offset for the connection

By default, tcpdump shows relative sequence numbers (to show absolute sequence number, use -S option)

TCP Header Length: 1 nibble | 4 bits | Multiply by 4 to convert to segment bytes | TCP header is 20 bytes without options | TCP options are commonly set (unlike in IP options) e.g. max segment size field & value
-	Also called: Data Offset

TSO: TCP segment offload: Handover from kernel to NIC driver | Must be turned off so that analysts can use tools like tcpdump or Wireshark that can read only from kernel | Tool that can help to check that TSO is turned off is ethtool | $ethtool -k eth0  | Disabling TSO is not recommended for production servers | IDS collection engines or other packet collection sensors MUST have TSO turned OFF.

TCP Flags: code bits | FIN: graceful termination | SYN: Establish new connection | RST: Abort TCP session | PSH: transmits data immediately | ACK: existence of ack number value is valid | URG: existence of urgent pointer value is valid | ECN: responds to an explicit congestion notification | CWR: Congestion Windows Reduced (RFC 3168)
CWR – ECN – URG – ACK – PSH – RST – SYN – FIN
ECN is implemented in TCP, SCTP, DCCP. 

-S on tcpdump displays absolute tcp sequence and ack numbers (by default, they are relative numbers displayed) 

4-way handshake: Client sends SYN to server | Server sends SYN to client on that port | Client sent SYN/ACK | Server sends ACK
A 3-way open will have a 4-way close (FIN -> ACK -> FIN -> ACK) : Graceful termination
TCP Fast Open: for large content delivery networks | Fast Open Initial (cookie) & Fast Open Subsequent (cookie + data) | Cookie uses AES_128 crypto hash of client’s IP address

Aborted session: Any system just sends RST/ACK to other system | Also for closed ports or when segment is not part of established connection, RST flag is returned

Urgent flag: possible evasion at IDS/IPS, as most hosts ignore this due to confusion (urgent flag applies to last byte or first byte after that?): RFC793 is confusion but RFC 1122 is clarifying it a bit
-	Client software must implement SIG_URG handler, as it is almost not handled at transport layer.

It is not necessary to set a PSH flag to send data. Just ACK flag is sufficient.

Weird combinations of flags sent: 1. For evading IDS/IPS    2. Mapping     3. OS fingerprinting
In TCP re-try or re-transmissions, e.g. no RST packet received in return | same packet is sent again (number of times, depends on OS). When no response in multiple attempts, then gives-up!

TCP Windows Size: 16 bit / 2 bytes | TCP buffer size for connection | Flow control | Size 0 means telling sending host to stop sending data | Initial window size is used in OS fingerprinting
-	The value keeps changing over packets sent (decreases after receiving data, but increases later again)

Window size and throughput are significant factors in speed / performance.
-	Throughput = Window size (in bits) / Latency (in seconds)
LaBrea: Traffic to unassigned IP addresses means, someone is scanning the internet.
-	LaBrea will send a fake-response to an ARP request for an unassigned IP.
-	When a SYN comes from scanning host, LaBrea sends fake SYN/ACK response. Upon receiving data, ACK is never sent back. This slows down scanning host. This tool does this by manipulating TCP Window size.
Any connections to LaBrea are anomalous (not normal).

TCP Checksum: Checksum includes some data from IP header (source ip, dst ip, tcp protocol, etc.) + TCP header + payload (data) | When IP or TCP checksum is invalid, packet is dropped. Else passed to app layer
-	Routers don’t care about TCP checksum / Receiving host must perform the checksum verification

TCP Options: Max 40 bytes: Maximum Segment Size (MSS) | NOP: Pads final option to 4-byte boundaries | Can be used for OS fingerprinting | Can be used for evasion attacks | NMAP uses TCP options to fingerprint OS
-	Minimum supported MSS is 536 bytes in IPv4 and 1220 bytes in IPv6

Timestamp: Specifically, for PAWS (Protection Against Wrapped Sequence numbers) | Compute roundtrip time
-	TCP Extensions for High Performance
(Number of clock ticks since the last reboot) | Multipath TCP: Established key from one subflow is used for another session / IDS/IPS has challenges to reassemble such packets
Selective acknowledgement (SACK) | MSS | WSCALE | Timestamp (TS) | MultiPath | Fast Open | NOP | EOL Option
TCP Stimulus responses: 
-	When an active host is listening on port: SYN/ACK is responded
-	When an active host is not listening on that port: RST/ACK is responded
-	When an active host doesn’t receive initial SYN, instead receives SYN/ACK directly, then it responds with RST/ACK (whether port is open or closed) => backscatter (unsolicited SYN/ACK segments)
-	When a host doesn’t exist: Router responds with ICMP host unreachable message
-	Port is blocked and Router/Firewall are silenced: No response received and sender retries again & again
-	When TCP delivery is failed, receiving host checks the missing segment and acknowledges sender (in 3 duplicate attempts) -> In tcpdump, we notice duplicate ack (& SACK is good for performance)
Nmap has option to use decoy IPs to perform the scan (to hide the actual IPs)
TCP Stream Reassembly: Pretty complicated | Lot of ambiguities

# BOOK-2: UDP		(4/5)
Send and Pray protocol | No flow control (window size / throughput) | ICMP source quench (type: 4, code: 0) can be used as alternate to flow control | transactional protocols use UDP (Q&A type) | OpenVPN will tunnel across other networks with UDP port 1194 (TCP 443 can be used where UDP is not permitted)
-	DNS / SNMP / NTP / DHCP
UDP can be one-way request | response is not mandatory
Fields: Source port, destination port, length (16 bit, header + data, minimum 8 bytes | 0 byte length used in IPv6, jumbogram), and checksum (covers both header and data / same formula as in IP and TCP / optional in IPv4, mandatory in IPv6)

traceroute uses UDP | sends 3 UDP packets to each hop | works by incremental TTL / ICMP time exceeded msg
-	UDP source port is incrementing by 1 
-	Router responds with ICMP error (time exceeded), along with part of IP/TCP headers received to it
-	Comparing the source port of sending host across packets can be useful to associate packets
-	The final target sends ICMP port unreachable message

UDP Stimulus responses: 
-	Host not listening on port 53: ICMP Port unreachable message (type: 3, code: 3)

# BOOK-2: ICMP		(5/5)
No built-in reliability | Proto = 1 in IPv4 & Proto = 58 in IPv6 | report error conditions.
e.g. large packet but DF bit is set in IP 

Conditions when ICMP error message should NOT be sent: Error condition is temporary | For another ICMP error message | A destination broadcast address | A source address of broadcast or loopback address | For bad checksums (we don’t know what’s broken e.g. IP could be altered) | Any fragment that is not 0-offset

Header: Type/Code: 1 byte each | Checksum: 2 bytes | Addln info: 4 bytes

ICMP error messages include the IPv4 embedded header | Wireshark can show this with filter as ip.src (even if actual source may vary)

Windows tracert uses ICMP (3 packets each with TTL 1 and increasing) | Linux traceroute uses UDP

ICMP echo requests are generally dropped at the front router (to avoid mapping of servers by attackers).
Using ICMP, we can not only discover live hosts, but also routers (e.g. Fragmentation is needed but DF bit is set, Destination host unreachable, etc.)
-	Routers and Switches are most unsecure devices compared to other systems on the internet.

ICMP echo request to a dst server, can return with a router’s redirect message (to take better route next time).
o	This can be used as MITM by attacker
ICMPv6: 0-127: Error messages | 128-255: Informational messages

# BOOK-3: Packet Crafting for IDS/IPS		(1/4)
Scapy: Can manipulate all layers of TCP/IP stack | easily craft application data | read, modify, write pcap files | Can import scapy packets into Python for complex tasks | Philippe Bondi (author)
-	Discovering fields in a given TCP/IP layer in Scapy: ls()    (e.g. ls(Ether), ls(TCP), ls(IP), etc.)
-	lsc() command will show all the commands available in Scapy
-	Assigning values: >>>ip=IP()  | >>>ip.src=”192.168.0.100” | >>>ip=IP(src=”192.168.0.100”)
-	Stacking layers: SYN=Ether()/IP()/TCP()/pay	| pay=”Sending data to 1.1.1.1”
-	Writing to pcap file: wrpcap(“/tmp/data.pcap”, SYN)  | wireshark(SYN) | Can run from snort tool to test
$snort -A console -q -K none -r /tmp/data.pcap -c local.rule
-	Reading from pcap file: >>>packets=rdpcap(“/tmp/data.pcap”)=> generally done to anonymize pcap data
o	Packets is now a LIST	| can access it using packets[0]

MUST delete IP.chksum and TCP.chksum in altered pcap files, to let scapy re-create new checksums.
>>>del packets[0][IP].chksum	| >>>del packets[0][TCP].chksum

-	Must be root to send packets | >>>send(packets) (only sends but don’t know response)	| sr1(packets) (sends packet and shows received response) | sendp(packets) (sends packet as-is)
o	In send(), Ether() header is added but in sendp() nothing is added by Scapy.

When scapy sends packet and destination host responds to our sending host, the actual host doesn’t know about packet sent. So, in TCP, it sends RST/ACK and in UDP, it sends ICMP port unreachable message.
-	We can use iptables in Linux (Firewall) to block the RST/ACK and ICMP messages being sent
-	To fix this issue, we have Cooked vs. Raw Sockets
o	In Cooked, Kernel builds the packet Scapy asked | In Raw, Scapy sends directly to n/w interface (In raw, it is PF_PACKET for Linux)

To import all Scapy functions into Python script:
		from scapy.all import *

# BOOK-3: Wireshark Part-III		(2/4)
Exporting objects from Wireshark (e.g. HTTP objects) | FTP files cannot be exported directly from Wireshark
After exporting all objects to a folder: $grep “^MZ” *  //will look for executables
When built-in Wireshark export doesn’t support, use “Follow TCP Streams”
-	SMTP is the common way to transfer files | required decoding content

Wireshark can save the attachment, but cannot decode the Base64 content. Just keep the base64 content and remove everything from the raw saved content (based on banner: _MIME_BOUNDARY_000_11181)
-	tshark options: -z is for statistics

# BOOK-3: Application protocols with Snort and Suricata		(3/4)
Snort: Packet decoder + Protocol decoder/parser + Perform detection + Alert/Log
Customization of IDS/IPS rules by analyst: Depends on sensor location, purpose.
•	snort.conf has the configuration (/etc/snort/snort.conf) (Has HOME_NET, EXTERNAL_NET, HTTP_*)
o	this file includes all other config files
•	classification.conf  -> assign priorities to logical classification
•	reference.conf -> add shorthand placeholders for custom signatures
•	threshold.conf -> rate limiting of alerts, suppression of rules or addresses
•	rules.conf & signatures
preprocessors: code that is supplied with snort to perform processing to 
decoded packets before handing off to detection engine.
e.g. reassembly of TCP segments, IP fragments, etc. into a session

$snort -c <use rules file>
$snort -T -c <use snort config file>	//tests the snort config file
$snort -K none		//overrides the logging configuration or use -l ./logs (to write logs to current folder)
$snort -A console		//specifies how alerts are generated
$snort -r sample.pcap -c snort.conf -q -K none -A console	//read from pcap and write logs to console
Ouput sample:
09/28-17:48:27.850168  [**] [1:100000034:1] Failed FTP Login [**] [Priority: 0] {TCP} 10.121.70.151:21 -> 10.234.125.254:2217
Snort output Format:   date:time [GID:SID:revision number] [Priority] {protocol} source_ip:port -> dst_ip:port
[**] delimits the Snort identifiers and alert message from the remaining output
SID is the rule number in local.rules
Default snort logs in /var/log/snort	| -A fast	//will omit packet details during logging

Writing Snort rules: requires us to write custom rules for various reasons (refer to book)
Suricata has dynamic protocol detection | Whereas Snort does protocol detection based on what we say in config
Suricata is multi-threaded | Whereas Snort is single-threaded
-	However, Snort provides API for write custom rules or custom preprocessors
o	e.g.  stream5 & frag3 preprocessors apply to multiple reassembled packets to detect anomaly

Snort rule = Rule header (mandatory) + Rule options (optional to provide) | Alert order is random
-	If rule options are provided, then SID (signature ID) is mandatory. SID less than 1M are reserved. 
-	Rule Options: parenthesis(keyword: argument;) | Hex data in content using two vertical pipes

alert tcp source_ip src_port <> dst_ip dst_port (msg: “Vis alert”; sid=1000001; rev=1; content=”|90 90|”;)

alert (alert & log), pass (skip the packet, don’t do anything), log (just log, no alert)
protocols: ip, tcp, udp, icmp
Rule content options:
-	Can optimize content based on begin and end (offset/distance) OR based on relative to end of previous content match (depth/within)
-	fast_pattern is content keyword modifier | can specify shorter content value as pattern-matching
o	e.g. if string “netcat” is found in content search, then look for “Microsoft windows”
-	Use of PCRE (Perl Compatible Regular Expressions): Always couple with static content match!
-	Use of nocase; will remove the case sensitive check on content
-	Use of http_uri; will search for content only in the HTTP URL or URI included in the HTTP request

Stream Reassembly: 
flow: keyword used to examine direction and state of traffic flow | greatly improves efficiency | to_server/from_client and to_client/from_server | best practice is to use <> instead of -> in snort rule

Debug a rule on failures: Remove each rule option (e.g. content), one by one, to see if the rule alerts.

Managing false negatives and false positives

Best practices for writing rules: avoid use of any for both ports | Use longest content matches OR unique shorter via fast_pattern | Avoid rules without content match, negative content match, or pcre without content match anchor | Use “bail conditions” flow, offset, depth early in the rule

Application protocols 
Protocol decode: Identify protocol -> parse it -> Look for violation -> examine values -> expose field names to user

HTTP Verb: GET/POST/PUT/HEAD, etc.
HTTP Version: 1.0/1.1/2.0 | HTTP/2 RFC7540 (Google’s SPDY) / TLS “hello” uses ALPN (App Layer Protocol Nego)
HTTP/2 packets are called “frames”. 
	Browser sends HTTP/1.1 request w/ headers: “Connection: Upgrade, HTTP2-Settings & Upgrade: h2c-14”
	Client sends PRI * HTTP/2.0

SMB: Server Message Block, adaptation of CIFS | 19 different messages, only 10 are common
SMB2/3 protocol: First command is ‘NEGOTIATE_SSESSION’. We can filter this using: “smb.cmd == 0x72” (negotiate protocol) or “smb2.cmd == 0” | 
-	Security Blob: ASN.1 encoded (challenge-response authn protocol)

SESSION_SETUP (establishment): Domain, Host, User | “smb2.cmd == 1” | Server sends session ID (smb2.sesid), 8-byte value, after user authn (challenge / response) | Password is NOT sent in clear / sent according to dialect agreed during negotiation / GSS-API / SPNEGO (Simple Protected Negotiation) (Encryption is NOT required) | Session IDs are NOT logged anywhere.

TREE_CONNECT (Access Services): Display filter: “smb2.cmd == 3” | Server assigns Tree ID for client’s requested object (smb2.tid), used for all subsequent access requests | Tree ID is ephemeral / not logged anywhere.
CREATE (Directory navigation): Creating handler to access the directory | “smb2.cmd == 5” | e.g. \Windows\, this is relative to earlier Tree: \\IP\C$ | Server create 16-byte GUID / File ID value in response | MACB times

QUERY_DIRECTORY (Obtain directory listing): “smb2.cmd == 14” | Includes search pattern inside the parent directory (referenced by GUID file ID) | Server also provides metadata related to folders and files in the parent directory (e.g. last change date, etc.). | MACB (Modified <contents>, Last Access, Change <file name>, Born <creation>) times | EoF size (byte count) | Allocation size (number of bytes on clusters on which file resides)

CREATE (Open a File): “smb2.cmd == 5” | smb2.filename | Server assigns GUID File ID (smb2.fid), ephemeral | Request to create a file handle to access the file | Response includes bit mask: SMB2_CREATE_QUERY_MAXIMAL_ACCESS_REQUEST (list of permissions for authnd user for resource) | 6 different types of disposition field values in request

READ/WRITE (Read from a file or write to a file): “smb2.cmd == 8” | Partial file reads with byte offsets & length | Cannot “follow TCP stream” to get original file (but can provide leads, e.g. can notice file access), UTF-16 encoding (NULL bytes \x00, represented with “ . “) and binary | Request has GUID File ID | Server responds with plaintext ‘Data:’ with offset indicators | Wireshark and Zeek can be use to reconstruct a file | Multiple READ commands are sent by client, to obtain large files based on offset indicators

CLOSE: smb2.cmd == 6 | De-assigns GUID File ID
TREE_DISCONNECT: smb2.cmd == 4 | De-assigns TREE ID | Un-map the drive
LOGOFF: smb2.cmd == 2 | De-assigns SESSION ID (after all trees are disconnected) | Can remain open long, unless forced policy exists at domain level

Indicator of Compromise (IoC) for SMB: client-to-client file share over SMB | client-to-server access at unusual hours | File share access by same account from different PC/country/LANs, etc. | Large copy actions | Too fast movement from one network to another

Microsoft RPC implementations: RPC over SMB | RPC directly over TCP/UDP (DCOM) | RPC over HTTPS
-	Microsoft EPM (End Point Mapper) runs on TCP port 135
o	3-way handshake -> Bind request -> Map request 
o	Service client is connecting to: Present in: Tower Pointer of the DCE/RPC Endpoint Mapper, Map

# DNS (Domain Name System): 
   Answer RR: (Resource Records) | Authority RR | Additional RR |

Transaction ID (0-offset field) in header must match for 
Query and response to be accepted by the receiving system.

Max 512 bytes in DNS data. So DNSSEC uses E-DNS that can send more than 512 bytes (also on IPv6)
-	EDNS uses Additional Records field to embed pseudo resource record.
DNS Query payload format:	(label = byte count)
 
DNS Response payload format:		(pointer = location where to find full data in the binary content)
Same until number of additional RRs in above. After that, it is below format.

DNSSEC: Integrity and authenticity of DNS records | PKI to digital sign responses | Introduces new DNS resource records: RRSIG, DNSKEY (verifying public key), DS, NSEC
-	Created to combat DNS cache poisoning, incorrect DNS responses, etc.

DNS attacks: DNS spoofing (wrong answer sent to requestor) | DNS cache poisoning (wrong answer sent to DNS server OR poisoning authoritative servers info) | Fast-flux (single/double)
-	bailiwick checking: prevent server from accepting data from an unrelated domain
dnscat2: Relies on recursion to pass a DNS query to the attacker-controlled server

DNS over TLS: Port 853 | Cloudfare: 1.1.1.1
Lot of DNS responses with NXDOMAIN within short span of time indicates DNS Cache poisoning.

Snort rule for DNS protocol	 byte_test: #bytes, operation, value, offset

tshark -n -r dns-bpf.pcap -Y '(udp.dstport == 53 and dns.flags.response == 0 and dns.count.queries > 0 and dns.count.answers > 0)' -T fields -e dns.a

SMTP (Simple Mail Transfer Protocol): Begins with MAIL command, server responds with 250 OK for success or 550 for failure. Then client sends DATA command (if success), then server responds with 354 code. Data ends with dot “.”

# BOOK-3: IDS/IPS Evasion	(4/4)
Insertion: IDS accepts a packet that destination host rejects unwanted data but accepts attack vector	//wireshark cannot see this correctly
Evasion: Destination host accepts everything that comes to it and the IDS misses it completely
	//wireshark can see this correctly

IP layer evasions: Fragmentation overlap, TTL variations
TCP evasions: Bad TCP checksums, Make IDS/IPS miss session beginning, TCP sequence overlapping, Abnormal TCP flags (TCP Fast Open), Manipulate TCP timestamp values, Manipulate TCP Urgent data

TCP insertions with timestamp:  
TCP insertions with URGENT pointer:  

Application layer evasion: e.g. Shellshock (exported functions stored as env variables | command added at end is run/executed, even when env variables are just read)  

Non-technical evasions: Payload in international language
Defense against attacks at IDS level: 
-	Malicious payload in multiple fragments or 1-byte payload packets: frag3 and stream5 preprocessor
-	Overlapping fragment content or TCP segment content: customize frag3 & stream3 for target-based host
-	Application layer attacks: Use of protocol level preprocessors (e.g. SMB, DNS, HTTP, etc.) for anomalies

By default, the bsd policy will be applied in this config  =>

Best defenses:
Host-based IPS
Target-aware IDS (Target Based Reassembly TBR)
Advanced protocol decoders/normalization

# BOOK-4: Architecture		(1/3)
Deployment options: Inline (IPS) & Passive (IDS)
IDS sensors must have minimum of 2 NICs | 
1.	Passive listening interface to monitor n/w traffic | Has no IP | Attacker should not be able to discover interface on monitored n/w | Block outbound traffic from sensor
2.	Communication interface for management console, within internal IP address
IPS sensors must have minimum 3 NICs (2 inline NICs and 1 management NIC) | Cannot have false positives
-	Some have built-in firewall and some are firewall by themselves
-	No IP addresses (transparent) or with IP address (firewall/proxy) | Can fail open or closed
-	IPS are often deployed in “monitor” mode long term

Special purpose vs. Generic sensor: Focused rule-set, specific ports & protocols inspected, focused alerting | wide rule coverage, heavy alerting, wide ports and protocols inspected

Approach for traffic collection & monitoring: Start at perimeter -> Servers -> Data

Devices to collect packet captures:
1.	Very low-cost option: Unpowered Tap (for non-production) | for production, use powered Tap
-	A basic Tap has four (4) ports (2 network ports and 2 monitor ports)
o	Each port on tap can act as both a tap and a mirror
-	Need to merge streams (downstream and upstream) between two sites of same company
-	Merge can be done by OS inside IDS (Bond two interfaces) -> via Bonding Kernel module
-	$ip link set bond0 up	//ensure bonding library is loaded and bond0 is the alias to it
-	Aggregate half-duplex to full-duplex data

Packet broker / IDS load balancer: provides aggregation, round-robin traffic distribution, session-based/stream-based distribution, service segregation	(Sees traffic as streams of data / not packet by packet)

Collecting packets at scale: Minimum 7 days of full packet capture on the busiest link
Open-source:
-	Deamonlogger with scripting
-	Stenographer (Go-based from Google)
Commercial: Require High-end Taps (if traffic > 10Gbps)! Endace, Gigamon, NETSCOUT, Garland Technology
-	SentryWire : 100Gbps w/ 6+ petabytes storage
-	Endace: high-speed packet capture

# BOOK-4: TLS		(2/3)
TLS 1.3 leverages TCP fast open (TFO) | DNS over TLS 1.3 is almost impossible for detection by IDS/IPS
TLS ALPN -> indicates the applications layer protocol name
STARTTLS:  Protocol extension to transform unsecure communication to a secure one with TLS | No separate listening port required | Server announces STARTTLS | Mostly used by SMTP message transfer agents (MTA)
-	Client sends EHLO (Extended Hello), Server responds with 250 STARTTLS
o	HELO is not encrypted | EHLO has possible encryption
STARTTLS downgrade attacks are possible by ensuring there isn’t any successful negotiation on protocol support between client and server | Fails open to unencrypted exchange | opportunistic encryption
-	STARTTLS can be used for SMTL, LDAP, etc.

Decryption of encrypted traffic on packets is possible. One example is: Use of terminating TLS proxy.
-	Gigamon GigaSMART
-	F5 Networks SSL Visibility and Orchestration

If cannot decrypt, then at least profile the communications / conversations.
-	e.g. small request and large response | vice-versa
-	Cisco open-source tool: Joy	-> https://github.com/cisco/joy

## Major TLS vulnerabilities: 
-	Heartbleed: OpenSSL v1.0.1-1.0.1f | allowed to access a leaked memory that a process relies by keeping the firewall alive (heartbeat request). RFC6520-> Such heartbeat request should NOT (it’s not MUST NOT) be sent during handshake. | Wireshark will name the Heartbleed packet as malformed. | Payload length: 16,384

# BOOK-4: Zeek		(3/3)
Network traffic analysis framework | Event driven | Customizable w/ site-specific analysis using scripting | 
-	PF_RING is software that can be used to improve packet capture performance

Zeek event engine uses DPD (Dynamic Protocol Detection)
-	For example, when HTTP protocol is used on unusual port, Zeek can still understand that it is HTTP

Zeek’s NetControl trigger rules to change configuration for switch, router, firewall.

Raise a notice: creating some kind of notice for event to signal the analyst to examine the activity (Snort alert)

Zeek can be installed in standalone or cluster mode (by original design) | defined in nodes.cfg file | 
-	Components: Proxy (synchronizes the state of Zeek), Manager (central log and notice collector), Worker (known as sensor | used for sniff, reassembly, protocol analysis)
o	Zeek broker is used to transmit traffic between nodes
o	Communication to manager is initiated by worker
	But latest rules are pushed by manager to worker nodes
o	Proxy and Manager will be on same host

Indicator of Compromise (IOC) and Events of Interest (EOI): Behavior-based alerting in Zeek
-	E.g. extremely large MIME attachment OR md5 hash of file transferred is same as md5 hash of known malicious file, etc.

Snort Signature (defines static properties of packet or stream found in headers or payload) vs. Zeek Event (define behaviors or characteristics of network traffic)
-	Zeek works by triggering event functions that can log interesting information
-	A user script can be subscribed to an event, triggering only when associated event occurs.
/usr/local/zeek/share/zeek/site/local.zeek
Logs are written to: /usr/local/zeek/logs	(at least one log file per protocol identified)

Zeek logs data can be connected together for a particular stream using the unique ID (connection ID or UID).
-	Will log only when protocol is in data and parser is loaded

Commands: $zeekctl	| $zeek -r http.pcap file-extract.zeek	| $cat ssl.log | zeek-cut  id.orig_h id.orig_p

Zeek start-up errors log: /usr/local/zeek/spool/zeek/stderr.log	(must be root)
Scripts | Signatures | Notice capabilities

Applying zeek signature on a packet capture file:
$zeek -r ssh.pcap -s linux.sig
//generates signature.log file

Sample zeek signature file:
signature dnscat {  
    ip-proto == udp  
    dst-port == 53  
    payload /.*dnscat.*/
    event "UDP dnscat tunnel"
}
By default zeek searches for 1024 bytes for a signature match.
/usr/local/zeek/share/zeek/base/init-bare.zeek has the property: dpd_buffer_size that can change the bytes.

## Zeek Scripts:
User-created custom scripts must be placed into: /usr/local/zeek/share/zeek/site location | Default zeek scripts are present in /usr/local/zeek/share/zeek/base directory

# BOOK-5: Practical NetFlow Applications	(1/3)
SiLK (Systems for Internet-Level Knowledge) | Collects and analyzes NetFlow data | e.g. detects abnormally large volume of outbound traffic (exfiltration) | Doesn’t collect payload, primary purpose is statistical analysis of traffic
-	Flow data stored in efficient binary format called: Repository
NetFlow/IPFIX: A way to capture metadata about conversations | IPFIX is now an IETF standard (referred as NetFlow v10) | NetFlow v5,7,9 are common | sFlow (industry standard for sampling flows), jFlow (Juniper’s implementation of sFlow)

Flow: src ip + dst ip + src port + dst port + protocol	(5-tuple)
Data: TCP flags (flags, --flag-initial, --flag-session), total bytes, and packets, start time, end time, duration, acquiring sensor identification

A refresh interval: Time for collection of NetFlow packets from sensor and to forward to storage/repository.
-	Every 10 min in general
-	Data storage is hierarchical in nature (Sensor type, Traffic direction (in/out), time interval)

rwfilter: Input is binary flow records from repository, converted tcpdump records, or output from another SiLK tool | Default output is binary format | Can pass output to other SiLK tools for further processing | providing a filter is MANDATORY (unlike with tcpdump)
-	Cannot dump data to console output. Gives error: 
o	“rwfilter: Will not read/write binary data on a terminal stdout.”
rwp2ya2silk: reformat tcpdump libpcap files into SiLK data for analysis

Some of the output processing tools are: rwcut, rwstats, rwuniq
  (by default, last 60 min)

Cisco NetFlow and SiLK formats are NOT same. SiLK on VM has 29 fields.

YAF -> Yet Another Flowmeter
 
$rwfilter --type=all --start-date 2019/05/01 --end-date 2019/05/04  -not-scidr 172.16.0.0/16,10.200.200.0/24,192.168.0.0/16 -flags-initial S/SA -dport 3389  -pass stdout | rwuniq -fields sip -no-titles | wc -l
Note: A dry-run is possible with rwfilter tool (to display the possible output, without actually running it).
                --print-stat
--stime or –etime (permits to use minutes, seconds, microseconds)
Possible outputs:
--pass=stdout | --fail=stdout | --print-stat: count of pass/fail records
--print-vol: counts of flow/bytes/packet
--max-pass: max number of flows to pass
--max-fail: max number of flows to fail

$rwfilter --type=all --proto=0-255 --start-date=2019/05/01 --end-date=2019/05/04 --pass=stdout | rwstats --fields=sip --values=bytes --count=10

$rwcut --fields stime,sip,sport,dip,dport,bytes

# BOOK-5: Modern & Future Monitoring		(2/3)
Alert driven vs. Data driven at sensor | Data-driven means Threat hunting

Security Onion, Verizon vflow, SIEM/SEM solutions, etc. are good for graphs/visual diagrams but not so useful for threat hunting (could be useful for identifying connections to wired countries, etc.)

PAE – Packet Analysis Engine: Consumes raw packet capture file | generates frequency analysis (e.g. graph of IP ID numbers)  
-	Can be used for Long Tail Analysis

Machine Learning: Applied mathematics | Linear Regression | Jupyter tool: web-based interface for python notebook-style | Loss OR Error: How far from correct are we! 
-	Mean Squared Error (MSE): 
o	15th order polynomial has the lowest MSE
Overfitting: It’s bad | Destroys predictive ability | 

Learning: Revise the function coefficients to minimize loss

Old ML approach: Data+Rules=Predictions
New ML approach: Data+Predictions=Rules

In Linear regression -> Rules means coefficients
Ŷ = σ(wX + b)	=> sigma of non-linear activation (weight x matrix/groups of numbers/vector + bias)
Scalar: Vector with one value | Dimensions: Number of related values 
Vector: Ordered set of values (set of coordinates) | Matrix: vector with grid (rows and columns)
Set of vectors taken together is: tensor | https://www.tensorflow.org/
-	To get features to be of same shape, we vectorize them 
One-hot encoding: In each packet, only one bit is hot or one
3D graph line would be a plane | more than 3D would be hyperplane
Cyber kill Chain: Reconnaisance->Weaponization->Delivery->Exploitation->Installation->C&C->ActionOnObjectives
