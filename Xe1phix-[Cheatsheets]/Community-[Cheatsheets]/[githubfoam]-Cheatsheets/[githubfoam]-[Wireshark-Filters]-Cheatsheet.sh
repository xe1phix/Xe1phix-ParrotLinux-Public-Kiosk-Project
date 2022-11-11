-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
https://www.wireshark.org/docs/dfref/ #Display Filter Reference
-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
eth.addr 	Traffic to or from an ethernet address
-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
wlan.addr 	Hardware address [Ethernet or MAC address]
-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
arp.src.proto_ipv4 	Sender IP in ARP packets
-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
tcp.analysis.ack_rtt 	Round-trip time

#The TCP retransmission mechanism ensures that data is reliably sent from end to end
tcp.analysis.retransmission 	#Display all the retransmissions,packet loss has occurred on the network somewhere between client and server
-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
#wireshark version 3.4.9, after downloading&configuring maxmind databases
ip and not ip.geoip.country == "United States"  #Exclude U.S.-based traffic
ip.geoip.dst_city == "Dublin" #Destination City [IPv4] 
ip.geoip.city == "Dublin" #Source or Destination City [IPv4]  
ip.geoip.dst_country == "Ireland"
ip.geoip.dst_country_iso == "IE"
!ip.geoip.country == "United States" #All Destination Countries Except United States
not ip.geoip.country == "United States" #All Destination Countries Except United States:  
-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
#wireshark version 3.4.9
ip.addr == 10.43.54.0/24
ip.dst == 10.43.54.0/24
ip.src == 10.43.54.0/24
-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
eth.dst == 00:0C:CC:76:4E:07 #source mac filter
eth.src == 00:0C:CC:76:4E:07 #destination mac filter
ether host 00:18:0a:aa:bb:cc #a specific mac. This will not work on interfaces where traffic has been NATed like NAT mode SSID or an Internet interface

bootp.hw.mac_addr == 00:0C:29:D5:AA:AA
-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
Protocol filter
tcp - will only display TCP packets
udp - will only display UDP packets
icmp - will only display ICMP (ping) packets
dhcp - will display DHCP packets (if you are using an old version of Wireshark you'll need to use bootp)
dns - will display DNS packets
-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
#DORA - Discover, Offer, Request, and Ack
#Display Filter Reference: Dynamic Host Configuration Protocol https://www.wireshark.org/docs/dfref/d/dhcp.html 

dhcp and ip.addr == 10.43.54.0/24 #only dhcp 
dhcp.hw.mac_addr == a4:83:e7:c9:37:cd #find DORA - Discover, Offer, Request, and Ack.The DORA all has the same ID
(dhcp and ip.addr == 10.43.54.0/24) and ip.addr == 10.43.54.99 # DHCP MMC - Client IP Address
(dhcp and ip.addr == 10.43.54.0/24) and dhcp.hw.mac_addr == a4:83:e7:c9:37:cd # DHCP MMC - Unique ID (Client MAC Address)
-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
tcp.port == 80 - this will display un-encrypted TCP traffic on port 80. 
tcp.port == 443 - this will only show encrypted TCP traffic using port 443. 
udp.port == 53 - another way of specifying DNS traffic, this will filter off of DNS's use of UDP port 53. 
-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
#https://www.wireshark.org/docs/dfref/d/dns.html
#https://www.wireshark.org/docs/dfref/d/dnsserver.html

(tcp.dstport == 53) && (dns.flags.response == 0) && (dns.qry.type == 0x00fc) #DNS Zone Transfer request 
(tcp.srcport == 53) && (dns.flags.response == 1) && (dns.qry.type == 0x00fc) #DNS Zone Transfer response
dns.qry.type in {251 252} or dns.flags.opcode eq 4 #DNS Zone Transfer



#UDP or TCP Stream
udp.stream eq ${udp.stream}
tcp.stream eq ${tcp.stream}

#Retransmit the query with the same transaction ID to their primary server
#Retransmit the query with the same transaction ID to their secondary (or ternary) server
#If retransmits the query to either their secondary or ternary servers, the UDP stream number changes.The transaction ID does not.
dns.id eq ${dns.id} 
dns.id == 0xff0b #Transaction ID

#nslookup yahoo.com 193.247.121.196 #dns query via dns server(193.247.121.196),optional
dns.resp.name == yahoo.com 
dns.resp.name == yahoo.com  and dns.time > 0.01

dns.time > 0.5 #0.5 seconds 500 miliseconds
dns.time > 1 # 1 sec
dns.time > .6 # greater than 600 miliseconds

dns and dns.qry.name == "microsoft.com" #filter based on the queried domain name

#https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml
dns.qry.type == 15 #filter MX queries

DNS pointer(PTR) query/response
dns.qry.type == 12
udp.port == 53
port 53 #Capture only DNS (port 53) traffic
port not 53 and not arp #Capture except all ARP and DNS traffic
!dns.response_in and dns.flags.response == 0 and dns # the lack of a recorded reply (!dns.response_in) combined with only looking for DNS queries (dns.flags.response == 0) that are only UDP port 53 (dns)
dns.flags.response == 0 # only DNS queries
dns.flags.response eq 1 # only DNS response queries

#https://datatracker.ietf.org/doc/html/rfc6895 RFC 6895 Domain Name System (DNS) IANA Considerations
dns.flags.rcode != 0 or (dns.flags.response eq 1 and dns.qry.type eq 28 and !dns.aaaa) #DNS Errors
dns.flags.rcode == 3 #NXDomain  Non-Existent Domain
((dns.flags.rcode == 3) && !(dns.qry.name contains ".local") && !(dns.qry.name contains ".svc") && !(dns.qry.name contains ".cluster"))
(dns.flags.rcode == 0) && (dns.qry.name == "microsoft.com") #No Error ,nslookup microsoft.com 193.247.121.196

dns.flags.rcode != 0 or (dns.flags.response eq 1 and dns.qry.type eq 28 and !dns.aaaa)
dns.flags.rcode eq 0 and dns.time gt .1 #Slow Responses

dns.flags.rcode > 0 #finding DNS errors
-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
Ping sweep
icmp.type == 8 || icmp.type == 0
ICMP Type 8 = ECHO Request
ICMP Type 0 = ECHO Reply
icmp || icmpv6

(icmp.type==3) && (icmp.code==1) 

“icmp.type==8 and not icmp.resp_in“ #filter for all ICMP echo request packets where the “response in” field does not exist, and find all unanswered pings
“icmp.type==8 and icmp.resp_not_found“ #no response was seen
-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

tcp.dstport == 25 #Wireshark Filter Destination Port
tcp.port in {443 4430..4434}

tcp.flags.reset == 1 && tcp.flags.ack == 1 && tcp.seq == 1 && tcp.ack == 1 #connection refusal ACK scan

http.request
http.request.method == GET
http.request.method == POST #Wireshark Filter HTTP POST
http.request.method == POST && frame contains "login" #Wireshark Filter HTTP POST

#Capture HTTP GET requests
port 80 and tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x47455420 #looks for the bytes 'G', 'E', 'T', and ' ' (hex values 47, 45, 54, and 20) just after the TCP header. "tcp[12:1] & 0xf0) >> 2"

ip.addr == 10.43.54.65
ip.addr == 10.92.182.6 or ip.addr == 172.16.7.7 - is going to display both 10.92.182.6 as well as 172.16.7.7
ip.addr== 192.168.12.160 and ip.addr==192.168.12.161 #Filter packets between two devices in a capture, menu -> statistics -> conversations
ip.addr >= 10.80.211.140 and ip.addr <= 10.80.211.142
ip.addr == 10.92.182.6 and dns - will only show the host 10.92.182.6 and it's DNS traffic. 
(ip.addr == 172.16.7.42 or ip.addr == 172.16.7.7) and dns - is going to show dns traffic for two IPs 172.16.7.42 OR 172.16.7.7
(ip.addr == 172.16.7.42 and dns) or (172.16.7.7 and icmp) - here the parentheses are being used to combine two completely different filters. DNS traffic for 172.16.7.42 as well as icmp traffic for 172.16.7.7. 
not ip.addr == 172.16.7.7 - is going to exclude all traffic that has an IP of 172.16.7.7
ip.dst == 10.43.54.65
ip.src == 10.43.54.65

#tcp 3 way handshake, https://www.mdpi.com/applsci/applsci-06-00358/article_deploy/html/images/applsci-06-00358-g001.png
ip.addr== 192.168.12.160 and ip.addr==192.168.12.161 and (tcp.flags == 0x0012) #looks for TCP flags set,displays the ones which have both SYN and ACK set.
ip.addr== 192.168.12.160 and ip.addr==192.168.12.161 and and (tcp.seq==0 or (tcp.seq==1 and tcp.ack == 1 and tcp.nxtseq==1))

#analyze - conversation filter - TCP
“tcp.flags.syn==1 or (tcp.seq==1 and tcp.ack==1 and tcp.len==0 and tcp.analysis.initial_rtt)” #show the handshake packets of any conversation,

Edit > Preferences > Protocols > TCP > Relative sequence numbers #get the actual TCP sequence number

Wireshark Filter SYN
tcp.flags.syn == 1
tcp.flags.syn == 1 && tcp.flags.ack == 0
SYN/ACK packets(bitwise filter)
tcp.flags & 0x12
tcp.flags.syn == 1 && tcp.flags.ack == 0 && tcp.ack == 0

TLS handshake
tls.record.content_type == 22
only TLS traffice
tls
client Hello
tls.handshake.type == 1
server Hello
tls.handshake.type == 2
connection close
tls.record.content_type == 21
tls.handshake.extensions_server_name contains "badsite"
#When the timeout occurs, the client usually sends an RST to the server to filter out the packets with the handshake timeout. 
(tcp.flags.reset eq 1) and (tcp.flags.ack eq 0)
#Filter out packets that are slow to respond to SYNACK during the server handshake
tcp.flags eq 0x012 && tcp.time_delta gt 0.0001

frame contains "tls"

net 192.168.0.0/24 #Capture traffic to or from a range of IP addresses
dst net 192.168.0.0/24 #Capture traffic to a range of IP addresses
src net 192.168.0.0/24
src net 192.168.0.0 mask 255.255.255.0

host 172.18.5.4 #Capture only traffic to or from IP address 172.18.5.4
host www.example.com and not (port 80 or port 25) #Capture non-HTTP and non-SMTP traffic on your server (both are equivalent)
host www.example.com and not port 80 and not port 25
host 8.8.8.8 # capture traffic going to the Google DNS server 8.8.8.8. 

(tcp[0:2] > 1500 and tcp[0:2] < 1550) or (tcp[2:2] > 1500 and tcp[2:2] < 1550) #Capture traffic within a range of ports
tcp portrange 1501-1549

ether proto 0x888e #Capture only Ethernet type EAPOL
not ether dst 01:80:c2:00:00:0e #Reject ethernet frames towards the Link Layer Discovery Protocol Multicast group
not broadcast and not multicast

ip #Capture only IPv4 traffic,get rid of lower layer protocols like ARP and STP

dst port 135 and tcp port 135 and ip[2:2]==48 #Blaster worm
#Welchia worm
#looks for an icmp echo request that is 92 bytes long and has an icmp payload that begins with 4 bytes of A's (hex)
#the signature of the welchia worm just before it tries to compromise a system
icmp[icmptype]==icmp-echo and ip[2:2]==92 and icmp[8:4]==0xAAAAAAAA 
# worm query
#looks for SYN packets originating from a local network on those specific ports,contacting other hosts on ports 135, 445, or 1433
dst port 135 or dst port 445 or dst port 1433  and tcp[tcpflags] & (tcp-syn) != 0 and tcp[tcpflags] & (tcp-ack) = 0 and src net 192.168.0.0/24

#Heartbleed Exploit
tcp src port 443 and (tcp[((tcp[12] & 0xF0) >> 4 ) * 4] = 0x18) and (tcp[((tcp[12] & 0xF0) >> 4 ) * 4 + 1] = 0x03) and (tcp[((tcp[12] & 0xF0) >> 4 ) * 4 + 2] < 0x04) and ((ip[2:2] - 4 * (ip[0] & 0x0F)  - 4 * ((tcp[12] & 0xF0) >> 4) > 69))
------------------------------------------------IPv6 basecamp------------------------------------------------
dst host ff02::1 #Capture IPv6 "all nodes" ,find rogue RAs
-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
Menu-View-Packet Bytes #The “Packet Bytes” pane
canonical hex dump of the packet data
Each line contains the data offset(left), bytes interpreted as sixteen hexadecimal(middle), and bytes interpreted a sixteen ASCII (right). Non-printable bytes are replaced with a period (“.”).

offset(left) (hexadecimal) beginning of the frame
0010 0x10 16
0020 0x20 32
0030 0x30 48

left middle                                           right
0020 20 21 22 22 24 25 26 27  28 29 2A 2B 2C 2D 2E 2F 
0030 30 31 32 33 34 35 36 37  38 39 3A 3B 3C 3D 3E 3F  

3F(hexadeciaml)=63(decimal) -> 63rd byte 

"X" in ascii = 78 in hexadecimal

converter hexadecimal,decimal,byte etc.
https://www.rapidtables.com/convert/number/hex-to-decimal.html
converter table
https://circuitglobe.com/wp-content/uploads/2016/09/hexadecimal-to-binary-conversion-examples-3.jpg
-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
Menu-View-Coloring Rules-Import #https://gitlab.com/wireshark/wireshark/-/wikis/ColoringRules
-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
#Tor
tcp.port == 9001 or tcp.port == 9030 or  tcp.port == 9150

#RawCap
RawCap.exe -q 127.0.0.1 - | Wireshark.exe -i - -k #Streaming PCAP to Wireshark
#write the PCAP data to a named pipe, and then let Wireshark "sniff" packets from that named pipe
RawCap.exe 127.0.0.1 \\.\pipe\RawCap #write PCAP data to a named pipe called "RawCap"
Wireshark-Capture-Options-Manage Interfaces-Pipes- "+" button -Name the pipe "\\.\pipe\RawCap" 
-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
#https://www.wireshark.org/docs/dfref/x/x509ce.html
SL.handshake.type==1 SSL  Client  Hello  requests

#https://www.wireshark.org/docs/dfref/x/x509sat.html
-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------