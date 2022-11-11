----------------------------------------------------------------------------------------------------
tcpdump -ni tap55ec3c7f-91 ip6 #locate the ICMPv6 packets

tcpdump -s0 -n -i any -w /tmp/$(hostname)-smbtrace.pcap #if the SMB client or SMB server is a Unix host,Troubleshooting Server Message Block (SMB)

tcpdump -D #Print the list of the network interfaces available on the system and on which tcpdump can capture packet
tcpdump -X -vvv -n -i eth0

#client-side traffic to a specific SSL virtual server listening on the VLAN external
# filters on the virtual server's IP address and port
tcpdump -vvv -s 0 -nni external -w /var/tmp/www-ssl-client.cap host 10.1.1.100 and port 443

#check the Client Hello message between the client and the server
#the Client Hello messages contain 01 in the sixth data byte of the TCP packet
tcpdump "tcp port 8081 and (tcp[((tcp[12] & 0xf0) >>2)] = 0x16) \\
  && (tcp[((tcp[12] & 0xf0) >>2)+5] = 0x01)" -w client-hello.pcap

#In the SSL handshake message, the tenth and eleventh bytes of the data contain the TLS version
tcpdump "tcp port 8081 and (tcp[((tcp[12] & 0xf0) >>2)] = 0x16) \\
  && (tcp[((tcp[12] & 0xf0) >>2)+9] = 0x03) \\
  && (tcp[((tcp[12] & 0xf0) >>2)+10] = 0x03)"

#Application Data Packets Over TLS
#Once the handshake is finished, the client and server can exchange the application data
#application data packets also contain the TLS version in the second and third data bytes
tcpdump "tcp port 8081 and (tcp[((tcp[12] & 0xf0) >>2)] = 0x17) \\
  && (tcp[((tcp[12] & 0xf0) >>2)+1] = 0x03) \\
  && (tcp[((tcp[12] & 0xf0) >>2)+2] = 0x03)" -w appdata.pcap

#SSL Connection Failures
#check the first byte, which contains 15 or 21, based on the failure
tcpdump "tcp port 8081 and (tcp[((tcp[12] & 0xf0) >>2)] = 0x15) || (tcp[((tcp[12] & 0xf0) >>2)] = 0x21)" -w error.pcap

#examine server-side traffic from one client to any pool member, 
#the -i option to specify the VLAN on which the servers reside
#filter on the client IP address, the server subnet, and the port on which the servers are listening.
tcpdump -vvv -s 0 -nni internal -w /var/tmp/www-ssl-server.cap host 192.168.22.33 and net 10.1.1.0/24 and port 8080


tcpdump host 100.111.222.50 and port 443 #Traffic to or from host 100.111.222.50, where the source or destination port is 443
tcpdump host 100.111.222.50 or host 100.11.12.99 #traffic sent between the two
tcpdump not host 100.111.222.50 #All traffic except anything to or from host 100.111.222.50
tcpdump host 100.111.222.50 or host 100.11.12.99 and port 443 #traffic to or from either 100.111.222.50 or 100.11.12.99 will be captured only where the source or destination port is 443
tcpdump '( src port 1039 and src host 204.57.235.37 and dst host 172.17.254.20 and dst port 443 )

tcpdump net 100.111.222.0/24 and not host 100.111.222.50 #Traffic to or from any host on the 100.111.222.00/24 network except anything to or from host 100.111.222.50
tcpdum[ net 192.168.103.0 mask 255.255.255.248
tcpdump  src net 1.1.1.0/24 #traffic from hosts with addresses in the 1.1.1.0/24 network only
tcpdump  dst net 1.1.1.0/24 #Traffic to hosts with addresses in the 1.1.1.0/24 
tcpdump  net 1.1.1.0/24 and 1.1.2.128/32
tcpdump  net 1.1.1.0/24 or net 2.2.2.0/24 #Traffic to or from network 1.1.1.0/24 or to or from network 2.2.2.0/24
tcpdump  net 1.1.1.0/24 or net 2.2.2.0/24 and port 80
tcpdump  net 1.1.1.0/24 or net 2.2.2.0/24 and udp src port 53

tcpdump -i eth1 ‘tcp[13] = 0x2'
tcpdump -i eth1 ‘tcp[13] = 0x12'
tcpdump portrange 21-25
tcpdump src port 1025

#The first two bytes of a TCP packet are the source port. If its offset is zero and the length is 2 bytes
#the filters are: tcp[0:2] for the source and tcp[2:2] for the destination port.
tcpdump 'tcp[0:2] == tcp[2:2]' #view traffic with the same source and destination
tcpdump 'tcp[2:2] == 80' #view traffic destination on TCP port 80

#configure filters for IP header properties using the same logic as the port source and destination filter.
#The flags section of an IP header is only 3 bits long, and 1 bit is reserved
#the only 2 bits that you can toggle in this octet are: the 1 bytes 01100000.
tcpdump 'ip[6] & 64 != 64' #view all traffic with the same source and destination IP
tcpdump 'ip[12:4] == ip[16:4]' #DF (don't fragment) bit set (IP) 
tcpdump 'ip[6] & 32 != 32' #MF (more fragments) bit set (IP) 

tcpdump 'ip[12:4] == ip[16:4]' #source ip equal to destination ip,classic land attack
tcpdump (tcp[0:2] = tcp[2:2]) && (ip[12:4] = ip[16:4]) #land attack

tcpdump src host 1.1.1.1 and dst port 80 or 443
tcpdump greater 32 #traffic base on packet size
tcpdump <= 102
tcpdump -i any #see what happens on the network
tcpdump -i any -c 20 # -c 20 packets only 
tcpdump -i any -c 5 -vv #more verbose output
tcpdump -i any -c 5 -vvv #-v more verbose output
tcpdump -i any -c 5 -vvv -t # -t Don't print a timestamp on each dump line. 
tcpdump -i any -c 5 -vvv -t #Don't print a timestamp on each dump line.
tcpdump -i any -c 5 -vvv -t #Don't print a timestamp on each dump line.
tcpdump -i any -c 5 -vvv -t #-n Don't convert addresses (i.e., host addresses, port numbers, etc.) to names. 

tcpdump icmp #traffic of a specific protocol, tcp, udp, icmp etc
tcpdump udp
tcpdump tcp

tcpdump less 32 #packets below or above a certain size (in bytes) 
tcpdump greater 128
tcpdump > 32 
tcpdump <= 128

#The Ethernet header is 14 bytes, with only three fields (src, dst, and type)
tcpdump -ni 1.1 -e ether proto 0x8809 #capture only LACP packets,capture LACP packets on interface 1.1 of a Link Aggregation Group (LAG),
tcpdump -e dst 192.168.0.2 #link-level header output
tcpdump 'ether[12:2] == 2054' #Match all ARPs
tcpdump 'ether[12:2] == 2048' #Match all IP packets 

tcpdump ether host 0:2:b3:7:10:73 #Match against a specific hardware (MAC) address
tcpdump src host 0:2:b3:7:10:73 #Match against a specific hardware (MAC) address
#traffic passing through a specific gateway (firewall, router)
#where 0:2:b3:7:10:73 is the gateway's MAC address and 192.168.103.1 is the gateway's IP address, excluding traffic to and from the gateway itself
tcpdump ether host 0:2:b3:7:10:73 and not host 192.168.103.1 

tcpdump dst 192.168.0.2 and src net and not icmp #traffic going to 192.168.0.2 that is not ICMP
tcpdump ip6 #only IPv6 Traffic
tcpdump -ttttnnvvS #view with verbose output,no host/port resolution,absolute sequence number and human-readable timestamps
tcpdump -nnvvS src 192.168.122.1 and dst port 4444
tcpdump -nnvvXSs 1514 #the final “s” increases the snaplength, grabbing the whole packet
tcpdump host 192.168.122.131 #using host, you can see traffic that’s going to or from 192.168.122.131
tcpdump -vv src mars and not dst port 22 #traffic from a host that isn’t SSH traffic

tcpdump dst 192.168.0.2 -vv -A -T snmp
tcpdump dst 192.168.0.2 -vv -A -T snmp -w snmpv3.pcap
tcpdump -vv -A -T snmp -s 0 "(dst port 162) or (src port 161) or (dst port 161) and (dst 192.168.0.2)"
tcpdump -i eno1 -T snmp -n dst portrange 161-162

tcpdump net 192.168.122.0/24 #Find packets by network
#raffic coming from 192.168.x.x and going to the 10.x or 172.16.x.x networks, and we’re showing hex output with no hostname resolution
tcpdump -nvX src net 192.168.0.0/16 and dst net 10.0.0.0/8 or 172.16.0.0/16

#The first byte in an ICMP packet is the message type; the second byte is the code
tcpdump -ni internal 'ip[9] == 1' #The IP header byte 9 is the protocol field icmp
tcpdump 'icmp[0] == 8' #View only the ICMP Echo Requests
tcpdump 'icmp[0] == 0' #View only the ICMP Echo Replies
tcpdump 'icmp[0] != 8 and icmp[0] != 0' #View all ICMP packets except ICMP Echo Requests and Replies
tcpdump 'icmp[icmptype] != icmp-echo and icmp[icmptype] != icmp-echoreply' #ICMP Packets that are not ECHO/REPLY (standard ping)
tcpdump 'icmp[0] == 3 and icmp[1] == 4' #View only the ICMP "Fragmentation needed but DF bit set" (Type 3, code 4) packets
tcpdump -n icmp and 'icmp[0] != 8 and icmp[0] != 0' #icmp echo request and reply
tcpdump -nnvXSs 0 -c1 icmp #packets with HEX output
tcpdump port 3389 #Show traffic related to a specific port
tcpdump -tlni eth1 -n icmp
tcpdump -i eth1 -c1 -n -s0 -vvvv icmp
tcpdump -c 1 -X icmp #PAcket Contents with Hex Output
tcpdump -tlni em0 
# listen for ICMP traffic on em0 network interface
tcpdump -tlni em0 -n icmp
# capture one ICMP packet and decode it
tcpdump -i nfe0 -c1 -n -s0 -vvvv icmp
tcpdump -i eth1 -c1 -n -s0 -vvvv icmp -w temp.pcap
tcpdump -r capture_file #read PCAP files

tcpdump -nn -l port 25 | grep -i 'MAIL FROM\|RCPT TO' #Capture SMTP / POP3 EmailNTP Query and Response

tcpdump dst port 123 #NTP Query and Response

tcpdump -nn -v port ftp or ftp-data

tcpdump -nn ip6 proto 6
tcpdump -nr ipv6-test.pcap ip6 proto 17 #IPv6 with UDP and reading from a previously saved capture file

#rotate tcpdump captures
#the file capture-(hour).pcap will be created every (-G) 3600 seconds (1 hour),capture-{1-24}.pcap, 
#if the hour was 15 the new file is (/tmp/capture-15.pcap)
tcpdump  -w /tmp/capture-%H.pcap -G 3600 -C 200
tcpdump -i any -w ~/captures/capture_%Y-%m-%d-%H-%M-%S.cap -G 30 -n -X -Z $USER “port 465”

tcpdump 'src 192.168.122.84 and (dst port 4444 or 22)'



 Only the PSH, RST, SYN, and FIN flags are displayed in tcpdump‘s flag field output. 
 URGs and ACKs are displayed, but they are shown elsewhere in the output rather than in the flags field ]

URG  =  (Not Displayed in Flag Field, Displayed elsewhere) 
ACK  =  (Not Displayed in Flag Field, Displayed elsewhere)
PSH  =  [P] (Push Data)
RST  =  [R] (Reset Connection)
SYN  =  [S] (Start Connection)
FIN  =  [F] (Finish Connection)
SYN-ACK =  [S.] (SynAcK Packet)
          
#The filter tcp[13] look at offset 13 in TCP HEADER
#the number represent the location within the byte, the !=0 means that the flag is set to 1
header[byte #] == value #the expected value for byte 13 of the TCP header

tcpdump	'tcp[13] == 1' #View only the FIN bit set
tcpdump 'tcp[13] & 8!=0' #Show all PUSH (PSH) packets
tcpdump 'tcp[13] & 32!=0' #Show all URGENT (URG) packets

tcpdump 'tcp[13] & 3 == 3' #View both SYN and FIN set
tcpdump 'tcp[13] & 3 != 0' #View either SYN or FIN set
tcpdump 'tcp[13] == 2 or tcp[13] == 1' #View only SYN or only FIN set

tcpdump 'tcp[13] & 16!=0' #Show all ACKNOWLEDGE( ACK) packets

tcpdump 'tcp[13] = 6' #Both the SYN and RST Set
tcpdump 'tcp[13] & 4!=0' #Show all RESET (RST packets
tcpdump	'tcp[13] & 4 == 4' #View RST set, ignore the others

tcpdump 'tcp[13] & 2!=0' #Show all SYNCHRONIZE (SYN) packets
tcpdump -ni internal 'tcp[13] == 2'#only the SYN packets
tcpdump 'tcp[13] == 2' #View only the SYN bit set
tcpdump 'tcp[13] & 2 == 2' #View only SYN set, ignore the others
#looks for the set SYN bit and ignores the rest of the flags in the header
#perform a logic AND (&) to remove all but the value of the SYN bit and then test it
#if the TCP flags are 00010010 and the mask for Syn is 00000010(2 in binary) then 00010010 + 00000010 = 00000010.
tcpdump -ni internal 'tcp[13] & 2 == 2' 

tcpdump 'tcp[13]=18' #packets that have both the SYN and ACK flags set,TCP flag byte equal to 18 (SYN flag set + ACK flag set = 2 + 16 = 18)
tcpdump -ni internal 'tcp[13] == 18'
tcpdump 'tcp[13] & 18 == 18' #View SYN set and ACK set, ignore all others
tcpdump 'tcp[13] & 1!=0' #Show all SYNCRONIZE/ACKNOWLEDGE (SYNACK) packets
tcpdump -ni internal 'tcp[13] == 18' or 'tcp[13] == 2 #view the SYN packets and the SYN and ACK packets,

#Alternatively tcpflags syntax, SYN,RST,FIN 
tcpdump 'tcp[tcpflags] == tcp-syn'
tcpdump 'tcp[tcpflags] == tcp-rst'
tcpdump 'tcp[tcpflags] == tcp-fin'
tcpdump 'tcp[tcpflags] == tcp-urg'
tcpdump 'tcp[tcpflags] == tcp-push'
tcpdump 'tcp[tcpflags] == tcp-ack'

#Identifying malformed/malicious packets
tcpdump 'tcp=[13] = 6' #Packets with both rst and syn flags shouldn't be the case
tcpdump 'tcp[32:4] = 0x47455420' #Find cleartext http get requests
tcpdump -s 0 -A -vv 'tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x47455420' #Capture only HTTP GET
# tcp[((tcp[12:1] & 0xf0) >> 2):4]  determines the location of the bytesafter the TCP header,then selects the 4 bytes
tcpdump -s 0 -A -vv 'tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x504f5354' #Capture only HTTP POST
tcpdump -s 0 -v -n -l | egrep -i "POST /|GET /|Host:" #Host and HTTP Request location from traffic.
tcpdump 'tcp[(tcp[12]>>2):4] = 0x5353482D' #Find ssh connection on any port via (banner text)
tcpdump 'src 10.0.2.4 and (dst port 3389 or 22)' #group your options using single quotes

tcpdump -nn -A -s1500 -l | grep "User-Agent:" #Extract HTTP User Agent from HTTP request header.
tcpdump -nn -A -s1500 -l | egrep -i 'User-Agent:|Host:'
tcpdump -vvAls0 | grep 'User-Agent:' #HTTP User Agents
tcpdump -vvAls0 | grep 'GET' #Cleartext GET Requests
tcpdump -vvAls0 | grep 'Host: #Http Host Headers
tcpdump -vvAls0 | grep 'Set-Cookie|Host:|Cookie:' #HTTP Cookies


tcpdump 'tcp[(tcp[12]>>2):4] = 0x5353482D' #SSH Connections,regardless of what port the connection comes in,getting the banner response
tcpdump -vvAs0 port 53 #DNS Traffic
tcpdump -vvAs0 port ftp or ftp-data #FTP traffic
tcpdump -vvAs0 port 123 # NTP traffic

#Find Cleartext Passwords
tcpdump port http or port ftp or port smtp or port imap or port pop3 or port telnet -lA | egrep -i -B5 'pass=|pwd=|log=|login=|user=|username=|pw=|passw=|passwd= |password=|pass:|user:|username:|password:|login:|pass |user '
tcpdump 'ip[6] & 128 != 0 #bit in the IP header that never gets set by legitimate applications
tcpdump -s 0 -A -n -l | egrep -i "POST /|pwd=|passwd=|password=|Host:" #passwords from the POST data

tcpdump -nn -A -s0 -l | egrep -i 'Set-Cookie|Host:|Cookie:' #Capture cookies from the server by searching on Set-Cookie: (from Server) and Cookie: (from Client) 

C:\Program Files\Wireshark>dumpcap -D
C:\Program Files\Wireshark>dumpcap -i 9
C:\Program Files\Wireshark>dumpcap -i 12 -w C:\Users\verona\Downloads\testtrace.pcapng -b filesize:2000

tcpdump -i eth0 -w dump.pcap
tcpdump src 192.168.2.3 and tcpport 80
dumpcap -i eth0 -w dump.pcapng
#searches either for the strings “pass” or “USER” on all packets going to/or coming from port 80 (TCP or UDP)
ngrep -q -d eth0 -W byline -wi "pass|USER" port 80 #The “-i” flag instructs ngrep to ignore case when matching

#HTTP Headers
tcpdump -vvvs 1024 -l -A host yahoo.com

#Show OSPF protocol traffic on the interface:
tcpdump -i eth-s1p1c0 proto ospf
#Show Telnet traffic on the interface:
tcpdump -i eth-s1p1c0 port telnet
tcpudmp -i eth-s1p1c0 port 23
tcpdump -i eth-s2p1c0 udp port 68 
#Show all traffic on the interface except port 80:
tcpdump -i eth-s1p1c0 not port 80
#Show traffic only from specific host:
tcpdump -i eth-s1p1c0 host 192.168.10.24
#Show additional information about each packet:
tcpdump -vv -i eth-s1p1c0
#Limit the size (in bytes) of captured packets 
tcpdump -s 320 -i eth-s1p1c0

#Saving a TCP dump in a .pcap file
tcpdump -w capture.pcap -i eth-s1p2c0 host 10.1.1.1 and host 20.2.2.2
tcpdump -nni any host 10.1.1.1 -w capture.pcap
tcpdump -nni any host 10.1.1.1 and host 20.2.2.2 -w capture.pcap
tcpdump -s 1500 -i eth-s1p1c0 -w /var/log/tcpdump_s1p1c0.cap

#Saving a TCP dump in a .pcap file
tcpdump -w capture.pcap -i eth-s1p2c0 host 10.1.1.1 and host 20.2.2.2
tcpdump -nni any host 10.1.1.1 -w capture.pcap
tcpdump -nni any host 10.1.1.1 and host 20.2.2.2 -w capture.pcap
tcpdump -s 1500 -i eth-s1p1c0 -w /var/log/tcpdump_s1p1c0.cap

tcpdump src host 1.1.1.1 and arp

tcpdump dst host 1.1.1.1 and not icmp
tcpdump 'src host 1.1.1.1 and (arp or icmp)'



tcpdump 'tcp[(tcp[12]>>2):4] = 0x5353482D' #SSH Connections,getting the banner response
tcpdump -vvAs0 port 53 #DNS Traffic
tcpdump -vvAs0 port ftp or ftp-data #FTP  Traffic

#VLAN tagging
tcpdump vlan 10 #Match packets with a VLAN tag of 10
tcpdump 'ether[14:2] & 4095 == 10' #ensure not including the priority or canonical bits as part of the VLAN tag
#Match packets with a VLAN tag of 10
#perform a logic AND of 4095 against the contents of bytes 14 and 15 
tcpdump '0100000000001010 & 0000111111111111 = 0000000000001010' 
----------------------------------------------------------------------------------------------------
#tcpdump output,IPV4 header explained
#https://upload.wikimedia.org/wikipedia/commons/thumb/6/60/IPv4_Packet-en.svg/1200px-IPv4_Packet-en.svg.png

#If the -v flag is specified, information from the IPv4 header is shown in parentheses after the IP or the link-layer header
tos tos, ttl ttl, id id, offset offset, flags [flags], proto proto, length length, options (options)
#https://www.tcpdump.org/manpages/tcpdump.1.html

tos is the type of service field; if the ECN bits are non-zero, those are reported as ECT(1), ECT(0), or CE
ttl is the time-to-live; it is not reported if it is zero
id is the IP identification field
offset is the fragment offset field; it is printed whether this is part of a fragmented datagram or not
flags are the MF and DF flags; + is reported if MF is set, and DF is reported if F is set. If neither are set, . is reported
proto is the protocol ID field. 
length is the total length field. 
options are the IP options, if any


$ sudo tcpdump -i any -vvvv dst 10.33.22.21
tcpdump: listening on any, link-type LINUX_SLL (Linux cooked v1), capture size 262144 bytes
12:38:21.039533 IP (tos 0x0, ttl 57, id 12400, offset 0, flags [none], proto TCP (6), length 44)
    vg-ubuntu-02.61748 > printer.org.local.http: Flags [S], cksum 0x7b48 (correct), seq 3600759408, win 1024, options [mss 1460], length 0
 
 #map IPV4 header format to tcpdump output
                    tos tos, ttl ttl, id id, offset offset, flags [flags], proto proto, length length, options (options)
12:38:21.039533 IP (tos 0x0, ttl 57, id 12400, offset 0, flags [none], proto TCP (6), length 44)
----------------------------------------------------------------------------------------------------
#tcpdump output, TCP header explained
#https://www.gatevidyalay.com/wp-content/uploads/2018/09/TCP-Header-Format.png

src > dst: Flags [tcpflags], seq data-seqno, ack ackno, win window, urg urgent, options [opts], length len
Src and dst are the source and destination IP addresses and ports. 
Tcpflags are some combination of 
S (SYN), 
F (FIN), 
P (PUSH), 
R (RST), 
U (URG), 
W (ECN CWR), 
E (ECN-Echo) 
`.' (ACK), 
`none' if no flags are set
data-seqno describes the portion of sequence space covered by the data in this packet
Ackno is sequence number of the next data expected the other direction on this connection
Window is the number of bytes of receive buffer space available the other direction on this connection.
Urg indicates there is `urgent' data in the packet. 
Opts are TCP options (e.g., mss 1024). 
Len is the length of payload data. 

$ sudo tcpdump -i any -vvvv dst 10.33.22.21
tcpdump: listening on any, link-type LINUX_SLL (Linux cooked v1), capture size 262144 bytes
12:38:21.039533 IP (tos 0x0, ttl 57, id 12400, offset 0, flags [none], proto TCP (6), length 44)
    vg-ubuntu-02.61748 > printer.org.local.http: Flags [S], cksum 0x7b48 (correct), seq 3600759408, win 1024, options [mss 1460], length 0

#map TCP header format to tcpdump output
#Ip, Src, dst, and flags are always present.
#The other fields depend on the contents of the packet's TCP protocol header

src > dst: Flags [tcpflags], seq data-seqno, ack ackno, win window, urg urgent, options [opts], length len
vg-ubuntu-02.61748 > printer.org.local.http: Flags [S], cksum 0x7b48 (correct), seq 3600759408, win 1024, options [mss 1460], length 0

tcpdump: listening on any, link-type LINUX_SLL (Linux cooked v1), capture size 262144 bytes
13:01:16.515391 IP (tos 0x0, ttl 57, id 25028, offset 0, flags [none], proto TCP (6), length 44)
    vg-ubuntu-02.54156 > printer.org.local.http: Flags [S], cksum 0x169c (correct), seq 3170031217, win 1024, options [mss 1460], length 0
13:01:16.517613 IP (tos 0x0, ttl 64, id 6938, offset 0, flags [none], proto TCP (6), length 44)
    printer.org.local.http > vg-ubuntu-02.54156: Flags [S.], cksum 0xed34 (correct), seq 659883521, ack 3170031218, win 65535, options [mss 1460], length 0
13:01:16.517671 IP (tos 0x0, ttl 64, id 0, offset 0, flags [DF], proto TCP (6), length 40)
    vg-ubuntu-02.54156 > printer.org.local.http: Flags [R], cksum 0x3255 (correct), seq 3170031218, win 0, length 0


The first line(timestamp 13:01:16.515391) says that 
TCP port 54156  on vg-ubuntu-02 sent a packet to port http on printer.org.local
The S indicates that the SYN flag was set
The packet sequence number was 3170031217 and it contained no data
There was no piggy-backed ACK #Piggybacking is a method of attaching acknowledgment to the outgoing data packet
the available receive window was 1024 bytes
there was a max-segment-size(mss) option requesting an MSS of 1460 bytes 
The packet contained no data so there is no data sequence number or length #length 0

The second line(timestamp 13:01:16.517613) says that
#Piggybacking is a method of attaching acknowledgment to the outgoing data packet
Http port on printer.org.local replies port 54156 on vg-ubuntu-02 with a similar packet except it includes a piggy-backed ACK for vg-ubuntu-02's SYN
The packet contained no data so there is no data sequence number or length #length 0

tcpdump: listening on any, link-type LINUX_SLL (Linux cooked v1), capture size 262144 bytes
IP rtsg.1023 > csam.login: Flags [.], ack 1, win 4096

Rtsg ACKs csam's SYN. The `.' means the ACK flag was set.
The packet contained no data so there is no data sequence number or length #length 0

tcpdump: listening on any, link-type LINUX_SLL (Linux cooked v1), capture size 262144 bytes
IP rtsg.1023 > csam.login: Flags [P.], seq 2:21, ack 1, win 4096, length 19
IP csam.login > rtsg.1023: Flags [P.], seq 1:2, ack 21, win 4077, length 1

 rtsg sends on port 1023 csam 19 bytes of data (bytes 2 through 20 in the rtsg → csam side of the conversation)
 The PUSH flag is set in the packet. #Flags [P.]
 csam says it's received data sent by rtsg up to but not including byte 21 #ack 21
 #ack 1, win 4096 - ack 21, win 4077(+19 4096)
 Most of this data is apparently sitting in the socket buffer since csam's receive window has gotten 19 bytes smaller
----------------------------------------------------------------------------------------------------