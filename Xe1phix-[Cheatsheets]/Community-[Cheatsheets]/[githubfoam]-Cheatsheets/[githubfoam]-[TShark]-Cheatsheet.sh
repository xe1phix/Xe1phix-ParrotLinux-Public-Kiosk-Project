============================================================================
#Wireshark installation directory: windows
C:\Program Files (x86)\Wireshark>tshark.exe
============================================================================
tshark -D #list of available interfaces
============================================================================
capture
============================================================================
tshark -i 2 #start capturing traffic on interface n°2
tshark -i 2 -a duration:10 #capture for 10 seconds, then stop
tshark -i 2 -w output_file.pcap #save a caputre to a file
tshark -i 2 -f "port bootpc" -w DHCP_Only.pcap -f #allows to configure a capture filter

#On a fabric interface, all packets coming from or going to a Virtual Machine (VM) will be encapsulated in MPLS over UDP or GRE header
#The -d udp.port flag instructs wireshark to interpret packets with the UDP port "51234" and the decode as MPLS label
#the encapsulated content (ICMPv6) can be recognized.
tshark -ni eth1 -Y "ip.addr==172.222.19.198 and ip.addr==172.222.19.199 and icmpv6" -d udp.port==51234,mpls

#extract data from any HTTP requests 
#-e options identify which fields to extract
tshark -i wlan0 -Y http.request -T fields -e http.host -e http.user_agent 

#extracts both the DNS query and the response address
tshark -i wlan0 -f "src port 53" -n -T fields -e dns.qry.name -e dns.resp.addr 
tshark -i wlan0 -f "src port 53" -n -T fields -e frame.time -e ip.src -e ip.dst -e dns.qry.name -e dns.resp.addr

#TCP stream of the HTTP Post
tshark -i wlan0 -Y 'http.request.method == POST and tcp contains "password"' | grep password
============================================================================
analysis
============================================================================
tshark -nr input.cap -R "dns" -V #print the DNS packets


#sort and count the occurrences of the http.user_agent
tshark -r example.pcap -Y http.request -T fields -e http.host -e http.user_agent | sort | uniq -c | sort -n

#HTTP filters
tshark -r example.pcap -Y http.request -T fields -e http.host -e ip.dst -e http.request.full_uri
============================================================================
#read file HTTP_Traffic and use filter http.request.methog==GET to create a filtered file HTTP_Get.pcap
tshark -2 -R "http.request.method==GET" -r HTTP_Traffic.pcap -w HTTP_Get.pcap 
tshark -r HTTP_Traffic.pcap -qz io,phs -z #read statistics from a file - this is for protocol hierarchy
============================================================================
tshark -r nmap_sn.pcap #read pcap file
tshark -n -r nmap_sn.pcap #Read a pcap, don't resolve names (layers 3 or 4)
tshark -nr nmap_sn.pcap 
============================================================================
#SSL  Client  Hello  requests
tshark -n -r [capture file] -Y ‘ssl.handshake.type==1’ -T fields -e ip.src -e ip.dst -e \ 
ssl.handshake.extensions_server_name 

#modern SSL libraries use Server Name Indication (SNI) as part of the SSL Client Hello to indicate to the server which site they are trying to connect to
#The SNI option is sent in the clear to allow for name virtual hosting with SSL
tshark -r file.pcap -Y 'ssl.handshake.type==1' -T fields -e ip.dst -e tcp.srcport -e ssl.handshake.extensions_server_name  | sed "s/\t/:/" > /tmp/ssi

#extract the host names advertised by the certificate that the server returns
#filter for certificate messages (type 11) and extract the source ip and the destination port
tshark -r file.pcap -Y 'ssl.handshake.type==11' -T fields -e ip.src -e tcp.dstport -e x509sat.uTF8String -e x509ce.dNSName | sed  "s/\t/:/" > /tmp/in

>tshark  -r  tor.pcapng  | findstr "Client Hello"

tshark -n -r [capture file] -Y ssl.handshake.type==11 -T fields -e x509ce.dNSName | tr -s \ 
‘,‘ ‘\n’ | sort | uniq -c | sort -rn | head -30

tshark -n -r [capture file] -Y ‘x509ce.uniformResourceIdentifier’ -T fields -e \ 
x509ce.uniformResourceIdentifier | tr -s ‘,‘ ‘\n’ | sort -u

tshark -n -r [capture file] -Y ssl.handshake.type==11 -T fields -e x509sat.IA5String -e 
x509sat.uTF8String -e x509sat.PrintableString -e x509sat.TeletexString -e 
x509sat.BMPString -e x509sat.UniversalString | tr -s ‘,’ ‘\n’ | sort -u

#extract URI,relevant threat database
tshark -r tor.pcapng -Y ssl.handshake.type==11 -T fields -e x509ce.uniformResourceIdentifier
#Extract Domain Name,relevant threat database
tshark -r tor.pcapng -Y ssl.handshake.type==11 -T fields -e x509ce.dNSName

#Cipher Suites list of trusted software and detect Cipher Suites list usage
tshark -r tor.pcapng -Y ssl.handshake.ciphersuites -Vx

#build a signature sha1 database for each Cipher Suite
tshark  -r  [capture  file]  -Y  ssl.handshake.type==1  -T  fields  \  -e  ssl.handshake.ciphersuite  | 
sort  -u  |  xargs  -I  {}  sh  -c  ‘echo  -n  {}”  “  &&  echo  -n  {}  |  \  sha1sum’  |  awk  ‘{printf  $2” 
“$1”\n”}’ 
============================================================================