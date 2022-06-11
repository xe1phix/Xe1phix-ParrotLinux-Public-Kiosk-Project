#!/bin/sh
##-========================================-##
##      [+] Xe1phix-TShark-Cheatsheet-[v*.*.*].sh
##-========================================-##



tshark -Y $Filter -r $InFile -w $OutFile
tshark -2 -R $Filter -r $InFile -w $OutFile



##-=============================-##
##   [+] Basic protocols dump:
##-=============================-##

## ------------------------------------------------------------------------------ ##
      tshark -i any -f 'port http' -Y http -l -N nNC      ## Dump HTTP Traffic
## ------------------------------------------------------------------------------ ##
      tshark -i any -f 'port smtp' -Y smtp -l -N nNC      ## Dump SMTP Traffic
## ------------------------------------------------------------------------------ ##
      tshark -i any -f 'port imap' -Y imap -l -N nNC      ## Dump IMAP Traffic
## ------------------------------------------------------------------------------ ##



##-==============================-##
##   [+] Filtering TCP packets
##-==============================-##
tshark -f "tcp"


##-==============================-##
##   [+] Filtering UDP packets
##-==============================-##
tshark -f "udp"


##-======================================-##
##  [+]
##-======================================-##
tshark -f "tcp port 80" -i eth0



##-==================================================-##
##   [+] Show all ICMPv6 traffic from a pcap file:
##-==================================================-##
tshark -Y "icmpv6" -r $File


##-====================================-##
##   [+] Only show multicast traffic:
##-====================================-##
tshark -r $File -Y "eth.dst[0] & 1"



##-======================================-##
##  [+]
##-======================================-##
tshark -i eth0 -T fields -e ip.src -e ip.dst -e frame.protocols -E header=y


##-=======================-##
##     [+] trace http requests
##-=======================-##
tshark -i eth0 -z proto,colinfo,http.request.uri,http.request.uri -R http.request.uri




TCP SYN packets
match all packets that contain a "tcp.flags" field with the 0x02 bit,
tcp.flags & 0x02



ip.src == $1
ip.dst == $2
tcp.srcport == $3
tcp.dstport == $4
ip.src == $2
ip.dst == $1
tcp.srcport == $4
tcp.dstport == $3



eth.dst eq ff:ff:ff:ff:ff:ff
ip.dst eq www.mit.edu
ip.src == 192.168.1.1
ip.addr == 129.111.0.0/16
ipx.src.net == 0xc0a82c00



ipv6.addr == ::1						## IPv6 address



tcp.port == 80 and ip.src == 192.168.2.1




ip.src==10.0.0.5 and tcp.flags.fin


ip.src==10.0.0.5 or ip.src==192.1.1.1




http.request.method == "POST"


hexadecimal to look for "HEAD":

http.request.method == "\x48EAD"
http.request.method in {"HEAD" "GET"}

octal to look for "HEAD":

http.request.method == "\110EAD"


The slice operator
take a slice of a field if the field is a text string or a byte array.


filter on the vendor portion of an ethernet address (the first three bytes)
eth.src[0:3] == 00:00:83
http.content_type[0:4] == "text"



use the slice operator on a protocol name


check the last four bytes of a frame:

frame[-4:4] == 0.1.2.3
frame[-4:] == 0.1.2.3



The "frame" protocol can be useful,
encompassing all the data captured

frame[100-199] contains "wireshark"




frame[4] == 0xff




The membership operator
A field may be checked for matches against a set of values



find traffic on common HTTP/HTTPS ports
tcp.port in {80 443 8080}


more verbose:
tcp.port == 80 or tcp.port == 443 or tcp.port == 8080


matches HTTP packets where the HOST header contains
http.request.uri == "https://www.wireshark.org/"


matches HTTP packets where the HOST header contains acme.org, acme.com, or acme.net.
http.host matches "acme\\.(org|com|net)"




find HTTP requests using the HEAD or GET methods:

http.request.method in {"HEAD" "GET"}






The set of values can also contain ranges:

tcp.port in {443 4430..4434}
ip.addr in {10.0.0.5 .. 10.0.0.9 192.168.1.1..192.168.1.9}
frame.time_delta in {10 .. 10.5}


http.request.method == "GET"


##-============================================-##
##     [+]
##-============================================-##
tshark -r $File.pcap -Y "http.request" -Tfields -e "ip.src" -e "http.user_agent" | uniq


##-============================================-##
##     [+]
##-============================================-##
tshark -r $File.pcap -Y "dns" -T fields -e "ip.src" -e "dns.flags.response" -e "dns.qry.name"


##-===============================================================-##
##     [+] DNS servers were used by the clients for domain name resolutions
##-===============================================================-##
tshark -r $File.pcap -Y "dns && dns.flags.response==0" -Tfields -e ip.dst


##-====================================-##
##     [+] Monitor DNS queries and replies:
##-====================================-##
tshark -Y "dns.flags.response == 1" -Tfields -e frame.time_delta -e dns.qry.name -e dns.a -Eseparator=


##-========================================-##
##     [+] Monitor HTTP requests and responses:
##-========================================-##
tshark -Y "http.request or http.response" -Tfields -e ip.dst -e http.request.full_uri -e http.request.method -e http.response.code -e http.response.phrase -Eseparator=/s


##-====================================-##
##     [+]
##-====================================-##
tshark -r $File.pcap -Y http.request  -T fields -e ip.src -e ip.dst -e http.host -e http.request.uri | awk '{print $1," -> ",$2, "\t: ","http://"$3$4}'


##-=====================================-##
##     [+] Monitor x509 (SSL/TLS) certificates:
##-=====================================-##
tshark -Y "ssl.handshake.certificate" -Tfields -e ip.src -e x509sat.uTF8String -e x509sat.printableString -e x509sat.universalString -e x509sat.IA5String -e x509sat.teletexString -Eseparator=/s -Equote=d


##-====================================-##
##     [+]
##-====================================-##
tshark -r $File.pcap -Y http.request  -T fields -e ip.src -e ip.dst -e http.host -e http.request.uri | awk '{print $1," -> ",$2, "\t: ","http://"$3$4}' | grep -v -e '\/image' -e '.css' -e '.ico' -e google -e 'honeynet.org'



##-====================================-##
##     [+]
##-====================================-##
tshark -r $File.pcap -Y "data-text-lines contains \"<script\"" -T fields -e frame.number -e ip.src -e ip.dst


##-====================================-##
##     [+]
##-====================================-##
tshark -r $File.pcap -Y http.request  -T fields -e ip.src -e ip.dst -e http.host -e http.request.uri | awk '{print $1," -> ",$2, "\t: ","http://"$3$4}' | grep -v -e '\/image' -e '.css' -e '.ico'  | grep 10.0.3.15 | sed -e 's/\?[^cse].*/\?\.\.\./g'


##-=================================-##
##     [+] HTTP traffic from a PCAP file
##-=================================-##
tshark -Y ‘http’ -r $File.pcap


##-===========================================-##
##     [+] Show the IP packets sent from IP address
##           192.168.252.128 to IP address 52.32.74.91
##-===========================================-##
tshark -r $File.pcap -Y "ip.src==192.168.252.128 && ip.dst==52.32.74.91"


##-============================================-##
##     [+] Only print packets containing GET requests
##-============================================-##
tshark -r $File.pcap -Y "http.request.method==GET"


##-=======================================================-##
##     [+] Print only source IP and URL for all GET request packets
##-=======================================================-##
tshark -r $File.pcap -Y "http.request.method==GET" -Tfields -e frame.time -e ip.src -e http.request.full_uri


##-======================================================-##
##     [+] How many HTTP packets contain the "password" string?
##-======================================================-##
tshark -r $File.pcap -Y "http contains password"


##-======================================================-##
##     [+] Which IP address was sent GET requests for $Domain
##-======================================================-##
tshark -r $File.pcap -Y "http.request.method==GET && http.host==$Domain" -Tfields -e ip.dst


##-======================================================-##
##     [+] What is the session ID being used by 192.168.252.128
##           for Amazon India store (amazon.in)?
##-======================================================-##
tshark -r $File.pcap -Y "ip contains $Domain && ip.src==192.168.252.128" -Tfields -e ip.src -e http.cookie


##-=========================================================-##
##     [+] What type of OS the machine on IP address 192.168.252.128
##           is using (i.e. Windows/Linux/MacOS/Solaris/Unix/BSD)?
##-=========================================================-##
tshark -r $File.pcap -Y "ip.src==192.168.252.128 && http" -Tfields -e http.user_agent


##-===========================-##
##     [+] Only show SSL traffic
##-===========================-##
tshark -Y ‘ssl’ -r $File.pcap


##-============================================-##
##     [+] Only print the source IP and destination IP
##          for all SSL handshake packets
##-============================================-##
tshark -r $File.pcap -Y "ssl.handshake" -Tfields -e ip.src -e ip.dst


##-==================================================-##
##     [+] List issuer name for all SSL certificates exchanged
##-==================================================-##
tshark -r $File.pcap -Y "ssl.handshake.certificate" -Tfields -e x509sat.printableString


##-======================================================-##
##     [+] Print the IP addresses of all servers accessed over SSL
##-======================================================-##
tshark -r $File.pcap -Y "ssl && ssl.handshake.type==1" -Tfields -e ip.dst


##-===============================================================-##
##     [+] IP addresses associated with Ask Ubuntu servers (askubuntu.com)
##-===============================================================-##
tshark -r $File.pcap -Y "ip contains askubuntu"


##-================================================-##
##     [+] IP address of the user who interacted
##          with with Ask Ubuntu servers (askubuntu.com)
##-================================================-##
tshark -r $File.pcap -Y "ip.dst==151.101.1.69 || ip.dst==151.101.193.69 || ip.dst==151.101.129.69 || ip.dst==151.101.65.69" -Tfields -e ip.src


##-==============================================================-##
##     [+] DNS servers were used by the clients for domain name resolutions
##-==============================================================-##
tshark -r $File.pcap -Y "dns && dns.flags.response==0" -Tfields -e ip.dst


##-============================================-##
##     [+] Name of the antivirus solution?
##           IP addresses of the machines running this
##-============================================-##
tshark -r $File.pcap -Y "ip contains avast" -Tfields -e ip.src



##-=====================================-##
##     [+] capture mysql queries sent to server
##-=====================================-##
tshark -i any -T fields -R mysql.query -e mysql.query


##-=======================================-##
##     [+]
##-=======================================-##
tshark -i eth0 -f 'not tcp port 22'



icmp[icmptype] != icmp-echo and icmp[icmptype] != icmp-echoreply

tshark -T fields -e http.host -r $File.pcap | sort | uniq -c | sort -nr

tshark -T fields -e http.host -e http.request.uri -Y 'http.request.method == \"GET\"' -r $File.pcap | sort | uniq
tshark -Y 'http contains \"User-Agent:\"' -T fields -e http.user_agent -r $File.pcap | sort | uniq -c | sort -nr

tshark -r $File.pcap -qz io,stat,10,tcp,udp,icmp,ip,smtp,smb,arp,browser

tshark -r $File.pcap -qz io,phs


TCP Conversation
tshark -r $File.pcap -qz conv,tcp



IP Conversation
tshark -r $File.pcap -qz conv,ip

UDP Conversation
tshark -r $File.pcap -qz conv,udp


(proto,src_addr,src_port,dst_addr,dst_port)



How Many | Port Used

tcpdump -nn -r $File.pcap -p 'tcp or udp' | awk -F' ' '{print $5}' | awk -F'.' '{print $5}' | sed 's/:/ /g'  | sort | uniq -c | sort -n


ALL IP List
tcpdump -nn -r $File.pcap -p 'tcp or udp'


Request IP List
tcpdump -nn -r $File.pcap -p 'tcp or udp' | awk -F' ' '{print $3}' | awk -F'.' '{print $1\".\"$2\".\"$3\".\"$4}' | sort | uniq | sort -n



"frame.protocols": "eth:ethertype:ip:tcp:bittorrent"






ngrep -q -I $File.pcap
mergecap $File.pcap -w $File.pcap -F pcap
ngrep -q -I $File.pcap | grep -i $File.pcap | sort | uniq -c



##-=======================================-##
##     [+]
##-=======================================-##
tshark -i eth0 -f 'tcp dport != { 80, 443 }'
tshark -i eth0 -f 'tnot cp dport 80, 443 '
tcp.port in {80 443 8080}

tcp.port == 80 || tcp.port == 443 || tcp.port == 8080




Print all connections of a source IP address in pcap

tshark -r $File.pcap -R "ip.src==192.168.1.2" -T fields -e "ip.dst" |sort |uniq -c




Capture all tcp and udp packets in LAN,
except packets coming to localhost (192.168.1.2)

tcpdump -n -i eth0 -w $File.pcap -v tcp or udp and 'not host 192.168.1.2'



##-========================-##
##     [+] HTTP GET request
##-========================-##
tshark -i eth0 -f 'tcp port 80 and tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x47455420' -w -


##-=================================-##
##     [+] Extract infomation form pcap
##-=================================-##
tshark -r $File.pcap -zio,phs

##-===========================================-##
##     [+] IOstatistics.txt contains Protocol Hierarchy
##-===========================================-##
tshark -nr $File -q -z io,stat,30 > IOstatistics.txt
tshark -nr $File -q -z io,phs >> IOstatistics.txt

##-================================================-##
##     [+] IPstatistics contains overall stats to/from endpoints
##-================================================-##
tshark -nr $File -q -z endpoints,ip > IPstatistics.txt
tshark -nr $File -q -z conv,ip >> IPstatistics.txt

##-===========================================-##
##     [+] Statistical data about HTTP conversations
##-===========================================-##
tshark -nr $File -q -z http,tree > HTTPInfo.txt
tshark -nr $File -q -z http_req,tree >> HTTPInfo.txt
tshark -nr $File -q -z http_srv,tree >> http_info.txt

##-===========================-##
##     [+] check for hostname flag
##-===========================-##
## ------------------------------------------------------------ ##
##     [?] Performing hostname resolution
## ------------------------------------------------------------- ##
tshark -nr $File -N Nnt -z hosts > $File.txt
cat $File.txt | grep '# TShark' -A 100000000 > hostnamesResolved.txt


##-=======================-##
##     [+] HTTP pcap carving
##-=======================-##
## -------------------------------------------------------------------------------------------------------- ##
##    [?] http.pcap contains all conversations containing port 80,8080,8000
## -------------------------------------------------------------------------------------------------------- ##
tshark -nr $File -n -Y '(tcp.port==80 || tcp.port==8080 || tcp.port==8000)' -w $File.pcap



##-===================================================-##
##     [+] Print all connections of a source IP address in pcap
##-===================================================-##
tshark -r $File.pcap -R "ip.src==192.168.1.2" -T fields -e "ip.dst" |sort |uniq -c


##-===================-##
##     [+] Decrypt SSL
##-===================-##
## --------------------------------------------------------------------------------------------------------------- ##
##     [?] on a web server (with access to the ssl key), decrypt SSL off the wire
## --------------------------------------------------------------------------------------------------------------- ##
openssl pkcs8 -in /etc/pki/tls/web.key -out /root/wc.key -nocrypt && tshark -o "ssl.desegment_ssl_records:TRUE" -o "ssl.desegment_ssl_application_data:TRUE" -o "ssl.keys_list:,443,http,/root/wc.key" -o "ssl.debug_file:rsa.log" -R "(tcp.port eq 443)"




##-==========================-##
##     [+] Decrypt 802.11 traffic:
##-==========================-##
tshark -r $File.pcap -o wlan.enable_decryption:TRUE -o wlan.wep_key1:wpa-psk:55f8e415485dd9a272060ca558d3db184be51b3cb6d4a048b064c7aaca335df2


##-======================================================-##
##     [+] Generate Top Talkers by #TCP conv started per second:
##-======================================================-##
## --------------------------------------------------------------------------------------------------------------- ##
##     [?] #_connects src_IP dst_IP When_It_Happened_Secs Show Sample Output
## --------------------------------------------------------------------------------------------------------------- ##
tshark -qr $File -z conv,tcp | awk '{printf("%s:%s:%s\n",$1,$3,$10)}' | awk -F: '{printf("%s %s %s\n",$1,$3,substr($5,1,length($5)-10))}' | sort | uniq -c | sort -nr


tshark -a filesize:10000 -b files:200 -i eth0 -w $File.pcap -f "port 80 or port 53 or port 443"



tshark -q -E separator=';' -T fields -e frame.time_epoch -e eth.src -e frame.len -b filesize:10000 -b files:100 -w $File.pcap


tshark -r $File.pcap -n -T fields -e ip.src -e tcp.srcport -e ip.dst -e tcp.dstport


##-================================================-##
##     [+] follow a tcp communication between two nodes
##-================================================-##
tshark -r $File.pcap -z "follow,tcp,hex,192.168.3.200:46168,192.168.3.100:5150" > /tmp/o46168_f5150.follow






dtruss -a -f tshark


tshark -f 'host '${i}'' -R "http.request" -T fields -e http.host -w $File.log -S

tshark -n -r $File.log -R "http.request" -T fields -e http.host > $File.txt


tshark -Nn -r $File.cap -o column.format:'"Unres","%us","Res","%rs"'


tshark -n -r $File.cap -o column.format:'"Unres","%us","Res","%rs"'

tshark -nn -r $File.pcap -z conv,tcp > tcp_convs
tshark -nn -r $File.pcap -z conv,udp > udp_convs
tshark -nn -r $File.pcap -z conv,ip > ip_convs
tshark -nn -q -r $File.pcap -Y http.request.full_uri -T fields -e http.request.full_uri -e http.referer | grep 'moonstoneafgelekte.onewide.co.uk' >>


tshark -i eth0 -f "host bucket-name.s3.amazonaws.com"  -w $File.pcap



tshark -n -r $File.pcap -Y dns.qry.name -T fields -e dns.qry.name -q | grep '-' | head -1 > mta-20150711-id
tshark -n -r $File.pcap -Y dns.qry.name -T fields -e dns.qry.name | sort -u > mta-20150711-dns-domains
tshark -n -r $File.pcap -z endpoints,ip -q | head -2 >> mta-20150711-id
tshark -n -r $File.pcap -z endpoints,ether -q >> mta-20150711-id
tshark -n -r $File.pcap -c1 -V | grep -i src >> mta-20150711-id
tshark -n -r $File.pcap -Y http -T fields -e http.request.full_uri -e http.referer | sort -u > mta-20150711-http



tshark -i vboxnet0


tshark -i eth0 multicast


##-==============================================================-##
##     [+] Get data out of the capture and remove all newlines and commas:

tshark -r $File.pcap -T fields -e data | tr -d '\n' | tr -d ',' > $File


##-================================================-##
##     [+]
##-================================================-##
tshark -i eth0 -p -n -Q -l -Y dhcpv6.msgtype==7 && dhcpv6.iaprefix.pref_addr -T fields -e ipv6.dst -e dhcpv6.iaprefix.pref_addr-e dhcpv6.iaprefix.pref_len -- ip6 and udp and dst port 546




##-================================================-##
##     [+]
##-================================================-##

END=$(tshark -r $File.pcap -T fields -e tcp.stream | sort -n | tail -1);
for ((i=0;i<=END;i++));
do
echo $i; tshark -r $File.pcap -qz follow,tcp,ascii,$i
done




##-#########################################-##
##     [+] TShark - Graphs + Statistrics + Lists
##-#########################################-##



##-====================================-##
##     [+]
##-====================================-##
tshark -r $File.pcap -qz http_req,tree


##-====================================-##
##     [+] List conversations by percentage:
##-====================================-##
 tshark -r $File -n -qz ip_hosts,tree


##-=============================-##
##     [+] List protocol breakdown:
##-=============================-##
tshark -r $File -n -qz ptype,tree


##-============================-##
##     [+] Show stats by protocol:
##-============================-##
tshark -q -r $File -z io,phs


##-=======================================================-##
##     [+] Show 5 second interval stats of tcp, icmp and udp traffic:
##-=======================================================-##
tshark -q -n -r $File -z io,stat,5,tcp,icmp,udp


##-===================================-##
##     [+] Show TCP retransmission count:
##-===================================-##
tshark -nr $File.pcap -qz 'io,stat,0,COUNT(tcp.analysis.retransmission)tcp.analysis.retransmission'




##-===================================================-##
##    [+] Extract Debugging Fields In  x509 Certificate Traffic:
##-===================================================-##
tshark -Y "ssl.handshake.certificate" -Tfields -e ip.src -e x509sat.uTF8String -e x509sat.printableString -e x509sat.universalString -e x509sat.IA5String -e x509sat.teletexString -Eseparator=/s -Equote=d


##-=========================-##
##     [+] Protocol hierarchy :
##-=========================-##
tshark -qr $File.pcap -z io,phs



##-=====================================-##
##     [+] Print DNS Query Names + CNames
##-=====================================-##
tshark -r $File.pcap -Tfields -e dns.qry.name -e dns.cname


##-============================================================-##
##     [+] PCAP Extraction, one query/response per line and unique one :
##-============================================================-##
tshark -r $File.pcap -Tfields -e dns.qry.name | awk '!a[$0]++' > $File.txt && tshark -r $File.pcap -Tfields -e dns.cname | awk '!a[$0]++' >> $File.txt





##-================================================-##
##     [+] SMB carving - Stats on CLI ran by smb or smb2
##-================================================-##
tshark -nr $File.pcap -q -z smb,srt > SMBstatistics.txt
tshark -nr $File.pcap -q -z smb2,srt >> SMBstatistics.txt



smb.pcap contains all conversations categorized by tshark dissectors as NBSS, SMB, or SMB2
tshark -nr $File -Y nbss -w $File.pcap


#DNS packet carving
dns.pcap contains all conversations categorized by tshark dissectors as DNS
tshark -nr $File -Y 'dns' -w $File.pcap


#DNS A record
##  DNS A query/responses have been outputted to dnsARecords.txt

tshark -nr $File -Y 'dns.qry.type == 1' -E header=y -T fields -e frame.number -e ip.src -e ip.dst -e dns.qry.name -e dns.a  > dnsARecords.txt


#AbuseIPDB variable check
echo "Performing IP Reputation lookups via AbuseIPDB. (Note: please ensure you have ran the AbuseIPDBInitial.sh script prior to use)"
			tshark -nr $File -T fields -e dns.a | tr ',' '\n' | sort | uniq > dstip.txt
				sed -i '1d' dstip.txt
			while read ABU
			do
				curl -s -G https://api.abuseipdb.com/api/v2/check   --data-urlencode "ipAddress=${ABU}"   -d maxAgeInDays=90   -d verbose   -H "Key: test"   -H "Accept: application/json" | jq '. | {IPaddress: .data.ipAddress, Domain: .data.domain, AbuseConfidenceScore: .data.abuseConfidenceScore, CountryCode: .data.countryCode, CountryName: .data.countryName}' >> output.txt
			done < dstip.txt
			sed '/}/a\'$'\n' output.txt > IPLookupResults.txt
			rm output.txt
			rm dstip.txt
		fi
fi




Capture TCP stream

    Step1 - capture network trafic):

tshark -i eth0 -f "port 9088" -w $File.pcap


    Step2 - list captured tcp streams):

 tshark -r $File.pcap -T fields -e tcp.stream | sort -u


    Step3 - dump the content of one particular tcp stream):

tshark -nr $File.pcap -q -d tcp.port==9088,http -z follow,http,ascii,_your_stream_number



Noice the "-d tcp.port==9088,http" option to force http decoding on this port
as in this case it is a socks5 proxy running on that port.





tshark -i eth0 -r $File.pcap -qz io,phs


tshark -r $File.pcap | grep 'NB.*20\>' | sed -e 's/<[^>]*>//g' | awk '{print $3,$4,$9}' | sort -u


tshark -r $File.pcap | grep 'NB.*1e\>' | sed -e 's/<[^>]*>//g' | awk '{print $3,$4,$9}' | sort -u


tshark -r $File.pcap arp | grep has | awk '{print $3," -> ",$9}' | tr -d '?'


tshark -r $File.pcap -Tfields -e "eth.src" | sort | uniq


tshark -r $File.pcap -R "browser.command==1" -Tfields -e "ip.src" -e "browser.server" | uniq


tshark -r $File.pcap -Tfields -e "eth.src" | sort |uniq


tshark -r $File.pcap -qz ip_hosts,tree


tshark -r $File.pcap -R "http.request" -Tfields -e "ip.src" -e "http.user_agent" | uniq


tshark -r $File.pcap -R "dns" -T fields -e "ip.src" -e "dns.flags.response" -e "dns.qry.name"


tshark -r $File.pcap -R http.request  -T fields -e ip.src -e ip.dst -e http.host -e http.request.uri | awk '{print $1," -> ",$2, "\t: ","http://"$3$4}'


tshark -r $File.pcap -R http.request  -T fields -e ip.src -e ip.dst -e http.host -e http.request.uri | awk '{print $1," -> ",$2, "\t: ","http://"$3$4}' | grep -v -e '\/image' -e '.css' -e '.ico' -e google -e 'honeynet.org'


tshark -r $File.pcap -qz http_req,tree


tshark -r $File.pcap -R "data-text-lines contains \"<script\"" -T fields -e frame.number -e ip.src -e ip.dst


tshark -r $File.pcap -R http.request  -T fields -e ip.src -e ip.dst -e http.host -e http.request.uri | awk '{print $1," -> ",$2, "\t: ","http://"$3$4}' | grep -v -e '\/image' -e '.css' -e '.ico'  | grep 10.0.3.15 | sed -e 's/\?[^cse].*/\?\.\.\./g'






##-=============================-##
##   [+] Basic protocols dump:
##-=============================-##

## ------------------------------------------------------------------------------ ##
      tshark -i any -f 'port http' -Y http -l -N nNC      ## Dump HTTP Traffic
## ------------------------------------------------------------------------------ ##
      tshark -i any -f 'port smtp' -Y smtp -l -N nNC      ## Dump SMTP Traffic
## ------------------------------------------------------------------------------ ##
      tshark -i any -f 'port imap' -Y imap -l -N nNC      ## Dump IMAP Traffic
## ------------------------------------------------------------------------------ ##

      ## Dump  Traffic
      ## Dump  Traffic
      ## Dump  Traffic
      ## Dump  Traffic

where options mean:

    -i: input interface
    -f: pcap filter
    -Y: one-pass wireshark filter
    -l: flush stdout for each line
    -N: resolve IP to DNS names concurrently


##-==================================================-##
##   [+] Show all ICMPv6 traffic from a pcap file.
##-==================================================-##
tshark -Y "icmpv6" -r $File


##-====================================-##
##   [+] Show only multicast traffic
##-====================================-##
tshark -r $File -Y "eth.dst[0] & 1"





Dump protocol details,
where -V means verbose output:

tshark -i any -f 'port http' -Y http -V

Capture packets to a file (equivalant to tcpdump):

dumpcap -i any -f 'port http' -w dump.cap

Analyze already captured packets, where -2 and -R mean two-pass wireshark filter that catches protocol elements spanning multiple packets:

tshark -r dump.cap -2 -R http -V

Extract a protocol flow No.10 as ASCII text:

tshark -r dump.cap -q -z follow,tcp,ascii,10

Extract specific procotol fields as comma-separated lines:

tshark -r dump.cap -2 -R http -T fields -E separator=, -e tcp.stream \
    -e http.request.method -e http.request.uri -e http.response.code -e http.response.phrase

Analyze traffic on non-standard port:

tshark -i any -f 'port 4000' -d tcp.port==4000,http -Y http



ether proto

atalk
    the filter checks both for the AppleTalk etype in an Ethernet frame and for a SNAP-format packet as it does for FDDI, Token Ring, and 802.11;
aarp
    the filter checks for the AppleTalk ARP etype in either an Ethernet frame or an 802.2 SNAP frame with an OUI of 0x000000;


IPv4 broadcast or multicast packets that were not sent via Ethernet broadcast or multicast:

    ether[0] & 1 = 0 and ip[16] >= 224



IPv4 traffic neither sourced from nor destined for local hosts
ip and not net localnet


all FTP traffic through Internet gateway `snup':

    gateway snup and (port ftp or ftp-data)


ICMP packets that are not echo requests/replies (i.e., not ping packets):

    icmp[icmptype] != icmp-echo and icmp[icmptype] != icmp-echoreply
    icmp6[icmp6type] != icmp6-echo and icmp6[icmp6type] != icmp6-echoreply


select the start and end packets (the SYN and FIN packets) of each TCP conversation
tcp[tcpflags] & (tcp-rst|tcp-ack) == (tcp-rst|tcp-ack)


##  Ethernet multicast packet
ether multicast
ether[0] & 1 != 0


IPv4 multicast packet.
ip multicast


IPv6 multicast packet.
ip6 multicast

ip broadcast
    True if the packet is an IPv4 broadcast packet.


proto ip6


IPv6 packet
ip6 protochain 6


src or dst port ftp-data


##  MITM
tshark -o 'ssl.desegment_ssl_records: TRUE' -o 'ssl.desegment_ssl_application_data: TRUE' -o 'ssl.keys_list: proxy,8080,http,/root/.mitmproxy/mitmproxy-ca.pem' -o 'ssl.debug_file: /root/wireshark-log' -i eth0   -w - 'tcp and host proxy and port 8080' | nc $1 $2

tshark -o "ssl.keylog_file: $KEYLOGFILE" -r "$dump.$ext" -Y "$DISPLAYFILTER" -T fields -e tcp.stream | sort -n | uniq
tshark -o "ssl.keylog_file: $KEYLOGFILE" -r $dump.$ext -T fields -e tcp.stream | sort -n | uniq



tshark -o "ssl.keylog_file: $KEYLOGFILE" -r "$dump.$ext" -T fields -e data -qz follow,tcp,raw,$i

tshark -o "ssl.keylog_file: $KEYLOGFILE" -r "$dump.$ext" -qz follow,tcp,ascii,$i

tshark -o "ssl.keylog_file: $KEYLOGFILE" -r "$dump.$ext" -T fields -e data -qz follow,ssl,raw,$i

tshark -o "ssl.keylog_file: $KEYLOGFILE" -r "$dump.$ext" -qz follow,ssl,ascii,$i


## call TSHARK on 1000 pkts
tshark -c 1000 -i any -T fields -e frame.protocols -e frame.len




