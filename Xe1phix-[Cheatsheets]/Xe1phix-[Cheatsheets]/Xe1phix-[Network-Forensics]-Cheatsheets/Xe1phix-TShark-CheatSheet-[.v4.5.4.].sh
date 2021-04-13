#!/bin/sh
##-========================================-##
##      [+] Xe1phix-TShark-Cheatsheet-[v*.*.*].sh
##-========================================-##


##-======================================-##
##  [+] 
##-======================================-##
tshark -f "tcp port 80" -i eth0


##-======================================-##
##  [+] 
##-======================================-##
tshark -i eth0 -T fields -e ip.src -e ip.dst -e frame.protocols -E header=y


##-=======================-##
##     [+] trace http requests 
##-=======================-##
tshark -i eth0 -z proto,colinfo,http.request.uri,http.request.uri -R http.request.uri


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
tshark -r $File.pcap -qz http_req,tree
 

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
tshark -i eth1 -f 'not tcp port 22'


##-========================-##
##     [+] HTTP GET request
##-========================-##
tshark -i eth0 -f 'tcp port 80 and tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x47455420' -w -


##-=================================-##
##     [+] Extract infomation form pcap
##-=================================-##
tshark -r $File.pcap -zio,phs


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


##-======================================================-##
##     [+] Generate Top Talkers by #TCP conv started per second:
##-======================================================-##
## --------------------------------------------------------------------------------------------------------------- ##
##     [?] #_connects src_IP dst_IP When_It_Happened_Secs Show Sample Output
## --------------------------------------------------------------------------------------------------------------- ##
tshark -qr $File -z conv,tcp | awk '{printf("%s:%s:%s\n",$1,$3,$10)}' | awk -F: '{printf("%s %s %s\n",$1,$3,substr($5,1,length($5)-10))}' | sort | uniq -c | sort -nr












