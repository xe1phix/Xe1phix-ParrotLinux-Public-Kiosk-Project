#!/bin/sh



## ------------------------------------------------------------------------------------------- ##
    netstat -tulanp                 ## Display TCP & UDP Packets, Listening
## ------------------------------------------------------------------------------------------- ##
    netstat -nr                     ## Displaying The Routing Table
## ------------------------------------------------------------------------------------------- ##


## ------------------------------------------------------------------------------------------- ##
    netstat -anp --tcp -4 | grep :22        ## Display Sockets Using Port 22
## ------------------------------------------------------------------------------------------- ##
    netstat -anp | grep DGRAM               ## Display Datagram Packets
## ------------------------------------------------------------------------------------------- ##
    netstat -anp | grep SEQPACKET           ## Display Sockets With Sequence Packets
## ------------------------------------------------------------------------------------------- ##

## ------------------------------------------------------------------------------------------- ##
    netstat --statistics --raw                  ## Displaying RAW network statistics
## ------------------------------------------------------------------------------------------- ##




##-===============================================================-##
##   [+] Show tcp connections sorted by Host / Most connections
##-===============================================================-##
netstat -ntu|awk '{print $5}'|cut -d: -f1 -s|sort|uniq -c|sort -nk1 -r


##-==============================================================-##
##   [+] Summarize the number of open TCP connections by state
##-==============================================================-##
netstat -nt | awk '{print $6}' | sort | uniq -c | sort -n -k 1 -r


##-====================================================-##
##   [+] Monitor open connections for httpd 
##       including listen, count and sort it per IP
##-====================================================-##
watch "netstat -plan|grep :80|awk {'print \$5'} | cut -d: -f 1 | sort | uniq -c | sort -nk 1"


##-=====================================================================================-##
##   [+] List all active access_logs for currently running Apache or Lighttpd process
##-=====================================================================================-##
lsof -p $(netstat -ltpn|awk '$4 ~ /:80$/ {print substr($7,1,index($7,"/")-1)}| awk '$9 ~ /access.log$/ {print $9| "sort -u"}'


##-=======================================================================-##
##   [+] List top 20 IP from which TCP connection is in SYN_RECV state
##-=======================================================================-##
netstat -pant 2> /dev/null | grep SYN_ | awk '{print $5;}' | cut -d: -f1 | sort | uniq -c | sort -n | tail -20


##-=============================================================================-##
##   [+] obtain a list of geographic localization for established connections
##-=============================================================================-##
for i in $(netstat --inet -n|grep ESTA|awk '{print $5}'|cut -d: -f1);do geoiplookup $i;done






netstat -nao | find ":[port]"

netstat -nao | find ":[port]" | find "[ClientIPaddr]"



netstat -s | awk '/:/ { p = $1 }; (p ~ /^tcp/) { print }'


netstat -s | awk '/:/ { p = $1 }; (p ~ /^Tcp/) { print }'




netstat -anp --tcp -4 | awk '/:22/ && /LISTEN/ { print $7 }' | cut -f1 -d/


netstat -anp --tcp -4 | awk '/:22/ && /LISTEN/ { print $7 }' | cut -f1 -d/


netstat -s | awk '/:/ { p = $1 }; (p ~ /^Tcp/) { print }'


netstat -s | awk '/:/ { p = $1 }; (p ~ /^tcp/) { print }'


kill `netstat -anp --tcp -4 | awk '/:22/ && /LISTEN/ { print $7 }' | cut -f1 -d/`

kill -9 $(ps x | grep "openvpn" | head -1 | awk {'printf $1'})




netstat -s | grep "Total Packets Received" | awk '{print}' >> $TEMP_DIR/TotalPacketsRecieved.txt && cat -vET $TEMP_DIR/VmStatPart.txt
netstat -s | grep "Incoming Packets Discarded" | awk '{print}' >> $TEMP_DIR/DiscardedIncomingPackets.txt && cat -vET $TEMP_DIR/DiscardedIncomingPackets.txt
netstat -s | grep "ICMP Messages Received" | awk '{print}' >> $TEMP_DIR/ICMPMessagesReceived.txt && cat -vET $TEMP_DIR/ICMPMessagesReceived.txt
netstat -s | grep "ICMP Messages Send" | awk '{print}' >> $TEMP_DIR/ICMPMessagesSent.txt && cat -vET $TEMP_DIR/ICMPMessagesSent.txt.txt
netstat -s | grep "Active Connections Openings" | awk '{print}' >> $TEMP_DIR/ActiveOpenConnections.txt && cat -vET $TEMP_DIR/ActiveOpenConnections.txt
netstat -s | grep "Passive Connections Openings" | awk '{print}' >> $TEMP_DIR/PassiveConnectionsOpenings.txt && cat -vET $TEMP_DIR/PassiveConnectionsOpenings.txt.txt
netstat -s | grep "Connections Estabished" | awk '{print}' >> $TEMP_DIR/ConnectionsEstabished.txt && cat -vET $TEMP_DIR/ConnectionsEstabished.txt.txt
netstat -s | grep "Bad segments Received." | awk '{print}' >> $TEMP_DIR/BadSegmentsReceived.txt && cat -vET $TEMP_DIR/BadSegmentsReceived.txt



Watch port 22 and show "ESTABLISHED" connections who arent localhost

sudo watch -n10 "netstat -ntu | grep :22| grep ESTAB | awk '{print \$5}' | cut -d: -f1 | grep -v 127.0.0.1 | sort"



Show number of connections to port 443 (webserver)

netstat -ntu | grep :443 | grep -v LISTEN | awk '{print $5}' | cut -d: -f1 | grep -v 127.0.0.1 | wc -l






##-=========================================================-##
##    [+] pull out just the PID of the master SSH daemon:
##-=========================================================-##
netstat -anp --tcp -4 | awk '/:22/ && /LISTEN/ { print $7 }' | cut -f1 -d/


##-==========================================================================-##
##    [+] Killing that process just requires appropriate use of backticks:
##-==========================================================================-##
kill `netstat -anp --tcp -4 | awk '/:22/ && /LISTEN/ { print $7 }' | cut -f1 -d/`


##-============================================-##
##    [+] Monitor open connections for httpd
##-===========================================-##
##    [?] including listen, count and sort it per IP

watch "netstat -plan|grep :80|awk {'print \$5'} | cut -d: -f 1 | sort | uniq -c | sort -nk 1"


