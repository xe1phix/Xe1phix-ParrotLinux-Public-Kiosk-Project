#!/bin/sh


Display Sockets Using Port 22
netstat -anp --tcp -4 | grep :22

Display Datagram Packets
netstat -anp | grep DGRAM

Display Sockets With Sequence Packets
netstat -anp | grep SEQPACKET

Displaying The Routing Table
netstat -nr

Displaying RAW network statistics
netstat --statistics --raw


Display Tcp Udp Packets, Listening, Numerical
netstat -tulanp


# Quick network status of machine
netstat -tn | awk 'NR>2 {print $6}' | sort | uniq -c | sort -rn


netstat -anp --tcp -4 | grep :22

netstat –ano | grep 22



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

