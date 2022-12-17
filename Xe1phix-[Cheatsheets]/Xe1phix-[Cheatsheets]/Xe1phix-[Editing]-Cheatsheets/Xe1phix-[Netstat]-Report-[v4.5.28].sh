
echo -e "\t<<+}================================================={+>>" >> $TEMP_DIR/NetstatIfaces.txt                         ## && cat -vET $TEMP_DIR/NetstatIfaces.txt
echo -e "\t\t >> Displaying The Routing Table:" >> $TEMP_DIR/NetstatIfaces.txt                                                    ## && cat -vET $TEMP_DIR/NetstatIfaces.txt
echo -e "\t<<+}================================================={+>>" >> $TEMP_DIR/NetstatIfaces.txt                         ## && cat -vET $TEMP_DIR/NetstatIfaces.txt
                    netstat -nr  >> $TEMP_DIR/NetstatIfaces.txt                                                                        ## && cat -vET $TEMP_DIR/NetstatIfaces.txt
echo "________________________________________________________________________" >>  >> $TEMP_DIR/NetstatIfaces.txt           ## && cat -vET $TEMP_DIR/NetstatIfaces.txt
                    echo >> $TEMP_DIR/NetstatIfaces.txt                                                                                     ## && cat -vET $TEMP_DIR/NetstatIfaces.txt




echo -e "\t<<+}================================================={+>>" >> netstat.txt && cat netstat.txt
echo -e "\t\t >> Display Process Information:" >> netstat.txt && cat netstat.txt
echo -e "\t<<+}================================================={+>>" >> netstat.txt && cat netstat.txt
netstat ‐anp ‐‐tcp ‐4 | grep :22  >> netstat.txt && cat netstat.txt
echo "________________________________________________________________________" >> netstat.txt && cat netstat.txt
                         echo >> netstat.txt && cat netstat.txt
echo -e "\t<<+}================================================={+>>" >> netstat.txt && cat netstat.txt
echo -e "\t\t >> Displaying RAW network statistics" >> netstat.txt && cat netstat.txt
echo -e "\t<<+}================================================={+>>" >> netstat.txt && cat netstat.txt
netstat --statistics --raw >> netstat.txt && cat netstat.txt
echo "________________________________________________________________________" >> netstat.txt && cat netstat.txt
                         echo >> netstat.txt && cat netstat.txt
echo -e "\t<<+}================================================={+>>" >> netstat.txt && cat netstat.txt
echo -e "\t\t >> :" >> netstat.txt && cat netstat.txt
echo -e "\t<<+}================================================={+>>" >> netstat.txt && cat netstat.txt
netstat --tcp --numeric >> netstat.txt && cat netstat.txt
echo "________________________________________________________________________" >> netstat.txt && cat netstat.txt
                         echo >> netstat.txt && cat netstat.txt
echo -e "\t<<+}================================================={+>>" >> netstat.txt && cat netstat.txt
echo -e "\t\t >> :" >> netstat.txt && cat netstat.txt
echo -e "\t<<+}================================================={+>>" >> netstat.txt && cat netstat.txt
netstat --tcp --listening --programs >> netstat.txt && cat netstat.txt
echo "________________________________________________________________________" >> netstat.txt && cat netstat.txt
                         echo >> netstat.txt && cat netstat.txt
echo -e "\t<<+}================================================={+>>" >> netstat.txt && cat netstat.txt
echo -e "\t\t >> Display Tcp Udp Packets, Listening, Numerical:" >> netstat.txt && cat netstat.txt
echo -e "\t<<+}================================================={+>>" >> netstat.txt && cat netstat.txt
netstat -tulanp >> netstat.txt && cat netstat.txt
echo "________________________________________________________________________" >> netstat.txt && cat netstat.txt
                         echo >> netstat.txt && cat netstat.txt
echo -e "\t<<+}================================================={+>>" >> netstat.txt && cat netstat.txt
echo -e "\t\t >> Display Connected Shit:" >> netstat.txt && cat netstat.txt
echo -e "\t<<+}================================================={+>>" >> netstat.txt && cat netstat.txt
netstat -nal | grep "CONNECTED" >> netstat.txt && cat netstat.txt
echo "________________________________________________________________________" >> netstat.txt && cat netstat.txt
                         echo >> netstat.txt && cat netstat.txt
echo -e "\t<<+}================================================={+>>" >> netstat.txt && cat netstat.txt
echo -e "\t\t >> Display Listening Shit:" >> netstat.txt && cat netstat.txt
echo -e "\t<<+}================================================={+>>" >> netstat.txt && cat netstat.txt
netstat -anp | grep LISTENING >> netstat.txt && cat netstat.txt
echo "________________________________________________________________________" >> netstat.txt && cat netstat.txt
                         echo >> netstat.txt && cat netstat.txt
echo -e "\t<<+}================================================={+>>" >> netstat.txt && cat netstat.txt
echo -e "\t\t >> Display Sockets With Sequence Packets:" >> netstat.txt && cat netstat.txt
echo -e "\t<<+}================================================={+>>" >> netstat.txt && cat netstat.txt
netstat -anp | grep SEQPACKET >> netstat.txt && cat netstat.txt
echo "________________________________________________________________________" >> netstat.txt && cat netstat.txt
                         echo >> netstat.txt && cat netstat.txt
echo -e "\t<<+}================================================={+>>" >> netstat.txt && cat netstat.txt
echo -e "\t\t >> Display Datagram Packets:" >> netstat.txt && cat netstat.txt
echo -e "\t<<+}================================================={+>>" >> netstat.txt && cat netstat.txt
netstat -anp | grep DGRAM >> netstat.txt && cat netstat.txt
echo "________________________________________________________________________" >> netstat.txt && cat netstat.txt
                         echo >> netstat.txt && cat netstat.txt
echo -e "\t<<+}================================================={+>>" >> netstat.txt && cat netstat.txt
echo -e "\t\t >> Display Sockets With The ACC Flag:" >> netstat.txt && cat netstat.txt
echo -e "\t<<+}================================================={+>>" >> netstat.txt && cat netstat.txt
netstat -anp | grep ACC >> netstat.txt && cat netstat.txt
echo "________________________________________________________________________" >> netstat.txt && cat netstat.txt
                         echo >> netstat.txt && cat netstat.txt





echo -e "\t<<+}================================================={+>>" >> $TEMP_DIR/NetstatLocalProg.txt
echo -e "\t\t >> :" >> $TEMP_DIR/NetstatLocalProg.txt
echo -e "\t<<+}================================================={+>>" >> $TEMP_DIR/NetstatLocalProg.txt
netstat --verbose --symbolic --extend --programs




echo "[+] Saving output from: netstat -na"


netstat -s | grep "Total Packets Received" | awk '{print}' >> $TEMP_DIR/TotalPacketsRecieved.txt && cat -vET $TEMP_DIR/VmStatPart.txt
netstat -s | grep "Incoming Packets Discarded" | awk '{print}' >> $TEMP_DIR/DiscardedIncomingPackets.txt && cat -vET $TEMP_DIR/DiscardedIncomingPackets.txt
netstat -s | grep "ICMP Messages Received" | awk '{print}' >> $TEMP_DIR/ICMPMessagesReceived.txt && cat -vET $TEMP_DIR/ICMPMessagesReceived.txt
netstat -s | grep "ICMP Messages Send" | awk '{print}' >> $TEMP_DIR/ICMPMessagesSent.txt && cat -vET $TEMP_DIR/ICMPMessagesSent.txt.txt
netstat -s | grep "Active Connections Openings" | awk '{print}' >> $TEMP_DIR/ActiveOpenConnections.txt && cat -vET $TEMP_DIR/ActiveOpenConnections.txt
netstat -s | grep "Passive Connections Openings" | awk '{print}' >> $TEMP_DIR/PassiveConnectionsOpenings.txt && cat -vET $TEMP_DIR/PassiveConnectionsOpenings.txt.txt
netstat -s | grep "Connections Estabished" | awk '{print}' >> $TEMP_DIR/ConnectionsEstabished.txt && cat -vET $TEMP_DIR/ConnectionsEstabished.txt.txt
netstat -s | grep "Bad segments Received." | awk '{print}' >> $TEMP_DIR/BadSegmentsReceived.txt && cat -vET $TEMP_DIR/BadSegmentsReceived.txt


