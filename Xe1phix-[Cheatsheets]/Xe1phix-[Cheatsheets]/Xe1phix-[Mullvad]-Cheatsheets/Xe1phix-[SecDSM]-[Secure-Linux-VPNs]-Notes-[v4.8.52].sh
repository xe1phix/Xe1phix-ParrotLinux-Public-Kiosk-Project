#!/bin/sh
##-===========================================================-##
##    [+] Xe1phix-[]-[v..].sh
##-===========================================================-##


Talk Resources:

Talk Overview:

Talk Cheatsheets:

Talk Slides:



https://wiki.archlinux.org/title/WireGuard


nm-settings

https://man.archlinux.org/man/nm-settings.5.en#wireguard_setting
https://man.archlinux.org/man/systemd.network.5#[NETWORK]_SECTION_OPTIONS
https://man.archlinux.org/man/systemd-resolved.service.8.en
https://man.archlinux.org/man/systemd.netdev.5#EXAMPLES





https://mullvad.net/en/help/different-entryexit-node-using-wireguard-and-socks5-proxy/






##-======================================-##
##   [+]  [DNS over HTTPS] and [DNS over TLS]
##-======================================-##
##  
## -------------------------------------------------------------- ##
##    [?]  Mullvad public DNS service offers :
## -------------------------------------------------------------- ##
## 
## -------------------------------------------------------------- ##
##		 >  DNS over HTTPS (DoH) 
## -------------------------------------------------------------- ##
##							+ 
## -------------------------------------------------------------- ##
##		 >  DNS over TLS (DoT), 
## -------------------------------------------------------------- ##
## 
## -------------------------------------------------------------- ##
##    [?]  With QNAME minimization 
##    [?]  And basic ad blocking. 
## -------------------------------------------------------------- ##


## ------------------------------------------- ##
##    [?]  Ad-blocking version:
## ------------------------------------------- ##
adblock.doh.mullvad.net

## ------------------------------------------- ##
##    [?]  Without ad blocking:
## ------------------------------------------- ##
doh.mullvad.net


## ---------------------------------------------- ##
##    [?]  DoT only uses port 853
## ---------------------------------------------- ##

## ---------------------------------------- ##
##    [?]  DoH uses port 443								##  (Without ad blocking)
## ---------------------------------------- ##


## ------------------------------------------------------- ##
##     [?]  doh.mullvad.net has address:
## ------------------------------------------------------- ##
##     >  194.242.2.2
## ------------------------------------------------------ ##

## ------------------------------------------------------ ##
##     [?]  doh.mullvad.net has address:
## ------------------------------------------------------ ##
##     >  193.19.108.2

## -------------------------------------------------------------- ##
##     [?]  doh.mullvad.net has IPv6 address:
## -------------------------------------------------------------- ##
##     >  2a07:e340::2											 ##  (With ad blocking)



adblock.doh.mullvad.net has address 194.242.2.3
adblock.doh.mullvad.net has address 193.19.108.3
adblock.doh.mullvad.net has IPv6 address 2a07:e340::3

Mullvad-Firefox-Enable-[DNS-over-HTTPS]-Custom-Provider


##-========================================================-##
##   [+]  Firefox-How-To-Use-The-Mullvad-DNS-Over-HTTPS-Service:
##-========================================================-##

## ------------------------------------------------------------ ##
##    [?]  In a Firefox browser window, 
##    [?]  click the menu button 
##    [?]  choose [Options] or [Preferences]
## ------------------------------------------------------------ ##

## ------------------------------------------------------------ ##
##    [?]  In the search box, type: “network”
## ------------------------------------------------------------ ##
##    [?]  Select the [Settings] button
## ------------------------------------------------------------ ##

## ------------------------------------------------------------ ##
##    [?]  At the bottom, check the box for:
## ------------------------------------------------------------ ##
##		 >  Enable [DNS over HTTPS]
## ------------------------------------------------------ ##

## ------------------------------------------------------ ##
##    [?]  Next to [Use Provider] choose: 
## ------------------------------------------------------ ##
##		 >  [Custom]
## ------------------------------------------------------ ##

## ------------------------------------------------------------------------------------------------- ##
##   [?]  In the text box that appears below, enter one of these URLs:
## ------------------------------------------------------------------------------------------------- ##

			  ## -------------------------------------------------------------- ##
			  ##    [?]  https://doh.mullvad.net/dns-query
			  ## -------------------------------------------------------------- ##
													or 
		## -------------------------------------------------------------------------- ##
		##    [?]  https://adblock.doh.mullvad.net/dns-query
		## -------------------------------------------------------------------------- ##



## ------------------------------------------------------------------------- ##
##   [?]  In the address bar of the browser, type in:
## ------------------------------------------------------------------------- ##
##   		  >  [about:config]
## ------------------------------------------------------------------------- ##


## ----------------------------------------------- ##
##   [?]  In the search box, type: 
## ----------------------------------------------- ##
##			  >  [network.trr.mode]
## ----------------------------------------------- ##

## ------------------------------------------------------------------------------------------------- ##
##   [?]  Change the value of [network.trr.mode] to: 
##           >  3
## ------------------------------------------------------------------------------------------------- ##
##   [?]  (this will disable the unencrypted fallback).
## ------------------------------------------------------------------------------------------------- ##


##-===============-##
##    [+]  DNSCrypt 
##-===============-##
(https://dnscrypt.info)


##-===========================-##
##    [+]  DNS over HTTPS (DoH) 
##-===========================-##
## ------------------------------------------------ ##
##   [?]  with DNSSEC and DNSBL
## ------------------------------------------------ ##


DNSCrypt 
or 
DNS over HTTPS

## ------------------------------------------------------------------------------------------------- ##
##   [?]  The DNSCrypt protocol authenticates communications 
##          between a dns-client and a dns-resolver. 
## ------------------------------------------------------------------------------------------------- ##

## ---------------------------------------------------------------------------------------------------------------------------- ##
##   [?]  It encrypts the traffic and prevents dns spoofing or man-in-the-middle-attacks.
## ---------------------------------------------------------------------------------------------------------------------------- ##


DNSCrypt-OpenNIC-Wiki
https://wiki.opennic.org/opennic/dnscrypt



##-======================-##
##   [+]  Enable debug logs:
##-======================-##

## ------------------------------------------------------------------------------------------------- ##
##   [?]  The Wireguard Linux kernel module supports dynamic debugging
## ------------------------------------------------------------------------------------------------- ##
##   [?]  debugging information can be written into the kernel ring buffer 
## ------------------------------------------------------------------------------------------------- ##
##   [?]  (viewable with dmesg and journalctl) by running: 
## ------------------------------------------------------------------------------------------------- ##
echo module wireguard +p > /sys/kernel/debug/dynamic_debug/control


##-===================================================-##
##   [+]  Generate QR code


## ------------------------------------------------------------------------------------------------- ##
##   [?]  qrencode can be used to generate client's configuration QR code
## ------------------------------------------------------------------------------------------------- ##

qrencode -t ansiutf8 -r client.conf



wg set "$INTERFACE" peer "$PUBLIC_KEY" endpoint "$ENDPOINT"




##-===================================================-##
##   [+]  parse WG configuration files 
and automatically reset the endpoint address:

/usr/share/wireguard-tools/examples/reresolve-dns/reresolve-dns.sh



## ------------------------------------------------------------------------------------------------------------------------------ ##
##   [?]   run this script periodically to recover from an endpoint that has changed its IP.

/usr/share/wireguard-tools/examples/reresolve-dns/reresolve-dns.sh /etc/wireguard/wg.conf 


## ------------------------------------------------------------------------------------------------- ##
##   [?]  One way of doing so is by updating all WireGuard endpoints 
##          once every thirty seconds via a systemd timer:



##-===================================================-##
##   [+]  /etc/systemd/system/wireguard_reresolve-dns.timer
##-===================================================-##

[Unit]
Description=Periodically reresolve DNS of all WireGuard endpoints

[Timer]
OnCalendar=*:*:0/30

[Install]
WantedBy=timers.target




##-===================================================-##
##   [+]  /etc/systemd/system/wireguard_reresolve-dns.service
##-===================================================-##

[Unit]
Description=Reresolve DNS of all WireGuard endpoints
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
ExecStart=/bin/sh -c 'for i in /etc/wireguard/*.conf; do /usr/share/wireguard-tools/examples/reresolve-dns/reresolve-dns.sh "$i"; done'

## ------------------------------------------------------------------------------------------------- ##
##   [?]  Afterwards enable and start wireguard_reresolve-dns.timer 
## ------------------------------------------------------------------------------------------------- ##



NetworkManager can import a wg-quick configuration file.

nmcli connection import type wireguard file /etc/wireguard/wg0.conf



import this into NetworkManager:

nmcli connection import type wireguard file "$CONF_FILE"


create a WireGuard profile 

nmcli connection add type wireguard ifname wg0 con-name my-wg0









set the permissions of the .netdev file:

chown root:systemd-network /etc/systemd/network/99-*.netdev
chmod 0640 /etc/systemd/network/99-*.netdev




To use a peer as a DNS server, 
specify its WireGuard tunnel's IP address(es) in the .network file using the DNS= option.


For search domains use the Domains= option.
See systemd.network(5) § [NETWORK] SECTION OPTIONS for details.


To use a peer as the only DNS server, then in the .network file's [Network] section set 
DNSDefaultRoute=true 
and add ~. to 
Domains=~


DNSDefaultRoute=true
Domains=~.





ufw route allow in on wg0 out on eth0

/etc/ufw/before.rules

*nat
:POSTROUTING ACCEPT [0:0]
-A POSTROUTING -s 10.0.0.0/24 -o enp5s0 -j MASQUERADE
COMMIT






WireGuard-[systemd-networkd]-routing all traffic over WireGuard

In this example Peer B connects to peer A with public IP address. 
Peer B routes all its traffic over WireGuard tunnel 
and uses Peer A for handling DNS requests. 

Peer A setup

/etc/systemd/network/99-wg0.netdev

[NetDev]
Name=wg0
Kind=wireguard
Description=WireGuard tunnel wg0

[WireGuard]
ListenPort=51871
PrivateKey=PEER_A_PRIVATE_KEY

[WireGuardPeer]
PublicKey=PEER_B_PUBLIC_KEY
PresharedKey=PEER_A-PEER_B-PRESHARED_KEY
AllowedIPs=10.0.0.2/32



/etc/systemd/network/99-wg0.network

[Match]
Name=wg0

[Network]
Address=10.0.0.1/24




Peer B setup:

/etc/systemd/network/99-wg0.netdev

[NetDev]
Name=wg0
Kind=wireguard
Description=WireGuard tunnel wg0

[WireGuard]
ListenPort=51902
PrivateKey=PEER_B_PRIVATE_KEY
FirewallMark=0x8888

[WireGuardPeer]
PublicKey=PEER_A_PUBLIC_KEY
PresharedKey=PEER_A-PEER_B-PRESHARED_KEY
AllowedIPs=0.0.0.0/0
Endpoint=198.51.100.101:51871

/etc/systemd/network/50-wg0.network

[Match]
Name=wg0

[Network]
Address=10.0.0.2/24
DNS=10.0.0.1
DNSDefaultRoute=true
Domains=~.

[RoutingPolicyRule]
FirewallMark=0x8888
InvertRule=true
Table=1000
Priority=10

[Route]
Gateway=10.0.0.1
GatewayOnLink=true
Table=1000











WireGuard-[Systemd-]-Reresolve-DNS-Periodically
WireGuard-[Systemd-]-Reresolve-DNS-Service
WireGuard-[Systemd-]-
WireGuard-[Systemd-]-
WireGuard-[Systemd-]-
WireGuard-[Systemd-]-Reresolve-DNS-Service




/home/parrotseckiosk/Downloads/[05-11-20]/Xe1phix-[HackerCons]/Xe1phix-InfoSecTalk-Materials/Secure-Linux-Networking-v2-[CornCon-2021]/Secure-Linux-Networking-v2-[CornCon-2021]-[Screenshots]/[Mullvad]-Screenshots/Mullvad-[OpenVPN]-Screenshots
about:networking#dns
about:networking#http

Mullvad-[WebRTC]-Screenshots
Mullvad-
[DNSCrypt]-Screenshots
Mullvad-[]-Screenshots
Mullvad-[]-Screenshots
Mullvad-[]-Screenshots
Mullvad-[]-Screenshots
Mullvad-[]-Screenshots
Mullvad-[]-Screenshots
Mullvad-[]-Screenshots
Mullvad-[]-Screenshots
Mullvad-[]-Screenshots
Mullvad-[]-Screenshots
Mullvad-[]-Screenshots

Firefox-WebRTC-Preferences-About-WebRTC
about:webrtc









What is WireGuard?
▪ Layer 3 secure network tunnel for IPv4 and IPv6.
▪ UDP-based. Punches through firewalls.
▪ Modern primitives: Curve25519, Blake2s, ChaCha20, Poly1305

Network Namespace
The WireGuard interface can live in one namespace, and the physical interface can live
in another.
▪ Only let your DHCP client touch physical interfaces, and only let your web browser see
WireGuard interfaces.


The Key Exchange
▪ The key exchange designed to keep our principles static allocations,
guarded state, fixed length headers, and stealthiness.
▪ In order for two peers to exchange data, they must first derive
ephemeral symmetric crypto session keys from their static public keys.
▪ Either side can reinitiate the handshake to derive new session keys.
▪ Invalid handshake messages are ignored

The Key Exchange: NoiseIK
▪ One peer is the initiator; the other is the responder.
▪ Each peer has their static identity – their long term static keypair.
▪ For each new handshake, each peer generates an ephemeral keypair.
▪ The security properties we want are achieved by computing ECDH() on
the combinations of two ephemeral keypairs and two static keypairs.

WireGuard-Security-Design-Principle-3-Static-Fixed-Length-Headers
▪ All packet headers have fixed width fields, so no parsing is necessary.
▪ Eliminates an entire class of vulnerabilities.
▪ No parsers → no parser vulnerabilities.


WireGuard-Security-Design-Principle-6-Solid-Crypto
▪ Strong key agreement & authenticity
▪ Key-compromise impersonation resistance
▪ Unknown key-share attack resistance
▪ Key secrecy
▪ Forward secrecy
▪ Session uniqueness
▪ Identity hiding
▪ Replay-attack prevention, while allowing for network packet reordering

▪ Handshake in kernel space, instead of punted to userspace daemon like
IKE/IPsec.
▪ Allows for more efficient and less complex protocols.
▪ Exploit interactions between handshake state and packet encryption state.


Performance
▪ Being in kernel space means that it is fast and low latency.
▪ No need to copy packets twice between user space and kernel space.
▪ ChaCha20Poly1305 is extremely fast on nearly all hardware, and safe.
▪ AES is exceedingly difficult to implement performantly and safely (no cache-timing
attacks) without specialized hardware.
▪ ChaCha20 can be implemented efficiently on nearly all general purpose processors.


WireGuard is written with less than 7,000 lines of code whereas IPSec contains 400,000 lines (OpenVPN is of similar complexity). The more code used, the greater the chance of a vulnerability being present in those lines. With a background in kernel exploit development, we don't expect the creator of WireGuard to have written code that contains 100 times more vulnerabilities than IPSec or OpenVPN.

Each WireGuard® server is connected to all the other WireGuard servers through WireGuard tunnels.



Routing all DNS over WireGuard (i.e. Domains=~.) will prevent the DNS resolution of endpoints.





WireGuard-[Key-Exchange]
WireGuard-[]
WireGuard-[]
WireGuard-[]
WireGuard-[]
WireGuard-[Performance-Measurements]
WireGuard-[]
WireGuard-Routing-peers
WireGuard-[Server-Config]-[Client-Config]
WireGuard-[Timers]
WireGuard-[]
WireGuard-[]
WireGuard-[]
WireGuard-[]
WireGuard-[]
WireGuard-[]
WireGuard-[]
WireGuard-[]
WireGuard-[]
WireGuard-[]
WireGuard-[]
WireGuard-[]
WireGuard-[]
WireGuard-[]
WireGuard-[]
WireGuard-[]
WireGuard-[]
WireGuard-[]
WireGuard-[]
WireGuard-[]
WireGuard-[]
WireGuard-[]
WireGuard-[]
WireGuard-[]
WireGuard-[]
WireGuard-[]
WireGuard-[]
WireGuard-[]
WireGuard-[]
WireGuard-[]

