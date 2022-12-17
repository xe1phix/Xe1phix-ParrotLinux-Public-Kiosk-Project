






Get info about the current connection:
nmcli con show


Add a new bridge:
nmcli con add type bridge ifname br0


Create a slave interface:
nmcli con add type bridge-slave ifname eno1 master br0


Turn on br0:
nmcli con up br0


$ nmcli con show
$ nmcli connection show --active


create a bridge, named br0
$ sudo nmcli con add ifname br0 type bridge con-name br0
$ sudo nmcli con add type bridge-slave ifname eno1 master br0
$ nmcli connection show



disable STP too:
$ sudo nmcli con modify br0 bridge.stp no
$ nmcli con show
$ nmcli -f bridge con show br0



The last command shows the bridge settings including disabled STP:

bridge.mac-address:                     --
bridge.stp:                             no
bridge.priority:                        32768
bridge.forward-delay:                   15
bridge.hello-time:                      2
bridge.max-age:                         20
bridge.ageing-time:                     300
bridge.multicast-snooping:              yes




How to turn on bridge interface
You must turn off “Wired connection 1” and turn on br0:
$ sudo nmcli con down "Wired connection 1"
$ sudo nmcli con up br0
$ nmcli con show

Use ip command to view the IP settings:
$ ip a s
$ ip a s br0





How to use br0 with KVM



<network>
  <name>br0</name>
  <forward mode="bridge"/>
  <bridge name="br0" />
</network>
Run virsh command as follows:
# virsh net-define /tmp/br0.xml
# virsh net-start br0
# virsh net-autostart br0
# virsh net-list --all



Sample outputs:

 Name                 State      Autostart     Persistent
----------------------------------------------------------
 br0                  active     yes           yes
 default              inactive   no            yes
 
 
 
 
 
 
 
auto br0
iface br0 inet static
        address 10.18.44.26
        netmask 255.255.255.192
        broadcast 10.18.44.63
        dns-nameservers 10.0.80.11 10.0.80.12
        # set static route for LAN 
	post-up route add -net 10.0.0.0 netmask 255.0.0.0 gw 10.18.44.1
	post-up route add -net 161.26.0.0 netmask 255.255.0.0 gw 10.18.44.1
        bridge_ports eth0
        bridge_stp off
        bridge_fd 0
        bridge_maxwait 0
 
 
 auto br0
iface br0 inet dhcp
        bridge_ports eth0
        bridge_stp off
        bridge_fd 0
        bridge_maxwait 0
 
 
 
 
 
 
 
 Verify connectivity
Use the ping/ip commands to verify that both LAN and WAN interfaces are reachable:
# See br0 and br1
ip a show
# See routing info
ip r
# ping public site
ping -c 2 cyberciti.biz
# ping lan server
ping -c 2 10.0.80.12
 
 
 


 
 
 
 # The loopback network interface
auto lo 
iface lo inet loopback
 
# Eth0 to Eth5 network switch
allow-hotplug eth0
iface eth0 inet manual
   pre-up   ifconfig $IFACE up
   pre-down ifconfig $IFACE down
 
allow-hotplug eth1
iface eth1 inet manual
   pre-up   ifconfig $IFACE up
   pre-down ifconfig $IFACE down
 
allow-hotplug eth2
iface eth2 inet manual
   pre-up   ifconfig $IFACE up 
   pre-down ifconfig $IFACE down
 
allow-hotplug eth3
iface eth3 inet manual
   pre-up   ifconfig $IFACE up
   pre-down ifconfig $IFACE down
 
allow-hotplug eth4
iface eth4 inet manual
   pre-up   ifconfig $IFACE up
   pre-down ifconfig $IFACE down
 
# Setup an IP address for our bridge 
auto br0
iface br0 inet static
  bridge_ports eth0 eth1 eth2 eth3 eth4
  address 192.168.1.253
  broadcast 192.169.1.255
  netmask 255.255.255.0
 
 
 
 
 
 
 
 How do I show a list of mac address?
# brctl showmacs br0

How can I see bridge stp information?
# brctl showstp br0
 
 
 
 
 
 sysctl -w net.ipv4.ip_forward=1

Next, use the following command:
/sbin/iptables -t nat -A POSTROUTING -o eth6 -j MASQUERADE
### ppp0 ###
/sbin/iptables -t nat -A POSTROUTING -o ppp0 -j MASQUERADE

OR setup an IP forwarding and masquerading (NAT):
/sbin/iptables --table nat --append POSTROUTING --out-interface eth6 -j MASQUERADE
/sbin/iptables --append FORWARD --in-interface br0 -j ACCEPT
 
 
 










 import OpenVPN config file from command line with NetworkManager

nmcli connection import type openvpn file /path/to/your.ovpn




nmcli connection import type openvpn file /home/$USER/.ovpn




nmcli connection up $ConnectionName



OpenVPN connection details:

nmcli connection show $ConnectionName


IP4.ADDRESS[1]:                         10.8.0.8/24
IP4.GATEWAY:                            10.8.0.1
IP4.DNS[1]:                             10.8.0.1



see IPv4/IPv6 OpenVPN client IP and other info

nmcli connection show $ConnectionName | egrep -i 'IP4|IPV6'
nmcli connection show $ConnectionName | egrep -i 'IP4'



Verify with ping - send ping requests to OpenVPN gateway:

ping -c 4 10.8.0.1





 dig +short myip.opendns.com @resolver1.opendns.com


dig TXT +short o-o.myaddr.l.google.com @ns1.google.com






iptables -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -I FORWARD -s 10.8.0.0/24 -j ACCEPT
iptables -I INPUT -p udp --dport 1194 -j ACCEPT
iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -j SNAT --to 139.59.1.155








systemctl start openvpn@server
systemctl restart openvpn@server

/etc/init.d/openvpn start
/etc/init.d/openvpn restart








extract the client certificate and client key into one file 'client-cacert.pem' (this should even work on a Win-Box ) 

openssl pkcs12 -in client-cacert.p12 -clcerts -out client-cacert.pem



extract it from your export file

openssl pkcs12 -in client-cacert.p12 -nokeys -cacerts -out root_X0F.crt



Converting certificates to encrypted .p12 format

# openssl pkcs12 -export -inkey keys/bugs.key -in keys/bugs.crt -certfile keys/ca.crt -out keys/bugs.p12















































































    /sbin/ethtool -K $INTERFACE sg off
    /sbin/ethtool -K $INTERFACE tx off
	
gsettings set org.gnome.nm-applet show-applet $nm_enabled


mac-address=`ip l show dev $INTERFACE |grep link|awk '{print $2}'`


bridge-utils-interfaces
interfaces
brctl
run-parts


/etc/network/interfaces

(eth|vif).*


bridge_hw MAC address
              set  the  Ethernet  MAC  address

http://bugs.debian.org/271406
http://bugs.debian.org/725786

http://bugs.debian.org/319832




arp-scan
dnsrecon
wpaclean
synaptic
Net::Pcap
mergecap
driftnet
editcap
captoinfo
capinfos
airolib-ng
hostapd
kismet_client
kismet.conf
iwspy
iwgetid
iwevent
crda
atmel_fwl




/proc/pid/ns/type


--list
--output
--task
--raw
--type
mnt,  net,  ipc, user, pid, uts and cgroup

--notruncate

lsns -o +PATH






airserv-ng
tkiptun-ng			## inject a few frames into a WPA TKIP network with QoS

wpa_action
wpa_background
wpa_cli
wpa_passphrase
wpa_supplicant
wpa_supplicant.conf
wpaclean
tuned
tc
sendto
flex
bison
packet

xt_bpf
epoll
seccomp-BPF






regulatory.bin

/lib/udev/rules.d/85-regulatory.rules

/proc/sys/net/ipv[4|6]/conf/[all|DEV]/



gbp - enables the Group Policy extension (VXLAN-GBP).

                          Allows to transport group policy context across VXLAN
                          network peers.  If enabled, includes the mark of a
                          packet in the VXLAN header for outgoing packets and
                          fills the packet mark based on the information found in
                          the VXLAN header for incomming packets.

                          Format of upper 16 bits of packet mark (flags);

                            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                            |-|-|-|-|-|-|-|-|-|D|-|-|A|-|-|-|
                            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

                            D := Don't Learn bit. When set, this bit indicates
                            that the egress VTEP MUST NOT learn the source address
                            of the encapsulated frame.

                            A := Indicates that the group policy has already been
                            applied to this packet. Policies MUST NOT be applied
                            by devices when the A bit is set.

                          Format of lower 16 bits of packet mark (policy ID):

                            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                            |        Group Policy ID        |
                            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

                          Example:
                            iptables -A OUTPUT [...] -j MARK --set-mark 0x800FF

                      gpe - enables the Generic Protocol extension (VXLAN-GPE).






 ip link add link DEVICE name NAME type { macvlan | macvtap } mode {
 private | vepa | bridge | passthru  [ nopromisc ] | source }


ip link add link DEVICE name NAME type macsec 



ip link set type bridge_slave 

ip link set type bond_slave 





bridge - Ethernet Bridge device

bond - Bonding device can - Controller Area Network inter‐
face

dummy - Dummy network interface

hsr - High-availability Seamless Redundancy device

ifb - Intermediate Functional Block device

ipoib - IP over Infiniband device

macvlan - Virtual interface base on link layer address (MAC)

macvtap - Virtual interface based on link layer address
(MAC) and TAP.

vcan - Virtual Controller Area Network interface

veth - Virtual ethernet interface

vlan - 802.1q tagged virtual LAN interface

vxlan - Virtual eXtended LAN

ip6tnl - Virtual tunnel interface IPv4|IPv6 over IPv6

ipip - Virtual tunnel interface IPv4 over IPv4

sit - Virtual tunnel interface IPv6 over IPv4

gre - Virtual tunnel interface GRE over IPv4

gretap - Virtual L2 tunnel interface GRE over IPv4

ip6gre - Virtual tunnel interface GRE over IPv6

ip6gretap - Virtual L2 tunnel interface GRE over IPv6

vti - Virtual tunnel interface

nlmon - Netlink monitoring device

ipvlan - Interface for L3 (IPv6/IPv4) based VLANs

lowpan - Interface for 6LoWPAN (IPv6) over IEEE 802.15.4 /
Bluetooth

geneve - GEneric NEtwork Virtualization Encapsulation

macsec - Interface for IEEE 802.1AE MAC Security (MACsec)

vrf - Interface for L3 VRF domains










VLAN offloading can be checked by ethtool:
ethtool -k <phy_dev> | grep tx-vlan-offload



iptables -t mangle -A POSTROUTING [...] -j CLASSIFY --set-class 0:4

ip link set veth0.10 type vlan egress 4:5


encap-csum


icsum flag requires that all input packets have the cor‐
rect checksum.
ocsum flag calculates checksums for outgoing packets.






mode bridge
mode passthru
mode source



address
port

sci 				secure channel identifier for this MACsec
cipher
icvlen				length of the Integrity Check Value
encrypt on
send_sci on
protect on			enables MACsec protection

replay on

validate strict
validate check





proto
rate
spoofchk on

query_rss on

state auto|enable|disable

trust on


node_guid eui64 - configure node GUID for the VF.

port_guid eui64 - configure port GUID for the VF.





ip link set type bridge_slave 


root_block on				block this port from becoming the
bridge's root port.

learning { on | off } - allow MAC address learning


proxy_arp { on

proxy_arp_wifi { on





mcast_router



ip link set type bond_slave [ queue_id ID ]




ip link set type 

add - add MACADDR to allowed list

set - replace allowed list

del - remove MACADDR from allowed list

flush - flush whole allowed list






group
type
vrf











iw help


address
       - protocol (IP or IPv6) address on a device.

addrlabel
       - label configuration for protocol address selection.

l2tp   - tunnel ethernet over IP (L2TPv3).

link   - network device.

maddress
       - multicast address.

monitor
       - watch for netlink messages.

mroute - multicast routing cache entry.

mrule  - rule in multicast routing policy database.

neighbour
       - manage ARP or NDISC cache entries.

netns  - manage network namespaces.

ntable - manage the neighbor cache's operation.

route  - routing table entry.

rule   - rule in routing policy database.

tcp_metrics/tcpmetrics
       - manage TCP Metrics

token  - manage tokenized interface identifiers.

tunnel - tunnel over IP.

tuntap - manage TUN/TAP devices.

xfrm   - manage IPSec policies.



ip netconf show - display network parameters


/etc/iproute2/group

ip link help

ip link set type 

ip link show type bridge
    Shows the bridge devices.

ip link show type vlan
    Shows the vlan devices.

ip link show master br0
    Shows devices enslaved by br0

ip link set dev ppp0 mtu 1400
    Change the MTU the ppp0 device.

ip link add link eth0 name eth0.10 type vlan id 10
    Creates a new vlan device eth0.10 on device eth0.

ip link delete dev eth0.10
    Removes vlan device.

ip link help gre
    Display help for the gre link type.

ip link add name tun1 type ipip remote 192.168.1.1 local 192.168.1.2 ttl
225 encap gue encap-sport auto encap-dport 5555 encap-csum encap-remcsum
    Creates an IPIP that is encapsulated with Generic UDP Encapsulation,
    and the outer UDP checksum and remote checksum offload are enabled.

ip link add link wpan0 lowpan0 type lowpan
    Creates a 6LoWPAN interface named lowpan0 on the underlying IEEE
    802.15.4 device wpan0.







setns


/var/run/netns/NAME refers to the specified network namespace.
/etc/netns/myvpn/resolv.conf



ip netns list

ip netns add vpn			Creates a network namespace and names it vpn

ip netns exec vpn ip link set lo up       Bring up the loopback interface in the vpn network namespace.

ip netns monitor

ip netns list-id

ip netns [ list ]

ip netns add NETNSNAME

ip [-all] netns del [ NETNSNAME ]

ip netns set NETNSNAME NETNSID

ip netns identify [ PID ]

ip netns pids NETNSNAME

ip [-all] netns exec [ NETNSNAME ] command...




ip netns add net0
ip link set dev eth0 netns net0
ip netns exec net0 SOME_PROCESS_IN_BACKGROUND
ip netns del net0

ip netns pids net0 | xargs kill
ip netns del net0





ip netns set NAME NETNSID - assign an id to a peer network namespace

ip netns identify [PID] - Report network namespaces names for process

ip netns pids NAME - Report processes in the named network namespace
ip [-all] netns exec [ NAME ] cmd ... - Run cmd in the named network names‐

ip netns monitor - Report as network namespace names are added and deleted

ip netns list-id - list network namespace ids (nsid)




peer 				change the link layer broadcast address or the peer address when the interface is POINTOPOINT

broadcast 
address 
mtu 
name 
dev 
group 
multicast on
arp on

alias 




netns 


ethtool -k 



vf mac 
vlan 
qos 
proto 
rate
spoofchk on
state auto|enable|disable
trust on
node_guid eui64
port_guid eui64



master 


addrgenmode none
stable_secret /proc/sys/net/ipv6/conf/{default,DEVICE}/stable_secret



/proc/sys/net/ipv6/conf/{default,DEVICE}/stable_secret






ip xfrm monitor [ all-nsid ] [ all

ip xfrm state add         add new state into xfrm
ip xfrm state update      update existing state in xfrm
ip xfrm state allocspi    allocate an SPI value
ip xfrm state delete      delete existing state in xfrm
ip xfrm state get         get existing state in xfrm
ip xfrm state deleteall   delete all existing state in xfrm
ip xfrm state list        print out the list of existing state in xfrm
ip xfrm state flush       flush all state in xfrm
ip xfrm state count       count all existing state in xfrm


ip xfrm policy add         add a new policy
ip xfrm policy update      update an existing policy
ip xfrm policy delete      delete an existing policy
ip xfrm policy get         get an existing policy
ip xfrm policy deleteall   delete all existing xfrm policies
ip xfrm policy list        print out the list of xfrm policies
ip xfrm policy flush       flush policies



ip xfrm policy count   count existing policies

ip xfrm policy set   configure the policy hash table


ip xfrm monitor    state monitoring for xfrm objects






Create a MACsec device on link eth0
       # ip link add link eth0 macsec0 type macsec port 11 encrypt on

   Configure a secure association on that device
       # ip macsec add macsec0 tx sa 0 pn 1024 on key 01 81818181818181818181818181818181

   Configure a receive channel
       # ip macsec add macsec0 rx port 1234 address c6:19:52:8f:e6:a0

   Configure a receive association
       # ip macsec add macsec0 rx port 1234 address c6:19:52:8f:e6:a0 sa 0 pn 1 on key 00 82828282828282828282828282828282

   Display MACsec configuration
       # ip macsec show




ip l2tp add tunnel 

tunnel_id 
peer_tunnel_id 
remote 
local 
encap udp, ip
udp_sport 
udp_dport 
udp_csum on
udp6_csum_rx on


ip l2tp add session 
tunnel_id 
session_id
peer_session_id
cookie
peer_cookie
l2spec_type none, default

offset 
peer_offset 






   Setup L2TP tunnels and sessions
       site-A:# ip l2tp add tunnel tunnel_id 3000 peer_tunnel_id 4000 \
                  encap udp local 1.2.3.4 remote 5.6.7.8 \
                  udp_sport 5000 udp_dport 6000
       site-A:# ip l2tp add session tunnel_id 3000 session_id 1000 \
                  peer_session_id 2000

       site-B:# ip l2tp add tunnel tunnel_id 4000 peer_tunnel_id 3000 \
                  encap udp local 5.6.7.8 remote 1.2.3.4 \
                  udp_sport 6000 udp_dport 5000
       site-B:# ip l2tp add session tunnel_id 4000 session_id 2000 \
                  peer_session_id 1000

       site-A:# ip link set l2tpeth0 up mtu 1488

       site-B:# ip link set l2tpeth0 up mtu 1488

       Notice that the IP addresses, UDP ports and tunnel / session ids are
       matched and reversed at each site.





Configure as IP interfaces
       The two interfaces can be configured with IP addresses if only IP data is
       to be carried. This is perhaps the simplest configuration.

       site-A:# ip addr add 10.42.1.1 peer 10.42.1.2 dev l2tpeth0

       site-B:# ip addr add 10.42.1.2 peer 10.42.1.1 dev l2tpeth0

       site-A:# ping 10.42.1.2

       Now the link should be usable. Add static routes as needed to have data
       sent over the new link.





Configure as bridged interfaces
       To carry non-IP data, the L2TP network interface is added to a bridge
       instead of being assigned its own IP address, using standard Linux utili‐
       ties. Since raw ethernet frames are then carried inside the tunnel, the MTU
       of the L2TP interfaces must be set to allow space for those headers.

       site-A:# ip link set l2tpeth0 up mtu 1446
       site-A:# ip link add br0 type bridge
       site-A:# ip link set l2tpeth0 master br0
       site-A:# ip link set eth0 master br0
       site-A:# ip link set br0 up

       If you are using VLANs, setup a bridge per VLAN and bridge each VLAN over a
       separate L2TP session. For example, to bridge VLAN ID 5 on eth1 over an
       L2TP pseudowire:

       site-A:# ip link set l2tpeth0 up mtu 1446
       site-A:# ip link add brvlan5 type bridge
       site-A:# ip link set l2tpeth0.5 master brvlan5
       site-A:# ip link set eth1.5 master brvlan5
       site-A:# ip link set brvlan5 up



       Adding the L2TP interface to a bridge causes the bridge to forward traffic
       over the L2TP pseudowire just like it forwards over any other interface.
       The bridge learns MAC addresses of hosts attached to each interface and
       intelligently forwards frames from one bridge port to another. IP addresses
       are not assigned to the l2tpethN interfaces. If the bridge is correctly
       configured at both sides of the L2TP pseudowire, it should be possible to
       reach hosts in the peer's bridged network.

       When raw ethernet frames are bridged across an L2TP tunnel, large frames
       may be fragmented and forwarded as individual IP fragments to the recipi‐
       ent, depending on the MTU of the physical interface used by the tunnel.
       When the ethernet frames carry protocols which are reassembled by the
       recipient, like IP, this isn't a problem. However, such fragmentation can
       cause problems for protocols like PPPoE where the recipient expects to
       receive ethernet frames exactly as transmitted. In such cases, it is impor‐
       tant that frames leaving the tunnel are reassembled back into a single
       frame before being forwarded on. To do so, enable netfilter connection
       tracking (conntrack) or manually load the Linux netfilter defrag modules at
       each tunnel endpoint.

       site-A:# modprobe nf_defrag_ipv4

       site-B:# modprobe nf_defrag_ipv4

       If L2TP is being used over IPv6, use the IPv6 defrag module.






ip tunnel show


ip tunnel add





ip token list - list all interface tokens
ip token get - get the interface token from the kernel
ip token del - delete an interface toke
ip token set - set an interface token


ip maddress show - list multicast addresses
ip maddress add - add a multicast addressq



-all
-color
-timestamp
-tshort

-stats
-details
-human-readable
-resolve
-oneline
-netns

ip netns exec NETNS ip 


ip addrlabel add 
label
dev

ip addrlabel list
ip addrlabel flush



ip rule show
ip rule add - insert a new rule
ip rule save
ip rule restore
ip rule flush - also dumps all the deleted rules.








--dev
--num-cpus
--interval
--loop
--csv
--omit-header
ifpps --promisc

ifpps eth0
ifpps -pd eth0
ifpps -lpcd wlan0 > plot.dat		Continuous terminal output for the wlan0 device in promiscuous mode.



pcapG

gnuplot
trafgen
bpfc
flowtop
trafgen
curvetun
netsniff-ng
mausezahn









--example
--verbose
--prio-high

-u <uid>, --user <uid> resp. -g <gid>, --group <gid>
       After ring setup, drop privileges to a non-root user/group combination.

--ring-size 
--rate 
--cpus 
--rand 

--rfraw 		create a mon<X> device

-o <dev>, -d <dev>, --out <dev>, --dev <dev>
       Defines the outgoing networking device such as eth0, wlan0 and others.


-i <cfg|->, -c <cfg|i>, --in <cfg|->, --conf <cfg|->		input configuration file






trafgen --dev eth0 --conf trafgen.cfg
    This is the most simple and, probably, the most common use of  trafgen.  It
    will generate traffic defined in the configuration file ''trafgen.cfg'' and
    transmit this via the ''eth0'' networking device. All online CPUs are used.

trafgen -e | trafgen -i - -o lo --cpp -n 1
    This is an example where we send one packet of the built-in example through
    the loopback device. The example configuration is passed via stdin and also
    through the C preprocessor before trafgen's packet compiler will see it.

trafgen --dev eth0 --conf fuzzing.cfg --smoke-test 10.0.0.1
    Read the ''fuzzing.cfg'' packet configuration file (which  contains  drnd()
    calls)  and  send  out  the generated packets to the ''eth0'' device. After
    each sent packet, ping probe the attacked host  with  address  10.0.0.1  to
    check if it's still alive. This also means, that we utilize 1 CPU only, and
    do not use the TX_RING, but sendto(2) packet I/O due to ''slow mode''.


trafgen --dev wlan0 --rfraw --conf beacon-test.txf -V --cpus 2
    As an output device ''wlan0'' is used and put into monitoring mode, thus we
    are going to transmit raw 802.11 frames through the air. Use the
     ''beacon-test.txf''  configuration file, set trafgen into verbose mode and
    use only 2 CPUs.

trafgen --dev em1 --conf frag_dos.cfg --rand --gap 1000us
    Use trafgen in sendto(2) mode instead of TX_RING mode and sleep after  each
    sent   packet   a   static   timegap  for  1000us.  Generate  packets  from
    ''frag_dos.cfg'' and select next packets to  send  randomly  instead  of  a
    round-robin fashion.  The output device for packets is ''em1''.

trafgen --dev eth0 --conf icmp.cfg --rand --num 1400000 -k1000
    Send  only  1400000  packets  using the ''icmp.cfg'' configuration file and
    then exit trafgen. Select packets randomly from that file for  transmission
    and  send  them out via ''eth0''. Also, trigger the kernel every 1000us for
    batching the ring frames from user space (default is 10us).

trafgen --dev eth0 --conf tcp_syn.cfg -u `id -u bob` -g `id -g bob`
    Send out packets generated from the configuration file ''tcp_syn.cfg''  via
    the ''eth0'' networking device. After setting up the ring for transmission,
    drop credentials to the non-root user/group bob/bob.

trafgen --dev eth0 '{ fill(0xff, 6), 0x00,  0x02,  0xb3,  rnd(3),  c16(0x0800),
    fill(0xca, 64) }' -n 1
    Send out 1 invaid IPv4 packet built from command line to all hosts.











cat /etc/netsniff-ng/mausezahn.conf
/etc/netsniff-ng/mausezahn.conf

mausezahn -x
mausezahn -t help
mausezahn  -t  tcp  help
mausezahn -t icmp help
mausezahn -t rtp help
mausezahn -t syslog help



mausezahn eth3 -t udp sp=69,dp=69,p=ca:fe:ba:be
mausezahn eth0 -t udp sp=1,dp=80,p=00:11:22:33
mausezahn eth0 -t udp sp=1,dp=80,p=00:11:22:33
mausezahn eth0 -t udp "sp=1,dp=80,p=00:11:22:33"
mausezahn -t bpdu help

mausezahn eth0 -t ip -P "Hello World"

mausezahn eth0 -t ip p=68:65:6c:6c:6f:20:77:6f:72:6c:64       # hex  pay‐

mausezahn eth0 -t ip "proto=89,
mausezahn -c 0  "aa bb cc dd ...."


ausezahn eth0 "ff:ff:ff:ff:ff:ff ff:ff:ff:ff:ff:ff 00:00 ca:fe:ba:be"
mausezahn eth0 -c 0 -a rand -b bcast -p 1000 "08 00 aa bb cc dd"
mausezahn eth0 -t arp
mausezahn    eth0    -t   arp   "reply,   senderip=192.168.0.1,   target‐
mausezahn eth0 -t bpdu "vlan=123, rid=2000"


mausezahn -t cdp change -c 0


mausezahn eth0 -t tcp -Q 7:500 "dp=80, flags=rst, p=aa:aa:aa"
mausezahn eth0 -t udp "dp=8888, sp=13442"  -P  "Mausezahn  is  great"  -Q
mausezahn eth0 -t udp "dp=8888, sp=13442" -P "Mausezahn is great"  \
mausezahn  eth0  -t  udp  "dp=8888,  sp=13442" -P "Mausezahn is great" -Q
mausezahn  eth0 -b bc -a rand "81:00 00:05 08:00 aa-aa-aa-aa-aa-aa-aa-aa-
mausezahn eth0 -M 214 -t tcp "dp=80" -P "HTTP..." -B myhost.com
mausezahn eth0 -M 9999,51,214 -t tcp "dp=80" -P "HTTP..." -B myhost.com
mausezahn eth0 -M 100:5:1,500:7 -t tcp "dp=80" -P "HTTP..." -B myhost.com
mausezahn eth0 -M 214:s -t tcp "dp=80" -P "HTTP..." -B myhost.com
mausezahn eth0 -t ip -A rand -B 192.168.1.0/24  -P "hello world"
mausezahn  eth0  -t  ip  -A  10.1.0.1-10.1.255.254   -B   255.255.255.255
mausezahn eth0 -t ip -B www.xyz.com
mausezahn eth0 -t ip dscp=46,ttl=1,proto=1,p=08:00:5a:a2:de:ad:be:af


mausezahn eth0 -A rand -B 1.1.1.1 -c 0 -t tcp "dp=1-1023, flags=syn"  \
mausezahn eth0 -A legal.host.com -B target.host.com \
mausezahn eth0 -A legal.host.com -B target.host.com \

mausezahn eth0 -B mydns-server.com -t dns "q=www.ibm.com"
mausezahn eth0 -A spoofed.dns-server.com -B target.host.com \

mausezahn -t rtp -B 192.168.1.19
mausezahn -T rtp

mausezahn -t rtp id=11:11:11:11 -B 192.168.2.2 &
Host1# mausezahn -T rtp id=22:22:22:22 "log, path=/tmp/mz/"
Host2# mausezahn -t rtp id=22:22:22:22 -B 192.168.1.1 &
Host2# mausezahn -T rtp id=11:11:11:11 "log, path=/tmp/mz/"

mausezahn -T rtp txt

mausezahn  -t  syslog sev=3 -P "You have been mausezahned." -A 10.1.1.109









 ''echo "1" > /proc/sys/net/core/bpf_jit_enable'' (normal working  mode)  or
       ''echo  "2" > /proc/sys/net/core/bpf_jit_enable'' (debug mode where emitted












/dev/net/tun




--dev 				Defines the name of the tunnel device that is being created.
--port 

--stun stunserver.org



--keygen
Generate private and public keypair. This must be done initially.

--export
Export user and key combination to stdout as a one-liner.

--dumpc
Dump all known clients that may connect to the local  curvetun  server  and
exit.

--dumps
Dump all known servers curvetun as a client can connect to, and exit.

--no-logging
Disable all curvetun logging of user information. 

--udp 


--ipv4 





curvetun -k

The client needs to export its public key data for the server

       curvetun -x


curvetun -C			 The server admin can check if the server has registered it
~/.curvetun/clients



the server needs to export its key to the client, as follows:

         server$ curvetun -x

 >> ~/.curvetun/servers




check its config using:

curvetun -S


art the server with:

curvetun -s -p 6666 -u
ifconfig curves0 up
ifconfig curves0 10.0.0.1/24

tart the client with:

curvetun -c=myfirstserver
ifconfig curvec0 up
ifconfig curvec0 10.0.0.2/24



ifconfig curves0 up
ifconfig curves0 10.0.0.1/24
echo 1 > /proc/sys/net/ipv4/ip_forward
iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
iptables  -A  FORWARD  -i  eth0  -o  curves0  -m  state  --state
TABLISHED -j ACCEPT
iptables -A FORWARD -i curves0 -o eth0 -j ACCEPT




start curvetun client

ifconfig curvec0 up
ifconfig curvec0 10.0.0.2/24
route add -net 1.2.3.0 netmask 255.255.255.0 gw 5.6.7.9 dev eth0
route add default gw 10.0.0.1
route del default gw 5.6.7.9




/var/log/iptraf/*.log - log file
        /var/lib/iptraf/* - important IPTraf data files










##-==========================-##
##   [+] Created vboxnet0 network:
##-==========================-##
vboxmanage hostonlyif create
vboxmanage hostonlyif ipconfig vboxnet0 –ip 192.168.56.1

## -------------------------------------------------------------------------------- ##
##   [+] Allow the guest VMs access to the Internet (optional). 
##   [?] As the user root:
## -------------------------------------------------------------------------------- ##
iptables –A FORWARD –o eth0 –i vboxnet0 –s 192.168.56.0/24 –m conntrack --ctstate NEW –j ACCEPT
iptables –A FORWARD –m conntrack --ctstate ESTABLISHED,RELATED –j ACCEPT
iptables –A POSTROUTING –t nat –j MASQUERADE
echo 1 > /proc/sys/net/ipv4/ip_forward






