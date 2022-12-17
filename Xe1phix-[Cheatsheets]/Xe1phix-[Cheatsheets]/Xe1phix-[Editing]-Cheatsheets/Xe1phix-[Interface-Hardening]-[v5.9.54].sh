# This file describes the network interfaces available on your system
# and how to activate them. For more information, see interfaces(5).

source /etc/network/interfaces.d/*

# The loopback network interface
auto lo
iface lo inet loopback

auto eth0
iface eth0 inet static
ip link set
   pre-up ifconfig eth0 hw ether 00:30:65:35:2e:37
   pre-up /etc/iptables/iptables.rules
   address 192.168.1.37
   gateway 192.168.1.1
   netmask 255.255.255.0
   dns-nameservers 172.98.193.62 193.138.218.74
   pre-up iptables-restore < /etc/iptables.up.rules
   post-up echo 1 > /proc/sys/net/ipv6/conf/\$IFACE/disable_ipv6
# post-up openvpn --config /etc/openvpn/openvpn.conf
#  pre-down killall -KILL openvpn
   down ifconfig $IFACE down

   up /etc/openvpn/update-resolv-conf
# down /etc/openvpn/update-resolv-conf
up /etc/openvpn/scripts/update-systemd-resolved
#   down /etc/openvpn/scripts/update-systemd-resolved
#   down-pre

   accept_ra 0
   privext 2
   dad-attempts 0
   request_prefix 0



# iface work-static static
	pre-up ifconfig eth0 hw ether 00:40:B7:13:37:01
    pre-up /etc/iptables/ $IFACE

    address 10.15.43.23
    netmask 255.255.255.0
    gateway 10.15.43.1
    dns-nameservers 203.0.113.1 203.0.113.2 203.0.113.3
    dns-search members.linode.com
   accept_ra 0

# iface work-static static
#     address 10.15.43.23
#     netmask 255.255.255.0
#     gateway 10.15.43.1

iface ethernet inet static
#     pre-up /usr/local/sbin/firewall $IFACE

     mtu 1500
     hwaddress
	pre-up /
   accept_ra 0
iface eth1-home inet static
#     pre-up [ -f /etc/network/local-network-ok ]

#     pre-up /usr/local/sbin/firewall

/etc/network/interfaces.d
       mapping wlan0
            script /usr/local/sbin/map-scheme
            map HOME wlan0-ClassC
            map AMBROSE wlan0-ClassA

wireless-<function> <value>
              wireless-essid Home
              wireless-mode Ad-Hoc




source interfaces.d/machine-dependent

       source-directory /etc/network/interfaces.d
     script /usr/local/sbin/map-scheme
       iface eth0 inet dhcp

       iface eth0 inet6 auto
            address 192.168.1.2/24
            gateway 192.168.1.1


privext 2
accept_ra 0
request_prefix
dhcp 0



hwaddress random
accept_ra 0
autoconf 0
privext 2
dad-attempts 0
request_prefix 0

dh_installifupdown --name=
etc/network/if-*/




+auto $MGMT_INTERFACE
+iface $MGMT_INTERFACE inet static
+  address $ADDRESS
+  gateway $GATEWAY
+  netmask $NETMASK
+  network $NETWORK
+  broadcast $BROADCAST
+  dns-nameservers $NAMESERVER



https://www.cyberciti.biz/tips/howto-ubuntu-linux-convert-dhcp-network-configuration-to-static-ip-configuration.html







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




        # set static route for LAN
# Eth0 to Eth5 network switch
allow-hotplug eth0
iface eth0 inet manual
   pre-up   ifconfig $IFACE up
   pre-down ifconfig $IFACE down


auto lo
iface lo inet loopback

# Management interface using DHCP (not recommended due to Bro issue described above)
auto eth0
iface eth0 inet dhcp

# OR

# Management interface using STATIC IP (instead of DHCP)
auto eth0
iface eth0 inet static
  address 192.168.1.14
  gateway 192.168.1.1
  netmask 255.255.255.0
  network 192.168.1.0
  broadcast 192.168.1.255
  # If running Security Onion 14.04, you'll need to configure DNS here
  dns-nameservers 192.168.1.1 192.168.1.2

# AND one or more of the following

# Connected to TAP or SPAN port for traffic monitoring
auto eth1
iface eth1 inet manual
  up ifconfig $IFACE -arp up
  up ip link set $IFACE promisc on
  down ip link set $IFACE promisc off
  down ifconfig $IFACE down
  post-up for i in rx tx sg tso ufo gso gro lro; do ethtool -K $IFACE $i off; done
  # If running Security Onion 14.04, you should also disable IPv6 as follows:
  post-up echo 1 > /proc/sys/net/ipv6/conf/$IFACE/disable_ipv6



https://github.com/Security-Onion-Solutions/security-onion/wiki/NetworkConfiguration



cat << EOF | sudo tee -a /etc/network/interfaces
# Bridge for OpenVPN tap0
auto br0
iface br0 inet manual
  bridge_ports none
  post-up for i in rx tx sg tso ufo gso gro lro; do ethtool -K \$IFACE \$i off; done
EOF

/sbin/ip link set "\$DEV" up promisc on
/sbin/brctl addif \$BR \$DEV

for i in rx tx sg tso ufo gso gro lro; do ethtool -K \$DEV \$i off; done




cat << EOF | sudo tee -a /etc/openvpn/up.sh
#!/bin/sh

BR=\$1
DEV=\$2
/sbin/ip link set "\$DEV" up promisc on
/sbin/brctl addif \$BR \$DEV

for i in rx tx sg tso ufo gso gro lro; do ethtool -K \$DEV \$i off; done
EOF


cat << EOF | sudo tee -a /etc/openvpn/up.sh
#!/bin/sh

BR=\$1
DEV=\$2
/sbin/ip link set "\$DEV" up promisc on
/sbin/brctl addif \$BR \$DEV

for i in rx tx sg tso ufo gso gro lro; do ethtool -K \$DEV \$i off; done
EOF


sudo chmod +x /etc/openvpn/up.sh /etc/openvpn/down.sh


        post-up openvpn --config /etc/openvpn/openvpn.conf
        pre-down killall -KILL openvpn








