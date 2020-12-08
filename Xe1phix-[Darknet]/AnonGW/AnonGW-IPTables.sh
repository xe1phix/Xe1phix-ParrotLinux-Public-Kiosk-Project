#!/bin/bash
# AnonGW-IPTables.sh
firewall () {

/sbin/iptables -F
/sbin/iptables -t nat -F
/sbin/iptables -t mangle -F
/sbin/iptables -X
/sbin/iptables -t nat -X
/sbin/iptables -t mangle -X
/sbin/iptables -Z
#______________POLICY__________________
/sbin/iptables -P INPUT DROP
/sbin/iptables -P FORWARD ACCEPT
/sbin/iptables -P OUTPUT ACCEPT
/sbin/ip6tables -P INPUT DROP
/sbin/ip6tables -P FORWARD DROP
/sbin/ip6tables -P OUTPUT DROP
#___________CUSTOM_ CHAINS_______________
/sbin/iptables -N SSH_CHECK
/sbin/iptables -N SSH_ATTACKED
/sbin/iptables -N SCAN_CHECK
/sbin/iptables -t nat -N BYPASS
    #________________MANGLE_______________
/sbin/iptables -t mangle -A POSTROUTING -o $virbr -p udp -m udp --dport 68 -j CHECKSUM --checksum-fill
/sbin/iptables -t mangle -A OUTPUT -p udp --dport 53 -j TOS --set-tos Minimize-Delay
/sbin/iptables -t mangle -A OUTPUT -p udp --dport 40 -j TOS --set-tos Minimize-Delay
/sbin/iptables -t mangle -A FORWARD -p tcp -m multiport --dport 22,873 -j TOS --set-tos Maximize-Throughput # sftp,rsync
#
#_________________OUTPUT___________________
# Custom
#_________________FORWARD__________________
#
#__________________INPUT___________________
/sbin/iptables -A INPUT  -i lo -j ACCEPT
/sbin/iptables -A INPUT -i $IntBr -j ACCEPT
/sbin/iptables -A INPUT -i $ExtBr -m multiport -p udp --dports $vpn_port,$i2p_port,$freenet_ports,$gnunet_ports -j ACCEPT #vpn,i2p,freenet(open,dark),gnunet
/sbin/iptables -A INPUT -i $ExtBr -m multiport -p tcp --dports $i2p_port,$gnunet_port,$tor_relays_ports -j ACCEPT #i2p,gnunet,tor
/sbin/iptables -A INPUT -i $ExtBr -m state --state ESTABLISHED,RELATED -j ACCEPT
/sbin/iptables -A INPUT -i $lxcbr -j ACCEPT
#
# SSH rules to comply with hosts.allow
/sbin/iptables -A INPUT -i $ExtBr -p tcp -m state --state NEW --dport 22 -j SSH_CHECK
/sbin/iptables -A INPUT -i $tun -p tcp -m state --state NEW --dport 22 -j SSH_CHECK
/sbin/iptables -A INPUT -i $virbr -p tcp -m state --state NEW --dport 22 -j SSH_CHECK
/sbin/iptables -A INPUT -i $lxcbr -p tcp -m state --state NEW --dport 22 -j SSH_CHECK
/sbin/iptables -A INPUT -i $tun -j ACCEPT
/sbin/iptables -A INPUT -i $virbr -j ACCEPT
#
/sbin/iptables -A SSH_CHECK -m recent --set --name SSH
/sbin/iptables -A SSH_CHECK -m recent --update --seconds 180 --hitcount 6 --name SSH -j SSH_ATTACKED
/sbin/iptables -A SSH_CHECK -j ACCEPT
/sbin/iptables -A SSH_ATTACKED -j LOG --log-prefix "iptables SSH attack: " --log-level 7
/sbin/iptables -A SSH_ATTACKED -j DROP
#
/sbin/iptables -A INPUT -i $ExtBr -p tcp --dport 22 -j DROP
#
/sbin/iptables -A INPUT -i $ExtBr -p icmp -j DROP
/sbin/iptables -A INPUT -i $ExtBr -p tcp --syn -m limit --limit 1/s -j ACCEPT
/sbin/iptables -A INPUT -i $ExtBr -p tcp --syn -j DROP
/sbin/iptables -A INPUT -i $ExtBr -p tcp --tcp-flags SYN,ACK,FIN,RST RST -m limit --limit 1/s -j ACCEPT
/sbin/iptables -A INPUT -i $ExtBr -p tcp --tcp-flags SYN,ACK,FIN,RST RST -j DROP
#
# NAT rules
/sbin/iptables -t nat -A POSTROUTING -o $tun -j MASQUERADE
/sbin/iptables -t nat -A POSTROUTING -o $ExtBr -p tcp ! -d $Ext_Net -j SNAT --to $IP_Ext:1024-65335 --random
/sbin/iptables -t nat -A POSTROUTING -o $ExtBr -p udp ! -d $Ext_Net -j SNAT --to $IP_Ext:1024-65335 --random
/sbin/iptables -t nat -A POSTROUTING -o $ExtBr ! -d $Ext_Net -j SNAT --to $IP_Ext --random
/sbin/iptables -t nat -A POSTROUTING -s $vir_net ! -d $vir_net -p tcp -o $IntBr -j MASQUERADE --to-ports 1024-65535 --random
/sbin/iptables -t nat -A POSTROUTING -s $vir_net ! -d $vir_net -p udp -o $IntBr -j MASQUERADE --to-ports 1024-65535 --random
/sbin/iptables -t nat -A POSTROUTING -s $vir_net ! -d $vir_net -o $IntBr -j MASQUERADE
/sbin/iptables -t nat -A POSTROUTING -s $lxc_net -j MASQUERADE
/sbin/iptables -t nat -A POSTROUTING -s $VPN -o $IntBr -j MASQUERADE
####### squid.conf: rules complying to --> acl localnet src
/sbin/iptables -t mangle -A PREROUTING -p tcp --dport 3128 ! -s $VPN -j DROP
#_____ SQUID _____
/sbin/iptables -t nat -A PREROUTING -s $DefaultGW -p tcp --dport 80 -j ACCEPT
#_____ TAHOE LAFS _____
/sbin/iptables -t nat -A PREROUTING -p tcp --dport 3456 -j REDIRECT --to-port 80

################  BYPASS RULES ####################
/sbin/iptables -t nat -A BYPASS -d 192.168/16,172.16/16 -j ACCEPT # or any remote LAN routed by vpn routing rules
/sbin/iptables -t nat -A BYPASS -d $safe_pub_addr -j ACCEPT
/sbin/iptables -t nat -A BYPASS -p udp --dport 1194 -d $ovpn_server1 -j ACCEPT
/sbin/iptables -t nat -A BYPASS -p udp --dport 1194 -d $ovpn_server2 -j ACCEPT
###########################################################

############### Load Mac Address filter ###################
for i in `/usr/bin/find /usr/local/etc/anon/ -maxdepth 1 -name *.fw -type f -print`; do . $i; done
deep_PC
deep_laptop
deep_tablet
deep_smartphone
}

firewall
