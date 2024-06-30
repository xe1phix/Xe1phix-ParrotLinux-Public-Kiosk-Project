#!/bin/bash
echo ' (pre) script declarations'
IP6TABLES='/sbin/ip6tables'
IP4TABLES='/sbin/iptables'
LAN_IF='ens+'
TUN_IF='tun+'
INNER_GLOBAL_UNICAST='2001:0db8:ffff:ffff::/48'
INNER_IPV4_UNICAST='10.8.0.0/24'
IPV4_LINK_LOCAL='169.254.0.0/16' #RFC 3927
IPV6_LINK_LOCAL='fe80::/10' #RFC 4291
IPV6_MULTICAST='ff00::/8' #RFC 4291
IPV4_MULTICAST='224.0.0.0/4' #RFC 5771
IPV6_ULA='fc00::/7' #RFC 4193
echo '-------------------------------------'
echo 'site-specific variables (change me)'
echo '-------------------------------------'
echo ' LAN_IF='$LAN_IF
echo ' TUN_IF='$TUN_IF
echo ' INNER_GLOBAL_UNICAST='$INNER_GLOBAL_UNICAST
echo ' INNER_IPV4_UNICAST='$INNER_IPV4_UNICAST

echo '-------------------------------------'
echo 'ipv4'
echo '-------------------------------------'

echo ' cleanup'
$IP4TABLES -t mangle -F
$IP4TABLES -t mangle -X
$IP4TABLES -t nat -F
$IP4TABLES -t nat -X
$IP4TABLES -F
$IP4TABLES -X

# chains

# portscan log and drop
$IP4TABLES -N PORTSCANLOG
$IP4TABLES -A PORTSCANLOG -m recent --name PORTSCAN --set -j LOG --log-prefix "iptables[PORTSCAN]: "
$IP4TABLES -A PORTSCANLOG -j DROP

# ssh brute force attack prevention
$IP4TABLES -N SSHBRUTE
# permits 10 new connections within 5 minutes from a single host then drops 
$IP4TABLES -A SSHBRUTE -m recent --name SSH --set --rsource
$IP4TABLES -A SSHBRUTE -m recent --name SSH --update --seconds 300 --hitcount 10 --rsource --rttl -m limit --limit 1/sec --limit-burst 100 -j LOG --log-prefix "iptables[SSH_BRUTE_FORCE_DROP]: "
$IP4TABLES -A SSHBRUTE -m recent --name SSH --update --seconds 300 --hitcount 10 --rsource --rttl -j DROP
$IP4TABLES -A SSHBRUTE -j ACCEPT

# icmpv4 ping flood attack prevention
# permits 5 pings within 1 second from a single host then drops
$IP4TABLES -N ICMP_FLOOD
$IP4TABLES -A ICMP_FLOOD -m recent --name ICMPv4 --set --rsource
$IP4TABLES -A ICMP_FLOOD -m recent --name ICMPv4 --update --seconds 1 --hitcount 10 --rsource --rttl -m limit --limit 1/sec --limit-burst 10 -j LOG --log-prefix "iptables[ICMP_FLOOD_DROP]: "
$IP4TABLES -A ICMP_FLOOD -m recent --name ICMPv4 --update --seconds 1 --hitcount 10 --rsource --rttl -j DROP
$IP4TABLES -A ICMP_FLOOD -j ACCEPT

# icmpv4 forward filter
$IP4TABLES -N ICMP_FORWARD
$IP4TABLES -A ICMP_FORWARD -p icmp -m icmp --icmp-type echo-request -d $INNER_IPV4_UNICAST -j ICMP_FLOOD
$IP4TABLES -A ICMP_FORWARD -p icmp -m icmp --icmp-type echo-request -s $INNER_IPV4_UNICAST -j ACCEPT
$IP4TABLES -A ICMP_FORWARD -p icmp -m icmp --icmp-type echo-reply -d $INNER_IPV4_UNICAST -m state --state ESTABLISHED,RELATED -j ACCEPT  #rfc 792
$IP4TABLES -A ICMP_FORWARD -p icmp -m icmp --icmp-type echo-reply -s $INNER_IPV4_UNICAST -j ACCEPT
$IP4TABLES -A ICMP_FORWARD -p icmp -m icmp --icmp-type destination-unreachable -j ACCEPT
$IP4TABLES -A ICMP_FORWARD -p icmp -m icmp --icmp-type source-quench -j ACCEPT
$IP4TABLES -A ICMP_FORWARD -p icmp -m icmp --icmp-type time-exceeded -d $INNER_IPV4_UNICAST -m state --state ESTABLISHED,RELATED -j ACCEPT
$IP4TABLES -A ICMP_FORWARD -p icmp -m icmp --icmp-type time-exceeded -s $INNER_IPV4_UNICAST -j ACCEPT
$IP4TABLES -A ICMP_FORWARD -p icmp -m icmp --icmp-type parameter-problem -j ACCEPT
#$IP4TABLES -A ICMP_FORWARD -p icmp -m icmp --icmp-type address-mask-request -j DROP
#$IP4TABLES -A ICMP_FORWARD -p icmp -m icmp --icmp-type timestamp-request -j DROP
$IP4TABLES -A ICMP_FORWARD -m limit --limit 1/second --limit-burst 100 -j LOG --log-prefix "iptables[ICMP_FORWARD_DROP]: "
$IP4TABLES -A ICMP_FORWARD -j DROP

# icmpv4 input filter
$IP4TABLES -N ICMP_INPUT
$IP4TABLES -A ICMP_INPUT -p icmp -m icmp --icmp-type echo-request -j ICMP_FLOOD
$IP4TABLES -A ICMP_INPUT -p icmp -m icmp --icmp-type echo-reply -m state --state ESTABLISHED,RELATED -j ACCEPT
$IP4TABLES -A ICMP_INPUT -p icmp -m icmp --icmp-type echo-reply -m state --state ESTABLISHED,RELATED -j ACCEPT
$IP4TABLES -A ICMP_INPUT -p icmp -m icmp --icmp-type destination-unreachable -j ACCEPT
$IP4TABLES -A ICMP_INPUT -p icmp -m icmp --icmp-type source-quench -j ACCEPT
$IP4TABLES -A ICMP_INPUT -p icmp -m icmp --icmp-type time-exceeded -m state --state ESTABLISHED,RELATED -j ACCEPT
$IP4TABLES -A ICMP_INPUT -p icmp -m icmp --icmp-type parameter-problem -j ACCEPT
#$IP4TABLES -A ICMP_INPUT -p icmp -m icmp --icmp-type address-mask-request -j DROP
#$IP4TABLES -A ICMP_INPUT -p icmp -m icmp --icmp-type timestamp-request -j DROP
$IP4TABLES -A ICMP_INPUT -m limit --limit 1/second --limit-burst 100 -j LOG --log-prefix "iptables[ICMP_INPUT_DROP]: "
$IP4TABLES -A ICMP_INPUT -j DROP

echo ' (harden) deny any tcp packet that does not start a connection with a syn flag'
$IP4TABLES -A INPUT -p tcp ! --syn -m state --state NEW -j DROP
$IP4TABLES -A FORWARD -p tcp ! --syn -m state --state NEW -j DROP

echo ' (harden) deny invalid unidentified traffic'
$IP4TABLES -A INPUT -m state --state INVALID -j DROP
$IP4TABLES -A FORWARD -m state --state INVALID -j DROP

echo ' (harden) deny invalid packets'
$IP4TABLES -A INPUT -p tcp -m tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG NONE -j DROP
$IP4TABLES -A INPUT -p tcp -m tcp --tcp-flags SYN,FIN SYN,FIN -j DROP
$IP4TABLES -A INPUT -p tcp -m tcp --tcp-flags SYN,RST SYN,RST -j DROP
$IP4TABLES -A INPUT -p tcp -m tcp --tcp-flags FIN,RST FIN,RST -j DROP
$IP4TABLES -A INPUT -p tcp -m tcp --tcp-flags ACK,FIN FIN -j DROP
$IP4TABLES -A INPUT -p tcp -m tcp --tcp-flags ACK,URG URG -j DROP
$IP4TABLES -A FORWARD -p tcp -m tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG NONE -j DROP
$IP4TABLES -A FORWARD -p tcp -m tcp --tcp-flags SYN,FIN SYN,FIN -j DROP
$IP4TABLES -A FORWARD -p tcp -m tcp --tcp-flags SYN,RST SYN,RST -j DROP
$IP4TABLES -A FORWARD -p tcp -m tcp --tcp-flags FIN,RST FIN,RST -j DROP
$IP4TABLES -A FORWARD -p tcp -m tcp --tcp-flags ACK,FIN FIN -j DROP
$IP4TABLES -A FORWARD -p tcp -m tcp --tcp-flags ACK,URG URG -j DROP

echo ' (harden) deny portscan'
# blocks detected port scanners for 24 hours
$IP4TABLES -A INPUT -m recent --name PORTSCAN --rcheck --seconds 86400 -j DROP
$IP4TABLES -A FORWARD -m recent --name PORTSCAN --rcheck --seconds 86400 -j DROP
$IP4TABLES -A INPUT -m recent --name PORTSCAN --remove
$IP4TABLES -A FORWARD -m recent --name PORTSCAN --remove
$IP4TABLES -A INPUT -i $LAN_IF -p udp -m multiport --dports 23,25 -j PORTSCANLOG
$IP4TABLES -A INPUT -i $LAN_IF -p tcp -m multiport --dports 23,25 -j PORTSCANLOG
$IP4TABLES -A FORWARD -i $LAN_IF -p udp -m multiport --dports 23,25 -j PORTSCANLOG
$IP4TABLES -A FORWARD -i $LAN_IF -p tcp -m multiport --dports 23,25 -j PORTSCANLOG

echo ' (harden) deny smurf rst flood attack'
$IP4TABLES -A INPUT -p tcp -m tcp --tcp-flags RST RST -m limit --limit 2/sec --limit-burst 2 -j ACCEPT
$IP4TABLES -A FORWARD -p tcp -m tcp --tcp-flags RST RST -m limit --limit 2/sec --limit-burst 2 -j ACCEPT

echo ' (harden) deny spoof/martian/bogon (rfc 1918, rfc 5735, etc)'
$IP4TABLES -A INPUT -i $LAN_IF -s 10.0.0.0/8 -j DROP
$IP4TABLES -A INPUT -i $LAN_IF -s 172.16.0.0/12 -j DROP
#$IP4TABLES -A INPUT -i $LAN_IF -s 192.168.0.0/16 -j DROP
$IP4TABLES -A INPUT -i $LAN_IF -s $IPV4_LINK_LOCAL -j DROP
$IP4TABLES -A INPUT -i $LAN_IF -s 0.0.0.0/8 -j DROP
$IP4TABLES -A INPUT -i $LAN_IF -s 127.0.0.0/8 -j DROP
$IP4TABLES -A INPUT -i $LAN_IF -s $IPV4_MULTICAST -j DROP
$IP4TABLES -A INPUT -i $LAN_IF -s 240.0.0.0/4 -j DROP
$IP4TABLES -A FORWARD -i $LAN_IF -s 10.0.0.0/8 -j DROP
$IP4TABLES -A FORWARD -i $LAN_IF -s 172.16.0.0/12 -j DROP
#$IP4TABLES -A FORWARD -i $LAN_IF -s 192.168.0.0/16 -j DROP
$IP4TABLES -A FORWARD -i $LAN_IF -s $IPV4_LINK_LOCAL -j DROP
$IP4TABLES -A FORWARD -i $LAN_IF -s 0.0.0.0/8 -j DROP
$IP4TABLES -A FORWARD -i $LAN_IF -s 127.0.0.0/8 -j DROP
$IP4TABLES -A FORWARD -i $LAN_IF -s $IPV4_MULTICAST -j DROP
$IP4TABLES -A FORWARD -i $LAN_IF -s 240.0.0.0/4 -j DROP

echo ' (harden) reject ident/auth'
$IP4TABLES -A INPUT -p tcp --dport 113 -m state --state NEW -j REJECT --reject-with tcp-reset
$IP4TABLES -A FORWARD -p tcp --dport 113 -m state --state NEW -j REJECT --reject-with tcp-reset

echo ' (harden) allow icmp'
$IP4TABLES -A INPUT -p icmp -j ICMP_INPUT
$IP4TABLES -A FORWARD -p icmp -j ICMP_FORWARD

echo ' allow existing connections'
$IP4TABLES -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
$IP4TABLES -A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT

echo ' allow traffic from loopback interface'
$IP4TABLES -A INPUT -i lo -s 127.0.0.1/8 -j ACCEPT

echo ' (harden) restrict dns port 53, dns will be handled by dnscrypt on udp443'
# //note: handled by general allow tun rule
#$IP4TABLES -A INPUT -i $TUN_IF -p udp --dport 53 -j ACCEPT
$IP4TABLES -A OUTPUT -o $LAN_IF -p udp --dport 53 -j REJECT --reject-with icmp-port-unreachable
$IP4TABLES -A FORWARD -i $TUN_IF -o $LAN_IF -p udp --dport 53 -j REJECT --reject-with icmp-port-unreachable

echo ' (harden) filter ipv4 multicast/broadcast'
# allow dhcp
$IP4TABLES -A INPUT -i $TUN_IF -m addrtype --dst-type BROADCAST -p udp --sport 68 --dport 67 -j ACCEPT
$IP4TABLES -A INPUT -i $LAN_IF -m addrtype --dst-type BROADCAST -p udp --sport 67 --dport 68 -j ACCEPT
# deny other types (keep anycast if 6to4 is needed)
$IP4TABLES -A INPUT -m addrtype --dst-type MULTICAST -j DROP
$IP4TABLES -A INPUT -m addrtype --dst-type BROADCAST -j DROP
$IP4TABLES -A INPUT -m addrtype --dst-type ANYCAST -j DROP
$IP4TABLES -A INPUT -m addrtype --src-type MULTICAST -j DROP
$IP4TABLES -A INPUT -m addrtype --src-type BROADCAST -j LOG --log-prefix "iptables[BROADCAST_DROP]: "
$IP4TABLES -A INPUT -m addrtype --src-type BROADCAST -j DROP
$IP4TABLES -A INPUT -m addrtype --src-type ANYCAST -j DROP
$IP4TABLES -A FORWARD -m addrtype --dst-type MULTICAST -j DROP
$IP4TABLES -A FORWARD -m addrtype --dst-type BROADCAST -j DROP
$IP4TABLES -A FORWARD -m addrtype --dst-type ANYCAST -j DROP
$IP4TABLES -A FORWARD -m addrtype --src-type MULTICAST -j DROP
$IP4TABLES -A FORWARD -m addrtype --src-type BROADCAST -j DROP
$IP4TABLES -A FORWARD -m addrtype --src-type ANYCAST -j DROP

echo ' (harden) allow ssh'
$IP4TABLES -A INPUT -p tcp --dport 22 -m state --state NEW -j SSHBRUTE
#$IP4TABLES -A FORWARD -p tcp --dport 22 -m state --state NEW -j SSHBRUTE

echo ' (nat) allow OpenVPN'
$IP4TABLES -A INPUT -i $LAN_IF -p udp --dport 995 -j ACCEPT
$IP4TABLES -A INPUT -i $TUN_IF -j ACCEPT
$IP4TABLES -A FORWARD -i $TUN_IF -o $LAN_IF -s $INNER_IPV4_UNICAST -m state --state NEW -j ACCEPT
$IP4TABLES -t nat -A POSTROUTING -o $LAN_IF -s $INNER_IPV4_UNICAST -j MASQUERADE

echo ' set default policies'
$IP4TABLES -P INPUT DROP
$IP4TABLES -P FORWARD DROP
$IP4TABLES -P OUTPUT ACCEPT
$IP4TABLES -t nat -P PREROUTING ACCEPT
$IP4TABLES -t nat -P POSTROUTING ACCEPT
$IP4TABLES -t nat -P OUTPUT ACCEPT

echo '-------------------------------------'
echo 'ipv6'
echo '-------------------------------------'

echo ' cleanup'
$IP6TABLES -t mangle -F
$IP6TABLES -t mangle -X
$IP6TABLES -t nat -F
$IP6TABLES -t nat -X
$IP6TABLES -F
$IP6TABLES -X

# chains

# portscan log and drop
$IP6TABLES -N PORTSCANLOG6
$IP6TABLES -A PORTSCANLOG6 -m recent --name PORTSCAN6 --set -j LOG --log-prefix "iptables[PORTSCAN]: "
$IP6TABLES -A PORTSCANLOG6 -j DROP

# ssh brute force attack prevention
$IP6TABLES -N SSHBRUTE6
# permits 10 new connections within 5 minutes from a single host then drops 
$IP6TABLES -A SSHBRUTE6 -m recent --name SSH6 --set --rsource
$IP6TABLES -A SSHBRUTE6 -m recent --name SSH6 --update --seconds 300 --hitcount 10 --rsource --rttl -m limit --limit 1/sec --limit-burst 100 -j LOG --log-prefix "ip6tables[SSH6_BRUTE_FORCE_DROP]: "
$IP6TABLES -A SSHBRUTE6 -m recent --name SSH6 --update --seconds 300 --hitcount 10 --rsource --rttl -j DROP
$IP6TABLES -A SSHBRUTE6 -j ACCEPT

# filter ipv6 multicast router messages
$IP6TABLES -N MULTICAST_ROUTER_MSG
$IP6TABLES -A MULTICAST_ROUTER_MSG -p ipv6-icmp --icmpv6-type 151 -s $IPV6_LINK_LOCAL -d ff02::6A -m hl --hl-eq 1 -j ACCEPT #multicast router advertisement
$IP6TABLES -A MULTICAST_ROUTER_MSG -p ipv6-icmp --icmpv6-type 152 -s $IPV6_LINK_LOCAL -d ff02::2 -m hl --hl-eq 1 -j ACCEPT #multicast router solicitation
$IP6TABLES -A MULTICAST_ROUTER_MSG -p ipv6-icmp --icmpv6-type 153 -s $IPV6_LINK_LOCAL -d ff02::6A -m hl --hl-eq 1 -j ACCEPT #multicast router termination
# log
$IP6TABLES -A MULTICAST_ROUTER_MSG -m limit --limit 1/second --limit-burst 100 -j LOG --log-prefix "ip6tables[MULTICAST_ROUTER_DROP]: "
$IP6TABLES -A MULTICAST_ROUTER_MSG -j DROP

# icmpv6 ping flood attack prevention
# permits 5 pings within 1 second from a single host then drops
$IP6TABLES -N ICMPV6_FLOOD
$IP6TABLES -A ICMPV6_FLOOD -m recent --name ICMPv6 --set --rsource
$IP6TABLES -A ICMPV6_FLOOD -m recent --name ICMPv6 --update --seconds 1 --hitcount 10 --rsource --rttl -m limit --limit 1/sec --limit-burst 10 -j LOG --log-prefix "ip6tables[ICMPV6_FLOOD_DROP]: "
$IP6TABLES -A ICMPV6_FLOOD -m recent --name ICMPv6 --update --seconds 1 --hitcount 10 --rsource --rttl -j DROP
$IP6TABLES -A ICMPV6_FLOOD -j ACCEPT

# icmpv6 forward filter
$IP6TABLES -N ICMPV6_FORWARD
# rfc 4890 section 4.3.1
$IP6TABLES -A ICMPV6_FORWARD -p ipv6-icmp --icmpv6-type echo-request -d $INNER_GLOBAL_UNICAST -j ICMPV6_FLOOD #128
$IP6TABLES -A ICMPV6_FORWARD -p ipv6-icmp --icmpv6-type echo-request -s $INNER_GLOBAL_UNICAST -j ACCEPT #128
$IP6TABLES -A ICMPV6_FORWARD -p ipv6-icmp -m hl --hl-eq 1 -j DROP 
$IP6TABLES -A ICMPV6_FORWARD -p ipv6-icmp --icmpv6-type echo-reply -d $INNER_GLOBAL_UNICAST -m state --state ESTABLISHED,RELATED -j ACCEPT #129
$IP6TABLES -A ICMPV6_FORWARD -p ipv6-icmp --icmpv6-type echo-reply -m addrtype --dst-type MULTICAST -j DROP #129
$IP6TABLES -A ICMPV6_FORWARD -p ipv6-icmp --icmpv6-type echo-reply -s $INNER_GLOBAL_UNICAST -j ACCEPT #129
$IP6TABLES -A ICMPV6_FORWARD -p ipv6-icmp --icmpv6-type destination-unreachable -d $INNER_GLOBAL_UNICAST -m state --state ESTABLISHED,RELATED -j ACCEPT #1
$IP6TABLES -A ICMPV6_FORWARD -p ipv6-icmp --icmpv6-type destination-unreachable -s $INNER_GLOBAL_UNICAST -j ACCEPT #1
$IP6TABLES -A ICMPV6_FORWARD -p ipv6-icmp --icmpv6-type packet-too-big -d $INNER_GLOBAL_UNICAST -m state --state ESTABLISHED,RELATED -j ACCEPT #2
$IP6TABLES -A ICMPV6_FORWARD -p ipv6-icmp --icmpv6-type packet-too-big -s $INNER_GLOBAL_UNICAST -j ACCEPT #2
$IP6TABLES -A ICMPV6_FORWARD -p ipv6-icmp --icmpv6-type ttl-zero-during-transit -d $INNER_GLOBAL_UNICAST -m state --state ESTABLISHED,RELATED -j ACCEPT #3 time-exceeded code 0
$IP6TABLES -A ICMPV6_FORWARD -p ipv6-icmp --icmpv6-type ttl-zero-during-transit -s $INNER_GLOBAL_UNICAST -j ACCEPT #3 time-exceeded code 0
$IP6TABLES -A ICMPV6_FORWARD -p ipv6-icmp --icmpv6-type unknown-header-type -d $INNER_GLOBAL_UNICAST -m state --state ESTABLISHED,RELATED -j ACCEPT #4 parameter-problem code 1
$IP6TABLES -A ICMPV6_FORWARD -p ipv6-icmp --icmpv6-type unknown-header-type -s $INNER_GLOBAL_UNICAST -j ACCEPT #4 parameter-problem code 1
$IP6TABLES -A ICMPV6_FORWARD -p ipv6-icmp --icmpv6-type unknown-option -d $INNER_GLOBAL_UNICAST -m state --state ESTABLISHED,RELATED -j ACCEPT #4 parameter-problem code 2
$IP6TABLES -A ICMPV6_FORWARD -p ipv6-icmp --icmpv6-type unknown-option -s $INNER_GLOBAL_UNICAST -j ACCEPT #4 parameter-problem code 2
# rfc 4890 section 4.3.2
$IP6TABLES -A ICMPV6_FORWARD -p ipv6-icmp --icmpv6-type ttl-zero-during-reassembly -d $INNER_GLOBAL_UNICAST -m state --state ESTABLISHED,RELATED -j ACCEPT #3 time-exceeded code 1
$IP6TABLES -A ICMPV6_FORWARD -p ipv6-icmp --icmpv6-type ttl-zero-during-reassembly -s $INNER_GLOBAL_UNICAST -j ACCEPT #3 time-exceeded code 1
$IP6TABLES -A ICMPV6_FORWARD -p ipv6-icmp --icmpv6-type bad-header -j ACCEPT #4 parameter-problem code 0
#$IP6TABLES -A ICMPV6_FORWARD -p ipv6-icmp --icmpv6-type 144 -j DROP #Home Agent address discovery request
#$IP6TABLES -A ICMPV6_FORWARD -p ipv6-icmp --icmpv6-type 145 -j DROP #Home Agent address discovery reply
#$IP6TABLES -A ICMPV6_FORWARD -p ipv6-icmp --icmpv6-type 146 -j DROP #Mobile prefix solicitation
#$IP6TABLES -A ICMPV6_FORWARD -p ipv6-icmp --icmpv6-type 147 -j DROP #Mobile prefix advertisement
# rfc 4890 section 4.3.3
#$IP6TABLES -A ICMPV6_FORWARD -p ipv6-icmp --icmpv6-type router-solicitation -m hl --hl-eq 255 -j DROP #133
#$IP6TABLES -A ICMPV6_FORWARD -p ipv6-icmp --icmpv6-type router-advertisement -m hl --hl-eq 255 -j DROP #134
#$IP6TABLES -A ICMPV6_FORWARD -p ipv6-icmp --icmpv6-type neighbour-solicitation -m hl --hl-eq 255 -j DROP #135
#$IP6TABLES -A ICMPV6_FORWARD -p ipv6-icmp --icmpv6-type neighbour-advertisement -m hl --hl-eq 255 -j DROP #136
#$IP6TABLES -A ICMPV6_FORWARD -p ipv6-icmp --icmpv6-type redirect -m hl --hl-eq 255 -j DROP #137
#$IP6TABLES -A ICMPV6_FORWARD -p ipv6-icmp --icmpv6-type 141 -m hl --hl-eq 255 -j DROP #inverse neighbor discovery solicitation
#$IP6TABLES -A ICMPV6_FORWARD -p ipv6-icmp --icmpv6-type 142 -m hl --hl-eq 255 -j DROP #inverse neighbor discovery advertisement
#$IP6TABLES -A ICMPV6_FORWARD -p ipv6-icmp --icmpv6-type 130 -s $IPV6_LINK_LOCAL -j DROP #MLDv1/v2: listener query
#$IP6TABLES -A ICMPV6_FORWARD -p ipv6-icmp --icmpv6-type 131 -s $IPV6_LINK_LOCAL -j DROP #MLDv1: listener report
#$IP6TABLES -A ICMPV6_FORWARD -p ipv6-icmp --icmpv6-type 132 -s $IPV6_LINK_LOCAL -j DROP #MLDv1: listener done
#$IP6TABLES -A ICMPV6_FORWARD -p ipv6-icmp --icmpv6-type 143 -s $IPV6_LINK_LOCAL -j DROP #MLDv2: listener report
#$IP6TABLES -A ICMPV6_FORWARD -p ipv6-icmp --icmpv6-type 148 -m hl --hl-eq 255 -j DROP #SEND: certificate path solicitation
#$IP6TABLES -A ICMPV6_FORWARD -p ipv6-icmp --icmpv6-type 149 -m hl --hl-eq 255 -j DROP #SEND: certificate path advertisement
#$IP6TABLES -A ICMPV6_FORWARD -p ipv6-icmp -m hl --hl-eq 1 -j MULTICAST_ROUTER_MSG
# rfc 4890 section 4.3.4
#$IP6TABLES -A ICMPV6_FORWARD -p ipv6-icmp --icmpv6-type 150 -j DROP #Seamoby Experimental
#IANA Unallocated Error messages (Types 5-99 inclusive and 102-126 inclusive)
#IANA Unallocated Informational messages (Types 154-199 inclusive and 202-254 inclusive)
# rfc 4890 section 4.3.5
#$IP6TABLES -A ICMPV6_FORWARD -p ipv6-icmp --icmpv6-type 139 -j DROP #node information query
#$IP6TABLES -A ICMPV6_FORWARD -p ipv6-icmp --icmpv6-type 140 -j DROP #node information reply
#$IP6TABLES -A ICMPV6_FORWARD -p ipv6-icmp --icmpv6-type 138 -j DROP #router renumbering
#Messages with types in the experimental allocations (Types 100, 101, 200, and 201)
#$IP6TABLES -A ICMPV6_FORWARD -p ipv6-icmp --icmpv6-type 127 -j DROP #extension type numbers
#$IP6TABLES -A ICMPV6_FORWARD -p ipv6-icmp --icmpv6-type 255 -j DROP #extension type numbers
# log
$IP6TABLES -A ICMPV6_FORWARD -m limit --limit 1/sec --limit-burst 100 -j LOG --log-prefix "ip6tables[ICMPV6_FORWARD_DROP]: "
$IP6TABLES -A ICMPV6_FORWARD -j DROP

# icmpv6 input filter
$IP6TABLES -N ICMPV6_INPUT
# rfc 4890 section 4.4.1
$IP6TABLES -A ICMPV6_INPUT -p ipv6-icmp --icmpv6-type echo-request -j ICMPV6_FLOOD #128
$IP6TABLES -A ICMPV6_INPUT -p ipv6-icmp -m hl --hl-eq 1 -j MULTICAST_ROUTER_MSG
$IP6TABLES -A ICMPV6_INPUT -p ipv6-icmp --icmpv6-type echo-reply -m state --state ESTABLISHED,RELATED -j ACCEPT #129
$IP6TABLES -A ICMPV6_INPUT -p ipv6-icmp --icmpv6-type destination-unreachable -m state --state ESTABLISHED,RELATED -j ACCEPT #1
$IP6TABLES -A ICMPV6_INPUT -p ipv6-icmp --icmpv6-type packet-too-big -m state --state ESTABLISHED,RELATED -j ACCEPT #2
$IP6TABLES -A ICMPV6_INPUT -p ipv6-icmp --icmpv6-type ttl-zero-during-transit -m state --state ESTABLISHED,RELATED -j ACCEPT #3 time-exceeded code 0
$IP6TABLES -A ICMPV6_INPUT -p ipv6-icmp --icmpv6-type unknown-header-type -m state --state ESTABLISHED,RELATED -j ACCEPT #4 parameter-problem code 1
$IP6TABLES -A ICMPV6_INPUT -p ipv6-icmp --icmpv6-type unknown-option -m state --state ESTABLISHED,RELATED -j ACCEPT #4 parameter-problem code 2
$IP6TABLES -A ICMPV6_INPUT -p ipv6-icmp --icmpv6-type router-solicitation -m hl --hl-eq 255 -m limit --limit 10/sec --limit-burst 5 -j ACCEPT #133
$IP6TABLES -A ICMPV6_INPUT -p ipv6-icmp --icmpv6-type router-advertisement -m hl --hl-eq 255 -m limit --limit 10/sec --limit-burst 5 -j ACCEPT #134
$IP6TABLES -A ICMPV6_INPUT -p ipv6-icmp --icmpv6-type neighbour-solicitation -m hl --hl-eq 255 -m limit --limit 30/sec --limit-burst 5 -j ACCEPT #135
$IP6TABLES -A ICMPV6_INPUT -p ipv6-icmp --icmpv6-type neighbour-advertisement -m hl --hl-eq 255 -m limit --limit 30/sec --limit-burst 5 -j ACCEPT #136
$IP6TABLES -A ICMPV6_INPUT -p ipv6-icmp --icmpv6-type 141 -m hl --hl-eq 255 -m limit --limit 30/sec --limit-burst 5 -j ACCEPT #inverse neighbor discovery solicitation
$IP6TABLES -A ICMPV6_INPUT -p ipv6-icmp --icmpv6-type 142 -m hl --hl-eq 255 -m limit --limit 30/sec --limit-burst 5 -j ACCEPT #inverse neighbor discovery advertisement
$IP6TABLES -A ICMPV6_INPUT -p ipv6-icmp --icmpv6-type 130 -s $IPV6_LINK_LOCAL -j ACCEPT #MLDv1/v2: listener query
$IP6TABLES -A ICMPV6_INPUT -p ipv6-icmp --icmpv6-type 131 -s $IPV6_LINK_LOCAL -j ACCEPT #MLDv1: listener report
$IP6TABLES -A ICMPV6_INPUT -p ipv6-icmp --icmpv6-type 132 -s $IPV6_LINK_LOCAL -j ACCEPT #MLDv1: listener done
$IP6TABLES -A ICMPV6_INPUT -p ipv6-icmp --icmpv6-type 143 -s $IPV6_LINK_LOCAL -j ACCEPT #MLDv2: listener report
$IP6TABLES -A ICMPV6_INPUT -p ipv6-icmp --icmpv6-type 148 -m hl --hl-eq 255 -j ACCEPT #SEND: certificate path solicitation
$IP6TABLES -A ICMPV6_INPUT -p ipv6-icmp --icmpv6-type 149 -m hl --hl-eq 255 -j ACCEPT #SEND: certificate path advertisement
# rfc 4890 section 4.4.2
$IP6TABLES -A ICMPV6_INPUT -p ipv6-icmp --icmpv6-type ttl-zero-during-reassembly -m state --state ESTABLISHED,RELATED -j ACCEPT #3 time-exceeded code 1
$IP6TABLES -A ICMPV6_INPUT -p ipv6-icmp --icmpv6-type bad-header -j ACCEPT #4 parameter-problem code 0
# rfc 4890 section 4.4.3
#$IP6TABLES -A ICMPV6_INPUT -p ipv6-icmp --icmpv6-type 138 -j DROP #router renumbering
#$IP6TABLES -A ICMPV6_INPUT -p ipv6-icmp --icmpv6-type 144 -j DROP #Home Agent address discovery request
#$IP6TABLES -A ICMPV6_INPUT -p ipv6-icmp --icmpv6-type 145 -j DROP #Home Agent address discovery reply
#$IP6TABLES -A ICMPV6_INPUT -p ipv6-icmp --icmpv6-type 146 -j DROP #Mobile prefix solicitation
#$IP6TABLES -A ICMPV6_INPUT -p ipv6-icmp --icmpv6-type 147 -j DROP #Mobile prefix advertisement
#$IP6TABLES -A ICMPV6_INPUT -p ipv6-icmp --icmpv6-type 150 -j DROP #Seamoby Experimental
# rfc 4890 section 4.4.4
#$IP6TABLES -A ICMPV6_INPUT -p ipv6-icmp --icmpv6-type redirect -m hl --hl-eq 255 -j DROP #137
#$IP6TABLES -A ICMPV6_INPUT -p ipv6-icmp --icmpv6-type 139 -j DROP #node information query
#$IP6TABLES -A ICMPV6_INPUT -p ipv6-icmp --icmpv6-type 140 -j DROP #node information reply
#IANA Unallocated Error messages (Types 5-99 inclusive and 102-126 inclusive)
# rfc 4890 section 4.4.5
#Messages with types in the experimental allocations (Types 100, 101, 200, and 201)
#$IP6TABLES -A ICMPV6_INPUT -p ipv6-icmp --icmpv6-type 127 -j DROP #extension type numbers
#$IP6TABLES -A ICMPV6_INPUT -p ipv6-icmp --icmpv6-type 255 -j DROP #extension type numbers
#IANA Unallocated Informational messages (Types 154-199 inclusive and 202-254 inclusive)
# log
$IP6TABLES -A ICMPV6_INPUT -m limit --limit 1/sec --limit-burst 100 -j LOG --log-prefix "ip6tables[ICMPV6_INPUT_DROP]: "
$IP6TABLES -A ICMPV6_INPUT -j DROP

echo ' (harden) deny any tcp packet that does not start a connection with a syn flag'
$IP6TABLES -A INPUT -p tcp ! --syn -m state --state NEW -j DROP
$IP6TABLES -A FORWARD -p tcp ! --syn -m state --state NEW -j DROP

echo ' (harden) deny invalid unidentified traffic'
$IP6TABLES -A INPUT -m state --state INVALID -j DROP
$IP6TABLES -A FORWARD -m state --state INVALID -j DROP

echo ' (harden) deny invalid packets'
$IP6TABLES -A INPUT -p tcp -m tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG NONE -j DROP
$IP6TABLES -A INPUT -p tcp -m tcp --tcp-flags SYN,FIN SYN,FIN -j DROP
$IP6TABLES -A INPUT -p tcp -m tcp --tcp-flags SYN,RST SYN,RST -j DROP
$IP6TABLES -A INPUT -p tcp -m tcp --tcp-flags FIN,RST FIN,RST -j DROP
$IP6TABLES -A INPUT -p tcp -m tcp --tcp-flags ACK,FIN FIN -j DROP
$IP6TABLES -A INPUT -p tcp -m tcp --tcp-flags ACK,URG URG -j DROP
$IP6TABLES -A FORWARD -p tcp -m tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG NONE -j DROP
$IP6TABLES -A FORWARD -p tcp -m tcp --tcp-flags SYN,FIN SYN,FIN -j DROP
$IP6TABLES -A FORWARD -p tcp -m tcp --tcp-flags SYN,RST SYN,RST -j DROP
$IP6TABLES -A FORWARD -p tcp -m tcp --tcp-flags FIN,RST FIN,RST -j DROP
$IP6TABLES -A FORWARD -p tcp -m tcp --tcp-flags ACK,FIN FIN -j DROP
$IP6TABLES -A FORWARD -p tcp -m tcp --tcp-flags ACK,URG URG -j DROP

echo ' (harden) deny portscan'
# blocks detected port scanners for 24 hours
$IP6TABLES -A INPUT -m recent --name PORTSCAN6 --rcheck --seconds 86400 -j DROP
$IP6TABLES -A FORWARD -m recent --name PORTSCAN6 --rcheck --seconds 86400 -j DROP
$IP6TABLES -A INPUT -m recent --name PORTSCAN6 --remove
$IP6TABLES -A FORWARD -m recent --name PORTSCAN6 --remove
$IP6TABLES -A INPUT -i $LAN_IF -p udp -m multiport --dports 23,25 -j PORTSCANLOG6
$IP6TABLES -A INPUT -i $LAN_IF -p tcp -m multiport --dports 23,25 -j PORTSCANLOG6
$IP6TABLES -A FORWARD -i $LAN_IF -p udp -m multiport --dports 23,25 -j PORTSCANLOG6
$IP6TABLES -A FORWARD -i $LAN_IF -p tcp -m multiport --dports 23,25 -j PORTSCANLOG6

echo ' (harden) deny smurf attack'
$IP6TABLES -A INPUT -p tcp -m tcp --tcp-flags RST RST -m limit --limit 2/sec --limit-burst 2 -j ACCEPT
$IP6TABLES -A FORWARD -p tcp -m tcp --tcp-flags RST RST -m limit --limit 2/sec --limit-burst 2 -j ACCEPT

echo ' (harden) deny ula/private ipv6 networks (rfc 4193)'
$IP6TABLES -A INPUT -i $LAN_IF -s $IPV6_ULA -j DROP
$IP6TABLES -A FORWARD -i $LAN_IF -s $IPV6_ULA -j DROP

echo ' (harden) drop deprecated routing header type 0 (RH0) (rfc 5095)'
$IP6TABLES -A INPUT -m rt --rt-type 0 -j DROP
$IP6TABLES -A FORWARD -m rt --rt-type 0 -j DROP

echo ' (harden) reject ident/auth'
$IP6TABLES -A INPUT -p tcp --dport 113 -m state --state NEW -j REJECT --reject-with tcp-reset
$IP6TABLES -A FORWARD -p tcp --dport 113 -m state --state NEW -j REJECT --reject-with tcp-reset

echo ' (harden) filter icmpv6'
$IP6TABLES -A INPUT -p icmpv6 -j ICMPV6_INPUT
$IP6TABLES -A FORWARD -p icmpv6 -j ICMPV6_FORWARD

echo ' allow existing connections'
$IP6TABLES -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
$IP6TABLES -A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT

echo ' allow traffic from loopback interface'
$IP6TABLES -A INPUT -i lo -s ::1/128 -j ACCEPT

echo ' (harden) restrict dns port 53, dns will be handled by dnscrypt on udp443'
# //note: handled by general allow tun rule
#$IP6TABLES -A INPUT -i $TUN_IF -p udp --dport 53 -j ACCEPT
$IP6TABLES -A OUTPUT -o $LAN_IF -p udp --dport 53 -j REJECT --reject-with icmp6-port-unreachable
$IP6TABLES -A FORWARD -i $TUN_IF -o $LAN_IF -p udp --dport 53 -j REJECT --reject-with icmp6-port-unreachable

echo ' allow dhcpv6'
$IP6TABLES -A INPUT -i $TUN_IF -p udp -d ff02::1:2 --sport 546 --dport 547 -j ACCEPT
$IP6TABLES -A INPUT -i $LAN_IF -p udp --sport 547 --dport 546 -j ACCEPT

echo ' (harden) allow ssh'
$IP6TABLES -A INPUT -p tcp --dport 22 -m state --state NEW -j SSHBRUTE6
#$IP6TABLES -A FORWARD -p tcp --dport 22 -m state --state NEW -j SSHBRUTE6

echo ' allow OpenVPN'
$IP6TABLES -A INPUT -i $LAN_IF -p udp --dport 995 -j ACCEPT
$IP6TABLES -A INPUT -i $TUN_IF -j ACCEPT
$IP6TABLES -A FORWARD -i $TUN_IF -o $LAN_IF -s $INNER_GLOBAL_UNICAST -m state --state NEW -j ACCEPT

#echo ' allow all link-local'
#$IP6TABLES -A INPUT -s $IPV6_LINK_LOCAL -m hl --hl-eq 255 -j ACCEPT

#echo ' allow all multicast'
#$IP6TABLES -A INPUT -s $IPV6_MULTICAST -j ACCEPT

# prevent dos by filling log files
$IP6TABLES -A INPUT -m limit --limit 1/sec --limit-burst 100 -j LOG --log-prefix "ip6tables[INPUT_DEFAULT_DROP]: "
$IP6TABLES -A FORWARD -m limit --limit 1/sec --limit-burst 100 -j LOG --log-prefix "ip6tables[FWD_DEFAULT_DROP]: "

echo ' set default policies'
$IP6TABLES -P INPUT DROP
$IP6TABLES -P FORWARD DROP
$IP6TABLES -P OUTPUT ACCEPT

echo 'exit'
exit 0