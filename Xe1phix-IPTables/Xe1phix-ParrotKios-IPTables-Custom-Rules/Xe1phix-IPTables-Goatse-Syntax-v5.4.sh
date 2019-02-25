#!/bin/sh
##-========================================-##
##   {+} Xe1phix-IPTables-Syntax-v4.7.sh
##-========================================-##
modprobe ip_conntrack
modprobe ipt_LOG
modprobe ipt_state
modprobe -v nf_log_ipv6 
modprobe -vi nf_log_ipv6 
modprobe -vi ipt_owner
modprobe -vi iptable_security
modprobe -vi ipt_rpfilter

##-=====================================-##
##  [+] Flush + Clear The IPv4 Chains:
##-=====================================-##
/sbin/iptables -F
/sbin/iptables -X
/sbin/iptables -t nat -F
/sbin/iptables -t nat -X
/sbin/iptables -t mangle -F
/sbin/iptables -t mangle -X

##-=====================================-##
##  [+] Flush + Delete The IPv6 Chains:
##-=====================================-##
ip6tables -F
ip6tables -X
ip6tables -t mangle -F
ip6tables -t mangle -X
##-==========================================================================-##
## No Need To Log IPv6 Drops. We're Dropping All of Them!
##-==========================================================================-##
## ip6tables -A INPUT -j LOG --log-prefix "Blocked: IPv6 Input Packets"
## ip6tables -A OUTPUT -j LOG --log-prefix "Blocked: IPv6 Output Packets"
## ip6tables -A FORWARD -j LOG --log-prefix "Blocked: IPv6 Forward Packets"
##-==========================================================================-##
## 
##-=====================================-##
##  [+] Drop/reject all IPv6 Traffic:    ##
##-=====================================-##
/sbin/ip6tables -P INPUT DROP
/sbin/ip6tables -P OUTPUT DROP
/sbin/ip6tables -A OUTPUT -j REJECT
/sbin/ip6tables -P FORWARD DROP
/sbin/ip6tables -A FORWARD -j REJECT
##-===================================================-##
##  [+] Block All IPv6 Packets VIA IPTables As Well:   ##
##-===================================================-##
/sbin/iptables -A INPUT -p ipv6 -j DROP
/sbin/iptables -A OUTPUT -p ipv6 -j DROP
/sbin/iptables -A FORWARD -p ipv6 -j DROP
##-===============================================================-##
##  [+] Drop All Output Packets That Are in An Invalid ctstate:    ##
##-===============================================================-##
/sbin/iptables -A OUTPUT -m conntrack --ctstate INVALID -j LOG --log-prefix "Invalid ctstate: Blocked: " --log-uid
/sbin/iptables -A OUTPUT -m conntrack --ctstate INVALID -j DROP
/sbin/iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
##-===============================================================-##
##  [+] Drop All Input Packets That Are in An Invalid ctstate:     ##
##-===============================================================-##
/sbin/iptables -A INPUT -m state --state INVALID -j LOG --log-prefix "DROP INVALID " --log-ip-options --log-tcp-options
/sbin/iptables -A INPUT -m state --state INVALID -j DROP
/sbin/iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
##-===============================================================-##
##  [+] Drop All Forward Packets That Are in An Invalid ctstate:   ##
##-===============================================================-##
/sbin/iptables -A FORWARD -m state --state INVALID -j LOG --log-prefix "Invalid ctstate" --log-ip-options --log-tcp-options
/sbin/iptables -A FORWARD -m state --state INVALID -j DROP
/sbin/iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT
##-==========================================-##
##  [+] Rules For Traffic With Bad Flags:     ##
##-==========================================-##
/sbin/iptables -A INPUT -p tcp --tcp-flags ALL ALL -j LOG --log-prefix "IPT: All Flags " --log-ip-options --log-tcp-options
/sbin/iptables -A INPUT -p tcp --tcp-flags ALL ALL -j DROP
/sbin/iptables -A INPUT -p tcp --tcp-flags ALL ACK,RST,SYN,FIN -j LOG --log-prefix "IPTables: Bad SF Flag " --log-ip-options --log-tcp-options
/sbin/iptables -A INPUT -p tcp --tcp-flags ALL ACK,RST,SYN,FIN -j DROP
/sbin/iptables -A INPUT -p tcp --tcp-flags SYN,FIN SYN,FIN -j LOG --log-prefix "IPTables: Bad SF Flag " --log-ip-options --log-tcp-options
/sbin/iptables -A INPUT -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP
/sbin/iptables -A INPUT -p tcp --tcp-flags SYN,RST SYN,RST -j LOG --log-prefix "IPT: Bad SR Flag " --log-ip-options --log-tcp-options
/sbin/iptables -A INPUT -p tcp --tcp-flags SYN,RST SYN,RST -j DROP
/sbin/iptables -A INPUT -p tcp --tcp-flags SYN,FIN,PSH SYN,FIN,PSH -j LOG --log-prefix "IPT: Bad SFP Flag " --log-ip-options --log-tcp-options
/sbin/iptables -A INPUT -p tcp --tcp-flags SYN,FIN,PSH SYN,FIN,PSH -j DROP
/sbin/iptables -A INPUT -p tcp --tcp-flags SYN,FIN,RST SYN,FIN,RST -j LOG --log-prefix "IPT: Bad SFR Flag " --log-ip-options --log-tcp-options
/sbin/iptables -A INPUT -p tcp --tcp-flags SYN,FIN,RST SYN,FIN,RST -j DROP
/sbin/iptables -A INPUT -p tcp --tcp-flags SYN,FIN,RST,PSH SYN,FIN,RST,PSH -j LOG --log-prefix "IPT: Bad SFRP Flag " --log-ip-options --log-tcp-options
/sbin/iptables -A INPUT -p tcp --tcp-flags SYN,FIN,RST,PSH SYN,FIN,RST,PSH -j DROP
/sbin/iptables -A INPUT -p tcp --tcp-flags FIN FIN -j LOG --log-prefix "IPT: Bad F Flag " --log-ip-options --log-tcp-options
/sbin/iptables -A INPUT -p tcp --tcp-flags FIN FIN -j DROP
/sbin/iptables -A INPUT -p tcp --tcp-flags ALL NONE -j LOG --log-prefix "IPT: Null Flag " --log-ip-options --log-tcp-options
/sbin/iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP
/sbin/iptables -A INPUT -s 255.0.0.0/8 -j LOG --log-prefix "Spoofed source IP!" --log-ip-options --log-tcp-options
/sbin/iptables -A INPUT -s 255.0.0.0/8 -j DROP
/sbin/iptables -v -L
/sbin/iptables -N check-flags
/sbin/iptables -A check-flags -p tcp --tcp-flags ALL FIN,URG,PSH -m limit --limit 5/minute -j LOG --log-level alert --log-prefix "NMAP-XMAS:"
/sbin/iptables -A check-flags -p tcp --tcp-flags ALL FIN,URG,PSH -j DROP
/sbin/iptables -A check-flags -p tcp --tcp-flags ALL ALL -m limit --limit 5/minute -j LOG --log-level 1 --log-prefix "XMAS:"
/sbin/iptables -A check-flags -p tcp --tcp-flags ALL ALL -j DROP
/sbin/iptables -A check-flags -p tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG -m limit --limit 5/minute -j LOG --log-level 1 --log-prefix "XMAS-PSH:"
/sbin/iptables -A check-flags -p tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG -j DROP
/sbin/iptables -v -L
/sbin/iptables -A check-flags -p tcp --tcp-flags ALL NONE -m limit --limit 5/minute -j LOG --log-level 1 --log-prefix "NULL_SCAN:"
/sbin/iptables -A check-flags -p tcp --tcp-flags ALL NONE -j DROP
/sbin/iptables -A check-flags -p tcp --tcp-flags SYN,RST SYN,RST -m limit --limit 5/minute -j LOG --log-level 5 --log-prefix "SYN/RST:"
/sbin/iptables -A check-flags -p tcp --tcp-flags SYN,RST SYN,RST -j DROP
/sbin/iptables -A check-flags -p tcp --tcp-flags SYN,FIN SYN,FIN -m limit --limit 5/minute -j LOG --log-level 5 --log-prefix "SYN/FIN:"
/sbin/iptables -A check-flags -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP
/sbin/iptables -A INPUT -p sctp --dport 80 -j DROP
/sbin/iptables -A INPUT -p sctp --chunk-types any DATA,INIT -j DROP
/sbin/iptables -v -L
/sbin/iptables -A INPUT -p udp --dport 3478 -j LOG --log-prefix "DROP WebRTC" --log-ip-options --log-tcp-options --log-uid
/sbin/iptables -A INPUT -p udp --dport 3478 -j DROP
/sbin/iptables -A INPUT -p udp --dport 3479 -j LOG --log-prefix "DROP WebRTC" --log-ip-options --log-tcp-options --log-uid
/sbin/iptables -A INPUT -p udp --dport 3479 -j DROP
/sbin/iptables -A INPUT -p tcp --dport 3478 -j LOG --log-prefix "DROP WebRTC" --log-ip-options --log-tcp-options --log-uid
/sbin/iptables -A INPUT -p tcp --dport 3478 -j DROP
/sbin/iptables -A INPUT -p tcp --dport 3479 -j LOG --log-prefix "DROP WebRTC" --log-ip-options --log-tcp-options --log-uid
/sbin/iptables -A INPUT -p tcp --dport 3479 -j DROP
/sbin/iptables -v -L
/sbin/iptables -A OUTPUT -p tcp --dport 80 --syn -m state --state NEW -j ACCEPT
/sbin/iptables -A OUTPUT -p udp --dport 53 -m state --state NEW -j ACCEPT
/sbin/iptables -A OUTPUT -p tcp --dport 53 -m state --state NEW -j ACCEPT
/sbin/iptables -A OUTPUT -p icmp --icmp-type echo-request -j ACCEPT
/sbin/iptables -A OUTPUT -p tcp --dport 443 --syn -m state --state NEW -j ACCEPT
/sbin/iptables -A OUTPUT --out-interface wlan0 -j ACCEPT
/sbin/iptables -A INPUT --in-interface wlan0 -j ACCEPT
/sbin/iptables -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
/sbin/iptables -v -L
/sbin/iptables -A INPUT -p TCP -i wlan0 -s 139.99.96.146 --dport 53 -j ACCEPT
/sbin/iptables -A INPUT -p TCP -i wlan0 -s 37.59.40.15 --dport 53 -j ACCEPT
/sbin/iptables -A INPUT -p TCP -i wlan0 -s 185.121.177.177 --dport 53 -j ACCEPT
/sbin/iptables -A OUTPUT -p TCP -i wlan0 -d 139.99.96.146 --dport 53 -j ACCEPT
/sbin/iptables -A OUTPUT -p TCP -d 139.99.96.146 --dport 53 -j ACCEPT
/sbin/iptables -A OUTPUT -p TCP -d 37.59.40.15 --dport 53 -j ACCEPT
/sbin/iptables -A OUTPUT -p TCP -d 185.121.177.177 --dport 53 -j ACCEPT
/sbin/iptables -A OUTPUT -p udp --dport 53 -m state --state NEW -j ACCEPT
/sbin/iptables -A OUTPUT -p tcp --dport 53 -m state --state NEW -j ACCEPT
/sbin/iptables -A INPUT -p UDP -i wlan0 --dport 67 --sport 68 -j ACCEPT
/sbin/iptables -A INPUT -p tcp -m multiport --dports 135,137,138,139,445,1433,1434 -j LOG --log-prefix "Blocked: Faggot Microsoft Service" --log-ip-options --log-tcp-options
/sbin/iptables -A INPUT -p tcp -m multiport --dports 135,137,138,139,445,1433,1434 -j DROP
/sbin/iptables -A INPUT -p udp -m multiport --dports 135,137,138,139,445,1433,1434 -j LOG --log-prefix "Blocked: Faggot Microsoft Service" --log-ip-options --log-tcp-options
/sbin/iptables -A INPUT -p udp -m multiport --dports 135,137,138,139,445,1433,1434 -j DROP
/sbin/iptables -A INPUT -p icmp --icmp-type echo-request -m length --length 86:0xffff -j LOG --log-prefix "Ping Packet Size Larger Than 85 Bytes: " --log-level 7
/sbin/iptables -A INPUT -p icmp --icmp-type echo-request -m length --length 86:0xffff -j DROP
##-=================================-##
##   [+] Save The IPTables Rules:    ##
##-=================================-##
/sbin/iptables-save /etc/iptables/Xe1phix-IPTables
/sbin/iptables-apply --write /etc/iptables/Xe1phix-IPTables
/sbin/iptables-apply > /etc/iptables/Xe1phix-IPTables
/sbin/iptables-save > /etc/iptables/Xe1phix-IPTables
/sbin/iptables-xml --verbose /etc/iptables/Xe1phix-IPTables
