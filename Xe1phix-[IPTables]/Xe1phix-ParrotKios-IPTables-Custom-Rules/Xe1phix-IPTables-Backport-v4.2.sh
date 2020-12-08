#!/bin/sh
modprobe -vi ipt_owner
modprobe ipt_LOG
modprobe -vi iptable_security
modprobe -vi ipt_rpfilter
modprobe -vi nf_log_ipv6
modprobe ipt_state

 
/sbin/iptables -F
/sbin/iptables -X
/sbin/iptables -L -n -v --line-numbers


$IP6TABLES -A INPUT -j LOG --log-prefix "Blocked INPUT IPV6: "
$IP6TABLES -A OUTPUT -j LOG --log-prefix "Blocked OUTPUT IPV6: "
$IP6TABLES -A FORWARD -j LOG --log-prefix "Blocked FORWARD IPV6: "
iptables -A INPUT -p ipv6 -j DROP
iptables -A OUTPUT -p ipv6 -j DROP
iptables -A FORWARD -p ipv6 -j DROP
ip6tables -P INPUT DROP
ip6tables -P OUTPUT DROP
ip6tables -P FORWARD DROP
iptables -L
/sbin/iptables -A INPUT -s 144.202.X.X -j DROP
/sbin/iptables -A OUTPUT -d 144.202.X.X -j DROP
/sbin/iptables -A FORWARD -s 144.202.X.X -j DROP
/sbin/iptables -A FORWARD -d 144.202.X.X -j DROP


/sbin/iptables -A OUTPUT --out-interface wlan0 -j ACCEPT
/sbin/iptables -A INPUT --in-interface wlan0 -j ACCEPT

/sbin/ip6tables -A INPUT --in-interface lo -j DROP
/sbin/ip6tables -A OUTPUT --out-interface lo -j DROP
/sbin/ip6tables -t nat -A PREROUTING -j DROP

/sbin/iptables -A INPUT -m state --state INVALID -j LOG --log-prefix "Invalid ctstate" --log-ip-options --log-tcp-options
/sbin/iptables -A INPUT -m state --state INVALID -j DROP
/sbin/iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

/sbin/iptables -A OUTPUT -m state --state INVALID -j LOG --log-prefix "Invalid ctstate" --log-ip-options --log-tcp-options
/sbin/iptables -A OUTPUT -m state --state INVALID -j DROP
/sbin/iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

/sbin/iptables -A FORWARD -m state --state INVALID -j LOG --log-prefix "Invalid ctstate" --log-ip-options --log-tcp-options
/sbin/iptables -A FORWARD -m state --state INVALID -j DROP
/sbin/iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT


$IPTABLES -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
$IPTABLES -A OUTPUT -p tcp --dport 80 --syn -m state --state NEW -j ACCEPT
$IPTABLES -A OUTPUT -p tcp --dport 443 --syn -m state --state NEW -j ACCEPT
$IPTABLES -A OUTPUT -p udp --dport 53 -m state --state NEW -j ACCEPT
$IPTABLES -A OUTPUT -p tcp --dport 53 -m state --state NEW -j ACCEPT
$IPTABLES -A OUTPUT -p icmp --icmp-type echo-request -j ACCEPT



iptables -A INPUT -p tcp --tcp-flags ALL ALL -j LOG --log-prefix "IPT: All Flags "
iptables -A INPUT -p tcp --tcp-flags ALL ALL -j DROP
iptables -A INPUT -p tcp --tcp-flags ALL ACK,RST,SYN,FIN -j LOG --log-prefix "IPTables: Bad SF Flag "
iptables -A INPUT -p tcp --tcp-flags ALL ACK,RST,SYN,FIN -j DROP
iptables -A INPUT -p tcp --tcp-flags SYN,FIN SYN,FIN -j LOG --log-prefix "IPTables: Bad SF Flag "
iptables -A INPUT -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP
iptables -A INPUT -p tcp --tcp-flags SYN,RST SYN,RST -j LOG --log-prefix "IPT: Bad SR Flag "
iptables -A INPUT -p tcp --tcp-flags SYN,RST SYN,RST -j DROP
iptables -A INPUT -p tcp --tcp-flags SYN,FIN,PSH SYN,FIN,PSH -j LOG --log-prefix "IPT: Bad SFP Flag "
iptables -A INPUT -p tcp --tcp-flags SYN,FIN,PSH SYN,FIN,PSH -j DROP
iptables -A INPUT -p tcp --tcp-flags SYN,FIN,RST SYN,FIN,RST -j LOG --log-prefix "IPT: Bad SFR Flag "
iptables -A INPUT -p tcp --tcp-flags SYN,FIN,RST SYN,FIN,RST -j DROP
iptables -A INPUT -p tcp --tcp-flags SYN,FIN,RST,PSH SYN,FIN,RST,PSH -j LOG --log-prefix "IPT: Bad SFRP Flag "
iptables -A INPUT -p tcp --tcp-flags SYN,FIN,RST,PSH SYN,FIN,RST,PSH -j DROP
iptables -A INPUT -p tcp --tcp-flags FIN FIN -j LOG --log-prefix "IPT: Bad F Flag "
iptables -A INPUT -p tcp --tcp-flags FIN FIN -j DROP
iptables -A INPUT -p tcp --tcp-flags ALL NONE -j LOG --log-prefix "IPT: Null Flag "
iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP
iptables -A INPUT -s 255.0.0.0/8 -j LOG --log-prefix "Spoofed source IP!"
iptables -A INPUT -s 255.0.0.0/8 -j DROP

iptables -N check-flags
iptables -L
iptables -F check-flags
iptables -L
iptables -A check-flags -p tcp --tcp-flags ALL FIN,URG,PSH -m limit --limit 5/minute -j LOG --log-level alert --log-prefix "NMAP-XMAS:"
iptables -A check-flags -p tcp --tcp-flags ALL FIN,URG,PSH -j DROP
iptables -A check-flags -p tcp --tcp-flags ALL ALL -m limit --limit 5/minute -j LOG --log-level 1 --log-prefix "XMAS:"
iptables -A check-flags -p tcp --tcp-flags ALL ALL -j DROP
iptables -A check-flags -p tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG -m limit --limit 5/minute -j LOG --log-level 1 --log-prefix "XMAS-PSH:"
iptables -A check-flags -p tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG -j DROP
iptables -L
iptables -A check-flags -p tcp --tcp-flags ALL NONE -m limit --limit 5/minute -j LOG --log-level 1 --log-prefix "NULL_SCAN:"
iptables -A check-flags -p tcp --tcp-flags ALL NONE -j DROP
iptables -A check-flags -p tcp --tcp-flags SYN,RST SYN,RST -m limit --limit 5/minute -j LOG --log-level 5 --log-prefix "SYN/RST:"
iptables -A check-flags -p tcp --tcp-flags SYN,RST SYN,RST -j DROP
iptables -A check-flags -p tcp --tcp-flags SYN,FIN SYN,FIN -m limit --limit 5/minute -j LOG --log-level 5 --log-prefix "SYN/FIN:"
iptables -A check-flags -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP
iptables -A INPUT -p sctp --dport 80 -j DROP
iptables -A INPUT -p sctp --chunk-types any DATA,INIT -j DROP

/sbin/iptables -A INPUT -p udp --dport 3478 -j LOG --log-prefix "DROP WebRTC" --log-ip-options --log-tcp-options --log-uid
/sbin/iptables -A INPUT -p udp --dport 3478 -j DROP
/sbin/iptables -A INPUT -p udp --dport 3479 -j LOG --log-prefix "DROP WebRTC" --log-ip-options --log-tcp-options --log-uid
/sbin/iptables -A INPUT -p udp --dport 3479 -j DROP
/sbin/iptables -A INPUT -p tcp --dport 3478 -j LOG --log-prefix "DROP WebRTC" --log-ip-options --log-tcp-options --log-uid
/sbin/iptables -A INPUT -p tcp --dport 3478 -j DROP
/sbin/iptables -A INPUT -p tcp --dport 3479 -j LOG --log-prefix "DROP WebRTC" --log-ip-options --log-tcp-options --log-uid
/sbin/iptables -A INPUT -p tcp --dport 3479 -j DROP


/sbin/iptables -A INPUT -p tcp --dport 135 -j LOG --log-prefix "DROP WebRTC" --log-ip-options --log-tcp-options --log-uid
/sbin/iptables -A INPUT -p tcp --dport 139 -j LOG --log-prefix "DROP WebRTC" --log-ip-options --log-tcp-options --log-uid
/sbin/iptables -A INPUT -p udp --dport 135:139 -j DROP


/sbin/iptables -A INPUT -m conntrack --ctstate INVALID -j DROP
/sbin/iptables -A INPUT -m state --state INVALID -j LOG --log-prefix "DROP INVALID " --log-tcp-options --log-ip-options
/sbin/iptables -A INPUT -m state --state INVALID -j DROP


# We don't care about Milkosoft, Drop SMB/CIFS/etc..
/sbin/iptables -A INPUT -p tcp -m multiport --dports 135,137,138,139,445,1433,1434 -j LOG --log-prefix "Blocked: Faggot Microsoft Service" --log-ip-options --log-tcp-options
/sbin/iptables -A INPUT -p tcp -m multiport --dports 135,137,138,139,445,1433,1434 -j DROP
/sbin/iptables -A INPUT -p udp -m multiport --dports 135,137,138,139,445,1433,1434 -j LOG --log-prefix "Blocked: Faggot Microsoft Service" --log-ip-options --log-tcp-options
/sbin/iptables -A INPUT -p udp -m multiport --dports 135,137,138,139,445,1433,1434 -j DROP


/sbin/iptables -A INPUT -p UDP -i wlan0 --dport 67 --sport 68 -j ACCEPT


/sbin/iptables -A INPUT -p TCP -i wlan0 -s ! 139.99.96.146 --dport 53 -j LOG --log-prefix "Blocked: Bad DNS IPAddr" --log-ip-options --log-tcp-options
/sbin/iptables -A INPUT -p TCP -i wlan0 -s ! 139.99.96.146 --dport 53 -j DROP
/sbin/iptables -A INPUT -p TCP -i wlan0 -s 139.99.96.146 --dport 53 -j ACCEPT

/sbin/iptables -A INPUT -p TCP -i wlan0 -s ! 37.59.40.15 --dport 53 -j LOG --log-prefix "Blocked: Bad DNS IPAddr" --log-ip-options --log-tcp-options
/sbin/iptables -A INPUT -p TCP -i wlan0 -s ! 37.59.40.15 --dport 53 -j DROP
/sbin/iptables -A INPUT -p TCP -i wlan0 -s 37.59.40.15 --dport 53 -j ACCEPT

/sbin/iptables -A INPUT -p TCP -i wlan0 -s ! 185.121.177.177 --dport 53 -j LOG --log-prefix "Blocked: Bad DNS IPAddr" --log-ip-options --log-tcp-options
## /sbin/iptables -A INPUT -p TCP -i wlan0 -s ! 185.121.177.177 --dport 53 -j DROP
/sbin/iptables -A INPUT -p TCP -i wlan0 -s 185.121.177.177 --dport 53 -j ACCEPT


/sbin/iptables -A OUTPUT -p TCP -d 139.99.96.146 --dport 53 -j ACCEPT
/sbin/iptables -A OUTPUT -p TCP -d ! 139.99.96.146 --dport 53 -j LOG --log-prefix "Blocked: Bad DNS IPAddr" --log-ip-options --log-tcp-options

/sbin/iptables -A OUTPUT -p TCP -d ! 37.59.40.15 --dport 53 -j LOG --log-prefix "Blocked: Bad DNS IPAddr" --log-ip-options --log-tcp-options
/sbin/iptables -A OUTPUT -p TCP -d 37.59.40.15 --dport 53 -j ACCEPT

/sbin/iptables -A OUTPUT -p TCP -d ! 185.121.177.177 --dport 53 -j LOG --log-prefix "Blocked: Bad DNS IPAddr" --log-ip-options --log-tcp-options
/sbin/iptables -A OUTPUT -p TCP -d 185.121.177.177 --dport 53 -j ACCEPT


## /sbin/iptables -A OUTPUT -p udp --dport 53 -m owner --uid-owner xe1phix -m conntrack --ctstate NEW -j ACCEPT


/sbin/iptables -A OUTPUT -p udp --dport 53 -m state --state NEW -j ACCEPT
/sbin/iptables -A OUTPUT -p tcp --dport 53 -m state --state NEW -j ACCEPT
/sbin/iptables -A OUTPUT -p icmp --icmp-type echo-request -j ACCEPT


/sbin/iptables -A OUTPUT -p tcp --dport 80 --syn -m state --state NEW -j ACCEPT					# HTTP Port
/sbin/iptables -A OUTPUT -p tcp --dport 443 --syn -m state --state NEW -j ACCEPT
/sbin/iptables -A OUTPUT -p tcp --dport 443 -j ACCEPT				# HTTPS Port




/sbin/iptables -A OUTPUT -p tcp --dport 6667 -j ACCEPT				# IRC Port
/sbin/iptables -A OUTPUT -p tcp --dport 6669 -j ACCEPT				# SIRC Port
/sbin/iptables -A INPUT -p tcp --destination-port 6697 -j LOG --log-prefix "IRC Attempt"
/sbin/iptables -A OUTPUT -p tcp --destination-port 6669 -j LOG --log-prefix "SSL IRC Attempt"

/sbin/iptables -A INPUT --dport 6667 -m owner --uid-owner 1000 -j ACCEPT
/sbin/iptables -A INPUT --dport 6667 -m owner --uid-owner xe1phix -j ACCEPT
/sbin/iptables -A INPUT --dport 6667 -m owner --uid-owner ! xe1phix -j LOG --log-prefix "Blocked: IRC Bad Owner" --log-ip-options --log-tcp-options --log-uid
/sbin/iptables -A INPUT --dport 6667 -m owner --uid-owner ! xe1phix -j DROP

/sbin/iptables -A INPUT --dport 6669 -m owner --uid-owner 1000 -j ACCEPT
/sbin/iptables -A INPUT --dport 6669 -m owner --uid-owner xe1phix -j ACCEPT
/sbin/iptables -A INPUT --dport 6669 -m owner --uid-owner ! xe1phix -j LOG --log-prefix "Blocked: IRC Bad Owner" --log-ip-options --log-tcp-options --log-uid
/sbin/iptables -A INPUT --dport 6669 -m owner --uid-owner ! xe1phix -j DROP


# Log and Drop Fragmented Traffic
/sbin/iptables -A INPUT -f -j LOG --log-prefix "IPT: Frag "
/sbin/iptables -A INPUT -f -j DROP

## Silently dropping all the broadcasted packets...
iptables -A INPUT -m pkttype --pkt-type broadcast -j DROP

iptables -A INPUT -p ip -m ttl --ttl-eq 0 -j LOG --log-prefix "ZERO TTL TRAFFIC "       ## Detecting and logging all IP packets with a TTL value of zero


echo
echo "###################################################################################"
echo "[+]=====================================================================[+]"
echo -e "\t\t\t Primary ICMP Types"
echo "[+]=====================================================================[+]"
echo -e "\t\t\t## || 0: Echo-Reply (Pong)         || ##"
echo -e "\t\t\t## || 3: Destination-Unreachable,  || ##"
echo -e "\t\t\t## || ============================ || ##"
echo "            ||     == > Port-Unreachable	  || ##"
echo "            ||	 == > Fragmentation-Needed|| ##"
echo -e "\t\t\t## || ============================ || ##"
echo -e "\t\t\t## || 4: Source-Quench             || ##"
echo -e "\t\t\t## || 5: Redirect                  || ##"
echo -e "\t\t\t## || 8: Echo-Request (Ping)       || ##"
echo -e "\t\t\t## || 11: Time-Exceeded            || ##"
echo -e "\t\t\t## || 12: Parameter-Problem        || ##"
echo "[+]=====================================================================[+]"
echo "###################################################################################"
echo
##########
# icmp types
#
#  0    Echo Reply                               [RFC792]
#  1    Unassigned                                  [JBP]
#  2    Unassigned                                  [JBP]
#  3    Destination Unreachable                  [RFC792]
#  4    Source Quench                            [RFC792]
#  5    Redirect                                 [RFC792]
#  6    Alternate Host Address                      [JBP]
#  7    Unassigned                                  [JBP]
#  8    Echo                                     [RFC792]
#  9    Router Advertisement                    [RFC1256]
# 10    Router Solicitation                     [RFC1256]
# 11    Time Exceeded                            [RFC792]
# 12    Parameter Problem                        [RFC792]
# 13    Timestamp                                [RFC792]
# 14    Timestamp Reply                          [RFC792]
# 15    Information Request                      [RFC792]
# 16    Information Reply                        [RFC792]
# 17    Address Mask Request                     [RFC950]
# 18    Address Mask Reply                       [RFC950]
# 19    Reserved (for Security)                    [Solo]
# 20-29 Reserved (for Robustness Experiment)        [ZSu]
# 30    Traceroute                              [RFC1393]
# 31    Datagram Conversion Error               [RFC1475]
# 32     Mobile Host Redirect              [David Johnson]
# 33     IPv6 Where-Are-You                 [Bill Simpson]
# 34     IPv6 I-Am-Here                     [Bill Simpson]
# 35     Mobile Registration Request        [Bill Simpson]
# 36     Mobile Registration Reply          [Bill Simpson]
# 37     Domain Name Request                     [Simpson]
# 38     Domain Name Reply                       [Simpson]
# 39     SKIP                                    [Markson]
# 40     Photuris                                [Simpson]
# 41-255 Reserved                                   [JBP]
##########
echo

echo "[+]=====================================================================[+]"
echo -e "\t\t\t[+] Blocking INCOMING ICMP Pings..."
echo "[+]=====================================================================[+]"
echo
echo
echo -e "\t\t__________________________________________"
echo
echo -e "\t\t\t[+] Required ICMP Packets:"
echo -e "\t\t__________________________________________"
echo
echo -e "\t\t<{&}===================================={&}>"
echo -e "\t\t     || • Destination-Unreachable(3) ||"
echo -e "\t\t     || • Source-Quench(4)           ||"
echo -e "\t\t     || • Time-Exceeded(11)          ||"
echo -e "\t\t<{&}===================================={&}>"
echo
echo "[+]=====================================================================[+]"






# First, drop all fragmented ICMP packets (almost always malicious).
$IPTABLES -A INPUT -p icmp --fragment -j DROPLOG
$IPTABLES -A OUTPUT -p icmp --fragment -j DROPLOG
$IPTABLES -A FORWARD -p icmp --fragment -j DROPLOG




iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 1/s -j ACCEPT

iptables -A INPUT -p icmp --icmp-type echo-request -m length --length 86:0xffff -j DROP
iptables -A INPUT -p icmp --icmp-type echo-request -m length --length 86:0xffff -j LOG --log-prefix "Ping Packet Size Larger Than 85 Bytes: " --log-level 7

iptables -A INPUT -p icmp --icmp-type 4/0 -j DROP       ## drops all ICMP source-quench

# Drop any other ICMP traffic.
$IPTABLES -A INPUT -p icmp -j DROPLOG
$IPTABLES -A OUTPUT -p icmp -j DROPLOG
$IPTABLES -A FORWARD -p icmp -j DROPLOG









iptables -I FORWARD -p tcp --dport 1433 -m state --state ESTABLISHED -m string --hex-string "'|00|" --algo bm -m string --hex-string "-|00|-|00|" --algo bm -j LOG --log-prefix "SQL INJECTION COMMENT "

iptables -A FORWARD -p udp --dport 53 -m string --string "/bin/sh" --algo bm -j LOG --log-prefix "SID100001 "

iptables -A INPUT -p tcp --dport 80 -m string --string "/etc/passwd" --from 100 --algo bm -j DROP
iptables -A INPUT -p tcp --dport 80 -m string --string "/etc/passwd" --to 1000 --algo bm -j DROP





echo "## ============================================================================== ##"
echo -e "\t\t\t[+] Invoking INPUT State Table..."
echo "## ============================================================================== ##"
## 
## ======================================================================================== ##
$IPTABLES -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
$IPTABLES -A INPUT -j DROP
## ======================================================================================== ##
## 
echo
echo "## ============================================================================== ##"
echo -e "\t\t\t[+] Invoking OUTPUT State Table..."
echo "## ============================================================================== ##"
## 
## ======================================================================================== ##
$IPTABLES -A OUTPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
$IPTABLES -A OUTPUT -j DROP
## ======================================================================================== ##
## 
