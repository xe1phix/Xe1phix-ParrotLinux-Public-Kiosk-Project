#!/bin/sh
## ------------------ ##
## ICMP-IPTables.sh
## ------------------ ##
echo
echo
echo "###################################################################################"
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
## 
##-=============================================================-##
$IPTABLES -A INPUT -p icmp -m icmp --icmp-type 3 -j ACCEPT
$IPTABLES -A INPUT -p icmp -m icmp --icmp-type 4 -j ACCEPT
$IPTABLES -A INPUT -p icmp -m icmp --icmp-type 11 -j ACCEPT
##-=============================================================-##
## 
##-=================================================================================================================-##
## $IPTABLES -A INPUT  -p icmp --icmp-type destination-unreachable -m state --state ESTABLISHED,RELATED -j ACCEPT
## $IPTABLES -A INPUT  -p icmp --icmp-type time-exceeded           -m state --state ESTABLISHED,RELATED -j ACCEPT
## $IPTABLES -A INPUT  -p icmp --icmp-type source-quench           -m state --state ESTABLISHED,RELATED -j ACCEPT
## $IPTABLES -A INPUT  -p icmp --icmp-type parameter-problem       -m state --state ESTABLISHED,RELATED -j ACCEPT
##-=================================================================================================================-##
## 
##-================================================================================-##
##    [+] Allow rate-limited incoming unicast ICMP ping, and related echo reply
##-================================================================================-##
## $IPTABLES -A INPUT  -p icmp --icmp-type echo-request -m addrtype --dst-type LOCAL -m limit --limit 20/minute -j ACCEPT
## $IPTABLES -A OUTPUT -p icmp --icmp-type echo-reply   -m state --state ESTABLISHED,RELATED -j ACCEPT


##-=======================================================================-##
## 
echo "[+]================================================================[+]"
echo -e "\t [?] For ping and traceroute you'll want:                        "
echo -e "\t     echo-request(8) and echo-reply(0) enabled.                  "
echo -e "\t [?] You might be able to disable them.                          " 
echo -e "\t     However, there's a good chance you'll break things.         "
echo "[+]================================================================[+]"
## 
##-=======================================================================-##
$IPTABLES -A INPUT -p icmp -m icmp --icmp-type 0 -j ACCEPT
$IPTABLES -A INPUT -p icmp -m icmp --icmp-type 8 -j ACCEPT
##-=======================================================================-##
##

##-==========================================-##
##    [+] Drop All Other ICMP Packets
##-==========================================-##
$IPTABLES -A INPUT -p icmp -m icmp -j DROP
$IPTABLES -A FORWARD -p icmp -m icmp -j DROP
$IPTABLES -A OUTPUT -p icmp -m icmp -j DROP


##-=======================================================-##
##    [+] Apply The DROP Policy For All Other Traffic:
##-=======================================================-##
## /sbin/iptables -P INPUT DROP
## /sbin/iptables -P FORWARD DROP
## /sbin/iptables -P OUTPUT DROP


##-========================================-##
##    [+] Drop/Reject All IPv6 Traffic:
##-========================================-##
/sbin/ip6tables -A INPUT -j DROP
/sbin/ip6tables -A OUTPUT -j REJECT
/sbin/ip6tables -A FORWARD -j REJECT

##-===========================================================-##
##    [+] Drop All The Other ICMP That Arn't Required:
##-===========================================================-##
## $IPTABLES -A INPUT -p icmp -m icmp --icmp-type 1 -j DENY
## $IPTABLES -A INPUT -p icmp -m icmp --icmp-type 2 -j DENY
## $IPTABLES -A INPUT -p icmp -m icmp --icmp-type 5 -j DENY
## $IPTABLES -A INPUT -p icmp -m icmp --icmp-type 6 -j DENY
## $IPTABLES -A INPUT -p icmp -m icmp --icmp-type 7 -j DENY
## $IPTABLES -A INPUT -p icmp -m icmp --icmp-type 9 -j DENY
## $IPTABLES -A INPUT -p icmp -m icmp --icmp-type 10 -j DENY
## $IPTABLES -A INPUT -p icmp -m icmp --icmp-type 12 -j DENY
