##~=~=~=~=~=~=-=~=~=~=~=~=~##
##  [+] Block Google      ##
##~=~=~=~=~=~=-=~=~=~=~=~=~##

/sbin/iptables -N GBLOCK
/sbin/iptables -A GBLOCK -d 8.8.4.0/24 -j REJECT
/sbin/iptables -A GBLOCK -d 8.8.8.0/24 -j REJECT
/sbin/iptables -A GBLOCK -d 8.34.208.0/20 -j REJECT
/sbin/iptables -A GBLOCK -d 8.35.192.0/20 -j REJECT
/sbin/iptables -A GBLOCK -d 23.236.48.0/20 -j REJECT
/sbin/iptables -A GBLOCK -d 23.251.128.0/19 -j REJECT
/sbin/iptables -A GBLOCK -d 35.184.0.0/12 -j REJECT
/sbin/iptables -A GBLOCK -d 35.200.0.0/14 -j REJECT
/sbin/iptables -A GBLOCK -d 35.204.0.0/15 -j REJECT
/sbin/iptables -A GBLOCK -d 63.88.73.0/24 -j REJECT
