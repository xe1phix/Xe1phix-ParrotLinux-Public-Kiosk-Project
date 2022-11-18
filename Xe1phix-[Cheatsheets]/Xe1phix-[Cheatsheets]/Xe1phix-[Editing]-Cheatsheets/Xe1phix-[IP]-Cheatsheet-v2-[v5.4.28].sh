
ip addr show -> List IP address of the server
ip addr show eth0
ip addr | grep inet6 #check that your server supports IPV6
ip addr show eth1 | grep "inet "
ip addr add 10.132.1.1/24 dev eth1 ->  Add a new IP4 address
ip addr show eth1 -> confrm that the new address is available on the interface

ip link set eth2 down -> bring an interface down  
ip link set eth2 up

ip -s link->view basic network statistics on all interfaces
ip -s link ls eth0 ->see the statistics for the eth0 interface
ip -s -s link ls eth0 ->see additional info

----------------------------------------------------------------------------------------------------
ip a #Identify Ethernet Interfaces
lshw -class network #identify all network interfaces available
ethtool eth4 #displays and changes Ethernet card settings

----------------------------------------------------------------------------------------------------
#Temporary IP Address Assignment

ip addr add 10.102.66.200/24 dev enp0s25 #Modify the IP address and subnet mask
ip link set dev enp0s25 up
ip link set dev enp0s25 down
ip address show dev enp0s25 #verify the IP address configuration of enp0s25

ip route add default via 10.102.66.1 #configure a default gateway
ip route show #verify your default gateway configuration




#check public IP,private (viewable within an internal network) or public (can be seen by other machines on the Internet)

#3rd party web-sites
$ wget -qO- http://ipecho.net/plain | xargs echo
$ curl ifconfig.co
$ curl ifconfig.me
$ curl icanhazip.com
$ curl -4 icanhazip.com
$ curl -6 icanhazip.com
$ curl ident.me
$ curl checkip.dyndns.org
$ curl api.ipify.org
$ curl ipinfo.io/ip
$ curl checkip.amazonaws.com
