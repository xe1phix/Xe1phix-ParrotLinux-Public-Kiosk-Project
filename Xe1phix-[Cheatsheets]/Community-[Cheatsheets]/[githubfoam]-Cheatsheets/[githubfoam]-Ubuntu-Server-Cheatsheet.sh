----------------------------------------------------------------------------------------------------
#ubuntu server 
----------------------------------------------------------------------------------------------------
apt-get install tasksel
#Select a Display Manager, GDM3 lightdm SDDM SLiM
apt-get install lightdm
#Choose a GUI, ubuntu-mate-core,lubuntu-core
tasksel
tasksel install ubuntu-mate-core
# check what display manager is configured
cat /etc/X11/default-display-manager
service lightdm start
service lightdm stop

cat /etc/X11/default-display-manager

tasksel install ubuntu-mate-core
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

#add DNS server IP addresses in the file /etc/resolv.conf,If DNS for your temporary network configuration requires
$ cat /etc/resolv.conf
nameserver 8.8.8.8
nameserver 8.8.4.4

ip addr flush enp0s25 #purge all IP configuration from an interface
----------------------------------------------------------------------------------------------------
#Static IP Address Assignment
$ cat /etc/netplan/00_installer-config.yaml
network:  
  ethernets:
    eth0:
      addresses: [10.10.10.2/24]
      gateway4: 10.10.10.1
      nameservers:
          addresses: [10.10.10.1, 1.1.1.1]
    version: 2
    
$ sudo netplan apply
----------------------------------------------------------------------------------------------------
#Static IP Address Assignment
$ cat /etc/netplan//etc/netplan/99_config.yaml
network:
  version: 2
  renderer: networkd
  ethernets:
    enp0s25:
      addresses:
        - 192.168.0.100/24
      gateway4: 192.168.0.1
      nameservers:
          search: [mydomain, otherdomain]
          addresses: [1.1.1.1, 8.8.8.8, 4.4.4.4]
----------------------------------------------------------------------------------------------------
#Dynamic IP Address Assignment (DHCP Client)
network:
  version: 2
  renderer: networkd
  ethernets:
    enp3s0:
      dhcp4: true
 $ sudo netplan apply     
----------------------------------------------------------------------------------------------------
#The loopback interface is identified by the system as lo and has a default IP address of 127.0.0.1
ip address show lo 

#Name Resolution
#Netplan configures systemd-resolved to generate a list of nameservers and domains to put in /etc/resolv.conf, which is a symlink
/etc/resolv.conf -> ../run/systemd/resolve/stub-resolv.conf

$ cat /etc/hosts
127.0.0.1   localhost
127.0.1.1   ubuntu-server
10.0.0.11   server1 server1.example.com vpn
10.0.0.12   server2 server2.example.com mail
10.0.0.13   server3 server3.example.com www
10.0.0.14   server4 server4.example.com file
----------------------------------------------------------------------------------------------------