
IRC client at localhost:6668
localhost:8118 (if Privoxy) 

[you@home ~]$ ssh -L 4242:127.0.0.1:4242 user1@machine1
[user1@machine1 ~]$ ssh -L 4242:127.0.0.1:4242 user2@machine2
[user2@machine2 ~]$ ssh -L 4242:127.0.0.1:4242 user3@machine3
...
[userN-1@machineN-1 ~]$ ssh -D 4242 userN@machineN




$ ifconfig eth0 down 
$ ifconfig eth0 hw ether de:ad:be:ef:f0:0d
$ ifconfig eth0 up


This quickstart generates two 
certificate authorities and 2048 bit keys, making it the most secure way
 to create an OpenVPN tunnel.

sudo chown -R nobody:nobody /etc/openvpn

adduser openvpn
chown -R openvpn:openvpn /etc/openvpn
modprobe tun
chmod 755 client-up

proto udp
port 53


proto tcp-server/proto tcp-client
port 443



http://kpvz7kpmcmne52qf.onion/wiki/index.php/Intrusive_Surveillance#Watching_Your_Back



ping LOCAL_GATEWAY_IP
arp -a

##########################################################################
## This should ensure you can connect to the VPN server through your 	##
## specific route for that IP.						##
##########################################################################

ping VPN_SERVER_IP


ping 192.168.69.1


##########################################################################
## 					 	##
## 						##
## 					 	##
## 						##
## 					 	##
## 						##
##########################################################################

ping DNS.SERVER.IP











echo "## ########################################## ###"
echo "## -L tells ssh to listen on a local port "
echo "## and forward those connections to another host "
echo "## and port through the ssh connection. 	##"
echo "## ########################################## ###"
┌─[root@parrot]
└──╼ $ ssh -L 4242:127.0.0.1:4242 user1@machine1
┌─[root@parrot]
└──╼ $ ssh -L 4242:127.0.0.1:4242 user2@machine2
┌─[root@parrot]
└──╼ $ ssh -L 4242:127.0.0.1:4242 user3@machine3



echo "## ########################################## ###"
echo "## -D tells ssh to open up a SOCKS 4 server where you specify. 	##"
echo "## ########################################## ###"
┌─[root@parrot]
└──╼ $ ssh -D 4242 userN@machineN
    
    
    
    


#################################################
## ## OpenVPN is awesome. It provides an encrypted tunnel from your computer to the OpenVPN server. 
## it is at least useful "one hop" of anonymous surfing, and restrictive firewalls. 
#################################################
## http://forums.gentoo.org/viewtopic.php?t=233080

┌─[root@parrot]
└──╼ $ adduser openvpn

┌─[root@parrot]
└──╼ $ chown -R openvpn:openvpn /etc/openvpn
## recompile kernels to support CONFIG_TUN (The Universal Tun/Tap Driver)
┌─[root@parrot]
└──╼ $ modprobe tun
┌─[root@parrot]
└──╼ $ sudo chmod 755 client-osx-up
┌─[root@parrot]
└──╼ $ chmod 755 client-up

 Configure server to use 192.168.69.1
 Configure client to use 192.168.69.2
 
## Replace VPN_SERVER_IP in client.conf with your server's IP

## Add a publicly available nameserver to /etc/resolv.conf. 

http://www.opennic.unrated.net/public_servers.html

##########################################################################################
## ## !!! WARNING: !!! ## ## 
## An attentive and fascist network administrator will still be able 
## to determine that you are tunneling packets over an openvpn tunnel by 
## watching your traffic. (rest assured, they won't be able to see what you are doing, 
## just that you're doing something)
#########################################################################################
## change the proto udp and port 53 lines in your server and client configuration
## file to proto tcp-server/proto tcp-client and port 443 (or port 22) 
## to make your openvpn session look more like a secure web (or ssh) connection.
###################################################################################






