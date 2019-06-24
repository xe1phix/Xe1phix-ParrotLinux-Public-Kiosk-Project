#!/bin/sh
#load config which stores variables and exit status checker function
source config


#ipecho.net/plain is a good stuff to check which IP is used to connect to the internet
ip_addr=$(curl http://ipecho.net/plain)
check_exit $? "Unable to connect to ipecho.net/plain"
echo "Currently, the router shows himself from this IP: ${ip_addr}"



echo "Calculating the best server w.r.t. RTT"
sh get_best_server.sh
echo "--------------------------------------"
VPN_FILE=$(cat last_best_server)
cd $VPN_ROOT

#Establishing connection to your VPN service
echo "Enabling openVPN in netns ${NETNS}"
$IP netns exec $NETNS openvpn --daemon --config $VPN_FILE

#here, we look after the tun0 interface in the network namespace
#until it is not up and running, we don't process
echo "Waiting the VPN connectivity became established..."
retval=1
while [ $retval -gt 0 ]
do
  echo -n "/\.-."
  #if tun0 interface was created, then grep returns 0, which means success!
  retval=$($IP netns exec $NETNS ifconfig|grep tun0 > /dev/null;echo $?)
  sleep 1
done
echo

#now, we check again our IP
ip_addr_vpn=$($IP netns exec $NETNS curl http://ipecho.net/plain)
echo "Currently the netns shows himself from this IP: ${ip_addr_vpn}"



if [ "$ip_addr" == "$ip_addr_vpn" ]
then
  echo "Same IPs ==> VPN connection could have not been established"
  exit 1
else
  echo "Different IPs ==> WE ARE UP AND RUNNING!"
fi
