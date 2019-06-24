#!/bin/sh

#---- BEFORE START -----#
# TO ENABLE NETWORKING ON OPENWRT FOR THIS NAMESPACE, ADD THESE LINES TO /etc/config/firewall
# to config zone lan
#	option device 'veth0 br-lan' # this lines specifies a device to the zone, we need to add br-lan as well to avoid disconnecting the regular lan from the wan
#	option subnet '10.200.1.0/24 192.168.89.0/24' #first network is the namespace network, and again, we need to add the lan network as well otherwise it becomes overwritten

#=======================#
#load config which stores variables and exit status checker function
source config

bring_up_loopback_in_netns ()
{
  #simply bringing up the lo interface in the namespace
  echo "Brining up lo interface in namespace ${NETNS}..."
  $IP netns exec $NETNS $IP link set dev lo up
  check_exit $? "Error occurred during bringing up loopback interface in netns"
}

initialize_veths ()
{
  #create a virtual ethernet pair with name veth0 and veth1
  echo "creating veth pairs..."
  $IP link add veth0 type veth peer name veth1
  check_exit $? "Error during creating virtual ethernet pair"

  #veth1 is being added to the namespace
  echo "Add veth1 to network namespace ${NETNS}..."
  $IP link set veth1 netns $NETNS
  check_exit $? "Unable to add veth1 to namespace ${NETNS}"

  #Setting up IP addresses for both of the veth interfaces
  echo "Setting up IP address for veth0..."
  $IP addr add $VETH0_IP/24 dev veth0
  check_exit $? "Unable to set IP for veth0"

  echo "Setting up IP address for veth1..."
  $IP netns exec $NETNS $IP addr add $VETH1_IP/24 dev veth1
  check_exit $? "Unable to set IP for veth1 in netns ${NETNS}"

  #And bringing them up
  echo "Bringing veth0 up..."
  $IP link set dev veth0 up
  check_exit $? "Unable to bring up veth0"

  echo "Brining veth1 in namespace ${NETNS} up..."
  $IP netns exec $NETNS $IP link set dev veth1 up
  check_exit $? "Unable to bring up veth1 in netns ${NETNS}"


  #Default gateway needs to be set in the namespace to route everything to the
  #other end of the veth pair located in the root namespace
  echo "Add default route to namespace ${NETNS}..."
  $IP netns exec $NETNS $IP route add default via $VETH0_IP dev veth1
  check_exit $? "Unable to bring up veth1 in netns ${NETNS}"

}


add_namespace_to_netns ()
{
  #create namespace specific DNS resolv.conf
  mkdir -p /etc/netns/$NETNS
  #we simply use Google's
  echo "nameserver 8.8.8.8" > /etc/netns/${NETNS}/resolv.conf 
}


#Create namespace
echo "Creating namespace 'torrent'..."
$IP netns add $NETNS
check_exit $? "Unable to create netns ${NETNS}"


echo "List of network namespaces:"
$IP netns list

bring_up_loopback_in_netns

initialize_veths


echo "Test pinging..."
$IP netns exec $NETNS ping -c 3 google.com

echo "Restarting firewall to take effect with the new subnets and interfaces..."
/etc/init.d/firewall restart


