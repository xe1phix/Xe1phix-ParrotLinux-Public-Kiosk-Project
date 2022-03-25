

usermod -a -G vboxusers username

sudo usermod -a -G vboxusers username



/etc/udev/rules.d/60-vboxdrv.rules


The numbers for the list of partitions can be taken from the output of
VBoxManage internalcommands listpartitions -rawdisk /dev/sda





VBoxManage list vms --long


VBoxManage showvminfo "Windows XP"







Create a group and assign a VM:

VBoxManage modifyvm "Fred" --groups "/TestGroup"
creates a group "TestGroup" and attaches the VM "Fred" to that group.

Command line option 2) Detach a VM from the group, and delete the group if empty:

VBoxManage modifyvm "Fred" --groups ""
It detaches all groups from the VM "Fred" and deletes the empty group.

Multiple groups e.g.:

VBoxManage modifyvm "Fred" --groups "/TestGroup,/TestGroup2"
It creates the groups "TestGroup" and "TestGroup2" (if they dont exist yet) and attaches the VM "Fred" to both of them.

Nested groups -- hierarchy of groups e.g.:

VBoxManage modifyvm "Fred" --groups "/TestGroup/TestGroup2"
It attaches the VM "Fred" to the subgroup "TestGroup2" of the "TestGroup" group.




VBoxManage command to disable the host I/O cache for a virtual storage controller:

VBoxManage storagectl "VM name" --name <controllername> --hostiocache off



Limiting bandwidth for disk images
creates a bandwidth group named "Limit", sets the limit to 20 MB/s and assigns the group to the attached disks of the VM:

VBoxManage bandwidthctl "VM name" add Limit --type disk --limit 20M
VBoxManage storageattach "VM name" --storagectl "SATA" --port 0 --device 0 --type hdd
                                   --medium disk1.vdi --bandwidthgroup Limit
VBoxManage storageattach "VM name" --storagectl "SATA" --port 1 --device 0 --type hdd
                                   --medium disk2.vdi --bandwidthgroup Limit



VBoxManage showmediuminfo     [disk|dvd|floppy] <uuid|filename>


Registered images can be listed by VBoxManage list hdds, VBoxManage list dvds, or VBoxManage list floppies



VBoxManage createmedium 

VBoxManage modifymedium 





https://www.virtualbox.org/manual/ch06.html#networkingmodes


VBoxManage natnetwork remove --netname 



create a NAT network:

VBoxManage natnetwork add --netname natnet1 --network "192.168.15.0/24" --enable

add a DHCP server to the NAT network after creation:

VBoxManage natnetwork modify --netname natnet1 --dhcp on



VBoxManage natnetwork add 


--ipv6 off





VBoxManage natnetwork modify --netname 

Starts specified NAT network service
VBoxManage natnetwork start --netname 


Stops specified NAT network service and any DHCP server
VBoxManage natnetwork stop --netname 

Lists all NAT network services with optional filtering, parameters
VBoxManage natnetwork list







VBoxManage list usbhost
VBoxManage list usbfilters
usbfilter modify
showvminfo 

usbfilter add
usbfilter remove
usbfilter modify

--action ignore|hold




--paravirtprovider none|default|legacy|minimal|hyperv|kvm









VBoxManage getextradata Fedora5 installdate

You could retrieve the information for all keys as follows:

VBoxManage getextradata Fedora5 enumerate








VBoxManage convertfromraw <filename> <outputfile>
--format VDI|VMDK|VHD]




VBoxManage dhcpserver add
VBoxManage dhcpserver modify 
VBoxManage dhcpserver remove 


VBoxManage dhcpserver add --ifname 


VBoxManage modifyvm "VM name" --natnet1 "192.168/16"
10.0.x.0/24




--cableconnected<1-N> on|off

--macaddress<1-N> auto|<mac>




VBoxManage setextradata "VM name" \
      "VBoxInternal/Devices/e1000/0/LUN#0/AttachedDriver/Config/HostResolverMappings/ \
      all_blocked_site/HostIP" 127.0.0.1
VBoxManage setextradata "VM name" \
      "VBoxInternal/Devices/e1000/0/LUN#0/AttachedDriver/Config/HostResolverMappings/ \
      all_blocked_site/HostNamePattern" "*.blocked-site.*|*.fb.org"






VBoxManage list hostonlyifs




VBoxManage snapshot 

VBoxManage snapshot restore <uuid|snapname>
VBoxManage snapshot list --details
VBoxManage snapshot showvminfo <uuid|snapname>










adds a USB device.

VBoxManage usbdevsource add 

VBoxManage usbdevsource remove 


VBoxManage debugvm <uuid|vmname> info




How to list extension packs:

$ VBoxManage list extpacks


How to remove an extension pack:

$ VBoxManage extpack uninstall "Oracle VM VirtualBox Extension Pack"


Used to remove temporary files and directories that may have been left behind if a previous install or uninstall command failed.
VBoxManage extpack cleanup






VBoxManage encryptmedium "uuid|filename" --newpassword "file|-" --cipher "cipher id" --newpasswordid "id"

AES-XTS256-PLAIN64
AES-XTS128-PLAIN64



Starting a VM with encrypted images
VBoxManage controlvm "uuid|vmname" addencpassword "id" "password" [--removeonsuspend "yes|no"]




Decrypting encrypted images
VBoxManage encryptmedium "uuid|filename" --oldpassword "file|-"




Enable the debug options by executing the following VBoxManage command:

VBoxManage modifyvm "VM name" --paravirtdebug "enabled=1"


VBoxManage modifyvm "VM name" --paravirtdebug "enabled=1,address=192.168.32.1,port=55000"








 Disabling the Guest Additions time synchronization
VBoxManage setextradata "VM name" "VBoxInternal/Devices/VMMDev/0/Config/GetHostTimeDisabled" 1








VBoxManage setextradata "VM name" VBoxInternal/Devices/IntNetIP/0/Trusted 1
VBoxManage setextradata "VM name" VBoxInternal/Devices/IntNetIP/0/Config/MAC 08:00:27:01:02:0f
VBoxManage setextradata "VM name" VBoxInternal/Devices/IntNetIP/0/Config/IP 10.0.9.1
VBoxManage setextradata "VM name" VBoxInternal/Devices/IntNetIP/0/Config/Netmask 255.255.255.0
VBoxManage setextradata "VM name" VBoxInternal/Devices/IntNetIP/0/LUN#0/Driver IntNet
VBoxManage setextradata "VM name" VBoxInternal/Devices/IntNetIP/0/LUN#0/Config/Network MyIntNet
VBoxManage setextradata "VM name" VBoxInternal/Devices/IntNetIP/0/LUN#0/Config/TrunkType 2
VBoxManage setextradata "VM name" VBoxInternal/Devices/IntNetIP/0/LUN#0/Config/IsService 1













## This adds a port-forwarding rule from the hosts TCP 1022 port to the port 22 
## on the guest with IP address 192.168.15.5. Host port, guest port and guest IP are mandatory. 
VBoxManage natnetwork modify --netname natnet1 --port-forward-4 "ssh:tcp:[]:1022:[192.168.15.5]:22"


## delete ssh port forwarding rule
VBoxManage natnetwork modify --netname natnet1 --port-forward-4 delete ssh


## Its possible to bind NAT service to specified interface:
VBoxManage setextradata global "NAT/win-nat-test-0/SourceIp4" 192.168.1.185


## To see the list of registered NAT networks, use:
VBoxManage list natnetworks




















UDP Tunnel networking
This networking mode allows to interconnect virtual machines running on different hosts.

Technically this is done by encapsulating Ethernet frames sent or received by the guest network card into UDP/IP datagrams, and sending them over any network available to the host.

UDP Tunnel mode has three parameters:

Source UDP port
The port on which the host listens. Datagrams arriving on this port from any source address will be forwarded to the receiving part of the guest network card.

Destination address
IP address of the target host of the transmitted data.

Destination UDP port
Port number to which the transmitted data is sent.

When interconnecting two virtual machines on two different hosts, their IP addresses must be swapped. On single host, source and destination UDP ports must be swapped.

In the following example host 1 uses the IP address 10.0.0.1 and host 2 uses IP address 10.0.0.2. Configuration via command-line:

        VBoxManage modifyvm "VM 01 on host 1" --nic<x> generic
        VBoxManage modifyvm "VM 01 on host 1" --nicgenericdrv<x> UDPTunnel
        VBoxManage modifyvm "VM 01 on host 1" --nicproperty<x> dest=10.0.0.2
        VBoxManage modifyvm "VM 01 on host 1" --nicproperty<x> sport=10001
        VBoxManage modifyvm "VM 01 on host 1" --nicproperty<x> dport=10002
and

        VBoxManage modifyvm "VM 02 on host 2" --nic<y> generic
        VBoxManage modifyvm "VM 02 on host 2" --nicgenericdrv<y> UDPTunnel
        VBoxManage modifyvm "VM 02 on host 2" --nicproperty<y> dest=10.0.0.1
        VBoxManage modifyvm "VM 02 on host 2" --nicproperty<y> sport=10002
        VBoxManage modifyvm "VM 02 on host 2" --nicproperty<y> dport=10001
Of course, you can always interconnect two virtual machines on the same host, by setting the destination address parameter to 127.0.0.1 on both. It will act similarly to "Internal network" in this case, however the host can see the network traffic which it could not in the normal Internal network case.







## https://www.virtualbox.org/wiki/Advanced_Networking_Linux







Advanced Network settings for Linux


A bridge can contain only one physical/virtual device. So you can create your bridge as follow:

#!/bin/sh
# set PATH for the case we are called via sudo or su root

PATH=/sbin:/usr/bin:/bin:/usr/bin

# create a tap
tunctl -t tap1 -u <user>
ip link set up dev tap1
f
# create the bridge
brctl addbr br0
brctl addif br0 tap1

# set the IP address and routing
ip link set up dev br0
ip addr add 10.1.1.1/24 dev br0
ip route add 10.1.1.0/24 dev br0








If we plan to use more as one virtual machine we can add further tap devices to the bridge. The script can be modified as follow:

#!/bin/sh
# set PATH for the case we are called via sudo or su root

PATH=/sbin:/usr/bin:/bin:/usr/bin
USER=<name of the vm user>

NUMBER_OF_VM
# create the bridge
brctl addbr br0

# create the taps and insert them into the bridge

NB=1
while [ $NB -lt $NUMBER_OF_VM
do
   tunctl -t tap$NB -u $USER
   ip link set up dev tap$NB
   brctl addif br0 tap$NB
   let NB=$NB+1
done

# set the IP address and routing
ip link set up dev br0
ip addr add 10.1.1.1/24 dev br0
ip route add 10.1.1.0/24 dev br0






