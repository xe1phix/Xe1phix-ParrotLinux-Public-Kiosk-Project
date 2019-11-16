#!/bin/sh
##############
##
##############
## nmcli.sh
#############
## 
## 
## 
######################











udevadm info /sys/class/net/eth0
udevadm info /sys/class/net/wlan0
udevadm info --export-db > udev.txt

describe 802-1x

nmcli device status
nmcli dev wifi
nmcli -f CONNECTIONS device show wlan0
nmcli -f GENERAL,WIFI-PROPERTIES dev show eth0 
nmcli -f GENERAL,WIFI-PROPERTIES dev show wlan0
nmcli -p con up ifname wlan0

nmcli status general
nmcli general
nmcli general status
nmcli general logging

nmcli radio on
nmcli radio wifi on
nmcli general


nmcli device show
nmcli device status

nmcli device monitor

~]$ nmcli general hostname

nmcli general hostname faggot

force h o st n amect l to notice the change in the static host name, restart ho stnamed as ro o t:
~]# systemctl restart systemd -ho stnamed




nmcli con up id bond0
nmcli con up id eth0
nmcli con up id wlan0
nmcli con 
nmcli dev disconnect bond0
nmcli dev disconnect eth0
nmcli dev disconnect wlan0





nmcli connection monitor
nmcli connection show
nmcli connection show --active

nmcli con up default
nmcli show connection
nmcli connection show
nmcli connection id
nmcli connection reload
nmcli connection show
nmcli connection edit
nmcli show
nmcli connection show
nmcli 
nmcli -t
nmcli -t device
nmcli --terse device
nmcli --terse --fields
--colors auto --terse






echo "Using the NetworkManager Command Line Tool, nmcli
echo "To create a bridge, named bridge-br0, 
echo "issue a command as follows as root:


# Connection 'bridge-br0' (6ad5bba6-98a0-4f20-839d-c997ba7668ad) successfully added.
nmcli con add type bridge ifname br0


echo "If no interface name is specified, 
echo "the name will default to bridge, bridge-1, bridge-2, and so on.
echo "To view the connections, issue the following command:

nmcli con show

echo "Output: \n\tNAME        UUID                                  TYPE            DEVICE"
echo "Output: \n\tbridge-br0  79cf6a3e-0310-4a78-b759-bda1cc3eef8d  bridge          br0"
echo "Output: \n\teth0        4d5c449a-a6c5-451c-8206-3c9a4ec88bca  802-3-ethernet  eth0"

echo "Spanning tree protocol (STP) is enabled by default. 
echo "The values used are from the IEEE 802.1D-1998 standard. 
echo "To disable STP for this bridge, 
echo "issue a command as follows as root:


nmcli con modify bridge-br0 bridge.stp no

echo "To re-enable 802.1D STP for this bridge, 
echo "issue a command as follows as root:

nmcli con modify bridge-br0 bridge.stp yes


echo "The default bridge priority for 802.1D STP is 32768. 
echo "The lower number is preferred in root bridge selection. 
echo "For example, a bridge with priority of 28672 would be 
echo "selected as the root bridge in preference to a bridge 
echo "with priority value of 32768 (the default). 
echo "To create a bridge with a non-default value, 
echo "issue a command as follows:



nmcli con add type bridge ifname br5 stp yes priority 28672

echo "Output: \n\t [!] Connection 'bridge-br5' (86b83ad3-b466-4795-aeb6-4a66eb1856c7) successfully added."


echo "The allowed values are in the range 0 to 65535.
echo "To change the bridge priority of an existing bridge 
echo "to a non-default value, issue a command in the following format:

nmcli connection modify bridge-br5 bridge.priority 36864



echo "The allowed values are in the range 0 to 65535.
echo "To view the bridge settings, issue the following command:

nmcli -f bridge con show bridge-br0




echo "Further options on 802.1D STP are listed in the bridge
echo "section of the nmcli(1) man page.
echo "To add, or enslave an interface, example eth1, 
echo "to the bridge bridge-br0, issue a command as follows:


nmcli con add type bridge-slave ifname eth1 master bridge-br0

echo "Output: \n\t [!] Connection 'bridge-slave-eth1' (70ffae80-7428-4d9c-8cbd-2e35de72476e) successfully added."


echo "At time of writing, nmcli only supports Ethernet slaves.
echo "To change a value using interactive mode, issue the following command:

nmcli connection edit bridge-br0

echo "You will be placed at the nmcli prompt.

nmcli> set bridge.priority 4096

nmcli> save temporary
nmcli> save persistent
nmcli> save

echo "Output: \n\tConnection 'bridge-br0' (79cf6a3e-0310-4a78-b759-bda1cc3eef8d) successfully saved."


nmcli> quit








man nmcli-examples

service NetworkManager start
nmcli dev | grep "ethernet"
nmcli dev | grep wifi

nmcli dev status STATE
nmcli dev status CONNECTION

nmcli dev show lo
nmcli dev show etho
nmcli dev show eth0
nmcli dev show wlan0

nmcli dev wlan0
nmcli con up wlan0
nmcli dev wifi list



nmcli dev disconnect wlan0
nmcli connection reload


nmcli dev modify wlan0 

nmcli dev lldp list


nmcli -p con show Ethernet-Connection-1








echo "ip macsec commands are used to configure transmit 
echo "secure associations and receive secure channels and their
echo "secure associations on a MACsec device created with the 
echo "ip link add command using the macsec type.


echo "Create a MACsec device on link eth0
ip link add link eth0 macsec0 type macsec port 11 encrypt on

echo "Configure a secure association on that device
ip macsec add macsec0 tx sa 0 pn 1024 on key 01 81818181818181818181818181818181

echo "Configure a receive channel
ip macsec add macsec0 rx port 1234 address c6:19:52:8f:e6:a0

echo "Configure a receive association
ip macsec add macsec0 rx port 1234 address c6:19:52:8f:e6:a0 sa 0 pn 1 on key 00 82828282828282828282828282828282

echo "Display MACsec configuration
ip macsec show




echo "Shows the entries for destinations from subnet
ip tcp_metrics show address 192.168.0.0/24
           

echo "The same but address keyword is optional
ip tcp_metrics show 192.168.0.0/24



echo "Show all is the default action
ip tcp_metrics





nmtui
nmtui-edit,
nmtui-connect,
nmtui-hostname
nm-online
nm-settings
nm-applet


hostapd_cli



nm-connection-editor













/etc/NetworkManager/system-connections
/org/freedesktop/NetworkManager/Settings/

NMConnectivityState
/var/lib/NetworkManager/NetworkManager.state

/etc/NetworkManager/NetworkManager.conf

echo "are run immediately, without waiting for the termination
echo "of previous scripts, and in parallel.
       
/etc/NetworkManager/dispatcher.d/no-wait.d/


/etc/NetworkManager/dispatcher.d/pre-up.d
vpn-pre-up

/etc/NetworkManager/dispatcher.d

--config /etc/NetworkManager/NetworkManager.conf
nm-system-settings.conf
NetworkManager.conf


--plugins

--log-domains
--log-level
--print-config


NetworkManager.conf(5), nmcli(1), nmcli-examples(7), nm-online(1), nm-settings(5), nm-applet(1), nm-connection-
       editor(1), udev(7)



VPN_IP_IFACE,
DEVICE_IP_IFACE,
DEVICE_IFACE,








echo "Listing available Wi-Fi APs"
nmcli device wifi list


NetworkManager --print-config


nmcli -f all dev wifi list



echo "Showing general information and properties for a Wi-Fi interface
nmcli -p -f general,wifi-properties device show wlan0



echo "Listing NetworkManager polkit permissions
echo "shows configured polkit permissions 
echo "for various NetworkManager operations.

/usr/share/polkit-1/actions/org.freedesktop.NetworkManager.policy


nmcli general permissions

pkaction --action-id org.freedesktop.NetworkManager.network-control --verbose


nmcli con mod em1-1 +ipv4.dns 8.8.4.4
nmcli con mod em1-1 -ipv4.dns 1



echo "Listing NetworkManager log level and domains"
nmcli general logging


ERR, WARN, INFO, DEBUG, TRACE. The ERR level logs only critical errors.
           WARN logs warnings that may reflect operation. INFO logs various informational messages that are useful for tracking
           state and operations. DEBUG enables verbose logging for debugging purposes. TRACE enables even more verbose logging then
           DEBUG level.

nmcli -t -c auto general logging level DEBUG 
nmcli -t -c auto general logging level DEBUG domains CORE,AUDIT,ETHER,IP

echo "Changing NetworkManager logging"
nmcli g log level DEBUG domains CORE,ETHER,IP			## log in DEBUG level, and only for CORE, ETHER and IP domains.
nmcli g log level INFO domains DEFAULT					## restores the default logging state


echo "Adding a bonding master and two slave connection profiles"
nmcli con add type bond ifname mybond0 mode active-backup
nmcli con add type ethernet ifname eth1 master mybond0
nmcli con add type ethernet ifname eth2 master mybond0

echo "Adding a team master and two slave connection profiles

nmcli con add type team con-name Team1 ifname Team1 config team1-master-json.conf
nmcli con add type ethernet con-name Team1-slave1 ifname em1 master Team1
nmcli con add type ethernet con-name Team1-slave2 ifname em2 master Team1


echo "change the configuration with modify command 
nmcli con modify Team1 team.config team1-master-another-json.conf

nmcli connection edit type ethernet

nmcli general permissions
connection.permissions
/usr/share/polkit-1/actions/org.freedesktop.NetworkManager.policy.

nmcli g log level 

connection.zone

tc.tfilters

ipv4.dhcp-send-hostname
ipv6.dhcp-send-hostname


nmcli -g ip4.address connection show my-con-eth0
nmcli -g ip4.address,ip4.dns connection show my-con-eth0


nmcli con mod my-con-em1 ipv4.dns "8.8.8.8 8.8.4.4"



general,2GHZ                        general,DNS                         general,ROUTE
general,5GHZ                        general,DOMAIN                      general,RSN-FLAGS
general,ACTIVE                      general,DRIVER                      general,RSSI
general,ACTIVE-PATH                 general,DRIVER-VERSION              general,S390-SUBCHANNELS
general,ADDRESS                     general,FIRMWARE-MISSING            general,SECURITY
general,ADHOC                       general,FIRMWARE-VERSION            general,SIGNAL
general,AP                          general,FREQ                        general,SLAVE
general,AUTOCONNECT                 general,GATEWAY                     general,SLAVES
general,AUTOCONNECT-PRIORITY        general,GENERAL                     general,SPEC-OBJECT
general,AVAILABLE-CONNECTION-PATHS  general,GROUP                       general,SPEED
general,AVAILABLE-CONNECTIONS       general,HWADDR                      general,SRIOV
general,BANNER                      general,ID                          general,SSID
general,BARS                        general,IEEE-802-1-PPVID            general,SSID-HEX
general,BLUETOOTH                   general,IEEE-802-1-PPVID-FLAGS      general,STATE
general,BOND                        general,IEEE-802-1-PVID             general,SYSTEM-CAPABILITIES
general,BRIDGE                      general,IEEE-802-1-VID              general,SYSTEM-DESCRIPTION
general,BSID                        general,IEEE-802-1-VLAN-NAME        general,SYSTEM-NAME
general,BSSID                       general,IN-USE                      general,TEAM
general,CAPABILITIES                general,IP4                         general,TIMESTAMP
general,CARRIER                     general,IP6                         general,TIMESTAMP-REAL
general,CARRIER-DETECT              general,IP-IFACE                    general,TKIP
general,CCMP                        general,IS-SOFTWARE                 general,TX-POW
general,CFG                         general,MASTER-PATH                 general,TYPE
general,CHAN                        general,METERED                     general,UDI
general,CHASSIS-ID                  general,MODE                        general,USERNAME
general,CHASSIS-ID-TYPE             general,MTU                         general,UUID
general,CINR                        general,NAME                        general,VENDOR
general,CONFIG                      general,NM-MANAGED                  general,VLAN
general,CONNECTION                  general,NM-PLUGIN-MISSING           general,VPN
general,CONNECTIONS                 general,NM-TYPE                     general,VPN-STATE
general,CON-PATH                    general,NSP                         general,WEP
general,CON-UUID                    general,OPTION                      general,WIFI-PROPERTIES
general,CTR-FREQ                    general,PARENT                      general,WIMAX-PROPERTIES
general,DBUS-PATH                   general,PHYS-PORT-ID                general,WINS
general,DEFAULT                     general,PORT-DESCRIPTION            general,WIRED-PROPERTIES
general,DEFAULT6                    general,PORT-ID                     general,WPA
general,DESTINATION                 general,PORT-ID-TYPE                general,WPA2
general,DEVICE                      general,PRODUCT                     general,WPA-FLAGS
general,DEVICES                     general,RATE                        general,ZONE
general,DHCP4                       general,READONLY                    
general,DHCP6                       general,REASON                      







nmcli con modify ipv6.ignore-auto-dns yes

nmcli con mod ethernet-2 connection.autoconnect no



nmcli dev wifi


nmcli general status && nmcli device show && nmcli connection show && echo -e "\t\t Now Processing a network readout..." && sleep 10 && nmcli dev wifi && nmcli -f CONNECTIONS device show && nmcli -f GENERAL,WIFI-PROPERTIES dev show wlan0 && nmcli device status &&  end





nmcli connection edit type wifi

nmcli> print all 



nmcli> print 802-11-wireless					## 


nmcli> set con.id My connection					## 




nmcli> goto connection							## enter into a setting or property for editing it.
nmcli connection> goto secondaries
nmcli> goto ipv4.addresses



echo "modifies 'autoconnect' property in the 'connection' setting of 'ethernet-2' connection."
nmcli con mod ethernet-2 connection.autoconnect no




echo ""
nmcli c a ifname eth0 type ethernet ipv6.method disabled ipv4.method link-local



echo ""
nmcli connection add type wifi autoconnect no ifname wlan0



echo "lists available Wi-Fi access points known to NetworkManager."
nmcli dev wifi






nmcli> verify
nmcli> verify fix
nmcli bond> verify
					## 



nmcli> remove wifi-sec
nmcli> remove eth.mtu
					## 

					## 

					## 

					## 

					## 



------------------------------------------------------------------------------
nmcli> print all 
===============================================================================
                       Connection profile details (wifi)
===============================================================================
connection.id:                          wifi
connection.uuid:                        dc7d1967-3bdd-4a33-bd0b-ce96908424f2
connection.stable-id:                   --
connection.interface-name:              --
connection.type:                        802-11-wireless
connection.autoconnect:                 yes
connection.autoconnect-priority:        0
connection.autoconnect-retries:         -1 (default)
connection.timestamp:                   0
connection.read-only:                   no
connection.permissions:                 
connection.zone:                        --
connection.master:                      --
connection.slave-type:                  --
connection.autoconnect-slaves:          -1 (default)
connection.secondaries:                 
connection.gateway-ping-timeout:        0
connection.metered:                     unknown
connection.lldp:                        -1 (default)
-------------------------------------------------------------------------------
802-11-wireless.ssid:                   --
802-11-wireless.mode:                   infrastructure
802-11-wireless.band:                   --
802-11-wireless.channel:                0
802-11-wireless.bssid:                  --
802-11-wireless.rate:                   0
802-11-wireless.tx-power:               0
802-11-wireless.mac-address:            --
802-11-wireless.cloned-mac-address:     --
802-11-wireless.generate-mac-address-mask:--
802-11-wireless.mac-address-blacklist:  
802-11-wireless.mac-address-randomization:default
802-11-wireless.mtu:                    auto
802-11-wireless.seen-bssids:            
802-11-wireless.hidden:                 no
802-11-wireless.powersave:              default (0)
-------------------------------------------------------------------------------
ipv4.method:                            auto
ipv4.dns:                               
ipv4.dns-search:                        
ipv4.dns-options:                       (default)
ipv4.dns-priority:                      0
ipv4.addresses:                         
ipv4.gateway:                           --
ipv4.routes:                            
ipv4.route-metric:                      -1
ipv4.ignore-auto-routes:                no
ipv4.ignore-auto-dns:                   no
ipv4.dhcp-client-id:                    --
ipv4.dhcp-timeout:                      0
ipv4.dhcp-send-hostname:                yes

echo "modifies 'autoconnect' property in the 'connection' setting of 'ethernet-2' connection."
nmcli con mod ethernet-2 connection.autoconnect no




echo ""
nmcli c a ifname eth0 type ethernet ipv6.method disabled ipv4.method link-local



echo ""
nmcli connection add type wifi autoconnect no ifname wlan0



echo "lists available Wi-Fi access points known to NetworkManager."
nmcli dev wifi





ipv4.dhcp-hostname:                     --
ipv4.dhcp-fqdn:                         --
ipv4.never-default:                     no
ipv4.may-fail:                          yes
ipv4.dad-timeout:                       -1 (default)
-------------------------------------------------------------------------------
ipv6.method:                            auto
ipv6.dns:                               
ipv6.dns-search:                        
ipv6.dns-options:                       (default)
ipv6.dns-priority:                      0
ipv6.addresses:                         
ipv6.gateway:                           --
ipv6.routes:                            
ipv6.route-metric:                      -1
ipv6.ignore-auto-routes:                no
ipv6.ignore-auto-dns:                   no
ipv6.never-default:                     no
ipv6.may-fail:                          yes
ipv6.ip6-privacy:                       -1 (unknown)
ipv6.addr-gen-mode:                     stable-privacy
ipv6.dhcp-send-hostname:                yes
ipv6.dhcp-hostname:                     --
ipv6.token:                             --
-------------------------------------------------------------------------------
proxy.method:                           none
proxy.browser-only:                     no
proxy.pac-url:                          --
proxy.pac-script:                       --
-------------------------------------------------------------------------------
nmcli> 




nmcli> print 802-11-wireless

['802-11-wireless' setting values]
802-11-wireless.ssid:                   --
802-11-wireless.mode:                   infrastructure
802-11-wireless.band:                   --
802-11-wireless.channel:                0
802-11-wireless.bssid:                  --
802-11-wireless.rate:                   0
802-11-wireless.tx-power:               0
802-11-wireless.mac-address:            --
802-11-wireless.cloned-mac-address:     --
802-11-wireless.generate-mac-address-mask:--
802-11-wireless.mac-address-blacklist:  
802-11-wireless.mac-address-randomization:default
802-11-wireless.mtu:                    auto
802-11-wireless.seen-bssids:            
802-11-wireless.hidden:                 no
802-11-wireless.powersave:              default (0)






nmcl i co nnecti o n sho w i d ' MyCafe' | g rep mtu

nmcl i co nnecti o n mo d i fy i d ' MyCafe' 80 2-11-wi rel ess. mtu 1350








nmcli dev mod em1 ipv4.method manual ipv4.addr "192.168.1.2/24, 10.10.1.5/8"

nmcli ipv4.addresses> set 192.168.1.100/24
nmcli ipv4.addresses> print

nmcli> set ipv4.gateway 192.168.1.1
           nmcli> verify
           Verify connection: OK
           nmcli> print







nmcli dev mod em1 +ipv4.dns 8.8.4.4
nmcli dev mod em1 -ipv4.dns 1



nmcli con mod my-con-em1 ipv4.dns "92.222.97.145 185.121.177.177"



nmcli> set ipv4.dns 92.222.97.145 192.99.85.244		## ParrotDNS

nmcli> set ipv4.dns 185.121.177.177					## OpenNIC


nmcli> print

nmcli> verify
nmcli> save






nmcli ipv4> print all



AP (Wi-Fi) or NSP (WiMAX)ant


nmcli device wifi list
nmcli -p -f general,wifi-properties device show wlan0
nmcli general permissions
pkaction --action-id org.freedesktop.NetworkManager.network-control --verbose



nmcli general logging

nmcli -t -f general -e yes -m tab dev show eth0



=$(nmcli dev | grep "ethernet" | grep -w "connected")

nmcli radio wifi on



nmcli connection edit type ethernet


nmcli connection edit type wifi

nmcli connection add type ethernet con-name "connection-name" ifname "*" mac 00:00:5E:00:53:00


nmcl i -p co n sho w




nmcli 

nmcli connection 

nmcli connection show --active
nmcli connection 
nmcli connection 
nmcli connection 
nmcli connection 
nmcli connection 
nmcli connection 
nmcli connection 
nmcli connection 
nmcli connection 
nmcli connection 
nmcli connection 











https://access.redhat.com/documentation/en-US/Red_Hat_Enterprise_Linux/7/html/Networking_Guide/sec-Network_Bridging_Using_the_NetworkManager_Command_Line_Tool_nmcli.html
