-------------------------------------------------------------------------------------------------------------------------------------
#CLI Shortcut Keystrokes

ctrl + shift + 6 #cancel command
? at the command prompt #Lists all commands available for a particular command mode
[Ctrl][A] Jumps to the first character of the command line
[Ctrl][E] Jumps to the endo f the command line
command ? #Lists the keywords, arguments, or both associated with a command
#Completes a partial command name
switch(config)#t 
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
the main command modes for the switch:
    User EXEC                                   Switch>    logout,enable(enter privileged EXEC mode)  
    Privileged EXEC                             Switch#    disable(exit to user EXEC mode),configure(enter global configuration mode)    
    Global configuration                        Switch(config)#    exit(exit to privileged EXEC mode),interface(enter interface configuration mode)    
    Interface configuration                     Switch(config-if)#     end(exit to privileged EXEC mode),exit(exit to global configuration mode)
    VLAN configuration                          Switch(config-vlan)#     exit(exit to global configuration mode),end(exit to privileged EXEC mode)  
    Line configuration                          Switch(config-line)#     exit(exit to global configuration mode),end(exit to privileged EXEC mode)  
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
Switch1>enable
Switch1#configure terminal

Switch# configure
Configuring from terminal, memory, or network [terminal]? 
#terminal 	Executes configuration commands from the terminal.
#memory 	For all platforms except the Cisco 7000 family, executes the commands stored in NVRAM
#network 	The copy rcp running-config or copy tftp running-config command replaces the configure network command

Internetwork operating system (IOS)
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
RAM — The running configuration file is stored
ROM —stores a bootstrap program that is loaded when the switch first powers on. This program finds the full Cisco IOS image and loads it into RAM
Flash memory —stores fully functional Cisco IOS images and is the default location where the switch gets its Cisco IOS at boot time
NVRAM — Nonvolatile RAM (NVRAM) stores the initial or startup configuration file that is used when the Cisco device is powered on or reloaded

running configuration #This configuration is only active in RAM, pull the plug and it’s gone
startup configuration #saved in NVRAM,next time boot switch, looks for the startup configuration and use it 
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
Gigabit Interface 1/0/1 #1st module of the switch and its port number 0/1
Gigabit Interface 1/0/1 # 0 stands for #0 slot,all interfaces in slot 0,FastEthernet 0/0 or FastEthernet 0/24,expansion slots have slot 0
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
commands
show is for reporting
debug is for monitoring

Switch# debug snmp packet
Switch# no debug snmp packet #disable debugging output, use the no form of this command. 
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
#the default VLAN 1 acts like the switch’s own NIC for connecting into a LAN to send IP packets.
#switch default IP address
Switch# show interfaces vlan 1

Switch# show interfaces status  #Show interface line status
Switch# show interfaces vlan VLANID  # CIDR, network mask,make sure switch virtual interface (SVI) configured for each VLAN and that the SVI is in an up/up state.
show interfaces description #generally indicate whether Layer 1 is working (line status) and whether Layer 2 is working (protocol status)

#FastEthernet 0 is up and operating, refers to the physical layer
#line protocol is up,refers to the Data Link Layer
show interface fastethernet 0

FastEthernet0 is up, line protocol is up #Both the Physical and Data Link layers on the interface are functioning correctly
FastEthernet0 is down, line protocol is down #indicates a physical interface problem. For example, the cable on this interface or on the remote interface is disconnected.
FastEthernet0 is up, line protocol is down #Physical layer is operational. The line protocol being down indicates a clocking or framing problem.Probable reasons for this are encapsulation and clock rate mismatches.
Ethernet0 is administratively down, line protocol is down #local interface has been manually shut down using the shutdown command.
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
ping 172.17.4.6 source Ethernet 0/0 #ping from the particular interface by adding the source parameter with the interface name at the end of the command
traceroute 10.10.60.6 source Loopback0
telnet 172.17.5.74 8080 #test whether a remote device is listening to the specific por


------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
Switch> ?  #display a comprehensive list of commands, enter a question mark (?) at the prompt
Switch# ?  #display a comprehensive list of commands, enter a question mark (?) at the prompt
Switch(config)# ?

------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
#sh running-config
#sh running-config | include snmp-server #check current SNMP settings 
#sh run | include snmp
#show running-config | include helper-address #check current DHCP helper settings 
#show running-config interface Vlan VLANID
#show running-config vlan VLANID
#show running-config | include interface Vlan
#show running-config | include interface Vlan | ip address
#show running-config | include hostname #query hostname

#sh run | i ^_ip address #i means include, ^ means beginning of line, _ means one space
#sh run | i ^interface|^_ip address 
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
#show mac address-table
#show mac address-table vlan VLANID
#show mac address-table dynamic #all MAC addresses that the switch has learned

#show mac address-table address DEVICEMACADDRESS #pc,phone,telephone,printer etc

#switch#show mac address-table int gi1/0/34  #find vlan,MAC address
#switch#show ip arp vlan 132 | include 001b.78d5.a2d7 #find IP of the device

#show ip arp
#show ip arp vlan VLANID
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
#show ip route
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
#show ip interface # provide details regarding layer 3 configuration on the interfaces
#show ip interface brief # IP address of LAYER 3 interface
#show ip interface brief | include up #the active (connected ports) , active(online) VLANs
#show ip arp Vlan VLANID #online IP list withing VLANNAME
#show interface status # ports,vlans



#show interfaces status #pick gigabitEthernet
#show interfaces gigabitEthernet 1/0/25
#show interfaces gigabitEthernet 1/0/19 vlan mapping # list all of the VLAN mappings that are configured on a port and indicate whether such mappings are enabled or disabled on the port
#show running-config interface gigabitEthernet 1/0/19 #shows interface information on Gigabit Ethernet interface 1/0/19 
#show ip interface gigabitEthernet 1/0/19  #shows interface information on Gigabit Ethernet interface 1/0/19 
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
#VLAN Troubleshooting
show vlan
show interfaces vlan
show interfaces vlan (#)
show interfaces trunk
show run interface gi1/0/8
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

Switch# sh version/show version #Cisco IOS version etc
Switch# show vlan
Switch# show vlan brief
Switch# show vlan brief | include Gi1/X/X
Router# show vlan id 1-4,3,7,5-20
Router# show vlan id 10 ifindex 
Router# show vlan free 
Switch# sh interfaces summary
Switch# sh interfaces description
Switch# show ip access-lists #Displays IP ACLs configured on the switch. 
Switch# sh vlan summary
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
show inventory
show env {all | fan | power | rps | stack [switch-number] | temperature} [ | {begin | exclude | include}
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

#show flash #all files,contents of flash memory
#show version | include image file # currently running file
System image file is "bootflash:/isr4300-universalk9.03.16.05.S.155-3.S5-ext.SPA.bin"
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
#When a Cisco device boots up, CDP starts up by default. CDP automatically discovers neighboring Cisco devices running CDP, regardless of which Layer 3 protocol or suites are running. 
#CDP exchanges hardware and software device information with its directly connected CDP neighbors
show cdp neighbors
show cdp neighbors detail
#show cdp neighbors Gig 1/0/24 #check the neighbor of that port
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
#show archive log config all
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
#show logging #display the state of logging (syslog)
#show logging history
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
#show history
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
Switch(config)#hostname LOCAL-SWITCH
#Configure the message of the day as "Unauthorized access is forbidden"
Switch(config)#banner motd #
Unauthorized access is forbidden#
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

Switch(config)#line vty 0 15 #Configure TELNET access 
witch(config-line)#exec-timeout 8 20
Switch(config-line)#password ciscotelnet
Switch(config-line)#logging synchronous
Switch(config-line)#login
Switch(config-line)#history size 15
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

Switch(config)#line con 0 #Configure CONSOLE access
Switch(config-line)#password ciscoconsole
Switch(config-line)#logging synchronous
Switch(config-line)#login
Switch(config-line)#history size 15
Switch(config-line)#exec-timeout 6 45
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
SNMP v3
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

Switch(config)#no snmp-server user user1 group1 v3 #remove user

Switch(config)#no snmp-server group group1  v3 priv #remove group
Switch(config)#no snmp-server group group1  v3 noauth
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
Delete the current Read-only (RO) community string
Router(config)#no snmp-server community public RO (where "public" is the Read-only community string)
Delete the current Read-write (RW) community string with this command: 
Router(config)#no snmp-server community private RW (where "private" is the Read-write community string) 

disable all SNMP
Switch#config term
Switch(config)#no snmp-server
Switch(config)#Ctrl-z

Switch#copy running-config startup-config (this copies the current running configuration so that when it's rebooted it comes back)

Switch# show startup-config #the config that is saved to NVRAM

Switch# show running-config #displays the config that is in the router RAM and the IOS is currently running on

Switch# wr mem #Write to NV memory
Switch(config)#do wr mem
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
#v3
show snmp
show snmp group
show snmp user
show snmp engineID

snmp-server manager #start the Simple Network Management Protocol (SNMP) manager process, use the snmp-server manager command in global configuration mode
no snmp-server manager #stop the SNMP manager process
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
snmp-server view ViewDefault iso included 
snmp-server group GrpMonitoring v3 priv read ViewDefault
snmp-server user UserJustMe GrpMonitoring v3 auth sha AuthPass1 priv aes 128 PrivPass2

snmp-server group GrpMonitoring v3 priv
snmp-server user UserJustMe GrpMonitoring v3 auth sha AuthPass1 priv aes 128 PrivPass2
snmp-server host mgmt 10.1.1.161 version 3 UserJustMe

snmp-server user UserJustMe network-admin v3 auth sha AuthPass1 priv aes-128 PrivPass2
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
