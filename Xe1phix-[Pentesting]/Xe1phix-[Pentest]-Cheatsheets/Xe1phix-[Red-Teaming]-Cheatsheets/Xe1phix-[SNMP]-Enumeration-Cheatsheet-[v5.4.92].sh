#!/bin/sh

##-=====================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<-##
##-=====================================================-##
##   [+] SNMP - Discovery + Enumeration + Pentesting
##-=====================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<-##
##-=====================================================-##



##  [+] Examples
snmpwalk -c public -v1 $TARGET 1.3.6.1.2.1.25.4.2.1.2
onesixtyone -c community -I $TARGET
snmpcheck -t $TARGET
snmpenum -t $TARGET


onesixtyone -i $line -o ../dir${domain}/snmponesixtyone_output.txt
onesixtyone -c /usr/share/sparta/wordlists/snmp-default.txt -o snmp_one_sixtyone${2}.txt


##  [+] Version3
nmap -sV -p 161 --script=snmp-info 192.168.1.0/24

##  [+] Wordlists
/usr/share/metasploit-framework/data/wordlists/snmp_default_pass.txt


##  [+] SNMP ENumeration:

snmpget -v 1 -c public IP version
snmpwalk -v 1 -c public IP
snmpbulkwalk -v 2 -c public IP

SNMP
----
onesixtyone -c /usr/share/doc/onesixtyone/dict.txt
Metasploit Module snmp_enum
snmpcheck -t snmpservice


snmpcheck -t $IP -c public

snmpenum -t $IP


##-============================-##
##  [+] SNMPv3 Enumeration
##-============================-##
nmap -sV -p 161 --script=snmp-info $IP/24


## ---------------------------------------------------------- ##
## [+]  Enumerate MIB:
## ---------------------------------------------------------- ##
## [•]  1.3.6.1.2.1.25.1.6.0		## System Processes
## [•]  1.3.6.1.2.1.25.4.2.1.2		## Running Programs
## [•]  1.3.6.1.2.1.25.4.2.1.4		## Processes Path
## [•]  1.3.6.1.2.1.25.2.3.1.4		## Storage Units
## [•]  1.3.6.1.2.1.25.6.3.1.2		## Software Name
## [•]  1.3.6.1.4.1.77.1.2.25		## User Accounts
## [•]  1.3.6.1.2.1.6.13.1.3		## TCP Local Ports



snmpwalk -c public -v1 $IP 1

Snmpwalk -c <community string> -v<version> $IP 1.3.6.1.2.1.25.4.2.1.2

onesixtyone -c names -i hosts

onesixtyone -d $IP



nmap -sU --open -p 161 $1
nmap -n -Pn -sV $IP -p $IP --script=snmp-netstat,snmp-processes -oN $OUTPUT/$IP:$PORT_snmp.nmap
onesixtyone -c public $IP | tee $OUTPUT/161_$IP-$PORT
onesixtyone -c /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings-onesixtyone.txt -dd $1 2>&1 | tee "snmp_onesixtyone_$1.txt"


snmpwalk -c public -v1 $IP | tee $OUTPUT/snmpwalk_$IP-$PORT
snmpwalk -c public -v1 $IP 1.3.6.1.4.1.77.1.2.25 | tee $OUTPUT/snmp_users_$IP-$PORT
snmpwalk -c public -v1 $IP 1.3.6.1.2.1.6.13.1.3 | tee $OUTPUT/snmp_ports_$IP-$PORT
snmpwalk -c public -v1 $IP 1.3.6.1.2.1.25.4.2.1.2 | tee $OUTPUT/snmp_process_$IP-$PORT
snmpwalk -c public -v1 $IP 1.3.6.1.2.1.25.6.3.1.2 | tee $OUTPUT/snmp_software_$IP-$PORT


snmpwalk -c public -v 1 $1 2>&1 | tee "snmpwalk.txt"
snmpwalk -c public -v 1 $1 1.3.6.1.2.1.25.1.6.0 2>&1 | tee "snmpwalk_system_processes.txt"
snmpwalk -c public -v 1 $1 1.3.6.1.2.1.25.4.2.1.2 2>&1 | tee "snmpwalk_running_processes.txt"
snmpwalk -c public -v 1 $1 1.3.6.1.2.1.25.4.2.1.4 2>&1 | tee "snmpwalk_process_paths.txt"
snmpwalk -c public -v 1 $1 1.3.6.1.2.1.25.2.3.1.4 2>&1 | tee "snmpwalk_storage_units.txt"
snmpwalk -c public -v 1 $1 1.3.6.1.2.1.25.6.3.1.2 2>&1 | tee "snmpwalk_software_names.txt"
snmpwalk -c public -v 1 $1 1.3.6.1.4.1.77.1.2.25 2>&1 | tee "snmpwalk_user_accounts.txt"
snmpwalk -c public -v 1 $1 1.3.6.1.2.1.6.13.1.3 2>&1 | tee "snmpwalk_tcp_ports.txt"





##-===========================================================-##
##  [+] SnmpWalk - start browsing through the
##                 MIB (management information base) tree.
##-===========================================================-##
snmpwalk -c public -v1 $IP


##-======================================================================-##
##  [+] extract only system users use this value 1.3.6.1.4.1.77.1.2.25,
##-======================================================================-##
snmpwalk -c public -v1 $IP <MIB value>

snmpwalk public -v1 $IP 1 |grep 77.1.2.25 |cut -d” “ -f4


## --------------------------------- ##
##  [+] Enumerating Windows Users:
## --------------------------------- ##
snmpwalk -c public -v1 $IP 1.3 |grep 77.1.2.25 |cut -d" " -f4


## ------------------------------------- ##
##  [+] Enumerating Running Services
## ------------------------------------- ##
snmpwalk -c public -v1 $IP 1 |grep hrSWRunName|cut -d" " -f4


## -------------------------------------- ##
##  [+] Enumerating installed software
## -------------------------------------- ##
snmpwalk -c public -v1 $IP 1 |grep hrSWInstalledName


## ----------------------------------- ##
##  [+] Enumerating open TCP ports
## ----------------------------------- ##
snmpwalk -c public -v1 $IP 1 |grep tcpConnState |cut -d"." -f6 |sort -nu



snmpbulkwalk -v 2 -c public IP



snmpget -v 1 -c public IP version



##  [+] Enmerate users from SNMP
snmpwalk public -v1 192.168.X.XXX 1 | grep 77.1.2.25 | cut -d” “ -f4
python /usr/share/doc/python-impacket-doc/examples/samrdump.py SNMP $TARGET


##  [+] Search SNMP with nmap
nmap -sT -p 161 192.168.1.0/24 -oG snmp_results.txt

