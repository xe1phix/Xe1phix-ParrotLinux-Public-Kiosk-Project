#!/bin/bash
##Extracting Live IPs from Nmap Scan

nmap 10.1.1.1 --open -oG scan-results; cat scan-results | grep "/open" | cut -d " " -f 2 > exposed-services-ips

##Simple Port Knocking

for x in 7000 8000 9000; do nmap -Pn –host_timeout 201 –max-retries 0 -p $x 1.1.1.1; done

##DNS lookups, Zone Transfers & Brute-Force

whois domain.com
dig {a|txt|ns|mx} domain.com
dig {a|txt|ns|mx} domain.com @ns1.domain.com
host -t {a|txt|ns|mx} megacorpone.com
host -a megacorpone.com
host -l megacorpone.com ns1.megacorpone.com
dnsrecon -d megacorpone.com -t axfr @ns2.megacorpone.com
dnsenum domain.com
nslookup -> set type=any -> ls -d domain.com
for sub in $(cat subdomains.txt);do host $sub.domain.com|grep "has.address";done

##Banner Grabbing

nc -v $TARGET 80
telnet $TARGET 80
curl -vX $TARGET

##NFS Exported Shares

##List NFS exported shares. If 'rw,no_root_squash' is present, upload and execute sid-shell​

showmount -e 192.168.110.102
chown root:root sid-shell; chmod +s sid-shell

##Kerberos User Enumeration

nmap $TARGET -p 88 --script krb5-enum-users --script-args krb5-enum-users.realm='test'

##HTTP Brute-Force & Vulnerability Scanning

target=10.0.0.1; gobuster -u http://$target -r -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,txt -t 150 -l | tee $target-gobuster
target=10.0.0.1; nikto -h http://$target:80 | tee $target-nikto
target=10.0.0.1; wpscan --url http://$target:80 --enumerate u,t,p | tee $target-wpscan-enum

##RPC / NetBios / SMB

rpcinfo -p $TARGET
nbtscan $TARGET

#list shares
smbclient -L //$TARGET -U ""

# null session
rpcclient -U "" $TARGET
smbclient -L //$TARGET
enum4linux $TARGET

##SNMP

# Windows User Accounts
snmpwalk -c public -v1 $TARGET 1.3.6.1.4.1.77.1.2.25

# Windows Running Programs
snmpwalk -c public -v1 $TARGET 1.3.6.1.2.1.25.4.2.1.2

# Windows Hostname
snmpwalk -c public -v1 $TARGET .1.3.6.1.2.1.1.5

# Windows Share Information
snmpwalk -c public -v1 $TARGET 1.3.6.1.4.1.77.1.2.3.1.1

# Windows Share Information
snmpwalk -c public -v1 $TARGET 1.3.6.1.4.1.77.1.2.27

# Windows TCP Ports
snmpwalk -c public -v1 $TARGET4 1.3.6.1.2.1.6.13.1.3

# Software Name
snmpwalk -c public -v1 $TARGET 1.3.6.1.2.1.25.6.3.1.2

# brute-force community strings
onesixtyone -i snmp-ips.txt -c community.txt

snmp-check $TARGET

##SMTP

smtp-user-enum -U /usr/share/wordlists/names.txt -t $TARGET -m 150

##Active Directory

# current domain info
[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()

# domain trusts
([System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()).GetAllTrustRelationships()

# current forest info
[System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()

# get forest trust relationships
([System.DirectoryServices.ActiveDirectory.Forest]::GetForest((New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Forest', 'forest-of-interest.local')))).GetAllTrustRelationships()

# get DCs of a domain
nltest /dclist:offense.local
net group "domain controllers" /domain

# get DC for currently authenticated session
nltest /dsgetdc:offense.local

# get domain trusts from cmd shell
nltest /domain_trusts

# get user info
nltest /user:"spotless"

# get DC for currently authenticated session
set l

# whoami on older Windows systems
set u