**SMB - Port 139/445**

enum4linux
enum4linux -v target-ip | Verbose mode, shows the underlying commands being executed by enum4linux
enum4linux -a target-ip | Do Everything, runs all options apart from dictionary based share name guessing
enum4linux -U target-ip | Lists usernames, if the server allows it - (RestrictAnonymous = 0)
enum4linux -u administrator -p password -U target-ip | If you've managed to obtain credentials, you can pull a full list of users regardless of the RestrictAnonymous option
enum4linux -r target-ip | Pulls usernames from the default RID range (500-550,1000-1050)
enum4linux -R 600-660 target-ip | Pull usernames using a custom RID range
enum4linux -G target-ip | Lists groups. if the server allows it, you can also specify username -u and password -p
enum4linux -S target-ip | List Windows shares, again you can also specify username -u and password -p
enum4linux -s shares.txt target-ip | Perform a dictionary attack, if the server doesn't let you retrieve a share list
enum4linux -o target-ip | Pulls OS information using smbclient, this can pull the service pack version on some versions of Windows
enum4linux -i target-ip | Pull information about printers known to the remove device.

nmblookup 
nmblookup -A target-ip

smbclient
smbclient -L //share -I target-ip -N
smbclient //share/subshare subshare -I target-ip

**SMTP - Port 25**

smtp-user-enum
smtp-user-enum -M VRFY -U /root/Desktop/unix-users-wordlist.txt -t target-ip

**Finger - Port 79**

finger-user-enum
perl finger-user-enum.pl -U /rppt/Desktop/unix-users-wordlist.txt -t target-ip

finger
finger user@target-ip

**NFS - Port 2049**
showmount
showmount -e target-ip

**RPC - Port 111**

RPCINFO
rpcinfo -p target-ip

RPCCLIENT
rpcclient -U "" -N target-ip
enumdomusers
enumdomgroups
getdompwinfo

**SNMP - Port 161**

snmp-check
snmp-check target-ip

**NETBIOS - Port 137**

nbtscan 
nbtscan target-ip

**HTTP/HTTPS** 

Nikto Scanner
nikto -h http://victimip -o /root/Desktop/victim/niktoscan.txt

Dirb Scanner
dirb http://victimip/ /Tools/SecLists/Discovery/Web-Content/common.txt -o /root/Desktop/victim/dirb.txt
dirb http://victimip/ /Tools/SecLists/Discovery/Web-Content/common.txt -X .zip,.tar,.gz,.tgz,.tar.gz,.7z,.rar -o /root/Desktop/victim/dirbsearchfiles.txt 

Gobuster Scanner
gobuster -u http://victimip/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt '200,204,301,307,403,500' -e | tee /root/Desktop/victim/gobusterdir.txt

EyeWitness
python EyeWitness.py -x /root/Desktop/website-name.xml --web --add-http-ports 3000
python EyeWitness.py -x /root/Desktop/website-name.xml --web 
python EyeWitness -f /root/Desktop/urls.txt --web

**HTTP/HTTPS (Subdomain Enumeration)**

Knock
sudo apt-get install python-dnspython
git clone https://github.com/guelfoweb/knock.git
cd knock
cd knockpy
chmod 755 knockpy.py
python knockpy.py google.com

**DNS (Zone Transfer) - Port 53**
dnsrecon -d google.com -t axfr

**HTTPS**

sslscan
sudo sslscan --no-colour target-ip
