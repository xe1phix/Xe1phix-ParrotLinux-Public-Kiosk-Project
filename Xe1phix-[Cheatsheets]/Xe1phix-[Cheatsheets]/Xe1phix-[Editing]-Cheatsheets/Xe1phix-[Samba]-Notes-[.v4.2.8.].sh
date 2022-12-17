#!/bin/sh


mkdir -p /home/samba/sambashare
chown -R root:sambashare /home/samba/sambashare
chmod -R 0770 /home/samba/sambashare
mkdir -p /home/samba/guest
chown -R nobody:nogroup /home/samba/guest
chmod -R 0775 /home/samba/guest

systemctl restart nmbd.service
systemctl restart smbd.service


## see which shares are available on a given host:
smbclient -L localhost


## Get a list of all browsable Samba shares on the target server.
smbclient -N -gL \\SambaServer 2>&1 | grep -e "Disk|" | cut -d'|' -f2



## 
ps axuww | egrep 'PID|samba|smbd|nmbd|winbindd'


## 
pkill samba smbd nmbd winbindd


## 
samba-tool domain provision --use-rfc2307 \
	 --realm=CORP.EXAMPLE.COM --domain=CORP \
	 --server-role=dc --dns-backend=BIND9_DLZ


## 
samba-tool user password --user=administrator


## List all files opened by a particular command
lsof -c dhcpd


## get IPs with a DHCP lease
egrep "^lease" /var/lib/dhcp/db/dhcpd.leases |awk '{ print $2 }'


## sorted list of dhcp allocations
grep ^lease /var/lib/dhcp/dhcpd.leases | cut -d ' ' -f 2 | sort -t . -k 1,1n -k 2,2n -k 3,3n -k 4,4n | uniq


## follow DNS Bind named log
journalctl --unit=named --follow

## 
/etc/samba/smb.conf
log file = /var/log/samba/%m.log
logging = syslog
syslog only = yes
logging = systemd


/etc/rsyslog.conf
## Log SAMBA audit information
	local3.*			/var/log/samba_audit.log

## 
systemctl restart rsyslog


## 
ps -axwwo user,pid,ppid,pgid,command


## determine theSamba server’s smbd daemon’s process ID
systemctl status smb | grep PID

## using the ss command to list any ports on which the daemon is listening:
ss -utlpn | grep 6869



## get the system’s hostname:
nmblookup -S server-hostname


## use NetBIOS over TCP to look up NetBIOS names
nmblookup -A


smbstatus -d 10		(debug)


## becoming anActive Directory member (or joining a domain) is
net mode join -U administrator-username



net status shares
net status sessions

## Stop or Start (Restart) a Windows service from a Linux machine
net rpc -I ADDRESS -U USERNAME%PASSWORD service {stop|start} SVCNAME


## 
smbcontrol smbd reload-config


## Mount a Windows share on the local network (Ubuntu) with user rights and use a specific samba user
mount -t cifs -o user,username="samba username" //$ip_or_host/$sharename /mnt

mount -t cifs -o credentials=/path/to/credenials //hostname/sharename /mount/point
mount -t cifs -o username=[USER] //[IP_SERVER]/[USER_FOLDER] /[DIR]/[USER]




## Unmount all mounted SAMBA/Windows shares
umount -t smbfs
mount|grep -e '//'|cut -d ' ' -f3| xargs -I {} umount {}


## List all Samba user name
pdbedit -w -L | awk -F":" '{print $1}'



## 
alias nbtstat='nmblookup -S -U <server> -R'


## RESTORE - SERVER
tdbdump passdb.tdb.bak > passdb.dumpfile
tdbrestore passdb.tdb < passdb.dumpfile



