#!/bin/sh
##-===============================================-##
##   [+] Firejail-Profile-Configuration-v4.7.sh
##-===============================================-##





include /etc/firejail/disable-common.inc
include /etc/firejail/disable-devel.inc
include /etc/firejail/disable-interpreters.inc
include /etc/firejail/disable-passwdmgr.inc
include /etc/firejail/disable-programs.inc
include /etc/firejail/disable-xdg.inc



whitelist ${HOME}/${DOCUMENTS}
whitelist ${HOME}/${DOWNLOADS}
whitelist ${HOME}/${PICTURES}
whitelist ${HOME}/${VIDEOS}


name $Firefox
nogroups
shell none
ipc-namespace


caps.drop all
protocol unix,inet

seccomp.block-secondary
memory-deny-write-execute


nonewprivs
noroot

disable-mnt

blacklist /usr/bin/gcc*
blacklist ${HOME}/.ssh
blacklist /tmp/ssh-*
blacklist /media/
blacklist /mnt/
blacklist /usr/local/bin
blacklist /boot/


blacklist ${HOME}/.bash_history
blacklist ${HOME}/.local/share/keyrings
blacklist ${HOME}/.gnupg
blacklist ${HOME}/.config/autostart
read-only ${HOME}/.local/share/applications




blacklist-nolog /usr/bin
blacklist-nolog /usr/bin/gcc*
blacklist-nolog /usr/sbin



include /etc/firejail/disable-common.inc
include ${HOME}/

mkdir ~/.mozilla
whitelist ~/.mozilla
mkdir ~/.cache/mozilla/firefox
whitelist ~/.cache/mozilla/firefox

read-only ~/.mozilla
read-only ~/.cache/mozilla/firefox

read-only /usr/lib/firefox/
read-only /usr/lib/firefox-esr/

read-only /etc/firefox
read-only /etc/firefox-esr

read-only /etc/
read-only /boot/
read-only /sbin/
read-only /usr/share/

overlay-tmpfs 
private 
private-home $PrivHome

cgroup /sys/fs/cgroup/g1/tasks
ipc-namespace

private-dev
private-tmp
private-cache

noexec $File|$Dir
no3d
nodvd
keep-var-tmp


private-etc
private-lib
private-opt
private-srv






read-only $File/$Dir
read-write $File/$Dir


tmpfs $dir

mkdir $dir
mkfile $file

bind $Dir1,$Dir2
bind $File1,$File2





tracelog


timeout hh:mm:ss
timeout 00:45:00





firejail --net=eth0 --scan


defaultgw 192.168.1.1
ip 192.168.1.37

iprange 192.168.1.100,192.168.1.150

## verify  IP addresses
sudo firejail --join-network=Firefox ip addr



## ###################################### ## 
## ______ FrozenDNS _______
## nameserver 92.222.97.144
## nameserver 92.222.97.145
## 
## _______ OpenDNS _________
## nameserver 208.67.222.222
## nameserver 208.67.220.220
## ###################################### ## 
firejail --ip=192.168.2.34 --dns=208.67.222.222
firejail --ip=192.168.2.34 --dns=208.67.220.220


dns 139.99.96.146
dns 185.121.177.177


firejail --dns.print=$PID



netfilter /usr/share/iptables/iptables.xslt
netfilter /etc/iptables/rules.v4
netfilter /etc/iptables/rules.v6
netfilter /etc/iptables/web-only.v4 
netfilter /etc/iptables/web-only.v6


netfilter /etc/firejail/webserver.net
netfilter /etc/firejail/nolocal.net


firejail --join-network=$Firefox bash -c "cat /etc/firejail/nolocal.net | /sbin/iptables-restore"


## verify netfilter configuration
firejail --join-network=$Firefox /sbin/iptables -vL


firejail --netfilter.print=$PID
firejail --netfilter6.print=$PID



net none


veth-name 

mac 
machine-id


sudo brctl addbr br0
sudo ifconfig br0 10.10.20.1/24
sudo brctl addbr br1
sudo ifconfig br1 10.10.30.1/24
firejail --net=br0 --net=br1


protocol unix,inet

dns 139.99.96.146
dns 37.59.40.15
dns 185.121.177.177


machine-id


overlay-tmpfs
private




## ----------------------------------------------- ##"
##  [+] Install a seccomp filter to block 
##      attempts to create memory mappings 
## ----------------------------------------------- ##"
##  [?] They could be both writable and executable,  
##      to change mappings to be executable 
##      or to create executable shared memory.
## ----------------------------------------------- ##"
memory-deny-write-execute










