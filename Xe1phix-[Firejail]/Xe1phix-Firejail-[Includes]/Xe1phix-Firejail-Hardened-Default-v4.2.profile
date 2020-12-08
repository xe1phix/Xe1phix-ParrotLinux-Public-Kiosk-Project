# This file is overwritten during software install.
# Persistent customizations should go in a .local file.
include /etc/firejail/default.local

# Persistent global definitions
include /etc/firejail/globals.local




blacklist /usr/bin/gcc*
blacklist ${HOME}/.bash_history
blacklist ${HOME}/.gnupg
blacklist ${HOME}/.ssh
blacklist /tmp/ssh-*
blacklist /media/
blacklist /mnt/
blacklist /boot/

read-only /etc/
read-only /sbin/
read-only /usr/bin
read-only /usr/share/




## ------------------------------------------------ ##
## read-only $File/$Dir
## read-write $File/$Dir
## noexec $File|$Dir
## ------------------------------------------------ ##
## tmpfs $dir
## ------------------------------------------------ ##
## mkdir $dir
## mkfile $file
## ------------------------------------------------ ##
## bind $Dir1,$Dir2
## bind $File1,$File2
## ------------------------------------------------ ##


include /etc/firejail/disable-common.inc
include /etc/firejail/disable-devel.inc
include /etc/firejail/disable-interpreters.inc
include /etc/firejail/disable-passwdmgr.inc
include /etc/firejail/disable-programs.inc
include /etc/firejail/disable-xdg.inc
include /etc/firejail/disable-exec.inc

apparmor
caps.drop all
seccomp
nogroups
nonewprivs
noroot
shell none

## net none
protocol unix,inet
## veth-name 
## mac 
## dns 139.99.96.146
## dns 37.59.40.15
## dns 185.121.177.177
## netfilter /etc/iptables/
## machine-id

## nodbus
no3d
notv
## nodvd
## novideo
## nosound


## tracelog
## timeout 00:45:00


private
## private-home $PrivHome
## overlay-tmpfs
## ipc-namespace
## cgroup /sys/fs/cgroup/g1/tasks
## disable-mnt


## private-bin 
## private-etc none
## private-lib
## private-opt
## private-srv
private-dev
private-cache
private-tmp

noexec ${HOME}
noexec /tmp

## seccomp.block-secondary
## memory-deny-write-execute