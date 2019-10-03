
sudo /usr/bin/gedit /etc/firejail/firefox.profile

addgroup firejail
chown root:firejail /usr/bin/firejail
chmod 4750 /usr/bin/firejail
ls -l /usr/bin/firejail
usermod -a -G firejail username

firecfg --fix-sound
sudo firecfg

cat /etc/firejail/firejail.users
sudo firecfg --add-users 



cat ~/Desktop/firefox.desktop
cat ~/.config/firejail/vlc.profile

firejail --list
firejail --shutdown=
firejail --join=


sudo mkdir /chroot
$ sudo debootstrap --arch=amd64 sid /chroot/sid
sudo firejail --noprofile --chroot=/chroot/sid
firejail --chroot=/chroot/sid
youtube-dl https://www.youtube.com/watch?v=Yk1HVPOeoTc
sudo firejail --noprofile --chroot=/chroot/sid


Start a root sandbox with a temporary OverlayFS filesystem
sudo firejail --noprofile --overlay-tmpfs


cat ~/.config/firejail/firefox-exr.profile
include /etc/firejail/firefox-esr.profile
iprange 192.168.1.100,192.168.1.240


cat ~/.config/firejail/transmission-qt.profile
include /etc/firejail/transmission-qt.profile
net eth0
iprange 192.168.1.100,192.168.1.240



include /etc/firejail/disable-terminals.inc
include /etc/firejail/disable-mgmt.inc
include /etc/firejail/disable-secret.inc
include /etc/firejail/disable-common.inc
include /etc/firejail/disable-devel.inc

whitelist ${DOWNLOADS}
mkdir ~/.mozilla
whitelist ~/.mozilla
mkdir ~/.cache
mkdir ~/.cache/mozilla
mkdir ~/.cache/mozilla/firefox
whitelist ~/.cache/mozilla/firefox
whitelist ~/.pki
include /etc/firejail/whitelist-common.inc


# HOME directory
blacklist ${HOME}/.ssh
tmpfs ${HOME}/.gnome2_private
blacklist ${HOME}/.gnome2/keyrings
blacklist ${HOME}/kde4/share/apps/kwallet
blacklist ${HOME}/kde/share/apps/kwallet
blacklist ${HOME}/.pki/nssdb
blacklist ${HOME}/.gnupg
blacklist ${HOME}/.local/share/recently-used.xbel


# Chromium browser profile
include /etc/firejail/disable-mgmt.inc
include /etc/firejail/disable-secret.inc
blacklist ${HOME}/.adobe
blacklist ${HOME}/.macromedia
blacklist ${HOME}/.mozilla

caps.keep sys_chroot,sys_admin,sys_time,sys_tty_config,wake_alarm

blacklist /boot
blacklist /mnt
blacklist /run/media


disable mprotect:
setfattr -n user.pax.flags -v "m" /usr/bin/problematic_binary

disable emutramp:
setfattr -n user.pax.flags -v "em" /usr/bin/problematic_binary



whitelist ${DOWNLOADS}
whitelist ~/.config/chromium
whitelist ~/.cache/chromium
include /etc/firejail/whitelist-common.inc 

read-only ${HOME}/.config/chromium/Default/Preferences
read-only ${HOME}/.config/chromium/Default/Bookmarks

tmpfs ${HOME}/.config/chromium/Default/Peppe*
tmpfs ${HOME}/.cache/chromium/Default/Cache/
blacklist ${HOME}/.adobe
blacklist ${HOME}/.macromedia
blacklist ${HOME}/.mozilla

blacklist /mnt


# Prevent manipulation of firejail configuration
blacklist /etc/firejail
blacklist ${HOME}/.config/firejail





blacklist ${HOME}/.adobe
blacklist ${HOME}/.macromedia
blacklist ${HOME}/.icedove
blacklist ${HOME}/.thunderbird
blacklist ${HOME}/.config/midori
blacklist ${HOME}/.config/opera
blacklist ${HOME}/.config/chromium
blacklist ${HOME}/.config/google-chrome


# Instant Messaging
blacklist ${HOME}/.purple

############## disable-history.inc #################
# History files in $HOME
blacklist ${HOME}/.history




whitelist ~/Downloads
whitelist ~/.config/chromium


firejail --private firefox -no-remote

cat ~/.config/firejail/vlc.profile
include /etc/firejail/vlc.profile
net none



firejail --whitelist=~/t --read-only=~/t



firejail --private=/home/username/work thunderbird &



firejail –read-only=${HOME} –read-write=${HOME}/test/




firejail --net=eth0 --ip=192.168.1.207 firefox
firejail --net=eth0 --netfilter=/etc/firejail/nolocal.net firefox


firejail –name=firefox –private-home=.mozilla –noexec=/tmp –nogroups –nonewprivs –dns=156.154.70.2 –dns=156.154.71.2 firefox -no-remote -private-window -P profile-2
 firejail –name=firefox –private-home=.mozilla –noexec=/tmp –nogroups –nonewprivs –dns=156.154.70.2 –dns=156.154.71.2 firefox -no-remote -private-window -P profile-3
 

firejail --caps.keep=setgid,setuid,net_bind_service /etc/init.d/nginx start
firejail --caps.keep=setgid,setuid,net_bind_service,chown /etc/init.d/nginx start

(nginx web server)
# firejail --caps.keep=chown,net_bind_service,setgid,setuid --seccomp /etc/init.d/nginx start

(apache web server)
# firejail --caps.keep=chown,sys_resource,net_bind_service,setuid,setgid --seccomp /etc/init.d/apache2 start

(net-snmp server)
# firejail --caps.keep=net_bind_service,setuid,setgid --seccomp /etc/init.d/snmpd start
# firejail --caps.keep=net_bind_service,setuid,setgid --seccomp /usr/sbin/snmptrapd start

(ISC DHCP server)
# firejail --caps.keep=net_bind_service,net_raw --seccomp /etc/init.d/isc-dhcp-server start


firejail –apparmor –caps.keep=chown,net_bind_service,setgid,setuid,dac_override –noprofile –seccomp nginx





force-nonewprivs yes


cd ~/.config/firejail
$ cp /etc/firejail/transmission-gtk.profile .
cat transmission-gtk.profile

caps.drop all
protocol unix,inet,inet6
netfilter
noroot
tracelog
shell none
seccomp.keep poll,select,nanosleep,futex,epoll_wait,fadvise64,read,lstat,stat,epoll_ctl,sendto,readv,recvfrom,ioctl,write,inotify_add_watch,writev,socket,getdents,mprotect,mmap,open,close,fstat,lseek,munmap,brk,rt_sigaction,rt_sigprocmask,access,pipe,madvise,connect,sendmsg,recvmsg,bind,listen,getsockname,getpeername,socketpair,setsockopt,getsockopt,clone,execve,uname,fcntl,ftruncate,rename,mkdir,rmdir,unlink,readlink,umask,getrlimit,getrusage,times,getuid,getgid,geteuid,getegid,getresuid,getresgid,statfs,fstatfs,prctl,arch_prctl,epoll_create,set_tid_address,clock_getres,inotify_rm_watch,set_robust_list,fallocate,eventfd2,inotify_init1,pwrite64,time,exit,exit_group



