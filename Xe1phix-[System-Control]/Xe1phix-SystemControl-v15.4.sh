#!/bin/sh
## Xe1phix-SystemControl-v1.3.sh



## /sbin/grubby --update-kernel=ALL --args="audit=1"
/sbin/grubby --update-kernel=ALL --args="security=apparmor apparmor=1"

sed --follow-symlinks -i "s/selinux=0//gI" /etc/grub.conf
sed --follow-symlinks -i "s/enforcing=0//gI" /etc/grub.conf


grub-mkpasswd-pbkdf2 

set superusers="Xe1phix"
grub-mkpasswd-pbkdf2 xe1phix $Pass


id -Z
unconfined_u:unconfined_r:unconfined_t


sestatus | grep "Loaded policy"

sestatus | grep mode

## Switch to the permissive mode
setenforce 0
echo 0 > /sys/fs/selinux/enforce


setsebool -P secure_mode_policyload on

semanage permissive -l

semanage user -l


##  [+]  chcat utility can be used to assign categories to users
chcat -L


stat dokuwiki | grep Context
Context: system_u:object_r:httpd_sys_rw_content_t


semanage fcontext -l



/.*                         system_u:object_r:default_t
/usr/.*                     system_u:object_r:usr_t
/usr/(.*/)?lib(/.*)?        system_u:object_r:lib_t

chcon -R -t httpd_sys_content_t /srv/www


## semanage fcontext -a -t httpd_sys_content_t "/srv/www(/.*)?"
## restorecon -R /srv/www





ausearch -m avc -ts recent



tcontext=system_u:object_r:mount_var_run_t:s0

scontext=system_u:system_r:dnsmasq_t
tcontext=system_u:object_r:sysctl_net_t




seinfo | grep -E '(dontaudit|allow)'

ausearch –m avc –ts today | audit2why

scanelf -n /bin/ls



grep ^SELINUX= /etc/selinux/config
SELINUX=enforcing

/etc/selinux/semanage.conf

cat /sys/fs/selinux/mls
sestatus | grep MLS

sestatus | grep deny_unknown

/etc/selinux/targeted/modules/active


/etc/selinux/targeted/policy
/etc/selinux/strict/policy



adduser --shell /usr/bin/firejail user


adduser --shell /usr/bin/firejail xe1phix
usermod --shell /usr/bin/firejail xe1phix
chpasswd --crypt-method SHA512 --sha-rounds 5000
usermod -aG wheel parrotkios

sudo firecfg
firecfg --list
sudo firecfg --clean





git clone https://github.com/netblue30/firejail.git
cd firejail
./configure && make && sudo make install-strip
./configure --prefix=/usr --enable-apparmor

aa-enforce firejail-default




aa-enforce firejail-default



setpriv --dump



setpriv --no-new-privs 


setpriv --reuid=1000 --regid=1000 --caps=-all

## create the mount ns with owning user ns
nsenter --user=$usernspath unshare --mount sleep 10 &

usermod --uid 101 user 

sudo deluser --group bluetooth
sudo deluser --group sambashare


usermod --shell /usr/sbin/nologin user
usermod --lock user
shadowconfig on


cat /etc/passwd
/etc/firejail/login.users
cat /etc/firejail/firejail.users



## Replace /bin/bash with a restricted firejail shell

cat /etc/shells

sudo usermod --shell /usr/sbin/nologin 
sudo usermod --shell /bin/false


sudo adduser --shell /usr/bin/firejail user
sudo usermod --shell /usr/bin/firejail user

sudo usermod --shell /usr/bin/firejail mysql
sudo usermod --shell /usr/sbin/nologin mysql
sudo usermod --shell /usr/bin/firejail postgres
sudo usermod --shell /usr/sbin/nologin postgres

/var/lib/postgresql

sudo usermod --shell /usr/sbin/nologin arpwatch
sudo usermod --shell /usr/sbin/nologin mixmaster













auditctl -a exit,always -F arch=b64 -S all -F path=/usr/bin/chromium -F key=MonitorChromium



curl --verbose --progress-bar --tlsv1 --url https://sks-keyservers.net/sks-keyservers.netCA.pem --output /home/amnesia/Gnupg/sks-keyservers.netCA.pem
curl --verbose --progress-bar --tlsv1 --url https://sks-keyservers.net/sks-keyservers.netCA.pem.asc --output /home/amnesia/Gnupg/sks-keyservers.netCA.pem.asc && apt-key add /home/amnesia/Gnupg/sks-keyservers.netCA.pem.asc
curl --verbose --progress-bar --tlsv1 --url https://sks-keyservers.net/ca/crl.pem --output /home/amnesia/Gnupg/crl.pem



gpg --keyserver x-hkp://pool.sks-keyservers.net --recv-keys 0x

https://sks-keyservers.net/ca/crl.pem
https://sks-keyservers.net/sks-keyservers.netCA.pem.asc
keyserver hkps://hkps.pool.sks-keyservers.net
keyserver-options ca-cert-file=/etc/ssl/certs/sks-keyservers.netCA.pem


curl --resolve 127.0.0.1:4444:http://killyourtv.i2p/killyourtv.asc 
https://blog.patternsinthevoid.net/isis.txt



Wlan="wlan0"
Alpha="wlan1"
VPN="tun0"
LOOPBACK="lo"
echo "###############################################################"
echo -e "\t [+] Establish Subnetting Criteria Environment Variables:"
echo "###############################################################"
CLASS_A="10.0.0.0/8"                # Class A private networks
CLASS_B="172.16.0.0/12"             # Class B private networks
CLASS_C="192.168.0.0/16"            # Class C private networks
CLASS_D_MULTICAST="224.0.0.0/4"         # Class D multicast addr
CLASS_E_RESERVED_NET="240.0.0.0/5"      # Class E reserved addr
BROADCAST_SRC="0.0.0.0"             # Broadcast source addr
BROADCAST_DEST="255.255.255.255"        # Broadcast destination addr
echo "###############################################################"



echo "alias history='history | cut -c8-199' " >> ~/.bashrc
echo "alias history='history | cut -c8-199' " >> /root/.bashrc


I2PUSER="i2psvc"
MODPROBE=/sbin/modprobe
IPTABLES=/sbin/iptables
IP6TABLES=/sbin/ip6tables
IPTABLES_RESTORE="$IPTABLES-restore"



SourcesList=/etc/apt/sources.list
resolution=$(xdpyinfo | grep 'dimensions:' | awk -F" " {'print $2'} | awk -F"x" {'print $1'})



/sys/kernel/debug/tracing/



renice +7 $(pgrep vlc)





udisksctl dump
udisksctl status


udisksctl info {--object-path OBJECT | --block-device

udisksctl mount {--object-path OBJECT | --block-device DEVICE} [--filesystem-type TYPE] [--options

udisksctl unmount --block-device /dev/sdc
udisksctl power-off {--object-path OBJECT | --block-device 

udisksctl loop-setup --file PATH [--read-only] [--offset OFFSET] [--size



grub‐install /dev/sda


sudo perl ‐pi ‐e 's,GRUB_CMDLINE_LINUX="(.*)"$,GRUB_CMDLINE_LINUX="$1 apparmor=1 security=apparmor",' /etc/default/grub


sudo update‐grub
sudo reboot

ApparmorProfiles=/etc/apparmor.d/"$1"
ApparmorModule=/sys/module/apparmor
aafs=/sys/kernel/security/apparmor
params=$module/parameters



/etc/init.d/apparmor start
/etc/init.d/apparmor restart


mount -tsecurityfs securityfs /sys/kernel/security

cat /sys/module/apparmor/parameters/enabled
cat /sys/kernel/security/apparmor/profiles
cat /sys/kernel/security/apparmor/policy/profiles/firejail-default.0/mode
cat /sys/module/apparmor/parameters/enabled


cat /sys/module/apparmor/parameters/enabled
aa-notify -p -f /var/log/audit/audit.log --display $DISPLAY



cat /etc/apparmor.d/$Profile | sudo apparmor_parser -a                  ## Load A New Profile
cat /etc/apparmor.d/$Profile | sudo apparmor_parser -r                  ## Reload An Existing Profile

apparmor_parser -a /etc/apparmor.d/<profile>
apparmor_parser -r /etc/apparmor.d/<profile>

sudo /etc/init.d/apparmor reload
sudo /etc/init.d/apparmor start


##-=================================-##
##  [+] Update An AppArmor Profile
##-=================================-##
sudo genprof firefox
sudo aa-logprof firefox
sudo apparmor_parser -r /etc/apparmor.d/<profile>
/etc/init.d/apparmor restart



cat /sys/module/apparmor/parameters/enabled

aa-status --verbose
cat /sys/kernel/security/apparmor/profiles
cat /proc/mounts | grep securityfs


/sbin/apparmor_parser -r -W "$profile"


sudo aa-notify -p -f /var/log/audit/audit.log

## Responding to policy changes automatically
aa-policy daemon

## Show processes that are unconfined
grep -L unconfined /proc/*/attr/current


## show the permissions granted when the user owns the 
## resource (file, directory, pipe, etc.) 
apparmor_parser -Q --debug /etc/apparmor.d/usr.bin.firefox | head -10



sudo cat /sys/kernel/security/apparmor/profiles | grep firejail


## put all profiles into complain mode:
sudo aa-complain /etc/apparmor.d/*				## put all profiles into complain mode:


## put all profiles into enforcing mode:
sudo aa-enforce /etc/apparmor.d/*								## put all profiles into enforcing mode:

## Enable Firefox Profile
sudo aa-enforce /etc/apparmor.d/usr.bin.firefox

## Reload profiles
apparmor_parser -r /etc/apparmor.d/*


## set all "extra" profiles to complain mode
cd /usr/share/doc/apparmor‐profiles/extras
cp ‐i *.* /etc/apparmor.d/
for f in *.* ; do aa‐complain /etc/apparmor.d/$f; done


aa-notify -p -f /var/log/audit/audit.log --display $DISPLAY



echo "##-=============================================================-##"
echo "         [+] Enforcing Your TorBrowser AppArmor Profile..."
echo "##-=============================================================-##"
sudo aa-enforce /etc/apparmor.d/usr.bin.torbrowser-launcher
sudo aa-enforce /etc/apparmor.d/torbrowser.start-tor-browser
sudo aa-enforce /etc/apparmor.d/torbrowser.Browser.firefox
sudo aa-enforce /etc/apparmor.d/torbrowser.Tor.tor

torbrowser_firefox
torbrowser_plugin_container

torbrowser_tor (enforce)
usr.bin.thunderbird

usr.bin.i2prouter
system_i2p

usr.sbin.ntpd

firejail-default


sbin.syslogd                             usr.sbin.apt-cacher-ng
sbin.syslog-ng


usr.sbin.dnsmasq




sysctl -w net.ipv6.conf.default.disable_ipv6="1"
sysctl -w net.ipv6.conf.all.disable_ipv6="1"
sysctl -q -w net.ipv6.conf.all.disable_ipv6="1"
sysctl -w net.ipv6.conf.lo.disable_ipv6="1"

sysctl -w net.ipv6.conf.all.autoconf="0"


sysctl -w net.ipv6.conf.all.accept_redirects="0"

sysctl -w net.ipv6.conf.all.accept_dad="0"
sysctl -w net.ipv6.conf.all.accept_ra="0"
sysctl -w net.ipv6.conf.all.dad_transmits="0"
sysctl -w net.ipv6.conf.default.router_solicitations="0"


sysctl -w net.ipv6.conf.all.accept_redirects=0
sysctl -w net.ipv6.conf.all.send_redirects=0

sysctl -w kernel.exec-shield=1
sysctl -w net.ipv4.tcp_syncookies=1
sysctl -w net.ipv4.conf.all.accept_redirects=0
sysctl -w net.ipv4.conf.all.send_redirects=0

sysctl -w net.ipv4.conf.all.rp_filter=1
sysctl -w net.ipv4.conf.default.rp_filter=1
sysctl -w net.ipv4.conf.lo.rp_filter="1"
net.ipv4.conf.eth0.rp_filter=1

sysctl -w net.ipv4.conf.default.arp_filter=1
sysctl -w net.ipv4.conf.eth0.arp_filter=


sysctl -w net.ipv4.icmp_echo_ignore_all=1

sysctl -w net.ipv4.tcp_timestamps=

sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1

sysctl -w net.ipv4.icmp_ignore_bogus_error_responses=1

sysctl -w net.ipv4.conf.all.log_martians=1
sysctl -w net.ipv4.conf.default.log_martians=1
sysctl -w net.ipv4.conf.eth0.log_martians="1"
sysctl -w net.ipv4.conf.lo.log_martians="1"

sysctl -w dev.cdrom.debug=1
sysctl -w dev.cdrom.check_media="1"
sysctl -w dev.scsi.logging_level="1"
sysctl -q -w net.netfilter.nf_conntrack_timestamp="1"
sysctl -q -w net.ipv4.tcp_timestamps="1"
sysctl -w fs.suid_dumpable=0
cat /proc/sys/fs/suid_dumpable
sysctl -w kernel.ctrl-alt-del=0


sysctl -w kernel.dmesg_restrict=1                                                    ## This toggle indicates whether unprivileged users are prevented from using dmesg(8) to view messages from the kernel's log buffer.
sysctl -w kernel.stack_tracer_enabled="1"
sysctl -w noexec_user_stack="1"
sysctl -w noexec_usr_stack_log="1"
set noexec_user_stack=1
set noexec_usr_stack_log=1
sysctl -w kernel.randomize_va_space="2"
sysctl -w kern.securelevel="2"
sysctl -w kernel.kptr_restrict="1"                  ## This toggle indicates whether restrictions are placed on exposing kernel addresses via /proc and other interfaces.

echo "#Enable ExecShield protection"
sysctl -w kernel.exec-shield="1"
set kernel.exec-shield="1"
sysctl -w kernel.sysctl_writes_strict="1"
echo "#Enabling kernels use of pids"
sysctl -w kernel.core_uses_pid="1"   # Controls whether core dumps will append the PID to the core filename
sysctl -w kernel.randomize_va_space="2"

printk_devkmsg="ratelimit"                          ## Control the logging to /dev/kmsg from userspace
perf_event_paranoid="2"                             ## Controls use of the performance events system by unprivileged users (without CAP_SYS_ADMIN).  The default value is 2.

sysctl -w kernel.stack_tracer_enabled=1
sysctl -w kernel.ftrace_enabled=1
sysctl -w kernel.ftrace_dump_on_oops=1
sysctl -w kernel.tracepoint_printk
sysctl -w kernel.unprivileged_bpf_disabled=0
sysctl -w kernel.unprivileged_userns_apparmor_policy=1
sysctl -w kernel.unprivileged_userns_clone=
sysctl -w kernel.yama.ptrace_scope

sysctl -w net.core.bpf_jit_enable=1
sysctl -w net.core.bpf_jit_harden=1
## net.core.bpf_jit_kallsyms=1

/sys/kernel/debug/tracing/options/verbose
/sys/kernel/debug/tracing/options/userstacktrace
/sys/kernel/debug/tracing/options/func_stack_trace
/sys/kernel/debug/tracing/options/function-trace
/sys/kernel/debug/tracing/tracing_on


cat -vT /sys/module/ipv6/parameters/autoconf
/sys/module/ipv6/parameters/disable
/sys/module/ipv6/parameters/disable_ipv6

/sys/module/apparmor/parameters/debug
/sys/module/apparmor/parameters/enabled
/sys/module/apparmor/parameters/logsyscall
/sys/module/apparmor/parameters/mode


sysctl -p

chmod 0644 /etc/sysctl.conf 
chown root:root /etc/sysctl.conf


user.max_cgroup_namespaces
user.max_ipc_namespaces
user.max_mnt_namespaces
user.max_net_namespaces = 63777
user.max_pid_namespaces = 63777
user.max_user_namespaces = 63777
user.max_uts_namespaces = 63777
net.netfilter.nf_log_all_netns


fs.xfs.error_level=3
fs.xfs.inherit_nodump
fs.xfs.inherit_sync
fs.xfs.irix_sgid_inherit
fs.xfs.panic_mask
fs.xfs.rotorstep
fs.xfs.speculative_cow_prealloc_lifetime
kernel.acct


sysctl -w kernel.kptr_restrict
sysctl -w kernel.modules_disabled


kernel.seccomp.actions_avail = kill_process kill_thread trap errno trace log allow
kernel.seccomp.actions_logged = kill_process kill_thread trap errno trace log


net.core.netdev_rss_key

vm.zone_reclaim_mode
vm.numa_zonelist_order

net.netfilter.nf_conntrack_timestamp=1
net.netfilter.nf_conntrack_log_invalid=1
net.netfilter.nf_conntrack_helper=1
net.netfilter.nf_conntrack_events=1
net.netfilter.nf_conntrack_acct=1
net.netfilter.nf_conntrack_checksum=1
net.netfilter.nf_conntrack_count=0
net.netfilter.nf_log_all_netns=1
net.ipv4.tcp_abort_on_overflow

net.ipv4.ip_unprivileged_port_start

net.ipv4.conf.lo.src_valid_mark

net.ipv4.conf.lo.drop_unicast_in_l2_multicast

debug.kprobes-optimization








## ############### ##
## DNSVariables.sh
## ############### ##


## --------------------------------------- ##
	OpenDNS1="208.67.222.222"
	export OpenDNS1=208.67.222.222
## --------------------------------------- ##
	OpenDNS2="208.67.220.220"
	export OpenDNS2="208.67.220.220"
## --------------------------------------- ##


## --------------------------------------- ##
	OpenNIC="185.121.177.177"
	export OpenNIC="185.121.177.177"
## --------------------------------------- ##


## --------------------------------------- ##
	FrozenDNS1="92.222.97.144"
	export FrozenDNS1="92.222.97.144"
## --------------------------------------- ##
	FrozenDNS2="92.222.97.145"
	export FrozenDNS2="92.222.97.145"
## --------------------------------------- ##
	FrozenDNS3="192.99.85.244"
	export FrozenDNS3="192.99.85.244"
## --------------------------------------- ##


## --------------------------------------- ##
	MullvadDNS="193.138.219.228"
	export MullvadDNS="193.138.219.228"
## --------------------------------------- ##


## ###################################### ## 
## ______ FrozenDNS _______
## nameserver 92.222.97.144
## nameserver 92.222.97.145
## 
## _______ OpenDNS _________
## nameserver 208.67.222.222
## nameserver 208.67.220.220
## ###################################### ## 
--ip=192.168.2.34 --dns=208.67.222.222
--ip=192.168.2.34 --dns=208.67.220.220








# FrozenDNS
nameserver 92.222.97.144
nameserver 92.222.97.145
nameserver 192.99.85.244

# ParrotDNS/OpenNIC
nameserver 139.99.96.146
nameserver 37.59.40.15
nameserver 185.121.177.177


# OpenDNS
nameserver 208.67.222.222
nameserver 208.67.220.220


# OpenNIC
nameserver 185.121.177.177

# Mullvad
nameserver 193.138.219.228

## =================================================================== ##
##	Add these ip addresses to network managers connections editor	   ##
## 			Under ipv4 settings, add this line to DNS Servers		   ##
## =================================================================== ##
92.22.97.145,185.121.177.177,192.99.85.244,208.67.222.222,208.67.220.220


























lsof /var/log/Xorg.0.log
ps ax | grep Xorg | awk '{print $1}'            ## 
ps ax | grep Xorg | awk '{print $1}'            ## Find opened log file for Xorg:


xdpyinfo | awk '/dimensions:/ {print $2}'		## grabbing the screen resolution (width x height)
xrandr --listmonitors                           ## 
xrandr --listactivemonitors
xrandr --query                  ## display the current state of the system.
xrandr --current                ## List current monitors 
xvidtune -show                  ## Print  the  currently selected settings to stdout in xorg.conf


xlsclients -l                   ## list client applications running on a display
xvinfo -display                    # Print out X-Video extension adaptor information




##-================================================================================-##"
##   [+] Pring details about the usage of CPU, I/O, memory, and network devices
##-================================================================================-##"
sar –u –r –n DEV




## Terminal Recorders
script -a -tscript.timing script.output


## record terminal session
scriptreplay -m1 -tscript.timing script.output


## The tmux terminal multiplexer now supports logging by using the pipe-pane option:

tmux pipe-pane -o -t session_index:window_index.pane_index 'cat >> ~/output.window_index-pane_index.txt'








ls --human-readable --size --file-type --numeric-uid-gid --group-directories-first --classify --si --color=always
ls --all --recursive --classify --color=always --format=single-column --group-directories-first 


stat --format=[%A/%a]:[%n]:[Size:%s.bytes]:[Uid:%u]:[User:%U]:[Group:%G]:[GID:%g]:[IO-Block:%o]:[File-type:%F]:[Inode:%i] $1

stat --format=%a:%A:%B:%F:%n:%s:%u:%U:%C:%b:%i
stat --format=%A:%a:%n:Size:%sbytes:Uid:%U:%u:Gid:%G:%g:IO Block:%o:File type:%F:Inode:%i
stat --format=%A:%a:%n:Size:%sbytes:%U:%u:%G:%g:%o:%b:%B:%F



umask 077






users | tr ' ' '\n' | sort | uniq			# print unique users with sort and uniq:

id                  ## Show the active user id with login and group
last                ## Show last logins on the system
who                 ## Show who is logged on the system


alias who='(who --boot; who --all; who --mesg; who --ips; who -T; who --dead; who -b -d --login -p -r -t -T -u) > who.txt'
(dmesg --kernel; dmesg --raw; dmesg --userspace; dmesg) > dmesg.txt



lastb --system --fullnames



pkg-config --list-all





pmap
pgrep -u root sshd
pcat
psview
pstree --arguments --show-pids --show-pgids --show-parents > pstree.txt


(ps -aux; ps -ejH; ps -eLf; ps axjf; ps axms; ps -ely; ps -ef; ps -eF;  ps -U root -u root u; ) > ps-dump.txt
(ps -eo 'pid,user,group,nice,vsz,rss,comm') > ps-table-dump.txt
ps -ef | awk '$1 == "root" && $6 != "?" {print}'
ps aox 'pid,user,args,size,pcpu,pmem,pgid,ppid,psr,tty,session,eip,esp,start_time' > ps-columns.txt

stat


chacl -l
setfacl -m u:root:ro 
getfacl file1 | setfacl --set-file=- file2      ## Copying the ACL of one file to another
mkdir --mode=0644 
chattr s                ## secure deletion (s)
immutable (i)


--dump
setpriv --reuid=1000 --regid=1000 
--bounding-set
--inh-caps (+|-)
--list-caps
--no-new-privs
--securebits noroot,noroot_locked,  no_setuid_fixup,  no_setuid_fixup_locked,  and  keep_caps_locked
--apparmor-profile 


egrep -r 127.0.0.1: /etc/*

find / -name "<file>*" -print						# Find all files whose name start with foo and print their path
find / -name "<file>*" -exec chmod 700 {} \;		# Find all files whose name start with foo and apply permission 700 to
find / -name "<file>*" -exec du {} \; | sort -nr
find / -name "<file>*" -ok mv {} /tmp/joe/ \;
find . -type f -print | xargs chmod 0640
(find / -type f -perm 04000 -ls; find / -type f -perm 02000 -ls; find / -nouser; find / -nogroup; find / -name .rhosts -type f -print 2> /dev/null) > find-dump.txt
fuser ‐m /home
fuser ‐va /home                 ## List processes accessing the /home partition
lsof /home

watch -n 1 lsof -nPi tcp:22
lsof ‐p
netstat ‐an | grep LISTEN
netstat ‐anp ‐‐udp ‐‐tcp | grep LISTEN
netstat ‐tupl
netstat ‐tup

(netstat --all; netstat --programs; netstat --statistics; netstat --groups; netstat --interfaces; netstat --route) > netstat-dump.txt



lsof ‐i






debugfs -w /dev/sda1 						## debugfs device Interactive ext2/ext3/ext4 filesystem debugger

dumpe2fs -h /dev/sda1						## Display filesystem's superblock information (e.g. number of mounts, last checks, UUID)
dumpe2fs /dev/sda1 | grep -i superblock     ## Display locations of superblock (primary and backup) of filesystem
dumpe2fs -b /dev/sda1						## Display blocks that are marked as bad in the filesystem

tune2fs -l /dev/sdc1 | grep "mount options"

tune2fs -j /dev/sda1 				# Add a journal to this ext2 filesystem, making it a ext3
tune2fs -C 4 /dev/sda1 				# Set the mount count of the filesystem to 4
tune2fs -c 20 /dev/sda1 			# Set the filesystem to be checked by fsck after 20 mounts
tune2fs -i 15d /dev/sda1 			# Set the filesystem to be checked by fsck each 15 days

tune2fs -l			                    ## List the contents of the filesystem superblock
tune2fs -o debug
tune2fs -o user_xattr
tune2fs -o acl
tune2fs -o journal_data
tune2fs -o journal_data_ordered
tune2fs -o journal_data_writeback
	
tune2fs -O [^]feature
tune2fs -O dir_index
                          Use hashed b-trees to speed up lookups for large directories.
tune2fs -O ea_inode
                          Allow  the value of each extended attribute to be placed in the data blocks of a separate inode if neces‐
                          sary, increasing the limit on the size and number of extended attributes  per  file.
tune2fs -O encrypt
                          Enable file system level encryption. 
tune2fs -O extent Enable  the  use  of extent trees to store the location of data blocks in inodes.

tune2fs -O extra_isize
                          Enable the extended inode fields used by ext4.
tune2fs -O has_journal

tune2fs -O read-only         
tune2fs -O quota                          
tune2fs -O mmp    Enable or disable multiple mount protection (MMP) feature.

tune2fs -O metadata_csum

tune2fs -Q 
	[^]usrquota		Sets/clears user quota inode in the superblock.
	[^]grpquota		Sets/clears group quota inode in the superblock.	
	[^]prjquota		Sets/clears project quota inode in the superblock.

tune2fs -U random|time		## Set  the  universally  unique identifier (UUID) of the filesystem to UUID. 


hdparm -g /dev/hda 			## Display drive geometry (cylinders, heads, sectors) of /dev/hda
hdparm -i /dev/hda 			## Display identification information for /dev/hda
hdparm -tT /dev/hda 		## Perform benchmarks on the /dev/hda drive

mount -o remount -o acl


cat /proc/$$/status | egrep '^[UG]id'

cat /proc/$$/uid_map



ls -l /dev/disk/by-id
ls -R /dev/mapper

udevadm info --attribute-walk --name=/dev/sda

parted --list print all
zuluMount-cli -l
udisksctl dump
cat /proc/partitions
mount | column ‐t

mount -t tmpfs none /mnt -o 'context="system_u:object_r:tmp_t:s0:c127,c456",noexec'

mount /tmp/disk.img /mnt -o loop
mount -t ext3 /tmp/disk.img /mnt

mount -t overlay  overlay -olowerdir=/lower,upperdir=/upper,workdir=/work  /merged

mkfs.xfs -l logdev=/dev/sdb1,size=10000b /dev/sda1

## Prints the start sector of partition 5 on /dev/sdb without header.
partx -o START -g --nr 5 /dev/sdb

## Lists the length in sectors and human-readable size of partition 5 on /dev/sda.
partx -o SECTORS,SIZE /dev/sda5 /dev/sda







mkdir --mode=0620 /mnt/cdrom/
mkdir --mode=0755 /mnt/cdrom/

mount -t iso9660 /dev/sr0 /mnt/cdrom -o ro,nodev,nosuid
mount -t iso9660 -o ro,loop=/dev/loop0 cd_image /cdrom
mount -t iso9660 /run/media/public/2TB/OS/ParrotSec/Parrot-full-3.2_amd64.iso /mnt/cdrom -o loop,ro,nosuid

chmod -v -R ugo+rwx /mnt/cdrom/
chown -v -R parrotkios /mnt/cdrom/
umount /dev/sr0 /mnt/cdrom

dd status=progress if=/dev/sr0 of=~/cdrom.iso



mount -t vfat /dev/sda /mnt/poo -o sys_immutable,ro,nosuid,noexec,nodev,noauto,errors=remount-ro
/dev/sda /mnt/poo vfat ro,nosuid,nodev,sys_immutable,noauto,errors=remount-ro 0 0



echo "Monitors remounts to read-only mode on all ext3 filesystems."
findmnt --poll=remount -t ext3 -O ro





alias du='du --human-readable --all --apparent-size --separate-dirs'
(du --human-readable --all --apparent-size --separate-dirs) > du.txt
(sfdisk --show-size; sfdisk --show-pt-geometry; sfdisk --show-geometry) > sfdisk-dump.txt

##-==============================================================-##
##  [+] 

udevadm info -a -n /dev/sda
udevadm info /sys/class/net/eth0
udevadm info /sys/class/net/wlan0

lsusb
lsdev
lshw
lsipc
lsdev
hddtemp /dev/sdb
smartctl -x /dev/sdb
hwinfo --short
hwinfo --block --short                  ##  Show all detected mountable Drives/Partitions/BlockDevices
lshw -class storage
lshw -class disk -class storage
lshw -html -class network

lsblk --topology --all --paths --fs
lsblk --all --perms --list
lsblk --all --perms --topology --fs --raw


lscpu
lspci
lsscsi


dmidecode --dump >> $TEMP_DIR/dmidump.txt
dmidecode --dump-bin dmibin.bin
dmidecode --from-dump dmibin.bin

$sfdisk=sfdisk --show-size --show-pt-geometry --show-geometry

sfdisk /dev/sda -O hdd-partition-sectors.save   ## save the sectors layout with sfdisk
sfdisk /dev/sda -I hdd-partition-sectors.save   ## recover the old sectors with backup


sfdisk -dx /dev/hda > $PartInfo.txt    ## Fetch partition table information:
/lib/systemd/system/systemd-rfkill.service
/lib/systemd/systemd-rfkill
/lib/udev/rules.d/61-gnome-settings-daemon-rfkill.rules


sfdisk --backup /dev/sda                    ## full (binary) backup - all sectors where the partition table is stored


sfdisk --dump /dev/sda > sda.dump           ## save desc of device layout to a text file.
sfdisk /dev/sda < sda.dump                  ## later restored by:

sfdisk –d /dev/sda > sda-table              ## Back up partition table to file
sfdisk /dev/sda < sda-table                 ## Restore partition table from file
sfdisk –d /dev/sda | sfdisk /dev/sdb        ## Copy partition table from disk to disk


nvme smart-log /dev/nvme1           ## View the nvme's internal smart log.
nvme id-ctrl /dev/nvme1 -H          ## check # of namespaces supported and used
nvme id-ns /dev/nvme0n1             ## check the size of the namespace
nvme-get-ns-id



dd if=/dev/zero of=/dev/hda bs=446 count=1							## blank your boot code
dd if=/dev/zero of=/dev/hda bs=512 count=1							## clear the complete MBR + partition table:
dd if=/dev/hda of=/home/knoppix/mbr_backup bs=512 count=1			## Save the MBR
dd if=/home/knoppix/mbr_backup of=/dev/hda bs=446 count=1			## restores the boot code in the MBR.
dd if=mbr_backup of=/dev/hda bs=512 count=1							## restore the full 512 bytes to the MBR with:


blockdev --setro /dev/sd            ## Set read-only
blockdev --setrw                    ## Set read-write.
blockdev --getbsz /dev/sda1         ## Print blocksize in bytes
blockdev --report



cat /sys/block/sda/queue/logical_block_size
cat /sys/block/sdc/queue/logical_block_size

cat /sys/block/sda/queue/physical_block_size
cat /sys/block/sdc/queue/physical_block_size

blockdev --getpbsz /dev/sda
blockdev --getpbsz /dev/sdc

blockdev --getss /dev/sda
blockdev --getss /dev/sdc


##-======================================================================================-##
##   specifying the 4096-byte sector size with the -b flag, the sectors of
##   the Linux partition are represented as 4K units, and there is no unallocated
##   area at the end of the drive.
##-======================================================================================-##
mmls -b 4096 /dev/sde




pvdisplay --columns --all --verbose         ## displaying the attributes of a physical volume
vgdisplay --verbose                         ## displaying the attributes of volume groups
lvdisplay                                   ## displays the attributes of a logical volume
vgck --verbose                              ## checking the volume group metadata
lvmdump                                     ## creates lvm2 information dumps for diagnostic purposes
lvmdiskscan                                 ## scans for all the devices visible to lvm2


blkid -U                        ## Print the name of the specified partition, given its UUID:
findfs UUID=                    ## Print the name of the specified partition, given its UUID:
blkid -L                        ## Print the UUID of the specified partition, given its label:
findfs LABEL=                   ## Print the name of the specified partition, given its label:

parted --list
partprobe --summary
parted /dev/sda print
findmnt --fstab --evaluate
showmount --all


watch -n 1 cat /proc/softirqs
watch -n 1 cat /proc/interrupts 
hdparm ‐i /dev/sda                ## Drive information by kernel drivers at the system boot time
hdparm ‐I /dev/sda                      ## Display drive information taken directly from the drive itself:
hdparm -g /dev/hda                          ## Display drive geometry (cylinders, heads, sectors) 

hdparm -r1 /dev/sda                 ## set a disk to read-only by setting a kernel flag

hdparm -t /dev/sda                      ## Performs & Displays Hard Drive Read Timings:	
hdparm -T /dev/sda                        ## Performs & Displays Device Cache Read Timings:
hdparm -H /dev/sda                  ## Read the temperature

cpufreq-info --debug

dumpe2fs -h /dev/sda1

## ------------------------------------------------------------------------------------------------- ##
    smartctl -a /dev/sda 			        ## Print SMART information for drive /dev/sda
## ------------------------------------------------------------------------------------------------- ##
    smartctl -s on --saveauto=on -t offline /dev/sda		## Disable SMART monitoring and log collection for drive /dev/sda
## ------------------------------------------------------------------------------------------------- ##
    smartctl -t long /dev/sda		        ## Begin an extended SMART self-test on drive /dev/sda
## ------------------------------------------------------------------------------------------------- ##
    smartctl -q errorsonly -H -l selftest /dev/sda
## ------------------------------------------------------------------------------------------------- ##
    smartctl -l error /dev/sda              ## View devices error logs
## ------------------------------------------------------------------------------------------------- ##
    smartctl -H /dev/sda			        ## Overall health report on the device
## ------------------------------------------------------------------------------------------------- ##
    smartctl -i /dev/sda			        ## details on a specific device
## ------------------------------------------------------------------------------------------------- ##
    smartctl --scan
## ------------------------------------------------------------------------------------------------- ##
    smartctl -x	/dev/sda                    ## smartctl --xall
## ------------------------------------------------------------------------------------------------- ##
    smartctl -c	/dev/sda                    ## smartctl --capabilities
## ------------------------------------------------------------------------------------------------- ##
    smartctl -A /dev/sda                    ## smartctl --attributes 
## ------------------------------------------------------------------------------------------------- ##
    smartctl -P showall | less              ## Show which devices are supported
## ------------------------------------------------------------------------------------------------- ##






smartctl --scan | grep "${DEVICE}" | cut -d' ' -f3)
smartctl --smart=on --offlineauto=on --saveauto=on /dev/sda						## (Enables SMART on first disk)


smartd -d -i 30                 ## Run in foreground (debug) mode, checking the disk status every 30 seconds.
smartd -q onecheck              ## Registers devices, and checks the status of the devices exactly once.
killall -HUP smartd             ## re-read the configuration file



grep MemTotal /proc/meminfo



udevadm info /dev/sdb | grep ID_SERIAL
grep -c '^processor' /proc/cpuinfo
cat -vET /proc/cpuinfo | grep --color -E "vmx|svm|lm"





dmidecode -t processor
cat /proc/cpuinfo
dmidecode -t memory				## view the memory, including slots used, size, data width, speed
cat /proc/meminfo
grep MemTotal /proc/meminfo
watch ‐n1 'cat /proc/interrupts'
free ‐m
cat /proc/devices
lspci ‐tv
lsusb ‐tv
lsusb --verbose -t
lsusb | grep Logitech


cat /sys/bus/usb/devices/*/product

pvdisplay







cat /sys/kernel/debug/pktcdvd/pktcdvd[0-7]/info                 ##read pktcdvd device infos in human readable form




dvd+rw-mediainfo /dev/
cdrwtool -i                         ## Print disc track info
--medium-info
--scan              ## Scan the medium for read errors
dvdisaster -d /dev/sdc -s


## Reads an image from drive /dev/sdc into the file $Disk.iso
## Each sectors integrity is verified by using its EDC and L-EC raw data.
dvdisaster -d /dev/hdc -i $Disk.iso --read-raw -r


## Creates an error correction file corr.ecc for the image $Disk.iso
dvdisaster -i $Disk.iso -e corr.ecc -c

##-================================================-##
##  [+] Repairs the image file $Disk.iso 
##      using the error correction file corr.ecc.
##-================================================-##
dvdisaster -i $Disk.iso -e corr.ecc -f

##-================================================-##
##  [+] Verifies the image $Disk.iso with information
##      from the error correction file corr.ecc.
##-================================================-##
dvdisaster -i $Disk.iso -e corr.ecc -t


              
--fix                               ## Try to fix medium image using .ecc information
--eject



lsscsi --classic                    ## 
lsscsi --hosts                      ## List the SCSI hosts currently attached to the system


lsscsi --verbose --scsi_id       ## show udev derived /dev/disk/by-id/scsi* entry
lsscsi --verbose --long          ## additional information output

lsscsi --verbose --list --long --device --size  ## List information about all SCSI devices:

cat /proc/mdstat                    ## Display information about RAID arrays and devices
mdadm --detail --scan
mdadm --misc -Q /dev/sdd1   ## Display information about a device
mdadm --misc -D /dev/md0    ## Display detailed information about the RAID array
mdadm --misc -o /dev/md0    ## Mark the RAID array as readonly
mdadm --misc -w /dev/md0    ## Mark the RAID array as read & write


ls /dev/mapper | grep 
$(grep "md[0-9]")
grep "hd[a-z][a-z][0-9]"
grep "sd[a-z][a-z][0-9]"
/dev/mmcblk0p1
/dev/nvme0n1p1



BLOCKSIZE=$(fsstat $PARTITION | head -40 | grep -a "Allocation Block Size" | awk ' { print $4 } ')
BLOCKSIZE=$(tune2fs -l $PARTITION | grep -a "Block size" | awk ' { print $3 } ')





mpstat 1
vmstat 2
iostat 2
ipcs ‐a

showmount --all
findfs LABEL=



## XFS has both primary and secondary superblocks.


##~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~##
    mkfs.xfs -l logdev=/dev/sdb1,size=10m /dev/sda1
    mkfs.xfs -l internal,size=10m
##~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~##


##~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~##
    xfs_info /dev/sda1
##~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~##
    xfsdump -f /mnt/bkup /mnt/xfsdata		            ## Creates a file-based backup of the /mnt/xfsdata directory
    xfsdump -v debug -p 15 -f /mnt/bkup /mnt/xfsdata    ## Verbose (debug), 15 sec intervals, 
##~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~##
    xfs_metadump -g $Source $Target                     ## Shows dump progress.
    xfs_metadump -g /dev/$Disk ~/xfs-metadata
##~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~##
    xfs_metadump /dev/sdd ~/xfs-metadata
##~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~##
    xfs_metadump -g -l $dst /dev/sdd ~/xfs-metadata     ## external log
    xfs_metadump -a -g /dev/sdd ~/xfs-metadata          ## Copies entire metadata blocks
##~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~##
    xfs_mdrestore -g -i $Source $Target
    xfs_mdrestore -g -i ~/xfs-metadata /dev/$Disk
##~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~##
    xfs_check /dev/$Disk
##~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~##
    xfs_repair -v -t 17 /dev/$Disk
##~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~##
    xfsrestore -f ~/xfsdump-data -L $session_label /dev/$Disk
    xfsrestore -f ./xfsdump-data -L 'session1' /dev/$Disk
##~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~##

##~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~##
    xfs_repair -n -x        ## Read all file data extents to look for disk errors.
##~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~##
    xfs_repair -n           ## no modify mode
##~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~##



cat -vET /proc/cmdline | xxd


##~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~##
    xfs_info /dev/sdb1					## Query the filesystem for information:
##~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~##
    xfs_admin -u /dev/vda1				## UUID associated with the noted LV:
##~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~##

##-=========================================================================================================-##
	xfs_admin -j /dev/sda		## Enables version 2 log format (journal which supports larger log buffers)
##-=========================================================================================================-##
	xfs_admin -u /dev/sda1		## Display filesystems UUID
##-=========================================================================================================-##
	xfs_admin -l /dev/sda		## Display filesystems label
##-=========================================================================================================-##




##-==============================================================-##
##  [+] 
##-==============================================================-##
pcat -v <PID> > /home/poo/xntps.pcat        ## Location of Each Memory Region That is Being Copied## 


##-==============================================================-##
##  [+] 
##-==============================================================-##
pmap -d 7840                                ## Display Libraries currently loaded by that process



##-==============================================================-##
##  [+] 
##-==============================================================-##





##-==============================================================-##
##  [+] 
##-==============================================================-##




ps -eo pid,user,group,args,etime,lstart jgrep $PID



gconftool-2 --type string --set org/mate/terminal/keybindings/copy '<Ctrl>c'
gconftool-2 --type string --set org/mate/terminal/keybindings/paste '<Ctrl>v'



gsettings list-schemas > ~/gsettings-schemas.txt
gsettings list-recursively > ~/gsettings-list-recursively.txt

/var/lib/gconf/debian.defaults
/var/lib/gconf/debian.mandatory
/usr/share/gconf/defaults/
/usr/share/gconf/mandatory/




/etc/apt/sources.list

kill ‐s TERM 4712               ## [15] TERM (software termination signal)
killall ‐1 httpd                ## [ 1] HUP (hang up)
pkill ‐9 http                   ## [ 9] KILL (non­catchable, non­ignorable
pkill ‐TERM ‐u www              ## [15] TERM (software termination signal)
fuser ‐k ‐TERM ‐m /home         ## [15] kill every process accessing /home (to umount)


kill $(ps -ef | awk '/sshd/ {print $2}')
kill $(ps -ef | awk '/mysql/ {print $2}')


## kill all related processes using your device
fuser -mk /dev/hdc




service --status-all | grep running
chkconfig --list
chkconfig --add

systemctl list-units | grep .service
systemctl list-units | grep .target
systemctl list-unit-files --type=service
systemctl list-unit-files --type=target
systemctl list-unit-files --type=service | grep -v disabled


systemctl --all list-unit-files
systemctl --all --show-types

systemctl show --property "Wants" multi-user.target
systemctl show --property "Requires" multi-user.target
systemctl show --property "WantedBy" getty.target
systemctl show --property "Wants" multi-user.target | fmt -10 | sed 's/Wants=//g' | sort

cat /etc/systemd/system/My_New_Service.service

##-==============================================================-##
##  [+] 
##-==============================================================-##


##-==============================================================-##
##  [+] 
##-==============================================================-##

rkhunter --quiet --verbose-logging --summary --hash SHA256 --cronjob --logfile /var/log/rk.log --check


## grant read access to all members of the "wheel" and "adm" system groups
setfacl -Rnm g:wheel:rx,d:g:wheel:rx,g:adm:rx,d:g:adm:rx /var/log/journal/


## On systems where /var/log/journal/ does not exist 
## yet but where persistent logging is desired.
## create the directory, and ensure it has the correct access modes:
mkdir -p /var/log/journal
systemd-tmpfiles --create --prefix /var/log/journal



journalctl --list-boots | head
journalctl -k                       ## kernel messages
journalctl -u NetworkManager.service
journalctl -u httpd.service
journalctl -k -b -1             ## view the boot logs
journalctl /dev/sda             ## all logs of the kernel device node `/dev/sda`
journalctl -u systemd-networkd


kill -HUP `pidof syslogd`
kill -HUP `cat /var/run/syslogd.pid`
/sbin/service rsyslog start
/etc/init.d/syslog reload
logger -t "food[$$]" -p local3.warning "$count connections from $host"

syslog-ng-ctl verbose --set=on
syslog-ng-ctl stats

/etc/syslog-ng/syslog-ng.conf


## When auditing is not enabled,
## we can configure the system logger to direct SELinux
## AVC messages into its own logfile. 

## For instance, with the syslog-ng system logger,
## the possible configuration parameters 
## could be as follows:

source kernsrc { file("/proc/kmsg"); };
destination avc { file("/var/log/avc.log"); };
filter f_avc { message(".*avc: .*"); };
log { source(kernsrc); filter(f_avc); destination(avc); };


logwatch --range all --archives --detail High --print | less
logwatch --print | less




loginctl list-users
loginctl user-status
loginctl --all show-user
loginctl list-seats
loginctl seat-status
loginctl show-seat
loginctl terminate-user
loginctl kill-user


systemd-logind.service
logind.conf


pgrep ‐l sshd                   ## Find the PIDs of processes by (part of) name

echo $$                         ## The PID of your shell
fuser ‐va 22/tcp                ## List processes using port 22 (Linux)

ps aux | grep 'ss[h]'           ## Find all ssh pids without the grep pid

chkconfig --list && chkconfig --del $Service && chkconfig --off $Service
service --status-all | grep running... | sort
systemctl status
systemctl stop $Service && systemctl disable $Service && systemctl mask $Service
update-rc.d $Service stop && update-rc.d $Service disable && update-rc.d $Service remove


















net.netfilter.nf_conntrack_timestamp
echo 1 > /proc/sys/net/netfilter/nf_conntrack_timestamp
echo 1 > /proc/sys/net/netfilter/nf_conntrack_acct
net.netfilter.nf_conntrack_acct


modprobe nf_conntrack_ipv4
modprobe nf_conntrack_ipv6

iptables -A INPUT -p tcp -m state --state ESTABLISHED -j ACCEPT
iptables -A OUTPUT -p tcp -m state --state NEW,ESTABLISHED -j ACCEPT







netsniff-ng
trafgen
mausezahn
ifpps
curvetun







##-====================================================================================-##
    iw wlan0 scan dump -u				## Dump the current scan results
##-====================================================================================-##
    iw wlan0 survey dump			    ## List all gathered channel survey data
##-====================================================================================-##
    iw wlan0 station dump				## List all stations known, AP on interfaces
##-====================================================================================-##
    iw wlan0 station get <MAC address>	## Get information for a specific station.
##-====================================================================================-##
    iw wlan0 event						## Monitor events from the kernel
##-====================================================================================-##



iwconfig wlan0 nwid off         ## Disable The Network ID Checking (NWID promiscuous)


nmcli radio all off
iw reg set US
iwconfig wlan1 txpower 25

nmcli device show
nmcli device status
nmcli general status
nmcli -t device
nmcli connection show
nmcli dev status STATE
nmcli dev status CONNECTION

nmcli device wifi list
nmcli device wifi list bssid

nmcli connection show
nmcli connection show Ethernet\ connection\ 1
nmcli -f GENERAL,WIFI-PROPERTIES dev show eth0 


pkaction --action-id org.freedesktop.NetworkManager.network-control --verbose

nmcli -p -f general,wifi-properties device show
nmcli connection edit type ethernet
nmcli> set connection.autoconnect no
nmcli -t -c auto radio wwan off


ethtool eth0
ethtool -S eth0                     ## Statistics
ethtool ‐s eth0 autoneg off


ip link show
ip addr show
ip neigh show
ip ntable show
ip route showdump
ip netconf show
ip netns list
ip netns add NAME
ip netns set NAME NETNSID

traceroute 
cat /proc/net/dev | columns -t 
awk '{ print $1,$5 }' /proc/net/dev
ifpps --dev eth0

wavemon -g                  ## Fix screen dimensions
wavemon -i wlan0            ## Use specified network interface

route ‐n
netstat ‐rn

route add ‐net 192.168.20.0 netmask 255.255.255.0 gw 192.168.16.254
ip route add 192.168.20.0/24 via 192.168.16.254
route add ‐net 192.168.20.0 netmask 255.255.255.0 dev eth0
route add default gw 192.168.51.254
ip route add default via 192.168.51.254 dev eth0


ifconfig eth0 hw ether




##-===========================================================================-##
##          [+] Link types:
##-===========================================================================-##
## --> 		vlan - 802.1q tagged virtual LAN interface
## --> 		veth - Virtual ethernet interface
## --> 		vcan - Virtual Local CAN interface
## --> 		dummy - Dummy network interface
## --> 		ifb - Intermediate Functional Block device
## --> 		macvlan - virtual interface base on link layer address (MAC)
## --> 		can - Controller Area Network interface
## --> 		bridge - Ethernet Bridge device
##-===========================================================================-##




Creates a new vlan device eth0.10 on device eth0
ip link add link eth0 name eth0.10 type vlan id 10


ip link add link eth0 name eth0.7 type vlan id 7

ip link delete dev eth0.7                                   ## Removes vlan device

ip link add link eth0 name eth0.7 type bridge





brctl show
ip link show

brctl addbr br0
brctl stp br0 off
brctl addif br0 eth0
brctl addif br0 eth1
ifdown eth0
ifdown eth1
ifconfig eth0 0.0.0.0 up
ifconfig eth1 0.0.0.0 up
ifconfig br0 10.0.3.129 broadcast 10.0.3.255 netmask 255.255.255.0 up 
route add default gw 10.0.3.129
for file in br0 eth0 eth1
do
   echo "1" > /proc/sys/net/ipv4/conf/${file}/proxy_arp
   echo "1" > /proc/sys/net/ipv4/conf/${file}/forwarding
done;
echo "1" > /proc/sys/net/ipv4/ip_forward
brctl delif br0 eth0
brctl delif br0 eth1
ifconfig br0 down
brctl delbr br0

#  iface br0 inet static
#       bridge-ifaces eth0 eth1
#       address 192.168.1.1
#       netmask 255.255.255.0
# [ a bridge which acts as an anonymous bridge ]
#  iface br0 inet manual
#       bridge-ifaces eth0 eth1
#       up ifconfig $IFACE up



for x in /sys/class/net/"${IFACE}"/brport/*; do
bridge_port='/sys/class/net/"${IFACE}"/brport/*'


for x in /sys/class/net/"${IFACE}"/bridge/*; do
is_bridge='/sys/class/net/"${IFACE}"/bridge/*'

for x in /sys/class/net/"${IFACE}"/brif/*; do
bridge_IFACE='/sys/class/net/"${IFACE}"/brif/*'




ip4list=$(echo $(ip -4 route | awk '{ print $1; }' | sed 's/\/.*$//'))
ip6list=$(echo $(ip -6 route | awk '{ print $1; }' | sed 's/\/.*$//'))



iptables ‐L ‐t nat          ## Check NAT status
iptables ‐L ‐n ‐v
iptables ‐F
iptables ‐X

$IPTABLES -P INPUT DROP
$IPTABLES -P OUTPUT DROP
$IPTABLES -P FORWARD DROP

cat /proc/sys/net/ipv4/ip_forward
echo 1 > /proc/sys/net/ipv4/ip_forward

#--- Disabling IPv6 can help
echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6
echo 1 > /proc/sys/net/ipv6/conf/default/disable_ipv6

macchanger --list | grep Cisco | cut -c9-16
macchanger --list | grep Apple | cut -c9-16
macchanger --list | grep Netgear | cut -c9-16
macchanger --list | grep Linksys | cut -c9-16

ip link set eth0 down
ifconfig eth0 down

ifconfig eth0 down && ifconfig hw ether $macaddr

iwconfig wlan1 txpower 25
iwconfig wlan0 txpower 20
ifconfig eth0 hw ether 00:30:65:e4:98:27
# ifconfig wlan0 hw ether 00:40:96:f4:34:67
ifconfig wlan0 hw ether 00:30:65:39:2e:77
ifconfig wlan1 hw ether 00:30:65:35:2e:37



rfkill block all
rfkill unblock wifi

ip link show wlan0


iw dev wlan0 station dump
iw dev wlan0 scan | less
iwlist wlan0 scanning | egrep "ESSID|Channel"
iwconfig wlan0 mode monitor channel 3
iw scan



dig ‐x 78.31.70.238
host 78.31.70.238
nslookup 78.31.70.238



dig MX google.com
dig @127.0.0.1 NS sun.com               # To test the local server
dig @204.97.212.10 NS MX heise.de       # Query an external server
dig AXFR @ns1.xname.org cb.vu           # Get the full zone (zone transfer)

host ‐t MX cb.vu                        ## Get the mail MX entry
host ‐t NS ‐T sun.com                   ## Get the NS record over a TCP connection
host ‐a sleepyowl.net                   ## Get everything




























ifconfig -a | egrep -e "(^eth|drop)"                ## Linux, interface drop counts:
ethtool -S eth0 | egrep '(rx_missed|no_buffer)'    ## Drop Values
awk '{ print $1, $5 }' /proc/net/dev                ## Drop counts through /proc/ Virtual net
ifconfig -a | grep -E '(^eth|RX.*dropped)'
ethtool -S eth0 | egrep '(rx_missed|no_buffer)'


## Get max RX size for monitored interface
MAX_RX=$(ethtool -g $INTERFACE | grep -m 1 RX | cut -d\: -f2 | awk '{sub(/^[ \t]+/, "")};1')


autoneg off

--show-priv-flags
--show-channels
--show-rxfh-indir
--show-time-stamping
--get-dump

rx on                   ## Specifies whether RX checksumming should be enabled.

tx on                   ## Specifies whether TX checksumming should be enabled.
rxhash on               ## Specifies whether receive hashing offload should be enabled

ifpps eth0
ifpps --promisc --dev eth0
ifpps --loop -p --csv -d wlan0 > gnuplot.dat


tcpstat -i eth0 -o "Time: %S\tpps: %p\tpacket count: %n\tnet load: %l\tBps: %B\n"

ifpps –dev eth0

sar -l 5 5
sar -L 5 5

watch -n 1 "cat /proc/net/dev | column -t"          ## ## Reads kernel stats from procfs, e.g.




ntop -d -L -u ntop –access-log-file=/var/log/ntop/access.log -b -C –output-packet-path=/var/log/ntop-
suspicious.log –local-subnets 192.168.1.0/24,192.168.2.0/24,192.168.3.0/24 -o -M -p
/etc/ntop/protocol.list -i br0,eth0,eth1,eth2,eth3,eth4,eth5 -o /var/log/ntop


echo "Sniff packets with live verbose output with timestamps also "
echo "hexadecimal values in addition to the ASCII strings."
ngrep -t -x 'USER|PASS|RETR|STOR' tcp port ftp and host server.example.com






ngrep -I bad_user.pcap -q -W single -t "GET" ip src 192.168.1.1 | awk
'{ print $2, $3, $11, $9}' | sed 's/\.\{1,3\}User-Agent//' | grep -v -E '(ad|
cache|analytics|wxdata|voicefive|imwx|weather.com|counterpath|
cloudfront|2mdn.net|click|api|acuity|tribal|pixel|touchofclass|flickr|
ytimg|pulse|twitter|facebook|graphic|revsci|digi|rss|cdn|brightcove|
atdmt|btrll|metric|content|trend|serv|content|global|fwmrm|typekit|[az]*-[a-z]*\.com|pinit|cisco|tumblr)' | sed '/ [ \t]*$/d' > url.txt








## To monitor all TCP ports, use a more general expression:
urlsnarf -i eth1 tcp


urlsnarf tcp port $Port









darkstat --verbose -i eth0 --hexdump --export /home/poozer/darkstat.txt


tail ‐n 500 /var/log/messages
tail /var/log/warn
tail -f /var/log/messages
tail /var/log/messages |grep ICMP |tail -n 1
tail /var/log/messages | grep UDP | tail -n 1




## ==================================================================================== ##
tcpick -i eth0 -C                           ## display the connection status:
## ==================================================================================== ##
tcpick -i eth0 -C -yP -h -a                 ## display the payload and packet headers:
## ==================================================================================== ##
tcpick -i eth0 -C -bCU -T1 "port 25"        ## display client data only of the first smtp connection:
## ==================================================================================== ##
tcpick -i eth0 -wR "port ftp-data"			## download a file passively:
## ==================================================================================== ##
tcpick   -i   eth0   --pipe  client  "port  80"  |  gzip  > http_response.gz
## ==================================================================================== ##

## ==================================================================================== ##
tcpick -i eth0 --pipe server "port 25" | nc foobar.net 25
## ==================================================================================== ##
tcpick -a			## Displays host names instead of ip addresses. 
## ==================================================================================== ##
tcpick -v5			## Verbose Lvl 1-5
## ==================================================================================== ##




## process all of the pcap files in the current directory
tcpflow -o out -a -l *.pcap







echo -e "\t<<+}===== converting the hostname to an IPv4 address using DNS: ====={+>>"
nmap --dns-servers 8.8.8.8,8.8.4.4 scanme.nmap.org


















## Recursively Download Files
wget -r -l 3 -k -p -H https://




##-======================================================-##
##  [+] Recursively fetch list of URLs with wget:
##-======================================================-##
cat url-list.txt | xargs wget ???c

##-======================================================-##
##  [+] Find out all the jpg images and archive it.
##-======================================================-##
find / -name *.jpg -type f -print | xargs tar -cvzf images.tar.gz

##-======================================================-##
##  [+] Copy all the images to an external hard-drive.
##-======================================================-##
ls *.jpg | xargs -n1 -i cp {} /external-hard?drive/directory







##-======================================================================================================================================-##
##  ||----------------------------------------------->> Clearnet access via HTTP/SOCKS <<---------------------------------------------||
##-======================================================================================================================================-##
## -------------------------------------------------------------------------------------------------------------------------------------- ##
    curl -fsSI -x 127.0.0.1:8118 ${webhost}									## Fetch via HTTP proxy as root
    sudo -n -u anon curl -fsSI -x 127.0.0.1:8118 ${webhost}					## Fetch via HTTP proxy as anon
    curl -fsSI --socks5-hostname 127.0.0.1:9050 ${webhost}					## Fetch via SOCKS proxy as root
    sudo -n -u anon curl -fsSI --socks5-hostname 127.0.0.1:9050 ${webhost}	## Fetch via SOCKS proxy as anon
## -------------------------------------------------------------------------------------------------------------------------------------- ##
    curl -fsSI --socks5 127.0.0.1:9050 ${webhost}							## Fetch via SOCKS proxy w/ local DNS as root
    sudo -n -u anon curl -fsSI --socks5 127.0.0.1:9050 ${webhost}			## Fetch via SOCKS proxy w/ local DNS as anon
## -------------------------------------------------------------------------------------------------------------------------------------- ##
##-======================================================================================================================================-##

##-======================================================================================================================================-##
##  ||---------------------------------------->> Fetch Over SOCKS5 Using Privoxy And Local DNS <<-------------------------------------||
##-======================================================================================================================================-##
## 
## -------------------------------------------------------------------------------------------------------------------------------------- ##
    sudo -n -u privoxy curl -fsSI --socks5-hostname 127.0.0.1:9050 ${webhost}		## Fetch via privoxy
    sudo -n -u privoxy curl -fsSI --socks5 127.0.0.1:9050 ${webhost}				## Fetch via SOCKS5 proxy w/ local DNS as privoxy
## -------------------------------------------------------------------------------------------------------------------------------------- ##
    sudo -n -u privoxy curl -fsSI --socks5-hostname 127.0.0.1:9050 ${webhost}		## Fetch via SOCKS5 proxy as privoxy 
    sudo -n -u privoxy curl -fsSI --socks5 127.0.0.1:9050 ${webhost}				## Fetch via SOCKS5 proxy w/ local DNS as privoxy" 
## -------------------------------------------------------------------------------------------------------------------------------------- ##
##-======================================================================================================================================-##

##-======================================================================================================================================-##
##  ||----------------------------------------------->> Darknet access via HTTP/SOCKS <<----------------------------------------------||
##-======================================================================================================================================-##
    sudo -n -u anon curl -fsSI -x 127.0.0.1:8118 ${onionhost}						## Fetch via .onion via HTTP proxy as anon
    sudo -n -u anon curl -fsSI --socks5-hostname 127.0.0.1:9050 ${onionhost}		## Fetch .onion via SOCKS proxy as anon
##-======================================================================================================================================-##








/etc/ssh/sshd_config

echo 'AddressFamily inet' | sudo tee -a /etc/ssh/sshd_config




## created an RSA key-pair
ssh-keygen -b 4096


mkdir -p ~/.ssh && sudo chmod -R 700 ~/.ssh/

ls ~/.ssh/id_rsa*



ssh-copy-id example_user@203.0.113.10


scp ~/.ssh/id_rsa.pub example_user@203.0.113.10:~/.ssh/authorized_keys


sudo chmod 700 -R ~/.ssh && chmod 600 ~/.ssh/authorized_keys


sudo systemctl restart sshd
sudo service ssh restart




/etc/iptables/ipv4
:   ~~~ conf
    *filter

    # Allow all loopback (lo0) traffic and reject traffic
    # to localhost that does not originate from lo0.
    -A INPUT -i lo -j ACCEPT
    -A INPUT ! -i lo -s 127.0.0.0/8 -j REJECT

    # Allow ping.
    -A INPUT -p icmp -m state --state NEW --icmp-type 8 -j ACCEPT

    # Allow SSH connections.
    -A INPUT -p tcp --dport 22 -m state --state NEW -j ACCEPT

    # Allow HTTP and HTTPS connections from anywhere
    # (the normal ports for web servers).
    -A INPUT -p tcp --dport 80 -m state --state NEW -j ACCEPT
    -A INPUT -p tcp --dport 443 -m state --state NEW -j ACCEPT

    # Allow inbound traffic from established connections.
    # This includes ICMP error returns.
    -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

    # Log what was incoming but denied (optional but useful).
    -A INPUT -m limit --limit 5/min -j LOG --log-prefix "iptables_INPUT_denied: " --log-level 7

    # Reject all other inbound.
    -A INPUT -j REJECT

    # Log any traffic that was sent to you
    # for forwarding (optional but useful).
    -A FORWARD -m limit --limit 5/min -j LOG --log-prefix "iptables_FORWARD_denied: " --log-level 7

    # Reject all traffic forwarding.
    -A FORWARD -j REJECT

    COMMIT
    ~~~




-A INPUT -s longview.linode.com -m state --state NEW -j ACCEPT



-A INPUT -s 193.138.219.228 -m state --state NEW -j ACCEPT

193.138.219.228




/etc/iptables/iptables.rules
/etc/iptables/ip6tables.rules

sudo iptables-restore < /etc/iptables/iptables.rules
sudo ip6tables-restore < /etc/iptables/ip6tables.rules

sudo systemctl start iptables && sudo systemctl start ip6tables
sudo systemctl enable iptables && sudo systemctl enable ip6tables





sudo iptables-restore < /tmp/v4
sudo ip6tables-restore < /tmp/v6

sudo service iptables save
sudo service ip6tables save


iptables -vL
ip6tables -vL

iptables -L --line-numbers






ssh -D 12345 user@host.domain               ## tells SSH to run the SOCKS server on port 12345



















## Generate a Google maps URL for GPS location data from digital photo
echo "https://www.google.com/maps/place/$(exiftool -ee -p '$gpslatitude, $gpslongitude' -c '%d?%d'%.2f"\" image.jpg 2> /dev/null | sed -e "s/ //g")"






Common calls:

access
close (close le handle)
fchmod (change le permissions)
fchown (change le ownership)
fstat (retrieve details)
lseek (move through le)
open (open le for reading/writing)
read (read a piece of data)
statfs (retrieve le system related details)



strace -e open                      ## Monitor opening of files: 
strace -e trace=$file -p $1234         ## See all file activity
strace -e trace=$desc -p $1234        ## 

sudo strace -P /etc/cups -p $2261

strace -e trace=network
strace -e trace=memory


-T – Display syscall duration in the output
strace -c                       ## See what time is spend and where
strace -f                       ## Track process including forked child processes
strace -P /tmp                  ## Track a process when interacting with a path
strace -o $trace.txt            ## Log strace output to a le
strace -e trace=$ipc            ## Track communication between processes (IPC)
strace -e trace=$signal         ## Track process signal handling (like HUP, exit)
strace -e trace=$file           ## Track file related syscalls

strace -e trace=process                ## Track process calls (like fork, exec)
strace -e trace=memory                ## Track memory syscalls
strace -e trace=network                ## Track memory syscalls


pgrep -u root named							# Find the process ID of the named daemon:
pgrep -u root sshd
pgrep -u root,daemon



pcat -v $PID                        ## displays the location of each memory region that is being copied

pmap -d 7840                        ## Provide Libraries loaded by a running process with pmap


pidstat -p $PID	                ## gather resource consumption details for a specific target process


kill `lsof -t /home`		        ## Kill all processes that have files open under /home.

killall -9 sshd 
pkill -9 -u root sshd 
pkill -HUP syslogd                  ## Make syslog reread its configuration file:


## kill all sshd processes whose parent process ID is 1:
pkill -P 1 sshd				## kills only the master sshd process leaving all of the users on the system still logged in.


 
## pull out just the PID of the master SSH daemon:
netstat -anp --tcp -4 | awk '/:22/ && /LISTEN/ { print $7 }' | cut -f1 -d/

echo "Killing that process just requires appropriate use of backticks:
kill `netstat -anp --tcp -4 | awk '/:22/ && /LISTEN/ { print $7 }' | cut -f1 -d/`



watch -n 1 lsof -nPi tcp:22
	while :; do kill -9 `lsof -t -i :22`; done







































cat /proc/cmdline | xxd

od -c --strings 
objdump --section-headers 
objdump --disassemble --section=.text 
objdump --syms           #
objdump --all-headers         #



echo hello | hexdump -v -e '/1 "%02X "' ; echo

echo hello | hexdump -v -e '"x" 1/1 "%02X" " "' ; echo      # hex with preceding 'x'


od -A x -t x1z -v            ## Display hexdump format output


xxd -l 120 -c 12 xxd.1              ## Hexdump the first 120 bytes with 12 octets per line.

xxd -l 120 -ps -c 20 xxd.1          ## Print 120 bytes as continuous hexdump with 20 octets per line.

xxd -s 0x36 -l 13 -c 13 xxd.1       ## Display just the date from the file xxd.1



##-=================================================================================================-##
##   [+] Rewind stdin before reading (Required) - Because `cat' already read to the end of stdin.
##-=================================================================================================-##
sh -c "cat > plain_copy; xxd -s 0 > hex_copy" < file


##-==============================================================-##
##  [+] Hexdump from file position 0x480 (=1024+128) onwards.
##  [?] The + sign means relative to the current position, 
##  [?] thus the 128 adds to the 1k where dd left off.
##-==============================================================-##
sh -c "dd of=plain_snippet bs=1k count=1; xxd -s +128 > hex_snippet" < file

##-==============================================================-##
##  [+] Hexdump from file position 0x100 ( = 1024-768) on.
##-==============================================================-##
sh -c "dd of=plain_snippet bs=1k count=1; xxd -s +-768 > hex_snippet" < file


##-==============================================================-##
##  [+] 
##-==============================================================-##


##-==============================================================-##
##  [+] 
##-==============================================================-##

##-==============================================================-##
##  [+] 
##-==============================================================-##


##-============================================================================-##
##  [+] 
##-============================================================================-##
## ---------------------------------------------------------------------------- ##
##  1). 
##  2). 
##  3). 
## ---------------------------------------------------------------------------- ##


##-============================================================================-##
##  [+] 
##-============================================================================-##
## ---------------------------------------------------------------------------- ##
##  1). 
##  2). 
##  3). 
## ---------------------------------------------------------------------------- ##



##-============================================================================-##
##  [+] 
##-============================================================================-##
## ---------------------------------------------------------------------------- ##
##  1). 
##  2). 
##  3). 
## ---------------------------------------------------------------------------- ##


##-============================================================================-##
##  [+] 
##-============================================================================-##
## ---------------------------------------------------------------------------- ##
##  1). 
##  2). 
##  3). 
## ---------------------------------------------------------------------------- ##


/proc/<pid>/status




## Dynamic Shared Object
readelf -h /proc/1/exe



## Symbol table '.dynsym'
readelf -s /proc/1/exe

## Dynamic section
readelf -d /proc/1/exe

## file's segment headers
readelf -l /proc/1/exe


pkaction --verbose





dd status=progress if=OPNsense-18.1.r1-OpenSSL-nano-amd64.img of=/dev/mmcblk0p1
dd status=progress if=HardenedBSD-aarch64-12.0-HARDENEDBSD-13634f1e55e-RaspberryPi3.img of=/dev/mmcblk0
dc3dd verb=on log=/home/xe1phix/BSD.log hash=sha1 if=HardenedBSD-aarch64-12.0-HARDENEDBSD-13634f1e55e-RaspberryPi3.img of=/dev/mmcblk0

time dd status=progress if=OPNsense-18.1.r1-OpenSSL-nano-amd64.img of=/dev/mmcblk0p1
time dc3dd verb=on log=/home/xe1phix/BSD.log hash=sha1 if=HardenedBSD-aarch64-12.0-HARDENEDBSD-13634f1e55e-RaspberryPi3.img of=/dev/mmcblk0




##-============================================================================-##
##  [+] 
##-============================================================================-##
## ---------------------------------------------------------------------------- ##
##  1). 
##  2). 
##  3). 
## ---------------------------------------------------------------------------- ##



mmls -i list                                    ## list the Sleuth Kit Supported image format types

ftkimager /dev/$Disk image --frag 20GB --s01    ## Acquired Image - maximum fragment size set at 20GB,
ewfacquire -S 2G /dev/$Disk                     ## Acquired Image - maximum segment file size 2G


Raw Images - Dont contain headers or meta information.


##-====================================================-##
##  [+] Compressing and splitting during acquisition:
##-====================================================-##
## ---------------------------------------------------- ##
## acquiring an image with dd
## compressing it with gzip
## and splitting it into CD-sized chunks:
## ---------------------------------------------------- ##
dd if=/dev/$Disk | gzip | split -d -b 640m - $image.raw.gz.

fls -o 63 -i split image.000 image.001 image.002    ## Sleuth Kit - Split 

dcfldd if=/dev/$Disk split=16G of=$image.raw     ## use dcfldd to acquire an image - Max 16G per image
dc3dd if=/dev/$Disk ofsz=640M ofs=$image.raw.000 ## use dcfldd to acquire an image - Max 640M per image

split -d -b 4G $image.raw $image.raw.             ## split an image into DVD-sized chunks:
dd if=/dev/$Disk | gzip | split -d -b 640m - $image.raw.gz.

cat image.raw.* > image.raw         ## concatenating the set of image fragments into a single image.

##-==================================================-##
##        [+] Reassemble The split pieces:
##  [?] Concatenate the files into a single image:
##-==================================================-##
cat /dvd/image.raw.gz.00 > image.raw.gz
cat /dvd/image.raw.gz.01 >> image.raw.gz
cat /dvd/image.raw.gz.02 >> image.raw.gz
cat /dvd/image.raw.gz.03 >> image.raw.gz

ls -1 image.raw.*       ## list the split pieces files


strace -e open image.raw.*


cat $image.raw.* > $image.raw                   ## Reassemble a Split Image
cat $image.raw.gz.* | zcat | 
cat $image.raw.gz.* | zcat > $image.raw         ## piping the split files into zcat and redirecting to a file:
dd if=/dev/$Disk |
dcfldd if=/dev/$Disk | gzip > $image.raw.gz        ## dcfldd image data stream --> stdout | gzip compressed, then redirected into a compressed file.
mmls $image.raw.*



zcat $image.raw.gz | sha256sum                   ## zcat uncompresses it, then pipes SHA256sum to determine the sha256 cryptographic hash.
cat $image.raw.* | sha256sum                    ## Check the SHA256 hashsum of the split raw images

ewfinfo $image.E01                                  ## Examine File Hashes
affinfo -S $image.aff            ## validity checking for AFF files
ewfverify $image.Ex01            ## evidence integrity checking - validate the hash
img_stat $image.E01              ## evidence integrity checking - 



fls -r image 2                  ## get a list of all files and directories in an image use:
fls -d -p image 29              ## get the full path of deleted files in a given directory:
fls -m /usr/local image 2       ## get the mactime output
fls -o 63 $disk-img.dd           ## the file system starts in sector 63:
fls -v -l $image.raw            ## Display file details in long format

fls -i "split" -o 63 disk-1.dd disk-2.dd disk-3.dd  ## disk image that is split:



mmls -t bsd -o 12345 -i split disk-1.dd disk-2.dd   ## list the contents of a BSD system that 
                                                    ## starts in sector 12345 of a split image:


mmls disk_image.dd      ## list the partition table
mmls -m                 ## Show metadata volumes
mmls -A                 ## Show unallocated volumes
mmls -a                 ## Show allocated volumes
mmls -B                 ## Include a column with the partition sizes in bytes
mmls -r                 ## Recurse  into  DOS  partitions and look for other partition tables.
mmls -v


ewfinfo -i          ## only show EWF acquiry information
ewfinfo -m          ## only show EWF media information
ewfinfo -e          ## only show EWF read error information

##-============================================================================-##
##  [+] converting AFF --> compressed SquashFS (forensic evidence container)
##-============================================================================-##
affcat $image.aff | sfsimage -i - $image.sfs      ## converting AFF --> compressed SquashFS 
                                                  ##    (forensic evidence container)


##-===========================================-##
##   [+] convert AFF images --> raw image
##-===========================================-##
affconvert -r $image.aff                         ## convert AFF images to a raw image


##-=======================================================-##
##   [+] ftkimager tool converts between EnCase and FTK
##-=======================================================-##
## ------------------------------------------------------- ##
##      a set of compressed FTK SMART *.s01 files
##     are converted to the EnCase EWF *E01 format:
## ------------------------------------------------------- ##

##-=====================================================================-##
##  [+] Convert from FTK SMART *.s01 --> EnCase EWF *E01 format
##-=====================================================================-##
ftkimager image.s01 image --e01


##-=====================================================================-##
##  [+] Convert Files from EnCase EWF *E01 format --> FTK SMART *.s01
##-=====================================================================-##
ftkimager image.E01 image --s01


aimage --lzma_compress --compression=9 /dev/$Disk $image.aff
affcat $image.aff | ftkimager - image --s01      ## convert a AFF image to EnCase or FTK
affcat $image.aff > $image.raw                    ## convert a raw image to an AFF format
affconvert -r $image.aff                         ## convert AFF images to a raw image
affconvert $image.raw                           ## convert a raw image -->> an AFF

affinfo $image.aff > $affinfo.txt                 ## extract the metadata from AFF files
sfsimage -a $affinfo.txt $image.sfs               ## add the AFF Metadta to the SquashFS forensic evidence container

ftkimager $image.s01 image --e01                    ## Converting FTK *.s01 --> EnCase EWF *E01 format
ftkimager $image.E01 image --s01                    ## Convert EnCase EWF *E01 --> FTK *.s01
ftkimager --compress 9 --s01 /dev/$Disk $image      ## FTK Smart Compressed Acquisition
ewfacquire $image.raw -t $image -f encase7          ## convert $image.raw to EnCase Expert Witness format:
ewfacquire -c bzip2:best -f encase7-v2 /dev/$Disk   ## EnCase EWF Compressed Acquisition
ewfinfo $image.E01                                  ## Examine File Hashes


affcat $image.aff | sfsimage -i - $image.sfs    ## converting AFF --> compressed SquashFS 
mksquashfs $image.raw $image.sfs -comp lzo -noI   ## raw image -->> compressed SquashFS
zcat $image.raw.gz | sfsimage -i - $image.sfs   ## gzipped raw image -->> SquashFS compressed file:
sfsimage -i $image.raw $image.sfs               ## Convert raw image -->> SquashFS
sfsimage -m $image.sfs                          ## mount the *.sfs file
unsquashfs -lls $image.sfs                      ## view the contents of a SquashFS file
affconvert -Oaff $image.sfs.d/$image.raw        ## [ (raw image) inside a SquashFS ] --> AFF file


## Remote Acquisition to a SquashFS Evidence Container
ssh root@remote-pc "dd if=/dev/mmcblk0" | sfsimage -i - remote-pc.sfs


## use ssh to pipe the disk image over ssh to the remote machine
dd if=/dev/hda1 | ssh username@192.168.0.2 "cat > /home/username/hda1_drive_image.img"


## To reimage /dev/hda1 with a file you have saved
dd if=/mnt/hdb1/hda1_drive_image.img of=/dev/hda1

## Restore Hard drive Image Through The network Tunneled over SSH
ssh username@192.168.0.2 "cat /home/username/hda1_drive_image.img" | dd of=/dev/hda1






mkdir -m 0700 -p \$GNUPGHOME;
for fpr in \$(gpg --with-fingerprint builder-conf-repo-key.asc | grep fingerprint | cut -f 2 -d= | tr -d ' '); do
echo \$fpr:6: | gpg --import-ownertrust;


/usr/lib/qubes/qrexec-client-vm dom0 qubesbuilder.ExportDisk /bin/echo -e "$key\n${PWD}/${IMAGE_NAME}"
    qvm-run --dispvm "/usr/lib/qubes/qrexec-client-vm dom0 qubesbuilder.AttachDisk /bin/echo $key;
            
        pkexec sh -c 'echo Defaults !requiretty >> /etc/sudoers';
        sudo mount /dev/xvdi /mnt/removable -o discard;
        cd /mnt/removable;
        umask 022;



##-==============================================================-##
##  [+] 


##-==============================================================-##
##  [+] 


##-==============================================================-##
##  [+] 


## [ (raw image) inside a SquashFS ] --> AFF file
affconvert -O aff $image.sfs.d/$image.raw        ## [ (raw image) inside a SquashFS ] --> AFF file



## gzipped raw image --> SquashFS compressed file:
zcat $image.raw.gz | sfsimage -i - $image.sfs



## Converting from a raw image to FTK SMAR
ftkimager $image.raw image --s01 --case-number 1 --evidence-number 1 --description "The case of the missing red stapler" --examiner "S. Holmes" --notes "This USB stick was found at the scene"




openssl x509 -in -.wikipedia.org -text -noout

cat -.wikipedia.org.DER | sha256sum >> wikipedia.org.sha256

openssl asn1parse -i -in wikipedia.pem

openssl asn1parse -in wikipedia.pem -strparse 4 -out wikipedia.tbs 


openssl asn1parse -in wikipedia.pem -strparse 1554 -out wikipedia.sig
od -tx1 wikipedia.sig
openssl x509 -in globalsignv2.pem -noout -pubkey >globalsignov2.pub
openssl pkey -in globalsignv2.pub -pubin -text

openssl sha256 <wikipedia.tbs -binary >hash
od -tx1 hash
openssl pkeyutl -verify -in hash -sigfile wikipedia.sig -inkey globalsignov2.pub -pubin -pkeyopt digest:sha256

openssl sha256 <wikipedia.tbs -verify globalsignov2.pub -signature wikipedia.sig




openssl req -new -nodes -out req.pem -keyout cert.key -sha25

openssl genrsa -rand -genkey -out cert.key 2048

openssl req -new -x509 -days 365 -key cert.key -out cert.crt



tar -c  | gzip | gpg -c | dd of=/home/poozer/file.tar.gz.gpg




dc3dd if=$image.raw of=/dev/$Disk log=clone.log        ## Write an Image File to a Clone Disk



##-=========================================================================================-##
##   [+] Encrypt an image with 256-bit AES using cipher block chaining mode
##-=========================================================================================-##
openssl enc -aes-256-cbc -in $image.raw -out $image.raw.aes


##-=========================================================================================-##
##   [+] Perform encryption during acquisition
##-=========================================================================================-##
dcfldd if=/dev/$Disk | openssl enc -aes-256-cbc > $image.raw.aes


##-=========================================================================================-##
##   [+] Decrypting The OpenSSL-encrypted file
##-=========================================================================================-##
openssl enc -d -aes-256-cbc -in $image.raw.aes -out $image.raw    

##-=========================================================================================-##
## Add compression on the fly during an acquisition, add gzip to the pipe
##-=========================================================================================-##
dcfldd if=/dev/$Disk | gzip | openssl enc -aes-256-cbc > $image.raw.gz.aes


##-=======================================================================-##
##  1). The decryption syntax takes the compressed and encrypted file as input
##  2). It then Pipes the decrypted output to gunzip, 
##  3). The raw image is piped to sha256sum.
## ----------------------------------------------------------------------- ##
##   TLDR: verify the cryptographic hash of the image
##-=======================================================================-##
openssl enc -d -aes-256-cbc < $image.raw.gz.aes | gunzip | md5sum









##-=========================================================================================-##
##   [+] Use GPG to encrypt a specified image, using symmetric encryption.
gpg -cv $image.raw


##-=========================================================================================-##
##   [+] encrypt on the fly during acquisition:
## ------------------------------------------------------------------------------ ##
##   1). dcfldd acquires the attached disk via /dev/$Disk 
##   2). pipes the disk directly into GPG, which reads from stdin, and encrypts to stdout.       ## GPG then redirects the finished GPG-encrypted image to an output file
## ------------------------------------------------------------------------------ ##
sudo dcfldd if=/dev/$Disk | gpg -cv > $image.raw.gpg


##-=================================================================================-##
##   [+] Decrypt GPG-encrypted image - Send Raw image to stdout (Output to file)
##-=================================================================================-##
## ------------------------------------------------------------------------------ ##
##   1). The GPG-encrypted image file is decrypted
##   2). The raw image is written to a file.
## ------------------------------------------------------------------------------ ##
gpg -dv -o $image.raw $image.raw.gpg




##-=========================================================================================-##
##   [+] Symmetric Encryption - Decrypting A GPG-encrypted file - Piping it to sha256sum
##-=========================================================================================-##
## ----------------------------------------------------------------------------------------- ##
##           [+] The integrity is verified by Comparing:
##   (GPG-encrypted image) <--> (raw image file SHA256 Hashsum)
## ----------------------------------------------------------------------------------------- ##
gpg -dv $image.raw.gpg | sha256sum





zcat $image.raw.gz | sha256sum      ## zcat uncompresses it, then pipes SHA256sum to determine the sha256 cryptographic hash.
cat $image.raw.* | sha256sum        ## Check the SHA256 hashsum of the split raw images

ewfinfo $image.E01               ## Examine File Hashes
affinfo -S $image.aff            ## validity checking for AFF files
ewfverify $image.Ex01            ## evidence integrity checking - validate the hash
img_stat $image.E01              ## evidence integrity checking - 



openssl sha256 $image.raw
grep "(sha256)" $hashlog.txt
diff $hash1.log $hash2.log            ## Check integrity of forensic images using cryptographic hashes
gpg < $hash.log.asc                  ## verify the gpg signature of the signed acquisition disk image:
gpgsm --verify $image.log.pem        ## S/MIME signed messages - validate signature of a PEM file



## FreeTSA
## the CA cert is fetched from FreeTSA:
curl http://freetsa.org/files/cacert.pem > $cacert.pem


## validate the timestamp:
openssl ts -verify -in $hash.log.tsr -queryfile $hash.log.tsq -CAfile $cacert.pem


The timestamp query ( tsq ) 
timestamp reponse ( tsr )



hdparm --verbose --dco-identify /dev/sda
hdparm --verbose --dco-restore


## To remove a DCO from the hard drive on /dev/sda:
tableau-parm -r /dev/sda


shred --force --iterations=4 --verbose --remove='wipesync' --zero 


shred --verbose --iterations=7 --zero --force 
rm --verbose --recursive --force

wipe -i -r -f -c 

srm -r -v -z
srm -v -z 

dc3dd wipe=/dev/$Disk

time dcfldd if=/dev/sdc of=





gpart $Image.raw                    ## partition scanning to identify lost partitions.

testdisk /list /dev/$Disk           ## repair and recover damaged partitions



zpool create -f -m /mnt/ZPool-ZFS ZPool-ZFS /dev/sdc
zpool import -d /mnt/ZPool-ZFS/Scripts ZPool-ZFS/Scripts
zfs set mountpoint=/mnt/ZPool-ZFS/Scripts ZPool-ZFS/Scripts

zpool import -d /mnt/ZPool-ZFS ZPool-ZFS

zpool export -f 
zfs unmount ZPool-ZFS/Scripts
umount /mnt/ZPool-ZFS/Scripts
zfs unmount -f ZPool-ZFS/Scripts

zpool get health ZPool-ZFS
zpool status -v ZPool-ZFS
chmod -v -R ugo+rwx /mnt/ZPool-ZFS
chown -v -R xe1phix /mnt/ZPool-ZFS

zfs list -o mounted,name,used,avail,copies,rdonly,mountpoint,type
zfs list -o name,used,avail,aclmode,aclinherit,zoned,xattr,copies,checksum,compress,rdonly
zpool get all ZPool-ZFS

zfs create -o exec=off -o compression=on -o setuid=off -o xattr=on -o checksum=sha256 -o zoned=on ZPool-ZFS/Scripts
zfs set exec=off ZPool-ZFS/Scripts
zfs set zoned=on ZPool-ZFS/Scripts
zfs set setuid=off ZPool-ZFS/Scripts
zfs set vscan=on ZPool-ZFS/Scripts
zfs set readonly=on ZPool-ZFS/Scripts
zfs set compression=zls ZPool-ZFS/Scripts
zfs set copies=2 ZPool-ZFS/Xe1phixGitLab
zfs set xattr=on ZPool-ZFS


zfs set compression=on ZPool-ZFS/Scripts
zfs snapshot -r ZPool-ZFS/Xe1phixGitLab@today


ewfmount image.E01 raw

hexedit -s raw/ewf1                 ## analyze the raw image




losetup -f --show
losetup -l                  ## List partition mappings
losetup -r                  ## Read-only partition mappings


fsck /dev/mapper/loop1p1            ## loop1p1 is the name of a device file under /dev/mapper which you can use to access the partition

kpartx -av disk.img                 ## mount all the partitions in a raw disk image:
kpartx -r -a -v raw/ewf1            ## Read-only partition mappings.
kpartx -d image.raw                 ## remove the devices
## loop deleted : /dev/loop0



## Creating a Loop Device
losetup /dev/loop0 /home/bob/safe.img




kpartx -a -s -v "$img" 2>&1




xmount --cache xmount.cache --in raw image.raw --out vdi virtual
ls virtual/




Create a directory with restricted chmod file mode bits.
Then  a Temp directory using mktemp. 
mkdir --mode=0644 QemuKVM && mktemp --directory QemuKVM/'tmp.XXXXXXXXXX'




qemu-img info file.img
qemu-img info image.qcow2



echo "----Creating QEMU Image----"
qemu-img create -f raw "${IMAGE}" 1G

echo "----Mounting QEMU Image----"
kpartx -a -s -v "${IMAGE}"

echo "----Creating Filesystem----"
mkfs.ext2 "${DEVICE}"

echo "----Making QEMU Image Mountpoint----"
if [ ! -e "${IMAGE_DIR}" ]; then
    mkdir "${IMAGE_DIR}"
    chown "${USER}" "${IMAGE_DIR}"
fi

echo "----Mounting QEMU Image Partition 1----"
mount "${DEVICE}" "${IMAGE_DIR}"

echo "----Unmounting QEMU Image----"
sync
umount "${DEVICE}"
kpartx -d "${IMAGE}"
losetup -d "${DEVICE}" &>/dev/null
dmsetup remove $(basename "$DEVICE") &>/dev/null






##-============================================================================-##
##           [+] KVM/Qemu - Converting Virtual Images Table:
##-============================================================================-##

qemu-img convert -f raw -O qcow2 image.img image.qcow2      ## convert a .raw image -->> .qcow2 image.
qemu-img convert -f vmdk -O raw image.vmdk image.img        ## convert a .vmdk image -->> .raw image.
qemu-img convert -f vmdk -O qcow2 image.vmdk image.qcow2    ## convert a .vmdk image -->> .qcow2 image file.
qemu-img convert appliance $HD.vmdk -O raw $raw.hdd         ## convert a .vmdk image -->> .hdd image.
qemu-img convert harddrive-name.vmdk raw-file.bin           ## Convert a .vmdk image -->> .bin file.





## convert a .raw image -->> .qcow2 image.
qemu-img convert -f raw -O qcow2 image.img image.qcow2      ## convert a .raw image -->> .qcow2 image.

## convert a .vmdk image -->> .raw image.
qemu-img convert -f vmdk -O raw image.vmdk image.img        ## convert a .vmdk image -->> .raw image.

## convert a ..vmdk image file to a q.cow2 image file.
qemu-img convert -f vmdk -O qcow2 image.vmdk image.qcow2    ## convert a ..vmdk image file to a q.cow2 image file.

## convert a .vmdk image -->> .hdd image.
qemu-img convert appliance $HD.vmdk -O raw $raw.hdd         ## convert a .vmdk image -->> .hdd image.

## Convert a .vmdk -->> .bin file.
qemu-img convert harddrive-name.vmdk raw-file.bin           ## Convert a .vmdk -->> .bin file.





## Network Block Device
qemu-nbd --read-only --connect /dev/nbd0 image.qcow2
mmls /dev/nbd0
fls /dev/nbd0p1
qemu-nbd --read-only --disconnect /dev/nbd0

## create a QCOW2-image for your virtual machine			## 
qemu-img create -f qcow2 vm.qcow2 10G					## 

virt-clone --connect=qemu://example.com/system -o this-vm -n that-vm --auto-clone


sudo -u "$user_name" qemu-img info "$vmdk_file"
sudo -u "$user_name" VBoxManage clonehd --format VDI "$vmdk_file" "$vdi_file"
sudo -u "$user_name" qemu-img info "$vdi_file"
sudo -u "$user_name" qemu-img info "$image_file"
sudo -u "$user_name" qemu-img convert -p -O raw "$image_file" "$raw_file"


qemu-img convert -p -O qcow2 -o preallocation=metadata "$Image.img" "$WHONIX_BINARY/$VMNAME-$new.qcow2"


## creates a raw image in the current directory from a VirtualBox VDI image.
VBoxManage clonehd ~/VirtualBox\ VMs/image.vdi image.img --format raw


VBoxManage showhdinfo $Image.vdi
qemu-nbd -c /dev/nbd0 $Image.vdi

vmdkinfo lion.vmdk                  ## retrieve information about the assembled image and each of the “Extents”
vmdkmount lion.vmdk lion            ## Creating a mount point and mounting the image makes it accessible as a raw image file





virsh net-list
virsh dumpxml <domain> > domain.xml
virsh create domain.xml
virsh define domain.xml
virsh iface-dumpxml iface > iface.xml
virsh iface-define iface.xml
virsh net-dumpxml --inactive network > network.xml
virsh net-define network.xml

## instructs virsh to additionally display pool persistence and capacity
virsh pool-dumpxml pool > pool.xml
virsh vol-create differentstoragepool newvolume.xml
virsh vol-dumpxml --pool storagepool1 appvolume1 > newvolume.xml
virsh pool-define pool.xml

virsh save-image-dumpxml state-file > state-file.xml
virsh save-image-define state-file state-file-xml


repo --name=fedora --gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-fedora-20-primary --ignoregroups=true --mirrorlist=https://mirrors.fedoraproject.org/metalink?repo=fedora-20&arch=$basearch
repo --name=fedora-updates --gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-fedora-20-primary --ignoregroups=true --mirrorlist=https://mirrors.fedoraproject.org/metalink?repo=updates-released-f20&arch=$basearch
repo --name=installer --baseurl=file:///tmp/qubes-installer/yum/installer/
repo --name=qubes-dom0 --baseurl=file:///tmp/qubes-installer/yum/qubes-dom0/
repo --name=dom0-updates --baseurl=file:///tmp/qubes-installer/yum/dom0-updates/



qvm-start lab-win7 --cdrom=/usr/lib/qubes/qubes-windows-tools-201211301354.iso

sudo qubes-dom0-update qubes-template-debian-8
sudo qubes-dom0-update anti-evil-maid
sudo qubes-dom0-update --enablerepo=qubes-tempates-community qubes-template-whonix-gw qubes-template-whonix-ws


qvm-create --hvm ubuntu --label red

qvm-start ubuntu --cdrom=work-web:/home/user/Downloads/ubuntu-12.10-desktop-i386.iso	


qvm-open-in-vm
qvm-copy-to-vm


qvm-copy-to-vm personal $GPG.key


qvm-run -q --tray -a my-new-anonvm 'TOR_SKIP_LAUNCH=1 TOR_SKIP_CONTROLPORTTEST=1 TOR_SOCKS_PORT=9050 TOR_SOCKS_HOST=1.2.3.4 ./tor-browser_en-US/Browser/start-tor-browser'


qvm-create -p torvm
qvm-service torvm -d qubes-netwatcher
qvm-service torvm -d qubes-firewall
qvm-service torvm -e qubes-tor

_____________________________________________________
# if you  created a new template in the previous step
qvm-prefs torvm -s template fedora-21-tor

____________________________________________________________
## From your TemplateVM, install the torproject Fedora repo
sudo yum install qubes-tor-repo

________________________________________________________
# Then, in the template, install the TorVM init scripts
sudo yum install qubes-tor

_________________________________________________________________________________
## Configure an AppVM to use TorVM as its NetVM (for example a vm named anon-web)
qvm-prefs -s anon-web sys-net torvm
## ... repeat for any other AppVMs you want torified...

_______________________________________________________________________________________
## Shutdown the TemplateVM.
## Set the prefs of your TorVM to use the default sys-net or sys-firewall as its NetVM
qvm-prefs -s torvm netvm sys-net




