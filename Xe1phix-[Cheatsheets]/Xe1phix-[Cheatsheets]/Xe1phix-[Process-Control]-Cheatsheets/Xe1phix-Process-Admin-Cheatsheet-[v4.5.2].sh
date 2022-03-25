
lsof -p $PID
lsof -p $(pgrep $Process)

strace -f -p $PID


Flush DNS cache
killall -HUP mDNSResponder


kill ‐s TERM $PID               ## [15] TERM (software termination signal)
killall ‐1 $Service             ## [ 1] HUP (hang up)
kill -SIGHUP $PID               ## [ 1] HUP (hang up)
pkill ‐9 $Service               ## [ 9] KILL (non­catchable, non­ignorable
kill -SIGKILL $PID              ## [ 9]  SIGKILL (Kill signal)
killall -9 $Service             ## [ 9]  SIGKILL (Kill signal)
pkill ‐TERM ‐u $User            ## [15] TERM (software termination signal)
kill -SIGTERM $PID              ## [15] SIGTERM (Termination signal.)
fuser ‐k ‐TERM ‐m /home         ## [15] kill every process accessing /home (to umount)

kill -9 $$                      ## Kill current session


kill $(ps -ef | awk '/sshd/ {print $2}')
kill $(ps -ef | awk '/mysql/ {print $2}')

kill `netstat -anp --tcp -4 | awk '/:22/ && /LISTEN/ { print $7 }' | cut -f1 -d/`
/etc/init.d/`netstat -anp --tcp -4 | awk '/:22/ && /LISTEN/ { print $7 }' | cut -f2 -d/` stop


## use kill to remove any user remotely running ssh off your box ##

kill $(ps -ef | awk '/sshd/ {print $2}')

kill $(ps -ef | awk '/cupsd/ {print $2}')



watch -n 1 lsof -nPi :47145
watch -n 1 lsof -nPi tcp:22
watch --color -n 1 lsof -nPi tcp:443
watch --color -n 1 lsof -nPi tcp:80
watch --color -n 1
watch --color -n 1 lsof -i udp:5353 -t
watch --color -n 1 lsof -iTCP -sTCP:LISTEN
watch --color -n 1 lsof -t -c sshd
watch --color -n 1 lsof -i tcp:ssh
watch --color -n 1 lsof -i tcp:22
watch --color -n 1 lsof -u syslog
watch --color -n 1 lsof +d /var/log
watch --color -n 1 lsof -i udp -u root

lsof -nP -iTCP -sTCP:LISTEN
lsof -nP -iUDP:LISTEN
lsof -P -i tcp | grep -i listen


TCP in use
lsof -nPi tcp

lsof -nPi udp


lsof



while :; do kill -9 `lsof -t -i :47145`; done


while :; do kill -9 `lsof -p $(pgrep gvfsd-smb)`; done
while :; do kill -9 `lsof -c gvfsd-smb)`; done
 /usr/lib/gvfs/gvfsd-smb-browse
/usr/lib/gvfs/gvfsd-smb-browse
_gateway:netbios-ssn
4054
/usr/lib/x86_64-linux-gnu/libsmbclient.so.0.4.0
/usr/lib/x86_64-linux-gnu/libsamba-util.so.0.0.1
/usr/lib/x86_64-linux-gnu/samba/libmsrpc3.so.0
/usr/lib/x86_64-linux-gnu/samba/liblibsmb.so.0
/usr/lib/x86_64-linux-gnu/samba/libsamba-security.so.0
/usr/lib/x86_64-linux-gnu/libsmbconf.so.0
/usr/lib/x86_64-linux-gnu/samba/libcli-smb-common.so.0
/usr/lib/x86_64-linux-gnu/samba/libsamba3-util.so.0
/usr/lib/x86_64-linux-gnu/libnss_mdns4_minimal.so.2
/usr/lib/x86_64-linux-gnu/samba/libwinbind-client.so.0
/usr/lib/x86_64-linux-gnu/samba/libwind-samba4.so.0.0.0
/usr/lib/x86_64-linux-gnu/samba/libcli-ldap-common.so.0
/usr/lib/x86_64-linux-gnu/samba/libsamba-modules.so.0
/usr/lib/x86_64-linux-gnu/libwbclient.so.0.14
/usr/lib/x86_64-linux-gnu/samba/libauthkrb5.so.0
/usr/lib/x86_64-linux-gnu/samba/libgssapi-samba4.so.2.0.0
/usr/lib/x86_64-linux-gnu/samba/libaddns.so.0
/usr/lib/x86_64-linux-gnu/libldap_r-2.4.so.2.10.11
/usr/lib/x86_64-linux-gnu/samba/libserver-role.so.0
/usr/lib/x86_64-linux-gnu/samba/libserver-id-db.so.0
/usr/lib/x86_64-linux-gnu/samba/libsmb-transport.so.0
/usr/lib/x86_64-linux-gnu/libndr-nbt.so.0.0.1
/usr/lib/x86_64-linux-gnu/samba/libsamba-sockets.so.0
/usr/lib/x86_64-linux-gnu/libdcerpc-binding.so.0.0.1






/proc/[pid]/stat
              Status information about the process





ss -plnut

netstat -plnut


ps -eo pid,user,group,gid,vsz,rss,comm --sort=-rss | less

ps -ef --sort=user | less



## kill all related processes using your device
fuser -mk /dev/sdc


chkconfig --list
service --status-all | grep '+'
service --status-all | grep running
service --status-all | grep running... | sort
systemctl list-units | grep .service
systemctl list-units | grep .target
systemctl list-unit-files --type=service
systemctl list-unit-files --type=target
systemctl list-unit-files --type service --state enabled
systemctl list-unit-files --type service --state running
systemctl list-unit-files --type=service | grep -v disabled
systemctl list-unit-files --type=service | grep -v masked





--signal

--state
--full
--user
--system


--property
--value
--recursive
--show-types


systemctl --all list-unit-files
systemctl --all --show-types

systemctl show --property "Wants" multi-user.target
systemctl show --property "Requires" multi-user.target
systemctl show --property "WantedBy" getty.target
systemctl show --property "Wants" multi-user.target | fmt -10 | sed 's/Wants=//g' | sort


systemctl status $Service | grep -i active
systemctl is-enabled


strings /sbin/init | grep -i systemd



cat /etc/systemd/system/My_New_Service.service
cat /lib/systemd/system/sshd.service


List failed units:
systemctl --failed


Show the cgroup slice, memory and parent for a PID:
systemctl status pid


| grep -Fe .service -e .socket





pidof apache2 | tr ' ' '\n' | grep -w $(cat -vET $PIDFILE)



pgrep -fl php
  // PHP related processes



Find the process ID of the named daemon:
pgrep -u root,daemon
pgrep -u root named


Make syslog reread its configuration file:
kill -HUP syslogd

Give detailed information on all xterm processes:
ps -fp $(pgrep -d, -x firefox)


Make all chrome processes run nicer:
renice +4 $(pgrep chrome)


/proc/pid/stat


ps aux --sort=-resident|head -11
  // Check for memory hoggers (one who leak?)





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
mkdir --mode=0774 /var/log/journal

systemd-tmpfiles --create --prefix /var/log/journal

/etc/systemd/journald.conf




journalctl --list-boots | head
journalctl -k                           ## kernel messages
journalctl -k -f                        ## follow kernel messages
journalctl -u NetworkManager.service    ## Service messages
journalctl -f -u NetworkManager.service ## follow service
journalctl -fn 0 -u NetworkManager -u wpa_supplicant
journalctl -u httpd.service             ##
journalctl -k -b -1                     ## view the boot logs
journalctl /dev/sda                     ## all logs of the kernel device node `/dev/sda`
journalctl -u systemd-networkd
journalctl -u auditd.service            ##
journalctl --list-boots                 ## check only boot messages
journalctl -b $BootID                   ## show boot messages for a selected boot ID

journalctl _SYSTEMD_UNIT=avahi-daemon.service
journalctl -p emerg..err
journalctl -o verbose
journalctl --since "2019-07-05 21:30:01" --until "2019-07-05 21:30:02"
journalctl -n50 --since "1 hour ago"





tail -f /var/log/messages

syslog –f
syslog –d <directory>

bzcat system.log.1.bz2 system.log.0.bz2 >> system_all.log

cat system.log >> system_all.log


# last logged on user information
lastlogedonusrs=`lastlog 2>/dev/null |grep -v "Never" 2>/dev/null`
if [ "$lastlogedonusrs" ]; then
  echo -e "\e[00;31m[-] Users that have previously logged onto the system:
fi




find . -mtime -7
  // Files created within last 7 days


find . -mtime +14 -type f -name '*.gz'
  // Files *.gz older than 14 days

tail -f file.log | grep 192.168.1.1
  // Monitor a log file

find . -size +100M
  // Files over 100megs


# top 10 by process sorted
ps aux | awk '{print $2, $4, $11}' | sort -k2rn | head -n 10
ps -eo size,pid,user,command | awk '{ hr=$1/1024 ; printf("%13.6f Mb ",hr) } { for ( x=4 ; x<=NF ; x++ ) { printf("%s ",$x) } print "" }' | sort


# number of open files
lsof | awk '{ print $2 " " $1; }' | sort -rn | uniq -c | sort -rn | head -20







View established connections of current machine:
netstat -a -n -p tcp | find "ESTAB"


/etc/systemd/journald.conf
/etc/systemd/journald.conf.d/*.conf
/run/systemd/journald.conf.d/*.conf
/usr/lib/systemd/journald.conf.d/*.conf



journalctl --rotate

journalctl --sync

sd-journal
systemd.journal-fields
sd_journal_print

MaxLevelStore=debug

MaxLevelSyslog=debug

MaxRetentionSec=0
SystemMaxFiles=


Storage=persistent
Compress=
Seal=
SplitMode=uid

RateLimitIntervalSec=
RateLimitBurst=
RateLimitIntervalSec=


--setup-keys




jls -f linux-ext3 img.dd

jcat -f linux-ext3 img.dd 34 | xxd



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



for foo in $(strace -e open lsof -i tcp 2>&1 | grep 'denied'| awk '{print $1}' | cut -d "/" -f3); do echo $foo $(cat /proc/$foo/cmdline)|awk '{if($2) print}'; done



lsof -p NNNN | awk '{print $9}' | grep '.so'

cat /proc/NNNN/maps | awk '{print $6}' | grep '.so' | sort | uniq


strace -e trace=open xtrabackup --prepare --target-dir=2014-11-27_06-06-49
while true; do lsof +D ./2014-11-27_06-06-49 ; sleep 0.1; done


echo | openssl s_client -showcerts -servername gnupg.org -connect ec2-54-69-218-94.us-west-2.compute.amazonaws.com:443 2>/dev/null | openssl x509 -inform pem -noout -text | grep \"Subject:\\|DNS:\"

ffmpeg -i in.mkv -c copy -c:s mov_text out.mp4
tshark  -i en14 -s0 -l -f \"not port 443 and not src 192.168.1.255 and not src 8.8.8.255 and not tcp\" -Y \"dns\" 2> /dev/null | tee -a /tmp/dns_log.txt | grep --line-buffered -v \"query response\" | awk  -v OFS=' ' '{ print $1,$5,\"[\"$3\"]\",\"-->\",$14}'
tshark  -i en14 -s0 -l -f \"not port 443 and not src 192.168.1.1 and not src 8.8.8.8 and not tcp\" -Y \"dns and dns.flags.response == 0\"  2> /dev/null | awk '{print $5,\" ---> \", $14}'

dig @224.0.0.251 -p 5353 -t ptr +short _printer._tcp.local


pcat -v $PID                        ## displays the location of each memory region that is being copied

pmap -d 7840                        ## Provide Libraries loaded by a running process with pmap


pidstat -p $PID	                ## gather resource consumption details for a specific target process

sar -n DEV 1
sar -n TCP,ETCP 1


pgrep -u root named							# Find the process ID of the named daemon:
pgrep -u root sshd
pgrep -u root,daemon


pcat -v $PID                        ## displays the location of each memory region that is being copied

pmap -d 7840                        ## Provide Libraries loaded by a running process with pmap
pmap -x $(pgrep java)


  /6/	   \6\
 /Y/		\Y\
(</_____\>)
	|	r-	|			## readable memory mapping
	|	w	|			## writable memory mapping
	|	x	|			## executable memory mapping
	|	s	|			## shared memory mapping or
	|	p	|			## private mapping.
<#--------#>


##-================================-##
##    [+] process memory mapped files
##-================================-##
## ------------------------------------------------------------------------------ ##
##     [?] the process’s memory mapped (shared) files
## ------------------------------------------------------------------------------ ##
pmap -x 6 | grep "[r-][w-][x-][s][R-]"


cat /proc/$(pgrep $Process)/status | grep


pidstat -p $PID	                ## gather resource consumption details for a specific target process


kill `lsof -t /home`		        ## Kill all processes that have files open under /home.

killall -9 sshd
pkill -9 -u root sshd
pkill -HUP syslogd                  ## Make syslog reread its configuration file:


##-==================================================-##
##    [+] kill all sshd processes whose parent process ID is 1:
##-==================================================-##
pkill -P 1 sshd				## kills only the master sshd process leaving all of the users on the system still logged in.




strace -etrace=write -p 1234
strace -f -e open bash ./foo.sh
strace -e trace=file -f /etc/init.d/your-service-rc-script start 2>&1 | grep 'EACCES'

strace -f -e trace=network ceph ping mon.hv03.lab.test.lan --connect-timeout=30 2>&1 | grep sin_addr





net.netfilter.nf_conntrack_timestamp
echo 1 > /proc/sys/net/netfilter/nf_conntrack_timestamp
echo 1 > /proc/sys/net/netfilter/nf_conntrack_acct
nf_conntrack_helper
nf_conntrack_log_invalid
net.netfilter.nf_conntrack_acct

/proc/sys/net/core/bpf_jit_enable
kernel.bpf_stats_enabled=
kernel.modules_disabled=
kernel.randomize_va_space=
kernel.seccomp.actions_avail=
kernel.seccomp.actions_logged=
kernel.stack_tracer_enabled=
kernel.sysctl_writes_strict=
kernel.unprivileged_bpf_disabled=
kernel.unprivileged_userns_apparmor_policy=
kernel.unprivileged_userns_clone=
ernel.usermodehelper.bset=
kernel.usermodehelper.inheritable=

net.core.bpf_jit_enable=
net.core.bpf_jit_harden=
net.core.bpf_jit_kallsyms=
net.core.bpf_jit_limit=

net.ipv4.tcp_fwmark_accept=
net.netfilter.nf_log_all_netns=
fs.suid_dumpable=





modprobe nf_conntrack_ipv4
modprobe nf_conntrack_ipv6

iptables -A INPUT -p tcp -m state --state ESTABLISHED -j ACCEPT
iptables -A OUTPUT -p tcp -m state --state NEW,ESTABLISHED -j ACCEPT




