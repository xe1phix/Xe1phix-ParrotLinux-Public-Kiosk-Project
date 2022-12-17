#!/bin/sh
##-===========================================================-##
##    [+] Xe1phix-[]-[v..].sh
##-===========================================================-##


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



##-==========================================-##
##  [+] Top 10 processes sorted by Size
##-==========================================-##
ps aux | awk '{print $2, $4, $11}' | sort -k2rn | head -n 10
ps -eo size,pid,user,command | awk '{ hr=$1/1024 ; printf("%13.6f Mb ",hr) } { for ( x=4 ; x<=NF ; x++ ) { printf("%s ",$x) } print "" }' | sort


##-=================================-##
##  [+] List Number of open files
##-=================================-##
lsof | awk '{ print $2 " " $1; }' | sort -rn | uniq -c | sort -rn | head -20


##-==========================================-##
##  [+] List users with running processes
##-==========================================-##
ps aux | sed -n '/USER/!s/\([^ ]\) .*/\1/p' | sort -u


##-=========================================================-##
##  [+] List Threads by Pid along with Thread Start Time
##-=========================================================-##
ps -o pid,lwp,lstart --pid 797 -L


##-=================================================-##
##   [+] Count processes related to HTTP server
##-=================================================-##
ps aux | grep http | grep -v grep | wc -l


##-=================================================-##
##   [+] Display top 5 processes consuming CPU
##-=================================================-##
ps -eo pcpu,user,pid,cmd | sort -r | head -5


##-========================================================================-##
##   [+] Display the top ten running processes - sorted by memory usage
##-========================================================================-##
ps aux | sort -nk +4 | tail




pstree --show-pids --show-parents --show-pgids --arguments --long --ascii >> pstree.txt && cat pstree.txt
pstree --show-pids --show-parents --show-pgids --arguments --long >> pstree.txt && cat pstree.txt
pstree --show-pids --arguments --long >> pstree.txt && cat pstree.txt
pstree --arguments --show-pids --show-pgids --show-parents > pstree.txt





##-==============================================================-##
##  [+] Summarize the number of open TCP connections by state
##-==============================================================-##
netstat -nt | awk '{print $6}' | sort | uniq -c | sort -n -k 1 -r


##-==============================================================-##
##  [+] calulate established tcp connection of local machine
##-==============================================================-##
netstat -an | grep -Ec '^tcp.+ESTABLISHED$'





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



dnstracer -v -o $domain
dnswalk -r -d $domain
dnsviz-query 

dnstwist --all


dnstraceroute [-h] [-q] [-a] [-s server] [-p port] [-c count] [-t type

--asn
              Turn on AS# lookups for each hop encountered

0trace eth0 $Domain

itrace -i eth0 -d $Domain

intrace

tctrace -i eth0 -d $Domain

tcptraceroute -i eth0 $Domain



tcptrace -l -r o3 $File




##-====================================================-##
##   [+] Print List of Live Hosts on Local Network:
##-====================================================-##
genlist -s 192.168.1.\*






fierce --domain $Domain --subdomains accounts --traverse 10


##-============================================================================-##
##   [+] Limit nearby IP traversal to certain domains with the --search flag:
##-============================================================================-##
fierce --domain $Domain --subdomains admin --search $Domain $Domain


##-==================================================================================-##
##   [+] Attempt an HTTP connection on domains discovered with the --connect flag:
##-==================================================================================-##
fierce --domain $Domain --subdomains mail --connect



##-=========================-##
##  [+] Fierce
##-=========================-##
fierce -dns $Domain
fierce -dns $Domain -file $OutputFile
fierce -dns $Domain -dnsserver $Server
fierce -range $IPRange -dnsserver $Server
fierce -dns $Domain -wordlist $Wordlist
fierce -dnsserver $DNS -dns $Domain -wordlist /usr/share/fierce/hosts.txt


fierce -dns $Domain -threads 3



dnsenum.pl --enum -f $File.txt --update a -r $Domain >> ~/Enumeration/$domain



##-=====================================================================-##
##   [+] Search for the A record of $Domain on your local nameserver:
##-=====================================================================-##
dnstracer $Domain


##-=====================================================================-##
##   [+] Search for the MX record of $Domain on the root-nameservers:
##-=====================================================================-##
dnstracer "-s" . "-q" mx $Domain


##-=================================================================-##
##   [+] Search for the PTR record (hostname) of 212.204.230.141:
##-=================================================================-##
dnstracer "-q" ptr 141.230.204.212.in-addr.arpa


##-========================-##
##   [+] IPv6 addresses:
##-========================-##
dnstracer "-q" ptr "-s" . "-o" 2.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.6.4.0.2.0.0.0.0.8.b.0.e.f.f.3.ip6.int



##-=================================================================-##
##   [+]
##-=================================================================-##
dnstop -l 3 eth0




dnswalk $Domain

## ------------------------------------------------------------- ##
##   [?] Print debugging and 'status' information to stderr
## ------------------------------------------------------------- ##


									## ----------------------------------------------------------- ##
dnswalk -r -d $* $Domain.		## Recursively descend sub-domains of the specified domain.
									## Print debugging and 'status' information to stderr
									## ----------------------------------------------------------- ##

									## ---------------------------------------------------- ##
dnswalk -F $Domain					## perform "fascist" checking
									## ---------------------------------------------------- ##
									##  [?] When checking an A record,
									##      compare the PTR name for each IP address
									##      with the forward name and report mismatches.
									## ---------------------------------------------------- ##

dmitry -p $Domain -f -b



dmitry -iwnse $Domain






##-================-##
##  [+] DNSMap
##-================-##
dnsmap -w $File.txt $Domain


## ----------------------------------------------------------- ##
##   [+] DNSenum - enumerate various DNS records, such as:
##                 NS, MX, SOA, and PTR records.
##   [?] DNSenum also tries to perform DNS zone transfer
## ----------------------------------------------------------- ##
dnsenum -p 5 -s 20 $Domain
dnsenum -f $File.txt $Domain
dnsenum -o dnsenum_info $Domain
dnsenum --enum -f $File.txt --update a -r $URL


ss -plnut

netstat -plnut


ps -eo pid,user,group,gid,vsz,rss,comm --sort=-rss | less

ps -ef --sort=user | less



##  [+] kill all related processes using your device

fuser -mk /dev/sdc




## ----------------------------------------------------------- ##
      chkconfig --list
      chkconfig --add $Service
      chkconfig --del $Service
      chkconfig --off $Service
## ----------------------------------------------------------- ##
      update-rc.d $Service stop
      update-rc.d $Service disable
      update-rc.d $Service remove
## ----------------------------------------------------------- ##
      service --status-all | grep running
      service --status-all | grep running... | sort
      service --status-all | grep -v not running
## ----------------------------------------------------------- ##
      systemctl status $Service
      systemctl stop $Service
      systemctl disable $Service
      systemctl mask $Service
## ------------------------------------------------------------------------ ##
      systemctl is-enabled $Service     ##  [+] Show if Unit is Enabled
      systemctl --failed                ##  [+] List Failed Units:
## ------------------------------------------------------------------------ ##
      systemctl --all --show-types
      systemctl --all list-units
      systemctl --all list-unit-files
## ----------------------------------------------------------------- ##
      systemctl list-units | grep .service
      systemctl list-units | grep .target
## ----------------------------------------------------------------- ##
      systemctl list-unit-files --type=service
      systemctl list-unit-files --type=target
## ----------------------------------------------------------------- ##
      systemctl list-unit-files --type=service | grep -v disabled
## ----------------------------------------------------------------- ##
      systemctl list-unit-files | grep -Fe .service -e .socket
## ----------------------------------------------------------------- ##
      systemctl status $Service | grep -i active
## ----------------------------------------------------------------- ##
      systemctl show --property "Wants" multi-user.target
      systemctl show --property "Requires" multi-user.target
      systemctl show --property "WantedBy" getty.target
## ---------------------------------------------------------------------------------------------- ##
      systemctl show --property "Wants" multi-user.target | fmt -10 | sed 's/Wants=//g' | sort
## ---------------------------------------------------------------------------------------------- ##




strings /sbin/init | grep -i systemd



cat /etc/systemd/system/My_New_Service.service
cat /lib/systemd/system/sshd.service


##  [+] List failed units:

systemctl --failed


##  [+] Show the cgroup slice, memory and parent for a PID:

systemctl status pid



| grep -Fe .service -e .socket



pgrep -fl php
##  [+] PHP related processes



kill -9 $(pgrep vlc)



##  [+] Find the process ID of the named daemon:

pgrep -u root,daemon
pgrep -u root named



##  [+] Make syslog reread its configuration file:

kill -HUP syslogd


##  [+] Give detailed information on all xterm processes:

ps -fp $(pgrep -d, -x firefox)



##  [+] Make all chrome processes run nicer:

renice +4 $(pgrep chrome)



/proc/pid/stat



ps aux --sort=-resident|head -11
##  [+] Check for memory hoggers (one who leak?)



shopt -s			# set
shopt -u			# unset

sed 's/foo/bar/'



apt-config dump


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




## ---------------------------------------------------------------------------------------------- ##
      journalctl -k -b -1                     ## view the boot logs
      journalctl --list-boots                 ## check only boot messages
      journalctl -b $BootID                   ## show boot messages for a selected boot ID
## ---------------------------------------------------------------------------------------------- ##
      journalctl -k                           ## kernel messages
      journalctl -k -f                        ## follow kernel messages
## ---------------------------------------------------------------------------------------------- ##
      journalctl /dev/sda                     ## all logs of the kernel device node `/dev/sda`

## ---------------------------------------------------------------------------------------------- ##
      journalctl -u $Service.service          ##
      journalctl -u NetworkManager.service    ## Service messages
## ---------------------------------------------------------------------------------------------- ##
      journalctl -f -u NetworkManager.service ## follow service
      journalctl -fn 0 -u NetworkManager -u wpa_supplicant
## ---------------------------------------------------------------------------------------------- ##
      journalctl -k -b -1                     ## view the boot logs
## ---------------------------------------------------------------------------------------------- ##
      journalctl -u systemd-networkd
      journalctl -u auditd.service            ##
## ---------------------------------------------------------------------------------------------- ##


      journalctl _SYSTEMD_UNIT=$Service.service
## ---------------------------------------------------------------------------------------------- ##
      journalctl -p emerg..err
      journalctl -o verbose
## ---------------------------------------------------------------------------------------------- ##
      journalctl --since "2019-07-05 21:30:01" --until "2019-07-05 21:30:02"
      journalctl -n50 --since "1 hour ago"
## ---------------------------------------------------------------------------------------------- ##




tail -f /var/log/messages

syslog –f
syslog –d <directory>

bzcat system.log.1.bz2 system.log.0.bz2 >> system_all.log

cat system.log >> system_all.log


##  [+] last logged on user information
lastlogedonusrs=`lastlog 2>/dev/null |grep -v "Never" 2>/dev/null`
if [ "$lastlogedonusrs" ]; then
  echo -e "\e[00;31m[-] Users that have previously logged onto the system:"
fi




iptables ­A INPUT ­p TCP ­­dport 22 ­j ULOG ­­ulog­prefix "SSH connection attempt: "



conntrackd -C /etc/conntrackd/conntrackd.conf


ulogd --daemon --uid ulog --pidfile /run/ulog/ulogd.pid


##  [+] 

darkstat --verbose -i eth0 --hexdump --export ~/$File.txt


nast -m -i eth0


ngrep -q 'HTTP' 'host 192.168'			## matches all headers containing the string 'HTTP' sent to or from the ip address starting with 192.168
ngrep -q 'HTTP' 'dst host 192.168'		## match a destination host
ngrep -q 'HTTP' 'src host 192.168'		## match a source host
ngrep -q 'HTTP' 'port 80'						## match a port




ntop -d -L -u ntop –access-log-file=/var/log/ntop/access.log -b -C –output-packet-path=/var/log/ntop-
suspicious.log –local-subnets 192.168.1.0/24,192.168.2.0/24,192.168.3.0/24 -o -M -p
/etc/ntop/protocol.list -i br0,eth0,eth1,eth2,eth3,eth4,eth5 -o /var/log/ntop




## ------------------------------ ##
##    [?] Extract PCAP Data:
## ------------------------------ ##
capinfos $File.pcap
tcpslice -r $File.pcap
tcpstat $File.pcap
tcpprof -S lipn -P 30000 -r $File.pcap
tcpflow -r $File.pcap
tcpxtract -f $File.pcap -o $Dir/
tcpick -a -C -r $File.pcap
tcpcapinfo $File.pcap
ngrep -I $File.pcap
nfdump -r $File.pcap
chaosreader -ve $File.pcap
tshark -r $File.pcap
tcpdump -r $File.pcap
bro -r $File.pcap
snort -r $File.pcap


tcpflow -o out -a -l *.pcap



tcpick -r $File.pcap -wRu 


tcpflow -c -e -r $File.pcap 'tcp and port (80 or 443)'
tcpflow -r $File.pcap tcp and port \(80 or 443\)
tcpick -r $File.pcap -C -yP -h 'port (25 or 587)'


iftop -i $File.pcap
iftop -i eth0


iftop -i eth0 -f 'port (80 or 443)'
iftop -i eth0 -f 'ip dst 192.168.1.5'

chaosreader -p 20,21,23 output1
       -j 10.1.2.1, --ipaddr 10.1.2.1
              Only examine these IPs.

       -J 10.1.2.1, --noipaddr 10.1.2.1
              Exclude these IPs.
--sort "time"|"size"|"type"|"ip"
              Sort Order: time/size/type/ip (Default time).

       -p 21,23, --port 21,23
              Only examine these ports (TCP & UDP).

       -P 80,81, --noport 80,81
              Exclude these ports (TCP & UDP).

       -s 5, --runonce 5
              Standalone. Run tcpdump/snoop for 5 mins.
--preferdns
              Show DNS names instead of IP addresses.



##-===================================================-##
##   [+]
##-===================================================-##
tcpxtract --file $File.pcap --output $File --device eth0




##-=================================================-##
##   [+] Read PCAP File - Extract 80 & 443 Packets
##-=================================================-##
tcpflow -c -e -r $File.pcap 'tcp and port (80 or 443)'
tcpflow -r $File.pcap tcp and port \(80 or 443\)


##-================================================-##
##   [+] Record on eth0 - Extract Port 80 Packets
##-================================================-##
tcpflow -p -c -i eth0 port 80


##-================================================-##
##   [+] Capture Port 80 With Snap Length: 96
##-================================================-##
tcpflow -i eth0 -b 96 -e -c port 80


##-================================================-##
##   [+] tcp/ip session reassembler:
##-================================================-##
tcpflow -i eth0 -e -c 'port 25'


##-================================================-##
##   [+] Process PCAP Files in Current Directory
##-================================================-##
tcpflow -o $File -a -l *.pcap


##-===================================================-##
##   [+] Record All Packets Going To & From $Domain
##   [+] Extract All of The HTTP Attachments:
##-===================================================-##
tcpflow -e scan_http -o $Dir host $Domain


##-=================================================================-##
##    [+] record traffic between helios and either hot or ace
##    [+] bin the results into 1000 files per directory
##    [+] calculate the MD5 of each flow:
##-=================================================================-##
tcpflow -X $File.xml -e scan_md5 -o $Dir -Fk host helios and \( hot or ace \)









find . -mtime -7
##  [+] Files created within last 7 days


find . -mtime +14 -type f -name '*.gz'
##  [+] Files *.gz older than 14 days

tail -f file.log | grep 192.168.1.1
##  [+] Monitor a log file

find . -size +100M
##  [+] Files over 100megs




##-==========================================-##
##  [+] Top 10 processes sorted by Size
##-==========================================-##
ps aux | awk '{print $2, $4, $11}' | sort -k2rn | head -n 10
ps -eo size,pid,user,command | awk '{ hr=$1/1024 ; printf("%13.6f Mb ",hr) } { for ( x=4 ; x<=NF ; x++ ) { printf("%s ",$x) } print "" }' | sort


##-=================================-##
##  [+] List Number of open files
##-=================================-##
lsof | awk '{ print $2 " " $1; }' | sort -rn | uniq -c | sort -rn | head -20


##-==========================================-##
##  [+] List users with running processes
##-==========================================-##
ps aux | sed -n '/USER/!s/\([^ ]\) .*/\1/p' | sort -u


##-=========================================================-##
##  [+] List Threads by Pid along with Thread Start Time
##-=========================================================-##
ps -o pid,lwp,lstart --pid 797 -L


##-=================================================-##
##   [+] Count processes related to HTTP server
##-=================================================-##
ps aux | grep http | grep -v grep | wc -l


##-=================================================-##
##   [+] Display top 5 processes consuming CPU
##-=================================================-##
ps -eo pcpu,user,pid,cmd | sort -r | head -5


##-========================================================================-##
##   [+] Display the top ten running processes - sorted by memory usage
##-========================================================================-##
ps aux | sort -nk +4 | tail




pstree --show-pids --show-parents --show-pgids --arguments --long --ascii >> pstree.txt && cat pstree.txt
pstree --show-pids --show-parents --show-pgids --arguments --long >> pstree.txt && cat pstree.txt
pstree --show-pids --arguments --long >> pstree.txt && cat pstree.txt
pstree --arguments --show-pids --show-pgids --show-parents > pstree.txt





##-==============================================================-##
##  [+] Summarize the number of open TCP connections by state
##-==============================================================-##
netstat -nt | awk '{print $6}' | sort | uniq -c | sort -n -k 1 -r


##-==============================================================-##
##  [+] calulate established tcp connection of local machine
##-==============================================================-##
netstat -an | grep -Ec '^tcp.+ESTABLISHED$'








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



##  [+] 
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


##-====================================-##
##   [+] process memory mapped files
##-====================================-##
## ------------------------------------------------------------------------------ ##
##   [?] the process’s memory mapped (shared) files
## ------------------------------------------------------------------------------ ##
pmap -x 6 | grep "[r-][w-][x-][s][R-]"


cat /proc/$(pgrep $Process)/status | grep


pidstat -p $PID	                ## gather resource consumption details for a specific target process



pcat -v $PID                        ## displays the location of each memory region that is being copied

pmap -d 7840                        ## Provide Libraries loaded by a running process with pmap


capsh



pidstat -p $PID	                ## gather resource consumption details for a specific target process

sar -n DEV 1
sar -n TCP,ETCP 1


strace -etrace=write -p 1234
strace -f -e open bash ./foo.sh
strace -e trace=file -f /etc/init.d/your-service-rc-script start 2>&1 | grep 'EACCES'

strace -f -e trace=network ceph ping mon.hv03.lab.test.lan --connect-timeout=30 2>&1 | grep sin_addr


##-=========================================================-##
##   [+] follow pid 927 and its children, writing to smtpd:
##-=========================================================-##
strace -p 927 -o smtpd -ff -tt


net.netfilter.nf_conntrack_timestamp
echo 1 > /proc/sys/net/netfilter/nf_conntrack_timestamp
echo 1 > /proc/sys/net/netfilter/nf_conntrack_acct
net.netfilter.nf_conntrack_acct


modprobe nf_conntrack_ipv4
modprobe nf_conntrack_ipv6

iptables -A INPUT -p tcp -m state --state ESTABLISHED -j ACCEPT
iptables -A OUTPUT -p tcp -m state --state NEW,ESTABLISHED -j ACCEPT






slub_debug=P					## Allow allocator validation checking to be enabled

page_poison=1					## Wipe higher-level memory allocations when they are freed (needs "page_poison=1"






  if [ $(lsof -nPi | grep -i apache | grep -c ":80 (LISTEN)") -ge 1 ]; then
    echo '[Success] Apache2 is up and running!'
  else



## Delete broken links
find /etc/apache2 -type l ! -exec test -e {} ; -print | sudo xargs rm


alias watchmysql="watch -n 1 mysqladmin --user=$1 --password=$2 processlist"


## export all of your databases from the remote server:
mysqldump --all-databases > all_databases.txt


alias watchmysql="watch -n 1 mysqladmin --user=$1 --password=$2 processlist"



# Get table column names from an MySQL-database in comma-seperated form
mysql -u<user> -p<password> -s -e 'DESCRIBE <table>' <database>  | tail -n +1 | awk '{ printf($1",")}' |  head -c -1



## Remote mysql dump all databases with ssh
alias mysqldumpssh="mysqldump -u user -p --all-databases | ssh user@host dd of=/opt/all-databases.dump"


# show tcp syn packets on all network interfaces
alias tcpdumptcpsyn="tcpdump -i any -n tcp[13] == 2"


/etc/pure-ftpd/
ps aux | grep pure-ftpd
-*-*/-*************-+*




## --------------------------- ##
##   [?] follow redirects
##   [?] set user-agent
##   [?] set method - GET
## --------------------------- ##
curl -Iks --location -X GET -A "x-agent" $Domain


## --------------------------------- ##
##   [?] Use Proxy for connection
## --------------------------------- ##
curl -Iks --location -X GET -A "x-agent" --proxy http://127.0.0.1:4444 $Domain
curl -Iks --location -X GET -A "x-agent" --proxy socks5://127.0.0.1:9050 $Domain
curl -Iks --location -X GET -A "x-agent" --proxy socks5://127.0.0.1:1080 $Domain


##-===========================================-##
##   [+] Bulk Download Files By Their URLs
##-===========================================-##
## ------------------------------------------------ ##
##   [?] The URL Links Are Fed To Curl From xarg
## ------------------------------------------------ ##
xargs -n 1 curl -O < $File





##
curl sftp://$URL.com/$File.zip -u $User

##
curl scp://$URL.com/$File.zip -u $User


## SFTP (but not SCP) supports getting a file listing
## back when the URL ends with a trailing slash:

curl sftp://$URL.com/ -u $User

curl sftp://$URL.com/~/$File.txt -u $User


## Require TLS security for your FTP transfer:
curl --ssl-reqd ftp://ftp.$URL.com/$File.txt


## Suggest TLS to be used for your FTP transfer:
curl --ssl ftp://ftp.$URL.com/$File.txt







##-================================================-##
##  [+] Upload a file to an FTP server:
##-================================================-##
curl -u $FTPUser:$FTPPass -T $Filename ftp://$URL


##-================================================-##
##  [+] Upload multiple files to an FTP server:
##-================================================-##
curl -u $FTPUser:$FTPPass -T "{$File1,$File2}" ftp://$URL


##-================================================-##
##  [+] Upload a file from STDIN to an FTP server:
##-================================================-##
curl -u $FTPUser:$FTPPass -T - ftp://$URL/$Path/$Filename


Anonymous FTP

nmap -sC -sV -p21
nmap -sV -n -sS -Pn-vv --open -p21 --script=ftp-anon,ftp-bounce,ftp-libopie,ftp-proftpd-backdoor,ftp-vsftpd-backdoor,ftp-vuln-cve2010-4221 <targets>







Retrieve current status of the jail service:

fail2ban-client status $Jail

- Remove the specified IP from the jail services ban list:

fail2ban-client set $Jail unbanip $IP

- Verify fail2ban server is alive:

fail2ban-client ping


##-=====================================-##
##   [+] check all route table
##       > including non default ones
##-=====================================-##
ip route show table all








## ---------------------------------------------- ##
##  [+] Testing connection to the remote host
## ---------------------------------------------- ##
echo | openssl s_client -connect $Domain:443 -showcerts


## ---------------------------------------------------------------- ##
##  [+] Testing connection to the remote host (with SNI support)
## ---------------------------------------------------------------- ##
echo | openssl s_client -showcerts -servername $Domain -connect $Domain:443


## ----------------------------------------------------------------------- ##
##  [+] Testing connection to the remote host with specific ssl version
## ----------------------------------------------------------------------- ##
openssl s_client -tls1_2 -connect $Domain:443


## ----------------------------------------------------------------------- ##
##  [+] Testing connection to the remote host with specific ssl cipher
## ----------------------------------------------------------------------- ##
openssl s_client -cipher 'AES128-SHA' -connect $Domain:443



##-=============================================-##
##   [+] Connect to SMTP server using STARTTLS
##-=============================================-##
openssl s_client -starttls smtp -crlf -connect 127.0.0.1:25
openssl s_client -connect smtp.office365.com:587 -starttls smtp
gnutls-cli-debug --starttls-proto smtp --port 25 localhost



##-=========================================-##
##   [+]
##-=========================================-##
openssl s_client -connect smtp.gmail.com:587 -starttls smtp < /dev/null 2>/dev/null |
openssl x509 -fingerprint -noout -in /dev/stdin | cut -d'=' -f2


##-=========================================-##
##   [+]
##-=========================================-##
openssl s_client -showcerts -starttls smtp -connect smtp_relay:smtp_relay_port < /dev/null 2> /dev/null


##-=========================================-##
##   [+]
##-=========================================-##
sudo -u postfix openssl s_client -showcerts -starttls smtp -connect smtp.gmail.com:587 < /dev/null 2> /dev/null


##-=========================================-##
##   [+]
##-=========================================-##
openssl s_client -CApath /etc/ssl/certs -showcerts -starttls smtp -connect smtp_relay:smtp_relay_port < /dev/null 2> /dev/null


##-=========================================-##
##   [+] secure POP:
##-=========================================-##
openssl s_client -quiet -connect $Domain:995
openssl s_client -crlf -connect server.server.net:110 -starttls pop3


##-=========================================-##
##   [+] secure IMAP:
##-=========================================-##
openssl s_client -quiet -connect $Domain:993
openssl s_client -ssl3 -connect imap.gmail.com:993
gnutls-cli imap.gmail.com -p 993




openssl s_client -showcerts -connect chat.freenode.net:6697




echo -e | openssl s_client -connect duh.to:5222 -starttls xmpp | openssl x509 -noout -fingerprint -sha256 | tr -d ':'


openssl x509 -in /etc/pki/xmpp-cert.pem -fingerprint -noout -sha256





gnutls-cli --crlf --starttls --x509cafile /etc/pki/CA/cacert.pem --port 25 mail.mydomainname.com






openssl s_client -host $Host -port 389
openssl s_client -host $Host -port 636


##-============================================-##
##   [+] Connect to LDAP/LDAPS Using CA File:
##-============================================-##
openssl s_client -CAfile /$Dir/$File.pem -host $Host -port 389
openssl s_client -CAfile /$Dir/$File.pem -host $Host -port 636

openssl s_client -connect $Host:$Port -starttls LDAP

openssl s_client -connect ldap.$Host:389
openssl s_client -connect ldap.$Host:636


##-=================================-##
##   [+] Dump LDAP/LDAPS To File:
##-=================================-##
tcpdump port 389 -w $File.pcap
tcpdump port 636 -w $File.pcap





openssl s_client -connect smtp.gmail.com:587 -starttls smtp < /dev/null 2>/dev/null |



openssl x509 -fingerprint -noout -in /dev/stdin | cut -d'=' -f2




openssl s_client -showcerts -starttls smtp -connect smtp_relay:smtp_relay_port < /dev/null 2> /dev/null



sudo -u postfix openssl s_client -showcerts -starttls smtp -connect smtp.gmail.com:587 < /dev/null 2> /dev/null



openssl s_client -CApath /etc/ssl/certs -showcerts -starttls smtp -connect smtp_relay:smtp_relay_port < /dev/null 2> /dev/null





gnutls-cli-debug localhost



Show all TCP/UDP/RAW/UNIX sockets:

ss -a -t|-u|-w|-x

- Filter TCP sockets by states, only/exclude:

ss state/exclude bucket/big/connected/synchronized/...

- Show all TCP sockets connected to the local HTTPS port (443):

ss -t src :443

- Show all TCP sockets listening on the local 8080 port:

ss -lt src :8080

- Show all TCP sockets along with processes connected to a remote ssh port:

ss -pt dst :ssh

- Show all UDP sockets connected on specific source and destination ports:

ss -u 'sport == :source_port and dport == :destination_port'

- Show all TCP IPv4 sockets locally connected on the subnet 192.168.0.0/16:

ss -4t src 192.168/16





SNMP
----
onesixtyone -c /usr/share/doc/onesixtyone/dict.txt
Metasploit Module snmp_enum
snmpcheck -t snmpservice




snmpcheck -t $IP -c public

snmpenum -t $IP


##-============================-##
##  [+] SNMPv3 Enumeration
##-============================-##
nmap -sV -p 161 --script=snmp-info $IP/24


## ---------------------------------------------------------- ##
## [+]  Enumerate MIB:
## ---------------------------------------------------------- ##
## [•]  1.3.6.1.2.1.25.1.6.0		## System Processes
## [•]  1.3.6.1.2.1.25.4.2.1.2		## Running Programs
## [•]  1.3.6.1.2.1.25.4.2.1.4		## Processes Path
## [•]  1.3.6.1.2.1.25.2.3.1.4		## Storage Units
## [•]  1.3.6.1.2.1.25.6.3.1.2		## Software Name
## [•]  1.3.6.1.4.1.77.1.2.25		## User Accounts
## [•]  1.3.6.1.2.1.6.13.1.3		## TCP Local Ports



snmpwalk -c public -v1 $IP 1

Snmpwalk -c <community string> -v<version> $IP 1.3.6.1.2.1.25.4.2.1.2

onesixtyone -c names -i hosts

onesixtyone -d $IP



nmap -sU --open -p 161 $1
nmap -n -Pn -sV $IP -p $IP --script=snmp-netstat,snmp-processes -oN $OUTPUT/$IP:$PORT_snmp.nmap
onesixtyone -c public $IP | tee $OUTPUT/161_$IP-$PORT
onesixtyone -c /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings-onesixtyone.txt -dd $1 2>&1 | tee "snmp_onesixtyone_$1.txt"


snmpwalk -c public -v1 $IP | tee $OUTPUT/snmpwalk_$IP-$PORT
snmpwalk -c public -v1 $IP 1.3.6.1.4.1.77.1.2.25 | tee $OUTPUT/snmp_users_$IP-$PORT
snmpwalk -c public -v1 $IP 1.3.6.1.2.1.6.13.1.3 | tee $OUTPUT/snmp_ports_$IP-$PORT
snmpwalk -c public -v1 $IP 1.3.6.1.2.1.25.4.2.1.2 | tee $OUTPUT/snmp_process_$IP-$PORT
snmpwalk -c public -v1 $IP 1.3.6.1.2.1.25.6.3.1.2 | tee $OUTPUT/snmp_software_$IP-$PORT


snmpwalk -c public -v 1 $1 2>&1 | tee "snmpwalk.txt"
snmpwalk -c public -v 1 $1 1.3.6.1.2.1.25.1.6.0 2>&1 | tee "snmpwalk_system_processes.txt"
snmpwalk -c public -v 1 $1 1.3.6.1.2.1.25.4.2.1.2 2>&1 | tee "snmpwalk_running_processes.txt"
snmpwalk -c public -v 1 $1 1.3.6.1.2.1.25.4.2.1.4 2>&1 | tee "snmpwalk_process_paths.txt"
snmpwalk -c public -v 1 $1 1.3.6.1.2.1.25.2.3.1.4 2>&1 | tee "snmpwalk_storage_units.txt"
snmpwalk -c public -v 1 $1 1.3.6.1.2.1.25.6.3.1.2 2>&1 | tee "snmpwalk_software_names.txt"
snmpwalk -c public -v 1 $1 1.3.6.1.4.1.77.1.2.25 2>&1 | tee "snmpwalk_user_accounts.txt"
snmpwalk -c public -v 1 $1 1.3.6.1.2.1.6.13.1.3 2>&1 | tee "snmpwalk_tcp_ports.txt"





##-===========================================================-##
##  [+] SnmpWalk - start browsing through the
##                 MIB (management information base) tree.
##-===========================================================-##
snmpwalk -c public -v1 $IP


##-======================================================================-##
##  [+] extract only system users use this value 1.3.6.1.4.1.77.1.2.25,
##-======================================================================-##
snmpwalk -c public -v1 $IP <MIB value>

snmpwalk public -v1 $IP 1 |grep 77.1.2.25 |cut -d” “ -f4


## --------------------------------- ##
##  [+] Enumerating Windows Users:
## --------------------------------- ##
snmpwalk -c public -v1 $IP 1.3 |grep 77.1.2.25 |cut -d" " -f4


## ------------------------------------- ##
##  [+] Enumerating Running Services
## ------------------------------------- ##
snmpwalk -c public -v1 $IP 1 |grep hrSWRunName|cut -d" " -f4


## -------------------------------------- ##
##  [+] Enumerating installed software
## -------------------------------------- ##
snmpwalk -c public -v1 $IP 1 |grep hrSWInstalledName


## ----------------------------------- ##
##  [+] Enumerating open TCP ports
## ----------------------------------- ##
snmpwalk -c public -v1 $IP 1 |grep tcpConnState |cut -d"." -f6 |sort -nu



snmpbulkwalk -v 2 -c public IP



snmpget -v 1 -c public IP version



##-=======================================-##
##  [+] Capture SNMP Query and Response
##-=======================================-##
tcpdump -n -s0  port 161 and udp



##-===========================================-##
##   [+]
##-===========================================-##
tcpdump -w $File.pcap tcp port ftp or ftp-data and host $Domain






