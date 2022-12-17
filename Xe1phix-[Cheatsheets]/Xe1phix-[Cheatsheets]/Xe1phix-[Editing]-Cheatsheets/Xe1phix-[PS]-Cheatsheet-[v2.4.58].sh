#!/bin/sh

Show Every Process Running As Root
ps -U root -u root u

Print The Process ID of Rsyslogd
ps -C rsyslogd -o pid

Print sshd Daemon PID
ps -ef | awk '/sshd/ {print $2}'

Find The sshd Daemon, And Kill It
kill $(ps -ef | awk '/sshd/ {print $2}')

Print User, Service And Num of
Processes Running Under That Service:
ps -ef | awk '{print $1}' | sort | uniq -c | sort -nr

List All Threads For A Particular process:
ps -C firefox-bin -L -o pid,tid,pcpu,state

SSH Uptime Statistics:
ps -eo pid,cmd,etime | egrep -E 'ssh-agent|gnome-keyring-daemon'


List processes in a hierarchy
ps -e -o pid,args --forest


ps -eo pid,user,args --sort user


List Processes By % Cpu Usage
ps -e -o pcpu,cpu,nice,state,cputime,args --sort pcpu | sed '/^ 0.0 /d' 


Find Processes Being Run As Root
ps -ef | awk '$1 == "root" && $6 != "?" {print}' 

Listing Users And Their Group Memberships
for u in `cut -f1 -d: /etc/passwd`; do echo -n $u:; groups $u; done | sort


Indepth Group Statistics
ps -eo pid,command,size,vsize,%mem,gid,sgid,egid,fgid,sgroup,rgroup,group,fgroup,egroup,tpgid,tgid,flags

Stack Statistics, esp eip nwchan etc...
ps -eo pid,uid,user,command,vsize,esp,eip,stackp,nwchan,lwp,psr,nlwp,flags


ps -eo uid,fuid,suid,ruid,euid >> Psuid.txt


Verbose User Statistics
ps -eo pid,%mem,command,size,fuser,suser,user,uname,ruser,euser,vsize,esp,eip,stackp,flags

Verbose User & UID Statistics
ps -eo uid,fuid,suid,ruid,euid,fuser,suser,user,uname,ruser,euser,command


Verbose Mem & Cpu Statistics
ps -eo uid,gid,user,group,command,size,vsize,sz,%mem,%cpu,flags




ps -eo pid,user,group,args,etime,lstart jgrep $PID

ps -eo pid,user,group,gid,vsz,rss,comm --sort=-rss | less

ps -ef --sort=user | less


echo "pull out just the PID of the master SSH daemon:"
netstat -anp --tcp -4 | awk '/:22/ && /LISTEN/ { print $7 }' | cut -f1 -d/



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



chrome_pid=$(ps -aux | grep "[c]hrome --user-data" | awk '{ print $2 }' | head -n 1 2>/dev/null)

alias chromekill="ps ux | grep '[C]hrome Helper --type=renderer' | grep -v extension-process | tr -s ' ' | cut -d ' ' -f2 | xargs kill"




