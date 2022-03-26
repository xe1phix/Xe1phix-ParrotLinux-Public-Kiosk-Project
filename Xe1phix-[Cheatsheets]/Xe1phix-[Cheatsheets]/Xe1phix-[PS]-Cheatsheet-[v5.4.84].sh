#!/bin/sh


##-===========================================-##
##   [+] show top 10 process eating memory
##-===========================================-##
ps auxf | sort -nr -k 4 | head -10


##-=========================================-##
##   [+] show top 10 process eating CPU
##-=========================================-##
ps auxf | sort -nr -k 3 | head -10


##-===========================================-##
##   [+] Show Every Process Running As Root
##-===========================================-##
ps -U root -u root u


##-========================================-##
##   [+] List All Threads For A process:
##-========================================-##
ps -C firefox -L -o pid,tid,pcpu,state


##-=================================================-##
##   [+] Print User, Service And Num of Processes
##-=================================================-##
ps -ef | awk '{print $1}' | sort | uniq -c | sort -nr


##-=========================================-##
##   [+] Print The Process ID of Rsyslogd
##-=========================================-##
ps -C rsyslogd -o pid


##-===============================-##
##   [+] Print sshd Daemon PID
##-===============================-##
ps -ef | awk '/sshd/ {print $2}'


##-=========================================-##
##   [+] Find The sshd Daemon, And Kill It
##-=========================================-##
kill $(ps -ef | awk '/sshd/ {print $2}')


##-=============================================-##
##   [+] PSTree - Graphical list of processes
##-=============================================-##
pstree --arguments --show-pids --show-pgids --show-parents


##-=================================================-##
##   [+] Print User, Service And Num of Processes
##-=================================================-##
ps -ef | awk '{print $1}' | sort | uniq -c | sort -nr


##-========================================-##
##   [+] List All Threads For A process:
##-========================================-##
ps -C $Service -L -o pid,tid,pcpu,state


##-===============================-##
##   [+] SSH Uptime Statistics:
##-===============================-##
ps -eo pid,cmd,etime | egrep -E 'ssh-agent|gnome-keyring-daemon'


##-=======================================-##
##   [+] List processes in a hierarchy
##-=======================================-##
ps -e -o pid,args --forest


##-=========================================-##
##   [+] Find Processes Being Run As Root
##-=========================================-##
ps -ef | awk '$1 == "root" && $6 != "?" {print}'


##-=================================-##
##   [+] Indepth Group Statistics
##-=================================-##
ps -eo pid,command,size,vsize,%mem,gid,sgid,egid,fgid,sgroup,rgroup,group,fgroup,egroup,tpgid,tgid,flags


##-================================================-##
##   [+] Stack Statistics, esp eip nwchan etc...
##-================================================-##
ps -eo pid,uid,user,command,vsize,esp,eip,stackp,nwchan,lwp,psr,nlwp,flags


##-=========================================-##
##   [+] Verbose User & UID Statistics
##-=========================================-##
ps -eo uid,fuid,suid,ruid,euid,fuser,suser,user,uname,ruser,euser,command


##-======================================-##
##   [+] Verbose Mem & Cpu Statistics
##-======================================-##
ps -eo uid,gid,user,group,command,size,vsize,sz,%mem,%cpu,flags


##-=======================================================-##
##   [+] pull out just the PID of the master SSH daemon:
##-=======================================================-##
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


##-==================================-##
##   [+] Print the PID of Chrome:
##-==================================-##
chrome_pid=$(ps -aux | grep "[c]hrome --user-data" | awk '{ print $2 }' | head -n 1 2>/dev/null)


##-===============================-##
##   [+] Kill Chrome processes
##-===============================-##
alias chromekill="ps ux | grep '[C]hrome Helper --type=renderer' | grep -v extension-process | tr -s ' ' | cut -d ' ' -f2 | xargs kill"


##-=============================================================================-##
##   [+] Use STrace to attach to all of the currently running apache processes
##-=============================================================================-##
ps auxw | grep sbin/apache | awk '{print"-p " $2}' | xargs strace

pgrep -f /usr/sbin/httpd | awk '{print"-p " $1}' | xargs strace

ps auxw | grep -E 'sbin/(apache|httpd)' | awk '{print"-p " $2}' | xargs strace -F


##-===========================================================-##
##   [+] Use STrace to attach to all apache child processes
##-===========================================================-##
ps h --ppid $(cat /var/run/apache2.pid) | awk '{print"-p " $1}' | xargs sudo strace


##-=========================================-##
##    [+] Kill all processes of $Service
##-=========================================-##
kill -9 $(ps aux | grep '$Service' | awk '{print $2}')


##-===================================-##
##     [+] Kill all Zombie processes
##-===================================-##
kill -9 `ps -xaw -o state -o ppid | grep Z | grep -v PID | awk '{print $2}'`



## ---------------------------------------------------------------------------------------- ##
	kill $(ps -ef | awk '/sshd/ {print $2}')				## kill sshd Processes
## ---------------------------------------------------------------------------------------- ##
	kill $(ps -ef | awk '/apache2/ {print $2}')				## kill Apache2 Processes
## ---------------------------------------------------------------------------------------- ##
	kill $(ps -ef | awk '/mysql/ {print $2}')				## kill mysql Processes
## ---------------------------------------------------------------------------------------- ##


##-==============================================-##
##   [+] Display any tcp connections to apache
##-==============================================-##
for i in `ps aux | grep httpd | awk '{print $2}'`; do lsof -n -p $i | grep ESTABLISHED; done;


##-==============================================================================================-##
##   [+] Show top 50 running processes ordered by highest memory/cpu usage refreshing every 1s
##-==============================================================================================-##
watch -n1 "ps aux --sort=-%mem,-%cpu | head -n 50"


##-=================================================-##
##   [+] Count processes related to HTTP server
##-=================================================-##
ps aux | grep http | grep -v grep | wc -l






(ps -aux; ps -ejH; ps -eLf; ps axjf; ps axms; ps -ely; ps -ef; ps -eF;  ps -U root -u root u; ) > ps-dump.txt
(ps -eo 'pid,user,group,nice,vsz,rss,comm') > ps-table-dump.txt

ps aox 'pid,user,args,size,pcpu,pmem,pgid,ppid,psr,tty,session,eip,esp,start_time' > ps-columns.txt


ps -eo pid,user,args --sort user

ps -eo pid,user,group,args,etime,lstart jgrep $PID

ps -eo pid,user,group,gid,vsz,rss,comm --sort=-rss | less

ps -ef --sort=user | less

List Processes By % Cpu Usage
ps -e -o pcpu,cpu,nice,state,cputime,args --sort pcpu | sed '/^ 0.0 /d'

