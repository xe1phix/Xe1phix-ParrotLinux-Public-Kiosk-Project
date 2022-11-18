ps aux | grep root #list services running as root
ps aux | grep 3813
ps -eo pid,user,group,args,etime,lstart | grep '[3]813'
ps aux | grep '[1]616'
ps -eo pid,user,group,args,etime,lstart | grep '[1]616'
ps aux | grep stuff
The init process, with process ID 1, which does nothing but wait around for its child processes to die. 
Usually started for /etc/inittab
$ ps -ef| grep init
# see the name of the process
$ sudo ps 1088 14324 14354
# CPU time, page faults of child processes
ps -Sla
$ ps -lu vagrant
memory information long format
$ ps -lma
signal format
$ ps -sx
controlling terminal
$ ps --tty 1 -s
#print a process tree
ps -ejH
ps axjf

list of command line arguments
pstree -a
show PIDS for each process name
pstree -p
sort processes with the same ancestor by PID instead of by name,numeric sort
pstree -n
pstree -np
find out the owner of a process in parenthesis
pstree -u
pstree -u vagrant
pstree -unp vagrant
highlight the current process and its ancestors
pstree -h
highlight the specified process
pstree -H 60093

find ID of a process owned by a specific user
$ pgrep -u vagrant sshd
$ pgrep -u vagrant -d:
list process names
$ pgrep -u vagrant -l
$ pgrep -u vagrant -a
count of matching processes
$ pgrep -c -u vagrant

top -> Checking the Priority of Running Processes
ps -o pid,comm,nice -p 594 -> Checking the Priority of Running Processes
ps -o pid,comm,nice,pri -p $(pidof snmpd)
ps -fl -C "perl test.pl" -> The “NI” column in the ps command output indicates the current nice value (i.e priority) of a process.
ps -p 2053 -o comm=

#NI – is the nice value, which is a user-space concept
#PRI – is the process’s actual priority, as seen by the Linux kernel
ps -o ni $(pidof snmpd)

#Total number of priorities = 140
#Real time priority range(PR or PRI):  0 to 99 
#User space priority range: 100 to 139
ps -o ni,pri $(pidof snmpd)

#PR = 20 + NI
#PR = 20 + (-20 to + 19)
#PR = (20 + -20)  to (20 + 19)
#PR = 0 to 39  (100 to 139 user space priority range)
ps -o pid,comm,nice,pri -p $(pidof snmpd)

cat /proc/$(pidof snmpd)/stat | awk '{print "priority " $18 " nice " $19}'
ps u $(pgrep snmpd) #ps with headers

#The NI column shows the scheduling priority or niceness of each process
#ranges from -20 to 19, with -20 being the most favorable or highest priority for scheduling
#19 being the least favorable or lowest priority
ps -e -o uid,pid,ppid,pri,ni,cmd |  { head -5 ; grep snmpd; } #ps with headers
