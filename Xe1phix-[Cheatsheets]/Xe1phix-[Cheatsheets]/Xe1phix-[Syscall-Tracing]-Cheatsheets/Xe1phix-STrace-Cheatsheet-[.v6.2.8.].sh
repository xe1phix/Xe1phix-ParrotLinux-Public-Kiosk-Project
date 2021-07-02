#!/bin/sh
##-===============================-##
##   [+] Xe1phix-STrace-v2.7.sh
##-===============================-##
set -o xtrace
set -o verbose


##-=======================-##
##     [+] Common Syscalls:
##-=======================-##
access
close (close file handle)
fchmod (change file permissions)
fchown (change file ownership)
fstat (retrieve details)
lseek (move through file)
open (open file for reading/writing)
read (read a piece of data)
statfs (retrieve file system related details)

	[+]  access
	[+]  close – close file handle
	[+]  fchmod – change file permissions
	[+]  fchown – change file ownership
	[+]  fstat – retrieve details
	[+]  lseek – move through file
	[+]  open – open file for reading/writing
	[+]  read – read a piece of data
	[+]  statfs – retrieve file system related details


strace -e open                      			## Monitor opening of files: 
strace -e trace=read						## Trace Read Syscalls
strace -e trace=write						## Trace Write Syscalls
strace -e trace=$File -p $PID			## Trace Files for $PID
strace -e trace=$Desc -p $PID		## Trace File Descriptors for $PID


##-===============================================-##
##    [+] Trace All processes accessing /etc/cups Directory
##-===============================================-##
strace -P /etc/cups -p $PID


##-============================-##
##    [+] Network Activity SysCalls:
##-============================-##
	~>  bind				##  Link the process to a network port
	~>  listen				##  Allow to receive incoming connections
	~>  socket			##  Open a local or network socket
	~>  setsockopt	##  Define options for an active socket

    bind – link the process to a network port
    listen – allow to receive incoming connections
    socket – open a local or network socket
    setsockopt – define options for an active socket


##-========================================-##
##    [+] 
##-========================================-##
strace -o $File -s 10000 -e trace=network -fp $PID


##-========================================-##
##    [+] 
##-========================================-##
strace -e trace=network -p `pgrep -x $Cmd`

##-============================-##
##    [+] Trace all Nginx processes
##-============================-##
strace -e trace=network -p `pidof nginx | sed -e 's/ /,/g'`


##-========================================-##
##    [+] 
##-========================================-##
strace -f -e trace=network ceph ping $Domain --connect-timeout=30 2>&1 | grep sin_addr
strace -f -e trace=network ceph ping mon.hv03.lab.test.lan --connect-timeout=30 2>&1 | grep sin_addr

strace -E R_PROFILE_USER=$RPROFILE -f -qq -o $File -e trace=network "$@"



##-========================================-##
##    [+] Track the open request of a network port
##-========================================-##
strace -f -e trace=bind nc -l 80

##-======================================================-##
##   [+] Track the open request of a network port (show TCP/UDP)
##-======================================================-##
strace -f -e trace=network nc -lu 80


##-==========================================-##
##   [+] Networrk Calls (parent and child processes)
##-==========================================-##
strace -f -e trace=network curl $Domain 


##-==============================-##
##   [+] Limit String Args to 100 Chars
##-==============================-##
strace -f -e trace=network -s 100 curl $Domain


##-============================-##
##   [+] Attach to T Current Network
##-============================-##
strace -p $PID -f -e trace=network -s [strsize]


##-======================-##
##   [+] Trace Connect Calls
##-======================-##
strace -p $PID -f -e trace=network -s [strsize]

##-========================-##
##   [+] Chosen network calls
##-========================-##
strace -p $PID -f -e poll,select,connect,recvfrom,sendto -s [strsize]




    -e trace=ipc – communication between processes (IPC)
    -e trace=memory – memory syscalls
    -e trace=network – network syscalls
    -e trace=process – process calls (like fork, exec)
    -e trace=signal – process signal handling (like HUP, exit)
    -e trace=file – file related syscalls
    -e trace=desc – all file descriptor related system calls


strace -e trace=process                ## Trace process calls (like fork, exec)
strace -e trace=memory                ## Trace memory syscalls
strace -e trace=network                ## Trace memory syscalls


strace -i 						## print instruction pointer during system call
strace -t $Cmd				## print timestamp
strace -T						## Display syscall duration in the output
strace -c						## See what time is spend and where
strace -D						## run tracer process as a detached 
									## grandchild, not as parent
strace -v						## verbose mode
strace -f                       ## Trace child processes
strace -F						## attempt to follow vforks
strace -S						## sortby -- sort syscall counts by: 
strace -S time				## sortby - Time
strace -S calls				## sortby - syscalls
strace -S name			## sortby - Name
strace -x						## print non-ascii strings in hex
strace -xx						## print all strings in hex
strace -P $Dir							## Trace a process when interacting with a path
strace -o $File.txt					## Log strace output to a file
strace -e trace=$IPC				## Trace communication between processes (IPC)
strace -e trace=$Signal			## Trace process signal handling (like HUP, exit)
strace -e trace=$File				## Trace file related syscalls



-P /tmp – track interaction with a path

Memory activity
strace -e trace=memory -fp $PID





##-==========================================-##
##    [+] Monitor whats written to stdout and stderr
##-==========================================-##
strace -f -e trace=write -e write=1,2 $Cmd >/dev/null


##-=================================================-##
##    [+] Summarise/profile system calls made by command
##-=================================================-##
strace -c $Cmd >/dev/null


##-=====================================-##
##    [+] List system calls made by command
##-=====================================-##
strace -f -e open $Cmd >/dev/null


##-==========================================-##
##    [+] 
##-==========================================-##
ltrace -f -e getenv $Cmd >/dev/null


##-==========================================-##
##    [+] intercept stdout/stderr of another process
##-==========================================-##
strace -ff -e trace=write -e write=1,2 -p $PID



strace -etrace=write  -p $PID


strace -e trace=file -f /etc/init.d/$Service start 2>&1 | grep 'EACCES'



##-===================================-##
##    [+] List files accessed by a command
##-===================================-##
strace -ff -e trace=file $Cmd 2>&1 | perl -ne 's/^[^"]+"(([^\\"]|\\[\\"nt])*)".*/$1/ && print'


##-===============================-##
##    [+] Slow the target PID
##    [+] Print details for each syscall:
##-===============================-##
strace -p $PID

##-================================-##
##    [+] File Descriptors

## ---------------------------------------------------------- ##
##    [+] Slow the target PID 
##    [+] Slow any newly created child process, 
##    [+] Print syscall details:
##-================================-##
strace -fp $PID

##-=========================-##
##    [+] Slow The Target PID
##    [+] Record SysCalls
##    [+] Print A Summary
##-=========================-##
strace -cp $PID

##-=========================-##
##    [+] Slow the target PID
##    [+] Print open() syscalls
##-=========================-##
strace -eopen -p $PID

##-=================================-##
##    [+] Slow the target PID
##    [+] Print open() and stat() syscalls
##-=================================-##
strace -eopen,stat -p $PID

##-=====================================-##
##    [+] Slow the target PID
##    [+] Print connect() and accept() syscalls
##-=====================================-##
strace -econnect,accept -p $PID

##-======================================-##
##    [+] Slow the target command 
##    [+] See what other programs it launches
##-======================================-##
strace -qfeexecve $Cmd

##-============================-##
##    [+] Slow the target PID
##    [+] Print time-since-epoch 
##-============================-##
## ---------------------------------------------------------------------- ##
##    [?] with (distorted) microsecond resolution:
## ---------------------------------------------------------------------- ##
strace -ttt -p $PID

##-===========================-##
##    [+] Slow the target PID
##    [+] Print syscall durations 
##-===========================-##
## ---------------------------------------------------------------------- ##
##    [?] with (distorted) microsecond resolution:
## ---------------------------------------------------------------------- ##
strace -T -p $PID


##-===================================-##
##    [+] 
##-===================================-##
strace -tt -f -ff -p `pidof apache2`
strace -f -p $(pidof $Cmd)



##-===================================-##
##    [+] Attach To An Existing Process
##    [+] Output a specific kernel call 
##         for that process & all child processes
##-===================================-##
strace -f -p $PID -e $KernelSyscall


##-===================================-##
##    [+] 
##-===================================-##
strace -p $! 2>&1 | head -5
strace -p $! 2>&1 | head -5



##-===================================-##
##    [+] 
##-===================================-##
# Track child process and redirect output to a file
ps auxw | grep 'sbin/[a]pache' | awk '{print " -p " $2}' | xargs strace -o $File




## -------------------------------------------------------------------------------- ##
	strace kill -0 `cat /var/run/psad/psad.pid` 2>&1 |grep kill
	execve("/bin/kill", ["kill", "-0", "7940"], [/* 43 vars */]) = 0
	kill(7940, SIG_0) = 0
## -------------------------------------------------------------------------------- ##





##-===================================-##
##    [+] 
##-===================================-##
for foo in $(strace -e open lsof -i tcp 2>&1 | grep 'denied'| awk '{print $1}' | cut -d "/" -f3); do echo $foo $(cat /proc/$foo/cmdline)|awk '{if($2) print}'; done



##-===================================-##
##    [+] 
##-===================================-##
strace -o $File -e trace=open,read,write,readv,writev,recv,recvfrom,send,sendto,network chroot . $File.pdf


##-===============================================-##
##    [+] Watch Incoming Connections With A Given String
##-===============================================-##
strace -f -e trace=network -s 100000 -p $PID 2>&1 | grep --line-buffered <string> -a4 -b4


strace -o trace.log -u $User ./$Program



a thread with the CAP_SETPCAP capability can manipulate the
       capabilities of threads other than itself. 



/proc/[pid]/status file shows the capability  sets  of  a  process's
       main  thread



capget
getcap


the  system-wide  capability bounding set,
         /proc/sys/kernel/cap-bound, always masks out this capability









