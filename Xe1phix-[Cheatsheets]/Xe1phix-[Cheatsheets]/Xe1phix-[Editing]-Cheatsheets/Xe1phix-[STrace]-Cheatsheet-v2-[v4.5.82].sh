

strace ls
strace -v #-v verbose option that can provide additional information on each system call
strace -s 80 -f ./program	#print the first 80 characters of every string
strace -i ls # print instruction pointer at the time of system call
strace -r ls # display a relative timestamp upon entry to each system call
strace -t ls #each line in strace output to start with clock time
strace -T ls #show time spent in system calls
strace -c ls #print a summary
strace -p 3569 #If a process is already running, you can trace it by simply passing its PID
strace -p `pidof rsyslogd`
strace -p $(pgrep rsyslogd) #monitor process without knowing its PID, but name
#if there are multiple processes to be traced at once (e.g. all instances of an running apache httpd)
strace $( pgrep httpd | sed 's/^/-p/' ) 
strace -c -p 3569 Summary of Linux Process
strace -c ls Counting number of sys calls
strace -o output.txt ls
strace -e trace=network -o OUTFILE php -q test2.php # write the output of strace to a file or redirect the output
strace -e trace=network php -q test2.php 2> test2debug #redirect the output
strace -e trace=open,stat,read,write ls
strace -e trace=mprotect,brk ifconfig eth0 # trace mprotect or brk system calls
strace -e trace=network ifconfig eth0 #Trace all the network related system calls
strace -e trace=network #Monitoring the network
strace -e trace=memory Monitoring memory calls
strace -e open ls  display only a specific system call, use the strace -e option
strace -f -eopen /usr/sbin/sshd 2>&1 | grep ssh	shows the three config files that OpenSSH’s sshd reads as it starts,strace sends its output to STDERR by default
strace -e trace=file -p 1234 #See all file activity,Monitoring file activity
strace -e trace=desc -p 1234
strace -P /etc/cups -p 2261 #track specific paths, use 1 or more times the -P parameter, following by the path
strace -f -o strace_acroread.txt acroread #follow system calls if a process fork
strace -q -e trace=process df -h trace all system calls involving process management.
strace -q  -e trace=file df -h trace all system calls that take a filename as an argument
strace -f -e execve ./script.sh #check what commands are exactly being executed by a script by using strace
strace -f -e execve bash x.sh

$ strace e execve bash -c true
$ strace -ve execve bash -c true
$ strace -e execve bash -c /bin/true

$ strace -o OUT -ff -e execve bash -c "/bin/true ; /bin/false"
$ grep execve OUT*
OUT.29328:execve("/usr/bin/bash", ["bash", "-c", "/bin/true"], 0x7ffc75ace798 /* 25 vars */) = 0
OUT.29328:execve("/bin/true", ["/bin/true"], 0x55bf673522c0 /* 25 vars */) = 0
OUT.29336:execve("/usr/bin/bash", ["bash", "-c", "/bin/true ; /bin/false"], 0x7ffe1b316638 /* 25 vars */) = 0
OUT.29337:execve("/bin/true", ["/bin/true"], 0x55aba17c92c0 /* 25 vars */) = 0
OUT.29338:execve("/bin/false", ["/bin/false"], 0x55aba17c92c0 /* 25 vars */) = 0

# Under Linux, fork is a special case of the more general clone system call, which you observed in the strace log.
#The child runs a part of the shell script. The child process is called a subshell.
strace -f -o bash-mystery-1.strace bash -c 'v=15; (echo $v)'
strace -f -o bash-mystery-2.strace bash -c 'v=15; bash x.sh'
man 2 clone #create a child process
grep clone bash-mystery-2.strace # filter child process

strace -e open,read,write cat /etc/HOSTNAME
strace -e open,read,write cat /etc/HOSTNAME > /dev/null
strace -e file cat /etc/HOSTNAME

#Execute Strace on a Running Linux Process Using Option -p
ps -C firefox-bin #PID 126
sudo strace -p 126 -o firefox_trace.txt #display the following error when your user id does not match the user id of the given process.
pidof sshd #PID 126
strace -p 126

#sleep.sh, endless loop
#! /bin/bash
while :
do
 sleep 10 &
 echo "Sleeping for 4 seconds.."
 sleep 4
done

$ sh sleep.sh & # run in the background
$ pstree -p #see sleep.sh child/parent processes
$ pgrep sleep | sed 's/^/-p/'
$ pidof sleep
$  sudo strace -c -fp PID # attach to parent process of the sleep.sh
$ strace -c -fp $( pgrep sleep | sed 's/^/-p/' ) # another terminal, monitor multipe=le child processes of sleep.sh
$ strace $( pgrep sleep | sed 's/^/-p/' ) # another terminal, monitor multipe=le child processes of sleep.sh

man 3 stat #access the documentation. stat is the system call that gets a file's status
man 2 execve

$ grep openat trace.log
