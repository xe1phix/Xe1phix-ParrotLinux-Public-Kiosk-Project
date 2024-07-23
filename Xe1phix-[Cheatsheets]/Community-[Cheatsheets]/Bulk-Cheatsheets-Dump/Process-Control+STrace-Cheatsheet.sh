Process-Control+STrace-Cheatsheet.sh


##  Working with processes


##  To show the process ID of a process by the string name
pgrep <processName>


##  To kill a process by the name of the process
pkill <processName>


##  To listen to see which process ID / name is listening on a port
netstat -tulpn | grep :25

##  25 denotes the port number




##  strace Notes

strace /usr/bin/ld -lsasl2

ln -s /usr/local/lib/libsasl2.so /usr/lib/libsasl2.so

/usr/bin/ld -lsasl2

##  To trace system calls from commands, ie,

strace df -h

##  To trace Linux Process PID

strace -p 42

##  To get a summary of a Linux process

strace -c -p 42

##  To print instruction pointer during system call

strace -i df -h

##  To show time of day for each output line

strace -t df -h

