#Identify processes using files, directories, or sockets.Who is Using a File or Directory
$ fuser  .
$ fuser -v ./
Check Processes Using TCP/UDP Sockets
fuser -v -n tcp 5000
the processes that are using my 'home' directory
$ fuser ~
$ fuser ~ -v
check for the root directory
$ fuser /
$ fuser / -v
$ fuser -v /home/ismail
$ fuser -v -m /home/ismail/.bashrc
$ fuser -v -n tcp 8080
$ fuser -v -n udp 53
kill this TCP listener, you can use option -k
$ fuser -i -k 8080/tcp
shows all processes at the (local) TELNET port
$ fuser telnet/tcp
list signals
$ fuser -l
STOP a process
$ fuser -i -k STOP [FILE/DIRECTORY]
kills all processes accessing the file system /home 
$ fuser -km /home


fuser 7000/tcp
fuser 3306/tcp
fuser 80/tcp
ss -tanp | grep 6379
fuser -v -n tcp 22


