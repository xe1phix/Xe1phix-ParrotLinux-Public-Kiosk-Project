# SED = TEST SQL QUERIES SYNTAX
# =============================
# Takes the table name and the WHERE clause to create a SELECT query with this values.

## UPDATE queries
sed 's|update\s\+\([A-Z0-9_]\+\).\+\(where\s\+.\+$\)|SELECT * FROM \1 \2|i' <text file with queries>
### example: UPDATE table_2 SET filed_1 = '123ab', field_2 = 123 WHERE field_3 = 'bla' and field_5 like '%lala'
### output example: SELECT * FROM table_2 WHERE field_3 = 'bla' and field_5 like '%lala'

## DELETE queries
sed 's|delete\s\+from\s\+\([A-z0-9_]\+\).\+\(where\s\+.\+$\)|SELECT * FROM \1 \2|i' <text file with queries>
### example: DELETE FROM table_1 WHERE field_1 = 123 and field_2 = 'abc';
### output example: SELECT * FROM table_1 WHERE field_1 = 123 and field_2 = 'abc';

# SMBCLIENT = LIST SHARED DRIVES ON A SERVER
# ================================================
# This tool is not included on the with Linux, you need to install it.
# $ sudo apt-get update && sudo apt-get install -y smbclient
# This tool allows you to connect to share drives on windows or linux servers.

## LIST shared folders (basic command)
sudo smbclient -L //<HOST_IP_OR_NAME> -U <USERNAME%PASSWORD>
## LIST shared folders in a grep_able format
sudo smbclient -L //<HOST_IP_OR_NAME> -U <USERNAME%PASSWORD> -g
## LIST shared folders in a grep_able format and cut the fat
sudo smbclient -L //<HOST_IP_OR_NAME> -U <USERNAME%PASSOWRD> -g | grep Disk | cut -f 1 -d '|'
## LIST only the names of the shared Disk

# MOUNT = MOUNT A WINDOWS SHARED DRIVE
# ====================================
# mount / umount are tools included with each linux distribution.
# You can use them to mount FS drives (USBs, shared drives, phones, etc).
# mount adds the drive to a directory of your choice.
# umount is to remove the drive from the directory.

# mount a windows shared drive
sudo mount -t cifs -o <username=MY.USERNAME,password=MY.PASSWORD> //<HOST_IP_OR_NAME> </path/to/destination>
# mount a pluged USB
# to get the name of the file system (FS) for the USB run:
sudo fdisk -l
# this will display a list of all the FS on your computer
# then to mount the drive
sudo mount <USB_FS_NAME '/dev/sda_1'> </path/to/destination>

# MOUNT WINDOWS DFS SHARED DRIVES
# ===============================
# to mount a DFS (Distributed Files System) two packages are necesarie "cifs-utils and keyutils"
# Once this two packages are installed, you need to modify this file: "/etc/request-key.conf" and add this lines
# (if they are not in the file already)

##OP     TYPE    DESCRIPTION     CALLOUT INFO    PROGRAM ARG1 ARG2 ARG3 ...
##====== ======= =============== =============== ===============================
#create  cifs.spnego     *       *               /usr/sbin/cifs.upcall -c %k
#create  dns_resolver    *       *               /usr/sbin/cifs.upcall %k

# then just run the mount command
sudo mount -t cifs -o <username=MY.USERNAME,password=MY.PASSWORD> //<HOST_IP_OR_NAME> </path/to/destination>
# Astute
sudo mount -t cifs -o username=<windows username>,password=<windows password> //astute.prv/public /home/ezequiel.lopez/mnts

# disconnect drive
sudo umount </path/to/destination>
# force disconnection
sudo umount -f </path/to/destination>

# Mount specifying owner and group on VirtualBox
sudo mount -t vboxsf -o uid=$UID,gid=$GID share ~/host

# to get the uid and gid use the command 'id'

# NET COMMAND (SAMBA)
# ===================
# This command allows you to interact with the services and other stuff on the remote server.
# To be able to use this command you need to have installed samba-common "sudo apt-get install samba-common"
# In this case I'll use net command to manage services on a windows 10 server.

# list all services in remote server
net rpc service list -S <server name> -U <domain/username%password>

# stop service
net rpc service stop <service name> -S <server name> -U <domain/username%password>

# start service
net rpc service start <service name> -S <server name> -U <domain/username%password>

# for more info refer to the man page.

# DF = DISPLAY THE SPACE OF A DRIVE
# =================================
# the df command shows the size of a drive really fast

df <directory> -h
# the -h flag is for human readable space units.

# LOOP THROUGH A LIST AND EXECUT A COMMAND ON EACH ELEMENT
# ========================================================
for x in *.ppk; do cp "${x}" "${x/.ppk/}"; done
## this command is copying all the .ppk files in the current directory
## and removing the extenssion

# LOOP THROUGH FIND LIST
# ======================
for x in `sudo find / -iname "*.conf"`; do sudo cp -r "${x}" /home/user/.conf.bkp/; done

# LOOP THROUGH SSH LIST OF FILES
# ==============================
for x in `ssh <hosname> "ls /home/user/"`; do scp <hostname>:/home/user/"${x}" ./mybakup/; done
## This script will do an ls on the remote server and send the result to the local stdout
## then with the for loop we can get this result and put it into a variable 'x' to the use
## it with scp to copy the files from the remote server to the local machine.
## NOTE: the user that you are using to ssh into the remote server has to be able to copy
## the files that you are trying to backup.

# COPY WITHOUT OVERWRITE
# ======================
sudo cp -vnpr xxx/* yyy
#  xxx = source
#  yyy = destination
#  v   = verbose
#  n   = no clobber (no overwrite)
#  p   = preserve permissions
#  r   = recursive

# SEND FILES THROUGH SSH
# ======================
## copy file from local over to remote server
scp -i <.ssh/key> <local/file> <user>@<host_name_or_ip>:<destination>
## using config
scp <local/file> <hostname>:<destination>
## copy file from remote server to local
scp -i <.ssh/key> <user>@<host_name_or_ip>:<file/to/copy> <local/destination>
## using config
scp <hostname>:<file/to/copy> <local/destination>

# FIND FILES WITH TEXT IN THEM
# ============================
grep -rnw '/path/to/somewhere/' -e "pattern"
# -r or -R is recursive,
# -n is line number, and
# -w stands for match the whole word.
# -l (lower-case L) can be added to just give the file name of matching files.

# Along with these, --exclude, --include, --exclude-dir or --include-dir flags
# could be used for efficient searching:
# This will only search through those files which have .c or .h extensions:
grep --include=\*.{c,h} -rnw '/path/to/somewhere/' -e "pattern"
# This will exclude searching all the files ending with .o extension:
grep --exclude=*.o -rnw '/path/to/somewhere/' -e "pattern"
# Just like exclude files, it's possible to exclude/include directories through
# --exclude-dir and --include-dir parameter. For example, this will exclude the
# dirs dir1/, dir2/ and all of them matching *.dst/:
grep --exclude-dir={dir1,dir2,*.dst} -rnw '/path/to/somewhere/' -e "pattern"
# This works very well for me, to achieve almost the same purpose like yours.

# RESTART LINUX SERVICE WITH SSH
# ==============================
ssh -i /path/to/ssh/key.pub user@<host ip or name> 'service apache2 status'

# GENERATE AN OpenSSH KEY
# =======================
ssh-keygen -t rsa -b 4096 -C skiel.j.lopez@gmail.com -f id_rsa
# This command will create an OpenSSH key type RSA 4096 bytes long with my emails as a comment and
# the file name id_rsa

# PUTTYGEN FROM PPK TO RSA
# ========================
# To ssh into a server when you have the putty key '.ppk' you need to convert the key into openssh
# To do so you will need to use putty utils tool so first install the tools
sudo apt-get update && sudo apt-get install -y putty-tools
# Then from ppk to openssh
puttygen <keyname.ppk> -O private-openssh -o <keyname>
# Now the other way, from openssh to ppk
puttygen <keyname> -o <keyname.ppk>
# list all the ppk keys and convert them into rsa
for ppkey in *.ppk; do puttygen "${ppkey}" -O private-openssh -o "${ppkey/.ppk/}"; done

# GENERATE PRIVATE KEY & CERTIFICATE SIGNING REQUEST (CSR) (BUY FROM CA)
# ======================================================================
# With this command you will all the files that you need to request a Certificate Authority (CA) certification.
# The authorities are companies that sign the Certification with the server private key. Then this signature can be
# decripted with the server public key. domain.key is the private key for the server
openssl req -newkey rsa:2048 -nodes -keyout domain.key -out domain.csr

# GENERATE CSR FROM EXISTING KEY
# ==============================
openssl req -key domain.key -new -out domain.csr

# GENERATE CSR FROM EXISTING KEY AND CERTIFICATE
# ==============================================
# Use this to renovate a CA certificate. It extracts the CSR from the old expred certificate.
openssl x509 -in domain.crt -signkey domain.key -new -x509toreq -out domain.csr

# With the key and the csr you can request an SSL certificate signed by one of the CA companies (godaddy, symantec, etc)

# GENERATE SELF SIGNED SSL CERTIFICATE (FREE)
# ===========================================
# selfsigned certificates are use in internal communications to be able to use HTTPS or (TLS, SSL) protocols to encrypt the
# information in transit.
# for example the requests from an elb to its servers can be encrypted using a self signed certificate.
openssl req -newkey rsa:2048 -nodes -keyout domain.key -x509 -days 365 -out domain.crt

# GENERATE SELF SIGNED SSL CRT WITH EXISTING KEY
# ==============================================
openssl req -key domain.key -new -x509 -days 365 -out domain.crt

# GENERATE SELF SIGNED SSL CRT WITH EXISTING KEY AND CSR
# ======================================================
openssl x509 -signkey domain.key -in domain.csr -req -days 365 -out domain.crt

# ADD SUDO USER
# =============
# To add a sudo user means that you want to add the user to the group of sudores.
sudo adduser <username> <groupname>
sudo adduser zeke sudo

# Now that the user was created and added to the sudores group you can define the home directory and the shell for this user
# Modify the file /etc/passwd
# The fields are separated by ':' modify the last 2
zeke:x:112:117::/home/zeke:/bin/bash
# if you set the user like in the example then in loging you will land in /home/zeke and it will open a bash session.

# CHECK OPEN PORTS
# ================
# The package net-tools has to be installed to have access to netstat
sudo netstat -tuna
# -t for TCP ports
# -u for UDP ports
# -n run netstat faster
# -a All
# This command will return a table with all the open ports on your machine and what services are running on them

# SEND EMAILS WITH TELNET
# =======================
# This is the most stright forward way to test if an email relay can send emails from anywhere.
# First you need to be able to connect to the server throught the ports 25, 587 or 465 (SMTP ports)
# To connect use this command [ telnet <DNS or IP> <port> ]
telnet postfix.epowercenterdirect.com 587
# Once connected start typing this commands.
# Send HELO message to the server and press enter
EHLO postfix.epowercenterdirect.com
# If the email server requires login enter this command and press enter
AUTH LOGIN
# Enter your user name encrypted in base 64. You can use one of several tools that are available to encode your user name
# The server responds with an encrypted base 64 prompt for your password. Enter your password encrypted in base 64
MAIL FROM:<email@domain.com>
RCPT TO:<email@domain.com>
DATA
SUBJECT:some subject
The message that you want to send

Bye
.
# If you see a 2xx return code it means that the email when through.

# SEND EMAILS WITH TELNET [AUTHENTICATION]
# ========================================
# Same as above but using authentication
$ telnet <smtp.emailsrvr.com> <port (465,587)>
Trying 123.456.789.1...
Connected to smtp.emailsrvr.com.
Escape character is '^]'.
220 ESMTP Tue, 05 Sep 2017 08:38:39 -0400: UCE strictly prohibited
EHLO localhost
250-someone.domain.com Hello localhost [123.456.789.1]
250-SIZE 34603008
250-8BITMIME
250-PIPELINING
250-AUTH PLAIN LOGIN
250-STARTTLS
250 HELP
# The command AUTH LOGIN starts the plain loging authetication method. Right after the return code 334 <key>
# enter the username encoded in base64 and hit enter, then enter the password also encoded in base64
AUTH LOGIN
334 VXNlcm5HBWU6
cmVWbHktZW5aY3JkaG5hLmNvbQ== # Username encoded in base64
334 UGFzc3dvcmQ6
SG0WNzEyNTu=                 # password encoded in base64
235 Authentication succeeded
MAIL FROM: from@email.com
250 OK
RCPT TO: to@email.com
250 Accepted
DATA
354 Enter message, ending with "." on a line by itself
Test message

BYE
.
250 OK id=1dpD8x-0000VH-JF

# LIST PROCESSES BY PORT
# ======================
# This command will list the process using the port tcp:8080 this will give you back the PID so you can kill the process with
# kill -9 PID
lsof -wni tcp:8080

# PROGRESS BAR FOR rm, cp, mv, etc
# ================================
# pv is a tool that takes inputs from the STDIN and uses them to create a progress bar on a process.
# This is an example with rm
rm -rv node_modules | pv -l -s $( du -a node_modules | wc -l ) > dev/null

# rm -rv: 'r' is for recursive and 'v' for verbose. The verbose option list all the files and directories that are being remove
# pv -l -s: 'l' count lines instead of bytesize 's' initial size in this case we need to provide the total number of lines that 
# we want to remove.
# $( du -a node_modules/ | wc -l ): this subshell returns the count of files and directories inside node_modules
## du -a node_modules/: du list the size of the content of node_modules. 'a' is used to include also the files inside each directory
## wc -l: counts the lines outputed by du. This gives us the total lines that -rv will output.
# > dev/null: send the output from rm -rv to the dev/null so only the progress bar is displayed.

# blkid list logical devices like CDROMs and USBs
$ sudo blkid