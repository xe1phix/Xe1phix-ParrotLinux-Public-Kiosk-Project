#!/bin/sh
## ######################################################################## ##
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.
#  
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#  
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
#  MA 02110-1301, USA.
#  
## ####################################################################### ##
## 
## ####################################################################### ##
## This isnt attended to be a shellscript, or an automation script.
## This is just a text document/reference for IRC.
## ####################################################################### ##



##					  ##
 ## ================ ##
  ##  Moist-IRC.sh  ##
 ## ================ ##
##					  ##


## =============================================================== ##
## The Term Chan is a Legacy unix terminology for irc channel 
## or BBS terminology idk look it up, 
## I ain't got time for that shit.
##
## xdg-open https://wikipedia.org
## xdg-open https://startpage.com
## =============================================================== ##




## ==================================================================== ##
## 			[?] How To Register An IRC Nick(name) With The Server 
## ==================================================================== ##





## =============================================================== ##
/msg Nickserv REGISTER ${password} ${email}
/msg NickServ VERIFY REGISTER ${username}
/msg Nickserv IDENTIFY ${password}
/msg NickServ confirm ${confirm code}
/msg NickServ VERIFY REGISTER ${username} ${confirm code}
/msg NickServ HELP
## =============================================================== ##



## ==================================================== ##
## 				[?] Basic IRC Commands:
## ==================================================== ##
/help				## Shows all available commands
/who				## Shows who is on the channel
/join #<chan>		## Join the specified channel
/leave #<chan>		## Leave the specified channel
/quit				## Quit IRC completely
## ==================================================== ##






echo "## ============================================ ##"
echo "	## 	[!] Dont Accept CTCPS, Known Vulns [!] 	##	"
echo "## ============================================ ##"

## --------------------------------------------------- ##
echo "[+] To Disable CTCPS Potentially Harmful Outcome..."
## --------------------------------------------------- ##
echo "[?] 1). Startup Hexchat"
echo "[?] 2). Connect To An IRC Server"
echo "[?] 	  And Type: "
echo
## --------------------------------------------------- ##
/IGNORE * CTCPS
## --------------------------------------------------- ##



echo "## ================================================ ##"
echo "## [!] Dont Accept DCC, Known Vulns. Also It Allows ##"
echo "## [!] Attacker To Ping + Reveals Your IP Addr 	  ##"
echo "## ================================================ ##"

## --------------------------------------------------- ##
echo "[+] To Disable DCC Potentially Harmful Outcome..."
## --------------------------------------------------- ##
echo "[?] 1). Startup Hexchat"
echo "[?] 2). Connect To An IRC Server"
echo "[?] 	  And Type: "
echo
## --------------------------------------------------- ##
/IGNORE * DCC
## --------------------------------------------------- ##







## ================================================================================== ##
## 								[?] Some DCC Examples:
## ================================================================================== ##

## -------------------------------------------------------------------------------- ##
/DCC GET ${nick} 							## accept an offered file
## -------------------------------------------------------------------------------- ##
/DCC SEND [-maxcps=#] ${nick} ${file}			## send a file to someone
## -------------------------------------------------------------------------------- ##
/DCC PSEND [-maxcps=#] ${nick} ${file}		## send a file using passive mode
## -------------------------------------------------------------------------------- ##
/DCC LIST 									## show DCC list
## -------------------------------------------------------------------------------- ##
/DCC CHAT ${nick}							## offer DCC CHAT to someone
## -------------------------------------------------------------------------------- ##
/DCC PCHAT ${nick}							## offer DCC CHAT using passive mode
## -------------------------------------------------------------------------------- ##

## ================================================================================== ##



## ========================================================================================= ##
## 						[?] How To Kill Hexchat When Its Not Responding
## ========================================================================================= ##

## ----------------------------------------------------------------------------------------- ##
/EXECKILL [-9]								## kills a running exec in the current session. 
#											## If -9 is given the process is SIGKILL'ed
## ----------------------------------------------------------------------------------------- ##
/EXECSTOP									## sends the process SIGSTOP
## ----------------------------------------------------------------------------------------- ##





## ========================================================================================= ##
## 								Routing/DNS Related Syntax
## ========================================================================================= ##

## ----------------------------------------------------------------------------------------- ##
/GATE ${host} ${port}				## proxies through a host, port defaults to 23
## ----------------------------------------------------------------------------------------- ##
/INVITE ${nick} ${chan}				## invites someone to a channel
## -------------------------------------------------------------------------------- ##
/SEND ${nick} ${file}				## Send ${nick} A File
## ----------------------------------------------------------------------------------------- ##
/CHECKSUM GET|SET					## 
## ----------------------------------------------------------------------------------------- ##
ignore %2!*@* ALL					## 
## ----------------------------------------------------------------------------------------- ##
/NCTCP ${nick} ${message}			## Sends a CTCP notice
## ----------------------------------------------------------------------------------------- ##
/DNS ${nick} | ${host} | ${ip}			## Resolves an IP or hostname
## ----------------------------------------------------------------------------------------- ##
/KEYX ${nick}						## performs DH1080 key-exchange with ${nick}
## ----------------------------------------------------------------------------------------- ##
/CTCP ${nick} ${message}			## send the CTCP message to nick, 
									## (common messages are VERSION and USERINFO)
## ----------------------------------------------------------------------------------------- ##
## ========================================================================================= ##





echo "##-=======================================================-##"
echo "    [?] To send, you use an IP address instead of a          "
echo "             nickname to initiate a connection               "   
echo "##-=======================================================-##"

echo "## --------------------------------------------------------------------- ##"
echo "          usage: /dcc [send|chat|fserve] IPADDRESS:PORT                    "
echo "## --------------------------------------------------------------------- ##"



/dcc send host:port

echo "## --------------------------------------------------------------------------- ##"
echo "     example:/dcc send cablemodem911.network.com:59 this is alphanumeric)         "
echo "     example: /dcc send 100.200.300.4:59 (this is numeric)                        "
echo "## --------------------------------------------------------------------------- ##"

/fserve Krejt 3 c:\temp\serve c:\temp\serving\welcome.txt 
/fserve Mookies 2 c:\outgoing c:\network\mirc\welcome.txt 
/fserve Friend 7 c:\




ctcp 1:server:/fserve $nick 3 c:\temp\serve






/query nickserv help register
/query nickserv help identify


/query alis list *archlinux*


/help irc.server.freenode.autoconnect







/server add freenode chat.freenode.net/6697 -ssl
/connect chat.freenode.net/6697 -ssl

/set weechat.network.gnutls_ca_file "/etc/ssl/certs/ca-certificates.crt"




/set irc.look.smart_filter "on"

##-===================================================-##
echo "[+] Next, we will create the sfilter alias:       "
##-===================================================-##

/alias add sfilter filter add irc_smart_$server_$channel irc.$server.$channel irc_smart_filter *



##-=============================================-##
echo "[?] We can now type this In any buffer:"
##-=============================================-##
echo "    $ /sfilter                           "

## ----------------------------------------------------------------------- ##
echo "[?]  And the smart filter will only be enabled for that buffer."     
## ----------------------------------------------------------------------- ##
echo "[?] The following alias will remove a previously  "
echo "    enabled smart filter in the current buffer:   "
## ----------------------------------------------------------------------- ##

##-========================-##
echo "[+] Add the alias:                                "
##-========================-##
/alias add rmsfilter filter del irc_smart_$server_$channel


/server add NAME HOST/6667 -autoconnect -ssl -ssl_dhkey_size=512 -password=PASSWORD -username=USERNAME -nicks=NICK



curl -F file=@/path/to/file -F channels=CHAN -F token=XXX https://slack.com/api/files.upload











## ================ ##
## 	Misc Commands   ##
## ================ ##




## =================================================== ##
## 			Commands Mentioned In The Manual: 
## =================================================== ##


## =================================================== ##
## --------------------------------------------------- ##
			me &2			||			ACTION
## --------------------------------------------------- ##
	   allchan me &2		||			AME
## --------------------------------------------------- ##
	  allserv nick &2		||			ANICK
## --------------------------------------------------- ##
	   allchan say &2		||			AMSG
## --------------------------------------------------- ##
	  quote MODE %c +b		||			BANLIST
## --------------------------------------------------- ##
		 dcc chat %2		||			CHAT
## --------------------------------------------------- ##
		  query %2			||			DIALOG
## --------------------------------------------------- ##
	    msg =%2 &3			||			DMSG
## --------------------------------------------------- ##
		   quit				||			EXIT
## --------------------------------------------------- ##
	 lastlog -r -- &2		||			GREP
## --------------------------------------------------- ##
	 ignore %2!*@* ALL		||			IGNALL
## --------------------------------------------------- ##
	 	  join &2			||			J
## --------------------------------------------------- ##
	quote KILL %2 :&3		||			KILL
## --------------------------------------------------- ##
		  part &2			||			LEAVE
## --------------------------------------------------- ##
		  msg &2			||			M
## --------------------------------------------------- ##
		msg @%c &2			||			OMSG
## --------------------------------------------------- ##
	  notice @%c &2			||			ONOTICE
## --------------------------------------------------- ##
		 quote &2			||			RAW
## --------------------------------------------------- ##
	    quote HELP			||			SERVHELP
## --------------------------------------------------- ##
		  ping				||			SPING
## --------------------------------------------------- ##
	quote SQUERY %2 :&3		||			SQUERY
## --------------------------------------------------- ##
	  server -ssl &2		||			SSLSERVER
## --------------------------------------------------- ##
	echo HexChat %v %m		||			SV
## --------------------------------------------------- ##
		mode %n &2			||			UMODE
## --------------------------------------------------- ##
	  quote STATS u			||			UPTIME
## --------------------------------------------------- ##
	 ctcp %2 VERSION		||			VER
## --------------------------------------------------- ##
	 ctcp %2 VERSION		||			VERSION
## --------------------------------------------------- ##
	quote WALLOPS :&2		||			WALLOPS
## --------------------------------------------------- ##
	 quote WHOIS %2			||			WI
## --------------------------------------------------- ##
	quote WHOIS %2 %2		||			WII
## --------------------------------------------------- ##   
## =================================================== ##




## ================================================================================== ##
## Connect To IRC Through SSL
## ================================================================================== ##

## -------------------------------------------------------------------------------- ##
/SERVCHAN -ssl ${host} ${port} ${chan}			## connects and joins a channel
## -------------------------------------------------------------------------------- ##
/SERVER -ssl ${host} ${port} ${password}		## The default port is 6667 
# 												## For SSL Use Port 6697
## -------------------------------------------------------------------------------- ##
## ================================================================================== ##




## ================================================================================== ##
## 								System Info Examples:
## ================================================================================== ##

## -------------------------------------------------------------------------------- ##
/SYSINFO [-e|-o] [CLIENT|OS|CPU|RAM|DISK|VGA|SOUND|ETHERNET|UPTIME]		## print various details about your system or print a summary without arguments
## -------------------------------------------------------------------------------- ##
/SYSINFO SET <variable>
## -------------------------------------------------------------------------------- ##








Xe1phix IRC Server && Chan List


## 
 


## ============================================= ##
					irc.2600.net
## ============================================= ##

## --------------------------------------------------------------- ##		<<--- Auto connect channels
	#2600,#defcon,#hackbbs,#hope,#offthehook,#offthewall,#phreak			<<--- just add this line to your irc client 
## --------------------------------------------------------------- ##		<<--- in the auto connect dialog box

#2600
#defcon
#hackbbs
#hope
#offthehook
#offthewall
#phreak


## ================================================== ##
					irc.oftc.net
## ================================================== ##
## 
## ---------------------------------------------------------------------------------- ##		<<--- Auto connect channels
	#nottor,#tails,#tails-dev,#tor,#tor-dev,#whonix,#i2p,#subgraph,#pax,#grsecurity				<<--- just add this line to your irc client 
## ---------------------------------------------------------------------------------- ##		<<--- in the auto connect dialog box

#guardianproject
#i2p
#noisebridge
#nottor
#openvas
#otr
#otr-dev
#qemu
#tor-bots
#whonix
#xen
#cryptocat
#ecryptfs
#freedombox
#whonix
#subgraph
#pax
#grsecurity
#vidalia
#nottor
#tails
#tails-dev
#tor
#tor2web
#tor-dev



## ================================================== ##
				irc.what-network.net
## ================================================== ##

## -------------------------------------------------------------------------------- ##		<<--- Auto connect channels
	#audiophile,#code,#electronic,#lossless,#pharmaceuticals,#phunk,#trance,#vinyl			<<--- just add this line to your irc client 
## -------------------------------------------------------------------------------- ##		<<--- in the auto connect dialog box




#audiophile
#code
#electronic
#lossless
#pharmaceuticals
#phunk
#trance
#vinyl
#noise





## ================================================== ##
					irc.rizon.net
## ================================================== ##

## --------------- ##		<<--- Auto connect channels
	#/b/,#4chan				<<--- just add this line to your irc client 
## --------------- ##		<<--- in the auto connect dialog box



#/b/
#4chan
#canv.as

## ================================================== ##
					irc.freenode.net
## ================================================== ##

## -------------------------------------------------------------------------------------------------------------------------------------------------- ##		<<--- Auto connect channels
	#aircrack-ng,#skullsecurity,#backtrack,#kali-linux,#metasploit,#Nmap,#wireshark,#pentoo,#gentoo-hardened,#securityweekly,#i2p,#i2pdev,#i2p-chat,			<<--- just add this line to your irc client 
## -------------------------------------------------------------------------------------------------------------------------------------------------- ##		<<--- in the auto connect dialog box




#aircrack-ng
#skullsecurity
#backtrack
#kali-linux
#metasploit
#Nmap
#wireshark
#openssh
#rapid7
#armitage
#social-engineer
#qubes
#pentoo
#gentoo
#gentoo-hardened
#openvswitch
#selinux
#lvm
#linuxjournalsecurityweekly
#blackarch
#linux-wireless
#gmrl
#openwrt
#cuckoosandbox 
#linuxjournal
#securityweekly
#pauldotcom
#i2p
#i2p-dev
#i2p-chat
#archlinux
#archlinux-security
#archlinux-offtopic
#vagrant
##kernel
#freebsd
#kvm
#freebsd-advocacy
#freebsd-commits
#freebsd-games
#freebsd-gnome
#freebsd-ports
#freebsd-python
#freebsd-src
#freebsd-tls
#freebsd-vbox
#alpine-linux
#lxcontainers
#netfilter
#rhel



## ================================================== ##
					irc.EFnet.net
## ================================================== ##

## --------------- ##		<<--- Auto connect channels
	#cdc,#nmap				<<--- just add this line to your irc client 
## --------------- ##		<<--- in the auto connect dialog box




#cdc
#nmap
#bsdcode
#bsddev
#bsddocs
#bsdmips
#bsdports
#bsdtinderbox
#bsdusb
#freebsdhelp
#freebsd




## ################################################################################################## ##
## =============================== Beginning THC Hydra SECURE IRC =================================== ##
## ################################################################################################## ##





## ================================================================================== ##
							## THC Hydra SECURE IRC
## ================================================================================== ##


https://www.ircs.thc.org/



## ---------------------------------------------------------------------------------- ##
		## Connect to IRCS.THC.ORG Port 6697 via the following IRSSI command
## ---------------------------------------------------------------------------------- ##

## ===================================================================================== ##
## Every user authenticates to IRCS with a SSL client certificate using the Atheme Nickserv. 
## Nobody can steal others nicks! 
## ===================================================================================== ##

## ===================================================================================== ##
## You can see whether a nick is properly authenticated 
## by HAVING "account: nickname"-line in /whois : 
## ===================================================================================== ##


## -------------------------------------------------------- ##
## 08:15 -!- nickname [~nickname@ircs.thc.org]
## 08:15 -!- ircname : Unknown
## 08:15 -!- server : ircs.thc.org [tHC Ircs network]
## 08:15 -!- account : nickname
## 08:15 -!- End of WHOIS
## -------------------------------------------------------- ##


## ================================================================================== ##
## 					Channels can be registered with ChanServ Bot.
## 				The recommended IRC Client is Irssi, ZNC (thx to tropic), ... 
## ================================================================================== ##


## ================================================================================== ##
## Connect to IRCS.THC.ORG Port 6697 via the following IRSSI command (more Info here):
## ================================================================================== ##


## ---------------------------------------------------------------------------------- ##
/server -ssl_verify -ssl_cafile ca-ircs-cert.pem -ssl_cert nick.pem ircs.thc.org 6697
## ---------------------------------------------------------------------------------- ##


## ================================================================================== ##
## nick.pem is your Client-Certificate used for authenticating your Nickname.
## Get it here: --->START NICKNAME REGISTRATION HERE<--- 
## ================================================================================== ##




## ################################################################################################## ##
## ================================= End of THC Hydra SECURE IRC ==================================== ##
## ################################################################################################## ##



## ================================================================================== ##
The IRC2P network offers services to register/manage nicknames and channels. 
## ================================================================================== ##

## ---------------------------------------------------------------------------------- ##
/msg nickserv help commands			## to get help about nickname management 
/msg chanserv help commands			## to get help about channel management 
/msg memoserv help commands			## to get help about sending/reading/creating memos




## ---------------------------------------------------------------------------------- ##
/msg nickserv set kill ON|OFF
## ---------------------------------------------------------------------------------- ##



## ================================================================================== ##

## ================================================================================== ##

## ---------------------------------------------------------------------------------- ##
/OTR genkey ${nick}@irc.server.net
## ---------------------------------------------------------------------------------- ##
/OTR start						## Starts an OTR chat (init also works)
/OTR finish ${nick}				## Finish an OTR chat
/OTR trust ${nick}				## Trusts the other user
/OTR auth ${nick} ${password}		## Auths a user via password
/OTR authq
## ---------------------------------------------------------------------------------- ##







## ################################################################################################## ##
## =============================== Beginning of I2p Irc2p Topic ===================================== ##
## ################################################################################################## ##




## ===================================================================================== ##

## ===================================================================================== ##
## 						KillYourTV I2P IRC (IRC2P Protocol) Server
## ===================================================================================== ##


## ---------------------------------------------------------------------------------- ##
/join channel #irc2p	
## ---------------------------------------------------------------------------------- ##
KillYourTV / kytv on irc.oftc.net
Killyourtv on irc.oftc.net
KillYourTV on irc.killyourtv.i2p
killyourtv / kytv on irc.freenode.net
KillYourTV on irc.postman.i2p
## ---------------------------------------------------------------------------------- ##
## irc.killyourtv.i2p=CnG0yQheyd67rl1nHuYZp1sVZxzXHe05UPrmT0B3Vxtd51K-Cq5E6v5~UTrU5lqj56ggvnRl0I8jg1vPn0Q50IH6ght~4ThkKlwDwTOMHmROz3sR6WLCOvD4ZFMDBYjBsxjF3383YSIlYrh~laTXSzD~lPhHLGD1jFQksqea-87sM-yfRzCbA7UyaHtURJ7A3GOb8Bm8W25mPOHpM~xT0TONvbi45IVmAeWkuZ5IhBsrzhWvY1-Riy6IW6KSRoQIZtr5o23cVHkjUh8J-~SWZR5wIgECefrVVCt556qDn35I2829Jlk26-iI9glMrr7funaOtp1wnDvNPTijlxwkeAx9GKPCX48nCyxIUeSTwGv0grDPn43V94tV0LSq8mkXZ1akDJUNf33z2Uao-nCi-ufb0Mt0rzgdRVW1i79GQHk4XbApzjYUjyaSY4cuR0yBRFHrOcrFt~XJABpt9DYklu6y3n54uOLZeXGnE5nKCSHLqyS3dxPTObIQvhz~ZjHRAAAA
## ---------------------------------------------------------------------------------- ##


## ===================================================================================== ##
## 						Other I2P IRC (IRC2P Protocol) Servers
## ===================================================================================== ##

## Irc2P							[[ xdg-open	http://127.0.0.1:6668	]]	## IRC tunnel to access the Irc2P network		
## Postman Irc2p IRC Server			[[ 	 hexchat irc.postman.i2p:6667	]]	## 
## Echelons Irc2p IRC Server		[[ 	 hexchat irc.echelon.i2p:6667	]]	## 


## ========================================================================================================== ##
## 										I2P Full IRC Addresses
## ========================================================================================================== ##
##
## ==================================================================================================================================================== ##
## irc.arcturus.i2p=8d5AIidKU7JudLbGi94VCS7Gu~SrSb4rxBp6ADbc9o0MiOp0vrKGVTdrWiDDLmlneRLqVTPIRmBkxB9PAtRZYmdvstiae9zat5twU7T~xA-mf95t1HZXPTMEnxOB6ZX~fSlxLWR3robKDq7L1DOF9aBXT5fw5KcdZmAw2pDeslobozNkB~38siDW3VEKQrNK6SlgkbcQ2ob5fQjUEN3IPnLbyhP4HAap0CppUfX3ix0YU1EP86XHig8ZUgmq2YQ8LpBOGZ21yHQ3pGDHuvgHHGl7bQqz2TV5MnyUaHkCAHu6d~agqdJc4ooORJZMUkWnFIbL4ioJbzZ9zPIPDam81Qw04MuTY5vPEz1Hx9egdWzJX-kCjFv~3-SPX0QVGYAY-cg~fIJfxH0G3jrjXOfGO6NelDiuyTGhvhCR1Y2O6jTqFyVyUc-WZAHAs2qRacfR-TtEpP2-s7fY191aWwxycD3tbXx1F0FG6AYJcnFhUFFp2uoUCryrY7HA6NA5lIDfAAAA
## irc.baffled.i2p=AjR0lkZfdzmQqLofq5En-yeUYZ9XOugrcpqgA6giY1v880AnhB~xokcAdV76Sx~D3MLkXKjCYF-AMIrvfV8cRZ0XkY8FPFb-MnsnACGirQ4~WN6kEjQ18iEH-OStEeoATiEzCzhQlIaJkCLnRo~lAbsnmqMrV3tJIjdQOL~uxbZQB5rQl~50w01XWIzsjwo0ZqzPjsJ6715HMRp6hag0NYNgf8ZE7vFKkvRNubl60lI3LWduoA7BjwuqCvHP8QddYmmL1s-L0rjDB0JGxRJ7~YZlUA0BECTIxdv2Kv-QEwr2UmuSLFQiQ2jQ5U5z0tzwObaIcAX4aAaKY16mC~cQE5cltSS3ElnLrI0qhpIeTM6217uigbAO6iigYFK5sazru9YEt0jDk2gzxlTF6m5BAn70tnu5IAikzRe2NI8VnkRa7K473r~mS30CzwOHXuxlSEPQUK3AkkrQN1Nfw5dCBLTpIF6aMPqR5tracYPOEOlro76rzChnNu-QDZmOQGkxAAAA
## irc.carambar.i2p=xfMseaHQgLA-MjJTKZoe8fL8cfjOhJBe1ii23jfdInJoioDTNRLJE4EnMxdda4Z2cCLM82Qcd7wqL2mv3uTRij-g9rgbSSxTZBv2TBfv8FkoOtAw3s3yUHCkYXUkjtj55gKv-wSvXCktEDyVt8u0dn4kAlkYg4PLQS2B5aFyL~IrZsV0URgTLxx0O3Ajmy2WLDjCM-jz0y7DKWSHDMJZu7Qm64z9IAVhIEV9yOThoBRnikXy9RJ5nCKEFgzrTHqUa9p9QivmGeP733kb0QC8BjyuPQRTlbaX~huR~3XlVtRx6qXNz6fJoKJL-WN3bJ9gO590MTrSy84d3dUsHtIPRHSwJ~KnpXXdwsLvaY-VItXuj9oKIosdDK0FEEuolm3nHqNmSZIpXXUQvjDvEw7Fxf2iRsK9x2tZnDJl4asN9I70wtyMt2EoXMU4UwGmaeGk3mkPeemCK3fms1NWCnDWfgKNvEru6CNOi38IVli~WHv9G47Uk2~atJbMt-6R~SBkAAAA
## irc.dg.i2p=bunRitjuWmSGkf5UV7pnjMRIxmP7fuHy9SgDfAA0M~4TWoBr4Ji4m5AyMGzhAdNaQW6c2-0CIe~RCDZ~vcN-BSNpaqzd80gKhXYxqUQQB83XRWDdLz-z0H~Y15k90p~n0GUSzsjlZctkYglNMyQ8MAUIpUEiLz6MVwArZqUI-CDOE664ZazcGtSKfBLZKycHsSj6WfLbwl2-R5Zv4f5Xisv9Hd0b8BsqJEWn1AmBMhM7p8l7okM2ZcRnC5ypzBdLfLSdkGJ5dEZAJIxz-GhtB8rJ3e0jJkbFjknGrJfxbwt~5n00nVuiUNMro2JRxQ7w~VzMw~lYRq~1B5TMtaKRDhxk7pnv5MxmVBFNhcT~hImcyxfT7GfIPzYU9s~uiFReoSjAOJZv-rKq4Oyeyz-Pa6lcg-c3MtuTXjJ2BMX2dA5Jw0FFVDDMOdDL2b1lwtyseQQkGtc15i4EtNy6iJrkbqAnIhO86E2C3jDf~yt2FlDlcbx6dkflJ3y3j2Wu9DAgAAAA
## irc.duck.i2p=Bxqr5E7-56oJeya1lsDLBN6L1gKme-FUS6Bh~TQS3HswomK9rpjrYNeqBTBoE8TCFl161~FI3soWqbnmFhIdhskausZsO0ez5-4IXMJW8NTilWqXQ3OJxA20M9grohx3RjkZgXU1ooTx7wviSHtXQYiiqnzGnIzmmEZo5-Xx6VjXakctebWwbi2PrsE6XLxrxXBzB34l4KlVsyX504BJiOT6KXNaVZxvG61GfGVfNHdeXljMDE5d25UdFC6RJdDnJ3Z7Yb7EjAww78aowbR0VCfJDH~cB868-VOKIxmor3Rs7giaLXmUyW~GRtFX10COJj5V6BrhKs61XOXxfbyQKGVXZ0mM2A8cdZE1ftr96SZgGy~V8uUHKvoa1HpjMNrPL5Tr6EGfJxOxAy6PHwotn6a8UMnCZgEdTbQ6U3BTywU~x3SCAQvfOT~dl3sZ-5ujYWNFRp7RhdY-WHn1Kj59MfU-VpczGYdV3bRkwT5lpIjST~vopLfkYUeB6gcVSr49AAAA
## irc.echelon.i2p=ooAkOd014ooZXQ4rpvFsqAZ108YU9knllXDocY5fD84IrRVXDbRyUFtlboDmiKDPNRTY2JIXvb-l5FahAB9SUAZ8voAdH4ozHrigHVg6scVtwU7GCfjq5byuwnyemupgk6saBQKfuyc7k3bYl5Iro85Lnx6EnaYYbyWjMwoUWksI6o3Hp5bNyj2B5wHX7HLzeg1ByxQZ4Q8BZbALg8yIcvKn3rHN4tO9FhQ-e5u6hRxINbMtBL1Hasxl9I8XSI0yalKSsmpWDNxRcx-2VKlVh3MPK~9VZlBrQzXwObLmpTuTukeNt8nheFQ7mZVAHt~1gCs2TmjQPVm2g9BQ32zqCFDhePNfBcxcG-Xl56mE9n6kUvaJWsy5~VhiZZmCUGKWMx0uH7odSiC3ohNgv7dhDpANVA~gvt0IhhwlnifHBa~HHfjFQz75kl0nzv3htkcBfLt4M3AZ5bKLP8ymeGP5NYINf6uKNJA9XrSoBjmv0GqvBvDP0Zl5OO2tkIxOBEWfAAAA
## irc.freshcoffee.i2p=VM42PrZcVJyDFV6Eqt1WkqZ6G260D72u6wsU8Bxt0oSDd5UtCkcrduYMl-~9bgc6AZJpJ1absO5-opUaSqA~0ypGox6gdlvKVCHqHhxR89VLy8nO-kS-cVBXb8TeUq5MdH3djZIQ8zKv9YL5Q9lGW2Nd1od~re~w2F5-AWM25y9P91Pu6wymokYlZoaIffG3O8aXA~0jBweqnE7epuSK5e~kZ~5omDBnfYlNC2MoNxgEiNbuyQdfXbLf5QjHzEIlIv1-BSym-OY9fCwqRuJc4eCKaXrMg6hy2U-HEkMz80Gq-2gEI-uxqTJHnNG4h276rU7ej1FpCPrsnXS0zSj7ppbksOBCrkqlNEYhy1wrCjoREfbBN9A1kHDTfT9cR73Ym8S2-incCzoQrcyJds-2KmXa5vfr5Pvt2v3SYXkrTKJzZXMhXotLP7CAzItVh~SXYMOQtiVd4NKXTgSmXVarewsHcbxnZuQUr0qimjAsTEJZPZMppQFNkfPAAqIoqz0wAAAA
## irc.ircbnc.i2p=d1SmdtsIrD9HBWaHpGC~EsjKMEYwMmfLQgfl2qFrAJEQDzcv0IgZf~0m2ZZptKuCGD35l6GK9iQkAapCRaeJUpSwlu6ph5JzRjH03483hUjst3yvdb7LrT3J9-zDXTGBLLRbikTcyujKwYJPvBmfKRmj4CGaUN5AdhSJtWkDf7RGMTpS0PNTV7XlKNBBx51xk3a1T076Ha-Uhxfwa-fr48ovn9t1cwNA2~6h8YLDXAy8h5s6pCyjhu7H54qY4DkpQ2mj5Z5Zqo8cICihn058AAsUWDUCTBPqv8s2hS45AjB8So0OQ4uu5hOWXuditLtQQ24sPR1Q7ALByfSS-mEz4GksQ4kmXGqNZKb8lbAnItbopfk4P-HP~sIguoGPa5SDDFRHshFpDQOeugv88i71NsqBLy-sdQvpVG2I4txy~-8-VAWbcBPZ17uIeqaLpmRy05voM7QUACsU1S1MNb0PpSNz4fwR8TrPIK4e0pVH0SJNG~ZeWKd1HnZD4P5egs-2AAAA
## irc.killyourtv.i2p=CnG0yQheyd67rl1nHuYZp1sVZxzXHe05UPrmT0B3Vxtd51K-Cq5E6v5~UTrU5lqj56ggvnRl0I8jg1vPn0Q50IH6ght~4ThkKlwDwTOMHmROz3sR6WLCOvD4ZFMDBYjBsxjF3383YSIlYrh~laTXSzD~lPhHLGD1jFQksqea-87sM-yfRzCbA7UyaHtURJ7A3GOb8Bm8W25mPOHpM~xT0TONvbi45IVmAeWkuZ5IhBsrzhWvY1-Riy6IW6KSRoQIZtr5o23cVHkjUh8J-~SWZR5wIgECefrVVCt556qDn35I2829Jlk26-iI9glMrr7funaOtp1wnDvNPTijlxwkeAx9GKPCX48nCyxIUeSTwGv0grDPn43V94tV0LSq8mkXZ1akDJUNf33z2Uao-nCi-ufb0Mt0rzgdRVW1i79GQHk4XbApzjYUjyaSY4cuR0yBRFHrOcrFt~XJABpt9DYklu6y3n54uOLZeXGnE5nKCSHLqyS3dxPTObIQvhz~ZjHRAAAA
## irc.nickster.i2p=4xIbFi15l6BFLkKCPDEVcb23aQia4Ry1pQeC5C0RGzqy5IednmnDQqG5l8mDID8vL831rUmCrj~sC537iQiUXlkKFJvdiuI0HEL4c6a7NCYz3cPncc2Uz~gnlG1YOPv-CkxcXSHxxGrv0-HA281a87hrEc7uQ7hBLPybMl6-Z4k-qsyABDdaZwbqEJDWxJKWNfEWfhj2fHSuYB9c6CJgkPektLdMEIxIO4fWgRaIvyr0jt7ObBcB9QhvZAUnP5~iD9gnl~sxfSg~Zi7UW2sB0ewrb63KLZtRDXmnb-Gc3Cn-6oqvqt~YeNXW2OKiEMggkonLJR8RmdTsgMSwbHvXhyp0utqwgIIP7W0if0IIcDg7t38JzSo67uKs3m9aBf1kJWL~d31v6enPjIpgeLllJB6OaJVtKojn~Yi7Sje~5DJnLxiZVGf~Dn3a9IynFCQ6KXiPo-6418Wl2-vkrq0~cWjmlYMASR9AMILZMr1rOQUf748e92~oYwX2W5saRVnoAAAA
## irc.orz.i2p=0oLxoY4VcI~e~OnFdHtYp9aghBcBLBK46BE-yffvaxsnsNgmf5xiRDORVJ0xjg6e8LZ-gTUXr5EHiJnJa5GEv3sris0PWEXW0QLV2WbkIOI3XNR8sa1WMAJYFX9wYSHNdGDuHj0Igcd9rxwaBufdcHeJ0WLvp1FXCMxEf9OTh52wL3ku5pPGlXaVp22RhJXqaKqGeIFh0A9t-gSF5cPB7D3jvoXPJlZtPFLkrsVQeDCpFC9TLaI2sebJjuEHaBhCLvjA8usG8WiZ0m-TVNwkg0XV~yy-rpOEGq-8CCLa1-7c6mc0gMmeolEFz9L9x6hXzw4TR0MXNMeu8nqeMhbvqws39iLiz1L2r6amzQrXjHReX1ibrEprNfLY~Ne1cgqQ5VsHpCr-UJv3D1QoFCJUwG7z0dJrgoi37aPRRjzUF-z67hi3z-ghKrY7d3m0YpTHUCwZ5o2uwUFM7xEvCXY4nQ8ndwEI0xJKfbBgWEmR8OxV3jbn9ZhSYSoygsbUQg55AAAA
## irc.postman.i2p=d38SuD-ayF9gprdrl2uJM-FfFBor8qmBVQDxZt8SL7VZPUukrkzvxeaCE8riF5~2g1EgOA1nSfrQ4mt5NhuyL8MxGf6xByDng2lVCZ5Ks2InFVdaCEVg0BCfzdpztUGfO81oT7902zoE260P-qDuiSih5KMEouSWr7RPfP75ivoKfnRhVFcZiI36mRUfgOjKSGloeVLdkGIYh3AVYZ4MqQSWP-MXcY0xr1cD~G1ars2vfTNUjwErPirsyktbES0xXDtgr-Q7EF1vYo3cbPttFTyG6LUSEHvcHErfov5hAy~3lYkhgqMqVFyeKDEyb4ZkoSse1q2TpKxzmDAC95H4DQoxB6onvGjpgYQgwK3ZREf-0UVYY8eVHbnN~jTWLnIOdHfEbSMqN5OMYMeLvLc~SX-qKGNExTaA6Zl80QOkTF~Hh3lAONXUhJgPtzuV2igtXyV~BuhFuA8M2nu~HwLsgv5qPN8wInudXpzhhp~hG36tZ90OGDMSA-XXRMzwhHgCAAAA
## ==================================================================================================================================================== ##



## ################################################################################################## ##
## ==================================== End of I2p Irc2p Topic ====================================== ##
## ################################################################################################## ##








## ################################################################################################## ##
## ========================== IsIsLoveCruft (Tor Dev) IRC Contact Info ============================== ##
## ################################################################################################## ##
## 
## 
## ================================================================================================== ##
## 		Server                 Account                     Fingerprint
## ================================================================================================== ##
## 
## -------------------------------------------------------------------------------------------------- ##
## irc.oftc.net           isis@irc.oftc.net				7267FDAF B23C8D86 C311AACC 7F16575A F57A7D3F
## -------------------------------------------------------------------------------------------------- ##
## irc.oftc.net           isis@37lnq2veifl4kar7.onion	993602EF 1C90AC48 07E00A75 7A8EA596 D567D609
## -------------------------------------------------------------------------------------------------- ##
## irc.indymedia.org      isis@h7gf2ha3hefoj5ls.onion	892A996F 6E916E85 083F88FC 1CF7F77D FB769E3C
## -------------------------------------------------------------------------------------------------- ##
## irc.freenode.net       isis@irc.freenode.net			15CC94D5 458F6D83 7651FBCE 2393B98F BD253117
## -------------------------------------------------------------------------------------------------- ##
## 
## ================================================================================================== ##
## 
## 
## ################################################################################################## ##
## ========================= IsIsLoveCruft (Tor Dev) Jabber Contact Info ============================ ##
## ################################################################################################## ##
## 
## =============================================================================================================== ##
## jabber.ccc.de				isislovecruft@jabber.ccc.de			E3C25B12 B1BD5DAA AE47F62D A2FE88AA D6C4F565
## =============================================================================================================== ##
##
## -------------------------------------------------------------------------------------------------- ##
## 	OTR Fingerprint = DBD3AB55 D2691E05 38B9528C 2C25C9D9 E2EDE0ED
## -------------------------------------------------------------------------------------------------- ##
##
## =============================================================================================================== ##
## okj7xc6j2szr2y75.onion		isislovecruft@jabber.ccc.de 		E3C25B12 B1BD5DAA AE47F62D A2FE88AA D6C4F565
## =============================================================================================================== ##
## 
## -------------------------------------------------------------------------------------------------- ##
## 	OTR Fingerprint = 226265F2 DA257A80 EB19B2AE 0D7E6317 E560D817
## -------------------------------------------------------------------------------------------------- ##
## 
## 


## ################################################################################################## ##
## ================================= RiseUp.net IRC Servers ========================================= ##
## ################################################################################################## ##
## 
## -------------------------------------------------------------------------------------------------- ##
## chat.riseup.net				isis@riseup.net			F9B81DF4 BA310806 B1513680 246598A0 6FC08CDB
## -------------------------------------------------------------------------------------------------- ##
## ztmc4p37hvues222.onion		isis@riseup.net			F9B81DF4 BA310806 B1513680 246598A0 6FC08CDB
## -------------------------------------------------------------------------------------------------- ##
## 
## ################################################################################################## ##
## ================================================================================================== ##
## ################################################################################################## ##








## =============== ##
## ParrotSec Group ##
## =============== ##

http://webchat.frozenbox.org/

#frozenbox
#parrot
#parrotdev



## ===================== ##
##  Your custom link is  ##
## ===================== ##
http://chat.frozenbox.org:3989?nick=xe1phix&channels=parrot&prompt=1




								## ===================== ##
								  ##  ParrotSec WebIRC  ##
								## ===================== ##

## -------------------------------------------------------------------------------------------------- ##
## 			http://chat.frozenbox.org:3989/?nick=parrot_....&channels=parrot&prompt=1				  ##
## -------------------------------------------------------------------------------------------------- ##










## ============================== ##
## -- ParrotSec telegram group -- ##
## ============================== ##
@parrotsec

## --------------------------------------------- ##
##		 https://telegram.me/parrotsec			 ##
## --------------------------------------------- ##












## ===================================================================================== ##
## 					List of NickServ Command Syntax Options:
## ===================================================================================== ##

/msg NickServ help

/NICKSERV REGISTER
/NICKSERV IDENTIFY
/NICKSERV INFO
/NICKSERV LISTCHANS
/NICKSERV RELEASE
/NICKSERV STATUS
/NICKSERV CERT
/NICKSERV VERIFY
/NICKSERV SETPASS
/NICKSERV LISTGROUPS




## ===================================================================================== ##
## ACC returns parsable information about a user's login status. 
## Note that on many networks, /whois shows similar information faster and more reliably. 
## ===================================================================================== ##





## =============================================
## 0 - account or user does not exist 
## 1 - account exists but user is not logged in 
## 2 - user is not logged in but recognized (see ACCESS) 
## 3 - user is logged in
## =============================================
## Syntax: ACC
## Syntax: ACC ${nick}
## Syntax: ACC ${nick} <account>
## Syntax: ACC ${nick} *
## =============================================
/msg NickServ ACC 
/ACC xe1phix *
    
    
    

## ===================================================================================== ##
## ACCESS maintains a list of user@host masks from where NickServ will recognize you, 
## so it will not prompt you to change nick
## ===================================================================================== ##
## =============================================
## Syntax: ACCESS LIST
## Syntax: ACCESS ADD [mask]
## Syntax: ACCESS DEL <mask>
## =============================================
/msg NickServ ACCESS LIST 
/msg NickServ ACCESS ADD jack@host.example.com 
/msg NickServ ACCESS ADD user@10.0.0.8 
/msg NickServ ACCESS ADD jilles@192.168.1.0/24 
/msg NickServ ACCESS DEL *someone@*.area.old.example.net







## ===================================================================================== ##
## CERT maintains a list of CertFP fingerprints that will allow NickServ 
## to recognize you and authenticate you automatically.
## ===================================================================================== ##

## =============================================
## Syntax: CERT LIST
## Syntax: CERT ADD [fingerprint]
## Syntax: CERT DEL <fingerprint>
## =============================================
/msg NickServ CERT LIST 
/msg NickServ CERT ADD f3a1aad46ca88e180c25c9c7021a4b3a 
/msg NickServ CERT DEL f3a1aad46ca88e180c25c9c7021a4b3a






/msg NickServ DROP ${nick} ${password}				## /DROP ${nick} ${password}

## ===================================================================================== ##
## FDROP forcefully removes the given account, including: 
## ===================================================================================== ##
## 
## -------------------------------------------------------------------------------------------------- ##
## >> all nicknames, 
## >> channel access 
## >> && memos attached to it.
## -------------------------------------------------------------------------------------------------- ##
/msg NickServ FDROP ${nick}



## ===================================================================================== ##
## FREEZE allows operators to "freeze" an abusive user's account
## ===================================================================================== ##
## 
## =============================================
## Syntax: FREEZE ${nick} ON|OFF <reason>
## =============================================
/msg NickServ FREEZE pfish ON Persistent spammer 
/msg NickServ FREEZE alambert OFF


## ===================================================================================== ##
## FUNGROUP forcefully unregisters the given nickname from the account it is registered to
## ===================================================================================== ##
/msg NickServ FUNGROUP ${nick}
/msg NickServ FUNGROUP ${nick} ${nick}



## ===================================================================================== ##
## FVERIFY allows administrators to confirm a change associated with 
## an account registration without having the verification email.
## ===================================================================================== ##
/msg NickServ FVERIFY REGISTER jenny 
/msg NickServ FVERIFY EMAILCHG Aeriana



## ===================================================================================== ##
## GHOST disconnects an old user session, 
## or somebody attempting to use your nickname without authorization.
## ===================================================================================== ##
/msg NickServ GHOST ${nick}




## ===================================================================================== ##
## GROUP registers your current nickname to your account.
## ===================================================================================== ##
/msg NickServ IDENTIFY ${nick} ${password} 
/msg NickServ GROUP





## ===================================================================================== ##
## HOLD prevents an account and all nicknames registered to it from expiring.
## ===================================================================================== ##
/msg NickServ HOLD ${nick} ON



## ===================================================================================== ##
## IDENTIFY identifies you with services so that you can perform general 
## maintenance and commands that require you to be logged in.
## ===================================================================================== ##
## 
## =============================================
## Syntax: IDENTIFY ${nick} ${password}
## =============================================
/msg NickServ IDENTIFY foo 
/msg NickServ IDENTIFY jilles foo



/msg NickServ INFO ${nick}					## Shows information about the registered nick w00t. 
/msg NickServ INFO =${nick}[home]		## Shows information about the registered nick the user w00tie[home] is logged in as.


## ===================================================================================== ##
## LIST shows registered users that match a given criteria. 
## Multiple criteria may be used in the same command.
## ===================================================================================== ##
/msg NickServ LIST pattern ${nick}* 
/msg NickServ LIST hold 
/msg NickServ LIST frozen pattern x* 
/msg NickServ LIST registered 30d 
/msg NickServ LIST marked registered 7d pattern ${nick} 
/msg NickServ LIST email *@gmail.com 
/msg NickServ LIST mark-reason *lamer*


    
## ===================================================================================== ##
## LISTCHANS shows the channels that you have access to, including those that you own.
## ===================================================================================== ##
/msg NickServ LISTCHANS



## ===================================================================================== ##
## LISTMAIL shows accounts registered to a given e-mail address. Wildcards are allowed.
## ===================================================================================== ##
## 
## =============================================
## Syntax: LISTMAIL <email>
## =============================================
/msg NickServ LISTMAIL ${email} 
/msg NickServ LISTMAIL *@cam.ac.uk






