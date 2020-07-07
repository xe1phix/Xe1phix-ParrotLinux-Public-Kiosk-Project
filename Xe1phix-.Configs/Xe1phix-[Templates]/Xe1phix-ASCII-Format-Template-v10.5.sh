
##-=====================================================-##
##   [+] :
##-=====================================================-##
## ----------------------------------------------------- ##
##   [?] 
## ----------------------------------------------------- ##



## ---------------------------------------------------------------------------------------------- ##
## ------------------------------------------------------------------------------------------ ##
## -------------------------------------------------------------------------------------- ##
## ---------------------------------------------------------------------------------- ##
## ------------------------------------------------------------------------------ ##
## -------------------------------------------------------------------------- ##
## ---------------------------------------------------------------------- ##
## ------------------------------------------------------------------ ##
## -------------------------------------------------------------- ##
## ---------------------------------------------------------- ##
## ------------------------------------------------------ ##
## -------------------------------------------------- ##
## ---------------------------------------------- ##
## ------------------------------------------ ##
## -------------------------------------- ##
## ---------------------------------- ##
## ------------------------------ ##
## -------------------------- ##
## ---------------------- ##
## ------------------ ##


##   [?] 






##-=========================-##
##-============================================-##
##-===================================================-##
##-==============================================================-##

##-==========================================================================================-##
##-=============================================================================================================-##
##   [+] 
##   [?.
] 




echo "##~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~##"
echo "##-===============================================================-##"
echo "##-                [+] :	                                        -##"
echo "##-===============================================================-##"
echo "##~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~##"

##~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~##


## ---------------------------------------- ##
##  (+) 
## ---------------------------------------- ##



##-========================================-##
##  (+) 
##-========================================-##




echo "##-==============================================================-##"
echo "##   [+] Generate a Certificate Signing Request (in PEM format):    "
echo "##              For the public key of a key pair                    "
echo "##-==============================================================-##"



echo -e "<<+}========================================={+>>"
echo -e "        {+} 							      "
echo -e "<<+}========================================={+>>"





##                                                                                                                                         _^_            _^_
##                                                                                                                                      <|_±_|>_ _<|_±_|>
##-//________________________________________________________________ -\\-##|##-//-
##/-----------------------------------------------------------------------------------------------------  -\\-#||#-//-
##    [?]                                                                                                                                       -||-#|#-||-
##                                                                                                                                                -||-#|#-||-
##                                                                                                                                                -||-#|#-||-
##\\_________________________________________________________________  -//-#||#-\\-
##-\-------------------------------------------------------------------------------------------------___//-##|##-\\___
                                                                                                                                            ####              ####


   _^_            _^_
<|_±_|>_ _<|_±_|>
     -\\-\     /-//-
       -\\v/-//-
        -||-#|#-||-
        -||-#|#-||-
        -||-#|#-||-
      -//V/^\V\\-
__-//V/      \V\\-__
######      ######



---------------- Firejail Audit: the GOOD, the BAD and the UGLY ----------------


GOOD: process 6 is running in a PID namespace.

GOOD: seccomp BPF enabled.
checking syscalls:

GOOD: all capabilities are disabled.

GOOD: SSH server not available on localhost.
GOOD: HTTP server not available on localhost.
GOOD: I cannot connect to netlink socket. Network utilities such as iproute2 will not work in the sandbox.

GOOD: Access to /dev directory is restricted.


BAD: the capability map is 3fffffffff, it should be all zero.

[WARNING]: CAP_SYS_ADMIN is enabled.
[WARNING]: CAP_SYS_BOOT is enabled.

UGLY: I can access files in /home/xe1phix/.ssh directory. Use "firejail --blacklist=/home/xe1phix/.ssh" to block it.
UGLY: I can access files in /home/xe1phix/.gnupg directory. Use "firejail --blacklist=/home/xe1phix/.gnupg" to block it.
UGLY: I can access files in /home/xe1phix/.mozilla directory. Use "firejail --blacklist=/home/xe1phix/.mozilla" to block it.
GOOD: I cannot access files in /home/xe1phix/.config/chromium directory.
GOOD: I cannot access files in /home/xe1phix/.icedove directory.
UGLY: I can access files in /home/xe1phix/.thunderbird directory.






 ======================================= 
|    OS information on 192.168.1.113    |
 ======================================= 





+ -- --=[Checking 
+ -- --=[Retrieving 
+ -- --=[Target: 




+ -- --=[
+ -- --=[Port 

+ Target Port:
+ Server: 
|   Protocol: 


| sslv2: 
|   SSLv2 supported

| ssl-cert: Subject: commonName=VulnOS.home
|_ssl-date: 2015-12-28T15:48:42+00:00; -17s from scanner time.

|_http-methods: 
| http-php-version: 

|_http-server-header: 
|_http-title: index

|_http-referer-checker: 

| Not valid before: 
|_Not valid after:  
|_ssl-date: 


|_  ciphers: 

|   Version: 
|   Status: 

|     user:$user
|_  Statistics: 



|   OS: Unix 








 ========================================== 
|    Share Enumeration on 192.168.1.113    |
 ========================================== 
Domain=[WORKGROUP] OS=[Unix] Server=[Samba 3.0.20-Debian]
Domain=[WORKGROUP] OS=[Unix] Server=[Samba 3.0.20-Debian]


	Sharename       Type      Comment
	---------       ----      -------
	print$          Disk      Printer Drivers
	tmp             Disk      oh noes!
	opt             Disk      


	Server               Comment
	---------            -------
	TREADSTONE           Samba 4.0.6-Debian

	Workgroup            Master
	---------            -------
	WORKGROUP            TREADSTONE




[DATA] 
[STATUS] 
[WARNING] 



137/udp   open          netbios-ns  Samba nmbd (workgroup: $WORKGROUP)
138/udp   open|filtered netbios-dgm


|_
| $
|   $Value
|_http-frontpage-login: false
| http-headers: 
|   Date: Mon, 28 Dec 2015 15:57:07 GMT
|   Server: Apache/2.2.14 (Ubuntu)
|   Last-Modified: Sun, 30 Mar 2014 00:35:52 GMT
|   ETag: "10353b-2e9-4f5c81e0490a0"
|   Accept-Ranges: bytes
|   Content-Length: 745
|   Vary: Accept-Encoding
|   Connection: close
|   Content-Type: text/html
|   



| dns-nsid: 
|_  bind.version: 9.7.0-P1

| dns-nsid: 
|_  bind.version: 9.7.0-P1
|_dns-recursion: 



| rpcinfo: 
|   program version   port/proto  service

| irc-info: 



6667/tcp  open          irc         IRCnet ircd
| irc-info: 
|   users: 1
|   servers: 1
|   chans: 15
|   lusers: 1
|   lservers: 0
|   server: irc.localhost
|   version: 2.11.2p1. irc.localhost 000A 
|   uptime: 0 days, 0:21:44
|   source ident: NONE or BLOCKED
|   source host: 192.168.1.149
|_  error: Closing Link





|_  error: 







 ----------------------------------------------------------
|                   Scan Information                       |
 ----------------------------------------------------------





       =[ metasploit v4.11.5-2015121501                   ]
+ -- --=[ 1518 exploits - 871 auxiliary - 256 post        ]
+ -- --=[ 436 payloads - 37 encoders - 8 nops             ]






##-================================================================-##
## --------------- [+] ___________________________ ---------------- ##
##-================================================================-##




##-==============================================================-##
##   || <lsof> || --> @ Internet IPv6 host address:port 1234 ||
##-==============================================================-##




       ┌─────────────┬─────────────────────────────────────────┐
       │Flag         │ Description                             │
       ├─────────────┼─────────────────────────────────────────┤
       │persistent   │ Gives  a client the same source-/desti‐ │
       │             │ nation-address for each connection.     │
       ├─────────────┼─────────────────────────────────────────┤
       │random       │ If used then port mapping will be  ran‐ │
       │             │ domized  using a random seeded MD5 hash │
       │             │ mix using source  and  destination  ad‐ │
       │             │ dress and destination port.             │
       ├─────────────┼─────────────────────────────────────────┤
       │fully-random │ If  used then port mapping is generated │
       │             │ based on a 32-bit  pseudo-random  algo‐ │
       │             │ rithm.                                  │
       └─────────────┴─────────────────────────────────────────┘






       ┌───────────┬───────────────────────────────┬───────────────────────────────┐
       │Expression │ Description                   │ Type                          │
       ├───────────┼───────────────────────────────┼───────────────────────────────┤
       │address    │ Specifies       that      the │ ipv4_addr,   ipv6_addr,   eg. │
       │           │ source/destination address of │ abcd::1234,  or you can use a │
       │           │ the  packet  should  be modi‐ │ mapping, eg. meta mark map  { │
       │           │ fied. You may specify a  map‐ │ 10   :   192.168.1.2,   20  : │
       │           │ ping  to relate a list of tu‐ │ 192.168.1.3 }                 │
       │           │ ples  composed  of  arbitrary │                               │
       │           │ expression  key  with address │                               │
       │           │ value.                        │                               │
       ├───────────┼───────────────────────────────┼───────────────────────────────┤
       │port       │ Specifies      that       the │ port number (16 bits)         │
       │           │ source/destination address of │                               │
       │           │ the packet  should  be  modi‐ │                               │
       │           │ fied.                         │                               │
       └───────────┴───────────────────────────────┴───────────────────────────────┘



       ┌──────────────┬───────────────────┬───────────────────────────┐
       │Value         │ Description       │ Type                      │
       ├──────────────┼───────────────────┼───────────────────────────┤
       │packet_number │ Number of packets │ unsigned integer (32 bit) │
       ├──────────────┼───────────────────┼───────────────────────────┤
       │byte_number   │ Number of bytes   │ unsigned integer (32 bit) │
       └──────────────┴───────────────────┴───────────────────────────┘


       ┌─────────┬───────────────────────────────┬───────────┐
       │Keyword  │ Description                   │ Value     │
       ├─────────┼───────────────────────────────┼───────────┤
       │priority │ TC packet priority            │ tc_handle │
       ├─────────┼───────────────────────────────┼───────────┤
       │mark     │ Packet mark                   │ mark      │
       ├─────────┼───────────────────────────────┼───────────┤
       │pkttype  │ packet type                   │ pkt_type  │
       ├─────────┼───────────────────────────────┼───────────┤
       │nftrace  │ ruleset    packet     tracing │ 0, 1      │
       │         │ on/off.   Use  monitor  trace │           │
       │         │ command to watch traces       │           │
       └─────────┴───────────────────────────────┴───────────┘

       ┌────────┬─────────┬──────────┬───────────┐
       │Name    │ Keyword │ Size     │ Base type │
       ├────────┼─────────┼──────────┼───────────┤
       │Integer │ integer │ variable │ -         │
       └────────┴─────────┴──────────┴───────────┘


       ┌──────────┬───────────────────────────────┬───────────────────┐
       │Keyword   │ Description                   │ Type              │
       ├──────────┼───────────────────────────────┼───────────────────┤
       │length    │ Length of the packet in bytes │ integer (32 bit)  │
       ├──────────┼───────────────────────────────┼───────────────────┤
       │protocol  │ Ethertype protocol value      │ ether_type        │
       ├──────────┼───────────────────────────────┼───────────────────┤
       │priority  │ TC packet priority            │ tc_handle         │
       ├──────────┼───────────────────────────────┼───────────────────┤
       │mark      │ Packet mark                   │ mark              │
       ├──────────┼───────────────────────────────┼───────────────────┤
       │iif       │ Input interface index         │ iface_index       │
       ├──────────┼───────────────────────────────┼───────────────────┤
       │iifname   │ Input interface name          │ string            │
       ├──────────┼───────────────────────────────┼───────────────────┤
       │iiftype   │ Input interface type          │ iface_type        │
       ├──────────┼───────────────────────────────┼───────────────────┤
       │oif       │ Output interface index        │ iface_index       │
       ├──────────┼───────────────────────────────┼───────────────────┤
       │oifname   │ Output interface name         │ string            │
       ├──────────┼───────────────────────────────┼───────────────────┤
       │oiftype   │ Output   interface   hardware │ iface_type        │
       │          │ type                          │                   │
       ├──────────┼───────────────────────────────┼───────────────────┤
       │skuid     │ UID associated with originat‐ │ uid               │
       │          │ ing socket                    │                   │
       ├──────────┼───────────────────────────────┼───────────────────┤
       │skgid     │ GID associated with originat‐ │ gid               │
       │          │ ing socket                    │                   │
       ├──────────┼───────────────────────────────┼───────────────────┤
       │rtclassid │ Routing realm                 │ realm             │
       ├──────────┼───────────────────────────────┼───────────────────┤
       │ibriport  │ Input bridge interface name   │ string            │
       ├──────────┼───────────────────────────────┼───────────────────┤
       │obriport  │ Output bridge interface name  │ string            │
       ├──────────┼───────────────────────────────┼───────────────────┤
       │pkttype   │ packet type                   │ pkt_type          │
       ├──────────┼───────────────────────────────┼───────────────────┤
       │cpu       │ cpu  number  processing   the │ integer (32 bits) │
       │          │ packet                        │                   │
       ├──────────┼───────────────────────────────┼───────────────────┤
       │iifgroup  │ incoming device group         │ devgroup          │
       ├──────────┼───────────────────────────────┼───────────────────┤
       │oifgroup  │ outgoing device group         │ devgroup          │
       ├──────────┼───────────────────────────────┼───────────────────┤
       │cgroup    │ control group id              │ integer (32 bits) │
       ├──────────┼───────────────────────────────┼───────────────────┤
       │random    │ pseudo-random number          │ integer (32 bits) │
       └──────────┴───────────────────────────────┴───────────────────┘






##-==============================================-##
## ---------------------------------------------- ##
##   [+] ____________________________________:    ##
## ---------------------------------------------- ##
##-==============================================-##

##-==============================================-##
## ---------------------------------------------- ##
##   [+] PSAD - Config Keywords + Definitions:    ##
## ---------------------------------------------- ##
##-==============================================-##








|     References:
|       https://$Domain.$(com|org|net)
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2011-2523
|       https://scarybeastsecurity.blogspot.com/2011/07/alert-vsftpd-download-backdoored.html
|_      https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/unix/ftp/vsftpd_234_backdoor.rb






## Make a backup
datestring="$(date '+%F-%H:%M:%S')"
backup_folder=~/hexchat_${datestring}
if [ -d ~/.config/hexchat ]; then
   mv ~/.config/hexchat "$backup_folder"
fi



## Copy config files.
mkdir --parents ~/.config/hexchat
cp -r /etc/skel/.config/hexchat ~/.config/











