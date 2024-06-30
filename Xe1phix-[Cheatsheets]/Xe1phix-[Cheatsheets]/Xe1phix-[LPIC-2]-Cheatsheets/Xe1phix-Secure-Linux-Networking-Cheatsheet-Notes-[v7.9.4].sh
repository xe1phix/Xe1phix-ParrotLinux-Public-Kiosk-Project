
.*[.](mkv|avi|mp4)



##-======================================-##
##      [+] Mullvad VPN - Public DNS
##-======================================-##	

## ------------------------------------------ ##			## --------------------------------------------------------------------------------------------------------------------------------------------- ##
nameserver 193.138.218.74								##    [?] Stable											##  [?]  Public Non-logging DNS server
## nameserver 193.138.219.228						##    [?] Expired March 20th 2019		##  [?]  https://mullvad.net/en/blog/2019/2/20/our-public-dns-changing/
## ------------------------------------------ ##			## --------------------------------------------------------------------------------------------------------------------------------------------- ##




##-==================================-##
##     [+] ParrotSec / OpenNIC  Nameservers:
##-==================================-##
nameserver 139.99.96.146
nameserver 37.59.40.15
nameserver 185.121.177.177


##-======================================-##
##      [+] ParrotSec / OpenNIC  Nameservers:
##-======================================-##
## ------------------------------------------------------------------ ##
##     [?] Owner: ParrotSec  (Lorenzo "Palinuro" )
## ------------------------------------------------------------------ ##
nameserver 198.98.49.91					##  ns2.us.dns.opennic.glue
nameserver 45.79.57.113					##  ns3.us.dns.opennic.glue


##-=========================-##			## --------------------------------------------------------- ##
##	  [+] OpenNIC NameServers						##     [?] https://servers.opennicproject.org
##-=========================-##			## --------------------------------------------------------- ##
nameserver 172.98.193.42								##     [?]  Stable as of  '[09-15-20]'										##  (ns1.nc.us)	
nameserver 50.116.17.96									## --------------------------------------------------------- ##			##  (ns5.tx.us)
nameserver 155.138.240.237							##     [?] <--- Your closest servers										##  (ns1.tx.us)
nameserver 162.243.19.47								## --------------------------------------------------------- ##			##  (ns6.ny.us)	






Checking the connection using nmcli:


nmcli con show
nmcli connection show --active



##  Bring The connection Down:

nmcli con down "Wired connection 1"


iface eth0 inet static
	address 192.168.1.101
	

        dns-nameservers 139.99.96.146,185.121.177.177,37.59.40.15




See where a shortened url takes you before click
check(){ curl -sI $1 | sed -n 's/Location: *//p';}
curl -sI https://bit.ly/3n4epen | sed -n 's/location: *//p'


##  Curl – Follow Redirect
curl -Iks --location -X GET -A "x-agent" $1


## perl regex to get URLs.
grep -P -o '(?<=href=")http:\S+(?=")' *.html



##### Check is Telegram notification enable, If enabled send message to telegram
curl -X POST "https://api.telegram.org/bot$telegramToken/sendMessage" -d "chat_id=$chatId&text=$messageToSend"




cat /etc/apt/sources.list.parrot 
cat /etc/apt/sources.list
cat /etc/apt/sources.list.d/parrot.list 





rm -f /etc/apt/sources.list.d/parrot.list
rm -f /etc/apt/sources.list.parrot
echo "deb http://deb.debian.org/debian stretch main contrib non-free" > /etc/apt/sources.list
echo "deb-src http://deb.debian.org/debian stretch main contrib non-free" >> /etc/apt/sources.list
echo "deb http://deb.debian.org/debian stretch-updates main contrib non-free" >> /etc/apt/sources.list
echo "deb-src http://deb.debian.org/debian stretch-updates main contrib non-free" >> /etc/apt/sources.list
echo "deb http://security.debian.org/debian-security/ stretch/updates main contrib non-free" >> /etc/apt/sources.list
echo "deb-src http://security.debian.org/debian-security/ stretch/updates main contrib non-free" >> /etc/apt/sources.list
echo "" >> /etc/apt/sources.list
echo "## deb http://deb.parrotsec.org/parrot stable main contrib non-free" >> /etc/apt/sources.list
echo "## deb-src http://archive.parrotsec.org/parrot stable main contrib non-free" >> /etc/apt/sources.list





chmod -v 744  -R $DirPath


 && 

chown -v -R parrotsec-kiosk $DirPath
chown -v -R nobody $DirPath
chown -v -R root $DirPath







## ========================================= ##
##  [+] Mullvad Certificates & Locations: 
## ========================================= ##
## 
## ----------------------------------------- ##
## 	[+] User Certificate => mullvad.crt
## ----------------------------------------- ##
## 		[+] CA Certificate => ca.crt
## ----------------------------------------- ##
## 	  [+] Private Key => mullvad.key
## ----------------------------------------- ##
##

*  The root certificate (CA): `ca.crt`.
*  Client certificate: `client1.crt`.
*  Client key: `client1.key`.
*  HMAC secret key: `ta.key`.
*  Client configuration file: `client.ovpn`.

## ========================================= ##



echo "##-=================================================-##"
echo "##     [+] Turn on The Immutable Bit For The VPN Keys & Certs:			 " 
echo "##-=================================================-##"
chattr +i /etc/openvpn/mullvad_ca.crt
chmod -v 0644 mullvad_ca.crt 
chown -v root mullvad_ca.crt
chattr +i /etc/openvpn/mullvad_crl.pem
chmod -v 0644 mullvad_crl.pem
chmod ug+r mullvad_userpass.txt
chown -v root mullvad_userpass.txt


sudo chmod -v 0644 mullvad_ca.crt 
sudo chmod -v 0644 mullvad_crl.pem 
sudo chmod ug+r mullvad_userpass.txt
cp /etc/resolv.conf ~/Scripts/resolv.conf.ovpnsave
chmod 644 ~/Scripts/resolv.conf.ovpnsave
sudo chown -v root mullvad_userpass.txt
sudo chown -v root mullvad_crl.pem 
sudo chown -v root mullvad_ca.crt



echo "## =========================================================== ##"
echo "   [+] Copy the mullvad config files to /etc/openvpn folder:"
echo "## =========================================================== ##"
sudo cp -v mullvad_ca.crt /etc/openvpn/
sudo cp -v mullvad_crl.pem /etc/openvpn/ 
sudo cp -v mullvad_se.conf /etc/openvpn/
sudo cp -v mullvad_se-modified.conf /etc/openvpn/
sudo cp -v mullvad_userpass.txt /etc/openvpn/
sudo cp -v update-resolv-conf /etc/openvpn/


cp -v mullvad_ca.crt /etc/openvpn/ && cp -v mullvad_se_sto.conf /etc/openvpn/ && cp -v mullvad_userpass.txt /etc/openvpn/ && cp -v update-resolv-conf /etc/openvpn/



echo "##-==================================-##"
echo "         [+] Fetch Mullvads GPG Signing Key:		 		"
echo "##-==================================-##"
gpg --keyserver pool.sks-keyservers.net --recv-keys A1198702FC3E0A09A9AE5B75D5A1D4F266DE8DDF


echo "##-==================================-##"
echo "         [+] Import Mullvads GPG Signing Key:				 "
echo "##-==================================-##"
gpg --keyid-format 0xlong --import mullvad-support-mail.asc
gpg --keyid-format 0xlong --import mullvad-code-signing.asc


echo "##-==================================-##"
echo "          [+] Print Mullvads GPG Fingerprints:				 "
echo "##-==================================-##"
gpg --keyid-format 0xlong --fingerprint 0xA1198702FC3E0A09A9AE5B75D5A1D4F266DE8DDF


echo "##-===================================-##"
echo "         [+] Mullvads GPG Fingerprints (Verified):			"
echo "##-===================================-##"
echo "Primary key fingerprint: A119 8702 FC3E 0A09 A9AE  5B75 D5A1 D4F2 66DE 8DDF"


echo "##-===========================-##"
echo "          [+] Sign Mullvads GPG Key:				"
echo "##-===========================-##"
gpg --lsign A1198702FC3E0A09A9AE5B75D5A1D4F266DE8DDF				## gpg --edit-key A1198702FC3E0A09A9AE5B75D5A1D4F266DE8DDF



echo "##-=====================================================-##"
echo "          [+] Verify Mullvads .deb against Their Published Signed .asc:					"
echo "##-=====================================================-##"
gpg --keyid-format 0xlong -v --verify MullvadVPN-2020.5_amd64.deb.asc MullvadVPN-2020.5_amd64.deb


https://mullvad.net/en/check/
https://mullvad.net/en/help/dns-leaks/
https://mullvad.net/en/help/different-entryexit-node-using-wireguard-and-socks5-proxy/
https://mullvad.net/en/help/wireguard-and-mullvad-vpn/

wg-quick up mullvad-se9

apt-get install openresolv
openvpn-client@mullvad.service
systemctl enable wg-quick@mullvad-se4


kill -HUP /run/openvpn/$1.pid



sudo chown root:root -R /etc/wireguard && sudo chmod 600 -R /etc/wireguard
wg-quick up mullvad-se4

sysctl net.ipv4.ip_forward=1

PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -A FORWARD -o %i -j ACCEPT; iptables -t nat -A POSTROUTING -o wg1 -j MASQUERADE
PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -D FORWARD -o %i -j ACCEPT; iptables -t nat -D POSTROUTING -o wg1 -j MASQUERADE



193.138.218.74


sudo service openvpn start
sudo nohup openvpn --config /etc/openvpn/mullvad_xx.conf


magnet:?xt=urn:btih:fc750867386654ea1c2797a057c107ed360a7765&dn=am.i.mullvad.net&tr=http%3A%2F%2Fam.i.mullvad.net%3A6969%2Fannounce
magnet:?xt=urn:btih:fc750867386654ea1c2797a057c107ed360a7765&dn=am.i.mullvad.net&tr=udp%3A%2F%2Fam.i.mullvad.net%3A6969




cp -v mullvad_se.conf /etc/openvpn/
chmod -v 0755 /etc/openvpn/update-resolv-conf






http://robtex.com/
https://dnsdumpster.com/

https://shodan.io/





https://hackertarget.com/dns-lookup/
http://searchdns.netcraft.com/
https://hackertarget.com/zone-transfer/
https://scans.io/
https://hackertarget.com/find-shared-dns-servers/
https://hackertarget.com/reverse-dns-lookup/

https://hackertarget.com/wp-content/uploads/2018/03/osint-map.png


https://hackertarget.com/ssl-check/


/home/parrotsec-kiosk/Downloads/Audio/BruceLee-BeLikeWater-Inspirational.mp4



Private-Non-Persistent-Sandbox
Private-Non-Persistent-Sandbox
discarded

Mount-bind


nonewprivs
read-write
read-only
whitelisted

jail
temporary filesystem

Mount  a  filesystem overlay


filesystem container, the system  directories  are  mounted  read-
              write.  All  filesystem  modifications  go  into the overlay.
overlay is  stored
              in  $HOME/.firejail/<NAME>  directory.   The created overlay can be reused

nonewprivs and a default capabilities filter
Linux capabilities filter
Drop all capabilities


IPC namespace
IPC namespace-sandbox



/etc/firejail/firejail.config

Blacklist-

cgroup

apparmor_status --verbose


./configure --prefix=/usr --enable-apparmor/
apparmor_parser -r /etc/apparmor.d/firejail-default
/etc/apparmor.d/local/firejail-default

~/.config/firejail/
/home/parrotsec-kiosk/.config/firejail/
/home/$User/.config/firejail/$Profile.profile

apparmor_parser -r /etc/apparmor.d/usr.sbin.NetworkManager
apparmor_parser -r /etc/apparmor.d/*
/etc/init.d/apparmor start
/etc/init.d/apparmor restart

sudo apparmor_parser -R /etc/apparmor.d/usr.bin.thunderbird

firejail --profile=/etc/firejail/firefox.profile --protocol=unix,inet,netlink,packet --dns=193.138.218.74 --dns=10.8.0.1 --dns=139.99.96.146 /usr/bin/firefox



firejail --interface=eth1 --interface=eth0.vlan100


sysctl -w net.ipv6.conf.all.disable_ipv6=1
sysctl -w net.ipv6.conf.default.disable_ipv6=1

# Prevent the IPv6 kernel module (ipv6) from loading the IPv6 networking stack
echo "options ipv6 disable=1" > /etc/modprobe.d/ipv6.conf

echo 1 > /proc/sys/net/ipv4/ip_forward



## IP address of the VPN server.
## Get the IP using: 
nslookup se.mullvad.net
nslookup se-sto.mullvad.net

ping se1-bridge.mullvad.net
ping se2-bridge.mullvad.net

mtr --no-dns --report 

dig +short myip.opendns.com @resolver1.opendns.com
dig +trace 






service network status
systemctl status networking.service -l
journalctl -u networking --no-pager | tail -20

networkctl status
systemctl status systemd-networkd -l
journalctl -u systemd-networkd --no-pager | tail -20

systemctl list-units --type=service
service --status-all

ssl-apache2-debian-ubuntu-SSL_Certificates_with_Apache_on_Debian






firewall-cmd --state
iptables -L
iptables-save > ~/iptables.txt

iptables -t nat -F
iptables -t mangle -F
iptables -F
iptables -X









    DNS servers were used by the clients for domain name resolutions?

    tshark -r HTTPS_traffic.pcap -Y "dns && dns.flags.response==0" -Tfields -e ip.dst


##-===================================================-##
##  [+] CAPTURE 50 DNS PACKETS AND PRINT TIMESTAMP
##-===================================================-##
tcpdump -i ethO -c 50 -tttt 'udp and port 53'


cat /var/log/messages | grep DHCP




tcpdump 
tcpdump 
tcpdump port 1080
-i eth0 -X port \(110 or 143\)
tcpdump -i eth0 -l -nn port 53

tcpdump -lnni eth0 'udp port 53'

tcpdump –r tcpdumpfile –x ‘dst port 31789’


##  Examining Port 31789
Records With tcpshow
tcpdump –r tcpdumpfile –enx ‘dst port 31789’ | tcpshow
-nolink


http://www.cipherdyne.org/LinuxFirewalls

## DoS FROM SPOOFED IPs
hping3 targetiP --flood --frag --spoof ip --destport $PortNum --syn



tail /var/log/messages |grep ICMP |tail -n 1

tail /var/log/messages | grep UDP | tail -n 1


tcpdump -i eth1 -l -nn -s 0 -X -c 1 port

tcpdump -A -i mon0 'tcp port 21'




##-========================================-##
##  [+] Capture DHCP Request And Replies:
##-========================================-##
## ---------------------------------------------------------------- ##
##  [?] DHCP requests are seen on port 67 and the reply is on 68.
## ---------------------------------------------------------------- ##
tcpdump -v -n port 67 or 68



## record the capture data to a file.
tcpdump -i eth0 udp port 53 -w cache.pcap



## read the results of the capture.
tcpdump -n -t -r cache.pcap port 53





Show only up to the first 10 packets by each source IP:

tcpdump -nn ip | awk '{s=$3;sub(/\.[0-9]+$/,"",s);if(a[s]++<10){print}}'




dhcpdump
dumpcap
pcapdump
tcpslice
tshark




tcpdump -d 'tcp[13] & 2 = 2' >/dev/null | grep -B 1 -A 2 0x2


Capture SYN
tcpdump -nnr 05-11-2012_12\:30_eth3.pcap -c 3 'tcp[13] & 2 = 2' | grep -E '(S|S\.)'





tcpdump -i xl0 'tcp[13] & 2 == 2'

atch packets which  have only SYN set:
tcpdump -i xl0 tcp[13] == 2



the PSH bit is bit number 3
the URG bit is bit number 5

                       |C|E|U|A|P|R|S|F|
                       |---------------|
                       |0 0 0 0 0 0 1 0|
                       |---------------|
                       |7 6 5 4 3 2 1 0|

       Looking at the control bits section we see that only bit number 1 (SYN) is set.



CAPTURE PACKETS ON ETH0 IN ASCII AND HEX AND WRITE TO FILE
tcpdump -i ethO -XX -w out.pcap


tcpdump host 10.0.0.1 && host 10.0.0.2            # Traffic between these hosts
tcpdump tcp dst port 80 or 8080                        # Packets to either TCP port

CAPTURE HTTP TRAFFIC TO2 .2 .2 .2
tcpdump -i ethO port 80 dst 2.2.2.2

SHOW CONNECTIONS TO A SPECIFIC IP
tcpdump -i ethO -tttt dst 192.168.1.22 and not net 192.168.1.0/24

PRINT ALL PING RESPONSES
tcpdump -i ethO 'icmp[icmptype] == icmp-echoreply'

CAPTURE 50 DNS PACKETS AND PRINT TIMESTAMP
tcpdump -i ethO -c 50 -tttt 'udp and port 53'


tcpdump -As80 -tni eth0 "udp port 53"


PORTS_USED=`netstat -antl |grep LISTEN | awk '{ print $4 }' | cut -d: -f2|sed '/^$/d'|sort`


SSL/TLS ports and versions
'mac-sha384-sha256-poly1305'


https://github.com/DenizParlak/Zeus


tcpdump -i eth0 443, 80, 88 8443 -w TelegramPCAP.pcap




https://gist.githubusercontent.com/markuskont/c7a314d0fdf4767e5f87f6963a660490/raw/0d7dc0aedd5fcfd49f3ebc2aa3dae5b6ae9e0007/150-syslog-ng-share.conf





dbus-send --print-reply --dest="org.gnome.Shell" /org/gnome/SessionManager/EndSessionDialog org.gnome.SessionManager.EndSessionDialog.Open uint32:2 uint32:0 uint32:60 array:objpath:/org/gnome/SessionManager/EndSessionDialog
# Reboot directly:
dbus-send --system --print-reply --dest=org.freedesktop.login1 /org/freedesktop/login1 "org.freedesktop.login1.Manager.Reboot" boolean:true

# Logout
# Only works for non-scripted usage?
loginctl kill-session $XDG_SESSION_ID;loginctl terminate-session $XDG_SESSION_ID





ss -o state established '( dport = :ssh or sport = :ssh )'

pgrep -u root sshd


kill -HUP `lsof -t /usr/sbin/sshd`
lsof -i tcp:ssh
lsof -i tcp:22
lsof -i | grep openvpn
lsof -Pni | grep 
lsof -i TCP:80


lsof -iTCP:3000 -sTCP:LISTEN -n -P will yield the offender so this process can be killed.



function killport() {
  lsof -i tcp:$1 | awk '(NR!=1) && ($1!="Google") && ($1!="firefox") {print $2}' | xargs kill
}








ngrep -d eth0 port 80

##  Display HTTP connections:
ss -o state established '( dport = :http or sport = :http )'


List open ports on Linux:

netstat -an --inet | grep LISTEN | grep -v 127.0.0.1

ss -l     (all open ports)

ss -nlp

SSH traffic:
darkstat -i fxp0 -f "port 22"
darkstat -i fxp0 -f "port 1194"

1194


ssldump
tls

chkconfig --list
service --status-all | grep -v not running
service --status-all | grep -v running

##-===========================================-##
##  [+] Kill a process running on port 8080
##-===========================================-##
lsof -i :8080 | awk '{l=$2} END {print l}' | xargs kill


##-===================================-##
##  [+] Show Processes Ran By SSHD
##-===================================-##
lsof -p $( pgrep sshd )
lsof -p $( pgrep NetworkManager )



List 10 largest open file on Unix:

lsof /|awk '{ if($7>1048576) print $7/1048576 "MB" " " $9 " " $1 }


echo "[+] Display the top ten running processes - sorted by memory usage"
ps aux | sort -nk +4 | tail




follow pid and its children, writing to "smtpd.":

strace -p 927 -o smtpd -ff -tt


strace -p "`pidof dead_loop`"

strace -p "`pgrep dead_loop`"







## captures traffic on a remote machine with tshark
ssh root@server.com 'tshark -f "port !22" -w -' | wireshark -k -i -

## analyze traffic remotely over ssh w/ wireshark
ssh root@HOST tcpdump -U -s0 -w - 'not port 22' | wireshark -k -i -



echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6




iw --help | cut -c2-199 | grep "dev <devname>"
dev <devname> station dump

dev <devname> auth <SSID> <bssid> <type:open|shared> <freq in MHz> [key 0:abcde d:1:6162636465]
dev <devname> connect [-w] <SSID> [<freq in MHz>] [<bssid>] [key 0:abcde d:1:6162636465] [mfp:req/opt/no]
dev <devname> disconnect


dev <devname> switch channel <channel> [NOHT|HT20|HT40+|HT40-|5MHz|10MHz|80MHz] [beacons <count>] [block-tx]
dev <devname> switch freq <freq> [NOHT|HT20|HT40+|HT40-|5MHz|10MHz|80MHz] [beacons <count>] [block-tx]
dev <devname> switch freq <control freq> [5|10|20|40|80|80+80|160] [<center1_freq> [<center2_freq>]] [beacons <count>] [block-tx]
dev <devname> info

dev <devname> interface add <name> type <type> [mesh_id <meshid>] [4addr on|off] [flags <flag>*] [addr <mac-addr>]
dev <devname> link
d

dev <devname> mesh leave
dev <devname> mesh join <mesh ID> [[freq <freq in MHz> <NOHT|HT20|HT40+|HT40-|80MHz>] [basic-rates <rate in Mbps,rate2,...>]], [mcast-rate <rate in Mbps>] [beacon-interval <time in TUs>] [dtim-perio
dev <devname> mgmt dump frame <type as hex ab> <pattern as hex ab:cd:..> [frame <type> <pattern>]* [count <frames>]
dev <devname> mpath dump




iwlist  wlp1s0 scan
iwlist wlp1s0 scan | grep -i essid
iw wlp1s0 connect BB
iwconfig wlp1s0 essid BB



iw dev %s set channel %s


##  Setting %s to frequency: %s MHz (Channel: %s)
iw dev %s set freq %s




/home/parrotsec-kiosk/Downloads/Scripts/Wiki/content-lpic2-202-prep



ip addr show
ip a show eth0
ip link set eth0 [up/down]

netstat -rn
route -n















nmcli device modify eth0 ipv6.never-default yes
nmcli device modify eth0 ipv6.method ignore
nmcli device modify eth0 -ipv6.ignore-auto-dns yes
nmcli device modify eth0 -ipv6.ignore-auto-routes yes




nmcli device show
nmcli device status
nmcli general status
nmcli -t device
nmcli connection show
nmcli dev status STATE
nmcli dev status CONNECTION

nmcli radio wifi on
nmcli con up id eth0
nmcli con up id wlan0
nmcli dev disconnect eth0
nmcli dev disconnect wlan0
nmcli -p con up ifname wlan0
nmcli device wifi list
nmcli device wifi list bssid




nmcli connection show
nmcli connection show Ethernet\ connection\ 1
nmcli -f GENERAL,WIFI-PROPERTIES dev show eth0 
nmcli -f GENERAL dev show eth0 
nmcli --overview general permissions

nmcli device modify eth0 ipv6.never-default yes
nmcli device modify eth0 ipv6.method ignore
nmcli device modify eth0 -ipv6.ignore-auto-dns yes
nmcli device modify eth0 -ipv6.ignore-auto-routes yes





pkaction --action-id org.freedesktop.NetworkManager.network-control --verbose

nmcli -p -f general,wifi-properties device show
nmcli connection edit type ethernet
nmcli> set connection.autoconnect no

nmcli -t -c auto radio wwan off

set ipv6.method ignore
set ipv4.dns 139.99.96.146,185.121.177.177
set ipv6.ignore-auto-dns yes
set ipv6.dhcp-send-hostname no
set 802-3-ethernet.wake-on-lan ignore

set ipv6.ignore-auto-dns yes
set ipv6.ignore-auto-routes yes
set ipv6.never-default yes
set connection.zone Drop
nmcli -t -c auto general logging level DEBUG 

mcli -p -f general,wifi-properties device show wlan0

nmcli> set ipv4.dns 92.222.97.145 192.99.85.244		## ParrotDNS
nmcli> set ipv4.dns 185.121.177.177					## OpenNIC



nmcli connection modify Wired\ connection\ 1 ipv6.dhcp-send-hostname no
802-3-ethernet.wake-on-lan ignore
ipv6.method ignore
ipv6.ignore-auto-dns yes
ipv6.dhcp-send-hostname no
ipv6.ignore-auto-dns yes
ipv6.ignore-auto-routes yes
ipv6.never-default yes


ipv4.dns 193.138.218.74,
ipv4.dns 198.98.49.91,45.79.57.113,193.138.218.74



nmcli device set autoconnect no

nmcli> set ipv6.method ignore
nmcli> set 802-3-ethernet.wake-on-lan ignore
nmcli> set ipv6.never-default yes
nmcli> set connection.autoconnect no
nmcli> set ipv6.ignore-auto-dns yes
nmcli> set ipv6.dhcp-send-hostname no
nmcli> set ipv4.dns 198.98.49.91,193.138.218.74
nmcli> set ipv6.ignore-auto-routes yes


nmcli connection import type wireguard file configuration_file
nmcli con import type openvpn file /etc/openvpn/$VPNProfile.ovpn

nmcli connection up mullvad_se_sto




Add a new bridge:
nmcli con add type bridge ifname br0

Turn on br0:
nmcli con up br0


curl -o /etc/sks-keyservers.netCA.pem https://sks-keyservers.net/sks-keyservers.netCA.pem













ssh-keygen -b 4096
ssh-keygen -t rsa -b 4096 -C "your_email@example.com"
ssh-keygen -t rsa -b 4096 -f ssh_host_key -C '' -N ''
chown root:root /etc/ssh/ssh_host_key{,.pub}
curl -o /etc/ssh/sshd_config https://raw.githubusercontent.com/drduh/config/master/sshd_config


cat ~/.ssh/id_rsa.pub
scp .ssh/$key.pub root@192.168.51.254:.ssh/

## test if SSH over the HTTPS port is possible, run this SSH command:
ssh -T -p 443 git@ssh.github.com


# Copy your SSH public key on a remote machine for passwordless login - the easy way
ssh-copy-id username@hostname


# Copy ssh keys to user@host to enable password-less ssh logins.
$ssh-copy-id user@host


mkdir ~/.ssh; touch ~/.ssh/authorized_keys; chmod 700 ~/.ssh
chmod 600 ~/.ssh/authorized_keys


# Copy your ssh public key to a server from a machine that doesn't have ssh-copy-id
cat ~/.ssh/id_rsa.pub | ssh user@machine "mkdir ~/.ssh; cat >> ~/.ssh/authorized_keys"
ssh user@example.com "echo `cat ~/.ssh/uploaded_key.pub` >> ~/.ssh/authorized_keys"


Copy the *public key* into the `~/.ssh/authorized_keys` file on the **remote machine**, using the following command. Substitute your own SSH user and host names:
scp ~/.ssh/id_rsa.pub user@example.com:/home/user/.ssh/uploaded_key.pub


Copy the public key to the server into the ~/.ssh folder:
scp .ssh/puttykey.pub root@192.168.51.254:.ssh/



## SFTP and SCP and PATH NAMES
curl ‐u $USER sftp://home.example.com/~/.bashrc





















file.txt host-two:/tmp


joe@host-two:/www/*.html /www/tmp


-r joe@host-two:/www /www/tmp


## connecting to a remote SSH server.
ssh -v -p 22 -C neo@remoteserver


Copy Files over SSH with SCP
scp mypic.png neo@remoteserver:/media/data/mypic_2.png


SSH Tunnel (port forward)
ssh  -L 9999:127.0.0.1:80 user@remoteserver


SSH Reverse Tunnel
setup a listening port on the remote server that will connect back to a local port on our localhost
ssh -v -R 0.0.0.0:1999:127.0.0.1:902 192.168.1.100 user@remoteserver


SSH Reverse Proxy
establishing a SOCKS proxy with our ssh connection
 the proxy is listening at the remote server end.
ssh -v -R 0.0.0.0:1999 192.168.1.100 user@remoteserver





# start a tunnel from some machine's port 80 to your local post 2001
ssh -N -L2001:localhost:80 somemachine

# directly ssh to host B that is only accessible through host A
ssh -t hostA ssh hostB

C h e ck f ing e rp rint
ssh-keygen -l -f /etc/ssh/ssh_host_rsa_key.pub


## View ~/.ssh/known_hosts key information
ssh-keygen -l -f ~/.ssh/known_hosts


# Mount folder/filesystem through SSH
sshfs name@server:/path/to/folder /path/to/mount/point

## copy from host1 to host2, through your host
ssh root@host1 "cd /somedir/tocopy/ && tar -cf - ." | ssh root@host2 "cd /samedir/tocopyto/ && tar -xf -"

## Connect via SSH to VirtualBox guest VM without knowing IP address
ssh vm-user@`VBoxManage guestproperty get "vm-name" "/VirtualBox/GuestInfo/Net/0/V4/IP" | awk '{ print $2 }'`


## Backup a local drive into a file on the remote host via ssh
dd if=/dev/sda | ssh user@server 'dd of=sda.img'

##-===================================-##
##     [+] Single use vnc-over-ssh connection 
##-===================================-##
ssh -f -L 5900:localhost:5900 your.ssh.server "x11vnc -safer -localhost -nopw -once -display :0"; vinagre localhost:5900



ssh remotehost 'dpkg --get-selections' | dpkg --set-selections && dselect install

## "Clone" a list of installed packages from one Debian/Ubuntu Server to another
apt-get install `ssh root@host_you_want_to_clone "dpkg -l | grep ii" | awk '{print $2}'`



##-==============================================-##
##     [+] SSH connection through host in the middle
ssh -t reachable_host ssh unreachable_host


ssh -L localport:desthost:destport user@gate

ssh -R destport:desthost:localport user@gate


ssh -X user@gate
# To force X forwarding


##-==============================================-##
##     [+] SSH Local Port Forwarding

ssh -L 0.0.0.0:4444:<attacking.machine.ip.address>:4444 <local_hostname>

ssh -L 10443:<victim.ip.address>:443 user@<pivot_host>

ssh -L 0.0.0.0:45001:<victim.ip.address>:80 user@<pivot_host>



##-==============================================-##
##     [+] Generate SSH host keys

ssh-keygen -t rsa -b 8192 -a 23 -C “root@myhostname” -f /etc/ssh/ssh\_host\_rsa\_key -N ‘’

ssh-keygen -t ed25519 -b 521 -a 64 -C “root@myhostname” -f /etc/ssh/ssh\_host\_ed25519\_key -N ‘’
ssh-keygen -t rsa -b 4096 -C “ts-user1-myhostname” -f ~/.ssh/ts-myhostname\_rsa

ssh-keygen -t rsa -b 4096 -C “putty-user1-myhostname” -f ~/.ssh/putty-myhostname\_rsa

ssh-keygen -t ed25519 -b 521 -C “cygwin-user1-myhostname” -f ~/.ssh/cygwin-myhostname\_ed25519

ssh-keygen -t ed25519 -b 521 -C “thor-user1-myhostname” -f ~/.ssh/thor-myhostname\_ed25519

chmod 0600 /home/user1/.ssh/\*

chmod 0644 /home/user1/.ssh/\*.pub

chmod 0644 /home/user1/authorized\_keys



ssh -R 1080 host


HTTP_PROXY=socks5://localhost:1080


##-===================================================-##
##      [+] Use SSH Tunneling To Connect To Mullvads VPN Servers			
##-===================================================-##
## ---------------------------------------------------------------------------------------- ##
##   [?] This involves logging in to our bridge servers 
##          and then running a local SOCKS proxy 
##          that you can connect OpenVPN to
## ---------------------------------------------------------------------------------------- ##
##   [?]  https://mullvad.net/en/help/ssh-and-mullvad-vpn/
## ---------------------------------------------------------------------------------------- ##

nslookup us-chi-br-001.mullvad.net

##  Non-authoritative answer:
##  Name:	us-chi-br-001.mullvad.net
##  Address: 68.235.43.114



echo "##-==============================================-##"
echo "         [+] SSH tunneling to connect to Mullvads VPN servers		"
echo "##-==============================================-##"
ssh -f -N -D 1234 mullvad@193.138.219.43







Certificate

cd /etc/stunnel
openssl genrsa -out stunnel.key 2048
openssl req -new -key stunnel.key -out stunnel.csr
openssl x509 -req -days 365 -in stunnel.csr -signkey stunnel.key -out stunnel.crt
cat stunnel.crt stunnel.key > stunnel.pem
chmod 640 stunnel.key stunnel.pem


gnutls-cli www.example.com --x509keyfile $MYKEY --x509certfile $MYCERT

gnutls-cli --starttls-proto smtp --port 25 localhost


openssl s_client -connect smtp.gmail.com:587 -starttls smtp < /dev/null 2>/dev/null |
openssl s_client -showcerts -starttls smtp -connect smtp_relay:smtp_relay_port < /dev/null 2> /dev/null
openssl s_client -CApath /etc/ssl/certs -showcerts -starttls smtp -connect smtp_relay:smtp_relay_port < /dev/null 2> /dev/null

sudo -u postfix openssl s_client -showcerts -starttls smtp -connect smtp.gmail.com:587 < /dev/null 2> /dev/null



gnutls-cli www.example.com --x509keyfile $MYKEY --x509certfile $MYCERT


debug services with starttls capability.

gnutls-cli-debug --starttls-proto smtp --port 25 localhost


danetool --check mullvad.net --proto tcp --port 443

gnutls-cli --print-cert mullvad.net

gnutls-cli -p 443 mullvad.net

GnuTLS: 
gnutls-cli --x509certfile ${OUTFILE}.crt --x509keyfile ${OUTFILE}.key

openssl s_client -connect api.github.com:443 -no_ssl2 -ign_eof



##-=======================================================================-##
##   [+] Use gnutls-cli to get a copy of the server certificate chain:
##-=======================================================================-##
echo | gnutls-cli -p 443 $Domain --save-cert $Chain.pem




gnutls-cli --save-cert=mullvad.pem mullvad.net:443


TLS connection over port 443 debug level 5
gnutls-cli -d 5 mullvad.net -p 443

Test gmail’s IMAP connection over 993:
gnutls-cli -d 5 imap.gmail.com -p 993


echo | gnutls-cli -p 443 $Domain --save-cert $Chain.pem


gnutls-cli -p 443 gist.github.com --protocols ssl3


openssl s_client -connect gist.github.com:443


gnutls-cli --port %p --sni-hostname %h --alpn ssh/2.0 %h


--list
--verbose

--dane
--ocsp
--starttls
--starttls-proto=
https, ftp, smtp, imap, ldap, xmpp, lmtp, pop3, nntp, sieve, postgres

--port=

--post-handshake-auth


--print-cert

--save-ocsp=
--save-client-trace=
--save-server-trace=
--logfile=

--x509cafile=
--x509crlfile=
--x509keyfile=
--x509certfile=










gnutls-cli-debug --verbose localhost



## start the server again:
gnutls-serv --http --x509cafile x509-ca.pem --x509keyfile x509-server-key.pem --x509certfile x509-server.pem
           




certtool --generate-privkey > x509-ca-key.pem


##-==============================================-##
##     [+] Calculate the fingerprint of RiseupCA.pem
certtool -i < RiseupCA.pem |egrep -A 1 'SHA256 fingerprint'
openssl x509 -sha256 -in RiseupCA.pem -noout -fingerprint


certtool -i < RiseupCA.pem |egrep -A 1 'SHA256 fingerprint'



##-==============================================-##
##     [+] Calculate the fingerprint of Protonmail-com.pem:

openssl x509 -sha256 -in protonmail-com.pem -noout -fingerprint
SHA256 Fingerprint=23:00:B8:54:21:8A:3D:4F:4F:E7:8B:58:9E:ED:FA:BB:16:65:51:89:D8:71:00:85:A5:67:D0:33:AA:60:3B:CC

openssl x509 -sha256 -in mullvad-n.pem -noout -fingerprint


23:00:B8:54:21:8A:3D:4F:4F:E7:8B:58:9E:ED:FA:BB:16:65:51:89:D8:71:00:85:A5:67:D0:33:AA:60:3B:CC
23:00:B8:54:21:8A:3D:4F:4F:E7:8B:58:9E:ED:FA:BB:16:65:51:89:D8:71:00:85:A5:67:D0:33:AA:60:3B:CC



certtool --certificate-info < protonmail-com.pem
certtool --certificate-info < protonmail-com.pem | grep sha256
sha256:2300b854218a3d4f4fe78b589eedfabb16655189d8710085a567d033aa603bcc


certtool --certificate-info < mullvad-n.pem
certtool --certificate-info < mullvad-n.pem | grep sha256


head -n -1 protonmail-com.pem | tail -n +2 | base64 -d | sha256sum


##-====================================-##
##     [+] Print some info about a PKCS#12 file:

openssl pkcs12 -in $File.p12 -info -noout


##-==========================-##
##  [+] Check certificate
##-==========================-##
openssl x509 -in $Certificate.crt -text -noout


##-=========================================-##
##  [+] View The Contents of The CSR File
##-=========================================-##
openssl req -text -in $Certificate.csr 



## Specify a date the file must be newer than:
curl ‐z "Jan 12 2012" http://remote.server.com/remote.html




##-=================================-##
##     [+] Check Site SSL Certificate Dates:

echo | openssl s_client -connect $Site.com:443 2>/dev/null | openssl x509 -dates -noout
echo | openssl s_client -connect mail.protonmail.com:443 2>/dev/null | openssl x509 -dates -noout
notBefore=Oct 25 10:30:50 2019 GMT
notAfter=Oct 25 10:30:50 2021 GMT


echo | openssl s_client -connect $Site.com:443 2>/dev/null | openssl x509 -dates -noout
echo | openssl s_client -connect mullvad.net:443 2>/dev/null | openssl x509 -dates -noout

## ------------------------------------------------------------ ##
##  [+] Testing connection to the remote host
## ------------------------------------------------------------ ##
echo | openssl s_client -connect $Domain:443 -showcerts


## ------------------------------------------------------------------------------------- ##
##  [+] Testing connection to the remote host (with SNI support)
## ------------------------------------------------------------------------------------- ##
echo | openssl s_client -showcerts -servername $Domain -connect $Domain:443


## --------------------------------------------------------------------------------------------- ##
##  [+] Testing connection to the remote host with specific ssl version
## --------------------------------------------------------------------------------------------- ##
openssl s_client -tls1_2 -connect $Domain:443


echo | openssl s_client -connect mullvad.net:443 -showcerts
echo | openssl s_client -showcerts -servername mullvad.net -connect mullvad.net:443
echo | openssl s_client -tls1_2 -connect mullvad.net:443

openssl x509 -noout -issuer -subject -fingerprint -dates
 | openssl x509 -noout -fingerprint -sha1
 | openssl x509 -noout -fingerprint -sha256
 | openssl x509 -noout -issuer_hash
 | openssl x509 -noout -subject
 | openssl x509 -in "${REQUIRED_CA}" -noout -subject

echo | openssl s_client -connect mullvad.net:443 2>/dev/null | openssl x509 -noout -issuer -subject -fingerprint -dates


openssl s_client -servername "$1" -connect "$1":443 | openssl x509 -fingerprint -sha256 -noout

openssl s_client -CApath /etc/ssl/certs -connect mullvad.net:443 -debug


openssl s_client -connect  | openssl x509 -text
##-=============================================-##
##   [+] Connect To Google.com using OpenSSL
##   [+] Examine The x509 Certificate:
##-=============================================-##
echo | openssl s_client -connect www.google.com:443 2>/dev/null | openssl x509 -text



##-=======================================================-##
##   [+] Request Information on the Chain Certificates.
##-=======================================================-##
ocsptool --ask --load-chain $Chain.pem


##-=======================================================-##
##   [+] Ask information on a particular certificate 
##-=======================================================-##
## ------------------------------------------------------- ##
##   [?] using --load-cert and --load-issuer
## ------------------------------------------------------- ##
ocsptool --ask http://ocsp.CAcert.org/ --load-chain $Chain.pem



## Create an OCSP request and write it to a file:
openssl ocsp -issuer issuer.pem -cert c1.pem -cert c2.pem -reqout req.der


## Send a query to an OCSP responder with URL 
## http://ocsp.myhost.com/ 
## save the response to a file, 
## print it out in text form, 
## and verify the response:
openssl ocsp -issuer issuer.pem -cert c1.pem -cert c2.pem -url http://ocsp.myhost.com/ -resp_text -respout resp.der


## Read in an OCSP response and print out text form:
openssl ocsp -respin resp.der -text -noverify


Print information about an OCSP request

ocsptool -i -Q ocsp-request.der



sent to standard input like this:

cat ocsp-request.der | ocsptool --request-info


## OCSP server on port 8888 using a standard ca configuration, 
## and a separate responder certificate. 
## All requests and responses are printed to a file.
openssl ocsp -index demoCA/index.txt -port 8888 -rsigner rcert.pem -CA demoCA/cacert.pem -text -out log.txt


## As above but exit after processing one request:
openssl ocsp -index demoCA/index.txt -port 8888 -rsigner rcert.pem -CA demoCA/cacert.pem -nrequest 1


## Query status information using an internally generated request:
openssl ocsp -index demoCA/index.txt -rsigner rcert.pem -CA demoCA/cacert.pem -issuer demoCA/cacert.pem -serial 1


## Query status information using request read from a file, 
## and write the response to a second file.
openssl ocsp -index demoCA/index.txt -rsigner rcert.pem -CA demoCA/cacert.pem -reqin req.der -respout resp.der


Generate an RSA private key

$ certtool -p --rsa --bits=keysize

Generate a certificate signing request

$ certtool -q --load-privkey private_key --outfile file

Generate a self-signed certificate

$ certtool -s --load-privkey private_key --outfile file



##-===========================================================-##
##   [+] Decode the private key and view its contents:

openssl rsa -text -in yourdomain.key -noout



##-===========================================================-##
##   [+] Extract your public key:

openssl rsa -in yourdomain.key -pubout -out yourdomain_public.key










openssl ts -query -data hash.log -out hash.log.tsq -cert
tsget -h https://freetsa.org/tsr hash.log.tsq
curl -s -H "Content-Type: application/timestamp-query" --data-binary "@hash.log.tsq" https://freetsa.org/tsr > hash.log.tsr
openssl ts -reply -in hash.log.tsr -text



##-=============================================-##
##   [+] FreeTSA
##-=============================================-##
## --------------------------------------------- ##
##   [?] the CA cert is fetched from FreeTSA:
## --------------------------------------------- ##
curl http://freetsa.org/files/cacert.pem > $cacert.pem

##-================================-##
##   [+] Validate The Timestamp:
##-================================-##
openssl ts -verify -in $hash.log.tsr -queryfile $hash.log.tsq -CAfile $cacert.pem


## ----------------------------------- ##
##   [?] Timestamp Query ( tsq ) 
##   [?] Timestamp Reponse ( tsr )
## ----------------------------------- ##







wget https://dl.eff.org/certbot-auto
sudo mv certbot-auto /usr/local/bin/certbot-auto
sudo chown root /usr/local/bin/certbot-auto
sudo chmod 0755 /usr/local/bin/certbot-auto
/usr/local/bin/certbot-auto --help

To check the integrity of the certbot-auto script, run:

wget -N https://dl.eff.org/certbot-auto.asc
gpg2 --keyserver ipv4.pool.sks-keyservers.net --recv-key A2CFB51FA275A7286234E7B24D17C995CD9775F2
gpg2 --trusted-key 4D17C995CD9775F2 --verify certbot-auto.asc /usr/local/bin/certbot-auto


gpg: Signature made Mon 10 Jun 2019 06:24:40 PM EDT
gpg:                using RSA key A2CFB51FA275A7286234E7B24D17C995CD9775F2
gpg: key 4D17C995CD9775F2 marked as ultimately trusted
gpg: checking the trustdb
gpg: marginals needed: 3  completes needed: 1  trust model: pgp
gpg: depth: 0  valid:   1  signed:   0  trust: 0-, 0q, 0n, 0m, 0f, 1u
gpg: next trustdb check due at 2027-11-22
gpg: Good signature from "Let's Encrypt Client Team <letsencrypt-client@eff.org>" [ultimate]



./certbot-auto certonly --manual --preferred-challenges dns -d '*.default.yourdomain.com'



certbot-auto --help all



https://hub.docker.com/u/certbot

sudo docker run -it --rm --name certbot \
            -v "/etc/letsencrypt:/etc/letsencrypt" \
            -v "/var/lib/letsencrypt:/var/lib/letsencrypt" \
            certbot/certbot certonly























https://dl.eff.org/certbot-auto.asc










sslscan --show-certificate 

sslyze --regular 

sslscan --tlsall 

openssl s_client -tls1_2 -cipher 'NULL,EXPORT,LOW,DES' -connect 


nmap --script=ssl-enum-ciphers.nse 




https://www.ssllabs.com/ssltest/analyze.html?d=mullvad.net



dnsenum.pl --enum -f dns.txt --update a -r $domain >> ~/Enumeration/$domain

dnstracer $domain

amass enum -src -ip -d DOMAIN.com


fierce -dns $domain

tcptraceroute -i eth0 $domain

nmap -PN -n -F -T4 -sV -A -oG temp.txt $domain

httprint -h www.$domain -s signatures.txt -P0

list-urls.py http://www.$domain

amap -d $IP $PORT

snmpwalk -c public -v1 $IP
snmpwalk public -v1 192.168.9.201 1 |grep 77.1.2.25 |cut -d” “ -f4

nikto -h $IP -p $PORT

smbclient -L\\ -N -I $IP

enum4linux $IP



dnsenum.pl --enum -f dns.txt --update a -r url
fierce.pl -dns url
lbd.sh url
nmap -PN -n -F -T4 -sV -A -oG temp.txt url
dnsenum.pl --dnsserver 8.8.8.8 --enum -f dns-big.txt --update a -r microsoft.com
nmap –sU –A –PN –n –pU:19,53,123,161 –script=ntp-monlist,dns-recursion,snmp-sysdescr <target>
# Nmap UDP Reflector Scanning and filtering
DNS: nmap -sU -pU:53 --script=dns-recursion -Pn -n -v <IP> | grep -B3 open | egrep -o "([0-9]{1,3}\.){3}[0-9]{1,3}"  > dnslist.txt



Unix TCP stacks reply with a SYN/ACK or a RST/ACK :
get the expected behavior of a RST:
hping -S -F -p 53 -s 53 127.0.0.1









openssl req -newkey rsa:4096 -keyout /etc/openvpn/$ClientVPNKey.pem -out /etc/openvpn/$ClientVPNKey.csr

openssl x509 -CA $cacert.pem -CAkey $cakey.pem -CAcreateserial -days 730 -req -in /etc/openvpn/$ClientVPNKey.csr -out /etc/openvpn/$ClientVPNKey.pem


openssl req -newkey rsa:4096 -keyout /etc/openvpn/$ClientVPNKey.pem -out /etc/openvpn/$ClientVPNKey.csr
##  Generating a RSA private key
##  ....++++
##  ...........................................................++++
##  writing new private key to '/etc/openvpn/ClientVPNKey.pem'


##-==============================================-##
##     [+] Convert Certificates To Encrypted .p12 Format:
##-==============================================-##
## ------------------------------------------------------------------------------- ##
##   [?] Some software will only read VPN certificates 
##         that are stored in a password-encrypted .p12 file.
## ------------------------------------------------------------------------------- ##
openssl pkcs12 -export -inkey $Key.key -in $Cert.crt -certfile $CA.crt -out $Cert.p12





openvpn --genkey --secret openvpn.key

scp openvpn.key 192.168.10.129:/root/





##  Create an archive file and encrypt its contents with **openssl**. This can be done with the following command:
tar cz folder_to_encrypt | openssl enc -aes-256-cbc -e > out.tar.gz.enc

Decryption can be done as follows:
cat out.tar.gz.enc  | openssl enc -aes-256-cbc -d



gpg --verbose --symmetric --cipher-algo aes256 --digest-algo sha512 --cert-digest-algo sha512 --s2k-mode 3 --s2k-count 65011712 --s2k-cipher-algo AES256 --s2k-digest-algo SHA512 



Enabling A Kill Switch Using IPTables:

sudo iptables -P OUTPUT DROP
sudo iptables -A OUTPUT -o tun+ -j ACCEPT
sudo iptables -A INPUT -i lo -j ACCEPT
sudo iptables -A OUTPUT -o lo -j ACCEPT
sudo iptables -A OUTPUT -d 255.255.255.255 -j ACCEPT
sudo iptables -A INPUT -s 255.255.255.255 -j ACCEPT
sudo iptables -A OUTPUT -o eth+ -p udp -m multiport --dports 53,1300:1302,1194:1197 -d 141.98.255.0/24,193.138.218.0/24,45.83.220.0/24,185.213.152.0/24,185.213.154.0/24,185.65.135.0/24,185.65.134.0/24 -j ACCEPT
sudo iptables -A OUTPUT -o eth+ -p tcp -m multiport --dports 53,443 -d 141.98.255.0/24,193.138.218.0/24,45.83.220.0/24,185.213.152.0/24,185.213.154.0/24,185.65.135.0/24,185.65.134.0/24 -j ACCEPT
sudo iptables -A OUTPUT -o eth+ ! -d 193.138.218.74 -p tcp --dport 53 -j DROP
sudo ip6tables -P OUTPUT DROP
sudo ip6tables -A OUTPUT -o tun+ -j ACCEPT



sudo systemctl enable openvpn*.service && sudo systemctl start openvpn*.service




Show account info
mullvad account get



mullvad account set 1234123412341234




List server locations
displays a list of available countries and cities.

mullvad relay list


Select a location
mullvad relay set location se mma


Select a specific server
mullvad relay set location se mma se-mma-001


Connect to the location that you selected.

mullvad connect
Disconnect

mullvad disconnect

Force an update to the serverlist

mullvad relay update
Check your connection status

mullvad status


Auto-connect Mullvad on start-up
and connect when you boot up your computer
mullvad auto-connect set on


turn Auto-connect off
mullvad auto-connect set off







check whether or not you are connected to Mullvad, you can run 
curl https://am.i.mullvad.net/connected


http://check2ip.com/
http://dnsleak.com/
http://www.dnsleaktest.com/
https://dnsleaktest.com/

curl https://check.torproject.org
curl -s https://check.torproject.org/ | cat | grep -m 1 Congratulations | xargs

torify openssl s_client -connect $ONION:$PORT -showcerts 2>/dev/null |  openssl x509 -in /dev/stdin -noout -fingerprint |  awk -F'=' '{print $2}' |  tr -d ':'



curl --proxy "socks5h://localhost:9050" --tlsv1.2 --compressed --user-agent "Mozilla/5.0 (Windows NT 6.1; rv:45.0) Gecko/20100101 Firefox/45.0" -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' -H 'DNT: 1' $URL



curl -v -x socks5://proxyuser:password@yourserverip:443 $URL


# construct telegram links:
# https://t.me/socks?server=yourserverip&port=443&user=proxyuser&pass=password
# tg://socks?server=yourserverip&port=443&user=proxyuser&pass=password



journalctl -f | grep vpn
tail -f /var/log/syslog | grep vpn
egrep -w 'warning|error|critical' /var/log/messages

journalctl -u openvpn-client@
journalctl -f | grep vpn
tail -f /var/log/syslog | grep vp
 

netstat ‐anp ‐‐udp ‐‐tcp | grep LISTEN

ethtool -S eth0


sudo wpa_cli status
sudo wpa_cli interface_list
sudo netstat -s | egrep -i 'loss|retran'

iwlist 
iwlist wlan0
sudo iwlist wlan0 scan
sudo iwlist wlan0 scan | grep ESSID
sudo ip link set wlan0 down
sudo ip link set wlan0 up
sudo iw reg get
sudo iw reg set CH
sudo nmcli radio wifi on
nmcli dev show wlan0
nmcli device wifi
nmcli device wifi rescan
sudo iwlist wlan0 scan




## process all of the pcap files in the current directory
tcpflow -o out -a -l *.pcap

## To monitor all TCP ports, use a more general expression:
urlsnarf -i eth1 tcp



### PCAP statistical data

capinfos file.pcap
tcpslice -r file.pcap
tcpdstat file.pcap




* Generate a target list from supplied IP netmask
Fping -a -g 192.168.7.0/24



### Network Forensics - File Extraction

tcpdump -nni eth0 -w image.pcap port 80 &
jobs
kill %1
tcpflow -r image.pcap
tcpxtract -f file.pcap -o xtract/
tcpstat -i eth0 -o "Time: %S\tpps: %p\tpacket count: %n\tnet load: %l\tBps: %B\n"



curvetun


## nolocal.net is a client filter that disable access to local network.
firejail --netfilter=/etc/firejail/nolocal.net --net=eth0 firefox

firejail --trace wget -q www.debian.org
firejail --tracelog firefox

firejail --overlay-tmpfs 








# enable user namespaces (https://superuser.com/questions/1094597/enable-user-namespaces-in-debian-kernel)
echo 'kernel.unprivileged_userns_clone=1' > /etc/sysctl.d/00-local-userns.conf
sudo sysctl kernel.unprivileged_userns_clone=1












* View 500 results of Moes.com via Google
Theharvester -d moes.com -l 500 -b google
* View default results of Chipotle.com via Linkedin
theharvester -d chipotle.com -b linkedin

* Extract public pdf, doc, and ppt files from target.com (limited to 200 searches and 5 downloads), save the downloads to "/root/Desktop/metagoofil/" and output results to "/root/Desktop/metagoofil/result.html"
metagoofil -d target.com -t pdf,doc,ppt -l 200 -n 5 -o /root/Desktop/metagoofil/ -f /root/Desktop/metagoofil/result.html
* Scan for documents from a domain (-d kali.org) that are PDF files (-t pdf), searching 100 results (-l 100), download 25 files (-n 25), saving the downloads to a directory (-o kalipdf), and saving the output to a file (-f kalipdf.html)
metagoofil -d kali.org -t pdf -l 100 -n 25 -o kalipdf -f kalipdf.html


* Target a domain
dnsrecon -d chipotle.com
* Search for Zone Transfers on domain
Dnsrecon -d chipotle.com -t axfr
* Google enumeration (servers)
dnsrecon -d chipotle.com -g



##   [+]  Update IP filter for qBittorrent 

wget -O - http://list.iblocklist.com/\?list\=ydxerpxkpcfqjaybcssw\&fileformat\=p2p\&archiveformat\=gz | gunzip > ~/ipfilter.p2p

https://www.commandlinefu.com/commands/view/14879/update-ip-filter-for-qbittorrent




##-==============================================-##
##   [+] Xe1phix-qBittorrent-IPfilter-Fetch.sh
##-==============================================-##
## ---------------------------------------------- ##
##   [?] Update IP filter for qBittorrent 
## ---------------------------------------------- ##
wget -O - http://list.iblocklist.com/\?list\=ydxerpxkpcfqjaybcssw\&fileformat\=p2p\&archiveformat\=gz | gunzip > ~/ipfilter.p2p




https://mullvad.net/en/account/#/openvpn-config/



##  Run our configuration script
curl -LO https://mullvad.net/media/files/mullvad-wg.sh && chmod +x ./mullvad-wg.sh && ./mullvad-wg.sh


##  set the correct permissions so only root can read them:
sudo chown root:root -R /etc/wireguard && sudo chmod 600 -R /etc/wireguard

##  start WireGuard automatically on boot
systemctl enable wg-quick@mullvad-se4

##  Turn on WireGuard
wg-quick up mullvad-se4


##  Turn off WireGuard
wg-quick down mullvad-se4









/sbin/iptables $ACTION OUTPUT -d $trusted_ip -m owner --uid-owner $EUID -j ACCEPT


firejail --netns=protected firefox






enable a kill switch?
Add the following lines under the [Interface] section 
of the WireGuard configuration files found in 
/etc/wireguard/

PostUp  =  iptables -I OUTPUT ! -o %i -m mark ! --mark $(wg show %i fwmark) -m addrtype ! --dst-type LOCAL -j REJECT && ip6tables -I OUTPUT ! -o %i -m mark ! --mark $(wg show %i fwmark) -m addrtype ! --dst-type LOCAL -j REJECT
PreDown = iptables -D OUTPUT ! -o %i -m mark ! --mark $(wg show  %i fwmark) -m addrtype ! --dst-type LOCAL -j REJECT && ip6tables -D OUTPUT ! -o %i -m mark ! --mark $(wg show  %i fwmark) -m addrtype ! --dst-type LOCAL -j REJECT

https://mullvad.net/en/help/wireguard-and-mullvad-vpn/


iptables -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -I FORWARD -s 10.8.0.0/24 -j ACCEPT
iptables -I INPUT -p udp --dport 1194 -j ACCEPT
iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -j SNAT --to 139.59.1.155



/sbin/iptables -t nat -A BYPASS -p udp --dport 1194 -d $ovpn_server1 -j ACCEPT
/sbin/iptables -t nat -A BYPASS -p udp --dport 1194 -d $ovpn_server2 -j ACCEPT



iptables-save > /root/iptables.save
cat /root/iptables.save | iptables-restore


iptables-persistent iptables-persistent/autosave_v4 boolean true
iptables-persistent iptables-persistent/autosave_v6 boolean true
iptables-save > /etc/iptables/IPTable-RulesAppended.v4 


systemctl start firewalld
systemctl enable firewalld

firewall-cmd --add-service openvpn
firewall-cmd --permanent --add-service openvpn
firewall-cmd --permanent --add-service=dns
firewall-cmd --add-masquerade
firewall-cmd --permanent --add-masquerade
firewall-cmd --permanent --zone=public --add-port=443/tcp
firewall-cmd --permanent --zone=public --add-port=443/udp

firewall-cmd --get-icmptypes && firewall-cmd --get-services && firewall-cmd --get-zones && firewall-cmd --list-all && firewall-cmd --list-lockdown-whitelist-users && firewall-cmd --list-services && firewall-cmd --list-source-ports && firewall-cmd --list-icmp-blocks && firewall-cmd --list-rich-rules && firewall-cmd --state && firewall-cmd --get-helpers && firewall-cmd --get-log-denied && firewall-cmd --get-short && firewall-cmd --query-icmp-block-inversion && firewall-cmd --get-ipset-types && firewall-cmd --list-lockdown-whitelist-users && firewall-cmd --list-lockdown-whitelist-commands && firewall-cmd --list-lockdown-whitelist-uids && firewall-cmd --list-ports && firewall-cmd --list-protocols && firewall-cmd --list-interfaces && firewall-cmd --get-active-zones && firewall-cmd --list-source-ports && firewall-cmd --list-sources



echo "##-=============================================-##"
echo "    [+] A tunnel with full TLS-based security      "
echo "##-=============================================-##"


echo "##-==============-##"
echo "    [+] On Bob:     "
echo "##-==============-##"
openvpn  --remote  alice.example.com  --dev  tun1  --ifconfig  10.4.0.1 10.4.0.2 --tls-client --ca ca.crt --cert client.crt --key client.key --reneg-sec 60 --verb 5


echo "##-================-##"
echo "    [+] On Alice:     "
echo "##-================-##"
openvpn --remote bob.example.com --dev tun1 --ifconfig 10.4.0.2 10.4.0.1 --tls-server --dh dh1024.pem --ca ca.crt  --cert  server.crt  --key server.key --reneg-sec 60 --verb 5







echo "##-=============================================-##"
echo "      [+] A tunnel with static-key security      "
echo "##-=============================================-##"


echo "##-=============================-##"
echo "    [+] Generate A Static Key:     "
echo "##-=============================-##"
openvpn --genkey --secret key


echo "##-==============-##"
echo "    [+] On Bob:     "
echo "##-==============-##"
openvpn --remote alice.example.com --dev tun1 --ifconfig 10.4.0.1 10.4.0.2 --verb 5 --secret key


echo "##-================-##"
echo "    [+] On Alice:     "
echo "##-================-##"
openvpn --remote bob.example.com --dev tun1 --ifconfig 10.4.0.2 10.4.0.1 --verb 5 --secret key



## Generate a public and private certificate on the client

wg genkey | tee client_private_key | wg pubkey > client_public_key







Generate a private and public key pair for the WireGuard server:
wg genkey | tee privatekey | wg pubkey > publickey


Create the file /etc/wireguard/wg0.conf 

enter your server’s private key in the PrivateKey field, and its IP addresses in the Address field.

[Interface]
PrivateKey = <Private Key>
Address = 10.0.0.1/24, fd86:ea04:1115::1/64
ListenPort = 51820
PostUp = iptables -A FORWARD -i wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE; ip6tables -A FORWARD -i wg0 -j ACCEPT; ip6tables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE; ip6tables -D FORWARD -i wg0 -j ACCEPT; ip6tables -t nat -D POSTROUTING -o eth0 -j MASQUERADE
SaveConfig = true





    Address defines the private IPv4 and IPv6 addresses for the WireGuard server. Each peer in the VPN network should have a unique value for this field.

    ListenPort specifies which port WireGuard will use for incoming connections.

    PostUp and PostDown defines steps to be run after the interface is turned on or off, respectively. In this case, iptables is used to set Linux IP masquerade rules to allow all the clients to share the server’s IPv4 and IPv6 address. The rules will then be cleared once the tunnel is down.

    SaveConfig tells the configuration file to automatically update whenever a new peer is added while the service is running.


Allow SSH connections and WireGuard’s VPN port:

Start Wireguard:

wg-quick up wg0



Enable the Wireguard service to automatically restart on boot:
sudo systemctl enable wg-quick@wg0

Check if the VPN tunnel is running with the following two commands:

sudo wg show
ifconfig wg0


Generate a key pair for the client if you have not already:

umask 077
wg genkey | tee privatekey | wg pubkey > publickey



The main difference between the client and the server’s configuration file, wg0.conf, is it must contain its own IP addresses and does not contain the ListenPort, PostUP, PostDown, and SaveConfig values.

/etc/wireguard/wg0.conf


    [Interface]
    PrivateKey = <Output of privatekey file that contains your private key>
    Address = 10.0.0.2/24, fd86:ea04:1115::5/64



[Peer]
PublicKey = <Server Public key>
Endpoint = <Server Public IP>:51820
AllowedIPs = 10.0.0.2/24, fd86:ea04:1115::5/64



Method 1

    The first method is to directly edit the client’s wg0.conf file with the server’s public key, public IP address, and port:

/etc/wireguard/wg0.conf 


Enable the wg service on both the client and server:

wg-quick up wg0
systemctl enable wg-quick@wg0




Method 2

Run the following command from the server. Replace the example IP addresses with those of the client:

sudo wg set wg0 peer <Client Public Key> endpoint <Client IP address>:51820 allowed-ips 203.0.113.12/24,fd86:ea04:1115::5/64


wg-quick save wg0







Step 4. Convert the DD image to a the qcow2 disk format with the 'qemu-img' utility.

qemu-img convert -O qcow2 /storage/location/snapshot.image /storage/location/snapshot.qcow2





ssh -f -N -D 1234 mullvad@68.235.43.114






└──╼ $nslookup us-chi-br-001.mullvad.net
Server:		192.168.1.1
Address:	192.168.1.1#53

Non-authoritative answer:
Name:	us-chi-br-001.mullvad.net
Address: 68.235.43.114







