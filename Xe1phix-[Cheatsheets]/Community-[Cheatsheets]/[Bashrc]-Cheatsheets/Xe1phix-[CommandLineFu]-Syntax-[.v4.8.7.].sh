#!/bin/sh
##-=========================================-##
##    [+] Xe1phix-[CommandLineFu]-Syntax-[.v*.*.*.].sh
##-=========================================-##


##-================================================-##
##  [+] Scan entire Git repos for dangerous Amazon Web Service IDs 
##-================================================-##
git ls-tree --full-tree -r --name-only HEAD | xargs egrep -w '[A-Z0-9]{20}'

##-================================================-##
##  [+] Scan entire Git repo for dangerous Amazon Web Service IDs
##-================================================-##
git grep -Ew '[A-Z0-9]{20}'


##-==========================-##
##  [+] Print all git repos from a user
##-==========================-##
curl -s https://api.github.com/users/<username>/repos?per_page=1000 |grep git_url |awk '{print $2}'| sed 's/"\(.*\)",/\1/'


##-========================================-##
##  [+] Print all git repos from a user (only curl and grep)
##-========================================-##
curl -s https://api.github.com/users/<username>/repos?per_page=1000 | grep -oP '(?<="git_url": ").*(?="\,)'


##-===============================-##
##  [+] Clone all repos from a user with lynx
##-===============================-##
## ------------------------------------------------------ ##
## https://wuseman.github.io/wcloner/
## ------------------------------------------------------ ##
lynx -dump -nonumbers https://github.com/USER?tab=repositories|grep '/USER/'|cut -d'/' -f1,2,3,4,5|uniq|xargs -L1 git clone


##-==========================-##
##  [+] Print all git repos from a user
##-==========================-##
curl -s "https://api.github.com/users/<username>/repos?per_page=1000" | jq '.[].git_url'



##-============================================-##
##  [+] Scan whole internet and specific port in humanistic time
##-============================================-##
## ---------------------------------------------------------------------------- ##
##  [?] build instructions:
## apt-get install git gcc make libpcap-dev 
## git clone https://github.com/robertdavidgraham/masscan 
## cd masscan 
## make install -pDm755 bin/masscan /usr/bin/masscan
## ---------------------------------------------------------------------------- ##
masscan 0.0.0.0/0 -p8080,8081,8082 --max-rate 100000 --banners --output-format grepable --output-filename /tmp/scan.xt --exclude 255.255.255.255





##-===========================-##
##  [+] Clone all github repos of a user
##-===========================-##
## ---------------------------------------------------------------------- ##
##  [?] Clones all repositories of given ${USERNAME}
## ---------------------------------------------------------------------- ##
curl -s "https://api.github.com/users/${USERNAME}/repos" | ruby -rubygems -e 'require "json"; JSON.load(STDIN.read).each {|repo| %x[git clone #{repo["ssh_url"]} ]}'





##-================================-##
##                        [+] sshuttle VPN: 
##-================================-##
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



## Based on:
## https://tor.stackexchange.com/questions/19221/how-to-setup-client-authorization-for-v3-onion-services


## Using OpenSSL 1.1 or later, generate a new X25519 private key.
## This will produce a PEM-encoded private key file, private-key.pem
$tor_user_sudo openssl genpkey -algorithm x25519 -out "$private_key_file"


## Using the newly generated private key file, generate a corresponding public key file, public-key.pem:
$tor_user_sudo openssl pkey -in "$private_key_file" -pubout -outform PEM -out "$public_key_file"


## Now that you have both the private and public parts of your keypair,
## first convert the private part from its PEM-encoded format into a Base32
## encoded string for use in your Tor client’s .auth_private file:
cat "$private_key_file" | \
   grep -v " PRIVATE KEY" | \
   basez --base64pem --decode | \
   tail --bytes 32 | \
   basez --base32 | \
   tr -d '=' | \
   $tor_user_sudo tee "$base_32_private" >/dev/null


## Reload Tor to so Tor will load client_authorization_full_path.

systemctl reload tor@default
systemctl --no-pager reload tor@default
systemctl --no-pager status tor@default


"INFO: Setting capabilities to run wireshark with user privileges."
setcap cap_net_raw,cap_net_admin=eip /usr/bin/dumpcap

true "NOTE: Whonix leaktest - Starting tshark as user..."
sudo --non-interactive -u user tshark -i eth0 -f "ip and src host 10.0.2.15 and not (port 80 or port 443 or port 9001 or port 9030 or ssh)"





if [ ! -e /etc/apt/sources.list.d/torproject.list ]; then
   echo "INFO: /etc/apt/sources.list.d/torproject.list does not exist."
else


grep -i "ExecStart=" /lib/systemd/system/tor@default.service | sed s/ExecStart=//g







Convert the hex string "444f53206d6f6465" to binary:
```bash
$ echo 444f53206d6f6465 | xxd -r -p



Print the length of each line of a file (/etc/passwd in this case), followed by the line itself:

```bash
cat $File | awk '{print length, $0;}'
cat $File | awk '{ print nlines }'
gawk '{ print  nlines }'

gawk -F: '{ print $1 }' $File

whois $j | egrep -w 'OrgName:|City:|Country:|OriginAS:|NetRange:'
ip=$(host $i | grep 'has address' | awk {'print $4'})


Print the 2nd field from a file using the string 'Mozilla/' as a delimiter:
cat /var/log/apache2/access.log | awk -F "Mozilla/" '{print $2}'



msfconsole --quiet -x "db_connect ${USER}@msf"

##-=======================================-##
##  [+] Simple alphabetic sort (may include duplicates)
##-=======================================-##
strings /pcaps/$File.pcap | grep -i user-agent | sort


##-====================-##
##  [+] Sort and unique lines:
##-====================-##
## ---------------------------------------------------------------------- ##
##  [?] The two following sets of commands are equivalent:
## ---------------------------------------------------------------------- ##
strings /pcaps/$File.pcap | grep -i user-agent | sort -u
strings /pcaps/$File.pcap | grep -i user-agent | sort | uniq


##-===================================-##
##  [+] Get a numeric count of each unique entry:
##-===================================-##
strings /pcaps/$File.pcap | grep -i user-agent | sort | uniq -c


##-====================================-##
##  [+] Get a numeric count of each unique entry, 
##        perform a numeric sort of that count:
##-====================================-##
strings /pcaps/$File.pcap | grep -i user-agent | sort | uniq -c | sort -n


##-=====================================-##
##  [+] Print the length of each unique line 
##        followed by the line itself, 
##        perform a reverse numeric sort of that count:
##-=====================================-##
strings /pcaps/$File.pcap | grep -i user-agent | sort -u | awk '{print length, $0}'| sort -rn










Find errors and packet loss on network cards

A grep against ethtool to look for common errors and packet loss statistics which network drivers report in their private data, which is queried with ethool -S. This is the current grep used in xsos (https://github.com/ryran/xsos), which I originally contributed and has been improved by the community over time. Show Sample Output

0
ethtool -S eth0 | egrep "(drop|disc|err|fifo|buf|fail|miss|OOB|fcs|full|frags|hdr|tso).*: [^0]"





Download all files from a Gist without Git

https://twitter.com/westonruter/status/501855721172922369

0
curl -L https://gist.github.com/westonruter/ea038141e46e017d280b/download | tar -xvz --strip-components=1


Download all files from a Github gist individually

Downloads each file from a github gist individually. Requires jq ( https://stedolan.github.io/jq/ ).

0
curl -sS --remote-name-all $(curl -sS https://api.github.com/gists/997ccc3690ccd3ac5196211aff59d989 | jq -r '.files[].raw_url')




git clone all user repos


0
curl -s https://api.github.com/users/tuxcanfly/repos | jq -r 'map(select(.fork == false)) | map(.url) | map(sub("https://api.github.com/repos/"; "git clone git@github.com:")) | @sh' | xargs -n1 sh -c]




Clone all remote branches of a specific GitHub repository

Show Sample Output

-1
git branch -a | grep "remotes/origin" | grep -v master | awk -F / '{print $3}' | xargs -I % git clone -b % git://github.com/jamesotron/DevWorld-2010-Cocoa-Workshop %




Check the current price of Bitcoin (jq version, defines a function)

The only pre-requisite is jq (and curl, obviously). The other version used grep, but jq is much more suited to JSON parsing than that. Show Sample Output

-1
btc() { echo "1 BTC = $(curl -s https://api.coindesk.com/v1/bpi/currentprice/$1.json | jq .bpi.\"$1\".rate | tr -d \"\"\") $1"; }





Download all recently uploaded pastes on pastebin.com


2
elinks -dump https://pastebin.com/archive|grep https|cut -c 7-|sed 's/com/com\/raw/g'|awk 'length($0)>32 && length($0)<35'|grep -v 'messages\|settings\|languages\|archive\|facebook\|scraping'|xargs wget
wuziduzi · 2019-05-13 10:56:11 0





nmap scan hosts for IP, MAC Address and device Vendor/Manufacturer

In the field, I needed to script a process to scan a specific vendor devices in the network. With the help of nmap, I got all the devices of that particular vendor, and started a scripted netcat session to download configuration files from a tftp server. This is the nmap loop (part of the script). You can however, add another pipe with grep to filter the vendor/manufacturer devices only. If want to check the whole script, check in http://pastebin.com/ju7h4Xf4 Show Sample Output

0
nmap -sP 10.0.0.0/8 | grep -v "Host" | tail -n +3 | tr '\n' ' ' | sed 's|Nmap|\nNmap|g' | grep "MAC Address" | cut -d " " -f5,8-15
jaimerosario · 2014-12-26 18:31:53 0





bulk dl files based on a pattern

-O switch creates local filename same as remote curl [][] -o #1#2 makes local files unique inserting sequence values into #x placeholders sequences can be alpha or numeric e.g [a-z] [1-25]

4
curl -O http://hosted.met-art.com/generated_gallery/full/061606AnnaUkrainePasha/met-art-free-sample-00[00-19].jpg






Bulk install

I used this to mass install a lot of perl stuff. Threw it together because I was feeling *especially* lazy. The 'perl' and the 'module' can be replaced with whatever you like.

-2
apt-cache search perl | grep module | awk '{print $1;}' | xargs sudo apt-get install -y




"Clone" a list of installed packages from one Debian/Ubuntu Server to another


12
apt-get install `ssh root@host_you_want_to_clone "dpkg -l | grep ii" | awk '{print $2}'`
TuxOtaku · 2011-05-10 13:33:51 3




clone a hard drive to a remote directory via ssh tunnel, and compressing the image


1
# dd if=/dev/sda | gzip -c | ssh user@ip 'dd of=/mnt/backups/sda.dd'
coolman · 2009-07-06 19:05:55 2





Clone or rescue a block device

If you use the logfile feature of ddrescue, the data is rescued very efficiently (only the needed blocks are read). Also you can interrupt the rescue at any time and resume it later at the same point. http://www.gnu.org/software/ddrescue/ddrescue.html

1
ddrescue -v /dev/sda /dev/sdb logfile.log




Screencast of your PC Display with mp4 output

Since ffmpeg on Ubuntu is deprecated, now there is avconv. Please note that the screen area here is set with a predefined format "-s wxga" that is corresponding to "-s 1366x768") There is also the option to add a title in the metadata of the resulting video.

2
avconv -v warning -f alsa -i default -f x11grab -r 15 -s wxga -i :0.0 -vcodec libx264 -preset ultrafast -threads auto -y -metadata title="Title here" ~/Video/AVCONV_REG.mp4




Screencast of your PC Display with webm output

Since ffmpeg on Ubuntu is deprecated, now there is avconv. Please note that the screen area here is set with a predefined format "-s wxga" that is corresponding to "-s 1366x768") There is also the option to add a title in the metadata of the resulting video.

0
avconv -v warning -f alsa -ac 2 -i default -f x11grab -r 15 -s wxga -i :0.0 -acodec libvorbis -ab 320k -vcodec libvpx -qmax 2 -qmin 1 -threads auto -y -metadata title="Title here" ~/Video/AVCONV_REG.webm






Convert SWF to video

This will dump a raw BGRA pixel stream and WAV which must then be converted to video: ffmpeg -f rawvideo -c:v rawvideo -s 1280x720 -r 12 -pix_fmt bgra -i "${i%.*}".bgra -c:v libx264 -preset veryslow -qp 0 -movflags +faststart -i "${i%.*}".wav -c:a libfdk_aac -b:a 384k "${i%.*}".mp4 ; rm "${i%.*}".bgra "${i%.*}".wav Our example generates an x264/720p/12fps/AAC best-quality MP4. To get dump-gnash, first install the build-dependencies for gnash (this step is OS-specific). Then: git clone http://git.savannah.gnu.org/r/gnash.git ; cd gnash ; ./autogen.sh ; ./configure --enable-renderer=agg --enable-gui=dump --disable-menus --enable-media=ffmpeg --disable-jemalloc ; make

0
i=in.swf; dump-gnash -1 -j 1280 -k 720 -D "${i%.*}".bgra@12 -A "${i%.*}".wav "${i}"




convert vdi to vmdk (virtualbox v3.2 hard disk conversion to vmware hard disk format)
vboxmanage clonehd --format VMDK <source image|uuid> <destination image>




Manipulate the metadata and edit the create time (This will change date to 1986:11:05 12:00 - Date: 1986 5th November, Time: 12.00) and then it will set modify date to the same as alldate.


3
exiftool "-AllDates=1986:11:05 12:00:00" a.jpg; exiftool "-DateTimeOriginal>FileModifyDate" a.jpg



Manipulate the metadata when the photo was taken, this will shift with +15hours + 30min


2
exiftool "-DateTimeOriginal+=0:0:0 15:30:0" a.jpg



Edit a PDF's metadata using exiftool

Edit the pdf file foo.pdf's metadata. -overwrite_original overwrites the original file (w/o it exiftool creates a new file)

1
exiftool -Title="This is the Title" -Author="Happy Man" -Subject="PDF Metadata" foo.pdf -overwrite_original



Use CreationDate metadata on .mov files to rename and modify the created/modify file dates on Mac


1
exiftool '-MDItemFSCreationDate<CreationDate' '-FileModifyDate<CreationDate' '-filename<CreationDate' -d %Y-%m-%d_%H-%M-%S%%+c.%%le . -ext mov




Fix time-stamped filenames of JPEG images according to the EXIF date the photo was taken

For each *.jpg or *.JPG file in the current directory, extract the date the photo was taken from its EXIF metadata. Then replace the date stamp, which is assumed to exist in the filename, by the date the photo was taken. A trick from https://unix.stackexchange.com/a/9256 is used to split the date into its components. Show Sample Output

0
(IFS=': '; for i in *.(#i)jpg; do set $(exiv2 -K 'Exif.Image.DateTime' -Pv $i 2> /dev/null); mv -v $i "$1-$2-$3${i#[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]}"; done)





Extract thumbnails from EXIF metadata

It will generate a new file ending with "_ThumbnailImage.jpg" which is the embedded thumbnail inside the JPG for example.

0
exiftool -a -b -W %d%f_%t%-c.%s -preview:all YourFileOrDirectory




set timestamp in exif of a image


0
exiv2 -M"set Exif.Photo.DateTimeOriginal `date "+%Y:%m:%d %H:%M:%S"`" filename.jpg







Find corrupted jpeg image files

This checks jpeg data and metadata, should be grepped as needed, maybe a -B1 Warning for the first, and a -E "WARNING|ERROR" for the second part....

0
find . -iname '*jpg' -print0 | xargs -0 exiftool -warning; find . -iname '*jpg' -print0 | xargs -0 jpeginfo -c



 List latest 5 modified files recursively 
ls -laht `find / -name "*.*" -type f -newermt "2016-04-05" ! -newermt "2016-04-10"`|head -5



Rotate a video file by 90 degrees CW

Change video orientation in metadata only

1
ffmpeg -i in.mov -c copy -metadata:s:v:0 rotate=90 out.mov







Write a listing of all directories and files on the computer to a compressed file.

This command is meant to be used to make a lightweight backup, for when you want to know which files might be missing or changed, but you don't care about their contents (because you have some way to recover them). Explanation of parts: "ls -RFal /" lists all files in and below the root directory, along with their permissions and some other metadata. I think sudo is necessary to allow ls to read the metadata of certain files. "| gzip" compresses the result, from 177 MB to 16 MB in my case. "> all_files_list.txt.gz" saves the result to a file in the current directory called all_files_list.txt.gz. This name can be changed, of course. Show Sample Output

sudo ls -RFal / | gzip > all_files_list.txt.gz
































Block all traffic from an Autonomous System (AS) Network (e.g. Facebook)

Retrieves AS route prefixes for IPv4 and IPv6, aggregates the routes to the minimal set, and adds netfilter rules to reject them. Relies on two helpers: IPv4 - "aggregate" by Joe Abley (package name 'aggregate'), IPv6 - "aggregate6" by Job Snijders ( https://github.com/job/aggregate6 ) Show Sample Output

0
ASN=32934; for IP in 4 6; do whois -h riswhois.ripe.net \!${IP/4/g}as${ASN} | sed -n '2 p' | tr \ \\n | aggregate${IP/4/} | while read NET; do ip${IP/4/}tables -I INPUT -S ${NET} -j REJECT; done; done





Get/List firefox bookmarks by tag from json backup

# Usage: ftagmarks TAG BOOKMARKS.JSON ftagmarks Bash ~/.mozilla/firefox/*.default/bookmarkbackups/bookmarks-*.json Tag can be partial matching, e.g. input 'Bas' or 'ash' will match 'Bash' tag. # Exact tag matching: ftagmark(){ jq -r --arg t "$1" '.children[] as $i|if $i.root == "tagsFolder" then ([$i.children[] as $j|{title: ($j.title), urls: [$j.children[].uri]}]) else empty end|.[] as $k|if $k.title == $t then $k.urls else empty end|.[]?' "$2"; } Usage: ftagmark TAG BOOKMARKS.JSON # List all tags: ftagmarkl(){ jq -r '.children[] as $i | if $i.root == "tagsFolder" then $i.children[].title else empty end' "$1"; } Usage: ftagmarkl BOOKMARKS.JSON # Requires: `jq` - must have CLI JSON processor http://stedolan.github.io/jq Show Sample Output

0
ftagmarks(){ jq -r --arg t "$1" '.children[] as $i|if $i.root == "tagsFolder" then ([$i.children[] as $j|{title: ($j.title), urls: [$j.children[].uri]}]) else empty end|.[] as $k|if ($k.title|contains($t)) then $k.urls else empty end|.[]?' "$2"; }
qwertyroot · 2016-12-24 15:12:04 0




echoinfo "Setting up auto-login for user $SUDO_USER"
        sed -i s/#\ autologin=dgod/autologin=$SUDO_USER/ /etc/lxdm/lxdm.conf >> $LOGFILE 2>&1
        sed -i s/^disable=0$/disable=1/ /etc/lxdm/lxdm.conf >> $LOGFILE 2>&1




  if [ "x$(dmidecode -s system-product-name | grep VMware)" != "x" ]; then


set -o noclobber >> $HOME/.bashrc
echo "set -o noclobber" | tee -a $HOME/.bashrc >> 

echoinfo "Configuring packet capture capabilities for non-root users"
    setcap 'CAP_NET_RAW+eip CAP_NET_ADMIN+eip' /usr/bin/dumpcap

echoinfo "Configuring sudo"
  if [ "x$(grep '$SUDO_USER' /etc/sudoers)" = "x" ]; then
    echo "$SUDO_USER ALL=NOPASSWD: ALL" | tee -a /etc/sudoers >> $LOGFILE 2>&1
  fi
  sed -i -e '/secure_path=/ s/^#*/#/' /etc/sudoers >> $LOGFILE 2>&1


if [ ! -e /var/www ]; then
    mkdir -p /var/www >> $LOGFILE 2>&1
    chown -R www-data:www-data /var/www >> $LOGFILE 2>&1
    chmod a+w /var/www >> $LOGFILE 2>&1



cp -f /usr/share/remnux/curl.conf $HOME/.curlrc
cp -f /usr/share/remnux/wget.conf $HOME/.wgetrc

# Set up LXTerminal options
if [ -e /usr/share/remnux/lxterminal.conf ]; then
    if [ ! -e $HOME/.config/lxterminal/lxterminal.conf ]; then
        mkdir -p $HOME/.config/lxterminal
        cp /usr/share/remnux/lxterminal.conf $HOME/.config/lxterminal
    fi
fi



    if [ -f /etc/pam.d/lxdm ]; then
      if [ "x$(egrep '^session required pam_systemd\.so$' /etc/pam.d/lxdm)" = "x" ]; then
        echo "session required pam_systemd.so" >> /etc/pam.d/lxdm
      fi
    fi


  echoinfo "Setting permissions for $SUDO_USER"  
  chown -f -R $SUDO_USER:$SUDO_USER /home/$SUDO_USER

Convert a CRL file from PEM to DER:

        openssl crl -in crl.pem -outform DER -out crl.der

       Output the text form of a DER encoded certificate:

        openssl crl -in crl.der -inform DER -text -noout

x509 -hash



dump_unknown
dump_der
dump_all
openssl x509 -addtrust arg clientAuth
openssl x509 -addtrust arg 
openssl x509 -addtrust serverAuth
openssl x509 -addtrust anyExtendedKeyUsage

openssl x509 -addtrust emailProtection
-checkhost val        Check certificate matches host
 -checkemail val       Check certificate matches email
 -checkip val          Check certificate matches ipaddr

-serial               Print serial number value
 -subject_hash         Print subject hash value
 -issuer_hash          Print issuer hash value

-subject_hash
 -subject              Print subject DN
 -issuer               Print issuer DN
 -email                Print email address(es)

-pubkey               Output the public key
 -fingerprint          Print the certificate fingerprint
 
 -ocspid               Print OCSP hash values for the subject name and public key
 -ocsp_uri             Print OCSP Responder URL(s)
 -trustout             Output a trusted certificate






 
 


















#create dirs and files
mkdir /etc/openvpn/easy-rsa
mkdir /etc/openvpn/easy-rsa/keys
mkdir /etc/openvpn/logs
OPENVPN_DIR=/etc/openvpn
OPENVPN_RSA_DIR=/etc/openvpn/easy-rsa
OPENVPN_KEYS=OPENVPN_RSA_DIR/keys

# Establish the default variables
#vars for certs
export EASY_RSA="/etc/openvpn/easy-rsa"
export OPENSSL="openssl"
export PKCS11TOOL="pkcs11-tool"
export GREP="grep"
export KEY_CONFIG=`$EASY_RSA/whichopensslcnf $EASY_RSA`
export KEY_DIR="$EASY_RSA/keys"
export PKCS11_MODULE_PATH="dummy"
export PKCS11_PIN="dummy"
export KEY_SIZE=4096
export CA_EXPIRE=3650
export KEY_EXPIRE=1825
export KEY_COUNTRY="US"
export KEY_PROVINCE="CA"
export KEY_CITY="SanFrancisco"
export KEY_ORG="Fort-Funston"
export KEY_EMAIL="my@vpn.net"
export KEY_OU="MyVPN"
export KEY_NAME="EasyRSA"


pkitool --batch --initca $*
pkitool" --batch --client client-cert
$OPENSSL dhparam -out ${KEY_DIR}/dh.pem ${KEY_SIZE}
openvpn --genkey --secret ${KEY_DIR}/ta.key


# ta tls auth OpenVPN 2.3.x
echo "key-direction 0" >> /etc/openvpn/client.conf
echo "<tls-auth>"  >> /etc/openvpn/client.conf
cat $KEY_DIR/ta.key >> /etc/openvpn/client.conf
echo "</tls-auth>" >> /etc/openvpn/client.conf

# ta tls crypt OpenVPN 2.4.x
echo "<tls-crypt>"  >> /etc/openvpn/server.conf
cat $KEY_DIR/ta.key >> /etc/openvpn/server.conf
echo "</tls-crypt>" >> /etc/openvpn/server.conf


echo "<dh>"  >> /etc/openvpn/client.conf
cat $KEY_DIR/dh.pem >> /etc/openvpn/client.conf
echo "</dh>" >> /etc/openvpn/client.conf


cp /tmp/ip6tables /etc/iptables/rules.v6
cp /tmp/iptables /etc/iptables/rules.v4
systemctl enable netfilter-persistent & systemctl start netfilter-persistent
systemctl enable openvpn@client & systemctl start openvpn@client
systemctl restart netfilter-persistent



# Allow traffic from OpenVPN client to NIC $NIC interface
-A POSTROUTING -s 10.8.0.0/8 -o ${NIC} -j MASQUERADE

iptables -t filter -A INPUT -p ${OVPNPROTOCOL} --dport ${OVPNPORT} -j ACCEPT
iptables -A INPUT -i tun+ -j ACCEPT
iptables -A FORWARD -i tun+ -j ACCEPT
iptables -A FORWARD -i tun+ -o eth0 -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -A FORWARD -i eth0 -o tun+ -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o eth0 -j MASQUERADE




echo "$VPNRULES" | cat - /etc/ufw/before.rules > temp && mv temp /etc/ufw/before.rules
sed -i -e 's/DEFAULT_FORWARD_POLICY="DROP"/DEFAULT_FORWARD_POLICY="ACCEPT"/g' /etc/default/ufw

ufw allow OpenSSH
ufw allow ssh
ufw disable

# allow SSH
iptables -t filter -A INPUT -p tcp --dport ${SSHPORT} -j ACCEPT


cp -v /etc/resolv.conf /etc/resolv.conf.trusted
chattr +i /etc/resolv.conf
chattr +i /etc/resolv.conf.trusted

iptables-save > /etc/iptables/rules.v4
iptables-save > /etc/iptables/rules.v6

chmod +x /root/iptables.rules

# install iptables-persistent to persist these rules after a reboot
echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections


# Network configuration
# Enable net.ipv4.ip_forward for the system
sed -i '/\<net.ipv4.ip_forward\>/c\net.ipv4.ip_forward=1' $SYSCTL
if ! grep -q "\<net.ipv4.ip_forward\>" $SYSCTL; then
	echo 'net.ipv4.ip_forward=1' >> $SYSCTL
fi
# Avoid an unneeded reboot
echo 1 > /proc/sys/net/ipv4/ip_forward







crl-verify /etc/openvpn/easy-rsa/keys/crl.pem

push "dhcp-option DNS 193.138.218.74"
push "dhcp-option DNS 10.8.0.1"
push "dhcp-option DNS 139.99.96.146"
push "dhcp-option DNS 37.59.40.15"
push "dhcp-option DNS 185.121.177.177"

push "redirect-gateway def1 bypass-dhcp"

resolv-retry infinite
persist-key
persist-tun

keepalive 10 120
tls-timeout 160
hand-window 160

cipher $CIPHER
auth SHA256

#uncomment for 2.4.x feature to disable automatically negotiate in AES-256-GCM
#ncp-disable

# Diffie hellman parameters.
## openssl dhparam -out dh1024.pem 1024
dh dh2048.pem

ca ca.crt
cert client.crt
key client.key

#max-clients 300
#user nobody
#group nobody
persist-key
persist-tun

status /etc/openvpn/logs/openvpn-status.log
log-append /etc/openvpn/logs/openvpn.log

verb 3
#reneg-sec 864000
ping 10
tls-client


#buffers
sndbuf 393216
rcvbuf 393216
push \042sndbuf 393216\042
push \042rcvbuf 393216\042
" >> /etc/openvpn/server.conf


#block local dns
setenv opt block-outside-dns


;log         openvpn.log
;log-append  openvpn.log

;max-clients 100





cd easy-rsa
source ./vars
./clean-all
./build-ca
./build-key-server server
./build-dh
cd keys
cp dh2048.pem ca.crt server.crt server.key /etc/openvpn
















## Disable IPv6 Forwarding
if sysctl net.ipv6.conf.all.forwarding | grep 1; then
    sysctl -w net.ipv6.conf.all.forwarding=0
    echo "net.ipv6.conf.all.forwarding = 0" >> /etc/sysctl.conf
else
    echo "IPv6 Forwarding is Already Disabled"
fi








#Generate a request for a client
cd ~/$EASYRSA/
./easyrsa gen-req $CLIENT_NAME nopass

#Copy the key to client directory
cp pki/private/$CLIENT_NAME.key ~/client-configs/keys/

#Transmit the request to the CA machine
scp pki/reqs/$CLIENT_NAME.req $CA_USER@$CA_IP:/tmp

#Invoke the sign-req script on the CA machine
ssh $CA_USER@$CA_IP "cd ~/CA-Setup && ./sign-req.sh $LOCAL_USER $LOCAL_IP client $CLIENT_NAME"








EIP=`curl -s checkip.dyndns.org | sed -e 's/.*Current IP Address: //' -e 's/<.*$//'`
IIPv6=`ip -6 addr | grep inet6 | grep fe80 | awk -F '[ \t]+|' '{print $3}'`

# Get Internet network interface with default route
NIC=$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)')

echo "Select server cipher:"
echo "1) AES-256-GCM (default for OpenVPN 2.4.x"

echo "Server will listen on $IP"
echo "Server will listen on $PORT"
echo "Server will use $CIPHER cipher"
echo "IPv6 - $IPV6E (1 is enabled, 0 is disabled)"




























