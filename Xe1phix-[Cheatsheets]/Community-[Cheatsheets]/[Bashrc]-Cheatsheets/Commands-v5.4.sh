#!/bin/sh
##-==============================-##
##    [+] 
##-==============================-##

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






