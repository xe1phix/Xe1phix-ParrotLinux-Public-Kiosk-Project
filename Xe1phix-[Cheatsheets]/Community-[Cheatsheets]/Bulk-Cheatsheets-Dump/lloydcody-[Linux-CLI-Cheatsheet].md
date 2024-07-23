# Network
ifconfig   #(network info)
ip a   #(network info)
ping <ip address>   #(sees whether a given IP address can be reached)
sudo ifdown -a; sudo ifup -a;   #(restarts all network interfaces)
sudo tcpflow -i any -C -J port XXXXX   #(raw network data) (also consider tcpdump)
sudo tcpdump -i eth0 icmp and icmp[icmptype]=icmp-echo   #(find out who's pinging me)
sudo netstat -nlp   #(find which processes are attached to which network ports)
sudo tcpdump -i eth0 -s0 -vv net 224.0.0.0/4   #(listen in on all incoming multicast UDP packets)
telnet 127.0.0.1 XXXXX   #(checks if a TCP connection can be established to an IP over port XXXXX)
ntop   #(network usage info)
nload networking monitoring tool   #(monitor network stats)
sudo arp-scan --interface=eth0 --localnet   #(scan local network for devices, sudo apt-get install arp-scan to install)
route   #(list routing table info)
sudo tcpdump port 1194 -vvv -A | grep "MESSAGE"   #(check OpenVPN connection on server)
nc -u <ip/domainname hq> 1194   #(to listen and on the local machine to send traffic and check ports are open)
curl -v -k yahoo.com   #(output contents of yahoo.com verbosely and ignoring invalid certificates)
wget yahoo.com   #(download the contents of yahoo.com's index page)
dig yahoo.com   #(DNS info for yahoo.com)


# Processes
ps ax   #(lists all running processes)
top   #(resource manager)
killall process-name-here   #(exits process by name)
apt-cache policy package123   #(find the installed and available versions of package123)
sudo apt-get install -y xdotool   #(installs xdotool for remote keyboard presses)


# System
history   #(lists all the previous commands which have executed on the device)
sudo reboot   #(reboots the machine)
export DISPLAY=:0   #(set the env var for the target display)
sudo xrandr   #(displays attached screen information)
lsb_release -a   #(list OS version info)
sudo lsusb   #(list USB devices)
who   #(gets all the current logged in users)
who -m   #(gets your user info)
xdpyinfo -display :0   #(gets X server info)
sudo chvt 7   #(change virtual terminal remotely)


# File management
mv XXXX.xxx YYYY.yyy   #(move/rename)
cp -R XXXX.xxx YYYY.yyy   #(copy and recurse into all dirs)  
scp -r /path/to/file 192.168.1.1:/path/to/file   #(copy over network)
locate XXXX.xxx   #(find a file on the system named XXXX.xxx)
zip -r filenameofchoice.zip .   #(zip contents of current directory up into a zip file named as you please)
unzip filenameofchoice.zip -d ./   #(unzip contents of zip file into current dir)


# PM2
pm2 startOrReload /path/to/some/file.json --update-env   #(starts up pm2 services as dictated by the given JSON data dir file)
pm2 save   #(save a pm2 configuration where services aren't behaving on start up)
pm2 logs --raw | bunyan   #(neater logs from PM2)
pm2 restart <process id>   #(if not running)


# Remote control
xdotool key "Ctrl+Shift+j"   #(with Chromium in focus, open Chromium console) 
xdotool key "Ctrl+bracketright"   #(with Chromium in focus, tab right in devtools, left is Ctrl+bracketleft)
xdotool "Shift+Ctrl+f5"   #(with Chromium in focus, content refresh)
xdotool "Page_Up"   #(with Chromium in focus, Page Up to the top of the console)


# PHP / MySQL
sudo sed -i 's|memory_limit = 128M|memory_limit = 264M|g' /etc/php5/fpm/php.ini && sudo service php5-fpm restart   #(ups the level of memory available to PHP)


# Upgrading the Chromium version
# 1. Got to: https://launchpad.net/ubuntu/trusty/amd64/chromium-browser/
# 2. Find the version you want and click into it's details (e.g. https://launchpad.net/ubuntu/trusty/amd64/chromium-browser/49.0.2623.108-0ubuntu0.14.04.1.1113)
# 3. Top right hand side of page has the download link (e,g, http://launchpadlibrarian.net/249878696/chromium-browser_49.0.2623.108-0ubuntu0.14.04.1.1113_amd64.deb)
# 4. Download all of its dependencies also
cd ~
wget http://launchpadlibrarian.net/252009569/fontconfig-config_2.11.94-0ubuntu1_all.deb
wget http://launchpadlibrarian.net/252009578/libfontconfig1_2.11.94-0ubuntu1_amd64.deb
wget http://launchpadlibrarian.net/249878696/chromium-browser_49.0.2623.108-0ubuntu0.14.04.1.1113_amd64.deb
wget http://launchpadlibrarian.net/249867018/chromium-browser-l10n_49.0.2623.108-0ubuntu0.14.04.1.1113_all.deb
wget http://launchpadlibrarian.net/249878698/chromium-codecs-ffmpeg-extra_49.0.2623.108-0ubuntu0.14.04.1.1113_amd64.deb
wget http://launchpadlibrarian.net/249878697/chromium-codecs-ffmpeg_49.0.2623.108-0ubuntu0.14.04.1.1113_amd64.deb
sudo cp ~/*.deb /var/cache/apt/archives/ # (assuming you don't have any other .deb files in your home dir)
killall chromium-browser
cd /var/cache/apt/archives/
sudo dpkg -i fontconfig-config_2.11.94-0ubuntu1_all.deb libfontconfig1_2.11.94-0ubuntu1_amd64.deb chromium-browser-l10n_49.0.2623.108-0ubuntu0.14.04.1.1113_all.deb chromium-browser_49.0.2623.108-0ubuntu0.14.04.1.1113_amd64.deb chromium-codecs-ffmpeg_49.0.2623.108-0ubuntu0.14.04.1.1113_amd64.deb chromium-codecs-ffmpeg-extra_49.0.2623.108-0ubuntu0.14.04.1.1113_amd64.deb


# USB serial
sudo stty -F /dev/ttyACM0   #(get baudrate of device)
sudo dmesg | grep tty   #(find tty name attached to USB serial device)
sudo apt-get install minicom
sudo minicom -s
sudo usermod -a -G dialout ubuntu
sudo adduser $USER dip
sudo adduser $USER dialout
sudo chmod 666 /dev/ttyACM0