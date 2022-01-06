#!/bin/sh


Cryptography
/home/x7h3z3r0l1x/Icons/4chan/3256.png

File Manipulation Utilities
/home/x7h3z3r0l1x/My Pictures/Icons/Breaking Bad Icons/PNG/018-Ar.png


Nautilus {Super User}
gksu /usr/bin/nautilus
/usr/share/icons/gnome-brave/scalable/apps/nautilus.svg


Synaptic Package Manager
synaptic-pkexec
Install, remove and upgrade software packages
/usr/share/icons/gnome-colors-common/scalable/apps/synaptic.svg


FileInfo {Superuser}
gksu /usr/local/bin/fileinfo %f
A GUI forensic tool for Ubuntu Linux designed to extract information from files.
/usr/share/icons/gnome/32x32/actions/fileinfo-ico.png







Audacious  -{ Firejail Xe1phix Custom Designed }-
firejail --profile=/etc/firejail/audacious.profile /usr/bin/audacious
/usr/share/icons/hicolor/scalable/apps/audacious.svg





/usr/share/applications/
$HOME/.local/share/applications/



AppArmor Notify
/usr/bin/aa-notify -p -s 1 -w 60
Receive on screen notifications of AppArmor denials








sudo firecfg

firecfg --list

sudo firecfg --clean


adduser --shell /usr/bin/firejail xe1phix
usermod --shell /usr/bin/firejail xe1phix







/etc/firejail/login.users


/usr/lib/firejail/firecfg.config




firemon --caps
firemon --interface
firemon --caps
firemon --netstats
firemon --cgroup
firemon --route
firemon --cpu
firemon --seccomp
firemon --list
firemon --tree
firemon --top


firecfg --fix
       /home/user/.local/share/applications/chromium.desktop created
       /home/user/.local/share/applications/vlc.desktop created




/home/xe1phix/.local/share/applications/firetools.desktop
/home/xe1phix/.local/share/applications/gnome-disk-image-mounter.desktop

/home/xe1phix/.local/share/applications/gnome-disk-image-writer.desktop

/home/xe1phix/.local/share/applications/mat.desktop
/home/xe1phix/.local/share/applications/org.gnome.DiskUtility.desktop
/home/xe1phix/.local/share/applications/services.desktop

/home/xe1phix/.local/share/applications/wireshark.desktop

/home/xe1phix/.local/share/applications/yubioath.desktop

/home/xe1phix/.local/share/applications/zenmap-root.desktop


/home/xe1phix/.local/share/applications/icedtea-netx-javaws.desktop

/home/xe1phix/.local/share/applications/caja-folder-handler.desktop

/home/xe1phix/.local/share/applications/caja-folder-handler.desktop

/home/xe1phix/.local/share/applications/atom.desktop


/home/xe1phix/Desktop/sepolicy.desktop



/home/xe1phix/.config/autostart/nm-applet.desktop

/run/user/1000/gnupg/S.dirmngr

/run/user/1000/gnupg/S.gpg-agent
/run/user/1000/gnupg/S.gpg-agent.browser
/run/user/1000/gnupg/S.gpg-agent.extra
/run/user/1000/gnupg/S.gpg-agent.ssh





./configure --prefix=/usr --enable-apparmor
aa-enforce firejail-default
firejail --apparmor firefox



ln -s /usr/bin/firejail /usr/bin/blueman-applet
blueman-adapters
blueman-applet
blueman-assistant
blueman-browse
blueman-manager
blueman-report
blueman-sendto
blueman-services




aa-enforce firejail-default



--git-install
--writable-var-log
--hosts-file=
--allow-private-blacklist
--machine-id
--private-opt=firefox




/etc/firejail/firejail.config

mkdir --parents --verbose --mode=0755 /home/faggot/Firejail/Profiles && cd /home/faggot/Firejail/Profiles && cp /etc/firejail/* /home/faggot/Firejail/Profiles/ && pwd && ls -ha

firejail --profile=/etc/firejail/firefox.profile


Firefox {Firejail Profile} 
firejail --profile=/etc/firejail/firefox-common.profile /usr/bin/firefox %u
/usr/share/icons/maia/apps/scalable/iceweasel.svg
/usr/share/icons/maia/apps/scalable/firefox-developer-icon.svg
/usr/share/icons/maia/apps/scalable/firefox-trunk.svg
/usr/share/icons/maia/apps/scalable/firefox.svg

Firefox Private {Firejail Profile} 
firejail --private --profile=/etc/firejail/firefox-common.profile /usr/bin/firefox %u
/usr/share/icons/maia/apps/scalable/iceweasel.svg


# change netfilter configuration
firejail --join-network=browser bash -c "cat /etc/firejail/nolocal.net  |  /sbin/iptables-restore"

# verify netfilter configuration
firejail --join-network=browser /sbin/iptables -vL

# verify  IP addresses
firejail --join-network=browser ip addr



I2P-Messenger
i2p-messenger
Chat over I2P via the SAM bridge and Seedless
/usr/share/pixmaps/i2p-messenger.xpm


jIRCii IRC Client
jircii
Chat with other people using Internet Relay Chat
/usr/share/pixmaps/jircii.xpm






I2P Start
/usr/bin/i2prouter start
Welcome to I2P!
/usr/share/i2p/docs/themes/console/images/itoopie_sm.png

I2P Restart
/usr/bin/i2prouter restart
Restarting The I2P Network
/usr/share/i2p/docs/themes/console/images/eepsite.png


Stop I2P Tunnels
/usr/bin/i2prouter stop
Stopping The I2P Network
/usr/share/i2p/docs/themes/console/images/errortriangle.png




firejail --name= --profile=/etc/firejail/



Seahorse  {Firejail Sandbox Profile}
firejail --name=seahorse --profile=/etc/firejail/seahorse.profile /usr/bin/seahorse



gksu /usr/bin/seahorse
Manage your passwords and encryption keys
/usr/share/icons/gnome-colors-common/scalable/apps/seahorse.svg
/usr/share/icons/hicolor/256x256/apps/gcr-gnupg.png


 {Firejail Sandbox Profile}
firejail --name=kgpg --profile=/etc/firejail/kgpg.profile /usr/bin/mkgpg %U
firejail --name= --profile=/etc/firejail/



Certificate and Key Storage {Firejail Sandbox Profile}
firejail --name=Gkeyringd --profile=/etc/firejail/gnome-keyring-daemon.profile /usr/bin/gnome-keyring-daemon --start --components=pkcs11
GNOME Keyring: PKCS#11 Component

gpa {Firejail Sandbox Profile}
firejail --name=gpa --profile=/etc/firejail/gpa.profile /usr/bin/gpa %F
/usr/share/icons/maia/apps/scalable/gpa.svg


Decrypt File {Firejail Sandbox Profile}
firejail --name=seahorse-decrypt --profile=/etc/firejail/seahorse.profile
seahorse-tool --decrypt


Import Key {Firejail Sandbox Profile}
firejail --name=seahorse-import --profile=/etc/firejail/seahorse.profile
seahorse-tool --import


Verify Signature {Firejail Sandbox Profile}
firejail --name=seahorse-verify --profile=/etc/firejail/seahorse.profile
seahorse-tool --verify





echo "Copy the custom made tor profiles to the main directory"
cp -v /home/xe1phix/Scripts/firejail-profiles/tor* /etc/firejail/
cp -v /home/xe1phix/Scripts/firejail-profiles/fe/tor-browser.profile /etc/firejail/




torsocks

torchat



Tor-Browser-en {Firejail Sandbox Profile}
firejail --name=tor-browser-en --profile=/etc/firejail/tor-browser-en.profile /usr/bin/tor-browser-en

torbrowser-launcher {Firejail Sandbox Profile}
firejail --name=torbrowser-launcher --profile=/etc/firejail/torbrowser-launcher.profile /usr/bin/torbrowser-launcher

tor Daemon {Firejail Sandbox Profile}
firejail --name=tor --profile=/etc/firejail/tor.profile /usr/bin/tor

tor-browser {Firejail Sandbox Profile}
firejail --name=tor-browser --profile=/etc/firejail/tor-browser.profile /usr/bin/tor-browser


TorChat Instant Messenger {Firejail Sandbox Profile}
firejail --name=torchat --profile=/etc/firejail/torchat.profile /usr/bin/torchat

start-tor-browser {Firejail Sandbox Profile}
firejail --name=start-tor-browser --profile=/etc/firejail/etc/start-tor-browser /usr/bin/torbrowser-launcher

private-bin bash,grep,tail,env,gpg,id,readlink,dirname,test,mkdir,ln,sed,cp,rm,getconf


caps.keep setuid,setgid,net_bind_service,dac_read_search




--profile=/etc/firejail/etc/
--profile=/etc/firejail/
--profile=/etc/firejail/
--profile=/etc/firejail/
--profile=/etc/firejail/
--profile=/etc/firejail/
--profile=/etc/firejail/

ln -s /usr/bin/firejail /usr/local/bin/firefox
which -a firefox

Firejail Firefox

private-tmp --noroot --caps.drop all --netfilter --nonewprivs --seccomp --caps.drop=all
firejail --private --apparmor --seccomp --name=firefox  --profile=/etc/firejail/firefox.profile  --overlay-tmpfs --dns=92.222.97.144 --dns=208.67.222.222  /usr/lib/firefox-esr/firefox-esr --no-remote  %u



Firefox Debugging {Firejail Strace} 
firejail  --allow-debuggers --profile=/etc/firejail/firefox.profile strace -f firefox

Firefox Debugging {Firejail Print Seccomp Syscalls} 
firejail --seccomp.print=browser



firejail --tracelog firefox
tail -f /var/log/syslog


firejail --trace wget -q www.debian.org



firejail --blacklist=/sbin --blacklist=/usr/sbin


Firefox Debugging {Firejail Debug Blacklists} 
firejail --debug-blacklists firefox-esr

Firefox Debugging {Firejail Debug Capabilities} 
firejail --debug-caps firefox-esr

Firefox Debugging {Firejail Debug Protocols} 
firejail --debug-protocols firefox-esr

Firefox Debugging {Firejail Debug Syscalls} 
firejail --debug-syscalls firefox-esr

Firefox Debugging {Firejail Debug Whitelists} 
firejail --debug-whitelists firefox-esr


firejail --net=eth0 --defaultgw=10.10.20.1 firefox
firejail --net=br0 --veth-name=

firejail --protocol=unix,inet

firejail --no3d firefox
firejail --output=

firejail --shell=/bin/dash script.sh
firejail --zsh

firejail --tmpfs=/var

firejail --overlay-named=
firejail --overlay-tmpfs firefox
firejail --overlay-clean
firejail --read-only=~/.mozilla firefox
firejail --read-only=~/test --read-write=~/Downloads/


firejail --noexec=/tmp
firejail --private-etc=group,hostname,localtime,nsswitch.conf,passwd,resolv.conf
--private-home=
--private=
firejail --private-opt=firefox /opt/firefox/firefox
firejail --private-srv=www /etc/init.d/apache2 start
firejail --private-tmp



firejail --net=eth0 --scan



firejail --private-bin=bash,sed,ls,cat
firejail --private-dev

firejail --private-etc=group,hostname,localtime,nsswitch.conf,passwd,resolv.conf
firejail --private-tmp

firejail --join-network=browser bash -c "cat /etc/firejail/nolocal.net | /sbin/iptables-restore"
firejail --join-network=browser /sbin/iptables -vL
firejail --join-network=browser ip addr


brctl addbr br0
ifconfig br0 10.10.20.1/24
brctl addbr br1
ifconfig br1 10.10.30.1/24
echo "1" > /proc/sys/net/ipv4/ip_forward
iptables ‐t nat ‐A PREROUTING ‐p tcp ‐‐dport 80 ‐j DNAT ‐‐to 10.10.20.10:80
iptables ‐t nat ‐A POSTROUTING ‐o eth0 ‐j MASQUERADE
iptables ‐A FORWARD ‐i eth0 ‐o br0 ‐p tcp ‐m tcp ‐‐dport 80 ‐j ACCEPT
iptables ‐A FORWARD ‐i eth0 ‐o br0 ‐m state ‐‐state RELATED,ESTABLISHED ‐j ACCEPT
iptables ‐A FORWARD ‐i br0 ‐j ACCEPT
iptables ‐P FORWARD DROP
/etc/init.d/iptables‐persistent save

iface br0 inet manual
pre‐up brctl addbr $IFACE
up ifconfig $IFACE 10.10.20.1/24

iface br0 inet manual
pre‐up brctl addbr $IFACE
up ifconfig $IFACE 10.10.20.1/24
down ifconfig $IFACE down
post‐down brctl delbr $IFACE




firejail --net=br0 --veth-name=iw0 --mac=00:11:22:33:44:55 --shell=/bin/bash ./iftest.sh
firejail --interface=wlan0 --mac=00:30:65:35:2e:37 --shell=/bin/bash ./iftest.sh
firejail --net=wlan0 --mac=00:30:65:35:2e:37 --shell=/bin/bash ./iftest.sh
firejail --net=br0 --veth-name=iw0 --mac=00:30:65:35:2e:37 --profile=/etc/firejail/etc/firefox-esr.profile --seccomp --apparmor --netfi



firejail --netfilter=/etc/firejail/nolocal.net
firejail --net=br0 --ip=10.10.20.5 --net=br1 --net=br2


firejail --net=br0 --net=br1

--fs.print=
--dns.print=

firejail --net=eth0 --defaultgw=10.10.20.1 firefox

firejail --dns=92.222.97.144 --dns=92.222.97.145 			# FrozenDNS

firejail --dns=208.67.222.222 --dns=208.67.220.220			# OpenDNS




firejail --dns=198.98.49.91 --dns=45.79.57.113

193.138.218.74

10.8.0.1

193.138.218.74,10.8.0.1

firejail --dns=198.98.49.91 --dns=45.79.57.113 --dns=193.138.218.74




firejail --profile=/etc/firejail/telegram.profile --protocol=unix,inet --dns=198.98.49.91 --dns=45.79.57.113 /usr/bin/telegram-desktop -- %u


firejail --interface=eth1 --interface=eth0.vlan100			# wlan devices not supported



firejail --net=br0 --ip=10.10.20.5 --net=br1 --net=br2			## new network namespace and connect it to br0, br1, and br2 host bridge devices.




firejail --join-network=browser ip addr						## verify  IP addresses


firejail --no3d --machine-id  --net=wlan0 --mac=00:11:22:33:44:55 firefox

firejail --netfilter=/etc/firejail/webserver.net --net=eth0 /etc/init.d/apache2 start

firejail --netfilter=/etc/firejail/nolocal.net --net=eth0 firefox


firejail --output=sandboxlog


firejail --caps.keep=net_broadcast,net_admin,net_raw
firejail --caps.keep=chown,net_bind_service,

firejail --caps.print=

firejail --cgroup=/sys/fs/cgroup/g1/tasks

firejail --chroot=/media/


firejail --x11 --net=eth0 firefox
firejail --x11=xorg firefox
firejail --x11=xpra --net=eth0 firefox


firejail --rmenv=DBUS_SESSION_BUS_ADDRESS










firefox-esr --profile 
--new-tab 
--private-window 
--ProfileManager
--search 

Custom definition for Firefox

mkdir ~/.mozilla
whitelist ~/.mozilla
mkdir ~/.cache/mozilla/firefox
whitelist ~/.cache/mozilla/firefox



adduser --shell /usr/bin/firejail username
usermod --shell /usr/bin/firejail username

/etc/firejail/login.users


--cgroup

--caps
--arp
--seccomp

firejail --name=
firejail --tree
firejail --top
firejail --interface
firejail --list
firejail --ls=firefox ~/Downloads
firejail --ls=telegram ~/Downloads



/usr/share/pixmaps/etherape.xpm
/usr/share/pixmaps/debian-security.png

/usr/share/pixmaps/firetools.png

/usr/share/pixmaps/torbrowser.png
/home/faggot/anon-icon-pack/arm.ico
/home/faggot/anon-icon-pack/whonixlock.png
/home/faggot/anon-icon-pack/whonix.png
/home/faggot/anon-icon-pack/timesync.ico


/home/faggot/anon-icon-pack/readme.ico

/usr/share/pixmaps/htop.png
/usr/share/pixmaps/gksu-root-terminal.png

/home/faggot/pixmaps/airsnort.png
/home/faggot/pixmaps/webscarab.png
/home/faggot/pixmaps/nmap-logo-64.png
/home/faggot/pixmaps/nessus-client.png
/home/faggot/pixmaps/kismet.png
/home/faggot/pixmaps/Logo-Final.png
/home/faggot/pixmaps/pentoo.png





MediaInfo  { Firejail Sandbox }



mpv Media Player {Firejail Sandboxed}
firejail --profile=/etc/firejail/mpv.profile --net=none /usr/bin/mpv --player-operation-mode=pseudo-gui
/usr/share/icons/maia/apps/scalable/mpv.svg


mpv Media Player {Private Firejail Sandbox}
firejail --profile=/etc/firejail/mpv.profile --private --net=none /usr/bin/mpv --player-operation-mode=pseudo-gui
/usr/share/icons/maia/apps/scalable/mpv.svg


mpv Media Player {Firejail Sandboxed}
firejail --profile=/etc/firejail/mpv.profile --net=none --private-tmp /usr/bin/mpv --player-operation-mode=pseudo-gui
/usr/share/icons/maia/apps/scalable/mpv.svg




mpv MediaPlayer {Firejail Full Syntax}
firejail --profile=/etc/firejail/mpv.profile --seccomp --caps.drop=all --net=none --shell=none --nonewprivs --noroot --nogroups --ipc-namespace --private-tmp --private-cache --private-dev --private-bin mpv,youtube-dl,python*,env /usr/bin/mpv --player-operation-mode=pseudo-gui
/usr/share/icons/maia/apps/scalable/mpv.svg




Atril {Firejail Sandbox Profile}
firejail --name=atril --profile=/etc/firejail/atril.profile --net=none /usr/bin/atril %U
View multi-page documents in firejailed secure environment
/usr/share/icons/maia/apps/scalable/evince.svg


Evince Document Viewer {Firejail Sandbox Profile}
firejail --name=docviewer --profile=/etc/firejail/etc/evince.profile /usr/bin/evince %U
/usr/share/icons/maia/apps/scalable/evince.svg
View multi-page documents


MuPdf Document Viewer {Firejail Sandbox Profile}
firejail --name=mupdf --profile=/etc/firejail/mupdf.profile /usr/bin/mupdf



xpdf {Firejail Sandbox Profile}
firejail --name=xpdf --profile=/etc/firejail/etc/xpdf.profile /usr/bin/xpdf
View PDF files




/etc/firejail/etc/pluma.profile



xchat.profile



MATE Terminal
mate-terminal


Use the command line
/usr/share/icons/hicolor/48x48/apps/parrot-shellnoob.png

--caps.drop=all --netfilter --nonewprivs --noroot


private-tmp
seccomp
shell none
 --net=none 


Transmission {Firejail Profile}
firejail --profile=/etc/firejail/transmission-gtk.profile transmission-gtk %U

--noroot --nonewprivs --nogroups --private-bin= --private-dev --private-tmp --protocol=unix,inet,netlink --seccomp --shell=none
Download and share files over BitTorrent
/usr/share/icons/maia/apps/scalable/transmission.svg

firejail audit transmission-gtk
firejail --debug-protocols transmission-gtk
firejail c transmission-gtk
firejail --debug-blacklists transmission-gtk
firejail --debug-caps transmission-gtk
firejail --audit transmission-gtk
firejail --errnos transmission-gtk
firejail --debug-errnos transmission-gtk
firejail --debug-seccomp transmission-gtk
firejail --seccomp-print transmission-gtk
firejail --seccomp-print= transmission-gtk
firejail --seccomp-print=net transmission-gtk
firejail --debug-syscalls transmission-gtk


firejail --trace --debug-syscalls --debug-seccomp --debug-caps --debug-caps --tracelog --noprofile /usr/bin/firefox-esr




Audacious -{ Firejail Xe1phix Custom Designed }-
firejail --name=Audacious --profile=/etc/firejail/audacious.profile /usr/bin/audacious
/usr/share/icons/maia/apps/scalable/audacity.svg












VLC Media Player {Firejail Sandboxed}
firejail --name=vlc --profile=/etc/firejail/vlc.profile --net=none /usr/bin/vlc
/usr/share/icons/hicolor/48x48/apps/vlc-xmas.png



VLC Media Player {Firejail NoNet Profile}
firejail --name=vlc --profile=/etc/firejail/vlc.profile --net=none /usr/bin/vlc
/usr/share/icons/maia/apps/scalable/vlc.svg
/usr/share/icons/hicolor/128x128/apps/vlc-xmas.png


/usr/bin/firejail --profile=/etc/firejail/
/usr/bin/firejail --profile=/etc/firejail/etc/vlc.profile --net=none 
/usr/bin/firejail --profile=/etc/firejail/vlc.profile --net=none 
/usr/bin/firejail --profile=/etc/firejail/vlc.profile --net=none /usr/bin/vlc --started-from-file %U


VLC Media Player {Firejail Hardened Syntax Profile}
firejail --noroot --nonewprivs --nogroups --private-bin=vlc,cvlc,nvlc,rvlc,qvlc,svlc --private-dev --private-tmp --net=none --seccomp --shell=none /usr/bin/vlc --started-from-file %U
/usr/share/icons/maia/apps/scalable/vlc.svg
/usr/share/icons/hicolor/128x128/apps/vlc-xmas.png





alsamixer



/usr/share/icons/maia/apps/scalable/bash.svg





Geany {Firejail Sandboxed}
firejail --profile=/etc/firejail/geany.profile --net=none /usr/bin/geany

xpdf {Firejail Sandboxed}
firejail --profile=/etc/firejail/xpdf.profile --net=none /usr/bin/xpdf %f

Evince {Firejail Sandboxed}
firejail --profile=/etc/firejail/evince.profile --net=none /usr/bin/evince

Atril Document Viewer {Firejail Sandboxed}
firejail --profile=/etc/firejail/atril.profile --net=none /usr/bin/atril %U



firejail --profile=/etc/firejail/vlc.profile /usr/bin/vlc --started-from-file %U


HexChat {Firejail Sandboxed}
firejail --profile=/etc/firejail/hexchat.profile /usr/bin/hexchat

Firefox-esr {Firejail Sandboxed}
firejail --profile=/etc/firejail/firefox-common.profile /usr/bin/firefox-esr


Audacious {Firejail Sandboxed}
firejail --profile=/etc/firejail/audacious.profile --net=none audacious



mpv Media Player {Firejail Sandboxed}
firejail --profile=/etc/firejail/mpv.profile --net=none --private-tmp /usr/bin/mpv --player-operation-mode=pseudo-gui

Totem {Firejail Sandboxed}
firejail --profile=/etc/firejail/totem.profile /usr/bin/totem %U

Gnash SWF Viewer {Firejail Sandboxed}
firejail --profile=/etc/firejail/gnash.profile /usr/bin/gnash-gtk-launcher %U

MediaInfo-gtk {Firejail Sandboxed}
firejail --profile=/etc/firejail/mediainfo.profile /usr/bin/mediainfo-gui %f

OpenShot Video Editor {Firejail Sandboxed}
openshot %F



Pluma Text Editor {Firejail Sandboxed}
firejail --profile=/etc/firejail/pluma.profile /usr/bin/pluma %U

Zim Desktop Wiki {Firejail Sandboxed}
firejail --profile=/etc/firejail/zim.profile /usr/bin/zim %f


Archive Manager {Firejail Sandboxed}
firejail --profile=/etc/firejail/file-roller.profile /usr/bin/file-roller %U


Engrampa Archive Manager {Firejail Sandboxed}
firejail --profile=/etc/firejail/engrampa.profile /usr/bin/engrampa %U



Liferea {Firejail Sandboxed}
firejail --profile=/etc/firejail/liferea.profile /usr/bin/liferea %U

Thunderbird {Firejail Sandboxed}
firejail --profile=/etc/firejail/thunderbird.profile /usr/bin/thunderbird %u

qBittorrent {Firejail Sandboxed}
firejail --profile=/etc/firejail/qbittorrent.profile /usr/bin/qbittorrent %U


Transmission-gtk {Firejail Sandboxed}
firejail --profile=/etc/firejail/transmission-gtk.profile /usr/bin/transmission-gtk %U

Eye of MATE Image Viewer {Firejail Sandboxed}
firejail --profile=/etc/firejail/eom.profile /usr/bin/eom %U


Eye of Gnome Image Viewer {Firejail Sandboxed}
firejail --profile=/etc/firejail/eog.profile /usr/bin/eog %U


Metadata Anonymization Toolkit (MAT) {Firejail Sandboxed}
firejail --profile=/etc/firejail/mat.profile /usr/bin/mat-gui

Caja File Browser {Firejail Sandboxed}
firejail --profile=/etc/firejail/caja.profile /usr/bin/caja --no-desktop --browser %U

firejail --profile=/etc/firejail/seahorse.profile /usr/bin/seahorse







Caja {SuperUser}
gksu /usr/bin/caja
Browse the file system with the file manager
/usr/share/icons/hicolor/scalable/apps/caja.svg


Caja {Firejail Sandboxed}
firejail --name=caja --profile=/etc/firejail/caja.profile --net=none /usr/bin/caja --no-desktop --browser %U
Browse the file system with the file manager
/usr/share/icons/maia/apps/scalable/system-file-manager.svg




Pluma Text Editor {Firejail Sandboxed}
firejail --name=pluma --profile=/etc/firejail/pluma.profile  /usr/bin/pluma %U
Edit text files
/usr/share/icons/maia/apps/scalable/gedit-logo.svg


Pluma {SuperUser}
gksu --sudo-mode /usr/bin/pluma
Edit text files
/usr/share/icons/maia/apps/scalable/gedit-logo.svg


Pluma Text Editor {Firejail Private Cache}
firejail --name=pluma --profile=/etc/firejail/pluma.profile --private --private-cache /usr/bin/pluma %U
Browse the file system with the file manager
/usr/share/icons/maia/apps/scalable/gedit.svg









firejail --profile=/etc/firejail/gedit.profile
/usr/share/icons/maia/apps/scalable/gedit-logo.svg







firejail --profile=/etc/firejail/eom.profile
firejail --caps.drop=all --net=none --seccomp --private oem %f



firejail --name=eom --profile=/etc/firejail/eom.profile --net=none /usr/bin/eom --new-instance 


firejail --profile=/etc/firejail/eog.profile







firejail --private --apparmor --seccomp --name=firefox  --profile=/etc/firejail/firefox.profile --overlay-tmpfs --dns=92.222.97.144 --dns=208.67.222.222  /usr/lib/firefox-esr/firefox-esr %u
/usr/lib/firefox-esr/firefox-esr -new-tab https://boards.4chan.org/b/
/usr/share/owasp-mantra-ff/Mantra/firefox -new-tab https://boards.4chan.org/b/ -no-remote







firejail --profile=/etc/firejail/start-tor-browser.profile





firejail --profile=/etc/firejail/exiftool.profile







Engrampa Archive Manager
engrampa %U
engrampa 
Create and modify an archive
/usr/share/icons/maia/apps/scalable/engrampa.svg



firejail --profile=/etc/firejail/gzip.profile
firejail --profile=/etc/firejail/xz.profile
firejail --profile=/etc/firejail/unzip.profile
firejail --profile=/etc/firejail/unrar.profile
firejail --profile=/etc/firejail/tar.profile
firejail --profile=/etc/firejail/7z.profile



firejail --profile=/etc/firejail/lxterminal.profile
firejail --profile=/etc/firejail/gnome-terminal
firejail --profile=/etc/firejail/mate-terminal




Root Terminal
gksu /usr/bin/x-terminal-emulator
Opens a terminal as the root user, using gksu to ask for the password
/usr/share/icons/gnome-colors-common/scalable/apps/gksu-root-terminal.svg




x-terminal-emulator --working-directory=/home/*/ --title fagginator --profile=faggot --new-tab










Seahorse {Superuser}
/usr/bin/seahorse
gksu /usr/bin/seahorse
Manage your passwords and encryption keys
/usr/share/icons/gnome-colors-common/scalable/apps/seahorse.svg
/usr/share/icons/hicolor/256x256/apps/gcr-gnupg.png













##-=====================================================================================================-##
## ----------------------------------------------------------------------------------------------------- ##
##-=====================================================================================================-##



##-=====================================================================================================-##
##-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<-##
##-=====================================================================================================-##
##-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~- [!] End of Stable Firejail Menu Configs [!] -~-~-~-~-~-~-~-~-~-~-~-~-~-##
##-=====================================================================================================-##
##-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<-##
##-=====================================================================================================-##



##-=====================================================================================================-##
## ----------------------------------------------------------------------------------------------------- ##
##-=====================================================================================================-##















##-=====================================================================================================-##
## ----------------------------------------------------------------------------------------------------- ##
## -------------------------- [+] Firejail Profile Configuration Parameters: --------------------------- ##
## ----------------------------------------------------------------------------------------------------- ##
##-=====================================================================================================-##



name Firefox
nogroups
shell none
ipc-namespace


caps.drop all
protocol unix,inet,packet

seccomp.block-secondary
memory-deny-write-execute



nonewprivs
noroot

disable-mnt

blacklist /usr/bin/gcc*
blacklist ${HOME}/.ssh
blacklist /media
blacklist /mnt
blacklist /usr/local/bin
blacklist /boot


include /etc/firejail/disable-common.inc
include ${HOME}/

mkdir ~/.mozilla
whitelist ~/.mozilla
mkdir ~/.cache/mozilla/firefox
whitelist ~/.cache/mozilla/firefox


overlay-tmpfs 
private 
private-home 

cgroup /sys/fs/cgroup/g1/tasks

private-cache
private-dev
private-tmp


read-only 
read-write 


tracelog


timeout hh:mm:ss


no3d
nodvd



firejail --net=eth0 --scan


defaultgw 192.168.1.1
ip 192.168.1.37


## verify  IP addresses
sudo firejail --join-network=browser ip addr



## ###################################### ## 
## ______ FrozenDNS _______
## nameserver 92.222.97.144
## nameserver 92.222.97.145
## 
## _______ OpenDNS _________
## nameserver 208.67.222.222
## nameserver 208.67.220.220
## ###################################### ## 
--ip=192.168.2.34 --dns=208.67.222.222
--ip=192.168.2.34 --dns=208.67.220.220

dns 139.99.96.146,185.121.177.177


firejail --dns.print=



## netfilter /usr/share/iptables/iptables.xslt
## netfilter /etc/iptables/rules.v4
## netfilter /etc/iptables/rules.v6
netfilter /etc/iptables/web-only.v4 
## netfilter /etc/iptables/web-only.v6


sudo firejail --join-network=browser bash -c "cat /etc/firejail/nolocal.net | /sbin/iptables-restore"


## verify netfilter configuration
sudo firejail --join-network=browser /sbin/iptables -vL


## firejail --netfilter.print=
## firejail --netfilter6.print=



net none


veth-name 

mac 
machine-id


sudo brctl addbr br0
sudo ifconfig br0 10.10.20.1/24
sudo brctl addbr br1
sudo ifconfig br1 10.10.30.1/24
firejail --net=br0 --net=br1

















##-=====================================================================================================-##
## ----------------------------------------------------------------------------------------------------- ##
## ------------------------- [!] End of Firejail Profile Config Parameters [!] ------------------------- ##
## ----------------------------------------------------------------------------------------------------- ##
##-=====================================================================================================-##












firejail --noexec=/tmp







Wifite {SuperUser}
gksu /usr/bin/wifite -i mon0 -wps -mac -showb -wpst 0

Wifite {SuperUser}
gksu /usr/bin/wifite -i mon0 -wps -mac -showb -wpst 0 -c <channel> -e <essid> -b <bssid>

Wifite Help Menu {SuperUser}
gksu /usr/bin/wifite --help



TrueCrypt
gksu /usr/bin/truecrypt
Create and mount TrueCrypt encrypted volumes
/usr/share/pixmaps/truecrypt.xpm 







Mount + Udisks






/usr/share/icons/hicolor/256x256/apps/parrot-apktool.png

















firejail --rlimit-fsize=1024 --rlimit-nproc=1000 --rlimit-nofile=500 --rlimit-sigpending=200


firejail --bind=/tmp/chroot,mntpoint

firejail --noprofile --bind=/tmp,/var/tmp --force

firejail --noprofile --bind=/tmp,/var/tmp --force
firejail --noprofile --overlay --force
firejail --noprofile --private-home=/tmp --force
firejail --noprofile --chroot=/tmp --force


firejail --name=dhcpd /etc/init.d/isc-dhcp-server start
firejail --join=dhcpd


firejail --join=
firejail --join-network=
firejail --join-filesystem=
firejail --name=nginx /etc/init.d/nginx start


firejail --bind=/tmp/chroot,mntpoint
firejail --bind=tmpfile,/etc/passwd
firejail --tmpfs=/var




cat /proc/self/status | grep Cap



lspci -nn | grep VGA
glxinfo  | grep rendering
glxinfo | grep "renderer string"


cat /sys/kernel/security/apparmor/profiles | grep firejail


## abstract unix socket bridge, example for ibus:

## before the sandbox is started
socat UNIX-LISTEN:/tmp/mysoc,fork ABSTRACT-CONNECT:/tmp/dbus-awBoQTCc &

## in sandbox
socat ABSTRACT-LISTEN:/tmp/dbus-awBoQTCc,fork UNIX-CONNECT:/tmp/mysock






Iceweasel→Firefox ESR

firejail --private=/home/netblue/firefox-home firefox-esr
firejail --private-home=.mozilla firefox

firefox-esr %u

/usr/share/icons/maia/apps/scalable/firefox-esr.svg
/usr/share/icons/maia/apps/scalable/firefox-nightly-icon.svg



firejail --caps.drop=all --net=none --seccomp --private oem %f

firejail --caps.drop=all --net=none --seccomp --nonewprivs --private-tmp --shell=none  mpv --player-operation-mode=pseudo-gui

nautilus --new-window /home/faggot/Browntown/ &


/usr/bin/pluma --new-window 




VLC media player
vlc --playlist-autostart, file:///home/faggot/Audio/FagList.m3u



Metadata Anonymisation Toolkit
mat-gui
/usr/share/pixmaps/mat.png

Metadata Anonymisation Toolkit {SuperUser}
gksu /usr/bin/mat-gui
/usr/share/pixmaps/mat.png


--backup
--list

mat --display mydocument.pdf			## Display the mydocument.pdf's harmful metadata

mat --check *.jpg						## Check all the jpg images from the current folder


firejail --allow-debuggers strace /usr/bin/mat --check kvm-linux-academy.png



/run/user/1000/bus
blacklist /tmp/.X11-unix



exiftool image.jpg -thumbnailimage -b | exiftool -			## Extract information from stdin.


cat a.jpg | exiftool -										##  Extract information from an embedded thumbnail image.








firejail debug-blacklists --profile=/etc/firejail/etc/pluma.profile /usr/bin/pluma %U







###################################################################
# Client filter rejecting local network traffic, with the exception of
# DNS traffic
#
#
###################################################################
firejail --net=eth0 --netfilter=/etc/firejail/nolocal.net firefox

-A OUTPUT -p udp --dport 53 -j ACCEPT
-A OUTPUT -d 192.168.0.0/16 -j DROP
-A OUTPUT -d 10.0.0.0/8 -j DROP
-A OUTPUT -d 172.16.0.0/12 -j DROP





gnome-terminal
mate-terminal
/usr/share/icons/hicolor/256x256/apps/parrot-shellnoob.png


firejail --appimage --private /home/xe1phix/firejail/appimage/Firefox-51.0.1.glibc2.3.3-x86_64.AppImage



FireJailed Appimage of Firefox {Private}
firejail --name=fireappimg --private --appimage /home/xe1phix/firejail/appimage/Firefox-51.0.1.glibc2.3.3-x86_64.AppImage



--protocol=unix,inet
--net=eth0
--veth-name=
--interface=eth0
--mac=
--dns=139.99.96.146 --dns=185.121.177.177
--seccomp.block-secondary
--private-dev
--read-only=
--timeout=hh:mm:ss - kill the sandbox
--netns=

--x11=xorg

--net=none --protocol=unix


--read-only=~/.mozilla
--read-only=~
--read-write=


include /etc/firejail/disable-common.inc
include /etc/firejail/disable-devel.inc
include /etc/firejail/disable-interpreters.inc
include /etc/firejail/disable-passwdmgr.inc
include /etc/firejail/disable-programs.inc
include /etc/firejail/whitelist-common.inc

mkdir ${HOME}/

whitelist ${DOWNLOADS}
protocol unix,inet
private
private-cache
disable-mnt
private-tmp
private-dev
noexec ${HOME}
noexec /tmp

net tun0
netfilter /etc/firejail/


mkdir ~/.mozilla
whitelist ~/.mozilla
mkdir ~/.cache/mozilla/firefox
whitelist ~/.cache/mozilla/firefox




name 

read-only 
read-write 
whitelist 
ipc-namespace
dns 
hosts-file 

tmpfs 
noexec 
mkfile 
overlay-tmpfs 
private 
private-home 
private-cache
private-tmp
shell none

cgroup /sys/fs/cgroup/g1/tasks
timeout hh:mm:ss






firejail --build=vlc.profile vlc ~/Videos/test.mp4



firejail --build telegram-desktop /usr/bin/telegram-desktop -- %u








Chromium Web Browser
/usr/bin/chromium %U
Access the Internet
/usr/share/icons/maia/apps/scalable/chromium.svg




Chromium {Firejail Appimage}
/home/xe1phix/firejail/appimage/Chromium-55.0.2843.0-x86_64.AppImage
/usr/share/icons/maia/apps/scalable/chromium.svg



Chromium {Firejail Profile}
firejail --name=chromium --profile=/etc/firejail/etc/chromium.profile /usr/bin/chromium %U
/usr/share/icons/maia/apps/scalable/chromium.svg






Chromium Web Browser {Firejail Appimage}
firejail --name=chromiumappimg --profile=/etc/firejail/etc/chromium.profile --appimage /home/xe1phix/firejail/appimage/Chromium-55.0.2843.0-x86_64.AppImage
firejail --name=chromiumappimg /home/xe1phix/firejail/appimage/Chromium-55.0.2843.0-x86_64.AppImage
/usr/share/icons/maia/apps/scalable/chromium.svg


Firefox Private {Firejail Profile}
firejail --name=firefox --private --read-only=~/.mozilla --profile=/etc/firejail/firefox-common.profile --dns=139.99.96.146 --dns=37.59.40.15 /usr/bin/firefox %u



Firefox-esr Private {Firejail Profile}
firejail --name=firefox-esr --profile=/etc/firejail/firefox.profile /usr/bin/firefox-esr %u

Firefox {Firejail Profile}
firejail --name=firefox --profile=/etc/firejail/firefox.profile /usr/bin/firefox %u





--blacklist=/home/xe1phix/.mozilla








--ipc-namespace


--output=logfile - stdout logging and log rotation





Firejail Pluma Debugging {All Debug Tests}
firejail --name=pluma --debug --profile=/etc/firejail/etc/pluma.profile /usr/bin/pluma %U


firejail --debug-blacklists --profile=/etc/firejail/etc/pluma.profile /usr/bin/pluma %U




Firejail Telegram Debugging {All Debug Tests}
##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=--=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##

##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=--=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##
firejail --name=telegram --debug --profile=/etc/firejail/etc/telegram.profile Telegram -- %u
## ------------------------------------------------------------------------------------------------- ##
/usr/share/icons/maia/apps/scalable/telegram.svg

/usr/local/etc/firejail/telegram.profile


Telegram {Firejail Profile}
firejail --name=telegram --profile=/etc/firejail/etc/telegram.profile /home/xe1phix/Downloads/Telegram/Telegram -- %u
/usr/share/icons/maia/apps/scalable/telegram.svg


Firejail Telegram Debugging {Firejail Debug Blacklists} 
firejail --debug-blacklists /home/xe1phix/Downloads/Telegram/Telegram -- %u
/usr/share/icons/maia/apps/scalable/telegram.svg

Firejail Telegram Debugging {Firejail Debug Capabilities} 
firejail --debug-caps /home/xe1phix/Downloads/Telegram/Telegram -- %u
/usr/share/icons/maia/apps/scalable/telegram.svg


Telegram Debugging {Firejail Debug Protocols} 
firejail --debug-protocols /home/xe1phix/Downloads/Telegram/Telegram -- %u
/usr/share/icons/maia/apps/scalable/telegram.svg

Firejail Telegram Debugging {Print Protocols} 
firejail --name=telegram --profile=/etc/firejail/etc/telegram.profile /home/xe1phix/Downloads/Telegram/Telegram
firejail --protocol.print=telegram --output=telegram-protocols.txt


Firejail Telegram Debugging {Firejail Debug Syscalls} 
firejail --debug-syscalls /home/xe1phix/Downloads/Telegram/Telegram -- %u
/usr/share/icons/maia/apps/scalable/telegram.svg

Firejail Telegram Debugging {Firejail Debug Whitelists} 
firejail --debug-whitelists /home/xe1phix/Downloads/Telegram/Telegram -- %u
/usr/share/icons/maia/apps/scalable/telegram.svg

Firejail Telegram Debugging {Firejail Strace} 
firejail --allow-debuggers --profile=/etc/firejail/etc/telegram.profile strace -f /home/xe1phix/Downloads/Telegram/Telegram -- %u
/usr/share/icons/maia/apps/scalable/telegram.svg


Firejail Telegram No Profile {Auditing Blacklisted Variables}
firejail --noprofile --tracelog --name=telegram Telegram && sleep 10 && tail -f /var/log/syslog | tee ~/FirejailAuditNoProfile.txt
/usr/share/icons/maia/apps/scalable/telegram.svg

Firejail Telegram Profile {Auditing Blacklisted Variables}
firejail --name=telegram --tracelog --profile=/etc/firejail/etc/telegram.profile /home/xe1phix/Downloads/Telegram/Telegram && sleep 10 && tail -f /var/log/syslog | tee ~/FirejailAuditTelegramProfile.txt
/usr/share/icons/maia/apps/scalable/telegram.svg


Firejail Telegram Debugging {Firejail Print Seccomp Syscalls} 
(firejail --name=telegram --noprofile --output=~/FirejailTelegramSeccompPrint.txt /home/xe1phix/Downloads/Telegram/Telegram &) && sleep 10 && firejail --seccomp.print=telegram  | tee ~/FirejailSeccompTelegramProfile.txt
/usr/share/icons/maia/apps/scalable/telegram.svg

Firejail Telegram Debugging {Firejail Print all recognized errors} 
firejail --debug-errnos
/usr/share/icons/maia/apps/scalable/telegram.svg


Firejail Telegram Logging {Cp stdout & stderr to logfile}
firejail --name=telegram --output=TelegramLogz --profile=/etc/firejail/etc/telegram.profile /home/xe1phix/Downloads/Telegram/Telegram
/usr/share/icons/maia/apps/scalable/telegram.svg


echo "Listing Log Files..." 
ls -l sandboxlog* && cat sandboxlog* | tee ~/sandboxlog.txt
/usr/share/icons/maia/apps/scalable/telegram.svg




Firejail Telegram Auditing {No Profile Audit}
firejail --audit --name=telegram --noprofile /home/xe1phix/Downloads/Telegram/Telegram
/usr/share/icons/maia/apps/scalable/telegram.svg


Firejail Telegram Auditing {Profile Defined Audit}
firejail --audit --name=telegram --profile=/etc/firejail/telegram.profile Telegram
/usr/share/icons/maia/apps/scalable/telegram.svg





firejail --list
firejail --caps.print=

firejail --name=
firejail --dns.print=


echo "Print The Filesystem Log For The Sandbox:"
Firejail FS-Log Debugging {Telegram Profile}
firejail --name=telegram --profile=/etc/firejail/telegram.profile Telegram; sleep 10 && echo -e "\n\n\t\tPrinting Sandbox's FS Debug Log Output...\n\n" && firejail --fs.print=telegram


Firejail FS-Log Debugging {Telegram Profile - No Profile Applied}
firejail --name=telegram 
firejail --fs.print=telegram


Firejail Debugging {Telegram - Protocol Printing - Without Defined Profile} 
firejail --name=telegram --noprofile --output=TelegramProtocolNoProfileLogz /home/xe1phix/Downloads/Telegram/Telegram &
firejail --protocol.print=telegram

Firejail Debugging {Telegram Profile - Protocol Printing} 
firejail --name=telegram --profile=/etc/firejail/etc/telegram.profile /home/xe1phix/Downloads/Telegram/Telegram &
--profile=/etc/firejail/etc/telegram.profile


Firejail Debugging {Telegram Profile - Seccomp Printing - Without Defined Profile} 
firejail --name=telegram --noprofile --output=TelegramSeccompNoProfileLogz /home/xe1phix/Downloads/Telegram/Telegram &
firejail --seccomp.print=telegram --output=TelegramLogz


Firejail Debugging {Telegram Profile - Seccomp Printing - With Defined Profile} 
firejail --name=telegram --output=TelegramSeccompProfileLogz --profile=/etc/firejail/etc/telegram.profile /home/xe1phix/Downloads/Telegram/Telegram &
firejail --seccomp.print=telegram --output=TelegramLogz




em  /opt/telegram/Telegram





firejail --debug --join=
cat /proc/self/status | grep Cap








Audit/Debug without the predefined security profiles in /etc/firejail/.
firejail --noprofile --output=~/Telegram-debug.txt --debug Telegram

firejail --noprofile --output=~/Telegram-syscalls.txt --debug-syscalls Telegram


firejail --noprofile --output=~/Telegram-caps.txt --debug-caps Telegram


firejail --noprofile --output=~/Firefox-debug.txt --debug firefox



firejail --noprofile --debug firefox
firejail --noprofile --debug-caps firefox
firejail --noprofile --debug-syscalls firefox
firejail --noprofile --audit firefox



firejail --tree
firejail --netstats
firejail --top
firejail --debug-check-filename Telegram



Spoof id number in /etc/machine-id file - a new random id is generated inside the sandbox


firejail --net=eth0 --mac=00:11:22:33:44:55 --machine-id
firejail --machine-id


--ip=192.168.2.34 --dns=92.222.97.144
--ip=192.168.2.34 --dns=92.222.97.145


##-======================================-## 
## ______ FrozenDNS _______
## nameserver 92.222.97.144
## nameserver 92.222.97.145
## 
## _______ OpenDNS _________
## nameserver 208.67.222.222
## nameserver 208.67.220.220
## 
## ___ParrotDNS/OpenNIC____
## nameserver 139.99.96.146
## nameserver 37.59.40.15
## nameserver 185.121.177.177
## 
##-======================================-## 
--ip=192.168.2.34 --dns=208.67.222.222
--ip=192.168.2.34 --dns=208.67.220.220




firejail --join-network=browser bash -c "cat /etc/firejail/nolocal.net | /sbin/iptables-restore"

firejail --join-network=browser ip addr

firejail --join-network=browser /sbin/iptables -vL










Firejail Telegram {Place Into Isolated Cgroup}
firejail --name=telegram --cgroup=/sys/fs/cgroup/g1/tasks --profile=/etc/firejail/etc/telegram.profile Telegram
/usr/share/icons/maia/apps/scalable/telegram.svg

Firejail Telegram {Chroot Into Isolated RootFS}
firejail --name=telegram --chroot=/media/telegram --noprofile --seccomp --caps.drop=all --netfilter --nonewprivs --noroot /home/xe1phix/Downloads/Telegram/Telegram
/usr/share/icons/maia/apps/scalable/telegram.svg

Firejail Telegram {Place Into Isolated Cgroup}
firejail --ipc-namespace 
/usr/share/icons/maia/apps/scalable/telegram.svg


SHELL=/bin/sh unshare --fork --pid chroot "${chrootdir}" "$@"



Mount  a  filesystem overlay on top of the current filesystem
firejail --overlay Telegram
/usr/share/icons/maia/apps/scalable/telegram.svg


firejail --overlay-tmpfs 
/usr/share/icons/maia/apps/scalable/telegram.svg


Clean all overlays stored in $HOME/.firejail directory
firejail --overlay-clean
/usr/share/icons/maia/apps/scalable/telegram.svg


Mount  new  /root  and  /home/user directories in temporary filesystems. 
firejail --private 


Build a new user home in a temporary filesystem
firejail --private=/home/xe1phix/Downloads/Telegram/Telegram-private Telegram


--private-etc=

firejail --name=telegram --private-etc=group,hostname,localtime,nsswitch.conf,passwd,resolv.conf Telegram





cd /home/xe1phix/Scripts/firejail

apt-get install libapparmor-dev




./configure --prefix=/usr --enable-apparmor

Configuration options:
   prefix: /usr
   sysconfdir: /etc
   seccomp: -DHAVE_SECCOMP
   <linux/seccomp.h>: -DHAVE_SECCOMP_H
   apparmor: -DHAVE_APPARMOR
   global config: -DHAVE_GLOBALCFG
   chroot: -DHAVE_CHROOT
   bind: -DHAVE_BIND
   network: -DHAVE_NETWORK
   user namespace: -DHAVE_USERNS
   X11 sandboxing support: -DHAVE_X11
   whitelisting: -DHAVE_WHITELIST
   private home support: -DHAVE_PRIVATE_HOME
   file transfer support: -DHAVE_FILE_TRANSFER
   overlayfs support: -DHAVE_OVERLAYFS
   git install support: 
   busybox workaround: no
   EXTRA_LDFLAGS: -lapparmor 
   fatal warnings: 
   Gcov instrumentation: 


aa-enforce firejail-default
## Setting /etc/apparmor.d/firejail-default to enforce mode.


firejail --blacklist=/sbin --blacklist=/usr/sbin



firejail --blacklist=/sbin --blacklist=/usr/sbin
firejail --chroot=


--apparmor.print=$name|$pid





Firejail Virtualbox Debugging {Profile Defined Audit}
firejail --profile=/etc/firejail/etc/telegram.profile --audit /home/xe1phix/Downloads/Telegram/Telegram


read-only ~/.mozilla



Geany {FireJail Sandbox}
firejail --name=geany --private --caps.drop=all --net=none --seccomp --nonewprivs --private-tmp --shell=none --profile=/etc/firejail/geany.profile /usr/bin/geany %F
A fast and lightweight IDE using GTK+


Atom
/opt/atom/atom %F
A hackable text editor for the 21st century
/usr/share/icons/maia/apps/scalable/atom.svg

virtualbox {FireJail}
firejail --name=virtualbox --profile=/etc/firejail/virtualbox.profile /usr/bin/virtualbox
/usr/share/icons/maia/apps/scalable/virtualbox.svg

firejail --debug-blacklists /etc/firejail/virtualbox.profile 
firejail --debug-syscalls /etc/firejail/virtualbox.profile 
firejail --debug-whitelists /etc/firejail/virtualbox.profile 
firejail --audit=~/virtsand-test virtualbox 
firejail --audit virtualbox 
firejail --debug-protocols virtualbox
firejail --trace --tracelog

firejail "--whitelist=/home/username/My Virtual Machines"





##-=====================================================-##
##   [+] Copy A File Outside of The Firejail Sandbox:
##-=====================================================-##
## --------------------------------------------------------------------------- ##
firejail --ls=$browser ~/Downloads
firejail --get=$browser ~/Downloads/$xpra-clipboard.png
firejail --put=$browser $xpra-clipboard.png ~/Downloads/$xpra-clipboard.png
## --------------------------------------------------------------------------- ##
firejail --ls=$PID ~/
firejail --get=$PID ~/$File
firejail --put=$PID ~/$File ~/Downloads/$File
## --------------------------------------------------------------------------- ##





firejail --zsh


firejail --name=
firejail --tree
firejail --top
firejail --interface
firejail --list
firejail --ls=firefox ~/Downloads
firejail --ls=telegram ~/Downloads

firejail --get=mybrowser ~/Downloads/xpra-clipboard.png
firejail --put=mybrowser xpra-clipboard.png ~/Downloads/xpra-clipboard.png





--read-only=

--rlimit-fsize=					## set the maximum file size that can be created by a process.
--rlimit-nofile=				## set the maximum number of files that can be opened by a process



firejail --name=virtualbox --debug-whitelists /etc/firejail/virtualbox.profile 


Firejail virtualbox Auditing {Profile Defined Audit}
firejail --name=virtualbox --audit virtualbox 


Firejail Virtualbox Debugging {Firejail Audit} 
firejail --name=virtualbox --profile=/etc/firejail/virtualbox.profile --audit /usr/bin/virtualbox




firejail --name=virtualbox --debug-syscalls /etc/firejail/virtualbox.profile 


firejail --name=virtualbox --debug-blacklists /etc/firejail/virtualbox.profile

Caja {Firejail Sandboxed}
firejail --name=caja --profile=/etc/firejail/caja.profile --caps.drop=all --net=none --seccomp --nonewprivs --private-tmp --shell=none /usr/bin/pluma %U
Browse the file system with the file manager
/usr/share/icons/maia/apps/scalable/system-file-manager.svg


Pluma Text Editor {Firejail Sandboxed}
firejail --name=pluma --profile=/etc/firejail/pluma.profile /usr/bin/pluma %U
Browse the file system with the file manager
/usr/share/icons/maia/apps/scalable/system-file-manager.svg



firejail --name=pluma --profile=/etc/firejail/pluma.profile --caps.drop=all --net=none --seccomp --nonewprivs --private-tmp --shell=none --private --private-cache /usr/bin/pluma %U
firejail --profile=/etc/firejail/pluma.profile --caps.drop=all --seccomp --nonewprivs --private-tmp --shell=none --private /usr/bin/pluma %U


Pluma Text Editor {Firejail Private Sandbox}
firejail --name=pluma --profile=/etc/firejail/pluma.profile --private --private-cache /usr/bin/pluma %U
Browse the file system with the file manager
/usr/share/icons/maia/apps/scalable/system-file-manager.svg



pluma --new-window 
/run/media/public/2TB/Xe1phixGitLab/GnuPG/Xe1phixGnuPG-Projects/Xe1phix-GnuPG/Xe1phixSources-v2.7.list
/run/media/public/2TB/Xe1phixGitLab/LPIC-2/LPIC-2-v6.0.sh
LPIC-1-v3.9.sh
/run/media/public/2TB/BrowntownAlpha/Sir-Goatse-lot/Grsec+PaX/GrsecParrotSec-v3.2.sh
/run/media/public/2TB/BrowntownAlpha/Sir-Goatse-lot/
/run/media/public/2TB/BrowntownAlpha/Sir-Goatse-lot/Proper-Shit-Gasm-Ediquite.sh
/run/media/public/2TB/BrowntownAlpha/Sir-Goatse-lot/PortableFaggotWall-v1.4.sh
/run/media/public/2TB/BrowntownAlpha/Sir-Goatse-lot/FaggotWall-v1.3.sh
/run/media/public/2TB/BrowntownAlpha/Sir-Goatse-lot/Chmod-2.4.sh
/run/media/public/2TB/BrowntownAlpha/Sir-Goatse-lot/Scriptz2.2.sh
/run/media/public/2TB/BrowntownAlpha/Sir-Goatse-lot/scripts
/run/media/public/2TB/BrowntownAlpha/Sir-Goatse-lot/History2.7.7.sh
/run/media/public/2TB/BrowntownAlpha/Sir-Goatse-lot/ids.sh
/run/media/public/2TB/BrowntownAlpha/Sir-Goatse-lot/startupz.sh
/run/media/public/2TB/BrowntownAlpha/Sir-Goatse-lot/SetEnforce-v2.5.sh
/run/media/public/2TB/BrowntownAlpha/Sir-Goatse-lot/Za-Xen-v1.3.sh



Pluma Text Editor {Firejail Sandboxed}
firejail --name=pluma --profile=/etc/firejail/pluma.profile --overlay-tmpfs /usr/bin/pluma %U

--overlay-named=
--overlay-tmpfs
--overlay-clean
--private=                      ## Use directory as user home.

--private-home=                 ## Build a new user home in a temporary filesystem,0


--profile.print=name|pid


--tmpfs=

--tunnel[=devname]
              Connect  the sandbox to a network overlay/VPN tunnel created by firetunnel utility. This options tries first the client side of the tunnel. If this fails,
              it tries the server side.
firejail --profile=/etc/firejail/pluma.profile  /usr/bin/pluma %U


firetunnel


## Move interface in a new network namespace.
firejail --interface=eth1 --interface=eth0.vlan100


firejail --net=br0 --veth-name=vlan





--disable-mnt


--net=tap_interface                 ## Enable a new network namespace and connect 
                                    ## it to this ethernet tap interface using 
                                    ## the standard Linux macvlan driver. 
              
firejail --net=tap0 --ip=10.10.20.80 --netmask=255.255.255.0 --defaultgw=10.10.20.1 firefox




--net=none
              Enable  a new, unconnected network namespace. The only interface available in the new namespace is a new loopback interface (lo).
              


firejail --netfilter=/etc/firejail/nolocal.net --net=eth0 




private-home


Edit text files
/usr/share/icons/maia/apps/scalable/gedit-logo.svg




firejail --debug-blacklists /etc/firejail/etc/pluma.profile /usr/bin/pluma %U

--netstats
--top 
--tree

firejail --name=pluma --profile=/etc/firejail/etc/ /usr/bin/ &


firejail --name= --profile=/etc/firejail/etc/.profile /usr/bin/ &

firejail --name= --profile=/etc/firejail/etc/.profile /usr/bin/ &


firejail --name= --profile=/etc/firejail/etc/.profile /usr/bin/ &

firejail --name= --profile=/etc/firejail/etc/.profile /usr/bin/ &

firejail --name= --profile=/etc/firejail/etc/.profile /usr/bin/ &

firejail --name= --profile=/etc/firejail/etc/.profile /usr/bin/ &

firejail --name=gpa --profile=/etc/firejail/etc/gpa.profile /usr/bin/gpa --no-remote --files &
firejail --name=gpa --profile=/etc/firejail/etc/gpa.profile /usr/bin/gpa --no-remote --keyring &






extract env for process
ps e -p <pid> | sed 's/ /\n/g' 


















# ssh client
quiet
noblacklist ~/.ssh
noblacklist /tmp/ssh-*
noblacklist /etc/ssh

firejail --blacklist=/sbin --blacklist=/usr/sbin




firejail --name=pdftotext --profile=/etc/firejail/etc/pdftotext.profile /usr/bin/pdftotext /usr/share/doc/apparmor-docs/* Textbooks/




blacklist ${HOME}/.bash_history
blacklist ${HOME}/.local/share/keyrings
blacklist ${HOME}/.gnupg
blacklist ${HOME}/.config/autostart
read-only ${HOME}/.local/share/applications



Disable /home/xe1phix/.macromedia
Mounting read-only ${HOME}/.local/share/applications
Disable /home/xe1phix/.config/autostart
Disable /etc/xdg/autostart
Disable /etc/X11/Xsession.d (requesterd /etc/X11/Xsession.d/)
Disable /home/xe1phix/VirtualBox VMs
Disable /home/xe1phix/.config/VirtualBox

pcscd




firejail --caps /etc/init.d/ start
firejail --caps /etc/init.d/ start
firejail --caps /etc/init.d/ start
firejail --caps /etc/init.d/ start
firejail --caps /etc/init.d/ start
firejail --caps /etc/init.d/ start
firejail --caps /etc/init.d/ start
firejail --caps /etc/init.d/ start
firejail --caps /etc/init.d/ start
firejail --caps /etc/init.d/ start
firejail --caps /etc/init.d/polkitd start
firejail --caps /etc/init.d/dbus-launch start
firejail --caps /etc/init.d/avahi-daemon start
firejail --caps /etc/init.d/pkcheck start
firejail --caps /etc/init.d/pkexec start
firejail --caps /etc/init.d/pkaction start
firejail --caps /etc/init.d/pkttyagent start


developer documentation




firejail --caps /etc/init.d/ start
firejail --caps /etc/init.d/ start
firejail --caps /etc/init.d/ start
firejail --caps /etc/init.d/ start
firejail --caps /etc/init.d/ start
firejail --caps /etc/init.d/ start
firejail --caps /etc/init.d/ start
firejail --caps /etc/init.d/ start








## 							<(+)==={{ nginx web server }}==(+)>

firejail --caps.keep=chown,net_bind_service,setgid,setuid --seccomp /etc/init.d/nginx start

## 							<(+)==={{ apache web server }}==(+)>
firejail --caps.keep=chown,sys_resource,net_bind_service,setuid,setgid --seccomp /etc/init.d/apache2 start

## 							<(+)==={{ net-snmp server }}==(+)>
firejail --caps.keep=net_bind_service,setuid,setgid --seccomp /etc/init.d/snmpd start
firejail --caps.keep=net_bind_service,setuid,setgid --seccomp /usr/sbin/snmptrapd start

## 							<(+)==={{ ISC DHCP server }}==(+)>

firejail --caps.keep=net_bind_service,net_raw --seccomp /etc/init.d/isc-dhcp-server start





firejail --caps /etc/init.d/hostapd start
firejail --caps /etc/init.d/postgresql start
mysql

firejail --caps /etc/init.d/openvpn start
network-manager


firejail --caps /etc/init.d/paxctld start
firejail --caps /etc/init.d/postfix start
firejail --caps /etc/init.d/rc.local start
firejail --caps /etc/init.d/rc start
firejail --caps /etc/init.d/redis-server start
firejail --caps /etc/init.d/rmnologin start
firejail --caps /etc/init.d/rsync start
firejail --caps /etc/init.d/rsyslog start
firejail --caps /etc/init.d/rwhod start
firejail --caps /etc/init.d/samba start
samba-ad-dc
firejail --caps /etc/init.d/tor start
firejail --caps /etc/init.d/smbd start
firejail --caps /etc/init.d/ssh start
firejail --caps /etc/init.d/stunnel4 start
firejail --caps /etc/init.d/thin start
firejail --caps /etc/init.d/ start
firejail --caps /etc/init.d/ start
firejail --caps /etc/init.d/ start
firejail --caps /etc/init.d/ start
firejail --caps /etc/init.d/ start
firejail --caps /etc/init.d/bluetooth start
firejail --caps /etc/init.d/clamav-daemon start
firejail --caps /etc/init.d/clamav-freshclam start
firejail --caps /etc/init.d/dnsmasq start
firejail --caps /etc/init.d/networking start
firejail --caps /etc/init.d/ebtables start
firejail --caps /etc/init.d/apf-firewall start
firejail --caps /etc/init.d/ start
firejail --caps /etc/init.d/ start
firejail --caps /etc/init.d/ start


firejail --caps /etc/init.d/ufw start
firejail --caps /etc/init.d/virtualbox start
firejail --caps /etc/init.d/vmaloader start


firejail --caps /etc/init.d/hwclock.sh start
ntp

firejail --caps /etc/init.d/apache2 start
firejail --caps /etc/init.d/apache-htcacheclean start
firejail --caps /etc/init.d/apparmor start
firejail --caps /etc/init.d/arpwatch start
firejail --caps /etc/init.d/binfmt-support start
firejail --caps /etc/init.d/ start
firejail --caps /etc/init.d/ start
firejail --caps /etc/init.d/ start
firejail --caps /etc/init.d/ start
firejail --caps /etc/init.d/ start

i2p






Chromium Web Browser


Root Terminal
gksu /usr/bin/x-terminal-emulator
Opens a terminal as the root user, using gksu to ask for the password
/usr/share/icons/gnome-colors-common/scalable/apps/gksu-root-terminal.svg


firejail --noroot xterm

firejail --zsh

adduser --shell /usr/bin/firejail $user




l [OPTIONS]                # starting a /bin/bash shell
l [OPTIONS] firefox        # starting Mozilla Firefox
firejail --allow-debuggers --profile=/etc/firejail/firefox.profile strace -f firefox
firejail --allusers
firejail --appimage krita-3.0-x86_64.appimage
firejail --appimage --private krita-3.0-x86_64.appimage
firejail --appimage --net=none --x11 krita-3.0-x86_64.appimage
firejail --blacklist=/sbin --blacklist=/usr/sbin
firejail --blacklist=~/.mozilla
firejail "--blacklist=/home/username/My Virtual Machines"
firejail --blacklist=/home/username/My\ Virtual\ Machines
firejail --caps.drop=all warzone2100
firejail --caps.keep=net_broadcast,net_admin,net_raw
firejail --name=mygame --caps.drop=all warzone2100 &
firejail --caps.print=mygame
firejail --list
firejail --caps.print=3272
firejail --chroot=/media/ubuntu warzone2100
firejail --cpu=0,1 handbrake
firejail --name=mygame --caps.drop=all warzone2100 &
firejail --cpu.print=mygame
firejail --list
firejail --cpu.print=3272
firejail --csh
firejail --debug firefox
firejail --debug-blacklists firefox
firejail --debug-caps
firejail --debug-check-filename firefox
firejail --debug-errnos
firejail --debug-protocols
firejail --debug-syscalls
firejail --debug-whitelists firefox
firejail --net=eth0 --defaultgw=10.10.20.1 firefox
firejail --dns=8.8.8.8 --dns=8.8.4.4 firefox
firejail --name=mygame --caps.drop=all warzone2100 &
firejail --dns.print=mygame
firejail --list
firejail --dns.print=3272
firejail --env=LD_LIBRARY_PATH=/opt/test/lib
firejail --name=mygame --caps.drop=all warzone2100 &
firejail --fs.print=mygame
firejail --list
firejail --fs.print=3272
firejail --hostname=officepc firefox
firejail --ignore=shell --ignore=seccomp firefox
firejail --interface=eth1 --interface=eth0.vlan100
firejail --net=eth0 --ip=10.10.20.56 firefox
firejail --net=eth0 --ip=none
firejail --net=eth0 --ip6=2001:0db8:0:f101::1/64 firefox
firejail --net=eth0 --iprange=192.168.1.100,192.168.1.150
firejail --ipc-namespace firefox
firejail --name=mygame --caps.drop=all warzone2100 &
firejail --join=mygame
firejail --list
firejail --join=3272
firejail --net=eth0 --name=browser firefox &
firejail --list
firejail --net=eth0 --mac=00:11:22:33:44:55 firefox
firejail --net=eth0 --mtu=1492
firejail --name=mybrowser firefox
firejail --net=br0 --net=br1
firejail --net=eth0 --ip=192.168.1.80 --dns=8.8.8.8 firefox
firejail --net=none vlc
firejail --net=eth0 --netfilter firefox
firejail --netfilter=/etc/firejail/webserver.net --net=eth0 \
firejail --netfilter=/etc/firejail/nolocal.net \
firejail --netstats
firejail --nice=2 firefox
firejail --no3d firefox
firejail
firejail --noblacklist=/bin/nc
firejail --noexec=/tmp
firejail --nogroups
firejail
firejail --noprofile
firejail --noroot
firejail --nosound firefox
firejail --output=sandboxlog /bin/bash
firejail --overlay firefox
firejail --overlay-named=jail1 firefox
firejail --overlay-tmpfs firefox
firejail --overlay-clean
firejail --private firefox
firejail --private=/home/netblue/firefox-home firefox
firejail --private-home=.mozilla firefox
firejail --private-bin=bash,sed,ls,cat
firejail --private-dev
firejail --private-etc=group,hostname,localtime, \
firejail --private-tmp
firejail --profile=myprofile
firejail --profile-path=~/myprofiles
firejail --profile-path=/home/netblue/myprofiles
firejail --protocol=unix,inet,inet6 firefox
firejail --name=mybrowser firefox &
firejail --protocol.print=mybrowser
firejail --list
firejail --protocol.print=3272
firejail --read-only=~/.mozilla firefox
firejail --whitelist=~/work --read-only=~ --read-only=~/work
firejail --read-only=~/test --read-write=~/test/a
firejail --rmenv=DBUS_SESSION_BUS_ADDRESS
firejail --net=eth0 --scan
firejail --seccomp
firejail --seccomp=utime,utimensat,utimes firefox
firejail --seccomp.drop=utime,utimensat,utimes
firejail --shell=none --seccomp.keep=poll,select,[...] transmission-gtk
firejail --seccomp.eperm=unlinkat
firejail --name=browser firefox &
firejail --seccomp.print=browser
firejail --shell=none script.sh
firejail --name=mygame --caps.drop=all warzone2100 &
firejail --shutdown=mygame
firejail --list
firejail --shutdown=3272
firejail --top
firejail --trace wget -q www.debian.org
firejail --tracelog firefox
firejail --tree
firejail --version
firejail --net=br0 --veth-name=if0
firejail --noprofile --whitelist=~/.mozilla
firejail --whitelist=/tmp/.X11-unix --whitelist=/dev/null
firejail "--whitelist=/home/username/My Virtual Machines"
firejail --x11 --net=eth0 firefox
firejail --x11=xephyr --net=eth0 openbox
firejail --x11=xorg firefox
firejail --x11=xpra --net=eth0 firefox
firejail --zsh
firejail --tree
firejail --apparmor firefox
firejail --name=mybrowser --private firefox
firejail --ls=mybrowser ~/Downloads
firejail --get=mybrowser ~/Downloads/xpra-clipboard.png
firejail --put=mybrowser xpra-clipboard.png ~/Downloads/xpra-clipboard.png
firejail --bandwidth=name|pid set network download upload
firejail --bandwidth=name|pid clear network
firejail --bandwidth=name|pid status
firejail --name=mybrowser --net=eth0 firefox &
firejail --bandwidth=mybrowser set eth0 80 20
firejail --bandwidth=mybrowser status
firejail --bandwidth=mybrowser clear eth0
firejail --audit transmission-gtk
firejail --audit=~/sandbox-test transmission-gtk
firejail --profile=/home/netblue/icecat.profile icecat
firejail icecat
firejail
firejail --noprofile


firejail --blacklist=/sbin --blacklist=/usr/sbin
firejail --chroot=
firejail --audit transmission-gtk
firejail --apparmor 
firejail --whitelist=~/.mozilla

firejail --trace wget -q www.debian.org
firejail --tracelog firefox
firejail --seccomp.print=browser


firejail --net=br0 --veth-name=if0
firejail --protocol.print=mybrowser
firejail --output=sandboxlog /bin/bash
firejail --overlay firefox
firejail --overlay-named=jail1 firefox
firejail --overlay-tmpfs firefox
firejail --overlay-clean
firejail --private firefox
firejail --private=/home/netblue/firefox-home firefox
firejail --private-home=.mozilla firefox
firejail --net=eth0 --mac=00:11:22:33:44:55 firefox
firejail --read-only=~/.mozilla firefox


firejail --csh
firejail --debug firefox
firejail --debug-blacklists firefox
firejail --debug-caps
firejail --debug-check-filename firefox
firejail --debug-errnos
firejail --debug-protocols
firejail --debug-syscalls
firejail --debug-whitelists firefox
firejail --net=eth0 --defaultgw=10.10.20.1 
firejail --bandwidth=mybrowser set eth0 80 20
firejail --bandwidth=name|pid clear network
firejail --bandwidth=name|pid status




firejail --ls=mybrowser ~/Downloads
firejail --get=mybrowser ~/Downloads/xpra-clipboard.png
firejail --put=mybrowser xpra-clipboard.png ~/Downloads/xpra-clipboard.png

firejail --netstats
firejail --tree
firejail --tree

firejail --read-only=~/.mozilla firefox
firejail --whitelist=~/work --read-only=~ --read-only=~/work
firejail --read-only=~/test --read-write=~/test/a
firejail --rmenv=DBUS_SESSION_BUS_ADDRESS
firejail --net=eth0 --scan




firejail --profile=/home/netblue/icecat.profile icecat



sed -i "s/\/etc\/firejail/\/home\/netblue\/myprofiles/g" *.profile

sed -i "s/\/etc\/firejail/\/home\/netblue\/myprofiles/g" *.inc



firejail --caps.drop=chown "$1"
firejail --caps.drop=dac_override "$1"
firejail --caps.drop=dac_read_search "$1"
firejail --caps.drop=fowner "$1"
firejail --caps.drop=fsetid "$1"
firejail --caps.drop=kill "$1"
firejail --caps.drop=setgid "$1"
firejail --caps.drop=setuid "$1"
firejail --caps.drop=setpcap "$1"
firejail --caps.drop=linux_immutable "$1"
firejail --caps.drop=net_bind_service "$1"
firejail --caps.drop=net_broadcast "$1"
firejail --caps.drop=net_admin "$1"
firejail --caps.drop=net_raw "$1"
firejail --caps.drop=ipc_lock "$1"
firejail --caps.drop=ipc_owner "$1"
firejail --caps.drop=sys_module "$1"
firejail --caps.drop=sys_rawio "$1"
firejail --caps.drop=sys_chroot "$1"
firejail --caps.drop=sys_ptrace "$1"
firejail --caps.drop=sys_pacct "$1"
firejail --caps.drop=sys_admin "$1"
firejail --caps.drop=sys_boot "$1"
firejail --caps.drop=sys_nice "$1"
firejail --caps.drop=sys_resource "$1"
firejail --caps.drop=sys_time "$1"
firejail --caps.drop=sys_tty_config "$1"
firejail --caps.drop=mknod "$1"
firejail --caps.drop=lease "$1"
firejail --caps.drop=audit_write "$1"
firejail --caps.drop=audit_control "$1"
firejail --caps.drop=setfcap "$1"
firejail --caps.drop=mac_override "$1"
firejail --caps.drop=mac_admin "$1"
firejail --caps.drop=syslog "$1"
firejail --caps.drop=wake_alarm "$1"








