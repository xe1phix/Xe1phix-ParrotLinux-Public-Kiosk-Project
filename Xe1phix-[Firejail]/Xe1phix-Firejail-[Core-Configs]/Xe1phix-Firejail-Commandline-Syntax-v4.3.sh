

sudo aa-logprof
aa-logprof -d/path/to/profile/directory/ 
aa-logprof -f/path/to/logfile/ 
sudo aa-notify -p -u USERNAME --display DISPLAY_NUMBER

/proc/*/attr/current


sudo aa-complain /etc/apparmor.d/usr.bin.thunderbird
sudo aa-enforce /etc/apparmor.d/usr.bin.thunderbird
sudo aa-enforce /etc/apparmor.d/sbin.
sudo aa-enforce -d /path/to/profiles/




./configure --prefix=/usr --enable-apparmor
aa-enforce firejail-default
firejail --apparmor firefox

journalctl | grep -i apparmor


sudo ln -s /usr/bin/firejail /usr/local/bin/firefox



firejail --profile=/etc/firejail/chromium.profile --debug chromium

firejail --debug --profile=/etc/firejail/firefox.profile firefox

firejail --caps.keep=sys_chroot,sys_admin,sys_time,sys_tty_config,wake_alarm chromium

firejail --caps.drop=sys_ptrace,kill,fsetid,dac_override,syslog,mac_admin,setuid,setgid,dac_read_search,linux_immutable,sys_module,net_admin,sys_rawio,net_bind_service,chown,fowner,sys_resource,ipc_owner,ipc_lock,mac_override,net_raw,sys_boot,net_broadcast,audit_read,audit_write,audit_control,setpcap,setfcap,block_suspend,mknod,lease,sys_nice,sys_pacct chromium

firejail  --caps.drop=sys_ptrace,kill,fsetid,dac_override,syslog,mac_admin,setuid,setgid,dac_read_search,linux_immutable,sys_module,net_admin,sys_rawio,net_bind_service,chown,fowner,sys_resource chromium
firejail --caps.print=23737


firejail --profile=/etc/firejail/google-chrome-stable --private=~/myprivatechrome google-chrome-stable


firejail --caps.drop=all --noroot --seccomp  /usr/bin/vlc --started-from-file %U


firejail --whitelist=~/.mozilla --whitelist=~/Downloads firefox


xdg-mime query default application/pdf
xdg-mime query default x-scheme-handler/irc
xdg-mime default hexchat.desktop x-scheme-handler/irc

xdg-mime query default x-scheme-handler/http
xdg-mime query default x-scheme-handler/https
xdg-mime query default text/html

xdg-mime default chromium-browser.desktop application/https
xdg-mime default chromium-browser.desktop application/https


firejail --profile=/etc/firejail/hexchat.profile hexchat

chattr +i 

firejail --profile=/home/heat/.config/firejail/libreoffice.profile /usr/bin/libreoffice "$@"

journalctl -e | grep syscall
ps aux | grep -e firejail -e firefox 

$ mkdir -p ~/.config/pulse
$ cd ~/.config/pulse
$ cp /etc/pulse/client.conf .
$ echo "enable-shm = no" >> client.conf 


sudo aa-enforce /etc/apparmor.d/usr.bin.firefox 
sudo apparmor_status 

firejail --caps.print=8422 

sudo -u username firejail …
sudo -u username firejail –allusers …

firejail --private=~/mykdenlive --appimage ~/Downloads/Kdenlive-17.12.0d-x86_64.AppImage




sudo mkdir -p /etc/default/grub.d
echo 'GRUB_CMDLINE_LINUX_DEFAULT="$GRUB_CMDLINE_LINUX_DEFAULT apparmor=1 security=apparmor"'  | sudo tee /etc/default/grub.d/apparmor.cfg
sudo update-grub



start a Firejail-friendly EncFS:
encfs -o allow_root ~/.crypt ~/crypt


SSHFS:
sshfs -o reconnect,allow_root netblue@192.168.1.25:/home/netblue/work work


firejail --net=br0 firefox

# host port 80 forwarded to sandbox port 80
iptables -t nat -A PREROUTING -p tcp --dport 80 -j DNAT --to 10.10.20.10:80


firejail --name=browser --net=eth0 firefox &
firejail --bandwidth=browser set eth0 80 20


## Apache server
firejail --net=eth0 --ip=192.168.1.244 /etc/init.d/apache2 start

# capabilities list for Apache server
caps.keep chown,sys_resource,net_bind_service,setuid,setgid

# capabilities list for nginx server
caps.keep chown,net_bind_service,setgid,setuid

# use a netfilter configuration
netfilter /etc/firejail/webserver.net

# instead of /var/www/html for webpages, use a different directory
bind /server/web1,/var/www/html




firejail –profile=/etc/firejail/transmission-gtk.profile /usr/bin/transmission-daemon -f –log-error

ps -ef|grep [t]ransmission

systemctl start transmission-daemon

transmission-daemon.service:
NotifyAccess=all







–blacklist=/media
–disable-mnt





firejail –join=PID ls -al




$ sudo paxctl -c /usr/lib/firefox/firefox
$ sudo paxctl -m /usr/lib/firefox/firefox
$ sudo paxctl -c /usr/lib/firefox/plugin-container
$ sudo paxctl -m /usr/lib/firefox/plugin-container

checksec --proc-all
checksec --proc-libs 123




firejail --build vlc ~/Videos/test.mp4


firejail --build /usr/bin/pluma %U
firejail --build /usr/bin/firefox
firejail --build /usr/bin/mpv --player-operation-mode=pseudo-gui
firejail --build /usr/bin/atril %U
firejail --build /usr/bin/qbittorrent %U
firejail --build /usr/bin/thunderbird %u
firejail --build /usr/bin/claws-mail %u
firejail --build /usr/bin/hexchat --existing %U
firejail --build /usr/bin/mat-gui
firejail --build /usr/bin/torchat
firejail --build /usr/bin/QOwnNotes
firejail --build /usr/bin/engrampa %U
firejail --build /usr/bin/eom '/home/xe1phix/Downloads/b/1567736072939.jpg'
firejail --build /usr/bin/audacious %U
firejail --build /usr/bin/vlc --started-from-file %U
firejail --build /usr/bin/geany %F






