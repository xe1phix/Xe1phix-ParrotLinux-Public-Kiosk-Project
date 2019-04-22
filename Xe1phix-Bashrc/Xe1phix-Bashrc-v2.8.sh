# ~/.bashrc: executed by bash(1) for non-login shells.
# see /usr/share/doc/bash/examples/startup-files (in the package bash-doc)
# for examples

# If not running interactively, don't do anything
case $- in
    *i*) ;;
      *) return;;
esac

export PATH=/usr/local/bin:/usr/bin:/bin:/usr/local/games:/sbin:/usr/sbin:/usr/games:/usr/share/games

# don't put duplicate lines or lines starting with space in the history.
# See bash(1) for more options
HISTCONTROL=ignoreboth

# append to the history file, don't overwrite it
shopt -s histverify
shopt -s histappend

# create HISTFILE if not exist
if [ ! -r "$HISTFILE" ]; then
    touch "$HISTFILE"
fi

# for setting history length see HISTSIZE and HISTFILESIZE in bash(1)
HISTSIZE=100000
HISTFILESIZE=200000


## export HISTTIMEFORMAT="%F %T "				# Add timestamp to history




# check the window size after each command and, if necessary,
# update the values of LINES and COLUMNS.
shopt -s checkwinsize

# If set, the pattern "**" used in a pathname expansion context will
# match all files and zero or more directories and subdirectories.
#shopt -s globstar


# set session timeout for root
if [ "${USER}" = "root" ]
then
  TMOUT=1200
fi

export GREP_OPTIONS="--color=auto"

# make less more friendly for non-text input files, see lesspipe(1)
#[ -x /usr/bin/lesspipe ] && eval "$(SHELL=/bin/sh lesspipe)"

# set variable identifying the chroot you work in (used in the prompt below)
if [ -z "${debian_chroot:-}" ] && [ -r /etc/debian_chroot ]; then
    debian_chroot=$(cat /etc/debian_chroot)
fi

# set a fancy prompt (non-color, unless we know we "want" color)
case "$TERM" in
    xterm-color) color_prompt=yes;;
esac

# uncomment for a colored prompt, if the terminal has the capability; turned
# off by default to not distract the user: the focus in a terminal window
# should be on the output of commands, not on the prompt
force_color_prompt=yes

if [ -n "$force_color_prompt" ]; then
    if [ -x /usr/bin/tput ] && tput setaf 1 >&/dev/null; then
	# We have color support; assume it's compliant with Ecma-48
	# (ISO/IEC-6429). (Lack of such support is extremely rare, and such
	# a case would tend to support setf rather than setaf.)
	color_prompt=yes
    else
	color_prompt=
    fi
fi

if [ "$color_prompt" = yes ]; then
    PS1="\[\033[0;31m\]\342\224\214\342\224\200\$([[ \$? != 0 ]] && echo \"[\[\033[0;31m\]\342\234\227\[\033[0;37m\]]\342\224\200\")[$(if [[ ${EUID} == 0 ]]; then echo '\[\033[01;31m\]root\[\033[01;33m\]@\[\033[01;96m\]\h'; else echo '\[\033[0;39m\]\u\[\033[01;33m\]@\[\033[01;96m\]\h'; fi)\[\033[0;31m\]]\342\224\200[\[\033[0;32m\]\w\[\033[0;31m\]]\n\[\033[0;31m\]\342\224\224\342\224\200\342\224\200\342\225\274 \[\033[0m\]\[\e[01;33m\]\\$\[\e[0m\]"
else
    PS1='┌──[\u@\h]─[\w]\n└──╼ \$ '
fi
unset color_prompt force_color_prompt

# If this is an xterm set the title to user@host:dir
case "$TERM" in
xterm*|rxvt*)
    PS1="\[\033[0;31m\]\342\224\214\342\224\200\$([[ \$? != 0 ]] && echo \"[\[\033[0;31m\]\342\234\227\[\033[0;37m\]]\342\224\200\")[$(if [[ ${EUID} == 0 ]]; then echo '\[\033[01;31m\]root\[\033[01;33m\]@\[\033[01;96m\]\h'; else echo '\[\033[0;39m\]\u\[\033[01;33m\]@\[\033[01;96m\]\h'; fi)\[\033[0;31m\]]\342\224\200[\[\033[0;32m\]\w\[\033[0;31m\]]\n\[\033[0;31m\]\342\224\224\342\224\200\342\224\200\342\225\274 \[\033[0m\]\[\e[01;33m\]\\$\[\e[0m\]"
    ;;
*)
    ;;
esac

# enable color support of ls and also add handy aliases
if [ -x /usr/bin/dircolors ]; then
    test -r ~/.dircolors && eval "$(dircolors -b ~/.dircolors)" || eval "$(dircolors -b)"
fi


if [ $EUID -ne 0 ]; then
  alias reboot='sudo /sbin/reboot'
  alias shutdown='sudo /sbin/shutdown'



## ############################################################################################$#### ##
## ################################### Director Transversing ####################################### ##
## ================================================================================================= ##
## ------------------------------------------------------------------------------------------------------------- ##
alias ..='cd ..'         # Go up one directory
alias ...='cd ../..'     # Go up two directories
alias ....='cd ../../..' # Go up three directories
alias -- -='cd -'        # Go back
## ------------------------------------------------------------------------------------------------------------- ##
mcdir () { mkdir -p "$@" && cd "$@"; }				## Create a directory and change into it at the same time	
## ------------------------------------------------------------------------------------------------------------- ##
## ================================================================================================= ##


alias dd="dd status=progess if=$1 of=$2"
alias cdsha1="dd if=/dev/sr0 | pv -s 700m | sha1sum | tee cdrom.sha1"
alias cdsha256="dd if=/dev/sr0 | pv -s 700m | sha256sum | tee cdrom.sha256"
alias cdsha512="dd if=/dev/sr0 | pv -s 700m | sha512sum | tee cdrom.sha512"
alias 256="sha256sum $1"
alias hash="sha1sum $1 && sha256sum $1 && sha512sum $1"


## ############################################################################################$#### ##
## ############################# Files && Directory Concatenate #################################### ##
## ================================================================================================= ##
alias ls='ls --all --color=always --classify --group-directories-first --human-readable -lZ'
alias lsinfo='ls --all --color=always --classify --group-directories-first --human-readable --size --numeric-uid-gid --file-type -Z'
alias lsrecurse='ls --all --color=always --recursive --classify --group-directories-first --human-readable --size --numeric-uid-gid'
alias lssingle='ls --all --group-directories-first --format=single-column --file-type --numeric-uid-gid --color=always'
## ------------------------------------------------------------------------------------------------------------- ##
alias dir='dir --color=auto'
alias vdir='vdir --color=auto'
alias lsdir='ls -d */'								## List only the directories
alias findhour='find / -mmin 60 -type f'			## Find files that have been modified on your system in the past 60 minutes
## ------------------------------------------------------------------------------------------------------------- ##
alias lsd='ls -l | grep "^d"'		
## alias lsd='ls -l | awk '/^d/ { print $NF } ' '
## alias lsd='ls -l | grep "^d" | cut -d" " -f9- '

## ================================================================================================= ##



## ================================================================================================= ##
alias statz='stat --format=[%A/%a]:[%n]:[Size:%s.bytes]:[Uid:%u]:[User:%U]:[Group:%G]:[GID:%g]:[IO-Block:%o]:[File-type:%F]:[Inode:%i]'
## ================================================================================================= ##




## ############################################################################################$#### ##
## ############################# Daemons && Service Administration ################################# ##
## ================================================================================================= ##
alias service='service --status-all'
alias chkliston='(chkconfig --list | grep "\bon\b")'
## ------------------------------------------------------------------------------------------------- ##
alias chkconfigon='/sbin/chkconfig --list | grep 5:on'
alias chkconfigoff='/sbin/chkconfig --list | grep 5:off'
## ------------------------------------------------------------------------------------------------- ##
alias initdenabled='(grep disable /etc/xinetd.d/* |grep no)'
## ------------------------------------------------------------------------------------------------- ##
alias sysjobs='systemctl list-jobs'
alias isenabled='systemctl is-enabled'
## ------------------------------------------------------------------------------------------------- ##
alias sysservicedisabled='systemctl list-unit-files --type=service | grep -v disabled'
alias sysserviceenabled='systemctl list-unit-files --type=service | grep -v enabled'
## ------------------------------------------------------------------------------------------------- ##
alias sysmultireq='systemctl show --property "Requires" multi-user.target'
alias sysgettywant='systemctl show --property "WantedBy" getty.target'
## ------------------------------------------------------------------------------------------------- ##
alias syslistunittarget='systemctl list-units --type=target --all'
alias sysshutdown='systemctl isolate poweroff.target'
alias poweroff='systemctl isolate poweroff.target'
alias multiuser='systemctl isolate multi-user.target'
alias syslistservice='systemctl list-unit-files --type service --all'
alias sysmultiwants='ls /etc/systemd/system/multi-user.target.wants'
## ------------------------------------------------------------------------------------------------- ##
## alias sys=''
## ================================================================================================= ##





## ================================================================================================= ##
alias memtosync='grep ^Dirty /proc/meminfo'
## ------------------------------------------------------------------------------------------------- ##
alias catstat='(cat /proc/*/stat | awk '{print $1,$2}')'
## ------------------------------------------------------------------------------------------------- ##
alias stringssystemd='strings /sbin/init | xargs strings systemd'
## ------------------------------------------------------------------------------------------------- ##
alias stringspci='od -c --strings /usr/bin/setpci'
## ------------------------------------------------------------------------------------------------- ##




## ############################################################################################$#### ##
## ########################################### Openssl ############################################# ##
## ================================================================================================= ##
alias listdigests='openssl list-message-digest-commands'
alias listciphers='openssl list-cipher-commands'
## ------------------------------------------------------------------------------------------------- ##



## ############################################################################################$#### ##
## ############################################ Time ############################################### ##
## ================================================================================================= ##
## 
## ------------------------------------------------------------------------------------------------- ##
alias settimezone='timedatectl set-timezone America/Chicago'
alias listtimezones='timedatectl list-timezones'
## ------------------------------------------------------------------------------------------------- ##
## 




if [ $EUID -ne 0 ]; then
  alias reboot='sudo /sbin/reboot'
  alias shutdown='sudo /sbin/shutdown'
fi



## ############################################################################################$#### ##
## ########################################## Networking ########################################### ##
## ================================================================================================= ##
alias netstop='echo "[+] Stopping The Networking Service..."; systemctl stop networking; chkconfig networking off; /etc/init.d/networking stop; service networking stop'
alias netstart='echo "[+] Starting The Networking Service..."; systemctl start networking; chkconfig networking on; /etc/init.d/networking start; service networking start'
## ------------------------------------------------------------------------------------------------------------- ##
alias bluestop='echo "[+] Stopping The Bluetooth Service..."; systemctl stop bluetooth; chkconfig bluetooth off; /etc/init.d/bluetooth stop; service bluetooth stop'
alias bluedisable='echo "[+] Disabling The Bluetooth Service..."; systemctl disable bluetooth; /etc/init.d/bluetooth disable; service bluetooth disable; update-rc.d bluetooth disable'
## ------------------------------------------------------------------------------------------------------------- ##
## alias stop='echo "[+] Disabling The  Service..."; systemctl disable ; /etc/init.d/ disable; service  disable; update-rc.d  disable'
## alias stop='echo "[+] Disabling The  Service..."; systemctl disable ; /etc/init.d/ disable; service  disable; update-rc.d  disable'
## alias stop='echo "[+] Disabling The  Service..."; systemctl disable ; /etc/init.d/ disable; service  disable; update-rc.d  disable'
## alias stop='echo "[+] Disabling The  Service..."; systemctl disable ; /etc/init.d/ disable; service  disable; update-rc.d  disable'
## alias stop='echo "[+] Disabling The  Service..."; systemctl disable ; /etc/init.d/ disable; service  disable; update-rc.d  disable'
## ------------------------------------------------------------------------------------------------------------- ##
## alias netstop='echo "[+] Enabling && Starting The  Service..."; systemctl enable; systemctl  start; /etc/init.d/ start; service  enable; service  start; update-rc.d  enable; chkconfig  on'
## alias netstop='echo "[+] Enabling && Starting The  Service..."; systemctl enable; systemctl  start; /etc/init.d/ start; service  enable; service  start; update-rc.d  enable; chkconfig  on'
## alias netstop='echo "[+] Enabling && Starting The  Service..."; systemctl enable; systemctl  start; /etc/init.d/ start; service  enable; service  start; update-rc.d  enable; chkconfig  on'
## alias netstop='echo "[+] Enabling && Starting The  Service..."; systemctl enable; systemctl  start; /etc/init.d/ start; service  enable; service  start; update-rc.d  enable; chkconfig  on'
## alias netstop='echo "[+] Enabling && Starting The  Service..."; systemctl enable; systemctl  start; /etc/init.d/ start; service  enable; service  start; update-rc.d  enable; chkconfig  on'
## ------------------------------------------------------------------------------------------------------------- ##
##
## ------------------------------------------------------------------------------------------------------------- ##
alias paxctldstart='echo "[+] Enabling && Starting The paxctld Service..."; systemctl enable paxctld; systemctl start paxctld; /etc/init.d/paxctld start; service paxctld enable; service paxctld start; update-rc.d paxctld enable; chkconfig paxctld on'
## ------------------------------------------------------------------------------------------------------------- ##





## ------------------------------------------------------------------------------------------------------------- ##
## alias stop='echo "[+] Disabling The  Service..."; systemctl disable ; /etc/init.d/ disable; service  disable; update-rc.d  disable'
## alias stop='echo "[+] Disabling The  Service..."; systemctl disable ; /etc/init.d/ disable; service  disable; update-rc.d  disable'
## ------------------------------------------------------------------------------------------------------------- ##
## network-manager
## apache2
## postgresql
## mysql
## apf-firewall
## ulogd2
## ufw
## apparmor
## auditd
## ebtables
## ferm
## greenbone-security-assistant
## gnunet
## i2p
## sagan
## samhain
## suricata
## snort
## xplico
## selinux-autorelabel
## tor
## openvpn
## 
## ------------------------------------------------------------------------------------------------------------- ##


## ------------------------------------------------------------------------------------------------------------- ##
alias netrestart="/etc/init.d/networking restart"
alias ifconfig='(ip a; ip addr; ip addr show; ifconfig -a; iwconfig -a)'
alias ifconfigeth0='/sbin/ifconfig eth0 hw ether 00:30:65:e4:98:27'
alias ifconfigwlan0='/sbin/ifconfig wlan0 hw ether 00:40:96:f4:34:67'
alias ifconfigwlan1='/sbin/ifconfig wlan1 hw ether 00:30:65:35:2e:37'
alias ifconfigdown='(/sbin/ifconfig $IFACE down; ip link set $IFACE down; ifdown $IFACE; rfkill block all'
alias blockall='rfkill block all'
alias unblock='/usr/sbin/rfkill unblock wifi'
alias ifconfig-eth='ifconfig -a | grep eth'
alias ifconfig-wlan='ifconfig -a | grep wlan'
## ----------------------------------------------------------------------------------------------- ##
alias wifimod='iwlist modulation'
## ----------------------------------------------------------------------------------------------- ##
alias disableipv6='echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6; echo 1 > /proc/sys/net/ipv6/conf/default/disable_ipv6'
## ----------------------------------------------------------------------------------------------- ##

## ======================================================================================================================================= ##
alias killbluetooth='/usr/sbin/rfkill block bluetooth && /sbin/chkconfig bluetooth off && /usr/sbin/update-rc.d bluetooth remove'
alias netstat='netstat -tulanp'
alias dns="/bin/grep 'nameserver' /etc/resolv.conf | awk '{print $2}'"
alias broadcast="/sbin/ifconfig | grep 'broadcast' | awk '{print $2}'"
alias ip='ip addr show && ip addr list'
alias mac="/sbin/ifconfig | grep 'ether' | awk '{print $2}'"
alias ports="netstat -tulanp >> ports.txt && /bin/cat -vT ports.txt"
## ----------------------------------------------------------------------------- ##
alias tcpservices='grep -vi tcp /etc/services'
alias udpservices='grep -vi tcp /etc/services'
alias sshpid='(eval `ssh-agent`)'
alias netstatlisten='(netstat -tap |grep LISTEN)'
## ----------------------------------------------------------------------------- ##
## ======================================================================================================================================= ##



## ##################################################################################################$#### ##
## ############################## Various Wireless Cracking Utils Aliases  ############################### ##
## ======================================================================================================= ##
alias airodump-ng="airodump-ng --manufacturer --wps --uptime"
## ------------------------------------------------------------------------------------------------- ##


## ======================================================================================================= ##
##### Metasploit
alias msfc="systemctl start postgresql; msfdb start; msfconsole"
alias msfconsole="systemctl start postgresql; msfdb start; msfconsole; armitage"

## ======================================================================================================= ##
##### OpenVAS
alias openvas="openvas-stop; openvas-start; sleep 3s; xdg-open https://127.0.0.1:9392/"
alias openvasupdate='mkdir -p /var/lib/openvas/gnupg/; cd /var/lib/openvas/gnupg/; curl --progress -k -L "http://www.openvas.org/OpenVAS_TI.asc" | gpg --import - ; greenbone-nvt-sync'
alias openvascreateuser='(openvasmd --create-user="$username"; openvasmd --user="$username" --new-password="$password"; openvasmd --user=root --new-password='@'")'
alias openvascheck="openvas-check-setup"
alias openvasadduser="openvas-adduser; openvasad --enable-modify-settings -c set_role -u $user -r $admin"

## ----------------------------------------------------------------------------------------------- ##
alias openvaswebui='openvas-start; sleep 3s; xdg-open https://127.0.0.1:9392/; echo -e "\t\tOpenVAS web UI; echo -e "\t\t\thttp://127.0.0.1:9392/login/login.html'

## ----------------------------------------------------------------------------------------------- ##
alias nmaplist='cat ${iplist} | xargs -n1 nmap -sV'

## ----------------------------------------------------------------------------------------------- ##
alias ssh-start="systemctl restart ssh"
alias ssh-stop="systemctl stop ssh"
## ----------------------------------------------------------------------------------------------- ##
alias status='systemctl list-units --full --all; systemctl --full --no-legend --no-pager --type=service --state=running list-units; systemctl list-unit-files --type=service; service --status-all | grep running'
## ----------------------------------------------------------------------------------------------- ##
alias serviceenabled='systemctl list-unit-files --type=service | grep -v disabled; '
## ----------------------------------------------------------------------------------------------- ##


## ############################################################################# ##
## ############################### DPKG Aliases ################################ ##
## ============================================================================= ##
alias depends='dpkg-deb --info '				## Queries .deb packages prereq
alias depgrep='$(depends) | grep Depends:'		## 
alias sizegrep='| grep Installed-Size:'			## 
dpkg-query -Wf '${Installed-Size}\t${Package}\n' | sort -n

aptitude remove $(dpkg -l|egrep '^ii  linux-(im|he)'|awk '{print $2}'|grep -v `uname -r`)
## 
## ----------------------------------------------------------------------------------------------- ##
libstatus='gcc-config -l; ldconfig --print-cache
alias getent='getent ahosts; getent ahostsv6; getent ethers; getent gshadow; getent netgroup; getent passwd; getent rpc; getent shadow; getent ahostsv4; getent aliases; getent group; getent hosts; getent networks; getent protocols; getent services' 
## ----------------------------------------------------------------------------------------------- ##
## 
## ============================================================================= ##


###################################################################################
################################## Git Aliases ####################################
## ============================================================================= ##
alias gitcheckout="git checkout master "	## start from the master branch
alias newbranch="git branch "				## create a new branch
alias gitswitch="git checkout "				## switch to the new branch
alias gitfetch='git fetch --all --prune'
## ============================================================================= ##


alias timestamp='date "+%Y%m%dT%H%M%S"'



alias alert='notify-send -i /usr/share/icons/gnome/32x32/apps/gnome-terminal.png "[$?] $(history|tail -n1|sed -e '\''s/^\s*[0-9]\+\s*//;s/;\s*alert$//'\'')"'



## ############################################################################# ##
## ############################### Sed Editor Aliases #####@@################### ##
## ============================================================================= ##
# alias sedaddtobegin="sed -e 's/^/<$Input>/'"			## Add to the beginning of each line
# alias sedaddtoend="sed -e 's/$/<$Input>/'"			## Add to the end of each line
alias Capitalize='$(sed 's/\b\(.\)/\u\1/g')'			## Capitalize the first letter of every word
alias RemoveBlank='$(sed '/^$/d')'						## Removes all blank lines in a document
## ============================================================================= ##


## ############################################################################# ##
## ################## Regular Expression Parsers Aliases ####################### ##
## ============================================================================= ##
alias egrep='egrep --color=auto'
alias cat='/bin/cat '
alias grep='grep --color=auto'
alias fgrep='fgrep --color=auto'
## ----------------------------------------------------------------------------- ##
alias repoenabled="(egrep '^deb' /etc/apt/sources.list)"
alias repodisabled="(egrep '^[#|#+] deb' /etc/apt/sources.list)"
## ----------------------------------------------------------------------------- ##
alias nocomment='grep -Ev '\''^(#|$)'\'''		# print file without comments
## ============================================================================= ##




## ============================================================================= ##
alias chmodu='chmod -v 0755'
alias chmodur='chmod -v -R 0755'
alias chmodr='chmod -v 0644'
alias chmodrr='chmod -v -R 0644'
## ----------------------------------------------------------------------------- ##
alias chmodu='chown -v xe1phix:xe1phix'
alias chmodur='chown -v -R xe1phix:xe1phix'
alias chmodr='chown -v root:root'
alias chmodrr='chown -v -R root:root'
## ----------------------------------------------------------------------------------------------- ##
find $HOME -type d -perm 777 -exec chmod 755 {} \; -print
modinfo $(cut -d' ' -f1 /proc/modules) | sed '/^dep/s/$/\n/; /^file\|^desc\|^dep/!d'
ls -1 /lib/modules
find public_html/ -type d -exec chmod 755 {} +
chmod 644 $(find . -type f)


alias chmodown="chmod -v -R ugo+rwx $1 && chown -v xe1phix:xe1phix -R $1"


## ############################################################################# ##
## ####################### File Manipulation Aliases ########################### ##
## ============================================================================= ##
alias cp='cp --verbose --recursive --parents'
alias mkdirsu='mkdir --mode=0620'
## ----------------------------------------------------------------------------- ##
alias shred='shred --verbose --iterations=7 --zero --force'
alias rm='rm --quiet --recursive --force ' 
## ============================================================================= ##







## ############################################################################################## ##
## ===================================== Mount  Aliases  ======================================== ##
## ============================================================================================== ##
alias mountacl="mount -t ext3 /dev/mapper/parrot--vg-root / -o acl,nosuid,usrquota,grpquota"
alias mountquota='mount -t ext3/dev/mapper/parrot--vg-root / -o acl,nosuid,usrquota,grpquota'
## =============================================================================================== ##



## ############################################################################################## ##
## ===================================== History  Aliases ======================================= ##
## ============================================================================================== ##
alias history="history | cut -c8-200"
alias histgrep="history | cut -c8-199 | grep"
alias top10hist="(history | awk '{a[$2]++}END{for(i in a){print a[i] " " i}}' | sort -rn | head)"
## ----------------------------------------------------------------------------------------------- ##
alias histlastuntil='until !!; do :; done'				# Retry the previous command until it exits successfully
## =============================================================================================== ##




echo ".mode tabs select host, case when host glob '.*' then 'TRUE' else 'FALSE' end, path, case when isSecure then 'TRUE' else 'FALSE' end, expiry, name, value from moz_cookies;" | sqlite3 ~/.mozilla/firefox/*.default/cookies.sqlite





## ============================================================================= ##
## ###################### Service Stuffz Aliases ############################### ##
## ============================================================================= ##
alias msfc='service postgresql start; service metasploit start; msfconsole -q \"$@\""\n'
alias openvasrestart='echo -n "[*] Restarting Openvas Service..." ;service openvas-manager restart; service openvas-scanner restart; service greenbone-security-assistant restart; xdg-open https://127.0.0.1:9392/'
alias openvasrestart='echo -n "[*] Updating & Fetching Openvas Feeds & Certs..."; openvas-certdata-sync; openvas-feed-update; openvas-portnames-update; openvas-nvt-sync, openvas-scapdata-sync; xdg-open https://127.0.0.1:9392/'
alias openvasrestart='echo -n "[*] Restarting Openvas Service..." ;service openvas-manager restart; service openvas-scanner restart; service greenbone-security-assistant restart; xdg-open https://127.0.0.1:9392/'
alias openvascheck='openvas-check-setup'
## ----------------------------------------------------------------------------------------------- ##
alias nexpose='service postgresql stop ; cd /opt/rapid7/nexpose/nsc ; ./nsc.sh'
## ----------------------------------------------------------------------------------------------- ##

## ========================================================================== ##
## ==================== Package Management Aliases ========================== ##
## ========================================================================== ##
## ----------------------------------------------------------------------------------------------- ##
alias update='echo; echo -n "[*] Updating Your Bullshit..." ; echo; apt-get update; echo ;'
## ----------------------------------------------------------------------------------------------- ##










## ============================================================================= ##


## ============================================================================= ##
## ########################## AV Stuffz Aliases ################################ ##
## ============================================================================= ##
##
## ======================================================================================================================================================== ##
alias sshstop='/usr/sbin/update-rc.d sshd disable; /usr/sbin/update-rc.d sshd remove; /sbin/chkconfig ssh off'
alias chk='chkconfig --allservices --list'
alias rkhunter-cvs='/usr/bin/rkhunter --check --verbose-logging --summary --logfile /var/log/Beastiality/Hunter.log --appendlog --display-logfile --enable all --nocolors --skip-keypress --syslog authpriv.notice'
alias rkhunter-cron='/usr/bin/rkhunter --quiet --check --verbose-logging --summary --cronjob --logfile /var/log/rkhunter.log --appendlog --display-logfile --enable all --nocolors --skip-keypress --syslog authpriv.notice'
## ======================================================================================================================================================== ##


bootuuid=`blkid -s UUID -o value "$dev_boot"1`
rootuuid=`blkid -s UUID -o value "$dev_root"`
swapuuid=`blkid -s UUID -o value "$dev_swap"`



## ============================================================================= ##
## ####################### Hardware Diagnostics Aliases ######################## ##
## ============================================================================= ##
alias sfdisk='sfdisk --show-size; sfdisk --show-pt-geometry; sfdisk --show-geometry'
alias fdisk='fdisk -c -u -l "/dev/sd[a-z][1-9]"'
alias parted='parted /dev/sda print'
alias tune2fs='tune2fs -l /dev/hda1 | grep Reserved >> /var/log/tune2fs.txt && /bin/cat -vET /var/log/tune2fs.txt'
alias partitions='(grep sda /proc/partitions; parted /dev/sda print; parted --list; partprobe --summary; pvdisplay /dev/sda2; blockdev --getbsz /dev/sda1; smartctl -a /dev/sda; free -m) > /var/log/Partions.txt && cat -vET /var/log/Partions.txt' 
alias lsblk='(lsblk --topology; lsblk --perms; lsblk --fs; lsblk --all; lsblk --raw) >> /var/log/lsblk.txt && cat /var/log/lsblk.txt'
alias lvmdisplay='(pvdisplay --columns --all --verbose; vgdisplay --verbose; vgck --verbose; lvdisplay; lvmdump; lvmdiskscan) >> /var/log/LvmInformation.txt && cat -vET /var/log/LvmInformation.txt'
alias fdisk-sda='fdisk -cul /dev/sda | grep /dev/sda'
alias sfdisk='sfdisk --show-size --show-pt-geometry --show-geometry'
alias raidstat='cat /proc/rd/status'
## ======================================================================================================================================================== ##



## ========================================================================== ##
alias pcidevices='cat -vET /proc/bus/pci/devices'
alias inputdevices='cat -vET /proc/bus/input/devices'
alias handlers='cat -vET /proc/bus/input/handlers'
alias serial='cat -vET /proc/tty/driver/serial'
alias ldiscs='cat -vET /proc/tty/ldiscs'
alias drivers='cat -vET /proc/tty/drivers'
## ========================================================================== ##




## ----------------------------------------------------------------------------------------------------------- ##
alias vmstat='(vmstat --stats; vmstat --slabs; vmstat --active; vmstat --one-header; vmstat --disk-sum; vmstat --disk) >> /var/log/vmstat.log && cat /var/log/vmstat.log | less'
alias netstat='(netstat --all; netstat --programs; netstat --statistics; netstat --groups; netstat --interfaces; netstat --route) > /var/log/netstat.log && cat /var/log/netstat.log | less'
## ----------------------------------------------------------------------------------------------------------- ##
alias dmidecode='(dmidecode --type 127; dmidecode --type 4;  dmidecode --type 3; dmidecode --type 2; dmidecode --type 16; dmidecode --type 19; 22; dmidecode --type 7; dmidecode --type 11; dmidecode --type 0; dmidecode --type 1) >> dmitypes.txt && cat dmitypes.txt | less'
## ----------------------------------------------------------------------------------------------------------- ##

## ========================================================================== ##
## ======================= Raw Mem Debugging Aliases ======================== ##
## ========================================================================== ##
alias dmesg='(dmesg --kernel; dmesg --raw; dmesg --userspace; dmesg) >> /var/log/dmesg.log && cat -vET dmesg.log'
alias iomem='grep "System RAM" /proc/iomem'
## ========================================================================== ##






#######################################################################
#################### Hashsum Verification Aliases #####################
## ================================================================= ##
alias sha1='openssl sha1'
alias sha256='openssl sha256'
alias sha512='openssl sha512'
## ----------------------------------------------------------------------------------------------------------- ##
alias dpkglist="$(dpkg -l | awk '/^ii/{print $2}')"
## ----------------------------------------------------------------------------------------------------------- ##




## ================================================================= ##
## ==================== Process Administration ===================== ##
## ================================================================= ##
alias top10ps='(ps aux | sort -nk +4 | tail)'
## ================================================================= ##



## ========================================================================== ##
## ================================ Aliases ================================ ##
## ========================================================================== ##
alias banner="cat /etc/issue.net"
## ================================================================= ##



## ========================================================================== ##
## ======================= Sed Regex Aliases ================================ ##
## ========================================================================== ##
alias RemoveBlank='sed '/^$/d' $1'                  # Remove blank lines
alias Capitalize='sed 's/\b\(.\)/\u\1/g' $1'		# Capitalize the first letter of every word
## ========================================================================== ##


## ========================================================================== ##
## ==================== Logs & Processes Aliases ============================ ##
## ========================================================================== ##
alias dmesgirq='(dmesg | grep -i irq)'		# show all interrupts found by the kernel during boot process
alias dmesgdma='(dmesg | grep -i dma)'			# shows dma capable devices during boot process
## ----------------------------------------------------------------------------------------------------------- ##
alias 30='dmesg | tail -n 30 | ccze -A'
alias 300='dmesg | tail -n 300 | ccze -A'
alias fuck='sudo killall '
alias damn='sudo kill -9 `pgrep $2` '
alias journalk='(journalctl -k >> /home/faggot/journalctlkernellog.txt)'
alias journalh='(journalctl --since "1 hour ago")'
alias journalssh='journalctl -u sshd.service'
alias journaldhcp='(journalctl -b | egrep "dhc")'
## ----------------------------------------------------------------------------------------------------------- ##
alias tail500='(tail ‐n 500 /var/log/messages)'     				 # Last 500 kernel/syslog messages 
alias tailicmp='(tail /var/log/messages |grep ICMP |tail -n 1)'
alias tailudp='(tail /var/log/messages | grep UDP | tail -n 1)'
alias tailtcp='(tail /var/log/messages | grep TCP | tail -n 1)'
## ----------------------------------------------------------------------------------------------------------- ##
alias who='(who --boot; who --all; who --mesg; who --ips; who -T; who --dead; who -b -d --login -p -r -t -T -u)'
alias environment='(printenv; env; set; whoami; uptime; id -a; umask -p; systemctl environment)'
## ----------------------------------------------------------------------------------------------------------- ##


diff -urp /originaldirectory /modifieddirectory



## ================================================================= ##


## ----------------------------------------------------------------------------------------------------------- ##
alias checkstack='objdump -d /boot/vm* | scripts/checkstack.pl'
## ----------------------------------------------------------------------------------------------------------- ##


## ----------------------------------------------------------------------------------------------------------- ##
alias hwclock='hwclock --show'
alias timereconf='dpkg-reconfigure tzdata'
## ----------------------------------------------------------------------------------------------------------- ##








## ----------------------------------------------------------------------------------------------------------- ##
alias modblacklist='modprobe --showconfig | grep blacklist'
awk '{print $1}' "/proc/modules" | xargs modinfo | awk '/^(filename|desc|depends)/'


## ----------------------------------------------------------------------------------------------------------- ##


## ----------------------------------------------------------------------------------------------------------- ##
alias uidmin='(awk '/^UID_MIN/{print$2}'	/etc/login.defs)'
alias uidmax='(awk '/^UID_MAX/{print$2}'	/etc/login.defs)'
alias sysuidmax='(awk '/^SYS_UID_MAX/{print$2}'	/etc/login.defs)'
## ----------------------------------------------------------------------------------------------------------- ##


alias launchpadkey="sudo apt-key adv --keyserver keyserver.ubuntu.com --recv-keys"

sudo apt-get update 2> /tmp/keymissing; for key in $(grep "NO_PUBKEY" /tmp/keymissing |sed "s/.*NO_PUBKEY //"); do echo -e "\nProcessing key: $key"; gpg --keyserver pool.sks-keyservers.net --recv $key && gpg --export --armor $key |sudo apt-key add -; done

gpg --gen-random --armor 1 30




## ----------------------------------------------------------------------------------------------------------- ##
GnupgGenKey="gpg --enable-large-rsa --full-gen-key"
GnupgKeyImport="gpg --keyid-format 0xlong --import"
gpgrecv="gpg --keyserver x-hkp://pool.sks-keyservers.net --recv-keys 0x"
GnupgVerify="gpg --keyid-format 0xlong --verify"
gpgencrypt="gpg -c --s2k-cipher-algo AES256 --s2k-digest-algo SHA512 --s2k-count 65536 "
GnupgHome="/home/xe1phix/.gnupg/"

alias GPGClearSigRelease='$(gpg --clearsign -o InRelease Release)'
alias GPGClearSigReleaseSig='$(gpg -abs -o Release.gpg Release)'
## ----------------------------------------------------------------------------------------------------------- ##
gpg --keyserver keys.riseup.net --recv-key 0x4E0791268F7C67EABE88F1B03043E2B7139A768E
gpg --fingerprint 0x4E0791268F7C67EABE88F1B03043E2B7139A768E

## ==================================================================================== ##
## 
##-====================================-##
##    [+] Setting GPG KeyServers...
##-====================================-##
## 
## ==================================================================================== ##
GPGKeyServer="--keyserver hkps://hkps.pool.sks-keyservers.net"
hkpsSksCACertFile="/etc/ssl/certs/hkps.pool.sks-keyservers.net.pem"
GnupgRiseupKeyserver="--keyserver keys.riseup.net"
GnupgUbuntuKeyserver="--keyserver hkp://keyserver.ubuntu.com"
GnupgSksXhkpKeyserver="--keyserver x-hkp://pool.sks-keyservers.net"
GnupgSksHkpsKeyserver="--keyserver hkps://hkps.pool.sks-keyservers.net"
GnupgPGPNetKeyserver="--keyserver subkeys.pgp.net"
GnupgNetKeyserver="--keyserver keys.gnupg.net"
## ==================================================================================== ##
## 
##-===============================================-##
##   [+] Setting GPG Defaults & Preferences...
##-===============================================-##
## 
## ==================================================================================== ##
GnupgDefaultKeyserver="--default-keyserver-url hkps://hkps.pool.sks-keyservers.net"
declare -r SKS_CA="sks-keyservers.netCA.pem"
GPGOnionKeyServer="--keyserver hkp://qdigse2yzvuglcix.onion"
KeyServerOpts="verbose verbose verbose no-include-revoked no-include-disabled no-auto-key-retrieve no-honor-keyserver-url no-honor-pka-record include-subkeys no-include-attributes"
GnupgListOpt="--list-options no-show-photos show-uid-validity no-show-unusable-uids no-show-unusable-subkeys show-notations show-user-notations show-policy-urls show-keyserver-urls show-sig-expire show-sig-subpackets"
GnupgVerifyOpt="--verify-options no-show-photos show-uid-validity show-notations show-user-notations show-policy-urls show-keyserver-urls pka-lookups pka-trust-increase"
GnupgCertDigestAlgo="--cert-digest-algo SHA512"
GnupgDigestAlgo="--digest-algo SHA512"
GnupgKeyFormat="--keyid-format 0xlong"
GnupgDefaultPrefList="--default-preference-list SHA512 SHA384 SHA256 AES256 ZLIB ZIP Uncompressed"
GnupgCipherPref="--personal-cipher-preferences AES256"
GnupgDigestPref="--personal-digest-preferences SHA512 SHA384 SHA256"
GnupgCompressPref="--personal-compress-preferences ZLIB ZIP"
GnupgCompressLvl="--compress-level 9"
UpdateDB="--update-trustdb"
## ==================================================================================== ##
## 
## ========================================== ##
##   [+] Securing Gnupg Keys Storage...
## ========================================== ##
## 
## ==================================================================================== ##
GnupgKeyServeropt="--s2k-cipher-algo AES256"
Gnupgs2kDigest="--s2k-digest-algo SHA512"			## use this one to mangle the passphrases:
Gnupgs2kMode="--s2k-mode 3"
Gnupgs2kCount="--s2k-count xxxxxx"
GnupgSecMem="--require-secmem"		## Don't run if we can't secure mempages
## ==================================================================================== ##
## 





SHA1="openssl dgst -sha1"
SHA256="openssl dgst -sha256"
SHA512="openssl dgst -sha512"



## curl --resolve 127.0.0.1:4444:http://killyourtv.i2p/killyourtv.asc
## curl --resolve 127.0.0.1:9053:https://tails.boum.org/tails-signing.key


## #################################################################### ##
## ==================== Networking Aliases ============================ ##
## #################################################################### ##
## 
## ======================================================================================================================================================== ##
alias fwdown="sudo iptables -F; sudo iptables -X; sudo iptables -A INPUT -j ACCEPT; sudo iptables -A FORWARD -j ACCEPT; sudo iptables -A OUTPUT -j ACCEPT"
## ----------------------------------------------------------------------------------------------------------- ##
alias fwcheck="/sbin/iptables -L -n -v --line-numbers'"
## ----------------------------------------------------------------------------------------------------------- ##
alias iip="(sudo /sbin/ifconfig wlan0|grep inet|head -1|sed 's/\:/ /'|awk '{print $3}')"
## ##################################################### ##
## Block known dirty hosts from reaching your machine
## ----------------------------------------------------------------------------------------------------------- ##
alias iptablesblocklist="(wget -qO - http://infiltrated.net/blacklisted|awk '!/#|[a-z]/&&/./{print "iptables -A INPUT -s "$1" -j DROP"}')"							
## ----------------------------------------------------------------------------------------------------------- ##


## ======================================================================================================================================================== ##



## ========================================================================= ##
## ================ Current Release: Testing/Lazy Dev ====================== ##
## ===================  Temporarly Commented Out =========================== ##
## ========================================================================= ##
## alias ifconfigeth0='/sbin/ifconfig eth0 hw ether 00:30:65:e4:98:27'
## alias ifconfigwlan0='/sbin/ifconfig wlan0 hw ether 00:40:96:f4:34:67'
## alias ifconfigwlan1='/sbin/ifconfig wlan1 hw ether 00:30:65:35:2e:37'
## ========================================================================= ##



## ============================================================================================== ##
## ================================ Process Management Aliases ================================== ##
## ============================================================================================== ##
alias psmem='ps auxf | sort -nr -k 4 | head -10'		## [?] show top 10 process eating memory
alias pscpu='ps auxf | sort -nr -k 3 | head -10'		## [?] show top 10 process eating CPU
alias ps='ps awwfux | less -S'							## Show a 4-way scrollable process tree with full details.
alias listening="(lsof -nPi | awk '/LISTEN/')"
alias lsofconnect='lsof -l -i +L -R -V'
alias lsofestablished='lsof -l -i +L -R -V | grep ESTABLISHED'
alias lsofuniq='lsof -P -i -n | cut -f 1 -d " "| uniq | tail -n +2'
alias lsof="lsof -FpcfDi"

alias pstree='pstree --arguments --show-pids --show-pgids --show-parents >> /var/log/pstree.txt; cat /var/log/pstree.log | less'
alias pscolumns='ps aox 'pid,user,args,size,pcpu,pmem,pgid,ppid,psr,tty,session,eip,esp,start_time' >> ps-columns.txt; cat /var/log/pscolumns.log | less'
alias psdump='(ps -aux; ps -ejH; ps -eLf; ps axjf; ps axms; ps -ely; ps -ef; ps -eF;  ps -U root -u root u; ) >> /var/log/psdump.log; cat /var/log/psdump.log'
## ============================================================================================== ##



## ========================================================================== ##
## ================================ DNS Aliases  ============================ ##
## ========================================================================== ##
alias dns=$(grep 'nameserver' /etc/resolv.conf | awk '{print $2}')
alias ip=$(ifconfig | grep 'broadcast' | awk '{print $2}')
alias mac=$(ifconfig | grep 'ether' | awk '{print $2}')
alias user=$(whoami)
## ----------------------------------------------------------------------------- ##


## ----------------------------------------------------------------------------- ##
alias dns1="dig +short @resolver1.opendns.com myip.opendns.com"
alias dns2="dig +short @208.67.222.222 myip.opendns.com"
alias dns3="dig +short @208.67.220.220 which.opendns.com txt"
## ----------------------------------------------------------------------------- ##
alias history="history | cut -c8-199"
## ============================================================== ##
## Get your outgoing IP address
alias myip='dig +short myip.opendns.com @resolver1.opendns.com'		
## ----------------------------------------------------------------------------- ##
## 
## ========================================================================== ##



## ========================================================================== ##
## ====================  ========================== ##
## ========================================================================== ##
## [+] View certificate information
## ----------------------------------------------------------------------------- ##
# openssl x509 ‐text ‐in servernamecert.pem      # View the certificate info 
# openssl req ‐noout ‐text ‐in server.csr        # View the request info 
# openssl s_client ‐connect cb.vu:443            # Check a web server certificate 
## ----------------------------------------------------------------------------- ##
## 
## ========================================================================== ##





debootstrap --variant=minbase --keyring=/usr/share/keyrings/debian-archive-keyring.gpg stable . "$mirror"




## =============================================================================================== ##
alias sources='(pluma /etc/apt/sources.list &)'
alias catsrc='cat /etc/apt/sources.list'
## =============================================================================================== ##





## =============================================================================================== ##
# Download all images from /b/
alias archiveb='(wget -r -l1 --no-parent -nH -nd -P/tmp -A".gif,.jpg" https://boards.4chan.org/b/)'		
alias scurl="curl --tlsv1.3 --verbose --ssl-reqd --progress-bar"
wget="wget -q -O - "
imgur(){ $*|convert label:@- png:-|curl -F "image=@-" -F "key=1913b4ac473c692372d108209958fd15" http://api.imgur.com/2/upload.xml|grep -Eo "<original>(.)*</original>" | grep -Eo "http://i.imgur.com/[^<]*";}

## =============================================================================================== ##



alias yt2mp3='youtube-dl -l --extract-audio --audio-format=mp3 -w -c'




## =============================================================================================== ##
## ========================================= Man Aliases  ======================================== ##
## =============================================================================================== ##
alias mansearch="man --all --apropos --wildcard --ignore-case"
alias manpdf='man -t $0 | lpr -Pps'
alias man
## ----------------------------------------------------------------------------------------------- ##
alias bashkeys='bind -P'						# List all bash shortcuts
## ----------------------------------------------------------------------------------------------- ##

## =============================================================================================== ##




## =============================================================================================== ##
## ----------------------------------------------------------------------------------------------- ##
alias startx="startx -- -nolisten tcp"
## ----------------------------------------------------------------------------------------------- ##

## =============================================================================================== ##






## =============================================================================================== ##
alias computergod='(cat /dev/urandom | hexdump -C | grep "ca fe")'
## =============================================================================================== ##



alias yt2mp3='youtube-dl -l --extract-audio --audio-format=mp3 -w -c'

yt-chanrip() { for i in $(curl -s http://gdata.youtube.com/feeds/api/users/"$1"/uploads | grep -Eo "watch\?v=[^[:space:]\"\'\\]{11}" | uniq); do youtube-dl --title --no-overwrites http://youtube.com/"$i"; done }






# Alias definitions.
# You may want to put all your additions into a separate file like
# ~/.bash_aliases, instead of adding them here directly.
# See /usr/share/doc/bash-doc/examples in the bash-doc package.

if [ -f ~/.bash_aliases ]; then
    . ~/.bash_aliases
fi

# enable programmable completion features (you don't need to enable
# this, if it's already enabled in /etc/bash.bashrc and /etc/profile
# sources /etc/bash.bashrc).
if ! shopt -oq posix; then
  if [ -f /usr/share/bash-completion/bash_completion ]; then
    . /usr/share/bash-completion/bash_completion
  elif [ -f /etc/bash_completion ]; then
    . /etc/bash_completion
  fi
fi


### Extract file, example. "ex package.tar.bz2"
ex() {
    if [[ -f $1 ]]; then
        case $1 in
            *.tar.bz2)   tar xjf $1  ;;
            *.tar.gz)    tar xzf $1  ;;
            *.bz2)       bunzip2 $1  ;;
            *.rar)       rar x $1    ;;
            *.gz)        gunzip $1   ;;
            *.tar)       tar xf $1   ;;
            *.tbz2)      tar xjf $1  ;;
            *.tgz)       tar xzf $1  ;;
            *.zip)       unzip $1    ;;
            *.Z)         uncompress $1  ;;
            *.7z)        7z x $1     ;;
            *)           echo $1 cannot be extracted ;;
        esac
    else
        echo $1 is not a valid file
    fi
}
