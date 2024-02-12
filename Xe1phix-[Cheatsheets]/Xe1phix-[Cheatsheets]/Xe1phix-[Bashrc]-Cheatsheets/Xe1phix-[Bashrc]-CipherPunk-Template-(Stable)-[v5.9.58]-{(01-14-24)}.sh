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
shopt -s cmdhist

# create HISTFILE if not exist
if [ ! -r "$HISTFILE" ]; then
    touch "$HISTFILE"
fi

# for setting history length see HISTSIZE and HISTFILESIZE in bash(1)
HISTSIZE=1000000
HISTFILESIZE=2000000


## export HISTTIMEFORMAT="%F %T "				# Add timestamp to history


zshsetshell="chsh -s /bin/zsh root"

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

alias totp="oathtool -b --totp $(cat ~/.google_authenticator | head -1)"

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
alias paxctldstart="systemctl enable paxctld; systemctl start paxctld; /etc/init.d/paxctld start; service paxctld enable; service paxctld start && echo $PAXCTLDBANNER"
alias PAXCTLDBANNER='echo "[+] Enabling + Starting The paxctld Service..."'
alias paxctldstartold="update-rc.d paxctld enable; chkconfig paxctld on"
## ------------------------------------------------------------------------------------------------------------- ##

AuditNumRecords=$(sudo egrep -e '^(-a|-w) ' /etc/audit/audit.rules | wc -l)
AuditNumRules=$(sudo bash -c "egrep -e '^(-a|-w) ' /etc/audit/rules.d/*" | wc -l)


##-======================================================================-##
## ================================ AppArmor ============================ ##
##-======================================================================-##


function apparmor_enable() {
    systemctl start apparmor
    profiles=$(find /etc/apparmor.d -type f | grep -v tunables | grep -v local | grep -v abstractions)
    profiles+=$(find /etc/apparmor.d -type f -exec grep -E "^(\s+)?profile" {} \; | cut -d'{' -f1 | sed 's/[ \t]*//' | cut -d' ' -f2 | uniq -u)
    for profile in $profiles; do
        aa-enforce -d /etc/apparmor.d $profile
    done
}

function apparmor_complain() {
    systemctl start apparmor
    profiles=$(find /etc/apparmor.d -type f | grep -v tunables | grep -v local | grep -v abstractions)
    profiles+=$(find /etc/apparmor.d -type f -exec grep -E "^(\s+)?profile" {} \; | cut -d'{' -f1 | sed 's/[ \t]*//' | cut -d' ' -f2 | uniq -u)
    for profile in $profiles; do
        aa-complain -d /etc/apparmor.d $profile
    done
}

function apparmor_disable() {
    systemctl stop apparmor
    systemctl disable apparmor
    profiles=$(find /etc/apparmor.d -type f | grep -v tunables | grep -v local | grep -v abstractions)
    profiles+=$(find /etc/apparmor.d -type f -exec grep -E "^(\s+)?profile" {} \; | cut -d'{' -f1 | sed 's/[ \t]*//' | cut -d' ' -f2 | uniq -u)
    for profile in $profiles; do
        aa-disable -d /etc/apparmor.d $profile
    done
}

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



# show tcp syn packets on all network interfaces
alias tcpdumptcpsyn="tcpdump -i any -n tcp[13] == 2"
alias tcpflow="tcpflow -p -c -i eth0 port 80"

# View HTTP traffic
alias sniff="sudo ngrep -d 'en1' -t '^(GET|POST) ' 'tcp and port 80'"
alias httpdump="sudo tcpdump -i en1 -n -s 0 -w - | grep -a -o -E \"Host\: .*|GET \/.*\""


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

# Summarize the number of open TCP connections by state
alias netstattcpstatus="netstat -nt | awk '{print $6}' | sort | uniq -c | sort -n -k 1 -r"

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




## --------------------------- ##
##   [+] Generate ssh keys
## --------------------------- ##
alias sshkeygen='$(ssh-keygen -t rsa -b 4096 -C "xe1phix@protonmail.ch")'

## ----------------------------------- ##
##   [+] Add SSH keys to SSH agent:
## ----------------------------------- ##
alias sshadd="ssh-add ~/.ssh/id_rsa"

## ----------------------------------------------------------------------------------------------- ##
alias ssh-start="systemctl restart ssh"
alias ssh-stop="systemctl stop ssh"

alias rsync="rsync --perms --chmod=uog+r --times --partial --progress --verbose $1"

## ----------------------------------------------------------------------------------------------- ##
alias status='systemctl list-units --full --all; systemctl --full --no-legend --no-pager --type=service --state=running list-units; systemctl list-unit-files --type=service; service --status-all | grep running'
## ----------------------------------------------------------------------------------------------- ##
alias serviceenabled='systemctl list-unit-files --type=service | grep -v disabled; '
## ----------------------------------------------------------------------------------------------- ##





alias debootdebian='debootstrap --variant=minbase --keyring=/usr/share/keyrings/debian-archive-keyring.gpg stable . "$mirror"'


##-=============================================================================-##
## ------------------------------- DPKG Aliases -------------------------------- ##
##-=============================================================================-##
alias dpkggrepsize="dpkg-query -W -f='${Installed-Size;10}\t${Package}\n' | sort -k1,1n"        ## List all packages by installed size (KBytes)
alias dpkgdebfind="find . -type f -and -iname "*.deb" | xargs -n 1 dpkg -I"
alias dpkgdepends='dpkg-deb --info $File.deb'				                                    ## Queries .deb packages prereq
alias dpkgdepgrep='dpkg-deb --info $(depends) | grep Depends:'		                            ##
alias dpkgsize='dpkg -l | grep Installed-Size:'		
## ----------------------------------------------------------------------------------------------- ##
alias dpkgpackagebackup="dpkg --get-selections > $AptPackageBackup"         ## Backup dpkg package selections
alias dpkgpackagerestore="dpkg --set-selections < $AptPackageBackup"        ## Restore dpkg package selections
## ----------------------------------------------------------------------------------------------- ##
## dpkg-deb --build                             ## 
## dpkg-deb --root-owner-group                  ## 
## dpkg-deb --raw-extract $File.deb $Dir        ## Extract control info and files.
## dpkg-deb --ctrl-tarfile $File.deb            ## Output control tarfile.
## dpkg-deb --fsys-tarfile $File.deb            ## Output filesystem tarfile.
## ----------------------------------------------------------------------------------------------- ##
## dpkg-deb --extract $File.deb                 ## 
## dpkg-deb --vextract $File.deb                ## 
## dpkg-deb --field                             ## 
## ----------------------------------------------------------------------------------------------- ##
## dpkg-deb --info $File.deb                    ## 
## dpkg-deb --show $File.deb                    ## 
## dpkg-deb --contents $File.deb                ## List contents
## ----------------------------------------------------------------------------------------------- ##
## dpkg-deb --debug                             ## 
## dpkg-deb --verbose                           ## 
## ----------------------------------------------------------------------------------------------- ##
## dpkg-reconfigure $File.deb                   ## 
## ----------------------------------------------------------------------------------------------- ##
## dpkg-genbuildinfo $File.deb                  ## 
## dpkg-checkbuilddeps $File.deb                ## 
## dpkg-buildpackage $File.deb
## ----------------------------------------------------------------------------------------------- ##
## dpkg-genchanges
## dpkg-parsechangelog
## ----------------------------------------------------------------------------------------------- ##


##
## ----------------------------------------------------------------------------------------------- ##
alias libstatus='gcc-config -l; ldconfig --print-cache'
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
alias sedposix="sed --posix"        ## disable all GNU extensions"
alias sedsandbox="sed --sandbox"    ## sandbox mode (disable e/r/w commands)


## ----------------------------------------------------------------- ##
##   [?] use tr to convert the spaces to newlines,
##   [?] forcing the output to have a single port entry per line.
## ----------------------------------------------------------------- ##
## ---------------------------------------------------------------------------------------------------------------------------------- ##
## cat $File.gnmap | tr ' ' \\n | awk -F/ '/\/\/\// {print $1 "/" $3}' | sort | uniq -c | sort -nr -k1 -k2
## ---------------------------------------------------------------------------------------------------------------------------------- ##
alias trconvertspacetonewline="cat $1 | tr ' ' \\n | awk -F/ '/\/\/\// {print $1 "/" $3}' | sort | uniq -c | sort -nr -k1 -k2"
## ---------------------------------------------------------------------------------------------------------------------------------- ##


awk - match port + protocol fields lines and output
awk '/^[0-9]/ {print $1}' test.nmap | sort | uniq -c | sort -nr -k1 -k2
awk '/^[0-9]/ {print $1}' $1 | sort | uniq -c | sort -nr -k1 -k2


chsh -s /bin/zsh root

## ############################################################################# ##
## ################## Regular Expression Parsers Aliases ####################### ##
## ============================================================================= ##
alias egrep='egrep --color=auto'
alias egrepr='egrep --color=auto --recursive'
alias cat='/bin/cat '
alias grep='grep --color=auto --extended-regexp'
alias grepperl="grep --color=auto --perl-regexp"
alias fgrep='fgrep --color=auto'

--include=GLOB        search only files that match GLOB
--regexp --only-matching

--regexp=$1 --invert-match         ## select non-matching lines
--initial-tab
--with-filename --dereference-recursive --exclude --ignore-case

--directories=read
--directories=recurse
--directories=skip
--directories --exclude-dir
--no-messages       ## suppress error messages
--file=FILE           take PATTERNS from FILE
--byte-offset       ## print byte offset with output lines

alias grepcomment="cat $1 | grep -E -v '^#'"      ##

alias catgrep="cat $1 | grep $2"

alias grepnum="grep '^[0-9]' $1"            ## Find lines starting with a number
alias catgrepnum="cat $1 | grep '^[0-9]' $1"            ## Find lines starting with a number

alias grepchar="egrep '^[a-z]|[A-Z]' $1"            ## Find lines starting with a number
alias catgrepnum="cat $1 | egrep '^[a-z]|[A-Z]' $1"            ## Find lines starting with a number


alias catgrepvar="cat $1 | grep '^$Var' $1"             ## Find lines starting with $Var
alias grepvar="grep '^$Var' $1"             ## Find lines starting with $Var
## ----------------------------------------------------------------------------- ##
alias repoenabled="(egrep '^deb' /etc/apt/sources.list)"
alias repodisabled="(egrep '^[#|#+] deb' /etc/apt/sources.list)"

grep-aptavail
grep-available
grep-status
## ----------------------------------------------------------------------------- ##
alias nocomment='grep -Ev '\''^(#|$)'\'''   ## print file without comments
## ============================================================================= ##
alias xargs='xargs --verbose'

alias xargsfile='xargs --verbose --arg-file=$1'       ## $FILE
alias xargsinteractive='xargs --verbose --interactive $1'


alias findxargsbyfile='find / -type f | xargs grep $1'
alias findxargstxt="find . -name '*.txt' | xargs grep -i $1"
alias findxargsbytypeshgrepstr="find . -name '*.sh' -exec grep -i $1 -print"
alias findxargsbytypeshgrepstr="find . -name '*.conf' -exec grep -i $1 -print"
alias findxargsbytypeshgrepstr="find . -name '*.cfg' -exec grep -i $1 -print"
alias findxargsbytypeshgrepstr="find . -name '*.bash' -exec grep -i $1 -print"
alias findxargsbytypeshgrepstr="find . -name '*.sh' -exec grep -i $1 -print"
alias findxargsbytypeshgrepstr="find . -name '*.sh' -exec grep -i $1 -print"
alias findxargsbytypeshgrepstr="find . -name '*.sh' -exec grep -i $1 -print"
alias findxargsbytypeshgrepstr="find . -name '*.sh' -exec grep -i $1 -print"


# Show me the size (sorted) of only the folders in this directory
alias folders="find . -maxdepth 1 -type d -print | xargs du -sk | sort -rn"

## list all folders from last 24 hours
find folder/ -maxdepth 2 -type f -name "*.json" -mtime -1 -exec grep -i 'string' {} \; 
  


# find <dir> <file name regexp> <file contents regexp>
function fing { find "$1" -name "$2" -exec grep -H "$3" "{}" \; }


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
find . -group root -print | xargs chown temp

alias chmodown="chmod -v -R ugo+rwx $1 && chown -v xe1phix:xe1phix -R $1"


## ############################################################################# ##
## ####################### File Manipulation Aliases ########################### ##
## ============================================================================= ##
alias cp='cp --verbose --recursive --parents'
alias mkdirsu='mkdir --mode=0620'
## ----------------------------------------------------------------------------- ##
alias shred='shred --verbose --iterations=7 --zero --force'
alias rm='rm --recursive --force'
## ============================================================================= ##


alias ntpsync="sudo ntpdate -v -b -s -t 10 time.nist.gov 0.debian.pool.ntp.org 1.debian.pool.ntp.org 2.debian.pool.ntp.org 3.debian.pool.ntp.org"
alias scanclam="sudo clamscan --block-encrypted  --scan-mail=no --scan-archive=yes --max-scansize=500M --exclude-dir=/mnt --exclude-dir=/media --exclude-dir=smb4k --exclude-dir=/run/user/root/gvfs --exclude-dir=/root/.gvfs --exclude-dir=^\/root\/\.clamtk\/viruses --exclude-dir=^\/sys\/ --exclude-dir=^\/dev\/ --exclude-dir=^\/proc\/ --exclude-dir=.thunderbird --exclude-dir=.mozilla-thunderbird --exclude-dir=Mail --exclude-dir=kmail --exclude-dir=evolution --max-filesize=20M --recursive=yes -v"
alias servnfs="exportfs -vfsar"
alias sessionbus="sudo -u $USER systemctl --user"
alias raminfo="sudo dmidecode --quiet --type 17 | more"


## ############################################################################################## ##
## ===================================== Mount  Aliases  ======================================== ##
## ============================================================================================== ##
alias mountacl="mount -t ext3 /dev/mapper/parrot--vg-root / -o acl,nosuid,usrquota,grpquota"
alias mountquota='mount -t ext3/dev/mapper/parrot--vg-root / -o acl,nosuid,usrquota,grpquota'
## =============================================================================================== ##



## ############################################################################################## ##
## ===================================== History  Aliases ======================================= ##
## ============================================================================================== ##
alias history="history | cut -c8-2000"
alias histgrep="history | cut -c8-1990 | grep"
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


alias bootuuid=`blkid -s UUID -o value /dev/sda1`
alias rootuuid=`blkid -s UUID -o value "$dev_root"`
alias swapuuid=`blkid -s UUID -o value "$dev_swap"`
alias blkidboot='sudo blkid --probe --usages filesystem,other /dev/sda1'


alias resolution=$(xdpyinfo | grep -A 3 "screen #0" | grep dimensions | tr -s " " | cut -d" " -f 3)

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
## clone a partition from one disk to another:
alias e2imageclone='e2image -ra -p /dev/sda1 /dev/sdb1'


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
alias netstatall='netstat --listening --program --numeric --tcp --udp --extend'
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
alias pscpu='ps auxf | sort -nr -k 3 | head -10'
alias psmem='ps auxf | sort -nr -k 4 | head -10'


## ========================================================================== ##
## ================================ Aliases ================================ ##
## ========================================================================== ##
alias banner="cat /etc/issue.net"
## ================================================================= ##



## ========================================================================== ##
## ======================= Sed Regex Aliases ================================ ##
## ========================================================================== ##
alias NoBlanks='sed '/^$/d' $1'                  # Remove blank lines
alias NoComments="sed -e 's/#.*//;/^\s*$/d'"
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
alias killuser='skill ‐9 ‐u $USER'              ## Kill the user and their processes

alias journalk='(journalctl -k >> /home/faggot/journalctlkernellog.txt)'
alias journalh='(journalctl --since "1 hour ago")'
alias journalssh='journalctl -u sshd.service'
alias journaldhcp='(journalctl -b | egrep "dhc")'
alias journalvacuum='(sudo journalctl --vacuum-size=20M && du -hs /var/log/journal/)'
## ----------------------------------------------------------------------------------------------------------- ##
alias tail500='(tail ‐n 500 /var/log/messages)'     				 # Last 500 kernel/syslog messages
alias tailicmp='(tail /var/log/messages |grep ICMP |tail -n 1)'
alias tailudp='(tail /var/log/messages | grep UDP | tail -n 1)'
alias tailtcp='(tail /var/log/messages | grep TCP | tail -n 1)'
## ----------------------------------------------------------------------------------------------------------- ##
alias who='(who --boot; who --all; who --mesg; who --ips; who -T; who --dead; who -b -d --login -p -r -t -T -u)'
alias environment='(printenv; env; set; whoami; uptime; id -a; umask -p; systemctl environment)'
## ----------------------------------------------------------------------------------------------------------- ##
alias cronrestart='killall ‐HUP crond'
alias cronstart='crontab -e'
## list all crontabs for users
alias cronstatus="cut -d: -f1 /etc/passwd | grep -vE "#" | xargs -i{} crontab -u {} -l"

alias diff='diff -urp $0 $1'





alias log="echo $2 \`date +%FT%R\` >> ~/examiner.log"           ## Forensic Examiner Activity Log


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



##-===================================================================-##
## ================================ GnuPG ============================ ##
##-===================================================================-##

if [[ -z "${GPG_AGENT_INFO}" ]]; then
    systemctl --user start gpg-agent
    export GPG_AGENT_PID="$(pgrep -xn -u $USER gpg-agent)"
    export GPG_AGENT_INFO="/run/user/$(id -u )/gnupg/S.gpg-agent:${GPG_AGENT_PID}:1"
    systemctl --user set-environment GPG_AGENT_INFO=${GPG_AGENT_INFO}
    gpg-connect-agent updatestartuptty /bye >/dev/null
fi


alias gpgenv="$(gpg-connect-agent 'getinfo std_env_names' /bye | awk '$1=="D" {print $2}')"


## ----------------------------------------------------------------------------------------------------------- ##
alias launchpadkey="sudo apt-key adv --keyserver keyserver.ubuntu.com --recv-keys"
alias gpgkeymissing='sudo apt-get update 2> /tmp/keymissing; for key in $(grep "NO_PUBKEY" /tmp/keymissing |sed "s/.*NO_PUBKEY //"); do echo -e "\nProcessing key: $key"; gpg --keyserver pool.sks-keyservers.net --recv $key && gpg --export --armor $key |sudo apt-key add -; done'
alias gpgarmor='gpg --gen-random --armor 1 30'
## ----------------------------------------------------------------------------------------------------------- ##
alias GnupgGenKey="gpg --enable-large-rsa --full-gen-key"
alias GnupgKeyImport="gpg --keyid-format 0xlong --import"
alias gpgrecv="gpg --keyserver x-hkp://pool.sks-keyservers.net --recv-keys 0x"
alias GnupgVerify="gpg --keyid-format 0xlong --verify"
alias gpgencrypt="gpg --verbose --symmetric --cipher-algo aes256 --digest-algo sha512 --cert-digest-algo sha512 --s2k-mode 3 --s2k-count 65011712 --s2k-cipher-algo AES256 --s2k-digest-algo SHA512 $1"
alias GnupgHome="/home/xe1phix/.gnupg/"

alias GPGClearSigRelease='$(gpg --clearsign -o InRelease Release)'
alias GPGClearSigReleaseSig='$(gpg -abs -o Release.gpg Release)'

alias GnuPGSignCanary="gpg --no-armor -o canary.asc --default-sig-expire 6m --clearsign canary.txt"


## ----------------------------------------------------------------------------------------------------------- ##
alias riseupgpg='gpg --keyserver keys.riseup.net --recv-key 0x4E0791268F7C67EABE88F1B03043E2B7139A768E'
alias riseupfpr='gpg --fingerprint 0x4E0791268F7C67EABE88F1B03043E2B7139A768E'

## ==================================================================================== ##
##
##-====================================-##
##    [+] Setting GPG KeyServers...
##-====================================-##
##
## ==================================================================================== ##
alias GPGKeyServer="gpg --keyserver hkps://hkps.pool.sks-keyservers.net"
alias hkpsSksCACertFile="/etc/ssl/certs/hkps.pool.sks-keyservers.net.pem"
alias GnupgRiseupKeyserver="gpg --keyserver keys.riseup.net"
alias GnupgUbuntuKeyserver="gpg --keyserver hkp://keyserver.ubuntu.com"
alias GnupgSksXhkpKeyserver="gpg --keyserver x-hkp://pool.sks-keyservers.net"
alias GnupgSksHkpsKeyserver="gpg --keyserver hkps://hkps.pool.sks-keyservers.net"
alias GnupgPGPNetKeyserver="gpg --keyserver subkeys.pgp.net"
alias GnupgNetKeyserver="gpg --keyserver keys.gnupg.net"
## ==================================================================================== ##
##
##-===============================================-##
##   [+] Setting GPG Defaults & Preferences...
##-===============================================-##
##
## ==================================================================================== ##
alias GnupgDefaultKeyserver="--default-keyserver-url hkps://hkps.pool.sks-keyservers.net"
## declare -r SKS_CA="sks-keyservers.netCA.pem"
alias GPGOnionKeyServer="--keyserver hkp://qdigse2yzvuglcix.onion"
alias KeyServerOpts="verbose verbose verbose no-include-revoked no-include-disabled no-auto-key-retrieve no-honor-keyserver-url no-honor-pka-record include-subkeys no-include-attributes"
alias GnupgListOpt="gpg --list-options no-show-photos show-uid-validity no-show-unusable-uids no-show-unusable-subkeys show-notations show-user-notations show-policy-urls show-keyserver-urls show-sig-expire show-sig-subpackets"
alias GnupgVerifyOpt="gpg --verify-options no-show-photos show-uid-validity show-notations show-user-notations show-policy-urls show-keyserver-urls pka-lookups pka-trust-increase"
alias GnupgCertDigestAlgo="gpg --cert-digest-algo SHA512"
alias GnupgDigestAlgo="gpg --digest-algo SHA512"
alias GnupgKeyFormat="gpg --keyid-format 0xlong"
alias GnupgDefaultPrefList="gpg --default-preference-list SHA512 SHA384 SHA256 AES256 ZLIB ZIP Uncompressed"
alias GnupgCipherPref="gpg --personal-cipher-preferences AES256"
alias GnupgDigestPref="gpg --personal-digest-preferences SHA512 SHA384 SHA256"
alias GnupgCompressPref="gpg --personal-compress-preferences ZLIB ZIP"
alias GnupgCompressLvl="gpg --compress-level 9"
alias UpdateDB="gpg --update-trustdb"
## ==================================================================================== ##
##
## ========================================== ##
##   [+] Securing Gnupg Keys Storage...
## ========================================== ##
##
## ==================================================================================== ##
alias GnupgKeyServeropt="gpg --s2k-cipher-algo AES256"
alias Gnupgs2kDigest="gpg --s2k-digest-algo SHA512"			## use this one to mangle the passphrases:
alias Gnupgs2kMode="gpg --s2k-mode 3"
alias Gnupgs2kCount="gpg --s2k-count xxxxxx"
alias GnupgSecMem="gpg --require-secmem"		## Don't run if we can't secure mempages
## ==================================================================================== ##
##

gpg --export-secret-keys
gpg --export-secret-subkeys

gpg --export-ownertrust > ~/.gnupg/GnuPGTrust.txt
gpg --import-ownertrust ~/.gnupg/GnuPGTrust.txt
gpg --export --keyring $Keyring --armor --output ~/.gnupg/$File
mv pubring.gpg publickeys.backup && gpg --import-options restore --import publickeys.backups





##-===================================================================-##
##  [+] Curl SOCKS5 Proxy Connection - Using Win Firefox UserAgent:
##-===================================================================-##
curl --proxy "socks5h://localhost:9050" --tlsv1.2 --compressed --user-agent "Mozilla/5.0 (Windows NT 6.1; rv:45.0) Gecko/20100101 Firefox/45.0" -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' -H 'DNT: 1' $URL



##-======================================-##
##  [+] Curl SOCKS5 Proxy Connection:
##-======================================-##
curl -s -m 10 --socks5 $hostport --socks5-hostname $hostport -L $URL


## curl --resolve 127.0.0.1:4444:http://killyourtv.i2p/killyourtv.asc
## curl --resolve 127.0.0.1:4444:http://killyourtv.i2p/ircserver/kytv-cacert.pem
## curl --resolve 127.0.0.1:9053:https://tails.boum.org/tails-signing.key


## #################################################################### ##
## ==================== Networking Aliases ============================ ##
## #################################################################### ##
##


function allowip() {
    sudo iptables -I INPUT -s "$1" -j ACCEPT
    sudo iptables -A OUTPUT -d "$1" -j ACCEPT    
}

function blockip() {
    sudo iptables -I INPUT -s "$1" -j DROP
    sudo iptables -A OUTPUT -d "$1" -j DROP
}

function allowport() {
    sudo iptables -I INPUT -p tcp -m tcp --dport "$1" -j ACCEPT
    sudo iptables -A OUTPUT -p tcp -m tcp --dport "$1" -j ACCEPT
}

function blockport() {
  sudo iptables -I INPUT -p tcp -m tcp --dport "$1" -j REJECT
  sudo iptables -A OUTPUT -p tcp -m tcp --dport "$1" -j REJECT
}

## ======================================================================================================================================================== ##
alias fwdown="sudo iptables -F; sudo iptables -X; sudo iptables -A INPUT -j ACCEPT; sudo iptables -A FORWARD -j ACCEPT; sudo iptables -A OUTPUT -j ACCEPT"
## ----------------------------------------------------------------------------------------------------------- ##
alias fwcheck="/sbin/iptables -L -n -v --line-numbers'"
## ----------------------------------------------------------------------------------------------------------- ##
alias iip="(sudo /sbin/ifconfig wlan0|grep inet|head -1|sed 's/\:/ /'|awk '{print $3}')"
## ##################################################### ##
## Block known dirty hosts from reaching your machine
## ----------------------------------------------------------------------------------------------------------- ##
alias iptablesblocklist="(wget -qO - http://infiltrated.net/blacklisted|awk '!/#|[a-z]/&&/./{print 'iptables -A INPUT -s '$1' -j DROP'}')"
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
alias lsofkillftp="lsof -i :20,21 | awk '{l=$2} END {print l}' | xargs kill"
alias pstree="$(pstree --arguments --show-pids --show-pgids --show-parents >> /var/log/pstree.txt"
alias pscolumns='ps aox pid,user,args,size,pcpu,pmem,pgid,ppid,psr,tty,session,eip,esp,start_time' >> ps-columns.txt; cat /var/log/pscolumns.log | less
alias psdump='$(ps -aux; ps -ejH; ps -eLf; ps axjf; ps axms; ps -ely; ps -ef; ps -eF;  ps -U root -u root u)' >> /var/log/psdump.log; cat /var/log/psdump.log
## ============================================================================================== ##

alias pscgroup='ps xawf -eo pid,user,cgroup,args'




## ========================================================================== ##
## ================================ DNS Aliases  ============================ ##
## ========================================================================== ##
alias dns=$(grep 'nameserver' /etc/resolv.conf | awk '{print $2}')
alias dnsprint=
alias ethip="ifconfig eth0 | egrep -o '([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)'"
alias wlanip="ifconfig wlan0 | egrep -o '([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)'"
alias ip=$(ifconfig | grep 'broadcast' | awk '{print $2}')
alias mac=$(ifconfig | grep 'ether' | awk '{print $2}')
alias user=$(whoami)
## ----------------------------------------------------------------------------- ##
alias extip='curl -s http://checkip.dyndns.org/ | sed "s/[a-zA-Z<>/ :]//g"'
## ----------------------------------------------------------------------------- ##
alias dns1="dig +short @resolver1.opendns.com myip.opendns.com"
alias dns2="dig +short @208.67.222.222 myip.opendns.com"
alias dns3="dig +short @208.67.220.220 which.opendns.com txt"
## ============================================================== ##
## Get your outgoing IP address
alias myip='dig +short myip.opendns.com @resolver1.opendns.com'
## ----------------------------------------------------------------------------- ##
##
## =========================================================================================================================================================================================== ##
alias dnscryptgenproviderkey="dnscrypt-wrapper --gen-provider-keypair | egrep '^Public key fingerprint' | awk '{print $4}' > /etc/dnscrypt-wrapper/fingerprint"
alias dnscryptgencryptkey="dnscrypt-wrapper --gen-crypt-keypair"
alias dnscryptgencert="dnscrypt-wrapper --crypt-secretkey-file $CryptSecret.key --provider-publickey-file=$PublicKey.key --provider-secretkey-file=$SecretKey.key --gen-cert-file"
## =========================================================================================================================================================================================== ##
##
## 
## ----------------------------------------------------------------------------- ##
## 



##-=====================================================================-##
## ================================ OpenSSL ============================ ##
##-=====================================================================-##


function certcheck() {
    openssl s_client -CAfile /etc/ssl/certs/ca-certificates.crt -showcerts -connect "$1"
}

function certkeymatch() {
    openssl x509 -in "$1" -noout -modulus
    openssl rsa -in "$2" -noout -modulus
}

function certmatchkey() {
    local certmd5=$(openssl x509 -noout -modulus -in "$1" | openssl md5)
    local keymd5=$(openssl rsa -noout -modulus -in "$2" | openssl md5)
    if [[ "$certmd5" == "$keymd5" ]]; then
        echo -e "The certificate matches the key.\n"
    elif [[ "$certmd5" != "$keymd5" ]]; then
        echo -e "The certificate DOES NOT match the key.\n"
    fi
}


function examinecert() {
    openssl x509 -inform PEM -in "$1" -text -noout
}


function examinekey() {
    openssl rsa -in "$1" -text -noout -check
}


function checkkey() {
    openssl rsa -check -text -noout -in "$1"
}


function checkstarttls() {
    openssl s_client -CAfile /etc/ssl/certs/ca-certificates.crt -showcerts -connect "$1":25 -starttls smtp
}

function checktls() {
    openssl s_client -CAfile /etc/ssl/certs/ca-certificates.crt -showcerts -connect "$1"
}

function dumpcerts() {
    openssl s_client -CAfile /etc/ssl/certs/ca-certificates.crt -showcerts -verify 5 -connect "$1" < /dev/null | awk '/BEGIN/,/END/{ if(/BEGIN/){a++}; out="cert"a".pem"; print >out}'
    for cert in *.pem; do newname=$(openssl x509 -noout -subject -in $cert | sed -n 's/^.*CN=\(.*\)$/\1/; s/[ ,.*]/_/g; s/__/_/g; s/^_//g;p').pem; mv $cert $newname; done
}



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
##-=============================================================================-##
## 
alias SHA1="openssl dgst -sha1"
alias SHA256="openssl dgst -sha256"
alias SHA512="openssl dgst -sha512"
##-=============================================================================-##
## 




# Archive every file in /var/logs
alias archivevarlog="find /var/logs -name *.log.?.gz | xargs tar -jcpf logs_`date +%Y-%m-%e`.tar.bz2"
alias archivevarlog="find /var/logs -name *.log|.?|.gz | xargs tar -jcpf logs_`date +%Y-%m-%e`.tar.bz2"


##-=====================================================================-##
## ================================ STrace ============================= ##
##-=====================================================================-##

## [+] Trace all Nginx processes:
alias stracenginx="$(strace -e trace=network -p `pidof nginx | sed -e 's/ /,/g'`)"


for PID in
    strace ‐p $PID ‐f ‐e trace=network,read,write ‐o ssh_trace.out ‐e write=4 ‐e read=6
'$(pidof ssh)'
alias stracessh=""
function stracessh() {
    for PID in
        strace ‐p $PID ‐f ‐e trace=network,read,write ‐o ssh_trace.out ‐e write=4 ‐e read=6
    '$(pidof ssh)'
}


## Monitor writes to stdout and stderr
alias stracemonitorio="$(strace -f -e trace=write -e write=1,2 $1 >/dev/null)"


## ----------------------------------------------------------------------------------------------------------------------------------------- ##
alias watchmysql="watch -n 1 mysqladmin --user=$1 --password=$2 processlist"
## ----------------------------------------------------------------------------------------------------------------------------------------- ##
##  [?] Get table column names from an MySQL-database in comma-seperated form
alias mysqltablenames="mysql -u$User -p$Pass -s -e 'DESCRIBE <table>' $Database"
## alias mysqltablenames="mysql -u$User -p$Pass -s -e 'DESCRIBE <table>' $Database  | tail -n +1 | awk '{ printf($1",")}' |  head -c -1"
## ----------------------------------------------------------------------------------------------------------------------------------------- ##
##  [+] MySQLDump - Dump All Databases Remotely Using SSH:
alias mysqldumpssh="mysqldump -u user -p --all-databases | ssh user@host dd of=/opt/all-databases.dump"
## ----------------------------------------------------------------------------------------------------------------------------------------- ##



alias debootdebian='debootstrap --variant=minbase --keyring=/usr/share/keyrings/debian-archive-keyring.gpg stable . "$mirror"'




## =============================================================================================== ##
alias sources='(sudo pluma /etc/apt/sources.list &)'
alias catsrc='cat /etc/apt/sources.list'
## =============================================================================================== ##



# Get duration of an audio file in seconds.
alias getduration=$(sox "$1" -n stat 2>&1|grep "Length (seconds):");echo ${durline#*\: }; }


## =============================================================================================== ##
# Download all images from /b/
alias archiveb='(wget -r -l1 --no-parent -nH -nd -P/tmp -A".gif,.jpg" https://boards.4chan.org/b/)'
alias scurl="curl --tlsv1.3 --verbose --ssl-reqd --progress-bar"
## alias wget="wget -q -O - "
alias imgur='imgur(){ $*|convert label:@- png:-|curl -F "image=@-" -F "key=1913b4ac473c692372d108209958fd15" http://api.imgur.com/2/upload.xml|grep -Eo "<original>(.)*</original>" | grep -Eo "http://i.imgur.com/[^<]*";}'

## =============================================================================================== ##



alias yt2mp3='youtube-dl -l --extract-audio --audio-format=mp3 -w -c'




## =============================================================================================== ##
## ========================================= Man Aliases  ======================================== ##
## =============================================================================================== ##
alias mansearch="man --all --apropos --wildcard --ignore-case"
alias manpdf='man -t $0 | lpr -Pps'
## alias man
## ----------------------------------------------------------------------------------------------- ##

# Reload tmux config
alias tmuxreload="bind r source-file ~/.tmux.conf && echo 'Reloaded ~/.tmux.conf!'"
alias

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
alias ytuser="yt-chanrip() { for i in $(curl -s http://gdata.youtube.com/feeds/api/users/"$1"/uploads | grep -Eo "watch\?v=[^[:space:]\"\'\\]{11}" | uniq); do youtube-dl --title --no-overwrites http://youtube.com/"$i"; done }"




alias Remoteip="curl -s checkip.dyndns.org | sed -e 's/.*Current IP Address: //' -e 's/<.*$//'"




##### Networking #####
alias Network_restart="sudo systemctl restart NetworkManager.service"
alias Network_stop="sudo systemctl stop NetworkManager.service"







alias WikiDir="cd /home/parrotsec-kiosk/Downloads/Scripts/ParrotLinux-Public-Kiosk-Project-Updated/[05-11-20]/Xe1phix-[Wiki]"
alias SaveDir="cd /home/parrotsec-kiosk/Downloads/Scripts/ParrotLinux-Public-Kiosk-Project-Updated/[05-11-20]/"




alias stat="stat --format=[%A/%a]:[%n]:[Size:%s.bytes]:[Uid:%u]:[User:%U]:[Group:%G]:[GID:%g]:[IO-Block:%o]:[File-type:%F]:[Inode:%i] $1"

alias bitrate| grep "BitRate_String"
Audio Bitrate
File Size                       : 2.8 MiB
Duration
File Modification Date/Time     : 2023:01:07 17:09:26+00:00
File Access Date/Time           : 2023:01:07 17:09:26+00:00
File Inode Change Date/Time     : 2023:01:07 17:09:26+00:00
File Permissions



alias exiftool="exiftool -a -u -g2 $1"
alias exiftoolrm="exiftool -all:all= $1"

alias pdfredact="pdf-redact-tools --sanitize $1"


alias iphelp="iw --help | cut -c2-199 | grep dev <devname>"


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
