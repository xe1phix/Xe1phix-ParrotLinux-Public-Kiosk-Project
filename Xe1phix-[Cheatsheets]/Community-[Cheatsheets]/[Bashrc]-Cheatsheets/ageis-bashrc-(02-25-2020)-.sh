#!/bin/bash
# ~/.bashrc: executed by bash(1) for non-login shells.
# kevin gallagher (@ageis) <kevingallagher@gmail.com>
# normally I divide this into separate files: .bashrc, .bash_profile, .bash_aliases and .bash_functions (also .bash_logout), but it's all concatenated here.

ulimit -s unlimited
export MYUID=$(id -u)
export USER="$(id -un)"

if [[ "$TILIX_ID" ]] || [[ "$VTE_VERSION" ]]; then
    source /etc/profile.d/vte.sh
fi

case $- in
    *i*) ;;
    *)
	# clear
        . /etc/profile
        . ~/.profile
        #return
        ;;
esac

# profile
if [ -f ~/.bash_profile ]; then
    source ~/.bash_profile
fi
umask 027

alias bashrc="source ~/.bashrc"
alias bashfuncs="source ~/.bash_functions"
alias bashaliases="source ~/.bash_aliases"

export DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/$(id -u)/bus"

if [[ ! -d "/run/user/$(id -u)" ]]; then
    sudo -EP mkdir -p "/run/user/$(id -u)"
    sudo -EP chown -R "$(id -u):$(id -u)" "/run/user/$(id -u)"
    systemctl --user && systemctl --user daemon-reexec && systemctl --user daemon-reload
fi

if [[ -z "$SSH_AUTH_SOCK" ]] || [[ -z "$SSH_AGENT_PID" ]]; then
    systemctl --user start ssh-agent
	export SSH_AUTH_SOCK="/run/user/$(id -u)/ssh-agent.sock"
    export SSH_AGENT_PID="$(pgrep -xn -u $USER ssh-agent)"
    systemctl --user set-environment SSH_AUTH_SOCK=${SSH_AUTH_SOCK} SSH_AGENT_PID=${SSH_AGENT_PID}
fi

if [[ -z "${GPG_AGENT_INFO}" ]]; then
    systemctl --user start gpg-agent
    export GPG_AGENT_PID="$(pgrep -xn -u $USER gpg-agent)"
    export GPG_AGENT_INFO="/run/user/$(id -u )/gnupg/S.gpg-agent:${GPG_AGENT_PID}:1"
    systemctl --user set-environment GPG_AGENT_INFO=${GPG_AGENT_INFO}
    gpg-connect-agent updatestartuptty /bye >/dev/null
fi

if [ -z "${DIRMNGR_INFO}" ]; then
    systemctl --user start dirmngr
    DIRMNGR_PID="$(pgrep -xn -u $USER dirmngr)"
    export DIRMNGR_INFO="/run/user/$(id -u)/gnupg/S.dirmngr:${DIRMNGR_PID}:1"
    systemctl --user set-environment DIRMNGR_INFO=${DIRMNGR_INFO}
fi

if [[ -z "${DISPLAY}" ]]; then
    DISP="$(ps -u $(id -u) -o pid= | xargs -I{} cat /proc/{}/environ 2>/dev/null | tr '\0' '\n' | grep -m1 '^DISPLAY=' | cut -d'=' -f3)"
    if [ ! -z "${DISP}" ]; then
        export DISPLAY="${DISP}"
        systemctl --user set-environment DISPLAY=${DISPLAY}
    fi
fi

if [[ -z "${XAUTHORITY}" ]]; then
    # XAUTH="$(ps -u $(id -u) -o pid= | xargs -I{} cat /proc/{}/environ 2>/dev/null | tr '\0' '\n' | grep -m1 '^XAUTHORITY=')"
	if [ ! -z "${XAUTH}" ]; then
		export XAUTHORITY="$HOME/.Xauthority"
		if [ ! -f "${XAUTHORITY}" ]; then
			xauth generate "${DISPLAY}" . trusted
			xauth add localhost:${DISPLAY} . $(xxd -l 16 -p /dev/urandom)
			xauth list
		fi
		systemctl --user set-environment XAUTHORITY=${XAUTHORITY}
	fi
fi

[ ! -z "$PS1" ] && clear
[ -z "$PS1" ] && return

export HISTSIZE=
export HISTFILESIZE=
export HISTTIMEFORMAT="[%d/%m/%y %T] "
export HISTCONTROL=$HISTCONTROL${HISTCONTROL+,}ignoreboth
# export HISTIGNORE=?:??
export HISTIGNORE=$'[ \t]*:&:[fb]g:exit:ls'
export PROMPT_COMMAND="history -a"

shopt -s histappend
shopt -s lithist
shopt -s checkwinsize
shopt -s globstar
shopt -s dotglob
shopt -s cmdhist
shopt -s autocd
shopt -s cdspell

# shopt -s dirspell
# shopt -s complete_fullquote
# shopt -s execfail
# shopt -s extquote
shopt -s force_fignore
# shopt -s huponexit
shopt -s nocaseglob
shopt -s nocasematch
# shopt -s progcomp
# shopt -s promptvars
# shopt -s shift_verbose
# shopt -s xpg_echo


# set +xeuo pipefail
set -o notify
set -o ignoreeof

[ -x /usr/bin/lesspipe ] && eval "$(SHELL=/bin/sh lesspipe)"

if [ -z "${debian_chroot:-}" ] && [ -r /etc/debian_chroot ]; then
    debian_chroot=$(cat /etc/debian_chroot)
fi

export color_prompt=yes

if [ "$color_prompt" = yes ]; then
    PS1='${debian_chroot:+($debian_chroot)}\[\033[01;32m\]\u@\h\[\033[00m\]:\[\033[01;34m\]\w\[\033[00m\]\$ '
else
    PS1='${debian_chroot:+($debian_chroot)}\u@\h:\w\$ '
fi

export force_color_prompt="yes"
export CLICOLOR=1

# If this is an xterm set the title to user@host:dir
case "$TERM" in
    xterm* | rxvt*)
        PS1="\[\e]0;${debian_chroot:+($debian_chroot)}\u@\h: \w\a\]$PS1"
        ;;
    *) ;;

esac

eval "$(dircolors -b)"

# Function definitions.
if [ -f ~/.bash_functions ]; then
    . ~/.bash_functions
fi

function activedisplay() {
    # mapfile -t SESSIONS< <(loginctl list-sessions --nolegend | awk {'print $1'})
    local DISP="$(ps -u $(id -u) -o pid= | xargs -I{} cat /proc/{}/environ 2>/dev/null | tr '\0' '\n' | grep -m1 '^DISPLAY=')"
    # local ACTIVETTY="$(cat /sys/class/tty/tty0/active)"
    # mapfile -t PROCS< <(pgrep -t "${ACTIVETTY}")
    # for PROC in "${PROCS[@]}}"; do
        # if [[ "$(loginctl show-session -p State --value ${SESS})" =~ "active" ]]; then local ACTIVESESS="${SESS}"; fi
        # local DISP="$(awk -v RS='\0' -F= '$1=="DISPLAY" {print $2}' /proc/${PROC}/environ 2>/dev/null)"; [[ -n "${DISP}" ]] && break;
    # done;
    echo -e "${DISP}"
}

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

function buildkerneldeb() {
    unset MAKEFLAGS
    unset ARCH
    CONCURRENCY_LEVEL=16 make-kpkg --rootcmd=fakeroot --verbose --arch-in-name --arch amd64 -j16 --initrd --uc --us kernel_image kernel_headers
}

function buildkernel() {
    unset ARCH
    make oldconfig
    # CONCURRENCY_LEVEL=8 screen fakeroot make-kpkg --us --uc --revision 1.KMG --initrd kernel_image kernel_headers
    CONCURRENCY_LEVEL=16 fakeroot make -j16 deb-pkg
}

function bytestohuman() {
    b=${1:-0}; d=''; s=0; S=(Bytes {K,M,G,T,P,E,Z,Y}iB)
    while ((b > 1024)); do
        d="$(printf ".%02d" $((b % 1024 * 100 / 1024)))"
        b=$((b / 1024))
        let s++
    done
    echo "$b$d ${S[$s]}"
}

function cache_gpg_pass() {
    local TMPFILE=$(mktemp)
    gpg --quiet --with-keygrip -K "${GPG_KEY}" > ${TMPFILE}
    local GPG_KEYGRIP="$(ack '\sKeygrip = (?<keygrip>[a-zA-Z][0-9].*$)' ${TMPFILE} --output '$+{keygrip}')"
    /usr/lib/gnupg/gpg-preset-passphrase --preset "${GPG_KEYGRIP}"
    gpg-connect-agent reloadagent /bye
}

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

function checkkey() {
    openssl rsa -check -text -noout -in "$1"
}

function checkstarttls() {
    openssl s_client -CAfile /etc/ssl/certs/ca-certificates.crt -showcerts -connect "$1":25 -starttls smtp
}

function checktls() {
    openssl s_client -CAfile /etc/ssl/certs/ca-certificates.crt -showcerts -connect "$1"
}

function clean_repos() {
    local CWD=$(pwd)
    mapfile -t REPOS< <(find ${CWD} -type d -name '.git' -exec readlink -f {} \;)
    unset GIT_CURL_VERBOSE
    export GIT_PROMPT_DISABLE=1
    for REPO in "${REPOS[@]}"; do
        local REPO_PATH="${REPO%/.git}"
        git -C "${REPO_PATH}" reset --hard HEAD
        git -C "${REPO_PATH}" clean -fdx
    done
}

function compare_dirs() {
    diff --brief --recursive "$1" "$2"
}

function confirm() {
    read -p "Are you sure you want to $1? (y/n): " -n 1 -r REPLY
    echo -e "\n"
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        return 0
    else
        return 1
    fi
}

function copysite() {
    local domain=$(echo "$@" | awk -F/ '{print $3}')
    wget --recursive --page-requisites --html-extension --convert-links --domains "$domain" --no-parent "$@"
}

function cpanu() {
    perl -MCPAN -e 'foreach (@ARGV) { CPAN::Shell->rematein("notest", "install", $_) }' $@
}

function disable() {
    local PROGRAM="$1"
    if confirm "disable ${PROGRAM}" -eq 0; then
	sudo systemctl disable "${PROGRAM}"
	local EXITSTATUS="$?"
	sleep 1s
	[[ ${EXITSTATUS} == 0 ]] && success "Disabled ${PROGRAM}." || failure "Failed to disable ${PROGRAM}."
    else
	failure "No action taken."
    fi
}

function del_remote_branch() {
    local REMOTE=$(git -C "$(pwd)" remote show | head -1)
    local BRANCH=$(git -C "$(pwd)" symbolic-ref --short "refs/remotes/${MAIN_REMOTE}/HEAD" | sed "s@^${REMOTE}/@@")
    git push "${REMOTE}" --delete "${BRANCH}"
    success "Deleted git branch ${BRANCH} on remote ${REMOTE}."
}

function dns() {
    dig +nocmd "$1" any +multiline +noall +answer
}

function dumpcerts() {
    openssl s_client -CAfile /etc/ssl/certs/ca-certificates.crt -showcerts -verify 5 -connect "$1" < /dev/null | awk '/BEGIN/,/END/{ if(/BEGIN/){a++}; out="cert"a".pem"; print >out}'
    for cert in *.pem; do newname=$(openssl x509 -noout -subject -in $cert | sed -n 's/^.*CN=\(.*\)$/\1/; s/[ ,.*]/_/g; s/__/_/g; s/^_//g;p').pem; mv $cert $newname; done
}

function clrdockerenv() {
    unset DOCKER_TLS_VERIFY
    unset DOCKER_CERT_PATH
    unset COMPOSE_TLS_VERSION
}

function clrflags() {
    declare -a VARS=("CGO_LDFLAGS" "GCJFLAGS" "GOGCCFLAGS" "FFLAGS" "CXXFLAGS" "LDFLAGS" "CPPFLAGS" "CGO_CFLAGS" "CGO_CXXFLAGS" "FCFLAGS" "OBJCFLAGS" "NVM_CD_FLAGS" "CGO_FFLAGS" "CFLAGS" "OBJCXXFLAGS")
    for i in "${VARS[@]}"; do
        unset $i
    done
}

function clrtmp() {
    local LASTBOOT="$(/usr/bin/last --time-format iso reboot | /usr/bin/head -2 | /usr/bin/tail -1 | /usr/bin/cut -d' ' -f8)"
    local LASTBOOT_EPOCH=$(/bin/date -d"${LASTBOOT}" +%s)
    mapfile -t OLD_TMPFILES < <(find /tmp /var/tmp -printf '%T@:%p\n')
    for TMPFILE in ${OLD_TMPFILES[*]}; do
        MODIFIED=$(echo "${TMPFILE}" | cut -z -d':' -f1 | cut -d'.' -f1)
        OLD_TMPFILENAME=$(echo "${TMPFILE}" | rev | cut -z -d':' -f1 | rev)
        if [ "$MODIFIED" -gt "$LASTBOOT_EPOCH" ]; then
            rm -rf "${OLD_TMPFILENAME}"
        fi
    done
}

function clrwineflags() {
    declare -a VARS=("WINESERVER" "WINEDLLPATH" "WINEARCH" "WINEPREFIX" "WINELOADER" "WINEDEBUG" "WINETRICKS_GUI" "WINE")
    for i in "${VARS[@]}"; do
        unset $i
    done
}

function dockerexec() {
    local container="$1"
    docker exec --privileged -it "$1" /bin/bash
}

function dockernets() {
    local containers=$(docker ps -a -q)
    for container in $containers; do
        docker inspect --format '{{ .NetworkSettings.IPAddress }}' "$container"
    done
}

function dockerrm() {
    local containers=$(docker ps -a -q)
    local images=$(docker images -q)
    for container in $containers; do
        docker rm "$container"
    done
    for image in $images; do
        docker rmi "$image"
    done
}

function dockerstop() {
    local containers=$(docker ps -a -q)
    for container in $containers; do
        docker stop "$container"
    done
}

function dockervols() {
    local containers=$(docker ps -a -q)
    for container in $containers; do
        docker inspect --format '{{ .Volumes }}' "$container"
    done
}

function enable() {
    local PROGRAM="$1"
    if confirm "enable ${PROGRAM}" -eq 0; then
        sudo systemctl enable "${PROGRAM}"
        local EXITSTATUS="$?"
        sleep 1s
        [[ ${EXITSTATUS} == 0 ]] && success "Enabled ${PROGRAM}." || failure "Failed to enable ${PROGRAM}."
    else
        failure "No action taken."
    fi
}

function encodemp3() {
    local FULLPATH=$(readlink -e "$1")
    local INPUTMEDIA=$(basename "$1")
    local FNAME=$(echo "${INPUTMEDIA}" | cut -d'.' -f1)
    local DESTDIR=$(dirname "${FULLPATH}")
    ffmpeg -i "$1" -vn -ab 128k -acodec libmp3lame -ar 44100 -y "${DESTDIR}/${FNAME}.mp3"
}

function examinecert() {
    openssl x509 -inform PEM -in "$1" -text -noout
}

function examinekey() {
    openssl rsa -in "$1" -text -noout -check
}

function failure() {
    ERR="$1"
    echo -e "\e[01;31m* $ERR\e[0m" 1>&2
}

function f() {
    find . -not -iwholename '*.svn*' -not -iwholename '*.git*' -iname "*$1*"
}

function find_dirty_repos() {
    local CWD=$(pwd)
    mapfile -t REPOS< <(find ${CWD} -type d -name '.git' -exec readlink -f {} \;)
    declare -a DIRTY_REPOS=()
    for REPO in "${REPOS[@]}"; do
        local REPO_PATH=${REPO%/.git}
        git -C "$REPO_PATH" diff-index --quiet HEAD -- &>/dev/null
        local GITSTATUS=$?
        if [ "$GITSTATUS" -eq 1 ]; then
            DIRTY_REPOS+=($REPO_PATH)
            failure "$REPO_PATH is dirty."
            # modifications
            # timelimit -q -t 3 -T 5 git -C $REPO_PATH diff --minimal --compact-summary | pr -to 4
            # untracked files
            # timelimit -q -t 3 -T 5 git -C $REPO_PATH ls-files . --abbrev --exclude-standard --others | pr -to 4
            timelimit -q -t 3 -T 5 git -C $REPO_PATH status -su | pr -to 4
        else
            success "$REPO_PATH is clean."
        fi
    done
}

function fixpycode() {
    autopep8 --max-line-length=120 --list-fixes -i "$1"
    yapf -i -vv "$1"
    black --line-length=120 -v "$1"
    /usr/local/bin/reindent3 "$1"
}

function fixlogitech() {
    # c52b :
    # 046d : Logitech
    find '/sys/devices/pci0000:00' -iname idProduct -exec cat {} \;
}

function flushiptables() {
    declare -a iptcmds=("/usr/sbin/iptables" "/usr/sbin/ip6tables")
    for i in "${iptcmds[@]}"; do
        # [ ! -e $i -a ! -x $i ]
        local ipt="sudo $i"
        $ipt -P INPUT ACCEPT
        $ipt -P FORWARD ACCEPT
        $ipt -P OUTPUT ACCEPT
        $ipt -F
        $ipt -X
        $ipt -t nat -F
        $ipt -t nat -X
        $ipt -t mangle -F
        $ipt -t mangle -X
        $ipt -t raw -F
        $ipt -t raw -X
    done
}

function freespace() {
    local CWD=$(pwd)
    mapfile -t BIGFILES< <(find ${CWD} -xdev -type f -size +50M -printf  '%s\t%k\t%p\n' | numfmt --field=1 --from=iec --to=si --padding=8 | sort -rh | tail -100)
    for f in "${BIGFILES[@]}"; do
        local FNAME="$(echo $f | cut -d' ' -f3)"
        local FSIZEKB="$(echo $f | cut -d' ' -f2)"
        read -p "\nPress 'y' to delete ${FNAME}, 'm' to move it to another directory, and 'k' to keep: " -n 1 -r REPLY
        if [[ $REPLY =~ ^[Mm]$ ]]; then
            read -e -p "\nEnter new destination for ${FNAME}: " -n 64 -r DESTDIR
            if [[ -d "${DESTDIR}" ]]; then
                local FREESPACE="$(df -k --sync ${DESTDIR} | awk '{ print $4 }' | tail -n 1| cut -d'%' -f1)"
                declare -i REMAINING=$(($FREESPACE - $FSIZEKB))
                if [[ "${REMAINING}" -gt 1024 ]]; then
                    local REMAINING_HUMAN_READABLE=$(printf '%dK\t' "${REMAINING}" | numfmt --field=1 --format="%-10f" --zero-terminated --from=auto --to=iec --padding=8)
                    success "\nThere will be ${REMAINING_HUMAN_READABLE} kilobytes left available on that filesystem after migrating the file..."
                    sudo mv -ivun -t "${DESTDIR}/" "${FNAME}" &
                fi
            fi
        elif [[ $REPLY =~ ^[Kk]$ ]]; then
            success "\nKeeping ${FSIZEKB} ${FNAME} where it's located."
        elif [[ $REPLY =~ ^[Yy]$ ]]; then
            sudo rm --preserve-root=all --one-file-system -rfvi "${FNAME}"
        fi
    done
    for job in $(jobs -p); do
        wait -n "$job"
    done
}

function gencert() {
    cd /etc/pki
    export EASYRSA=$(pwd)
    ./easyrsa --batch --req-cn="$1" gen-req "$1" nopass
    read -e -p "Enter any DNS subject alternative names (SANs) for $1: " -n 24 -r REPLY
    if [[ $REPLY =~ ^\.(com|org|net|pro)$ || $REPLY == 'localhost' ]]; then
        AVGPING=$(printf '%-8.2f' "$(fping -c3 -t300 --ipv4 --iface=eth0 -i 100 -W 3 "$REPLY" | tail -1 | awk '{ print $4 }' | cut -d '/' -f 2)")
        DIGTIME=$(dig +noall +stats +timeout=3 @"$REPLY" google.com | awk '/Query/{sum+=$4}END{print ""sum"ms"}')
        echo "AVGPING: $AVGPING"
        echo "DIGTIME: $DIGTIME"
        if (( $(echo "$AVGPING == 0" | bc -l) )) && (( $(echo "$DIGTIME == 0" | bc -l) )); then
            failure "Couldn't ping/dig $REPLY. Not adding SAN to certificate."
            local SANS=""
            echo "SANS1: ${SANS}"
        else
            local SANS="DNS:${REPLY}"
            echo "SAN2S: ${SANS}"
        fi
    else
        local SANS=""
        echo "SANS3: ${SANS}"
    fi
    unset REPLY
    read -e -p "Enter any IP subject alternative names (SANs) for $1: " -n 24 -r REPLY
    if [[ $REPLY =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        AVGPING=$(printf '%-8.2f' "$(ping -c 10 -i 1 -W 3 "$REPLY" | tail -1 | awk '{ print $4 }' | cut -d '/' -f 2)")
        if (( $(echo "$AVGPING == 0" | bc -l) )); then
            failure "Couldn't ping $REPLY. Not adding SAN to certificate."
        else
            echo "SANS4: ${SANS}"
            [[ -z "$SANS" ]] && local SANS="IP:${REPLY}"
            [[ ! -z "$SANS" ]] && SANS+=",IP:${REPLY}"
        fi
    else
        failure "${REPLY} is not a valid IP address. Not adding SAN to certificate."
    fi
    echo "SANS: ${SANS}"
}
# easyrsa --batch --subject-alt-name='${REPLY}' sign-req server example.org

function gendhparam() {
    local OUTDIR="/etc/ssl"
    echo -e "Generating Diffie-Hellman parameters...\n"
    dhdata=$(tempfile 2>/dev/null)
    # trap "rm -f $dhdata" 0 1 2 5 15
    local ans="$(zenity --list --text "DH parameter size" --radiolist --height=256 --width=128 --column "Choose" --column "Bits" FALSE 1024 FALSE 2048 FALSE 3072 TRUE 4096)"
    echo -e "$ans\n"

    export ANS="/tmp/ans.$$"
    mkfifo $ANS

    dialog --backtitle "Parameter generation" --title "Diffie-Hellman key length" --output-fd 3 --stdout --radiolist "Choose:" 12 40 4 \
           1 "1024" off \
           2 "2048" off \
           3 "3072" off \
           4 "4096" on >&3


    case $(cat $dhdata) in
        1) export DH_KEYLENGTH=1024;;
        2) export DH_KEYLENGTH=2048;;
        3) export DH_KEYLENGTH=3072;;
        4) export DH_KEYLENGTH=4096;;
    esac

    return 0

    while true; do
        read -p "How many bytes? [1024] [2048] [4096] E[x]it: " -a array
        for choice in "${array[@]}"; do
            case "$choice" in
                [1-1024]*)
                    export DHBITS="1024"; break;;
                [20-2048]*)
                    export DHBITS="2048"; break;;
                [30-3072]*)
                    export DHBITS="3072"; break;;
                [40-4096]*)
                    export DHBITS="4096"; break;;
                [x]* ) echo "Cancelled dhparam generation."; return 0;;
                * ) failure "Invalid option."; return 0;;
            esac
        done
    done
    local numre="^[0-9]+$"
    if [[ "${DHBITS}" =~ $numre ]]; then
      read -p "Chosen ${DHBITS} bits. Where do you want to write them? (${OUTDIR}): " -n 1 -r DHDEST
      echo -e "\n"
      if [[ $DHDEST =~ [^a-zA-Z0-9\ \/$] ]] && [ -d "$DHDEST" ]; then
        openssl dhparam -out "${DHDEST}/dhparam-${DHBITS}.pem" "${DHBITS}"
      fi
    fi
}

function genpw() {
    if hash diceware 2>/dev/null; then
        local wordcount
        wordcount=9
        if hash xclip 2>/dev/null; then
            diceware "$@" -n $wordcount | tee >(xclip -selection clipboard)
        else
            diceware "$@" -n $wordcount
        fi
    else
        strings /dev/urandom | grep -o '[[:alnum:]]' | head -n 32 | tr -d '\n' | head -c 24
        echo
    fi
}

function get_ssh_pubkey() {
      local SSHPUBKEY="$(mktemp)"
      ssh-keygen -v -y -f "$1" > "${SSHPUBKEY}"
  /bin/cat "${SSHPUBKEY}"
}

function gen_smartcard_key() {
    local GPG_KEY_ALGO="RSA"
    local GPG_KEY_CREATION_DATE="$(date +%Y-%m-%d)"
    if [[ -z "${GNUPGHOME}" ]]; then
        exec 4>&1;
        export GNUPGHOME=$(dialog --inputbox 'Confirm your GNUPGHOME:'  0 0 "${HOME}/.gnupg" 2>&1 1>&4)
        exec 4>&-;
    fi
    echo -e "GNUPGHOME is ${GNUPGHOME}\n"
    exec 5>&1;
    local GPG_KEY_PASSWORD=$(dialog --passwordbox 'Password:' 0 0 2>&1 1>&5);
    exec 5>&-;
    exec 6>&1;
    local GPG_KEY_NAME=$(dialog --inputbox 'Name:' 0 0 2>&1 1>&6);
    exec 6>&-;
    exec 7>&1;
    local GPG_KEY_EMAIL=$(dialog --inputbox 'E-mail:' 0 0 2>&1 1>&7);
    exec 7>&-;
    exec 8>&1;
    local GPG_KEY_EXPIRY=$(dialog --inputbox 'Expiry:' 0 0 '5y' 2>&1 1>&8);
    exec 8>&-;

    local DIALOG_RESULT=$(mktemp 2>/dev/null)
    # trap "rm -f ${DIALOG_RESULT}" 0 1 2 5 15
    local GPG_KEY_SIZE=$(whiptail --title "GPG key size" --radiolist "Choose:" 12 40 4 \
			   1 "1024" off \
			   2 "2048" off \
			   3 "3072" off \
			   4 "4096" on 3>&1 1>&2 2>&3)
    case $(echo ${GPG_KEY_SIZE}) in
        1) local GPG_KEY_LENGTH=1024;;
        2) local GPG_KEY_LENGTH=2048;;
        3) local GPG_KEY_LENGTH=3072;;
        4) local GPG_KEY_LENGTH=4096;;
    esac
    echo -e "We'll generate a cert+sign primary key with the following parameters:\n"
    echo -e "Key-Type: ${GPG_KEY_ALGO}\n"
    echo -e "Key-Length: ${GPG_KEY_LENGTH}\n"
    echo -e "Name-Real: ${GPG_KEY_NAME}\n"
    echo -e "Name-Email: ${GPG_KEY_EMAIL}\n"
    echo -e "Expire-Date: ${GPG_KEY_EXPIRY}\n"
    echo -e "Passphrase: ${GPG_KEY_PASSWORD}\n"
    echo -e "Creation-Date: ${GPG_KEY_CREATION_DATE}\n"
    export GPG_PARAM_FILE="$(mktemp)"
    export GPG_KEY_TEMP_ALIAS=$(basename "${GPG_PARAM_FILE}" | cut -d'.' -f2)

/bin/cat << EOF > "${GPG_PARAM_FILE}"
%echo Generating a GPG key...
Key-Type: ${GPG_KEY_ALGO}
Key-Length: ${GPG_KEY_LENGTH}
Key-Usage: cert,sign
Name-Real: ${GPG_KEY_NAME}
Name-Email: ${GPG_KEY_EMAIL}
Expire-Date: ${GPG_KEY_EXPIRY}
Creation-Date: ${GPG_KEY_CREATION_DATE}
Passphrase: ${GPG_KEY_PASSWORD}
%no-protection
%transient-key
%pubring ${GNUPGHOME}/${GPG_KEY_TEMP_ALIAS}.pub
%secring ${GNUPGHOME}/${GPG_KEY_TEMP_ALIAS}.sec
%commit
%echo Done
EOF

    export GPG_FINGERPRINT=$(gpg --homedir "${GNUPGHOME}" --verbose --batch --status-fd=1 --generate-key "${GPG_PARAM_FILE}" | cut -d' ' -f4)
    gpg --import "${GNUPGHOME}/${GPG_KEY_TEMP_ALIAS}.pub"
    gpg --import "${GNUPGHOME}/.gnupg/private-keys-v1.d/${GPG_FINGERPRINT}.key"
    for cap in encrypt auth; do
        echo -e "Generating $cap key for ${GPG_FINGERPRINT}...\n"
        gpg --homedir "${GNUPGHOME}" --verbose --batch --quick-add-key ${GPG_FINGERPRINT} ${GPG_KEY_ALGO}${GPG_KEY_LENGTH} $cap ${GPG_KEY_EXPIRY}
    done
    echo -e "Setting your new key to ultimately trusted...\n"
    gpg --homedir "${GNUPGHOME}" --verbose --yes --list-keys --fingerprint --with-colons "${GPG_FINGERPRINT}" |
        sed -E -n -e 's/^fpr:::::::::([0-9A-F]+):$/\1:6:/p' |
        gpg --homedir "${GNUPGHOME}" --verbose --import-ownertrust --yes
}

function getdigest() {
    openssl x509 -pubkey <"$1" | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | base64
}


function getlinks() {
    lynx -listonly -dump "$1" | awk '/^[ ]*[1-9][0-9]*\./{sub("^ [^.]*.[ ]*","",$0); print;}'| sort -u
}

function getoffline() {
    NET_DEVICES=$(sudo lshw -short -C net -quiet -sanitize | tail +3 | awk {'print $2'})
    for device in $NET_DEVICES; do
        timelimit -q -t 3 -T 5 sudo ifdown "${device}"
    done
}

function getonline() {
    sudo systemctl restart systemd-networkd
    sudo systemctl restart networking
    sudo systemctl restart NetworkManager
    NET_DEVICES=$(sudo lshw -short -C net -quiet -sanitize | tail +3 | awk {'print $2'})
    for device in $NET_DEVICES; do
        timelimit -q -t 3 -T 5 sudo dhclient "${device}"
        timelimit -q -t 3 -T 5 sudo ifup "${device}"
    done
    sudo systemctl restart dnsmasq
    sudo systemctl restart coredns
    sudo systemctl restart systemd-resolved
}

function gitcommitdate() {
    GIT_COMMITTER_DATE="$(date)"
    git commit --amend --no-edit --date "$(date)"
}

function git_restore_deleted() {
    local DELETED="$1"
    local LAST_COMMIT="$(git rev-list -n 1 HEAD -- $DELETED)"
    LAST_COMMIT+='^'
    git checkout "${LAST_COMMIT}" -- "$DELETED"
}

function git_restore_previous() {
    local PREVIOUS="$1"
    local LAST_COMMIT="$(git rev-list -n 2 HEAD -- $PREVIOUS | tail -1)"
    LAST_COMMIT+='^'
    git checkout "${LAST_COMMIT}" -- "$PREVIOUS"
}

function headers() {
    curl -I https://"$1"
}

function hiprio() {
    local procs="$(pgrep -iw $1)"
    for proc in $procs; do
        sudo renice -n -19 -p "$proc"
        sudo ionice -c 2 -n 0 -p "$proc"
    done
}

function install_apt_depends() {
    sudo apt-get install $(apt-cache depends $1 | grep Depends | sed "s/.*ends:\ //" | tr '\n' ' ')
}

function kicksysd() {
    sudo systemctl daemon-reexec
    sudo systemctl daemon-reload
    sudo systemctl reset-failed
}

function killpulse() {
    local PULSE_PID="$(pgrep pulseaudio)"
    killall -wv pulseaudio
    sleep 1
    sudo kill -9 "$PULSE_PID"
}

function killvagrant() {
    local VPID="$(pgrep vagrant)"
    kill "${VPID}"
    sleep 1
    kill -9 "${VPID}"
}

function killvlc() {
    local VPID="$(pgrep vlc)"
    kill "$VPID"
    sleep 1
    kill -9 "$VPID"
}

function kpls () {
    if [ -z "$1" ]; then
        keepassxc-cli ls --recursive /home/$USER/dev/keepass.kdbx
    else
        keepassxc-cli ls /home/$USER/dev/keepass.kdbx "$1"
    fi
}

function kpshow () {
    keepassxc-cli show /home/$USER/dev/keepass.kdbx "$1"
}

function largefolders() {
    if [ -z "$1" ]; then
        local searchpath="$(pwd)"
    else
        local searchpath="$1"
    fi
    sudo find "${searchpath}" -xdev -maxdepth 5 -type d -print0 | xargs -0 du -bx --max-depth=5 2>/dev/null | perl -M'Number::Bytes::Human format_bytes' -lane 'my $SIZE = format_bytes ($F[0], bs=>1000, round_style => 'round', quiet => 1, precision => 2); shift @F; print $SIZE . "\t@F";' | sort -rh | head -20
}

function latlong() {
    curl http://ipinfodb.com 2>/dev/null | perl -0777 -nE 'm/Latitude : (-?\d+\.\d+).+?Longitude : (-?\d+\.\d+)/ms; say "$1:$2" if $1 and $2'
}

function listvms() {
    mapfile -t VBOX_VMS< <(VBoxManage list vms | sed -e 's/^"//' | cut -d'"' -f1)
    mapfile -d '}' -t VBOX_VM_UUIDS< <(VBoxManage list vms | cut -d'{' -f2)
    mapfile -d '}' -t VBOX_RUNNING_VMS< <(VBoxManage list runningvms | cut -d'{' -f2)
    for i in ${!VBOX_VMS[@]}; do
        local VBOXVM="${VBOX_VMS[$i]}"
        local VBOXID="${VBOX_VM_UUIDS[$i]}"
        if [[ ${VBOX_RUNNING_VMS[*]} =~ .*${VBOXID}.* ]]; then
            echo -e "\e[01;32m${VBOXVM} ${VBOXID} \n\e[0m"
        else
            echo -e "\e[01;31m${VBOXVM} ${VBOXID} \n\e[0m"
        fi
    done
}

function lock_resolv() {
    sudo chattr +i /etc/resolv.conf
}

function loprio() {
    local procs="$(pgrep -iw $1)"
    for proc in $procs; do
        echo "$proc"
        sudo renice -n +19 -p "$proc"
        sudo ionice -c 2 -n 7 -p "$proc"
    done
}

function makecolors() {
    ccred=$(echo -e "\033[0;31m")
    ccyellow=$(echo -e "\033[0;33m")
    ccend=$(echo -e "\033[0m")
    /usr/bin/make "$@" 2>&1 | sed -E -e "/[Ee]rror[: ]/ s%$pathpat%$ccred&$ccend%g" -e "/[Ww]arning[: ]/ s%$pathpat%$ccyellow&$ccend%g"
    return ${PIPESTATUS[0]}
}

function maketarbz() {
    # export TAR_OPTS="--auto-compress --one-file-system --quoting-style='literal' --utc --verbose --deference --compress --totals=SIGQUIT --ignore-failed-read --seek --wildcards --no-acls --no-selinux --no-xattrs --verify"
    if [ -d "$1" ]; then
        local ARCHIVENAME=$(basename "$1.tar.bz2")
        export BZIP2="-9"; tar -pcvjf "${TAR_OPTS}" "$1" "${ARCHIVENAME}"
    fi
}

function maketargz() {
    # export TAR_OPTS="--auto-compress --one-file-system --quoting-style='literal' --utc --verbose --deference --compress --totals=SIGQUIT --ignore-failed-read --seek --wildcards --no-acls --no-selinux --no-xattrs --verify"
    if [ -d "$1" ]; then
        local ARCHIVENAME=$(basename "$1.tar.xz")
        export XZ_OPT="-9"; tar -zpcvf "${TAR_OPTS}" "$1" "${ARCHIVENAME}"
    fi
}

function maketarxz() {
    # export TAR_OPTS="--auto-compress --one-file-system --quoting-style='literal' --utc --verbose --deference --compress --totals=SIGQUIT --ignore-failed-read --seek --wildcards --no-acls --no-selinux --no-xattrs --verify"
    if [ -d "$1" ]; then
        local ARCHIVEDIR=$(basename "$1.tar.gz")
        export GZIP="-9"; tar -pcvJf  "${TAR_OPTS}" "$1" "${ARCHIVENAME}"
    fi
}

function netdriver() {
    # takes as argument the interface name e.g. eth0 or wlan1, returns the underlying kernel driver
    ethtool -i "$1" | sed -n 's/^driver:\ //p'
}

function newcert() {
    openssl req -new -newkey rsa:4096 -nodes -sha512 -keyout domain.com.key -out domain.com.csr
}

function newlines() {
    sed -i 's/\\n/\n/g' "$1"
}

function noblanklines() {
    sed -i '/^$/d' "$1"
}

function nocomments() {
    cat "$1" | egrep -v "(^#.*|^$)"
}

function noleading() {
    sed -i "s/^[ \t]*//" "$1"
}

function noprio() {
    local procs="$(pgrep -iw $1)"
    for proc in $procs; do
        echo "$proc"
        sudo renice -n 0 -p "$proc"
        sudo ionice -c 1 -n 3 -p "$proc"
     done
 }
 
function parentproc() {
    local PSTREE="$(mktemp)"
    mkfifo "${PSTREE}"
    local PID="$(sudo pgrep -inxw $1)"
    for _pid in $PID; do
        local PARENTPID="$(sudo ps -o ppid= -p $_pid)"
        if [[ ! -z "${PARENTPID}" ]]; then
            echo -e "Parent of $_pid is ${PARENTPID}.\n"
            echo -e "$(sudo ps -p ${PARENTPID} -o command=)\n"
            local PARENTOFPARENTPID="$(sudo ps -o ppid= -p $PARENTPID)"
            if [ $? -eq 0 ]; then
                echo -e "The parent's parent is ${PARENTOFPARENTPID}\n"
            fi
        fi
        sudo pstree -ptshlU "${_pid}" >> $PSTREE 2>&1
    done
    sudo sed -rn "/.{$($PSTREE expand -t1 2>/dev/null | wc -L 2>/dev/null)}/{p;q}" $PSTREE 2>/dev/null
    sudo rm -f "${PSTREE}"
}

function pdfshrink() {
    local input=$1
    local output=$2
    if [ -e $1 ]; then
        gs -sDEVICE=pdfwrite -dCompatibilityLevel=1.6 -dPDFSETTINGS=/ebook -dNOPAUSE -dQUIET -dBATCH -sOutputFile="$2" "$1"
    fi
}

function perms_open() {
    find "$(pwd)" -type f -perm 0640 -exec chmod 664 {} \;
    find "$(pwd)" . -type d -perm 0755 -exec chmod 775 {} \;
}

function perms_strict() {
    find . -type f -perm 0640 -exec chmod 664 {} \;
    find . -type d -perm 0750 -exec chmod 775 {} \;
}

function proxy_on() {
    if [ -z ${HTTP_PROXY+http://127.0.0.1:8123/} ]; then
        failure "Proxy was not turned on."
        export HTTP_PROXY="http://127.0.0.1:8123"
    else
        success "Proxy will be set to '$HTTP_PROXY'.";
    fi
    export HTTPS_PROXY="$HTTP_PROXY"
    export SOCKS_PROXY="$HTTP_PROXY"
    export FTP_PROXY="$HTTP_PROXY"
    export ALL_PROXY="$HTTP_PROXY"
    export NO_PROXY="localhost,127.0.0.1,::1"
    env | grep --color=always -e _PROXY | sort
}

function proxy_off() {
    variables=("HTTP_PROXY" "HTTPS_PROXY" "ALL_PROXY" "FTP_PROXY" "SOCKS_PROXY")
    for i in "${variables[@]}"; do
	unset $i
    done
    env | grep --color=always -e _PROXY | sort
    success "Proxy turned off."
}

function proxy_switch() {
    success "Switching proxy to http://127.0.0.1:8118."
    export HTTP_PROXY="http://127.0.0.1:8118"
    proxy_on
}

function qt_switch() {
    read -p "Do you want to use 5.11.3, 5.12.6, 5.13.2, 5.14.0 (1, 2, 3 or 4)?: " -n 1 -r REPLY
    echo "REPLY IS: ${REPLY}\n"
    if [[ $REPLY =~ ^[1] ]]; then
        export LD_LIBRARY_PATH=/opt/qt/5.11.3/gcc_64/lib:$LD_LIBRARY_PATH
        export PATH=/opt/qt/5.11.3/gcc_64/bin:$PATH
        export QT_PLUGIN_PATH=/opt/qt/5.11.3/gcc_64/plugins/platforms
        export PKG_CONFIG_PATH=/opt/qt/5.11.3/gcc_64/lib/pkgconfig
        export QML_IMPORT_PATH=/opt/qt/5.11.3/gcc_64/qml
        export QML2_IMPORT_PATH=/opt/qt/5.11.3/gcc_64/qml
        export QT_QPA_PLATFORM_PLUGIN_PATH=/opt/qt/5.11.3/gcc_64/plugins
        success "QT has been set to 5.11.3."
    elif [[ $REPLY =~ ^[2] ]]; then
        export LD_LIBRARY_PATH=/opt/qt/5.12.6/gcc_64/lib:$LD_LIBRARY_PATH
        export PATH=/opt/qt/5.12.6/gcc_64/bin:$PATH
        export QT_PLUGIN_PATH=/opt/qt/5.12.6/gcc_64/plugins/platforms
        export PKG_CONFIG_PATH=/opt/qt/5.12.6/gcc_64/lib/pkgconfig
        export QML_IMPORT_PATH=/opt/qt/5.12.6/gcc_64/qml
        export QML2_IMPORT_PATH=/opt/qt/5.12.6/gcc_64/qml
        export QT_QPA_PLATFORM_PLUGIN_PATH=/opt/qt/5.12.6/gcc_64/plugins
        success "QT has been set to 5.12.6."
    elif [[ $REPLY =~ ^[3] ]]; then
        export LD_LIBRARY_PATH=/opt/qt/5.13.2/gcc_64/lib:$LD_LIBRARY_PATH
        export PATH=/opt/qt/5.13.2/gcc_64/bin:$PATH
        export QT_PLUGIN_PATH=/opt/qt/5.13.2/gcc_64/plugins/platforms
        export PKG_CONFIG_PATH=/opt/qt/5.13.2/gcc_64/lib/pkgconfig
        export QML_IMPORT_PATH=/opt/qt/5.13.2/gcc_64/qml
        export QML2_IMPORT_PATH=/opt/qt/5.13.2/gcc_64/qml
        export QT_QPA_PLATFORM_PLUGIN_PATH=/opt/qt/5.13.2/gcc_64/plugins
        success "QT has been set to 5.13.2."
    elif [[ $REPLY =~ ^[4] ]]; then
        export LD_LIBRARY_PATH=/opt/qt/5.14.0/gcc_64/lib:$LD_LIBRARY_PATH
        export PATH=/opt/qt/5.14.0/gcc_64/bin:$PATH
        export QT_PLUGIN_PATH=/opt/qt/5.14.0/gcc_64/plugins/platforms
        export PKG_CONFIG_PATH=/opt/qt/5.14.0/gcc_64/lib/pkgconfig
        export QML_IMPORT_PATH=/opt/qt/5.14.0/gcc_64/qml
        export QML2_IMPORT_PATH=/opt/qt/5.14.0/gcc_64/qml
        export QT_QPA_PLATFORM_PLUGIN_PATH=/opt/qt/5.14.0/gcc_64/plugins
        success "QT has been set to 5.14.0."
    fi
   env | grep --color=always -e '^QT' | sort
}

function rebuildcabundle() {
    perlbrew switch-off
    mk-ca-bundle -kmvf /etc/ssl/cacert.pem
    local TMPCABUNDLE=$(mktemp)
    grep -vE '^(#|================)' /etc/ssl/cacert.pem > ${TMPCABUNDLE}
    mapfile -t CA_METADATA < <(sed -e 's/END CERTIFICATE-----\(.*\)-----BEGIN CERTIFICATE/\1/' ${TMPCABUNDLE} | grep -vE 'BEGIN CERTIFICATE|END CERTIFICATE')
    mapfile -t CA_NAMES < <(sed -n '$!N;/BEGIN CERTIFICATE/P;D' ${TMPCABUNDLE} | grep -v 'BEGIN CERTIFICATE')
    for i in "${!CA_NAMES[@]}" ; do CA_NAMES[$i]="${CA_NAMES[$i]:-''}"; done
    for ca in "${CA_NAMES[@]}"; do
        sed -i "/^${ca}$/d" ${TMPCABUNDLE}
    done
    noblanklines ${TMPCABUNDLE}
    nocomments ${TMPCABUNDLE}
    nopreceding ${TMPCABUNDLE}
    clean ${TMPCABUNDLE}
    mv ${TMPCABUNDLE} /etc/ssl/cacert.pem
    chmod 640 /etc/ssl/cacert.pem
    chown root:ssl-cert /etc/ssl/cacert.pem
}

function reload() {
    sudo systemctl reload "$1"
}

function repackdeb() {
    if [ -e "$1" ]; then
        dpkg-deb -I "$1"
    fi
    export DPKGTMPDIR="$(mktemp -d)"
    export DEBARCHIVE="$(basename $1)"
    export FULLPATH="$(readlink -e $1)"
    export DPKGDEST="$(dirname $FULLPATH)"
    export NEWDEBARCHIVE=$(printf '%s\n' "${DEBARCHIVE%.deb}_repacked.deb")
    # trap "rm -rf ${DPKGTMPDIR}" EXIT
    mkdir -pv ${DPKGTMPDIR}
    fakeroot sh -c 'dpkg-deb -RvD "${FULLPATH}" "${DPKGTMPDIR}"; exit'
    # guake -n guake -e 'cd ${DPKGTMPDIR}; ls -lrt ${DPKGTMPDIR}' guake -r 'dpkg editing session'
    read -n 1 -s -r -p "${DEBARCHIVE} extracted to ${DPKGTMPDIR}. Press Enter when finished making modifications."
    fakeroot sh -c 'dpkg-deb -bvD "${DPKGTMPDIR}" "${DPKGDEST}/${NEWDEBARCHIVE}"'
    debdiff "${FULLPATH}" "${DPKGDEST}/${NEWDEBARCHIVE}"
    rm -rf "${DPKGTMPDIR}"
}

function restart() {
    local PROGRAM="$1"
    if confirm "restart ${PROGRAM}" -eq 0; then
        sudo systemctl restart "${PROGRAM}"
        local EXITSTATUS="$?"
        sleep 1s
        [[ ${EXITSTATUS} == 0 ]] && success "Restarted ${PROGRAM}." || failure "Failed to restart ${PROGRAM}."
    else
        failure "No action taken."
    fi
}

function rmdockerlogs() {
    local container="$1"
    local logpath="$(docker inspect --format='{{.LogPath}}' "$1"f)"
    truncate -s 0 "$logpath"
}

function rpmextract () {
    local RPMFILE=$1
    rpm2cpio "${RPMFILE}" | cpio -idmv
}

function setuplocale() {
    local l0c4l3=$(locale | cut -d '=' -f1)
    for loc in $l0c4l3; do
        export $loc=en_US.UTF-8
    done
}

function showcert() {
    openssl x509 -text -noout -dates -in "$1"
}

function show_module_settings() {
    systool -m "$1" -a
    systool -m "$1" -v
}

function signal() {
    # local signal_app_id="bikioccmkafdpakkkcpdbppfkghcmihk"
    # nohup /usr/bin/google-chrome --profile-directory=Default --app-id="${signal_app_id}" "$@" >/dev/null 2>&1 &
    nohup /usr/local/bin/signal-desktop >/dev/null 2>&1 &
}

function smiley() {
    RC=$?
    [[ ${RC} == 0 ]] && echo '😊' || echo "😠 ${RC}"
}

function sqldump() {
    local MYSQL_USERNAME="$1"
    local MYSQL_DATABASE="$2"
    local TODAYS_DATE="$(date +%F)"
    mysqldump -u "${MYSQL_USERNAME}" -p "${MYSQL_DATABASE}" --single-transaction --quick --lock-tables=false > "${MYSQL_DATABASE}_${TODAYS_DATE}.sql"
    gzip "${MYSQL_DATABASE}_${TODAYS_DATE}.sql"
}

function start() {
    local PROGRAM="$1"
    if confirm "start ${PROGRAM}" -eq 0; then
        sudo systemctl start "${PROGRAM}"
        local EXITSTATUS="$?"
        sleep 1s
        [[ ${EXITSTATUS} == 0 ]] && success "Started ${PROGRAM}." || failure "Failed to start ${PROGRAM}."
    else
        failure "No action taken."
    fi
}

function startvm() {
    VBoxManage startvm "$1" --type headless
    VBoxManage controlvm "$1" reset
}

function status() {
    sudo systemctl status "$1"
}

function stop() {
    local PROGRAM="$1"
    if confirm "stop ${PROGRAM}" -eq 0; then
        sudo systemctl stop "${PROGRAM}"
        local EXITSTATUS="$?"
        sleep 1s
        [[ ${EXITSTATUS} == 0 ]] && success "Stopped ${PROGRAM}." || failure "Failed to stop ${PROGRAM}."
    else
        failure "No action taken."
    fi
}

function stopvm() {
    VBoxManage controlvm "$1" savestate
    VBoxManage controlvm "$1" poweroff
}

function strlen() {
    echo "$@" | awk '{ print length }'
}

function success() {
    MSG="$1"
    echo -e "\e[01;32m* $MSG\e[0m"
}

function testssl() {
    /usr/local/bin/testssl.sh --openssl='/usr/bin/openssl' "$1"
}

function update_bash_completions() {
    mapfile -t COMPLETIONS < <(find /usr/share/bash-completion/completions -mindepth 1 -type f -exec readlink -sf {} \;)
    for C in "${COMPLETIONS[@]}"; do
        local COMPLETION="$(basename ${C})"
        if [[ ! -f "${COMPLETION}" ]]; then
            sudo ln -s "${C}" "/etc/bash_completion.d/${COMPLETION}"
        fi
    done
}

function update_repos() {
    local CWD=$(pwd)
    mapfile -t REPOS< <(find ${CWD} -type d -name '.git' -exec readlink -f {} \;)
    unset GIT_CURL_VERBOSE
    export GIT_PROMPT_DISABLE=1
    for REPO in "${REPOS[@]}"; do
        local REPO_PATH="${REPO%/.git}"
        timelimit -q -t 3 -T 5 git -C "${REPO_PATH}" fetch -q -4 --all
        local MAIN_REMOTE=$(git -C "${REPO_PATH}" remote show | head -1)
        local REPO_URL=$(git -C "${REPO_PATH}" remote get-url "${MAIN_REMOTE}")
        local REPO_NAME="$(basename ${REPO_URL})"
        local DEFAULT_BRANCH=$(git -C "$REPO_PATH" symbolic-ref --short "refs/remotes/${MAIN_REMOTE}/HEAD" | sed "s@^${MAIN_REMOTE}/@@")
        git -C ${REPO_PATH} checkout ${DEFAULT_BRANCH}
        timelimit -q -t 3 -T 5 git -C ${REPO_PATH} pull ${MAIN_REMOTE} ${DEFAULT_BRANCH}
        local EXITSTATUS="$?"
        [[ ${EXITSTATUS} == 0 ]] && success "Updated ${REPO_NAME}." || failure "Failed to update ${REPO_NAME}."
    done
}

function urlencode() {
    old_lc_collate=$LC_COLLATE
    LC_COLLATE=C
    local length="${#1}"
    for (( i = 0; i < length; i++ )); do
        local c="${1:i:1}"
        case $c in
            [a-zA-Z0-9.~_-]) printf "$c" ;;
            *) printf '%%%02X' "'$c" ;;
        esac
    done
     LC_COLLATE=$old_lc_collate
}

function urldecode() {
    local url_encoded="${1//+/ }"
    printf '%b' "${url_encoded//%/\\x}"
}

function verifycert() {
    openssl verify -verbose -CAfile <(cat "$2") "$1"
}

function viewlog() {
    if [ -z "$1" ]; then
        sudo journalctl -e --output json-pretty
    else
        sudo journalctl --output json-pretty -e -u "$1"
    fi
}

function whatsmyip() {
    local myipv4="$(dig +short -4 @resolver1.opendns.com myip.opendns.com A)"
    local myipv6="$(dig +short -6 @resolver1.ipv6-sandbox.opendns.com myip.opendns.com AAAA)"
    local reverse="$(dig +short -4 -x ${myipv4})"
    echo -e "${myipv4}\n${myipv6}\n${reverse}"
}

function wine_switch() {
    read -p "Do you want to set Wine to 32-bit or 64-bit? (32/64): " -n 3 -r REPLY
    echo "REPLY IS: ${REPLY}\n"
    if [[ $REPLY =~ ^[32.*] ]]; then
        export WINEARCH="win32"
        export WINEPREFIX="/media/data/wine32"
        export WINE="/opt/wine32/bin/wine"
        export WINESERVER="/opt/wine32/bin/wineserver"
        export WINELOADER="/opt/wine32/bin/wine-preloader"
        export WINEDEBUG="-all"
        # export WINEDLLPATH="/opt/wine32/lib:/usr/lib/x86_64-linux-gnu/wine"
        success "Wine has been set to 32-bit."
        echo -e "winetricks commands: dlls fonts settings winecfg regedit taskmgr explorer uninstaller shell folder annihilate\n"
        # sudo setcap cap_net_raw+epi /opt/wine32/bin/wine-preloader
        nohup winetricks --country=US --torify arch=32 prefix=win32 taskmgr >/dev/null 2>&1
    elif [[ $REPLY =~ ^[64.*] ]]; then
        export WINEARCH="win64"
        export WINEPREFIX="/media/data/wine"
        export WINE="/opt/wine64/bin/wine64"
        export WINESERVER="/opt/wine64/bin/wineserver64"
        export WINELOADER="/opt/wine64/bin/wine64-preloader"
        export WINEDEBUG="-all"
        # export WINEDLLPATH="/opt/wine64/lib64:/opt/wine64/lib:/usr/lib/x86_64-linux-gnu/wine"
        success "Wine has been set to 64-bit."
        echo -e "winetricks commands: dlls fonts settings winecfg regedit taskmgr explorer uninstaller shell folder annihilate\n"
        # sudo setcap cap_net_raw+epi /opt/wine64/bin/wine-preloader /opt/wine64/bin/wine64-preloader
        nohup winetricks --country=US --torify arch=64 prefix=wine taskmgr >/dev/null 2>&1
   fi
   env | grep --color=always -e '^WINE' | sort
}

function xauthority() {
  local XAUTH="$(ps -u $(id -u) -o pid= | xargs -I{} cat /proc/{}/environ 2>/dev/null | tr '\0' '\n' | grep -m1 '^XAUTHORITY=')"
  if [ -z "${XAUTH}" ]; then
      export XAUTHORITY="$HOME/.Xauthority"
  fi
  systemctl --user set-environment XAUTHORITY=${XAUTHORITY}
}

function yml2json() {
    python -c 'import json, sys, yaml ; y=yaml.safe_load(sys.stdin.read()) ; json.dump(y, sys.stdout)'
}

# Alias definitions.
if [ -f ~/.bash_aliases ]; then
    . ~/.bash_aliases
fi

#~/.bash_aliases
alias ansibledocs="nativefier --name 'Ansible Documentation' -e '5.0.11' --disable-dev-tools --verbose --clear-cache --icon '/home/$USER/dev/nativefier/ansible.png' --ignore-gpu-blacklist --show-menu-bar --single-instance --user-agent 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/77.0.3865.90 Safari/537.36' 'https://docs.ansible.com/ansible/latest/index.html'"
alias apk="sudo apk"
alias apt-cache="sudo apt-cache"
# alias apt-disable="sudo apt-disable"
# alias apt-enable="sudo apt-enable"
alias apt-expired="sudo apt-get -o Acquire::Check-Valid-Until=false"
alias apt-get="sudo apt-get"
alias bashrc="source ~/.bashrc"
alias biosinfo="sudo dmidecode --type bios"
alias bootlog="sudo journalctl --no-hostname -o short-monotonic --boot -0"
alias builddeb="dpkg-buildpackage -us -uc -b -D -rfakeroot -j16 -z9"
alias buildpy3mod="python3 setup.py sdist bdist_wheel"
alias buildpy3release="python3 setup.py egg_info -Db '' sdist bdist_egg"
alias chmod="sudo chmod"
alias chown="sudo chown"
alias cleanenv="env -i bash --noprofile --norc"
alias clean="sed -i 's/[ \t]*$//'"
alias clipboard="/usr/bin/xclip -selection clipboard"
alias cmdline="/bin/cat /proc/cmdline"
alias compileperlbrew="perlbrew install --notest --force -Dusethreads -Duselargefiles -Dcccdlflags=-fPIC -Doptimize=-O2 -Duseshrplib -Duse64bitall -Darchname=x86_64-linux-gnu -Dccflags=-DDEBIAN -Aldflags='-L/lib64 -L/usr/lib64'"
alias code="/usr/bin/code"
alias connections="ss -t -u -4  -n -p -f inet state ESTABLISHED src 192.168.1.200"
alias current_tty="loginctl list-sessions --output json-pretty | jq -r '.[] | .tty' | head -1"
alias dd="dd status=progress"
alias delpyc="find . -type d -name "__pycache__" -exec rm -rf {} \; && find . -type f -iname "*.pyc" -exec rm -rf {} \;"
alias diceware="diceware --no-caps --delimiter=' '"
alias df="df -h"
# alias dir='dir --color=auto'
alias dir='ls --color=auto --format=vertical'
alias dmesg="sudo dmesg"
alias dnslog="sudo less +G /var/log/dnsmasq.log"
alias dropcaches="sync && echo 1 > /proc/sys/vm/drop_caches && echo 2 > /proc/sys/vm/drop_caches && echo 3 > /proc/sys/vm/drop_caches"
alias dunderscores="find . -name \"* *\" -type d | /usr/local/bin/rename 's/ /_/g'"
alias du="du -h"
alias editresolv="sudo chattr -i /etc/resolv.conf && sudo vim /etc/resolv.conf"
alias enterchroot="schroot -v -c buster -d /home/kevin -s /bin/bash -u kevin -p --automatic-session"
alias egrep='egrep --color=auto'
alias enablesearch="stty -ixon"
alias errs="sudo journalctl --output json-pretty -p err -b"
alias exifprobe="exifprobe -c"
alias fgrep='fgrep --color=auto'
alias findstring="grep -Rnis"
alias fixscrn="xrandr --output HDMI-A-1 --right-of HDMI-A-0"
alias freshen="sudo apt-get -q -y install --reinstall --allow-downgrades -o Dpkg::Options::='--force-confold'"
alias funderscores="find . -name \"* *\" -type f | /usr/local/bin/rename 's/ /_/g'"
alias fwincoming="ufp -c -i -b | egrep -v '(172.17.0.1|169.254.0.1|224.0.0.[0-9]+|192.168.1.(1|2|255)|239.255.255.250)\s' | egrep -v '(SPT|DPT): 0\s'"
alias fwoutgoing="ufp -c -o -b | egrep -v '(172.17.0.1|169.254.0.1|224.0.0.[0-9]+|192.168.1.(1|2|255)|239.255.255.250)\s' | egrep -v '(SPT|DPT): 0\s'"
alias geoip2lookup='mmdblookup --file /usr/share/GeoIP/GeoLite2-ASN.mmdb --ip'
alias geoiplookup='geoiplookup -f /usr/share/GeoIP/GeoIPCity.dat'
alias getchmod="stat -c '%a %n' "
alias getxwindowid="xwininfo"
alias gitamend="git commit --amend --cleanup=strip --no-edit"
alias githist="git log --graph --topo-order --pretty=format:'%Cred%h%Creset -%C(yellow)%d%Creset %s %Cgreen(%cr)%Creset %C(cyan)<%an>%Creset' --abbrev-commit --date=relative"
alias gitignore="git ls-files -i --exclude-standard"
alias gitlog_branches="git log --graph --all --pretty=format:'%Cred%h%Creset -%C(yellow)%d%Creset %s %Cgreen(%cr) %C(bold blue)<%an>%Creset' --abbrev-commit --"
alias gitlog="git log --graph --pretty=format:'%Cred%h%Creset -%C(yellow)%d%Creset %s %Cgreen(%cr) %C(bold blue)<%an>%Creset' --abbrev-commit --"
alias gitlog_plain="git log --graph --pretty=format:'%h -%d %s (%cr) <%an>' --abbrev-commit --"
alias gitmodified="git diff --minimal --compact-summary ."
alias gitsubmodules="git submodule update --init --recursive"
alias git_tags="git fetch -v --all --tags && git for-each-ref --sort=taggerdate --format '%(refname) %(taggerdate)' refs/tags"
alias gituntracked="git ls-files . --exclude-standard --others"
alias globalprefix="export CMAKE_PREFIX_PATH=/usr; export MAKE_PREFIX_PATH=/usr"
# alias gpgreset='echo RELOADAGENT | gpg-connect-agent'
# alias gpg='/usr/bin/gpg2'
alias grep='grep --color=auto'
alias hist="history | sed 's/^[ ]*[0-9]\+[ ]*//'"
alias ionice="sudo ionice"
alias ipmiview="/opt/jdk1.8.0_241/bin/java -jar /opt/IPMI/IPMIView/IPMIView20.jar"
alias journalctl="sudo journalctl"
alias kill="sudo kill"
alias la='ls -A'
alias less='less -r'
alias largefiles="sudo find . -xdev -type f -size +50M -printf '%s\t%k\t%p\n' | numfmt --field=1 --from=iec --to=si --padding=8 | sort -rh | head -100"
alias listdbus_sess="dbus-send --session --dest=org.freedesktop.DBus --type=method_call --print-reply /org/freedesktop/DBus org.freedesktop.DBus.ListNames"
alias listdbus_sys="dbus-send --system --dest=org.freedesktop.DBus --type=method_call --print-reply /org/freedesktop/DBus org.freedesktop.DBus.ListNames"
alias listfailed="systemctl list-units --state=failed"
alias ll='ls -l'
alias l='ls -CF'
alias linuxdocs="less /usr/src/linux/Documentation/admin-guide/kernel-parameters.txt"
alias localprefix="export CMAKE_PREFIX_PATH=/usr/local; export MAKE_PREFIX_PATH=/usr;"
alias lockresolv="sudo chattr +i /etc/resolv.conf"
alias ls='ls -hF --color=tty'
alias meminfo="sudo lshw  -quiet -short -class memory"
alias mosh='mosh --server/usr/bin/mosh-server'
alias mount="sudo mount"
alias myhost='dig +short -4 -x $(myip)'
alias myip6='dig +short -6 @resolver1.ipv6-sandbox.opendns.com myip.opendns.com AAAA'
alias myip='dig -4 +short myip.opendns.com @resolver1.opendns.com'
alias mylocalip="ip addr show | grep -e 'inet' | awk {'print $2'} | grep -E '^192\.168\.*' | cut -d'/' -f1 | head -1"
alias newpw="pwgen -B 16 1 | tee >(xclip -selection clipboard)"
alias nocomment="sed -e 's/#.*//;/^\s*$/d'"
alias nopreceding="noleading"
alias ntpsync="sudo ntpdate -v -b -s -t 10 time.nist.gov 0.debian.pool.ntp.org 1.debian.pool.ntp.org 2.debian.pool.ntp.org 3.debian.pool.ntp.org"
alias optimize="export CFLAGS=\"-Ofast\"; export CPPFLAGS=\"-Ofast\";"
alias othercolumns="awk '{for (i=3; i<NF; i++) printf \"$i\" \" \"; print $NF}'"
alias perlupdate="cpan-outdated -p | cpanm --notest --quiet"
alias ping="ping -4 -c 100 -i 1 -W 3 -s 56 -t 64"
alias pkill="sudo pkill -e"
alias prevdir="cd -"
alias promreload="curl -X POST http://127.0.0.1:9090/prometheus/-/reload"
alias ps_mem="sudo ps_mem"
alias pulseenv="pax11publish -d -i"
alias pulseinputs="pacmd list-sources | grep -e 'index:' -e device.string -e 'name:'"
alias pulsemodules="pacmd list-modules | grep -e 'name:' | cut -d':' -f2 | sed -E 's/(<|>)//g'"
alias pulseoutputs="pacmd list-sinks | grep -e 'name:' -e 'index:'"
alias raminfo="sudo dmidecode --quiet --type 17 | more"
alias randhex="openssl rand -hex 16 | tee >(xclip -selection clipboard)"
alias renamelower="rename 'y/A-Z/a-z/'"
alias renice="sudo renice"
alias restoreconf="sudo apt-get -q -y install --reinstall -o Dpkg::Options::='--force-confmiss'"
alias reverse="dig +short -4 -x"
alias rotatelogs="/usr/sbin/logrotate /etc/logrotate.conf"
alias routerlog="sudo less +G /var/log/router.log"
alias runvlcasroot="sudo sed -i 's/geteuid/getppid/' /usr/bin/vlc"
alias saveaudio="youtube-dl --extract-audio --audio-format best"
alias scanclam="sudo clamscan --block-encrypted  --scan-mail=no --scan-archive=yes --max-scansize=500M --exclude-dir=/mnt --exclude-dir=/media --exclude-dir=smb4k --exclude-dir=/run/user/root/gvfs --exclude-dir=/root/.gvfs --exclude-dir=^\/root\/\.clamtk\/viruses --exclude-dir=^\/sys\/ --exclude-dir=^\/dev\/ --exclude-dir=^\/proc\/ --exclude-dir=.thunderbird --exclude-dir=.mozilla-thunderbird --exclude-dir=Mail --exclude-dir=kmail --exclude-dir=evolution --max-filesize=20M --recursive=yes -v"
alias servnfs="exportfs -vfsar"
alias sessionbus="sudo -u $USER systemctl --user"
alias shellformat="shfmt -ci -sr -s -f"
alias showlinks="lynx -dump -listonly -nonumbers"
alias snd_default_input="pacmd list-sources | grep -e 'index:' -e device.string -e 'name:' | grep -A 1 '*' | tail -1 | cut -d':' -f2 | sed -E 's/(<|>)//g'"
alias snd_default_output="pacmd list-sinks | grep -e 'name:' -e 'index:' | grep -A 1 '*' | tail -1 | cut -d':' -f2 | sed -E 's/(<|>)//g'"
alias soundtest="speaker-test -t wav -c 2"
alias startdbus="/usr/bin/dbus-daemon --session --address=unix:path=/run/user/${MYUID}/bus --syslog --fork --systemd-activation"
alias startpulse="/usr/bin/pulseaudio --verbose --use-pid-file --disallow-exit=1 --fail=1 --daemonize -F /etc/pulse/default.pa"
alias suatom="sudo /usr/bin/atom --safe --new-window --clear-window-state"
alias sucat="sudo cat"
alias suchrome="sudo google-chrome --no-sandbox --user-data-dir=/root/.config/google-chrome"
alias sucode="sudo /usr/bin/code --user-data-dir='/root/.config/Code'"
alias sucp="sudo cp"
alias sudo="/usr/bin/sudo -E -H -n -S"
alias suln="sudo ln"
alias sumkdir="sudo mkdir"
alias sumv="sudo mv"
alias sup6="ss -t -u -4 -l -r -n -p '( src 0.0.0.0 )'"
alias suppresserrors="export CFLAGS=\"-Wno-error\"; export CXXFLAGS=\"-Wno-error\""
alias suptcp="ss -t -4 -l -r -n -p -f inet '( src 0.0.0.0 )'"
alias supudp="ss -u -4 -l -r -n -p -f inet '( src 0.0.0.0 )'"
alias surm="sudo rm"
alias susublime="sudo /opt/sublime_text/sublime_text --new-window"
alias suvim="sudo vim"
alias svncleanup="svn status --no-ignore | grep '^[I?]' | cut -c 9- | while IFS= read -r f; do rm -rf "$f"; done"
alias syslog="sudo less +G /var/log/syslog"
alias systemctl="sudo systemctl"
alias torlog="sudo less +G /var/log/tor/notice.log"
alias torrenttrackers="git -C /home/$USER/dev/trackerslist pull && cat /home/$USER/dev/trackerslist/trackers_best.txt | tee >(xclip -selection clipboard)"
# alias totp2="oathtool -b --totp REDACTED"
alias totp="oathtool -b --totp $(cat ~/.google_authenticator | head -1)"
# alias totp_twitter="oathtool -b --totp REDACTED"
alias traceopen="strace -d -v -o /tmp/strace.txt -e trace=open,ioctl"
alias trace="strace -d -v -o /tmp/strace.txt"
alias ufwlog="sudo cat /var/log/ufw.log | grep 'BLOCK' | less +G"
alias updatecacerts="sudo mk-ca-bundle -kmvf /etc/ssl/cacert.pem"
alias updategotools="go get -u golang.org/x/tools/..."
alias updatenodejs="npm -g update --unsafe-perm=true --allow-root"
alias updatepy2="python2 -m pip_review --auto && pip-check -c pip2 -rfHu"
alias updatepy3="python3 -m pip_review --auto && pip-check -c pip3 -rfHu"
# alias vdir='vdir --color=auto'
alias vdir='ls --color=auto --format=long'
alias vlc="/usr/bin/vlc"
alias weather='curl wttr.in'
alias whence='type -a'
alias wine="/opt/wine64/bin/wine64"
alias winefix="sudo sysctl -w vm.mmap_min_addr=0"
alias xwindows="xlsclients | awk {'print $2'} | sort -u && xwininfo -root -children"
alias zcalc="/usr/bin/zsh -c zcalc"
alias zcashwallet="java -jar /home/$USER/dev/zcash-swing-wallet/build/jars/ZCashSwingWalletUI.jar"
alias zero="truncate -s 0"

if ! shopt -oq posix; then
    if [ -f /usr/share/bash-completion/bash_completion ]; then
        . /usr/share/bash-completion/bash_completion
    elif [ -f /etc/bash_completion ]; then
        . /etc/bash_completion
    fi
fi


if [ -x /usr/lib/command-not-found -o -x /usr/share/command-not-found/command-not-found ]; then
    function command_not_found_handle {
        # check because c-n-f could've been removed in the meantime
        if [ -x /usr/lib/command-not-found ]; then
            /usr/lib/command-not-found -- "$1"
            return $?
        elif [ -x /usr/share/command-not-found/command-not-found ]; then
            /usr/share/command-not-found/command-not-found -- "$1"
            return $?
        else
            printf "%s: command not found\n" "$1" >&2
            return 127
        fi
    }
fi

export SSH_ENV="$HOME/.ssh/environment"
if [[ -f "${SSH_ENV}" ]]; then
    eval "$(cat "${SSH_ENV}")"
fi

if [ ! -f "$HOME/.Xauthority" ]; then
    xauth generate "${DISPLAY}" . trusted
    xauth add localhost:${DISPLAY} . $(xxd -l 16 -p /dev/urandom)
    xauth list
fi

if [[ ! -d "/run/user/$(id -u)" ]]; then
    sudo -EP mkdir -p "/run/user/$(id -u)"
    sudo -EP chown -R "$(id -u):$(id -u)" "/run/user/$(id -u)"
fi

if [ -z "${DIRMNGR_INFO}" ]; then
    DIRMNGR_PID=$(pgrep -nx -U "$(id -u)" dirmngr)
    export DIRMNGR_INFO="/run/user/$(id -u)/gnupg/S.dirmngr:${DIRMNGR_PID}:1"
    # eval "$(dirmngr --daemon --options ~/.gnupg/dirmngr.conf)"
fi

# eval $(cat ~/.gnupg/gpg-agent-info)

# export ALL_PROXY="socks5://127.0.0.1:9050"
export ANSIBLE_NOCOWS=1
export ANSIBLE_LOAD_CALLBACK_PLUGINS=1
# export ARCH=amd64
export ATOM_HOME="$HOME/.atom"
export AUTOMATED_TESTING=0
export AUTO_NTFY_DONE_IGNORE="vim screen tmux sudo ssh rsync byobu irssi nano"
export AUTO_NTFY_DONE_LONGER_THAN=-L30
export AUTO_NTFY_DONE_UNFOCUSED_ONLY=-b
export BROWSER="google-chrome"
export BZIP2="-9"
export CHARSET=UTF-8
export COLUMNS=132; export LINES=44;
export CPANSCRIPT_LOGLEVEL=WARN
export CPAN_RUN_SHELL_TEST_WITHOUT_EXPECT=1
export CURL_CA_BUNDLE="/etc/ssl/certs/ca-certificates.crt"
export CVSROOT="/home/$USER/dev/"
export COMPOSE_TLS_VERSION="TLSv1_2"
export DEB_BUILD_HARDENING=1
export DEB_BUILD_MAINT_OPTIONS="hardening=+all"
export DEB_DH_MAKESHLIBS_ARG="--ignore-missing-info"
# export DEBFULLNAME=""
# export DEBEMAIL=""
# export DOCKER_CERT_PATH="/home/$USER/.docker"
# export DOCKER_TLS_VERIFY=0
export DOCKER_HOST="unix:///var/run/docker.sock"
export DBUS_SYSTEM_BUS_ADDRESS="unix:path=/var/run/dbus/system_bus_socket"
# export DISPLAY="$(activedisplay)"
export EDITOR="vim"
export FIGNORE=".o .svn .pyc .pyo .swp .swa .DS_Store .git .localized .egg-info"
export GCC_COLORS='error=01;31:warning=01;35:note=01;36:caret=01;32:locus=01:quote=01'
export GIT_CURL_VERBOSE=1
# export GIT_AUTHOR_NAME=""
# export GIT_AUTHOR_EMAIL=""
export GIT_COMMAND="/usr/bin/git"
# export GIT_COMMITTER_NAME=""
# export GIT_COMMITTER_EMAIL=""
export GIT_DISCOVERY_ACROSS_FILESYSTEM=1
export GIT_EDITOR="vim"
export GIT_PROMPT_DISABLE=1
export GIT_PROMPT_ONLY_IN_REPO=1
export GIT_PROMPT_FETCH_REMOTE_STATUS=0
export GIT_PROMPT_SHOW_UPSTREAM=0
export GIT_PROMPT_IGNORE_SUBMODULES=1
export GIT_PROMPT_WITH_VIRTUAL_ENV=1
export GIT_PROMPT_SHOW_UPSTREAM=1
export GIT_PROMPT_SHOW_UNTRACKED_FILES=normal
export GIT_PROMPT_SHOW_CHANGED_FILES_COUNT=1
export GIT_PROMPT_COMMAND_FAIL="😠 ${Red}✘ "
export GIT_PROMPT_COMMAND_OK="😊 ${Green}✔  "
# export GIT_PROMPT_START="$(__vte_osc7)"
export GIT_PROMPT_THEME="Solarized_UserHost"
export GIT_PROMPT_WITH_USERNAME_AND_REPO=1
# export GIT_PROMPT_END="$(__vte_osc7) $(smiley)"
export GNOME_ACCESSIBILITY=0
export GNUPGHOME="$HOME/.gnupg"
export GOOGLE_APPLICATION_CREDENTIALS=''
export GOPATH="$HOME/go"
export GOCACHE="$HOME/.cache/go-build"
export GOARCH="amd64"
export GOHOSTARCH="amd64"
export GOHOSTOS="linux"
export GOOS="linux"
export GOROOT="/usr/local/go"
export GOTOOLDIR="/usr/local/go/pkg/tool/linux_amd64"
export GS_LIB=/usr/share/ghostscript/fonts
# export GREP_OPTIONS='--color=auto'
export CGO_CFLAGS="-g -Ofast -O3 -O2"
export CGO_CXXFLAGS="-g -Ofast -O3 -O2"
export CGO_FFLAGS="-g -Ofast -O3 -O2"
export CGO_LDFLAGS="-g -Ofast -O3 -O2"
export GOGCCFLAGS="-fPIC -m64 -pthread -fmessage-length=0 -Ofast -O3 -O2 -gno-record-gcc-switches"
# export GPG_KEY=0x3B324F4FF73BECF8
# export GPG_KEYGRIP="$(gpg --quiet --with-keygrip -K  | grep -E '\sKeygrip = ([a-zA-Z][0-9].*)$' | cut -d'=' -f2 | sed 's/^ //')"
export GPG_TTY=$(tty)
# gpg-connect-agent updatestartuptty /bye >/dev/null
export GDK_SYNCHRONIZE=0
export GDK_USE_XFT=1
# export GTK_IM_MODULE_FILE=/etc/gtk-2.0/gtk.immodules
# export GTK_IM_MODULE_FILE=/usr/lib/gtk-3.0/3.0.0/immodules.cache
# export GTK_IM_MODULE=ibus
export GTK_MODULES="appmenu-gtk-module:gail:atk-bridge"
export GTK_VERSION=$(pkg-config --modversion gtk+-3.0 | tr . _ | cut -d '_' -f 1-2)
export GTK2_RC_FILES="$HOME/.gtkrc-2.0"
export GTK_USE_PORTAL=1
export GZIP="-1"
export INTEL_NO_HW=1
export INSTALL_MOD_STRIP=1
export JAVA_HOME="/usr/lib/jvm/java-11-openjdk-amd64"
export JAVA_HOME="/opt/jdk1.8.0_241"
export JAVA_OPTS="-XX:+IgnoreUnrecognizedVMOptions -Djava.net.preferIPv4Stack=true -Djava.net.useSystemProxies=true -DsocksProxyHost=127.0.0.1 -DsocksProxyPort=9050"
export JAVA_OPTIONS="${JAVA_OPTS}"
export KEYBASE_AUTOSTART=1
export KEYBASE_NO_GUI=0
export KEYBASE_NO_KBFS=1
export KEYBASE_SYSTEMD=1
export KEYBASE_START_UI=1
export LESSOPEN="|/usr/local/bin/lesspipe %s"
export LESS_ADVANCED_PREPROCESSOR=1
export LIBGL_DEBUG=verbose
export VAAPI_MPEG4_ENABLED=true
export LIBGL_ALWAYS_INDIRECT=1
export LIBGL_DRI3_DISABLE=false
export LIBGL_ALWAYS_SOFTWARE=false
export LIBGL_DRIVERS_PATH="/usr/lib/x86_64-linux-gnu/dri"
export MESA_LOG_FILE=/var/log/mesa.log
export MOZ_ENABLE_WAYLAND=1
export NCURSES_NO_UTF8_ACS=1
export LPASS_HOME="$HOME/.lpass"
export LPASS_AGENT_TIMEOUT=0
export LPASS_AGENT_DISABLE=1
export LPASS_ASKPASS="/usr/bin/zenity --password --title=Password --timeout 30"
export LPASS_CLIPBOARD_COMMAND=/usr/bin/xclip
export LPDEST="/dev/null"
export LD_LIBRARY_PATH="/opt/qt/5.12.5/gcc_64/lib:/opt/wine64/lib64"
# export MAKEFLAGS="-j$((NB_CORES)) -l${NB_CORES}"
export MALLOC_CHECK_=0
export MESON_TESTTHREADS=16
export NO_PROXY="localhost,127.0.0.0/8,::1"
# export NODE_EXTRA_CA_CERTS="/etc/ssl/cacert.pem"
export NONINTERACTIVE_TESTING=1
export NB_CORES=$(grep -c '^processor' /proc/cpuinfo)
export NO_AT_BRIDGE=1
# export NPM_CONFIG_PREFIX=/usr/local
export NVM_DIR="$HOME/.nvm"
export OOO_FORCE_DESKTOP="gnome"
export OS=linux
export PACKER_LOG=1
export PAGER=less
export PARALLELMFLAGS="-j8"
export PERLBREW_CPAN_MIRROR="https://mirrors.sonic.net/cpan/"
export PERLBREW_HOME=/home/$USER/.perlbrew
export PERLBREW_ROOT=/usr/share/perl/perlbrew
export PERLBREW_PERL=perl-5.31.9
export PERL_CANARY_STABILITY_NOPROMPT=1
export PERL_CPANM_OPT="--verbose --notest --no-interactive --sudo --cascade-search --save-dists=/usr/share/perl/cpanm/cache --mirror=/usr/share/perl/cpanm/cache --mirror=https://mirrors.sonic.net/cpan"
# export CPAN_OPTS="-T -X"
export PERL_DEBUG_MSTATS=0
export PERL_MM_NONINTERACTIVE=1
export PERL_MM_USE_DEFAULT=1
export PERL_DL_NONLAZY=0
export PERL5LIB="/home/$USER/perl5/lib/perl5${PERL5LIB:+:${PERL5LIB}}"; export PERL5LIB;
export PERL_LOCAL_LIB_ROOT="/home/$USER/perl5${PERL_LOCAL_LIB_ROOT:+:${PERL_LOCAL_LIB_ROOT}}"
# export PERL_MB_OPT="--install_base \"/home/$USER/perl5\""; export PERL_MB_OPT;
# export PERL_MM_OPT="INSTALL_BASE=/home/$USER/perl5"; export PERL_MM_OPT;
export PERLLIB="/usr/share/perl/5.24.1:/usr/share/perl/5.28.1:/usr/share/perl/5.29.8:/opt/perl5/perls/perl-5.31.4/lib:/root/perl5/perlbrew/perls/perl-5.31.4/lib"
export PERL5LIB="${PERLLIB}"
export PLATFORM=$(uname -s | sed -e 's/  */-/g;y/ABCDEFGHIJKLMNOPQRSTUVWXYZ/abcdefghijklmnopqrstuvwxyz/')
# export PKG_CONFIG_PATH="/usr/lib/x86_64-linux-gnu/pkgconfig"
export PKG_CONFIG_PATH="/opt/qt/5.12.5/gcc_64/lib/pkgconfig"
# export POSIXLY_CORRECT=1
# export PROMPT_COMMAND='echo -ne "$(smiley); PS1=$(\d \T\n[\u@\H\t\d\t\w\$)"'
# function custom_prompt() {
#   __git_ps1 "\[\033[0;31m\]\u \[\033[0;36m\]\h:\w\[\033[00m\]" " \n\[\033[0;31m\]>\[\033[00m\] " " %s"
#   VTE_PWD_THING="$(__vte_osc7)"
#   PS1="$PS1$VTE_PWD_THING"
# }
export PROJECT_HOME="$HOME/dev"
# export PULSE_COOKIE="/tmp/pulse-cookie"
export PULSE_SERVER="unix:/tmp/pulse-socket"
export PULSE_LATENCY_MSEC=250
export PYTHON="/usr/bin/python3.7"
export PYTHONDONTWRITEBYTECODE=1
export PYTHONHTTPSVERIFY=0
export PY_COLORS=1
export QUOTING_STYLE=literal
export QT_ACCESSIBILITY=0
export QT_X11_NO_MITSHM=1
export QT_PLUGIN_PATH=/opt/qt/5.12.5/gcc_64/plugins/platforms
# export QT_IM_MODULE=ibus
export RELEASE_TESTING=0
export RUST_BACKTRACE=1
export S_COLORS=auto
export SDL_AUDIODRIVER='alsa'
export SDL_VIDEODRIVER='x11'
export SHELL="/bin/bash"
export SSH_ASKPASS="/usr/bin/ssh-askpass"
# export SOCKS5_PASSWORD=""
# export SOCKS5_SERVER="192.168.192.1:9050"
# export SOCKS5_USER="$USER"
export SOCKS_VERSION=5
export SYSTEMD_LESS=FRXMK
export SYSTEMD_LOG_LEVEL=info
# export SSH_AUTH_SOCK="/home/$USER/.gnupg/S.gpg-agent.ssh"
# export SSH_AUTH_SOCK='/run/user/$(id -u)/gnupg/S.gpg-agent.ssh'
export TAR_OPTS="--auto-compress --one-file-system --quoting-style='literal' --utc --verbose --deference --compress --totals=SIGQUIT --ignore-failed-read --seek --wildcards --no-acls --no-selinux --no-xattrs --verify --format=gnu --blocking-factor=20"
export TERM=xterm-256color
export TEXARCH=x86_64-linux
export TMPDIR="/var/tmp"
export TEMP="/var/tmp"
export TOR_CONTROL_HOST=192.168.192.1
# export TOR_CONTROL_PASSWD='""'
export TOR_CONTROL_PORT=9051
export TOR_CONTROL_COOKIE_AUTH_FILE=/var/run/tor/control.authcookie
export TOR_NO_DISPLAY_NETWORK_SETTINGS=0
export TOR_SKIP_CONTROLPORTTEST=0
export TOR_SKIP_LAUNCH=1
export TOR_SOCKS_HOST=192.168.192.1
export TOR_SOCKS_PORT=9050
# export TOR_TRANSPROXY=1
export TZ="America/Los_Angeles"
export USER="$(id -un)"
export CHECKPOINT_DISABLE=1
export VAGRANT_EXPERIMENTAL=1
export VAGRANT_CHECKPOINT_DISABLE=1
export VAGRANT_DEFAULT_PROVIDER="virtualbox"
export VAGRANT_DISABLE_VBOXSYMLINKCREATE=1
export VAGRANT_INSTALL_LOCAL_PLUGINS=1
export VAGRANT_LOCAL_PLUGINS_LOAD=1
export VDPAU_DRIVER=va_gl
export VAGRANT_LOG=warn
export VAGRANT_DISABLE_RESOLV_REPLACE=1
export VAGRANT_FORCE_COLOR=1
export LIBVA_DRIVER_NAME=radeonsi_drv_video
# export WINE=/opt/wine64/bin/wine64
export WINEARCH="win64"
export WINEPREFIX="$HOME/.local/share/wineprefixes/wine"
# export WINE="/usr/lib/wine/wine64"
# export WINE="/opt/wine64/bin/wine64"
# export WINESERVER="/usr/lib/wine/wineserver64"
# export WINESERVER="/opt/wine64/bin/wineserver64"
# export WINELOADER="/usr/lib/wine/wine64-preloader"
# export WINELOADER="/opt/wine64/bin/wine64"
export WINEDEBUG="warn+all"
# export WINEDLLPATH="/opt/wine64/lib64:/opt/wine64/lib:/usr/lib/x86_64-linux-gnu/wine"
export WINETRICKS_GUI=none
export WORKON_HOME="/opt/venvs"
export XDG_SESSION_TYPE=x11
export XDG_SESSION_CLASS=user
export XDG_CURRENT_DESKTOP=xfce
export XDG_RUNTIME_DIR="/run/user/$(id -u)"
# export XMODIFIERS=@im=ibus
export XZ_OPTS="-1"; export XZ_OPT="${XZ_OPTS}";
export XZ_DEFAULTS="-T 8"

# builds
export CFLAGS="-g -O3 -Wno-error -m64 -march=native"
export CPPFLAGS="-O3 -Wno-error"
export CXXFLAGS="-g -O3 -Wno-error -m64 -march=native -ftree-vectorize -pipe"
export FCFLAGS="-g -O3"
export FFLAGS="-g -O3"
export GCJFLAGS="-g -O3"
export LDFLAGS="-Wl,-z,relro"
export OBJCFLAGS="-g -O3 -Wno-error"
export OBJCXXFLAGS="-g -O3 -Wno-error"
export CPU_FLAGS_X86="aes avx avx2 f16c fma3 mmx mmxext pclmul popcnt sse sse2 sse3 sse4_1 sse4_2 ssse3"
export DEB_SIGN_KEYID="2C84664F26AAE27BAD5790FDB604C32AD5D7C6D8"
export DH_VERBOSE=1

 # locale
export LANG=en_US.UTF-8
export LANGUAGE=en_US.UTF-8
export LC_CTYPE="en_US.UTF-8"
export LC_NUMERIC="en_US.UTF-8"
export LC_TIME="en_US.UTF-8"
export LC_COLLATE="en_US.UTF-8"
export LC_MONETARY="en_US.UTF-8"
export LC_MESSAGES="en_US.UTF-8"
export LC_PAPER="en_US.UTF-8"
export LC_NAME="en_US.UTF-8"
export LC_ADDRESS="en_US.UTF-8"
export LC_TELEPHONE="en_US.UTF-8"
export LC_MEASUREMENT="en_US.UTF-8"
export LC_IDENTIFICATION="en_US.UTF-8"
export LC_ALL="en_US.UTF-8"

# PATH modifications
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$HOME/.local/bin:$HOME/bin"
export PATH="$PATH:$HOME/go/bin"
export PATH="$PATH:$HOME/.cargo/bin"
export PATH="$HOME/.rustup/toolchains/stable-x86_64-unknown-linux-gnu/bin:$PATH"
export PATH=$PATH:"/opt/imagemagick/bin"
export PATH=$PATH:"/opt/Android/SDK/platform-tools"
# export PATH="/opt/jdk1.8.0_241/bin:$PATH"
export PATH="/opt/qt/5.13.0/gcc_64/bin:$PATH"
export PATH=$PATH:"/opt/Android/platform-tools"
export PATH="/usr/lib/ccache:$PATH"
export PATH="/opt/gradle-4.1/bin:$PATH"
export PATH="$PATH:/snap/bin"
# export PATH="/opt/node-v6.16.0-linux-x64/bin:$PATH"
# export PATH="/opt/node-v10.16.3-linux-x64/bin:$PATH"
# export PATH="/opt/node-v11.13.0-linux-x64/bin:$PATH"
# export PATH="/opt/node-v8.16.0-linux-x64/bin:$PATH"
# export PATH="/opt/wine64/bin:$PATH"
export PATH="/usr/lib/wine:$PATH"
export PATH="/usr/local/texlive/2018/bin/x86_64-linux:$PATH"
# export PATH="$PATH:$HOME/.rvm/bin"
# export PATH="/home/$USER/.gem/ruby/2.6.3/bin:$PATH"
export PATH="/usr/lib/rstudio/bin:$PATH"
if [ -d ~/.bash-git-prompt ]; then source ~/.bash-git-prompt/gitprompt.sh; fi
if [ -f /etc/profile.d/bash_completion.sh ]; then source /etc/profile.d/bash_completion.sh; fi
if [ -d ~/.homesick ]; then source ~/.homesick/repos/homeshick/homeshick.sh; fi
if [ -d /opt/perl5 ]; then source /opt/perl5/etc/bashrc; fi
if [ -f /usr/local/bin/virtualenvwrapper.sh ]; then source /usr/local/bin/virtualenvwrapper.sh; fi
if [ -f /etc/profile.d/nodejs.sh ]; then source /etc/profile.d/nodejs.sh; fi
# if [ -f $USER/.rvm/scripts/rvm ]; then source $USER/.rvm/scripts/rvm; fi
[[ -s "$HOME/.rvm/scripts/rvm" ]] && source "$HOME/.rvm/scripts/rvm"
[ -s "$NVM_DIR/nvm.sh" ] && \. "$NVM_DIR/nvm.sh"
[ -s "$NVM_DIR/bash_completion" ] && \. "$NVM_DIR/bash_completion"

if $(python3 -c "import sys, pkgutil; sys.exit(0 if pkgutil.find_loader('ntfy') else 1)") && [[ $MYUID -ne 0 ]]; then
    eval "$(ntfy shell-integration)"
fi

if [ -f '/opt/google-cloud-sdk/path.bash.inc' ]; then . '/opt/google-cloud-sdk/path.bash.inc'; fi
if [ -f '/opt/google-cloud-sdk/completion.bash.inc' ]; then . '/opt/google-cloud-sdk/completion.bash.inc'; fi

# [[ -f ~/.bash-preexec.sh ]] && source ~/.bash-preexec.sh
export __bp_enable_subshells="true"

# function precmd_git_dirty() {
# if [ -d "$PWD/.git" ]; then
#     git diff-index --quiet HEAD -- &>/dev/null
#     local GITSTATUS=$?
#     if [ "$GITSTATUS" -eq 1 ]; then
#         failure "The current working directory is a Git repository with unstaged changes."
#     fi
# fi
# }

# preexec_functions+=(precmd_git_dirty)
# precmd_functions+=(precmd_git_dirty)

# perlbrew switch-off

 # exit status emoji
 # export PROMPT_COMMAND='echo -ne "$(smiley) \033]0;${USER}@${HOSTNAME}: ${PWD}\007"'
 # export PROMPT_COMMAND='echo -ne "$(smiley)$(__vte_osc7) \033]0 ${USER}@${HOSTNAME}: ${PWD}\007"'

# sessionbus start dirmngr gpg-agent ssh-agent