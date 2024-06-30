#!/bin/sh

alias pw="gpg --decrypt ~/.pw.gpg"


resolution=$(xrandr | grep -A1 $output | tail -n1 | awk '{ print $1 }')


horiz_res=$(echo $resolution | sed 's/\([0-9]\+\)x.*/\1/g')
vert_res=$(echo $resolution | sed 's/[0-9]\+x\([0-9]\+\)/\1/g')
output="$(xrandr | grep -v disconnected | grep connected | cut -d' ' -f1)"



alias xorg='sudo geany /etc/X11/xorg.conf'
alias ls='ls -hF --color=auto --group-directories-first '
alias df='df -h -T'
alias grep='grep -n --color=auto'
alias duf='du -skh * | sort -n'

# quick nmap scan over socks
alias pscan='proxychains nmap -sTV -PN -n -p21,22,25,80,3306,6667 '

# Colors
blue="\033[1;34m"
green="\033[1;32m"
red="\033[1;31m"
bold="\033[1;37m"
reset="\033[0m"

PORT80=`netstat -nta | grep ESTABLISHED | awk '{ print $5}' | grep -c :80`
PORT443=`netstat -nta | grep ESTABLISHED | awk '{ print $5}' | grep -c :443`
echo 'Current Connection Statistics'
echo "Port 80: $PORT80"
echo "Port 443 SSL: $PORT443"

cname=$( awk -F: '/model name/ {name=$2} END {print name}' /proc/cpuinfo )
cores=$( awk -F: '/model name/ {core++} END {print core}' /proc/cpuinfo )
freq=$( awk -F: ' /cpu MHz/ {freq=$2} END {print freq}' /proc/cpuinfo )
tram=$( free -m | awk 'NR==2 {print $2}' )
swap=$( free -m | awk 'NR==4 {print $2}' )
up=$(uptime|awk '{ $1=$2=$(NF-6)=$(NF-5)=$(NF-4)=$(NF-3)=$(NF-2)=$(NF-1)=$NF=""; print }')

# show output
echo "CPU model : $cname"
echo "Number of cores : $cores"
echo "CPU frequency : $freq MHz"
echo "Total amount of ram : $tram MB"
echo "Total amount of swap : $swap MB"
echo "System uptime : $up"


# run disk IO test
io=$( ( dd if=/dev/zero of=test_$$ bs=64k count=6k conv=fdatasync && rm -f test_$$ ) 2>&1 | awk -F, '{io=$NF} END { print io}' )
echo "I/O speed : $io"
























