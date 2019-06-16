#!/bin/sh
##-=================================-##
##   [+] Xe1phix-AddDebianRepos.sh
##-=================================-##
echo -e "deb http://deb.debian.org/debian/ stretch main contrib non-free\n## deb-src http://deb.debian.org/debian stretch main contrib non-free\n\ndeb http://deb.debian.org/debian-security/ stretch/updates main contrib non-free \n## deb-src http://deb.debian.org/debian-security/ stretch/updates main contrib non-free\n\ndeb http://deb.debian.org/debian/ stretch-updates main contrib non-free \n## deb-src http://deb.debian.org/debian stretch-updates main contrib non-free" >> /etc/apt/sources.list.d/Debian.list
