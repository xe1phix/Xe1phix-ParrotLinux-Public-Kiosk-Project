#!/bin/bash

# Variables
Domain=$1
TARGET=$2
IP=$3
File=$4
LOGNAME="gobuster_log.txt"
wordlist="/usr/share/wordlists/dirbuster/directorylist2.3medium.txt"
threads=100
extensions="php,html,js,txt,jsp,pl"
dirStatusCodes="200,204,301,302,307,403,500"

# Run Gobuster with different wordlists
function run_gobuster() {
gobuster dir -u http://$1/ -w $2 -t $threads -e -s $dirStatusCodes -o $3
}

# Web enumeration with for loop
echo "[+] Starting web enumeration with Gobuster"
for wordlist in /usr/share/seclists/Discovery/Web_Content/*; do
run_gobuster $Domain $wordlist $LOGNAME &
done

# Gobuster directory bruteforce with extension scanning for Linux and Apache
echo "[+] Gobuster - Scanning directories and files for Linux (Apache)"
gobuster dir -u http://10.10.10.10/ -w $wordlist -x $extensions -s $dirStatusCodes &

# Gobuster directory bruteforce for Windows (IIS)
echo "[+] Gobuster - Scanning directories and files for Windows (IIS)"
gobuster dir -u http://10.10.10.10/ -w $wordlist -x php,html,js,asp,aspx,jsp,bak -s $dirStatusCodes &

# Dirsearch directory enumeration
echo "[+] Dirsearch - Enumerating directories"
python3 dirsearch.py -u http://$IP/ -w $wordlist -e php,html,js,txt,jsp,pl -t 50 &

# Nikto scanning
echo "[+] Running Nikto on HTTP and HTTPS"
nikto -h http://$IP/ -p 80 &
nikto -h https://$IP/ -p 443 &

# Gospider crawling
echo "[+] Crawling for JavaScript files using Gospider"
gospider -S "subs/filtered_hosts.txt" -js -t 50 -d 3 --sitemap --robots -w -r > "subs/gospider.txt" &

# WhatWeb - Web technology fingerprinting
echo "[+] Fingerprinting web technologies with WhatWeb"
whatweb -v $Domain > data/domain_info.txt &

# Dirsearch in a loop for multiple hosts
for host in $(cat alive.txt); do
DIRSEARCH_FILE=$(echo $host | sed 's/[\.|\/|:]/_/g').txt
dirsearch -u $host -e $extensions -r -b -t $threads --plaintext --output reports/dirsearch/$DIRSEARCH_FILE &
done

# HTTProbe to check if servers are alive
echo "[+] Probing for alive servers with HTTProbe"
<a href="alive.txt">cat all.txt / httprobe -c 50 -t 5 >></a>
echo "[+] $(cat alive.txt | wc -l) assets are responding"

# Feroxbuster directory brute force
echo "[+] Running Feroxbuster for directory brute-forcing"
feroxbuster -u http://$IP/ -w /usr/share/seclists/Discovery/WebContent/raft-small-words.txt -o feroxbuster_results.txt -t 50 &

# Wait for background processes to finish
wait
echo "[+] Web enumeration and crawling completed!"
