#!/usr/bin/bash

mkdir $1
cd $1
echo $1 > wildcards

echo "[+] Starting Subdomain gathering..."
subfinder -d $1 -o subfinder.out
cat wildcards | assetfinder --subs-only > assetfinder.out
findomain -f wildcards --unique-output findomain.out
cat subfinder.out assetfinder.out findomain.out | anew > allsubs.out

echo "[+] Starting live domains gathering..."
cat allsubs.out | httprobe -c 80 --prefer-https > LiveSubs.out
echo "[+] Starting aquatone..."
cat LiveSubs.out | aquatone -out aquatone
echo "[+] Finished."
