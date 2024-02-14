#!/bin/bash
# need to add bing api key in recon-ng key table . register on bing and get the key
# 
# use command "keys add bing_api <key value>" to add the key
#
# Subdomain enumeration script that creates/uses a dynamic resource script for recon-ng.
# Enumall.sh uses baidu scraping, bing scraping, baidu scraping, netcraft, and bruteforces for DNS subdomains.
# That file needs to be dropped in /usr/share/recon-ng/data/
# written by suraj pratap
# set the domain name in domain parameter to test
domain=""

stamp=$(date +"%m_%d_%Y")

#create rc file with workspace.timestamp and start enumerating hosts
touch $domain$stamp.resource
echo ""
echo $domain
echo ""
echo "workspaces select $domain$stamp" >> $domain$stamp.resource
echo ""
echo "set TIMEOUT 100" >> $domain$stamp.resource
echo "use recon/domains-hosts/baidu_site" >> $domain$stamp.resource
echo "set SOURCE $domain" >> $domain$stamp.resource
echo "run" >> $domain$stamp.resource
echo ""
echo "use recon/domains-hosts/bing_domain_web" >> $domain$stamp.resource
echo "set SOURCE $domain" >> $domain$stamp.resource
echo "run" >> $domain$stamp.resource
echo ""
echo "use recon/domains-hosts/google_site_web" >> $domain$stamp.resource
echo "set SOURCE $domain" >> $domain$stamp.resource
echo "run" >> $domain$stamp.resource
echo ""
echo "use recon/domains-hosts/netcraft" >> $domain$stamp.resource
echo "set SOURCE $domain" >> $domain$stamp.resource
echo "run" >> $domain$stamp.resource
echo ""
echo "use recon/domains-hosts/yahoo_domain" >> $domain$stamp.resource
echo "set SOURCE $domain" >> $domain$stamp.resource
echo "run" >> $domain$stamp.resource
echo ""
echo "use recon/domains-hosts/vpnhunter" >> $domain$stamp.resource
echo "set SOURCE $domain" >> $domain$stamp.resource
echo "run" >> $domain$stamp.resource
echo ""
echo "use recon/domains-hosts/brute_hosts" >> $domain$stamp.resource
echo "set WORDLIST /usr/share/recon-ng/data/sorted_knock_dnsrecon_fierce_recon-ng.txt" >> $domain$stamp.resource
echo "set SOURCE $domain" >> $domain$stamp.resource
echo "run" >> $domain$stamp.resource
echo ""
echo "use recon/netblocks-companies/whois_orgs" >> $domain$stamp.resource
echo "set SOURCE $domain" >> $domain$stamp.resource
echo "run" >> $domain$stamp.resource
echo ""
echo "use recon/hosts-hosts/resolve" >> $domain$stamp.resource
echo "set SOURCE default" >> $domain$stamp.resource
echo "run" >> $domain$stamp.resource
echo ""
echo "use reporting/csv" >> $domain$stamp.resource
echo "set FILENAME /root/Desktop/$domain$stamp.csv" >> $domain$stamp.resource
echo "run" >> $domain$stamp.resource
echo ""
echo "use reporting/list" >> $domain$stamp.resource
echo "set FILENAME /root/Desktop/$domain$stamp.lst" >> $domain$stamp.resource
echo "set COLUMN host" >> $domain$stamp.resource
echo "run" >> $domain$stamp.resource
echo ""
echo "exit" >> $domain$stamp.resource
sleep 1
echo ""

path=$(pwd)
cd /usr/share/recon-ng
./recon-ng --no-check -r $path/$domain$stamp.resource
