#!/bin/sh
##-=====================================-##
##   [+] Xe1phix-[SSL]-Cheatsheet.sh
##-=====================================-##


sslscan --ipv4 --show-certificate --ssl2 --ssl3 --tlsall --no-colour $Domain



echo "Please provide the target ip address and the port."

sslscan --show-certificate --verbose --no-colour --xml=sslscan_$1_$2.xml $1:$2 2>&1 | tee "$1_$2_sslscan.txt"


##-===============-##
##   [+] 
##-===============-##
sslscan $domain:443





sslyze $Domain --resum --certinfo=basic --compression --reneg --sslv2 --sslv3

sslyze -regular $Domain


tlssled $Domain 443

sslyze $domain --resum --certinfo=basic --compression --reneg --sslv2 --sslv3 --hide_rejected_ciphers


httsquash -r $Domain

httprint -h $Domain -s signatures.txt -P0




httprint -h $Domain -s $File.txt -P0

## --------------------------------------------------------------------- ##
##   [+] Double checking for subdomains with amass and certspotter...
## --------------------------------------------------------------------- ##
amass enum -d $URL | tee -a $URL/recon/$File.txt
curl -s https://certspotter.com/api/v0/certs\?domain\=$URL | jq '.[].dns_names[]' | sed 's/\"//g' | sed 's/\*\.//g' | sort -u
certspotter | tee -a $URL/recon/$File.txt




dnsdumpster.com

censys.io/domain?q=
censys.io/certificates?q=


spyse -target $Target --subdomains 



curl -s https://crt.sh/?q=%25.$Target


testssl.sh -e -E -f -p -y -Y -S -P -c -H -U $IP

