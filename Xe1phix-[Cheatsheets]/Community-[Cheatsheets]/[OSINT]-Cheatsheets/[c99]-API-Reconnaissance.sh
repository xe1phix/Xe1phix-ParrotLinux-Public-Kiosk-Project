#!/bin/bash


C99_API="Your C99 API KEY"



if [[ $1 == "1" ]]
then 
curl -sS "https://api.c99.nl/subdomainfinder?key=$C99_API&domain=$2" | grep -oP  "(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]" 


elif [[ $1 == "2" ]]
then 
curl -sS "https://api.c99.nl/firewalldetector?key=$C99_API&url=$2"

elif [[ $1 == "3" ]] 
then 

for i in $(cat $2) 
do 
echo $i $(curl -sS "https://api.c99.nl/portscanner?key=$C99_API&host=$i") | tee -a all-ports-list-4.out
done 

elif [[ $1 == "4" ]]
then 

for i in $(cat $2) 
do
echo $i $(curl -sS "https://api.c99.nl/portscanner?key=$C99_API&host=$i&port=$3" )
done 

elif [[ $1 == "5" ]]
then

for i in $(cat $2)
do
echo $i $(curl -sS "https://api.c99.nl/nmap?key=$C99_API&host=$i&json")
done 

elif [[ $1 == "6" ]] 
then 
curl -sS "https://api.c99.nl/dnsresolver?key=$C99_API&host=$2"

elif [[ $1 == "7" ]]
then
curl -sS "https://api.c99.nl/ip2domains?key=$C99_API&ip=$2" 

# for i in $(cat ips.out);do curl -sS "https://api.c99.nl/ip2domains?key=$C99_API&ip=$i" ;done | tee -a domains.out

elif [[ $1 == "8" ]]
then 
curl -sS "https://api.c99.nl/whois?key=$C99_API&domain=$2"


elif [[ $1 == "9" ]]
then

curl -sS "https://api.c99.nl/getheaders?key=$C99_API&host=$2"

else 

echo " Choose number from 1 to 10 as first argument" 
echo "

./script.sh [option] [target.com]

1 - Subdomain Finder [ ./run.sh 1 target.com ] output will be saved into subdomains.out
2 - Firewall Technology (WAF) Detector [ ./run.sh 2 target.com ]
3 - Multiple Port Scanner [ ./run.sh 3 hosts.txt 
4 - Single Port Scanner [ ./run.sh 4 hosts.txt PORT_Number ]
5 - Nmap Scanner [ ./run.sh 5 hosts.txt 
6 - Host to IP [ ./run.sh 6 target.com ]
7 - IP 2 Domains [ ./run.sh 7 IP/1.1.1.1 ]
8 - Whois Checker [ ./run.sh 8 target.com ]
9 - Get Website Headers [ ./run.sh 10 target.com ]

Created by @osamahamad to use with some oneliners.
"


fi

