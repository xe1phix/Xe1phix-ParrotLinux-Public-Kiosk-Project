#!/bin/sh
##-======================================-##
##   [+] Xe1phix-[Nikto]-Cheatsheet.sh
##-======================================-##


nikto -h $IP -p 1234 $IP
nikto -C all -h 192.168.1.1 -p 80
nikto -C all -h 192.168.1.1 -p 443


nikto -h $IP -p $PORT



## ---------------------------------------------------- ##
##   [+] Proxy Enumeration (useful for open proxies)
## ---------------------------------------------------- ##
nikto -useproxy http://$IP:3128 -h $IP



nikto -Option USERAGENT=Mozilla -url=http://10.11.1.24  -o nikto.txt

nikto -port 80,443 -host $ip -o -v nikto.txt

nikto -host $IP -C all -p 80 -output $File.txt | grep -v Cookie


nikto -h $Domain -port 443 -Format htm --output $Domain.htm


