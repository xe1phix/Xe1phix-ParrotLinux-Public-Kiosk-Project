#!/bin/sh
##-============================================-##
##   [+] Xe1phix-[Unicornscan]-Cheatsheet.sh
##-============================================-##


browse to
http://127.0.0.1/unicornscan

­epgsqldb


unicornscan -v $IP                 ## runs the default TCP SYN scan
unicornscan -v -m U $IP            ## scan type is supposed to be UDP
unicornscan X.X.X.X:a -r10000 -v
unicornscan 192.168.0.0/24:139				## network wide scan on port 139:

unicornscan -mT -I 10.11.1.252:a -v 
unicornscan -mU -I 10.11.1.252:p -v 

unicornscan -mU -I 192.168.24.53:a -v -l unicorn_full_udp.txt ;  unicornscan -mT -I 192.168.24.53:a -v -l unicorn_full_tcp.txt


