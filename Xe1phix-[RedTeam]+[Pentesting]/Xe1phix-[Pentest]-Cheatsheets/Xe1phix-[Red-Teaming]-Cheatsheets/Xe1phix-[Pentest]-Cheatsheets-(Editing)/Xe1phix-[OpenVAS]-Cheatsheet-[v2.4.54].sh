#!/bin/sh
##-=======================================-##
##   [+] Xe1phix-[OpenVAS]-Cheatsheet.sh
##-=======================================-##



##-======================================-##
##   [+] OpenVAS Vulnerability Scanner
##-======================================-##

##-==============================-##
##   [+] OpenVAS Initial Setup
##-==============================-##


##-==============================-##
##   [+] run the initial setup
##-==============================-##
openvas-setup


##-==================-##
##   [+] add user
##-==================-##
openvas-adduser


##-=====================================================-##
##   [+] launch Greenbone Security Desktop and log in
##-=====================================================-##
gsd


##-=================-##
##   [+] OpenVAS
##-=================-##
openvas-setup
https://localhost:9392




openvas-check-setup
openvas-stop
openvas-start
openvasmd --user=$User --new-password=$Pass
openvasmd --create-user $User



