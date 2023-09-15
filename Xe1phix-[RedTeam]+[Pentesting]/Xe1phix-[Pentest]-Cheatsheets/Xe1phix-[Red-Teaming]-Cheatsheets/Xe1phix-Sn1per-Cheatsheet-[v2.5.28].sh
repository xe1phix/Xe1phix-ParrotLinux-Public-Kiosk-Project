#!/bin/sh


##-===================-##
##    [*] NORMAL MODE
##-===================-##
sniper -t $Target

##-===================================-##
##    [*] NORMAL MODE + OSINT + RECON
##-===================================-##
sniper -t $Target -o -re

##-===================================-##
##    [*] STEALTH MODE + OSINT + RECON
##-===================================-##
sniper -t $Target -m stealth -o -re

##-=====================-##
##    [*] DISCOVER MODE
##-=====================-##
sniper -t $CIDR -m discover -w $Workspace

##-==============================-##
##    [*] SCAN ONLY SPECIFIC PORT
##-==============================-##
sniper -t $Target -m port -p $Ports

##-==============================-##
##    [*] FULLPORTONLY SCAN MODE
##-==============================-##
sniper -t $Target -fp

##-===================================-##
##    [*] WEB MODE - PORT 80 + 443 ONLY!
##-===================================-##
sniper -t $Target -m web

##-===========================-##
##    [*] HTTP WEB PORT MODE
##-===========================-##
sniper -t $Target -m webporthttp -p $Port

##-===========================-##
##    [*] HTTPS WEB PORT MODE
##-===========================-##
sniper -t $Target -m webporthttps -p $Port

##-===========================-##
##    [*] HTTP WEBSCAN MODE
##-===========================-##
sniper -t $Target -m webscan

##-===========================-##
##    [*] ENABLE BRUTEFORCE
##-===========================-##
sniper -t $Target -b

##-=====================-##
##    [*] AIRSTRIKE MODE
##-=====================-##
sniper -f $File.txt -m airstrike

##-==================================-##
##    [*] NUKE MODE WITH TARGET LIST
##-==================================-##
## ------------------------------------------------------------- ##
##    [+] BRUTEFORCE ENABLED
##    [+] FULLPORTSCAN ENABLED
##    [+] OSINT ENABLED
##    [+] RECON ENABLED
##    [+] WORKSPACE & LOOT ENABLED
## ------------------------------------------------------------- ##
sniper -f $File.txt -m nuke -w $Workspace

##-===========================-##
##    [*] MASS PORT SCAN MODE
##-===========================-##
sniper -f $File.txt -m massportscan

##-===========================-##
##    [*] MASS WEB SCAN MODE
##-===========================-##
sniper -f $File.txt -m massweb

##-================================-##
##    [*] MASS WEBSCAN SCAN MODE
##-===========================-##
sniper -f $File.txt -m masswebscan

##-===========================-##
##    [*] MASS VULN SCAN MODE
##-===========================-##
sniper -f $File.txt -m massvulnscan


OPENVAS_HOST="127.0.0.1"
OPENVAS_PORT="9390"

sniper -t 127.0.0.1 -m vulnscan
sniper -f /$Dir/$File.txt -m massvulnscan


sniper -t $TARGET -m $MODE --noreport $args
sniper -m stealth --noreport --noloot -t $TARGET


##-======================-##
##    [*] PORT SCAN MODE
##-======================-##
sniper -t $Target -m port -p <PORT_NUM>

##-=======================-##
##    [*] LIST WORKSPACES
##-=======================-##
sniper --list

##-=========================-##
##    [*] DELETE WORKSPACE
##-=========================-##
sniper -w $Workspace -d

##-===================================-##
##    [*] DELETE HOST FROM WORKSPACE
##-===================================-##
sniper -w $Workspace -t $Target -dh

##-=============================-##
##    [*] GET SNIPER SCAN STATUS
##-=============================-##
sniper --status

##-==============================-##
##    [*] LOOT REIMPORT FUNCTION
##-==============================-##
sniper -w $Workspace --reimport

##-=================================-##
##    [*] LOOT REIMPORTALL FUNCTION
##-=================================-##
sniper -w $Workspace --reimportall

##-===============================-##
##    [*] LOOT REIMPORT FUNCTION
##-===============================-##
sniper -w $Workspace --reload

##-=============================-##
##    [*] LOOT EXPORT FUNCTION
##-=============================-##
sniper -w $Workspace --export

##-========================-##
##    [*] SCHEDULED SCANS
##-========================-##
sniper -w $Workspace -s daily|weekly|monthly

##-===========================-##
##    [*] USE A CUSTOM CONFIG
##-===========================-##
sniper -c /$Dir/sniper.conf -t $Target -w $Workspace

##-====================-##
##    [*] UPDATE SNIPER
##-====================-##
sniper --update
