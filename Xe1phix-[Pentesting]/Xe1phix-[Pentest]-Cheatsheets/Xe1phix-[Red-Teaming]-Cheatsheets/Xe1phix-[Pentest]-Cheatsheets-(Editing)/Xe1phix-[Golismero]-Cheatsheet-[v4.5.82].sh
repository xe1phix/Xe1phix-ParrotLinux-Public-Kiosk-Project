#!/bin/sh
##-==========================================-##
##   [+] Xe1phix-[Golismero]-Cheatsheet.sh
##-==========================================-##



##-======================================================-##
##  [+] scan a website and show the results on screen:
##-======================================================-##
golismero.py scan $Target


##-=========================================================================-##
##  [+] grab Nmap results, scan all hosts found and write an HTML report:
##-=========================================================================-##
golismero.py scan -i $File.xml -o $File.html


##-===================================================================================-##
##  [+] grab results from OpenVAS and show them on screen, but don't scan anything:
##-===================================================================================-##
golismero.py import -i $File.xml



golismero scan 10.0.0.0/24 172.16.0.0/24 $Target


##-============================================================-##
##  [+] show a list of all available configuration profiles:
##-============================================================-##
golismero.py profiles


##-=============================================-##
##  [+] show a list of all available plugins:
##-=============================================-##
golismero.py plugins


##-=============================-##
##  [+] Custom plugins setup:

golismero.py scan -e spider -e plecost -e dns* $Target


##-===========================-##
##  [+] Plugin parameters:
##-===========================-##
golismero.py scan -a openvas:port=9182 -a openvas:user=tor $Target
golismero.py scan -a openvas:profile=“My new profile” $Target


##-===============================-##
##  [+] increasing debug level:
##-===============================-##
golismero.py scan -nd -vv $Target


##-===================================================-##
##  [+] dump the database from a previous scan:
##-===================================================-##
golismero.py dump -db $File.db -o $File.sql



