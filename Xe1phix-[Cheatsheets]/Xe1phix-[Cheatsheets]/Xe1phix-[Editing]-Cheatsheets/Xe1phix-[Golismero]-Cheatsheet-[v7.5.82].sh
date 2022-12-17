#!/bin/sh
##-===========================================================-##
##    [+] Xe1phix-[Golismero]-Cheatsheet-[v..].sh
##-===========================================================-##


##-======================================================-##
##  [+] scan a website and show the results on screen:
##-======================================================-##
golismero.py scan $Target
golismero scan 10.0.0.0/24 172.16.0.0/24 $Target


##-=========================================================================-##
##  [+] grab Nmap results, scan all hosts found and write an HTML report:
##-=========================================================================-##
golismero.py scan -i $File.xml -o $File.html


##-===================================================================================-##
##  [+] grab results from OpenVAS and show them on screen, but don't scan anything:
##-===================================================================================-##
golismero.py import -i $File.xml


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
##-=============================-##
golismero.py scan -e spider -e plecost -e dns* $Target



##-======================================================-##
##  [+] scan a website and show the results on screen:
##-======================================================-##
golismero.py scan $Domain


##-=========================================================================-##
##  [+] grab Nmap results, scan all hosts found and write an HTML report:
##-=========================================================================-##
golismero.py scan -i $NMapOutput.xml -o $File.html



## --------------------------------------- ##
##  [?] Display openvas plugin details:
## --------------------------------------- ##
golismero.py info openvas


##-===================================================================================-##
##  [+] grab results from OpenVAS and show them on screen, but don't scan anything:
##-===================================================================================-##
golismero.py import -i $OpenVASOutput.xml


##-============================================================-##
##  [+] show a list of all available configuration profiles:
##-============================================================-##
golismero.py profiles


##-=============================================-##
##  [+] show a list of all available plugins:
##-=============================================-##
golismero.py plugins


##-===================================================-##
##  [+] show information on all bruteforcer plugins:
##-===================================================-##
golismero.py info brute_*


##-===================================================-##
##  [+] dump the database from a previous scan:
##-===================================================-##
golismero.py dump -db $File.db -o $File.sql


##-===========================-##
##  [+] Plugin parameters:
##-===========================-##
golismero.py scan -a openvas:port=9182 -a openvas:user=tor $Target
golismero.py scan -a openvas:profile=“My new profile” $Target


##-===============================-##
##  [+] increasing debug level:
##-===============================-##
golismero.py scan -nd -vv $Target






--verbose --quiet  --output --full --audit-db
--enable-plugin
--allow-subdomains

scan
dump                          #
load                          #
profiles                                # Show a list of available config profiles

plugins                            # Show a list of available plugins

info                          # Show detailed information on a given plugin.










List available plugins:




Generate html report:"
golismero.py scan WEBSITE -o report.html

Generate multiple reports:"
golismero.py report -o report.html -db info.db

Generate report from database:"
golismero.py report -o r.xml -o r.txt -o r.rst

Import information from other tools:"
golismero.py import -i openvas_results.xml

Import information from other tools:"
golismero.py report -i ov.xml -o res.html


Import information from other tools:"
golismero.py dump -db example.db -o dump.sql

Import information from other tools:"
golismero.py load -i dump.sql


nstallation (from git):"
git clone https://github.com/golismero/golismero golismero
Global commands."
golismero {SCAN|PROFILES|PLUGINS|INFO|REPORT|IMPORT|DUMP|UPDATE}


Quick scan:"
golismero.py scan TARGET
golismero.py scan 10.0.0.0/24 172.16.0.0/24 TARGET
List available profiles:"
golismero.py profiles
Custom plugins setup:"
golismero.py scan -e spider -e plecost -e dns* TARGET
Plugin parameters:"
golismero.py scan -a openvas:port=9182 -a openvas:user=tor TARGET
golismero.py scan -a openvas:profile=“My new profile” TARGET
Audit name and results database:"
golismero.py scan --audit-name my_audit -db my_database.db TARGET
Without database and increasing debug level:"
golismero.py scan -nd -vv TARGET
Setting proxy:"
golismero.py scan -pu USER -pp PASS -pa ADDRESS -pn PORT TARGET
Following redirects (or only one) and set max depth crawling:"
golismero.py scan --follow-redirects --depth 2 TARGET
golismero.py scan --follow-first --depth 4 TARGET
Performance and networks options:"
golismero.py scan --max-concurrent 10 --max-connections 25 TARGET
Set scope and limits:"
golismero.py scan --max-links 95 --allow-subdomains --parent TARGET
golismero.py scan --forbid-subdomains --no-parent TARGET
Session management:"
golismero.py scan --cookie “COOKIE_VAL” --user-agent random TARGET
golismero.py scan --cookie-file FILE_PATH.jar TARGET
echo "Set profile:"
golismero.py scan --profile quick TARGET


