

----
##-===================-##
##     [+] Check Headers
##-===================-##
python3 finalrecon.py --headers $URL


##-========================-##
##     [+] Check SSL Certificate
##-========================-##
python3 finalrecon.py --sslinfo $URL


##-=====================-##
##     [+] Check Whois Info
##-=====================-##
python3 finalrecon.py --whois $URL

##-===================-##
##     [+] Crawl Target
##-===================-##
python3 finalrecon.py --crawl $URL

##-========================-##
##     [+] Directory Searching
##-========================-##
python3 finalrecon.py --dir $URL -e txt,php -w /$Dir/$File

##-==================-##
##     [+] Full Scan
##-==================-##
python3 finalrecon.py --full $URL