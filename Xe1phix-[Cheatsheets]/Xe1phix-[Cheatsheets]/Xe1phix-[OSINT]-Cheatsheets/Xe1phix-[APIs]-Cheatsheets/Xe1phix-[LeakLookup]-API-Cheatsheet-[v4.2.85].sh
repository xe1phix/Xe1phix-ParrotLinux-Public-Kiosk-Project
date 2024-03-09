#!/bin/sh

##-=======================================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-=======================================================================-##
## 	     [+] LeakLookup API - OSINT - Password Leak Database API
##-=======================================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-=======================================================================-##


##-============================================-##
##   [+] LeakLookup API - Register Account:
##-============================================-##
https://leak-lookup.com/account/register


##-==================================-##
##   [+] LeakLookup API - Search:
##-==================================-##
https://leak-lookup.com/api/search


##-================================================-##
##   [+] LeakLookup API - Email Address Lookup:
##-================================================-##
curl 'https://leak-lookup.com/api/search' -d 'key=$APIKey&type=email_address&query=david.smith@gmail.com'


##-===========================================-##
##   [+] LeakLookup API - Username Lookup:
##-===========================================-##
curl 'https://leak-lookup.com/api/search' -d 'key=$APIKey&type=username&query=david.smith'


##-=========================================-##
##   [+] LeakLookup API - Domain Search:
##-=========================================-##
curl 'https://leak-lookup.com/api/search' -d 'key=$APIKey&type=domain&query=example.com'


##-=============================================-##
##   [+] LeakLookup API - IPv4 Address Search:
##-=============================================-##
curl 'https://leak-lookup.com/api/search' -d 'key=$APIKey&type=ipaddress&query=112.109.11.112'


##-========================================-##
##   [+] LeakLookup API - Stats Lookup:
##-========================================-##
curl 'https://leak-lookup.com/api/stats' -d 'key=$APIKey'


##-===========================================-##
##   [+] LeakLookup API - Hash Lookup API:
##-===========================================-##
curl 'https://leak-lookup.com/api/hash' -d 'key=$APIKey&query=5f4dcc3b5aa765d61d8327deb882cf99'


##-=======================================-##
##   [+] LeakLookup API - Hash Lookup:
##-=======================================-##
curl 'https://leak-lookup.com/api/hash' -d 'key=$APIKey&query=5f4dcc3b5aa765d61d8327deb882cf99'


##-========================================-##
##   [+] LeakLookup API - Domain Stats:
##-========================================-##
curl 'https://leak-lookup.com/api/stats' -d 'key=$APIKey'

