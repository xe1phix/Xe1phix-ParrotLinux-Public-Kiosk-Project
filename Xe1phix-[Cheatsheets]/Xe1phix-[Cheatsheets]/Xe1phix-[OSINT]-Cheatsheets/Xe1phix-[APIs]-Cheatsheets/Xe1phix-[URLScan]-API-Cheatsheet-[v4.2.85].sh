#!/bin/sh

##-=======================================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-=======================================================================-##
## 	     [+] URLScan.io API - OSINT - 
##-=======================================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-=======================================================================-##


##-==================================================-##
##   [+] URLScan.io API - 
##-==================================================-##
curl -X POST "https://urlscan.io/api/v1/scan/" -H "Content-Type: application/json" -H "API-Key: $apikey" -d "{ "url\": \"$URL\", \"visibility\": \"public\", \"tags\": [\"demotag1\", \"demotag2\"] }"



##-=======================================================-##
##   [+] URLScan.io API - Read Input from List of URLs:
##-=======================================================-##
echo list|tr -d "\r"|while read url; do
  curl -X POST "https://urlscan.io/api/v1/scan/" \
      -H "Content-Type: application/json" \
      -H "API-Key: $APIKey" \
      -d "{\"url\": \"$URL\", \"visibility\": \"public\"}"
  sleep 2;
done



##-===========================================-##
##   [+] URLScan.io API - Get Screenshots: 
##-===========================================-##
curl https://urlscan.io/screenshots/$uuid.png


##-==============================================-##
##   [+] URLScan.io API - Search By DOM UUID:
##-==============================================-##
curl https://urlscan.io/dom/$uuid


##-============================================-##
##   [+] URLScan.io API - Search By Domain:
##-============================================-##
curl "https://urlscan.io/api/v1/search/?q=$Domain:urlscan.io"


##-===============================================-##
##   [+] URLScan.io API - Search By IP Address:
##-===============================================-##
https://urlscan.io/api/v1/search?q=$IP


##-======================================================-##
##   [+] Curl - URLScan.io API - Search By IP Address:
##-======================================================-##
curl -v --url "https://urlscan.io/api/v1/search?ip=$IP"


##-=================================================-##
##   [+] OSINT - URLScan.io API - Domain Scanner:
##-=================================================-##
curl -s "https://urlscan.io/api/v1/search/?q=$Domain:$1" | jq -r '.results[].page.domain' | sort -u >> tmp.txt

curl --insecure -L -s "https://urlscan.io/api/v1/search/?q=domain:$Domain" 2> /dev/null | egrep "country|server|domain|ip|asn|$Domain|prt"| sort -u | tee $DIR/urlscanio-$Domain.txt


