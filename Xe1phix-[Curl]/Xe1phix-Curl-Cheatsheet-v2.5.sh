#!/bin/sh

##-=========================-##
##  [+] Grab HTTP Headers
##-=========================-##
curl -LIN $Domain



##-=====================-##
##  [+] Redirections: 
##-=====================-##
## ----------------------------------------------------------- ##
##  [?] Examine the response of a 301 message or Javascript.
## ----------------------------------------------------------- ##
curl -vvvv $Domain



##-======================================-##
##  [+] Curl SOCKS5 Proxy Connection:
##-======================================-##
curl -s -m 10 --socks5 $hostport --socks5-hostname $hostport -L $URL



##-===================================================================-##
##  [+] Curl SOCKS5 Proxy Connection - Using Win Firefox UserAgent:
##-===================================================================-##
curl --proxy "socks5h://localhost:9050" --tlsv1.2 --compressed --user-agent "Mozilla/5.0 (Windows NT 6.1; rv:45.0) Gecko/20100101 Firefox/45.0" -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' -H 'DNT: 1' $URL



##-==========================================-##
##  [+] Curl - Windows Firefox UserAgent:
##-==========================================-##
wget -U "Mozilla/5.0 (Windows NT 6.1; rv:45.0) Gecko/20100101 Firefox/45.0" $URL



## --------------------------------------------------------- ##
##   [?] if you ever forget the dns4tor*.onion address, 
##       --> you can simply use cURL:
## --------------------------------------------------------- ##
curl -sI https://tor.cloudflare-dns.com | grep alt-svc




##-=======================================================-##
##  [+] Print the Response Headers and Body (together)
##-=======================================================-##
curl -i $Domain



##-=========================================-##
##  [+] Print Only the Response Headers
##-=========================================-##
curl -s -o /dev/null -D - $Domain



##-========================================-##
##  [+] Detailed Trace with Timestamps
##-========================================-##
curl --trace - --trace-time $Domain



##-======================================-##
##  [+] Print Only the Response Code
##-======================================-##
curl -w '%{response_code}' -s -o /dev/null $Domain



##-==========================================-##
##  [+] Print Only the Response Headers
##-==========================================-##
curl -s -o /dev/null -D - $Domain



##-==========================================-##
##  [+] Change the User Agent to Firefox
##-==========================================-##
curl -A 'Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:60.0) Gecko/20100101 Firefox/60.0' $Domain



##-==========================================-##
##  [+] Change the User Agent to Chrome
##-==========================================-##
curl -A 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/76.0.3809.100 Safari/537.36' $Domain



##-====================================-##
##  [+] Pretend to be a Google Bot
##-====================================-##
curl -A 'Googlebot/2.1 (+http://www.google.com/bot.html)' $Domain



##-===============================-##
##  [+] Remove the User Agent
##-===============================-##
curl -A '' $Domain


##-==================================-##
##  [+] Send an Empty User Agent
##-==================================-##
curl -A '' -H 'User-Agent;' $Domain



##-===============================-##
##  [+] Save Cookies to a File
##-===============================-##
curl -c cookies.txt $Domain



##-=================================-##
##  [+] Load Cookies from a File
##-=================================-##
curl -b cookies.txt $Domain



##-==========================================-##
##  [+] Send a Referer via the -H argument
##-==========================================-##
curl -H 'Referer: https://digg.com' $Domain



##-=======================-##
##  [+] Add a Referrer
##-=======================-##
curl -e 'https://google.com?q=cats' $Domain



##-================================================-##
##      [+] Bulk Download Files By Their URLs 
##-================================================-##
## ------------------------------------------------ ##
##  [?] The URL Links Are Fed To Curl From xarg
## ------------------------------------------------ ##
xargs -n 1 curl -O < $URLFile



##-=================================-##
##  [+] Basic HTTP Auth:
##-=================================-## 
curl -u $Username:$Password $URL



##-=================================-##
##  [+] Basic HTTP Auth w/Data:
##-=================================-## 
curl $URL -u $Username:$Password -d $Data



##-=================================-##
##  [+] Download from FTP server:
##-=================================-## 
curl -u $FTPUser:$FTPPass -O ftp://$Host/$Path/$File



##-=================================-##
##  [+] Download by proxy server:
##-=================================-## 
curl -x $ProxyURL:$Port $URL



##-=======================-##
##  [+] Ignore SSL Cert:
##-=======================-##  
curl -k $URL



##-============================-##
##  [+] Advanced Operations
##-============================-##


##-=================-## 
##  [+] JSON POST:
##-=================-## 
curl -X POST -H "Content-Type: application/json" -H "Authorization: $type $key" -d '{"key1":"value1","key2":"value2","key3":literal3,"list4":$"listval1","listval2","listval3"}' $URL



##-============================================================-##
##   [+] Use ranges to download or list according to a range:
##-============================================================-##
## ------------------------------------------------------------------------ ##
##  [?] the [a-z] is literal and will look for files named a to z.
## ------------------------------------------------------------------------ ##
curl ftp://$URL/$Path/[a-z]/




##-================================================-##
##  [+] Copy Files Locally:
##-================================================-## 
curl -o $Destination FILE://$Source

curl -o targetfile.txt FILE://mnt/somewhere/targetfile.txt


##-================================================-##
##  [+] List FTP server contents:
##-================================================-## 
curl -u $FTPUser:$FTPPass -O ftp://$host/$Path/


##-================================================-##
##  [+] Upload a file to an FTP server:
##-================================================-## 
curl -u $FTPUser:$FTPPass -T $Filename ftp://$URL


##-================================================-##
##  [+] Upload multiple files to an FTP server:
##-================================================-## 
curl -u $FTPUser:$FTPPass -T "{$File1,$File2}" ftp://$URL


##-================================================-##
##  [+] Upload a file from STDIN to an FTP server:
##-================================================-## 
curl -u $FTPUser:$FTPPass -T - ftp://$URL/$Path/$Filename