#!/bin/sh

##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##
##    [+] WFuzz - Web Application Bruteforcer + Pentesting
##-===========================================================-##
##-<!>~<!>~<!>~<!>~<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-<!>-##
##-===========================================================-##



## ---------------------------------------- ##
##    [?] wfuzz -z payload,params $URL
## ---------------------------------------- ##
wfuzz -v verbose     ## Verbose 
wfuzz -p $Addr       ## (proxy)
wfuzz -t $Num        ## number of concurrent connections
wfuzz -s $Num        ## delay between requests
wfuzz -R $Depth      ## Recursion level
wfuzz -L             ## follow HTTP redirections
wfuzz -u $URL        ## URL for request
wfuzz -z $Payload    ## Payload for each FUZZ keyword used
wfuzz -w $File       ## specify a wordlist file (alias for -z file,payload)
wfuzz -V alltype     ## All parameters bruteforcing
wfuzz -x $Method     ## HTTP method for request



##-========================================-##
##    [+] Wfuzz - 
##-========================================-##
wfuzz -v -t $Threads -L --hc 404 -w $Wordlist -u $URL -f $File


##-========================================-##
##    [+] Wfuzz - The web brute forcer
##-========================================-##
wfuzz -c -z $File.txt --sc 200 http://$IP


##-===================================-##
##    [+] bruteforce web parameter
##-===================================-##
wfuzz -u http://$IP/path/index.php?param=FUZZ -w /usr/share/wordlists/rockyou.txt


##-======================================-##
##    [+] bruteforce post data (login)
##-======================================-##
wfuzz -u http://$IP/path/index.php?action=authenticate -d 'username=admin&password=FUZZ' -w /usr/share/wordlists/rockyou.txt




wfuzz -c -w /usr/share/wfuzz/wordlist/general/megabeast.txt $IP:60080/?FUZZ=test

wfuzz -c --hw 114 -w /usr/share/wfuzz/wordlist/general/megabeast.txt $IP:60080/?page=FUZZ

wfuzz -c -w /usr/share/wfuzz/wordlist/general/common.txt "$IP:60080/?page=mailer&mail=FUZZ"

wfuzz -c -w /usr/share/seclists/Discovery/Web_Content/common.txt --hc 404 $IP/FUZZ

wfuzz -c -w /usr/share/seclists/Discovery/Web_Content/common.txt -R 3 --sc 200 $IP/FUZZ




##-========================================-##
##   [+] Fuzz DNS using wfuzz - hide 404
##-========================================-##
wfuzz -H 'Host: FUZZ.site.com' -w $File -u $Domain --hh $RemoveString -hc 404


