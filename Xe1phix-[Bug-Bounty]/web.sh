
gobuster u $Domain w /usr/share/wordlists/dirb/big.txt t 100
gobuster u http://$TARGET w /usr/share/wordlists/dirb/big.txt t 100
  
gobuster u http://$IP w /usr/share/seclists/Discovery/Web_Content/Top1000RobotsDisallowed.txt
gobuster u http://$IP w /usr/share/seclists/Discovery/Web_Content/common.txt
  


  
  [?] A for loop so you can go do other stuff
  
for wordlist in $(ls);do gobuster u $Domain w $File t 100;done


  
gobuster w /usr/share/wordlists/dirb/common.txt u http://$IP/
  
gobuster u http://$IP/  w /usr/share/seclists/Discovery/Web_Content/common.txt s '200,204,301,302,307,403,500' e
gobuster u http://$IP/ w /usr/share/seclists/Discovery/Web_Content/cgis.txt s '200,204,403,500' e
  
gobuster dir u http://$IP/ w $File.txt
gobuster dir u https://$IP w /usr/share/wordlists/dirbuster/directorylist1.0.txt t 50 k o gobuster
  
a href"wordlist.txt"recursebuster u $Domain w/a
  
gobuster u http://$IP/ w /usr/share/wordlist/dirb/big.txt s '200,204,301,302,307,403,500' e
  




   [+] Web Scanning with extensions





     [+] Gobuster  Linux

  
    [?]  Example web server: Apache
  
gobuster dir e u http://10.10.10.10/ w /usr/share/wordlists/dirbuster/directorylist2.3medium.txt x php,html,js,txt,jsp,pl s 200,204,301,302,307,403,401



     [+] Gobuster  Windows

  
    [?]  Example web server: IIS
  
gobuster dir e u http://10.10.10.10/ w /usr/share/wordlists/dirbuster/directorylist2.3medium.txt x php,html,js,txt,asp,aspx,jsp,bak s 200,204,301,302,307,403,401



     [+] DirSearch  Linux

  
    [?]  Example web server: Apache)
  
python3 dirsearch.py r u http://10.10.10.131/ w /usr/share/dirbuster/wordlists/directorylist2.3medium.txt e php,html,js,txt,jsp,pl t 50



    [+] DirSearch  Windows

  
    [?]  Example web server: IIS)
  
python3 dirsearch.py r u http://10.10.10.131/ w /usr/share/dirbuster/wordlists/directorylist2.3medium.txt e php,html,js,txt,asp,aspx,jsp,bak t 50




   [+] DirSearch  banner inspection

dirsearch big.txt e sh,txt,htm,php,cgi,html,pl,bak,old





     [+] HTTP

gobuster dir u http://10.10.10.10 w /usr/share/dirbuster/wordlists/directorylist2.3medium.txt x php,html,txt t 69




     [+]       [+] Gobuster  HTTPS

gobuster dir k u https://10.10.10.10/ w /usr/share/wordlists/dirbuster/directorylist2.3medium.txt t 69




     [+] Gobuster 

gobuster w /usr/share/wordlists/dirbuster/directorylist2.3medium.txt u 10.10.10.27 x '.php' e t 25




     [+] Gobuster 

gobuster w /usr/share/wordlists/dirbuster/directorylist2.3medium.txt u 10.10.10.27 e t 25



    [+]  Nikto

nikto h 10.10.10.10 p 80


    [+]  Nikto HTTPS

nikto h 10.10.10.10 p 443



   [+] bruteforce webdirectories and files by extention

gobuster dir u http://$IP w /usr/share/wordlists/dirbuster/directorylist2.3medium.txt x php,txt t 30




   [+] Gobuster  Subdomain Brute:

gobuster m dns u $Domain w $File t 50



   [+] Gobuster 

gobuster dir u $1 w /usr/share/seclists/Discovery/WebContent/common.txt e z k l o $LOGNAME



   [+] Gobuster 

gobuster $dir a $user_agent t $threads e q r s $dirStatusCodes u $url x $FILE_EXT l w $wordlist o $scanname k





~~~~

   	[+] GoSpider 

~~~~




  
a href"https://github.com/jaelesproject/gospider"   [?]/a
  
a href"urls.txt"gospider S websites.txt js t 20 d 2 sitemap robots w r /a




xargs P 500 a pay I@ sh c 'nc w1 z v @ 443 2/dev/null && echo @' | xargs I@ P10 sh c 'gospider a s "https://@" d 2 | grep Eo "(http|https)://[^/\"].*\.js+" | sed "s\] \ \ng" | anew'


Single target
gospider S domain.txt t 3 c 100 |  tr " " "\n" | grep v ".js" | grep "https://" | grep "" | qsreplace '%22svg%20onloadconfirm(1);'


a href"OUT.txt"gospider S URLS.txt c 10 d 5 blacklist ".(jpg/jpeg/gif/css/tif/tiff/png/ttf/woff/woff2/ico/pdf/svg/txt)" othersource / grep e "code200" / awk '{print $5}'/ grep "" / qsreplace a / dalfox pipe / tee/a




gospider S database/lives.txt d 10 c 20 t 50 K 3 noredirect js a w blacklist ".(eot|jpg|jpeg|gif|css|tif|tiff|png|ttf|otf|woff|woff2|ico|svg|txt)" includesubs q o .tmp/gospider 2 /dev/null | anew q .tmp/gospider.list

xargs a database/lives.txt P 50 I % bash c "echo % | waybackurls" 2 /dev/null | anew q .tmp/waybackurls.list
a href"../../../../../dev/null"xargs a database/lives.txt P 50 I % bash c "echo % / gau blacklist eot,jpg,jpeg,gif,css,tif,tiff,png,ttf,otf,woff,woff2,ico,svg,txt retries 3 threads 50" 2 /dev/null / anew q .tmp/gau.list 2 /dev/null &/a


cat .tmp/gospider.list .tmp/gau.list .tmp/waybackurls.list 2 /dev/null | sed '/\[/d' | grep $DM | sort u | uro | anew q database/urls.txt   Filtering duplicate and common endpoints



   [+] gospider  Injection xss using qsreplace to urls filter

gospider S domain.txt t 3 c 100 |  tr " " "\n" | grep v ".js" | grep "https://" | grep "" | qsreplace '%22svg%20onloadconfirm(1);'



gospider S database/lives.txt d 10 c 20 t 50 K 3 noredirect js a w blacklist ".(eot|jpg|jpeg|gif|css|tif|tiff|png|ttf|otf|woff|woff2|ico|svg|txt)" includesubs q o .tmp/gospider 2 /dev/null | anew q .tmp/gospider.list


Filtering duplicate and common endpoints

cat .tmp/gospider.list .tmp/gau.list .tmp/waybackurls.list 2 /dev/null | sed '/\[/d' | grep $DM | sort u | uro | anew q database/urls.txt



 Crawling using gospider
echo  "[+] Crawling for js files using gospider"
gospider S "subs/filtered_hosts.txt" js t 50 d 3 sitemap robots w r  "subs/gospider.txt"

 Extracting subdomains from JS Files
echo  "[+] Extracting Subdomains......"
sed i '/^.\{2048\}./d' "subs/gospider.txt"

cat "subs/gospider.txt" | grep o 'https?://[^ ]+' | sed 's/]$//' | unfurl u domains | grep "$target_domain" | sort u  "subs/scrap_subs.txt"
rm "subs/gospider.txt"






   	[+] ParamSpider  Parameter Spider






   [+] ParamSpider 

paramspider d $Domain



   [+] ParamSpider  URLs From File

paramspider l $File



   [+] Paramspider  Stream URLs on the termial:

paramspider d $Domain s



   [+] ParamSpider  Proxy

paramspider d $Domain proxy '127.0.0.1:7890'
paramspider d $Domain proxy '10.8.0.1:1080'
paramspider d $Domain proxy '10.64.0.1:1080'



   [+] ParamSpider  Placeholder

  
   [?] Adding a placeholder for URL
       parameter values (default: "FUZZ"):
  
paramspider d $Domain p 'h1relection/h1'



   [+] ParamSpider  Hunt For URLS

python3 paramspider.py domain $Domain exclude woff,png,svg,php,jpg output /$Dir/$File.txt














   [+] DirSearch  Directory Fuzzing:

dirsearch u http://$IP/ e .php



   [+] Webr00t  Directory Bruteforce Tool

perl Webr00t.pl h 172.31.2.47 v | grep v "404 Not Found"


   	[+] WhatWeb 

  
   [?] Provide the protocol scheme (http or https):
   [?] The target server (IP address, hostname or URI) and the port:
  
whatweb colornever noerrors a 3 v $1://$2:$3 2&1 | tee "$1_$2_$3_whatweb.txt"



   [+] WhatWeb  Fingerprinting on $Target & $Port

whatweb a3 color never http://$Target:$Port logbrief $LogFile



whatweb v $Domain  data/$file_/analysis/dynamic/domain_info.txt


  
   [?] identifies all known services
  
whatweb $IP

whatweb $IP:80 colornever logbrief"whattheweb.txt"



a href"../../../../../data"  [+] whatweb  Pulling plugins/a

whatweb infoplugins t 50 v $Domain  $File.txt



  [+] whatweb  Running whatweb on $Domain

whatweb t 50 v $Domain  $File.txt



  [+] whatweb 

whatweb i $URLs u $UserAgent a 3 v logxml $Log.xml





    [+] dirsearch  HTTP Enumeration

dirsearch big.txt e sh,txt,htm,php,cgi,html,pl,bak,old



dirsearch u $Domain e php


for host in `cat alive.txt`; do
DIRSEARCH_FILE$(echo $host | sed E 's/[\.|\/|:]+/_/g').txt
dirsearch e $DIRSEARCH_EXTENSIONS r b u t $DIRSEARCH_THREADS plaintext reports/dirsearch/$DIRSEARCH_FILE u $host
done





  
   [?] httprobe  Uses a list of domains and probes servers to see if they're up
  



    [+] HTTProbe 

httprobe
httprobe s p https:443



    [+] HTTProbe 

cat all.txt | httprobe c $Concurrency t $Timeout  $Alive.txt


echo "  "
echo "   $(cat alive.txt | wc l) Assets Are Responding"
echo "  "



cat $Dir/$File.txt | httprobe cat $File.txt | httprobe s p https:443




~~~~

   	[+] FeroxBuster 

~~~~




feroxbuster url $URL e x .php,txt,html w /usr/share/seclists/Discovery/WebContent/raftsmallwords.txt o $Dir/ferox.out

feroxbuster url $URL e x .php,txt,html w /usr/share/seclists/Discovery/WebContent/raftsmallwords.txt o $Dir/ferox.out




    [+] Feroxbuster  Add PDF, Js, Html, PHP, Json, and Docx to Each URL:

feroxbuster url $URL x pdf x js,html x php txt json,docx



    [+] Feroxbuster  IPv6 NonRecursive Scan with Info LogLevel:

feroxbuster u http://[::1] norecursion vv



    [+] Feroxbuster  Proxy Traffic Through Burp:

a href"127.0.0.1:8080"feroxbuster u http://127.1 insecureproxy/a



    [+] Feroxbuster  Proxy Traffic Through OpenVPN SOCKS5 Proxy:

feroxbuster u http://127.1 proxy socks5h://10.8.0.1:1080



    [+] Feroxbuster  Proxy Traffic Through Wireguard SOCKS5 Proxy:

feroxbuster u http://127.1 proxy socks5h://10.64.0.1:1080



    [+] Feroxbuster  Proxy Traffic Through Tor SOCKS5 Proxy:

feroxbuster u http://127.1 proxy socks5h://127.0.0.1:9050



    [+] Feroxbuster  Pass auth token via query parameter

feroxbuster u http://127.1 query token0123456789ABCDEF



    [+] Feroxbuster  IPv6, nonrecursive scan with INFOlevel logging enabled

feroxbuster u http://[::1] norecursion vv



    [+] Feroxbuster  Read urls from STDIN

cat targets | feroxbuster stdin silent s 200 301 302 redirects x js | fff s 200 o jsfiles



    [+] Feroxbuster  Proxy traffic through Burp

a href"http://127.0.0.1:8080"feroxbuster u http://127.1 insecure proxy/a




    [+] Feroxbuster  Brute force directories on a web server:

a href"directorylistlowercase2.3medium.txt"cat subdomains_live_long.txt / feroxbuster stdin silent k n autobail randomagent t 50 T 3 json o feroxbuster_results.txt s 200,301,302,401,403 w/a








dotdotpwn.pl m http h $IP M GET o unix
dotdotpwn.pl m http h 192.168.1.1 M GET








dotdotpwn.pl m %s u %s h %s k %s f %s d %s o %s x %s t 1 q C b
dotdotpwn.pl m %s u %s h %s k %s f %s d %s o %s x %s t 1 e %s q C b

dotdotpwn.pl m http h %s k %s f %s d %s o %s x %s t 1 q C b
dotdotpwn.pl m http h %s k %s f %s d %s o %s x %s t 1 e %s q C b



[+] Total Traversals found: 





CXSecurity, ZeroDay, Vulners, National
Vulnerability Database, WPScan Vulnerability Database





!~!~!~!~!!!!!!!!!!!

   	[+] Dirb  Web Enumeration + Pentesting

!~!~!~!~!!!!!!!!!!!



  
  [+] Dirb  URL Brute Force:
  
 
  
    dirb http://$IP r o dirb$IP.txt
  
    dirb http://"$1"/ | tee /tmp/results/$1/$1dirb$port.txt
  
    dirb http://$IP/ /usr/share/wordlist/dirb/big.txt
  
    dirb http://$host:$port/ /usr/share/dirb/wordlists/big.txt a \"$2\" o dirbresultshttp$host$port.txt f 
    dirb https://$host:$port/ /usr/share/dirb/wordlists/big.txt a \"$2\" o dirbresultshttps$host$port.txt f
  




   [+] Dirb  

dirb $URL $File a $UserAgent b f S



   [+] Dirb  

dirb $URL $Wordlist a $UserAgent b f S






listurls.py $Domain





!~!~!~!~!!!!!!!!!!!

    [+] WFuzz  Web Application Bruteforcer + Pentesting

wfuzz v t $Threads L hc 404 w $Wordlist u $URL f $File




    [+] Wfuzz  The web brute forcer

wfuzz c z $File.txt sc 200 http://$IP



   [+] WFuzz  Bruteforce web parameter

wfuzz u http://$IP/path/index.php?paramFUZZ w /usr/share/wordlists/rockyou.txt



   [+] WFuzz  Bruteforce post data (login)

wfuzz u http://$IP/path/index.php?actionauthenticate d 'usernameadmin&passwordFUZZ' w /usr/share/wordlists/rockyou.txt

wfuzz c z file,users.txt z file,pass.txt d "nameFUZZ&passwordFUZ2Z" sc 200 hh 206 t 200 $URL/login.php



   [+] WFuzz  

wfuzz c w /usr/share/wfuzz/wordlist/general/megabeast.txt $IP:60080/?FUZZtest



   [+] WFuzz  

wfuzz c hw 114 w /usr/share/wfuzz/wordlist/general/megabeast.txt $IP:60080/?pageFUZZ



   [+] WFuzz  

wfuzz c w /usr/share/wfuzz/wordlist/general/common.txt "$IP:60080/?pagemailer&mailFUZZ"



   [+] WFuzz  

wfuzz c w /usr/share/seclists/Discovery/Web_Content/common.txt hc 404 $IP/FUZZ



   [+] WFuzz  Fuzz Files:

wfuzz c w /usr/share/seclists/Discovery/Web_Content/raftmediumfiles.txt hc 404 t 200 f $Dir/$WFuzzFiles.out $IP/FUZZ



   [+] WFuzz  Fuzz Directories:

wfuzz c z /usr/share/seclists/Discovery/Web_Content/raftmediumfiles.txt hc 404 t 200 f $Dir/$WFuzzDirs.out "$URL/FUZZ"



   [+] WFuzz  

wfuzz c w /usr/share/seclists/Discovery/Web_Content/common.txt R 3 sc 200 $IP/FUZZ



   [+] WFuzz  SubDomain Bruteforce

wfuzz c f subdomains.txt w /usr/share/seclists/Discovery/DNS/bitquarksubdomainstop100000.txt hl 7 t 200 u "$URL" H "Host: FUZZ.$domain"



   [+] WFuzz  Host Bruteforce

wfuzz c w /usr/share/wordlists/SecLists/Discovery/DNS/subdomainstop1million20000.txt c 400,404,403 H "Host: FUZZ.$Domain.com" u $Domain t 100



   [+] WFuzz  UserAgent Filter Code:

wfuzz c w useragents.txt p 127.0.0.1:8080:HTTP ss"Welcome " "UserAgent: FUZZ" "http://$Domain.com/index.php"



   [+] WFuzz  Fuzz using Inline List:

wfuzz z list,GETHEADPOSTTRACEOPTIONS X FUZZ http://testphp.vulnweb.com



   [+] WFuzz  

wfuzz z file,usr/share/wordlists/nosqli H "Authorization: Bearer TOKEN" H "ContentType: application/json" d "{\"coupon_code\":FUZZ} http://crapi.apisec.ai/community/api/v2/coupon/validatecoupon" sc 200




   [+] WFuzz  Fuzz DNS using wfuzz  hide 404

wfuzz H 'Host: FUZZ.site.com' w $File u $Domain hh $RemoveString hc 404



   [+] NMap  HTTP Form Fuzzer  

nmap script httpformfuzzer scriptargs 'httpformfuzzer.targets{1{path/},2{path/register.html}}' p 80 $IP




fuzz some sort of data in the URL’s query string, 
this can be achieved by specifying the FUZZ keyword in the URL after a question mark:

wfuzz z range,010 hl 97 http://testphp.vulnweb.com/listproducts.php?catFUZZ"






!~!~!~!~!!!!!!!!!!!

   	[+] ffuf  Fuzzing + Web Vulnerability Scanner

!~!~!~!~!!!!!!!!!!!





   [+] ffuf  FUZZ parameters

  
    [?] dont forget to include LFI or RFI statements
  
ffuf u "$URL/?FUZZ1" c w /usr/share/seclists/Discovery/WebContent/burpparameternames.txt fw 39 t 200

for i in {0..255}; do echo $i; done | ffuf u '$URL?idFUZZ' c w  fw 33 t 200 o recon/sequence.md





   [+] ffuf  Fuzz For Files

wfuzz c z file,/usr/share/seclists/Discovery/WebContent/raftmediumfiles.txt hc 404 t 200 f recon/wfuzzfiles.out "$URL/FUZZ" 



   [+] ffuf  Change Request Method

ffuf c t 200 fs 50,182 u "$URL/FUZZ/" w /usr/share/wordlists/dirb/big.txt o recon/ffufpost_method.md t 200 X POST



   [+] ffuf  FUZZ File Extensions

ffuf u $URL/indexFUZZ w /usr/share/seclists/Discovery/WebContent/webextensions.txt o recon/ffufext.md t 200


ffuf c u $URL/FUZZ w /usr/share/seclists/Discovery/WebContent/raftmediumwordslowercase.txt e .sh,.cgi,.pl,.py fc 404 t 200 o recon/ffufextensions.md



   [+] ffuf  Fuzz Directories

ffuf c u $URL/FUZZ w /usr/share/seclists/Discovery/WebContent/raftmediumdirectorieslowercase.txt t 200 o recon/ffuf.md






   [+] ffuf  Directory Fuzzing

ffuf w wordlist.txt:FUZZ u http://SERVER_IP:PORT/FUZZ



   [+] ffuf  Extension Fuzzing

ffuf w wordlist.txt:FUZZ u http://SERVER_IP:PORT/indexFUZZ



   [+] ffuf  Page Fuzzing

ffuf w wordlist.txt:FUZZ u http://SERVER_IP:PORT/blog/FUZZ.php



   [+] ffuf  Recursive Fuzzing

ffuf w wordlist.txt:FUZZ u http://SERVER_IP:PORT/FUZZ recursion recursiondepth 1 e .php v



   [+] ffuf  Subdomain Fuzzing

ffuf w wordlist.txt:FUZZ u https://FUZZ.hackthebox.eu/



   [+] ffuf  VHost Fuzzing

ffuf w wordlist.txt:FUZZ u http://academy.htb:PORT/ H 'Host: FUZZ.academy.htb' fs xxx



   [+] ffuf  Parameter Fuzzing  GET

ffuf w wordlist.txt:FUZZ u http://admin.academy.htb:PORT/admin/admin.php?FUZZkey fs xxx



   [+] ffuf  Parameter Fuzzing  POST

ffuf w wordlist.txt:FUZZ u http://admin.academy.htb:PORT/admin/admin.php X POST d 'FUZZkey' H 'ContentType: application/xwwwformurlencoded' fs xxx



   [+] ffuf  Value Fuzzing

ffuf w ids.txt:FUZZ u http://admin.academy.htb:PORT/admin/admin.php X POST d 'idFUZZ' H 'ContentType: application/xwwwformurlencoded' fs xxx



   	[+] Dirb  Web Directory Fuzzing





  
   [?] Please provide the following:
        Target URL Base
        User Agent String
        Proxy Host and Port
  
dirb $1 /usr/share/seclists/Discovery/WebContent/big.txt a $2 l r S o $LOGNAME p $3:$4


dirb $1 /usr/share/seclists/Discovery/WebContent/big.txt l r S o $LOGNAME




dirsearch b u $1 t 16 r E f w /usr/share/wordlists/dirbuster/directorylist2.3medium.txt plaintextreport$LOGNAME


dirsearch b u $1 t 16 r E f w /usr/share/seclists/Discovery/WebContent/big.txt plaintextreport$LOGNAME



   [+] Dirb  Directory Fuzzing:

dirb $Domain /usr/share/wordlists/dirb/big.txt o $File.txt



  
   [?] Please provide the following:
        Target URL
        User Agent String
        HTTP code to ignore
  
dirb $1 /usr/share/seclists/Discovery/WebContent/big.txt a $2 l r S o $LOGNAME f N $3


