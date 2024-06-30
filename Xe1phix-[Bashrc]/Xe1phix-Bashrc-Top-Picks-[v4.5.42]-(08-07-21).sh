

## backup delicious bookmarks++
curl --user login:password -o DeliciousBookmarks.xml -O 'https://api.del.icio.us/v1/posts/all'


##  Download all Delicious bookmarks
curl -u username -o bookmarks.xml https://api.del.icio.us/v1/posts/all


##  Look up the definition of a word
curl dict://dict.org/d:something


##  How fast is the connexion to a URL, some stats from curl
URL="http://www.google.com";curl -L --w "$URL\nDNS %{time_namelookup}s  conn %{time_connect}s  time %{time_total}s\nSpeed %{speed_download}bps Size %{size_download}bytes\n" -o/dev/null -s $URL


##  
curl -n --ssl-reqd --mail-from "<user@gmail.com>" --mail-rcpt "<user@server.tld>" --url smtps://smtp.gmail.com:465 -T file.txt


##  Get a file from an SSH server using SFTP:
curl -u username sftp://shell.example.com/etc/issue


##  Get a file from an SSH server using
curl -u username: --key ~/.ssh/id_dsa --pubkey ~/.ssh/id_dsa.pub \		


##  
curl --dump-header headers.txt curl.haxx.se

##  
curl --resolve 127.0.0.1:4444:http://killyourtv.i2p/killyourtv.asc 



##  How fast is the connexion to a URL, some stats from curl
URL="http://www.google.com";curl -L --w "$URL\nDNS %{time_namelookup}s conn %{time_connect}s time %{time_total}s\nSpeed %{speed_download}bps Size %{size_download}bytes\n" -o/dev/null -s $URL




$ cat .curlrc

-w "dnslookup: %{time_namelookup} | connect: %{time_connect} | appconnect: %{time_appconnect} | pretransfer: %{time_pretransfer} | starttransfer: %{time_starttransfer} | total: %{time_total} | size: %{size_download}\n"


curl -so /dev/null https://www.zasag.mn
##  dnslookup: 1.510 | connect: 1.757 | appconnect: 2.256 | pretransfer: 2.259 |
##  starttransfer: 2.506 | total: 3.001 | size: 53107


##  Save the Top 2500 commands from commandlinefu to a single text file
curl http://www.commandlinefu.com/commands/browse/sort-by-votes/plaintext/[0-2500:25] | grep -v _curl_ > comfu.txt


##  Get all these commands in a text file with description.
for x in `jot - 0 2400 25`; do curl "http://www.commandlinefu.com/commands/browse/sort-by-votes/plaintext/$x" ; done > commandlinefu.txt


##  Stream YouTube URL directly to mplayer
id="dMH0bHeiRNg";mplayer -fs http://youtube.com/get_video.php?video_id=$id\&t=$(curl -s http://www.youtube.com/watch?v=$id | sed -n 's/.*, "t": "\([^"]*\)", .*/\1/p')


##  geoip information
curl -s "http://www.geody.com/geoip.php?ip=$(curl -s icanhazip.com)" | sed '/^IP:/!d;s/<[^>][^>]*>//g'


##  Create QR codes from a URL.
qrurl() { curl "http://chart.apis.google.com/chart?chs=150x150&cht=qr&chld=H%7C0&chl=$1" -o qr.$(date +%Y%m%d%H%M%S).png; }


##  Print trending topics on Twitter
curl -s search.twitter.com | awk -F'</?[^>]+>' '/\/intra\/trend\//{print $2}'


##  Google URL shortener
curl -s -d'&url=URL' http://goo.gl/api/url | sed -e 's/{"short_url":"//' -e 's/","added_to_history":false}/\n/'


##  Expand shortened URLs
expandurl() { curl -sIL $1 | grep ^Location; }

##  Updating the status on identi.ca using curl.
curl -u USER:PASS -d status="NEW STATUS" http://identi.ca/api/statuses/update.xml

##  Shutdown a Windows machine from Linux
net rpc shutdown -I ipAddressOfWindowsPC -U username%password


##  List of commands you use most often
history | awk '{print $2}' | sort | uniq -c | sort -rn | head


##  Get the 10 biggest files/folders for the current direcotry
du -s * | sort -n | tail


##  List 10 largest directories in current directory
du -hs */ | sort -hr | head


##  
lsof -i tcp:80
netstat -p tcp:80





##  Recursively change permissions on files, leave directories alone.
find /$Dir/ -type f -print0 | xargs -0 chmod 644
find /$Dir/ -type f -exec chmod 644 {} +


##  Find and copy files
find / -iname "$FileName" -print0 | xargs -I {} cp {} /$Dir/
find / -iname "$FileName" | xargs -I {} cp {} /$Dir/





##  Lists all listening ports together with the PID of the associated process
lsof -Pan -i tcp -i udp

##  List all open ports and their owning executables
lsof -i -P | grep -i "listen"


##  View network activity of any application or user in realtime
lsof -r 2 -p PID -i -a


##  View user activity per directory.
lsof -u someuser -a +D /etc





##  find geographical location of an ip address
lynx -dump http://www.ip-adress.com/ip_tracer/?QRY=$1|grep address|egrep 'city|state|country'|awk '{print $3,$4,$5,$6,$7,$8}'|sed 's\ip address flag \\'|sed 's\My\\'


##  Cut out a piece of film from a file. Choose an arbitrary length and starting time.
ffmpeg -vcodec copy -acodec copy -i orginalfile -ss 00:01:30 -t 0:0:20 newfile

##  sniff network traffic on a given interface and displays the IP addresses of the machines communicating with the current host (one IP per line)
tcpdump -i wlan0 -n ip | awk '{ print gensub(/(.*)\..*/,"\\1","g",$3), $4, gensub(/(.*)\..*/,"\\1","g",$5) }' | awk -F " > " '{print $1"\n"$2}'



##  Monitor open connections for httpd including listen, count and sort it per IP
watch "netstat -plan|grep :80|awk {'print \$5'} | cut -d: -f 1 | sort | uniq -c | sort -nk 1"

##  Monitor TCP opened connections
watch -n 1 "netstat -tpanl | grep ESTABLISHED"

##  All IP connected to my host
netstat -lantp | grep ESTABLISHED |awk '{print $5}' | awk -F: '{print $1}' | sort -u

##  Number of open connections per ip.
netstat -ntu | awk '{print $5}' | cut -d: -f1 | sort | uniq -c | sort -n

##  List the number and type of active network connections
netstat -ant | awk '{print $NF}' | grep -v '[a-z]' | sort | uniq -c

##  Show apps that use internet connection at the moment. (Multi-Language)
netstat -lantp | grep -i stab | awk -F/ '{print $2}' | sort | uniq
netstat -lantp | grep -i establ | awk -F/ '{print $2}' | sort | uniq




##  Extract audio from Flash video (*.flv) as mp3 file
ffmpeg -i video.flv -vn -ar 44100 -ac 2 -ab 192k -f mp3 audio.mp3

##  Find the most recently changed files (recursively)
find . -type f -printf '%TY-%Tm-%Td %TT %p\n' | sort





##  Save an HTML page, and covert it to a .pdf file
wget $URL | htmldoc --webpage -f "$URL".pdf - ; xpdf "$URL".pdf &


##  get all pdf and zips from a website using wget
wget --reject html,htm --accept pdf,zip -rl1 url


##  Download Youtube video with wget!
wget http://www.youtube.com/watch?v=dQw4w9WgXcQ -qO- | sed -n "/fmt_url_map/{s/[\'\"\|]/\n/g;p}" | sed -n '/^fmt_url_map/,/videoplayback/p' | sed -e :a -e '$q;N;5,$D;ba' | tr -d '\n' | sed -e 's/\(.*\),\(.\)\{1,3\}/\1/' | wget -i - -O surprise.flv

##  Block known dirty hosts from reaching your machine
wget -qO - http://infiltrated.net/blacklisted|awk '!/#|[a-z]/&&/./{print "iptables -A INPUT -s "$1" -j DROP"}'


##-================================================-## 
##      [+] Bulk Download Files By Their URLs 
##-================================================-## 
## ---------------------------------------------------------------- ## 
##  [?] The URL Links Are Fed To Curl From xarg 
## ---------------------------------------------------------------- ## 
xargs -n 1 curl -O < $URLFile 





##  Display current bandwidth statistics
ifstat -nt

##  Get Cisco network information
tcpdump -nn -v -i eth0 -s 1500 -c 1 'ether[20:2] == 0x2000'

##  Quick glance at who's been using your system recently
last | grep -v "^$" | awk '{ print $1 }' | sort -nr | uniq -c

##  create dir tree
mkdir -p doc/{text/,img/{wallpaper/,photos/}}

##  Get all links of a website
lynx -dump http://www.domain.com | awk '/http/{print $2}'

##  Find all active ip's in a subnet
arp-scan -I eth0 192.168.1.0/24

##  
ssh -f -L3389:<RDP_HOST>:3389 <SSH_PROXY> "sleep 10" && rdesktop -T'<WINDOW_TITLE>' -uAdministrator -g800x600 -a8 -rsound:off -rclipboard:PRIMARYCLIPBOARD -5 localhost
#RDP through SSH tunnel

##  
curl -s --request GET   --url https://www.virustotal.com/api/v3/files/"${THE}"  --header 'x-apikey: data' | jq '. | {MD5: .data.attributes.md5, Malicious: .data.attributes.last_analysis_stats.malicious, Undetected: .data.attributes.last_analysis_stats.undetected, Errors: .error}' >> output.txt

##  


echo "Performing HTTP Object Lookups via VirusTotal
curl -s --request GET   --url https://www.virustotal.com/api/v3/files/"${ARG}"  --header 'x-apikey: data' | jq '. | {MD5: .data.attributes.md5, Malicious: .data.attributes.last_analysis_stats.malicious, Undetected: .data.attributes.last_analysis_stats.undetected, Errors: .error}' >> output.txt


##  Connect via SSH to VirtualBox guest VM without knowing IP address
ssh vm-user@`VBoxManage guestproperty get "vm-name" "/VirtualBox/GuestInfo/Net/0/V4/IP" | awk '{ print $2 }'`


##  Stream audio over ssh
sox $File.mp3 -t wav - |ssh thelab@company.com paplay


##  


##  


##  



firejail --dns.print=803431
firejail --net.print=803431



gobuster -u http://10.11.1.49/ -w /usr/share/golismero/wordlist/fuzzdb/Discovery/PredictableRes/CMS/drupal_plugins.fuzz.txt -s '200,204,301,302,307,403,500'


nikto +host 10.11.1.49


wfuzz.py -c -z file,users.txt -z file,pass.txt --sc 200 http://www.site.com/log.asp?user=FUZZ&pass=FUZ2Z
wfuzz.py -c -z range,1-10 --hc=BBB http://www.site.com/FUZZ{something not there}
wfuzz.py --script=robots -z list,robots.txt http://www.webscantest.com/FUZZ

sqlmap -v 3 -u 'http://192.168.1.105/dev/select.php?id=' -p id - -dbms=mysql --technique=B




netstat : List Host Open Ports
netstat -ap tcp | grep -i listen

.


tcpdump : Dump all TCP Traffic
sudo tcpdump -A -i all 


sed -e 's/oldText/newText/g; s/moreOldText/moreNewText/g' ./myTextFile.txt




https://github.com/topics/pcap
https://github.com/topics/pcap-analyzer
https://github.com/topics/pcap-parser
https://github.com/topics/network-analysis
https://github.com/topics/network-forensics
https://github.com/topics/network-monitoring?l=shell






#To run Snort on Ubuntu safely without root access, you should create a #new unprivileged user and a new user group for the daemon to run under.

groupadd snort
useradd snort -r -s /sbin/nologin -c SNORT_IDS -g snort



