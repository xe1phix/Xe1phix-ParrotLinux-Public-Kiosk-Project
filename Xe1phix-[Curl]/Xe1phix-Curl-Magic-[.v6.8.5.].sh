#!/bin/bash
## Curl.sh


## Fetch File using SFTP:
curl sftp://$URL.com/$File.zip -u $User

## Require TLS security for your FTP transfer:
curl --ssl-reqd ftp://ftp.$URL.com/$File.txt

## Fetch File using SCP:
curl scp://$URL.com/$File.zip -u $User


## SFTP (but not SCP) supports getting a file listing 
## back when the URL ends with a trailing slash:

curl sftp://$URL.com/ -u $User

curl sftp://$URL.com/~/$File.txt -u $User


## Require TLS security for your FTP transfer:
curl --ssl-reqd ftp://ftp.$URL.com/$File.txt

## Suggest TLS to be used for your FTP transfer:
curl --ssl ftp://ftp.$URL.com/$File.txt


curl --key-type PEM --key 


curl --pem 
curl --cert 
curl --crt-file 
--pubkey
--cert-type
--crlfile
--dns-servers
--key
--key-type




curl --resolve <host:port:address>

curl --resolve 127.0.0.1:4444:http://killyourtv.i2p/killyourtv.asc 

curl --resolve 127.0.0.1:9053:https://tails.boum.org/tails-signing.key
curl --socks5-hostname 127.0.0.1:9050 https://check.torproject.org

curl --proxy http://
curl --proxy socks4a://
curl --proxy --socks4a
curl --proxy socks5://
curl --socks5 $HOST:$Port
curl --socks5 127.0.0.1:9150
curl --proxy "socks5h://localhost:9050"

curl -s -k --socks5 'localhost:9050' "$image_url"
curl -s -k -L --socks5 'localhost:9050' "$1"
curl --socks5 127.0.0.1:9150 http://checkip.amazonaws.com/
curl --socks5 localhost:9050 http://checkip.dyndns.com/
curl --socks5-hostname 127.0.0.1:9050 https://check.torproject.org
curl --socks5 localhost:9050 --socks5-hostname localhost:9050 -s https://check.torproject.org/ | cat | grep -m 1 Congratulations | xargs
curl --socks5 localhost:9050 --socks5-hostname localhost:9050 -s https://check.torproject.org/ | cat | grep -m 1 Congratulations | xargs

curl -IL --socks5 host:port --proxy-user username:password https://api.telegram.org





##-=========================-## 
##  [+] Grab HTTP Headers 
##-=========================-## 
curl -LIN $Domain

curl -i -I -X TRACE --insecure "$1"



## ----------------------------------------------------------------------- ## 
##   [?] if you ever forget the dns4tor*.onion address
##       --> you can simply use cURL: 
## ----------------------------------------------------------------------- ## 
 curl -sI https://tor.cloudflare-dns.com | grep alt-svc



##-===============================-## 
##     [+] Curl SOCKS5 Proxy Connection: 
##-===============================-## 
curl -s -m 10 --socks5 $hostport --socks5-hostname $hostport -L $URL


Print some info about a PKCS#12 file:
openssl pkcs12 -in file.p12 -info -noout


-fingerprint

calculate the fingerprint of RiseupCA.pem
certtool -i < RiseupCA.pem |egrep -A 1 'SHA256 fingerprint'
openssl x509 -sha256 -in RiseupCA.pem -noout -fingerprint

head -n -1 RiseupCA.pem | tail -n +2 | base64 -d | sha256sum


# check site ssl certificate dates
echo | openssl s_client -connect $Site.com:443 2>/dev/null |openssl x509 -dates -noout



sudo openssl req -newkey rsa:4096 -keyout /etc/openvpn/vpn-key.pem -out vpn.csr


sudo openssl req -newkey rsa:4096 -keyout /etc/openvpn/ClientVPNKey.pem -out /etc/openvpn/ClientVPNKey.csr

sudo openssl req -newkey rsa:4096 -keyout /etc/openvpn/ServerVPNKey.pem -out ServerVPNKey.csr
openssl x509 -CA cacert.pem -CAkey cakey.pem -CAcreateserial -days 730 -req -in ClientVPNKey.csr -out ClientVPNKey.pem


Curl – Securely Connecting Using TLS (Required) - 

curl --tlsv1.3 --verbose --progress-bar --ssl-reqd 


curl --verbose --progress-bar --tlsv1 --url https://help.riseup.net/en/security/network-security/riseup-ca/RiseupCA.pem --output /home/amnesia/Gnupg/RiseupCA.pem
curl --verbose --progress-bar --tlsv1 --url https://help.riseup.net/en/security/network-security/riseup-ca/riseupCA-signed-sha1.txt --output /home/amnesia/Gnupg/riseupCA-signed-sha1.txt
curl --verbose --progress-bar --tlsv1 --url https://help.riseup.net/en/security/network-security/certificates/riseup-signed-certificate-fingerprints.txt  --output /home/amnesia/Gnupg/
curl --tlsv1 --url https://tails.boum.org/tails-signing.key --output /home/amnesia/Gnupg/tails-signing.key  && gpg --keyid-format long --import tails-signing.key
curl -Os https://releases.hashicorp.com/vault/0.5.2/vault_0.5.2_linux_amd64.zip
curl -Os https://releases.hashicorp.com/vault/0.5.2/vault_0.5.2_SHA256SUMS
curl -Os https://releases.hashicorp.com/vault/0.5.2/vault_0.5.2_SHA256SUMS.sig
curl --tlsv1.3 --verbose --progress-bar --url=https://keys.qubes-os.org/keys/qubes-master-signing-key.asc --output=~/qubes-master-signing-key.asc
curl --tlsv1 --url https://www.whonix.org/wiki/Whonix_Signing_Key --output /home/amnesia/Gnupg/Whonix_Signing_Key
curl --tlsv1 --url https://geti2p.net/_static/debian-repo.pub --output /home/amnesia/Gnupg/debian-repo.pub
curl --tlsv1 --url https://www.whonix.org/patrick.asc --output /home/amnesia/Gnupg/patrick.asc

echo "## ============================================== ##"
echo "   [+] Curl Fetch Mullvads .asc (Require SSL):"
echo "## ============================================== ##"
curl --verbose --ssl-reqd --url https://mullvad.net/media/mullvad-support-mail.asc --output ~/mullvad-support-mail.asc
curl --verbose --ssl-reqd --url https://mullvad.net/media/mullvad-code-signing.asc --output ~/mullvad-code-signing.asc

curl --verbose --ssl-reqd --url https://mullvad.net/media/mullvad-code-signing.asc --output ~/Downloads/Scripts/Mullvad-LinuxSetup/mullvad-code-signing.asc

curl --verbose --ssl-reqd --url https://mullvad.net/media/mullvad-code-signing.asc | gpg --keyid-format 0xlong --verbose --import



curl --verbose --ssl-reqd --url https://mullvad.net/media/app/MullvadVPN-2020.2_amd64.deb.asc --output ~/Downloads/Scripts/Mullvad-LinuxSetup/MullvadVPN-2020.2_amd64.deb.asc

curl --verbose --tlsv1.2 --url https://mullvad.net/media/app/MullvadVPN-2020.2_amd64.deb.asc --output ~/Downloads/Scripts/Mullvad-LinuxSetup/MullvadVPN-2020.2_amd64.deb.asc


curl --verbose --tlsv1.2 --url https://mullvad.net/media/app/MullvadVPN-2020.2_amd64.deb --output ~/Downloads/Scripts/Mullvad-LinuxSetup/MullvadVPN-2020.2_amd64.deb


alias archiveb='(wget -r -l1 --no-parent -nH -nd -P/tmp -A".gif,.jpg" https://boards.4chan.org/b/)'		


curl http://example.com/a.gz | tar xz

curl -s checkip.dyndns.org | grep -Eo '[0-9\.]+'
curl -v -k -u user:password "https://members.dyndns.org/nic/update?hostname=<your_domain_name_here>&myip=$(curl -s http://checkip.dyndns.org | sed 's/[a-zA-Z<>/ :]//g')&wildcard=NOCHG&mx=NOCHG&backmx=NOCHG"
curl -u $USERNAME:$PASSWORD "http://dynupdate.no-ip.com/nic/update?hostname=$HOSTNAME"
curl -s http://checkip.dyndns.org/ | grep -o "[[:digit:].]\+"
curl -s http://checkip.dyndns.org | sed 's/[a-zA-Z<>/ :]//g'
curl -s 'http://checkip.dyndns.org' | sed 's/.*Current IP Address: \([0-9\.]*\).*/\1/g'





curl https://icanhazip.com/ 2>/dev/null || dnsdomainname || hostname

# How fast is the connexion to a URL, some stats from curl
URL="http://www.google.com";curl -L --w "$URL\nDNS %{time_namelookup}s  conn %{time_connect}s  time %{time_total}s\nSpeed %{speed_download}bps Size %{size_download}bytes\n" -o/dev/null -s $URL

# Send email with curl and gmail
curl -n --ssl-reqd --mail-from "<user@gmail.com>" --mail-rcpt "<user@server.tld>" --url smtps://smtp.gmail.com:465 -T file.txt

curl -u username:password --silent "https://mail.google.com/mail/feed/atom" | tr -d '\n' | awk -F '<entry>' '{for (i=2; i<=NF; i++) {print $i}}' | sed -n "s/<title>\(.*\)<\/title.*name>\(.*\)<\/name>.*/\2 - \1/p"

cmdfu(){ curl "http://www.commandlinefu.com/commands/matching/$@/$(echo -n $@ | openssl base64)/plaintext"; }

curl http://www.commandlinefu.com/commands/browse/sort-by-votes/plaintext/[0-2500:25] | grep -v _curl_ > comfu.txt




## 
curl sftp://example.com/file.zip -u user

## 
curl scp://example.com/file.zip -u user


## SFTP (but not SCP) supports getting a file listing 
## back when the URL ends with a trailing slash:
curl sftp://example.com/ -u user


## 
curl sftp://example.com/~/todo.txt -u daniel


## Require TLS security for your FTP transfer:
curl --ssl-reqd ftp://ftp.example.com/file.txt


## Suggest TLS to be used for your FTP transfer:
curl --ssl ftp://ftp.example.com/file.txt


## Get a file over HTTPS:
curl https://www.example.com/




## 
ftp://ftp.example.com/file[1-100].txt


## 
http://site.{one,two,three}.com


## 
ftp://ftp.example.com/file[a-z].txt


## 
http://example.com/archive[1996-1999]/vol[1-4]/part{a,b,c}.html/



curl -Is slashdot.org | egrep '^X-(F|B|L)' | cut -d \- -f 2
curl -Is slashdot.org | sed -n '5p' | sed 's/^X-//'




## 
curl --resolve 127.0.0.1:4444:http://killyourtv.i2p/killyourtv.asc 


## 
curl --tlsv1.2 --url --https://geti2p.net/_static/i2p-debian-repo.key.asc --output=~/


## 
curl --verbose --progress-bar --tlsv1 --url $I2PPublicKeyURL --output /home/amnesia/Gnupg/debian-repo.pub && apt-key add /home/amnesia/Gnupg/debian-repo.pub


## 
curl https://keys.qubes-os.org/keys/qubes-master-signing-key.asc


## 
curl --tlsv1 --url https://help.riseup.net/security/network-security/riseup-ca/RiseupCA.pem  --output /home/amnesia/Gnupg/RiseupCA.pem


## 
curl https://check.torproject.org

## 
curl https://meejah.ca/meejah.asc | gpg --import








curl -x socks5://[user:password@]proxyhost[:port]/ url
curl --socks5 192.168.1.254:3099 https://www.cyberciti.biz/

sudo -n -u anon curl -fsSI --socks5 127.0.0.1:9050 ${webhost}						    ## Fetch via SOCKS proxy w/ local DNS as anon

sudo -n -u anon curl -fsSI --socks5-hostname 127.0.0.1:9050 ${webhost}      		    ## Fetch via SOCKS proxy as anon

curl -fsSI --socks5-hostname 127.0.0.1:9050 ${webhost}                                  ## Fetch via SOCKS proxy as root

sudo -n -u anon curl -fsSI -x 127.0.0.1:8118 ${webhost}                                 ## Fetch via HTTP proxy as anon

curl -fsSI -x 127.0.0.1:8118 ${webhost}                                                 ## Fetch via HTTP proxy as root

sudo -n -u privoxy curl -fsSI --socks5-hostname 127.0.0.1:9050 ${webhost}               ## Fetch via privoxy

sudo -n -u privoxy curl -fsSI --socks5 127.0.0.1:9050 ${webhost}                        ## Fetch via SOCKS5 proxy w/ local DNS as privoxy

sudo -n -u privoxy curl -fsSI --socks5-hostname 127.0.0.1:9050 ${webhost}               ## Fetch via SOCKS5 proxy as privoxy

sudo -n -u privoxy curl -fsSI --socks5 127.0.0.1:9050 ${webhost}                        ## Fetch via SOCKS5 proxy w/ local DNS as privoxy"

sudo -n -u anon curl -fsSI -x 127.0.0.1:8118 ${onionhost}                               ## Fetch via .onion via HTTP proxy as anon

sudo -n -u anon curl -fsSI --socks5-hostname 127.0.0.1:9050 ${onionhost}                ## Fetch .onion via SOCKS proxy as anon







# Request using p12 client certificate
curl --cert-type P12 --cert ClientCert.p12:ClientCertPassword $URL


# Request using client certificate + key
curl --cacert ca.pem --key $ClientKey.pem --cert $ClientCert.pem $URL



curl -k -v -4 --cert public.pem --key private.pem 



curl -sLk --cacert /etc/kubernetes/ssl/kube-ca.pem --cert /etc/kubernetes/ssl/kube-node.pem --key /etc/kubernetes/ssl/kube-node-key.pem 


openssl pkcs12 -export -out cert.pfx -inkey key.pem -in cert.pem -certfile ca.pem
curl --cert cert.pfx:mypassword 



curl -v -s -k --key client.key --cert client.crt $URL




curl --key /etc/elasticsearch/secret/admin-key  --cert /etc/elasticsearch/secret/admin-cert --cacert /etc/elasticsearch/secret/admin-ca -XGET "https://localhost:9200/_cat/indices"
curl --key /etc/elasticsearch/secret/admin-key  --cert /etc/elasticsearch/secret/admin-cert --cacert /etc/elasticsearch/secret/admin-ca -XGET "https://localhost:9200/project.name.b6133790-8961-11e6-91c2-005056bd0733.2017.08.17/_search?pretty=1"



## 
curl http://url/rss | grep -o '<enclosure url="[^"]*' | grep -o '[^"]*$' | xargs wget -c


## 
curl http://pswonly.swsgtv.libsynpro.com/rss | grep -o '<enclosure url="[^"]*' | grep -o '[^"]*$' | xargs wget -c


## 
curl -L -s `curl -s http://www.2600.com/oth-broadband.xml` | xmlstarlet sel -t -m "//enclosure[1]" -v "@url" -n | head -n 1` | ssh -t [user]@[host] "mpg123 -"


## 
curl -n --ssl-reqd --mail-from "<user@gmail.com>" --mail-rcpt "<user@server.tld>" --url smtps://smtp.gmail.com:465 -T file.txt


## 
curl -u username -o bookmarks.xml https://api.del.icio.us/v1/posts/all


## 
check(){ curl -sI $1 | sed -n 's/Location: *//p';}

curl -s "http://www.geody.com/geoip.php?ip=$(curl -s icanhazip.com)" | sed '/^IP:/!d;s/<[^>][^>]*>//g'




## 
curl -O http://www.commandlinefu.com/commands/browse/sort-by-votes/plaintext/[0-2400:25]


## 
for x in `seq 0 25 2400`; do curl "http://www.commandlinefu.com/commands/browse/sort-by-votes/plaintext/$x" ; done > commandlinefu.txt


## 
cmdfu(){ curl "http://www.commandlinefu.com/commands/matching/$@/$(echo -n $@ | openssl base64)/plaintext"; }


## 
curl "http://www.commandlinefu.com/commands/browse/sort-by-votes/plaintext"



## 
grep -q '^## Get header' "$file" 2>/dev/null

## Get header
alias header="curl -I"\n' >> "$file"

## 
/run/media/public/2TB/BrowntownAlpha/Sir-Goatse-lot/net2.sh:grep -q '^## Get external IP address' "$file" 2>/dev/null

## 
alias ipx="curl -s http://ipinfo.io/ip"\n' >> "$file"



## 
cmdfu(){ curl "http://www.commandlinefu.com/commands/matching/$@/$(echo -n $@ | openssl base64)/plaintext"; }


## 
curl -Is slashdot.org | egrep '^X-(F|B|L)' | cut -d \- -f 2


## 
URL="http://www.google.com";curl -L --w "$URL\nDNS %{time_namelookup}s conn %{time_connect}s time %{time_total}s\nSpeed %{speed_download}bps Size %{size_download}bytes\n" -o/dev/null -s $URL


## 
curl -u user:pass -d status="Tweeting from the shell" http://twitter.com/statuses/update.xml


## 
curl --resolve 127.0.0.1:4444:http://killyourtv.i2p/killyourtv.asc


## 
curl --resolve 127.0.0.1:9053:https://tails.boum.org/tails-signing.key


## 
curl --verbose --ssl-reqd --tlsv1.3 --progress-bar --proto=https $1


## 
curl --verbose --ssl-reqd --tlsv1.2 --http2 --show-error --trace-time --progress-bar --url  --output /home/faggot/



## 
curl --resolve 127.0.0.1:4444:http://killyourtv.i2p/killyourtv.asc
curl --proxy http://
curl --proxy socks4a://
curl --proxy --socks4a
curl --proxy socks5://
curl --socks5 HOST[:PORT]
curl --socks5 127.0.0.1:9150
curl --http-proxy=socks4a://127.0.0.1:59050
curl --socks5 127.0.0.1:9150


## 
curl --verbose --progress-bar --tlsv1 --url https://geti2p.net/_static/debian-repo.pub --output /home/amnesia/Gnupg/debian-repo.pub && apt-key add /home/amnesia/Gnupg/debian-repo.pub

## 
curl -o i2p-debian-repo-key.asc -3 --tlsv1.2 --verbose https://geti2p.net/_static/i2p-debian-repo.key.asc



## Retrieve the date from the torproject site
curl -silent --head torproject.org | grep -i date:


## 
curl --resolve 127.0.0.1:4444:http://killyourtv.i2p/killyourtv.asc


## 
curl --tlsv1.2 --url https://dl.dropboxusercontent.com/u/18621288/debian/pool/main/i/i2p-keyring/i2p-keyring_2014.09.25_all.deb --output ~/Gnupg/i2p-keyring_2014.09.25_all.deb


## 
curl https://meejah.ca/meejah.asc | gpg --import


## 
curl --verbose --progress-bar --tlsv1 --url https://www.whonix.org/patrick.asc --output /home/amnesia/Gnupg/patrick.asc && apt-key add /home/amnesia/Gnupg patrick.asc

## 
curl ‐o spender‐gpg‐key.asc https://grsecurity.net/spender‐gpg‐key.asc


## 
curl --tlsv1.2 --url https://keys.qubes-os.org/keys/qubes-master-signing-key.asc --verbose --output /home/${usr}/Gnupg/qubes-master-signing-key.asc


## 
curl -O https://mirror.securix.org/securix-codesign.pub


## 
curl --socks5 127.0.0.1:9150


## 
curl --tlsv1 --url https://dl.dropboxusercontent.com/u/18621288/debian/pool/main/i/i2p-keyring/i2p-keyring_2014.09.25_all.deb --output /home/amnesia/Gnupg/i2p-keyring_2014.09.25_all.deb | dpkg -i i2p-keyring_2014.09.25_all.deb


## 
curl --tlsv1 --url http://archive.kali.org/archive-key.asc --output /home/amnesia/Gnupg/archive-key.asc | gpg --import


## 
curl --tlsv1 --url https://tails.boum.org/tails-signing.key --output /home/amnesia/Gnupg/tails-signing.key  && gpg --keyid-format long --import tails-signing.key


## 
curl --tlsv1 --url https://blog.patternsinthevoid.net/isis.txt --output /home/amnesia/Gnupg/isis.txt


## 
curl --tlsv1 --url https://blog.patternsinthevoid.net/isis.sig --output /home/amnesia/Gnupg/isis.sig



## 
curl --tlsv1 --url https://blog.patternsinthevoid.net/0xA3ADB67A2CDB8B35.asc --output /home/amnesia/Gnupg/0xA3ADB67A2CDB8B35.asc


## 
curl --tlsv1 --url https://blog.patternsinthevoid.net/0xA3ADB67A2CDB8B35.sig --output /home/amnesia/Gnupg/0xA3ADB67A2CDB8B35.sig


## 
curl --tlsv1 --url https://help.riseup.net/security/network-security/riseup-ca/RiseupCA.pem  --output /home/amnesia/Gnupg/RiseupCA.pem	


## 
curl --tlsv1 --url   --output /home/amnesia/ | gpg --import


## 
curl --tlsv1 --url http://archive.kali.org/archive-key.asc --output /home/amnesia/Gnupg/archive-key.asc | gpg --import


## 
curl https://getfedora.org/static/fedora.gpg | gpg --import


## 
curl --verbose --progress-bar --tlsv1 --url https://raw.githubusercontent.com/Security-Onion-Solutions/security-onion/master/KEYS --output /home/faggot/Gnupg/KEYS


## 
curl --verbose --progress-bar --tlsv1 --url=http://www.netfilter.org/files/coreteam-gpg-key.txt --output coreteam-gpg-key.txt


## 
curl --verbose --progress-bar --tlsv1 --url https://tails.boum.org/<tails.iso> | tee >(sha1sum > dvd.sha1) > dvd.iso



## 
curl --key-type PEM --key 


## 
curl --cacert 


## 
curl --verbose --progress-bar --tlsv1 --url https://help.riseup.net/en/security/network-security/riseup-ca/RiseupCA.pem --output /home/amnesia/Gnupg/RiseupCA.pem


## 
curl --verbose --progress-bar --tlsv1 --url https://help.riseup.net/en/security/network-security/riseup-ca/riseupCA-signed-sha1.txt --output /home/amnesia/Gnupg/riseupCA-signed-sha1.txt


## 
curl --verbose --progress-bar --tlsv1 --url https://help.riseup.net/en/security/network-security/certificates/riseup-signed-certificate-fingerprints.txt  --output /home/amnesia/Gnupg/




## Update airmon-ng OUI Database File:
airodump-ng-oui-update 2>/dev/null || curl --progress -k -L "http://standards.ieee.org/develop/regauth/oui/oui.txt" > /etc/aircrack-ng/oui.txt





curl ifconfig.me/ip             ## -> IP Adress
curl ifconfig.me/host           ## -> Remote Host
curl ifconfig.me/ua             ## ->User Agent
curl ifconfig.me/port           ## -> Port




## 
curl http://name:passwd@machine.domain/full/path/to/file



## Get the first 100 bytes of a document:
curl ‐r 0‐99 http://www.get.this/


## Get the last 500 bytes of a document:
curl ‐r ‐500 http://www.get.this/


## Get the first 100 bytes of a document using FTP:
curl ‐r 0‐99 ftp://www.get.this/README


## Upload all data on stdin to a specified server:
curl ‐T ‐ ftp://ftp.upload.com/myfile


## Upload all data on stdin to a specified HTTP site:
curl ‐T ‐ http://www.upload.com/myfile






## Trace the connection while a file is being retrieved:
curl ‐‐trace trace.txt www.haxx.se


## Store the HTTP headers in a separate file 
##     (headers.txt in the example):
curl ‐‐dump‐header headers.txt curl.haxx.se



## Spoof a user agent of a windows 95 box, using firefox
curl ‐A 'Mozilla/3.0 (Win95; I)' http://www.nationsbank.com/

curl -u username -o bookmarks.xml https://api.del.icio.us/v1/posts/all


curl --user login:password -o DeliciousBookmarks.xml -O 'https://api.del.icio.us/v1/posts/all'






## Curl also has the ability to use previously received cookies
## And apply them to future connections via file output
curl ‐‐dump‐header headers www.example.com


## use the cookies from the 'headers' file like:
curl ‐b headers www.example.com


## make curl save the incoming cookies using the well‐known 
## netscape cookie format like this:
curl ‐c cookies.txt www.example.com


## To display the amount of bytes downloaded:
curl ‐w 'We downloaded %{size_download} bytes\n' www.download.com


## how to automatically retrieve a document 
## using a certificate with a personal password:
curl ‐E /path/to/cert.pem:password https://secure.site.com/





## SFTP and SCP and PATH NAMES
curl ‐u $USER sftp://home.example.com/~/.bashrc







## download that only gets performed if the
## remote file is newer than a local copy.
curl ‐z local.html http://remote.server.com/remote.html


## Specify a date the file must be newer than:
curl ‐z "Jan 12 2012" http://remote.server.com/remote.html



## 'm' are 'match' & 'find'
## 'd' are 'define'& 'lookup'


## 
curl dict://dict.org/m:curl

## 
curl dict://dict.org/d:heisenbug:jargon

## 
curl dict://dict.org/d:daniel:web1913



## 
curl dict://dict.org/find:curl


curl dict://dict.org/d:something




## 
curl -s http://isc.sans.org/sources.html|grep "ipinfo.html"|awk -F"ip=" {'print $2'}|awk -F"\"" {'print $1'}|xargs -n1 sudo iptables -A OUTPUT -j DROP -d > 2&>1


## 
curl -s http://isc.sans.org/ipsascii.html | grep -v '#' | awk '{print $1}' | perl -pi -e 's/(?:^0{1,})|(?:(?<=\.)0{1,}(?!\.))//g' | grep -v -P '^10\.|^172\.((1[6-9])|(2[0-9])|(3[0|1]))\.|^192\.168\.'


## 
curl -s http://isc.sans.org/ipsascii.html|grep -v '#'|awk '{print $1}'|perl -pi -e 's/(?:^0{1,})|(?:(?<=\.)0{1,}(?!\.))//g'|egrep -v '^192\.|^10\.|^172\.|^224\.'


## 
curl -s http://checkip.dyndns.org | sed 's/[a-zA-Z<>/ :]//g'



## Get http headers for an url
curl -I www.commandlinefu.com		


## Run a command, store the output in a pastebin on the internet and place the URL on the xclipboard
ls | curl -F 'sprunge=<-' http://sprunge.us | xclip		


## Quickly share code or text from vim to others.
:w !curl -F "sprunge=<-" http://sprunge.us | xclip		


curl dict://dict.org/d:$example


dict() { curl dict://dict.org/d:$1; }


dict() { curl -s dict://dict.org/d:$1 | perl -ne 's/\r//; last if /^\.$/; print if /^151/../^250/'; }


## Get your public ip using dyndns
curl -s http://checkip.dyndns.org/ | grep -o "[[:digit:].]\+"		



## Check your unread Gmail from the command line
curl -u username:password --silent "https://mail.google.com/mail/feed/atom" | tr -d '\n' | awk -F '<entry>' '{for (i=2; i<=NF; i++) {print $i}}' | sed -n "s/<title>\(.*\)<\/title.*name>\(.*\)<\/name>.*/\2 - \1/p"


curl -u username:password --silent "https://mail.google.com/mail/feed/atom" | tr -d '\n' | awk -F '<entry>' '{for (i=2; i<=NF; i++) {print $i}}' | perl -pe 's/^<title>(.*)<\/title>.*?<name>(.*?)<\/name>.*$/$2 - $1/'
curl -u username:password --silent "https://mail.google.com/mail/feed/atom" | tr -d '\n' | awk -F '<entry>' '{for (i=2; i<=NF; i++) {print $i}}' | perl -pe 's/^<title>(.*)<\/title>.*<name>(.*)<\/name>.*$/$2 - $1/'



curl -u username --silent "https://mail.google.com/mail/feed/atom" | awk 'BEGIN{FS="\n";RS="(</entry>\n)?<entry>"}NR!=1{print "\033[1;31m"$9"\033[0;32m ("$10")\033[0m:\t\033[1;33m"$2"\033[0m"}' | sed -e 's,<[^>]*>,,g' | column -t -s $'\t'


curl -u user:pass -d status="Tweeting from the shell" http://twitter.com/statuses/update.xml


i="8uyxVmdaJ-w";mplayer -fs $(curl -s "http://www.youtube.com/get_video_info?&video_id=$i" | echo -e $(sed 's/%/\\x/g;s/.*\(v[0-9]\.lscache.*\)/http:\/\/\1/g') | grep -oP '^[^|,]*')
id="dMH0bHeiRNg";mplayer -fs http://youtube.com/get_video.php?video_id=$id\&t=$(curl -s http://www.youtube.com/watch?v=$id | sed -n 's/.*, "t": "\([^"]*\)", .*/\1/p')



cmdfu(){ curl "http://www.commandlinefu.com/commands/matching/$@/$(echo -n $@ | openssl base64)/plaintext"; }


## Gets a random Futurama quote from /.
curl -Is slashdot.org | egrep '^X-(F|B|L)' | cut -d \- -f 2


## How fast is the connexion to a URL, some stats from curl
URL="http://www.google.com";curl -L --w "$URL\nDNS %{time_namelookup}s conn %{time_connect}s time %{time_total}s\nSpeed %{speed_download}bps Size %{size_download}bytes\n" -o/dev/null -s $URL


## Send email with curl and gmail
curl -n --ssl-reqd --mail-from "<user@gmail.com>" --mail-rcpt "<user@server.tld>" --url smtps://smtp.gmail.com:465 -T file.txt



## Useful to advise when a wget 
## download or a simulation ends. Example:
wget URL && notify-send "Done" || notify-send "Failed"


## Fetch the current human population of Earth
curl -s http://www.census.gov/popclock/data/population/world | python -c 'import json,sys;obj=json.load(sys.stdin);print obj["world"]["population"]'

check(){ curl -sI $1 | sed -n 's/Location: *//p';}



## Execute a command, convert output to .png file, upload file to imgur.com, then returning the address of the .png.
imgur(){ $*|convert label:@- png:-|curl -F "image=@-" -F "key=1913b4ac473c692372d108209958fd15" http://api.imgur.com/2/upload.xml|grep -Eo "<original>(.)*</original>" | grep -Eo "http://i.imgur.com/[^<]*";}


## Send an http HEAD request w/curl
curl -I http://localhost



## ---------------------------------------------------------------------------------------------------------- ##


ssh-reverse-socks5-proxy.sh
$ ssh -R 1080 host
$ curl -k --socks5 localhost https://not-reachable-from-host
$ HTTP_PROXY=socks5://localhost:1080 ./someotherbinary https://not-reachable-from-host




## Get the definition of curl from a dictionary:
curl dict://dict.org/m:curl


## Display the size of a file downloaded
curl -w 'We downloaded %{size_download} bytes\n' www.download.com

## use SSL for FTP transfers:
curl --ftp-ssl ftp://files.are.secure.com/secrets.txt


## Get a file from an SSH server using SFTP:
curl -u username sftp://shell.example.com/etc/issue			




## Get a file from an SSH server using
## SCP using a private key to authenticate:
curl -u username: --key ~/.ssh/id_dsa --pubkey ~/.ssh/id_dsa.pub scp://shell.example.com/~/personal.txt									


## Get the main page from an IPv6 web server:
curl -g "http://[2001:1890:1112:1::20]/"					



## For ftp files using name+passwd, include them in the URL like:
curl ftp://name:passwd@machine.domain:port/full/path/to/file


## or specify them with the -u flag like
curl -u name:passwd ftp://machine.domain:port/full/path/to/file


## Like So:
curl http://name:passwd@machine.domain/full/path/to/file


## Upload data from a specified file, login with user and password:
curl -T uploadfile -u user:passwd ftp://ftp.upload.com/myfile


## Store the HTTP headers in a separate file (headers.txt in the example):
curl --dump-header headers.txt curl.haxx.se


## Send multiple files in a single "field" with a single field name:
curl -F "pictures=@dog.gif,cat.gif"


## Dump a Webpages Headers:
curl --dump-header headers www.example.com


## Get a list of a directory of an FTP site:
curl ftp://cool.haxx.se/


## Get the definition of curl from a dictionary:
curl dict://dict.org/m:curl



urls=('www.ubuntu.com' 'google.com'); for i in ${urls[@]}; do http_code=$(curl -I -s $i -w %{http_code}); echo $i status: ${http_code:9:3}; done


# resume download using curl
curl -C - -o partially_downloaded_file 'www.example.com/path/to/the/file'



curl -s "http://www.gravatar.com/avatar/`uuidgen | md5sum | awk '{print $1}'`?s=64&d=identicon&r=PG" | display


qrurl() { curl "http://chart.apis.google.com/chart?chs=150x150&cht=qr&chld=H%7C0&chl=$1" -o qr.$(date +%Y%m%d%H%M%S).png; }



albumart(){ local y="$@";awk '/View larger image/{gsub(/^.*largeImagePopup\(.|., .*$/,"");print;exit}' <(curl -s 'http://www.albumart.org/index.php?srchkey='${y// /+}'&itempage=1&newsearch=1&searchindex=Music');}




curl http://example.com/foo.tar.gz | tar zxvf -


# Check if your webserver supports gzip compression with curl
curl -I -H "Accept-Encoding: gzip,deflate" http://example.org


eog `curl -s http://xkcd.com/ | sed -n 's/<h3>Image URL.*: \(.*\)<\/h3>/\1/p'`
curl -sL xkcd.com | grep '<img [^>]*/><br/>' | sed -r 's|<img src="(.*)" title="(.*)" alt="(.*)" /><br/>|\1\t\2\t\3|' > /tmp/a; curl -s $(cat /tmp/a | cut -f1) | convert - -gravity south -draw "text 0,0 \"$(cat /tmp/a | cut -f2)\"" pdf:- > xkcd.pdf




curl http://www.phrack.org/archives/tgz/phrack[1-67].tar.gz -o phrack#1.tar.gz




curl -A Mozilla http://www.google.com/search?q=test |html2text -width 80




curl -n -d status='Hello from cli' https://twitter.com/statuses/update.xml

curl -s search.twitter.com | awk -F'</?[^>]+>' '/\/intra\/trend\//{print $2}'
tweet () { curl -u UserName -d status="$*" http://twitter.com/statuses/update.xml; }

curl -u <user>:<password> -d status="Amarok, now playing: $(dcop amarok default nowPlaying)" http://twitter.com/statuses/update.json

# Update twitter via curl (and also set the "from" bit)
curl -u twitter-username -d status="Hello World, Twitter!" -d source="cURL" http://twitter.com/statuses/update.xml



curl 'LINK' | pdftotext - - | less





u=`curl -d 'dl.start=Free' $(curl $1|perl -wpi -e 's/^.*"(http:\/\/rs.*)" method.*$/$1/'|egrep '^http'|head -n1)|grep "Level(3) \#2"|perl -wpi -e 's/^.*(http:\/\/rs[^\\\\]*).*$/$1/'`;sleep 60;wget $u

pyt() { id=$(curl -s 'https://www.youtube.com/results?search_query='$(tr \  + <<<"$1") | grep -om3 '"[[:alnum:]]\{11\}"' | awk NR==3 | tr -d \"); youtube-dl -q 'https://www.youtube.com/watch?v='"$id" -o - | mplayer -vo null /dev/fd/3 3<&0 </dev/tty; }


qrurl() { curl -sS "http://chart.apis.google.com/chart?chs=200x200&cht=qr&chld=H|0&chl=$1" -o - | display -filter point -resize 600x600 png:-; }



curl --user "USERNAME:PASSWORD" -d status="MESSAGE_GOES_HERE $(curl -s tinyurl.com/api-create.php?url=URL_GOES_HERE) $(curl -s api.hostip.info/get_html.php?ip=$(curl ip.appspot.com))" -d source="cURL" twitter.com/statuses/update.json -o /dev/null



imgur(){ $*|convert label:@- png:-|curl -F "image=@-" -F "key=1913b4ac473c692372d108209958fd15" http://api.imgur.com/2/upload.xml|grep -Eo "<original>(.)*</original>" | grep -Eo "http://i.imgur.com/[^<]*";}


Q="YOURSEARCH"; GOOG_URL="http://www.google.com/search?q="; AGENT="Mozilla/4.0"; stream=$(curl -A "$AGENT" -skLm 10 "${GOOG_URL}\"${Q/\ /+}\"" | grep -oP '\/url\?q=.+?&amp' | sed 's/\/url?q=//;s/&amp//'); echo -e "${stream//\%/\x}"






##-================================================-##
## [+] $1 == Accept header
## [+] $2 == Content Type header
## [+] $3 == Auth Cookie header
## [+] $4 == post data
## [+] $5 == proxy (http://127.0.0.1:8080)
## [+] $6 == target url
##-================================================-##

echo "##-============================================================================-##"
echo "    [!] Please provide Accept header, content-type, authorization cookie,         "
echo "        post data, proxy server and target url.                                   "
echo "##-============================================================================-##"
curl -X POST --header "$1" --header "$2" --header 'Accept-Language: en' --header "$3" -d "$4" -x "$5" --insecure --include "$6"

curl -X POST --header "$1" --header "$2" --header 'Accept-Language: en' --header "$3" -d "$4" -x "$5" --insecure --include "$6"




##-================================================-##
## [+] $1 == Accept header
## [+] $2 == Content Type header
## [+] $3 == Auth Cookie header
## [+] $4 == put data
## [+] $5 == proxy (http://127.0.0.1:8080)
## [+] $6 == target url
##-================================================-##

echo "##-============================================================================-##"
echo "    [!] Please provide Accept header, content-type, authorization cookie, "
echo "        put data, proxy server and target url."
echo "##-============================================================================-##"
curl -X PUT --header "$1" --header "$2" --header 'Accept-Language: en' --header "$3" -d "$4" -x "$5" --insecure --include "$6"





## Basic Authentication
curl -u "username" https://api.github.com


## OAuth2 Token (sent in a header)
curl -H "Authorization: token OAUTH-TOKEN" https://api.github.com


## OAuth2 Token (sent as a parameter)
curl https://api.github.com/?access_token=OAUTH-TOKEN


## OAuth2 Key/Secret
curl 'https://api.github.com/users/whatever?client_id=xxxx&client_secret=yyyy'




##-================================================-##
## [+] $1 == Accept header
## [+] $3 == Auth Cookie header
## [+] $5 == proxy (http://127.0.0.1:8080)
## [+] $6 == target url
##-================================================-##

echo "##-============================================================-##"
echo "    [!] Please provide Accept header, authorization cookie,       "
echo "        proxy server and target url.                              "
echo "##-============================================================-##"

curl -X GET --header "$1" --header 'Accept-Language: en' --header "$2" -x "$3" --insecure --include "$4"



echo "##-============================================================-##"
echo "    [!] "
echo "                                    "
echo "##-============================================================-##"








##-================================================-##
## [+] $5 == proxy (http://127.0.0.1:8080)
## [+] $6 == target url
##-================================================-##


echo "##-===================================================-##"
echo "    [!] Please provide proxy server and target url"
echo "##-===================================================-##"
curl -i -I -X OPTIONS -x "$1" --insecure "$2"





  
  



## Download the certificate for this server:
HOST=blog.patternsinthevoid.net && PORT=443
openssl s_client -connect "${HOST}":"${PORT}" </dev/null 2>/dev/null | \
    sed -nr '/(-){5}(BEGIN CERTIFICATE){1}(-){5}/,/(-){5}(END CERTIFICATE){1}(-){5}/p' | \
    cat > ${HOME}/${HOST}.pem



## Check the SSL certificate fingerprint (it should match the ones given in this file):
cat ${HOME}/${HOST}.pem | openssl x509 -fingerprint -noout -in /dev/stdin


## dump the certificate information
echo | openssl s_client -connect www.google.com:443 2>/dev/null | openssl x509 -noout -dates


## pull off just the "notAfter" date from my output:
echo | openssl s_client -connect www.google.com:443 2>/dev/null | openssl x509 -noout -dates | tail -1 | cut -f2 -d=


## convert a time stamp string like this into a "Unix epoch" date with the GNU date command:
date +%s -d 'Sep 2 00:00:00 2014 GMT'


date +%s -d "$(echo | openssl s_client -connect www.google.com:443 2>/dev/null | openssl x509 -noout -dates | tail -1 | cut -f2 -d=)"



[[ $(( $(date +%s -d "$(echo | openssl s_client -connect www.google.com:443 2>/dev/null | openssl x509 -noout -dates | tail -1 | cut -f2 -d=)") - $(date +%s) )) -gt 3628800 ]] && echo GOOD || echo EXPIRING



openssl s_client -connect www.google.com:443 2>/dev/null | openssl x509 -noout -dates


echo | openssl s_client -connect www.$d:443 2>/dev/null | openssl x509 -noout -dates | tail -1 | cut -f2 -d=)


echo | openssl s_client -connect www.google.com:443 2>/dev/null | openssl x509 -noout -issuer -subject -fingerprint -dates


echo | openssl s_client -connect www.google.com:443 2>/dev/null | openssl x509 -text




##-================================================-## 
##      [+] Bulk Download Files By Their URLs 
##-================================================-## 
## ---------------------------------------------------------------- ## 
##  [?] The URL Links Are Fed To Curl From xarg 
## ---------------------------------------------------------------- ## 
xargs -n 1 curl -O < $URLFile 






See where a shortened url takes you before click
check(){ curl -sI $1 | sed -n 's/Location: *//p';}
curl -sI https://bit.ly/3n4epen | sed -n 's/location: *//p'


##  Curl – Follow Redirect
curl -Iks --location -X GET -A "x-agent" $1




verify torified connectivity
curl https://check.torproject.org


With SOCKS5 proxy running locally

curl ifconfig.co --socks5-host 10.64.0.1
193.138.219.60

With SOCK5 proxy running on another server

curl ifconfig.co --socks5-host nl1-wg.socks5.mullvad.net
185.65.134.190



echo "Usage: $NAME domain.tld origin.ip" 1>&2
  echo "Returns the response headers and a diff of a domain vs. its origin ip. Requires SSL." 1>&2

  echo "Returns the response headers and a diff of a domain vs. its origin ip. Requires SSL." 1>&2

COMMAND="diff <(curl -Isk https://$1) <(curl -Isk -H 'Host: $1' https://$2)"

echo "Comparing '$1' to '$2'..."










CLUSTER=$(curl -X GET -u "$USERNAME:$USERPASS" -i $BASE/clusters | grep '"name"' | awk -F'"' '{print $4}')
nodes=$(curl -X GET -u "$USERNAME:$USERPASS" -i $BASE/hosts | grep hostname | awk -F'"' '{print $4}')
curl -s -u "$USERNAME:$USERPASS" $BASE/cm/service/commands | grep id > /dev/null
    curl -s -u "$USERNAME:$USERPASS" $BASE/clusters/$CLUSTER/commands | grep id > /dev/null

curl -s -X PUT -H 'Content-type:application/json' \
	-d '{"items":[{"name":"enableSecurity","value":"true"}]}' \
	-u "$USERNAME:$USERPASS" \
	$BASE/clusters/$CLUSTER/services/$1/config


    curl -s -X PUT -H 'Content-type:application/json' \
	-d '{"items":[{"name":"dfs_datanode_http_port","value":"1006"}, 
      {"name":"dfs_datanode_port","value":"1004"}, 
      {"name":"dfs_datanode_data_dir_perm","value":"700"}]}' \
	-u "$USERNAME:$USERPASS" \
	$BASE/clusters/$CLUSTER/services/$1/roleConfigGroups/$1-DATANODE-BASE/config
}

mr(){
    [ -n "mr1" ]; curl -s -X PUT -H 'Content-type:application/json' \
	-d '{"items":[{"name":"taskcontroller_min_user_id","value":"0"}]}' \
	-u "$USERNAME:$USERPASS" \
	$BASE/clusters/$CLUSTER/services/$1/roleConfigGroups/$1-TASKTRACKER-BASE/config

    [ -n "yarn" ]; curl -s -X PUT -H 'Content-type:application/json' \
	-d '{"items":[{"name":"container_executor_min_user_id","value":"0"}]}' \
	-u "$USERNAME:$USERPASS" \
	$BASE/clusters/$CLUSTER/services/$1/roleConfigGroups/$1-NODEMANAGER-BASE/config
}

hbase(){
    [ -n "hbase" ]; curl -s -X PUT -H 'Content-type:application/json' \
	-d '{"items":[{"name":"hbase_security_authentication","value":"kerberos"},
      {"name":"hbase_security_authorization","value":"true"}]}' \
	-u "$USERNAME:$USERPASS" \
	$BASE/clusters/$CLUSTER/services/$1/config
}

# Kerberos
krb(){
    curl -X PUT -u "$USERNAME:$USERPASS" -H "content-type:application/json" \
	-d '{ "items": [{"name": "KDC_HOST", "value": "'$CMNODE'"}, 
                  {"name": "KDC_TYPE", "value": "MIT KDC"}, 
                  {"name": "KRB_MANAGE_KRB5_CONF", "value": "true"},
                  {"name": "SECURITY_REALM", "value": "HADOOP"}]}' \
	$BASE/cm/config

  cm_wait
}

# Admin User
other(){
    curl -X POST -u "$USERNAME:$USERPASS" -i \
	-G --data-urlencode 'username=cloudera-scm/admin@HADOOP' \
        --data-urlencode 'password=cloudera' \
	$BASE/cm/commands/importAdminCredentials
  cm_wait
}



# Deploy Client Config
curl -X POST -u "$USERNAME:$USERPASS" -i $BASE/clusters/$CLUSTER/commands/deployClientConfig
cluster_wait


# Restart Cluster
curl -X POST -u "$USERNAME:$USERPASS" -i \
	-H "Content-Type:application/json" \
	-d '{"redeployClientConfiguration": true, "restartOnlyStaleServices": null}' \
$BASE/clusters/$CLUSTER/commands/restart
cluster_wait


echo "##-============================================================-##"
echo "    [!]                               "
echo "                                      "
echo "##-============================================================-##"



echo "##-============================================================-##"
echo "    [!]                               "
echo "                                      "
echo "##-============================================================-##"



echo "##-============================================================-##"
echo "    [!]                               "
echo "                                      "
echo "##-============================================================-##"



echo "##-============================================================-##"
echo "    [!]                               "
echo "                                      "
echo "##-============================================================-##"

# Overcome cookie & csrf-token
## First save cookie to file, and csrf-token to env
export CSRF_TOKEN=$(curl -ks me.pc:3000 --cookie-jar cookie | grep "csrf-token" | sed -e 's/.*content="//g' -e 's/".*//g')
## Then post using above (via local proxy in this example)
curl -XPOST -H 'Content-Type: application/json' -d '{"email": "foo@mail.com", "password": "passwd"}' -H "X-CSRF-Token: ${CSRF_TOKEN}" -b cookie -x http://localhost:9080 http://me.pc:3000/api/login

echo "##-============================================================-##"
echo "    [!] provide a target host"
echo "                                    "
echo "##-============================================================-##"
curl -I -i -X HEAD --insecure "$1"


echo "##-============================================================-##"
echo "    [!] provide the target $host and $port"
echo "##-============================================================-##"
echo -e 'HEAD / HTTP/1.0\r\n\r\n' | nc $1 $2



echo "##-========================================-##"
echo "    [!] provide The target host"
echo "##-========================================-##"
curl -i -I -X TRACE --insecure "$1"



echo "##-============================================================-##"
echo "    [!] Please provide the Following:                             "
echo "        -->                                      "
echo "        -->                                      "
echo "        -->                                      "
echo "##-============================================================-##"


echo "##-============================================================-##"
echo "    [!] Please provide the Following:                             "
echo "        -->                                      "
echo "        -->                                      "
echo "        -->                                      "
echo "##-============================================================-##"


echo "##-============================================================-##"
echo "    [!] Please provide the Following:                             "
echo "        -->                                      "
echo "        -->                                      "
echo "        -->                                      "
echo "##-============================================================-##"



echo "##-============================================================-##"
echo "    [!] Please provide the Following:                             "
echo "        -->                                      "
echo "        -->                                      "
echo "        -->                                      "
echo "##-============================================================-##"





echo "##-============================================================-##"
echo "    [!] Please provide the Following:                             "
echo "        -->                                      "
echo "        -->                                      "
echo "        -->                                      "
echo "##-============================================================-##"

