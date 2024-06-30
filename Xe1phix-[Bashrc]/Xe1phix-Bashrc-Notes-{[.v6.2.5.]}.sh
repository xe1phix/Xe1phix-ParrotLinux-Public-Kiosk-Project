chrome_pid=$(ps -aux | grep "[c]hrome --user-data" | awk '{ print $2 }' | head -n 1 2>/dev/null)


# nsenter the chrome runc container
nsenter -t "$chrome_pid" --pid --user --net --uts --mount --ipc /usr/bin/google-chrome --user-data-dir=/data "$@" 2>/dev/null


alias chromekill="ps ux | grep '[C]hrome Helper --type=renderer' | grep -v extension-process | tr -s ' ' | cut -d ' ' -f2 | xargs kill"




alias pubip="dig +short myip.opendns.com @resolver1.opendns.com"


# Flush Directory Service cache
alias flush="dscacheutil -flushcache && killall -HUP mDNSResponder"


# View HTTP traffic
alias sniff="sudo ngrep -d 'en1' -t '^(GET|POST) ' 'tcp and port 80'"
alias httpdump="sudo tcpdump -i en1 -n -s 0 -w - | grep -a -o -E \"Host\: .*|GET \/.*\""


# copy working directory
alias cwd='pwd | tr -d "\r\n" | xclip -selection clipboard'



# Pipe my public key to my clipboard.
alias pubkey="more ~/.ssh/id_rsa.pub | xclip -selection clipboard | echo '=> Public key copied to pasteboard.'"

# Pipe my private key to my clipboard.
alias prikey="more ~/.ssh/id_rsa | xclip -selection clipboard | echo '=> Private key copied to pasteboard.'"








ssh-keygen -t rsa -b 4096 -C "This is a test key"


# Create a tunnel from your local 9091 port to the remote machine's 9090 port
ssh -L 9091:127.0.0.1:9090 <username>@<remote-ip-address> -N



SSH into a box and "look back at yourself"
ssh <some user>:<some machine> 'echo $SSH_CONNECTION | cut -d" " -f1'






dig +short myip.opendns.com @resolver1.opendns.com




ifconfig | grep -w inet | grep -v 127.0.0.1 | awk '{print $2}'
ifconfig | grep -w inet6 | grep -v ::1 | awk '{print $2}'

ip addr show | grep -w inet | grep -v 127.0.0.1 | awk '{print $2}' | cut -d"/" -f1
ip addr show | grep -w inet6 | grep -v ::1 | awk '{print $2}' | cut -d"/" -f1


What's my MAC address?

ifconfig | grep -w ether | awk '{print $2}'
ip addr show | grep -w ether | awk '{print $2}'

What's my network device name?

ip addr show | grep -w inet | grep -v 127.0.0.1 | awk '{print $NF}'


Watch port 22 and show "ESTABLISHED" connections who aren't localhost

sudo watch -n10 "netstat -ntu | grep :22| grep ESTAB | awk '{print \$5}' | cut -d: -f1 | grep -v 127.0.0.1 | sort"

Show number of connections to port 443 (webserver)

netstat -ntu | grep :443 | grep -v LISTEN | awk '{print $5}' | cut -d: -f1 | grep -v 127.0.0.1 | wc -l




echo "Killing proccess..."
 	kill -9 $(ps x | grep "openvpn" | head -1 | awk {'printf $1'}) &> /dev/null







curl -s --data-urlencode "text=$default_message" "https://api.telegram.org/bot$token/sendMessage?chat_id=$chatid"
curl -s --data-urlencode "text=$@" "https://api.telegram.org/bot$token/sendMessage?chat_id=$chatid"


curl --tlsv1.2 -v -k 
openssl s_client -tls1_2 -connect 
 -servername 


curl -F “url=https://<YOURDOMAIN.EXAMPLE>/<WEBHOOKLOCATION>" https://api.telegram.org/bot<YOURTOKEN>/setWebhook


curl example for a self-signed certificate:
curl -F "url=https://<YOURDOMAIN.EXAMPLE>/<WEBHOOKLOCATION>" -F "certificate=@<YOURCERTIFICATE>.pem" https://api.telegram.org/bot<YOURTOKEN>/setWebhook


curl --tlsv1.2 -v -k https://yourbotdomain:yourbotport/


curl -s -X POST https://api.telegram.org/bot172375318:AAGmeHbDlUxNeeuNEbXuq4fEulglo8hv-_A/sendMessage -d text="$HOSTNAME$ $HOSTSTATE$ $HOSTADDRESS$ $HOSTOUTPUT$ $LONGDATETIME$" -d chat_id=-99524960

/usr/bin/wget -qO - https://api.telegram.org/bot$API_TOKEN/getUpdates
/usr/bin/wget -q --spider "https://api.telegram.org/bot$API_TOKEN/sendMessage?chat_id=$CHAT_ID&parse_mode=html&text=$MSG" 2>&1

curl -m 600 --socks5 127.0.0.1:9050 -k -i -X GET https://api.telegram.org/bot$API_TOKEN/getUpdates
curl -m 600 --socks5 127.0.0.1:9050 -k -s -X POST "https://api.telegram.org/bot$API_TOKEN/sendMessage?chat_id=$CHAT_ID&parse_mode=html&text=$MSG" 2>&1

### route rublock 
iptables -A OUTPUT -t mangle -m set --match-set rublock dst,src -j MARK --set-mark 1
iptables -t nat -A POSTROUTING -m mark --mark 1 -s $(nvram get wan0_ipaddr) -o tun0 -j MASQUERADE

curl -m 600 --socks5 127.0.0.1:1080 -k -i -X GET https://api.telegram.org/bot$API_TOKEN/getUpdates
curl -m 600 --socks5 127.0.0.1:1080 -k -s -X POST "https://api.telegram.org/bot$API_TOKEN/sendMessage?chat_id=$CHAT_ID&parse_mode=html&text=$MSG" 2>&1


curl -X POST "https://api.telegram.org/bot[TOKEN_DEL_BOT]/sendMessage" -d "chat_id=@[Nome_del_canale]&text= Testo da inviare seguito, se volete da URL http://www.miosito.it/Pratica_1453710103829/"












cat photobucket.txt | xargs -I url basename url | while read file; do grep "${file}$" photobucket.txt; done | while read file; do curl -O --referer "http://s.photobucket.com/" ${file}; echo ${file}; done

cut -d/ -f 7 photobucket_files.txt | grep -v "." | sort -u | while read dir; do mkdir ${dir}; cd ${dir}; grep "/${dir}/" ../photobucket_files.txt | while read file; do curl -O --referer "http://s.photobucket.com/" ${file%$'\r'}; done; cd -; done


cat photobucket_files.txt | xargs wget --referer 'http://s.photobucket.com/' --wait=1 --random-wait --input-file=-


cat pb.txt | while read file; do curl -O --referer "https://i240.photobucket.com/" ${file}; done








https://t.me/get_id_bot
/setprivacy





TOKEN="<bot token>"
CHAT_ID="<chat ID>"
URL="https://api.telegram.org/bot$TOKEN/sendMessage"

curl -s -X POST $URL -d chat_id=$CHAT_ID -d text="$MESSAGE" -d parse_mode=html










sudo iptables –A INPUT –p tcp –m tcp –dport portnumber -j ACCEPT
sudo iptables –A INPUT –i interfacename –p tcp –m tcp –dport portnumber -j ACCEPT
sudo iptables –A INPUT –i interfacename –p tcp –m iprange –src-range 149.154.167.197-149.154.167.233 –dport portnumber -j ACCEPT

sudo ufw allow in on interfacename to any port portnumber proto tcp from 149.154.167.192/26





Forcing TLS in your virtual host on Apache:
SSLProtocol -all +TLSv1.2
Forcing TLS in your virtual host on Nginx:
ssl_protocols TLSv1.2;



openssl req -newkey rsa:2048 -keyout yourprivatekey.key -out yoursigningrequest.csr



keytool:
keytool -genkey -alias yourbotdomainname -keyalg RSA -keystore yourkeystore.jks -keysize 2048


generates the initial keystore, from which you can then create a CSR like this:

keytool -certreq -alias yourbotdomainname -keystore yourkeystore.jks -file yourbotdomainname.csr






    Using OpenSSL
    openssl req -text -noout -verify -in yoursigningrequest.csr

    Using Java keytool
    keytool -printcertreq -v -file yourbotdomainname.csr


Using OpenSSL:
openssl x509 -in yourdomain.crt -text -noout

Using Java keytool:
keytool -printcert -v -yourdomain.crt





generate some certificates:

    Using OpenSSL:
    openssl req -newkey rsa:2048 -sha256 -nodes -keyout YOURPRIVATE.key -x509 -days 365 -out YOURPUBLIC.pem -subj "/C=US/ST=New York/L=Brooklyn/O=Example Brooklyn Company/CN=YOURDOMAIN.EXAMPLE"






keytool:
keytool -genkey -keyalg RSA -alias YOURDOMAIN.EXAMPLE -keystore YOURJKS.jks -storepass YOURPASSWORD -validity 360 -keysize 2048

What is your first and last name?
[test.telegram.org]:
What is the name of your organizational unit?
[Unknown]:  
What is the name of your organization?
[Unknown]:  
What is the name of your City or Locality?
[Unknown]:  
What is the name of your State or Province?
[Unknown]:  
What is the two-letter country code for this unit?
[Unknown]:  
Is CN=test.telegram.org, OU=Unknown, O=Unknown, L=Unknown, ST=Unknown, C=Unknown correct?
[no]: yes



Convert the JKS to pkcs12 (intermediate step for conversion to PEM):
keytool -importkeystore -srckeystore YOURJKS.jks -destkeystore YOURPKCS.p12 -srcstoretype jks -deststoretype pkcs12

Convert PKCS12 to PEM (requires OpenSSL)
openssl pkcs12 -in YOURPKCS.p12 -out YOURPEM.pem -nokeys







convert a DER formatted root certificate to PEM:

    Using OpenSSL:
    openssl x509 -inform der -in root.cer -out root.pem

    Using Java keytool:
    keytool -import -alias Root -keystore YOURKEYSTORE.JKS -trustcacerts -file ROOTCERT.CER
    The root certificate needs to be imported in your keystore first:
    keytool -exportcert -alias Root -file <YOURROOTPEMFILE.PEM> -rfc -keystore YOURKEYSTORE.JKS








openssl req -config req.conf -newkey rsa:2048 -nodes -keyout subdomain.example.com.pem -sha256 -out subdomain.example.com.csr




Verification

    openssl s_client -connect subdomain.example.com:443 -servername subdomain.example.com -CApath /etc/ssl/certs < /dev/null



https://www.ssllabs.com/ssltest/analyze.html



















losetup -r /dev/loop0 disk.img

kpartx -rav disk.img


VBoxManage internalcommands createrawvmdk -filename "</path/to/file>.vmdk" -rawdisk /dev/loopX




losetup -d /dev/loop0
kpartx -rav disk.img























