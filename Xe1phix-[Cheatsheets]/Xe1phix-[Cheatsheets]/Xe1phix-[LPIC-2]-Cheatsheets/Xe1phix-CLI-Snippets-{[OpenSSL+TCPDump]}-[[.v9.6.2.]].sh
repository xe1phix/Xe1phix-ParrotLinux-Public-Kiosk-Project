#!/bin/sh
##-===========================================================-##
##  [+] Xe1phix-CLI-Snippets-(OpenSSL+TCPDump+Etc)-v5.2.sh
##-===========================================================-##




##-==============================================-##
##  [+] connect to HTTPS Server With OpenSSL:
##-==============================================-##
openssl s_client -connect twitter.com:443



Retrieve an SSL Certificate from a Server With OpenSSL

openssl s_client -showcerts -servername $Domain -connect $Domain:443 < /dev/null






##-==========================-##
##  [+] Generate RSA keys
##-==========================-##
openssl genrsa -out rsa.pem 1024
openssl rsa -in rsa.pem -pubout -outform pem -out rsa-pub.out



##-=============================================-##
##  [+] Connect To HTTP Port 80 Using Netcat;
##-=============================================-##
nc twitter.com 80






##-=========================-##
##  [+] Generate RSA keys
##-=========================-##
openssl genrsa -out $RSA.pem 1024
openssl rsa -in $RSA.pem -pubout -outform pem -out $RSAPubKey.out




From Openssl to Coherence priv key

    openssl pkcs8 -nocrypt -in rsa.pem -inform PEM -topk8 -outform DER -out rsa.der
    cat rsa.der | xxd -ps | paste -s -d '' > rsa.der.hex

From Openssl to Coherence pub key

    openssl rsa -in rsa.pem -pubout -outform DER -out rsa-pub.der
    cat rsa-pub.der | xxd -ps | paste -s -d '' > rsa-pub.der.hex

From Coherence to Openssl priv key

    cat crsa.der.hex | xxd -r -p - > crsa.der
    openssl rsa -inform der -outform pem -in crsa.der -out crsa.pem

From Coherence to Openssl pub key

    cat crsa-pub.der.hex | xxd -r -p - > crsa-pub.der
    openssl rsa -inform der -outform pem -pubin -in crsa-pub.der -out crsa-pub.pem



##-=========================-##
##  [+] Generate DSA keys
##-=========================-##
openssl dsaparam -out $DSAParameter.pem 1024
openssl gendsa -out $DSA.pem $DSAParameter.pem
openssl dsa -in $DSA.pem -pubout -outform PEM -out $DSAPub.pem



From Openssl to Coherence priv key

    openssl pkcs8 -nocrypt -in dsa.pem -inform PEM -topk8 -outform DER -out dsa.der
    cat dsa.der | xxd -ps | paste -s -d '' > dsa.der.hex

From Openssl to Coherence pub key

    openssl dsa -in dsa.pem -pubout -outform DER -out dsa-pub.der
    cat dsa-pub.der | xxd -ps | paste -s -d '' > dsa-pub.der.hex

From Coherence to Openssl priv key

    cat cdsa.der.hex | xxd -r -p - > cdsa.der
    openssl dsa -inform der -outform pem -in cdsa.der -out cdsa.pem

From Coherence to Openssl pub key

    cat cdsa-pub.der.hex | xxd -r -p - > cdsa-pub.der
    openssl dsa -inform der -outform pem -pubin -in cdsa-pub.der -out cdsa-pub.pem








##-=======================-##
##  [+] Generate a key
##-=======================-##
openssl genrsa -out ~/[domain].ssl/[FQDN].key 4096



##-====================================================-##
##  [+] Generate a Certificate Signing Request (CSR)
##-====================================================-##
openssl req -new -sha256 -key ~/[domain].ssl/[FQDN].key -out ~/[domain].ssl/[FQDN].csr



##-========================-##
##  [+] Verify your CSR
##-========================-##
openssl req -noout -text -in ~/[domain].ssl/[FQDN].csr




##-================================================-##
##  [+] Generate self-signed certificate [SHA256]
##-================================================-##
openssl req -newkey rsa:2048 -SHA256 -new -nodes -x509 -days 3650 -keyout key.pem -out cert-sha256.pem




##-=======================================-##
##  [+] Connect To $Site Using OpenSSL:
##-=======================================-##
openssl s_client -connect $Domain:443



##-==========================-##
##  [+] Check certificate
##-==========================-##
openssl x509 -in $Certificate.crt -text -noout





##-=========================================-##
##  [+] OpenSSL check p12 expiration time
##-=========================================-##

## ------------------------------------------------------------------- ##
##  [?] extract the certificate from the .p12 file to a .pem file:
## ------------------------------------------------------------------- ##
openssl pkcs12 -in $Certificate.p12 -out $Certificate.pem -nodes

## -------------------------------------------------------------------------- ##
##  [?] extract the expiration date from the certificate in the .pem file:
## -------------------------------------------------------------------------- ##
cat $Certificate.pem | openssl x509 -noout -enddate






NICKNAME=$( openssl x509 -in "${REQUIRED_CA}" -noout -subject | sed 's/^.*\(CN\|OU\)=//' )
certutil -A -n "${NICKNAME}" -t CT,c,c -a -d "${FF_HOME}" 0<"${REQUIRED_CA}"
cat "${REQUIRED_CA}" | certutil -A -n "${NICKNAME}" -t CT,c,C -a -d "${FF_HOME}"
ISSUER=$( certutil -L -n "${CERT8_CAs[${FINGERPRINT}]}" -a -d "${OLD_FF_HOME}" | openssl x509 -noout -issuer_hash )
NICKNAMES=( $( certutil -L -d "${FF_HOME}" | grep -F -v ",," | sed '1,4d' | gawk 'NF--' ) )
COUNTRY=$( certutil -L -n "${NICKNAME}" -a -d "${FF_HOME}" | openssl x509 -noout -subject | grep -o "C=[A-Z]\+" )
NICKNAMES=( $( certutil -L -d "${FF_HOME}" | sed '1,4d' | grep -F -v ',,' | gawk 'NF--' ) )
FP=$( certutil -L -n "${NICKNAME}" -a -d "${FF_HOME}" | openssl x509 -noout -fingerprint -sha1 | sed 's/^.*Fingerprint=//' )
FPS+=( $( certutil -L -n "${NICKNAME}" -a -d "${FF_HOME}" | openssl x509 -noout -fingerprint -sha1 | sed 's/^.*Fingerprint=//' ) )

NICKNAMES=( $( certutil -L -d "${CERT8}" | sed '1,4d' | gawk 'NF--' ) )
FP=$( certutil -L -n "${NICKNAME}" -a -d "${CERT8}" | openssl x509 -noout -fingerprint -sha1 | sed 's/^.*Fingerprint=//' )
CERT_COUNT=$(( $( certutil -L -d "${FF_HOME}" | wc -l ) - 4 ))
certutil -L -d "${FF_HOME}" | sed 1,4d | grep -v '\(,,\|u,u,u\)'



certutil -L -d "${FF_HOME}"
certutil -L -n "${NICKNAME}" -a -d "${CERT8}"
certutil -L -n "${NICKNAME}" -a -d "${FF_HOME}"
certutil -L -n "${NICKNAME}" -a -d "${FF_HOME}"
certutil -L -n "${CERT8_CAs[${FINGERPRINT}]}" -a -d "${OLD_FF_HOME}"
certutil -A -n "${NICKNAME}" -t CT,c,C -a -d "${FF_HOME}"
certutil -A -n "${NICKNAME}" -t CT,c,c -a -d "${FF_HOME}" 0<"${REQUIRED_CA}"




 | openssl verify -CAfile "${REQUIRED_CA}"
 | openssl x509 -noout -issuer_hash
 | openssl x509 -noout -subject
 | openssl x509 -noout -enddate
 
 | openssl x509 -in "${REQUIRED_CA}" -noout -subject
 | openssl x509 -noout -fingerprint -sha1
 | openssl x509 -noout -fingerprint -sha256

 
 grep -H -m1 'BEGIN PGP SIGNATURE'
 $(find /etc/apt/trusted.gpg* -regex .*gpg$ | sed 's/^/ --keyring /')
 
 
 
 
 | grep -o "C=[A-Z]\+"
 | sed 's/^.*\(CN\|OU\)=//'
 | cut -d'"' -f2
 | gawk 'NF--'
 | sed '1,4d' 
 | sed 's/^.*Fingerprint=//'
 | grep -F -v ",,"
 | wc -l
 | sed 's/^.*\(CN\|OU\)=//'

  | awk '{ print $2 }'
  | cut -d"(" -f1
  
 awk -F':' '{print $1}'
 
 
 find . -name "*.[h|c]"
 
 
echo -n "$3" | base64 $BASE64ARG | wc -c | awk '{printf "size=%d",$1}'

IP=$( ip addr | egrep -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | egrep -v "^192\.168|^172\.1[6-9]\.|^172\.2[0-9]\.|^172\.3[0-2]\.|^10\.|^127\.|^255\.|^0\." | head -n 1 )







ls {*.sh,*.py}                  ## list all .sh and .py files
ls -l [a-z]*   #list all files with alphabet in its filename.


# '*' serves as a "wild card" for filename expansion.
# '?' serves as a single-character "wild card" for filename expansion.

/etc/pa*wd    #/etc/passwd
/b?n/?at      #/bin/cat







https://trac.torproject.org/projects/tor/wiki/doc/TransparentProxy#Checkingforleaks




##-=========================================================-##
##                      [+] Reserved blocks
##-=========================================================-##
## --------------------------------------------------------- ##
##   [?] These addresses shouldnt be routed through Tor:
## --------------------------------------------------------- ##
    0.0.0.0/8
    10.0.0.0/8
    100.64.0.0/10
    127.0.0.0/8
    169.254.0.0/16
    172.16.0.0/12
    192.0.0.0/24
    192.0.2.0/24
    192.168.0.0/16
    192.88.99.0/24
    198.18.0.0/15
    198.51.100.0/24
    203.0.113.0/24
    224.0.0.0/4
    240.0.0.0/4
    255.255.255.255/32 



tor_uid="$(id -u debian-tor)"



curl -s -m 10 --socks5 "$hostport" --socks5-hostname "$hostport" -L "$url" 


curl --proxy "socks5h://localhost:9050" --tlsv1.2 --compressed --user-agent "Mozilla/5.0 (Windows NT 6.1; rv:45.0) Gecko/20100101 Firefox/45.0" -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' -H 'DNT: 1' [urlhere]



wget -U "Mozilla/5.0 (Windows NT 6.1; rv:45.0) Gecko/20100101 Firefox/45.0" [urlhere]









gpg --with-colons --fingerprint "<fingerprint>" | grep "^fpr" | cut -d: -f10









openssl s_client -connect smtp.gmail.com:587 -starttls smtp < /dev/null 2>/dev/null |



openssl x509 -fingerprint -noout -in /dev/stdin | cut -d'=' -f2




openssl s_client -showcerts -starttls smtp -connect smtp_relay:smtp_relay_port < /dev/null 2> /dev/null



sudo -u postfix openssl s_client -showcerts -starttls smtp -connect smtp.gmail.com:587 < /dev/null 2> /dev/null



openssl s_client -CApath /etc/ssl/certs -showcerts -starttls smtp -connect smtp_relay:smtp_relay_port < /dev/null 2> /dev/null











openssl base64 -in input.p12







Connecting using raw public-key authentication

To connect to a server using raw public-key authentication, you need to enable the option to negotiate raw public-keys via the priority strings such as in the example below.

gnutls-cli -p 5556 localhost --priority NORMAL:-CTYPE-CLI-ALL:+CTYPE-CLI-RAWPK \
    --rawpkkeyfile cli.key.pem \
    --rawpkfile cli.rawpk.pem







 connect to a server using PSK authentication

gnutls-cli -p 5556 localhost --pskusername psk_identity \
    --pskkey 88f3824b3e5659f52d00e959bacab954b6540344 \
    --priority NORMAL:-KX-ALL:+ECDHE-PSK:+DHE-PSK:+PSK




Listing ciphersuites in a priority string

gnutls-cli --priority SECURE192 -l




Connecting using a PKCS #11 token


p11tool --list-tokens


p11tool --login --list-certs "pkcs11:model=PKCS15;manufacturer=MyMan;serial=1234;token=Test"


MYCERT="pkcs11:model=PKCS15;manufacturer=MyMan;serial=1234;token=Test;object=client;type=cert"
MYKEY="pkcs11:model=PKCS15;manufacturer=MyMan;serial=1234;token=Test;object=client;type=private"
export MYCERT MYKEY

gnutls-cli www.example.com --x509keyfile $MYKEY --x509certfile $MYCERT









debug services with starttls capability.

gnutls-cli-debug --starttls-proto smtp --port 25 localhost








Print information about an OCSP request

ocsptool -i -Q ocsp-request.der



sent to standard input like this:

cat ocsp-request.der | ocsptool --request-info









DANE TLSA RR generation

To create a DANE TLSA resource record for a certificate (or public key) that was issued localy and may or may not be signed by a CA use the following command.

$ danetool --tlsa-rr --host www.example.com --load-certificate cert.pem

To create a DANE TLSA resource record for a CA signed certificate, which will be marked as such use the following command.

$ danetool --tlsa-rr --host www.example.com --load-certificate cert.pem \
  --no-domain

The former is useful to add in your DNS entry even if your certificate is signed by a CA. That way even users who do not trust your CA will be able to verify your certificate using DANE.

In order to create a record for the CA signer of your certificate use the following.

$ danetool --tlsa-rr --host www.example.com --load-certificate cert.pem \
  --ca --no-domain

To read a server’s DANE TLSA entry, use:

$ danetool --check www.example.com --proto tcp --port 443

To verify an HTTPS server’s DANE TLSA entry, use:

$ danetool --check www.example.com --proto tcp --port 443 --load-certificate chain.pem

To verify an SMTP server’s DANE TLSA entry, use:

$ danetool --check www.example.com --proto tcp --starttls-proto=smtp --load-certificate chain.pem



































gnutls-cli-debug localhost


























## ----------------------------------------------------------------------------------- ##
##   [?] Socat builds a connection between your local system on port 4242 
##       and examplename.onion on port 6667 via your Tor SOCKS proxy on port 9050. 
## ----------------------------------------------------------------------------------- ##
##   [?] Simply connect to localhost on port 4242 to utilise it. 
## ----------------------------------------------------------------------------------- ##


## ------------------------------------------------------------------------------------------------ ##
##   [?] Note: If you are using Tor browser for your connection you will need to use port 9150. 
## ------------------------------------------------------------------------------------------------ ##
socat TCP4-LISTEN:4242,bind=127.0.0.1,fork SOCKS4A:localhost:examplename.onion:6667,socksport=9050
    
    

##-========================================================-##
##  [+] use socat to forward port TCP:443 to localhost:
##-========================================================-##
socat TCP4-LISTEN:443,reuseaddr,fork SOCKS4A:127.0.0.1:dns4torpnlfs2ifuz2s2yf3fc7rdmsbhm6rw75euj35pac6ap25zgqad.onion:443,socksport=9150


## ------------------------------------------------------------------------ ##
##   [?] Instruct your machine to treat the .onion address as localhost:
## ------------------------------------------------------------------------ ##
cat << EOF >> /etc/hosts
127.0.0.1 dns4torpnlfs2ifuz2s2yf3fc7rdmsbhm6rw75euj35pac6ap25zgqad.onion
EOF





##-======================-##
##  [+] DNS over UDP
##-======================-##


## ------------------------------------------------------------------------ ##
##   [?] encapsulate packets to port UDP:53 on localhost as TCP packets:
## ------------------------------------------------------------------------ ##
socat UDP4-LISTEN:53,reuseaddr,fork SOCKS4A:127.0.0.1:dns4torpnlfs2ifuz2s2yf3fc7rdmsbhm6rw75euj35pac6ap25zgqad.onion:253,socksport=9150

    
	
Use socat to emulate an SMTP mail SERVER 
	
socat TCP4-LISTEN:25,fork EXEC:'bash -c \"echo 220;sleep 1;echo 250;sleep 1;echo 250;sleep 1;echo 250;sleep 1;echo 354;sleep 1;echo 250; timeout 5 cat >> /tmp/socat.log\"'






 Create a tunnel from a remote server to the local machine using a specific source port     

socat TCP-LISTEN:locport,fork TCP:XXX.XXX.XXX.XXX:YYY,sourceport=srcport










UDP over SSH

Forward local UDP port to remotetarget via ssh.

0
socat udp-listen:1611 system:'ssh remoteserver "socat stdio udp-connect:remotetarget:161"'














##-====================================-##
##  [+] DNS over TCP, TLS, and HTTPS
##-====================================-##
PORT=853; socat TCP4-LISTEN:${PORT},reuseaddr,fork SOCKS4A:127.0.0.1:dns4torpnlfs2ifuz2s2yf3fc7rdmsbhm6rw75euj35pac6ap25zgqad.onion:${PORT},socksport=9150




## --------------------------------------------------------- ##
##   [?] if you ever forget the dns4tor*.onion address, 
##       --> you can simply use cURL:
## --------------------------------------------------------- ##
curl -sI https://tor.cloudflare-dns.com | grep alt-svc


## ---------------------------------------------------------------------------------------------------------------- ##
    alt-svc: h2="dns4torpnlfs2ifuz2s2yf3fc7rdmsbhm6rw75euj35pac6ap25zgqad.onion:443"; ma=315360000; persist=1
## ---------------------------------------------------------------------------------------------------------------- ##






##-=================================-##
##  [+] Disable IPv6 with sysctl
##-=================================-##
sysctl -w net.ipv6.conf.all.disable_ipv6=1
sysctl -w net.ipv6.conf.default.disable_ipv6=1






## --------------------------------------------------------- ##
##   [?] you will need to identify the Tor guard IP
## --------------------------------------------------------- ##
##   [?] you can use ss, netstat or GETINFO entry-guards 
##       through the tor controller to identify the guard IP.
## --------------------------------------------------------- ##
ss -ntp | grep "$(cat /var/run/tor/tor.pid)"


##-=======================================================-##
##  [+] use tcpdump to check for possible non-tor leaks
##-=======================================================-##
tcpdump -n -f -p -i eth0 not arp and not host IP.TO.TOR.GUARD






# Get server public cert
openssl s_client -showcerts -connect 192.168.111.23:443 </dev/null


# How to get server SSL cert
openssl s_client -showcerts -connect <server IP>:443








##-============================================-##
##  [+] Create certificate with the config
##-============================================-##
openssl req -out sslcert.csr -newkey rsa:2048 -nodes -keyout private.key -config ./san.cnf


##-============================================-##
##  [+] Generate self-signed certificate 
##      from existing private key and CSR
##-============================================-##
openssl x509 -signkey domain.key -in domain.csr -req -days 365 -out domain.crt


##-==========================================-##
##  [+] Extract info from SSL certificate
##-==========================================-##
openssl x509 -in $Server.crt -text


##-=================================-##
##  [+] Extract the cert issuer
##-=================================-##
openssl x509 -in $Server.crt -noout -issuer






##-=================================-##
##  [+] check kernel route status
##-=================================-##
ip xfrm state


##-============================-##
##  [+] check kernel routes
##-============================-##
ip xfrm policy


##-=====================================-##
##   [+] check all route table 
##       > including non default ones
##-=====================================-##
ip route show table all


##-========================-##
##  [+] strongswan log
##-========================-##
sudo journalctl -u strongswan.service







##-====================================================-##
##            [+] Generate an RSA Key Pair 
##-====================================================-##
## ---------------------------------------------------- ##
##   [?] Before you can obtain an X.509 certificate
## ---------------------------------------------------- ##
##   [?] Your web server will use this RSA key pair
##       to sign responses identifying it as the
##       bearer of the certificate.
## ---------------------------------------------------- ##
genrsa req x509 pkcs12 



##-=========================================-##
##  [+] Generate A 4096 Bit RSA Key Pair
##-=========================================-##
openssl genrsa -aes256 -out $Certificate.key 4096 



##-==========================================================-##
##  1). Create a Certificate Signing Request
## ---------------------------------------------------------- ##
##  2). Send A Request to your Certificate Authority (CA)
##      (So They Can Sign A Certificate)
##-==========================================================-##


## ---------------------------------------------------------- ##
##   [?] This states that you control the site 
##       Identified by the Common Name (CN)
## ---------------------------------------------------------- ##
##   [?] This verifies you as the owner of the Private Key
## ---------------------------------------------------------- ##
openssl req -new -key $Certificate.key -days 365 -out $Certificate.csr 



##-=========================================-##
##  [+] View The Contents of The CSR File
##-=========================================-##
openssl req -text -in $Certificate.csr 



##-=========================================-##
##  [+] Receiving A X.509 Certificate
##-=========================================-##
## ------------------------------------------------------------ ##
##   [?] You Will Receive A X.509 Certificate When Your
##       --> Certificate Authority Validates Your Identity
## ------------------------------------------------------------ ##
##  --> They Will Send You A Certificate
##  --> This Will be In PEM Format 
##  --> Saved In .cer Extension Form
## ------------------------------------------------------------ ##



##-==============================================-##
##  [+] View The Contents of This Certificate:
##-==============================================-##
openssl x509 -in $Certificate.cer -text 




##-=================================================================-##
##  [+] Package the Key and Certificate into a PKCS #12 Keystore
##-=================================================================-##
## 
## ------------------------------------------------------------------- ##
##-<+>-<+>-<+>-<+>-<+>-<+>-<+>-<+>-<+>-<+>-<+>-<+>-<+>-<+>-<+>-<+>-<+>-##
##    [?] A PKCS #12 Keystore Has Either A .pfx or .p12 Extensio
##-<+>-<+>-<+>-<+>-<+>-<+>-<+>-<+>-<+>-<+>-<+>-<+>-<+>-<+>-<+>-<+>-<+>-##
## ------------------------------------------------------------------- ##
## 
## ----------------------------------------------------------- ##
##   [?] When Combining the key and certificate
##       You will be prompted for the following:
## ----------------------------------------------------------- ##
##       --> Existing Passphrase For The Encrypted Key File
##       --> As Well As: 
##       --> New Passphrase For The PCKS #12 File
## ----------------------------------------------------------- ##
openssl pkcs12 -export -in $Certificate.cer -inkey $Certificate.key -out $Certificate.pfx 





##-===================================================================-##
##  [+] Apaches Incompatability with The PKCS #12 Keystore Format
##-===================================================================-##
## 
## ------------------------------------------------------------------- ##
##  [?] Apache does not use the PKCS #12 Keystore Format. 
##      --> It expects the key to be separate from the Certificate. 
## ------------------------------------------------------------------- ##
##-<+>-<+>-<+>-<+>-<+>-<+>-<+>-<+>-<+>-<+>-<+>-<+>-<+>-<+>-<+>-<+>-<+>-##
## ------------------------------------------------------------------- ##
##  [?] Furthermore, if the key is encrypted, 
##      --> Apache will prompt for your pass every time it starts
## ------------------------------------------------------------------- ##
##-<+>-<+>-<+>-<+>-<+>-<+>-<+>-<+>-<+>-<+>-<+>-<+>-<+>-<+>-<+>-<+>-<+>-##
## ------------------------------------------------------------------- ##
##  [?] That means that you won't be able to reboot your web server
##      --> Without being logged in.
## ------------------------------------------------------------------- ##
##-<+>-<+>-<+>-<+>-<+>-<+>-<+>-<+>-<+>-<+>-<+>-<+>-<+>-<+>-<+>-<+>-<+>-##
## ------------------------------------------------------------------- ##
##  [?] This will prompt for your passphrase for decrypting the key
## ------------------------------------------------------------------- ##
##-<+>-<+>-<+>-<+>-<+>-<+>-<+>-<+>-<+>-<+>-<+>-<+>-<+>-<+>-<+>-<+>-<+>-##
## ------------------------------------------------------------------- ##
## 
## 
##-===================================================================-##
##                   [!] Do This With Great Caution [!]
##-===================================================================-##
## ------------------------------------------------------------------- ##
##  [?] If an attacker can gain access to the key, your compromised!
## ------------------------------------------------------------------- ##
## 
##-======================================================-##
##  [+] Strip the passphrase from the key file
##-======================================================-##
openssl rsa -in $Certificate.key -out $StripedKey.key 




environment variables
```
$0   :name of shell or shell script.
$?   :most recent foreground pipeline exit status.
$-   :current options set for the shell.
$$   :pid of the current shell (not subshell).
$!   :is the PID of the most recent background command.






if [ ! -d /usr/share/ca-certificates ]
      then



function 

        if [ ! -f "$File" ]
        then
            echo "    [-] WARNING: not found!" 1>&2
        fi
    done


    if [ -n  ]
    then
        $Cmd
    else
        $Cmd

    fi

done | sort | uniq -c












## find all cert8.db files under ~/.mozilla/firefox
CERT8S=( $( find ~/.mozilla/firefox -type f -name cert8.db | sed 's/\/cert8\.db$//' ) )


























## 
## ------------------------------------------------------------------- ##
##-<+>-<+>-<+>-<+>-<+>-<+>-<+>-<+>-<+>-<+>-<+>-<+>-<+>-<+>-<+>-<+>-<+>-##
## ------------------------------------------------------------------- ##
##   [?] 
##       --> 
##       --> 
## ------------------------------------------------------------------- ##
##-<+>-<+>-<+>-<+>-<+>-<+>-<+>-<+>-<+>-<+>-<+>-<+>-<+>-<+>-<+>-<+>-<+>-##
## ------------------------------------------------------------------- ##
## 
## 
## ------------------------------------------------------------------- ##
##-<+>-<+>-<+>-<+>-<+>-<+>-<+>-<+>-<+>-<+>-<+>-<+>-<+>-<+>-<+>-<+>-<+>-##
## ------------------------------------------------------------------- ##
##   [?] 
##       --> 
##       --> 
## ------------------------------------------------------------------- ##
##-<+>-<+>-<+>-<+>-<+>-<+>-<+>-<+>-<+>-<+>-<+>-<+>-<+>-<+>-<+>-<+>-<+>-##
## ------------------------------------------------------------------- ##
## 
## 
## ------------------------------------------------------------------- ##
##-<+>-<+>-<+>-<+>-<+>-<+>-<+>-<+>-<+>-<+>-<+>-<+>-<+>-<+>-<+>-<+>-<+>-##
## ------------------------------------------------------------------- ##
##   [?] 
##       --> 
##       --> 
## ------------------------------------------------------------------- ##
##-<+>-<+>-<+>-<+>-<+>-<+>-<+>-<+>-<+>-<+>-<+>-<+>-<+>-<+>-<+>-<+>-<+>-##
## ------------------------------------------------------------------- ##
## 
## 
## ------------------------------------------------------------------- ##
##-<+>-<+>-<+>-<+>-<+>-<+>-<+>-<+>-<+>-<+>-<+>-<+>-<+>-<+>-<+>-<+>-<+>-##
## ------------------------------------------------------------------- ##
##   [?] 
##       --> 
##       --> 
## ------------------------------------------------------------------- ##
##-<+>-<+>-<+>-<+>-<+>-<+>-<+>-<+>-<+>-<+>-<+>-<+>-<+>-<+>-<+>-<+>-<+>-##
## ------------------------------------------------------------------- ##
## 







Print the Response Headers and Body (together)

curl -i $Domain




Print Only the Response Headers

curl -s -o /dev/null -D - $Domain



Detailed Trace with Timestamps

curl --trace - --trace-time $Domain




Print Only the Response Code

curl -w '%{response_code}' -s -o /dev/null $Domain



Print Only the Response Headers

curl -s -o /dev/null -D - $Domain





Change the User Agent to Firefox

curl -A 'Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:60.0) Gecko/20100101 Firefox/60.0' $Domain


Change the User Agent to Chrome

curl -A 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/76.0.3809.100 Safari/537.36' $Domain


Pretend to be a Google Bot

curl -A 'Googlebot/2.1 (+http://www.google.com/bot.html)' $Domain



Remove the User Agent

curl -A '' $Domain



This recipe passes an empty string '' to the -A command line option. 
The empty string tells curl to remove the user agent header 
and not to send User-Agent HTTP header.



Send an Empty User Agent

curl -A '' -H 'User-Agent;' $Domain







Save Cookies to a File

curl -c cookies.txt $Domain



Load Cookies from a File

curl -b cookies.txt $Domain



Send a Referer via the -H argument

curl -H 'Referer: https://digg.com' $Domain


Add a Referrer

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






https://lwn.net/Articles/531114/
https://lwn.net/Articles/443241/
https://www.ibm.com/developerworks/linux/library/l-mount-namespaces/index.html#artrelatedtopics

https://github.com/pekman/netns-exec/blob/master/netns-exec-dbus
https://github.com/pekman/openvpn-netns/blob/master/openvpn-netns-shell
https://github.com/pekman/openvpn-netns/blob/master/openvpn-netns
https://github.com/pekman/openvpn-netns/blob/master/openvpn-scripts/netns
https://gist.github.com/Schnouki/fd171bcb2d8c556e8fdf
https://github.com/Ernillew/netns-vpn/blob/master/etc/systemd/system/vpnns.service
https://github.com/Ernillew/netns-vpn/blob/master/etc/systemd/system/openvpn-ns%40.service
https://github.com/conallprendergast/openvpn-netns-systemd/blob/master/etc/openvpn/netns
https://github.com/conallprendergast/openvpn-netns-systemd/blob/master/etc/systemd/system/openvpn-ns%40.service
https://github.com/conallprendergast/openvpn-netns-systemd/blob/master/bin/vpn-exec
https://github.com/russkel/openvpn-client-netns/blob/master/openvpn-client-netns%40.service
https://github.com/BarrRedKola/ovnt/blob/master/connect_vpn_netns.sh
https://github.com/BarrRedKola/ovnt/blob/master/create_netns.sh
https://github.com/BarrRedKola/ovnt/blob/master/dismiss_netns_en_masse.sh
https://github.com/BarrRedKola/ovnt/blob/master/start_transmission_netns.sh

https://github.com/kristenjacobs/container-networking/blob/master/4-overlay-network/setup.sh









tshark -i $1 -T fields \
-e ip.src \
-e ip.dst \
-e frame.protocols \
-E header=y





echo "Creating the namespaces"
sudo ip netns add $CON1
sudo ip netns add $CON2

echo "Creating the veth pairs"
sudo ip link add veth10 type veth peer name veth11
sudo ip link add veth20 type veth peer name veth21

echo "Adding the veth pairs to the namespaces"
sudo ip link set veth11 netns $CON1
sudo ip link set veth21 netns $CON2

echo "Configuring the interfaces in the network namespaces with IP address"
sudo ip netns exec $CON1 ip addr add $IP1/24 dev veth11 
sudo ip netns exec $CON2 ip addr add $IP2/24 dev veth21 

echo "Enabling the interfaces inside the network namespaces"
sudo ip netns exec $CON1 ip link set dev veth11 up
sudo ip netns exec $CON2 ip link set dev veth21 up

echo "Creating the bridge"
sudo ip link add name br0 type bridge

echo "Adding the network namespaces interfaces to the bridge"
sudo ip link set dev veth10 master br0
sudo ip link set dev veth20 master br0

echo "Assigning the IP address to the bridge"
sudo ip addr add $BRIDGE_IP/24 dev br0

echo "Enabling the bridge"
sudo ip link set dev br0 up

echo "Enabling the interfaces connected to the bridge"
sudo ip link set dev veth10 up
sudo ip link set dev veth20 up

echo "Setting the loopback interfaces in the network namespaces"
sudo ip netns exec $CON1 ip link set lo up
sudo ip netns exec $CON2 ip link set lo up

echo "Setting the default route in the network namespaces"
sudo ip netns exec $CON1 ip route add default via $BRIDGE_IP dev veth11
sudo ip netns exec $CON2 ip route add default via $BRIDGE_IP dev veth21

echo "Enables IP forwarding on the node"
sudo sysctl -w net.ipv4.ip_forward=1

# ------------------- Step 4 Specific Setup --------------------- #

echo "Starts the UDP tunnel in the background"
sudo socat TUN:$TUNNEL_IP/16,iff-up UDP:$TO_NODE_IP:9000,bind=$NODE_IP:9000 &

echo "Setting the MTU on the tun interface"
sudo ip link set dev tun0 mtu 1492

echo "Disables reverse path filtering"
sudo bash -c 'echo 0 > /proc/sys/net/ipv4/conf/all/rp_filter'
sudo bash -c 'echo 0 > /proc/sys/net/ipv4/conf/enp0s8/rp_filter'
sudo bash -c 'echo 0 > /proc/sys/net/ipv4/conf/br0/rp_filter'
sudo bash -c 'echo 0 > /proc/sys/net/ipv4/conf/tun0/rp_filter'






ip link add ${HM}-${BRG} type veth peer name ${HM}.${BRG}
brctl addif ${BRG} ${HM}-${BRG}
ip link set ${HM}-${BRG} up
ip link set ${HM}.${BRG} netns ${HS}
ip netns exec ${HS} ip link set dev ${HM}.${BRG} name ${NIC}
ip netns exec ${HS} ip link set ${NIC} address ${mac}
ip netns exec ${HS} ip link set ${NIC} up
ip netns exec ${HS} ip addr add ${Array[0]}/${Array[1]} dev ${NIC}
if [ ! -z "$GWS" ]; then
  ip netns exec ${HS} ip route add default via ${GWS}
fi



 
 



##-=============================-##
##  [+] Change default shell
##-=============================-##
sudo dpkg-reconfigure dash










The primary network interface (dhcp)

auto eth0
iface eth0 inet dhcp
The primary network interface (static)

auto eth0
iface eth0 inet static
address 192.168.1.14
netmask 255.255.255.0
gateway 192.168.1.1
dns-nameservers 8.8.8.8 8.8.4.4

sudo /etc/init.d/networking stop
sudo service networking start






##-===========================================-##
##  [+] List of connections using port 8080
##-===========================================-##
ss -pn '( dport = 8080 or sport = 8080 )'



##-===========================================-##
##  [+] Get list of recently changed files:
##-===========================================-##
find $1 -type f -exec stat --format '%Y :%y %n' "{}" ; | grep -v cache |sort -nr | cut -d: -f2- | head







https://hackertarget.com/tcpdump-examples/

















alias httpdump="sudo tcpdump -i en1 -n -s 0 -w - | grep -a -o -E \"Host\: .*|GET \/.*\""


## TCPDUMP all the data on port $1 
## into rotated files /tmp/results
tcpdump -i any -s0 tcp port "$1" -A -w /tmp/$Results -C 100
  



Display a pcap file
tcpdump -r passwordz.pcap

Display ips and filter and sort
tcpdump -n -r passwordz.pcap | awk -F" " '{print $3}' | sort -u | head

Grab a packet capture on port 80
tcpdump tcp port 80 -w output.pcap -i eth0

Check for ACK or PSH flag set in a TCP packet
tcpdump -A -n 'tcp[13] = 24' -r passwordz.pcap







    TCP connections

    SYN -> SYN/ACK -> ACK
    DATA -> DATA/ACK -> ACK -> ACK
    FIN -> FIN/ACK -> ACK

	

Monitor TCP traffic

tcpdump -n -tttt -i eth1 tcp

Monitor ftp traffic

tcpdump -A port ftp -v






##-====================================================-##
##  [+] Save to pcap file and display data on screen
##-====================================================-##
tcpdump -n -w - port 8080 |tee dump.pcap |tcpdump -A -r -



##-==================================-##
##  [+] Capture Packets on Port 80
##-==================================-##
tcpdump -A -s0 port 80


##-==============================-##
##  [+] Filter on UDP traffic
##-==============================-##
tcpdump -i eth0 udp
tcpdump -i eth0 proto 17




##-=========================================-##
##  [+] Capture Hosts based on IP address
##-=========================================-##
tcpdump -i eth0 host 10.10.1.1


##-===========================================================-##
##  [+] Capture only packets going one way using src or dst
##-===========================================================-##
tcpdump -i eth0 dst 10.10.1.20




##-=============================-##
##  [+] Write a capture file
##-=============================-##
tcpdump -i eth0 -s0 -w test.pcap





##-========================================================-##
##  [+] Line Buffered Mode
## ----------------------------------------------------------- ##
##  [?] buffered (or packet buffered -C) mode
## ----------------------------------------------------------- ##
tcpdump -i eth0 -s0 -l port 80 | grep 'Server:'



##-========================================================-##
##   [+] Extract HTTP User Agent from HTTP request header
##-========================================================-##
tcpdump -nn -A -s1500 -l | grep "User-Agent:"


##-===================================================-##
##   [+]  Extract User Agent + Header From Packets:
##-===================================================-##
## ------------------------------------------------------------------- ##
##   [?] use egrep and multiple matches we can get the User Agent 
##        and the Host (or any other header) from the request.
## ------------------------------------------------------------------- ##
tcpdump -nn -A -s1500 -l | egrep -i 'User-Agent:|Host:'


##-==============================================-##
##  [+] Capture only HTTP GET and POST packets
##-==============================================-##
tcpdump -s 0 -A -vv 'tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x47455420'


##-====================================-##
##  [+] Select Only on POST Requests:
##-====================================-##
## ------------------------------------------------------------------------ ##
##  [?] Match the hexadecimal GET and POST ascii Fingerprints in Packets
## ------------------------------------------------------------------------ ##
tcpdump -s 0 -A -vv 'tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x504f5354'


##-===================================-##
##  [+] Extract HTTP Request URLs
##-===================================-##
## ----------------------------------------------------------- ##
##  [?] Parse Host and HTTP Request location from traffic
## ----------------------------------------------------------- ##
tcpdump -s 0 -v -n -l | egrep -i "POST /|GET /|Host:"



##-==============================================-##
##  [+] Extract HTTP Passwords in POST Requests
##-==============================================-##
tcpdump -s 0 -A -n -l | egrep -i "POST /|pwd=|passwd=|password=|Host:"


##-==================================================-##
##  [+] Capture Cookies from Server and from Client
##-==================================================-##
tcpdump -nn -A -s0 -l | egrep -i 'Set-Cookie|Host:|Cookie:'


##-================================-##
##  [+] Capture all ICMP packets
##-================================-##
tcpdump -n icmp


##-=================================================================-##
##  [+] Show ICMP Packets that are not ECHO/REPLY (standard ping)
##-=================================================================-##
tcpdump 'icmp[icmptype] != icmp-echo and icmp[icmptype] != icmp-echoreply'


##-===================================-##
##  [+] Capture SMTP / POP3 Email
##-===================================-##
## ----------------------------------- ##
##  [?] Parse the email recipients
## ----------------------------------- ##
tcpdump -nn -l port 25 | grep -i 'MAIL FROM\|RCPT TO'


##-=======================================-##
##  [+] Extract NTP Query and Response
##-=======================================-##
tcpdump dst port 123


##-=======================================-##
##  [+] Capture SNMP Query and Response
##-=======================================-##
tcpdump -n -s0  port 161 and udp


##-==============================================-##
##  [+] Capture FTP Credentials and Commands
##-==============================================-##
## ______________________________________________
## ---------------------------------------------- ##
##  [?] Capture FTP Connections (TCP port 20)
## ---------------------------------------------- ##
##  [?] FTP Commands: LIST, CWD and PASSIVE
## ---------------------------------------------- ##
## ______________________________________________
## ---------------------------------------------- ##
##  [?] After the authentication is established 
##      an FTP session can be active or passive 
## ---------------------------------------------- ##
tcpdump -nn -v port ftp or ftp-data



##-=============================-##
##  [+] Rotate Capture Files
##-=============================-##
## ----------------------------------------------------------- ##
##  [?] The file capture-(hour).pcap 
##      will be created every (-G) 3600 seconds (1 hour). 
##      The files will be overwritten the following day. 
##      So you should end up with capture-{1-24}.pcap, i
## ----------------------------------------------------------- ##
tcpdump  -w /tmp/capture-%H.pcap -G 3600 -C 200



##-=================================================-##
##  [+] Capture IPv6 traffic using the ip6 filter
##-=================================================-##
tcpdump -nn ip6 proto 6


##-==================================================================-##
##  [+] Read IPv6 UDP Traffic from a previously saved capture file
##-==================================================================-##
tcpdump -nr ipv6-test.pcap ip6 proto 17



##-==============================================-##
##  [+] Test Network For Someone Running Nmap: 
##-==============================================-##
## ---------------------------------------------- ##
##  [?] Detect Port Scan in Network Traffic
## ---------------------------------------------- ##
tcpdump -nn port 80 | grep "GET /"


##-=============================================================-##
##  [+] Capture Start and End Packets of every non-local host
##-=============================================================-##
## ------------------------------------------------------------- ##
##  [?] Show each established TCP conversation with timestamps
## ------------------------------------------------------------- ##
tcpdump 'tcp[tcpflags] & (tcp-syn|tcp-fin) != 0 and not src and dst net localnet'



##-=================================================-##
##  [+] Capture DNS Request and Response Packets
##-=================================================-##
## ------------------------------------------------- ##
##  [?] Outbound DNS request to Google public DNS 
##      and the A record (ip address) response
## ------------------------------------------------- ##
tcpdump -i wlp58s0 -s0 port 53


##-=================================-##
##  [+] Capture HTTP data packets
##-=================================-##
## --------------------------------------------------------------- ##
##  [?] Only capture on HTTP data packets on port 80. 
## --------------------------------------------------------------- ##
##  [?] Avoid capturing the TCP session setup (SYN / FIN / ACK)
## --------------------------------------------------------------- ##
tcpdump 'tcp port 80 and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)'



##-==================================================-##
##  [+] Capture with tcpdump and view in Wireshark
##-==================================================-##
'tcpdump -s0 -c 1000 -nn -w - not port 22' | wireshark -k -i -



##-========================================-##
##  [+] Capture Top Hosts by Packets
##-========================================-##
## ---------------------------------------- ##
##  [?] List the top number of packets 
##  [?] Extract the IP address
##  [?] Sort and count the occurrances
## ---------------------------------------- ##
tcpdump -nnn -t -c 200 | cut -f 1,2,3,4 -d '.' | sort | uniq -c | sort -nr | head -n 20



##-===========================================-##
##  [+] Capture all the plaintext passwords
##-===========================================-##
## -------------------------------------------------------- ##
##  [?] capture passwords (hostname, ip address, system)
## -------------------------------------------------------- ##
tcpdump port http or port ftp or port smtp or port imap or port pop3 or port telnet -l -A | egrep -i -B5 'pass=|pwd=|log=|login=|user=|username=|pw=|passw=|passwd=|password=|pass:|user:|username:|password:|login:|pass |user '



##-========================================-##
##  [+] Capture DHCP Request And Replies:
##-========================================-##
## ---------------------------------------------------------------- ##
##  [?] DHCP requests are seen on port 67 and the reply is on 68.
## ---------------------------------------------------------------- ##
tcpdump -v -n port 67 or 68



# record the capture data to a file.
$ sudo tcpdump -i ens33 udp port 53 -w cache.pcap



# read the results of the capture.
$ sudo tcpdump -n -t -r cache.pcap port 53




tcpdump -i any -s0 -w capture.pcap
tcpdump -i eth0 -w capture -n -U -s 0 src not 192.168.1.X and dst not 192.168.1.X
tcpdump -vv -i eth0 src not 192.168.1.X and dst not 192.168.1.X








tcpdump -i wlan0 -vvv -A | grep "GET"




This will grep all GET from the wlan0 interface. 
This will not get any SSL-encrypted traffic.

sudo tcpdump -i wlan0 src port 80 or dst port 80 -w port-80-recording.pcap
sudo tcpdump -i eth0 src port 80 or dst port 80 -w port-80-recording.pcap



Print the traffic in hex with ascii interpretation.

tcpdump -nX -r file.pcap



Only record tcp-traffic

tcpdump tcp -w file.pcap




##-===============================-##
##  [+] Dump Packets By Domain
##-===============================-##
tcpdump -i eth0 -nt -s 500 port domain


##-======================================-##
##  [+] Filter By Domain Using Regex:
##-======================================-##
tcpdump -i eth0 -nt port 53 | grep $DomainDNS



#!/bin/bash
IP=$3
PWD=`pwd`
LOG_FILE="${PWD}/../logs/active-responses.log"
[ "x${IP}" = "x" ] && exit 1
echo "`date` $0 $1 $2 $3 $4 $5" >> ${LOG_FILE}
/usr/sbin/tcpdump -i any -s 0 -G 600 -W 1 -w /var/tmp/tcpdump-$IP-%Y%m%d%H%M.pcap src host $IP or dst host $IP


















Wireshark

Show only SMTP (port 25) and ICMP traffic:

tcp.port eq 25 or icmp

Show only traffic in the LAN (192.168.x.x), between workstations and servers -- no Internet:

ip.src==192.168.0.0/16 and ip.dst==192.168.0.0/16

Filter by a protocol ( e.g. SIP ) and filter out unwanted IPs:

ip.src != xxx.xxx.xxx.xxx && ip.dst != xxx.xxx.xxx.xxx && sip

Some commands are equal

ip.addr == xxx.xxx.xxx.xxx

Equals

ip.src == xxx.xxx.xxx.xxx or ip.dst == xxx.xxx.xxx.xxx

ip.addr != xxx.xxx.xxx.xxx

Equals

ip.src != xxx.xxx.xxx.xxx or ip.dst != xxx.xxx.xxx.xxx

















##-=========================================-##
##  [+] Match packets with the following:
##      -------------------------------
##      		  POST (^*) 							## at the start of the line 
##      ------------- or --------------
##            HTTP POST requests
##      -------------------------------
##      in a simple text output format. 
##-=========================================-##
ngrep -d wlan0 '^POST'


## ----------------------------------------------- ##
##  [?] String 'pwd' has shown the HTTP POST
##      request with my login and password
## ----------------------------------------------- ##
ngrep -t -d wlan0 'pwd'



tcpflow will log all the tcpflows
or TCP sessions into text files


##-===========================================-##
##  [+] Capture all HTTP flows over port 80 
##      and store them as text files
##-===========================================-##
tcpflow -i wlan0 'port 80'









Switch to monitor mode
sudo iw phy phy0 interface add mon0 type monitor


Change radio channel
sudo iw dev mon0 set freq 2437


Capture traffic
sudo tcpdump -i mon0 -n -w wireless.cap



Start scanning
airodump-ng mon0

Send deauth­ent­ication
airepl­­ay-ng -0 1 -a mac_ad­­dr­e­ss_ap -c mac_ad­­dr­e­s­s_­­client

Kill conflicting processes
airmon-ng check kill








##-==============================================-##
##  [+] 
##-==============================================-##
## ----------------------------------------------------------- ##
##  [?] 
## ----------------------------------------------------------- ##



##-==============================================-##
##  [+] 
##-==============================================-##
## ----------------------------------------------------------- ##
##  [?] 
## ----------------------------------------------------------- ##



##-==============================================-##
##  [+] 
##-==============================================-##
## ----------------------------------------------------------- ##
##  [?] 
## ----------------------------------------------------------- ##



##-==============================================-##
##  [+] 
##-==============================================-##
## ----------------------------------------------------------- ##
##  [?] 
## ----------------------------------------------------------- ##



##-==============================================-##
##  [+] 
##-==============================================-##
## ----------------------------------------------------------- ##
##  [?] 
## ----------------------------------------------------------- ##



##-==============================================-##
##  [+] 
##-==============================================-##
## ----------------------------------------------------------- ##
##  [?] 
## ----------------------------------------------------------- ##



##-==============================================-##
##  [+] 
##-==============================================-##
## ----------------------------------------------------------- ##
##  [?] 
## ----------------------------------------------------------- ##



##-==============================================-##
##  [+] 
##-==============================================-##
## ----------------------------------------------------------- ##
##  [?] 
## ----------------------------------------------------------- ##



##-==============================================-##
##  [+] 
##-==============================================-##
## ----------------------------------------------------------- ##
##  [?] 
## ----------------------------------------------------------- ##



##-==============================================-##
##  [+] 
##-==============================================-##
## ----------------------------------------------------------- ##
##  [?] 
## ----------------------------------------------------------- ##














MAIN_INTERFACE=$(ip route list | grep default | cut -d' ' -f 5)
DISK=$(mount | grep ' / ' | cut -d' ' -f1 | sed 's/[0-9]*$//g')
ADDRESS=$(ip addr show $MAIN_INTERFACE | grep global | cut -d' ' -f 6 | head -n 1)
GATEWAY=$(ip route list | grep default | cut -d' ' -f 3)

# URL to RouterOS CHR
ROUTEROS_URL=https://download2.mikrotik.com/routeros/6.43.14/chr-6.43.14.img.zip

echo -e "Please confirm the settings:"
echo -e "Installation destination: ${DISK}"
echo -e "Network information:"
echo -e "\tinterface: ${MAIN_INTERFACE}"
echo -e "\tIPv4 address: ${ADDRESS}"
echo -e "\tIPv4 gateway: ${GATEWAY}"




echo "Mounting temporary rootfs..."
mount -t squashfs "${WORKDIR}/rootfs.squashfs" "${WORKDIR}/newrootro"
mount -t overlay overlay -o rw,lowerdir="${WORKDIR}/newrootro",upperdir="${WORKDIR}/newrootrw",workdir="${WORKDIR}/overlayfs_workdir" "${WORKDIR}/newroot"







echo "convert image"
qemu-img convert chr.img -O qcow2 chr.qcow2
qemu-img resize chr.qcow2 `fdisk $DISK -l | head -n 1 | cut -d',' -f 2 | cut -d' ' -f 2`

echo "mount image"
modprobe nbd
qemu-nbd -c /dev/nbd0 chr.qcow2
echo "waiting qemu-nbd"
sleep 5
partprobe /dev/nbd0
mount /dev/nbd0p2 /mnt


echo "resize partition"
echo -e 'd\n2\nn\np\n2\n65537\n\nw\n' | fdisk /dev/nbd0
e2fsck -f -y /dev/nbd0p2 || true
resize2fs /dev/nbd0p2
sleep 5

echo "move image to RAM (this will take quite a while)"
mount -t tmpfs tmpfs /mnt
pv /dev/nbd0 | gzip > /mnt/chr-extended.gz
sleep 5


# Auto configure script on RouterOS first boot

/ip address add address=$ADDRESS interface=[/interface ethernet find where name=ether1]
/ip route add gateway=$GATEWAY
/ip service disable telnet
/ip dns set servers=8.8.8.8,8.8.4.4
EOF











magicrescue –r jpeg-jﬁf foundﬁles /dev/sda1




alias arm='sudo -u tor arm'
alias mtr='mtr -tbz --mpls'


# NetworkManager
alias nmcli="nmcli -pretty -colors yes -ask"





metagoofil -d target.com -t pdf,doc,ppt -l 200 -n 5 -o /root/Desktop/metagoofil/ -f /root/Desktop/metagoofil/result.html

    Let us understand the details of the command:
    -d to specify the target domain.
    -t to specify the file type you want metagoofil to locate and download.
    -l to limit the results to a search. By default, it is set to 200.
    -n to specify the number of files to download.
    -o to specify a directory to save download file.
    -f output file name and location.




theharvester -d url -l 500 -b all -b all = all search engines







Emulate with qemu

System emulation

launching an image with the following command

qemu-system-arm \
  -kernel kernel-qemu \
  -cpu arm1176 \
  -m 256 \
  -M versatilepb \
  -no-reboot \
  -serial stdio \
  -append "root=/dev/sda2 panic=1 rootfstype=ext4 rw" \
  -hda <disk_image.img>









