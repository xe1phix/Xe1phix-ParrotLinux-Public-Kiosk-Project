gnunet-arm
gnunet-ats
gnunet-auto-share
gnunet-bcd
gnunet-bugreport
gnunet-cadet
gnunet.conf
gnunet-config
gnunet-conversation
gnunet-conversation-gtk
gnunet-conversation-test
gnunet-core
gnunet-datastore
gnunet-directory
gnunet-dns2gns
gnunet-download
gnunet-ecc
gnunet-fs
gnunet-fs-gtk
gnunet-fuse
gnunet-gns
gnunet-gns-gtk
gnunet-gns-proxy
gnunet-gns-proxy
gnunet-gns-proxy-setup-ca
gnunet-gtk
gnunet-identity
gnunet-identity-gtk
gnunet-namecache
gnunet-namestore
gnunet-namestore-fcfsd
gnunet-namestore-gtk
gnunet-nat
gnunet-nat-auto
gnunet-nat-server
gnunet-nse
gnunet-peerinfo
gnunet-peerinfo-gtk
gnunet-publish
gnunet-qr
gnunet-reclaim
gnunet-resolver
gnunet-revocation
gnunet-scalarproduct
gnunet-scrypt
gnutls_pubkey_import
gnutls-serv 
gnutls_rehandshake
gnutls-cli
gnutls-cli-debug
gnutls_tdb_init








Running your own TLS server based on GnuTLS



add support for X.509

certtool --generate-privkey > x509-ca-key.pem
echo 'cn = GnuTLS test CA' > ca.tmpl
echo 'ca' >> ca.tmpl
echo 'cert_signing_key' >> ca.tmpl
certtool --generate-self-signed --load-privkey x509-ca-key.pem   --template ca.tmpl --outfile x509-ca.pem



Then; 

##-============================================- ##
##     [+]  Generate A Server Certificate:


## ------------------------------------------------------------------------------ ##
##    [?]  Remember to change the $dns_name value 
## ------------------------------------------------------------------------------ ##
##           to the name of your server host,
##								  or 
##          skip that command to avoid the field.
## ------------------------------------------------------------------------------ ##


certtool --generate-privkey > x509-server-key.pem
echo 'organization = GnuTLS test server' > server.tmpl
echo 'cn = test.gnutls.org' >> server.tmpl
echo 'tls_www_server' >> server.tmpl
echo 'encryption_key' >> server.tmpl
echo 'signing_key' >> server.tmpl
echo 'dns_name = test.gnutls.org' >> server.tmpl
certtool --generate-certificate --load-privkey x509-server-key.pem   --load-ca-certificate x509-ca.pem --load-ca-privkey x509-ca-key.pem   --template server.tmpl --outfile x509-server.pem




## ---------------------------------------------------------------------- ##
##    [?]  For use in the client, you may want to:
## ---------------------------------------------------------------------- ##

##-============================================- ##
##    [+]  generate a client certificate as well:
##-============================================- ##

certtool --generate-privkey > x509-client-key.pem
echo 'cn = GnuTLS test client' > client.tmpl
echo 'tls_www_client' >> client.tmpl
echo 'encryption_key' >> client.tmpl
echo 'signing_key' >> client.tmpl
certtool --generate-certificate --load-privkey x509-client-key.pem   --load-ca-certificate x509-ca.pem --load-ca-privkey x509-ca-key.pem   --template client.tmpl --outfile x509-client.pem



## --------------------------------------------------------------------------------------------------------------------- ##
##     [?]  To be able to import the client key/certificate into some applications, 
##     [?]  you will need to convert them into a PKCS#12 structure.  
## --------------------------------------------------------------------------------------------------------------------- ##
##     [?]  This also encrypts the security sensitive key with a password.
## --------------------------------------------------------------------------------------------------------------------- ##
certtool --to-p12 --load-ca-certificate x509-ca.pem   --load-privkey x509-client-key.pem --load-certificate x509-client.pem   --outder --outfile x509-client.p12



##-============================================- ##
##    [+]  Create a proxy certificate for the client as well:
##-============================================- ##
certtool --generate-privkey > x509-proxy-key.pem
echo 'cn = GnuTLS test client proxy' > proxy.tmpl
certtool --generate-proxy --load-privkey x509-proxy-key.pem   --load-ca-certificate x509-client.pem --load-ca-privkey x509-client-key.pem   --load-certificate x509-client.pem --template proxy.tmpl   --outfile x509-proxy.pem




##-============================================- ##
##    [+]  Start the server again:
##-============================================- ##
gnutls-serv --http  --x509cafile x509-ca.pem  --x509keyfile x509-server-key.pem  --x509certfile x509-server.pem


##-==================================================- ##
##     [+]  Try connecting to the server using your web browser:
##-==================================================- ##
## ----------------------------------------------------------------------------------------------- ##
##     [?]  Note that the server listens to port 5556 by default.
## ----------------------------------------------------------------------------------------------- ##


##-======================-===========- ##
##    [+]  Allow connections using ECDSA:
##-======================-===========- ##
## ------------------------------------------------------------------------------------------------- ##
##    [+]  Create a ECDSA key and certificate for the server:
##    [?]  These credentials will be used in the final example below.
## ------------------------------------------------------------------------------------------------- ##
certtool --generate-privkey --ecdsa > x509-server-key-ecc.pem
certtool --generate-certificate --load-privkey x509-server-key-ecc.pem   --load-ca-certificate x509-ca.pem --load-ca-privkey x509-ca-key.pem   --template server.tmpl --outfile x509-server-ecc.pem


## ------------------------------------------------------------------------------------------------- ##
##    [?]  The next step is to add support for SRP authentication. 
##    [?]  This requires an SRP password file created with srptool.  
##    [?]  To start the server with SRP support:
## ------------------------------------------------------------------------------------------------- ##
gnutls-serv --http --priority NORMAL:+SRP-RSA:+SRP  --srppasswdconf srp-tpasswd.conf  --srppasswd srp-passwd.txt



## ------------------------------------------------------------------------------------------------- ##
##    [+]  Let's start a server with support for PSK. 
##    [?]  This would require a password file created with psktool.
## ------------------------------------------------------------------------------------------------- ##
gnutls-serv --http --priority NORMAL:+ECDHE-PSK:+PSK  --pskpasswd psk-passwd.txt


If you want a server with support for raw public-keys 
we can also add these credentials. 
Note however thatthere is no identity information linked to these keys 
as is the case with regular x509 certificates. 
Authentication must be done via different means. 
Also we need to explicitly enable raw public-key certificates 
via the priority strings:


gnutls-serv --http --priority NORMAL:+CTYPE-CLI-RAWPK:+CTYPE-SRV-RAWPK  --rawpkfile srv.rawpk.pem  --rawpkkeyfile srv.key.pem




       Finally, we start the server with all the earlier parameters and you get this command:

gnutls-serv --http --priority NORMAL:+PSK:+SRP:+CTYPE-CLI-RAWPK:+CTYPE-SRV-RAWPK  --x509cafile x509-ca.pem  --x509keyfile x509-server-key.pem  --x509certfile x509-server.pem  --x509keyfile x509-server-key-ecc.pem  --x509certfile x509-server-ecc.pem  --srppasswdconf srp-tpasswd.conf  --srppasswd srp-passwd.txt --pskpasswd psk-passwd.txt --rawpkfile srv.rawpk.pem --rawpkkeyfile srv.key.pem












--generate
              Generate Diffie-Hellman parameters.


--udp
              Use DTLS (datagram TLS) over UDP.









gnutls-serv --debug=										##  Enable debugging  ( range: 0 to 9999 }

gnutls-serv --require-client-cert					##  Require a client certificate
gnutls-serv --verify-client-cert						##  If a client certificate is sent then verify it.

gnutls-serv --x509fmtder								##  Use DER format for certificates to read from

gnutls-serv --dhparams=$File						##  DH params file to use  (file must pre-exist)
gnutls-serv --x509cafile=$String					##  Certificate file or PKCS #11 URL to use
gnutls-serv --x509crlfile=$File						##  CRL file to use   (file must pre-exist)

gnutls-serv --x509keyfile=$String				##  X.509 key file or PKCS #11 URL to use

gnutls-serv --x509certfile=$String				##  X.509 Certificate file or PKCS #11 URL to use

gnutls-serv --rawpkkeyfile=$String				##  Private key file (PKCS #8 or PKCS #12) or PKCS #11 URL to use

gnutls-serv --rawpkfile=$String					##  Raw public-key file to use




$File


gnutls-serv ---ocsp-response=str    The OCSP response to send to client

gnutls-serv --ignore-ocsp-response-errors  Ignore any errors when setting the OCSP response
gnutls-serv --port=num             The port to connect to
gnutls-serv --list                 Print a list of the supported algorithms and modes
gnutls-serv --provider=file        Specify the PKCS #11 provider library


--priority=SECURE256.









gnutls-serv --http --priority "NORMAL:+ANON-ECDH:+ANON-DH"

