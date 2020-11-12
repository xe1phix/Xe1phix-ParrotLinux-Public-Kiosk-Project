







## generate a CA:
certtool --generate-privkey > x509-ca-key.pem


echo 'cn = GnuTLS test CA' > ca.tmpl
echo 'ca' >> ca.tmpl
echo 'cert_signing_key' >> ca.tmpl


certtool --generate-self-signed --load-privkey x509-ca-key.pem   --template ca.tmpl --outfile x509-ca.pem



certtool --generate-privkey > x509-server-key.pem


echo 'organization = GnuTLS test server' > server.tmpl
echo 'cn = test.gnutls.org' >> server.tmpl
echo 'tls_www_server' >> server.tmpl
echo 'encryption_key' >> server.tmpl
echo 'signing_key' >> server.tmpl
echo 'dns_name = test.gnutls.org' >> server.tmpl


certtool --generate-certificate --load-privkey x509-server-key.pem   --load-ca-certificate x509-ca.pem --load-ca-privkey x509-ca-key.pem   --template server.tmpl --outfile x509-server.pem
           
           
## generate a client certificate as well.
certtool --generate-privkey > x509-client-key.pem


echo 'cn = GnuTLS test client' > client.tmpl
echo 'tls_www_client' >> client.tmpl
echo 'encryption_key' >> client.tmpl
echo 'signing_key' >> client.tmpl


certtool --generate-certificate --load-privkey x509-client-key.pem --load-ca-certificate x509-ca.pem --load-ca-privkey x509-ca-key.pem   --template client.tmpl --outfile x509-client.pem


## To be able to import the client key/certificate into some applications, you will need to convert them into a
## PKCS#12 structure.  This also encrypts the security sensitive key with a password.
certtool --to-p12 --load-ca-certificate x509-ca.pem --load-privkey x509-client-key.pem --load-certificate x509-client.pem   --outder --outfile x509-client.p12
           

           
## start the server again:
gnutls-serv --http --x509cafile x509-ca.pem --x509keyfile x509-server-key.pem --x509certfile x509-server.pem
           
           
           
           
           
           
## create a DSA key and certificate for the server      
certtool --generate-privkey --dsa > x509-server-key-dsa.pem
certtool --generate-certificate --load-privkey x509-server-key-dsa.pem --load-ca-certificate x509-ca.pem --load-ca-privkey x509-ca-key.pem   --template server.tmpl --outfile x509-server-dsa.pem
           
           
           
           
           
           
           
           
           
           
           
           
           
           
           
           

















openssl s_client -connect $host </dev/null 2>/dev/null | openssl x509 -in /dev/stdin -noout -fingerprint $fprtype

openssl s_client -connect $host </dev/null 2>/dev/null | openssl x509 -in /dev/stdin -noout -fingerprint



-tls1_2

openssl ciphers -V

openssl nseq 
-toseq              ## Output NS Sequence file
-in $infile         ## Input file
-out $outfile       ## Output file






## Create an OCSP request and write it to a file:
openssl ocsp -issuer issuer.pem -cert c1.pem -cert c2.pem -reqout req.der


## Send a query to an OCSP responder with URL 
## http://ocsp.myhost.com/ 
## save the response to a file, 
## print it out in text form, 
## and verify the response:
openssl ocsp -issuer issuer.pem -cert c1.pem -cert c2.pem -url http://ocsp.myhost.com/ -resp_text -respout resp.der


## Read in an OCSP response and print out text form:
openssl ocsp -respin resp.der -text -noverify


## OCSP server on port 8888 using a standard ca configuration, 
## and a separate responder certificate. 
## All requests and responses are printed to a file.
openssl ocsp -index demoCA/index.txt -port 8888 -rsigner rcert.pem -CA demoCA/cacert.pem -text -out log.txt


## As above but exit after processing one request:
openssl ocsp -index demoCA/index.txt -port 8888 -rsigner rcert.pem -CA demoCA/cacert.pem -nrequest 1


## Query status information using an internally generated request:
openssl ocsp -index demoCA/index.txt -rsigner rcert.pem -CA demoCA/cacert.pem -issuer demoCA/cacert.pem -serial 1


## Query status information using request read from a file, 
## and write the response to a second file.
openssl ocsp -index demoCA/index.txt -rsigner rcert.pem -CA demoCA/cacert.pem -reqin req.der -respout resp.der



## 
gnutls-cli


## 
gnutls_key_generate



## list the ciphersuites in a priority string:
gnutls-cli --priority SECURE192 -l


## view all tokens in your system use:
p11tool --list-tokens


## view all objects in a token use:
p11tool --login --list-all "pkcs11:TOKEN-URL"








p11tool --login --list-certs "pkcs11:model=PKCS15;manufacturer=MyMan;serial=1234;token=Test"

MYCERT="pkcs11:model=PKCS15;manufacturer=MyMan;serial=1234;token=Test;object=client;type=cert"
MYKEY="pkcs11:model=PKCS15;manufacturer=MyMan;serial=1234;token=Test;object=client;type=private"
export MYCERT MYKEY


## 
gnutls-cli www.example.com --x509keyfile $MYKEY --x509certfile $MYCERT
           
           



## Connecting to STARTTLS services
## You could also use the client to connect to services with starttls capability.
gnutls-cli --starttls-proto smtp --port 25 localhost



## debug services with starttls capability.
gnutls-cli-debug --starttls-proto smtp --port 25 localhost


## 
gnutls-cli-debug --verbose localhost


