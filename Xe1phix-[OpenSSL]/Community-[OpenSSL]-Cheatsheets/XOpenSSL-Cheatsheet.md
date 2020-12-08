General OpenSSL Commands
========================

These commands allow you to generate CSRs, Certificates, 
Private Keys and do other miscellaneous tasks.

## Generate a new private key and Certificate Signing Request
openssl req -out CSR.csr -new -newkey rsa:2048 -nodes -keyout privateKey.key

## Generate a self-signed certificate (see How to Create and Install an Apache Self Signed Certificate for more info)
openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout privateKey.key -out certificate.crt

## Generate a certificate signing request (CSR) for an existing private key
openssl req -out CSR.csr -key privateKey.key -new


## Generate a certificate signing request based on an existing certificate
openssl x509 -x509toreq -in certificate.crt -out CSR.csr -signkey privateKey.key


## Remove a passphrase from a private key
openssl rsa -in privateKey.pem -out newPrivateKey.pem


Checking Using OpenSSL
======================
If you need to check the information within a Certificate, 
CSR or Private Key, use these commands. You can also 
check CSRs and check certificates using our online tools.

## Check a Certificate Signing Request (CSR)
openssl req -text -noout -verify -in CSR.csr

## Check a private key
openssl rsa -in privateKey.key -check

## Check a certificate
openssl x509 -in certificate.crt -text -noout

## Check a PKCS#12 file (.pfx or .p12)
openssl pkcs12 -info -in keyStore.p12


Debugging Using OpenSSL
=======================

If you are receiving an error that the private doesn't match the certificate or that a certificate that you installed to a site is not trusted, try one of these commands. If you are trying to verify that an SSL certificate is installed correctly, be sure to check out the SSL Checker.

## Check an MD5 hash of the public key to ensure that it matches 
## with what is in a CSR or private key
openssl x509 -noout -modulus -in certificate.crt | openssl md5
openssl rsa -noout -modulus -in privateKey.key | openssl md5
openssl req -noout -modulus -in CSR.csr | openssl md5

## Check an SSL connection. All the certificates (including Intermediates) should be displayed
openssl s_client -connect www.paypal.com:443


Converting Using OpenSSL
========================

These commands allow you to convert certificates and keys to different formats 
to make them compatible with specific types of servers or software. 
For example, you can convert a normal PEM file that would work with Apache 
to a PFX (PKCS#12) file and use it with Tomcat or IIS. 
Use our SSL Converter to convert certificates without messing with OpenSSL.

## Convert a DER file (.crt .cer .der) to PEM
openssl x509 -inform der -in certificate.cer -out certificate.pem

## Convert a PEM file to DER
openssl x509 -outform der -in certificate.pem -out certificate.der

## Convert a PKCS#12 file (.pfx .p12) containing a private key and certificates to PEM
openssl pkcs12 -in keyStore.pfx -out keyStore.pem -nodes

## You can add `-nocerts` to only output the private key 
## or add `-nokeys` to only output the certificates.


## Convert a PEM certificate file and a private key to PKCS#12 (.pfx .p12)
openssl pkcs12 -export -out certificate.pfx -inkey privateKey.key -in certificate.crt -certfile CACert.crt




openssl x509 -subject -noout < "/etc/ssl/certs/Equifax_Secure_CA.pem"


openssl genpkey -algorithm RSA -out private/key.pem -pkeyopt rsa_keygen_bits:4096

openssl genpkey -aes-256-cbc -algorithm RSA -out private/key.pem -pkeyopt rsa_keygen_bits:4096


To obtain a certificate from a certificate authority, you need to create a Certificate Signing Request (CSR) and sign it with a previously generated private key:
openssl req -new -sha256 -key private/key.pem -out req.csr


To create a self-signed certificate with a previously generated private key:
openssl req -key private/key.pem -x509 -new -days 3650 -out selfcert.pem







openssl genrsa -out "${OUT}.key" 4096
    openssl req -new -key "${OUT}.key" -out "${OUT}.csr" \
        -subj '/C=US/ST=CA/L=San Francisco/O=Docker/CN=Notary Testing Client Auth'



openssl x509 -req -days 3650 -in "${OUT}.csr" -signkey "${OUT}.key" \
        -out "${OUT}.crt" -extfile "${OUT}.cnf" -extensions ssl_client



openssl genrsa -out "${OUT}.key" 4096
    openssl req -new -nodes -key "${OUT}.key" -out "${OUT}.csr" \
        -subj "/C=US/ST=CA/L=San Francisco/O=Docker/CN=${COMMONNAME}" \
        -config "${OUT}.cnf" -extensions "v3_req"
    openssl x509 -req -days 3650 -in "${OUT}.csr" -signkey "${OUT}.key" \
        -out "${OUT}.crt" -extensions v3_req -extfile "${OUT}.cnf"




 and openssl (one-liner)
server$ while true; do read -n30 ui; echo $ui |openssl enc -aes-256-ctr -a -k PaSSw; done | nc -l -p 8877 | while read so; do decoded_so=`echo "$so"| openssl enc -d -a -aes-256-ctr -k PaSSw`; 
openssl rand -base64 6
openssl s_client -starttls smtp -crlf -connect 127.0.0.1
echo | openssl s_client -connect www.google.com
openssl s_client -connect [host]
function brainwallet_checksum () { (o='openssl sha256 -binary'; p='printf';($p %b "\x80";$p %s "$1"|$o)|$o|sha256sum|cut -b1-8); }
openssl rand -base64 <length>
# Encrypted archive with openssl and tar
tar c folder_to_encrypt | openssl enc -aes-256-cbc -e > secret.tar.enc
# Encrypted archive with openssl and tar
tar --create --file - --posix --gzip -- <dir> | openssl enc -e -aes256 -out <file>
openssl enc -aes-256-ctr -pass pass
grep -ioE "(url\(|src=)['\"]?[^)'\"]*" a.html | grep -ioE "[^\"'(]*.(jpg|png|gif)" | while read l ; do sed -i "s>$l>data
echo -n 'text to be encrypted' | openssl md5
openssl rand -hex 6 | sed 's/\(..\)/\1
echo $(openssl rand 4 | od -DAn)
cmdfu(){ curl "http
cat /etc/passwd | openssl aes-256-cbc -a -e -pass pass
step3() { s=$(echo -n $b | openssl dgst -sha1 -hmac $hmac -binary | openssl base64); signature=`for((i=0;i<${#s};i++)); do case ${s
