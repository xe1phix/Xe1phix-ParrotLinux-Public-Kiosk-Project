#!/bin/sh


 *  **PKI**: Public Key Infrastructure. This describes the collection of files
    and associations between the CA, keypairs, requests, and certificates.
 *  **CA**: Certificate Authority. This is the "master cert" at the root of a
    PKI.
 *  **cert**: Certificate. A certificate is a request that has been signed by a
    CA. The certificate contains the public key, some details describing the
    cert itself, and a digital signature from the CA.
 *  **request**: Certificate Request (optionally 'req'.) This is a request for a
    certificate that is then send to a CA for signing. A request contains the
    desired cert information along with a digital signature from the private
    key.
 *  **keypair**: A keypair is an asymmetric cryptographic pair of keys. These
    keys are split into two parts: the public and private keys. The public key
    is included in a request and certificate.


##-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~--##

##-==============================================================-##
##   [+] ~+~|~+~|-+~|~+~|-+~|~+~|-+~|~+~|-+~|~+~|-+~|~+~|-+~ ##




##-====================================================-##
##-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~--##
##-==============================================================-##
##   [+]          <<------------------------->>
##-==============================================================-##
##   [+]              Generation of Ciphers
##-==============================================================-##
##   [+]          <<------------------------->>
##=<-------------------------------------------------->=##
##-====================================================-##




echo "## ===================================================== ##"
echo "               [+] Generation of Ciphers:		             "
echo "## ===================================================== ##"
echo "##~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~##"


echo -e "<<+}========================================={+>>"
echo -e "        {+} Execution File Permissions      "
echo -e "<<+}========================================={+>>"

##-==============================================================-##
##   [+] Generate an RSA private key using default parameters:

openssl genpkey -algorithm RSA -out key.pem


echo -e "<<+}========================================={+>>"
echo -e "        {+} 							      "
echo -e "<<+}========================================={+>>"


echo -e "<<+}========================================={+>>"
echo -e "        {+} 							      "
echo -e "<<+}========================================={+>>"




echo "##~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~##"


##-==============================================================-##
##   [+] Generate an RSA private key using default parameters:
openssl genpkey -algorithm RSA -out key.pem









echo "## ===================================================== ##"
echo "               [+] Download A Cipher File:		             "
echo "		.asc | x509 | PEM | DER | TLS | SSL | GPG | Keyring |   "
echo "                  .DIGESTS | .DIGESTS.asc                     "
echo "## ===================================================== ##"
echo "##~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~##"



echo -e "<<+}========================================={+>>"
echo -e "        {+} 							      "
echo -e "<<+}========================================={+>>"


echo -e "<<+}========================================={+>>"
echo -e "        {+} 							      "
echo -e "<<+}========================================={+>>"


echo -e "<<+}========================================={+>>"
echo -e "        {+} 							      "
echo -e "<<+}========================================={+>>"


echo -e "<<+}========================================={+>>"
echo -e "        {+} 							      "
echo -e "<<+}========================================={+>>"












##-==============================================================-##
##   [+] Encrypt output private key using 128 bit AES and the passphrase "hello":
openssl genpkey -algorithm RSA -out key.pem -aes-256-cbc -pass pass:hello



echo -e "<<+}========================================={+>>"
echo -e "        {+} 							      "
echo -e "<<+}========================================={+>>"


echo -e "<<+}========================================={+>>"
echo -e "        {+} 							      "
echo -e "<<+}========================================={+>>"


echo -e "<<+}========================================={+>>"
echo -e "        {+} 							      "
echo -e "<<+}========================================={+>>"


echo -e "<<+}========================================={+>>"
echo -e "        {+} 							      "
echo -e "<<+}========================================={+>>"


echo -e "<<+}========================================={+>>"
echo -e "        {+} 							      "
echo -e "<<+}========================================={+>>"


echo -e "<<+}========================================={+>>"
echo -e "        {+} 							      "
echo -e "<<+}========================================={+>>"


echo -e "<<+}========================================={+>>"
echo -e "        {+} 							      "
echo -e "<<+}========================================={+>>"


echo -e "<<+}========================================={+>>"
echo -e "        {+} 							      "
echo -e "<<+}========================================={+>>"






echo "## ===================================================== ##"
echo "               [+] Converting Ciphers:		             "
echo "## ===================================================== ##"
echo "##~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~##"





##-==============================================================-##
##   [+] PEM to DER
openssl x509 -in cert.crt -outform der -out cert.der

##-==============================================================-##
##   [+] DER to PEM
openssl x509 -in cert.crt -inform der -outform pem -out cert.pem







echo "## ===================================================== ##"
echo "          [+] Aquiring Cryptographic Signatures:	         "
echo "## ===================================================== ##"
echo "##~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~##"






gpg --fetch-keys $key.asc

wget -q -O - http://archive.kali.org/archive-key.asc | gpg --import

wget -q -O - http://<URLPathToFile>.asc | gpg --import

curl --verbose --progress-bar --tlsv1 --url https://raw.githubusercontent.com/Security-Onion-Solutions/security-onion/master/KEYS --output /home/faggot/Gnupg/KEYS

curl https://getfedora.org/static/fedora.gpg | gpg --import





curl --tlsv1.2 --url https://keys.qubes-os.org/keys/qubes-master-signing-key.asc --verbose --output /home/faggot/Gnupg/qubes-master-signing-key.asc | gpg --import 








curl --proxy http://
curl --proxy socks4a://
curl --proxy --socks4a
curl --proxy socks5://

curl --socks5 HOST[:PORT]
curl --socks5 127.0.0.1:9150

curl --resolve <host:port:address>

curl --resolve 127.0.0.1:4444:http://killyourtv.i2p/killyourtv.asc 










curl --verbose --progress-bar --tlsv1 --url https://geti2p.net/_static/debian-repo.pub --output /home/amnesia/Gnupg/debian-repo.pub && apt-key add /home/amnesia/Gnupg/debian-repo.pub
curl --verbose --progress-bar --tlsv1 --url https://tails.boum.org/tails-signing.key --output /home/amnesia/Gnupg/tails-signing.key && apt-key add /home/amnesia/Gnupg/tails-signing.key
curl --verbose --progress-bar --tlsv1 --url https://www.whonix.org/patrick.asc --output /home/amnesia/Gnupg/patrick.asc && apt-key add /home/amnesia/Gnupg/patrick.asc
curl --verbose --progress-bar --tlsv1 --url https://ftp-master.debian.org/keys/archive-key-7.0.asc --output /home/amnesia/Gnupg/archive-key-7.0.asc && apt-key add /home/amnesia/Gnupg/archive-key-7.0.asc



curl --verbose --progress-bar --tlsv1 --url https://sks-keyservers.net/sks-keyservers.netCA.pem --output /home/amnesia/Gnupg/sks-keyservers.netCA.pem
curl --verbose --progress-bar --tlsv1 --url https://sks-keyservers.net/sks-keyservers.netCA.pem.asc --output /home/amnesia/Gnupg/sks-keyservers.netCA.pem.asc && apt-key add /home/amnesia/Gnupg/sks-keyservers.netCA.pem.asc
curl --verbose --progress-bar --tlsv1 --url https://sks-keyservers.net/ca/crl.pem --output /home/amnesia/Gnupg/crl.pem






pkeyutl
rsautl
x509
genpkey
pkcs7
pkeyutl
gendsa
pkcs12
verify
x509v3_config
ca
req
CA.pl
spkac
config
X509v3
crypto
signver
openssl-verify
openssl-rsautl
openssl-rand



echo "##~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~##"
echo "## =============================================================== ##"
echo "                  [+] Hashing Files With OpenSSL:	                   "
echo "## =============================================================== ##"
echo "##~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~##"

openssl dgst -sha1 Xe1phix.asc
openssl dgst -sha256 Xe1phix.asc
openssl dgst -sha512 Xe1phix.asc


openssl dgst -sha256 Xe1phix.asc
openssl dgst -sha256 Xe1phix.asc > Xe1phix.asc.sha256
ls
openssl dgst -sha512 Xe1phix.asc > Xe1phix.asc.sha512
openssl dgst -sha1 Xe1phix.asc > Xe1phix.asc.sha1
sha1sum Xe1phix.asc > sha1sum && sha256sum Xe1phix.asc > sha256sum && sha512sum Xe1phix.asc > sha512sum



openssl dgst -sha1 Xe1phix-GnuPG-Fingerprints.txt > Xe1phix-GnuPG-Fingerprints.txt.sha1
openssl dgst -sha256 Xe1phix-GnuPG-Fingerprints.txt > Xe1phix-GnuPG-Fingerprints.txt.sha256
openssl dgst -sha512 Xe1phix-GnuPG-Fingerprints.txt > Xe1phix-GnuPG-Fingerprints.txt.sha512

openssl dgst -sha1 Xe1phix-GnuPG-Fingerprints.txt.asc > Xe1phix-GnuPG-Fingerprints.txt.asc.sha1
openssl dgst -sha256 Xe1phix-GnuPG-Fingerprints.txt.asc > Xe1phix-GnuPG-Fingerprints.txt.asc.sha256
openssl dgst -sha512 Xe1phix-GnuPG-Fingerprints.txt.asc > Xe1phix-GnuPG-Fingerprints.txt.asc.sha512

openssl dgst -sha1 Xe1phix-GnuPG-Hashsums.txt > Xe1phix-GnuPG-Hashsums.txt.sha1
openssl dgst -sha256 Xe1phix-GnuPG-Hashsums.txt > Xe1phix-GnuPG-Hashsums.txt.sha256
openssl dgst -sha512 Xe1phix-GnuPG-Hashsums.txt > Xe1phix-GnuPG-Hashsums.txt.sha512

openssl dgst -sha1 Xe1phix-GnuPG-Hashsums.txt.asc > Xe1phix-GnuPG-Hashsums.txt.asc.sha1
openssl dgst -sha256 Xe1phix-GnuPG-Hashsums.txt.asc > Xe1phix-GnuPG-Hashsums.txt.asc.sha256
openssl dgst -sha512 Xe1phix-GnuPG-Hashsums.txt.asc > Xe1phix-GnuPG-Hashsums.txt.asc.sha512

openssl dgst -sha1 Xe1phixCollection-v8.4.asc > Xe1phixCollection-v8.4.asc.sha1
openssl dgst -sha256 Xe1phixCollection-v8.4.asc > Xe1phixCollection-v8.4.asc.sha256
openssl dgst -sha512 Xe1phixCollection-v8.4.asc > Xe1phixCollection-v8.4.asc.sha512

openssl dgst -sha1 Xe1phixSources-v2.7.list > Xe1phixSources-v2.7.list.sha1
openssl dgst -sha256 Xe1phixSources-v2.7.list > Xe1phixSources-v2.7.list.sha256
openssl dgst -sha512 Xe1phixSources-v2.7.list > Xe1phixSources-v2.7.list.sha512

openssl dgst -sha1 Xe1phixSources-v2.7.list.asc > Xe1phixSources-v2.7.list.asc.sha1
openssl dgst -sha256 Xe1phixSources-v2.7.list.asc > Xe1phixSources-v2.7.list.asc.sha256
openssl dgst -sha512 Xe1phixSources-v2.7.list.asc > Xe1phixSources-v2.7.list.asc.sha512

openssl dgst -sha1 0x8C2731DD2541089E88181251760286DD6EC3F80D.asc > 0x8C2731DD2541089E88181251760286DD6EC3F80D.asc.sha1
openssl dgst -sha256 0x8C2731DD2541089E88181251760286DD6EC3F80D.asc > 0x8C2731DD2541089E88181251760286DD6EC3F80D.asc.sha256
openssl dgst -sha512 0x8C2731DD2541089E88181251760286DD6EC3F80D.asc > 0x8C2731DD2541089E88181251760286DD6EC3F80D.asc.sha512




openssl dgst -sha1 > .sha1
openssl dgst -sha256 > .sha256
openssl dgst -sha512  > .sha512

openssl dgst -sha1 > .sha1
openssl dgst -sha256 > .sha256
openssl dgst -sha512  > .sha512




echo "##~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~##"
echo "## =============================================================== ##"
echo "    [+] Encrypting And Decrypting Files With OpenSSL:	   "
echo "## =============================================================== ##"
echo "##~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~##"








##-===============================================-##
##-==============================================================-##
##   [+]   [+] 

gpg --output doc.sig --sign doc
gpg --output doc.sig --clearsign doc
gpg --output doc.sig --detach-sig doc


##-===============================================-##
##-==============================================================-##
##   [+]   [+] create a self-signed (CA) certificate, use the following command:
openssl req -new -x509 -days 365 -key ca.key -out ca.crt

##-===============================================-##
##-==============================================================-##
##   [+]   [+] signs the log output containing the MD5 hash
gpg --clearsign hash.log
gpgsm -a -r holmes@digitalforensics.ch -o hash.log.pem --sign hash.log


##-===============================================-##
##-==============================================================-##
##   [+]   [+] verify the gpg signature of the person who signed the acquired disk image:
gpg < hash.log.asc

##-===============================================-##
##-==============================================================-##
##   [+]   [+] S/MIME signed messages, 

##-===============================================-##
##-==============================================================-##
##   [+]   [+] Validate the signature from a PEM file
gpgsm --verify image.log.pem


##-===============================================-##
##-==============================================================-##
##   [+]   [+] encrypt an image with 256-bit AES using cipher block chaining mode
openssl enc -aes-256-cbc -in image.raw -out image.raw.aes

##-===============================================-##
##-==============================================================-##
##   [+]   [+] perform encryption during acquisition
dcfldd if=/dev/sdg | openssl enc -aes-256-cbc > image.raw.aes


##-===============================================-##
##-==============================================================-##
##   [+]   [+] Decrypting an OpenSSL-encrypted file
openssl enc -d -aes-256-cbc -in image.raw.aes -out image.raw


##-===============================================-##
##-==============================================================-##
##   [+]   [+] add gzip compression on the fly during an acquisition:
dcfldd if=/dev/sdg | gzip | openssl enc -aes-256-cbc > image.raw.gz.aes



##-===============================================-##
##-==============================================================-##
##   [+]   [+] verify the cryptographic hash of the image
openssl enc -d -aes-256-cbc < image.raw.gz.aes | gunzip | sha256sum







##-===============================-##
##-==============================================================-##
##   [+]     [+] Encrypt and decrypt:
##-===============================-##
# openssl aes‐128‐cbc ‐salt ‐in file ‐out file.aes
# openssl aes‐128‐cbc ‐d ‐salt ‐in file.aes ‐out file


##-===============================================-##
##-==============================================================-##
##   [+]   [+] tar and encrypt a whole directory
##-===============================================-##
# tar ‐cf ‐ directory | openssl aes‐128‐cbc ‐salt ‐out directory.tar.aes      ## Encrypt
# openssl aes‐128‐cbc ‐d ‐salt ‐in directory.tar.aes | tar ‐x ‐f ‐            ## Decrypt

##-===============================================-##
##-==============================================================-##
##   [+]   [+] tar zip and encrypt a whole directory:
##-===============================================-##
tar ‐zcf ‐ directory | openssl aes‐128‐cbc ‐salt ‐out directory.tar.gz.aes      ## Encrypt
openssl aes‐128‐cbc ‐d ‐salt ‐in directory.tar.gz.aes | tar ‐xz ‐f ‐            ## Decrypt



##-==============================================================-##
##   [+] Use ­k mysecretpassword after aes­128­cbc 
##-==============================================================-##
##   [+] to avoid the interactive password request. 
##-==============================================================-##
##   [+] However note that this is highly insecure.

##-==============================================================-##
##   [+] Use aes­256­cbc instead of aes­128­cbc 
##-==============================================================-##
##   [+] to get even stronger encryption. 








openssl enc -help





openssl smime -verify -in SMIME-SIGNED-E-MAIL -noverify -pk7out > SMIME-SIGNED-E-MAIL.pk7
openssl pkcs7 -print_certs -in SMIME-SIGNED-E-MAIL.pk7 > SMIME-SIGNED-E-MAIL.pem
openssl x509 -in SMIME-SIGNED-E-MAIL.pem -noout -hash
cp SMIME-SIGNED-E-MAIL.pem ~/.smime/certificates/
$(openssl x509 -in SMIME-SIGNED-E-MAIL.pem -noout -hash)".0"
echo $(openssl x509 -in SMIME-SIGNED-E-MAIL.pem -noout -email) 
$(openssl x509 -in SMIME-SIGNED-E-MAIL.pem -noout -hash)".0" 
ALIAS >> ~/.smime/certificates/.index






##-==============================================================-##
##   [+] The manual way: 
##-==============================================================-##
##   [+] Create key locally (using OpenSSL) 
##-==============================================================-##
##   [+] and get certificate with CSR


##-==========================================================================-##
##-==============================================================-##
##   [+]  ~> $file.key      ## Contains the private key (from Step_1&2)
##-==============================================================-##
##   [+]  ~> $file.crt      ## The server-generated certificate (from Step_3)
##-==============================================================-##
##   [+]  ~> $root.pem      ## The CAcert root certificate
##-==========================================================================-##



##-===============================================-##
##-==============================================================-##
##   [+]              [+] Generate the key
##-===============================================-##


##-======================================================-##
##-==============================================================-##
##   [+]   [+] Create the CSR - Certificate Signing Request 
##-======================================================-##
openssl req -nodes -newkey rsa:4096 -keyout my.key -out my.csr


##-===============================================-##
##-==============================================================-##
##   [+]          [+] Prepare A PKCS12 File:
##-==============================================================-##
##   [+]  (including the root certificate of the CA)
##-===============================================-##
openssl pkcs12 -export -in my.crt -inkey my.key -in root.pem -out my.p12


##-===============================================-##
##-==============================================================-##
##   [+]   [+] 
##-===============================================-##
openssl pkcs12 -export -in my.crt -inkey my.key -out my.p12









##-===============================================-##
##-==============================================================-##
##   [+]   [+] Sign some data using a private key:
openssl pkeyutl -sign -in file -inkey key.pem -out sig


##-==============================================================-##
##   [+] Recover the signed data (e.g. if an RSA key is used):
openssl pkeyutl -verifyrecover -in sig -inkey key.pem


##-==============================================================-##
##   [+] Verify the signature (e.g. a DSA key):
openssl pkeyutl -verify -in file -sigfile sig -inkey key.pem


##-==============================================================-##
##   [+] Sign data using a message digest value (this is currently only valid for RSA):
openssl pkeyutl -sign -in file -inkey key.pem -out sig -pkeyopt digest:sha256


##-==============================================================-##
##   [+] Derive a shared secret value:
openssl pkeyutl -derive -inkey key.pem -peerkey pubkey.pem -out secret


##-===========================================================-##
##-==============================================================-##
##   [+]   [+] Hexdump 48 bytes of TLS1 PRF using digest SHA256
##-==============================================================-##
##   [+]       As Well as: shared secret + seed consisting of
##-==============================================================-##
##   [+]       The single byte 0xFF:
##-===========================================================-##
openssl pkeyutl -kdf TLS1-PRF -kdflen 48 -pkeyopt md:SHA256 -pkeyopt hexsecret:ff -pkeyopt hexseed:ff -hexdump





psktool
gnutls-cli-debug
gnutls-serv
srptool
gnutls-cli
danetool
tpmtool
Net::DNS::RR::TLSA
ocsptool
p11tool



echo "##~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~##"
echo "## =============================================================== ##"
echo "    [+] Verifying The Integrity of The Cryptographic Signatures:	   "
echo "## =============================================================== ##"
echo "##~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~##"





# Check the SSL certificate fingerprint (it should match the ones given in this file):
cat ${HOME}/${HOST}.pem | openssl x509 -fingerprint -noout -in /dev/stdin






##-==============================================================-##
##   [+] Download this file (https://blog.patternsinthevoid.net/isis.txt):
wget -q --ca-certificate=${HOST}.pem https://${HOST}/isis.txt



##-==============================================================-##
##   [+] Check signature and import key:
gpg -o isis -v isis.txt && gpg --import isis




echo "## ===================================================== ##"
echo "          [+] Importing Cryptographic Signatures:	         "
echo "## ===================================================== ##"
echo "##~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~##"


gpg --keyid-format long --import tails-signing.key

gpg --keyid-format long --import debian-repo.pub
gpg --keyid-format long --import cisofy-software.pub

apt-key add debian-repo.pub
gpg --import patrick.asc


gpg --import qubes-master-signing-key.asc && apt-key add qubes-master-signing-key.asc && gpg --export 427F11FD0FAA4B080123F01CDDFA1A3E36879494










echo "##~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~##"
echo "## =============================================================== ##"
echo "   		 [+] Signing The Cryptographic Signatures:	   				"
echo "## =============================================================== ##"
echo "##~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~##"












##-==============================================================-##
##   [+] generates a new public-private key pair and certificate

signtool option -G 





##-==============================================================-##
##   [+] Set security level to 2 
##-==============================================================-##
##   [+]       Display all ciphers consistent with level 2:

openssl ciphers -s -v 'ALL:@SECLEVEL=2'








keyrings

keyutils
persistent-keyring
user-keyring
user-session-keyring
user-namespaces
request-key
credentials




echo "##~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~##"
echo "## =============================================================== ##"
echo "   		    [+] Print Certificate Fingerprints :	   			   "
echo "## =============================================================== ##"
echo "##~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~##"



##-==============================================================-##
##   [+] View information about a given SSL certificate, stored in a PEM file.
openssl x509 -text -in $File


cp newca.pem /usr/share/ssl/certs
/usr/bin/c_rehash


$OPENSSL x509 -hash -fingerprint -noout -in $File
$OPENSSL crl -hash -fingerprint -noout -in $File


##-==============================================================-##
##   [+] Output the text form of a DER encoded certificate:
openssl crl -in crl.der -text -noout


##-==============================================================-##
##   [+] 
keytool -list -keystore java.home/lib/security/cacerts


##-==============================================================-##
##   [+] 
keytool -printcert -file $file



##-==============================================================-##
##   [+] view the certificate information simply do:


openssl x509 ‐text ‐in servernamecert.pem           ## View the certificate info
openssl req ‐noout ‐text ‐in server.csr             ## View the request info
openssl s_client ‐connect cb.vu:443                 ## Check a web server certificate






##-==============================================================-##
##   [+] Print some info about a PKCS#12 file:
openssl pkcs12 -in $file.p12 -info -noout -fingerprint


##-==============================================================-##
##   [+] Calculate the fingerprint of RiseupCA.pem:

certtool -i < RiseupCA.pem |egrep -A 1 'SHA256 fingerprint'


##-==============================================================-##
##   [+] 
openssl x509 -sha256 -in RiseupCA.pem -noout -fingerprint


##-==============================================================-##
##   [+] 
head -n -1 RiseupCA.pem | tail -n +2 | base64 -d | sha256sum


##-==============================================================-##
##   [+] 
sudo openvpn --client --dev tun --auth-user-pass --remote vpn.riseup.net 1194 --keysize 256 --auth SHA256 --cipher AES-256-CBC --ca RiseupCA.pem 














 
 
 
##-==============================================================-##
##   [+] 
sudo openssl req -newkey rsa:4096 -keyout /etc/openvpn/vpn-key.pem -out vpn.csr

##-==============================================================-##
##   [+] 
sudo openssl req -newkey rsa:4096 -keyout /etc/openvpn/ClientVPNKey.pem -out /etc/openvpn/ClientVPNKey.csr


##-==============================================================-##
##   [+] 

echo 'OpenVPN' | sha256sum | cut -c1-20

echo 'ClientVPN' | sha256sum | cut -c1-20
echo 'Challenge' | sha256sum | cut -c1-20





##-==============================================================-##
##   [+] 

sudo openssl req -newkey rsa:4096 -keyout /etc/openvpn/ServerVPNKey.pem -out ServerVPNKey.csr

echo 'ServerVPN' | sha256sum | cut -c1-20
echo 'Challenge' | sha256sum | cut -c1-20


##-==============================================================-##
##   [+] 

openssl x509 -CA cacert.pem -CAkey cakey.pem -CAcreateserial -days 730 -req -in ClientVPNKey.csr -out ClientVPNKey.pem


Please enter the following 'extra' attributes
to be sent with your certificate request
A challenge password []:

echo -n 'poop' | sha1sum | cut -c1-20



##-==============================================================-##
##   [+] On your CAs environment (hopefully elsewhere):

openssl x509 -CA cacert.pem -CAkey cakey.pem -CAcreateserial -days 730 -req -in vpn.csr -out vpn-cert.pem


##-==============================================================-##
##   [+] 

./easy-rsa.sh --batch build-ca nopass
chown nobody:$GROUPNAME /etc/openvpn/crl.pem


##-==============================================================-##
##   [+] 

sudo openssl dhparam -out /etc/openvpn/dh4096.pem 4096
sudo cp -v dh4096.pem /etc/openvpn/dh2048.pem



##-==============================================================-##
##   [+] 

sudo openssl dhparam -out /etc/openvpn/ClientVPN-dh4096.pem 4096


##-==============================================================-##
##   [+] 

sudo openssl dhparam -out /etc/openvpn/ServerVPN-dh4096.pem 4096




##-==============================================================-##
##   [+] 

openssl x509 -in cert.pem -addtrust clientAuth -setalias "Steve's Class 1 CA" -out trust.pem



##-==============================================================-##
##   [+] 

genrsa -aes256 -out numbits 512





##-==============================================================-##
##   [+] Download this file (https://blog.patternsinthevoid.net/isis.txt):
wget -q --ca-certificate=${HOST}.pem https://${HOST}/isis.txt



##-==============================================================-##
##   [+] Check the SSL certificate fingerprint (it should match the ones given in this file):
cat ${HOME}/${HOST}.pem | openssl x509 -fingerprint -noout -in /dev/stdin


##-==============================================================-##
##   [+] Display the certificate SHA1 fingerprint:
openssl x509 -sha1 -in cert.pem -noout -fingerprint


##-==============================================================-##
##   [+] Check the SSL certificate fingerprint (it should match the ones given in this file):
cat .pem | openssl x509 -fingerprint -noout -in /dev/stdin


##-==============================================================-##
##   [+] 
openssl x509 -noout -issuer -subject -fingerprint -dates


##-==============================================================-##
##   [+] 

openssl s_client -connect  | openssl x509 -text

##-=============================================-##
##   [+] Connect To Google.com using OpenSSL
##   [+] Examine The x509 Certificate:
##-=============================================-##
echo | openssl s_client -connect www.google.com:443 2>/dev/null | openssl x509 -text


##-=======================================================-##
##   [+] Connect To Google using OpenSSL
##   [+] Print The x509 Certificates Date Information:
##-=======================================================-##
date +%s -d "$(echo | openssl s_client -connect www.google.com:443 2>/dev/null | openssl x509 -noout -dates | tail -1 | cut -f2 -d=)"


##-=========================================================-##
##   [+] Remove just the "notAfter" date from the output:
##-=========================================================-##
echo | openssl s_client -connect www.google.com:443 2>/dev/null | openssl x509 -noout -dates | tail -1 | cut -f2 -d=


##-==========================================-##
##   [+] dump the certificate information
##-==========================================-##
echo | openssl s_client -connect www.google.com:443 2>/dev/null | openssl x509 -noout -dates



##-==================================================-##
##   [+] Download the certificate for this server:
##-==================================================-##

HOST=blog.patternsinthevoid.net && PORT=443
openssl s_client -connect "${HOST}":"${PORT}" </dev/null 2>/dev/null | \
    sed -nr '/(-){5}(BEGIN CERTIFICATE){1}(-){5}/,/(-){5}(END CERTIFICATE){1}(-){5}/p' | \
    cat > ${HOME}/${HOST}.pem


##-=====================================================-##
##   [+] Check the SSL certificate fingerprint:
##-=====================================================-##
## ----------------------------------------------------- ##
##   [?] It should match the ones given in this file
## ----------------------------------------------------- ##
cat ${HOME}/${HOST}.pem | openssl x509 -fingerprint -noout -in /dev/stdin





openssl s_client -connect blog.patternsinthevoid.net:443 </dev/null 2>/dev/null | sed -nr '/(-){5}(BEGIN CERTIFICATE){1}(-){5}/,/(-){5}(END CERTIFICATE){1}(-){5}/p' | cat > ${HOME}/${HOST}.pem



echo "##===============================##"
echo "[+] This report that displays 	 "
echo "    The following attributes: 	 "
echo "##===============================##"

echo "#>-------------------------------<#"
echo "    -> certificate issuer			"
echo "#--------------------------------#"
echo "    -> certificate name			"
echo "#--------------------------------#"
echo "    -> fingerprint				"
echo "#--------------------------------#"
echo "    -> dates						"
echo "#--------------------------------#"
echo
echo "#>-------------------------------<#"
echo " [?] in addition to the dates:"
echo "#>-------------------------------<#"
echo | openssl s_client -connect www.google.com:443 2>/dev/null | openssl x509 -noout -issuer -subject -fingerprint -dates




##-==============================================================-##
##   [+] Check the certificate for the secure IMAP server
##-==============================================================-##
##   [+] Against the system trusted certificate list:
openssl s_client -quiet -CAfile /usr/share/ssl/cert.pem -connect mail.server.net:993



##-==============================================================-##
##   [+] check the certificate of a secure web site
openssl s_client -quiet -CAdir /usr/share/ssl/certs -connect www.yoyodyne.com:443



##-===================================================-##
##   [+] validate a certificate in a file cert.pem
##-===================================================-##
openssl validate -CA... -in cert.pem




##-==============================================================-##
##   [+] view info in an SSL certificate (Stored in .pem):
##-==============================================================-##
openssl x509 -text -in $File



##-==============================================================-##
##   [+] 
##-==============================================================-##
cp newca.pem /usr/share/ssl/certs
/usr/bin/c_rehash



##-==============================================================-##
##   [+] 
##-==============================================================-##
openssl x509 -hash -fingerprint -noout -in $File


##-==============================================================-##
##   [+] 
##-==============================================================-##
openssl crl -hash -fingerprint -noout -in $File


##-==============================================================-##
##   [+] Output the text form of a DER encoded certificate:
##-==============================================================-##
openssl crl -in crl.der -text -noout





##-==============================================================-##
##   [+] 
##-==============================================================-##
openssl s_client -connect "$1:$2" -CAfile $CACERTS -servername $1 < /dev/null 2> /dev/null


##-==============================================================-##
##   [+] 
##-==============================================================-##
openssl --insecure --print-cert --x509cafile "$CACERTS" "$1" -p "$2"  < /dev/null 2>/dev/null









##-==============================================================-##
##   [+] extract_fingerprints
##-==============================================================-##



##-==============================================================-##
##   [+]   [+] Roughly equivalent to 
##-==============================================================-##
##   [+] ----------------------------------------------------------------------- ##
##-==============================================================-##
##   [+] "grep -A1 "SHA-1 fingerprint" | head -n 2 | grep -o '[a-f0-9]{40}'"
##-==============================================================-##
##   [+] ----------------------------------------------------------------------- ##
certtool -i < $1 | sed -n '/SHA-1 fingerprint/{n;p;q}' | sed 's/\s\+\([a-f0-9]\{40\}\)/\1/'


##-==============================================================-##
##   [+] 
##-==============================================================-##
openssl x509 -in $1 -fingerprint -noout | normalize




##-==============================================================-##
##   [+] OpenSSL's format: Mar  7 16:08:35 2022 GMT
##-==============================================================-##
DATA=$(openssl x509 -enddate -noout -in $1 | cut -d'=' -f2-)



##-==============================================================-##
##   [+] Certtool's format: Mon Mar 07 16:08:35 UTC 2022
##-==============================================================-##
DATA=$(certtool -i < "$1" | sed -e '/Not\sAfter/!d' -e 's/^.*:\s\(.*\)/\1/')



##-==============================================================-##
##   [+] 
##-==============================================================-##
BITS=$(openssl x509 -text -noout -in $1 | sed -e '/Public-Key/!d' -e 's/\s\+Public-Key: (\([0-9]\+\) bit)/\1 bits/')


##-==============================================================-##
##   [+] 
##-==============================================================-##
BITS=$(certtool -i < $1 | sed -e '/^.*Algorithm Security Level/!d' -e 's/.*(\([0-9]\+\) bits).*/\1 bits/')




get_sigtype()
openssl x509 -text -noout -in $1 | sed -e '/Signature Algorithm/!d' -e 's/\s\+Signature Algorithm:\s\+\(.\+\)/\1/' | head -n1
certtool -i < $1 | sed -e '/^.*Signature Algorithm:/!d' -e 's/.*:\s\+\(.*\)/\1/'






##-==============================================================-##
##   [+] Sign a SSL Certificate Request (CSR)
##-==============================================================-##


##-==============================================================-##
##   [+] create an own SSLeay config
##-==============================================================-##



cat >ca.config <<EOT
[ ca ]
default_ca			= CA_own
[ CA_own ]
dir				= /usr/share/ssl
certs				= /usr/share/ssl/certs
new_certs_dir			= /usr/share/ssl/ca.db.certs
database			= /usr/share/ssl/ca.db.index
serial				= /usr/share/ssl/ca.db.serial
RANDFILE			= /usr/share/ssl/ca.db.rand
certificate			= /usr/share/ssl/certs/ca.crt
private_key			= /usr/share/ssl/private/ca.key
default_days			= 365
default_crl_days		= 30
default_md			= md5
preserve			= no
policy				= policy_anything
[ policy_anything ]
countryName			= optional
stateOrProvinceName 		= optional
localityName			= optional
organizationName		= optional
organizationalUnitName		= optional
commonName			= supplied
emailAddress			= optional
EOT




##-==============================================================-##
##   [+] sign the certificate
##-==============================================================-##


##-==============================================================-##
##   [+] CA signing: $CSR -> $CERT:
##-==============================================================-##
openssl ca -config ca.config -out $CERT -infiles $CSR


##-==============================================================-##
##   [+] CA verifying: $CERT <-> CA cert
##-==============================================================-##
openssl verify -CAfile /usr/share/ssl/certs/ca.crt $CERT



##-==============================================================-##
##   [+]   [+] Self-signing:
##-==============================================================-##
if [ "$KEYTYPE" == "ssl-self" ]; then
openssl x509 -in "${NODE}_csr.pem" -out "$NODE.crt" -req -signkey "${NODE}_privatekey.pem" -days 365

##-==============================================================-##
##   [+] 
##-==============================================================-##
chmod 600 "${NODE}_privatekey.pem"


##-==============================================================-##
##   [+] 
##-==============================================================-##
openssl req -batch -nodes -config openssl.conf -newkey rsa:4096 -sha256 -keyout ${NODE}_privatekey.pem -out ${NODE}_csr.pem


##-==============================================================-##
##   [+] 
##-==============================================================-##
openssl req -noout -text -in ${NODE}_csr.pem








##-==============================================================-##
##   [+] get an initial recipient
##-==============================================================-##
if [ -e "$HOME/.gnupg/gpg.conf" ]; then
    recipient="`grep -e "^default-key" ~/.gnupg/gpg.conf | cut -d ' ' -f 2`"


##-==============================================================-##
##   [+] Check the main key
##-==============================================================-##
gpg --with-colons --fixed-list-mode --list-keys "$recipient" | grep ^pub | cut -d : -f 7

##-==============================================================-##
##   [+] Check the subkeys
##-==============================================================-##
gpg --with-colons --fixed-list-mode --list-keys "$recipient" | grep ^sub | cut -d : -f 7


##-==============================================================-##
##   [+] 
##-==============================================================-##
key="`gpg --fingerprint --with-colons $recipient 2> /dev/null`"

##-==============================================================-##
##   [+] 
##-==============================================================-##
fpr="`echo "$key" | grep -e '^fpr:' | head -1 | cut -d : -f 10`"


##-==============================================================-##
##   [+] 
##-==============================================================-##
uid="`echo "$key" | grep -e '^uid:' | head -1 | cut -d : -f 10 | sed -e 's|^[^<]*<||' -e 's|>$||'`"





##-==============================================================-##
##   [+] Show cert fingerprint
##-==============================================================-##
if [ "$KEYTYPE" == "ssl-self" ]; then
    openssl x509 -noout -in "$TMPWORK/${NODE}.crt" -fingerprint








##-==============================================================-##
##   [+] Create a certificate authority
##-==============================================================-##
openssl req ‐new ‐x509 ‐days 730 ‐config /etc/ssl/openssl.cnf ‐keyout CA/private/cakey.pem ‐out CA/cacert.pem






##-==============================================================-##
##   [+] PKCS#10 certificate request
##-==============================================================-##



##-==============================================================-##
##   [+] Create a certificate signing request


openssl req ‐new ‐keyout newkey.pem ‐out newreq.pem ‐config /etc/ssl/openssl.cnf







##-==============================================================-##
##   [+]   [+] Sign the certificate


##-============================================-##
##-==============================================================-##
##   [+]   [?] The certificate request has to be 
##-==============================================================-##
##   [+]       signed by the CA to be valid

cat newreq.pem newkey.pem > new.pem
openssl ca ‐policy policy_anything ‐out servernamecert.pem ‐config /etc/ssl/openssl.cnf ‐infiles new.pem









##-=====================================================-##
##-==============================================================-##
##   [+]              [+] Create a private key 
##-==============================================================-##
##   [+]       Generate a certificate request from it:
##-=====================================================-##
openssl genrsa -out key.pem 4096
openssl req -new -key key.pem -out req.pem


##-=====================================================-##
##-==============================================================-##
##   [+]     [+] Examine and verify certificate request:

openssl req -in req.pem -text -verify -noout


##-=======================================================-##
##-==============================================================-##
##   [+]     [+] Generate a certificate request - using req:

openssl req -newkey rsa:4096 -keyout key.pem -out req.pem



##-=======================================================-##
##-==============================================================-##
##   [+]     [+] Generate a self signed root certificate:
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out req.pem


##-=======================================================-##
##-==============================================================-##
##   [+]     [+] Sign a certificate request, using CA extensions:
openssl ca -in req.pem -extensions v3_ca -out newcert.pem


##-=======================================-##
##-==============================================================-##
##   [+]     [+] Sign several requests:
openssl ca -infiles req1.pem req2.pem req3.pem









##-=======================================================-##
##-==============================================================-##
##   [+]     [+] Create some DSA parameters:
openssl dsaparam -out dsap.pem 1024


##-=======================================================-##
##-==============================================================-##
##   [+]     [+] Create a DSA CA certificate and private key:

openssl req -x509 -newkey dsa:dsap.pem -keyout cacert.pem -out cacert.pem


##-=======================================================================-##
##-==============================================================-##
##   [+]     [+] Create a DSA certificate request, as well as a private key 
##-==============================================================-##
##   [+] ----------------------------------------------------------------------- ##
##-==============================================================-##
##   [+]     (a different set of parameters can optionally be created first):
##-==============================================================-##
##   [+] ----------------------------------------------------------------------- ##
openssl req -out newreq.pem -newkey dsa:dsap.pem


##-==============================-##
##-==============================================================-##
##   [+]     [+] Sign the request:

CA.pl -signreq




##-==============================================================================-##
##-==============================================================-##
##   [+] ------------------------------------------------------------------------------ ##
##-==============================================================================-##


##-=======================================================================================-##
##-==============================================================-##
##   [+]                      [!] PKCS1-v1_5 padding for SHA256 signatures: [!]
##-=======================================================================================-##
##-==============================================================-##
##   [+] 
##		 as defined in RFC3447. It is prepended to the actual signature (32 bytes) to
##		 form a sequence of 256 bytes (2048 bits) that is amenable to RSA signing. The
##		 padded hash will look as follows:
#
##		    0x00 0x01 0xff ... 0xff 0x00  ASN1HEADER  SHA256HASH
##		   |--------------205-----------||----19----||----32----|
#
##		 where ASN1HEADER is the ASN.1 description of the signed data. The complete 51
##		 bytes of actual data (i.e. the ASN.1 header complete with the hash) are
##		 packed as follows:
#
##		  SEQUENCE(2+49) {
##		   SEQUENCE(2+13) {
##		    OBJECT(2+9) id-sha256
##		    NULL(2+0)
##		   }
##		   OCTET STRING(2+32) <actual signature bytes...>
##		  }
##-==============================================================-##
##   [+] 
##-=======================================================================================-##





##-==============================================================-##
##   [+] Parse a PKCS#12 file and output it to a file:
openssl pkcs12 -in file.p12 -out file.pem


##-==============================================================-##
##           [+] Print some info about a PKCS#12 file:
##-==============================================================-##
openssl pkcs12 -in file.p12 -info -noout



##-==============================================================-##
##                  [+] Create a PKCS#12 file:
##-==============================================================-##
openssl pkcs12 -export -in file.pem -out file.p12 -name "My Certificate"


##-==============================================================-##
##              [+] Include some extra certificates:
##-==============================================================-##
openssl pkcs12 -export -in file.pem -out file.p12 -name "My Certificate" -certfile othercerts.pem







##-===========================-##
##   [+] Generate a CRL
##-===========================-##
openssl ca -gencrl -out crl.pem










CA.pl -newca
CA.pl -newreq
CA.pl -signreq
CA.pl -pkcs12 "My Test Certificate"



-newcert				## 
-newreq				## 
-newca				## 
-pkcs12				## 
-crl				## 
				    ## 




-sign			## 
				## 
				## 
				## 
				## 
				## 
				## 
				## 




openssl req				## 
openssl pkcs12			## 
openssl ca				## 
openssl x509			## 

openssl verify




# padding for openssl rsautl -pkcs (smartcard keys)
#
# The following is an ASN.1 header. It is prepended to the actual signature
# (32 bytes) to form a sequence of 51 bytes. OpenSSL will add additional
# PKCS#1 1.5 padding during the signing operation. The padded hash will look
# as follows:
#
#    ASN1HEADER  SHA256HASH
#   |----19----||----32----|
#
# where ASN1HEADER is the ASN.1 description of the signed data. The complete 51
# bytes of actual data (i.e. the ASN.1 header complete with the hash) are
# packed as follows:
#
#  SEQUENCE(2+49) {
#   SEQUENCE(2+13) {
#    OBJECT(2+9) id-sha256
#    NULL(2+0)
#   }
#   OCTET STRING(2+32) <actual signature bytes...>
#  }


-in
-out
-text
-new
-pubkey
-verify

-newkey rsa





echo "##~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~##"
echo "## =============================================================== ##"
echo "                  [+] :	                   "
echo "## =============================================================== ##"
echo "##~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~##"






openssl rsautl -verify -in file -inkey ClientVPNKey.pem -raw -hexdump
openssl rsautl -verify -in sig -inkey ClientVPNKey.pem




openssl rsautl -sign -in file -inkey key.pem -out sig
openssl req -nodes -new -x509 -keyout ca.key -out ca.crt --genkey --secret xe1phix.key





openssl genrsa -out "${OUT}.key" 4096


openssl req -new -key "${OUT}.key" -out "${OUT}.csr" -subj '/C=US/ST=CA/L=San Francisco/O=Docker/CN=Notary Testing Client Auth'



openssl x509 -req -days 3650 -in "${OUT}.csr" -signkey "${OUT}.key" -out "${OUT}.crt" -extfile "${OUT}.cnf" -extensions ssl_client





openssl genrsa -out "${OUT}.key" 4096


openssl req -new -nodes -key "${OUT}.key" -out "${OUT}.csr" -subj "/C=US/ST=CA/L=San Francisco/O=Docker/CN=${COMMONNAME}" -config "${OUT}.cnf" -extensions "v3_req"


openssl x509 -req -days 3650 -in "${OUT}.csr" -signkey "${OUT}.key" -out "${OUT}.crt" -extensions v3_req -extfile "${OUT}.cnf"









echo "## ================================================ ##"
echo "## 		[+] Generate key for tls-auth				"
echo "## ================================================ ##"
openvpn --genkey --secret /etc/openvpn/ta.key


##-============================================-##
##   [+] In the server configuration, add:
##-============================================-##
tls-auth ta.key 0

##-============================================-##
##   [+] In the client configuration, add:
##-============================================-##
tls-auth ta.key 1












##-==============================================================-##
##   [+] Convert a certificate from PEM to DER format:
##-==============================================================-##
openssl x509 -in cert.pem -inform PEM -out cert.der -outform DER









echo "## ================================================ ##"
echo "## [+] Change The Permissions to Private Files:		"
echo "## ================================================ ##"


##-==============================================================-##
##   [+] Change The Permissions to Private Files:
##-==============================================================-##
sudo chmod 600 /etc/openvpn/vpn-key.pem
sudo chmod 600 /etc/openvpn/ta.key



echo "## ========================================================= ##"
echo "## [+] Turn on The Immutable Bit For The VPN Keys & Certs:	 " 
echo "## ========================================================= ##"
chattr +i /etc/openvpn/mullvad_ca.crt
chmod -v 0644 
chown -v 
chattr +i /etc/openvpn/mullvad_crl.pem


sudo chmod u+r vpn-key.pem
chattr +i 
sudo chmod ug+r mullvad_userpass.txt
chattr +i ta.key

vpn.csr

chattr +i dh4096.pem



echo "## ================================================ ##"
echo "				[+] TLS Authentication					"
echo "## ================================================ ##"
echo "## ------------------------------------------------ ##"
echo "## [?] To enable TLS authentication					"
echo "## 	 first generate a static encryption key. 		"
echo "## 	 This needs to be securely copied 				"
echo "## 	 to all OpenVPN clients and servers.			"
echo "## ------------------------------------------------ ##"
echo "## ================================================ ##"
openvpn --genkey --secret vpn.tlsauth


echo "## ================================================================ ##"
echo "## 					In the configuration files: 					"
echo "## ================================================================ ##"
echo "## ---------------------------------------------------------------- ##"
echo "## [?] The KEYDIR must be 0 on one of the sides and 1 on the other. 	"
echo "## 	 So if you choose the KEYDIR value of 0 for the server, all		"
echo "## 	 clients must be 1, and vice versa.								"
echo "## ---------------------------------------------------------------- ##"
echo "## ================================================================ ##"
tls-auth myvpn.tlsauth 





echo "##~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~##"
echo "## =============================================================== ##"
echo "                          [+] EasyRSA:	                   "
echo "## =============================================================== ##"
echo "##~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~##"




./easyrsa help options

##-=========================-##
##   [+] Configure vars:
##-=========================-##

sed -i "s/KEY_SIZE=.*/KEY_SIZE=4096/g" /etc/openvpn/easy-rsa/vars
sed -i 's/export CA_EXPIRE=3650/export CA_EXPIRE=365/' /etc/openvpn/easy-rsa/vars
sed -i 's/export KEY_EXPIRE=3650/export KEY_EXPIRE=365/' /etc/openvpn/easy-rsa/vars
sed -i "s/export KEY_COUNTRY=\"US\"/export KEY_COUNTRY=\"$country\"/" /etc/openvpn/easy-rsa/vars
sed -i "s/export KEY_PROVINCE=\"CA\"/export KEY_PROVINCE=\"$province\"/" /etc/openvpn/easy-rsa/vars
sed -i "s/export KEY_CITY=\"SanFrancisco\"/export KEY_CITY=\"$city\"/" /etc/openvpn/easy-rsa/vars
sed -i "s/export KEY_ORG=\"Fort-Funston\"/export KEY_ORG=\"$organization\"/" /etc/openvpn/easy-rsa/vars
sed -i "s/export KEY_EMAIL=\"me@myhost.mydomain\"/export KEY_EMAIL=\"$email\"/" /etc/openvpn/easy-rsa/vars
sed -i "s/export KEY_OU=\"MyOrganizationalUnit\"/export KEY_OU=\"$organizationUnit\"/" /etc/openvpn/easy-rsa/vars
sed -i "s/export KEY_NAME=\"EasyRSA\"/export KEY_NAME=\"$commonName\"/" /etc/openvpn/easy-rsa/vars
sed -i "s/export KEY_CN=openvpn.example.com/export KEY_CN=\"$commonName\"/" /etc/openvpn/easy-rsa/vars





##-========================================-##
##   [+] Initiate the PKI Gen Process:
##-========================================-##
./easyrsa init-pki


##-=================================================-##
##   [+] Build a Certificate Authority, (no pass):
##-=================================================-##
./easyrsa build-ca nopass


##-=========================================================-##
##   [+] Generate a Request, and Sign The .csr (no pass):
##-=========================================================-##
./easyrsa gen-req VPN.csr nopass


##-======================================================================-##
##   [+] req: /etc/openvpn/easy-rsa/easyrsa3/pki/reqs/VPN.csr.req
## ---------------------------------------------------------------------- ##
##   [+] key: /etc/openvpn/easy-rsa/easyrsa3/pki/private/VPN.csr.key
##-======================================================================-##
sudo ./easyrsa build-client-full Xe1phix


##-========================================-##
##   [+] Generate a crl.pem Certificate:
##-========================================-##
sudo ./easyrsa gen-crl

## ---------------------------------------------------------------------- ##
##   [+] CRL file: /etc/openvpn/easy-rsa/easyrsa3/pki/crl.pem
## ---------------------------------------------------------------------- ##


##-=================================-##
##   [+] Set RSA Keys Password:
##-=================================-##
set-rsa-pass 



echo "##~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~##"
echo "## =============================================================== ##"
echo "                  [+] :	                   "
echo "## =============================================================== ##"
echo "##~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~##"







##-==============================================================-##
##   [+] 
##-==============================================================-##
openssl ocsp -issuer "$issuer" "$nonce" -CAfile "$verify" -url "$ocsp_url" -serial "${serial}"




echo "##~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~##"
echo "## =============================================================== ##"
echo "                  [+] :	                   "
echo "## =============================================================== ##"
echo "##~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~##"




echo "##-====================================-##"
echo "    [+]"	                   
echo "##-====================================-##"




echo "##-====================================-##"
echo "      [+]	Certificate Authority:          "
echo "##-====================================-##"
openssl genrsa 4096																## ca-key.pem
openssl req -sha256 -new -key ca-key.pem -subj /CN=OpenVPN-CA/					## ca-csr.pem 
openssl x509 -req -sha256 -in ca-csr.pem -signkey ca-key.pem -days 365			## ca-cert.pem
echo 01																			## ca-cert.srl




echo "##-====================================-##"
echo "      [+]	Server Key & Certificate        "
echo "##-====================================-##"
openssl genrsa 4096																				## server-key.pem
openssl req -sha256 -new -key server-key.pem -subj /CN=OpenVPN-Server/							## server-csr.pem
openssl x509 -sha256 -req -in server-csr.pem -CA ca-cert.pem -CAkey ca-key.pem -days 365		## server-cert.pem


echo "##-====================================-##"
echo "      [+]	Client Key & Certificate        "
echo "##-====================================-##"
openssl genrsa 4096																				## client-key.pem
openssl req -sha256 -new -key client-key.pem -subj /CN=OpenVPN-Client/							## client-csr.pem
openssl x509 -req -sha256 -in client-csr.pem -CA ca-cert.pem -CAkey ca-key.pem -days 365		## client-cert.pem


echo "##-======================================-##"
echo "      [+]	Diffie hellman parameters:        "
echo "##-======================================-##"
openssl dhparam 2048																			## dh.pem 



echo "##-========================================================================-##"
echo "##   [+] Read The Certificate Signing Request (.csr) & The Cert (.csr):       "
echo "##-========================================================================-##"
openssl x509 -text -in certif.crt -noout 			## Read a certificate
openssl req -text -in request.csr -noout  			## Read a Certificate Signing Request



echo "##-==============================================================-##"
echo "##   [+] Generate a Certificate Signing Request (in PEM format):    "
echo "##              For the public key of a key pair                    "
echo "##-==============================================================-##"
openssl req -new -key private.key -out request.csr  			


echo "##-==============================================================-##"
echo "##       ______ [+] Create a 4096-bit RSA key pair: _______                "
echo "##       Then Generate a Certificate Signing Request for it:        "
echo "##-==============================================================-##"
openssl req -new -nodes -keyout private.key -out request.csr -newkey rsa:4096 


##-====================================================-##
##   [+] Generate a Self-Signed Root Certificate 
##         (and create a new CA private key)
##-====================================================-##
openssl req -x509 -newkey rsa:4096 -nodes -keyout private.key -out certif.crt -days validity 

##-===============================================-##
##   [+] Generate a Self-Signed Certificate:
##-===============================================-##
openssl ca -config ca.conf -in request.csr -out certif.crt -days validity -verbose 


##-================================-##
##   [+] Revoke a Certificate:
##-================================-##
openssl ca -config ca.conf -gencrl -revoke certif.crt -crl_reason why 



##-==================================================-##
##   [+] Generate a Certificate Revocation List:
##          (List all Revoked Certificates)
##-==================================================-##
openssl ca -config ca.conf -gencrl -out crlist.crl 

##-===================================================-##
##   [+] Convert a certificate from PEM to DER:
##-===================================================-##
openssl x509 -in certif.pem -outform DER -out certif.der 

##-==============================================================-##
##   [+] Convert a certificate from PEM to PKCS#12:
##             (including the private key)
##-==============================================================-##
openssl pkcs12 -export -in certif.pem -inkey private.key -out certif.pfx -name friendlyname 

openssl pkcs12 -export -inkey keys/bugs.key -in keys/bugs.crt -certfile keys/ca.crt -out keys/bugs.p12

##-==============================================================-##
##   [+] Create a PEM certificate from CRT and private key:
##-==============================================================-##
cat cert.crt cert.key > cert.pem 

##-============================================-##
##     [+] Generate the digest of a file:
##-============================================-##
openssl dgst -hashfunction -out file.hash file 

##-==============================================================-##
##     __________ [+] Verify the digest of a file ___________ 
##    (no output means that digest verification is successful)
##-==============================================================-##
openssl dgst -hashfunction file | cmp -b file.hash 

##-==============================================================-##
##   [+] Generate the signature of a file
openssl dgst -hashfunction -sign private.key -out file.sig file 


##-==============================================================-##
##   [+] Verify the signature of a file
openssl dgst -hashfunction -verify public.key -signature file.sig file 

##-==============================================================-##
##   [+] Encrypt a file
openssl enc -e -cipher -in file -out file.enc -salt 

##-==============================================================-##
##   [+] Decrypt a file
openssl enc -d -cipher -in file.enc -out file 

##-==============================================================-##
##   [+] Generate a 2048-bit RSA key pair protected by TripleDES passphrase
openssl genpkey -algorithm RSA -cipher 3des -pkeyopt rsa_keygen_bits:2048 -out key.pem 

##-==============================================================-##
##   [+] Examine a private key
openssl pkey -text -in private.key -noout 

##-==============================================================-##
##   [+] Change the passphrase of a private key
openssl pkey -in old.key -out new.key -cipher 

##-==============================================================-##
##   [+] Remove the passphrase from a private key
openssl pkey -in old.key -out new.key 


##-==============================================================-##
##   [+] Retrieve and inspect a SSL certificate from a website
openssl s_client -connect www.website.com:443 > tmpfile 
openssl x509 -in tmpfile -text

##-==============================================================-##
##   [+] List all available hash functions
openssl list-message-digest-commands 

##-==============================================================-##
##   [+] List all available ciphers
openssl list-cipher-commands 





# Generate CA key and cert
openssl req -new -newkey rsa:4096 -days 3650 -nodes -x509 \
    -extensions easyrsa_ca -keyout sample-ca/ca.key -out sample-ca/ca.crt \
    -subj "/C=KG/ST=NA/L=BISHKEK/O=OpenVPN-TEST/emailAddress=me@myhost.mydomain" \
    -config openssl.cnf


##-==============================================================-##
##   [+] Create server key and cert
openssl req -new -nodes -config openssl.cnf -extensions server \
    -keyout sample-ca/server.key -out sample-ca/server.csr \
    -subj "/C=KG/ST=NA/O=OpenVPN-TEST/CN=Test-Server/emailAddress=me@myhost.mydomain"
    

openssl ca -batch -config openssl.cnf -extensions server -out sample-ca/server.crt -in sample-ca/server.csr


##-==============================================================-##
##   [+] Create client key and cert
openssl req -new -nodes -config openssl.cnf \
    -keyout sample-ca/client.key -out sample-ca/client.csr \
    -subj "/C=KG/ST=NA/O=OpenVPN-TEST/CN=Test-Client/emailAddress=me@myhost.mydomain"


openssl ca -batch -config openssl.cnf -out sample-ca/client.crt -in sample-ca/client.csr



##-==============================================================-##
##   [+] Create password protected key file
openssl rsa -aes256 -passout pass:password -in sample-ca/client.key -out sample-ca/client-pass.key


##-==============================================================-##
##   [+] Create pkcs#12 client bundle
openssl pkcs12 -export -nodes -password pass:password \
    -out sample-ca/client.p12 -inkey sample-ca/client.key \
    -in sample-ca/client.crt -certfile sample-ca/ca.crt

##-==============================================================-##
##   [+] Create a client cert, revoke it, generate CRL
openssl req -new -nodes -config openssl.cnf \
    -keyout sample-ca/client-revoked.key -out sample-ca/client-revoked.csr \
    -subj "/C=KG/ST=NA/O=OpenVPN-TEST/CN=client-revoked/emailAddress=me@myhost.mydomain"

openssl ca -batch -config openssl.cnf -out sample-ca/client-revoked.crt -in sample-ca/client-revoked.csr
openssl ca -config openssl.cnf -revoke sample-ca/client-revoked.crt
openssl ca -config openssl.cnf -gencrl -out sample-ca/ca.crl



##-==============================================================-##
##   [+] Create DSA server and client cert (signed by 'regular' RSA CA)
openssl dsaparam -out sample-ca/dsaparams.pem 2048

openssl req -new -newkey dsa:sample-ca/dsaparams.pem -nodes -config openssl.cnf \
    -extensions server \
    -keyout sample-ca/server-dsa.key -out sample-ca/server-dsa.csr \
    -subj "/C=KG/ST=NA/O=OpenVPN-TEST/CN=Test-Server-DSA/emailAddress=me@myhost.mydomain"

##-==============================================================-##
##   [+] 
openssl ca -batch -config openssl.cnf -extensions server -out sample-ca/server-dsa.crt -in sample-ca/server-dsa.csr



openssl req -new -newkey dsa:sample-ca/dsaparams.pem -nodes -config openssl.cnf \
    -keyout sample-ca/client-dsa.key -out sample-ca/client-dsa.csr \
    -subj "/C=KG/ST=NA/O=OpenVPN-TEST/CN=Test-Client-DSA/emailAddress=me@myhost.mydomain"

##-==============================================================-##
##   [+] 
openssl ca -batch -config openssl.cnf -out sample-ca/client-dsa.crt -in sample-ca/client-dsa.csr



##-==============================================================-##
##   [+] Create EC server and client cert (signed by 'regular' RSA CA)
openssl ecparam -out sample-ca/secp256k1.pem -name secp256k1

##-==============================================================-##
##   [+] 
openssl req -new -newkey ec:sample-ca/secp256k1.pem -nodes -config openssl.cnf \
    -extensions server \
    -keyout sample-ca/server-ec.key -out sample-ca/server-ec.csr \
    -subj "/C=KG/ST=NA/O=OpenVPN-TEST/CN=Test-Server-EC/emailAddress=me@myhost.mydomain"
    
##-==============================================================-##
##   [+] 
openssl ca -batch -config openssl.cnf -extensions server -out sample-ca/server-ec.crt -in sample-ca/server-ec.csr


##-==============================================================-##
##   [+] 
openssl req -new -newkey ec:sample-ca/secp256k1.pem -nodes -config openssl.cnf \
    -keyout sample-ca/client-ec.key -out sample-ca/client-ec.csr \
    -subj "/C=KG/ST=NA/O=OpenVPN-TEST/CN=Test-Client-EC/emailAddress=me@myhost.mydomain"

##-==============================================================-##
##   [+] 
openssl ca -batch -config openssl.cnf -out sample-ca/client-ec.crt -in sample-ca/client-ec.csr





echo "## ============================================= ##"
echo "      Encrypt and decrypt A single file:"
echo "## ============================================= ##"
openssl aes‐128‐cbc ‐salt ‐in file ‐out file.aes 
openssl aes‐128‐cbc ‐d ‐salt ‐in file.aes ‐out file 


echo "## ======================================================= ##"
echo -e "\t Note that the file can of course be a tar archive."
echo -e "\t     tar and encrypt a whole directory"
echo "## ======================================================= ##"
echo "## --------------------------------------------------------------------------- ##"
tar ‐cf ‐ directory | openssl aes‐128‐cbc ‐salt ‐out directory.tar.aes      # Encrypt 
openssl aes‐128‐cbc ‐d ‐salt ‐in directory.tar.aes | tar ‐x ‐f ‐            # Decrypt 
echo "## --------------------------------------------------------------------------- ##"

echo "## ======================================================= ##"
echo -e "\t\t Tar zip and encrypt a whole directory"
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



##-==============================================================-##
##   [+] CA/private/cakey.pem (CA server private key)
##-==============================================================-##
##   [+] CA/cacert.pem (CA server public key)
##-==============================================================-##
##   [+] certs/servernamekey.pem (server private key)
##-==============================================================-##
##   [+] certs/servernamecert.pem (server signed certificate)
##-==============================================================-##
##   [+] certs/servername.pem (server certificate with private key)



openssl x509 ‐text ‐in servernamecert.pem      # View the certificate info 
openssl req ‐noout ‐text ‐in server.csr        # View the request info 
openssl s_client ‐connect cb.vu:443            # Check a web server certificate 





##-==============================================================-##
##   [+] create a CA, 
##-==============================================================-##
##   [+] create a request, 
##-==============================================================-##
##   [+] sign the request 
##-==============================================================-##
##   [+] create a PKCS#12 file


CA.pl -newca
CA.pl -newreq
CA.pl -signreq
CA.pl -pkcs12 "My Test Certificate"





##-==============================================================-##
##   [+] Create some DSA parameters:
openssl dsaparam -out dsap.pem 1024

##-==============================================================-##
##   [+] Create a DSA CA certificate and private key:
openssl req -x509 -newkey dsa:dsap.pem -keyout cacert.pem -out cacert.pem

##-==============================================================-##
##   [+] Create the CA directories and files:
CA.pl -newca

##-==============================================================-##
##   [+] enter cacert.pem when prompted for the CA file name.

##-==============================================================-##
##   [+] Create a DSA certificate request and private key (a different set of parameters can optionally be created first):
openssl req -out newreq.pem -newkey dsa:dsap.pem

##-==============================================================-##
##   [+] Sign the request:
CA.pl -signreq





echo "##~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~##"
echo "## =============================================================== ##"
echo "                  [+] :	                   "
echo "## =============================================================== ##"
echo "##~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~##"









echo "## =========================================== ##"
echo -e "\t\tTo create an RSA private key:"
echo "## =========================================== ##"
certtool --generate-privkey --outfile key.pem --rsa

echo "## ============================================================================= ##"
echo -e "\tprivate key is stored in a smart card you can generate a request"
echo "## ============================================================================= ##"
./certtool --generate-request --load-privkey "pkcs11:..." --load-pubkey "pkcs11:..."


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
echo -e "\tGenerate parameters for Diffie-Hellman key exchange, use the command:"
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




##-==============================================================-##
##   [+] sign the certificate
echo "CA signing: $CSR -> $CERT:"
openssl ca -config ca.config -out $CERT -infiles $CSR


echo "CA verifying: $CERT <-> CA cert"
openssl verify -CAfile /usr/share/ssl/certs/ca.crt $CERT








-show_chain
-crl_download
-extended_crl         enable extended CRL features
-check_ss_sig         check root CA self-signatures


Recognized usages:
	sslclient 	SSL client
	sslserver 	SSL server
	nssslserver	Netscape SSL server
	smimesign 	S/MIME signing
	smimeencrypt	S/MIME encryption
	crlsign   	CRL signing
	any       	Any Purpose
	ocsphelper	OCSP helper
	timestampsign	Time Stamp signing
Recognized verify names:
	default   
	pkcs7     
	smime_sign
	ssl_client
	ssl_server



openssl verify -help
openssl ocsp -help



echo "## =================================================================== ##"
echo -e "\t First a master key needs to be created in base64 encoding:"
echo "## =================================================================== ##"
openssl rand -base64 32 > key.b64
KEY=$(base64 -d key.b64 | hexdump  -v -e '/1 "%02X"')


echo "## =================================================================== ##"
echo -e "\t Each secret to be encrypted needs to have a random initialization "
echo -e "\t Vector generated. These do not need to be kept secret"
echo "## =================================================================== ##"
openssl rand -base64 16 > iv.b64
IV=$(base64 -d iv.b64 | hexdump  -v -e '/1 "%02X"')


echo "## =================================================================== ##"
echo -e "\t The secret to be defined can now be encrypted, "
echo -e "\t in this case were telling openssl to base64 encode "
echo -e "\t the result, but it could be left as raw bytes if desired."
echo "## =================================================================== ##"
SECRET=$(echo -n "letmein" |
openssl enc -aes-256-cbc -a -K $KEY -iv $IV)



echo "##~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~##"
echo "## =============================================================== ##"
echo "                  [+] :	                   "
echo "## =============================================================== ##"
echo "##~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~##"




openssl smime -help




##-==============================================================-##
##   [+] Create a cleartext signed message:
openssl smime -sign -in message.txt -text -out mail.msg -signer mycert.pem


##-==============================================================-##
##   [+] Create an opaque signed message:
openssl smime -sign -in message.txt -text -out mail.msg -nodetach -signer mycert.pem


##-==============================================================-##
##   [+] Create a signed message, include some additional certificates and read the private key from another file:
openssl smime -sign -in in.txt -text -out mail.msg -signer mycert.pem -inkey mykey.pem -certfile mycerts.pem


##-==============================================================-##
##   [+] Create a signed message with two signers:
openssl smime -sign -in message.txt -text -out mail.msg -signer mycert.pem -signer othercert.pem


##-==============================================================-##
##   [+] Send a signed message under Unix directly to sendmail, including headers:
openssl smime -sign -in in.txt -text -signer mycert.pem -from steve@openssl.org -to someone@somewhere -subject "Signed message" | sendmail someone@somewhere

##-==============================================================-##
##   [+] Verify a message and extract the signer's certificate if successful:
openssl smime -verify -in mail.msg -signer user.pem -out signedtext.txt


##-==============================================================-##
##   [+] Send encrypted mail using triple DES:
openssl smime -encrypt -in in.txt -from steve@openssl.org -to someone@somewhere -subject "Encrypted message" -des3 user.pem -out mail.msg


##-==============================================================-##
##   [+] Sign and encrypt mail:
openssl smime -sign -in ml.txt -signer my.pem -text | openssl smime -encrypt -out mail.msg -from steve@openssl.org -to someone@somewhere -subject "Signed and Encrypted message" -des3 user.pem


##-==============================================================-##
##   [+] Decrypt mail:
openssl smime -decrypt -in mail.msg -recip mycert.pem -inkey key.pem



##-==============================================================-##
##   [+] The output from Netscape form signing is a PKCS#7 structure with the detached signature format. 
##-==============================================================-##
##   [+] You can use this program to verify the signature by
##-==============================================================-##
##   [+] line wrapping the base64 encoded structure and surrounding it with:
openssl smime -verify -inform PEM -in signature.pem -content content.txt


##-==============================================================-##
##   [+] Alternatively you can base64 decode the signature and use:
openssl smime -verify -inform DER -in signature.der -content content.txt


##-==============================================================-##
##   [+] Create an encrypted message using 128 bit Camellia:
openssl smime -encrypt -in plain.txt -camellia128 -out mail.msg cert.pem


##-==============================================================-##
##   [+] Add a signer to an existing message:
openssl smime -resign -in mail.msg -signer newsign.pem -out mail2.msg








airtun-ng ifdata ifquery ifstat nmtui-edit nmtui-connect perfmonctl systemd.netdev veth

x509v3_config 

openssl-x509 -help 

 -fingerprint 
 -signkey 
 -pubkey 
 -subject_hash 
 -issuer_hash 
 -ocspid 
 -hash 
 -serial 
 -subject 
 -issuer 
 -ocsp_uri 
 -trustout 
 -addtrust 
 -clientAuth 
 -serverAuth email
 -Protection  
 -keyform PEM|DER  
 
 x509  
 ASN1_generate_nconf


echo "##~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~##"
echo "## =============================================================== ##"
echo "                  [+] :	                   "
echo "## =============================================================== ##"
echo "##~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~##"


##-==============================================================-##
##   [+] SSL Handshake between a Client and www.google.com
$ OpenSSL s_client -connect www.google.com:443 -state -ssl3


# Download this file (https://blog.patternsinthevoid.net/isis.txt):
wget -q --ca-certificate=${HOST}.pem https://${HOST}/isis.txt




How to verify this file and the server it lives on:
---------------------------------------------------
# Download the certificate for this server:
HOST=blog.patternsinthevoid.net && PORT=443
openssl s_client -connect "${HOST}":"${PORT}" </dev/null 2>/dev/null | \
    sed -nr '/(-){5}(BEGIN CERTIFICATE){1}(-){5}/,/(-){5}(END CERTIFICATE){1}(-){5}/p' | \
    cat > ${HOME}/${HOST}.pem
# Check the SSL certificate fingerprint (it should match the ones given in this file):
cat ${HOME}/${HOST}.pem | openssl x509 -fingerprint -noout -in /dev/stdin
# Download this file (https://blog.patternsinthevoid.net/isis.txt):
wget -q --ca-certificate=${HOST}.pem https://${HOST}/isis.txt
# Check signature and import key:
gpg -o isis -v isis.txt && gpg --import isis




##-==============================================================-##
##   [+] check site ssl certificate dates
echo | openssl s_client -connect www.google.com:443 2>/dev/null |openssl x509 -dates -noout



s_client can be used to debug SSL servers. To connect to an SSL HTTP server the command:

        openssl s_client -connect servername:443

openssl s_client -brief -starttls smtp \
               -connect smtp.example.com:25 \
               -dane_tlsa_domain smtp.example.com \
               -dane_tlsa_rrdata "2 1 1
                 B111DD8A1C2091A89BD4FD60C57F0716CCE50FEEFF8137CDBEE0326E 02CF362B" \
               -dane_tlsa_rrdata "2 1 1
                 60B87575447DCBA2A36B7D11AC09FB24A9DB406FEE12D2CC90180517 616E8A18"




##-===========================================================================-##
##   [?] s_time can be used to measure the performance of an SSL connection.  

##-==============================================================-##
##   [+] onnect to an SSL HTTP server and get the default page:

openssl s_time -connect servername:443 -www / -CApath yourdir -CAfile yourfile.pem -cipher commoncipher [-ssl3]





##-==============================================================-##
##   [+] RFC-3161 Timestamping Signatures with PGP or S/MIME
##-==============================================================-##
openssl ts -query -data $hash.log -out $hash.log.tsq -cert


##-===================================================-##
##   [+] files can be sent to the FreeTSA service:
##-===================================================-##
tsget -h https://freetsa.org/tsr $hash.log.tsq


##-==============================================================-##
##   [+] Manually submit the timestamp request Using curl:
##-==============================================================-##
curl -s -H "Content-Type: application/timestamp-query" --data-binary "@hash.log.tsq" https://freetsa.org/tsr > hash.log.tsr


##-============================================-##
##   [+] view the contents of the timestamp
##-============================================-##
openssl ts -reply -in $hash.log.tsr -text




openssl-s_client -host boreas.openna.com -port 993

openssl req -new -x509 -nodes -days 365 -out $tmp.pem



##-==============================================-##
##   [?] The CA cert is fetched from FreeTSA
##-==============================================-##
curl http://freetsa.org/files/cacert.pem > $cacert.pem



##-==============================================================-##
##   [+] Validate the timestamp using:
##-==============================================================-##
##   [?] The Timestamp Query ( tsq ) 
##-==============================================================-##
##   [?] The Timestamp Reponse ( tsr )
##-==============================================================-##
openssl ts -verify -in $hash.log.tsr -queryfile $hash.log.tsq -CAfile $cacert.pem









echo "## ============================================-##"
echo -e "\t\t [+] Create a certificate authority"
echo "## ============================================-##"


## ---------------------------------------------------------------------------------------------------------------------- ##
    openssl req ‐new ‐x509 ‐days 730 ‐config /etc/ssl/$openssl.cnf ‐keyout CA/private/$cakey.pem ‐out CA/$cacert.pem
## ---------------------------------------------------------------------------------------------------------------------- ##
    openssl req ‐new ‐keyout $newkey.pem ‐out $newreq.pem ‐config /etc/ssl/$openssl.cnf 
    openssl req ‐nodes ‐new ‐keyout $newkey.pem ‐out $newreq.pem ‐config /etc/ssl/$openssl.cnf    # No encryption for the key 
## ---------------------------------------------------------------------------------------------------------------------- ##

echo "##-==============================-##"
echo "     [+] Sign the certificate:      "
echo "##-==============================-##"
## ---------------------------------------------------------------------------------------------------------- ##"
cat newreq.pem $newkey.pem > $new.pem 
## ---------------------------------------------------------------------------------------------------------- ##"
openssl ca ‐policy policy_anything ‐out $servernamecert.pem ‐config /etc/ssl/$openssl.cnf ‐infiles $new.pem 
## ---------------------------------------------------------------------------------------------------------- ##"
mv $newkey.pem $servernamekey.pem 
## ---------------------------------------------------------------------------------------------------------- ##"


## ---------------------------------------------------------------------------------------------------------- ##"
CA/private/$cakey.pem (CA server private key)
## ---------------------------------------------------------------------------------------------------------- ##"
CA/$cacert.pem (CA server public key)
## ---------------------------------------------------------------------------------------------------------- ##"
certs/$servernamekey.pem (server private key)
## ---------------------------------------------------------------------------------------------------------- ##"
certs/$servernamecert.pem (server signed certificate)
## ---------------------------------------------------------------------------------------------------------- ##"
certs/$servername.pem (server certificate with private key)
## ---------------------------------------------------------------------------------------------------------- ##"






## ---------------------------------------------------------------------------------------------------------- ##"
    openssl x509 ‐text ‐in $servernamecert.pem      # View the certificate info 
## ---------------------------------------------------------------------------------------------------------- ##"
    openssl req ‐noout ‐text ‐in $server.csr        # View the request info 
## ---------------------------------------------------------------------------------------------------------- ##"
    openssl s_client ‐connect cb.vu:443            # Check a web server certificate 
## ---------------------------------------------------------------------------------------------------------- ##"







echo "## =========================================== ##"
echo "     [+] Create an RSA private key:              "
echo "## =========================================== ##"
certtool --generate-privkey --outfile $key.pem --rsa




echo "##-=============================-##"
echo "##   [?] Generate A Request:       "
echo "##-=============================-##"
echo "## --------------------------------------------------- ##"
echo "##   [?] The Private key is stored in a smart card       "
echo "## --------------------------------------------------- ##"
certtool --generate-request --load-privkey "$pkcs11:..." --load-pubkey "$pkcs11:..."


echo "## ============================================================================= ##"
echo -e "\t\tCreate self-signed certificate"
echo "## ============================================================================= ##"
certtool --generate-privkey --outfile $ca-key.pem
certtool --generate-self-signed --load-privkey $ca-key.pem --outfile $ca-cert.pem

certtool --generate-certificate --load-request $request.pem --outfile $cert.pem --load-ca-certificate $ca-cert.pem --load-ca-privkey $ca-key.pem


echo "## ============================================================================= ##"
echo -e "\tGenerate a certificate using the private key only, use the command:"
echo "## ============================================================================= ##"
certtool --generate-certificate --load-privkey $key.pem --outfile $cert.pem --load-ca-certificate $ca-cert.pem --load-ca-privkey ca-key.pem


echo "## ======================================= ##"
echo -e "\t\tCertificate information"
echo "## ======================================= ##"
certtool --certificate-info --infile $cert.pem

echo "## ============================================================================= ##"
echo "Generate a PKCS #12 structure using the previous key and certificate, use the command:"
echo "## ============================================================================= ##"
certtool --load-certificate $cert.pem --load-privkey $key.pem --to-p12 --outder --outfile $key.p12

certtool --load-ca-certificate $ca.pem --load-certificate $cert.pem --load-privkey $key.pem --to-p12 --outder --outfile $key.p12

echo "## ============================================================================= ##"
echo -e "\tGenerate parameters for Diffie-Hellman key exchange, use the command:"
echo "## ============================================================================= ##"
certtool --generate-dh-params --outfile $dh.pem --sec-param medium

certtool --generate-privkey > $proxy-key.pem
certtool --generate-proxy --load-ca-privkey $key.pem --load-privkey $proxy-key.pem --load-certificate $cert.pem --outfile proxy-cert.pem

echo "## ============================================================ ##"
echo -e "\t\tCertificate revocation list generation"
echo -e "\tCreate an empty Certificate Revocation List (CRL) do:"
echo "## ============================================================ ##"
certtool --generate-crl --load-ca-privkey $x509-ca-key.pem --load-ca-certificate $x509-ca.pem

echo "## ============================================================================= ##"
echo -e "\tcreate a CRL that contains some revoked certificates, "
echo -e "place the certificates in a file and use --load-certificate as follows:"
echo "## ============================================================================= ##"
certtool --generate-crl --load-ca-privkey $x509-ca-key.pem --load-ca-certificate $x509-ca.pem --load-certificate $revoked-certs.pem


echo "## ============================================================ ##"
echo -e "\t\tverify a Certificate Revocation List (CRL):"
echo "## ============================================================ ##"
certtool --verify-crl --load-ca-certificate $x509-ca.pem < $crl.pem




##-===============================================-##
##   [+] Print out text version of parameters:
##-===============================================-##
openssl pkeyparam -in $param.pem -text






##-====================================================================-##
##   [+] Generate a new private key and Certificate Signing Request:
##-====================================================================-##
openssl req -out CSR.csr -new -newkey rsa:2048 -nodes -keyout privateKey.key


##-===========================================-##
##   [+] Generate a self-signed certificate 
##-===========================================-##
openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout privateKey.key -out certificate.crt


##-======================================================-##
##   [+] Generate a certificate signing request (CSR) 
##            for an existing private key
##-======================================================-##
openssl req -out CSR.csr -key privateKey.key -new


##-================================================================================-##
##   [+] Generate a certificate signing request based on an existing certificate:
##-================================================================================-##
openssl x509 -x509toreq -in certificate.crt -out CSR.csr -signkey privateKey.key


##-==================================================-##
##   [+] Remove a passphrase from a private key:
##-==================================================-##
openssl rsa -in privateKey.pem -out newPrivateKey.pem



Checking Using OpenSSL
======================



##-==================================================-##
##   [+] Check a Certificate Signing Request (CSR)
##-==================================================-##
openssl req -text -noout -verify -in CSR.csr


##-=============================-##
##   [+] Check a private key
##-=============================-##
openssl rsa -in privateKey.key -check


##-=============================-##
##   [+] Check a certificate
##-=============================-##
openssl x509 -in certificate.crt -text -noout


##-============================================-##
##   [+] Check a PKCS#12 file (.pfx or .p12)
##-============================================-##
openssl pkcs12 -info -in keyStore.p12






Debugging Using OpenSSL
=======================


##-==============================================================-##
##   [+] Check an MD5 hash of the public key to ensure that it  
##       matches with what is in a CSR or private key
##-==============================================================-##
openssl x509 -noout -modulus -in certificate.crt | openssl md5
openssl rsa -noout -modulus -in privateKey.key | openssl md5
openssl req -noout -modulus -in CSR.csr | openssl md5



##-==================================================================-##
##   [+] verify that your public and private keys match:
##-==================================================================-##
## ------------------------------------------------------------------ ##
##       use the -modulus switch to generate a hash of the output 
##       for all three files (private key, CSR, and certificate).
## ------------------------------------------------------------------ ##


##-================================================-##
##   [+] Generate a hash of each file's modulus:
##-================================================-##
openssl rsa -modulus -in $Domain.key -noout | openssl sha256
openssl req -modulus -in $Domain.csr -noout | openssl sha256
openssl x509 -modulus -in $Domain.crt -noout | openssl sha256






##-================================-##
##   [+] Check an SSL connection:
##-================================-##
## ---------------------------------------------------------------------------- ##
##   [?] All the certificates (including Intermediates) should be displayed
## ---------------------------------------------------------------------------- ##
openssl s_client -connect www.paypal.com:443





## Converting Using OpenSSL


##-===========================================================-##
##   [+] convert certificates and keys to different formats
##-===========================================================-##




##-===========================================================-##
##   [+] Decode the private key and view its contents:

openssl rsa -text -in yourdomain.key -noout



##-===========================================================-##
##   [+] Extract your public key:

openssl rsa -in yourdomain.key -pubout -out yourdomain_public.key



##-===========================================================-##
##   [+] Create your CSR. 

## ---------------------------------------------------------------------------- ##
##   [?] The CSR is created using the PEM format and contains 
##       the public key portion of the private key 
##       as well as information about you (or your company).
## ---------------------------------------------------------------------------- ##
openssl req -new -key yourdomain.key -out yourdomain.csr




## ----------------------------------------------------------------------------------------- ##
##   [?] When creating a CSR, provide all the needed information using the -subj switch.
## ----------------------------------------------------------------------------------------- ##
openssl req -new -key yourdomain.key -out yourdomain.csr -subj "/C=US/ST=Utah/L=Lehi/O=Your Company, Inc./OU=IT/CN=yourdomain.com"





##-=============================================-##
##   [+] Create both the private key and CSR:
##-=============================================-##


##-=============================================-##
##   [+] Generate a new private key (-newkey) 
##   [+] use the RSA algorithm with a 4096-bit key length (rsa:4096) 
##   [+] use without a passphrase (-nodes) 
##   [+] Create the key file $Domain.key (-keyout $Domain.key)


generates the CSR $Domain.csr (-out $Domain.csr) 
the information for the CSR is supplied (-subj).


openssl req -new -newkey rsa:2048 -nodes -keyout $Domain.key -out $Domain.csr -subj "/C=US/ST=Utah/L=Lehi/O=Your Company, Inc./OU=IT/CN=yourdomain.com"



Verifying CSR Information

After creating your CSR using your private key, 
verify that the information contained in the CSR 
isnt corrupt, or been tampered with


view the information in your CSR before submitting it to a CA :

openssl req -text -in $Domain.csr -noout -verify


## ------------------------------------------------------------- ##
##   [?] The -verify switch checks the signature of the file
## ------------------------------------------------------------- ##


view the contents of your certificate:

openssl x509 -text -in $Domain.crt -noout






##-====================================================-##
##   [+] Convert a DER file (.crt .cer .der) to PEM
##-====================================================-##
openssl x509 -inform der -in $Cert.cer -out $Cert.pem


##-===================================-##
##   [+] Convert a PEM file to DER
##-===================================-##
openssl x509 -outform der -in $Cert.pem -out $Cert.der


##-==============================================================================================-##
##   [+] Convert a PKCS#12 file (.pfx .p12) containing a private key and certificates to PEM
##-==============================================================================================-##
openssl pkcs12 -in $keyStore.pfx -out $keyStore.pem -nodes



##-======================================================================-##
##   [+] Convert your PEM key and certificate into the PKCS#12 format:
##-======================================================================-##
openssl pkcs12 -export -name "$Domain-digicert-(expiration date)" -out $Domain.pfx -inkey $Domain.key -in $Domain.crt



##-===========================================================-##
##   [+] extract the private key from a PKCS#12 (.pfx) file 
##   [+] convert it into a PEM encoded private key:
##-===========================================================-##
openssl pkcs12 -in $Domain.pfx -nocerts -out $Domain.key -nodes



##-===========================================================-##
##   [+] extract the certificate from a PKCS#12 (.pfx) file
##   [+] convert it into a PEM encoded certificate:
##-===========================================================-##
openssl pkcs12 -in $Domain.pfx -nokeys -clcerts -out $Domain.crt



##-=========================================================================-##
##   [+] Convert a PEM encoded certificate into a DER encoded certificate:
##-==========================================================================-##
openssl x509 -inform PEM -in $Domain.crt -outform DER -out $Domain.der


##-=========================================================================-##
##   [+] Convert a PEM encoded private key into a DER encoded private key:
##-==========================================================================-##
openssl rsa -inform PEM -in $Domain.key -outform DER -out $Domain_key.der



##-==========================================================================-##
##   [+] Convert a DER encoded certificate into a PEM encoded certificate:
##-==========================================================================-##
openssl x509 -inform DER -in $Domain.der -outform PEM -out $Domain.crt




##-==========================================================================-##
##   [+] Convert a DER encoded private key into a PEM encoded private key:
##-==========================================================================-##
openssl rsa -inform DER -in $Domain_key.der -outform PEM -out $Domain.key




















## -------------------------------------------------------------- ##
##   [?] You can add `-nocerts` to only output the private key 
##         or add `-nokeys` to only output the certificates.
## -------------------------------------------------------------- ##

##-=================================================================================-##
##   [+] Convert a PEM certificate file and a private key to PKCS#12 (.pfx .p12)
##-=================================================================================-##
openssl pkcs12 -export -out $Cert.pfx -inkey $privateKey.key -in $Cert.crt -certfile $CACert.crt




openssl x509 -subject -noout < "/etc/ssl/certs/Equifax_Secure_CA.pem"


openssl genpkey -algorithm RSA -out private/$key.pem -pkeyopt rsa_keygen_bits:4096

openssl genpkey -aes-256-cbc -algorithm RSA -out private/$key.pem -pkeyopt rsa_keygen_bits:4096


##-==============================================================-##
##   [+] Obtain a certificate from a certificate authority
##-==============================================================-##
## -------------------------------------------------------------- ##
##   [?] You need to create a Certificate Signing Request (CSR) 
##       and sign it with a previously generated private key:
## -------------------------------------------------------------- ##
openssl req -new -sha256 -key private/$key.pem -out $req.csr


##-===================================================================================-##
##   [+] Create a self-signed certificate with a previously generated private key:
##-===================================================================================-##
openssl req -key private/$key.pem -x509 -new -days 3650 -out $SelfCert.pem


##-==============================================-##
##   [+] Generate the certificate for Apache2
##-==============================================-##
openssl req -new -x509 -sha256 -days 365 -nodes -out /etc/ssl/localcerts/apache.pem -keyout /etc/ssl/localcerts/apache.key



openssl genrsa -out "${OUT}.key" 4096
openssl req -new -key "${OUT}.key" -out "${OUT}.csr" -subj '/C=US/ST=CA/L=San Francisco/O=Docker/CN=Notary Testing Client Auth'



openssl x509 -req -days 3650 -in "${OUT}.csr" -signkey "${OUT}.key" -out "${OUT}.crt" -extfile "${OUT}.cnf" -extensions ssl_client



openssl genrsa -out "${OUT}.key" 4096
openssl req -new -nodes -key "${OUT}.key" -out "${OUT}.csr" \-subj "/C=US/ST=CA/L=San Francisco/O=Docker/CN=${COMMONNAME}" -config "${OUT}.cnf" -extensions "v3_req"
openssl x509 -req -days 3650 -in "${OUT}.csr" -signkey "${OUT}.key" -out "${OUT}.crt" -extensions v3_req -extfile "${OUT}.cnf"







##-============================-##
##   [+] Create the root CA
##-============================-##
openssl req -x509 -config "${CONFIGS_DIR}/openssl-ca.cnf" -newkey rsa:4096 -sha256 -subj "${CERT_SUBJ}" -nodes -out "${CERT_DIR}/cacert.pem" -outform PEM

openssl x509 -noout -text -in "${CERT_DIR}/cacert.pem"


##-=======================================================-##
##   [+] Create the server certificate signing request
##-=======================================================-##
openssl req -config "${CONFIGS_DIR}/$openssl-server.cnf" -newkey rsa:2048 -sha256 -subj "/CN=localhost" -nodes -out "${CERT_DIR}/server.csr" -outform PEM

openssl req -text -noout -verify -in "${CERT_DIR}/$server.csr"


##-===============================-##
##   [+] Create the server cert
##-===============================-##
openssl ca -batch -config "${CONFIGS_DIR}/$OpenSSLCA.cnf" -policy signing_policy -extensions signing_req -out "${CERT_DIR}/server.cert" -infiles "${CERT_DIR}/server.csr"

openssl x509 -noout -text -in "${CERT_DIR}/$server.cert"



##-======================================================-##
##   [+] Create the client certificate signing request
##-======================================================-##
openssl req -config "${CONFIGS_DIR}/$openssl-client.cnf" -newkey rsa:2048 -sha256 -subj "/CN=client" -nodes -out "${CERT_DIR}/client.csr" -outform PEM

openssl req -text -noout -verify -in "${CERT_DIR}/$client.csr"


##-================================-##
##   [+] Create the client cert
##-================================-##
openssl ca -batch -config "${CONFIGS_DIR}/$openssl-ca.cnf" -policy signing_policy -extensions signing_req -out "${CERT_DIR}/client.cert" -infiles "${CERT_DIR}/client.csr"

openssl x509 -noout -text -in "${CERT_DIR}/$client.cert"



##-=====================================-##
##   [+] Remove the signing requests
##-=====================================-##
rm -rf "${CERT_DIR}/$client.csr" "${CERT_DIR}/$server.csr" "${CERT_DIR}/"*.attr "${CERT_DIR}/"*.old



##-==============================================================-##
##   [+] copy the certs and keys to places where 
##       they can be auto picked up by the docker daemon
##-==============================================================-##
cp "${CERT_DIR}/$cacert.pem" "${CERT_DIR}/$ca.pem"
cp "${CERT_DIR}/$server.cert" "${CERT_DIR}/$cert.pem"
cp "${CERT_DIR}/$server.key" "${CERT_DIR}/$key.pem"






while true; do read -n30 ui; echo $ui |openssl enc -aes-256-ctr -a -k PaSSw; done | nc -l -p 8877 | while read so; do decoded_so=`echo "$so"| openssl enc -d -a -aes-256-ctr -k PaSSw`; 


openssl rand -base64 6

openssl rand -base64 $length

openssl rand -hex 6 | sed 's/\(..\)/\1'

echo $(openssl rand 4 | od -DAn)


##-====================================================-##
##   [+] Test SMTPs Ability To Setup TLS Connections:
##-====================================================-##
openssl s_client -starttls smtp -crlf -connect 127.0.0.1



echo | openssl s_client -connect www.google.com



openssl s_client -connect $host



'openssl sha256 -binary'; p='printf';($p %b "\x80";$p %s "$1"|$o)|$o|sha256sum|cut -b1-8)



##-===============================================-##
##   [+] Encrypted archive with openssl and tar
##-===============================================-##
tar c $Folder | openssl enc -aes-256-cbc -e > $secret.tar.enc



##-===============================================-##
##   [+] Encrypted archive with openssl and tar
##-===============================================-##
tar --create --file - --posix --gzip -- $Dir | openssl enc -e -aes256 -out $File


openssl enc -aes-256-ctr -pass $pass





cat /etc/passwd | openssl aes-256-cbc -a -e -pass $pass






step3() { s=$(echo -n $b | openssl dgst -sha1 -hmac $hmac -binary | openssl base64); signature=`for((i=0;i<${#s};i++)); do case ${s






##-=============================================-##
##   [+] View all tokens in your system use:
##-=============================================-##
p11tool --list-tokens

##-=====================================-##
##   [+] View all objects in a token:
##-=====================================-##
p11tool --login --list-all "pkcs11:TOKEN-URL"

##-==========================================================-##
##   [+] Store a private key and a certificate in a token:
##-==========================================================-##
p11tool --login --write "pkcs11:URL" --load-privkey key.pem           --label "Mykey"
p11tool --login --write "pkcs11:URL" --load-certificate cert.pem           --label "Mykey"


## ------------------------------------------------------------------ ##
##   [?] Note that some tokens require the same label to be used 
##       for the certificate and its corresponding private key.
## ------------------------------------------------------------------ ##


##-=======================================================-##
##   [+] Enumerate an RSA private key inside the token:
##-=======================================================-##
p11tool --login --generate-rsa --bits 1024 --label "MyNewKey"           --outfile MyNewKey.pub "pkcs11:TOKEN-URL"




## ----------------------------------------------------------------------------- ##
##   [?] The bits parameter in the above example is explicitly set because 
##       some tokens only support limited choices in the bit length. 
##       The output file is the corresponding public key. 
## ----------------------------------------------------------------------------- ##
##   [?] This key can be used to generate a certificate request withcerttool.
## ----------------------------------------------------------------------------- ##
certtool --generate-request --load-privkey "pkcs11:KEY-URL"    --load-pubkey MyNewKey.pub --outfile request.pem








##-============================================================-##
##   [+] Generate a key that is to be stored in file system:
##-============================================================-##
tpmtool --generate-rsa --bits 2048 --outfile tpmkey.pem

##-===========================================================-##
##   [+] Generate a key that is to be stored in TPMs flash:
##-===========================================================-##
tpmtool --generate-rsa --bits 2048 --register --user

##-=========================================-##
##   [+] Get the public key of a TPM key:
##-=========================================-##
tpmtool --pubkey tpmkey:uuid=58ad734b-bde6-45c7-89d8-756a55ad1891;storage=user           --outfile pubkey.pem

##-=================================================-##
##   [+] If the key is stored in the file system:
##-=================================================-##
tpmtool --pubkey tpmkey:file=tmpkey.pem --outfile pubkey.pem

##-=====================================-##
##   [+] List all keys stored in TPM:
tpmtool --list





ecryptfs-generate-tpm-key -p 0 -p 2 -p 3












