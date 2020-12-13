


XE1PHIX_FINGERPRINT="8C27 31DD 2541 089E 8818  1251 7602 86DD 6EC3 F80D

XE1PHIX_EMAIL="xe1phix@gmail.com"
XE1PHIX_ALTEMAIL="xe1phix@protonmail.ch"
XE1PHIX_I2PMAIL="Xe1phix@mail.i2p"




To check the available entropy, check the kernel parameters:
cat /proc/sys/kernel/random/entropy_avail



echo "personal-digest-preferences SHA512 SHA256" >> ~/.gnupg/gpg.conf
echo "cert-digest-algo SHA512" >> ~/.gnupg/gpg.conf
echo "default-preference-list SHA512 SHA384 SHA256 SHA224 AES256 AES192 AES ZLIB BZIP2 ZIP Uncompressed" >> ~/.gnupg/gpg.conf
echo "personal-cipher-preferences AES256 AES192 AES" >> ~/.gnupg/gpg.conf

(PGP|GPG) SIGNED MESSAGE
(PGP|GPG) SIGNATURE
(SHA1|SHA256|SHA512)

echo "-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-"
echo -e "\t The Owner exports his GPG public key for the recipient"
echo "-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-"
gpg --export --armor Xe1phix > Xe1phix.asc
gpg -a -o $HOME/$i-signed.asc --export $i



gpg --output Xe1phix.key --armor --export 1251760286DD6EC3F80D
gpg --output Xe1phix.key --armor --export 8C2731DD2541089E88181251760286DD6EC3F80D
gpg --output Xe1phix.txt --armor --export 1251760286DD6EC3F80D

gpg --output Xe1phix.key --armor --export 0x8C2731DD2541089E88181251760286DD6EC3F80D


gpg --output 0x1251760286DD6EC3F80D.asc --armor --export 1251760286DD6EC3F80D
gpg --output 0x1251760286DD6EC3F80D.asc --armor --export 8C2731DD2541089E88181251760286DD6EC3F80D

gpg --output 0x1251760286DD6EC3F80D.sig --sign 0x1251760286DD6EC3F80D.asc

gpg --output Xe1phix.txt.asc --detach-sig Xe1phix.txt
gpg --output Xe1phix.asc.sig --sign Xe1phix.asc

gpg -abs -o Xe1phix.gpg Xe1phix.asc
gpg -abs -o 0x1251760286DD6EC3F80D.gpg 0x1251760286DD6EC3F80D.asc

gpg --verbose --output Xe1phixSourcesV-1.4.list.asc --detach-sig Xe1phixSourcesV-1.4.list
gpg --verbose --output LPIC-2-v6.0.sh.asc --detach-sig LPIC-2-v6.0.sh

## gpg: writing to 'Xe1phix.txt.asc'
## gpg: writing to 'Xe1phix.asc.sig'
## gpg: writing to '0x1251760286DD6EC3F80D.sig'
## gpg: writing to '0x1251760286DD6EC3F80D.gpg'
## gpg: writing to 'Xe1phix.txt.sig'
## gpg: writing to 'Xe1phix.gpg'
## 
## 
## gpg: RSA/SHA512 signature from: "760286DD6EC3F80D Xe1phix ("From Nothing To Being There is No Logic Bridge.") <Xe1phix@mail.i2p>"


gpg --armor --export 0x8C2731DD2541089E88181251760286DD6EC3F80D > Xe1phix.asc
gpg --armor --export 0x1251760286DD6EC3F80D > Xe1phix.asc

## RFC-3161 Timestamping Signatures with PGP or S/MIME
openssl ts -query -data Xe1phix.asc -out Xe1phix.asc.tsq -cert


## files can be sent to the FreeTSA service:
tsget -h https://freetsa.org/tsr Xe1phix.asc.tsq

## view the contents of the timestamp
openssl ts -reply -in Xe1phix.asc.tsr -text

## Validate the timestamp using:
## The Timestamp Query ( tsq ) 
## The Timestamp Reponse ( tsr )
openssl ts -verify -in Xe1phix.asc.tsr -queryfile Xe1phix.asc.tsq -CAfile cacert.pem


gpg --output revoke.asc --gen-revoke 0x8C2731DD2541089E88181251760286DD6EC3F80D
gpg --output revoke.asc --gen-revoke 0x1251760286DD6EC3F80D


gpg --homedir /home/xe1phix/.gnupg --default-key 0x1251760286DD6EC3F80D --sign --armor --output $File

gpg --homedir /etc/portage/gpg --edit-key DCD05B71EAB94199527F44ACDB6B8C1F96D8BF6D trust



--primary-keyring --homedir
--keyring
--default-key

--secret-keyring
gpg --clear-sign 
gpg -u 0x12345678 -sb file

openssl dgst -sha1 Xe1phix.asc
openssl dgst -sha256 Xe1phix.asc
openssl dgst -sha512 Xe1phix.asc


openssl dgst -sha256 Xe1phix.asc
openssl dgst -sha256 Xe1phix.asc > Xe1phix.asc.sha256

openssl dgst -sha512 Xe1phix.asc > Xe1phix.asc.sha512
openssl dgst -sha1 Xe1phix.asc > Xe1phix.asc.sha1


sha1sum Xe1phix.asc > sha1sum 
sha256sum Xe1phix.asc > sha256sum 
sha512sum Xe1phix.asc > sha512sum


{,.DIGESTS.asc,.DIGESTS}
{,.gpgsig,.sha256sum}
sha1sum -c stage3*.tar.bz2.DIGESTS
gpg --verify stage3-*.tar.bz2.DIGESTS.asc
gpg --verify portage-latest.tar.bz2.gpgsig portage-latest.tar.bz2

echo "## =========================================== ##"
echo "	   [+] Checking sha256sum Hash of $File         "
echo "## =========================================== ##"
grep "$file" "$sums" | sha256sum -c


gpg --output doc.sig --sign doc
gpg --output doc.asc --clearsign doc
gpg --output doc.sig --detach-sig doc


## create a self-signed (CA) certificate, use the following command:
openssl req -new -x509 -days 365 -key ca.key -out ca.crt



gpg --clearsign -o 


## signs the log output containing the MD5 hash
gpg --clearsign hash.log
gpgsm -a -r holmes@digitalforensics.ch -o hash.log.pem --sign hash.log


## verify the gpg signature of the person who signed the acquired disk image:
gpg < hash.log.asc

## S/MIME signed messages, 

## Validate the signature from a PEM file
gpgsm --verify image.log.pem


## Fetch the CA cert from FreeTSA
curl http://freetsa.org/files/cacert.pem > cacert.pem

## Validate the timestamp using:
## The Timestamp Query ( tsq ) 
## The Timestamp Reponse ( tsr )
openssl ts -verify -in hash.log.tsr -queryfile hash.log.tsq -CAfile cacert.pem



gpg --clearsign -o InRelease Release
gpg -abs -o Release.gpg Release

gpg -abs -o SHA1SUMS.gpg SHA1SUMS
gpg -abs -o SHA256SUMS.gpg SHA256SUMS
gpg -abs -o SHA512SUMS.gpg SHA512SUMS





echo "## ================================================ ##"
echo "	   [+] Verifying SHA Hashsum Integrity against      "
echo "         The Publishers GnuPG Signature file:         "
echo "## ================================================ ##"

gpg --keyid-format 0xlong --verify SHA1SUMS.gpg SHA1SUMS
gpg --keyid-format 0xlong --verify SHA256SUMS.gpg SHA256SUMS
gpg --keyid-format 0xlong --verify SHA512SUMS.gpg SHA512SUMS


gpg --verify $sig $sums 2>/dev/null | grep "VALIDSIG"




## RFC-3161 Timestamping Signatures with PGP or S/MIME
openssl ts -query -data hash.log -out hash.log.tsq -cert

## files can be sent to the FreeTSA service:
tsget -h https://freetsa.org/tsr hash.log.tsq


## Manually submit the timestamp request with the curl command as follows:
curl -s -H "Content-Type: application/timestamp-query" --data-binary "@hash.log.tsq" https://freetsa.org/tsr > hash.log.tsr


## view the contents of the timestamp
openssl ts -reply -in hash.log.tsr -text




s_client -host boreas.openna.com -port 993

openssl req -new -x509 -nodes -days 365 -out tmp.pem


echo "-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-"
echo -e "\t Create a file with just the text test inside:"
echo "-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-"
echo -e 'test' > ~/file.txt



]

()     

echo "-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-"
echo -e "\t>  []Encrypt <file> with a symmetric cipher using a passphrase"
echo -e "\t>      Uses the AES-256 cipher algorithm to encrypt the passphrase"
echo -e "\t>      Uses the SHA-512 digest algorithm to mangle the passphrase"
echo -e "\t>      Mangles the passphrase for 65536 iterations"
echo "-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-"
gpg -c --s2k-cipher-algo AES256 --s2k-digest-algo SHA512 --s2k-count 65536 file.txt



## encrypt an image with 256-bit AES using cipher block chaining mode
openssl enc -aes-256-cbc -in image.raw -out image.raw.aes

## perform encryption during acquisition
dcfldd if=/dev/sdg | openssl enc -aes-256-cbc > image.raw.aes


## Decrypting an OpenSSL-encrypted file
openssl enc -d -aes-256-cbc -in image.raw.aes -out image.raw


## add gzip compression on the fly during an acquisition:
dcfldd if=/dev/sdg | gzip | openssl enc -aes-256-cbc > image.raw.gz.aes



## verify the cryptographic hash of the image
openssl enc -d -aes-256-cbc < image.raw.gz.aes | gunzip | sha256sum


cat ${HOME}/${HOST}.pem | openssl x509 -fingerprint -noout -in /dev/stdin

openssl x509 -in /usr/local/share/ca-certificates/frozenCA.crt -noout -text

openssl dgst -sha512 -verify /home/$USER/.gnupg/Gnupg-Pub/securix-codesign.pub -signature "${LASTVERSION}.tar.gz.sign" "${LASTVERSION}.tar.gz"
openssl dgst -sha512 -verify securix-codesign.pub -signature sha512.hash.sign sha512.hash


curl --socks5 127.0.0.1:9150
curl --resolve 127.0.0.1:4444


echo "-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-"
echo -e "\t\t\t Sign An Encrypted File"
echo -e "\t This will sign the gpg encrypted file with a .asc"
echo "-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-"
gpg --clearsign file.txt.gpg



## ======================================================== ##
## -------------------- Keyrings -------------------------- ##
## ======================================================== ##
## /usr/share/keyrings/debian-archive-keyring.gpg
## /usr/share/keyrings/debian-archive-removed-keys.gpg
## /usr/share/keyrings/debian-keyring.gpg
## /usr/share/keyrings/debian-maintainers.gpg
## /usr/share/keyrings/debian-nonupload.gpg
## /usr/share/keyrings/debian-role-keys.gpg
## /usr/share/keyrings/i2p-archive-keyring.gpg
## /usr/share/keyrings/i2p-archive-removed-keys.gpg
## /usr/share/keyrings/kytv-archive-keyring.gpg
## /usr/share/keyrings/kytv-archive-removed-keys.gpg
## /usr/share/keyrings/parrot-archive-keyring.gpg


## ======================================================== ##
## ----------------- Aptitude Trusted Keys ---------------- ##
## ======================================================== ##
## /etc/apt/trusted.gpg.d/debian-archive-jessie-automatic.gpg
## /etc/apt/trusted.gpg.d/debian-archive-jessie-security-automatic.gpg
## /etc/apt/trusted.gpg.d/debian-archive-jessie-stable.gpg
## /etc/apt/trusted.gpg.d/debian-archive-squeeze-automatic.gpg
## /etc/apt/trusted.gpg.d/debian-archive-squeeze-stable.gpg
## /etc/apt/trusted.gpg.d/debian-archive-wheezy-automatic.gpg
## /etc/apt/trusted.gpg.d/debian-archive-wheezy-stable.gpg
## /etc/apt/trusted.gpg.d/parrot-archive-keyring.gpg
## /etc/apt/trusted.gpg.d/pkg-mozilla-archive-keyring.gpg
## /etc/apt/trusted.gpg.d/whonix.gpg




echo "##-===============================================================-##"
echo "##~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~##"
echo "##-===============================================================-##"
echo "##=---------------------------------------------------------------=##"
echo "##        {+} Retrieving A Recipients CipherPunk Identifiers       ##"
echo "##                   (GnuPG Key |IRC|OTR|pem|crt)                  ##"
echo "##=---------------------------------------------------------------=##"
echo "##-===============================================================-##"



##-======================================================-##
##~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~~=~=~=~=~=~=~##
##    <<------------------------------------------->>
##        {+} Retrieving Someone Elses GnuPG Key:
##    <<------------------------------------------->>
##~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~~=~=~=~=~=~=~##
##-======================================================-##

Retrieving Someone Elses GnuPG Key:


echo "## _____________________________________________________________  ##"
echo "##|_____________________________________________________________|-##"
















	## ======================= ##
	  ## Clearnet Keyservers: ##
	## ========================##
## ================================== ##
## keyserver hkp://keys.gnupg.net
## keyserver hkp://subkeys.pgp.net
## keyserver mailto:pgp-public-keys@keys.pgp.net
## keysever ldap://keyserver.pgp.com
## ldap://pgp.surfnet.nl:11370
## keyserver pgp.mit.edu
## ------------------------------- ##
## p80.pool.sks-keyservers.net
## ha.pool.sks-keyservers.net
## pool.sks-keyservers.net
## eu.pool.sks-keyservers.net
## na.pool.sks-keyservers.net
## oc.pool.sks-keyservers.net
## ipv6.pool.sks-keyservers.net
## ipv4.pool.sks-keyservers.net
## hkp://jirk5u4osbsr34t5.onion
## ------------------------------- ##
## keys.fedoraproject.org
## keys.i2p-projekt.de
## keyserver.opensuse.org
## keyserver.ubuntu.com
## keyserver.freenet.de
## ----------------------------------- ##
## zimmermann.mayfirst.org
## 	keyserver.freenet.de
## zimmermann.mayfirst.org 11370
## ----------------------------------- ##
## keyserver hkps://keys.mayfirst.org
## keyserver hkp://keys.mayfirst.org
## =================================================================================== ##



## ========================================= ##
## -- KillYourTV Darknet IRC Channel Cert -- ##
## ========================================= ##
## http://killyourtv.i2p/ircserver/kytv-cacert.pem
## /usr/local/share/ca-certificates/kytv-cacert.crt
## update-ca-certificates
## ------------------------------------------------------------------------------------------------------------------ ##
## curl --resolve 127.0.0.1:4444:http://killyourtv.i2p/killyourtv.asc
## curl --resolve 127.0.0.1:9053:https://tails.boum.org/tails-signing.key

## keyserver-options http-proxy=socks5-hostname://127.0.0.1:9050
## keyserver-options http-proxy=socks5-hostname://127.0.0.1:9050




	## ======================= ##
	## ----------------------- ##
	## 	Indymedia Keyservers:  ##
	## ------------------------##
	## ======================= ##

## tor+http://deb.kkkkkkkkkk63ava6.onion


## keyserver='http://18.9.60.141'                    ## cryptonomicon.mit
## keyserver='hkp://209.234.253.170'                 ## keys.mayfirst.org
## keyserver='hkps://2eghzlv2wwcq7u7y.onion'         ## keys.indymedia.org (hkps)
## kerserver='https://qtt2yl5jocgrk7nu.onion'


## keyserver hkps://2eghzlv2wwcq7u7y.onion
## keyserver hkp://2eghzlv2wwcq7u7y.onion
## keyserver hkps://keys.indymedia.org
## keyserver hkp://keys.indymedia.org
## keyserver https://keys.indymedia.org
## keyserver http://keys.indymedia.org
## keyserver https://qtt2yl5jocgrk7nu.onion
## keyserver http://qtt2yl5jocgrk7nu.onion
## keyserver hkp://jirk5u4osbsr34t5.onion
## ===================================================================== ##
## keyserver-options ca-cert-file=~/scripts/certs/keys.indymedia.org
## kerservopts=$keyservopts" ca-cert-file=~/.keys.indymedia.org.pem"
## ===================================================================== ##
## keyserver hkps://keys.mayfirst.org
## keyserver hkp://keys.mayfirst.org
## ===================================================================== ##



apt-key adv --keyserver x-hkp://pool.sks-keyservers.net --recv-keys 0x
gpg --keyserver pool.sks-keyservers.net --send-keys 0x
gpg --keyserver keyring.debian.org --send-keys 0x
gpg --export  | sudo apt-key add -

gpg --recv-key 0x
gpg --keyserver x-hkp://pool.sks-keyservers.net --recv-keys 0x
gpg --keyserver subkeys.pgp.net --recv-keys 0x
gpg --keyserver keys.gnupg.net --recv-keys 0x









echo "-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-"
echo -e "\t If you are the recipient, import the other persons public key:"
echo "-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-"
gpg --keyid-format 0xlong --import Xe1phix.asc


echo "-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-"
echo -e "\t Print the creators public GPG key fingerprint out"
echo -e "\t And compare it to what its supposed to be"
echo "-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-"
gpg --fingerprint Xe1phix
gpg --fingerprint 0xA271C1004F10F66529E4D8A4DCB041AA34E56227

gpg --fingerprint $i | grep fingerprint

echo "-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-"
echo -e "\t Sign The Creators Public key:"
echo "-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-"
gpg --lsign Xe1phix
gpg --lsign 0xA271C1004F10F66529E4D8A4DCB041AA34E56227




echo "-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-"
echo -e "Verify The file against the signature the other person made for that file"
echo "-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-"
gpg --verify --keyid-format 0xlong file.txt.gpg file.txt

gpg --keyid-format 0xlong --verify 

echo "-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-"
echo -e "\t\t Finally, Decrypt the file:"
echo "-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-"
gpg --output file.txt --decrypt file.txt.gpg






## Using GPG to encrypt an existing image
gpg -cv image.raw

## dcfldd acquires the disk 
## While being piped to gpg, encrypting it on the fly
dcfldd if=/dev/sde | gpg -cv > image.raw.gpg

## GPG-encrypted image file is decrypted
gpg -dv -o image.raw image.raw.gpg

## output the hash of the raw image file
gpg -dv image.raw.gpg | sha256sum



s2k-cipher-algo AES256
s2k-digest-algo SHA512
s2k-mode 3

cert-digest-algo SHA512
digest-algo SHA512





• Comodo RFC-3161 Timestamping Service: 
http://timestamp.comodoca.com/?td=sha256
• FreeTSA: 
http:// freetsa.org/ index_en.php
• Polish CERTUM PCC - General Certification Authority: 
http://time.certum.pl/
• Safe Creative Timestamping Authority (TSA) server: 
http://tsa.safecreative.org/
• StartCom Free RFC-3161 Timestamping Service: 
http:// tsa.startssl.com/rfc3161
• Zeitstempeldienst der DFN-PKI: 
http:// www.pki.dfn.de/ zeitstempeldienst/
