
gpg --enable-large-rsa --full-gen-key


gpg --keyid-format 0xlong --import Xe1phixCollection.asc 
gpg --batch --import ~/GnuPG/GPGKeys/*.key
gpg --import < tails-signing.key

gpg --list-keys



gpg --keyserver hkp://pool.sks-keyservers.net --recv-keys 0x
gpg --verbose --fingerprint 0x
gpg --lsign 0x
gpg --export  | sudo apt-key add -
gpg --keyserver pool.sks-keyservers.net --send-keys 0x






gpg --fingerprint B35050593C2F765640E6DDDB97CAA129F4C6B9A4
gpg --lsign B35050593C2F765640E6DDDB97CAA129F4C6B9A4
gpg --list-keys
gpg --fingerprint B35050593C2F765640E6DDDB97CAA129F4C6B9A4
gpg --fingerprint C07B79F43025772903D19385042FB0305F53BE86
gpg --lsign C07B79F43025772903D19385042FB0305F53BE86
gpg --fingerprint C686553B9795FA72214DE39CD7427F070F4FC7A6
gpg --lsign C686553B9795FA72214DE39CD7427F070F4FC7A6
gpg --fingerprint 3B3EAB807D70721BA9C03E55C7B39D0362972489
gpg --lsign 3B3EAB807D70721BA9C03E55C7B39D0362972489
gpg --export B35050593C2F765640E6DDDB97CAA129F4C6B9A4 | sudo apt-key add -
gpg --export C07B79F43025772903D19385042FB0305F53BE86 | sudo apt-key add -
gpg --export C686553B9795FA72214DE39CD7427F070F4FC7A6 | sudo apt-key add -
gpg --export 3B3EAB807D70721BA9C03E55C7B39D0362972489 | sudo apt-key add -
gpg --lsign-key 0x6ED6F5CB5FA6FB2F460AE88EEDA0D2388AE22BA9
gpg --lsign-key 0xE1CF20DDFFE4B89E802658F1E0B11894F66AEC98
gpg --lsign-key 0xD21169141CECD440F2EB8DDA9D6D8F6BC857C906
gpg --lsign-key 0x126C0D24BD8A2942CC7DF8AC7638D0442B90D010
gpg --lsign-key 0xA1BD8E9D78F7FE5C3E65D8AF8B48AD6246925553
gpg --lsign-key 0xED6D65271AACF0FF15D123036FB2A1C265FFB764
gpg --lsign-key 0x0E4EDE2C7F3E1FC0D033800E64481591B98321F9
gpg --export 0x0E4EDE2C7F3E1FC0D033800E64481591B98321F9 | sudo apt-key add -
gpg --export 0xED6D65271AACF0FF15D123036FB2A1C265FFB764 | sudo apt-key add -
gpg --export 0xA1BD8E9D78F7FE5C3E65D8AF8B48AD6246925553 | sudo apt-key add -
gpg --export 0x126C0D24BD8A2942CC7DF8AC7638D0442B90D010 | sudo apt-key add -
gpg --export 0xD21169141CECD440F2EB8DDA9D6D8F6BC857C906 | sudo apt-key add -
gpg --export 0xE1CF20DDFFE4B89E802658F1E0B11894F66AEC98 | sudo apt-key add -
gpg --export 0x6ED6F5CB5FA6FB2F460AE88EEDA0D2388AE22BA9 | sudo apt-key add -




gpg --verbose --keyid-format 0xlong --verify 

Verify the certifications made on the Tails signing key:

gpg --keyid-format 0xlong --check-sigs 


--list-key --with-key-data --with-subkey-fingerprints 
--check-sig --with-fingerprint --with-key-data
--with-fingerprint --with-colons0 --with-key-data --with-validation
--with-fingerprint --with-key-data --with-colons --print-pka-records 
--keyid-format 0xlong --with-key-data 



gpg --verify $file.iso.DIGESTS.asc $file.iso.DIGESTS && gpg --verify $file.iso.sig $file.iso



apt-key update
gpg --list-trustdb
gpg --update-trustdb
gpg --refresh-keys
gpg --rebuild-keydb-caches
gpg --check-trustdb


echo "##-======================================================-##"
echo "   [+] Configure GnuPG to use hardened defaults:"
echo "##-======================================================-##"
gpg --default-preference-list "SHA512 SHA384 SHA256 SHA224 AES256 AES192 AES CAST5 ZLIB BZIP2 ZIP Uncompressed"
gpg --cert-digest-algo SHA512
gpg --personal-digest-preferences SHA512
gpg --personal-compress-preferences ZLIB BZIP2
--cipher-algo AES256




gpg --homedir ~/.gnupg --keyring 0x --sign --armor --output $File









gpg -sb $file		## Sign The File With Your GPG Key (.sig file)

gpg --clearsign $file ## Sign The File With Your GPG Key (.asc file)



echo "##-======================================================-##"
echo "   [+] Sign files, against a recipients public gpg key"
echo "##-======================================================-##"


echo "##-==============================================================================-##"
echo "   [+] First, you need to import, verify, then sign the recipients public key:"
echo "##-==============================================================================-##"
gpg --verbose --keyid-format 0xlong --import 
gpg --verbose --fingerprint 0x
gpg --verbose --lsign-key 0x


echo "##-===============================================================-##"
echo "   [+] Now Encrypt And Sign the Files To Send To The Recipient:"
echo "##-===============================================================-##"
gpg --recipient 0x --sign --armor --output $File

gpg -u 0x -sb file




gpg --export  | sudo apt-key add -

gpg --export --armor 0x >> Freenode.asc

gpg2 --export --armor xe1phix@mail.i2p > xe1phix.asc




gpg2 --no-armor -o canary.asc --default-sig-expire 183d --clearsign canary.txt


mail a public key - export the key in ASCII armored format
gpg --export --armor | mail goronzero@gmail.com




## --------------------------------------------------------------------------------------------------------------------------- ##
https://sks-keyservers.net/sks-keyservers.netCA.pem
https://sks-keyservers.net/sks-keyservers.netCA.pem.asc
https://sks-keyservers.net/ca/crl.pem
## --------------------------------------------------------------------------------------------------------------------------- ##
The fingerprint of this certificate is 
79:1B:27:A3:8E:66:7F:80:27:81:4D:4E:68:E7:C4:78:A4:5D:5A:17 
## --------------------------------------------------------------------------------------------------------------------------- ##
and the X509v3 Subject Key Identifier is 
E4 C3 2A 09 14 67 D8 4D 52 12 4E 93 3C 13 E8 A0 8D DA B6 F3
## --------------------------------------------------------------------------------------------------------------------------- ##
https://sks-keyservers.net/pks/lookup?op=get&search=0x94CBAFDD30345109561835AA0B7F8B60E3EDFAE3
hkp://jirk5u4osbsr34t5.onion 
## --------------------------------------------------------------------------------------------------------------------------- ##



--symmetric --encrypt 

or 

--symmetric --sign --encrypt




gpg -c --s2k-cipher-algo AES256 --s2k-digest-algo SHA512 --s2k-count 65536 doc

gpg --output doc.sig --sign 

gpg --output doc.sig --clearsign 


gpg --output doc.sig --detach-sig 
gpg --export -a $GPGKEY > mykey.asc
gpg --export key-id > key.gpg

gpg --import < .gnupg/pubring.gpg.backup
gpg --import < sub.secring					## reimport your subkey stubs: 

gpg --homedir /home/xe1phix/.gnupg --armor --export-secret-keys 0x > 0x$PRIVKEYID.private.gpg-key
gpg --homedir /home/xe1phix/.gnupg --armor --export 0x > 0x$PUBKEYID.public.gpg-key
gpg --homedir /home/xe1phix/.gnupg --armor --export-secret-subkeys 0x$PRIVKEYID > subkeys
gpg --armor --export-secret-subkeys 0x$PRIVKEYID > 0x$PRIVKEYID.secret-subkeys.gpg-key

--homedir /home/xe1phix/.gnupg



## ================================================================================================================= ##
## ========================================= GPG Hidden Recipient opts ============================================= ##
## ================================================================================================================= ##
	gpg --hidden-encrypt-to				## Encrypt for user ID name, but hide the key ID of this user's key.  		 ##
	gpg --hidden-recipient				## This hides the receiver of the message and is a limited					 ##
	gpg --hidden-recipient-file			## countermeasure  against  traffic  analysis.								 ##
## ================================================================================================================= ##




Split the key into multiple parts. This breaks the key down into multiple parts:

gpgsplit key.gpg
gpg --list-packets 000002-002.sig
cat 0000* > fixedkey.gpg






