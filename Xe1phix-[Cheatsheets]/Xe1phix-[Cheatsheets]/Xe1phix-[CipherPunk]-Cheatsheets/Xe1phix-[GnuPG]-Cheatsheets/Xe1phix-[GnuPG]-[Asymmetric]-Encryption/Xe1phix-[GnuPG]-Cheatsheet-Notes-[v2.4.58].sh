


echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "    [?] The Owner Exports His GPG Public Key For The Recipient:"
echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
gpg --export --armor $Owner > $Owner.asc

echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "    [+] Sign Your Public GPG Key File:"
echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
gpg --output $File.txt.asc --detach-sig $File.txt
gpg --output $File.asc.sig --sign $File.asc

echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "     [?] The Recipient Imports The GPG Public Key:"
echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
gpg --import < $GPGKeyFile
gpg --import qubes-secpack/keys/*/*
gpg --verbose --keyid-format 0xlong --import $GPGKeyFile



echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "    [+] Verify The Recipients Signature File Against The Base File:"
echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
gpg --verify --keyid-format 0xlong $file.txt.gpg $file.txt

echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "    [+] Verify The Integrity of SHA Hashsums:"
echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
gpg --verify SHA1SUMS.gpg SHA1SUMS
gpg --verify SHA256SUMS.gpg SHA256SUMS
gpg --verify SHA512SUMS.gpg SHA512SUMS


echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "    [+] Verify The Integrity of A File             "
echo "    [?] Against Its GPG Signed File (.asc file):   "
echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
gpg --verbose --keyid-format 0xlong --verify 


echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "          [+] Encrypt & Sign A File:               "
echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "## --------------------------------------------- ##"
echo "     [?] Only Decryptable By The Recipient.        "
echo "## --------------------------------------------- ##"
gpg --encrypt --sign --armor -r <$Recipient>@email.com $File
gpg -se -r $Recipient $File


echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "    [+] Decrypt A File Encrypted By GnuPG:"
echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
gpg --output $file.txt --decrypt $file.txt.gpg






gpg --output doc.sig --sign doc
gpg --output doc.sig --clearsign doc
gpg --output doc.sig --detach-sig doc






##-==============================================================-##
##   [+]   [+] create a self-signed (CA) certificate, use the following command:
openssl req -new -x509 -days 365 -key ca.key -out ca.crt


##-==============================================================-##
##   [+]   [+] signs the log output containing the MD5 hash
gpg --clearsign hash.log
gpgsm -a -r holmes@digitalforensics.ch -o hash.log.pem --sign hash.log


##-==============================================================-##
##   [+]   [+] verify the gpg signature of the person who signed the acquired disk image:
gpg < hash.log.asc

##-==============================================================-##
##   [+]   [+] Validate the signature from a PEM file
gpgsm --verify image.log.pem






gpg --enable-large-rsa --full-gen-key



gpg --recv-key 0x
gpg --keyserver x-hkp://pool.sks-keyservers.net --recv-keys 0x
apt-key adv --keyserver x-hkp://pool.sks-keyservers.net --recv-keys 0x
gpg --keyserver hkp://jirk5u4osbsr34t5.onion --recv-keys 0x
gpg --keyserver pool.sks-keyservers.net --recv-keys 0x
gpg --keyserver subkeys.pgp.net --recv-keys 0x
gpg --keyserver keys.gnupg.net --recv-keys 0x
gpg --keyserver keys.riseup.net --recv-keys 0x
gpg --keyserver ldap://keyserver.pgp.com --recv-keys 0x
gpg --keyserver keys.inscrutable.i2p --recv-keys 0x
gpg --keyserver pgpkeys.mit.edu --recv-keys 0x
gpg --keyserver keyserver.ubuntu.com --recv-keys 0x
gpg --keyserver keyserver.opensuse.org --recv-keys 0x
gpg --keyserver keys.fedoraproject.org --recv-keys 0x
gpg --keyserver keys.i2p-projekt.de --recv-keys 0x

gpg --keyserver pool.sks-keyservers.net --send-keys 0x
gpg --keyserver keyring.debian.org --send-keys 0x
gpg --export  | sudo apt-key add -



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

sha256sum -c SHA256SUMS

openssl dgst -md5 $File
openssl dgst -sha1 $File
openssl dgst -sha256 $File
openssl dgst -sha512 $File







