#!/bin/sh


echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "    [+] Create A GPG Key:"
echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
gpg --enable-large-rsa --full-gen-key



echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "    [?] The Owner Exports His GPG Public Key For The Recipient:"
echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
gpg --export --armor $Owner > $Owner.asc
gpg --armor --export $Owner@$Email.com > $Owner.asc
gpg --verbose --armor --export $Owner@$Email.com > 0x$FullGPGFingerprint.asc
gpg --verbose --armor --export $Owner@$Email.com > 0x$GPGKeyID.asc


echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "    [?] Xe1phix Exports His Public GnuPG Key For Recipients:"
echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
gpg --export --armor Xe1phix > Xe1phix.asc
gpg --armor --export Xe1phix@mail.i2p > Xe1phix.asc
gpg --verbose --armor --export Xe1phix@mail.i2p > 0x8C2731DD2541089E88181251760286DD6EC3F80D.asc
gpg --verbose --armor --export Xe1phix@mail.i2p > 0x760286DD6EC3F80D.asc


echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "    [+] Sign Your Public GPG Key File:"
echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
gpg --output $File.txt.asc --detach-sig $File.txt
gpg --output $File.asc.sig --sign $File.asc


echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "    [+] Xe1phix - Signing His Public GPG Key File:"
echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
gpg --output Xe1phix.txt.asc --detach-sig Xe1phix.txt
gpg --output Xe1phix.asc.sig --sign Xe1phix.asc


echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "     [?] The Recipient Imports The GPG Public Key:"
echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
gpg --import < $GPGKeyFile
gpg --import qubes-secpack/keys/*/*
gpg --verbose --keyid-format 0xlong --import $GPGKeyFile


echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "     [?] Import Xe1phix's Public GnuPG Key:"
echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
gpg --import < Xe1phix.asc
gpg --verbose --keyid-format 0xlong --import Xe1phix.asc


echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "    [+] Retrieve The Recipients Public GPG Key From The KeyServer:"
echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
gpg --keyserver pool.sks-keyservers.net --recv-keys 0x
apt-key adv --keyserver x-hkp://pool.sks-keyservers.net --recv-keys 0x
gpg --keyserver subkeys.pgp.net --recv 
gpg --keyserver pgp.mit.edu --recv-keys 
gpg --keyserver hkp://qdigse2yzvuglcix.onion --recv-keys 0x


echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "    [+] Retrieve Xe1phix's Public GPG Key From The KeyServers:"
echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
gpg --keyserver pool.sks-keyservers.net --recv-keys 0x8C2731DD2541089E88181251760286DD6EC3F80D
apt-key adv --keyserver x-hkp://pool.sks-keyservers.net --recv-keys 0x8C2731DD2541089E88181251760286DD6EC3F80D



echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "    [+] Send The Recipients Public GPG Key To The Server:"
echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
gpg --keyserver pool.sks-keyservers.net --send-keys 0x$GPGFingerprint
gpg --keyserver keyring.debian.org --send-keys 0x$GPGFingerprint



echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "    [+] Export The Recipients Public GPG Key Into Your List of Trusted Keys:"
echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
gpg --export $GPGFingerprint | sudo apt-key add -



echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "    [+] Create A File With Just The Text "test" Inside:"
echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo -e 'test' > ~/file.txt



echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "    [+] Encrypts $File With A Symmetric Cipher Encryption (Using A Passphrase):"
echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "## ------------------------------------------------------------------------------- ##"
echo "    [?] Uses The AES-256 Cipher Algorithm To Encrypt The Passphrase"
echo "    [?] Uses The SHA-512 Digest Algorithm To Mangle The Passphrase"
echo "    [?] Mangles The Passphrase For 65536 Iterations"
echo "## ------------------------------------------------------------------------------- ##"
gpg -c --s2k-cipher-algo AES256 --s2k-digest-algo SHA512 --s2k-count 65536 $file.txt
--s2k-mode 3
gpg --symmetric --cipher-algo aes256 --digest-algo sha256 --cert-digest-algo sha256


gpg --symmetric --cipher-algo aes256 --digest-algo sha512 --cert-digest-algo sha512 16105696.jpeg
rm -f 16105696.jpeg
gpg -d 16105696.jpeg.gpg > 16105696.jpeg



echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "                    [+] Sign A GPG Encrypted File:"
echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "## --------------------------------------------------------------------- ##"
echo "        [?] This Will Sign The GPG Encrypted File (.gpg.asc)"
echo "## --------------------------------------------------------------------- ##"
echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
gpg --clearsign $file.txt.gpg
gpg -abs -o $Release.gpg $Release


echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "     [+] Print The Recipients Public GnuPG Key Fingerprint:"
echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "## ----------------------------------------------------------- ##"
echo "     [?] Compare It To What Its Supposed To Be."
echo "## ----------------------------------------------------------- ##"
gpg --fingerprint Xe1phix
gpg --fingerprint Xe1phix@mail.i2p
gpg --verbose --fingerprint 0xA271C1004F10F66529E4D8A4DCB041AA34E56227



echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "    [+] Sign The Recipients Public key:"
echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
gpg --lsign Xe1phix
gpg --lsign Xe1phix@mail.i2p
gpg --lsign 0xA271C1004F10F66529E4D8A4DCB041AA34E56227


echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "    [+] Signing Files With Your GPG Key:"
echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
gpg -sb $file               ## Sign The File With Your GPG Key (.sig file)
gpg --clearsign $file       ## Sign The File With Your GPG Key (.asc file)



echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "          [+] Encrypt & Sign A File:               "
echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "## --------------------------------------------- ##"
echo "     [?] Only Decryptable By The Recipient.        "
echo "## --------------------------------------------- ##"
gpg --encrypt --sign --armor -r <$Recipient>@email.com $File
gpg -se -r $Recipient $File


echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "     [+] Encrypt & Sign A File (Using Xe1phix As The Recipient):       "
echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
gpg --encrypt --sign --armor --recipient Xe1phix@mail.i2p $File
gpg -se -r Xe1phix@mail.i2p $File

gpg --encrypt --sign --armor --recipient Xe1phix $File
gpg --encrypt --sign --armor --recipient 8C2731DD2541089E88181251760286DD6EC3F80D $File
gpg --encrypt --sign --armor --recipient 760286DD6EC3F80D $File



echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "    [+] Create SHA Hashsums:"
echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
openssl dgst -sha1 $File
openssl dgst -sha256 $File
openssl dgst -sha512 $File



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




echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "    [+] Verify Integrity of ISO Files:"
echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "## --------------------------------------- ##"
echo "    [?] (Signed By Trusted Developers)"
echo "## --------------------------------------- ##"
gpg --keyid-format 0xlong --verify tails-i386-*.*.iso.sig tails-i386-*.*.iso
gpg --verbose --verify securityonion-*.*.*.*.iso.sig securityonion-*.*.*.*.iso
gpg --keyid-format 0xlong --verify Qubes-*.iso.asc Qubes-*.iso
gpg --keyid-format 0xlong --verify Whonix-Gateway-*.libvirt.xz.asc Whonix-Gateway-*.libvirt.xz
gpg --keyid-format 0xlong --verify Whonix-Workstation-*.libvirt.xz.asc Whonix-Workstation-*.libvirt.xz
gpg --verify subgraph-*.iso.sha256.sig subgraph-*.iso.sha256



echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "    [+] Verify Integrity of A Trusted Developers Canary:"
echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
gpg --verify $canary-*-2018.txt.sig $canary-*-2018.txt



echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "    [+] Decrypt A File Encrypted By GnuPG:"
echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
gpg --output $file.txt --decrypt $file.txt.gpg


echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "    [+] Output The Hash of The Raw Image File:"
echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
gpg -dv $image.raw.gpg | sha256sum


echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "    [+] Encrypt An Image With OpenSSL:"
echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "## ------------------------------------------- ##"
echo "    [?] Using 256-bit AES Encryption" 
echo "    [?] Cipher Block Chaining Mode Enabled"
echo "## ------------------------------------------- ##"
openssl enc -aes-256-cbc -in $image.raw -out $image.raw.aes


echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "    [+] Decrypt An OpenSSL Encrypted File:"
echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
openssl enc -d -aes-256-cbc -in $image.raw.aes -out $image.raw


echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "    [+] Verify The Cryptographic Hash of An Image:"
echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
openssl enc -d -aes-256-cbc < $image.raw.gz.aes | gunzip | sha256sum


