#!/bin/sh


gpg2 --enable-large-rsa --full-gen-key
gpg --recv-keys 0x
gpg --keyserver x-hkp://pool.sks-keyservers.net --recv-keys 0x
gpg --keyserver pool.sks-keyservers.net --recv-keys 0x
gpg --keyserver x-hkp://pool.sks-keyservers.net --recv-keys "69B4 D9BE 2765 A81E 5736 8CD9 0904 1C77 C434 1056"
apt-key adv --keyserver x-hkp://pool.sks-keyservers.net --recv-keys 0x
gpg --keyserver pool.sks-keyservers.net --send-keys 0x
gpg --export  | sudo apt-key add -

curl --tlsv1 --url   --output /home/xe1phix/GnuPG/$i.{asc|key|pub|gpg} && gpg --keyid-format 0xlong --import $i && gpg --fingerprint $i | grep fingerprint
wget -qO - http://archive.parrotsec.org/parrot/misc/parrotsec.gpg | apt-key add -
curl https://getfedora.org/static/fedora.gpg | gpg --import
curl --verbose --progress-bar --tlsv1 --url=  --output
curl --tlsv1.2 --url https://keys.qubes-os.org/keys/qubes-master-signing-key.asc --verbose --output /home/faggot/Gnupg/qubes-master-signing-key.asc

gpg --import < schneier-gpgkey.txt
gpg --import qubes-secpack/keys/*/*
gpg --keyid-format 0xlong --import 

gpg --edit-key 

gpg --fingerprint schneier
gpg --fingerprint schneier@schneier.com
gpg --verbose --fingerprint 0xA271C1004F10F66529E4D8A4DCB041AA34E56227
gpg --list-sigs 0x
gpg --list-keys --with-fingerprint 
gpg --list-sig 


gpg --lsign schneier
gpg --lsign 0xA271C1004F10F66529E4D8A4DCB041AA34E56227

gpg --keyserver pool.sks-keyservers.net --send-keys 0x


openssl dgst -sha1 
openssl dgst -sha256 
openssl dgst -sha512 

gpg --verify SHA1SUMS.gpg SHA1SUMS
gpg --verify SHA256SUMS.gpg SHA256SUMS
gpg --verify SHA512SUMS.gpg SHA512SUMS

gpg --verbose --keyid-format 0xlong --verify 
gpg --verify $file.iso.DIGESTS.asc $file.iso.DIGESTS && gpg --verify $file.iso.sig $file.iso

gpg --no-armor -o canary.asc --default-sig-expire 183d --clearsign canary.txt
gpg --verify canary-001-2015.txt.sig.joanna canary-001-2015.txt

gpg --verbose --fingerprint --with-subkey-fingerprint
gpg --verbose --fingerprint --with-keygrip
gpg --verbose --fingerprint --with-key-data
gpg --verbose --fingerprint --with-colons

gpg --list-key --with-key-data --with-subkey-fingerprints 
gpg --check-sig --with-fingerprint --with-key-data
gpg --with-fingerprint --with-colons0 --with-key-data --with-validation
gpg --with-fingerprint --with-key-data --with-colons --print-pka-records 
gpg --keyid-format 0xlong --with-key-data 


gpg -sb $file		## Sign The File With Your GPG Key (.sig file)

gpg --clearsign $file ## Sign The File With Your GPG Key (.asc file)


gpg -c --s2k-cipher-algo AES256 --s2k-digest-algo SHA512 --s2k-count 65536 doc

gpg --output doc.sig --sign 

gpg --output doc.sig --clearsign 


gpg --output doc.sig --detach-sig 
gpg --export -a $GPGKEY > mykey.asc
gpg --export key-id > key.gpg

gpg --homedir ~/.gnupg --keyring 0x --sign --armor --output $File






/usr/share/keyrings/debian-archive-keyring.gpg
/usr/share/keyrings/debian-archive-removed-keys.gpg
/usr/share/keyrings/debian-keyring.gpg
/usr/share/keyrings/debian-maintainers.gpg
/usr/share/keyrings/debian-nonupload.gpg
/usr/share/keyrings/debian-role-keys.gpg
/usr/share/keyrings/i2p-archive-keyring.gpg
/usr/share/keyrings/i2p-archive-removed-keys.gpg
/usr/share/keyrings/kytv-archive-keyring.gpg
/usr/share/keyrings/kytv-archive-removed-keys.gpg
/usr/share/keyrings/parrot-archive-keyring.gpg
