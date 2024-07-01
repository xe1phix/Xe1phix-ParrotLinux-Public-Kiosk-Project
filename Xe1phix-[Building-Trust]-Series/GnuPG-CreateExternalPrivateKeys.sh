
https://wiki.debian.org/Subkeys?action=show&redirect=subkeys
https://help.ubuntu.com/community/GPGKeyOnUSBDrive


export GNUPGHOME=/media/


Export the key:

gpg --export key-id > key.gpg


Split the key into multiple parts. This breaks the key down into multiple parts:

gpgsplit key.gpg



gpg --list-packets 000002-002.sig



Put the key back together:

cat 0000* > fixedkey.gpg




mount -t tmpfs -o size=1M tmpfs /tmp/gpg


umount /tmp/gpg



gpg --homedir /tmp/gpg --import 


gpg --list-trustdb
gpg --update-trustdb
gpg --list-ownertrust
gpg --export-ownertrust > otrust.txt
gpg --armor --export-secret-keys 0x98DDBB4E22CA2C83 > 0x98DDBB4E22CA2C83.private.gpg-key
gpg --armor --export 0x98DDBB4E22CA2C83 > 0x98DDBB4E22CA2C83.public.gpg-key
gpg --import-ownertrust < otrust.txt

