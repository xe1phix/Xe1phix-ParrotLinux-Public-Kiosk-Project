

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

gpg --output Xe1phix.key --armor --export 0x1251760286DD6EC3F80D
gpg --output Xe1phix.key --armor --export 0x8C2731DD2541089E88181251760286DD6EC3F80D

gpg --armor --export 0x8C2731DD2541089E88181251760286DD6EC3F80D > Xe1phix.asc
gpg --armor --export 0x1251760286DD6EC3F80D > Xe1phix.asc

gpg --output revoke.asc --gen-revoke 0x8C2731DD2541089E88181251760286DD6EC3F80D
gpg --output revoke.asc --gen-revoke 0x1251760286DD6EC3F80D


gpg --homedir /home/xe1phix/.gnupg --default-key 0x1251760286DD6EC3F80D --sign --armor --output $File


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
ls
openssl dgst -sha512 Xe1phix.asc > Xe1phix.asc.sha512
openssl dgst -sha1 Xe1phix.asc > Xe1phix.asc.sha1
sha1sum Xe1phix.asc > sha1sum && sha256sum Xe1phix.asc > sha256sum && sha512sum Xe1phix.asc > sha512sum



gpg --output doc.sig --sign doc

gpg --clearsign -o InRelease Release
gpg -abs -o Release.gpg Release



gpg --keyid-format 0xlong --verify SHA1SUMS.gpg SHA1SUMS
gpg --keyid-format 0xlong --verify SHA256SUMS.gpg SHA256SUMS



echo "-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-"
echo -e "\t Create a file with just the text test inside:"
echo "-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-"
echo -e 'test' > ~/file.txt



]


echo "-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-"
echo -e "\t> Encrypts <file> with a symmetric cipher using a passphrase"
echo -e "\t> Uses the AES-256 cipher algorithm to encrypt the passphrase"
echo -e "\t> Uses the SHA-512 digest algorithm to mangle the passphrase"
echo -e "\t> Mangles the passphrase for 65536 iterations"
echo "-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-"
gpg -c --s2k-cipher-algo AES256 --s2k-digest-algo SHA512 --s2k-count 65536 file.txt


echo "-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-"
echo -e "\t\t\t Sign An Encrypted File"
echo -e "\t This will sign the gpg encrypted file with a .asc"
echo "-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-"
gpg --clearsign file.txt.gpg



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








