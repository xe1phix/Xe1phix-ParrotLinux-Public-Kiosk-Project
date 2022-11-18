

Xe1phix-[Gpgsm]+[OpenSSL]+[Dcfldd]+[Tar]+[GZip]-Cheatsheet-[v4.5.75].sh



##-==============================================================-##
##   [+]   [+] create a self-signed (CA) certificate, use the following command:
##-==============================================================-##

openssl req -new -x509 -days 365 -key $File.key -out $File.crt



##-==============================================================-##
##   [+]   [+] signs the log output containing the MD5 hash
##-==============================================================-##

gpg --clearsign $File.log

gpgsm -a -r $Recipient -o $File.log.pem --sign $File.log



##-=========================================================-##
##   [+] Validate The GnuPG Signature of $File.log.asc 
##   [+] Against The $Recients GnuPG signature.
##-=========================================================-##

##-=========================================================-##
##   [+] Validate The GnuPG Signature of $File.log.asc 
##   [+] Against The Trusted Developers GnuPG signature.
##-=========================================================-##


##-=========================================================-##
##   [+] Verify The Integrity of $File.img.asc 
##   [+] Against The Trusted Developers GnuPG signature.
##-=========================================================-##

##-================================================-##
##   [+] Verify The Integrity of $File.img.asc 
##   [+] Against The $Recients GnuPG signature.
##-================================================-##



gpg < $File.log.asc
gpg < $File.img.asc
gpg --keyid-format 0xlong --import < $File.img.asc



##-==============================================================-##
##   [+]   [+] S/MIME signed messages




##-==============================================================-##
##   [+]   [+] Validate the signature from a PEM file

gpgsm --verify $File.log.pem



##-==============================================================-##
##   [+]   [+] encrypt an image with AES-256-bit using cipher block chaining mode


openssl enc -aes-256-cbc -in $File.raw -out $File.raw.aes


##-==============================================================-##
##   [+]   [+] perform encryption during acquisition


dcfldd if=/dev/$Disk | openssl enc -aes-256-cbc > $File.raw.aes



##-==============================================================-##
##   [+]   [+] Decrypting an OpenSSL-encrypted file


openssl enc -d -aes-256-cbc -in $File.raw.aes -out $File.raw



##-==============================================================-##
##   [+]   [+] add gzip compression on the fly during an acquisition:


dcfldd if=/dev/$Disk | gzip | openssl enc -aes-256-cbc > $File.raw.gz.aes




##-==============================================================-##
##   [+]   [+] verify the cryptographic hash of the image


openssl enc -d -aes-256-cbc < $File.raw.gz.aes | gunzip | sha256sum



##-====================================================================-##
##    [+] Encrypt $File Using OpenSSL AES256 Symmetric Encryption:
##    [+] Decrypt A Symmetric Encrypted $File.aes Using OpenSSL:
##-====================================================================-##
openssl aes‐128‐cbc ‐salt ‐in $File ‐out $File.aes
openssl aes‐128‐cbc ‐d ‐salt ‐in $File.aes ‐out $File



##-==============================================================-##
##    [+] Use Tar To Compress Contents of /$Dir/*
##    [+] Pipe The I/O Through OpenSSL
##    [+] Encrypt The I/O Stream With AES256 Encryption
##-===============================================-##
tar ‐cf ‐ /$Dir/ | openssl aes‐128‐cbc ‐salt ‐out $File.tar.aes      ## Encrypt
openssl aes‐128‐cbc ‐d ‐salt ‐in $File.tar.aes | tar ‐x ‐f ‐            ## Decrypt



##-==============================================================-##
##   [+]   [+] tar zip and encrypt a whole directory:
##-===============================================-##
tar ‐zcf ‐ /$Dir/ | openssl aes‐128‐cbc ‐salt ‐out $File.tar.gz.aes      ## Encrypt
openssl aes‐128‐cbc ‐d ‐salt ‐in $File.tar.gz.aes | tar ‐xz ‐f ‐         ## Decrypt

