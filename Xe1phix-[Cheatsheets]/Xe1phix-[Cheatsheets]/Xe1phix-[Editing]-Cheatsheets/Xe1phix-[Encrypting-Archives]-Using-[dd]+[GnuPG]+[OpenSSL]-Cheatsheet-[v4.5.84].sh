##-=========================================================================================-##
##   [+] Encrypt an image with 256-bit AES using cipher block chaining mode
##-=========================================================================================-##
openssl enc -aes-256-cbc -in $Image.raw -out $Image.raw.aes


##-=========================================================================================-##
##   [+] Perform encryption during acquisition
##-=========================================================================================-##
dcfldd if=/dev/$Disk status=on | openssl enc -aes-256-cbc > $Image.raw.aes
dcfldd if=/dev/sde status=on | openssl enc -aes-256-cbc > sde.raw.aes
dc3dd if=/dev/sde verb=on | openssl enc -aes-256-cbc > sde.raw.aes

##-=========================================================================================-##
##   [+] Decrypting The OpenSSL-encrypted file
##-=========================================================================================-##
openssl enc -d -aes-256-cbc -in $Image.raw.aes -out $Image.raw    
openssl enc -d -aes-256-cbc -in sde.raw.aes -out sde.raw

##-=========================================================================================-##
## Add compression on the fly during an acquisition, add gzip to the pipe
##-=========================================================================================-##
dcfldd if=/dev/$Disk status=on | gzip | openssl enc -aes-256-cbc > $Image.raw.gz.aes
dc3dd if=/dev/$Disk verb=on | gzip | openssl enc -aes-256-cbc > $Image.raw.gz.aes

##-=======================================================================-##
##  1). The decryption syntax takes the compressed and encrypted file as input
##  2). It then Pipes the decrypted output to gunzip, 
##  3). The raw image is piped to sha256sum.
## ----------------------------------------------------------------------- ##
##   TLDR: verify the cryptographic hash of the image
##-=======================================================================-##
openssl enc -d -aes-256-cbc < $Image.raw.gz.aes | gunzip | md5sum






##-=======================================================================-##
##   [+] Compress Files or A Directory 
##   [+] Pipe To GZip For Compression
##   [+] GnuPG Symmetric Encrypted Output (Encrypted With A Passphrase)
##-=======================================================================-##
tar -c $Files | gzip | gpg -c | dd of=~/$File.tar.gz.gpg
tar -c $Dir | gzip | gpg -c | dd of=~/$File.tar.gz.gpg


##-=======================================================================-##
##   [+] GnuPG Symmetric Encrypt A File (Encrypted With A Passphrase)
##-=======================================================================-##
gpg --verbose --symmetric --cipher-algo aes256 --digest-algo sha512 --cert-digest-algo sha512 --s2k-mode 3 --s2k-count 65011712 --s2k-cipher-algo AES256 --s2k-digest-algo SHA512 $File


##-===========================================================================-##
##   [+] Use GPG to encrypt a specified image, using symmetric encryption:
##-===========================================================================-##
gpg -cv $Image.raw


##-=========================================================================================-##
##   [+] encrypt on the fly during acquisition:
## ------------------------------------------------------------------------------ ##
##   1). dcfldd acquires the attached disk via /dev/$Disk 
##   2). pipes the disk directly into GPG, which reads from stdin, and encrypts to stdout.       ## GPG then redirects the finished GPG-encrypted image to an output file
## ------------------------------------------------------------------------------ ##
dcfldd if=/dev/$Disk status=on | gpg -cv > $Image.raw.gpg
dc3dd if=/dev/$Disk verb=on | gpg -cv > $Image.raw.gpg

dcfldd if=/dev/$Disk status=on | gpg --verbose --symmetric --cipher-algo aes256 --digest-algo sha512 --cert-digest-algo sha512 --s2k-mode 3 --s2k-count 65011712 --s2k-cipher-algo AES256 --s2k-digest-algo SHA512 > $image.raw.gpg
dc3dd if=/dev/$Disk verb=on | gpg --verbose --symmetric --cipher-algo aes256 --digest-algo sha512 --cert-digest-algo sha512 --s2k-mode 3 --s2k-count 65011712 --s2k-cipher-algo AES256 --s2k-digest-algo SHA512 > $image.raw.gpg


##-=================================================================================-##
##   [+] Decrypt GPG-encrypted image - Send Raw image to stdout (Output to file)
##-=================================================================================-##
## ------------------------------------------------------------------------------ ##
##   1). The GPG-encrypted image file is decrypted
##   2). The raw image is written to a file.
## ------------------------------------------------------------------------------ ##
gpg -dv -o $image.raw $image.raw.gpg
gpg -dv -o sde.raw sde.raw.gpg



##-=========================================================================================-##
##   [+] Symmetric Encryption - Decrypting A GPG-encrypted file - Piping it to sha256sum
##-=========================================================================================-##
## ----------------------------------------------------------------------------------------- ##
##           [+] The integrity is verified by Comparing:
##   (GPG-encrypted image) <--> (raw image file SHA256 Hashsum)
## ----------------------------------------------------------------------------------------- ##
gpg -dv $Image.raw.gpg | sha256sum





zcat $Image.raw.gz | sha256sum      ## zcat uncompresses it, then pipes SHA256sum to determine the sha256 cryptographic hash.
cat $Image.raw.* | sha256sum        ## Check the SHA256 hashsum of the split raw images

