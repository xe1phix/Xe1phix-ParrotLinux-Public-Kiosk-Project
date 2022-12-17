ewfinfo $Image.E01              ## Examine File Hashes
ewfinfo ewf.E01

affinfo -S $Image.aff           ## validity checking for AFF files

ewfverify $Image.Ex01           ## evidence integrity checking - validate the hash
ewfverify ewf.E01

img_stat $Image.E01             ## evidence integrity checking - 
img_stat ewf.E01

fsstat $Image.dd                ## Displays details about the file system
fsstat sde.raw

ils $Image.dd                   ## Displays inode details
ils sde.raw

fls -v -l $Image.raw
fls -v -l sde.raw

img_stat $Image.raw
img_stat sde.raw

qemu-img info $Image.raw
qemu-img info sde.raw

qemu-img info $Image.raw.aes
qemu-img info sde.raw.aes

openssl sha256 ewf.*
openssl sha512 ewf.*

openssl sha256 *.aff
openssl sha512 *.aff

openssl sha256 $Image.raw
openssl sha512 $Image.raw

openssl sha256 $File.raw.gz
openssl sha512 $File.raw.gz

openssl sha256 $Image.raw.gpg
openssl sha512 $Image.raw.gpg

openssl sha256 $File.tar.gz.gpg
openssl sha512 $File.tar.gz.gpg

openssl sha256 $Image.raw.gz.aes
openssl sha512 $Image.raw.gz.aes

openssl sha256 $Image.aff
openssl sha512 $Image.aff

