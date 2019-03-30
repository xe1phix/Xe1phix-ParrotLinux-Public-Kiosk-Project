
echo "##-############################################################################-##"
echo "##-============================================================================-##"
echo "       [+] AES-256 Encrypted-To-Base64 Encoded Split Files {Crypto-KungFu}        "
echo "##-============================================================================-##"
echo "##-############################################################################-##"


dd if=/dev/urandom of=/mnt/<Drive>/Encrypt bs=<size>M count=2

losetup -e AES256 /dev/loop0 /mnt/<Drive>/Encrypt

mkfs -t ext3 /dev/loop0

mkdir /mnt/<Drive2>

mount -t ext3 /dev/loop0 /mnt/<Drive2>

df -k

mount -t ext3 /mnt/Drive/Encrypt /mnt/<Drive2> -o loop=/dev/loop0,encryption=AES256

split --bytes=<Size> /mnt/<Drive>/Encrypt

cat xa* > Encrypt

mount -t ext3 /mnt/<Drive>/Encrypt /mnt/<Drive2> -o loop=/dev/loop0,encryption=AES256

uuencode -m xaa xaa.html > xaa.html
uuencode -m xab xab.html > xab.html

uudecode -o xaa xaa.html
uudevode -o xab xab.html
