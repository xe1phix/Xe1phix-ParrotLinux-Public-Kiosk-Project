#!/bin/sh
##-===========================================================-##
##   [+] Encrypting-Files-With-OpenSSL-Using-AES-256-CBC.sh
##-===========================================================-##


echo "##-====================================================-##"
echo "    [+] Encrypt The .jpeg File With OpenSSL:"
echo "##-====================================================-##"
openssl enc -aes-256-cbc -v -e -salt -in 16105696.jpeg -out 16105696.jpeg.aes

echo "##-================================================================-##"
echo "    [+] Remove The .jpeg File So You Can Decrypt The .aes File:"
echo "##-================================================================-##"
srm -v 16105696.jpeg

echo "##-=====================================================-##"
echo "    [+] Decrypt The Encrypted .jpeg File With OpenSSL:"
echo "##-=====================================================-##"
openssl enc -aes-256-cbc -v -d -aes-256-cbc -in 16105696.jpeg.aes -out 16105696.jpeg
