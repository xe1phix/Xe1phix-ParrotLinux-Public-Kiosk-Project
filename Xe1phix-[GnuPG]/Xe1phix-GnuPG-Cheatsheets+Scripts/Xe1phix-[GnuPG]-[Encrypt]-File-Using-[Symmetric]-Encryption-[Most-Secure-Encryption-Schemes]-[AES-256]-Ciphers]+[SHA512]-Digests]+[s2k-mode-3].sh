#!/bin/sh
gpg --verbose --symmetric --cipher-algo aes256 --digest-algo sha512 --cert-digest-algo sha512 --s2k-mode 3 --s2k-count 65011712 --s2k-cipher-algo AES256 --s2k-digest-algo SHA512 $1
