#!/bin/sh

ls --format=single-column

gpg --keyid-format 0xlong --import Firejail.asc
gpg --fingerprint F951164995F5C4006A73411E2CCB36ADFC5849A7
gpg --lsign F951164995F5C4006A73411E2CCB36ADFC5849A7


gpg --verbose --keyid-format 0xlong --verify
gpg --verbose --keyid-format 0xlong --verify firejail-*.*.**.*.tar.xz.asc firejail-*.*.**.*.tar.xz



