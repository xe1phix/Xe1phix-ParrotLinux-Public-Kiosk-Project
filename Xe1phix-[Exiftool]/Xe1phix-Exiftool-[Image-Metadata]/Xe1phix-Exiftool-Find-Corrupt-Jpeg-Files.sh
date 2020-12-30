#!/bin/sh
##-=================================-##
## [+] Xe1phix-Exiftool-Find-Corrupt-Jpeg-Files.sh
##-=================================-##
## ------------------------------------------------------------------------------- ##
##  [?] Find corrupted jpeg image files
## ------------------------------------------------------------------------------- ##
find . -iname '*jpg' -print0 | xargs -0 exiftool -warning; find . -iname '*jpg' -print0 | xargs -0 jpeginfo -c
