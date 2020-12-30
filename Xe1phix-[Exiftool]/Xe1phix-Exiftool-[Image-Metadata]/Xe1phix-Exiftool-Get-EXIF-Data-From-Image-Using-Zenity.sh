#!/bin/sh
##-=========================================-##
## [+] Xe1phix-Exiftool-Get-EXIF-Data-From-Image-Using-Zenity.sh
##-=========================================-##
## ------------------------------------------------------------------ ##
##  [?] Get EXIF data from image with zenity
## ------------------------------------------------------------------ ##
ans=$(zenity --title "Choose image:" --file-selection); exiftool -s ${ans} | zenity --width 800 --height 600 --text-info;
