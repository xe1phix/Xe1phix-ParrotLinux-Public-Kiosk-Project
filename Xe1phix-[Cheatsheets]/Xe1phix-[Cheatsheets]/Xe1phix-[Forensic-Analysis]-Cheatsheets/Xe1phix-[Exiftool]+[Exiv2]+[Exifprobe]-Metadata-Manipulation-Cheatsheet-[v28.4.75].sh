#!/bin/sh
##-==============================================================================================-##
##   [+] Xe1phix-[Exiftool]+[Exiv2]+[Exifprobe]-Metadata-Manipulation-Cheatsheet-[v24.8.24].sh
##-==============================================================================================-##


##-================================-##
##   [+] Extract Image Metadata:
##-================================-##
exif $File.jpg
exiftags -idav $File.jpg
exifprobe $File.jpg
exiv2 -Pkyct $File.jpg
exiftool -verbose -extractEmbedded $File.jpg 
exiftool -a -G1 -s $File.jpg 


##-=======================================-##
##   [+] Extract Date/Time Information:
##-=======================================-##
exiftool -time:all -a -G0:1 -s $File.jpg 
exiftool -a -u -g1 $File.jpg 


##-=============================================-##
##   [+] Remove All Metadata From $Dst image:
##-=============================================-##
exiftool -all=  $File.png


##-=====================================-##
##   [+] Copy Values of Writable Tags
##   [?] From "src.jpg" To "$Dst.jpg"
##-=====================================-##
exiftool -TagsFromFile $Src.jpg -all:all $Dst.jpg


##-=========================================-##
##   [+] Erase All Metadata From $Dst.jpg
##-=========================================-##
## ----------------------------------------- ##
##   [?] Copy The EXIF Tags From:
## ----------------------------------------- ##
##   [?] $Src.jpg -> $Dst.jpg
## ----------------------------------------- ##
exiftool -all= -tagsfromfile $src.jpg -exif:all $Dst.jpg



##-====================================-##
##   [+] Copy/Overwrite All Metadata 
##-====================================-##
## ------------------------------------ ##
##   [?] "$Src.jpg" --> "$Dst.jpg"
## ------------------------------------ ##
##   [+] Delete All XMP Information 
## ------------------------------------ ##
##   [+] Delete Thumbnail From $Dst
## ------------------------------------ ##
exiftool -tagsFromFile $Src.jpg -XMP:All= -ThumbnailImage= -m $Dst.jpg



##-========================================-##
##   [+] Copy Metadata Information 
##-========================================-##
## ---------------------------------------- ##
##   [?] $Src.jpg -> XMP Data File
## ---------------------------------------- ##
exiftool -Tagsfromfile $Src.jpg $Dst.xmp


##-=========================================-##
##   [+] Copy All Metadata From "src.jpg"
##   [+] Write in XMP Format To "dst.jpg"
##-=========================================-##
exiftool -TagsFromFile $Src.jpg '-all>xmp:all' $Dst.jpg


##-===================================-##
##   [+] Copy ICC_Profile:
##   [+] From $Src.jpg To $Dst.jpg:
##-===================================-##
exiftool -TagsFromFile $Src.jpg -icc_profile $Dst.jpg


##-========================================-##
##   [+] Copy All Metadata:
##   [+] Preserve The Original Structure:
##-========================================-##
exiftool -tagsfromfile $Src.jpg -all:all $Dst.jpg


##-=================================-##
##   [+] Copy XMP As A Block:
##   [+] From One File To Another:
##-=================================-##
exiftool -tagsfromfile $Src.jpg -xmp $Dst.cr2


##-=====================================-##
##   [+] Erase All The Metadata:
##   [+] From $Dst.jpg Then
##   [+] Copy EXIF Tags From $Src.jpg:
##-=====================================-##
exiftool -all= -tagsfromfile $Src.jpg -exif:all $Dst.jpg


##-=========================================-##
##   [+] Copy The Make and Model Tags:
##   [+] Implant Them into Another image:
##-=========================================-##
exiftool -tagsfromfile $Src.jpg -makernotes -make -model $Dst.jpg


##-===========================================-##
##   [+] Copy All Metadata From $Src.jpg
##   [+] Writing To $Dst.jpg As A XMP File:
##-===========================================-##
exiftool -TagsFromFile $Src.jpg '-all>xmp:all' $Dst.jpg


##-======================================================-##
##   [+] Copy all possible information from $Src.jpg
##   [+] Write in XMP format to $Dst.jpg.
##-======================================================-##
exiftool -TagsFromFile $Src.jpg '-all>xmp:all' $Dst.jpg


##-========================================================-##
##   [+] Erase all meta information from $Dst.jpg image
##   [+] Then copy EXIF tags from $Src.jpg
##-========================================================-##
exiftool -all= -tagsfromfile $Src.jpg -exif:all $Dst.jpg



