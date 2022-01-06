#!/bin/sh
##-==========================================================-##
##    Xe1phix-Exiftool-Metadata-Manipulating-Injecting.sh
##-==========================================================-##


##-================================-##
##   [+] Extract Image Metadata:
##-================================-##
exif $File.jpg
exiftags -idav $File.jpg
exifprobe $File.jpg
exiv2 -Pkyct $File.jpg
exiftool -verbose -extractEmbedded $File.jpg 
exiftool -a -G1 -s $File.jpg 

##-======================================-##
##   [+] Extract Date/Time Information:
##-======================================-##
exiftool -time:all -a -G0:1 -s $File.jpg 
exiftool -a -u -g1 $File.jpg 


##-========================================-##
##   [+] Remove Metadata From $Dst image:
##-========================================-##
exiftool -all=  $File.png


##-=====================================-##
##   [+] Copy Values of Writable Tags
##   [+] From "src.jpg" To "$Dst.jpg"
##-=====================================-##
exiftool -TagsFromFile $Src.jpg -all:all $Dst.jpg


##-========================================-##
##   [+] Erase All Metadata From $Dst.jpg
##-========================================-##
##   [+] Copy The EXIF Tags From:
## -------------------------------- ##
##   [+] $Src.jpg -> $Dst.jpg
## -------------------------------- ##
exiftool -all= -tagsfromfile $src.jpg -exif:all $Dst.jpg


##-===================================-##
##   [+] Copy/Overwrite All Metadata 
##-===================================-##
## ----------------------------------- ##
##   [?] "$Src.jpg" --> "$Dst.jpg"
## ----------------------------------- ##
##   [+] Delete All XMP Information 
## ----------------------------------- ##
##   [+] Delete Thumbnail From $Dst
## ----------------------------------- ##
exiftool -tagsFromFile $a.jpg -XMP:All= -ThumbnailImage= -m $b.jpg



##-=================================-##
##   [+] Copy Metadata Information 
##-=================================-##
## --------------------------------- ##
##   [?] $Src.jpg -> XMP Data File
## --------------------------------- ##
exiftool -Tagsfromfile $a.jpg $out.xmp


## Copy All possible Information From "src.jpg"
## Write in XMP Format To "dst.jpg".
exiftool -TagsFromFile $Src.jpg '-all>xmp:all' $Dst.jpg


## Copy ICC_Profile From one image To Another.
exiftool -TagsFromFile $Src.jpg -icc_profile $Dst.jpg


## Copy the Make and Model Tags, and implant Them into Another image:
exiftool -tagsfromfile $Src.jpg -makernotes -make -model $Dst.jpg


## Copy All Information And preserve The original Structure
exiftool -tagsfromfile $Src.jpg -all:all $Dst.jpg


## copy XMP as a block from one file to another
exiftool -tagsfromfile $Src.jpg -xmp $Dst.cr2


echo "##-===================================================-##"
echo "   [+] Erase all meta information from $Dst.jpg image"
echo "	 		then copy EXIF tags from $Src.jpg"
echo "##-===================================================-##"
exiftool -all= -tagsfromfile $Src.jpg -exif:all $Dst.jpg



echo "##-===================================================-##"
echo "   [+] Copy all possible information from $Src.jpg"
echo "   [+] Write in XMP format to $Dst.jpg."
echo "##-===================================================-##"
exiftool -TagsFromFile $Src.jpg '-all>xmp:all' $Dst.jpg


