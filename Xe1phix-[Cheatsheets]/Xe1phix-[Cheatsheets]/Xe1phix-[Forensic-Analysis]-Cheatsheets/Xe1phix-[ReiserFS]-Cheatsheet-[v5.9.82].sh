#!/bin/sh




## ------------------------------------------ ##
##   [?] You have ReiserFS on /dev/sda1
##   [?] Create journal on /dev/journal
## ------------------------------------------ ##


## ---------------------------------------------------------------------------- ##
##   [?] boot kernel patched with special relocatable journal support patch
## ---------------------------------------------------------------------------- ##
reiserfstune /dev/sda1 --journal-new-device /dev/journal -f


mount /dev/sda1 


echo "##-==============================================-##"
##   [+]  Change max transaction size to 512 blocks"
echo "##-==============================================-##"
reiserfstune -t 512 /dev/sda1

echo "##-=========================================================================================-##"
echo "Use your file system on another kernel that doesn't contain relocatable journal support."
echo "##-=========================================================================================-##"
umount /dev/sda1


reiserfstune /dev/sda1 -j /dev/journal --journal-new-device /dev/hda1 --make-journal-standard


mount /dev/sda1 and use.


echo "##-==============================================================================-##"
##   [+] Configure ReiserFS on /dev/hda1 and to be able to switch between different "
##   [+] journals including journal located on the device containing the filesystem."
echo "##-==============================================================================-##"
##   [+] boot kernel patched with special relocatable journal support patch"
echo "##-==============================================================================-##"
mkreiserfs /dev/sda1

echo "##-=========================================================================================-##"
##   [+] you got solid state disk (perhaps /dev/sda, they typically look like scsi disks)"
echo "##-=========================================================================================-##"
reiserfstune --journal-new-device /dev/sda1 -f /dev/hda1


echo "##-===========================================================================-##"
##   [+] If your scsi device dies, and you have an extra IDE device try this:"
echo "##-===========================================================================-##"
reiserfsck --no-journal-available /dev/sda1

or

reiserfsck --rebuild-tree --no-journal-available /dev/sda1

reiserfstune --no-journal-available --journal-new-device /dev/sda1 /dev/sda1




debugreiserfs


- J Displays the journal header, which includes assorted filesystem
details.


gunzip -c xxx.gz | debugreiserfs -u /dev/image


-d     prints the formatted nodes of the internal tree of the filesystem.

       -D     prints the formatted nodes of all used blocks of the filesystem.

       -m     prints the contents of the bitmap (slightly useful).

       -o     prints the objectid map (slightly useful).



extracts  the  filesystem's metadata
debugreiserfs -p /dev/xxx | gzip -c > xxx.gz


builds the ReiserFS filesystem image
gunzip -c xxx.gz | debugreiserfs -u /dev/image


Creates a file with a list of the blocks that are flagged as being bad In the filesystem.
debugreiserfs -B file 

Get the file system's block size:

# debugreiserfs /dev/hda3 | grep '^Blocksize'

Calculate the block number:

# echo "(58656333-54781650)*512/4096" | bc -l

# get more info about this block 
debugreiserfs -1 484335 /dev/hda3



