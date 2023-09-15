#!/bin/sh

##-=================================================-##
##   [+] Imaging a device on a Unix-based system:
##-=================================================-##
ewfacquire /dev/sda


##-=================================================-##
##   [+] Converting a RAW into an EWF image
##-=================================================-##
ewfacquire $Disk.raw


##-===============================================================-##
##   [+] Forensic aquisition of /dev/sdd into a EWF filesystem
##-===============================================================-##
ewfacquire -v -c bzip2:best -m removable -f encase7-v2 -d sha256 -l /$Dir/ewf-log.txt /dev/sdd


##-=============================================-##
##   [+] Pipe /dev/sdd into ewfacquirestream
##-=============================================-##
ewfacquirestream -t encase7 -d sha256 -c bzip2:best -e Xe1phix -m removable -t $Ewf < /dev/sdd


##-=================================================-##
##   [+] Concatinate a series of split raw files
##   [+] Pipe them into ewfacquirestream
##-=================================================-##
cat $File.raw.??? | ewfacquirestream
cat $File.??? | ewfacquirestream  -c best -m fixed -t $File -S 1T 


##-==============================================================-##
##   [+] Convert an optical disc (split) RAW into an EWF image
##-==============================================================-##
ewfacquire -T $Image.cue $Image.iso


##-==========================================================================-##
##   [+] Converting an EWF into another EWF format or a (split) RAW image
##-==========================================================================-##
ewfexport $Image.E01
ewfexport -d sha256 -f raw -l /$Dir/EWF-to-Raw.txt -t /$Dir/EWF-Raw $Image.E01


##-=================================================-##
##   [+] Exporting files from a logical image (L01)
##-=================================================-##
ewfexport $Image.L01


##-=================================================-##
##   [+] FUSE mounting an EWF image
##-=================================================-##
ewfmount -v $Image.E01 $Dir/
ewfmount -v $Image.E01 /dev/$Disk


##-=============================================-##
##   [+] FUSE mounting a logical image (L01)
##-=============================================-##
ewfmount -f files $Image.L01 /mnt/$Dir


##-=========================================================-##
##   [+] Mount EWF image as Loop filesystem using kpartx:
##-=========================================================-##
kpartx -r -a -v $Dir/ewf1


##-=========================================================-##
##   [+] Mount EWF image as Loop filesystem using Mount:
##-=========================================================-##
mkdir $Dir
mount --read-only /dev/mapper/loop0p1 $Dir


##-==========================================================-##
##   [+] Unmount EWF image as Loop filesystem using umount:
##-==========================================================-##
umount $Dir
kpartx -d $Dir/ewf1

##-======================================================-##
##   [+] Unmount EWF Loop filesystem using fusermount:
##-======================================================-##
fusermount -u $Image
fusermount -u /mnt/$Dir


##-=================================================================-##
##   [?] Display the size,type,inode,permissions of an EWF image:
##-=================================================================-##
file /$Dir/ewf.E01
stat --format=[%n]:[Size:%s.bytes]:[IO-Block:%o]:[File-type:%F]:[Inode:%i] /$Dir/ewf.E01
stat --format=[%n]:[User:%U]:[Group:%G]:[Uid:%u]:[GID:%g]:[%A/%a] /$Dir/ewf.E01


##-====================================================-##
##   [+] Print verbose EWF filesystem information:
##-====================================================-##
ewfinfo $Image.E01
img_stat -i ewf /$Dir/ewf.E01
cat /$Dir/ewf-log.txt


##-==================================================-##
##   [+] Verify the integrity of an EWF filesystem
##-==================================================-##
ewfverify $Image.E01




