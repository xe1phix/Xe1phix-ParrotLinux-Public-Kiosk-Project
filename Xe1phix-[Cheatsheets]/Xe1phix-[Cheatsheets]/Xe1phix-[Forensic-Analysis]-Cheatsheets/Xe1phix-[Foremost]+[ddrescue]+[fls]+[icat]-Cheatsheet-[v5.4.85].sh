#!/bin/sh



##-=========================================-##
##   [+] Recover all known file types.
##-=========================================-##
foremost -t all -i /$Dir/$File -o /$Dir/


##-====================================================================-##
##   [+] Clone a partition from physical disk /dev/sda, partition 1,
##       to physical disk /dev/sdb, partition 1 with e2image, run
##-========================================================================-##
e2image -ra -p /dev/sda1 /dev/sdb1


##-=======================================================-##
##   [+] Clone a faulty or dying drive, run ddrescue twice.
##       First round, copy every block without read error
##       and log the errors to rescue.log.
##-=======================================================-##
ddrescue -f -n /dev/sda /dev/sdb rescue.log



##-=======================================================-##
##   [+] Copy only the bad blocks and try 3 times
##       to read from the source before giving up.
##-=======================================================-##
ddrescue -d -f -r3 /dev/sdX /dev/sdY rescue.log


##-=================================================-##
##   [+] dd compression to an image file on the fly.
##-=================================================-##
dd_rescue /dev/sda1 - | bzip2 > /dir/$File.img.bz2




##-========================================================================-##
##   [+] List the files and directory names in a particular image:
##-========================================================================-##
fls $File.dd -r -f ext3 -i raw



##-========================================================================-##
##   [+] Write files to a specified output directory:
##-========================================================================-##
foremost -t all -o /$Dir/ -i $File.dd




##-========================================================================-##
##   [+] Pass in one of the backup superblocks as an option to fsck:
##-========================================================================-##
fsck -b 32768 /dev/hda2


##-=============================================================-##
##   [+] Passing the backup superblock into mount explicitly:
##-=============================================================-##
mount sb=32768 /dev/hda2 /mnt


##-=============================================================-##
##   [+]
##-=============================================================-##
dd if=/dev/hda of=/mnt/$Dir/$File.dd


##-========================================================================-##
##   [+]
##-========================================================================-##
gddrescue -n /dev/hda /mnt/$Dir/$File.raw rescued.log


##-========================================================================-##
##   [+] Grab most of the error-free areas quickly
##-========================================================================-##




##-========================================================================-##
##   [+] Use ddrescue, skipping the dodgy areas
##       grab most of the error-free areas quickly
##-========================================================================-##
gddrescue -n /dev/sda /mnt/$Dir/$File.raw rescued.log





##-================================================-##
##   [+] Carve out embedded/appended stego files
##-================================================-##
foremost $File.jpg


##-==================================================-##
##   [+] Recode the file and throw away the result
##-==================================================-##
ffmpeg -v info -i stego.mp3 -f null


##-====================================-##
##   [+] Sleuthkit - fls output Log:
##-====================================-##
sudo fls /forensic/floppy$1/forensic$1.iso > /forensic/floppy$1/logs/logfls$1.txt


##-=======================================-##
##   [+] EWFAcquire - Acquire file E01
##-=======================================-##
sudo ewfacquire /dev/fd0 -D floppy$1 -e floppysic -C 1.1 -N floppy$1 -E $1 -D floppy$1 -t floppy$1 -l ~/forensic/floppy$1/logs/ewfacquire$1.txt -m removable -M physical -f encase6 -c deflate -o 0 -B 737280 -S 1.4 -P 512 -g 64 -b 64 -w


##-=================================================-##
##   [+] List files and directories in disk image
##-=================================================-##
sudo fls -r -m "/" -i ewf floppy$1.E01 >> ewf$1.txt


##-===================================-##
##   [+] Make timeline in csv format
##-===================================-##
sudo mactime -b ewf$1.txt -d > mactime$1.csv


##-==========================-##
##   [+] Search for file in E01 Image
##-==========================-##
fls -r -F floppy2.E01 |grep


##-==========================-##
##   [+] Take back node 28 
##-==========================-##
icat floppy2.E01 28 > test22.PAS

icat image.raw 68 > photo.jpg_
icat image.raw 34 > customerlist.xls_




tsk_recover -o          # recovering the deleted files

tsk_recover -a -o       # allocated files





##-================================================-##
##   [+] Trace the I/O on /dev/sda 
##   [+] Parse the output in human readable form
##-================================================-##
blktrace -d /dev/sda -o - | blkparse -i -

btrace /dev/sda



##-================================================-##
##   [+] Trace the devices I/O + Save the output
##-================================================-##
blktrace /dev/sda


##-================================-##
##   [+] Parse Device trace file:
##-================================-##
blkparse --verbose --input=$File





