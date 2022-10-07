#!/bin/sh
 
 
##-=========================================-##
##   [+] Recover all known file types.
##-=========================================-##
foremost -t all -i /$Dir/$File -o /$Dir/
 
 
##-====================================================================-##
##   [+] Clone a partition from physical disk /dev/sda, partition 1
##       to physical disk /dev/sdb, partition 1 with e2image
##-========================================================================-##
e2image -ra -p /dev/sda1 /dev/sdb1
 
 
##-============================================================-##
##   [+] Clone a faulty or dying drive, run ddrescue twice.
##   [?] First round, copy every block without read error
##   [?] log the errors to $File.log.
##-============================================================-##
ddrescue -f -n /dev/sda /dev/sdb $File.log
 
 
##-=======================================================-##
##   [+] Copy only the bad blocks and try 3 times
##       to read from the source before giving up.
##-=======================================================-##
ddrescue -d -f -r3 /dev/sdX /dev/sdb $File.log
 
 
##-====================================================-##
##   [+] dd compression to an image file on the fly:
##-====================================================-##
dd_rescue /dev/sda1 - | bzip2 > /$Dir/$File.img.bz2
 
 
##-================================================================-##
##   [+] List the files and directory names in a raw dd image:
##-================================================================-##
fls $File.dd -r -f ext3 -i raw
 
 
##-=======================================================-##
##   [+] Write files to a specified output directory:
##-=======================================================-##
foremost -t all -o /$Dir/ -i $File.dd
 
 
##-========================================================================-##
##   [+] Pass in one of the backup superblocks as an option to fsck:
##-========================================================================-##
fsck -b 32768 /dev/sda2
 
 
##-=============================================================-##
##   [+] Passing the backup superblock into mount explicitly:
##-=============================================================-##
mount sb=32768 /dev/sda2 /mnt
 
 
##-=============================================================-##
##   [+] Forensic backup of /dev/sda to a raw dd file:
##-=============================================================-##
dd if=/dev/sda of=/mnt/$Dir/$File.dd
 
 
##-=====================================================================-##
##   [+] Forensic acquisition of sda using gddrescue output to raw:
##-=====================================================================-##
gddrescue -n /dev/sda /mnt/$Dir/$File.raw $File.log
 
 
##-=======================================================-##
##   [+] Use ddrescue, skipping the dodgy areas
##       grab most of the error-free areas quickly
##-=======================================================-##
gddrescue -n /dev/sda /mnt/$Dir/$File.raw $File.log

