#!/bin/sh
##-==================================================-##
##   [+] FTK SMART Compression During Aquisition:
##-==================================================-##
ftkimager --compress 9 --s01 /dev/$Disk $Image


##-=========================================================-##
##   [+] AFFlib Built-in Compression During Aquisition:
##-=========================================================-##
aimage --lzma_compress --compression=9 /dev/$Disk $Image.aff


##-===========================================-##
##   [+] EnCase EWF Compressed Acquisition
##-===========================================-##
ewfacquire -c bzip2:best -f encase7-v2 /dev/$Disk


##-==================================================-##
##   [+] SquashFS Compressed Evidence Containers:
##-==================================================-##
mksquashfs $Image.raw $Image.sfs -comp lzo -noI
