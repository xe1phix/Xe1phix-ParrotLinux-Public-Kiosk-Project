#!/bin/sh
## 


## Antiforensics - 5 part series



chmod -v -R ugo+rwx OWL/
chown -v -R xe1phix OWL/


wipe -i -c -r -f 
-P 4


wipe -i -c -r -f /dev/sdc

wipefs --all --backup /dev/sd

dd if=~/wipefs-sdb-0x00000438.bak of=/dev/sdb seek=$((0x00000438)) bs=1 conv=notrunc
              Restores an ext2 signature from the backup file  ~/wipefs-sdb-0x00000438.bak.

echo "File will be securely wiped by zeroing when deleted"
chattr -s

srm -v -r -z /dev/sdc



if=, ifs=, pat=, or tpat=

of=, hof=, ofs=, hofs=, fhod


wipe=  hwipe=  verb=on  

log= hlog=

hash=sha256
hash=sha512



Wiping a drive:
dc3dd wipe=/dev/sdc log=wipe.txt

Wiping a drive with verification:
dc3dd hwipe=/dev/sdc hash=sha1 log=wipe.txt


dc3dd verb=on hwipe=/dev/sdc

dc3dd verb=on wipe=/dev/sdc



dd status=progress if=/dev/urandom of=/dev/sdc




dcfldd  status=on statusinterval=256




srm -r -v -z 

## confirm the disk has been wiped with zeros, you can use dd to read
## the disk into a hexdump
dd if=/dev/sda | hd


shred --verbose data=journal --force --iterations=4 --remove='wipesync' --zero


shred --verbose /dev/sda5

###############################################################
# 1 pass, write pseudo-random data; 3x faster than the default
###############################################################
$ shred --verbose -n7 /dev/sda5



hdparm --security-erase dummy /dev/sdh




# 1 pass, write pseudo-random data; 3x faster than the default
shred --verbose --force --iterations=7  /dev/sda5 data=journal 






'unlink' => use a  standard  unlink  call

'wipe' => also first obfuscate bytes in the name.


'wipesync' => also sync each obfuscated byte to disk.  






/etc/systemd/system/



--sysinfo 

bleachbit --debug-log=/var/log/bleachbit.log --shred --overwrite










'unlink'
'wipe'
'wipesync'


dcfldd


if=
of= 
bs=
status=


hash=
hashlog=

hash=sha1
hash=sha256
hash=sha512

count=BLOCKS             copy only BLOCKS input blocks


hashconv=[before|after]

hashformat=

totalhashformat=

status=on statusinterval=



status=on statusinterval=7 hash=sha256

if=
of=  
bs= status=




statusinterval=			## update the status message every N blocks default value is 256


sizeprobe=[if|of]			## determine the size of the input or output file


split=

splitformat='a' or 'n'



vf=FILE                  verify that FILE matches the specified input
verifylog=FILE           send verify results to FILE instead of stderr
verifylog:=COMMAND       exec and write verify results to process COMMAND













##################################################################################
echo "Delete GPS tags which may have been added by the geotag feature.  Note that"
echo "this does not remove all GPS tags -- to do this instead use "-gps:all="."
##################################################################################
exiftool -geotag= a.jpg



echo "##################################################################################"
echo "Delete XMP GPS tags which were added by the geotag feature."
echo "##################################################################################"
exiftool -xmp:geotag= a.jpg







