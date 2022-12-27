#!/bin/sh
## 


## Antiforensics - 5 part series



shred --force --iterations=3 --remove=wipesync --verbose --zero $Files
wipe -c -f -q -Q 3 -i -r $Dir/$Files
srm -r -v $Dir/$Files

chmod -v -R ugo+rwx $Dir/
chown -v -R xe1phix $Dir/


wipe -i -c -r -f 
-P 4


wipe -i -c -r -f /dev/sdc

wipefs --all --backup /dev/sd

## Restores an ext2 signature from the backup file  ~/wipefs-sdb-0x00000438.bak.
dd if=~/wipefs-sdb-0x00000438.bak of=/dev/sdb seek=$((0x00000438)) bs=1 conv=notrunc



echo "File will be securely wiped by zeroing when deleted"
chattr -s

srm -v -r -z /dev/sdc



if=, ifs=, pat=, or tpat=

of=, hof=, ofs=, hofs=, fhod


wipe=  hwipe=  verb=on  

log= hlog=

hash=sha256
hash=sha512



## Wiping a drive:
dc3dd wipe=/dev/sdc log=wipe.txt

## Wiping a drive with verification:
dc3dd hwipe=/dev/sdc hash=sha1 log=wipe.txt

## 
dc3dd verb=on hwipe=/dev/sdc

## 
dc3dd verb=on wipe=/dev/sdc


## 
dd status=progress if=/dev/urandom of=/dev/sdc




##-=====================================================-##
##   [+] confirm the disk has been wiped with zeros,
##       use dd to read the disk into a hexdump
##-=====================================================-##
dd if=/dev/sda | hd


##-================================================-##
##   [+] create a 100 MiB file containing zeros:
##-================================================-##
dcfldd if=/dev/zero of=test bs=1M count=100
dcfldd if=/dev/zero of=test bs=100M count=1
dcfldd if=/dev/zero of=test bs=50M count=2
dcfldd if=/dev/zero of=test limit=100M
           
           
##-==================================================-##
##   [+] validate image file against the source:
##-==================================================-##
dcfldd if=/dev/sdb vf=sdb.img


##-================================================-##
##   [+] Create a Raw copy of Disk sdb 
##       Verified integrity using SHA256 hashes
##-================================================-##
dcfldd if=/dev/sdb bs=4096 hash=sha256 sha256log=sdb.sha256 of=sdb.img

##-====================================================-##
##   [+] Copy $Input to $Output using SHA256 Hashes
##-====================================================-##
dcfldd if=$Input of=$Output status=on statusinterval=7 hash=sha256 hashlog=$Output.sha256


##-===================================================-##
##   [+] create a copy (forensics image) 
##       from a disk called /dev/sdb inside a file
##-===================================================-##
## ----------------------------------------------------------- ##
##   [?] using 4096 bytes (4 KiB) blocks (32 KiB default):
## ----------------------------------------------------------- ##
dcfldd if=/dev/sdb bs=4096 of=sdb.img






shred --verbose data=journal --force --iterations=4 --remove='wipesync' --zero


shred --verbose /dev/sda5

###############################################################
# 1 pass, write pseudo-random data; 3x faster than the default
###############################################################
$ shred --verbose -n7 /dev/sda5



hdparm --security-erase dummy /dev/sdh




## 1 pass, write pseudo-random data; 3x faster than the default
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


dcfldd if= of= 


if=
of= 
bs=
status=


hash=
hashlog=

hash=sha1
hash=sha256
hash=sha512

count=BLOCKS             ## copy only BLOCKS input blocks


hashconv=[before|after]

hashformat=

totalhashformat=

status=on statusinterval=



dcfldd if=$Input of=$Output status=on statusinterval=7 hash=sha256 hashlog=$Output.sha256

dcfldd if= of= verifylog=$File

if=
of=  
bs= status=




statusinterval=			    ## update the status message every N blocks default value is 256


sizeprobe=[if|of]			## determine the size of the input or output file


split=

splitformat='a' or 'n'



vf=FILE                  ## verify that FILE matches the specified input
verifylog=FILE           ## send verify results to FILE instead of stderr
verifylog:=COMMAND       ## exec and write verify results to process COMMAND




verifylog=FILE
              Send verify results to FILE instead of stderr








##################################################################################
echo "Delete GPS tags which may have been added by the geotag feature.  Note that"
echo "this does not remove all GPS tags -- to do this instead use "-gps:all="."
##################################################################################
exiftool -geotag= a.jpg



echo "##################################################################################"
echo "Delete XMP GPS tags which were added by the geotag feature."
echo "##################################################################################"
exiftool -xmp:geotag= a.jpg







