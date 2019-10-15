#!/bin/sh
## Xe1phix-dd.sh





# Start dd and show progress every X seconds
dd if=/path/inputfile | pv | dd of=/path/outpufile

# Backup a local drive into a file on the remote host via ssh
dd if=/dev/sda | ssh user@server 'dd of=sda.img'



sudo dd if=/dev/mem | cat | strings


tar -c  | gzip | gpg -c | dd of=/home/poozer/file.tar.gz.gpg


echo "##########################################################"
## Make encrypted archive of dir/ on remote machine ##
echo "##########################################################"
$ tar -c dir/ | gzip | gpg -c | ssh user@remote 'dd of=dir.tar.gz.gpg'


tar -c /usr/share/initramfs-tools/ | gzip | gpg -c | dd of=/home/poozer/initramfs.tar.gz.gpg


tar -c dir/ | gzip | gpg -c | dd of=/home/poozer/file.tar.gz.gpg




echo "Create and burn an ISO image"
dd if=/dev/hdc of=/tmp/mycd.iso bs=2048 conv=notrunc
mkisofs ‐J ‐L ‐r ‐V TITLE ‐o imagefile.iso /path/to/dir 		# Use mkisofs to create a CD/DVD image from files in a directory.

echo "create an ISO image is to use dd:"
dd if=/dev/cdrom of=image.iso

echo "create an ISO image from /dev/cdrom, use the following command:"
cat /dev/cdrom > image.iso

echo "write the ISO to a USB storage device, use the following command:"
dd if=image.iso of=/dev/sdb1



Imaging a device to a single output file with generation of md5 and sha1
hashes of the device:

$ ./dc3dd if=/dev/sda of=suspect.img hash=md5 hash=sha1 log=suspect.txt

Imaging a device to a set of CD-sized output files with generation of 
md5 and and sha1 hashes of the device:

$ ./dc3dd if=/dev/sda ofs=suspect.img.000 ofsz=650M hash=md5 hash=sha1
log=suspect.txt

Imaging a device to both a single output file and to a set of CD-sized
output files with generation of md5 and sha1 hashes of the device:

$ ./dc3dd if=/dev/sda of=suspect.img of=suspect.img ofs=suspect.img.000
ofsz=650M hash=md5 hash=sha1 log=suspect.txt

Imaging a device to both a single output file and to a set of CD-sized
output files with generation of md5 and sha1 hashes of the device
and md5 and sha1 hashes of the outputs:

$ ./dc3dd if=/dev/sda of=suspect.img hof=suspect.img hofs=suspect.img.000
ofsz=650M hash=md5 hash=sha1 log=suspect.txt

Restoring a set of image files to a device with verification hashes of 
only the bytes dc3dd writes to the device:
$ ./dc3dd ifs=suspect.img.000 hof=/dev/sdb hash=md5 hash=sha1 log=suspect-restore.txt

Restoring a set of image files to a device with verification hashes of 
both the bytes dc3dd writes to the device and the entire device:
$ ./dc3dd ifs=suspect.img.000 fhod=/dev/sdb hash=md5 hash=sha1 log=suspect-restore.txt

Wiping a drive:
$ ./dc3dd wipe=/dev/sdb log=wipe.txt

Wiping a drive with verification:
$ ./dc3dd hwipe=/dev/sdb hash=md5 hash=sha1 log=wipe.txt






# Snapshot of Currently Active Memory
dd bs=1024 < /dev/mem > mem
dd bs=1024 < /dev/kmem > kmem


# Taking a Disk Snapshot
$ dd if=/dev/hda1 bs=1024 > hda1

## Creating an Empty Image File
$ dd if=/dev/urandom of=/home/bob/safe.img bs=1k count=10024



   ## Read ~1 MB at once.
   dd if="$raw_file" of="$auto_hash_folder/$raw_file_basename.dd.0-1000000" bs=1000000 count=1

   ## Read byte by byte from 0 to 440.
   ## There should be no differences here.
   dd if="$raw_file" of="$auto_hash_folder/$raw_file_basename.dd.0-440" bs=1 count=440

   ## Read byte by byte from 441 to 444.
   ## Disk signature may differ. (Fixed in Whonix 8.5.0.1 and above.)
   dd if="$raw_file" of="$auto_hash_folder/$raw_file_basename.dd.441-444" bs=1 skip=440 count=3

   ## Read byte by byte from 445 to 1000000.
   ## There should be no differences here.
   dd if="$raw_file" of="$auto_hash_folder/$raw_file_basename.dd.445-1000000" bs=1 skip=444 count=1000000




########################################################################
# Advise to drop cache for whole file
###############################################################
$ dd if=ifile iflag=nocache count=0

###############################################################
# Ensure drop cache for the whole file
###############################################################
$ dd of=ofile oflag=nocache conv=notrunc,fdatasync count=0

###############################################################
# Drop cache for part of file
###############################################################
$ dd if=ifile iflag=nocache skip=10 count=10 of=/dev/null

###############################################################
# Stream data using just the read-ahead cache
###############################################################
$ dd if=ifile of=ofile iflag=nocache oflag=nocache

###############################################################
# I/O statistics to standard error and then resume copying
###############################################################
'INFO' signal 'dd'

###############################################################

###############################################################
$ dd if=/dev/zero of=/dev/null count=10MB & pid=$!

###############################################################

###############################################################
$ kill -s INFO $pid; wait $pid




$ dd if=/dev/urandom of=/home/bob/safe.img bs=1k count=10024


# Snapshot of Currently Active Memory
dd bs=1024 < /dev/mem > mem
dd bs=1024 < /dev/kmem > kmem


# Taking a Disk Snapshot
$ dd if=/dev/hda1 bs=1024 > hda1




kpartx -r -a -v image.raw



dd if=/dev/fd0 of=floppy.img 			## to create an image of a fl oppy disk.


dc3dd if=/dev/sda hof=image.raw ofs=image.000 ofsz=1G hlog=hash.log
hash=md5



cat image.raw.gz.* | zcat | md5sum








convert a qcow2 image into a raw image with:

e2image -r hda1.qcow2 hda1.raw






create a QCOW2 image file
e2image -Q /dev/hda1 hda1.qcow2


QCOW2 image minimize the amount of disk space by storing data in special format with pack data closely together



bzip2 -z hda1.qcow2



qemu-img
qemu-img --help







Clone base.img to "modified.img"
Diff The difference between them "diff.qcow2"

qemu-img create -f qcow2 -b modified.img diff.qcow2
                   qemu-img rebase -b base.img diff.qcow2





--trace events=trace-events-all






-f' first image format
  '-F' second image format


create
convert 
dd -f fmt -O output_fmt if=input of=output


info 
map 
snapshot 

-a' applies a snapshot (revert disk to saved state)
  '-c' creates a snapshot
  '-d' deletes a snapshot
  '-l' lists all snapshots in the given image

check 





e2image -r /dev/hda1 - | bzip2 > hda1.e2i.bz2






## Create a debian root image for qemuQ
qemu disk.img -kernel /boot/vmlinuz























rdd-copy --count 512 /dev/hda mbr.img


rdd-copy --sha1 /dev/hda1

rdd-copy -l rdd-log.txt /dev/fd0f.img




--progress 5

--log-file 

--verbose 










affdiskprint -x XML


affverify













ewfacquirestream -C 1 -D Floppy -E 1.1 -e 'John D.' -N 'Just a floppy in my system' -m removable -M logic
al -t floppy </dev/fd0




ewfacquire /dev/fd0

convert a split RAW image into an EWF image:
# ewfacquire usb256.raw.0??



ewfacquire -T cdrom.cue cdrom.iso




ewfexport floppy.E01



ewfinfo -d dm floppy.E01




## mount data stored in EWF files
ewfmount floppy.E01 floppy/






ddrescue







