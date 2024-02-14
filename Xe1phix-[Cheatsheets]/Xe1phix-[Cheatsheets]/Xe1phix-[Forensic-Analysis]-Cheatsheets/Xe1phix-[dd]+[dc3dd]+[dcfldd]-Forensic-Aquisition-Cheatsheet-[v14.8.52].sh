#!/bin/sh
##########################
## Mount-losetup-dd.sh
##########################




##-==========================================================================================-##
    dd if=/dev/$Disk of=$Image.img 		## Create Backup:       ||
    dd if=$Image.img of=/dev/$Disk 		## Restore Backup:      ||
##-===========================================================================================================-##
    dd if=/dev/$Disk of=/home/$Image.img bs=4096 conv=notrunc,noerror 	## Backup Disk  --> .img File        ||
    dd if=/home/$Image.img of=/dev/$Disk bs=4096 conv=notrunc,noerror 	## Restore Disk <-- .img        ||
    ## ------------------------------------------------------------------------------------------------------- ##
    dd bs=1M if=/dev/ad4s3e | gzip ‐c > ad4s3e.gz                  		## Zip+Backup --> Archive       ||
    dd bs=1M if=/dev/ad4s3e | gzip | ssh eedcoba@fry 'dd of=ad4s3e.gz' 	## Zip+Backup --> SSH           ||
    ## ------------------------------------------------------------------------------------------------------- ##
    gunzip ‐dc ad4s3e.gz | dd of=/dev/ad0s3e bs=1M					    ## Decompress zip --> Disk      ||
    gunzip ‐dc ad4s3e.gz | ssh eedcoba@host 'dd of=/dev/ad0s3e bs=1M'   ## Decompress zip --> SSH       ||
##-===========================================================================================================-##

##-=========================================================================================================================================================-##
    dd if=/dev/ad0 of=/dev/ad2 skip=1 seek=1 bs=4k conv=noerror   						  ## Skip MBR This is necessary if the destination (ad2) is smaller. ||
    dd if=/vm/FreeBSD‐8.2‐RELEASE‐amd64‐memstick.img of=/dev/$USB bs=10240 conv=sync 	  ## Copy FreeBSD image to USB memory stick                          ||
##-=========================================================================================================================================================-##

##-=====================================================================-##
    dd if=/dev/$Disk of=/dev/null bs=1m	## Check for bad blocks  ||
    mount ‐o loop /$Image.img /mnt		## Mount the image       ||
##-=====================================================================-##
    dd if=/dev/zero of=/dev/$Disk		## Delete full disk         ||
    dd if=/dev/urandom of=/dev/$Disk	## Delete full disk better  ||
    kill ‐USR1 $PID 					## View dd progress (Linux) ||
##-===============================================================================================-##
    dd if=/dev/$Disk of=/mbr_$Disk.bak bs=512 count=1     ## Backup the full MBR             ||
    dd if=/dev/zero of=/dev/$Disk bs=512 count=1          ## Delete MBR and partition table  ||
    dd if=/mbr_$Disk.bak of=/dev/$Disk bs=512 count=1     ## Restore the full MBR            ||
    dd if=/mbr_$Disk.bak of=/dev/$Disk bs=446 count=1     ## Restore only the boot loader    ||
##-==========================================================================================================-##
    dd if=/mbr_$Disk.bak of=/dev/$Disk bs=1 count=64 skip=446 seek=446      ## Restore partition table    ||
    dd bs=1k if=/dev/$Disk conv=sync,noerror,notrunc of=$Image.img          ## Store into an image        ||
##-==========================================================================================================================================-##
    dd bs=1k if=/dev/$Disk conv=sync,noerror,notrunc | gzip | ssh root@fry 'dd of=hda1.gz bs=1k'		## Send over remote ssh connection 
##-==========================================================================================================================================-##


##-=======================================================-##
    gzip $Image.img		## Compess Backup with gzip   ||
    bzip2 $Image.img	## Compess Backup with bzip2  ||
##-=======================================================-##

##-======================================================================================================-##
    dd if=/dev/$Disk of=~/mbr.txt count=1 bs=512        ## backup the MBR - /dev/sda --> ~/$MBR_Backup
    dd if=~/mbr.txt of=/dev/$Disk count=1 bs=512        ## Restore the MBR - /dev/sda <-- ~/$MBR_Backup
## ----------------------------------------------------------------------------------------------------------------------------------- ##
    sfdisk -d /dev/$Disk > partition_backup.txt         ## Backup partition table  || -~{> /dev/sda --> ~/$Partition_Backup <}~- ||
    sfdisk /dev/$Disk < partition_backup.txt			## Restore partition table || -~{> /dev/sda <-- ~/$Partition_Backup <}~- ||
##-===================================================================================================================================-##



echo -e "\t## ========================================================= ##"
echo -e "\t ## ====== ways to securely wipe drives                          "
echo -e "\t## ========================================================= ##"



##-=======================================================================-##
##  [+] overrite data using /dev/zero - Generate 0's overwriting data:"
##-=======================================================================-##
dd if=/dev/zero of=/dev/sdX



##-===========================================================-##
##  [+] overwrite data with urandom - peudorandom generator:
##-===========================================================-##
dd if=/dev/urandom of=/dev/sdX









mount ‐t tmpfs ‐osize=64m tmpfs /memdisk 		# Create a memory file system


##-==============================-##
echo "Linux with losetup Method 1"
##-==============================-##
#####################################################################################
dd if=/dev/zero of=/usr/vdisk.img bs=1024k count=1024 		# Creates the loop img
#####################################################################################
mkfs.ext3 /usr/vdisk.img				# make a ext3 loop in dev
mount ‐o loop /usr/vdisk.img /mnt		# mount loop in directory
umount /mnt; rm /usr/vdisk.img			# Cleanup unmount and remove
#####################################################################################

##-=============================-##
echo "Linux with losetup Method 2"
##-=============================-##
dd if=/dev/urandom of=/usr/vdisk.img bs=1024k count=1024		# Creates the loop img 
#####################################################################################
losetup /dev/loop0 /usr/vdisk.img	# Creates and associates /dev/loop0 
mkfs.ext3 /dev/loop0 				# make a ext3 loop in dev
mount /dev/loop0 /mnt 			# mount loop on mnt
losetup ‐a                      # Check used loops 
umount /mnt 					# unmount loop
losetup ‐d /dev/loop0           # Detach 
rm /usr/vdisk.img				# remove loop image
#####################################################################################





mount -t ecryptfs /home/faggot/Secret /home/faggot/Secret
mount | grep /home/johndoe/Secret

mkfs -t ext2 -L rootfs -cv /dev/hda3

e2image -r /dev/hda1 - | bzip2 > hda1.e2i.bz2



mount −t ext2 /dev/fd0 /mnt/floppy
mount −t iso9660 /dev/hdb /mnt/cdrom
mount −t iso /tmp/image_file /mnt/iso_file/ −o loop







###############################################################
echo "Convert a Nero .nrg file to .iso"
dd bs=1k if=$Image.nrg of=$Image.iso skip=300

###############################################################
echo "Convert a bin/cue image to .iso"
bchunk imagefile.bin imagefile.cue $Image.iso

###############################################################
growisofs ‐dvd‐compat ‐Z /dev/dvd=$Image.iso     # Burn existing iso image 
growisofs ‐dvd‐compat ‐Z /dev/dvd ‐J ‐R /p/to/data  # Burn directly
###############################################################

##-=========================================================-##
echo "Create and burn an ISO image"
dd if=/dev/hdc of=/tmp/$Image.iso bs=2048 conv=notrunc

mkisofs ‐J ‐L ‐r ‐V TITLE ‐o $Image.iso /path/to/dir 		# Use mkisofs to create a CD/DVD image from files in a directory.

##-=========================================================-##
echo "create an ISO image is to use dd:"
dd if=/dev/cdrom of=$Image.iso

##-=========================================================-##
echo "create an ISO image from /dev/cdrom, use the following command:"
cat /dev/cdrom > $Image.iso

##-=========================================================-##
echo "write the ISO to a USB storage device, use the following command:"
##-=========================================================-##
dd if=$Image.iso of=/dev/sdb1 status=progress

##-=========================================================-##
echo "burn the image to the CD-ROM as follows"
##-=========================================================-##
cdrecord -v dev=/dev/sr0 $Image.iso

cdrecord -v dev=/dev/sr0 $Image.iso -speed 8
cdrecord -v dev=/dev/sr0 $Image.iso -multi




## Mount the cdrom image at /mnt/dir (read only) ##
mount -o loop cdrom.iso /mnt/dir


mount -o loop /dev/sr0 /mnt/cdrom

mount -o loop /mnt/fag/os/Parrot-full-2.0.5_amd64.iso /mnt/parrot





tar xvf remnux-6.0-ova-public.ova
qemu-img convert -0 qcow2 REMnuxV6-disk1.vmdk remnux.qcow2


wget --quiet -0 - https://remnux.org/get-remnux.sh | udo bash





##-==============================-##
echo "Linux with losetup Method 1"
##-==============================-##
#####################################################################################
dd if=/dev/zero of=/usr/vdisk.img bs=1024k count=1024 		# Creates the loop img
#####################################################################################
mkfs.ext3 /usr/vdisk.img				# make a ext3 loop in dev
mount ‐o loop /usr/vdisk.img /mnt		# mount loop in directory
umount /mnt; rm /usr/vdisk.img			# Cleanup unmount and remove
#####################################################################################

##-=============================-##
echo "Linux with losetup Method 2"
##-=============================-##
dd if=/dev/urandom of=/usr/vdisk.img bs=1024k count=1024		# Creates the loop img 
#####################################################################################
losetup /dev/loop0 /usr/vdisk.img	# Creates and associates /dev/loop0 
mkfs.ext3 /dev/loop0 				# make a ext3 loop in dev
mount /dev/loop0 /mnt 			# mount loop on mnt
losetup ‐a                      # Check used loops 
umount /mnt 					# unmount loop
losetup ‐d /dev/loop0           # Detach 
rm /usr/vdisk.img				# remove loop image
#####################################################################################


dd if=/dev/sr0 of=/home/faggot/OS/HardenedBSD.iso bs=2048
dd if=/dev/sr0 of=/home/faggot/OS/Qubes-R3.0-rc1-X86_64.iso bs=2048


genisoimage -o output.raw -hfs -graft-points newname=oldname cd_dir


genisoimage -boot-info-table

genisoimage -boot-load-seg
genisoimage 
genisoimage -boot-load-size
genisoimage -hppa-ramdisk
genisoimage -hppa-kernel-32
genisoimage -hppa-kernel-64
genisoimage -hppa-cmdline
genisoimage -hppa-bootloader
genisoimage -alpha-boot
genisoimage -dir-mode
genisoimage -file-mode
genisoimage -gid
genisoimage -iso-level
genisoimage -jigdo-jigdo			# Produce a jigdo .jigdo metadata file as well as the filesystem image.
genisoimage -md5-list
genisoimage -jigdo-force-md5
genisoimage -jigdo-template-compress
genisoimage -generic-boot
genisoimage -log-file
genisoimage -new-dir-mode
genisoimage -o 
genisoimage -root
genisoimage -uid
genisoimage -v
genisoimage -z			# Generate special RRIP records for transparently compressed files.
genisoimage -map
genisoimage -root-info
genisoimage -magic			# 
genisoimage 			# 
genisoimage 			# 
genisoimage -o cd.iso -r cd_dir		# create a CD with Rock Ridge extensions of the source directory cd_dir:
genisoimage -o cd.iso -R cd_dir		# create a CD with Rock Ridge extensions of the source directory cd_dir where all files have at least read  permission  and all files are owned by root, call:
genisoimage 
genisoimage 
genisoimage 
genisoimage 
genisoimage -o cd.iso cd_dir
			# 
mkzftree --verbose 
--parallelism	# 
--uncompress	# 
--level			# compression level (1-9, default is 9).
--force			# Always compress all files, even if they get larger when compressed.




mount -t hfs /dev/fd0 /mnt/floppy
genisoimage --cap -o output source_dir /mnt/floppy

write a tar archive directly to a CD that will later contain a simple ISO9660 filesystem with the tar archive call:

tar cf - . | genisoimage -stream-media-size 333000 | wodim dev=b,t,l -dao tsize=333000s -







find `mount | grep -vE "$CHECKSECURITY_FILTER" | cut -d ' ' -f 3` \
	-xdev $PATHCHK \
	\( -type f -perm +06000 -o \( \( -type b -o -type c \) \
	$DEVCHK \) \) \
        -ignore_readdir_race  \
	-printf "%8i %5m %3n %-10u %-10g %9s %t %h/%f\n" |
	sort -k 12 >$TMPSETUID


mount | grep -E 'type (nfs|afs)' | grep -vE '\(.*(nosuid|noexec).*nodev.*\)'
echo $nfssys |grep "[a-z]"| wc -l
























