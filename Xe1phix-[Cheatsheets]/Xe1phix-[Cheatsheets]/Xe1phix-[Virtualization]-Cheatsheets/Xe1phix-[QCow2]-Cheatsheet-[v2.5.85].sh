#!/bin/sh


##-==========================================-##
##   [+] Create a QCow2 image from a HDD
##-==========================================-##
e2image -Q /dev/sda1 $Image.qcow2


##-================================================-##
##   [+] Convert a QCow2 image into a Raw image
##-================================================-##
e2image -r $Image.qcow2 $Image.raw


##-================================================-##
##   [+] Create An 8GB Virtual Hard Drive Image:
##-================================================-##
qemu-img create -f qcow2 $File.qcow2 8G


##-================================================-##
##   [+] Run The QCow2 Image In A Virtual Macine:
##-================================================-##
qemu-system-x86_64 -enable-kvm -hda $File.qcow2 -m 4096


##-=================================================-##
##   [+] Mount A QCOW2 Image:
##-=================================================-##
qcowmount $File.qcow2 /mnt/qcowimage/


##-=================================================-##
##   [+] Pass "allow_root" to the fuse subsystem:
##-=================================================-##
qcowmount -X allow_root $File.qcow2 /mnt/qcowimage/


##-=================================================-##
##   [+] Unmount /mnt/qcowimage/ Using umount:
##-=================================================-##
unmount /mnt/qcowimage/


##-=================================================-##
##   [+] Unmount /mnt/qcowimage/ Using fusermount:
##-=================================================-##
fusermount -u /mnt/qcowimage/


##-========================================================================-##
##   [+] Create a new image, read/write snapshot of the original image:
##-========================================================================-##
qemu-img create -f qcow2 -b $File.img snapshot.img


##-==========================================-##
##   [+] Determine an images backing file
##-==========================================-##
qemu-img info $File.img


##-=================================================================-##
##                  [+] Temporary snapshots
##-=================================================================-##
## ----------------------------------------------------------------- ##
##   [?] any changes made to the virtual machine while it is 
##       running are written to temporary files and thrown away 
##       when the virtual machine is turned off
## ----------------------------------------------------------------- ##
qemu -hda $File.img -snapshot

