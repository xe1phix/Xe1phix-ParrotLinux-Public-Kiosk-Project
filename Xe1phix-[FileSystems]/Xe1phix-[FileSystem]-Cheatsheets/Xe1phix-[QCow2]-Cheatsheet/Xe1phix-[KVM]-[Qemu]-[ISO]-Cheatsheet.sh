#!/bin/sh
##-==================================================-##
##   [+]  Creating a basic Linux virtual machine from an ISO:
##-==================================================-##

## ------------------------------------------------------------- ##
##   [?]  Create a virtual hard-drive image:
## ------------------------------------------------------------- ##
qemu-img create -f qcow2 $Disk.qcow2 8G

## -------------------------------------------------------------------------- ##
##   [?]  Your virtual hard-drive is now ready for use. 
## -------------------------------------------------------------------------- ##

##-=========================================-##
##   [+]  Test a virtual machine with the hard-drive:
##-=========================================-##
qemu-system-x86_64 -enable-kvm -hda $Disk.qcow2 -m 4096


##-============================================================================-##
##   [+]  Start a virtual machine with an operating system ISO attached to the virtual CDROM:
##-============================================================================-##
qemu-system-x86_64 -enable-kvm -hda $Disk.qcow2 -m 4096 -cdrom $File.iso -boot d



##-======================================================-##
##     [+]  Convert the virtual hard-drive image to the qcow2 format:
##-======================================================-##
qemu-img convert -f raw -O qcow2 ./disk.img ./disk.qcow2




