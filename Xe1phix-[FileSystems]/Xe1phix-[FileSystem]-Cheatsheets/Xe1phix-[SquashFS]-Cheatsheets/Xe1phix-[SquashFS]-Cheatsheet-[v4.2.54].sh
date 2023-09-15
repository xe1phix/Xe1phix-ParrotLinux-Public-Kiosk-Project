#!/bin/bash


##-=================================================================-##
##   [+] Image a disk into a SquashFS forensic evidence container
##-=================================================================-##
sfsimage -i /dev/sde $File.sfs


##-==============================================================-##
##   [+] Add additional evidence to a container using sfsimage
##-==============================================================-##
sfsimage -a photo.jpg $File.sfs


##-====================================================================-##
##   [+] List the contents of a SquashFS forensic evidence container
##-====================================================================-##
sfsimage -l $File.sfs


##-===================================================-##
##   [+] The *.sfs file is mounted with the -m flag
##-===================================================-##
sfsimage -m $File.sfs


##-=================================================-##
##   [+] Display information about the raw file:
##-=================================================-##
mmls kingston.sfs.d/$File.raw


##-======================================-##
##   [+] Unmount it with the -u flag:
##-======================================-##
sfsimage -u kingston.sfs.d

