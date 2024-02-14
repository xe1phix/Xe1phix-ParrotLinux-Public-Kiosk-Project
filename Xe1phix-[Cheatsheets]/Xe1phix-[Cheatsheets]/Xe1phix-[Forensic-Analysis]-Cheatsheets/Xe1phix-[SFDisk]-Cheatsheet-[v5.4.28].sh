#!/bin/sh
##-=======================================-##
##   [+] Xe1phix-[SFDisk]-Cheatsheet.sh
##-=======================================-##





##-==========================================================-##
##   [+] Creates empty GPT partition table.
##-==========================================================-##
echo 'label: gpt' | sfdisk /dev/sdb





sfdisk --wipe
sfdisk --wipe-partitions



##-==========================================================-##
##  [+] reates a 100MiB free area before the  first
##      partition  and moves the data it contains (e.g. a filesystem)
##-==========================================================-##
echo '+100M,' | sfdisk --move-data /dev/sdc -N 1



##-==========================================================-##
##  [+] reates a new partition from the free space (at offset 2048)
##-==========================================================-##

echo '2048,' | sfdisk /dev/sdc --append



##-==========================================================-##
##  [+] eorders partitions to match disk order 
##      (the original sdc1 will become sdc2)
##-==========================================================-##

sfdisk /dev/sdb --reorder


sfdisk --verify $Device
##-==========================================================-##
##  [+] Test whether the partition table and partitions seem correct.
##-==========================================================-##



sfdisk --backup --backup-file ~/sfdisk-$Device-$Offset.bak


##-==========================================================-##
##  [+] Print all supported types for the current disk label
##-==========================================================-##

sfdisk --list-types



##-=====================================================-##
##  [+] List the sizes of all / specified devices 
##      in units of 1024 byte size. 
##-=====================================================-##
 
sfdisk --show-size




##-=====================================-##
##  [+] Change the GPT partition UUID.
##-=====================================-##
sfdisk --part-uuid


##-=====================================-##
##  [+] Change the partition type.
##-=====================================-##

sfdisk --part-type




##-==========================================================-##
##  [+] Change  the  GPT  partition name (label)
##-==========================================================-##

## ----------------------------------------------------------------------- ##
##  [?] If the label isnt specified, print the current partition label.
## ----------------------------------------------------------------------- ##
sfdisk --part-label





##-==========================================================-##
##  [+] The currently supported attribute bits are: 

RequiredPartition
NoBlockIOProtocol
LegacyBIOSBootable 


GUID-specific bits          ## in the range from 48 to63.  
                            ## For example, the string 
                            ## "RequiredPartition,50,51" 
                            ## sets three bits.



sfdisk --part-attrs



sfdisk --list-free

sfdisk --list --show-geometry



sfdisk --list --json



sfdisk --partno <num>        specify partition number


sfdisk --append              append partitions to existing partition table


sfdisk --backup              backup partition table sectors (see -O)


sfdisk --dump <dev>            ## dump partition table (usable for later input)

sfdisk --bytes               print SIZE in bytes rather than in human readable format



sfdisk --verify 

