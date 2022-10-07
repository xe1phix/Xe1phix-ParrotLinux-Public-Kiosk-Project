#!/bin/sh


dumpe2fs /dev/sda3 | grep "Block count"


debugfs -w /dev/sda1 						## debugfs device Interactive ext2/ext3/ext4 filesystem debugger

dumpe2fs -h /dev/sda1						## Display filesystems superblock information (e.g. number of mounts, last checks, UUID)
dumpe2fs /dev/sda1 | grep -i superblock     ## Display locations of superblock (primary and backup) of filesystem
dumpe2fs -b /dev/sda1						## Display blocks that are marked as bad in the filesystem

tune2fs -l /dev/sdc1 | grep "mount options"

tune2fs -j /dev/sda1 				# Add a journal to this ext2 filesystem, making it a ext3
tune2fs -C 4 /dev/sda1 				# Set the mount count of the filesystem to 4
tune2fs -c 20 /dev/sda1 			# Set the filesystem to be checked by fsck after 20 mounts
tune2fs -i 15d /dev/sda1 			# Set the filesystem to be checked by fsck each 15 days


dumpe2fs -h /dev/sda1 | grep -i 'mount count'

tune2fs -c 20 /dev/sda1

fsck.mode=force




tune2fs -c 4 -i 1m                  ## Max mount count 4 or Check interval 1 Month

tune2fs -l			                    ## List the contents of the filesystem superblock
tune2fs -o debug
tune2fs -o user_xattr
tune2fs -o acl
tune2fs -o journal_data
tune2fs -o journal_data_ordered
tune2fs -o journal_data_writeback
	
tune2fs -O [^]feature
tune2fs -O dir_index
                          Use hashed b-trees to speed up lookups for large directories.
tune2fs -O ea_inode
                          Allow  the value of each extended attribute to be placed in the data blocks of a separate inode if neces‐
                          sary, increasing the limit on the size and number of extended attributes  per  file.
tune2fs -O encrypt
                          Enable file system level encryption. 
tune2fs -O extent Enable  the  use  of extent trees to store the location of data blocks in inodes.

tune2fs -O extra_isize
                          Enable the extended inode fields used by ext4.
tune2fs -O has_journal

tune2fs -O read-only         
tune2fs -O quota                          
tune2fs -O mmp    Enable or disable multiple mount protection (MMP) feature.

tune2fs -O metadata_csum

tune2fs -Q 
	[^]usrquota		Sets/clears user quota inode in the superblock.
	[^]grpquota		Sets/clears group quota inode in the superblock.	
	[^]prjquota		Sets/clears project quota inode in the superblock.

tune2fs -U random|time		## Set  the  universally  unique identifier (UUID) of the filesystem to UUID. 



##-========================================================================-##
##   [+] Get the superblock information for the problem filesystem:
##-========================================================================-##
dumpe2fs /dev/sda2 | grep superblock


##-========================================================================-##
##   [+] Sets the interval between checks to 13 days.
##-========================================================================-##
tune2fs -i 13d /dev/sda1


##-=================================================-##
##   [+] Enable hashed b-trees on EXT filesystems
##-=================================================-##
## ------------------------------------------------------ ##
##   [?] hashed b-trees - Speeds up directory lookups
## ------------------------------------------------------ ##
tune2fs -O dir_index /dev/sda1


##-===================================================================-##
##   [+] Enable backup copies of the superblock on EXT filesystems
##-===================================================================-##
tune2fs -O sparse_super /dev/sda1


##-=========================================================-##
##   [+] Enable metadata checksuming on EXT filesystems
##-=========================================================-##
tune2fs -O metadata_csum /dev/sdb


##-========================================================================-##
##   [+] Check the Block size
##-========================================================================-##
tune2fs -l /dev/sdb | grep 'Block size'


##-========================================================================-##
##   [+] Check the Block size
##-========================================================================-##
getconf PAGE_SIZE



##-========================================================================-##
##   [+] Enable the encryption feature flag on the filesystem
##-========================================================================-##
tune2fs -O encrypt /dev/sdb



##-========================================================================-##
##   [+] Migrating an Ext3 filesystem to a Ext4 filesystem
##-========================================================================-##
tune2fs -O extents,uninit_bg,dir_index /dev/sdb





## ------------------------------------------------------------ ##
##   [?] Find out where the partitions are:
##   [?] List the start and end cylinders of each partition 
##   [?] List the units in which they’re measured.
## ------------------------------------------------------------ ##
fdisk -lu /mnt/$Dir/$File.dd


##-==============================================-##
##   [+] Mount the image as a loopback device:
##-==============================================-##
mount -o loop /mnt/$Dir/$File.dd /mnt/$Dir


##-=======================================================-##
##   [+] Pass in one of the backup superblocks to fsck:
##-=======================================================-##
fsck -b 32768 /dev/sda2


##-==============================================-##
##   [+] Pass the backup superblock to mount:
##-==============================================-##
mount sb=32768 /dev/sda2 /mnt



## ---------------------------------------------------------- ##
##   [?] When the superblock of a partition is damaged
##       you can specify a different superblock to use:
## ---------------------------------------------------------- ##
debugfs -b 1024 -s 8193 /dev/sda1



##-==================================================================-##
##   [+] ee which filesystems are mounted by issuing the command:
##-==================================================================-##
cat /proc/mounts


##-==================================================================-##
##   [+] Find out what filesystems your current kernel supports:
##-==================================================================-##
cat /proc/filesystems




##-============================================================-##
##   [+] Migrating an Ext3 filesystem to a Ext4 filesystem
##-============================================================-##
tune2fs -O extents,uninit_bg,dir_index /dev/sdb


##-======================================-##
##   [+] Defrag the Ext4 filesystem
##-======================================-##
e4defrag -c -v /dev/sdb


##-========================================================================-##
##   [+] XFS Fragmentation and Defragmentation
##-========================================================================-##
## ------------------------------------------------------------------------ ##
##       Measure the current level of fragmentation with xfs_db.
## ------------------------------------------------------------------------ ##
xfs_db -c frag -r /dev/sdb1


##-======================================-##
##   [+] Defragment XFS with xfs_fsr.
##-======================================-##
xfs_fsr /dev/sdb1





##-=========================================-##
##   [+] Add a journal to the filesystem
##-=========================================-##
tune2fs -j /dev/sdb


##-=========================================-##
##   [+] Use this external journal file:
##-=========================================-##
tune2fs -j -J device=/dev/sdb2 /dev/sda1


##-=========================================-##
##   [+] Create a journal of size 512MB:
##-=========================================-##
tune2fs -j -J size=512 /dev/sda1


##-======================================================-##
##   [+] Create a journal file on a different device 
##-======================================================-##
mke2fs -O journal_dev /dev/sdb2


##-===============================================-##
##   [+] Enable journaling on an EXT filesystem
##-===============================================-##
tune2fs -O ^has_journal /dev/sdb1







##-=============================-##
##   [+] Check the Block size
##-=============================-##
tune2fs -l /dev/sdb | grep 'Block size'


##-=============================-##
##   [+] Check the Block size
##-=============================-##
getconf PAGE_SIZE


##-=========================================-##
##   [+] Specify a 4096-byte sector size:
##-=========================================-##
mmls -b 4096 /dev/sde


##-=================================================-##
##   [+] Create A Ext4 Filesystem 
##   [?] Using a block size of 4096-byte blocks:
##-=================================================-##
mkfs.ext4 -b 4096 -O metadata_csum /dev/sde1


##-========================================================================-##
##   [+] Create an XFS FileSystem, specifying a block size of 8192-byte blocks:
##-========================================================================-##
mkfs.xfs -b size=8192 /dev/sde1



##-========================================================================-##
##   [+] Create a Btrfs FileSystem, using a custom node size or tree block size:
##-========================================================================-##
mkfs.btrfs -n 65536 /dev/sde1





