
mke2fs -j -b 4096 /dev/sdb                  ## Formats using large block size (Default is 1024-byte blocks)

dumpe2fs /dev/sda3 | grep "Block count"



badblocks -o badblocks.rpt /dev/sda3 $TotalBlockCount

e2fsck -f -l badblocks.rpt /dev/sda1

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


hdparm -g /dev/hda 			## Display drive geometry (cylinders, heads, sectors) of /dev/hda
hdparm -i /dev/hda 			## Display identification information for /dev/hda
hdparm -tT /dev/hda 		## Perform benchmarks on the /dev/hda drive

mount -o remount -o acl


cat /proc/$$/status | egrep '^[UG]id'

cat /proc/$$/uid_map



ls -l /dev/disk/by-id
ls -R /dev/mapper

udevadm info --attribute-walk --name=/dev/sda

parted --list print all
zuluMount-cli -l
udisksctl dump
cat /proc/partitions
mount | column ‐t

mount -t tmpfs none /mnt -o 'context="system_u:object_r:tmp_t:s0:c127,c456",noexec'

mount /tmp/disk.img /mnt -o loop
mount -t ext3 /tmp/disk.img /mnt

mount -t overlay  overlay -olowerdir=/lower,upperdir=/upper,workdir=/work  /merged

mkfs.xfs -l logdev=/dev/sdb1,size=10000b /dev/sda1

## Prints the start sector of partition 5 on /dev/sdb without header.
partx -o START -g --nr 5 /dev/sdb

## Lists the length in sectors and human-readable size of partition 5 on /dev/sda.
partx -o SECTORS,SIZE /dev/sda5 /dev/sda


