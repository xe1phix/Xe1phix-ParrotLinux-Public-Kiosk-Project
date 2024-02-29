#!/bin/sh
#####################################################################################################
fsck -N				        # dont execute, just show what could be done
fsck -As			        # Check and repair serially all filesystems listed in /etc/fstab
fsck -f /dev/sda1	        # Force a filesystem check on /dev/sda1 even if it thinks is not necessary
fsck -fv /dev/sda1	        # Force another check, this time with verbose output:
fsck -y /dev/sda1	        # During filesystem repair, do not ask questions and assume that the answer is always yes
#####################################################################################################
fsck.ext2 -c /dev/sda1		# Check a ext2 filesystem, running the badblocks command
e2fsck -c /dev/sda1			# mark all bad blocks and add them to the bad block inode to prevent 
							# them from being allocated to files or directories
#####################################################################################################
e2fsck -p		## Automatic repair (no questions)
e2fsck -n		## Make no changes to the filesystem
e2fsck -y		## Assume "yes" to all questions
e2fsck -c		## Check for bad blocks and add them to the badblock list
e2fsck -f		## Force checking even if filesystem is marked clean
e2fsck -v		## Be verbose
#####################################################################################################
e2fsck -b superblock			## Use alternative superblock
e2fsck -B blocksize				## Force blocksize when looking for superblock
e2fsck -j external_journal		## Set location of the external journal
e2fsck -l bad_blocks_file		## Add to badblocks list
e2fsck -L bad_blocks_file		## Set badblocks list
#####################################################################################################
badblocks -o badblocks.rpt /dev/sda3 $TotalBlockCount

e2fsck -f -l badblocks.rpt /dev/sda1



