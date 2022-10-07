#!/bin/sh

## ----------------------------------------------------------------------------------------------------- ##
	fsck -N                     ## dont execute, just show what could be done
	fsck -As                    ## Check and repair all filesystems listed in /etc/fstab
	fsck -f /dev/sda1           ## Force a filesystem check on /dev/sda1
	fsck -fv /dev/sda1          ## Force another check, this time with verbose output:
	fsck -y /dev/sda1           ## During filesystem repair, do not ask questions and assume yes
## ----------------------------------------------------------------------------------------------------- ##
	fsck.ext2 -c /dev/sda1      ## Check a ext2 filesystem, running the badblocks command
	e2fsck -c /dev/sda1         ## mark all bad blocks and add them to the bad block inode to 
                                    ## prevent them from being allocated to files or directories
## ----------------------------------------------------------------------------------------------------- ##
	e2fsck -p                   ## Automatic repair (no questions)
	e2fsck -n                   ## Make no changes to the filesystem
	e2fsck -y                   ## Assume "yes" to all questions
	e2fsck -c                   ## Check for bad blocks and add them to the badblock list
	e2fsck -f                   ## Force checking even if filesystem is marked clean
	e2fsck -v                   ## Be verbose
## ----------------------------------------------------------------------------------------------------- ##
	e2fsck -b $Superblock		## Use alternative superblock
	e2fsck -B $BlockSize		## Force blocksize when looking for superblock
	e2fsck -j $Dir			## Set location of the external journal
	e2fsck -l $BadBlocksFile	## Add to badblocks list
	e2fsck -L $BadBlocksFile	## Set badblocks list
## ----------------------------------------------------------------------------------------------------- ##
	badblocks -o $BadBlocks.rpt /dev/sda3 $TotalBlockCount
	e2fsck -f -l $BadBlocks.rpt /dev/sda1
## ----------------------------------------------------------------------------------------------------- ##


