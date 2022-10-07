#!/bin/sh
## Btrfs.sh



##-======================================-##
##   [+] Show The Btrfs Full Help Page
##-======================================-##
btrfs --help --full


##-===============================================-##
##   [+] List of Filesystem Features Supported:
##-===============================================-##
mkfs.btrfs -O list-all






                    ## --------------------------------------------------------------- ##
mixed-bg            ##  [+] Mixed data and metadata block groups
                    ## --------------------------------------------------------------- ##

                    ## --------------------------------------------------------------- ##
extref              ##  [+] Increased hardlink limit per file in a directory to 65536,
                    ## --------------------------------------------------------------- ##

                    ## --------------------------------------------------------------- ##
raid56              ##  [+] Extended format for RAID5/6
                    ## --------------------------------------------------------------- ##

                    ## --------------------------------------------------------------- ##
no-holes            ##  [+] Improved representation of file extents. 
                    ##      ( where holes arnt Stored as an extent.)
                    ##  [?] Saves a few percent of metadata if sparse files are used
                    ## --------------------------------------------------------------- ##




##-================================-##
##   [+] Format A Partition:
##-================================-##


##-=======================================-##
##   [+] Create A New Btrfs Partition:
##-=======================================-##



##-==================================================-##
##   [+] Specify A Label For The New Partition:
##-==================================================-##
## -------------------------------------------------- ##
##   [?] The String Needs To Be Less Than 256 Bytes
## -------------------------------------------------- ##
mkfs.btrfs -L BtreeFS /dev/sdc




##-====================================================================-##
##   [+] Specify An Allocated Profile For Your New Btrfs Filesystem:
##-====================================================================-##
## -------------------------------------------------------------------- ##
##  [?] A Single Device Filesystem Will Default To DUP
##  [?] Unless A SSD is Detected. Then it Will Default To Single. 
## -------------------------------------------------------------------- ##

mkfs.btrfs -m single /dev/sdc
mkfs.btrfs -m mixed /dev/sdc


## --------------------------------------------------------------- ##
##   [+] The mixed mode will remove the isolation and then,
##   [+] Store both types in the same block group type.
## --------------------------------------------------------------- ##



## -------------------------------------------------------------------- ##
##  [?] The detection is based on the value of the queued rotation.
##  [?] where DEV is the short name of the device.
## -------------------------------------------------------------------- ##
cat /sys/block/DEV/queue/rotational



## --------------------------------------------------------------- ##
##   [+] Combined Both  Options: 
## --------------------------------------------------------------- ##
##   [?] Specify The Data Block Groups Profile:
##   [?] Specify The Metadata Block Groups Profile:
## --------------------------------------------------------------- ##
mkfs.btrfs --data single --label ChickenFucker /dev/sdb
mkfs.btrfs --data single --metadata single --label Xe1phixGitLab /dev/sdc
mkfs.btrfs --data single --metadata single /dev/sdc




##-===================================================-##
##   [+]  Forcibly overwrite the block devices 
##        when an existing filesystem is detected. 
##-===================================================-##
mkfs.btrfs --force --data single --label ChickenFucker /dev/sdb


##-=============================================================-##
##   [?]  By default, mkfs.btrfs will utilize libblkid 
##        To check For any btrfs filesystems on the devices.
##-=============================================================-##




##-==============================================-##
##   [+] Create A Subvolume Named "btrfs-test"
##-==============================================-##
cd /run/media/public/BTree/
btrfs subvolume create btrfs-test



##-====================================================-##
##   [+] Create A Subvolume, And Add It To A qgroup
##-====================================================-##
btrfs subvolume create -i $qgroupID



##-===========================================-##
##   [+] Snapshot btrfs-test For A Backup:
##-===========================================-##
btrfs subvolume snapshot btrfs-test/ btrfs-test-snap/


##-===========================================-##
##   [+] Readonly snapshot of the subvolume
##-===========================================-##
btrfs subvolume snapshot -r btrfs-test/ btrfs-test-snap/


##-=========================================================-##
##   [+] List Subvolumes And Snapshots In The Filesystem.
##-=========================================================-##
btrfs subvolume list /mnt/btrfs-test/
btrfs subvolume list -p -u -t btrfs-test


## ----------------------------------------------------------------------------------------------- ##
    btrfs subvolume list -p             ## print parent ID
## ----------------------------------------------------------------------------------------------- ##
    btrfs subvolume list -c             ## print the ogeneration of the subvolume
## ----------------------------------------------------------------------------------------------- ##
    btrfs subvolume list -g             ## print the generation of the subvolume
## ----------------------------------------------------------------------------------------------- ##
    btrfs subvolume list -u             ## print the uuid of subvolumes (and snapshots)
## ----------------------------------------------------------------------------------------------- ##
    btrfs subvolume list -q             ## print the parent uuid of the snapshots
## ----------------------------------------------------------------------------------------------- ##
    btrfs subvolume list -R             ## print the uuid of the received snapshots
## ----------------------------------------------------------------------------------------------- ##
    btrfs subvolume list -t             ## print the result as a table
## ----------------------------------------------------------------------------------------------- ##
    btrfs subvolume list --sort=        ## list the subvolume in order of gen, ogen, rootid or path
## ----------------------------------------------------------------------------------------------- ##



##-================================-##
##   [+] Query Btrfs Partitions:		
##-================================-##
btrfs filesystem usage
btrfs filesystem usage /
btrfs fi usage /mnt


btrfs filesystem usage -h -T --si btrfs-test
btrfs filesystem usage -h -T btrfs-test
btrfs filesystem usage -h btrfs-test


##-=============================================-##
##   [+] Scan Devices For A Btrfs Filesystem
##-=============================================-##
btrfs device scan --all-devices
btrfs device scan /dev/sdc



use the mount options device to specify the list of devices to scan at the time of mount.

mount -o device=/dev/sdb,device=/dev/sdc /dev/sda /mnt











##-===================================================================-##
##   [+] Populate the toplevel subvolume with files from $RootDir:
##-===================================================================-##
mkfs.btrfs --rootdir $RootDir


##-=============================================-##
##   [+] Show Device IO Error Statistics
##-=============================================-##
btrfs device stats /dev/sdc


##-===========================================-##
##   [+] Summarize Disk Usage of Each File:
##-===========================================-##
btrfs filesystem du 


##-=========================================================-##
##   [+] Show Space Usage Information For A Mount Point:
##-=========================================================-##
btrfs filesystem df /media/xe1phix/Btrfs



echo "##-==========================================================================-##"
echo "   [+] Shows How Much Has Been Allocated Out of The Total Available Space		  "
echo "##-==========================================================================-##"
btrfs fi show


echo "##-================================================-##"
echo "   [+] See How The Allocation is Used:			"
echo "       See How Much of it Contains Useful Data:		"
echo "##-================================================-##"
btrfs fi df ../BTree/
btrfs fi df btrfs-test
btrfs filesystem df /run/media/public/BTree



##-====================================-##
##   [+] List The Btrfs-Control File:
##-====================================-##
ls -l /dev/btrfs-control


##-====================================================-##
##   [+] Print Btrfs Features Allowed By The Kernel:
##-====================================================-##
ls /sys/fs/btrfs/features/


##-=================================-##
##   [+] Print Btrfs Sector Size:
##-=================================-##
cat -vT /sys/fs/btrfs/425b905b-424e-4bd6-a3d6-008011146f9b/sectorsize


##-===========================-##
##   [+] Print Device Size:
##-===========================-##
cat -vT /sys/fs/btrfs/425b905b-424e-4bd6-a3d6-008011146f9b/devices/sde/size


##-=====================================-##
##   [+] Print Btrfs Stat Information:
##-=====================================-##
cat -vT /sys/fs/btrfs/eafed205-e99b-4b12-b31b-57625b69c5c1/devices/sdc/stat



##-============================================-##
##   [+] Show Btrfs Superblock Information
##-============================================-##
btrfs inspect-internal dump-super --full --all /dev/sdc


##-=============================-##
##   [+] Dump Tree Structures
##-=============================-##
btrfs inspect-internal dump-tree 
btrfs inspect-internal dump-tree --extents /dev/sdc
btrfs inspect-internal dump-tree --device /dev/sdc
btrfs inspect-internal dump-tree --uuid /dev/sdc


##-============================================-##
##   [+] Print Sizes And Statistics of Trees:
##-============================================-##
btrfs inspect-internal tree-stats /dev/sdc



##-=====================================================-##
##   [?] A filesystem object can be a the filesystem, 
##       a subvolume, an inode or a device.
##-=====================================================-##


##-============================================================-##
##   [+] Lists available properties with their descriptions
##-============================================================-##
btrfs property list ../BTree/
btrfs property list ../BTree/btrfs-test
btrfs property list ../BTree/btrfs-test-snap/


##-============================================-##
##   [+] Get a property from a btrfs object:
##-============================================-##
btrfs property get ../BTree/
btrfs property get -t s btrfs-test
btrfs property get -t d btrfs-test
btrfs property get -t f btrfs-test




Sets a property on a btrfs object.


btrfs property set 
btrfs property set -t s /media/xe1phix/BonerBruser ro true
btrfs property set -t s /media/xe1phix/BonerBruser ro false
btrfs property set -t f /media/xe1phix/BonerBruser label $Label

##-==========================================================-##
##   [?] Btrfs automatically tries to compress files using 
##        Lempel-Ziv-Oberhumer (LZO) or zlib compression
##-==========================================================-##

##-=========================================================-##
##   [+] Mount A Btrfs File System with lzo Compression:
##-=========================================================-##
mount -o compress=lzo /dev/sdb /mnt



##-=========================================================-##
##   [+] Mount A Btrfs File System with zlib Compression:
##-=========================================================-##
mount -o compress=zlib /dev/sdb /mnt


##-=========================================-##
##   [+] The FStab Config Would Look Like:
##-=========================================-##
/dev/sdb /mnt   btrfs   defaults,compress=lzo 0 1



##-================================================================-##
##   [+] Compression Can Be Set At The File System-Level 
##   [?] By Mounting The File System with Compression Enabled 
##-================================================================-##
mount -o compress=lzo /dev/sdb /mnt/$Path







##-============================================================-##
##   [+] Create a subvolume, mount using lzo compression:
##       Create a subvolume named mysubvol:
##-============================================================-##
btrfs subvolume create /mnt/Btreez/Btree-Subvolume


##-====================================================-##
##   [+] Mount the subvolume and enable compression
##-====================================================-##
mount -o compress=lzo,subvol=Btree-Subvolume /dev/sdb /mnt/Btreez/Btree-Subvolume




##-==================================================================-##
##   [+] Create snapshots almost instantly, Initially They
##       Consume virtually no additional disk space 
##       (any modest impact results from additional metadata).
##-==================================================================-##



##-==================================================================-##
##   [+] Create a snapshot of the MYFILES subvolume and 
##       put the newly created snapshot in /mnt/Btreez/Snapshot
##-==================================================================-##
btrfs subvolume snapshot /mnt/Btreez/Btree-Snapshot /mnt/Btreez/Snapshot





##-============================================-##
##   [+] Creating a Snapshot of a Subvolume
##-============================================-##



##-=================================================================-##
##  [?] Btrfs also supports the creation of clones for individual 
##      files within a file system or subvolume
##-=================================================================-##

##-=================================================================-##
##  [?] Clones - are lightweight copies—only an inode is created, 
##      and it shares the same disk blocks as the original file.
##-=================================================================-##




##-====================================-##
##   [+] Clone the file: myfile1 
##       Creating the clone myfile3
##-====================================-##
cp --reflink /mnt/Btreez/Btreez/$file1 /mnt/Btreez/Btreez/$file3




##-================================================================-##
##   [+] Identify which files have changed on a given subvolume:
##-================================================================-##
btrfs subvolume find-new
















##-============================================-##
##  [+] Run A Btrfs Check on The Filesystem:
##-============================================-##
btrfs check --repair $device


##-============================================================================-##
##  [?] If you have a dead btrfs file system, 
##  [+] you can try to mount it with the recovery mount option 
##      which will try to seek for a usable copy of the tree root:
##-============================================================================-##
mount -o recovery /dev/sdb /mnt



##-====================================-##
##  [+] Force a sync on a filesystem
##-====================================-##
btrfs filesystem sync /dev/sdc


##-====================================-##
##  [+] Add a device to a filesystem
##-====================================-##
btrfs device add /dev/sdc /mnt/BTree/ 	





btrfs filesystem show /dev/sdc





/sys/fs/btrfs/a77fbf52-6ab1-4169-9ffe-e105f3809ec0/devices/dm-1/trace/pid



/sys/fs/btrfs/a77fbf52-6ab1-4169-9ffe-e105f3809ec0/devices/dm-1/trace/enable


/sys/fs/btrfs/a77fbf52-6ab1-4169-9ffe-e105f3809ec0/devices/dm-1/integrity/read_verify


/sys/fs/btrfs/a77fbf52-6ab1-4169-9ffe-e105f3809ec0/devices/dm-1/integrity/device_is_integrity_capable



/sys/fs/btrfs/a77fbf52-6ab1-4169-9ffe-e105f3809ec0/devices/dm-1/dm/uuid








echo "##-============================================================================-##"
echo "   [+] Remove the failed hard drive by mounting the system in Degraded Mode:		"
echo "##-============================================================================-##"
mount -o degraded /dev/sdb /mnt



echo "##-============================================-##"
echo "   [+] Create Snapshots of those subvolumes: 		"
echo "##-============================================-##"
btrfs subvolume snapshot /source /destination



echo "##-====================================-##"
echo "   [+] Get the ID of that subvolume:		"
echo "##-====================================-##"

btrfs subvolume list /mntpt



echo "##-============================================-##"
echo "   [+] Then mount it to another mount point:		"
echo "##-============================================-##"

umount /mntpt
mount -o subvol=231 /dev/sdx /newmntpt





echo "##-============================-##"
echo "   [+] create a subvolume:		"
echo "##-============================-##"

btrfs subvolume create $Path/$Subvolume



echo "##-=============================================-##"
echo "   [+] list the current subvolumes under <path>:	 "
echo "##-=============================================-##"

btrfs subvolume list -p $Path



echo "##-============================-##"
echo "   [+] delete a subvolume:		"
echo "##-============================-##"

btrfs subvolume delete $Path/$Subvolume

btrfs subvolume delete /home-snap/


echo "##-====================================-##"
echo "   [+] Change the default sub-volume:		"
echo "##-====================================-##"

btrfs subvolume set-default subvolume-id /




echo "##-============================================-##"
echo "   [+] Enable qgroups (Quota Group Support):		"
echo "##-============================================-##"

btrfs quota enable $Path


echo "##-================================================================-##"
echo "   [+] Create a qgroup (quota group) for each of the subvolumes		"
echo "       Using their <subvolume id> and rescan them:					"
echo "##-================================================================-##"


btrfs subvolume list $Path | cut -d' ' -f2 | xargs -I{} -n1 btrfs qgroup create 0/{} $Path




btrfs quota rescan $Path






echo "##-====================================================-##"
echo "   [?] Quota groups in Btrfs form a tree hierarchy		"
echo "## ---------------------------------------------------- ##"
echo "   [?] whereby qgroups are attached to subvolumes.		"
echo "##-====================================================-##"






echo "##-==================================================================-##"
echo "   [+] show usage and limits for a given path within a filesystem:	  "
echo "##-==================================================================-##"
btrfs qgroup show -reF $Path


echo "##-=================================-##"
echo "   [+] apply a limit to a qgroup		 "
echo "##-=================================-##"
btrfs qgroup limit


echo "##-=================================-##"
echo "   [+] Rescan the subvolumes:			 "
echo "##-=================================-##"
btrfs quota rescan $Path



echo "##-===========================================================-##"
echo "   [+] Then you can assign a limit to any subvolume using;	   "
echo "##-===========================================================-##"
btrfs qgroup limit 100G $Path/$Subvolume


echo "##-========================================-##"
echo "   [+] You can look at quota usage using		"
echo "##-========================================-##"
btrfs qgroup show $Path





echo "##-========================================================-##"
echo "   [+] Disable copy-on-write for single files/directories:	"
echo "##-========================================================-##"
chattr +C /dir/file




echo "##-============================================-##"
echo "   [+] Manually Defragment your root Directory:	"
echo "##-============================================-##"
btrfs filesystem defragment -r /



##-=======================================================-##
## [+] Recursively defragment files under $Directory. 
## [+] wait until all blocks are flushed, 
## [+] Then force file compression.
##-=======================================================-##

btrfs filesystem defrag -v -r -f -clzo $Directory




echo "##-========================================================================-##"
echo "   [+] Btrfs Scrub - Fault isolation and checksum algorithms                  "
echo "##-========================================================================-##"
echo "## ------------------------------------------------------------------------ ##"
echo "   > It Reads all the data and metadata on the filesystem						" 
echo "   > Uses checksums and the duplicate copies from RAID  						"
echo "     Storage to identify and repair any corrupt data.							"	
echo "## ------------------------------------------------------------------------ ##"


echo "## -------------------------------------------------------------------------------- ##"
echo "   > Fault isolation - is provided by storing metadata separately from user data      "
echo "     and by protecting information through cyclical redundancy checks (CRCs)          "
echo "     that are stored in a btree that is separate from the data.                       "
echo "## -------------------------------------------------------------------------------- ##"




echo "##-======================================================================-##"
echo "   [+] Start a (background) scrub on the filesystem which contains /:		  "
echo "##-======================================================================-##"
btrfs scrub start /mnt/BTree


echo "##-===========================================-##"
echo "   [+] Initiate a check of the file system       "
echo "##-===========================================-##"
btrfs scrub start /mnt/BTree


btrfs scrub start 


## ------------------------------------------------------------------------------------------------------------- ##
    btrfs scrub start -f $Path|$Device          ## force starting new scrub even if a scrub is already running
                                                ## this is useful when scrub stats record file is damaged
## ------------------------------------------------------------------------------------------------------------- ##
    btrfs scrub start -R $Path|$Device          ## raw print mode, print full data instead of summary
## ------------------------------------------------------------------------------------------------------------- ##
    btrfs scrub start -r $Path|$Device          ## read only mode
## ----------------------------------------------------------------------------------------------- ##
    btrfs scrub start -d $Path|$Device          ## stats per device
## ----------------------------------------------------------------------------------------------- ##



echo "##-============================================-##"
echo "   [+] Check the status of a running scrub:		"
echo "##-============================================-##"
btrfs scrub status /mnt/BTree

## ----------------------------------------------------------------------------------------------- ##
    btrfs scrub status -d /mnt/BTree         ## stats per device
## ----------------------------------------------------------------------------------------------- ##
    btrfs scrub status -R /mnt/BTree         ## print raw stats
## ----------------------------------------------------------------------------------------------- ##



echo "##-================================================================================-##"
echo "   [+] Btrfs Balance - Passes all data in the FS through the allocator again. 		"
echo "##-================================================================================-##"
echo "## -------------------------------------------------------------------------------- ##"
echo "   [?] It is primarily intended to rebalance the data in the FS 						"
echo "       Across the devices (when a device is added or removed). 						"
echo "## -------------------------------------------------------------------------------- ##"
echo "   [?] A balance will regenerate missing copies for the  								"
echo "       Redundant RAID levels, if a device has failed.									"
echo "## -------------------------------------------------------------------------------- ##"
echo "##-================================================================================-##"



echo "##-================================================================================-##"
echo "   [?] On a single-device filesystem a balance may be also useful for (temporarily) 	"
echo "       Reducing the amount of allocated but unused (meta)data chunks. 				"
echo "##-================================================================================-##"
btrfs balance start /
btrfs balance status /





echo "##-==========================================================================-##"
echo " [?] A snapshot is simply a subvolume that shares its data (and metadata) 	  "
echo "     with some other subvolume, using btrfs's COW capabilities.				  " 
echo "##-==========================================================================-##"
echo "## -------------------------------------------------------------------------- ##"
echo "   [?] Note: Snapshots are not recursive. Every nested subvolume 				  "
echo "             will be an empty directory inside the snapshot.					  "
echo "## -------------------------------------------------------------------------- ##"



echo "##-=============================-##"
echo "   [+] create a snapshot:			 "
echo "##-=============================-##"
btrfs subvolume snapshot $source /$dest/






echo "##-=================================-##"
echo "     [+] Compression level (0 ~ 9)     "
echo "##-=================================-##"
btrfs-image -w -c 5 /run/media/public/BTrees ~/BTrees






echo "## -------------------------------------------------------------------------- ##"
echo "   [?] A subvolume can be sent to stdout or a file using the send command. 	  "
echo "## -------------------------------------------------------------------------- ##"
echo "   [?] Which is useful for copying a subvolume to an external device 			  "
echo "            (e.g. a USB disk mounted at /backup above).						  "
echo "## -------------------------------------------------------------------------- ##"


btrfs send $RootBackup | btrfs receive $Backup
btrfs send /root_backup | btrfs receive /backup





echo "##-==========================================================================-##"
echo "   [+] Send only the incremental difference to /backup:						  "
echo "##-==========================================================================-##"
echo "## -------------------------------------------------------------------------- ##"
echo "   [?] A new subvolume named root_backup_new will be present in /backup.		  "
echo "## -------------------------------------------------------------------------- ##"


btrfs send -p $RootBackup $RootBackupNew | btrfs receive $Backup
btrfs send -p /root_backup /root_backup_new | btrfs receive /backup

btrfs send --verbose -f ~/Btree-Backup          ## write to a file
btrfs receive --dump -v


-p <parent>      Send an incremental stream from <parent> to <subvol>.


 -c <clone-src>   Use this snapshot as a clone source for an 
                     incremental send (multiple allowed)






echo "##-====================================================================-##"
echo "     [?] btrfs-check cannot be used on a mounted file system. 			"
echo "## -------------------------------------------------------------------- ##"
echo "     [?] To be able to use btrfs-check without booting from a live USB:	"
echo "         Regenerate the initial ramdisk using mkinitcpio:					"
echo "## -------------------------------------------------------------------- ##"
echo "##-====================================================================-##"


echo "##-=====================================-##"
echo "   [+] Add It To The Initial Ramdisk:		 "
echo "##-=====================================-##"
/etc/mkinitcpio.conf

BINARIES=("/usr/bin/btrfs")




echo "##-============================================================-##"
echo "   [+] Checksum Hardware Acceleration - To Verify if Btrfs 		"
echo "       Checksum is Hardware Accelerated:							"
echo "##-============================================================-##"
dmesg | grep crc32c









echo "##-========================================-##"
echo "   [+] create a RAID1 mirror in Btrfs?		"
echo "##-========================================-##"
mkfs.btrfs -m raid1 -d raid1 /dev/sda1 /dev/sdb1


echo "##-====================================================-##"
echo "   [?] Show the data structure of the RAID partitions:	"
echo "##-====================================================-##"
btrfs fi df /mnt/BTree


## -------------------------------------------------- ##"
## ----------------- Example Output ----------------- ##"
## -------------------------------------------------- ##"
echo "	Data, RAID1: total=1.00GB, used=128.00KB		"
echo "	Data: total=8.00MB, used=0.00					"
echo "	System, RAID1: total=8.00MB, used=4.00KB		"
echo "	System: total=4.00MB, used=0.00					"
echo "	Metadata, RAID1: total=1.00GB, used=24.00KB		"
echo "	Metadata: total=8.00MB, used=0.00				"
## -------------------------------------------------- ##"







echo "##-================================================================-##"
echo "   [+] "
echo "##-================================================================-##"




##-=========================================-##
##  [+] Show btrfs superblock information
##-=========================================-##
btrfs-show-super
btrfs inspect-internal dump-super --full --all /dev/sdc




##-=========================-##
##  [+] Backup A Snapshot:
 ##-=========================-##
btrfs send /root_backup | btrfs receive /backup







##-========================================================-##
##  [+] Send only the difference between two snapshots
##-========================================================-##
btrfs send -p /root_backup /root_backup_new | btrfs receive /backup









btrfsctl        ## control program to create snapshots and subvolumes:

mount /dev/sda2 /mnt

btrfsctl -s new_subvol_name /mnt
btrfsctl -s snapshot_of_default /mnt/default
btrfsctl -s snapshot_of_new_subvol /mnt/new_subvol_name
btrfsctl -s snapshot_of_a_snapshot /mnt/snapshot_of_new_subvol

ls /mnt

default snapshot_of_a_snapshot snapshot_of_new_subvol
new_subvol_name snapshot_of_default











##-================================================-##
##  [+] Btrfs provides a mount option that 
##      enables an auto-defragmentation helper
##-================================================-##
mount -o autodefrag





##-=====================================================-##
##  [+] Initiate Offline file system defragmentation
##-=====================================================-##
btrfs filesystem defrag /mnt


btrfs filesystem defragment 

-v                  be verbose
        -r                  defragment files recursively
        -c[zlib,lzo,zstd]   compress the file while defragmenting
        -f                  flush data to disk immediately after defragmenting






## ----------------------------------------------------------------------------------------------- ##
    btrfstune -r 		    ## enable extended inode refs
## ----------------------------------------------------------------------------------------------- ##
    btrfstune -x 		    ## enable skinny metadata extent refs
## ----------------------------------------------------------------------------------------------- ##
    btrfstune -n 		    ## enable no-holes feature (more efficient sparse file representation)
## ----------------------------------------------------------------------------------------------- ##
    btrfstune -f 		    ## force to do dangerous operation, make sure that you are aware of the dangers
## ----------------------------------------------------------------------------------------------- ##
    btrfstune -u            ## change fsid, use a random one
## ----------------------------------------------------------------------------------------------- ##
    btrfstune -U $UUID		## change fsid to UUID
## ----------------------------------------------------------------------------------------------- ##







## ----------------------------------------------------------------------------------------------- ##
    btrfs check --super $SuperBlock             ## use this superblock copy
## ----------------------------------------------------------------------------------------------- ##
    btrfs check --backup                        ## use the first valid backup root copy
## ----------------------------------------------------------------------------------------------- ##
    btrfs check --repair                        ## try to repair the filesystem
## ----------------------------------------------------------------------------------------------- ##
    btrfs check --readonly                      ## run in read-only mode (default)
## ----------------------------------------------------------------------------------------------- ##
    btrfs check --init-csum-tree                ## create a new CRC tree
## ----------------------------------------------------------------------------------------------- ##
    btrfs check --init-extent-tree              ## create a new extent tree
## ----------------------------------------------------------------------------------------------- ##
    btrfs check --check-data-csum               ## verify checksums of data blocks
## ----------------------------------------------------------------------------------------------- ##
    btrfs check --qgroup-report                 ## print a report on qgroup consistency
## ----------------------------------------------------------------------------------------------- ##
    btrfs check --subvol-extents $SubVolID      ## print subvolume extents and sharing state
## ----------------------------------------------------------------------------------------------- ##
    btrfs check --progress                      ## indicate progress
## ----------------------------------------------------------------------------------------------- ##
    btrfs check --clear-space-cache v1|v2       ## clear space cache for v1 or v2
## ----------------------------------------------------------------------------------------------- ##

btrfs check --progress --check-data-csum 




## ----------------------------------------------------------------------------------------------- ##
    btrfs rescue fix-device-size $Device        ## Re-align device and super block sizes.
## ----------------------------------------------------------------------------------------------- ##
    btrfs rescue zero-log $Device               ## Clear the tree log.
## ----------------------------------------------------------------------------------------------- ##
    btrfs rescue super-recover -v $Device       ## Recover bad superblocks from good copies
## ----------------------------------------------------------------------------------------------- ##
    btrfs rescue chunk-recover -v $Device       ## Recover the chunk tree by scanning 
                                                ## the devices one by one.
## ----------------------------------------------------------------------------------------------- ##




##-===================================================================-##
##  [+] Try to restore files from a damaged filesystem (unmounted)
##-===================================================================-##
btrfs restore --verbose <device> <path> | -l <device>


## ----------------------------------------------------------------------------------------------- ##
    btrfs restore --verbose --snapshots             ## 
## ----------------------------------------------------------------------------------------------- ##
    btrfs restore --verbose --xattr                 ## restore extended attributes
## ----------------------------------------------------------------------------------------------- ##
    btrfs restore --verbose --metadata              ## restore owner, mode and times
## ----------------------------------------------------------------------------------------------- ##
    btrfs restore --verbose --symlink               ## restore symbolic links
## ----------------------------------------------------------------------------------------------- ##
    btrfs restore --verbose --ignore-errors         ## ignore errors
## ----------------------------------------------------------------------------------------------- ##
    btrfs restore --verbose --overwrite             ## 
## ----------------------------------------------------------------------------------------------- ##
    btrfs restore --verbose --super $mirror         ## super mirror
## ----------------------------------------------------------------------------------------------- ##
    btrfs restore --verbose --root $rootid          ## root objectid
## ----------------------------------------------------------------------------------------------- ##
    btrfs restore --verbose -d $Dir                 ## find directory
## ----------------------------------------------------------------------------------------------- ##
    btrfs restore --verbose --list-roots            ## list tree roots
## ----------------------------------------------------------------------------------------------- ##
    btrfs restore --verbose -t $bytenr              ## tree location
    
## ----------------------------------------------------------------------------------------------- ##
    btrfs restore --verbose -f $bytenr              ## filesystem location
## ----------------------------------------------------------------------------------------------- ##


