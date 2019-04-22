
Ψ	Ψ	ϕ	∑ 	ψ 	φ 	σ	π	μ	λ 	η 	ζ 	ε 	Ω 	} 	± 	Ω 	€ 	♦ 	¥ 	§ 	¶ 	» 	Θ 	Ψ 	₤ 	ℒ 	ℤ 	
℧ 	ℵ 	← 	↑ 	→ 	↓ 	∓ 	∑ 	∉ 	≽ 	≼ 	≻ 	≺ 	≫ 	≪ 	≥ 	≤ 	≠ 	③ 	☑ 	☒ 	● 	► 	▸ 	▶ 	▪ 	☼ 	♦ 	
✓ 	✙ 	✡ 	✫ 	✬ 	✭ 	✮ 	✯ 	✹ 	✸ 	✷ 	✶ 	✵ 	➔ 	➢ 	➸ 	⩽ 	⩾ 	 	 	 	 	 	 	 	 	 	 	
 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	
 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	 	
 	 	 	 	 	 		 	 	 	 		 	 	 	 	 	 	 	 	 	 	 	 	 		Θ	 	
	 			 	 	 	 															 	 	
																												
																												
																											
									℧	Ω	₱	€	₫	₩	₦	₤	₡	∞	⌀	₤	⁆	⁅	Ψ	B	D	Ξ	Ψ	
Φ	ϕ	฿	※	†	⁅	⁆	₤	Ω	℧	⩾	⩽	⟧	⟦	∑	≠	Ӂ	ӂ	Ӝ	ӝ	Җ	»	«	¥	Ψ	Ω	╝	╟	
╠	╡	╢	╣	╤	╥	╦	╧	╨	╩	╩	╪	╫	╬	♦	●	◄	▼	►	Ф	Ж	ж	ψ	Ω	Ψ	Ǽ	ǽ	¥
〙	〙	〘	〩	ぁ	あ	ぉ	お	を	ホ	ㄓ	㊧	㎓	㎒	㎑	㎐	㎏	㎎	㎍	㍾	㍽	㍼	㍻	㏒	㏀	㐂	㐆	︷	︸

echo "##~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~##"
echo "   		                                        "
echo "##~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~##"

echo "##~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=##"
echo "   		                                                                "
echo "##~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=##"



Copy-on-write, 
snapshotting
data integrity verification
automatic repair (scrubbing)
RAID-Z
maximum 16 Exabyte file size, 
a maximum 256 Quadrillion Zettabytes
no limit on number of filesystems (datasets) or files


ZFS module dependencies

depmod -a







VDEVs - virtual block devices


the zfs daemon can import and mount zfs pools automatically. 
The daemon mounts the zfs pools reading the file 
/etc/zfs/zpool.cache

For each pool you want automatically mounted by the zfs daemon execute:
zpool set cachefile=/etc/zfs/zpool.cache <pool>


















A ZVOL is a ZFS block device that resides in your storage pool.

This means that the single block device gets to take
advantage of your underlying RAID array, such as mirrors or RAID-Z.




echo " [?] all storage is combined into a common pool "
echo " [?] that is then used to create one or more datasets. "


echo " [?] A ZFS pool can be backed by: 

whole disks 
partitions
regular files



All data and metadata written are checksummed to ensure 
that the data has not become corrupted over time.

Every time data is read from a ZFS pool, the checksum is calculated and compared to the checksum 
that was calculated when the data was originally written.


If you have a redundant ZFS pool, 
the corruption will be automatically repaired and noted in the status screen. 

You can also initiate a manual scan of all data on the drive to check for corruption:

zpool scrub mypool
zpool status mypool


We can also simulate the failure of a disk:
# rm /tutorial/file3
# zpool scrub mypool
# zpool status mypool


Simulate replacing the failed disk with a new one:
# truncate -s 2G /tutorial/file3
# zpool replace mypool 474744448393399570 /tutorial/file3
# zpool status mypool










echo " [+] ZFS pool types:

stripe, mirror, raidz1, raidz2 and raidz3




echo " [+] Create a RAID-Z chain of partions"
zpool create mypool raidz1 /tutorial/file1 /tutorial/file2 /tutorial/file3 /tutorial/file4


echo " [?] This will create /mypool and will be 6GB in size. "
echo " [?] We have 4 pseudo-drives of 2GB each, "
echo " [?] minus 1 for data redundancy."


change the mount point of your zpool during creation:
zpool create -m /mnt mypool /tutorial/file1 /tutorial/file2 /tutorial/file3 /tutorial/file4







echo " [?] One of the most powerful features of ZFS is the ability to "
echo "     create multiple separate file systems                        "
echo "     with different settings from a common storage pool. "


echo " [+] Here we'll create a "subdirectory" dataset in the root pool 
echo "     and enable LZ4 compression on it. 


echo " [?] We can then make another subdirectory and disable compression on it.




Deduplication
-------------

echo " [?] deduplication allows you to store the same data multiple times, 
echo "          but only take up the space of a single copy.

echo " [?] Data can be deduplicated on the file, block, or byte level


zfs create mypool/vms
zfs set dedup=on mypool/vms


If youre paranoid about hash collisions, 
you might want to use extra verification

zfs set dedup=verify mypool/vms
zfs set checksum=sha256,verify mypool/vms

zfs set checksum=sha256 zfs




Adaptive Replacement Cache

ZFS will store a copy of the most often-accessed files in RAM 
(in addition to having a copy in the pool).


L2ARC is a caching "layer" between the RAM
(very fast) and the disks (not so fast).





add an L2ARC to your existing zpool, we might do:
zpool add mypool cache /tutorial/ssd







zfs create mypool/usr
zfs create -o compression=lz4 mypool/usr/ports
zfs create -o compression=off mypool/usr/ports/distfiles
zfs list




zfs get -r compression mypool





when using zfs set to change a property, 
it only affects data written after the setting is applied.

Enabling or disabling compression does not change data that was written previously.






## delete a zpool:
zpool destroy mypool

## Or just a specific dataset:
zfs destroy mypool/dumbstuff






Lets create a 10MB file in the ports dataset:
# dd if=/dev/random of=/mypool/usr/ports/somefile bs=1m count=10
# cd /mypool/usr/ports
# ls -lh






A snapshot is a first class read-only filesystem.

                            Creating Snapshots
You can create two types of snapshots: pool snapshots and dataset snapshots.

pool/dataset@snapshot-name
pool@snapshot-name

zfs snapshot tank/test@tuesday





If you specify the -r (recursive) flag, it will
also create a snapshot of each sub-dataset using the same snapshot name.



zfs snapshot -r mypool/usr/ports@firstsnapshot
zfs list -t all -o name,used,refer,written



ZFS snapshots are read-only, but they can be accessed via a hidden ".zfs" directory. 
This allows you to easily restore a single file that was accidentally modified or deleted:
# ls -lh /mypool/usr/ports/.zfs/snapshot/firstsnapshot/




ZFS Rollback feature:

If you wanted to reverse all of the files in a dataset back to how they were in a snapshot,
rather than copying all of the files from the snapshot back to the dataset 
(which would consume double the space), 
ZFS has the "rollback" operation, 
which reverts all changes written since the snapshot:

zfs rollback -r mypool/usr/ports@firstsnapshot
zfs list -t all -o name,used,refer,written -r mypool




Sending and Receiving Snapshots
ZFS lets you send snapshots of your pool or dataset and output it to a file.
You can also pipe it to other commands. 
This can be used to send datasets over the internet, 
using SSH, and receive them on a remote host.


lets take a snapshot of a dataset and redirect it to a regular file.


This is a local backup.

zfs snapshot mypool/myfiles@backup
zfs send mypool/myfiles@backup > /mnt/filesystem-backup


restore the backup from the file
zfs receive -v mypool/myfiles < /mnt/filesystem-backup


copy that snapshot to a remote server
zfs send mypool/myfiles@backup | ssh you@remoteserver zfs receive -v otherpool/myfiles






Its also possible to do incremental data (changes to snapshot)

zfs send -i mypool/myfiles@backup mypool/myfiles@laterbackup | ssh you@remoteserver zfs receive -v otherpool/myfiles









LZ4 (the latest and greatest - recommended)
gzip (configurable between levels 0-9, uses 6 by default - not recommended)
LZJB (still pretty fast and provides a good trade-off between speed and space)




## enable or disable compression on each dataset, 
## and check the ratio of space saved with:
zfs get compressratio mypool


zfs set compression=





To grow a mirror, expansion will need to be set on the pool.
zpool set autoexpand=on mypool


## choose the checksum algorithm with the "set" subcommand:

zfs set checksum=sha256 mypool



Repair broken or corrupt Boot environments with beadm:

take a snapshot of the main pool, break something, 
then reboot back into the snapshot where everything worked.


beadm create sketchyupdate


echo "$WARNING_DO_NOT_RUN_THIS!!"
rm -rf /boot/*


beadm activate sketchyupdate
reboot

beadm list















zpool offline mypool ad1

























Creating a ZVOL
To create a ZVOL, we use the "-V" switch with our "zfs create" command, and give it a size.

zfs create -V 1G tank/disk1

ls -l /dev/zvol/tank/disk1
ls -l /dev/tank/disk1





I now have the block device /dev/loop0 that represents my 1 GB file.

fallocate -l 1G /tmp/file.img
dd status=progress if=/dev/urandom of=/tmp/file.img 
losetup /dev/loop0 /tmp/file.img




by default you only have 8
loopback devices for your exported block devices.



it requires a preallocated image, on top of your filesystem. So, you are managing three
layers of data: the block device, the file, and the blocks on the filesystem.

With ZVOLs, the block device is exported
right off the storage pool, just like any other dataset.







ext4 formatted ZVOL and mounted to /mnt


zfs create -V 100G tank/ext4
fdisk /dev/tank/ext4
fdisk -l /dev/tank/ext4





mkfs.ext4 /dev/zd0p1
mkfs.ext4 /dev/zd0p2
mkdir /mnt/zd0p{1,2}
mount /dev/zd0p1 /mnt/zd0p1
mount /dev/zd0p2 /mnt/zd0p2





Enable compression on the ZVOL, 
copy over some data, 
then take a snapshot:


zfs set compression=lzjb pool/ext4
tar -cf /mnt/zd0p1/files.tar /etc/
tar -cf /mnt/zd0p2/files.tar /etc/ /var/log/
zfs snapshot tank/ext4@001


You just enabled transparent compression 
and took a snapshot of your ext4 filesystem.











ZVOL storage for VMs

attach the block device to the virtual machine, 
and from its perspective, you have a 
"/dev/vda" or "/dev/sda" 
depending on the setup.





If using libvirt, you would have
/etc/libvirt/qemu/vm.xml


"/dev/zd0" is the ZVOL block device:


<disk type='block' device='disk'>
  <driver name='qemu' type='raw' cache='none'/>
  <source dev='/dev/zd0'/>
  <target dev='vda' bus='virtio'/>
  <alias name='virtio-disk0'/>
  <address type='pci' domain='0x0000' bus='0x00' slot='0x05' function='0x0'/>
</disk>



your VM gets all the ZFS benefits underneath, such as 
snapshots, compression, deduplication, data integrity, drive redundancy, etc.




ZFS datasets


storage pools are not meant to store data directly. Instead, 
we should create filesystems that share the same storage system




as files are placed in the dataset, the pool marks that storage as unavailable to all datasets.




we will assume our ZFS shared storage is named "tank"

Further, we will assume that the pool is
created with 4 preallocated files of 1 GB in size each, in a RAIDZ-1 array.



zfs create tank/test
zfs list


zfs create tank/test2
zfs create tank/test3
zfs create tank/test4
zfs create tank/test5
zfs list





the mount point for the dataset is "/<pool-name>/<dataset-name>"


umount /tank/test5
mount | grep tank


zfs mount tank/test5
mount | grep tank




change the "mountpoint" property
zfs set mountpoint=/mnt/test tank/test


mount | grep tank



Nested Datasets
Datasets don't need to be isolated. 

You can create nested datasets within each other. 
This allows you to create namespaces, 
while tuning a nested directory structure, 
without affecting the other.


maybe you want compression on /var/log, 
but not on the parent /var.


zfs create tank/test/log
zfs list


Additional Dataset Administration





rename the zfs/olddata dataset 
to reflect that its an old copy of the data

zfs rename zfs/olddata zfs/newdata
zfs list






zfs create -o mountpoint=/mnt/vztmp rpool/vztmp
zfs set acltype=posixacl rpool/vztmp


Copy the partition table from /dev/sda to /dev/sdb:
sgdisk --replicate=/dev/sdb /dev/sda


Ensure the GUIDs are randomized 
otherwise the kernel and ZFS will get really, really confused:
sgdisk --randomize-guids /dev/sdb











zfs-import-cache.service
zfs-mount.service

zfs-share.service
zfs-import.target















