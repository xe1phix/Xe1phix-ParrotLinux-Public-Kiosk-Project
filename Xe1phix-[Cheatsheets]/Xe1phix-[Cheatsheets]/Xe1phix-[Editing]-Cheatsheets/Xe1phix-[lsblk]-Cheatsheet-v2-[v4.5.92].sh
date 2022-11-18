

lsblk -f -> when used with the -f option, it prints file system type on partitions 
sudo file -sL /dev/sdb1 -> file system type on partitions
lsblk -f
lsblk -l
lsblk --scsi
lsblk -o name,type,fstype,label,partlabel,model,mountpoint,size
lsblk --json | jq -c '.blockdevices[]|[.name,.size]'

#/etc/fstab explained, Each field can be separated by another either by spaces or tabs

First field – The block device,reference a block device is by using its LABEL or UUID (Universal Unique IDentifier)
$ lsblk -d -fs /dev/sdb1 # get UUID

Second field – The mountpoint
Third field – The filesystem type
Fourth field – Mount options, use the default set of mount options we specify default as a value
Fifth field – Should the filesystem be dumped?, either 0 or 1,used by the dump backup program (if installed)

Sixth field – Fsck order;fsck utility, should check filesystems on boot;
value of 1 must always be used for the root filesystem
if not  root filesystem,for all the others, value of  2
If not provided it defaults to 0


# generate traces of the i/o traffic on block devices 
"sudo blktrace -d /dev/sda -o - | blkparse -i -"

