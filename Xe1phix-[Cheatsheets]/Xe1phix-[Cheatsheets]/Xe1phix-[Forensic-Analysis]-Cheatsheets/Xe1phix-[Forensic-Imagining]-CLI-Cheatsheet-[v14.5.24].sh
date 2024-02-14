
TCT (The Coroner’s Toolkit)


















echo "## ##################################### ###"
echo "## Acquiring physical memory with dc3dd. ##"
echo "## ##################################### ###"
┌─[root@parrot]
└──╼ $ /media/cdrom/Linux-IR/dc3dd if=/dev/mem >/media/IR/memory/host.physicalmem

echo "## ########################################## ###"
echo "## Using memdump to acquire physical memory.  ##"
echo "## ########################################## ###"
┌─[root@parrot]
└──╼ $ /media/cdrom/Linux-IR/memdump > /media/IR/memory/host.memdump

echo "## ################################################ ###"
echo "## Acquiring the contents of /proc/kcore with dc3dd ###"
echo "## ################################################ ###"
┌─[root@parrot]
└──╼ $ /media/cdrom/Linux-IR/dc3dd if=/proc/kcore of=/media/IR/memory/host.kcore




echo "## ########################################## ###"
echo "## 	##"
echo "## ########################################## ###"

┌─[root@parrot]
└──╼ $ /media/cdrom/Linux-IR/insmod /media/cdrom/Linux-IR/lime.ko

┌─[root@parrot]
└──╼ $ “path=/media/IR/memdump-lime.bin format=padded”










/media/cdrom/Linux-IR/dc3dd if=/dev/hda
of=/media/IR/victim13.dd log=/media/IR/audit/victim13.log
hash=md5 hlog=/media/IR/audit/victim13.md5






echo "## ==================================================================== ##"
echo "## ==========  ========== ##"
echo "## ==================================================================== ##"
sudo dd if=/dev/hda of=/mnt/recovery/hdaimage.dd

echo "## ==================================================================== ##"
echo "## ==== dd will abort on error. Avoid this with the noerror option ==== ##"
echo "## ==================================================================== ##"
sudo dd conv=noerror if=/dev/hda of=/mnt/recovery/hdaimage.dd


echo "## ==================================================================== ##"
echo "## ============= grab most of the error-free areas ==================== ##"
echo "## ==================================================================== ##"
gddrescue -n /dev/hda /mnt/recovery/hdaimage.raw rescued.log

echo "## ==================================================================== ##"
echo "## ====== Once you have your bit-for-bit copy, run fsck on it: ======== ##"
echo "## ==================================================================== ##"
fsck /mnt/recovery/hdaimage.dd


echo "## ==================================================================== ##"
echo "## ============ mount the image as a loopback device: ================= ##"
echo "## ==================================================================== ##"
mount -o loop /mnt/recovery/hdaimage.dd /mnt/hdaimage

echo "## ==================================================================== ##"
echo "## ========= Find out where the partitions are with this: ============= ##"
echo "## ==================================================================== ##"
fdisk -lu /mnt/recovery/hdaimage.dd

echo "## =============================================================================== ##"
echo "## which will list the start and end cylinders of each partition and the units in  ##"
echo "## which they’re measured. If the second partition starts at cylinder 80300 and    ##"
echo "## the units are 512 bytes, then that partition starts at 80300 × 512 = 41,113,600 ##"
echo "## 		bytes. In this case, the command you want looks like this: 				 ##"
echo "## =============================================================================== ##"
mount -o loop,offset=41113600 /mnt/recover/hdaimage.raw /mnt/hdaimage

echo "## ==================================================================== ##"
echo "## ============== write the image back onto another disk ============== ##"
echo "## ==================================================================== ##"
dd if=/mnt/recovery/hdaimage.raw of=/dev/hdb		










Imaging a device to a set of CD-sized output files with generation of
md5 and and sha1 hashes of the device:

dc3dd if=/dev/sda ofs=suspect.img.000 ofsz=650M hash=md5 hash=sha1 log=suspect.txt

Imaging a device to both a single output file and to a set of CD-sized
output files with generation of md5 and sha1 hashes of the device:

dc3dd if=/dev/sda of=suspect.img of=suspect.img ofs=suspect.img.000 ofsz=650M hash=md5 hash=sha1 log=suspect.txt

Imaging a device to both a single output file and to a set of CD-sized
output files with generation of md5 and sha1 hashes of the device
and md5 and sha1 hashes of the outputs:

dc3dd if=/dev/sda of=suspect.img hof=suspect.img hofs=suspect.img.000 ofsz=650M hash=md5 hash=sha1 log=suspect.txt

Restoring a set of image files to a device with verification hashes of
only the bytes dc3dd writes to the device:
dc3dd ifs=suspect.img.000 phod=/dev/sdb hash=md5 hash=sha1 log=suspect-restore.txt

Restoring a set of image files to a device with verification hashes of
both the bytes dc3dd writes to the device and the entire device:
dc3dd ifs=suspect.img.000 fhod=/dev/sdb hash=md5 hash=sha1 log=suspect-restore.txt


echo -e "\t\t Wiping a drive:"
echo "________________________________________________"
dc3dd wipe=/dev/sdb log=wipe.txt



echo "################################################"
echo -e "\t\t Wiping a drive with verification:"
echo "________________________________________________"
dc3dd hwipe=/dev/sdb hash=md5 hash=sha1 log=wipe.txt
echo "________________________________________________"
echo "################################################"



dc3dd if=/dev/sda of=suspect.img hash=md5 hash=sha1 log=suspect.txt







Sleuthkit and the Coroner’s Toolkit


mount –o ro /dev/hda1 /mnt/hda1
mount -o rw /dev/hdb1 /mnt/hdb1
mkdir /mnt/hdb1/data
script /mnt/hdb1/grave-robber-output

grave-robber -c /mnt/hda1 -o LINUX2 -d /mnt/hdb1/data -v

cd /mnt/hdb1/data









the Sleuthkit command-line tools:
• ils lists inode information from the image.
• ffind finds the file or directory name using the inode.
• icat outputs the file content based on its inode number.


use ffind to get the file/directory name, and then output the
content with icat once you establish whether you’re looking at a file or a directory.


output to the directory from where you ran it:
foremost image.dd

write them to a specified output directory:
foremost -t all -o /rescue/dir -i image.dd





list the files and directory names in a
particular image:
fls hdaimage.dd -r -f ext3 -i raw


r/r * 10: myfile.txt

r/r at the start of the line gives the directory entry type value and the file type (r means regular
file; d is a directory). As a rule, these will match. * indicates that it’s been deleted, and 10 is the inode
number.





retrieve the contents of this file:
icat -r -f ext3 -i raw hdaimage.dd 10 > myfile.txt


Use the sorter script to look for particular types of file

sorter -f ext3 -C /usr/local/sleuthkit/share/sort/images.sort 
-d data/sortedimages -h -s hdaimage.dd	
