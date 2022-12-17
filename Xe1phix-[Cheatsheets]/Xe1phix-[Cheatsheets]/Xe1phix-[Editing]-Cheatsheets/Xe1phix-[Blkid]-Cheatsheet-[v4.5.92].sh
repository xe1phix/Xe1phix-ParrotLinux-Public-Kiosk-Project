#!/bin/sh


echo "##-============================================-##"
echo "     [+] Display I/O topology information"
echo "##-============================================-##"
blkid --info /dev/$Disk


echo "##-=================================================================-##"
echo "     [+] Print the name of the specified partition, given its UUID "
echo "##-=================================================================-##"
blkid -U 652b786e-b87f-49d2-af23-8087ced0c667


echo "##-====================================================-##"
echo "     [+] Print the UUID of the specified partition		 "
echo "##-====================================================-##"
blkid -L /boot


echo "##-====================================================-##"
echo "     [+] Print the device of the specified UUID"
echo "##-====================================================-##"
blkid -o device -t UUID="$1"


echo "##-=========================================-##"
echo "     [+] List the UUID devices directory:"
echo "##-=========================================-##"
ls -l /dev/disk/by-uuid/


echo "##-====================================================-##"
echo "     [+] Probes for vfat, ext3 and ext4 filesystems"
echo "##-====================================================-##"
blkid --probe --match-types vfat,ext3,ext4 /dev/sda1


echo "##-====================================-##"
echo "     [+] Probes for all filesystem:"
echo "##-====================================-##"
blkid --probe --usages filesystem,other /dev/sda1


echo "##-====================================================-##"
echo "     [+] Print the device of the specified label"
echo "##-====================================================-##"
blkid -o device -t LABEL="$1"


echo "##-===================================================-##"
echo "     [+] List the directory containing disk labels:"
echo "##-===================================================-##"
ls -l /dev/disk/by-label/
echo "$1" | grep -q "LABEL="
echo "$1" | cut -d = -f 2



