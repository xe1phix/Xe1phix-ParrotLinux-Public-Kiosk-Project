#!/bin/bash



##-====================================================================-##
##   [+] Clone a partition from physical disk /dev/sda, partition 1,
##       to physical disk /dev/sdb, partition 1 with e2image, run
##-========================================================================-##
e2image -ra -p /dev/sda1 /dev/sdb1


##-=======================================================-##
##   [+] Clone a faulty or dying drive, run ddrescue twice.
##       First round, copy every block without read error
##       and log the errors to rescue.log.
##-=======================================================-##
ddrescue -f -n /dev/sda /dev/sdb rescue.log



##-=======================================================-##
##   [+] Copy only the bad blocks and try 3 times
##       to read from the source before giving up.
##-=======================================================-##
ddrescue -d -f -r3 /dev/sdX /dev/sdY rescue.log



##-========================================-##
##   [+] Clone or rescue a block device
##-========================================-##
ddrescue -v /dev/sda /dev/sdb logfile.log



##-========================================================================-##
##   [+]
##-========================================================================-##
gddrescue -n /dev/hda /mnt/recovery/hdaimage.raw rescued.log



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



##-========================================================================-##
##   [+] Use ddrescue, skipping the dodgy areas
##       grab most of the error-free areas quickly
##-========================================================================-##
gddrescue -n /dev/sda /mnt/recovery/$Image.raw rescued.log



##-========================================================================-##
##   [+] Mount the image as a loopback device:
##-========================================================================-##
mount -o loop /mnt/recovery/$Image.dd /mnt/$Image


