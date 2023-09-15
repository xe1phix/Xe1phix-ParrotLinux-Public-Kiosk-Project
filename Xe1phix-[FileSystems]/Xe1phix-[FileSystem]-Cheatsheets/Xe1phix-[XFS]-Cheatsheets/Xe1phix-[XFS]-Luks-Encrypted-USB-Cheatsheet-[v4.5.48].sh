#!/bin/sh
##-=======================================================-##
##   [+] Xe1phix-[XFS]-Luks-Encrypted-USB-Cheatsheet.sh
##-=======================================================-##



echo "## ======================================================================= ##"
echo "     [+] Initialize the LUKS encryption on the newly-created partition."
echo "## ======================================================================= ##"
cryptsetup --verbose --verify-passphrase luksFormat /dev/sdd1
cryptsetup luksOpen /dev/sdd1 LUKS


echo "## ======================================================= ##"
echo "     [+] Create An XFS Filesystem, and label it LUKS:"
echo "## ======================================================= ##"
mkfs.xfs -L persistence /dev/mapper/LUKS


echo "## ======================================================================= ##"
echo "      [x] Create a mount point"
echo "      [x] Mount our new encrypted partition"
echo "      [x] Set up the persistence.conf file"
echo "      [x] Unmount the partition. "
echo "## ======================================================================= ##"
mkdir -v --mode=0755 /mnt/LUKS
mount /dev/mapper/LUKS /mnt/LUKS
echo "/ union" > /mnt/LUKS/persistence.conf


echo "## ============================================ ##"
echo "      [+] Status of the mapping (ParrotSec) "
echo "## ============================================ ##"
cryptsetup status /dev/mapper/LUKS

echo "## ======================================================== ##"
echo "      [+]  Dump the header information of a LUKS device."
echo "## ======================================================== ##"
cryptsetup luksDump /dev/sdd1


echo "##-=======================================================-##"
echo "      [+] Show All The Logical Volumes & Device Names"
echo "##-=======================================================-##"
lvs -o devices


echo "## ------------------------------------------------------------------------ ##"
echo "      [?] The Encrypted Logical Volumes Are Mounted At Boot Time        "
echo "          Using The Information From The /etc/crypttab File.          "
echo "## ------------------------------------------------------------------------ ##"
cat /etc/crypttab


echo "## ========================================== ##"
echo "      [+] Print the UUID of a LUKS device."
echo "## ========================================== ##"
cryptsetup luksUUID /dev/sdd1


echo "## ======================================== ##"
echo "      [+] Add a Nuke Slot to /dev/sda1: "
echo "## ======================================== ##"
cryptsetup luksAddNuke /dev/sdd1

echo "## ================================================= ##"
echo "      [+] Check if the Nuke Slot has been added:"
echo "## ================================================= ##"
cryptsetup luksDump /dev/sdd1

echo "##-======================================-##"
echo "      [+] Check If It's A LUKS Device:"
echo "##-======================================-##"
cryptsetup isLuks /dev/sdd3


echo "## ------------------------------------------------------------------------ ##"
echo "      [?] Stores a binary backup of the LUKS header and keyslot area."
echo "## ------------------------------------------------------------------------ ##"
cryptsetup luksHeaderBackup --header-backup-file luksheader.back /dev/sdd1

cryptsetup luksHeaderBackup --header-backup-file /mnt/LUKS/luksheader.back /dev/sdd1


echo "## ====================================================== ##"
echo "     [+] Restores a binary backup of the LUKS header "
echo "     [+] and keyslot area from the specified file."
echo "## ====================================================== ##"
cryptsetup luksHeaderRestore /dev/sdd1 --header-backup-file luksheader.back


echo "## ==================================================== ##"
echo "      [+] Print LUKS Header File Type & Attributes: "
echo "## ==================================================== ##"
file luksheader.back



echo "## ======================================================= ##"
echo "      [+] Encrypt The LUKS Header Backup With OpenSSL:"
echo "## ======================================================= ##"
openssl enc -aes-256-cbc -e -salt -in $Key -out $File
openssl enc -aes-256-cbc -salt -in luksheader.back -out luksheader.back.enc



echo "## ============================================= ##"
echo "      [+] List Both The Header Backup Files: "
echo "## ============================================= ##"
ls -lh luksheader.back*


echo "## =================================================================== ##"
echo "     [+] Cross Examine The Unencrypted Header Vs The Encrypted One"
echo "## =================================================================== ##"
file luksheader.back*


echo "## ===================================================== ##"
echo "     [+] Decrypt The OpenSSL Encrypted LUKS Header:"
echo "## ===================================================== ##"
openssl enc -d -aes-256-cbc -in luksheader.back.enc -out luksheader.back


echo "## ====================================================================== ##"
echo "     [+] Copy This Script To The Persistent Partition For Future Use:"
echo "## ====================================================================== ##"
cp -v infosectalk-Brown/GnuPG-CryptoPartyWorkshop/XFS-LUKSEncryptedUSB.sh /mnt/LUKS/



echo "## =================================================================== ##"
echo "     [+] Unmount the partition. "
echo "     [+] Close the encrypted channel to our persistence partition."
echo "## =================================================================== ##"
umount /dev/mapper/LUKS
cryptsetup luksClose /dev/mapper/LUKS





