#!/bin/bash
##-------------------------------------------------------##
## GrubPermissionsAudit.sh
##-------------------------------------------------------##
## Audit the permissions set for the system's 
## boot loader (grub)'s configuration files.
##-------------------------------------------------------##
## If its a security concern, fix that shit NOW! 
## Don't ignore it like a bitch!
##------------------------------------------------------##

echo "##-=========================================================-##"
echo "     [+] Check the group-ownership of the grub.conf file:"
echo "##-=========================================================-##"

ls -lLd /boot/grub/grub.conf
stat -c %G /boot/grub/grub.conf

echo "##-=========================================================================-##"
echo "    [?] If the group-owner of the file is not root, this must be changed		 "
echo "    [?] Fix: Change the group-ownership of the file.							 "
echo "##-=========================================================================-##"
chgrp root /boot/grub/grub.conf   


echo "##-============================================-##"
echo "     [+] Check the ownership of the file.:		"
echo "##-============================================-##"


ls -lLd /boot/grub/grub.conf

stat -c %U /boot/grub/grub.conf

echo "##-====================================================================-##"
echo "    [?] If the owner of the file is not root, this must be changed		"
echo "    [?] Fix: Change the ownership of the file.							"
echo "##-====================================================================-##"
chown root /boot/grub/grub.conf   



if [ -a "/boot/grub/grub.conf" ]; then
	OWNER=`stat -c %U /boot/grub/grub.conf`;
	if [ "$OWNER" != "root" ]; then
		chown root /boot/grub/grub.conf
	fi
fi


echo "##-=====================================================================================-##"
echo "##---------------------------------------------------------------------------------------##"
echo "   [?] Strict File permissions on the boot loader config files is critical!				 "
echo "   [?] Anything higher then 0600 is unacceptable!								 			 "
echo "##---------------------------------------------------------------------------------------##"
echo "   [?] A person with malicous intent could modify your systems boot parameters.		 	 "
echo "   [?] You would be pwned at a low level, possibly unaware of the boot time MITM.			 "
echo "##---------------------------------------------------------------------------------------##"
echo "##-=====================================================================================-##"


echo "##-================================================-##"
echo "   [+] Checking /boot/grub/grub.conf permissions...	"
echo "##-================================================-##"


if [ -a "/boot/grub/grub.conf" ]; then
	GRUBPERM=`stat -L --format='%04a' /boot/grub/grub.cfg`
	ls -lL /boot/grub/grub.conf

chmod u-xs,g-rwxs,o-rwxt /boot/grub/grub.conf













Securing /etc/grub.conf 

enter the Grub shell, execute the md5crpyt and copy the ciphertext over to the .conf file.

puppy# grub
grub> md5crypt
Password: ********
Encrypted: $1$2FXKzQ0$I6k7iy22wB27CrkzdVPe70
grub> quit





add another parameter to the password option which is authenticated by your password, 
allowing only the admin access specialized kernels or boot boot options.



password --md5 $1$2FXKzQ0$I6k7iy22wB27CrkzdVPe70 /boot/grub/administrator-menu.lst



Grub allows you to protect a specific boot entry by specifying a lock directly after the title in the grub.conf File

default=1
timeout=10
splashimage=(hd0,0)/grub/splash.xpm.gz
password --md5 $1$2FXKzQ0$I6k7iy22wB27CrkzdVPe70
title Red Hat Linux (2.6.7)
lock
root (hd0,0)
kernel /vmlinuz-2.6.7 ro root=LABEL=/
initrd /initrd-2.6.7.img



chown root:root /etc/grub.conf
chmod 0600 /etc/grub.conf

/boot/grub2/grub.cfg
/boot/grub/menu.lst
/boot/grub/grub.cfg



echo "########################################################"
## Backup Grub to a disk ##
echo "########################################################"
cd /tmp
grub-mkrescue --output=grub-img.iso
dd if=grub-img.iso of=/dev/fd0 bs=1440 count=1
##############################################################
grub-mkdevicemap --device-map=device.map
cat device.map
echo "########################################################"








