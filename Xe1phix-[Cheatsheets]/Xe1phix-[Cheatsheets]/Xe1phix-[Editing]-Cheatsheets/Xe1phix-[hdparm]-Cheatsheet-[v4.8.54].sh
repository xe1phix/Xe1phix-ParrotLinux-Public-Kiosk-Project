#!/bin/sh


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


