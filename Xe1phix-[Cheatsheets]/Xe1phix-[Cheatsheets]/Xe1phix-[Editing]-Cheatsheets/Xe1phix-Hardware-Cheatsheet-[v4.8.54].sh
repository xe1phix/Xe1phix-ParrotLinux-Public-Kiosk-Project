

alias du='du --human-readable --all --apparent-size --separate-dirs'
(du --human-readable --all --apparent-size --separate-dirs) > du.txt
(sfdisk --show-size; sfdisk --show-pt-geometry; sfdisk --show-geometry) > sfdisk-dump.txt

##-==============================================================-##
##  [+] 

udevadm info -a -n /dev/sda
udevadm info /sys/class/net/eth0
udevadm info /sys/class/net/wlan0

udevadm trigger --action=add
udevadm control --reload-rules

lsusb
lsdev
lshw
lsipc
lsdev
hddtemp /dev/sdb
smartctl -x /dev/sdb
hwinfo --short
hwinfo --block --short                  ##  Show all detected mountable Drives/Partitions/BlockDevices
lshw -class storage
lshw -class disk -class storage
lshw -html -class network

lsblk --topology --all --paths --fs
lsblk --all --perms --list
lsblk --all --perms --topology --fs --raw

lsblk -o KNAME,TYPE,FSTYPE,SIZE,LABEL
lsblk -o KNAME,ROTA,RO,RM,STATE,MOUNTPOINT

lscpu
lspci
lsscsi


dmidecode --dump >> $TEMP_DIR/dmidump.txt
dmidecode --dump-bin dmibin.bin
dmidecode --from-dump dmibin.bin

$sfdisk=sfdisk --show-size --show-pt-geometry --show-geometry

sfdisk /dev/sda -O hdd-partition-sectors.save   ## save the sectors layout with sfdisk
sfdisk /dev/sda -I hdd-partition-sectors.save   ## recover the old sectors with backup


sfdisk -dx /dev/hda > $PartInfo.txt    ## Fetch partition table information:
/lib/systemd/system/systemd-rfkill.service
/lib/systemd/systemd-rfkill
/lib/udev/rules.d/61-gnome-settings-daemon-rfkill.rules


sfdisk --backup /dev/sda                    ## full (binary) backup - all sectors where the partition table is stored


sfdisk --dump /dev/sda > sda.dump           ## save desc of device layout to a text file.
sfdisk /dev/sda < sda.dump                  ## later restored by:

sfdisk –d /dev/sda > sda-table              ## Back up partition table to file
sfdisk /dev/sda < sda-table                 ## Restore partition table from file
sfdisk –d /dev/sda | sfdisk /dev/sdb        ## Copy partition table from disk to disk


nvme smart-log /dev/nvme1           ## View the nvmes internal smart log.
nvme id-ctrl /dev/nvme1 -H          ## check # of namespaces supported and used
nvme id-ns /dev/nvme0n1             ## check the size of the namespace
nvme-get-ns-id



dd if=/dev/zero of=/dev/hda bs=446 count=1							## blank your boot code
dd if=/dev/zero of=/dev/hda bs=512 count=1							## clear the complete MBR + partition table:
dd if=/dev/hda of=/home/knoppix/mbr_backup bs=512 count=1			## Save the MBR
dd if=/home/knoppix/mbr_backup of=/dev/hda bs=446 count=1			## restores the boot code in the MBR.
dd if=mbr_backup of=/dev/hda bs=512 count=1							## restore the full 512 bytes to the MBR with:


blockdev --setro /dev/sd            ## Set read-only
blockdev --setrw                    ## Set read-write.
blockdev --getbsz /dev/sda1         ## Print blocksize in bytes
blockdev --report



cat /sys/block/sda/queue/logical_block_size
cat /sys/block/sdc/queue/logical_block_size

cat /sys/block/sda/queue/physical_block_size
cat /sys/block/sdc/queue/physical_block_size

blockdev --getpbsz /dev/sda
blockdev --getpbsz /dev/sdc

blockdev --getss /dev/sda
blockdev --getss /dev/sdc


##-======================================================================================-##
##   specifying the 4096-byte sector size with the -b flag, the sectors of
##   the Linux partition are represented as 4K units, and there is no unallocated
##   area at the end of the drive.
##-======================================================================================-##
mmls -b 4096 /dev/sde




pvdisplay --columns --all --verbose         ## displaying the attributes of a physical volume
vgdisplay --verbose                         ## displaying the attributes of volume groups
lvdisplay                                   ## displays the attributes of a logical volume
vgck --verbose                              ## checking the volume group metadata
lvmdump                                     ## creates lvm2 information dumps for diagnostic purposes
lvmdiskscan                                 ## scans for all the devices visible to lvm2


blkid -U                        ## Print the name of the specified partition, given its UUID:
findfs UUID=                    ## Print the name of the specified partition, given its UUID:
blkid -L                        ## Print the UUID of the specified partition, given its label:
findfs LABEL=                   ## Print the name of the specified partition, given its label:

parted --list
partprobe --summary
parted /dev/sda print
findmnt --fstab --evaluate
showmount --all


watch -n 1 cat /proc/softirqs
watch -n 1 cat /proc/interrupts 
hdparm ‐i /dev/sda                ## Drive information by kernel drivers at the system boot time
hdparm ‐I /dev/sda                      ## Display drive information taken directly from the drive itself:
hdparm -g /dev/hda                          ## Display drive geometry (cylinders, heads, sectors) 

hdparm -r1 /dev/sda                 ## set a disk to read-only by setting a kernel flag

hdparm -t /dev/sda                      ## Performs & Displays Hard Drive Read Timings:	
hdparm -T /dev/sda                        ## Performs & Displays Device Cache Read Timings:
hdparm -H /dev/sda                  ## Read the temperature

cpufreq-info --debug

dumpe2fs -h /dev/sda1

## ------------------------------------------------------------------------------------------------- ##
    smartctl -a /dev/sda 			        ## Print SMART information for drive /dev/sda
## ------------------------------------------------------------------------------------------------- ##
    smartctl -s on --saveauto=on -t offline /dev/sda		## Disable SMART monitoring and log collection for drive /dev/sda
## ------------------------------------------------------------------------------------------------- ##
    smartctl -t long /dev/sda		        ## Begin an extended SMART self-test on drive /dev/sda
## ------------------------------------------------------------------------------------------------- ##
    smartctl -q errorsonly -H -l selftest /dev/sda
## ------------------------------------------------------------------------------------------------- ##
    smartctl -l error /dev/sda              ## View devices error logs
## ------------------------------------------------------------------------------------------------- ##
    smartctl -H /dev/sda			        ## Overall health report on the device
## ------------------------------------------------------------------------------------------------- ##
    smartctl -i /dev/sda			        ## details on a specific device
## ------------------------------------------------------------------------------------------------- ##
    smartctl --scan
## ------------------------------------------------------------------------------------------------- ##
    smartctl -x	/dev/sda                    ## smartctl --xall
## ------------------------------------------------------------------------------------------------- ##
    smartctl -c	/dev/sda                    ## smartctl --capabilities
## ------------------------------------------------------------------------------------------------- ##
    smartctl -A /dev/sda                    ## smartctl --attributes 
## ------------------------------------------------------------------------------------------------- ##
    smartctl -P showall | less              ## Show which devices are supported
## ------------------------------------------------------------------------------------------------- ##


killall -HUP smartd




smartctl --scan | grep "${DEVICE}" | cut -d' ' -f3)
smartctl --smart=on --offlineauto=on --saveauto=on /dev/sda						## (Enables SMART on first disk)


smartd -d -i 30                 ## Run in foreground (debug) mode, checking the disk status every 30 seconds.
smartd -q onecheck              ## Registers devices, and checks the status of the devices exactly once.
killall -HUP smartd             ## re-read the configuration file
kill -SIGUSR1 <pid>
kill -SIGUSR1 (pgrep smartd)
killall -USR1 smartd

