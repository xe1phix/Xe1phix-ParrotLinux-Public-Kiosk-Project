#!/bin/bash
###########################
## Volatiliously-bro.sh	##
##########################


$ sudo insmod lime.ko "path=/mnt/externaldrive/memdmp.lime format=lime"

$ sudo insmod lime.ko "path=tcp:4444 format=lime"

$ nc 192.168.1.40 4444 > memdmp.lime




echo "########################################################"
echo ""
echo "########################################################"
dwarfdump -di module.ko > module.dwarf





$ python vol.py --profile=LinuxDebian-3_2x64 -f debian.lime linux_psaux


$ python vol.py --profile=LinuxDebian-3_2x64 -f hiddenargs.lime
linux_psaux -p 24896

$ python vol.py --profile=LinuxDebian-3_2x64 -f hiddenargs.lime
linux_pslist -p 24896

$ python vol.py --profile=LinuxDebian-3_2x64 -f hiddenargs.lime
linux_proc_maps -p 24896

$ python vol.py --profile=LinuxDebian-3_2x64 -f debian.lime linux_psenv




echo "########################################################"
echo ""
echo "########################################################"
$ python vol.py --info | grep Linux

echo "########################################################"
echo ""
echo "########################################################"
$ python vol.py --profile=LinuxFedora17x64 -f /path/to/memory/sample linux_pslist

echo "########################################################"
echo ""
echo "########################################################"
$ python vol.py --profile=LinuxDebian-3_2x64 -f debian.lime linux_proc_maps -p 1

echo "########################################################"
echo ""
echo "########################################################"
$ python vol.py --profile=LinuxDebian-3_2x64 -f debian.lime linux_dump_map
		-p 1 -s 0x400000 -D dump


echo "########################################################"
echo ""
echo "########################################################"
$ file dump/task.1.0x400000.vma


echo "########################################################"
echo ""
echo "########################################################"
$ python vol.py --profile=LinuxDebian-3_2x64 -f debian.lime linux_psaux

echo "########################################################"
echo ""
echo "########################################################"
$ python vol.py --profile=LinuxSuse-2_6_26x64 -f infected.lime
	linux_psaux -p 27394

echo "########################################################"
echo ""
echo "########################################################"
$ python vol.py --profile=LinuxDebian-3_2x64 -f hiddenargs.lime
	linux_psaux -p 24896

echo "########################################################"
echo ""
echo "########################################################"
$ python vol.py --profile=LinuxDebian-3_2x64 -f hiddenargs.lime
	linux_pslist -p 24896

echo "########################################################"
echo ""
echo "########################################################"
$ python vol.py --profile=LinuxDebian-3_2x64 -f hiddenargs.lime
	linux_proc_maps -p 24896


echo "########################################################"
echo ""
echo "########################################################"
$ python vol.py --profile=LinuxDebian-3_2x64 -f debian.lime linux_psenv


echo "########################################################"
echo ""
echo "########################################################"
$ python vol.py --profile=LinuxDebian-3_2x64 -f debian.lime linux_lsof -p 8643



echo "########################################################"
echo "analyzes opened file handles of an SSH client:"
echo "########################################################"
$ python vol.py --profile=LinuxDebian-3_2x64 -f debian.lime linux_lsof -p 2745



echo "########################################################"
echo "analyzing the process’ network connections with linux_netstat"
echo "########################################################"
$ python vol.py --profile=LinuxDebian-3_2x64 -f debian.lime
	linux_netstat -p 2745



echo "########################################################"
echo "shows the file descriptors of a Linux key logger "
echo "########################################################"
$ python vol.py --profile=LinuxDebian-3_2x64 -f keylog.lime
	linux_pslist | grep logkeys

echo "########################################################"
echo ""
echo "########################################################"
$ python vol.py --profile=LinuxDebian-3_2x64 -f keylog.lime
	linux_psaux -p 8625


echo "########################################################"
echo ""
echo "########################################################"
$ python vol.py --profile=LinuxDebian-3_2x64 -f keylog.lime
	linux_lsof -p 8625


echo "########################################################"
echo ""
echo "########################################################"
python vol.py --profile=Linuxdfrws-profilex86 -f challenge.mem
linux_bash -p 2585




echo "########################################################"
echo "Detecting the Fake Binary"
echo "########################################################"
python vol.py --profile=LinuxDebian-3_2x64 -f backdooredrm.lime
	linux_bash_hash -p 23971

echo "########################################################"
echo ""
echo "########################################################"
python vol.py --profile=LinuxDebian-3_2x64 -f backdooredrm.lime
	linux_bash_env -p 23971


echo "########################################################"
echo "listening for TCP and UDP connections:"
echo "########################################################"
$ python vol.py --profile=LinuxDebian-3_2x64 -f debian.lime linux_netstat


echo "########################################################"
echo ""
echo "########################################################"
python vol.py --profile=LinuxDebian-3_2x64 -f nmap.lime
	linux_netstat > netstat.txt



echo "########################################################"
echo "The following shows output from the linux_netstat plugin for select Unix sockets:"
echo "########################################################"
$ python vol.py --profile=LinuxDebian-3_2x64 -f debian.lime linux_netstat



echo "########################################################"
echo "output of the  plugin on the Debian memory sample:"
echo "########################################################"
$ python vol.py --profile=LinuxDebian-3_2x64 -f debian.lime
	linux_pkt_queues -D output

echo "########################################################"
echo ""
echo "########################################################"
$ python vol.py --profile=LinuxDebian-3_2x64 -f debian.lime linux_pslist -p 1851


echo "########################################################"
echo "output from linux_ifconfig on the Debian memory sample:"
echo "########################################################"
$ python vol.py --profile=LinuxDebian-3_2x64 -f debian.lime linux_ifconfig


echo "########################################################"
echo "output from the same system with tcpdump running and an aliased interface use"
echo "########################################################"
python vol.py --profile=LinuxDebian-3_2x64 -f tcpdump.lime linux_ifconfig


echo "########################################################"
echo "shows that tcpdump and dhclient have raw sockets open. "
echo "########################################################"
python vol.py --profile=LinuxDebian-3_2x64 -f tcpdump.lime linux_list_raw



echo "########################################################"
echo "determine what is occupying the interface and using raw sockets"
echo "########################################################"
python vol.py --profile=LinuxDebian-3_2x64 -f tcpdump.lime linux_psaux -p 3796







echo "########################################################"
echo ""
echo "########################################################"
$ volatility pslist -f memory.img

echo "########################################################"
echo ""
echo "########################################################"
$ volatility psscan2 -f memory.img

echo "########################################################"
echo "extract the list of .EXEs from each command and diff them"
echo "########################################################"
$ volatility pslist -f memory.img | tail -n +2 | awk '{print $1}' | sort

echo "########################################################"
echo "awk to extract the name of the .EXE from the first column"
echo "and finally pipe the whole thing into sort"
echo "########################################################"
$ volatility psscan2 -f memory.img | tail -n +4 | awk '{print $NF}' | sort

echo "########################################################"
echo ""
echo "########################################################"
diff <(volatility psscan2 -f memory.img | tail -n +4 | awk '{print $NF}' | sort) \
	<(volatility pslist -f memory.img | tail -n +2 | awk '{print $1}' | sort)









• raw (Single raw file (dd))
• Advanced Forensic Format (AFF)
	> 
• afd (AFF Multiple File)
• afm (AFF with external metadata)
• afflib (All AFFLIB image formats (including beta ones))
• ewf (Expert Witness format (encase))
	> EWF format supports metadata, compression, encryption, hashing, split files, and more

• split (Split raw files)



udevadm monitor
udevadm info /dev/




## Supported image format types:
img_stat -i list








• Mass storage controller class (class ID 01)
• SATA mass storage controller (class ID 01, subclass ID 06)
• serial bus controller class (class ID 0C)
• USB serial bus controller class (class ID 0C, subclass ID 03)

DCO ( Device Configuration Overlay feature set )






Document Device Identification Details

• Vendor, make, and model
• Serial number or WWN
• Linux device name
• PCI domain:bus:slot.function
• PCI vendorID:deviceID
• USB bus:device
• USB vendorID:productID
• SCSI host:channel:target:lun




## check the CPU family and model, current and maximum speed,
## number of cores and threads, and other flags and characteristics
dmidecode -t processor


dmidecode -t memory				## view the memory, including slots used, size, data width, speed
dmidecode -t slot				## view the number of PCI slots, usage, designation
dmidecode -t cache				## view the CPU’s cache (L1, L2, and L3):

## view the storage interfaces, type (SATA, NVME, SCSI
lshw -class storage

## generate a quick overview of the bus information
lshw -businfo
lshw -businfo -class storage		## specifically look for an attached device type
lshw -businfo -class disk			## 



## list all SATA mass storage controller (class ID 01, subclass ID 06) devices:
lspci -d ::0106


## enumerates all the SCSI, IDE, RAID, ATA, SATA, SAS,
## and NVME mass storage controller devices on a system:
for i in 00 01 04 05 06 07 08; do lspci -d ::01$i; done


## queries the SMART interface for a drive’s temperature is hddtemp
hddtemp /dev/sdb


## detailed output on a disk’s temperature
smartctl -x /dev/sdb


## serial bus controller class (class ID 0C)
lspci -d ::0C03



## lists all devices with the 
## USB serial bus controller class 
## (class ID 0C, subclass ID 03)
lspci -d ::0C03


## enumerates all FireWire, USB, and 
## Fibre Channel serial bus controllers
for i in 00 03 04; do lspci -d ::0C$i; done


echo "grabbing the screen resolution..."
xdpyinfo | awk '/dimensions:/ {print $2}'			# "width x height"


xrandr -q				# 









## retrieve more information by specifying 
## the subject disk’s vendor:productID

lsusb -vd 0781:5583


lsscsi is also useful for linking kernel 
device paths with device files in /dev:
lsscsi -v




prints human-readable timestamps of the kernel ring buffer
dmesg -T



lsblk provides useful technical details, such as the
device name, size, physical and logical sector size
transport (USB, SATA,SAS, and so on), SCSI address
https://en.wikipedia.org/wiki/World_Wide_Name
lsblk -pd -o TRAN,NAME,SERIAL,VENDOR,MODEL,REV,WWN,SIZE,HCTL,SUBSYSTEMS,HCTL



Document evidence for the use of a write blocker.
tableau-parm /dev/sdc > write-blocked.txt


query blockdev for a report on the current 
status of the device (including the read-only flag):
blockdev --report /dev/sda > wrtblk.txt





query device attributes
bus:device (using -s ) 
		or by 
vendor:product (using -d )

lsusb -v -s 2:2 > lsusb.txt
lsusb -v -d 13fe:5200 > lsusb.txt



the -O flag will out- put all available columns in the output:
lsblk -O /dev/sda > lsblk.txt


# specifying the SCSI address to use:
lsscsi -vtg -L 16:0:0:0 > lsscsi.txt




Query Disk Capabilities and Features with hdparm

The hdparm tool operates by sending requests to the OS disk drivers
(using ioctls) to retrieve information about the disk.


document information about the drive,
including manufacturer, model, serial number
hdparm -I /dev/sda




DCO ( Device Configuration Overlay feature set )










retrieve a verbose list of disk parameters
sdparm -a -l

A more concise query:
extract the Vital Product Data (VPD)
sdparm -i



The smartctl command queries attached ATA, SATA, SAS, and SCSI
hardware.


print all identifying information about the drive
smartctl -x /dev/sda


shows the health of the drive and
the results of self-tests




Enable Access to Hidden Sectors

There is no special technique to
image these hidden areas once they’ve been made accessible. They’re sim-
ply disk sectors protected by drive configuration parameters.

Removing the HPA or DCO modifies the drive’s configuration, but it does
not modify its contents.






queries for the features modified by
a DCO:
hdparm --dco-identify /dev/sdl

hdparm -I /dev/sdl


the full sectors will be revealed.
hdparm --dco-restore /dev/sdl

hdparm --yes-i-know-what-i-am-doing --dco-restore /dev/sdl



DCO hidden area’s exact sector offset
which will be
useful when you want to extract only the DCO sectors for separate analysis.













Remove a DCO



tableau-parm -r




Examples of HPA uses
include diagnostic tools, recovery partitions

It’s important to note the HPA hidden area’s exact sec-
tor offset, which will be useful when you want to extract only the HPA sectors
for separate analysis.


detect the existence of an HPA
hdparm -N /dev/sdl


## The result is only temporary; 
## the original HPA will be in place next time you cycle the drive’s power.
hdparm --yes-i-know-what-i-am-doing -N 976773168 /dev/sdl








Drive Service Area Access
Hard disk drives need to store information such as SMART logs, ATA
passwords, bad sector lists, firmware, and other persistent information.
This information is typically stored on the disk platters in reserved, user-
inaccessible sectors called the system area (also known as the service area,
negative sectors, or maintenance sectors)

it’s possible to bypass the standard SATA, USB, or SAS
interfaces and access storage media using debug or diagnostic ports built
into the drive electronics. These interfaces may use serial RS-232/TTL,
JTAG for chip access


Online forums exist that discuss low-level disk access
http://forum.hddguru.com/index.php
http://www.hddoracle.com/index.php
http://www.evidencemagazine.com/index.php?option=com_content&task=view&id=922


Methods of accessing the underlying areas of SSD or flash storage media
include the physical removal (desoldering) of memory chips, sometimes
called chip-off. The memory contents from these chips can then be extracted
and reconstructed into readable blocks of data.

















dcfldd if=/dev/sdb of=./image.raw



## dcfldd command is suspended by pressing CTRL -Z



## The process can also be resumed with
kill -SIGCONT






## A hardware write blocker intercepts drive 
## commands sent to the disk that might modify the data.

## Multifunction drive bay write blocker
https://github.com/ecbftw/tableau-parm/
https://github.com/msuhanov/Linux-write-blocker/
http://www.cftt.nist.gov/software_write_block.htm			## NIST CFTT has performed software write blocker tool tests


## tableau-parm toolcan query the Tableau hardware write blocker for information.


## hdparm and blockdev can set a disk to read-only by setting a kernel flag.
hdparm -r1 /dev/sdk

blockdev --setro /dev/sdk











## SquashFS Forensic Evidence Containers


## a SquashFS container is created, and a regular raw image is produced within it.
sfsimage -i /dev/sde kingston.sfs


## Append additional evidence to a container using sfsimage
sfsimage -a photo.jpg kingston.sfs


## list the contents of a SquashFS forensic evidence container (without mounting it)
sfsimage -l kingston.sfs


## *.sfs file is mounted
sfsimage -m kingston.sfs


## MMLS is like fdisk for raw images:
mmls kingston.sfs.d/image.raw





## unmount the SquashFS container 
sfsimage -u kingston.sfs.d


## list all mounted SquashFS containers.
sfsimage -m






## The image is compressed on the fly 
## without needing any temporary files.


## sfsimage was used to image an 8TB subject disk 
## on an investigator system containing only 2TB of disk space. 
## the resulting compressed SquashFS file was only 1TB.


ls -l bonkers.sfs bonkers.sfs.d/bonkers.raw








## maintain an examiner activity log of completed tasks
## by using a shell alias that redirects 
## a short description into a file with a timestamp:
alias log="echo $2 \`date +%FT%R\` >> ~/examiner.log"


## 
## 



## 
## 


## Snoopy is a preloaded library that functions 
## as a wrapper around the execv() and execve() system calls.
## https:// github.com/ a2o/ snoopy/

fls -p -r /dev/sda1 | grep -i "\.doc$" |wc -l



## Terminal Recorders
script -a -tscript.timing script.output

## view the recording using the scriptreplay
scriptreplay -m1 -tscript.timing script.output


## The tmux terminal multiplexer now supports log-
## ging by using the pipe-pane option
tmux pipe-pane -o -t session_index:window_index.pane_index 'cat >> ~/output .window_index-pane_index.txt'





A file extension should always indicate the format of the content. For
example:
• *.txt can be opened and read using a text editor.
• *.raw is a raw data dump (disk, memory, and so on).
• *.pcap is captured network traffic.
• *.db is a database (possibly a Sleuth Kit file list).
• *.sfs is a SquashFS evidence container.
• *.e01 and *.aff are forensic formats.




When you’re analyzing an extracted file, saving tool output, or making
manual notes, create a text file with the original name and append _.txt to it.

exif photo.jpg_ > photo.jpg_.txt


objdump -x super-updater57.exe_ > super-updater57.exe_.txt



Save Command Output with Redirection


fls /dev/sda1 > fls-part1.txt
fls /dev/sda2 > fls-part2.txt


## redirect stdout and stderr file descriptors to the file.
fls /dev/sda &> fls-part1.txt


## combining stderr and stdin
fls /dev/sda > fls-part1.txt 2>&1

## example of using the time command to run a disk-imaging program:
time dcfldd if=/dev/sdc of=./ssd-image.raw




## Any output piped into ts 
## will have a timestamp appended to each line of output.
(ls -l image.raw; cp -v image.raw /exam/image.raw; md5sum /exam/image.raw) |ts




Some filesystems use metadata to represent a sequence of zeros in a file instead
of actually writing all the zeros to the disk.

Sparse files contain “holes” where
a sequence of zeros is known to exist.


## the file size and the MD5 hash are also identical. However, notice



dd if=/dev/sde of=sparse-image.raw conv=sparse


how the block size used on the filesystem is very different
ls -ls image.raw sparse-image.raw


md5sum image.raw sparse-image.raw




## compress images on the fly during acquisition using piping
## and redirection. For example:
dcfldd if=/dev/sde | gzip > image.raw.gz

















## SquashFS Compressed Evidence Containers
# a raw image file was converted to a compressed SquashFS file:
mksquashfs image.raw image.sfs -comp lzo -noI



## imaging a disk using aimage and
## specifying the LZMA compression algorithm
aimage --lzma_compress --compression=9 /dev/sdj image.aff

## 
## 


## FTK SMART Compressed Format
ftkimager --compress 9 --s01 /dev/sdj image



## EnCase EWF Compressed Format
## The ewfacquire tool provides flags to control compression 
## during the acquisition process.
ewfacquire -c bzip2:best -f encase7-v2 /dev/sdj



## 
## 



## 
## 







acquiring an image with dd, compressing
it with gzip, and splitting it into CD-sized chunks:
# dd if=/dev/sdb | gzip | split -d -b 640m - image.raw.gz.




break an existing image into DVD-sized chunks:
$ split -d -b 4G image.raw image.raw.







## use dcfldd to acquire an image using the split=16G flag
dcfldd if=/dev/sdc split=16G of=image.raw

## 



## 



## 
dc3dd if=/dev/sdh ofsz=640M ofs=image.raw.000







## acquire a disk to a split EnCase image using ewfacquire by specifying a
maximum segment file size using the -S flag:

ewfacquire -S 2G /dev/sdc



## EnCase forensic suite - save an image into parts during acquisition
ftkimager /dev/sdk image --frag 20GB --s01













## EWF image is split into 54 pieces
img_stat image.E01



## check for sets of split files:
$ mmls image.raw.000






## split raw image into 3 parts:
fls -o 63 -i split image.000 image.001 image.002





## list split pieces of a file:
ls -1 image.raw.*


## check whether a set of split files is recognized
img_stat image.raw.000




## You can also uncompress and assemble a set of split files from a com-
## pressed image by piping all the split files into zcat and redirecting the out-
## put to a file:

cat image.raw.gz.* | zcat > image.raw



## 
cat image.raw.* > image.raw








## directory full of raw files is represented as a single disk image
affuse image.raw.000 /mnt


# ls -l /mnt












## Verify the Hash Taken During Acquisition
img_stat image.E01


calculate the hash from the raw disk device
dd if=/dev/sdj | md5sum

## validate sha256 cryptographic hash
zcat image.raw.gz | sha256sum



SHA1 hash is validated:
$ affinfo -S image.aff


validates the image stored in the metadata of
the EnCase format.
ewfverify image.Ex01




















## kpartx tool reads the partition table on a disk or image file,
## creates a loop device for the whole image, and then creates mapper devices
## for each partition

kpartx -r -a -v image.raw


fls /dev/mapper/loop0


fsstat /dev/mapper/loop0









## bind as read only
mkdir dir
mount --read-only /dev/mapper/loop0 /mnt/dir

umount p3
rmdir p3








remove them all by using the kpartx delete ( -d ) flag
kpartx -d image.raw


















cat /sys/block/sda/queue/logical_block_size

cat /sys/block/sda/queue/physical_block_size

blockdev --getpbsz /dev/sda

blockdev --getss /dev/sda






mmls /dev/sde


## specifying the 4096-byte sector size with the -b flag
mmls -b 4096 /dev/sde				








strings -e b  | less

strings -e l  | less

hexdump -C 

# byte# & ASCII with control chars
echo hello | hexdump -v  -e '/1  "%_ad#  "' -e '/1 " _%_u\_\n"'

hex bytes
echo hello | hexdump -v -e '/1 "%02X "' ; echo
           
hex bytes, with ASCII section
echo hello | hexdump -e '8/1 "%02X ""\t"" "' -e '8/1 "%c""\n"'

# hex with preceding 'x'
echo hello | hexdump -v -e '"x" 1/1 "%02X" " "' ; echo

# one hex byte per line
echo hello | hexdump -v -e '/1 "%02X\n"

# a table of byte#, hex, decimal, octal, ASCII
echo hello | hexdump -v  -e '/1  "%_ad#    "' -e '/1    "%02X hex"' -e '/1 " = %03i dec"' -e '/1 " = %03o oct"' -e '/1 " = _%c\_\n"'
           
           
xxd file0.m4a | head -1 
    
(gdb) info registers

           















http://www.metropipe.net/ppm.php?SID=4e38766ea6a3fab4792ced91b2bdbe48
https://en.wikipedia.org/wiki/List_of_device_bit_rates
http://www.pointsoftware.ch/en/howto-bash-audit-command-logger/



Penguin Sleuth Kit
http://www.linux-forensics.com/


http://www.vmware.com/appliances/directory/813


The Revealer Toolkit
http://www.vmware.com/appliances/directory/213673


• Adepto – a drive imaging utility

Helix







