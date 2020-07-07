#!/bin/sh
## Xe1phix-ForensicAnalysis-v3.2.sh



hdparm --verbose --dco-identify /dev/

--dco-freeze
--dco-restore
--dco-setmax



hdparm --verbose -N /dev/



mmls /dev/nvme0n1


## check the number of namespaces supported and used
nvme id-ctrl /dev/nvme1 -H

## check the size of the namespace
nvme id-ns /dev/nvme0n1

hddtemp /dev/sdb
smartctl -x /dev/sdb
nvme smart-log /dev/nvme1

cat /sys/block/sda/queue/logical_block_size
cat /sys/block/sdc/queue/logical_block_size


cat /sys/block/sda/queue/physical_block_size
cat /sys/block/sdc/queue/physical_block_size

blockdev --getpbsz /dev/sda
blockdev --getpbsz /dev/sdc

blockdev --getss /dev/sda
blockdev --getss /dev/sdc



## specifying the 4096-byte sector size with the -b flag, the sectors of
## the Linux partition are represented as 4K units, and there is no unallocated
## area at the end of the drive.
mmls -b 4096 /dev/sde


img_stat -i list



## Terminal Recorders
script -a -tscript.timing script.output

## record terminal session
scriptreplay -m1 -tscript.timing script.output


## The tmux terminal multiplexer now supports logging by using the pipe-pane option:
tmux pipe-pane -o -t session_index:window_index.pane_index 'cat >> ~/output.window_index-pane_index.txt'


## 
icat image.raw 68 > photo.jpg_
icat image.raw 34 > customerlist.xls_
icat image.raw 267 > super-updater57.exe_
objdump -x


grep clientnames.xls fls-part1.txt >> notes.txt


time dcfldd if=/dev/sdc of=./ssd-image.raw


(ls -l image.raw; cp -v image.raw /exam/image.raw; md5sum /exam/image.raw) |ts



## Some filesystems use metadata to represent a sequence of zeros in a file instead
## of actually writing all the zeros to the disk. Sparse files contain “holes” where
## a sequence of zeros is known to exist

dd if=/dev/sde of=sparse-image.raw conv=sparse


15466496+0 records in
15466496+0 records out
7918845952 bytes (7.9 GB, 7.4 GiB) copied, 112.315 s, 70.5 MB/s

15466496+0 records in
15466496+0 records out
7918845952 bytes (7.9 GB, 7.4 GiB) copied, 106.622 s, 74.3 MB/s

echo "##-=====================================================================================-##"
echo "    [?] Notice how the block size is very different (7733252 blocks versus 2600 blocks):      "
echo "##-=====================================================================================-##"
ls -ls image.raw sparse-image.raw

7733252 -rw-r----- 1 root root 7918845952 May 15 08:28 image.raw
2600    -rw-r----- 1 root root 7918845952 May 15 08:30 sparse-image.raw


sudo tableau-parm /dev/sdg

## set a disk to read-only by setting a kernel flag.

hdparm -r1 /dev/sd
blockdev --setro /dev/sd



## To xmount an EWF image from your acquired disk as a raw DD image under /mnt:
xmount --in ewf ./acquired_disk.E?? /mnt

## To xmount the same ewf image as vdi file, you would use a command like this:
xmount --in ewf ./acquired_disk.E?? --out vdi /mnt

## And to enable virtual write support on a raw DD input image xmounted as VDI file:
xmount --in raw ./acquired_disk.dd --out vdi --cache ./disk.cache /mnt


ifind


xmount --in $ITYPE --out dd ${imm[@]} $MNTPNT



img_stat   | grep "Image Type:"







## list the partition table of a Windows system using autodetect:
mmls disk_image.dd

## To list the contents of a BSD system that starts in sector 12345 of a split image:
mmls -t bsd -o 12345 -i split disk-1.dd disk-2.dd



## using photorec to carve inside the freespace
photorec /d $DIR_FREESPACE/ /cmd $imm fileopt,everything,enable,freespace,search

## 
mmls $imm | grep ^[0-9] | grep '[[:digit:]]'| awk '{print $3,$4}' > $outputdir/mmls.txt



## 
blkls -s -o 

 | xargs rm -rf


tsk_recover -o          # recovering the deleted files

tsk_recover -a -o       # allocated files


HASHES_FILE=$outputdir/$lineparts/hashes.txt      # File output hash




## 

## 

## 

## 
http://www.pointsoftware.ch/en/howto-bash-audit-command-logger/
https://github.com/ecbftw/tableau-parm/
https://github.com/msuhanov/Linux-write-blocker/
http://www.cftt.nist.gov/hardware_write_block.htm
http://research.google.com/archive/disk_failures.pdf
## 
http://whmcr.com/2011/10/14/auditd-logging-all-commands/
## 
http://www.pointsoftware.ch/en/howto-bash-audit-command-logger/
## Unification of Digital Evidence from Disparate Sources (Digital Evidence Bags)
http://dfrws.org/sites/default/files/session-files/paper-unification_of_digital_evidence_from_disparate_sources.pdf
## Digital Forensic Research Workshop (DFRWS)
http://www.dfrws.org/CDESF/survey-dfrws-cdesf-diskimg-01.pdf
## The Linux Storage Stack Diagram
https://www.thomas-krenn.com/en/wiki/Linux_Storage_Stack_Diagram
