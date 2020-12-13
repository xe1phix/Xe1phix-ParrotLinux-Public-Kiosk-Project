


##-======================================================================================-##
##   [+] EnCase Expert Witness format
##-======================================================================================-##

ewfacquire -c best -t /exam/macbookair /dev/sdf















##-======================================================================================-##
##   [+] FTK Imager - FTK SMART format
##-======================================================================================-##



##-======================================================================================-##
##   [+] Use ftkimager to acquire an attached disk:
##-======================================================================================-##

## adding the --s01 flag saves it to FTK’s SMART format.

ftkimager /dev/sdf --s01 --description "SN4C53000120 Ultra Fit" sandisk





##-======================================================================================-##
##   [+] A 4K native (4096-byte native sector size) drive is imaged using sfsimage:
##-======================================================================================-##
sfsimage -i /dev/sdd 4Knative.sfs



dc3dd if=$DDIN log=errorlog.txt hlog=hashlog.txt hash=md5


cat /sys/block/sdd/queue/logical_block_size
cat /sys/block/sdd/queue/physical_block_size


##-======================================================================================-##
##   [+] SquashFS compressed filesystem
##-======================================================================================-##


## Micro SD card
sfsimage -i /dev/sdf MicroSD.sfs



##-======================================================================================-##
##   [+] Image The block device by using the -i flag:
##-======================================================================================-##
sfsimage -i /dev/sde philips-usb-drive.sfs


##-======================================================================================-##
##   [+] Show the size of the compressed *.sfs file:
##-======================================================================================-##


ls -lh *.sfs

-rw-r----- 1 holmes holmes 4.5G May 7 15:41 philips-usb-drive.sfs





##-======================================================================================-##
##   [+] Acquire an Image to Multiple Destinations
##-======================================================================================-##
dc3dd if=/dev/sde of=/exam/local-lab.raw of=/ext/third-party.raw


##-======================================================================================-##
## create a hash (or multiple hashes) with dcfldd
##-======================================================================================-##
dcfldd if=/dev/sde of=image.raw conv=noerror,sync hash=md5,sha256


dc3dd if=/dev/sde of=image.raw hash=md5 hash=sha1 hash=sha512








##-======================================================================================-##
##  [+] Pipe the image into sha256sum/sha512sum during the acquisition process:
##-======================================================================================-##
dd if=/dev/sdb | tee $Image.raw | sha1sum

dd if=/dev/sdb | tee $Image.raw | sha256sum

dd if=/dev/sdb | tee $Image.raw | sha512sum



##-======================================================================================-##
##   [+] Generate a separate hash for every 10MB sequence of sectors 
##   [+] Then, Generate a list of hashes for a disk.
##-======================================================================================-##
dcfldd if=/dev/sdd of=$Disk.raw conv=noerror,sync hashwindow=1M




##-======================================================================================-##
##  [?] In dc3dd, hash windows are referred to as piecewise hashing.
## -------------------------------------------------------------------------------------- ##
##  [?] hashes can be created, not by sector range but per split file. 
##-======================================================================================-##

##-======================================================================================-##
##  [+] The hashes for the sector ranges in each split file are logged:
##-======================================================================================-##
dc3dd if=/dev/sdd hof=$Disk.raw ofs=$Disk.000 ofsz=1G hlog=$Hash.log hash=sha1




time dcfldd if=/dev/sdc of=./ssd-image.raw

(ls -l image.raw; cp -v image.raw /exam/image.raw; md5sum /exam/image.raw) |ts



gpg --clearsign hash.log
cat hash.log.asc

gpgsm -a -r holmes@digitalforensics.ch -o hash.log.pem --sign hash.log


openssl ts -query -data hash.log -out hash.log.tsq -cert
tsget -h https://freetsa.org/tsr hash.log.tsq
curl -s -H "Content-Type: application/timestamp-query" --data-binary "@hash.log.tsq" https://freetsa.org/tsr > hash.log.tsr
openssl ts -reply -in hash.log.tsr -text











dcfldd if=/dev/sdd | gzip > image.raw.gz
zcat image.raw.gz | sha256sum



aimage --lzma_compress --compression=9 /dev/sdj image.aff




ewfacquire -v -c bzip2:best -m removable -f encase7-v2 -d sha256 -l /home/xe1phix/ewf-log.txt /dev/sdd


ewfacquirestream -t encase7 -d sha256 -c bzip2:best -e Xe1phix -m removable -t $Ewf < /dev/sdd



ewfacquire $Disk.raw




cat $Disk.raw.??? | ewfacquirestream
cat $Disk.??? | ewfacquirestream -c best -m fixed -t $Disk -S 1T
facquire -T $DvD.cue $DvD.iso





cat /dev/cdrom | od | more





echo $Pass | sha1sum | awk '{ print $1 }'




ewfinfo $Image.E01


clear && stat --format=[%n]:[Size:%s.bytes]:[IO-Block:%o]:[File-type:%F]:[Inode:%i] /home/xe1phix/ewf.E01 && stat --format=[%n]:[User:%U]:[Group:%G]:[Uid:%u]:[GID:%g]:[%A/%a] /home/xe1phix/ewf.E01 && file /home/xe1phix/ewf.E01 && stat /home/xe1phix/ewf.E01 && img_stat -i ewf /home/xe1phix/ewf.E01 && cat /home/xe1phix/ewf-log.txt








ewfmount -v $Image.E01 $Image/
ewfmount -v $Image.E01 EWF/

ewfmount $ewf_files $mount_point

ewfmount -X $ewf_files $mount_point


kpartx -r -a -v EWF/ewf1

mkdir p1
mount --read-only /dev/mapper/loop0p1 p1

umount p1
kpartx -d EWF/ewf1

fusermount -u $Image
fusermount -u EWF

ewfexport -d sha256 -f raw -l /home/xe1phix/EWF-to-Raw.txt -t /home/xe1phix/EWF-Raw $Image.E01




ewfexport $Image.E01



ewfexport $Image.L01




ewfexport $Image.E01 $MountPoint





ewfmount -f $Files $Image.L01 $MountPoint





xmount --cache xmount.cache --in ewf $Image.E01 --out vdi virtual
ls virtual/
xmount --cache xmount.cache --in ewf $Image.E01 --out raw /mnt/raw


losetup  --read-only --find --show image.raw
losetup  --read-only --find --show /mnt/raw/ewf.dd
losetup
losetup --detach /dev/loop0


fstat /dev/mapper/loop0p1


kpartx -r -a -v /mnt/raw/ewf.dd

mount --read-only /dev/mapper/loop0p1 /mnt/raw/ewf.dd






 1. Cgroups v2 provides a unified hierarchy against which all controllers are mounted.

       2. "Internal" processes are not permitted.  With the exception of the root cgroup, processes may reside only  in  leaf  nodes  (cgroups
          that do not themselves contain child cgroups).  The details are somewhat more subtle than this, and are described below.

       3. Active cgroups must be specified via the files cgroup.controllers and cgroup.subtree_control.

       4. The tasks file has been removed.  In addition, the cgroup.clone_children file that is employed by the cpuset controller has been re‐
          moved.

       5. An improved mechanism for notification of empty cgroups is provided by the cgroup.events file.
  
  
  
  cgroup_no_v1=list
  
  
  
  
  
  
  
  
  
  
  
  
  
  


CGROUP_LOGLEVEL=DEBUG
INFO
WARNING
ERROR


/etc/cgconfig.conf
/etc/cgrules.conf               ## default libcgroup configuration file



cgclassify - move running task(s) to given cgroups

cgclassify -g <controllers>:<path> --sticky <pidlist>



lscgroup [[-g] <controllers>:<path              ## defines  the  control  groups  whose subgroups will be shown



lssubsys

cgset [-r <name=value>] <cgroup_path>
cgset --copy-from <source_cgroup_path> <cgroup_path>








mount -t cgroup2 -o remount,nsdelegate none /sys/fs/cgroup/unified





/proc/cgroups                       ##  This file contains information about the controllers that are compiled into the kernel.


/proc/[pid]/cgroup                  ##



/sys/kernel/cgroup/delegate         ## This file exports a list of the cgroups v2 files (one per line) that are delegatable

cat /sys/kernel/cgroup/delegate







/sys/kernel/cgroup/features

cat /sys/kernel/cgroup/features

nsdelegate (since Linux 4.15)
                     The kernel supports the nsdelegate mount option.





The location for the mounts these scripts create is /sys/fs/cgroup


cgroupfs-mount                  ## set up cgroupfs mount hierarchies





CLONE_NEWCGROUP flag





unshare
setns
prctl
ptrace
sigaction
clone
prlimit
systemd-cgls
systemd-cgtop
perf_event_open
setrlimit
strace
seccomp_export_bpf
seccomp_init
seccomp_load
seccomp_rule_add
struct bpf_elf_map





echo 1 > /proc/sys/net/core/bpf_jit_enable

clang -O2 -emit-llvm -c bpf.c -o - | llc -march=bpf -filetype=obj -o bpf.o



objdump -h bpf.o                ## inspecting ELF section headers:






act_bpf
cls_bpf

modprobe test_bpf


##  [?] any tcpdump(8) filter expression can be abused as a classifier where a match will result in the default  classid:

bpftool EN10MB 'tcp[tcpflags] & tcp-syn != 0' > /var/bpf/tcp-syn
tc filter add dev em1 parent 1: bpf bytecode-file /var/bpf/tcp-syn flowid 1:1



##  [?] Basically, such a minimal generator is equivalent to:

tcpdump -iem1 -ddd 'tcp[tcpflags] & tcp-syn != 0' | tr '\n' ',' > /var/bpf/tcp-syn




##  [?] a classifier can be loaded as:

bpf_asm foobar > /var/bpf/tcp-syn
tc filter add dev em1 parent 1: bpf bytecode-file /var/bpf/tcp-syn flowid 1:1







##  [?] encapsulates incoming ICMP packets on eth0 from 10.0.0.2 into VLAN ID 123:

tc qdisc add dev eth0 handle ffff: ingress
tc filter add dev eth0 parent ffff: pref 11 protocol ip \
    u32 match ip protocol 1 0xff flowid 1:1 \
        match ip src 10.0.0.2 flowid 1:1 \
    action vlan push id 123





##  [?] example of the pop function: 
##  [?] Incoming VLAN packets on eth0 are decapsulated 
##  [?] and the classification  process  then  restarted for the plain packet:

tc qdisc add dev eth0 handle ffff: ingress
tc filter add dev $ETH parent ffff: pref 1 protocol 802.1Q \
    u32 match u32 0 0 flowid 1:1 \
    action vlan pop reclassify




##  [?] tc filter statement:
##  [?] will match if the packet's fwmark value is 6.  
tc filter add ... handle 6 fw classid 1:1



##  [?] This is a sample iptables statement marking packets coming in on eth0:
iptables -t mangle -A PREROUTING -i eth0 -j MARK --set-mark 6










cgred.conf  is  cgred service configuration file









##  [?] net_cls control group has to be created first 
##  [?] and class as well as process ID(s) assigned to it. 
##  [?] The following creates a net_cls cgroup named "foobar":



modprobe cls_cgroup
mkdir /sys/fs/cgroup/net_cls
mount -t cgroup -onet_cls net_cls /sys/fs/cgroup/net_cls
mkdir /sys/fs/cgroup/net_cls/foobar



##  [?] To assign a class ID to the created cgroup, 
##  [?] a file named net_cls.classid has to be created 
##  [?] which contains the class ID to  be  assigned
##  [?] as a hexadecimal, 64bit wide number.

##  [?] So a class ID of  ff:be  has to be written like so: 
##  [?] 0xff00be (leading zeroes may be omitted).



##  [?] assigns class ID 1:2 to foobar cgroup:

echo 0x10002 > /sys/fs/cgroup/net_cls/foobar/net_cls.classid

##  [?] Finally some PIDs can be assigned to the given cgroup:

echo 1234 > /sys/fs/cgroup/net_cls/foobar/tasks
echo 5678 > /sys/fs/cgroup/net_cls/foobar/tasks

##  [?] Now by simply attaching a cgroup filter to a qdisc makes packets from PIDs 1234 and 5678 be pushed into class 1:2.





tc-ematch
tc
Documentation/cgroups/net_cls.txt

















mount -t tmpfs -o uid=0,gid=0,mode=0755 cgroup /sys/fs/cgroup





cgexec -g *:test1 ls
       runs command ls in control group test1 in all mounted controllers.

       cgexec -g cpu,memory:test1 ls -l
       runs command ls -l in control group test1 in controllers cpu and memory.

       cgexec -g cpu,memory:test1 -g swap:test2 ls -l
       runs command ls -l in control group test1 in controllers cpu and memory and control group test2 in controller swap.







ls -l /dev/btrfs-control
/sys/fs/btrfs/features
/sys/fs/btrfs/UUID/features/
mknod --mode=600 c 10 234 /dev/btrfs-control	





mkfs.xfs -l logdev=/dev/sdb1,size=10000b /dev/sda1





mkfs.btrfs -f -n 65536 /dev/loop0








mount -t tmpfs none /mnt -o 'context="system_u:object_r:tmp_t:s0:c127,c456",noexec'
context="system_u:object_r:removable_t"




mount /tmp/disk.img /mnt -t vfat -o loop=/dev/loop3
mount /tmp/disk.img /mnt -o loop

errors=remount-ro
sys_immutable

mount -t overlay  overlay -olowerdir=/lower,upperdir=/upper,workdir=/work  /merged

























##-=================================-##
##   [+] Backup Grub to a disk
##-=================================-##
cd /tmp
grub-mkrescue --output=grub-img.iso
dd if=grub-img.iso of=/dev/fd0 bs=1440 count=1




grub-mkdevicemap --device-map=device.map
cat device.map





echo $File | sha1sum | awk '{ print $1 }'

cryptroot /dev/sda2 none luks,keyscript=/usr/local/sbin/cryptkey
root=/dev/mapper/crypt0 cryptopts=target=crypt0,source=/dev/sda1,cipher=aes-xts-plain64,size=256,hash=sha1
cryptswap /dev/sda2 cryptroot cipher=aes-xts-plain65,size=256,hash=sha1,keyscript=decrypt_derived,swap

dd if=/dev/random bs=4k count=1 | gpg ‐a ‐‐cipher‐algo AES256 ‐c ‐ > /mnt/usb/keys/fs.gpg
gpg ‐q ‐o ‐ /mnt/usb/keys/fs.gpg | cryptsetup ‐v ‐c aes create cryptfs /dev/hdxN
mkfs.ext3 /dev/mapper/cryptfs
mount /dev/mapper/cryptfs /crypto





## Checking for S.M.A.R.T. capability ---"
DISKTYPE="$(smartctl --scan | grep "${DEVICE}" | cut -d' ' -f3)"
SMARTSTATUS="$(smartctl -i -d "${DISKTYPE}" "${DEVICE}")"
if [[ "${SMARTSTATUS}" == "*Available*" ]]; then
	echo "--- Device ${DEVICE} Supports S.M.A.R.T."

	echo "Setting Up S.M.A.R.T. Disk Controls..."
	echo
	smartctl -s on -d "${DISKTYPE}" "${DEVICE}"
	echo "--- S.M.A.R.T. Disk Controls Is Now Enabled And Monitoring has been setup"
else 
	echo "--- Device ${DEVICE} doesnt support S.M.A.R.T."
fi











##-======================================================================================-##
##   [+] Verify the raw storage media data:
##-======================================================================================-##
ewfverify -v -d sha256 $Disk.E01


##-======================================================================================-##
##   [+] Verify logical file data:
##-======================================================================================-##
ewfverify -v -f $Files $Disk.E01



ewfrecover -t $Ewf -l /home/xe1phix/Ewf-Recover.txt corrupt.E01




## Acquire a Remote Disk to EnCase or FTK Format
ssh remote-pc "dd if=/dev/sda" | ewfacquirestream -D 16048539022588504422 -t eepc-16048539022588504422






echo "## ==================================================================== ##"
echo -e "\t\t [+] Execute This on The Receiving Machine:"
echo "## ==================================================================== ##"
ssh root@123.45.67.89 "dd if=/dev/xvda " | dd of=/home/archive/linode.img



echo "## ===================================== ##"
echo -e "\t\t [+] Mount the raw image:			"
echo "## ===================================== ##"
mount -o loop linode.img linode












affconvert -r image.aff
affcat image.aff > image.raw


affcat image.aff | ewfacquirestream -C 42 -E 1 -e "S. Holmes" -D "Data theft
case" image


affcat image.aff | sfsimage -i - image.sfs


affinfo image.aff > affinfo.txt
sfsimage -a affinfo.txt image.sfs



blkstat -i ewf image ewf.E01


istat -i ewf image ewf.E01

ils -e -i ewf image ewf.E01



fusermount -u mount_point, to unmount


-d -o debug
                     Enable debug output




affconvert
affix
affinfo
affdiskprint
affstats
affverify
affcopy
affsign
affrecover
affcat
affcrypto
affxml
affsegment
affcompare






qemu-img
qemu-img --help







Run an extracted zip archive containing a centos6 .vmx and .vmdk file, converting the images to qcow2 format

virt-convert centos6/ --disk-format qcow2

--input-format ovf --disk-format  --destination 













lkvm run 

setup <name>

--disk <image file|directory>



lkvm run -k bzImage



qemu disk.img -kernel /boot/vmlinuz



















dcfldd if=/dev/sde | gpg -cv > image.raw.gpg
gpg -dv -o image.raw image.raw.gpg
gpg -dv image.raw.gpg | md5sum



openssl enc -aes-256-cbc -in image.raw -out image.raw.aes

dcfldd if=/dev/sdg | openssl enc -aes-256-cbc > image.raw.aes
dcfldd if=/dev/sdg | gzip | openssl enc -aes-256-cbc > image.raw.gz.aes


openssl enc -d -aes-256-cbc -in image.raw.aes -out image.raw
openssl enc -d -aes-256-cbc < image.raw.gz.aes | gunzip | md5sum






gpg --verbose --symmetric --cert-digest-algo sha512 --digest-algo sha512 --cipher-algo aes256 --s2k-mode 3 --s2k-cipher-algo AES256 --s2k-digest-algo SHA512 --s2k-count 65011712 


gpg --verbose --symmetric --cert-digest-algo sha512 --digest-algo sha512 --cipher-algo aes256 --s2k-mode 3 --s2k-cipher-algo AES256 --s2k-digest-algo SHA512 --s2k-count 65011712 
gpg --verbose --symmetric --cert-digest-algo sha512 --digest-algo sha512 --cipher-algo aes256 --s2k-mode 3 --s2k-cipher-algo AES256 --s2k-digest-algo SHA512 --s2k-count 65011712 
gpg --verbose --symmetric --cert-digest-algo sha512 --digest-algo sha512 --cipher-algo aes256 --s2k-mode 3 --s2k-cipher-algo AES256 --s2k-digest-algo SHA512 --s2k-count 65011712 
gpg --verbose --symmetric --cert-digest-algo sha512 --digest-algo sha512 --cipher-algo aes256 --s2k-mode 3 --s2k-cipher-algo AES256 --s2k-digest-algo SHA512 --s2k-count 65011712 
gpg --verbose --symmetric --cert-digest-algo sha512 --digest-algo sha512 --cipher-algo aes256 --s2k-mode 3 --s2k-cipher-algo AES256 --s2k-digest-algo SHA512 --s2k-count 65011712 
gpg --verbose --symmetric --cert-digest-algo sha512 --digest-algo sha512 --cipher-algo aes256 --s2k-mode 3 --s2k-cipher-algo AES256 --s2k-digest-algo SHA512 --s2k-count 65011712 




ftkimager --outpass monkey99 --e01 /dev/sdg image

affcrypto -e -N monkey99 image.aff

dd_rescue -L crypt=enc:passfd=0:pbkdf2 /dev/sdc samsung.raw.aes



veracrypt -c /dev/sda
veracrypt /dev/sda /mnt
veracrypt --dismount /mnt









# script to generate a keyfile that is encrypted with openssl

if [ -x /usr/bin/openssl ]; then
	key=`tempfile`
	dd if=/dev/random of=$key bs=1c count=256
	openssl enc -aes-256-cbc -e -salt -in $key -out $1
	#rm -f $key; key=""
	shred -uz $key; key=""
else
	echo "/usr/bin/openssl is not available" && exit 1
fi





outp=$(dd if=/dev/urandom of=/dev/stdout bs=1 count=6 2> /dev/null | base64)



dialog --clear --title "Cipher" \
        --menu "Choose your favorite cipher" 20 61 4 \
        "aes-cbc-essiv:sha256"  "Low Security/Fast" \
        "twofish-cbc-essiv:sha256" "Good Security/Slow" \
        "serpent-cbc-essiv:sha256"  "High Security/Very Slow"


LOOP_DEV=`losetup -f`
fnamevol=fdisk -l | grep /dev/sd
$fnamevol =~ /dev/sd[a-z][1-9]

create the encrypted volume
echo
echo "Defining loop device"
losetup $LOOP_DEV $fnamevol
echo "Formatting as luks volume"
cryptsetup -c $cipher -s 256 -y luksFormat $LOOP_DEV
echo
echo "Please, reinsert the password one more time"
cryptsetup luksOpen $LOOP_DEV $CRYPT_NAME
echo
echo "Formatting the crypt device as FAT32"
mkdosfs /dev/mapper/$CRYPT_NAME
echo
echo "OK! Almost done! Let's close everything"
cryptsetup luksClose /dev/mapper/$CRYPT_NAME
losetup -d $LOOP_DEV

















cdparanoia --output-raw --log-summary 1- cdda.raw



fls -p -r /dev/sda1 | grep -i "\.doc$" |wc -l



##-======================================================================================-##
## 
##-======================================================================================-##
script -a -tscript.timing script.output

##-======================================================================================-##
##   [+] View the recording using the scriptreplay
##-======================================================================================-##
scriptreplay -m1 -tscript.timing script.output



##-=========================================================================================-##
##  [?] The tmux terminal multiplexer now supports logging by using the pipe-pane option:
##-=========================================================================================-##
tmux pipe-pane -o -t session_index:window_index.pane_index 'cat >> ~/output.window_index-pane_index.txt'









##-======================================================================================-##
##   [+] file extension formats:
##-======================================================================================-##

• *.txt can be opened and read using a text editor.
• *.raw is a raw data dump (disk, memory, and so on).
• *.pcap is captured network traffic.
• *.db is a database (possibly a Sleuth Kit file list).
• *.sfs is a SquashFS evidence container.
• *.e01 and *.aff are forensic formats.



icat image.raw 68 > photo.jpg_
icat image.raw 34 > customerlist.xls_
icat image.raw 267 > super-updater57.exe_

exif photo.jpg_ > photo.jpg_.txt

objdump -x super-updater57.exe_ > super-updater57.exe_.txt






fls /dev/sda &> fls-part1.txt
fls /dev/sda > fls-part1.txt 2>&1










hddtemp /dev/sdb
smartctl -x /dev/sdb




tableau-parm /dev/sd






/dev/sda image.raw image.log



ddrescue -b 2048 /dev/cdrom cdrom.raw





WHOLE DISK TO IMAGE RESCUE - If your ddrescue command was:
ddrescue /dev/sda rescued_image rescued_logfile



PARTITION ONLY TO IMAGE RESCUE - If your ddrescue command was:
     ddrescue /dev/sda1 rescued_image rescued_logfile

Then the ddru_ntfsfindbad command would be:
     ddru_ntfsfindbad rescued_image rescued_logfile

WHOLE DISK TO DISK RESCUE - If your ddrescue command was:
     ddrescue /dev/sda /dev/sdb rescued_logfile



set_xattr=XATTR.NAME
chk_xattr=XATTR.NAME


alg=help
dd_rhelp

dd_rescue [options] [--shred2/--shred3/--shred4/--random

-v -c 1 

-l logfile name of a file to log errors and summary to (def=""),
         -o bbfile  name of a file to log bad blocks numbers (def=""),






## Remote Forensic Imaging with rdd
rdd-copy -S --md5 -l server.log
cat server.log


rdd-copy -C --md5 -l client.log -I /dev/sde -O -N lab-pc:/evi/image.raw
cat client.log






## over the network using a secure shell session originating from the remote PC:
dd if=/dev/sdb | ssh lab-pc "cat > sandisk-02028302BCA1D848.raw"


## from the examiner workstation
ssh remote-pc "dd if=/dev/sdb" > sandisk-02028302BCA1D848.raw





## Remote Acquisition to a SquashFS Evidence Container
ssh root@remote-pc "dd if=/dev/mmcblk0" | sfsimage -i - remote-pc.sfs
sfsimage -i - remote-pc.sfs




























## Securely cleans swap and temporary directories (/tmp, /var/tmp) on shutdown with scrub
}
	# Scrub Temp Files
	echo -n "Scrubing '/tmp' directory... "
	/usr/bin/find /tmp -type f -exec /usr/bin/scrub -S -f -r -p dod {} \; &> /dev/null
	echo "Finished."

	# Scrub Temp Files
	echo -n "Scrubing '/var/tmp' directory... "
	/usr/bin/find /var/tmp -type f -exec /usr/bin/scrub -S -f -r -p dod {} \; &> /dev/null
	echo "Finished."
}









## show all devices that have a btrfs file system at the specified mount point:
btrfs filesystem show /mount-point





## An ISO image (or a disk image in general) can be mounted by using the loop device
mount -o ro,loop Fedora-14-x86_64-Live-Desktop.iso /media/cdrom


mount --bind old_directory new_directory
mount --rbind old_directory new_directory

mount --bind /media /media
# mount --make-shared /media

mount --bind /media /mnt


mount /dev/cdrom /media/cdrom
ls /media/cdrom
ls /mnt/cdrom




## When a mount point is marked as a slave mount, 
## any mount within the original mount point is reflected in it, 
## but no mount within a slave mount is reflected in its original.

mount --make-slave mount_point

## Private Mount
mount --make-private mount_point


## mark the /mnt/ directory as private, type:
mount --make-private /mnt



## Creating an Unbindable Mount Point
mount --make-unbindable /media





change the directory in which a file system is mounted:
mount --move old_directory new_directory











btrace
verify_blkparse
blkrawverify
btt







trace the i/o on the device /dev/hda and parse the output to human readable form, use the following command:

blktrace -d /dev/sda -o - | blkparse -i -

       This same behaviour can be achieve with the convenience script btrace.  The command

btrace /dev/sda

       has exactly the same effect as the previous command. See btrace (8) for more information.

       To trace the i/o on a device and save the output for later processing with blkparse, use blktrace like this:

blktrace /dev/sda /dev/sdb

       This will trace i/o on the devices /dev/sda and /dev/sdb and save the recorded information in the files sda and
       sdb in the current directory, for the two different devices, respectively.  This trace information can later be
       parsed by the blkparse utility:

blkparse sda sdb











rahash2 -a sha256

-b $bsize
-B          Show per-block hash

-e          Use little endian to display checksums

-E $algo     encrypt. Use -S to set key and -I to set IV
-E aes
-D $algo     decrypt. Use -S to set key and -I to set IV
-D aes

-L          list all available algorithms (see -a)
 -r          output radare commands
 -s $string   hash this string instead of files

-I $iv       use give initialization vector (IV) (hexa or s:string)
 -S @/dev/urandom     ## @ prefix points to a file
 -k          show hash using the openssh's randomkey algorithm













RHOMEDIR     ~/.config/radare2
RCFILE       ~/.radare2rc (user preferences, batch script)
R2_USER_PLUGINS ~/.local/share/radare2/plugins



 =                  ## read file from stdin (use -i and -c to run cmds)

-S                  ## Enable sandboxed mode (same as -e cfg.sandbox=true)

-t                  ## Get binary information using a threa

-H                  ## Show files and environment help

-x                  ## Open the file map without executable permissions

-X                  ## Same as -e bin.usextr=false, do not use extract plugins

-d                  ## Start in debugger mode
-D dbg.backend      ## Enable debug mode. Set cfg.debug=true
-l $plugfile         ## Load given plugin file
-L                  ## List supported IO plugins.
-x                  ## open without exec-flag (asm.emu will not work), See io.exec
-c '$cmd'                  ## execute radare command
-C                  ## file is host:port (alias for -c+=http://%s/cmd/)
-d                  ## debug the executable 'file' or running process 'pid'





## all connections to or from the specified ip-address/port pair
cutter $ip-address $port
cutter 10.10.0.45 80



## connection between the two ip/port number pairs given
ip-address-1 port-1 ip-address-2 port-2
cutter 200.1.2.3 22 10.10.0.45 32451




##-======================================================================================-##
##   [+] 
##-======================================================================================-##

 •> PCI domain:bus:slot.function
 • PCI vendorID:deviceID
• USB bus:device
• USB vendorID:productID
• SCSI host:channel:target:lun



lsblk -O /dev/sda > lsblk.txt






hdparm --dco-identify /dev/sd

hdparm --dco-restore /dev/sd
hdparm --yes-i-know-what-i-am-doing --dco-restore /dev/sd



##-======================================================================================-##
##   [+] Detect the existence of an HPA:
##-======================================================================================-##
hdparm -N /dev/sdl

hdparm --yes-i-know-what-i-am-doing -N 976773168 /dev/sd




##-======================================================================================-##
##   [+] Temporarily remove the HPA:
##-======================================================================================-##
hdparm --yes-i-know-what-i-am-doing -N 976773168 /dev/sdl

To make the change permanent, 
add p to the sector count number:
##-======================================================================================-##
hdparm --yes-i-know-what-i-am-doing -N p976773168 /dev/sdl





nvme list                           ## list the attached NVME devices:

nvme list-ns /dev/nvme1             ## check each NVME drive for multiple namespace

mmls /dev/nvme1n1

nvme smart-log /dev/nvme1           ## use the nvme tool to extract the SMART log



##-======================================================================================-##
##   [+] 
##-======================================================================================-##





##-======================================================================================-##
##   [+] 
##-======================================================================================-##




##-======================================================================================-##
##   [+] 
##-======================================================================================-##



##-======================================================================================-##
##   [?] 
## -------------------------------------------------------------------------------------- ##
##   [?] 
##-======================================================================================-##


##-======================================================================================-##
##   [•] 
##-======================================================================================-##

 •> 

##-======================================================================================-##
##   [*] 
##   [^] 












