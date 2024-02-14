

##-=============================-##
##   [+] Mount a QCOW image:
##-=============================-##
qcowmount image.qcow2 /mnt/qcowimage/


##-=================================================-##
##   [+] Pass "allow_root" to the fuse sub system using the qcowmount -X option:
##-=================================================-##
qcowmount -X allow_root image.qcow2 /mnt/qcowimage/



unmount /mnt/qcowimage/ using umount:
umount /mnt/qcowimage/


##-=================================================-##
##   [+] Or fusermount:
##-=================================================-##
fusermount -u /mnt/qcowimage/





mount a VHD image:

vhdimount image.vhd /mnt/fuse
vhdimount -X allow_root image.vhd /mnt/fuse

mount -o loop,ro,offset=${OFFSET} /mnt/fuse/vhdi1 /mnt/file_system

umount /mnt/fuse
fusermount -u /mnt/fuse




ewfmount 'image location' 'mountpoint'


ewfmount $file $e01mt


VMTYPE=`vmdkinfo $file 2>/dev/null | grep 'Disk type:' | awk -F: '{ print $2 }'`
FILETYPE=`file $file | awk -F: '{ print $2 }' | sed 's?^ ??'`
vhdimount $file $vhdmt
vmdkmount $file $vmdkmt


