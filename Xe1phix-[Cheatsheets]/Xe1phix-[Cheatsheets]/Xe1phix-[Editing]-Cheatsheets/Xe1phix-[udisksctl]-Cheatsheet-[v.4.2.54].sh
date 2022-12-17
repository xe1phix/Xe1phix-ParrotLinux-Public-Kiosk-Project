#!/bin/sh



udisksctl dump
udisksctl status
udisksctl monitor



udisksctl info --object-path $OBJECT | --block-device $DEVICE

udisksctl mount --object-path $OBJECT | --block-device $DEVICE --filesystem-type $TYPE --options $OPTIONS --no-user-interaction

udisksctl unmount --object-path $OBJECT | --block-device $DEVICE --force --no-user-interaction

udisksctl unlock --object-path $OBJECT | --block-device $DEVICE --no-user-interaction --key-file $PATH

udisksctl lock --object-path $OBJECT | --block-device $DEVICE --no-user-interaction

udisksctl loop-setup --file $PATH --read-only --offset $OFFSET --size $SIZE --no-user-interaction

udisksctl loop-delete --object-path $OBJECT | --block-device $DEVICE --no-user-interaction

udisksctl power-off --object-path $OBJECT | --block-device $DEVICE --no-user-interaction

udisksctl smart-simulate --file $PATH --object-path $OBJECT | --block-device $DEVICE --no-user-interaction




udisksctl mount --block-device /dev/sdb1 --filesystem-type btrfs


udisksctl info --block-device /dev/sdb


##-=================================================-##
##   [+] Show information about my DvD Drive:
##-=================================================-##
udisksctl info --drive hp_______DVDRAM_GU90N_M5NE3AH0028


udisksctl info --object-path block_devices/pktcdvd0




udisksctl loop-setup --file $PATH --read-only --offset $OFFSET --size $SIZE] --no-user-interaction






udisksctl loop-setup -r -f $Loop.iso


udisks --inhibit-all-polling







udisksctl info {--object-path OBJECT | --block-device

udisksctl mount {--object-path OBJECT | --block-device DEVICE} [--filesystem-type TYPE] [--options

udisksctl unmount --block-device /dev/sdc
udisksctl power-off {--object-path OBJECT | --block-device 

udisksctl loop-setup --file PATH [--read-only] [--offset OFFSET] [--size



# To get info about a device:
udisksctl info -b <device>

# To mount a device:
udisksctl mount --block-device <device>

# To unmount a device:
udisksctl unmount --block-device <device>

# To get help:
udisksctl help 



