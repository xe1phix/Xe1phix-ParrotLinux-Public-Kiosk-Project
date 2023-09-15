#!/bin/sh
## ------------------------------------------------------------------------------- ##
##     [?]  Mark A Specified Block Device As Read-Only:
## ------------------------------------------------------------------------------- ##
    bdev="$1"
[ -b "/dev/$bdev" ] || exit
[ ! -z $bdev##loop*$ ] || exit
    blockdev --setro "/dev/$bdev" || logger "wrtblk: blockdev --setro /dev/$bdev

