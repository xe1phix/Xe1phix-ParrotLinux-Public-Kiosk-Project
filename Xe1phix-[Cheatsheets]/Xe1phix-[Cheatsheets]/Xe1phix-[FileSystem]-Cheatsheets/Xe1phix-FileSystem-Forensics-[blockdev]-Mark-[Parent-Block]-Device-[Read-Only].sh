#!/bin/sh
## --------------------------------------------------------------------------- ##
##     [?]  Mark A Parent Block Device As Read-Only:
## --------------------------------------------------------------------------- ##
        syspath=$(echo /sys/block/*/"$bdev")
[ "$syspath" = "/sys/block/*/$bdev" ] && exit
        dir=$syspath%/*$
        parent=$dir##*/$
[ -b "/dev/$parent" ] || exit
        blockdev --setro "/dev/$parent" || logger "wrtblk: blockdev --setro /dev/$parent
        

