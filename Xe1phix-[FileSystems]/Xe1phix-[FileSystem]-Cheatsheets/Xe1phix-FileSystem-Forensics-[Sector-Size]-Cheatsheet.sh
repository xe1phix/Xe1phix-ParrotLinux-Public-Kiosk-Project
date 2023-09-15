#!/bin/sh


##-=====================================-##
##     [+] Find The Logical Sector Size:
##-=====================================-##
cat /sys/block/sda/queue/logical_block_size

##-=====================================-##
##     [+] Find The Physical Sector Size:
##-=====================================-##
cat /sys/block/sda/queue/physical_block_size

##-=====================================-##
##     [+] Find The Physical Sector Size:
##-=====================================-##
blockdev --getpbsz /dev/sda

##-=====================================-##
##     [+] Find The Logical Sector Size:
##-=====================================-##
blockdev --getss /dev/sda


