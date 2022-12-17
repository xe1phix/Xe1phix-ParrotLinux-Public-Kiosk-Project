#!/bin/sh


lsblk --all              #  print all devices
lsblk --bytes            #  print SIZE in bytes rather than in human readable format
lsblk --nodeps           #  dont print slaves or holders
lsblk --discard          #  print discard capabilities
lsblk --exclude <list>   #  exclude devices by major number (default: RAM disks)
lsblk --fs               #  output info about filesystems
lsblk --help             #  usage information (this)
lsblk --ascii            #  use ascii characters only
lsblk --perms            #  output info about permissions
lsblk --list             #  use list format ouput
lsblk --noheadings       #  dont print headings
lsblk --output <list>    #  output columns
lsblk --pairs            #  use key="value" output format
lsblk --raw              #  use raw output format
lsblk --topology         #  output info about topology



echo "shows the relationship between the UUID and the partition"
blkid > $TEMP_DIR/blkid.txt
echo "tree structure of disk partitions && UUIDs"
lsblk > $TEMP_DIR/lsblk.txt
echo "Output  info  about  block  device  topology"
lsblk --topology > $TEMP_DIR/lsblk.topology.txt
echo "Output  info  about device owner, group and mode"
lsblk --perms > $TEMP_DIR/lsblk.perms.txt
echo "The authoritative information about filesystems"
lsblk --fs > $TEMP_DIR/lsblk.fs.txt
echo "List all block devices"
lsblk --all > $TEMP_DIR/lsblk.all.txt
echo "Use the raw output format"
lsblk --raw > $TEMP_DIR/lsblk.raw.txt
echo "Print the SIZE column in bytes"
lsblk --bytes > $TEMP_DIR/lsblk.bytes.txt


