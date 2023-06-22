#!/bin/sh




genisoimage -o output.raw -hfs -graft-points newname=oldname cd_dir


genisoimage -boot-info-table

genisoimage -boot-load-seg
genisoimage 
genisoimage -boot-load-size
genisoimage -hppa-ramdisk
genisoimage -hppa-kernel-32
genisoimage -hppa-kernel-64
genisoimage -hppa-cmdline
genisoimage -hppa-bootloader
genisoimage -alpha-boot
genisoimage -dir-mode
genisoimage -file-mode
genisoimage -gid
genisoimage -iso-level
genisoimage -jigdo-jigdo			# Produce a jigdo .jigdo metadata file as well as the filesystem image.
genisoimage -md5-list
genisoimage -jigdo-force-md5
genisoimage -jigdo-template-compress
genisoimage -generic-boot
genisoimage -log-file
genisoimage -new-dir-mode
genisoimage -o 
genisoimage -root
genisoimage -uid
genisoimage -v
genisoimage -z			# Generate special RRIP records for transparently compressed files.
genisoimage -map
genisoimage -root-info
genisoimage -magic			# 
genisoimage 			# 
genisoimage 			# 
genisoimage -o cd.iso -r cd_dir		# create a CD with Rock Ridge extensions of the source directory cd_dir:
genisoimage -o cd.iso -R cd_dir		# create a CD with Rock Ridge extensions of the source directory cd_dir where all files have at least read  permission  and all files are owned by root, call:
genisoimage 
genisoimage 
genisoimage 
genisoimage 
genisoimage -o cd.iso cd_dir
			# 
mkzftree --verbose 
--parallelism	# 
--uncompress	# 
--level			# compression level (1-9, default is 9).
--force			# Always compress all files, even if they get larger when compressed.




mount -t hfs /dev/fd0 /mnt/floppy
genisoimage --cap -o output source_dir /mnt/floppy

write a tar archive directly to a CD that will later contain a simple ISO9660 filesystem with the tar archive call:

tar cf - . | genisoimage -stream-media-size 333000 | wodim dev=b,t,l -dao tsize=333000s -


