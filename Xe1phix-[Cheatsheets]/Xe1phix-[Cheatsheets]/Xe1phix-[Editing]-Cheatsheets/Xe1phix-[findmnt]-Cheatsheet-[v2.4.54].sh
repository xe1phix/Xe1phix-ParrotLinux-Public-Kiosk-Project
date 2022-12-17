#!/bin/sh

findmnt --fstab -t nfs										# Prints all NFS filesystems defined in /etc/fstab.
findmnt --fstab /mnt/foo									# Prints  all  /etc/fstab filesystems where the mountpoint directory is /mnt/foo.  It al bind mounts where /mnt/foo is a source.
findmnt --fstab --target /mnt/foo							# Prints all /etc/fstab filesystems where the mountpoint directory is /mnt/foo.
findmnt --fstab --evaluate									# Prints all /etc/fstab filesystems and converts LABEL= and UUID= tags to the real devic
findmnt -n --raw --evaluate --output=target LABEL=/boot		# Prints only the mountpoint where the filesystem with label "/boot" is mounted.
findmnt --poll --target /mnt/foo							# Monitors mount, unmount, remount and move on /mnt/foo.
findmnt --poll=umount --first-only --target /mnt/foo		# Waits for /mnt/foo unmount.
findmnt --poll=remount -t ext3 -O ro						# Monitors remounts to read-only mode on all ext3 filesystems.


