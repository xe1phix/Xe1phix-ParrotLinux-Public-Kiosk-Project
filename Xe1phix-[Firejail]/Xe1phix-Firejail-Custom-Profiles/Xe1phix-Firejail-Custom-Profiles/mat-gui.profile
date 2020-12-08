# This file is overwritten during software install.
# Persistent customizations should go in a .local file.
include /etc/firejail/mat-gui.local

blacklist /usr/bin/gcc*
blacklist /tmp/.X11-unix
blacklist /run/user/1000/bus
blacklist /home/xe1phix/.config/pulse


# mat-gui profile
noblacklist /usr/bin/perl
noblacklist /usr/share/perl*
noblacklist /usr/lib/python2.7/*
noblacklist /usr/local/lib/python2.7/*
noblacklist /usr/lib/x86_64-linux-gnu/gstreamer-1.0/libgstgdkpixbuf.so
noblacklist /usr/share/libimage-exiftool-perl/*
noblacklist /usr/share/doc/libimage-exiftool-perl/*
noblacklist /usr/share/libimage-metadata-jpeg-perl/

noblacklist /usr/local/bin/exiftool
noblacklist /usr/bin/exiftool
## noblacklist python-hachoir-core
noblacklist /usr/bin/mutagen-inspect
noblacklist /usr/bin/hachoir-metadata-gtk
noblacklist /usr/bin/hachoir-metadata-qt
noblacklist /usr/bin/hachoir-urwid
noblacklist /usr/bin/hachoir-metadata
## noblacklist python-hachoir-parser
## noblacklist python-cairo
noblacklist /usr/share/doc/python-mutagen/*
noblacklist /usr/share/doc/python-pdfrw/*
noblacklist /usr/lib/x86_64-linux-gnu/libpoppler-*
noblacklist /usr/share/doc/libpoppler*

noblacklist /usr/share/mat/
whitelist /usr/share/mat/
whitelist /usr/bin/exiftool
whitelist /usr/bin/mat
whitelist /usr/bin/mat-gui

include /etc/firejail/disable-common.inc
include /etc/firejail/disable-programs.inc
include /etc/firejail/disable-devel.inc
include /etc/firejail/disable-interpreters.inc
include /etc/firejail/disable-passwdmgr.inc
include /etc/firejail/whitelist-common.inc
include /etc/firejail/whitelist-var-common.inc

caps.drop all
nogroups
nonewprivs
noroot
noautopulse
nosound
protocol unix
seccomp
## netfilter
nodvd
ip none
no3d
tracelog
x11 xorg
## shell none
## net none

private

# private-bin mat,mat-gui,
## private-etc 

disable-mnt
private-tmp
private-dev
private-cache

# memory-deny-write-execute - breaks python
noexec ${HOME}
noexec /tmp
