include /etc/firejail/disable-common.inc
include /etc/firejail/disable-passwdmgr.inc
private-tmp
private-dev
blacklist /mnt
blacklist /media
dns 139.99.96.146
dns 37.59.40.15
protocol unix,inet,
nodvd
novideo
notv
seccomp
nonewprivs
caps.drop all
noroot
