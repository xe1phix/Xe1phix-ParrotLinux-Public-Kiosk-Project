# Firejail profile for audacious
# Description: Small and fast audio player which supports lots of formats
# This file is overwritten after every install/update
# Persistent local customizations
include /etc/firejail/audacious.local
# Persistent global definitions
include /etc/firejail/globals.local

noblacklist ${HOME}/.config/Audaciousrc
noblacklist ${HOME}/.config/audacious

noblacklist ${HOME}/Audio
noblacklist ${HOME}/Podcasts
noblacklist ${HOME}/Videos
noblacklist /run/media/public/2TB/Audio
noblacklist /run/media/public/2TB/Podcasts
noblacklist /run/media/public/2TB/Quantum Physics
noblacklist /run/media/public/2TB/ZBro
noblacklist /run/media/public/2TB/infosec


## ---------------------------------------------------- ##
## [?] Whitelisting will bind the files in a TMPFS
##     That sounds too resource heavy for mp3's
## ---------------------------------------------------- ##
## whitelist /run/media/public/2TB/Audio
## whitelist /run/media/public/2TB/Podcasts
## whitelist /run/media/public/2TB/Quantum Physics
## whitelist /run/media/public/2TB/ZBro
## whitelist /run/media/public/2TB/infosec

whitelist ${HOME}/Videos

include /etc/firejail/disable-common.inc
include /etc/firejail/disable-devel.inc
include /etc/firejail/disable-interpreters.inc
include /etc/firejail/disable-passwdmgr.inc
include /etc/firejail/disable-programs.inc
include /etc/firejail/disable-xdg.inc

include /etc/firejail/whitelist-var-common.inc

apparmor
caps.drop all
netfilter
nodbus
nogroups
nonewprivs
noroot
notv
## novideo
net none
seccomp
shell none
tracelog

# private-bin audacious
private-dev
private-tmp
## disable-mnt

memory-deny-write-execute
noexec ${HOME}
noexec /tmp
