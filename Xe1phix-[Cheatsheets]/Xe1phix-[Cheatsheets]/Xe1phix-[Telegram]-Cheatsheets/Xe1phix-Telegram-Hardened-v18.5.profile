v# Firejail profile for telegram
# This file is overwritten after every install/update
# Persistent local customizations
include /etc/firejail/telegram.local
# Persistent global definitions
include /etc/firejail/globals.local

include /etc/firejail/disable-common.inc
include /etc/firejail/disable-devel.inc
include /etc/firejail/disable-interpreters.inc
include /etc/firejail/disable-passwdmgr.inc
include /etc/firejail/disable-programs.inc
include /etc/firejail/disable-xdg.inc
include /etc/firejail/whitelist-common.inc
include /etc/firejail/whitelist-var-common.inc


noblacklist ${HOME}/Downloads
noblacklist ${HOME}/Downloads/Telegram
noblacklist ${HOME}/Downloads/Telegram/Telegram
noblacklist ${HOME}/Downloads/Telegram Desktop/
noblacklist ${HOME}/.config/firetools/
noblacklist ${HOME}/.gconf
noblacklist ${HOME}/.kde/share/kde4/services/tg.protocol
noblacklist ${HOME}/.local/share/icons/telegram.png
noblacklist ${HOME}/.local/share/TelegramDesktop
## noblacklist ${HOME}/.local/share/TelegramDesktop/tdata
noblacklist ${HOME}/.local/share/applications/telegramdesktop.desktop
## exec ${HOME}/.local/share/applications/telegramdesktop.desktop
## noblacklist /var/tmp
## whitelist ${DOWNLOADS}
whitelist ${HOME}/Downloads/
## whitelist ${HOME}/.gconf
## whitelist ${HOME}/.kde/share/kde4/services/tg.protocol
## whitelist ${HOME}/.local/share/icons/telegram.png
## whitelist ${HOME}/Downloads/Telegram/
read-write ${HOME}/Downloads/Telegram Desktop/
## whitelist ${HOME}/.local/share/TelegramDesktop
## whitelist ${HOME}/.local/share/applications/telegramdesktop.desktop
## noexec ${HOME}/Downloads/Telegram Desktop
## noexec ${HOME}/.local/share/TelegramDesktop/tdata



read-only /usr/lib/parrot-skel
blacklist /etc/firefox
blacklist /etc/firefox-esr
## read-only /etc/firefox*
## read-only /etc/firefox-esr
## whitelist ~/.mozilla
blacklist ${HOME}/.mozilla
## whitelist /usr/lib/firefox
## whitelist /usr/lib/firefox-esr
blacklist /usr/lib/firefox
blacklist /usr/lib/firefox-esr
## whitelist ${HOME}/.config/torbrowser
## whitelist ${HOME}/.local/share/torbrowser
## whitelist ${DOWNLOADS}/tor-browser_en-US
## whitelist /tmp/.X11-unix
## whitelist ${HOME}/.local/share/icons
## blacklist ~/My Virtual Machines/
## whitelist ${HOME}/My Virtual Machines/
blacklist /usr/bin/zuluMount-cli
blacklist /usr/bin/zuluCrypt-cli
blacklist /bin/mount
blacklist /bin/umount
blacklist /bin/ntfs-3g
blacklist /etc/adduser.conf
blacklist /usr/bin/sudo
blacklist /bin/su
blacklist /usr/bin/newgrp
blacklist /usr/bin/gpasswd
blacklist /usr/bin/chage
blacklist /etc/shadow
blacklist /etc/shadow-
blacklist /etc/passwd
blacklist /etc/passwd-
blacklist /etc/group
blacklist /etc/group-
blacklist /etc/gshadow
blacklist /etc/gshadow-
blacklist /etc/passwd
blacklist /etc/passwd-
blacklist /usr/bin/pkexec
blacklist /etc/apt
## read-only /etc/apt/sources.list
blacklist ${HOME}/.thunderbird
blacklist ${HOME}/.icedove
blacklist ${HOME}/.config/chromium
blacklist ${HOME}/
blacklist /boot/.config
blacklist /etc/grub.d
blacklist /etc/default/grub
blacklist /etc/default/grub.d/
blacklist /etc/java
blacklist /usr/share/java
## blacklist /usr/lib/jvm/java-11-openjdk-amd64/bin/java
## blacklist /usr/lib/jvm/java-11-openjdk-amd64/bin/javac
blacklist /usr/share/lua
blacklist /usr/bin/gcc*
blacklist /usr/share/php*
blacklist /usr/bin/php
blacklist /usr/lib/php
## blacklist /usr/share/perl*
blacklist /usr/lib/perl
blacklist /usr/bin/perl
blacklist /usr/bin/cpan
blacklist /usr/bin/node
blacklist /usr/bin/rust-gdb
blacklist /usr/bin/rustc
blacklist /usr/lib/valgrind
blacklist ${HOME}/.bash_history
blacklist ${HOME}/.gnupg
blacklist ${HOME}/.ssh
blacklist /tmp/ssh-*
blacklist /bin/nc.openbsd
read-only /run/resolvconf/resolv.conf
read-only /etc/resolv.conf
read-only /etc/resolv.conf.head
blacklist /sys/class/bluetooth
blacklist ${HOME}.bashrc
## read-only ${HOME}.bashrc
blacklist /root/.profile
blacklist /root/.bashrc
blacklist /root/.bash_history
blacklist /root/.synaptic/
blacklist /root/.config/
blacklist /root/.rpmdb/
read-only /etc/firejail/
## read-only ${HOME}/.local/share/applications
blacklist ${HOME}/.config/autostart
blacklist /etc/xdg/autostart
## blacklist /etc/X11/Xsession.d
## blacklist ${HOME}/.Xauthority
## blacklist ${HOME}/.config/pulse/client.conf
## blacklist ${HOME}/.pulse/client.conf
## blacklist ${HOME}/.config/pulse/client.conf.d
## blacklist /run/user/1000/pulse/native
## /home/xe1phix/.config/pulse/cookie
## read-only /tmp/.X11-unix
blacklist ${HOME}/.config/VirtualBox
blacklist ${HOME}/.macromedia
blacklist /etc/rc0.d
blacklist /etc/rc1.d
blacklist /etc/rc2.d
blacklist /etc/rc3.d
blacklist /etc/rc4.d
blacklist /etc/rc5.d
blacklist /etc/rc6.d
blacklist /etc/rcS.d
blacklist /proc/sys/kernel/core_pattern
blacklist /proc/sysrq-trigger
blacklist /proc/sys/vm/panic_on_oom
blacklist /proc/irq
blacklist /proc/bus
blacklist /proc/sched_debug
blacklist /proc/timer_list
blacklist /proc/kcore
blacklist /etc/dkms
blacklist /etc/kernel
blacklist /proc/kmsg
blacklist /etc/logrotate.conf
blacklist /etc/logrotate.d
blacklist /etc/cron.d
blacklist /etc/cron.daily
blacklist /etc/cron.hourly
blacklist /etc/cron.monthly
blacklist /etc/cron.weekly
blacklist /etc/crontab
blacklist /etc/profile.d
blacklist /proc/sys/fs/binfmt_misc
blacklist /proc/sys/kernel/modprobe
blacklist /lib/modules
blacklist /etc/modules-load.d
blacklist /etc/udev/udev.conf
blacklist /sys/fs
blacklist /sys/power
blacklist /sys/firmware
blacklist /sys/kernel/debug
blacklist /sys/kernel/vmcoreinfo
blacklist /usr/lib/debug
blacklist /etc/selinux
blacklist /etc/apparmor
blacklist /etc/apparmor.d
whitelist /var/lib/dbus
whitelist /var/lib/menu-xdg
blacklist /run/user/1000/gnupg
blacklist /run/user/1000/systemd
blacklist /run/user/1000/bus
## noexec /run/media
## noexec /media
## noexec /mnt
## noexec /etc
## noexec /var
read-only /bin
read-only /sbin
read-only /lib
read-only /lib64
read-only /lib32
read-only /etc
read-only /usr
read-only /var
blacklist /mnt
blacklist /boot
blacklist /media
blacklist /run/media
blacklist /run/mount
read-only /usr/local/bin
blacklist /usr/include
blacklist /usr/src/
read-only /usr/share/






## ------------------------------------------------ ##
## blacklist-nolog $File|$Dir
## nowhitelist $File|$Dir
## ------------------------------------------------ ##
## read-only $File|$Dir
## read-write $File|$Dir
## noexec $File|$Dir
## ------------------------------------------------ ##
## tmpfs $dir
## ------------------------------------------------ ##
## mkdir $dir
## mkfile $file
## ------------------------------------------------ ##
## bind $Dir1,$Dir2
## bind $File1,$File2
## ------------------------------------------------ ##
## bind /tmp/chroot,$MountPoint
## bind $TmpFile,/etc/passwd
## ------------------------------------------------ ##



## apparmor
seccomp
## seccomp $Syscall,$Syscall,$Syscall                       ## Enable seccomp filter + blacklist the list of syscalls
## seccomp.drop $Syscall,$Syscall,$Syscall
## seccomp.keep $Syscall,$Syscall,$Syscall
## seccomp.block-secondary
## caps
caps.drop all
## caps.drop $Capability,$Capability,$Capability
## caps.keep $Capability,$Capability,$Capability
## caps.drop CAP_SYS_ADMIN,CAP_SYS_BOOT,CAP_DAC_OVERRIDE,CAP_DAC_READ_SEARCH
## cgroup /sys/fs/cgroup/g1/tasks
ipc-namespace
disable-mnt
nonewprivs
## tracelog
noroot
nogroups
shell none
noexec /tmp
noexec ${HOME}/
## shell /bin/sh
## shell /bin/zsh
## allow-debuggers
## deterministic-exit-code
## memory-deny-write-execute


## overlay
## overlay-named $Name
## overlay-tmpfs 
## private
## private-home $Dir
## private-bin 
## private-etc
## private-etc group,hostname,localtime,nsswitch.conf,passwd,resolv.conf
## private-lib
## private-opt
## private-srv
## private-cwd $Dir
private-dev
## private-cache            ## Breaks Telegram
private-tmp
machine-id
## chroot /tmp
## tmpfs $Dir






## ------------------------------------------------------------------------------------------------------------------------------------- ##
##   [+] https://gitlab.com/xe1phix/ParrotLinux-Public-Kiosk-Project/blob/master/Xe1phix-DNS/Xe1phix-DNS-Trusted-ResolverList-v4.7.txt
## -------------------------------------------------------------------------------------------------------------------------------------- ##

## OpenNIC:
dns 209.141.60.226

## ParrotSec / OpenNIC:
dns 139.99.96.146

## Mullvad
dns 193.138.218.74

## ------------------------------------------------------------------------------------------------------------------- ##
## dns 198.98.49.91         ## OpenNIC
## dns 185.121.177.177      ## OpenNIC
## dns 209.97.158.137       ## OpenNIC
## dns 37.59.40.15          ## OpenNIC - ParrotSec
## dns 185.121.177.177      ## OpenNIC - ParrotSec
## dns 192.99.85.244        ## FrozenDNS
## ------------------------------------------------------------------------------------------------------------------- ##
## dns 208.67.222.222       ## OpenDNS - Wikileaks declared malicious - https://wikileaks.org/wiki/Alternative_DNS
## dns 208.67.220.220       ## OpenDNS - Wikileaks declared malicious - https://wikileaks.org/wiki/Alternative_DNS
## ------------------------------------------------------------------------------------------------------------------- ##
## 
protocol unix,inet
## protocol unix,inet,packet,netlink
## netfilter /etc/firejail/nolocal.net
## netfilter /etc/iptables/$Rules.v4
## netfilter6 /etc/iptables/$Rules.v6
## netfilter /usr/share/iptables/iptables.xslt
## veth-name eth0.vlan100
## mac $00:11:22:33:44:55
## net none
## net eth0
## net wlan0
## net tun0
## net br0
## ip netns
## hostname $Name
## defaultgw 192.168.1.1
## ip 192.168.1.37
## ip6 $FuckIPv6
## iprange 192.168.1.150,192.168.1.160
## mtu 1500
## hosts-file $File
## bandwidth set eth0 80 20
## bandwidth $Name|$PID set $Interface $Down $Up



## rlimit-nproc $1000               ## Set the maximum number of processes that can be created
## rlimit-as $123456789012          ## Set the maximum size of the process's virtual memory
## rlimit-cpu $123                  ## Set the maximum CPU time in seconds
## rlimit-fsize $1024               ## Set Maximum file size that can be created by a process to 1024 bytes.
## rlimit-nofile $500               ## Set Maximum number of files that can be opened by a proces
## rlimit-sigpending $200           ## Set the maximum number of processes that can be created 


## join-or-start $Process
## timeout 00:45:00                 ## Kill the sandbox automatically after the time has elapsed.
## cpu $0|$1|$2                     ## Use only CPU cores 0, 1 and 2.
## nice 15                          ## (favorable)  -20  vs   19  (least favorable)

notv
no3d
## nou2f
nodvd
## x11
## x11 none
## x11 xephyr
## xephyr-screen 640x480
## x11 xorg
## x11 xpra
## blacklist /tmp/.X11-unix/X0
## blacklist @/tmp/.X11-unix/X0
## noautopulse
## nosound
## novideo
## nodbus
## name $Name
## env HOME=/home/xe1phix
## env LD_LIBRARY_PATH=$PATH
## rmenv DBUS_SESSION_BUS_ADDRESS
## env HOME=/home/xe1phix
## rmenv 


## keep-dev-shm                             ## /dev/shm directory is untouched
## keep-var-tmp                             ## /var/tmp directory is untouched.
## writable-var-log
## writable-run-user
