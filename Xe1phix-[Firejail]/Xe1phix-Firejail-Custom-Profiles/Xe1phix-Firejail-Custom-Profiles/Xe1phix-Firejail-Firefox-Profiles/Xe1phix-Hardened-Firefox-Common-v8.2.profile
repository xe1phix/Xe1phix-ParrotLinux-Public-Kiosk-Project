# Firejail profile for firefox-common
# This file is overwritten after every install/update
# Persistent local customizations
include firefox-common.local
# Persistent global definitions
# already included by caller profile
#include globals.local

include /etc/firejail/disable-common.inc
include /etc/firejail/disable-devel.inc
include /etc/firejail/disable-interpreters.inc
include /etc/firejail/disable-passwdmgr.inc
include /etc/firejail/disable-programs.inc
include /etc/firejail/disable-xdg.inc
## include /etc/firejail/whitelist-common.inc
## include /etc/firejail/whitelist-var-common.inc
## include /etc/firejail/firefox-common-addons.inc

noblacklist ${HOME}/.mozilla
noblacklist /etc/firefox/
## noblacklist /etc/firefox/firefox.js
noblacklist /etc/firefox-esr/
## noblacklist /etc/firefox-esr/firefox-esr.js
read-only /etc/firefox/
## read-only /etc/firefox/firefox.js
read-only /etc/firefox-esr/
## read-only /etc/firefox-esr/firefox-esr.js
whitelist ${HOME}/.mozilla
read-only ${HOME}/.mozilla
## whitelist /usr/lib/firefox
## whitelist /usr/lib/firefox-esr
noblacklist /usr/lib/firefox
noblacklist /usr/lib/firefox-esr
read-only /usr/lib/firefox
read-only /usr/lib/firefox-esr
## whitelist ${HOME}/.config/torbrowser
## whitelist ${HOME}/.local/share/torbrowser
## whitelist ${DOWNLOADS}/tor-browser_en-US
noblacklist ${HOME}/Downloads
whitelist ${HOME}/Downloads
noblacklist ${HOME}/.local/share/applications
read-only ${HOME}/.local/share/applications
whitelist ${HOME}/.local/share/applications
noblacklist ${HOME}/.pki
noblacklist ${HOME}/.local/share/pki
mkdir ${HOME}/.pki
mkdir ${HOME}/.local/share/pki
whitelist ${HOME}/.pki
whitelist ${HOME}/.local/share/pki






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
## seccomp
## seccomp $Syscall,$Syscall,$Syscall                       ## Enable seccomp filter + blacklist the list of syscalls
## seccomp @clock,@cpu-emulation,@debug,@module,@obsolete,@raw-io,@reboot,@resources,@swap,acct,add_key,bpf,fanotify_init,io_cancel,io_destroy,io_getevents,io_setup,io_submit,ioprio_set,kcmp,keyctl,mount,name_to_handle_at,nfsservctl,ni_syscall,open_by_handle_at,personality,pivot_root,process_vm_readv,ptrace,remap_file_pages,request_key,setdomainname,sethostname,syslog,umount,umount2,userfaultfd,vhangup,vmsplice
seccomp.drop @clock,@cpu-emulation,@debug,@module,@obsolete,@raw-io,@reboot,@resources,@swap,acct,add_key,bpf,fanotify_init,io_cancel,io_destroy,io_getevents,io_setup,io_submit,ioprio_set,kcmp,keyctl,mount,name_to_handle_at,nfsservctl,ni_syscall,open_by_handle_at,personality,pivot_root,process_vm_readv,ptrace,remap_file_pages,request_key,setdomainname,sethostname,syslog,umount,umount2,userfaultfd,vhangup,vmsplice
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
## noexec ${HOME}
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
private-etc ca-certificates,ssl,machine-id,dconf,selinux,passwd,group,hostname,hosts,localtime,nsswitch.conf,resolv.conf,xdg,gtk-2.0,gtk-3.0,X11,pango,fonts,mime.types,mailcap,asound.conf,pulse,pki,crypto-policies,ld.so.cache,alternatives
## private-lib
## private-opt
## private-srv
## private-cwd $Dir
private-dev
private-cache
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
## net tap0
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
## rlimit-fsize e$1024               ## Set Maximum file size that can be created by a process to 1024 bytes.
## rlimit-nofile $500               ## Set Maximum number of files that can be opened by a proces
## rlimit-sigpending $200           ## Set the maximum number of processes that can be created 


## join-or-start $Process
## timeout 00:45:00                 ## Kill the sandbox automatically after the time has elapsed.
## cpu $0|$1|$2                     ## Use only CPU cores 0, 1 and 2.
## nice 15                          ## (favorable)  -20  vs   19  (least favorable)

notv
## no3d
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
