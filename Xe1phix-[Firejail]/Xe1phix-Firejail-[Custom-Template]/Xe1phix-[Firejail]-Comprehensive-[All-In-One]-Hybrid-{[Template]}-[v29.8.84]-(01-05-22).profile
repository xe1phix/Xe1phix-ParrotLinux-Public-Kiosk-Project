## ------------------------------------------------------------ ##
##   [?] Firejail profile for $Profile
## ------------------------------------------------------------ ##
## 
## ------------------------------------------------------------ ##
##   [?] This file is overwritten after every install/update
## ------------------------------------------------------------ ##
## 
## 
## ------------------------------------------------------- ##
##  [+] Persistent local customizations
## ------------------------------------------------------- ##
## include $Profile.local
## 
## ------------------------------------------------------- ##
##  [+] Persistent global definitions
## ------------------------------------------------------- ##
## include $Globals.local
## ------------------------------------------------------- ##



## --------------------------------------------------------------- ##
## noblacklist ${HOME}/.$Directory
noblacklist ${HOME}/Downloads/
## --------------------------------------------------------------- ##
## read-write ${HOME}/Downloads/Telegram Desktop/
whitelist ${HOME}/Downloads/
## read-only ${HOME}/Downloads/
## read-only ${HOME}/.$Directory
## read-only ${HOME}/.mozilla
## --------------------------------------------------------------- ##
## blacklist /etc/$Directory
## blacklist ${HOME}/.$Directory
## blacklist ${HOME}/Downloads/
## --------------------------------------------------------------- ##
## firejail --read-only=~/.mozilla firefox
## firejail --read-write=${HOME}/Downloads/
## --------------------------------------------------------------- ##
## read-only /run/resolvconf/resolv.conf
## read-only /etc/resolv.conf
## read-only /etc/resolv.conf.head
## read-only /etc/firejail/
## --------------------------------------------------------------- ##
## blacklist /mnt
## blacklist /boot
## blacklist /media
## blacklist /run/media
## blacklist /run/mount
## read-only /usr/local/bin
## --------------------------------------------------------------- ##


## --------------------------------- ##
## mkdir $Directory
## mkfile $File
## bind $File1,$File2
## bind $Directory1,$Directory2
## --------------------------------- ##


include disable-common.inc
include disable-devel.inc
include disable-exec.inc
include disable-interpreters.inc
include disable-passwdmgr.inc
include disable-programs.inc
include disable-xdg.inc
include disable-write-mnt.inc
include disable-shell.inc


## ------------------------------------------------ ##
## include /etc/firejail/disable-common.inc
## include /etc/firejail/disable-devel.inc
## include /etc/firejail/disable-interpreters.inc
## include /etc/firejail/disable-passwdmgr.inc
## include /etc/firejail/disable-programs.inc
## include /etc/firejail/disable-xdg.inc
## include /etc/firejail/disable-exec.inc
## include /etc/firejail/disable-write-mnt.inc
## include /etc/firejail/disable-shell.inc
## ------------------------------------------------ ##


## ------------------------------------------------ ##
## include allow-bin-sh.inc
## include allow-common-devel.inc
## include whitelist-common.inc
## whitelist-player-common.inc
## include whitelist-runuser-common.inc
## include whitelist-usr-share-common.inc
## include whitelist-var-common.inc
## ------------------------------------------------ ##


## ------------------------------------------------ ##
## 				Mullvad DNS Server
## ------------------------------------------------ ##
dns 193.138.218.74

## ------------------------------------------------ ##
## 			Backplane OpenNIC DNS Server
## ------------------------------------------------ ##
dns 172.98.193.62


##-===================================================-##
##   [+] Run program inside of a Network_Namespace
##-===================================================-##
## --------------------------------------------------- ##
##   [?] Must first be created, then configured using "ip netns"
## --------------------------------------------------- ##

## -------------------------------------- ##
## netns $Namespace
## firejail --netns=
## -------------------------------------- ##



## -------------------------------------- ##
## firejail --netstats
## firejail --list
## firejail --tree
## firejail --top
## -------------------------------------- ##
## firejail --net.print=$PID
## firejail --netfilter.print=$PID
## firejail --netfilter6.print=$PID
## firejail --seccomp.print=$PID
## firejail --caps.print=$PID
## firejail --dns.print=$PID
## firejail --fs.print=$PID
## firejail --profile.print=$PID
## firejail --protocol.print=$PID
## -------------------------------------- ##
##  
## ------------------------------------------- ##
##    [?] Print control group information
## ------------------------------------------- ##
##  firemon --cgroup


## ---------------------------------------------------------------------- ##
##   [?] Trace the syscalls being used during execution with STrace:
## ---------------------------------------------------------------------- ##
## sudo strace -u $USER $StraceOptions firejail $Syntax
##  
##  
## ---------------------------------------------------------------------- ##
##   [?] Trace the syscalls being used during execution with STrace:
## ---------------------------------------------------------------------- ##
##  firejail  --allow-debuggers --profile=/etc/firejail/firefox.profile strace -f firefox



## ---------------------------------------------------------------------------- ##
##   [?] Firejail uses Linux namespaces, seccomp-bpf and Linux capabilities
## ---------------------------------------------------------------------------- ##
##   [?] Firejail can work in a SELinux or AppArmor environment, 
##   [?] Firejail integrates with Linux Control Groups.
## ---------------------------------------------------------------------------- ##


##-==============================================================-##
##    [+] firejail-ui - Firejail sandbox configuration wizard
##-==============================================================-##


##-=====================================================-##
##    [+] sandbox file manager (firemgr) application
##-=====================================================-##



## -------------------------------------------------- ##
##   [+] enable Firetools to start automatically 
##   [?] when you log into your desktop by running:
## -------------------------------------------------- ##
##  firetools --autostart



## ----------------------------------------------------------------------- ##
##   [+] Segmentation faults
## ----------------------------------------------------------------------- ##
##  [?] Check your system logs. There may be blocked syscalls 
##  [?] which are logged by audit when this profile uses seccomp.
## ----------------------------------------------------------------------- ##



## ----------------------------------------------------------------------- ##
##   [?] You can create, modify, and shape Firejails default profile.
## ----------------------------------------------------------------------- ##
##   
## ------------------------------------------------------------ ##
##   [?] Firejails default profile (global) configuration
##        Can be found at the following location:
## ------------------------------------------------------------ ##
##   [+] /etc/firejail/default.profile
## ------------------------------------------------------------ ##
##  
## ------------------------------------------------ ##
##   firejail --profile=default /usr/bin/$Binary
## ------------------------------------------------ ##



##-==========================-##
##    [+] firejail.config
##-==========================-##
##  
## ------------------------------------------------------------ ##
##   [+] firejail.config
## ------------------------------------------------------------ ##
##   [+] firejail.config.dpkg-dist
## ------------------------------------------------------------ ##
##  
## ------------------------------------------------------------ ##
##   [+] include /etc/firejail/$File.profile
## ------------------------------------------------------------ ##
##   [+] include ~/.config/firejail/
## ------------------------------------------------------------ ##
##   [+] include ~/.local/share/applications/
## ------------------------------------------------------------ ##
##  
##  
## ----------------------------------------------------------------------- ##
##   [?] Show the current configuration being used in firejail.config:
## ----------------------------------------------------------------------- ##
## grep overlayfs /etc/firejail/firejail.config



##-============================================-##
##   [+] Remove all firejail symbolic links:
##-============================================-##
##  sudo firecfg --debug --clean
##  
##  
##-===================================================================-##
##   [+] Firecfg - Desktop integration utility for Firejail software
##-===================================================================-##
## ------------------------------------------------------------------- ##
##   [?] Checks .desktop files in /usr/share/applications/
## ------------------------------------------------------------------- ##
##   [?] set or update the symbolic links for desktop integration
## ------------------------------------------------------------------- ##
##   [?] Fix .desktop files in $HOME/.local/share/applications/ 
## ------------------------------------------------------------------- ##
##   [?] Load and force the AppArmor profile "firejail-default"
## ------------------------------------------------------------------- ##
##  sudo firecfg --debug --fix
##  
##  
## ------------------------------------------- ##
##   [?] List all firejail symbolic links:
## ------------------------------------------- ##
##  firecfg --list


##-=========================================================-##
##    [+] firejail.users - Firejail user access database
##-=========================================================-##
##  cat /etc/firejail/firejail.users
##  sudo firecfg --add-users $user
##  
##  
##-==========================================-##
##   [+] Add the current user to the 
##       Firejail user access database:
##-==========================================-##
## sudo firecfg --debug --add-users $User
##  
##  
##-===============================================-##
##   [+] Create  a special firejail user group:
##-===============================================-##
## ---------------------------------------------------------------- ##
##  [?] (Allowing only users in this group to run the sandbox)
## ---------------------------------------------------------------- ##
## addgroup --system firejail
## chown root:firejail /usr/bin/firejail
## chmod 4750 /usr/bin/firejail



##-======================================-##
##    [+] Regular Profiles (.profile) 
##-======================================-##
##  
## --------------------------------------------------------------------------------- ##
##  [?] Regular Profiles (.profile) use the firejail directory: /etc/firejail/
## --------------------------------------------------------------------------------- ##




##-===================================================-##
##    [+] Persistent global File (globals.local):
##-===================================================-##
## --------------------------------------------------------------------------------- ##
##  [?] globals.local is a special override file, 
## --------------------------------------------------------------------------------- ##
##  [?] It overrides (.local) files, and affects every regular profile.
## --------------------------------------------------------------------------------- ##
##  include globals.local




##-==========================================================-##
##    [+] firejail --build - Automatic profile generation
##-==========================================================-##
## ---------------------------------------------------------- ##
##  [?] builds a whitelisted profile.
## ---------------------------------------------------------- ##
##  [?] The profile is printed on the screen.
## ---------------------------------------------------------- ##
##  [?] strace builds a whitelisted seccomp profile
## ---------------------------------------------------------- ##
##  Examples:
##  firejail --build vlc ~/Videos/test.mp4
##  firejail --build=vlc.profile vlc ~/Videos/test.mp4
## ---------------------------------------------------------- ##


##-====================================================-##
##    [+] Make A symbolic link to /usr/bin/firejail
##-====================================================-##
## ---------------------------------------------------- ##
##  [?] So when programs are ran, they will start
##  [?] using a Firejail sandbox by default.
## ---------------------------------------------------- ##
##  sudo ln -s /usr/bin/firejail /usr/local/bin/firefox
## 
## ----------------------- ##
##    [?] Verify $PATH
## ----------------------- ##
##  which -a firefox /usr/local/bin/firefox /usr/bin/firefox




## ------------------------------------------------ ##
## firejail --net=eth0 --veth-name=eth0.vlan100
## ------------------------------------------------ ##
## net eth0
## veth-name eth0.vlan100


## ------------------------------------------------------------------------------ ##
## firejail --ip=192.168.1.68 --netmask=255.255.255.0 --defaultgw=192.168.1.1
## firejail --net=br0 --ip=10.10.20.5 --net=br1 --net=br2
## ------------------------------------------------------------------------------ ##
## ip 192.168.1.68
## defaultgw 192.168.1.1



## ------------------------------------------------------ ##
##   [+] Acquire an IP address and default gateway
## ------------------------------------------------------ ##
##  [?] Firejail uses ISC dhclient DHCP client
##  
## ----------------------------------------------------------------------------- ##
## 
##  ______________________________________________________________________
## |______________________________________________________________________|
##  |__DHCP Client__| |_DHCP-Server_| |_DHCP-Client_|   |__DHCP-Server___|
##    DHCP Discover --> DHCP Offer <-- DHCP Request -->  DHCP Acknowledge
## 
## ----------------------------------------------------------------------------- ##
## 
## ------------------------------------------------------ ##
## net br0
## ip dhcp
## 
## ------------------------------------------------------ ##
##   [+] Acquire  an IPv6 address and default gateway from 
## ------------------------------------------------------ ##
## net br0
## ip6 dhcp
## ------------------------------------------------------ ##




## -------------------------------------- ##
## interface eth0
## firejail --interface=eth0
## firejail --net=eth0 --ip=10.10.20.56
## -------------------------------------- ##
## mac $MacAddress
## firejail --mac=$MacAddress
## -------------------------------------- ##
## hostname $Hostname
## firejail --hostname=$Hostname
## -------------------------------------- ##
## iprange $IP,IP
## firejail --iprange=$IP,IP
## firejail --iprange=192.168.1.100,192.168.1.150
## -------------------------------------- ##
## netmask 255.255.255.0
## firejail --netmask=255.255.255.0
## -------------------------------------- ##



## -------------------------------------------------------- ##
## /usr/share/doc/firejail/syscalls.txt
## -------------------------------------------------------- ##
## firejail --seccomp=@clock,mkdir,unlinkat transmission-gtk
## firejail --seccomp=unlinkat:ENOENT,utimensat,utimes
## -------------------------------------------------------- ##
## firejail --seccomp.drop=utime,utimensat,utimes,@clock
## firejail --seccomp.drop=unlinkat:ENOENT,utimensat,utimes
## -------------------------------------------------------- ##
## seccomp.drop $Syscall
## -------------------------------------------------------- ##
## firejail --seccomp.keep=poll,select transmission-gtk
## seccomp.keep $Syscall
## -------------------------------------------------------- ##
## seccomp-error-action ERRNO
## seccomp-error-action kill
## seccomp-error-action log
## -------------------------------------------------------- ##
## firejail --seccomp-error-action=kill
## firejail --seccomp-error-action=log
## firejail --seccomp-error-action=ERRNO
## -------------------------------------------------------- ##
## seccomp.block-secondary
## firejail --seccomp.block-secondary
## -------------------------------------------------------- ##
seccomp




##-===============================================-##
##   [+] AppArmor Security Sandbox Confinement
##-===============================================-##
## ----------------------------------------------- ##
## apparmor
## firejail --apparmor
## ----------------------------------------------- ##



##-=====================================-##
##   [+] Enable AppArmor Confinement
##-=====================================-##
## ----------------------------------------------------------------- ##
##  [?] AppArmor support is disabled by default at compile time. 
## ----------------------------------------------------------------- ##
##  [?] Use --enable-apparmor configuration option to enable it:
## ----------------------------------------------------------------- ##
##  ./configure --prefix=/usr --enable-apparmor
## 
## 
## --------------------------------- ##
##  systemctl enable apparmor
##  systemctl start apparmor
##  /etc/init.d/apparmor start
## --------------------------------- ##
## 
## 
## ----------------------------------------------------- ##
##  [?] The AppArmor profile file (firejail-default) 
##  [?] is placed in /etc/apparmor.d
## ----------------------------------------------------- ##
## 
## 
## ----------------------------------------------------- ##
##  [?] The local customizations must be placed in 
## ----------------------------------------------------- ##
##  [?] /etc/apparmor.d/local/firejail-local
## 
## 
## ----------------------------------------------------- ##
##  [?] The profile needs to be loaded into the kernel 
##      by reloading apparmor.service.
## ----------------------------------------------------- ##
##  service apparmor reload
##  /etc/init.d/apparmor restart
##  systemctl enable restart
## 
## 
##-===================================================================-##
##   [+] apparmor_parser - loads AppArmor profiles into the kernel
##-===================================================================-##
## apparmor_parser --verbose -r /etc/apparmor.d/firejail-default
## 
## 
##-===============================================-##
##   [+] Enforce all of the AppArmor profiles 
##       in the /etc/apparmor.d/ directory:
##-===============================================-##
##  apparmor_parser --verbose -r /etc/apparmor.d/*
## 
## 
## 
## ---------------------------------------------------------------- ##
##    [?] You may need to mount the securityFS into the kernel:
## ---------------------------------------------------------------- ##
##  mount -tsecurityfs securityfs /sys/kernel/security
## 
## 
## ------------------------------------------------- ##
##   [?] See if AppArmor is Loaded and Enabled 
##   [?]         (should print “Y”):
## ------------------------------------------------- ##
##  cat /sys/module/apparmor/parameters/enabled
## 
## 
## ---------------------------------------------------------------- ##
##  cat /sys/kernel/security/apparmor/profiles
## ---------------------------------------------------------------- ##
##  cat /sys/kernel/security/apparmor/policy/profiles/
## ---------------------------------------------------------------- ##
##  cat /sys/kernel/security/apparmor/profiles | grep firejail
## ---------------------------------------------------------------- ##
## 
##
##-======================================================================-##
##   [+] aa-status - Report The Current State of AppArmor Confinement
##-======================================================================-##
##  sudo apparmor_status --verbose
## 
## 
##-========================================================================-##
##   [+] aa-complain - Set an AppArmor Security Profile To Complain Mode
##-========================================================================-##
## ------------------------------------------------------------------------ ##
##  [?] In complain mode, the security policy is not enforced 
##  [?] but rather access violations are logged to the system log.
## ------------------------------------------------------------------------ ##
## 
## -------------------------------------------------- ##
##   [+] Place all of the apparmor profiles 
##       in /etc/apparmor.d/* into complain mode:
## -------------------------------------------------- ##
##  sudo aa-complain /etc/apparmor.d/*
## 
## 
##-======================================================================-##
##   [+] aa-enforce - set an AppArmor security profile to enforce mode
##-======================================================================-##
## 
## -------------------------------------------------- ##
##   [+] Place all of the apparmor profiles 
##       in /etc/apparmor.d/* into enforce mode:
## -------------------------------------------------- ##
##  sudo aa-enforce /etc/apparmor.d/*
## 
## 
##-===============================================-##
##   [+] Enforce the Firejail AppArmor profile:
##-===============================================-##
##  sudo aa-enforce firejail-default



##-============================================-##
##   [+] Linux Capabilities (POSIX 1003.1e)
##-============================================-##
## 
## ------------------------------- ##
## caps.keep $Caps
## caps.drop $Caps
## ------------------------------- ##
## 
## ------------------------------------------------------------------------------------------------------ ##
## firejail --caps.keep=chown,net_bind_service,setgid,setuid /etc/init.d/nginx start
## firejail --caps.keep=chown,sys_resource,net_bind_service,setuid,setgid /etc/init.d/apache2 start
## ------------------------------------------------------------------------------------------------------ ##
caps.drop all



##-===================================================-##
##   [+] CGroup v2 (Linux Control Groups)
##-===================================================-##
## --------------------------------------------------- ##
##   [?] The sandbox is placed in g1 control group
## --------------------------------------------------- ##
## cgroup /sys/fs/cgroup/g1/tasks
## firejail --cgroup=/sys/fs/cgroup/g1/tasks
## --------------------------------------------------- ##


##-=================================================================-##
##   [+] IPC Namespoace Isolation
##-=================================================================-##
## ----------------------------------------------------------------- ##
##   [?] Resource isolation for IPC Objects, and IPC Identifiers,
## ----------------------------------------------------------------- ##
## ipc-namespace
## firejail --ipc-namespace
## ------------------------------- ##


##-====================================================================-##
##   [+] NoNewPrivledges - 
##-====================================================================-##
## -------------------------------------------------------------------- ##
##   [?] Ensures that child processes cannot acquire new privileges.
## -------------------------------------------------------------------- ##
## 
## ------------------------------- ##
## firejail --nonewprivs
## ------------------------------- ##
nonewprivs


##-================================================-##
##   [+] User Namespace Isolation
##-================================================-##
## ------------------------------------------------ ##
##   [+] Run program inside of a User_Namespace
## ------------------------------------------------ ##
## firejail --noroot
## ------------------------------------------------ ##
noroot


## --------------------------------------------------- ##
##   [+] OverlayFS - Mount an Overlay Filesystem 
## --------------------------------------------------- ##
## overlay
## firejail --overlay
## --------------------------------------------------- ##
## grep overlayfs /etc/firejail/firejail.config






## ----------------------- ##
##   [+] iptables.xml
## ----------------------- ##
##   [+] nolocal.net
## ----------------------- ##
##   [+] nolocal6.net
## ----------------------- ##
##   [+] webserver.net
## ----------------------- ##


## --------------------------------------------------- ##
## netfilter /etc/iptables/$File
## firejail --netfilter
## --------------------------------------------------- ##
## firejail --netfilter=/etc/iptables/$File
## firejail --netfilter=/etc/firejail/nolocal.net
## firejail --netfilter=/etc/firejail/nolocal6.net
## firejail --netfilter=/etc/firejail/webserver.net
## --------------------------------------------------- ##
## firejail --netfilter.print=
## firejail --netfilter6.print=
## --------------------------------------------------- ##



## ------------------------------------------ ##
##   [+] 
## ------------------------------------------ ##
## machine-id
## firejail --machine-id
## ------------------------------------------ ##



## ------------------------------------------ ##
##   [+] Disable DVD and audio CD devices
## ------------------------------------------ ##
nodvd



## ------------------------------------------ ##
##   [+] 
## ------------------------------------------ ##
## 
## ------------------------------------------ ##
noroot


## ------------------------------------------ ##
##   [+] 
## ------------------------------------------ ##
## 
## ------------------------------------------ ##
notv


## ------------------------------------------ ##
##   [+] 
## ------------------------------------------ ##
## 
## ------------------------------------------ ##
nogroups



## ------------------------------------------ ##
##   [+] 
## ------------------------------------------ ##
## 
## ------------------------------------------ ##
## timeout hh:mm:ss
## firejail --timeout=hh:mm:ss
## ------------------------------------------ ##
## firejail --timeout=01:30:00 firefox
## ------------------------------------------ ##


## ------------------------------------------------ ##
##   [+] 
## ------------------------------------------------ ##
## firejail --shell=none
## firejail --shell=/bin/dash script.sh
## ------------------------------------------------ ##
shell none


## ------------------------------------------------ ##
##   [+] 
## ------------------------------------------------ ##
## firejail --protocol=unix,inet
## ------------------------------------------------ ##
protocol unix,inet,netlink




## ------------------------------------------------ ##
##   [+] 
## ------------------------------------------------ ##
## net none
## firejail --net=none vlc
## firejail --protocol=unix,inet
## ------------------------------------------------ ##



## ------------------------------------------------ ##
##   [+] 
## ------------------------------------------------ ##
## tracelog
## firejail --tracelog
## firejail --trace 
## firejail --trace $Program
## ------------------------------------------------ ##



## ------------------------------------------------ ##
##   [+] 
## ------------------------------------------------ ##
## read-only ${HOME}



## ------------------------------------------------ ##
##   [+] 
## ------------------------------------------------ ##
noexec /tmp
noexec ${HOME}/




## ------------------------------------------------ ##
##   [+] 
## ------------------------------------------------ ##
disable-mnt




## ------------------------------------------ ##
##   [+] 
## ------------------------------------------ ##
## firejail --private
## firejail --private=$Dir
## firejail --private-home=$Dir
## ------------------------------------------------ ##
## firejail --private=/home/$User/firejail-home
## firejail --private-home=.mozilla firefox
## ------------------------------------------------ ##
## private



## ------------------------------------------ ##
##   [+] 
## ------------------------------------------ ##
##  firejail --private-dev
## ------------------------------------------ ##
private-dev


## ------------------------------------------ ##
##   [+] 
## ------------------------------------------ ##
##  firejail --private-cache
## ------------------------------------------ ##
private-cache


## ------------------------------------------ ##
##   [+] 
## ------------------------------------------ ##
##  firejail --private-etc=
## ------------------------------------------ ##
## private-etc alsa,alternatives,ca-certificates,crypto-policies,fonts,group,ld.so.cache,localtime,machine-id,os-release,pki,pulse,resolv.conf,ssl,xdg




## ------------------------------------------ ##
##   [+] 
## ------------------------------------------ ##
## firejail --private-tmp
## ------------------------------------------ ##
private-tmp



## ------------------------------------------ ##
##   [+] 
## ------------------------------------------ ##
## 
## ------------------------------------------ ##
## 
## ----------------------------------------------------------------- ##
## firejail --dbus-user=none
## firejail --dbus-user=filter --dbus-user.log
## firejail --dbus-user=filter --dbus-user.own=org.gnome.foo.*
## ----------------------------------------------------------------- ##



## ------------------------------------------ ##
##   [+] 
## ------------------------------------------ ##
## memory-deny-write-execute
