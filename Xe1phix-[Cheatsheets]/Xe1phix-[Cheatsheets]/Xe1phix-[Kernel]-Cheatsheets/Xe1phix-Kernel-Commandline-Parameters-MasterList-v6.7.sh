#!/bin/sh


cat /proc/cmdline
BOOT_IMAGE=/boot/vmlinuz-4.14.0-parrot13-amd64 root=UUID=f60cfaf7-af83-4b2d-b630-820855cf0868 ro initrd=/install/initrd.gz noautologin nonet noipv6 security=apparmor apparmor=1 errors=remount-ro x11failsafe xmodule=vesa kalsr modprobe.blacklist=drm,radeon powersaved=off noresume debug noefi noconfig=sudo lang=us edd=off vga=normal rfkill.default_state=0 rfkill.master_switch_mode=2 nonfs time loglevel=9 acl user_xattr data=journal barrier=1 journal_checksum




########################################################
			Boot Time Kernal Modifications: 
########################################################


################################################################################################################
fstab 					Mount Description Options
################################################################################################################
auto 					File system will be mounted automatically at boot time.
noauto 					File system will not be mounted automatically at boot time.
dev 					Allows interpretation of block or character special devices on this file system.
nodev 					Does not interpret block or character special devices on this file system.
exec 					Execution of binaries is allowed on this file system.
noexec 					Execution of binaries is NOT allowed on this file system.
suid 					setuid bits are allowed to take effect on this file system.
nosuid 					setuid bits are not allowed to take effect on this file system.
user 					Normal users can mount this device.
nouser 					Only root users can mount this device.
owner 					Allows the owner of the device to mount the file system.
ro 						File system will be mounted read-only.
rw 						File system will be mounted read-write.
defaults 				default options as rw, suid, dev, exec, auto, nouser, and async.
silent                  Turn on the silent flag.
loud                    Turn off the silent flag
lazytime                Only update times (atime, mtime, ctime) on the in-memory version of the file inode.
nolazytime              Do not use the lazytime feature
diratime                Update directory inode access times on this filesystem.
nodiratime              Do  not update directory inode access times on this filesystem.
dirsync                 All directory updates within the filesystem should be done synchronously.
async                   All I/O to the filesystem should be done asynchronously.
sync                    All I/O to the filesystem should be done synchronously.
atime                   Do not use the noatime feature, so the inode access time is controlled by kernel defaults.
noatime                 Do  not  update inode access times on this filesystem 
nofail                  Do not report errors for this device if it does not exist.
_netdev                 The  filesystem  resides  on  a device that requires network access
iversion                Every time the inode is modified, the i_version field will be incremented.
noiversion              Do not increment the i_version inode field.
mand                    Allow mandatory locks on this filesystem.  See fcntl(2).
nomand                  Do not allow mandatory locks on this filesystem.
loop                    Mount as a loop device
offset=$Bytes           Specify Offset
show_sys_files          System Files
streams_interface=$1    Streams
remount                 Attempt to remount an already-mounted filesystem.

fscontext				Provide SELinux security context to those file systems without one.
context=
context="system_u:object_r:removable_t"
context="system_u:object_r:tmp_t:s0:c127,c456

rootcontext=
fscontext=
defcontext=






X-mount.mkdir[=mode]    
group 					Users that belong to the device’s group can mount it
nomodeset 				Disable Kernel mode setting.
systemd.unit=rescue 	Boot to single­user mode (root).
systemd.unit=multi­ user Boot to a specified runlevel.
init=/bin/sh 			Boot to shell.
initrd= 				Specify the location of the initial ramdisk.
root= 					Root filesystem.





vFAT Filesystem Mount Options:

sys_immutable




Mount options for affs


uid=$Value
gid=$Value
setuid=$Value
setgid=$Value
mode=0755|0644|0620|0600|0400


#####################################################
	Sample umask values and their effects
#####################################################
 Umask 	 Created files 			Created directories
#####################################################
| 000 |	0666 | (rw-rw-rw-) 	  | 0777 | (rwxrwxrwx)	|
| 002 |	0664 | (rw-rw-r--) 	  | 0775 | (rwxrwxr-x)	|
| 022 |	0644 | (rw-r--r--) 	  | 0755 | (rwxr-xr-x)	|
| 027 |	0640 | (rw-r-----) 	  | 0750 | (rwxr-x---)	|
| 077 |	0600 | (rw-------) 	  | 0700 | (rwx------)	|
| 277 |	0400 | (r--------) 	  | 0500 | (r-x------)	|
#####################################################




protect             Do not allow any changes to the protection bits on the filesystem.

usemp               Set  UID and GID of the root of the filesystem to the UID and GID of the mount point upon the first sync or umount, and then clear this option.

verbose             Print an informational message for each successful mount.

prefix=$String       Prefix used before volume name, when following a link.

volume=$String       Prefix (of length at most 30) used before '/' when following a symbolic link.

reserved=$Value      (Default: 2.) Number of unused blocks at the start of the device.

root=$Value          Give explicitly the location of the root block.

bs=512|1024|2048|4096            Give blocksize.  Allowed values are 512, 1024, 2048, 4096.

grpquota
noquota
quota
usrquota






Mount options for iso9660





mount --verbose --namespace /proc/1/ns/mnt

ls -l /proc/$$/ns
readlink /proc/$$/ns/uts
setns




modules_load=





systemd.run=

systemd.unit=emergency.target
systemd.unit=rescue.target
systemd.debug-shell
systemd.mask=
systemd.wants=

systemd.firstboot=







systemd.setenv=



SyslogFacility=kern, user, mail, daemon, auth, syslog, lpr, news, uucp,cron, authpriv, ftp, local0, local1, local2, local3, local4, local5, local6 or local7

SyslogLevelPrefix=
SyslogLevel=emerg, alert,crit, err, warning, notice, info, debug



StandardOutput=
StandardError=journal|syslog|kmsg


systemd-journald
sd-journal
systemd.netdev
systemd-resolved.service
systemd-networkd.service
networkctl
networkd.conf
systemd.dnssd
machine-info

/proc/sys/net/ipv6/conf/ifname/disable_ipv6


systemd.link

/usr/share/doc/ecryptfs-utils/ecryptfs-faq.html





fsck.mode=		[auto|force|skip]			## "auto" checks are done when the file system checker deems them necessary. 
											## "force" unconditionally results in full file system checks.
											## "skip" skips any file system checks.

fsck.repair=	[preen|yes|no]				## "yes" will answer yes to all questions by fsck
											## "preen", and will automatically repair problems that can be safely fixed.
											## "no" will answer no to all


systemd.log_target= 
systemd.log_level=
systemd.log_location=


modprobe.blacklist=btsdio,btusb,appletalk,hfs,hfsplus,efivars,efivarfs,efi-pstore,efibc,appletouch,thunderbolt_net,btintel,btrtl,hid-apple,hid-microsoft,nfc,nfc_digital,nfcsim,nfs,nfs_acl,nfsd,nfs_layout_flexfiles,nfs_layout_nfsv41_files,nfsv2,nfsv3,nfsv4,cifs


systemd.mask=bluetooth,ModemManager,mysql,postgresql,printer,apache2,nginx,httpd,iscsi,iscsid,rpcbind,rpc-statd-notify,rpcgssd,rpcsvcgssd,rpcidmapd,rpcsvcgssd,quotarpc,rwhod,pppd-dns,freeradius,ptunnel,miredo,dns2tcp,atftpd,nmbd,minissdpd,dradis,ldap,samba-ad-dc,mariadb,saned,strongswan,thin,ipsec,isc-dhcp-server,fio,fcoe,rsync,radvd,rarpd,rdisc,beef-xss,pppd-dns,arpwatch,nfs-server,mountnfs,libbluetooth3,redis,redis-server,apt-daily,cups,cups-browsed,geoclue,winbind,snmpd,dovecot,tomcat5,exim4,sendmail,smbd,mysqld,lighttpd,nfs,couchdb


systemd.wants=cgroupfs-mount,paxctld,snort,sagan,gnunet,firewalld,logrotate,smartd,cron,smartmontools,vtun,openvpn,conntrackd,nftables,ebtables,samhain,auditd,suricata,libvirtd,libvirtd-guests,qemu-guest-agent,libvirt-guests,virtlogd,tinc,tor,i2p,onioncat,shadowsocks,redsocks,lxc,lxcfs,darkstat,ippl,pcapdump,ntopng,nfdump,flow-control,firehol,fireqos,sysstat,collectd,stunnel4,zfs-import,zfs-import-scan,zfs-import-cache,zfs-fuse,zfs-mount,zfs-zed,zfs-share,mountdebugfs,wg-quick




mount.usr=                          ## Configures the /usr file system (if required)
mount.usrfstype=                    ## Configures the /usr file system type
mount.usrflags=                     ## Configures the /usr file system mount options





roothash=
systemd.verity=                     ## Configures the integrity protection root hash for the root file system
rd.systemd.verity=
systemd.verity_root_data=
systemd.verity_root_hash=

           
           
root=
rootfstype=
rootflags=




udev.log_priority=|err|info|debug|						## Set the log level.
rd.udev.log_priority=



udev.children_max=						## Limit the number of events executed in parallel.
rd.udev.children_max=



udev.exec_delay=						## Delay the execution of RUN instructions by the given number of seconds. 
										## This option might be useful when debugging
										## system crashes during coldplug caused by loading non-working kernel modules.
rd.udev.exec_delay=						



udev.event_timeout= 					## Wait for events to finish up to the given number of seconds.
										## This option might be useful if events are terminated due to
										## kernel drivers taking too long to initialize.
rd.udev.event_timeout=

net.ifnames=							## Network interfaces are renamed to give them predictable names when possible.
net.naming-scheme=

resolve_names=|early|late|never|











systemd.log_target=journal-or-kmsg
systemd.log_target=console
systemd.log_target=kmsg
systemd.log_level=debug
systemd.show_status=1
systemd.show_status

systemd.log_target=
systemd.log_level= 
systemd.log_location= 
systemd.log_color=
systemd.default_standard_output= 
systemd.default_standard_error=

systemd.dump_core
systemd.crash_chvt
systemd.crash_shell
systemd.crash_reboot
systemd.volatile=
systemd.confirm_spawn 
systemd.service_watchdogs 
systemd.show_status


x-systemd.automount
x-systemd.device-timeout=1|2|3




quotacheck.mode=



fsck.mode=force|auto
fsck.repair=preen|yes|no

systemd.mask=
systemd.wants=

systemd.restore_state=              ## rfkill.service


systemd.setenv=
systemd.machine_id=
systemd.unified_cgroup_hierarchy
systemd.legacy_systemd_cgroup_controller


systemd.unit=emergency.target
systemd.unit=rescue.target 
systemd.unit=runlevel5.target
systemd.unit=runlevel4.target

locale.LANG=
locale.LANGUAGE=





systemd.crash_shell
systemd.confirm_spawn


modinfo bluetooth
parm:           disable_esco:Disable eSCO connection creation (bool)
parm:           disable_ertm:Disable enhanced retransmission mode (bool)








security.SMACK64=printing user.attr-with-spaces="foo bar"




						      _____________________________________
load_ramdisk=n				 | Load a kernel ramdisk from a floppy |
						## ------------------------------------------- ##
						##   1 = the ramdisk is loaded by the kernel
						##       at boot time from floppy drive.
						## ------------------------------------------- ##



		

noeject						Do NOT eject CD after halt
noprompt					Do NOT prompt to remove the CD
splash						Boot with fancy background splashscreen
desktop=|beryl|fluxbox|		
	|gnome|icewm|kde|
	|lg3d|larswm|twm|
	|openbox|wmaker|
	|xfce|xfce4|



bootfrom=/dev/sda1/Knoppix.iso

screen=1280x1024 			Use specified screen resolution for X
depth=16 					Use specified color depth for X


xvrefresh=60 (or vsync=60) 		## Use 60 Hz vertical refresh rate for X
xhrefresh=80 (or hsync=80) 		## Use 80 kHz horizontal refresh rate for X



xmodule=ati						## Use specified Xorg module
	|fbdev|mga|nv|
	|radeon|savage|
	|svga|i810|s3| 
		
		
wheelmouse				## Enable IMPS/2 protocol for wheel mice
nowheelmouse			## Force plain PS/2 protocol for PS/2 mouse
vga=normal				## No-frame-buffer mode, but X
fb1280x1024				## Use fixed frame-buffer graphics (1)
fb1024x768				## Use fixed frame-buffer graphics (2)
fb800x600				## Use fixed frame-buffer graphics (3)

xmodule=fbdev           ## use the same framebuffer support for X 
                        ## that you use in the console.


mem=256M				## Tell the Linux kernel to use 256 MB of
                        ## RAM, despite what the BIOS might claim




noacpi
noapic
noagp				## Skip parts of hardware detection
noapm
noaudio
noddc
nofirewire
noisapnpbios
nopcmcia
noscsi
noswap
nousb

nofail
Failsafe				Boot with (almost) no hardware detection
pci=bios				Workaround for bad PCI controllers
mem=128M				Specify memory size in megabytes
dma						Enable DMA for all IDE drives
noideraid				Disable IDE RAID detection



lang=us					## Specify language/keyboard
>> |cn|de|da|pl|
>> |ies|fr|t|nl|
>> |ru|sk|tr|tw|
		 
keyboard=us                 ## Use a different console keyboard
xkeyboard=us                ## Use a different X keyboard
tz=America/Los_Angeles      ## Use a particular time zone

nofb                        ## Disable framebuffer

modules_load=				## list of kernel modules to statically load during early boot.
rd.modules_load=			## read by the initial RAM disk only.

noexec=on|off               ## Non Executable Mappings


block_validity=
barrier=1


uid=${luser},
gid=${lgroup},
file_umask=0177

fmask=0177,
dmask=077
mode=0400,
dmode=0500
acl
user_xattr


cdroot_hash=${fshash} 
add_efi_memmap 
blacklist=firewire-sbp2
memtest=1 
loglevel=4
time						## Show timing data on every kernel log message.


apic						## Change the verbosity of the APIC subsystem when booting.
apic=quiet|verbose|debug

vdso						## Enable or disable the VDSO mapping.
vdso=0|1



mce							## Enable the machine check exception feature.
nomce						## Disable the machine check exception feature.
nosep						## Disable x86 SYSENTER/SYSEXIT support.
nosmp						## Run as a single-processor machine.
S							## Run init in single-user mode.


acpi_os_name				## Fake the operating system name to ACPI.
acpi_os_name=$name

processor.max_cstate
processor.max_cstate=n          ## Limit the processor to a maximum C-state.



noisapnp                        ## Disable the ISA Plug and Play (PnP) subsystem.


pnpbios
PnP BIOS settings.
pnpbios= [ on | off | curr | no-curr ]


lp=0                            ## Disables the printer driver.

lp=auto
lp=none,parport0                ## use the first parallel port for lp1, and  disable  lp0. 

parport_init_
mode
Parallel port initialization mode.
parport_init_mode= [ spp | ps2 | epp | ecp | ecpepp ]



clocksource
Set the specific clocksource.
clocksource= [ hpet | pit | tsc | acpi_pm | cyclone | scx200_hrt ]


hashdist
Distribute large hashes across NUMA nodes.
hashdist= [ 0 | 1 ]


max_loop
Maximum number of loopback devices.
max_loop=n                  ##  








pti=on
slab_nomerge
slub_debug=FPZ
nosmt
page_poison=1










crashkernel				    ## Reserve a portion of physical memory for kexec to use.
crashkernel=n [ KMG ]@ start [ KMG ]


elfcorehdr					## Start of the kernel core image ELF header.
elfcorhdr=n












memtest=2                   ## 
earlyprintk=efi             ## 
log_buf_len					## Set the size of the kernel log buffer.

earlyprintk= 				## Show early boot message
vga|serial][,ttySn[,baudrate


add_efi_memmap - include EFI memory map in kernels RAM map
noefi                       ## disable EFI runtime services
efi=nochunk|noruntime
edd=off

ipv6.disable=1
disable_ipv6=1
ipv6.autoconf=0

ca_keys=

data=journal|ordered|writeback
journal_checksum
barrier=1


zfsforce=1
zswap.enabled=1
zswap.zpool=

module=Tails
vsyscall=none
block.events_dfl_poll_msecs=1000

ecryptfskey=

noprompt 
timezone=Etc/UTC 

noautologin 
slab_nomerge 
slub_debug=FZ 
mce=0 





doevms          This enables support for IBM's pluggable EVMS, or Enterprise
                Volume Management System.  This is not safe to use with lvm2.



hda=stroke      This allows you to partition the whole hard disk even when your
                BIOS is unable to handle large disks.  This option is only used
                on machines with an older BIOS.  Replace hda with the device
                that is requiring this option.
ide=nodma       This forces the disabling of DMA in the kernel and is required
                by some IDE chipsets and also by some CDROM drives.  If your
                system is having trouble reading from your IDE CDROM, try this
                option.  This also disables the default hdparm settings from
                being executed.
noapic          This disables the Advanced Programmable Interrupt Controller
                that is present on newer motherboards.  It has been known to
                cause some problems on older hardware.



apm=power-off
libata.force=noncq


ramdisk_size=100000 root=/dev/ram0
ramdisk_blocksize=1024


toram
debug
nosudo
noconfig=sudo
noautologin
noxautologin
userfullname=$USER
integrity-check
{live-media|bootfrom}=$DEVICE
live-media=$Device
bootfrom=$Device

live-media-encryption=$Type
encryption=$Type

{live-media-encryption|encryption}=$TYPE
live-media-offset=$BYTES
live-media-path=$PATH
live-media-timeout=$SECONDS

persistent[=nofiles]
persistent-path=PATH
nopersistent

module=
lp=0

rfkill.default_state=0
rfkill.master_switch_mode=2
systemd.restore_state=1

luks.options=
luks.key=
luks=

fsck.repair=
fsck.mode=

mount.usr=
net.ifnames=




security=tomoyo
TOMOYO_trigger=/usr/lib/systemd/systemd





systemd.setenv=GPUMOD=nvidia
systemd.setenv=GPUMOD=nonvidia




















access=ACCESS
console=TTY,SPEED
fetch=URL
hostname=$HOSTNAME
username=$USER
userfullname=$USER
integrity-check


ip=[CLIENT_IP]:[SERVER_IP]:[GATEWAY_IP]:[NETMASK]:[HOSTNAME]:[DEVICE]:[AUTOCONF]  [,[CLIENT_IP]:[SERVER_IP]:[GATEWAY_IP]:[NETMASK]:[HOSTNAME]:[DEVICE]:[AUTOCONF]]*
ip[=frommedia]
{keyb|kbd-chooser/method}=KEYBOARD
{klayout|console-setup/layoutcode}=LAYOUT
{kvariant|console-setup/variantcode}=VARIANT
{kmodel|console-setup/modelcode}=CODE
koptions=$OPTIONS
live-getty
{live-media|bootfrom}=DEVICE

live-media=$Device
bootfrom=$Device

live-media-encryption=$Type
encryption=$Type

{live-media-encryption|encryption}=TYPE
live-media-offset=$BYTES
live-media-path=$PATH
live-media-timeout=$SECONDS
{locale|debian-installer/locale}=LOCALE
module=NAME

noautologin
noxautologin
nofastboot
nopersistent
nosudo
swapon
nouser
noxautoconfig
persistent[=nofiles]
persistent-path=PATH
{preseed/file|file}=FILE
package/question=VALUE
quickreboot
showmounts
timezone=TIMEZONE
todisk=DEVICE
toram
union=aufs|unionfs
utc=yes|no
xdebconf
xvideomode=RESOLUTION


rfkill.default_state=0
		0	"airplane mode".  All wifi, bluetooth, wimax, gps, fm,
			etc. communication is blocked by default.
		1	Unblocked.

rfkill.master_switch_mode=2
		0	The "airplane mode" button does nothing.
		1	The "airplane mode" button toggles between everything
			blocked and the previous configuration.
		2	The "airplane mode" button toggles between everything
			blocked and everything unblocked.


systemd.restore_state=1				restore the rfkill settings on boot


/lib/systemd/systemd-rfkill

pcimodules
ecryptfs-add-passphrase
ecryptfs-insert-wrapped-passphrase-into-keyring

init_module
kernel-install

klogctl
kmem
kmod
dkms
drm-kms
drmAvailable
finit_module
add_key


grub-mkpasswd-pbkdf2
--iteration-count= 


grub-mkconfig -o /boot/grub/grub.cfg
bluetooth.target
printer.target




luks.options=
luks.key=
luks=

fsck.repair=
fsck.mode=

mount.usr=
net.ifnames=





rodata=on       ## Mark read-only kernel memory as read-only (default).
rodata=off      ## Leave read-only kernel memory writable for debugging.


stacktrace      ## Enabled the stack tracer on boot up. [FTRACE] 

stacktrace_filter=[function-list]
			[FTRACE] Limit the functions that the stack tracer
			will trace at boot up.




irqpoll
noirqdebug

_______________________________________________________________________________________________________
 • irqfixup		 				|  [?] Basic fix For issues with your interrupts.
								| --------------------------------------------------------------------
								|  ## This is intended to get systems with badly broken firmware running
								| --------------------------------------------------------------------

_______________________________________________________________________________________________________
 • 		 				|  [?] 
								| --------------------------------------------------------------------
								|  ## 
								| --------------------------------------------------------------------


_______________________________________________________________________________________________________
 • 		 				|  [?] 
								| --------------------------------------------------------------------
								|  ## 
								| --------------------------------------------------------------------

_______________________________________________________________________________________________________
 • 		 				|  [?] 
								| --------------------------------------------------------------------
								|  ## 
								| --------------------------------------------------------------------

_______________________________________________________________________________________________________
 • 		 				|  [?] 
								| --------------------------------------------------------------------
								|  ## 
								| --------------------------------------------------------------------

_______________________________________________________________________________________________________
 • 		 				|  [?] 
								| --------------------------------------------------------------------
								|  ## 
								| --------------------------------------------------------------------




hugepages=n

Set the number of hugetlb pages.

The hugetlb feature lets you configure Linux to use 4 MB pages,
one thousand times the default size.



ihash_entries

Set the number of inode hash buckets.



                                ##-===============================================-##
ihash_entries=$N                ##  [+] Set the number of inode hash buckets.
                                ##-===============================================-##
                                ## 
                                ## --------------------------------------------------------------------------------- ##
                                ##  [?] Override the default number of hash buckets for the kernel’s inode cache. 
                                ## --------------------------------------------------------------------------------- ##
                                ##  [?] Recommended only for kernel experts.
                                ## --------------------------------------------------------------------------------- ##



                                ##-===============================================================-##
mem=nopentium                   ##  [+] Disable the use of huge (4 MB) pages for kernel memory.
                                ##-===============================================================-##




                                ##-===============================================================-##
memmap                          ##  [+] Enable setting of an exact E820 memory map.
                                ##-===============================================================-##
                                
                                
                                ## --------------------------------- ##
memmap=$exactmap                ##  [+] Use a specific memory map. 
                                ## --------------------------------- ##
                                ##
                                ## -------------------------------------------------------------------------------------- ##
                                ##  [?] The exactmap lines can be constructed based on BIOS output or other requirements.
                                ## --------------------------------------------------------------------------------------- ##


                                ##-===============================================================-##
noexec                          ##  [+] Enable or disable nonexecutable mappings.
                                ##-===============================================================-##


                                ##-========================================================-##
noexec= [ on | off ]            ##  [+] Enable or disable the kernel’s ability 
                                ##      to map sections of memory as nonexecutable.
                                ##  [?] By default, the mapping is enabled ( on ).
                                ##-========================================================-##




                                ## ------------------------------------ ##
reserve                         ##   [+] Reserve some I/O memory.
                                ## ------------------------------------ ##

                                ## --------------------------------------------------------------- ##
reserve=n [ KMG ]               ##   [+] Force the kernel to ignore some of the I/O memory areas.
                                ## --------------------------------------------------------------- ##




                                ## -------------------------------------------------- ##
vdso                            ##  [+] Enable or disable the VDSO mapping.
                                ## -------------------------------------------------- ##

                                ## ----------------------------------------------------------- ##
vdso= [ 0 | 1 ]                 ##  [+] Disable ( 0 ) or enable ( 1 ) the VDSO 
                                ##      (Virtual Dynamic Shared Object) mapping option. 
                                ## ----------------------------------------------------------- ##
                                ##  [?] By default, it is enabled.
                                ## ----------------------------------------------------------- ##


                                ## ----------------------------------------------------------- ##
cachesize                       ##  [+] Override level 2 CPU cache size detection.
                                ## ----------------------------------------------------------- ##
                                

                                ## ----------------------------------------------------------- ##
cachesize=n                     ##  [+] Sometimes CPU hardware bugs make them 
                                ##      report the cache size incorrectly.
                                ## ----------------------------------------------------------- ##




                                 ## ----------------------------------------------------------- ##
nmi_watchdog                     ##  [+] Set the NMI watchdog value.
                                 ## ----------------------------------------------------------- ##



                                    ## ------------------------------------------------------------------------------------ ##
nmi_watchdog= [ 0 | 1 | 2 | 3 ]     ##  [+] This is a debugging feature that allows the user to override the
                                    ##      default nonmaskable interrupt (NMI) watchdog value. 0 specifies
                                    ##      that no NMI watchdog should be used. 1 specifies that the APIC
                                    ##      should be used if present. 2 specifies that the local APIC should be
                                    ##      used if present. 3 means that the NMI watchdog is invalid, so Do not use it.
                                    ## ------------------------------------------------------------------------------------ ##





                                 ## ---------------------------------------------------------- ##
mce                              ##   [+] Enable the machine check exception feature.
                                 ## ---------------------------------------------------------- ##
                                 ##  [?] Some processors can check for machine errors 
                                 ##      (usually errors In the hardware).
                                 ## ---------------------------------------------------------- ##



                                 ## ---------------------------------------------------------- ##
nomce                            ##   [+] Disable the machine check exception feature.
                                 ## ---------------------------------------------------------- ##


                                 ## ---------------------------------------------------------- ##
nosep                            ##   [+] Disable x86 SYSENTER/SYSEXIT support.
                                 ## ---------------------------------------------------------- ##
                                 ##   [+] Disable x86 SYSENTER/SYSEXIT support In the kernel. 
                                 ## ---------------------------------------------------------- ##
                                 ##   [?] This can cause some system calls to take longer.
                                 ## ---------------------------------------------------------- ##


                                 ## ---------------------------------------------------------------------------------------------- ##
nosmp                            ##  [+] Run as a single-processor machine.
                                 ## ---------------------------------------------------------------------------------------------- ##
                                 ##  [?] Tell an SMP kernel to act as a uniprocessor kernel, even on a multiprocessor machine.
                                 ## ---------------------------------------------------------------------------------------------- ##




                                      ## ---------------------------------------------------------------------- ##
maxcpus=$N                            ##  [+] Maximum number of CPUs to use.
                                      ## ---------------------------------------------------------------------- ##
                                      ## Specify the maximum number of processors that a SMP kernel
                                      ## should use, even if there are more processors present In the system.
                                      ## ---------------------------------------------------------------------- ##





                                    ## --------------------- ##
udev.log_priority=                  ## Set the log level
rd.udev.log_priority=               ## --------------------- ##


                                    ## ---------------------------------------------------------- ##
udev.children_max=                  ## Limit the number of events executed In parallel
                                    ## ---------------------------------------------------------- ##

                                    ## ------------------------------------------------------------------------------ ##
udev.exec_delay=                    ## Delay the execution of RUN instructions by the given number of seconds.
rd.udev.exec_delay=                 ## This option might be useful when debugging system crashes during coldplug 
                                    ## caused by loading non-working kernel modules.
                                    ## ------------------------------------------------------------------------------ ##


                                    ## ---------------------------------------------------------- ##
net.ifnames=                        ## Network interfaces are renamed (0 disables it)
                                    ## ---------------------------------------------------------- ##


                                    ## ---------------------------------------------------------- ##
udev_log                            ## The log level. Valid values: err, info, debug.
                                    ## ---------------------------------------------------------- ##





                                    ## ---------------------------------------------------------- ##
acpi_force_table_verification       ## Enable table checksum verification during early stage.
                                    ## ---------------------------------------------------------- ##



                                    ## ------------------------------------------------- ##
acpi_os_name=	                    ## Tell ACPI BIOS the name of the OS Format
                                    ## ------------------------------------------------- ##
                                    ## To spoof as Windows 98: ="Microsoft Windows"
                                    ## ------------------------------------------------- ##












b43.blacklist=yes

nomdmondff

nomdmonisw
























loglevel=						## Set the default console log level.
								## -------------------------------------------------------------------------------- ##
								## 	The kernel log levels are:
								## 								
								##  0). (KERN_EMERG)	| 0 |	|| The system is unusable.
								## -------------------------------------------------------------------------------- ##
								##  1). (KERN_ALERT)	| 1 |	|| Actions that must be taken care of immediately.
								## -------------------------------------------------------------------------------- ##
								##  2). (KERN_CRIT)		| 2 |	|| Critical conditions.
								## -------------------------------------------------------------------------------- ##
								##  3). (KERN_ERR)		| 3 |	|| Noncritical error conditions.
								## -------------------------------------------------------------------------------- ##
								##  4). (KERN_WARNING)	| 4 |	|| 	Warning conditions that should be taken care of.
								## -------------------------------------------------------------------------------- ##
								##  5). (KERN_NOTICE)	| 5 |	|| Normal, but significant events.
								## -------------------------------------------------------------------------------- ##
								##  6). (KERN_INFO)		| 6 |	|| Informational messages that require no action.
								## -------------------------------------------------------------------------------- ##
								##  7). (KERN_DEBUG)	| 7 |	|| Kernel debugging messages
								## -------------------------------------------------------------------------------- ##

								## Set the size of the kernel log buffer.
								## Set the size of the kernel’s internal log buffer.
log_buf_len=n [ KMG ]

								## 
								## 
								## 


								## ======================================================================== ##
initcall_debug					## 				Debug the initcall functions in the kernel.
								## ======================================================================== ##
								## Cause the kernel to trace all functions that are called by the kernel
								## during initialization of the system as the kernel boots. This option
								## is useful for determining where the kernel is dying during startup.
								## ------------------------------------------------------------------------ ##


_______________________________________________________________________________________________________
 •  initcall_debug				|
								|
								|
								|

_______________________________________________________________________________________________________
 • time 						|  Show timing data on every kernel log message.
								|  Cause the kernel to prefix every 
								|  kernel log message with a timestamp.
								|





_______________________________________________________________________________________________________
 •  				|
								|
								|
								|

_______________________________________________________________________________________________________
 • 		 				|  
								|  
								|  
								|  
_______________________________________________________________________________________________________
 • 		 				|  
								|  
								|  
								|  
_______________________________________________________________________________________________________
 • 		 				|  
								|  
								|  
								|  
_______________________________________________________________________________________________________
 • 		 				|  
								|  
								|  
								|  
_______________________________________________________________________________________________________
 • 		 				|  
								|  
								|  
								|  
_______________________________________________________________________________________________________
 • 		 				|  
								|  
								|  
								|  
_______________________________________________________________________________________________________
 • 		 				|  
								|  
								|  
								|  
_______________________________________________________________________________________________________
 • 		 				|  
								|  
								|  
								|  
_______________________________________________________________________________________________________
 • 		 				|  
								|  
								|  
								|  
_______________________________________________________________________________________________________
 • 		 				|  
								|  
								|  
								|  





live-config.debconf-preseed=$filesystem|$medium|$URL
debconf-preseed=$medium|$filesystem|$URL


hostname=$HOSTNAME
LIVE_HOSTNAME="system"
live-config.hostname=$HOSTNAME
live-config.hostname=SELKS 
live-config.hostname=parrot

username=$USER
LIVE_USERNAME="User"
live-config.username=$USER
LIVE_USER_FULLNAME="Debian Live User"
LIVE_USER_FULLNAME="ParrotSec Live User"

LIVE_USER_DEFAULT_GROUPS="audio cdrom dip floppy video plugdev netdev powerdev scanner bluetooth debian-tor"

noroot         | live-config.noroot
nottyautologin | live-config.nottyautologin
nox11autologin | live-config.nox11autologin


LIVE_CONFIG_CMDLINE="${LIVE_CONFIG_CMDLINE:-$(cat /proc/cmdline)}"
export LIVE_CONFIG_CMDLINE




findiso=${iso_path}

live-config.hostname=SELKS 
live-config.user-default-groups=audio,cdrom,floppy,video,dip,plugdev,scanner,bluetooth,netdev,sudo
live-config.user-default-groups="GROUP1,GROUP2 ... GROUPn"
live-config.user-fullname="USER FULLNAME"

noconfig=sudo 
username=user 
user-fullname=User 
hostname=subgraph

blacklist=						Completely disable loading of specified module(s) via
                                blacklisting through udev's /etc/modprobe.d/

libata.dma=0                   Disable DMA on PATA and SATA devices


radeon.modeset=0  nomodeset    Disable Kernel Mode Setting (KMS) for Radeon driver.
i915.modeset=0    nomodeset    Disable Kernel Mode Setting (KMS) for Intel driver.
nouveau.modeset=0 nomodeset    Disable Kernel Mode Setting (KMS) for Nouveau driver.
cirrus.modeset=0  nomodeset    Disable Kernel Mode Setting (KMS) for Cirrus driver.
mgag200.modeset=0 nomodeset    Disable Kernel Mode Setting (KMS) for MGAG200 driver.


libata.dma=0                   Disable DMA on PATA and SATA devices
libata.ignore_hpa=1            Disable host protected area (which should enable the whole disk)


swap                           Activate present/detected swap partitions
noswraid                       Disable scanning for software raid arrays (creates /etc/mdadm/mdadm.conf)
swraid                         Enable automatic assembling of software raid arrays
nodmraid                       Do not enable present dmraid devices.
dmraid=on                      Automatically enable any present dmraid devices.
dmraid=off                     Actively try to stop any present dmraid devices.
nolvm                          Disable scanning for Logical Volumes (LVM)
lvm                            Automatically activate Logival Volumes (LVM) during boot
read-only                      Make sure all harddisk devices (/dev/hd* /dev/sd*) are forced to read-only mode
ethdevice=...                  Use specified network device for network boot instead of default (eth0)
ethdevice-timeout=...          Use specified network configuration timeout instead of default (15sec)
xmodule=ati|fbdev|i810|mga     Use specified X.org-Module (1)
xmodule=nv|radeon|savage|s3    Use specified X.org-Module (2)
xmodule=radeon|svga|i810       Use specified X.org-Module (3)

live-config.xorg-driver=XORG_DRIVER
live-config.xorg-resolution=XORG_RESOLUTION
live-config.x-session-manager=X_SESSION_MANAGER


no{acpi,agp,cpu,dhcp}          Skip parts of HW-detection (1)
no{dma,fstab,modem}            Skip parts of HW-detection (2)
no{pcmcia,scsi,swap,usb}       Skip parts of HW-detection (3)

vnc_connect=host[:port]        Connect to a listening VNC client ("vncviewer -listen" reverse connection).
vnc=password                   Start VNC server with startup of X.org and sets the password

ssh=password                   Set password for root & grml user and start ssh-server
grml passwd=...                     Set password for root & grml user
grml encpasswd=....                 Set specified hash as password for root & grml user, use e.g.
                                    'mkpasswd -H md5' to generate such a hash

startup=script                 Start $script instead of grml-quickconfig on startup
nosyslog                       Do not start syslog daemon
nogpm                          Disable GPM daemon
noconsolefont                  Disable setting of console font (using consolechars)
noblank                        Disable console blanking
noquick                        Disable grml-quickconfig startup script
wondershaper=eth0,1000,500     Set up basic traffic shaping
services={postfix,mysql,...}   Start service(s) which have an init-script (/etc/init.d/)
welcome                        Welcome message via soundoutput
noeject                        Do NOT eject CD after halt/reboot
noprompt                       Do NOT prompt to remove the CD when halting/rebooting the system
live-config.debug

{live-media|bootfrom}=DEVICE
{live-media-encryption|encryption}=TYPE
live-media-offset=BYTES
live-media-path=PATH
live-media-timeout=SECONDS



nouveau.modeset=0 nvidia.modeset=0 radeon.modeset=0


################################################################################################################
Rescue					Instead of installing, run the kernel to open Linux rescue mode.
mediacheck				Check the installation CD/DVD for checksum errors.
nofirewire 				Not to load support for frewire devices
nodma 					Not to load DMA support for hard disks
noide 					Not to load support for IDE devices
nompath 				Not to enable support for multipath devices
noparport 				Not to load support for parallel ports
nopcmcia 				Not to load support for PCMCIA controllers
noprobe 				Not to probe hardware, instead prompt user for drivers
noscsi  				Not to load support for SCSI devices
nousb 					Not to load support for USB devices
noipv6  				Not to enable IPV6 networking
nonet 					Not to probe for network devices
noquota					Do not set users quotas on this partition.
quota					Allow users quotas on this partition.
numa-off 				Disable the Non-Uniform Memory Access (NUMA) for AMD64 architecture
acpi=off 				Disable the Advanced Confguration and Power Interface (ACPI
xdriver=vesa 			Use standard vesa video driver
resolution=1024x768  	Choose exact resolution to use
nofb 				 	Dont use the VGA 16 framebuffer driver
skipddc 				Dont probe DDC of the monitor (the probe can hang the installer)
graphical 				Force a graphical installation
################################################################################################################



##########################################################################
Mount 					options unique to the isofs filesystem
##########################################################################
_________________________________________________________________________
block=512 			{+} Set the block size for the disk to 512 bytes
_________________________________________________________________________
block=1024			{+} Set the block size for the disk to 1024 bytes
_________________________________________________________________________
block=2048			{+} Set the block size for the disk to 2048 bytes
_________________________________________________________________________
check=relaxed 		{+} Matches filenames with different cases
_________________________________________________________________________
check=strict 	    {+} Matches only filenames with the exact same case
_________________________________________________________________________
cruft 				{+} Try to handle badly formatted CDs.
_________________________________________________________________________
map=off 			{+} Do not map non-Rock Ridge filenames to lower case
_________________________________________________________________________
map=normal			{+} Map non-Rock Ridge filenames to lower case
_________________________________________________________________________
map=acorn 
map=normal  		{+} but also apply Acorn extensions if present
_________________________________________________________________________
mode=xxx 			{+} Sets the permissions on files to xxx unless Rock Ridge
						extensions set the permissions otherwise
_________________________________________________________________________
dmode=xxx 			{+} Sets the permissions on directories to xxx unless Rock Ridge
						extensions set the permissions otherwise
_________________________________________________________________________
overriderockperm 	{+} Set permissions on files and directories according to
						'mode' and 'dmode' even though Rock Ridge extensions are
						present.
_________________________________________________________________________
nojoliet			{+} Ignore Joliet extensions if they are present.
_________________________________________________________________________
norock				{+} Ignore Rock Ridge extensions if they are present.
_________________________________________________________________________
hide				{+} Completely strip hidden files from the file system.
_________________________________________________________________________
showassoc			{+} Show files marked with the 'associated' bit
_________________________________________________________________________
unhide				{+} Deprecated; showing hidden files is now default;
						If given, it is a synonym for 'showassoc' which will
						recreate previous unhide behavior
_________________________________________________________________________
session=x 			{+} Select number of session on multisession CD
_________________________________________________________________________
sbsector=xxx		{+} Session begins from sector xxx




/sys/firmware/acpi/tables/SSDT
https://www.kernel.org/doc/Documentation/acpi/initrd_table_override.txt

#######################################################################################

#######################################################################################
__________________________________________________________________________________
acpi=on         This loads support for ACPI and also causes the acpid daemon to
                be started by the CD on boot.  This is only needed if your
                system requires ACPI to function properly.  This is not
                required for Hyperthreading support.
__________________________________________________________________________________#
acpi=off        Completely disables ACPI.  This is useful on some older systems
                and is also a requirement for using APM.  This will disable any
                Hyperthreading support of your processor.
__________________________________________________________________________________
console=X       This sets up serial console access for the CD.  The first
                option is the device, usually ttyS0 on x86, followed by any
                connection options, which are comma separated.  The default
                options are 9600,8,n,1.
__________________________________________________________________________________
dmraid=X        This allows for passing options to the device-mapper RAID
                subsystem.  Options should be encapsulated in quotes.
__________________________________________________________________________________
doapm           This loads APM driver support.  This requires you to also use
                acpi=off.
__________________________________________________________________________________
dopcmcia        This loads support for PCMCIA and Cardbus hardware and also
                causes the pcmcia cardmgr to be started by the CD on boot.
                This is only required when booting from PCMCIA/Cardbus devices.
__________________________________________________________________________________
doscsi          This loads support for most SCSI controllers.  This is also a
                requirement for account    required    pam_unix.sobooting most USB devices, as they use the SCSI
                subsystem of the kernel.
__________________________________________________________________________________
hda=stroke      This allows you to partition the whole hard disk even when your
                BIOS is unable to handle large disks.  This option is only used
                on machines with an older BIOS.  Replace hda with the device
                that is requiring this option.

__________________________________________________________________________________
ide=nodma       This forces the disabling of DMA in the kernel and is required
                by some IDE chipsets and also by some CDROM drives.  If your
                system is having trouble reading from your IDE CDROM, try this
                option.  This also disables the default hdparm settings from
                being executed.
__________________________________________________________________________________
noapic          This disables the Advanced Programmable Interrupt Controller
                that is present on newer motherboards.  It has been known to
                cause some problems on older hardware.
__________________________________________________________________________________
nodetect        This disables all of the autodetection done by the CD,
                including device autodetection and DHCP probing.  This is
                useful for doing debugging of a failing CD or driver.
__________________________________________________________________________________
nodhcp          This disables DHCP probing on detected network cards.  This is
                useful on networks with only static addresses.
__________________________________________________________________________________
nodmraid        Disables support for device-mapper RAID, such as that used for
                on-board IDE/SATA RAID controllers.
__________________________________________________________________________________
nofirewire      This disables the loading of Firewire modules.  This should
                only be necessary if your Firewire hardware is causing
                a problem with booting the CD.
__________________________________________________________________________________
nogpm           This diables gpm console mouse support.
__________________________________________________________________________________
nohotplug       This disables the loading of the hotplug and coldplug init
                scripts at boot.  This is useful for doing debugging of a
                failing CD or driver.
__________________________________________________________________________________
nokeymap        This disables the keymap selection used to select non-US
                keyboard layouts.
__________________________________________________________________________________
nolapic         This disables the local APIC on Uniprocessor kernels.
__________________________________________________________________________________
nosata          This disables the loading of Serial ATA modules.  This is used
                if your system is having problems with the SATA subsystem.
__________________________________________________________________________________
nosmp           This disables SMP, or Symmetric Multiprocessing, on SMP-enabled
                kernels.  This is useful for debugging SMP-related issues with
                certain drivers and motherboards.
__________________________________________________________________________________
nosound         This disables sound support and volume setting.  This is useful
                for systems where sound support causes problems.
__________________________________________________________________________________
nousb           This disables the autoloading of USB modules.  This is useful
                for debugging USB issues.
__________________________________________________________________________________
slowusb         This adds some extra pauses into the boot process for slow
                USB CDROMs, like in the IBM BladeCenter.
__________________________________________________________________________________


preseed/url=https://www.kali.org/dojo/preseed.cfg		allows us to preseed Kali installations securely over SSL.

__________________________________________________________________________________
max_scsi_luns=  ## specify the number of probed LUNs at boot
__________________________________________________________________________________
hd=cdrom        ## tells the IDE driver that there is an ATAPI compatible 
                ## CD-ROM attached in place of a normal IDE hard disk.    
__________________________________________________________________________________
hd=nowerr       ## enables a work-around for drives with the WRERR_STAT bit stuck on permanently.
__________________________________________________________________________________
hd=cyls,heads,  ## specify the physical geometry of the disk
    sects,irq
__________________________________________________________________________________
rootdelay=      ## set the delay (in seconds) to pause before attempting 
                ## to mount the root filesystem.
__________________________________________________________________________________
irqpoll			if some driver hang with irq problem messages
__________________________________________________________________________________

#########################################################################################
#########################################################################################



no3d 
noaudio 
noapm 
noapic 
nolapic
acpi=off 
pci=bios 
pnpbios=off 
nodma 
nopcmcia 
noscsi 
nousb




## XFS


uquota/uqnoenforce		## Userquotas
gquota/gqnoenforce		## Groupquotas
pquota/pqnoenforce		## Projectquota







netboot=|nfs|cifs|

nfsopts=

__________________________________________________________________________________
nfsaddrs=       ## sets the NFS boot address
__________________________________________________________________________________
nfsroot=        ## sets the NFS root name
__________________________________________________________________________________





## ============================================================================================= ##
											NUMA
## ============================================================================================= ##
________________________________________________________________________________________________
numa=off					Only set up a single NUMA node spanning all memory.
________________________________________________________________________________________________
numa=noacpi  				Dont parse the SRAT table for NUMA setup
________________________________________________________________________________________________
numa=fake=<size>[MG]		If given as a memory unit, fills all system RAM with nodes of
							size interleaved over physical nodes.
________________________________________________________________________________________________
numa=fake=<N>				If given as an integer, fills all system RAM with N fake nodes
							interleaved over physical nodes.
## ============================================================================================= ##





## ============================================================================================= ##
											ACPI
## ============================================================================================= ##
________________________________________________________________________________________________
acpi=off						Don't enable ACPI
________________________________________________________________________________________________
acpi=ht							Use ACPI boot table parsing, but don't enable ACPI interpreter
________________________________________________________________________________________________
acpi=force						Force ACPI on (currently not needed)
________________________________________________________________________________________________
acpi=strict   					Disable out of spec ACPI workarounds.
________________________________________________________________________________________________
acpi=noirq						Don't route interrupts
________________________________________________________________________________________________
acpi_sci={edge,level,high,low}  Set up ACPI SCI interrupt.
## ============================================================================================= ##




/sys/bus/pci/devices/*/vendor
/sys/bus/pci/devices/*/device
/sys/bus/pci/devices/*/class
/sys/bus/pci/devices/*/config

## ============================================================================================= ##
												PCI
## ============================================================================================= ##
________________________________________________________________________________________________
pci=off				Dont use PCI
________________________________________________________________________________________________
pci=conf1			Use conf1 access.
________________________________________________________________________________________________
pci=conf2			Use conf2 access.
________________________________________________________________________________________________
pci=rom				Assign ROMs.
________________________________________________________________________________________________
pci=assign-busses	Assign busses
________________________________________________________________________________________________
pci=irqmask=MASK	Set PCI interrupt mask to MASK
________________________________________________________________________________________________
pci=lastbus=NUMBER	Scan up to NUMBER busses, no matter what the mptable says.
________________________________________________________________________________________________
pci=noacpi			Dont use ACPI to set up PCI interrupt routing.
## ============================================================================================= ##


################################################################################################
############################ || ===>	  SELinux			<=== || ############################
################################################################################################
checkreqprot= [ 0 | 1 ]						Set the initial checkreqprot flag value. 0 means that the check
											protection will be applied by the kernel and will include any
											implied execute protection. 1 means that the check protection is
											requested by the application.
________________________________________________________________________________________________
enforcing= [ 0 | 1 ]						Specify whether SELinux enforces its rules upon boot. 0 means that
											SELinux will just log policy violations but will not deny access to
											anything. 1 means that the enforcement will be fully enabled with
											denials as well as logging. The default value is 0 .
________________________________________________________________________________________________
selinux= [ 0 | 1 ]							allows SELinux to be enabled ( 1 ) or disabled ( 0 )
________________________________________________________________________________________________
selinux_compat_net= [ 0 | 1 ]				Set the network control model.
#################################################################################################


context=$context
fscontext=$context
defcontext=$context
rootcontext=$context

export context=$context


mount -t tmpfs none /mnt -o 'context="system_u:object_r:tmp_t:s0:c127,c456",noexec'

context=

rootcontext=
fscontext=

defcontext=


context="system_u:object_r:removable_t"








setuid=value and 
setgid=value
              Set the owner and group of all files.

user_xattr


usrjquota=aquota.user|grpjquota=aquota.group|jqfmt=vfsv0







##################################################################################
################ || ===>	Volume/Device Management:		<=== || #############
##################################################################################
__________________________________________________________________________________
doevms          This enables support for IBM's pluggable EVMS, or Enterprise
                Volume Management System.  This is not safe to use with lvm2.
__________________________________________________________________________________
dolvm           This enables support for Linux's Logical Volume Management.
                This is not safe to use with evms2.
##################################################################################




##################################################################################
################ || ===>	Screen reader access:		<=== || ##################
##################################################################################
speakup.synth=synth  starts speakup using a given synthesizer.
                     supported synths are acntpc, acntsa, apollo, audptr, bns,
                     decext, dectlk, dtlk, keypc, ltlk, spkout and txprt.
                     Also, soft is supported for software speech and dummy is
                     supported for testing.
__________________________________________________________________________________
speakup.quiet=1      sets the synthesizer not to speak until a key is pressed.
__________________________________________________________________________________
speakup_SYNTH.port=n sets the port for internal synthesizers.
__________________________________________________________________________________
speakup_SYNTH.ser=n  sets the serial port for external synthesizers.
###################################################################################


####################################################################################
################ || ===>	  Other options:			<=== || ####################
####################################################################################
_________________________________________________________________________________  ##
debug           Enables debugging code.  This might get messy, as it displays	   ##
                a lot of data to the screen.									   ##
__________________________________________________________________________________ ##
docache         This caches the entire runtime portion of the CD into RAM,		   ##
                which allows you to umount /mnt/cdrom and mount another CDROM.	   ##
                This option requires that you have at least twice as much		   ##
                available RAM as the size of the CD.							   ##
__________________________________________________________________________________ ##
doload=X        This causes the initial ramdisk to load any module listed, as	   ##
                well as dependencies.  Replace X with the module name.		 	   ##
                Multiple modules can be specified by a comma-separated list.	   ##
__________________________________________________________________________________ ##
dosshd          Starts sshd on boot, which is useful for unattended installs.	   ##
__________________________________________________________________________________ ##
passwd=foo      Sets whatever follows the equals as the root password, which	   ##
                is required for dosshd since we scramble the root password.		   ##
__________________________________________________________________________________ ##
noload=X        This causes the initial ramdisk to skip the loading of a		   ##
                specific module that may be causing a problem.  Syntax matches	   ##
                that of doload.													   ##
__________________________________________________________________________________ ##
nonfs           Disables the starting of portmap/nfsmount on boot.		 		   ##
__________________________________________________________________________________ ##
nox             This causes an X-enabled LiveCD to not automatically start X,	   ##
                but rather, to drop to the command line instead.				   ##
__________________________________________________________________________________ ##
scandelay       This causes the CD to pause for 10 seconds during certain		   ##
                portions the boot process to allow for devices that are slow to    ##
                initialize to be ready for use.									   ##
__________________________________________________________________________________ ##
scandelay=X     This allows you to specify a given delay, in seconds, to be		   ##
                added to certain portions of the boot process to allow for		   ##
                devices that are slow to initialize to be ready for use.		   ##
                Replace X with the number of seconds to pause.					   ##
#######################################################################################
#########################################################################################


################################################################################################
############################ || ===>	  Machine check			<=== || ############################
################################################################################################


mce=off
	Disable machine check
__________________________________________________________________________________ ##
mce=no_cmci
	Disable CMCI(Corrected Machine Check Interrupt) that
	Intel processor supports.  Usually this disablement is
	not recommended, but it might be handy if your hardware
	is misbehaving.
	Note that you'll get more problems without CMCI than with
	due to the shared banks, i.e. you might get duplicated
	error logs.
__________________________________________________________________________________ ##
mce=dont_log_ce
	Don't make logs for corrected errors.  All events reported
	as corrected are silently cleared by OS.
	This option will be useful if you have no interest in any
	of corrected errors.
__________________________________________________________________________________ ##
mce=ignore_ce
	Disable features for corrected errors, e.g. polling timer
	and CMCI.  All events reported as corrected are not cleared
	by OS and remained in its error banks.
	Usually this disablement is not recommended, however if
	there is an agent checking/clearing corrected errors
	(e.g. BIOS or hardware monitoring applications), conflicting
	with OS's error handling, and you cannot deactivate the agent,
	then this option will be a help.
__________________________________________________________________________________ ##
mce=bootlog
	Enable logging of machine checks left over from booting.
	Disabled by default on AMD because some BIOS leave bogus ones.
	If your BIOS doesn't do that it's a good idea to enable though
	to make sure you log even machine check events that result
	in a reboot. On Intel systems it is enabled by default.
__________________________________________________________________________________ ##
mce=nobootlog
	Disable boot machine check logging.
__________________________________________________________________________________ ##
mce=tolerancelevel[,monarchtimeout] (number,number)
	tolerance levels:
	0: always panic on uncorrected errors, log corrected errors
	1: panic or SIGBUS on uncorrected errors, log corrected errors
	2: SIGBUS or log uncorrected errors, log corrected errors
	3: never panic or SIGBUS, log all errors (for testing only)
	Default is 1
	Can be also set using sysfs which is preferable.
	monarchtimeout:
	Sets the time in us to wait for other CPUs on machine checks. 0
	to disable.
__________________________________________________________________________________ ##
mce=bios_cmci_threshold
	Don't overwrite the bios-set CMCI threshold. This boot option
	prevents Linux from overwriting the CMCI threshold set by the
	bios. Without this option, Linux always sets the CMCI
	threshold to 1. Enabling this may make memory predictive failure
	analysis less effective if the bios sets thresholds for memory
	errors since we will not see details for all errors.
__________________________________________________________________________________ ##
nomce (for compatibility with i386): same as mce=off
__________________________________________________________________________________ ##



#####################################################################################
#################### || ===>	  APICs			<=== || ############################
#####################################################################################
__________________________________________________________________________________ ##
apic				Use IO-APIC. Default
__________________________________________________________________________________ ##
noapic	 			Don't use the IO-APIC.
__________________________________________________________________________________ ##
disableapic	 		Don't use the local APIC
__________________________________________________________________________________ ##
nolapic	 			Don't use the local APIC (alias for i386 compatibility)
__________________________________________________________________________________ ##
noapictimer			 Don't set up the APIC timer
__________________________________________________________________________________ ##
no_timer_check 		 Don't check the IO-APIC timer. This can work around
					 problems with incorrect timer initialization on some boards.
__________________________________________________________________________________ ##
apicmaintimer		 Run time keeping from the local APIC timer instead
	                 of using the PIT/HPET interrupt for this. This is useful
	                 when the PIT/HPET interrupts are unreliable.
__________________________________________________________________________________ ##
noapicmaintimer 	 Don't do time keeping using the APIC timer.
					 Useful when this option was auto selected, but doesn't work.
__________________________________________________________________________________ ##
apicpmtimer			 Do APIC timer calibration using the pmtimer. Implies
					 apicmaintimer. Useful when your PIT timer is totally broken.
__________________________________________________________________________________ ##




__________________________________________________________________________________ ##
noisapnp										Disable the ISA Plug and Play (PnP) subsystem.
												Disable the ISA PnP subsystem, if it has been enabled in the kernel	configuration.
__________________________________________________________________________________ ##
pnpbios= [ on | off | curr | no-curr ]			Set the main PnP BIOS settings. on enables the PnP BIOS
												subsystem. off disables the PnP BIOS subsystem.


__________________________________________________________________________________ ##
pnp_reserve_irq									PnP BIOS reserved IRQs.
__________________________________________________________________________________ ##
pnp_reserve_irq=irq1 [ ,irq2 ...]				List of the IRQs that the PnP BIOS subsystem should not use for autoconfiguration.
__________________________________________________________________________________ ##
pnp_reserve_dma									PnP BIOS reserved DMAs.
__________________________________________________________________________________ ##
pnp_reserve_dma=dma1 [ ,dma2 ...]				List of the DMAs that the PnP BIOS subsystem should not use for autoconfiguration.
__________________________________________________________________________________ ##
pnp_reserve_io										PnP BIOS reserved I/O ports.
__________________________________________________________________________________ ##
pnp_reserve_io=io1,size1 [ ,io2,size2 ...]			I/O ports that the PnP BIOS subsystem should not use for autocon-
													figuration. Each port is listed by its starting location and size.
__________________________________________________________________________________ ##
pnp_reserve_mem=mem1,size1 [ ,mem2,size2 ...]	PnP BIOS reserved memory regions.
												Memory regions that the PnP BIOS subsystem should not use for
												autoconfiguration. Each region is listed by its starting location and size.
__________________________________________________________________________________ ##







__________________________________________________________________________________ ##
acpi_fake_ecdt				ECDT workaround. If present, this allows ACPI to workaround 
							BIOS failures when it lacks an Embedded Controller Description Table.
__________________________________________________________________________________ ##
pi_dbg_layer 				ACPI debug layer.
__________________________________________________________________________________ ##
acpi_generic_				hotkey Use generic ACPI hotkey driver.
__________________________________________________________________________________ ##
acpi_os_name=name			Fake the operating system name to ACPI.
__________________________________________________________________________________ ##






#####################################################################################
#################### || ===>	  Timing			<=== || ############################
#####################################################################################
__________________________________________________________________________________ ##
notsc			Don't use the CPU time stamp counter to read the wall time.
				This can be used to work around timing problems on multiprocessor 
				systems with not properly synchronized CPUs.
__________________________________________________________________________________ ##
nohpet			Don't use the HPET timer.
__________________________________________________________________________________ ##
Idle loop
__________________________________________________________________________________ ##
idle=poll		Don't do power saving in the idle loop using HLT, but poll for rescheduling
				event. This will make the CPUs eat a lot more power, but may be useful
				to get slightly better performance in multiprocessor benchmarks. It also
				makes some profiling using performance counters more accurate.
				Please note that on systems with MONITOR/MWAIT support (like Intel EM64T
				CPUs) this option has no performance advantage over the normal idle loop.
				It may also interact badly with hyperthreading.
__________________________________________________________________________________ ##
reboot=b[ios] | t[riple] | k[bd] | a[cpi] | e[fi] [, [w]arm | [c]old]
   bios	  Use the CPU reboot vector for warm reset
   warm   Don't set the cold reboot flag
   cold   Set the cold reboot flag
   triple Force a triple fault (init)
   kbd    Use the keyboard controller. cold reset (default)
   acpi   Use the ACPI RESET_REG in the FADT. If ACPI is not configured or the
          ACPI reset does not work, the reboot path attempts the reset using
          the keyboard controller.
   efi    Use efi reset_system runtime service. If EFI is not configured or the
          EFI reset does not work, the reboot path attempts the reset using
          the keyboard controller.
__________________________________________________________________________________ ##



rootfstype=auto ro liveimg quiet  rhgb rd.live.check
root=live:LABEL=IprediaOS-1-i686-Live-Desktop


Following options can be combined with install:
    Type: nodma               to install with DMA disabled for IDE
          verbose             to install with kernel messages enabled
          rescue              to boot in rescue mode
          memtest             to test memory

    install nopcmcia          to install and disable PCMCIA detection
    install nousb             to install and disable USB detection
    install nousb nopcmcia    to install and disable both
    install modules           to install and add kernelmodules
    install nombr             to install and skip writing MBR
    install disk=<megabyte>   to install and set used diskspace
    install swap=<megabyte>   to install and set SWAP filesize

intel_iommu=on

## ========================================================================================== ##
## ============================= EFI-specific kernel parameters ============================= ##
## ========================================================================================== ##
noefi         						 - disable EFI runtime services (for EFI/kernel arch mismatch)
add_efi_memmap						 - include EFI memory map in kernels RAM map
video=efifb:{macbook,mini,i17,i20}
gentoo=xfb    						 - force EFI framebuffer for X server (use when xvesa fails)
## ========================================================================================== ##
## =========================== Liberté-specific kernel parameters =========================== ##
## ========================================================================================== ##
## cdroot_type={auto,vfat,ext4,iso9660,hfsplus,squashfs} - boot media filesystem type
## cdroot_flags=...					- boot media mount flags
## cdroot=/dev/xxx					- boot media device (can be a glob pattern)
## cdroot_hash=<blks>:<hex>			- SquashFS image DM-Verity hexadecimal SHA-256 root hash
## ========================================================================================== ##
## loop=...           - path to SquashFS image on boot media
## debug              - pause initramfs before mount probing and before booting
## readonly           - set read-only access for boot media device (no OTFE)
## toram / notoram    - cache SquashFS image in RAM (automatic for CDs)
## blacklist=...      - comma-separated list of kernel modules to blacklist
## ========================================================================================== ##
## gentoo=root        - unlock root password ("liberte")
## gentoo=xvesa       - force VESA video driver in Xorg
## gentoo=xfb         - force framebuffer video driver in Xorg (useful for EFI)
## gentoo=xkms        - force modesetting video driver in Xorg (Poulsbo, USB, ...)
## gentoo=nosettings  - do not save/restore user-level application settings
## gentoo=nox         - disable X server configuration (manual "startx" is ok)
## gentoo=nologo      - disable desktop background logo (includes lock screen)
## gentoo=noanon      - non-anonymous mode with separate user settings (CAUTION)
## ========================================================================================== ##
## tz=...             - real-time clock non-UTC timezone (+ default user timezone)
##                      (see Time Zone column of "Language and Time Zone" applet)
## gentoo=nontp       - disable NTP time synchronization (use with tz=...)
## ========================================================================================== ##
## bridges=...        - comma-separated list of Tor bridges: IP[:port(=443)]
## gentoo=obfs        - enable obfsproxy (obfs2) transport for bridges
## ========================================================================================== ##
## video=[driver:]800x600-32 - select framebuffer video mode
## nomodeset                 - disable kernel mode-setting
## quiet, debug, loglevel=n  - control kernel logging verbosity
## memtest=n                 - simple RAM test (lowmem-only on 32-bit kernel)
## ========================================================================================== ##
## ============================== Video issues troubleshooting ============================== ##
## ========================================================================================== ##
## video=LVDS-1:e (/ d)  - toggle video outputs (see /sys/class/drm)
## fbcon=map:1           - framebuffer driver should not take over the console
## noacpi, noapic        - disable ACPI (very problematic), IOAPIC altogether
## acpi_backlight=vendor - prefer vendor-specific driver for backlight control
## acpi_osi=Linux        - add Linux to supported ACPI OS interfaces
##                         (apply *both* options to fix incorrect backlight)
## ========================================================================================== ##



https://github.com/systemd/systemd/blob/master/doc/BOOT_LOADER_SPECIFICATION.md
https://www.freedesktop.org/wiki/Software/systemd/BootLoaderInterface



