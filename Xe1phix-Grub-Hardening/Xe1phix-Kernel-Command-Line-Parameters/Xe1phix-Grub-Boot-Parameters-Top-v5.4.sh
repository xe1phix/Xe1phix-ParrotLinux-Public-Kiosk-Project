




security=apparmor
apparmor=1

security=tomoyo
TOMOYO_trigger=/usr/lib/systemd/systemd


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

context="system_u:object_r:removable_t"

mount -t tmpfs none /mnt -o 'context="system_u:object_r:tmp_t:s0:c127,c456",noexec'


##  -{


ramdisk_size=100000 root=/dev/ram0
ramdisk_blocksize=1024



noexec=on|off               ## Non Executable Mappings




noeject						Do NOT eject CD during Liveboot
toram
rodata=on       ## Mark read-only kernel memory as read-only (default).
passwd=$Pass      ## Sets whatever follows the equals as the root password


debug
loglevel=4
time						## Show timing data on every kernel log message.


noexec=on|off               ## Non Executable Mappings
acl
user_xattr
quota					Allow users quotas on this partition.
quotacheck.mode=


overriderockperm
nojoliet
norock

uid=1000
gid=1000
file_umask=0177
fmask=0177
dmask=077
mode=0400|0755|0744|0644
dmode=0500
nosudo
noconfig=sudo




noroot         | live-config.noroot
noautologin    |
noxautologin   |
nottyautologin | live-config.nottyautologin
nox11autologin | live-config.nox11autologin


nouser

username=
user-fullname=
userfullname=$USER
live-config.user-fullname=


hostname=$HOSTNAME
LIVE_HOSTNAME="system"
live-config.hostname=$HOSTNAME
live-config.hostname=SELKS 
live-config.hostname=parrot



live-config.user-default-groups=audio,cdrom,floppy,video,dip,plugdev,scanner,bluetooth,netdev,sudo
live-config.user-default-groups=
LIVE_USER_DEFAULT_GROUPS="audio cdrom dip floppy video plugdev netdev powerdev scanner bluetooth debian-tor"





integrity-check
mediacheck                          ## Check the installation CD/DVD For checksum errors.

luks=
luks.key=
luks.options=

live-media-encryption=$Type
encryption=$Type
union=$aufs|$unionfs

{live-media-encryption|encryption}=$TYPE
{live-media|bootfrom}=$DEVICE
live-media-path=$PATH
persistent-path=

persistent[=nofiles]
persistent-path=$PATH
nopersistent

{live-media|bootfrom}=$DEVICE
live-media=$Device
bootfrom=$Device                            ## bootfrom=/dev/sda1/Knoppix.iso

preseed/url=https://www.kali.org/dojo/preseed.cfg

noeject                     ## Do NOT eject DvD

module=
module=$Tails               ## Custom Tails Modprobe 
modules_load=				## list of kernel modules to statically load during early boot.


radeon.modeset=0            ## Radeon driver
i915.modeset=0              ## Intel driver
nouveau.modeset=0           ## Nouveau driver.
cirrus.modeset=0            ## Cirrus driver.
mgag200.modeset=0           ## MGAG200 driver.

libata.ignore_hpa=1         ## Disable host protected area 
                            ## (which should enable the whole disk)




vga=normal				    ## No-frame-buffer mode, but X
xmodule=vesa
xdriver=vesa 			Use standard vesa video driver
screen=1280x1024 			Use specified screen resolution for X
resolution=1024x768  	Choose exact resolution to use

live-config.xorg-driver=$XORG_DRIVER
live-config.xorg-resolution=$XORG_RESOLUTION
live-config.x-session-manager=$X_SESSION_MANAGER

no3d
Failsafe				    ## Boot with (almost) no hardware detection

lp=0                        ## Disables the printer driver.

noefi                           ## disable EFI runtime services
nousb                           ## Disable SysFS's lack of the Usea I coulf have gond! /sys
pnpbios=off                     ## PnP BIOS settings.
add_efi_memmap				    ## include EFI memory map In kernels RAM map
noisapnp                        ## Disable the ISA Plug and Play (PnP) subsystem.
max_loop=$n                     ## Maximum number of loopback devices.
acpi_os_name=$name              ## Fake the operating system name to ACPI.


mem=$256M				                ## Tell the Linux kernel to use 256 MB of RAM
ramdisk_size=$100000 root=/dev/ram0
ramdisk_blocksize=$1024





## -------------------------------- Tails OS Parameters -------------------------------- ##
processor.max_cstate=$n                 ## Limit the processor to a maximum C-state.
vsyscall=none
block.events_dfl_poll_msecs=1000  
## ------------------------------------------------------------------------------------- ##


blacklist=btsdio,btusb,appletalk,hfs,hfsplus,efivars,efivarfs,efi_pstore,appletouch,thunderbolt_net,btintel,btrtl,hid-apple
systemd.mask=bluetooth,ModemManager,mysql,postgresql,printer,apache2,smbd,mysqld,lighttpd,nfs,couchdb
systemd.wants=

root=
rootfstype=
rootflags=
roothash=

mount.usr=                          ## Configures the /usr file system (if required)
mount.usrfstype=                    ## Configures the /usr file system type
mount.usrflags=                     ## Configures the /usr file system mount options
net.ifnames=


systemd.verity=                     ## Configures the integrity protection root hash for the root file system
systemd.verity_root_data=
systemd.verity_root_hash=


rfkill.default_state=0
rfkill.master_switch_mode=2
systemd.restore_state=1             ## rfkill.service


nonet 					## Dont probe for network devices
noipv6  				## Dont enable IPV6 networking
nonfs                   ## Disable NFS


fsck.mode=force|auto
fsck.repair=preen|yes|no

systemd.unit=emergency.target
systemd.unit=rescue.target 
systemd.crash_shell

systemd.confirm_spawn


systemd.log_target=journal-or-kmsg
systemd.log_target=console
systemd.log_target=kmsg
systemd.log_level=debug
systemd.show_status=1
systemd.log_location= 




locale.LANG=
lang=us					    ## Specify language/keyboard
keyboard=us                 ## Use a different console keyboard
xkeyboard=us                ## Use a different X keyboard
tz=America/Los_Angeles      ## Use a particular time zone

systemd.setenv=
systemd.machine_id=

vsyscall=none
block.events_dfl_poll_msecs=1000  

stacktrace
stacktrace_filter=$FunctionList         ## Limit the functions that the stack tracer will trace at boot up.


ihash_entries=              ## Override the default number of hash buckets for the kernel’s inode

vdso=[0|1]                  ## Enable or disable the VDSO (Virtual Dynamic Shared Object) mapping



