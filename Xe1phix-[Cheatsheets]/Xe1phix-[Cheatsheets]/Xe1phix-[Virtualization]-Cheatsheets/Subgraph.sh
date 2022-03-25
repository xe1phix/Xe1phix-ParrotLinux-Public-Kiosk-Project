#!/bin/bash
## Subgraph.sh




echo "## ========================================================================= ##"
echo -e "\t\t[+] Creating a basic Linux virtual machine"
echo "## ========================================================================= ##"
qemu-img -enable-kvm	## enables KVM virtualisation, which is faster than Qemu’s emulation
qemu-img -hda			## This attaches the virtual hard-drive you created
qemu-img -m				## This allocates RAM to the virtual machine (4096MB in the example)
qemu-img -cdrom			## The path to the operation system ISO
qemu-img -boot			## This specifies the boot order for the virtual machine, d is the virtual CDROM




echo "## ========================================================================= ##"
echo -e "\t\t[+] create a virtual hard-drive image for it:"
echo "## ========================================================================= ##"
$ qemu-img create -f qcow2 disk.qcow2 8G


echo "## ========================================================================= ##"
echo -e "\t\t[+] Your virtual hard-drive is now ready for use. Run the following command to test a virtual"
echo -e "\t\t[+] machine with the hard-drive:"
echo "## ========================================================================= ##"
qemu-system-x86_64 -enable-kvm -hda ./disk.qcow2 -m 4096


echo "## ========================================================================= ##"
echo -e "\t\t[+] start a virtual machine with an operating system ISO attached to the virtual CDROM"
echo "## ========================================================================= ##"
qemu-system-x86_64 -enable-kvm -hda ./disk.qcow2 -m 4096 -cdrom ./subgraph-os-alpha_2016-06-16_2.iso -boot d



## libreboot ROM images in QEMU:
qemu-system-i386 -M q35 -m 512 -bios qemu_q35_ich9_keymap_mode.rom
qemu-system-i386 -M pc -m 512 -bios qemu_i440fx_piix4_keymap_mode.rom







echo "## ========================================================================= ##"
echo -e "\t\t[+] Creating an advanced Debian Stretch virtual machine using debootstrap..."
echo "## ========================================================================= ##"

echo "## ========================================================================= ##"
echo -e "\t\t[+] Create a virtual hard-drive image for the operating system"
echo "## ========================================================================= ##"


echo "## ========================================================================= ##"
echo -e "\t\t[+] Create a sparse virtual hard-drive image:"
echo "## ========================================================================= ##"
truncate --size 8G ./disk.img


echo "## ========================================================================= ##"
echo -e "\t\t{2} To format the virtual hard-drive run the following command:"
echo "## ========================================================================= ##"
/sbin/mkfs.ext4 ./disk.img


echo "## ========================================================================= ##"
echo -e "\t\t[+] After formatting the hard-drive, you can create a proper partition table. We will skip"
echo -e "\t\t[+] this step in the tutorial as it is not strictly necessary to run the virtual machine."
echo "## ========================================================================= ##"

echo "## ========================================================================= ##"
echo -e "\t\t{3} Mount the virtual hard-drive:"
echo "## ========================================================================= ##"
mount -o loop ./disk.img /mnt	


echo "## ========================================================================= ##"
echo -e "\t\t[+] show how much space is used by the image:"
echo "## ========================================================================= ##"
du -sh disk.img


echo "## ========================================================================= ##"
echo -e "\t\t[+] The amount shown is a fraction of the total amount specified in the truncate command:"
echo "## ========================================================================= ##"
189M
disk.img

echo "## ========================================================================= ##"
echo -e "\t\t[+] To verify the total amount that was specified in the truncate command"
echo "## ========================================================================= ##"
du --apparent-size -sh disk.img




echo "## ========================================================================= ##"
echo -e "\t\t [+] Installing the operating system with deboostrap"
echo "## ========================================================================= ##"



echo "## ========================================================================= ##"
echo "\t\t [+] Now that the virtual disk-image is created, we can now use debootstrap"
echo "\t\t     To install Debian Stretch. Follow these steps to install it:"
echo "## ========================================================================= ##"



echo "## ========================================================================= ##"
echo -e "\t\t [1] Run debootstrap to install the operating system:"
echo "## ========================================================================= ##"
sudo debootstrap --variant=mintbase --include=systemd-sysv stretch /mnt



echo "## ========================================================================= ##"
echo -e "\t\t [2] Set a root password for the installed operating system:"
echo "## ========================================================================= ##"
sudo chroot /mnt passwd



echo "## ========================================================================= ##"
echo -e "\t\t [3] Create a standard fstab configuration:"
echo "## ========================================================================= ##"
## --------------------------------------------------------------- ##
tee /mnt/etc/fstab << EOL
## --------------------------------------------------------------- ##
/dev/sda	/	ext4	defaults,errors=remount-ro 0 1
## --------------------------------------------------------------- ##
EOL
## --------------------------------------------------------------- ##

echo "## ========================================================================= ##"
echo -e "\t\t [!] Installing the :[Grsecurity]: kernel in the operating system..."
echo -e "\t\t [!] install the Subgraph OS Grsecurity kernel in your virtual machine..."
echo "## ========================================================================= ##"
echo "## --------------------------------------------------------------------------------------------- ##"
cd /tmp
apt-get download linux-{image,headers}-grsec-amd64-subgraph linux-{image,headers}-$(uname -r)
echo "## --------------------------------------------------------------------------------------------- ##"
sudo cp ./linux-{image,headers}-$(uname -r) /mnt/tmp
echo "## --------------------------------------------------------------------------------------------- ##"
sudo chroot /mnt
echo "## --------------------------------------------------------------------------------------------- ##"
dpkg -i /tmp/linux-{image,headers}-*
echo "## --------------------------------------------------------------------------------------------- ##"
update-initramfs -u -k all
exit
echo "## --------------------------------------------------------------------------------------------- ##"




echo "## ======================================================================================= ##"
echo "\t\t [?] Copy the files to the directory you want to start the virtual machine from:"
echo "## ======================================================================================= ##"
cp /mnt/boot/vmlinuz-<version>-amd64 /mnt/boot/initrd.img-<version>-amd64 /home/user/path/to/vm
echo "## --------------------------------------------------------------------------------------------- ##"
echo 
echo 
echo "<+-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-+>"
echo -e "\t [+] Syncing Data..."
echo "<+-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-+>"
sync
echo
echo "<+-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-+>"
echo -e "\t [+] Data Syncing Complete!"
echo "<+-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-+>"
echo
sudo umount /mnt
echo "<+-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-+>"
echo -e "\t [+] Unmount Complete!"
echo "<+-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-+>"
echo
echo
echo "## --------------------------------------------------------------------------------------------- ##"


echo "## ======================================================================================= ##"
echo -e "\t\t[+] Enabling/disabling USB Lockout"
echo "## --------------------------------------------------------------------------------------------------------------------------- ##"
echo "https://en.wikibooks.org/wiki/Grsecurity/Appendix/Grsecurity_and_PaX_Configuration_Options#Deny_new_USB_connections_after_toggle"
echo "## --------------------------------------------------------------------------------------------------------------------------- ##"
echo "## ======================================================================================= ##"



echo "## ======================================================================================= ##"
echo -e "\t\t[+] enable USB Lockout"
echo "## ===================================================== ##"
usblockout --enable

echo "## ===================================================== ##"
echo -e "\t\t[+] Run the following command to disable USB Lockout"
echo "## ===================================================== ##"
usblockout --disable





echo "## ======================================================================================= ##"
echo -e "\t\t\t[•] M Represents :[Enabled]: flags"
echo -e "\t\t\t[•] m Represents :[Disabled flags"
echo "## ======================================================================================= ##"



“/home/user/.local/share/torbrowser/tbb/x86_64/tor-browser_en-US/Browser/firefox”


echo "<+-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-+>"
echo -e "\t\t\t\t[+] :[PaX]: flags"
echo "<+-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-+>"
echo "## ===================================================== ##"
echo -e "\t\t[•]  P/p: Enable/disable PAGEXEC"
echo -e "\t\t[•]  E/e: Enable/disable EMUTRAMP"
echo -e "\t\t[•]  M/m: Enable/disable MPROTECT"
echo -e "\t\t[•]  R/r: Enable/disable RANDMAP"
echo -e "\t\t[•]  X/x: Enable/disable RANDEXEC"
echo -e "\t\t[•]  S/x: Enable/disable SEGMEXEC"
echo "## ===================================================== ##"




echo "## ======================================================================================= ##"
echo -e "\t\t[?] A detailed description of these flags can be found on the following page:"
echo "       ## https://en.wikibooks.org/wiki/Grsecurity/Appendix/PaX_Flags"
echo "## ======================================================================================= ##"




echo "## ======================================================================================= ##"
echo -e "\t\t[?] :[PaX flags must be re-applied after any configuration changes"
echo "## ======================================================================================= ##"



echo "## ======================================================================================= ##"
echo -e "\t\t[?] :[PaX includes other memory protection and control flow integrity features so that it is more difficult"
echo -e "\t\t    for attackers to exploit memory corruption vulnerabilities in applications and the kernel."
echo "## ======================================================================================= ##"



echo "## ======================================================================================= ##"
echo -e "\t\t[?] :[Paxrat configuration files are written in JSON."
echo -e "\t\t    And They are stored in the following directory:"
echo "## ======================================================================================= ##"


echo -e "\t\t[?] :[PaxRat Configuration Directory: /etc/paxrat/"
echo -e "\t\t[?] :[PaxRat Configuration File: /etc/paxrat/paxrat.conf"

PAXRATCONFDIR="/etc/paxrat"
PAXRATCONF="/etc/paxrat/paxrat.conf"



echo "## ======================================================================================= ##"
echo -e "\t\t[+] snippet of a :[PaX flag]: configuration for Tor Browser"
echo "## ======================================================================================= ##"



"/home/user/.local/share/torbrowser/tbb/x86_64/tor-browser_en-US/Browser/firefox":
{
	"flags": "m",
	"nonroot": true
}







echo "## ======================================================================================= ##"
echo -e "\t\t[#] Sandboxing applications with :[Subgraph Oz"
echo "## ======================================================================================= ##"


echo "## ======================================================================================= ##"
echo -e "\t[?] :[Oz can provide the following protections to sandboxed applications:"
echo "## ======================================================================================= ##"
echo -e "\t\t\t[•] Restrict the files that the application has access to"
echo -e "\t\t\t[•] Restrict network access"
echo -e "\t\t\t[•] Restrict audio playback"
echo -e "\t\t\t[•] Restrict the system calls the application can make (using seccomp )"
echo -e "\t\t\t[•] Restrict malicious interactions between X11 applications (using xpra )"




echo "## ======================================================================================= ##"
echo -e "\t\t[?] Normally, applications running under the X11 display server can interact with each other. "
echo -e "\t\t[?] This means that one application can intercept or inject events into another application."
echo -e "\t\t[?] An attacker could abuse this to perform malicious actions such as intercepting the "
echo -e "\t\t[?] keystrokes from another desktop application. To prevent these attacks, Oz sandboxes"
echo -e "\t\t[?] use xpra to render applications on the desktop."
echo "## ======================================================================================= ##"


echo "## ======================================================================================= ##"
echo -e "\t\t[?] :[Xpra isolates applications by using a separate display server to render each application."
echo -e "\t\t[?] Since the applications do not share the same display server, they cannot interact."
echo -e "[?] ## https://github.com/subgraph/oz/wiki/Oz-Technical-Details"
echo "## ======================================================================================= ##"


echo "## ======================================================================================= ##"
echo -e "\t\t[+] Enabling an Oz profile"
echo "## ======================================================================================= ##"

echo "## ======================================================================================= ##"
echo -e "\t\t[?] :[Oz profiles can be found in the following directory:"
echo "## ======================================================================================= ##"


echo -e "\t\t\t[?] :[Oz profiles]: Directory: /var/lib/oz/cells.d/"



OzProfiles="/var/lib/oz/cells.d/"
OzProfilesDir="/var/lib/oz/cells.d/"





sudo oz-setup install evince

echo "## ======================================================================================= ##"
echo -e "\t\t[?] When the profile is installed, Oz will divert the path of the program executable. "
echo -e "\t\t[?] Instead of the program running directly, diverting it lets Oz start the program. "
echo -e "\t\t[?] So the next time it is started, the program will be sandboxed by Oz."
echo "## ======================================================================================= ##"


echo "## ======================================================================================= ##"
echo -e "\t\t[+] Disable a Oz profile for evince"
echo "## ======================================================================================= ##"
sudo oz-setup remove evince



echo "## ======================================================================================= ##"
echo -e "\t\t[+] Viewing the status of an Oz profile"
echo "## ======================================================================================= ##"
sudo oz-setup status /usr/bin/evince








echo "## ======================================================================================= ##"
echo -e "\t\t[+] Package divert is installed for:
echo -e "\t\t[+] Package divert is not installed for:
echo "## ======================================================================================= ##"




echo "## ======================================================================================= ##"
echo -e "\t\t[+] Creating an Oz profile
echo "## ======================================================================================= ##"

{
 "name": "eog"
 , "path": "/usr/bin/eog"
 , "allow_files": true
 , "xserver": {
	"enabled": true
	, "enable_tray": false
	, "tray_icon":"/usr/share/icons/hicolor/scalable/apps/eog.svg"

 }
 , "networking":{
	"type":"empty"
 }
 , "whitelist": [
	{"path":"/var/lib/oz/cells.d/eog-whitelist.seccomp", "read_only": true}
 ]
 , "blacklist": [
 ]
 , "environment": [
	{"name":"GTK_THEME", "value":"Adwaita:dark"}
	, {"name":"GTK2_RC_FILES",
 "value":"/usr/share/themes/Darklooks/gtk-2.0/gtkrc"}
 ]
 , "seccomp": {
	"mode":"whitelist"
	, "enforce": true
	, "whitelist":"/var/lib/oz/cells.d/eog-whitelist.seccomp"
 }
 }

echo "## ======================================================================================= ##"







echo "## ======================================================================================= ##"
echo -e "\t\t[+] Example Oz profile configuration options"
echo "## ======================================================================================= ##"


echo "## ====================================================================================================================== ##"
echo -e "\t[•] name:		 -->	 The name of the profile
echo -e "\t[•] path:		 -->	 The path to the program executable
echo -e "\t[•] allow_files:	 -->	 Allow files to be passed as arguments to the program (such as image files for eog )
echo "## --------------------------------------------------------------------------------------------------------------------- ##"
echo -e "\t[•] xserver		 --> 	 enabled: Enable the use of the Xserver ( xpra )
echo -e "\t[•] xserver		 --> 	 enable_tray: Enable the xpra diagnostic tray (defaults to false , enabling it requires extra software)
echo -e "\t[•] xserver		 --> 	 tray_icon: The path to the tray icon
echo -e "\t[•] networking	 --> 	 type: The networking configuration type, empty disables networking entirely
echo -e "\t[•] whitelist	 --> 	 path: The path of a file to add to the sandbox, in this case it is the seccomp whitelist for eog
echo -e "\t[•] whitelist	 --> 	 path	 --> 	 read_only: Whether or not the allowed file is read-only, should be true in most cases
echo -e "\t[•] blacklist	 --> 	 Removes access to a file in the sandbox, accepts the path argument
echo -e "\t[•] environment	 --> 	 name, value: Adds environment variables by name and value to the sandbox
echo -e "\t[•] seccomp		 --> 	 mode: Adds a seccomp policy (either whitelist or blacklist) to the sandbox
echo -e "\t[•] seccomp		 --> 	 enforce“: The seccomp enforcement mode
echo -e "\t[•] seccomp		 --> 	 whitelist: The path to the whitelist policy
echo "## ====================================================================================================================== ##"


echo -e "\t\t[?] ## https://github.com/subgraph/oz"


echo -e "\t\t[+] located in the profiles directory:"
echo -e "\t\t\t >> /var/lib/oz/cells.d"

ProfilesDir="/var/lib/oz/cells.d"


echo -e "\t\t[+] The Oz generic blacklist is located here:"
/var/lib/oz/cells.d/generic-blacklist.seccomp


echo -e "\t\t[+] Profile Firefox using oz-seccomp-tracer"
echo -e "\t\t[+] a seccomp whitelist is generated after it exits."
oz-seccomp-tracer -trace -output firefox-whitelist.seccomp /usr/bin/firefox 2>firefox_syscalls.txt



## ========================================================================== ##


"whitelist": [
		, {"path":"/var/lib/oz/cells.d/firefox-whitelist.seccomp",
				"read_only": true}
]


## ========================================================================== ##


"seccomp": {
		"mode":"whitelist"
		,
"whitelist":"/var/lib/oz/cells.d/firefox-whitelist.seccomp"
		, "enforce": true
}


## ========================================================================== ##


systemctl restart oz-daemon.service







echo -e "\t\t[+] Securing system calls with seccomp in Oz"


echo "[?] Seccomp is a feature of the Linux kernel to limit exposed system calls. "
echo "[?] As system calls provide a user interface to the kernel, they expose it to attacks. "
echo "[?] These attacks can let an attacker elevate their privileges on the computer. "
echo "[?] The Oz sandbox uses seccomp to protect against this type of attack."


echo "[?] Oz supports seccomp policies on a per-application basis. Seccomp kills applications whenever"
echo "[?] they violate a policy. This protects the computer in cases where an attacker tries to exploit a"
echo "[?] vulnerability in the kernel that depends on the blocked system call."
echo "[?] Some attacks also use system calls as part of their payload. A payload is the malicious code"
echo "[?] that runs as a result of a successful exploit. The seccomp policies in Oz can prevent payloads"
echo "[?] from running if they use a blocked system call."





+ :[Whitelist policies are default deny. This means that only system calls that are explicitly permitted will be allowed. 
All other system calls (those not on the whitelist ) cause the application to be killed.


+ :[Blacklist policies]:	are default allow. This means that seccomp blocks system calls in the black-
list policy but allows all others (those not on the blacklist ).
Whitelist policies are appropriate when the application is well understood. By well under-
stood, we mean that the behavior of the application is predictable enough to create a precise
profile of allowed system calls. This is more secure than a blacklist because known behavior
of the application is allowed but unknown behavior is blocked. The disadvantage of this ap-
proach is that the whitelists must be updated regularly to reflect the known behavior of the
application.
Blacklist policies are appropriate for applications that are not as well understood. We use
them prior to the creation of a whitelist or if there is some other reason a whitelist cannot
be created.
Oz includes a generic blacklist that will work out-of-the-box with many applications. This
policy blocks unusual or exotic system calls that applications do not normally use.




Profiling applications with oz-seccomp-tracer"

+ :[oz-seccomp-tracer profiles applications as they run to determine the system calls that they use. "

This tool will generate a seccomp whitelist after it exits.




You can then use Firefox as you normally would. When you are finished, a seccomp whitelist
will be saved to firefox-whitelist.seccomp . oz-seccomp-tracer prints all of the system calls
from the application to stdout . So we also advise you to redirect this output to a separate file.
We use firefox_syscalls.txt in this example. You could also redirect this output to /dev/null
if you don’t want to save it.




Fix a bug that prevents Glibc from building with GCC-4.5.3:

patch -Np1 -i ../glibc-2.12.2-gcc_fix-1.patch

Add PaX support to Glibc:

patch -Np1 -i ../glibc-2.12.2-pt_pax-1.patch
patch -Np1 -i ../glibc-2.12.2-dl_execstack-1.patch
patch -Np1 -i ../glibc-2.12.2-localedef_trampoline-1.patch
    


cat /lib/modules/$(uname -r)/build/.config

/proc/config.gz 				is only provided if the kernel  is  configured  with  CONFIG_IKCONFIG_PROC



gradm



# To learn on a given role, add l to the role mode
# For both of these, to enable learning, enable the system like:
# gradm2 -L /etc/grsec2/learning.logs -E
# and then generate the rules after disabling the system after the 
# learning phase with:
# gradm2 -L /etc/grsec2/learning.logs -O /etc/grsec2/policy
# To use full system learning, enable the system like:
# gradm2 -F -L /etc/grsec2/learning.logs
# and then generate the rules after disabling the system after the 
# learning phase with:
# gradm2 -F -L /etc/grsec2/learning.logs -O /etc/grsec2/policy


# capability auditing / log suppression
# use of a capability can be audited by adding "audit" to the line, eg:
# +CAP_SYS_RAWIO audit
# log suppression for denial of a capbility can be done by adding "suppress":
# -CAP_SYS_RAWIO suppress


grlearn







pspax - list ELF/PaX information about running processes

--all



chpax

scanelf
paxctl


dumpelf --verbose

elfedit - Update the ELF header of ELF files.

SYNOPSIS
       elfedit [--input-mach=machine]
               [--input-type=type]
               [--input-osabi=osabi]
               --output-mach=machine
               --output-type=type
               --output-osabi=osabi

gold - The GNU ELF linker






paxctld.config

getfattr ‐n user.pax.flags /usr/bin/python3.2
setfattr ‐n user.pax.flags ‐v P /usr/bin/python3.2
getfattr ‐n user.pax.flags /usr/bin/python3.2

















 Non-authoritative answer:
 Name:	security.debian.org
 Address: 212.211.132.32
 Name:	security.debian.org
 Address: 212.211.132.250
 Name:	security.debian.org
 Address: 195.20.242.89


 Non-authoritative answer:
 Name:	httpredir.debian.org
 Address: 128.31.0.66
 Name:	httpredir.debian.org
 Address: 5.153.231.35


 Non-authoritative answer:
 Name:	devrepo.subgraph.com
 Address: 45.55.146.85















