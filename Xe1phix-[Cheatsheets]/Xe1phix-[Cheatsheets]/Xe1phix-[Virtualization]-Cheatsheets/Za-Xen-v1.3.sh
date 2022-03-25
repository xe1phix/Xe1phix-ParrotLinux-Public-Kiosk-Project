#!/bin/bash
###############
## Za-Xen.sh
###############



Migrate Linux VMs from XEN (SolusVM) to KVM (Proxmox)


Get Image of Xen VM:


Create image of the volume using below command:
dd if=/dev/mapper/vm<number> of=xenvm.img bs=1M
2. Copy that image to Proxmox or KVM installed node to the appropriate storage.
3. Create blank disk for KVM on Proxmox Node
dd if=/dev/zero of=kvmvm.raw bs=1M count=12288
4. Need to create Partitioning like Xen VM. So as we have only one Partition in Xen VM. We will just create one Partition inside the kvmvm image.
parted kvmvm.raw
(parted)$ mklabel msdos
(parted)$ mkpart primary ext3 0 12288M
(parted)$ set 1 boot on
(parted)$ quit
5. Load dm-mod module
modprobe dm­mod
6. Create drivers to access partition inside kvmvm.raw
losetup /dev/loop0 kvmvm.raw
kpartx ­a /dev/loop0
Now you can access partition1 inside kvmvm.raw using /dev/mapper/loop0p1
7. Time to push the image of XenVM on partition1 of kvmvm.raw using dd
dd if=xenvm.img of=/dev/mapper/loop0p1 bs=1M
8. Run Filesystem check on ext3 {�lesystem to correct the errors.
fsck ­f /dev/mapper/loop0p1
9. Create VM in Proxmox also use harddrive image as raw and now qcow2. Replace that VM’s image {�le with kvmvm.raw.
10. Now if we boot Proxmox VM, it wont boot successfully. We will need to install or update grub {�rst. To do so use CentOS / Ubuntu installation CD image and boot VM into
rescue mode with chroot enabled. VM’s drive will be mounted on /mnt/sysimage
11. Install grub
chroot /mnt/sysimage
grub
grub> root (hd0,0)
grub> find /boot/grub/stage1
grub> setup (hd0)
12. Change in /boot/grub/grub.conf.
Remove console=hvc0 xencons=tty0 from line number 5 starts with kernel.
And change root device from /dev/xvda1 to /dev/sda1


kernel /boot/vmlinuz­2.6.32­279.el6.x86_64 root=/dev/sda1 ro



pv-grub-menu

xen-hypervisor-4.8-amd64
xen-linux-system-4.8.0-parrot-amd64
xen-system-amd64
xen-linux-system-amd64













python -m qubes.tests.run -l | grep fedora-21			## 
python -m qubes.tests.run -l | grep 					## 

    network/VmNetworking_fedora-21/test_000_simple_networking
    network/VmNetworking_fedora-21/test_010_simple_proxyvm
    network/VmNetworking_fedora-21/test_020_simple_proxyvm_nm
    network/VmNetworking_fedora-21/test_030_firewallvm_firewall
    network/VmNetworking_fedora-21/test_040_inter_vm
    vm_qrexec_gui/TC_00_AppVM_fedora-21/test_000_start_shutdown
    vm_qrexec_gui/TC_00_AppVM_fedora-21/test_010_run_gui_app
    vm_qrexec_gui/TC_00_AppVM_fedora-21/test_050_qrexec_simple_eof
    vm_qrexec_gui/TC_00_AppVM_fedora-21/test_051_qrexec_simple_eof_reverse
    vm_qrexec_gui/TC_00_AppVM_fedora-21/test_052_qrexec_vm_service_eof
    vm_qrexec_gui/TC_00_AppVM_fedora-21/test_053_qrexec_vm_service_eof_reverse
    vm_qrexec_gui/TC_00_AppVM_fedora-21/test_060_qrexec_exit_code_dom0
    vm_qrexec_gui/TC_00_AppVM_fedora-21/test_065_qrexec_exit_code_vm
    vm_qrexec_gui/TC_00_AppVM_fedora-21/test_100_qrexec_filecopy
    vm_qrexec_gui/TC_00_AppVM_fedora-21/test_110_qrexec_filecopy_deny
    vm_qrexec_gui/TC_00_AppVM_fedora-21/test_120_qrexec_filecopy_self
    vm_qrexec_gui/TC_20_DispVM_fedora-21/test_000_prepare_dvm
    vm_qrexec_gui/TC_20_DispVM_fedora-21/test_010_simple_dvm_run
    vm_qrexec_gui/TC_20_DispVM_fedora-21/test_020_gui_app
    vm_qrexec_gui/TC_20_DispVM_fedora-21/test_030_edit_file


python -m unittest -v qubes.tests				## 
python -m qubes.tests.run -v					## 



sudo qubes-dom0-update anti-evil-maid			## 




create a QCOW2-image for your virtual machine			## 
qemu-img create -f qcow2 vm.qcow2 10G					## 


create a backing-file (overlay which contains all of the future delta) and an image 
which will contain a snapshot of the VM (the size should be larger than your virtual memory you have configured):

qemu-img create -b vm.img -f qcow2 overlay.qcow2			## 
qemu-img create -f qcow2 ram.qcow2 1G						## 



qemu-system-x86_64 --enable-kvm -m 1024 -hdb ram.qcow2 -hda overlay.qcow2 -serial mon:stdio -device nec-usb-xhci -device usb-redir,chardev=usbchardev,debug=0






sudo xl info | less			## 


Creating an HVM domain
----------------------
qvm-create win7 --hvm --label green

qvm-start win7 --cdrom=/usr/local/iso/win7_en.iso

qvm-start win7 --cdrom=/dev/cdrom			## 

--cdrom=[appvm]:[/path/to/iso/within/appvm]			## 

qvm-create --hvm ubuntu --label red

qvm-start ubuntu --cdrom=work-web:/home/user/Downloads/ubuntu-12.10-desktop-i386.iso			## 


Setting up networking for HVM domains
-------------------------------------



http://theinvisiblethings.blogspot.com/2011/09/playing-with-qubes-networking-for-fun.html


qvm-ls -n			## 


Using Template-based HVM domains
--------------------------------


Cloning HVM domains
-------------------

qvm-prefs win7
name              : win7
label             : green
type              : HVM
netvm             : firewallvm
updateable?       : True
installed by RPM? : False
include in backups: False
dir               : /var/lib/qubes/appvms/win7
config            : /var/lib/qubes/appvms/win7/win7.conf
pcidevs           : []
root img          : /var/lib/qubes/appvms/win7/root.img
private img       : /var/lib/qubes/appvms/win7/private.img
vcpus             : 4
memory            : 512
maxmem            : 512
MAC               : 00:16:3E:5E:6C:05 (auto)
debug             : off
default user      : user
qrexec_installed  : False
qrexec timeout    : 60
drive             : None
timezone          : localtime

qvm-clone win7 win7-copy
/.../

qvm-prefs win7-copy
name              : win7-copy
label             : green
type              : HVM
netvm             : firewallvm
updateable?       : True
installed by RPM? : False
include in backups: False
dir               : /var/lib/qubes/appvms/win7-copy
config            : /var/lib/qubes/appvms/win7-copy/win7-copy.conf
pcidevs           : []
root img          : /var/lib/qubes/appvms/win7-copy/root.img
private img       : /var/lib/qubes/appvms/win7-copy/private.img
vcpus             : 4
memory            : 512
maxmem            : 512
MAC               : 00:16:3E:5E:6C:01 (auto)
debug             : off
default user      : user
qrexec_installed  : False
qrexec timeout    : 60
drive             : None
timezone          : localtime


qvm-ls -n

/.../
         win7-copy |    |  Halted |   Yes |       | *firewallvm |  green |  10.137.2.3 |        n/a |  10.137.2.1 |
              win7 |    |  Halted |   Yes |       | *firewallvm |  green |  10.137.2.7 |        n/a |  10.137.2.1 |
/.../


qvm-prefs win7-copy -s mac 00:16:3E:5E:6C:05

qvm-prefs win7-copy

name              : win7-copy
label             : green
type              : HVM
netvm             : firewallvm
updateable?       : True
installed by RPM? : False
include in backups: False
dir               : /var/lib/qubes/appvms/win7-copy
config            : /var/lib/qubes/appvms/win7-copy/win7-copy.conf
pcidevs           : []
root img          : /var/lib/qubes/appvms/win7-copy/root.img
private img       : /var/lib/qubes/appvms/win7-copy/private.img
vcpus             : 4
memory            : 512
maxmem            : 512
MAC               : 00:16:3E:5E:6C:05
debug             : off
default user      : user
qrexec_installed  : False
qrexec timeout    : 60
drive             : None
timezone          : localtime




sudo qubes-dom0-update qubes-windows-tools


rpm -ql qubes-windows-tools-1-201211301354.noarch /usr/lib/qubes/qubes-windows-tools-201211301354.iso


qvm-start lab-win7 --cdrom=/usr/lib/qubes/qubes-windows-tools-201211301354.iso


qvm-prefs lab-win7 -s qrexec_installed true			## 


qvm-prefs lab-win7 -s default_user joanna			## 

qvm-run lab-win7 calc
qvm-run lab-win7 -p cmd.exe























_____________________________________________________________________________________________
In dom0, create a proxy vm and disable unnecessary services and enable qubes-tor:
______________________________________
qvm-clone fedora-21 fedora-21-tor
qvm-create -p torvm
qvm-service torvm -d qubes-netwatcher
qvm-service torvm -d qubes-firewall
qvm-service torvm -e qubes-tor

_____________________________________________________
# if you  created a new template in the previous step
qvm-prefs torvm -s template fedora-21-tor

____________________________________________________________
## From your TemplateVM, install the torproject Fedora repo
sudo yum install qubes-tor-repo

________________________________________________________
# Then, in the template, install the TorVM init scripts
sudo yum install qubes-tor

_________________________________________________________________________________
## Configure an AppVM to use TorVM as its NetVM (for example a vm named anon-web)
qvm-prefs -s anon-web sys-net torvm
## ... repeat for any other AppVMs you want torified...

_______________________________________________________________________________________
## Shutdown the TemplateVM.
## Set the prefs of your TorVM to use the default sys-net or sys-firewall as its NetVM
qvm-prefs -s torvm netvm sys-net

_____________________________________________________________________________________
## Start the TorVM and any AppVM you have configured to be route through the TorVM
## From the AppVMs, verify torified connectivity
curl https://check.torproject.org

________________________________
## Troubleshooting:
sudo service qubes-tor status
sudo grep Tor /var/log/messages
sudo service qubes-tor restart

_____________________________________________________________________________________________
qvm-run -q --tray -a my-new-anonvm 'TOR_SKIP_LAUNCH=1 TOR_SKIP_CONTROLPORTTEST=1 TOR_SOCKS_PORT=9050 TOR_SOCKS_HOST=1.2.3.4 ./tor-browser_en-US/Browser/start-tor-browser'
_____________________________________________________________________________________________
`sh -c 'echo TOR_SKIP_LAUNCH=1 TOR_SKIP_CONTROLPORTTEST=1 TOR_SOCKS_PORT=9050 TOR_SOCKS_HOST=1.2.3.4 ./tor-browser_en-US/Browser/start-tor-browser | /usr/lib/qubes/qfile-daemon-dvm qubes.VMShell dom0 DEFAULT red'`

_____________________________________________________________________________________________
## Custom Tor Configuration
/usr/lib/qubes-tor/torrc			## 
/rw/usrlocal/etc/qubes-tor/torrc			## 


												
									         /^\\
								 ___________//__\\___________
						   ________|| Trusting & Signing ||__________
							|| ** The Qubes Security Pack (QSP)** ||
____________________________||____________________________________||_________________________
https://keys.qubes-os.org/keys/qubes-release-2-signing-key.asc    ||
____________________________________________________________________________________________
curl --tlsv1 --url https://keys.qubes-os.org/keys/qubes-master-signing-key.asc --output /home/$user/Gnupg/archive-key.asc | 
_____________________________________________________________________________________________
gpg --export 0x427F11FD0FAA4B080123F01CDDFA1A3E36879494 | sudo apt-key add -
_____________________________________________________________________________________________
curl --tlsv1 --url https://keys.qubes-os.org/keys/qubes-master-signing-key.asc --output /home/$user/Gnupg/archive-key.asc | apt-key add 
_____________________________________________________________________________________________
gpg --keyserver pool.sks-keyservers.net --recv-keys 0x427F11FD0FAA4B080123F01CDDFA1A3E36879494

_____________________________________________________________________________________________

gpg> fpr				## Fingerprint 	qubes master key
__________________________________________________________________________
pub   4096R/36879494 2010-04-01 Qubes Master Signing Key
 Primary key fingerprint: 427F 11FD 0FAA 4B08 0123  F01C DDFA 1A3E 3687 9494

_____________________________________________________________________________
gpg --list-sig 0A40E458
gpg -v --verify Qubes-R2-x86_64-DVD.iso.asc
gpg -v --verify qsb-013-2015.txt.sig.joanna qsb-013-2015.txt
gpg -v --verify qsb-013-2015.txt.sig.marmarek qsb-013-2015.tx











gpg --edit-key alice

Add a signing subkey

gpg> addkey
Key is protected.



gpg> save














Generate a revocation certificate
A general-purpose revocation certificate that specifies no reason why you are revoking your keys:
[user@vault ~]$ gpg --output revocation.cert --gen-revoke alice

Backup your precious master keys and revocation certificate
Create a backup of Alice’s private key:
[user@vault ~]$ gpg --export-secret-keys --armor alice > alice_gpg_private.key
Create a backup of Alice’s public key:
[user@vault ~]$ gpg --export --armor alice > alice_gpg_public.key
Keep these files safe!
[user@vault ~]$ tar -cf gpg_master_keys.tar alice_gpg*.key revocation.cert

Shred the files we backed up – now everything is in the tar file:
shred -u alice_gpg*.key revocation.cert



Delete your master signing key from your keyring:
[user@vault ~]$ gpg --delete-secret-key alice@domain.com


Export all subkeys to a temporary file:
[user@vault ~]$ gpg --export-secret-subkeys alice@domain.com > subkeys




gpg --export-secret-keys --armor alice > alice_gpg_private_lesser.key

Export Alice’s “lesser” public key:
[user@vault ~]$ gpg --export --armor alice > alice_gpg_public_lesser.key



Move the daily-use keyring to Alice’s “personal” AppVM
qvm-copy-to-vm personal alice_gpg_p*_lesser.key








________________________________________________
qvm-prefs -s usbvm autostart true
_________________________________________________
sudo qubes-dom0-update qubes-template-debian-7
_________________________________________________
sudo qubes-dom0-update qubes-template-debian-8




qvm-pci --list 						## list/set VM PCI devices
qvm-pci --add 						## Add a PCI device to specified VM
qvm-pci --delete					## Remove a PCI device from specified VM
________________________________________________________________________________________
qvm-block --list 					## list/set VM PCI devices.
qvm-block --attach  				## Attach block device to specified VM
qvm-block --ro  					## Force read-only mode
qvm-block --frontend=FRONTEND   	## Specify device name at destination VM [default: xvdi]
qvm-block --detach     				## Detach block device
_________________________________________________________________________________________
qvm-copy-to-vm						## 
qvm-open-in-dvm						## 
qvm-open-in-vm						## 
qvm-run								## 






/run/media/user/				## ExternalDeviceMountPoint



qubes-dom-update qubes-core-dom0 qubes-manager

qubes-dom0-update patch

patch /usr/lib64/python2.7/site-package/qubes/qubes.py < qubes.py-bridge.diff
patch /usr/lib64/python2.7/site-package/qubesmanager/settings.py < settings.py-bridge.diff
patch /usr/lib64/python2.7/site-package/qubesmanager/ui_settingsdlg.py < ui_settingsdlg.py-bridge.diff






qvm-prefs --set maxmem							## memory size in MB
										## memory size in MB
qvm-prefs --list kernel							## kernel version, `default`, `none`


qvm-prefs --set template $templatename			## 

/var/lib/qubes/vm-kernels						## 

qvm-prefs --list 								## list/set various per-VM properties
qvm-prefs --set 								## 

qvm-prefs --list vcpus							## 
qvm-prefs --set include\_in\_backups `True`

pcidevs											## 

qvm-prefs --set label `red` 
qvm-prefs --set label `orange`
qvm-prefs --set label `yellow`
qvm-prefs --set label `green`
qvm-prefs --set label `gray`
qvm-prefs --set label `blue`
qvm-prefs --set label `purple`
qvm-prefs --set label `black`


qubes-firewall  

qvm-firewall
qubes-network  
qubes-updates-proxy  
yum-proxy-setup  
meminfo-writer  				## 
qubes-update-check  			## 


qvm-service --list				## 
qvm-service --enable			## 
qvm-service --disable  			## 
qvm-service --default 			## 


qvm-service --disable network-manager  			## 

/etc/qubes/guid.conf			## 



_______________________________________________________________________________________________
	{+}	/rw/config/qubes-ip-change-hook` 	## script run in NetVM after external IP change (or 												connection to the network)
_______________________________________________________________________________________________
	{+}	/rw/config/qubes-firewall-user-script` ## script run in ProxyVM after firewall update. 												   ## Good place to write own custom firewall rules
_______________________________________________________________________________________________
	{+}	/rw/config/suspend-module-blacklist` ## list of modules (one per line) to be unloaded 												 ## before system going to sleep. The file is used 
											 ## only in VM with some PCI devices attached. 												 ## Supposed to be used for problematic drivers.
_______________________________________________________________________________________________





################################################################################################
All configuration files for Qubes Revisor are kept in the ```conf/``` directory:
################################################################################################
_______________________________________________________________________________________________
	{+}	conf/qubes-install.conf			 Main Revisor configuration file. This configures Revisor to build Qubes Installation image based on Fedora 13. All other configuration files and working directories are pointed here.
_______________________________________________________________________________________________
	{+}	conf/qubes-x86_64.conf 		 This file describes all repositories needed to build Qubes for x86\_64 architecture.
_______________________________________________________________________________________________
	{+} conf/qubes-kickstart.cfg  ## Fedora Kickstart formatted file describing which 									  ## packages should land in the ISO /Packages repository. This 
								  ## describes basically what will be available for 
								  ## installation. The packages list built using this file will 
								  ## be further filtered by the comps file.
_______________________________________________________________________________________________
	{+}	conf/comps-qubes.xml		##  Repository Comps file for ISO `/Packages` repository, 										## describing packages and package groups of the installer 
									## repository. Package groups are used to select which of 
									## the packages are mandatory to install, which are 
									## optional and which are to be just available on the ISO 
									## but not installed by default (not used on Qubes).
################################################################################################
################################################################################################











































### Attacks on Intel TXT

-   [Attacking Intel® Trusted Execution Technology](http://invisiblethingslab.com/resources/bh09dc/Attacking%20Intel%20TXT%20-%20paper.pdf) by Rafal Wojtczuk, Joanna Rutkowska
-   [ACPI: Design Principles and Concerns](http://www.ssi.gouv.fr/IMG/pdf/article_acpi.pdf) by Loic Duflot, Olivier Levillain, and Benjamin Morin
-   [Another Way to Circumvent Intel® Trusted Execution Technology](http://invisiblethingslab.com/resources/misc09/Another%20TXT%20Attack.pdf) by Rafal Wojtczuk, Joanna Rutkowska, Alex Tereshkin
-   [Attacking Intel TXT® via SINIT code execution hijacking](http://www.invisiblethingslab.com/resources/2011/Attacking_Intel_TXT_via_SINIT_hijacking.pdf) by Rafal Wojtczuk and Joanna Rutkowska

### Software attacks coming through devices

-   [Can you still trust your network card?](http://www.ssi.gouv.fr/IMG/pdf/csw-trustnetworkcard.pdf) by Loïc Duflot, Yves-Alexis Perez and others
-   [Remotely Attacking Network Cards (or why we do need VT-d and TXT)](http://theinvisiblethings.blogspot.com/2010/04/remotely-attacking-network-cards-or-why.html) by Joanna Rutkowska
-   [On Formally Verified Microkernels (and on attacking them)](http://theinvisiblethings.blogspot.com/2010/05/on-formally-verified-microkernels-and.html) by Joanna Rutkowska
-   [Following the White Rabbit: Software Attacks against Intel® VT-d](http://www.invisiblethingslab.com/resources/2011/Software%20Attacks%20on%20Intel%20VT-d.pdf) by Rafal Wojtczuk and Joanna Rutkowska

### Application-level security

-   [Virtics: A System for Privilege Separation of Legacy Desktop Applications](http://radlab.cs.berkeley.edu/wiki/Virtics) by Matt Piotrowski
    (We plan to implement some ideas from Matt's thesis in Qubes very soon -- stay tuned for details)

### VMM/Xen disagregation

-   [[http://tjd.phlegethon.org/words/sosp11-xoar.pdf](http://tjd.phlegethon.org/words/sosp11-xoar.pdf) "Breaking Up is Hard to Do: Security and Functionality in a Commodity Hypervisor] by Patrick Colp at el.
     (Also see [this thread on xen-devel](http://www.gossamer-threads.com/lists/xen/devel/230011))















/usr/bin/lxc-execute
       -n foo -f /usr/share/doc/lxc/examples/lxc-macvlan.conf /bin/bash


















virt-install --connect qemu:///system --name vm1.example.com \
--ram 32768 --vcpus 4 --disk path=/vm1/vm1.example.com.qcow2 \
--network=bridge:br0 --os-type=linux --os-variant=rhel6 \
--cdrom /vm1/iso/CentOS-6.4-x86_64-bin-DVD1.iso \
--graphics spice,password=mypassword –autostart
 
# Enable libvirt to start automatically.
# chkconfig libvirtd on
# service libvirtd start



Automated KVM Installation


PXE Linux Config
default menu.c32
prompt 0
timeout 5
 
menu title PXE Boot Menu
 
label 1
menu label ^1 - Install KVM
kernel images/centos/6.5/x86_64/vmlinuz
APPEND text load_ramdisk=1 initrd=images/centos/6.5/x86_64/initrd.img network noipv6
ksdevice=eth0 ks=http://ks/kickstart/ks.cfg i8042.noaux console=tty0
 
label local
menu label ^0 - Boot from first hard drive
com32 chain.c32
append hd0

Kickstart Postinstall File
# commands sections (required)
bootloader --location=mbr
authconfig --enableshadow
keyboard us
autopart
 
# optional components
clearpart -all
firewall --disabled
install --url http://ks.example.com/centos/6.4
network --bootproto=static --ip=10.1.1.100 --netmask=255.255.255.0 --gateway=10.1.1.1
--nameserver=10.1.1.10
#packages section (required)
%packages
@Virtualization
 
# preinstall section (optional)
%pre
 
# postinstall section (optional)
%post





Clustered Kickstart Solution


iPXE (http://ipxe.org/), which supports PXE over HTTP


[user@dom0 ~]$ sudo qubes-dom0-update qubes-template-debian-7
[user@dom0 ~]$ sudo qubes-dom0-update qubes-template-debian-8



sudo qubes-dom0-update --enablerepo=qubes-tempates-community qubes-template-whonix-gw qubes-template-whonix-ws






echo -e "\t\t[+] "

# Do not manage xen-provided network devices
unmanaged_devices=mac:fe:ff:ff:ff:ff:ff
#for mac in `xenstore-ls device/vif | grep mac | cut -d= -f2 | tr -d '" '`; do
#    unmanaged_devices="$unmanaged_devices;mac:$mac"
#done
sed -i -e "s/^unmanaged-devices=.*/unmanaged-devices=$unmanaged_devices/" /etc/NetworkManager/NetworkManager.conf
sed -i -e "s/^plugins=.*/plugins=keyfile/" /etc/NetworkManager/NetworkManager.conf







The kvm API is a set of ioctls that are issued to control various aspects
of a virtual machine.  The ioctls belong to three classes

 - System ioctls: These query and set global attributes which affect the
   whole kvm subsystem.  In addition a system ioctl is used to create
   virtual machines

 - VM ioctls: These query and set attributes that affect an entire virtual
   machine, for example memory layout.  In addition a VM ioctl is used to
   create virtual cpus (vcpus).

   Only run VM ioctls from the same process (address space) that was used
   to create the VM.

 - vcpu ioctls: These query and set attributes that control the operation
   of a single virtual cpu.

   Only run vcpu ioctls from the same thread that was used to create the
   vcpu.



File descriptors
-------------------
A KVM_CREATE_VM ioctl on this
handle will create a VM file descriptor which can be used to issue VM
ioctls.  A KVM_CREATE_VCPU ioctl on a VM fd will create a virtual cpu
and return a file descriptor pointing to it.




the vcpus are mapped onto virtual
threads in one or more virtual CPU cores. 
The KVM_CAP_PPC_SMT capability indicates the number
of vcpus per virtual core (vcore).
Userspace can control the threading (SMT) mode of the guest by its
allocation of vcpu ids. 




KVM_RUN

This ioctl is used to run a guest virtual cpu.  While there are no
explicit parameters, there is an implicit parameter block that can be
obtained by mmap()ing the vcpu fd at offset 0, with the size given by
KVM_GET_VCPU_MMAP_SIZE.  The parameter block is formatted as a 'struct
kvm_run'



KVM_GET_REGS

Reads the general purpose registers from the vcpu.

/* x86 */
struct kvm_regs {
	/* out (KVM_GET_REGS) / in (KVM_SET_REGS) */
	__u64 rax, rbx, rcx, rdx;
	__u64 rsi, rdi, rsp, rbp;
	__u64 r8,  r9,  r10, r11;
	__u64 r12, r13, r14, r15;
	__u64 rip, rflags;
};



the virtual CPUs TLB array, establishing a shared memory area
between userspace and KVM.  The "params" and "array" fields are userspace
addresses of mmu-type-specific data structures.  The "array_len" field is an
safety mechanism, and should be set to the size in bytes of the memory that
userspace has reserved for the array.  It must be at least the size dictated
by "mmu_type" and "params".

While KVM_RUN is active, the shared region is under control of KVM.  Its
contents are undefined, and any modification by userspace results in
boundedly undefined behavior.











































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
echo -e "\t\t[+] Installing the operating system with deboostrap"
echo "## ========================================================================= ##"



echo "## ========================================================================= ##"
echo "\t\tNow that the virtual disk-image is created, we can now use debootstrap"
echo "\t\tTo install Debian Stretch. Follow these steps to install it:"
echo "## ========================================================================= ##"


echo "## ========================================================================= ##"
echo -e "\t\t[1] Run debootstrap to install the operating system:"
echo "## ========================================================================= ##"
sudo debootstrap --variant=mintbase --include=systemd-sysv stretch /mnt



echo "## ========================================================================= ##"
echo -e "\t\t[2] Set a root password for the installed operating system:"
echo "## ========================================================================= ##"
sudo chroot /mnt passwd



echo "## ========================================================================= ##"
echo -e "\t\t[3] Create a standard fstab configuration:"
echo "## ========================================================================= ##"

## --------------------------------------------------------------- ##
tee /mnt/etc/fstab << EOL
## --------------------------------------------------------------- ##
/dev/sda	/	ext4	defaults,errors=remount-ro 0 1
## --------------------------------------------------------------- ##
EOL
## --------------------------------------------------------------- ##

echo "## ========================================================================= ##"
echo "Installing the Grsecurity kernel in the operating system..."
echo "install the Subgraph OS Grsecurity kernel in your virtual machine..."
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
echo "\t\tcopy the files to the directory you want to start the virtual machine from:"
echo "## ======================================================================================= ##"
cp /mnt/boot/vmlinuz-<version>-amd64 /mnt/boot/initrd.img-<version>-amd64 /home/user/path/to/vm
echo "## --------------------------------------------------------------------------------------------- ##"
sync
sudo umount /mnt
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
echo -e "\t\t\t[•] M represent enabled flags"
echo -e "\t\t\t[•] m Represents Disabled flags"
echo "## ======================================================================================= ##"



“/home/user/.local/share/torbrowser/tbb/x86_64/tor-browser_en-US/Browser/firefox”

echo -e "\t\t\t[+] PaX flags

echo "## ===================================================== ##"
echo -e "\t\t\t[•]  P/p: Enable/disable PAGEXEC"
echo -e "\t\t\t[•]  E/e: Enable/disable EMUTRAMP"
echo -e "\t\t\t[•]  M/m: Enable/disable MPROTECT"
echo -e "\t\t\t[•]  R/r: Enable/disable RANDMAP"
echo -e "\t\t\t[•]  X/x: Enable/disable RANDEXEC"
echo -e "\t\t\t[•]  S/x: Enable/disable SEGMEXEC"
echo "## ===================================================== ##"















echo "## =================================================================== ##"
echo -e "\t "
echo "## =================================================================== ##"


vmdebootstrap --image=FILE --size=SIZE [--mirror=URL] [--distribution=NAME]

vmdebootstrap --verbose --image jessie-uefi.img --grub  --use-uefi --customize ./examples/qemu-efi-bochs-drm.sh



echo "## =================================================================== ##"
echo -e "\t "
echo "## =================================================================== ##"
qemu-system-x86_64 -L /usr/share/ovmf/ -machine accel=kvm -m 4096 -smp 2 -drive format=raw,file=test.img


echo "## =================================================================== ##"
echo -e "\t "
echo "## =================================================================== ##"
/usr/share/vmdebootstrap/qemu-wrapper.sh jessie-uefi.img amd64 /usr/share/ovmf/



echo "## ================================================== ##"
echo -e "\tTo create an image for the stable release of Debian:
echo "## =================================================================== ##"

sudo vmdebootstrap --image test.img --size 1G --log test.log --log-level debug --verbose --mirror http://mirror.lan/debian/



echo "## ================================================== ##"
echo -e "\t\tchmod manually:"
echo "## ================================================== ##"
sudo chmod a+w ./test.img


















echo "## =================================================================== ##"
echo -e "\tExecute using qemu, e.g. on amd64 using qemu-system-x86_64:"
echo "## =================================================================== ##"
qemu-system-x86_64 -drive format=raw,file=./test.img

/usr/share/vmdebootstrap/qemu-wrapper.sh jessie.img amd64


qemu-system-x86_64 -L /usr/share/ovmf/ -machine accel=kvm -m 4096 -smp 2 -drive format=raw,file=test.img



sudo yarns/run-tests --env TESTS=build --env MIRROR=http://mirror/debian

sudo yarns/run-tests --env TESTS=build --env MIRROR=http://mirror/debian





qemu-system-x86_64 -machine help
qemu-system-x86_64 -chardev help

qemu-system-x86_64 '-device help'			## print all possible drivers
qemu-system-x86_64 '-device driver,help' 	## print all possible properties
qemu-system-x86_64 -audio-help				## print list of audio drivers and their options
qemu-system-x86_64 -soundhw help'			## get the list of supported cards
qemu-system-x86_64 '-soundhw all'			## enable all of them

qemu-system-x86_64 -cpu help


echo "## =================================================================== ##"
echo -e "\t Get a list of log items:"
echo "## =================================================================== ##"
qemu-system-x86_64 -d help' for a list of log items

echo "## =================================================================== ##"
echo -e "\t Get a list of trace events"
echo "## =================================================================== ##"
qemu-system-x86_64 -d trace:help"


echo "## =================================================================== ##"
echo -e "\t "
echo "## =================================================================== ##"
-boot [order=drives][,once=drives][,menu=on|off]
      [,splash=sp_name][,splash-time=sp_time][,reboot-timeout=rb_time][,strict=on|off]
                'drives': floppy (a), hard disk (c), CD-ROM (d), network (n)
                'sp_name': the file's name that would be passed to bios as logo picture, if menu=on
                'sp_time': the period that splash picture last if menu=on, unit is ms
                'rb_timeout': the timeout before guest reboot when boot failed, unit is ms


echo "## =================================================================== ##"
echo -e "\t "
echo "## =================================================================== ##"
-virtfs local,path=path,mount_tag=tag,security_model=[mapped-xattr|mapped-file|passthrough|none]
        [,writeout=immediate][,readonly][,socket=socket|sock_fd=sock_fd]
-virtfs_synth Create synthetic file system image





-mtdblock file  use 'file' as on-board Flash memory image
-sd file        use 'file' as SecureDigital card image
-pflash file    use 'file' as a parallel flash image
-snapshot       write to temporary files instead of disk image files



echo "## =================================================================== ##"
echo -e "\t "
echo "## =================================================================== ##"
-drive [file=file][,if=type][,bus=n][,unit=m][,media=d][,index=i]
       [,cyls=c,heads=h,secs=s[,trans=t]][,snapshot=on|off]
       [,cache=writethrough|writeback|none|directsync|unsafe][,format=f]
       [,serial=s][,addr=A][,rerror=ignore|stop|report]
       [,werror=ignore|stop|report|enospc][,id=name][,aio=threads|native]
       [,readonly=on|off][,copy-on-read=on|off]
       [,discard=ignore|unmap][,detect-zeroes=on|off|unmap]
       [[,bps=b]|[[,bps_rd=r][,bps_wr=w]]]
       [[,iops=i]|[[,iops_rd=r][,iops_wr=w]]]
       [[,bps_max=bm]|[[,bps_rd_max=rm][,bps_wr_max=wm]]]
       [[,iops_max=im]|[[,iops_rd_max=irm][,iops_wr_max=iwm]]]
       [[,iops_size=is]]
       [[,group=g]]
                use 'file' as a drive image


echo "## ================================================================================= ##"
echo -e "\tCreates a cryptodev backend which executes crypto opreation from the QEMU cipher APIS. "
echo "## ================================================================================= ##"
echo "## --------------------------------------------------------------------------------- ##"
echo -e "\t The id parameter is a unique ID that will be used to "
echo -e "\t Reference this cryptodev backend from the virtio-crypto device. "
echo "## --------------------------------------------------------------------------------- ##"
qemu-system-x86_64 -object cryptodev-backend-builtin,id=id -device virtio-crypto-pci,id=crypto0,cryptodev=cryptodev0

echo "## =============================================================================================== ##"
echo -e "\tDefines a secret to store a password, encryption key, or some other sensitive data."
echo "## =============================================================================================== ##"
-object secret,id=id,file=filename,format=raw|base64[,keyid=secretid,iv=string


echo "## =================================================================== ##"
echo -e "\t "
echo "## =================================================================== ##"
For greater security, AES-256-CBC should be used


echo "## =================================================================== ##"
echo -e "\tFirst a master key needs to be created in base64 encoding:"
echo "## =================================================================== ##"
openssl rand -base64 32 > key.b64
KEY=$(base64 -d key.b64 | hexdump  -v -e '/1 "%02X"')


echo "## =================================================================== ##"
echo -e "\tEach secret to be encrypted needs to have a random initialization "
echo -e "\tVector generated. These do not need to be kept secret"
echo "## =================================================================== ##"
openssl rand -base64 16 > iv.b64
IV=$(base64 -d iv.b64 | hexdump  -v -e '/1 "%02X"')


echo "## =================================================================== ##"
echo -e "\tThe secret to be defined can now be encrypted, "
echo -e "\tin this case were telling openssl to base64 encode "
echo -e "\tthe result, but it could be left as raw bytes if desired."
echo "## =================================================================== ##"
SECRET=$(echo -n "letmein" |
openssl enc -aes-256-cbc -a -K $KEY -iv $IV)


QEMU -object secret,id=secmaster0,format=base64,file=key.b64 \
                       -object secret,id=sec0,keyid=secmaster0,format=base64,\
                       data=$SECRET,iv=$(<iv.b64)




-mem-path FILE  provide backing storage for guest RAM
-mem-prealloc   preallocate guest memory (use with -mem-path)

-m [size=]megs[,slots=n,maxmem=size]
                configure guest RAM
                size: initial amount of guest memory
                slots: number of hotplug slots (default: none)
                maxmem: maximum amount of guest memory (default: none)

echo "## ========================================================================================= ##"
echo -e "\tSets guest startup RAM size to megs megabytes. Default is 128 MiB"
echo "## ========================================================================================= ##"
qemu-system-x86_64 -m 1G,slots=3,maxmem=4G




echo "## ========================================================================================= ##"
echo -e "\tSet OpenBIOS variables in NVRAM, for example:"
echo "## ========================================================================================= ##"
qemu-system-ppc -prom-env 'auto-boot?=false' -prom-env 'boot-device=hd:2,\yaboot' -prom-env 'boot-args=conf=hd:2,\yaboot.conf'




echo "## ========================================================================================= ##"
echo -e "\tYou can open an image using pre-opened file descriptors from an fd set:"
echo "## ========================================================================================= ##"
qemu-system-i386 -add-fd fd=3,set=2,opaque="rdwr:/path/to/file"
qemu-system-i386 -add-fd fd=4,set=2,opaque="rdonly:/path/to/file"
qemu-system-i386 -drive file=/dev/fdset/2,index=0,media=disk




echo "## ========================================================================================= ##"
echo -e "\tSet default value of drivers property prop to value"
echo "## ========================================================================================= ##"
qemu-system-i386 -global ide-drive.physical_block_size=4096 -drive file=file,if=ide,index=0,media=disk


echo "## ========================================================================================= ##"
echo -e "\tBoot from CD-ROM first, switch back to default order after reboot"
echo "## ========================================================================================= ##"
qemu-system-i386 -boot once=d


echo "## ========================================================================================= ##"
echo -e "\tBoot with a splash picture for 5 seconds."
echo "## ========================================================================================= ##"
qemu-system-i386 -boot menu=on,splash=/root/boot.bmp,splash-time=5000




echo "## ========================================================================================= ##"
echo -e "\tEnable audio and selected sound hardware."
echo "## ========================================================================================= ##"
qemu-system-i386 -soundhw hda disk.img
qemu-system-i386 -soundhw all disk.img
qemu-system-i386 -soundhw help




echo "## ========================================================================================= ##"
echo -e "\tInstead of -cdrom you can use:"
echo "## ========================================================================================= ##"
qemu-system-i386 -drive file=file,index=2,media=cdrom


echo "## ========================================================================================= ##"
echo -e "\tYou can connect a CDROM to the slave of ide0:"
echo "## ========================================================================================= ##"
qemu-system-i386 -drive file=file,if=ide,index=1,media=cdrom


echo "## ========================================================================================= ##"
echo -e "\tIf you don't specify the "file=" argument, you define an empty drive:"
echo "## ========================================================================================= ##"
qemu-system-i386 -drive if=ide,index=1,media=cdrom


echo "## ========================================================================================= ##"
echo -e "\tYou can connect a SCSI disk with unit ID 6 on the bus #0:"
echo "## ========================================================================================= ##"
qemu-system-i386 -drive file=file,if=scsi,bus=0,unit=6


echo "## ========================================================================================= ##"
echo -e "\tInstead of -fda, -fdb, you can use:"
echo "## ========================================================================================= ##"
qemu-system-i386 -drive file=file,index=0,if=floppy
qemu-system-i386 -drive file=file,index=1,if=floppy



echo "## ========================================================================================= ##"
echo -e "\tBy default, interface is "ide" and index is automatically incremented:"
echo "## ========================================================================================= ##"
qemu-system-i386 -drive file=a -drive file=b"


echo "## ========================================================================================= ##"
echo -e "\tIs interpreted like:"
echo "## ========================================================================================= ##"
qemu-system-i386 -hda a -hdb b







echo "## ========================================================================================= ##"
echo -e "\tDisable copy paste between the client and the guest."
echo "## ========================================================================================= ##"
disable-copy-paste


echo "## ========================================================================================= ##"
echo -e "\tDisable spice-vdagent based file-xfer between the client and the guest."
echo "## ========================================================================================= ##"
disable-agent-file-xfer


echo "## ========================================================================================= ##"
echo -e "\tSet the TCP port spice is listening on for encrypted channels."
echo "## ========================================================================================= ##"
tls-port=<nr>


echo "## ========================================================================================= ##"
echo -e "\tSet the x509 file directory. Expects same filenames as -vnc $display,x509=$dir"
echo "## ========================================================================================= ##"
x509-dir=<dir>


echo "## ========================================================================================= ##"
echo -e "\tThe x509 file names can also be configured individually."
echo "## ========================================================================================= ##"
x509-key-file=<file>
x509-key-password=<file>
x509-cert-file=<file>
x509-cacert-file=<file>
x509-dh-key-file=<file>


echo "## ========================================================================================= ##"
echo -e "\tSpecify which ciphers to use."
echo "## ========================================================================================= ##"
tls-ciphers=<list>


-object tls-creds-x509,id=id,endpoint=endpoint,dir=/path/to/cred/dir,verify-peer=on|off,passwordid=id


x509 certificate credentials  must be stored in PEM format
ca-cert.pem
ca-crl.pem (optional)
server-cert.pem (only servers)
server-key.pem (only servers)
client-cert.pem (only clients)
client-key.pem (only clients)
dh-params.pem




Character device options:
-chardev help
-chardev null,id=id[,mux=on|off][,logfile=PATH][,logappend=on|off]
-chardev socket,id=id[,host=host],port=port[,to=to][,ipv4][,ipv6][,nodelay][,reconnect=seconds]
         [,server][,nowait][,telnet][,reconnect=seconds][,mux=on|off]
         [,logfile=PATH][,logappend=on|off][,tls-creds=ID] (tcp)
-chardev socket,id=id,path=path[,server][,nowait][,telnet][,reconnect=seconds]
         [,mux=on|off][,logfile=PATH][,logappend=on|off] (unix)
-chardev udp,id=id[,host=host],port=port[,localaddr=localaddr]
         [,localport=localport][,ipv4][,ipv6][,mux=on|off]
         [,logfile=PATH][,logappend=on|off]
-chardev msmouse,id=id[,mux=on|off][,logfile=PATH][,logappend=on|off]
-chardev vc,id=id[[,width=width][,height=height]][[,cols=cols][,rows=rows]]
         [,mux=on|off][,logfile=PATH][,logappend=on|off]
-chardev ringbuf,id=id[,size=size][,logfile=PATH][,logappend=on|off]
-chardev file,id=id,path=path[,mux=on|off][,logfile=PATH][,logappend=on|off]
-chardev pipe,id=id,path=path[,mux=on|off][,logfile=PATH][,logappend=on|off]
-chardev pty,id=id[,mux=on|off][,logfile=PATH][,logappend=on|off]
-chardev stdio,id=id[,mux=on|off][,signal=on|off][,logfile=PATH][,logappend=on|off]
-chardev braille,id=id[,mux=on|off][,logfile=PATH][,logappend=on|off]
-chardev serial,id=id,path=path[,mux=on|off][,logfile=PATH][,logappend=on|off]
-chardev tty,id=id,path=path[,mux=on|off][,logfile=PATH][,logappend=on|off]
-chardev parallel,id=id,path=path[,mux=on|off][,logfile=PATH][,logappend=on|off]
-chardev parport,id=id,path=path[,mux=on|off][,logfile=PATH][,logappend=on|off]




echo "## ========================================================================================= ##"
echo -e "\tUse file as hard disk 0, 1, 2 or 3 image."
echo "## ========================================================================================= ##"
-hda <file>
-hdb <file>
-hdc <file>
-hdd <file>



echo "## ========================================================================================= ##"
echo -e "\tUse file as CD-ROM image"
echo "## ========================================================================================= ##"
-cdrom <file>


echo "## ========================================================================================= ##"
echo -e "\tDefine a new drive"
echo "## ========================================================================================= ##"
-drive 


echo "## ========================================================================================= ##"
echo -e "\tDefines which disk image to use with this drive."
echo "## ========================================================================================= ##"
file=<file>

echo "## ========================================================================================= ##"
echo -e "\tDefines on which type on interface the drive is connected."
echo "## ========================================================================================= ##"
echo "## ----------------------------------------------------------------------------------------- ##"
echo -e "\tAvailable types are: ide, scsi, sd, mtd,floppy, pflash, virtio."
echo "## ----------------------------------------------------------------------------------------- ##"
if=wlan0


echo "## ========================================================================================= ##"
echo -e "\tDefine where is connected the drive by defining the bus number and the unit id."
echo "## ========================================================================================= ##"
bus=bus,unit=unit



echo "## ========================================================================================= ##"
echo -e "\tDefines where is connected the drive by using an index inside: "
echo -e "\tThe list of available connectors of a given interface type."
echo "## ========================================================================================= ##"
index=index


echo "## ========================================================================================= ##"
echo -e "\tThis option defines the type of the media: disk or cdrom."
echo "## ========================================================================================= ##"
media=disk|cdrom






echo "## ========================================================================================= ##"
echo -e "\tDefine a new file system device"
echo "## ========================================================================================= ##"
-fsdev


echo "## ========================================================================================= ##"
echo -e "\tBoots as Read Only"
echo "## ========================================================================================= ##"
readonly


echo "## ========================================================================================= ##"
echo -e "\t"
echo "## ========================================================================================= ##"
security_model=

echo "## ========================================================================================= ##"
echo -e "\tFiles are stored using the same credentials as they are created on the guest. "
echo -e "\tThis requires QEMU to run as root."
echo "## ========================================================================================= ##"
"passthrough"

echo "## ========================================================================================= ##"
echo -e "\tSome of the file attributes like: "
echo -e "\tuid, gid, mode bits and link target are stored as file attributes."
echo "## ========================================================================================= ##"
"mapped-xattr"

echo "## ========================================================================================= ##"
echo -e "\tAttributes are stored inside the hidden .virtfs_metadata directory."
echo "## ========================================================================================= ##"
"mapped-file"







echo "## ========================================================================================= ##"
echo -e "\tSet the password you need to authenticate."
echo "## ========================================================================================= ##"

password=

echo "## ========================================================================================= ##"
echo -e "\tStartup in full screen mode:"
echo "## ========================================================================================= ##"
-full-screen



echo "## ========================================================================================= ##"
echo -e "\tVNC Security setup:"
echo "## ========================================================================================= ##"

-vnc 
-usbdevice tablet
reverse

vnc_security

x509verify

tls


echo "## ========================================================================================= ##"
echo -e "\tProvides the ID of a set of TLS credentials to use to secure the VNC server."
echo "## ========================================================================================= ##"
-object tls-creds

echo "## ========================================================================================= ##"
echo -e "\t"
echo "## ========================================================================================= ##"
set_password vnc <password>
expire_password <protocol>
<expiration-time>


echo "## ========================================================================================= ##"
echo -e "\t"
echo "## ========================================================================================= ##"
acl
echo "## ========================================================================================= ##"
echo -e "\t"
echo "## ========================================================================================= ##"

sasl
/etc/sasl2/qemu.conf.
SASL_CONF_PATH




echo "## ========================================================================================= ##"
echo -e "\tRequire that x509 credentials are used for negotiating the TLS session."
echo "## ========================================================================================= ##"
x509verify=/path/to/certificate/dir


echo "## ========================================================================================= ##"
echo -e "\tRequire that x509 credentials are used for negotiating the TLS session."
echo "## ========================================================================================= ##"
x509=/path/to/certificate/dir


echo "## ========================================================================================= ##"
echo -e "\tSet display sharing policy"
echo "## ========================================================================================= ##"
share=allow-exclusive|force-shared|ignore


echo "## ========================================================================================= ##"
echo -e "\tAllows clients to ask for exclusive access."
echo "## ========================================================================================= ##"
share='allow-exclusive' 

echo "## ========================================================================================= ##"
echo -e "\tDisables exclusive client access."
echo "## ========================================================================================= ##"
share='force-shared' 


echo "## ========================================================================================= ##"
echo -e "\tCompletely ignores the shared flag and allows everybody connect unconditionally."
echo "## ========================================================================================= ##"
share='ignore' 

echo "## ========================================================================================= ##"
echo -e "\tDisable ACPI (Advanced Configuration and Power Interface) support"
echo "## ========================================================================================= ##"
-no-acpi





Bluetooth(R) options:
qemu-system-x86_64 -bt hci,null    dumb bluetooth HCI - doesn't respond to commands
qemu-system-x86_64 -bt hci,host[:id]
                use host's HCI with the given name
qemu-system-x86_64 -bt hci[,vlan=n]
                emulate a standard HCI in virtual scatternet 'n'
qemu-system-x86_64 -bt vhci[,vlan=n]
                add host computer to virtual scatternet 'n' using VHCI
qemu-system-x86_64 -bt device:dev[,vlan=n]
                emulate a bluetooth device 'dev' in scatternet 'n'


qemu-system-x86_64 -netdev socket,id=str[,fd=h][,listen=[host]:port][,connect=host:port]
                configure a network backend to connect to another network
                using a socket connection
qemu-system-x86_64 -netdev socket,id=str[,fd=h][,mcast=maddr:port[,localaddr=addr]]
                configure a network backend to connect to a multicast maddr and port
                use 'localaddr=addr' to specify the host address to send packets from
qemu-system-x86_64 -netdev socket,id=str[,fd=h][,udp=host:port][,localaddr=host:port]
                configure a network backend to connect to another network
                using an UDP tunnel
qemu-system-x86_64 -netdev vde,id=str[,sock=socketpath][,port=n][,group=groupname][,mode=octalmode]
                configure a network backend to connect to port 'n' of a vde switch
                running on host and listening for incoming connections on 'socketpath'.
                Use group 'groupname' and mode 'octalmode' to change default
                ownership and permissions for communication port.
qemu-system-x86_64 -netdev vhost-user,id=str,chardev=dev[,vhostforce=on|off]
                configure a vhost-user network, backed by a chardev 'dev'
qemu-system-x86_64 -netdev hubport,id=str,hubid=n
                configure a hub port on QEMU VLAN 'n'

echo "## ========================================================================================= ##"
echo -e "\tList of available devices"
echo "## ========================================================================================= ##"
qemu-system-x86_64 -net nic,model=help

echo "## ========================================================================================= ##"

echo "## ========================================================================================= ##"

echo "## ----------------------------------------------------------------------- ##"
echo -e "'src=' to specify source address"
echo -e "'dst=' to specify destination address"
echo -e "'udp=on' to specify udp encapsulation"
echo -e "'srcport=' to specify source udp port"
echo -e "'dstport=' to specify destination udp port"
echo -e "'ipv6=on' to force v6"
echo "## ----------------------------------------------------------------------- ##"

echo "## ========================================================================================= ##"
echo -e "L2TPv3 uses cookies to prevent misconfiguration as"
echo -e "well as a weak security measure"
echo "## ========================================================================================= ##"
echo "## ----------------------------------------------------------------------- ##"
echo -e "'rxcookie=0x012345678' to specify a rxcookie"
echo -e "'txcookie=0x012345678' to specify a txcookie"
echo -e "'cookie64=on' to set cookie size to 64 bit, otherwise 32"
echo -e "'counter=off' to force a 'cut-down' L2TPv3 with no counter"
echo -e "'pincounter=on' to work around broken counter handling in peer"
echo -e "'offset=X' to add an extra offset between header and data
echo "## ----------------------------------------------------------------------- ##"








qemu-system-x86_64 -netdev bridge,id=str[,br=bridge][,helper=helper]
                configure a host TAP network backend with ID 'str' that is
                connected to a bridge (default=br0)
                using the program 'helper (default=/usr/lib/qemu/qemu-bridge-helper)



echo "## =========================================================================================== ##"
echo -e "\t\t\t Configure a host TAP network backend with ID 'str'"
echo "## =========================================================================================== ##"
qemu-system-x86_64 -netdev tap,id=str[,fd=h][,fds=x:y:...:z][,ifname=name][,script=file][,downscript=dfile]


echo "## =========================================================================================== ##"
echo -e "\t\t\t connected to a bridge (default=br0)"
echo "## =========================================================================================== ##"
,br=bridge,helper=helper][,sndbuf=nbytes][,vnet_hdr=on|off][,vhost=on|off]
,vhostfd=h][,vhostfds=x:y:...:z][,vhostforce=on|off][,queues=n]
,poll-us=n
                
                

echo "## + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + ##"
echo "## =========================================================================================== ##"
echo -e "\t\t\t Network scripts file:"
echo "## =========================================================================================== ##"
echo -e "\t ## ------------------------------------------------------------------------------------- ##"
echo -e "\t\t Enable network scripts (default=/etc/qemu-ifup)
echo -e "\t ## ------------------------------------------------------------------------------------- ##"
echo -e "\t\t Disable network scripts (default=/etc/qemu-ifdown)
echo -e "\t ## ------------------------------------------------------------------------------------- ##"
echo "## + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + ##"

echo
echo "## + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + ##"
echo "## =========================================================================================== ##"
echo -e "network helper 'helper' \t\t Configure qemu-bridge-helper" 
echo "## =========================================================================================== ##"
echo "## ------------------------------------------------------------------------------------- ##"
echo -e "\t\t \ndefault=/usr/lib/qemu/qemu-bridge-helper"
echo "## ------------------------------------------------------------------------------------- ##"
echo "## + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + ##"
echo

echo
echo "## + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + ##"
echo "## =========================================================================================== ##"
echo -e "'sndbuf=nbytes' \t\t Limit the size of the send buffer "
echo "## =========================================================================================== ##"
echo -e "\t ## ------------------------------------------------------------------------------------- ##"
echo -e "\t\t The default is disabled 'sndbuf=0' "
echo -e "\t\t To Enable flow control set 'sndbuf=1048576' "
echo -e "\t ## ------------------------------------------------------------------------------------- ##"
echo "## + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + ##"
echo

echo
echo "## + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + ##"
echo "## =========================================================================================== ##"
echo -e "vhost=on \t\t Enable experimental in kernel accelerator"
echo "## =========================================================================================== ##"
echo -e "## ----------------------------------------------------- ##"
echo -e " >> (only has effect for virtio guests which use MSIX)"
echo -e "## ----------------------------------------------------- ##"
echo "## + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + ##"
echo
echo
echo "## =========================================================================================== ##"
echo -e "'[down]script=no' \t\t Disable script execution"
echo "## =========================================================================================== ##"
echo "## =========================================================================================== ##"
echo -e "'fd=h' \t\t\t Connect to an already opened TAP interface"
echo "## =========================================================================================== ##"
echo -e "'fds=x:y:...:z' \t\t Connect to already opened multiqueue capable TAP interfaces"
echo "## =========================================================================================== ##"
echo -e "vnet_hdr=off \t\t Avoid enabling the IFF_VNET_HDR tap flag"
echo "## =========================================================================================== ##"
echo -e "vnet_hdr=on \t\t Make the lack of IFF_VNET_HDR support an error condition"
echo "## =========================================================================================== ##"
echo -e "vhostforce=on \t\t Force vhost on for non-MSIX virtio guests"
echo "## =========================================================================================== ##"
echo -e "'vhostfd=h' \t\t Connect to an already opened vhost net device"
echo "## =========================================================================================== ##"
echo -e "'vhostfds=x:y:...:z \t Connect to multiple already opened vhost net devices"
echo "## =========================================================================================== ##"
echo -e "'queues=n' \t\t Specify the number of queues to be created for multiqueue TAP"
echo "## =========================================================================================== ##"
echo -e "'poll-us=n' \t\t Specify the max micro secs spent busy polling for vhost net"
echo "## =========================================================================================== ##"







qemu-system-x86_64 -netdev tap
,id=<str>
,fd=<h>
,fds=<x:y:...:z>
,ifname=<name>
,script=<file>
,downscript=<dfile>

echo "## =========================================================================================== ##"
echo -e "\t\t\t connected to a bridge (default=br0)"
echo "## =========================================================================================== ##"
,br=<bridge>
,helper=<helper>
,sndbuf=<nbytes>
,vnet_hdr=on|off
,vhost=on|off
,vhostfd=<h
,vhostfds=<x:y:...:z>
,vhostforce=on|off
,queues=<n>
,poll-us=<n>









echo "## ========================================================================================= ##"
echo -e "\tCreate a new Network Interface Card and connect it to VLAN"
echo "## ========================================================================================= ##"
qemu-system-x86_64 -net nic,vlan=<n>,macaddr=<mac>,model=<type>,name=<name>,addr=<addr>


qemu-system-x86_64 -netdev user,id=



echo "## ========================================================================================= ##"
echo -e "\tIf enabled guest will be isolated, it will not be able to contact "
echo -e "\tThe host and no guest IP packets will be routed over the host to the outside."
echo "## ========================================================================================= ##"
restrict=on


echo "## ========================================================================================= ##"
echo -e "\tProvides an entry for the domain-search list sent by the built-in DHCP server."
echo "## ========================================================================================= ##"
qemu -net user,dnssearch=mgmt.example.org,dnssearch=example.org


echo "## ========================================================================================= ##"
echo -e "\tNetwork boot a guest from a local directory"
echo "## ========================================================================================= ##"
qemu-system-x86_64 -hda linux.img -boot n -net user,tftp=/path/to/tftp/files,bootfile=/pxelinux.0




echo "## +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ ##"
echo "## ========================================================================================= ##"
echo -e "\tRedirect incoming TCP or UDP connections to the:"
echo -e "\t Host port > host port > Guest IP address > Guestaddr:<Guest Port>"
echo "## ========================================================================================= ##"
echo "## +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ ##"
qemu-system-x86_64 hostfwd=[tcp|udp]:[hostaddr]:hostport-[guestaddr]:guestport


echo "## ========================================================================================= ##"
echo -e "\tTo redirect host X11 connection from screen 1 to guest screen 0, use the following:"
echo "## ========================================================================================= ##"


echo "## ========================================================================================= ##"
echo -e "\tOn the host"
echo "## ========================================================================================= ##"
qemu-system-i386 -net user,hostfwd=tcp:127.0.0.1:6001-:6000


echo "## ========================================================================================= ##"
echo -e "\tThis host xterm should open in the guest X11 server"
echo "## ========================================================================================= ##"
xterm -display :1



echo "## ######################################################################################### ##"
echo "## +++++++++++++++++++++++++++ End CLI Command Seq +++++++++++++++++++++++++++++++++++++++++ ##"
echo "## ######################################################################################### ##"



echo "## +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ ##"
echo "## ========================================================================================= ##"
echo -e "\t\t\t To redirect telnet connections"
echo -e "\t\t From host port 5555 to telnet port on the guest"
echo -e "\t\t\t Use the following:"
echo "## ========================================================================================= ##"
echo "## +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ ##"


echo "## ========================================================================================= ##"
echo -e "\tOn the host type:"
echo "## ========================================================================================= ##"
qemu-system-i386 -net user,hostfwd=tcp::5555-:23
telnet localhost 5555


echo "## ========================================================================================= ##"
echo -e "\tThen when you use on the host telnet localhost 5555"
echo -e "\tYou connect to the guest telnet server."
echo "## ========================================================================================= ##"


echo "## ######################################################################################### ##"
echo "## +++++++++++++++++++++++++++ End CLI Command Seq +++++++++++++++++++++++++++++++++++++++++ ##"
echo "## ######################################################################################### ##"







echo "## +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ ##"
echo "## ========================================================================================= ##"
echo -e "\t Execute a command on every TCP connection established by the guest "
echo -e "\t So that QEMU behaves similar to an inetd process through the virtual server:"
echo "## ========================================================================================= ##"
echo "## +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ ##"


echo "## ========================================================================================= ##"
echo -e "\t Open 10.10.1.1:4321 on bootup, "
echo -e "\t Connect 10.0.2.100:1234 to it wheneverThe guest accesses it"
echo "## ========================================================================================= ##"
qemu -net user,guestfwd=tcp:10.0.2.100:1234-tcp:10.10.1.1:4321


echo "## ========================================================================================= ##"
echo -e "\t Call "netcat 10.10.1.1 4321" on every TCP connection to 10.0.2.100:1234"
echo -e "\t And connect the TCP stream to its stdin/stdout"
echo "## ========================================================================================= ##"
qemu -net 'user,guestfwd=tcp:10.0.2.100:1234-cmd:netcat 10.10.1.1 4321'



echo "## ######################################################################################### ##"
echo "## +++++++++++++++++++++++++++ End CLI Command Seq +++++++++++++++++++++++++++++++++++++++++ ##"
echo "## ######################################################################################### ##"







echo "## ========================================================================================= ##"
echo -e "\tLaunch a QEMU instance with the default network script"
echo "## ========================================================================================= ##"
qemu-system-i386 linux.img -net nic -net tap

echo "## ============================================ ##"
echo -e "\tLaunch a QEMU instance with two NICs"
echo -e "\tEach one connected to a TAP device"
echo "## ============================================ ##"
qemu-system-i386 linux.img -net nic,vlan=0 -net tap,vlan=0,ifname=tap0 -net nic,vlan=1 -net tap,vlan=1,ifname=tap1


echo "## ========================================================================================= ##"
echo -e "\tLaunch a QEMU instance with the default network helper to"
echo -e "\tConnect a TAP device to bridge br0""
echo "## ========================================================================================= ##"
qemu-system-i386 linux.img -net nic -net tap,"helper=/path/to/qemu-bridge-helper"


echo "## ========================================================================================= ##"
echo -e "\tLaunch a QEMU instance with the default network "
echo -e "\tHelper to Connect a TAP device to bridge br0"
echo "## ========================================================================================= ##"
qemu-system-i386 linux.img -net bridge -net nic,model=virtio



echo "## ========================================================================================= ##"
echo -e "\tLaunch a QEMU instance with the default network helper to"
echo -e "\tConnect a TAP device to bridge qemubr0"
echo "## ========================================================================================= ##"
qemu-system-i386 linux.img -net bridge,br=qemubr0 -net nic,model=virtio



echo "## ========================================================================================= ##"
echo -e "\tConnect the VLAN n to a remote VLAN in another QEMU virtual machine using a TCP socket connection."
echo "## ========================================================================================= ##"
-netdev socket,id=id[,fd=h][,listen=[host]:port][,connect=host:port
-net socket[,vlan=n][,name=name][,fd=h] [,listen=[host]:port][,connect=host:port

echo "## ========================================================================================= ##"
echo -e "\tLaunch a first QEMU instance"
echo "## ========================================================================================= ##"
qemu-system-i386 linux.img -net nic,macaddr=52:54:00:12:34:56 -net socket,listen=:1234


echo "## ========================================================================================= ##"
echo -e "\tConnect the VLAN 0 of this instance to the VLAN 0"
echo -e "\tOf the first instance"
echo "## ========================================================================================= ##"
qemu-system-i386 linux.img -net nic,macaddr=52:54:00:12:34:57 -net socket,connect=127.0.0.1:1234


echo "## ========================================================================================= ##"
echo -e "\tCreate a VLAN n shared with another QEMU virtual machines using a UDP multicast socket, "
echo -e "\tEffectively making a bus for every QEMU with same multicast address maddr and port."
echo "## ========================================================================================= ##"



echo "## ========================================================================================= ##"
Several QEMU can be running on different hosts and share same bus "
(assuming correct multicast setup for these hosts)."
echo "## ========================================================================================= ##"


echo "## ========================================================================================= ##"
echo -e "\tLaunch one QEMU instance"
echo "## ========================================================================================= ##"
qemu-system-i386 linux.img -net nic,macaddr=52:54:00:12:34:56 -net socket,mcast=230.0.0.1:1234


echo "## ========================================================================================= ##"
echo -e "\tLaunch another QEMU instance on same bus"
echo "## ========================================================================================= ##"
qemu-system-i386 linux.img -net nic,macaddr=52:54:00:12:34:57 -net socket,mcast=230.0.0.1:1234


echo "## ========================================================================================= ##"
echo -e "\tlaunch yet another QEMU instance on same bus"
echo "## ========================================================================================= ##"
qemu-system-i386 linux.img -net nic,macaddr=52:54:00:12:34:58 -net socket,mcast=230.0.0.1:1234


echo "## ========================================================================================= ##"
echo -e "\tExample (User Mode Linux compat)"
echo "## ========================================================================================= ##"


echo "## ========================================================================================= ##"
echo -e "\tLaunch QEMU instance "
echo -e "\t Note mcast address selected is UML's default "
echo "## ========================================================================================= ##"
qemu-system-i386 linux.img -net nic,macaddr=52:54:00:12:34:56 -net socket,mcast=239.192.168.1:1102

echo "## ========================================================================================= ##"
echo -e "\tLaunch UML"
echo "## ========================================================================================= ##"
/path/to/linux ubd0=/path/to/root_fs eth0=mcast

echo "## ========================================================================================= ##"
echo -e "\tExample (send packets from host's 1.2.3.4):"
echo "## ========================================================================================= ##"
qemu-system-i386 linux.img -net nic,macaddr=52:54:00:12:34:56 -net socket,mcast=239.192.168.1:1102,localaddr=1.2.3.4



echo "## ==================================================== ##"
echo -e "\tTo attach a VM running on host 4.3.2.1 via L2TPv3 to "
echo -e "\tThe bridge br-lan on the remote Linux host 1.2.3.4:"
echo "## ==================================================== ##"

echo "## ============================================ ##"
echo -e "\tSetup tunnel on linux host using raw "
echo -e "\tIP as encapsulation on 1.2.3.4"
echo "## ============================================ ##"
ip l2tp add tunnel remote 4.3.2.1 local 1.2.3.4 tunnel_id 1 peer_tunnel_id 1 encap udp udp_sport 16384 udp_dport 16384
ip l2tp add session tunnel_id 1 name vmtunnel0 session_id 0xFFFFFFFF peer_session_id 0xFFFFFFFF
ifconfig vmtunnel0 mtu 1500
ifconfig vmtunnel0 up
brctl addif br-lan vmtunnel0



echo "## ========================================================================================= ##"
echo -e "\tOn 4.3.2.1 launch QEMU instance"
echo "## ========================================================================================= ##"

qemu-system-i386 linux.img -net nic -net l2tpv3,src=4.2.3.1,dst=1.2.3.4,udp,srcport=16384,dstport=16384,rxsession=0xffffffff,txsession=0xffffffff,counter



echo "## ========================================================================================= ##"
echo -e "\tConnect VLAN n to PORT n of a vde switch running on host and "
echo -e "\tlistening for incoming connections on socketpath."
echo "## ========================================================================================= ##"



echo "## ========================================================================================= ##"
echo -e "\tLaunch vde switch"
echo "## ========================================================================================= ##"
vde_switch -F -sock /tmp/myswitch



echo "## ========================================================================================= ##"
echo -e "\tLaunch QEMU instance"
echo "## ========================================================================================= ##"
qemu-system-i386 linux.img -net nic -net vde,sock=/tmp/myswitch



-net l2tpv3,vlan=wlan0,name=<name>,src=<srcaddr>,dst=<dstaddr>,srcport=<srcport>,dstport=<dstport>


echo "## ========================================================================================= ##"
echo -e "\tDump PCAP File of Current Network Traffic For Later Forensic Network Analysis"
echo "## ========================================================================================= ##"
-net dump,vlan=wlan0,file=qemu-vlan0.pcap


echo "## ========================================================================================= ##"
echo -e "\t Dump the network traffic on netdev dev to the file"
echo "## ========================================================================================= ##"
-object filter-dump,id=id,netdev=dev[,file=filename][,maxlen=len]
               



echo "## ========================================================================================= ##"
echo -e "\t Output vmstate information in JSON format to file"
echo "## ========================================================================================= ##"
-dump-vmstate

-chroot dir     chroot to dir just before starting the VM
-runas user     change to user id user just before starting the VM
-sandbox <arg>  Enable seccomp mode 2 system call filter (default 'off').




-L path         set the directory for the BIOS, VGA BIOS and keymaps
-bios file      set the filename for the BIOS
-enable-kvm     enable KVM full virtualization support
-xen-domid id   specify xen guest domain id
-xen-create     create domain using xen hypercalls, bypassing xend
                warning: should not be used when xend is in use
-xen-attach     attach to existing xen domain
-D logfile      output log to logfile (default stderr)



-fw_cfg [name=]<name>,file=<file>
                add named fw_cfg entry with contents from file
-fw_cfg [name=]<name>,string=<str>
                add named fw_cfg entry with contents from string




TPM device options:


echo "## ========================================================================================= ##"
echo -e "\t use path to provide path to a character device; default is /dev/tpm0"
echo -e "\t can be searched for in /sys/class/misc/tpm?/device"
echo "## ========================================================================================= ##"
-tpmdev passthrough,id=id[,path=path][,cancel-path=path]


Linux/Multiboot boot specific:
-kernel bzImage use 'bzImage' as kernel image
-append cmdline use 'cmdline' as kernel command line
-initrd file    use 'file' as initial ram disk
-dtb    file    use 'file' as device tree image








echo "## ========================================================================================= ##"
echo -e "\t "
echo "## ========================================================================================= ##"


echo "## ========================================================================================= ##"
echo -e "\t "
echo "## ========================================================================================= ##"



echo "## ========================================================================================= ##"
echo -e "\t "
echo "## ========================================================================================= ##"


echo "## ========================================================================================= ##"
echo -e "\t "
echo "## ========================================================================================= ##"


echo "## ========================================================================================= ##"
echo -e "\t "
echo "## ========================================================================================= ##"


echo "## ========================================================================================= ##"
echo -e "\t "
echo "## ========================================================================================= ##"



use it with the help of filter-mirror and filter-redirector.

                       primary:
                       -netdev tap,id=hn0,vhost=off,script=/etc/qemu-ifup,downscript=/etc/qemu-ifdown
                       -device e1000,id=e0,netdev=hn0,mac=52:a4:00:12:78:66
                       -chardev socket,id=mirror0,host=3.3.3.3,port=9003,server,nowait
                       -chardev socket,id=compare1,host=3.3.3.3,port=9004,server,nowait
                       -chardev socket,id=compare0,host=3.3.3.3,port=9001,server,nowait
                       -chardev socket,id=compare0-0,host=3.3.3.3,port=9001
                       -chardev socket,id=compare_out,host=3.3.3.3,port=9005,server,nowait
                       -chardev socket,id=compare_out0,host=3.3.3.3,port=9005
                       -object filter-mirror,id=m0,netdev=hn0,queue=tx,outdev=mirror0
                       -object filter-redirector,netdev=hn0,id=redire0,queue=rx,indev=compare_out
                       -object filter-redirector,netdev=hn0,id=redire1,queue=rx,outdev=compare0
                       -object colo-compare,id=comp0,primary_in=compare0-0,secondary_in=compare1,outdev=compare_out0

                       secondary:
                       -netdev tap,id=hn0,vhost=off,script=/etc/qemu-ifup,down script=/etc/qemu-ifdown
                       -device e1000,netdev=hn0,mac=52:a4:00:12:78:66
                       -chardev socket,id=red0,host=3.3.3.3,port=9003
                       -chardev socket,id=red1,host=3.3.3.3,port=9004
                       -object filter-redirector,id=f1,netdev=hn0,queue=tx,indev=red0
                       -object filter-redirector,id=f2,netdev=hn0,queue=rx,outdev=red1



















# Mount a VMware virtual disk (.vmdk) file on a Linux box
kpartx -av <image-flat.vmdk>; mount -o /dev/mapper/loop0p1 /mnt/vmdk




/etc/vmware/networking

add_bridge_mapping eth1 0
add_bridge_mapping eth0 -1
answer VNET_1_DHCP yes
answer VNET_1_DHCP_CFG_HASH 4A4AE55F8580E079D81A16FCF6BBBD7CC5C4039B
answer VNET_1_HOSTONLY_NETMASK 255.255.255.0
answer VNET_1_HOSTONLY_SUBNET 192.168.181.0
answer VNET_1_VIRTUAL_ADAPTER yes
answer VNET_8_DHCP yes
answer VNET_8_DHCP_CFG_HASH 19236B469B0420644DAC5D6C9AF16A2E604C4CB9
answer VNET_8_HOSTONLY_NETMASK 255.255.255.0
answer VNET_8_HOSTONLY_SUBNET 192.168.207.0
answer VNET_8_NAT yes
answer VNET_8_VIRTUAL_ADAPTER yes

ps axuww | egrep 'PID|vmnet-bridge' | cut -c 1-5,9-15,65-


/usr/bin/vmnet-bridge -s 6 -d /var/run/vmnet-bridge-0.pid -n 0 -eeth0







