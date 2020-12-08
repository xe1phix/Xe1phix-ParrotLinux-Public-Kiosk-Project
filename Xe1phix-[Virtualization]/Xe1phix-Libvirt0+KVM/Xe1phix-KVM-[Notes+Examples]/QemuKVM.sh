






|         | Paravirtualization  | Full-virtualization   |
|---------|:--------------------|:----------------------|
| Block   | Virtio SCSI         | IDE                   |
| Net     | Virtio Net          | e1000                 |
| Serial  | ttyS0               | ttyS0                 |








Known virtualization technologies
┌──────────┬────────────────┬──────────────────────────────┐
│Type      │ ID             │ Product                      │
├──────────┼────────────────┼──────────────────────────────┤
│VM        │ qemu           │ QEMU software virtualization │
│          ├────────────────┼──────────────────────────────┤
│          │ kvm            │ Linux KVM kernel virtual     │
│          │                │ machine                      │
│          ├────────────────┼──────────────────────────────┤
│          │ zvm            │ s390 z/VM                    │
│          ├────────────────┼──────────────────────────────┤
│          │ vmware         │ VMware Workstation or        │
│          │                │ Server, and related products │
│          ├────────────────┼──────────────────────────────┤
│          │ microsoft      │ Hyper-V, also known as       │
│          │                │ Viridian or Windows Server   │
│          │                │ Virtualization               │
│          ├────────────────┼──────────────────────────────┤
│          │ oracle         │ Oracle VM VirtualBox         │
│          │                │ (historically marketed by    │
│          │                │ innotek and Sun              │
│          │                │ Microsystems)                │
│          ├────────────────┼──────────────────────────────┤
│          │ xen            │ Xen hypervisor (only domU,   │
│          │                │ not dom0)                    │
│          ├────────────────┼──────────────────────────────┤
│          │ bochs          │ Bochs Emulator               │
│          ├────────────────┼──────────────────────────────┤
│          │ uml            │ User-mode Linux              │
│          ├────────────────┼──────────────────────────────┤
│          │ parallels      │ Parallels Desktop, Parallels │
│          │                │ Server                       │
│          ├────────────────┼──────────────────────────────┤
│          │ bhyve          │ bhyve, FreeBSD hypervisor    │
├──────────┼────────────────┼──────────────────────────────┤
│Container │ openvz         │ OpenVZ/Virtuozzo             │
│          ├────────────────┼──────────────────────────────┤
│          │ lxc            │ Linux container              │
│          │                │ implementation by LXC        │
│          ├────────────────┼──────────────────────────────┤
│          │ lxc-libvirt    │ Linux container              │
│          │                │ implementation by libvirt    │
│          ├────────────────┼──────────────────────────────┤
│          │ systemd-nspawn │ systemds minimal container  │
│          │                │ implementation, see systemd- │
│          │                │ nspawn(1)                    │
│          ├────────────────┼──────────────────────────────┤
│          │ docker         │ Docker container manager     │
│          ├────────────────┼──────────────────────────────┤
│          │ rkt            │ rkt app container runtime    │
└──────────┴────────────────┴──────────────────────────────┘


Open Virtual Machine Format (OVF)
Virtual Machine Disk Format
(VMDK)

Virtual Disk Development Kit (VDDK)

VM monitor (VMM)

VMware storage volumes (VMFS)










.vmdk – virtual hard drive for the guest operation system
.vmem – backup of the virtual machine’s paging file
.vmsn – snapshot file
.vmsd – snapshot metadata
.nvram – virtual machine bios information
.vmx – virtual machine configuration file
.vmss – virtual machine suspended state file
.vmtm – team data configuration
.vmxf – supplemental team configuration file













## creates  a  virtual  tunnel  interface  (atX)  for  sending arbitrary IP packets by using raw
       ieee802.11 packet injection.
airtun-ng -a 00:14:22:56:F3:4E -t 0 -y keystream.xor wlan0








byte  byte      1
      kilobyte  1,000
KiB   kibibyte  1,024
      megabyte  1,000,000
MiB   mebibyte  1,048,576
      gigabyte  1,000,000,000
GiB   gibibyte  1,073,741,824
      terabyte  1,000,000,000,000
TiB   tebibyte  1,099,511,627,776
      petabyte  1,000,000,000,000,000
PiB   pebibyte  1,125,899,906,842,624
      exabyte   1,000,000,000,000,000,000
EiB   exbibyte  1,152,921,504,606,846,976




xen:///
    this is used to connect to the local Xen hypervisor

qemu:///system
    connect locally as root to the daemon supervising QEMU and KVM domains

qemu:///session
    connect locally as a normal user to his own set of QEMU and KVM domains

lxc:///
    connect to a local linux container




 qemu-img format strings¶ Image format 	Argument to qemu-img
QCOW2 (KVM, Xen) 	qcow2
QED (KVM) 	qed
raw 	raw
VDI (VirtualBox) 	vdi
VHD (Hyper-V) 	vpc
VMDK (VMware) 	vmdk




qemu-img info --backing-chain snap2.qcow2



## Debugging.
sudo -u "$user_name" qemu-img info "$vmdk_file"

sudo -u "$user_name" VBoxManage clonehd --format VDI "$vmdk_file" "$vdi_file"

sudo -u "$user_name" qemu-img info "$vdi_file"


sudo -u "$user_name" qemu-img info "$image_file"


sudo -u "$user_name" qemu-img convert -p -O raw "$image_file" "$raw_file"


Parsed file systems.
virt-filesystems -a "$raw_file" > "$auto_hash_folder/$raw_file_basename.virt-filesystems-a"




## convert a raw image file named image.img to a qcow2 image file.
qemu-img convert -f raw -O qcow2 image.img image.qcow2

## convert a vmdk image file to a raw image file.
qemu-img convert -f vmdk -O raw image.vmdk image.img

## convert a vmdk image file to a qcow2 image file.
qemu-img convert -f vmdk -O qcow2 image.vmdk image.qcow2

## 
qemu-img convert appliance $HD.vmdk -O raw $raw.hdd

## Convert the file to a .bin
qemu-img convert harddrive-name.vmdk raw-file.bin



qemu-img convert -p -O qcow2 -o preallocation=metadata "$WHONIX_BINARY/$VMNAME.img" "$WHONIX_BINARY/$VMNAME-$whonix_build_whonix_version_new.qcow2"

      qemu-img \
         convert \
            -p \
            -O qcow2 \
            -o preallocation=metadata \
            "$WHONIX_BINARY/$VMNAME.img" \
            "$WHONIX_BINARY/$VMNAME-$whonix_build_whonix_version_new.qcow2"


du -h --apparent-size file.img


      qemu-img \
         convert \
            -p \
            -O qcow2 \
            -o cluster_size=2M \
            -o preallocation=metadata \
            "$WHONIX_BINARY/$VMNAME.img" \
            "$WHONIX_BINARY/$VMNAME-$whonix_build_whonix_version_new.qcow2"

qemu-img info file.img


I want to create a new VM that is a copy of that VM.
make a 
copy of $this-vm
named $that-vm

and takes care of duplicating storage devices.

virt-clone --connect=qemu://example.com/system -o this-vm -n that-vm --auto-clone






virsh shutdown this.vm

## copy the storage.
cp /var/lib/libvirt/images/{this-vm,that-vm}.img

##  dump the xml for the original
virsh dumpxml this-vm > /tmp/that-vm.xml


## hardware addresses need to be removed, 
## libvirt will assign new addresses automatically
sed -i /uuid/d /tmp/that-vm.xml
sed -i '/mac address/d' /tmp/that-vm.xml


## rename the vm: (this also updates the storage path)
sed -i s/this-vm/that-vm /tmp/that-vm.xml


create the new vm
virsh define /tmp/that-vm.xml
virsh start this-vm
virsh start that-vm



# dump the xml for the virtual isolated network
virsh net-dumpxml whonix > /tmp/whonix.xml

# hardware addresses need to be removed, libvirt will assign
# new addresses automatically
sed -i /uuid/d /tmp/whonix.xml
sed -i '/mac address/d' /whonix.xml


https://access.redhat.com/documentation/en-US/Red_Hat_Enterprise_Linux/6/html/Virtualization_Administration_Guide/section-libvirt-dom-xml-sound-devices.html

https://github.com/Whonix/Whonix/blob/master/libvirt/whonix_libvirt_import whonix_libvirt_import






==How to Edit in nano with virsh?==
su
# EDITOR=nano virsh edit ''GuestMachineName''




virsh net-define [path]/whonix_network.xml
virsh net-autostart Whonix
virsh net-start Whonix







== How to disable KVMClock? ==

In xml file add:
<timer name='kvmclock' present='no'/>






virsh domxml-to-native qemu-argv ./usr/share/whonix-libvirt/xml/Whonix-Gateway_qemu.xml




cat /usr/share/libvirt/cpu_map.xml


<pre>
<cpu mode='custom' match='exact'>
   <model fallback='forbid'>qemu64</model>
   <topology sockets='1' cores='2' threads='1'/>
   <feature policy='disable' name='tsc'/>
   <feature policy='disable' name='clflush'/>
   <feature policy='optional' name='aes'/>
</cpu>
</pre>











-p' show progress of command
--output' takes the format in which the output must be done (human or json)


qcow2
encryption

qemu-img map --output= $file

dd 
-O -f $fmt [output_fmt] [bs=block_size] if=input of=output
Parameters to dd subcommand:
  'bs=BYTES' read and write up to BYTES bytes at a time (default: 512)
  'count=N' copy only N input blocks
  'if=FILE' read from FILE
  'of=FILE' write to FILE
  'skip=N' skip N bs-sized blocks at the start of input


check

-f human [--output=ofmt] [-r [leaks | all]] $file

-r is specified, qemu-img tries to repair any
           inconsistencies found during the check

-r tries to repair any inconsistencies that are found during the check.
-r leaks repairs only cluster leaks
-r all fixes all kinds of errors


-c creates a snapshot
-d deletes a snapshot
-l lists all snapshots in the given image

snapshot_param
snapshot.id=[ID]
snapshot.name=[NAME]


create [-q] [--object objectdef] [--image-opts] [-f fmt] [-o options] filename [size]
dd [--image-opts] [-f fmt] [-O output_fmt] [bs=block_size] [count=blocks] [skip=blocks] if=input of=output
  info [--object objectdef] [--image-opts] [-f fmt] [--output=ofmt] [--backing-chain] filename
  map [--object objectdef] [--image-opts] [-f fmt] [--output=ofmt] filename
  snapshot [--object objectdef] [--image-opts] [-q] [-l | -a snapshot | -c snapshot | -d snapshot] filename


Supported formats: blkdebug blkreplay blkverify bochs cloop dmg file ftp ftps gluster host_cdrom host_device http https iscsi iser luks nbd nfs null-aio null-co parallels qcow qcow2 qed quorum raw rbd replication sheepdog ssh vdi vhdx vmdk vpc vvfat



qemu-make-debian-root - Create a debian root image for qemu
qemu-make-debian-root [-k] [-s] size-in-MiB distrib deburl image [files-to-copy-in-/root]



qemu disk.img -kernel /boot/vmlinuz



qemu-system-x86_64 -enable-kvm








--connect
--log
--readonly


virsh # help host
virsh # help list

cpumap					 		## Displays the node's total number of CPUs
cpustats					## cpu stats of the node.
memstats					## memory stats of the node.


sysinfo
           Print the XML representation of the hypervisor sysinfo

capabilities
           Print an XML document describing the capabilities of the hypervisor we are currently connected to.

virsh capabilities



virsh list 
--inactive
--all
running
shut off
crashed

--state-running
--persistent
--with-managed-save.
--without-managed-save.
--with-snapshot.
--without-snapshot.

virsh list --title




## Creating the domain xml

virt-install --connect qemu:///system \
             --import \
             --name container-linux1 \
             --ram 1024 --vcpus 1 \
             --os-type=linux \
             --os-variant=virtio26 \
             --disk path=/var/lib/libvirt/images/container-linux/container-linux1.qcow2,format=qcow2,bus=virtio \
             --vnc --noautoconsole \
             --print-xml > /var/lib/libvirt/container-linux/container-linux1/domain.xml





virsh dumpxml <domain> > domain.xml
virsh create domain.xml


virsh dumpxml --inactive --security-info domain > domain.xml
virsh define domain.xml

--details option instructs virsh to additionally display volume type





## see all the records in this month for a guest
auvirt --start this-month --vm GuestVmName --all-events










## creates a raw image in the current directory from a VirtualBox VDI image.
VBoxManage clonehd ~/VirtualBox\ VMs/image.vdi image.img --format raw



openstack image set --property hw_disk_bus='ide' image_name_or_id






virsh dumpxml <domain> > domain.xml
            vi domain.xml (or make changes with your other text editor)
            virsh create domain.xml


## Edit the XML configuration file for a network.
virsh net-dumpxml --inactive network > network.xml
            vi network.xml (or make changes with your other text editor)
            virsh net-define network.xml



desc domain [[--live] [--config] | [--current]] [--title] [--edit] [--new-desc New description or title
       message]
           Show or modify description and title of a domain

snapshot-create.


virsh iface-dumpxml iface > iface.xml
            vi iface.xml (or make changes with your other text editor)
            virsh iface-define iface.xml


virsh net-dumpxml --inactive network > network.xml
virsh net-define network.xml
virsh iface-dumpxml iface > iface.xml
virsh iface-define iface.xml





domblkstat domain [block-device] [--human]
           Get device block stats for a running domain. 

domblklist


Explanation of fields (fields appear in the following order):
             rd_req            - count of read operations
             rd_bytes          - count of read bytes
             wr_req            - count of write operations
             wr_bytes          - count of written bytes
             errs              - error count
             flush_operations  - count of flush operations
             rd_total_times    - total time read operations took (ns)
             wr_total_times    - total time write operations took (ns)
             flush_total_times - total time flush operations took (ns)
               <-- other fields provided by hypervisor -->


domifaddr domain [interface] [--full] [--source lease|agent]
           Get a list of interfaces of a running domain along with their IP and MAC addresses

domifstat domain interface-device
           Get network interface stats for a running domain

domif-setlink domain interface-device state [--config]
           Modify link state of the domain's virtual interface. 

domif-getlink domain interface-device [--config]
           Query link state of the domain's virtual interface.


dommemstat domain [--period seconds] [[--config] [--live] | [--current]]
           Get memory stats for a running domain.


Explanation of fields:
             swap_in           - The amount of data read from swap space (in kB)
             swap_out          - The amount of memory written out to swap space (in kB)
             major_fault       - The number of page faults where disk IO was required
             minor_fault       - The number of other page faults
             unused            - The amount of memory left unused by the system (in kB)
             available         - The amount of usable memory as seen by the domain (in kB)
             actual            - Current balloon value (in KB)
             rss               - Resident Set Size of the running domain's process (in kB)
             usable            - The amount of memory which can be reclaimed by balloon without causing host
           swapping (in KB)
             last-update       - Timestamp of the last update of statistics (in seconds)




domblkerror domain
           Show errors on block devices.


domblkinfo domain block-device
           Get block device size info for a domain.

domiflist domain [--inactive]
           Print a table showing the brief information of all virtual interfaces associated with domain. 


blockcopy domain path { dest [format] [--blockdev] | --xml file }

				## Copy a disk backing image chain to a destination.


       blockpull domain path [bandwidth] [--bytes] [base] [--wait [--verbose] [--timeout seconds] [--async]]
       [--keep-relative]
           Populate a disk from its backing image chain. 



blkdeviotune domain device --current
--live
--config



--total-iops-sec
--read-bytes-sec
--total-bytes-sec-max

--size-iops-sec











save-image-dumpxml --security-info

virsh save-image-dumpxml state-file > state-file.xml
            vi state-file.xml (or make changes with your other text editor)
            virsh save-image-define state-file state-file-xml


save-image-define file xml [{--running | --paused


virsh restore




migrate disk-list


--persistent-xml file

--copy-storage-all







virsh vcpuinfo fedora





virsh send-process-signal myguest 1 15
             virsh send-process-signal myguest 1 term
             virsh send-process-signal myguest 1 sigterm
             virsh send-process-signal myguest 1 SIG_HUP



virsh memtune 


virsh dominfo


set-user-password --encrypted


             # send one stroke 'right-ctrl+C'
             virsh send-key dom KEY_RIGHTCTRL KEY_C

             # send a tab, held for 1 second
             virsh send-key --holdtime 1000 0xf



## instructs virsh to additionally display pool persistence and capacity
virsh pool-dumpxml pool > pool.xml
virsh pool-define pool.xml


virsh vol-dumpxml --pool storagepool1 appvolume1 > newvolume.xml
virsh vol-create differentstoragepool newvolume.xml



virsh snapshot-dumpxml dom name > snapshot.xml
virsh snapshot-create dom snapshot.xml --redefine [--current]
virsh nwfilter-dumpxml myfilter > myfilter.xml
virsh nwfilter-define myfilter.xml
    $ virsh qemu-attach $QEMUPID



--no-metadata is specified, then the snapshot data is created, but any metadata is immediately
napshot unless









qemu-system-x86_64 -m 256 -display vnc=127.0.0.1:11 -cdrom slackware64-14.0-install-dvd.iso  -net nic,macaddr=52:54:00:12:FF:57 -net tap,ifname=tap1-0,script=no,downscript=no &









add your ssh keys to the Linux Container by creating a config:

yaml container-linux-config

storage:
  files:
  - path: /etc/hostname
    filesystem: "root"
    contents:
      inline: "container-linux1"

passwd:
  users:
    - name: core
      ssh_authorized_keys:
        - "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC0g+ZTxC7weoIJLUafOgrm+h..."






When run as root.
       /etc/libvirtd.conf
           The default configuration file used by libvirtd, unless overridden on the command line using the
           -f|--config option.

       /var/run/libvirt/libvirt-sock
       /var/run/libvirt/libvirt-sock-ro
           The sockets libvirtd will use.

       /etc/pki/CA/cacert.pem
           The TLS Certificate Authority certificate libvirtd will use.

       /etc/pki/libvirt/servercert.pem
           The TLS Server certificate libvirtd will use.

       /etc/pki/libvirt/private/serverkey.pem
           The TLS Server private key libvirtd will use.

       /var/run/libvirtd.pid
           The PID file to use, unless overridden by the -p|--pid-file option.


When run as non-root.
       $XDG_CONFIG_HOME/libvirtd.conf
           The default configuration file used by libvirtd, unless overridden on the command line using the
           -f|--config option.

       $XDG_RUNTIME_DIR/libvirt/libvirt-sock
           The socket libvirtd will use.

       $HOME/.pki/libvirt/cacert.pem
           The TLS Certificate Authority certificate libvirtd will use.

       $HOME/.pki/libvirt/servercert.pem
           The TLS Server certificate libvirtd will use.

       $HOME/.pki/libvirt/serverkey.pem
           The TLS Server private key libvirtd will use.

       $XDG_RUNTIME_DIR/libvirt/libvirtd.pid
           The PID file to use, unless overridden by the -p|--pid-file option.

       If $XDG_CONFIG_HOME is not set in your environment, libvirtd will use $HOME/.config
       If $XDG_RUNTIME_DIR is not set in your environment, libvirtd will use $HOME/.cache




start libvirtd, instructing it to daemonize and create a PID file:

        # libvirtd -d
        # ls -la /var/run/libvirtd.pid
        -rw-r--r-- 1 root root 6 Jul  9 02:40 /var/run/libvirtd.pid









start the shell as a login shell, use:

       openvt -l bash

       To get a long listing you must supply the -- separator:

       openvt -- ls -lqq



systemd-detect-virt detects execution in a virtualized environment




systemd-nspawn@.service
systemd-nspawn - Spawn a namespace container
				 it fully virtualizes the file system hierarchy, as well
       as the process tree, the various IPC subsystems and the host and domain name.

--directory=, --image=, nor --machine=


systemctl set-property

--private-users-chown			## all files and directories in the containers directory tree will adjusted so that they
								## are owned to the appropriate UIDs/GIDs selected for the container
--private-users=


--private-network
--network-interface= and configured with --network-veth
--drop-capability=


A "macvlan" interface is a virtual interface that adds a second MAC address to an
           existing physical Ethernet link. 


--network-veth
           Create a virtual Ethernet link ("veth") between host and container. 

--machine=		## prefixed with "ve-"


systemd-networkd.service

/lib/systemd/network/80-container-ve.network		## network file matching the host-side interfaces
													## to enable automatic address provisioning on the 
													## created virtual link via DHCP


/lib/systemd/network/80-container-host0.network




--network-veth-extra=
           Adds an additional virtual Ethernet link between host and container. 



--network-bridge=			## Adds the host side of the Ethernet link created with 
							## --network-veth to the specified Ethernet bridge interface.




makes it easy to place multiple related containers on a common, virtual Ethernet-based
           broadcast domain, here called a "zone". Each container may only be part of one zone, but each zone
           may contain any number of containers.



--port=



## If the host uses SELinux, allow the VM access to the config:
semanage fcontext -a -t virt_content_t "/var/lib/libvirt/container-linux/container-linux1"
restorecon -R "/var/lib/libvirt/container-linux/container-linux1"



--selinux-context=
           Sets the SELinux security context to be used to label processes in the container.

       -L, --selinux-apifs-context=
           Sets the SELinux security context to be used to label files in the virtual API file systems in the
           container.


--link-journal=
"no", "host",
           "try-host", "guest", "try-guest", "auto"				## --link-journal=try-guest is the default


/var/log/journal/machine-id


--read-only
           Mount the root file system read-only for the container.


--bind=, --bind-ro=
           Bind mount a file or directory from the host into the container. 


--tmpfs=
           Mount a tmpfs file system into the container.
--read-only


--overlay=, --overlay-ro=
           Combine multiple directory trees into one overlay file system and mount it into the container.







Name: 9050
Protocol: TCP
Host IP: 127.0.0.1
Host Port: 9050
Guest IP: leave blank
Guest Port: 9050


VBoxManage modifyvm "Whonix-Gateway" --natpf1 "9050",tcp,127.0.0.1,9050,,9050

VBoxManage modifyvm "Whonix-Gateway" --natpf1 "9000",tcp,127.0.0.1,9000,,9000


ClientTransportPlugin flashproxy exec /usr/bin/flashproxy-client --register :0 :9000

ClientTransportPlugin obfs4 exec /usr/bin/obfs4proxy managed

















xmount
creates a virtual disk
image that you can boot using VM software, such as VirtualBox or kvm-
qemu. The xmount tool allows you to simulate a read-write drive, making
the VM think the disk is writable, but it continues to protect the image in
a read-only state. Multiple VM output formats are available, including raw,
DMG, VDI, VHD, VMDK, and VMDKS.



mkdir virtual

xmount --cache xmount.cache --in raw image.raw --out vdi virtual

cat virtual/image.info


## remove mount
fusermount -u virtual


A xmount.cache file containing data written during the use of the VM
might exist. You can save the file if you need to continue the previous VM
session, or you can remove it.



# qemu-img info image.qcow2

## Network Block Device
qemu-nbd --read-only --connect /dev/nbd0 image.qcow2


mmls /dev/nbd0


fls /dev/nbd0p1



qemu-nbd --read-only --disconnect /dev/nbd0

mount /dev/nbd0p1 p1
mount: /dev/nbd0p1 is write-protected, mounting read-only











VBoxManage showhdinfo OpenSolaris.vdi



qemu-nbd -c /dev/nbd0 OpenSolaris.vdi










systemd-machined










debootstrap
dnf
pacman
machinectl






























Virtual Privacy Machine


http://www.dmtf.org
http://virtualappliances.net






