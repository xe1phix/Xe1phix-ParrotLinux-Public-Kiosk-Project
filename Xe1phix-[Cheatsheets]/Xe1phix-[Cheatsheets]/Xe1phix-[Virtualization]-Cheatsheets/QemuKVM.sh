


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
│          │ systemd-nspawn │ systemd's minimal container  │
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








## Debugging.
sudo -u "$user_name" qemu-img info "$vmdk_file"

sudo -u "$user_name" VBoxManage clonehd --format VDI "$vmdk_file" "$vdi_file"

sudo -u "$user_name" qemu-img info "$vdi_file"


sudo -u "$user_name" qemu-img info "$image_file"


sudo -u "$user_name" qemu-img convert -p -O raw "$image_file" "$raw_file"


Parsed file systems.
virt-filesystems -a "$raw_file" > "$auto_hash_folder/$raw_file_basename.virt-filesystems-a"




This example will convert a raw image file named image.img to a qcow2 image file.

$ qemu-img convert -f raw -O qcow2 image.img image.qcow2

Run the following command to convert a vmdk image file to a raw image file.

$ qemu-img convert -f vmdk -O raw image.vmdk image.img

Run the following command to convert a vmdk image file to a qcow2 image file.

$ qemu-img convert -f vmdk -O qcow2 image.vmdk image.qcow2

qemu-img convert appliance $HD.vmdk -O raw $raw.hdd


Convert the file to a .bin
qemu-img convert harddrive-name.vmdk raw-file.bin







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


virsh dumpxml <domain> > domain.xml
virsh create domain.xml


virsh dumpxml --inactive --security-info domain > domain.xml
virsh define domain.xml

--details option instructs virsh to additionally display volume type
















creates a raw image in the current directory from a VirtualBox VDI image.

$ VBoxManage clonehd ~/VirtualBox\ VMs/image.vdi image.img --format raw



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





































systemd-machined










debootstrap
dnf
pacman
machinectl






























Virtual Privacy Machine


http://www.dmtf.org
http://virtualappliances.net






