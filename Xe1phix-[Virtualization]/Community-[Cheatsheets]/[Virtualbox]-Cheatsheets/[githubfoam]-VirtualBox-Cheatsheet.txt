==========================================================================================================
Windows Host
>vboxmanage --version
6.0.12r133076
==========================================================================================================
problem: move/copy VM manually and run
Cannot register the DVD image
C:\Program Files\Oracle\VirtualBox\VBoxGuestAdditions.iso' with UUID {fc087cbc-df04-47b4-b42f-25f614463f78} already exists. 
fix: edit  ".VBOX" file and remove entries between tags
<DVDImages>
</DVDImages>
==========================================================================================================
problem:
The virtual machine is being powered down, stuck
fix:
>VBoxManage startvm vbox-docker-01 --type emergencystop
==========================================================================================================
problem:
'VBoxManage' is not recognized as an internal or external command,operable program or batch file.
fix:
>set PATH=%PATH%;"C:\Program Files\Oracle\VirtualBox"
==========================================================================================================
Download VirtualBox Extension Pack
File > Preferences and select the Extensions tab. Click the add icon to install VirtualBox Extension Pack
==========================================================================================================
PS:for windows hosts
add the C:\Program Files\Oracle\VirtualBox directory to your PATH

# sharing folders bidirectional virtualbox
# host:windows guest:linux
Devices -> Shared Folders -> Shared Folders Settings -> Add (plus sign) -> Transient Folders -> Automount
# add user into vboxsf group
$ sudo usermod -a -G vboxsf sanchez
$ sudo grep vboxsf /etc/group
vboxsf:x:999:sanchez

"VBoxManage" command is different from "sudo VBoxManage" command

VBoxManage --version

sudo apt-get dist-upgrade -y -> Debian-based linux makes sure VirtualBox Guest Additions is installed

VBoxManage list runningvms -> Find running vm to box
vagrant package --base xxxxx_1522057296984_52705 --output ubuntu1604.box --> Package running vm as vagrant box

# Download an ISO image of VirtualBox Guest Additions http://download.virtualbox.org/virtualbox/
wget -c http://download.virtualbox.org/virtualbox/5.2.12/VBoxGuestAdditions_5.2.12.iso -O VBoxGuestAdditions_5.2.12.iso
sudo mount -o loop VBoxGuestAdditions_5.2.12.iso /tmp/vbox
sudo sh /mnt/VBoxLinuxAdditions.run

lsmod | grep vboxguest -> verify vbox installation
modinfo vboxguest
#verify that Guest Additions are installed successfully
lsmod | grep vbox

==========================================================================================================
https://www.virtualbox.org/manual/

#troubleshooting
VBoxManage list vms | awk '{print $2;}' 
VBoxManage list runningvms | awk '{print $2;}'
VBoxManage  showvminfo vmid
VBoxManage  showvminfo vmname | more
VBoxManage unregistervm --delete vmid
VBoxManage  modifyvm vmid --name vmname
==========================================================================================================
#troubleshooting, windows 11

Problem: 
VERR_NEM_VM_CREATE_FAILED 
Fix:
Control Panel-Programs-Programs and Features-Turn Windows features on or off-Windows Sandbox


=========================================================================================================
#https://www.virtualbox.org/manual/ch08.html#vboxmanage-storagectl

>VBoxManage storagectl vbox-chroot-79 --name disk1 --add sata
>VBoxManage storagectl vbox-chroot-79 --remove --name disk1
>VBoxManage showvminfo vbox-chroot-79 --details | findstr Storage

VBoxManage storagectl vbox-chroot-79 --name disksata1 --add sata  --hostiocache on
VBoxManage storagectl vbox-chroot-79 --name diskscsi1 --add scsi  --hostiocache on
VBoxManage storagectl vbox-chroot-79 --name disksas1 --add sas  --hostiocache on
VBoxManage storagectl vbox-chroot-79 --name controller-pcie1 --add pcie  --hostiocache on
VBoxManage storagectl vbox-chroot-79 --name floppy1 --add floppy  --hostiocache on
VBoxManage storagectl vbox-chroot-79 --name usb1 --add usb  --hostiocache on

>VBoxManage closemedium disk nvme_disk1.vdi --delete
#For compatibility with earlier versions of Oracle VM VirtualBox, the createvdi and createhd commands are also supported and mapped internally to the createmedium command. 
#https://www.virtualbox.org/manual/ch08.html
>VBoxManage createmedium #type for help
>VBoxManage createmedium --name vbox-chroot-79 --filename nvme_disk1 --variant Fixed --size 1024

>vboxmanage --version
6.1.32r149290
>VBoxManage createmedium --filename vdi_disk.vdi --format VDI --size 50000
0%...10%...20%...30%...40%...50%...60%...70%...80%...90%...100%
Medium created. UUID: 4c200422-b7d3-4287-b38d-a5b96dfef94c
>VBoxManage storageattach vbox-ubuntu-02 --storagectl SATA --type hdd --medium vdi_disk.vdi  --port 0 --device 0

>VBoxManage showmediuminfo  disk 847f5e9c-e6e0-46d8-b826-868e7ea4fb4c
>VBoxManage list hdds | findstr nvme_disk1

VBoxManage closemedium disk nvme_disk1.vdi --delete
VBoxManage storagectl vbox-chroot-79 --remove --name disk1

>VBoxManage createmedium disk --filename nvme_controller_disk1 --format VDI --variant Fixed --size 1024
>VBoxManage list hdds | findstr nvme_controller_disk1
Location:       C:\Users\veronica\nvme_disk1.vdi
>VBoxManage closemedium disk nvme_disk1.vdi --delete
>VBoxManage storagectl vbox-chroot-79 --name system-bus-pcie1 --add pcie --controller "NVMe" --portcount 1 --bootable off --hostiocache on
>VBoxManage storageattach vbox-chroot-79 --storagectl system-bus-pcie1 --type hdd --medium C:\Users\veronica\nvme_controller_disk1.vdi --port 0

# command prompt format
VBoxManage createmedium --name vbox-chroot-79 --filename nvme_disk1 --variant Fixed --size 1024
VBoxManage storagectl vbox-chroot-79 --name controllernvme1 --add pcie --controller "NVMe" --portcount 1 --bootable off --hostiocache on
VBoxManage storageattach vbox-chroot-79 --storagectl controllernvme1 --type hdd --medium nvme_disk1 --port 0

# Vagrantfile format
vb.customize ["createmedium", "--filename", nvme_disk1, "--variant", "Fixed", "--size", "1024"]
vb.customize ["storagectl", :id, "--name", "controllernvme1", "--add", "pcie", "--controller", "NVMe", "--portcount", "2", "--bootable", "off", "--hostiocache", "on"]
vb.customize ["storageattach", :id, "--storagectl", "controllernvme1", "--type", "hdd", "--medium", nvme_disk1, "--port", "0"]
==========================================================================================================
#system buses/ controllers
VBoxManage closemedium disk nvme_disk1.vdi --delete
VBoxManage storagectl vbox-chroot-79 --remove --name disk1

VBoxManage list hdds | findstr nvme_controller_disk1
Location:       C:\Users\veronica\nvme_disk1.vdi
VBoxManage closemedium disk nvme_disk1.vdi --delete

VBoxManage createmedium disk --filename nvme_controller_disk1 --format VDI --variant Fixed --size 4096
VBoxManage storagectl vbox-controller-81 --name system-bus-pcie --add pcie --controller "NVMe" --portcount 2 --bootable off --hostiocache on
VBoxManage storageattach vbox-controller-81 --storagectl system-bus-pcie --type hdd --medium C:\Users\veronica\nvme_controller_disk1.vdi --port 0

VBoxManage createmedium disk --filename LSILogicSAS_controller_disk1 --format VDI --variant Fixed --size 4096
VBoxManage storagectl vbox-controller-81 --name system-bus-sas --add sas --controller "LSILogicSAS" --portcount 2 --bootable off --hostiocache on
VBoxManage storageattach vbox-controller-81 --storagectl system-bus-sas --type hdd --medium C:\Users\veronica\LSILogicSAS_controller_disk1.vdi --port 0


VBoxManage createmedium disk --filename BusLogic_controller_disk1 --format VDI --variant Fixed --size 4096
VBoxManage storagectl vbox-controller-81 --name system-bus-scsi --add scsi --controller "BusLogic" --portcount 16 --bootable off --hostiocache on
VBoxManage storageattach vbox-controller-81 --storagectl system-bus-scsi --type hdd --medium C:\Users\veronica\BusLogic_controller_disk1.vdi --port 1

"existing system bus"
VBoxManage createmedium disk --filename LSILogic_controller_disk1 --format VDI --variant Fixed --size 4096
VBoxManage storageattach vbox-controller-81 --storagectl system-bus-scsi --type hdd --medium C:\Users\veronica\LSILogic_controller_disk1.vdi --port 0

"existing system bus"
VBoxManage createmedium disk --filename IntelAhci_controller_disk1 --format VDI --variant Fixed --size 4096
VBoxManage storageattach vbox-controller-81 --storagectl ""SATA Controller" --type hdd --medium C:\Users\veronica\IntelAhci_controller_disk1.vdi --port 1

"existing system bus"
VBoxManage createmedium disk --filename PIIX4_controller_disk1 --format VDI --variant Fixed  --size 4096
VBoxManage storageattach vbox-controller-81 --storagectl "IDE Controller" --type hdd --medium C:\Users\veronica\PIIX4_controller_disk1.vdi --port 0 --device 0
--port 0,--device 0 primary master



VBoxManage createmedium disk --filename PIIX4_controller_disk1 --format VDI --variant Fixed --size 1024
VBoxManage list hdds | findstr PIIX4_controller_disk1
Location:       C:\users\veronica\PIIX4_controller_disk1.vdi
VBoxManage storageattach vbox-chroot-79 --storagectl "IDE Controller" --type hdd --medium C:\users\veronica\PIIX4_controller_disk1.vdi --port 0 --device 0
--port 0,--device 0 primary master
--port 1, --device 0 secondary master
--port 1,--device 1 secondary slave
--port 0,--device 1 secondary master



VBoxManage storagectl vbox-controller-81 --name "SATA Controller" --add sata --controller "IntelAhci" --portcount 1 --bootable off --hostiocache on


VBoxManage storagectl vbox-chroot-79 --name system-bus-scsi --add scsi --controller "LSILogic" --portcount 2 --bootable off --hostiocache on
VBoxManage createmedium disk --filename LSILogic_controller_disk1 --format VDI --variant Fixed --size 1024
VBoxManage storageattach vbox-chroot-79 --storagectl system-bus-scsi --type hdd --medium C:\users\veronica\LSILogic_controller_disk1.vdi --port 0

VBoxManage storagectl vbox-chroot-79 --name system-bus-sas --add sas --controller "LSILogicSAS" --portcount 2 --bootable off --hostiocache on
VBoxManage createmedium disk --filename LSILogicSAS_controller_disk1 --format VDI --variant Fixed --size 1024
VBoxManage storageattach vbox-chroot-79 --storagectl system-bus-sas --type hdd --medium C:\users\veronica\LSILogicSAS_controller_disk1.vdi --port 0

==========================================================================================================

VBoxManage: error: Cannot unregister the machine 'xx' while it is locked
sudo VBoxManage controlvm 'xx' poweroff

VBoxManage: error: The machine 'xx' is already locked for a session (or being unlocked)
sudo VBoxManage startvm 'xx' --type emergencystop

rm -fr ~/"VirtualBox VMs/NAMEOFVM" -> delete it manually
ps -ef | grep -i virtualbox

# Remove "VirtualBox Host-Only Ethernet Adapter" windows 10
Device Manager -> Network Adapter -> right click -> uninstall device

# Remove "VirtualBox Host-Only Ethernet Adapter" windows 10, no GUI
VBoxManage list -l hostonlyifs
vboxmanage hostonlyif remove "VirtualBox Host-Only Ethernet Adapter #15"
0%...10%...20%...30%...40%...50%...60%...70%...80%...90%...100%

# Create/Remove "VirtualBox Host-Only Ethernet Adapter" windows 10
VBoxManage list hostonlyifs
VBoxManage hostonlyif ipconfig "VirtualBox Host-Only Ethernet Adapter" --ip 192.168.45.24 --netmask 255.255.255.0
vboxmanage hostonlyif remove "VirtualBox Host-Only Ethernet Adapter"
VBoxManage list hostonlyifs

# Add/Remove an eighth NIC of hostonly networking to a existing VM
>VBoxManage list vms
"control-machine" {bbf0048b-57ad-4be6-9985-a8e06ffe7737}

>VBoxManage modifyvm "control-machine" --hostonlyadapter8 vboxnetX
>VBoxManage modifyvm "control-machine" --nic8 hostonly
>VBoxManage modifyvm "control-machine" --nic5 none

# Add/Remove an eighth NIC of hostonly networking to a existing VM, one-liner
VBoxManage modifyvm "control-machine" --nic8 hostonly --hostonlyadapter8 vboxnetX
VBoxManage modifyvm "control-machine" --nic9 none
------------------------------------------------------------------------------------------
Windows Host
>vboxmanage --version
6.0.12r133076

ISO download VirtualBox Guest Additions for Linux
http://download.virtualbox.org/virtualbox/

Vbox Guest
$ wget http://download.virtualbox.org/virtualbox/6.0.12/VBoxGuestAdditions_6.0.12.iso
$ sudo mount -o loop,ro VBoxGuestAdditions_6.0.12.iso /mnt
$ sudo sh /mnt/VBoxLinuxAdditions.run --nox11
reboot

$ lsmod | grep vboxguest
vboxguest             331776  1

$ modinfo vboxguest
filename:       /lib/modules/4.4.0-131-generic/misc/vboxguest.ko
version:        6.0.12 r133076
license:        GPL
description:    Oracle VM VirtualBox Guest Additions for Linux Module
author:         Oracle Corporation
srcversion:     72B364F5735D30373E34B7F
alias:          pci:v000080EEd0000CAFEsv00000000sd00000000bc*sc*i*
depends:
retpoline:      Y
vermagic:       4.4.0-131-generic SMP mod_unload modversions retpoline

$ lsmod | grep vbox
vboxguest             331776  1
vboxvideo              40960  1
ttm                    98304  1 vboxvideo
drm_kms_helper        155648  1 vboxvideo
drm                   364544  4 ttm,drm_kms_helper,vboxvideo
------------------------------------------------------------------------------------------
create a closed network

VirtualBox > Preferences >  Network tab > add a new network
------------------------------------------------------------------------------------------
