##  qemu-cheatsheet.sh


##  This is based on the howto appearing in 
##  the Fedora Project wiki. 


##  Create a new qemu image: `
qemu-img create -f vmdk test1.img 10G


##  (notice this command line creates an image in vmdk, 
##  [VMware](http://www.vmware.com), format, 
##  for compatibility -- qcow2 is the native format) 
##  Install an O/S from CD (or DVD):
qemu -cdrom /dev/cdrom -hda test1.img -boot d -m 512


##  Start up an installed O/S:
qemu test1.img -boot c -m 1024

##  ` If no network options are specified 
##  qemu will emulate an Intel e1000 PCI network card 
##  in user mode that bridges to the host's network interface. 
##  User mode will allow outgoing connections from the guest, 
##  but blocks incoming ones from outside. 
##  There's a nice article on QEMU Networking that shows how to go beyond the defaults, like using TAP interfaces to permit outside access to the guest.
