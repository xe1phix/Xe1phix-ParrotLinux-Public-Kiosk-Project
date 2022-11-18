#KVM

egrep -c '(vmx|svm)' /proc/cpuinfo | echo "virtualization is  supported" | echo "virtualization is not supported"
egrep -c '(vmx|svm)' /proc/cpuinfo && echo "virtualization is  supported" || echo "virtualization is not supported"

grep -i vmx /proc/cpuinfo 				#check if the CPU supports virtualization
lsmod | grep kvm 						#check  if the kvm kernel module is loaded

$ grep -c ^processor /proc/cpuinfo 		#check that your server has (at least) 8 CPU cores

To run KVM, you need a processor that supports hardware virtualization. 
Intel and AMD both have developed extensions for their processors, deemed respectively Intel VT-x (code name Vanderpool) and AMD-V (code name Pacifica)
#If 0 it means that your CPU doesn't support hardware virtualization.
#If 1 or more it does - but you still need to make sure that virtualization is enabled in the BIOS. 
egrep -c '(vmx|svm)' /proc/cpuinfo  
egrep -q 'vmx|svm' /proc/cpuinfo && echo yes || echo no #To use VM drivers, verify that your system has virtualization support enabled


#If the above command outputs “no”
#If you are running within a VM, your hypervisor does not allow nested virtualization. You will need to use the None (bare-metal) driver
#If you are running on a physical machine, ensure that your BIOS has hardware virtualization enabled
cat /sys/hypervisor/properties/capabilities 

#if it is enabled or not from xen

kvm-ok 

#If you see You can still run virtual machines,
but it'll be much slower without the KVM extensions
INFO: Your CPU does not support KVM extensions
KVM acceleration can NOT be used

egrep -c ' lm ' /proc/cpuinfo 

#If 0 is printed, it means that your CPU is not 64-bit. If 1 or higher it is 64-bit

uname -m
x86_64

#By default dhcpd based network bridge configured by libvirtd
brctl show
virsh net-list 

#All VMs (guest machine) only have network access to other VMs on the same server.
#A private network 192.168.122.0/24 created
virsh net-dumpxml default


virt-install --name=linuxconfig-vm \
--vcpus=1 \
--memory=2048 \
--cdrom=/media/sanchez/KARNAK/linux_distributions/CentOS-Stream-8-x86_64-20210617-dvd1.iso \
--disk size=5 \
--os-variant=centos-stream8



