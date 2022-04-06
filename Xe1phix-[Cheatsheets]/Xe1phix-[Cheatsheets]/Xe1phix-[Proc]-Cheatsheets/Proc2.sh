#!/bin/bash
###########
## Proc2.sh ##
###########






echo "List all Kernel modules loaded at boot time:..."
cat -vET /modules >  $TEMP_DIR/modules.txt && cat -vET $TEMP_DIR/modules.txt												# contains the names of kernel modules that should be loaded at boot time
echo "Examining /proc/buddyinfo data about nodes and memory..."
cat -vET /proc/buddyinfo > $TEMP_DIR/buddyinfo.txt && cat -vET $TEMP_DIR/buddyinfo.txt					# contains data about nodes and memory
echo "Examining /proc/cgroups, data about CPU groups"
cat -vET /proc/cgroups >  $TEMP_DIR/cgroups.txt && cat -vET $TEMP_DIR/cgroups.txt																	# 
echo "Examining the command line given to start the process"
cat -vET /proc/cmdline >  $TEMP_DIR/cmdline.txt && cat -vET $TEMP_DIR/cmdline.txt															# 
echo "Examining /proc/consoles, giving information about consoles"
cat -vET /proc/consoles >  $TEMP_DIR/consoles.txt && cat -vET $TEMP_DIR/consoles.txt																		# 
echo "Examining /proc/cpuinfo, a very informative listing of the CPUs system"
cat -vET /proc/cpuinfo >  $TEMP_DIR/cpuinfo.txt && cat -vET $TEMP_DIR/cpuinfo.txt																		# 
echo "Examining /proc/crypto, crytographic routines available"
cat -vET /proc/crypto >  $TEMP_DIR/crypto.txt && cat -vET $TEMP_DIR/crypto.txt																		# 
echo "Examining /proc/devices, a list of the devices "
cat -vET /proc/devices >  $TEMP_DIR/devices.txt && cat -vET $TEMP_DIR/devices.txt																	# 
echo "Examining /proc/diskstats, a list of the disk statistics"
cat -vET /proc/diskstats >  $TEMP_DIR/diskstats.txt && cat -vET $TEMP_DIR/diskstats.txt																	# 
echo "Examining DMA Logging Resaults:"
cat -vET /proc/dma >  $TEMP_DIR/dma.txt && cat -vET $TEMP_DIR/dma.txt																									# 
echo "Examining /proc/filesystems, list of the filesystems available"
cat -vET /proc/filesystems >  $TEMP_DIR/filesystems.txt && cat -vET $TEMP_DIR/filesystems.txt											# 
echo "Examining a very detailed listing of the interrupts"
cat -vET /proc/interrupts >  $TEMP_DIR/interrupts.txt && cat -vET  $TEMP_DIR/interrupts.txt											# 
echo "Examining /proc/iomem, the I/O memory information"
cat -vET /proc/iomem >  $TEMP_DIR/iomem.txt && cat -vET  $TEMP_DIR/iomem.txt																		# 
echo "Examining the I/O port information"
cat -vET /proc/ioports >  $TEMP_DIR/ioports.txt && cat -vET  $TEMP_DIR/ioports.txt																		# 
echo "Examining /proc/kallsyms, a list of the OS symbols"
cat -vET /proc/kallsyms >  $TEMP_DIR/kallsyms.txt && cat -vET  $TEMP_DIR/kallsyms.txt																		# 
echo "Examining /proc/kcore, the memory image of this machine"
cat -vET /proc/kcore >  $TEMP_DIR/kcore.txt && cat -vET  $TEMP_DIR/kcore.txt																		# 
echo "Examining /proc/meminfo, a detailed list of mem usage"
cat -vET /proc/meminfo >  $TEMP_DIR/meminfo.txt && cat -vET  $TEMP_DIR/meminfo.txt											# 
echo "Examining /proc/mounts, list of the mounted filesystems (real and virtual)"
cat -vET /proc/mounts >  $TEMP_DIR/mounts.txt && cat -vET  $TEMP_DIR/mounts.txt																		# 
echo "Examining /proc/partitions list of the partitions"
cat -vET /proc/partitions >  $TEMP_DIR/partitions.txt && cat -vET  $TEMP_DIR/partitions.txt																		# 
echo "Examining /proc/slabinfo, list of the slab memory objects"
cat -vET /proc/slabinfo >  $TEMP_DIR/slabinfo.txt && cat -vET  $TEMP_DIR/slabinfo.txt																		# 
echo "Examining /proc/softirqs IRQ listing"
cat -vET /proc/softirqs >  $TEMP_DIR/softirqs.txt && cat -vET  $TEMP_DIR/softirqs.txt																		# 
echo "Displaying The Amount of time the machine has been up"
cat -vET /proc/uptime >  $TEMP_DIR/uptime.txt && cat -vET  $TEMP_DIR/uptime.txt																	# 
echo "Displaying The Kernel Version"
cat -vET /proc/version >  $TEMP_DIR/version.txt && cat -vET  $TEMP_DIR/version.txt																		# 
echo "Examining /proc/zoneinfo, a  rather detailed memory listing"
cat -vET /proc/zoneinfo >  $TEMP_DIR/zoneinfo.txt && cat -vET  $TEMP_DIR/zoneinfo.txt																		# 
echo "Time Elapsed Since Boot"
cat -vET /proc/uptime >  $TEMP_DIR/uptime.txt && cat -vET  $TEMP_DIR/uptime.txt
echo "System Load Averages"
cat -vET /proc/loadavg >  $TEMP_DIR/loadavg.txt && cat -vET  $TEMP_DIR/loadavg.txt
echo "Filesystems Supported by the system"
cat -vET /proc/filesystems >  $TEMP_DIR/filesystems.txt && cat -vET  $TEMP_DIR/filesystems.txt
echo "Drive partition information "
cat -vET /proc/partitions >  $TEMP_DIR/partitions.txt && cat -vET  $TEMP_DIR/partitions.txt
echo "Information about RAID arrays and devices "
cat -vET /proc/mdstat >  $TEMP_DIR/mdstat.txt && cat -vET  $TEMP_DIR/mdstat.txt
echo "Size of total and used swap areas"
cat -vET /proc/swaps >  $TEMP_DIR/swaps.txt && cat -vET  $TEMP_DIR/swaps.txt
echo "Mounted partitions"
cat -vET /proc/mounts >  $TEMP_DIR/mounts.txt && cat -vET  $TEMP_DIR/mounts.txt
echo "Drivers currently loaded "
cat -vET /proc/devices >  $TEMP_DIR/devices.txt && cat -vET  $TEMP_DIR/devices.txt
echo "Kernel modules currently loaded "
cat -vET /proc/modules >  $TEMP_DIR/modules.txt && cat -vET  $TEMP_DIR/modules.txt
echo "Buses (e.g. PCI, USB, PC Card) "
cat -vET /proc/bus >  $TEMP_DIR/bus.txt && cat -vET  $TEMP_DIR/bus.txt
echo "I/O addresses in use "
cat -vET /proc/ioports >  $TEMP_DIR/ioports.txt && cat -vET  $TEMP_DIR/ioports.txt
echo "DMA channels in use "
cat -vET /proc/dma >  $TEMP_DIR/dma.txt && cat -vET  $TEMP_DIR/dma.txt
echo "Current IRQs (Interrupt Requests) "
cat -vET /proc/interrupts >  $TEMP_DIR/interrupts.txt && cat -vET  $TEMP_DIR/interrupts.txt
echo "CPUs information "
cat -vET /proc/cpuinfo >  $TEMP_DIR/cpuinfo.txt && cat -vET  $TEMP_DIR/cpuinfo.txt
echo "Total and free memory"
cat -vET /proc/meminfo >  $TEMP_DIR/meminfo.txt && cat -vET  $TEMP_DIR/meminfo.txt
echo "Linux version"
cat -vET /proc/version >  $TEMP_DIR/version.txt && cat -vET  $TEMP_DIR/version.txt
echo "Advanced  Power  Management  Version  And  Battery  Information"
cat -vET /proc/apm >  $TEMP_DIR/apm.txt && cat -vET  $TEMP_DIR/apm.txt
echo "PCMCIA Subdirectory Devices"
cat -vET /proc/bus/pccard >  $TEMP_DIR/pccard.txt && cat -vET  $TEMP_DIR/pccard.txt
echo "PCMCIA Subdirectory Drivers"
cat -vET /proc/bus/pccard/drivers >  $TEMP_DIR/pccard-drivers.txt && cat -vET  $TEMP_DIR/pccard-drivers.txt
echo "Pseudo-Files Containing Information About PCI Busses, Installed Devices, and device drivers"
cat -vET /proc/bus/pci >  $TEMP_DIR/pci.txt && cat -vET  $TEMP_DIR/pci.txt
echo "Information  About  PCI  Devices"
cat -vET /proc/bus/pci/devices >  $TEMP_DIR/pci-devices.txt && cat -vET  $TEMP_DIR/pci-devices.txt
echo "Information About Systems With The IDE Bus"
cat -vET /proc/ide >  $TEMP_DIR/ide.txt && cat -vET  $TEMP_DIR/ide.txt
echo "Information on A Certain Processes limits:"
cat -vET /proc/$pid/limits >  $TEMP_DIR/limitspid.txt && cat -vET  $TEMP_DIR/limitspid.txt
echo "Information on A Certain Processes limits:"
cat -vET /proc/self/limits >  $TEMP_DIR/limitsSelf.txt && cat -vET  $TEMP_DIR/limitsSelf.txt
echo "Information On A Certain Processes Limits:"
cat -vET /proc/1/limits >  $TEMP_DIR/limits1.txt && cat -vET  $TEMP_DIR/limits.txt

echo -e "\t\t##########################################"
echo -e "\t\t##### Proc Function Report NO Imediate Cat Output ########"
echo -e "\t\t##########################################"

echo -e "\t_____________________________________________________________"
echo -e "\t {+} Information Reguarding SNMP Agent {+} "
echo -e "\t#######################################"
cat -vET /proc/net/snmp >  $TEMP_DIR/SNMP.txt
echo -e "\t_____________________________________________________________"
echo -e "\t {+} Dump of The TCP Socket Table {+} "
echo -e "\t#######################################"
cat -vET /proc/net/tcp >  $TEMP_DIR/TCP.txt
echo -e "\t\t_________________________________________"
echo -e "\t\t {+} Dump of The UDP Socket Table {+} "
echo -e "\t\t#########################"
cat -vET /proc/net/udp >  $TEMP_DIR/UDP.txt
echo -e "\t_____________________________________________________________"
echo -e "\t {+} The Dev Pseudo-File Network Device Status Information {+} "
echo -e "\t#######################################"
cat -vET /proc/net/dev >  $TEMP_DIR/dev.txt
echo -e "\t_____________________________________________________________"
echo -e "\t {+} Internet Group Management Protocol  {+} "
echo -e "\t#######################################"
cat -vET /proc/net/igmp >  $TEMP_DIR/igmp.txt
echo -e "\t_____________________________________________________________"
echo -e "\t {+} Dump of The RAW Socket Table {+} "
echo -e "\t#######################################"
cat -vET /proc/net/raw >  $TEMP_DIR/raw.txt

echo -e "\t_____________________________________________________________"
echo -e "\t {+} Information About The Corresponding File Descriptor {+} "
echo -e "\t#######################################"
cat -vET /proc/self/fdinfo >  $TEMP_DIR/fdinfo.txt
echo -e "\t_____________________________________________________________"
echo -e "\t {+} Information About The Corresponding File Descriptor {+} "
echo -e "\t#######################################"
cat -vET /proc/1/fdinfo >  $TEMP_DIR/fdinfo.txt
echo -e "\t_____________________________________________________________"
echo -e "\t {+} Information About The Corresponding File Descriptor {+} "
echo -e "\t#######################################"
cat -vET /proc/$pid/fdinfo >  $TEMP_DIR/fdinfo.txt
echo "Advanced  Power  Management  Version  And  Battery  Information"
cat -vET /proc/apm >  $TEMP_DIR/apm.txt
echo "PCMCIA Subdirectory Devices"
cat -vET /proc/bus/pccard >  $TEMP_DIR/pccard.txt
echo "PCMCIA Subdirectory Drivers"
cat -vET /proc/bus/pccard/drivers >  $TEMP_DIR/pccard-drivers.txt
echo "Pseudo-Files Containing Information About PCI Busses, Installed Devices, and device drivers"
cat -vET /proc/bus/pci >  $TEMP_DIR/pci.txt
echo "Information  About  PCI  Devices"
cat -vET /proc/bus/pci/devices >  $TEMP_DIR/pci-devices.txt
echo "Information About Systems With The IDE Bus"
cat -vET /proc/ide >  $TEMP_DIR/ide.txt
echo "Information on A Certain Processes limits:"
cat -vET /proc/$pid/limits >  $TEMP_DIR/limitspid.txt
echo "Information on A Certain Processes limits:"
cat -vET /proc/self/limits >  $TEMP_DIR/limitsSelf.txt
echo "Information On A Certain Processes Limits:"
cat -vET /proc/1/limits >  $TEMP_DIR/limits1.txt

echo -e "\t\t###############################################"
echo -e "\t\t###############################################"























































echo -e "\t\t##########################################"
echo -e "\t\t##### Proc Function Classic Layout NO Cat Output #########"
echo -e "\t\t##########################################"


echo "List all Kernel modules loaded at boot time:..."
cat -vET /modules >  $TEMP_DIR/modules.txt												# contains the names of kernel modules that should be loaded at boot time
echo "Examining /proc/buddyinfo data about nodes and memory..."
cat -vET /proc/buddyinfo > $TEMP_DIR/buddyinfo.txt			# contains data about nodes and memory
echo "Examining /proc/cgroups, data about CPU groups"
cat -vET /proc/cgroups >  $TEMP_DIR/cgroups.txt															# 
echo "Examining the command line given to start the process"
cat -vET /proc/cmdline >  $TEMP_DIR/cmdline.txt											# 
echo "Examining /proc/consoles, giving information about consoles"
cat -vET /proc/consoles >  $TEMP_DIR/consoles.txt																	# 
echo "Examining /proc/cpuinfo, a very informative listing of the CPUs system"
cat -vET /proc/cpuinfo >  $TEMP_DIR/cpuinfo.txt																	# 
echo "Examining /proc/crypto, crytographic routines available"
cat -vET /proc/crypto >  $TEMP_DIR/crypto.txt																# 
echo "Examining /proc/devices, a list of the devices "
cat -vET /proc/devices >  $TEMP_DIR/devices.txt																# 
echo "Examining /proc/diskstats, a list of the disk statistics"
cat -vET /proc/diskstats >  $TEMP_DIR/diskstats.txt															# 
echo "Examining DMA Logging Resaults:"
cat -vET /proc/dma >  $TEMP_DIR/dma.txt																						# 
echo "Examining /proc/filesystems, list of the filesystems available"
cat -vET /proc/filesystems >  $TEMP_DIR/filesystems.txt											# 
echo "Examining a very detailed listing of the interrupts"
cat -vET /proc/interrupts >  $TEMP_DIR/interrupts.txt											# 
echo "Examining /proc/iomem, the I/O memory information"
cat -vET /proc/iomem >  $TEMP_DIR/iomem.txt																	# 
echo "Examining the I/O port information"
cat -vET /proc/ioports >  $TEMP_DIR/ioports.txt																	# 
echo "Examining /proc/kallsyms, a list of the OS symbols"
cat -vET /proc/kallsyms >  $TEMP_DIR/kallsyms.txt																	# 
echo "Examining /proc/kcore, the memory image of this machine"
cat -vET /proc/kcore >  $TEMP_DIR/kcore.txt															# 
echo "Examining /proc/meminfo, a detailed list of mem usage"
cat -vET /proc/meminfo >  $TEMP_DIR/meminfo.txt									# 
echo "Examining /proc/mounts, list of the mounted filesystems (real and virtual)"
cat -vET /proc/mounts >  $TEMP_DIR/mounts.txt																	# 
echo "Examining /proc/partitions list of the partitions"
cat -vET /proc/partitions >  $TEMP_DIR/partitions.txt															# 
echo "Examining /proc/slabinfo, list of the slab memory objects"
cat -vET /proc/slabinfo >  $TEMP_DIR/slabinfo.txt															# 
echo "Examining /proc/softirqs IRQ listing"
cat -vET /proc/softirqs >  $TEMP_DIR/softirqs.txt																# 
echo "Displaying The Amount of time the machine has been up"
cat -vET /proc/uptime >  $TEMP_DIR/uptime.txt 																# 
echo "Displaying The Kernel Version"
cat -vET /proc/version >  $TEMP_DIR/version.txt																	# 
echo "Examining /proc/zoneinfo, a  rather detailed memory listing"
cat -vET /proc/zoneinfo >  $TEMP_DIR/zoneinfo.txt																	# 
echo "Time Elapsed Since Boot"
cat -vET /proc/uptime >  $TEMP_DIR/uptime.txt
echo "System Load Averages"
cat -vET /proc/loadavg >  $TEMP_DIR/loadavg.txt
echo "Filesystems Supported by the system"
cat -vET /proc/filesystems >  $TEMP_DIR/filesystems.txt
echo "Drive partition information "
cat -vET /proc/partitions >  $TEMP_DIR/partitions.txt
echo "Information about RAID arrays and devices "
cat -vET /proc/mdstat >  $TEMP_DIR/mdstat.txt
echo "Size of total and used swap areas"


-b				
-d     Used to set only the default ACL of a directory
-R     Removes the file access ACL only
-D     Removes directory default ACL only
-B     Remove all ACLs
-l     Lists  the  access ACL 
-r     Set  the  access  ACL  recursively



cat -vET /proc/swaps >  $TEMP_DIR/swaps.txt
echo "Mounted partitions"
cat -vET /proc/mounts >  $TEMP_DIR/mounts.txt
echo "Drivers currently loaded "
cat -vET /proc/devices >  $TEMP_DIR/devices.txt
echo "Kernel modules currently loaded "
cat -vET /proc/modules >  $TEMP_DIR/modules.txt
echo "Buses (e.g. PCI, USB, PC Card) "
cat -vET /proc/bus >  $TEMP_DIR/bus.txt
echo "I/O addresses in use "
cat -vET /proc/ioports >  $TEMP_DIR/ioports.txt
echo "DMA channels in use "
cat -vET /proc/dma >  $TEMP_DIR/dma.txt
echo "Current IRQs (Interrupt Requests) "
cat -vET /proc/interrupts >  $TEMP_DIR/interrupts.txt
echo "CPUs information "
cat -vET /proc/cpuinfo >  $TEMP_DIR/cpuinfo.txt
echo "Total and free memory"
cat -vET /proc/meminfo >  $TEMP_DIR/meminfo.txt
echo "Linux version"
cat -vET /proc/version >  $TEMP_DIR/version.txt
echo "the SCSI IO subsystem status"
cat -vET /proc/scsi >  $TEMP_DIR/SCSI.txt
echo "listing of all SCSI devices known to the kernel"
cat -vET /proc/scsi/scsi >  $TEMP_DIR/SCSI-devices.txt
echo "system-wide limit on the total number of pages of  System  V shared memory."
cat -vET /proc/sys/kernel/shmall >  $TEMP_DIR/shmall.txt
echo "determines whether kernel addresses are exposed via /proc files and other interfaces"
cat -vET /proc/sys/kernel/kptr_restrict >  $TEMP_DIR/kptr_restrict.txt
echo "flag that controls the L2 cache of G3 processor boards"
cat -vET /proc/sys/kernel/l2cr >  $TEMP_DIR/L2-cache.txt
echo "path to the kernel module loader"
cat -vET /proc/sys/kernel/modprobe >  $TEMP_DIR/modprobe.txt
echo "values representing the console_loglevel"
cat -vET /proc/sys/kernel/printk >  $TEMP_DIR/printk.txt
echo "number of UNIX 98 pseudoterminals"
cat -vET /proc/sys/kernel/pty >  $TEMP_DIR/pty.txt
echo "defines the maximum number of pseudoterminals"
cat -vET /proc/sys/kernel/pty/max >  $TEMP_DIR/pty-max.txt
echo "how many pseudoterminals are currently being use"
cat -vET /proc/sys/kernel/pty/nr >  $TEMP_DIR/pty-nr.txt
echo "size of the generic SCSI device (sg) buffer"
cat -vET /proc/sys/kernel/sg-big-buff >  $TEMP_DIR/SCSI-sg-buffer.txt
echo "functions allowed to  be  invoked  by  the  SysRq  key"
cat -vET /proc/sys/kernel/sysrq >  $TEMP_DIR/sysrq.txt
echo " how aggressively the kernel will swap memory pages"
cat -vET /proc/sys/vm/swappiness >  $TEMP_DIR/swappiness.txt
echo "list of theSystem  V  Interprocess  Communication (IPC) objects "
echo "(respectively: message queues, semaphores, and shared memory) "
cat -vET /proc/sysvipc >  $TEMP_DIR/sysvipc.txt
echo "mapped memory regions and their access permissions."
cat -vET /proc/$pid/maps >  $TEMP_DIR/maps.txt
echo "memory consumption of the processs mappings"
cat -vET /proc/$pid/smaps >  $TEMP_DIR/smaps.txt
echo "This contains three numbers measuring the CPU load:"
cat -vET /proc/loadavg >  $TEMP_DIR/loadavg.txt
echo "Output from PID Status:"
cat -vET /proc/$pid/status >  $TEMP_DIR/PidStatus.txt
echo "/etc/networks Configuration:"
cat -vET /etc/networks >  $TEMP_DIR/networks.txt
echo "/etc/hosts DHCP Server Configuration Setup"
cat -vET /etc/hosts >  $TEMP_DIR/hosts.txt
echo "/etc/ethers: Ethernet Configuration:"
cat -vET /etc/ethers >  $TEMP_DIR/ethers.txt
echo "PROC Wireless Networking Statistics:"
cat -vET /proc/net/wireless >  $TEMP_DIR/wireless.txt
echo "anycast6 Networking Statistics:"
cat -vET /proc/net/anycast6 >  $TEMP_DIR/anycast6.txt
echo "Proc Networking connector Statistics:"
cat -vET /proc/net/connector >  $TEMP_DIR/connector.txt
