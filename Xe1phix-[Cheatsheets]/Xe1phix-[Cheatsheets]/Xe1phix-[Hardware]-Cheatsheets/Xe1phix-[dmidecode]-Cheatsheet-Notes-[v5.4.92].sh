!#/bin/sh

BRAND=`cat -vET $TEMP_DIR/dmidecode |grep -A9 "System Information" |grep "Manufacturer:" |cut -d ' ' -f2-`
PRODUCT=`cat -vET $TEMP_DIR/dmidecode |grep -A9 "System Information" |grep "Product Name:" |cut -d ' ' -f3-`
TYPE=`cat -vET $TEMP_DIR/dmidecode |grep -A9 "Chassis Information" |grep Type |cut -d ' ' -f2- |tr '[:upper:]' '[:lower:]'`

if [[ $BRAND =~ "O.E.M" ]]
 then
    BRAND=`cat -vET $TEMP_DIR/dmidecode |grep -A9 "Base Board Information" |grep "Manufacturer:" |cut -d ' ' -f2-`
    PRODUCT=`cat -vET $TEMP_DIR/dmidecode |grep -A9 "Base Board Information" |grep "Product Name:" |cut -d ' ' -f3-`
fi

KERNEL=`uname -r |cut -d '.' -f-3`
CPU=`cat -vET $TEMP_DIR/cpuinfo |grep "model name" |sort -u |cut -d ' ' -f3- |sed -e "s/[[:space:]]*/\  /"`
CHIPSET=`cat -vET $TEMP_DIR/lspci |grep "00:00.0.*Host bridge" |cut -d ':' -f3- |sed -e "s/[[:space:]]*/\  /"`
VGA=`cat -vET $TEMP_DIR/lspci |grep "VGA\|Display" |cut -d ':' -f3- |sed -e "s/^[[:space:]]*/\  /"`
NET=`cat -vET $TEMP_DIR/lspci |lspci |grep "Network\|Ethernet" |cut -d ':' -f3- |sed -e "s/^[[:space:]]*/\  /"`
SCSI=`cat -vET $TEMP_DIR/scsi |grep Model |cut -d ':' -f3-|sed -e "s/^[[:space:]]*/\  /"`
RAM=`cat -vET $TEMP_DIR/xl-info |grep total_memory |cut -d ':' -f2 |tr -d ' '`
BIOS=`cat -vET $TEMP_DIR/dmidecode |grep -A9 "BIOS Information" |grep "Version" |cut -d ' ' -f2-`
XEN_MAJOR=`cat -vET $TEMP_DIR/xl-info |grep xen_major |cut -d: -f2 |tr -d ' '`
XEN_MINOR=`cat -vET $TEMP_DIR/xl-info |grep xen_minor |cut -d: -f2 |tr -d ' '`
XEN_EXTRA=`cat -vET $TEMP_DIR/xl-info |grep xen_extra |cut -d: -f2 |tr -d ' '`
QUBES=`cat -vET $TEMP_DIR/qubes-release |cut -d '(' -f2 |cut -d ')' -f1`
XL_VTX=`cat -vET $TEMP_DIR/xl-info |grep xen_caps | grep hvm`
XL_VTD=`cat -vET $TEMP_DIR/xl-info |grep virt_caps |grep hvm_directio`
PCRS=`find /sys/devices/ -name pcrs`




MemMemAvailable=`cat -vET /proc/meminfo |grep MemAvailable:`
MemBuffers=`cat -vET /proc/meminfo |grep Buffers:`
MemCached=`cat -vET /proc/meminfo |grep Cached:`
MemSwapCached=`cat -vET /proc/meminfo |grep SwapCached:`
MemActive=`cat -vET /proc/meminfo |grep Active:`
MemInActive=`cat -vET /proc/meminfo |grep Inactive:`
MemKernelStack=`cat -vET /proc/meminfo |grep KernelStack:`
MemPageTables=`cat -vET /proc/meminfo |grep PageTables:`
MemVmallocTotal=`cat -vET /proc/meminfo |grep VmallocTotal:`
MemVmallocUsed=`cat -vET /proc/meminfo |grep VmallocUsed:`
MemVmallocChunk=`cat -vET /proc/meminfo |grep VmallocChunk:`
MemSwapTotal=`cat -vET /proc/meminfo |grep SwapTotal:`
MemSwapFree=`cat -vET /proc/meminfo |grep SwapFree:`
MemShmem=`cat -vET /proc/meminfo |grep Shmem:`
MemHugepagesize=`cat -vET /proc/meminfo |grep Hugepagesize:`







MemMemAvailable=`cat -vET /proc/meminfo |grep MemAvailable: >> $TEMP_DIR/MEM/MemAvailable`
MemBuffers=`cat -vET /proc/meminfo |grep Buffers: >> $TEMP_DIR/MEM/Buffers`
MemCached=`cat -vET /proc/meminfo |grep Cached: >> $TEMP_DIR/MEM/Cached`
MemSwapCached=`cat -vET /proc/meminfo |grep SwapCached: >> $TEMP_DIR/MEM/SwapCached`
MemActive=`cat -vET /proc/meminfo |grep Active: >> $TEMP_DIR/MEM/Active`
MemInActive=`cat -vET /proc/meminfo |grep Inactive: >> $TEMP_DIR/MEM/Inactive`
MemKernelStack=`cat -vET /proc/meminfo |grep KernelStack: >> $TEMP_DIR/MEM/KernelStack`
MemPageTables=`cat -vET /proc/meminfo |grep PageTables: >> $TEMP_DIR/MEM/PageTables`
MemVmallocTotal=`cat -vET /proc/meminfo |grep VmallocTotal: >> $TEMP_DIR/MEM/VmallocTotal`
MemVmallocUsed=`cat -vET /proc/meminfo |grep VmallocUsed: >> $TEMP_DIR/MEM/VmallocUsed`
MemVmallocChunk=`cat -vET /proc/meminfo |grep VmallocChunk: >> $TEMP_DIR/MEM/VmallocChunk`
MemSwapTotal=`cat -vET /proc/meminfo |grep SwapTotal: >> $TEMP_DIR/MEM/SwapTotal`
MemSwapFree=`cat -vET /proc/meminfo |grep SwapFree: >> $TEMP_DIR/MEM/SwapFree`
MemShmem=`cat -vET /proc/meminfo |grep Shmem: >> $TEMP_DIR/MEM/Shmem`
MemHugepagesize=`cat -vET /proc/meminfo |grep Hugepagesize: >> $TEMP_DIR/MEM/Hugepagesize`




if [[ $MEM ]]
 then
    VTD="Active"
    IOMMU="yes"

 else
    VTD="Not active"
    IOMMU="no"

fi


SMBIOS=`biosdecode --dev-mem /dev/mem | grep "SMBIOS" >> $TEMP_DIR/SMBIOS`
ACPI=`biosdecode --dev-mem /dev/mem | grep "ACPI" >> $TEMP_DIR/ACPI`
PNPBIOS=`biosdecode --dev-mem /dev/mem | grep "PNP BIOS" >> $TEMP_DIR/PNPBIOS`
PCInterupt=`biosdecode --dev-mem /dev/mem | grep "PCI Interrupt" >> $TEMP_DIR/PCInterupt`

MemAvailable=`cat -vET /proc/meminfo |grep MemAvailable: >> $TEMP_DIR/MemAvailable`
RSDTable32bitAddr=`biosdecode --dev-mem /dev/mem | grep "RSD Table 32-bit Address:" >> $TEMP_DIR/RSDTable32bitAddr`
RSD32bitAddr=`biosdecode --dev-mem /dev/mem | grep "RSD Table 32-bit Address:" |cut -d ':' -f2 >> $TEMP_DIR/RSD32bitAddr`
OEMIdent=`biosdecode --dev-mem /dev/mem | grep "OEM Identifier:" >> $TEMP_DIR/OEMIdent`
CallIfaceAddr=`biosdecode --dev-mem /dev/mem | grep "Calling Interface Address:" >> $TEMP_DIR/CallIfaceAddr`
ProtectedModeCodeAddr=`biosdecode --dev-mem /dev/mem | grep "16-bit Protected Mode Code Address:" >> $TEMP_DIR/ProtectedModeCodeAddr`
ProtectedModeDataAddr=`biosdecode --dev-mem /dev/mem | grep "16-bit Protected Mode Data Address:" >> $TEMP_DIR/ProtectedModeDataAddr`
StrTableLength=`biosdecode --dev-mem /dev/mem | grep "Structure Table Length:" >> $TEMP_DIR/StrTableLength`
StrTableAddr=`biosdecode --dev-mem /dev/mem | grep "Structure Table Address:" >> $TEMP_DIR/StrTableAddr`
NumStr=`biosdecode --dev-mem /dev/mem | grep "Number Of Structures:" >> $TEMP_DIR/NumStr`
MaxStructSize=`biosdecode --dev-mem /dev/mem | grep "Maximum Structure Size:" >> $TEMP_DIR/MaxStructSize`



DmiBiosVendor=`dmidecode --string bios-vendor  >> $TEMP_DIR/BiosVendor.txt`
DmiBiosVersion=`dmidecode --string bios-version >> $TEMP_DIR/BiosVersion.txt`
DmiBiosReleaseDate=`dmidecode --string bios-release-date >> $TEMP_DIR/BiosReleaseDate.txt`
DmiSystemManufacturer=`dmidecode --string system-manufacturer >> $TEMP_DIR/SystemManufacturer.txt`
DmiSystemProductName=`dmidecode --string system-product-name >> $TEMP_DIR/SystemProductName.txt`
DmiSystemVersion=`dmidecode --string system-version >> $TEMP_DIR/SystemVersion.txt`
DmiSystemSerialNumber=`dmidecode --string system-serial-number >> $TEMP_DIR/SystemSerialNumber.txt`
DmiSystemUuid=`dmidecode --string system-uuid >> $TEMP_DIR/SystemUuid.txt`
DmiBaseManufacturer=`dmidecode --string baseboard-manufacturer >> $TEMP_DIR/BaseManufacturer.txt`
DmiBaseProductName=`dmidecode --string baseboard-product-name >> $TEMP_DIR/BaseProductName.txt`
DmiBaseVersion=`dmidecode --string baseboard-version >> $TEMP_DIR/BaseVersion.txt`
DmiBaseSerialNum=`dmidecode --string baseboard-serial-number >> $TEMP_DIR/BaseSerialNum.txt`
DmiBaseboardAssetTag=`dmidecode --string baseboard-asset-tag >> $TEMP_DIR/BaseboardAssetTag.txt`
DmiChassisManufacturer=`dmidecode --string chassis-manufacturer >> $TEMP_DIR/ChassisManufacturer.txt`
DmiChassisType=`dmidecode --string chassis-type >> $TEMP_DIR/ChassisType.txt`
DmiChassisVersion=`dmidecode --string chassis-version >> $TEMP_DIR/ChassisVersion.txt`
DmiChassisSerialNum=`dmidecode --string chassis-serial-number >> $TEMP_DIR/ChassisSerialNum.txt`
DmiChassisAssetTag=`dmidecode --string chassis-asset-tag >> $TEMP_DIR/ChassisAssetTag.txt`
DmiProcessorFam=`dmidecode --string processor-family >> $TEMP_DIR/ProcessorFam.txt`
DmiProcessorManufacturer=`dmidecode --string processor-manufacturer >> $TEMP_DIR/ProcessorManufacturer.txt`
DmiProcessorVersion=`dmidecode --string processor-version >> $TEMP_DIR/ProcessorVersion.txt`
DmiProcessorFreq=`dmidecode --string processor-frequency >> $TEMP_DIR/ProcessorFreq.txt`



DmiTypeBios=`dmidecode --type bios >> $TEMP_DIR/DmiTypeBios.txt`
DmiTypeSystem=`dmidecode --type system >> $TEMP_DIR/DmiTypeSystem.txt`
DmiTypeBase=`dmidecode --type baseboard >> $TEMP_DIR/DmiTypeBase.txt`
DmiTypeChassis=`dmidecode --type chassis >> $TEMP_DIR/DmiTypeChassis.txt`
DmiTypeProcessor=`dmidecode --type processor >> $TEMP_DIR/DmiTypeProcessor.txt`
DmiTypeMemory=`dmidecode --type memory >> $TEMP_DIR/DmiTypeMemory.txt`
DmiTypeCache=`dmidecode --type cache >> $TEMP_DIR/DmiTypeCache.txt`
DmiTypeConnector=`dmidecode --type connector >> $TEMP_DIR/DmiTypeConnector.txt`
DmiTypeSlot=`dmidecode --type slot >> $TEMP_DIR/DmiTypeSlot.txt`


echo "Display  active and  inactive memory:"
VmStatMemState=`vmstat --active >> $TEMP_DIR/VmStatMemState.txt`                          # active/inactive memory
echo "Displays slabinfo:"
VmStatSlabinfo=`vmstat --slabs >> $TEMP_DIR/VmStatSlabinfo.txt`                                     # slabinfo
echo "Displays a table of various event counters and memory statistics.:"
VmstatStats=`vmstat --stats >> $TEMP_DIR/VmstatStats.txt`                                                     # event counter statistics
echo "Report disk statistics:"
VmStatDiskStats=`vmstat --disk >> $TEMP_DIR/VmStatDiskStats.txt`                                         # disk statistics
echo "Report some  summary  statistics about disk activity:"
VmStatDiskSum=`vmstat --disk-sum >> $TEMP_DIR/VmStatDiskSum.txt`                          # summarize disk statistics
echo "Detailed statistics about partitions:"
VmStatPart=`vmstat --partition >> $TEMP_DIR/VmStatPart.txt`                                         # partition specific statistics
echo "Output Format Vmstat Will use:"
VmStatKb=`vmstat --unit k  >> $TEMP_DIR/VmStatKb.txt`                                                    # 1000 (k), 1024 (K),  1000000  (m), or  1048576  (M) bytes
echo "display kernel slab cache information"
VmStatSlabCache=`slabtop --once >> $TEMP_DIR/VmStatSlabCache.txt`



lsblkALL=`lsblk --all >> $TEMP_DIR/lsblkALL`
lsblkBytes=`lsblk --bytes >> $TEMP_DIR/lsblkBytes`
lsblkNoDeps=`lsblk --nodeps >> $TEMP_DIR/lsblkNoDeps`
lsblkDiscard=`lsblk --discard >> $TEMP_DIR/lsblkDiscard`
lsblkFS=`lsblk --fs >> $TEMP_DIR/lsblkFS`
lsblkAscii=`lsblk --ascii >> $TEMP_DIR/lsblkAscii`
lsblkPerms=`lsblk --perms >> $TEMP_DIR/lsblkPerms`
lsblkList=`lsblk --list >> $TEMP_DIR/lsblkList`
lsblkNoHeadings=`lsblk --noheadings >> $TEMP_DIR/lsblkNoHeadings`
lsblkPairs=`lsblk --pairs >> $TEMP_DIR/lsblkPairs`
lsblkRaw=`lsblk --raw >> $TEMP_DIR/lsblkRaw`
lsblkTopology=`lsblk --topology >> $TEMP_DIR/lsblkTopology`


