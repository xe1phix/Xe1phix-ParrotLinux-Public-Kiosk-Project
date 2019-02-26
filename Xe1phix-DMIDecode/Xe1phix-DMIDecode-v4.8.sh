


dmidecode --dump >> $TEMP_DIR/dmidump.txt

TMPDIR=`mktemp -d /tmp/DMIDecode.XXXXXX`


dmidecode --dump >> $TEMP_DIR/DmiDump.txt && cat -vET $TEMP_DIR/DmiDump.txt.txt



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


dmidecode | grep -iq virtual >> $TEMP_DIR/DmiVirt.txt && cat -vET $TEMP_DIR/DmiVirt.txt 

dmidecode --dump >> $TEMP_DIR/DmiDump.txt && cat -vET $TEMP_DIR/DmiDump.txt.txt

dmidecode --type 127 >> $TEMP_DIR/DmiType127.txt && cat -vET $TEMP_DIR/DmiType127.txt
dmidecode --type 4 >> $TEMP_DIR/DmiType4.txt && cat -vET $TEMP_DIR/DmiType4.txt
dmidecode --type 3 >> $TEMP_DIR/DmiType3.txt && cat -vET $TEMP_DIR/DmiType3.txt
dmidecode --type 2 >> $TEMP_DIR/DmiType2.txt && cat -vET $TEMP_DIR/DmiType2.txt
dmidecode --type 16 >> $TEMP_DIR/DmiType16.txt && cat -vET $TEMP_DIR/DmiType16.txt
dmidecode --type 19 >> $TEMP_DIR/DmiType19.txt && cat -vET $TEMP_DIR/DmiType19.txt
dmidecode --type 22 >> $TEMP_DIR/DmiType22.txt && cat -vET $TEMP_DIR/DmiType22.txt
dmidecode --type 7 >> $TEMP_DIR/DmiType7.txt && cat -vET $TEMP_DIR/DmiType7.txt
dmidecode --type 11 >> $TEMP_DIR/DmiType11.txt && cat -vET $TEMP_DIR/DmiType11.txt
dmidecode --type 0 >> $TEMP_DIR/DmiType0.txt && cat -vET $TEMP_DIR/DmiType0.txt
dmidecode --type 1 >> $TEMP_DIR/DmiType1.txt && cat -vET $TEMP_DIR/DmiType1.txt

 > dmitypes.txt
 ) > dmibin.txt

echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "    [+] The DMI Table is located at offset 0x20"
echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
dmidecode --dump-bin 0x20 >> $TEMP_DIR/DmiBin0x20.txt && cat -vET $TEMP_DIR/DmiBin0x20.txt
dmidecode --from-dump DmiBin0x20.txt

echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "    [+] The SMBIOS or DMI Entry Point is located at offset 0x00"
echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
dmidecode --dump-bin 0x00  >> $TEMP_DIR/DmiBin0x00.txt && cat -vET $TEMP_DIR/DmiBin0x00.txt.txt
dmidecode --from-dump DmiBin0x00.txt

dmidecode --dev-mem /dev/mem >> $TEMP_DIR/DmiDevMem.txt && cat -vET $TEMP_DIR/DmiDevMem.txt
dmidecode --dev-mem /dev/kmem  >> $TEMP_DIR/DmiDevKmem.txt && cat -vET $TEMP_DIR/DmiDevKmem.txt




       The SMBIOS specification defines the following DMI types:

       Type   Information
       ────────────────────────────────────────
          0   BIOS
          1   System
          2   Base Board
          3   Chassis
          4   Processor
          5   Memory Controller
          6   Memory Module
          7   Cache
          8   Port Connector
          9   System Slots
         10   On Board Devices
         11   OEM Strings
         12   System Configuration Options
         13   BIOS Language
         14   Group Associations
         15   System Event Log
         16   Physical Memory Array

         17   Memory Device
         18   32-bit Memory Error
         19   Memory Array Mapped Address
         20   Memory Device Mapped Address
         21   Built-in Pointing Device
         22   Portable Battery
         23   System Reset
         24   Hardware Security
         25   System Power Controls
         26   Voltage Probe
         27   Cooling Device
         28   Temperature Probe
         29   Electrical Current Probe
         30   Out-of-band Remote Access
         31   Boot Integrity Services
         32   System Boot
         33   64-bit Memory Error
         34   Management Device
         35   Management Device Component
         36   Management Device Threshold Data
         37   Memory Channel
         38   IPMI Device
         39   Power Supply
         40   Additional Information
         41   Onboard Device

          126  disabled  entries
          127 is an end-of-table marker
       128-255 OEM-specific data

dmidecode --string ;
dmidecode --dump > dmidump.txt

dmidecode |grep -A9 "BIOS Information" |grep "Version" |cut -d ' ' -f2-
dmidecode |grep -A9 "System Information" |grep "Manufacturer:" |cut -d ' ' -f2-
dmidecode |grep -A9 "System Information" |grep "Product Name:" |cut -d ' ' -f3-
dmidecode |grep -A9 "Chassis Information" |grep Type |cut -d ' ' -f2- |tr '[:upper:]' '[:lower:]'
dmidecode |grep -A9 "Base Board Information" |grep "Manufacturer:" |cut -d ' ' -f2-
dmidecode |grep -A9 "Base Board Information" |grep "Product Name:" |cut -d ' ' -f3-
dmidecode |grep -A9 "BIOS Information" |grep "Version" |cut -d ' ' -f2-
dmidecode |grep -A9 "BIOS Information" |grep "Version" |cut -d ' ' -f2-





dmidecode --type system >> $TEMP_DIR/DmiTypeSystem.txt
dmidecode --type baseboard >> $TEMP_DIR/DmiTypeBase.txt
dmidecode --type chassis >> $TEMP_DIR/DmiTypeChassis.txt
dmidecode --type processor >> $TEMP_DIR/DmiTypeProcessor.txt
dmidecode --type memory >> $TEMP_DIR/DmiTypeMemory.txt
dmidecode --type cache >> $TEMP_DIR/DmiTypeCache.txt
dmidecode --type connector >> $TEMP_DIR/DmiTypeConnector.txt
dmidecode --type slot >> $TEMP_DIR/DmiTypeSlot.txt


dmidecode --type bios >> $TEMP_DIR/DmiTypeBios.txt && cat -vET $TEMP_DIR/DmiTypeBios.txt
dmidecode --type system >> $TEMP_DIR/DmiTypeSystem.txt && cat -vET $TEMP_DIR/DmiTypeSystem.txt
dmidecode --type baseboard >> $TEMP_DIR/DmiTypeBase.txt && cat -vET $TEMP_DIR/DmiTypeBase.txt
dmidecode --type chassis >> $TEMP_DIR/DmiTypeChassis.txt && cat -vET $TEMP_DIR/DmiTypeChassis.txt
dmidecode --type processor >> $TEMP_DIR/DmiTypeProcessor.txt && cat -vET $TEMP_DIR/DmiTypeProcessor.txt
dmidecode --type memory >> $TEMP_DIR/DmiTypeMemory.txt && cat -vET $TEMP_DIR/DmiTypeMemory.txt
dmidecode --type cache >> $TEMP_DIR/DmiTypeCache.txt && cat -vET $TEMP_DIR/DmiTypeCache.txt
dmidecode --type connector >> $TEMP_DIR/DmiTypeConnector.txt && cat -vET $TEMP_DIR/DmiTypeConnector.txt
dmidecode --type slot >> $TEMP_DIR/DmiTypeSlot.txt && cat -vET $TEMP_DIR/DmiTypeSlot.txt




dmidecode --string bios-vendor  >> $TEMP_DIR/BiosVendor.txt && cat -vET $TEMP_DIR/BiosVendor.txt
dmidecode --string bios-version >> $TEMP_DIR/BiosVersion.txt && cat -vET $TEMP_DIR/BiosVersion.txt
dmidecode --string bios-release-date >> $TEMP_DIR/BiosReleaseDate.txt && cat -vET $TEMP_DIR/BiosReleaseDate.txt
dmidecode --string system-manufacturer >> $TEMP_DIR/SystemManufacturer.txt && cat -vET $TEMP_DIR/SystemManufacturer.txt
dmidecode --string system-product-name >> $TEMP_DIR/SystemProductName.txt && cat -vET $TEMP_DIR/SystemProductName.txt
dmidecode --string system-version >> $TEMP_DIR/SystemVersion.txt && cat -vET $TEMP_DIR/SystemVersion.txt
dmidecode --string system-serial-number >> $TEMP_DIR/SystemSerialNumber.txt && cat -vET $TEMP_DIR/SystemSerialNumber.txt
dmidecode --string system-uuid >> $TEMP_DIR/SystemUuid.txt && cat -vET $TEMP_DIR/SystemUuid.txt
dmidecode --string baseboard-manufacturer >> $TEMP_DIR/BaseManufacturer.txt && cat -vET $TEMP_DIR/BaseManufacturer.txt
dmidecode --string baseboard-product-name >> $TEMP_DIR/BaseProductName.txt && cat -vET $TEMP_DIR/BaseProductName.txt
dmidecode --string baseboard-version >> $TEMP_DIR/BaseVersion.txt && cat -vET $TEMP_DIR/BaseVersion.txt
dmidecode --string baseboard-serial-number >> $TEMP_DIR/BaseSerialNum.txt && cat -vET $TEMP_DIR/BaseSerialNum.txt
dmidecode --string baseboard-asset-tag >> $TEMP_DIR/BaseboardAssetTag.txt && cat -vET $TEMP_DIR/BaseboardAssetTag.txt
dmidecode --string chassis-manufacturer >> $TEMP_DIR/ChassisManufacturer.txt && cat -vET $TEMP_DIR/ChassisManufacturer.txt
dmidecode --string chassis-type >> $TEMP_DIR/ChassisType.txt && cat -vET $TEMP_DIR/ChassisType.txt
dmidecode --string chassis-version >> $TEMP_DIR/ChassisVersion.txt && cat -vET $TEMP_DIR/ChassisVersion.txt
dmidecode --string chassis-serial-number >> $TEMP_DIR/ChassisSerialNum.txt && cat -vET $TEMP_DIR/ChassisSerialNum.txt
dmidecode --string chassis-asset-tag >> $TEMP_DIR/ChassisAssetTag.txt && cat -vET $TEMP_DIR/ChassisAssetTag.txt
dmidecode --string processor-family >> $TEMP_DIR/ProcessorFam.txt && cat -vET $TEMP_DIR/ProcessorFam.txt
dmidecode --string processor-manufacturer >> $TEMP_DIR/ProcessorManufacturer.txt && cat -vET $TEMP_DIR/ProcessorManufacturer.txt
dmidecode --string processor-version >> $TEMP_DIR/ProcessorVersion.txt && cat -vET $TEMP_DIR/ProcessorVersion.txt
dmidecode --string processor-frequency >> $TEMP_DIR/ProcessorFreq.txt && cat -vET $TEMP_DIR/ProcessorFreq.txt



biosdecode --dev-mem /dev/mem | grep "RSD Table 32-bit Address:"
biosdecode --dev-mem /dev/mem | grep "RSD Table 32-bit Address:" |cut -d ':' -f2
biosdecode --dev-mem /dev/mem | grep "RSD Table 32-bit Address:" |cut -d ':' -f2 |cut -d ':' -f2 |tr -d ' '

vpddecode --dev-mem /dev/mem


vpddecode --string bios-build-id
vpddecode --string box-serial-number
vpddecode --string motherboard-serial-number
vpddecode --string machine-type-model
vpddecode --string bios-release-date

vpddecode --string --dump




