

dmidecode | grep -iq virtual >> $TEMP_DIR/DmiVirt.txt && cat -vET $TEMP_DIR/DmiVirt.txtdmidecode --dump >> $TEMP_DIR/DmiDump.txt && cat -vET $TEMP_DIR/DmiDump.txt.txt## </>
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

echo "The DMI Table is located at offset 0x20"
dmidecode --dump-bin 0x20 >> $TEMP_DIR/DmiBin0x20.txt && cat -vET $TEMP_DIR/DmiBin0x20.txt
dmidecode --from-dump DmiBin0x20.txt

echo "The SMBIOS or DMI Entry Point is located at offset 0x00"
dmidecode --dump-bin 0x00  >> $TEMP_DIR/DmiBin0x00.txt && cat -vET $TEMP_DIR/DmiBin0x00.txt.txt
dmidecode --from-dump DmiBin0x00.txt

dmidecode --dev-mem /dev/mem >> $TEMP_DIR/DmiDevMem.txt && cat -vET $TEMP_DIR/DmiDevMem.txt
dmidecode --dev-mem /dev/kmem  >> $TEMP_DIR/DmiDevKmem.txt && cat -vET $TEMP_DIR/DmiDevKmem.txt




       Keyword           Types
     ────────────────────────────────────────────
       bios                   |    $0  |  $13  |       |       |      |
       system                 |    $1  |  $12  |  $15  |  $23  |  $32  |
       baseboard              |    $2  |  $10  |  $41  |         |         |
       chassis                |    $3  |          |         |         |         |
       processor              |    $4  |          |         |         |         |
       memory                 |    $5  |  $6   |  $16  |  $17  |      |
       cache                  |    $7  |          |         |         |         |
       connector              |    $8  |          |    |         |         |
       slot                   |    $9  |          |    |         |         |
     ────────────────────────────────────────────






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


