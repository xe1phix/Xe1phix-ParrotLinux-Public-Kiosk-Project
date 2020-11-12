#!/bin/sh
##-=============================================================================-##
##													[+] Xe1phix-Examining-The-DMI-Tables.sh
##-=============================================================================-##
## ------------------------------------------------------------------------------------------------------------------------------------- ##
export TempDir='mktemp --tmpdir=tmp.XXXXXXXXXX'
## ------------------------------------------------------------------------------------------------------------------------------------- ##
SMBIOS=`biosdecode --dev-mem /dev/mem | grep "SMBIOS" >> $TempDir/SMBIOS`
ACPI=`biosdecode --dev-mem /dev/mem | grep "ACPI" >> $TempDir/ACPI`
PNPBIOS=`biosdecode --dev-mem /dev/mem | grep "PNP BIOS" >> $TempDir/PNPBIOS`
PCInterupt=`biosdecode --dev-mem /dev/mem | grep "PCI Interrupt" >> $TempDir/PCInterupt`
## ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ##
MemAvailable=`cat -vET /proc/meminfo |grep MemAvailable: >> $TempDir/MemAvailable`
RSDTable32bitAddr=`biosdecode --dev-mem /dev/mem | grep "RSD Table 32-bit Address:" >> $TempDir/RSDTable32bitAddr`
RSD32bitAddr=`biosdecode --dev-mem /dev/mem | grep "RSD Table 32-bit Address:" |cut -d ':' -f2 >> $TempDir/RSD32bitAddr`
OEMIdent=`biosdecode --dev-mem /dev/mem | grep "OEM Identifier:" >> $TempDir/OEMIdent`
CallIfaceAddr=`biosdecode --dev-mem /dev/mem | grep "Calling Interface Address:" >> $TempDir/CallIfaceAddr`
ProtectedModeCodeAddr=`biosdecode --dev-mem /dev/mem | grep "16-bit Protected Mode Code Address:" >> $TempDir/ProtectedModeCodeAddr`
ProtectedModeDataAddr=`biosdecode --dev-mem /dev/mem | grep "16-bit Protected Mode Data Address:" >> $TempDir/ProtectedModeDataAddr`
StrTableLength=`biosdecode --dev-mem /dev/mem | grep "Structure Table Length:" >> $TempDir/StrTableLength`
StrTableAddr=`biosdecode --dev-mem /dev/mem | grep "Structure Table Address:" >> $TempDir/StrTableAddr`
NumStr=`biosdecode --dev-mem /dev/mem | grep "Number Of Structures:" >> $TempDir/NumStr`
MaxStructSize=`biosdecode --dev-mem /dev/mem | grep "Maximum Structure Size:" >> $TempDir/MaxStructSize`
## ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ##
DmiBiosVendor=`dmidecode --string bios-vendor  >> $TempDir/BiosVendor.txt`
DmiBiosVersion=`dmidecode --string bios-version >> $TempDir/BiosVersion.txt`
DmiBiosReleaseDate=`dmidecode --string bios-release-date >> $TempDir/BiosReleaseDate.txt`
DmiSystemManufacturer=`dmidecode --string system-manufacturer >> $TempDir/SystemManufacturer.txt`
DmiSystemProductName=`dmidecode --string system-product-name >> $TempDir/SystemProductName.txt`
DmiSystemVersion=`dmidecode --string system-version >> $TempDir/SystemVersion.txt`
DmiSystemSerialNumber=`dmidecode --string system-serial-number >> $TempDir/SystemSerialNumber.txt`
DmiSystemUuid=`dmidecode --string system-uuid >> $TempDir/SystemUuid.txt`
DmiBaseManufacturer=`dmidecode --string baseboard-manufacturer >> $TempDir/BaseManufacturer.txt`
DmiBaseProductName=`dmidecode --string baseboard-product-name >> $TempDir/BaseProductName.txt`
DmiBaseVersion=`dmidecode --string baseboard-version >> $TempDir/BaseVersion.txt`
DmiBaseSerialNum=`dmidecode --string baseboard-serial-number >> $TempDir/BaseSerialNum.txt`
DmiBaseboardAssetTag=`dmidecode --string baseboard-asset-tag >> $TempDir/BaseboardAssetTag.txt`
DmiChassisManufacturer=`dmidecode --string chassis-manufacturer >> $TempDir/ChassisManufacturer.txt`
DmiChassisType=`dmidecode --string chassis-type >> $TempDir/ChassisType.txt`
DmiChassisVersion=`dmidecode --string chassis-version >> $TempDir/ChassisVersion.txt`
DmiChassisSerialNum=`dmidecode --string chassis-serial-number >> $TempDir/ChassisSerialNum.txt`
DmiChassisAssetTag=`dmidecode --string chassis-asset-tag >> $TempDir/ChassisAssetTag.txt`
DmiProcessorFam=`dmidecode --string processor-family >> $TempDir/ProcessorFam.txt`
DmiProcessorManufacturer=`dmidecode --string processor-manufacturer >> $TempDir/ProcessorManufacturer.txt`
DmiProcessorVersion=`dmidecode --string processor-version >> $TempDir/ProcessorVersion.txt`
DmiProcessorFreq=`dmidecode --string processor-frequency >> $TempDir/ProcessorFreq.txt`
## ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ##
DmiTypeBios=`dmidecode --type bios >> $TempDir/DmiTypeBios.txt`
DmiTypeSystem=`dmidecode --type system >> $TempDir/DmiTypeSystem.txt`
DmiTypeBase=`dmidecode --type baseboard >> $TempDir/DmiTypeBase.txt`
DmiTypeChassis=`dmidecode --type chassis >> $TempDir/DmiTypeChassis.txt`
DmiTypeProcessor=`dmidecode --type processor >> $TempDir/DmiTypeProcessor.txt`
DmiTypeMemory=`dmidecode --type memory >> $TempDir/DmiTypeMemory.txt`
DmiTypeCache=`dmidecode --type cache >> $TempDir/DmiTypeCache.txt`
DmiTypeConnector=`dmidecode --type connector >> $TempDir/DmiTypeConnector.txt`
DmiTypeSlot=`dmidecode --type slot >> $TempDir/DmiTypeSlot.txt`
## ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ##
