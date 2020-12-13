#/bin/sh


## -------------------------------------------------------- ##
## [?] Use 'mmls -t list' for list of supported types)
## -------------------------------------------------------- ##
mmls -t list
mmls -t $VType           ## Specify type of volume system 



## ---------------------------------------------------- ##
    mmls -a           ## Show allocated volumes
## ---------------------------------------------------- ##
    mmls -A           ## Show unallocated volumes
## ---------------------------------------------------- ##
    mmls -m           ## Show metadata volumes
## ---------------------------------------------------- ##
    mmls -M           ## Hide metadata volumes
## ---------------------------------------------------- ##


## ---------------------------------------------------------------------------------------------------------------- ##
    mmls -i $ImgType        ## Identify the type of image file, such as raw.
## ---------------------------------------------------------------------------------------------------------------- ##
    mmls -B                 ## Include a column with the partition sizes in bytes (print the rounded length in bytes)
## ---------------------------------------------------------------------------------------------------------------- ##
    mmls -r                 ## Recurse into DOS partitions and look for other partition tables.
## ---------------------------------------------------------------------------------------------------------------- ##
    mmls -o $ImgOffset      ## Offset to the start of the volume that contains the partition system (in sectors)
## ---------------------------------------------------------------------------------------------------------------- ##
    mmls -b $SectorSize     ## The size (in bytes) of the device sectors
## ---------------------------------------------------------------------------------------------------------------- ##



##-========================================================================-##
##  [+] List the partition table of a Windows system using autodetect:
##-========================================================================-##
mmls disk_image.dd

##-========================================================================================-##
##  [+] List the contents of a BSD system that starts in sector 12345 of a split image:
##-========================================================================================-##
mmls -t bsd -o 12345 -i split disk-1.dd disk-2.dd
       





mmls -i list

## ----------------------------------------------- ##
##       [?] Supported Image Format Types:
## ----------------------------------------------- ##
## --> raw      (Single or split raw file (dd))
## --> aff      (Advanced Forensic Format)
## --> afd      (AFF Multiple File)
## --> afm      (AFF with external metadata)
## --> afflib   (All AFFLIB image formats (including beta ones))
## --> ewf      (Expert Witness Format (EnCase))




mmls -t list

## ----------------------------------------------- ##
##       [?] Supported Partition Types:
## ----------------------------------------------- ##
## --> dos      (DOS Partition Table)
## --> mac      (MAC Partition Map)
## --> bsd      (BSD Disk Label)
## --> sun      (Sun Volume Table of Contents (Solaris))
## --> gpt      (GUID Partition Table (EFI))












## ------------------------------------------------------ ##
##   [?] The AFF Toolkit provides these executables: 
## ------------------------------------------------------ ##
## 
##                -->  AFFCat 
##                -->  AFFcompare 
##                -->  AFFconvert
##                -->  AFFCopy 
##                -->  AFFCrypto 
##                -->  AFFDiskprint 
##                -->  AFFInfo 
##                -->  AFFix 
##                -->  AFFRecover 
##                -->  AFFSegment
##                -->  AFFSign 
##                -->  AFFStats 
##                -->  AFFuse 
##                -->  AFFVerify
##                -->  AFFXml





##-=================================================-##
##  [+] Expert Witness Compression Format (EWF)
##-=================================================-##

## --------------------------------------------------------------- ##
##   [?] EWF reads media information of EWF files in the SMART 
##        (EWF-S01) format and the EnCase (EWF-E01) format. 
## --------------------------------------------------------------- ##

## --------------------------------------------------------------------------- ##
##   [?] It supports files created by EnCase 1 to 6, linen and FTK Imager. 
##       To acquire, verify and export EWF files.
## --------------------------------------------------------------------------- ##


