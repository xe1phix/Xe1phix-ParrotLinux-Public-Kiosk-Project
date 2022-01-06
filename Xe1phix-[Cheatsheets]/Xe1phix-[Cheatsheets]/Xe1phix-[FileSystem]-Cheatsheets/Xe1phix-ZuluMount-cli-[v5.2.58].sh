#!/bin/sh



## ------------------------------------------------------------------------------------------------------------------------------------------------- ##
    zuluMount-cli -m -d /dev/sdc1					## Mount A Volumes
    zuluMount-cli -u -d /dev/sdc1						## Unmount A Volumes

    zuluMount-cli -d $VolumesPath					## Volumes Path
    zuluMount-cli -z $MountPoint					## Mount Point
    zuluMount-cli -e mode rw							## Read-Write Mode
    zuluMount-cli -e mode ro							## Read-Only Mode
## ------------------------------------------------------------------------------------------------------------------------------------------------- ##
    zuluMount-cli -u -d /dev/sdc1							## Unmount A Volume
    zuluMount-cli -m -d /dev/sdc2 -p $Pass			## Unmount A Volume
## ------------------------------------------------------------------------------------------------------------------------------------------------- ##
    zuluMount-cli -l								## Print Expanded List of All Volumes
    zuluMount-cli -P								## Print A List of All Volumes
    zuluMount-cli -A								## Print A List of All Volumes
    zuluMount-cli -S 								## Print A List of System Volumes
    zuluMount-cli -N								## Print A List of Non System Volumes
    zuluMount-cli -E								## Print A List of Mounted Volumes
    zuluMount-cli -D								## Get A Device Node Address From its Mapper Path
## ------------------------------------------------------------------------------------------------------------------------------------------------- ##
    zuluMount-cli -Y								## File System Options
    zuluMount-cli -e								## Mount Options
## ------------------------------------------------------------------------------------------------------------------------------------------------- ##
    zuluMount-cli -t								## Unlock a Volumes as VeraCrypt Volumes, Use "-t vera"
    zuluMount-cli -F								## Path To Truecrypt Multiple KeyFiles.
## ------------------------------------------------------------------------------------------------------------------------------------------------- ##
    zuluMount-cli -M								## Create A Mount Point In "/run/media/private/$USER"
                                                    		## Publicly Accessible "mirror" in "/run/media/public/'
## ------------------------------------------------------------------------------------------------------------------------------------------------- ##
    zuluMount-cli -o                              ## Offset In Sectors on Where The Volumes Starts In The Volumes.
## ------------------------------------------------------------------------------------------------------------------------------------------------- ##
##  [?]  crypto_LUKS,crypto_PLAIN,crypto_TCRYPT $Volume -p $Pass -f $KeyFile
## ------------------------------------------------------------------------------------------------------------------------------------------------- ##
    zuluMount-cli -m -d /dev/sdc2 -p $Pass            	## Mount And Encrypted Volumes With A Key "$Pass"
## ------------------------------------------------------------------------------------------------------------------------------------------------- ##



