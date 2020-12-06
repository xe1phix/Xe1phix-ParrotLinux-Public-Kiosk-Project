#!/bin/sh



## --------------------------------------------------------------------------------------------------- ##
    zuluMount-cli -m -d /dev/sdc1				    ## mount a volume
    zuluMount-cli -u -d /dev/sdc1					## unmount a volume
## --------------------------------------------------------------------------------------------------- ##
    zuluMount-cli -M                                ## create a mount point in "/run/media/private/$USER" and a 
                                                    ## publicly accessible "mirror" in "/run/media/public/'
## --------------------------------------------------------------------------------------------------- ##
    zuluMount-cli -d $VolumePath
    zuluMount-cli -z $MountPoint
    zuluMount-cli -e mode(rw/ro)
## --------------------------------------------------------------------------------------------------- ##
    zuluMount-cli -u -d /dev/sdc1					## unmount a volume
    zuluMount-cli -m -d /dev/sdc2 -p xyz			## unmount a volume
## --------------------------------------------------------------------------------------------------- ##
    zuluMount-cli -l								## print expanded list of all volumes
    zuluMount-cli -P								## print a list of all volumes
    zuluMount-cli -A                                ## print a list of all volumes
    zuluMount-cli -S 								## print a list of system volumes
    zuluMount-cli -N								## print a list of non system volumes
    zuluMount-cli -E								## print a list of mounted volumes
    zuluMount-cli -D                                ## get a device node address from its mapper path
## --------------------------------------------------------------------------------------------------- ##
    zuluMount-cli -Y                                ## file system options
    zuluMount-cli -e								## mount options
## --------------------------------------------------------------------------------------------------- ##
    zuluMount-cli -o                                ## offset in sectors on where the volume starts in the volume.
## --------------------------------------------------------------------------------------------------- ##
##  [+] crypto_LUKS,crypto_PLAIN,crypto_TCRYPT volumes, -p passphrase/-f keyfile
## --------------------------------------------------------------------------------------------------- ##
    zuluMount-cli -m -d /dev/sdc2 -p xyz            ## mount and encrypted volume with a key "xyz"
## --------------------------------------------------------------------------------------------------- ##
    zuluMount-cli -t                                ## unlock a volume as VeraCrypt volume,use "-t vera"
    zuluMount-cli -F                                ## path to truecrypt multiple keyfiles.
## --------------------------------------------------------------------------------------------------- ##






