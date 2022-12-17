

Non-Volatile Memory Express (nvme)


NVME specification introduces the concept of namespaces



## The 0 in the device file name indicates that this is the first NVMe drive.
## The p1 denotes that this is partition 1 within this drive’s namespace one.

## the partition is a subdivision of the namespace.
/dev/nmve0n1p1


## refer to a 
## 2nd NMVe drive’s
## 3rd namespace 
## and 2nd partition:
## /dev/nvme1n3p2


## check the number of namespaces supported and used
nvme id-ctrl /dev/nvme1 -H


Retrieve the geometry from nvme0
nvme lnvm-id-ns /dev/nvme0 -n 1





Optional Admin Command Support (OACS)


Number of Namespaces field ( nn ) shows the number of namespaces on the
controller


## check the size of the namespace
nvme id-ns /dev/nvme0n1


## check HD for multiple namespaces:
nvme list-ns /dev/nvme1


## list the attached NVMe devices:
nvme list



mmls /dev/nvme1n1



## extract the SMART log 
nvme smart-log /dev/nvme1


Print the raw SMART log to a file:
nvme smart-log /dev/nvme0 --raw-binary > smart_log.raw


USB Attached SCSI Protocol (UASP).


