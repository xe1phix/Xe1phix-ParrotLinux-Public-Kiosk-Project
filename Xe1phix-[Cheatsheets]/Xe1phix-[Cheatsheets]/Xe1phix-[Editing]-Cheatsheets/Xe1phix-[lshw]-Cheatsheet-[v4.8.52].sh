#!/bin/sh


lshw -short -class disk


lshw --class disk



Lists hardware In a compact format
lshw -short


Lists all disks and storage controllers In the system.
lshw -class disk -class storage

Lists all network interfaces In HTML.
lshw -html -class network



Outputs the device list showing bus information
detailing SCSI, USB, IDE and PCI addresses

lshw -short -businfo



view the storage interfaces, type (SATA, NVME, SCSI):
lshw -class storage


lshw -businfo -class storage

lshw -businfo -class disk


