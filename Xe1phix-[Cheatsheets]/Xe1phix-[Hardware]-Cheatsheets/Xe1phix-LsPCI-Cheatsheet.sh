#!/bin/sh
##-=========================================================================-##
##                      [+] Xe1phix-LsPCI-Cheatsheet.sh
##-=========================================================================-##
## ------------------------------------------------------------------------- ##
##	[?]  PCI device drivers call pci_register_driver() during 
##       their initialization with a pointer to a structure 
##       describing the driver.
## ------------------------------------------------------------------------- ##
##	[?]  A PCI Express Port is a logical PCI-PCI Bridge structure. 
## ------------------------------------------------------------------------- ##
##	[?]  There are two types of PCI Express Ports: 
##       -> Root Port
##       -> Switch Port
## ------------------------------------------------------------------------- ##
##	[?]  The Root Port originates a PCI Express link 
##       from a PCI Express Root Complex.
## ------------------------------------------------------------------------- ##
##	[?]  The Switch Port connects PCI Express links 
##       to internal logical PCI buses.
## ------------------------------------------------------------------------- ##
##-=========================================================================-##
##
## 
##~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~##
##-========================================================================-##
lspci -mm           ## Produce machine-readable output (single -m for an obsolete format)
lspci -t            ## Show bus tree
lspci -k            ## Show kernel drivers handling each device
##-========================================================================-##
lspci -x            ## Show hex-dump of the standard part of the config space
lspci -xxx          ## Show hex-dump of the whole config space (dangerous; root only)
lspci -xxxx         ## Show hex-dump of the 4096-byte extended config space (root only)
lspci -b            ## Bus-centric view (addresses and IRQs as seen by the bus)
lspci -D            ## Always show domain numbers
##-========================================================================-##
##~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~##
## 
## 
##~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=##
##-========================================================================-##
##  ------------ <:[ Resolving of device IDs to names ]:> ----------------- ##
##-========================================================================-##
lspci -n            ## Show numeric IDs
lspci -nn           ## Show both textual and numeric IDs (names & numbers)
lspci -q            ## Query the PCI ID database for unknown IDs via DNS
lspci -qq			## As above, but re-query locally cached entries
lspci -Q            ## Query the PCI ID database for all IDs via DNS
##-========================================================================-##
##~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~##
