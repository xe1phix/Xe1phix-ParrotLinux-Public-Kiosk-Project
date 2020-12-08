#!/bin/sh
## Convert-vmdk-to-vdi.sh

###############################################################
## Convert .vmdk to .vdi
###############################################################
sudo -u "$user_name" qemu-img convert "$vmdk_file" -O raw "$vdi_file"
