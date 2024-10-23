#!/bin/bash

# Description: This script automates virtualization file conversion using qemu-img.
# It supports conversions between raw, qcow2, vmdk, and other formats.

# Variables
IMAGE=$1  # Input image file (without extension)
HD=$2     # Optional hard disk variable for specific cases
RAW_HDD=$3  # Raw hard disk format
RAW_IMAGE=$IMAGE.img
QCOW2_IMAGE=$IMAGE.qcow2
VMDK_IMAGE=$IMAGE.vmdk
BIN_IMAGE=$IMAGE.bin

# Checking if input is provided
if [ -z "$IMAGE" ]; then
  echo "Usage: $0 <ImageName> [HardDisk] [RawHDD]"
  exit 1
fi

# Converting from raw to qcow2
echo "Converting $RAW_IMAGE to $QCOW2_IMAGE..."
qemu-img convert -f raw -O qcow2 $RAW_IMAGE $QCOW2_IMAGE
echo "Conversion completed."

# Converting from vmdk to raw
echo "Converting $VMDK_IMAGE to $RAW_IMAGE..."
qemu-img convert -f vmdk -O raw $VMDK_IMAGE $RAW_IMAGE
echo "Conversion completed."

# Converting from vmdk to qcow2
echo "Converting $VMDK_IMAGE to $QCOW2_IMAGE..."
qemu-img convert -f vmdk -O qcow2 $VMDK_IMAGE $QCOW2_IMAGE
echo "Conversion completed."

# Converting appliance (vmdk) to raw HDD
if [ -n "$HD" ] && [ -n "$RAW_HDD" ]; then
  echo "Converting $HD.vmdk to $RAW_HDD..."
  qemu-img convert appliance $HD.vmdk -O raw $RAW_HDD
  echo "Conversion completed."
fi

# Converting vmdk to binary file
echo "Converting $VMDK_IMAGE to $BIN_IMAGE..."
qemu-img convert $VMDK_IMAGE $BIN_IMAGE
echo "Conversion completed."

# Converting raw to vmdk
echo "Converting $RAW_IMAGE to $VMDK_IMAGE..."
qemu-img convert $RAW_IMAGE -O vmdk $VMDK_IMAGE
echo "Conversion completed."

# Converting dd to vmdk (if applicable)
if [ -f "$IMAGE.dd" ]; then
  echo "Converting $IMAGE.dd to $VMDK_IMAGE..."
  qemu-img convert $IMAGE.dd -O vmdk $VMDK_IMAGE
  echo "Conversion completed."
fi

echo "All conversions completed successfully."

# End of script