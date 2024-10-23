#!/bin/bash

# Global variables
IMAGE=""
HD=""
RAW_IMG=""
QCOW_IMG=""
BIN_IMG=""
RAW_HDD=""

# Function to sanitize input
sanitize_input() {
local input="$1"
# Remove any leading/trailing spaces, and escape any special characters
sanitized_input=$(echo "$input" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//;s/[^a-zA-Z0-9._-]//g')
printf "%s" "$sanitized_input"
}

# Function to convert raw to qcow2
convert_raw_to_qcow2() {
local img="$1"
local qcow2="$2"
if ! qemu-img convert -f raw -O qcow2 "$img" "$qcow2"; then
printf "Error converting raw to qcow2.\n" >&2
return 1
fi
printf "Conversion to qcow2 successful: %s -> %s\n" "$img" "$qcow2"
}

# Function to convert vmdk to raw
convert_vmdk_to_raw() {
local vmdk="$1"
local img="$2"
if ! qemu-img convert -f vmdk -O raw "$vmdk" "$img"; then
printf "Error converting vmdk to raw.\n" >&2
return 1
fi
printf "Conversion to raw successful: %s -> %s\n" "$vmdk" "$img"
}

# Function to convert vmdk to qcow2
convert_vmdk_to_qcow2() {
local vmdk="$1"
local qcow2="$2"
if ! qemu-img convert -f vmdk -O qcow2 "$vmdk" "$qcow2"; then
printf "Error converting vmdk to qcow2.\n" >&2
return 1
fi
printf "Conversion to qcow2 successful: %s -> %s\n" "$vmdk" "$qcow2"
}

# Function to convert vmdk appliance to raw hdd
convert_appliance_to_raw() {
local vmdk="$1"
local hdd="$2"
if ! qemu-img convert appliance "$vmdk" -O raw "$hdd"; then
printf "Error converting appliance vmdk to raw hdd.\n" >&2
return 1
fi
printf "Conversion to raw HDD successful: %s -> %s\n" "$vmdk" "$hdd"
}

<a href="../../../../../system/bin"># Function to convert vmdk to</a>
convert_vmdk_to_bin() {
local vmdk="$1"
local bin="$2"
if ! qemu-img convert "$vmdk" "$bin"; then
printf "Error converting vmdk to bin.\n" >&2
return 1
fi
printf "Conversion to bin successful: %s -> %s\n" "$vmdk" "$bin"
}

# Main menu function
main_menu() {
local choice
while true; do
printf "\n--- Virtual Filesystem Converter Menu ---\n"
printf "1. Convert RAW to QCOW2\n"
printf "2. Convert VMDK to RAW\n"
printf "3. Convert VMDK to QCOW2\n"
printf "4. Convert Appliance VMDK to RAW HDD\n"
printf "5. Convert VMDK to BIN\n"
printf "6. Exit\n"
printf "Choose an option (1-6): "
read -r choice

case "$choice" in
1)
printf "Enter RAW image file path (e.g., image.img): "
read -r IMAGE
IMAGE=$(sanitize_input "$IMAGE")
QCOW_IMG="${IMAGE%.img}.qcow2"
convert_raw_to_qcow2 "$IMAGE" "$QCOW_IMG"
;;
2)
printf "Enter VMDK file path (e.g., image.vmdk): "
read -r IMAGE
IMAGE=$(sanitize_input "$IMAGE")
RAW_IMG="${IMAGE%.vmdk}.img"
convert_vmdk_to_raw "$IMAGE" "$RAW_IMG"
;;
3)
printf "Enter VMDK file path (e.g., image.vmdk): "
read -r IMAGE
IMAGE=$(sanitize_input "$IMAGE")
QCOW_IMG="${IMAGE%.vmdk}.qcow2"
convert_vmdk_to_qcow2 "$IMAGE" "$QCOW_IMG"
;;
4)
printf "Enter Appliance VMDK file path (e.g., hd.vmdk): "
read -r HD
HD=$(sanitize_input "$HD")
RAW_HDD="${HD%.vmdk}.hdd"
convert_appliance_to_raw "$HD" "$RAW_HDD"
;;
5)
printf "Enter VMDK file path (e.g., image.vmdk): "
read -r IMAGE
IMAGE=$(sanitize_input "$IMAGE")
BIN_IMG="${IMAGE%.vmdk}.bin"
convert_vmdk_to_bin "$IMAGE" "$BIN_IMG"
;;
6)
printf "Exiting...\n"
break
;;
*)
printf "Invalid option. Please try again.\n"
;;
esac
done
}

# Run main menu
main_menu
