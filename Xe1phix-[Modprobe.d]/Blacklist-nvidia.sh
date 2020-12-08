#!/bin/sh
##-============================-##
##   [+] Blacklist-nvidia.sh
##-============================-##
echo "blacklist nvidia" >> /etc/modprobe.d/Blacklist-nvidia.conf
echo "blacklist nvidia_drm" >> /etc/modprobe.d/Blacklist-nvidia.conf
echo "blacklist nvidia_modeset" >> /etc/modprobe.d/Blacklist-nvidia.conf
echo "remove nvidia" >> /etc/modprobe.d/Blacklist-nvidia.conf
modprobe -vr nvidia-drm nvidia-modeset nvidia-uvm nvidia
rmmod nvidia
