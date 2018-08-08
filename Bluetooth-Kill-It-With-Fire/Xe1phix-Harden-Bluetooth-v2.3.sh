#!/bin/sh
#
## Xe1phix-Harden-Bluetooth-v2.3.sh
#

GRUB_CMDLINE_LINUX="bluetooth.blacklist=yes"



gsettings set org.blueman.plugins.powermanager auto-power-on false
echo disable > /proc/acpi/ibm/bluetooth

echo "blacklist btusb" > /etc/modprobe.d/blacklist.conf
echo "blacklist bluetooth" > /etc/modprobe.d/blacklist.conf



disable blueman-applet on start

sudo sed -i 's/NoDisplay=true/NoDisplay=false/g' /etc/xdg/autostart/blueman.desktop
gnome-session-properties

cd /etc/xdg/autostart/

sudo sed --in-place 's/NoDisplay=true/NoDisplay=false/g' *.desktop

sudo sh -c "echo 'manual' > /etc/init/bluetooth.override"

sudo service bluetooth stop
sudo systemctl disable bluetooth
update-rc.d bluetooth remove
/etc/init.d/bluetooth stop
rfkill block bluetooth
chkconfig bluetooth off
systemctl disable bluetooth.service

/etc/bluetooth/main.conf
AutoEnable=false
InitiallyPowered = false
BLUETOOTH_ENABLED=0

/etc/default/bluetooth
BLUETOOTH_ENABLED=0



