#!/bin/sh
#
## Xe1phix-Harden-Bluetooth-v2.3.sh
#

GRUB_CMDLINE_LINUX="bluetooth.blacklist=yes"

/usr/sbin/bluetoothd
/usr/bin/hciattach
/etc/default/bluetooth

# Prevent Bluetooth autoload 
echo "alias net‐pf‐31 off" >> /etc/modprobe.d/modprobe.conf
echo "install bluetooth /bin/false" >> /etc/modprobe.d/usgcb-blacklist.conf
echo "install net-pf-31 /bin/false" >> /etc/modprobe.d/usgcb-blacklist.conf

gsettings set org.blueman.plugins.powermanager auto-power-on false

echo "disable" > /proc/acpi/ibm/bluetooth

echo "blacklist btusb" > /etc/modprobe.d/blacklist.conf
echo "blacklist bluetooth" > /etc/modprobe.d/blacklist.conf





## ---------------------------------------------------------------------------------------- ##
alias net-pf-31 off
blacklist bluetooth
remove bluetooth

options disable_esco=1       ## disable_esco:Disable eSCO connection creation (bool)
options disable_ertm=1       ## disable_ertm:Disable enhanced retransmission mode (bool)
## ---------------------------------------------------------------------------------------- ##
blacklist btusb
remove btusb
## ---------------------------------------------------------------------------------------- ##
blacklist btsdio                  ## Generic Bluetooth SDIO driver ver 0.1
remove btsdio                  ## Generic Bluetooth SDIO driver ver 0.1
## ---------------------------------------------------------------------------------------- ##
blacklist btintel                 ## Bluetooth support for Intel devices ver 0.1
remove btintel                 ## Bluetooth support for Intel devices ver 0.1
## ---------------------------------------------------------------------------------------- ##
blacklist btrtl                   ## Bluetooth support for Realtek devices ver 0.1
remove btrtl                   ## Bluetooth support for Realtek devices ver 0.1
## ---------------------------------------------------------------------------------------- ##
blacklist bt3c_cs                 ## Bluetooth driver for the 3Com Bluetooth PCMCIA card
remove bt3c_cs                 ## Bluetooth driver for the 3Com Bluetooth PCMCIA card
## ---------------------------------------------------------------------------------------- ##
blacklist btmrvl                  ## description:    Marvell Bluetooth driver ver 1.0
remove btmrvl                  ## description:    Marvell Bluetooth driver ver 1.0
## ---------------------------------------------------------------------------------------- ##
blacklist btqca                   ## Bluetooth support for Qualcomm Atheros family ver 0.1
remove btqca                   ## Bluetooth support for Qualcomm Atheros family ver 0.1
## ---------------------------------------------------------------------------------------- ##
alias net-pf-31 off
blacklist btbcm                   ## Bluetooth support for Broadcom devices ver 0.1
remove btbcm
## ---------------------------------------------------------------------------------------- ##
blacklist bluetooth_6lowpan                   ## Bluetooth 6LoWPAN
remove bluetooth_6lowpan
## ---------------------------------------------------------------------------------------- ##
blacklist rfcomm               ## Bluetooth RFCOMM ver 1.11
remove rfcomm
options disable_cfc 1          ## :Disable credit based flow control
## ---------------------------------------------------------------------------------------- ##




/etc/default/bluetooth

disable blueman-applet on start

sudo sed -i 's/NoDisplay=true/NoDisplay=false/g' /etc/xdg/autostart/blueman.desktop-gnome-session-properties
sudo sh -c "echo 'manual' > /etc/init/bluetooth.override"

sudo service bluetooth stop
sudo service bluetooth disable
sudo systemctl disable bluetooth
update-rc.d bluetooth stop
update-rc.d bluetooth disable
update-rc.d bluetooth remove
/etc/init.d/bluetooth stop
/etc/init.d/bluetooth disable
rfkill block bluetooth
chkconfig bluetooth off
systemctl status bluetooth.service
systemctl stop bluetooth.service
systemctl is-active bluetooth.service
systemctl disable bluetooth.service
systemctl kill bluetooth.service
killall -e bluetoothd


/etc/bluetooth/main.conf
AutoEnable=false
InitiallyPowered = false
BLUETOOTH_ENABLED=0

/etc/default/bluetooth
BLUETOOTH_ENABLED=0



