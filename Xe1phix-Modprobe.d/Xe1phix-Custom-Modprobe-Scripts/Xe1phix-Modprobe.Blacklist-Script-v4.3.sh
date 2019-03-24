#!/bin/sh
##-=============================-##
##   Xe1phix-Blacklist-v4.3.sh
##-=============================-##
## ------------------------------------------------------------------ ##
##  [?] This Script will create a modprobe config to block:
##      --> Bluetooth Drivers
##      --> EFI Drivers
##      --> Apple Drivers
##      --> IPv6 Drivers
## ------------------------------------------------------------------ ##
echo "## ---------------------------------------------------------------------------------------- ##" >> /etc/modprobe.d/Xe1phix-Blacklist.conf
echo "alias net‐pf‐31 off" >> /etc/modprobe.d/Xe1phix-Blacklist.conf
echo "install bluetooth /bin/false" >> /etc/modprobe.d/Xe1phix-Blacklist.conf
echo "blacklist bluetooth" >> /etc/modprobe.d/Xe1phix-Blacklist.conf
echo "remove bluetooth" >> /etc/modprobe.d/Xe1phix-Blacklist.conf
echo "## ---------------------------------------------------------------------------------------- ##" >> /etc/modprobe.d/Xe1phix-Blacklist.conf
echo "alias net-pf-31 off" >> /etc/modprobe.d/Xe1phix-Blacklist.conf
echo "blacklist bluetooth" >> /etc/modprobe.d/Xe1phix-Blacklist.conf
echo "remove bluetooth" >> /etc/modprobe.d/Xe1phix-Blacklist.conf
echo -e "\n" >> /etc/modprobe.d/Xe1phix-Blacklist.conf
echo "options disable_esco=1       ## disable_esco:Disable eSCO connection creation (bool)" >> /etc/modprobe.d/Xe1phix-Blacklist.conf
echo "options disable_ertm=1       ## disable_ertm:Disable enhanced retransmission mode (bool)" >> /etc/modprobe.d/Xe1phix-Blacklist.conf
echo "## ---------------------------------------------------------------------------------------- ##" >> /etc/modprobe.d/Xe1phix-Blacklist.conf
echo "blacklist btusb" >> /etc/modprobe.d/Xe1phix-Blacklist.conf
echo "remove btusb" >> /etc/modprobe.d/Xe1phix-Blacklist.conf
echo "## ---------------------------------------------------------------------------------------- ##" >> /etc/modprobe.d/Xe1phix-Blacklist.conf
echo "blacklist btsdio                  ## Generic Bluetooth SDIO driver ver 0.1" >> /etc/modprobe.d/Xe1phix-Blacklist.conf
echo "remove btsdio                  ## Generic Bluetooth SDIO driver ver 0.1" >> /etc/modprobe.d/Xe1phix-Blacklist.conf
echo "## ---------------------------------------------------------------------------------------- ##" >> /etc/modprobe.d/Xe1phix-Blacklist.conf
echo "blacklist btintel                 ## Bluetooth support for Intel devices ver 0.1" >> /etc/modprobe.d/Xe1phix-Blacklist.conf
echo "remove btintel                 ## Bluetooth support for Intel devices ver 0.1" >> /etc/modprobe.d/Xe1phix-Blacklist.conf
echo "## ---------------------------------------------------------------------------------------- ##" >> /etc/modprobe.d/Xe1phix-Blacklist.conf
echo "blacklist btrtl                   ## Bluetooth support for Realtek devices ver 0.1" >> /etc/modprobe.d/Xe1phix-Blacklist.conf
echo "remove btrtl                   ## Bluetooth support for Realtek devices ver 0.1" >> /etc/modprobe.d/Xe1phix-Blacklist.conf
echo "## ---------------------------------------------------------------------------------------- ##" >> /etc/modprobe.d/Xe1phix-Blacklist.conf
echo "blacklist bt3c_cs                 ## Bluetooth driver for the 3Com Bluetooth PCMCIA card" >> /etc/modprobe.d/Xe1phix-Blacklist.conf
echo "remove bt3c_cs                 ## Bluetooth driver for the 3Com Bluetooth PCMCIA card" >> /etc/modprobe.d/Xe1phix-Blacklist.conf
echo "## ---------------------------------------------------------------------------------------- ##" >> /etc/modprobe.d/Xe1phix-Blacklist.conf
echo "blacklist btmrvl                  ## description:    Marvell Bluetooth driver ver 1.0" >> /etc/modprobe.d/Xe1phix-Blacklist.conf
echo "remove btmrvl                  ## description:    Marvell Bluetooth driver ver 1.0" >> /etc/modprobe.d/Xe1phix-Blacklist.conf
echo "## ---------------------------------------------------------------------------------------- ##" >> /etc/modprobe.d/Xe1phix-Blacklist.conf
echo "blacklist btqca                   ## Bluetooth support for Qualcomm Atheros family ver 0.1" >> /etc/modprobe.d/Xe1phix-Blacklist.conf
echo "remove btqca                   ## Bluetooth support for Qualcomm Atheros family ver 0.1" >> /etc/modprobe.d/Xe1phix-Blacklist.conf
echo "## ---------------------------------------------------------------------------------------- ##" >> /etc/modprobe.d/Xe1phix-Blacklist.conf
echo "alias net-pf-31 off" >> /etc/modprobe.d/Xe1phix-Blacklist.conf
echo "blacklist btbcm                   ## Bluetooth support for Broadcom devices ver 0.1" >> /etc/modprobe.d/Xe1phix-Blacklist.conf
echo "remove btbcm" >> /etc/modprobe.d/Xe1phix-Blacklist.conf
echo "## ---------------------------------------------------------------------------------------- ##" >> /etc/modprobe.d/Xe1phix-Blacklist.conf
echo "blacklist bluetooth_6lowpan                   ## Bluetooth 6LoWPAN" >> /etc/modprobe.d/Xe1phix-Blacklist.conf
echo "remove bluetooth_6lowpan" >> /etc/modprobe.d/Xe1phix-Blacklist.conf
echo "## ---------------------------------------------------------------------------------------- ##" >> /etc/modprobe.d/Xe1phix-Blacklist.conf
echo "blacklist rfcomm               ## Bluetooth RFCOMM ver 1.11" >> /etc/modprobe.d/Xe1phix-Blacklist.conf
echo "remove rfcomm" >> /etc/modprobe.d/Xe1phix-Blacklist.conf
echo "options disable_cfc 1          ## :Disable credit based flow control" >> /etc/modprobe.d/Xe1phix-Blacklist.conf
echo "## ---------------------------------------------------------------------------------------- ##" >> /etc/modprobe.d/Xe1phix-Blacklist.conf
echo "blacklist appletalk" >> /etc/modprobe.d/Xe1phix-Blacklist.conf
echo "remove appletalk" >> /etc/modprobe.d/Xe1phix-Blacklist.conf
echo "## ---------------------------------------------------------------------------------------- ##" >> /etc/modprobe.d/Xe1phix-Blacklist.conf
echo "blacklist hfs" >> /etc/modprobe.d/Xe1phix-Blacklist.conf
echo "remove hfs" >> /etc/modprobe.d/Xe1phix-Blacklist.conf
echo "## ---------------------------------------------------------------------------------------- ##" >> /etc/modprobe.d/Xe1phix-Blacklist.conf
echo "blacklist hfsplus" >> /etc/modprobe.d/Xe1phix-Blacklist.conf
echo "remove hfsplus" >> /etc/modprobe.d/Xe1phix-Blacklist.conf
echo "## ---------------------------------------------------------------------------------------- ##" >> /etc/modprobe.d/Xe1phix-Blacklist.conf
echo "blacklist ipv6" >> /etc/modprobe.d/Xe1phix-Blacklist.conf
echo "remove ipv6" >> /etc/modprobe.d/Xe1phix-Blacklist.conf
echo "alias net-pf-10 off" >> /etc/modprobe.d/Xe1phix-Blacklist.conf
echo "options ipv6 disable=1" >> /etc/modprobe.d/Xe1phix-Blacklist.conf
echo "## ---------------------------------------------------------------------------------------- ##" >> /etc/modprobe.d/Xe1phix-Blacklist.conf
echo "blacklist efi_pstore" >> /etc/modprobe.d/Xe1phix-Blacklist.conf
echo "remove efi_pstore" >> /etc/modprobe.d/Xe1phix-Blacklist.conf
echo "options pstore_disable 1" >> /etc/modprobe.d/Xe1phix-Blacklist.conf
echo "## ---------------------------------------------------------------------------------------- ##" >> /etc/modprobe.d/Xe1phix-Blacklist.conf
echo "blacklist efivarfs" >> /etc/modprobe.d/Xe1phix-Blacklist.conf
echo "remove efivarfs" >> /etc/modprobe.d/Xe1phix-Blacklist.conf
echo "alias fs-efivarfs off" >> /etc/modprobe.d/Xe1phix-Blacklist.conf
echo "## ---------------------------------------------------------------------------------------- ##" >> /etc/modprobe.d/Xe1phix-Blacklist.conf
echo "blacklist efivars" >> /etc/modprobe.d/Xe1phix-Blacklist.conf
echo "remove efivars" >> /etc/modprobe.d/Xe1phix-Blacklist.conf
echo "alias net-pf-31 off" >> /etc/modprobe.d/Xe1phix-Blacklist.conf
echo "## ---------------------------------------------------------------------------------------- ##" >> /etc/modprobe.d/Xe1phix-Blacklist.conf
echo "blacklist appletalk                   ## AppleTalk 0.20" >> /etc/modprobe.d/Xe1phix-Blacklist.conf
echo "remove appletalk" >> /etc/modprobe.d/Xe1phix-Blacklist.conf
echo "alias net-pf-5 off" >> /etc/modprobe.d/Xe1phix-Blacklist.conf
echo "## ---------------------------------------------------------------------------------------- ##" >> /etc/modprobe.d/Xe1phix-Blacklist.conf
echo "blacklist appletouch                  ## Apple PowerBook and MacBook USB touchpad driver" >> /etc/modprobe.d/Xe1phix-Blacklist.conf
echo "remove appletouch" >> /etc/modprobe.d/Xe1phix-Blacklist.conf
echo "## ---------------------------------------------------------------------------------------- ##" >> /etc/modprobe.d/Xe1phix-Blacklist.conf
echo "blacklist thunderbolt         ## thunderbolt" >> /etc/modprobe.d/Xe1phix-Blacklist.conf
echo "remove thunderbolt" >> /etc/modprobe.d/Xe1phix-Blacklist.conf
echo "## ---------------------------------------------------------------------------------------- ##" >> /etc/modprobe.d/Xe1phix-Blacklist.conf
echo "blacklist thunderbolt_net             ## Thunderbolt network driver" >> /etc/modprobe.d/Xe1phix-Blacklist.conf
echo "remove thunderbolt_net" >> /etc/modprobe.d/Xe1phix-Blacklist.conf
echo "## ---------------------------------------------------------------------------------------- ##" >> /etc/modprobe.d/Xe1phix-Blacklist.conf
echo "blacklist applesmc                ## Apple SMC" >> /etc/modprobe.d/Xe1phix-Blacklist.conf
echo "remove applesmc" >> /etc/modprobe.d/Xe1phix-Blacklist.conf
echo "## ---------------------------------------------------------------------------------------- ##" >> /etc/modprobe.d/Xe1phix-Blacklist.conf
echo "blacklist appledisplay            ## Apple Cinema Display driver" >> /etc/modprobe.d/Xe1phix-Blacklist.conf
echo "remove appledisplay" >> /etc/modprobe.d/Xe1phix-Blacklist.conf
echo "## ---------------------------------------------------------------------------------------- ##" >> /etc/modprobe.d/Xe1phix-Blacklist.conf
echo "alias mbp_nvidia_bl off" >> /etc/modprobe.d/Xe1phix-Blacklist.conf
echo "blacklist apple_bl                ## Apple Backlight Driver" >> /etc/modprobe.d/Xe1phix-Blacklist.conf
echo "remove apple_bl " >> /etc/modprobe.d/Xe1phix-Blacklist.conf
echo "## ---------------------------------------------------------------------------------------- ##" >> /etc/modprobe.d/Xe1phix-Blacklist.conf
echo "blacklist apple_gmux              ## Apple Gmux Driver" >> /etc/modprobe.d/Xe1phix-Blacklist.conf
echo "alias char-major-10-157 off " >> /etc/modprobe.d/Xe1phix-Blacklist.conf
echo "remove apple_gmux" >> /etc/modprobe.d/Xe1phix-Blacklist.conf
echo "## ---------------------------------------------------------------------------------------- ##" >> /etc/modprobe.d/Xe1phix-Blacklist.conf
echo "blacklist hid_microsoft" >> /etc/modprobe.d/Xe1phix-Blacklist.conf
echo "remove hid_microsoft" >> /etc/modprobe.d/Xe1phix-Blacklist.conf
echo "## ---------------------------------------------------------------------------------------- ##" >> /etc/modprobe.d/Xe1phix-Blacklist.conf
echo "blacklist hid_apple" >> /etc/modprobe.d/Xe1phix-Blacklist.conf
echo "remove hid_apple" >> /etc/modprobe.d/Xe1phix-Blacklist.conf
echo "## ---------------------------------------------------------------------------------------- ##" >> /etc/modprobe.d/Xe1phix-Blacklist.conf
echo "blacklist hid_appleir                 ## HID Apple IR remote controls" >> /etc/modprobe.d/Xe1phix-Blacklist.conf
echo "remove hid_appleir" >> /etc/modprobe.d/Xe1phix-Blacklist.conf
echo "## ---------------------------------------------------------------------------------------- ##" >> /etc/modprobe.d/Xe1phix-Blacklist.conf
echo "blacklist hfs                         ## " >> /etc/modprobe.d/Xe1phix-Blacklist.conf
echo "remove hfs" >> /etc/modprobe.d/Xe1phix-Blacklist.conf
echo "alias fs-hfs off" >> /etc/modprobe.d/Xe1phix-Blacklist.conf
echo "## ---------------------------------------------------------------------------------------- ##" >> /etc/modprobe.d/Xe1phix-Blacklist.conf
echo "blacklist hfsplus                    ## Extended Macintosh Filesystem" >> /etc/modprobe.d/Xe1phix-Blacklist.conf
echo "remove hfsplus" >> /etc/modprobe.d/Xe1phix-Blacklist.conf
echo "alias fs-hfsplus off" >> /etc/modprobe.d/Xe1phix-Blacklist.conf
echo "## ---------------------------------------------------------------------------------------- ##" >> /etc/modprobe.d/Xe1phix-Blacklist.conf
echo "install rfkill" >> /etc/modprobe.d/Xe1phix-Blacklist.conf
echo "options master_switch_mode 1" >> /etc/modprobe.d/Xe1phix-Blacklist.conf
echo "options default_state 0" >> /etc/modprobe.d/Xe1phix-Blacklist.conf
echo "## ---------------------------------------------------------------------------------------- ##" >> /etc/modprobe.d/Xe1phix-Blacklist.conf
