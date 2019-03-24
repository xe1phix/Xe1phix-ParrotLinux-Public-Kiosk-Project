

## ---------------------------------------------------------------------------------------- ##
echo "alias net‐pf‐31 off" >> /etc/modprobe.d/modprobe.conf
echo "install bluetooth /bin/false" >> /etc/modprobe.d/usgcb-blacklist.conf
alias net-pf-31 bluetooth
blacklist bluetooth
remove bluetooth
modprobe -v -r bluetooth
rmmod bluetooth
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


## ---------------------------------------------------------------------------------------- ##
## /lib/modules/4.16.0-parrot5-amd64/kernel/net/appletalk/appletalk.ko
alias net-pf-5                  ## AppleTalk 0.20
blacklist appletalk
remove appletalk
## ---------------------------------------------------------------------------------------- ##
blacklist hfs
remove hfs
## ---------------------------------------------------------------------------------------- ##
blacklist hfsplus
remove hfsplus
## ---------------------------------------------------------------------------------------- ##
echo -e "options ipv6 disable=1" >> /etc/modprobe.d/usgcb-blacklist.conf
## ---------------------------------------------------------------------------------------- ##
blacklist efi_pstore
remove efi_pstore
options pstore_disable 1
## ---------------------------------------------------------------------------------------- ##
blacklist efivarfs
remove efivarfs
alias fs-efivarfs off
## ---------------------------------------------------------------------------------------- ##
blacklist efivars
remove efivars
alias net-pf-31 off
## ---------------------------------------------------------------------------------------- ##
## /lib/modules/4.16.0-parrot5-amd64/kernel/net/appletalk/appletalk.ko
blacklist appletalk                   ## AppleTalk 0.20
remove appletalk
alias net-pf-5 off
## ---------------------------------------------------------------------------------------- ##
## /lib/modules/4.16.0-parrot5-amd64/kernel/drivers/input/mouse/appletouch.ko
blacklist appletouch                  ## Apple PowerBook and MacBook USB touchpad driver
remove appletouch
## ---------------------------------------------------------------------------------------- ##
blacklist thunderbolt         ## thunderbolt
remove thunderbolt
## ---------------------------------------------------------------------------------------- ##
blacklist thunderbolt_net             ## Thunderbolt network driver
remove thunderbolt_net
## ---------------------------------------------------------------------------------------- ##
## /lib/modules/4.16.0-parrot5-amd64/kernel/drivers/hwmon/applesmc.ko
blacklist applesmc                ## Apple SMC
remove applesmc
## ---------------------------------------------------------------------------------------- ##
## /lib/modules/4.16.0-parrot5-amd64/kernel/drivers/usb/misc/appledisplay.ko
blacklist appledisplay            ## Apple Cinema Display driver
remove appledisplay
## ---------------------------------------------------------------------------------------- ##
## /lib/modules/4.16.0-parrot5-amd64/kernel/drivers/video/backlight/apple_bl.ko
alias mbp_nvidia_bl off
blacklist apple_bl                ## Apple Backlight Driver
remove apple_bl 
## ---------------------------------------------------------------------------------------- ##
blacklist apple_gmux              ## Apple Gmux Driver
alias char-major-10-157 off 
remove apple_gmux
## ---------------------------------------------------------------------------------------- ##
blacklist hid_microsoft
remove hid_microsoft
## ---------------------------------------------------------------------------------------- ##
blacklist hid_apple
remove hid_apple
## ---------------------------------------------------------------------------------------- ##
blacklist hid_appleir                 ## HID Apple IR remote controls
remove hid_appleir
## ---------------------------------------------------------------------------------------- ##
blacklist hfs                         ## 
remove hfs
alias fs-hfs off
## ---------------------------------------------------------------------------------------- ##
blacklist hfsplus                    ## Extended Macintosh Filesystem
remove hfsplus
alias fs-hfsplus off
## ---------------------------------------------------------------------------------------- ##
install rfkill
options master_switch_mode 1
options default_state 0
## ---------------------------------------------------------------------------------------- ##
















