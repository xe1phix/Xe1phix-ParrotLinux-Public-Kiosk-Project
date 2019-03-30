

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
blacklist btusb                 ## Generic Bluetooth USB driver ver 0.8
remove btusb
## -------------------------------------------------------------------------------------------------------------------------------- ##
echo "options disable_scofix $Bool" >> /etc/modprobe.d/btusb.conf           ## Disable fixup of wrong SCO buffer size (bool)
echo "options force_scofix $Bool" >> /etc/modprobe.d/btusb.conf             ## Force fixup of wrong SCO buffers size (bool)
echo "options enable_autosuspend $Bool" >> /etc/modprobe.d/btusb.conf       ## Enable USB autosuspend by default (bool)
echo "options reset $Bool" >> /etc/modprobe.d/btusb.conf                    ## Send HCI reset command on initialization (bool)
## -------------------------------------------------------------------------------------------------------------------------------- ##
##-========================================================================================-##
## ---------------------------------------------------------------------------------------- ##
blacklist btsdio                    ## Generic Bluetooth SDIO driver ver 0.1
remove btsdio
## ---------------------------------------------------------------------------------------- ##
blacklist btintel                   ## Bluetooth support for Intel devices ver 0.1
remove btintel
## ---------------------------------------------------------------------------------------- ##
blacklist btrtl                     ## Bluetooth support for Realtek devices ver 0.1
remove btrtl
## ---------------------------------------------------------------------------------------- ##
blacklist bt3c_cs                   ## Bluetooth driver for the 3Com Bluetooth PCMCIA card
remove bt3c_cs
## ---------------------------------------------------------------------------------------- ##
blacklist btmrvl                    ## Marvell Bluetooth driver ver 1.0
remove btmrvl
## ---------------------------------------------------------------------------------------- ##
blacklist btmrvl_sdio               ## Marvell BT-over-SDIO driver ver 1.0  -  depends: mmc_core,btmrvl,bluetooth
remove btmrvl_sdio
## ---------------------------------------------------------------------------------------- ##
blacklist btqca                     ## Bluetooth support for Qualcomm Atheros family ver 0.1
remove btqca
## ---------------------------------------------------------------------------------------- ##
blacklist btbcm                     ## Bluetooth support for Broadcom devices ver 0.1
remove btbcm
alias net-pf-31 off
## ---------------------------------------------------------------------------------------- ##
blacklist bluetooth_6lowpan         ## Bluetooth 6LoWPAN
remove bluetooth_6lowpan
## ---------------------------------------------------------------------------------------- ##
blacklist rfcomm                    ## Bluetooth RFCOMM ver 1.11
remove rfcomm
options disable_cfc 1               ## Disable credit based flow control
## ---------------------------------------------------------------------------------------- ##
## blacklist btcoexist              ## Realtek 802.11n PCI wireless core
## remove btcoexist                 ## Bluetooth CoExist? 
## ---------------------------------------------------------------------------------------- ##
blacklist bluecard_cs               ## Bluetooth driver for the Anycom BlueCard (LSE039/LSE041)
remove bluecard_cs
## ---------------------------------------------------------------------------------------- ##
blacklist appletalk                 ## AppleTalk 0.20
remove appletalk
alias net-pf-5 off
## ---------------------------------------------------------------------------------------- ##
blacklist hfs                       ## Apple HFS Filesystem
remove hfs
alias fs-hfs off
## ---------------------------------------------------------------------------------------- ##
blacklist hfsplus                   ## Apple HFS+ Filesystem
remove hfsplus
## ---------------------------------------------------------------------------------------- ##
## echo "options ipv6 disable=1" >> /etc/modprobe.d/ipv6.conf
## ---------------------------------------------------------------------------------------- ##
blacklist efi_pstore                    ## EFI variable backend for pstore
remove efi_pstore
options pstore_disable 1
## ---------------------------------------------------------------------------------------- ##
blacklist efivarfs                      ## EFI Variable Filesystem
remove efivarfs
alias fs-efivarfs off
## ---------------------------------------------------------------------------------------- ##
blacklist efivars                       ## sysfs interface to EFI Variables
remove efivars
alias net-pf-31 off
## ---------------------------------------------------------------------------------------- ##
## /lib/modules/4.16.0-parrot5-amd64/kernel/net/appletalk/appletalk.ko
blacklist appletalk                     ## AppleTalk 0.20
remove appletalk
alias net-pf-5 off
## ---------------------------------------------------------------------------------------- ##
## /lib/modules/4.16.0-parrot5-amd64/kernel/drivers/input/mouse/appletouch.ko
blacklist appletouch                    ## Apple PowerBook and MacBook USB touchpad driver
remove appletouch
## ---------------------------------------------------------------------------------------- ##
blacklist thunderbolt                   ## Thunderbolt
remove thunderbolt
## ---------------------------------------------------------------------------------------- ##
blacklist thunderbolt_net               ## Thunderbolt network driver
remove thunderbolt_net
## ---------------------------------------------------------------------------------------- ##
blacklist ipheth                       ## Apple iPhone USB Ethernet driver
remove ipheth
## ---------------------------------------------------------------------------------------- ##
blacklist applesmc                      ## Apple SMC
remove applesmc
## ---------------------------------------------------------------------------------------- ##
blacklist appledisplay                  ## Apple Cinema Display driver
remove appledisplay
## ---------------------------------------------------------------------------------------- ##
blacklist apple_bl                      ## Apple Backlight Driver
remove apple_bl
alias mbp_nvidia_bl off
## ---------------------------------------------------------------------------------------- ##
blacklist apple_gmux                    ## Apple Gmux Driver
remove apple_gmux
alias char-major-10-157 off
## ---------------------------------------------------------------------------------------- ##
blacklist hid_microsoft                 ## Microsoft Bullshit
remove hid_microsoft
## ---------------------------------------------------------------------------------------- ##
blacklist hid-appleir                   ## HID Apple IR remote controls
remove hid-appleir
## ---------------------------------------------------------------------------------------- ##
blacklist hid-apple                     ## Apple Bullshit
remove hid-apple
## ---------------------------------------------------------------------------------------- ##
blacklist hfsplus                    ## Extended Macintosh Filesystem
remove hfsplus
alias fs-hfsplus off
## ---------------------------------------------------------------------------------------- ##
install rfkill
options master_switch_mode 1
options default_state 0
## ---------------------------------------------------------------------------------------- ##
## acer_wmi                         ## Acer Laptop WMI Extras Driver
options acer_wmi threeg 0           ## Set initial state of 3G hardware
## ---------------------------------------------------------------------------------------- ##
blacklist stkwebcam                 ## Syntek DC1125 webcam driver
remove stkwebcam
## ---------------------------------------------------------------------------------------- ##
## dell_laptop                      ## Dell laptop driver
options force_rfkill true
## ---------------------------------------------------------------------------------------- ##
blacklist toshiba_bluetooth         ## Toshiba Laptop ACPI Bluetooth Enable Driver
remove toshiba_bluetooth
## ---------------------------------------------------------------------------------------- ##
## dell_laptop                      ## Dell laptop driver
options force_rfkill true
## ---------------------------------------------------------------------------------------- ##
## dell_rbtn                        ## Dell Airplane Mode Switch driver
options auto_remove_rfkill 0
## ---------------------------------------------------------------------------------------- ##
## asus_laptop                      ## Asus Laptop Support
options wlan_status 0               ## Set the wlan_status on boot (|0| disabled |1| enabled, |-1| dont do anything).
options bluetooth_status 0          ## Set the Bluetooth status on boot (|0| disabled |1| enabled, |-1| dont do anything).
options wimax_status 0              ## Set the wimax status on boot (|0| disabled |1| enabled, |-1| dont do anything).
options wwan_status 0               ## Set the wwan status on boot (|0| disabled |1| enabled, |-1| dont do anything).
options als_status 0                ## Set the ALS status on boot (|0| disabled |1| enabled, default is 0 (int) )
## ---------------------------------------------------------------------------------------- ##
blacklist hci_vhci          ## Bluetooth virtual HCI driver ver 1.5
remove hci_vhci
## options amp              ## Create AMP controller device (bool)
## ---------------------------------------------------------------------------------------- ##
blacklist hci_uart          ## Bluetooth HCI UART driver ver 2.3
remove hci_uart
## options txcrc            ## Transmit CRC with every BCSP packet (bool)
## options hciextn          ## Convert HCI Extensions into BCSP packets (bool)
## ---------------------------------------------------------------------------------------- ##
blacklist btusb                 ## Generic Bluetooth USB driver ver 0.8
remove btusb
## options disable_scofix          ## Disable fixup of wrong SCO buffer size (bool)
## options force_scofix            ## Force fixup of wrong SCO buffers size (bool)
## options enable_autosuspend      ## Enable USB autosuspend by default (bool)
## options reset                   ## Send HCI reset command on initialization (bool)
## ---------------------------------------------------------------------------------------- ##
echo "install xt_sysrq" >> /etc/modprobe.d/xt_sysrq.conf
echo "options xt_sysrq password=cookies" >> /etc/modprobe.d/xt_sysrq.conf
echo "options xt_sysrq hash=sha256" >> /etc/modprobe.d/xt_sysrq.conf
## ---------------------------------------------------------------------------------------- ##
##-========================================================================================-##
## -------------------------------------------------------------------------------------------------------------------------------- ##
echo "options usbfs_memory_mb $MB" >> /etc/modprobe.d/usbcore.conf      ## maximum MB allowed for usbfs buffers (0 = no limit)
## -------------------------------------------------------------------------------------------------------------------------------- ##
echo "options nousb false" >> /etc/modprobe.d/usbcore.conf
echo "options usbfs_snoop false" >> /etc/modprobe.d/usbcore.conf        ##  true to log all usbfs traffic
echo "options authorized_default 1" >> /etc/modprobe.d/usbcore.conf     ##  Default USB device authorization: 
##                                                                      ##  0 is not authorized, 1 is authorized, 
##                                                                      ## -1 is authorized except for wireless USB (default,
## -------------------------------------------------------------------------------------------------------------------------------- ##
## option authorized_default 0         ## Not Authorized
## option authorized_default 1         ## Authorized
## option authorized_default -1        ## Authorized except for wireless USB
## ---------------------------------------------------------------------------------------- ##
##-========================================================================================-##
## ---------------------------------------------------------------------------------------- ##
install cdrom
option debug 1
option check_media_type 1
option autoeject 0
option autoclose 0
option lockdoor 1
## option mrw_format_restart 1
## ---------------------------------------------------------------------------------------- ##
## install dvb_usb
## blacklist dvb_usb
## remove dvb_usb
option debug 1                          ## set debugging level (1=info,xfer=2,pll=4,ts=8,err=16,rc=32,fw=64,mem=128,uxfer=256
option disable_rc_polling 1             ## disable remote control polling
## option force_pid_filter_usage 1      ## force all dvb-usb-devices to use a PID filter
## ---------------------------------------------------------------------------------------- ##
##-========================================================================================-##
## ---------------------------------------------------------------------------------------- ##
## scsi_mod                    ## SCSI core
## install scsi_mod
echo "options scsi_logging_level 7" >> /etc/modprobe.d/scsi_mod.conf
## ---------------------------------------------------------------------------------------- ##
##-========================================================================================-##
## ---------------------------------------------------------------------------------------- ##
echo "install nf_conntrack" >> /etc/modprobe.d/nf_conntrack.conf
echo "options tstamp true" >> /etc/modprobe.d/nf_conntrack.conf
echo "options acct true" >> /etc/modprobe.d/nf_conntrack.conf
echo "options nf_conntrack_helper true" >> /etc/modprobe.d/nf_conntrack.conf
echo "options expect_hashsize sha256" >> /etc/modprobe.d/nf_conntrack.conf
## ---------------------------------------------------------------------------------------- ##
##-========================================================================================-##
## ---------------------------------------------------------------------------------------- ##
install tun                             ## Universal TUN/TAP device drivers
install tap
## ---------------------------------------------------------------------------------------- ##
install cfg80211
alias net-pf-16-proto-16-family-nl80211
options ieee80211_regdom US             ## IEEE 802.11 regulatory domain code (charp)
## ---------------------------------------------------------------------------------------- ##
blacklist ip_gre                        ## GRE over IPv4 tunneling device
remove ip_gre
alias netdev-erspan0
alias netdev-gretap0
alias netdev-gre0
alias rtnl-link-erspan
alias rtnl-link-gretap
alias rtnl-link-gre
## ---------------------------------------------------------------------------------------- ##
blacklist ip6_gre                       ## GRE over IPv6 tunneling device
remove ip6_gre
alias netdev-ip6gre0
## alias rtnl-link-ip6erspan
## alias rtnl-link-ip6gretap
## alias rtnl-link-ip6gre
## options log_ecn_error true          ## Log packets received with corrupted ECN 
## ---------------------------------------------------------------------------------------- ##
##-========================================================================================-##
## ---------------------------------------------------------------------------------------- ##
## blacklist 
## remove 
## ---------------------------------------------------------------------------------------- ##
## blacklist 
## remove 
## ---------------------------------------------------------------------------------------- ##
