## mkinitramfs -k -o ~/tmp/initramfs-2.6.21-686 2.6.21-686
## lsinitramfs -l 
##-==================================================================-##
##   [?] Pass options to the module using the kernel command line
##-==================================================================-##
## module_name.parameter_name=parameter_value
## thinkpad_acpi.fan_control=1
## 
## ---------------------------------------------------------------------------------------- ##
## echo "blacklist bluetooth" >> /etc/modprobe.d/Blacklist-Bluetooth.conf
## echo "remove bluetooth" >> /etc/modprobe.d/Blacklist-Bluetooth.conf
## echo "alias net-pf-31 bluetooth" >> /etc/modprobe.d/Blacklist-Bluetooth.conf
## echo "alias net‐pf‐31 off" >> /etc/modprobe.d/Blacklist-Bluetooth.conf
## echo "install bluetooth /bin/false" >> /etc/modprobe.d/Blacklist-Bluetooth.conf
modprobe -v -r bluetooth
rmmod bluetooth
## ---------------------------------------------------------------------------------------- ##
##-========================================================================================-##
blacklist bluetooth          ## Bluetooth Core ver 2.22
remove bluetooth
alias net-pf-31 off
##-========================================================================================-##
## ---------------------------------------------------------------------------------------- ##
options disable_esco=1       ## disable_esco:Disable eSCO connection creation (bool)
options disable_ertm=1       ## disable_ertm:Disable enhanced retransmission mode (bool)
## ---------------------------------------------------------------------------------------- ##
## 
##-================================================================================================================================-##
blacklist btusb             ## Generic Bluetooth USB driver ver 0.8
remove btusb
##-================================================================================================================================-##
## -------------------------------------------------------------------------------------------------------------------------------- ##
## options disable_scofix			    ## Disable fixup of wrong SCO buffer size (bool)
## options force_scofix			        ## Force fixup of wrong SCO buffers size (bool)
## options enable_autosuspend			## Enable USB autosuspend by default (bool)
## options reset			            ## Send HCI reset command on initialization (bool)
## -------------------------------------------------------------------------------------------------------------------------------- ##
## echo "options disable_scofix $Bool" >> /etc/modprobe.d/btusb.conf           ## Disable fixup of wrong SCO buffer size (bool)
## echo "options force_scofix $Bool" >> /etc/modprobe.d/btusb.conf             ## Force fixup of wrong SCO buffers size (bool)
## echo "options enable_autosuspend $Bool" >> /etc/modprobe.d/btusb.conf       ## Enable USB autosuspend by default (bool)
## echo "options reset $Bool" >> /etc/modprobe.d/btusb.conf                    ## Send HCI reset command on initialization (bool)
## -------------------------------------------------------------------------------------------------------------------------------- ##
##-================================================================================================================================-##
## 
## 
##-========================================================================================-##
## ------------------------------------------------------------------------------------------------------------------------- ##
blacklist ath3k                         ## Atheros AR30xx firmware driver
remove ath3k                            ## /lib/modules/4.19.0-parrot4-28t-amd64/kernel/drivers/bluetooth/ath3k.ko
## ------------------------------------------------------------------------------------------------------------------------- ##
blacklist btsdio                        ## Generic Bluetooth SDIO driver ver 0.1
remove btsdio                           ## /lib/modules/4.19.0-parrot4-28t-amd64/kernel/drivers/bluetooth/btsdio.ko
## ------------------------------------------------------------------------------------------------------------------------- ##
blacklist btintel                       ## Bluetooth support for Intel devices ver 0.1
remove btintel                          ## /lib/modules/4.19.0-parrot4-28t-amd64/kernel/drivers/bluetooth/btintel.ko
## ------------------------------------------------------------------------------------------------------------------------- ##
blacklist btrtl                         ## Bluetooth support for Realtek devices ver 0.1
remove btrtl                            ## /lib/modules/4.19.0-parrot4-28t-amd64/kernel/drivers/bluetooth/btrtl.ko
## ------------------------------------------------------------------------------------------------------------------------- ##
blacklist bt3c_cs                       ## Bluetooth driver for the 3Com Bluetooth PCMCIA card
remove bt3c_cs                          ## /lib/modules/4.19.0-parrot4-28t-amd64/kernel/drivers/bluetooth/bt3c_cs.ko
## ------------------------------------------------------------------------------------------------------------------------- ##
blacklist btmrvl                        ## Marvell Bluetooth driver ver 1.0
remove btmrvl                           ## /lib/modules/4.19.0-parrot4-28t-amd64/kernel/drivers/bluetooth/btmrvl.ko
## ------------------------------------------------------------------------------------------------------------------------- ##
blacklist btmrvl_sdio                   ## Marvell BT-over-SDIO driver ver 1.0  -  depends: mmc_core,btmrvl,bluetooth
remove btmrvl_sdio                      ## /lib/modules/4.19.0-parrot4-28t-amd64/kernel/drivers/bluetooth/btmrvl_sdio.ko
## ------------------------------------------------------------------------------------------------------------------------- ##
blacklist btqca                         ## Bluetooth support for Qualcomm Atheros family ver 0.1
remove btqca                            ## /lib/modules/4.19.0-parrot4-28t-amd64/kernel/drivers/bluetooth/btqca.ko
## ------------------------------------------------------------------------------------------------------------------------- ##
blacklist btbcm                         ## Bluetooth support for Broadcom devices ver 0.1
remove btbcm                            ## /lib/modules/4.19.0-parrot4-28t-amd64/kernel/drivers/bluetooth/btbcm.ko
alias net-pf-31 off
## ------------------------------------------------------------------------------------------------------------------------- ##
blacklist bcm203x                       ## Broadcom Blutonium firmware driver ver 1.2
remove bcm203x                          ## /lib/modules/4.19.0-parrot4-28t-amd64/kernel/drivers/bluetooth/bcm203x.ko
## ------------------------------------------------------------------------------------------------------------------------- ##
blacklist bfusb                         ## BlueFRITZ! USB driver ver 1.2
remove bfusb                            ## /lib/modules/4.19.0-parrot4-28t-amd64/kernel/drivers/bluetooth/bfusb.ko
## ------------------------------------------------------------------------------------------------------------------------- ##
blacklist bpa10x                        ## Digianswer Bluetooth USB driver ver 0.11
remove bpa10x                           ## /lib/modules/4.19.0-parrot4-28t-amd64/kernel/drivers/bluetooth/bpa10x.ko
## ------------------------------------------------------------------------------------------------------------------------- ##
blacklist btmtkuart                     ## MediaTek Bluetooth Serial driver ver 0.1
remove btmtkuart                        ## /lib/modules/4.19.0-parrot4-28t-amd64/kernel/drivers/bluetooth/btmtkuart.ko
## ------------------------------------------------------------------------------------------------------------------------- ##
blacklist bluetooth_6lowpan             ## Bluetooth 6LoWPAN
remove bluetooth_6lowpan
## ------------------------------------------------------------------------------------------------------------------------- ##
blacklist btrsi                         ## RSI BT driver
remove btrsi                            ## /lib/modules/4.19.0-parrot4-28t-amd64/kernel/drivers/bluetooth/btrsi.ko
## ------------------------------------------------------------------------------------------------------------------------- ##
blacklist dtl1_cs                       ## Bluetooth driver for Nokia Connectivity Card DTL-1
remove dtl1_cs                          ## /lib/modules/4.19.0-parrot4-28t-amd64/kernel/drivers/bluetooth/dtl1_cs.ko
## ------------------------------------------------------------------------------------------------------------------------- ##
blacklist hci_nokia                     ## Bluetooth HCI UART Nokia H4+ driver ver 0.1
remove hci_nokia                        ## /lib/modules/4.19.0-parrot4-28t-amd64/kernel/drivers/bluetooth/hci_nokia.ko
## ------------------------------------------------------------------------------------------------------------------------- ##
blacklist hci                           ## NFC HCI Core
remove hci                              ## /lib/modules/4.19.0-parrot4-28t-amd64/kernel/net/nfc/hci/hci.ko
## ---------------------------------------------------------------------------------------- ##
blacklist rfcomm                        ## Bluetooth RFCOMM ver 1.11
remove rfcomm                           ## /lib/modules/4.19.0-parrot4-28t-amd64/kernel/net/bluetooth/rfcomm/rfcomm.ko
alias bt-proto-3 off
options disable_cfc 1                   ## Disable credit based flow control
## options channel_mtu                  ## Default MTU for the RFCOMM channel (int)
## options l2cap_mtu                    ## Default MTU for the L2CAP connection (uint)
## options l2cap_ertm                   ## Use L2CAP ERTM mode for connection (bool)
## ------------------------------------------------------------------------------------------------------------------------- ##
## blacklist btcoexist                  ## Realtek 802.11n PCI wireless core
## remove btcoexist                     ## Bluetooth CoExist? 
## ------------------------------------------------------------------------------------------------------------------------- ##
blacklist bluecard_cs                   ## Bluetooth driver for the Anycom BlueCard (LSE039/LSE041)
remove bluecard_cs
## ------------------------------------------------------------------------------------------------------------------------- ##
blacklist hidp                          ## Bluetooth HIDP ver 1.2
remove hidp                             ## /lib/modules/4.19.0-parrot4-28t-amd64/kernel/net/bluetooth/hidp/hidp.ko
alias bt-proto-6 off
## ------------------------------------------------------------------------------------------------------------------------- ##
blacklist cmtp                          ## Bluetooth CMTP ver 1.0
remove cmtp                             ## /lib/modules/4.19.0-parrot4-28t-amd64/kernel/net/bluetooth/cmtp/cmtp.ko
alias bt-proto-5 off
## ------------------------------------------------------------------------------------------------------------------------- ##
blacklist nfc                               ## NFC Core ver 0.1
remove nfc                                  ## /lib/modules/4.19.0-parrot4-28t-amd64/kernel/net/nfc/nfc.ko
alias net-pf-39 off
## ------------------------------------------------------------------------------------------------------------------------- ##
blacklist hci                               ## NFC HCI Core
remove hci                                  ## /lib/modules/4.19.0-parrot4-28t-amd64/kernel/net/nfc/hci/hci.ko
## ------------------------------------------------------------------------------------------------------------------------- ##
blacklist nfc_digital
remove nfc_digital                          ## /lib/modules/4.19.0-parrot4-28t-amd64/kernel/net/nfc/nfc_digital.ko
## ------------------------------------------------------------------------------------------------------------------------- ##
blacklist sunrpc                            ## 
remove sunrpc                               ## /lib/modules/4.19.0-parrot4-28t-amd64/kernel/net/sunrpc/sunrpc.ko
## ------------------------------------------------------------------------------------------------------------------------- ##
blacklist auth_rpcgss                       ## 
remove auth_rpcgss                          ## /lib/modules/4.19.0-parrot4-28t-amd64/kernel/net/sunrpc/auth_gss/auth_rpcgss.ko
## ------------------------------------------------------------------------------------------------------------------------- ##
blacklist chromeos_pstore                   ## Chrome OS pstore module
remove chromeos_pstore                      ## /lib/modules/4.19.0-parrot4-28t-amd64/kernel/drivers/platform/chrome/chromeos_pstore.ko
## ------------------------------------------------------------------------------------------------------------------------- ##
blacklist cros_kbd_led_backlight            ## ChromeOS Keyboard backlight LED Driver
remove cros_kbd_led_backlight               ## /lib/modules/4.19.0-parrot4-28t-amd64/kernel/drivers/platform/chrome/cros_kbd_led_backlight.ko
## ------------------------------------------------------------------------------------------------------------------------- ##
blacklist chromeos_laptop                   ## Chrome OS Laptop driver
remove chromeos_laptop                      ## /lib/modules/4.19.0-parrot4-28t-amd64/kernel/drivers/platform/chrome/chromeos_laptop.ko
## ------------------------------------------------------------------------------------------------------------------------- ##
blacklist appletalk                     ## AppleTalk 0.20
remove appletalk
alias net-pf-5 off
## ------------------------------------------------------------------------------------------------------------------------- ##
blacklist hfs                           ## Apple HFS Filesystem
remove hfs
alias fs-hfs off
## ------------------------------------------------------------------------------------------------------------------------- ##
blacklist hfsplus                       ## Apple HFS+ Filesystem
remove hfsplus
## ---------------------------------------------------------------------------------------- ##
## echo "options ipv6 disable=1" >> /etc/modprobe.d/ipv6.conf
## ---------------------------------------------------------------------------------------- ##
blacklist efi_pstore                    ## EFI variable backend for pstore
remove efi_pstore
options pstore_disable 1
## ------------------------------------------------------------------------------------------------------------------------- ##
blacklist efivarfs                      ## EFI Variable Filesystem
remove efivarfs
alias fs-efivarfs off
## ------------------------------------------------------------------------------------------------------------------------- ##
blacklist efivars                       ## sysfs interface to EFI Variables
remove efivars
alias net-pf-31 off
## ------------------------------------------------------------------------------------------------------------------------- ##
blacklist appletalk                     ## AppleTalk 0.20
remove appletalk
alias net-pf-5 off
## ------------------------------------------------------------------------------------------------------------------------- ##
blacklist appletouch                    ## Apple PowerBook and MacBook USB touchpad driver
remove appletouch
## ------------------------------------------------------------------------------------------------------------------------- ##
blacklist thunderbolt                   ## Thunderbolt
remove thunderbolt
## ------------------------------------------------------------------------------------------------------------------------- ##
blacklist thunderbolt_net               ## Thunderbolt network driver
remove thunderbolt_net
## ------------------------------------------------------------------------------------------------------------------------- ##
blacklist ipheth                        ## Apple iPhone USB Ethernet driver
remove ipheth
## ------------------------------------------------------------------------------------------------------------------------- ##
blacklist applesmc                      ## Apple SMC
remove applesmc
## ------------------------------------------------------------------------------------------------------------------------- ##
blacklist appledisplay                  ## Apple Cinema Display driver
remove appledisplay
## ------------------------------------------------------------------------------------------------------------------------- ##
blacklist apple_bl                      ## Apple Backlight Driver
remove apple_bl
alias mbp_nvidia_bl off
## ------------------------------------------------------------------------------------------------------------------------- ##
blacklist apple_gmux                    ## Apple Gmux Driver
remove apple_gmux
alias char-major-10-157 off
## ------------------------------------------------------------------------------------------------------------------------- ##
blacklist hid_microsoft                 ## Microsoft Bullshit
remove hid_microsoft
## ------------------------------------------------------------------------------------------------------------------------- ##
blacklist hid-appleir                   ## HID Apple IR remote controls
remove hid-appleir
## ------------------------------------------------------------------------------------------------------------------------- ##
blacklist hid-apple                     ## Apple Bullshit
remove hid-apple
## ------------------------------------------------------------------------------------------------------------------------- ##
blacklist hfsplus                       ## Extended Macintosh Filesystem
remove hfsplus
alias fs-hfsplus off
## ------------------------------------------------------------------------------------------------------------------------- ##
install rfkill
options master_switch_mode 1
options default_state 0
## ------------------------------------------------------------------------------------------------------------------------- ##
## acer_wmi                             ## Acer Laptop WMI Extras Driver
## options acer_wmi threeg 0            ## Set initial state of 3G hardware
## ------------------------------------------------------------------------------------------------------------------------- ##
blacklist stkwebcam                     ## Syntek DC1125 webcam driver
remove stkwebcam
## ------------------------------------------------------------------------------------------------------------------------- ##
## dell_laptop                          ## Dell laptop driver
## options force_rfkill true
## ------------------------------------------------------------------------------------------------------------------------- ##
blacklist toshiba_bluetooth             ## Toshiba Laptop ACPI Bluetooth Enable Driver
remove toshiba_bluetooth
## ------------------------------------------------------------------------------------------------------------------------- ##
## dell_laptop                          ## Dell laptop driver
## options force_rfkill true
## ------------------------------------------------------------------------------------------------------------------------- ##
## dell_rbtn                            ## Dell Airplane Mode Switch driver
## options auto_remove_rfkill 0
## ------------------------------------------------------------------------------------------------------------------------- ##
## 
##-==============================================================================================================================-##
## install asus_laptop                 ## Asus Laptop Support
##-==============================================================================================================================-##
## ------------------------------------------------------------------------------------------------------------------------------ ##
## options wlan_status 0               ## Set the wlan_status on boot (|0| disabled |1| enabled, |-1| dont do anything).
## options bluetooth_status 0          ## Set the Bluetooth status on boot (|0| disabled |1| enabled, |-1| dont do anything).
## options wimax_status 0              ## Set the wimax status on boot (|0| disabled |1| enabled, |-1| dont do anything).
## options wwan_status 0               ## Set the wwan status on boot (|0| disabled |1| enabled, |-1| dont do anything).
## options als_status 0                ## Set the ALS status on boot (|0| disabled |1| enabled, default is 0 (int) )
## ------------------------------------------------------------------------------------------------------------------------------ ##
##-==============================================================================================================================-##
## 
## 
##-===========================================================================================================-##
blacklist hci_vhci          ## Bluetooth virtual HCI driver ver 1.5
remove hci_vhci             ## /lib/modules/4.19.0-parrot4-28t-amd64/kernel/drivers/bluetooth/hci_vhci.ko
##-===========================================================================================================-##
## ----------------------------------------------------------------------- ##
## options amp              ## Create AMP controller device (bool)
## ----------------------------------------------------------------------- ##
## 
## 
##-===================================================================================-##
blacklist hci_uart          ## Bluetooth HCI UART driver ver 2.3
remove hci_uart             ## /lib/modules/4.19.0-parrot4-28t-amd64/kernel/drivers/bluetooth/hci_uart.ko
## alias tty-ldisc-15
##-===================================================================================-##
## ----------------------------------------------------------------------------------- ##
## options txcrc            ## Transmit CRC with every BCSP packet (bool)
## options hciextn          ## Convert HCI Extensions into BCSP packets (bool)
## ----------------------------------------------------------------------------------- ##
##-===================================================================================-##
## 
## 
##-========================================================================================-##
blacklist btusb                 ## Generic Bluetooth USB driver ver 0.8
remove btusb                    ## /lib/modules/4.19.0-parrot4-28t-amd64/kernel/drivers/bluetooth/btusb.ko
##-========================================================================================-##
## ---------------------------------------------------------------------------------------- ##
## options disable_scofix          ## Disable fixup of wrong SCO buffer size (bool)
## options force_scofix            ## Force fixup of wrong SCO buffers size (bool)
## options enable_autosuspend      ## Enable USB autosuspend by default (bool)
## options reset                   ## Send HCI reset command on initialization (bool)
## ---------------------------------------------------------------------------------------- ##
##-========================================================================================-##
## 
## 
##-========================================================================================-##
blacklist bnep                  ## Bluetooth BNEP ver 1.3
remove bnep                     ## /lib/modules/4.19.0-parrot4-28t-amd64/kernel/net/bluetooth/bnep/bnep.ko
alias bt-proto-4 off
##-========================================================================================-##
## ---------------------------------------------------------------------------------------- ##
## options compress_src         ## Compress sources headers (bool)
## options compress_dst         ## Compress destination headers (bool)
## ---------------------------------------------------------------------------------------- ##
##-========================================================================================-##
## 
## ---------------------------------------------------------------------------------------- ##
## install xt_sysrq
## options xt_sysrq password=cookies
## options xt_sysrq hash=sha256
## ---------------------------------------------------------------------------------------- ##
## echo "install xt_sysrq" >> /etc/modprobe.d/xt_sysrq.conf
## echo "options xt_sysrq password=cookies" >> /etc/modprobe.d/xt_sysrq.conf
## echo "options xt_sysrq hash=sha256" >> /etc/modprobe.d/xt_sysrq.conf
## ---------------------------------------------------------------------------------------- ##
##-========================================================================================-##
## -------------------------------------------------------------------------------------------------------------------------------- ##
## echo "options usbfs_memory_mb $MB" >> /etc/modprobe.d/usbcore.conf      ## maximum MB allowed for usbfs buffers (0 = no limit)
## -------------------------------------------------------------------------------------------------------------------------------- ##
options nousb false
options usbfs_snoop false               ## true to log all usbfs traffic
## options usbfs_memory_mb                 ## maximum MB allowed for usbfs buffers (0 = no limit)
options authorized_default 1            ## Default USB device authorization: 
## ---------------------------------------------------------------------------------------- ##
## option authorized_default  0        ## Not Authorized
## option authorized_default  1        ## Authorized
## option authorized_default -1        ## Authorized except for wireless USB (default)
## ---------------------------------------------------------------------------------------- ##
## 
## -------------------------------------------------------------------------------------------------------------------------------- ##
## echo "options nousb false" >> /etc/modprobe.d/usbcore.conf
## echo "options usbfs_snoop false" >> /etc/modprobe.d/usbcore.conf        ##  true to log all usbfs traffic
## echo "options authorized_default 1" >> /etc/modprobe.d/usbcore.conf     ##  Default USB device authorization
## -------------------------------------------------------------------------------------------------------------------------------- ##
## option authorized_default  0        ## Not Authorized
## option authorized_default  1        ## Authorized
## option authorized_default -1        ## Authorized except for wireless USB (default)
## ---------------------------------------------------------------------------------------- ##
##-========================================================================================-##
## 
## 
##-===============================================================================================================================-##
blacklist usbip_core                ## USB/IP Core
remove usbip_core                   ## /lib/modules/4.19.0-parrot4-28t-amd64/kernel/drivers/usb/usbip/usbip-core.ko
##-===============================================================================================================================-##
blacklist usbip_host                ## USB/IP Host Driver
remove usbip_host                   ## /lib/modules/4.19.0-parrot4-28t-amd64/kernel/drivers/usb/usbip/usbip-host.ko
##-===============================================================================================================================-##
blacklist usbip_vudc                ## USB over IP Device Controller
remove usbip_vudc                   ## /lib/modules/4.19.0-parrot4-28t-amd64/kernel/drivers/usb/usbip/usbip-vudc.ko
##-===============================================================================================================================-##
blacklist usbnet                    ## USB network driver framework
remove usbnet                       ## /lib/modules/4.19.0-parrot4-28t-amd64/kernel/drivers/net/usb/usbnet.ko
##-===============================================================================================================================-##
blacklist usb_wwan                  ## USB Driver for GSM modems
remove usb_wwan                     ## /lib/modules/4.19.0-parrot4-28t-amd64/kernel/drivers/usb/serial/usb_wwan.ko
##-===============================================================================================================================-##
blacklist vhci_hcd                  ## USB/IP 'Virtual' Host Controller (VHCI) Driver
remove vhci_hcd                     ## /lib/modules/4.19.0-parrot4-28t-amd64/kernel/drivers/usb/usbip/vhci-hcd.ko
##-===============================================================================================================================-##
blacklist usblp                     ## USB Printer Device Class driver
remove usblp                        ## /lib/modules/4.19.0-parrot4-28t-amd64/kernel/drivers/usb/class/usblp.ko
##-===============================================================================================================================-##
## 
##-========================================-##
install cdrom
##-========================================-##
## ---------------------------------------- ##
option debug 1
option check_media_type 1
option autoeject 0
option autoclose 0
option lockdoor 1
## option mrw_format_restart 1
## ---------------------------------------- ##
##-========================================-##
## 
## 
##-===============================================================================================================================-##
## install dvb_usb
## blacklist dvb_usb
## remove dvb_usb
##-===============================================================================================================================-##
## ------------------------------------------------------------------------------------------------------------------------------- ##
option debug 1                          ## set debugging level (1=info,xfer=2,pll=4,ts=8,err=16,rc=32,fw=64,mem=128,uxfer=256
option disable_rc_polling 1             ## disable remote control polling
## option force_pid_filter_usage 1      ## force all dvb-usb-devices to use a PID filter
## ------------------------------------------------------------------------------------------------------------------------------- ##
##-===============================================================================================================================-##
## 
## 
##-========================================================================================-##
install scsi_mod                        ## SCSI core
##-========================================================================================-##
## -------------------------------------------------------------------------------------------------------------------------------------- ##
## options dev_flags			        ## Given scsi_dev_flags=vendor  ## model    ## flags[,v     ## m	## f] add black/white list entries for vendor and model with an integer value of flags to the scsi device info list (string)
## options default_dev_flags			## scsi default device flag integer value (int)
## options max_luns			            ## last scsi LUN (should be between 1 and 2^64-1) (ullong)
## options scan manual			        ## sync, async, manual, or none. Setting to 'manual' disables automatic scanning, but allows
options scsi_logging_level 7		    ## a bit mask of logging levels (int)
## -------------------------------------------------------------------------------------------------------------------------------------- ##
## echo "options scsi_logging_level 7" >> /etc/modprobe.d/scsi_mod.conf
## -------------------------------------------------------------------------------------------------------------------------------------- ##
##-======================================================================================================================================-##
## 
## 
## --------------------------------------------------------------------------------------------------------------------------------------------------------- ##
##-=========================================================================================================================================================-##
blacklist nfs                               ## Network Filesystem (NFS)
remove nfs
##-=========================================================================================================================================================-##
## --------------------------------------------------------------------------------------------------------------------------------------------------------- ##
## options callback_tcpport                 ## portnr
## options callback_nr_threads              ## Number of threads that will be assigned to the NFSv4 callback channels. (ushort)
## options nfs_idmap_cache_timeout			## int
## options nfs4_disable_idmapping			## Turn off NFSv4 idmapping when using 'sec=sys' (bool)
## options max_session_slots			    ## Maximum number of outstanding NFSv4.1 requests the client will negotiate (ushort)
## options max_session_cb_slots			    ## Maximum number of parallel NFSv4.1 callbacks the client will process for a given server (ushort)
## options send_implementation_id			## Send implementation ID with NFSv4.1 exchange_id (ushort)
## options nfs4_unique_id			        ## nfs_client_id4 uniquifier string (string)
## options recover_lost_locks			    ## If the server reports that a lock might be lost, try to recover it risking data corruption. (bool)
## options enable_ino64                     ## bool
## options nfs_access_max_cachesize		    ## NFS access maximum total cache length (ulong)
## --------------------------------------------------------------------------------------------------------------------------------------------------------- ##
##-=========================================================================================================================================================-##
## 
## 
##-======================================================================================-##
blacklist blocklayoutdriver                 ## The NFSv4.1 pNFS Block layout driver
remove blocklayoutdriver
##-======================================================================================-##
## 
## 
##-=========================================================================================================================================================================================-##
blacklist nfs_layout_nfsv41_files           ## The NFSv4 file layout driver
remove nfs_layout_nfsv41_files
##-=========================================================================================================================================================================================-##
## ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ##
## options dataserver_retrans               ## The  number of times the NFSv4.1 client retries a request before it attempts further  recovery  action. (uint)
## options dataserver_timeo                 ## The time (in tenths of a second) the NFSv4.1  client  waits for a response from a  data server before it retries an NFS request. (uint)
## ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ##
##-=========================================================================================================================================================================================-##
## 
##-=========================================================================================================================================================================================-##
blacklist nfs_layout_flexfiles              ## The NFSv4 flexfile layout driver
remove nfs_layout_flexfiles
##-=========================================================================================================================================================================================-##
## ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ##
## options dataserver_retrans               ## The number of times the NFSv4.1 client retries a request before it attempts further  recovery  action. (uint)
## options dataserver_timeo                 ## The time (in tenths of a second) the NFSv4.1  client  waits for a response from a  data server before it retries an NFS request. (uint)
## ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ##
##-=========================================================================================================================================================================================-##
## 
##-==========================================================================================================-##
blacklist nfsv4                             ## Network Filesystem Version 4
remove nfsv4
##-==========================================================================================================-##
## 
## 
##-==================================================================================================================-##
blacklist nfsd                              ## Network Filesystem Daemon
remove nfsd
##-==================================================================================================================-##
## ------------------------------------------------------------------------------------------------------------------ ##
## options cltrack_prog			            ## Path to the nfsdcltrack upcall program (string)
## options cltrack_legacy_disable			## Disable legacy recoverydir conversion. Default	##  false (bool)
## options nfs4_disable_idmapping			## Turn off server's NFSv4 idmapping when using 'sec=sys' (bool)
## ------------------------------------------------------------------------------------------------------------------ ##
##-==================================================================================================================-##
## 
##-================================================================================-##
blacklist nfsv3                             ## Network Filesystem Version 3
remove nfsv3
##-================================================================================-##
## 
##-================================================================================-##
blacklist nfsv2                             ## Network Filesystem Version 2
remove nfsv2
##-================================================================================-##
## 
## 
## ------------------------------------------------------------------------------------------------------------------------------------------------ ##
##-================================================================================================================================================-##
##                                                              [+] CIFS Filesystem
##-================================================================================================================================================-##
blacklist cifs                      ## 
remove cifs
## alias fs-smb3 off
## alias fs-cifs off
## ------------------------------------------------------------------------------------------------------------------------------------------------ ##
## options CIFSMaxBufSize			## Network buffer size (not including header). Default	##  16384 Range			##  8192 to 130048 (uint)
## options cifs_min_rcv			    ## Network buffers in pool. Default			            ##  4 Range			    ##  1 to 64 (uint)
## options cifs_min_small			## Small network buffers in pool. Default			    ##  30 Range			##  2 to 256 (uint)
## options cifs_max_pending		    ## Simultaneous requests to server. Default			    ##  32767 Range			##  2 to 32767. (uint)
## options enable_oplocks			## Enable or disable oplocks. Default			        ##  y/Y/1 (bool)
## ------------------------------------------------------------------------------------------------------------------------------------------------ ##
##-================================================================================================================================================-##
## 

## ------------------------------------------------------------------------------------------------------------------------------------ ##
## blacklist scsi_transport_fc                      ## FC Transport Attributes
## remove scsi_transport_fc                         ## /lib/modules/4.19.0-parrot4-28t-amd64/kernel/drivers/scsi/scsi_transport_fc.ko
## ------------------------------------------------------------------------------------------------------------------------------------ ##
blacklist scsi_transport_iscsi                      ## iSCSI Transport Interface
remove scsi_transport_iscsi                         ## /lib/modules/4.19.0-parrot4-28t-amd64/kernel/drivers/scsi/scsi_transport_iscsi.ko
## alias net-pf-16-proto-8
## ------------------------------------------------------------------------------------------------------------------------------------ ##
blacklist scsi_transport_sas                        ## SAS Transport Attributes
remove scsi_transport_sas                           ## /lib/modules/4.19.0-parrot4-28t-amd64/kernel/drivers/scsi/scsi_transport_sas.ko
## ------------------------------------------------------------------------------------------------------------------------------------ ##
## blacklist scsi_transport_spi                    ## SPI Transport Attributes
## remove scsi_transport_spi                       ## /lib/modules/4.19.0-parrot4-28t-amd64/kernel/drivers/scsi/scsi_transport_spi.ko
## ------------------------------------------------------------------------------------------------------------------------------------ ##
## blacklist scsi_transport_srp                    ## SRP Transport Attributes
## remove scsi_transport_srp                       ## /lib/modules/4.19.0-parrot4-28t-amd64/kernel/drivers/scsi/scsi_transport_srp.ko
## ------------------------------------------------------------------------------------------------------------------------------------ ##
blacklist garmin_gps                        ## garmin gps driver
remove garmin_gps                           ## /lib/modules/4.19.0-parrot4-28t-amd64/kernel/drivers/usb/serial/garmin_gps.ko
## ------------------------------------------------------------------------------------------------------------------------------------ ##
blacklist libiscsi                          ## iSCSI library functions
remove libiscsi                             ## /lib/modules/4.19.0-parrot4-28t-amd64/kernel/drivers/scsi/libiscsi.ko
## ------------------------------------------------------------------------------------------------------------------------------------ ##
blacklist libiscsi_tcp                      ## iSCSI/TCP data-path
remove libiscsi_tcp                         ## /lib/modules/4.19.0-parrot4-28t-amd64/kernel/drivers/scsi/libiscsi_tcp.ko
## ------------------------------------------------------------------------------------------------------------------------------------ ##
blacklist cxgbit                            ## Chelsio iSCSI target offload driver
remove cxgbit                               ## /lib/modules/4.19.0-parrot4-28t-amd64/kernel/drivers/target/iscsi/cxgbit/cxgbit.ko
## ------------------------------------------------------------------------------------------------------------------------------------ ##
blacklist iscsi_target_mod                  ## iSCSI-Target Driver for mainline target infrastructure
remove iscsi_target_mod                     ## /lib/modules/4.19.0-parrot4-28t-amd64/kernel/drivers/target/iscsi/iscsi_target_mod.ko
## ------------------------------------------------------------------------------------------------------------------------------------ ##
## blacklist target_core_mod                ## Target_Core_Mod/ConfigFS
## remove target_core_mod                   ## /lib/modules/4.19.0-parrot4-28t-amd64/kernel/drivers/target/target_core_mod.ko
## ------------------------------------------------------------------------------------------------------------------------------------ ##
## blacklist tcm_loop                       ## TCM loopback virtual Linux/SCSI fabric module
## remove tcm_loop                          ## /lib/modules/4.19.0-parrot4-28t-amd64/kernel/drivers/target/loopback/tcm_loop.ko
## ------------------------------------------------------------------------------------------------------------------------------------ ##
## blacklist tcm_fc                         ## FC TCM fabric driver 0.4
## remove tcm_fc                            ## /lib/modules/4.19.0-parrot4-28t-amd64/kernel/drivers/target/tcm_fc/tcm_fc.ko
## ------------------------------------------------------------------------------------------------------------------------------------ ##
blacklist wusbcore                          ## Wireless USB core
remove wusbcore                             ## /lib/modules/4.19.0-parrot4-28t-amd64/kernel/drivers/usb/wusbcore/wusbcore.ko
## options debug_crypto_verify 1            ## verify the key generation algorithms
## ------------------------------------------------------------------------------------------------------------------------------------ ##
## 
## 
## b43                              ## Broadcom B43 wireless driver
## options btcoex 0
## options verbose 3
## /lib/modules/4.19.0-parrot4-28t-amd64/kernel/drivers/char/tpm/
## 
## 
## ------------------------------------------------------------------------------------------------------------------------- ##
## vblacklist 
## remove 
## ------------------------------------------------------------------------------------------------------------------------- ##
## 
## 
## ------------------------------------------------------------------------------------------------------------------------- ##
## blacklist 
## remove 
## ------------------------------------------------------------------------------------------------------------------------- ##


##-========================================================================================-##
## 
##-===================================================================================================================-##
##  install cfg80211                            ## wireless configuration support
## alias net-pf-16-proto-16-family-nl80211
##-===================================================================================================================-##
##  options ieee80211_regdom US                 ## IEEE 802.11 regulatory domain code (charp)
## options bss_entries_limit                ## limit to number of scan BSS entries (per wiphy, default 1000) (int)
## options cfg80211_disable_40mhz_24ghz     ## Disable 40MHz support in the 2.4GHz band (bool)
## ------------------------------------------------------------------------------------------------------------------- ##
## 
##-========================================================================================-##
blacklist ip_gre                        ## GRE over IPv4 tunneling device
remove ip_gre
##-========================================================================================-##
## ---------------------------------------------------------------------------------------- ##
## alias netdev-erspan0
## alias netdev-gretap0
## alias netdev-gre0
## alias rtnl-link-erspan
## alias rtnl-link-gretap
## alias rtnl-link-gre
## ---------------------------------------------------------------------------------------- ##
## 
##-========================================================================================-##
blacklist ip6_gre                       ## GRE over IPv6 tunneling device
remove ip6_gre
##-========================================================================================-##
## alias netdev-ip6gre0
## alias rtnl-link-ip6erspan
## alias rtnl-link-ip6gretap
## alias rtnl-link-ip6gre
## options log_ecn_error true           ## Log packets received with corrupted ECN 
## ---------------------------------------------------------------------------------------- ##
## 
##-========================================================================================-##
## ---------------------------------------------------------------------------------------- ##
## install dell_laptop                  ## Dell laptop driver
## options force_rfkill true            ## enable rfkill on non whitelisted models (bool)
## ---------------------------------------------------------------------------------------- ##
## install dell_rbtn                    ## Dell Airplane Mode Switch driver
## options auto_remove_rfkill			## Automatically remove rfkill devices when other modules start receiving events from this module and re-add them when the last module stops receiving events (default true) (bool)
## ---------------------------------------------------------------------------------------- ##
## 
## 
## ---------------------------------------------------------------------------------------- ##
## blacklist 
## remove 
## ---------------------------------------------------------------------------------------- ##
## blacklist 
## remove 
## ---------------------------------------------------------------------------------------- ##
## blacklist 
## remove 
## ---------------------------------------------------------------------------------------- ##
## blacklist 
## remove 
## ---------------------------------------------------------------------------------------- ##
## blacklist                           ## 
## remove 
## alias 
## options 
## ---------------------------------------------------------------------------------------- ##
## blacklist                           ## 
## remove 
## alias 
## options 
## ---------------------------------------------------------------------------------------- ##
##-========================================================================================-##
## ---------------------------------------------------------------------------------------- ##
