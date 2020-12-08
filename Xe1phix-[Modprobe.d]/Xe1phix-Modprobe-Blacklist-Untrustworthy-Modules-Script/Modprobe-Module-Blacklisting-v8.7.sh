#!/bin/sh
##-=============================================-##
##  [+] Modprobe-Module-Blacklisting-v*.*.sh
##-=============================================-##
## 
##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##
## --------------------------------------------- ##
## modinfo $Module
## systool $Module
## modprobe --verbose --show $Module
## modprobe --verbose --show-depends $Module
## modprobe --verbose --showconfig $Module
## modprobe --verbose --use-blacklist $Module
## modprobe --verbose --remove $Module
## modprobe --verbose --install $Module
## --------------------------------------------- ##
##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##
modprobe --verbose --use-blacklist acerhdf
modprobe --verbose --use-blacklist acer-wmi
modprobe --verbose --use-blacklist rfd_ftl
modprobe --verbose --use-blacklist intel-cstate
modprobe --verbose --use-blacklist ieee802154_6lowpan
modprobe --verbose --use-blacklist intel-smartconnect
modprobe --verbose --use-blacklist rndis_wlan
modprobe --verbose --use-blacklist rsi_usb
modprobe --verbose --use-blacklist intel-vbtn
modprobe --verbose --use-blacklist ip6_gre
## modprobe --verbose --use-blacklist ip6t_ipv6header
modprobe --verbose --use-blacklist ip_gre
modprobe --verbose --use-blacklist ipcomp6
modprobe --verbose --use-blacklist iphase
modprobe --verbose --use-blacklist ah6
modprobe --verbose --use-blacklist aoe
## ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ##
modprobe --verbose --use-blacklist ir-usb
modprobe --verbose --use-blacklist ttusbir
modprobe --verbose --use-blacklist sir_ir
modprobe --verbose --use-blacklist fintek-cir
modprobe --verbose --use-blacklist keyspan_remote
## ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ##
modprobe --verbose --use-blacklist efi-pstore
modprobe --verbose --use-blacklist efivarfs
modprobe --verbose --use-blacklist efivars
modprobe --verbose --use-blacklist efibc
## ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ##
modprobe --verbose --use-blacklist fcoe
modprobe --verbose --use-blacklist firewire-net
modprobe --verbose --use-blacklist firestream
## ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ##
modprobe --verbose --use-blacklist iscsi_boot_sysfs
modprobe --verbose --use-blacklist iscsi_ibft
modprobe --verbose --use-blacklist libiscsi
modprobe --verbose --use-blacklist libiscsi_tcp
modprobe --verbose --use-blacklist libsas
modprobe --verbose --use-blacklist libfcoe
modprobe --verbose --use-blacklist libfc
modprobe --verbose --use-blacklist iscsi_target_mod
modprobe --verbose --use-blacklist iscsi_tcp
modprobe --verbose --use-blacklist scsi_transport_fc
modprobe --verbose --use-blacklist scsi_transport_sas
modprobe --verbose --use-blacklist scsi_transport_iscsi
modprobe --verbose --use-blacklist scsi_transport_spi
modprobe --verbose --use-blacklist scsi_transport_srp
## ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ##
modprobe --verbose --use-blacklist blocklayoutdriver
modprobe --verbose --use-blacklist atmel_cs
modprobe --verbose --use-blacklist vport-gre
modprobe --verbose --use-blacklist virtio_scsi
modprobe --verbose --use-blacklist vmw_pvscsi
modprobe --verbose --use-blacklist vmw_vsock_virtio_transport
modprobe --verbose --use-blacklist vmw_vsock_virtio_transport_common
modprobe --verbose --use-blacklist vmw_vsock_vmci_transport
## ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ##
modprobe --verbose --use-blacklist sctp
modprobe --verbose --use-blacklist sctp_diag
## ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ##
modprobe --verbose --use-blacklist sunrpc
modprobe --verbose --use-blacklist auth_rpcgss
modprobe --verbose --use-blacklist rpcsec_gss_krb5
modprobe --verbose --use-blacklist rpcrdma
modprobe --verbose --use-blacklist hid_sunplus                 ## /lib/modules/5.2.0-2parrot1-amd64/kernel/drivers/hid/hid-sunplus.ko
## ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ##
modprobe --verbose --use-blacklist ses
modprobe --verbose --use-blacklist sierra_net
modprobe --verbose --use-blacklist smsusb
modprobe --verbose --use-blacklist smsdvb                   ## SMS DVB subsystem adaptation module      ## /lib/modules/5.2.0-2parrot1-amd64/kernel/drivers/media/common/siano/smsdvb.ko
modprobe --verbose --use-blacklist smsmdtv                  ## Siano MDTV Core module
modprobe --verbose --use-blacklist smssdio
## ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ##
modprobe --verbose --use-blacklist chromeos_laptop
modprobe --verbose --use-blacklist chromeos_pstore
## ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ##
modprobe --verbose --use-blacklist mic_bus
modprobe --verbose --use-blacklist mic_host
## ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ##
modprobe --verbose --use-blacklist mISDNisar
modprobe --verbose --use-blacklist mISDN_core
## ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ##
modprobe --verbose --use-blacklist dccp
modprobe --verbose --use-blacklist dccp_diag
modprobe --verbose --use-blacklist dccp_ipv4
modprobe --verbose --use-blacklist dccp_ipv6
## ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ##
modprobe --verbose --use-blacklist esp6
modprobe --verbose --use-blacklist esp6_offload
modprobe --verbose --use-blacklist esp_scsi
## ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ##
modprobe --verbose --use-blacklist n_gsm
## ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ##
modprobe --verbose --use-blacklist lp
modprobe --verbose --use-blacklist lpc_ich
modprobe --verbose --use-blacklist lpc_sch
modprobe --verbose --use-blacklist lpfc
## ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ##
modprobe --verbose --use-blacklist rfcomm						## Bluetooth RFCOMM ver 1.11        ## /lib/modules/5.2.0-2parrot1-amd64/kernel/net/bluetooth/rfcomm/rfcomm.ko          ## alias bt-proto-3
modprobe --verbose --use-blacklist snd-bt87x
modprobe --verbose --use-blacklist libertas_sdio
modprobe --verbose --use-blacklist libertas_cs
modprobe --verbose --use-blacklist bttv
modprobe --verbose --use-blacklist btmrvl
modprobe --verbose --use-blacklist btmrvl_sdio
modprobe --verbose --use-blacklist btmtkuart					## MediaTek Bluetooth Serial driver ver 0.2
modprobe --verbose --use-blacklist btqca
modprobe --verbose --use-blacklist btrsi                        ## RSI BT driver            ## /lib/modules/5.2.0-2parrot1-amd64/kernel/drivers/bluetooth/btrsi.ko
modprobe --verbose --use-blacklist btsdio
modprobe --verbose --use-blacklist toshiba_bluetooth
modprobe --verbose --use-blacklist bluetooth_6lowpan            ## /lib/modules/5.2.0-2parrot1-amd64/kernel/net/bluetooth/bluetooth_6lowpan.ko
modprobe --verbose --use-blacklist bluecard_cs
modprobe --verbose --use-blacklist bfusb
modprobe --verbose --use-blacklist bcma
modprobe --verbose --use-blacklist bcm203x
modprobe --verbose --use-blacklist ath3k
modprobe --verbose --use-blacklist btintel
modprobe --verbose --use-blacklist btrtl
modprobe --verbose --use-blacklist dtl1_cs
modprobe --verbose --use-blacklist hci
modprobe --verbose --use-blacklist hci_uart
modprobe --verbose --use-blacklist hci_nokia
modprobe --verbose --use-blacklist hci_vhci
modprobe --verbose --use-blacklist hidp            ## Bluetooth HIDP ver 1.2           ## /lib/modules/5.2.0-2parrot1-amd64/kernel/net/bluetooth/hidp/hidp.ko           ## alias bt-proto-6
modprobe --verbose --use-blacklist cmtp            ## Bluetooth CMTP ver 1.0           ## /lib/modules/5.2.0-2parrot1-amd64/kernel/net/bluetooth/cmtp/cmtp.ko           ## alias bt-proto-6
modprobe --verbose --use-blacklist bnep            ## Bluetooth BNEP ver 1.3           ## /lib/modules/5.2.0-2parrot1-amd64/kernel/net/bluetooth/bnep/bnep.ko           ## alias bt-proto-4
modprobe --verbose --use-blacklist btbcm
modprobe --verbose --use-blacklist be2iscsi
modprobe --verbose --use-blacklist be2net
modprobe --verbose --use-blacklist bpa10x
modprobe --verbose --use-blacklist bt3c_cs
modprobe --verbose --use-blacklist btcoexist
## ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ##
modprobe --verbose --use-blacklist l2tp_ip6
modprobe --verbose --use-blacklist nhc_ghc_icmpv6
modprobe --verbose --use-blacklist nhc_ipv6
## ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ##
modprobe --verbose --use-blacklist apple_bl
modprobe --verbose --use-blacklist appledisplay
modprobe --verbose --use-blacklist hid-apple
modprobe --verbose --use-blacklist hid-appleir
modprobe --verbose --use-blacklist apple-gmux
modprobe --verbose --use-blacklist applesmc
modprobe --verbose --use-blacklist appletalk
modprobe --verbose --use-blacklist appletouch
modprobe --verbose --use-blacklist ipheth
modprobe --verbose --use-blacklist hfs
modprobe --verbose --use-blacklist hfsplus
modprobe --verbose --use-blacklist hfcmulti
modprobe --verbose --use-blacklist hfcpci
modprobe --verbose --use-blacklist hfcsusb
## modprobe --verbose --use-blacklist thunderbolt
modprobe --verbose --use-blacklist thunderbolt-net
modprobe --verbose --use-blacklist bcm5974                ## Apple USB BCM5974 multitouch driver       ## /lib/modules/5.2.0-2parrot1-amd64/kernel/drivers/input/mouse/bcm5974.ko
## ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ##
modprobe --verbose --use-blacklist ipddp                   ## /lib/modules/5.2.0-2parrot1-amd64/kernel/drivers/net/appletalk/ipddp.ko
modprobe --verbose --use-blacklist usbip-core
modprobe --verbose --use-blacklist usbip-host
modprobe --verbose --use-blacklist usbip-vudc
modprobe --verbose --use-blacklist usbnet
modprobe --verbose --use-blacklist usbtv
modprobe --verbose --use-blacklist usb_wwan
modprobe --verbose --use-blacklist gre
modprobe --verbose --use-blacklist grace
## ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ##
modprobe --verbose --use-blacklist b2c2_flexcop
modprobe --verbose --use-blacklist dvb-core
modprobe --verbose --use-blacklist dvb-bt8xx
modprobe --verbose --use-blacklist bcm3510                 ## Broadcom BCM3510 ATSC (8VSB/16VSB & ITU J83 AnnexB FEC QAM64/256) demodulator driver
## ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ##
modprobe --verbose --use-blacklist 6lowpan
modprobe --verbose --use-blacklist ieee802154_6lowpan
## ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ##
modprobe --verbose --use-blacklist nfc
modprobe --verbose --use-blacklist nfc_digital
modprobe --verbose --use-blacklist nfcsim
modprobe --verbose --use-blacklist nfs
modprobe --verbose --use-blacklist nfs_acl
modprobe --verbose --use-blacklist nfsd
modprobe --verbose --use-blacklist nfs_layout_flexfiles
modprobe --verbose --use-blacklist nfs_layout_nfsv41_files
modprobe --verbose --use-blacklist nfsv2
modprobe --verbose --use-blacklist nfsv3
modprobe --verbose --use-blacklist nfsv4
modprobe --verbose --use-blacklist cifs
## ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ##
modprobe --verbose --use-blacklist ib_core
modprobe --verbose --use-blacklist pppoatm
modprobe --verbose --use-blacklist mwifiex
modprobe --verbose --use-blacklist mwifiex_sdio
modprobe --verbose --use-blacklist wimax
modprobe --verbose --use-blacklist wacom
modprobe --verbose --use-blacklist wacom_w8001
modprobe --verbose --use-blacklist winbond-840
modprobe --verbose --use-blacklist winbond-cir
modprobe --verbose --use-blacklist wusbcore
modprobe --verbose --use-blacklist wusb-wa
modprobe --verbose --use-blacklist qmi_wwan
modprobe --verbose --use-blacklist isicom
modprobe --verbose --use-blacklist toshiba_haps
modprobe --verbose --use-blacklist mpt3sas
modprobe --verbose --use-blacklist mptlan
modprobe --verbose --use-blacklist mptsas
modprobe --verbose --use-blacklist mptscsih
modprobe --verbose --use-blacklist mptspi
## ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ##
modprobe --verbose --use-blacklist hid-microsoft
modprobe --verbose --use-blacklist touchwin
modprobe --verbose --use-blacklist mspro_block
modprobe --verbose --use-blacklist surface3_spi
modprobe --verbose --use-blacklist surfacepro3_button
## ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ##
