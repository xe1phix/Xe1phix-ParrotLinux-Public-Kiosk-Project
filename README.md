## 
#  _____ <!> ParrotSec Linux - Public Kios Project <!> ______
## Designing & Implementing A restricted & Trustworthy Environment 
## 
## 




- [ ] Hardened kernel

        - [ ] GrSecurity Patched Kernel
                - [ ] PaX Hardening
                        - [x] PaXctl
                        - [x] PaXTest
                        - [x] PaXctld
                        - [x] 


- [x] Hardened Kernel Runtime Parameters

        - [x] Blacklist IPv6
                - [x] ipv6.disable=1
                - [x] noipv6
                - [x] ipv6.autoconf=0


        - [x] Modprobe Blacklisting
                - [x] Bluetooth Blacklisting
                        - [x] btsdio            - Bluetooth SDIO driver
                        - [x] btusb             - 
                        - [x] btintel           - Intel
                        - [x] btrtl             - Realtek Bluetooth
                        - [x] bt3c_cs           - 3Com Bluetooth PCMCIA
                        - [x] btmrvl            - Bluetooth driver ver 1.0
                        - [x] btmrvl_sdio       - BT-over-SDIO
                        - [x] btqca                 - Qualcomm Atheros family
                        - [x] btbcm                 - Broadcom
                        - [x] bluetooth_6lowpan     - Bluetooth 6LoWPAN
                        - [x] rfcomm                - Bluetooth RFCOMM ver 1.11
                        - [x] bluecard_cs           - Anycom BlueCard (LSE039/LSE041)


                - [x] Apple Blacklisting
                        - [x] appletalk
                        - [x] thunderbolt_net
                        - [x] 
                        - [x] hfs
                        - [x] hfsplus
                        - [x] appletouch
                        - [x] hid-apple


                - [x] EFI Blacklisting:
                        - [x] efivars
                        - [x] efivarfs
                        - [x] efi_pstore



                        