#!/bin/sh



echo -n ${value} > /sys/module/${modulename}/parameters/${parm}
modinfo -p ${modulename}

blacklist
remove

/lib/systemd/systemd-modules-load
/usr/lib/modules-load.d
/etc/modules-load.d

modinfo /lib/modules/4.16.0-parrot5-amd64/kernel/net/ipv4/* | less

--sign

ecryptfs
parm:           ecryptfs_verbosity:Initial verbosity level (0 or 1; defaults to 0, which is Quiet) (int)
parm:           ecryptfs_message_buf_len:Number of message buffer elements (uint)
parm:           ecryptfs_message_wait_timeout:Maximum number of seconds that an operation will sleep while waiting for a message response from userspace (long)
parm:           ecryptfs_number_of_users:An estimate of the number of concurrent users of eCryptfs (uint)



echo "## ======================================================================================== ##"


parm:           master_switch_mode:SW_RFKILL_ALL ON should: 0=do nothing (only unlock); 1=restore; 2=unblock all (uint)
parm:           default_state:Default initial state for all radio types, 0 = radio off (uint)


options rfkill master_switch_mode=0
options rfkill default_state=0


alias bluetooth net-pf-31
blacklist bluetooth
remove bluetooth



bluetooth

parm:           disable_esco:Disable eSCO connection creation (bool)
parm:           disable_ertm:Disable enhanced retransmission mode (bool)


alias bluetooth net-pf-31
blacklist bluetooth
remove bluetooth

options disable_esco=1
options disable_ertm=1



btusb           ## Generic Bluetooth USB driver ver 0.8
filename:       /lib/modules/4.18.0-parrot10-amd64/kernel/drivers/bluetooth/btusb.ko

parm:           disable_scofix:Disable fixup of wrong SCO buffer size (bool)
parm:           force_scofix:Force fixup of wrong SCO buffers size (bool)
parm:           enable_autosuspend:Enable USB autosuspend by default (bool)
parm:           reset:Send HCI reset command on initialization (bool)




modinfo hci_vhci
parm:           amp:Create AMP controller device (bool)



/sys/module/module/parameters/sig_enforce

echo -e "options ipv6 disable=1" >> /etc/modprobe.d/usgcb-blacklist.conf
echo -e "install bluetooth /bin/false" >> /etc/modprobe.d/usgcb-blacklist.conf
echo -e "install net-pf-31 /bin/false" >> /etc/modprobe.d/usgcb-blacklist.conf
echo -e "install appletalk /bin/false" >> /etc/modprobe.d/usgcb-blacklist.conf 
echo -e "install hfs /bin/false" >> /etc/modprobe.d/usgcb-blacklist.conf
echo -e "install hfsplus /bin/false" >> /etc/modprobe.d/usgcb-blacklist.conf



# Disable beep sound from your computer
echo "blacklist pcspkr"|sudo tee -a /etc/modprobe.d/blacklist.conf



# Short Information about loaded kernel modules
awk '{print $1}' "/proc/modules" | xargs modinfo | awk '/^(filename|desc|depends)/'


echo "blacklist pcspkr"|sudo tee -a /etc/modprobe.d/blacklist.conf



cat /sys/module/drm_kms_helper/holders/nouveau/parameters/

cat /sys/module/drm/parameters/


cat /sys/module/edac_core/parameters/

cat /sys/module/hid/parameters/

cat /sys/module/intel_idle/parameters/max_cstate


cat /sys/module/ipv6/parameters/autoconf

/sys/module/ipv6/parameters/autoconf
/sys/module/ipv6/parameters/disable_ipv6





cat /sys/module/libata/parameters/allow_tpm


cat /sys/module/libata/parameters/ignore_hpa
cat /sys/module/libata/parameters/noacpi
cat /sys/module/libata/parameters/dma
cat /sys/module/libata/parameters/fua
cat /sys/module/libata/parameters/atapi_enabled
cat /sys/module/libata/parameters/acpi_gtf_filter
cat /sys/module/libata/parameters/atapi_an
cat /sys/module/libata/parameters/
cat /sys/module/libata/parameters/
cat /sys/module/libata/parameters/
cat /sys/module/libata/parameters/
cat /sys/module/libata/parameters/


cat /sys/module/nf_conntrack/parameters/acct
cat /sys/module/nf_conntrack/parameters/expect_hashsize
cat /sys/module/nf_conntrack/parameters/hashsize
cat /sys/module/nf_conntrack/parameters/nf_conntrack_helper
cat /sys/module/nf_conntrack/parameters/tstamp

cat /sys/module/nf_conntrack_ipv4/parameters/hashsize


cat /sys/module/nouveau/parameters/



/sys/module/rfkill/parameters/default_state


modinfo rng-core
/lib/modules/4.16.0-parrot5-amd64/kernel/drivers/char/hw_random/rng-core.ko
parm:           current_quality:current hwrng entropy estimation per mill (ushort)
parm:           default_quality:default entropy content of hwrng per mill (ushort)



modinfo scsi_mod
/lib/modules/4.16.0-parrot5-amd64/kernel/drivers/scsi/scsi_mod.ko

parm:           dev_flags:Given scsi_dev_flags=vendor:model:flags[,v:m:f] add black/white list entries for vendor and model with an integer value of flags to the scsi device info list (string)
parm:           default_dev_flags:scsi default device flag integer value (int)
parm:           max_luns:last scsi LUN (should be between 1 and 2^64-1) (ullong)
parm:           scan:sync, async, manual, or none. Setting to 'manual' disables automatic scanning, but allows
parm:           scsi_logging_level:a bit mask of logging levels (int)


cat /sys/module/scsi_mod/parameters/scan




cat /sys/module/snd_hda_intel/parameters/


cat /sys/module/usbcore/parameters/nousb


cat /sys/module/usbcore/parameters/authorized_default




parm:           usbfs_snoop:true to log all usbfs traffic (bool)
parm:           usbfs_snoop_max:maximum number of bytes to print while snooping (uint)
parm:           usbfs_memory_mb:maximum MB allowed for usbfs buffers (0 = no limit) (uint)

parm:           authorized_default:Default USB device authorization: 0 is not authorized, 1 is authorized, -1 is authorized except for wireless USB (default, old behaviour (int)

parm:           nousb:bool


option nousb 1
option usbfs_snoop 1


modinfo usb-storage




/lib/modules/4.16.0-parrot5-amd64/kernel/drivers/hid/hid.ko
parm:           debug:toggle HID debugging messages (int)



modinfo  scsi_debug

parm:           add_host:0..127 hosts allowed(def=1) (int)
parm:           ato:application tag ownership: 0=disk 1=host (def=1) (int)
parm:           cdb_len:suggest CDB lengths to drivers (def=10) (int)
parm:           clustering:when set enables larger transfers (def=0) (bool)
parm:           delay:response delay (def=1 jiffy); 0:imm, -1,-2:tiny (int)
parm:           dev_size_mb:size in MiB of ram shared by devs(def=8) (int)
parm:           dif:data integrity field type: 0-3 (def=0) (int)
parm:           dix:data integrity extensions mask (def=0) (int)
parm:           dsense:use descriptor sense format(def=0 -> fixed) (int)
parm:           every_nth:timeout every nth command(def=0) (int)
parm:           fake_rw:fake reads/writes instead of copying (def=0) (int)
parm:           guard:protection checksum: 0=crc, 1=ip (def=0) (uint)
parm:           host_lock:host_lock is ignored (def=0) (bool)
parm:           inq_vendor:SCSI INQUIRY vendor string (def="Linux") (string)
parm:           inq_product:SCSI INQUIRY product string (def="scsi_debug") (string)
parm:           inq_rev:SCSI INQUIRY revision string (def="0187") (string)
parm:           lbpu:enable LBP, support UNMAP command (def=0) (int)
parm:           lbpws:enable LBP, support WRITE SAME(16) with UNMAP bit (def=0) (int)
parm:           lbpws10:enable LBP, support WRITE SAME(10) with UNMAP bit (def=0) (int)
parm:           lbprz:on read unmapped LBs return 0 when 1 (def), return 0xff when 2 (int)
parm:           lowest_aligned:lowest aligned lba (def=0) (int)
parm:           max_luns:number of LUNs per target to simulate(def=1) (int)
parm:           max_queue:max number of queued commands (1 to max(def)) (int)
parm:           ndelay:response delay in nanoseconds (def=0 -> ignore) (int)
parm:           no_lun_0:no LU number 0 (def=0 -> have lun 0) (int)
parm:           no_uld:stop ULD (e.g. sd driver) attaching (def=0)) (int)
parm:           num_parts:number of partitions(def=0) (int)
parm:           num_tgts:number of targets per host to simulate(def=1) (int)
parm:           opt_blks:optimal transfer length in blocks (def=1024) (int)
parm:           opts:1->noise, 2->medium_err, 4->timeout, 8->recovered_err... (def=0) (int)
parm:           physblk_exp:physical block exponent (def=0) (int)
parm:           opt_xferlen_exp:optimal transfer length granularity exponent (def=physblk_exp) (int)
parm:           ptype:SCSI peripheral type(def=0[disk]) (int)
parm:           removable:claim to have removable media (def=0) (bool)
parm:           scsi_level:SCSI level to simulate(def=7[SPC-5]) (int)
parm:           sector_size:logical block size in bytes (def=512) (int)
parm:           statistics:collect statistics on commands, queues (def=0) (bool)
parm:           strict:stricter checks: reserved field in cdb (def=0) (bool)
parm:           submit_queues:support for block multi-queue (def=1) (int)
parm:           unmap_alignment:lowest aligned thin provisioning lba (def=0) (int)
parm:           unmap_granularity:thin provisioning granularity in blocks (def=1) (int)
parm:           unmap_max_blocks:max # of blocks can be unmapped in one cmd (def=0xffffffff) (int)
parm:           unmap_max_desc:max # of ranges that can be unmapped in one cmd (def=256) (int)
parm:           uuid_ctl:1->use uuid for lu name, 0->don't, 2->all use same (def=0) (int)
parm:           virtual_gb:virtual gigabyte (GiB) size (def=0 -> use dev_size_mb) (int)
parm:           vpd_use_hostno:0 -> dev ids ignore hostno (def=1 -> unique dev ids) (int)
parm:           write_same_length:Maximum blocks per WRITE SAME cmd (def=0xffff) (int)


scsi_level
sector_size
strict
guard

fake_rw
dix
dif
ato





name:           thinkpad_acpi
description:    ThinkPad ACPI Extras
filename:       /lib/modules/4.18.0-parrot10-amd64/kernel/drivers/platform/x86/thinkpad_acpi.ko

parm:           experimental:Enables experimental features when non-zero (int)
parm:           debug:Sets debug level bit-mask (uint)
parm:           force_load:Attempts to load the driver even on a mis-identified ThinkPad when true (bool)
parm:           fan_control:Enables setting fan parameters features when true (bool)
parm:           brightness_mode:Selects brightness control strategy: 0=auto, 1=EC, 2=UCMS, 3=EC+NVRAM (uint)
parm:           brightness_enable:Enables backlight control when 1, disables when 0 (uint)
parm:           volume_mode:Selects volume control strategy: 0=auto, 1=EC, 2=N/A, 3=EC+NVRAM (uint)
parm:           volume_capabilities:Selects the mixer capabilites: 0=auto, 1=volume and mute, 2=mute only (uint)
parm:           volume_control:Enables software override for the console audio control when true (bool)
parm:           software_mute:Request full software mute control (bool)
parm:           index:ALSA index for the ACPI EC Mixer (int)
parm:           id:ALSA id for the ACPI EC Mixer (charp)
parm:           enable:Enable the ALSA interface for the ACPI EC Mixer (bool)
parm:           hotkey:Simulates thinkpad-acpi procfs command at module load, see documentation
parm:           bluetooth:Simulates thinkpad-acpi procfs command at module load, see documentation
parm:           video:Simulates thinkpad-acpi procfs command at module load, see documentation
parm:           light:Simulates thinkpad-acpi procfs command at module load, see documentation
parm:           cmos:Simulates thinkpad-acpi procfs command at module load, see documentation
parm:           led:Simulates thinkpad-acpi procfs command at module load, see documentation
parm:           beep:Simulates thinkpad-acpi procfs command at module load, see documentation
parm:           brightness:Simulates thinkpad-acpi procfs command at module load, see documentation
parm:           volume:Simulates thinkpad-acpi procfs command at module load, see documentation
parm:           fan:Simulates thinkpad-acpi procfs command at module load, see documentation






name:           thunderbolt_net
description:    Thunderbolt network driver
filename:       /lib/modules/4.18.0-parrot10-amd64/kernel/drivers/thunderbolt/thunderbolt.ko


name:           thunderbolt

filename:       /lib/modules/4.18.0-parrot10-amd64/kernel/drivers/thunderbolt/thunderbolt.ko



name:           drm
description:    DRM panel infrastructure
filename:       /lib/modules/4.18.0-parrot10-amd64/kernel/drivers/gpu/drm/drm.ko
parm:           edid_firmware:Do not probe monitor, use specified EDID blob from built-in data or /lib/firmware instead.  (string)
parm:           vblankoffdelay:Delay until vblank irq auto-disable [msecs] (0: never disable, <0: disable immediately) (int)
parm:           timestamp_precision_usec:Max. error on timestamps [usecs] (int)
parm:           edid_fixup:Minimum number of valid EDID header bytes (0-8, default 6) (int)
parm:           debug:Enable debug output, where each bit enables a debug category.
                Bit 0 (0x01) will enable CORE messages (drm core code)
                Bit 1 (0x02) will enable DRIVER messages (drm controller code)
                Bit 2 (0x04) will enable KMS messages (modesetting code)
                Bit 3 (0x08) will enable PRIME messages (prime code)
                Bit 4 (0x10) will enable ATOMIC messages (atomic code)
                Bit 5 (0x20) will enable VBL messages (vblank code)
                Bit 7 (0x80) will enable LEASE messages (leasing code) (int)



name:           drm_kms_helper
description:    DRM KMS helper
filename:       /lib/modules/4.18.0-parrot10-amd64/kernel/drivers/gpu/drm/drm_kms_helper.ko

parm:           fbdev_emulation:Enable legacy fbdev emulation [default=true] (bool)
parm:           drm_fbdev_overalloc:Overallocation of the fbdev buffer (%) [default=100] (int)
parm:           edid_firmware:DEPRECATED. Use drm.edid_firmware module parameter instead. (charp)
parm:           poll:bool
parm:           dp_aux_i2c_speed_khz:Assumed speed of the i2c bus in kHz, (1-400, default 10) (int)
parm:           dp_aux_i2c_transfer_size:Number of bytes to transfer in a single I2C over DP AUX CH message, (1-16, default 16) (int)




name:           acer_wmi
description:    Acer Laptop WMI Extras Driver
filename:       /lib/modules/4.18.0-parrot10-amd64/kernel/drivers/platform/x86/acer-wmi.ko
parm:           mailled:Set initial state of Mail LED (int)
parm:           brightness:Set initial LCD backlight brightness (int)
parm:           threeg:Set initial state of 3G hardware (int)
parm:           force_series:Force a different laptop series (int)
parm:           ec_raw_mode:Enable EC raw mode (bool)



name:           mwifiex
description:    Marvell WiFi-Ex Driver version 1.0
filename:       /lib/modules/4.18.0-parrot10-amd64/kernel/drivers/net/wireless/marvell/mwifiex/mwifiex.ko
parm:           reg_alpha2:charp
parm:           drcs:multi-channel operation:1, single-channel operation:0 (bool)
parm:           disable_auto_ds:deepsleep enabled=0(default), deepsleep disabled=1 (bool)
parm:           disconnect_on_suspend:int
parm:           disable_tx_amsdu:bool
parm:           debug_mask:bitmap for debug flags (uint)
parm:           cal_data_cfg:charp
parm:           driver_mode:station=0x1(default), ap-sta=0x3, station-p2p=0x5, ap-sta-p2p=0x7 (ushort)
parm:           mfg_mode:manufacturing mode enable:1, disable:0 (bool)
parm:           aggr_ctrl:usb tx aggregation enable:1, disable:0 (bool)



name:           wil6210
description:    Driver for 60g WiFi WIL6210 card
filename:       /lib/modules/4.18.0-parrot10-amd64/kernel/drivers/net/wireless/ath/wil6210/wil6210.ko
parm:           rtap_include_phy_info: Include PHY info in the radiotap header, default - no (bool)
parm:           rx_align_2: align Rx buffers on 4*n+2, default - no (bool)
parm:           rx_large_buf: allocate 8KB RX buffers, default - no (bool)
parm:           max_assoc_sta: Max number of stations associated to the AP (uint)
parm:           agg_wsize: Window size for Tx Block Ack after connect; 0 - use default; < 0 - don't auto-establish (int)
parm:           led_id: 60G device led enablement. Set the led ID (0-2) to enable (byte)
parm:           use_msi: Use MSI interrupt, default - true (bool)
parm:           ftm_mode: Set factory test mode, default - false (bool)
parm:           disable_ap_sme: let user space handle AP mode SME (bool)
parm:           debug_fw: do not perform card reset. For FW debug (bool)
parm:           oob_mode: enable out of the box (OOB) mode in FW, for diagnostics and certification (byte)
parm:           no_fw_recovery: disable automatic FW error recovery (bool)
parm:           rx_ring_overflow_thrsh: RX ring overflow threshold in descriptors. (ushort)
parm:           mtu_max: Max MTU value.
parm:           rx_ring_order: Rx ring order; size = 1 << order
parm:           tx_ring_order: Tx ring order; size = 1 << order
parm:           bcast_ring_order: Bcast ring order; size = 1 << order




filename:       /lib/modules/4.18.0-parrot10-amd64/kernel/drivers/char/tpm/tpm.ko
description:    TPM Driver
name:           tpm
parm:           suspend_pcr:PCR to use for dummy writes to facilitate flush on suspend. (uint)


name:           tpm_atmel
description:    TPM Driver
filename:       /lib/modules/4.18.0-parrot10-amd64/kernel/drivers/char/tpm/tpm_atmel.ko



name:           tpm_crb
description:    TPM2 Driver
filename:       /lib/modules/4.18.0-parrot10-amd64/kernel/drivers/char/tpm/tpm_crb.ko



name:           tpm_i2c_atmel
description:    Atmel TPM I2C Driver
filename:       /lib/modules/4.18.0-parrot10-amd64/kernel/drivers/char/tpm/tpm_i2c_atmel.ko


name:           tpm_infineon
description:    Driver for Infineon TPM SLD 9630 TT 1.1 / SLB 9635 TT 1.2
filename:       /lib/modules/4.18.0-parrot10-amd64/kernel/drivers/char/tpm/tpm_infineon.ko




name:           tpm_nsc
description:    TPM Driver
filename:       /lib/modules/4.18.0-parrot10-amd64/kernel/drivers/char/tpm/tpm_nsc.ko



name:           tun
description:    Universal TUN/TAP device driver
filename:       /lib/modules/4.18.0-parrot10-amd64/kernel/drivers/net/tun.ko



name:           tunnel4
filename:       /lib/modules/4.18.0-parrot10-amd64/kernel/net/ipv4/tunnel4.ko


name:           tvaudio
description:    device driver for various i2c TV sound decoder / audiomux chips
filename:       /lib/modules/4.18.0-parrot10-amd64/kernel/drivers/media/i2c/tvaudio.ko
parm:           debug:int
parm:           tda9874a_SIF:int
parm:           tda9874a_AMSEL:int
parm:           tda9874a_STD:int
parm:           tda8425:int
parm:           tda9840:int
parm:           tda9850:int
parm:           tda9855:int
parm:           tda9873:int
parm:           tda9874a:int
parm:           tda9875:int
parm:           tea6300:int
parm:           tea6320:int
parm:           tea6420:int
parm:           pic16c54:int
parm:           ta8874z:int




name:           tveeprom
description:    i2c Hauppauge eeprom decoder driver
filename:       /lib/modules/4.18.0-parrot10-amd64/kernel/drivers/media/common/tveeprom.ko


name:           ttusb_dec
description:    TechnoTrend/Hauppauge DEC USB
filename:       /lib/modules/4.18.0-parrot10-amd64/kernel/drivers/media/usb/ttusb-dec/ttusb_dec.ko

vermagic:       4.18.0-parrot10-amd64 SMP mod_unload modversions 
parm:           debug:Turn on/off debugging (default:off). (int)
parm:           output_pva:Output PVA from dvr device (default:off) (int)
parm:           enable_rc:Turn on/off IR remote control(default: off) (int)
parm:           adapter_nr:DVB adapter numbers (array of short)








name:           team_mode_activebackup
description:    Active-backup mode for team
/lib/modules/4.18.0-parrot10-amd64/kernel/drivers/net/team/team_mode_activebackup.ko



name:           tmem
description:    Shim to Xen transcendent memory
filename:       /lib/modules/4.18.0-parrot10-amd64/kernel/drivers/xen/tmem.ko
parm:           frontswap:bool



name:           ttpci_eeprom
/lib/modules/4.18.0-parrot10-amd64/kernel/drivers/media/pci/ttpci/ttpci-eeprom.ko
description:    Decode dvb_net MAC address from EEPROM of PCI DVB cards made by Siemens, Technotrend, Hauppauge



name:           ttusbir
description:    TechnoTrend USB IR Receiver
filename:       /lib/modules/4.18.0-parrot10-amd64/kernel/drivers/media/rc/ttusbir.ko



name:           wireguard
description:    WireGuard secure network tunnel
alias:          net-pf-16-proto-16-family-wireguard
alias:          rtnl-link-wireguard
filename:       /lib/modules/4.18.0-parrot10-amd64/kernel/net/wireguard.ko






name:           wusbcore
description:    Wireless USB core
filename:       /lib/modules/4.18.0-parrot10-amd64/kernel/drivers/usb/wusbcore/wusbcore.ko
parm:           debug_crypto_verify:verify the key generation algorithms (int)





name:           esp_scsi
filename:       /lib/modules/4.18.0-parrot10-amd64/kernel/drivers/scsi/esp_scsi.ko
description:    ESP SCSI driver core
parm:           esp_bus_reset_settle:ESP scsi bus reset delay in seconds (int)
parm:           esp_debug:ESP bitmapped debugging message enable value:
        0x00000001      Log interrupt events
        0x00000002      Log scsi commands
        0x00000004      Log resets
        0x00000008      Log message in events
        0x00000010      Log message out events
        0x00000020      Log command completion
        0x00000040      Log disconnects
        0x00000080      Log data start
        0x00000100      Log data done
        0x00000200      Log reconnects
        0x00000400      Log auto-sense data
         (int)








name:           ext4
alias:          fs-ext4
alias:          ext3
alias:          fs-ext3
alias:          ext2
alias:          fs-ext2
description:    Fourth Extended Filesystem
/lib/modules/4.18.0-parrot10-amd64/kernel/fs/ext4/ext4.ko


name:           eeepc_laptop
filename:       /lib/modules/4.18.0-parrot10-amd64/kernel/drivers/platform/x86/eeepc-laptop.ko
description:    Eee PC Hotkey Driver
parm:           hotplug_disabled:Disable hotplug for wireless device. If your laptop need that, please report to acpi4asus-user@lists.sourceforge.
net. (bool)



name:           eeepc_wmi
filename:       /lib/modules/4.18.0-parrot10-amd64/kernel/drivers/platform/x86/eeepc-wmi.ko
alias:          wmi:ABBC0F72-8EA1-11D1-00A0-C90629100000
description:    Eee PC WMI Hotkey Driver
parm:           hotplug_wireless:Enable hotplug for wireless device. If your laptop needs that, please report to acpi4asus-user@lists.sourceforge.net. (bool)







































sparse-keymap


wmi








modinfo dell-smm-hwmon

parm:           force:Force loading without checking for supported models (bool)
parm:           ignore_dmi:Continue probing hardware even if DMI data does not match (bool)
parm:           restricted:Restrict fan control and serial number to CAP_SYS_ADMIN (default: 1) (bool)
parm:           power_status:Report power status in /proc/i8k (default: 0) (bool)
parm:           fan_mult:Factor to multiply fan speed with (default: autodetect) (uint)
parm:           fan_max:Maximum configurable fan speed (default: autodetect) (uint)










name:           scsi_mod


snd_hda_codec_hdmi
parm:           static_hdmi_pcm:Don't restrict PCM parameters per ELD info (bool)


snd_hda_intel
option snoop disable            ## disable snooping

name:           usbcore
parm:           usbfs_snoop:true to log all usbfs traffic (bool)
parm:           usbfs_snoop_max:maximum number of bytes to print while snooping (uint)
parm:           usbfs_memory_mb:maximum MB allowed for usbfs buffers (0 = no limit) (uint)
parm:           authorized_default:Default USB device authorization: 0 is not authorized, 1 is authorized, -1 is authorized except for wireless USB (default, old behaviour (int)


name:           scsi_mod
vermagic:       4.16.0-parrot5-amd64 SMP mod_unload modversions 
parm:           dev_flags:Given scsi_dev_flags=vendor:model:flags[,v:m:f] add black/white list entries for vendor and model with an integer value of flags to the scsi device info list (string)
parm:           default_dev_flags:scsi default device flag integer value (int)
parm:           scsi_logging_level:a bit mask of logging levels (int)


echo "## ======================================================================================== ##"





ls /sys/module/*/parameters


/sys/module/nf_conntrack/parameters:
acct  expect_hashsize  hashsize  nf_conntrack_helper  tstamp

/sys/module/ipv6/parameters:
autoconf  disable  disable_ipv6

/sys/module/drm_kms_helper/parameters:
dp_aux_i2c_speed_khz  dp_aux_i2c_transfer_size  drm_fbdev_overalloc  edid_firmware  fbdev_emulation  poll

/sys/module/drm/parameters:
debug  edid_firmware  edid_fixup  timestamp_precision_usec  vblankoffdelay

/sys/module/apparmor/parameters:
audit  audit_header  debug  enabled  hash_policy  lock_policy  logsyscall  mode  paranoid_load  path_max

/sys/module/block/parameters:
events_dfl_poll_msecs







name:           nouveau
filename:       /lib/modules/4.18.0-parrot10-amd64/kernel/drivers/gpu/drm/nouveau/nouveau.ko


description:    nVidia Riva/TNT/GeForce/Quadro/Tesla/Tegra K1+
author:         Nouveau Project
alias:          pci:v000012D2d*sv*sd*bc03sc*i*
alias:          pci:v000010DEd*sv*sd*bc03sc*i*
depends:        drm,drm_kms_helper,ttm,mxm-wmi,button,wmi,video,i2c-algo-bit
retpoline:      Y
intree:         Y
name:           nouveau
vermagic:       4.18.0-parrot10-amd64 SMP mod_unload modversions 
parm:           vram_pushbuf:Create DMA push buffers in VRAM (int)
parm:           tv_norm:Default TV norm.
		Supported: PAL, PAL-M, PAL-N, PAL-Nc, NTSC-M, NTSC-J,
			hd480i, hd480p, hd576i, hd576p, hd720p, hd1080i.
		Default: PAL
		*NOTE* Ignored for cards with external TV encoders. (charp)
parm:           nofbaccel:Disable fbcon acceleration (int)
parm:           fbcon_bpp:fbcon bits-per-pixel (default: auto) (int)
parm:           mst:Enable DisplayPort multi-stream (default: enabled) (int)
parm:           tv_disable:Disable TV-out detection (int)
parm:           ignorelid:Ignore ACPI lid status (int)
parm:           duallink:Allow dual-link TMDS (default: enabled) (int)
parm:           hdmimhz:Force a maximum HDMI pixel clock (in MHz) (int)
parm:           config:option string to pass to driver core (charp)
parm:           debug:debug string to pass to driver core (charp)
parm:           noaccel:disable kernel/abi16 acceleration (int)
parm:           modeset:enable driver (default: auto, 0 = disabled, 1 = enabled, 2 = headless) (int)
parm:           atomic:Expose atomic ioctl (default: disabled) (int)
parm:           runpm:disable (0), force enable (1), optimus only default (-1) (int)






name:           drm
parm:           edid_firmware:Do not probe monitor, use specified EDID blob from built-in data or /lib/firmware instead.  (string)
parm:           vblankoffdelay:Delay until vblank irq auto-disable [msecs] (0: never disable, <0: disable immediately) (int)
parm:           timestamp_precision_usec:Max. error on timestamps [usecs] (int)
parm:           edid_fixup:Minimum number of valid EDID header bytes (0-8, default 6) (int)
parm:           debug:Enable debug output, where each bit enables a debug category.
                Bit 0 (0x01) will enable CORE messages (drm core code)
                Bit 1 (0x02) will enable DRIVER messages (drm controller code)
                Bit 2 (0x04) will enable KMS messages (modesetting code)
                Bit 3 (0x08) will enable PRIME messages (prime code)
                Bit 4 (0x10) will enable ATOMIC messages (atomic code)
                Bit 5 (0x20) will enable VBL messages (vblank code)
                Bit 7 (0x80) will enable LEASE messages (leasing code) (int)




name:           drm_kms_helper
vermagic:       4.16.0-parrot5-amd64 SMP mod_unload modversions 
parm:           fbdev_emulation:Enable legacy fbdev emulation [default=true] (bool)
parm:           drm_fbdev_overalloc:Overallocation of the fbdev buffer (%) [default=100] (int)
parm:           edid_firmware:DEPRECATED. Use drm.edid_firmware module parameter instead. (charp)
parm:           poll:bool
parm:           dp_aux_i2c_speed_khz:Assumed speed of the i2c bus in kHz, (1-400, default 10) (int)
parm:           dp_aux_i2c_transfer_size:Number of bytes to transfer in a single I2C over DP AUX CH message, (1-16, default 16) 


name:           nouveau
vermagic:       4.16.0-parrot5-amd64 SMP mod_unload modversions 
parm:           tv_norm:Default TV norm.
                Supported: PAL, PAL-M, PAL-N, PAL-Nc, NTSC-M, NTSC-J,
                        hd480i, hd480p, hd576i, hd576p, hd720p, hd1080i.
                Default: PAL
                *NOTE* Ignored for cards with external TV encoders. (charp)
parm:           vram_pushbuf:Create DMA push buffers in VRAM (int)
parm:           nofbaccel:Disable fbcon acceleration (int)
parm:           fbcon_bpp:fbcon bits-per-pixel (default: auto) (int)
parm:           mst:Enable DisplayPort multi-stream (default: enabled) (int)
parm:           atomic:Expose atomic ioctl (default: disabled) (int)
parm:           tv_disable:Disable TV-out detection (int)
parm:           ignorelid:Ignore ACPI lid status (int)
parm:           duallink:Allow dual-link TMDS (default: enabled) (int)
parm:           hdmimhz:Force a maximum HDMI pixel clock (in MHz) (int)
parm:           config:option string to pass to driver core (charp)
parm:           debug:debug string to pass to driver core (charp)
parm:           noaccel:disable kernel/abi16 acceleration (int)
parm:           modeset:enable driver (default: auto, 0 = disabled, 1 = enabled, 2 = headless) (int)
parm:           runpm:disable (0), force enable (1), optimus only default (-1) (int)











usbcore
vermagic:       4.16.0-parrot5-amd64 SMP mod_unload modversions 
parm:           usbfs_snoop:true to log all usbfs traffic (bool)
parm:           usbfs_snoop_max:maximum number of bytes to print while snooping (uint)
parm:           usbfs_memory_mb:maximum MB allowed for usbfs buffers (0 = no limit) (uint)
parm:           authorized_default:Default USB device authorization: 0 is not authorized, 1 is authorized, -1 is authorized except for wireless USB (default, old behaviour (int)
parm:           blinkenlights:true to cycle leds on hubs (bool)
parm:           initial_descriptor_timeout:initial 64-byte descriptor request timeout in milliseconds (default 5000 - 5.0 seconds) (int)
parm:           old_scheme_first:start with the old device initialization scheme (bool)
parm:           use_both_schemes:try the other device initialization scheme if the first one fails (bool)
parm:           nousb:bool
parm:           autosuspend:default autosuspend delay (int)




usbhid
vermagic:       4.16.0-parrot5-amd64 SMP mod_unload modversions 
parm:           mousepoll:Polling interval of mice (uint)
parm:           jspoll:Polling interval of joysticks (uint)
parm:           ignoreled:Autosuspend with active leds (uint)
parm:           quirks:Add/modify USB HID quirks by specifying  quirks=vendorID:productID:quirks where vendorID, productID, and quirks are all in 0x-p




cryptd
parm:           cryptd_max_cpu_qlen:Set cryptd Max queue depth (uint)


dm_mod
vermagic:       4.16.0-parrot5-amd64 SMP mod_unload modversions 
parm:           reserved_rq_based_ios:Reserved IOs in request-based mempools (uint)
parm:           use_blk_mq:Use block multiqueue for request-based DM devices (bool)
parm:           dm_mq_nr_hw_queues:Number of hardware queues for request-based dm-mq devices (uint)
parm:           dm_mq_queue_depth:Queue depth for request-based dm-mq devices (uint)
parm:           stats_current_allocated_bytes:Memory currently used by statistics (ulong)
parm:           major:The major number of the device mapper (uint)
parm:           reserved_bio_based_ios:Reserved IOs in bio-based mempools (uint)
parm:           dm_numa_node:NUMA node for DM device memory allocations (int)



drm
vermagic:       4.16.0-parrot5-amd64 SMP mod_unload modversions 
parm:           edid_firmware:Do not probe monitor, use specified EDID blob from built-in data or /lib/firmware instead.  (string)
parm:           vblankoffdelay:Delay until vblank irq auto-disable [msecs] (0: never disable, <0: disable immediately) (int)
parm:           timestamp_precision_usec:Max. error on timestamps [usecs] (int)
parm:           edid_fixup:Minimum number of valid EDID header bytes (0-8, default 6) (int)
parm:           debug:Enable debug output, where each bit enables a debug category.
                Bit 0 (0x01) will enable CORE messages (drm core code)
                Bit 1 (0x02) will enable DRIVER messages (drm controller code)
                Bit 2 (0x04) will enable KMS messages (modesetting code)
                Bit 3 (0x08) will enable PRIME messages (prime code)
                Bit 4 (0x10) will enable ATOMIC messages (atomic code)
                Bit 5 (0x20) will enable VBL messages (vblank code)
                Bit 7 (0x80) will enable LEASE messages (leasing code) (int)
filename:       /lib/modules/4.16.0-parrot5-amd64/kernel/drivers/gpu/drm/nouveau/nouveau.ko
firmware:       nvidia/gp100/gr/sw_method_init.bin
firmware:       nvidia/gp100/gr/sw_bundle_init.bin
firmware:       nvidia/gp100/gr/sw_nonctx.bin
firmware:       nvidia/gp100/gr/sw_ctx.bin
firmware:       nvidia/gp100/gr/gpccs_sig.bin
firmware:       nvidia/gp100/gr/gpccs_data.bin
firmware:       nvidia/gp100/gr/gpccs_inst.bin
firmware:       nvidia/gp100/gr/gpccs_bl.bin
firmware:       nvidia/gp100/gr/fecs_sig.bin
firmware:       nvidia/gp100/gr/fecs_data.bin
firmware:       nvidia/gp100/gr/fecs_inst.bin
firmware:       nvidia/gp100/gr/fecs_bl.bin
firmware:       nvidia/gp100/acr/ucode_unload.bin
firmware:       nvidia/gp100/acr/ucode_load.bin
firmware:       nvidia/gp100/acr/bl.bin
firmware:       nvidia/gm206/gr/sw_method_init.bin
firmware:       nvidia/gm206/gr/sw_bundle_init.bin
firmware:       nvidia/gm206/gr/sw_nonctx.bin
firmware:       nvidia/gm206/gr/sw_ctx.bin
firmware:       nvidia/gm206/gr/gpccs_sig.bin
firmware:       nvidia/gm206/gr/gpccs_data.bin
firmware:       nvidia/gm206/gr/gpccs_inst.bin
firmware:       nvidia/gm206/gr/gpccs_bl.bin
firmware:       nvidia/gm206/gr/fecs_sig.bin
firmware:       nvidia/gm206/gr/fecs_data.bin
firmware:       nvidia/gm206/gr/fecs_inst.bin
firmware:       nvidia/gm206/gr/fecs_bl.bin
firmware:       nvidia/gm206/acr/ucode_unload.bin
firmware:       nvidia/gm206/acr/ucode_load.bin
firmware:       nvidia/gm206/acr/bl.bin
firmware:       nvidia/gm204/gr/sw_method_init.bin
firmware:       nvidia/gm204/gr/sw_bundle_init.bin





Nouveau Project
depends:        drm,drm_kms_helper,ttm,mxm-wmi,button,wmi,video,i2c-algo-bit
nouveau
vermagic:       4.16.0-parrot5-amd64 SMP mod_unload modversions 
parm:           tv_norm:Default TV norm.
                Supported: PAL, PAL-M, PAL-N, PAL-Nc, NTSC-M, NTSC-J,
                        hd480i, hd480p, hd576i, hd576p, hd720p, hd1080i.
                Default: PAL
                *NOTE* Ignored for cards with external TV encoders. (charp)
parm:           vram_pushbuf:Create DMA push buffers in VRAM (int)
parm:           nofbaccel:Disable fbcon acceleration (int)
parm:           fbcon_bpp:fbcon bits-per-pixel (default: auto) (int)
parm:           mst:Enable DisplayPort multi-stream (default: enabled) (int)
parm:           atomic:Expose atomic ioctl (default: disabled) (int)
parm:           tv_disable:Disable TV-out detection (int)
parm:           ignorelid:Ignore ACPI lid status (int)
parm:           duallink:Allow dual-link TMDS (default: enabled) (int)
parm:           hdmimhz:Force a maximum HDMI pixel clock (in MHz) (int)
parm:           config:option string to pass to driver core (charp)
parm:           debug:debug string to pass to driver core (charp)
parm:           noaccel:disable kernel/abi16 acceleration (int)
parm:           modeset:enable driver (default: auto, 0 = disabled, 1 = enabled, 2 = headless) (int)
parm:           runpm:disable (0), force enable (1), optimus only default (-1) (int)


DRM KMS helper

drm_kms_helper
vermagic:       4.16.0-parrot5-amd64 SMP mod_unload modversions 
parm:           fbdev_emulation:Enable legacy fbdev emulation [default=true] (bool)
parm:           drm_fbdev_overalloc:Overallocation of the fbdev buffer (%) [default=100] (int)
parm:           edid_firmware:DEPRECATED. Use drm.edid_firmware module parameter instead. (charp)
parm:           poll:bool
parm:           dp_aux_i2c_speed_khz:Assumed speed of the i2c bus in kHz, (1-400, default 10) (int)
parm:           dp_aux_i2c_transfer_size:Number of bytes to transfer in a single I2C over DP AUX CH message, (1-16, default 16) (int)



kvm
vermagic:       4.16.0-parrot5-amd64 SMP mod_unload modversions 
parm:           ignore_msrs:bool
parm:           report_ignored_msrs:bool
parm:           min_timer_period_us:uint
parm:           kvmclock_periodic_sync:bool
parm:           tsc_tolerance_ppm:uint
parm:           lapic_timer_advance_ns:uint
parm:           vector_hashing:bool
parm:           halt_poll_ns:uint
parm:           halt_poll_ns_grow:uint
parm:           halt_poll_ns_shrink:uint


kvm_amd
vermagic:       4.16.0-parrot5-amd64 SMP mod_unload modversions 
parm:           npt:int
parm:           nested:int
parm:           avic:int
parm:           vls:int
parm:           vgif:int
parm:           sev:int


snd_hda_intel
vermagic:       4.16.0-parrot5-amd64 SMP mod_unload modversions 
parm:           index:Index value for Intel HD audio interface. (array of int)
parm:           id:ID string for Intel HD audio interface. (array of charp)
parm:           enable:Enable Intel HD audio interface. (array of bool)
parm:           model:Use the given board model. (array of charp)
parm:           position_fix:DMA pointer read method.(-1 = system default, 0 = auto, 1 = LPIB, 2 = POSBUF, 3 = VIACOMBO, 4 = COMBO, 5 = SKL+). (array of int)
parm:           bdl_pos_adj:BDL position adjustment offset. (array of int)
parm:           probe_mask:Bitmask to probe codecs (default = -1). (array of int)
parm:           probe_only:Only probing and no codec initialization. (array of int)
parm:           jackpoll_ms:Ms between polling for jack events (default = 0, using unsol events only) (array of int)
parm:           single_cmd:Use single command to communicate with codecs (for debugging only). (bint)
parm:           enable_msi:Enable Message Signaled Interrupt (MSI) (bint)
parm:           patch:Patch file for Intel HD audio interface. (array of charp)
parm:           beep_mode:Select HDA Beep registration mode (0=off, 1=on) (default=1). (array of bool)
parm:           power_save:Automatic power-saving timeout (in second, 0 = disable). (xint)
parm:           pm_blacklist:Enable power-management blacklist (bool)
parm:           power_save_controller:Reset controller in power save mode. (bool)
parm:           align_buffer_size:Force buffer and period sizes to be multiple of 128 bytes. (bint)
parm:           snoop:Enable/disable snooping (bint)






name:           usbcore
vermagic:       4.16.0-parrot5-amd64 SMP mod_unload modversions 
parm:           usbfs_snoop:true to log all usbfs traffic (bool)
parm:           usbfs_snoop_max:maximum number of bytes to print while snooping (uint)
parm:           usbfs_memory_mb:maximum MB allowed for usbfs buffers (0 = no limit) (uint)
parm:           authorized_default:Default USB device authorization: 0 is not authorized, 1 is authorized, -1 is authorized except for wireless USB (default, old behaviour (int)
parm:           blinkenlights:true to cycle leds on hubs (bool)
parm:           initial_descriptor_timeout:initial 64-byte descriptor request timeout in milliseconds (default 5000 - 5.0 seconds) (int)
parm:           old_scheme_first:start with the old device initialization scheme (bool)
parm:           use_both_schemes:try the other device initialization scheme if the first one fails (bool)
parm:           nousb:bool
parm:           autosuspend:default autosuspend delay (int)




name:           scsi_mod
vermagic:       4.16.0-parrot5-amd64 SMP mod_unload modversions 
parm:           dev_flags:Given scsi_dev_flags=vendor:model:flags[,v:m:f] add black/white list entries for vendor and model with an integer value of flags to the scsi device info list (string)
parm:           default_dev_flags:scsi default device flag integer value (int)
parm:           max_luns:last scsi LUN (should be between 1 and 2^64-1) (ullong)
parm:           scan:sync, async, manual, or none. Setting to 'manual' disables automatic scanning, but allows for manual device scan via the 'scan' sysfs attribute. (string)
parm:           inq_timeout:Timeout (in seconds) waiting for devices to answer INQUIRY. Default is 20. Some devices may need more; most need less. (uint)
parm:           eh_deadline:SCSI EH timeout in seconds (should be between 0 and 2^31-1) (int)
parm:           scsi_logging_level:a bit mask of logging levels (int)
parm:           use_blk_mq:bool
















nf_conntrack	
parm:           tstamp:Enable connection tracking flow timestamping. (bool)
parm:           acct:Enable connection tracking flow accounting. (bool)
parm:           nf_conntrack_helper:Enable automatic conntrack helper assignment (default 0) (bool)
parm:           expect_hashsize:uint

cfg80211
parm:           bss_entries_limit:limit to number of scan BSS entries (per wiphy, default 1000) (int)
parm:           ieee80211_regdom:IEEE 802.11 regulatory domain code (charp)
parm:           cfg80211_disable_40mhz_24ghz:Disable 40MHz support in the 2.4GHz band (bool)

ip6_tunnel
parm:           log_ecn_error:Log packets received with corrupted ECN (bool)





blacklist bluecard_cs
blacklist 

echo -e "options ipv6 disable=1" >> /etc/modprobe.d/usgcb-blacklist.conf


applesmc
appletouch

bluetooth
disable_esco:Disable eSCO connection creation (bool)
disable_ertm:Disable enhanced retransmission mode (bool)

rfcomm
disable_cfc:Disable credit based flow control (bool)
channel_mtu:Default MTU for the RFCOMM channel (int)
l2cap_mtu:Default MTU for the L2CAP connection (uint)
l2cap_ertm:Use L2CAP ERTM mode for connection (bool)


options ip6_gre log_ecn_error=1


ip6t_NPT
ip6t_rt

ip6_udp_tunnel

toshiba_bluetooth


parm:           debug:AFS debugging mask (uint)
parm:           rootcell:root AFS cell name and VL server IP addr list


cifs
parm:           CIFSMaxBufSize:Network buffer size (not including header). Default: 16384 Range: 8192 to 130048 (uint)
parm:           cifs_min_rcv:Network buffers in pool. Default: 4 Range: 1 to 64 (uint)
parm:           cifs_min_small:Small network buffers in pool. Default: 30 Range: 2 to 256 (uint)
parm:           cifs_max_pending:Simultaneous requests to server. Default: 32767 Range: 2 to 32767. (uint)
parm:           enable_oplocks:Enable or disable oplocks. Default: y/Y/1 (bool)

nfsd
parm:           cltrack_prog:Path to the nfsdcltrack upcall program (string)
parm:           cltrack_legacy_disable:Disable legacy recoverydir conversion. Default: false (bool)
parm:           nfs4_disable_idmapping:Turn off server's NFSv4 idmapping when using 'sec=sys' (bool)

nfs
parm:           callback_tcpport:portnr
parm:           callback_nr_threads:Number of threads that will be assigned to the NFSv4 callback channels. (ushort)
parm:           nfs_idmap_cache_timeout:int
parm:           nfs4_disable_idmapping:Turn off NFSv4 idmapping when using 'sec=sys' (bool)
parm:           max_session_slots:Maximum number of outstanding NFSv4.1 requests the client will negotiate (ushort)
parm:           max_session_cb_slots:Maximum number of parallel NFSv4.1 callbacks the client will process for a given server (ushort)
parm:           send_implementation_id:Send implementation ID with NFSv4.1 exchange_id (ushort)
parm:           nfs4_unique_id:nfs_client_id4 uniquifier string (string)
parm:           recover_lost_locks:If the server reports that a lock might be lost, try to recover it risking data corruption. (bool)
parm:           enable_ino64:bool
parm:           nfs_access_max_cachesize:NFS access maximum total cache length (ulong)


overlay
parm:           check_copy_up:bool
parm:           ovl_check_copy_up:Warn on copy-up when causing process also has a R/O fd open
parm:           redirect_max:ushort
parm:           ovl_redirect_max:Maximum length of absolute redirect xattr value
parm:           redirect_dir:bool
parm:           ovl_redirect_dir_def:Default to on or off for the redirect_dir feature
parm:           redirect_always_follow:bool
parm:           ovl_redirect_always_follow:Follow redirects even if redirect_dir feature is turned off
parm:           index:bool
parm:           ovl_index_def:Default to on or off for the inodes index feature
parm:           nfs_export:bool
parm:           ovl_nfs_export_def:Default to on or off for the NFS export feature


ramoops
parm:           record_size:size of each dump done on oops/panic (ulong)
parm:           console_size:size of kernel console log (ulong)
parm:           ftrace_size:size of ftrace log (ulong)
parm:           pmsg_size:size of user space message log (ulong)
parm:           mem_address:start of reserved RAM used to store oops/panic logs (ullong)
parm:           mem_size:size of reserved RAM used to store oops/panic logs (ulong)
parm:           mem_type:set to 1 to try to use unbuffered memory (default 0) (uint)
parm:           dump_oops:set to 1 to dump oopses, 0 to only dump panics (default 1) (int)
parm:           ecc:int
parm:           ramoops_ecc:if non-zero, the option enables ECC support and specifies ECC buffer size in bytes (1 is a special value, means 16 bytes E




libata
parm:           zpodd_poweroff_delay:Poweroff delay for ZPODD in seconds (int)
parm:           acpi_gtf_filter:filter mask for ACPI _GTF commands, set to filter out (0x1=set xfermode, 0x2=lock/freeze lock, 0x4=DIPM, 0x8=FPDMA non
parm:           force:Force ATA configurations including cable type, link speed and transfer mode (see Documentation/admin-guide/kernel-parameters.rst for details) (string)
parm:           atapi_enabled:Enable discovery of ATAPI devices (0=off, 1=on [default]) (int)
parm:           atapi_dmadir:Enable ATAPI DMADIR bridge support (0=off [default], 1=on) (int)
parm:           atapi_passthru16:Enable ATA_16 passthru for ATAPI devices (0=off, 1=on [default]) (int)
parm:           fua:FUA support (0=off [default], 1=on) (int)
parm:           ignore_hpa:Ignore HPA limit (0=keep BIOS limits, 1=ignore limits, using full disk) (int)
parm:           dma:DMA enable/disable (0x1==ATA, 0x2==ATAPI, 0x4==CF) (int)
parm:           ata_probe_timeout:Set ATA probing timeout (seconds) (int)
parm:           noacpi:Disable the use of ACPI in probe/suspend/resume (0=off [default], 1=on) (int)
parm:           allow_tpm:Permit the use of TPM commands (0=off [default], 1=on) (int)
parm:           atapi_an:Enable ATAPI AN media presence notification (0=0ff [default], 1=on) (int)


pata_ali
parm:           atapi_dma:Enable ATAPI DMA (0=disable, 1=enable) (int)


name:           pata_it821x
vermagic:       4.16.0-parrot5-amd64 SMP mod_unload modversions 
parm:           noraid:Force card into bypass mode (int)


name:           sata_mv
vermagic:       4.16.0-parrot5-amd64 SMP mod_unload modversions 
parm:           msi:Enable use of PCI MSI (0=off, 1=on) (int)
parm:           irq_coalescing_io_count:IRQ coalescing I/O count threshold (0..255) (int)
parm:           irq_coalescing_usecs:IRQ coalescing time threshold in usecs (int)


name:           sata_nv
vermagic:       4.16.0-parrot5-amd64 SMP mod_unload modversions 
parm:           adma:Enable use of ADMA (Default: false) (bool)
parm:           swncq:Enable use of SWNCQ (Default: true) (bool)
parm:           msi:Enable use of MSI (Default: false) (bool)


name:           sata_sil24
vermagic:       4.16.0-parrot5-amd64 SMP mod_unload modversions 
parm:           msi:Enable MSI (Default: false) (bool)


name:           sata_via
vermagic:       4.16.0-parrot5-amd64 SMP mod_unload modversions 
parm:           vt6420_hotplug:Enable hot-plug support for VT6420 (0=Don't support, 1=support) (int)


name:           ambassador
vermagic:       4.16.0-parrot5-amd64 SMP mod_unload modversions 
parm:           debug:debug bitmap, see .h file (ushort)
parm:           cmds:number of command queue entries (uint)
parm:           txs:number of TX queue entries (uint)
parm:           rxs:number of RX queue entries [4] (array of uint)
parm:           rxs_bs:size of RX buffers [4] (array of uint)
parm:           rx_lats:number of extra buffers to cope with RX latencies (uint)
parm:           pci_lat:PCI latency in bus cycles (byte)


he
vermagic:       4.16.0-parrot5-amd64 SMP mod_unload modversions 
parm:           disable64:disable 64-bit pci bus transfers (bool)
parm:           nvpibits:numbers of bits for vpi (default 0) (short)
parm:           nvcibits:numbers of bits for vci (default 12) (short)
parm:           rx_skb_reserve:padding for receive skb (default 16) (short)
parm:           irq_coalesce:use interrupt coalescing (default 1) (bool)
parm:           sdh:use SDH framing (default 0) (bool)
/

brd
vermagic:       4.16.0-parrot5-amd64 SMP mod_unload modversions 
parm:           rd_nr:Maximum number of brd devices (int)
parm:           rd_size:Size of each RAM disk in kbytes. (ulong)
parm:           max_part:Num Minors to reserve between devices (int)
/


Generic Bluetooth USB driver ver 0.8
usbcore,btbcm,bluetooth,btrtl,btintel
btusb
parm:           disable_scofix:Disable fixup of wrong SCO buffer size (bool)
parm:           force_scofix:Force fixup of wrong SCO buffers size (bool)
parm:           enable_autosuspend:Enable USB autosuspend by default (bool)
parm:           reset:Send HCI reset command on initialization (bool)


Bluetooth HCI UART driver ver 2.3
hci_uart
parm:           txcrc:Transmit CRC with every BCSP packet (bool)
parm:           hciextn:Convert HCI Extensions into BCSP packets (bool)



Bluetooth virtual HCI driver ver 1.5
hci_vhci
parm:           amp:Create AMP controller device (bool)


cdrom
parm:           debug:bool
parm:           autoclose:bool
parm:           autoeject:bool
parm:           lockdoor:bool
parm:           check_media_type:bool
parm:           mrw_format_restart:bool

hangcheck_timer
vermagic:       4.16.0-parrot5-amd64 SMP mod_unload modversions 
parm:           hangcheck_tick:Timer delay. (int)
parm:           hangcheck_margin:If the hangcheck timer has been delayed more than hangcheck_margin seconds, the driver will fire. (int)
parm:           hangcheck_reboot:If nonzero, the machine will reboot when the timer margin is exceeded. (int)
parm:           hangcheck_dump_tasks:If nonzero, the machine will dump the system task state when the timer margin is exceeded. (int)


raw
vermagic:       4.16.0-parrot5-amd64 SMP mod_unload modversions 
parm:           max_raw_minors:Maximum number of raw devices (1-65536) (int)


acpi_cpufreq
vermagic:       4.16.0-parrot5-amd64 SMP mod_unload modversions 
parm:           acpi_pstate_strict:value 0 or non-zero. non-zero -> strict ACPI checks are performed during frequency changes. (uint)







crypto-sha256-padlock
sha256-all
crypto-sha256-all

amd64_edac_mod
parm:           report_gart_errors:int
parm:           ecc_enable_override:int
parm:           edac_op_state:EDAC Error Reporting state: 0=Poll,1=NMI (int)


e752x_edac
vermagic:       4.16.0-parrot5-amd64 SMP mod_unload modversions 
parm:           force_function_unhide:if BIOS sets Dev0:Fun1 up as hidden: 1=force unhide and hope BIOS doesn't fight driver for Dev0:Fun1 access (int)
parm:           edac_op_state:EDAC Error Reporting state: 0=Poll,1=NMI (int)
parm:           sysbus_parity:0=disable system bus parity checking, 1=enable system bus parity checking, default=auto-detect (int)
parm:           report_non_memory_errors:0=disable non-memory error reporting, 1=enable non-memory error reporting (int)


i3000_edac
vermagic:       4.16.0-parrot5-amd64 SMP mod_unload modversions 
parm:           edac_op_state:EDAC Error Reporting state: 0=Poll,1=NMI (int)


i5000_edac
vermagic:       4.16.0-parrot5-amd64 SMP mod_unload modversions 
parm:           edac_op_state:EDAC Error Reporting state: 0=Poll,1=NMI (int)
parm:           misc_messages:Log miscellaneous non fatal messages (int)



firewire_ohci
vermagic:       4.16.0-parrot5-amd64 SMP mod_unload modversions 
parm:           quirks:Chip quirks (default = 0, nonatomic cycle timer = 0x1, reset packet generation = 0x2, AR/selfID endianness = 0x4, no 1394a enhancements = 0x8, disable MSI = 0x10, TI SLLZ059 erratum = 0x20, IR wake unreliable = 0x40) (int)
parm:           debug:Verbose logging (default = 0, AT/AR events = 1, self-IDs = 2, IRQs = 4, busReset events = 8, or a combination, or all = -1) (int)
parm:           remote_dma:Enable unfiltered remote DMA (default = N) (bool)



dell_rbu
Driver for updating BIOS image on DELL systems
/lib/modules/4.16.0-parrot5-amd64/kernel/drivers/firmware/dell_rbu.ko

parm:           image_type:BIOS image type. choose- mono or packet or init (string)
parm:           allocation_floor:Minimum address for allocations when using Packet mode (ulong)


hid_apple
parm:           fnmode:Mode of fn key on Apple keyboards (0 = disabled, [1] = fkeyslast, 2 = fkeysfirst) (uint)
parm:           iso_layout:Enable/Disable hardcoded ISO-layout of the keyboard. (0 = disabled, [1] = enabled) (uint)
parm:           swap_opt_cmd:Swap the Option ("Alt") and Command ("Flag") keys. (For people who want to keep Windows PC keyboard muscle memory. [0] = as-is, Mac layout. 1 = swapped, Windows layout.) (uint)

HID Apple IR remote controls
hid_appleir
/lib/modules/4.16.0-parrot5-amd64/kernel/drivers/hid/hid-asus.ko
/lib/modules/4.16.0-parrot5-amd64/kernel/drivers/hid/hid-apple.ko


hid
parm:           debug:toggle HID debugging messages (int)
parm:           ignore_special_drivers:Ignore any special drivers and handle all devices by generic driver (int)


hid_logitech_hidpp
vermagic:       4.16.0-parrot5-amd64 SMP mod_unload modversions 
parm:           disable_raw_mode:Disable Raw mode reporting for touchpads and keep firmware gestures. (bool)
parm:           disable_tap_to_click:Disable Tap-To-Click mode reporting for touchpads (only on the K400 currently). (bool)
GG


abituguru
vermagic:       4.16.0-parrot5-amd64 SMP mod_unload modversions 
parm:           force:Set to one to force detection. (bool)
parm:           bank1_types:Bank1 sensortype autodetection override:
   -1 autodetect
    0 volt sensor
    1 temp sensor
    2 not connected (array of int)
parm:           fan_sensors:Number of fan sensors on the uGuru (0 = autodetect) (int)
parm:           pwms:Number of PWMs on the uGuru (0 = autodetect) (int)
parm:           verbose:How verbose should the driver be? (0-3):
   0 normal output
   1 + verbose error reporting
   2 + sensors type probing info
   3 + retryable error reporting (int)



 acpi_power_meter
vermagic:       4.16.0-parrot5-amd64 SMP mod_unload modversions 
parm:           force_cap_on:Enable power cap even it is unsafe to do so. (bool)



adm1021
vermagic:       4.16.0-parrot5-amd64 SMP mod_unload modversions 
parm:           read_only:Don't set any values, read only mode (bool)



Dell laptop SMM BIOS hwmon driver
dell_smm_hwmon
vermagic:       4.16.0-parrot5-amd64 SMP mod_unload modversions 
parm:           force:Force loading without checking for supported models (bool)
parm:           ignore_dmi:Continue probing hardware even if DMI data does not match (bool)
parm:           restricted:Restrict fan control and serial number to CAP_SYS_ADMIN (default: 1) (bool)
parm:           power_status:Report power status in /proc/i8k (default: 0) (bool)
parm:           fan_mult:Factor to multiply fan speed with (default: autodetect) (uint)
parm:           fan_max:Maximum configurable fan speed (default: autodetect) (uint)


DME1737 sensors
dme1737
vermagic:       4.16.0-parrot5-amd64 SMP mod_unload modversions 
parm:           force_start:Force the chip to start monitoring inputs (bool)
parm:           force_id:Override the detected device ID (ushort)
parm:           probe_all_addr:Include probing of non-standard LPC addresses (bool)


gl520sm
parm:           extra_sensor_type:Type of extra sensor (0=autodetect, 1=temperature, 2=voltage) (ushort)


IT8705F/IT871xF/IT872xF hardware monitoring driver
it87
vermagic:       4.16.0-parrot5-amd64 SMP mod_unload modversions 
parm:           force_id:Override the detected device ID (ushort)
parm:           update_vbat:Update vbat if set else return powerup value (bool)
parm:           fix_pwm_polarity:Force PWM polarity to active high (DANGEROUS) (bool)



PC8736x hardware monitor
pc87360
parm:           init:Chip initialization level:
 0: None
*1: Forcibly enable internal voltage and temperature channels, except in9
 2: Forcibly enable all voltage and temperature channels, except in9
 3: Forcibly enable all voltage and temperature channels, including in9 (int)
parm:           force_id:Override the detected device ID (ushort)




device-mapper buffered I/O library
dm_bufio
vermagic:       4.16.0-parrot5-amd64 SMP mod_unload modversions 
parm:           max_cache_size_bytes:Size of metadata cache (ulong)
parm:           max_age_seconds:Max age of a buffer in seconds (uint)
parm:           retain_bytes:Try to keep at least this many bytes cached in memory (ulong)
parm:           peak_allocated_bytes:Tracks the maximum allocated memory (ulong)
parm:           allocated_kmem_cache_bytes:Memory allocated with kmem_cache_alloc (ulong)
parm:           allocated_get_free_pages_bytes:Memory allocated with get_free_pages (ulong)
parm:           allocated_vmalloc_bytes:Memory allocated with vmalloc (ulong)
parm:           current_allocated_bytes:Memory currently used by the cache (ulong)





dm_cache
parm:           cache_copy_throttle:A percentage of time allocated for copying to and/or from cache (uint)

dm_mirror
parm:           raid1_resync_throttle:A percentage of time allocated for raid resynchronization (uint)




dm_mod
parm:           reserved_rq_based_ios:Reserved IOs in request-based mempools (uint)
parm:           use_blk_mq:Use block multiqueue for request-based DM devices (bool)
parm:           dm_mq_nr_hw_queues:Number of hardware queues for request-based dm-mq devices (uint)
parm:           dm_mq_queue_depth:Queue depth for request-based dm-mq devices (uint)
parm:           stats_current_allocated_bytes:Memory currently used by statistics (ulong)
parm:           major:The major number of the device mapper (uint)
parm:           reserved_bio_based_ios:Reserved IOs in bio-based mempools (uint)
parm:           dm_numa_node:NUMA node for DM device memory allocations (int)



dm_raid

parm:           devices_handle_discard_safely:Set to Y if all devices in each array reliably return zeroes on reads from discarded regions (bool)


dm_snapshot
device-mapper snapshot target

parm:           snapshot_copy_throttle:A percentage of time allocated for copy on write (uint)


dm_thin_pool		
device-mapper thin provisioning target

parm:           snapshot_copy_throttle:A percentage of time allocated for copy on write (uint)
parm:           no_space_timeout:Out of data space queue IO timeout in seconds (uint)



raid456
parm:           devices_handle_discard_safely:Set to Y if all devices in each array reliably return zeroes on reads from discarded regions (bool)




mtdoops
MTD Oops/Panic console logger/driver

parm:           record_size:record size for MTD OOPS pages in bytes (default 4096) (ulong)
parm:           mtddev:name or index number of the MTD device to use (string)
parm:           dump_oops:set to 1 to dump oopses, 0 to only dump panics (default 1) (int)




mtdswap
Block device access to an MTD suitable for using as swap space

parm:           partitions:MTD partition numbers to use as swap partitions="1,3,5" (string)
parm:           spare_eblocks:Percentage of spare erase blocks for garbage collection (default 10%) (uint)
parm:           header:Include builtin swap header (default 0, without header) (bool)



netconsole
vermagic:       4.16.0-parrot5-amd64 SMP mod_unload modversions 
parm:           netconsole: netconsole=[src-port]@[src-ip]/[dev],[tgt-port]@<tgt-ip>/[tgt-macaddr] (string)
parm:           oops_only:Only log oops messages (bool)



virtio_net
vermagic:       4.16.0-parrot5-amd64 SMP mod_unload modversions 
parm:           napi_weight:int
parm:           csum:bool
parm:           gso:bool
parm:           napi_tx:bool


vxlan
vermagic:       4.16.0-parrot5-amd64 SMP mod_unload modversions 
parm:           udp_port:Destination UDP port (ushort)
parm:           log_ecn_error:Log packets received with corrupted ECN (bool)



xen_netfront
vermagic:       4.16.0-parrot5-amd64 SMP mod_unload modversions 
parm:           max_queues:Maximum number of queues per virtual interface (uint)


parport_pc
vermagic:       4.16.0-parrot5-amd64 SMP mod_unload modversions 
parm:           io:Base I/O address (SPP regs) (array of int)
parm:           io_hi:Base I/O address (ECR) (array of int)
parm:           irq:IRQ line (array of charp)
parm:           dma:DMA channel (array of charp)
parm:           init_mode:Initialise mode for VIA VT8231 port (spp, ps2, epp, ecp or ecpepp) (charp)


pci_stub
vermagic:       4.16.0-parrot5-amd64 SMP mod_unload modversions 
parm:           ids:Initial PCI IDs to add to the stub driver, format is "vendor:device[:subvendor[:subdevice[:class[:class_mask]]]]" and multiple comma separated entries can be specified (string)




 pcmcia_core
vermagic:       4.16.0-parrot5-amd64 SMP mod_unload modversions 
parm:           setup_delay:int
parm:           resume_delay:int
parm:           shutdown_delay:int
parm:           vcc_settle:int
parm:           reset_time:int
parm:           unreset_delay:int
parm:           unreset_check:int
parm:           unreset_limit:int
parm:           cis_speed:int



yenta_socket
vermagic:       4.16.0-parrot5-amd64 SMP mod_unload modversions 
parm:           disable_clkrun:If PC card doesn't function properly, please try this option (bool)
parm:           isa_probe:If set ISA interrupts are probed (default). Set to N to disable probing (bool)
parm:           pwr_irqs_off:Force IRQs off during power-on of slot. Use only when seeing IRQ storms! (bool)
parm:           o2_speedup:Use prefetch/burst for O2-bridges: 'on', 'off' or 'default' (uses recommended behaviour for the detected bridge) (string)
parm:           override_bios:yenta ignore bios resource allocation (uint)



ch
device driver for scsi media changer devices

parm:           init:initialize element status on driver load (default: on) (int)
parm:           timeout_move:timeout for move commands (default: 300 seconds) (int)
parm:           timeout_init:timeout for INITIALIZE ELEMENT STATUS (default: 3600 seconds) (int)
parm:           verbose:be verbose (default: on) (int)
parm:           debug:enable/disable debug messages, also prints more detailed sense codes on scsi errors (default: off) (int)
parm:           dt_id:array of int
parm:           dt_lun:array of int
parm:           vendor_firsts:array of int
parm:           vendor_counts:array of int



dc395x
SCSI host adapter driver for Tekram TRM-S1040 based adapters: Tekram DC395 and DC315 series

parm:           safe:Use safe and slow settings only. Default: false (bool)
parm:           adapter_id:Adapter SCSI ID. Default 7 (0-15) (int)
parm:           max_speed:Maximum bus speed. Default 1 (0-7) Speeds: 0=20, 1=13.3, 2=10, 3=8, 4=6.7, 5=5.8, 6=5, 7=4 Mhz (int)
parm:           dev_mode:Device mode. (int)
parm:           adapter_mode:Adapter mode. (int)
parm:           tags:Number of tags (1<<x). Default 3 (0-5) (int)
parm:           reset_delay:Reset delay in seconds. Default 1 (0-180) (int)




EATA/DMA SCSI Driver
eata

parm:           eata: equivalent to the "eata=..." kernel boot option.            Example: modprobe eata "eata=0x7410,0x230,lc:y,tm:0,mq:4,ep:n" (strin




filename:       /lib/modules/4.18.0-parrot10-amd64/kernel/drivers/gpu/drm/drm_kms_helper.ko

description:    DRM KMS helper
name:           drm_kms_helper
parm:           fbdev_emulation:Enable legacy fbdev emulation [default=true] (bool)
parm:           drm_fbdev_overalloc:Overallocation of the fbdev buffer (%) [default=100] (int)
parm:           edid_firmware:DEPRECATED. Use drm.edid_firmware module parameter instead. (charp)
parm:           poll:bool
parm:           dp_aux_i2c_speed_khz:Assumed speed of the i2c bus in kHz, (1-400, default 10) (int)
parm:           dp_aux_i2c_transfer_size:Number of bytes to transfer in a single I2C over DP AUX CH message, (1-16, default 16) (int)



description:    RAID4/5/6 (striping with parity) personality for MD
name:           raid456
parm:           devices_handle_discard_safely:Set to Y if all devices in each array reliably return zeroes on reads from discarded regions (bool)




name:           kvm_amd
filename:       /lib/modules/4.18.0-parrot10-amd64/kernel/arch/x86/kvm/kvm-amd.ko
parm:           pause_filter_thresh:ushort
parm:           pause_filter_count:ushort
parm:           pause_filter_count_grow:ushort
parm:           pause_filter_count_shrink:ushort
parm:           pause_filter_count_max:ushort
parm:           npt:int
parm:           nested:int
parm:           avic:int
parm:           vls:int
parm:           vgif:int
parm:           sev:int






name:           dm_mod
vermagic:       4.18.0-parrot10-amd64 SMP mod_unload modversions 
parm:           reserved_rq_based_ios:Reserved IOs in request-based mempools (uint)
parm:           use_blk_mq:Use block multiqueue for request-based DM devices (bool)
parm:           dm_mq_nr_hw_queues:Number of hardware queues for request-based dm-mq devices (uint)
parm:           dm_mq_queue_depth:Queue depth for request-based dm-mq devices (uint)
parm:           stats_current_allocated_bytes:Memory currently used by statistics (ulong)
parm:           major:The major number of the device mapper (uint)
parm:           reserved_bio_based_ios:Reserved IOs in bio-based mempools (uint)
parm:           dm_numa_node:NUMA node for DM device memory allocations (int)



name:           snd_hda_codec_hdmi
vermagic:       4.18.0-parrot10-amd64 SMP mod_unload modversions 
parm:           static_hdmi_pcm:Don't restrict PCM parameters per ELD info (bool)



filename:       /lib/modules/4.18.0-parrot10-amd64/kernel/drivers/block/pktcdvd.ko
description:    Packet writing layer for CD/DVD drives
depends:        cdrom
name:           pktcdvd


filename:       /lib/modules/4.18.0-parrot10-amd64/kernel/drivers/cdrom/cdrom.ko
name:           cdrom
vermagic:       4.18.0-parrot10-amd64 SMP mod_unload modversions 
parm:           debug:bool
parm:           autoclose:bool
parm:           autoeject:bool
parm:           lockdoor:bool
parm:           check_media_type:bool
parm:           mrw_format_restart:bool


filename:       /lib/modules/4.18.0-parrot10-amd64/kernel/drivers/ata/libahci.ko
description:    Common AHCI SATA low-level routines
name:           libahci

parm:           skip_host_reset:skip global host reset (0=don't skip, 1=skip) (int)
parm:           ignore_sss:Ignore staggered spinup flag (0=don't ignore, 1=ignore) (int)
parm:           ahci_em_messages:AHCI Enclosure Management Message control (0 = off, 1 = on) (bool)
parm:           devslp_idle_timeout:device sleep idle timeout (int)




name:           usbcore
filename:       /lib/modules/4.18.0-parrot10-amd64/kernel/drivers/usb/core/usbcore.ko

parm:           quirks:Add/modify USB quirks by specifying quirks=vendorID:productID:quirks
parm:           usbfs_snoop:true to log all usbfs traffic (bool)
parm:           usbfs_snoop_max:maximum number of bytes to print while snooping (uint)
parm:           usbfs_memory_mb:maximum MB allowed for usbfs buffers (0 = no limit) (uint)
parm:           authorized_default:Default USB device authorization: 0 is not authorized, 1 is authorized, -1 is authorized except for wireless USB (default, old behaviour (int)
parm:           blinkenlights:true to cycle leds on hubs (bool)
parm:           initial_descriptor_timeout:initial 64-byte descriptor request timeout in milliseconds (default 5000 - 5.0 seconds) (int)
parm:           old_scheme_first:start with the old device initialization scheme (bool)
parm:           use_both_schemes:try the other device initialization scheme if the first one fails (bool)
parm:           nousb:bool
parm:           autosuspend:default autosuspend delay (int)


name:           usbcore
filename:       /lib/modules/4.18.0-parrot10-amd64/kernel/drivers/usb/core/usbcore.ko

parm:           quirks:Add/modify USB quirks by specifying quirks=vendorID:productID:quirks
parm:           usbfs_snoop:true to log all usbfs traffic (bool)
parm:           usbfs_snoop_max:maximum number of bytes to print while snooping (uint)
parm:           usbfs_memory_mb:maximum MB allowed for usbfs buffers (0 = no limit) (uint)
parm:           authorized_default:Default USB device authorization: 0 is not authorized, 1 is authorized, -1 is authorized except for wireless USB (default, old behaviour (int)
parm:           blinkenlights:true to cycle leds on hubs (bool)
parm:           initial_descriptor_timeout:initial 64-byte descriptor request timeout in milliseconds (default 5000 - 5.0 seconds) (int)
parm:           old_scheme_first:start with the old device initialization scheme (bool)
parm:           use_both_schemes:try the other device initialization scheme if the first one fails (bool)
parm:           nousb:bool
parm:           autosuspend:default autosuspend delay (int)





















filename:       /lib/modules/4.18.0-parrot10-amd64/kernel/drivers/md/dm-mod.ko

description:    device-mapper driver
alias:          devname:mapper/control
alias:          char-major-10-236
name:           dm_mod

parm:           reserved_rq_based_ios:Reserved IOs in request-based mempools (uint)
parm:           use_blk_mq:Use block multiqueue for request-based DM devices (bool)
parm:           dm_mq_nr_hw_queues:Number of hardware queues for request-based dm-mq devices (uint)
parm:           dm_mq_queue_depth:Queue depth for request-based dm-mq devices (uint)
parm:           stats_current_allocated_bytes:Memory currently used by statistics (ulong)
parm:           major:The major number of the device mapper (uint)
parm:           reserved_bio_based_ios:Reserved IOs in bio-based mempools (uint)
parm:           dm_numa_node:NUMA node for DM device memory allocations (int)


















esp_scsi
ESP SCSI driver core
parm:           esp_debug:ESP bitmapped debugging message enable value:
        0x00000001      Log interrupt events
        0x00000002      Log scsi commands
        0x00000004      Log resets
        0x00000008      Log message in events
        0x00000010      Log message out events
        0x00000020      Log command completion
        0x00000040      Log disconnects
        0x00000080      Log data start
        0x00000100      Log data done
        0x00000200      Log reconnects
        0x00000400      Log auto-sense data




gdth
vermagic:       4.16.0-parrot5-amd64 SMP mod_unload modversions 
parm:           irq:array of int
parm:           disable:int
parm:           reserve_mode:int
parm:           reserve_list:array of int
parm:           reverse_scan:int
parm:           hdr_channel:int
parm:           max_ids:int
parm:           rescan:int
parm:           shared_access:int
parm:           probe_eisa_isa:int
parm:           force_dma32:int






hpsa
parm:           hpsa_simple_mode:Use 'simple mode' rather than 'performant mode' (int)



hv_storvsc
vermagic:       4.16.0-parrot5-amd64 SMP mod_unload modversions 
parm:           logging_level:Logging level, 0 - None, 1 - Error (default), 2 - Warning. (int)
parm:           storvsc_ringbuffer_size:Ring buffer size (bytes) (int)
parm:           storvsc_vcpus_per_sub_channel:Ratio of VCPUs to subchannels (int)


ipr
vermagic:       4.16.0-parrot5-amd64 SMP mod_unload modversions 
parm:           max_speed:Maximum bus speed (0-2). Default: 1=U160. Speeds: 0=80 MB/s, 1=U160, 2=U320 (uint)
parm:           log_level:Set to 0 - 4 for increasing verbosity of device driver (uint)
parm:           testmode:DANGEROUS!!! Allows unsupported configurations (int)
parm:           fastfail:Reduce timeouts and retries (int)
parm:           transop_timeout:Time in seconds to wait for adapter to come operational (default: 300) (int)
parm:           debug:Enable device driver debugging logging. Set to 1 to enable. (default: 0) (int)
parm:           dual_ioa_raid:Enable dual adapter RAID support. Set to 1 to enable. (default: 1) (int)
parm:           max_devs:Specify the maximum number of physical devices. [Default=1024] (int)
parm:           number_of_msix:Specify the number of MSIX interrupts to use on capable adapters (1 - 16).  (default:16) (int)
parm:           fast_reboot:Skip adapter shutdown during reboot. Set to 1 to enable. (default: 0) (int)



iscsi_tcp
vermagic:       4.16.0-parrot5-amd64 SMP mod_unload modversions 
parm:           max_lun:uint
parm:           debug_iscsi_tcp:Turn on debugging for iscsi_tcp module Set to 1 to turn on, and zero to turn off. Default is off. (int)



libiscsi
vermagic:       4.16.0-parrot5-amd64 SMP mod_unload modversions 
parm:           debug_libiscsi_conn:Turn on debugging for connections in libiscsi module. Set to 1 to turn on, and zero to turn off. Default is off. (int)
parm:           debug_libiscsi_session:Turn on debugging for sessions in libiscsi module. Set to 1 to turn on, and zero to turn off. Default is off. (int)
parm:           debug_libiscsi_eh:Turn on debugging for error handling in libiscsi module. Set to 1 to turn on, and zero to turn off. Default is off. (int)



libiscsi_tcp
vermagic:       4.16.0-parrot5-amd64 SMP mod_unload modversions 
parm:           debug_libiscsi_tcp:Turn on debugging for libiscsi_tcp module. Set to 1 to turn on, and zero to turn off. Default is off. (int)



megaraid
vermagic:       4.16.0-parrot5-amd64 SMP mod_unload modversions 
parm:           max_cmd_per_lun:Maximum number of commands which can be issued to a single LUN (default=DEF_CMD_PER_LUN=63) (uint)
parm:           max_sectors_per_io:Maximum number of sectors per I/O request (default=MAX_SECTORS_PER_IO=128) (ushort)
parm:           max_mbox_busy_wait:Maximum wait for mailbox in microseconds if busy (default=MBOX_BUSY_WAIT=10) (ushort)



pmcraid
vermagic:       4.16.0-parrot5-amd64 SMP mod_unload modversions 
parm:           log_level:Enables firmware error code logging, default :1 high-severity errors, 2: all errors including high-severity errors, 0: disables logging (uint)
parm:           debug:Enable driver verbose message logging. Set 1 to enable.(default: 0) (uint)
parm:           disable_aen:Disable driver aen notifications to apps. Set 1 to disable.(default: 0) (uint)




scsi_debug
vermagic:       4.16.0-parrot5-amd64 SMP mod_unload modversions 
parm:           add_host:0..127 hosts allowed(def=1) (int)
parm:           ato:application tag ownership: 0=disk 1=host (def=1) (int)
parm:           cdb_len:suggest CDB lengths to drivers (def=10) (int)
parm:           clustering:when set enables larger transfers (def=0) (bool)
parm:           delay:response delay (def=1 jiffy); 0:imm, -1,-2:tiny (int)
parm:           dev_size_mb:size in MiB of ram shared by devs(def=8) (int)
parm:           dif:data integrity field type: 0-3 (def=0) (int)
parm:           dix:data integrity extensions mask (def=0) (int)
parm:           dsense:use descriptor sense format(def=0 -> fixed) (int)
parm:           every_nth:timeout every nth command(def=0) (int)
parm:           fake_rw:fake reads/writes instead of copying (def=0) (int)
parm:           guard:protection checksum: 0=crc, 1=ip (def=0) (uint)
parm:           host_lock:host_lock is ignored (def=0) (bool)
parm:           inq_vendor:SCSI INQUIRY vendor string (def="Linux") (string)
parm:           inq_product:SCSI INQUIRY product string (def="scsi_debug") (string)
parm:           inq_rev:SCSI INQUIRY revision string (def="0187") (string)
parm:           lbpu:enable LBP, support UNMAP command (def=0) (int)
parm:           lbpws:enable LBP, support WRITE SAME(16) with UNMAP bit (def=0) (int)
parm:           lbpws10:enable LBP, support WRITE SAME(10) with UNMAP bit (def=0) (int)
parm:           lbprz:on read unmapped LBs return 0 when 1 (def), return 0xff when 2 (int)
parm:           lowest_aligned:lowest aligned lba (def=0) (int)
parm:           max_luns:number of LUNs per target to simulate(def=1) (int)
parm:           max_queue:max number of queued commands (1 to max(def)) (int)
parm:           ndelay:response delay in nanoseconds (def=0 -> ignore) (int)
parm:           no_lun_0:no LU number 0 (def=0 -> have lun 0) (int)
parm:           no_uld:stop ULD (e.g. sd driver) attaching (def=0)) (int)
parm:           num_parts:number of partitions(def=0) (int)
parm:           num_tgts:number of targets per host to simulate(def=1) (int)
parm:           opt_blks:optimal transfer length in blocks (def=1024) (int)
parm:           opts:1->noise, 2->medium_err, 4->timeout, 8->recovered_err... (def=0) (int)
parm:           physblk_exp:physical block exponent (def=0) (int)
parm:           opt_xferlen_exp:optimal transfer length granularity exponent (def=physblk_exp) (int)
parm:           ptype:SCSI peripheral type(def=0[disk]) (int)
parm:           removable:claim to have removable media (def=0) (bool)
parm:           scsi_level:SCSI level to simulate(def=7[SPC-5]) (int)
parm:           sector_size:logical block size in bytes (def=512) (int)
parm:           statistics:collect statistics on commands, queues (def=0) (bool)
parm:           strict:stricter checks: reserved field in cdb (def=0) (bool)
parm:           submit_queues:support for block multi-queue (def=1) (int)
parm:           unmap_alignment:lowest aligned thin provisioning lba (def=0) (int)
parm:           unmap_granularity:thin provisioning granularity in blocks (def=1) (int)
parm:           unmap_max_blocks:max # of blocks can be unmapped in one cmd (def=0xffffffff) (int)
parm:           unmap_max_desc:max # of ranges that can be unmapped in one cmd (def=256) (int)
parm:           uuid_ctl:1->use uuid for lu name, 0->don't, 2->all use same (def=0) (int)
parm:           virtual_gb:virtual gigabyte (GiB) size (def=0 -> use dev_size_mb) (int)
parm:           vpd_use_hostno:0 -> dev ids ignore hostno (def=1 -> unique dev ids) (int)
parm:           write_same_length:Maximum blocks per WRITE SAME cmd (def=0xffff) (int)



st
SCSI tape (st) driver

parm:           buffer_kbs:Default driver buffer size for fixed block mode (KB; 32) (int)
parm:           max_sg_segs:Maximum number of scatter/gather segments to use (256) (int)
parm:           try_direct_io:Try direct I/O between user buffer and tape drive (1) (int)
parm:           debug_flag:Enable DEBUG, same as setting debugging=1 (int)
parm:           try_rdio:Try direct read i/o when possible (int)
parm:           try_wdio:Try direct write i/o when possible (int)


VMware PVSCSI driver
vmw_pvscsi

parm:           ring_pages:Number of pages per req/cmp ring - (default=8[up to 16 targets],32[for 16+ targets]) (int)
parm:           msg_ring_pages:Number of pages for the msg ring - (default=1) (int)
parm:           cmd_per_lun:Maximum commands per lun - (default=254) (int)
parm:           disable_msi:Disable MSI use in driver - (default=0) (bool)
parm:           disable_msix:Disable MSI-X use in driver - (default=0) (bool)
parm:           use_msg:Use msg ring when available - (default=1) (bool)
parm:           use_req_threshold:Use driver-based request coalescing if configured - (default=1) (bool)






modinfo drm drm_kms_helper nouveau isofs usb_debug zram xxen-privcmd xen-tpmfront tpm xenfs xen-tpmfront cdrom btusb btrfs nouveau drm_kms_helper pktcdvd sr_mod efi-pstore efivarfs efivars bluetooth bluetooth_6lowpan binfmt_misc btusb scsi_mod act_vlan act_bpf appletalk  asus-wireless appletouch applesmc appledisplay apple_bl apple-gmux applicom panasonic-laptop pktcdvd pktgen pcmcia pci-stub pata_amd fuse usbcore usbhid usbmon usb-common hp-wireless hid-microsoft hid-apple hid-appleir hfs hfsplus hfcsusb batman-adv bfusb br_netfilter bridge btintel bochs-drm drm macvlan macvtap map_ram ntfs intel-cstate intel-smartconnect intel-hid i2c-smbus ati_remote ati_remote2 ata_generic ablk_helper asus-wmi asus-nb-wmi asus_atk0110 acpi-als act_bpf act_csum firewire-core firewire-net forcedeth fscache fscrypto fcrypt fam15h_power overlay openvswitch ocfs2_stack_user veth vhost_vsock videobuf-core virtio virtio_blk virtio_console virtio_crypto virtio_input virtio_net virtio_pci virtio_scsi vfio usbhid usbmon usbserial usbtest usbtv usb_wwan tcrypt test_bpf test_static_key_base test_static_keys test_user_copy thunderbolt thunderbolt-net toshiba_bluetooth toshiba_acpi toshiba_haps tpm tpm_atmel tpm_nsc tpm_tis_core ttpci-eeprom ttyprintk tun romfs realtek rfcomm rfkill radeon radeonfb rtlwifi rfcomm wimax ssnd-hda-codec-hdmi snd-hda-codec-realteksnd-hda-core sata_* snd-* | less



name:           rfcomm
vermagic:       4.16.0-parrot5-amd64 SMP mod_unload modversions 
parm:           disable_cfc:Disable credit based flow control (bool)
parm:           channel_mtu:Default MTU for the RFCOMM channel (int)
parm:           l2cap_mtu:Default MTU for the L2CAP connection (uint)
parm:           l2cap_ertm:Use L2CAP ERTM mode for connection (bool)



description:    RF switch support
name:           rfkill
vermagic:       4.16.0-parrot5-amd64 SMP mod_unload modversions 
parm:           master_switch_mode:SW_RFKILL_ALL ON should: 0=do nothing (only unlock); 1=restore; 2=unblock all (uint)
parm:           default_state:Default initial state for all radio types, 0 = radio off (uint)




description:    nVidia Riva/TNT/GeForce/Quadro/Tesla/Tegra K1+
name:           nouveau
vermagic:       4.16.0-parrot5-amd64 SMP mod_unload modversions 
parm:           tv_norm:Default TV norm.
                Supported: PAL, PAL-M, PAL-N, PAL-Nc, NTSC-M, NTSC-J,
                        hd480i, hd480p, hd576i, hd576p, hd720p, hd1080i.
                Default: PAL
                *NOTE* Ignored for cards with external TV encoders. (charp)
parm:           vram_pushbuf:Create DMA push buffers in VRAM (int)
parm:           nofbaccel:Disable fbcon acceleration (int)
parm:           fbcon_bpp:fbcon bits-per-pixel (default: auto) (int)
parm:           mst:Enable DisplayPort multi-stream (default: enabled) (int)
parm:           atomic:Expose atomic ioctl (default: disabled) (int)
parm:           tv_disable:Disable TV-out detection (int)
parm:           ignorelid:Ignore ACPI lid status (int)
parm:           duallink:Allow dual-link TMDS (default: enabled) (int)
parm:           hdmimhz:Force a maximum HDMI pixel clock (in MHz) (int)
parm:           config:option string to pass to driver core (charp)
parm:           debug:debug string to pass to driver core (charp)
parm:           noaccel:disable kernel/abi16 acceleration (int)
parm:           modeset:enable driver (default: auto, 0 = disabled, 1 = enabled, 2 = headless) (int)
parm:           runpm:disable (0), force enable (1), optimus only default (-1) (int)

name:           radeon
vermagic:       4.16.0-parrot5-amd64 SMP mod_unload modversions 
parm:           no_wb:Disable AGP writeback for scratch registers (int)
parm:           modeset:Disable/Enable modesetting (int)
parm:           dynclks:Disable/Enable dynamic clocks (int)
parm:           r4xx_atom:Enable ATOMBIOS modesetting for R4xx (int)
parm:           vramlimit:Restrict VRAM for testing, in megabytes (int)
parm:           agpmode:AGP Mode (-1 == PCI) (int)
parm:           gartsize:Size of PCIE/IGP gart to setup in megabytes (32, 64, etc., -1 = auto) (int)
parm:           benchmark:Run benchmark (int)
parm:           test:Run tests (int)
parm:           connector_table:Force connector table (int)
parm:           tv:TV enable (0 = disable) (int)
parm:           audio:Audio enable (-1 = auto, 0 = disable, 1 = enable) (int)
parm:           disp_priority:Display Priority (0 = auto, 1 = normal, 2 = high) (int)
parm:           hw_i2c:hw i2c engine enable (0 = disable) (int)
parm:           pcie_gen2:PCIE Gen2 mode (-1 = auto, 0 = disable, 1 = enable) (int)
parm:           msi:MSI support (1 = enable, 0 = disable, -1 = auto) (int)
parm:           lockup_timeout:GPU lockup timeout in ms (default 10000 = 10 seconds, 0 = disable) (int)
parm:           fastfb:Direct FB access for IGP chips (0 = disable, 1 = enable) (int)
parm:           dpm:DPM support (1 = enable, 0 = disable, -1 = auto) (int)
parm:           aspm:ASPM support (1 = enable, 0 = disable, -1 = auto) (int)
parm:           runpm:PX runtime pm (1 = force enable, 0 = disable, -1 = PX only default) (int)
parm:           hard_reset:PCI config reset (1 = force enable, 0 = disable (default)) (int)
parm:           vm_size:VM address space size in gigabytes (default 4GB) (int)
parm:           vm_block_size:VM page table size in bits (default depending on vm_size) (int)
parm:           deep_color:Deep Color support (1 = enable, 0 = disable (default)) (int)
parm:           use_pflipirq:Pflip irqs for pageflip completion (0 = disable, 1 = as fallback, 2 = exclusive (default)) (int)
parm:           bapm:BAPM support (1 = enable, 0 = disable, -1 = auto) (int)
parm:           backlight:backlight support (1 = enable, 0 = disable, -1 = auto) (int)
parm:           auxch:Use native auxch experimental support (1 = enable, 0 = disable, -1 = auto) (int)
parm:           mst:DisplayPort MST experimental support (1 = enable, 0 = disable) (int)
parm:           uvd:uvd enable/disable uvd support (1 = enable, 0 = disable) (int)
parm:           vce:vce enable/disable vce support (1 = enable, 0 = disable) (int)
:parm:           si_support:SI support (1 = enabled (default), 0 = disabled) (int)
parm:           cik_support:CIK support (1 = enabled (default), 0 = disabled) (int)




description:    framebuffer driver for ATI Radeon chipset
name:           radeonfb

parm:           default_dynclk:int: -2=enable on mobility only,-1=do not change,0=off,1=on (int)
parm:           noaccel:bool: disable acceleration (bool)
parm:           nomodeset:bool: disable actual setting of video mode (bool)
parm:           mirror:bool: mirror the display to both monitors (bool)
parm:           force_dfp:bool: force display to dfp (bool)
parm:           ignore_edid:bool: Ignore EDID data when doing DDC probe (bool)
parm:           monitor_layout:Specify monitor mapping (like XFree86) (charp)
parm:           force_measure_pll:Force measurement of PLL (debug) (bool)
parm:           nomtrr:bool: disable use of MTRR registers (bool)
parm:           panel_yres:int: set panel yres (int)
parm:           mode_option:Specify resolution as "<xres>x<yres>[-<bpp>][@<refresh>]"  (charp)
parm:           force_sleep:bool: force D2 sleep mode on all hardware (bool)
parm:           ignore_devlist:bool: ignore workarounds for bugs in specific laptops (bool)




description:    DRM KMS helper
name:           drm_kms_helper
vermagic:       4.16.0-parrot5-amd64 SMP mod_unload modversions 
parm:           fbdev_emulation:Enable legacy fbdev emulation [default=true] (bool)
parm:           drm_fbdev_overalloc:Overallocation of the fbdev buffer (%) [default=100] (int)
parm:           edid_firmware:DEPRECATED. Use drm.edid_firmware module parameter instead. (charp)
parm:           poll:bool
parm:           dp_aux_i2c_speed_khz:Assumed speed of the i2c bus in kHz, (1-400, default 10) (int)
parm:           dp_aux_i2c_transfer_size:Number of bytes to transfer in a single I2C over DP AUX CH message, (1-16, default 16) 



description:    EFI variable backend for pstore
name:           efi_pstore
vermagic:       4.16.0-parrot5-amd64 SMP mod_unload modversions 
parm:           pstore_disable:bool



name:           scsi_mod
vermagic:       4.16.0-parrot5-amd64 SMP mod_unload modversions 
parm:           dev_flags:Given scsi_dev_flags=vendor:model:flags[,v:m:f] add black/white list entries for vendor and model with an integer value of flags to the scsi device info list (string)
parm:           default_dev_flags:scsi default device flag integer value (int)
parm:           max_luns:last scsi LUN (should be between 1 and 2^64-1) (ullong)
parm:           scan:sync, async, manual, or none. Setting to 'manual' disables automatic scanning, but allows for manual device scan via the 'scan' sysfs attribute. (string)
parm:           inq_timeout:Timeout (in seconds) waiting for devices to answer INQUIRY. Default is 20. Some devices may need more; most need less. (uint)
parm:           eh_deadline:SCSI EH timeout in seconds (should be between 0 and 2^31-1) (int)
parm:           scsi_logging_level:a bit mask of logging levels (int)
parm:           use_blk_mq:bool



name:           appletouch
vermagic:       4.16.0-parrot5-amd64 SMP mod_unload modversions 
parm:           threshold:Discard any change in data from a sensor (the trackpad has many of these sensors) less than this value. (int)
parm:           debug:Activate debugging output (int)

name:           apple_bl
vermagic:       4.16.0-parrot5-amd64 SMP mod_unload modversions 
parm:           debug:Set to one to enable debugging messages. (int)


name:           pktgen
vermagic:       4.16.0-parrot5-amd64 SMP mod_unload modversions 
parm:           pg_count_d:Default number of packets to inject (int)
parm:           pg_delay_d:Default delay between packets (nanoseconds) (int)
parm:           pg_clone_skb_d:Default number of copies of the same packet (int)
parm:           debug:Enable debugging of pktgen module (int)


name:           fuse
vermagic:       4.16.0-parrot5-amd64 SMP mod_unload modversions 
parm:           max_user_bgreq:Global limit for the maximum number of backgrounded requests an unprivileged user can set (uint)
parm:           max_user_congthresh:Global limit for the maximum congestion threshold an unprivileged user can set (uint)


name:           usbcore
vermagic:       4.16.0-parrot5-amd64 SMP mod_unload modversions 
parm:           usbfs_snoop:true to log all usbfs traffic (bool)
parm:           usbfs_snoop_max:maximum number of bytes to print while snooping (uint)
parm:           usbfs_memory_mb:maximum MB allowed for usbfs buffers (0 = no limit) (uint)
parm:           authorized_default:Default USB device authorization: 0 is not authorized, 1 is authorized, -1 is authorized except for wireless USB (default, old behaviour (int)
parm:           blinkenlights:true to cycle leds on hubs (bool)
parm:           initial_descriptor_timeout:initial 64-byte descriptor request timeout in milliseconds (default 5000 - 5.0 seconds) (int)
parm:           old_scheme_first:start with the old device initialization scheme (bool)
parm:           use_both_schemes:try the other device initialization scheme if the first one fails (bool)
parm:           nousb:bool
parm:           autosuspend:default autosuspend delay (int)


name:           usbhid
vermagic:       4.16.0-parrot5-amd64 SMP mod_unload modversions 
parm:           mousepoll:Polling interval of mice (uint)
parm:           jspoll:Polling interval of joysticks (uint)
parm:           ignoreled:Autosuspend with active leds (uint)
parm:           quirks:Add/modify USB HID quirks by specifying  quirks=vendorID:productID:quirks where vendorID, productID, and 


name:           hid_apple
vermagic:       4.16.0-parrot5-amd64 SMP mod_unload modversions 
parm:           fnmode:Mode of fn key on Apple keyboards (0 = disabled, [1] = fkeyslast, 2 = fkeysfirst) (uint)
parm:           iso_layout:Enable/Disable hardcoded ISO-layout of the keyboard. (0 = disabled, [1] = enabled) (uint)
parm:           swap_opt_cmd:Swap the Option ("Alt") and Command ("Flag") keys. (For people who want to keep Windows PC keyboard muscle memory. [0] = as-is, Mac layout. 1 = swapped, Windows layout.) (uint)



B.A.T.M.A.N. advanced
batman_adv

rtnl-link-batadv
net-pf-16-proto-16-family-batadv




name:           bochs_drm
vermagic:       4.16.0-parrot5-amd64 SMP mod_unload modversions 
parm:           defx:default x resolution (int)
parm:           defy:default y resolution (int)
parm:           modeset:enable/disable kernel modesetting (int)
parm:           fbdev:register fbdev device (bool)




description:    ATI/X10 RF USB Remote Control
name:           ati_remote
vermagic:       4.16.0-parrot5-amd64 SMP mod_unload modversions 
parm:           channel_mask:Bitmask of remote control channels to ignore (ulong)
parm:           debug:Enable extra debug messages and information (int)
parm:           repeat_filter:Repeat filter time, default = 60 msec (int)
parm:           repeat_delay:Delay before sending repeats, default = 500 msec (int)
parm:           mouse:Enable mouse device, default = yes (bool)


description:    ATI/Philips USB RF remote driver
name:           ati_remote2
vermagic:       4.16.0-parrot5-amd64 SMP mod_unload modversions 
parm:           channel_mask:Bitmask of channels to accept <15:Channel16>...<1:Channel2><0:Channel1> (channel_mask)
parm:           mode_mask:Bitmask of modes to accept <4:PC><3:AUX4><2:AUX3><1:AUX2><0:AUX1> (mode_mask)



name:           forcedeth
vermagic:       4.16.0-parrot5-amd64 SMP mod_unload modversions 
parm:           max_interrupt_work:forcedeth maximum events handled per interrupt (int)
parm:           optimization_mode:In throughput mode (0), every tx & rx packet will generate an interrupt. In CPU mode (1), interrupts are controlled by a timer. In dynamic mode (2), the mode toggles between throughput and CPU mode based on network load. (int)
parm:           poll_interval:Interval determines how frequent timer interrupt is generated by [(time_in_micro_secs * 100) / (2^10)]. Min is 0 and Max is 65535. (int)
parm:           msi:MSI interrupts are enabled by setting to 1 and disabled by setting to 0. (int)
parm:           msix:MSIX interrupts are enabled by setting to 1 and disabled by setting to 0. (int)
parm:           dma_64bit:High DMA is enabled by setting to 1 and disabled by setting to 0. (int)
parm:           phy_cross:Phy crossover detection for Realtek 8201 phy is enabled by setting to 1 and disabled by setting to 0. (int)
parm:           phy_power_down:Power down phy and disable link when interface is down (1), or leave phy powered up (0). (int)
:modinfo: ERROR: Module ssnd-hda-codec-hdmi not found.
modinfo: ERROR: Module snd-hda-codec-realteksnd-hda-core not found.
modinfo: ERROR: Module sata_* not found.
modinfo: ERROR: Module snd-* not found.
parm:           debug_tx_timeout:Dump tx related registers and ring when tx_timeout happens (bool)



name:           fscache
vermagic:       4.16.0-parrot5-amd64 SMP mod_unload modversions 
parm:           defer_lookup:uint
parm:           fscache_defer_lookup:Defer cookie lookup to background thread
parm:           defer_create:uint
parm:           fscache_defer_create:Defer cookie creation to background thread
parm:           debug:uint
parm:           fscache_debug:FS-Cache debugging mask



name:           fscrypto
vermagic:       4.16.0-parrot5-amd64 SMP mod_unload modversions 
parm:           num_prealloc_crypto_pages:Number of crypto pages to preallocate (uint)
parm:           num_prealloc_crypto_ctxs:Number of crypto contexts to preallocate (uint)




alias:          fs-overlay
description:    Overlay filesystem
name:           overlay

parm:           check_copy_up:bool
parm:           ovl_check_copy_up:Warn on copy-up when causing process also has a R/O fd open
parm:           redirect_max:ushort
parm:           ovl_redirect_max:Maximum length of absolute redirect xattr value
parm:           redirect_dir:bool
parm:           ovl_redirect_dir_def:Default to on or off for the redirect_dir feature
parm:           redirect_always_follow:bool
parm:           ovl_redirect_always_follow:Follow redirects even if redirect_dir feature is turned off
parm:           index:bool
parm:           ovl_index_def:Default to on or off for the inodes index feature
parm:           nfs_export:bool
parm:           ovl_nfs_export_def:Default to on or off for the NFS export feature


name:           usbtest
vermagic:       4.16.0-parrot5-amd64 SMP mod_unload modversions 
parm:           alt:>= 0 to override altsetting selection (int)
parm:           pattern:uint
parm:           mod_pattern:i/o pattern (0 == zeroes)
parm:           realworld:clear to demand stricter spec compliance (uint)
parm:           force_interrupt:0 = test default; else interrupt (uint)
parm:           vendor:vendor code (from usb-if) (ushort)
parm:           product:product code (from vendor) (ushort)




name:           tcrypt
vermagic:       4.16.0-parrot5-amd64 SMP mod_unload modversions 
parm:           alg:charp
parm:           type:uint
parm:           mask:uint
parm:           mode:int
parm:           sec:Length in seconds of speed tests (defaults to zero which uses CPU cycles instead) (uint)
parm:           num_mb:Number of concurrent requests to be used in mb speed tests (defaults to 8) (uint)


name:           test_bpf
vermagic:       4.16.0-parrot5-amd64 SMP mod_unload modversions 
parm:           test_name:string
parm:           test_id:int
parm:           test_range:array of int



toshiba_bluetooth

toshiba_bluetooth                       ## description:    Toshiba Laptop ACPI Bluetooth Enable Driver

##   /lib/modules/4.18.0-parrot10-amd64/kernel/drivers/platform/x86/toshiba_bluetooth.ko



filename:       /lib/modules/4.18.0-parrot10-amd64/kernel/drivers/mmc/host/toshsd.ko
description:    Toshiba PCI Secure Digital Host Controller Interface driver
depends:        mmc_core
name:           toshsd




description:    Toshiba Laptop ACPI Extras Driver
name:           toshiba_acpi
parm:           disable_hotkeys:Disables the hotkeys activation (bool)



name:           thunderbolt
filename:       /lib/modules/4.18.0-parrot10-amd64/kernel/drivers/net/thunderbolt-net.ko
description:    Thunderbolt network driver
alias:          tbsvc:knetworkp00000001v*r*
name:           thunderbolt_net





name:           thmc50
description:    THMC50 driver
filename:       /lib/modules/4.18.0-parrot10-amd64/kernel/drivers/hwmon/thmc50.ko
parm:           adm1022_temp3:List of adapter,address pairs to enable 3rd temperature (ADM1022 only) (array of ushort)



filename:       /lib/modules/4.18.0-parrot10-amd64/kernel/fs/hfsplus/hfsplus.ko
alias:          fs-hfsplus
description:    Extended Macintosh Filesystem
name:           hfsplus






filename:       /lib/modules/4.18.0-parrot10-amd64/kernel/drivers/bluetooth/bluecard_cs.ko
description:    Bluetooth driver for the Anycom BlueCard (LSE039/LSE041)
name:           bluecard_cs




name:           btusb
filename:       /lib/modules/4.18.0-parrot10-amd64/kernel/drivers/bluetooth/btusb.ko
description:    Generic Bluetooth USB driver ver 0.8
depends:        usbcore,btbcm,bluetooth,btrtl,btintel

parm:           disable_scofix:Disable fixup of wrong SCO buffer size (bool)
parm:           force_scofix:Force fixup of wrong SCO buffers size (bool)
parm:           enable_autosuspend:Enable USB autosuspend by default (bool)
parm:           reset:Send HCI reset command on initialization (bool)

filename:       /lib/modules/4.18.0-parrot10-amd64/kernel/drivers/bluetooth/btbcm.ko





name:           btbcm
filename:       /lib/modules/4.18.0-parrot10-amd64/kernel/drivers/bluetooth/btbcm.ko
description:    Bluetooth support for Broadcom devices ver 0.1
filename:       /lib/modules/4.18.0-parrot10-amd64/kernel/net/bluetooth/bluetooth_6lowpan.ko
description:    Bluetooth 6LoWPAN


name:           bluetooth_6lowpan




description:    Samsung Backlight driver
filename:       /lib/modules/4.18.0-parrot10-amd64/kernel/fs/binfmt_misc.ko
filename:       /lib/modules/4.18.0-parrot10-amd64/kernel/drivers/platform/x86/samsung-laptop.ko



binfmt_misc
fs-binfmt_misc



samsung_laptop
author:         Greg Kroah-Hartman <gregkh@suse.de>
filename:       /lib/modules/4.18.0-parrot10-amd64/kernel/drivers/platform/x86/samsung-laptop.ko
parm:           force:Disable the DMI check and forces the driver to be loaded (bool)
parm:           debug:Debug enabled or not (bool)


filename:       /lib/modules/4.18.0-parrot10-amd64/kernel/drivers/platform/x86/samsung-q10.ko
description:    Samsung Q10 Driver
name:           samsung_q10
parm:           force:Disable the DMI check and force the driver to be loaded (bool)







name:           bochs_drm
filename:       /lib/modules/4.18.0-parrot10-amd64/kernel/drivers/gpu/drm/bochs/bochs-drm.ko
parm:           defx:default x resolution (int)
parm:           defy:default y resolution (int)
parm:           modeset:enable/disable kernel modesetting (int)
parm:           fbdev:register fbdev device (bool)



name:           hfcsusb
filename:       /lib/modules/4.18.0-parrot10-amd64/kernel/drivers/isdn/hardware/mISDN/hfcmulti.ko
name:           hfcmulti
parm:           debug:uint
parm:           poll:uint
parm:           clock:int
parm:           timer:uint
parm:           clockdelay_te:uint
parm:           clockdelay_nt:uint
parm:           type:array of uint
parm:           pcm:array of int
parm:           dmask:array of uint
parm:           bmask:array of uint
parm:           iomode:array of uint
parm:           port:array of uint
parm:           hwid:uint
filename:       /lib/modules/4.18.0-parrot10-amd64/kernel/drivers/isdn/hardware/mISDN/hfcpci.ko
































toshiba_haps            ## Toshiba HDD Active Protection Sensor

tpm                     ## TPM Driver
parm:           suspend_pcr:PCR to use for dummy writes to facilitate flush on suspend. (uint)


TPM Driver
    
tpm_atmel               ## TPM Driver
tpm_nsc
tpm_tis_core
ttpci_eeprom            ## Decode dvb_net MAC address from EEPROM of PCI DVB cards made by Siemens, Technotrend, Hauppauge




tun                     ## Universal TUN/TAP device driver
devname:net/tun
char-major-10-200














































































synclink_gt
vermagic:       4.16.0-parrot5-amd64 SMP mod_unload modversions 
parm:           ttymajor:TTY major device number override: 0=auto assigned (int)
parm:           debug_level:Debug syslog output: 0=disabled, 1 to 5=increasing detail (int)
parm:           maxframe:Maximum frame size used by device (4096 to 65535) (array of int)




synclink
vermagic:       4.16.0-parrot5-amd64 SMP mod_unload modversions 
parm:           break_on_load:bool
parm:           ttymajor:int
parm:           io:array of int
parm:           irq:array of int
parm:           dma:array of int
parm:           debug_level:int
parm:           maxframe:array of int
parm:           txdmabufs:array of int
parm:           txholdbufs:array of int




vfio_iommu_type1
Type1 IOMMU driver for VFIO

parm:           allow_unsafe_interrupts:Enable VFIO IOMMU support for on platforms without interrupt remapping support. (bool)
parm:           disable_hugepages:Disable VFIO IOMMU support for IOMMU hugepages. (bool)



Host kernel accelerator for virtio
vhost
vermagic:       4.16.0-parrot5-amd64 SMP mod_unload modversions 
parm:           max_mem_regions:Maximum number of memory regions in memory map. (default: 64) (ushort)
parm:           max_iotlb_entries:Maximum number of iotlb entries. (default: 2048) (int)


vhost_net
Host kernel accelerator for virtio net




wire
vermagic:       4.16.0-parrot5-amd64 SMP mod_unload modversions 
parm:           delay_coef:int
parm:           disable_irqs:int
parm:           search_count:int
parm:           enable_pullup:int
parm:           timeout:time in seconds between automatic slave searches (int)
parm:           timeout_us:time in microseconds between automatic slave searches (int)
parm:           max_slave_count:maximum number of slaves detected in a search (int)
parm:           slave_ttl:Number of searches not seeing a slave before it will be removed (int)


filename:       /lib/modules/4.18.0-parrot10-amd64/kernel/drivers/acpi/thermal.ko
parm:           act:Disable or override all lowest active trip points. (int)
parm:           crt:Disable or lower all critical trip points. (int)
parm:           tzp:Thermal zone polling frequency, in 1/10 seconds. (int)
parm:           nocrt:Set to take no action upon ACPI thermal zone critical trips points. (int)
parm:           off:Set to disable ACPI thermal support. (int)
parm:           psv:Disable or override all passive trip points. (int)
filename:       /lib/modules/4.18.0-parrot10-amd64/kernel/drivers/acpi/button.ko
parm:           lid_report_interval:Interval (ms) between lid key events (ulong)
parm:           lid_init_state:Behavior for reporting LID initial state





filename:       /lib/modules/4.18.0-parrot10-amd64/kernel/drivers/scsi/scsi_mod.ko
parm:           dev_flags:Given scsi_dev_flags=vendor:model:flags[,v:m:f] add black/white list entries for vendor and model with an integer value of flags to the scsi device info list (string)
parm:           default_dev_flags:scsi default device flag uint64_t value (ullong)
parm:           max_luns:last scsi LUN (should be between 1 and 2^64-1) (ullong)
parm:           scan:sync, async, manual, or none. Setting to 'manual' disables automatic scanning, but allows for manual device scan via the 'scan' sysfs attribute. (string)
parm:           inq_timeout:Timeout (in seconds) waiting for devices to answer INQUIRY. Default is 20. Some devices may need more; most need less. (uint)
parm:           eh_deadline:SCSI EH timeout in seconds (should be between 0 and 2^31-1) (int)
parm:           scsi_logging_level:a bit mask of logging levels (int)
parm:           use_blk_mq:bool





filename:       /lib/modules/4.18.0-parrot10-amd64/kernel/drivers/usb/core/usbcore.ko
parm:           quirks:Add/modify USB quirks by specifying quirks=vendorID:productID:quirks
parm:           usbfs_snoop:true to log all usbfs traffic (bool)
parm:           usbfs_snoop_max:maximum number of bytes to print while snooping (uint)
parm:           usbfs_memory_mb:maximum MB allowed for usbfs buffers (0 = no limit) (uint)
parm:           authorized_default:Default USB device authorization: 0 is not authorized, 1 is authorized, -1 is authorized except for wireless USB (default, old behaviour (int)
parm:           blinkenlights:true to cycle leds on hubs (bool)
parm:           initial_descriptor_timeout:initial 64-byte descriptor request timeout in milliseconds (default 5000 - 5.0 seconds) (int)
parm:           old_scheme_first:start with the old device initialization scheme (bool)
parm:           use_both_schemes:try the other device initialization scheme if the first one fails (bool)
parm:           nousb:bool
parm:           autosuspend:default autosuspend delay (int)


filename:       /lib/modules/4.18.0-parrot10-amd64/kernel/drivers/gpu/drm/drm.ko
parm:           edid_firmware:Do not probe monitor, use specified EDID blob from built-in data or /lib/firmware instead.  (string)
parm:           vblankoffdelay:Delay until vblank irq auto-disable [msecs] (0: never disable, <0: disable immediately) (int)
parm:           timestamp_precision_usec:Max. error on timestamps [usecs] (int)
parm:           edid_fixup:Minimum number of valid EDID header bytes (0-8, default 6) (int)
parm:           debug:Enable debug output, where each bit enables a debug category.























hp watchdog driver
hpwdt
vermagic:       4.16.0-parrot5-amd64 SMP mod_unload modversions 
parm:           soft_margin:Watchdog timeout in seconds (int)
parm:           nowayout:Watchdog cannot be stopped once started (default=0) (bool)
parm:           allow_kdump:Start a kernel dump after NMI occurs (int)




Intel Atom E6xx Watchdog Device Driver
ie6xx_wdt
vermagic:       4.16.0-parrot5-amd64 SMP mod_unload modversions 
parm:           timeout:Default Watchdog timer setting (60s).The range is from 1 to 600 (uint)
parm:           nowayout:Watchdog cannot be stopped once started (default=0) (bool)
parm:           resetmode:Resetmode bits: 0x08 warm reset (cold reset otherwise), 0x10 reset enable, 0x20 disable toggle GPIO[4] (default=0x10) (byte)



it8712f_wdt
vermagic:       4.16.0-parrot5-amd64 SMP mod_unload modversions 
parm:           margin:Watchdog margin in seconds (int)
parm:           nowayout:Disable watchdog shutdown on close (bool)
parm:           wdt_control_reg:Value to write to watchdog control register. The default WDT_RESET_GAME resets the timer on game port reads that this driver generates. You can also use KBD, MOUSE or CIR if you have some external way to generate those interrupts. (int)



 iTCO_vendor_support
ntel TCO Vendor Specific WatchDog Timer Driver Support
parm:           vendorsupport:iTCO vendor specific support mode, default=0 (none), 1=SuperMicro Pent3, 2=SuperMicro Pent4+, 911=Broken SMI BIOS (int)


iTCO_wdt
Intel TCO WatchDog Timer Driver

parm:           heartbeat:Watchdog timeout in seconds. 5..76 (TCO v1) or 3..614 (TCO v2), default=30) (int)
parm:           nowayout:Watchdog cannot be stopped once started (default=0) (bool)
parm:           turn_SMI_watchdog_clear_off:Turn off SMI clearing watchdog (depends on TCO-version)(default=1) (int)




softdog
vermagic:       4.16.0-parrot5-amd64 SMP mod_unload modversions 
parm:           soft_margin:Watchdog soft_margin in seconds. (0 < soft_margin < 65536, default=60) (uint)
parm:           nowayout:Watchdog cannot be stopped once started (default=0) (bool)
parm:           soft_noboot:Softdog action, set to 1 to ignore reboots, 0 to reboot (default=0) (int)
parm:           soft_panic:Softdog action, set to 1 to panic, 0 to reboot (default=0) (int)



wdt_pci
vermagic:       4.16.0-parrot5-amd64 SMP mod_unload modversions 
parm:           heartbeat:Watchdog heartbeat in seconds. (0<heartbeat<65536, default=60) (int)
parm:           nowayout:Watchdog cannot be stopped once started (default=0) (bool)
parm:           tachometer:PCI-WDT501 Fan Tachometer support (0=disable, default=0) (int)
parm:           type:PCI-WDT501 Card type (500 or 501 , default=500) (int)


xen_gntdev
  User-space granted page access driver
parm:           limit:Maximum number of grants that may be mapped by the gntdev device (int)









xen_privcmd
parm:           dm_op_max_nr_bufs:Maximum number of buffers per dm_op hypercall (uint)
parm:           dm_op_buf_max_size:Maximum size of a dm_op hypercall buffer (uint)


xen_scsiback
Xen SCSI backend driver

parm:           log_print_stat:bool
parm:           max_buffer_pages:Maximum number of free pages to keep in backend buffer (int)















description:    Compressed RAM Block Device
name:           zram
parm:           num_devices:Number of pre-created zram devices (uint)



vermagic:       4.16.0-parrot5-amd64 SMP mod_unload modversions 
parm:           num_devices:Number of pre-created zram devices (uint)

name:           cdrom
vermagic:       4.16.0-parrot5-amd64 SMP mod_unload modversions 
parm:           debug:bool
parm:           autoclose:bool
parm:           autoeject:bool
parm:           lockdoor:bool
parm:           check_media_type:bool
parm:           mrw_format_restart:bool

name:           btusb
vermagic:       4.16.0-parrot5-amd64 SMP mod_unload modversions 
parm:           disable_scofix:Disable fixup of wrong SCO buffer size (bool)
parm:           force_scofix:Force fixup of wrong SCO buffers size (bool)
parm:           enable_autosuspend:Enable USB autosuspend by default (bool)
parm:           reset:Send HCI reset command on initialization (bool)



description:    bttv - v4l/v4l2 driver module for bt848/878 based cards
name:           bttv
vermagic:       4.16.0-parrot5-amd64 SMP mod_unload modversions 
parm:           btcx_debug:debug messages, default is 0 (no) (int)
parm:           ir_debug:int
parm:           ir_rc5_remote_gap:int
parm:           i2c_debug:configure i2c debug level (int)
parm:           i2c_hw:force use of hardware i2c support, instead of software bitbang (int)
parm:           i2c_scan:scan i2c bus at insmod time (int)
parm:           i2c_udelay:soft i2c delay at insmod time, in usecs (should be 5 or higher). Lower value means higher bus speed. (int)
parm:           vbibufs:number of vbi buffers, range 2-32, default 4 (int)
parm:           vbi_debug:vbi code debug messages, default is 0 (no) (int)
parm:           gpiomask:int
parm:           audioall:int
parm:           svhs:array of int
parm:           remote:array of int
parm:           audiomux:array of int
parm:           triton1:set ETBF pci config bit [enable bug compatibility for triton1 + others] (int)
parm:           vsfx:set VSFX pci config bit [yet another chipset flaw workaround] (int)
parm:           latency:pci latency timer (int)
parm:           card:specify TV/grabber card model, see CARDLIST file for a list (array of int)
parm:           pll:specify installed crystal (0=none, 28=28 MHz, 35=35 MHz, 14=14 MHz) (array of int)
parm:           tuner:specify installed tuner type (array of int)
parm:           autoload:obsolete option, please do not use anymore (int)
parm:           audiodev:specify audio device:
		-1 = no audio
		 0 = autodetect (default)
		 1 = msp3400
		 2 = tda7432
		 3 = tvaudio (array of int)
parm:           saa6588:if 1, then load the saa6588 RDS module, default (0) is to use the card definition.
parm:           no_overlay:allow override overlay default (0 disables, 1 enables) [some VIA/SIS chipsets are known to have problem with overlay] (int)
parm:           debug_latency:int
parm:           fdsr:int
parm:           v4l2:int
parm:           combfilter:int
parm:           lumafilter:int
parm:           radio:The TV card supports radio, default is 0 (no) (array of int)
parm:           bigendian:byte order of the framebuffer, default is native endian (int)
parm:           bttv_verbose:verbose startup messages, default is 1 (yes) (int)
parm:           bttv_gpio:log gpio changes, default is 0 (no) (int)
parm:           bttv_debug:debug messages, default is 0 (no) (int)
parm:           irq_debug:irq handler debug messages, default is 0 (no) (int)
parm:           disable_ir:disable infrared remote support (int)
parm:           gbuffers:number of capture buffers. range 2-32, default 8 (int)
parm:           gbufsize:size of the capture buffers, default is 0x208000 (int)
parm:           reset_crop:reset cropping parameters at open(), default is 1 (yes) for compatibility with older applications (int)
parm:           automute:mute audio on bad/missing video signal, default is 1 (yes) (int)
parm:           chroma_agc:enables the AGC of chroma signal, default is 0 (no) (int)
parm:           agc_crush:enables the luminance AGC crush, default is 1 (yes) (int)
parm:           whitecrush_upper:sets the white crush upper value, default is 207 (int)
parm:           whitecrush_lower:sets the white crush lower value, default is 127 (int)
parm:           vcr_hack:enables the VCR hack (improves synch on poor VCR tapes), default is 0 (no) (int)
parm:           irq_iswitch:switch inputs in irq handler (int)
parm:           uv_ratio:ratio between u and v gains, default is 50 (int)
parm:           full_luma_range:use the full luma range, default is 0 (no) (int)
parm:           coring:set the luma coring level, default is 0 (no) (int)
parm:           video_nr:video device numbers (array of int)
parm:           vbi_nr:vbi device numbers (array of int)
parm:           radio_nr:radio device numbers (array of int)



















parm:           experimental_zcopytx:Enable Zero Copy TX; 1 -Enable; 0 - Disable (int)





























scsi_mod
SCSI core

parm:           default_dev_flags:scsi default device flag integer value (int)
parm:           max_luns:last scsi LUN (should be between 1 and 2^64-1) (ullong)
parm:           scan:sync, async, manual, or none. Setting to 'manual' disables automatic scanning, but allows for manual device scan via the 'scan' sysfs attribute. (string)
parm:           inq_timeout:Timeout (in seconds) waiting for devices to answer INQUIRY. Default is 20. Some devices may need more; most need less. (uint)
parm:           eh_deadline:SCSI EH timeout in seconds (should be between 0 and 2^31-1) (int)
parm:           scsi_logging_level:a bit mask of logging levels (int)
parm:           use_blk_mq:bool



scsi_transport_fc
parm:           dev_loss_tmo:Maximum number of seconds that the FC transport should insulate the loss of a remote port. Once this value is exceeded, the scsi target is removed. Value should be between 1 and SCSI_DEVICE_BLOCK_MAX_TIMEOUT if fast_io_fail_tmo is not set. (uint)



scsi_transport_iscsi
parm:           debug_session:Turn on debugging for sessions in scsi_transport_iscsi module. Set to 1 to turn on, and zero to turn off. Default is off. (int)
parm:           debug_conn:Turn on debugging for connections in scsi_transport_iscsi module. Set to 1 to turn on, and zero to turn off. Default is off. (int)



sg
SCSI generic (sg) driver

parm:           scatter_elem_sz:scatter gather element size (default: max(SG_SCATTER_SZ, PAGE_SIZE)) (int)
parm:           def_reserved_size:size of buffer reserved for each fd (int)
parm:           allow_dio:allow direct I/O (default: 0 (disallow)) (int)




sr_mod
SCSI cdrom (sr) driver

parm:           xa_test:int




stex
vermagic:       4.16.0-parrot5-amd64 SMP mod_unload modversions 
parm:           msi:Enable Message Signaled Interrupts(0=off, 1=on) (int)
















































fscache
parm:           defer_lookup:uint
parm:           fscache_defer_lookup:Defer cookie lookup to background thread
parm:           defer_create:uint
parm:           fscache_defer_create:Defer cookie creation to background thread
parm:           debug:uint
parm:           fscache_debug:FS-Cache debugging mask

fscrypto
parm:           num_prealloc_crypto_pages:Number of crypto pages to preallocate (uint)
parm:           num_prealloc_crypto_ctxs:Number of crypto contexts to preallocate (uint)


fuse
parm:           max_user_bgreq:Global limit for the maximum number of backgrounded requests an unprivileged user can set (uint)
parm:           max_user_congthresh:Global limit for the maximum congestion threshold an unprivileged user can set (uint)


jfs
parm:           nTxBlock:Number of transaction blocks (max:65536) (int)
parm:           nTxLock:Number of transaction locks (max:65536) (int)
parm:           commit_threads:Number of commit threads (int)


parm:           nsm_use_hostnames:bool
parm:           nlm_max_connections:uint


modinfo /lib/modules/4.16.0-parrot5-amd64/kernel/net/*/*/* | grep parm
parm:           compress_src:Compress sources headers (bool)
parm:           compress_dst:Compress destination headers (bool)
parm:           disable_cfc:Disable credit based flow control (bool)
parm:           channel_mtu:Default MTU for the RFCOMM channel (int)
parm:           l2cap_mtu:Default MTU for the L2CAP connection (uint)
parm:           l2cap_ertm:Use L2CAP ERTM mode for connection (bool)
parm:           forward:bool
parm:           raw_before_defrag:Enable raw table before defrag (bool)
parm:           forward:bool
parm:           raw_before_defrag:Enable raw table before defrag (bool)
parm:           max_sets:maximal number of sets (int)
parm:           ports:Ports to monitor for FTP control commands (array of ushort)
parm:           conn_tab_bits:Set connections' hash size (int)
parm:           expired_cred_retry_delay:Timeout (in seconds) until the RPC engine retries an expired credential (uint)
parm:           key_expire_timeo:Time (in seconds) at the end of a credential keys lifetime where the NFS layer cleans up prior to key 





ipw2200

parm:           disable:manually disable the radio (default 0 [radio on]) (int)
parm:           associate:auto associate when scanning (default off) (int)
parm:           auto_create:auto create adhoc network (default on) (int)
parm:           led:enable led control on some systems (default 1 on) (int)
parm:           debug:debug output mask (int)
parm:           channel:channel to limit associate to (default 0 [ANY]) (int)
parm:           rtap_iface:create the rtap interface (1 - create, default 0) (int)
parm:           qos_enable:enable all QoS functionalitis (int)
parm:           qos_burst_enable:enable QoS burst mode (int)
parm:           qos_no_ack_mask:mask Tx_Queue to no ack (int)
parm:           burst_duration_CCK:set CCK burst value (int)
parm:           burst_duration_OFDM:set OFDM burst value (int)
parm:           mode:network mode (0=BSS,1=IBSS,2=Monitor) (int)
parm:           bt_coexist:enable bluetooth coexistence (default off) (int)
parm:           hwcrypto:enable hardware crypto (default off) (int)
parm:           cmdlog:allocate a ring buffer for logging firmware commands (int)
parm:           roaming:enable roaming support (default on) (int)
parm:           antenna:select antenna 1=Main, 3=Aux, default 0 [both], 2=slow_diversity (choose the one with lower background noise) (


parm:           log_ecn_error:Log packets received with corrupted ECN (bool)
parm:           forward:bool
parm:           raw_before_defrag:Enable raw table before defrag (bool)
parm:           log_ecn_error:Log packets received with corrupted ECN (bool)
parm:           connect_retries:Maximum number of connect retries (one second each) (int)
parm:           initial_wait:Time to wait before attempting a connection (in seconds) (int)
parm:           ipddp_mode:int
parm:           log_ecn_error:Log packets received with corrupted ECN (bool)
parm:           IA_TX_BUF:int
parm:           IA_TX_BUF_SZ:int
parm:           IA_RX_BUF:int
parm:           IA_RX_BUF_SZ:int
parm:           IADebugFlag:uint
parm:           log_ecn_error:Log packets received with corrupted ECN (bool)
parm:           ipmi_major:Sets the major number of the IPMI device.  By default, or if you set it to zero, it will choose the next available device.  Setting it to -1 will disable the interface.  Other values will set the major device number to that value. (int)
parm:           panic_op:Sets if the IPMI driver will attempt to store panic information in the event log in the event of a panic.  Set to 'none' for no, 'event' for a single event, or 'string' for a generic event and the panic string in IPMI OEM events.
parm:           ifnum_to_use:The interface number to use for the watchdog timer.  Setting to -1 defaults to the first registered interface
parm:           poweroff_powercycle: Set to non-zero to enable power cycle instead of power down. Power cycle is contingent on hardware support, otherwise it defaults back to power down. (int)
parm:           trypci:Setting this to zero will disable the default scan of the interfaces identified via pci (bool)
parm:           tryplatform:Setting this to zero will disable the default scan of the interfaces identified via platform interfaces besides ACPI, OpenFirmware, and DMI (bool)
parm:           tryacpi:Setting this to zero will disable the default scan of the interfaces identified via ACPI (bool)
parm:           trydmi:Setting this to zero will disable the default scan of the interfaces identified via DMI (bool)
parm:           type:Defines the type of each interface, each interface separated by commas.  The types are 'kcs', 'smic', and 'bt'.  For example si_type=kcs,bt will set the first interface to kcs and the second to bt (string)
parm:           addrs:Sets the memory address of each interface, the addresses separated by commas.  Only use if an interface is in memory.  Otherwise, set it to zero or leave it blank. (array of ulong)
parm:           ports:Sets the port address of each interface, the addresses separated by commas.  Only use if an interface is a port.  Otherwise, set it to zero or leave it blank. (array of uint)
parm:           irqs:Sets the interrupt of each interface, the addresses separated by commas.  Only use if an interface has an interrupt.  Otherwise, set it to zero or leave it blank. (array of int)
parm:           regspacings:The number of bytes between the start address and each successive register used by the interface.  For instance, if the start address is 0xca2 and the spacing is 2, then the second address is at 0xca4.  Defaults to 1. (array of int)
parm:           regsizes:The size of the specific IPMI register in bytes. This should generally be 1, 2, 4, or 8 for an 8-bit, 16-bit, 32-bit, or 64-bit register.  Use this if you the 8-bit IPMI register has to be read from a larger register. (array of int)
parm:           regshifts:The amount to shift the data read from the. IPMI register, in bits.  For instance, if the data is read from a 32-bit word and the IPMI data is in bit 8-15, then the shift would be 8 (array of int)
parm:           slave_addrs:Set the default IPMB slave address for the controller.  Normally this is 0x20, but can be overridden by this parm.  This is an array indexed by interface number. (array of int)
parm:           hotmod:Add and remove interfaces.  See Documentation/IPMI.txt in the kernel sources for the gory details.
parm:           bt_debug:debug bitmask, 1=enable, 2=messages, 4=states (int)
parm:           smic_debug:debug bitmask, 1=enable, 2=messages, 4=states (int)
parm:           kcs_debug:debug bitmask, 1=enable, 2=messages, 4=states (int)
parm:           force_kipmid:Force the kipmi daemon to be enabled (1) or disabled(0).  Normally the IPMI driver auto-detects this, but the value may be overridden by this parm. (array of int)
parm:           unload_when_empty:Unload the module if no interfaces are specified or found, default is 1.  Setting to 0 is useful for hot add of devices using hotmod. (bool)
parm:           kipmid_max_busy_us:Max time (in microseconds) to busy-wait for IPMI data before sleeping. 0 (default) means to wait forever. Set to 100-500 if kipmid is using up a lot of CPU time. (array of uint)
parm:           ifnum_to_use:The interface number to use for the watchdog timer.  Setting to -1 defaults to the first registered interface (wdog_ifnum)
parm:           timeout:Timeout value in seconds. (timeout)
parm:           pretimeout:Pretimeout value in seconds. (timeout)
parm:           panic_wdt_timeout:Timeout value on kernel panic in seconds. (timeout)
parm:           action:Timeout action. One of: reset, none, power_cycle, power_off.
parm:           preaction:Pretimeout action.  One of: pre_none, pre_smi, pre_nmi, pre_int.
parm:           preop:Pretimeout driver operation.  One of: preop_none, preop_panic, preop_give_data.
parm:           start_now:Set to 1 to start the watchdog assoon as the driver is loaded. (int)
parm:           nowayout:Watchdog cannot be stopped once started (default=CONFIG_WATCHDOG_NOWAYOUT) (bool)
parm:           max_speed:Maximum bus speed (0-2). Default: 1=U160. Speeds: 0=80 MB/s, 1=U160, 2=U320 (uint)
parm:           log_level:Set to 0 - 4 for increasing verbosity of device driver (uint)
parm:           testmode:DANGEROUS!!! Allows unsupported configurations (int)
parm:           fastfail:Reduce timeouts and retries (int)
parm:           transop_timeout:Time in seconds to wait for adapter to come operational (default: 300) (int)
parm:           debug:Enable device driver debugging logging. Set to 1 to enable. (default: 0) (int)
parm:           dual_ioa_raid:Enable dual adapter RAID support. Set to 1 to enable. (default: 1) (int)
parm:           max_devs:Specify the maximum number of physical devices. [Default=1024] (int)
parm:           number_of_msix:Specify the number of MSIX interrupts to use on capable adapters (1 - 16).  (default:16) (int)
parm:           fast_reboot:Skip adapter shutdown during reboot. Set to 1 to enable. (default: 0) (int)
parm:           ips:charp
parm:           max_sets:maximal number of sets (int)
parm:           forward:bool
parm:           raw_before_defrag:Enable raw table before defrag (bool)
parm:           conn_tab_bits:Set connections' hash size (int)
parm:           ports:Ports to monitor for FTP control commands (array of ushort)
parm:           disable:manually disable the radio (default 0 [radio on]) (int)
parm:           associate:auto associate when scanning (default off) (int)
parm:           auto_create:auto create adhoc network (default on) (int)
parm:           led:enable led control on some systems (default 1 on) (int)
parm:           debug:debug output mask (int)
parm:           channel:channel to limit associate to (default 0 [ANY]) (int)
parm:           rtap_iface:create the rtap interface (1 - create, default 0) (int)
parm:           qos_enable:enable all QoS functionalitis (int)
parm:           qos_burst_enable:enable QoS burst mode (int)
parm:           qos_no_ack_mask:mask Tx_Queue to no ack (int)
parm:           burst_duration_CCK:set CCK burst value (int)
parm:           burst_duration_OFDM:set OFDM burst value (int)
parm:           mode:network mode (0=BSS,1=IBSS,2=Monitor) (int)
parm:           bt_coexist:enable bluetooth coexistence (default off) (int)
parm:           hwcrypto:enable hardware crypto (default off) (int)
parm:           cmdlog:allocate a ring buffer for logging firmware commands (int)
parm:           roaming:enable roaming support (default on) (int)
parm:           antenna:select antenna 1=Main, 3=Aux, default 0 [both], 2=slow_diversity (choose the one with lower background noise) (int)
parm:           debug:switch on debug messages [0] (int)
parm:           loopback:debug: enable ras_raw channel [0] (int)

