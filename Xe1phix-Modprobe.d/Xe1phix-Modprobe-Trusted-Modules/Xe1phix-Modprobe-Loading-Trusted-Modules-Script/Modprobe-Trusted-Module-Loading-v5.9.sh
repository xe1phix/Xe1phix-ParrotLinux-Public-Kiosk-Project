#!/bin/sh
##-=============================================-##
##  [+] Modprobe-Trusted-Module-Loading-v*.*.sh
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
modprobe --verbose --install forcedeth
## ------------------------------------------------------------------ ##
modprobe --verbose --install virtio
modprobe --verbose --install virtio_blk
modprobe --verbose --install virtio_input
modprobe --verbose --install virtio_pci
modprobe --verbose --install virtio_console
## ------------------------------------------------------------------ ##
modprobe --verbose --install sr_mod
## ------------------------------------------------------------------ ##
modprobe --verbose --install cpufreq_userspace
## ------------------------------------------------------------------ ##
modprobe --verbose --install tpm_atmel.ko
modprobe --verbose --install tpm_crb.ko
modprobe --verbose --install tpm_i2c_atmel.ko
modprobe --verbose --install tpm_i2c_infineon.ko
modprobe --verbose --install tpm_i2c_nuvoton.ko
modprobe --verbose --install tpm_infineon.ko
modprobe --verbose --install tpm.ko
modprobe --verbose --install tpm_nsc.ko
modprobe --verbose --install tpm_tis_core.ko
modprobe --verbose --install tpm_tis.ko
modprobe --verbose --install tpm_tis_spi.ko
modprobe --verbose --install tpm_vtpm_proxy.ko
modprobe --verbose --install xen-tpmfront.ko
modprobe --verbose --install tpm_st33zp24_i2c.ko
modprobe --verbose --install tpm_st33zp24.ko
## ------------------------------------------------------------------ ##
modprobe --verbose --install macvlan
modprobe --verbose --install macvtap
modprobe --verbose --install veth
modprobe --verbose --install openvswitch
modprobe --verbose --install overlay
modprobe --verbose --install cls_basic
modprobe --verbose --install cls_bpf
modprobe --verbose --install cls_cgroup
modprobe --verbose --install cls_flow
modprobe --verbose --install cls_fw
modprobe --verbose --install cls_matchall
modprobe --verbose --install cls_route
modprobe --verbose --install cls_u32
## ------------------------------------------------------------------ ##
modprobe --verbose --install br_netfilter               ## Linux ethernet netfilter firewall bridge             ## /lib/modules/5.2.0-2parrot1-amd64/kernel/net/bridge/br_netfilter.ko
modprobe --verbose --install bridge                     ## /lib/modules/5.2.0-2parrot1-amd64/kernel/net/bridge/bridge.ko
## alias rtnl-link-bridge
## ------------------------------------------------------------------ ##
modprobe --verbose --install tap
## ------------------------------------------------------------------ ##
modprobe --verbose --install batman_adv          ## B.A.T.M.A.N. advanced                            ## /lib/modules/5.2.0-2parrot1-amd64/kernel/net/batman-adv/batman-adv.ko
## alias net-pf-16-proto-16-family-batadv
## alias rtnl-link-batadv
## ------------------------------------------------------------------ ##
modprobe --verbose --install ax25                ## amateur radio AX.25 link layer protocol          ## /lib/modules/5.2.0-2parrot1-amd64/kernel/net/ax25/ax25.ko
## ------------------------------------------------------------------ ##
modprobe --verbose --install cdrom
modprobe --verbose --install loop
modprobe --verbose --install act_vlan
modprobe --verbose --install act_ipt
modprobe --verbose --install act_connmark
modprobe --verbose --install act_bpf
modprobe --verbose --install act_csum
modprobe --verbose --install ip_set
modprobe --verbose --install iptable_filter
modprobe --verbose --install nf_conncount
modprobe --verbose --install nf_conntrack
modprobe --verbose --install nf_conntrack_ftp
modprobe --verbose --install nf_conntrack_irc
modprobe --verbose --install nf_conntrack_netlink
modprobe --verbose --install nf_conntrack_broadcast
modprobe --verbose --install nf_conntrack_tftp
modprobe --verbose --install ebtable_filter
modprobe --verbose --install ebtable_nat
modprobe --verbose --install ebtables
modprobe --verbose --install ebt_vlan
modprobe --verbose --install ebt_pkttype
modprobe --verbose --install ebt_nflog
modprobe --verbose --install ebt_mark_m
modprobe --verbose --install ebt_mark
modprobe --verbose --install ebt_log
modprobe --verbose --install ebt_limit
modprobe --verbose --install iptable_security
modprobe --verbose --install ipt_rpfilter
modprobe --verbose --install ip_set
modprobe --verbose --install ip_set_hash_ipmark
## ------------------------------------------------------------------ ##
modprobe --verbose --install nf_flow_table
modprobe --verbose --install nf_log_arp
modprobe --verbose --install nf_log_common
modprobe --verbose --install nfnetlink_log
## ------------------------------------------------------------------ ##
modprobe --verbose --install kvm-amd
modprobe --verbose --install kvm-intel
modprobe --verbose --install hackrf
modprobe --verbose --install qemu_fw_cfg
modprobe --verbose --install wire
modprobe --verbose --install wireguard
modprobe --verbose --install xen-acpi-processor
modprobe --verbose --install xenfs
## ------------------------------------------------------------------ ##
modprobe --verbose --install xfrm4_tunnel
modprobe --verbose --install xfrm_algo
modprobe --verbose --install l2tp_core
modprobe --verbose --install l2tp_debugfs
modprobe --verbose --install l2tp_eth
modprobe --verbose --install l2tp_ip
modprobe --verbose --install ipvtap
modprobe --verbose --install lz4_compress
modprobe --verbose --install crc32_generic
modprobe --verbose --install crc32c-intel
modprobe --verbose --install crypto_engine
modprobe --verbose --install crypto_user
## ------------------------------------------------------------------ ##
modprobe --verbose --install sha1-ssse3
modprobe --verbose --install sha256-ssse3
modprobe --verbose --install sha512_generic
modprobe --verbose --install sha512-ssse3
modprobe --verbose --install sha3_generic
modprobe --verbose --install dm-crypt
modprobe --verbose --install dm-integrity
modprobe --verbose --install dm-log
modprobe --verbose --install dm-log-userspace
modprobe --verbose --install dm-log-writes
modprobe --verbose --install dm-mod
## ------------------------------------------------------------------ ##
modprobe --verbose --install dst_ca
modprobe --verbose --install tcrypt
## ------------------------------------------------------------------ ##
modprobe --verbose --install dm-zoned
modprobe --verbose --install lineage-pem
## ------------------------------------------------------------------ ##
modprobe --verbose --install lttng-tracer
## ------------------------------------------------------------------ ##
modprobe --verbose --install dns_resolver
modprobe --verbose --install xt_addrtype
modprobe --verbose --install xt_AUDIT
modprobe --verbose --install xt_bpf
modprobe --verbose --install xt_cgroup
modprobe --verbose --install xt_CHECKSUM
modprobe --verbose --install xt_CLASSIFY
modprobe --verbose --install xt_cluster
modprobe --verbose --install xt_comment
modprobe --verbose --install xt_connbytes
modprobe --verbose --install xt_connlabel
modprobe --verbose --install xt_connlimit
modprobe --verbose --install xt_connmark
modprobe --verbose --install xt_CONNSECMARK
modprobe --verbose --install xt_conntrack
modprobe --verbose --install xt_cpu
modprobe --verbose --install xt_CT
modprobe --verbose --install xt_dccp
modprobe --verbose --install xt_devgroup
modprobe --verbose --install xt_dscp
modprobe --verbose --install xt_DSCP
modprobe --verbose --install xt_ecn
modprobe --verbose --install xt_esp
modprobe --verbose --install xt_hashlimit
modprobe --verbose --install xt_helper
modprobe --verbose --install xt_hl
modprobe --verbose --install xt_HL
modprobe --verbose --install xt_HMARK
modprobe --verbose --install xt_IDLETIMER
modprobe --verbose --install xt_ipcomp
modprobe --verbose --install xt_iprange
modprobe --verbose --install xt_ipvs
modprobe --verbose --install xt_l2tp
modprobe --verbose --install xt_LED
modprobe --verbose --install xt_length
modprobe --verbose --install xt_limit
modprobe --verbose --install xt_LOG
modprobe --verbose --install xt_mac
modprobe --verbose --install xt_mark
modprobe --verbose --install xt_MASQUERADE
modprobe --verbose --install xt_multiport
modprobe --verbose --install xt_nat
modprobe --verbose --install xt_NETMAP
modprobe --verbose --install xt_nfacct
modprobe --verbose --install xt_NFLOG
modprobe --verbose --install xt_NFQUEUE
modprobe --verbose --install xt_osf
modprobe --verbose --install xt_owner
modprobe --verbose --install xt_physdev
modprobe --verbose --install xt_pkttype
modprobe --verbose --install xt_policy
modprobe --verbose --install xt_quota
modprobe --verbose --install xt_rateest
modprobe --verbose --install xt_RATEEST
modprobe --verbose --install xt_realm
modprobe --verbose --install xt_recent
modprobe --verbose --install xt_REDIRECT
modprobe --verbose --install xt_sctp
modprobe --verbose --install xt_SECMARK
modprobe --verbose --install xt_set
modprobe --verbose --install xt_socket
modprobe --verbose --install xt_state
modprobe --verbose --install xt_statistic
modprobe --verbose --install xt_string
modprobe --verbose --install xt_tcpmss
modprobe --verbose --install xt_TCPMSS
modprobe --verbose --install xt_TCPOPTSTRIP
modprobe --verbose --install xt_tcpudp
modprobe --verbose --install xt_TEE
modprobe --verbose --install xt_time
modprobe --verbose --install xt_TPROXY
modprobe --verbose --install xt_TRACE
modprobe --verbose --install xt_u32
