#!/bin/bash
#########
## Xe1phix-EnableServices-v2.3.sh
#########
UPDATE='$(which update-rc.d)'
export UPDATE='$(which update-rc.d)'
SERVICEBIN='$(which service)'
export SERVICEBIN='$(which service)'


   for SERVICE in								    \
       dbus-org.fedoraproject.FirewallD1.service    \
       sys-devices-virtual-misc-rfkill.device       \
       systemd-tmpfiles-setup-dev.service           \
       systemd-tmpfiles-setup.service               \
       systemd-update-utmp.service                  \
       systemd-rfkill.service		                \
       dev-rfkill.device                            \
       sys-devices-virtual-misc-rfkill.device       \
       systemd-rfkill.service                       \
       systemd-rfkill.socket                        \
       systemd-sysctl.service           \
       binfmt-support.service           \
       debug-shell.service              \
       yhsm-yubikey-ksm                 \
       paxctld.service                  \
       apparmor.service                 \
       sagan.service					\
       snort.service					\
       suricata.service					\
       auditd.service                   \
       gnunet.service                   \
## ------------------------------------ \
##     opendnssec-enforcer.service      \
##     opendnssec-signer.service        \
##     ods-enforcerd.service            \
##     unbound-resolvconf.service       \
##     unbound.service                  \
##     curvedns.service                 \
##     fprobe.service                   \
##     pcapdump.service                 \
## ------------------------------------ \
##     zram-setup@.service              \
##     zram-setup@zram0.service         \
##     zram-setup@zram1.service         \
##     zramswap.service                 \
## ------------------------------------ \
##     yhsm-yubikey-ksm.service         \
##     lttng-sessiond.service           \
##     dracut-mount.service             \
## ------------------------------------ \
##     libvirtd.service                 \
##     libvirt-guests.service           \
##     qemu-guest-agent.service         \
##     virtlockd-admin.socket           \
##     virtlockd.socket                 \
##     virtlogd                         \
##     virtlogd.service                 \
## ------------------------------------ \
##     xplico.service                   \
##     Xplico.service                   \
##     ntopng.service                   \
##     cockpit.service                  \
##     cockpit.socket                   \
##     cockpit-motd.service             \
## ------------------------------------ \
##     lxc.service                      \
##     lxcfs.service                    \
##     var-lib-lxcfs.mount              \
## ------------------------------------ \
##     tinc                             \
##     tinc.service                     \
##     redsocks                         \
##     redsocks.service                 \
##     i2p                              \
##     i2p.service                      \
##     tor                              \
##     tor@default.service              \
##     tor.service                      \
##     tor@.service                     \
##     onioncat.service                 \
## ------------------------------------ \
##     l2tpd.service                    \
##     xl2tpd.service                   \
##     stunnel4.service                 \
##     openvpn-server@.service          \
##     ssh.service                      \
##     ssh@.service                     \
##     ssh.socket                       \
##     sshd.service                     \
##     sslh.service                     \
##     ntp.service                      \
##     quotaon.service                  \
##     systemd-quotacheck.service       \
## ------------------------------------ \
       logrotate.service				\
       logrotate.timer                  \
       alsa-state.service               \
       alsa-restore.service             \
       alsa-utils.service               \
       smartd.service                   \
       smartmontools.service            \
       sysstat.service                  \
       polkit.service                   \
       rsyslog.service                  \
       syslog.service                   \
       syslog.socket                    \
       lvm2-lvmpolld.socket             \
       lvm2-monitor.service             \
       systemd-journald.service         \
       systemd-journald-audit.socket    \
       systemd-journald-dev-log.socket  \
       systemd-journald.socket          \
       systemd-modules-load.service     \
       systemd-udevd.service            \
       systemd-fsckd.service            \
       systemd-fsck-root.service        \
       xfs_scrub_all.service            \
       xfs_scrub_all.timer              \
       xfs_scrub_fail@.service          \
       xfs_scrub@.service               \
       btrfs-scrub.service              \
       btrfs-scrub.timer                \
       btrfs-defrag.service             \
       btrfs-defrag.timer               \
       btrfsmaintenance-refresh.service \
       btrfsmaintenance-refresh.path    \
## ------------------------------------ \
##     btrfs-trim.service               \
##     btrfs-trim.timer                 \
##     fstrim.service                   \
##     fstrim.timer                     \
## ------------------------------------ \
       cgroupfs-mount.service           \
       sudo.service                     \
       cron.service                     \
       udev.service                     \
       dbus.service                     \
       kmod.service                     \
       kmod                             \
       udisks2.service                  \
       zfs.target                       \
       zfs-fuse.service                 \
       zfs-import-cache.service         \
       zfs-import-scan.service          \
       zfs-import.target                \
       zfs-mount.service                \
       zfs-share.service                \
       zfs-zed.service                  \
       ipset.service                    \
       ebtables.service                 \
       nftables.service                 \
       openvpn.service                  \
       openvpn-client@.service          \
       openvpn@.service                 \
       wg-quick@.service                \
       vtun.service                     \
       saslauthd                        \
       spamassassin                     \
       certbot.timer                    \
       acmetool.service                 \
       acmetool                         \
       acmetool.timer                   \
       certbot.timer                    \
       certbot.service                  \
       iptables.service                 \
       ufw.service                      \
       suricata             \
       pcapdump             \
       darkstat             \
       darkstat.service     \
       ufw          		\
       paxctld.service      \
       snort                \
       sagan                \
       ippl                 \
       ippl.service         \
       bootlogd.service     \
       bootlogs.service     \
       firewalld            \
       plymouth-log         \
       apparmor             \
       polkit               \
       logrotate            \
       cron                 \
       smartd               \
       hddtemp              \
       hddtemp.service      \
       smartmontools        \
       collectd             \
       collectl             \
       rsyslog              \
       sudo                 \
       schroot              \
       schroot.service      \
       sysstat              \
       haveged              \
       haveged.service      \
       fio                  \
       fio.service          \
       udisks2              \
       btrbk                \
       btrbk.service        \
       zfs-fuse             \
       zfs-import           \
       zfs-mount            \
       zfs-share            \
       htpdate              \
       iptables;
do
      if [ -e /etc/init.d/$SERVICE ]; then
            echo "##-======================================================-##"
            echo "     [+] Enabling & Starting Pre-Approved Services..."
            echo "##-======================================================-##"
            /etc/init.d/$SERVICE start
            $SERVICEBIN $SERVICE start
            ## /sbin/chkconfig --level 0123456 $SERVICE on
            $UPDATE $SERVICE enable
            /sbin/service $SERVICE start
            /usr/bin/service $SERVICE start
            ## /usr/sbin/update-rc.d $SERVICE enable
			## /sbin/update-rc.d $SERVICE enable
			
      else
            echo "##-============================================================-##"
            echo "     [?] SERVICE Doesn't Exist In /etc/init.d/ ($SERVICE)."
            echo "##-============================================================-##"
            echo -e "\n\n\n\n\n"
            echo "##-=====================================================-##"
            echo "      [+] Trying To Enable It Through Systemctl..." 
            echo "##-=====================================================-##"
			systemctl start $SERVICE
			systemctl enable $SERVICE
			## /sbin/chkconfig --level 12345 $SERVICE on
			systemctl unmask $SERVICE
			## chkconfig --add 
			update-rc.d $SERVICE enable
      fi
done
