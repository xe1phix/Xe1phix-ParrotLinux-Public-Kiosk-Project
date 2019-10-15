#!/bin/bash
#########
## Xe1phix-EnableServices-v2.3.sh
#########
UPDATE='$(which update-rc.d)'
export UPDATE='$(which update-rc.d)'
SERVICEBIN='$(which service)'
export SERVICEBIN='$(which service)'


   for SERVICE in								\
       sys-devices-virtual-misc-rfkill.device   \
       systemd-tmpfiles-setup-dev.service       \
       systemd-rfkill.service		            \
       dev-rfkill.device                        \
       systemd-rfkill.service                   \
       systemd-rfkill.socket                    \
       systemd-sysctl.service                   \
       systemd-tmpfiles-setup.service           \
       systemd-update-utmp.service              \
       sagan.service					        \
       snort.service					\
       suricata.service					\
       logrotate.service				\
       logrotate.timer                  \
       smartd.service                   \
       sysstat.service                  \
       polkit.service                   \
       rsyslog.service                  \
       syslog.service                   \
       syslog.socket                    \
       systemd-journald.service         \
       systemd-journald-audit.socket    \
       systemd-journald-dev-log.socket  \
       systemd-journald.socket          \
       systemd-modules-load.service     \
       sudo.service                     \
       udisks2.service                  \
       zfs-fuse.service                 \
       ipset.service                    \
       iptables.service                 \
       ufw.service                      \
       suricata             \
       ufw          		\
       snort                \
       sagan                \
       firewalld            \
       apparmor             \
       polkit               \
       logrotate            \
       smartd               \
       hddtemp              \
       smartmontools        \
       collectd             \
       collectl             \
       rsyslog              \
       sudo                 \
       sysstat              \
       udisks2              \
       zfs-fuse             \
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
