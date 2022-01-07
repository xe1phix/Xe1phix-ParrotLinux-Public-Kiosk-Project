#!/bin/bash
#####################################
## Xe1phix-DisableServices-v*.*.sh ##
#####################################
UPDATE='$(which update-rc.d)'
export UPDATE='$(which update-rc.d)'
SERVICEBIN='$(which service)'
export SERVICEBIN='$(which service)'


##-=======================================-##
##      unbound                                         \
##      unbound.service                              \
##      unbound-resolvconf.service              \
##      wpa_supplicant                               \
##      hostapd.service                                 \
##      hostapd                                              \
##      modprobe@drm.service                    \
##      collectd                                           \
##      collectd.service                                \
##      collectl                                            \
##      openvpn.service                             \
##      openvpn                                         \
##-=======================================-##

   for SERVICE in                                       \
       greenbone-security-assistant.service         \
       greenbone-security-assistant                 \
       selinux-autorelabel                          \
       selinux-autorelabel-mark.service             \
       selinux-autorelabel.service                     \
       selinux-autorelabel.target                       \
       setroubleshoot                               \
       wacom-inputattach@.service                   \
       ModemManager.service                         \
       isc-dhcp-server.service                           \
       dbus-org.bluez.service                             \
       strongswan-starter.service                        \
       openvas-manager.service                          \
       openvas-scanner.service                           \
       openvas-manager                                      \
       openvas-scanner                                        \
       ospd-openvas                                 \
       ospd-openvas.service                         \
       gvmd                                         \
       gvmd.service                                 \
       opendnssec-enforcer.service                  \
       opendnssec-signer.service                    \
       opendnssec-enforcer                          \
       opendnssec-signer                          \
       apache-htcacheclean                      \
       apache-htcacheclean@.service                 \
       corosync.service                             \
       cloud-init-local.service                     \
       shellinabox                                  \
       shellinabox.service                          \
       zfs-fuse                                     \
       zfs-zed.dpkg-new                             \
       sheepdog                                     \
       mdmon                                        \
       mdmon@.service                               \
       mdadm                                        \
       mdadm.service                                \
       mdadm-shutdown.service                       \
       mdadm-waitidle.service                       \
       mdadm-grow-continue@.service                 \
       mdadm-last-resort@.service                   \
       mdadm-last-resort@.timer                     \
       mdcheck_continue.service                     \
       mdcheck_continue.timer                       \
       mdcheck_start.service                        \
       mdcheck_start.timer                          \
       mdmonitor-oneshot.service                    \
       mdmonitor-oneshot.timer                      \
       mdmonitor.service                            \
       modprobe@drm.service                         \
       sanoid-prune.service                         \
       sanoid.service                               \
       sanoid.timer                                 \
       schroot.service                              \
       anbox-container-manager.service              \
       var-lib-lxcfs.mount                          \
       lxcfs.mount                                  \
       lxcfs                                        \
       lxcfs.service                                \
       lxc-net                                      \
       lxc-net.service                              \
       lxc                                          \
       lxc.service                                  \
       lxc@.service                                 \
       xencommons.service                           \
       xendomains.service                           \
       usbmuxd                                      \
       usbmuxd.service                              \
       wacom-inputattach@.service                   \
       unbound                                      \
       unbound.service                              \
       unbound-resolvconf.service                   \
       xl2tpd                                       \
       xl2tpd.service                               \
       firewalld                                    \
       firewalld.service                            \
       libvirt-guests.service                       \
       libvirtd.service                             \
       virtualbox.service                           \
       virtualbox-guest-utils                       \
       vboxweb.service                              \
       open-vm-tools.service                        \
       libvirtd.socket                              \
       libvirtd-admin.socket                        \
       libvirtd-tcp.socket                          \
       libvirtd-tls.socket                          \
       virt-guest-shutdown.target                   \
       virtlockd-admin.socket                       \
       virtlockd.socket                             \
       virtlogd-admin.socket                        \
       virtlogd.socket                              \
       ykval-queue.service                             \
       redis-server.service                             \
       redis.service                                \
       python-faraday.service                       \
       faraday.service                              \
       apt-daily.service                            \
       apt-daily-upgrade.service                    \
       apt-daily.timer                                  \
       apt-daily-upgrade.timer                      \
       libbluetooth3                                  \
       nfs-kernel-server.service                    \
       nfs-server.service                           \
       rpc-statd-notify.service                     \
       beef-xss.service                             \
       iscsi-shutdown.service                       \
       apache2                                          \
       apache2.service                              \
       apache2@.service                             \
       couchdb.service                              \
       arpwatch.service                             \
       mysql.service                                  \
       nginx.service                                \
       nginx                                        \
       smb.service                              \
       sysstat                                      \
       sysstat.service                             \
       sysstat-collect.service                      \
       sysstat-collect.timer                        \
       sysstat-summary.service                      \
       sysstat-summary.timer                        \
       kismet                                       \
       kismet.service                               \
       bettercap                                    \
       bettercap.service                            \
       Xplico.service                               \
       xplico.service                               \
       ntopng                                       \
       ntopng.service                               \
       netperf                                      \
       netperf.service                              \
       fio                                          \
       fio.service                                  \
       darkstat.service                             \
       darkstat                                     \
       postgresql.service                  \
       beef-xss                                 \
       isc-dhcp-server                      \
       pppd-dns.service                    \
       lighttpd.service                       \
       httpd.service                            \
       iscsid.service                           \
       iscsi.service                             \
       mountnfs.service                     \
       fstrim.service                           \
       fstrim.timer                              \
       fstrim                                         \
       freeradius.service                      \
       exim4.service                            \
       exim4-base.timer                       \
       exim4-base.service                   \
       rpcbind.target                             \
       miredo.service                           \
       iodined.service                          \
       iodined                                      \
       printer.target                             \
       cups                                           \
       cups.service                              \
       cups-browsed                            \
       cups.socket                                \
       saned.service                             \
       saned@.service                            \
       saned.socket                              \
       inetsim.service                          \
       apt-daily.service                        \
       stunnel@.service                         \
       stunnel.target                           \
       stunnel4.service                         \
       ptunnel.service                          \
       thin                                     \
       thin.service                             \
       ModemManager                             \
       bluetooth.service                        \
       bluetooth.target                         \
       bluetooth                                \
       acmetool.service                         \
       acmetool.timer                           \
       openvpn-server                           \
       openvpn-server@.service                  \
       strongswan.service                       \
       strongswan                               \
       ipsec                                    \
       ipsec.service                            \
       l2tpd                                    \
       l2tpd.service                \
       redsocks.service          \
       redsocks                       \
       shadowsocks                             \
       shadowsocks.service                      \
       shadowsocks-local@.service               \
       shadowsocks-server@.service              \
       tinc                                     \
       tinc.service                             \
       rsync.service                \
       rwhod.service              \
       ssh.service                   \
       sslh.service                  \
       sslh                               \
       arpwatch                      \
       atftpd.service               \
       geoclue                         \
       geoclue.service             \
       geoipupdate.service          \
       geoipupdate.timer            \
       smartcard.target                 \
       i2p.service                    \
       tor.service                      \
       tor                                   \
       tor@default.service              \
       tor@.service                             \
       i2p                                   \
       onioncat                         \
       onioncat.service                 \
       bluetooth                        \
       saned                               \
       squid.service                   \
       opensnitch                       \
       opensnitch.service               \
       mariadb                          \
       mariadb.service                  \
       king-phisher                     \
       king-phisher.service             \
       httpd                                \
       samba-ad-dc                    \
       samba-ad-dc.service              \
       lighttpd                             \
       iscsi                                   \
       iscsid                                 \
       ldap                                   \
       ldap.service                       \
       mysqld                               \
       nfs                                      \
       nfs.service                          \
       nfslock                                \
       dradis.service                     \
       dradis                                   \
       couchdb                              \
       nginx                                    \
       minissdpd                       \
       nmbd                              \
       nmbd.service                         \
       squid                              \
       squidtaild                       \
       stunnel4                         \
       mysql                            \
       atd.service                    \
       rsync                            \
       ssh                                \
       xplico                          \
       rwhod                         \
       pppd-dns                     \
       shorewall                    \
       smbd                          \
       smbd.service                     \
       freeradius                   \
       ptunnel                      \
       miredo                       \
       inetsim                       \
       dns2tcp                      \
       dns2tcp.service                  \
       atftpd                           \
       fireqos                          \
       firehol                          \
       ferm                 \
       exim4                \
       gnunet               \
       htpdate              \
       postgresql           \
       privoxy              \
       psacct               \
       radvd                \
       rarpd                \
       rdisc                 \
       rusersd              \
       rpcgssd              \
       rpcsvcgssd          \
       rpcidmapd          \
       rpcsvcgssd          \
       saslauthd            \
       sendmail             \
       cyrus-imapd       \
       dovecot              \
       tomcat5              \
       ypbind               \
       yppasswdd         \
       ypserv               \
       ypxfrd               \
       smb                   \
       snmpd               \
       snmpd.service   \
       snmptrapd         \
       spamassassin     \
       winbind              \
       wine;
do
      if [ -e /etc/init.d/$SERVICE ]; then
            # Doing business this way causes less needless errors that a
            # reviewer of the hardening process doesn't need to deal with.
            /etc/init.d/$SERVICE stop
            $SERVICEBIN $SERVICE stop
            ## /sbin/chkconfig --level 0123456 $SERVICE off
            $UPDATE $SERVICE disable
            ## /sbin/service $SERVICE stop
            ## /usr/bin/service $SERVICE stop
            ## /usr/sbin/update-rc.d $SERVICE disable
			## /sbin/update-rc.d $SERVICE disable
			## update-rc.d $SERVICE remove 
			
      else
            echo "SERVICE doesn't exist in /etc/init.d/ ($SERVICE)."
            echo "Trying to disable it through systemctl..." 
			systemctl stop $SERVICE
			systemctl disable $SERVICE
			## /sbin/chkconfig --level 12345 $SERVICE off
			systemctl mask $SERVICE                                          ## Uncomment this line to mask services
			## chkconfig --del 
			update-rc.d $SERVICE disable 
			## update-rc.d $SERVICE remove 
      fi
done
