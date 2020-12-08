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
##      sysstat                                              \
##      modprobe@drm.service                    \
##      sysstat.service                                 \
##      collectd                                           \
##      collectd.service                                \
##      collectl                                            \
##      openvpn.service                             \
##      openvpn                                         \
##-=======================================-##

   for SERVICE in                                       \
       greenbone-security-assistant.service    \
       greenbone-security-assistant                 \
       selinux-autorelabel                                 \
       selinux-autorelabel-mark.service           \
       selinux-autorelabel.service                     \
       selinux-autorelabel.target                       \
       setroubleshoot                                         \
       wacom-inputattach@.service                   \
       ModemManager.service                         \
       isc-dhcp-server.service                           \
       dbus-org.bluez.service                             \
       strongswan-starter.service                        \
       openvas-manager.service                          \
       openvas-scanner.service                           \
       openvas-manager                                      \
       openvas-scanner                                        \
       opendnssec-enforcer.service         \
       opendnssec-signer.service             \
       opendnssec-enforcer                      \
       opendnssec-signer                          \
       apache-htcacheclean                      \
       apache-htcacheclean@.service       \
       xencommons.service                       \
       xendomains.service                         \
       xl2tpd.service                                  \
       libvirt-guests.service                       \
       libvirtd.service                                 \
       virtualbox.service                           \
       vboxweb.service                              \
       open-vm-tools.service                    \
       libvirtd.socket                                  \
       libvirtd-admin.socket                        \
       virt-guest-shutdown.target               \
       virtlockd-admin.socket                   \
       virtlockd.socket                                 \
       virtlogd-admin.socket                        \
       virtlogd.socket                                  \
       ykval-queue.service                             \
       redis-server.service                             \
       redis.service                                        \
       python-faraday.service                       \
       apt-daily.service                                \
       apt-daily-upgrade.service                \
       apt-daily.timer                                  \
       apt-daily-upgrade.timer                  \
       libbluetooth3                                  \
       nfs-kernel-server.service                \
       nfs-server.service                           \
       rpc-statd-notify.service                 \
       beef-xss.service                             \
       iscsi-shutdown.service                   \
       apache2                                          \
       apache2.service                              \
       apache2@.service                           \
       couchdb.service                              \
       arpwatch.service                             \
       mysql.service                                  \
       nginx.service                        \
       nginx                                     \
       smb.service                          \
       Xplico.service                       \
       xplico.service                       \
       ntopng                                   \
       ntopng.service                       \
       netperf                                  \
       netperf.service                      \
       fio                                          \
       fio.service                              \
       darkstat.service                     \
       darkstat                                 \
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
       saned.socket                              \
       inetsim.service                          \
       apt-daily.service                        \
       stunnel4.service                         \
       ptunnel.service             \
       thin.service                   \
       ModemManager           \
       bluetooth.service          \
       bluetooth.target            \
       bluetooth                      \
       strongswan.service       \
       strongswan                   \
       ipsec                            \
       ipsec.service                \
       l2tpd                            \
       l2tpd.service                \
       redsocks.service          \
       redsocks                       \
       tinc                               \
       tinc.service                  \
       rsync.service                \
       rwhod.service              \
       ssh.service                   \
       sslh.service                  \
       sslh                               \
       arpwatch                      \
       atftpd.service               \
       geoclue                         \
       geoclue.service             \
       i2p.service                    \
       tor.service                      \
       tor                                   \
       i2p                                   \
       bluetooth                        \
       saned                               \
       squid.service                   \
       mariadb                          \
       mariadb.service              \
       king-phisher.service       \
       httpd                                \
       samba-ad-dc                    \
       samba-ad-dc.service       \
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
       dns2tcp.service                   \
       dns2tcp                                \
       couchdb                              \
       nginx                                    \
       minissdpd                       \
       nmbd                              \
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
       smbd.service             \
       freeradius                   \
       ptunnel                      \
       miredo                       \
       inetsim                       \
       dns2tcp                      \
       dns2tcp.service          \
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
       squid                  \
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
			## systemctl mask $SERVICE                                          ## Uncomment this line to mask services
			## chkconfig --del 
			update-rc.d $SERVICE disable 
			## update-rc.d $SERVICE remove 
      fi
done
