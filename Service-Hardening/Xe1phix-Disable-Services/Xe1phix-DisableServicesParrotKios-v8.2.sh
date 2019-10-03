#!/bin/bash
#########
## Xe1phix-DisableServices-v2.0.sh
#########
UPDATE='$(which update-rc.d)'
export UPDATE='$(which update-rc.d)'
SERVICEBIN='$(which service)'
export SERVICEBIN='$(which service)'


   for SERVICE in                                   \
       greenbone-security-assistant.service         \
       greenbone-security-assistant                 \
       selinux-autorelabel                          \
       selinux-autorelabel-mark.service             \
       selinux-autorelabel.service                  \
       selinux-autorelabel.target                   \
       setroubleshoot                               \
       ModemManager.service                         \
       dbus-org.freedesktop.ModemManager1.service   \
       isc-dhcp-server.service                      \
       dbus-org.bluez.service                       \
       openvas-manager.service                  \
       openvas-scanner.service                  \
       openvas-manager                          \
       openvas-scanner                          \
       opendnssec-enforcer.service              \
       opendnssec-signer.service                \
       opendnssec-enforcer                      \
       opendnssec-signer                        \
       unbound-resolvconf.service               \
       apache-htcacheclean                      \
       apache-htcacheclean@.service             \
       redis-server.service                     \
       redis.service                            \
       python-faraday.service                   \
       apt-daily.service                        \
       apt-daily-upgrade.service                \
       apt-daily.timer                          \
       apt-daily-upgrade.timer                  \
       libbluetooth3                            \
       nfs-kernel-server.service                \
       nfs-server.service                       \
       rpc-statd-notify.service                 \
       beef-xss.service                         \
       iscsi-shutdown.service                   \
       apache2                                  \
       apache2.service      \
       apache2@.service     \
       couchdb.service      \
       arpwatch.service     \
       mysql.service        \
       nginx.service        \
       nginx                \
       smb.service          \
       Xplico.service       \
       xplico.service       \
       ntopng               \
       ntopng.service       \
       fio                  \
       fio.service          \
       darkstat.service     \
       darkstat             \
       postgresql.service   \
       beef-xss             \
       hostapd.service      \
       hostapd              \
       isc-dhcp-server      \
       pppd-dns.service     \
       lighttpd.service     \
       httpd.service        \
       iscsid.service       \
       iscsi.service        \
       mountnfs.service     \
       fstrim.service       \
       fstrim.timer         \
       fstrim               \
       unbound.service      \
       openvpn.service      \
       openvpn              \
       freeradius.service   \
       exim4.service        \
       rpcbind.target       \
       miredo.service       \
       iodined.service      \
       iodined              \
       printer.target       \
       cups                 \
       cups.service         \
       saned.service        \
       saned.socket         \
       inetsim.service      \
       sysstat.service      \
       apt-daily.service    \
       stunnel4.service     \
       ptunnel.service      \
       thin.service         \
       ModemManager         \
       bluetooth.service    \
       bluetooth.target     \
       bluetooth            \
       strongswan.service   \
       strongswan           \
       redsocks.service		\
       redsocks             \
       tinc                 \
       tinc.service         \
       rsync.service        \
       rwhod.service        \
       ssh.service          \
       sslh.service         \
       sslh                 \
       arpwatch             \
       atftpd.service       \
       geoclue              \
       geoclue.service      \
       i2p.service          \
       tor.service          \
       tor                  \
       i2p                  \
       bluetooth            \
       saned                \
       squid.service        \
       mariadb.service      \
       king-phisher.service \
       httpd                \
       samba-ad-dc          \
       lighttpd             \
       iscsi                \
       iscsid               \
       ldap                 \
       ldap.service         \
       mysqld               \
       nfs                  \
       nfs.service          \
       nfslock              \
       dradis.service       \
       dradis               \
       dns2tcp.service      \
       dns2tcp              \
       collectd             \
       collectd.service     \
       collectl             \
       couchdb              \
       nginx                \
       minissdpd            \
       nmbd                 \
       squid                \
       squidtaild           \
       stunnel4             \
       sysstat              \
       mysql                \
       rsync                \
       ssh                  \
       xplico               \
       rwhod                \
       pppd-dns             \
       shorewall            \
       smbd                 \
       freeradius           \
       ptunnel              \
       miredo               \
       inetsim              \
       dns2tcp              \
       dns2tcp.service      \
       atftpd               \
       fireqos              \
       firehol              \
       ferm                 \
       exim4                \
       gnunet               \
       htpdate              \
       postgresql           \
       privoxy              \
       psacct               \
       radvd                \
       rarpd                \
       rdisc                \
       rusersd              \
       rpcgssd              \
       rpcsvcgssd           \
       rpcidmapd            \
       rpcsvcgssd           \
       saslauthd            \
       sendmail             \
       cyrus-imapd          \
       dovecot              \
       tomcat5              \
       ypbind               \
       yppasswdd            \
       ypserv               \
       ypxfrd               \
       smb                  \
       snmpd                \
       snmpd.service        \
       snmptrapd            \
       spamassassin         \
       squid                \
       unbound              \
       winbind              \
       wine                 \
       wpa_supplicant;
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
			## systemctl mask $SERVICE                          ## Uncomment this line to mask services
			## chkconfig --del 
            ## echo "install bluetooth /bin/false" > /etc/modprobe.d/bluetooth.conf
			update-rc.d $SERVICE disable 
			## update-rc.d $SERVICE remove 
      fi
done
