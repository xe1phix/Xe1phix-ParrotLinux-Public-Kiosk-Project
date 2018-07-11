#!/bin/bash
#########
## Xe1phix-DisableServices-v2.0.sh
#########
UPDATE='$(which update-rc.d)'
export UPDATE='$(which update-rc.d)'
SERVICEBIN='$(which service)'
export SERVICEBIN='$(which service)'


   for SERVICE in								\
       greenbone-security-assistant.service		\
       NetworkManager-wait-online.service		\
       NetworkManager-dispatcher.service		\
       isc-dhcp-server.service					\
       dbus-org.bluez.service					\
       openvas-manager.service					\
       openvas-scanner.service					\
       opendnssec-enforcer.service              \
       opendnssec-signer.service                \
       opendnssec-enforcer                      \
       opendnssec-signer                        \
       apache-htcacheclean                      \
       libbluetooth3					        \
       networking.service						\
       NetworkManager.service					\
       network-online.target					\
       beef-xss.service							\
       network.target		\
       apache2.service		\
       couchdb.service		\
       arpwatch.service     \
       mysql.service		\
       postgresql.service	\
       pppd-dns.service		\
       lighttpd.service     \
       printer.target		\
       apt-daily.service    \
       stunnel4.service		\
       thin.service			\
       bluetooth.service	\
       bluetooth.target     \
       redsocks.service		\
       rsync.service		\
       rwhod.service		\
       ssh.service			\
       arpwatch.service		\
       atftpd.service		\
       geoclue.service		\
       i2p.service			\
       tor.service			\
       bluetooth			\
       saned                \
       squid.service        \
       mariadb.service      \
       king-phisher.service \
       httpd           		\
       samba-ad-dc    		\
       lighttpd				\
       ip6tables			\
       iscsi				\
       iscsid				\
       ldap				    \
       mysqld               \
       nfs                  \
       collectd             \
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
       xplico               \
       rwhod                \
       shorewall            \
       smbd                 \
       freeradius           \
       ptunnel              \
       dns2tcp              \
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
       rpcgssd              \
       rpcidmapd            \
       rpcsvcgssd           \
       saslauthd            \
       sendmail             \
       smb                  \
       snmpd                \
       snmptrapd            \
       spamassassin         \
       squid                \
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
			## systemctl mask $SERVICE
			## chkconfig --del 
            ## echo "install bluetooth /bin/false" > /etc/modprobe.d/bluetooth.conf
			## update-rc.d $SERVICE disable 
			## update-rc.d $SERVICE remove 
      fi
done