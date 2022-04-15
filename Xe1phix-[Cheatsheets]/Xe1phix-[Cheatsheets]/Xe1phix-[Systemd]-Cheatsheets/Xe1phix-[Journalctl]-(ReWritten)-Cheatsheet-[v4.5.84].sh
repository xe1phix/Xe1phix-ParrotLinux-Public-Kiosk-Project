#!/bin/sh

## On systems where /var/log/journal/ does not exist
## yet but where persistent logging is desired.
## create the directory, and ensure it has the correct access modes:
mkdir --mode=0774 /var/log/journal

systemd-tmpfiles --create --prefix /var/log/journal
/etc/systemd/journald.conf




journalctl --list-boots | head
journalctl -k                           ## kernel messages
journalctl -k -f                        ## follow kernel messages
journalctl -u NetworkManager.service    ## Service messages
journalctl -f -u NetworkManager.service ## follow service
journalctl -fn 0 -u NetworkManager -u wpa_supplicant
journalctl -u httpd.service             ##
journalctl -k -b -1                     ## view the boot logs
journalctl /dev/sda                     ## all logs of the kernel device node `/dev/sda`
journalctl -u systemd-networkd
journalctl -u auditd.service            ##
journalctl --list-boots                 ## check only boot messages
journalctl -b $BootID                   ## show boot messages for a selected boot ID

journalctl _SYSTEMD_UNIT=avahi-daemon.service
journalctl -p emerg..err
journalctl -o verbose
journalctl --since "2019-07-05 21:30:01" --until "2019-07-05 21:30:02"
journalctl -n50 --since "1 hour ago"



journalctl --grep=SECCOMP --follow
firejail --seccomp-error-action=log /usr/bin/signal-desktop
firejail --debug-syscalls | grep



journalctl --rotate

journalctl --sync


journalctl -u networking --no-pager | tail -20
journalctl -u systemd-networkd --no-pager | tail -20


journalctl -f | grep vpn
tail -f /var/log/syslog | grep vpn
egrep -w 'warning|error|critical' /var/log/messages


journalctl --unit openvpn-client
journalctl -u openvpn-client@
journalctl -f | grep vpn
tail -f /var/log/syslog | grep vpn



journalctl -k --grep="IN=.*OUT=.*"


##-=======================================-##
##   [+] Find failures with journalctl
##-=======================================-##
journalctl --no-pager --since today --grep 'fail|error|fatal' --output json | jq '._EXE' | sort | uniq -c | sort --numeric --reverse --key 1





systemctl cat --all openvpn.service
systemctl cat --all openvpn-client@.service
systemctl edit --all openvpn-client@.service
resolvconf-pull-resolved.path
resolvconf-pull-resolved.service
resolvconf.service
systemd-networkd.service



systemctl show --all qbittorrent.service
systemctl edit --all --force qbittorrent.service

networkctl status

systemd-analyze security sshd.service




kill -HUP `pidof rsyslogd`
kill -HUP `cat /var/run/rsyslogd.pid`
service rsyslog start
/etc/init.d/rsyslog reload


journalctl /usr/bin/dbus-daemon

journalctl /dev/sda

journalctl -k -b -1

journalctl _SYSTEMD_UNIT=avahi-daemon.service _PID=28097 + _SYSTEMD_UNIT=dbus.service
journalctl _SYSTEMD_UNIT=avahi-daemon.service _SYSTEMD_UNIT=dbus.service
journalctl _SYSTEMD_UNIT=avahi-daemon.service _PID=28097
journalctl _SYSTEMD_UNIT=avahi-daemon.service

journalctl _SYSTEMD_UNIT=$Service
journalctl -u $Service
journalctl _SYSTEMD_UNIT=$Service



journalctl -p warning
+9

systemctl log-level debug
systemd-analyze security



SYSTEMD_LOG_LEVEL=debug
/lib/systemd/systemd-networkd

[Service]
Environment=SYSTEMD_LOG_LEVEL=debug



##-==============================================================-##
##  [+] Retrieve dropped connections from firewalld journaling
##-==============================================================-##
journalctl -b | grep -o "PROTO=.*" | sed -r 's/(PROTO|SPT|DPT|LEN)=//g' | awk '{print $1, $3}' | sort | uniq -c


sed -i 's/^#Storage=.*/Storage=persistent/' "$JOURNALDCONF"
sed -i 's/^#ForwardToSyslog=.*/ForwardToSyslog=yes/' "$JOURNALDCONF"
sed -i 's/^#Compress=.*/Compress=yes/' "$JOURNALDCONF"
sed -i "s/^\$FileCreateMode.*/\$FileCreateMode 0600/g" "$RSYSLOGCONF"

systemctl status systemd-journald --no-pager


Systemd/system.conf
Systemd/user.conf

  sed -i 's/^#DumpCore=.*/DumpCore=no/' "$SYSTEMCONF"
  sed -i 's/^#CrashShell=.*/CrashShell=no/' "$SYSTEMCONF"
  sed -i 's/^#DefaultLimitCORE=.*/DefaultLimitCORE=0/' "$SYSTEMCONF"
  sed -i 's/^#DefaultLimitNOFILE=.*/DefaultLimitNOFILE=1024/' "$SYSTEMCONF"
  sed -i 's/^#DefaultLimitNPROC=.*/DefaultLimitNPROC=1024/' "$SYSTEMCONF"

  sed -i 's/^#DefaultLimitCORE=.*/DefaultLimitCORE=0/' "$USERCONF"
  sed -i 's/^#DefaultLimitNOFILE=.*/DefaultLimitNOFILE=1024/' "$USERCONF"







systemctl | grep '$Service' ---> locate the service unit name
journalctl -S <time stamp> -u $Service
journalctl --all --output cat -u $Service
journalctl -f                           ## As tail




## Clear journalctl
journalctl --flush --rotate
journalctl --vacuum-time=1s



ournalctl -u $Service -n 1 -o verbose



journalctl -u $Service MESSAGE_ID=ae8f7b866b0347b9af31fe1c80b127c0


systemd-run -p IPAccounting=yes --wait wget $URL


systemd-run -p IPAddressDeny=any -p IPAddressAllow=$IP -p IPAddressAllow=127.0.0.0/8 -t /bin/sh

systemctl set-property system.slice IPAddressDeny=any IPAddressAllow=localhost
systemctl set-property apache.service IPAddressAllow=10.0.0.0/8


systemd-resolve


systemd-run --pipe -p IPAddressDeny=any -p IPAddressAllow=$IP -p IPAddressAllow=$IP -p DynamicUser=yes curl $URL | lp


systemd-run --pipe -p IPAddressDeny=any -p IPAddressAllow=$IP -p IPAddressAllow=$IP -p DynamicUser=yes curl $URL | lp




systemd-nspawn -L system_u:object_r:svirt_sandbox_file_t:s0:c0,c1 -Z system_u:system_r:svirt_lxc_net_t:s0:c0,c1 -D /srv/container /bin/sh




systemd-run --pty --property=DynamicUser=yes --property=StateDirectory=wuff /bin/sh

systemd-run --pty --property=DynamicUser=yes --property=StateDirectory=wuff /bin/sh


systemd-nspawn -bi $File.raw


qemu-kvm -m 512 -smp 2 -bios /usr/share/edk2/ovmf/$File.fd -drive format=raw,file=$File.raw






systemctl --property=
systemctl set-property




systemctl --overlay=
systemctl --overlay-ro=


systemctl --capability=

List one or more additional capabilities to grant the container.
Takes a comma-separated list of capability names,
see capabilities(7) for more information. Note that the following capabilities
will be granted in any way:

CAP_CHOWN, CAP_DAC_OVERRIDE, CAP_DAC_READ_SEARCH, CAP_FOWNER, CAP_FSETID, CAP_IPC_OWNER, CAP_KILL, CAP_LEASE, CAP_LINUX_IMMUTABLE, CAP_NET_BIND_SERVICE, CAP_NET_BROADCAST, CAP_NET_RAW, CAP_SETGID, CAP_SETFCAP, CAP_SETPCAP, CAP_SETUID, CAP_SYS_ADMIN, CAP_SYS_CHROOT, CAP_SYS_NICE, CAP_SYS_PTRACE, CAP_SYS_TTY_CONFIG, CAP_SYS_RESOURCE, CAP_SYS_BOOT, CAP_AUDIT_WRITE, CAP_AUDIT_CONTROL
Also
CAP_NET_ADMIN is retained if

systemctl --private-network
 is specified. If the special value "all" is passed, all capabilities are retained.

systemctl --drop-capability=



systemctl --network-veth
or
systemctl --network-bridge=

systemctl --network-ipvlan=


systemctl --network-ipvlan=
systemctl --private-network
systemctl --private-users=





systemd-debug-generator
 is a generator that reads the kernel command line and understands three options:

If the
systemd.mask=
option is specified and followed by a unit name,
this unit is masked for the runtime,
similar to the effect of systemctl(1)'s mask command.
This is useful to boot with certain units removed from the initial boot transaction
for debugging system startup. May be specified more than once.

If the
systemd.wants=
option is specified and followed by a unit name,
a start job for this unit is added to the initial transaction.
This is useful to start one or more additional units at boot.
May be specified more than once.

If the
systemd.debug-shell
option is specified, the debug shell service "debug-shell.service"



dir=$(mktemp -d)
SYSTEMD_LOG_LEVEL=debug /usr/lib/systemd/system-generators/systemd-fstab-generator \
        "$dir" "$dir" "$dir"
find $dir





--dump-configuration-items
--show-status=




