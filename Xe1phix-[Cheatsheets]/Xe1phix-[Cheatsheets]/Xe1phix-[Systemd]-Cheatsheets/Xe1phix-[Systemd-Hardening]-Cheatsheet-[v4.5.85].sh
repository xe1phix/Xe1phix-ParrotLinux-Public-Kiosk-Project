#!/bin/sh





systemctl show --property "Wants" multi-user.target

systemctl show --property "Wants" multi-user.target | fmt -10 | sed 's/Wants=//g' | sort

systemctl list-unit-files --state=masked
systemctl list-unit-files


systemctl list-units | grep .service
systemctl list-units | grep .target
systemctl list-unit-files --type=service
systemctl list-unit-files --type=target


# Display all the underlying parameters of a Unit
$ systemctl show httpd.service



systemctl show --property "Requires" multi-user.target
ls -l /lib/systemd/system/runlevel*.target
ls -l /etc/systemd/system/default.target
initctl list | grep start/running
systemctl show --property "WantedBy" getty.target
systemctl list-unit-files --type=service | grep -v disabled

systemctl -a | grep -E '.*\.service.*loaded.*active.*running' |  grep -v '@' | awk '{print $1}'




systemd-analyze log-level
systemd-analyze log-target


NotifyAccess=all
LogsDirectoryMode=
LogLevelMax=debug
LogExtraFields=


systemctl log-level debug


systemd-analyze security


ExecStop=/bin/kill -9 $MAINPID



SYSTEMD_LOG_LEVEL=debug /lib/systemd/systemd-networkd

[Service]
Environment=SYSTEMD_LOG_LEVEL=debug



systemctl --user set-environment
systemctl --user show-environment



systemctl edit --full
systemctl edit sshd.service
systemctl cat sshd.service
/lib/systemd/system/ssh.service

/etc/systemd/system/unit.d/
/usr/lib/systemd/system/
/usr/lib/systemd/system/systemd-resolved.service.d/



# View the start time of each service
systemd-analyze blame

# Show waterfall-like startup process flow
systemd-analyze critical-chain

# Display the startup flow of the specified service
systemd-analyze critical-chain atd.service


systemd-analyze security httpd.service
/etc/systemd/system/httpd.service.d/security.conf




[Service]


##-===================-##
##   [+]
##-===================-##
ProtectSystem=full
ProtectSystem=strict
ProtectHome=yes

##-===================-##
##   [+]
##-===================-##
PrivateDevices=yes

##-===================-##
##   [+]
##-===================-##
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes


##-===================-##
##   [+]
##-===================-##
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM

##-===================-##
##   [+]
##-===================-##
NoNewPrivileges=yes


##-===================-##
##   [+] PrivateTmp
##-===================-##
## Creates a file system namespace under
## /tmp/systemd-private-*-[unit name]-*/tmp
## rather than a shared /tmp or /var/tmp
PrivateTmp=yes




systemd-analyze security $Service.service
systemd-analyze security sshd.service
systemd-analyze security
systemd-analyze security
systemd-analyze security




systemd-analyze cat-config modprobe.d


cat > /etc/systemd/network/04-eth0.network
cat > /etc/systemd/network/08-wlan0.network
systemctl edit wpa_supplicant@wlan0.service


systemctl cat --all openvpn.service
systemctl cat --all openvpn-client@.service
systemctl edit --all openvpn-client@.service
resolvconf-pull-resolved.path
resolvconf-pull-resolved.service
resolvconf.service
systemd-networkd.service


systemd-udevd.service
tmp.mount
i2p.service
ifupdown-pre.service




systemctl show --all qbittorrent.service
systemctl edit --all --force qbittorrent.service

networkctl status



systemd.syntax
systemd.netdev

systemd.network
systemd-networkd
systemd-networkd.service

/etc/systemd/networkd.conf
/etc/systemd/networkd.conf.d/*.conf
/lib/systemd/networkd.conf.d/*.conf


pstree -Aacp
# ps -aef --forest
lsof /usr/lib/systemd/systemd
fuser /usr/lib/systemd/systemd



systemd-resolve --interface <NombreInterfaz> --set-dns






systemd-cgls


systemd-cgtop
top
sar -P ALL 2
sar -P ALL 5        ## Check CPU:

systemctl status cgmanager.service




/etc/cgconfig.conf
/etc/cgconfig.d/

cgconfigparser --load=/etc/cgconfig.conf

--tperm=
--fperm=
--dperm=



cgcreate -g *:student devices:teacher
              create control group student in  all  mounted  hierarchies  and
              create control group teacher in hierarchy containing controller
              devices.


create a new memory cgroup called 'compute', you can use:

dbus-send --print-reply --address=unix:path=/sys/fs/cgroup/cgman‐
       ager/sock --type=method_call /org/linuxcontainers/cgmanager org.linux‐
       containers.cgmanager0_0.Create   string:'memory'   string:"compute"  >
       /dev/null 2>&1


set a limit of 100000

dbus-send --print-reply --address=unix:path=/sys/fs/cgroup/cgman‐
       ager/sock --type=method_call /org/linuxcontainers/cgmanager org.linux‐
       containers.cgmanager0_0.SetValue   string:'memory'    string:"compute"
       string:memory.limit_in_bytes int32:100000 > /dev/null 2>&1



/proc/[pid]/cgroup

cat /sys/kernel/cgroup/features





systemctl set-property httpd.service CPUQuota=5%
systemctl set-property httpd.service CPUShares=500
systemctl set-property httpd.service CPUAccounting=yes

ls -l /etc/systemd/system/httpd.service.d/*
-rw-r--r--. 1 root root 22 Mar 18 11:48 /etc/systemd/system/httpd.service.d/50-CPUQuota.conf
-rw-r--r--. 1 root root 24 Mar 18 11:52 /etc/systemd/system/httpd.service.d/50-CPUShares.conf
-rw-r--r--. 1 root root 28 Mar 18 11:53 /etc/systemd/system/httpd.service.d/50-CPUAccounting.conf

systemctl set-property stress1 CPUQuota=33%



/usr/lib/systemd/system/systemd-hostnamed.service



systemctl edit --force --full httpd.service


cat /etc/systemd/system/httpd.service.d/security.conf
cp -v /etc/systemd/system/httpd.service.d/security.conf /etc/systemd/system/apache2.service.d/


systemctl set-property apache2.service NoNewPrivileges=true



CapabilityBoundingSet=CAP_SYS_ADMIN
WatchdogSec=3min
PrivateTmp=yes
PrivateDevices=yes
PrivateNetwork=yes
ProtectSystem=yes
ProtectHome=yes


SELinuxContext=
PAMName=
PAMName=systemd-user
SmackLabel=
AppArmorProfile=

KillSignal=SIGKILL

##-===================-##
##   [+]
##-===================-##
AmbientCapabilities=
AmbientCapabilities=CAP_CHOWN CAP_NET_RAW
CapabilityBoundingSet=~CAP_SYS_ADMIN CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=

Delegate=

##-===================-##
##   [+]
##-===================-##
DeviceAllow=

##-===================-##
##   [+]
##-===================-##
IPAddressDeny=

##-===================-##
##   [+]
##-===================-##
KeyringMode=

##-===================-##
##   [+]
##-===================-##
LockPersonality=

##-===================-##
##   [+]
##-===================-##
MemoryDenyWriteExecute=
NoNewPrivileges=true

##-===================-##
##   [+]
##-===================-##
NotifyAccess=

PrivateDevices=
PrivateMounts=
PrivateNetwork=
PrivateTmp=
PrivateUsers=
RestrictNamespaces=uts ipc pid user cgroup net


ProtectControlGroups=yes
ProtectHome=read-only
ProtectHostname=

ProtectKernelLogs=
ProtectKernelModules=
ProtectKernelTunables=

ProtectSystem=
ProtectSystem=full
ProtectSystem=strict


RestrictAddressFamilies=
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
RestrictAddressFamilies=AF_UNIX AF_INET
RestrictAddressFamilies=~AF_INET6

RestrictRealtime=
RestrictSUIDSGID=

##-===================-##
##   [+]
##-===================-##
RootDirectory=/$Dir/
ReadOnlyPaths=/foo
ReadWritePaths=/foo/bar
ProtectHome=tmpfs
TemporaryFileSystem=

BindPaths=/mnt/backup
BindPaths=
BindReadOnlyPaths=

RuntimeDirectoryMode=0750



DirectoryMode 0755
UMask 0022
WorkingDirectory /
RootDirectory /
NonBlocking no
PrivateTmp no
ControlGroupModify no
ControlGroupPersistent yes
PrivateNetwork no



DirectoryMode=0755
UMask=0022
WorkingDirectory=/
RootDirectory=/
NonBlocking=no
PrivateTmp=no
ControlGroupModify=no
ControlGroupPersistent=yes
PrivateNetwork=no



##-===================-##
##   [+]
##-===================-##
SystemCallArchitectures=
SystemCallFilter=


capsh --print | sed -re "s/[^ ]+?\-[epi]+//g" -e '/IAB/d' | grep cap_sys_module
grep "CapAmb:" /proc/self/status


systemd-analyze security modprobe@drm.service >> ~/Download/Systemd-Security-Reports/Xe1phix-[modprobe@drm.service]-Security-Report.txt

grep -i PermitUserEnvironment /etc/ssh/sshd_config

PermitUserEnvironment no


##-===================-##
##   [+]
##-===================-##
UMask=
User=$User
DynamicUser=yes

| =InaccessibleDirectories= | directories that are inaccessible            |
| =ReadonlyDirectories=     | directories that are read-only               |
| =AllowedDevices=          | private =/dev= containing only these devices |



