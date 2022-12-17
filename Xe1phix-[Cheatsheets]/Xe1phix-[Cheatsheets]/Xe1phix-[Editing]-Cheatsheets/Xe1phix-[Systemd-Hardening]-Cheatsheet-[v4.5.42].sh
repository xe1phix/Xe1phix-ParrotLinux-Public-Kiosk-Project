#!/bin/sh

systemctl show --property "Wants" multi-user.target 

systemctl show --property "Wants" multi-user.target |
> fmt -10 | sed 's/Wants=//g' | sort

systemctl list-unit-files --state=masked
systemctl list-unit-files


systemctl list-units | grep .service
systemctl list-units | grep .target
systemctl list-unit-files --type=service
systemctl list-unit-files --type=target
systemctl show --property "Requires" multi-user.target
ls -l /lib/systemd/system/runlevel*.target
ls -l /etc/systemd/system/default.target
initctl list | grep start/running
systemctl show --property "WantedBy" getty.target
systemctl list-unit-files --type=service | grep -v disabled

systemctl -a | grep -E '.*\.service.*loaded.*active.*running' |  grep -v '@' | awk '{print $1}'


systemctl log-level debug
systemd-analyze security 



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


systemd-analyze security httpd.service
/etc/systemd/system/httpd.service.d/security.conf
[Service]
ProtectSystem=full
ProtectSystem=strict
ProtectHome=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM
NoNewPrivileges=yes
PrivateTmp=yes

systemd-analyze security sshd.service

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




AmbientCapabilities=
CapabilityBoundingSet=
Delegate=
DeviceAllow=
IPAddressDeny=
KeyringMode=
LockPersonality=
MemoryDenyWriteExecute=
NoNewPrivileges=
NotifyAccess=
PrivateDevices=
PrivateMounts=
PrivateNetwork=
PrivateTmp=
PrivateUsers=
ProtectControlGroups=
ProtectHome=
ProtectHostname=
ProtectKernelLogs=
ProtectKernelModules=
ProtectKernelTunables=
ProtectSystem=
RestrictAddressFamilies=
RestrictNamespaces=
RestrictRealtime=
RestrictSUIDSGID=
RootDirectory=/RootImage=
SystemCallArchitectures=
SystemCallFilter=
UMask=
User=/DynamicUser=

