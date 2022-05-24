**TL;DR:** These tables list equivalent options rather than equal options. Read
their docs!  
**NOTE:** Keep in mind that systemd is made to run and sandbox system-services
while firejail has its focus on desktop programs. Therefore some options differ
in their behavior, for example does firejail's `private-tmp` always bind-mount
`/tmp/.X11-unix`, while systemd's `PrivateTmp=yes` does not. Always read the
documentation of the option you use!

 - [`man 5 systemd.exec`]
 - [`man 5 systemd.resource-control`]
 - [`man 5 systemd.service`]
 - [`man 5 systemd.unit`]
 - [`man 1 firejail`]
 - [`man 5 firejail-profile`]

[`man 5 systemd.exec`]: https://www.freedesktop.org/software/systemd/man/systemd.exec.html
[`man 5 systemd.resource-control`]: https://www.freedesktop.org/software/systemd/man/systemd.resource-control.html
[`man 5 systemd.service`]: https://www.freedesktop.org/software/systemd/man/systemd.service.html
[`man 5 systemd.unit`]: https://www.freedesktop.org/software/systemd/man/systemd.unit.html
[`man 1 firejail`]: https://firejail.wordpress.com/features-3/man-firejail/
[`man 5 firejail-profile`]: https://firejail.wordpress.com/features-3/man-firejail-profile/

## Filesystem

| firejail | systemd |
| -------- | ------- |
| always | `PrivateMounts=yes` |
| `blacklist /home`<br>`blacklist /root`<br>`blacklist /run/user` | `ProtectHome=yes` |
| `blacklist /boot` | `InaccessiblePaths=/boot` |
| `chroot /foobaz` | `RootDirectory=/foobaz` |
| `disable-mnt` | `InaccessiblePaths=/mnt`<br>`InaccessiblePaths=/media`<br>`InaccessiblePaths=/run/mount`(breaks systemd)<br>`InaccessiblePaths=/run/media` |
| `mkdir` | Not Implemented<br>You can use `RuntimeDirectory=`, `StateDirectory=`, `CacheDirectory=`, `LogsDirectory=`, `ConfigurationDirectory=`.<br>You could write a `mkdir@.service` and use `After=mkdir\x2fetc\x2fdnsmasq.service`/`After=mkdir@etc-dnsmasq.service`. |
| `mkfile` | Not Implemented |
| `noexec /tmp` | `NoExecPaths=/tmp` |
| Not Implemented | `ExecPaths=/tmp/bin` |
| `private-bin bash,getenforce,python3` | `TemporaryFileSystem=/bin`<br>`TemporaryFileSystem=/usr/bin`<br>`TemporaryFileSystem=/sbin`<br>`TemporaryFileSystem=/usr/sbin`<br>`BindReadOnlyPaths=/bin/bash`<br>`BindReadOnlyPaths=/usr/bin/python3`<br>`BindReadOnlyPaths=/usr/sbin/getenforce` |
| `private-cwd` | `WorkingDirectory=~` |
| `private-cwd /root` | `WorkingDirectory=/root` |
| `private-etc ca-certificates,crypto-policies,nsswitch.conf,pki,resolv.conf,ssl` |  `TemporaryFileSystem=/etc`<br>`BindReadOnlyPaths=-/etc/ca-certificates`<br>`BindReadOnlyPaths=-/etc/crypto-policies`<br>`BindReadOnlyPaths=-/etc/nsswitch.conf`<br>`BindReadOnlyPaths=-/etc/pki`<br>`BindReadOnlyPaths=-/etc/resolv.conf`<br>`BindReadOnlyPaths=-/etc/ssl` |
| `private-lib` | Not Implemented |
| `private-opt vivaldi` |  `TemporaryFileSystem=/opt`<br>`BindReadOnlyPaths=/opt/vivaldi` |
| `private-srv www` | `TemporaryFileSystem=/srv`<br>`BindReadOnlyPaths=-/srv/www` |
| `private-tmp` | `PrivateTmp=yes` |
| `read-only /usr` | `ProtectSystem=yes` |
| `read-only /usr`<br>`read-only /etc` | `ProtectSystem=full` |
| `read-only /` | `ProtectSystem=strict` |
| `read-only /home`<br>`read-only /root`<br>`read-only /run/user` | `ProtectHome=read-only` |
| `read-only /sys/fs/cgroup` | `ProtectControlGroups=yes` |
| `read-only /proc/acpi`<br>`read-only /proc/fs`<br>`read-only /proc/irq`<br>`read-only /proc/latency_stats`<br>`read-only /proc/sys`<br>`read-only /proc/sysrq-trigger`<br>`read-only /proc/timer_stats`<br>`read-only /sys` | `ProtectKernelTunables=yes` |
| `read-only /foo` | `ReadOnlyPaths=/foo` |
| `read-write /foo/bar` | `ReadWritePaths=/foo/bar` |
| `tmpfs /home`<br>`tmpfs /root`<br>`tmpfs /run/user` | `ProtectHome=tmpfs` |
| `tmpfs /xyzzy` | `TemporaryFileSystem=/xyzzy` |
| `tracelog` | Not Implemented |
| `whitelist /mnt/backup` | `TemporaryFileSystem=/mnt`<br>`BindPaths=/mnt/backup` |
| fixme | `BindPaths=` `BindReadOnlyPaths=` |
| always (via pid-namespace) | `ProtectProc=invisible` |
| Not Implemented | `ProtectProc=noaccess` |
| fixme | `ProcSubset=pid` |
| Not Implemented | `RestrictSUIDSGID=yes` |

## Devices

| firejail | systemd |
| -------- | ------- |
| `private-dev` | `PrivateDevices=yes` |
| `no3d` | `InaccessiblePaths=/dev/dri` |
| `nodvd` | `InaccessiblePaths=/dev/sr*` |
| `noinput` | `InaccessiblePaths=/dev/input` |
| `nosound` | `InaccessiblePaths=/dev/snd` |
| `notv` | `InaccessiblePaths=/dev/dvb` |
| `nou2f` | `InaccessiblePaths=/dev/hidraw*` |
| `novideo` | `InaccessiblePaths=/dev/video*` |

## Seccomp, mdwe, Capabilities and NNP

| firejail | systemd |
| -------- | ------- |
| `caps.drop all` |  `CapabilityBoundingSet=` |
| `caps.drop sys_admin,net_admin` | `CapabilityBoundingSet=~CAP_SYS_ADMIN CAP_NET_ADMIN` |
| `caps.keep net_bind_service` | `CapabilityBoundingSet=CAP_NET_BIND_SERVICE` |
| `memory-deny-write-execute` | `MemoryDenyWriteExecute=yes`<br>`SystemCallFilter=~memfd_create` |
| `nonewprivs` | `NoNewPrivileges=yes` |
| `seccomp` | `SystemCallFilter=<omitted because it is to long, look at syscalls.txt>` |
| `seccomp.block-secondary` | `SystemCallArchitectures=native` |
| `seccomp.drop @debug` | `SystemCallFilter=~@debug` |
| `seccomp.keep @file-system,mount` | `SystemCallFilter=@file-system mount` |
| [#3106](https://github.com/netblue30/firejail/issues/3106) | `SystemCallFilter=@system-service` |
| `seccomp-error-action EPERM` (default) | `SystemCallErrorNumber=EPERM` |
| `seccomp-error-action kill` | `SystemCallErrorNumber=` (default) |
| `caps.drop sys_time,wake_alarm`<br>`seccomp.drop @clock`<br>`read-only /dev/rtc*` | `ProtectClock=yes` |
| `caps.drop syslog`<br>`seccomp.drop syslog`<br>`blacklist /dev/kmsg`<br>`blacklist /proc/kmsg` | `ProtectKernelLogs=yes` |
| `caps.drop sys_module`<br>`blacklist /usr/lib/modules`<br>`seccomp.drop @module` | `ProtectKernelModules=yes`
| fixme | `LockPersonality=yes` |

## Networking

| firejail | systemd |
| -------- | ------- |
| `dns 9.9.9.9` | Not Implemented |
| `hosts-file` | Not Implemented |
| `hostname myhost` | Not Implemented |
| `net none` | `PrivateNetwork=yes` |
| `net eth0` | Not Implemented |
| `netfilter /etc/firejail/myfilter.net` | Not Implemented |
| Not Implemented | `IPIngressFilterPath=` `IPEgressFilterPath=` |
| `net eth0`<br>`netfilter ipdenyallow.net` | `IPAddressDeny=` `IPAddressAllow=` |
| `netns NAME` | `NetworkNamespacePath=/var/run/netns/NAME` |
| `protocol unix,inet,inet6` | `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6` |
| fixme | `ProtectHostname=yes` |

## D-Bus

D-Bus filtering is not implemented for systemd and blocking the system-bus socket breaks systemd.

## Resource Limits

| firejail | systemd |
| -------- | ------- |
| `cpu 0,1` | `CPUAffinity=0,1` |
| `nice 2` | `Nice=2` |
| `rlimit*` | `Limit*`
| `timeout` | `TimeoutSec=` |
| fixme | `RestrictRealtime=yes` |
| Not Implemented | `CoredumpFilter=` |
| Not Implemented | `KeyringMode=` |
| Not Implemented | `OOMScoreAdjust=` |
| Not Implemented | `UMask=0077` |

## User/Group

| firejail | systemd |
| -------- | ------- |
| `nogroups` | Not Implemented |
| `noroot` | `PrivateUsers=yes` |
| Not Implemented | `User=user`<br>`Group=group`<br>`SupplementaryGroups=supp_group1 supp_group2` |
| Not Implemented | `DynamicUser=yes` |
| Not Implemented | `RemoveIPC=yes` |

## Environment

| firejail | systemd |
| -------- | ------- |
| `env FOO=bar` | `Environment=FOO=bar` |
| `rmenv` | `UnsetEnvironment=EDITOR` |

## Uncategorized

| firejail | systemd |
| -------- | ------- |
| `include some-common.inc` | Not Implemented<br>You can use symlinks / hardlinks in `/etc/systemd/system/UNIT.d`. |
| `ipc-namespace` | `PrivateIPC=yes` |
| `join` | `JoinsNamespaceOf=` |
| `machine-id` | Not Implemented<br>Maybe you can use `ExecStartPre=!/bin/sh -c "dbus-uuidgen > /etc/machine-id"`, however until now nobody had tested this. |
| Not Implemented | `RestrictNamespaces=` |
