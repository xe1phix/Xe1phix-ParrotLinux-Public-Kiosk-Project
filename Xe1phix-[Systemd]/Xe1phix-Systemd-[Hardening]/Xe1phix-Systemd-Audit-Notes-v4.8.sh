



| Name    | Description |
|---------|-------------|
| ExecStartPre | Commands that will run before `ExecStart`. |
| ExecStart | Main commands to run for this unit. |
| ExecStartPost | Commands that will run after all `ExecStart` commands have completed. |
| ExecReload | Commands that will run when this unit is reloaded via `systemctl reload foo.service` |
| ExecStop | Commands that will run when this unit is considered failed or if it is stopped via `systemctl stop foo.service` |
| ExecStopPost | Commands that will run after `ExecStop` has completed. |
| RestartSec | The amount of time to sleep before restarting a service. Useful to prevent your failed service from attempting to restart itself every 100ms. |











sys-devices-virtual-misc-rfkill.device
sys-devices-virtual-misc-rfkill.device
/lib/systemd/system/systemd-rfkill.service




Names=systemd-rfkill.service




systemd.restore_state=
"0", does not restore the rfkill settings on boot.


vlan-interfaces



systemd-cryptsetup-generator
systemd.wants=
systemd.mask=
modules_load=
modules-load.d
kernel-command-line

systemd.journald.forward_to_syslog=
systemd.journald.forward_to_kmsg=
systemd.journald.forward_to_console=

sd-journal
sd_journal_print
journald.conf


systemd.setenv=
systemctl set-environment
PassEnvironment=


SyslogLevel=debug
StandardOutput=journal
SyslogLevelPrefix=
sd-daemon
SyslogFacility=
SyslogIdentifier=
LogExtraFields=
systemd.journal-fields
LogLevelMax=
MaxLevelStore=
journald.conf


PRIORITY=debug
SYSLOG_FACILITY=

systemd-nspawn

systemd.resource-control


sd_booted

personality

systemd-tmpfiles-setup.service

/etc/systemd/dnssd/http.dnssd
/usr/lib/systemd/dnssd,

/run/systemd/dnssd

/etc/security/pam_env.conf



pam_env.so [debug] [conffile=conf-file] [envfile=env-file] [readenv=0|1] [user_envfile=env-file] [user_readenv=0|1]


pam.d

grub-set-default
grub-reboot




       ~/.config/environment.d/*.conf

       /etc/environment.d/*.conf

       /run/environment.d/*.conf

       /usr/lib/environment.d/*.conf



AppArmorProfile=

pam_namespace


/usr/share/doc/libgksu2-0/README.Debian

NoNewPrivileges=yes
PrivateNetwork=yes
ProtectHome=yes
ProtectSystem=yes
PrivateDevices=yes
PrivateTmp=yes
User=
CapabilityBoundingSet=cap_chown cap_dac_override cap_dac_read_search cap_fowner cap_fsetid cap_kill cap_setgid cap_setuid cap_se
IPAccounting=no
UMask=0022
DevicePolicy=
systemctl set-property 
ProtectHome=read-only   tmpfs
ProtectSystem=strict
NotifyAccess=all
SecureBits=keep-caps, keep-caps-locked, no-setuid-fixup, no-setuid-fixup-locked, noroot, and noroot-locked
AppArmorProfile=
SELinuxContext=
TemporaryFileSystem=

ProtectSystem=strict    full    
SystemCallFilter=~_sysctl add_key adjtimex afs_syscall bdflush break chroot clock_adjtime clock_settime create_module delete_mod
MemoryDenyWriteExecute=yes
RestrictRealtime=yes

RestrictNamespaces=no

PAMName=systemd-user
PrivateTmp=no
RestrictNamespaces=no
ReadOnlyPaths=
ProtectControlGroups=
LogsDirectoryMode=
LogLevelMax=debug
LogExtraFields=
StandardError=journal

systemd.confirm_spawn=

TemporaryFileSystem=/var:ro
BindReadOnlyPaths=/var/lib/systemd

RestrictAddressFamilies=AF_UNIX AF_INET
RestrictAddressFamilies=~AF_INET6

systemd.journal-fields
systemd-system.conf
systemd --user
sysusers.d

systemd --user
dbus-daemon --session
dbus-update-activation-environment --systemd --all

systemd-nspawn
pkg-config
networkctl
busctl
bootctl
machinectl



pam_systemd








systemd-analyze syscall-filter

systemd-analyze log-level
systemd-analyze log-target
systemd-analyze verify
systemd-analyze service-watchdogs



systemd.network
systemd-networkd.service
systemd-system.conf
systemd.service
systemd.exec
systemd.directives


/etc/systemd/resolved.conf,
/run/systemd/resolve/resolv.conf
/run/systemd/resolve/stub-resolv.conf



systemd-journald.service
systemd-logind.service
systemd-journald-audit.socket
udisks2.service



sys-kernel-config.mount
syslog.service
syslog-ng.service

rsyslog.service
resolvconf.service
systemd-networkd.service
networking.service
NetworkManager-dispatcher.service
network-manager.service
NetworkManager.service
NetworkManager-wait-online.service
network-online.target
network-pre.target
network.target
wpa_supplicant.service

zfs-fuse.service
zed.service
tmp.mount
user@1000.service







[Network]
LinkLocalAddressing=no
IPv6AcceptRA=no


[Network]
DHCP=yes


[Match]
Name=enp2s0

[Network]
Address=192.168.0.15/24
Gateway=192.168.0.1






/etc/systemd/system/etcd2.service.d/30-certificates.conf


[Service]
# Client Env Vars
Environment=ETCD_CA_FILE=/path/to/CA.pem
Environment=ETCD_CERT_FILE=/path/to/server.crt
Environment=ETCD_KEY_FILE=/path/to/server.key
# Peer Env Vars
Environment=ETCD_PEER_CA_FILE=/path/to/CA.pem
Environment=ETCD_PEER_CERT_FILE=/path/to/peers.crt
Environment=ETCD_PEER_KEY_FILE=/path/to/peers.key




/etc/systemd/system.conf.d/10-default-env.conf





create systemd unit file `/etc/systemd/system/device-attach.service`:

```
[Service]
Type=oneshot
ExecStart=/usr/bin/echo 'device has been attached'



start `udevadm monitor --environment` to monitor kernel events.



virsh attach-disk $Name /mnt/$Mnt $sdc


ACTION=="add", SUBSYSTEM=="block", TAG+="systemd", ENV{SYSTEMD_WANTS}="device-attach.service"

/etc/udev/rules.d/01-block.rules


ACTION=="add", SUBSYSTEM=="block", TAG+="systemd", ENV{SYSTEMD_WANTS}="device-attach.service"





systemctl list-units | grep .service





ExecStart=/usr/bin/docker run --name apache1 -p 8081:80 coreos/apache /usr/sbin/apache2ctl -D FOREGROUND


ExecStart=/usr/bin/docker run --name apache1 -p 8081:80 coreos/apache /usr/sbin/apache2ctl -D FOREGROUND




## Unit specifiers

In our last example we had to hardcode our IP address when we announced our container in etcd. That's not scalable and systemd has a few variables built in to help us out. Here's a few of the most useful:

| Variable | Meaning | Description |
|----------|---------|-------------|
| `%n` | Full unit name | Useful if the name of your unit is unique enough to be used as an argument on a command. |
| `%m` | Machine ID | Useful for namespacing etcd keys by machine. Example: `/machines/%m/units` |
| `%b` | BootID | Similar to the machine ID, but this value is random and changes on each boot |
| `%H` | Hostname | Allows you to run the same unit file across many machines. Useful for service discovery. Example: `/domains/example.com/%H:8081` |




















Accept
AccuracySec
After
Alias
AllowIsolate
Also
AmbientCapabilities
AppArmorProfile
Architecture
AssertACPower
AssertArchitecture
AssertCapability
AssertControlGroupController
AssertDirectoryNotEmpty
AssertFileIsExecutable
AssertFileNotEmpty
AssertFirstBoot
AssertGroup
AssertHost
AssertKernelCommandLine
AssertKernelVersion
AssertNeedsUpdate
AssertNull
AssertPathExists
AssertPathExistsGlob
AssertPathIsDirectory
AssertPathIsMountPoint
AssertPathIsReadWrite
AssertPathIsSymbolicLink
AssertSecurity
AssertUser
AssertVirtualization
Backlog
Before
BindIPv6Only
BindPaths
BindReadOnlyPaths
BindsTo
BindTo
BindToDevice
BlockIOAccounting
BlockIODeviceWeight
BlockIOReadBandwidth
BlockIOWeight
BlockIOWriteBandwidth
Broadcast
BusName
BusPolicy
CacheDirectory
CacheDirectoryMode
Capabilities
CapabilityBoundingSet
CollectMode
ConditionACPower
ConditionArchitecture
ConditionCapability
ConditionControlGroupController
ConditionDirectoryNotEmpty
ConditionFileIsExecutable
ConditionFileNotEmpty
ConditionFirstBoot
ConditionGroup
ConditionHost
ConditionKernelCommandLine
ConditionKernelVersion
ConditionNeedsUpdate
ConditionNull
ConditionPathExists
ConditionPathExistsGlob
ConditionPathIsDirectory
ConditionPathIsMountPoint
ConditionPathIsReadWrite
ConditionPathIsSymbolicLink
ConditionSecurity
ConditionUser
ConditionVirtualization
ConfigurationDirectory
ConfigurationDirectoryMode
ConfirmSpawn
Conflicts
CPUAccounting
CPUAffinity
CPUQuota
CPUSchedulingPolicy
CPUSchedulingPriority
CPUSchedulingResetOnFork
CPUShares
CPUWeight
DefaultBlockIOAccounting
DefaultCPUAccounting
DefaultDependencies
DefaultInstance
DefaultLimitAS
DefaultLimitASSoft
DefaultLimitCORE
DefaultLimitCORESoft
DefaultLimitCPU
DefaultLimitCPUSoft
DefaultLimitDATA
DefaultLimitDATASoft
DefaultLimitFSIZE
DefaultLimitFSIZESoft
DefaultLimitLOCKS
DefaultLimitLOCKSSoft
DefaultLimitMEMLOCK
DefaultLimitMEMLOCKSoft
DefaultLimitMSGQUEUE
DefaultLimitMSGQUEUESoft
DefaultLimitNICE
DefaultLimitNICESoft
DefaultLimitNOFILE
DefaultLimitNOFILESoft
DefaultLimitNPROC
DefaultLimitNPROCSoft
DefaultLimitRSS
DefaultLimitRSSSoft
DefaultLimitRTPRIO
DefaultLimitRTPRIOSoft
DefaultLimitRTTIME
DefaultLimitRTTIMESoft
DefaultLimitSIGPENDING
DefaultLimitSIGPENDINGSoft
DefaultLimitSTACK
DefaultLimitSTACKSoft
DefaultMemoryAccounting
DefaultRestartUSec
DefaultStandardError
DefaultStandardOutput
DefaultStartLimitBurst
DefaultStartLimitIntervalUSec
DefaultTasksAccounting
DefaultTasksMax
DefaultTimeoutStartUSec
DefaultTimeoutStopUSec
DefaultTimerAccuracyUSec
DeferAcceptSec
Delegate
Description
DeviceAllow
DevicePolicy
DirectoryMode
DirectoryNotEmpty
Documentation
DynamicUser
Environment
EnvironmentFile
ExecReload
ExecStart
ExecStartPost
ExecStartPre
ExecStop
ExecStopPost
ExecStopPre
ExitCode
FailureAction
Features
FileDescriptorName
FileDescriptorStoreMax
FinishTimestamp
FinishTimestampMonotonic
FirmwareTimestampMonotonic
ForceUnmount
FreeBind
GeneratorsFinishTimestamp
GeneratorsFinishTimestampMonotonic
GeneratorsStartTimestamp
GeneratorsStartTimestampMonotonic
Group
GuessMainPID
IgnoreOnIsolate
IgnoreOnSnapshot
IgnoreSIGPIPE
InaccessibleDirectories
InaccessiblePaths
InitRDTimestampMonotonic
IOAccounting
IODeviceWeight
IOReadBandwidthMax
IOReadIOPSMax
IOSchedulingClass
IOSchedulingPriority
IOWeight
IOWriteBandwidthMax
IOWriteIOPSMax
IPAccounting
IPAddressAllow
IPAddressDeny
IPTOS
IPTTL
JobRunningTimeoutSec
JobTimeoutAction
JobTimeoutRebootArgument
JobTimeoutSec
JoinsNamespaceOf
KeepAlive
KeepAliveIntervalSec
KeepAliveProbes
KeepAliveTimeSec
KernelTimestamp
KernelTimestampMonotonic
KeyringMode
KillMode
KillSignal
LazyUnmount
LimitAS
LimitCORE
LimitCPU
LimitDATA
LimitFSIZE
LimitLOCKS
LimitMEMLOCK
LimitMSGQUEUE
LimitNICE
LimitNOFILE
LimitNPROC
LimitRSS
LimitRTPRIO
LimitRTTIME
LimitSIGPENDING
LimitSTACK
ListenDatagram
ListenFIFO
ListenMessageQueue
ListenNetlink
ListenSequentialPacket
ListenSpecial
ListenStream
ListenUSBFunction
LoaderTimestampMonotonic
LockPersonality
LogExtraFields
LogLevel
LogLevelMax
LogsDirectory
LogsDirectoryMode
LogTarget
MakeDirectory
Mark
MaxConnections
MaxConnectionsPerSource
MemoryAccounting
MemoryDenyWriteExecute
MemoryHigh
MemoryLimit
MemoryLow
MemoryMax
MemorySwapMax
MessageQueueMaxMessages
MessageQueueMessageSize
MountAPIVFS
MountFlags
NetClass
NFailedJobs
NFailedUnits
Nice
NInstalledJobs
NJobs
NNames
NoDelay
NonBlocking
NoNewPrivileges
NotifyAccess
OnActiveSec
OnBootSec
OnCalendar
OnFailure
OnFailureIsolate
OnFailureJobMode
OnStartupSec
OnUnitActiveSec
OnUnitInactiveSec
OOMScoreAdjust
Options
PAMName
PartOf
PassCredentials
PassEnvironment
PassSecurity
PathChanged
PathExists
PathExistsGlob
PathModified
PermissionsStartOnly
Persistent
Personality
PIDFile
PipeSize
Priority
PrivateDevices
PrivateNetwork
PrivateTmp
PrivateUsers
Progress
PropagateReloadFrom
PropagateReloadTo
PropagatesReloadTo
ProtectControlGroups
ProtectHome
ProtectKernelModules
ProtectKernelTunables
ProtectSystem
RandomizedDelaySec
ReadOnlyDirectories
ReadOnlyPaths
ReadWriteDirectories
ReadWritePaths
RebootArgument
ReceiveBuffer
RefuseManualStart
RefuseManualStop
ReloadPropagatedFrom
RemainAfterElapse
RemainAfterExit
RemoveIPC
RemoveOnStop
RequiredBy
Requires
RequiresMountsFor
RequiresOverridable
Requisite
RequisiteOverridable
Restart
RestartForceExitStatus
RestartPreventExitStatus
RestartSec
RestrictAddressFamilies
RestrictNamespaces
RestrictRealtime
ReusePort
RootDirectory
RootDirectoryStartOnly
RootImage
RuntimeDirectory
RuntimeDirectoryMode
RuntimeDirectoryPreserve
RuntimeMaxSec
RuntimeWatchdogUSec
SecureBits
SecurityFinishTimestamp
SecurityFinishTimestampMonotonic
SecurityStartTimestamp
SecurityStartTimestampMonotonic
SELinuxContext
SELinuxContextFromNet
SendBuffer
SendSIGHUP
SendSIGKILL
Service
ServiceWatchdogs
ShowStatus
ShutdownWatchdogUSec
Slice
SloppyOptions
SmackLabel
SmackLabelIPIn
SmackLabelIPOut
SmackProcessLabel
SocketGroup
SocketMode
SocketProtocol
Sockets
SocketUser
SourcePath
StandardError
StandardInput
StandardInputData
StandardInputText
StandardOutput
StartLimitAction
StartLimitBurst
StartLimitInterval
StartLimitIntervalSec
StartupBlockIOWeight
StartupCPUShares
StartupCPUWeight
StartupIOWeight
StateDirectory
StateDirectoryMode
StopWhenUnneeded
SuccessAction
SuccessExitStatus
SupplementaryGroups
Symlinks
SyslogFacility
SyslogIdentifier
SyslogLevel
SyslogLevelPrefix
SystemCallArchitectures
SystemCallErrorNumber
SystemCallFilter
SystemState
SysVStartPriority
TasksAccounting
TasksMax
TCPCongestion
TemporaryFileSystem
TimeoutIdleSec
TimeoutSec
TimeoutStartSec
TimeoutStopSec
TimerSlackNSec
Transparent
TriggerLimitBurst
TriggerLimitIntervalSec
TTYPath
TTYReset
TTYVHangup
TTYVTDisallocate
Type
UMask
Unit
UnitPath
UnitsLoadFinishTimestamp
UnitsLoadFinishTimestampMonotonic
UnitsLoadStartTimestamp
UnitsLoadStartTimestampMonotonic
UnsetEnvironment
USBFunctionDescriptors
USBFunctionStrings
User
UserspaceTimestamp
UserspaceTimestampMonotonic
UtmpIdentifier
UtmpMode
Version
WakeSystem
WantedBy
Wants
WatchdogSec
What
Where
WorkingDirectory
Writable
