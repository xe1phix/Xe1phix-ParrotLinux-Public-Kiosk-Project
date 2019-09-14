


systemctl show -p FragmentPath accounts-daemon.service
## ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ##
FragmentPath=/lib/systemd/system/accounts-daemon.service
## ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ##

systemctl show -p CapabilityBoundingSet apache2.service
## ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ##
CapabilityBoundingSet=cap_chown cap_dac_override cap_dac_read_search cap_fowner cap_fsetid cap_kill cap_setgid cap_setuid cap_setpcap c
## ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ##

systemctl show -p CapabilityBoundingSet network-manager.service 
## ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ##
CapabilityBoundingSet=cap_dac_override cap_kill cap_setgid cap_setuid cap_net_bind_service cap_net_admin cap_net_raw cap_sys_module cap_sys_chroot cap_audit_write
## ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ##

systemctl show -p CapabilityBoundingSet network-manager.service | less
## ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ##
CapabilityBoundingSet=cap_chown cap_dac_override cap_dac_read_search cap_fowner cap_fsetid cap_kill cap_setgid cap_setuid cap_setpcap cap_linux_immutable cap_net_bind_service cap_net_broadcast cap_net_admin cap_net_raw cap_ipc_lock cap_ipc_owner cap_sys_module cap_sys_rawio cap_sys_chroot cap_sys_ptrace cap_sys_pacct cap_sys_admin cap_sys_boot cap_sys_nice cap_sys_resource cap_sys_time cap_sys_tty_config cap_mknod cap_lease cap_audit_write cap_audit_control cap_setfcap cap_mac_override cap_mac_admin cap_syslog cap_wake_alarm cap_block_suspend
## ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ##

systemctl show -p CapabilityBoundingSet NetworkManager.service | less
## ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ##
CapabilityBoundingSet=cap_dac_override cap_kill cap_setgid cap_setuid cap_net_bind_service cap_net_admin cap_net_raw cap_sys_module cap_sys_chroot cap_audit_write
## ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ##

systemctl show -p CapabilityBoundingSet network-manager.service | less
## ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ##
CapabilityBoundingSet=cap_dac_override cap_kill cap_setgid cap_setuid cap_net_bind_service cap_net_admin cap_net_raw cap_sys_module cap_sys_chroot cap_audit_write
## ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ##


systemctl show -p CapabilityBoundingSet NetworkManager-dispatcher.service | less
## ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ##
CapabilityBoundingSet=cap_chown cap_dac_override cap_dac_read_search cap_fowner cap_fsetid cap_kill cap_setgid cap_setuid cap_setpcap cap_linux_immutable cap_net_bind_service cap_net_broadcast cap_net_admin cap_net_raw cap_ipc_lock cap_ipc_owner cap_sys_module cap_sys_rawio cap_sys_chroot cap_sys_ptrace cap_sys_pacct cap_sys_admin cap_sys_boot cap_sys_nice cap_sys_resource cap_sys_time cap_sys_tty_config cap_mknod cap_lease cap_audit_write cap_audit_control cap_setfcap cap_mac_override cap_mac_admin cap_syslog cap_wake_alarm cap_block_suspend
## ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ##


systemctl show -p CapabilityBoundingSet NetworkManager-wait-online.service | less
## ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ##
CapabilityBoundingSet=cap_chown cap_dac_override cap_dac_read_search cap_fowner cap_fsetid cap_kill cap_setgid cap_setuid cap_setpcap cap_linux_immutable cap_net_bind_service cap_net_broadcast cap_net_admin cap_net_raw cap_ipc_lock cap_ipc_owner cap_sys_module cap_sys_rawio cap_sys_chroot cap_sys_ptrace cap_sys_pacct cap_sys_admin cap_sys_boot cap_sys_nice cap_sys_resource cap_sys_time cap_sys_tty_config cap_mknod cap_lease cap_audit_write cap_audit_control cap_setfcap cap_mac_override cap_mac_admin cap_syslog cap_wake_alarm cap_block_suspend
## ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ##




gdbus introspect --system --dest org.freedesktop.systemd1 --object-path /org/freedesktop/systemd1 --recurse | less


gdbus introspect --system --dest org.freedesktop.systemd1 --object-path /org/freedesktop/systemd1/unit/apparmor_2eservice --recurse | grep "readonly t " | cut -c18-199




ActiveState


sys-subsystem-bluetooth-devices-hci0.device
sys-subsystem-net-devices-eth0.device
sys-subsystem-net-devices-wlan0.device


sys-kernel-config.mount
sys-kernel-debug.mount


stunnel4.service
sudo.service
suricata.service
snort.service
sockets.target
sound.target
sshd.service
ssh.service
ssh.socket







rwhod.service
sagan.service


rpcbind.target
rsync.service
rsyslog.service

media-cdrom0.mount







ControlGroup


"User=
Group=
CapabilityBoundingSet=
CapabilityBoundingSet

    PrivateTmp=(true|yes)
    PrivateDevices=(true|yes)
    NoNewPrivileges=(true|yes)
    SELinuxContext=
    AppArmorProfile=
    LimitNOFILE=
    LimitNPROC="

ProtectHome=true
ProtectHome=read-only



ProtectSystem=full
ProtectSystem=true


AllowIsolate
CanIsolate

BindReadOnlyPaths
AppArmorProfile



systemctl show -p 
Display all 464 possibilities? (y or n)


Accept
AccuracyUSec
ActiveEnterTimestamp
ActiveEnterTimestampMonotonic
ActiveExitTimestamp
ActiveExitTimestampMonotonic
ActiveState
After
AllowIsolate
AmbientCapabilities
AppArmorProfile
Architecture
AssertResult
Asserts
AssertTimestamp
AssertTimestampMonotonic
Backlog
Before
BindIPv6Only
BindPaths
BindReadOnlyPaths
BindsTo
BindToDevice
BlockIOAccounting
BlockIODeviceWeight
BlockIOReadBandwidth
BlockIOWeight
BlockIOWriteBandwidth
BoundBy
Broadcast
BusName
CacheDirectory
CacheDirectoryMode
CanIsolate
CanReload
CanStart
CanStop
CapabilityBoundingSet
CollectMode
ConditionResult
Conditions
ConditionTimestamp
ConditionTimestampMonotonic
ConfigurationDirectory
ConfigurationDirectoryMode
ConfirmSpawn
ConflictedBy
Conflicts
ConsistsOf
ControlGroup
Controller
ControlPID
CPUAccounting
CPUAffinity
CPUQuotaPerSecUSec
CPUSchedulingPolicy
CPUSchedulingPriority
CPUSchedulingResetOnFork
CPUShares
CPUUsageNSec
CPUWeight
DefaultBlockIOAccounting
DefaultCPUAccounting
DefaultDependencies
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
DeferAcceptUSec
Delegate
DelegateControllers
Description
DeviceAllow
DevicePolicy
DirectoryMode
Documentation
DropInPaths
DynamicUser
Environment
EnvironmentFiles
ExecActivate
ExecDeactivate
ExecMainCode
ExecMainExitTimestamp
ExecMainExitTimestampMonotonic
ExecMainPID
ExecMainStartTimestamp
ExecMainStartTimestampMonotonic
ExecMainStatus
ExecMount
ExecReload
ExecRemount
ExecStart
ExecStartPost
ExecStartPre
ExecStop
ExecStopPost
ExecStopPre
ExecUnmount
ExitCode
FailureAction
Features
FileDescriptorName
FileDescriptorStoreMax
FinishTimestamp
FinishTimestampMonotonic
FirmwareTimestamp
FirmwareTimestampMonotonic
Following
ForceUnmount
FragmentPath
FreeBind
GeneratorsFinishTimestamp
GeneratorsFinishTimestampMonotonic
GeneratorsStartTimestamp
GeneratorsStartTimestampMonotonic
GID
Group
GuessMainPID
Id
IgnoreOnIsolate
IgnoreSIGPIPE
InaccessiblePaths
InactiveEnterTimestamp
InactiveEnterTimestampMonotonic
InactiveExitTimestamp
InactiveExitTimestampMonotonic
InitRDTimestamp
InitRDTimestampMonotonic
InvocationID
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
IPEgressBytes
IPEgressPackets
IPIngressBytes
IPIngressPackets
IPTOS
IPTTL
Job
JobRunningTimeoutUSec
JobTimeoutAction
JobTimeoutRebootArgument
JobTimeoutUSec
JobType
JoinsNamespaceOf
KeepAlive
KeepAliveIntervalUSec
KeepAliveProbes
KeepAliveTimeUSec
KernelTimestamp
KernelTimestampMonotonic
KeyringMode
KillMode
KillSignal
LastTriggerUSec
LastTriggerUSecMonotonic
LazyUnmount
LimitAS
LimitASSoft
LimitCORE
LimitCORESoft
LimitCPU
LimitCPUSoft
LimitDATA
LimitDATASoft
LimitFSIZE
LimitFSIZESoft
LimitLOCKS
LimitLOCKSSoft
LimitMEMLOCK
LimitMEMLOCKSoft
LimitMSGQUEUE
LimitMSGQUEUESoft
LimitNICE
LimitNICESoft
LimitNOFILE
LimitNOFILESoft
LimitNPROC
LimitNPROCSoft
LimitRSS
LimitRSSSoft
LimitRTPRIO
LimitRTPRIOSoft
LimitRTTIME
LimitRTTIMESoft
LimitSIGPENDING
LimitSIGPENDINGSoft
LimitSTACK
LimitSTACKSoft
Listen
LoadError
LoaderTimestamp
LoaderTimestampMonotonic
LoadState
LockPersonality
LogExtraFields
LogLevel
LogLevelMax
LogsDirectory
LogsDirectoryMode
LogTarget
MainPID
MakeDirectory
Mark
MaxConnections
MaxConnectionsPerSource
MemoryAccounting
MemoryCurrent
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
NAccepted
Names
NConnections
NeedDaemonReload
NextElapseUSecMonotonic
NextElapseUSecRealtime
NFailedJobs
NFailedUnits
NFileDescriptorStore
Nice
NInstalledJobs
NJobs
NNames
NoDelay
NonBlocking
NoNewPrivileges
NotifyAccess
NRefused
NRestarts
OnFailure
OnFailureJobMode
OOMScoreAdjust
Options
PAMName
PartOf
PassCredentials
PassEnvironment
PassSecurity
Paths
PermissionsStartOnly
Perpetual
Persistent
Personality
PIDFile
PipeSize
Priority
PrivateDevices
PrivateMounts
PrivateNetwork
PrivateTmp
PrivateUsers
Progress
PropagatesReloadTo
ProtectControlGroups
ProtectHome
ProtectKernelModules
ProtectKernelTunables
ProtectSystem
RandomizedDelayUSec
ReadOnlyPaths
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
Requisite
RequisiteOf
Restart
RestartForceExitStatus
RestartPreventExitStatus
RestartUSec
RestrictAddressFamilies
RestrictNamespaces
RestrictRealtime
Result
ReusePort
RootDirectory
RootDirectoryStartOnly
RootImage
RuntimeDirectory
RuntimeDirectoryMode
RuntimeDirectoryPreserve
RuntimeMaxUSec
RuntimeWatchdogUSec
SameProcessGroup
SecureBits
SecurityFinishTimestamp
SecurityFinishTimestampMonotonic
SecurityStartTimestamp
SecurityStartTimestampMonotonic
SELinuxContext
SendBuffer
SendSIGHUP
SendSIGKILL
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
SocketUser
SourcePath
StandardError
StandardErrorFileDescriptorName
StandardInput
StandardInputData
StandardInputFileDescriptorName
StandardOutput
StandardOutputFileDescriptorName
StartLimitAction
StartLimitBurst
StartLimitIntervalUSec
StartupBlockIOWeight
StartupCPUShares
StartupCPUWeight
StartupIOWeight
State
StateChangeTimestamp
StateChangeTimestampMonotonic
StateDirectory
StateDirectoryMode
StatusErrno
StatusText
StopWhenUnneeded
SubState
SuccessAction
SuccessExitStatus
SupplementaryGroups
Symlinks
SysFSPath
SyslogFacility
SyslogIdentifier
SyslogLevel
SyslogLevelPrefix
SyslogPriority
SystemCallArchitectures
SystemCallErrorNumber
SystemCallFilter
SystemState
Tainted
TasksAccounting
TasksCurrent
TasksMax
TCPCongestion
TemporaryFileSystem
TimeoutIdleUSec
TimeoutStartUSec
TimeoutStopUSec
TimeoutUSec
TimersCalendar
TimerSlackNSec
TimersMonotonic
Transient
Transparent
TriggeredBy
TriggerLimitBurst
TriggerLimitIntervalUSec
Triggers
TTYPath
TTYReset
TTYVHangup
TTYVTDisallocate
Type
UID
UMask
Unit
UnitFilePreset
UnitFileState
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
Virtualization
WakeSystem
WantedBy
Wants
WatchdogTimestamp
WatchdogTimestampMonotonic
WatchdogUSec
What
Where
WorkingDirectory
Writable



libvirtd.service
libvirt-guests.service


