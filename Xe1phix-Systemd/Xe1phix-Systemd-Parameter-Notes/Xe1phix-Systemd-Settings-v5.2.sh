CapabilityBoundingSet=~CAP_SYS_ADMIN
SystemCallFilter=~@mount
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM



ReadOnlyPaths=
BindReadOnlyPaths=
ReadOnlyPaths=


InaccessiblePaths=


TemporaryFileSystem=




ProtectSystem=strict



ConfigurationDirectory=
LogsDirectoryMode=
DynamicUser=
LogsDirectory=
CacheDirectory=                            ## /var/cache │ $XDG_CACHE_HOME
CacheDirectoryMode=

ProtectSystem=full          ## mounts the /usr and /boot directories read-only for processes
strict                      ## If set to "strict" the entire fil system hierarchy is mounted read-only

ProtectHome=read-only
tmpfs

RemoveIPC=                  ## all System V and POSIX IPC objects owned by the user and group the processes of this unit are run as are removed when the unit is stopped.
PrivateTmp=                 ## sets up a new file system namespace for the executed processes and mounts private /tmp and /var/tmp directories inside it

ProtectKernelTunables=


User=
Group=

UMask=


SELinuxContext=
AppArmorProfile=
SmackProcessLabel=

setexeccon


SecureBits=keep-caps, keep-caps-locked,no-setuid-fixup, no-setuid-fixup-locked, noroot, and noroot-locked



NoNewPrivileges=yes
User=nobody



SystemCallFilter=
SystemCallArchitectures=

ProtectKernelTunables=true
ProtectKernelModules=CAP_SYS_MODULE
                                ## kernel.modules_disabled > sysctl.d


RestrictAddressFamilies=AF_INET AF_UNIX         ## Restricts the set of socket address families accessible to the processes 
RestrictAddressFamilies=~AF_INET6           ## When prefixed with ~ the listed address families will be blacklist


RestrictNamespaces=cgroup, ipc, net, mnt,pid, user and uts
JoinsNamespaceOf=

RestrictNamespaces=cgroup ipc
RestrictNamespaces=~cgroup net


PrivateDevices=
ProtectKernelTunables=
ProtectKernelModules=                   ## explicit module loading will be denied
ProtectControlGroups=                   ## the Linux Control Groups (cgroups(7)) hierarchies accessible through /sys/fs/cgroup will be made read-only to all processes

MemoryDenyWriteExecute=
RestrictRealtime=
LockPersonality=


systemctl show 
systemd-analyze syscall-filter



RestrictRealtime=                   ## any attempts to enable realtime scheduling in a process of the unit are refused.





AmbientCapabilities=CAP_SYS_ADMIN,CAP_DAC_OVERRIDE, CAP_SYS_PTRACE

CapabilityBoundingSet=CAP_SYS_ADMIN, CAP_DAC_OVERRIDE, CAP_SYS_PTRACE


PAMName=

NotifyAccess=all


SupplementaryGroups=


MountAPIVFS=                    ## private mount namespace for the unit's processes

MountFlags=shared, slave or private


PrivateDevices=
PrivateMounts=                  ## the processes of this unit will be run in their own private file system (mount) namespace with all mount propagation from the processes
PrivateUsers=                   ## sets up a new user namespac

MemoryDenyWriteExecute=yes


RootDirectory=
RootImage=

WorkingDirectory=


RestrictAddressFamilies=




StandardError=journal




DefaultEnvironment=
systemd.setenv=
PassEnvironment=
Environment=
UnsetEnvironment=
EnvironmentFile=.


Environment="VAR1=word1 word2" VAR2=word3 "VAR3=$word 5 6"
PassEnvironment=VAR1 VAR2 VAR3


Personality=
LockPersonality=                ## locks down the personality(2) system call



UtmpIdentifier=
UtmpMode="init", "login" or "user"



SyslogFacility=kern, user, mail, daemon,auth, syslog, lpr, news, uucp, cron, authpriv, ftp, local0, local1, local2, local3,local4, local5, local6 or local7

SyslogIdentifier=journal, syslog or kmsg

SyslogLevel=emerg, alert, crit, err, warning, notice, info, debug
LogLevelMax=alert, crit,err, warning, notice, info, debug

LogExtraFields=

SyslogLevelPrefix=journal, syslog or kmsg

StandardInput=null, tty, tty-force, tty-fail, data, file:path, socket or fd:name
StandardOutput=inherit, null, tty, journal, syslog, kmsg, journal+console, syslog+console,kmsg+console, file:path, socket or fd:name
StandardError=



StandardInputText=
StandardInputData=


FileDescriptorName=


UMask=0022

IPAccounting=


LimitCPU=infinity
LimitCPUSoft=infinity
LimitFSIZE=infinity
LimitFSIZESoft=infinity
LimitDATA=infinity
LimitDATASoft=infinity
LimitSTACK=infinity
LimitSTACKSoft=8388608
LimitCORE=infinity
LimitCORESoft=0
LimitRSS=infinity
LimitRSSSoft=infinity
LimitNOFILE=4096
LimitNOFILESoft=1024
LimitAS=infinity
LimitASSoft=infinity
LimitNPROC=31207
LimitNPROCSoft=31207
LimitMEMLOCK=16777216
LimitMEMLOCKSoft=16777216
LimitLOCKS=infinity
LimitLOCKSSoft=infinity
LimitSIGPENDING=31207
LimitSIGPENDINGSoft=31207
LimitMSGQUEUE=819200
LimitMSGQUEUESoft=819200
LimitNICE=0
LimitNICESoft=0
LimitRTPRIO=0
LimitRTPRIOSoft=0
LimitRTTIME=infinity
LimitRTTIMESoft=



SyslogPriority=30
SyslogLevelPrefix=yes
SyslogLevel=6
SyslogFacility=3
LogLevelMax=-1
SecureBits=0
CapabilityBoundingSet=cap_chown cap_dac_override cap_dac_read_search cap_fowner cap_fsetid cap_kill cap
AmbientCapabilities=
DynamicUser=no
RemoveIPC=no
MountFlags=
PrivateTmp=no
PrivateDevices=no
ProtectKernelTunables=no
ProtectKernelModules=no
ProtectControlGroups=no

PrivateNetwork=no
PrivateUsers=no
PrivateMounts=no
ProtectHome=no
ProtectSystem=no
SameProcessGroup=no
UtmpMode=init
IgnoreSIGPIPE=yes
NoNewPrivileges=no
SystemCallErrorNumber=0
LockPersonality=no
RuntimeDirectoryPreserve=no

RuntimeDirectoryMode=0755
StateDirectoryMode=0755
CacheDirectoryMode=0755
LogsDirectoryMode=0755
ConfigurationDirectoryMode=0755
MemoryDenyWriteExecute=no
RestrictRealtime=no
RestrictNamespaces=no
MountAPIVFS=no
KeyringMode=private
KillMode=control-group
KillSignal=15
SendSIGKILL=yes
SendSIGHUP=no

Requires=system.slice

CanStart=yes
CanStop=yes
CanReload=no
CanIsolate=no

AllowIsolate=no

OnFailureJobMode=replace
IgnoreOnIsolate=no
NeedDaemonReload=no

FailureAction=none


DevicePolicy=auto
IOAccounting=no

ControlGroup=
UID=
GID=
ExecMainPID=
MainPID=719
ControlPID=

PermissionsStartOnly=no
RootDirectoryStartOnly=no

NotifyAccess=












systemctl --all set-property 

journalctl --user-unit=
journalctl --unit=


--show-types
systemctl --state=help

list-sockets


show-environment
set-environment
unset-environment
import-environment


systemd.resource-control





