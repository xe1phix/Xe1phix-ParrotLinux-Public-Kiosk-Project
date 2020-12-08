
sed -i 's/^UMASK.*/UMASK\t\t077/' "$LOGINDEFS"

IPAccounting = true

IPAddressAllow = []
IPAddressDeny = []


CPUAccounting = true
IOAccounting = true
BlockIOAccounting = true
## MemoryAccounting = true




KillMode=process
GuessMainPID=no
RemainAfterExit=yes

ConditionPathExists=/sys/kernel/debug
ConditionCapability=CAP_SYS_RAWIO


Environment = []
EnvironmentFiles = []



PassEnvironment = []
UnsetEnvironment
UMask
LimitNPROC = 29537
LimitNPROCSoft = 29537
LimitNICE = 0
Nice
LimitRTPRIO

RootDirectory

StandardOutput = 'journal'

NonBlocking

RootImage


LogsDirectory = []
LogsDirectoryMode = 0644


SyslogPriority
SyslogIdentifier
SyslogLevelPrefix = true
SyslogLevel = 6
SyslogFacility = 3
LogLevelMax = -1
LogExtraFields

UtmpIdentifier = ''
UtmpMode = 'init'

TasksAccounting = true
TasksMax = 4915





SecureBits
CapabilityBoundingSet
AmbientCapabilities
NoNewPrivileges = true
MemoryDenyWriteExecute = true
SystemCallFilter = true

NotifyAccess = 'none'
PermissionsStartOnly
RootDirectoryStartOnly

DelegateControllCPUAccounting = ers = []



IgnoreSIGPIPE = true

User
Group
DynamicUser = false
PIDFile = ''




RemoveIPC = false
RestrictNamespaces
SupplementaryGroups = []

RestrictRealtime = true

PAMName = ''
SELinuxContext = (false, '')
AppArmorProfile = (false, '')
SmackProcessLabel = (false, '')

KeyringMode = 'private'

ReadWritePaths = []
ReadOnlyPaths = []
InaccessiblePaths = []
MountFlags = 0

BindPaths = []
BindReadOnlyPaths = []


TemporaryFileSystem = []
MountAPIVFS = false

PrivateTmp = true

CacheDirectory = []
CacheDirectoryMode = 0700

ConfigurationDirectory = []
ConfigurationDirectoryMode = 0622


RuntimeDirectory = []
RuntimeDirectoryPreserve = 'yes'
RuntimeDirectoryMode = 0755

StateDirectoryMode = 
StateDirectory = []

PrivateDevices = true
PrivateMounts = true
ProtectHome = yes
ProtectSystem = yes



DevicePolicy = 'auto'
DeviceAllow = []




SameProcessGroup = true
ProtectKernelTunables = true
ProtectKernelModules = true
ProtectControlGroups = true


KillMode = 'control-group'
KillSignal = 15
SendSIGKILL = true
SendSIGHUP = false


PrivateNetwork = true
RestrictAddressFamilies = true


PrivateUsers = true



Personality = ''
LockPersonality = false





OnFailureJobMode = 'replace'




CanIsolate = true
AllowIsolate = true
IgnoreOnIsolate = false


RestrictNamespaces

RequiresMountsFor
JoinsNamespaceOf















ConditionPathExists=!/etc/alsa/state-daemon.conf
ConditionPathExistsGlob=/dev/snd/control*
ConditionPathExists=/var/lib/alsa/asound.state













