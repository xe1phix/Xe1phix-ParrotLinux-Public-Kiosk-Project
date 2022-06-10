#!/bin/sh



/usr/share/doc/firejail/profile.template




r = read
w = write
l = link
k = lock
a = append

r   ## read access
w   ## write access
a   ## limited write access (append)*
k   ## lock a file
m   ## load into memory - executable mapping
x   ## allows execution

ix: executes the file under the constraints of the profile (inherit)
ux**: executes the file outside of the profile (unconfined)
Cx: executes the file in its own profile, which is specific to the parent process
Px**: executes the file in its own profile, which you will have to define (profile)
**Capital C, P or U means that the environment is sanitized before executing the code. You want
to sanitize whenever possible.


ix = inherit = Inherit the parents profile.
px = requires a separate profile exists for the application, with environment scrubbing.
Px = requires a separate profile exists for the application, without environment scrubbing.

ux and Ux = Allow execution of an application unconfined, with and without environmental scrubbing. (use with caution if at all).




sudo perl ‐pi ‐e 's,GRUB_CMDLINE_LINUX="(.*)"$,GRUB_CMDLINE_LINUX="$1 apparmor=1 security=apparmor",' /etc/default/grub
set CONFIG_SECURITY_APPARMOR=y
set CONFIG_DEFAULT_SECURITY="apparmor"
set CONFIG_SECURITY_APPARMOR_BOOTPARAM_VALUE=1
sudo update‐grub
sudo reboot


##-========================================-##
##   [+] Show the kernel boot arguements:
##-========================================-##
cat -vET /proc/cmdline | xxd


##-===================================-##
##   [+] Start the AppArmor daemon:
##-===================================-##
/etc/init.d/apparmor start

## --------------------------------- ##
systemctl enable apparmor
systemctl start apparmor
## --------------------------------- ##
##
##
## ----------------------------------------------------- ##
##  [?] The AppArmor profile file (firejail-default)
##  [?] is placed in /etc/apparmor.d
## ----------------------------------------------------- ##
##
##
## ----------------------------------------------------- ##
##  [?] The local customizations must be placed in
## ----------------------------------------------------- ##
##  [?] /etc/apparmor.d/local/firejail-local
##
##
## ----------------------------------------------------- ##
##  [?] The profile needs to be loaded into the kernel
##      by reloading apparmor.service.
## ----------------------------------------------------- ##
service apparmor reload
/etc/init.d/apparmor restart


##-===================================================================-##
##   [+] apparmor_parser - loads AppArmor profiles into the kernel
##-===================================================================-##
apparmor_parser --verbose -r /etc/apparmor.d/firejail-default


##-===============================================-##
##   [+] Enforce all of the AppArmor profiles
##       in the /etc/apparmor.d/ directory:
##-===============================================-##
apparmor_parser --verbose -r /etc/apparmor.d/*


## ---------------------------------------------------------------- ##
##    [?] You may need to mount the securityFS into the kernel:
## ---------------------------------------------------------------- ##
##  mount -tsecurityfs securityfs /sys/kernel/security
##
##
## ------------------------------------------------- ##
##   [?] see if AppArmor is loaded and enabled
##   [?]         (should print “Y”):
## ------------------------------------------------- ##
##  cat /sys/module/apparmor/parameters/enabled
##
##
## ---------------------------------------------------------------- ##
##  cat /sys/kernel/security/apparmor/profiles
## ---------------------------------------------------------------- ##
##  cat /sys/kernel/security/apparmor/policy/profiles/
## ---------------------------------------------------------------- ##
##  cat /sys/kernel/security/apparmor/profiles | grep firejail
## ---------------------------------------------------------------- ##
##
##
##-======================================================================-##
##   [+] aa-status - report the current state of AppArmor confinement
##-======================================================================-##
sudo apparmor_status --verbose


##-========================================================================-##
##   [+] aa-complain - set an AppArmor security profile to complain mode
##-========================================================================-##
## ------------------------------------------------------------------------ ##
##  [?] In complain mode, the security policy is not enforced
##  [?] but rather access violations are logged to the system log.
## ------------------------------------------------------------------------ ##
##
## -------------------------------------------------- ##
##   [+] Place all of the apparmor profiles
##       in /etc/apparmor.d/* into complain mode:
## -------------------------------------------------- ##
sudo aa-complain /etc/apparmor.d/*


##-======================================================================-##
##   [+] aa-enforce - set an AppArmor security profile to enforce mode
##-======================================================================-##
##
## -------------------------------------------------- ##
##   [+] Place all of the apparmor profiles
##       in /etc/apparmor.d/* into enforce mode:
## -------------------------------------------------- ##
sudo aa-enforce /etc/apparmor.d/*


##-===============================================-##
##   [+] Enforce the Firejail AppArmor profile:
##-===============================================-##
sudo aa-enforce firejail-default





1sud
## ----------------------------------------------------------- ##
##   [?] Allow your desktop user to read audit logs
##       in /var/log/audit by adding it to audit user group
## ----------------------------------------------------------- ##
groupadd -r audit
gpasswd -a xe1phix audit
sudo adduser xe1phix adm
usermod xe1phix --groups adm audit

##-========================================-##
##   [+] Add audit group to auditd.conf:
##-========================================-##
/etc/audit/auditd.conf

log_group = audit


AppArmor Notify
/usr/bin/aa-notify -p -s 1 -w 60


##-=======================================================-##
##   [+] set an AppArmor security profile to audit mode
##-=======================================================-##
aa-audit --dir /etc/apparmor.d/


## ---------------------------------------------------------------------- ##
##  [?] aa-notify - display information about logged AppArmor messages
## ---------------------------------------------------------------------- ##
/etc/apparmor/notify.conf
~/.apparmor/notify.conf

--verbose


##-===================================================-##
##   [+] Get desktop notification on DENIED actions
##-===================================================-##
sudo aa-notify -p -f /var/log/audit/audit.log
aa-notify -p -f /var/log/audit /audit.log --display $DISPLAY



##-=====================================-##
##   [+]

~/.config/autostart/apparmor-notify.desktop

[Desktop Entry]
Type=Application
Name=AppArmor Notify
Comment=Receive on screen notifications of AppArmor denials
TryExec=aa-notify
Exec=aa-notify -p -s 1 -w 60 -f /var/log/audit/audit.log
StartupNotify=false
NoDisplay=true



##-===================================================-##
##   [+] check if the aa-notify process is running:
##-===================================================-##
pgrep -ax aa-notify



##-============================-##
##   [+] generate a profile:
##-============================-##
sudo genprof $Profile




##-===================================================-##
##   [+] search your logs and modify your profile
##-===================================================-##
sudo aa-logprof $Profile




cat /sys/module/apparmor/parameters/enabled
cat /sys/module/apparmor/parameters/mode
cat /sys/module/apparmor/parameters/debug



##-=====================================-##
##   [+] turn off deny audit quieting:
##-=====================================-##
echo -n noquiet > /sys/module/apparmor/parameters/audit


##-==================================-##
##   [+] Force audit mode globally:
##-==================================-##
echo -n all > /sys/module/apparmor/parameters/audit


cat /sys/module/apparmor/parameters/audit


cat /sys/module/apparmor/parameters/audit_header
echo "1" > /sys/module/apparmor/parameters/audit_header

cat /sys/module/apparmor/parameters/debug
cat /sys/module/apparmor/parameters/enabled


cat /sys/module/apparmor/parameters/hash_policy
echo "1" > /sys/module/apparmor/parameters/hash_policy

cat /sys/module/apparmor/parameters/lock_policy


cat /sys/module/apparmor/parameters/logsyscall


cat /sys/module/apparmor/parameters/mode


cat /sys/module/apparmor/parameters/paranoid_load
echo "1" > /sys/module/apparmor/parameters/paranoid_load

cat /sys/module/apparmor/parameters/path_max

cat /sys/module/apparmor/parameters/rawdata_compression_level


##-============================-##
##   [+] Enable debug mode:
##-============================-##
echo 1 > /sys/module/apparmor/parameters/debug


##-=======================================-##
##   [+] Check if SecurityFS is mounted:
##-=======================================-##
cat /proc/mounts | grep "/sys/kernel/security"


--apparmorfs /sys/kernel/security/apparmor


##-==================================================-##
##   [+] Mount the AppArmor securityfs filesystem:
##-==================================================-##
mount -tsecurityfs securityfs /sys/kernel/security


cat /sys/kernel/security/apparmor/profiles
cat /sys/module/apparmor/parameters/enabled
cat /sys/kernel/security/apparmor/policy/profiles/



sudo cat /sys/kernel/security/apparmor/profiles | grep firejail
cat /sys/kernel/security/apparmor/policy/profiles/firejail-default.52/mode


sudo apparmor_status --verbose



aa-status --verbose 				## displays multiple data points about loaded AppArmor policy set
aa-status --profiled 				## displays the number of loaded AppArmor policies
aa-status --enabled					## returns error code if AppArmor is not enabled.
aa-status --enforced				## displays the number of loaded enforcing AppArmor policies
aa-status --complaining				## displays the number of loaded non-enforcing AppArmor policies

sudo aa-complain /bin/ping						## put a profile in complain mode:

sudo aa-complain --dir /etc/apparmor.d/*				## put all profiles into complain mode:

sudo aa-enforce /bin/ping						## put a profile in enforcing mode:

sudo aa-enforce 								## put all profiles into enforcing mode:


sudo aa-enforce /etc/apparmor.d/usr.lib.firefox.firefox
sudo aa-enforce --dir /etc/apparmor.d/*



apparmor_parser --warn=rules-not-enforced



invoke-rc.d apparmor reload						## Reload all profiles
/etc/init.d/apparmor restart
/etc/init.d/apparmor reload                     ## Reload all profiles


##-======================================================-##
##   [+] replace the definition already in the kernel
##-======================================================-##
apparmor_parser --replace /etc/apparmor.d/bin.ping


##-=======================================-##
##   [+] Load a profile into the kernel:
##-=======================================-##
apparmor_parser --verbose --add /etc/apparmor.d/*



apparmor_parser --verbose --add /etc/apparmor.d/usr.lib.firefox.firefox
apparmor_parser --verbose --add /etc/apparmor.d/usr.lib.firefox.firefox.sh
apparmor_parser --verbose --add /etc/apparmor.d/usr.lib.firefox.mozilla-xremote-client

apparmor_parser --help=dump


##-=======================================================-##
##   [+] Report the cache processing (hit/miss details)
##-=======================================================-##
apparmor_parser --verbose --show-cache


##-==================================-##
##   [+] clear out cached profiles
##-==================================-##
apparmor_parser --verbose --purge-cache




## Produce a list of policies from a given set of profiles


sudo aa-enforce /etc/apparmor.d/usr.bin.firefox		## Enable Firefox Profile


/etc/apparmor.d/
/var/lib/apparmor/
/var/log/audit/audit.log
/var/log/messages



git clone https://github.com/netblue30/firejail.git			## Cloning The Firejail Github Repo
cd firejail
./configure && make && sudo make install-strip				## Initiate Firejail Setup Using The Make Compiler
./configure --prefix=/usr --enable-apparmor					## Load The Apparmor Kernel Module
															## Then Compile Into Firejail Source...
aa-enforce firejail-default									## Load The Apparmor Profile Into The Kernel



##-=======================================================-##
##   [+] Check if process is using AppArmor confinement.
##-=======================================================-##
firemon --apparmor $PID


##-=======================================================-##
##   [+] Check if process is using AppArmor confinement.
##-=======================================================-##
firejail --apparmor.print=$PID




  echo "[$SCRIPT_COUNT] Enforce apparmor profiles"

  if ! grep 'session.*pam_apparmor.so order=user,group,default' /etc/pam.d/*; then
    echo 'session optional pam_apparmor.so order=user,group,default' > /etc/pam.d/apparmor
  fi



