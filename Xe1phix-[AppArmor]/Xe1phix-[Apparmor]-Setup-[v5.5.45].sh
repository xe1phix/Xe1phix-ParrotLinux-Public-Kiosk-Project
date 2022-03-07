#!/bin/sh










r: r is read access
w: w is write access
a: a is limited write access (append)*
k: k allows the ability to lock a file
m: m lets a file be loaded into memory
x: allows execution
ix: executes the file under the constraints of the profile (inherit)
ux**: executes the file outside of the profile (unconfined)
Cx: executes the file in its own profile, which is specific to the parent process
Px**: executes the file in its own profile, which you will have to define (profile)
**Capital C, P or U means that the environment is sanitized before executing the code. You want
to sanitize whenever possible.




sudo perl ‐pi ‐e 's,GRUB_CMDLINE_LINUX="(.*)"$,GRUB_CMDLINE_LINUX="$1 apparmor=1 security=apparmor",' /etc/default/grub
set CONFIG_SECURITY_APPARMOR=y
set CONFIG_DEFAULT_SECURITY="apparmor"
set CONFIG_SECURITY_APPARMOR_BOOTPARAM_VALUE=1
sudo update‐grub
sudo reboot

echo "umask $umask" >> /etc/bashrc


cat -vET /proc/cmdline | xxd


/etc/init.d/apparmor start


To use aa-notify, add your user to the "adm" group so it is allowed to
read the logs.


## using auditd, start aa-notify to get notification
## whenever a program causes a DENIED message.
sudo aa-notify -p -f /var/log/audit/audit.log
aa-notify -p -f /var/log/audit /audit.log --display $DISPLAY


cat /sys/module/apparmor/parameters/enabled
cat /sys/module/apparmor/parameters/mode
cat /sys/module/apparmor/parameters/debug


cat /sys/module/apparmor/parameters/audit
cat /sys/module/apparmor/parameters/audit_header
cat /sys/module/apparmor/parameters/debug
cat /sys/module/apparmor/parameters/enabled
cat /sys/module/apparmor/parameters/hash_policy
cat /sys/module/apparmor/parameters/lock_policy
cat /sys/module/apparmor/parameters/logsyscall
cat /sys/module/apparmor/parameters/mode
cat /sys/module/apparmor/parameters/paranoid_load
cat /sys/module/apparmor/parameters/path_max
cat /sys/module/apparmor/parameters/rawdata_compression_level

cat /sys/module/apparmor/parameters/debug

## enable debug mode:
echo 1 > /sys/module/apparmor/parameters/debug


cat /proc/mounts | grep "/sys/kernel/security"

--apparmorfs /sys/kernel/security/apparmor

## mount the AppArmor securityfs filesystem:
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

invoke-rc.d apparmor reload						## Reload all profiles:
/etc/init.d/apparmor restart
/etc/init.d/apparmor reload

## replace the definition already in the kernel
apparmor_parser --replace /etc/apparmor.d/bin.ping

## Report on the profiles as they are loaded
apparmor_parser --verbose --add /etc/apparmor.d/*

apparmor_parser --verbose --add /etc/apparmor.d/usr.lib.firefox.firefox
apparmor_parser --verbose --add /etc/apparmor.d/usr.lib.firefox.firefox.sh
apparmor_parser --verbose --add /etc/apparmor.d/usr.lib.firefox.mozilla-xremote-client

apparmor_parser --help=dump

## Report the cache processing (hit/miss details)
apparmor_parser --verbose --show-cache


## clear out cached profiles
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



