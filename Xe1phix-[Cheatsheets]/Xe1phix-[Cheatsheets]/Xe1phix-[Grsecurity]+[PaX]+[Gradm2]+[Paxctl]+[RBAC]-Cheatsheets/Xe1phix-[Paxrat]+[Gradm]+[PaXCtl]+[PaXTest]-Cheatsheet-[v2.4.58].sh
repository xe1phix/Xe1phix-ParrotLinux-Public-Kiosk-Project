#!/bin/sh


systemctl start paxctld
systemctl status paxctld
gradm -C


chkconfig suricata 1|2|3|4|5

chkconfig syslog-ng 1|2|3|4|5

ufw enable
chkconfig ufw start
chkconfig ufw 1|2|3|4|5


ufw status verbose
ufw status
ufw logging debug
ufw logging full
ufw status
ufw status verbose



chkconfig --list
chkconfig --allservices


echo "## ======================================================================================= ##"
echo -e "\t\t PaXrat Configuration example:"
echo "## ======================================================================================= ##"



echo "## --------------------------------------------------------------------------------------- ##"

```json
{
  "/usr/lib/iceweasel/iceweasel": {
    "flags": "pm"
  },
  "/usr/lib/iceweasel/plugin-container": {
    "flags": "m"
  },
  "/home/user/.local/share/torbrowser/tbb/x86_64/tor-browser_en-US/Browser/firefox": {
    "flags": "pm",
    "nonroot": true
  }
}
```
echo "## --------------------------------------------------------------------------------------- ##"




echo "## ======================================================================================= ##"
echo -e "\t\t Set flags on a single binary"
echo "## ======================================================================================= ##"
paxrat -s pm -b /usr/lib/iceweasel/iceweasel



echo "## ======================================================================================= ##"
echo -e "\t\t ## Set all flags from a config file:"
echo "## ======================================================================================= ##"
paxrat -c paxrat.conf



echo "## ======================================================================================= ##"
echo -e "\t\t ## Test to make sure the provided config file is valid:"
echo "## ======================================================================================= ##"
sudo paxrat -c paxrat.conf -t


echo "## ======================================================================================= ##"
echo -e "\t\t ## Run in watcher mode:"
echo "## ======================================================================================= ##"
sudo paxrat -c paxrat.conf -w





echo "## ======================================================================================= ##"
echo " +-+-+- PaXrat
echo "## ======================================================================================= ##"
paxrat -s pm -b /usr/lib/iceweasel/iceweasel ____________ # Set flags on a single binary
paxrat -c paxrat.conf ___________________________________ # Set all flags from a config file
sudo paxrat -c paxrat.conf -t ___________________________ # Test to make sure the provided config file is valid
sudo paxrat -c paxrat.conf -w ___________________________ # Run in watcher mode
echo "## ======================================================================================= ##"




## ======================================================================================= ##
paxctld -c <config_file> __________	# the default is /etc/paxctld.conf
paxctld -d ________________________ # Make paxctld run as a daemon
paxctld -p <pid_file> _____________ # Specify the pid file to use when running in daemon mode
paxctld -q ________________________ # Enable quiet mode to suppress all syslogs from paxctld
## ======================================================================================= ##

## ======================================================================================= ##
gradm -V -L -F ____________________ # Toggle full learning mode
gradm -C __________________________ # Perform  a  check  of the RBAC policy
gradm -R __________________________ # Reload the RBAC system
gradm -E __________________________ # Enable the RBAC system
## ======================================================================================= ##





$ sudo paxctl ‐c /usr/lib/firefox/firefox
$ sudo paxctl ‐m /usr/lib/firefox/firefox
$ sudo paxctl ‐c /usr/lib/firefox/plugin‐container
$ sudo paxctl ‐m /usr/lib/firefox/plugin‐container




echo "## ======================================================================================= ##"
echo -e "\t\t :"
echo "## ======================================================================================= ##"









/etc/grsec2/learn_config
policy








To use the learning mode, activate it using gradm:
gradm ‐F ‐L /etc/grsec/learning.log

gradm ‐F ‐L /etc/grsec/learning.log ‐O /etc/grsec/learning.roles



mv /etc/grsec/learning.roles /etc/grsec/policy
chmod 0600 /etc/grsec/policy






/etc/sysctl.d/05‐grsecurity.conf



chmod +x checksec.s
PENETRATION
# ./checksec.sh --version
SECURIT


./checksec.sh --kernel


cat checksec.sh | grep "CONFIG_" | sed 's/.*\(CONFIG_[^=]*\).*/\1/g'







getfattr ‐n user.pax.flags



setfattr ‐n user.pax.flags ‐v "emr"



paxctl -v /usr/bin/vi


paxctl -c /usr/bin/vi


paxctl -v /usr/bin/vi




echo 0 > /proc/sys/kernel/grsecurity/chroot_caps
echo 0 > /proc/sys/kernel/grsecurity/chroot_deny_mount


paxctl -v /opt/google/chrome/chrome
paxctl -v /opt/google/chrome/nacl_helper
paxctl -v /opt/google/chrome/chrome-sandbox

paxctl -Cm /usr/bin/nodejs




/usr/lib/jvm/java-6-openjdk-amd64/jre/bin/java






pidof inetd | xargs pspax -p




To check if a library has executable stack enabled, run:
execstack -q /usr/lib/libcrypto.so.0.9.8


To query the status of all libraries in your system, run:
find /lib /usr/lib -name '*.so.*.*.*' | xargs execstack



