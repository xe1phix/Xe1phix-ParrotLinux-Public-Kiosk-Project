## Super Hot
cd -              # go to previous directory.

## Copy public key to servers that I want to be accessible to connects to me
# server1 should be configured via ~/.ssh/config like
# Host server1
#	  HostName 10.0.2.4
#	  User sabahtalateh
#	  Port 22
ssh-copy-id -i id_rsa.pub server1
ssh-copy-id -i id_rsa.pub user@192.168.1.1

## Set me as owner for brew
sudo chown -R $(whoami) /usr/local/Cellar /usr/local/bin


## Find large files
find / -size +20000k -exec ls -lh {} \;
# Find files in /boot, larger then 10M.
find /boot -maxdepth 1 -size +10M -exec du -h {} \;
# Only links, dirs, files.
find / -type (l|d|f) 
# Only pdf files.
find -name '*.pdf' 

## Pipe.
# Make named pipe.
mkfifo fifo1 

## Tee
# Redirect output of ls to f1 and f2
ls | tee f1 f2 

## Disk usage.
# Show size of current directory.
du -sh .
# Show disk free space
df -h 

## Archiving.
# Compress.
tar -cvf /where/to/put/it.tar /what/to/compress 
gzip /where/to/put/it.tar
bzip2 /where/to/put/it.tar
# With gzip.
tar -czvf /where/to/put/it.tar.gz /what/to/compress
# With bzip.
tar -cjvf /what/to/compress /where/to/put/it.tar.bz2
# View archive contents.
tar -tf /what/to/check 
# Decompress into current directory.
tar -xvf /tmp/sabahtalateh.tar
# Decompress into specific directory.
tar -xvf /tmp/sabahtalateh.tar -C ./test/

## CPIO.
### Create.
find -name '*.pdf' | cpio -o > /tmp/pdf.cpio
### Extract to current dir.
cpio -id < ../initramfs-3.10.0-693.el7.x86_64.img

## Time measure.
# Measure time that command was executing.
time tar -czvf /what/to/compress /where/to/put/it.tar.gz

## Permissions.
chmod u=rwx,g=rw,o=rw     # In human readable way.
chmod u+rx,g+x,o+x,a-r file1 # Add and remove permission for user(u)/group(g)/others(o)/all(a).
chmod u+s file1           # add sticky bit (effective user id will be set to a file owner, permissions for executor will be set to owners permissions).
id -u                     # User id.
id -un                    # Username.
id -g                     # Group id.
id -gn                    # Group name.
id -Gn                    # All user groups.
chgrp wheel file1         # Change file group.
newgrp wheel              # Change users primary group.
cp -a file1 /root/file1a  # Copy with saving permissions.

## Misc.
# File type.
file filename
# File statistics.
stat filename

## Script
# This command will write all the output in typescript file.
script
# To make other user to see you cammnds make a pipe and tight it to script command.
# [user 2] will see all the output of [user 1]
# [user 1]
mkfifo /tmp/mypipe
script -f /tmp/mypipe
# [user 2]
cat /tmp/mypipe

## SSH
# Permanently ssh-add on MacOS
#https://apple.stackexchange.com/questions/48502/how-can-i-permanently-add-my-ssh-private-key-to-keychain-so-it-is-automatically
# Screen
#http://aperiodic.net/screen/quick_reference
screen
screen -S server1 ssh server1
# C-a " - list screens
# C-a : - run command

## RPM and Yum (RedHat)
rpm -qf $(which vim) # Show in which package some file belongs to.
rpm -ql $(which vim) # show package files.
rpm -qc $(which vim) # list config files.

## DPKG and APT (Debian)
dpkg -l                       # list packages
dpkg -L vim                   # list files associated with package
dpkg -s vim                   # package status (including config files). vim is a package name, not a path.
dkpg -S /etc/vim/vimrc.tiny   # show package that /etc/vim/vimrc.tiny is belongs to
apt-cache search postfix      # search packages that contains postfix in name or description
apt-cache pkgnames postfix    # show packages tha contains postfix in package name

## Messaging
write $USERNAME # write message to $USERNAME
wall < message  # write message to all users
mesg            # show messaging
mesg [y|n]      # disable/enable messaging for current user

## Powering off
halt      # Stop CPU but leave it turned on.
poweroff  # Power OFF.
reboot    # Reboot.
runlevel  # Show current runlevel.
who -r    # Show current runlevel.
systemctl isolate [graphical.target|multi-user.target|rescue.targer]  # change runlevel.
systemctl set-default [graphical.target|multi-user.target]            # set default runlevel.

## GRUB
vim /etc/default/grub                   # Edit grub settings.
grub2-mkconfig -o /boot/grub2/grub.cfg  # Regenerate grub config.
# restore lost root password https://app.pluralsight.com/player?course=lfcs-linux-operation-essentials&author=andrew-mallett&name=lfcs-linux-operation-essentials-m3&clip=2

## Processes.
ps -e           # all the processes.
ps axu          # list all the processes in user oriented format.
ps -elf         # long and full listing of all the processes.
ps -e --forest  # list all processe in tree view. 
ps -f           # show all the columns.
ps -F           # show all the columns.
# UID        PID  PPID  C    SZ   RSS PSR STIME TTY          TIME CMD
# sabahta+  1469  1468  0 28848  2112   0 03:35 pts/1    00:00:00 -bash
# sabahta+  1702  1469  0 37759  1708   0 03:58 pts/1    00:00:00 ps -F
# RSS - Resident Set Size - How much memory program takes in operative memory.

ps -l                     # long listing.
ps -ly                    # long listing with RSS.

ps -p1 -f                 # full listing of process with PID=1.

pstree -G                 # list processes as tree with (draw pretty on Linux). 
pstree -g 2               # list processes as tree with (draw pretty on MacOS).

kill -l                   # list kill signals.
kill [-15|-term|-sigterm] # terminat the process.
kill [-9|-kill|-sigkill]  # kill (more hard then term) the process.

# Pgrep.
pgrep sshd              # look for the processes with sshd in name.
ps -F -p $(pgrep sshd)  # show information about sshd processes.
ps -p 4052              # show information about 4052 process.

# Table of processes.
top

sleep 1000&                 # Run process in background.
sleep 1000 => Ctrl+Z        # Suspend program (it will not be executing).
sleep 1000 => Ctrl+Z => bg  # Bring program to background.
sleep 1000 => Ctrl+Z => fg  # Bring program to foreground.

## Nice.
# 19 - Lowest priority, -20 - Highest.
# From -20 to -1 can be set only as root.
nice -n 19 sleep 1000 &   # Run process with nice=19.
renice -n 10 -p 2113      # Change priority of 2113 process to 10.
sudo vi /etc/security/limits.conf # Configure default nice value and other useful things.

## Performance
free                  # print free memory.
free -m               # print free memory in megabytes.
pmap PID              # print memory map for process.
pwdx PID              # print working directory for process.
w                     # show who logged in.
lscpu                 # information about CPU.
cat /proc/uptime      # show uptime total working time and idle time.
watch -n 4 uptime     # watch uptime every 4 seconds.
tload                 # view CPU utilization.
top -b -n 1 > file1   # record top output to file1.
vmstat                # virtual memory statistic.
vmstat 5 3            # collect information 3 times with 5 seconds delay.

## Sysstat
# 1. Install sysstat on your distributive.
cat /etc/cron.d/sysstat         # sysstat cron configuration.
cat /etc/sysstat/sysstat        # sysstat config (Debian).
cat /etc/sysconfig/sysstat      # sysstat config (RedHat).
systemctl start sysstat         # don't forget to start it.
systemctl enable sysstat        # and ebable.
# IOStat
iostat -m 1 4                   # 4 times, 1 second gap.
pidstat -p PID 1 4              # statistic about process.
mpstat -P ALL 1 4               # stat about all processes.
sar -u                          # print CPU utilization (if systat was installed and configured).
sar -r                          # print memory utilization.
sar -b                          # disk io.
sar -n DEV                      # network statistic.
sar -q                          # load avg.
sar -s 15:10:00 -e 15:30:00     # sar in interval.
sar -s 15:10:00 -e 15:30:00 -f /var/log/[sysstat|sa]/sa4 # sar in interval from file.

## Shared libraries.
ldd /bin/grep                   # list shared libraries that are user by the program.
ldconfig -p                     # print shared libraries.
ls -l /etc/ld.so.cache          # ld cache.
ldconfig                        # update ld cache.

df -h                           # disk free space in human readable format.

## Scheduling
# Cron
vi /etc/crontab                 # system crons.
crontab -l                      # list user crons.
crontab -e                      # edit.
crontab -r                      # remove crontab from current user.

at noon                         # ad task to at daemon.
atq                             # show at queue.
atd                             # delete task from at queue.

## Auditing
lastlog                         # list all users and last login time.
lastlog | grep -v "Never"       # exclude never logged in users.
last -n 10                      # show last 10 logged in users.
last user -n 10                 # show last 10 logins for user.
lastb                           # show bad logins.

grep sudo /var/log/auth.log     # look for sudo in auth.log (Debian)
grep sudo /var/log/secure*      # look for sudo in secure files (RedHat)
awk '/sudo/ {print $0} ' secure # print lines with `sudo` from secure.
awk '/sudo/ {print $5, $6} ' secure # print 5 and 6 field with `sudo` from secure.

## Rsyslog
1. vim [/etc/rsyslog.conf(RedHat)|/etc/rsyslog.d/50-default.conf(Debian)] 
2. # add local1.info /var/log/sabah
3. # systemctl restart rsyslog
4. logger -p local1.warn "Test Message"
5. tail /var/log/messages
6. tail /var/log/sabah

## Logrotate
# runs with anacron (/etc/anacrontab)
cat /etc/cron.daily/logrotate   # view logrotate script
less /etc/logrotate.conf        # view logrotate.conf
# add to /etc/logrotate.conf
#/var/log/sabah {
#    missingok
#    notifempty
#    size 10
#    compress
#}
logrotate /etc/logrotate.conf
gunzip /var/log/sabah-YYMMDD.gz

## Journalctl
journalctl -n 10                # list last 10 entries
journalctl -f                   # fallow 
journalctl -b                   # information since last boot

mkdir /var/log/journal          # make dir for journal
vim /etc/systemd/journald.conf  # edit config

journalctl -u sshd.service      # show logs from sshd.
journalctl --since "2018-03-05 12:00:00"  # since time.
journalctl --since "10 minutes age"
journalctl --list-boots         # list boot journals.
journalctl -b -1                # view previous boot journal.


## SELinux
ls -Z                           # shows se linux prmissions.
getenforce                      # print enforcing mode.
sestatus                        # SE status.
cat /etc/selinux/config         # SE config.
setenforce [0|1]                # go to [permissive|enforcing] mode.
id -Z                           # print user SE information.
ps -Z                           # print processes with SE info.
ps -Z -p $(pgrep sshd)
#LABEL                             PID TTY      STAT   TIME COMMAND
#system_u:system_r:sshd_t:s0-s0:c0.c1023 1108 ? Ss     0:00 /usr/sbin/sshd -D
#system_u:system_r:sshd_t:s0-s0:c0.c1023 1247 ? SNs    0:00 sshd: sabahtalateh [priv]
#unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 1250 ? SN   0:00 sshd: sabahtalateh@pts/0


## Dependecy managment (RedHat).
yum install httpd               # Then press d for only download package.
tree /var/cache/yum             # You will see downloaded packages.
cd /path/to/packages            # go to directory with packages.
rpm -qa                         # list all installed packages.
rpm -qi nmap                    # information about nmap package.
rpm -ql nmap                    # list files in package.
rpm -qpi httpd-2.4.6-67.el7.centos.6.x86_64.rpm # show package info from package file.
rpm -qpl httpd-2.4.6-67.el7.centos.6.x86_64.rpm # list files in package.
rpm -e nmap                     # remove nmap package.
rpm -qf /etc/hosts              # show what package /etc/hosts is belongs to.
rpm -V setup                    # verify package.

yum install bash-completion     # install.
yum info bash-completion.noarch # print information about the package.
yum version                     # version of yum.
yum remove nmap                 # remove nmap.
yum deplist nmap                # show dependencies list for nmap.
yum list installed              # list installed packages.
yum list available              # list all packages available through the repos.

yum repolist                    # list enabled repos.
yum repolist all                # list all repos.


## Dependecy managment (Debian).
dpkg -l                         # list installed.
dpkg -L vim                     # list file associated with vim package.
dpkg -s vim                     # status of vim package, information about it.
dpkg -S $(realpath $(which vim))# show package that vim binary file is belongs to.
ls /var/cache/apt/archives/     # list downloaded archives.
dpkg -r package                 # remove package from system.
dpkg -i lalala.deb              # install deb package.

apt list --installed            # list installed packages.
apt-cache search ^postfix       # search for package with name in cache.
apt-cache pkgnames postfix      # search postfix in packagenames.
apt-get remove postfix          # remove postfix, save settings.
apt-get purge postfix           # remove postfix and its settings.
dpkg-reconfigure postfix        # reconfigure postfix.

vim /etc/apt/sources.list       # repos list.


## Services.
systemctl enable httpd          # start service on loading.
systemctl status httpd          # service status.

### Users and Groups.
cat /etc/passwd                 # list users and (not often) passwords.
getent passwd                   # same as previous on local env. get data from passwd database if OpenLDAP or Active Directory are used.
less /etc/nsswitch.conf         # config file wich is used to get getent knowing from where to get information.
getent group                    # list groups.
getent networks                 # list networks.
getent services                 # list all known services and their ports.

# when login with `su -` or `su -l` the tem will load login scripts in /etc/ptofile, ~/.bash_profile, ~/.bashrc, /etc/bashrc
# when using `su` with no flags then just ~/.bashrc and /etc/bashrc loaded
# when exiting bash, the ~/.bash_logout will be executed.

echo $PS1                       # see the console prompt.
# [\u@\h \W]\$
# [sabahtalateh@server1 etc]$
# change case in vim - `~`

/etc/skel                       # contain template for user's home directory.

## User managment.
id                              # show information about logged in user.
id root                         # show information about root account.
id -g                           # show user group id.
id -gn                          # show user group name.
id -G                           # show all user groups.
id -Gn                          # show all user group names.

sudo useradd -m user1           # add user1 with home directory creation.
tail -n 1 /etc/passwd           # see added user in passwd file, on last line.
# user1     : x                                                 : 1001   : 1002     : user 1:   /home/user1 :/bin/bash
# username  : password (x means that password is in /etc/shadow): user id: group id : fullname: home:       : default shell
sudo useradd -N user2 -g users -G adm # -N - no private group, -g - primary group, -G - secondary groups.
sudo useradd user3 -G adm -s /bin/sh  # -s set default shell.

# Set users password.
sudo passwd user1               # set password for user1.
sudo tail -n 1 /etc/shadow      # view last password.
# user3    : !!                    : 17603                                       : 0                    : 99999                  : 7                                   :::
# username : password(!! - invalid): days since 01.01.1970 (password last change): days to keep password: change every 99999 days: warning in 7 days before expiration :

echo 'user1:passwd1' | sudo chpasswd  # change password for user1.

## Password age
chage -l username               # show info about user1 password. Human readable info from /etc/shadow
# Last password change					: Mar 08, 2018
# Password expires					: never
# Password inactive					: never
# Account expires						: never
# Minimum number of days between password change		: 0
# Maximum number of days between password change		: 99999
# Number of days of warning before password expires	: 7

sudo pwunconv                   # place passwords in /etc/passwd instead of /etc/shadow
sudo pwconv                     # place password into the /etc/shadow
sudo chage -M 40 user1          # set days between password change to 40.
sudo passwd -l user1            # lock user1 password, user could not login.
sudo passwd -u user1            # lock user1 password, user could not login.

## Account defaults
less /etc/login.defs            # default settings for users.
sudo useradd -D                 # show user defaults.
sudo useradd -Ds /bin/bash      # modify default shell.
sudo vim /etc/default/useradd   # edit useradd defaults.

sudo usermod -c "User One" user1  # modify user1 fullname.
cshs -l                         # list available shells (RedHat).
cat /etc/shells                 # list available shells (Debian).
chsh -s /usr/bin/zsh user1      # change shell for user1.
sudo userdel -r user1           # remove user with all its directories.
sudo find /home -uid 1002 -delete # find and delete all files that was owned by the user with UID=1002.

## Groups.
grep -e 'sabahtalateh' /etc/group # all the user that is in sabahtalateh group.
newgrp sudo                     # change primary group of current user to sudo group.
sudo groupadd sales             # add sales group.
grep sales /etc/group
# sales:x:1002:
# x - group password is shadowed.
sudo cat sales /etc/gshadow     # list group passwords.
sudo usermod -G sales sabahtalateh # change primary group of sabahtalateh to sales.
sudo usermod -a -G sales sabahtalateh # add sabahtalateh to sales group (need to relogin).
sudo usermod -G sales,sabahtalateh sabahtalateh # set sabahtalateh groups to sales and sabahtalateh (need to relogin).
sudo gpasswd -M sabahtalateh,root sales # add sabahtalateh and root to sales group (need relogin).
chmod g+s /some/dir             # when some file created in directory then its group will be set as the directory group.
umask XXX                       # don't forget to set umask to set default permissions on file when it's creating.
sudo gpasswd adm                # set the adm group password, when executing newgrp adm then password will be prompted.


## Pluggable Authentication Modules.
ls /etc/pam.d/                  # show pam files.


## User limits.
ulimit -a                       # show all user limits.
ulimit -u                       # show user proceses limit (not more that N processes can be running simultaniously).
ulimit -u 10                    # limit user processes to 10.
netstat -ltn                    # show -l(listening), -t(tcp), -n(numeric) ports.


## Storage managment.
lsblk                           # list block devices.

## Show kernel modules.
uname -r                        # show kernel release version.
# 4.13.0-37-generic for example, with that open /boot/config-4.13.0-37-generic
less /boot/config-4.13.0-37-generic # to show kernel config.
grep ACL /boot/config-$(uname -r)   # grep acl info from kernel config.
sudo tune2fs -l /dev/sda1 | grep -i acl # show whether or not /dev/sda1 has acl support.
getfacl file1                   # get acl for file1.
setfacl -m d:o:--- test-acl     # set acl -m - modify, d - default, o - others, --- - no read, write, execute. acl rule will be applied for all the directory content.
setfacl -d -m u:sabahtalateh:rw test-acl  # -d - default, u - user.


##### Networking #####
# show network interfaces 
ifconf [interface_name]         # OBSOLETE! show config of interface or all interfaces.
ip addr                         # show information abot interfaces (ip addresses).
ip route                        # show routing table.
ip neigh                        # show neighbours.
sudo ip netns add development   # add new network namespace.
ip netns                        # show network namespaces.

## Hostnames.
hostname -f                     # show full hostname of the machine.
uname -n                        # name of node (same as host).
hostnamectl                     # detailed information about host.
hostname centos7                # change hostname to centos7 (transient).
hostnamectl set-hostname centos72.sabahtalathe.com  # set hostname (permanent).
cat /etc/hostname               # view hostname.
hostnamectl set-hostname "centos'72.sabahtalathe.com" # set pretty hostname (with apostrophe or other illegal symbol).
hostnamectl                     # will show pretty name in pretty section.
cat /etc/machine-info           # will show the pretty name.

# dig - resolve hostnames.

dig www.pluralsight.com @8.8.8.8  # dig wit dns 8.8.8.8
dig +short www.pluralsight.com @8.8.8.8 # +short - only ip addresses for www.pluralsight.com
dig +short pluralsight.com @8.8.8.8 MX  # MX - Mail Exchange - Show entries for mail exchange entries.


## Time
date                            # shows date and time.
hwclock                         # hardware clock.
date --set="20170101 12:03"     # set date and time.
hwclock --hctosys               # synchronize hardware clock to system time.
hwclock --systohc               # synchronize system time to hardware clock.
timedatectl set-time "2007-09-01 22:00" # set time and date.
# Failed to set time: Automatic time synchronization is enabled
timedatectl set-ntp false       # disable ntp.

## IP Addresses.
ip addr show                    # show ip addresses.
ip -4 addr show                 # show only IPv4 addresses.
ip -4 addr show enp0s8          # show IP addresses for enp0s8 interface.
ip -6 addr show                 # show only IPv6 addresses.
ip addr add 172.17.67.3/16 dev enp0s8 # add IP to enp0s8 interface.
systemctl status NetworkManager # status of network manager.
nmcli connection show           # show connections.
nmcli connection show enp0s8    # show information about connection.
nmcli -p connection show enp0s8 # show prettified information about connection.
nmcli connection add con-name home ifname enp0s8 type ethernet ip4 192.168.99.4 gw4 192.168.99.1  # add connection.
nmcli connection down enp0s8    # down connection.
nmcli connection up home        # up connection after that you shoud conect via new IP addres (192.168.99.4).

systemctl status network        # status of standard network manager.
cd /etc/sysconfig/network-scripts # directory with network scripts.
# To not to control an interface by NetworkManager add NM_CONTROLED=no to /etc/sysconfig/network-scripts/enp0s8
# network is using more often on servers, NetworManager (nmcli) more often on desktops or laptops.

ip route show                   # show ip route table.
#169.254.0.0/16 dev enp0s8 scope link metric 1002                       - machine take an address from this subnet when there is no DHCP server.
#192.168.99.0/24 dev enp0s8 proto kernel scope link src 192.168.99.101  - network we connected to.

route                           # old command to show route table.

netstat -r                      # routing table.
netstat -rn                     # addresses rather than the names in subnets.

ip route add default via 192.168.99.102 # add default route via 192.168.99.102.
# to add gateway edit /etc/sysconfig/network-scripts/ifcfg-enp0s8
# Add two strings.
# DEFROUTE="yes"
# GATEWAY="192.168.99.102"

### To use CentOS as a router add to /etc/sysctl.conf line
# net.ipv4.ip_forward=1, after that reread config with
sysctl -p                     # reread sysctl config.
# check if it enabled with 
cat /proc/sys/net/ipv4/ip_forward
# stop firewall
systemctl stop firewalld.service 
iptables -L                   # list IP Tables (should be empty if firewall is stopped).
iptables -t nat -L            # IP Tables for NAT.
iptables -t nat -A POSTROUTING -o enp0s3 -j MASQUERADE  # add nat rule to mask packets on enp0s3 (external network card).

## Firewaling.
firewall-cmd --state          # check firewall state.
systemctl start firewalld     # start firewall.
firewall-cmd --get-default-zone # get default zone.
firewall-cmd --get-active-zones # get active zones.
firewall-cmd --get-zones      # get all zones.
firewall-cmd --permanent --zone=public --remove-interface=enps0s3 # remove interface from zone.
firewall-cmd --permanent --zone=external --add-interface=enps0s3  # add interface to external zone.
# Or edit vim /etc/sysconfig/network-scripts/ifcfg-enp0s8, set ZONE to prefered zone.
firewall-cmd --set-default-zone=external  # set default zone.
firewall-cmd --list-all       # list everything in default zone.
firewall-cmd --list-all --zone=external # list everything in extarnal zone.
firewall-cmd --permanent --remove-service=ssh --zone=external # deny access via ssh to external zone.
firewall-cmd --list-services --zone=internal  # list enabled services from internal zone.

ls /usr/lib/firewalld/services/ # list services that can be controlled by firewall.
firewall-cmd --permanent --new-service="puppet" # create new service in /etc/firewalld/services.
restorecon puppet.xml         # restore SELinux context for newly created service.
chmod 644 puppet.xml          # set correct priviliges to the file.
# <?xml version="1.0" encoding="utf-8"?>
# <service>
#         <short>Puppet</short>
#         <port protocol="tcp" port="443"/>
#         <port protocol="tcp" port="8140"/>
# </service>

firewall-cmd --permanent --remove-masquerade --zone=external  # disable masquareding packages (don't allow to go to internet using this server as a router).
firewall-cmd --permanent --add-masquerade --zone=external # enable masquerading (make server network address translation router).

## IP tables.
iptables -L                   # list IP tables.
iptables -nvL                 # show extended. With interfaces names.
# if the firewall is disabled it looks like this.
#Chain INPUT (policy ACCEPT)
#target     prot opt source               destination
#
#Chain FORWARD (policy ACCEPT)
#target     prot opt source               destination
#
#Chain OUTPUT (policy ACCEPT)
#target     prot opt source               destination

# And we can save this config to file.
iptables-save > fwoff         # save config of the firewall.
iptables -A INPUT -i lo -j ACCEPT # accept trafic from lo interface.
# (Allow any ESTABLISHED or RELATED trafic, that was initiated on the machine).
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT  # allow trafic to return back to the machine (should be set almost everytime).
iptables -A INPUT -p tcp --dport=22 -j ACCEPT # allow to connect to this machine via ssh (or any protocol uses 22 port) (dport - destination port).
iptables -A INPUT -j DROP     # drop everything except that was marked as ACCEPT.
iptables -A FORWARD -j DROP   # do not forward any packages (do not work as a router).
iptables-restore < fwoff      # restore firewall settings.
iptables -F                   # remove (flush) all rules.
yum install -y iptables-services  # install iptales-services.
vim /etc/sysconfig/iptables   # iptables rules.
vim /etc/sysconfig/iptables-config  #service config.
# Change IPTABLES_SAVE_ON_STOP and IPTABLES_SAVE_ON_RESTART from no to yes and 
# restart firewalld (systemctl disable firewall, systemctl stop firewall, systemctl enable iptables.service, systemctl start iptables.service).
iptables -I INPUT 1 -p tcp --dport 80 -j ACCEPT # insert rule to 1-st position.
# then on any restart (systemctl restart iptables.service) rules will be saved (to /etc/sysconfig/iptables).

## Tunneling.
# Create ssh tunnel (any request to localhost:8080 will be encrypted via ssh an redirected to server2:80).
ssh -f -L 8080:localhost:80 root@server2 -N # redirect packages from localhost:8080 to server2:80 (-f - background) (-L listen ports) (-N - not run any command). 
# After work close the tunnel.
ps -ef | grep ssh
# root       976     1  0 18:17 ?        00:00:00 /usr/sbin/sshd -D
# root      1087   976  0 18:17 ?        00:00:00 sshd: sabahtalateh [priv]
# sabahta+  1090  1087  0 18:17 ?        00:00:00 sshd: sabahtalateh@pts/0
# sabahta+  1121     1  0 18:17 ?        00:00:00 ssh -f -L 8080:localhost:80 sabahtalateh@server2 -N
# sabahta+  1165  1091  0 18:20 pts/0    00:00:00 grep --color=auto ssh
kill 1121                     # close the tunnel.

## Open VPN.
sudo yum install -y epel-release        # install epel-release package.
sudo yum install -y openvpn easy-rsa    # install required packages.
systemctl stop firewalld                # stop firewall.
iptables -L -t nat                      # check that nat table is empty.
iptables -t nat  -A POSTROUTING  -o enp0s3 -j MASQUERADE  # Masquerade packages that came from the internet (enp0s3 - card that aimed to the internet).
cp /usr/share/doc/openvpn-2.4.5/sample/sample-config-files/server.conf /etc/openvpn/  # copy sample config.

# Open the server config.
vim /etc/openvpn/server.conf            # server config file.
# dh dh2048.pem                         # key path.
# uncomment this string push "redirect-gateway def1 bypass-dhcp"
# change `push "dhcp-option DNS ..."` to `"dhcp-option DNS 8.8.8.8"` and `"dhcp-option DNS 8.8.4.4"` (google dns servers) and uncomment them.
# uncomment fallow strings
# user nobody
# group nobody
#
# Make directory for keys
mkdir -p /etc/openvpn/easy-rsa/keys/    # make directory for keys.
cp -rf /usr/share/easy-rsa/3.0/* /etc/openvpn/easy-rsa/ # copy easy-rsa scripts.
# Download easy-rsa variables example.
wget -P /etc/openvpn/easy-rsa/ https://raw.githubusercontent.com/QueuingKoala/easyrsa3/master/easyrsa3/vars.example
# rename it to vars.
mv vars.example vars
./easyrsa init-pki                      # init pki structure.
./easyrsa build-ca                      # build certificate authority.
./easyrsa gen-dh                        # generate diffie hellman key.

https://notessysadmin.com/quickstart-openvpn-server
https://serveradmin.ru/nastroyka-openvpn-na-centos-7/


## Monitoring
tracepath -n 192.168.56.101             # trace network path to some domain or ip address.
ip link show                            # show interfaces with MAC addresses.
ip link show enp0s8                     # show info for interface enp0s8.
ip -s link show enp0s8                  # show statistic for interface (packages accepted/lost etc..).
netstat -tln                            # show ports (-t - tcp) (-l - listening) (-n - port number instead of service name)
netstat -i                              # interfaces statistic.
netstat -s                              # stat by protocols.
# With sysstat installed you can view the network information.
sar -n DEV                              # -n - network, DEV - devices, by default reading will make from todays sa file.
sar -n DEV 1 10                         # read 10 times witj 1 second gap.
sar -n DEV 1                            # read every 1 second.
nmap scanme.nmap.org                    # scan for open ports.
nmap --iflist                           # list ip addresses and routing table.


### Services.
ps -fp 1                                # list full process info for process with PID=1.
systemctl mask sshd                     # prevent server from starting (symlink to /dev/null will be created for this service).

## BIND.
yum install -y bind bind-utils          # install bind and utils.
systemct start named                    # start named.
## Basic configuration of bind is caching only server.
netstat -tln | grep 53                  # show 53 ports.
# 53 - DNS Server. 953 - For controlling DNS Server.
#tcp        0      0 127.0.0.1:53            0.0.0.0:*               LISTEN
#tcp        0      0 127.0.0.1:953           0.0.0.0:*               LISTEN
#tcp6       0      0 ::1:53                  :::*                    LISTEN
#tcp6       0      0 ::1:953                 :::*                    LISTEN

dig www.pluralsight.com @127.0.0.1      # perform lookup on the local machine (@127.0.0.1).

# to configure dns server to listen not only on localhost do this.
vim /etc/named.conf                     # named config file.
# change these values
# listen-on port 53 { 127.0.0.1; };
# listen-on-v6 port 53 { ::1; };
# to
# listen-on port 53 { any; };     # listen any interface on IPv4.
# listen-on-v6 port 53 { none; }; # not listen interfaces on IPv6
named-checkconf                         # check if config is ok.
# to allow other machines to user DNS server do this.
vim /etc/named.conf                     # named config file.
# add your subnet here 
# allow-query     { localhost; 192.168.99.0/24; localnets; }; 
# (192.168.99.0/24 - subnet that I want to allow to use my DNS).
# (localnets) - all the local networks that this machine is connected to.

# to enable your DNS to be a forwarder for the other DNS servers do this.
vim /etc/named.conf                     # named config file.
# add these lines in the options section.
# forwarders      { 8.8.8.8; 8.8.8.4; };      # list of servers that we will forward requests to.
# forward only;                               # don't try to lookup by ourselfs.

## Zones.
# To add zone config to BIND add such configuration to /etc/named.conf
#zone "example.vm." {
#        type master;             # master read-write copy, slave - read-only copy.
#        file "db.example";       
#        allow-update { none; };  # for not dynamic dns.
#};

## To create DNS zone do this.
cd /var/named
cp named.empty db.example
chgrp named db.example

# Zone config example.
#$TTL 3H                ; How long to cache names.
#$ORIGIN example.vm.    ; will be appended to the end of name that is not ended with dot.
#; example.vm. - Start of Authority name, server1.example.vm. - current machine name, root.example.vm. = root@example.vm. (mail severv name)
#example.vm.     IN SOA  server1.example.vm. root.example.vm. (
#                                        1       ; serial - should be changed on every file edit.
#                                        1D      ; refresh - sync with slaves every 1 day.
#                                        1H      ; retry - retry every hour if sycn fails.
#                                        1W      ; expire - if for 1 week not sync the expire.
#                                        3H )    ; minimum -  TTL (if not specified with $TTL variable).
#example.vm.     NS      server1.example.vm.    ; zone name and it's name server.
#server1         A       192.168.99.100         ; name in zone and machine IPv4 ($ORIGIN will be appended to server1 as it does not ends with a dot).
named-checkzone example.vm. db.example      # check if zone settings are correct.
systemctl restart named

cat /var/named/data/named.run               # if zone was loaded the you will see in this file such string.
#zone example.vm/IN: loaded serial 1

# Ater all you can dig your new zone from the same machine.
dig server1.example.vm @127.0.0.1           # or from any other.
dig -t NS example.vm @127.0.0.1             # get Name Server records

## Accessing DNS with python.
yum install -y python-dns                   # python api to access dns.


## SELinux
yum -y install samba*                       # Set up all the samba related packages.
vim /etc/samba/smb.conf                     # Edit samba settings.
# Add this
#[share]
#        path = /share
#        writable = yes
# Don't forget to set directory permissions to 1777 (1 - Only owner can delete).
testparm                                    # Test configuration.
systemctl start nmb smb                     # Start samba.
systemctl enable nmb smb
smbpasswd -a root                           # Add samba password for root.
auditctl -w /share/ -p rwa -k smb_access    # Add rule to watch shred folder.
smbclient //localhost/share [password]      # Login to samba.
ls                                          # Try to list files on samba server, you will get an error.
ausearch -i -k smb_access                   # Search through the log what happens.
#type=SYSCALL msg=audit(1524612925.478:282): arch=c000003e syscall=257 success=no exit=-13 a0=ffffffffffffff9c a1=55832dcd2ae0 a2=90800 a3=0 items=1 ppid=1385 pid=2149 auid=4294967295 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=(none) ses=4294967295 comm="smbd" exe="/usr/sbin/smbd" subj=system_u:system_r:smbd_t:s0 key="smb_access"
yum install -y policycoreutils-python       # Install package to manage politics.
semanage fcontext -a -t samba_share_t '/share(/.*)?'  # Change samba directory context.
restorecon -R /share                        # Restore context with previously created rule.

chcon -R -t samba_share_t /share            # Or you can use chcon command.

# also you can use sebools to manage selinux access.
getsebool samba_export_all_rw               # samba_export_all_rw --> off
setsebool -P samba_export_all_rw 1          # samba_export_all_rw --> on
systemctl restart smb

yum install -y setools-console              # install SETools
semanage permissive -a smbd_t               # Add samba to list of permissive domains.

## Virtualization.
yum history info                            # Show last yum transaction.
yum history undo {Transaction ID}           # Undo transaction.
yum history info {Transaction ID}           # Full description of transaction.

## Capture traffic
tcpdump -A -vvvv -s 9999 -i eth0 port 80    # -A Print each packet in ASCII. -vvvv - verbose. -s 9999 - len of packets to display.













