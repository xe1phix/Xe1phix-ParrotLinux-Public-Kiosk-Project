--------------------------------------------------------------------------------------------------------------------
#Cleaning the Yum Cache

yum clean all #clean all cached information
yum clean packages #remove cached packages only
yum clean metadata #delete metadata for each enabled repository
yum clean headers

#the message “Metadata file does not match checksum” during a Yum operation, clearing the metadata from the cache might not help
#adding the following line to /etc/yum.conf resolves the problem
# vi /etc/yum.conf
http_caching=none

#insufficient space in download directory /var/cache/yum/rhel-x86_64-server-6/packages
#As the /var filesystem where yum cache is located is full and there is no disk space for yum to download the system updates, the above error will be shown.
#The yum cache location is configured in /etc/yum.conf file as cachedir option in the [main] section and can be changed:
$ cat /etc/yum.conf 
[main]
cachedir=/var/cache/yum/$basearch/$releasever
--------------------------------------------------------------------------------------------------------------------
#disable root user

sudo passwd -l root #lock the password for the root user
sudo usermod -L root #lock the password for the root user
sudo passwd -d root # remove the password of the account,can not unlock a locked account if it doesn't have any password

#Enable Root Login
sudo passwd root #set a new password for the account
sudo passwd -u root #unlock the root user,unlock the password
su root
------------------------------------------------------------------------------------------
#disable root account ,change root user’s shell
#only effective with programs that require a shell for user login, otherwise, sudo, ftp and email clients can access the root account.
#Before blocking access to the root account create an administrative account, capable of using sudo command to gain root user privileges

useradd -m -c "Admin User" admin
passwd admin
usermod -aG wheel admin    #CentOS/RHEL
su admin #switch to that account to block root access.

sudo vim /etc/passwd
root:x:0:0:root:/root:/sbin/nologin

usermod -s /usr/sbin/nologin root #Use the usermod command to set the default shell

/etc/nologin.txt #set a custom message,when root user logs in, gets the message “This account is currently not available.” 
------------------------------------------------------------------------------------------
#disable root account , disable root Login via console device (TTY)
# only affects programs such as login, display managers (i.e gdm, kdm and xdm) and other network services that launch a TTY
#Programs such as su, sudo, ssh, and other related openssh tools have access to the root account.
#Before blocking access to the root account create an administrative account, capable of using sudo command to gain root user privileges
#PAM module called pam_securetty, which permits root access only if the user is logging in on a “secure” TTY, /etc/securetty.
#emptying this file prevents root login on any devices attached to the computer system

sudo mv /etc/securetty /etc/securetty.orig #create an empty file
sudo touch /etc/securetty
sudo chmod 600 /etc/securetty
------------------------------------------------------------------------------------------
#disable root account, disable ssh root login
#only affects openssh tools set, programs such as ssh, scp, sftp is blocked from accessing the root account.

#enable ssh root access
$ sudo sed -i 's/PermitRootLogin no/PermitRootLogin yes/' /etc/ssh/sshd_config
$ sudo service sshd restart

#disable ssh root access
$ sudo sed -i 's/PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
$ cat /etc/ssh/sshd_config | grep PermitRootLogin
PermitRootLogin no
$ sudo service sshd restart

#troubleshooting sshd log
$ sudo journalctl -t sshd -f

sudo vim /etc/ssh/sshd_config #the directive PermitRootLogin and set its value to no
sudo systemctl restart sshd 
------------------------------------------------------------------------------------------
#disable root user access to a system, by restricting access to login and sshd services,via PAM

#add the configuration below in both files
auth    required       pam_listfile.so \
        onerr=succeed  item=user  sense=deny  file=/etc/ssh/deniedusers
	
sudo vim /etc/pam.d/login
sudo vim /etc/pam.d/sshd

sudo vim /etc/ssh/deniedusers #Add the user root
sudo chmod 600 /etc/ssh/deniedusers

--------------------------------------------------------------------------------------------------------------------
#Create a New Sudo User(CentOS)
adduser username
passwd username
usermod -aG wheel username #add the user to the wheel group.By default, on CentOS, members of the wheel group have sudo privileges
su - username # switch to the new user account

#verify if user is sudoer
sudo -l -U userjohndoe  #list user's privileges or check a specific command
sudo --validate / sudo -v #update the user's cached credentials, authenticating the user if necessary
sudo --list #print the list of allowed and forbidden commands for the user who is executing the sudo command
groups #verify if user is sudoer, member of wheel group
sudo whoami # returns root
--------------------------------------------------------------------------------------------------------------------
$ sudo cp /etc/pam.d/system-auth{,.orig} # copy file with extension .orig
--------------------------------------------------------------------------------------------------------------------
/var/log/secure #failed SSH sessions are recorded
--------------------------------------------------------------------------------------------------------------------
##the syslog deamon configuration
cat /etc/rsyslog.conf
#create custom syslog messages
cat<<EOF | sudo tee -a /etc/rsyslog.conf
# New lines added for testing log message generation     
local4.crit                                             /var/log/local4crit.log  
local4.=info                                            /var/log/local4info.log
EOF
sudo systemctl restart rsyslog
logger -p local4.info " This is a info message from local 4"
logger -p local4.crit " This is a critical message from local 4"
ls -lai /var/log/local*
cat /var/log/local4crit.log
--------------------------------------------------------------------------------------------------------------------
#Configuring the logrotate daemon
cat /etc/logrotate.conf
/etc/logrotate.d #configuration for specific logs 
head -n 15 /etc/logrotate.d/syslog #the syslog daemon has its own log rotation configuration file

#add custom lograte /etc/logrotate.conf

#wtmp keeps track of system logins
/var/log/wtmp {
    missingok
    monthly
    create 0664 root utmp
    rotate 1
}

#btmp keeps track of bad login attempts
/var/log/btmp {
    missingok
    monthly
    create 0660 root utmp
    rotate 1
} 
sudo logrotate -fv /etc/logrotate.conf #force logrotate to rotate a log file immediately
--------------------------------------------------------------------------------------------------------------------
egrep "Failed|Failure" /var/log/secure
grep "Failed" /var/log/secure
grep "authentication failure" /var/log/secure
journalctl _SYSTEMD_UNIT=sshd.service | egrep "Failed|Failure"  #display all failed SSH login attempts 
--------------------------------------------------------------------------------------------------------------------
#CentOS 8 ships with Nginx 1.14 by default
dnf module list nginx
dnf module reset nginx -y
dnf module enable nginx:1.20 -y
dnf update -y
dnf install nginx -y
systemctl enable --now nginx
systemctl status nginx
--------------------------------------------------------------------------------------------------------------------
timedatectl list-timezones
timedatectl list-timezones | grep Los
timedatectl set-timezone America/Los_Angeles
$ date

yum/apt install chrony
systemctl stop chronyd
chronyd -q 'pool pool.ntp.org iburst'
systemctl start chronyd
chronyc tracking #verify
systemctl restart chronyd ; watch chronyc tracking #realtime witnessing
chronyc sources
chronyc sources -v
chronyc
--------------------------------------------------------------------------------------------------------------------
sudo systemctl reload httpd.service
apachectl configtest
/etc/httpd/conf/httpd.conf

sudo apachectl configtest #test your Apache configuration
tail -n 2 /etc/httpd/logs/error_log
tail -f /etc/httpd/logs/error_log

#troubleshooting
sudo journalctl -u httpd.service --since today --no-pager
sudo systemctl status httpd.service -l --no-pager
systemctl status httpd
sudo httpd -t #check the config files 
sudo httpd -S #show parsed virtual host and run settings
ls /var/log/httpd/
grep -i -r error /var/log/httpd/

sudo ps aux | grep -E 'apache2|httpd' #check the processes
sudo kill -a httpd

journalctl -b | grep "tx hang"
journalctl --since yesterday | grep "tx hang"

#find the most recent errors
journalctl --no-pager --since today \
--grep 'fail|error|fatal' --output json|jq '._EXE' | \
sort | uniq -c | sort --numeric --reverse --key 1
--------------------------------------------------------------------------------------------------------------------
#two services handle syslog messages:The systemd-journald daemon,The Rsyslog service 
#The systemd-journald daemon collects messages from various sources and forwards them to Rsyslog for further processing
/var/log directory store syslog messages

/var/log/messages - all syslog messages except the following
/var/log/secure - security and authentication-related messages and errors
/var/log/maillog - mail server-related messages and errors
/var/log/cron - log files related to periodically executed tasks
/var/log/boot.log - log files related to system startup 
--------------------------------------------------------------------------------------------------------------------
#crontab

$ systemctl status crond
$ systemctl restart crond

journalctl -u crond #systemd cron job log 
journalctl -t CROND
journalctl -t CROND -f # watch live
journalctl -t CROND | tail -20

tail -v /var/log/cron #Print filename header
tail -f /var/log/cron | grep CRON
grep CRON /var/log/cron #troubleshoot cron 

#Check that crond is running
$ ps -ef | grep crond | grep -v grep 
ps -o pid,sess,cmd afx | egrep crond

$ sudo tail -f /var/log/cron.log

cat /etc/anacrontab #find out cron timings for /etc/cron.{daily,weekly,monthly}/

--------------------------------------------------------------------------------------------------------------------
problem:
AH00558: Could not reliably determine the server's fully qualified domain name error
troubleshooting:
apachectl configtest
systemctl status httpd.service -l --no-pager
journalctl -u httpd.service --since today --no-pager
fix:
$ cat /etc/httpd/conf/httpd.conf | grep "ServerName 127.0.0.1"
ServerName 127.0.0.1 #Add a line containing ServerName 127.0.0.1 to the end of the file
apachectl configtest
systemctl reload httpd.service
systemctl restart httpd.service
systemctl status httpd.service
--------------------------------------------------------------------------------------------------------------------
#centos stream,perl-Net-SNMP fix
sudo dnf -y install https://dl.fedoraproject.org/pub/epel/epel-release-latest-8.noarch.rpm
sudo dnf config-manager --set-enabled powertools
sudo dnf repolist
sudo yum --enablerepo=powertools,epel install perl-Net-SNMP
--------------------------------------------------------------------------------------------------------------------
#centos stream
problem:
/usr/bin/env: ‘python’: No such file or directory
fix:
python3 -V
python2 -V
yum update -yqq
yum install python3 -yqq
python3 -V
whereis python3
ln -s /usr/bin/python3 /usr/bin/python
/usr/bin/python -> /usr/bin/python3
--------------------------------------------------------------------------------------------------------------------
rpm -qRp <rpm package> #see the dependencies of the installation package
--------------------------------------------------------------------------------------------------------------------
#Create a New Sudo User
adduser username
passwd username
usermod -aG wheel username #add the user to the wheel group.By default, on CentOS, members of the wheel group have sudo privileges
su - username # switch to the new user account
--------------------------------------------------------------------------------------------------------------------
yum install traceroute -y
--------------------------------------------------------------------------------------------------------------------
echo myhost > /etc/hostname #rename host
echo 192.168.1.51 hostname.db.local hostname >> /etc/hosts #

vi /etc/resolv.conf


$ nmcli device (ens192 down)
$ nmcli device connect ens192
$ nmcli con show --active 

$ vi /etc/sysconfig/network-scripts/ifcfg-ens192
#update those lines
BOOTPROTO=static
ONBOOT=yes
#add those lines
IPADDR=192.168.1.10i
NETMASK=255.255.255.0
GATEWAY=192.168.1.1
DNS1=192.168.1.1
DNS2=8.8.8.8
DOMAIN=tecmint.lan
	
sudo nmcli networking off
sudo nmcli networking on
--------------------------------------------------------------------------------------------------------------------
#create new network connection,assume type is ethernet connection as used interface is called eth0
nmcli conn add con-name MY_CONNECTION ifname eth0 type ethernet \
ip4.addresses SOME.IP.TO.BE.USED/mask \
ipv4.gateway SOME.GATEWAY.TO.BE.USED \
ipv4.dns SOME.DNS.TO.BE.USED  

#modify an exisiting connection,+ sign provided DNS will be added to the list of DNS being used
#if omitted + sign the whole list will be replaced by provided value
#nmtui when using GUI 
nmcli con modify MY_CONNECTION [+]ipv4.dns SOME.DNS.TO.BE.USED  
nmcli con mod MY_CONNECTION ipv4.ignore-auto-dns yes       # to disable DHCP DNS

nmcli con show --active      # to check if the connection is not up 
nmcli con up MY_CONNECTION
nmcli con show --active      # to check if the connection is up

#automatically start the new connection on system reboot
nmcli con mod OLD_ACTIVE_CONNECTION connection.autoconnect no     # disable the old connection from starting on reboot 
nmcli con up MY_CONNECTION connection.autoconnect yes # automatically switch to new connection on reboot 
--------------------------------------------------------------------------------------------------------------------
#Change hostname of the system
hostnamectl set-hostname SOME_NAME
nmcli general hostname SOME_NAME
--------------------------------------------------------------------------------------------------------------------
#Install Apache and allow it to get documents from NFS mounted folder

yum install -y httpd
#when installing service/software which interacts with network 
#it is crucial to keep in mind configuring firewall to enable incoming connections for this service
# notice the '-permament' option (in order to save rule to survive during reboots)
firewall-cmd –permanent –add-service=http
firewall-cmd –reload
#autostart after reboo,services usually does not autostart as a part of installation process
systemctl enable httpd
systemctl start httpd

#SELinux set to enforcing mode
#analyze Selinux denials log
#diagnose SELinux denials,provide user friendly explanations for a SELinux denial
# recommendations for how one might adjust the system to prevent the denial in the future
sealert -a /var/log/audit/audit.log

#Apache will be allowed to get documents from NFS mounted folder
setsebool -P httpd_use_nfs 1
--------------------------------------------------------------------------------------------------------------------
#extending of logical partitions,XFS filesystem  does not allow downsizing of XFS partition
# notice -r flag which indicates not only to resize logical volume but also filesystem on it
lvextend –size 200M -r /dev/VOLUME_GROUP/LOGICAL_VOLUME
#In order to give a logical volume a label we have to unmount it first, set a label and then mount it again
# umount /LINK/TO/FILESYSTEM/MOUNT/POINT
# xfs_admin -L "myFS" /dev/VOLUME_GROUP/LOGICAL_VOLUME
# mount /LINK/TO/FILESYSTEM/MOUNT/POINT
--------------------------------------------------------------------------------------------------------------------
#query DNS servers
cat /etc/resolv.conf 
nmcli dev show | grep DNS 
nmcli device show eth0 | grep IP4.DNS
( nmcli dev list || nmcli dev show ) 2>/dev/null | grep DNS
nm-tool | grep DNS
systemd-resolve --status # systems running systemd
resolvectl # systems running systemd
--------------------------------------------------------------------------------------------------------------------
#centos 8 minimal in2ternet connection
nmcli d #list ethernet card installed
nmtui # dhcp enabled
nmcli networking off
nmcli networking on
--------------------------------------------------------------------------------------------------------------------
/etc/ssl/certs
"ca-bundle.crt"
"ca-bundle.trust.crt"  certificates with "extended validation",identify yourself to the cert issuer by i.e. your passport. 
--------------------------------------------------------------------------------------------------------------------
Problem:
Errors during downloading metadata for repository 'epel-modular':
  - Curl error (60): Peer certificate cannot be authenticated with given CA certificates for https://mirrors.fedoraproject.org/metalink?repo=epel-modular-8&arch=x86_64&infra=stock&content=centos [SSL certificate problem: self signed certificate in certificate chain]
Error: Failed to download metadata for repo 'epel-modular': Cannot prepare internal mirrorlist: Curl error (60): Peer certificate cannot be authenticated with given CA certificates for https://mirrors.fedoraproject.org/metalink?repo=epel-modular-8&arch=x86_64&infra=stock&content=centos [SSL certificate problem: self signed certificate in certificate chain]
Fix1:
sslverify=false #add the following to "/etc/yum.conf"
Fix2:
yum-config-manager --save --setopt=epel.sslverify=false
cat  /etc/yum.repos.d/epel.repo
--------------------------------------------------------------------------------------------------------------------
yum update -y
dnf update -y
--------------------------------------------------------------------------------------------------------------------
#setting system locale to en_US.utf8
localectl set-locale LC_CTYPE=en_US.utf8
localectl status
--------------------------------------------------------------------------------------------------------------------
#find out which package provides 'netstat' command.
yum provides */netstat
yum whatprovides */netstat
yum whatprovides *bin/which #which: command not found
--------------------------------------------------------------------------------------------------------------------
yum groupinstall "Development Tools"

#Listing the packages in a package group php
yum group info php  
yum group info @php 
yum groups info @php
yum groups info php
yum groupinfo @php
yum groupinfo php
--------------------------------------------------------------------------------------------------------------------
yum history #view a full history of YUM transactions, we can run the command below which will show us the: transaction id, login user who executed the particular action, date and time when the operation happened
yum history list all
yum history info httpd #view details of transactions concerning a given package such as httpd web server
yum history summary httpd #a summary of the transactions concerning httpd package
yum history info 15 #display details of the transaction
yum history package-list httpd
yum history package-info httpd
yum history package-list httpd epel-release #history about multiple packages
yum history undo 2
yum history redo 2 
yum history rollback 2 
yum history redo force-reinstall 16 #reinstalls any packages that were installed in that transaction
yum history stats
yum history sync
yum history new #set a new history file
--------------------------------------------------------------------------------------------------------------------
# Check CentOS Version
    /etc/centos-release
    /etc/os-release
    /etc/redhat-release
    /etc/system-release

nmcli dev
nmtui
#restar network option 1
systemctl restart NetworkManager
systemctl restart NetworkManager.service
#restar network option 2
nmcli networking off
nmcli networking on

  Install the package
  rpm -ivh --test mozilla-mail-1.7.5-17.i586.rpm
  Upgrade package
  rpm -Uvh --test mozilla-mail-1.7.6-12.i586.rpm  
  yum remove mozilla-mail # Erase/remove/uninstall an installed package with dependencies
  rpm -ev mozilla-mail # Erase/remove/ an installed package
  Erase/remove/ an installed package without checking for dependencies
  rpm -ev --nodeps mozilla-mail
  Display list all installed packages
  rpm -qa
  Display installed information along with package version and short description
  rpm -qi mozilla-mail
  Find out what package a file belongs to i.e. find what package owns the file
  rpm -qf /etc/passwd
  Display list of configuration file(s) for a package
  rpm -qc httpd
  Display list of configuration files for a command
  rpm -qcf /usr/X11R6/bin/xeyes
  Display list of all recently installed RPMs
  rpm -qa --last
  Find out what dependencies a rpm file has
  rpm -qpR mediawiki-1.4rc1-4.i586.rpm
  rpm --queryformat='%12{SIZE} %{NAME}\n' -q java-11-openjdk-headless #Display the size of an installed RPM
  
  yum list installed | grep -i vim-minimal
  yum list installed -> grep glusterfs
  yum list available -> available packages
  yum list available | grep -i pip | awk ‘{print $1}’ #Check the available version of python-pip
  #Installing Guest Additions
  yum install dkms
  yum groupinstall "Development Tools"
  yum install kernel-devel
  
 #Install/Upgrade to latest kernel
 rpm --import https://www.elrepo.org/RPM-GPG-KEY-elrepo.org
 rpm -Uvh http://www.elrepo.org/elrepo-release-7.0-3.el7.elrepo.noarch.rpm 
 yum --disablerepo="*" --enablerepo="elrepo-kernel" list available
 yum --enablerepo=elrepo-kernel install kernel-ml
 reboot
 /etc/default/grub -> update "GRUB_DEFAULT=0"
 grub2-mkconfig -o /boot/grub2/grub.cfg
 reboot
 


#do not need the full kernel source
yum install kernel-devel

#need the full kernel source
mkdir -p ~/rpmbuild/{BUILD,BUILDROOT,RPMS,SOURCES,SPECS,SRPMS} -As an ordinary user, not root
echo '%_topdir %(echo $HOME)/rpmbuild' > ~/.rpmmacros -As an ordinary user, not root
yum install rpm-build redhat-rpm-config asciidoc hmaccalc perl-ExtUtils-Embed pesign xmlto
yum install audit-libs-devel binutils-devel elfutils-devel elfutils-libelf-devel
yum install ncurses-devel newt-devel numactl-devel pciutils-devel python-devel zlib-devel
#Find the kernel source rpm package in
http://vault.centos.org/7.N.YYMM/os/Source/SPackages/
http://vault.centos.org/7.N.YYMM/updates/Source/SPackages/
rpm -i http://vault.centos.org/7.4.1708/updates/Source/SPackages/kernel-3.10.0-693.21.1.el7.src.rpm 2>&1 | grep -v exist -As an ordinary user, not root
yum info iptables -> check iptables version

sudo yum repolist  -> List new repos
sudo yum search htop  -> Search and install htop package from epel repo on a CentOS/RHEL 7.x
sudo yum info htop -> get more info
sudo yum --showduplicates list docker-ce -> list all available versions of package available
yum list docker-ce --showduplicates | sort -r
yum install <package name>-<version info>
yum install httpd-2.4.6-6

yum repolist #verify the EPEL repository is enabled
yum --disablerepo="*" --enablerepo="epel" list available #list the software packages that constitute the EPEL repository
dnf --disablerepo="*" --enablerepo="epel" list available #list the software packages that constitute the EPEL repository
yum --disablerepo="*" --enablerepo="epel" list available | grep 'htop' #search for individual package
yum --enablerepo=epel info htop #search a package
yum --enablerepo=epel install htop #search a package

find out what package it belongs, mkpasswd 
$ yum whatprovides "*/mkpasswd"
$ repoquery -q --file */mkpasswd

yum list installed | awk '{print $1 " " $2}'
yum list installed | awk '{print $1 "------------" $2}'

yum list installed | awk ' /'unzip'/    {print $1}            '
unzip.x86_64
yum list installed | awk ' /unzip/    {print $1}            '
yum list installed | awk ' /'unzip'/ '
yum list installed | awk ' /unzip/   '

yum list installed | awk ' /'unzip'/    {print $3 "--" $2}            '
yum list installed | awk ' /'unzip'/    {print $3"**" $2 ; print $2"--" $3}            '
yum list installed | awk ' /'zip'/    {print $3"**" $2 ; print $2"--" $3 "\n"}            '
yum list installed | awk '    /'zip'/    { print $2"\t" $3} 

# How to install and configure telnet
rpm -qa | grep telnet
yum install telnet-server telnet

#Start and Enable Firewalld
systemctl enable firewalld
systemctl start firewalld
systemctl status firewalld

# Add the service to firewalld
firewall-cmd --add-service=telnet --zone=public
firewall-cmd --list-services
rpm -q firewalld
firewall-cmd --state

semanage port -a -t telnetd_port_t -p tcp # Add the service to selinux.
setenforce 0 #disable selinux
sestatus #current mode of SELinux
getenforce #current mode of SELinux
cat /etc/selinux/config #current mode of SELinux
setenforce Permissive #Disable SELinux Temporarily,only work until the next reboot
echo 0 > /selinux/enforce #Disable SELinux Temporarily,only work until the next reboot

sed -i 's/=enforcing/=disabled/g' /etc/selinux/config && reboot #Disable SELinux Permanently,change the directive SELinux=enforcing to SELinux=disabled
sed -i 's/SELINUX=.*/SELINUX=disabled/g' /etc/selinux/config #disable SELinux permanently
cat /etc/selinux/config | grep SELINUX

firewall-cmd --add-port={53,80,443,5647,9090}/tcp --permanent
firewall-cmd --add-port="67-69,53/udp" --permanent

sudo firewall-cmd --state #check the firewall status
sudo firewall-cmd --get-default-zone #view the default zone
sudo firewall-cmd --get-active-zones #check what zones are used by your network interface(s) type
sudo firewall-cmd --zone=public --list-all #the zone configuration settings 
firewall-cmd --list-all
firewall-cmd --list-ports
sudo firewall-cmd --list-all-zones #check the configurations of all available zones type 
sudo firewall-cmd --zone=public --change-interface=eth0 #Changing the Zone of an Interface
sudo firewall-cmd --set-default-zone=home #Changing the Default Zone 
sudo firewall-cmd --get-services #list of all default available services type
cat /usr/lib/firewalld/services/http.xml #find more information about each service by opening the associated .xml file
sudo firewall-cmd --zone=public --add-service=http #allow incoming HTTP traffic (port 80) for interfaces in the public zone
sudo firewall-cmd --zone=public --list-services #verify the service
sudo firewall-cmd --permanent --zone=public --list-services #Use the --list-services along with the --permanent option to verify your changes
sudo firewall-cmd --zone=public --remove-service=http --permanent #removing service
sudo firewall-cmd --zone=public --add-port=32400/tcp #open the port in the public zone for the current session 
sudo firewall-cmd --zone=public --remove-port=32400/tcp #remove the port in the public zone for the current session 
sudo firewall-cmd --zone=public --list-ports #verify the port
sudo cp /usr/lib/firewalld/services/ssh.xml /etc/firewalld/services/plexmediaserver.xml #Creating a new FirewallD Service

sudo firewall-cmd --zone=external --add-masquerade #Forwarding Port with Firewalld,enable masquerading for external zone type
sudo firewall-cmd --zone=external --add-forward-port=port=80:proto=tcp:toport=8080  #forwarding the traffic from port 80 to port 8080 on the same server:
sudo firewall-cmd --zone=external --add-forward-port=port=80:proto=tcp:toaddr=10.10.10.3 #Forward traffic to another server
sudo firewall-cmd --zone=external --add-forward-port=port=80:proto=tcp:toport=8080:toaddr=10.10.10.3 #Forward traffic to another server on a different port

Creating a Ruleset with FirewallD 
sudo firewall-cmd --set-default-zone=dmz #change the default zone to dmz and to assign it to the eth0 interface
sudo firewall-cmd --zone=dmz --add-interface=eth0 #only one interface eth0, allow incoming traffic only on SSH, HTTP, and HTTPS ports
sudo firewall-cmd --permanent --zone=dmz --add-service=http #Open HTTP and HTTPS ports
sudo firewall-cmd --permanent --zone=dmz --add-service=https #the dmz (demilitarized) zone by default it only allows SSH traffic
sudo firewall-cmd --reload #Make the changes effective immediately by reloading the firewall
sudo firewall-cmd --zone=dmz --list-all #Verify the changes

RPM package database
$ ls -lai /var/lib/rpm

# create new user, new group with the same name
sudo adduser sdn --system --user-group

--------------------------------------------------------------------------------------------------------------------
Add the osquery key
curl -L https://pkg.osquery.io/rpm/GPG | sudo tee /etc/pki/rpm-gpg/RPM-GPG-KEY-osquery
Verify the osquery key
$ gpg --quiet --with-fingerprint /etc/pki/rpm-gpg/RPM-GPG-KEY-osquery
pub   rsa4096 2015-01-24 [SC]
uid           osquery (osquery) <osquery@fb.com>
sub   rsa4096 2015-01-24 [E]

Add osquery repo
sudo yum-config-manager --add-repo https://pkg.osquery.io/rpm/osquery-s3-rpm.repo
sudo yum-config-manager --enable osquery-s3-rpm
Verify osquery repo
$ cat  /etc/yum.repos.d/osquery-s3-rpm.repo
[osquery-s3-rpm-repo]
name=name=osquery RPM repository - $basearch
baseurl=https://s3.amazonaws.com/osquery-packages/rpm/$basearch/
enabled=1
gpgkey = file:///etc/pki/rpm-gpg/RPM-GPG-KEY-osquery
gpgcheck=1
--------------------------------------------------------------------------------------------------------------------
dnf install ImageMagick
convert imagename.jpg -resize 800x600 newimagename.jpg
convert image.jpg image.png
convert image.png image.gif
convert imagename.jpg -rotate 90 newimage.jpg
--------------------------------------------------------------------------------------------------------------------
======================================================================================
find out which package provides 'netstat' command.
dnf provides */netstat
dnf whatprovides */netstat
======================================================================================
dnf config-manager --add-repo repository_url #
dnf cache

view the repositories
$ sudo dnf repolist all
$ sudo dnf repolist
# dnf config-manager --set-enabled repository_url
# dnf config-manager --add-repo http://www.example.com/example.repo

dnf info ansible
dnf search ansible
dnf -y update
dnf -y install ansible
======================================================================================
dnf grouplist
dnf groupinfo "Basic Web Server"
dnf groupinstall "Web Server" -y
dnf group update
dnf group remove
======================================================================================
# mainline kernel branch:
curl -s https://repos.fedorapeople.org/repos/thl/kernel-vanilla.repo | sudo tee /etc/yum.repos.d/kernel-vanilla.repo
sudo dnf --enablerepo=kernel-vanilla-mainline update
uname -r
sudo dnf config-manager --set-enabled kernel-vanilla-mainline
sudo dnf update
sudo reboot

$ hostnamectl
   Static hostname: postgresql04
         Icon name: computer-vm
           Chassis: vm
        Machine ID: fa8a1edd06864f47ba4cad5d0f5ca134
           Boot ID: 55e2030fb8694eaaa6f442322c7346c1
    Virtualization: oracle
  Operating System: Fedora 29 (Twenty Nine)
       CPE OS Name: cpe:/o:fedoraproject:fedora:29
            Kernel: Linux 5.2.0-0.rc2.git0.1.vanilla.knurd.1.fc29.x86_64
      Architecture: x86-64

======================================================================================
# stable kernel branch:
$ hostnamectl
   Static hostname: postgresql05
         Icon name: computer-vm
           Chassis: vm
        Machine ID: fa8a1edd06864f47ba4cad5d0f5ca134
           Boot ID: bffa82da956e4ddb8c231a4144496fd5
    Virtualization: oracle
  Operating System: Fedora 29 (Twenty Nine)
       CPE OS Name: cpe:/o:fedoraproject:fedora:29
            Kernel: Linux 4.18.16-300.fc29.x86_64
      Architecture: x86-64
	  
curl -s https://repos.fedorapeople.org/repos/thl/kernel-vanilla.repo | sudo tee /etc/yum.repos.d/kernel-vanilla.repo
sudo dnf --enablerepo=kernel-vanilla-stable update
sudo dnf config-manager --set-enabled kernel-vanilla-stable
sudo dnf update
sudo reboot

$ hostnamectl
   Static hostname: postgresql05
         Icon name: computer-vm
           Chassis: vm
        Machine ID: fa8a1edd06864f47ba4cad5d0f5ca134
           Boot ID: fceef84738ad4f12a8f9bf9638e49f87
    Virtualization: oracle
  Operating System: Fedora 29 (Twenty Nine)
       CPE OS Name: cpe:/o:fedoraproject:fedora:29
            Kernel: Linux 5.1.5-350.vanilla.knurd.1.fc29.x86_64
======================================================================================