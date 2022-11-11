----------------------------------------------------------------------------------------------------
#shortcuts ubuntu desktop mate
type to search - keyboard shortcuts

ctrl+alt+d minimize/maximize all windows
alt+F9 - minimize windows
ctrl+alt+l - lock screen
--------------------------------------------------------------------------------------------------------------------
#hardening

#remove unsecure packages
$ apt list --installed | grep telnet 
$ sudo apt-get --purge remove xinetd nis yp-tools tftpd atftpd tftpd-hpa telnetd rsh-server rsh-redone-server telnet

apt install vsftpd #(VSFTPD stands for “Very Secure FTP Daemon software package”) Vsftpd SSL / TLS FTP Server Configuration

apt list --installed | grep ssh #no need to install additional packages in order to use SFTP,require the prebuild SSHd package that got already installed during installation on the server
apt install ssh # if SSH server is not already installed

apt-get install openssh-server #
----------------------------------------------------------------------------------------------------
# first setup

# Stop and disable apt-daily upgrade services;
systemctl stop apt-daily.timer
systemctl disable apt-daily.timer
systemctl disable apt-daily.service
systemctl stop apt-daily-upgrade.timer
systemctl disable apt-daily-upgrade.timer
systemctl disable apt-daily-upgrade.service

# Enable retry logic for apt up to 10 times
echo "APT::Acquire::Retries \"10\";" > /etc/apt/apt.conf.d/80-retries

# Configure apt to always assume Y
echo "APT::Get::Assume-Yes \"true\";" > /etc/apt/apt.conf.d/90assumeyes

# Fix bad proxy and http headers settings
cat <<EOF >> /etc/apt/apt.conf.d/99bad_proxy
Acquire::http::Pipeline-Depth 0;
Acquire::http::No-Cache true;
Acquire::BrokenProxy    true;
EOF

sudo apt-get update -qy && sudo apt-get -yq dist-upgrade && sudo apt-get purge unattended-upgrades
sudo apt-get update -qy && sudo apt-get clean all && sudo apt-get -yq dist-upgrade && sudo apt-get purge unattended-upgrades \
&& sudo apt -y autoremove && sudo apt clean
----------------------------------------------------------------------------------------------------
Problem:
ping yahoo.com
Temporary failure in name resolution

Fix:

echo "nameserver 8.8.8.8" |sudo tee -a /etc/resolv.conf #Misconfigured resolv.conf File
sudo systemctl restart systemd-resolved.service 

sudo chown root:root /etc/resolv.conf #Misconfigured Permissions
sudo chmod 644 /etc/resolv.conf

sudo ufw allow 43/tcp #Firewall Restrictions,port 43, used for whois lookup,port 53, used for domain name resolution
sudo ufw allow 53/tcp
sudo ufw reload
sudo firewall-cmd --add-port=43/tcp --permanent
sudo firewall-cmd --add-port=53/tcp --permanent
sudo firewall-cmd --reload

ping yahoo.com

----------------------------------------------------------------------------------------------------
Problem:
$ host vg-ubuntu-02
Host vg-ubuntu-02 not found: 2(SERVFAIL)
$ ping -c 1 vg-ubuntu-02
PING vg-ubuntu-02.local (10.35.8.64) 56(84) bytes of data.
From 10.35.8.65 icmp_seq=1 Destination Host Unreachable

--- vg-ubuntu-02.local ping statistics ---
1 packets transmitted, 0 received, +1 errors, 100% packet loss, time 0ms
$ host -v -t A vg-ubuntu-02
Trying "vg-ubuntu-02.Bakircay.Local"
Trying "vg-ubuntu-02"
Host vg-ubuntu-02 not found: 2(SERVFAIL)
Received 30 bytes from 10.0.2.3#53 in 1 ms

$ getent hosts vg-ubuntu-02
10.35.8.64      vg-ubuntu-02.local vg-ubuntu-02


/etc/nsswitch.conf #hosts:        files dns,first interrogate /etc/hosts and then interrogate DNS if unsuccessful.
----------------------------------------------------------------------------------------------------
#using systemd resolved service to cache DNS entries

$ sudo systemctl is-active systemd-resolved.service #find out whether the service is running use
sudo systemd-resolve --statistics
sudo systemd-resolve -4 vg-centos-02 #Resolve IPv4 addresses

systemctl restart systemd-resolved.service
----------------------------------------------------------------------------------------------------
#Create a New Sudo User(ubuntu)
sudo adduser test1
sudo usermod -aG sudo test1

#verify if user is sudoer
id test1
sudo -l -U test1
test1@vg-ubuntu-01:~$ sudo --list
test1@vg-ubuntu-01:~$ groups
test1@vg-ubuntu-01:~$ sudo whoami # returns root


#Create a New Sudo User (ubuntu)
sudo adduser barak #create new user
sudo adduser barak sudo #Add the user to sudo group 
usermod -aG sudo barak #Add the user to sudo group 

id barak  #verify sudo group
groups newuser #verify sudo group

su - barak #Verify Sudo Access
$ ls /root
ls: cannot open directory '/root': Permission denied
sudo ls /root
----------------------------------------------------------------------------------------------------
#Configuring the logrotate daemon
cat /etc/logrotate.conf
/etc/logrotate.d #configuration for specific logs 
head -n 15 /etc/logrotate.d/rsyslog #the rsyslog daemon has its own log rotation configuration file

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
----------------------------------------------------------------------------------------------------
#Ubuntu 20.04 uses a daemon called rsyslogd which is a superset of syslogd, cat /etc/rsyslog.conf
#the syslog deamon configuration
cat /etc/rsyslog.conf
/etc/rsyslog.d/50-default.conf #all additional Rsyslog rules are placed
 
 #create custom syslog messages
cat<<EOF | sudo tee -a /etc/rsyslog.conf
# Logging for INN news system.  
#  
news.crit			/var/log/news/news.crit  
news.err			/var/log/news/news.err  
news.notice			-/var/log/news/news.notice
EOF
sudo /etc/init.d/rsyslog restart
logger -p news.crit " This is a critical message from news"
ls -lai /var/log/news*
cat /var/log/news/news*
----------------------------------------------------------------------------------------------------
#Create a New Sudo User
sudo adduser barak #create new user
sudo adduser barak sudo #Add the user to sudo group 
usermod -aG sudo barak #Add the user to sudo group 

id barak  #verify sudo group
groups newuser #verify sudo group

su - barak #Verify Sudo Access
$ ls /root
ls: cannot open directory '/root': Permission denied
sudo ls /root

----------------------------------------------------------------------------------------------------
#failed login attempts
 $ sudo grep "Failed password" /var/log/auth.log | head -3
 $ sudo grep "Failed password" /var/log/auth.log | awk '{print $9}' | sort | uniq -c 
 $ sudo lastb
---------------------------------------------------------------------------------------------------- 
#Intrusion prevention with fail2ban
sudo apt update
sudo apt install fail2ban
sudo systemctl start fail2ban
sudo systemctl enable fail2ban

sudo cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
#For SSH, fail2ban will monitor the log file /var/log/auth.log using the fail2ban sshd filter

#Any attempt to login to the server failing three times (within a configurable time span) will be blocked 
#from further attempts by iptables blocking the originating IP address (for a configurable amount of time).
sudo nano /etc/fail2ban/jail.local
[sshd]
enabled = true
port = 22
filter = sshd
logpath = /var/log/auth.log

#be aware of the risk of being locked out testing the system
ignoreself = true
ignoreip = <Your-IP-address>
maxretry = 3

sudo systemctl restart fail2ban
sudo fail2ban-client status #see the enabled traffic type jails


#For HTTP, there are filters for Apache and Nginx
# a jail rule protecting HTTP authentication
#Rules can also be defined to block activities such as trying to run scripts, using a server as proxy and blocking bad bots.
[nginx-http-auth]
enabled  = true
filter   = nginx-http-auth
port     = http,https
logpath  = /var/log/nginx/error.log

sudo fail2ban-client set sshd unbanip <IP-address> #A blocked IP address is released (unbanned) 
----------------------------------------------------------------------------------------------------
problem:
journalctl doesn't keep boot history
resolution: https://bugs.launchpad.net/ubuntu/+source/systemd/+bug/1618188

sudo mkdir -p /var/log/journal
sudo systemd-tmpfiles --create --prefix /var/log/journal
l /var/log/journal

grep -i error /var/log/syslog.1

$ ls /var/log/syslog* #logs not listed on journalctl
/var/log/syslog    /var/log/syslog.2.gz  /var/log/syslog.4.gz  /var/log/syslog.6.gz
/var/log/syslog.1  /var/log/syslog.3.gz  /var/log/syslog.5.gz  /var/log/syslog.7.gz
----------------------------------------------------------------------------------------------------
/etc/letsencrypt/live #find the generated certificate files
/etc/letsencrypt/live/$domain
https://www.ssllabs.com/ssltest #verify the status of your SSL certificate 

$ sudo ls /etc/letsencrypt

$ sudo ls /var/log/letsencrypt/
curl -I https://acme-v02.api.letsencrypt.org
$ sudo tail -10  /var/log/letsencrypt/letsencrypt.log

sudo certbot renew --dry-run # Test "renew" or "certonly" without saving any certificates

#the "certbot.timer" utility for automatic certificate renewal
#It checks the validity of SSL certificates in the system twice a day and extends those that expire in the next 30 days
sudo systemctl status certbot.timer 

$ sudo ls  /etc/letsencrypt/renewal/
$ sudo cat  /etc/letsencrypt/renewal/example.com
sudo grep -r /etc/letsencrypt/ -e 'outdated.example.com'

/etc/cron.d/certbot #a renewal cron job was created automatically 

#Automatically Renew Let’s Encrypt Certificates
$ crontab -e
0 12 * * * /usr/bin/certbot renew --quiet #every day at noon

$ cat /etc/cron.daily/renewcerts
#!/bin/bash
certbot renew
$ chmod a+x /etc/cron.daily/renewcerts
$ run-parts --test -v /etc/cron.daily  # verify that the script would actually run, but don't run them

#Automatically Renew Let’s Encrypt Certificates
sudo crontab -e
@daily /usr/bin/certbot renew --quiet

#SSL installed to /etc/letsencrypt/live/ssl.itsyndicate.org
#Test SSL Configuration
curl -vI https://ssl.itsyndicate.org

certbot -d cyberciti.biz #force cert renewal even if it is not near its expiration date

sudo certbot renew #renew Let's Encrypt certificates,manually trigger the renewal
certbot certonly --force-renew -d example.com #If there are multiple certificates for different domains,renew a specific certificate
sudo certbot renew --dry-run #verify that the certificate renewed

 #keep the certificate but discontinue future renewals 
 #(for example ,switch to a different server, but wait for all the DNS changes to propagate)
 mv /etc/letsencrypt/renewal/example.com.conf  /etc/letsencrypt/renewal/example.com.conf.disabled
 sudo certbot renew --dry-run
 
 certbot delete #interactive menu
 #removes the certificate and all relevant files from your letsencrypt config directory
 certbot delete --cert-name example.com #delete a certificate non-interactively 

#remove a domain from certbot renewals
rm -rf /etc/letsencrypt/live/${BAD_DOMAIN}/
rm -f /etc/letsencrypt/renewal/${BAD_DOMAIN}.conf
certbot renew --dry-run
certbot renew

----------------------------------------------------------------------------------------------------
problem:
AH00558: Could not reliably determine the server's fully qualified domain name error
troubleshooting:
apachectl configtest
systemctl status apache2.service -l --no-pager
systemctl status apache2.service --full
systemctl is-enabled apache2.service #Verify that if a service enabled or not
systemctl is-active apache2 #if a service is running 
systemctl is-active --quiet apache2 && echo apache2 is running
journalctl -u apache2.service --since today --no-pager
journalctl UNIT=apache2.service
systemctl cat apache2.service #view systemd service/unit file source

fix:
$ cat /etc/apache2/apache2.conf| grep "ServerName 127.0.0.1"

ServerName 127.0.0.1 #Add a line containing ServerName 127.0.0.1 to the end of the file

cat<<EOF | sudo tee -a /etc/apache2/apache2.conf
ServerName 127.0.0.1
EOF

apachectl configtest
systemctl reload apache2.service
systemctl restart apache2.service
systemctl status apache2.service
----------------------------------------------------------------------------------------------------
#check that the locale of the server
systemctl show-environment
systemctl set-environment LANG=en_US.UTF-8
cat /etc/default/locale
----------------------------------------------------------------------------------------------------
apt depends kali-tools-database #list all the tools included in the kali-linux-web metapackage
apt-cache show kali-linux-web | grep Depends

#Part of this information is dependencies and you can see it in the line starting with Depends
#The information about the package dependencies, installation size, the package source etc,
apt show kali-tools-database 
----------------------------------------------------------------------------------------------------
apt install neofetch #system info bash script for Linux, MacOS, *BSD and Unix-like sysem
----------------------------------------------------------------------------------------------------
apt #for the terminal and gives output,displays a progress bar 
apt-get/apt-cache #for scripts and gives stable, parsable output
----------------------------------------------------------------------------------------------------
- No output except for errors
- implies -y (--assume-yes, answers "yes" to the questions)

apt-get update -qq && apt-get install --qq ansible
----------------------------------------------------------------------------------------------------
Package A depends on Package B if B absolutely must be installed in order to run A. In some cases, A depends not only on B, but on a version of B. In this case, the version dependency is usually a lower limit, in the sense that A depends on any version of B more recent than some specified version.
Package A recommends Package B, if the package maintainer judges that most users would not want A without also having the functionality provided by B.
Package A suggests Package B if B contains files that are related to (and usually enhance) the functionality of A

apt-get --install-suggests install
#While recommends are not absolutely necessary,this is done so that people with space constraints can keep their systems a little slimmer
apt-get --no-install-recommends install 
----------------------------------------------------------------------------------------------------
#https://snapcraft.io/docs/snap-confinement
$ snap info podman
$ snap info --verbose podman  #A snap’s confinement level is the degree of isolation it has from your system
snap --version #make sure snap installed
snap list --all mailspring #check all revisions of mailspring
snap list # list installed snaps
snap find media player
sudo snap disable mailspring
sudo snap enable mailspring
sudo snap remove mailspring #completely remove a snap
sudo snap remove  --revision=482 mailspring
sudo snap install --classic snapcraft #The --classic switch enables the installation of a snap that uses classic confinement.
sudo snap revert mailspring # revert to a previously used version
sudo snap refresh mailspring
sudo snap refresh		#update all snaps on the local system
sudo snap refresh --list #see which snap packages have available updates
sudo snap refresh <package_name> --channel=<channel_name> #stable/candidate/edge/beta
snap services  #see the services initiated by snap apps
sudo snap restart <package_name>
sudo snap stop <package_name>
sudo snap start <service_name>
sudo snap stop --disable <service_name>
sudo snap start --enable <service_name>
snap changes #see the history of changes
----------------------------------------------------------------------------------------------------
multipass version
----------------------------------------------------------------------------------------------------
apt list --upgradable #see these additional updates
do-release-upgrade # Run this on 18.04 to upgrade to 20.04

apt-get upgrade -> Do not change what is installed (only versions)
apt upgrade -> Install but not remove packages. Install available upgrades of all packages currently installed on the system from the sources configured via
           sources.list
apt update -> download package information from all configured sources
apt-get dist-upgrade -> Install or remove packages as necessary to complete the upgrade
apt full-upgrade -> Perform the same function as apt-get dist-upgrade

sudo apt-get remove <package>


apt-cache 	 name* ->which package contains the software
----------------------------------------------------------------------------------------------------
#list all installed packages on Ubuntu

apt list --installed 
apt list | grep nginx
apt list apache

aptitude search -F '%p' '~i' > list.txt
aptitude search '~i!~M' # installed (not just installed as dependencies)
apt-cache pkgnames > package_list.txt
apt-mark showmanual > list-manually-installed.txt

dpkg --list 'ansible*' #text file containing installed packages
#The first three columns of the output show the desired action, the package status, and  errors,in that order
man dpkg-query

dpkg -l | awk  '{print $2}'
dpkg -l |awk '/^[hi]i/{print $2}' > list.txt
dpkg --get-selections > list.txt

dpkg-query -W -f='${PackageSpec} ${Status}\n' | grep installed |  sort -u | cut -f1 -d \ > installed-pkgs

#all packages intentionally installed (not as dependencies) by apt commands
(zcat $(ls -tr /var/log/apt/history.log*.gz); cat /var/log/apt/history.log) 2>/dev/null |
  egrep '^(Start-Date:|Commandline:)' |
  grep -v aptdaemon |
  egrep '^Commandline:'

#all packages intentionally installed (not as dependencies) by apt commands with installation date
(zcat $(ls -tr /var/log/apt/history.log*.gz); cat /var/log/apt/history.log) 2>/dev/null |
  egrep '^(Start-Date:|Commandline:)' |
  grep -v aptdaemon |
  egrep -B1 '^Commandline:'
  
----------------------------------------------------------------------------------------------------
sudo apt-get install system-config-kickstart #generate a Kickstart file

#preseed
sudo apt-get install debconf-utils
sudo debconf-get-selections --installer

#nfs config
sudo apt-get install nfs-kernel-server
sudo vi /etc/fstab
192.168.1.1:/nas_directory  /ubuntu_directory  nfs   soft,intr,rsize=8192,wsize=8192
sudo mount -o soft,intr,rsize=8192,wsize=8192 10.222.2.27:/nas_directory /ubuntu_directory
df -h

sudo add-apt-repository ppa:someppa/ppa
sudo add-apt-repository --remove ppa:someppa/ppa

sudo apt list --upgradable -> Check for upgradable packages

 apt-cache search linux-generic -> Find out the latest version of Linux kernel type on the current system
   e.g:linux-image-4* 

apt-cache search . | grep -i "metapackage\|meta-package"

sudo apt-get install linux-headers-$(uname -r) -> install current kernel
sudo apt-get install linux-headers-generic -> install generic kernel
sudo apt-get install linux-headers-$(uname -r)
sudo apt-get upgrade linux-headers-$(uname -r)
apt-cache search linux-image
sudo apt-get install linux-image-your_version_choice linux-headers-your_version_choice linux-image-extra-your_version_choice
sudo apt-get install -y linux-image-4.15.0.20 linux-headers-4.15.0.20 linux-image-extra-4.15.0.20

sudo apt-get install package=version -> Install specific version
sudo apt-get install -y mongodb-org=3.4.10

there are multiple versions of a package within the repositories, with a single default package.
apt-cache policy package


maintains its own database of information, which includes the installation path of every file controlled by a package in the database.
sudo apt-get update
sudo apt-get install apt-file
sudo apt-file update
only work for file locations that are installed directly by a package. 
Any file that is created through post-installation scripts will not be found
sudo apt-file search /usr/bin/kubectl




backup sources lists and trusted key list
mkdir ~/sources
cp -R /etc/apt/sources.list* ~/sources
The trusted keys can be backed up
apt-key exportall > ~/trusted_keys.txt
add the trusted keys and implement the sources lists copied from the first computer
sudo apt-key add ~/trusted_keys.txt
sudo cp -R ~sources/* /etc/apt/


# list all available versions
apt-cache policy mongodb-org
apt-cache show mongodb-org
apt-cache show libapache2-mod-security2 | grep Version
apt-cache showpkg mongodb-org
apt-cache madison mongodb-org

show detailed information about a package
apt-cache show mongodb-org
show additional information about each of the candidates, 
including a full list of reverse dependencies (a list of packages that depend on the queried package)
information about this package's relationship to other packages:
apt-cache showpkg package

dpkg --listfiles  librrds-perl

Show Dependencies and Reverse Dependencies
apt-cache depends package
find out which packages depend on a certain package
apt-cache rdepends package

apt-cache madison docker-ce
docker-ce | 5:18.09.8~3-0~ubuntu-cosmic | https://download.docker.com/linux/ubuntu cosmic/stable amd64 Packages
sudo apt-get install docker-ce=5:18.09.8~3-0~ubuntu-cosmic docker-ce-cli=5:18.09.8~3-0~ubuntu-cosmic containerd.io

repositories (and installed DEB packages) 
search for available packages
$ apt-cache search kubelet
$ aptitude versions docker-ce

-----------------------------------------------------------------------------
list the repositories that are used
$ grep ^[^#] /etc/apt/sources.list /etc/apt/sources.list.d/*
$ ls /var/lib/apt/lists/*_Packages | grep kubernetes
$ grep -rhE ^deb /etc/apt/sources.list*
$ sudo apt-cache policy

#Delete A Repository
sudo nano /etc/apt/sources.list
#If added PPA repositories
$ sudo add-apt-repository -r ppa:ansible/ansible
$ sudo apt update

$ sudo add-apt-repository --remove ppa:PPA_Name/ppa
ls /etc/apt/sources.list.d #see all the PPAs 
sudo rm -i /etc/apt/sources.list.d/PPA_Name.list #remove the .list file associated with the PPA

#List PPA Repositories
$ apt policy | grep ppa
$ sudo apt-cache policy | grep ppa
 500 http://ppa.launchpad.net/ansible/ansible/ubuntu focal/main amd64 Packages
     origin ppa.launchpad.net
#Remove PPA
$ sudo add-apt-repository --remove ppa:ansible/ansible
     


#Delete Repository keys 
$ sudo apt-key list
#the long (40 characters) hex value is the repository key.
$ sudo apt-key del "3820 03C2 C8B7 B4AB 813E 915B 14E4 9429 73C6 2A1B"
#Or specify the last 8 characters 
$ sudo apt-key del 73C62A1B
-----------------------------------------------------------------------------
see the side effects of a procedure before without actually committing to executing the command
$ apt-get install -s kubectl=1.13.3-00
$ sudo apt-get -s dist-upgrade

Fix Broken Dependencies and Packages
sudo apt-get install -f

download a package from the repositories without actually installing it
apt-get download package

To download the source of a package, you must have a corresponding deb-src line in your source.list file for apt
sudo apt-get source package
ls -F

================================================================================================
# Add/Edit Kernel parameters
$ grep GRUB_CMDLINE_LINUX_DEFAULT /etc/default/grub 
GRUB_CMDLINE_LINUX_DEFAULT="quiet"
$ sudo perl -i -pe 'm/quiet/ and s//quiet nokaslr/' /etc/default/grub
$ grep quiet /etc/default/grub
GRUB_CMDLINE_LINUX_DEFAULT="quiet splash nokaslr"
$ sudo update-grub

# Clone / Compile specific kernel
sudo git clone git://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable.git linux -> latest stable kernel to "linux" directory
git tag -l | grep v4.9.1 -> find specific kernel version
git checkout -b kernel490 v4.9.1 -> switch to kernel with custom name "kernel490"


$ sudo apt-get update
$ sudo apt-get install linux-source -> Install Kernel Source Code And Headers 
================================================================================================
$ hostnamectl
   Static hostname: control-machine
         Icon name: computer-vm
           Chassis: vm
        Machine ID: c3dbdd98481045bdbbbfecad34aa29e2
           Boot ID: 3b6ee7c136a54fb0b006dfe7efb7cc53
    Virtualization: oracle
  Operating System: Ubuntu 18.10
            Kernel: Linux 4.18.0-10-generic
      Architecture: x86-64


# check on http://kernel.ubuntu.com/~kernel-ppa/mainline/ 

wget https://kernel.ubuntu.com/~kernel-ppa/mainline/v5.1.5/linux-headers-5.1.5-050105_5.1.5-050105.201905251333_all.deb
wget https://kernel.ubuntu.com/~kernel-ppa/mainline/v5.1.5/linux-headers-5.1.5-050105-generic_5.1.5-050105.201905251333_amd64.deb
wget https://kernel.ubuntu.com/~kernel-ppa/mainline/v5.1.5/linux-image-unsigned-5.1.5-050105-generic_5.1.5-050105.201905251333_amd64.deb
wget https://kernel.ubuntu.com/~kernel-ppa/mainline/v5.1.5/linux-modules-5.1.5-050105-generic_5.1.5-050105.201905251333_amd64.deb
$ sudo dpkg -i *.deb
$ sudo reboot 
$ hostnamectl
   Static hostname: control-machine
         Icon name: computer-vm
           Chassis: vm
        Machine ID: c3dbdd98481045bdbbbfecad34aa29e2
           Boot ID: cd56427e3a1c43e49ea9527b197202a3
    Virtualization: oracle
  Operating System: Ubuntu 18.10
            Kernel: Linux 5.1.5-050105-generic
      Architecture: x86-64
================================================================================================
echo deb http://download.virtualbox.org/virtualbox/debian xenial contrib | sudo tee -a /etc/apt/sources.list.d/virtualbox.list
wget -q https://www.virtualbox.org/download/oracle_vbox_2016.asc -O- | sudo apt-key add -
apt-get update -qq
apt-get install -y virtualbox-5.2
================================================================================================
#Install virtualbox guest addition terminal -1
sudo apt-get update
sudo apt-get install build-essential linux-headers-$(uname -r)
sudo apt-get install virtualbox-guest-x11
#Install virtualbox guest addition terminal -2
sudo apt-get install virtualbox-guest-dkms virtualbox-guest-utils virtualbox-guest-x11

sudo gdebi example.deb -> in comparison to the above dpkg command is that gdebi will automatically download and install all required prerequisite packages. 

#find the Ubuntu version
lsb_release -a
lsb_release -d
lsb_release -c # Ubuntu Codename:       focal etc
hostnamectl
cat /etc/lsb-release
cat /etc/issue
cat /etc/os-release
cat /etc/lsb-release | grep CODENAME

$ codename=$(lsb_release --codename | cut -f2)
echo $codename
sudo apt-get install -y neofetch & neofetch 

#troubleshoot wireless/network 
lspci -nnk | grep -iA2 net
lsusb
lsmod
iwconfig
rfkill list
lspci -nn
lspci -vnn | grep Network
lspci -nn | grep 0280 
lspci | grep Broadcom
lshw -c network 
sudo lshw -businfo | grep network
lspci -v
lspci -n

#clamav antivirus
clamdscan -V -> the version of ClamAV
sudo freshclam -> update the virus definition database or virus signature
clamscan -r /home -> check files in the all users home directories 
clamscan -r / -> check all files on the computer
clamscan -r --bell -i / -> check all files on the computer, but only display infected files and ring a bell when found a threat.
sudo clamscan -r /folder/to/scan/ | grep FOUND >> /path/to/save/report/myfile.txt -> put all the infected files list on a particular file
sudo lsof /var/log/clamav/freshclam.log
sudo /etc/init.d/clamav-freshclam start
sudo /etc/init.d/clamav-freshclam status
sudo clamscan --max-filesize=3999M --max-scansize=3999M --exclude-dir=/sys/* -i -r /
https://help.ubuntu.com/community/ClamAV

sudo apt-get install inetutils-traceroute

sudo apt-get install tasksel
tasksel --list-tasks (List the tasks available on a system.)
tasksel --task-packages web-server (List the packages that would be installed by that task)
tasksel --task-packages standard
tasksel --task-packages laptop
aptitude search ~pstandard ~prequired ~pimportant -F%p
"sudo apt-get install ubuntu-desktop^"
sudo dpkg-reconfigure tasksel

#Add Docker’s official GPG key
"curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -"
#Verify  key
sudo apt-key fingerprint 0EBFCD88
#set up the stable repository
sudo add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable"

chmod o+x vagrant_2.1.2_linux_amd64.zip
sudo unzip vagrant_2.1.2_linux_amd64.zip -d /mnt/vagrant
sudo sed -i -e '$a\' -e 'export PATH=$PATH:/mnt/vagrant' ~/.bashrc
source ~/.bashrc

Installing the 64-Bit JDK 9 

method1
Delete the .tar.gz file if you want to save disk space


tar -zxvf jdk-9.0.1_linux-x64_bin.tar.gz 
sudo mkdir -p /usr/java
sudo mv jdk-9.0.1 /usr/java
ls /usr/java/jdk-9.0.1/
sudo vi .bashrc
export JAVA_HOME=/usr/java/jdk-9.0.1/
export  PATH=$PATH:$JAVA_HOME/bin
source .bashrc 
echo $JAVA_HOME
java -version

uninstall
delete directory


method2
sudo apt-get install default-jdk

Unlike the remove command purge command removes everything.
useful if you do not want to save the configuration files or if you are having issues and want to start from a clean slate.
sudo apt-get purge package

uninstall
sudo apt-get remove default-jdk
sudo apt-get purge default-jdk
sudo apt-get autoremove default-jdk

When removing packages from your system with apt-get remove or apt-get purge, the package target will be removed.
any dependencies that were automatically installed in order to fulfill the installation requirements will remain behind
automatically remove any packages that were installed as dependencies that are no longer required by any packages
sudo apt-get autoremove

 remove all of the associated configuration files from the dependencies being removed
 sudo apt-get --purge autoremove
 
 remove any package files on the local system that are associated with packages that are no longer available from the repositories
 sudo apt-get autoclean
 
# Converting RPM packages to DEB packages
$ sudo alien htop-0.9-1.el6.rf.i686.rpm
# Converting a DEB package to a RPM
$ sudo alien -r htop_1.0.1-1_i386.deb
--------------------------------------------------------------------------------------
sudo systemctl reload apache2.service
apachectl configtest
/etc/apache2/apache2.conf

sudo apachectl configtest #test your Apache configuration
sudo tail -n 2 /var/log/apache2/error.log
ls /var/log/apache2/
grep -i -r error /var/log/apache2/
zgrep error /var/log/apache2/error.log.2.gz
grep -R '25/Apr/2020:00' | cut -d " " -f1,4,7,8,9 #date, IP, page, and status code in apache2 logs

#troubleshoot apache2
sudo journalctl -u apache2.service --since today --no-pager
sudo systemctl status apache2.service -l --no-pager
apache2ctl -t #check the config files 
apache2ctl -S #show parsed virtual host and run settings
/usr/sbin/apache2 -V
netstat -pant | grep -Ei 'apache|:80|:443'

#verify if service is online
systemctl -l --type service --all | grep apache2
service --status-all | grep apache2

ps aux | grep -E 'apache2|httpd'
killall apache2
systemctl status apache2
$ crontab -l
#journal watchdog every day at 07:00 AM
10 10 * * * DATE_VAR=$(echo "Date:..$(date)") && JOURNALCTL_VAR=$(journalctl --disk-usage) && CONCAT="$DATE_VAR $JOURNALCTL_VAR" && echo $CONCAT >> /home/bakadmin/journalctl_diary.out
--------------------------------------------------------------------------------------
#Enable your firewall,https://help.ubuntu.com/community/UFW
sudo apt-get install ufw

#The general (default) rules, allowing all outgoing and blocking all incoming traffic
sudo ufw default allow outgoing
sudo ufw default deny incoming



ufw enable
echo "y" | sudo ufw enable # automating w bash script
sudo ufw --force enable # automating w bash script


sudo ufw app info "Apache"
sudo ufw app info "Apache Secure"
sudo ufw app info "Apache Full"
sudo ufw app list | grep Nginx

sudo ufw app list #list which profiles are currently available


ufw allow http
ufw allow https #allow all incoming HTTPS (port 443) connections
sudo ufw allow "Apache Full"
sudo ufw allow “OpenSSH” #
sudo ufw allow "Nginx Full" #allow both HTTP and HTTPS traffic on the server (ports 80 and 443)
ufw allow 80
sudo ufw allow 22 #an alternative syntax is to specify the exact port number of the SSH service
ufw allow 443 # alternative syntax is to specify the port number of the HTTPS service
sudo ufw allow proto tcp from any to any port 80,443 #allow all incoming HTTP and HTTPS (ports 80 and 443) connections
sudo ufw allow from 203.0.113.103 to any port 3306 #allow the IP address 203.0.113.103 to connect to the server’s MySQL port
sudo ufw allow from 203.0.113.0/24 to any port 3306 #allow the entire 203.0.113.0/24 subnet to be able to connect MySQL server
sudo ufw allow from 203.0.113.103 to any port 5432 #Allow PostgreSQL Connection from Specific IP Address 
sudo ufw allow from 203.0.113.0/24 to any port 5432
sudo ufw allow out to 131.103.20.167 port 22 #create exception 
sudo ufw allow from 203.0.113.103 proto tcp to any port 22 #allow only SSH connections coming from the IP address 203.0.113.10
sudo ufw allow from 203.0.113.103 to any port 873 #allow only Rsync connections coming from the IP address 203.0.113.103
sudo ufw allow in on eth0 from 203.0.113.102
sudo ufw allow from 203.0.113.101
ufw allow proto tcp from any to any port 80,443,8080:8090 comment 'web app'

sudo ufw deny out 25 #Block Outgoing SMTP Mail
ufw deny https
ufw deny 443
sudo ufw deny from 203.0.113.100 #Block an IP Address
sudo ufw deny from 203.0.113.0/24 #Block a Subnet
sudo ufw deny in on eth0 from 203.0.113.100 #Block Incoming Connections to a Network Interface
ufw deny proto tcp from 10.0.0.0/8 to 192.168.0.1 port 25



ufw insert 3 deny to any port 22 from 10.0.0.135 proto tcp #insert rule 3

#let the sender know when traffic is being denied, rather than simply ignoring it. reject instead of deny
ufw reject telnet comment 'telnet is unencrypted'

sudo ufw status numbered #specify which rule you want to delete is by providing the rule ID
sudo ufw status verbose #The current set of rules (in optional verbose mode)
ufw status

sudo ufw delete 1
sudo ufw delete allow from 203.0.113.101 #Delete UFW Rule

#troubleshoot
ufw allow log 22/tcp #per  rule logging,By default, no logging is performed when a packet matches a rule
ls /var/log/ufw*
sudo ufw logging low #If logging is off, verify with If logging is off ufw status verbose
sudo service rsyslog status #see if rsyslogd is running
tail -f /var/log/ufw.log

sudo mkdir -p /etc/ufw/applications.d
sudo sh -c "echo '[NCPA]' > /etc/ufw/applications.d/ncpa"
sudo sh -c "echo 'title=Nagios Cross Platorm Agent' >> /etc/ufw/applications.d/ncpa"
sudo sh -c "echo 'description=Nagios Monitoring Agent' >> /etc/ufw/applications.d/ncpa"
sudo sh -c "echo 'ports=5693/tcp' >> /etc/ufw/applications.d/ncpa"
sudo ufw allow NCPA
sudo ufw reload



cat<<EOF | sudo tee /etc/ufw/applications.d/apache-server
[Apache]
title=Web Server (HTTP)
description=Apache web server.
ports=80/tcp

[Apache Secure]
title=Web Server (HTTPS)
description=Apache web server.
ports=443/tcp

[Apache Full]
title=Web Server (HTTP,HTTPS)
description=Apache web server.
ports=80,443/tcp
EOF

--------------------------------------------------------------------------------------
# Operating System: Ubuntu 16.04.5 LTS
$ cat /etc/ssh/sshd_config | grep PermitRootLogin
PermitRootLogin no
~$ cat /etc/ssh/sshd_config | grep 5901
Port 5901
$ sudo service ssh reload
--------------------------------------------------------------------------------------
# Operating System: Ubuntu 16.04.5 LTS
# creating new users for POP3 or SMTP (mail server) or FTP  no need to grant shell access to a user. 
# use special shell called "nologin"
# a replacement shell field for accounts that have been disabled or have other user level access such as ftp, pop3, smtp etc
useradd -s /usr/sbin/nologin tony
$ sudo usermod -s /usr/sbin/nologin member1
--------------------------------------------------------------------------------------------------------------------
#disable root account

sudo passwd -l root #lock the password for the root user
sudo usermod -L root #lock the password for the root user

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
usermod -aG sudo admin     #Debian/Ubuntu 
su admin #switch to that account to block root access.
sudo vim /etc/passwd
root:x:0:0:root:/root:/sbin/nologin
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
#apt-get install openssh-server
$ cat /etc/ssh/sshd_config | grep PermitRootLogin
PermitRootLogin prohibit-password
$ sudo sed -i 's/PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config
$ sudo service ssh restart

#disable ssh root access
#apt-get install openssh-server
$ sudo sed -i 's/PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
$ cat /etc/ssh/sshd_config | grep PermitRootLogin
PermitRootLogin no
$ sudo service ssh restart

#troubleshooting sshd log
$ tail -f /var/log/auth.log #live monitoring
$ sudo grep sshd /var/log/auth.log
$ sudo tail -f -n 20 /var/log/auth.log | grep 'sshd'
$ sudo journalctl -t sshd -f
$ sudo journalctl -t sshd -b0 #from the last boot
$ sudo journalctl -t sshd -b0 -r #from the last boot in the reverse order
$ grep -rsh sshd /var/log |sort
2022-04-04 12:37:00,788 - util.py[DEBUG]: Reading from /etc/ssh/sshd_config (quiet=False)
2022-04-04 12:37:00,789 - util.py[DEBUG]: Read 2540 bytes from /etc/ssh/sshd_config
2022-04-04 12:37:00,794 - util.py[DEBUG]: Read 2540 bytes from /etc/ssh/sshd_config
2022-04-04 12:37:00,794 - util.py[DEBUG]: Reading from /etc/ssh/sshd_config (quiet=False)
2022-04-04 12:37:07,919 - util.py[DEBUG]: Read 2540 bytes from /etc/ssh/sshd_config
2022-04-04 12:37:07,919 - util.py[DEBUG]: Reading from /etc/ssh/sshd_config (quiet=False)

------------------------------------------------------------------------------------------
#disable root user access to a system, by restricting access to login and sshd services,via PAM

#add the configuration below in both files
auth    required       pam_listfile.so \
        onerr=succeed  item=user  sense=deny  file=/etc/ssh/deniedusers
	
sudo vim /etc/pam.d/login
sudo vim /etc/pam.d/sshd

sudo vim /etc/ssh/deniedusers #Add the user root
sudo chmod 600 /etc/ssh/deniedusers
--------------------------------------------------------------------------------------
$ sudo /usr/sbin/visudo

User_name Machine_name=(Effective_user) command

    User_name: This is the name of ‘sudo‘ user.
     Machine_name: This is the host name, in which ‘sudo‘ command is valid. Useful when you have lots of host machines.
    (Effective_user): The ‘Effective user’ that are allowed to execute the commands. This column lets you allows users to execute System Commands.
     Command: command or a set of commands which user may run.

# Using syslog To Track All sudo Commands
grep sudo /var/log/messages

verify whether or not the user belongs to group=sudo 
$ groups
$ id
add an existing user with id=foo to group=sudo
$ sudo adduser foo sudo
--------------------------------------------------------------------------------------
update / install mozilla firefox
$ sudo apt-get update
$ sudo apt install firefox
remove
$ sudo apt-get purge firefox
--------------------------------------------------------------------------------------
update / install mozilla firefox - method 2nd
tar xvjf firefox-68.0.tar.bz2
To start Firefox, run the firefox script in the firefox folder: 
~/firefox/firefox
--------------------------------------------------------------------------------------
update / install virtualbox
dpkg -l | grep virtualbox
sudo dpkg -i virtualbox-5.2_5.2.30-130521~Ubuntu~xenial_amd64.deb # method1
sudo apt install ./virtualbox-5.2_5.2.30-130521~Ubuntu~xenial_amd64.deb #method2
--------------------------------------------------------------------------------------
update / install vagrant
wget https://releases.hashicorp.com/vagrant/2.2.5/vagrant_2.2.5_x86_64.deb
sudo dpkg -i vagrant_2.2.5_x86_64.deb 
--------------------------------------------------------------------------------------
"Hold" (held back). Held back packages cannot be installed, removed, purged, or upgraded unless the hold mark is removed.
apt-mark hold kubelet kubeadm kubectl
--------------------------------------------------------------------------------------
wget -nv https://download.opensuse.org/repositories/security:zeek/xUbuntu_19.04/Release.key -O Release.key
sudo apt-key add - < Release.key
apt-key list
$ ls -lai /etc/apt/trusted.gpg.d
sudo apt-key del AAF3 EB04 4C49 C402 A9E7  B9AE 69D1 B2AA EE3D 166A
--------------------------------------------------------------------------------------
#Problem
"E:Conflicting values set for option Signed-By regarding source https://packages.microsoft.com/repos/code/ stable: /etc/apt/trusted.gpg.d/packages.microsoft.gpg != , E:The list of sources could not be read."}

 rm /etc/apt/sources.list.d/vscode.list
 rm /etc/apt/sources.list.d/vscode.list.save
 rm  /etc/apt/trusted.gpg.d/ansible_ubuntu_ansible.gpg~ 
 rm  /etc/apt/trusted.gpg.d/packages.microsoft.gpg~ 
--------------------------------------------------------------------------------------
Troubleshooting: Could not get lock /var/lib/dpkg/lock’

Method 1:
Unable to lock (/var/lib/dpkg/)
ps aux | grep apt
sudo fuser -cuk /var/lib/dpkg/loc
sudo rm -f /var/lib/dpkg/lock

sudo fuser -cuk /var/cache/apt/archives/lock
sudo rm -f /var/cache/apt/archives/lock

Important tip: never ever delete lock files as a first step – this should only be your last resort.

Method 2:
sudo dpkg --configure -a 
cat /proc/mounts
dmesg
sudo mount / -o remount,rw

Method 3:
ps aux | grep -i apt
sudo kill -9 <process id>
sudo killall apt apt-get

Method 4:
lsof /var/lib/dpkg/lock
lsof /var/lib/apt/lists/lock
lsof /var/cache/apt/archives/lock
sudo kill -9 PID
sudo rm /var/lib/apt/lists/lock
sudo rm /var/cache/apt/archives/lock
sudo rm /var/lib/dpkg/lock
sudo dpkg --configure -a
--------------------------------------------------------------------------------------
Troubleshooting: “dpkg: error: dpkg frontend is locked by another process”

lsof /var/lib/dpkg/lock-frontend
sudo kill -9 PID
sudo rm /var/lib/dpkg/lock-frontend
sudo dpkg --configure -a
--------------------------------------------------------------------------------------
----------------------------------------------------------------------------------------------------
dpkg -i package.deb
does not attempt to perform installs from the repository, and instead looks for .deb packages in the current directory, or the path supplied
sudo dpkg --install debfile.deb

dpkg -r package.deb -> uninstall package
dpkg -P wget -> remove package with Purge 


List Files Installed by a Package
$ dpkg -L kubectl
list all packages (whether installed or not) that contain that pattern
$ dpkg -l kubectl*
dpkg -l -> list all the installed packages
dpkg -L wget -> what has been installed of wget
dpkg -l | grep virtualbox*
dpkg -p packagename -> see details for a specific package
dpkg --list | grep linux-image -> list all installed kernel
sudo apt list --installed | grep tmux #find out whether a specific package is installed
sudo dpkg-query -l | grep tmux
dpkg-query -L <package_name> # search for package
echo $PATH # verify if the package is in the $PATH
sudo dpkg-query -f '${binary:Package}\n' -W > packages_list.txt #list of all installed packages
sudo xargs -a packages_list.txt apt install #install the same packages from the file
sudo dpkg-query -f '${binary:Package}\n' -W | wc -l #Count the Number of Installed Packages

dpkg-query -W
dpkg-query -s linux-headers-$(uname -r) -> list current kernel
# all packages are labelled as one of: required, important, standard, optional, or extra.
dpkg-query -Wf '${Package;-40}${Priority}\n'
# Remove optional and extra packages
dpkg-query -Wf '${Package;-40}${Priority}\n' | awk '$2 ~ /optional|extra/ { print $1 }' | xargs -I % sudo apt-get -y purge %

list all packages from a repository
grep neo4j /var/lib/apt/lists/http.kali.org_kali_dists_kali-rolling_*_Packages

list all packages from PPAs
grep ^Package: /var/lib/apt/lists/ppa.launchpad.net_*_Packages

Show Info about a .deb Package
dpkg --info debfile.deb

$ dpkg --get-selections kubectl*
list of all of the packages installed or removed but not purged:
dpkg --get-selections | awk '$2 ~ /^install/'
get a list of removed packages that have not had their configuration files purged
$ dpkg --get-selections | awk '$2 !~ /^install/'

print out the package that installed the file 
Search for What Package Installs to a Location
dpkg -S /usr/bin/kubectl
dpkg -S /usr/bin
dpkg -S /usr
dpkg -S {package_name} -> see details for a specific package
$ dpkg -s unzip
$ dpkg -s unzip | grep -i Architecture

clear the state of all non-essential packages from the new computer
sudo dpkg --clear-selections

in comparison to the above dpkg command is that gdebi will automatically download and install all required prerequisite packages.
sudo gdebi example.deb 

sudo dpkg-reconfigure tasksel
----------------------------------------------------------------------------------------------------
#replicate the set of packages installed on one system to another
#This list can then be copied to the second machine and imported,export your package list
dpkg --get-selections > ~/packagelist.txt

The actual installation and upgrade procedure will be handled by a tool called dselectsudo apt-get update
sudo apt-get install dselect
sudo dselect update
sudo dpkg --set-selections < packagelist.txt
sudo apt-get dselect-upgrade
----------------------------------------------------------------------------------------------------
dpkg --get-selections > list.txt #Create a backup
dpkg --clear-selections #(on another system) restore installations from that list
sudo dpkg --set-selections < list.txt
sudo apt-get autoremove # get rid of stale packages

#Make backup
sudo apt-clone clone path-to/apt-clone-state-ubuntu-$(lsb_release -sr)-$(date +%F).tar.gz
#Restore backup
sudo apt-clone restore path-to/apt-clone-state-ubuntu.tar.gz
#Restore to newer release
sudo apt-clone restore-new-distro path-to/apt-clone-state-ubuntu.tar.gz $(lsb_release -sc)

dpkg -l | awk  '{print $2}' > package_list.txt
xargs < package_list.txt apt-get install -y
----------------------------------------------------------------------------------------------------
#crontab

/var/spool/cron/crontabs #The user-specific cron jobs are located,recommended to edit using the crontab -e command.
sudo cat /var/spool/cron/crontabs/root


sudo systemctl status cron
ps -ef | grep cron | grep -v grep #Check that cron is running

journalctl -u cron #systemd cron job log 
journalctl -t CRON
journalctl -t CRON -f # watch live
journalctl -t CRON | tail -20
journalctl --since 'today' -t CRON # between time range
journalctl --since '2022-02-16 21:00:00' --until '2022-02-16 22:00:00' -t CRON # between time range
   journalctl --since "2015-01-10 17:15:00"
   journalctl -S "2020-91-12 07:00:00"
   journalctl -S -1d #The “d” stands for “day”, and the “-1” means one day in the past
   journalctl -S -1h
   journalctl --since "2015-06-26 23:15:00" --until "2015-06-26 23:20:00"
   journalctl -S "2020-91-12 07:00:00" -U "2020-91-12 07:15:00"
   journalctl --since yesterday
   journalctl -S yesterday
   journalctl --since yesterday --until now
   journalctl --since today
   journalctl -S -2d -U today #everything from two days ago up until the start of today
   journalctl --since 09:00 --until "1 hour ago"
   journalctl --since '1h ago' --until '10 min ago'
   

tail -f /var/log/syslog | grep CRON
tail -f -n 5 /var/log/syslog | grep CRON  #print the new messages as it is logged in real-time, last 5 lines
grep CRON /var/log/syslog
grep CRON.*\(root\) /var/log/syslog #see jobs run by a certain user
grep -i cron /var/log/syslog
awk '/^May 20 06:25:*/,/May 20 08:29:*/' /var/log/syslog | grep cron.daily #between time range
sed -n '/May 20 06:27:53/,/May 20 06:28:22/p' /var/log/syslog

nano /etc/crontab
ls -ld /etc/cron.* #default cron execution times, every day, every hour every month

crontab -l -u vagrant #scheduled jobs for the specified user
cat /var/spool/cron/crontabs/ubuntu # view cron

#cron job script
#!/bin/bash
[command]
date > /home/user/last_completed
#cron job script task
* * * * * bash /path/to/script.bash

cat /etc/crontab  #cron timings for /etc/cron.{daily,weekly,monthly}/
grep run-parts /etc/crontab
run-parts -v /etc/cron.daily #force to run daily cron jobs
 
$ cat /etc/cron.allow
barak
$ sudo systemctl restart cron/crond
$ cat /etc/cron.d/barak_job
*/1 * * * * barak echo "Nightly Backup Successful: $(date)" >> /tmp/mybackup.log
$ crontab -u barak -l
#*/1 * * * * barak echo "Nightly Backup Successful: $(date) runs" >> /tmp/barak_job.log
$ sudo tail -f /var/log/syslog | grep --color=auto CRON
----------------------------------------------------------------------------------------------------
apt-get install p7zip
p7zip -d something.7z #extract 7z 
----------------------------------------------------------------------------------------------------
apt-get install megatools
megadl 'https://mega.co.nz/#F!<some_id>!<some_other_id>' # download mega files
----------------------------------------------------------------------------------------------------
#development packages 
apt-get install -y build-essential 

----------------------------------------------------------------------------------------------------
#verify rsync is installed
apt list --installed | grep rsync
rsync --version
----------------------------------------------------------------------------------------------------

