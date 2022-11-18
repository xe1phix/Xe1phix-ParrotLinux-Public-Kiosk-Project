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


sudo apt-get install package=version -> Install specific version


there are multiple versions of a package within the repositories, with a single default package.
apt-cache policy package


maintains its own database of information, which includes the installation path of every file controlled by a package in the database.
sudo apt-get update
sudo apt-get install apt-file
sudo apt-file update
only work for file locations that are installed directly by a package. 
Any file that is created through post-installation scripts will not be found
sudo apt-file search /usr/bin/kubectl



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

