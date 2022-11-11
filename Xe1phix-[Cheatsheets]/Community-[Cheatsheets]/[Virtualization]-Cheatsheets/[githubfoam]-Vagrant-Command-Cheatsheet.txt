------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
vagrant up vg-mrtg-03 --debug-timestamp #debug vagrant
vagrant up vg-mrtg-03 --debug
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
#from host(linux host) to vagrant guest /windows host (winscp)
scp -P 2222 your_file vagrant@127.0.0.1:.

#copy the file back on vagrant guest to your local host
scp -P 2222 vagrant@127.0.0.1:/PATH/filename .

#from host(windows host) to vagrant guest (centos)
vagrant ssh-config # IdentityFile path for handle "i"
>scp -P 2200 -i IdentityFile(path) test.text vagrant@127.0.0.1:/tmp

#copy file from vagrant guest (ubuntu) to host(windows host)
>vagrant ssh vg-nagios-05 -c "sudo cat /usr/local/nagios/etc/objects/timeperiods.cfg" > a.txt
vagrant ssh-config > config.txt
"scp -F config.txt default:/path/to/file ." #default is the vagrant name

#running multiple machines, from vagrant guest linux to windows host 
vagrant ssh-config vg-nagios-05> vg-nagios-05-config.txt
"scp -F vg-nagios-05-config.txt vg-nagios-05:/usr/local/nagios/etc/objects/timeperiods.cfg ."
>scp -F vg-mrtg-03-config.txt vg-mrtg-03:/etc/mrtg/* mrtg

#running multiple machines, from windows host to vagrant guest linux  
vagrant ssh-config vg-nagios-02> vg-nagios-02-ssh-config.txt
>scp -F vg-nagios-02-ssh-config.txt C:\Users\voltran\Downloads\tap.png vg-nagios-02:/home/vagrant
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
# Windows HOST, linux vagrant vm guest, run command on vagrant vm guest from windows host
>vagrant ssh vg-mrtg-03 -c "ls -lai /etc/snmp"

# Linux HOST, linux vagrant vm guest, run command on vagrant vm guest from linux host
vagrant ssh -c 'cat - > ~/file_on_guest.txt'

------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
# Linux HOST, linux vagrant vm guest
from guest to host copy file:
vagrant ssh -c 'cat ~/file_on_guest.txt' > ~/file_on_host.txt
from host to guest copy file:
cat ~/file_on_host.txt | vagrant ssh -c 'cat - > ~/file_on_guest.txt'

------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
#copy file from host to vagrant vm guest, multiple vagrant vm machines
$vagrant upload ~/Desktop/file.sh host1 #  /home/vagrant on host1
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
#copy file from host to vagrant vm guest in Vagrantfile
config.vm.provision "file", source: "~/otherfolder/.", destination: "/remote/otherlocation" #using globing on the host machine to grab all files within a folder
config.vm.provision "file", source: "/otherfolder", destination: "/remote/otherlocation"
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
vagrant port vg-docker-01 #display the full list of guest ports mapped to the host machine ports.
------------------------------------------------------------------------------------------
vagrant init --template Vagrantfile.ansible.role.erb
vagrant up --provider=libvirt "vg-docker-01" 
------------------------------------------------------------------------------------------
vagrant box add --insecure --provider virtualbox "kalilinux/rolling" #self-signed SSL issues
------------------------------------------------------------------------------------------
PROBLEM:Error: 
Vagrant cannot forward the specified ports on this VM, since they
would collide with some other application that is already listening
on these ports. The forwarded port to 2201 is already in use
on the host machine.

Sometimes, Vagrant will attempt to auto-correct this for you. In this
case, Vagrant was unable to. This is usually because the guest machine
is in a state which doesn't allow modifying port forwarding. You could
try 'vagrant reload' (equivalent of running a halt followed by an up)
so vagrant can attempt to auto-correct this upon booting. Be warned
that any unsaved work might be lost.

fix:vagrant reload vg-ubuntu-01
------------------------------------------------------------------------------------------
PROBLEM:Error: schannel: next InitializeSecurityContext failed: Unknown error (0x80092012) - The revocation function was unable to check revocation for the certificate
FIX:vagrant box add --insecure
FIX:vagrantfile
kalicluster.vm.box_download_insecure=true
------------------------------------------------------------------------------------------
#linux
curl -O https://raw.githubusercontent.com/rapid7/metasploitable3/master/Vagrantfile && vagrant up

#windows
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/rapid7/metasploitable3/master/Vagrantfile" -OutFile "Vagrantfile"
vagrant up
------------------------------------------------------------------------------------------
vagrant ssh vgnode04 -c "hostnamectl" # run command wo logging in
vagrant ssh vg-mrtg-03 -c "ls -lai /etc/mrtg"
------------------------------------------------------------------------------------------
export USERNAME="testuser"
$ vagrant cloud auth login --username $USERNAME
In a moment we will ask for your username and password to HashiCorp's
Vagrant Cloud. After authenticating, we will store an access token locally on
disk. Your login details will be transmitted over a secure connection, and
are never stored on disk locally.

If you do not have an Vagrant Cloud account, sign up at
https://www.vagrantcloud.com

Vagrant Cloud username or email: vagrantfoam
Password (will be hidden):

export TOKEN="testtoken"
$ vagrant cloud auth login --username $USERNAME --token $TOKEN
The token was successfully saved.
You are already logged in.
$ vagrant cloud auth whoami
Currently logged in as vagrantfoam
$ vagrant cloud auth logout
You are logged out.

$ vagrant cloud auth login --token $TOKEN
The token was successfully saved.
You are already logged in
$ vagrant cloud auth whoami
Currently logged in as vagrantfoam
$ vagrant cloud auth logout
You are logged out.

vagrant cloud publish $USERNAME/supertest 1.0.0 virtualbox boxes/my/virtualbox.box -d "A really cool box to download and use" --version-description "A cool version" --release --short-description "Download me!"
vagrant cloud search hashicorp --limit 5
------------------------------------------------------------------------------------------
echo "=============================Install Vagrant without generic linux install============================================================="
#https://www.vagrantup.com/downloads
# export VAGRANT_CURRENT_VERSION="2.2.9"
apt-get install -qqy unzip jq

# https://releases.hashicorp.com/vagrant/2.2.9/vagrant_2.2.9_SHA256SUMS
export VAGRANT_CURRENT_VERSION="$(curl -s https://checkpoint-api.hashicorp.com/v1/check/vagrant | jq -r -M '.current_version')"
export VAGRANT_URL="https://releases.hashicorp.com/vagrant/${VAGRANT_CURRENT_VERSION}/vagrant_${VAGRANT_CURRENT_VERSION}_x86_64.deb"
export VAGRANT_SHA256_URL="https://releases.hashicorp.com/vagrant/$VAGRANT_CURRENT_VERSION/vagrant_${VAGRANT_CURRENT_VERSION}_SHA256SUMS"
export  VAGRANT_SHA256_SIG_URL="https://releases.hashicorp.com/vagrant/$VAGRANT_CURRENT_VERSION/vagrant_${VAGRANT_CURRENT_VERSION}_SHA256SUMS.sig"

# wget -nv "${VAGRANT_URL}"
curl -LO "${VAGRANT_URL}"
curl -LO "${VAGRANT_SHA256_URL}"
curl -LO "${VAGRANT_SHA256_SIG_URL}"
export HASHICORP_PUBLIC_KEY_URL="https://keybase.io/hashicorp/pgp_keys.asc" #https://www.hashicorp.com/security
`curl -sSL "${HASHICORP_PUBLIC_KEY_URL}" | gpg --import -` # import the public key (PGP key)
gpg --verify "vagrant_${VAGRANT_CURRENT_VERSION}_SHA256SUMS.sig" "vagrant_${VAGRANT_CURRENT_VERSION}_SHA256SUMS" 2>/dev/null #Verify the signature file is untampered

sha256sum  vagrant_${VAGRANT_CURRENT_VERSION}_x86_64.deb # via sha256sum
openssl dgst -sha256 vagrant_${VAGRANT_CURRENT_VERSION}_x86_64.deb # via openssl

echo $(shasum -a 256 -c "vagrant_${VAGRANT_CURRENT_VERSION}_SHA256SUMS" 2>&1 | grep OK)


dpkg -i vagrant_${VAGRANT_CURRENT_VERSION}_x86_64.deb
vagrant version
------------------------------------------------------------------------------------------
          - echo "=============Install Vagrant with generic linux install=============="
	  - #https://www.vagrantup.com/downloads
	  - export VAGRANT_CURRENT_VERSION="2.2.9"
          - sudo apt-get install -qqy unzip jq
          - VAGRANT_CURRENT_VERSION="$(curl -s https://checkpoint-api.hashicorp.com/v1/check/vagrant | jq -r -M '.current_version')"
          - VAGRANT_URL="https://releases.hashicorp.com/vagrant/$VAGRANT_CURRENT_VERSION/vagrant_${VAGRANT_CURRENT_VERSION}_linux_amd64.zip"
          - VAGRANT_SHA256_URL="https://releases.hashicorp.com/vagrant/$VAGRANT_CURRENT_VERSION/vagrant_${VAGRANT_CURRENT_VERSION}_SHA256SUMS"
          - VAGRANT_SHA256_SIG_URL="https://releases.hashicorp.com/vagrant/$VAGRANT_CURRENT_VERSION/vagrant_${VAGRANT_CURRENT_VERSION}_SHA256SUMS.sig"
	  - curl -LO "${VAGRANT_URL}"
          - curl -LO "${VAGRANT_SHA256_URL}"
          - curl -LO "${VAGRANT_SHA256_SIG_URL}"
	  - HASHICORP_PUBLIC_KEY_URL="https://keybase.io/hashicorp/pgp_keys.asc" #https://www.hashicorp.com/security
          - 'curl -sSL "${HASHICORP_PUBLIC_KEY_URL}" | gpg --import -' # import the public key (PGP key)
          - gpg --verify "vagrant_${VAGRANT_CURRENT_VERSION}_SHA256SUMS.sig" "vagrant_${VAGRANT_CURRENT_VERSION}_SHA256SUMS" 2>/dev/null #Verify the signature file is untampered
          - shasum -a 256 -c "vagrant_${VAGRANT_CURRENT_VERSION}_SHA256SUMS" | sudo tee output.txt  # Verify the SHASUM matches the archive.
          - cat output.txt  | grep OK # print OK
          - unzip "vagrant_${VAGRANT_CURRENT_VERSION}_linux_amd64.zip"
          - sudo cp vagrant /usr/bin
          - vagrant version	  
------------------------------------------------------------------------------------------
FIX:
vagrant box add "bento/ubuntu-16.04" --provider=virtualbox

PROBLEM:
$ sudo vagrant box add "bento/ubuntu-19.10"

==> box: Loading metadata for box 'bento/ubuntu-19.10'

    box: URL: https://vagrantcloud.com/bento/ubuntu-19.10

This box can work with multiple providers! The providers that it

can work with are listed below. Please review the list and choose

the provider you will be working with.

1) parallels

2) virtualbox

3) vmware_desktop

Enter your choice:
------------------------------------------------------------------------------------------
vagrant up --no-parallel #
------------------------------------------------------------------------------------------
# Install missing plugins

unless Vagrant.has_plugin?("vagrant-reload")
  puts 'Installing vagrant-reload Plugin...'
  system('vagrant plugin install vagrant-reload')
end
------------------------------------------------------------------------------------------
vagrant plugin list 

vagrant plugin install vagrant-disksize #plugin to resize disks in VirtualBox
vagrant plugin install vagrant-libvirt #The vagrant-libvirt plugin is required when using KVM on Linux
vagrant plugin install vagrant-mutate #Convert vagrant boxes to work with different providers
vagrant plugin install vagrant-cachier #plugin for caching packages that are downloaded while setting up the  environment
vagrant plugin install vagrant-hostmanager #plugin that manages hosts files within a multi-machine environment 

vagrant plugin install vagrant-reload #plugin that adds a reload provisioning step that can be used to do a reload on a VM during provisioning.
config.vm.provision :reload #add to your Vagrantfile

vagrant plugin install vagrant-vbguest #plugin enables guest support for some VirtualBox features like shared folders,installing guest additions after each and every new installation and keeping them updated after a new version of VirtualBox is released
config.vbguest.auto_update = true #add to your Vagrantfile
------------------------------------------------------------------------------------------
change something from the Vagrantfile, apply the changes by reloading the VM
vagrant reload
copy a file to your vagrant machine,
scp -P 2222 -i /path/to/private_key someFileName.txt vagrant@127.0.0.1
use a manually downloaded image, add the box to Vagrant and create a matching Vagrantfile
vagrant box add osm/releasesix /path/to/vagrant.box
vagrant init osm/releasesix
add more forwarded ports
config.vm.network "forwarded_port", guest: 3000, host: 3000
vagrant reload
------------------------------------------------------------------------------------------
Create a base Vagrantfile
vagrant init hashicorp/precise64
Create a minimal Vagrantfile (no comments or helpers)
vagrant init -m hashicorp/precise64
Create a Vagrantfile with the specific box, from the specific box URL
vagrant init my-company-box https://boxes.company.com/my-company.box
Create a Vagrantfile, locking the box to a version constraint
vagrant init --box-version '> 0.1.5' hashicorp/precise64

vagrant global-status -> Lists "id" and "name" of virtual machines
vagrant global-status --prune

vagrant status -> Overview about the virtual machines
vagrant destroy -f -> Destroys all virtual machines with force
vagrant destroy gluster2 -f -> Destroys only gluster2
vagrant destroy id  -> Destroys only vagrant machine 
vagrant destroy gluster2 -f -> Destroys only gluster2 with force

vagrant box remove ubuntu/xenial64 --box-version 20180420.0.0
vagrant box add precise64 https://files.hashicorp.com/precise64.box

vagrant up -> Spins up virtual machines which are currently down
vagrant up gluster2 -> Spins up gluster2 virtual machine if currently down
vagrant halt gluster2 -> Halts gluster2 virtual machine
------------------------------------------------------------------------------------------
vagrant provision id -> Runs vagrant machine with ansible shell etc provisioning configured in Vagrant file
------------------------------------------------------------------------------------------
#troubleshooting

vagrant up --debug &> vagrant.log -> Runs in debug mode to troubleshoot virtual machine
vagrant up --provision --debug &> vagrant.log -> Runs in debug mode to trouble shoot vagrant provisioning

On Windows, at command prompt:
set VAGRANT_LOG=info
vagrant up
------------------------------------------------------------------------------------------
VBoxManage list runningvms -> Find running vm to box
vagrant package --base xxxxx_1522057296984_52705 --output ubuntu1604.box --> Package running vm as vagrant box

vagrant ssh-config ID -> Details of vagrant vm guest
ssh vagrant@hostname -i /path/to/vagrantfile/.vagrant/machines/app/virtualbox/private_key -> Connect with vagrant insecure ssh key

vagrant ssh-config --host db-server >> ~/.ssh/config -> Add VMs config to ~/.ssh/config 


------------------------------------------------------------------------------------------
Generating a new SSH key
ssh-keygen -t rsa -b 4096 -C "your_email@example.com"
 
run ssh-agent
eval `ssh-agent -s`

Ensure the ssh-agent is running
$(ssh-agent -s)
Agent pid 3906

Add your SSH private key to the ssh-agent
$ ssh-add ~/.ssh/id_rsa

private key must be available to the local ssh-agent. You can check with ssh-add -L
$ ssh-add -L

add your public key to ~/.ssh/authorized_keys on the Vagrant VM guest
ssh-copy-id -p 2222 vagrant@localhost

#copy public key to vagrant VM guest
cat ~/.ssh/id_rsa.pub | ssh USER@HOST "mkdir -p ~/.ssh && cat >> ~/.ssh/authorized_keys"
cat ~/.ssh/id_rsa.pub | ssh -p 2200 vagrant@127.0.0.1 "mkdir -p ~/.ssh && cat >> ~/.ssh/authorized_keys"

# Install Chef on the Vagrant box.
vagrant plugin install vagrant-omnibus
#Berkshelf enabled Chef environment
vagrant plugin install vagrant-berkshelf
#
------------------------------------------------------------------------------------------
----------CONVERTING VBOX VMS INTO VAGRANT BOXES------------------------------------------
------------------------------------------------------------------------------------------
#Create first a CentOS virtualbox VM then convert to a vagrant box

#Create a new virtual machine with the following settings:
    Name: centos74minimal
    Type: Linux
    Version: Redhat 64
    Memory Size: 1024MB (to taste)
    New Virtual Disk: [Type: VMDK, Size: 40 GB]
		Disable floppy
    Disable audio
    Disable USB
    system-processor-2x
    general-advanced-dragndrop-bidirectional
    Ensure Network Adapter 1 is set to NAT
    Add this port-forwarding rule: [Name: SSH, Protocol: TCP, Host IP: blank, Host Port: 2222, Guest IP: blank, Guest Port: 22]
 #Install operating system
    standard partition-auto
    set hostname
    network disabled
    sudo passwd root
    set the user to vagrant and the password to vagrant.
    make this user administrator
 #Post install
 vagrant@vagranthost ~]$ hostnamectl
   Static hostname: vagranthost
         Icon name: computer-vm
           Chassis: vm
        Machine ID: 0627840c87874e83a094d51ebd04e0d2
           Boot ID: 230e703e6a9e4774b4d99ea1ffffd909
    Virtualization: kvm
  Operating System: CentOS Linux 7 (Core)
       CPE OS Name: cpe:/o:centos:centos:7
            Kernel: Linux 3.10.0-693.el7.x86_64
      Architecture: x86-64
[vagrant@vagranthost ~]$ cat /etc/hosts
127.0.0.1   localhost localhost.localdomain localhost4 localhost4.localdomain4
::1         localhost localhost.localdomain localhost6 localhost6.localdomain6
[vagrant@vagranthost ~]$ ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN qlen 1
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: enp0s3: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP qlen 1000
    link/ether 08:00:27:bf:3e:08 brd ff:ff:ff:ff:ff:ff
    inet 10.0.2.15/24 brd 10.0.2.255 scope global dynamic enp0s3
       valid_lft 86299sec preferred_lft 86299sec
    inet6 fe80::a343:aecc:ce58:ed49/64 scope link 
       valid_lft forever preferred_lft forever
3: virbr0: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500 qdisc noqueue state DOWN qlen 1000
    link/ether 52:54:00:89:0f:5d brd ff:ff:ff:ff:ff:ff
    inet 192.168.122.1/24 brd 192.168.122.255 scope global virbr0
       valid_lft forever preferred_lft forever
4: virbr0-nic: <BROADCAST,MULTICAST> mtu 1500 qdisc pfifo_fast master virbr0 state DOWN qlen 1000
    link/ether 52:54:00:89:0f:5d brd ff:ff:ff:ff:ff:ff
[vagrant@vagranthost ~]$ ifconfig
enp0s3: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.0.2.15  netmask 255.255.255.0  broadcast 10.0.2.255
        inet6 fe80::a343:aecc:ce58:ed49  prefixlen 64  scopeid 0x20<link>
        ether 08:00:27:bf:3e:08  txqueuelen 1000  (Ethernet)
        RX packets 33  bytes 5821 (5.6 KiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 69  bytes 8057 (7.8 KiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
        loop  txqueuelen 1  (Local Loopback)
        RX packets 72  bytes 5752 (5.6 KiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 72  bytes 5752 (5.6 KiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

virbr0: flags=4099<UP,BROADCAST,MULTICAST>  mtu 1500
        inet 192.168.122.1  netmask 255.255.255.0  broadcast 192.168.122.255
        ether 52:54:00:89:0f:5d  txqueuelen 1000  (Ethernet)
        RX packets 0  bytes 0 (0.0 B)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 0  bytes 0 (0.0 B)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

[vagrant@vagranthost ~]$ free -h
              total        used        free      shared  buff/cache   available
Mem:           1.8G        694M        686M        9.5M        458M        957M
Swap:          1.0G          0B        1.0G

[vagrant@vagranthost ~]$ df -h
Filesystem      Size  Used Avail Use% Mounted on
/dev/sda2        38G  4.1G   34G  11% /
devtmpfs        906M     0  906M   0% /dev
tmpfs           920M     0  920M   0% /dev/shm
tmpfs           920M  8.8M  911M   1% /run
tmpfs           920M     0  920M   0% /sys/fs/cgroup
/dev/sda1      1014M  173M  842M  18% /boot
tmpfs           184M  4.0K  184M   1% /run/user/42
tmpfs           184M   16K  184M   1% /run/user/1000

# VBox Guest Additions. attach CDROM from menu
sudo mount /dev/cdrom /mnt
cd /mnt
sudo ./VBoxLinuxAdditions.run
sudo umount /dev/cdrom /mnt
verify
lsmod | grep vboxguest

sudo passwd root
su -
sudo visudo -f /etc/sudoers.d/vagrant
# add vagrant user
vagrant ALL=(ALL) NOPASSWD:ALL
# test sudoers
sudo pwd

#firewall && ssh for vagrant connections
sudo systemctl stop firewalld
sudo systemctl disable firewalld
sudo systemctl enable sshd.service
sudo systemctl start sshd.service
sudo systemctl status sshd.service
sudo chkconfig firewalld off

sudo yum update -y
sudo yum upgrade -y
sudo shutdown -r now

#Install vagrant key
mkdir -p /home/vagrant/.ssh
chmod 700 /home/vagrant/.ssh
wget --no-check-certificate \
          https://raw.github.com/mitchellh/vagrant/master/keys/vagrant.pub \
          -O /home/vagrant/.ssh/authorized_keys
chmod 600 /home/vagrant/.ssh/authorized_keys
chown -R vagrant /home/vagrant/.ssh
sudo vi /etc/ssh/sshd_config
#Find and uncomment the following line because we added the Vagrant key above to the authorized_keys file:
AuthorizedKeysFile %h/.ssh/authorized_keys

#zero out the drive
sudo yum clean all
sudo rm -rf /var/cache/yum
sudo dd if=/dev/zero of=/EMPTY bs=1M
sudo rm -f /EMPTY
cat /dev/null > ~/.bash_history && history -c && exit

#Repackaging. On VirtualBox GUI "centos74minima" is seen.Or VBoxManage list runningvms.
vagrant package --base centos74minimal --output centos74minimal.box
vagrant box add "centos74minimal/v1.0" centos74minimal.box
vagrant box list
vagrant init "centos74minimal/v1.0"
vagrant up
vagrant ssh
------------------------------------------------------------------------------------------
#Create first a Fedora27 virtualbox VM then convert to a vagrant box

#Create a new virtual machine with the following settings:
    Memory Size: 1024MB (to taste)
    New Virtual Disk: [Type: VMDK, Size: 40 GB]
		Disable floppy
    Disable audio
    Disable USB
    system-processor-2x
    general-advanced-dragndrop-bidirectional
    Ensure Network Adapter 1 is set to NAT
    Add this port-forwarding rule: [Name: SSH, Protocol: TCP, Host IP: blank, Host Port: 2222, Guest IP: blank, Guest Port: 22]
 #Install operating system
    standard partition-auto
    set hostname
    network disabled
    sudo passwd root
    set the user to vagrant and the password to vagrant.
    make this user administrator
    
 #Post install
[vagrant@vagranthost ~]$ hostnamectl
   Static hostname: vagranthost
         Icon name: computer-vm
           Chassis: vm
        Machine ID: d555cb57d31d495db0460d58ff0f83d4
           Boot ID: b708585c23634769a33e46ed9985f3f1
    Virtualization: oracle
  Operating System: Fedora 27 (Server Edition)
       CPE OS Name: cpe:/o:fedoraproject:fedora:27
            Kernel: Linux 4.13.9-300.fc27.x86_64
      Architecture: x86-64
[vagrant@vagranthost ~]$ ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host
       valid_lft forever preferred_lft forever
2: enp0s3: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
    link/ether 08:00:27:45:a1:53 brd ff:ff:ff:ff:ff:ff
    inet 10.0.2.15/24 brd 10.0.2.255 scope global dynamic enp0s3
       valid_lft 86045sec preferred_lft 86045sec
    inet6 fe80::8ace:6cca:318:283d/64 scope link
       valid_lft forever preferred_lft forever
       

[vagrant@vagranthost ~]$ ifconfig
enp0s3: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.0.2.15  netmask 255.255.255.0  broadcast 10.0.2.255
        inet6 fe80::8ace:6cca:318:283d  prefixlen 64  scopeid 0x20<link>
        ether 08:00:27:45:a1:53  txqueuelen 1000  (Ethernet)
        RX packets 14023  bytes 2278575 (2.1 MiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 8206  bytes 2163779 (2.0 MiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 0  bytes 0 (0.0 B)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 0  bytes 0 (0.0 B)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0


[vagrant@vagranthost ~]$ free -h
              total        used        free      shared  buff/cache   available
Mem:           2.0G        112M        1.6G        884K        209M        1.7G
Swap:          2.2G          0B        2.2G

[vagrant@vagranthost ~]$ df -h
Filesystem               Size  Used Avail Use% Mounted on
devtmpfs                 987M     0  987M   0% /dev
tmpfs                    999M     0  999M   0% /dev/shm
tmpfs                    999M  880K  998M   1% /run
tmpfs                    999M     0  999M   0% /sys/fs/cgroup
/dev/mapper/fedora-root   15G  1.3G   14G   9% /
tmpfs                    999M  4.0K  999M   1% /tmp
/dev/sda1                976M  117M  793M  13% /boot
tmpfs                    200M     0  200M   0% /run/user/1000

# VBox Guest Additions. 
wget http://download.virtualbox.org/virtualbox/5.2.6/VBoxGuestAdditions_5.2.6.iso
sudo mount -o loop VBoxGuestAdditions_5.2.6.iso /mnt
sudo mount /dev/sr0 /mnt
cd /mnt
sudo dnf -y install elfutils-libelf-devel
sudo dnf -y install gcc make perl
sudo dnf -y install kernel-devel-4.13.9-300.fc27.x86_64
sudo ./VBoxLinuxAdditions.run 
sudo ./VBoxLinuxAdditions.run
sudo umount /dev/cdrom /mnt
verify
lsmod | grep vboxguest
lsmod | grep vboxsf
sudo umount /dev/sr0 /mnt

sudo passwd root
su -
sudo visudo -f /etc/sudoers.d/vagrant
# add vagrant user
vagrant ALL=(ALL) NOPASSWD:ALL
# test sudoers
sudo pwd

#firewall && ssh for vagrant connections
sudo systemctl stop firewalld
sudo systemctl disable firewalld
sudo systemctl enable sshd.service
sudo systemctl start sshd.service
sudo systemctl status sshd.service
sudo chkconfig firewalld off

sudo dnf update -y
sudo dnf upgrade -y
sudo shutdown -r now

#Install vagrant key
mkdir -p /home/vagrant/.ssh
chmod 700 /home/vagrant/.ssh
wget --no-check-certificate \
          https://raw.github.com/mitchellh/vagrant/master/keys/vagrant.pub \
          -O /home/vagrant/.ssh/authorized_keys
chmod 600 /home/vagrant/.ssh/authorized_keys
chown -R vagrant /home/vagrant/.ssh
sudo vi /etc/ssh/sshd_config
#Find and uncomment the following line because we added the Vagrant key above to the authorized_keys file:
AuthorizedKeysFile %h/.ssh/authorized_keys

#zero out the drive
sudo dnf clean all
sudo rm -rf /var/cache/dnf
sudo dd if=/dev/zero of=/EMPTY bs=1M
sudo rm -f /EMPTY
cat /dev/null > ~/.bash_history && history -c && exit

#Repackaging. On VirtualBox GUI "centos74minimal" is seen.Or VBoxManage list runningvms.
vagrant package --base centos74minimal --output centos74minimal.box
vagrant box add "centos74minimal/v1.0" centos74minimal.box
vagrant box list
vagrant init "centos74minimal/v1.0"
vagrant up
vagrant ssh
------------------------------------------------------------------------------------------
 Create a new virtual machine with the following settings:
    Memory Size: 1024MB (to taste)
    New Virtual Disk: [Type: VMDK, Size: 40 GB]  
		Disable floppy
    Disable audio
    Disable USB
    system-processor-1x
    general-advanced-dragndrop-bidirectional
    Ensure Network Adapter 1 is set to NAT
    Add this port-forwarding rule: [Name: SSH, Protocol: TCP, Host IP: blank, Host Port: 2222, Guest IP: blank, Guest Port: 22]
    
    INSTALL THE OPERATING SYSTEM        
    standard partition-auto
    set hostname ; vagranthost
    network disabled
    sudo passwd root
    set the user to vagrant and the password to vagrant.
    make this user administrator
    
    
    sudo passwd root
    su -

sudo apt-get xxx
update - Retrieve new lists of packages
upgrade - Perform an upgrade
dist-upgrade - Distribution upgrade, see apt-get(8)
autoremove - Remove automatically all unused packages
autoclean - Erase old downloaded archive files



sudo apt-get install -y gcc make perl
sudo mount /dev/cdrom /mnt
cd /mnt
sudo ./VBoxLinuxAdditions.run
sudo umount /dev/cdrom /mnt
verify
lsmod | grep vboxguest


disable firewall 
sudo systemctl disable ufw
sudo systemctl stop ufw
sudo systemctl status ufw

make sure ssh is working
INSTALL AND CONFIGURE OPENSSH SERVER
sudo apt-get install -y openssh-server


sudo visudo -f /etc/sudoers.d/vagrant
# add vagrant user
vagrant ALL=(ALL) NOPASSWD:ALL
sudo pwd


INSTALL THE VAGRANT KEY

mkdir -p /home/vagrant/.ssh
chmod 700 /home/vagrant/.ssh
wget --no-check-certificate \
          https://raw.github.com/mitchellh/vagrant/master/keys/vagrant.pub \
          -O /home/vagrant/.ssh/authorized_keys
chmod 600 /home/vagrant/.ssh/authorized_keys
chown -R vagrant /home/vagrant/.ssh


#MISSING PART
sudo nano /etc/ssh/sshd_config
#Find and uncomment the following line because we added the Vagrant key above to the authorized_keys file:
AuthorizedKeysFile %h/.ssh/authorized_keys


#“zero out” the drive.
sudo dd if=/dev/zero of=/EMPTY bs=1M
sudo rm -f /EMPTY
cat /dev/null > ~/.bash_history && history -c && exit


vagrant package --base ubuntu1604 --output ubuntu1604.box
vagrant box add "ubuntu1604" ubuntu1604.box
vagrant init ubuntu1604
vagrant up
------------------------------------------------------------------------------------------
vagrant plugin install vagrant-vbguest -> automatically deploy the VirtualBox Guest Additions

#use this plugin confguration only if the plugin is found by Vagrant itself
if Vagrant.has_plugin?("vagrant-vbguest") then
config.vbguest.auto_update = false
end
------------------------------------------------------------------------------------------
>vagrant up master
The VirtualBox VM was created with a user that doesn't match the
current user running Vagrant. VirtualBox requires that the same user
be used to manage the VM that was created. Please re-run Vagrant with
that user. This is not a Vagrant issue.

The UID used to create the VM was: 501
Your UID is: 0

need to delete the .vagrant. 
need to update the creator_uid file in .vagrant
The file : .vagrant/machines/web/virtualbox/creator_uid
assign the ownership for :.vagrant/machines/web to the new uid
------------------------------------------------------------------------------------------
#bash script

if [ "$(vagrant status | grep "${__BOX_NAME}.*running" | wc -l)" -eq "1" ];
then
  echo "Re-provisioning..."
  vagrant provision
else
  echo "Booting up the virtual machine..."
  vagrant up --provision
fi
------------------------------------------------------------------------------------------
vagrant box outdated #whether or not the box you are using in your current Vagrant environment is outdated
vagrant box outdated --global #every installed box will be checked for updates
vagrant box update #updates the box for the current Vagrant environment if there are updates available
vagrant box prune #
vagrant box prune --force #remove all installed boxes that are outdated and not currently in use
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
#troubleshooting, windows 11
Problem:
Failed to open/create the internal network 'HostInterfaceNetworking-VirtualBox Host-Only Ethernet Adapter' (VERR_INTNET_FLT_IF_NOT_FOUND).
Failed to attach the network LUN (VERR_INTNET_FLT_IF_NOT_FOUND).

Fix:
Control Panel\Network and Internet\Network Connections\
Disable VMware Virtual Ethernet Adapter for VMnetXXX network connections
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
#troubleshooting, windows 11

Problem:
windows: WinRM transport: negotiate
Timed out while waiting for the machine to boot. This means that
Vagrant was unable to communicate with the guest machine within
the configured ("config.vm.boot_timeout" value) time period.


------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------