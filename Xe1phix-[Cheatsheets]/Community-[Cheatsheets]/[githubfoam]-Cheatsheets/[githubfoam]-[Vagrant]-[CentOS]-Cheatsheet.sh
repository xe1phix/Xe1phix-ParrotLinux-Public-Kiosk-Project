Create first a CentOS virtualbox VM then convert to a vagrant box

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
    
 
make vagrant user administrator

GUI install package selection
GNOME Desktop
development tool
system administration tools


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
sudo vi /etc/ssh/sshd_config (already configured)
#Find and uncomment the following line because we added the Vagrant key above to the authorized_keys file:
AuthorizedKeysFile      .ssh/authorized_keys

#zero out the drive
sudo yum clean all
sudo rm -rf /var/cache/yum
sudo dd if=/dev/zero of=/EMPTY bs=1M
sudo rm -f /EMPTY
cat /dev/null > ~/.bash_history && history -c && exit

WHILE VM IS NOT RUNNING
#Repackaging. On VirtualBox GUI "centos74minima" is seen.Or VBoxManage list runningvms.
vagrant package --base CentOS-7-x86_64-DVD-1804 --output CentOS-7-x86_64-DVD-1804.box
vagrant box add "CentOS-7-x86_64-DVD-1804.box" CentOS-7-x86_64-DVD-1804.box
vagrant box list
vagrant init "CentOS-7-x86_64-DVD-1804.box"
vagrant up "CentOS-7-x86_64-DVD-1804.box"
vagrant ssh
