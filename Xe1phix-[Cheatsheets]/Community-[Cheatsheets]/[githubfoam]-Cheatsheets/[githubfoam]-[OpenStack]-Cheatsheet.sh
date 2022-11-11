--------------------------------------------------------------------------
# All-in-one openstack run on single ubuntu-16.04 vagrant VM guest. min 6GB ram required.

vagrant up
E:\PURR\openstack3>vagrant ssh-config 33b9056
Host default
  HostName 127.0.0.1
  User vagrant
  Port 2222
  UserKnownHostsFile /dev/null
  StrictHostKeyChecking no
  PasswordAuthentication no
  IdentityFile E:/PURR/openstack3/.vagrant/machines/default/virtualbox/private_key
  IdentitiesOnly yes
  LogLevel FATAL
  
vagrant@vagranthost:~$ ifconfig
enp0s3    Link encap:Ethernet  HWaddr 08:00:27:52:15:ec
          inet addr:10.0.2.15  Bcast:10.0.2.255  Mask:255.255.255.0
          inet6 addr: fe80::8eab:13d7:16af:81f3/64 Scope:Link
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:132027 errors:0 dropped:0 overruns:0 frame:0
          TX packets:47844 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000
          RX bytes:129989509 (129.9 MB)  TX bytes:2930369 (2.9 MB)

lo        Link encap:Local Loopback
          inet addr:127.0.0.1  Mask:255.0.0.0
          inet6 addr: ::1/128 Scope:Host
          UP LOOPBACK RUNNING  MTU:65536  Metric:1
          RX packets:60 errors:0 dropped:0 overruns:0 frame:0
          TX packets:60 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000
          RX bytes:9751 (9.7 KB)  TX bytes:9751 (9.7 KB)

$ ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host
       valid_lft forever preferred_lft forever
2: enp0s3: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 1000
    link/ether 08:00:27:52:15:ec brd ff:ff:ff:ff:ff:ff
    inet 10.0.2.15/24 brd 10.0.2.255 scope global dynamic enp0s3
       valid_lft 85512sec preferred_lft 85512sec
    inet6 fe80::8eab:13d7:16af:81f3/64 scope link
       valid_lft forever preferred_lft forever
	   
	   
E:\PURR\openstack3>vagrant ssh-config 33b9056
Host default
  HostName 127.0.0.1
  User vagrant
  Port 2222
  UserKnownHostsFile /dev/null
  StrictHostKeyChecking no
  PasswordAuthentication no
  IdentityFile E:/PURR/openstack3/.vagrant/machines/default/virtualbox/private_key
  IdentitiesOnly yes
  LogLevel FATAL
		  
$ cat /etc/hosts
127.0.0.1       localhost
127.0.1.1       vagranthost

# The following lines are desirable for IPv6 capable hosts
::1     ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters

~$ free -h
              total        used        free      shared  buff/cache   available
Mem:           3,9G        136M        3,4G        9,2M        280M        3,5G
Swap:          2,0G          0B        2,0G

$ df -h
Filesystem      Size  Used Avail Use% Mounted on
udev            2,0G     0  2,0G   0% /dev
tmpfs           395M  6,0M  389M   2% /run
/dev/sda1        38G  4,9G   31G  14% /
tmpfs           2,0G  176K  2,0G   1% /dev/shm
tmpfs           5,0M     0  5,0M   0% /run/lock
tmpfs           2,0G     0  2,0G   0% /sys/fs/cgroup
tmpfs           395M   32K  395M   1% /run/user/108
vagrant         392G  323G   69G  83% /vagrant
tmpfs           395M     0  395M   0% /run/user/1000

vagrant@vagranthost:~$ sudo -i 

root@vagranthost:~# useradd -s /bin/bash -d /opt/stack -m stack
root@vagranthost:~# echo "stack ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers

root@vagranthost:~# sudo passwd stack
root@vagranthost:~# su - stack

stack@vagranthost:~$ pwd
/opt/stack

stack@vagranthost:~$ sudo apt-get install git -y
stack@vagranthost:~$ git clone https://git.openstack.org/openstack-dev/devstack
stack@vagranthost:~$ cd devstack/




stack@vagranthost:~/devstack$ sudo vi local.conf

local ip:10.0.2.15 

stack@vagranthost:~/devstack$ cat local.conf
[[local|localrc]]
FLOATING_RANGE=10.0.2.224/27
FIXED_RANGE=10.11.12.0/24
FIXED_NETWORK_SIZE=256
FLAT_INTERFACE=enp0s3
ADMIN_PASSWORD=supersecret
DATABASE_PASSWORD=$ADMIN_PASSWORD
RABBIT_PASSWORD=$ADMIN_PASSWORD
SERVICE_PASSWORD=$ADMIN_PASSWORD

stack@vagranthost:~$./stack.sh


OSError: [Errno 13] Permission denied: '/opt/stack/.cache/pip/wheels/2c/f7/79/13f3a12cd723892437c0cfbde1230ab4d82947ff7b3839a4fc'

stack@vagranthost:~/devstack$ sudo ls -la /opt/stack/
drwx------  2 root  root  4096 Mar 14 12:38 .cache

stack@vagranthost:~/devstack$ sudo chown -R stack:stack /opt/stack/.cache/
drwx------  2 stack stack 4096 Mar 14 12:38 .cache


AGAIN!!
stack@vagranthost:~$./stack.sh


=========================
DevStack Component Timing
 (times are in seconds)
=========================
run_process           32
test_with_retry        2
apt-get-update        10
pip_install          356
osc                  131
wait_for_service      35
git_timed            245
dbsync                24
apt-get              308
-------------------------
Unaccounted time     582
=========================
Total runtime        1725



This is your host IP address: 10.0.2.15
This is your host IPv6 address: ::1
Horizon is now available at http://10.0.2.15/dashboard
Keystone is serving at http://10.0.2.15/identity/
The default users are: admin and demo
The password: supersecret

WARNING:
Using lib/neutron-legacy is deprecated, and it will be removed in the future


Services are running under systemd unit files.
For more information see:
https://docs.openstack.org/devstack/latest/systemd.html

DevStack Version: rocky
Change: 9f50f541385c929262a2e9c05093881960fe7d8f Merge "Revert to using neutron-legacy based services" 2018-03-13 17:40:14 +0000
OS Version: Ubuntu 16.04 xenial

2018-03-14 10:13:16.334 | stack.sh completed in 1726 seconds.



AFTER INSTALLATION memory+disk space

$ free -h
              total        used        free      shared  buff/cache   available
Mem:           3,9G        3,5G        118M         20M        225M         84M
Swap:          2,0G        688M        1,3G


$ df -h
Filesystem      Size  Used Avail Use% Mounted on
udev            2,0G     0  2,0G   0% /dev
tmpfs           395M   41M  354M  11% /run
/dev/sda1        38G  8,1G   28G  23% /
tmpfs           2,0G  260K  2,0G   1% /dev/shm
tmpfs           5,0M     0  5,0M   0% /run/lock
tmpfs           2,0G     0  2,0G   0% /sys/fs/cgroup
vagrant         392G  328G   64G  84% /vagrant
tmpfs           395M   52K  395M   1% /run/user/1000

-------------------------------------------------------------------------------------------------------
#https://www.rdoproject.org/
# All-in-one openstack RDO run on single Scientific Linux 7.4vagrant VM guest. min 8GB ram required.

vagrant@vagranthost ~]$ hostnamectl
   Static hostname: vagranthost
         Icon name: computer-vm
           Chassis: vm
        Machine ID: a1a35943505e4479963714acaa2b5c74
           Boot ID: e0abd19722934a89b2029faf843b9d9a
    Virtualization: kvm
  Operating System: Scientific Linux 7.4 (Nitrogen)
       CPE OS Name: cpe:/o:scientificlinux:scientificlinux:7.4:GA
            Kernel: Linux 3.10.0-693.17.1.el7.x86_64
      Architecture: x86-64
[vagrant@vagranthost ~]$ cat /etc/hosts
127.0.0.1   localhost localhost.localdomain localhost4 localhost4.localdomain4
::1         localhost localhost.localdomain localhost6 localhost6.localdomain6

[vagrant@vagranthost ~]$ free -h
              total        used        free      shared  buff/cache   available
Mem:           5.7G        262M        5.1G        8.6M        335M        5.2G
Swap:          2.0G          0B        2.0G
[vagrant@vagranthost ~]$ df -h
Filesystem                   Size  Used Avail Use% Mounted on
/dev/mapper/scientific-root   38G  4.1G   34G  11% /
devtmpfs                     2.9G     0  2.9G   0% /dev
tmpfs                        2.9G     0  2.9G   0% /dev/shm
tmpfs                        2.9G  8.5M  2.9G   1% /run
tmpfs                        2.9G     0  2.9G   0% /sys/fs/cgroup
/dev/sda1                   1014M  228M  787M  23% /boot
tmpfs                        581M  8.0K  581M   1% /run/user/42
vagrant                      181G   37G  144G  21% /vagrant
tmpfs                        581M     0  581M   0% /run/user/1000
[vagrant@vagranthost ~]$ 

vagrant@vagranthost ~]$ ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN qlen 1
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: enp0s3: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP qlen 1000
    link/ether 08:00:27:c7:c6:5d brd ff:ff:ff:ff:ff:ff
    inet 10.0.2.15/24 brd 10.0.2.255 scope global dynamic enp0s3
       valid_lft 86197sec preferred_lft 86197sec
    inet6 fe80::4397:fa63:4eb3:b4f8/64 scope link 
       valid_lft forever preferred_lft forever
3: virbr0: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500 qdisc noqueue state DOWN qlen 1000
    link/ether 52:54:00:4c:ad:de brd ff:ff:ff:ff:ff:ff
    inet 192.168.122.1/24 brd 192.168.122.255 scope global virbr0
       valid_lft forever preferred_lft forever
4: virbr0-nic: <BROADCAST,MULTICAST> mtu 1500 qdisc pfifo_fast master virbr0 state DOWN qlen 1000
    link/ether 52:54:00:4c:ad:de brd ff:ff:ff:ff:ff:ff


[vagrant@vagranthost ~]$ ifconfig
enp0s3: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.0.2.15  netmask 255.255.255.0  broadcast 10.0.2.255
        inet6 fe80::4397:fa63:4eb3:b4f8  prefixlen 64  scopeid 0x20<link>
        ether 08:00:27:c7:c6:5d  txqueuelen 1000  (Ethernet)
        RX packets 1908  bytes 229980 (224.5 KiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 1745  bytes 158594 (154.8 KiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
        loop  txqueuelen 1  (Local Loopback)
        RX packets 72  bytes 6008 (5.8 KiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 72  bytes 6008 (5.8 KiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

virbr0: flags=4099<UP,BROADCAST,MULTICAST>  mtu 1500
        inet 192.168.122.1  netmask 255.255.255.0  broadcast 192.168.122.255
        ether 52:54:00:4c:ad:de  txqueuelen 1000  (Ethernet)
        RX packets 0  bytes 0 (0.0 B)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 0  bytes 0 (0.0 B)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0


[vagrant@vagranthost ~]$ sudo systemctl disable firewalld
Removed symlink /etc/systemd/system/dbus-org.fedoraproject.FirewallD1.service.
Removed symlink /etc/systemd/system/basic.target.wants/firewalld.service.
[vagrant@vagranthost ~]$ sudo systemctl stop firewalld
[vagrant@vagranthost ~]$ sudo systemctl disable NetworkManager
Removed symlink /etc/systemd/system/multi-user.target.wants/NetworkManager.service.
Removed symlink /etc/systemd/system/dbus-org.freedesktop.NetworkManager.service.
Removed symlink /etc/systemd/system/dbus-org.freedesktop.nm-dispatcher.service.
[vagrant@vagranthost ~]$ sudo systemctl stop NetworkManager
[vagrant@vagranthost ~]$ sudo systemctl enable network
network.service is not a native service, redirecting to /sbin/chkconfig.
Executing /sbin/chkconfig network on
[vagrant@vagranthost ~]$ sudo systemctl start network


[vagrant@vagranthost ~]$ sudo yum install -y https://rdoproject.org/repos/rdo-release.rpm


On CentOS, the Extras repository provides the RPM that enables the OpenStack repository. Extras is enabled by default on CentOS 7, so you can simply install the RPM to set up the OpenStack repository.
https://www.rdoproject.org/install/packstack/
[vagrant@vagranthost ~]$ sudo yum install -y centos-release-openstack-queens
Loaded plugins: langpacks
openstack-queens                                                                                                                                         | 2.9 kB  00:00:00     
rdo-qemu-ev                                                                                                                                              | 2.9 kB  00:00:00     
(1/2): rdo-qemu-ev/x86_64/primary_db                                                                                                                     |  37 kB  00:00:00     
(2/2): openstack-queens/x86_64/primary_db                                                                                                                | 765 kB  00:00:00     
No package centos-release-openstack-queens available.
Error: Nothing to do

[vagrant@vagranthost ~]$ sudo yum-config-manager --enable openstack-queens
[vagrant@vagranthost ~]$ sudo yum update -y

[vagrant@vagranthost ~]$ sudo yum install -y openstack-packstack
[vagrant@vagranthost ~]$ sudo packstack --allinone



**** Installation completed successfully ******

Additional information:
 * A new answerfile was created in: /root/packstack-answers-20180316-043518.txt
 * Time synchronization installation was skipped. Please note that unsynchronized time on server instances might be problem for some OpenStack components.
 * File /root/keystonerc_admin has been created on OpenStack client host 10.0.2.15. To use the command line tools you need to source the file.
 * To access the OpenStack Dashboard browse to http://10.0.2.15/dashboard .
Please, find your login credentials stored in the keystonerc_admin in your home directory.
 * Because of the kernel update the host 10.0.2.15 requires reboot.
 * The installation log file is available at: /var/tmp/packstack/20180316-043517-w6nSBt/openstack-setup.log
 * The generated manifests are available at: /var/tmp/packstack/20180316-043517-w6nSBt/manifests


[vagrant@vagranthost ~]$ df -h
Filesystem                   Size  Used Avail Use% Mounted on
/dev/mapper/scientific-root   38G  5.7G   33G  15% /
devtmpfs                     2.9G     0  2.9G   0% /dev
tmpfs                        2.9G  4.0K  2.9G   1% /dev/shm
tmpfs                        2.9G  8.6M  2.9G   1% /run
tmpfs                        2.9G     0  2.9G   0% /sys/fs/cgroup
/dev/sda1                   1014M  285M  730M  29% /boot
/dev/loop0                   1.9G  6.1M  1.7G   1% /srv/node/swiftloopback
tmpfs                        581M   12K  581M   1% /run/user/42
tmpfs                        581M     0  581M   0% /run/user/1000
[vagrant@vagranthost ~]$ free -h
              total        used        free      shared  buff/cache   available
Mem:           5.7G        5.2G        181M        8.6M        333M        183M
Swap:          2.0G         48K        2.0G

--------------------------------------------------------------------------