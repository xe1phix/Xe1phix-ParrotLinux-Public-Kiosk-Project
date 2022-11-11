------------------------------------------------------------------------------------------
 # Use VBoxManage to customize the VM.
 
      openstack.vm.provider :virtualbox do |vb|         
          vb.customize ["modifyvm", :id, "--ioapic", "on"] # turn on I/O APIC
          vb.customize ["modifyvm", :id, "--cpus", "#{$cpus}"] # set number of vcpus
          vb.customize ["modifyvm", :id, "--memory", "#{$memory}"] # set amount of memory allocated vm memory
          vb.customize ["modifyvm", :id, "--ostype", "Ubuntu_64"] # set guest OS type
          vb.customize ["modifyvm", :id, "--natdnshostresolver1", "on"] # enables DNS resolution from guest using host's DNS
          vb.customize ["modifyvm", :id, "--nicpromisc3", "allow-all"] # turn on promiscuous mode on nic 3
          vb.customize ["modifyvm", :id, "--nictype1", "virtio"]
          vb.customize ["modifyvm", :id, "--nictype2", "virtio"]
          vb.customize ["modifyvm", :id, "--nictype3", "virtio"]
          vb.customize ["modifyvm", :id, "--pae", "on"] # enables PAE
          vb.customize ["modifyvm", :id, "--longmode", "on"] # enables long mode (64 bit mode in GUEST OS)
          vb.customize ["modifyvm", :id, "--hpet", "on"] # enables a High Precision Event Timer (HPET)
          vb.customize ["modifyvm", :id, "--hwvirtex", "on"] # turn on host hardware virtualization extensions (VT-x|AMD-V)
          vb.customize ["modifyvm", :id, "--nestedpaging", "on"] # if --hwvirtex is on, this enables nested paging
          vb.customize ["modifyvm", :id, "--largepages", "on"] # if --hwvirtex & --nestedpaging are on
          vb.customize ["modifyvm", :id, "--vtxvpid", "on"] # if --hwvirtex on
          vb.customize ["modifyvm", :id, "--vtxux", "on"] # if --vtux on (Intel VT-x only) enables unrestricted guest mode
          vb.customize ["modifyvm", :id, "--boot1", "disk"] # tells vm to boot from disk only
          vb.customize ["modifyvm", :id, "--rtcuseutc", "on"] # lets the real-time clock (RTC) operate in UTC time
          vb.customize ["modifyvm", :id, "--audio", "none"]
          vb.customize ["modifyvm", :id, "--clipboard", "disabled"]
          vb.customize ["modifyvm", :id, "--usbehci", "off"]
          vb.customize ["modifyvm", :id, "--vrde", "off"]
          vb.customize ["guestproperty", "set", :id, "/VirtualBox/GuestAdd/VBoxService/--timesync-set-threshold", 10000]
      end
------------------------------------------------------------------------------------------
#if condition


  if config.vm.provider :vmware_workstation
    # If we're running VMware Workstation (i.e. Linux)
    if Vagrant.has_plugin?("vagrant-triggers")
      config.trigger.before :up do
        puts "[+] INFO: Ensuring /dev/vmnet* are correct to allow promiscuous mode."
        puts "[+]       Needed for access to containers on different VMs."
        run "./fix_vmnet.sh"
      end
    else
      puts "[-] You do not have vagrant-triggers installed so Vagrant is unable"
      puts "[-] to set the correct permissions for promiscuous mode to function"
      puts "[-] on VMware Workstation based environments"
      puts "[-]"
      puts "[-] Install using: vagrant plugin install vagrant-triggers"
      puts "[-]"
      puts "[-] Please ensure /dev/vmnet* is group owned and writeable by you"
      puts "[-]          sudo chmod chgrp <gid> /dev/vmnet*"
      puts "[-]          sudo chmod g+rw /dev/vmnet*"
    end
  end
  
------------------------------------------------------------------------------------------
#if condition

          # Otherwise using VirtualBox
        box.vm.provider :virtualbox do |vbox|
          vbox.name = "#{hostname}"
          # Defaults
          vbox.linked_clone = true if Vagrant::VERSION =~ /^1.8/
          vbox.customize ["modifyvm", :id, "--memory", 1024]
          vbox.customize ["modifyvm", :id, "--cpus", 1]
          if prefix == "controller"
            vbox.customize ["modifyvm", :id, "--memory", 7168]
            vbox.customize ["modifyvm", :id, "--cpus", 2]
          end
          if prefix == "compute"
            vbox.customize ["modifyvm", :id, "--memory", 4096]
            vbox.customize ["modifyvm", :id, "--cpus", 1]
          end
          vbox.customize ["modifyvm", :id, "--nicpromisc1", "allow-all"]
          vbox.customize ["modifyvm", :id, "--nicpromisc2", "allow-all"]
          vbox.customize ["modifyvm", :id, "--nicpromisc3", "allow-all"]
          vbox.customize ["modifyvm", :id, "--nicpromisc4", "allow-all"]
          vbox.customize ["modifyvm", :id, "--nicpromisc5", "allow-all"]
        end
	
	# If using VMware Workstation
        box.vm.provider "vmware_workstation" do |v|
          v.linked_clone = true if Vagrant::VERSION =~ /^1.8/
          v.vmx["memsize"] = 1024
          if prefix == "controller"
            v.vmx["memsize"] = 7168
            v.vmx["numvcpus"] = "2"
          end
          if prefix == "compute"
            v.vmx["memsize"] = 4096
            v.vmx["numvcpus"] = "1"
            v.vmx["vhv.enable"] = "TRUE"
          end
        end
	
        # If using VMware Fusion
        box.vm.provider "vmware_fusion" do |v|
          v.linked_clone = true if Vagrant::VERSION =~ /^1.8/
          v.vmx["memsize"] = 1024
          if prefix == "controller"
            v.vmx["memsize"] = 7168
            v.vmx["numvcpus"] = "2"
          end
          if prefix == "compute"
            v.vmx["memsize"] = 4096
            v.vmx["numvcpus"] = "1"
            v.vmx["vhv.enable"] = "TRUE"
          end
        end
------------------------------------------------------------------------------------------
# avoid dot slash "./" in shell script file

$Prometheus_From_Precompiled_Binary_script = <<-SCRIPT
export PATH=$PATH:/tmp/prometheus-2.37.0.linux-amd64
SCRIPT
------------------------------------------------------------------------------------------
#Passing variable to a shell script provisioner in vagrant

config.vm.provision :shell, :path => "bootstrap.sh", :args:["first", "second"]

#the single quotes around first arg are only needed if it include spaces as part of the argument passed.
# equivalent to $ bootstrap.sh 'first arg' second
#config.vm.provision :shell, :path => "bootstrap.sh", :args => "'first arg' second"

var1= "192.168.50.4"
var2 = "my_server"
config.vm.provision :shell, :path => 'setup.sh', :args => [var1, var2]
------------------------------------------------------------------------------------------
#Timed out while waiting for the machine to boot. This means that
#Vagrant was unable to communicate with the guest machine within
#the configured ("config.vm.boot_timeout" value) time period.By default this is 300 seconds/5 mins.

	      config.vm.define "vg-debian-03" do |k8scluster|
                # https://wiki.debian.org/DebianReleases
                #https://github.com/chef/bento/tree/main/packer_templates/debian
                k8scluster.vm.box = "bento/debian-11.2"
                k8scluster.vm.boot_timeout = 1800 # 30 minutes
                k8scluster.vm.hostname = "vg-debian-03"
                k8scluster.vm.network "private_network", ip: "192.168.50.18"                
                # k8scluster.vm.synced_folder ".", "/vagrant", disabled: true 
                k8scluster.vm.provider "virtualbox" do |vb|
                    vb.name = "vbox-debian-03"
                    vb.memory = "4096"
                end
------------------------------------------------------------------------------------------
config.vm.network "public_network", ip: "192.168.0.201" #bridged network,DHCP enabled,IP assignment
kalicluster.vm.network "public_network" #bridged network,DHCP enabled,auto IP assignment
------------------------------------------------------------------------------------------
#capture Vagrant Network Traffic

Vagrant.configure("2") do |config|
  # ...

  config.vm.provider "virtualbox" do |vb|
    vb.customize ["modifyvm", :id, "--nictrace1", "on"]
    vb.customize ["modifyvm", :id, "--nictracefile1", "dump.pcap"]
  end
end
------------------------------------------------------------------------------------------
config.vm.provider "virtualbox" do |v|
  v.customize ["modifyvm", :id, "--groups", "/testgroupname"]
end
------------------------------------------------------------------------------------------
$centos_docker_script = <<SCRIPT
sudo docker --version
SCRIPT

#Specifies whether to execute the shell script as a privileged user or not (sudo)
box.vm.provision "shell", inline: $ubuntu_docker_script, privileged: true # privileged user root
box.vm.provision "shell", inline: $ubuntu_docker_script, privileged: false # not privileged user (sudo)

------------------------------------------------------------------------------------------
#have a specific command executed only once after a reboot.
# a specific command could require certain files not to be in use or for example the vagrant user not to be logged in

#Vagrantfile
config.vm.provision :shell, path: "prescript.sh"
config.vm.provision :reload
config.vm.provision :shell, path: "postscript.sh"
------------------------------------------------------------------------------------------
#linux host

$ echo 'Vagrant.configure("2") do |config|
  config.vm.box = "bento/ubuntu-16.04"
  config.vm.network "forwarded_port", guest: 8080, host: 8080
end' > Vagrantfile
$ vagrant up
$ vagrant ssh
------------------------------------------------------------------------------------------
#Change vagrants default IP

The default IP address of Vagrant VM is 10.0.2.15

# Assigns any IP withing that subnet
 config.vm.provider "virtualbox" do |v|
      v.memory = 1048
      v.cpus = 2
      v.name = "vagrantguestvm"
      v.customize ['modifyvm', :id, '--natnet1', '192.168.222.0/24']
 end

------------------------------------------------------------------------------------------
#Install python for ansible. In case ubuntu 16.04 minimalCD ISO required for remote deployments
   config.vm.provision "shell", inline: <<-SHELL
   test -e /usr/bin/python || (apt -qqy update && apt install -qqy python-minimal)
   SHELL

# On windows it is "users" directory
config.vm.synced_folder ".", "/vagrant", disabled:false

------------------------------------------------------------------------------------------
Firing up Redhat based Centos Scientific Linux Fedora vagrant vmguest with ansible-ready environment

---Vagrantfile----
config.vm.provision "shell", inline: <<-SHELL
     sudo yum install epel-release -y 
     sudo yum update -y
     sudo yum install ansible -y 
   SHELL
---Vagrantfile----
------------------------------------------------------------------------------------------
Firing up Debian based ubuntu vagrant vmguest with ansible-ready environment

---Vagrantfile----
#Install python for ansible. In case ubuntu 16.04 minimalCD ISO required for remote deployments
   config.vm.provision "shell", inline: <<-SHELL
   test -e /usr/bin/python || (apt -qqy update && apt install -qqy python-minimal)
   SHELL
   config.vm.provision "shell", inline: <<-SHELL
	   sudo apt-get install software-properties-common -y 
	   sudo apt-add-repository ppa:ansible/ansible -y 
	   sudo apt-get update -y 
	   sudo apt-get install ansible -y 
   SHELL
---Vagrantfile----

  ------------------------------------------------------------------------------------------
   config file..
    	  # Create a forwarded port mapping which allows access to a specific port
	  # within the machine from a port on the host machine. In the example below,
	  # accessing "localhost:8080" will access port 80 on the guest machine.
	  # NOTE: This will enable public access to the opened port
	    config.vm.network "forwarded_port", guest: 80, host: 8080

vagrant vmguest is booting..
==> jenkinsmaster1: Preparing network interfaces based on configuration...
    jenkinsmaster1: Adapter 1: nat
    jenkinsmaster1: Adapter 2: hostonly
==> jenkinsmaster1: Forwarding ports...
    jenkinsmaster1: 80 (guest) => 8080 (host) (adapter 1)
    jenkinsmaster1: 22 (guest) => 2222 (host) (adapter 1)
   
   Listing NICS on vagrant vmguest..
   $ hostname -I
   10.0.2.15 192.168.39.14
    
    apache webserver test page..
    http://127.0.0.1:8080/
------------------------------------------------------------------------------------------
traffic sent to port 80/8000 on the host machine will be delivered to port 8080/8000 on the guest machine.

  config.vm.network :forwarded_port, guest: 8080, host: 80
  config.vm.network :forwarded_port, guest: 8000, host: 8000
------------------------------------------------------------------------------------------
  # Start a simple HTTP server provided by Python out of the box
sudo python -m SimpleHTTPServer 80
------------------------------------------------------------------------------------------
Shared directories

config.vm.synced_folder "scripts", "/vagrant_data"
------------------------------------------------------------------------------------------
File Edit/Replace
# disable selinux
config.vm.provision "shell", inline: 'sed -i -e "s/enabled/disabled/" /etc/sysconfig/selinux'
------------------------------------------------------------------------------------------
# set repos for lustre server, client and e2fsprogs
config.vm.provision "shell", inline: "touch /etc/yum.repos.d/lustre.repo; cat <<'EOF' > /etc/yum.repos.d/lustre.repo\n[lustre-server]\nname=lustre-server\nbaseurl=https://downloads.hpdd.intel.com/public/lustre/lustre-2.10.0/el7/server/ \nenabled=1\ngpgcheck=0\nEOF" 
config.vm.provision "shell", inline: "touch /etc/yum.repos.d/lustre-client.repo; cat <<'EOF' > /etc/yum.repos.d/lustre-client.repo\n[lustre-client]\nname=lustre-server\nbaseurl=https://downloads.hpdd.intel.com/public/lustre/lustre-2.10.0/el7/client/ \nenabled=1\ngpgcheck=0\nEOF"
config.vm.provision "shell", inline: "touch /etc/yum.repos.d/e2fsprogs.repo; cat <<'EOF' > /etc/yum.repos.d/e2fsprogs.repo\n[e2fsprogs]\nname=e2fsprogs\nbaseurl=https://downloads.hpdd.intel.com/public/e2fsprogs/latest/el7/ \nenabled=1\ngpgcheck=0\nEOF"
------------------------------------------------------------------------------------------
# install right kerne, set it to default for grub and boot with it  
config.vm.provision "shell", inline: "yum install -y kernel-3.10.0-514.21.1.el7_lustre;grub2-set-default 0;reboot"
------------------------------------------------------------------------------------------
  config.vm.provision "ansible_local" do |ansible|
    ansible.playbook = "playbook.yml"
    ansible.become = true
    ansible.groups = {
     "mgmt" => ["gfs01"],
     "meta" => ["gfs02"],
     "all_groups:children" => ["gfs01", "gfs01"]
    }
  end
  ------------------------------------------------------------------------------------------
      config.vm.synced_folder ".", "/vagrant", disabled:false
      
      config.vm.provision "ansible_local" do |ansible|
      ansible.playbook = "/vagrant/deploy.yml"
      ansible.become = true
      ansible.verbose = ""
      end  
------------------------------------------------------------------------------------------
  config.vm.provision "ansible" do |ansible|
    ansible.playbook       = "./test_playbook.yml"
    ansible.sudo           = true
    ansible.inventory_path = "local.ini"
    ansible.extra_vars     = { ansible_ssh_user: 'vagrant' }
  ------------------------------------------------------------------------------------------
  workaround ssh problem with new box created via VirtualBox GUI
  
  config.ssh.username="vagrant"
  config.ssh.password="vagrant"
  ------------------------------------------------------------------------------------------

     config.vm.define "softroce1" do |softrocestack|
		softrocestack.vm.network "private_network", ip: "192.168.100.11"
		softrocestack.vm.box = "miniubuntu"
                softrocestack.vm.box = "ubuntu-17.10.1-server-amd64-softroce"
		softrocestack.vm.synced_folder ".", "/vagrant", disabled: false

		softrocestack.vm.provision "shell", inline: <<-SHELL
		echo " =================================================================================="
		echo " ========================SERVER IS UP-TO-DATE======================================"
		echo " =================================================================================="
		sudo apt-get update -y
		sudo apt-get dist-upgrade -y
	#	echo " =================================================================================="
	#	echo " ========================Install gluster==========================================="
	#	echo " =================================================================================="
	#	sudo apt-get install ansible -y
		echo " =================================================================================="
		echo " ==================sOFTRoCE READY TO GO============================================"
		echo " =================================================================================="
		SHELL
		
		softrocestack.vm.provider "virtualbox" do |v|
		v.memory = 1048
		v.cpus = 2
		v.name = "softroce1"
		end
		
    ------------------------------------------------------------------------------------------
    ofedcluster.vm.provision "shell", inline: <<-SHELL
	       sudo hostnamectl set-hostname stormy
	       echo "172.28.128.15 vg-checkmk-client.local vg-checkmk-client" |sudo tee -a /etc/hosts
    SHELL
    ------------------------------------------------------------------------------------------
    #file provisioner, file copy
    
     vagrant ssh-config id    
    "scp -P 2200 vagrant@127.0.0.1:/vagrant/some-file.txt ."
    folder copy
    config.vm.provision "file", source: "~/path/to/host/folder", destination: "$HOME/remote/newfolder"
    permission problem
    chmod 777 -R /remote/folder
    
    #file copy from windows host to linux guest, relative path(windows)
    k8scluster.vm.provision "file", source: "mrtg/rddtool-cgi/14all.cgi.source", destination: "/tmp/14all.cgi"   
     ------------------------------------------------------------------------------------------
    file copy
    
    vagrant ssh-config id
    add entry in ~/.ssh/config:
    Host vagrant
    User vagrant
    HostName localhost
    Port 2222
    
    scp file vagrant:/path/
    IdentityFile /home/user_name/.vagrant.d/insecure_private_key
     ------------------------------------------------------------------------------------------
    file copy
    
    Find the private key, ssh port and IP
    vagrant ssh-config id
    "scp -P 2222 -i /root/.vagrant.d/insecure_private_key \  someFileName.txt vagrant@127.0.0.1:~"
    
    from guest to host:
    "vagrant ssh -c 'cat ~/file_on_guest.txt' > ~/file_on_host.txt"
    "scp -P 2222 vagrant@127.0.0.1:/PATH/filename ."
     ------------------------------------------------------------------------------------------
    
   config.vm.synced_folder ‘.’, ‘/vagrant’, disabled: true
   config.vm.provision “ansible_local” do |ansible|
   ansible.provisioning_path = “/ansible”
    
    provisioning_path (string) - An absolute path on the guest machine where the Ansible files are stored. The ansible-galaxy and ansible-playbook commands are executed from this directory. This is the location to place an ansible.cfg file, in case you need it.
The default value is /vagrant.
     ------------------------------------------------------------------------------------------
     mini ISO Ubuntu, python workaround through VagrantFile

Vagrantfile 
config.vm.box = "miniubuntunew"
config.vm.define "client2" do |client|
    client.vm.network "private_network", ip: "192.168.35.42"
    client.vm.box = "miniubuntunew"
    #client.vm.box = "ubuntu1604"
  end

  config.vm.provider "virtualbox" do |v|
      v.memory = 1024
      v.cpus = 2     
  end

     #Install python for ansible
      config.vm.provision "shell", inline: <<-SHELL
        test -e /usr/bin/python || (apt -qqy update && apt install -qqy python-minimal)
       SHELL

mini ISO Ubuntu, python workaround through VagrantFile

playbook.yml file
---
- hosts: all
  gather_facts: false
  
  pre_tasks:
  - name: Install python for Ansible
    raw: test -e /usr/bin/python || (apt -y update && apt install -y python-minimal)
    
    
Ansible’s “raw” module (for executing commands in a quick and dirty way) and the script module don’t even need that. 
So technically, you can use Ansible to install python-simplejson using the raw module, which then allows you to use everything else
http://docs.ansible.com/ansible/latest/intro_installation.html

Executes a low-down and dirty SSH command, not going through the module subsystem. This is useful and should only be done in two cases. The first case is installing python-simplejson on older (Python 2.4 and before) hosts that need it as a dependency to run modules, since nearly all core modules require it. Another is speaking to any devices such as routers that do not have any Python installed. In any other case, using the shell or command module is much more appropriate. 
Arguments given to raw are run directly through the configured remote shell.
http://docs.ansible.com/ansible/latest/raw_module.html

--------------------------------------------------------------------------

$ ssh -i .vagrant/machines/default/virtualbox/private_key -p 2222 vagrant@localhost

vagrant insecure_private_key

$ vagrant ssh-config
Host default
  HostName 127.0.0.1
  User vagrant
  Port 2222
  UserKnownHostsFile /dev/null
  StrictHostKeyChecking no
  PasswordAuthentication no
  IdentityFile C:/Users/konst/.vagrant.d/insecure_private_key
  IdentitiesOnly yes
  LogLevel FATAL

 the contents of file insecure_private_key with the contents of your personal system private key
 Add it to the Vagrantfile
 
 Vagrant.configure("2") do |config|
  config.ssh.private_key_path = "~/.ssh/id_rsa"
  config.ssh.forward_agent = true
end
--------------------------------------------------------------------------
#Vagrant to work with Chef Solo (a way of running Chef in standalone mode, without the need of a Chef server) to provision vagrant box

config.vm.provision :chef_solo do |chef|
chef.add_recipe 'apache2'
end
--------------------------------------------------------------------------
  config.vm.box = "bento/centos-7.4"
  config.vm.box_check_update = false
--------------------------------------------------------------------------
#specify a default VM
config.vm.define "prod", primary: true do |config|
[...]
end

#do not start automatically a VM when issuing the vagrant up
config.vm.define "staging", autostart: false do |config|
[...]
end
--------------------------------------------------------------------------
STORAGE
--------------------------------------------------------------------------
#VDI: Oracle’s Default Disk Format Used by Virtual Box
#VHD: The Virtual Disk Format Used by Microsoft
#VMDK: VMWare’s Virtual Disk File Format
--------------------------------------------------------------------------
	 glusterfedora.vm.provider "virtualbox" do |vb|
			  if !File.exist?("storage01.vmdk")
				vb.customize ["createmedium", "--filename", "storage01.vmdk", "--size", 61440]
                vb.customize ["modifymedium", "storage01.vmdk", "--type", "normal"]
			  end
             vb.customize ["storageattach", :id, "--storagectl", "SATA Controller", "--port", 1, "--device", 0, "--type", "hdd", "--medium", "storage01.vmdk"]
    end
--------------------------------------------------------------------------
#Vagrant deletes attached virtual disk when vagrant destroy is issued

VAGRANTFILE_API_VERSION = "2"
HOME_DISK = "/var/home.vdi"

Vagrant.configure(VAGRANTFILE_API_VERSION) do |config|
  config.vm.box = "deb/jessie-i386"

  config.vm.provider :virtualbox do |vb|
    if ARGV[0] == "up" && ! File.exist?(HOME_DISK)
      vb.customize ['createhd',
                    '--filename', HOME_DISK,
                    '--format', 'VDI',
                    '--size', 50000]

      vb.customize ['storageattach', :id,
                    '--storagectl', 'SATA Controller',
                    '--port', 0,
		    '--device', 0,
                    '--type', 'hdd',
		    '--medium', HOME_DISK]
    end
  end
end
--------------------------------------------------------------------------
file_to_disk = './tmp/large_disk.vdi'

Vagrant::Config.run do |config|
  config.vm.box = 'base'

  config.vm.customize ['createhd', '--filename', file_to_disk, '--size', 500 * 1024]
  config.vm.customize ['storageattach', :id, '--storagectl', 'SATA Controller', '--port', 1, '--device', 0, '--type', 'hdd', '--medium', file_to_disk]
end
--------------------------------------------------------------------------
disk_size = 1024
disk_filename = "workdisk.vdi"
disk_id_filename = ".disk.id"
file_root = File.dirname(File.expand_path(__FILE__))
$disk_id_file = File.join(file_root, disk_id_filename)
$disk_file = File.join(file_root, disk_filename)
$disk_size = disk_size.to_s

class VagrantPlugins::ProviderVirtualBox::Action::SetName
    alias_method :original_call, :call
    def call(env)
        ui = env[:ui]
        controller_name = "SATA Whatever"
        driver = env[:machine].provider.driver
        uuid = driver.instance_eval { @uuid }
        vm_info = driver.execute("showvminfo", uuid)
        has_controller = vm_info.match("Storage Controller Name.*#{controller_name}")
        if !File.exist?($disk_file)
            ui.info "Creating storage file '#{$disk_file}'..."
            driver.execute(
                "createmedium", "disk",
                "--filename", $disk_file,
                "--format", "VDI",
                "--size", $disk_size
            )
        end
        if !has_controller
            ui.info "Creating storage controller '#{controller_name}'..."
            driver.execute(
                "storagectl", uuid,
                "--name", "#{controller_name}",
                "--add", "sata",
                "--controller", "IntelAhci",
                "--portcount", "1",
                "--hostiocache", "off"
            )
        end
        ui.info "Attaching '#{$disk_file}' to '#{controller_name}'..."
        driver.execute(
            "storageattach", uuid,
            "--storagectl", "#{controller_name}",
            "--port", "0",
            "--type", "hdd",
            "--medium", $disk_file
        )
        work_disk_info = driver.execute("showmediuminfo", $disk_file)
        work_disk_uuid = work_disk_info.match(/^UUID\:\s*([a-z0-9\-]+)/).captures[0]
        uuid_blocks = work_disk_uuid.split("-")
        disk_by_id = "ata-VBOX_HARDDISK_VB"
        disk_by_id += uuid_blocks[0] + "-"
        disk_by_id += uuid_blocks[-1][10..11]
        disk_by_id += uuid_blocks[-1][8..9]
        disk_by_id += uuid_blocks[-1][6..7]
        disk_by_id += uuid_blocks[-1][4..5]
        File.open($disk_id_file, "w") {|f| f.write(disk_by_id) }
        original_call(env)
    end
end

Vagrant.configure(2) do |config|
    config.vm.box = "debian/jessie64"
    !File.exist?($disk_id_file) ? File.open($disk_id_file, "w") {} : nil
    config.vm.provision "file", source: $disk_id_file, destination: disk_id_filename
    config.vm.provision "shell", inline: <<-EOF
        disk=/dev/disk/by-id/$(<#{disk_id_filename})
        apt-get install -y gdisk
        sgdisk -n 0:0:0 -t 0:8300 $disk
        sleep 1 # TODO: how to make sure partition is done?
        mkfs.ext4 ${disk}-part1
        mkdir /work
        echo "${disk}-part1 /work ext4 defaults 0 0" >> /etc/fstab
        mount /work
        chown -R vagrant:vagrant /work
    EOF
end
--------------------------------------------------------------------------

# -*- mode: ruby -*-
# vi: set ft=ruby :

  class VagrantPlugins::ProviderVirtualBox::Action::SetName
    alias_method :original_call, :call
    def call(env)
      machine = env[:machine]
      driver = machine.provider.driver
      uuid = driver.instance_eval { @uuid }
      ui = env[:ui]

      controller_name = 'SATA Controller'

      vm_info = driver.execute("showvminfo", uuid)
      has_this_controller = vm_info.match("Storage Controller Name.*#{controller_name}")

      if has_this_controller
        ui.info "already has the #{controller_name} hdd controller"
      else
        ui.info "creating #{controller_name} controller #{controller_name}"
        driver.execute('storagectl', uuid,
          '--name', "#{controller_name}",
          '--add', 'sata',
          '--controller', 'IntelAhci')
      end

      ## Disk Management
      format = "VMDK"
      size = 1024
      port = 0

      ui.info "attaching storage to #{controller_name}"
      %w(sdb sdc).each do |hdd|
        if File.exist?("#{hdd}" + ".vmdk")
          ui.info "#{hdd} Already Exists"
        else
              ui.info "Creating #{hdd}\.vmdk"
              driver.execute("createhd", 
                   "--filename", "#{hdd}", 
                   "--size", size, 
                   "--format", "#{format}")
               end

        # Attach devices
        driver.execute('storageattach', uuid,
          '--storagectl', "#{controller_name}",
          '--port', port += 1,
          '--type', 'hdd',
          '--medium', "#{hdd}" + ".vmdk")
      end

      original_call(env)
    end
  end

Vagrant.configure(2) do |config|
  config.vm.box = "rhelboxname"

  # Hopefully a fix for issue with sudo requiring a tty...?
  config.ssh.pty = true

  config.vm.provider :virtualbox do |vb|
    # No idea why this is...  I just copy it every time ';
    vb.customize ["modifyvm", :id, "--usbehci", "off"]

  end # end config.vm.provider

end # end Vagrant.configure(2) do |config|
--------------------------------------------------------------------------
Vagrant.configure(2) do |config|

  config.vm.box = "ubuntu/trusty64"
  config.vm.box_check_update = false
  config.vm.network "private_network", ip: "192.168.33.9"
  config.vm.provider "virtualbox" do |vb|
    vb.gui = false
    vb.memory = "1024"
    vb.name = "try_disk"

    file_to_disk = File.realpath( "." ).to_s + "/disk.vdi"

    if ARGV[0] == "up" && ! File.exist?(file_to_disk)
       vb.customize [
            'createhd',
            '--filename', file_to_disk,
            '--format', 'VDI',
            '--size', 30 * 1024 # 30 GB
            ]
       vb.customize [
            'storageattach', :id,
            '--storagectl', 'SATA', # The name may vary
            '--port', 1, '--device', 0,
            '--type', 'hdd', '--medium',
            file_to_disk
            ]
    end
  end

  # Tow partition in one disk
  config.vm.provision "shell", inline: <<-SHELL
set -e
set -x

if [ -f /etc/provision_env_disk_added_date ]
then
   echo "Provision runtime already done."
   exit 0
fi


sudo fdisk -u /dev/sdb <<EOF
n
p
1

+500M
n
p
2


w
EOF

mkfs.ext4 /dev/sdb1
mkfs.ext4 /dev/sdb2
mkdir -p /{data,extra}
mount -t ext4 /dev/sdb1 /data
mount -t ext4 /dev/sdb2 /extra

date > /etc/provision_env_disk_added_date
  SHELL

  config.vm.provision "shell", inline: <<-SHELL
    echo Well done
  SHELL
end
--------------------------------------------------------------------------
#windows host

Vagrant.configure("2") do |config|
 config.vm.provider "virtualbox" do |vb|
      file_to_disk = 'D:/UniServerZ/www/VM/tealit.com/large_disk.vdi'
      unless File.exist?(file_to_disk)
        vb.customize ['createhd', '--filename', file_to_disk, '--size', 500 * 1024]
      end
      vb.customize ['storageattach', :id, '--storagectl', 'SATA Controller', '--port', 1, '--device', 0, '--type', 'hdd', '--medium', file_to_disk]
   end
end
--------------------------------------------------------------------------
class VagrantPlugins::ProviderVirtualBox::Action::SetName
  alias_method :original_call, :call
  def call(env)
    machine = env[:machine]
    driver = machine.provider.driver
    uuid = driver.instance_eval { @uuid }
    ui = env[:ui]

    # Find out folder of VM
    vm_folder = ""
    vm_info = driver.execute("showvminfo", uuid, "--machinereadable")
    lines = vm_info.split("\n")
    lines.each do |line|
      if line.start_with?("CfgFile")
        vm_folder = line.split("=")[1].gsub('"','')
        vm_folder = File.expand_path("..", vm_folder)
        ui.info "VM Folder is: #{vm_folder}"
      end
    end

    size = 10240
    disk_file = vm_folder + "/disk1.vmdk"

    ui.info "Adding disk to VM"
    if File.exist?(disk_file)
      ui.info "Disk already exists"
    else
      ui.info "Creating new disk"
      driver.execute("createmedium", "disk", "--filename", disk_file, "--size", "#{size}", "--format", "VMDK")
      ui.info "Attaching disk to VM"
      driver.execute('storageattach', uuid, '--storagectl', "SATA Controller", '--port', "1", '--type', 'hdd', '--medium', disk_file)
    end

    original_call(env)
  end
end
--------------------------------------------------------------------------
$sdb1 = <<-SCRIPT
parted /dev/sdb mklabel msdos
parted /dev/sdb mkpart primary 0% 100%
mkfs.xfs /dev/sdb1
mkdir /mnt/data1
if grep -Fxq "sdb1" /etc/fstab
then
  echo 'sdb1 exist in fstab'
else
  echo `blkid /dev/sdb1 | awk '{print$2}' | sed -e 's/"//g'` /mnt/data1   xfs   noatime,nobarrier   0   0 >> /etc/fstab
fi
if mount | grep /mnt/data1 > /dev/null; then
  echo "/dev/sdb1 mounted /mnt/data1"
  umount /mnt/data1
  mount /mnt/data1
else
  mount /mnt/data1
fi
SCRIPT

$sdc1 = <<-SCRIPT
parted /dev/sdc mklabel msdos
parted /dev/sdc mkpart primary 0% 100%
mkfs.xfs /dev/sdc1
mkdir /mnt/data2
if grep -Fxq "sdc1" /etc/fstab
then
  echo 'sdc1 exist in fstab'
else
  echo `blkid /dev/sdc1 | awk '{print$2}' | sed -e 's/"//g'` /mnt/data2   xfs   noatime,nobarrier   0   0 >> /etc/fstab
fi
if mount | grep /mnt/data2 > /dev/null; then
  echo "/dev/sdc1 mounted /mnt/data2"
  umount /mnt/data2
  mount /mnt/data2
else
  mount /mnt/data2
fi
SCRIPT

$sdd1 = <<-SCRIPT
parted /dev/sdd mklabel msdos
parted /dev/sdd mkpart primary 0% 100%
mkfs.xfs /dev/sdd1
mkdir /mnt/metadata1
if grep -Fxq "sdd1" /etc/fstab
then
  echo 'sdd1 exist in fstab'
else
  echo `blkid /dev/sdd1 | awk '{print$2}' | sed -e 's/"//g'` /mnt/metadata1   xfs   noatime,nobarrier   0   0 >> /etc/fstab
fi
if mount | grep /mnt/metadata1 > /dev/null; then
  echo "/dev/sdd1 mounted /mnt/metadata1"
  umount /mnt/metadata1
  mount /mnt/metadata1
else
  mount /mnt/metadata1
fi
SCRIPT

node1disk1 = "./tmp/node1disk1.vdi";
node1disk2 = "./tmp/node1disk2.vdi";
node1disk3 = "./tmp/node1disk3.vdi";

ip_node1 = "192.168.33.31";

Vagrant.configure("2") do |config|

  config.vm.define "node1" do |node1|
    node1.vm.network "private_network", ip: ip_node1
    node1.vm.hostname = "node1"
    node1.vm.define "node1"
    node1.vm.box_download_insecure = true
    node1.vm.box = "centos/7"
    node1.vm.provider "virtualbox" do |vb|
      vb.memory = "2048"
      if not File.exists?(node1disk1)
        vb.customize ['createhd', '--filename', node1disk1, '--variant', 'Fixed', '--size', 1 * 1024]
        vb.customize ['storageattach', :id,  '--storagectl', 'IDE', '--port', 0, '--device', 1, '--type', 'hdd', '--medium', node1disk1]
      end
      if not File.exists?(node1disk2)
        vb.customize ['createhd', '--filename', node1disk2, '--variant', 'Fixed', '--size', 1 * 1024]
        vb.customize ['storageattach', :id,  '--storagectl', 'IDE', '--port', 1, '--device', 0, '--type', 'hdd', '--medium', node1disk2]
      end
      if not File.exists?(node1disk3)
        vb.customize ['createhd', '--filename', node1disk3, '--variant', 'Fixed', '--size', 1 * 1024]
        vb.customize ['storageattach', :id,  '--storagectl', 'IDE', '--port', 1, '--device', 1, '--type', 'hdd', '--medium', node1disk3]
      end
    end
    node1.vm.provision "shell", inline: $sdb1
    node1.vm.provision "shell", inline: $sdc1
    node1.vm.provision "shell", inline: $sdd1
  end

end
--------------------------------------------------------------------------
# variables 
cpus = ENV["VM_CPUS"] || 2
ram = ENV["VM_RAM"] || 4096

Vagrant.configure("2") do |config|
  config.vm.box = "windows2016_core_L1"
  config.vm.box_url = "file:/Users/Shared/git/packer-windows2016-core-level1/box/vmware/windows2016_core_L1.box"

    config.vm.communicator = "winrm"
    config.winrm.guest_port = "5986"
    config.winrm.port = "55986"
    config.winrm.transport = :ssl
    config.winrm.ssl_peer_verification = false
  
      # Admin user name and password
      config.winrm.username = "vagrant"
      config.winrm.password = "vagrant"
      config.winrm.timeout = 120
  
      config.vm.guest = :windows
      config.windows.halt_timeout = 15
      config.vm.boot_timeout = 900 # Give sysprep first-boot enough time
      config.vm.graceful_halt_timeout = 900 # Give windows update time
        #Export RDP and SSH
      config.vm.network :forwarded_port, guest: 3389, host: 8389, id: "rdp", auto_correct: true
  
      config.vm.provider :virtualbox do |v, override|
          v.gui = true
          v.customize ["modifyvm", :id, "--memory", ram]
          v.customize ["modifyvm", :id, "--cpus", cpus]
          v.customize ["modifyvm", :id, "--vram", 128]
          v.customize ["setextradata", "global", "GUI/SuppressMessages", "all"]
          v.customize ["modifyvm", :id, "--clipboard", "bidirectional"]
          v.customize ["setextradata", "global", "GUI/MaxGuestResolution", "any"]
          v.customize ["setextradata", :id, "CustomVideoMode1", "1024x768x32"]
      end
      
            config.vm.provider :vmware_workstation do |v, override|
          v.gui = true
          v.vmx["memsize"] = ram
          v.vmx["numvcpus"] = cpus
          v.vmx["ethernet0.virtualDev"] = "vmxnet3"
          v.vmx["ethernet0.pcislotnumber"] = "192"
          v.vmx["scsi0.virtualDev"] = "lsisas1068"
          v.enable_vmrun_ip_lookup = false
      end

end
--------------------------------------------------------------------------
STORAGE
--------------------------------------------------------------------------
multiple ports
  guest_port: 9200
  host_port: 9200
  guest_port1: 80
  host_port1: 82
  
  box.vm.network "forwarded_port", guest: server["guest_port"], host: server["host_port"],  id: 'elastic_port'
  box.vm.network "forwarded_port", guest: server["guest_port1"], host: server["host_port1"],  id: 'httpd_port'
--------------------------------------------------------------------------