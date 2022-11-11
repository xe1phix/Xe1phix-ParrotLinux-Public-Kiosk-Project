----------------------------------------------------------------------------------------------------------------------
$ ansible --version
ansible 2.9.27
  config file = /etc/ansible/ansible.cfg
  configured module search path = [u'/home/ansiadm/.ansible/plugins/modules', u'/usr/share/ansible/plugins/modules']
  ansible python module location = /usr/lib/python2.7/dist-packages/ansible
  executable location = /usr/bin/ansible
  python version = 2.7.17 (default, Mar 18 2022, 13:21:42) [GCC 7.5.0]
----------------------------------------------------------------------------------------------------------------------  
#specify a different inventory file using the -i <path> option on the command line
/etc/ansible/hosts #Ansible’s inventory, which defaults to being saved in the location /etc/ansible/hosts

/etc/ansible/ansible.cfg #config file

-b, --become          run operations with become (does not imply password prompting)
-k, –ask-pass: ask for connection password  
-K, –ask-become-pass: ask for privilege escalation password
----------------------------------------------------------------------------------------------------------------------

#INI-like inventory file
mail.example.com

[webservers]
foo.example.com
bar.example.com

[dbservers]
one.example.com
two.example.com
three.example.com
----------------------------------------------------------------------------------------------------------------------
#YAML-like inventory file
all:
  hosts:
    mail.example.com:
  children:
    webservers:
      hosts:
        foo.example.com:
        bar.example.com:
    dbservers:
      hosts:
        one.example.com:
        two.example.com:
        three.example.com:
----------------------------------------------------------------------------------------------------------------------
sudo apt-get install python-virtualenv
python -m virtualenv ansible  # Create a virtualenv if one does not already exist
source ansible/bin/activate   # Activate the virtual environment
python -m pip install ansible

----------------------------------------------------------------------------------------------------------------------
# Not inventory, remote passwordless ssh connection

[clients]
control01 ansible_host=192.168.45.10 ansible_connection=ssh ansible_ssh_port=22 ansible_ssh_private_key_file=/home/vagrant/.ssh/id_rsa ansible_user=vagrant
#vagrant-client01 ansible_host=10.10.40.94 ansible_ssh_private_key_file='.vagrant/machines/vagrant-client01/virtualbox/private_key' ansible_connection=local ansible_ssh_user='vagrant'
[all:vars]
ansible_python_interpreter=/usr/bin/python3
---------------------------------------------------------------------------------------------------------------------- 
Running a playbook in dry-run mode
ansible-playbook playbooks/PLAYBOOK_NAME.yml --check

ansible hostname -m setup
ansible -m setup test-instance -i inventory  | grep ansible_distribution
sudo ansible all -m setup -i "`hostname`," --connection=local -a "filter=ansible_distribution*"

Specifying a user
ansible-playbook playbooks/atmo_playbook.yml --user atmouser

Using a specific SSH private key
ansible -m ping hosts --private-key=~/.ssh/keys/id_rsa -u centos

Passing Variables via CLI
ansible-playbook playbooks/atmo_playbook.yml -e "ATMOUSERNAME=atmouser"

Modify file
ansible all -m lineinfile -a "dest=/etc/group regexp='^(users:x:100:)(.*)' line='\1ldapusername,\2' state=present backrefs=yes"

ansible-playbook release.yml --extra-vars "version=1.23.45 other_variable=foo"
ansible-playbook arcade.yml --extra-vars '{"pacman":"mrs","ghosts":["inky","pinky","clyde","sue"]}'
ansible-playbook release.yml --extra-vars "@some_file.json"

Passing variables on the command line
~/..ansible/roles ->ansible role default dir
/etc/ansible/hosts
#shell variable ANSIBLE_HOST

#hostfile
This is a deprecated setting since 1.9, please look at inventory for the new setting.
#ansible.cfg 
#ansible_ssh_user, ansible_ssh_host, and ansible_ssh_port deprecated

singular1->hostname
ansible-inventory --inventory-file=inventory --host singular1
ansible-inventory --inventory-file=inventory --list
ansible-inventory --inventory-file=inventory --graph

$ ansible -i inventory client1.example.lan -m setup | grep ansible_user
$ ansible -i inventory client1.example.lan -m setup -a "filter=facter_*"
$ ansible client1.example.lan -i inventory -m setup | grep ansible_default_ipv4.gateway
$ ansible -i inventory client1.example.lan -m ping
$ ansible -i inventory client1.example.lan -m ping -u root
$ ansible all -m ping -i bakircay-inventory.ini -l servergroup #only for specific group in inventory
$ ansible -i inventory c-m ping -u root
$ ansible -i inventory "client*" -m yum -a 'name=httpd state=absent'
$ ansible -i inventory "client*" -a "yum update"
$ ansible -i inventory "client*" -a "uname -a"
$ ansible -i inventory "client*" -m yum -a 'name=* state=latest'
$ ansible -i inventory client1.example.lan -m shell -a "yum list installed | grep docker" #only for specific server in inventory

ansible all -m ping -i inventory.ini -l servers_prod_1 #ping specific group of files
ansible all  -i inventory.ini -l servers_prod_1 -m ping #ping specific group of files

$ ansible -i inventory client1.example.lan -m shell -a "hostnamectl"
$ ansible -i inventory client1.example.lan -m shell -a "cat /etc/hosts"
$ ansible -i inventory client1.example.lan -m shell -a "ifconfig"
$ ansible -i inventory client1.example.lan -m shell -a "whoami"
$ ansible -i inventory client1.example.lan -m shell -a "nmcli d status"
$ ansible -i inventory client1.example.lan -m shell -a "sudo ifconfig -a"
$ ansible -i inventory selinux1 -m shell -a "whoami"

ansible -m debug -a 'var=hostvars' localhost
ansible -m debug -a 'var=hostvars' localhost | grep inventory_hostname
ansible -m debug -a 'var=hostvars' client1.example.lan -i inventory
ansible -m debug -a 'var=hostvars' client1.example.lan -i inventory| grep inventory_hostname	

ansible www.example.com -m service -a "name=sshd state=restarted" --sudo -K
ansible www.example.com -m copy -a "src=/home/liquidat/tmp/test.yml dest=/home/liquidat/text.yaml"
ansible www.example.com -m copy -a "src=/home/liquidat/tmp/test.yml dest=/home/liquidat/text.yaml"

ansible-config view -> Displays the current config file
ansible-config list -> List all current configs reading lib/constants.py and shows env and config file setting names

#verbose mode,  add -v (or -vv, -vvv, -vvvv, -vvvvv).
ansible-playbook playbook.yml -v
ansible-playbook playbook.yml -vv
ansible-playbook playbook.yml -vvv

ansible-playbook playbooks/PLAYBOOK_NAME.yml --limit "host1,host2"

ansible-playbook --list-hosts /vagrant/deploy.yml
ansible-playbook --list-tags /vagrant/deploy.yml
ansible-playbook --syntax-check installnginx.yml 
ansible-playbook -i hosts installnginx.yml 

ansible-playbook deploy-gluster.yml --tags "inventoryvars"
ansible-playbook deploy-gluster.yml --skip-tags "inventoryvars"

-----------------------------------------------------------------------------------------------------
# run ansible role on command prompt

roles:
    - {role: 'apache', tags: 'apache'}

ansible-playbook webserver.yml --tags "apache"

-----------------------------------------------------------------------------------------------------


ansible-playbook vagranthost -i hosts -b -k -u vagrant nginx.yml

ansible-doc apt -> details of the apt module
ansible-doc --list -> plugin list

ansible all --sudo --ask-sudo-pass -m raw -a 'sudo apt-get -y install python-simplejson
ansible web -m apt -a "name=apache2 state=present" -> Installs httpd package on the [web] group within your Ansible inventory
ansible all -m apt -a "name=bash=4.3 state=present" -> Install a certain version of Bash to every node
ansible all -m apt -a "upgrade=dist" -> the target nodes to update all installed software
ansible all -m yum -a "name=httpd state=present"
ansible all -m yum -a "name=* state=latest"

ansible <ansible group> -a "<shell command>"
ansible mysql -a "reboot -now" -> reboot all the members of the mysql group
ansible mysql -m service -a "name=mysql state=restarted" -> restart MySQL
ansible mysql -m service -a "name=mysql state=stopped"
ansible mysql -m service -a "name=mysql state=started"

#-m ping - Use the "ping" module, which simply runs the ping command and returns the results
#-s - Use "sudo" to run the commands
#-k - Ask for a password rather than use key-based authentication
#-u vagrant - Log into servers using user vagrant
ansible vagranthost -i hosts -m ping -b -k -u vagrant
ansible vagranthost -i hosts -b -k -u vagrant -m shell -a 'apt-get install nginx -y'
ansible vagranthost -i hosts -b -k -u vagrant -m apt -a 'pkg=nginx state=installed update_cache=true'
ansible vagranthost -i hosts -b -k -u vagrant -m apt -a 'pkg=nginx state=absent
ansible scientific_linux -m ping  -k -u vagrant
ansible scientific_linux -k  -u vagrant -m shell -a 'hostnamectl'
ansible scientific_linux -b -u vagrant -m shell -a 'whoami'
ansible scientific_linux -b -k -u  vagrant -m yum -a 'name=httpd state=latest'
ansible scientific_linux -b -k -u vagrant -m yum -a 'name=httpd state=absent'
ansible scientific_linux -b -k -u  vagrant -m yum -a 'name=* state=latest'
ansible scientific_linux -b -k -u  vagrant -m yum -a 'name=* state=latest exclude=kernel*'

ansible -i hosts local --connection=local -b --become-user=root -m shell -a 'apt-get install nginx' -> Run against a local server
ansible -i hosts remote -b --become-user=root all -m shell -a 'apt-get install nginx' -> Run against a remote server

ansible all -m user -a "name=gduffy" comment="Griff Duffy" group=users password="amadeuppassword" -> add a user named gduffy to a group called
users on every node within your Ansible inventory
ansible db -m user -a "name=gduffy" state=absent remove=yes"
ansible all -m user -a "name=beth shell=/bin/ksh home=/mnt/externalhome

ansible all -m user -a "name=meg generate_ssh_key=yes" -> create a user called Meg with an associated key
ansible all -m copy -a "src=keys/id_rsa dest="/home/beth/.ssh/id_rsa mode=0600 ->attach a key to a specifed account
ansible web_servers -m authorized_key -a "user=michael key="{{lookup('file', '/home/michael/.ssh/id_rsa.pub') }}" ->adds public key
to all web servers defned within the Ansible inventory.

Copy SSH key manually
ansible <HOST_GROUP> -m authorized_key -a "user=root key='ssh-rsa AAAA...XXX == root@hostname'"
----------------------------------------------------------------------------------------------------
ANSIBLE_VAULT_PASSWORD_FILE=~/.vault_pass.txt -> Ansible will automatically search for the password in that file
ansible-vault create passwd.yml -> Create a new encrypted data file.Set the password for vault
ansible-vault edit passwd.yml -> Edit encrypted file
ansible-vault rekey passwd.yml -> Change password for encrypted file

EDITOR=nano ansible-vault . . .

# make this persistent, open your ~/.bashrc file
nano ~/.bashrc
export EDITOR=nano #adding an EDITOR assignment to the end of the file
echo $EDITOR
----------------------------------------------------------------------------------------------------
#Install ansible Debian/Ubuntu
sudo apt-add-repository ppa:ansible/ansible
sudo apt-get update
sudo apt-get install ansible
ansible --version

#Install ansible Red Hat/CentOS
sudo yum -y install https://dl.fedoraproject.org/pub/epel/epelrelease-latest-7.noarch.rpm
sudo yum install ansible
ansible --version
-----------------------------------------------------------------------------------------------------
# 3x servers + 1x controller(remote control)

vagrant@vg-ubuntu-01:~$ whoami
vagrant
vagrant@vg-ubuntu-01:~$ sudo whoami
root
vagrant@vg-ubuntu-01:~$ id vagrant
uid=1000(vagrant) gid=1000(vagrant) groups=1000(vagrant),999(docker)


cat | sudo tee  << EOF
#!/bin/bash
apt-get update -yq
apt-get install software-properties-common -yq
add-apt-repository --yes --update ppa:ansible/ansible
apt-get install ansible -yq
VER=$(ansible --version)
echo "ansible version ...: $VER"
EOF

sudo cp /etc/hosts{,.orig} #backup

cat | sudo tee -a /etc/hosts << EOF
10.35.8.66 vg-ubuntu-02.local vg-ubuntu-02
10.35.8.69 vg-centos-01.local vg-centos-01
10.35.8.68 vg-centos-02.local vg-centos-02
EOF

cat | sudo tee custom-inventory.ini << EOF
#INI-like inventory file

[ubuntu_servers]
vg-ubuntu-02

[centos_servers]
vg-centos-01
vg-centos-02

[centos_servers:vars]
super_group = wheel


[ubuntu_servers:vars]
super_group = sudo
EOF


$ ansible-inventory --inventory-file=custom-inventory.ini --list
$ ansible-inventory --inventory-file=custom-inventory.ini --graph
@all:
  |--@centos_servers:
  |  |--vg-centos-01
  |  |--vg-centos-02
  |--@ubuntu_servers:
  |  |--vg-ubuntu-02
  |--@ungrouped:
  
                
$ cat /etc/ansible/ansible.cfg | grep host_key_checking
#host_key_checking = False

vagrant@vg-ubuntu-01:~$ ansible all -m ping -i custom-inventory.ini --ask-pass
SSH password:
vg-centos-02 | UNREACHABLE! => {
    "changed": false,
    "msg": "Failed to connect to the host via ssh: Permission denied (publickey,gssapi-keyex,gssapi-with-mic).",
    "unreachable": true
}
vg-ubuntu-02 | UNREACHABLE! => {
    "changed": false,
    "msg": "Failed to connect to the host via ssh: Permission denied (publickey).",
    "unreachable": true
}
vg-centos-01 | SUCCESS => {
    "ansible_facts": {
        "discovered_interpreter_python": "/usr/libexec/platform-python"
    },
    "changed": false,
    "ping": "pong"
}
$ sudo ansible all -m ping -i custom-inventory.ini --ask-pass
SSH password:
vg-ubuntu-02 | UNREACHABLE! => {
    "changed": false,
    "msg": "Failed to connect to the host via ssh: Permission denied (publickey).",
    "unreachable": true
}
vg-centos-02 | UNREACHABLE! => {
    "changed": false,
    "msg": "Failed to connect to the host via ssh: Permission denied (publickey,gssapi-keyex,gssapi-with-mic).",
    "unreachable": true
}
vg-centos-01 | SUCCESS => {
    "ansible_facts": {
        "discovered_interpreter_python": "/usr/libexec/platform-python"
    },
    "changed": false,
    "ping": "pong"
}


FIX:
vagrant@vg-ubuntu-02:~$ sudo grep --color PasswordAuthentication /etc/ssh/sshd_config
PasswordAuthentication no
# PasswordAuthentication.  Depending on your PAM configuration,
# PAM authentication, then enable this but set PasswordAuthentication
vagrant@vg-ubuntu-02:~$ sudo sed -i 's/PasswordAuthentication no/PasswordAuthentication yes/' /etc/ssh/sshd_config
vagrant@vg-ubuntu-02:~$ sudo grep --color PasswordAuthentication /etc/ssh/sshd_config
PasswordAuthentication yes
# PasswordAuthentication.  Depending on your PAM configuration,
# PAM authentication, then enable this but set PasswordAuthentication
$ sudo tail -f /var/log/auth.log
Apr 26 11:32:23 ubuntu-xenial sshd[5113]: Accepted password for vagrant from 10.35.8.67 port 46310 ssh2
Apr 26 11:32:23 ubuntu-xenial sshd[5113]: pam_unix(sshd:session): session opened for user vagrant by (uid=0)
Apr 26 11:32:23 ubuntu-xenial systemd-logind[1067]: New session 9 of user vagrant.

$ ansible all -m ping -i custom-inventory.ini --ask-pass
SSH password:
vg-centos-02 | UNREACHABLE! => {
    "changed": false,
    "msg": "Failed to connect to the host via ssh: Permission denied (publickey,gssapi-keyex,gssapi-with-mic).",
    "unreachable": true
}
vg-ubuntu-02 | SUCCESS => {
    "ansible_facts": {
        "discovered_interpreter_python": "/usr/bin/python3"
    },
    "changed": false,
    "ping": "pong"
}
vg-centos-01 | SUCCESS => {
    "ansible_facts": {
        "discovered_interpreter_python": "/usr/libexec/platform-python"
    },
    "changed": false,
    "ping": "pong"
}



FIX:  allow password authentication
[vagrant@vg-centos-02 ~]$ sudo grep --color PasswordAuthentication /etc/ssh/sshd_config
#PasswordAuthentication yes
PasswordAuthentication no
[vagrant@vg-centos-02 ~]$ sudo sed -i 's/PasswordAuthentication no/PasswordAuthentication yes/' /etc/ssh/sshd_config
[vagrant@vg-centos-02 ~]$ sudo grep --color PasswordAuthentication /etc/ssh/sshd_config
#PasswordAuthentication yes
PasswordAuthentication yes
# PasswordAuthentication.  Depending on your PAM configuration,
[vagrant@vg-centos-02 ~]$ sudo service sshd restart
Redirecting to /bin/systemctl restart sshd.service
[vagrant@vg-centos-02 ~]$ sudo journalctl -t sshd -f
Apr 26 11:35:01 vg-centos-02 sshd[5798]: Server listening on 0.0.0.0 port 22.
Apr 26 11:35:01 vg-centos-02 sshd[5798]: Server listening on :: port 22.
Apr 26 11:37:00 vg-centos-02 sshd[5807]: Accepted password for vagrant from 10.35.8.67 port 51456 ssh2
Apr 26 11:37:00 vg-centos-02 sshd[5807]: pam_unix(sshd:session): session opened for user vagrant by (uid=0)


$ sudo ansible -i custom-inventory.ini vg-centos-01 -m setup --ask-pass | grep ansible_user
SSH password:
        "ansible_user_dir": "/root",
        "ansible_user_gecos": "root",
        "ansible_user_gid": 0,
        "ansible_user_id": "root",
        "ansible_user_shell": "/bin/bash",
        "ansible_user_uid": 0,
        "ansible_userspace_architecture": "x86_64",
        "ansible_userspace_bits": "64",


#server groups in the inventory file
vagrant@vg-ubuntu-01:~$ ansible ubuntu_servers -m shell -a "hostnamectl" -i custom-inventory.ini --ask-pass
SSH password:
vg-ubuntu-02 | CHANGED | rc=0 >>
   Static hostname: vg-ubuntu-02
         Icon name: computer-vm
           Chassis: vm
        Machine ID: 832684edd7804fa59b04cc7c1efe63ba
           Boot ID: 1140618df6994658b5b6739159d21e96
    Virtualization: oracle
  Operating System: Ubuntu 16.04.7 LTS
            Kernel: Linux 4.4.0-210-generic
      Architecture: x86-64


vagrant@vg-ubuntu-01:~$ cat | sudo tee create_user.yaml << EOF
---
- name: "Create New User"
  hosts: all
  become: true
  gather_facts: false
  vars:
# Define your username and password here that you want to create on target hosts.
    username: ansibleadm
    userpass: admpass
  tasks:
    - name: "Create User"
      ansible.builtin.user:
        name: "{{ username }}"
        state: present
        shell: /bin/bash
        password: "{{ userpass | password_hash('sha512') }}"
        update_password: on_create
        groups: "{{ super_group }}"
        append: yes
EOF

vagrant@vg-ubuntu-01:~$ ansible-playbook create_user.yaml -i custom-inventory.ini --syntax-check

playbook: create_user.yaml

#Running a playbook in dry-run mode
vagrant@vg-ubuntu-01:~$ ansible-playbook create_user.yaml -i custom-inventory.ini --check --ask-pass
SSH password:

# --ask-pass not required, as become=true param in create_user.yaml 
vagrant@vg-ubuntu-01:~$ ansible-playbook create_user.yaml -i custom-inventory.ini

PLAY [Create New User] *****************************************************************************************************************

TASK [Create User] *********************************************************************************************************************
changed: [vg-ubuntu-02]
changed: [vg-centos-02]
changed: [vg-centos-01]

PLAY RECAP *****************************************************************************************************************************
vg-centos-01               : ok=1    changed=1    unreachable=0    failed=0    skipped=0    rescued=0    ignored=0
vg-centos-02               : ok=1    changed=1    unreachable=0    failed=0    skipped=0    rescued=0    ignored=0
vg-ubuntu-02               : ok=1    changed=1    unreachable=0    failed=0    skipped=0    rescued=0    ignored=0

#verify user on target servers
vagrant@vg-ubuntu-02:~$ id ansibleadm
uid=1002(ansibleadm) gid=1002(ansibleadm) groups=1002(ansibleadm),27(sudo)
[vagrant@vg-centos-01 ~]$ id ansibleadm
uid=1002(ansibleadm) gid=1002(ansibleadm) groups=1002(ansibleadm),10(wheel)
[vagrant@vg-centos-02 ~]$ id ansibleadm
uid=1001(ansibleadm) gid=1001(ansibleadm) groups=1001(ansibleadm),10(wheel)

    
#new playbook ssh.yaml, create sudo user with SSH keys and deliver on target servers

#controller server, create sudo user, this password is different from the password in ssh.yaml, same user ansibleadm.
vagrant@vg-ubuntu-01:~$ sudo adduser ansibleadm
Adding user `ansibleadm' ...
Adding new group `ansibleadm' (1002) ...
Adding new user `ansibleadm' (1002) with group `ansibleadm' ...
Creating home directory `/home/ansibleadm' ...
Copying files from `/etc/skel' ...
Enter new UNIX password:
Retype new UNIX password:
passwd: password updated successfully
Changing the user information for ansibleadm
Enter the new value, or press ENTER for the default
        Full Name []:
        Room Number []:
        Work Phone []:
        Home Phone []:
        Other []:
Is the information correct? [Y/n] y
vagrant@vg-ubuntu-01:~$ sudo usermod -aG sudo ansibleadm
vagrant@vg-ubuntu-01:~$ id ansibleadm
uid=1002(ansibleadm) gid=1002(ansibleadm) groups=1002(ansibleadm),27(sudo)

#login as sudo user and create SSH keys, skip passphrase for automation purposes
vagrant@vg-ubuntu-01:~$ su - ansibleadm
Password:
ansibleadm@vg-ubuntu-01:~$ ssh-keygen
Generating public/private rsa key pair.
Enter file in which to save the key (/home/ansibleadm/.ssh/id_rsa):
Created directory '/home/ansibleadm/.ssh'.
Enter passphrase (empty for no passphrase):
Enter same passphrase again:
Your identification has been saved in /home/ansibleadm/.ssh/id_rsa.
Your public key has been saved in /home/ansibleadm/.ssh/id_rsa.pub.
The key fingerprint is:
SHA256:YDWRPmsGRx4/9FmTOgml/B7MbEFcP52Oj9oMWIF7F/Q ansibleadm@vg-ubuntu-01
The key's randomart image is:
+---[RSA 2048]----+
|        +o ooo.. |
|       .+o+oo =.o|
|      o+ =o+.* Eo|
|     ...= +=B.+ .|
|       oS+ +B+ . |
|        + +o..o  |
|       o . ... . |
|            =    |
|           . o   |
+----[SHA256]-----+
ansibleadm@vg-ubuntu-01:~$ ls -lai .ssh
total 16
269652 drwx------ 2 ansibleadm ansibleadm 4096 Apr 26 12:29 .
269648 drwxr-xr-x 3 ansibleadm ansibleadm 4096 Apr 26 12:29 ..
269653 -rw------- 1 ansibleadm ansibleadm 1675 Apr 26 12:29 id_rsa
269654 -rw-r--r-- 1 ansibleadm ansibleadm  405 Apr 26 12:29 id_rsa.pub


vagrant@vg-ubuntu-01:~$ ansible-playbook ssh.yaml -i custom-inventory.ini --syntax-check

playbook: ssh.yaml

# user not created yet, avoid  for now
vagrant@vg-ubuntu-01:~$ vagrant@vg-ubuntu-01:~$ sudo ansible-playbook ssh.yaml -i custom-inventory.ini --check --ask-pass
SSH password:

PLAY [Create New User] *****************************************************************************************************************

TASK [Create User] *********************************************************************************************************************
changed: [vg-ubuntu-02]
changed: [vg-centos-02]
changed: [vg-centos-01]

TASK [Deploy SSH Public Key] ***********************************************************************************************************
fatal: [vg-centos-02]: FAILED! => {"changed": false, "msg": "Either user must exist or you must provide full path to key file in check mode"}
fatal: [vg-ubuntu-02]: FAILED! => {"changed": false, "msg": "Either user must exist or you must provide full path to key file in check mode"}
fatal: [vg-centos-01]: FAILED! => {"changed": false, "msg": "Either user must exist or you must provide full path to key file in check mode"}

PLAY RECAP *****************************************************************************************************************************
vg-centos-01               : ok=1    changed=1    unreachable=0    failed=1    skipped=0    rescued=0    ignored=0
vg-centos-02               : ok=1    changed=1    unreachable=0    failed=1    skipped=0    rescued=0    ignored=0
vg-ubuntu-02               : ok=1    changed=1    unreachable=0    failed=1    skipped=0    rescued=0    ignored=0

vagrant@vg-ubuntu-01:~$ sudo ansible-playbook ssh.yaml -i custom-inventory.ini

PLAY [Create New User] *****************************************************************************************************************

TASK [Create User] *********************************************************************************************************************
changed: [vg-ubuntu-02]
changed: [vg-centos-02]
changed: [vg-centos-01]

TASK [Deploy SSH Public Key] ***********************************************************************************************************
changed: [vg-ubuntu-02]
changed: [vg-centos-02]
changed: [vg-centos-01]

PLAY RECAP *****************************************************************************************************************************
vg-centos-01               : ok=2    changed=2    unreachable=0    failed=0    skipped=0    rescued=0    ignored=0
vg-centos-02               : ok=2    changed=2    unreachable=0    failed=0    skipped=0    rescued=0    ignored=0
vg-ubuntu-02               : ok=2    changed=2    unreachable=0    failed=0    skipped=0    rescued=0    ignored=0

#verify if user exists
vagrant@vg-ubuntu-02:~$ id ansibleadm
uid=1006(ansibleadm) gid=1006(ansibleadm) groups=1006(ansibleadm),27(sudo)

#verify user's password
vagrant@vg-ubuntu-02:~$ su - ansibleadm
Password:
To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.

#verify SSH publich key, comparing with on controller vg-ubuntu-01
ansibleadm@vg-ubuntu-02:~$ cat .ssh/authorized_keys
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDlTPavvyZzM4FY2lCO69a4SQ919vja3UTPHTjpJu2QbYOyKuHggHCD2Q3wExz9hvAb/mASCHxOEHVFleMwbivNgjofgJ/DG5Yomvz7J4vXFOUgNpq4rhQL/pm/+6qf7+fekHyMju70oHR6SIJd74gN4TSgs+OLWnekFTVVA/S/p0KN2lYZt7KTLDDzOd51Votz/MK3qZ2DpDdEqr6D+LG+lP/f7zIElWMHtdx/KFwNICPIWjb1hDcVADpgbKDTWNG9e8KsVnUPx2OI2+GTUWRIaVXNPxDIj96qb1+8JjKGpuvpCPMxBlDFj7TMEoUSPLvCNECiHyTlTA/B7GIzNrkJ ansibleadm@vg-ubuntu-01
ansibleadm@vg-ubuntu-01:~$ cat .ssh/id_rsa.pub
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDlTPavvyZzM4FY2lCO69a4SQ919vja3UTPHTjpJu2QbYOyKuHggHCD2Q3wExz9hvAb/mASCHxOEHVFleMwbivNgjofgJ/DG5Yomvz7J4vXFOUgNpq4rhQL/pm/+6qf7+fekHyMju70oHR6SIJd74gN4TSgs+OLWnekFTVVA/S/p0KN2lYZt7KTLDDzOd51Votz/MK3qZ2DpDdEqr6D+LG+lP/f7zIElWMHtdx/KFwNICPIWjb1hDcVADpgbKDTWNG9e8KsVnUPx2OI2+GTUWRIaVXNPxDIj96qb1+8JjKGpuvpCPMxBlDFj7TMEoUSPLvCNECiHyTlTA/B7GIzNrkJ ansibleadm@vg-ubuntu-01

#verify passwordless ssh connection from controller server vg-ubuntu-01
vagrant@vg-ubuntu-01:~$ su - ansibleadm
Password:
To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.
ansibleadm@vg-ubuntu-01:~$ ssh ansibleadm@vg-ubuntu-02
Welcome to Ubuntu 16.04.7 LTS (GNU/Linux 4.4.0-210-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

UA Infra: Extended Security Maintenance (ESM) is not enabled.

1 update can be applied immediately.
To see these additional updates run: apt list --upgradable

96 additional security updates can be applied with UA Infra: ESM
Learn more about enabling UA Infra: ESM service for Ubuntu 16.04 at
https://ubuntu.com/16-04

New release '18.04.6 LTS' available.
Run 'do-release-upgrade' to upgrade to it.


Last login: Tue Apr 26 12:44:23 2022 from 10.35.8.67
To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.

ansibleadm@vg-ubuntu-02:~$ whoami
ansibleadm
ansibleadm@vg-ubuntu-02:~$ sudo whoami
[sudo] password for ansibleadm:
root
ansibleadm@vg-ubuntu-02:~$

# new ansible admin with sudo privilleges and access to all servers

#copy server list
ansibleadm@vg-ubuntu-01:~$ sudo cp /home/vagrant/custom-inventory.ini .
ansibleadm@vg-ubuntu-01:~$ cat create_group_loop.yaml
---
- name: creating groups with loop
  hosts: all
  become: true
  tasks:
   - group:
      name: "{{ item }}"
      state: present
     loop:
      - group1
      - group2
ansibleadm@vg-ubuntu-01:~$ ansible-playbook create_group_loop.yaml -i custom-inventory.ini --syntax-check

playbook: create_group_loop.yaml

ansibleadm@vg-ubuntu-01:~$ ansible-playbook create_group_loop.yaml -i custom-inventory.ini --check

PLAY [creating groups with loop] *******************************************************************************************************

TASK [Gathering Facts] *****************************************************************************************************************
fatal: [vg-ubuntu-02]: FAILED! => {"msg": "Missing sudo password"}
fatal: [vg-centos-02]: FAILED! => {"msg": "Missing sudo password"}
fatal: [vg-centos-01]: FAILED! => {"msg": "Missing sudo password"}

PLAY RECAP *****************************************************************************************************************************
vg-centos-01               : ok=0    changed=0    unreachable=0    failed=1    skipped=0    rescued=0    ignored=0
vg-centos-02               : ok=0    changed=0    unreachable=0    failed=1    skipped=0    rescued=0    ignored=0
vg-ubuntu-02               : ok=0    changed=0    unreachable=0    failed=1    skipped=0    rescued=0    ignored=0


FIX:
#become: no
ansibleadm@vg-ubuntu-01:~$ cat create_group_loop.yaml
---
- name: creating groups with loop
  hosts: all
  become: no
  tasks:
   - group:
      name: "{{ item }}"
      state: present
     loop:
      - group1
      - group2
      
ansibleadm@vg-ubuntu-01:~$ ansible-playbook create_group_loop.yaml -i custom-inventory.ini --list-hosts

playbook: create_group_loop.yaml

  play #1 (all): creating groups with loop      TAGS: []
    pattern: [u'all']
    hosts (3):
      vg-ubuntu-02
      vg-centos-02
      vg-centos-01

ansibleadm@vg-ubuntu-01:~$ ansible all -m ping -i custom-inventory.ini
vg-ubuntu-02 | SUCCESS => {
    "ansible_facts": {
        "discovered_interpreter_python": "/usr/bin/python3"
    },
    "changed": false,
    "ping": "pong"
}
vg-centos-02 | SUCCESS => {
    "ansible_facts": {
        "discovered_interpreter_python": "/usr/libexec/platform-python"
    },
    "changed": false,
    "ping": "pong"
}
vg-centos-01 | SUCCESS => {
    "ansible_facts": {
        "discovered_interpreter_python": "/usr/libexec/platform-python"
    },
    "changed": false,
    "ping": "pong"
}


ansibleadm@vg-ubuntu-01:~$ ansible-playbook create_group_loop.yaml -i custom-inventory.ini --check

PLAY [creating groups with loop] *******************************************************************************************************

TASK [Gathering Facts] *****************************************************************************************************************
ok: [vg-centos-02]
ok: [vg-ubuntu-02]
ok: [vg-centos-01]

TASK [group] ***************************************************************************************************************************
changed: [vg-ubuntu-02] => (item=group1)
changed: [vg-centos-02] => (item=group1)
changed: [vg-centos-01] => (item=group1)
changed: [vg-ubuntu-02] => (item=group2)
changed: [vg-centos-02] => (item=group2)
changed: [vg-centos-01] => (item=group2)

PLAY RECAP *****************************************************************************************************************************
vg-centos-01               : ok=2    changed=1    unreachable=0    failed=0    skipped=0    rescued=0    ignored=0
vg-centos-02               : ok=2    changed=1    unreachable=0    failed=0    skipped=0    rescued=0    ignored=0
vg-ubuntu-02               : ok=2    changed=1    unreachable=0    failed=0    skipped=0    rescued=0    ignored=0
ansibleadm@vg-ubuntu-01:~$ ansible-playbook create_group_loop.yaml -i custom-inventory.ini --check --ask-pass
SSH password:

PLAY [creating groups with loop] *******************************************************************************************************

TASK [Gathering Facts] *****************************************************************************************************************
ok: [vg-centos-02]
ok: [vg-ubuntu-02]
ok: [vg-centos-01]

TASK [group] ***************************************************************************************************************************
changed: [vg-ubuntu-02] => (item=group1)
changed: [vg-centos-02] => (item=group1)
changed: [vg-centos-01] => (item=group1)
changed: [vg-ubuntu-02] => (item=group2)
changed: [vg-centos-02] => (item=group2)
changed: [vg-centos-01] => (item=group2)

PLAY RECAP *****************************************************************************************************************************
vg-centos-01               : ok=2    changed=1    unreachable=0    failed=0    skipped=0    rescued=0    ignored=0
vg-centos-02               : ok=2    changed=1    unreachable=0    failed=0    skipped=0    rescued=0    ignored=0
vg-ubuntu-02               : ok=2    changed=1    unreachable=0    failed=0    skipped=0    rescued=0    ignored=0


# turn off password authentication on vg-ubuntu-02

vagrant@vg-ubuntu-02:~$ sudo grep --color PasswordAuthentication /etc/ssh/sshd_config
PasswordAuthentication yes
# PasswordAuthentication.  Depending on your PAM configuration,
# PAM authentication, then enable this but set PasswordAuthentication
vagrant@vg-ubuntu-02:~$ sudo sed -i 's/PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
vagrant@vg-ubuntu-02:~$ sudo service ssh restart
vagrant@vg-ubuntu-02:~$ sudo grep --color PasswordAuthentication /etc/ssh/sshd_config
PasswordAuthentication no

#connect to vg-ubuntu-02 in passwordless SSH mode from controller vg-ubuntu-01

ansibleadm@vg-ubuntu-01:~$ ssh ansibleadm@vg-ubuntu-02
Welcome to Ubuntu 16.04.7 LTS (GNU/Linux 4.4.0-210-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

UA Infra: Extended Security Maintenance (ESM) is not enabled.

1 update can be applied immediately.
To see these additional updates run: apt list --upgradable

96 additional security updates can be applied with UA Infra: ESM
Learn more about enabling UA Infra: ESM service for Ubuntu 16.04 at
https://ubuntu.com/16-04

New release '18.04.6 LTS' available.
Run 'do-release-upgrade' to upgrade to it.


Last login: Tue Apr 26 13:01:14 2022 from 10.35.8.67
ansibleadm@vg-ubuntu-02:~$

#verify passwordless connection from controller vg-ubuntu-01

vagrant@vg-ubuntu-02:~$ sudo tail -f /var/log/auth.log
Apr 26 13:04:52 ubuntu-xenial sshd[7883]: Accepted publickey for ansibleadm from 10.35.8.67 port 46452 ssh2: RSA SHA256:YDWRPmsGRx4/9FmTOgml/B7MbEFcP52Oj9oMWIF7F/Q
Apr 26 13:04:52 ubuntu-xenial sshd[7883]: pam_unix(sshd:session): session opened for user ansibleadm by (uid=0)
Apr 26 13:04:52 ubuntu-xenial systemd: pam_unix(systemd-user:session): session opened for user ansibleadm by (uid=0)
Apr 26 13:04:52 ubuntu-xenial systemd-logind[1067]: New session 31 of user ansibleadm.

#no need to set become: no in ssh.yaml
ansibleadm@vg-ubuntu-01:~$ cat ssh.yaml | grep become
  become: true
  
$ ansible-playbook ssh.yaml -i custom-inventory.ini --check -bK
BECOME password:

PLAY [Create New User] *****************************************************************************************************************

TASK [Create User] *********************************************************************************************************************
ok: [vg-ubuntu-02]
ok: [vg-centos-02]
ok: [vg-centos-01]

TASK [Deploy SSH Public Key] ***********************************************************************************************************
ok: [vg-ubuntu-02]
ok: [vg-centos-02]
ok: [vg-centos-01]

TASK [Deny root from login] ************************************************************************************************************
changed: [vg-ubuntu-02]
changed: [vg-centos-02]
changed: [vg-centos-01]

PLAY RECAP *****************************************************************************************************************************
vg-centos-01               : ok=3    changed=1    unreachable=0    failed=0    skipped=0    rescued=0    ignored=0
vg-centos-02               : ok=3    changed=1    unreachable=0    failed=0    skipped=0    rescued=0    ignored=0
vg-ubuntu-02               : ok=3    changed=1    unreachable=0    failed=0    skipped=0    rescued=0    ignored=0

#run playbook for only a specific server group ubuntu_servers,-l ubuntu_servers

#password in ssh.yaml, not the password set on vg-ubuntu-01 by sudo user vagrant, two different passwords

ansibleadm@vg-ubuntu-01:~$ ansible-playbook ssh.yaml -i custom-inventory.ini --check -bK -l ubuntu_servers
BECOME password:

PLAY [Create New User] *****************************************************************************************************************

TASK [Create User] *********************************************************************************************************************
ok: [vg-ubuntu-02]

TASK [Deploy SSH Public Key] ***********************************************************************************************************
ok: [vg-ubuntu-02]

TASK [Deny root from login] ************************************************************************************************************
changed: [vg-ubuntu-02]

PLAY RECAP *****************************************************************************************************************************
vg-ubuntu-02               : ok=3    changed=1    unreachable=0    failed=0    skipped=0    rescued=0    ignored=0

# disable root login and passwordauthentication, only passwordless SSH logins enabled

ansibleadm@vg-ubuntu-01:~$ cat ssh.yaml
---
- name: Create New User
  hosts: all
  become: true
  gather_facts: false
  vars:
# Define your username and password here that you want to create on target hosts.
    username: ansibleadm
    userpass: admpass
  tasks:
    - name: "Create User"
      ansible.builtin.user:
        name: "{{ username }}"
        state: present
        shell: /bin/bash
        password: "{{ userpass | password_hash('sha512') }}"
        update_password: on_create
        groups: "{{ super_group }}"
        append: yes

    - name: "Deploy SSH Public Key"
      authorized_key:
       user: "{{ username }}"
       state: present
       key: "{{ lookup('file', '/home/{{ username }}/.ssh/id_rsa.pub') }}"

    - name: "Disable password login, only SSH enabled"
      lineinfile:
          dest: /etc/ssh/sshd_config
          regexp: '^(#)?PasswordAuthentication \w*$'
          line: 'PasswordAuthentication no'
          state: present

    - name: "Deny root from login"
      lineinfile:
          dest: /etc/ssh/sshd_config
          regexp: '^(#)?PermitRootLogin \w*$'
          line: 'PermitRootLogin no'
          state: present
          
#password authentication disable, avoid small "-k" for now
#    -k, --ask-pass: ask for connection password
#    -K, --ask-become-pass: ask for privilege escalation password

ansibleadm@vg-ubuntu-01:~$ ansible-playbook ssh.yaml -i custom-inventory.ini -bk -l centos_servers
SSH password:

PLAY [Create New User] *****************************************************************************************************************

TASK [Create User] *********************************************************************************************************************
fatal: [vg-centos-02]: FAILED! => {"msg": "Missing sudo password"}
fatal: [vg-centos-01]: FAILED! => {"msg": "Missing sudo password"}

PLAY RECAP *****************************************************************************************************************************
vg-centos-01               : ok=0    changed=0    unreachable=0    failed=1    skipped=0    rescued=0    ignored=0
vg-centos-02               : ok=0    changed=0    unreachable=0    failed=1    skipped=0    rescued=0    ignored=0 


#password authentication disable, runs big "-K"
#    -k, --ask-pass: ask for connection password
#    -K, --ask-become-pass: ask for privilege escalation password

ansibleadm@vg-ubuntu-01:~$ ansible-playbook ssh.yaml -i custom-inventory.ini -bK -l centos_servers
BECOME password:

PLAY [Create New User] *****************************************************************************************************************

TASK [Create User] *********************************************************************************************************************
ok: [vg-centos-02]
ok: [vg-centos-01]

TASK [Deploy SSH Public Key] ***********************************************************************************************************
ok: [vg-centos-02]
ok: [vg-centos-01]

TASK [Disable password login, only SSH enabled] ****************************************************************************************
ok: [vg-centos-02]
ok: [vg-centos-01]

TASK [Deny root from login] ************************************************************************************************************
ok: [vg-centos-02]
ok: [vg-centos-01]

PLAY RECAP *****************************************************************************************************************************
vg-centos-01               : ok=4    changed=0    unreachable=0    failed=0    skipped=0    rescued=0    ignored=0
vg-centos-02               : ok=4    changed=0    unreachable=0    failed=0    skipped=0    rescued=0    ignored=0
-----------------------------------------------------------------------------------------------------
#create cron jobs remotely

ansibleadm@vg-ubuntu-01:~$ cat cron.yml
---
- name: "set cron jobs"
  hosts: all
  tasks:
   #Ensure a job that runs at 2 and 5 exists.
   # Creates an entry like "0 5,2 * * ls -alh > /dev/null"
   - name: "set disk space cron job - crontab -e"
     cron:
      name: "check disk space"
      minute: "0"
      hour: "5,2"
      job: "df -h"
      user: "ansibleadm" # add sudo crontab -e
      state: present
      #state: absent
   - name: "set memory space cron job -sudo crontab -e"
     cron:
      name: "check memory space"
      minute: "0"
      hour: "5,2"
      job: "free -m"
      state: present
      #state: absent
      user: "root" # add sudo crontab -e
      

ansibleadm@vg-ubuntu-01:~$ ansible-playbook cron.yml -i custom-inventory.ini -l ubuntu_servers --syntax-check

playbook: cron.yml
ansibleadm@vg-ubuntu-01:~$ ansible-playbook cron.yml -i custom-inventory.ini -l ubuntu_servers --check

(ansibleadm cron jobs, crontab -l,crontab -e)
$ ansible-playbook cron.yml -i custom-inventory.ini -l ubuntu_servers -K 

(ansibleadm cron jobs, sudo crontab -l,sudo crontab -e)
$ ansibleadm@vg-ubuntu-01:~$ ansible-playbook cron.yml -i custom-inventory.ini -l ubuntu_servers -bK

#verify
ansibleadm@vg-ubuntu-02:~$ crontab -l
#Ansible: check disk space
0 5,2 * * * df -h
-----------------------------------------------------------------------------------------------------
#Deprecation warnings can be disabled by setting deprecation_warnings=False in ansible.cfg.
$ cat /etc/ansible/ansible.cfg  | grep deprecation
# by default (as of 1.4), Ansible may display deprecation warnings for language
#deprecation_warnings = True

#disable
sudo sed -i 's/#deprecation_warnings = True/deprecation_warnings = False/' /etc/ansible/ansible.cfg
#enable
sudo sed -i 's/deprecation_warnings = False/deprecation_warnings = True/' /etc/ansible/ansible.cfg
-----------------------------------------------------------------------------------------------------
#troubleshooting
#add an entry like this to the /etc/hosts file on your Ansible control node to resolve the hostname to an IP address.

Problem:
 "msg": "Failed to connect to the host via ssh: ssh: Could not resolve hostname server1.example.com: Name or service not known",
Fix:
# nslookup server1.example.com
-----------------------------------------------------------------------------------------------------
#troubleshooting
#If you don't want to modify ansible.cfg or the playbook.yml then you can just set an environment variable:

Problem:
 The authenticity of host 'xx' can't be established due to 'Host is unknown: xx'.\nThe ssh-rsa key fingerprint is SHA1:xx.
Fix:
# export ANSIBLE_HOST_KEY_CHECKING=False
-----------------------------------------------------------------------------------------------------
#troubleshooting
Problem:
fatal: [albus.local]: FAILED! => {"msg": "to use the 'ssh' connection type with passwords, you must install the sshpass program"}
Fix:
apt install sshpass
-----------------------------------------------------------------------------------------------------
#troubleshooting

Problem:
{"changed": false, "msg": "ssh connection failed: ssh connect failed: No route to host"}

Fix:
# ansible -i inventory hostname -m ping
-----------------------------------------------------------------------------------------------------
#troubleshooting,Enabling Networking logging

export ANSIBLE_LOG_PATH=~/ansible.log # Specify the location for the log file

export ANSIBLE_DEBUG=True # Enable Debug

# Run with 4*v for connection level verbosity
ansible-playbook -vvvv 

# less $ANSIBLE_LOG_PATH
# grep "p=28990" $ANSIBLE_LOG_PATH

#ensure connectivity by attempting to execute a single command on the remote device
    connect to switch1.example.net specified in the inventory file inventory
    use the module arista.eos.eos_command
    run the command ?
    connect using the username admin
    inform the ansible command to prompt for the SSH password by specifying -k

ansible -m arista.eos.eos_command -a 'commands=?' -i inventory switch1.example.net -e 'ansible_connection=ansible.netcommon.network_cli' -u admin -k
ansible -m cisco.ios.ios_command -a 'commands=?' -i inventory switch1.example.net -e 'ansible_connection=ansible.netcommon.network_cli' -u admin -k

#=====================================================================
#ansible,https://docs.ansible.com/ansible/latest/collections/fortinet/fortios/fortios_monitor_fact_module.html

ansible-galaxy collection install fortinet.fortios
ansible-galaxy collection list #check whether it is installed
# ansible-galaxy collection verify fortinet.fortios #verify

ansible-galaxy collection install fortinet.fortios -f
ansible-galaxy collection install -f fortinet.fortios:1.1.9

-----------------------------------------------------------------------------------------------------

