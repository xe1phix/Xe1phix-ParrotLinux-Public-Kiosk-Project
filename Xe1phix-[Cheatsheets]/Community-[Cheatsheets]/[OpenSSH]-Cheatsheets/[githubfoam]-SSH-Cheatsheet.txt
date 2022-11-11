-----------------------------------------------------------------------------------------------------
#disable public key authentication, connect as user root via ssh 
sshuser@vg-ubuntu-01:~$ ssh root@vg-ubuntu-02 -o PubkeyAuthentication=no
-----------------------------------------------------------------------------------------------------
#connect with one private key

#access ec2-23-22-230-24.compute-1.amazonaws.com with a private key located in ~/.ssh/alice.pem
$ ssh -i ~/.ssh/alice.pem alice@ec2-23-22-230-24.compute-1.amazonaws.com
-----------------------------------------------------------------------------------------------------
$ cat ~/.ssh/config
Host server
    Hostname 0.0.0.0
    User batman
    IdentityFile ~/.ssh/id_rsa_server
    
~/.ssh/config #ssh gets its configuration from locally
/etc/ssh/config #ssh gets its configuration from globally 
$ ssh -v server #see if your config file is loaded
$ ls -ld --  .ssh*/ #Directory permissions should be 700
$ ssh -v -F ~/.ssh/config #

#multiple private keys,declare which private key to use for each SSH server,~/.ssh/config
#cannot directly SSH to alternative names (e.g., IP address or hostname alias defined in /etc/hosts) of the SSH server

$ cat ~/.ssh/config
Host ec2-23-22-230-24.compute-1.amazonaws.com
  IdentityFile ~/.ssh/alice.pem

Host ec2-33-01-200-71.compute-1.amazonaws.com
  IdentityFile ~/.ssh/alice_v2.pem

$ ssh alice@ec2-23-22-230-24.compute-1.amazonaws.com # SSH without explicitly specifying your private key with -i option
-----------------------------------------------------------------------------------------------------
ssh-keyscan -H 192.168.1.162 >> ~/.ssh/known_hosts # update the known_hosts file located in the path, ~/.ssh/known_hosts, with the scanned fingerprint found in the IP address
ssh-keyscan hostname #Print the rsa1 host key for machine hostname
ssh-keyscan -p 22 10.0.2.15 #shows the different keys that have been scanned at port number 22 
ssh-keyscan -t rsa 10.0.2.15 #read all public keys of the rsa type from the IP address 10.0.2.15

#Find all hosts from the file ssh_hosts which have new or different keys from those in the sorted file ssh_known_hosts
"ssh-keyscan -t rsa,dsa -f ssh_hosts | sort -u - ssh_known_hosts | diff ssh_known_hosts -"
#The -t option has been used to retrieve the rsa keys, and the -f option has been used to retrieve the keys from the known_hosts file
ssh-keyscan -t rsa -f ~/.ssh/known_hosts | sort -u ~/.ssh/known_hosts
-----------------------------------------------------------------------------------------------------
 #troubleshooting
journalctl -u sshd
grep sshd /var/log/auth.log
grep sshd /var/log/secure

ssh -vvvvvv host
ssh -T git@github.com #verify your connection

#make sure you are connecting to the right domain
#check that the key is being used by trying to connect to git@github.com
#The "-1" at the end of the "identity file" lines means SSH couldn't find a file to use
#If a file existed, those lines would be "1" and "Offering public key", respectively
ssh -vT git@github.com 

ssh -G host


#putty debug
"Session"-"Logging" -"all session output"-"SSH packet data"
-----------------------------------------------------------------------------------------------------
 ~/.ssh/known_hosts ->check host entries
 
ls -al ~/.ssh -> See if existing SSH keys are present
#[-t dsa | ecdsa | ecdsa-sk | ed25519 | ed25519-sk | rsa] 
#RSA – 1024, 2048, or 4096 bit keys
ssh-keygen -t rsa -b 4096 -C "your_email@example.com" -> Generate a new SSH key (if there is no private/public keys)

#Make sure you have a key that is being used
eval "$(ssh-agent -s)" - > Start the ssh-agent in the background,If you are using Git Bash, turn on ssh-agent
eval $(ssh-agent -s) #start the ssh-agent in the background,If you are using another terminal prompt, such as Git for Windows, turn on ssh-agen

#Verify the public key is attached to your account
ssh-agent -s #Start SSH agent in the background
ssh-add -l -E sha256 #Find and take a note of your public key fingerprint

ssh-add ~/.ssh/id_rsa ->Add your SSH private key to the ssh-agent.
ssh-keygen -p -> change the passphrase for an existing private key without regenerating the keypair
ssh -T git@github.com -> Test your SSH connection  (If SSH is closed, Using SSH over the HTTPS port)

ssh -T -p 443 git@ssh.github.com -> To test if SSH over the HTTPS port is possible
~/.ssh/config -> Enabling SSH connections over HTTPS
~/.ssh/config -> Create config file
---config---
Host github.com
  Hostname ssh.github.com
  Port 443
---config---

ssh -T git@github.com -> Test  this configuration

PROBLEM:Bad owner or permissions on /home/userxx/.ssh/config
FIX:chmod 600 ~/.ssh/config


ONE USER HAS MULTIPLE GITHUB ACCOUNTS && SSH OVER HTTPS REQUIRED
one user has two profiles, such as githubPersonal && githubWork
githubPersonal has different account and repos on github
githubWork has different account and repos on github

~/.ssh

$ ssh-keygen -t rsa -b 4096 -C "email@githubPersonal" -> Generate a new SSH key (if there is no private/public keys)
$ ssh-keygen -t rsa -b 4096 -C "email@githubWork" -> Generate a new SSH key (if there is no private/public keys)
$ ssh-keygen -t rsa -b 4096 -f ~/.ssh/vps-cloud.web-server.key -C "My web-server key"

upload public keys on github
~/.ssh/id_rsa_personal.pub
~/.ssh/id_rsa_work.pub

 ~/.ssh/config

---config---
Host github-personal
  Hostname ssh.github.com
  user git
  Port 443
  IdentityFile ~/.ssh/id_rsa_github-personal

Host github-workfirst
  Hostname ssh.github.com
  user git
  Port 443
  IdentityFile ~/.ssh/id_rsa_github-workfirst
---config---

ssh-add -D -> Deletes all identities from the agent.

eval "$(ssh-agent -s)" - > Start the ssh-agent in the background

ssh-add id_rsa_personal -> Add new keys - private keys
ssh-add id_rsa_work -> Add new keys - private keys

ssh-add -l -> Test to make sure new keys are stored
ssh-add -l -E sha256 #Verify that you have a private key generated and loaded into SSH

ssh -T -p 443 git@ssh.github.com -> To test if SSH over the HTTPS port is possible
ssh -T git@githubworkfirst -> Test  this configuration

git clone git@github-workfirst:githubaccount1/testrepo1.git testdirectory1
git clone git@github-personal:githubaccount2/testrepo2.git testdirectory1

--------------------------------------------------------------------------------------------------------------------


$ eval "$(ssh-agent -s)" # start ssh-agent
Agent pid 580516
$ ssh-add ~/.ssh/id_rsa #Upload the private key that you generated
Identity added: /home/sshuser/.ssh/id_rsa (sshuser@vg-ubuntu-01)
$ ssh-add -l
4096 SHA256:1R37PbdplAwzHRECwPZGCVB27QSRwk+Z34LYNuUrv9U sshuser@vg-ubuntu-01 (RSA)
$ ssh-add -L
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQDwjXzwttGq5qGcyZuStCzHy2Zu6g+2WGXNrUly10olY6nZBQE2pLPbbYwMavuQvyj7NHsyXH+3soVLiekkoLgZNpx1KAmqL7eqnGaio0mqJn5VGrM6hNSGj7D17kd9wc2ijIFZdCLVNmdrwTtf2OHSwVcUGcP1IVx6pQ3Odt8C2twg+BwEX11j37VuZdCP2IMvE/t+dRHH4Xf7naXFsJAZFj5H2S2usErswKC4e1PQY8Y4PwR1NRCpyxNT5ZgDq885KgeYy0ThdJveYV7wdRLzYdHHU3hLTE3X83JkPZdt/CI7fXmWjH58y9CS3EAfBnrzQVd67fCoA8PCW4ruYCNSNQT9nAHWFzBM9wwNhpHa9p5m2fWnJGZbLts/0xOct3eVnTEONqq8DneYPQO4MWDMk5ebYjYlW7f7PLCMawjadhh3gGEP6TfD0QP9wSOtNFpYFjPUoFvwgH1wL2XuoY8xgfZ5bir0mZF+z6bj/hZQK2DQwHJ0JkbFGQaengLT4AljaEnR5FI2FAmBTnsH2GNinASceCM1My4MLtkyc+ZWMj3/r9X7GCol4CGIgcguVJR6RHsBehFc7QraYC8xiSWynSSo+iL0S7/2yzx6BY4urM7HHVVCuVAWo8ZxD4MaJEZZjAF33/L3ZHMhHQRQGqnTGZoV6Sf6rSeghNlt171wrw== sshuser@vg-ubuntu-01
--------------------------------------------------------------------------------------------------------------------
$ eval "$(ssh-agent -k)" # stop ssh-agent
Agent pid 580516 killed

if [ $(ps ax | grep [s]sh-agent | wc -l) -gt 0 ] ; then echo "ssh-agent is already running";else echo "ssh-agent is not running"; fi

$ cat $HOME/.ssh-agent
$ cat ~/.ssh-agent
SSH_AUTH_SOCK=/tmp/ssh-KAWKW9dtK6iJ/agent.582546; export SSH_AUTH_SOCK;
SSH_AGENT_PID=582547; export SSH_AGENT_PID;
echo Agent pid 582547;

#list all ssh-agents and kill all
sshuser@vg-ubuntu-01:~$ eval "$(ssh-agent -s)"
Agent pid 580952
sshuser@vg-ubuntu-01:~$ echo $(pidof ssh-agent)
580952
sshuser@vg-ubuntu-01:~$ eval "$(ssh-agent -s)"
Agent pid 580967
sshuser@vg-ubuntu-01:~$ echo $(pidof ssh-agent)
580967 580952
sshuser@vg-ubuntu-01:~$ killall ssh-agent
sshuser@vg-ubuntu-01:~$ echo $(pidof ssh-agent)

$ eval "$(ssh-agent -s)"
Agent pid 581391
$ pgrep -u $USER -n ssh-agent -a
581391 ssh-agent -s
$ export SSH_AGENT_PID=$(pgrep -u $USER -n ssh-agent) && echo $SSH_AGENT_PID
581391

eval "$(ssh-agent -s)" # start ssh-agent
eval `ssh-agent` # start ssh-agent
SSH_AGENT_PID="$(pidof ssh-agent)" ssh-agent -k # stop ssh-agent
kill -9 $(pidof ssh-agent) # stop ssh-agent
eval "$(ssh-agent -k)" # stop ssh-agent

start the ssh-agent
$ exec ssh-agent bash
add the ~/.ssh/id_rsa, ~/.ssh/id_dsa and ~/.ssh/identity files to ssh-agent
$ ssh-add
Display the entries loaded in ssh-agent
$ ssh-add -l #Lists fingerprints of all identities currently represented by the agent.
$ ssh-add -L #the -L option allows you to view the public keys of the identities ssh-agent currently maintains.
Delete all entries from ssh-agent
$ ssh-add -D
Delete specific entries from ssh-agent
$ ssh-add -d /home/ramesh/.ssh/id_rsa
Lock (or) Unlock the SSH Agent
$ ssh-add -x
-----------------------------------------------------------------------------------------------------
# add a passphrase to ssh-agent and you will not be prompted for it when using ssh or scp/sftp/rsync to connect to hosts with your public key
eval $(ssh-agent)
# Type the ssh-add command to prompt the user for a private key passphrase and adds it to the list maintained by ssh-agent command
ssh-add
#add or replace a passphrase for an existing private key
ssh-keygen -p
#backup an existing private/public key
rsync -avr $HOME/.ssh user@home.nas-server:/path/to/encrpted/nas/partition/
cp -avr $HOME/.ssh/ /mnt/usb/backups/

 $HOME/.ssh/id_rsa– contains your private key.
 $HOME/.ssh/id_rsa.pub – contain your public key.
 
 ls -la .ssh
"id_rsa.pub" public keys
"id_rsa" private keys
"authorized_keys2" list of hosts authorized to login remotely using the private key
"known_hosts" list of remote hosts that users connect to from this host
-----------------------------------------------------------------------------------------------------
	Home directory on the server should not be writable by others: chmod go-w /home/$USER
	 home directory should not be writeable by the group or others 755 (drwxr-xr-x)
	 chmod g-w,o-w ~
	
	Make sure that user owns the files/folders and not root: chown user:user authorized_keys and chown user:user /home/$USER/.ssh
	SSH folder on the server needs 700 permissions: chmod 700 /home/$USER/.ssh
	
	#If you are still prompted for a password 
	ssh [remote_username]@[server_ip_address] "chmod 700 .ssh; chmod 640 .ssh/authorized_keys"
	Set permissions 700 for the .ssh directory.
	Set permissions 640 for the .ssh/authorized_keys directory.
	
	the directory containing your .ssh directory must not be writeable by group or other. Thus chmod go-w ~
	public key (.pub file): 644 (-rw-r--r--)
	private key (id_rsa): 600 (-rw-------)
	Authorized_keys file needs 644 permissions: chmod 644 /home/$USER/.ssh/authorized_key
	Put the generated public key (from ssh-keygen) in the user's authorized_keys file on the server
	restart ssh: service ssh restart
	make sure client has the public key and private key files in the local user's .ssh folder and login: ssh user@host.com
	------------------------------------------------------------------------------------------
	.ssh directory itself must be writable only by you: 
	chmod 700 ~/.ssh 
	or 
	chmod u=rwx,go= ~/.ssh.
	chmod 600 ~/.ssh/id_rsa;  or chmod 400 ~/.ssh/id_rsa; (private key protection)
	chmod 600 ~/.ssh/id_rsa.pub (i.e. chmod u=rw,go= ~/.ssh/id_rsa ~/.ssh/id_rsa.pub)
	or 
	chmod 644 ~/.ssh/id_rsa.pub (i.e. chmod a=r,u+w ~/.ssh/id_rsa.pub) 
------------------------------------------------------------------------------------------
	chmod 700 ~/.ssh
	chmod 644 ~/.ssh/authorized_keys
	chmod 644 ~/.ssh/known_hosts
	chmod 644 ~/.ssh/config
	chmod 600 ~/.ssh/id_rsa
	chmod 644 ~/.ssh/id_rsa.pub
	chmod 600 ~/.ssh/github_rsa
	chmod 644 ~/.ssh/github_rsa.pub
	chmod 600 ~/.ssh/mozilla_rsa
	chmod 644 ~/.ssh/mozilla_rsa.pub
    

------------------------------------------------------------------------------------------
 # copy public key method 
 ssh sheena@192.168.0.11 "chmod 700 .ssh; chmod 600 .ssh/authorized_keys
 # copy public key method 
 cat ~/.ssh/id_rsa.pub | ssh username@remote_host "mkdir -p ~/.ssh && touch ~/.ssh/authorized_keys && chmod -R go= ~/.ssh && cat >> ~/.ssh/authorized_keys"
 # copy public key method 
 ssh-copy-id -i ~/.ssh/id_rsa.pub user@remote-server
 # copy public key method 
 scp -pr  ~/.ssh/id_rsa.pub ram@client.itzgeek.local:/tmp
 # copy public key method 
 cat ~/.ssh/id_rsa.pub | ssh username@remote_host "mkdir -p ~/.ssh && cat >> ~/.ssh/authorized_keys"
# copy public key method 
# cat ~/.ssh/id_rsa.pub | ssh user@remote-host "cat >> ~/.ssh/authorized_keys"
 
 #copy mykey.rsa.pub to the target server (not id_rsa.pub)
 #the target server has the host server key (hostkey.rsa.pub) in .ssh/authorized_keys
 ssh-copy-id -i mykey.rsa.pub -o "IdentityFile hostkey.rsa" user@target 
 ssh-copy-id -f -i hostkey.rsa.pub user@target
 
 # change is the listening port number
 # vi /etc/ssh/sshd_config
 Port 22
 Port 2022
 
 echo public_key_string >> ~/.ssh/authorized_keys
 
 # if StrictModes is set to yes in /etc/ssh/sshd_config (the default)
 #machine, keys created
$ chmod 700 ~/.ssh
$ chmod 600 ~/.ssh/id_rsa 
 #destination machine
 chmod 700 ~/.ssh
 chmod 600 ~/.ssh/authorized_keys
 
------------------------------------------------------------------------------------------
servera - server
serverb - server

***servera
$ systemctl status ssh # verify ssh running
$ systemctl status ssh # verify sshd running
● ssh.service - OpenBSD Secure Shell server
   Loaded: loaded (/lib/systemd/system/ssh.service; enabled; vendor preset: enabled)
   Active: active (running) since Paz 2019-06-23 16:07:02 +03; 27min ago
 Main PID: 5373 (sshd)
   CGroup: /system.slice/ssh.service
           └─5373 /usr/sbin/sshd -D
 $ cat /etc/passwd | grep vagrant # verify user
vagrant:x:1003:1004::/home/vagrant:
 $ cat .ssh/authorized_keys # verify copied public key

 ***serverb
 $ systemctl status ssh # verify ssh running
  $ systemctl status sshd # verify ssh running
 $ cat /etc/passwd | grep vagrant # verify user
 vagrant:x:1003:1004::/home/vagrant:
 $ ssh-keygen -t rsa
 $ ssh-copy-id -i $HOME/.ssh/id_rsa.pub vagrant@servera # copy public key method 1
 $ scp $HOME/.ssh/id_rsa.pub vagrant@servera:~/.ssh/authorized_keys # copy public key method 2
 $ cat $HOME/.ssh/id_rsa.pub | ssh vagrant@servera "cat >> .ssh/authorized_keys" # copy public key method 3
 $ ssh vagrant@servera # test passwordless public key-based authentication
 $ scp foo.txt vagrant@servera:/tmp/ # test passwordless public key-based authentication
$ cat .ssh/id_rsa.pub # view public key

#ssh-copy-id is a script that uses ssh(1) to log into a remote machine 
#(presumably using a login password, so password authentication should be enabled
#Upload Public Key Using the ssh-copy-id,The public key is then automatically copied into the .ssh/authorized_keys file
ssh-copy-id [remote_username]@[server_ip_address] 

#Upload Public Key Using the cat Command
ssh [remote_username]@[server_ip_address] mkdir -p .ssh #connecting to the server and creating a .ssh directory on it
#upload the public key from the local machine to the remote server,the key will be stored under the name authorized_keys in the newly created .ssh directory
cat .ssh/id_rsa.pub | ssh [remote_username]@[server_ip_address] 'cat >> .ssh/authorized_keys'
ssh [remote_username]@[server_ip_address] #og in to Server Without Password

debug mode, verbose
scp -r -vvvv /tmp/${HOST1}/* ${HOST1}:/tmp
----------------------------------------------------------------------------------------------------
#The guest user will be authenticated by a dedicated SSH key, generated on the client 
#(the machine from which guest is supposed to log in) with
#which also generates the public key guest.key.pub that needs to be copied to the server.

ssh-keygen -t rsa -b 4096 -f guest.key
ssh-add guest.key

#After logging in to the server as ubuntu (or any other superuser) over SSH, create a new user with
sudo adduser --disabled-password guest

sudo mkdir /home/guest/.ssh
sudo nano /home/guest/.ssh/authenticated_keys #the entire content of the file guest.pub

sudo chmod 0755 /home/guest/.ssh
sudo chmod 0644 /home/guest/.ssh/authenticated_keys

ssh -i guest.key guest@<ip-address> #login as guest

-----------------------------------------------------------------------------------------
#when you type ssh user@private1 SSH will establish a connection to the bastion host 
#and then through the bastion host connect to “private1”, using the specified keys
#run "who" on the remote node,see the connections are coming from the bastion host, not the original SSH client

Host private1
  IdentityFile ~/.ssh/rsa_private_key
  ProxyCommand ssh user@bastion -W %h:%p

Host bastion
  IdentityFile ~/.ssh/bastion_rsa_key
------------------------------------------------------------------------------------------
Problem:
$ ssh -i privatekey.ppk ubuntu@SERVERIP

Permissions 0644 for 'privatekey.ppk' are too open.
It is required that your private key files are NOT accessible by others.
This private key will be ignored.
Load key "privatekey.ppk": bad permissions
Permission denied (publickey).

fix:
chmod 600 privatekey.ppk
------------------------------------------------------------------------------------------
Problem:
“couldn't load private key - Putty key format too new.” This issue happens when you use PuTTygen to generate or convert to a ppk key”
PuTTY doesn't support the SSH private key format
convert the private key to the PuTTY required format

fix:
puttygen
private key should have a ppk format
Change the PuTTygen PPK File Version to version 2
-----------------------------------------------------------------------------------------
#convert .ppk under to openssh keys on Windows
Putty Key Generator - Load private key 
Putty Key Generator - Conversions - Export OpenSSH key

-----------------------------------------------------------------------------------------