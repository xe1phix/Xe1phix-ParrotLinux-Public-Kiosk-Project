#!/bin/sh
##-===========================================-##
##    Xe1phix-SecureNetworking-SSH-v2.7.sh
##-===========================================-##
https://cromwell-intl.com/linux/ssh-2-access-control.html





SSH_AUTH_SOCK=/tmp/ssh-WeBckDhIvaF7/agent.11515; export SSH_AUTH_SOCK;
SSH_AGENT_PID=2269; export SSH_AGENT_PID; 




passwd -l $user


## For defense in depth, also replace the users login shell 
## with something that exits immediately and is not a shell.
chsh -s /bin/false username


chmod -R g-w /home/*/.ssh







pstree -u | egrep -C 4 'sshd|ssh-agent'

lsof -i tcp:ssh | egrep 'PID|LISTEN'

ps axuww | egrep 'PID|sshd'

strace -f -e 'read,write' -p 


## Re-start the SSH service
pkill -HUP sshd


systemctl restart sshd


Supported types are:

##   [+] || 0 ||        ## Unknown, not tested.
##   [+] || 2 ||        ## "Safe" prime; (p-1)/2 is also prime.
##   [+] || 4 ||        ## Sophie Germain; 2p+1 is also prime.


The following values test is represented in the following way:

0x00  Not tested.
                        0x01  Composite number – not prime.
                        0x02  Sieve of Eratosthenes.
                        0x04  Probabilistic Miller-Rabin primality tests.





## calculate numbers that are likely to be useful
ssh-keygen -G


## provides a high degree of assurance that the numbers are prime 
## and are safe for use in Diffie-Hellman operations
ssh-keygen -T




cd ~/.ssh
ssh-keygen -t rsa
ssh-keygen -t dsa
ssh-keygen -t ecdsa -b 521
ssh-keygen -t ed25519
sort -u authorized_keys *.pub -o authorized_keys
chmod 644 authorized_keys







ssh‐keygen ‐t dsa ‐N '' 
# cat ~/.ssh/id_dsa.pub | ssh you@host‐server "cat ‐ >> ~/.ssh/authorized_keys2" 

cd ~/.ssh 
# ssh‐keygen ‐i ‐f keyfilename.pub >> authorized_keys2 

scp .ssh/puttykey.pub root@192.168.51.254:.ssh/



ssh‐keygen ‐t rsa ‐N ''
cat ~/.ssh/id_rsa.pub | ssh you@host‐server "cat ‐ >> ~/.ssh/authorized_keys2"


ssh‐keygen ‐i ‐f keyfilename.pub >> authorized_keys2



ssh‐keygen ‐l ‐f /etc/ssh/ssh_host_rsa_key.pub      # For RSA key 
ssh‐keygen ‐l ‐f /etc/ssh/ssh_host_dsa_key.pub      # For DSA key (default) 


scp file.txt host‐two:/tmp 
scp joe@host‐two:/www/*.html /www/tmp 
scp ‐r joe@host‐two:/www /www/tmp 
scp ‐P 20022 cb@cb.vu:unixtoolbox.xhtml .           # connect on port 20022 



##-=-=-=-=--=-=-=-=-=--=-=-=-=-=--=-=-=-=-=-=-##
##  [+] Transfer files to a remote machine:"
##-=-=-=-=--=-=-=-=-=--=-=-=-=-=--=-=-=-=-=-=-##
scp filename user@remotehost:/home/path

##      
##      


##-=-=-=-=--=-=-=-=-=--=-=-=-=-=--=-=-=-=-=-=-=-=-=-=-=-##
##  [+] Copy a file from the remote host to the 
##      current directory with the given filename."
##-=-=-=-=--=-=-=-=-=--=-=-=-=-=--=-=-=-=-=-=-=-=-=-=-=-##
scp $user@$remotehost:/home/path/$filename $filename

echo "recursively copy a directory over a network with the -r parameter:"
scp -r /home/slynux $user@$remotehost:/home/backups		# Copies the directory /home/slynux recurisvely 
														# to a remotelocation

echo "set up a reverse port forward on that remote machine to the local machine"
ssh -R 8000:localhost:80 $user@$REMOTE_MACHINE


ssh ‐R 2022:localhost:22 $user@$gate            # forwards client 22 to gate:2022
ssh ‐L 3022:localhost:2022 $admin@$gate         # forwards client 3022 to gate:2022
ssh ‐p 3022 $admin@$localhost                   # local:3022 ‐> gate:2022 ‐> client:22


ssh ‐L localport:desthost:destport $user@$gate  # desthost as seen from the gate 
ssh ‐R destport:desthost:localport $user@$gate  # forwards your localport to destination 
ssh ‐X $user@$gate   # To force X forwarding 

ssh ‐L 2401:localhost:2401 ‐L 8080:localhost:80 $user@$gate






##-=====================================-##
##  [+] IRC client at localhost:6668
##      localhost:8118 (if Privoxy) 
##-=====================================-##




[you@home ~]$ ssh -L 4242:127.0.0.1:4242 user1@machine1
[user1@machine1 ~]$ ssh -L 4242:127.0.0.1:4242 user2@machine2
[user2@machine2 ~]$ ssh -L 4242:127.0.0.1:4242 user3@machine3

[userN-1@machineN-1 ~]$ ssh -D 4242 userN@machineN




ifconfig eth0 down 
ifconfig eth0 hw ether de:ad:be:ef:f0:0d
ifconfig eth0 up




##-===================================================================================-##
##  [?] This quickstart generates two certificate authorities, and 2048 bit keys.
##      making it the most secure way to create an OpenVPN tunnel.
##-===================================================================================-##


sudo chown -R nobody:nobody /etc/openvpn

adduser openvpn
chown -R openvpn:openvpn /etc/openvpn
modprobe tun
chmod 755 client-up

proto udp
port 53


proto tcp-server/proto tcp-client
port 443



http://kpvz7kpmcmne52qf.onion/wiki/index.php/Intrusive_Surveillance#Watching_Your_Back



ping $LOCAL_GATEWAY_IP
arp -a

##########################################################################
## This should ensure you can connect to the VPN server through your 	##
## specific route for that IP.						##
##########################################################################

ping $VPN_SERVER_IP


ping 192.168.69.1


##########################################################################
## 					 	##
## 						##
## 					 	##
## 						##
## 					 	##
## 						##
##########################################################################

ping $DNSSERVER.IP











echo "## ########################################## ###"
echo "## -L tells ssh to listen on a local port "
echo "## and forward those connections to another host "
echo "## and port through the ssh connection. 	##"
echo "## ########################################## ###"



## ------------------------------------------------------------ ##
    ssh -L 4242:127.0.0.1:4242 $user1@$machine1
## ------------------------------------------------------------ ##
    ssh -L 4242:127.0.0.1:4242 $user2@$machine2
## ------------------------------------------------------------ ##
    ssh -L 4242:127.0.0.1:4242 $user3@$machine3
## ------------------------------------------------------------ ##




##-====================================================================-##
##  [?] -D tells ssh to open up a SOCKS 4 server where you specify. 	##"
##-====================================================================-##
ssh -D 4242 $userN@$machineN
    
    
    
    


##-======================================================================-##
##  [?] OpenVPN is awesome. It provides an encrypted tunnel
##      from your computer to the OpenVPN server. 
##      it is at least useful "one hop" of 
##      anonymous surfing, and restrictive firewalls. 
##-======================================================================-##
## http://forums.gentoo.org/viewtopic.php?t=233080




adduser openvpn
chown -R openvpn:openvpn /etc/openvpn


## recompile kernels to support 
CONFIG_TUN (The Universal Tun/Tap Driver)


modprobe tun
sudo chmod 755 client-osx-up
chmod 755 client-up



Configure server to use 192.168.69.1
Configure client to use 192.168.69.2
 
 
 
## Replace VPN_SERVER_IP in client.conf with your server's IP


##-===============================================================-##
##  [+] Add a publicly available nameserver to /etc/resolv.conf. 
##-===============================================================-##
http://www.opennic.unrated.net/public_servers.html



##########################################################################################
## ## !!! WARNING: !!! ## ## 
## An attentive and fascist network administrator will still be able 
## to determine that you are tunneling packets over an openvpn tunnel by 
## watching your traffic. (rest assured, they won't be able to see what you are doing, 
## just that you're doing something)
#########################################################################################
## change the proto udp and port 53 lines in your server and client configuration
## file to proto tcp-server/proto tcp-client and port 443 (or port 22) 
## to make your openvpn session look more like a secure web (or ssh) connection.
###################################################################################





##-========================================================-##
##  [+] Copy your ssh public key to a server 
##      from a machine that doesn't have ssh-copy-id
##-========================================================-##
cat ~/.ssh/id_rsa.pub | ssh user@machine "mkdir ~/.ssh; cat >> ~/.ssh/authorized_keys"


##-========================================================-##
##  [+] Mount folder/filesystem through SSH
##-========================================================-##
sshfs name@server:/path/to/folder /path/to/mount/point



##-========================================================-##
##  [+] Make encrypted archive of dir/ on remote machine ##
##-========================================================-##
tar -c dir/ | gzip | gpg -c | ssh user@remote 'dd of=dir.tar.gz.gpg'


##-========================================================-##
##  [+] Backup harddisk to remote machine ##
##-========================================================-##
dd bs=1M if=/dev/sda | gzip | ssh user@remote 'dd of=sda.gz'







Protocol 2 
PasswordAuthentication no
AllowUsers 
UseDNS no



echo 'SSHD: ALL' >> /etc/hosts.allow
/etc/init.d/sshd restart





scp file.txt host‐two:/tmp
scp joe@host‐two:/www/*.html /www/tmp
scp ‐r joe@host‐two:/www /www/tmp
scp ‐P 20022 cb@cb.vu:unixtoolbox.xhtml .           ## connect on port 20022








##-================================================================-##
##   [+] add this line in the sshd PAM file ( /etc/pam.d/sshd ):
## ---------------------------------------------------------------- ##
##   [?] before the existing auth lines:
## ---------------------------------------------------------------- ##

auth   required   pam_abl.so config=/etc/security/pam_abl.conf 


##   [?] 




/etc/security/pam_abl.conf

# Black-list any remote host with 10 consecutive authentication failures
# in one hour, or 30 in one day.  Keep them in the black-list for two days
# and then purge them.
host_db=/var/lib/abl/hosts.db
host_purge=2d
host_rule=*:10/1h,30/1d
# Black-list any local user other than root for which there are 10
# consecutive authentication failures in one hour, or 30 in one day.
# Keep them in the black-list for two days and then purge them.
# Note that this means that non-root users may be subjected to denial of
# service attacks caused by remote password guessing.
user_db=/var/lib/abl/users.db
user_purge=2d
user_rule=!root:10/1h,30/1d 



ssh-add -l















##-=-=-=-=--=-=-=-=-=--=-=-=-=-=--=-##
##  [+] Authenticating to GitHub
##-=-=-=-=--=-=-=-=-=--=-=-=-=-=--=-##







https://github.com/settings/tokens/new
https://help.github.com/enterprise/2.12/user/articles/creating-a-personal-access-token-for-the-command-line/


https://help.github.com/articles/using-ssh-over-the-https-port/






##-=-=-=-=--=-=-=-=-=--=-=-=-=-=--=-##
##  [+] sign a tag:


## ------------------------------------------- ##
##   [?] add -s to your git tag command.
## ------------------------------------------- ##
git tag -s mytag				# Creates a signed tag


## ---------------------------------==---------- ##
##   [?] Verify your signed tag it by running: 
## ---------------------------------==---------- ##
echo " [^] git tag -v [tag-name]."




git tag -v mytag				## Verifies the signed tag


git config commit.gpgsign true. 


## ------------------------------------------------ ##
##   [?] To sign all commits by default In any 
##       local repository on your computer, run 
## ------------------------------------------------ ##
git config --global commit.gpgsign true





## ------------------------------------------------------- ##
##   [?] When committing changes In your local branch
## ------------------------------------------------------- ##

##-=-=-=-=--=-=-=-=-=--=-=-=-=-=--=-=-=-=-=--=-=-=-=-=-##
##  [+] add the -S flag to the git commit command:"
##-=-=-=-=--=-=-=-=-=--=-=-=-=-=--=-=-=-=-=--=-=-=-=-=-##

git commit -S -m your commit message			            ## Creates a signed commit




## ------------------------------------------------------- ##
##   [?] When youve finished creating commits locally
## ------------------------------------------------------- ##
##-=-=-=-=--=-=-=-=-=--=-=-=-=-=--=-=-=-=-=--=-=-=-=-=-=-=-##
##  [+] Push them to your remote repository on GitHub:
##-=-=-=-=--=-=-=-=-=--=-=-=-=-=--=-=-=-=-=--=-=-=-=-=-=-=-##

git push








## ------------------------------------------------------- ##
##   [?] Your key must be available to ssh-agent
## ------------------------------------------------------- ##

## ------------------------------------------------------- ##
##   [?] You can check that your key is visible to ssh-agent 
##       by running the following command:
## ------------------------------------------------------- ##
ssh-add -L



## ------------------------------------------------------------ ##
##   [?] If the command says that no identity is available
##       you'll need to add your key
## ------------------------------------------------------------ ##
ssh-add $key








##-=-=-=-=--=-=-=-=-=--=-=-=-=-=--=-=-=-=-=--=-=-=-##
##  [+] Start the ssh-agent In the background.
##-=-=-=-=--=-=-=-=-=--=-=-=-=-=--=-=-=-=-=--=-=-=-##
eval "$(ssh-agent -s)"



##-=-=-=-=--=-=-=-=-=--=-=-=-=-=--=-=-=-=-=--=-=-##
##  [+] Print out the SSH_AUTH_SOCK variable:
##-=-=-=-=--=-=-=-=-=--=-=-=-=-=--=-=-=-=-=--=-=-##
echo "$SSH_AUTH_SOCK"




ssh-add -l -E sha256


2048 MD5:a0:dd:42:3c:5a:9d:e4:2a:21:52:4e:78:07:6e:c8:4d /Users/USERNAME/.ssh/id_rsa (RSA)




##-=-=-=-=--=-=-=-=-=--=-=-=-=-=--=-=-=-=-=-=-=-=-=-##
##  [+] 
##-=-=-=-=--=-=-=-=-=--=-=-=-=-=--=-=-=-=-=-=-=-=-=-##

##-=-=-=-=--=-=-=-=-=--=-=-=-=-=--=-=-=-=-##"
##  [+] Using SSH over the HTTPS port:
##-=-=-=-=--=-=-=-=-=--=-=-=-=-=--=-=-=-=-##"


##-======================================================-##
##  [?] To test if SSH over the HTTPS port is possible:
##  [?] Run this SSH command:
##-======================================================-##
ssh -T -p 443 git@ssh.github.com



## ------------------------------------------------------- ##
##  -# Hi $username! Youve successfully authenticated, 
##  -# but GitHub does not provide shell access.
## ------------------------------------------------------- ##


##-=========================================================================-##
##  [?] If you are able to SSH into git@ssh.github.com over port 443, "
##       you can override your SSH settings to force any connection "
##       to GitHub to run though that server and port."
##-=========================================================================-##


##-=============================================-##
##  [?] To set this In your ssh config
##      edit the file at ~/.ssh/config
##      and add this section:"
##-=============================================-##


##-=-=-=-=--=-=-=-=-=--=-=-=-=-=--=-=-=-=-=-##

Host github.com
  Hostname ssh.github.com
  Port 443

##-=-=-=-=--=-=-=-=-=--=-=-=-=-=--=-=-=-=-=-##

##-=============================================-##
##  [?] You can test that this works 
##      by connecting once more to GitHub:"
##-=============================================-##


ssh -T git@github.com



## ------------------------------------------------------- ##
##  -# Hi $username! You've successfully authenticated, "
##  -# but GitHub does not provide shell access."
## ------------------------------------------------------- ##




##-====================================-##
##  [+] Retrieve authorized SSH keys
##-====================================-##
curl -L 'https://api_key:your-amazing-password@hostname:admin_port/setup/api/settings/authorized-keys'



##-====================================-##
##  [+] Add a new authorized SSH key:
##-====================================-##
curl -L -X POST 'https://api_key:your-amazing-password@hostname:admin_port/setup/api/settings/authorized-keys' -F authorized_key=@/path/to/key.pub




##-====================================-##
##  [+] Remove an authorized SSH key
curl -L -X DELETE 'https://api_key:your-amazing-password@hostname:admin_port/setup/api/settings/authorized-keys' -F authorized_key=@/path/to/key.pub











##-====================================-##
##  [+] Change your remote's URL 
##      from SSH --> HTTPS 
##      with: git remote set-url
##-====================================-##
git remote set-url origin https://hostname/USERNAME/REPOSITORY.git










accessing the API via cURL, the following command would authenticate you if you replace <username> with your GitHub username. (cURL will prompt you to enter the password.)

curl -u username https://api.github.com/user





Via OAuth Tokens
 you can use personal access tokens or OAuth tokens instead of your password.

curl -u username:token https://api.github.com/user





If you're using the API to access an organization that enforces SAML SSO for authentication, you'll need to create a personal access token (PAT) and whitelist the token for that organization. Visit the URL specified in X-GitHub-SSO to whitelist the token for the organization.

curl -v -H "Authorization: token TOKEN" https://api.github.com/repos/octodocs-test/test

X-GitHub-SSO: required; url=https://github.com/orgs/octodocs-test/sso?authorization_request=AZSCKtL4U8yX1H3sCQIVnVgmjmon5fWxks5YrqhJgah0b2tlbl9pZM4EuMz4
{
  "message": "Resource protected by organization SAML enforcement. You must grant your personal token access to this organization.",
  "documentation_url": "https://help.github.com"
}





Use the api_key parameter to send this token with each request. For example:

curl -L 'https://hostname:admin_port/setup/api?api_key=your-amazing-password'




curl -L -X POST 'https://hostname:admin_port/setup/api/start' -F license=@/path/to/github-enterprise.ghl -F "password=your-amazing-password" -F settings=</path/to/settings.json





curl -L 'https://api_key:your-amazing-password@hostname:admin_port/setup/api/settings'



curl -L -X PUT 'https://api_key:your-amazing-password@hostname:admin_port/setup/api/settings' --data-urlencode "settings=`cat /path/to/settings.json`"









SSHD_CONFIG='/etc/ssh/sshd_config'

##-=================================================================-##
##  [+] Determine which version of ssh is default (should be 2)
##-=================================================================-##
cat /etc/ssh/sshd_config |grep Protocol


##-=====================================================-##
##  [+] Determine the port SSH listens on by default
##-=====================================================-##
cat /etc/ssh/sshd_config |grep Port

##-=====================================================-##
##  [+] check to see if root login is enabled via SSH
##-=====================================================-##
cat /etc/ssh/sshd_config |grep PermitRootLogin


##-================================================================-##
##  [+] set an alias to ssh to force it to always use port 63456:
##-================================================================-##
alias ssh="ssh -p 63456"


ssh-copy-id -i ~/.ssh/id_rsa.pub myserver.mynetwork.com

















