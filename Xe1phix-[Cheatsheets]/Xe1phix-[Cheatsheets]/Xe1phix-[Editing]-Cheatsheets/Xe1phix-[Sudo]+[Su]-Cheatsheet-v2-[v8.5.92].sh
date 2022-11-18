#Create a New Sudo User(CentOS)
adduser username
passwd username
usermod -aG wheel username #add user to the wheel group.By default, on CentOS, members of the wheel group have sudo privileges
su - username # switch to the new user account

#verify if user is sudoer
sudo -l -U userjohndoe  #list user's privileges or check a specific command
sudo --validate / sudo -v #update the user's cached credentials, authenticating the user if necessary
sudo --list #print the list of allowed and forbidden commands for the user who is executing the sudo command
groups #verify if user is sudoer, member of wheel group
sudo whoami # returns root

----------------------------------------------------------------------------------------------------
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
echo $HOME $USER
sudo bash -c 'echo $HOME $USER'
sudo -H bash -c 'echo $HOME $USER'

#-H flag makes sudo assume root's home directory as HOME instead of the current user's home directory
sudo -H 
#sudo user
echo "stack ALL=(ALL) NOPASSWD: ALL" |sudo tee -a /etc/sudoers

#allow a user aaron to run all commands using sudo without a password, open the sudoers file
$ sudo visudo
aaron ALL=(ALL) NOPASSWD: ALL 

%sys ALL=(ALL) NOPASSWD: ALL #all member of the sys group will run all commands using sudo without a password
alf ALL=(ALL) NOPASSWD: ALL #permit a user to run a given command (/bin/kill) using sudo without a password
%sys ALL=(ALL) NOPASSWD: /bin/kill, /bin/rm #the sys group to run the commands: /bin/kill, /bin/rm using sudo without a password

#su vs sudo
#"sudo" asks for your password,"su" asks for the password for the user whom you are switching to
#sudo lets you issue commands as another user without changing your identity,entry in /etc/sudoers to execute these restricted permissions
#without entering the root password
#su keeps the environment of the old/original user even after the switch to root 
#creates a new environment (as dictated by the ~/.bashrc of the root user), 
#similar to the case when you explicitly log in as root user from the log-in screen.
"su -"  
"su -l" #pass more arguments

"su -c" #su [target-user] -c [command-to-run]  a command that you want to run after switching to the target user.
su -c '/home/annie/annie-script.sh' annie #While logged in as user dave, run the annie-script.sh as user annie
su -c 'echo I am $(whoami)' #Without specifying a target user,switch into root

#The password prompt is not preferable, during scripting
#disable the password prompt when user dave is executing scripts as user annie.dave uses su without having to input annie‘s password.
#/etc/pam.d/su,add the following lines right after the line "auth sufficient pam_rootok.so" 
auth  [success=ignore default=1] pam_succeed_if.so user = annie #rule checks if the target user is annie
auth  sufficient                 pam_succeed_if.so use_uid user = dave #rule to check if the current user is dave
su -c /home/annie/annie-script.sh annie #run by dave

auth       sufficient pam_rootok.so
auth       [success=ignore default=1] pam_succeed_if.so user = otheruser
auth       sufficient   pam_succeed_if.so use_uid user ingroup somegroup

#/etc/sudoers
echo 'dave ALL=(annie) /home/annie/annie-script.sh' | EDITOR='tee -a' visudo #The rule grants dave the permission to execute the script annie-script.sh as user annie on any hosts
sudo -u annie /home/annie/annie-script.sh #while logged in as dave
sudo -u root /home/annie/annie-script.sh #Sorry, user dave is not allowed to execute '/home/annie/annie-script.sh' as root
"sudo -s" or "sudo -i" #mimic "su" or "su -l"
"sudo -s or sudo -i" #temporarily become a user with root privileges

#/etc/sudoers
echo 'dave ALL=(ALL) /home/annie/annie-script.sh' | EDITOR='tee -a' #The rule grants dave to execute the script annie-script.sh as any users
sudo -u root /home/annie/annie-script.sh #while logged in as dave

#The password prompt is not preferable, during scripting
#/etc/sudoers
dave ALL=(ALL) NOPASSWD: /home/annie/annie-script.sh' | EDITOR='tee -a'

# switching to root using sudo -i (or sudo su) cancels auditing/logging
# when a sudo command is executed, the original username and the command are logged
"sudo su"
"sudo -i"
su is equivalent to sudo -i
gives you the root environment, i.e. your ~/.bashrc is ignored.
simulates a login into the root account
Your working directory will be /root
will read root's .profile


"sudo -s" 
gives you the user's environment, so your ~/.bashrc is respected.
launches a shell as root
doesn't change your working directory

"sudo bash" #runs bash as a super user
sudo -E #The -E (preserve environment) option indicates to the security policy that the user wishes to preserve their existing environment variables. 
==========================================================================================================
