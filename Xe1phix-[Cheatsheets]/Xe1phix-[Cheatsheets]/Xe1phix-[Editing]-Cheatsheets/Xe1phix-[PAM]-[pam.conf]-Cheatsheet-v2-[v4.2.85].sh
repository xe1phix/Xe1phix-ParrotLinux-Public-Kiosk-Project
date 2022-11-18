
------------------------------------------------------------------------------------------
#disable root user access to a system, 
by restricting access to login and sshd services,via PAM

#add the configuration below in both files
auth    required       pam_listfile.so \
        onerr=succeed  item=user  sense=deny  file=/etc/ssh/deniedusers
	
sudo vim /etc/pam.d/login
sudo vim /etc/pam.d/sshd

sudo vim /etc/ssh/deniedusers 			#Add the user root
sudo chmod 600 /etc/ssh/deniedusers

--------------------------------------------------------------------------------------------------------------------
#Create a New Sudo User(CentOS)
adduser username
passwd username
usermod -aG wheel username 				#add the user to the wheel group.By default, on CentOS, members of the wheel group have sudo privileges
su - username 							# switch to the new user account

#verify if user is sudoer
sudo -l -U userjohndoe  				#list user's privileges or check a specific command
sudo --validate / sudo -v 				#update the user's cached credentials, authenticating the user if necessary
sudo --list 							#print the list of allowed and forbidden commands for the user who is executing the sudo command
groups 									#verify if user is sudoer, member of wheel group
sudo whoami 							# returns root
--------------------------------------------------------------------------------------------------------------------
cp /etc/pam.d/system-auth{,.orig} 		# copy file with extension .orig
--------------------------------------------------------------------------------------------------------------------
