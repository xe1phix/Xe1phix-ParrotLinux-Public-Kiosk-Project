#Configuring the LogRotate daemon


cat /etc/logrotate.conf
/etc/logrotate.d 							#configuration for specific logs 
head -n 15 /etc/logrotate.d/syslog 			#the syslog daemon has its own log rotation configuration file

#add custom lograte /etc/logrotate.conf

#wtmp keeps track of system logins
/var/log/wtmp {
    missingok
    monthly
    create 0664 root utmp
    rotate 1
}

#btmp keeps track of bad login attempts
/var/log/btmp {
    missingok
    monthly
    create 0660 root utmp
    rotate 1
} 
sudo logrotate -fv /etc/logrotate.conf 

#force logrotate to rotate a log file immediately
