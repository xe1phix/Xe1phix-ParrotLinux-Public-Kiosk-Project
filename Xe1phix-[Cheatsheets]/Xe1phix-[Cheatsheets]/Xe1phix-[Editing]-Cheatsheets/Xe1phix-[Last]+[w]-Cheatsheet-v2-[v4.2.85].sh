#lastb #shows users that failed to login,review the /var/log/btmp file (containing failed login attempts)

#the login history of users
last logins
last -R #review the contents of the /var/log/wtmp binary file
last | grep sysadmin
last -f /var/log/btmp #Use the last command to view the btmp file
last mark #pass the user name 
last pts/0 #pass the tty
last mark root pts/0 #specify multiple usernames and ttys
last -p 2020-01-15 #find out who logged into the system on a specific date
last -s 2020-02-13 -u 2020-02-18 #the -s (--since) and -t (--until) option to tell last to display the lines since or until the specified time
last -F #y default, last doesn’t show the seconds and the year. Use the -F, --fulltimes option
last -25 #last 25 logins
last -i #IP address
last -d #DNS address
#the system last rebooted
last reboot
