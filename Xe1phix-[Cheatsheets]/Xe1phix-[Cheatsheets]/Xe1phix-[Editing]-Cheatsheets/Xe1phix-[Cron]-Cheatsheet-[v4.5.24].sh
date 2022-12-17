#!/bin/sh


/etc/cron.allow
/etc/cron.deny
/var/spool/cron/crontabs/*		# user crontabs


    field          allowed values
 _______________________________________________________          --------------
 || minute         0-59
 || hour           0-23
 || day of month   1-31
 || month          1-12
 || day of week    0-7
 || Sun			   0|7



____________________________________________________________________
 || m | h |dom|mon|dow| user | command |
 ||___|___|___|___|___|______|_________|_____________________
 || 0 | 0 | 1 | 1 | * |						@reboot   Run once, at startup
 || 0 | 0 | 1 | 1 | * |____ 				@yearly   Run once a year
 ||     									@annually
					   ____ 				@yearly
 || 0 | 0 | 1 | * | * |						@monthly  Run once a month
 || 0 | 0 | * | * | 0 |						@weekly   Run once a week
 || 0 | 0 | * | * | * |						@daily 	  Run once a day
 || 0 | 12|	* | * | * |					@daily 	  Same as @midnight
 || 0 | * | * | * | * |    					@hourly	  Run once an hour


crontab -e 				# Edit your user crontab file
crontab -e -u jdoe 		# Edit the crontab file of another user (command available only to the superuser)



user accounts can NOT submit jobs via at or batch?
/ETC/AT.DENY



at 5:00pm tomorrow myscript.sh 					####
at -f mylistofcommands.txt 5:00pm tomorrow		# Execute a command once at the specified time (absolute or relative)
echo "rm file" | at now+2 minutes 				####


at -l		######
atq 		## List the scheduled jobs


at -d 3		## Remove job number 3 from the list
atrm 3 		#####



ldd /usr/bin/crontab | grep pam

Whenever an external command is executed, a child process is created. This action is termed forking.

