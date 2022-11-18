#crontab

##  Display scheduled jobs for the specified user
crontab -l -u vagrant
crontab -l

# Display Cron Table
ls -la /etc/cron*

sudo crontab -u user -e 	#
crontab -e 					#when running as a non-root user
sudo crontab -e 			#the root user's crontab


If the /etc/cron.allow file exists, 
then users must be listed in it 
in order to be allowed to run the crontab command

If the /etc/cron.allow file does not exist 
but the /etc/cron.deny file does, 
then users must not be listed 
in the /etc/cron.deny file 
in order to run crontab

If the /etc/cron.allow file exists, 
then users must be listed in it in order 
to be allowed to run the crontab command
/etc/cron.deny

If a blank cron.deny file has been created, 
cron only available to root or users in cron.allow. 


# Delete All Cron Jobs
crontab -r
crontab -r -i 				# the command prompt  to confirm

# All scripts in each directory are run as root
#Cron jobs may not run with the environment, 
in particular the PATH, that you expect. 
Try using full paths to files and programs
#The "%" character is used as newline delimiter in cron commands. 
If you need to pass that character into a script, 
you need to escape it as "\%".

#anacron uses the runparts command and 
/etc/cron.hourly, 
/etc/cron.weekly, and 
/etc/cron.monthly directories.
#anacron itself is invoked from the /etc/crontab file

#user crontabs
/etc/cron.hourly/, /etc/cron.daily/, /etc/cron.weekly/, and /etc/cron.monthly/
ls -la /etc/cron.daily/ #View daily cron jobs

crontab -l > backup_cron.txt #Backup All Cron Jobs

/etc/crontab #not recommended that you add anything,this could cause a problem if the /etc/crontab file is affected by updates
/etc/cron.d #not be affected by updates, several people might look after a server, then the directory /etc/cron.d is probably the best place to install crontabs
/etc/cron.d #These files also have username fields

#the files inside /etc/cron.d
chown root:root /etc/cron.d/*
chmod go-wx /etc/cron.d/*
chmod -x /etc/cron.d/*


cat /etc/cron.allow


sudo systemctl restart cron


cat /etc/cron.d/barak_job
*/1 * * * * barak echo "Nightly Backup Successful: $(date) " > /tmp/test1_job.log
*/1 * * * * /usr/bin/free -m | awk '{ if($1 == "Mem:" ) print $3}' | awk '{ if ( $1 > 140 ) print $0; else print "less" }' >> /tmp/memo.log




#troubleshooting cron

cat /etc/cron.d/barak_job
*/1 * * * * barak echo "Nightly Backup Successful: $(date) " &> /tmp/test1_job.log #redirect stdout and stderr to a file.
*/1 * * * * barak echo "Nightly Backup Successful: $(date) " > /tmp/test1_job.log2 2>&1 #redirect stdout and stderr to a file.



#php specific

php /bla/bla/something.php >> /var/logs/somelog-for-stdout.log


#the only difference from the syntax of the user crontabs is that the line specifies the user to run the job as

00 01 * * * rusty /home/rusty/rusty-list-files.sh #run Rusty's command script as user rusty from his home directory.


/usr/bin/php /home/username/public_html/cron.php #Execute PHP script:

mysqldump -u root -pPASSWORD database > /root/db.sql #MySQL dump:

/usr/bin/wget --spider "http://www.domain.com/cron.php"  #Access URL:

cat /etc/cron.allow
barak
sudo systemctl restart cron/crond
cat /etc/cron.d/barak_job
*/1 * * * * barak echo "Nightly Backup Successful: $(date)" >> /tmp/mybackup.log
crontab -u barak -l
#*/1 * * * * barak echo "Nightly Backup Successful: $(date) runs" >> /tmp/barak_job.log
sudo tail -f /var/log/syslog | grep --color=auto CRON


crontab -e
@hourly echo "Nightly Backup Successful: $(date)" >> /tmp/mybackup.log

#"-u borg" is used take the identity of the borg user
cat /etc/cron.daily/borgbackup_check 

#!/bin/bash
sudo -u borg borg check /borgbackup >> /var/log/borgbackup.log

#once every 5 minutes

cat | sudo tee /etc/cron.d/cron-mrtg << EOF

*/5 * * * * env LANG=C /usr/bin/mrtg /etc/mrtg.cfg
EOF
#verify
cat /etc/cron.d/cron-mrtg
crontab -l 

cat | sudo tee /etc/cron.d/sysinfo << EOF
#once every 5 minutes
*/5 * * * * /bin/bash /home/vagrant/sysinfo_func.sh
EOF
#verify
cat /etc/cron.d/cron-mrtg

* * * * * /bin/date >> /tmp/cron_output #This will append the current date to a log file every minute.
* * * * * /usr/bin/php /var/www/domain.com/backup.php > /dev/null 2>&1 #run a script but keep it running in the background
at specific time
00 15 * * 4 sh /root/test.sh
35 21 * * 7 /bin/date >> /tmp/cron_output
every 5 minutes
*/5 * * * *  mycommand
an hourly cron job but run at minute 15 instead (i.e. 00:15, 01:15, 02:15 etc.):
15 * * * * [command]
once a day, at 2:30am:
30 2 * * * [command]
once a month, on the second day of the month at midnight (i.e. January 2nd 12:00am, February 2nd 12:00am etc.):
0 0 2 * * [command]
on Mondays, every hour (i.e. 24 times in one day, but only on Mondays):
0 * * * 1 [command]
three times every hour, at minutes 0, 10 and 20:
0,10,20 * * * * [command]
# Stop download Mon-Fri, 6am
0 6 * * 1,2,3,4,5 root          virsh shutdown download
*/5 * * * * /path/to/some-script.sh #every 5 minutes
@reboot /scripts/script.sh #tasks to execute on system reboot
@hourly /scripts/script.sh #execute on an hourly.
0 * * * */scripts/script.sh #execute on an hourly.
@daily /scripts/script.sh # execute on a daily basis.
0 2 * * * /scripts/script.sh # executes the task in the second minute of every day.#
@weekly /bin/script.sh #execute on a weekly basis
0 0 4 * sun /bin/script.sh #execute on a weekly basis
@monthly /scripts/script.sh #execute on a monthly basis
0 0 1 * * /scripts/script.sh #execution of a task in the first minute of the month
@yearly /scripts/script.sh #schedule tasks on a yearly basis.
@yearly /scripts/script.sh #executes the task in the fifth minute of every year.
* * * * *  sleep 15; /scripts/script.sh #schedule a cron to execute after every 15 Seconds
0 4,17 * * mon,tue /scripts/script.sh #execute twice on Monday and Tuesday
0 17 * * mon,wed  /script/script.sh #run each Monday and Wednesday at 5 PM
0 7,17 * * * /scripts/script.sh #execute at 7 AM and 5 PM daily
0 5 * * mon  /scripts/script.sh #execute the task on every Monday at 5 AM
0 */6 * * * /scripts/script.sh #run a script for 6 hours interval
0 8-10 * * * /scripts/script.sh # run every hour between 08-10AM
0 2 * * sat  [ $(date +%d) -le 06 ] && /script/script.sh #execute on first Saturday of every month
0   12  1-7 *   *   [ "$(date '+\%a')" = "Mon" ] && echo "It's Monday" #on the first Monday of every month
* * * feb,jun,sep *  /script/script.sh #run tasks in Feb, June and September months



--------------------------------------------------------------------------------------------------------------------
#crontab

systemctl status crond
systemctl restart crond

journalctl -u crond 						#systemd cron job log 
journalctl -t CROND
journalctl -t CROND -f 						# watch live
journalctl -t CROND | tail -20

tail -v /var/log/cron 						#Print filename header
tail -f /var/log/cron | grep CRON
grep CRON /var/log/cron 					#troubleshoot cron 

#Check that crond is running
ps -ef | grep crond | grep -v grep 
ps -o pid,sess,cmd afx | egrep crond

sudo tail -f /var/log/cron.log

cat /etc/anacrontab 						#find out cron timings for /etc/cron.{daily,weekly,monthly}/

--------------------------------------------------------------------------------------------------------------------
