  #/etc/systemd/journald.conf
   #SystemMaxUse=100M 
   cat /etc/systemd/journald.conf | grep SystemMaxUse
   journalctl --vacuum-size=100M
   
   sudo usermod -a -G systemd-journal $USER # add the current user to the systemd-journal group
   
   # process the data further with text processing tools like grep, awk, or sed, or redirect the output to a file
   journalctl --no-pager #print its output directly to the standard output instead of using a pager by including the --no-pager flag
   
   journalctl -o json -n 10 --no-pager #change the format to format like JSON
   journalctl -o json-pretty -n 10 --no-pager
   
   sudo mkdir -p /var/log/journal
   ls -l /var/log/journal/3a0d751560f045428773cbf4c1769a5c/
   sudo cp /etc/systemd/journald.conf{,.orig}
   sed -i 's/#Storage.*/Storage=persistent/' /etc/systemd/journald.conf # set "Storage" type to "persistent
   sudo vi /etc/systemd/journald.conf
   Storage=persistent
   systemctl restart systemd-journald.service
   journalctl --flush # move the journal log files from /run/log/journal to /var/log/journal
   #The options prefixed with "Runtime" apply to the journal files when stored on a volatile in-memory file system, 
   #more specifically /run/log/journal
   
   
   journalctl --vacuum-files=2 # have 10 archived journal files and want to reduce these down to 2
   journalctl --verify
   
   journalctl | head -1 #What time range do I have logs for?
   journalctl -F _SYSTEMD_UNIT #What systemd services do I have logs for?  
   journalctl -F _COMM 
   journalctl -F _EXE 
   journalctl -F _CMDLINE
   #What users do the services that logged something run as (swap _UID/-u with _GID/-g for groups)?
   journalctl -F _UID | xargs -n1 id -nu 
   journalctl -F _UID | xargs -n1 id -ng
   
   #provide test input for journalctl
   logger -p err 'something erronous happened'
   systemd-cat -p info echo 'something informational happened'
   
   #What selector fields are there? Show up to 8 values each
   for f in $(sudo journalctl --fields); do 
   echo ===========$f; 
   sudo journalctl -F $f; 
   done | grep -A8 ========
  
   
   #remove all entries
   journalctl --rotate
   journalctl --vacuum-time=1s
   journalctl -m --vacuum-time=1s #-m flag, it merges all journals and then clean them up
   #remove all entries
   find /var/log/journal -name "*.journal" | xargs sudo rm
   systemctl restart systemd-journald
   #remove all entries
   rm -rf /run/log/journal/*

   journalctl --rotate --vacuum-size=500M #rotate journal files and remove archived journal files until the disk space they use is under 500M
   
   
   #Rotating is a way of marking the current active log files as an archive and create a fresh logfile from this moment
   # The flush switch asks the journal daemon to flush any log data stored 
   #in /run/log/journal/ into /var/log/journal/, if persistent storage is enabled.
   #Manual delete,removes all archived journal log files until the last second,clears everything
   journalctl --flush --rotate #applies to only archived log files only, not on active journal files
   journalctl --vacuum-time=1s
   #Manual delete,clears all archived journal log files and retains the last 400MB files
   journalctl --flush --rotate
   journalctl --vacuum-size=400M
   #Manual delete,only the last 2 journal files are kept and everything else is removed
   journalctl --flush --rotate
   journalctl --vacuum-files=2
   
   journalctl -b ->all of the journal entries that have been collected since the most recent reboot
   journalctl --list-boots #list of boot numbers, their IDs, and the timestamps of the first and last message pertaining to the boot
   journalctl --boot=ID _SYSTEMD_UNIT=foo
   journalctl -b -1 -> see the journal from the previous boot,use boot number to pick specific boot	
   journalctl -k -b -1  -> Shows kernel logs for the current boot.
   
   $ journalctl --list-boots #list boot id
   -1 340f8a96d40749f8b2530cc76810d62d Tue 2022-01-18 14:33:46 +03—Tue 2022-01-18 15:14:42 +03
    0 75c35ddeb4274787ad78d1092bf9743a Tue 2022-01-18 23:08:10 +03—Wed 2022-01-19 09:25:35 +03
   $ journalctl -b 75c35ddeb4274787ad78d1092bf9743a #use boot id
   
   journalctl --since "2015-01-10 17:15:00"
   journalctl -S "2020-91-12 07:00:00"
   journalctl -S -1d #The “d” stands for “day”, and the “-1” means one day in the past
   journalctl -S -1h
   journalctl --since "2015-06-26 23:15:00" --until "2015-06-26 23:20:00"
   journalctl -S "2020-91-12 07:00:00" -U "2020-91-12 07:15:00"
   journalctl --since yesterday
   journalctl -S yesterday
   journalctl --since yesterday --until now
   journalctl --since today
   journalctl -S -2d -U today #everything from two days ago up until the start of today
   journalctl --since 09:00 --until "1 hour ago"
   journalctl --since '1h ago' --until '10 min ago'
   
   #syslog log levels i.e. "emerg" (0), "alert" (1), "crit" (2), "err" (3), "warning" (4), "notice" (5), "info" (6), "debug" (7)
   journalctl -p 0
   journalctl -p 0..2 # logs for a range between emerg(0) and critical(2)
   journalctl -f -p warning    # show me warnings
   journalctl -p err           # show all errors 
   
   journalctl -xp info
   journalctl -xu sshd
   journalctl -fxu httpd.service
   journalctl -fxu sshd.service -p debug
   journalctl -fx
   journalctl -xn
   
   journalctl /dev/sda ->  displays logs related to the /dev/sda file system.
   journalctl /sbin/sshd #logs from the sshd binary
   journalctl -n20 _EXE=/usr/sbin/sshd
   journalctl /usr/bin/bash
   
   journalctl -u nginx.service -> see all of the logs from an Nginx unit on our system
   journalctl -u nginx.service --since today
   journalctl -b -u docker -o json
   journalctl -u docker.service --since "2016-10-13 22:00"
   journalctl _SYSTEMD_UNIT=sshd.service
   journalctl -u sshd.service
   journalctl -u sshd.service -x #logs with more details
   journalctl _PID=8088
   journalctl -b _SYSTEMD_UNIT=foo _PID=number #logs for systemd-units that match foo and the PID number
   #all messages from the foo service process with the PID plus all messages from the foo1 service
   journalctl -b _SYSTEMD_UNIT=foo _PID=number + _SYSTEMD_UNIT=foo1 
   journalctl -b _SYSTEMD_UNIT=foo _SYSTEMD_UNIT=foo1 #shows logs matching a systemd-unit foo or a systemd-unit foo1
   
   #Filter logs based on user
   id -u www-data 
   33   
   journalctl _UID=33 --since today   
   
   journalctl -k ->Kernel messages, those usually found in dmesg output
   journalctl _TRANSPORT=kernel
   
   journalctl -n 20 ->see with a number after the -n
   journalctl -n 10 -o short-full #Changing the Display Format
   journalctl -n 10 -o verbose
   journalctl -n 10 -o json
   journalctl -n 10 -o json-pretty
   journalctl -n 10 -o cat #see the log entry messages, without time stamps or other metadata
   
   journalctl --disk-usage #using persistent storage then the below output shows the amount of disk used
   #removes archived journal files until the disk space they use falls below the specified size 
   #(specified with the usual "K", "M", "G", "T" suffixes),
   journalctl --vacuum-size=1G
   journalctl --vacuum-time=1weeks #clear all messages older than one week
   journalctl --vacuum-time=2d #Retain only the past two days
   
   journalctl -f -> continuously prints log messages, similar to tail -f  
   journalctl -u mysql.service -f
   journalctl -f -e -p err docker --since today # -e implies -n1000
   
   #who ran sudo in the past week, what commandline, what PWD and user?
   journalctl  --since '1 week ago' _COMM=sudo -o json \
     | jq -r '(.__REALTIME_TIMESTAMP|tonumber|(./1e6)|todate) + "\t" + ._CMDLINE + "\t" + .MESSAGE' \
     | column -ts $'\t'
   #How many ssh auth errors today?   
   journalctl -o cat -p err -u ssh --since today | wc -l
   #filter specific error
   journalctl -o cat -p err | grep "tx hang"
   #executables have been logging errors at a loglevel lower than error in the past month?
   journalctl --since -1month -p 7..4 -o json | jq -r 'select (.MESSAGE | contains("error")) | ._EXE'  | sort -u
   #show error logs for a particular version of a service
   journactl -p err /opt/fooservice/9e76/bin/fooservice
   #Filter by start and end dates and particular PIDs
   journalctl _SYSTEMD_UNIT=docker --since '2018–11–01 14:00' --until '2018–11–13 14:00' _PID=123 _PID=456
   ------------------------------------------------------------------------------------------------
   Job for autofs.service failed because a configured resource limit was exceeded. See "systemctl status autofs.service" and "journalctl -xe" for details.
   systemctl start autofs 
   systemctl is-active autofs
   systemctl is-active autofs >/dev/null 2>&1 && echo YES || echo NO
   
   ps -aux | grep -i autofs | grep -v grep #grep command was shown in the output, remove this distraction is to add another pipe to grep -v grep
   
   kill -9 `ps -ef | grep '[k]eyword' | awk '{print $2}'` # get the pid from ps command
   ps -aux | grep dockerd | grep -v grep | awk '{print $2}'  # get the pid from ps command

