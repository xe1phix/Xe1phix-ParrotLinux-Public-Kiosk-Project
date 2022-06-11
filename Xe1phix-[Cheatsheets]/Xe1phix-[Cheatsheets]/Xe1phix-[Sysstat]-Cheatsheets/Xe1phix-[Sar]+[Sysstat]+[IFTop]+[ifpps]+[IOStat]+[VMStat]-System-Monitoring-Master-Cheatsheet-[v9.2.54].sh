#!/bin/sh
##-===============================================-##
##   [+]
##-===============================================-##


## ------------------------------------------------------------------------------------------------------- ##
## [?] vmstat   || Report virtual memory statistics
## [?] iostat   || reports CPU statistics and input/output statistics for block devices and partitions.
## [?] mpstat   || reports individual or combined processor related statistics.
## [?] pidstat  || reports statistics for Linux tasks (processes) : I/O, CPU, memory, etc.
## ------------------------------------------------------------------------------------------------------- ##
##
## ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ##
## [?] sar      || collects, reports and saves system activity information (see below a list of metrics collected by sar).
## [?] sadc     || is the system activity data collector, used as a backend for sar.
## [?] sa1      || collects and stores binary data in the system activity daily data file. It is a front end to sadc designed to be run from cron or systemd.
## [?] sa2      || writes a summarized daily activity report. It is a front end to sar designed to be run from cron or systemd.
## [?] sadf     || displays data collected by sar in multiple formats (CSV, XML, JSON, etc.) and can be used for data exchange with other programs. This command can also be used to draw graphs for the various activities collected by sar using SVG (Scalable Vector Graphics) format.
## ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ##




/etc/default/sysstat
/var/log/sysstat/saXX
/var/log/sa/sa          ## system activity binary datafile

/etc/cron.d/sysstat
/etc/cron.daily/sysstat
/etc/sysstat/sysstat.ioconf
/etc/sysstat/sysstat
/usr/lib/sysstat/sa1


dpkg-reconfigure sysstat
systemctl enable sysstat
systemctl start sysstat



iftop -i eth0


iftop -i eth0 -f 'port (80 or 443)'
iftop -i eth0 -f 'ip dst 192.168.1.5'


iftop -i eth0 -F 192.168.1.0/255.255.255.0




## ---------------------------------------------------------------------------------------------------------- ##
        sar -A                      ## Display all the statistics saved in current daily data file.
## ---------------------------------------------------------------------------------------------------------- ##
		sar -u | less				## shows CPU usage
## ---------------------------------------------------------------------------------------------------------- ##
		sar -d						## output disk statistics.
## ---------------------------------------------------------------------------------------------------------- ##
		sar -b						## I/O and transfer rate statistics
## ---------------------------------------------------------------------------------------------------------- ##
		sar -n DEV 5 2				## Measure network activity on a interfaces
## ---------------------------------------------------------------------------------------------------------- ##
		sar –u –r –n DEV			## details about the usage of CPU, I/O, memory, and network devices
## ---------------------------------------------------------------------------------------------------------- ##
		sar -u 2 5					## Report CPU utilization for each 2 seconds. 5 lines are displayed.
## ---------------------------------------------------------------------------------------------------------- ##
		sar -A						## Display all the statistics saved In current daily data file.
## ---------------------------------------------------------------------------------------------------------- ##
        sadf -p -P 1                ## CPU statistics for processor 1
## ---------------------------------------------------------------------------------------------------------- ##





sar -u
sar -P ALL
sar -q
sar -B
sar -W
sar -r	                    ##  %memused

--iface=

-S XDISK
-S IPV6
-S SNMP
-S ALL
DISK, INT, IPV6, POWER, SNMP, XDISK, ALL and XALL





##-================================================-##
##  [+] Extract memory and network statistics
##      from system activity file sa21
##      display as a database friendly format
##-================================================-##
sadf -d /var/log/sysstat/sa21 -- -r -n DEV



##-================================================-##
##   [+] Display memory and network statistics
##       saving it in a daily data file sa16.
##-================================================-##
sar -r -n DEV -f /var/log/sysstat/sa16




## ---------------------------------------------------------------------------------- ##
##    [+]  Report statistics on IRQ 14
##    [?]  Update interval is 2 seconds
##    [?]  Display only 10 lines at a time.
##    [?]  Data is stored  In  a file called int14.file.
## ---------------------------------------------------------------------------------- ##
sar -I 14 -o int14.file 2 10


##    [+]  Display memory and network statistics
##    [?]  saved In daily data file 'sa16'.

## ---------------------------------------------------------------------------------------------------------------------------- ##
		sar -r -n DEV -f /var/log/sysstat/sa16		##  Display memory and network statistics
																		##  saved In daily data file 'sa16'.
## ---------------------------------------------------------------------------------------------------------------------------- ##


## Write 10 records of one second intervals
## to the /tmp/datafile binary file.
/usr/lib/sysstat/sadc 1 10 /$Dir/$File


## Insert the comment "Backup Start" into the file /tmp/datafile.
/usr/lib/sysstat/sadc -C "Backup Start" /$Dir/$File






cat /etc/cron.d/sysstat

# Run system activity accounting tool every 10 minutes
*/10 * * * * root /usr/lib64/sa/sa1 -S DISK 1 1
# 0 * * * * root /usr/lib64/sa/sa1 -S DISK 600 6 &
# Generate a daily summary of process accounting at 23:53
53 23 * * * root /usr/lib64/sa/sa2 -A




## ---------------------------------------------------------------------------------------------------------------------------- ##
    iostat -x               ## extended disk I/O statistics
## ---------------------------------------------------------------------------------------------------------------------------- ##
	iostat -d 2				## Display a continuous device report at two second intervals.
## ---------------------------------------------------------------------------------------------------------------------------- ##
	iostat -d 2 6			## Display six reports at two second intervals for all devices.
## ---------------------------------------------------------------------------------------------------------------------------- ##
	iostat -x sda sdb 2 6	## Display six reports of extended statistics at two second intervals for devices sda and sdb.
## ---------------------------------------------------------------------------------------------------------------------------- ##
	iostat -p sda 2 6		## Display six reports at two second intervals for device sda and all its partitions (sda1, etc.)
## ---------------------------------------------------------------------------------------------------------------------------- ##
	iostat -dx 1 5			## Print a detailed report for all devices every second, for 5 times
## ---------------------------------------------------------------------------------------------------------------------------- ##



vmstat 1                    ##  "free" (main memory)
                            ##  swap" (virtual memory);
vmstat -P                   ##  per-process: top

vmstat 1 5 						# Print a report every second, for 5 times


prstat -a
prstat -c 1
prstat -mLc 1

iostat -x                       ##  extended disk I/O statistics
iostat -dx 1 5  				# Print a detailed report for all devices every second, for 5 times

mpstat  						# Print a report about processor activities
mpstat 1 5  					# Print a report of global statistics among all processors every second, for 5 times
mpstat -P ALL 1

htop
iotop
powertop


/proc/stat
/proc/*/stat
/proc/diskstats                 ## disks statistics

grep -c '^processor' /proc/cpuinfo





pidstat -d              report I/O statistics for tasks

pidstat 1
pidstat -u -p ALL   ## list all processes in a report



##-================================================-##
##  [+] Trace the I/O on the device /dev/sda
##  [+] Parse the output to human readable form
##-================================================-##
blktrace -d /dev/sda -o - | blkparse -i -
btrace /dev/sda



sar -u 2 5
              Report CPU utilization for each 2 seconds.  5  lines  are  dis‐
              played.


sar -I 14 -o int14.file 2 10
              Report  statistics  on  IRQ 14 for each 2 seconds. 10 lines are
              displayed.  Data are stored in a file called int14.file.

## Display memory and network statistics saved in daily data file sa16.
sar -r -n DEV -f /var/log/sysstat/sa16


sar -A Display all the statistics saved in current daily data file.




## Extract memory and network statistics
## from system activity file sa21
## display as a database friendly format

sadf -d /var/log/sysstat/sa21 -- -r -n DEV

























##-########################################################-##










/var/log/sysstat/saXX
dpkg-reconfigure sysstat

systemctl enable sysstat
systemctl start sysstat
/etc/default/sysstat

change
ENABLED="false"
to
ENABLED="true"

restart the sysstat service:
service sysstat restart



pidstat -u -p ALL   ## list all processes in a report

pidstat -d to be able to report I/O statistics for tasks

iostat -x           ##  extended disk I/O statistics


# Rotate file at midnight
0 0 * * * /usr/lib/sa/sa1 --rotate
# Run system activity accounting tool every 10 minutes
0,10,20,30,40,50 * * * * /usr/lib/sa/sa1 1 1
# Generate a text summary of previous day process accounting at 00:07
7 0 * * * /usr/lib/sa/sa2 -A



collect data (including those from disks) every 10 minutes, place the following entry
       in your root crontab file:

       0,10,20,30,40,50 * * * * /usr/lib/sysstat/sa1 1 1 -S DISK

       To  rotate  current  system activity daily data file, ensuring it is complete, place the
       following entry in your root crontab file:

       0 0 * * * /usr/lib/sysstat/sa1 --rotate





/var/log/sa/sa          ## system activity binary datafile






sar -I 14 -o int14.file 2 10

## Report statistics on IRQ 14 for each 2 seconds.
## 10 lines are displayed.
## Data are stored in a file called int14.file.







sar -A          ## Display all the statistics saved in current daily data file.



## Write 10 records of one second intervals
## to the /tmp/datafile binary file.

/usr/lib/sysstat/sadc 1 10 /$Dir/$File



## Insert the comment "Backup Start"
into the file /tmp/datafile:

/usr/lib/sysstat/sadc -C "Backup Start" /$Dir/$File



