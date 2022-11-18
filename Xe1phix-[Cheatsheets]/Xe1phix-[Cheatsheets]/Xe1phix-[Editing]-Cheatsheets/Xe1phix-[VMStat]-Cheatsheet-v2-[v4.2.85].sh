# /etc/default/sysstat ENABLED="true"
#sudo service sysstat restar
vmstat 1 99999 ->the system statistics every second, for the number of times specifed (99999 in this instance)
vmstat –a 1 99 ->show memory usage information
vmstat -a -S M 1 9 -> reformat in Mega Bytes
vmstat 1 99999 ->gather information for disks and other block devices
vmstat -d -w
iostat 1 9 ->CPU information and disk information for all devices
iostat -d -p sda 1 9-> show information for device sda with disk statistics
sar -u 1 30 -> display CPU statistics every second for 30 seconds 
sar -r 1 30  -> display memoru statistics every second for 30 seconds 
sar -b 1 30  -> display block device statistics every second for 30 seconds 

