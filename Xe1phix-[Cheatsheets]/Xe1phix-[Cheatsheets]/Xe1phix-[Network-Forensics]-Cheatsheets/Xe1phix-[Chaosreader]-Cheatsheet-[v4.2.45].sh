#!/bin/sh

chaosreader --dir					## Output all files to this directory
chaosreader --verbose			## 
chaosreader -ve $File				## Create HTML 2-way & hex files for everything
chaosreader -p $Ports $File	## only ftp and telnet
chaosreader -s 10					## runs tcpdump for 10 minutes and generates the log file
chaosreader --ipaddr $IP		## Only examine these IPs
chaosreader --filter 'port 7'		## Dump Filter - Port #
chaosreader --port 21,23			## Only examine these ports (TCP & UDP)
chaosreader --preferdns			## Show DNS names instead of IP addresses.
chaosreader --sort type			## Sort Order: type
chaosreader --sort ip				## Sort Order: ip



runs tcpdump/snoop and generates the log file
chaosreader  -s  10  

chaosreader -S 5,12

chaosreader -S 2,5      # Standalone, sniff network 5 times for 2 min



tcpdump -s9000 -w output1        # create tcpdump capture file
chaosreader output1              # extract recognised sessions, or,

chaosreader -ve output1          # gimme everything, or,

chaosreader -p 20,21,23 output1  # only ftp and telnet...

