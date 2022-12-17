#!/bin/sh

daemonlogger -i eth0 -l /var/log/daemonlogger/$File



daemonlogger -r              Activate ringbuffer mode

daemonlogger -s <bytes>      Rollover the log file every <bytes>
daemonlogger -S <snaplen>    Capture <snaplen> bytes per packet
daemonlogger -t <time>       Rollover the log file on time intervals

daemonlogger -R $File.pcap  Read packets from <pcap file>
daemonlogger -u <user name>  Set user ID to <user name>

