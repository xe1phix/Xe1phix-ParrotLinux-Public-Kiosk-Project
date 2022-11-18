# detect driver hardware problems
dmesg | more
The output of dmesg is maintained in the log file
/var/log/dmesg
cat /var/log/dmesg | less
data from /dev/kmsg
use syslog
# dmesg -S
# limit the output to only error and warnings
dmesg --level=err,warn
# dmesg produce timestamps 
dmesg --level=err -T
dmesg -T | grep -i eth0
dmesg --level=err,warn -T | grep -i eth0
# limit dmesg's output only to userspace messages
dmesg -u
# timestmaps along with decode facility and levels in dmesg command output
dmesg -Tx
Supported log levels (priorities):
   emerg - system is unusable
   alert - action must be taken immediately
    crit - critical conditions
     err - error conditions
    warn - warning conditions
  notice - normal but significant condition
    info - informational
   debug - debug-level messages
dmesg -TL -f kern
dmesg -TL -f daemon
Supported log facilities:
    kern - kernel messages
    user - random user-level messages
    mail - mail system
  daemon - system daemons
    auth - security/authorization messages
  syslog - messages generated internally by syslogd
     lpr - line printer subsystem
    news - network news subsystem
# verify vt-d is ON
"dmesg | grep Virtualization"
# dmesg | grep -i memory
# dmesg | grep -i dma
# dmesg | grep -i usb
# dmesg | grep -E "memory|dma|usb|tty" 
# dmesg | grep -E "sda|dma"
Clear dmesg logs
# dmesg -C
# dmesg -c
Display colored messages
# dmesg -L
Monitor real time dmesg logs
# dmesg --follow
# dmesg -Tx --follow
# watch "dmesg | tail 7-20"
Display raw message buffer
# dmesg -r
#virtual machine check
$ dmesg |grep -i hypervisor
