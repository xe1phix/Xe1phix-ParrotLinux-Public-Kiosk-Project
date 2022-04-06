#!/bin/sh
##-==========================================================================================-##
##   [+] Xe1phix-[Hardware]-Performance-[Monitoring-Events-(PMUs)]-Cheatsheet-[v9.5.62].sh
##-==========================================================================================-##
##
##
##-========================================-##
##  LPE == Linux Performance Events
##-========================================-##
##  load average
/proc/loadavg
##  wasnt included for CPU metrics
##  since Linux load averages include tasks in the
##  uninterruptable state (usually I/O).
##-===========================================================================-##
##  measure of memory capacity saturation -
##  the degree to which a process is driving the system beyond its ability
##  (and causing paging/swapping).
##-===========================================================================-##
##  CPC == CPU Performance Counters
##  Performance Instrumentation Counters (PICs)
##-===========================================================================-##
##  Performance Monitoring Events (PMUs)
##  (Hardware Events)
##-===========================================================================-##
##  tracing functions from different layers of the I/O subsystem:
##  block device
##  SCSI
##  SATA
##  IDE
##  Some static probes are available
##  (LPE "scsi" and "block" tracepoint events)
##-===========================================================================-##
##  CPI == Cycles Per Instruction
##  (others use IPC == Instructions Per Cycle).
##-===========================================================================-##
##  I/O interconnect:
##  this includes the CPU to I/O controller busses,
##  the I/O controller(s), and device busses (eg, PCIe).
##-===========================================================================-##
##  Dynamic Tracing: Allows custom metrics to be developed,
##-===========================================================================-##
##  Trusted Execution Environments" (TEEs).
##-===========================================================================-##


mpostat 1
mpstat -P ALL 1

prstat -c 1
prstat -mLc 1
pidstat 1

sar -u
sar -P ALL
sar -q
sar -B
sar -W
sar -r	                    ##  %memused


ps -o pcpu
pidstat 1

dstat -c

slabtop -s
slabtop -c              ##  kmem slab usage


dstat -m                ##  free
free -m             	##  Mem (main memory)
uptime              	##  load averages
iostat 1

top
htop               ##  "RES" (resident main memory)
                    ##  "VIRT" (virtual memory)
top -o cpu
top -S

lockstat -Ii rate

vmstat 1                    ##  "free" (main memory)
                            ##  swap" (virtual memory);
vmstat -P                   ##  per-process: top

pmcstat                     ##  error counters are supported (eg, thermal throttling)
cpustat

grep -c '^processor' /proc/cpuinfo

dstat -p        	        ##  CPU count
dstat -c                     ##  sum



netstat -i              	##  RX-ERR"/"TX-ERR";
ip -s link                  ##  errors";
sar -n EDEV             	##  rxerr/s" "txerr/s";
/proc/net/dev           	##  errs"	##  drop"; extra counters may be under
/sys/class/net/...
/proc/PID/stat
htop as MINFLT


etstat -s               ##  segments retransmited";
sar -n EDEV             ##  drop and *fifo metrics;
/proc/net/dev           ##  RX/TX "drop";
nicstat                 ##  "Sat" dynamic tracing for other TCP/IP stack queueing


sar -n DEV 1	        ##  rxKB/s"/max "txKB/s"/max;
ip -s link              ##  , RX/TX tput / max bandwidth;
/proc/net/dev	        ##  bytes" RX/TX tput/max;
nicstat

iostat -xz 1            ## sum devices and compare to known IOPS/tput limits per-card


iostat -xz 1	        ##  %util";
sar -d	                ##  %util"; per-process:
iotop;
pidstat -d;
/proc/PID/sched

iostat -xnz 1	        ##  avgqu-sz" > 1, or high "await";
sar -d same             ##  LPE block probes for queue length/latency; dynamic/static tracing of I/O subsystem



cp /proc/cpuinfo                       02-cpu
cpupower -c all info                 > 02-cpu-freq
cpupower -c all idle-info           >> 02-cpu-freq
cpupower -c all frequency-info      >> 02-cpu-freq
vpddecode



lspci -vvvxxxDnn -A linux-sysfs      > 05-pci
lsusb -v                             > 05-usb
lsscsi -dgpLv                        > 06-scsi-dev
lsscsi -HLv                          > 06-scsi-host
lsscsi -HLtv                         > 06-scsi-top
lspcmcia                             > 07-pcmcia





/sys/devices/
smartctl                ##  dynamic/static tracing of I/O subsystem response codes

swapon -s
free
/proc/meminfo               ##  "SwapFree"/"SwapTotal"; file systems:
df -h


sysctl kernel.threads-max
/proc/sys/kernel/threads-max




 sar -v	                    ##
 file-nr
 vs
 /proc/sys/fs/file-max
 dstat --fs             	## files
 /proc/sys/fs/file-nr       ## per-process:

 ls /proc/PID/fd | wc -l
   vs
 ulimit -n


/proc/PID/stat              ## for minor-fault rate

/proc/PID/schedstat         ## dynamic tracing [5]; OOM killer:

dmesg | grep killed

perf sched latency          ## (shows "Average" and "Maximum" delay per-schedule)


perf                        ##  (LPE) if processor specific error events (CPC) are available


perf probe               ##  dynamically trace the scheduler functions


perf stat -e

perf record -a -g -F 997



strace errno == EMFILE          ##  on syscalls returning fds (eg, open(), accept()



##-================================================-##
##  [+] Trace the I/O on the device /dev/sda
##  [+] Parse the output to human readable form
##-================================================-##
blktrace -d /dev/sda -o - | blkparse -i -
btrace /dev/sda




valgrind --tool=drd             ##  various errors; dynamic tracing of pthread_mutex_lock() for
                                ##  EAGAIN, EINVAL, EPERM, EDEADLK, ENOMEM, EOWNERDEAD

valgrind --tool=drd             ##  to infer contention from held time;
                                ##  dynamic tracing of synchronization functions for wait time



valgrind --tool=drd --exclusive-threshold=      ## (held time); dynamic tracing of lock to unlock function time






dmesg                   ##  for physical failures; dynamic tracing




zfs get all
zfs get all $Dir/$Dir
zfs get mounted,readonly,mountpoint,type
zfs get used,available,mountpoint
zfs get -H -o value compression
zfs get -r -s local -o name,property,value all $Dir
zfs get -o name,avail,used,usedsnap,usedds,usedrefreserv,usedchild -t filesystem,volume


zfs list -o mounted,name,used,avail,copies,rdonly,mountpoint,type
zfs list -o name,used,avail,aclmode,aclinherit,zoned,xattr,copies,checksum,compress,rdonly

zpool get all $Dir
zpool get health $Dir
zpool status -v $Dir


df | awk 'NR==1||/zfs/'
df | awk 'NR==1||/(zfs|$Dir)/'
lsmod | awk 'NR==1||/zfs/'


zfs -o name,avail,used,usedsnap,usedds,usedrefreserv,usedchild -t filesystem,volume
zfs -t filesystem
zfs -t snapshot
zfs -t volume
zfs -t all

zfs get -o name,property,value,received,source
zfs get -s local,default,inherited,temporary,received



zfs create -p ZPool-ZFS
zfs set mountpoint=/mnt/$Dir $Dir
zfs set mountpoint=/mnt/ZPool-ZFS ZPool-ZFS

zpool import
zfs mount $Dir
mount | grep $Dir
zpool import -d /mnt/$Dir
zpool import -d /mnt/$Dir $Dir


zfs mount | grep $Dir
zfs mount $Dir
mount -F zfs $Dir/$Dir

zfs create ZPool-ZFS/Xe1phixGitLab

chmod -v -R ugo+rwx /mnt/ZPool-ZFS/
chown -v -R xe1phix /mnt/ZPool-ZFS/
chgrp -hR xe1phix /mnt/ZPool-ZFS/

zpool set listsnapshots=on ZPool-ZFS
zfs snapshot -r ZPool-ZFS/Xe1phixGitLab@today
zfs clone ZPool-ZFS/Xe1phixGitLab@today ZPool-ZFS/Xe1phixGitLabBackup

## reverts the contents of ZPool-ZFS/Audio
##   to the snapshot named yesterday
zfs rollback -r ZPool-ZFS/Xe1phixGitLab@yesterday
zfs snapshot -r ZPool-ZFS/Xe1phixGitLab@yesterday

zfs set checksum=sha256 ZPool-ZFS/Scripts
zfs set exec=off ZPool-ZFS/Scripts
zfs set readonly=on ZPool-ZFS/Scripts

zfs get compressratio
zfs set compression=on ZPool-ZFS/Wordlists
zfs set compression=zls ZPool-ZFS/Scripts

zfs set zoned=on ZPool-ZFS/Scripts
zfs set acltype=posixacl ZPool-ZFS/Scripts
zfs set setuid=off ZPool-ZFS/Scripts
zfs set sync=disabled ZPool-ZFS/$Dir
zfs set vscan=on ZPool-ZFS/Scripts
zfs set copies=2 ZPool-ZFS/Xe1phixGitLab



zfs mount -o ro $Dir
zfs mount -o remount,rw $Dir

zfs unmount $Dir/$dir/$dir/
zfs unmount -f $Dir/$dir/$dir/
umount /mnt/$Dir


echo "##-=========================================================-##"
echo "      [+] Initiate A manual scan to check for corruption:      "
echo "##-=========================================================-##"
zpool scrub $Dir




echo "##-==============================-##"
echo "    [+] Nested Datasets             "
echo "##-==============================-##"

echo "##-==========================================-##"
echo "    [?] Datasets dont need to be isolated.      "
echo "##-==========================================-##"

echo "##-===========================================================-##"
echo "    [?] You can create nested datasets within each other.         "
echo "##-===========================================================-##"

echo "##-=================================================-##"
echo "##        This allows you to create namespaces,        "
echo "##      while tuning a nested directory structure,     "
echo "##              without affecting the other.           "
echo "##-=================================================-##"

echo "##-=================================================-##"
echo "    [?] If you want to compress zfs/log:              "
echo "    [?] but not on the parent zfs/ directory:         "
echo "##-=================================================-##"

## ----------------------------------------------- ##
##    [?] Consists of a ZIL header
##    [?] Which points to a list of:
##        Records, ZIL blocks and a ZIL trailer
## ----------------------------------------------- ##

zfs create zfs/log
zfs set compression=on zfs/log          ## Enables or disables compression for a dataset.
zfs get compressratio zfs/log
zfs inherit -r compression zfs/log
zfs set exec=off zfs/log
zpool add zfs log /dev/sd -f



zfs create -V 1G tank/swap
mkswap /dev/zvol/tank/swap
swapon /dev/zvol/tank/swap


zfs set quota=20G ZPool-ZFS/$DataSet/$Dir



echo "##-=====================================================================-##"
echo "    [?] The zfs daemon can import and mount zfs pools automatically.       "
echo "    [?] The daemon mounts the zfs pools reading the file:                  "
echo "##-=====================================================================-##"
/etc/zfs/zpool.cache

echo "##-====================================================-##"
echo "    [+] For each pool you want automatically              "
echo "        mounted by the zfs daemon execute:                "
echo "##-====================================================-##"
zpool set cachefile=/etc/zfs/zpool.cache ZPool-ZFS




##-====================================================-##
##    [+]  Secondary Cache (L2ARC)
##-====================================================-##
##    [?] L2ARC is a Caching Layer between:
## ------------------------------------------------- ##
##       -> The RAM (very fast)
## ------------------------------------------------- ##
##                 And
## ------------------------------------------------- ##
##       -> The Hard Disks (not so fast).
## ------------------------------------------------- ##
secondarycache

-o primarycache=metadata



