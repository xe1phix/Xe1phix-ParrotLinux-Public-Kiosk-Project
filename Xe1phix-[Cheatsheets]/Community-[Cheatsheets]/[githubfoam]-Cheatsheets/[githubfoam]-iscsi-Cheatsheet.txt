--------------------------------------------------------------------------
iscsi troubleshooting
--------------------------------------------------------------------------
View discovered targets
  # iscsiadm -m node
  12.212.84.7:3260,1 iqn.tgt-1

Identify the target transport is configured as iSER
    # iscsiadm -m node -T iqn.tgt-1 | grep -i trans
    iface.transport_name = iser

View sessions
    # iscsiadm -m session
    iser: [6] 12.212.84.7:3260,1 iqn.tgt-1 (non-flash)

To get more debug info about the sessions
# iscsiadm -m session -P 3

View the current debug level of ib_iser
# cat /sys/module/ib_iser/parameters/debug_level
0

To change the debug Level (for example to 2=Info)
# echo 2 > /sys/module/ib_iser/parameters/debug_level
# cat /sys/module/ib_iser/parameters/debug_level
2

Increase debug level for libiscsi
    # echo 1 > /sys/module/libiscsi/parameters/debug_libiscsi_conn
    # echo 1 > /sys/module/libiscsi/parameters/debug_libiscsi_eh
    # echo 1 > /sys/module/libiscsi/parameters/debug_libiscsi_session
    
iSCSI state machine is managed via a user-space daemon called iscsid
execute iscsid in foreground with debug level 3
    # service iscsid stop
    # iscsid -d 3 -f
    
ib_iser messages are logged to the system default log file
Distros with systemd have logs in the journalctl
Older distros usually have it in /var/log/messages or /var/log/syslog

tgtd is a user-space application which uses syslog for the logging output
running tgtd in foreground with debug

The lsscsi command is a tool that parses information from the /proc and /sys pseudo filesystems into human
# yum –y install lsscsi

The /proc/scsi/scsi file can provide additional detail about volumes and targets on a Linux host.
# cat /proc/scsi/scsi

#Format and Mount iSCSI Volume
#partition and create a filesystem on the target using fdisk and mkfs.ext3
$fdisk /dev/sdd
$mkfs.ext3 /dev/sdd1
#If your volume is large size like 1TB, run mkfs.ext3 in background using nohup:
$ nohup mkfs.ext3 /dev/sdd1 &
Mount new partition:
$mkdir /mnt/iscsi
$mount /dev/sdd1 /mnt/iscsi
#Mount iSCSI drive automatically at boot time, make sure iscsi service turned on at boot time:
$chkconfig iscsi on
#Open /etc/fstab file and append config directive:
/dev/sdd1 /mnt/iscsi ext3 _netdev 0 0
--------------------------------------------------------------------------
ISER Performance Tuning and Benchmark
--------------------------------------------------------------------------
IRQ affinity settings
This is relevant for both Initiators and Targets.
bash script will evenly spread all mlx4 and mlx5 devices IRQs between all available cores
#!/bin/bash
IRQS=$(cat /proc/interrupts | egrep 'mlx4|mlx5' | awk '{print $1}' | sed 's/://')
cores=($(seq 1 $(grep -c processor /proc/cpuinfo)))
i=0
for IRQ in $IRQS
do
  core=${cores[$i]}
  let "mask=2**(core-1)"
  echo $(printf "%x" $mask) > /proc/irq/$IRQ/smp_affinity
  let "i+=1"
  if [[ $i ==${#cores[@]} ]]; then i=0
  fi
done



CPU scaling
This is relevant for both Initiators and Targets.
# echo performance > /sys/devices/system/cpu/cpu[0-9]*/cpufreq/scaling_governor

Block layer staging
Relevant for Initiators only. For each block device set

This will set the IO scheduler to do no-operation. IO schedulers try to accelerate HDD access time by minimizing seeks. When working with SAN targets normally it is better to let the target machine do these optimizations if needed (normally a single LUN is not made of a single HDD...). In addition, SDDs do not suffer from seek time
# echo noop > /sys/block/$dev/queue/scheduler

Normally the block layer will try to merge IOs to consecutive offsets. On fast SAN networks it may be better not to merge, and save the CPU utilization
# echo 2 > /sys/block/$dev/queue/nomerges

The system uses physical devices to gather randomness for its random numbers generator. Can save some utilization by turning this off.
# echo 1 > /sys/block/$dev/queue/rq_affinity

--------------------------------------------------------------------------
    
    

    
    
    