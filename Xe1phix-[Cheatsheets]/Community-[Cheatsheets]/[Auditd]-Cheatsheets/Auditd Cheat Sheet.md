#Auditd Cheat Sheet 
##Files
###/etc/audit/auditd.conf

auditd.conf should be changed based on the importance of log integrity and how long you would like to keep records.

Here are the options that manage log rotation: 

```bash
flush = INCREMENTAL
freq = 20
num_logs = 5
disp_qos = lossy
dispatcher = /sbin/audispd
name_format = NONE
##name = mydomain
max_log_file = 6 
max_log_file_action = ROTATE
space_left = 75
```

_action options determine how resilient the system will be to failure:

```bash
admin_space_left_action = SUSPEND
disk_full_action = SUSPEND
disk_error_action = SUSPEND
```

###/etc/audit/audit.rules

There are a number of compliance example included in ```/usr/share/doc/auditd/examples```

This contains all of the rules that are loaded when the system starts, most rulesets start with: 

```bash
## First rule - delete all
-D

## Increase the buffers to survive stress events.
## Make this bigger for busy systems
-b 8192

## Set failure mode to panic
-f 2
```

Rules can be added here or via the auditctl command. 

##Commands
###auditd
```auditd -f``` - foreground auditd, messages go to stderr
```SIGHUP``` - Reconfigure Auditd, re-read configuration files 

"A boot param of audit=1 should be added to ensure that all processes that run before the audit daemon starts is marked as auditable by the kernel. "
- [Auditd Man Page] [auditd_man]

###auditctl
"auditctl program is used to control the behavior, get status, and add or delete rules into the 2.6 kernel’s audit system."

```auditctl - l``` - List current rule set

####Control Behavior 
   * ```auditctl -e 0``` - Temporarily disable auditing 
   * ```auditctl -e 1``` - Re-enable auditing
   * ```auditctl -e 2``` - Lock auditing to enabled, reboot to change configuration. 
   * ```auditctl -f 0``` - Do not report critical errors 
   * ```auditctl -f 1``` - Default, printk critical errors 
   * ```auditctl -f 2``` - Panic on critical errors 
- [Auditctl Man Page] [auditctl_man]

####Manage Rules
   * ```auditctl -D``` - Clear all rules
   * ```auditctl -l``` - List ruleset
   * ```auditctl -w /file -p rwxa -k file_alert``` - Watch all actions on a file and label with file_alert
   * ```auditctl -a always,exit -F arch=b32 -F uid=www-data -S execve -k programs -k www``` - Log all commands executed by the www-data user and label with programs and www keywords

###ausearch
b
   * ```ausearch -a 104``` - Search for event id 104
   * ```ausearch --uid 0 --syscall EXECVE --success yes``` - Search for all programs executed by root that were successful 
   * ```ausearch -ui 0 -sc EXECVE -sv yes``` - Search for all programs executed by root that were successful 



###aureport

   * ```aureport --auth``` - Authentication Report
   * ```aureport --login --failed``` - Failed Login Report
   * ```aureport --file``` - File Report


##Rules
“audit rules come in 3 varieties: control, file, and syscall”
  * Control - “configuring the audit system”
  * File - “audit access to particular files or directories”
  * Syscall - “loaded into a matching engine that intercepts each syscall”
```
-a action list: always log on syscall exit
-F field 
-S syscall: execve
-k Logging Key: programs
```
```bash
-a always,exit -F arch=b32 -F uid=33 -S execve -k programs -k www
-a always,exit -F arch=b64 -F uid=33 -S execve -k programs -k www
-a always,exit -F arch=b32 -C auid!=uid -S execve -k su_program -k programs
-a always,exit -F arch=b64 -C auid!=uid -S execve -k su_program -k programs
-a exit,always -S unlink -S rmdir
-a exit,always -S stime.*
-a exit,always -S setrlimit.*
-w /var/www -p wa
-w /etc/group -p wa
-w /etc/passwd -p wa
-w /etc/shadow -p wa
-w /etc/sudoers -p wa
```
- [audit.rules Man Page] [audit.rules_man]

##OSSEC
https://github.com/ossec/ossec-hids/blob/6eb2d4dce24688c675de3202f21a925b0b7501f9/etc/decoder.xml#L2414

#Links
[auditd_man]: http://linux.die.net/man/8/auditd  "Auditd Man Page"
[auditctl_man]: http://linux.die.net/man/8/auditctl  "Auditctl Man Page"
[audit.rules_man]: http://linux.die.net/man/7/audit.rules  "audit.rules man page"
http://security.blogoverflow.com/2013/01/a-brief-introduction-to-auditd/
https://access.redhat.com/documentation/en-US/Red_Hat_Enterprise_Linux/7/html/Security_Guide/chap-system_auditing.html

## Reporting and Alerting Links


Splunk: https://splunkbase.splunk.com/app/2642/
Logstash: https://gist.github.com/artbikes/2313040 
Logstash: http://serverfault.com/questions/609192/how-to-parse-audit-log-using-logstash 
ELSA

Bro: https://github.com/set-element/auditdBroFramework
BroCon ‘15: https://www.bro.org/brocon2015/brocon2015_abstracts.html#looking-for-ghosts-in-themachine 

Ossec
http://www.ossec.net/files/ossec-hids-2.7-release-note.txt
https://github.com/ossec/ossec-docs/blob/master/decoders/10_auditd_decoder.xml 


##PCI-DSS
http://linux-audit.com/category/compliance/pci-dss/
http://networkrecipes.blogspot.com/2013/03/auditd-in-linux-for-pci-dss-compliance.html


##CIS Benchmark
https://benchmarks.cisecurity.org/tools2/linux/CIS_Red_Hat_Enterprise_Linux_6_Benchmark_v1.1.0.pdf
http://blog.ptsecurity.com/2010/11/requirement-10-track-and-monitor-all.html

