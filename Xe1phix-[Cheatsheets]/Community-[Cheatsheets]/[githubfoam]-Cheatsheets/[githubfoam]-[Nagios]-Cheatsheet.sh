--------------------------------------------------------------------------------------------------------------------
#instance 1
sudo docker run -d   --name nagiosweb85   -v $(pwd)/nagios/etc/:/opt/nagios/etc/   -v $(pwd)/nagios/var:/opt/nagios/var/   -v $(pwd)/nagios/ssmtp:/etc/ssmtp/   -v $(pwd)/nagios/:/opt/Custom-Nagios-Plugins   -p 85:80   -e "TZ=Europe/Athens"   alpine:nagios446
http://10.3.0.57:85/nagios/

#instance 2
sudo docker run -d   --name nagiosweb84   -v $(pwd)/nagios/etc/:/opt/nagios/etc/   -v $(pwd)/nagios/var:/opt/nagios/var/   -v $(pwd)/nagios/ssmtp:/etc/ssmtp/   -v $(pwd)/nagios/:/opt/Custom-Nagios-Plugins   -p 84:80   -e "TZ=Europe/Athens"   alpine:nagios446
http://10.3.0.57:84/nagios/

sudo docker container stop nagiosweb85
sudo docker container start nagiosweb85

--------------------------------------------------------------------------------------------------------------------
#png to gd2 format,statusmap image
apt-get update -y && apt-get install libgd-tools -y
--------------------------------------------------------------------------------------------------------------------
#nagios.cfg
cat  /usr/local/nagios/etc/nagios.cfg  | grep -v '^#' | grep -v '^$'
--------------------------------------------------------------------------------------------------------------------
$ cat /usr/local/nagios/etc/nagios.cfg | grep debug_file
debug_file=/usr/local/nagios/var/nagios.debug
max_debug_file_size=1000000

$ cat /usr/local/nagios/etc/nagios.cfg | grep debug_level
debug_level=0

$ stat /usr/local/nagios/var/nagios.debug
stat: cannot statx '/usr/local/nagios/var/nagios.debug': No such file or directory

$ sudo sed -i.bck 's/^debug_level=0/debug_level=-1/' /usr/local/nagios/etc/nagios.cfg
$ stat /usr/local/nagios/etc/nagios.cfg.bck
$ cat /usr/local/nagios/etc/nagios.cfg | grep debug_level
debug_level=-1

$ cat /usr/local/nagios/etc/nagios.cfg | grep debug_verbosity
debug_verbosity=2

$ sudo kill -HUP pid #restart nagios core daemon

$  stat /usr/local/nagios/var/nagios.debug
  File: /usr/local/nagios/var/nagios.debug
  
 STOP DEBUG
$ sudo sed -i.bck 's/^debug_level=-1/debug_level=0/' /usr/local/nagios/etc/nagios.cfg
$ cat /usr/local/nagios/etc/nagios.cfg | grep debug_level
debug_level=0
$ sudo kill -HUP pid #restart nagios core daemon
--------------------------------------------------------------------------------------------------------------------
#add plugins nagios core

yum install -y net-snmp-utils perl-Net-SNMP


wget http://www.techspacekh.com/wp-content/uploads/check_cisco_switch.zip
unzip check_cisco_switch.zip
sudo chmod +x check_cisco_switch.pl
sudo cp check_cisco_switch.pl /usr/local/nagios/libexec
stat /usr/local/nagios/libexec/check_cisco_switch.pl
./check_cisco_switch.pl -H 10.0.0.1 -C T@s9aMon -t fan
 
wget http://www.techspacekh.com/wp-content/uploads/check_cisco.zip
unzip check_cisco.zip
sudo chmod o+x check_cisco.pl
sudo cp check_cisco.pl /usr/local/nagios/libexec
ls -lai check_cisco.pl
stat /usr/local/nagios/libexec/check_cisco.pl
./check_cisco.pl -H 10.100.1.22 -C A@B9aMon -i FastEthernet0/1

sudo mkdir -p /usr/local/nagios/etc/objects/techspacekh
sudo mkdir -p /usr/local/nagios/etc/objects/techspacekh/remotehosts
sudo mkdir -p /usr/local/nagios/etc/objects/techspacekh/servicegroups
sudo mkdir -p /usr/local/nagios/etc/objects/techspacekh/hostgroups

sudo vi /usr/local/nagios/etc/nagios.cfg
cfg_dir=/usr/local/nagios/etc/objects/techspacekh

ps axu | grep nagios | grep -v grep
sudo kill pid
ps axu | grep nagios | grep -v grep
sudo /usr/local/nagios/bin/nagios -pv /usr/local/nagios/etc/nagios.cfg
sudo /usr/local/nagios/bin/nagios -ud /usr/local/nagios/etc/nagios.cfg
ps axu | grep nagios | grep -v grep
sudo kill -HUP pidx

sudo vi /usr/local/nagios/etc/objects/commands.cfg
define command{
 command_name check_cisco_switch
 command_line $USER1$/check_cisco_switch.pl -H $HOSTADDRESS$ -C $ARG1$ -t $ARG2$ -w $ARG3$ -c $ARG4$
 }

define command{
 command_name check_cisco_int
 command_line $USER1$/check_cisco.pl -H $HOSTADDRESS$ -C $ARG1$ -i $ARG2$
 }
 
 $ cat /usr/local/nagios/etc/objects/commands.cfg | grep check_cisco
 command_name check_cisco_switch
 command_line $USER1$/check_cisco_switch.pl -H $HOSTADDRESS$ -C $ARG1$ -t $ARG2$ -w $ARG3$ -c $ARG4$
 command_name check_cisco_int
 command_line $USER1$/check_cisco.pl -H $HOSTADDRESS$ -C $ARG1$ -i $ARG2$
 
cat | sudo tee /usr/local/nagios/etc/objects/techspacekh/hostgroups/cisco-switches.cfg << EOF
define hostgroup{
  hostgroup_name cisco-switches
  alias Cisco Switches
  }
EOF

cat | sudo tee /usr/local/nagios/etc/objects/techspacekh/servicegroups/cisco-services.cfg << EOF
define servicegroup{
 servicegroup_name memory-usage
 alias Memory Usage
 }

define servicegroup{
 servicegroup_name cpu-usage
 alias CPU Usage
 }

define servicegroup{
 servicegroup_name device-fan
 alias Device Fan
 }

define servicegroup{
 servicegroup_name device-powersupply
 alias Device Power Suply
 }

define servicegroup{
 servicegroup_name cisco-interfacestatus
 alias Cisco Interface Status
 }
EOF



cat | sudo tee /usr/local/nagios/etc/objects/techspacekh/remotehosts/test-switch01.cfg<< EOF
define host{
 use generic-switch
 host_name Test-Switch01
 alias Test-Switch01
 notes Access Switch
 address 10.0.0.1
 hostgroups cisco-switches
 }

define service{
 use generic-service
 host_name Test-Switch01
 service_description PING
 check_command check_ping!200.0,20%!600.0,60%
 check_interval 5
 retry_interval 1
 }

define service{
 use generic-service
 host_name Test-Switch01
 service_description Memory Usage
 check_command check_cisco_switch!T@s9aMon!mem!50!40
 servicegroups memory-usage
 }

define service{
 use generic-service
 host_name Test-Switch01
 service_description CPU Usage
 check_command check_cisco_switch!T@s9aMon!cpu!60!70
 servicegroups cpu-usage
 }

define service{
 use generic-service
 host_name Test-Switch01
 service_description Device Fan
 check_command check_cisco_switch!T@s9aMon!fan
 servicegroups device-fan
 }
define service{
 use generic-service
 host_name Test-Switch01
 service_description Device Power Suply
 check_command check_cisco_switch!T@s9aMon!ps
 servicegroups device-powersupply
 }

define service{
 use generic-service
 host_name Test-Switch01
 service_description Port Fa0/1
 check_command check_cisco_int!T@s9aMon!Fa0/1
 servicegroups cisco-interfacestatus
 }

define service{
 use generic-service
 host_name Test-Switch01
 service_description Port Fa0/2
 check_command check_cisco_int!T@s9aMon!Fa0/2
 servicegroups cisco-interfacestatus
 }
EOF

ps axu | grep nagios | grep -v grep
sudo /usr/local/nagios/bin/nagios -pv /usr/local/nagios/etc/nagios.cfg
sudo /usr/local/nagios/bin/nagios -ud /usr/local/nagios/etc/nagios.cfg
ps axu | grep nagios | grep -v grep
sudo kill -HUP pidx
--------------------------------------------------------------------------------------------------------------------
cat /usr/local/nagios/var/archives/nagios-09-11-2021-00.log | grep "Switch01"

$ sudo tail -f /usr/local/nagios/var/nagios.log # nagios log
--------------------------------------------------------------------------------------------------------------------
timedatectl list-timezones
timedatectl list-timezones | grep Los
timedatectl set-timezone America/Los_Angeles
$ date

yum/apt install chrony
systemctl stop chronyd
chronyd -q 'pool pool.ntp.org iburst'
systemctl start chronyd
chronyc tracking #verify
systemctl restart chronyd ; watch chronyc tracking #realtime witnessing
chronyc sources
chronyc sources -v
chronyc
--------------------------------------------------------------------------------------------------------------------
ls /usr/local/nagios/libexec/check_mrtgtraf
/usr/local/nagios/libexec/check_snmp -H 192.168.4.11 -C public -o ifOperStatus.1 -r 1 -m RFC1213-MIB
/usr/local/nagios/libexec/check_mrtgtraf -F /var/lib/mrtg/192.168.4.11.log  -a AVG -w 1000000,1000000 -c 5000000,5000000 -e 10
------------------------------------------------------------------------------------------
/usr/local/nagios/bin/nagiostats -c /usr/local/nagios/etc/nagios.cfg #run the nagiostats utility using the --mrtg and --data arguments
/usr/local/nagios/bin/nagiostats --help
/usr/local/nagios/bin/nagiostats | grep "Ok/Warn/Unk/Crit:"
/usr/local/nagios/bin/nagiostats | grep "Ok/Warn/Unk/Crit:"
--------------------------------------------------------------------------------------------------------------------
htpasswd /usr/local/nagios/etc/htpasswd.users joe_user #create the joe_user user ID
htpasswd -b /usr/local/nagios/etc/htpasswd.users new_userid my_password #specify a password by using the -b flag
htpasswd /usr/local/nagios/etc/htpasswd.users joe_use # update the password for the user ID for joe_use
htpasswd -D /usr/local/nagios/etc/htpasswd.users joe_user #delete the joe_user user ID

/usr/local/nagios/etc/htpasswd.users
--------------------------------------------------------------------------------------------------------------------
#The advantage of manually starting the Nagios daemon is that you can run two Nagios instance on one server
# run a small test instance,create a nagios-test.cfg that points to different configuration object directories 
# /usr/local/nagios/bin/nagios -d /usr/local/nagios/etc/nagios-test.cfg
--------------------------------------------------------------------------------------------------------------------
/usr/local/nagios/bin/nagios -v /usr/local/nagios/etc/nagios.cfg # pre-flight check,verify Nagios configuration file against a sample configuration file

/usr/local/nagios/bin/nagios -s  /usr/local/nagios/etc/nagios.cfg #how much time Nagios might spend procesing configuration files

--------------------------------------------------------------------------------------------------------------------
/usr/local/nagios/var/objects.precache #The precache configuration information

/usr/local/nagios/bin/nagios -pv /usr/local/nagios/etc/nagios.cfg #create the pre-cache configuration files
more /usr/local/nagios/var/objects.precache

#stop Nagios daemon
$ ps axu | grep nagios | grep -v grep
$ sudo kill pid # kill the first instance of pids (/usr/local/nagios/bin/nagios -d /usr/local/nagios/etc/nagios.cfg)

# use the cached objects from the /usr/local/nagios/var/objects.precache
/usr/local/nagios/bin/nagios -ud /usr/local/nagios/etc/nagios.cfg
# restart to use the cached objects from the /usr/local/nagios/var/objects.precache
ps axu | grep nagios | grep -v grep
nagios     99900  0.0  0.9  70008  4560 ?        Ss   07:36   0:00 /usr/local/nagios/bin/nagios -ud /usr/local/nagios/etc/nagios.cfg
nagios     99901  0.0  0.2  17396  1220 ?        S    07:36   0:00 /usr/local/nagios/bin/nagios --worker /usr/local/nagios/var/rw/nagios.qh
nagios     99902  0.0  0.2  17396  1280 ?        S    07:36   0:00 /usr/local/nagios/bin/nagios --worker /usr/local/nagios/var/rw/nagios.qh
nagios     99903  0.0  0.2  17396  1372 ?        S    07:36   0:00 /usr/local/nagios/bin/nagios --worker /usr/local/nagios/var/rw/nagios.qh
nagios     99904  0.0  0.2  17396  1220 ?        S    07:36   0:00 /usr/local/nagios/bin/nagios --worker /usr/local/nagios/var/rw/nagios.qh
nagios     99905  0.0  0.4  69492  1992 ?        S    07:36   0:00 /usr/local/nagios/bin/nagios -ud /usr/local/nagios/etc/nagios.cfg

[vagrant@vg-compute-09 ~]$ sudo kill -HUP 99900

[vagrant@vg-compute-09 ~]$ ps axu | grep nagios | grep -v grep
nagios     99900  0.0  1.5  74160  7548 ?        Ss   07:36   0:00 /usr/local/nagios/bin/nagios -ud /usr/local/nagios/etc/nagios.cfg
nagios     99905  0.0  0.4  69492  1992 ?        S    07:36   0:00 /usr/local/nagios/bin/nagios -ud /usr/local/nagios/etc/nagios.cfg
nagios     99922  0.0  0.2  15852  1372 ?        S    07:39   0:00 /usr/local/nagios/bin/nagios --worker /usr/local/nagios/var/rw/nagios.qh
nagios     99923  0.0  0.2  15852  1288 ?        S    07:39   0:00 /usr/local/nagios/bin/nagios --worker /usr/local/nagios/var/rw/nagios.qh
nagios     99924  0.0  0.2  15852  1220 ?        S    07:39   0:00 /usr/local/nagios/bin/nagios --worker /usr/local/nagios/var/rw/nagios.qh
nagios     99925  0.0  0.2  15852  1316 ?        S    07:39   0:00 /usr/local/nagios/bin/nagios --worker /usr/local/nagios/var/rw/nagios.qh
--------------------------------------------------------------------------------------------------------------------
#run nagios w pre-cached configuration
/usr/local/nagios/bin/nagios -pv /usr/local/nagios/etc/nagios.cfg #create the pre-cache configuration files
/usr/local/nagios/bin/nagios -ud /usr/local/nagios/etc/nagios.cfg # use the cached objects from the /usr/local/nagios/var/objects.precache
ps axu | grep nagios | grep -v grep
sudo kill -HUP PID #restart nagios daemon
sudo kill PID #stop nagios daemon
--------------------------------------------------------------------------------------------------------------------
#how to check nagios core version
/usr/local/nagios/bin/nagios --help | grep "Nagios Core"
--------------------------------------------------------------------------------------------------------------------
#start Nagios daemon
/usr/local/nagios/bin/nagios -d /usr/local/nagios/etc/nagios.cfg 
--------------------------------------------------------------------------------------------------------------------
#stop Nagios daemon

#find pid of nagios core 
$ ps axu | grep nagios | grep -v grep
nagios     96886  0.0  0.4  74220  1920 ?        Ss   06:30   0:00 /usr/local/nagios/bin/nagios -d /usr/local/nagios/etc/nagios.cfg
nagios     96888  0.0  0.2  17396  1404 ?        S    06:30   0:00 /usr/local/nagios/bin/nagios --worker /usr/local/nagios/var/rw/nagios.qh
nagios     96889  0.0  0.2  17396  1284 ?        S    06:30   0:00 /usr/local/nagios/bin/nagios --worker /usr/local/nagios/var/rw/nagios.qh
nagios     96890  0.0  0.2  17396  1352 ?        S    06:30   0:00 /usr/local/nagios/bin/nagios --worker /usr/local/nagios/var/rw/nagios.qh
nagios     96891  0.0  0.2  17396  1348 ?        S    06:30   0:00 /usr/local/nagios/bin/nagios --worker /usr/local/nagios/var/rw/nagios.qh
nagios     96931  0.0  0.0  73704   448 ?        S    06:30   0:00 /usr/local/nagios/bin/nagios -d /usr/local/nagios/etc/nagios.cfg

$ sudo kill 96886 # kill the first instance of pids (/usr/local/nagios/bin/nagios -d /usr/local/nagios/etc/nagios.cfg)

$ ps axu | grep nagios | grep -v grep # verify all is gone

#start the Nagios daemon manually
$ sudo /usr/local/nagios/bin/nagios -d /usr/local/nagios/etc/nagios.cfg

#verify nagios core started
$ ps axu | grep nagios | grep -v grep
nagios     99421  0.0  0.9  70004  4300 ?        Ss   07:02   0:00 /usr/local/nagios/bin/nagios -d /usr/local/nagios/etc/nagios.cfg
nagios     99422  0.0  0.2  17396  1012 ?        S    07:02   0:00 /usr/local/nagios/bin/nagios --worker /usr/local/nagios/var/rw/nagios.qh
nagios     99423  0.0  0.1  17396   948 ?        S    07:02   0:00 /usr/local/nagios/bin/nagios --worker /usr/local/nagios/var/rw/nagios.qh
nagios     99424  0.0  0.2  17396  1104 ?        S    07:02   0:00 /usr/local/nagios/bin/nagios --worker /usr/local/nagios/var/rw/nagios.qh
nagios     99425  0.0  0.2  17396  1012 ?        S    07:02   0:00 /usr/local/nagios/bin/nagios --worker /usr/local/nagios/var/rw/nagios.qh
nagios     99426  0.0  0.3  69488  1632 ?        S    07:02   0:00 /usr/local/nagios/bin/nagios -d /usr/local/nagios/etc/nagios.cfg

browse nagios core website
http://192.168.60.60/nagios/
--------------------------------------------------------------------------------------------------------------------
#restart Nagios daemon

$ ps axu | grep nagios | grep -v grep
nagios     99421  0.0  0.8  70004  4040 ?        Ss   07:02   0:00 /usr/local/nagios/bin/nagios -d /usr/local/nagios/etc/nagios.cfg
nagios     99422  0.0  0.4  17396  1996 ?        S    07:02   0:00 /usr/local/nagios/bin/nagios --worker /usr/local/nagios/var/rw/nagios.qh
nagios     99423  0.0  0.4  17396  2060 ?        S    07:02   0:00 /usr/local/nagios/bin/nagios --worker /usr/local/nagios/var/rw/nagios.qh
nagios     99424  0.0  0.4  17396  2292 ?        S    07:02   0:00 /usr/local/nagios/bin/nagios --worker /usr/local/nagios/var/rw/nagios.qh
nagios     99425  0.0  0.4  17396  2052 ?        S    07:02   0:00 /usr/local/nagios/bin/nagios --worker /usr/local/nagios/var/rw/nagios.qh
nagios     99426  0.0  0.2  69488  1420 ?        S    07:02   0:00 /usr/local/nagios/bin/nagios -d /usr/local/nagios/etc/nagios.cfg

#restart the Nagios Core process by sending it a SIGHUP (signal hangup) manually, same pid comes up
$ sudo kill -HUP 99421 

$ ps axu | grep nagios | grep -v grep
nagios     99421  0.0  1.4  74168  6716 ?        Ss   07:02   0:00 /usr/local/nagios/bin/nagios -d /usr/local/nagios/etc/nagios.cfg
nagios     99426  0.0  0.2  69488  1420 ?        S    07:02   0:00 /usr/local/nagios/bin/nagios -d /usr/local/nagios/etc/nagios.cfg
nagios     99461  0.0  0.2  15852  1352 ?        S    07:06   0:00 /usr/local/nagios/bin/nagios --worker /usr/local/nagios/var/rw/nagios.qh
nagios     99462  0.0  0.2  15852  1360 ?        S    07:06   0:00 /usr/local/nagios/bin/nagios --worker /usr/local/nagios/var/rw/nagios.qh
nagios     99463  0.0  0.2  15852  1280 ?        S    07:06   0:00 /usr/local/nagios/bin/nagios --worker /usr/local/nagios/var/rw/nagios.qh
nagios     99464  0.0  0.2  15852  1324 ?        S    07:06   0:00 /usr/local/nagios/bin/nagios --worker /usr/local/nagios/var/rw/nagios.qh

--------------------------------------------------------------------------------------------------------------------
systemctl stop/start/restart nagios #without daemon
--------------------------------------------------------------------------------------------------------------------
/usr/local/nagios/libexec/check_wmi_plus.pl -H 10.25.14.3 -u wmiagent -p wmiagent -m checkcpu -w ’80’ -c ’90’ -d
/usr/local/nagios/libexec/check_wmi_plus.pl -H 10.25.14.3 -u wmiagent -p wmiagent -m checkcpu -w ’80’ -c ’90’ –extrawmicarg “–debuglevel=4”
/usr/local/nagios/libexec/check_wmi_plus.pl -H 10.25.14.3 -u wmiagent -p wmiagent -m checkcpu -d

Get-WmiObject -Query ‘select PercentProcessorTime,Timestamp_Sys100NS from Win32_PerfRawData_PerfOS_Processor where Name=”_Total”‘

/usr/local/nagios/libexec/check_wmi_plus.pl -H 10.25.14.3 -u your_domain/wmiagent -p wmiagent -m checkcpu
vi /usr/local/nagios/libexec/check_wmi_plus.conf
our @opt_extra_wmic_args=(); # extra arguments to pass to wmic
#Add “–option=client ntlmv2 auth=Yes”
our @opt_extra_wmic_args=(“–option=client ntlmv2 auth=Yes”); # extra arguments to pass to wmic
--------------------------------------------------------------------------------------------------------------------
#troubleshooting
systemctl restart nagios
journalctl -xe
journalctl -u nagios.service

tail -f /usr/local/nagios/var/nagios.log # nagios log

# strace /usr/local/nagios/bin/nagios -d /usr/local/nagios/etc/nagios.cfg
# strace -c /usr/local/nagios/bin/nagios -d /usr/local/nagios/etc/nagios.cfg
# strace -e close /usr/local/nagios/bin/nagios -d /usr/local/nagios/etc/nagios.cfg
# strace -e kill /usr/local/nagios/bin/nagios -d /usr/local/nagios/etc/nagios.cfg
# strace -e access /usr/local/nagios/bin/nagios -d /usr/local/nagios/etc/nagios.cfg

# upgrade from 4.4.6 to 4.4.7
systemctl status nagios
Problem:
Apr 14 15:35:01 nag nagios[503]: qh: echo service query handler registered
Apr 14 15:35:01 nag nagios[503]: qh: help for the query handler registered
Apr 14 15:35:01 nag nagios[503]: wproc: Successfully registered manager as @wproc with query handler
Apr 14 15:35:01 nag nagios[503]: wproc: Registry request: name=Core Worker 510;pid=510
Apr 14 15:35:01 nag nagios[503]: wproc: Registry request: name=Core Worker 513;pid=513
Apr 14 15:35:01 nag nagios[503]: wproc: Registry request: name=Core Worker 511;pid=511
Apr 14 15:35:01 nag nagios[503]: wproc: Registry request: name=Core Worker 512;pid=512
Apr 14 15:35:01 nag nagios[503]: Caught SIGSEGV, shutting down...


systemctl stop nagios.service
systemctl status nagios.service

cat /usr/local/nagios/etc/nagios.cfg | grep check_for_update
cp /usr/local/nagios/etc/nagios.cfg{,.orig}

sed -i 's/check_for_updates=1/check_for_updates=0/g'  /usr/local/nagios/etc/nagios.cfg
cat /usr/local/nagios/etc/nagios.cfg | grep check_for_updates

systemctl start nagios.service
systemctl status nagios.service
--------------------------------------------------------------------------------------------------------------------
#centos
/etc/snmp/snmpd.conf

sudo service snmpd status
sudo service snmpd start

#SNMP v2
snmpwalk -v2c -c public localhost system
snmpwalk -v2c -c public 192.168.58.9 system
snmpwalk -v2c -c monsvronly 192.168.58.9 | head -10

# Using OID system (1.3.6.1.2.1.1) to get basic system information about host
snmpwalk -v2c -c public 192.168.1.1:161 1.3.6.1.2.1.1

netstat -alun | grep 161
nc -uvz 192.168.58.9 161

echo -e "# SNMP version 2c community\nrocommunity monsvronly 192.168.58.8" | sudo tee -a /etc/snmp/snmpd.conf

firewall-cmd --add-port=161/udp --permanent
firewall-cmd --reload

#SNMP v3
sudo net-snmp-create-v3-user -ro -A STrP@SSWRD -a SHA -X STr0ngP@SSWRD -x AES snmpadmin

# snmpwalk v3 example with authentication and encryption
snmpwalk -v3 -l authPriv -u UserMe -a SHA -A AuthPass1 -x AES -X PrivPass2 192.168.1.1:161 1.3.6.1.2.1.1
snmpwalk -v3 -a SHA -A STrP@SSWRD -x AES -X STr0ngP@SSWRD -l authPriv -u snmpadmin localhost | head -10
snmpwalk -v3 -l authPriv -u UserJustMe -a SHA -A AuthPass1 -x AES -X PrivPass2 10.7.1.9:161 sysDescr
snmpwalk -v3 -l authPriv -u snmp-poller -a SHA -A "PASSWORD1" -x AES -X "PASSWORD1" 10.10.60.50

# snmpwalk v3 example with authentication, but no encryption
snmpwalk -v3 -u snappimon -A ‘$nmP$tr!nGm0n!’ -l authNoPriv -a MD5 172.16.1.1 1.3.6.1.2.1.2
snmpwalk -v3 -l authnoPriv -u UserMe -a SHA -A AuthPass1 192.168.1.1:161 1.3.6.1.2.1.1

# snmpwalk v3 example with no authentication and no encryption but you still needs a username
snmpwalk -v3 -l noAuthNoPriv -u UserMe 192.168.1.1:161 1.3.6.1.2.1.1

# Using OID dot1dTpFdbAddress and SNMPv3 context name to get mac addresses in VLAN 32
snmpwalk -v3 -l authNoPriv -u UserMe -a MD5 -A AuthPass1 -n vlan-32 192.168.1.1 dot1dTpFdbAddress

# Using OID sysDescr (1.3.6.1.2.1.1.1) to get system description
snmpget -v3 -l authPriv -u UserMe -a SHA -A AuthPass1 -x AES -X PrivPass2 10.1.1.1 1.3.6.1.2.1.1.0
snmpget -v3 -l authPriv -u snmpadmin  -a SHA -A "STrP@SSWRD" -x AES -X "STr0ngP@SSWRD" localhost sysName.0 system.sysUpTime.0
snmpget -v3 -l authPriv -u snmp-poller -a SHA -A "PASSWORD1" -x AES -X "PASSWORD1" 10.10.60.50 sysName.0
snmpget -v3 -l authPriv -u snmp-poller -a SHA -A "PASSWORD1" -x AES -X "PASSWORD1" 10.10.60.50 sysName.0 system.sysUpTime.0

# Using OID ifAdminStatus (1.3.6.1.2.1.2.2.1.7) to administratively shutdown interface with index 10105
snmpset -v3 -l authPriv -u UserMe -a SHA -A AuthPass1 -x AES -X PrivPass2 192.168.1.1 1.3.6.1.2.1.2.2.1.7.10105 i 2

# Using OID ifAdminStatus (1.3.6.1.2.1.2.2.1.7) to administratively shutdown interface with index 10105
snmpset -v2c -c private 192.168.1.1 1.3.6.1.2.1.2.2.1.7.10105 i 2

# Using OID netSnmpExampleHeartbeatRate (1.3.6.1.4.1.8072.2.3.2.1) to send a trap using numeric OID
snmptrap -v3 -e 0x090807060504030201 -l authPriv -u UserMe -a SHA -A AuthPass1 -x AES -X PrivPass2 127.0.0.1:161 ''  1.3.6.1.4.1.8072.2.3.0.1 1.3.6.1.4.1.8072.2.3.2.1 i 60
# Using OID netSnmpExampleHeartbeatRate (1.3.6.1.4.1.8072.2.3.2.1) to send a trap using MIB
snmptrap -v3 -e 0x090807060504030201 -l authPriv -u UserMe -a SHA -A AuthPass1 -x AES -X PrivPass2 127.0.0.1:161 '' NET-SNMP-EXAMPLES-MIB::netSnmpExampleHeartbeatNotification netSnmpExampleHeartbeatRate i 60

# Using OID netSnmpExampleHeartbeatRate (1.3.6.1.4.1.8072.2.3.2.1) to send a trap using MIB
snmptrap -v2c -c public 127.0.0.1 '' NET-SNMP-EXAMPLES-MIB::netSnmpExampleHeartbeatNotification netSnmpExampleHeartbeatRate i 6

# Using OID linkUp (1.3.6.1.6.3.1.1.5.4) to send a trap that notifies that eth0 is in UP state
snmptrap -v2c -c public 127.0.0.1 '' '.1.3.6.1.6.3.1.1.5.4' .1.3.6.1.6.3.1.1.5.4 s "eth0"

snmptrap -v 1 -c public 10.1.1.160 .1.3.6.1.4.1.28116.20 10.0.1.250 6 "" "" 1.3.6.1.4.1.28116.20.1 s "Test Trap"

#SNMP v3 troubleshooting
tcpdump -nni eth0 host <ip address> and port 161
--------------------------------------------------------------------------------------------------------------------
#MRTG SNMP v3

/usr/local/mrtg-2/bin/cfgmaker --global 'Workdir: /path/to/workdir' --global 'Options[_]: bits, growright' --ifref=descr --output /path/to/output.cfg --enablesnmpv3 --username=<username> --authprotocol=MD5 --authpassword=<authpass> --privprotocol=des --privpassword=<encrypass> --contextengineid=<engineid> --snmp-options=:::::3 <router.ip>
cfgmaker --global 'Workdir: /var/www/mrtg' --global 'Options[_]: bits, growright' --output /etc/mrtg/mrtg.cfg --enablesnmpv3 --username=cactiuser --authprotocol=md5 --privprotocol=des --authpassword=12345678 --privpassword=87654321 --ifref=descr --contextengineid=80003a8c04 --snmp-options=:::::3 192.168.0.1
/usr/bin/cfgmaker --global "WorkDir: /var/www/mrtg/cordr1" --enablesnmpv3 --username=*** --authpassword=*** --contextengineid=0x2e81200 --snmp-options=:::::3 --global "Options[_]: bits,growright" --global "WithPeak[_]: ymwd" --ifdesc=alias --output /etc/mrtg/mrtg_cordr1.cfg ***.***.***.242

cfgmaker --global 'WorkDir: /var/www/mrtg' \
--global 'Options[_]: growright, bits' \
--output=/etc/mrtg/192.168.1.100.cfg \
--enablesnmpv3 --username=username4snmpv3 \
--authpassword=rootsrockreggae --authproto=md5 \
--snmp-options=:::::3 \
--contextengineid=0x80001f8880711168720eb1e745 \
securev3user@192.168.1.100

cfgmaker --global 'WorkDir: /var/www/mrtg' \
--global 'Options[_]: growright, bits' \
--output=/etc/mrtg/192.168.1.100-secure.cfg \
--enablesnmpv3 --username=securev3user --authpassword=mandeville \
--authproto=md5 --privpassword=savlamar --privprotocol=des \
--snmp-options=:::::3 \
--contextengineid=0x80001f8880711168720eb1e745 \
securev3user@192.168.1.100


# execute mrtg 3 times (display warnings until 3 times)
# for (( i=1 ; i <= 3 ; i++ )); do env LANG=C mrtg /etc/mrtg/mrtg.cfg; done

crontab -e
*/5 * * * * env LANG=C mrtg /etc/mrtg.cfg --logging /var/log/mrtg.log

cfgmaker public@localhost > /etc/mrtg.cfg #OPTION 1
sudo cfgmaker --output=/etc/mrtg.cfg public@localhost #OPTION 2

/usr/bin/indexmaker -output=/var/www/mrtg/index.html -title=”Memory and CPU Usage” /etc/mrtg/cpu.cfg
sudo sh -c 'indexmaker -output=/var/www/mrtg/index.html -title=”Memory and CPU Usage” /etc/mrtg/cpu.cfg'

#/usr/bin/indexmaker –output=/var/www/mrtg/index.html \
–title=”Memory and CPU Usage ” \
–sort=name \
–enumerate \
/etc/mrtg/cpu.cfg \
/etc/mrtg/mem.cfg \
/etc/cron.mrtg/memfree \
/etc/cron.mrtg/mempercent \
/etc/cron.mrtg/disk
--------------------------------------------------------------------------------------------------------------------
#Install MIBS ubuntu
sudo apt-get install snmp-mibs-downloader -y
sudo download-mibs
$ snmptranslate -Tp

$ /var/lib/snmp/mibs/
iana/ ietf/

snmpwalk -v 1 -c public 127.0.0.1 -m /var/lib/snmp/mibs/ietf/HOST-RESOURCES-MIB |grep hrStorageDescr
snmpwalk -v 1 -c public 127.0.0.1 -m /var/lib/snmp/mibs/ietf/HOST-RESOURCES-MIB |grep memory
--------------------------------------------------------------------------------------------------------------------
/etc/cron.d/mrtg
*/5 * * * * root LANG=C LC_ALL=C /usr/bin/mrtg /etc/mrtg/mrtg.cfg --lock-file /var/lock/mrtg/mrtg_l --confcache-file /var/lib/mrtg/mrtg.ok
*/5 * * * * root env LANG=C /usr/local/mrtg2/bin/mrtg /home/mrtg/mrtg.cfg --logging /var/log/mrtg.log
*/5 * * * * root LANG=C LC_ALL=C /usr/bin/mrtg /etc/mrtg/mrtg.cfg --logging /var/log/mrtg.log --lock-file /var/lock/mrtg/mrtg_l --confcache-file /var/lib/mrtg/mrtg.ok

sudo sh -c 'for (( i=1 ; i <= 3 ; i++ )); do env LANG=C mrtg /etc/mrtg/mrtg.cfg; done'
cfgmaker --snmp-options=:::::2 --ifref=descr --ifdesc=descr --global "WorkDir: /var/www/html/mymrtg" public@localhost > /etc/mrtg/mrtg.cfg

--------------------------------------------------------------------------------------------------------------------
#monitor a failure

#!/bin/bash

######################################  VARIABLES ############################################################
NAGIOS_LOG=`cat /usr/local/nagios/var/log/nagios.log | perl -pe 's/(\d+)/localtime($1)/e' | grep Caught | awk '{print $2" "$3" "$4" "$6" "$7" "$8" "$9$10}' > /usr/local/nagios/var/log/tmp_log`

NAGIOS_LOG_COUNT=`awk -v d1="$(date --date="-60 min" "+%b %_d %H:%M")" -v d2="$(date "+%b %_d %H:%M")" '$0 > d1 && $0 < d2 || $0 ~ d2' /usr/local/nagios/var/log/tmp_log | wc -l`

SERVICE_NAG_COUNT=`/etc/init.d/nagios status | grep running | wc -l`
####################################### DEC END ##############################################################

if [ $NAGIOS_LOG_COUNT == 0 ];

then

echo "Nagios is running OK"

elif [ $NAGIOS_LOG_COUNT -ge 1 ];

then

echo "Nagios Service Outage" >> /usr/local/nagios/var/nagios_service_check_log

echo "=====================" >> /usr/local/nagios/var/nagios_service_check_log

echo "$NAGIOS_LOG" >> /usr/local/nagios/var/nagios_service_check_log

echo "## Restarting Nagios Service ##" >> /usr/local/nagios/var/nagios_service_check_log

/etc/init.d/nagios restart >> /usr/local/nagios/var/nagios_service_check_log

sleep 2

if [ $SERVICE_NAG_COUNT == 1 ];

then

############# VARIABLE ###############################
SERVICE_NAG=`/etc/init.d/nagios status | grep running`
######################################################

echo "OK - $SERVICE_NAG" >> /usr/local/nagios/var/nagios_service_check_log | mail -s "NOTIFICATION - Nagios Service Outage" admin@howtovmlinux.com < /usr/local/nagios/var/nagios_service_check_log && rm -rf /usr/local/nagios/var/nagios_service_check_log

else

echo "CRITICAL - Nagios Service restart failed" >> /usr/local/nagios/var/nagios_service_check_log | mail -s "CRITICAL - Nagios Service Outage - Escalation Needed" admin@howtovmlinux.com < /usr/local/nagios/var/nagios_service_check_log && rm -rf /usr/local/nagios/var/nagios_service_check_log

fi
fi
--------------------------------------------------------------------------------------------------------------------