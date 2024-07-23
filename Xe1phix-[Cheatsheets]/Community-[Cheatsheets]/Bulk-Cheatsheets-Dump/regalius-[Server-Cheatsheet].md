Sniffing HTTP request/response with tcpdump
```
tcpdump -A -s 0 'tcp dst port 80 and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)'
```

Sniffing TCP request/response with tcpdump to UTF-8
```
tcpdump tcp port 2112 -s 16000 -w - | tr -t '[^[:print:]]' ''
```
Sniffing Datadog Metrics sent
```
tcpdump udp port 8125 -vv -X | tr -t '[^[:print:]]' ''
```

Sniffing PostgreSQL query sent
```
tcpdump -nnvvXSs 1514 -i lo0 dst port 5432
```
Sniffing Cassandra Query sent
```
tcpdump tcp port 9042 -s 16000 -w - | tr -t '[^[:print:]]' ''
```
Filter by source ip:
```
tcpdump -A -s 0 'src <IP_ADDRESS> and tcp port 80 and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)'
```
Multiple ip:
```
tcpdump -A -s 0 '(src <IP_ADDRESS1> or src <IP_ADDRESS2>) and tcp port 80 and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)'
```

Chown recursive
```
find . -type f -name '*.pdf' -print0 | xargs -0 chown someuser:somegroup
```

List Open Ports
```
lsof -i -P -n | grep LISTEN
```

Get process name from PID
```
ps -p <PID> -o comm=
```

Get PID from process name
```
pidof <PROCESS_NAME>
```
```
ps aux | grep <PROCESS_NAME>
```

Check Free Memory
```
free -h
```

Check memory usage per process
```
ps -o pid,user,%mem,command ax | sort -b -k3 -r
```
Check if file is in pagecache
```
https://github.com/tobert/pcstat
pcstat <DIRECTORY/FILE>
```

free pagecache:
```
echo 1 > /proc/sys/vm/drop_caches
```

free dentries and inodes:
```
echo 2 > /proc/sys/vm/drop_caches
```

free pagecache, dentries and inodes:
```
echo 3 > /proc/sys/vm/drop_caches
```

This operation will not "lose" any data (caches are written out to disk before their data is dropped), however, to really make sure all cache is cleaned, you should sync first. E.g. all caches should be cleared if you run
```
sync; echo 3 > /proc/sys/vm/drop_caches
```

Check disk space usage
```
df -h
```

Check disk iNode usage
```
df -i
```

Check largest iNode concentration
```
find / -xdev -printf '%h\n' | sort | uniq -c | sort -k 1 -n
```

Delete file recursively
```
find . -name "*" -type f -delete
```

Check largest files
```
find <PATH> -type f -exec du -Sh {} + | sort -rh | head -n 5
```

Replace in file, with pattern
```
sed '/<PATTERN>/d' --in-place <FILENAME>
```

Replace every nth occurence
```
awk '/<PATTERN>/&&v++%<OCCURENCE>{sub(/<PATTERN>/, "<REPLACEWITH>")}{print}' <FILENAME>
```

Rename directory recursive
```
find . -depth -name "*<CURR_NAME>*" | \
while IFS= read -r ent; do mv $ent ${ent%<CURR_NAME>*}<NEW_NAME>${ent##*<CURR_NAME>}; done
```

Check largest disk usage in current directory
```
du -cks * | sort -rn | head
```

Check the largest folders/files including the sub-directories
```
du -Sh | sort -rh | head -5
```

Check global largest disk usage directory
```
du -a / | sort -n -r | head 10
```

Check PID of file user
```
fuser <FILEPATH>
```

Find Deleted file's file descriptor
```
find /proc/*/fd -ls | grep  '(deleted)'
```

Check limits for a process
```
cat /proc/<PID>/limits
```

Check open file descriptor for a process
```
ls -l /proc/<PID>/fd/ | wc -l
```
List open files and PID
```
ps aux | sed 1d | awk '{print "fd_count=$(lsof -p " $2 " | wc -l) && echo " $2 " $fd_count"}' | xargs -I {} bash -c {}
```

List open connection by IP
```
netstat -ntu | awk '{print $5}' | cut -d: -f1 | sort | uniq -c | sort -rn
```

List open connection by IP:port
```
netstat -ntu | awk '{print $5}' | sort | uniq -c | sort -rn
```

Show established connection with Process name
```
netstat -ap
```

Run commands from file
```
// command_list.sh:
echo "1"
echo "2"
echo "3"

// command line prompt:
$: cat command_list.sh | awk '{system($0)}'
1
2 
3
```

Find Go Version from Binary
```
% gdb $HOME/bin/godoc
GNU gdb (Ubuntu 7.11.1-0ubuntu1~16.04) 7.11.1
Copyright (C) 2016 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
(gdb) p 'runtime.buildVersion'
$1 = 0xa9ceb8 "go1.8.3"
```

Show scheduler latency per process
```
awk 'NF > 7 {if ($1 == "task"){ if (h == 0) { print; h=1} } else { print } }' /proc/sched_debug | awk '{print $6 " | " $1 " | " $2}' | sort -rn
```

Show per-CPU utilization
```
mpstat -P ALL 1
```

Wireshark from tailed pcap
```
tail -f -c +0 foo.pcap | wireshark -k -i -
```
## Docker Network Failure Orchestration

You can introduce latency between containers using the tc command. For example, if the ping time is 5ms then by running the command:
```
tc qdisc add dev eth0 root netem delay 1000ms
```
the ping will now be approx. 1005 ms.

To remove the delay run the command:
```
tc qdisc del dev eth0 root netem
```
It's possible to simulate the complete failure of the network using the iptables command, so the following command will block all traffic to the IP address 192.168.1.202:
```
iptables -A INPUT -s 192.168.1.202/255.255.255.255 -j DROP
```
and to unblock it again use:
```
iptables -D INPUT -s 192.168.1.202/255.255.255.255 -j DROP
```

Check Disk Block Size
```
blockdev --getbsz /dev/vda1
```

Format and Mount Disk
```
/bin/echo -e "n\np\n1\n\n\nt\n8e\nw" | fdisk /dev/vdb
pvcreate /dev/vdb1 ; sleep 1
vgcreate vgdata /dev/vdb1 ; sleep 1
lvcreate -l +100%FREE -n lvdata vgdata
mkfs.ext4 /dev/vgdata/lvdata

# add to /etc/fstab:
/dev/vgdata/lvdata      /data   ext4    errors=remount-ro       0       2

umount /data/snapshot
mount /dev/vgdata/lvdata /data
mount /data/snapshot
mkdir /data/elasticsearch
```

Find text in files within directory
```
grep -rnw '<directory>' -e "<pattern>"
```

Extend LVM
```
/bin/echo -e "n\np\n1\n\n\nt\n8e\nw" | fdisk /dev/vdb
vgextend ubuntu-box-1-vg /dev/vdb
lvextend -l +100%FREE /dev/ubuntu-box-1-vg/root
resize2fs -p /dev/mapper/ubuntu--box--1--vg-root
```

Grow partition and Extend LVM from same disk
```
#check disk
fdisk -l
#grow partition
growpart /dev/vdb 1
#resize PV
pvresize /dev/vdb1
# resize the logical volume
lvextend --verbose --extents +100%FREE --resizefs /dev/vgdata/lvdata
```

Get file line START-END
```
cat file.txt | head -n "<END>" | tail -n +"<START>"
```

Screen

List all screen
```
screen -ls
```

Create new screen
```
screen -S <name>
```

Kill non responding screen
```
screen -X -S <screen name> quit
```
Go to screen
```
screen -x <screen name>
```

Docker

Inspect Virtual IP Addresses for each containers
```
docker inspect -f '{{.Name}} - {{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' $(docker ps -aq)
```

Inspect step by step image build process
```
docker image history --no-trunc image_name > image_history
```

PostgreSQL

tcpdump PostgreSQL from App server
```
tcpdump -nnvvXSs 1514 -i lo0 dst port 5432
```

SSH
Bind Port
```
ssh -fN -D <PORT> <USERNAME>@<IP_ADDRESS>
```

NSQ

Create Topic
```
curl -X http://<IP_ADDRESS_NSQD>:4151/topic/create?topic=<topic_name>
```

Remove all un-printable character from string
```
Echo "String" | tr -cd "[:print:]\n"
```

Tail Grep and Count
```
 tail -f /path/to/file |grep "string" > /tmp/intermediate-file &
 watch -d grep -c "string" /tmp/intermediate-file
 ```
 
 Find IP's identity with IP-API
 ```
 curl --request POST \
  --url http://ip-api.com/batch \
  --header 'content-type: application/json' \
  --data '[
  {"fields": "city,country,countryCode,query", "lang": "en"},
    "<IP1>",
    "<IP2>"
]'
```
 

# Update DNS resolv.conf in Ubuntu
1. Edit /etc/resolvconf/resolvconf.d/*
2. Trigger
```
resolvconf -u
```

# Bash textfile to hashtable
Bash < 4
```
OIFS=$IFS
IFS=','
while read key value
do
    declare  "hash_table_$key=$value"
done < ./<file>.csv
IFS=$OIFS

echo $hash_table_<KEY>
```

Bash >= 4
```
declare -A hash_table

OIFS=$IFS
IFS=','
while read key value
do
    hash_table=( ["$key"]="$value")
done < ./<file>.csv
IFS=$OIFS

echo $hash_table["<KEY>"]
```

## Elasticsearch
 
 Watch profile, get shard index & time execution
 ```
 watch -n 1 "curl -X POST -H 'Content-Type: application/json' http://<IP_ADDRESS>:9200/<INDEX>/_search\?human\=true -d '' |  jq '.profile | .shards | .[] | \"\(.id | split(\"[\")[3] | split(\"]\")[0]) - \(.searches[0].query[0].time)\"' | tr -d '\"' |  sort -n"
 ```
 
 ## Redis
 Delete key by pattern
 ```
 redis-cli --scan --pattern <pattern>* | xargs redis-cli unlink
 ```
  
## Jobs scheduling
 
https://linux.die.net/man/1/at
Schedule job at
```
echo "<COMMAND>" | at<TIME>
```
Inspect at queue
```
atq
```
Inspect single at job
```
at -c <JOB_ID>
```
Remove single at job
```
atrm <JOB_ID>
```
Kill job after
```
timeout <DURATION> <COMMAND>
```

## Java
Show all flags in JVM
```
java -Xms1M -Xmx1M -XX:+UseConcMarkSweepGC -XX:+UnlockDiagnosticVMOptions -XX:+PrintFlagsFinal -version
```

JConsole from remote
```
ssh -fN -D 7777 root@<REMOTE HOST>
jconsole -J-DsocksProxyHost=localhost -J-DsocksProxyPort=7777 service:jmx:rmi:///jndi/rmi://localhost:7199/jmxrmi -J-DsocksNonProxyHosts=
```

## Output File
```
SomeCommand > SomeFile.txt  
```
Or if you want to append data:
```
SomeCommand >> SomeFile.txt
```
If you want stderr as well use this:
```
SomeCommand &> SomeFile.txt  
```
or this to append:
```
SomeCommand &>> SomeFile.txt  
```
if you want to have both stderr and output displayed on the console and in a file use this:
```
SomeCommand 2>&1 | tee SomeFile.txt
```
(If you want the output only, drop the 2 above)


# NGINX
Proxypass by query parameter
```
location / {
    set $pp_d example.net;
    if ($arg_tld = com) {
        set $pp_d example.com;
    }
    proxy_pass http://$pp_d;
    proxy_redirect off;
    ...
}
```

# Golang

Parse race log file to unique occurence
```
cat <LOGFILE> | grep 'WARNING: DATA RACE\|Previous ' -A 3 | sed '/WARNING: DATA RACE/d' | awk '/--/&&v++%2{sub(/--/, "~~")}{print}' | tr -d '\n' |  tr '~~' '\n' | sed '/^ *$/d' | grep -v "\[failed" | sed 's/Previous/ Previous/' | awk '{print $1 " " $7 " " $8 " | " $10 " " $11 " " $17 " " $18}' | sort | uniq -c | sort -rn
```

# PostgreSQL
Get all indexes
```
SELECT
    tablename,
    indexname,
    indexdef
FROM
    pg_indexes
WHERE
    schemaname = 'public'
ORDER BY
    tablename,
    indexname;
```
Get all FK
```
SELECT conrelid::regclass AS "FK_Table"
      ,CASE WHEN pg_get_constraintdef(c.oid) LIKE 'FOREIGN KEY %' THEN substring(pg_get_constraintdef(c.oid), 14, position(')' in pg_get_constraintdef(c.oid))-14) END AS "FK_Column"
      ,CASE WHEN pg_get_constraintdef(c.oid) LIKE 'FOREIGN KEY %' THEN substring(pg_get_constraintdef(c.oid), position(' REFERENCES ' in pg_get_constraintdef(c.oid))+12, position('(' in substring(pg_get_constraintdef(c.oid), 14))-position(' REFERENCES ' in pg_get_constraintdef(c.oid))+1) END AS "PK_Table"
      ,CASE WHEN pg_get_constraintdef(c.oid) LIKE 'FOREIGN KEY %' THEN substring(pg_get_constraintdef(c.oid), position('(' in substring(pg_get_constraintdef(c.oid), 14))+14, position(')' in substring(pg_get_constraintdef(c.oid), position('(' in substring(pg_get_constraintdef(c.oid), 14))+14))-1) END AS "PK_Column"
FROM   pg_constraint c
JOIN   pg_namespace n ON n.oid = c.connamespace
WHERE  contype IN ('f', 'p ')
AND pg_get_constraintdef(c.oid) LIKE 'FOREIGN KEY %'
ORDER  BY pg_get_constraintdef(c.oid), conrelid::regclass::text, contype DESC;
```
Find duplicate value in column
```
Select * from
(
select id, <COLUMN>, count(1)over(partition by <COLUMN>) as counts
from <TABLE_NAME>
)a
Where counts > 1
```

Install perf from source, for lazy person
```
git clone https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git
cd linux/tools/perf
make
cp perf /usr/bin
```

The authenticity of host '<IP-ADDRESS> (<IP-ADDRESS>)' can't be established.
ECDSA key fingerprint is SHA256:<SOME_KEY>.
```
ssh-keygen -R <IP_ADDRESS>
```