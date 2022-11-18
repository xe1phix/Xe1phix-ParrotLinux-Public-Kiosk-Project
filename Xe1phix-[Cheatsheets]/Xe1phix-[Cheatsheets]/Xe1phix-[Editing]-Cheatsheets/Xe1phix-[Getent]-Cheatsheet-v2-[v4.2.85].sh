#Administrative databases in Unix,getent – get entries from administrative database
    passwd – can be used to confirm usernames, userids, home directories and full names of your users
    group – all the information about Unix groups known to your system
    services – all the Unix services configured on your system
    networks – networking information – what networks your system belongs to
    protocols – everything your system knows about network protocols

$ getent hosts # /etc/hosts file
$ getent hosts vg-ubuntu-01 double-check which IPs this hostname points to
$ getent networks #check the network and IP address of your system
$ getent services 20 #Use “services” with the port number to find the service name and its protocol

#List Users(system and normal users) on Linux using the /etc/passwd File, normal user has a real login shell and a home directory.
awk -F: '{ print $1}' /etc/passwd
cat /etc/passwd | awk -F: '{print $1}'
awk -F: '{ print $1}' /etc/passwd | wc -l # get the # of users
cut -d: -f1 /etc/passwd
cat /etc/passwd | cut -d: -f1
getent passwd # list users
getent passwd | awk -F ":" '{print $1}'
getent passwd | cut -d: -f1
getent passwd # equivalent to cat /etc/passwd
getent passwd rahul #details for a particular user
getent passwd 0 #find a username by UID

$ cut -d":" -f1 /etc/passwd #list all users

#list normal user names
awk -F: '{if($3 >= 1000 && $3 < 2**16-2) print $1}' /etc/passwd
awk -F: '{if(($3 >= 500)&&($3 <65534)) print $1}' /etc/passwd
awk -F: '{if(!(( $2 == "!!")||($2 == "*"))) print $1}' /etc/shadow 
grep -E ":[0-9]{4,6}:[0-9]{4,6}:" /etc/passwd | cut -d: -f1
$ getent passwd | awk 'NR==FNR { if ($1 ~ /^UID_(MIN|MAX)$/) m[$1] = $2; next }
{ split ($0, a, /:/);
  if (a[3] >= m["UID_MIN"] && a[3] <= m["UID_MAX"] && a[7] !~ /(false|nologin)$/)
    print a[1] }' /etc/login.defs -
$ getent passwd | \
nologin|false)> grep -vE '(nologin|false)$' | \
: -v mi> awk -F: -v min=`awk '/^UID_MIN/ {print $2}' /etc/login.defs` \
X/ {p> -v max=`awk '/^UID_MAX/ {print $2}' /etc/login.defs` \
$3 >= > '{if(($3 >= min)&&($3 <= max)) print $1}' | \
t -u> sort -u

grep -E '^UID_MIN|^UID_MAX' /etc/login.defs #Each user has a numeric user ID called UID. If not specified automatically selected from the /etc/login.defs
getent passwd {1000..60000} #list all normal users depending on UID_MIN/UID_MAX in /etc/login.defs
eval getent passwd {$(awk '/^UID_MIN/ {print $2}' /etc/login.defs)..$(awk '/^UID_MAX/ {print $2}' /etc/login.defs)} | cut -d: -f1
# generic,UID_MIN and UID_MIN values may be different, 
eval getent passwd {$(awk '/^UID_MIN/ {print $2}' /etc/login.defs)..$(awk '/^UID_MAX/ {print $2}' /etc/login.defs)}


awk -F ":" '{print $5}' /etc/passwd #print the fifth field
getent passwd $UID| awk -F ":" '{print $5}'
GECOS fields (which stands for "General Electric Comprehensive Operating System")
username:password:userid:groupid:gecos:home-dir:shell
GECOS are divided as:
:FullName,RoomAddress,WorkPhone,HomePhone,Others:

sally:x:0:529:Sally Jones:/home/myhome:/bin/passwd #might be used on, a Samba fle server or a POP mail server to enable users to change their passwords via SSH without granting login shell access.

