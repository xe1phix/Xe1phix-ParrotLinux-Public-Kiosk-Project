
 Generate SHA1 hash for each file in a list 
ls [FILENAME] | xargs openssl sha1


cat list.txt | awk '{gsub("https://","https://USERNAME:PASSWORD@",$0);print $0}' | xargs -P 2 -IXXX sh -c 'git clone XXX' # awk置換版
cat list.txt | sed 's/https:\/\//https:\/\/USERNAME:PASSWORD@/' | xargs -P 2 -IXXX sh -c 'git clone XXX' # gsed置換版




# Find tutorial;
# http://www.grymoire.com/Unix/Find.html

# find files modified less than 5 days ago
$ find . -type f -mtime -5 -print | xargs ls -l

# find files (with spaces in name) modified less than 5 days ago 
$ find . -type f -mtime -5 -print0 | xargs -0 ls -l

# find & remove directories older than 200 days
$ find . -type d -mtime +200 -print | xargs rm -rf
# or
$ for i in `find /dir -type d -mtime +200 -print`; do echo -e "Deleting directory $i";rm -rf $i; done

# find and replace text in multiple files
$ find . -type f -exec sed -i -e 's/old-string/new-string/g' {} \;

# find and copy files
find . -name '*.tif' -type f -exec cp {} /data/geoserver/data/raster/ \;




find . -name "*.sh"| xargs rm -rf
find . -name "*.sh"| xargs rm -rf
find . -name "*.sh" -print0 | xargs -0 rm -rf
find /tmp -name "*.tmp"| xargs rm
ls | xargs -p -l gzip
find . -name "*.pl" | xargs tar -zcf pl.tar.gz
ls | sed -e "p;s/.txt$/.sql/" | xargs -n2 fmv
ls | xargs -I FILE mv {} <...>-{}
find . -group root -print | xargs chown temp
find . -group root -print | xargs chgrp temp
find /tmp -type f -name '*' -mtime +7 -print0 | xargs -0 rm -f
find /proc -user myuser -maxdepth 1 -type d -mtime +7 -exec basename {} \; | xargs kill -9
cut -d: -f1 < /etc/passwd | sort | xargs echo
find . -type f -printf '%20s %p\n' | sort -n | cut -b22- | tr '\n' '\000' | xargs -0 ls -laSr
echo dir1 dir2 dir3 | xargs -P 3 -I NAME tar czf NAME.tar.gz NAME 
wget -nv https://habrahabr.ru/company/selectel/blog/248207 | egrep -o "http://[^[:space:]]*.jpg" | xargs -P 10 -n 1 wget -nv 
xargs -I FILE my_command “FILE”
find . -type f -and -iname "*.deb" | xargs -n 1 dpkg -I
cat bad_ip_list | xargs -I IP iptables -A INPUT -s IP -j DROP
/usr/bin/whois -H -h whois.ripe.net -T route -i origin AS<номер>|egrep "^route"|awk '{print $2}' |xargs -I NET iptables -A INPUT -s NET -j DROP 
tr -dc A-Za-z0-9_ < /dev/urandom | head -c 10 | xargs
сat /var/lib/dpkg/info/*.list > /tmp/listin ; ls /proc/*/exe |xargs -l readlink | grep -xvFf /tmp/listin; rm /tmp/listin
dpkg -l linux-* | awk '/^ii/{ print $2}' | grep -v -e `uname -r | cut -f1,2 -d"-"` | grep -e [0-9] | xargs sudo apt-get -y purge
(sed 's/#.*//g'|sed '/^ *$/d'|tr '\n' ';'|xargs echo) < script.sh



# Remove all the sound related kernel modules
lsmod | grep snd | awk '{print $1}' | sudo xargs rmmod

# Find the ISPs of everyone who logged into your server
grep -o -E "Accepted publickey for .*" /var/log/auth.log | awk '{print $6}' | xargs -n1 whois | grep org-name

# Download all the Zed Shaw sessions and play them one after another
curl -s zedshaw.com/sessions/ | grep -o -P "http://zedshaw.music.s3.amazonaws.com/.*?.ogg" | xargs curl -s | ogg123 -

# Download all the Zed Shaw sessions, 6 *concurrently at a time* and play them *concurrently* creating a crazy mashup
curl -s zedshaw.com/sessions/ | grep -o -P "http://zedshaw.music.s3.amazonaws.com/.*?.ogg" | xargs -P 6 -n 1 curl -s | ogg123 -





# 1.) pipe list of images to xargs
# 2.) construct URL for each image
# 3.) download files in parallel 
cat images.txt | xargs -I img -P 0 wget -O img "http://fillmurray.com/222/"img



#list the file opened by process-id
ps aux | grep 'index.js' | grep -v 'grep' | awk '{ print $2 }' | xargs -I {} sh -c "lsof -p {}"

#list the file opened by process other than specified pid
ps aux | grep 'index.js' | grep -v 'grep' | awk '{ print $2 }' | xargs -I {} sh -c "lsof -p ^{}"

# list network services by process-id
ps aux | grep 'index.js' | grep -v 'grep' | awk '{ print $2 }' | xargs -I {} sh -c "lsof -i | grep {}"




find . -name '*.py' | xargs wc -l





Move all backup files somewhere else;

find . -name '*~' -print 0 | xargs -0 -I % cp % ~/backups

Parallel sleep:
time echo {1..5} | xargs -n 1 -P 5 sleep

real    0m5.013s
user    0m0.003s
sys     0m0.014s


Sequential sleep:
time echo {1..5} | xargs -n 1 sleep
real    0m15.022s
user    0m0.004s
sys     0m0.015s






