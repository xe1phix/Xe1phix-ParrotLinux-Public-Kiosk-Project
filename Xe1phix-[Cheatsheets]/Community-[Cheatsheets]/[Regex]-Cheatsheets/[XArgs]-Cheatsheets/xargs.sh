#source https://habrahabr.ru/company/selectel/blog/248207

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
