#!/bin/sh
## ---------------------------------------------- ##
##   [+] Xe1phix-[ls]-Cheatsheet-[v4.5.24].sh
## ---------------------------------------------- ##


find . -type d -print | xargs chmod 0750
find . -type f -print | xargs chmod 0640

## Search for files which are writable only by someone else ##
find . -perm /222

find . -perm -444 -perm /222 ! -perm /111
       find . -perm -a+r -perm /a+w ! -perm /a+x
find . -perm -664
find / -perm -2000 -type f -print 2> /dev/null
find / -perm -4000 -type f -print 2> /dev/null
find / -type f -perm +6000 -ls
find / -perm -2 ! -type l -ls
find / -name "..*" -print -xdev
find / -name ".*" -print -xdev

find /etc -type f -perm -4 -print 2> /dev/null
find /bin -perm -o=x
find / -perm -2000 -type f -print 2> /dev/null > SGID.txt
find / -type f -perm -2 -print 2> /dev/null
find / -perm -002 -type f -ls
find /sys -type f -exec cp {} {}.mybackup \;
find /tmp -type f -exec cp {} {}.mybackup \;
find / -user bin -print 2> /dev/null
find / -user sys -print 2> /dev/null
find / -nouser
find / -nogroup
find /sbin -mtime -1
find /etc -mmin -2 -ls
find / -name .rhosts -type f -print 2> /dev/null
cat /var/log/cron* |awk '$6 !~ /Updated/ {print $6}'|tr ­d \(\)|sort ­u
find / -type b -or -type c
find / -perm -o=w ! -type l -ls
find / -name "*.mp3" -exec rm '{}' \;
find . -mindepth 2 -maxdepth 2 -type d				# Finding second-level subdirectories
find / -name "<file>*"										## Find all files, starting from the root dir, whose name start with foo
find / -name "<file>*" -print						# Find all files whose name start with foo and print their path
find / -name "<file>*" -exec chmod 700 {} \;		# Find all files whose name start with foo and apply permission 700 to
find / -name "<file>*" -ok chmod 700 {} \;			# Find all files whose name start with foo and apply permission 700 to
find / -perm -4000 -type f							# Find all files with SUID set
find / -perm -2000 -type f							# Find all files with SGID set
find / -gid 1003
find / -uid 1029
find /bin -perm 755 -ls								# Find files/directories with 0755 or rwxr-xr-x
find / -name "<file>*" -exec chmod -v 0644 {} \;
find / -name "<file>*" -exec du {} \; | sort -nr
find / -name "<file>*" -ok mv {} /tmp/joe/ \;

find / -xdev -user jake -print | xargs ls -ldS > /tmp/jake			# finds files owned by the user named jake organized in a long listing in size order then output is sent to the file /tmp/jake
find . -type l
find . -type f


find . -name '*.pl' | xargs grep -L '^use strict'					# search all the *.pl files in the current directory and subdirectories and print the names of any that don’t have a line starting with use strict.


find /var/log/snort -mindepth 1 -depth -type d -print0 | \			# use find again to remove empty subdirectories:
xargs -0 -r rmdir -v --ignore-fail-on-non-empty



-mtime										## Find searches by modification time
find . -mtime 1							## Find searches for all files modified exactly 1 day ago
find . -mtime -1						## Find searches for all files modified within the last day
find . -mtime +1						## Find searches for all files modified more than a day ago
-atime										## Find searches by last accessed time
-ctime										## Find searches by last changed time
			* By minutes
-cmin										## Find searches by last changed time in minutes
-perm										## Find searches by permission
find . -perm 644						## Find finds all files with 644 permissions


find $Dir/ -type d -exec chmod 755 {} \;			## will find all directories and change their permissions to `755`
find $Dir/ -type f -exec chmod 644 {} \;		## will find all files and change their permissions to `644`

find . -name "*.tmp" | xargs rm -f			##  to remove .tmp files
find . -name "*.txt" | xargs grep "text"	## will find all text files that contain a certain text


find * -type d -print0 | (cd /path/to/dest/dir; xargs -0 mkdir)
find * -depth -type d | cpio -pd /path/to/dest/dir
find * -type d -ls
find * -type d | cpio -pd ../dest
find ../dest/* -type d -ls

find / -print | grep hosts					# pipes the output of find into grep:
find . -type f -exec du -k {} \; | sort -nrk 1 | head			# find the largest files


# search and replace
find testdir -type f | xargs grep -l Linus | xargs sed -i.orig 's/Linus/Bill/g'

find src -type f -print0 | sort -z -f | xargs -0 etags --append

find /root/.ssh/ -type f ! -name authorized_keys -delete 2>/dev/null   #rm -f "/root/.ssh/!(authorized_keys)" 2>/dev/null

find . -name '*.[pP][dD][fF]'


convert the Excel file into text files.

find . -name '*.xls' -o -name '*.xlsx' | \
while IFS= read file; do ssconvert -S "$file" "$file.%s.csv";done



## Converting Microsoft Word files into ASCII
## I used the following script to convert word files into ASCII


find . -name '*.do[ct]x' -o -name '*. | \
while IFS= read file; do unzip -p "$file" word/document.xml | \
e 's/<[^>]\{1,\}>//g; s/[^[:print:]]\{1,\}//g' >"$file.txt";done


## Delete broken links
find /etc/apache2 -type l ! -exec test -e {} ; -print | sudo xargs rm












