egrep -I -i -r '\$(\{|%7B)jndi:(ldap[s]?|rmi|dns|nis|iiop|corba|nds|http):/[^\n]+' /var/log
find /var/log/ -type f -exec sh -c "cat {} | sed -e 's/\${lower://'g | tr -d '}' | egrep -I -i 'jndi:(ldap[s]?|rmi|dns|nis|iiop|corba|nds|http):'" \;
find /var/log/ -name '*.gz' -type f -exec sh -c "zcat {} | sed -e 's/\${lower://'g | tr -d '}' | egrep -i 'jndi:(ldap[s]?|rmi|dns|nis|iiop|corba|nds|http):'" \;
#searches for exploitation attempts in compressed files in folder /var/log and all sub folders
find /var/log -name \*.gz -print0 | xargs -0 zgrep -E -i '\$(\{|%7B)jndi:(ldap[s]?|rmi|dns|nis|iiop|corba|nds|http):/[^\n]+'

#files starting at the current directory (.) and that up to a maximum of 1 level of subdirectories
find . -maxdepth 2 -type f -name file.txt | xargs -I{} cat {} > ./total_file.txt

#Get total size of a list of files
perl -le 'map { $sum += -s } @ARGV; print $sum' -- *.pdf #Size of all non-hidden PDF files in current directory.

#list files between 1st Dec 2021 and 1st Jan 2022 and total size of each file
find . -type f -newermt 2012-01-01 ! -newermt 2022-01-01 -exec du -sh {} \;
find . -type f -newermt 2012-01-01 ! -newermt 2022-01-01 -exec ls -lt {} \; | sort -k6M -k7n #sorting month & date based
find . -name 'flibble*' -ctime +90 -exec du -sh {} \;

find . -type f -mmin -5 -print0 | xargs -0 /bin/ls -ltr #which files was modified in last 5 minutes
find . -type f -mmin -5 -exec ls -ltr {} +
find . -mmin -5 -exec ls -ltrd {} + #not limiting to files

#list files between 1st Dec 2021 and 1st Jan 2022 and grand total size of each found files, not sum of total sizes
"find . -name "*.tar" -type f -newermt 2012-01-01 ! -newermt 2022-01-01 -exec du -sch {} +"
find . "*.tar" -type f -newermt 2012-01-01 ! -newermt 2022-01-01 -exec du -sch {} + | tail -1 #only total
find . -name "*.tar" -type f -newermt 2012-01-01 ! -newermt 2022-01-01 -exec du -sch {} + | tail -1 | awk '{print $1}'

$ find . -size +2G #search for all files greater than 2 Gigabytes
$ find . -size -10k #search for all files with less than 10 Kilobytes
$ find . -size +10M -size -20M #search for files greater than 10MB but smaller than 20MB
$ sudo find /var -size +5M -exec ls -sh {} + #search for files in /etc directory which are greater than 5MB and print file size
$ find . -type f -exec ls -s {} + | sort -n -r | head -3 #Find first 3 largest files located in a in a current directory recursively
$ find /etc/ -type f -exec ls -s {} + | sort -n | head -3 #Find first 3 smallest files located in a in a current directory recursively
$ find . -type f -size 0b # search for empty files
$ find . -type f -empty # search for empty files

$ sudo find /var/log -name \*.log -size +1M -exec ls -lrt {} \; # find files larger than 1M,`M'    for Megabytes (units of 1048576 bytes)
$ sudo find /var/log -name \*.log -size +1M -exec ls -lrt {} \; | wc -l #get count
$ sudo find /var/log -name \*.log -size +1M -exec ls -lrt {} \; | awk '{ total += $5 }; END { print total }' # get total size, column 5(size) of ls command, 

#total size of all found files
$ sudo find /var/log -name \*.log -size +1M -exec ls -l {} \; | awk '{ sum += $5} END  \
{hum[1024^3]="Gb"; hum[1024^2]="Mb"; hum[1024]="Kb"; for (x=1024^3; x>=1024; x/=1024) { if (sum>=x) { printf "%.2f %s\n",sum/x,hum[x]; break; } } if (sum<1024) print "1kb"; }'


$ find /var/log/apt -type f -name "*.dat" -size +100M #list files larger than 100M

$ find /var/log/apt -iname *.log -print0 | xargs -r0 du -csh | tail -n 1; # -iname case insensitive
$ find /var/log/apt -iname *.log -exec ls -lh {} \;

$ find /var/log/apt -name *.log -size +10c -print0 | du -c --files0-from=- | awk 'END{print $1}'
$ find /var/log/apt -name *.log -size +10c -print0 | du -ch --files0-from=- | awk 'END{print $1}'
$ find /var/log/apt -name *.log -size +10c -print0 | du -ch --files0-from=- --total -s|tail -1 #xargs pipe "|" calls du command many times
$ find /var/log/apt -name *.log -type f -exec ls -s \; | awk '{sum+=$1;} END {print sum/1000;}' #excludes all directories
du -ch /var/log/apt | tail -1 | cut -f 1

$ (find /var/log/apt -name *.log -size +10c -printf '%s+'; echo 0 ) | bc
$ ( find /var/log/apt -name *.log -size +10c -printf 's+=%s\n'; echo s ) | bc

$ find /var/log/apt -name *.log -size +10c -printf '%s\n' | jq -s add
$ find /var/log/apt -name *.log -size +10c -exec stat -c%s '{}' + | jq -s add

find . -name "*.tar" -type f -newermt 2012-01-01 ! -newermt 2022-01-01 -print0 | xargs -0 du -c --block-size=human-readable
find . -name 'flibble*' -ctime +90 -print0 > filenames && du -shc --files0-from=filenames
du -c `find . -name 'flibble*' -ctime +90` | tail -1
find . -name 'flibble*' -ctime +90 -printf "%s\n" |perl -lnE '$sum += $_} END {say $sum'
find . -name 'flibble*' -ctime +90 -printf "%s\t%p\n" |perl -apE '$sum += $F[0]} END {say $sum'
echo "$(( ($(find . -name 'flibble*' -ctime +90 -type f -printf '%k+' )0)/1024/1024 )) GB"

#-mtime +7 means older than 8 days (age rounded to integer number of days greater than 7). 
log_history=13 && find /opt/freeswitch/var/log/freeswitch -type f -mtime +$log_history -delete #Delete old/rotated log files
# if tomcat directory exists,delete logs
log_history=13 && [[ -d /var/log/tomcat7 ]] && find /var/log/tomcat7 -type f -mtime +$log_history -delete 
#Delete FreeSWITCH wav/opus recordings older than 13 days
history=13 && find /var/freeswitch/meetings/ -name "*.wav"  -mtime +$history -delete

# find all files, SUID bit enabled
find / -perm -4000 -exec ls -l {} \;
find /usr/bin/ -perm -4000 -exec ls -l {} \;
find /bin/ -perm -4000 -exec ls -l {} \;
find / -xdev -perm -4000 2>/dev/null

#-perm denotes that we will search for the permissions that follow:
#-u=s denotes that we will look for files which are owned by the root user
#-type states the type of file we are looking for
#f denotes a regular file, excluding directories and special files
find / -perm -u=s -type f 2>/dev/null


find / -uid 0 –perm -4000 -print #find all programs whose SetUID is set to run as root
find / -perm -2000 -exec ls -l {} \; # find all files, SGID bit enabled

find /lib/modules/`uname -r` -type f -name '*quota_v*.ko*'

#counts files recursively in all subfolders in the specified folder
find /data -type f | wc -l
#counts files in the current dir, not recursively
find /data -maxdepth 1 -type f | wc -l
#counts folders recursively in all subfolders in the specified folder
find /data -type d | wc -l

find -type f -exec md5sum -t {} \; | cut -d ' ' -f 1 | sort | md5sum #compute checksum

find . -type f -newermt 2012-02-01 ! -newermt 2022-01-01 #between 1st Dec 2021 and 1st Jan 2022
find . -type f -newermt 2012-02-01 ! -newermt 2022-01-01 -ls #list files between 1st Dec 2021 and 1st Jan 2022
find . -type f -newermt 2012-02-01 ! -newermt 2022-01-01 -exec echo {} \; #test before delete
find . -type f -newermt 2012-02-01 ! -newermt 2022-01-01 -exec rm -rf {} \; #delete between 1st Dec 2021 and 1st Jan 2022
find . -type f -newermt 2012-01-01 ! -newermt 2022-01-01 -exec ls -l {} \;

#never put the -delete action at the first position
#If the -delete action is at the first position, during its evaluation, it deletes the given directory and everything in it
#the -delete action implies the -depth option
#The -depth option asks the find command to search each directory’s contents before the directory itself. 
# -delete as the first option, it starts deletion from each directory tree’s very bottom
$ find test -delete -type d -name '.git' # the test directory has been deleted
$ ls test
ls: cannot access 'test': No such file or directory

#the -delete action cannot delete a non-empty directory recursively, can only delete files and empty directories

find test -depth -type d -name '.git' -exec rm -r '{}' \; #remove all .git directories 
find test -type d -name '.git' | xargs rm -r #remove all .git directories 
find ~/Downloads/ -empty -type d -delete #delete all empty directories
find /path/ -empty -type d | wc -l ## count empty dirs only ##
find /path/to/dir/ -type d -empty -print0 | xargs -0 -I {} /bin/rmdir "{}" #find and delete all empty directories
find /path/to/dir -type d -empty -print0 -exec rmdir -v "{}" \; #find and delete all empty directories,slow due to -exec
$ sudo find /var -type d -empty -mtime +50
$ sudo find /var -type d -empty -mtime +5 -exec sh -c 'du -sch' sh {} +

#-exec with an external command, it fills each found file in the ‘{}’ placeholder
find test -name 'whatever.txt' -exec rm {} \; #remove all whatever.txt files
find test -name 'whatever.txt' | xargs rm #remove all whatever.txt files
find ~/Downloads/ -empty -type -f -delete #delete all empty files
find /path/ -empty -type f | wc -l ## count empty files only ##

find /path/to/dir/ -type f -empty -print0 | xargs -0 -I {} /bin/rm "{}" #delete all empty files
find /path/to/dir/ -type f -empty -print0 -exec rm -v "{}" \; #delete all empty files,slow due to -exec

find / -name .DS_Store -delete #-delete will perform better because it doesn't have to spawn an external process for each and every matched file
find / -name ".DS_Store" -exec rm {} \; #recommended because -delete does not exist in all versions of find
find / -iname "*~"  -exec rm -i {} \; # gives an interactive delete
find / -name .DS_Store -exec rm {} + #The command termination + instead of \; highly optimizes the exec clause by not running the rm command for each and every .DS_Store present on the file system
find / -name .DS_Store -print0 | xargs -0 rm #avoiding the overhead of spawning an external process for each matched file

find . -type f -newermt 2012-01-01 ! -newermt 2022-01-01 -exec du -sh {} \;#list files between 1st Dec 2021 and 1st Jan 2022 and total size

#-delete does not delete empty directories
$ find /path/to/dir/ -type d -name ".TemporaryItems" -delete
find: cannot delete ‘./.TemporaryItems’: Directory not empty
$ find /path/to/dir/ -type d -name ".TemporaryItems" -exec rm -rv "{}" +

find /home -group ftpusers # list file owned by a user or group
find /data/project -group ftpusers -name "*.c" # list file owned by all *.c file belongs to a group called “ftpusers
find /data/project -group ftpusers -name "*.c" # list file owned by all *.c file belongs to a group called “ftpusers ,case insensitive
find $HOME -name "*.mp4" -group pedro -ls #list file in ls command format pass the -ls
find /var -user pedro
find /var/www -user pedro -name "*.pl" # find all *.pl (perl files) file belongs to a user
find / -type f -user bonnie -o -user clyde #find files by users bonnie and clyde
find / -type d -user vivek -o -user wendy #find dirs  by users bonnie and clyde

find test -type d -name '.git' # list git directories
find . -type d -newermt 2012-02-01 ! -newermt 2022-01-01 -ls #list directories between 1st Dec 2021 and 1st Jan 2022
find . -type d -newermt 2012-03-22 ! -newermt 2022-03-24 -exec echo {} \; #test before delete
find . -type d -newermt 2012-02-01 ! -newermt 2022-01-01 -exec rm -rf {} \; #delete directories between 1st Dec 2021 and 1st Jan 2022

find /dir/ -type f -newerXY 'yyyy-mm-dd'
The letters X and Y can be any of the following letters:
    a – The access time of the file reference
    B – The birth time of the file reference
    c – The inode status change time of reference
    m – The modification time of the file reference
    t – reference is interpreted directly as a time

find . -type f -newerat 2017-09-25 ! -newerat 2017-09-26 #all files accessed on the 25/Sep/2017
find /home/you -iname "*.c" -atime 30 -type f  #all *.c file accessed exactly 30 days ago
find /home/you -iname "*.c" -atime -30 -type f #all *.c file accessed 30 days ago, not older than 30 days
find /home/you -iname "*.c" -atime -30 -type f -ls
find /home/you -iname "*.c" -atime +30 -type f #all *.c file accessed more than 30 days ago, older than 30 days
find /home/you -iname "*.c" -atime +30 -type f -ls
