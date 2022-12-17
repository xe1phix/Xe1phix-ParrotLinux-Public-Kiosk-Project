#!/bin/sh


find . -name "$Name*"
find . -name "[a-z]*.*"
find . -size +5M
find . -size -5M
find . -type l
find . -type d


find . -atime +5		# Acess Time
find . -ctime +5		# Changed Time
find . -mtime +5		# Modification Time


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
find / -name "<file>*" 								# Find all files, starting from the root dir, whose name start with foo
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


# Check all bash scripts in current dir for syntax errors
find . -name '*.sh' -exec bash -n {} \;


# Remove all zero size files from current directory (not recursive)
find . -maxdepth 1 -empty -delete

# Move all files in subdirectories to current dir
find ./ -type f -exec mv {} . \;



Find and copy files

find / -iname "passw" -print0 | xargs -I {} cp {} /new/path
find / -iname "passw" | xargs -I {} cp {} /new/path



# Find jpeg images and copy them to a central location
find . -iname "*.jpg" -print0 | tr '[A-Z]' '[a-z]' | xargs -0 cp --backup=numbered -dp -u --target-directory {location} &



##-======================================-##
##   [+]
##-======================================-##
find / iname "*.mp3"
find / -iregex '.*\.\(mp3\|ogg\|wav\)$'
find ~ -iname ".mp3"
find ~/mp3/ -iname '*.mp3' -exec mv "{}" /tmp/ \;


##-========================================================================-##
##   [+] Print a list of the 30 last modified mp3s sorted by last first
##-========================================================================-##
find ~/$Dir -daystart -mtime -60 -name *mp3 -printf "%T@\t%p\n" | sort -f -r | head -n 30 | cut -f 2


# find broken symbolic links
find -L . -type l

# Find all symlinks that link to directories
find -type l -xtype d

# Rename .JPG to .jpg recursively
find /path/to/images -name '*.JPG' -exec rename "s/.JPG/.jpg/g" \{\} \;

# Copy all documents PDF in disk for your home directory
find / -name "*.pdf" -exec cp -t ~/Documents/PDF {} +


# recursive reset file/dir perms
find public_html/stuff -type d -exec chmod 755 {} + -or -type f -exec chmod 644 {} +


# Search through files, ignoring .svn
find . -not \( -name .svn -prune \) -type f -print0 | xargs --null grep <searchTerm>




