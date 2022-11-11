------------------------------------------------------------------------------------------
#in case editing the same file via unix/windows interfaces , formatting problem
sed -i -e 's/\r$//' /vagrant/src/autogen.sh

sed -i 's#ORIGINAL_VALLUE#NEW_VALUE#g' myfile1 myfile2 #replace a string on one or more files
-----------------------------------------------------------------------------------------------------  
sed -e 's/[{}]/''/g' /vagrant/test.json | awk -v k="text" '{n=split($0,a,","); for (i=1; i<=n; i++) print a[i]}'

echo `blkid /dev/sdb1 | awk '{print$2}' | sed -e 's/"//g'` /mnt/disk   xfs   noatime,nobarrier   0   0 >> /etc/fstab

#multiple strings
sed -e '/error/b' -e '/critcial/b' -e d /var/log/apache/nixcraft.com_error_log
sed -n '/yahoo-www/!p' /etc/hosts #show all hosts except yahoo-www
----------------------------------------------------------------------------------------------------- 
sed -ri  '/\s+$/s///' file #looks for whitespace at the end of the line and if present removes it
sed -i 's/\s*$//' file
sed 's/ *$//' file
sed 's/[[:blank:]]*$//' file
sed 's/[[:blank:]]//g' raw_file.txt
sed ':a; N; s/[[:space:]]//g; ta' raw_file.txt
echo -e " \t   blahblah  \t  " | sed 's/^[ \t]*//;s/[ \t]*$//'
#use hexdump to confirm that the sed command is stripping the desired characters correctly
echo -e " \t   blahblah  \t  " | sed 's/^[ \t]*//;s/[ \t]*$//' | hexdump -C
sed 's/^[[:blank:]]*//;s/[[:blank:]]*$//' < file
echo -e " \t   blahblah  \t  " | sed 's/^[[:blank:]]*//;s/[[:blank:]]*$//'
#deletes leading and tailing spaces without touching any spaces between words
$ echo -e "   \t  A   \tB\tC   \t  " | sed 's/^[ \t]*//;s/[ \t]*$//'
----------------------------------------------------------------------------------------------------- 
# displays the comments

sed '/^#/ !d' /etc/resolv.confprint directory structure in the form of a tree
sudo ls -R | grep ":$" | sed -e 's/:$//' -e 's/[^-][^\/]*\//--/g' -e 's/^/   /' -e 's/-/|/'
sed '/^#//' /etc/resolv.confprint # remove lines starting with "#"
sed -i '14,18 s/^/#/' bla.conf #comment lines 2 through 4 of bla.conf
sed -i '14,18 s/^##*//' bla.conf

# displays without comments                                                    
sed '/ *#/d; /^ *$/d' /etc/zabbix/zabbix_server.conffind /home/vagrant | sed -e "s/[^-][^\/]*\// |/g" -e "s/|\([^ ]\)/|-\1/"cat /etc/services | sed 's/#//' | tee servicesaltered | sort > alphaservices
sed '' -> accepts input from the standard input stream

sed -e '1d' -e '2d' -e '5d' books.txt  -> delete three lines, specified three separate commands with -e option.

sed 'N;$!P;$!D;$d' thegeekstuff.txt ->Delete Last 2 Lines of a file
sed '$!N;$!D' thegeekstuff.txt -> Print Last 2 Lines of a file

sed -n '/match/ p' -> grep match

# .e extension backup file,substitute the expression
sed -ie 's/PermitRootLogin yes/#PermitRootLogin yes/' /etc/ssh/sshd_config 
sed -i 's/PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config
sed 's/on/forward/' annoying.txt -> substitute the expression "on" with "forward".
sed 's/on/forward/g' annoying.txt ->  substitute command is changing every instance, the "g" flag
sed 's/on/forward/2' annoying.txt -> change the second instance of "on" that sed finds on each line,
sed 's/SINGING/saying/i' annoying.txt -> search process to ignore case, we can pass it the "i" flag
sed 's/^.*at/REPLACED/' annoying.txt -> match the from the beginning of the line to "at"


CLIENTSCRIPT="foo"
CLIENTFILE="bar
autoboot_delay="-1"

CLIENTSCRIPT="foo"
CLIENTSCRIPT2="hello"
autoboot_delay="-1"
mlx5_load="YES"

sed -e '/autoboot_delay="-1"/a\'$'\n''mlx5_load="YES"' out.txt

sed -i -e '1i\' -e 'HAVE_OPENBLAS = \\usr' ./settings.mk ->add the line at the beginning of file
sed -i -e '$a\' -e 'HAVE_OPENBLAS = \\usr' ./settings.mk ->add the line at the end of file
sed '$ a b01\tBaking powder' products.txt #append the text, “b01 Baking powder” after the last line of the file
sed -i -e '5i\' -e 'HAVE_OPENBLAS = \\usr' ./settings.mk ->add the line as line 5, and shift down subsequent lines
sed -i -e '5c\' -e 'HAVE_OPENBLAS = \\usr' ./settings.mk -> replace line 5 in the file with the new line
sed -i "s/^enabled=1/enabled=0/" /etc/yum.repos.d/wazuh.repo -> Wazuh repository  disabled

sed '2 a b01\tBaking powder' products.txt #append the text, “b01 Baking powder”, after the first two lines of the file
sed '/^s01.*/a b01\tBaking Powder' products.txt #search any line starting with “s01”, and add the new string “b01 Baking powder” after it. 
sed '/Powder$/a b01\tBaking Powder' products.txt #search any line that ends with “Powder” and insert the new line after it.
sed '/^[a-c]/a b01\tBaking Powder\nb02\tBaking Soda' products.txt #two lines will be added after the a-c range
sed '/cream/i b01\tBaking Powder' products.txt #Insert a line after matching a pattern 

#adds one line "ServerName 127.0.0.1" after SearchPattern "#ServerName www.example.com:80"
sed -i '/#ServerName www.example.com:80/aServerName 127.0.0.1' /etc/httpd/conf/httpd.conf
sed '/^anothervalue=.*/a after=me' test.txt # insert a line after the match
sed '/^anothervalue=.*/i before=me' test.txt #insert a line before the match
sed '/^anothervalue=.*/i before=me\nbefore2=me2' test.txt #insert multiple lines before the match
#prepend the lines before the match
sed -i '/pattern/i \
line1 \
line2' inputfile
#append the lines after the match

#some systems don't support \n in sed,insert NEWTEXT after SEARCHPATTERN
printf "/^SEARCHPATTERN/a\nNEWTEXT\n.\nw\nq\n" |\
    /bin/ed $filename

sed -i '/^SEARCHPATTERN$/ s:$:\nNEWTEXT:' FILE #insert NEWTEXT after SEARCHPATTERN

$ echo "I like programming." | sed 's/inng/& Do you like programming?/'

sudo sed -i -e '$a\' -e 'deb http://webmin.mirror.somersettechsolutions.co.uk/repository sarge contrib' /etc/apt/sources.list

# replace "Where = /nonexistant/path/to/file/archive/dir/bacula-restores" with "Where = /bacula/restore"
sudo sed -i 's/Where = \/nonexistant\/path\/to\/file\/archive\/dir\/bacula-restores/Where = \/bacula\/restore/g'  /etc/bacula/bacula-dir.conf.bck
sed -i 's/#Storage.*/Storage=persistent/' /etc/systemd/journald.conf
sed -i 's/check_for_updates=1/check_for_updates=0/g'  /usr/local/nagios/etc/nagios.cfg
sudo sed -i.bck 's/^debug_level=-1/debug_level=0/' /usr/local/nagios/etc/nagios.cfg

sed 's/\bthe\b/this/' -> For each line in a given input file, transform the first occurrence of the word 'the' with 'this' case sensitive. 
sed -e 's/\bthy\b/your/Ig' -> For each line in a given input file, transform all the occurrences of the word 'thy' with 'your'. case insensitive
sed -e 's/thy/{&}/Ig' -> Given an input file, in each line, highlight all the occurrences of 'thy' by wrapping them up in brace brackets . case insensitive

Given lines of credit card numbers, mask the first digits of each credit card number with an asterisk (i.e., *)
Each credit card number consists of four space-separated groups of four digits.
sed 's/\([[:digit:]]\{4\}[[:space:]]\)\{3\}/**** **** **** /'

N lines, each containing a credit card number with the ordering of its segments reversed
sed 's/\([[:digit:]]\{4\}\)[[:space:]]\([[:digit:]]\{4\}\)[[:space:]]\([[:digit:]]\{4\}\)[[:space:]]\([0-9]\{4\}\)/\4 \3 \2 \1/'

mask IP addresses in the log
sed 's/[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}/***.***.***.***/g' /vagrant/access_log

# multiple entry, remove chars
sed -r -e 's/[..]//g' -e 's/[0-9]//g' -e 's/[==]//g' reqcal1.txt
#  lowercase to uppercase.
sed 'y/abcdefghijklmnopqrstuvwxyz/ABCDEFGHIJKLMNOPQRSTUVWXYZ/' text.txt
#uppercase to lowercase.
sed 'y/ABCDEFGHIJKLMNOPQRSTUVWXYZ/abcdefghijklmnopqrstuvwxyz/' text.txt
# 3 character shift
sed 'y/abcdefghijklmnopqrstuvwxyz/defghijklmnopqrstuvwxyzabc/' text.txt
# Remove the last word.
sed -r 's/\d$//g' text.txt
# Remove all letters.
sed -r 's/[a-zA-Z]//g' text.txt
# Remove html tags 
sed -r 's|(</?[a-z]+>)||g' text.txt
# Delete lines from 3 to 5.
sed '3,5d' text.txt
# Delete every lines starting from 3 and skipping by 2.
sed '3~2d' text.txt
sed -n '/Linux/=' filename #Prints the line number that matches the pattern.
sed -n '/#ServerName www.example.com:80/=' /etc/httpd/conf/httpd.conf #matches the pattern "#ServerName www.example.com:80"
sed -n 1,15p /etc/passwd | awk -F":" '{print $1}'
sed -n '5,10p' myfile.txt #return lines 5 through 10 from myfile.txt
sed '20,35d' myfile.txt  #print the entire file to exclude lines 20 through 35 from myfile.txt
sed -n -e '5,7p' -e '10,13p' myfile.txt  #display lines 5-7 and 10-13 from myfile.txt
# replace text, change config
sed 's%SELINUX=enforcing%SELINUX=disabled%g' /etc/sysconfig/selinux
sed 's%192.168.18%192.168.13%' iplist.txt
# add text, change config
sudo sed -i 's%allowed_hosts=127.0.0.1,::1%allowed_hosts=192.168.18.16,127.0.0.1,::1%g' /etc/nagios/nrpe.cfg
-----------------------------------------------------------------------------------------------------
#escaping characters
/ (to close the clause)
\ (to escape characters, backreference, &c.)
& (to include the match in the replacement)

KEYWORD="WorkDir: /var/www/mrtg/"
REPLACE="WorkDir: /var/www/html/mrtg/"
sudo sed -i 's/^WorkDir: \/var\/www\/mrtg/WorkDir: \/var\/www\/html\/mrtg/' /etc/mrtg.cfg

sudo sed -i.bck 's/^WorkDir: \/var\/www\/mrtg/WorkDir: \/var\/www\/html\/mrtg/' /etc/mrtg.cfg #creates backup file
stat /etc/mrtg.cfg.bck
-----------------------------------------------------------------------------------------------------
sed -i -e '/CSE/! s/Count/80/;' dept.txt #replace the ‘Count’ value in the line that does not contain the text, ‘CSE’. dept.txt file
-----------------------------------------------------------------------------------------------------
