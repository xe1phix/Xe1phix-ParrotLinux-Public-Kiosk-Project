# displays without comments                                                    
egrep -v "^#|^$" /etc/zabbix/zabbix_server.conf
-----------------------------------------------------------------------------------------------------
#r = recursive i.e, search subdirectories within the current directory
#n = to print the line numbers to stdout
#i = case insensitive search
grep -rni "string" * 
grep -rni "apache /etc/cron.d"

#string search current and subfolders
$ grep -rl "900990" .
./.crs-setup.conf.swp
./crs/crs-setup.conf
./crs-setup.conf

# displays the comments
grep ^# /etc/resolv.conf

# displays without comments                                                    
grep ^[^#] /etc/resolv.confprint directory/file structure in the form of a tree
grep ^[^\;] /etc/resolv.conffind . | sed -e "s/[^-][^\/]*\// |/g" -e "s/|\([^ ]\)/|-\1/"
grep -v "^#" /etc/zabbix/zabbix_server.conf | grep -v "^$"sed '' quote.txt -> display the contents of the file

# search multiple strings, words
grep 'string1' filename | grep 'string2' #search two strings in one line 
grep -n 'string1' filename | grep 'string2' #search two strings in one line and print line numbers
grep 'string1.*string2\|string2.*string1' filename #search two strings in one line 
grep -n 'string1.*string2\|string2.*string1' filename #search two strings in one line and print line numbers
grep -E "string1(?.*)string2" file #search two strings in one line 
grep -nE "string1(?.*)string2" file #search two strings in one line and print line numbers

#Grep for Multiple Strings
grep 'wordA*'\''wordB' *.py ### Search all python files for 'wordA' or 'wordB'
grep 'word*' *.txt ### Search all text files
grep 'word1\|word2\|word3' /path/to/file
grep 'warning\|error\|critical' /var/log/messages
grep -e 'warning\|error\|critical' /var/log/messages
egrep -wi --color 'warning|error|critical' /var/log/messages #-i (ignore case)
egrep -wi --color 'foo|bar' /etc/*.conf
egrep -Rwi --color 'foo|bar' /etc/ #including sub-directories
egrep -w 'warning|error|critical' /var/log/messages
grep -w 'warning\|error\|critical' /var/log/messages

egrep -ne 'null|three' #search multiple string and output line numbers 

grep -o "0x[^']*" file.txt # matching text starting with "0x"
grep "zip$" #filters the lines that end in zip

grep -r --include "*.jar" JndiLookup.class / #Detect the presence of Log4j 

grep --color regex filename #Highlight
grep --color ksh /etc/shells
grep -o regex filename #Only The Matches, Not The Lines
egrep "v{2}" filename #Match a character “v” two times
egrep 'co{1,2}l' filename #match both “col” and “cool” words
egrep 'c{3,}' filename #match any row of at least three letters ‘c’
grep "[[:digit:]]\{2\}[ -]\?[[:digit:]]\{10\}" filename #match mobile number format 91-1234567890
egrep '[[:digit:]]{1,3}\.[[:digit:]]{1,3}\.[[:digit:]]{1,3}\.[[:digit:]]{1,3}' file #match an IP address,All three dots need to be escaped

$ grep '^[P-R]' list.txt #lines from list.txt file that starts with P or Q or R
$ grep '[^A-C]' list.txt #lines from list.txt file that starts with A or B or C

$ grep [!P-R] list.txt #from list.txt file that starts with ‘P’ or Q or R
$ grep [!4-8] list.txt #lines from list.txt file that starts with any digit from 4 to 8.

$ grep a$ list.txt #lines from list.txt file that ends with ‘a’
$ grep 50$ list.txt #lines from list.txt file that end with the number 50

grep -i "boar" /etc/passwd #Perform a case-insensitive search for the word ‘bar’

grep "Gnome Display Manager" /etc/passwd #If the search string includes spaces, enclose it in single or double quotation marks

#the string “linux” will match only if it occurs at the very beginning of a line
grep '^linux' file.txt #The ^ (caret) symbol 
grep 'linux$' file.txt #lines end with linux string
grep '^linux$' file.txt #lines contain only linux string
grep '^\.[0-9]' filename #lines starting with a dot and digit
grep '^..$' filename #lines with  two characters

#The . (period) symbol is a meta-character that matches any single character
grep 'kan..roo' file.txt #match anything that begins with “kan” then has two characters and ends with the string “roo”
grep 'acce[np]t' file.txt #find the lines that contain “accept” or “accent”
grep 'co[^l]a' file.txt #match any combination of strings starting with “co” followed by any letter except “l” followed by “la”, such as “coca”, “cobalt” and so on
grep '^[A-Z]' file.txt #matches each line that starts with a capital letter

grep 's*right' #match “right”, “sright” “ssright” and so on
grep -E '^[A-Z].*[.,]$' file.txt #matches all lines that starts with capital letter and ends with either period or comma

grep 'b\?right' file.txt #match both “bright” and “right”. The ? character is escaped with a backslash because we’re using basic regular expressions
grep -E 'b?right' file.txt

grep -E 's+right' file.txt #match “sright” and “ssright”, but not “right”
grep -E '[[:digit:]]{3,9}' file.txt #matches all integers that have between 3 and 9 digits

grep 'word' filename
grep 'word' file1 file2 file3
grep -i "boar" /etc/passwd #Perform a case-insensitive search for the word ‘bar’
"grep -R 'httpd' ." #Look for all files in the current directory and in all of its subdirectories
grep -r "192.168.1.5" /etc/ #search recursively i.e. read all files under each directory for a string “192.168.1.5”
grep -c 'nixcraft' frontpage.md #display the total number of times that the string ‘nixcraft’ appears in a file named frontpage.md

#Grep NOT
#-v flag to print inverts the match; that is, it matches only those lines that do not contain the given word
grep -v -c -e "that" ->  find out how many lines that does not match the pattern
grep -v Sales employee.txt #all the lines except those that contains the keyword “Sales”

grep -w "the" -> Output only those lines that contain the word 'the'.
grep -iw "the" -> Output only those lines that contain the word 'the'. The search should NOT be case sensitive.
grep -viwe "that" -> Only display those lines that do NOT contain the word 'that'.
grep -Eiw "th(e|ose|en|at)" < /dev/stdin -> display all those lines which contain any of the following words "the,that,then,those" .The search should not be sensitive to case. Display only those lines of an input file, which contain the required words.  
grep '\([0-9]\) *\1' -> Given an input file, with N credit card numbers,grep out and output only those credit card numbers which have two or more consecutive occurences of the same digit (which may be separated by a space, if they are in different segments). Assume that the credit card numbers will have 4 space separated segments with 4 digits each

#top 10 IP addresses in the log file.
grep -E -o "([0-9]{1,3}[\.]){3}[0-9]{1,3}" access.log | uniq -ci | sort -nr | head -n10

ifconfig -a | grep -E -o "([0-9]{1,3}[\.]){3}[0-9]{1,3}" | awk 'ORS=NR%2?" , ":"\n"'
ip addr show eth1 | grep inet | awk '{ print $2; }' | sed 's/\/.*$//'
ifconfig -a | grep -E -o "([0-9]{1,3}[\.]){3}[0-9]{1,3}"

#list process binary path and permissions
ps aux | awk '{print $11}' | xargs -r ls -la 2>/dev/null |awk '!x[$0]++'
ps -elf | grep autofs | grep -v grep  | awk '{print $4}' | xargs kill -9 

######group expressions,grep -E option is for extended regexp,three expressions are functionally equivalent
grep "\(grouping\)" file.txt #use parentheses without using extended regular expressions, escape with the backslash
grep -E "(grouping)" file.txt
egrep "(grouping)" file.txt

grep -E "(GPL|General Public License)" GPL-3 #find either GPL or General Public License in the text
grep -E "(copy)?right" GPL-3 #matches copyright and right by putting copy in an optional group
grep -E '(fear)?less' file.txt #matches both “fearless” and “less”. The ? quantifier makes the (fear) group optional
grep -E "free[^[:space:]]+" GPL-3 # matches the string free plus one or more characters that are not white space characters
grep -E "[AEIOUaeiou]{3}" GPL-3 #find all of the lines in the GPL-3 file that contain triple-vowels
grep -E "[[:alpha:]]{16,20}" GPL-3 #match any words that have between 16 and 20 characters

grep -e pattern1 -e pattern2 filename #Grep OR Using grep -e,
egrep 'Tech|Sales' employee.txt #Grep OR Using egrep
grep 'Tech\|Sales' employee.txt #Grep OR Using \|,grep either Tech or Sales from the employee.txt file
grep 'fatal\|error\|critical' /var/log/nginx/error.log
grep -E 'fatal|error|critical' /var/log/nginx/error.log # use the extended regular expression, then the operator | should not be escaped
grep -E 'Tech|Sales' employee.txt #Grep OR Using -E

#Grep AND
grep Manager employee.txt | grep Sales #all the lines that contain both “Manager” and “Sales” in the same line
grep -E 'Dev.*Tech' employee.txt #all the lines that contain both “Dev” and “Tech” in it (in the same order).
grep -E 'Manager.*Sales|Sales.*Manager' employee.txt #all the lines that contain both “Manager” and “Sales” in it (in any order)
-----------------------------------------------------------------------------------------------------
