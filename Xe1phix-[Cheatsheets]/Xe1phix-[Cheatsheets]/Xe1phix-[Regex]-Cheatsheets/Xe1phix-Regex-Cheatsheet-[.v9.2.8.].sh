#!/bin/sh

## =========================================================================================================== ##
##  • 0). Standard input (STDIN)			|| Input stream		|| By default attached to the keyboard.
##  • 1). Standard output (STDOUT)	|| Output stream	|| Normal program output. By default, this is the screen.
##  • 2). Standard error (STDERR)		|| Output stream	|| Meant for error messages. By default, this is the screen.
## =========================================================================================================== ##


_______,_____,____________________________
 Signal	 | Num |  Meaning
_______|_____|____________________________
 HUP	|	  1 	|  Hangup, reread config		||
 INT		|	  2 	|  Interrupt, stop run			||
 KILL	|	  9		|  Exit immediately				||
 TERM	|	15		|  Terminate nicely				||
 TSTP	|	20		|  Stop executing					||
======================================


##-==========================================================-##
		|| Cmd 2>&1		|| Redirect Both output and errors to file			||
		|| Cmd 2>			|| Redirects error output.									||
		|| Cmd 1>>		|| Redirect and append stdout to file.					||
		|| Cmd &>		|| Redirect both stdout and stderr to file.			||
		|| Cmd 1>&2		|| Redirect Standard output to standard error.	||
		|| Cmd >&		|| Redirect both stdout and stderr to file.			||
		|| Cmd >>&		|| Append both stdout and stderr to file.			||
##-============================================================-##
		|| Cmd >file 2>&1				|| Redirects stderr to stdout then to file.		|| 
		|| Cmd1 | Cmd2				|| Pipe stdout to cmd2									||
		|| Cmd1 |& Cmd2				|| Pipe stdout and stderr to cmd2					||
		|| Cmd1 2>&1 | Cmd2		||	Pipe stdout and stderr to cmd2					||
##-============================================================-##



##-==========================================================-##
##										[+] Comparison Operators 
##-==========================================================-##
 ||  =~	||	Matching regular expression.				[regex]																		||
 ||   !~	||	Not matching regular expression.		[regex]																		||
 ||    =	||	Equal to. 												[number, size, percent, string, string list]				||
 ||	  !=	||	Not equal to.										[number, size, percent, string, string_list]			||
 || >=	||	Greater than or equal to.					[number, size, percent]											||
 ||	   >	||	Greater than.										[number, size, percent]											||
 || <=	||	Less than or equal to.							[number, size, percent]											||
 ||    <	||	Less than.											[number, size, percent]											||
##-==========================================================-##												  		  ####






 ||    $0  || The name of the script itself (script.sh)
 ||    $1  || The first argument (filename1)
 ||    $2  || The second argument (dir1)
 ||    $9  || The ninth argument
 || ${10} || The tenth argument and must be enclosed in brackets after $9.
 || ${11} || The eleventh argument.


declare -r $Variable
declare -r $Variable=$Value


set -o								## List currently configured shell options
set -o $Variable				## set shell variable option
set +o $Variable				## set shell variable option

shopt -p							## view a list of the currently configured options

shopt -s $Variable			## enable (set) each option
shopt -u $Variable			## disable (unset) each option

# Turn on the extended pattern matching features 
shopt -q -s extglob

# Append rather than overwrite history on exit
shopt -s histappend


histappend
restricted_shell

export -p			## display a list of all exported variables and functions



## ========================================================== ##
echo $!				# process id of last background command
echo $SHELL			# Default shell used
## ========================================================== ##

## ========================================================== ##
$$              # The current process ID 
$?              # exit status of last command 
## ========================================================== ##
!n     			# Refer to command line n.
!123			# execute the 123rd command inside bash history
!!				# execute the last command inside bash history
!!:gs/hda/sda	# prevous command, replacing hda with sda
!!:s/one/two	# prevous command, replacing the first insidance of one with two
"!$"			# represents the last argument of the prevous command
!ssh			# execute the last command that started with ssh
## =================================================================================== ##




$?			# show the status of the last command which was run
=============
0	# Successful
1	# Failed
2	# Synatx error



||?<exp>|| Match zero or one instance of patter n.
||*<exp>|| Match zero or more instances of patter n.
||+<exp>|| Match one or more instances of patter n.
||@<exp>|| Match exactly one instance of patter n.
||!<exp>|| Match any strings that don’t match patter n.


||; || Command separator
||& || Background execution
||()||	Command grouping




## ==================== ##
||  	  ! cmd		    || NOT; execute cmd, and produce a zero exit status if cmd exits with a nonzero status. Other wise, produce a nonzero status when cmd exits with a zero status.
||		cmd1 | cmd2		|| Pipe; use output from cmd1 as input to cmd2.
||		cmd1 ; cmd2		|| Command sequence; execute multiple cmds on the same line.
||		cmd1 && cmd2    || AND; execute cmd1 and then (if cmd1 succeeds) cmd2. This is a “shor t circuit” operation: cmd2 is never executed if cmd1 fails.
||		cmd1 || cmd2    || OR; execute either cmd1 or (if cmd1 fails) cmd2. This is a “short Circuit” operation; cmd2 is never executed if cmd1 succeed
||		cmd1 ‘ cmd2 ‘   || Command substitution; use cmd2 output as arguments to cmd1.
||     cmd1 $( cmd2 )   || POSIX shell command substitution; nesting is allowed.
||	  ( cmd1 ; cmd2 ) 	|| Execute commands as a group in a subshell.
||	 { cmd1 ; cmd2 ; }  || Execute commands as a group in the current shell.
||	 cmd $(( express )) || POSIX shell arithmetic substitution. Use the result of expression as argument to cmd.
## ==================== ##





|| <command>; ||				## command separator

||  (.)  ||				## execute commands in subshell
||	{.} ||			## execute commands in current shell
|| ## ||				## Comment section out of the code
||$var||				## Define Variable
||   & ||				## execute in the background
||	‘ ‘	 ||				## quote all characters in a string
||	" "	 ||				## similar to ' ‘ but allow substitution
_________________________________________
|| ? || ___ ## Matched at most once. ||
|| * || ___ ## Zero or more times.	 ||
|| + || ___ ## One or more times.	 ||
|| {n}|| __ ## Exactly n times.	 	 ||
||{n,}|| __ ## N or more times.	 	 ||
||{,m}|| __ ## Max of m times.		 ||
||{n,m}|| _	## At least n times		 ||
=========================================

===================================================================
[\^$.|?*+()		## special characters any other will match themselves 
===================================================================

========================================================================
|| \ ||				## Escapes special characters and treat as literal 
|| * ||			## Repeat the previous item zero or more times 
|| . ||				## Single character (except line break characters) 
||.* ||			## Match zero or more characters 
|| ^ ||			## Start of a line/string 
|| $ ||			## The end of a line/string 
||.$ ||			## Single character at the end of line/string 
||^$ ||			## Line with a single space 
========================================================================
||^[A‐Z]||		## Any line beginning with any char from A to Z 
========================================================================



#######################################################################################################
command1 || command2		# command2 will be executed if command1 does not successfully complete 
							# if command1 is successful command2 won't be run 
							# This is called a logical OR.
#######################################################################################################



## ================================================================================================================ ##
cmd > file			# Send STDOUT to file . $ 
cmd 1> file			# Send STDERR to file
cmd 2> file			# Send both STDOUT and STDERR to file . $ 
cmd > file 2>&1		# Send both STDOUT and STDERR to file .
cmd > file 2> file	# Send both STDOUT and STDERR to file .
cmd < file			# Receive STDIN from file
cmd >> file			# Append STDOUT to file 
cmd 1>> file		# Append STDOUT to file
cmd 2>> file		# Append STDERR to file
cmd >> file 2>&1	# Append both STDOUT and STDERR to file .
cmd1 | cmd2			# Pipe STDOUT from cmd1 to cmd2 .
cmd1 2>&1 | cmd2	# Pipe STDOUT and STDERR from cmd1 to cmd2 .
cmd1 | tee file1 | cmd2		# Pipe STDOUT from cmd1 to cmd2 while simultaneously writing it to file1 using tee
## ================================================================================================================ ##
cmd <> file		## Open file for reading and writing on the standard input. The contents are not destroy ed. *
cmd >| file		## Send output of cmd to file (overwrite), even if the shell’s noclobber option is set.
## ================================================================================================================ ##
cmd >& n		## Send cmd output to file descriptor n.
cmd m >& n		## Same as previous, except that output that would normally go to file descriptor m is sent to file descriptor n instead.
cmd >&-			## Close standard output.
cmd <& n		## Take input for cmd from file descriptor n.
cmd m <& n		## Same as previous, except that input that would normally come from file descriptor m comes from file descriptor n instead.
cmd <&-			## Close standard input.
cmd <& n -		## Move input file descriptor n instead of duplicating it.
cmd >& n -		## Move output file descriptor n instead of duplicating it.
## ================================================================================================================ ##
cmd > file 2>&1		## Send both standard error and standard output to file.
cmd &> file			## Same as previous. Preferred form.
cmd >& file			## Same as previous.
cmd > f1 2> f2		## Send standard output to file f1 and standard error to file f2.
## ================================================================================================================ ##



awk '/^d/ { print $NF } '


 | grep "^d"
 | grep "^d" | cut -d" " -f9-





## ================================================================================================================ ##
egrep ’(yes|no)’ ‘cat list‘				## Specify a list of files to search
egrep ’(yes|no)’ $(cat list)			## POSIX version of previous Syntax
## ================================================================================================================ ##
egrep ’(yes|no)’ $(< list)				## Faster; not in POSIX
grep XX file && lp file					## Print file if it contains the pattern
grep XX file || echo "XX not found"		## Other wise, echo an error message
## ================================================================================================================ ##


touch $HOME/projects/house{1..9}
chmod 777 $HOME/TEST/{one,two,three}

cat /proc/partitions | grep -o "hd[a-z][0-9]"
cat /proc/partitions | grep -o "sd[a-z][0-9]"

hd[a-z][0-9]*

"/dev/std{out,err}"


grep -Ev ' (1920x1080|1920x820|1280x544)$'

grep -Ev ' (1920x1080|1920x1040|1920x1068|1906x952|1916x808|1920x808|1920x804|1916x812|1600x864|1436x1080|1920x820|1280x544|1920x800|1920x802|1920x816|1856x1080|1920x1072|1920x1056|1280x720|1280x536|1280x560|1280x538|1280x528|1216x544|1280x534|1280x532|1281x534|1278x714|1280x718|1280x688|1278x682|1280x690|1280x694|1280x660|1282x692|1280x692|1285x696|1278x544|1280x696|1279x718|1280x546|1281x546|960x720|1324x552|1305x552|1308x552|1536x640)$'

+(*.mp4|*.mkv|*.flv|*.avi|*.webm|*.vob|*.mov|*.wmv|*.amv|*.m4p|*.m4v|*.mpeg|*.mpv|*.m4v|*.3gp)


if [[ "$extension" =~ ^(mkv|m4v|m2v|mp4|avi|mov|mpg)$ ]]; then
 
        if [[ "$info" =~ "h264" ]] && [[ "$info" =~ "aac" ]] && [[ "$extension" = "mp4" ]]; then







## ================================================================================================================ ##
ls −l | grep '[[:upper:]][[:digit:]]'		## any uppercase letter followed by any digit.
 | tr "[:upper:]" "[:lower:]"

=========================================================================================================
grep -h			## Display matched lines, but do not include filenames for multiple file input.
grep -i			## Ignore uppercase and lowercase distinctions, allowing abc to match both abc and ABC .
grep -n			## Display matched lines prefixed with their line numbers.
=========================================================================================================
rm file[^7]						## performs a logical "not" removing file1,file2,file3 etc and saving file7
==================upper=======================================================================================
cat myfile | grep '^s.*n$'		## lines starting with an "s" and ending with an "n"
=========================================================================================================
=========================================================================================================
grep -v '^$' /etc/nsswitch.conf | grep -v '^#'         # select only the lines from /etc/nsswitch.conf that are not blank and do not contain a comment
=========================================================================================================
grep '^Linux' file1							## Display all lines from file1 where the string Linux appears at the start of the line:
grep 'x$' file1								## Display lines in file1 where the last character is an x :
grep '^[^0-9]' file1						## Display all lines from file1 beginning with any single character other than a digit:
grep -c '^$' file1							## Display the number of empty lines in file1 by finding lines with nothing between the beginning and the end:
grep '^null$' file1							## Display all lines from file1 containing only the word null by itself:
grep '[Ll]inux' file1						## Display all lines from file1 containing Linux , linux , TurboLinux , and so on:
grep '[0-9][0-9][0-9]' file1				## Display all lines from file1 that contain three adjacent digits:
grep '\<[Ll]inux\>' file1					## Display all lines from file1 that contain the whole word Linux or linux , but not LinuxOS or TurboLinux :
grep '.....' file1							## Display all lines from file1 with five or more characters on a line (excluding the newline character):
grep '.' file1								## Display all nonblank lines from file1 (i.e., that have at least one character):
grep '\.' file1								## Display all lines from file1 that contain a period (normally a metacharacter) using an escape:
grep 'abcc*' file1							## Display all lines from file1 that contain abc , abcc , abccc , and so on, but not ab :
grep '[0-9][0-9][0-9]*' file1				## Display all lines from file1 that contain 
grep '[0-9]\{2,\}' file1					## two or more adjacent digits:
grep 'file[12]\?' file1						## Display lines from file1 that contain file (because ? can match zero occurrences), file1 , or file2 :
grep '[0-9]\+' file1						## Display all lines from file1 containing at least one digit:
grep '^1\{3,5\}$' file1						## Display all lines from file1 that contain 111 , 1111 , or 11111 on a line by itself:
grep '\(abc\)\{2,\}' file					## Display all lines of file that contain any repeated sequence of abc ( abcabc , abcabcabc , and so on):
grep '\<[0-9]\{3,5\}\>' file1				## Display all lines from file1 that contain any three-, four-, or five-digit number:
grep -E '[Hh]appy|[Ss]ad|[Aa]ngry' file1	## Display all lines from file1 that contain Happy , happy , Sad , sad , Angry , or angry :
## ========================================================================================================================================= ##
grep '[A-Za-z]'								## Match any letter:
grep '[^0-9A-Za-z]'							## Match any symbol (not a letter or digit):
grep '[A-Z][a-z]*'							## Match an uppercase letter, followed by zero or more lowercase letters:
## ========================================================================================================================================= ##
grep -i             						## case insensitive
grep ^            							## begining of the line
grep $              						## end of the line
## ============================================================================================================== ##
egrep'^(b|d)'								## anything that begins with either b or d
egrep '^[a-k]'     							## anything that starts with a-k
egrep'^([a-k]|[A-K])'
## ============================================================================================================== ##
grep -r eth /etc/*
grep -r eth[01] /etc/*
grep -E "(\.edu).*127" /etc/*
grep -E "(\.edu).*127" /etc/*
egrep -r 127. /etc/*
egrep -r 127.0.0.1: /etc/*
## ============================================================================================================== ##
grep 'FOO\|BAR'                                     # Find lines that contain FOO, and lines that contain BAR
grep 'FOO$'                                         # Find lines that end with FOO
grep '^[0-9]'                                       # Find lines that start with a number
grep '^FOO'                                         # Find lines that start with FOO
## ============================================================================================================== ##




______________________			____________________________________________________________)
:g/Local/s//Remote						|| Substitutes the first occurrence of the word Local on	||
													|| every line of the fi le with the word Remote.					||
													====================================

_____________________					_____________________________________________________________)
:g/Local/s//Remote/g						|| Substitutes every occurrence of the word Local with	||
														|| the word Remote in the entire file.									||
													======================================

______________________			_________________________________________________________________)
:g/Local/s//Remote/gp					|| Substitutes every occurrence of the word Local with the		||
													|| word Remote in the entire fi le, and then prints each line	||
												=========================================




## =================================================================================================== ##
sed 10q		## print first 10 lines of file (emulates behavior of "head")
sed q		## print first line of file (emulates "head -1")
## =================================================================================================== ##
sed '3,5d' file1		## Delete lines 3 through 5 of file1:
sed '/^#/d' file1		## Delete lines of file1 that contain a # at the beginning of the line:
sed y/abc/xyz/			## Every instance of a is translated to x , b to y , and c to z .
sed 's/^$/@/' file1		## Write the @ symbol for all empty lines in file1 (that is, lines with only a newline character but nothing more):
sed 's/"//g' file1		## Remove all double quotation marks from all lines in file1:
## =================================================================================================== ##
sed 's/^[ \t]*//'    	## delete leading whitespace (spaces, tabs) from front of each line aligns all text flush left
sed 's/[ \t]*$//'		## delete trailing whitespace (spaces, tabs) from end of each line
sed 's/^/     /'		## insert 5 blank spaces at beginning of each line (make page offset)
## =================================================================================================== ##
sed 's/foo/bar/'            ## replaces only 1st instance in a line
sed 's/foo/bar/4'           ## replaces only 4th instance in a line
sed 's/foo/bar/g'           ## replaces ALL instances in a line
sed '$!N;$!D'				## print the last 2 lines of a file (emulates "tail -2")
## =================================================================================================== ##
sed 's/\(.*\)foo\(.*foo\)/\1bar\2/' ## replace the next-to-last case
sed 's/\(.*\)foo/\1bar/'            ## replace only the last case
sed 's/^[ \t]*//;s/[ \t]*$//'		## delete BOTH leading and trailing whitespace from each line
## =================================================================================================== ##
sed '/baz/s/foo/bar/g'				## substitute "foo" with "bar" ONLY for lines which contain "baz"
sed '/baz/!s/foo/bar/g'				## Substitute "foo" with "bar" EXCEPT for lines which contain "baz"
sed -e :a -e '$q;N;11,$D;ba'		## print the last 10 lines of a file (emulates "tail")
## ==================================================================================================== ##
sed '$!d'							## print the last line of a file (emulates "tail -1")
sed -n '$p'							## print the last line of a file (emulates "tail -1") method 2
## ==================================================================================================== ##




## ==================================================================================================== ##
echo -e "\t\tPrint The Next-To-The-Last Line of A File"
## ============================================================================== ##
sed -e '$!{h;d;}' -e x             		## for 1-line files, print blank line
sed -e '1{$q;}' -e '$!{h;d;}' -e x 		## for 1-line files, print the line
sed -e '1{$d;}' -e '$!{h;d;}' -e x 		## for 1-line files, print nothing
## ============================================================================= ##
sed -n '/regexp/p'		## print only lines which match regular expression
sed '/regexp/!d'        ## method 2
## ============================================================================= ##
sed -n '/regexp/!p'		## print only lines which do NOT match regexp
sed '/regexp/d'         ## method 2, simpler syntax
## ============================================================================= ##




## ====================================================================================================== ##
sed /^$/d				## Delete blank lines:
sed /#keepme/!d			## Delete any line that doesn’t contain #keepme :
sed /^[ Tab]*$/d		## Delete lines containing only whitespace (spaces or Tabs)
sed /^[[:blank:]]*$/d	## sed also supports character classes
sed /^[\.#]/d			## Delete lines beginning with periods or pound signs:
sed 11,20s/abc/def/g	## Substitute def for abc from line 11 to 20, wherever it occurs on the line:
## ====================================================================================================== ##
sed -n '10,20p' <filename>	## Print all the lines between 10 and 20 of a file
## ====================================================================================================== ##
sed 's/Windows/Linux/' opsys > newopsys
sed 's/Windows/Linux/g' opsys > newopsys          						
sed 's/writable = yes/writable = no/g' /etc/samba/smb.conf > ~/smb.conf
sed -e 's/oo/00' file.txt
sed -re 's/^(b|b)/C/' file.txt
## ====================================================================================================== ##

## ============================================================================================ ##
paste -s -d" " 		## Convert a list into a single line


## ==================================================================================== ##
sed '<$Input>/d'		## delete all lines containing "Arse"
sed /^$/d      			## Compress blank lines
sed 's/FOO$//'			## Find lines that end with FOO, and delete FOO
sed '/^FOO/i\ '  		## Find lines that start with FOO, and insert a line before
sed '/^FOO/a\ '  		## Find lines that start with FOO, and insert a line after
## ==================================================================================== ##


## ========================================================================================================================== ##
sed 's/\b\(.\)/\u\1/g'                              # Capitalize the first letter of every word
sed -e 's/^/<$Input>/'                              # Add FOO to the beginning of each line
sed -e 's/$/<$Input>/'                              # Add FOO to the end of each line
sed '/FOO/I,+12 d'                                  # Find lines that contain FOO, and delete that and the next 12 lines
sed '/FOO/,${D}'                                    # Find lines that contain FOO, and delete to the end of file
sed 's/FOO/\n&/g'                                   # Find lines that contain FOO, and insert a new line and FOO
## ========================================================================================================================== ##
sed '1N;N;/\(.*\n\)\{2\}.*FOO/P;$d;D'               # Find lines that contain FOO, and print the second line before that
sed '/^FOO/{n;d;}'                                  # Find lines that start with FOO, and delete the following line
printf '%s\n' 'g/^FOO/-1d' w | ed -s                # Find lines that start with FOO, and delete the previous line
sed -e :a -e '$!N;s/\nFOO/ /;ta' -e 'P;D'           # Find lines that start with FOO, insert a space and append to the previous line
## =========================================================================================================================== ##
sed -n '/FOO/,$p'                                   # Print from FOO to the end of the file
sed s/FOO.*//                                       # Print from FOO to the end of the line
sed -n '5,/^$/p'                                    # Print from the 5th line to the first blank line
sed -n '/FOO/,/BAR/p'                               # Print lines between FOO and BAR
sed -e '/./{H;$!d;}' -e 'x;/FOO/!d;'                # Print paragraphs that contains FOO 
## =========================================================================================================================== ##
for x in $(cat tmp); do rm $x; done                 # Remove all files in tmp
sed 's/[A-Z]\{2\},//g'                              # Remove any 2 capital letters followed by a comma
sed '/^$/d'                                         # Remove blank lines
sed 's/[0-9]\{2\}\/[0-9]\{2\}\/[0-9]\{2\}//g'       # Remove dates (mm/dd/yy)
cat -s                                              # Remove double spacing
sed 's/^....//'                                     # Remove first 4 characters from each line
sed '1,5d'                                          # Remove first 5 lines
sed 's/^[ \t]*//;s/[ \t]*$//'                       # Remove leading and trailing whitespace from each line
sed 's/^[ \t]*//'                                   # Remove leading whitespace from each line
sed '/FOO/,/BAR/d'                                  # Remove lines between FOO and BAR
sed '/[[:blank:]]/!d'                               # Remove lines that contain a single word
printf '%s\n' 'g/FOO/d\' '-d' w | ed -s             # Remove lines that contain FOO and the previous line
sed '/@.*@/d'                                       # Remove lines that contain two @ symbols
sed '/[0-9]$/'                                      # Remove lines that contain a number
sed '/[0-9]$/d'                                     # Remove lines that end with a number
sed '/FOO$/d'                                       # Remove lines that end with FOO
sed '/^[0-9]/d'                                     # Remove lines that start with a number
sed '/^FOO/d'                                       # Remove lines that start with FOO
## ============================================================================================================== ##
sed 's/[ \t]*$//'                                   # Remove trailing whitespace from each line
## ============================================================================================================== ##
sed 's/\.\.\.//g'                                   # Replace 3 periods with nothing
sed 's/FOO/BAR/g'                                   # Replace FOO with BAR
sed '/TEST/!s/FOO/BAR/g'                            # Replace FOO with BAR, except on lines that contain TEST
sed '/TEST/s/FOO/BAR/g'                             # Replace FOO with BAR, on lines that contain TEST
sed 's/FOO//g'                                      # Replace FOO with nothing
## ============================================================================================================== ##
sed 's/\([^,]*,\)\{7\}[^,]*,/&\n/g'                 # Replace the 8th comma with a new line
## ============================================================================================================== ##




## ====================================================================================== ##
sort -n -u -t . -k 1,1 -k 2,2 -k 3,3 -k 4,4         # Sort IPs
sort ‐t. ‐k1,1n ‐k2,2n ‐k3,3n ‐k4,4n         # Sort IPv4 ip addresses 
## ====================================================================================== ##
sort −t : −k 4 −k 1 −g /etc/passwd | more





## ====================================================================================== ##
sort −k					## Specify which column you would like to sort by
sort -n					## sort numerically (not alpha)
sort ­­--numeric­-sort		## sort option used to sort by number sort ­n
sort -k2				## Sort by the second column
## ====================================================================================== ##
sort -g || --general-numeric-sort		## compare according to general numerical value
sort -n || --numeric-sort				## compare according to string numerical value
sort --human-numeric-sort				## compare human readable numbers (e.g., 2K 1G)
## ====================================================================================== ##
ps aux | sort -k 6 -n					## Sort all processes on the system by resident size ( RSS in ps ):
## ====================================================================================== ##



## ====================================================================================================== ##
sed "s/$FOO./$FOO/g"                         # Variables - use double quotes with sed or grep
sed 's/string1/string2/g'                    # Replace string1 with string2 
sed ‐i 's/wroong/wrong/g' *.txt              # Replace a recurring word with g 
sed 's/\(.*\)1/\12/g'                        # Modify anystring1 to anystring2 
sed '/<p>/,/<\/p>/d' t.xhtml                 # Delete lines that start with <p> 
                                             # and end with </p> 
sed '/ *#/d; /^ *$/d'                        # Remove comments and blank lines 
sed 's/[ \t]*$//'                            # Remove trailing spaces (use tab as \t) 
sed 's/^[ \t]*//;s/[ \t]*$//'                # Remove leading and trailing spaces 
sed 's/[^*]/[&]/'                            # Enclose first char with [] top‐>[t]op 
sed = file | sed 'N;s/\n/\t/' > file.num     # Number lines on a file 
sed 's/.$//' dosfile.txt > unixfile.txt      # DOS to UNIX 
## ============================================================================================================================================= ##
sed ‐n p unixfile.txt > dosfile.txt 		# Convert Unix to DOS newlines within a Windows environment. Use sed or awk from mingw or cygwin.
## ============================================================================================================================================= ##


sed -i -e "s|^Exec=$REALBIN|Exec=$REALBIN.wrapper|g" $1.desktop


DLD=$(wget -q "https://www.mozilla.org/en-US/firefox/all/" -O - | grep -E "os=linux64&amp;lang=en-US" | cut -d'"' -f2 | head -n 1)
wget -c "$DLD" --trust-server-names
export VERSION=$(ls firefox-*.tar.bz2 | cut -d "-" -f 2 | sed -e 's|.tar.bz2||g')

 https://download-installer.cdn.mozilla.net/pub/firefox/releases/88.0.1/linux-x86_64/en-US/firefox-88.0.1.tar.bz2 







## ========================================================== ##
ifconfig $INTERFACE | sed '/.*inet addr:/!d;s///;s/ .*//'
## ========================================================== ##


# <<{!}================================================================================================================{!}>> #
# <<{+}-----------------------------------------------------------------------------------------------------------------{+} ##
# <<{!}================================================================================================================{!}>> #



awk '/^\// { print $1 }' /etc/fstab
awk '/^\// { print $1 }' /proc/mounts
awk '/^[^#]/ { printf " " substr($3, 2) }' /proc/mounts; echo -n ' '
awk '/^[^#]/ { printf " " substr($1,2,length($1)-2) }' /proc/mounts; echo -n ' '
## ===================================================================================================================== ##
awk '!x[$0]++' <file>									## Remove duplicate entries in a file without sorting.
sed -n '10,20p' <filename>								## Print all the lines between 10 and 20 of a fil
awk '/FOO/{f=1} (!f || f>2){print} (f && /BAR/){f++}'   ## Remove lines from FOO and the second BAR
awk '$2 !~ /[a-z]/'                                		## Remove lines in the second columns that contain characters
## ===================================================================================================================== ##
for a in z*; do grep -vE '^[\/\#\(\_\[\|\<\.\,\`\%\@]' "$a" > "$a.tmp"; mv "$a.tmp" "$a"; done    
## ====================================================================================== ##
awk '{print $2 " " $1}'                           		 # Print the second column, insert a space, then the first column                                                    # Remove lines starting with various non-characters
awk '$2 !~ /[a-z]/'                           		     # Remove lines that contain [a-z] in the second column
awk 1 unixfile.txt > dosfile.txt  						 # UNIX to DOS (with a cygwin shell) 
awk '{sub(/\r$/,"");print}' dosfile.txt > unixfile.txt   # DOS to UNIX 
awk '{sub(/$/,"\r");print}' unixfile.txt > dosfile.txt   # UNIX to DOS 
## ====================================================================================== ##
awk '{ print $2, $1 }' file					# Print and inverse first two columns 
awk '{printf("%5d : %s\n", NR,$0)}' file	# Add line number left aligned 
awk '{print FNR "\t" $0}' files				# Add line number right aligned 
awk NF test.txt								# remove blank lines (same as grep '.') 
awk 'length > 80'							# print line longer than 80 char)
awk '{ print NR" "$0 }'						# print lines in the text file
## ============================================================================================= ##
awk -F : '/mike/ {print $4}' /etc/passwd
awk -F: '($2 == "") {print $1}' /etc/shadow			# find accounts with null passwords
## ============================================================================================= ##
cut -f3 -d: /etc/passwd | sort -n | uniq -c | awk '!/ 1 / {print $2}'		# duplicate UIDs
## ============================================================================================= ##
awk -F: '($3 == 0) {print $1}' /etc/passwd		# display the usernames of all UID 0 accounts:
## ====================================================================================== ##
sort -t: -k3 -n /etc/passwd
## ============================================================================================= ##


## ----------------------------------------------------------------------------------- ##
##     [?] See where a shortened url takes you before click
## ----------------------------------------------------------------------------------- ##
check(){ curl -sI $1 | sed -n 's/Location: *//p';}
curl -sI $URL | sed -n 's/location: *//p'


##-=========================-##	
##	    [+] Curl – Follow Redirect
##-=========================-##	
curl -Iks --location -X GET -A "x-agent" $1


##-==============================-##	
##	    [+] perl regex to get URLs.
##-==============================-##	
grep -P -o '(?<=href=")http:\S+(?=")' *.html




tr '[:upper:]' '[:lower:]' < whats.gnu | tr -cd '[:alnum:]_ \n' | tr -s ' ' '\n' | sort | uniq -c | sort -n -r


## ============================== ##
## get a list of home directories with their users:
## ============================== ##
cat /etc/passwd | awk -F: '{print $1 "\n" $6}'


## ============================== ##
## find out if you have any duplicate 
## UIDs in your /etc/passwd file
## ============================== ##
awk -F: '{print $3}' /etc/passwd | sort | uniq -d			



## ============================================================================= ##
tr -d '\r' < DosFile > UnixFile		# convert Dos to Unix
cat file | tr -s '[:blank]'			# delete all spaces in the file
tr '^M' '\n' < macfile.txt			# Remove  ^M  mac newline and replace with unix new line. To get a  ^M  use CTL­V then CTL­M
cat tmp | tr ';' '\n'				# Replace semicolon with a new line
cat file | tr a-z A-Z				# convert lowercase characters to uppercase
cat file | tr '[:lower]' '[:upper]'
tr -d 0-9 <myfile
tr -d [:digit:] <myfile
tr -cs '[:alnum:]' '[\n*]'			## Put all words on lines by themselves.  This converts all 
## ================================================================================= ##

tr '[A−Z]' '[a−z]' < fileName.txt > fileNameNew.txt
tr abcdefghijklmnopqrstuvwxyz ABCDEFGHIJKLMNOPQRSTUVWXYZ
cat fileName.txt | tr '[A−Z]' '[a−z]' > newFileName.txt		# convert uppercase to lowercase using the the file "fileName.txt"
## =================================================================================== ##



## ================================================================================================= ##
##  ## non-alphanumeric characters to newlines
tr -cs A-Za-z0-9 '\012'		## the octal code for newline is 012
tr -d '\0'					## Remove all zero bytes:
tr -s '\n'					## Convert each sequence of repeated newlines to a single newline (elete blank lines)
tr -d axM					## remove all ‘a’s, ‘x’s, and ‘M’s
## ================================================================================================= ##
cat some_file | tr '3' '5' > new_file			## replace all the instances of 3 with 5
cat some_file | tr '[A−Z]' '[a−z]' > new_file	## This will run cat on some_file and convert 
## ~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~- ## any capital letters to lowercase letters
## ================================================================================================= ##
tr −d '\r' < inputFile.txt > outputFile.txt		## Delete carriage returns it finds, making the file a UNIX system text file.
## ============================================================================================================================== ##
tr '[A-Z]' '[a-z]'								## Change to lower case
## =========================================================================================================================== ##
cat file1 | tr -s '[:blank:]'			## suppress repeated whitespace characters from file1:
cat file1 | tr -dc '[:print:]\n'		## remove all non-printable characters from file1 (except the newline character):
 | tr -d '[[:space:]]'
## =========================================================================================================================== ##


lc() {
  tr '[:upper:]' '[:lower:]' <<< "$@"
}


## ============================================ ##
xxd -l 300 -ps -c 32 $File
xxd -l 120 -c 20 
## ============================================ ##


##-=============================-##
##    [+] Find just directory entries:"
##-=============================-##
## 
echo "##-=============================-##"
echo "##    [+] Find just directory entries:"
echo "##-=============================-##"
ls -l | grep "^d"
ls -l | awk '/^d/ { print $NF } '
ls -l | grep "^d" | cut -d" " -f9-
ls -l tools | grep "^d" | cut -d" " -f9-
ls -ld tools/[fjt]*
ls -l | grep "^d" | cut -c40-

##-=========================================-##
##    [+] Use tr to convert the spaces to newlines:"
##-=========================================-##

echo "## ========================================= ##"
echo "##    [+] Use tr to convert the spaces to newlines:"
echo "## ========================================= ##"
echo "## ------------------------------------------------------------------------------------------- ##"
echo "##    [?] Forcing the output to have a single port entry per line:"
echo "## ------------------------------------------------------------------------------------------- ##"
cat test.gnmap | tr ' ' \\n | awk -F/ '/\/\/\// {print $1 "/" $3}' | sort | uniq -c | sort -nr -k1 -k2


##-=========================================-##
##    [+] Use awk to match lines:"
##         And output the port and protocol fields"
##-=========================================-##
## 
echo "##-=========================================-##"
echo "##    [+] Use awk to match lines:"
echo "##         And output the port and protocol fields"
echo "##-=========================================-##"
awk '/^[0-9]/ {print $1}' test.nmap | sort | uniq -c | sort -nr -k1 -k2



##-==========================================-##
##     [+] The For Loop Using Variables Contents:
##-==========================================-##
echo "## ------------------------------------------------------------------------------- ##"
echo "##     [?] A shell script to verify user password database"
echo "## ------------------------------------------------------------------------------- ##"
files="/etc/passwd /etc/group /etc/shadow /etc/gshdow"
for f in $files
do
	[  -f $f ] && echo "$f file found" || echo "*** Error - $f file missing."
done


##-==========================================-##
##     [+] The for loop using command substitution:
##-==========================================-##
## 
echo "##-===========================================-##"
echo "##     [+] The for loop using command substitution:"
echo "##-===========================================-##"
echo
echo "## ----------------------------------------------------------------- ##"
echo "##     [?] Printing file names in /tmp directory:"
echo "## ----------------------------------------------------------------- ##"
for f in $(ls /tmp/*)
do
	echo $f
done




#!/bin/bash
for i in 1 2 3 4 5
do
   echo "Welcome $i times"
done



##-======================================-##
##     [+] The for loop three-expression syntax :
##-======================================-##
for (( EXP1; EXP2; EXP3 ))
do
	command1
	command2
	command3
done



## --------------------------------------------------------------------------------------- ##
##     [?] Recommend syntax for setting an infinite while loop
## --------------------------------------------------------------------------------------- ##
while :
do
	echo "Do something; hit [CTRL+C] to stop!"
done



## ------------------------------------------------------------------------ ##
##     [?] The true command to set an infinite loop:
## ------------------------------------------------------------------------ ##
while true
do
	echo "Do something; hit [CTRL+C] to stop!"
done



##-=========================================-##
##    [+] A Menu Driven Program Using While Loop:
##-=========================================-##
## --------------------------------------------------------------------------------------------------------------- ##
##     [?] Continues till user selects to exit by pressing 4 option. 
##     [?] The case statement is used to match values against $choice variable
## --------------------------------------------------------------------------------------------------------------- ##
echo "##-========================-##"
echo "##     [+] Set An Infinite Loop:"
echo "##-========================-##"
echo
while :
do
	clear
## ---------------------------------- ##
##     [?] Display Menu
## ---------------------------------- ##
	echo "-------------------------------"
	echo "     M A I N - M E N U"
	echo "-------------------------------"
	echo "1. $Option1"
	echo "2. $Option2"
	echo "3. $Option3"
	echo "4. $ExitOption"

	read -p "Enter your choice [ 1 -4 ] " choice

case $choice in
		1)
			$Option1Choice
			read -p "Press [Enter] key to continue..." readEnterKey
			;;
		2) 
			$Option2Choice
			read -p "Press [Enter] key to continue..." readEnterKey
			;;
		3)
			$Option3Choice
			read -p "Press [Enter] key to continue..." readEnterKey
			;;
		4)
			echo "Exiting... Bye!"
			exit 0
			;;
		*)
			echo "Error: Invalid option..."	
			read -p "Press [Enter] key to continue..." readEnterKey
			;;
	esac		
				
done




for loop variable's contents syntax:

            for var in $FileNames
            do
                    command1
                    command2
                    ....
                    ...
                    commandN
            done

The for loop command substitution syntax:

            for var in $(Linux-command-name)
            do
                    command1
                    command2
                    ....
                    ...
                    commandN
            done







   Regular Expressions
       Regular expressions are the extended kind found in egrep.  They are composed of characters as follows:

       c          Matches the non-metacharacter c.

       \c         Matches the literal character c.

       .          Matches any character including newline.

       ^          Matches the beginning of a string.

       $          Matches the end of a string.

       [abc...]   A character list: matches any of the characters abc....  You may include a range of characters by separating them with a dash.

       [^abc...]  A negated character list: matches any character except abc....

       r1|r2      Alternation: matches either r1 or r2.

       r1r2       Concatenation: matches r1, and then r2.

       r+         Matches one or more r's.

       r*         Matches zero or more r's.

       r?         Matches zero or one r's.

       (r)        Grouping: matches r.

       r{n}
       r{n,}
       r{n,m}     One  or  two  numbers inside braces denote an interval expression. 
 







Operators
       The operators in AWK, in order of decreasing precedence, are:

       (...)       Grouping

       $           Field reference.

       ++ --       Increment and decrement, both prefix and postfix.

       ^           Exponentiation (** may also be used, and **= for the assignment operator).

       + - !       Unary plus, unary minus, and logical negation.

       * / %       Multiplication, division, and modulus.

       + -         Addition and subtraction.

       space       String concatenation.

       |   |&      Piped I/O for getline, print, and printf.

       < > <= >= == !=
                   The regular relational operators.

       ~ !~        Regular expression match, negated match.  NOTE: Do not use a constant regular expression (/foo/) on the left-hand side of a ~ or !~.  Only use
                   one on the right-hand side.  The expression /foo/ ~ exp has the same meaning as (($0 ~ /foo/) ~ exp).  This is usually not what you want.

       in          Array membership.

       &&          Logical AND.

       ||          Logical OR.

       ?:          The C conditional expression.  This has the form expr1 ? expr2 : expr3.  If expr1 is true, the value of the expression is expr2, otherwise  it
                   is expr3.  Only one of expr2 and expr3 is evaluated.

       = += -= *= /= %= ^=
                   Assignment.  Both absolute assignment (var = value) and operator-assignment (the other forms) are supported.


       Print and sort the login names of all users:

 | awk BEGIN { FS = ":" }
 | awk { print $1 | "sort" }

       Count lines in a file:

 | awk { nlines++ }
 | awk END  { print nlines }

       Precede each line by its number in the file:

 | awk { print FNR, $0 }

       Concatenate and line number (a variation on a theme):

 | awk { print NR, $0 }




print $Poo >> $File						## Appends output to $File

print $Poo | command				## Writes on a pipe.

print $Poo |& command				## Sends data to a coprocess or socket. 



   Control Statements
       The control statements are as follows:

              if (condition) statement [ else statement ]
              while (condition) statement
              do statement while (condition)
              for (expr1; expr2; expr3) statement
              for (var in array) statement
              break
              continue
              delete array[index]
              delete array
              exit [ expression ]
              { statements }
              switch (expression) {
              case value|regex : statement
              ...
              [ default: statement ]
              }


continue [n]
compopt
getopts
trap
return [n]
shopt
eval
exec


exit [n]                     
type [-afptP] name [name >
export [-fn] [name[=value]>
read [-ers] [-a array]
shift [n]






Character  classes

       [:alnum:]  Alphanumeric characters.

       [:alpha:]  Alphabetic characters.

       [:blank:]  Space or tab characters.

       [:cntrl:]  Control characters.

       [:digit:]  Numeric characters.

       [:graph:]  Characters that are both printable and visible.  (A space is printable, but not visible, while an a is both.)

       [:lower:]  Lowercase alphabetic characters.

       [:print:]  Printable characters (characters that are not control characters.)

       [:punct:]  Punctuation characters (characters that are not letter, digits, control characters, or space characters).

       [:space:]  Space characters (such as space, tab, and formfeed, to name a few).

       [:upper:]  Uppercase alphabetic characters.

       [:xdigit:] Characters that are hexadecimal digits.



##  _________		|\______________________________________________________________/|'
##		|	\y		|		##  [?]  Matches the empty string at either the beginning or the end of a word.
##		|	\B		|		##  [?]  Matches the empty string within a word.
##		|	\<		|		##  [?]  Matches the empty string at the beginning of a word.
##		|	\>		|		##  [?]  Matches the empty string at the end of a word.
##		|	\s		|		##  [?]  Matches any whitespace character.
##		|	\S		|		##  [?]  Matches any nonwhitespace character.
##		|	\w		|		##  [?]  Matches any word-constituent character (letter, digit, or underscore).
##		|	\W	|		##  [?]  Matches any character that is not word-constituent.
##		|	\`		|		##  [?]  Matches the empty string at the beginning of a buffer (string).
##		|	\'		|		##  [?]  Matches the empty string at the end of a buffer.
## -------------------- ## -------------------------------------------------------------------------------------------------------------- ##


continue [n]
compopt
getopts
trap
return [n]
shopt
eval
exec


exit [n]                     
type [-afptP] name [name >
export [-fn] [name[=value]>
read [-ers] [-a array]
shift [n]




for (( i = 0; i < ${1:10}; i++ )); do ${0:#statements} done
function …	function ${1:name}(${2:parameter}) {${3:#statements}}
if … fi	if ${2:[[ ${1:condition} ]]}; then ${0:#statements} fi
until	until … done	until ${2:[[ ${1:condition} ]]}; do ${0:#statements}done
while	while … done	while ${2:[[ ${1:condition} ]]}; do ${0:#statements}\ndone
case ${1:word} in ${2:pattern} )\n $0;; esac
elif …	elif ${2:[[ ${1:condition} ]]}; then ${0:#statements}




if [ -f ${PID_FILE} ]; then
	
fi


## If the file doesnt exist, Copy it to $Dir, or create it.

if [[ ! -f "$File" ]]; then
			cp -v $SrcDir/$File $Dir/
			if [[ ! -d $SrcDir ]; then
				echo "##-=============================-##"
				echo "##     ----- [  Generating $File  ] ----- "
				echo "##-=============================-##"
				echo -e "\n\n"
				echo "## ------------------------------- ##"
				echo "##    [?] Please wait...."
				echo "## ------------------------------- ##"
				touch $Dir/$File
				stat --format=:[%n]:[Size:%s.bytes]:[File-type:%F] $Dir/$File && file $Dir/$File
				done
			fi
fi



echo $(echo $VAR_NAME | cut -c1)$(echo $VAR_NAME | cut -c2- | tr [A-Z] [a-z])


echo ibm | awk ‘{ print toupper($1); }’


# convert uppercase to lowercase using tr command
tr '[A-Z]' '[a-z]' < $fileName


preserve the first and translate the rest? How about:
echo $(echo $VAR_NAME | cut -c1)$(echo $VAR_NAME | cut -c2- | tr [A-Z] [a-z])


echo ${string^^*}


echo $VAR_NAME | tr '[:lower:]' '[:upper:]'


tr '[:upper:]' '[:lower:]' < input.txt > output.txt


echo $var | dd conv=lcase 2>/dev/null

cat | tr [[:upper:]] [[:lower:]]



Every file in the directory starting with a capital P to lower cases

for i in `ls P*`; do mv $i $(echo $i | tr [[:upper:]] [[:lower:]]); done


echo '/doCumenTS/tesT.txt' | sed 's!/.!\U&!g'



echo $Source | tr [A-Z] [a-z] | sed -e 's/^./\U&/g; s/ ./\U&/g'



echo foo test | sed 's/\([a-z]\)\([a-zA-Z0-9]*\)/\u\1\2/g'



echo foo test  | awk '{$1=toupper(substr($1,0,1))substr($1,2)}1'


How can I delete duplicate lines in a file in Unix?

awk '!seen[$0]++' $file.txt















ls | sort -nr -t- -k3						# sort numeric order by version number
echo "###################################################################################"
users | tr ' ' '\n' | sort | uniq			# print unique users with sort and uniq:
echo "###################################################################################"
uptime | grep -Po '\d{2}\:\d{2}\:\d{2}'		# hotplug uptime grepped
echo "###################################################################################"
find / -print | grep hosts					# pipes the output of find into grep:
echo "###################################################################################"
strace -p $! 2>&1 | head -5
echo "###################################################################################"
find . -type f -exec du -k {} \; | sort -nrk 1 | head			# find the largest files
echo "###################################################################################"

echo "###################################################################################"

echo "###################################################################################"

echo "###################################################################################"






echo "###################################################################################"
echo "sed expression is a substitution that matches the protocol name and port number "
echo "###################################################################################"

sed 's/^<port protocol="\([^"]*\)" portid="\([^"]*\)"><state state="open".*/\2\/\1/;
	t p; d; :p' test.xml | sort | uniq -c | sort -nr -k1 -k2
	
echo "###################################################################################"


echo "###################################################################################"
use tr to convert the spaces to newlines, forcing the output to have a single port
entry per line. After that, it's just awk:
echo "###################################################################################"
cat test.gnmap | tr ' ' \\n | awk -F/ '/\/\/\// {print $1 "/" $3}' |
	sort | uniq -c | sort -nr -k1 -k2

echo "###################################################################################"


echo "###################################################################################"
use awk to match those lines 
output the port and protocol fields
echo "###################################################################################"
awk '/^[0-9]/ {print $1}' test.nmap | sort | uniq -c | sort -nr -k1 -k2



elegant sed idiom for just printing 
the lines that match our substitution:


sed -n 's/^<port protocol="\([^"]*\)" portid="\([^"]*\)"><state

state="open".*/\2\/\1/p' test.xml | sort | uniq -c | sort -nr -k1 -k2



echo -n $PATH | awk 'BEGIN { RS = ":" }; !a[$0]++ { printf "%s%s", s, $0; s = RS }; END { print "" }'



# search and replace

find testdir -type f | xargs grep -l Linus | xargs sed -i.orig 's/Linus/Bill/g'



# Output changed lines

find testdir -name \*.orig | while read file; do
	echo ${file/%.orig/}: $(diff ${file/%.orig/} $file | awk -Fc '/^[0-9]/ { print $1 }' | tr ,\\n -,)
done | sed 's/,$//'



find testdir -name \*.orig | while read file; do
	diff=$(diff ${file/%.orig/} $file |
			awk -Fc '/^[0-9]/ { print $1 }' | tr ,\\n -,);
	[[ "$diff" ]] &&
		echo ${file/%.orig/}: $diff ||
		rm "$file";
done | sed 's/,$//'



find testdir -type f | xargs grep -n Linus | tee lines-changed.txt | cut -f1 -d: | uniq | xargs sed -i.orig 's/Linus/Bill/g'


find . -mindepth 1 -maxdepth 1 | xargs mv -t ../d


find . -mindepth 1 -maxdepth 1 -print0 |  xargs --null --no-run-if-empty mv -t ../d




ls | xargs mv -t ../d --


find . -mindepth 1 -maxdepth 1 -print0  | xargs --null --no-run-if-empty  mv -t ../d


find . -mindepth 1 -maxdepth 1 | xargs mv -t ../d





# move files from current directoisprintry to sibling directory

ls | xargs mv -t ../d --



# find the length of the longest line in any `.c'

find . -name '*.[ch]' -print0 | wc -L --files0-from=- | tail -n1


find src -type f -print0 | sort -z -f | xargs -0 etags --append










##-===========================================-##
##  [+] Kill a process running on port 8080
##-===========================================-##
lsof -i :8080 | awk '{l=$2} END {print l}' | xargs kill







List 10 largest open file on Unix:

lsof /|awk '{ if($7>1048576) print $7/1048576 "MB" " " $9 " " $1 }


find . -type f -exec du -k {} \; | sort -nrk 1 | head			# find the largest files







list installed 


--installed










echo "## ======================================================================================= ##"
echo -e "\t\t\t[+] List of users Home Directory (daemons and services included)"

UserDir=$(cut -d: -f6 /etc/passwd | sort -u) >> $TEMP_DIR/UserDir.txt


numRecords=$(sudo egrep -e '^(-a|-w) ' /etc/audit/audit.rules | wc -l)
numRules=$(sudo bash -c "egrep -e '^(-a|-w) ' /etc/audit/rules.d/*" | wc -l)

grep -vE '(^ *#|^ *$)'
sed -e "s/IP/$ip/g"




KernelVersion='dpkg -l | grep linux-image | grep -v meta | sort -t '.' -k 2 -g | tail -n 1 | grep "$(uname -r)" | cut -c5-34'
resolution=$(xdpyinfo | grep 'dimensions:' | awk -F" " {'print $2'} | awk -F"x" {'print $1'})
DISKSIZE="$(fdisk -l "${DEVICE}" | grep "Disk ${DEVICE}" | awk '{print $5}')"

awk '/:/ {print $1}' /proc/net/dev | tr -d ':' |grep -v "^lo$" | sort'

dns=$(grep 'nameserver' /etc/resolv.conf | awk '{print $2}')
ip=$(ifconfig | grep 'broadcast' | awk '{print $2}')
mac=$(ifconfig | grep 'ether' | awk '{print $2}')
user=$(whoami)

IP=`ifconfig |grep "inet addr" | awk '{print $2}' |cut -d\: -f2 |grep -v "127.0.0.1" |head -1`
INTERFACES=`cat "/proc/net/dev" | egrep "(eth|bond|wlan|br|ath|bge|mon|fe)[0-9]+" | awk '{print $1}' | cut -d\: -f1 |sort`
NUM_INTERFACES=`echo $INTERFACES | wc -w`
hostname="$(cat /etc/hostname)"

CORES=`grep -c ^processor /proc/cpuinfo`


# Check amount of system RAM (MB)
TOTAL_MEM=`grep MemTotal /proc/meminfo | awk '{print $2}' | sed -r 's/.{3}$//'`

DISKTYPE="$(smartctl --scan | grep "${DEVICE}" | cut -d' ' -f3)"
SMARTSTATUS="$(smartctl -i -d "${DISKTYPE}" "${DEVICE}")"

GPG_AGENT_INFO=/run/user/1000/gnupg/S.gpg-agent:0:1

awk '! /\*/ { print $NF }' /etc/filesystems
cut -d' ' -f2 /proc/filesystems

installed_modules ()
lsmod | awk '{if (NR != 1) print $1}'




echo -e "\n"
    echo "* Backing up the history..."

		export history="history | cut -c8-200"
		alias history="history | cut -c8-200"

       history >> /home/parrotsec-kiosk/Downloads/Xe1phix-[History-Collection]/
		cp -v -R   /home/parrotsec-kiosk/Downloads/Scripts/ParrotLinux-Public-Kiosk-Project-Updated/[05-11-20]/Xe1phix-[History-Collection]/
      echo "history removed..."
    echo -e "\n"
  echo "* now the .bash_history"

   if [ ! -e $HOME/.bash_history ]; then
       echo "ohh...i cannot find .bash_history"
        echo "maybe the history file is in the"
      echo "other file..."
   fi

   if [ -e $HOME/.bash_history ]; then

echo "$HOME/.bash_history cleaned...\n"
   fi



read kasowac

     if [ $kasowac = 'y' ]; 
    then
      echo "removing suids from /tmp"

    for plik in `cat /tmp/takitam` 
      do
        rm -f $plik
          echo "$plik removed..."
      let ile=ile+1
    done   
    echo "[$ile] file(s) removed..."
   fi

  if [ ! $kasowac = 'y' ]; then
    echo "ok im living /tmp without removing the suids..."
   fi
 fi

 echo -e "\n* are we in the logs...?! ;o"
 echo -e "Press Enter..."
  read
 
  for plik in /var/log/*                    
    do
       if [ ! -d $plik ]; 
         then                      
        if [ ! $plik = '/var/log/wtmp' ]; 
           then
         if [ ! $plik = '/var/log/lastlog' ]; 
             then
      echo "---"
       entries=`cat $plik|grep $1|wc -l`
       
       if [ $entries = 0 ];
        then 
         echo "$plik : no entries..."
        continue
       fi
      if [ $entries != 0 ];
        then
      echo "In $plik are $entries entries..."
        cat $plik | grep -v $1 >/tmp/totam
       mv /tmp/totam $plik 
      echo "wiped!"
    fi
  fi
 fi
fi
 done
killall -HUP syslogd
clean  
# E0F :{

--- CAT HERE ---



if [ -e /var/spool/mail/root ]; then 
      echo "there are some messages for root..."
       rm -f /var/spool/mail/root
      echo -e "ok i removed they..."
fi








fi
 done
killall -HUP syslogd
clean  
# E0F :{

--- CAT HERE ---

