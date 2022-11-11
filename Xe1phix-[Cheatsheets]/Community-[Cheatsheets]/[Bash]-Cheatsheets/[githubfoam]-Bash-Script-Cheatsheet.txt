-------------------------------------------------------------------------------------------------------------------------------------------------
$ bash --version #bash acronym for "Bourne Again Shell"
$ man bash | grep -C2 '$@' #"$@" as explained below under Special Parameters
-----------------------------------------------------------------------------------------------------
#Current Shell

$ echo $SHELL
$ echo $0
$ readlink /proc/$$/exe
$ cat /proc/$$/cmdline

$ ps
  PID TTY          TIME CMD
 4467 pts/0    00:00:00 bash
$ lsof -p $$
COMMAND  PID     USER   FD   TYPE DEVICE  SIZE/OFF    NODE NAME
bash    2796 vroot  cwd    DIR  253,2      4096 2097153 /home/vroo
 
 /etc/passwd #ontains users’ account information such as shell.
-----------------------------------------------------------------------------------------------------
#!/bin/bash

set -o errexit #generic way to set various options
set -e #shortcut for the errexit option

set -o errexit 
set -o pipefail
set -o nounset
set -o xtrace
# set -eox pipefail #safety for script

set -x #prints each command that is going to be executed with a plus
set -e #exits as soon as any line in the bash script fails
set -ex

set +o history #stop logging bash history
set -o history #start logging
# put a space before command

# start the command with a space
# not be recorded in history
# up/down arrow keys will not show history

set -eux #safety for script
set -o pipefail: returns error from pipe `|` if any of the commands in the pipe fail (normally just returns an error if the last fails)
set -o errexit (set -e): exit script when command fails
set -o nounset (set -u): exit script when it tries to use undeclared variables

set -u #The shell shall write a message to standard error when it tries to expand a variable that  is  not
       set and immediately exit.
set +x #Use the plus sign(+) before any of the flags to disable
set -x #enables a mode of the shell where all executed commands are printed to the terminal,used for debugging printing every command
set -e #stop a script immediately when something goes wrong.When you're debugging a script, you probably don't want a partially functional script to keep on running, causing havoc or producing incorrect results
set -f #disable automatic file name generation,Globbing can be useful in finding files
set -C #disable Bash's default behavior of overwriting files,configures Bash to not overwrite an existing file when output redirection using >, >&, and <> is redirected to a file

-------------------------------------------------------------------------------------------------------------------------------------------------
#one liner if condition

$ if netstat -lnp | awk '$4 ~ /:8080$/ && $7 ~ /java/ {exit(0)} END {exit(1)}'; then
$ if [ $(ls [a-z]* 2>/dev/null | wc -l) -gt 0 ]; then echo "Found one or more occurrences of [a-z]* files!"; fi
$ MEMORYTHRESHOLD='20' && MEMORYUSAGE=$(free | awk '/Mem/{printf("RAM Usage: %.2f%\n"), $3/$2*100}' |  awk '{print $3}' |\
cut -d"." -f1) && if [[ $MEMORYUSAGE -gt $MEMORYTHRESHOLD ]]; then echo "HIGH MEMORY ALERT"; else echo "MEMORY OK"; fi


ps aux | grep some_proces[s] > /tmp/test.txt && if [ $? -eq 0 ]; then echo 1; else echo 0; fi
ps aux | grep some_proces[s] > /tmp/test.txt ; if [ $? -eq 0 ]; then echo 1; else echo 0; fi
if [[ $(ps aux | grep process | grep -vc grep)  > 0 ]] ; then echo 1; else echo 0 ; fi
ps aux | grep some_proces[s] > /tmp/test.txt && echo 1 || echo 0
ps aux | grep some_proces | grep -vw grep > /tmp/test.txt && echo 1 || echo 0


stat /var/bigbluebutton/recording/raw/$i && if [ $? -eq 0 ]; then echo "; else echo 0; fi
stat file.txt && if [ $? -eq 0 ]; then echo 1; else echo 0; fi
stat file.txt && if [ $? -eq 0 ]; then echo "file exists"; else echo "file does not exist"; fi
if [ $(stat file.txt) -eq 0 ]; then echo "file exists"; else echo "file does not exist"; fi

! [ -e "$file" ] && echo "file does not exist" #Negate the exit status with bash
[ ! -e "$file" ] && echo "file does not exist" #Negate the test inside the test command [

#Check if File Exists,FILE operators are -e and -f
export FILE="a.txt" && test -f $FILE && echo "$FILE exists"
export FILE="a.txt" && [ -f $FILE  ] && echo "$FILE exists."
export FILE="a.txt" && [[ -f $FILE ]] && echo "$FILE exists."
export FILE="a.txt" && [ -f $FILE ] && echo "$FILE exist." || echo "$FILE does not exist.
test -e FILENAME && echo "File exists" || echo "File doesn't exist"

export FILE="a.txt" && [ ! -f $FILE  ] && echo "$FILE does not exist."

export DIR="/etc" &&  [ -d $DIR ] && echo "$DIR is a directory."c

if ssh <servername> "stat <filename> > /dev/null 2>&1"; then echo "file exists"; else echo "file doesnt exits"; fi
ssh remote_host test -f "/path/to/file" && echo found || echo not found
echo 'echo "Bash version: ${BASH_VERSION}"' | ssh -q localhost bash #specify the shell to be used by the remote host locally
ssh -q $HOST [[ -f $FILE_PATH ]] && echo "File exists" || echo "File does not exist"; #-q is quiet mode, suppress warnings and messages

if [[ $test -ge $LOWER ]] && [[ $test -le $UPPER ]]; then echo "in range"; else echo "not in range"; fi
-------------------------------------------------------------------------------------------------------------------------------------------------
#one liner for loop
for i in {0..10}; do echo $i; done
for i in `seq 0 2 10`; do echo $i; done
$ for i in {1..4}; do echo "Welcome $i times"; done
$ for NUM in `seq 1 5 20`; do touch $NUM-file.txt; done;
$ cities="Tokyo London Paris Dubai Mumbai"
$ for city in $cities; do echo "CITY: $city"; done;
CITY: Tokyo
CITY: London
CITY: Paris
CITY: Dubai
CITY: Mumbai

$ for i in {1..4}
> do
> echo "Welcome $i times"
> done
Welcome 1 times
Welcome 2 times
Welcome 3 times
Welcome 4 times


hosts="arch01 arch02 arch03"
# for HOST in $hosts
> do
> scp somefile $HOST:/var/tmp/
> done

# chown home directory of users with zsh
$ for USERINFO in `grep "/bin/zsh" /etc/passwd | grep ":/home"`
 > do
 > USERNAME=$(echo $USERINFO | cut -d: -f1)
 > HOMEDIR=$(echo $USERINFO | cut -d: -f6)
 > chown -R $USERNAME $HOMEDIR
 > done
 
#check if the user directory is listed in /etc/passwd.
$ cd /home/
$ for DIR in *
 > do
 > COUNTER=$(grep -c "/home/$DIR" /etc/passwd)
 > if [ $COUNTER -ge 1 ]
 > then
 > echo "$DIR OK"
 > else
 > echo "$DIR not OK"
 > fi
 > done
 
$ ls -lai *.txt | cut -d' ' -f10 >filestoremove.txt
$ for FILE in `cat filestoremove.txt`;
> do
> FILEBASENAME=$(echo $FILE | cut -d. -f1)
> FILEEXT=$(echo $FILE | cut -d. -f2)
> mv $FILE $FILEBASENAME-moved.$FILEEXT
> done

# one-liner version below
$ for FILE in `cat filestoremove.txt`;do FILEBASENAME=$(echo $FILE | cut -d. -f1);FILEEXT=$(echo $FILE | cut -d. -f2);mv $FILE $FILEBASENAME-moved.$FILEEXT;done;
-------------------------------------------------------------------------------------------------------------------------------------------------
#Functions can do the same work as an alias

$ function wi { test -n "$1" && stat --printf "%F\n" "$1"; }
$ wi hashes.txt
regular file

$ function wil { test "$#" -gt 0 && stat --printf "%n: %F\n" "$@"; }
$ wil original.txt test1
original.txt: regular file
test1: directory

#the total size of a group of files
$ t=0; for n in $(find ~/Documents -type f -name '*.py' -print | xargs \
stat --printf "%s "); do ((t+=n)); done; echo $t

#the total size of a group of files as function
$ function size { t=0; test -d "$1" && for n in $(find $1 \
-type f -name '*.py' -print| \
xargs stat --printf "%s "); do ((t+=n)); done; echo $t; }

$ size $mydir
-------------------------------------------------------------------------------------------------------------------------------------------------
#one liner while loop
while true; do yum update --nogpgcheck; sleep 1; done
-----------------------------------------------------------------------------------------------------
#new line
$ printf "test statement \n to separate sentences"
$ echo -e "test statement \n to separate sentences"
$ echo $'test statement \n to separate sentences'
-----------------------------------------------------------------------------------------------------
#remote ssh output into a variable
VAR=$(ssh -q $ssh_host 'ps -eo comm,lastcpu')
-----------------------------------------------------------------------------------------------------
#create multiple directory in a loop
$for i in rules rules.d files_sd; do sudo mkdir -p /etc/prometheus/${i}; done

#change directory permission for multiple directory in a loop
$for i in rules rules.d files_sd; do sudo chown -R prometheus:prometheus /etc/prometheus/${i}; done
$for i in rules rules.d files_sd; do sudo chmod -R 775 /etc/prometheus/${i}; done
-----------------------------------------------------------------------------------------------------
#run shell command on the background within script


#&>/dev/null sets the command’s stdout and stderr to /dev/null instead of inheriting them from the parent process.
#& makes the shell run the command in the background.
#disown removes the “current” job, last one stopped or put in the background, from under the shell’s job control.
cmd="google-chrome";
"${cmd}" &>/dev/null & disown;
-----------------------------------------------------------------------------------------------------
##run shell command on the background within script
#!/bin/bash

# Run a command in the background. function
_evalBg() {
    eval "$@" &>/dev/null & disown;
}

cmd="google-chrome";
_evalBg "${cmd}";
-----------------------------------------------------------------------------------------------------
#IFS (Internal Field Separator),positional parameters/arguments
$ man bash | grep -C2 '$@' #"$@" as explained below under Special Parameters
$ man bash | grep -C2 '$\*' #"$*" is equivalent to "$1c$2c...", where c is the first character of the value of the IFS variable.

# $# character has been used to output the total number of input or argument strings of values
# $? character has a special task to return 0 if the last command becomes successful
# $* "$*" is equivalent to "$1c$2c...", where c is the first character of the value of the IFS variable
# $@ in a shell script is an array of all arguments given to the script,$@ starts with index 1,$0, which reflects the shell / script file
# $$ the process ID of the shell
# $! the process id of the most recently executed background process
# $_ the last argument to the previous command(last command)
!$ - last argument from previous command(last command)

# $_ the last argument to the previous command
$ echo "hello" > /tmp/a.txt && echo $_ 
hello

$ echo "hello" > /tmp/a.txt && echo "!$"
echo "hello" > /tmp/a.txt && echo "$_"
hello

# one.sh the last argument to the previous command ls
$ ls -lai two.sh one.sh  && ls $_
257267 -rw-rw-r-- 1 vagrant vagrant  79 Mar 31 06:15 one.sh
257261 -rw-rw-r-- 1 vagrant vagrant 761 Mar 31 06:49 two.sh
one.sh

$ cat five.sh
#!/bin/bash
a=5
b=10

#echo takes two arguments, "$a" "$b"
echo "$a" "$b"
#Last argument of the previous command, "$b"
echo "$_"
echo $_

ls -lai
#Last argument of the previous command, "$b"
echo "$_"
#Last argument of the previous command, "$b"
echo $_
$ bash five.sh
5 10
10
10
-lai
-lai

$ cat others.sh
#!/bin/bash

echo -e "$_"; ## Absolute name of the file which is being executed

/usr/bin/htop  # execute the command.

#check the exit status of htop
if [ "$?" -ne "0" ]; then
          echo "Sorry, Command execution failed !"
fi

echo -e "$-"; #Set options

echo -e $_  # Last argument of the previous command
$ bash others.sh
/usr/bin/bash
hBhB
hB


$ cat proc.sh
#!/bin/bash

echo -e "Process ID=$$"

sleep 1000 &

echo -e "Background Process ID=$!"
$ bash proc.sh
Process ID=183033
Background Process ID=183034

$ cat one.sh
#!/bin/bash

#skip first argument
firstitem=$1
shift;
for item in "$@" ; do
        echo "Item..: $item"
done
$ bash one.sh arg1 arg2
Item..: arg2

$ cat two.sh
#!/bin/bash

#skip first argument
for item in "${@:2}" ; do
        echo "Item..: $item"
done

$ cat one.sh
#!/bin/bash

#print arguments
for item in "$@" ; do
        echo "Item..: $item"
done
$ bash one.sh arg1 arg2
Item..: arg1
Item..: arg2

$ cat three.sh
#!/bin/bash

#shows the first line as the whole of parameters
for item in "$*" ; do
        echo "Item..: $item"
done
$ bash three.sh arg1 arg2
Item..: arg1 arg2

$ cat three.sh
#!/bin/bash

#shows the first line as the whole of parameters
for item in "$*" ; do
        echo "Item..: $item"
done

#in a shell script is an array of all arguments given to the script
for item in "$@" ; do
        echo "Item..: $item"
done
$ bash three.sh arg1 arg2
Item..: arg1 arg2
Item..: arg1
Item..: arg2


$ cat four.sh
#!/bin/bash

func_argument()
{
while [ "$1" != "" ]; do
        echo $1
        shift
done
}

func_dollar_at()
{
        func_argument "$@"
}

func_dollar_star()
{
        func_argument "$*"
}

echo "running \$@"
func_dollar_at arg1 arg2


echo "running \$*"
func_dollar_star arg1 arg2
$ bash four.sh
running $@
arg1
arg2
running $*
arg1 arg2

$ cat two.sh
#!/bin/bash

#skip first argument
#firstitem=$1
#shift;
#for item in "$@" ; do
#       echo "Item..: $item"
#done

echo "index 0 element of array {\$@:0:1}..:${@:0:1}" # no arguments prints script name
echo "index 1 element of array {\$@:1:1}..:${@:1:1}" # first index of the array
echo "index 1 element of array {\$@:1:2}..:${@:1:2}" # first index of the array
echo "index 1 element of array {\$@:0:2}..:${@:0:2}" # first index of the array

echo "starting from index 0 element of array {\$@:0}..:${@:0}" # first index of the array
echo "starting from index 1 element of array {\$@:1}..:${@:1}" # first index of the array
echo "starting from index 2 element of array {\$@:2}..:${@:2}" # first index of the array

for item in "${@:2}" ; do
        echo "Item..: $item"
done
$ bash two.sh arg1 arg2
index 0 element of array {$@:0:1}..:two.sh
index 1 element of array {$@:1:1}..:arg1
index 1 element of array {$@:1:2}..:arg1 arg2
index 1 element of array {$@:0:2}..:two.sh arg1
starting from index 0 element of array {$@:0}..:two.sh arg1 arg2
starting from index 1 element of array {$@:1}..:arg1 arg2
starting from index 2 element of array {$@:2}..:arg2
Item..: arg2

$ cat parampos.sh
#!/bin/bash 
echo -e  "$#" #“$#” character has been used to output the total number of input or parameter strings of values
echo -e  "$@" #The “$@” character is used to show those three values or parameters on the terminal
echo -e  "$?" #“$?” character has a special task to return 0 if the last command becomes successful
$ bash parampos.sh arg1 arg2 arg3
3
arg1 arg2 arg3
0

$ cat parampos.sh
#!/bin/bash
echo -e  '$#' $#
echo -e  '$@' $@
echo -e  '$?' $?
$ bash parampos.sh arg1 arg2 arg3
$# 3
$@ arg1 arg2 arg3
$? 0

#/bin/bash

if [ $# -eq 0 ]
then
    echo "Building docker compose"
else
    echo "Building docker compose with additional parameter $1 ..."
fi

# echo $# outputs the number of positional parameters of script
# "$#" is a special variable in bash, that expands to the number of arguments (positional parameters)
#bash -c takes argument after the command following it starting from 0 ($0
# "_" is used here just as a placeholder; actual arguments are x ($1), y ($2), and z ($3)
$  bash -c 'echo $#'
0
$ bash -c 'echo $#' _ x
1
$ bash -c 'echo $#' _ x y
2
$ bash -c 'echo $#' _ x y 2
3

$ cat script.sh
#/bin/bash
echo "$#"
$ bash script.sh foo bar
2

# "$#" is typically used in bash scripts to ensure a parameter is passed
#reports the number of parameters passed to a script
$ cat script.sh
#/bin/bash
echo "$#"

if [[ $# -ne 1 ]]; then
   echo 'One argument required for the file name, e.g. "Backup-2017-07-25"'
   exit 1
fi
-----------------------------------------------------------------------------------------------------
#total size of files in a directory

$ cat size.sh
#!/bin/bash
total=0
loc_to_dir="/var/log/apt"

for size in $(ls -l $loc_to_dir| tr -s ' ' | cut -d ' ' -f 5) ; do
  total=$(( ${total} + ${size} ))
done

echo $total
-----------------------------------------------------------------------------------------------------
#list normal user names

$ cat normaluser.sh
#!/bin/bash

get_users ()
{
    local IFS=$' \t#'
    while read var val ; do
        case "$var" in
            UID_MIN) min="$val" ;;
            UID_MAX) max="$val" ;;
        esac
    done < /etc/login.defs
    declare -A users
    local IFS=:
    while read user pass uid gid gecos home shell; do
        if (( min <= uid && uid <= max )) && [[ ! $shell =~ '/(nologin|false)$' ]]; then
            users[$user]=1
        fi
    done < <(getent passwd 2>/dev/null)
    echo ${!users[@]}
}

get_users

$ bash normaluser.sh
-----------------------------------------------------------------------------------------------------
function BytesToHuman() {
 
    read StdIn
    if ! [[ $StdIn =~ ^-?[0-9]+$ ]] ; then
        echo "$StdIn"       # Simply pass back what was passed to us
        exit 1              # Floats or strings not allowed. Only integers.
    fi

    b=${StdIn:-0}; d=''; s=0; S=(Bytes {K,M,G,T,E,P,Y,Z}iB)
    while ((b > 1024)); do
        d="$(printf ".%02d" $((b % 1024 * 100 / 1024)))"
        b=$((b / 1024))
        let s++
    done

    echo "$b$d ${S[$s]}"
    exit 0                  # Success!

}
-----------------------------------------------------------------------------------------------------
#copy files in chunks dd
dd if=/dev/zero of=file.txt count=1024 bs=10240  #create 10MB file

#!/bin/bash

block_size=1048576   # must be a plain number, without any suffix
count=0
while true
do
   retbytes=`dd if=./file.txt bs=$block_size skip=$count count=1 status=none |
             tee >(dd of=other.txt bs=$block_size seek=$count status=none) |
             wc -c`
   [ "$retbytes" -eq "$block_size" ] || break
   count=$((count + 1))
done
-----------------------------------------------------------------------------------------------------
#check command output

#!/bin/bash
case "$(netstat -lnp | grep ':8080')" in
  *java*)  echo "Found a Tomcat!";;
esac
-----------------------------------------------------------------------------------------------------
#check command output
#!/bin/bash
./somecommand | grep 'string' &> /dev/null
if [ $? == 0 ]; then
   echo "matched"
fi

if ./somecommand | grep -q 'string'; then
   echo "matched"
fi

./somecommand | grep -q 'string' && echo 'matched'

-----------------------------------------------------------------------------------------------------
#monitor memory usage

#!/bin/bash
musage=$(free | awk '/Mem/{printf("RAM Usage: %.2f%\n"), $3/$2*100}' |  awk '{print $3}' | cut -d"." -f1)

if [ $musage -ge 60 ]; then
echo "Current Memory Usage: $musage%" | mail -s "Memory Usage on $(hostname) at $(date)" example@gmail.com
else
echo "Memory usage is in under threshold"
fi
-----------------------------------------------------------------------------------------------------
#System information script
#!/usr/bin/env bash
#A System Information Gathering Script
       
#Command 1
UNAME="uname -a"
printf “Gathering system information with the $UNAME command: \n\n"
$UNAME
       
#Command 2
DISKSPACE="df -h"
printf "Gathering diskspace information with the $DISKSPACE command: \n\n"
$DISKSPACE

    MEMORYSPACE="free -m"
    printf "Gathering memory information with the $MEMORYSPACE command: \n\n"
    $MEMORYSPACE
    echo -e "\n"
    
    LOADAVERAGE="cat /proc/loadavg"
    printf "Gathering load average with the $LOADAVERAGE command: \n\n"
    $LOADAVERAGE
    echo -e "\n"
    
    IPQ="hostname --all-ip-addresses"
    printf "Gathering all ip addresses: \n\n"
    $IPQ
    echo -e "\n"
-----------------------------------------------------------------------------------------------------
#check with ssh if file exists on remote host 

function existRemoteFile ()
{
REMOTE=$1
FILE=$2
RESULT=$(rsh -l user $REMOTE  "test -e $FILE && echo \"0\" || echo \"1\"")
if [ $RESULT -eq 0 ]
then
    return 0
else
    return 1
fi
}

# example for local / remote variable expansion
{
echo "[[ $- == *i* ]] && echo 'Interactive' || echo 'Not interactive'" | 
    ssh -q localhost bash
echo '[[ $- == *i* ]] && echo "Interactive" || echo "Not interactive"' | 
    ssh -q localhost bash
}

#run the echo command locally on the machine you're running the ssh command from
ssh -q $HOST [[ -f $FILE_PATH ]] && echo "File exists"
#run the echo command on  the remote server
ssh -q $HOST "[[ ! -f $FILE_PATH ]] && touch $FILE_PATH"
ssh -q $HOST "[[ ! -f $FILE_PATH ]] && touch $FILE_PATH"

#!/bin/bash
host='localhost'  # localhost as test case
file='~/.bash_history'
if `echo 'test -f '"${file}"' && exit 0 || exit 1' | ssh -q "${host}" sh`; then
#if `echo '[[ -f '"${file}"' ]] && exit 0 || exit 1' | ssh -q "${host}" bash`; then
   echo exists
else
   echo does not exist
fi

#!/bin/bash
ssh host "test -e /path/to/file"
if [ $? -eq 0 ]; then
    # your file exists
fi

#!/bin/bash
if ssh host "test -e /path/to/file"; then
    # your file exists
fi


#!/bin/bash
if ! ssh $USER@$HOST "test -e file.txt" 2> /dev/null; then
  echo "File not exist"
fi

#!/bin/bash
HOST="example.com"
FILE="/path/to/file"

if ssh $HOST "test -e $FILE"; then
    echo "File exists."
else
    echo "File does not exist."
fi

#!/bin/bash
USE_IP='-o StrictHostKeyChecking=no username@192.168.1.2'

FILE_NAME=/home/user/file.txt

SSH_PASS='sshpass -p password-for-remote-machine'

if $SSH_PASS ssh $USE_IP stat $FILE_NAME \> /dev/null 2\>\&1
            then
                    echo "File exists"
            else
                    echo "File does not exist"

fi
-----------------------------------------------------------------------------------------------------
#Shell Script to Check if Every Passed Argument is a File or Directory

#!/bin/sh
#Using -d option we are checking whether the first argument is a directory or not.
#$1 refers to the first argument
if [ -d $1 ]
then
        echo "The provided argument is the directory."
#Using -f option we are checking whether the first argument is a file or not.
elif [ -f $1 ]
then
        echo "The provided argument is the file."
#if the provided argument is not file and directory then it does not exist on the system.   
else
        echo "The given argument does not exist on the file system."
fi


# script empty parameter/argument check
if [ $# -eq 0 ]
then
            echo "Argument is required, e.g:sudo bash fileparam.sh <list.txt>"
                exit
        else
                    echo "Running script with additional argument $1 ..."
                    #Using -d option we are checking whether the first argument is a directory or not.
                    #$1 refers to the first argument
                    if [ -d $1 ]
                    then
                        echo "The provided argument  '$1' is a directory."
                    #Using -f option we are checking whether the first argument is a file or not.
                    elif [ -f $1 ]
                    then
                        echo "The provided argument '$1' is a file."
                    #if the provided argument is not file and directory then it does not exist on the system.
                    else
                        echo "The given argument '$1' does not exist on the file system."
                    fi

fi

-----------------------------------------------------------------------------------------------------
#date check

#!/bin/bash

# exit if today is not a Monday (and prevent locale issues by using the day number) 
if [ $(date +%u) != 1 ] ; then
  exit 0
fi

# exit if today is not the first Monday
if [ $(date +%d) -gt 7 ] ; then
  exit 0
fi
-----------------------------------------------------------------------------------------------------
#System information script, remote server ssh
#!/bin/bash
#A System Information Gathering Script

#logs file format logs/ dir
current_time=$(date "+%Y.%m.%d-%H.%M.%S")
log_file="sysinfo_$current_time.log"
#printf "Log File - Gathering information from remote from servers" > logs/$log_file
echo -e "Log File - Gathering information from remote from servers\n" > logs/$log_file


UNAME="uname -a"
echo -e "=====================================================\n">> logs/$log_file
echo -e "Gathering system information with the $UNAME command:\n">> logs/$log_file
#vg-ubuntu-02 entry in /etc/hosts
ssh vagrant@vg-ubuntu-02 "$UNAME" >> logs/$log_file

echo -e "===================================================== \n">> logs/$log_file
echo -e "Gathering system information with the hostnamectl command: \n">> logs/$log_file
#vg-ubuntu-02 entry in /etc/hosts
ssh vagrant@vg-ubuntu-02 "hostnamectl status" >> logs/$log_file
-----------------------------------------------------------------------------------------------------
#arithmetic expression

$ declare A=2+2 #the string-based type system has treated this as the declaration of some text
$ echo $A
2+2

$ declare -i A=2+2
$ echo $A
4
$ let A=2+2
$ echo $A
4

$ echo ${A}string #separate the variable’s name from the rest of the expression
2string

$ A=2;B=2 #get the value of an arithmetic operation, without declaring it as a variable, by putting it in double parentheses
$ echo $((A+B+1))
5

$ expr 2 + 3
5

-----------------------------------------------------------------------------------------------------
$ echo "scale=2;4/3" | bc #Bash can only do integer math
1.33
$ echo "for(i=1; i<=10; i++) {if (i % 2 == 0) i;}" | bc
$ echo "scale=4;sqrt(10)" | bc

$ cat decimal.sh
#!/bin/bash

x=6.5 #(example)
y=-7.5 #(example)
if [ $(echo "$x>=0.1 && $x<=5.5 && $y>=-5.9 && $y<=-0.1" | bc) -eq 1 ] ; then cat="good";
elif [ $(echo "$x>=5.5 && $x<=10.5 && $y>=-10.9 && $y<=-5.9" | bc) -eq 1 ]; then cat="bad";
fi
echo "$cat"

$ cat decimal_big.sh
#!/bin/bash

x=6.5 #(example)
y=-6.5 #(example)

boundsGood="0.1 5.5 -5.9 -0.1"
boundsBad="5.5 10.5 -10.9 -5.9"

# Paramaters in following order: x, y, xmin, xmax, ymin, ymax; bounds are inclusive.
function in_bounds {
    local x=$1
    local y=$2
    local x_min=$3
    local x_max=$4
    local y_min=$5
    local y_max=$6
    [ $(echo "$x >= $x_min && $x <= $x_max && $y >= $y_min && $y <= $y_max" | bc) -eq 1 ]
}

# Paramaters in following order: x, y, xmin, xmax, ymin, ymax; bounds are inclusive.
function in_bounds_alternative {
    [ $(printf "x = %f; y = %f; xmin = %f; xmax = %f; ymin = %f; ymax = %f; x >= xmin && x <= xmax && y >= ymin && y <= ymax\n" "$1" "$2" "$3" "$4" "$5" "$6" | bc) -eq 1 ]
}

if in_bounds $x $y $boundsGood ; then cat="good";
elif in_bounds $x $y $boundsBad ; then cat="bad";
fi
echo "$cat"


if in_bounds_alternative $x $y $boundsGood ; then cat="good";
elif in_bounds_alternative $x $y $boundsBad ; then cat="bad";
fi
echo "alternative $cat"

$ cat decimal_awk.sh
#!/bin/sh

x=3.5
y=-2.5
x="$x" y="$y" awk 'BEGIN{
        print ENVIRON["x"],ENVIRON["y"];
        if ((ENVIRON["x"] >= 0.1) && (ENVIRON["x"] <= 5.5) \
           && (ENVIRON["y"] >= -5.9) &&  (ENVIRON["y"] <= -0.1)){
              print "good";
        }
        else if ((ENVIRON["x"] >= 5.5) && (ENVIRON["x"] <= 10.5) \
           && (ENVIRON["y"] >= -10.9) &&  (ENVIRON["y"] <= -5.9)){
             print "bad";
        }

}'
$ bash decimal_awk.sh
3.5 -2.5
good
-----------------------------------------------------------------------------------------------------
#if condition string comparison

String Comparison 	Returns true (0) if:
[ str1 = str2 ] 	str1 equals str2
[ str1 != str2 ] 	str1 does not equal str2
[ str1 < str2 ] 	str1 precedes str2 in lexical order
[ str1 > str2 ] 	str1 follows str2 in lexical order
[ -z str1 ] 	str1 has length zero (holds null value)
[ -nstr1 ] 	str1has nonzero length (contains one or more characters

[[ a > b ]] || echo "a does not come after b"
[[ az < za ]] && echo "az comes before za"
[[ a = a ]] && echo "a equals a"
[[ a != b ]] && echo "a is not equal to b"

#conditional evaluation
[[ -n $var && -f $var ]] && echo "$var is a file"
[[ -b $var || -c $var ]] && echo "$var is a device"

#expression grouping 
[[ $var = img* && ($var = *.png || $var = *.jpg) ]] &&
echo "$var starts with img and ends with .jpg or .png" 

#Pattern matching 
[[ $name = a* ]] || echo "name does not start with an 'a': $name"

#RegularExpression matching
[[ $(date) =~ ^Fri\ ...\ 13 ]] && echo "It's Friday the 13th!"

#!/bin/bash
name=John
if [ $name = "John" ]
then
  echo "John is here !!!"
fi

# else if condition
#!/bin/bash

name=snoopy

if [ "$name" = "snoopy" ] then
	echo "It was a dark and stormy night."
elif [ "$name" == "charlie" ]
then
	echo "You’re a good man Charlie Brown."
elif [ "$name" == "lucy" ]
then
	echo "The doctor is in."
elif [ "$name" == "schroeder" ]
then
	echo "In concert." 
else
	echo "Not a Snoopy character."
fi
-----------------------------------------------------------------------------------------------------
#if condition range numeric comparison

Numeric Comparison 	Returns true (0) if:
[ $num1 -eq $num2 ] 	num1 equals num2
[ $num1 -ne $num2 ] 	num1 does not equal num2
[ $num1 -lt $num2 ] 	num1 is less than num2
[ $num1 -gt $num2 ] 	num1 is greater than num2
[ $num1 -le $num2 ] 	num1 is less than or equal to num2
[ $num1 -ge $num2 ] 	num1 is greater than or equal to num2

[[ 5 -gt 10 ]] || echo "5 is not bigger than 10"
[[ 8 -lt 9 ]] && echo "8 is less than 9"
[[ 3 -ge 3 ]] && echo "3 is greater than or equal to 3"
[[ 3 -le 8 ]] && echo "3 is less than or equal to 8"
[[ 5 -eq 05 ]] && echo "5 equals 05"
[[ 6 -ne 20 ]] && echo "6 is not equal to 20"

if [ "$number" -ge 2 ] && [ "$number" -le 5 ]; then
if [[ $number -ge 2 && $number -le 5 ]]; then

#using the arithmetic expression, ((...)) 
if ((number >= 2 && number <= 5)); then
  # your code
fi

if [ $(echo "$1 % 4" | bc) -eq 0 ]; then
if [[ $(( $1 % 4 )) == 0 ]]; then

#!/bin/bash
test=11
if [[ "$test" != [0-9] ]];then
   echo "not in range"
else
   echo "number within range"
fi

#!/bin/bash
#@file: trymod4.bash

if [ $(echo "$1 % 4" | bc) -eq 0 ]; then
  echo "$1 is evenly divisible by 4"
else
  echo "$1 is NOT evenly divisible by 4"
fi



#!/bin/bash
while :; do
  read -p "Enter a number between 2 and 5: " number
  [[ $number =~ ^[0-9]+$ ]] || { echo "Enter a valid number"; continue; }
  if ((number >= 2 && number <= 5)); then
    echo "valid number"
    break
  else
    echo "number out of range, try again"
  fi
done

echo "Enter number" 

#!/bin/bash
read input

  if [[ $input ]] && [ $input -eq $input 2>/dev/null ]

  then

        if ((input >= 1 && input <= 4)); then

    echo "Access Granted..."

    break

  else

    echo "Wrong code"

  fi

  else

     echo "$input is not an integer or not defined"

  fi


-----------------------------------------------------------------------------------------------------
#elif condition

#!/bin/bash
read -p "Enter marks: " marks
if [ $marks -ge 80 ]
then
  echo "Excellent"
 
elif [ $marks -ge 60 ]
then
  echo "Good"
 
else
  echo "Satisfactory"
fi

!/bin/bash
total=100
if [ $total -eq 100 ]
then
 echo "total is equal to 100"
elif [ $total -lt 100 ]
then
 echo "total is less than 100"
else
 echo "total is greater than 100"
fi


$ cat range.sh
#!/bin/bash

#debug
#number=20 #warning
number=40 #critical
#number=5 #normal

MEMORY_WARNING_THRESHOLD=10
MEMORY_CRITICAL_THRESHOLD=30

if [[ "$number" -ge $MEMORY_WARNING_THRESHOLD ]] && [[ "$number" -le $MEMORY_CRITICAL_THRESHOLD ]];
then
        echo -e "WARNING..:$number less than MEMORY_CRITICAL_THRESHOLD $MEMORY_CRITICAL_THRESHOLD \n\
        and bigger than MEMORY_WARNING_THRESHOLD $MEMORY_WARNING_THRESHOLD"

elif  [[ "$number" -ge $MEMORY_CRITICAL_THRESHOLD ]]
then
        echo "CRITICAL..:$number bigger than MEMORY_WARNING_THRESHOLD $MEMORY_CRITICAL_THRESHOLD"
else
        echo "NORMAL....:$number less than MEMORY_WARNING_THRESHOLD $MEMORY_WARNING_THRESHOLD"
fi
#The script assigns the value of $1 to the year variable.
#!/bin/bash

if [ $# -ne 1 ] # "$#" If number of argument passed to the script is not equal to one
then
	echo "You need to enter the year."
	exit 1 
fi

year=$1

if [ $[$year % 400] -eq "0" ]
then
	echo "$year is a leap year!" 
elif [ $[$year % 4] -eq 0 ]
then
	if [ $[$year % 100] -ne 0 ]
	then
		echo "$year is a leap year!"
	else
		echo "$year is not a leap year."
	fi
else
	echo "$year is not a leap year."
fi

$ cat num.sh
#!/bin/bash
num=150
if [[ $num -gt 100 ]] && [[ $num -lt 200 ]]
then
        echo "The number lies between 100 and 200"
fi
-----------------------------------------------------------------------------------------------------
#check whether a certain file path is a directory

#!/bin/bash
if [ -d "/tmp" ] ; then
    echo "/tmp is a directory"
else 
    echo "/tmp is not a directory"
fi

#!/bin/bash
FILE="/etc/docker"
if [ -d "$FILE" ]; then
    echo "$FILE is a directory."
fi
-----------------------------------------------------------------------------------------------------
#The test command includes the following FILE operators

-b FileName 	Returns a True exit value if the specified FileName exists and is a block special file.
-c FileName 	Returns a True exit value if the specified FileName exists and is a character special file.
-d FileName 	Returns a True exit value if the specified FileName exists and is a directory.
-e FileName 	Returns a True exit value if the specified FileName exists.
-f FileName 	Returns a True exit value if the specified FileName exists and is a regular file.
-g FileName 	Returns a True exit value if the specified FileName exists and its Set Group ID bit is set.
-h FileName 	Returns a True exit value if the specified FileName exists and is a symbolic link.
-k FileName 	Returns a True exit value if the specified FileName exists and its sticky bit is set.
-L FileName 	Returns a True exit value if the specified FileName exists and is a symbolic link.
-n String1 	Returns a True exit value if the length of the String1 variable is nonzero.
-p FileName 	Returns a True exit value if the specified FileName exists and is a named pipe (FIFO).
-r FileName 	Returns a True exit value if the specified FileName exists and is readable by the current process.
-S filename - Check if file is socket
-s FileName 	Returns a True exit value if the specified FileName exists and has a size greater than 0.
-t FileDescriptor 	Returns a True exit value if the file with a file descriptor number of FileDescriptor is open and associated with a terminal.
-u FileName 	Returns a True exit value if the specified FileName exists and its Set User ID bit is set.
-w FileName 	Returns a True exit value if the specified FileName exists and the write flag is on. However, the FileNamewill not be writable on a read-only file system even if test indicates true.
-x FileName 	Returns a True exit value if the specified FileName exists and the execute flag is on. If the specified file exists and is a directory, the True exit value indicates that the current process has permission to search in the directory.
-z String1 	Returns a True exit value if the length of the String1 variable is 0 (zero).

#Check if File Exists,FILE operators are -e and -f

FILE=/etc/resolv.conf
if test -f "$FILE"; then
    echo "$FILE exists."
fi

FILE=/etc/resolv.conf
if [ -f "$FILE" ]; then
    echo "$FILE exists."
fi

FILE=/etc/resolv.conf
if [[ -f "$FILE" ]]; then
    echo "$FILE exists."
fi

FILE=/etc/resolv.conf
if [ -f "$FILE" ]; then
    echo "$FILE exists."
else 
    echo "$FILE does not exist."
fi

#Negate the exit status with bash
if ! [ -e "$file" ]; then
    echo "file does not exist"
fi

#Negate the test inside the test command [
if [ ! -e "$file" ]; then
    echo "file does not exist"
fi

#The test command has a "not" logical operator which is the exclamation point
if [[ ! -f $FILE ]]; then
    if [[ -L $FILE ]]; then
        printf '%s is a broken symlink!\n' "$FILE"
    else
        printf '%s does not exist!\n' "$FILE"
    fi
fi

-----------------------------------------------------------------------------------------------------
# "$#" in the function f expands to the number of arguments passed to the function

#!/bin/sh

f() {
    echo "$#"
}

f a b c

# In check_args, $# expands to the number of arguments passed to the function itself, which in that script is always 0.
#!/bin/sh

check_args() { # doesn't work!
    if [ "$#" -ne 2 ]; then
        printf '%s: error: need 2 arguments, got %d\n' "$0" "$#" >&2
        exit 1
    fi
}

# script argument check
if [ $# -eq 0 ]
then
    echo "Argument is required, e.g:sudo bash mon.sh <list.txt>"
    exit
elif [ $# -gt 1 ]
then
    echo "One argument is required, e.g:sudo bash mon.sh <list.txt>"
    exit
else
    echo "Running script with additional parameter $1 ..."
fi

-----------------------------------------------------------------------------------------------------
# Other "#" uses in Bash
myvar="some string"; echo ${#myvar} #find the length of a string
myArr=(A B C); echo ${#myArr[@]} #find the number of array elements
myArr=(A B C); echo ${#myArr[0]} #find the length of the first array element
-----------------------------------------------------------------------------------------------------
#run script within script

#!/bin/bash
SCRIPT_PATH="/path/to/script.sh"

# Here you execute your script
"$SCRIPT_PATH"

# or
. "$SCRIPT_PATH"

# or
source "$SCRIPT_PATH"

# or
bash "$SCRIPT_PATH"

# or
eval '"$SCRIPT_PATH"'

# or
OUTPUT=$("$SCRIPT_PATH")
echo $OUTPUT

# or
OUTPUT=`"$SCRIPT_PATH"`
echo $OUTPUT

# or
("$SCRIPT_PATH")

# or
(exec "$SCRIPT_PATH")

# fetch the output of the producer script as an argument on the consumer script.
$ ./script-that-consumes-argument.sh `sh script-that-produces-argument.sh`
-----------------------------------------------------------------------------------------------------
readarray -t lines < file.txt
count=${#lines[@]}

for i in "${!lines[@]}"; do
    index=$(( (i * 12 - 1) / count + 1 ))
    echo "${lines[i]}" >> "file${index}.txt"
done

awk '{
    a[NR] = $0
}
END {
    for (i = 1; i in a; ++i) {
        x = (i * 12 - 1) / NR + 1
        sub(/\..*$/, "", x)
        print a[i] > "file" x ".txt"
    }
}' 

-----------------------------------------------------------------------------------------------------
#Reading file by omitting backslash escape
#!/bin/bash
while read -r line; do
# Reading each line
echo $line
done < company2.txt
-----------------------------------------------------------------------------------------------------
#Passing filename from the command line and reading the file
#!/bin/bash
filename=$1
while read line; do
# reading each line
echo $line
done < $filename
-----------------------------------------------------------------------------------------------------
#Reading file content line by line 

#!/bin/bash
filename='company.txt'
n=1
while read line; do
# reading each line
echo "Line No. $n : $line"
n=$((n+1))
done < $filename
-----------------------------------------------------------------------------------------------------
IFS stands for "internal field separator" used by the shell to determine how to do word splitting
IFS=$'\n'
-----------------------------------------------------------------------------------------------------
#remove whitespaces from variables
k=`echo $k | sed 's/ *$//g'` #remove whitespaces
$ echo " Bash Scripting Language " | xargs # Remove the spaces from the string data using `xargv`
$ Var=`echo $Var | sed -e 's/^[[:space:]]*//'` #Remove the spaces from the variable
$ myVar=`echo $myVar | sed 's/ *$//g'` # The following `sed` command will remove the trailing spaces from the variable
$ echo "Hello ${myVar##*( )}" # The following command will print the output after removing the spaces from the beginning of the variable, $myVar
$ echo "${myVar%%*( )} is welcome to our site"  #The following command will print the output after removing the spaces from the ending of the variable, $myVar

#store lines as variables,use bash
#remove leading whitespace from a string
shopt -s extglob
printf '%s\n' "${text##+([[:space:]])}"
#remove trailing whitespace from a string
shopt -s extglob
printf '%s\n' "${text%%+([[:space:]])}"
#remove all whitespace from a string
printf '%s\n' "${text//[[:space:]]}"



-----------------------------------------------------------------------------------------------------
#Reading file content line by line 

#IFS= (or IFS='') prevents leading/trailing whitespace from being trimmed
#-r prevents backslash escapes from being interpreted.
#!/bin/bash
while IFS= read -r line; do
    #echo "Text read from file: $line"
    echo "$line"
done < company.txt
-----------------------------------------------------------------------------------------------------
#Reading file content line by line 

$ cat 1_fileread.sh
#!/bin/sh
echo "reading line by line"

#http://mywiki.wooledge.org/BashFAQ/001
file=$1
while IFS= read -r line; do
        printf '%s \n' "$line" #line is a variable name, use any valid shell variable name(s)
done < "$file" #< "$file" redirects the loop's input from a file whose name is stored in a variable
$ bash 1_fileread.sh ids.txt
-----------------------------------------------------------------------------------------------------
#Reading file content line by line into an array

$ cat arrayfileread.sh
#!/bin/sh
echo "reading file into array"

filename=$1
arr=()
while IFS= read -r line; do
          arr+=("$line")
done < $filename
echo ${arr[@]} # all array members
$ bash arrayfileread.sh ids.txt
-----------------------------------------------------------------------------------------------------
#Reading file content line by line into an array

$ cat mapfilearrayfileread.sh
#!/bin/sh
echo "reading file into array"

filename=$1
echo "reading file..: $filename"
mapfile lines < $filename
#echo  ${lines[@]} #print all array members

for i in "${lines[@]}"; do
        echo "element: $i"
done
$ bash mapfilearrayfileread.sh ids.txt
-----------------------------------------------------------------------------------------------------
#Reading file content line by line into an array

mapfile -t lines < <(some command)
$ mapfile arr < <(printf "Item 1\nItem 2\nItem 3\n")
$ echo  ${arr[@]}
$ mapfile arr2 < <(cat ids.txt)
$ echo  ${arr2[@]}
mapfile -t lines <myfile
$ mapfile lines < ids.txt
$ mapfile -n 2 arr < example.txt # Read the specified number of lines using -n

$ mapfile -t lines < ids.txt #Strip newlines and store item using -t
$ echo ${lines[@]} # all array members
$ echo ${lines[0]} # 1st member
$ echo ${lines[1]} # 2nd member

#one liner
$ filename="ids.txt" && echo $filename && mapfile arr < $filename && echo  ${arr[@]}}
-----------------------------------------------------------------------------------------------------
# Create a dummy file
echo -e "1\n2\n3\n4" > testfile.txt

# Loop through and read two lines at a time
while read -r ONE; do
    read -r TWO
    echo "ONE: $ONE TWO: $TWO"
done < testfile.txt

# Create a dummy variable
STR=$(echo -e "1\n2\n3\n4")

# Loop through and read two lines at a time
while read -r ONE; do
    read -r TWO
    echo "ONE: $ONE TWO: $TWO"
done <<< "$STR"
-----------------------------------------------------------------------------------------------------
#!/bin/bash

del=$(date --date="90 days ago" +%Y%m%d)
for i in `find . -type d -name "2*"`; do
  (($del > $(basename $i))) && echo "delete $i" || echo "dont delete $i"
  #(($del > $(basename $i)))  && rm -rf $i #uncommen to delete
done

-----------------------------------------------------------------------------------------------------
# Delete streams in kurento older than N days

#!/bin/bash

history=5

for app in recordings screenshare; do
        app_dir=/var/kurento/$app
        if [[ -d $app_dir ]]; then
                find $app_dir -name "*.mkv" -o -name "*.webm" -mtime +$history -delete
                find $app_dir -type d -empty -mtime +$history -exec rmdir '{}' +
        fi
done

-----------------------------------------------------------------------------------------------------
#!/bin/bash

#move files from current dir
dir=$(pwd)

for i in $(find $dir -newermt "2022-03-22" ! -newermt "2022-03-23"); do
  mv $i /tmp
done
-----------------------------------------------------------------------------------------------------
#find creation/birth dates of files

#!/bin/bash
disk=$(df -Th . | grep ext4  |awk '{print $1}')
dir=$(pwd)

for file in $dir/*
do
    crtime=$(debugfs -R "stat $file" $disk 2>/dev/null | grep crtime |  awk -F'-- ' '{print $2}' | awk '{print $2,$3,$5,$4}')
     printf "$crtime\t$file\n"
done | sort -k4 | sort -n -k 3 -k 1M -k2 -k4

#! /bin/bash
from='2022-03-01 00:00:00.0000000000' # 01-Mar-22
to='2022-03-31 23:59:59.9999999999'   # 31-Mar-22

for file in * ; do
    crtime=$( stat -c%w "$file" )
    if [[ $from < $crtime && $crtime < $to ]] ; then
        echo "$crtime $file"
    fi
done

-----------------------------------------------------------------------------------------------------
#!/bin/bash
set -euox pipefail #safety for script

    if [[ $(hostname) == "node1" ]] && [[ ! -f "$kubernetes_release" ]]; then
        kubectl version --short
    fi

-----------------------------------------------------------------------------------------------------
#!/bin/bash
set -euox pipefail #safety for script
if [[ $(lsb_release -rs) == "18.04" ]]; then #check if virtualization is supported on Linux, xenial fails w 0, bionic works w 2
       echo "virtualization is supported"
       #Copy your files here
else
       echo "virtualization is not supported"
fi
-----------------------------------------------------------------------------------------------------
#!/bin/bash
set -euox pipefail #safety for script

if [[ $(egrep -c '(vmx|svm)' /proc/cpuinfo) == 0 ]]; then
         echo "virtualization is not supported"
else
      echo "===================================="
      echo eval "$(egrep -c '(vmx|svm)' /proc/cpuinfo)" 2>/dev/null
      echo "===================================="
      echo "virtualization is not supported"
fi    
-----------------------------------------------------------------------------------------------------
#compare  if two files have the same contents

STATUS="$(cmp --silent $FILE1 $FILE2; echo $?)"  # "$?" gives exit status for each comparison

if [[ $STATUS -ne 0 ]]; then  # if status isn't equal to 0, then execute code
    DO A COMMAND ON $FILE1
else
    DO SOMETHING ELSE
fi

#compare  if two files have the same contents
if cmp --silent -- "$FILE1" "$FILE2"; then
  echo "files contents are identical"
else
  echo "files differ"
fi

#compare  if two files have the same contents,compare by checksum algorithm like sha256
sha256sum oldFile > oldFile.sha256
echo "$(cat oldFile.sha256) newFile" | sha256sum --check
newFile: OK

#returns 1 on difference and 0 on no difference
if diff file1 file2 > /dev/null
then
    echo "No difference"
else
    echo "Difference"
fi

# return status 0 if they are the same, and 1 if different
diff -s file1 file2 ; 
if [[ $? ==0 ]] ; then
  echo 'files are the same'
else
  echo 'files are different'
fi

#not using the []  brackets
if netstat -lntp | grep ':8080.*java' > /dev/null; then
    echo "Found a Tomcat!"
fi

#$(<command>) command substitution,use the bash [[ conditional construct
if [[ $(netstat -lnp | grep ':8080') = *java* ]]; then
  echo "Found a Tomcat!"
fi

if [[ $(HEAD mycompany-intranet.com | grep '200\ OK' | wc -l) = "1" ]];  then
    echo doing some intranet settings (proxy, etc)
else
    echo doing some work-at-home settings (proxy, etc)
fi


#use the cksum command
chk1=`cksum <file1> | awk -F" " '{print $1}'`
chk2=`cksum <file2> | awk -F" " '{print $1}'`

if [ $chk1 -eq $chk2 ]
then
  echo "File is identical"
else
  echo "File is not identical"
fi
-----------------------------------------------------------------------------------------------------
#Read commands but do not execute them. This may be used to check a script for syntax errors,noexec mode
$ bash -n ./unity_check.sh 

bash -x # runs the script <file> with tracing of each command executed, xtrace
bash -x -c ls -lai #run a command in BASH, use -c option
test -x <file> #tests whether <file> has execute permissions for the current user

#bash -e, if any command in the script fails (i.e. returns a non-zero exist status), then the whole script immediately fails.
#errexit
bash -e myScript
------------------------------------------------------------------------------------------
$(command)        	#Command Substitution 
(list) 		  	#Group commands in a subshell: ( )
{ list; } 	  	#Group commands in the current shell: { }
[[ expression ]]  	#Test - return the binary result of an expression: [[ ]]
$(( expression )  	#Arithmetic expansion The format for Arithmetic expansion is
(( expr1 && expr2 )) 	#Combine multiple expressions ( expression )

# the difference between test, [ and [[ used to evaluate expressions
# [ (aka test) command
# [ is a synonym for test (but requires a final argument of ]
# [ and test are POSIX utilities (generally builtin)
# test implements the old, portable syntax of the command
# If portability/conformance to POSIX or the BourneShell is a concern, the old syntax should be used

# [[ ... ]] test construct 
# [[ ... ]] works only in the Korn shell (where it originates), Bash, Zsh, and recent versions of Yash and busybox 
# [[ is a new, improved version,a keyword rather than a program
# If the script requires BASH, Zsh, or KornShell, the new syntax is usually more flexible, but not necessarily backwards compatible

#comparing [] vs [[ ]]
$ file="test.doc" #somefile that does not exists

$  [ -f "$filename" ] || printf 'File does not exist or is not a regular file: %s\n' "$filename" >&2
File does not exist or is not a regular file:

$ if [[ ! -e $file ]]; then \
> echo "File doesn't exist or is in an inaccessible directory or is a symlink to a file that doesn't exist." >&2 ;
> fi
File doesn't exist or is in an inaccessible directory or is a symlink to a file that doesn't exist.


$ time for ((i=0; i<100000; i++)); do [ "$i" = 1000 ]; done #Operating System: Ubuntu 21.10

real    0m0.896s
user    0m0.896s
sys     0m0.000s
$ time for ((i=0; i<100000; i++)); do [ "$i" = 1000 ]; done #Operating System: CentOS Stream 8

real    0m1.065s
user    0m0.970s
sys     0m0.000s


$ time for ((i=0; i<100000; i++)); do [[ "$i" = 1000 ]]; done #Operating System: Ubuntu 21.10

real    0m0.663s
user    0m0.663s
sys     0m0.000s
$ time for ((i=0; i<100000; i++)); do [[ "$i" = 1000 ]]; done  #Operating System: CentOS Stream 8

real    0m0.763s
user    0m0.695s
sys     0m0.000s
------------------------------------------------------------------------------------------
#Busybox shell,check busybox version 
#BusyBox is an open source (GPL) project providing simple implementations of nearly 400 common commands, 
#including ls, mv, ln, mkdir, more, ps, gzip, bzip2, tar, and grep. It also contains a version of the programming 
#language awk, the stream editor sed, the filesystem checker fsck, the rpm and dpkg package managers

apt/yum/pacman/dnf/zypper install busybox # method1
#method2
wget https://busybox.net/downloads/binaries/1.31.0-defconfig-multiarch-musl/busybox-x86_64 && \
mv busybox-x86_64  busybox && chmod +x busybox 
#method2
docker pull busybox && docker run -it --rm busybox #Run a container from the image and enter the BusyBox shell

which busybox
$ busybox sh # switch to busybox shell
$ busybox command
$ busybox --list
$ busybox --list | wc -l
$ busybox ping -c google.com
# busybox vi index.html
<!DOCTYPE html>
<html>
<body>
Welcome to BusyBox !
</body>
</html>

chsh -s $(which busybox) #set zsh as the default shell
chsh -s $(which bash) # revert to Bash

~ $ busybox echo $0
sh
busybox | head -1
~ $ busybox ls --help

if ps ax -o pid,comm | grep `echo $$` | grep busybox ; then
    echo "it is BusyBox"
fi

#!/bin/ash
exe=`exec 2>/dev/null; readlink "/proc/$$/exe"`
case "$exe" in
*/busybox)
    echo "It's a busybox shell."
    ;;
esac
~ $ sudo ln -s /bin/busybox /bin/ash #The program busybox will act as a shell if linked with the name ash
~ $ ./test.sh
It's a busybox shell.

#!/bin/ash

domain="mydomain.com"
record="11019653"
api_key="key1234"

ip="$(curl http://ipecho.net/plain)"

content="$(curl \
-k \
-H "Authorization: Bearer $api_key" \
-H "Content-Type: application/json" \
-d '{"data": "'"$ip"'"}' \
-X PUT "https://api.digitalocean.com/v2/domains/$domain/record/$record")"

echo "$content"

------------------------------------------------------------------------------------------
#zsh shell (Z-Shell)
apt/yum/pacman/dnf/zypper install zsh

zsh --version
chsh -s $(which zsh) #set zsh as the default shell
chsh -s $(which bash) # revert to Bash
------------------------------------------------------------------------------------------
#KSH ( Korn Shell ) get the version of ksh
apt/yum/pacman/dnf/zypper ksh zsh


[1]$ ksh --version
  version         sh (AT&T Research) 93u+ 2012-08-01
[4]$ echo ${.sh.version}
Version AJM 93u+ 2012-08-01
[3]$ echo $KSH_VERSION
Version AJM 93u+ 2012-08-01
[2]$ strings /bin/ksh | grep Version | tail -2
@(#)$Id: Version AJM 93u+ 2012-08-01 

chsh -s $(which zsh) #set zsh as the default shell
chsh -s $(which ksh93) # revert to Bash

echo $SHELL #Logout,login,verify

#!/bin/ksh
if whence -a whence > /dev/null; then
   echo "using modern version of KSH."
else
  echo "using an older version of KSH."
fi
~ [10]$ chmod +x test.ksh
~ [11]$ ./test.ksh
using modern version of KSH.

#!/bin/ksh
# Name: userinfo.ksh


# set variables 
FILE="/etc/passwd"
NOW="$(date)"
HOSTNAME="`hostname`"
USERS_ACCOUNT="$(wc -l $FILE)"
 
# Greet user
print "Hi, $USER. I'm $0. I'm $SHELL script running on $HOSTNAME at $NOW." 
print 
print "*** User accounts: $USERS_ACCOUNT"
print "*** Current working directory: $PWD"
 
print "*** Running for loop test just for fun:"
for x in {1..3}
do
    print "Welcome $x times."
done
~ [10]$ chmod +x test.ksh
~ [11]$ ./test.ksh
------------------------------------------------------------------------------------------
#A subshell can access the global variables set by the 'parent shell' but not the local variables
#Any changes made by a subshell to a global variable is not passed to the parent shell.

$ cat script.sh
echo $var
$ var=LBH
$ echo $var
LBH
$ bash script.sh # The script doesn't see the value of variable var

$ export var=LBG
$ echo $var
LBG
$ bash script.sh #Shell scripts run in subshell (by default)
LBG

$ bash #start new shell
$ exit #exit new shell

#commands from the script are executed by the current shell 
#as if they were typed into terminal instead of being run via a script in a subshell.
#Scripts can access the local variables
$ . script #not the same as running a shell script like this ./script

#different subshell syntaxes, namely $() and back-tick surrounded statements
# ' indicates literal, 
# " indicates that the string will be parsed for subshells and variables

# ' single quotes. This resulted in our subshell command,
#inside the single quotes, to be interpreted as literal text instead of a command
$ echo '$(echo 'a')'
$(echo a)

# " and thus the string is parsed for actual commands and variables
#subshell is being started,with subshell syntax ($()),
#the command inside the subshell (echo 'a') is being executed literally,an a is produced
#then inserted in the overarching / top level echo
#The command at that stage can be read as echo "a" and thus the output is a
$ echo "$(echo 'a')"
a

#echo the letter b inside the subshell,
#this is joined on the left and the right by the letters a and c yielding the overall output to be abc
$ echo "a`echo 'b'`c"
abc

#subshell syntax of using back-ticks instead of $()
$ echo "a$(echo 'b')c"
abc

#Double quotes inside subshells and sub-subshells,a subshell can be nested inside another subshell
echo "$(echo "$(echo "it works")" | sed 's|it|it surely|')"
 
#prints 1 because the subshell is a replication of the shell that spawned it
$ x=1
$ (echo $x)
1

# run a shell as a child process of a shell
$ x=1
$ sh -c 'echo $x'

# run a shell as a child process of a shell
$ x=1
$ perl -le 'print $x'                                                                                             1 ⨯

# run a shell as a child process of a shell
$ x=1
$ python -c 'print x'
Traceback (most recent call last):
  File "<string>", line 1, in <module>
NameError: name 'x' is not defined
------------------------------------------------------------------------------------------
# exit.sh to test exit codes
#!/bin/bash
exit 1
------------------------------------------------------------------------------------------
bash exit.sh
echo $?
1
-----------------------------------------------------------------------------------------------------
cat 'doesnotexist.txt' 2>/dev/null || exit 0 #suppress exit status (exit code)
cat file.txt || exit 0

 cat filecheck.sh
#!/bin/bash

cat file.txt

if [ $? -eq 0 ]
then
  echo "The script ran ok"
  exit 0
else
  echo "The script failed" >&2
  exit 1
fi

$ bash -n filecheck.sh
$ bash -xe filecheck.sh

#set an exit code in a script
$ cat exit.sh
#!/bin/bash

exit 1
$ bash -ex exit.sh
+ exit 1
----------------------------------------------------------------------------------------------------
#export variable
export VAR="HELLO, VARIABLE"
echo $VAR
-----------------------------------------------------------------------------------------------------
#export variable

# cat env.vars
foo=test

eval `cat env.vars`
echo $foo 
export eval `cat env.vars`
echo $foo 
export -- `cat env.vars`
echo $foo 
-----------------------------------------------------------------------------------------------------
#echo a line of bash to a file without executing
touch /home/file.sh
echo "#!/bin/bash" >> /home/file.sh
echo "for line in \$(grep -o 'guest-......' /etc/passwd | sort -u); do sudo deluser \$line; done" >> /home/file.sh

------------------------------------------------------------------------------------------
shell script
$0 represent the shell script file name itself
$1 Starting with $1, are actual command line arguments sent to the shell script.
------------------------------------------------------------------------------------------
 clear your bash history
>~/.bash_history
Another option is link ~/.bash_history to /dev/null
ln -sf /dev/null ~/.bash_history
-------------------------------------------------------------------------------------------------------------------------------------------------
# remote public github content run
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install.sh)"
-------------------------------------------------------------------------------------------------------------------------------------------------
#-c string If  the  -c  option  is  present, then commands are read from string.
#If there are arguments after the  string,  they  are assigned to the positional parameters, starting with $0.

/bin/sh -c 'curl -L https://istio.io/downloadIstio | sh -' #single quotes
/bin/sh -eu -xv -c 'cmd1 | cmd2' #debug.
-------------------------------------------------------------------------------------------------------------------------------------------------
#!/bin/sh

# bash lvm-create-vol.sh 3 1
# pvdisplay --- Physical volume ---
# vgdisplay --- Volume group ---
# lvdisplay --- Logical volume ---
VOL_GROUP="vgvagrant"  #Defines the volume group to create volumes on
if [ $1 ];
then
    VOLUMES=$1;
else
    echo "Number of volumes ";
    exit;
fi

if [ $2 ];
then
    SIZE=$2;
else
    echo "Size of volumes in (GB)";
    exit;
fi

VOL=0
while [ $VOL -lt $VOLUMES ];
do
    #create volumes
    lvcreate -L $SIZE -n vol$VOL $VOL_GROUP;
    VOL=$(( $VOL  1 ));
done

-------------------------------------------------------------------------------------------------------------------------------------------------
#Syntax for Command Substitution
#The old-style uses backticks (also called backquotes) to wrap the command being substituted
#The new style begins with a dollar sign and wraps the rest of the command in parenthesis

#using the output of one command as an argument to another command
$ today=$(date +%d-%b-%Y) && echo $today
$ echo "Today is $(date +%d-%b-%Y)"
#The inner command, rpm -qa | grep httpd, lists all the packages that have httpd in the name
#The outer command, rpm -ql, lists all the files in each package
$ rpm -ql $(rpm -qa | grep httpd)
-------------------------------------------------------------------------------------------------------------------------------------------------
# not a separate external command, but rather a shell built-in
#takes a string as its argument, and evaluates it as if it s typed on a command line
$ COMMAND="ls -lrt"
vagrant@vagrant:~$ eval $COMMAND

#This command can be used in any script also where the variable name is unknown until executing the script. 
#In bash, however, this can be accomplished with variable indirection using the syntax
${!varname}

$ cat tryeval.sh
#!/bin/bash
#Initialize the variable x and y
x=5
y=15

#The first command variable is used to assign `expr` command to add the values of $x and $y
c1="`expr $x + $y`"

#The second command variable is used to assign `echo` command
c2="echo"

#`eval` will calculate and print the sum of $x and $y by executing the commands of $c1 and $c2 variables
eval $c2 $c1
$ bash tryeval.sh
20


-------------------------------------------------------------------------------------------------------------------------------------------------
#from windows to linux copy problem fix
$ make
Makefile:21: *** missing separator.  Stop.
$ perl -pi -e 's/^  */\t/' Makefile

# unix/windows file editing
"/bin/bash^M: bad interpreter: No such file or directory"
fix:  sed -i -e 's/\r$//' build_all.sh
-------------------------------------------------------------------------------------------------------------------------------------------------
#Makefile gnu fortran
F90 = gfortran
TARGET=ff
OBJECTS = $(TARGET).o
FCFLAGS = -Ofast -g -pg -fbounds-check

#all: clean run

#compile
$(TARGET): $(OBJECTS)
	$(F90) $(FCFLAGS) -o $(TARGET) $(OBJECTS)
%.o: %.f90
	$(F90) $(FCFLAGS) -c $^
run:
	./$(TARGET)
	gprof $(TARGET) gmon.out > ff_analysis.txt

.PHONY:clean

clean:
	rm -rf $(TARGET) $(OBJECTS) *.out *.o
-------------------------------------------------------------------------------------------------------------------------------------------------
# The double-bracket syntax serves as an enhanced version of the single-bracket syntax
# the double-bracket syntax features shell globbing.if $stringvar contains the phrase “string” anywhere, the condition will return true. 
if [[ "$stringvar" == *string* ]]; then
#match both “String” and “string”, use the following syntax
#only general shell globbing is allowed. Bash-specific things like {1..4} or {foo,bar} does not work. 
if [[ "$stringvar" == *[sS]tring* ]]; then
#The second difference is that word splitting is prevented. omit placing quotes around string variables
if [[ $stringvarwithspaces != foo ]]; then

#without the double-bracket syntax
if [ -a *.sh ]; then 
#return true if there is one single file in the working directory that has a .sh extension.
return false,If there are none
hrow an error and stop executing the script,If there are several .sh files,because *.sh is expanded to the files in the working directory
#with the double-bracket syntax
if [[ -a *.sh ]]; then
#return true if there is a file in the working directory called “*.sh

#the double-bracket syntax allows regex pattern matching using the “=~” operator.
#the and operator has precedence over the or operator, meaning that “&&” or “-a” will be evaluated before “||” or “-o”.
#returns true if $num is equal to 3 and $stringvar is equal to “foo”.
if [[ $num -eq 3 && "$stringvar" == foo ]]; then

#Double-parenthesis syntax
#true if $num is less than or equal to 5.
if (( $num <= 5 )); then

-------------------------------------------------------------------------------------------------------------------------------------------------
if ! [ -e "/var/run/postgresql/*.pid" ]
then
    /etc/init.d/postgresql start
fi
-------------------------------------------------------------------------------------------------------------------------------------------------
$ cat prog.sh
Number=5
while [[ $Number -gt 1 ]]
do
    printf "$Number\n"
    ((Number -= 1 ))
done
-------------------------------------------------------------------------------------------------------------------------------------------------
$ cat updateVulnDBs.sh
#!/bin/bash

declare -a databases=("cve" "exploitdb" "openvas" "osvdb" "scipvuldb" "securityfocus" 
                      "securitytracker" "xforce")

for DB in "${databases[@]}"; do
    wget https://www.computec.ch/projekte/vulscan/download/${DB}.csv
done
-------------------------------------------------------------------------------------------------------------------------------------------------
# terminate the SSH agent

#!/bin/bash

## in .bash_profile

SSHAGENT=`which ssh-agent`
SSHAGENTARGS="-s"
if [ -z "$SSH_AUTH_SOCK" -a -x "$SSHAGENT" ]; then
    eval `$SSHAGENT $SSHAGENTARGS`
    trap "kill $SSH_AGENT_PID" 0
fi

## in .logout

if [ ${SSH_AGENT_PID+1} == 1 ]; then
    ssh-add -D
    ssh-agent -k > /dev/null 2>&1
    unset SSH_AGENT_PID
    unset SSH_AUTH_SOCK
fi
-------------------------------------------------------------------------------------------------------------------------------------------------
#run's the ssh-agent(each run new ssh-agent,not the same ssh-agent) for the current shell, adds a key to it and runs two git commands,

#!/bin/bash
eval "$(ssh-agent -s)"
SSH_AGENT_PID=$(pgrep -u $USER -n ssh-agent)
echo $SSH_AGENT_PID
ssh-add /home/sshuser/.ssh/id_rsa

git --version
#git -C /var/www/barak/ reset --hard origin/master
#git -C /var/www/barak/ pull origin master

-------------------------------------------------------------------------------------------------------------------------------------------------
#empty variable check

        #empty var check
        if [ -z "$i" ];then #meeting id empty
                echo -e "meeting id empty \n"
                exit
        elif [ -z "$k" ];then #directory list empty
                echo -e " directory list empty \n"
                exit
        fi
-------------------------------------------------------------------------------------------------------------------------------------------------
#boolean variable check

#!/bin/bash

# Using “true” or “false” for declaring boolean values

#Take the username

echo "Enter username:"

read username

#Take the password

echo "Enter password:"

read password

administrator="false"

#Check username and password

if [[ $username == "admin" && $password == "secret" ]]; then

        #Set "true" for valid user

        valid="true"

        #Set "true" for administrator

        administrator="true"

elif [[ $username == "fahmida" && $password == "67890" ]]; then

        #Set "true" for valid user

        valid="true"

else

        #Set "false" for invalid user

        valid="false"

fi


#Print message based on the values of $valid and $administrator variables

if [[ $valid == "true" && $administrator == "true" ]]; then

        echo "Welcome Administrator."

elif [[ $valid == "true" && $administrator == "false" ]]; then

        echo "Welcome $username."

else

        echo "Username or Password is invalid."

fi

$ cat bool.sh
#!/bin/bash

        #FLAG_FOUND_FILE="false"
        FLAG_FOUND_FILE="true"
        echo "flag FLAG_FOUND_FILE set to..: $FLAG_FOUND_FILE"
        if [ "$FLAG_FOUND_FILE" = true ]; then
                echo -e "flag FLAG_FOUND_FILE :$FLAG_FOUND_FILE"
        else
                echo -e "flag FLAG_FOUND_FILE :$FLAG_FOUND_FILE"
        fi

-------------------------------------------------------------------------------------------------------------------------------------------------
#monitor cpu ram etc

# crontab -e
*/5 * * * * /bin/bash /opt/scripts/memory-alert.sh

# sudo chmod +x /opt/scripts/memory-alert.sh
# ./opt/scripts/memory-alert.sh#test

# vi /opt/scripts/memory-alert.sh

#!/bin/sh
ramusage=$(free | awk '/Mem/{printf("RAM Usage: %.2f\n"), $3/$2*100}'| awk '{print $3}')

if [ "$ramusage" > 20 ]; then

 SUBJECT="ATTENTION: Memory Utilization is High on $(hostname) at $(date)"
 MESSAGE="/tmp/Mail.out"
 TO="2day@gmail.com"
 echo "Memory Current Usage is: $ramusage%" >> $MESSAGE
 echo "" >> $MESSAGE
 echo "------------------------------------------------------------------" >> $MESSAGE
 echo "Top Memory Consuming Process Using top command" >> $MESSAGE
 echo "------------------------------------------------------------------" >> $MESSAGE
 echo "$(top -b -o +%MEM | head -n 20)" >> $MESSAGE
 echo "" >> $MESSAGE
 echo "------------------------------------------------------------------" >> $MESSAGE
 echo "Top Memory Consuming Process Using ps command" >> $MESSAGE
 echo "------------------------------------------------------------------" >> $MESSAGE
 echo "$(ps -eo pid,ppid,%mem,%Memory,cmd --sort=-%mem | head)" >> $MESSAGE
 mail -s "$SUBJECT" "$TO" < $MESSAGE
 rm /tmp/Mail.out
fi
-------------------------------------------------------------------------------------------------------------------------------------------------
#monitor cpu ram etc, one liner

# crontab -e
*/5 * * * * /usr/bin/free | awk '/Mem/{printf("RAM Usage: %.2f%\n"), $3/$2*100}' | awk '{print $3}' | awk '{ if($1 > 80) print $0;}' | mail -s "High Memory Alert" 2day@gmail.com
-------------------------------------------------------------------------------------------------------------------------------------------------
#monitor cpu ram etc

#!/bin/bash
echo `date`
#cpu use threshold
cpu_threshold='80'
 #mem idle threshold
mem_threshold='100'
 #disk use threshold
disk_threshold='90'
#---cpu
cpu_usage () {
cpu_idle=`top -b -n 1 | grep Cpu | awk '{print $8}'|cut -f 1 -d "."`
cpu_use=`expr 100 - $cpu_idle`
 echo "cpu utilization: $cpu_use"
if [ $cpu_use -gt $cpu_threshold ]
    then
        echo "cpu warning!!!"
    else
        echo "cpu ok!!!"
fi
}
#---mem
mem_usage () {
 #MB units
mem_free=`free -m | grep "Mem" | awk '{print $4+$6}'`
 echo "memory space remaining : $mem_free MB"
if [ $mem_free -lt $mem_threshold  ]
    then
        echo "mem warning!!!"
    else
        echo "mem ok!!!"
fi
}
#---disk
disk_usage () {
disk_use=`df -P | grep /dev | grep -v -E '(tmp|boot)' | awk '{print $5}' | cut -f 1 -d "%"`
 echo "disk usage : $disk_use" 
if [ $disk_use -gt $disk_threshold ]
    then
        echo "disk warning!!!"
    else
        echo "disk ok!!!"
fi
 
 
}
cpu_usage
mem_usage
disk_usage

$ vi system_stats.sh
$ sudo chmod +x system_stats.sh
$ ./system_stats.sh #test
$ crontab -e
0 10 * * * ./system_stats.sh >>/opt/system.log
$ sudo cat /opt/system.log
-------------------------------------------------------------------------------------------------------------------------------------------------
------------------------------------------------------------------------------------------
#The script can be added directly to the local ~/.bashrc in a user’s home directory, so that all logins are printed to syslog
cat /var/log/syslog 

DEBUG="logger"
if [[ -n $SSH_CONNECTION ]] ; then
    $DEBUG "${USER} logged in to ${HOSTNAME}"
fi
-------------------------------------------------------------------------------------------------------------------------------------------------
#set the password
#!/bin/bash
echo "Setting  password to  " $password           
echo $password |passwd --stdin sampleuser
-------------------------------------------------------------------------------------------------------------------------------------------------
vagrant@vg-ubuntu-01:~$ echo "nfs-kernel server status : $(systemctl is-active nfs-kernel-server)"
nfs-kernel server status : active
vagrant@vg-ubuntu-01:~$
-------------------------------------------------------------------------------------------------------------------------------------------------
#!/bin/bash

#####################################################
# Setup NFS server
#####################################################

# Format the volume for the nfs server
if ! mountpoint -q /nfsdata; then
  mkfs.ext4 /dev/sdb
fi

# Mount locally
mkdir -p /nfsdata
if ! grep 'nfsdata' /etc/fstab; then
    echo "/dev/sdb        /nfsdata        ext4       defaults     0  2" >> /etc/fstab
fi

if ! mountpoint -q /nfsdata; then
    mount /nfsdata
fi

# Allow unrestricted perms
chmod 777 /nfsdata

# Install & start NFS services
yum install -y nfs-utils
systemctl start nfs-server rpcbind
systemctl enable nfs-server rpcbind

# Export over NFS
echo "/nfsdata 10.0.4.0/24(rw,sync,no_root_squash)" > /etc/exports
exportfs -r

# Mount the filesystem to our own host
mkdir -p /nfs
if ! grep -q "master:nfsdata" /etc/fstab; then
    echo "master:/nfsdata        /nfs         nfs4  defaults,_netdev 0 0" >> /etc/fstab
fi

if ! mountpoint -q /nfs; then
    mount /nfs
fi
-------------------------------------------------------------------------------------------------------------------------------------------------
#Execute SQL Queries From The Linux Shell
$ mysql -u USER -pPASSWORD -e "SQL_QUERY"
$ mysql -u USER -pPASSWORD -D DATABASE -e "SQL_QUERY"
$ mysql -u USER -pPASSWORD -h HOSTNAME -e "SQL_QUERY"
$ mysql -u USER -pPASSWORD -N -e "SQL_QUERY" #Suppressing column headings
$ mysql -u USER -pPASSWORD -B -e "SQL_QUERY" #Suppress table borders
$ mysql -u USER -pPASSWORD -e "SQL_QUERY" > FILE #Save the output to a file

#!/bin/bash
mysql -u root -psecret <<MY_QUERY
USE mysql
SHOW tables
MY_QUERY
-------------------------------------------------------------------------------------------------------------------------------------------------
#check if the process is running

#!/bin/bash
SERVICE="nginx"
if pgrep -x "$SERVICE" >/dev/null
then
    echo "$SERVICE is running"
else
    echo "$SERVICE stopped"
    # uncomment to start nginx if stopped
    # systemctl start nginx
    # mail  
fi

-------------------------------------------------------------------------------------------------------------------------------------------------
# transfer from local to remote, delete files if transfer is OK

#!/bin/bash
rsync -r -z -c /home/pi/queue root@server.mine.com:/home/foobar
if [ "$?" -eq "0" ]
then
  rm -rf rm /home/pi/queue/*
  echo "Done"
else
  echo "Error while running rsync"
fi
-------------------------------------------------------------------------------------------------------------------------------------------------
# check if rsync is running

RSYNC_COMMAND=$(rsync -r -z -c /home/pi/queue root@server.mine.com:/home/foobar)

    if [ $? -eq 0 ]; then
        # Success do some more work!

        if [ -n "${RSYNC_COMMAND}" ]; then
            # Stuff to run, because rsync has changes
        else
            # No changes were made by rsync
        fi
    else
        # Something went wrong!
        exit 1
    fi
-------------------------------------------------------------------------------------------------------------------------------------------------
#rsync process check

#!/bin/bash

while [ 1 ]
do
    rsync -avz --partial /tmp /mnt:
    if [ "$?" = "0" ] ; then
        echo "rsync completed normally"
        exit
    else
        echo "Rsync failure. Backing off and retrying in 180 s..."
        sleep 180
    fi
done
---------------------------------------------------------------------------------------------------------------------------------------------
#auto nmap scanning

#!/bin/sh

XXX="192.168.50"
NMAP_DIR="/var/log/nmap"

mkdir /var/log/nmap/$XXX

if [ -d $NMAP_DIR ] ; then
    echo "directory exists"
else
    echo "creating directory"
    #mkdir /var/log/nmap/$XXX
fi



TODAY=`date +"%d-%m-%y"`

if [ -f /var/log/nmap/$XXX/scan-$TODAY.xml ] ; then
    echo "file exists"
else
    echo "creating file"
    touch /var/log/nmap/$XXX/scan-$TODAY.xml
fi

OPTIONS="--open --reason -oX /var/log/nmap/$XXX/scan-$TODAY.xml -F 192.168.50.0/24"

nmap $OPTIONS

sleep 10
rm /var/log/nmap/$XXX/yesterday.xml
mv /var/log/nmap/$XXX/today.xml /var/log/nmap/$XXX/yesterday.xml

ln -s /var/log/nmap/$XXX/scan-$TODAY.xml /var/log/nmap/$XXX/today.xml

--------------------------------------------------------------------------------------------------------------------------------------------
