# Run the last command as root
sudo !!
# Serve current directory tree at http://$HOSTNAME:8000/
python -m SimpleHTTPServer
# Save a file you edited in vim without the needed permissions
:w !sudo tee %
# change to the previous working directory
cd -
# Runs previous command but replacing
^foo^bar
# mtr, better than traceroute and ping combined
mtr google.com
# quickly backup or copy a file with bash
cp filename{,.bak}
# Rapidly invoke an editor to write a long, complex, or tricky command
ctrl-x e
# Execute a command without saving it in the history
<space>command
# Copy ssh keys to user@host to enable password-less ssh logins.
$ssh-copy-id user@host
# Empty a file
> file.txt
# Salvage a borked terminal
reset
# Capture video of a linux desktop
ffmpeg -f x11grab -s wxga -r 25 -i :0.0 -sameq /tmp/out.mpg
# Place the argument of the most recent command on the shell
'ALT+.' or '<ESC> .'
# currently mounted filesystems in nice layout
mount | column -t
# start a tunnel from some machine's port 80 to your local post 2001
ssh -N -L2001:localhost:80 somemachine
# Execute a command at a given time
echo "ls -l" | at midnight
# Query Wikipedia via console over DNS
dig +short txt <keyword>.wp.dg.cx
# Lists all listening ports together with the PID of the associated process
netstat -tlnp
# output your microphone to a remote computer's speaker
dd if=/dev/dsp | ssh -c arcfour -C username@host dd of=/dev/dsp
# Update twitter via curl
curl -u user:pass -d status="Tweeting from the shell" http://twitter.com/statuses/update.xml
# Mount a temporary ram partition
mount -t tmpfs tmpfs /mnt -o size=1024m
# Runs previous command replacing foo by bar every time that foo appears
!!:gs/foo/bar
# Mount folder/filesystem through SSH
sshfs name@server:/path/to/folder /path/to/mount/point
# Quick access to the ascii table.
man ascii
# Compare a remote file with a local file
ssh user@host cat /path/to/remotefile | diff /path/to/localfile -
# Download an entire website
wget --random-wait -r -p -e robots=off -U mozilla http://www.example.com
# Get your external IP address
curl ifconfig.me
# List the size (in human readable form) of all sub folders from the current location
du -h --max-depth=1
# Jump to a directory, execute a command and jump back to current dir
(cd /tmp && ls)
# Clear the terminal screen
ctrl-l
# Shutdown a Windows machine from Linux
net rpc shutdown -I ipAddressOfWindowsPC -U username%password
# A very simple and useful stopwatch
time read (ctrl-d to stop)
# SSH connection through host in the middle
ssh -t reachable_host ssh unreachable_host
# type partial command, kill this command, check something you forgot, yank the command, resume typing.
<ctrl+u> [...] <ctrl+y>
# Check your unread Gmail from the command line
curl -u username --silent "https://mail.google.com/mail/feed/atom" | perl -ne 'print "\t" if /<name>/; print "$2\n" if /<(title|name)>(.*)<\/\1>/;'
# Display the top ten running processes - sorted by memory usage
ps aux | sort -nk +4 | tail
# Watch Star Wars via telnet
telnet towel.blinkenlights.nl
# Make 'less' behave like 'tail -f'.
less +F somelogfile
# Simulate typing
echo "You can simulate on-screen typing just like in the movies" | pv -qL 10
# Set audible alarm when an IP address comes online
ping -i 60 -a IP_address
# Reboot machine when everything is hanging
<alt> + <print screen/sys rq> + <R> - <S> - <E> - <I> - <U> - <B>
# List of commands you use most often
history | awk '{a[$2]++}END{for(i in a){print a[i] " " i}}' | sort -rn | head
# Close shell keeping all subprocess running
disown -a && exit
# Display a block of text with AWK
awk '/start_pattern/,/stop_pattern/' file.txt
# Backticks are evil
echo "The date is: $(date +%D)"
# Create a script of the last executed command
echo "!!" > foo.sh
# Push your present working directory to a stack that you can pop later
pushd /tmp
# Watch Network Service Activity in Real-time
lsof -i
# Set CDPATH to ease navigation
CDPATH=:..:~:~/projects
# diff two unsorted files without creating temporary files
diff <(sort file1) <(sort file2)
# Sharing file through http 80 port
nc -v -l 80 < file.ext
# Put a console clock in top right corner
while sleep 1;do tput sc;tput cup 0 $(($(tput cols)-29));date;tput rc;done &
# Show apps that use internet connection at the moment. (Multi-Language)
lsof -P -i -n
# 32 bits or 64 bits?
getconf LONG_BIT
# Matrix Style
tr -c "[:digit:]" " " < /dev/urandom | dd cbs=$COLUMNS conv=unblock | GREP_COLOR="1;32" grep --color "[^ ]"
# python smtp server
python -m smtpd -n -c DebuggingServer localhost:1025
# Google Translate
translate(){ wget -qO- "http://ajax.googleapis.com/ajax/services/language/translate?v=1.0&q=$1&langpair=$2|${3:-en}" | sed 's/.*"translatedText":"\([^"]*\)".*}/\1\n/'; }
# Reuse all parameter of the previous command line
!*
# Display which distro is installed
cat /etc/issue
# Extract tarball from internet without local saving
wget -qO - "http://www.tarball.com/tarball.gz" | tar zxvf -
# escape any command aliases
\[command]
# Rip audio from a video file.
mplayer -ao pcm -vo null -vc dummy -dumpaudio -dumpfile <output-file> <input-file>
# Delete all files in a folder that don't match a certain file extension
rm !(*.foo|*.bar|*.baz)
# Kills a process that is locking a file.
fuser -k filename
# save command output to image
ifconfig | convert label:@- ip.png
# Copy your SSH public key on a remote machine for passwordless login - the easy way
ssh-copy-id username@hostname
# Remove duplicate entries in a file without sorting.
awk '!x[$0]++' <file>
# Inserts the results of an autocompletion in the command line
ESC *
# Add Password Protection to a file your editing in vim.
vim -x <FILENAME>
# Stream YouTube URL directly to mplayer.
i="8uyxVmdaJ-w";mplayer -fs $(curl -s "http://www.youtube.com/get_video_info?&video_id=$i" | echo -e $(sed 's/%/\\x/g;s/.*\(v[0-9]\.lscache.*\)/http:\/\/\1/g') | grep -oP '^[^|,]*')
# A fun thing to do with ram is actually open it up and take a peek. This command will show you all the string (plain text) values in ram
sudo dd if=/dev/mem | cat | strings
# Insert the last command without the last argument (bash)
!:-
# Easy and fast access to often executed commands that are very long and complex.
some_very_long_and_complex_command # label
# Find the process you are looking for minus the grepped one
ps aux | grep [p]rocess-name
# Graphical tree of sub-directories
ls -R | grep ":$" | sed -e 's/:$//' -e 's/[^-][^\/]*\//--/g' -e 's/^/   /' -e 's/-/|/'
# Easily search running processes (alias).
alias 'ps?'='ps ax | grep '
# Create a CD/DVD ISO image from disk.
readom dev=/dev/scd0 f=/path/to/image.iso
# quickly rename a file
mv filename.{old,new}
# Define a quick calculator function
? () { echo "$*" | bc -l; }
# Job Control
^Z $bg $disown
# Monitor progress of a command
pv access.log | gzip > access.log.gz
# intercept stdout/stderr of another process
strace -ff -e trace=write -e write=1,2 -p SOME_PID
# Print all the lines between 10 and 20 of a file
sed -n '10,20p' <filename>
# Make directory including intermediate directories
mkdir -p a/long/directory/path
# Graph # of connections for each hosts.
netstat -an | grep ESTABLISHED | awk '{print $5}' | awk -F: '{print $1}' | sort | uniq -c | awk '{ printf("%s\t%s\t",$2,$1) ; for (i = 0; i < $1; i++) {printf("*")}; print "" }'
# Edit a file on a remote host using vim
vim scp://username@host//path/to/somefile
# Send pop-up notifications on Gnome
notify-send ["<title>"] "<body>"
# Generate a random password 30 characters long
strings /dev/urandom | grep -o '[[:alnum:]]' | head -n 30 | tr -d '\n'; echo
# Mount a .iso file in UNIX/Linux
mount /path/to/file.iso /mnt/cdrom -oloop
# Multiple variable assignments from command output in BASH
read day month year <<< $(date +'%d %m %y')
# Remove all but one specific file
rm -f !(survivior.txt)
# Find Duplicate Files (based on size first, then MD5 hash)
find -not -empty -type f -printf "%s\n" | sort -rn | uniq -d | xargs -I{} -n1 find -type f -size {}c -print0 | xargs -0 md5sum | sort | uniq -w32 --all-repeated=separate
# Display a cool clock on your terminal
watch -t -n1 "date +%T|figlet"
# Convert seconds to human-readable format
date -d@1234567890
# Monitor the queries being run by MySQL
watch -n 1 mysqladmin --user=<user> --password=<password> processlist
# Show apps that use internet connection at the moment. (Multi-Language)
ss -p
# Check your unread Gmail from the command line
curl -u username:password --silent "https://mail.google.com/mail/feed/atom" | tr -d '\n' | awk -F '<entry>' '{for (i=2; i<=NF; i++) {print $i}}' | sed -n "s/<title>\(.*\)<\/title.*name>\(.*\)<\/name>.*/\2 - \1/p"
# directly ssh to host B that is only accessible through host A
ssh -t hostA ssh hostB
# return external ip
curl icanhazip.com
# Processor / memory bandwidthd? in GB/s
dd if=/dev/zero of=/dev/null bs=1M count=32768
# Get the 10 biggest files/folders for the current direcotry
du -s * | sort -n | tail
# Create a pdf version of a manpage
man -t manpage | ps2pdf - filename.pdf
# Copy a file using pv and watch its progress
pv sourcefile > destfile
# Show File System Hierarchy
man hier
# Open Finder from the current Terminal location
open .
# Record a screencast and convert it to an mpeg
ffmpeg -f x11grab -r 25 -s 800x600 -i :0.0 /tmp/outputFile.mpg
# Create a persistent connection to a machine
ssh -MNf <user>@<host>
# Draw kernel module dependancy graph.
lsmod | perl -e 'print "digraph \"lsmod\" {";<>;while(<>){@_=split/\s+/; print "\"$_[0]\" -> \"$_\"\n" for split/,/,$_[3]}print "}"' | dot -Tpng | display -
# RTFM function
rtfm() { help $@ || man $@ || $BROWSER "http://www.google.com/search?q=$@"; }
# Remove a line in a text file. Useful to fix
ssh-keygen -R <the_offending_host>
# Share a terminal screen with others
% screen -r someuser/
# Run a command only when load average is below a certain threshold
echo "rm -rf /unwanted-but-large/folder" | batch
# To print a specific line from a file
sed -n 5p <file>
# Search commandlinefu.com from the command line using the API
cmdfu(){ curl "http://www.commandlinefu.com/commands/matching/$@/$(echo -n $@ | openssl base64)/plaintext"; }
# Remove security limitations from PDF documents using ghostscript
gs -q -dNOPAUSE -dBATCH -sDEVICE=pdfwrite -sOutputFile=OUTPUT.pdf -c .setpdfwrite -f INPUT.pdf
# Run a file system check on your next boot.
sudo touch /forcefsck
# Backup all MySQL Databases to individual files
for I in $(mysql -e 'show databases' -s --skip-column-names); do mysqldump $I | gzip > "$I.sql.gz"; done
# replace spaces in filenames with underscores
rename 'y/ /_/' *
# List all bash shortcuts
bind -P
# Download Youtube video with wget!
wget http://www.youtube.com/watch?v=dQw4w9WgXcQ -qO- | sed -n "/fmt_url_map/{s/[\'\"\|]/\n/g;p}" | sed -n '/^fmt_url_map/,/videoplayback/p' | sed -e :a -e '$q;N;5,$D;ba' | tr -d '\n' | sed -e 's/\(.*\),\(.\)\{1,3\}/\1/' | wget -i - -O surprise.flv
# Show numerical values for each of the 256 colors in bash
for code in {0..255}; do echo -e "\e[38;05;${code}m $code: Test"; done
# Makes the permissions of file2 the same as file1
chmod --reference file1 file2
# Binary Clock
watch -n 1 'echo "obase=2;`date +%s`" | bc'
# Attach screen over ssh
ssh -t remote_host screen -r
# (Debian/Ubuntu) Discover what package a file belongs to
dpkg -S /usr/bin/ls
# Copy your ssh public key to a server from a machine that doesn't have ssh-copy-id
cat ~/.ssh/id_rsa.pub | ssh user@machine "mkdir ~/.ssh; cat >> ~/.ssh/authorized_keys"
# Download all images from a site
wget -r -l1 --no-parent -nH -nd -P/tmp -A".gif,.jpg" http://example.com/images
# Broadcast your shell thru ports 5000, 5001, 5002 ...
script -qf | tee >(nc -kl 5000) >(nc -kl 5001) >(nc -kl 5002)
# What is my public IP-address?
curl ifconfig.me
# Eavesdrop on your system
diff <(lsof -p 1234) <(sleep 10; lsof -p 1234)
# Port Knocking!
knock <host> 3000 4000 5000 && ssh -p <port> user@host && knock <host> 5000 4000 3000
# Show a 4-way scrollable process tree with full details.
ps awwfux | less -S
# Sort the size usage of a directory tree by gigabytes, kilobytes, megabytes, then bytes.
du -b --max-depth 1 | sort -nr | perl -pe 's{([0-9]+)}{sprintf "%.1f%s", $1>=2**30? ($1/2**30, "G"): $1>=2**20? ($1/2**20, "M"): $1>=2**10? ($1/2**10, "K"): ($1, "")}e'
# Block known dirty hosts from reaching your machine
wget -qO - http://infiltrated.net/blacklisted|awk '!/#|[a-z]/&&/./{print "iptables -A INPUT -s "$1" -j DROP"}'
# using `!#$' to referance backward-word
cp /work/host/phone/ui/main.cpp !#$:s/host/target
# mkdir & cd into it as single command
mkdir /home/foo/doc/bar && cd $_
# Remove all files previously extracted from a tar(.gz) file.
tar -tf <file.tar.gz> | xargs rm -r
# Search recursively to find a word or phrase in certain file types, such as C code
find . -name "*.[ch]" -exec grep -i -H "search pharse" {} \;
# which program is this port belongs to ?
lsof -i tcp:80
# Bring the word under the cursor on the :ex line in Vim
:<C-R><C-W>
# Duplicate installed packages from one machine to the other (RPM-based systems)
ssh root@remote.host "rpm -qa" | xargs yum -y install
# Use tee to process a pipe with two or more processes
echo "tee can split a pipe in two"|tee >(rev) >(tr ' ' '_')
# List only the directories
ls -d */
# Synchronize date and time with a server over ssh
date --set="$(ssh user@server date)"
# ls not pattern
ls !(*.gz)
# Edit a google doc with vim
google docs edit --title "To-Do List" --editor vim
# A robust, modular log coloriser
ccze
# Remind yourself to leave in 15 minutes
leave +15
# check site ssl certificate dates
echo | openssl s_client -connect www.google.com:443 2>/dev/null |openssl x509 -dates -noout
# Remove a line in a text file. Useful to fix "ssh host key change" warnings
sed -i 8d ~/.ssh/known_hosts
# Release memory used by the Linux kernel on caches
free && sync && echo 3 > /proc/sys/vm/drop_caches && free
# Colorized grep in less
grep --color=always | less -R
# Add timestamp to history
export HISTTIMEFORMAT="%F %T "
# exit without saving history
kill -9 $$
# make directory tree
mkdir -p work/{d1,d2}/{src,bin,bak}
# Create a quick back-up copy of a file
cp file.txt{,.bak}
# Quick access to ASCII code of a key
showkey -a
# Exclude multiple columns using AWK
awk '{$1=$3=""}1' file
# Recursively remove all empty directories
find . -type d -empty -delete
# Exclude .svn, .git and other VCS junk for a pristine tarball
tar --exclude-vcs -cf src.tar src/
# Show apps that use internet connection at the moment.
lsof -P -i -n | cut -f 1 -d " "| uniq | tail -n +2
# Recursively change permissions on files, leave directories alone.
find ./ -type f -exec chmod 644 {} \;
# Convert PDF to JPG
for file in `ls *.pdf`; do convert -verbose -colorspace RGB -resize 800 -interlace none -density 300 -quality 80 $file `echo $file | sed 's/\.pdf$/\.jpg/'`; done
# Start COMMAND, and kill it if still running after 5 seconds
timeout 5s COMMAND
# Fast, built-in pipe-based data sink
<COMMAND> |:
# Control ssh connection
[enter]~?
# Get the IP of the host your coming from when logged in remotely
echo ${SSH_CLIENT%% *}
# Colorful man
apt-get install most && update-alternatives --set pager /usr/bin/most
# Create a nifty overview of the hardware in your computer
lshw -html > hardware.html
# Manually Pause/Unpause Firefox Process with POSIX-Signals
killall -STOP -m firefox
# Gets a random Futurama quote from /.
curl -Is slashdot.org | egrep '^X-(F|B|L)' | cut -d \- -f 2
# recursive search and replace old with new string, inside files
$ grep -rl oldstring . |xargs sed -i -e 's/oldstring/newstring/'
# How to establish a remote Gnu screen session that you can re-connect to
ssh -t user@some.domain.com /usr/bin/screen -xRR
# Display a list of committers sorted by the frequency of commits
svn log -q|grep "|"|awk "{print \$3}"|sort|uniq -c|sort -nr
# Copy a MySQL Database to a new Server via SSH with one command
mysqldump --add-drop-table --extended-insert --force --log-error=error.log -uUSER -pPASS OLD_DB_NAME | ssh -C user@newhost "mysql -uUSER -pPASS NEW_DB_NAME"
# Prettify an XML file
tidy -xml -i -m [file]
# Find out how much data is waiting to be written to disk
grep ^Dirty /proc/meminfo
# Google text-to-speech in mp3 format
wget -q -U Mozilla -O output.mp3 "http://translate.google.com/translate_tts?ie=UTF-8&tl=en&q=hello+world
# Take screenshot through SSH
DISPLAY=:0.0 import -window root /tmp/shot.png
# pretend to be busy in office to enjoy a cup of coffee
cat /dev/urandom | hexdump -C | grep "ca fe"
# run complex remote shell cmds over ssh, without escaping quotes
ssh host -l user $(<cmd.txt)
# notify yourself when a long-running command which has ALREADY STARTED is finished
<ctrl+z> fg; notify_me
# Opens vi/vim at pattern in file
vi +/pattern [file]
# GREP a PDF file.
pdftotext [file] - | grep 'YourPattern'
# prints line numbers
nl
# Pipe stdout and stderr, etc., to separate commands
some_command > >(/bin/cmd_for_stdout) 2> >(/bin/cmd_for_stderr)
# Remove blank lines from a file using grep and save output to new file
grep . filename > newfilename
# Search for a <pattern> string inside all files in the current directory
grep -RnisI <pattern> *
# Go to parent directory of filename edited in last command
cd !$:h
# Diff on two variables
diff <(echo "$a") <(echo "$b")
# Draw a Sierpinski triangle
perl -e 'print "P1\n256 256\n", map {$_&($_>>8)?1:0} (0..0xffff)' | display
# Compare two directory trees.
diff <(cd dir1 && find | sort) <(cd dir2 && find | sort)
# delete a line from your shell history
history -d
# Save your sessions in vim to resume later
:mksession! <filename>
# read manpage of a unix command as pdf in preview (Os X)
man -t UNIX_COMMAND | open -f -a preview
# Intercept, monitor and manipulate a TCP connection.
mkfifo /tmp/fifo; cat /tmp/fifo | nc -l -p 1234 | tee -a to.log | nc machine port | tee -a from.log > /tmp/fifo
# List the number and type of active network connections
netstat -ant | awk '{print $NF}' | grep -v '[a-z]' | sort | uniq -c
# find files in a date range
find . -type f -newermt "2010-01-01" ! -newermt "2010-06-01"
# Use file(1) to view device information
file -s /dev/sd*
# Find usb device
diff <(lsusb) <(sleep 3s && lsusb)
# Bind a key with a command
bind -x '"\C-l":ls -l'
# Recover a deleted file
grep -a -B 25 -A 100 'some string in the file' /dev/sda1 > results.txt
# April Fools' Day Prank
PROMPT_COMMAND='if [ $RANDOM -le 3200 ]; then printf "\0337\033[%d;%dH\033[4%dm \033[m\0338" $((RANDOM%LINES+1)) $((RANDOM%COLUMNS+1)) $((RANDOM%8)); fi'
# Create colorized html file from Vim or Vimdiff
:TOhtml
# live ssh network throughput test
yes | pv | ssh $host "cat > /dev/null"
# Press Any Key to Continue
read -sn 1 -p "Press any key to continue..."
# backup all your commandlinefu.com favourites to a plaintext file
clfavs(){ URL="http://www.commandlinefu.com";wget -O - --save-cookies c --post-data "username=$1&password=$2&submit=Let+me+in" $URL/users/signin;for i in `seq 0 25 $3`;do wget -O - --load-cookies c $URL/commands/favourites/plaintext/$i >>$4;done;rm -f c;}
# git remove files which have been deleted
git add -u
# Schedule a script or command in x num hours, silently run in the background even if logged out
( ( sleep 2h; your-command your-args ) & )
# Use lynx to run repeating website actions
lynx -accept_all_cookies -cmd_script=/your/keystroke-file
# shut of the screen.
xset dpms force standby
# runs a bash script in debugging mode
bash -x ./post_to_commandlinefu.sh
# find geographical location of an ip address
lynx -dump http://www.ip-adress.com/ip_tracer/?QRY=$1|grep address|egrep 'city|state|country'|awk '{print $3,$4,$5,$6,$7,$8}'|sed 's\ip address flag \\'|sed 's\My\\'
# A child process which survives the parent's death (for sure)
( command & )
# Bind a key with a command
bind '"\C-l":"ls -l\n"'
# prevent accidents while using wildcards
rm *.txt <TAB> <TAB>
# Random Number Between 1 And X
echo $[RANDOM%X+1]
# Lists all listening ports together with the PID of the associated process
lsof -Pan -i tcp -i udp
# Alias HEAD for automatic smart output
alias head='head -n $((${LINES:-`tput lines 2>/dev/null||echo -n 12`} - 2))'
# easily find megabyte eating files or directories
alias dush="du -sm *|sort -n|tail"
# copy working directory and compress it on-the-fly while showing progress
tar -cf - . | pv -s $(du -sb . | awk '{print $1}') | gzip > out.tgz
# View the newest xkcd comic.
xkcd(){ wget -qO- http://xkcd.com/|tee >(feh $(grep -Po '(?<=")http://imgs[^/]+/comics/[^"]+\.\w{3}'))|grep -Po '(?<=(\w{3})" title=").*(?=" alt)';}
# send echo to socket network
echo "foo" > /dev/tcp/192.168.1.2/25
# convert unixtime to human-readable
date -d @1234567890
# List all files opened by a particular command
lsof -c dhcpd
# Perform a branching conditional
true && { echo success;} || { echo failed; }
# Create a single-use TCP (or UDP) proxy
nc -l -p 2000 -c "nc example.org 3000"
# Speed up launch of firefox
find ~ -name '*.sqlite' -exec sqlite3 '{}' 'VACUUM;' \;
# Convert Youtube videos to MP3
youtube-dl -t --extract-audio --audio-format mp3 YOUTUBE_URL_HERE
# GRUB2: set Super Mario as startup tune
echo "GRUB_INIT_TUNE=\"1000 334 1 334 1 0 1 334 1 0 1 261 1 334 1 0 1 392 2 0 4 196 2\"" | sudo tee -a /etc/default/grub > /dev/null && sudo update-grub
# exclude a column with cut
cut -f5 --complement
# List alive hosts in specific subnet
nmap -sP 192.168.1.0/24
# analyze traffic remotely over ssh w/ wireshark
ssh root@server.com 'tshark -f "port !22" -w -' | wireshark -k -i -
# Create an audio test CD of sine waves from 1 to 99 Hz
(echo CD_DA; for f in {01..99}; do echo "$f Hz">&2; sox -nt cdda -r44100 -c2 $f.cdda synth 30 sine $f; echo TRACK AUDIO; echo FILE \"$f.cdda\" 0; done) > cdrdao.toc && cdrdao write cdrdao.toc && rm ??.cdda cdrdao.toc
# Listen to BBC Radio from the command line.
bbcradio() { local s PS3="Select a station: ";select s in 1 1x 2 3 4 5 6 7 "Asian Network an" "Nations & Local lcl";do break;done;s=($s);mplayer -playlist "http://www.bbc.co.uk/radio/listen/live/r"${s[@]: -1}".asx";}
# Create a directory and change into it at the same time
md () { mkdir -p "$@" && cd "$@"; }
# Show current working directory of a process
pwdx pid
# throttle bandwidth with cstream
tar -cj /backup | cstream -t 777k | ssh host 'tar -xj -C /backup'
# Resume scp of a big file
rsync --partial --progress --rsh=ssh  $file_source $user@$host:$destination_file
# Find files that have been modified on your system in the past 60 minutes
sudo find / -mmin 60 -type f
# Use tee + process substitution to split STDOUT to multiple commands
some_command | tee >(command1) >(command2) >(command3) ... | command4
# Print diagram of user/groups
awk 'BEGIN{FS=":"; print "digraph{"}{split($4, a, ","); for (i in a) printf "\"%s\" [shape=box]\n\"%s\" -> \"%s\"\n", $1, a[i], $1}END{print "}"}' /etc/group|display
# Create a file server, listening in port 7000
while true; do nc -l 7000 | tar -xvf -; done
# format txt as table not joining empty columns
column -tns: /etc/passwd
# Tell local Debian machine to install packages used by remote Debian machine
ssh remotehost 'dpkg --get-selections' | dpkg --set-selections && dselect install
# Shell recorder with replay
script -t /tmp/mylog.out 2>/tmp/mylog.time; <do your work>; <CTRL-D>; scriptreplay /tmp/mylog.time /tmp/mylog.out
# send a circular
wall <<< "Broadcast This"
# Diff remote webpages using wget
diff <(wget -q -O - URL1) <(wget -q -O - URL2)
# The BOFH Excuse Server
telnet towel.blinkenlights.nl 666
# processes per user counter
ps hax -o user | sort | uniq -c
# Monitor bandwidth by pid
nethogs -p eth0
# use vim to get colorful diff output
svn diff | view -
# Run a long job and notify me when it's finished
./my-really-long-job.sh && notify-send "Job finished"
# Quickly graph a list of numbers
gnuplot -persist <(echo "plot '<(sort -n listOfNumbers.txt)' with lines")
# Nicely display permissions in octal format with filename
stat -c '%A %a %n' *
# Brute force discover
sudo zcat /var/log/auth.log.*.gz | awk '/Failed password/&&!/for invalid user/{a[$9]++}/Failed password for invalid user/{a["*" $11]++}END{for (i in a) printf "%6s\t%s\n", a[i], i|"sort -n"}'
# convert uppercase files to lowercase files
rename 'y/A-Z/a-z/' *
# Convert seconds into minutes and seconds
bc <<< 'obase=60;299'
# cat a bunch of small files with file indication
grep . *
# stderr in color
mycommand 2> >(while read line; do echo -e "\e[01;31m$line\e[0m"; done)
# VI config to save files with +x when a shebang is found on line 1
au BufWritePost * if getline(1) =~ "^#!" | if getline(1) =~ "/bin/" | silent !chmod +x <afile> | endif | endif
# find all file larger than 500M
find / -type f -size +500M
# Close a hanging ssh session
~.
# List files with quotes around each filename
ls -Q
# Define words and phrases with google.
define(){ local y="$@";curl -sA"Opera" "http://www.google.com/search?q=define:${y// /+}"|grep -Po '(?<=<li>)[^<]+'|nl|perl -MHTML::Entities -pe 'decode_entities($_)' 2>/dev/null;}
# perl one-liner to get the current week number
date +%V
# Get your external IP address
curl ip.appspot.com
# check open ports
lsof -Pni4 | grep LISTEN
# A fun thing to do with ram is actually open it up and take a peek. This command will show you all the string (plain text) values in ram
sudo strings /dev/mem
# Recursively compare two directories and output their differences on a readable format
diff -urp /originaldirectory /modifieddirectory
# DELETE all those duplicate files but one based on md5 hash comparision in the current directory tree
find . -type f -print0|xargs -0 md5sum|sort|perl -ne 'chomp;$ph=$h;($h,$f)=split(/\s+/,$_,2);print "$f"."\x00" if ($h eq $ph)'|xargs -0 rm -v --
# When feeling down, this command helps
sl
# List recorded formular fields of Firefox
cd ~/.mozilla/firefox/ && sqlite3 `cat profiles.ini | grep Path | awk -F= '{print $2}'`/formhistory.sqlite "select * from moz_formhistory" && cd - > /dev/null
# Base conversions with bc
echo "obase=2; 27" | bc -l
