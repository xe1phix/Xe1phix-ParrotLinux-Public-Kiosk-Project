
#list open files
lsof
#list open files owned by user1
lsof -u user1
#list open file via tcp
lsof -i TCP:1-1024
lsof -i TCP:80
PID 27808
lsof -Pan -p 27808 -i
lsof -p 2


# troubleshooting #1
find all the opened files and processes along with the one who opened them
# lsof –p PID
Count number of files & processes
# lsof -p 4271 | wc -l
Check the currently opened log file
lsof –p | grep log
Find out port number used by daemon
# lsof -i -P |grep 4271

# find out what running processes are associated with each open port on Linux
netstat -nlp|grep 9000
sudo ss -lptn 'sport = :80'
sudo netstat -nlp | grep :80
sudo lsof -n -i :80 | grep LISTEN
fuser 3306/tcp
fuser 80/tcp
ss -tanp | grep 6379
fuser -v -n tcp 22
sudo netstat -ltnp | grep -w ':80'
netstat -tulpn | grep :80
netstat -tulpn
ls -l /proc/1138/exe 
sudo ss -tulpn
sudo ss -tulpn | grep :3306
fuser 7000/tcp
ls -l /proc/3813/exe 
man transmission
whatis transmission
# find out current working directory of a process pid 3813
ls -l /proc/3813/cwd
pwdx 3813
# Find Out Owner Of a Process on Linux
cat /proc/3813/environ
grep --color -w -a USER /proc/3813/environ
lsof -i :80 | grep LISTEN
