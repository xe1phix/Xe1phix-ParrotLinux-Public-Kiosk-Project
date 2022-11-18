$ sudo tree -d /var/log/ --du -sch
/var/log/
├── [4.0K]  dist-upgrade
├── [4.0K]  fsck
├── [4.0K]  lxd
├── [4.0K]  apt
└── [4.0K]  unattended-upgrades
$ sudo tree /var/log/ --du -h

$ sudo tree -a  /var/log #display hidden files
$ tree -daC
$ tree -f #view the full path for each directory and file
$ sudo tree -f -L 3
$ sudo tree -f -P cata* #only list files that match cata*, so files such as Catalina.sh, catalina.bat, etc
$ tree -P "*.log"
$ sudo tree -f -I *log /var/log #-I option,display all the files that do not match the specified pattern
$ sudo tree -d -I *log /var/log 
$ tree -I "*.log"
$ sudo tree -f --prune #prune empty directories from the output 
$ sudo tree -f -p #-p which prints the file type and permissions for each file
$ sudo tree -f -pug #print the username,the group name
$ sudo tree -f -pugs #print the size of each file in bytes along with the name using the -s option
$ sudo tree -f -pugh #human-readable format, use the -h flag
$ sudo tree -f -pug -h -D  #display the date of the last modification time for each sub-directory or file
$ tree -d -L 3 # the depth of directory tree in output
tree -vr #sort the files from Z-A
$ tree -L 2
tree -J #the output is in JSON format
$ sudo tree -o direc_tree.txt
