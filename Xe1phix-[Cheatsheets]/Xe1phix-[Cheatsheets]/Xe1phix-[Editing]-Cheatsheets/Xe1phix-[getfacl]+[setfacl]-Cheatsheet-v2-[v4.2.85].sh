getfacl -a a.txt #file access control list of a file or directory.
getfacl -t a.txt
getfacl -n file #numeric user and group IDs
getfacl -d a.txt #the default access control list of a file or directory.
getfacl -R directory # the ACLs of all files and directories recursively (sub-directories)
getfacl -L -R directory #follow symbolic links to directories. The default behavior is to follow symbolic link arguments and skip symbolic links encountered in subdirectories
getfacl -P -R directory #do not follow symbolic links to directories,skip symbolic link arguments

setfacl -m u:deepak:rw a.txt #grant read and write permission
setfacl -b a.txt #remove all extended ACL entries,remove all entries
setfacl -x u:deepak a.txt #remove user
setfacl -x g:linux file #remove group
setfacl -m g:linux:rw -R directory #remove group  recursively (sub-directories)
setfacl -k file #remove the default access control list
setfacl --test -x g:linux -R dir1 #The ACLs are not modified in test mode. It only displays the changes that will take place
setfacl -dm "user:my_user:r--" /path/to/directory #Add a default entry to grant access to the user my_user on all newly created files within a directory


getfacl file1 | setfacl --set-file=- file2 #copy the ACL of one file to another
