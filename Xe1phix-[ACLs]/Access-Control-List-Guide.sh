## Add username to have read, write and execute on /files:
setfacl -m u:$user:rwx /$files

## Add username to have +write access on /files:
setfacl -m u:$user:+w /$files

## Add default user access right to read and write on the folder:
setfacl -m d:u:$user:rw $folder/

## Add groupname to have read, write and execute on /files:
setfacl -m g:$group:rwx /$files

## Add groupname to have recursive +execute on folder:
setfacl -R -m g:$groupe:+x $folder/

## Add default group access right to read and write on the folder
setfacl -m d:g:$groupe:rw testfolder/

## Get ACL on /files:
getfacl /$files

## Remove ACL on /files
setfacl -b /$files

## Remove default ACL on folder:
setfacl -k $folder/
