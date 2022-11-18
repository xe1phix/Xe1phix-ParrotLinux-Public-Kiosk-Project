Local to Remote: rsync [OPTION]... -e ssh [SRC]... [USER@]HOST:DEST
Remote to Local: rsync [OPTION]... -e ssh [USER@]HOST:SRC... [DEST]

-v, –verbose – Using this option in the rsync command gives the status about transferred files.
-vv – Usually, this option is used to get information about the skipped files during file transfer.
-q, –quiet – This option simply suppress non-error messages.

rsync -av --rsync-path="rsync --log-file=/tmp/rlog" source/ destination/ #enable error log for rsync
#rsync exits with a non-zero code when the transfer fails,write details to log files.
rsync -avz -e ssh root@example.com:/ /mybackup/ > /var/log/rsync.log 2>&1

Problem:
rsync: failed to set times on "some_dir: Operation not permitted (1)
mkstemp "some_file" failed: Permission denied (13)
Fix:
if the user is 'abc' then 
the destination directory should be 
lrwxrwxrwx 1 abc abc 34 Jul 18 14:05 Destination_directory
chown -R abc:abc Destination_directory

rsync -aEim --delete /path/to/remote/ /path/to/local/ # rsync output to stdout with the -i flag

#Only files that rsync has fully successfully transferred are removed.
rsync -r -z -c --remove-source-files  /home/pi/queue root@server.mine.com:/home/foobar 

rsync -avz source destination #preserve permissions, ownership, and timestamp

#When the trailing slash  "/" is omitted the source directory will be copied inside the destination directory
#transfer the local directory to the directory on a remote machine
$ rsync -avz -e "ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null" --progress /home/filerunner/dir1 vg-ubuntu-02:/tmp
$ ls /tmp/dir1
a.txt

#When the source directory has a trailing slash  "/", rsync will copy only the contents of the source directory to the destination directory
$ rsync -avz -e "ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null" --progress /home/filerunner/dir1/ vg-ubuntu-02:/tmp
$ ls /tmp
a.txt

#dry run mode,
rsync -azhv -e "ssh -p 2212" --dry-run /home/bob/test_219 

#find out if the files are in sync, without actually doing a sync dry run mode
#-c, --checksum - skip based on checksum, not mod-time & size
#-r, --recursive - recurse into directories
#-n, --dry-run - perform a trial run with no changes made
#does not show anything if server2 has more files then server1
rsync -n -avrc /abc/home/sample1/* server2:/abc/home/sample2/
#dry-run mode verify
rsync -avzrch --progress --exclude=lost+found/ -e "ssh -i /home/vagrant/privatekey" --delete user@server:/mnt/files/ /mnt/disk1/ > /tmp/rsync_out 2>&1


#find out if the files are in sync, without actually doing a sync dry run mode
#--delete is needed to show if a file exists on server 2 but not server 1
rsync -n -avr --size-only --delete /abc/home/sample1/ server2:/abc/home/sample2/

#find out if the files are in sync, without actually doing a sync dry run mode
#Without --dry-run, it will automatically copy files of different sizes 
#if the sizes are identical, checksum them and copy if different
#The delete option will remove files from the target if not present on the source
rsync -cr --delete --dry-run source/ target/ > output_file 2>&1 &
#--size-only             skip files that match in size, no checksum
rsync -n -avr --size-only --delete /abc/home/sample1/ server2:/abc/home/sample2/

rsync -a -e "ssh -p 3322" /home/linuxize/images/ user@12.12.12.12:/var/www/images/ #if SSH is listening on port 3322

#transfer a single file /opt/file.zip from the local system to the /var/www/ directory on the remote system with IP 12.12.12.12
#If the file exists on the remote server it is overwritten
rsync -a /opt/file.zip user@12.12.12.12:/var/www/ 
#save the file under a different name
rsync -a /opt/file.zip user@12.12.12.12:/var/www/file2.zip

#transfer data from a remote to a local machine
rsync -a user@12.12.12.12:/var/www/file.zip /opt/

#synchronize the local and remote directory
rsync -a /home/linuxize/images/ user@12.12.12.12:/var/www/images/

#use the --delete option if you want to synchronize the local and remote directory
#delete files in the destination directory if they don’t exist in the source directory.
rsync -a --delete /home/linuxize/images/ user@12.12.12.12:/var/www/images/


#the “-r” option for “recursive” and the “-a” option for “all” (otherwise non-regular files will be skipped) 
#copy the “/etc” folder to the “/etc_backup” of the remote server
#with the “devconnected” username to server 192.168.178.35/24
rsync -ar /etc devconnected@192.168.178.35:/etc_backup

#Similarly,copy the content of the “/etc/ directory rather than the directory itself
rsync -ar /etc/* devconnected@192.168.178.35:/etc_backup/ 

# taggged with the current date
rsync -ar /etc/* devconnected@192.168.178.35:/etc_backup/etc_$(date "+%F")

#from local to remote server with private key
rsync -auvz -e "ssh -i private-key-file" source destination #Using rsync With SSH and Private Key 
rsync -auvz -e "ssh -i /home/yourUserName/.ssh/yourUserName-rsync-key" junk.txt yourUserName@calypso.nrel.colostate.edu
rsync -avzhe ssh backup.tar.gz root@192.168.0.141:/backups/
rsync -avzhe ssh --progress /root/rpmpkgs root@192.168.0.141:/root/rpmpkgs
 
#from remote to local server
rsync -avzh root@192.168.0.141:/root/rpmpkgs /tmp/myrpms
rsync -avze ssh --include 'R*' --exclude '*' root@192.168.0.141:/var/lib/rpm/ /root/rpm
#exclude lost+found dir
rsync --archive --no-compress --delete-before --info=progress2 --human-readable --exclude=lost+found/ /mnt/backup/ /mnt/backup-2/

#run rsycn on the background
rsync -avze ssh --include 'R*' --exclude '*' root@192.168.0.141:/var/lib/rpm/ /root/rpm > rsync.out 2>&1 &
tail -f rsync.out
