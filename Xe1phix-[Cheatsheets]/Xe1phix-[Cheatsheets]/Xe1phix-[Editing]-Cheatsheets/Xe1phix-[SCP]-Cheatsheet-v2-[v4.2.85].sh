#copy the “/etc” directory to a backup server located at 192.168.178.35 in the “/etc_backup” folder
scp -r /etc devconnected@192.168.178.35:/etc_backup/
# taggged with the current date
scp -r /etc devconnected@192.168.178.35:/etc_backup/etc_$(date "+%F")

   scp your_username@remotehost.edu:foobar.txt /some/local/directory-> Copy the file "foobar.txt" from a remote host to the local host
   scp file.txt remote_username@10.10.0.2:/remote/directory/newfilename.txt # save the file under a different name,Omitting the filename from the destination location copies the file with the original name.
   scp foobar.txt your_username@remotehost.edu:/some/remote/directory -> Copy the file "foobar.txt" from the local host to a remote host
   scp your_username@rh1.edu:/some/remote/directory/foobar.txt your_username@rh2.edu:/some/remote/directory/ ->Copy the file "foobar.txt" from remote host "rh1.edu" to remote host "rh2.edu"
   scp -P 2322 file.txt remote_username@10.10.0.2:/remote/directory #the remote host is listening on a port other than the default 22 
   scp -r /local/directory remote_username@10.10.0.2:/remote/directory #copy a directory from a local to remote system,use the -r flag for recursive
   
   # don’t have to log in to one of the servers to transfer files from one to another remote machine.
   #copy the file /files/file.txt from the remote host host1.com to the directory /files on the remote host host2.com
   scp user1@host1.com:/files/file.txt user2@host2.com:/files
   scp -3 user1@host1.com:/files/file.txt user2@host2.com:/files #route the traffic through the local host (machine on which the command is issued), use the -3 option

