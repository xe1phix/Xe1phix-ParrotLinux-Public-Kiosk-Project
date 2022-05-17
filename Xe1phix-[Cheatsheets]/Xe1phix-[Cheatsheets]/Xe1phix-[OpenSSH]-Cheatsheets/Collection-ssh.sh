#!/bin/sh



ssh‐keygen ‐t dsa ‐N '' 
cat ~/.ssh/id_dsa.pub | ssh $you@host‐server "cat ‐ >> ~/.ssh/$authorized_keys2" 

cd ~/.ssh 
ssh‐keygen ‐i ‐f $keyfilename.pub >> $authorized_keys2 

scp .ssh/$key.pub root@192.168.51.254:.ssh/






ssh‐keygen ‐l ‐f /etc/ssh/$ssh_host_rsa_key.pub      ## For RSA key 
ssh‐keygen ‐l ‐f /etc/ssh/$ssh_host_dsa_key.pub      ## For DSA key (default) 


scp $file.txt host‐two:/tmp 
scp $joe@host‐two:/www/*.html /www/tmp 
scp ‐r $joe@host‐two:/www /www/tmp 
scp ‐P 20022 $cb@cb.vu:unixtoolbox.xhtml .           ## connect on port 20022 



echo "transfer files to a remote machine as follows:"
scp $filename $user@$remotehost:/home/path



echo "copy a file from the remote host to the current directory with the given filename."
scp $user@$remotehost:/home/path/$filename $filename



echo "recursively copy a directory "
echo "over a network with the -r parameter:"

scp -r /home/slynux $user@remotehost:/home/backups		## Copies the directory /home/slynux recurisvely 
														## to a remotelocation

echo "set up a reverse port forward on that remote machine to the local machine"
ssh -R 8000:localhost:80 $user@$REMOTE_MACHINE


ssh ‐R 2022:localhost:22 $user@gate            ## forwards client 22 to gate:2022
ssh ‐L 3022:localhost:2022 $admin@gate         ## forwards client 3022 to gate:2022
ssh ‐p 3022 $admin@localhost                   ## local:3022 ‐> gate:2022 ‐> client:22


ssh ‐L localport:desthost:destport user@gate        ## desthost as seen from the gate 
ssh ‐R destport:desthost:localport user@gate        ## forwards your localport to destination 
ssh ‐X user@gate                                    ## To force X forwarding 



ssh ‐L 2401:localhost:2401 ‐L 8080:localhost:80 user@gate



echo 'SSHD: ALL' >> /etc/hosts.allow 
/etc/init.d/sshd restart

















