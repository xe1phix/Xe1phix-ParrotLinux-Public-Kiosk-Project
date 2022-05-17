#!/bin/bash




Copy your ssh public key to a server from a machine that doesn't have ssh-copy-id
cat ~/.ssh/id_rsa.pub | ssh user@machine "mkdir ~/.ssh; cat >> ~/.ssh/authorized_keys"


# Mount folder/filesystem through SSH
sshfs name@server:/path/to/folder /path/to/mount/point



echo "##########################################################"
## Make encrypted archive of dir/ on remote machine ##
echo "##########################################################"
$ tar -c dir/ | gzip | gpg -c | ssh user@remote 'dd of=dir.tar.gz.gpg'


## Backup harddisk to remote machine ##
$ dd bs=1M if=/dev/sda | gzip | ssh user@remote 'dd of=sda.gz'













