tar xjvf backup.tbz
tar -zxvf backup.tar.gz
tar -xf file_name.tar.gz --directory /target/directory

#ssh and tar to make secure backups. Make a backup via encrypted file transfer
tar --create --directory /home/joe/tmp/ --file - *| \
ssh raspberrypi "tar --directory /home/joe \
--verbose --list --file -"

wget --no-check-certificate https://www.cacti.net/downloads/cacti-latest.tar.gz
tar -zxvf cacti-latest.tar.gz
mv cacti-1* /opt/cacti
(OR tar -xf cacti-latest.tar.gz --directory /opt/cacti)

tar -zxvf /tmp/onos-1.12.0.tar.gz  --strip-components 1 --directory /opt --one-top-level=onos
tar xvf mysql-5.7.23-linux-glibc2.12-x86_64.tar.gz --one-top-level=mysql57 --strip-components 1
tar zxvf ugly_name.tgz --one-top-level=pretty_name
#extract .xz file
unxz tor-browser-linux32-5.5.4_en-US.tar.xz
tar xvf tor-browser-linux32-5.5.4_en-US.tar
#extract .bz2 file
bzip2 -dk FileZilla_3.29.0_x86_64-linux-gnu.tar.bz2 
tar xvf FileZilla_3.29.0_x86_64-linux-gnu.tar
#extract .zip file
unzip terraform_0.11.7_linux_amd64.zip -d terraform
#extract .rar file
unrar e extract.rar r
# create user home directory backup 
tar cvf filename.tar /home/vagrant/
# show which files were changed
tar dvf filename.tar
# update the changed files
tar uvf filename.tar 
# make smaller backup 
gzip filename.tar
