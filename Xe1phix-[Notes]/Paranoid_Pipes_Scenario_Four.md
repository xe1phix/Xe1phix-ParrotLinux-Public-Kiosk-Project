# Scenario Four

-----

> Logging output `->` Named Pipe encryption input file `->`
> Encrypt & send output to `->` Pipe decryption input file `->`
> Mount decryption input file directory via SSHfs `->`
> Start listener on remote mounted Pipe decryption input file `->`
> Log decrypted output `->` On rotate send encrypted email

-----

> This scenario is an *extension* of the usage model explained within
> [Paranoid_Pipes_Scenario_Two.md](Paranoid_Pipes_Scenario_Two.md) documentation,
> Use `sshfs` to mount your remote's (web server's logging) directory, start
> decryption named pipe listener on local system listening to where the
> remote's encryption output will be sent, then start the remote's encrypting
> named pipe service to output to the shared (`sshfs` mounted) named pipe file.
> So long as your head isn't spinning from that and the file paths are correct,
> then like magic your remote's logs will be saved on the local file system in
> plan text for a finite time prior to being re-encrypted and sent to an email
> account for archival. The *sweet* part of this setup is a disconnect from the
> remote or local side of `sshfs` will cause logs to be saved on the remote's
> file system in an encrypted format 

## Setup local server

### Install additional dependencies on local server

```
sudo apt-get install sshfs
```

### Generate ssh key pair on local server

```
Var_sshfs_user="s0ands0"
## Make a directory and move there for key generation
mkdir -p ~/.ssh_fs
cd ~/.ssh_fs
## Generate key pair of specified name
ssh-keygen -t rsa -b 4096 -f ${Var_sshfs_user}
## Copy public key to local tmp directory
cp ${Var_sshfs_user}.pub /tmp/${Var_sshfs_user}.pub
## Save that path to a variable for latter use
Var_ssh_pubkey="/tmp/${Var_sshfs_user}.pub"
```

### Configure `ssh` client settings on local server

> Set some variables, note, the `Var_ssh_host` variable will be used latter
> within this document.

```
Var_ssh_conf="/etc/ssh/ssh_conf"
Var_ssh_host="Web_Host"
Var_ssh_hostname="192.168.0.3"
Var_ssh_user="notsudo"
```

> Note the following redirection will append to your ssh configs so long as you
> remember the number of greater/less-then signs required.

```
sudo cat >> "${Var_ssh_conf}" <<EOF
Host ${Var_ssh_host}
    Hostname ${Var_ssh_hostname}
    User ${Var_ssh_user}
    IdentityFile ~/.ssh_fs/${Var_sshfs_user}
EOF
```

### Clone project on local server

```
mkdir ~/git_clones
cd ~/git_clones
git clone https://github.com/S0AndS0/Perinoid_Pipes
cd Perinoid_Pipes
```

### Generate GnuPG key pair on local server

> Set some variables, note, the `Var_gnupg_pubkey_file` variable will be used
> latter within this document

```
Var_gnupg_email="user@host.domain"
Var_gnupg_pubkey_file="/tmp/${Var_gnupg_email//[@.]/}"
```

> Make directory for GnuPG key revoke cert to be save to and `cd` to it.

```
mkdir ~/.gpg_remote_pair
cd ~/.gpg_remote_pair
```

> Allow executable permissions for current running user to the following helper
> script.

```
chmod u+x Script_Helpers/GnuPG_Gen_Key.sh
```

> Print available command line options and their default settings. Note add
> '--help' at the end to double check your own custom settings.

```
Script_Helpers/GnuPG_Gen_Key.sh --help
```

> Run the helper script with the following defined options.

```
Script_Helpers/GnuPG_Gen_Key.sh\
 --prompt-for-pass-yn='yes'\
 --gnupg-email="${Var_gnupg_email}"\
 --gnupg-export-public-key-yn='yes'\
 --gnupg-export-public-key-location="${Var_gnupg_pubkey_file}"\
 --help
```

> Remove `--help` from above to accept default and customized
> options. Note that by setting `--prompt-for-pass-yn` to `yes`
> will cause the script to request a passphrase be generated.

## Setup remote server

### Setup up SFTP `user:group` on remote

```
Var_sftp_user="enclogger"
Var_sftp_group="sftplogger"
## Add new user and group for restrictions
adduser ${Var_sftp_user}
groupadd ${Var_sftp_group}
## Add new user to new group
usermod -a -G ${Var_sftp_group} ${Var_sftp_user}
## Lock the new user from logins
passwd -l ${Var_sftp_user}
## Lock the new user from shell access
usermod -s /bin/false ${Var_sftp_user}
```

### Setup `chroot` directory for new user on remote

```
Var_sftp_chroot="/sftp/logger"
## Make base of chroot dir owned by root
mkdir -p ${Var_sftp_chroot}
chown root:root ${Var_sftp_chroot}
chmod 0754 ${Var_sftp_chroot}
## Make spicific directory that new user may read/write to
mkdir -p ${Var_sftp_chroot}/${Var_sftp_user}
chown ${Var_sftp_chroot}:${Var_sftp_user} ${Var_sftp_chroot}/${Var_sftp_user}
chmod 0764 ${Var_sftp_chroot}/${Var_sftp_user}
```

### Append configs for ssh server on remote

> Note you'll need to manually edit the bellow file to ensure that the following
> line is set correctly for `Subsystem` global settings; above the next block.

```
Subsystem    sftp    internal-sftp
```

> Configuration block for new sftp user group

```
Var_sshd_conf="/etc/ssh/sshd_conf"
cat >> "${Var_sshd_conf}" <<EOF
Match Group ${Var_sftp_group}
    ChrootDirectory ${Var_sftp_chroot}
    ForceCommand internal-sftp
    AllowTcpForwarding no
EOF
```

> Note that the remote's ssh server should be restarted &/or reloaded after any
> configuration changes. Additionally for remote servers it's a good idea to
> open a second local terminal and re-connect. **without** disconecting the
> first, to test that settings haven't been buggered up.

## Setup named pipe & mount points

### Copy local ssh public key to remote

```
Var_ssh_command="mkdir -p /home/${Var_ssh_user}; cat >> /home/${Var_ssh_user}/.ssh/authorized_keys"
cat ${Var_ssh_pubkey} | ssh root@${Var_ssh_hostname} "${Var_ssh_command}"
```

### Mount remote directory to local

```
Var_mount_point="/mnt/"
## Make a mount point on local
mkdir -p ${Var_mount_point}
## Mount via sshfs
sshfs ${Var_ssh_host}:/ ${Var_mount_point}
```

### Copy GnuPG public key to remote mount point

```
cp ${Var_gnupg_pubkey_file} ${Var_mount_point}/${Var_ssh_user}
```

### Setup named pipe listener for decryption on local

```
/script/path/script_name.sh --enc-copy-save-yn='yes'\
 --enc-copy-save-path="/jailer_scripts/website_host/Web_log_pipe_to_pipe_decrypter.sh"\
 --enc-copy-save-ownership="notwwwuser:notwwwgroup"\
 --enc-copy-save-permissions='100'\
 --debug-level='6'\
 --enc-parsing-quit-string='SoMe_rAnDoM_sTrInG_wItHoUt_SpAcEs_tHaT_iS_nOt_NoRmAlY_rEaD'\
 --log-level='0'\
 --enc-pipe-file="${Var_mount_point}/website_host/www_access.pipe"\
 --enc-pipe-ownership='notwwwuser:wwwgroup'\
 --enc-pipe-permissions='420'\
 --enc-parsing-output-file="/jailed_logs/website_host/www_access.log"\
 --enc-parsing-recipient="user@host.domain"\
 --enc-parsing-output-rotate-actions='compress-encrypt,remove-old'\
 --enc-parsing-output-check-frequency='250'\
 --enc-parsing-output-max-size='8046'\
 --enc-parsing-output-rotate-recipient="user@host.domain"\
 --enc-parsing-output-rotate-yn='yes'\
 --enc-parsing-save-output-yn='yes'\
 --enc-parsing-disown-yn='yes' --help
```

### Setup named pipe for remote server encryption

```
/script/path/script_name.sh --enc-copy-save-yn='yes'\
 --enc-copy-save-path="${Var_mount_point}/website_host/Web_log_pipe_to_pipe_encrypter.sh"\
 --enc-copy-save-ownership="notwwwuser:notwwwgroup"\
 --enc-copy-save-permissions='100'\
 --debug-level='6'\
 --enc-parsing-quit-string='sOmE_rAnDoM_sTrInG_wItHoUt_SpAcEs_tHaT_iS_nOt_NoRmAlY_rEaD'\
 --log-level='0'\
 --enc-pipe-file="${Var_sftp_chroot}/website_host/var/log/www/access.log.pipe"\
 --enc-pipe-ownership='notwwwuser:wwwgroup'\
 --enc-pipe-permissions='420'\
 --enc-parsing-output-file="${Var_sftp_chroot}/website_host/www_access.pipe"\
 --enc-parsing-recipient="${Var_gnupg_email}"\
 --enc-parsing-output-rotate-actions='compress-encrypt,remove-old'\
 --enc-parsing-output-check-frequency='250'\
 --enc-parsing-output-max-size='8046'\
 --enc-parsing-output-rotate-recipient="user@host.domain"\
 --enc-parsing-output-rotate-yn='yes'\
 --enc-parsing-save-output-yn='yes'\
 --enc-parsing-disown-yn='yes' --help
```

## Licensing notice for this file

```
    Copyright (C) 2016 S0AndS0.
    Permission is granted to copy, distribute and/or modify this document under
    the terms of the GNU Free Documentation License, Version 1.3 published by
    the Free Software Foundation; with the Invariant Sections being
    "Title page". A copy of the license is included in the directory entitled
    "License".
```

[Link to title page](Contributing_Financially.md)

[Link to related license](../Licenses/GNU_FDLv1.3_Documentation.md)

