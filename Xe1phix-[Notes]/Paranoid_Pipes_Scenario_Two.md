# Scenario two

-----

> `Logging output` -> `Pipe (encryption) input` -> `Encryption` ->
> `Pipe (decryption) input` -> `Log output (rotate)` -> `Encrypted email`

-----

> Let's say you're web server's threat modal is different than that described
> by `Scenario one` and your server still needs to respond to threats in *near*
> real time via Fail2Ban but you still don't wish to make it easy on future
> attackers to access your server's logs. In the following example we'll be
> setting up a pipe to pipe encryption of logs such that they only exist in plan
> text long enough for monitoring software to do it's thing.

## Generate server only key pare on host file system

> Note not on the chrooted web server's file system

```
gpg --homedir /tmp/.gnupg --gen-key
# Follow the prompts and set solid passphrase.
```

## Export the server's revocation cert

> Note you'll want to move this file off server if generating keys on the
> same server that will also service clients because when your server becomes
> compromised this cert will allow you to revoke these keys if they're ever
> uploaded to a key server.

```
gpg --homedir /tmp/.gnupg --gen-revoke --output /tmp/.gnupg/server_gpg_revoke.asci
```

## Export the server's public key

> This is for importation within host server file system.

```
gpg --homedir /tmp/.gnupg --export --output /tmp/.gnupg/server_public.key
```

## Export the server's privet key

> back this up on another device using same transmission methods as
> transmitting revoke cert. But we'll also need to import this key to the
> server's host file system so don't shred it just yet.

```
gpg --homedir /tmp/.gnupg --export-secret-keys --output /tmp/.gnupg/server_secret.key
```

## Import web server's private key to host's keyring

> This will also import the public key so login to the user account you will
> have running the pipe listening scripts prior to the following command; ie
> the one defined by `--enc-copy-save-ownership="notwwwuser:notwwwgroup"`
> command line option in next section.

```
gpg --import /tmp/.gnupg/server_secret.key
```

## Or using `su` for `notwwwuser` user

> (the same as owner of parsing pipe listeners) command key import without
> having to login that user.

```
su notwwwuser -c "gpg --import /tmp/.gnupg/server_secret.key"
```

## Remove the temp home directory GnuPG has been using for key generation

> Do this once you have backed up the privet key and revoke cert to another
> device.

```
rm -Irf /tmp/.gnupg
```

## Write some scripts to different directories

> When using the main script of this project; be sure to pay attention to the
> differences in command line options used and not used between runs.

### First is a pipe to pipe encryption named pipe listening script

```
/script/path/script_name.sh --enc-copy-save-yn='yes'\
 --enc-copy-save-path="/jailer_scripts/website_host/Web_log_pipe_to_pipe_encrypter.sh"\
 --enc-copy-save-ownership="notwwwuser:notwwwgroup"\
 --enc-copy-save-permissions='100'\
 --debug-level='6'\
 --enc-parsing-quit-string='sOmE_rAnDoM_sTrInG_wItHoUt_SpAcEs_tHaT_iS_nOt_NoRmAlY_rEaD'\
 --log-level='0'\
 --enc-pipe-file="/jailed_servers/website_host/var/log/www/access.log.pipe"\
 --enc-pipe-ownership='notwwwuser:wwwgroup'\
 --enc-pipe-permissions='420'\
 --enc-parsing-output-file="/jailed_logs/website_host/www_access.pipe"\
 --enc-parsing-recipient="user@host.domain"\
 --enc-parsing-output-rotate-yn='no'\
 --enc-parsing-save-output-yn='yes'\
 --enc-parsing-bulk-output-dir="/jailed_logs/host_backups"\
 --enc-parsing-disown-yn='yes' --help
```

### Second pipe will decrypt

> With a little modification, anything written to it's listening pipe will
> output to a log file that fail2ban and other log monitoring services may read.
> Note the log rotation settings as stated may fill your email's inbox but at
> least your logs only live in plan text for a short time on the public server.

```
/script/path/script_name.sh --dec-copy-save-yn='yes'\
 --dec-copy-save-path="/jailer_scripts/website_host/Web_log_pipe_to_pipe_decrypter.sh"\
 --dec-copy-save-ownership="notwwwuser:notwwwgroup"\
 --dec-copy-save-permissions='100'\
 --dec-pass="private-key-passphrase-or-file-path-to-passphrase"\
 --debug-level='6'\
 --log-level='0'\
 --dec-pipe-file="/jailed_logs/website_host/www_access.pipe"\
 --dec-pipe-ownership='notwwwuser:wwwgroup'\
 --dec-pipe-permissions='420'\
 --dec-parsing-save-output-yn='yes'\
 --dec-parsing-output-file="/jailed_logs/website_host/www_access.log"\
 --dec-parsing-quit-string='SoMe_rAnDoM_sTrInG_wItHoUt_SpAcEs_tHaT_iS_nOt_NoRmAlY_rEaD'\
 --enc-parsing-output-file="/jailed_logs/website_host/www_access.pipe"\
 --enc-parsing-bulk-output-dir="/jailed_logs/host_backups"\
 --dec-parsing-disown-yn='yes' --help
```

#### Start stop lines for decryption pipe to log file

```
# Start decryption pipe listener
/jailer_scripts/website_host/Web_log_pipe_to_pipe_decrypter.sh
# Stop decryption pipe listener
echo 'SoMe_rAnDoM_sTrInG_wItHoUt_SpAcEs_tHaT_iS_nOt_NoRmAlY_rEaD' > /jailed_servers/website_host/var/log/www/access.log.pipe
```

#### Start stop lines for encryption pipe to pipe files

```
## Start encryption pipe listener
/jailer_scripts/website_host/Web_log_pipe_to_pipe_encrypter.sh
# Stop decryption pipe listener
echo 'sOmE_rAnDoM_sTrInG_wItHoUt_SpAcEs_tHaT_iS_nOt_NoRmAlY_rEaD' > /jailed_logs/website_host/www_access.pipe
```

## Notes on differences between written script's options used above

### Input -> output first script options

```
--enc-pipe-file="/jailed_servers/website_host/var/log/www/access.log.pipe" \
--enc-parsing-output-file="/jailed_logs/website_host/www_access.pipe" \
```

### Input -> output second script options

```
--enc-pipe-file="/jailed_logs/website_host/www_access.pipe" \
--enc-parsing-output-file="/jailed_logs/website_host/www_access.log" \
```

> Above outlines taking input written by web server logging service on pipe
> `/jailed_servers/website_host/var/log/www/access.log.pipe` putting through
> encryption before outputting to pipe `/jailed_logs/website_host/www_access.pipe`
> file that the second script is listening for lines to parse for decryption. Data
> is passed through the second script's decryption loops and output in clear text
> file under `/jailed_logs/website_host/www_access.log` path.
> Now some maybe wondering what the benefit of this type of set up is. Simply if
> the second script dies then the first script will just make an encrypted log
> under the same file path as the second script's listening pipe; much like in
> `Scenario one`'s usage example. And if at a latter time you wish to move
> decryption to a separate physical server, ie over an VPN or SSH connection, then
> you'll only need to move the second script and private key to begin setting up
> pipe to pipe encrypted (doubly at that point) centralized log proxy decrypter...
> the authors will cover this in another scenario further on.

### Input -> output pre-parsing and log rotation options in the first script

```
--enc-parsing-filter-input-yn='yes' \
--enc-parsing-output-rotate-yn='no' \
--enc-parsing-save-output-yn='yes' \
```

### Input -> output pre-parsing and log rotation options in the second script

```
--enc-parsing-filter-input-yn='no' \
--enc-parsing-output-rotate-actions='compress-encrypt,remove-old' \
--enc-parsing-output-check-frequency='250' \
--enc-parsing-output-max-size='8046' \
--enc-parsing-output-rotate-recipient="user@host.domain" \
--enc-parsing-output-rotate-yn='yes' \
--enc-parsing-save-output-yn='yes' \
```

> Above we're disabling the log rotation for the first script because it's
> *log* file is really the listening pipe of the second script, thus we really
> don't want the first script trying to preform log rotate actions on a named
> pipe. And we're setting low values for the log rotation of the second script
> to keep clear text versions of or logs from kicking around on the host's file
> system for any longer than they need to be, however, this will cause your web
> or sys admin's email to become quite full unless they've setup some form of
> auto retrieval script to handle the traffic automatically. This is a balance
> your team must strike between threat modal vs administrating the log shuffle
> over-head described. The `--enc-parsing-filter-input-yn='`*yes/no*`'` option
> differences between first and second scripts are; in the first script we set
> this to `yes` to restrict what input is read and encrypted, and in the second
> script to prevent GnuPG decryption from failing to decrypt we set this to `no`
> and read raw lines in.

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
