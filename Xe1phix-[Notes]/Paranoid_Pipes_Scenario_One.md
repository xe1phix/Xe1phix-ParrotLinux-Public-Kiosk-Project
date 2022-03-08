# Scenario one

> `Logging output` -> `Pipe (encryption) input` -> `Encrypted log output` ->
> `Rotate using encrypted email and compression`

This scenario was written with the following link's questions as it's
 inspiration Serverfault
 [Asymmetric encrypt server logs that end up with sensitive data written to them](http://serverfault.com/questions/89126/asymmetrically-encrypted-filesystem)

-----

## Quote begin

> I'm dealing with some data that's governed by specific regulations and that
> must be handled in a specific manner.
> I'm finding that this data ends up in some of my log files as a result of the
> system operating as intended. I'd like to find a way to log messages on the
> server that receives that date, but to do so in such a way that the data is
> encrypted as it's written to disk and may not be decrypted by that same server.

## Quote cut-off

-----

> As of the time of writing this document both the authors of this project and
> the author of the above question have not found a suitable solution; aside from
> the following command line options being used on the project's script that is...

```
./Paranoid_Pipes.sh\
 --enc-copy-save-yn='yes'\
 --enc-copy-save-path="/jailer_scripts/website_host/Web_log_encrypter.sh"\
 --enc-copy-save-ownership="notwwwuser:notwwwgroup"\
 --enc-copy-save-permissions='100'\
 --debug-level='6'\
 --enc-parsing-quit-string='sOmErAnDoM_sTrInG_wItHoUt_SpAcEs_tHaT_iS_nOt_NoRmAlY_rEaD'\
 --log-level='0'\
 --enc-pipe-file="/jailed_servers/website_host/var/log/www/access.log.pipe"\
 --enc-pipe-ownership='notwwwuser:wwwgroup'\
 --enc-pipe-permissions='420'\
 --enc-parsing-output-file="/jailed_logs/website_host/www_access.gpg"\
 --enc-parsing-recipient="user@host.domain"\
 --enc-parsing-output-rotate-actions='compress-encrypt,remove-old'\
 --enc-output-rotate-check-requency='25000'\
 --enc-parsing-output-max-size='8388608'\
 --enc-parsing-output-rotate-recipient="user@host.domain"\
 --enc-parsing-output-rotate-yn='yes'\
 --enc-parsing-save-output-yn='yes'\
 --enc-parsing-disown-yn='yes' --help
 --enc-parsing-bulk-out-dir="/server/backups/website_host"
```

> Note, if you've setup the web server within a chroot (as is assumed by
> example values) then future attackers will not see your server's log data
> from previous connections, instead they'll see a named pipe that they can not
> write to unless they're the same `group` as that that preforms normal log
> writes. Nor will future attackers gain access to the encrypted logs until
> they've broken out of the server's jail. Even then the encrypted logs should
> be useless to them so long as the private key is **not** also stored on the
> host.

### Summery of logging data flow

1. Client interacts with server such that logs are generated. Modify the server
 or daemon to use the same file path as defined by `--enc-pipe-file` option
 for output of it's logs.

1. Written data to named pipe is read by Bash loops contained in customized
 script copy defined by `--enc-copy-save-path` option.

1. Using public key defined by `--output-parse-recipient` option, every data
 block read by the script copy will be encrypted. Note this script is capable
 of reading multi-line writes to it's named pipe in a single operation, thus if
 your logging daemon or server writes multiple lines per client interaction
 then the entire write action is captured up to a few thousand lines at a time.

1. The encrypted data is then saved (appended) to file defined by
 `--enc-parsing-output-file` option and the Bash loop checks it's internal write
 count against the count defined by `--enc-parsing-output-check-frequency` option
 and usually restarts processes that listen to named pipe for more writes.

> If the internal write count matches that of
> `--enc-parsing-output-check-frequency` or is greater then the
> `--enc-parsing-output-max-size` value is used to check the encrypted log file size.
> If the encrypted log file size matches that of `--enc-parsing-output-max-size`
> or is greater then the actions defined by `--enc-parsing-output-rotate-actions` option is
> considered.
> Note the more actions listed in the `--enc-parsing-output-rotate-actions` option the
> longer that the named pipe will be blocked for writing/parsing actions.
> Note if your server has `mutt` installed and configured to send emails you
> may wish to use the following instead. Additionally when emailed log rotation
> is enabled it will be the address defined by `--enc-parsing-output-rotate-recipient`
> option that receives attached encrypted logs.

## Enable emailed log rotation instead

```
--enc-parsing-output-rotate-actions='encrypted-email,remove-old'
```

> If no line matches `--enc-parsing-quit-string` option then reading named pipe
> for write actions from server or logging daemon is resumed and step `1`
> above starts again.

### What does the other above options do

#### Enable saving script copy saving operation

> all customized options are then saved by the main script to the script copy
> saved to the path defined by `--enc-copy-save-path` option.

```
--enc-copy-save-yn='yes'
```

#### The `<user>:<group>` allowed to run script copy

> This should be a **non**-root and/or **non**-sudo user group combo because
> it'll be parsing logs generated by the web server and thus unknown clients
> with unknown motives.

```
--enc-copy-save-ownership="notwwwuser:notwwwgroup"
```

#### Set execute permissions for script owner only

> Once written it should not be modifiable by any user other than a root/sudo
> user capable of running
> `su -u notwwuser -c "/jailer_scripts/website_host/Web_log_encrypter.sh"`.

```
--enc-copy-save-permissions='100'
```

#### Set debug levels really high

> all saving script operations are shown. Note setting this level equal to or
> higher than `3` will cause the main script to prompt to continue, this is
> normal and a requires a `yes` like response to continue.

```
--debug-level='6'
```

#### Set log level to lowest value possible value

> avoids writing anything unintentional to host system. If instead a log of
> every message passed is desired then use n+1, where `n` is the level chosen
> above with `--debug-level` option, ei `7` to capture every message from above
> example to a log file.

```
--log-level='0'
```

#### The `User` allowed to read from above pipe file name

> and the `Group` allowed to write to named pipe file. Tip the owner in bellow
> should be the same as the script copy's owner and the group should be the same
> as one that the chrooted web server's logger is apart of.

```
--enc-pipe-ownership='notwwwuser:wwwgroup'
```

#### Read and write permissions

> that support the above ownership split that would be readable by the script
> copy's owner, writable by logging group, and nothing more.

```
--enc-pipe-permissions='420'
```

> The combination of these above ownership and permission options **must**
> be correct for the target server or either; the logging service will be unable
> to write to the named pipe file, or the script copy will be unable to read
> from the named pipe.
> Tip: `ls -hal /path/to/standard.log` will reveal the `user` and `group`
> that the target server currently uses, make use of the old log file's
> `group`'s permissions for defining the above command line `wwwgroup` value.

#### Cause script, once written, to be run in the background

> Note this uses (internally called) `disown` command. This option is the last
> in above example options that will be written to the script copy.

```
--enc-parsing-disown-yn='yes'
```

#### Printing set options & exit without writing scirpt copy

> Remove this option after reviewing that options are set for your needs and
> the script will be saved and started prior to the main script exiting.

```
--help
```

> Last steps are to configure the target server or log daemon to start writing
> to the above named pipe instead of their default locations; note if using a
> log daemon such as `rsyslog` then for testing you may wish to have logs
> written to both default location and new named pipe location. For servers such
> as Nginx and other web servers be sure to check the documentation for
> "Log Rotation" for how to properly restart the related server's logging. Next
> sets of links are what this document's author could find for proper server
> restart signals; hint nginx is easiest.
> Web Server : [Nginx log rotation documentation](https://www.nginx.com/resources/wiki/start/topics/examples/logrotation/)
> Modify virtual host log access and log error lines to point to related named
> pipes, then use the following `kill` signal to restart the server's logging.
> Note `master.nginx.pid` should contain the full file path if not within Nginx's
> configuration directory.

```
kill -USR1 $(cat master.nginx.pid)
```

- Apache v2.4 [log rotation documentation](https://httpd.apache.org/docs/2.4/programs/rotatelogs.html)
- Rsyslog v8`ompipe` [plug-in documentation](http://www.rsyslog.com/doc/v8-stable/configuration/modules/ompipe.html)

#### Automation of named pipe log encryption for nginx

> Add the following line just before `daemon-start-stop` line under web
> server's start action; on Debian based systems this is usually under
> `/etc/init.d/nginx` file path.

```
/jailer_scripts/website_host/Web_log_encrypter.sh
```

> Add the following just after `daemon-start-stop` line under web server's
> stop action.

```
echo 'sOmErAnDoM_sTrInG_wItHoUt_SpAcEs_tHaT_iS_nOt_NoRmAlY_rEaD' > /jailed_servers/website_host/var/log/www/access.log.pipe
```

> Test that all still works as desired by restarting the server with the
> following series of commands.

```
/etc/init.d/nginx stop &&\
 /etc/init.d/nginx start &&\
 tail -f /jailed_logs/website_host/www_access.gpg
```

After clients reconnect you'll see the `~.gpg` logs start filling up, use
 `Ctrl^c` keyboard short-cut to exit tail command and wait for emails to start
 rolling into the log rotation email's inbox.

> Now at some point in the future you or your web-admin will need access to the
> logs, first decrypt the rolled logs with the second key used to encrypt them
> and then have your web-admin run something like the following to have
> encrypted data *chunks* shoved through decryption commands.

```
./Paranoid_Pipes.sh\
 --debug-level="9"\
 --dec-yn="yes"\
 --dec-parsing-disown-yn="no"\
 --dec-bulk-check-sleep="2"\
 --dec-bulk-check-count-max='1'\
 --dec-pass="/path/to/passphrase.file"\
 --dec-parsing-save-output-yn="yes"\
 --dec-parsing-output-file="/path/to/decrypted.log"\
 --enc-parsing-output-file="/jailed_logs/website_host/www_access.gpg"\
 --dec-parsing-bulk-out-dir="/path/to/decrypted/backups"\
 --enc-parsing-bulk-out-dir="/server/backups/website_host"
```

> This portion of the main script maybe verified by checing logs for
> [version_two_last_tests.sh](../.travis-ci/version_two_last_tests.sh)
> and used by your decrypting server to accomplish this goal. Which should (for
> medium to small log files) pull each encrypted section within a previously
> appended to encrypted log file out into an array of arrays, then push those
> arrays one by one through either; decryption command & out to clear text file,
> or, if a pipe is detected as above script's output path then the compound array
> will dump there instead and it'll be up to the listening pipe's script to output
> to it's destination. This allows, with proper custom settings, for piping
> through search parameters that save only relevant or requested information to a
> clear text file while ignoring everything else.

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
