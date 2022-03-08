# Scenario three

-----

> `Save custom script copy over SSH` -> `Target host's Logging output` ->
> `Pipe (encryption) input` -> `Encrypted Log output` ->
> `Rotate encrypt and email removing old`

-----

## Write customized pipe listener script over SSH

> These are the options used from `Scenario one` so edit as needed and be
> aware that file paths will be relative to that of the SSH server being logged
> into. Note we're only saving these variables to make the final command easier
> to read.

```
Script_options="--enc-copy-save-yn='yes'\
 --enc-copy-save-path='/jailer_scripts/website_host/Web_log_encrypter.sh'\
 --enc-copy-save-ownership='notwwwuser:notwwwgroup'\
 --enc-copy-save-permissions='100'\
 --debug-level='6'\
 --enc-parsing-quit-string='sOmErAnDoM_sTrInG_wItHoUt_SpAcEs_tHaT_iS_nOt_NoRmAlY_rEaD'\
 --log-level='0'\
 --enc-pipe-file='/jailed_servers/website_host/var/log/www/access.log.pipe'\
 --enc-pipe-ownership='notwwwuser:wwwgroup'\
 --enc-pipe-permissions='420'\
 --enc-parsing-output-file='/jailed_logs/website_host/www_access.gpg'\
 --enc-parsing-recipient='user@host.domain'\
 --enc-parsing-filter-input-yn='yes'\
 --enc-parsing-output-rotate-actions='compress-encrypt,remove-old'\
 --enc-parsing-output-check-frequency='25000'\
 --enc-parsing-output-max-size='8388608'\
 --enc-parsing-output-rotate-recipient='user@host.domain'\
 --enc-parsing-output-rotate-yn='yes'\
 --enc-parsing-save-output-yn='yes'\
 --enc-parsing-disown-yn='yes'"
```

> Note the use of `\` (back-slashes) for escaping new lines above, these are not
> neaded when you input the above on one line, in either case do not forget the
> clossing double quote (`"`) for the variable's assignment.

## Run the main script from host using redirection and assigned variables

```
ssh user@remote "$(</path/to/main/script.sh ${Script_options})"
```

## Restart named pipe listener script over SSH

> now that it is local to and configured for the target's file system.

```
## Send quit string to named pipe
ssh user@remote "echo 'sTrInG_wItHoUt_SpAcEs' > /jailed_servers/website_host/var/log/www/access.log.pipe"
## Start script over SSH
ssh user@remote "/jailer_scripts/website_host/Web_log_encrypter.sh"
```

> The above steps maybe repeated for any other servers (or same server
> different but log) that require setup of log encryption, however, if attempting
> to automate this for a large cluster it is advisable to define separate quit
> strings for each remote host. Linked within `../Script_Helpers` directory of
> project,
> [../Script_Helpers/Paranoid_Pipes_Scenario_Three.sh](../Script_Helpers/Paranoid_Pipes_Scenario_Three.sh),
> the authors have provided an example of what they would do to setup
> multiple remote hosts in quick succession that each only need one template
> written.

## Important variables to modify in above example script

> List 'remote user' `@` 'remote host' `:` 'listening server port' separated
> by `,` of servers that should receive a script copy for encrypting logs and
> files via named pipe

```
Remote_hosts="webadmin@webhost:22,sqladmin@sqlhost:9823"
```

## Relative path on target server to Bash shell

> The following default should work for most systems without modification.

```
Remote_host_shell="/bin/bash"
```

## Generate random characters of given numerical length

> for use in making custom quit strings for each named pipe listener script
> that will be written. Note this will be logged on the relative local file
> system for all servers and each target should receive their own randomized
> quit string written to their script copy.

```
Quit_string_length='32'
```

## Relative local file path to save the above script's logs out to

> Note this maybe an encrypting pipe path on your local file system too if you
> wish to keep quit strings and servers setup private.

```
Log_file_path='/tmp/ssh_remote_encrypted_setup.log'
```

## Path to main script downloaded (`clone`d) on local host

> ei not on your target servers. If this is not set properly then the script's
> `ssh ${_host} -s ${Remote_host_shell} "$(<${Main_script_path} ${Script_options})"`
> command will miss-fire.

```
Main_script_path='/path/to/writer_script.sh'
```

## Paths relative to each target host's file system

> target directory path to save script copy to.

```
Script_save_dir='/usr/local/sbin'
```

> target directory to save listening script copy's output to

```
Script_save_output_dir='/var/log'
```

## Import onto each target host the related public key

> and what each target host will use for line-by-line and recognized file type
> encryption.

```
Script_save_parse_recipient='user@host.suffix'
```

## Second pub key's email address to import onto each target host

> and what each target host will use for log rotation encryption and emailing
> compressed logs actions.

```
Script_save_rotate_recipient='user@host.suffix'
```

> Above will save an encrypting script to each host defined by the `Remote_hosts`
> variable and import the gpg keys defined by `Script_save_parse_recipient and
> `Script_save_rotate_recipient variables to each of them. The scripts them
> selves will each have variable names for pipes, output files, and listening
> script by parsing the individual target host. Because the script copies are
> much smaller than the main script of this project, after running above, coping
> and modifying the individual target host's scripts on a case by case basis is
> the suggested next course of action.
> Bellow is a run-down of what changes per target host and what will remain
> constant.

## Variable defined options that change per-host assigned to each script copy

```
--enc-copy-save-path='${Script_save_dir}/${_host_name}_log_encrypter.sh'
--enc-pipe-file='${Script_save_output_dir}/${_host_name}_access.log.pipe'
--enc-pipe-ownership='${_host_name}:${_host_name}'
--enc-copy-save-ownership='${_host_name}:${_host_name}'
--enc-parsing-output-file='${Script_save_output_dir}/${_host_name}_access.gpg'
```

## Variable defined options that do not change per-host

> assigned to each script copy

```
--enc-parsing-recipient='${Script_save_parse_recipient}'
--enc-parsing-output-rotate-recipient='${Script_save_rotate_recipient}'
```

## List of options that do not change per-host assigned to each script copy

```
--enc-copy-save-yn='yes'
--enc-copy-save-permissions='100'
--debug-level='6'
--log-level='0'
--enc-pipe-permissions='420'
--enc-parsing-filter-input-yn='yes'
--enc-parsing-output-rotate-actions='compress-encrypt,remove-old'
--enc-parsing-output-check-frequency='25000'
--enc-parsing-output-max-size='8388608'
--enc-parsing-output-rotate-yn='yes'
--enc-parsing-save-output-yn='yes'
--enc-parsing-disown-yn='yes'
```

> After modifying and running the above script you should have a log file on the
> local host of actions preformed as defined by `Log_file_path` variable that
> saves each script copy's quit string as defined by the following option used in
> above `for` loop.

```
--enc-parsing-quit-string='${_random_quit_string}'
```

> Sample output log file

```
# <Host> | <Quit string>
#--------|--------------
# webadmin@webhost | somerandomstring
# sqladmin@sqlhost | someotherrandomstring
## Finished above at Day Month Day# hh:mm:ss Zone Year
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
