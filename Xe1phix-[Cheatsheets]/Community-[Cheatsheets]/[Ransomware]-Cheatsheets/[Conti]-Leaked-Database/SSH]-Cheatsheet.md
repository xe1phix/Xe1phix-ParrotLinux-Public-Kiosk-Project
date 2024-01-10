# SSH

## 01 - Manual

### 1.1 - Banner Grab

#### 1.1.1 - Ncat

`$ echo "EXIT" | netcat -nv <IP> 22`

#### 1.1.2 - Telnet

`$ echo "EXIT" | telnet <IP> 22`

### 1.2 - Configuration Files

`$ cat /etc/ssh/sshd_config`

`$ cat /etc/ssh/ssh_host*`

`$ cat /home/$USER/.ssh/config`

### 1.3 - SFTP Command Execution

Once you have the SSH credentials to authenticate

`$ ssh -v <username>@<IP> "<command>"`

`$ ssh -v <username>@<IP> /bin/bash`

## 02 - SSH-Audit

`$ ssh-audit <IP>`

## 03 - Nmap

### Nmap NSE Enumeration

`$ nmap -p 22 --script sshv1 <IP>`

`$ nmap -p 22 --script ssh-auth-methods <IP>`

`$ nmap -p 22 --script ssh-2-enum-algos,ssh-hostkey <IP>`

`$ nmap -p 22 --script ssh-run --script-args="ssh-run.cmd=<commands>, ssh-run.username=<username>, ssh-run.password=<password> <IP>`

## 04 - Metasploit

### 4.1 - Banner Grab

```
msf > use auxiliary/scanner/ssh/ssh_version

msf auxiliary(scanner/ssh/ssh_version) > options

Module options (auxiliary/scanner/ssh/ssh_version): 

   Name     Current Setting  Required  Description 
   ----     ---------------  --------  ----------- 
   RHOSTS                    yes       The target host(s), see https://github.com/rapid7/metasploit-framework/wiki/Using-Metasploit 
   RPORT    22               yes       The target port (TCP) 
   THREADS  1                yes       The number of concurrent threads (max one per host) 
   TIMEOUT  30               yes       Timeout for the SSH probe

msf auxiliary(scanner/ssh/ssh_version) > set rhosts <IP>

msf auxiliary(scanner/ssh/ssh_version) > set threads 8

msf auxiliary(scanner/ssh/ssh_version) > run
```

## References

- [SSH-Audit](https://github.com/jtesta/ssh-audit)

- [Pentesting SSH](https://book.hacktricks.xyz/pentesting/pentesting-ssh)

- [Kali SSH Configuration](https://www.kali.org/docs/general-use/ssh-configuration/)