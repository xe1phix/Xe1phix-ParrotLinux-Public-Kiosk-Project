# LDAP

## 01 - Manual

### 1.1 - Usage

#### 1.1.1 - LDAPDomainDump

`$ ldapdomaindump <IP> [-r <IP>] -u '<domain_name>\<username>' -p '<password>' [--authtype SIMPLE] --no-json --no-grep -o ldap-loot-dir`

#### 1.1.2 - LDAPSearch

- **Note:** **tdl** **(Top Level Domain)** is `.com`, `.net`, etc...

`$ ldapsearch -x -h ldap://<IP> -D '<DOMAIN>\<username>' -w '<password>' -b "DC=<1_subdomain>,DC=<tdl>"`

### 1.2 - Null Credentials

`$ ldapsearch -x -h ldap://<IP> -D '' -w '' -b "DC=<subdomain>,DC=<tdl>"`

### 1.3 - Enumerate User Accounts

#### 1.3.1 - Usernames

- **Retrieve Users**

`$ ldapsearch -x -h ldap://<IP> -D '<DOMAIN_NAME>\<username>' -w '' -b "CN=Users,DC=<subdomain>,DC=<tdl>"`

- **Retrieve a specific user account**

`$ ldapsearch -x -h ldap://<IP> -D '<DOMAIN_NAME>\<username>' -w '' -b "CN=<username>,CN=Users,DC=<subdomain>,DC=<tdl>"`

- **Retrieve Domain Users**

`$ ldapsearch -x -h ldap://<IP> -D '<DOMAIN_NAME>\<username>' -w '' -b "CN=Domain Users,CN=Users,DC=<subdomain>,DC=<tdl>"`

#### 1.3.2 - Administrators

- **Retrieve Domain Admins**

`$ ldapsearch -x -h ldap://<IP> -D '<DOMAIN_NAME>\<username>' -w '' -b "CN=Domain Admins,CN=Users,DC=<subdomain>,DC=<tdl>"`

- **Retrieve Enterprise Admins**

`$ ldapsearch -x -h ldap://<IP> -D '<DOMAIN_NAME>\<username>' -w '' -b "CN=Enterprise Admins,CN=Users,DC=<subdomain>,DC=<tdl>"`

- **Retrieve Administrators**

`$ ldapsearch -x -h ldap://<IP> -D '<DOMAIN_NAME>\<username>' -w '' -b "CN=Administrators,CN=Builtin,DC=<subdomain>,DC=<tdl>"`

#### 1.3.3 - Remote Desktop Users

- **Retrieve Remote Desktop Group**

`$ ldapsearch -x -h ldap://<IP> -D '<DOMAIN_NAME>\<username>' -w '' -b "CN=Remote Desktop Users,CN=Builtin,DC=<subdomain>,DC=<tdl>"`

### 1.4 - Retrieve Computers

`$ ldapsearch -x -h ldap://<IP> -D '<DOMAIN_NAME>\<username>' -w '' -b "CN=Computers,DC=<subdomain>,DC=<tdl>"`

## 02 - Nmap

### 2.1 - Anonymous Credentials

`$ nmap -p 389 -n -sV --script "ldap* and not brute" <IP>`

### 2.2 - LDAP Search

- **sAMAccountName**

`$ nmap -p 389 --script ldap-search --script-args 'ldap.username="cn=<username>,cn=users,dc=<domain_name>,dc=<tdl>",ldap.password=<password>, ldap.qfilter=users,ldap.attrib=sAMAccountName' <IP>`

- **Enumerate Operating System**

`$ nmap -p 389 --script ldap-search --script-args 'ldap.username="cn=<username>,cn=users,dc=<domain_name>,dc=<tdl>",ldap.password=<password>,ldap.qfilter=custom,ldap.searchattrib="operatingSystem",ldap.searchvalue="Windows *Server*",ldap.atrrib={operatingSystem,whencreated,OperatingSystemServicePack}' <IP>`

### 2.3 - Novel Universal Password

`$ nmap -p 636 --script ldap-novell-getpass --script-args 'ldap-novell-getpass.username="CN=<username>,O=<company>",ldap-novell-getpass.password=<password>,ldap-novell-getpass.account="CN=<username>,OU=<project>,O=<company>"'`

### 2.4 - LDAP RootDSE

`$ nmap -p 389 --script ldap-rootdse <IP>`

## References

- [Pentesting LDAP](https://book.hacktricks.xyz/pentesting/pentesting-ldap)