# MySQL

## 01 - Manual

### 1.1 - Usage

#### 1.1.1 - Authenticate

- **Local**

`$ mysql -u <username>`

`$ mysql -u <username> -p <password>`

- **Remote**

`$ mysql -h <IP> -u <username>`

`$ mysql -h <IP> -u <username>@<IP>`

`$ mysql -h <IP> -u <username> -p <password>`

### 1.2 - MySQL Version

- **MySQL service version**

`MySQL [(none)]> SELECT VERSION();`

### 1.3 - Operating System

- **Enumerate OS**

`MySQL [(none)]> SHOW VARIABLES LIKE "%version%";`

`MySQL [(none)]> SELECT LOAD_FILE('/etc/issue');`

`MySQL [(none)]> SELECT LOAD_FILE('/etc/os-release');`

### 1.3 - Database

#### 1.3.1 - List databases

`MySQL [(none)]> SHOW DATABASES;`

#### 1.3.2 - Retrieve Tables

- **Select Database**

`MySQL [(none)]> USE <database>;`

- **Show tables**

`MySQL [wordpress]> SHOW TABLES;`

- **Display records from a table**

`MySQL [(none)]> SELECT * FROM <table>;`

`MySQL [(none)]> SELECT @@datadir;`

`MySQL [(none)]> SHOW VARIABLES WHERE Variable_Name LIKE "%dir";`

#### 1.3.3 - Hashdump Credentials

- **Method 1:**

`MySQL [(none)]> SELECT user,authentication_string from mysql.user;`

`MySQL [(none)]> SELECT user,password from mysql.user;`

- **Method 2:**

`MySQL [(none)]> use mysql;`

`MySQL [(mysql)]> SELECT user,authentication_string from user;`

`MySQL [(mysql)]> SELECT user,password from user;`

### 1.4 - Enumerate Users

#### 1.4.1 - Discover users connected to the compromised MySQL database server

`MySQL [(none)]> SELECT USER();`

`MySQL [(none)]> SELECT LOAD_FILE('/etc/passwd');`

### 1.5 - Privilege Escalation

TODO: Finish the enumeration part for escalating to root/admin privileges

#### 1.5.1 - Discover what privileges does the user have access

`MySQL [(none)]> SHOW PRIVILEGES;`

`MySQL [(none)]> SHOW PRIVILEGES \G;`

These two are the most critical ways other than the basic query SQL commands just to get a reverse shell and escalate privileges for abusing the UDF MySQL feature. Look at the [[Pentesting Phases/Post Exploitation/Shell Is The Beginning/Privilege Escalation/Linux/Service Exploits/MySQL|Service Exploits]] section.

```
*************************** <number>. row ***************************
Privilege: Execute
  Context: Functions,Procedures
  Comment: To execute stored routines
*************************** <number>. row ***************************
Privilege: File
  Context: File access on server
  Comment: To read and write files on the server

MySQL [(none)]> SELECT user,host FROM mysql.user;

MySQL [(none)]> SHOW GRANTS FOR <username>@<IP>;
```

## 02 - Nmap

### 2.1 - MySQL Information

`$ nmap -p 3306 -sV --script mysql-info <IP>`

### 2.2 - Empty Password

`$ nmap -p 3306 --script mysql-empty-password <IP>`

### 2.3 - MySQL Audit

`$ nmap -p 3306 --script=mysql-audit --script-args="mysql-audit.username='<username>',mysql-audit.password='<password>',mysql-audit.filename='/usr/share/nmap/nselib/data/mysql-cis.audit'" <IP>`

### 2.4 - Database

#### 2.4.1 - Retrieve Users

`$ nmap -p 3306 --script mysql-users --script-args="mysqluser='<username>',mysqlpass='<password>'" <IP>`

#### 2.4.2 - Retrieve Databases

`$ nmap -p 3306 --script mysql-databases --script-args="mysqluser='<username>',mysqlpass='<password>'" <IP>`

#### 2.4.3 - Retrieve Variables

`$ nmap -p 3306 --script mysql-variables --script-args="mysqluser='<username>',mysqlpass='<password>'" <IP>`

#### 2.4.4 - Hashdump

`$ nmap -p 3306 --script mysql-dump-hashes --script-args "username='<username>',password='<password>'" <IP>`

## 03 - Metasploit

### 3.1 - Banner Grab

#### 3.1.1 - Scan MySQL version

```
msf > use auxiliary/scanner/mysql/mysql_version

msf auxiliary(scanner/mysql/mysql_version) > options

Module options (auxiliary/scanner/mysql/mysql_version):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   RHOSTS                    yes       The target host(s), see https://github.com/rapid7/metasploit-framework/wiki/Using-Metasploit
   RPORT    3306             yes       The target port (TCP)
   THREADS  1                yes       The number of concurrent threads (max one per host)

msf auxiliary(scanner/mysql/mysql_version) > set rhosts <IP>

msf auxiliary(scanner/mysql/mysql_version) > set threads 2

msf auxiliary(scanner/mysql/mysql_version) > run
```

### 3.2 - Database

#### 3.2.1 - Schema

```
msf > use auxiliary/scanner/mysql/mysql_schemadump

msf auxiliary(scanner/mysql/mysql_schemadump) > options

Module options (auxiliary/scanner/mysql/mysql_schemadump):

   Name             Current Setting  Required  Description
   ----             ---------------  --------  -----------
   DISPLAY_RESULTS  true             yes       Display the Results to the Screen
   PASSWORD                          no        The password for the specified username
   RHOSTS                            yes       The target host(s), see https://github.com/rapid7/metasploit-framework/wiki/Using-Metasploit
   RPORT            3306             yes       The target port (TCP)
   THREADS          1                yes       The number of concurrent threads (max one per host)
   USERNAME                          no        The username to authenticate as

msf auxiliary(scanner/mysql/mysql_schemadump) > set rhosts <IP>

msf auxiliary(scanner/mysql/mysql_schemadump) > set threads 2

msf auxiliary(scanner/mysql/mysql_schemadump) > set username <username>

msf auxiliary(scanner/mysql/mysql_schemadump) > set password <password>

msf auxiliary(scanner/mysql/mysql_schemadump) > run
```

#### 3.2.2 - Enumerate Instance

```
msf > use auxiliary/admin/mysql/mysql_enum

msf auxiliary(admin/mysql/mysql_enum) > options

Module options (auxiliary/admin/mysql/mysql_enum):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   PASSWORD                   no        The password for the specified username
   RHOSTS                     yes       The target host(s), see https://github.com/rapid7/metasploit-framework/wiki/Using-Metasploit
   RPORT     3306             yes       The target port (TCP)
   USERNAME                   no        The username to authenticate as

msf auxiliary(admin/mysql/mysql_enum) > set rhosts <IP>

msf auxiliary(admin/mysql/mysql_enum) > set username <username>

msf auxiliary(admin/mysql/mysql_enum) > set password <password>

msf auxiliary(admin/mysql/mysql_enum) > run
```

#### 3.2.3 - Writable Directory

```
msf > use auxiliary/scanner/mysql/mysql_writable_dirs

msf auxiliary(scanner/mysql/mysql_writable_dirs) > options

Module options (auxiliary/scanner/mysql/mysql_writable_dirs):

   Name       Current Setting  Required  Description
   ----       ---------------  --------  -----------
   DIR_LIST                    yes       List of directories to test
   FILE_NAME  vDXcsdmE         yes       Name of file to write
   PASSWORD                    no        The password for the specified username
   RHOSTS                      yes       The target host(s), see https://github.com/rapid7/metasploit-framework/wiki/Using-Metasploit
   RPORT      3306             yes       The target port (TCP)
   THREADS    1                yes       The number of concurrent threads (max one per host)
   USERNAME   root             yes       The username to authenticate as

msf auxiliary(scanner/mysql/mysql_writable_dirs) > set rhosts <IP>

msf auxiliary(scanner/mysql/mysql_writable_dirs) > set file_name <file>

msf auxiliary(scanner/mysql/mysql_writable_dirs) > set threads 4

msf auxiliary(scanner/mysql/mysql_writable_dirs) > set dir_list </path/to/dir/>

msf auxiliary(scanner/mysql/mysql_writable_dirs) > set username <username>

msf auxiliary(scanner/mysql/mysql_writable_dirs) > set password <password>

msf auxiliary(scanner/mysql/mysql_writable_dirs) > run
```

#### 3.2.4 - Enumerate Files

```
msf > use auxiliary/scanner/mysql/mysql_file_enum

msf auxiliary(scanner/mysql/mysql_file_enum) > options

Module options (auxiliary/scanner/mysql/mysql_file_enum):

   Name           Current Setting  Required  Description
   ----           ---------------  --------  -----------
   DATABASE_NAME  mysql            yes       Name of database to use
   FILE_LIST                       yes       List of directories to enumerate
   PASSWORD                        no        The password for the specified username
   RHOSTS                          yes       The target host(s), see https://github.com/rapid7/metasploit-framework/wiki/Using-Metasploit
   RPORT          3306             yes       The target port (TCP)
   TABLE_NAME     seWmJUSI         yes       Name of table to use - Warning, if the table already exists its contents will be corrupted
   THREADS        1                yes       The number of concurrent threads (max one per host)
   USERNAME       root             yes       The username to authenticate as

msf auxiliary(scanner/mysql/mysql_file_enum) > set rhosts <IP>

msf auxiliary(scanner/mysql/mysql_file_enum) > set database_name <database>

msf auxiliary(scanner/mysql/mysql_file_enum) > set table_name <table>

msf auxiliary(scanner/mysql/mysql_file_enum) > set file_list </usr/share/metasplot-framework/data/wordlists/sensitive_files.txt | /opt/metasploit/data/wordlists/sensitive_files.txt>

msf auxiliary(scanner/mysql/mysql_file_enum) > set username <username>

msf auxiliary(scanner/mysql/mysql_file_enum) > set password <password>

msf auxiliary(scanner/mysql/mysql_file_enum) > run -j
```

#### 3.2.5 - Hashdump

```
msf > use auxiliary/scanner/mysql/mysql_hashdump

msf auxiliary(scanner/mysql/mysql_hashdump) > options

Module options (auxiliary/scanner/mysql/mysql_hashdump):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   PASSWORD                   no        The password for the specified username
   RHOSTS                     yes       The target host(s), see https://github.com/rapid7/metasploit-framework/wiki/Using-Metasploit
   RPORT     3306             yes       The target port (TCP)
   THREADS   1                yes       The number of concurrent threads (max one per host)
   USERNAME                   no        The username to authenticate as

msf auxiliary(scanner/mysql/mysql_hashdump) > set rhosts <IP>

msf auxiliary(scanner/mysql/mysql_hashdump) > set threads 2

msf auxiliary(scanner/mysql/mysql_hashdump) > set username <username>

msf auxiliary(scanner/mysql/mysql_hashdump) > set password <password>

msf auxiliary(scanner/mysql/mysql_hashdump) > run
```

### 3.3 - SQL Queries

```
msf > use auxiliary/admin/mysql/mysql_sql

msf auxiliary(admin/mysql/mysql_sql) > options

Module options (auxiliary/admin/mysql/mysql_sql):

   Name      Current Setting   Required  Description
   ----      ---------------   --------  -----------
   PASSWORD                    no        The password for the specified username
   RHOSTS                      yes       The target host(s), see https://github.com/rapid7/metasploit-framework/wiki/Using-Metasploit
   RPORT     3306              yes       The target port (TCP)
   SQL       select version()  yes       The SQL to execute.
   USERNAME                    no        The username to authenticate as

msf auxiliary(admin/mysql/mysql_sql) > set rhosts <IP>

msf auxiliary(admin/mysql/mysql_sql) > set sql <query_commands>

msf auxiliary(admin/mysql/mysql_sql) > set username <username>

msf auxiliary(admin/mysql/mysql_sql) > set password <password>

msf auxiliary(admin/mysql/mysql_sql) > run
```


## References

- [Pentesting MySQL](https://book.hacktricks.xyz/pentesting/pentesting-mysql)

- [SQL Injection](https://www.websec.ca/kb/sql_injection)

- [MySQL Pentesting Metasploit Framework](https://www.yeahhub.com/mysql-pentesting-metasploit-framework/)

- [MySQL Show Privileges Statement](https://www.tutorialspoint.com/mysql/mysql_show_privileges_statement.htm)

- [MySQL Show User Privileges](https://phoenixnap.com/kb/mysql-show-user-privileges)

- [How to Find The MySQL Data Directory From Command Line in Windows](https://stackoverflow.com/questions/17968287/how-to-find-the-mysql-data-directory-from-command-line-in-windows)

- [MySQL Penetration Testing Nmap](https://www.hackingarticles.in/mysql-penetration-testing-nmap/)

- [Penetration Testing on MySQL Port 3306 ](https://www.hackingarticles.in/penetration-testing-on-mysql-port-3306/)

- [Metasploit Unleashed Admin MySQL Auxiliary Modules](https://www.offensive-security.com/metasploit-unleashed/admin-mysql-auxiliary-modules/)