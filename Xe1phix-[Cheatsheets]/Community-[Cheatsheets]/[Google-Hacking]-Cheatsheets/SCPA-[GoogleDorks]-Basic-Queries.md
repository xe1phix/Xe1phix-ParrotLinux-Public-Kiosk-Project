# 01 -  Basic Search

`site:*.website.com -site:www.website.com`

`filetype:xls site:info.website.com`

# 02 - Network Protocols

`inurl:ftp`

`inurl:ldap`

`inurl:smtp`

`inurl:imap`

# 03 - Sensitive Data

## 3.1 - Sensitive Files

- **Confidential Documents**

`ext:(doc | pdf | xls | txt | ps | rtf | odt | sxw | psw | ppt | pps | xml) (intext:confidential salary | intext:"budget approved") inurl:confidential`

`ext:(doc | pdf | xls | txt | ps | rtf | odt | sxw | psw | ppt | pps | xml) (intext:confidential salary | intext:"budget approved") inurl:confidential`

- **History Commands**

`intitle:"index of" ./bash_history`

## 3.2 - Database Leaks

- **PHPMyAdmin**

`"phpMyAdmin MYSQL-Dump" "INSERT INTO" -"the"`

`"phpMyAdmin MySQL-Dump" filetype:txt`

`filetype:sql "insert into" (pass|passwd|password)`

`filetype:sql ("values * MD5" | "values * password" | "values * encrypt")`

`filetype:sql +"IDENTIFIED BY" -cvs`

`filetype:sql password`

## 3.3 - Panels

- **PHPMyAdmin**


- **CPanel**


## 3.4 - Passwords

- **Mail Server**

`passwords site:mail.website.com`

- **SSH Keys**

`intitle:index.of id_rsa -id_rsa.pub`

## References

- [https://exposingtheinvisible.org/en/guides/google-dorking/](https://exposingtheinvisible.org/en/guides/google-dorking/)

- [https://kit.exposingtheinvisible.org/en/how/google-dorking.html](https://kit.exposingtheinvisible.org/en/how/google-dorking.html)

- [https://gbhackers.com/latest-google-dorks-list/](https://gbhackers.com/latest-google-dorks-list/)
