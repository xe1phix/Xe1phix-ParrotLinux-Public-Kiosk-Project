# 09 - WebDAV

## 9.1 - WebDAV Detection

### 9.1.1 - Metasploit

- **Metasploit auxilary module HTTP WebDAV Scanner**

```
msf > use auxiliary/scanner/http/webdav_scanner

msf auxiliary(scanner/http/webdav_scanner) > options

Module options (auxiliary/scanner/http/webdav_scanner):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   PATH     /                yes       Path to use
   Proxies                   no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS                    yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
   RPORT    80               yes       The target port (TCP)
   SSL      false            no        Negotiate SSL/TLS for outgoing connections
   THREADS  1                yes       The number of concurrent threads (max one per host)
   VHOST                     no        HTTP server virtual host


View the full module info with the info, or info -d command.

msf auxiliary(scanner/http/webdav_scanner) > set path </uri_path>

msf auxiliary(scanner/http/webdav_scanner) > set threads 8

msf auxiliary(scanner/http/webdav_scanner) > set rhosts <IP>

msf auxiliary(scanner/http/webdav_scanner) > set rport <PORT>

msf auxiliary(scanner/http/webdav_scanner) > run
```

## 9.2 - File Upload

### 9.2.1 - Davtest

`$ davtest -cleanup -url http[s]://<IP>`

### 9.2.2 - cadaver

```
$ cadaver http[s]://<IP>
dav:\> put file.txt

dav:\> copy file.txt webshell.php
```

### 9.2.3 - Nmap

`$ nmap -p 80,443 --script http-put --script-args http-put.url='<upload_directory>',http-put.file='<file>' <IP>`

## 9.3 - Internal IP

### 9.3.1 - Metasploit

- **Metasploit auxilary module HTTP WebDAV Internal IP Scanner**

```
msf > use auxiliary/scanner/http/webdav_internal_ip

msf auxiliary(scanner/http/webdav_internal_ip) > options

Module options (auxiliary/scanner/http/webdav_internal_ip):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   PATH     /                yes       Path to use
   Proxies                   no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS                    yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
   RPORT    80               yes       The target port (TCP)
   SSL      false            no        Negotiate SSL/TLS for outgoing connections
   THREADS  1                yes       The number of concurrent threads (max one per host)
   VHOST                     no        HTTP server virtual host


View the full module info with the info, or info -d command.

msf auxiliary(scanner/http/webdav_internal_ip) > set path </uri_path>

msf auxiliary(scanner/http/webdav_internal_ip) > set threads 8

msf auxiliary(scanner/http/webdav_internal_ip) > set rhosts <IP>

msf auxiliary(scanner/http/webdav_internal_ip) > set rport <PORT>

msf auxiliary(scanner/http/webdav_internal_ip) > run
```

## 9.4 - WebDAV Website Content

### 9.4.1 - Metasploit

```
msf > use auxiliary/scanner/http/webdav_website_content

msf auxiliary(scanner/http/webdav_website_content) > options

Module options (auxiliary/scanner/http/webdav_website_content):

  Name     Current Setting  Required  Description  
  ----     ---------------  --------  -----------  
  PATH     /                yes       Path to use
  Proxies                   no        A proxy chain of format type:host:port[,type:host:port][...]
  RHOSTS                    yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
  RPORT    80               yes       The target port (TCP)
  SSL      false            no        Negotiate SSL/TLS for outgoing connections
  THREADS  1                yes       The number of concurrent threads (max one per host)
  VHOST                     no        HTTP server virtual host


View the full module info with the info, or info -d command.
  
msf auxiliary(scanner/http/webdav_website_content) > set path </uri_path>

msf auxiliary(scanner/http/webdav_website_content) > set threads 8

msf auxiliary(scanner/http/webdav_website_content) > set rhosts <IP>

msf auxiliary(scanner/http/webdav_website_content) > set rport <PORT>

msf auxiliary(scanner/http/webdav_website_content) > run
```