##  Basic operation of strace is simple:
strace /usr/sbin/httpd

##  In most cases you'll want to 
##  generate a file to capture the output for more detailed analysis:
strace -o strace.out /usr/sbin/httpd

##  Because many daemons fork additional processes, 
##  the "-f" option is also recommended:
strace -o strace.out -f /usr/sbin/httpd

##  To check a running process, 
##  use the "-p" option with the process number:
strace -o strace.out -fp 48511

##  When using this last mode you'll need 
##  to CNTRL-c to exit tracing.
