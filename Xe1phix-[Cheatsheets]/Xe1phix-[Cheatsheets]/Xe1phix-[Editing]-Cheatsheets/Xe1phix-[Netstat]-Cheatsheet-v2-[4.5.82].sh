#show routing table without resolving domain names
netstat -nr
netstat -r -n # The flag U indicates that route is up and G indicates that it is gateway 
netstat -alun | grep 161
# show informations about errors/collisions
netstat -ni  
# show statistics about your network card
netstat -i -I em0  
netstat -a
netstat -at
netstat -s
netstat -au
netstat -l
netstat -lu
netstat -lt
netstat -tulpn  	
netstat -plan
netstat -plan | grep ":80"
netstat -lntp | grep ':8080.*java' > /dev/null && command
netstat -pan -A inet,inet6 | grep -v ESTABLISHED #determine which ports are listening for connections from the network
netstat -tlnw #Use the -l option of the netstat command to display only listening server sockets:
netstat -plnS #Scan for Open SCTP Ports
netstat -nl -A inet,inet6 | grep 2500 #Scan for Open SCTP Ports
netstat -pant | grep -Ei 'apache|:80|:443'
netstat -tunlp | grep ":80 "
List all TCP sockets and related PIDs
netstat -antp
netstat -anp
List all UDP sockets and related PIDs
netstat -anup
# find out on which port a program is running
netstat -ap | grep ssh
#If there is an IP address instead, then the port is open only on that specific interface
#For listening ports, if the source address is 0.0.0.0, it is listening on all available interfaces
#The Recv-Q and Send-Q fields show the number of bytes pending acknowledgment in either direction
#the PID/Program name field shows the process ID and the name of the process responsible for the listening port or connection
netstat -anptu 
#number of established connection
netstat -an|grep ESTABLISHED|awk '{print $5}'|awk -F: '{print $1}'|sort|uniq -c|awk '{ printf("%s\t%s\t",$2,$1); for (i = 0; i < $1; i++) {printf("*")}; print ""}'

#see that the Nessus server is up and running
netstat -n | grep tcp
netstat -tap | grep LISTEN
netstat -pltn | grep 8834
