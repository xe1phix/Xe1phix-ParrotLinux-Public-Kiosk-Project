#!/bin/sh

ss -t				## show established TCP connections
ss -u 				## show established UDP connections
ss -A tcp 
ss -x 
ss -ltn 			## see which ports are listening for connections
ss -nt
ss -ltn
ss -ua
ss -a -A udp
ss -lun ->udp
ss -s			## prints out the statistics

##  [?] ss is the socket statistics 

ss -tr #netstat -t
ss -ntr #see port numbers
ss -an |grep LISTEN #netstat -an |grep LISTEN
ss -an | grep 2500 #show SCTP open ports
ss -tlw # list open ports in the listening state
ss -plno -A tcp,udp,sctp #The UNCONN state shows the ports in UDP listening mode
