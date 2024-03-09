#!/bin/sh


##-================================================================-##
##   [+] HTTPry - Listen on eth0 and save output to binary PCAP:
##-================================================================-##
httpry eth0 -b $Dir/$File.pcap



##-==============================================-##
##   [+] HTTPry - Filter output by HTTP verbs:
##-==============================================-##
httpry -m get|post|head|options|delete|trace|connect|patch


##-================================================================-##
##   [+] HTTPry - Read from input capture file and filter by IP:
##-================================================================-##
httpry -r $Dir/$File.log 'host $IP'
httpry -r $Dir/$File.log 'host 192.168.0.25'


##-=========================================-##
##   [+] HTTPry - Run as daemon process:
##-=========================================-##
httpry -d -o $Dir/$File.log

