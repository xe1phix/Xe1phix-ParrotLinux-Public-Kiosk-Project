#!/bin/sh
##-====================================-##
##   [+] Xe1phix-[p0f]-Cheatsheet.sh
##-====================================-##


p0f -i wlan0


## ----------------------------------------- ##
##   [+] Set iface In promiscuous mode 
##   [+] dump traffic to the log file
## ----------------------------------------- ##
p0f -i eth0 -p -d -o $File.log




p0f -r $File 




## ------------------------------------------------- ##
##   [+] Xprobe2 OS fingerprinting
## ------------------------------------------------- ##
##   [?] fuzzy signature matching to provide 
##       the probable operating system assessment
## ------------------------------------------------- ##
xprobe2 $IP

xprobe2 -v -p tcp:80:open $IP
xprobe2 -v -p tcp:80:open 192.168.6.66


