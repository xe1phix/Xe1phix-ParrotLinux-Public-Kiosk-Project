#!/bin/sh
## --------------- ##
## BlockShellshock.sh
## --------------- ##

# Block Shellshock
$IPTABLES -A INPUT -m string --algo bm --hex-string '|28 29 20 7B|' -j DROP
$IP6TABLES -A INPUT -m string --algo bm --hex-string '|28 29 20 7B|' -j DROP
