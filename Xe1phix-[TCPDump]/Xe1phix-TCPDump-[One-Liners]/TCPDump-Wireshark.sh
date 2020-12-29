#!/bin/sh
##-==================================================-##
##  [+] Capture with tcpdump and view in Wireshark
##-==================================================-##
tcpdump -s0 -c 1000 -nn -w - not port 22 | wireshark -k -i -
