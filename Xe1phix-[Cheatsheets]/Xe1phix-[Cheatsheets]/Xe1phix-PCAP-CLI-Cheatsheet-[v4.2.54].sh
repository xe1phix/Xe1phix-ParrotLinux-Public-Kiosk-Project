#!/bin/sh

## ------------------------------ ##
##    [?] Extract PCAP Data:
## ------------------------------ ##
capinfos $File.pcap
tcpslice -r $File.pcap
tcpstat $File.pcap
tcpprof -S lipn -P 30000 -r $File.pcap
tcpflow -r $File.pcap
tcpxtract -f $File.pcap -o $Dir/
tcpick -a -C -r $File.pcap
tcpcapinfo $File.pcap
ngrep -I $File.pcap
nfdump -r $File.pcap
chaosreader -ve $File.pcap
tshark -r $File.pcap
tcpdump -r $File.pcap
bro -r $File.pcap
snort -r $File.pcap
