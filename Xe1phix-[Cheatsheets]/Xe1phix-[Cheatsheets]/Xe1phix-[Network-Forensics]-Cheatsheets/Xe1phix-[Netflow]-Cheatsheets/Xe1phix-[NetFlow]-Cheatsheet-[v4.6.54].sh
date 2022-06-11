#!/bin/sh



##-=================================================-##
##   [+] Read PCAP File - Extract 80 & 443 Packets
##-=================================================-##
tcpflow -c -e -r $File.pcap 'tcp and port (80 or 443)'
tcpflow -r $File.pcap tcp and port \(80 or 443\)


##-================================================-##
##   [+] Record on eth0 - Extract Port 80 Packets
##-================================================-##
tcpflow -p -c -i eth0 port 80


##-================================================-##
##   [+] Capture Port 80 With Snap Length: 96
##-================================================-##
tcpflow -i eth0 -b 96 -e -c port 80


##-================================================-##
##   [+] tcp/ip session reassembler:
##-================================================-##
tcpflow -i eth0 -e -c 'port 25'


##-================================================-##
##   [+] Process PCAP Files in Current Directory
##-================================================-##
tcpflow -o $File -a -l *.pcap


##-===================================================-##
##   [+] Record All Packets Going To & From $Domain
##   [+] Extract All of The HTTP Attachments:
##-===================================================-##
tcpflow -e scan_http -o $Dir host $Domain


##-=================================================================-##
##    [+] record traffic between helios and either hot or ace
##    [+] bin the results into 1000 files per directory
##    [+] calculate the MD5 of each flow:
##-=================================================================-##
tcpflow -X $File.xml -e scan_md5 -o $Dir -Fk host helios and \( hot or ace \)







flow-stat — Generate reports with flow data.


Provide a report  on  top  source/destination  IP  pairs  sorted  by
octets,  report  in percent total form for the flows in /flows/krc4.
Use the preload option to flow-cat to preserve meta information  and
display it with flow-stat.

flow-cat -p /flows/krc4 | flow-stat -f10 -P -p -S4



Provide  a top destination IP address report by outbound traffic, ie
the top sinks of traffic on the campus network.  Assume the  ifIndex
of the campus interface is 5.

flow-cat  -p  /flows/krc4  | flow-filter -I5 | flow-stat -f8 -P -p -S3



EXAMPLES
Provide a top source/destination AS report.
Use symbolic names.

flow-cat -p /flows/krc4 | flow-stat -f20 -n -P -p -S4





Network topology and flow.acl
The network topology and flow.acl will be used for many of the exam‐
ples that follow.  Flows are collected and stored in /flows/R.

                               ISP-A       ISP-B
                                +           +
                                 +         +
                   IP=10.1.2.1/24 +       + IP=10.1.1.1/24
                        ifIndex=2  +     +  ifIndex=1
              interface=serial1/1   +   +   interface=serial0/0
                                    -----
                                    | R | Campus Router
                                    -----
                                    +   +
                  IP=10.1.4.1/24   +     +   IP=10.1.3.1/24
                       ifIndex=4  +       +  ifIndex=3
           interface=Ethernet1/1 +         + interface=Ethernet0/0
                                +           +
                              Sales      Marketing



Finding spoofed addresses
Display all flow records that originate from the campus and are sent
       to the Internet but are not using legal addresses.

flow-cat /flows/R | flow-filter -Snot_campus -I1,2 | flow-print



Summary  of  the  destinations  of  the internally spoofed addresses sorted by octets.

flow-cat /flows/R | flow-filter -Snot_campus -I1,2 |  flow-stat  -f8 -S2



Summary of the sources of the internally spoofed addresses sorted by flows.

flow-cat /flows/R | flow-filter -Snot_campus -I1,2 |  flow-stat  -f9 -S1



Summary  of  the  internally  spoofed  sources and destination pairs sorted by packets.

flow-cat /flows/R | flow-filter -Snot_campus -I1,2 | flow-stat  -f10 -S4



       Display  all flow records that originate external to the campus that
       have campus addresses.  Many times these can be attackers trying  to
       exploit  host based authentication mechanisms like unix r* commands.
       Another common source is mobile  clients  which  send  packets  with
       their campus addresses before obtaining a valid IP.

flow-cat /flows/R | flow-filter -Scampus -i1,2 | flow-print

Summary  of  the  destinations  of  the externally spoofed addresses sorted by octets.






Locate hosts using or running services
       Find all SMTP servers active during the collection period that  have
       established  connections  to  the  Internet.   Summarize  sorted  by
       octets.

flow-cat /flows/R | flow-filter -I1,2 -P25 | flow-stat -f9 -S2



       Find all outbound NNTP connections to the Internet.  Summarize  with
       source and destination IP sorted by octets.

flow-cat /flows/R | flow-filter -I1,2 -P119 | flow-stat -f10 -S3



       Find  all  inbound NNTP connections to the Internet.  Summarize with
       source and destination IP sorted by octets.

flow-cat /flows/R | flow-filter -i1,2 -P119 | flow-stat -f10 -S3





Multicast usage
Summarize Multicast S,G where sources are on campus.

flow-cat /flows/R | flow-filter -Dmulticast -I1,2 |  flow-stat  -f10 -S3



Summarize Multicast S,G where sources are off campus.

flow-cat  /flows/R  | flow-filter -Dmulticast -i1,2 | flow-stat -f10 -S3






Find scanners
Find SMTP scanners  with  flow-dscan.   This  will  also  find  SMTP
clients which try to contact many servers.
This behavior is characterized by a recent Microsoft worm.


touch dscan.suppress.src dscan.suppress.dst
flow-cat /flows/R | flow-filter -P25 | flow-dscan -b



flowtop  - top-like netfilter TCP/UDP/SCTP/DCCP/ICMP(v6) flow tracking



flowtop --show-src
flowtop -46UTDISs



echo 1 > /proc/sys/net/netfilter/nf_conntrack_acct
echo 1 > /proc/sys/net/netfilter/nf_conntrack_timestamp
net.netfilter.nf_conntrack_timestamp





flow-capture  — Manage storage of flow file archives by expiring old data.





Receive  flows  from the exporter at 10.0.0.1 port 9800.
Maintain 5 Gigabytes of flow files in /flows/krc4.
Mask the source and  destination   IP   addresses
contained   in   the   flow  exports  with 255.255.248.0.


flow-capture -w /flows/krc4 -m 255.255.248.0 -E5G 0/10.0.0.1/9800



Receive flows from any exporter on port 9800.
Do  not  perform  any flow file space management.
Store the exports in /flows/krc4.  Emit a stat log message every 5 minutes.

flow-capture -w /flows/krc4 0/0/9800 -S5







flow-dscan — Detect scanning and other suspicious network activity

In a topology where 25 is the only output interface  run
flow-dscanover  the  data  in  /flows/krc4.
Ignore www and multicast traffic,store the internal state in dscan.statefile on exit.  Use empty sup‐
       press  list  files  dscan.suppress.src  and dscan.suppress.dst.  The
       output produced by flow-dscan typically must be  manually  inspected
       by  using  flow-filter  and  flow-print.
Many of the alerts will be false until the suppress lists are populated for the local  environ‐
       ment.


flow-cat /flows/krc4 | flow-dscan -I25 -b -m -s dscan.statefile -p -W




Print all traffic with a destination port of 80.

flow-cat /flows/krc4 | flow-filter -P80 | flow-print



Print  all  traffic with with source IP 10.0.0.1.
Populate flow.acl with ip access-list standard badguy permit host 10.0.0.1

flow-cat /flows/krc4 | flow-filter -Sbadguy | flow-print



Report all destinations that IP 10.0.0.1 has sent traffic to.   Sort
by octets.  Populate flow.acl with
ip access-list standard badguy permit host 10.0.0.1

flow-cat /flows/krc4 | flow-filter -Sbadguy | flow-stat -f8 -S2








flow-gen — Generate test flows

Generate a test pattern of 1000 version 5 flows and send them in the
Cisco NetFlow packet format to 10.0.0.1 port 9500.

flow-gen -V5 | flow-send 0/10.0.0.1/9500




flow-header — Display meta information in flow file

flow-header  <  flow‐file



Display flows in flowfile

flow-print < flowfile





flow-report — Generate reports from flow data.


flow-cat flows | flow-report -stest -Stest







flow-nfilter utility will filter flows based on filter criteria


flow-cat flows | flow-nfilter -ftest -Ffoo | flow-print

