

----
Tcpdump Sniffing

    Sniff anything on one interface:

tcpdump -i <interface>

    Filtering on host (source/destination/any):

tcpdump -i <interface> host <IP>
tcpdump -i <interface> src host <IP>
tcpdump -i <interface> dst host <IP>
tcpdump -i <interface> ether host <MAC>
tcpdump -i <interface> ether src host <MAC>
tcpdump -i <interface> ether dst host <MAC>

    Filtering on port (source/destination/any):

tcpdump -i <interface> port <port>
tcpdump -i <interface> src port <port>
tcpdump -i <interface> dst port <port>

    Filtering on network (e.g. network=192.168)

tcpdump -i <interface> net <network>
tcpdump -i <interface> src net <network>
tcpdump -i <interface> dst net <network>

    Protocol filtering

tcpdump -i <interface> arp
tcpdump -i <interface> ip
tcpdump -i <interface> tcp
tcpdump -i <interface> udp
tcpdump -i <interface> icmp

    Condition usage example

tcpdump -i <interface> '((tcp) and (port 80) and ((dst host 192.168.1.254) or (dst host 192.168.1.200)))'

    Disable name resolution

tcpdump -i <interface> -n

    Make sure to capture whole packet (no truncation)

tcpdump -i <interface> -s 0

    Write full pcap file

tcpdump -i <interface> -s 0 -w capture.pcap

    Show DNS traffic

tcpdump -i <interface> -nn -l udp port 53

    Show HTTP User-Agent & Hosts

tcpdump -i <interface> -nn -l -A -s1500 | egrep -i 'User-Agent:|Host:'

    Show HTTP Requests & Hosts

tcpdump -i <interface> -nn -l -s 0 -v | egrep -i "POST /|GET /|Host:"

    Show email recipients

tcpdump -i <interface> -nn -l port 25 | egrep -i 'MAIL FROM\|RCPT TO'

    Show FTP data

tcpdump -i <interface> -nn -v port ftp or ftp-data

    Show all passwords different protocols

tcpdump -i wlan0 port http or port ftp or port smtp or port imap or port pop3 or port telnet -l -A | egrep -i -B5 'pass=|pwd=|log=|login=|user=|username=|pw=|passw=|passwd=|password=|pass:|user:|username:|password:|login:|pass |user '