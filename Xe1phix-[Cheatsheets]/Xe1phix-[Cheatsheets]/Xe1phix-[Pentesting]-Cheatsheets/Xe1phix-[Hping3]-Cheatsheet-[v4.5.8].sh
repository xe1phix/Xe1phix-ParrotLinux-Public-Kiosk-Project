#!/bin/sh


##-=============================-##
##  [+] ICMP Ping
##-=============================-##
hping3 -1 $IP


##-=============================-##
##  [+] ACK Scan on port 80
##-=============================-##
hping3 -A $IP -p 80


##-=============================-##
##  [+] UDP Scan on port 80
##-=============================-##
hping3 -2 $IP p 80


##-=============================-##
##  [+] SYN Scan on port 50-60
##-=============================-##
hping3 -8 50-60 -s $IP -v


##-=============================-##
##  [+] FIN PUSH URG Scan 
##-=============================-##
hping3 -F -p -U $IP -p 80


##-=============================-##
##  [+] Scan Entire Subnet
##-=============================-##
hping3 -1 10.0.1.x --rand-dest -I eth0


##-=======================================================-##
##  [+] Intercept All Traffic Containing HTTP Signature:
##-=======================================================-##
hping3 -9 HTTP -I eth0


##-=======================================-##
##  [+] Collect Initial Sequence Number:
##-=======================================-##
hping3 $IP -Q -p 139 -s





##-=============================-##
##  [+] 
##-=============================-##
hping3 -S -p 53 $IP


##-=============================-##
##  [+] 
##-=============================-##
hping3 --udp -p 500 $IP
hping3 --udp -p 123 $IP



##-=============================-##
##  [+] 
##-=============================-##
hping3 -V -p 80 -s 5050 <scan_type> $Domain


  * `-V|--verbose` - verbose mode
  * `-p|--destport` - set destination port
  * `-s|--baseport` - set source port
  * `<scan_type>` - set scan type
    * `-F|--fin` - set FIN flag, port open if no reply
    * `-S|--syn` - set SYN flag
    * `-P|--push` - set PUSH flag
    * `-A|--ack` - set ACK flag (use when ping is blocked, RST response back if the port is open)
    * `-U|--urg` - set URG flag
    * `-Y|--ymas` - set Y unused flag (0x80 - nullscan), port open if no reply
    * `-M 0 -UPF` - set TCP sequence number and scan type (URG+PUSH+FIN), port open if no reply



##-=============================-##
##  [+] 
##-=============================-##
hping3 -V -c 1 -1 -C 8 $Domain


  * `-c [num]` - packet count
  * `-1` - set ICMP mode
  * `-C|--icmptype [icmp-num]` - set icmp type (default icmp-echo = 8)



##-=============================-##
##  [+] 
##-=============================-##
hping3 -V -c 1000000 -d 120 -S -w 64 -p 80 --flood --rand-source <remote_host>





##-======================-##
##   [+] HPING3 Scans
##-======================-##
hping3 -c 3 -s 53 -p 80 -S 192.168.0.1

## Open = flags = SA
## Closed = Flags = RA
## Blocked = ICMP unreachable
## Dropped = No response



## takes a text file called udp.txt and sends probes to each UDP port number listed in that file

for port in `cat udp.txt`; do echo TESTING UDP PORT: $port; hping3 -2 -p $port -c 1 $IP; done



DoS from spoofed IPs:

hping3 $TargetIP --flood --frag --spoof $ip --destport # --syn



