
##-===============================================-##
##   [+] nping - Network packet generation tool
##-===============================================-##



## ---------------------------------------------------------------------- ##
##   [?] Echo Mode - see how the generated probes change in transit
##   [?] Revealing the differences between the transmitted packets 
##   [?] And the packets received at the other end
## ---------------------------------------------------------------------- ##



##-================================-##
##   [+] nping - TCP Probe Mode:
##-================================-##
nping -c 1 --tcp -p 80,433 $Domain




nping --tcp-connect			## Unprivileged TCP connect probe mode.
nping --tcp					## TCP probe mode.
nping --udp					## UDP probe mode.
nping --icmp				## ICMP probe mode.
nping --arp					## ARP/RARP probe mode.
nping --traceroute			## Traceroute mode



##-================================-##
##   [+] nping - TCP CONNECT MODE
##-================================-##
nping --dest-port					## Set destination port(s)
nping --source-port $Port			## Try to use a custom source port



nping --interface 



##-================================-##
##   [+] nping - IPv6 OPTIONS:
##-================================-##
nping --IPv6
nping --dest-ip


nping --dest-mac					## Set destination mac address
nping --source-mac <mac>               ## Set source MAC address.
nping --ether-type <type>			## Set EtherType value.




nping --source-ip $SrcAddr		## Set source IP address.
nping --dest-ip $DstAddr		## Set destination IP address
nping --tos $TOS				## Set type of service field (8bits).
nping --id  $ID					## Set identification field (16 bits).
nping --df						## Set Dont Fragment flag.
nping --mf						## Set More Fragments flag.
nping --ttl $Hops				## Set time to live

nping -send-eth                       : Send packets at the raw ethernet layer.
nping --send-ip                        : Send packets using raw IP sockets.
nping --bpf-filter <filter spec>       : Specify custom BPF filter




nping --tcp -p 80 --flags rst --ttl 2 192.168.1.1
nping --icmp --icmp-type time --delay 500ms 192.168.254.254
nping --echo-server "public" -e wlan0 -vvv
nping --echo-client "public" $Domain --tcp -p1-1024 --flags ack


nping -c 1 --tcp -p 22 --flags syn $IP

nping -tcp -p 445 -data hexdata(AF56A43D) $IP


