##
# Configure logging
##
iptables -N LOGDROP > /dev/null 2> /dev/null
iptables -F LOGDROP
iptables -A LOGDROP -j LOG --log-prefix "LOGDROP "
iptables -A LOGDROP -j DROP

##
# Block simple announcements
##
iptables -A FORWARD -m string --algo bm --string "BitTorrent" -j LOGDROP
iptables -A FORWARD -m string --algo bm --string "BitTorrent protocol" -j LOGDROP
iptables -A FORWARD -m string --algo bm --string "peer_id=" -j LOGDROP
iptables -A FORWARD -m string --algo bm --string ".torrent" -j LOGDROP
iptables -A FORWARD -m string --algo bm --string "announce.php?passkey=" -j LOGDROP
iptables -A FORWARD -m string --algo bm --string "torrent" -j LOGDROP
iptables -A FORWARD -m string --algo bm --string "announce" -j LOGDROP
iptables -A FORWARD -m string --algo bm --string "info_hash" -j LOGDROP

##
# Block DHT annoucements
##
iptables -A FORWARD -m string --string "get_peers" --algo bm -j LOGDROP
iptables -A FORWARD -m string --string "announce_peer" --algo bm -j LOGDROP
iptables -A FORWARD -m string --string "find_node" --algo bm -j LOGDROP


##
# Block common tracker ports
##
iptables -A OUTPUT -p tcp --dport 22 -j DROP # Also used for SSH however a few trackers misuse the port. Consider the collatoral damage here.
iptables -A OUTPUT -p udp --dport 22 -j DROP # Also used for SSH however a few trackers misuse the port. Consider the collatoral damage here.
iptables -A OUTPUT -p tcp --dport 1337 -j DROP
iptables -A OUTPUT -p udp --dport 1337 -j DROP
iptables -A OUTPUT -p tcp --dport 6969 -j DROP
iptables -A OUTPUT -p udp --dport 6969 -j DROP
iptables -A OUTPUT -p tcp --dport 2710 -j DROP
iptables -A OUTPUT -p udp --dport 2710 -j DROP
iptables -A OUTPUT -p tcp --dport 6881-6889 -j DROP
iptables -A OUTPUT -p udp --dport 6881-6889 -j DROP

##
# Block known trackers
##
iptables -A OUTPUT -p tcp -m string --string "thepiratebay.org" --algo kmp -j REJECT
iptables -A OUTPUT -p tcp -m string --string "yts.am" --algo kmp -j REJECT
iptables -A OUTPUT -p tcp -m string --string "1337x.to" --algo kmp -j REJECT
iptables -A OUTPUT -p tcp -m string --string "rarbg.to" --algo kmp -j REJECT
iptables -A OUTPUT -p tcp -m string --string "rutracker.org" --algo kmp -j REJECT
iptables -A OUTPUT -p tcp -m string --string "nyaa.si" --algo kmp -j REJECT
iptables -A OUTPUT -p tcp -m string --string "torrentz2.eu" --algo kmp -j REJECT
iptables -A OUTPUT -p tcp -m string --string "cinecalidad.to" --algo kmp -j REJECT
iptables -A OUTPUT -p tcp -m string --string "eztv.re" --algo kmp -j REJECT
iptables -A OUTPUT -p tcp -m string --string "horriblesubs.info" --algo kmp -j REJECT
iptables -A OUTPUT -p tcp -m string --string "zooqle.com" --algo kmp -j REJECT
iptables -A OUTPUT -p tcp -m string --string "nnm-club.me" --algo kmp -j REJECT
iptables -A OUTPUT -p tcp -m string --string "kickasstorrents.to" --algo kmp -j REJECT
iptables -A OUTPUT -p tcp -m string --string "kickasstorrents.ee" --algo kmp -j REJECT
iptables -A OUTPUT -p tcp -m string --string "kickasskat.top" --algo kmp -j REJECT
iptables -A OUTPUT -p tcp -m string --string "katcr.co" --algo kmp -j REJECT
iptables -A OUTPUT -p tcp -m string --string "katcr.to" --algo kmp -j REJECT
iptables -A OUTPUT -p tcp -m string --string "torrentdownloads.me" --algo kmp -j REJECT
iptables -A OUTPUT -p tcp -m string --string "demonoid.to" --algo kmp -j REJECT
iptables -A OUTPUT -p tcp -m string --string "demonoid.pw" --algo kmp -j REJECT
