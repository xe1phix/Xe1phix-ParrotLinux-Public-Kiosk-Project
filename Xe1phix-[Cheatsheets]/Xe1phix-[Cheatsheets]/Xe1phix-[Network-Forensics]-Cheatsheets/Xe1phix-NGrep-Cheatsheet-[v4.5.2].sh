
##-=====================================-##
##     [+] Listen to TCP traffic on eth0 device
##-=====================================-##
ngrep -d 'eth0' -W byline -t -q '^(GET|POST|PUT|HEAD|CONNECT) '



ngrep -q 'HTTP' 'tcp'							## Filter Out TCP Packets
ngrep -q 'HTTP' 'udp'							## Filter Out UDP Packets
ngrep -q 'HTTP' 'icmp'							## Filter Out ICMP Packets
ngrep -q 'HTTP' 'host 192.168'			## matches all headers containing the string 'HTTP' sent to or from the ip address starting with 192.168
ngrep -q 'HTTP' 'dst host 192.168'		## match a destination host
ngrep -q 'HTTP' 'src host 192.168'		## match a source host
ngrep -q 'HTTP' 'port 80'						## match a port




##-=======================================-##
##     [+] Sniff packets with live verbose output 
##     [+] Timestamps
##     [+] Hexadecimal values 
##     [+] ASCII strings
##-=======================================-##
ngrep -t -x 'USER|PASS|RETR|STOR' tcp port ftp and host $Domain





##-=======================================-##
##     [+] 
##-=======================================-##
ngrep -I $File.pcap -q -W single -t "GET" ip src 192.168.1.1 | awk '{ print $2, $3, $11, $9}' | sed 's/\.\{1,3\}User-Agent//' | grep -v -E '(ad|cache|analytics|wxdata|voicefive|imwx|weather.com|counterpath|cloudfront|2mdn.net|click|api|acuity|tribal|pixel|touchofclass|flickr|ytimg|pulse|twitter|facebook|graphic|revsci|digi|rss|cdn|brightcove|atdmt|btrll|metric|content|trend|serv|content|global|fwmrm|typekit|[az]*-[a-z]*\.com|pinit|cisco|tumblr)' | sed '/ [ \t]*$/d' > $File.txt


