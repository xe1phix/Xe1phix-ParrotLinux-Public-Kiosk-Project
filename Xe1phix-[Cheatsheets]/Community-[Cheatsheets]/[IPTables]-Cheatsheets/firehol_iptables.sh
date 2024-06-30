
#this may take a while, run with no hup and monitor the log
rm blocklist-ipsets/ -r
git clone https://github.com/firehol/blocklist-ipsets.git
cd blocklist-ipsets/
#We just want the IP's
grep -E -o "([0-9]{1,3}[\.]){3}[0-9]{1,3}" *.ipset > merged-file
#We just want the unique IP's across the board
sort -u merged-file > merged-file_output
#Just the unique ips, iptables
for IP in $(cat merged-file_output | grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b" | awk '{print $1}' | sort | uniq); do echo "Banning $IP"; iptables -A INPUT -s $IP/32 -d 0/0 -j DROP; iptables -A INPUT -s $IP/32 -d 0/0 -j LOG --log-prefix 'firehol-iptables-rule-js'; done
echo "yay, Finished!"
