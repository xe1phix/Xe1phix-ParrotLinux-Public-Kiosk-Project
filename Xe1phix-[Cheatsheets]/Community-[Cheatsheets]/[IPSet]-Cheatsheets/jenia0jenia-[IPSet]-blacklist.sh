sudo apt-get install ipset 
sudo ipset create blacklist hash:ip hashsize 4096
sudo iptables -I INPUT -m set --match-set blacklist src -j DROP
sudo iptables -I FORWARD -m set --match-set blacklist src -j DROP
sudo ipset add blacklist 79.83.246.80
sudo ipset add blacklist 218.92.1.186
