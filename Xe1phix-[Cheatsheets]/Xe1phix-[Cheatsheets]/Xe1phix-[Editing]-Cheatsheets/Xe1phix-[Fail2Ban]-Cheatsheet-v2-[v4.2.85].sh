---------------------------------------------------------------------------------------------------- 
#Intrusion prevention with fail2ban
sudo apt update
sudo apt install fail2ban
sudo systemctl start fail2ban
sudo systemctl enable fail2ban

sudo cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
#For SSH, fail2ban will monitor the log file /var/log/auth.log using the fail2ban sshd filter

#Any attempt to login to the server failing three times (within a configurable time span) will be blocked 
#from further attempts by iptables blocking the originating IP address (for a configurable amount of time).
sudo nano /etc/fail2ban/jail.local
[sshd]
enabled = true
port = 22
filter = sshd
logpath = /var/log/auth.log

#be aware of the risk of being locked out testing the system
ignoreself = true
ignoreip = <Your-IP-address>
maxretry = 3

sudo systemctl restart fail2ban
sudo fail2ban-client status #see the enabled traffic type jails


#For HTTP, there are filters for Apache and Nginx
# a jail rule protecting HTTP authentication
#Rules can also be defined to block activities such as trying to run scripts, using a server as proxy and blocking bad bots.
[nginx-http-auth]
enabled  = true
filter   = nginx-http-auth
port     = http,https
logpath  = /var/log/nginx/error.log

sudo fail2ban-client set sshd unbanip <IP-address> #A blocked IP address is released (unbanned) 
----------------------------------------------------------------------------------------------------
