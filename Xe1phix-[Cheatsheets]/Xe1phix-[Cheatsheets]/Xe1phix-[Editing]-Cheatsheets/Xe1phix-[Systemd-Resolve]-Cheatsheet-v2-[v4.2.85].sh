echo "nameserver 8.8.8.8" |sudo tee -a /etc/resolv.conf #Misconfigured resolv.conf File
sudo systemctl restart systemd-resolved.service 

sudo chown root:root /etc/resolv.conf #Misconfigured Permissions
sudo chmod 644 /etc/resolv.conf


----------------------------------------------------------------------------------------------------
#using systemd resolved service to cache DNS entries

systemctl is-active systemd-resolved.service #find out whether the service is running use
systemd-resolve --statistics
systemd-resolve -4 vg-centos-02 #Resolve IPv4 addresses

systemctl restart systemd-resolved.service
