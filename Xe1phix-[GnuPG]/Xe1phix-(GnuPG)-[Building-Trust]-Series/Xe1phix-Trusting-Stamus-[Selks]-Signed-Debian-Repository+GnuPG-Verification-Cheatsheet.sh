#!/bin/sh
#######
## Xe1phix-StamusSelksSetup.sh
#######

wget -qO - http://packages.stamus-networks.com/packages.stamus-networks.com.gpg.key | apt-key add - 
wget -qO - http://packages.stamus-networks.com/packages.selks4.stamus-networks.com.gpg.key | apt-key add - 
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | apt-key add -
wget -qO - https://evebox.org/files/GPG-KEY-evebox | sudo apt-key add -

cat >> /etc/apt/sources.list.d/elastic-5.x.list <<EOF
deb https://artifacts.elastic.co/packages/5.x/apt stable main
EOF

cat >> /etc/apt/sources.list.d/curator5.list <<EOF
deb http://packages.elastic.co/curator/4/debian stable main
EOF

cat >> /etc/apt/sources.list.d/evebox.list <<EOF
deb http://files.evebox.org/evebox/debian stable main
EOF

cat >> /etc/apt/sources.list.d/selks4.list <<EOF
# SELKS4 Stamus Networks repos
#
# Manual changes here can be overwritten during 
# SELKS updates and upgrades !!

deb http://packages.stamus-networks.com/selks4/debian/ stretch main
deb http://packages.stamus-networks.com/selks4/debian-kernel/ stretch main
#deb http://packages.stamus-networks.com/selks4/debian-test/ stretch main
EOF

sudo /bin/systemctl enable elasticsearch && \
sudo /bin/systemctl enable logstash && \
sudo /bin/systemctl enable kibana && \
sudo /bin/systemctl daemon-reload







# supervisor conf
ln -s /usr/share/doc/scirius/examples/scirius-supervisor.conf /etc/supervisor/conf.d/scirius-supervisor.conf

# Set the right permissions for the logstash user to run suricata
chown -R logstash:logstash /var/log/suricata

# www-data needs to write Suricata rules
chown -R www-data.www-data /etc/suricata/rules/


openssl req -new -nodes -x509 -subj "/C=FR/ST=IDF/L=Paris/O=Stamus/CN=SELKS" -days 3650 -keyout /etc/nginx/ssl/scirius.key -out /etc/nginx/ssl/scirius.crt -extensions v3_ca 


# set permissions for Scirius 
touch /var/log/scirius.log
touch /var/log/scirius-error.log
chown www-data /var/log/scirius*
chown -R www-data /var/lib/scirius/git-sources/
chown -R www-data /var/lib/scirius/db/
chown -R www-data.www-data /etc/suricata/rules/

# fix permissions for user www-data/scirius
usermod -a -G logstash www-data
mkdir -p /var/run/suricata/
chmod g+w /var/run/suricata/ -R
