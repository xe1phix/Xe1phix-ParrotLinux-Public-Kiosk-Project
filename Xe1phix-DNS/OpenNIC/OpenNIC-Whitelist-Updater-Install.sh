#!/bin/bash

# Ask if user is root
if [[ $EUID -ne 0 ]] && [[ "$(id -u)" -ne 0 ]]; then
   echo "This script must be run as root" 1>&2
   exit 1
fi

# Install dnspython module
apt-get install python-dnspython

# Remove any crons from previous versions.
rm /etc/cron.d/opennic_update 2> /dev/null

# Remove previous script
rm /opt/opennic/update.py* 2> /dev/null

# Get API username and key from the user
echo -n "Enter your OpenNIC username (provided by http://www.opennicproject.org/members/) and press [ENTER]: "
read username

echo -n "Enter your OpenNIC auth key: (not your password) and press [ENTER]: "
read key

# Make directory for script. 
mkdir -p /usr/local/bin/opennic-update 2> /dev/null

# Enter this directory.
cd /usr/local/bin/opennic-update

# Remove previous script
rm update.py 2> /dev/null

# Download the script.
wget --quiet https://raw.githubusercontent.com/CalumMc/OpenNIC-Whitelist-Updater/master/update.py
chmod 755 update.py

# Make directory for config. 
mkdir /etc/opennic-update 2> /dev/null

# Enter this directory.
cd /etc/opennic-update

# Remove previous config file
rm /etc/opennic-update/opennic-update.conf 2> /dev/null

# Download the default config.
wget --quiet https://raw.githubusercontent.com/CalumMc/OpenNIC-Whitelist-Updater/master/opennic-update.conf

sed -i -e s/USER_HERE/"$username"/g opennic-update.conf
sed -i -e s/KEY_HERE/"$key"/g opennic-update.conf

# Remove previous init.d script
rm /etc/init.d/opennic-update 2> /dev/null

# Download the init.d script
cd /etc/init.d
wget --quiet https://raw.githubusercontent.com/CalumMc/OpenNIC-Whitelist-Updater/master/opennic-update
chmod 755 /etc/init.d/opennic-update

# Start on startup
update-rc.d opennic-update defaults

# Start the updater
/etc/init.d/opennic-update start

echo ""
echo "The IP updater has been enabled."
echo "Please allow five minutes before checking"
echo "http://www.opennicproject.org/members/"
echo "to see if your IP is listed."
echo "For more help, connect to #opennic on Freenode."
echo "Thank you for using OpenNIC."
