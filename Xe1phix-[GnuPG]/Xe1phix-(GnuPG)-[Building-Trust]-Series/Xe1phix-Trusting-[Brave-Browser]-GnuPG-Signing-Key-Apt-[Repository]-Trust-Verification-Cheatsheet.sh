#!/bin/sh
##-=========================================================================-##
##  [+] Brave GnuPG Public Key + Debian .Deb Repositories - Sources.list
##-=========================================================================-##
curl -s https://s3-us-west-2.amazonaws.com/brave-apt/keys.asc | sudo apt-key add -
echo "deb [arch=amd64] https://s3-us-west-2.amazonaws.com/brave-apt jessie main" | sudo tee /etc/apt/sources.list.d/brave-jessie.list
sudo apt update && sudo apt install -y brave
