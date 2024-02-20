#!/bin/bash
 
# Add the Docker repository key to your local keychain
# using apt-key finger you can check the fingerprint matches 36A1 D786 9245 C895 0F96 6E92 D857 6A8B A88D 21E9
sh -c "wget -qO- https://get.docker.io/gpg | apt-key add -"
 
# Add the Docker repository to your apt sources list.
sudo sh -c "echo deb http://get.docker.io/ubuntu docker main > /etc/apt/sources.list.d/docker.list"
 
# update
apt-get update
 
# install
apt-get install -y lxc-docker
 
# download the base 'ubuntu' container
# and run bash inside it while setting up an interactive shell
sudo docker run -i -t ubuntu /bin/bash