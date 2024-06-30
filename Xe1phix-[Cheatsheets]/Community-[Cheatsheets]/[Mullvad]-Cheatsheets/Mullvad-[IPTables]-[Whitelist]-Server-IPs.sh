#!/bin/bash

cd `dirname $0`

echo "flushing iptables"
  sudo iptables -F


  # Allow traffic to any mullvad server.
echo "enabling outbound mullvad traffic"
  for remote in `cat mullvadIPs.txt | awk '/remote [0-9]+\.[0-9]+\.[0-9]+\./ { print $2; }'`;

  do

	remote=$remote"0/16"
        sudo iptables -A INPUT -s $remote -j ACCEPT

  done


  # Allow local traffic.
echo "enabling outbound local traffic"
  sudo iptables -A INPUT -s 10.0.0.0/8 -j ACCEPT

  sudo iptables -A INPUT -s 172.16.0.0/12 -j ACCEPT

  sudo iptables -A INPUT -s 192.168.0.0/16 -j ACCEPT

  sudo iptables -A INPUT -s 127.0.0.1 -j ACCEPT


  # Disallow everything else.
echo "blocking other outbound traffic"
  sudo iptables -A INPUT ! -i tun+ -j DROP


  # Allow traffic from any mullvad server.
echo "enabling inbound mullvad traffic"
  for remote in `cat mullvadIPs.txt | awk '/remote [0-9]+\.[0-9]+\.[0-9]+\./ { print $2; }'`;

  do

	remote=$remote"0/8"
        sudo iptables -A OUTPUT -d $remote -j ACCEPT

  done


  # Allow local traffic.
echo "enabling inbound local traffic"
  sudo iptables -A OUTPUT -d 10.0.0.0/8 -j ACCEPT

  sudo iptables -A OUTPUT -d 172.16.0.0/12 -j ACCEPT

  sudo iptables -A OUTPUT -d 192.168.0.0/16 -j ACCEPT

  sudo iptables -A OUTPUT -d 127.0.0.1 -j ACCEPT


  # Disallow everything else.
echo "blocking other inbound traffic"
  sudo iptables -A OUTPUT ! -o tun+ -j DROP
