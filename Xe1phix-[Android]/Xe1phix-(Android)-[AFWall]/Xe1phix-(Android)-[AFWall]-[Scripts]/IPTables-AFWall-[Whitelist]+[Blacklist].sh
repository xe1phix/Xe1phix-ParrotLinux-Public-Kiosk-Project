#!/bin/bash

WHITELIST=/whitelist.txt
BLACKLIST=/blacklist.txt

# Clear all existent rules 
echo 'Clearing all rules'
iptables -F


# Whitelist
for x in `grep -v ^# $WHITELIST | awk '{print $1}'`; do
        echo "Allowing $x..."
        $IPTABLES -A INPUT -t filter -s $x -j ACCEPT
done


# Blacklist
for x in `grep -v ^# $BLACKLIST | awk '{print $1}'`; do
        echo "Denied $x..."
        $IPTABLES -A INPUT -t filter -s $x -j DROP
done
