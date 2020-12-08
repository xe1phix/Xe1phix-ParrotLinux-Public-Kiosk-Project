#!/bin/sh
## 
##-=======================================================================-##
##  [+] Block Outgoing Traffic With The Destination Marked As India (IN)
##-=======================================================================-##
iptables -A OUTPUT -m geoip --dst-cc IN -j DROP
