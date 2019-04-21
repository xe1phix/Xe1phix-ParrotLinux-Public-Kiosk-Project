#!/bin/sh
## 
##-=========================================================-##
##  [+] OpenNIC-WhitelistDNSLookups+SyncDNSMasqServers.sh
##-=========================================================-##

##-====================================================-##
##  [+] Register IP to be whitelisted on DNS lookups
##-====================================================-##
0 12 * * * /opt/opennic-whitelist.sh -u <user> -t <token>

##-==========================================================-##
##  [+] Sync dnsmasq servers config from geoip OpenNIC API
##-==========================================================-##
5 12 * * * /opt/opennic-dnsmasq-geoip-sync.sh`

