##-===================================================-##
##   [+]  /etc/NetworkManager/dispatcher.d/50-wg0.sh
##-===================================================-##

start WireGuard using a dispatcher script

#!/bin/sh
case $2 in
  up)
    wg-quick up wg0
    ip route add <endpoint ip> via $IP4_GATEWAY dev $DEVICE_IP_IFACE
    ;;
  pre-down)
    wg-quick down wg0
    ;;
esac
