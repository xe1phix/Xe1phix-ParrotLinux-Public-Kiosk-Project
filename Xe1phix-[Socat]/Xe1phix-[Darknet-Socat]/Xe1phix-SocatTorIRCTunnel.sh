#!/bin/sh
## Xe1phix-SocatTorIRCListener.sh

## Create A Listener At localhost:1234 For A Tunnel 
## To Freenode's Onion On Port 6667 
## (Remember To Change This If You're Using EXTERNAL.)
socat TCP4-LISTEN:1234,fork SOCKS4A:localhost:freenodeok2gncmy.onion:6667,socksport=9050 
