#!/bin/sh
##
## ------------------------------------------------------------------ ##
##  [+] gnunet-setup            || A GUI to configure GNUnet
## ------------------------------------------------------------------ ##
##  [+] gnunet-gtk              || Meta-GUI
## ------------------------------------------------------------------ ##
##  [+] gnunet-fs-gtk           || A GUI for file-sharing with GNUnet
## ------------------------------------------------------------------ ##
##  [+] gnunet-peerinfo-gtk     || A GUI for inspecting what
##                              || peers your peer knows about
## ------------------------------------------------------------------ ##
##  [+] gnunet-namestore-gtk    || Edit your GNS zones
## ------------------------------------------------------------------ ##
##  [+] gnunet-identity-gtk     || Manage your identities/pseudonyms
## ------------------------------------------------------------------ ##
##  [+] gnunet-statistics-gtk   || Visualize GNUnet statistics
## ------------------------------------------------------------------ ##



##-===================================-##
##   [+] Change its configuration:
##-===================================-##
dpkg-reconfigure -plow gnunet-server


## ------------------------------------------------------- ##
##   [+] Start, stop or restart the server manually:
## ------------------------------------------------------- ##
/etc/init.d/gnunet




/var/lib/gnunet
~gnunet/.config/gnunet.conf
gnunet-arm -s -c /etc/gnunet.conf





## ------------------------------------------------------- ##
##   [+] System-wide defaults typically located In:
## ------------------------------------------------------- ##
$GNUNET_PREFIX/share/gnunet/config.d/



## ------------------------------------------------------------------ ##
##   [?] The user-specific configuration file should be located in
## ------------------------------------------------------------------ ##
~/.config/gnunet.conf


cat $SERVICEHOME/data/hosts/* > $File



## ------------------------------------------------------------------ ##
##   [?] You can run the build-in web server by adding '-p'
##       to the OPTIONS value in the "hostlist" section of
##       gnunet.conf and opening the respective HTTPPORT to the public.
## ------------------------------------------------------------------ ##
$SERVICEHOME/data/hosts/

gnunet-peerinfo -g



##-=============================-##
##   [+] GET a URI for a peer
##-=============================-##
gnunet-peerinfo -p URI



##-=====================================-##
##   [+] Add a URI from another peer
##-=====================================-##
## ------------------------------------------------------- ##
##   [?] GNUnet peers that use UDP or WLAN
##       will discover each other automatically
## ------------------------------------------------------- ##




## ----------------------------------------------------------------- ##
##   [?] In order to hide GNUnets HTTP/HTTPS traffic perfectly, you might
## ----------------------------------------------------------------- ##
##   [?] Consider running GNUnets HTTP/HTTPS transport on port 80/443.
## ----------------------------------------------------------------- ##
##   [?] However, we do not recommend running GNUnet as root.
##   [?] Instead, forward port 80 to say 1080
## ----------------------------------------------------------------- ##


## HTTP:
iptables -t nat -A PREROUTING -p tcp -m tcp --dport 80 -j REDIRECT --to-ports 1080

## HTTPS:
iptables -t nat -A PREROUTING -p tcp -m tcp --dport 443 -j REDIRECT --to-ports 4433





##-====================================-##
##   [+] Edit the gnunet.conf config:
##-====================================-##
## ------------------------------------ ##
##   [+] HTTPS section:
## ------------------------------------ ##
##   [?] "ADVERTISED_PORT" to "80"
## ------------------------------------ ##
##   [?] "PORT" to 1080
## ------------------------------------ ##
##-====================================-##
## ------------------------------------ ##
##   [+] HTTPS section:
## ------------------------------------ ##
##   [?] "ADVERTISED_PORT" to "443"
## ------------------------------------ ##
##   [?] "PORT" to 4433.
## ------------------------------------ ##




/usr/local/lib/gnunet/libexec/


chown root:root $(DESTDIR)$(libexecdir)/gnunet-helper-vpn
chmod u+s $(DESTDIR)$(libexecdir)/gnunet-helper-vpn
chown root:root $(DESTDIR)$(libexecdir)/gnunet-helper-transport-wlan
chmod u+s $(DESTDIR)$(libexecdir)/gnunet-helper-transport-wlan
chown root:root $(DESTDIR)$(libexecdir)/gnunet-helper-transport-bluetooth
chmod u+s $(DESTDIR)$(libexecdir)/gnunet-helper-transport-bluetooth
chown root $(DESTDIR)$(libexecdir)/gnunet-helper-dns
chgrp $(GNUNETDNS_GROUP) $(DESTDIR)$(libexecdir)/gnunet-helper-dns
chmod 4750 $(DESTDIR)$(libexecdir)/gnunet-helper-dns
chgrp $(GNUNETDNS_GROUP) $(DESTDIR)$(libexecdir)/gnunet-helper-dns
chown gnunet:$(GNUNETDNS_GROUP) $(DESTDIR)$(libexecdir)/gnunet-helper-dns
chmod 2750 $(DESTDIR)$(libexecdir)/gnunet-helper-dns
chown root:root $(DESTDIR)$(libexecdir)/gnunet-helper-exit
chmod u+s $(DESTDIR)$(libexecdir)/gnunet-helper-exit
chown root:root $(DESTDIR)$(libexecdir)/gnunet-helper-nat-server
chown root:root $(DESTDIR)$(libexecdir)/gnunet-helper-nat-client
chmod u+s $(DESTDIR)$(libexecdir)/gnunet-helper-nat-server
chmod u+s $(DESTDIR)$(libexecdir)/gnunet-helper-nat-client



export GNUNET_PREFIX=/usr/local/lib # or other directory of your choice
addgroup gnunetdns
adduser --system --home "/var/lib/gnunet" --group gnunet --shell /bin/sh
./configure --prefix=$GNUNET_PREFIX/.. --with-extractor=$LE_PREFIX
make
make install            ## finally install GNUnet with:






sudo -u gnunet gnunet-arm -s



~gnunet/.config/gnunet.conf



##-=============================-##
##   [+] Start GNUnet using
##-=============================-##
gnunet-arm -s -c /etc/gnunet.conf






##-=================================================-##
##   [+] Configure and test the network settings
##-=================================================-##
## ---------------------------------------------------------- ##
##   [?] Choose which applications to run and configure databases.
## ---------------------------------------------------------- ##
gnunet-setup



GNUNET_PREFIX/../share/gnunet/config.d/


##-=================================================-##
##   [+] Obtain an initial list of GNUnet hosts
##-=================================================-##

## ---------------------------------------------------------- ##
##   [?] The default configuration contains URLs
##       where GNUnet downloads the hostlist when started.
## ---------------------------------------------------------- ##



##-===========================-##
##   [+] Copy the hostkeys
##-===========================-##
to "$SERVICEHOME/data/hosts/"




##-==============================-##
##   [+] GET a URI for a peer
##-==============================-##
gnunet-peerinfo -g



##-=====================================-##
##   [+] Add a URI from another peer
##-=====================================-##
gnunet-peerinfo -p URI


## ---------------------------------------------------------- ##
##   [?] GNUnet peers that use UDP or WLAN
##       will discover each other automatically
##       (if they are in the vicinity of each other)
## ---------------------------------------------------------- ##
##   [?] using broadcasts (IPv4/WLAN) or multicasts (IPv6).
## ---------------------------------------------------------- ##



##-=====================================-##
##   [+] Start the GnuNet local node:
##-=====================================-##
gnunet-arm -s



## ---------------------------------------------------- ##
##   [?] Once your peer is running,
##       you should then be able to access GNUnet:
## ---------------------------------------------------- ##
gnunet-search KEYWORD



##-=====================================-##
##   [+] Retrieve A File:
##-=====================================-##
## ---------------------------------------------------- ##
##  [?] The GNUNET_URI is printed by gnunet-search
##      together with a description.
## ---------------------------------------------------- ##
gnunet-download -o FILENAME GNUNET_URI





##-=====================================-##
##   [+] Publish Files on GNUnet
##-=====================================-##
gnunet-publish


## ---------------------------------------------------- ##
##  [?] After installing gnunet-gtk
##      > invoke the setup tool
##      > file-sharing GUI with:
## ---------------------------------------------------- ##
gnunet-setup
gnunet-fs-gtk














