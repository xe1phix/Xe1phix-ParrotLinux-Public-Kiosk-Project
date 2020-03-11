#!/bin/sh
##-====================================================================-##
##   [+] Create An SSL Certificate for Localhost Connections:
##-====================================================================-##
## -------------------------------------------------------------------- ##
##   [?] https://letsencrypt.org/docs/certificates-for-localhost/
## -------------------------------------------------------------------- ##
/usr/bin/openssl req -x509 -out Xe1phix-ParrotSec-Kiosk-LocalHost.crt -keyout Xe1phix-ParrotSec-Kiosk-LocalHost.key -newkey rsa:4096 -nodes -sha512 -subj '/CN=localhost' -extensions EXT -config <( printf "[dn]\nCN=localhost\n[req]\ndistinguished_name = dn\n[EXT]\nsubjectAltName=DNS:localhost\nkeyUsage=digitalSignature\nextendedKeyUsage=serverAuth")
