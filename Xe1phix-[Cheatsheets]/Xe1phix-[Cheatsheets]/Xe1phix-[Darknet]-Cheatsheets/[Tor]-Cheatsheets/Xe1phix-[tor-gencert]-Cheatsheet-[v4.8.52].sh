#!/bin/sh

## ----------------------------------------------------------------------------- ##
##   [?] tor-gencert - Generate certs and keys For Tor directory authorities
## ----------------------------------------------------------------------------- ##
##   [?] Tor directory authorities running the v3 Tor directory protocol, 
## ----------------------------------------------------------------------------- ##
##   [?] Every directory authority has a long term authority identity key 
##   [?] (which is distinct from the identity key it uses as a Tor server); 
##   [?] this key should be kept offline in a secure location.
## ----------------------------------------------------------------------------- ##


##-======================================-##
##   [+] Generate a new identity key:
##-======================================-##
tor-gencert --create-identity-key


##-======================================================-##
##   [+] Read the identity key from the specified file:
##-======================================================-##
##   [?] Default: "./authority_identity_key"
## ------------------------------------------------------ ##
tor-gencert -i $File


##-=====================================================-##
##   [+] Write the signing key to the specified file:
##-=====================================================-##
##   [?] Default: "./authority_signing_key"
## ----------------------------------------------------- ##
tor-gencert -s $File


##-=====================================================-##
##   [+] Write the certificate to the specified file:
##-=====================================================-##
##   [?] Default: "./authority_certificate"
## ----------------------------------------------------- ##
tor-gencert -c $File
