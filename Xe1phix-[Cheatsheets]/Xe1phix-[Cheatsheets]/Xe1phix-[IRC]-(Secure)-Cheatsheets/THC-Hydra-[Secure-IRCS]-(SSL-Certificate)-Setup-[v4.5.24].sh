#!/bin/sh
##-==========================================-##
##		[+] THC-Hydra - Secure IRC Setup
##-==========================================-##


##-==============================================-##
##     [+] Connect to IRCS.THC.ORG Port 6697:
##-==============================================-##
## ---------------------------------------------- ##
##    [?] via the following IRSSI command
## ---------------------------------------------- ##


## ---------------------------------------------------------------------------- ##
##    [?] Every user authenticates to IRCS with a SSL client certificate.
## ---------------------------------------------------------------------------- ##
##    [?] using the Atheme Nickserv.
##         Nobody can steal others nicks! 
## ---------------------------------------------------------------------------- ##
##    [?] You can see whether a nick is properly authenticated 
##    [?] by issuing:
## ---------------------------------------------------------------------------- ##
##      	 "account: nickname"-line in /whois : 
## ---------------------------------------------------------------------------- ##

## -------------------------------------------------------------- ##
##   08:15 -!- nickname [~nickname@ircs.thc.org]
##   08:15 -!- ircname : Unknown
##   08:15 -!- server : ircs.thc.org [tHC Ircs network]
##   08:15 -!- account : nickname
##   08:15 -!- End of WHOIS
## -------------------------------------------------------------- ##


## -------------------------------------------------------------- ##
##      [?] Channels can be registered with ChanServ Bot.
##      [?] The recommended IRC Client is Irssi, ZNC
## -------------------------------------------------------------- ##

##-==============================================-##
##     [+] Connect to IRCS.THC.ORG Port 6697 
##     [?] Using The IRSSI Client:
##-==============================================-##
/server -ssl_verify -ssl_cafile ca-ircs-cert.pem -ssl_cert nick.pem ircs.thc.org 6697


## --------------------------------------------------- ##
##     [?] nick.pem is your Client-Certificate 
##     [?] used for authenticating your Nickname.
## --------------------------------------------------- ##

