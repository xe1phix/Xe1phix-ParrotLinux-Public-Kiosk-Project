#!/bin/sh
##-======================================-##
##   [+] Xe1phix-[SMTP]-Cheatsheet.sh
##-======================================-##



##-=============================================-##
##   [+] Connect to SMTP server using STARTTLS
##-=============================================-##
openssl s_client -starttls smtp -crlf -connect 127.0.0.1:25

openssl s_client -tls1_2 -connect auth.startssl.com:443    

openssl s_client -connect $Domain:443 -tls1_2 -servername $Domain | openssl x509 -text -noout


##   Connect to SMTP server using STARTTLS 

##   [+] connect to an SMTP server over TLS.
##   [?] which is useful for debugging SMTP sessions.

## ---------------------------------------- ##
##    [?] Command Source:
## ---------------------------------------- ##
## ------------------------------------------------------------------------------------------------------------------------------------------------- ##
##~->  https://www.commandlinefu.com/commands/view/3093/connect-to-smtp-server-using-starttls
## ------------------------------------------------------------------------------------------------------------------------------------------------- ##
openssl s_client -starttls smtp -crlf -connect 127.0.0.1:25

