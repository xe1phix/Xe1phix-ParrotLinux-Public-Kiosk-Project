#!/bin/sh



## ---------------------------------------------- ##
##  [+] Testing connection to the remote host
## ---------------------------------------------- ##
echo | openssl s_client -connect $Domain:443 -showcerts


## ---------------------------------------------------------------- ##
##  [+] Testing connection to the remote host (with SNI support)
## ---------------------------------------------------------------- ##
echo | openssl s_client -showcerts -servername $Domain -connect $Domain:443


## ----------------------------------------------------------------------- ##
##  [+] Testing connection to the remote host with specific ssl version
## ----------------------------------------------------------------------- ##
openssl s_client -tls1_2 -connect $Domain:443


## ----------------------------------------------------------------------- ##
##  [+] Testing connection to the remote host with specific ssl cipher
## ----------------------------------------------------------------------- ##
openssl s_client -cipher 'AES128-SHA' -connect $Domain:443



##-=======================================-##
##   [+] Connect to LDAP Using OpenSSL:
##-=======================================-##
openssl s_client -connect $LDAPService:636
openssl s_client -connect $LDAPHost:636
openssl s_client -connect $LDAPHost:636 -ssl3
openssl s_client -connect $LDAPHost:636 -stls1


##-============================================-##
##   [+] Connect to LDAP/LDAPS Using CA File:
##-============================================-##
openssl s_client -CAfile /$Dir/$File.pem -host $Host -port 389
openssl s_client -CAfile /$Dir/$File.pem -host $Host -port 636

openssl s_client -connect $Host:$Port -starttls LDAP

openssl s_client -connect ldap.$Host:389
openssl s_client -connect ldap.$Host:636



##-===========================================-##
##   [+] Connect To StartSSL Using TLSv1.2:
##-===========================================-##
openssl s_client -tls1_2 -connect auth.startssl.com:443   


##-=======================================-##
##   [+] Connect To POP3 Using OpenSSL:
##-=======================================-##
openssl s_client -crlf -connect $Domain:110 -starttls pop3


##-================================-##
##   [+] Secure POP3 Connection:
##-================================-##
openssl s_client -quiet -connect $Domain:995
openssl s_client -crlf -connect $Domain:110 -starttls pop3


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



openssl s_client -connect $Domain:443 -state -nbio -servername $Domain
openssl s_client -tls1_2 -connect $Domain:443 -state -nbio -servername $Domain

openssl s_client -connect smtp.comcast.net:465 -tls1_2

##-================================-##
##     [+] Save the output In a File
##     [+] display the certificate details
##-================================-##
openssl s_client -connect smtp.comcast.net:465 -tls1_2 > /tmp/smtps
openssl x509 -in /tmp/smtps -text



openssl x509 -in serverCASigned.crt -text -noout


openssl s_client -connect smtp.comcast.net:465 -tls1_2 | openssl x509 -in /dev/stdin -text


openssl s_client -connect smtp.office365.com:587 -starttls smtp


##-================================-##
##   [+] Secure IMAP Connection:
##-================================-##
openssl s_client -quiet -connect $Domain:993
openssl s_client -ssl3 -connect imap.gmail.com:993
gnutls-cli imap.gmail.com -p 993


##-====================================-##
##   [+] Connect to Gmail using IMAP
##-====================================-##
openssl s_client -tls1 -connect imap.gmail.com:993
openssl s_client -tls1_2 -connect imap.gmail.com:993
openssl s_client -ssl3 -connect imap.gmail.com:993

openssl s_client -host $Domain -port 993
openssl s_client -tls1 -host $Domain -port 993
openssl s_client -tls1_2 -host $Domain -port $Port



##-======================================-##
##    [+] Connect to an MTA Using SMTP
##-======================================-##
openssl s_client -connect $Sub.$Domain.com:25 -starttls smtp
openssl s_client -connect $Domain:25 -starttls smtp

gnutls-cli-debug --starttls-proto smtp --port 25 localhost


##-===================================-##
##     [+] Connect To A SMTP Server 
##-===================================-##
## ---------------------------------------------- ##
##     [?] Securing The Connection Using A CA
## ---------------------------------------------- ##
openssl s_client -starttls smtp -CApath $Dir/ -connect 127.0.0.1:25
openssl s_client -starttls smtp -CApath $Dir/ -connect $Domain:25
openssl s_client -CAfile $CAFile -starttls smtp -connect 127.0.0.1:25
openssl s_client -CAfile $CAFile -starttls smtp -connect $Domain:25
openssl s_client -CAfile $CAFile -starttls smtp -connect $Domain --port 25
openssl s_client -starttls smtp -CApath /etc/postfix/certs/ -connect 127.0.0.1:25
openssl s_client -starttls smtp -CApath /etc/postfix/certs/ -connect $Domain:25



openssl s_client -connect smtp.office365.com:587 -starttls smtp






##-============================================================-##
##   [+] Connect to a non-MTA client such as an IMAP server:
##-============================================================-##
openssl s_client -connect $Sub.$Domain.com:993
openssl s_client -connect $Domain:993


##-===============================================-##
##   [+] Connect to GMail As The Postfix User:
##-===============================================-##
sudo -u postfix openssl s_client -showcerts -starttls smtp -connect smtp.gmail.com:587 < /dev/null 2> /dev/null



##-======================================-##
##   [+] Connect to IRC Using OpenSSL:
##-======================================-##
openssl s_client -showcerts -connect chat.freenode.net:6697
openssl s_client -showcerts -connect -tls1_2 chat.freenode.net:6697


##-=========================================================-##
##   [+] Connect to Libera.Chat Using An SSL Certificate: 
##-=========================================================-##
openssl s_client -CAfile /$Dir/$File.pem $Domain
openssl s_client -CAfile /$Dir/libera.pem -p 6697 irc.libera.chat



gnutls-cli $Domain -p 389 --starttls-proto=ldap



##-=============================================-##
##   [+] Download certificate from FTP 
##-=============================================-##
echo | openssl s_client -servername ftp.$Domain -connect ftp.$Domain:21 -starttls ftp 2>/dev/null | sed -ne '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p'


##-=============================================-##
##   [+] Download certificate chain from FTP 
##-=============================================-##
echo | openssl s_client -showcerts -connect ftp.$Domain:21 -starttls ftp 2>/dev/null | sed -ne '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p'


echo | openssl s_client -connect $Domain:21 -starttls ftp
echo | openssl s_client -connect ftp.$Domain:21 -starttls ftp

echo | openssl s_client -connect ftp.debian.org:21 -starttls ftp




gnutls-cli $Domain --x509keyfile $MYKEY --x509certfile $MYCERT

gnutls-cli --print-cert mullvad.net


##-=======================================================================-##
##   [+] Use gnutls-cli to get a copy of the server certificate chain:
##-=======================================================================-##
echo | gnutls-cli -p 443 $Domain --save-cert $Chain.pem


##-====================================================-##
##   [+] TLS connection over port 443 debug level 5
##-====================================================-##
gnutls-cli -d 5 mullvad.net -p 443


##-====================================================-##
##   [+] Test gmail’s IMAP connection over 993:
##-====================================================-##
gnutls-cli -d 5 imap.gmail.com -p 993


##-====================================================-##
##   [+] 
##-====================================================-##
echo | gnutls-cli -p 443 $Domain --save-cert $Chain.pem


gnutls-cli -p 443 gist.github.com --protocols ssl3


openssl s_client -connect gist.github.com:443


##-====================================================-##
##   [+] 
##-====================================================-##
gnutls-cli --port $Port --sni-hostname $Domain --alpn ssh/2.0 %h



gnutls-cli -p 443 mullvad.net




gnutls-cli imap.gmail.com -p 993


##-================================-##
##   [+] Start a GnuTLS Server:
##-================================-##
gnutls-serv --http --x509cafile x509-ca.pem --x509keyfile x509-server-key.pem --x509certfile x509-server.pem
           

##-====================================================-##
##   [+] 
##-====================================================-##
gnutls-cli --crlf --starttls --x509cafile /etc/pki/CA/cacert.pem --port 25 mail.$Domain.com


