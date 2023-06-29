#!/bin/sh
##-===================================================-##
##   [+] Xe1phix-[OCSPTool]-Cheatsheet-[v4.8.5].sh
##-===================================================-##
## 
## 
##-===============================================================================-##
##   [+] generate an OCSP request for a certificate and to verify the response
##-===============================================================================-##



##-=======================================================================-##
##   [+] Use gnutls-cli to get a copy of the server certificate chain:
##-=======================================================================-##
echo | gnutls-cli -p 443 $Domain --save-cert $Chain.pem



##-=============================-##
##   [+] Verify The Response
##-=============================-##
certtool -i < $Chain.pem


##-=======================================================-##
##   [+] Request Information on the Chain Certificates.
##-=======================================================-##
ocsptool --ask --load-chain $Chain.pem


##-=======================================================-##
##   [+] Ask information on a particular certificate 
##-=======================================================-##
## ------------------------------------------------------- ##
##   [?] using --load-cert and --load-issuer
## ------------------------------------------------------- ##
ocsptool --ask http://ocsp.CAcert.org/ --load-chain $Chain.pem



##-======================================================-##
##   [+] Parse  an OCSP request and print information:
##-======================================================-##
## -------------------------------------------------------------------- ##
##   [?] specify the name of the file containing the OCSP request
## -------------------------------------------------------------------- ##
##   [?] It should contain the OCSP request in binary DER format.
## -------------------------------------------------------------------- ##
ocsptool -i -Q $OCSPRequest.der


## ---------------------------------------------------------------------- ##
##   [?] The input file may also be sent to standard input like this:
## ---------------------------------------------------------------------- ##
cat $OCSPRequest.der | ocsptool --request-info



##-==================================================-##
##   [+] Print information about an OCSP response:
##-==================================================-##

##-================================-##
##   [+] Parse an OCSP Response 
##-================================-##
ocsptool -j -Q $OCSPRequest.der
cat $OCSPRequest.der | ocsptool --response-info





##-==================================-##
##   [+] Generate an OCSP request
##-==================================-##
ocsptool -q --load-issuer $Issuer.pem --load-cert $Client.pem --outfile $OCSPRequest.der


##-===========================================-##
##   [+] Verify signature in OCSP response
##-===========================================-##
## 
## ------------------------------------------------------------------------- ##
##   [?] The OCSP response is verified against a set of trust anchors
## ------------------------------------------------------------------------- ##
## 
## ------------------------------------------------------------------------- ##
##   [?] The trust anchors are concatenated certificates in PEM format.
## ------------------------------------------------------------------------- ##
## 
## ------------------------------------------------------------------------- ##
##   [?] The certificate that signed the OCSP response 
##       needs to be in the set of trust anchors
## ------------------------------------------------------------------------- ##
## 
## 
##                          or 
## 
## ----------------------------------------------------- ##
##   [?] The issuer of the signer certificate 
##       needs to be in the set of trust anchors 
##       and the OCSP Extended Key Usage bit has to
##       be asserted in the signer certificate.
## ----------------------------------------------------- ##
ocsptool -e --load-trust $Issuer.pem --load-response $OCSPResponse.der




##-=====================================================================-##
##   [+] Verify signature in OCSP response against given certificate
##-=====================================================================-##
ocsptool -e --load-signer $OCSPSigner.pem --load-response $OCSPResponse.der




##-================================-##
##   [+] Certificate information
##-================================-##
certtool --certificate-info --infile $Cert.pem



##-========================================-##
##   [+] PKCS #12 structure generation
##-========================================-##
certtool --load-certificate $Cert.pem --load-privkey $Key.pem --to-p12 --outder --outfile $Key.p12

certtool --load-ca-certificate $CA.pem --load-certificate $Cert.pem --load-privkey $Key.pem --to-p12 --outder --outfile $Key.p12


##-================================-##
##   [+] Verifying a certificate
##-================================-##
certtool --verify --infile $Cert.pem

certtool --verify --verify-hostname $HostName --infile $Cert.pem





certtool --pubkey-info --infile $Key.pem
certtool --certificate-info $Cert.pem
certtool --fingerprint $Key.pem



certtool --generate-self-signed











