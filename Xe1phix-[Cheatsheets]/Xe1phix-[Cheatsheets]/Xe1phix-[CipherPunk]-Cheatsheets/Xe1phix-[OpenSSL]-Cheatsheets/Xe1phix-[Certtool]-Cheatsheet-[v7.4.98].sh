#!/bin/sh
##-===================================================-##
##   [+] Xe1phix-Certtool-Cheatsheet-[v7.4.95].sh
##-===================================================-##
## 
## 


##-=======================================-##
##   [+] Print Public Key Information:
##-=======================================-##
certtool --pubkey-info --infile $Key.pem


##-=======================================-##
##    [+] View Certificate Information
##-=======================================-##
certtool --certificate-info --infile $Cert.pem


##-==================================-##
##   [+] Fingerprint Certificate:
##-==================================-##
certtool --fingerprint $Key.pem


##-====================================-##
##    [+] Create An RSA Private Key:
##-====================================-##
certtool --generate-privkey --rsa --outfile $Key.pem


##-==========================================-##
##    [+] Create Self-Signed Certificate
##-==========================================-##
certtool --generate-privkey --outfile $Key.pem
certtool --generate-self-signed --load-privkey $Key.pem --outfile $Key.pem
certtool --generate-certificate --load-request $Request.pem --outfile $Cert.pem --load-ca-certificate $CACert.pem --load-ca-privkey $CAKey.pem


##-========================================================-##
##    [+] Generate A Certificate Using The Private Key
##-========================================================-##
certtool --generate-certificate --load-privkey $Key.pem --outfile $Cert.pem --load-ca-certificate $CACert.pem --load-ca-privkey $CAKey.pem


##-==========================================-##
##    [+] Generate A Certificate Request:
##-==========================================-##
## ----------------------------------------------------------- ##
##    [?]  When the private key is stored in a smart card 
## ----------------------------------------------------------- ##
certtool --generate-request --load-privkey "pkcs11:..." --load-pubkey "pkcs11:..."


##-=======================================-##
##    [+] Generate a PKCS #12 Structure 
##-=======================================-##
## ------------------------------------------------- ##
##    [?] Using the previous key and certificate
## ------------------------------------------------- ##
certtool --load-certificate $Cert.pem --load-privkey $Key.pem --to-p12 --outder --outfile $Key.p12
certtool --load-ca-certificate $CA.pem --load-certificate $Cert.pem --load-privkey $Key.pem --to-p12 --outder --outfile $Key.p12
certtool --load-ca-certificate $CACert.pem --load-certificate $Cert.pem --load-privkey $Key.pem --to-p12 --outder --outfile $Key.p12


##-=============================================================-##
##    [+] Generate Diffie-Hellman Key Exchange Parameters:
##-=============================================================-##
certtool --generate-dh-params --outfile $DH.pem --sec-param medium
certtool --generate-privkey > $Key.pem
certtool --generate-proxy --load-ca-privkey $Key.pem --load-privkey $ProxyKey.pem --load-certificate $Cert.pem --outfile $ProxyCert.pem


##-================================-##
##   [+] Verifying a certificate
##-================================-##
certtool --verify --infile $Cert.pem
certtool --verify --verify-hostname $HostName --infile $Cert.pem


##-=============================================================-##
##    [+] Certificate Revocation List (CRL) Generation
##-=============================================================-##
## ------------------------------------------------------------- ##
##    [?] Create an empty Certificate Revocation List (CRL):
## ------------------------------------------------------------- ##
certtool --generate-crl --load-ca-privkey $x509CAKey.pem --load-ca-certificate $x509CA.pem

## ------------------------------------------------------------- ##
##    [?] Create a CRL that contains revoked certificates
## ------------------------------------------------------------- ##
certtool --generate-crl --load-ca-privkey $x509CAKey.pem --load-ca-certificate $x509CA.pem --load-certificate $RevokedCerts.pem



##-======================================================-##
##    [+] Verify A Certificate Revocation List (CRL):
##-======================================================-##
certtool --verify-crl --load-ca-certificate $x509CACert.pem < $CRL.pem







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







