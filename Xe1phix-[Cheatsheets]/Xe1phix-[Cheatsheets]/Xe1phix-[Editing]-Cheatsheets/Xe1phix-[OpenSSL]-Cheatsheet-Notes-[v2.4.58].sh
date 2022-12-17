
echo "##~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~##"
echo "## =============================================================== ##"
echo "   		    [+] Print Certificate Fingerprints :	   			   "
echo "## =============================================================== ##"
echo "##~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~##"


##-==============================================================-##
##   [+] View information about a given SSL certificate, stored in a PEM file.
openssl x509 -text -in $File


cp newca.pem /usr/share/ssl/certs
/usr/bin/c_rehash


$OPENSSL x509 -hash -fingerprint -noout -in $File
$OPENSSL crl -hash -fingerprint -noout -in $File


##-==============================================================-##
##   [+] Output the text form of a DER encoded certificate:
openssl crl -in crl.der -text -noout


##-==============================================================-##
##   [+] 
keytool -list -keystore java.home/lib/security/cacerts


##-==============================================================-##
##   [+] 
keytool -printcert -file $file



##-==============================================================-##
##   [+] view the certificate information simply do:


openssl x509 ‐text ‐in servernamecert.pem           ## View the certificate info
openssl req ‐noout ‐text ‐in server.csr             ## View the request info
openssl s_client ‐connect cb.vu:443                 ## Check a web server certificate


##-==============================================================-##
##   [+] Check the SSL certificate fingerprint 

openssl x509 -noout -issuer -subject -fingerprint -dates
cat .pem | openssl x509 -fingerprint -noout -in /dev/stdin
openssl x509 -sha1 -in cert.pem -noout -fingerprint						##  Display the certificate SHA1 fingerprint:

##-==============================================================-##
##   [+] Print some info about a PKCS#12 file:
openssl pkcs12 -in $file.p12 -info -noout -fingerprint


##-==============================================================-##
##   [+] Calculate the fingerprint of RiseupCA.pem:

certtool -i < RiseupCA.pem |egrep -A 1 'SHA256 fingerprint'


##-==============================================================-##
##   [+] 
openssl x509 -sha256 -in RiseupCA.pem -noout -fingerprint


##-==============================================================-##
##   [+] 
head -n -1 RiseupCA.pem | tail -n +2 | base64 -d | sha256sum



## ---------------------------------------------------------------------------------------------------------- ##
    openssl x509 ‐text ‐in $servernamecert.pem      # View the certificate info 
## ---------------------------------------------------------------------------------------------------------- ##
    openssl req ‐noout ‐text ‐in $server.csr        # View the request info 
## ---------------------------------------------------------------------------------------------------------- ##



certtool --certificate-info --infile $cert.pem				##  Certificate information


##-===============================================-##
##   [+] Print out text version of parameters:
##-===============================================-##
openssl pkeyparam -in $param.pem -text







CERT_PATH="$( openssl version -a|grep "^OPENSSLDIR:"|cut -d'"' -f2 )/certs"

# print the PEM from the cert8.db and get the FP with openssl
    COUNTRY=$( certutil -L -n "${NICKNAME}" -a -d "${FF_HOME}" | openssl x509 -noout -subject | grep -o "C=[A-Z]\+" )

NICKNAMES=( $( certutil -L -d "${FF_HOME}" | grep -F -v ",," | sed '1,4d' | gawk 'NF--' ) )

ISSUER=$( certutil -L -n "${CERT8_CAs[${FINGERPRINT}]}" -a -d "${OLD_FF_HOME}" | openssl x509 -noout -issuer_hash )

NICKNAME=$( openssl x509 -in "${REQUIRED_CA}" -noout -subject | sed 's/^.*\(CN\|OU\)=//' )
    certutil -A -n "${NICKNAME}" -t CT,c,c -a -d "${FF_HOME}" 0<"${REQUIRED_CA}"


 # print the PEM from the cert8.db and get the FP with openssl
      FP=$( certutil -L -n "${NICKNAME}" -a -d "${CERT8}" | openssl x509 -noout -fingerprint -sha1 | sed 's/^.*Fingerprint=//' )
#FPS+=( $( certutil -L -n "${NICKNAME}" -a -d "${FF_HOME}" | openssl x509 -noout -fingerprint -sha1 | sed 's/^.*Fingerprint=//' ) )


# find all cert8.db files under ~/.mozilla/firefox
    CERT8S=( $( find ~/.mozilla/firefox -type f -name cert8.db | sed 's/\/cert8\.db$//' ) )




# verify
      #certutil -L -n "${CERT8_CAs[${FINGERPRINT}]}" -a -d "${OLD_FF_HOME}" | openssl verify -CAfile "${REQUIRED_CA}"


CERT_COUNT=$(( $( certutil -L -d "${FF_HOME}" | wc -l ) - 4 ))






