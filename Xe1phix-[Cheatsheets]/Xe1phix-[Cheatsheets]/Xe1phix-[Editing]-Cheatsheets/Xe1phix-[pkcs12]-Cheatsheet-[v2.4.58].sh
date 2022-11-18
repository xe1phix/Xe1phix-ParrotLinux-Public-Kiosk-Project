

##-==============================================================-##
##   [+] Parse a PKCS#12 file and output it to a file:

openssl pkcs12 -in file.p12 -out file.pem


##-==============================================================-##
##           [+] Print some info about a PKCS#12 file:
##-==============================================================-##
openssl pkcs12 -in file.p12 -info -noout



##-==============================================================-##
##                  [+] Create a PKCS#12 file:
##-==============================================================-##
openssl pkcs12 -export -in file.pem -out file.p12 -name "My Certificate"


##-==============================================================-##
##              [+] Include some extra certificates:
##-==============================================================-##
openssl pkcs12 -export -in file.pem -out file.p12 -name "My Certificate" -certfile othercerts.pem



