

the ASN.1 header for the SEQUENCE tag, the part containing all the 'real' information named tbsCertificate which is an abbreviation for To Be Signed
openssl asn1parse -i -in wikipedia.pem


openssl asn1parse -in wikipedia.pem -strparse 4 -out wikipedia.tbs 



od -tx1 wikipedia.tbs


openssl asn1parse -in wikipedia.pem -strparse 1554 -out wikipedia.sig



od -tx1 wikipedia.sig










openssl x509 -in globalsignv2.pem -noout -pubkey >globalsignov2.pub
$ openssl pkey -in globalsignv2.pub -pubin -text





openssl sha256 <wikipedia.tbs -binary >hash
$ od -tx1 hash




openssl pkeyutl -verify -in hash -sigfile wikipedia.sig -inkey globalsignov2.pub -pubin -pkeyopt digest:sha256



openssl sha256 <wikipedia.tbs -verify globalsignov2.pub -signature wikipedia.sig







PEM to DER

$ openssl x509 -in cert.crt -outform der -out cert.der

DER to PEM

$ openssl x509 -in cert.crt -inform der -outform pem -out cert.pem



