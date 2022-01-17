#!/bin/sh
## Xe1phixKeytool.sh



keytool -printcrl -help && keytool -printcertreq -help && keytool -printcert -help && keytool  -help && keytool  -help && keytool -importkeystore -help && keytool -importcert -help && keytool  -help



       -alias "mykey"
       -keyalg
           "DSA" (when using -genkeypair)
           "DES" (when using -genseckey)
       -keysize
           2048 (when using -genkeypair and -keyalg is "RSA")
           1024 (when using -genkeypair and -keyalg is "DSA")
           256 (when using -genkeypair and -keyalg is "EC")
           56 (when using -genseckey and -keyalg is "DES")
           168 (when using -genseckey and -keyalg is "DESede")
       -validity 90
       -keystore <the file named .keystore in the user's home directory>
       -storetype <the value of the "keystore.type" property in the
           security properties file, which is returned by the static
           getDefaultType method in java.security.KeyStore>
       -file
           stdin (if reading)
           stdout (if writing)
       -protected false





       · If the underlying private key is of type DSA, then the -sigalg option defaults to SHA1withDSA.

       · If the underlying private key is of type RSA, then the -sigalg option defaults to SHA256withRSA.

       · If the underlying private key is of type EC, then the -sigalg option defaults to SHA256withECDSA.

-sigalg










keytool -certreq [OPTION]...

Generates a certificate request

Options:

 -alias <alias>          alias name of the entry to process
 -sigalg <alg>           signature algorithm name
 -file <file>            output file name
 -keypass <arg>          key password
 -keystore <keystore>    keystore name
 -dname <name>           distinguished name
 -ext <value>            X.509 extension
 -storepass <arg>        keystore password
 -storetype <type>       keystore type
 -providername <name>    provider name
 -addprovider <name>     add security provider by name (e.g. SunPKCS11)
   [-providerarg <arg>]    configure argument for -addprovider
 -providerclass <class>  add security provider by fully-qualified class name
   [-providerarg <arg>]    configure argument for -providerclass
 -providerpath <list>    provider classpath
 -v                      verbose output
 -protected              password through protected mechanism




keytool -gencert [OPTION]...

Generates certificate from a certificate request

Options:

 -rfc                    output in RFC style
 -infile <file>          input file name
 -outfile <file>         output file name
 -alias <alias>          alias name of the entry to process
 -sigalg <alg>           signature algorithm name
 -dname <name>           distinguished name
 -startdate <date>       certificate validity start date/time
 -ext <value>            X.509 extension
 -validity <days>        validity number of days
 -keypass <arg>          key password
 -keystore <keystore>    keystore name
 -storepass <arg>        keystore password
 -storetype <type>       keystore type
 -providername <name>    provider name
 -addprovider <name>     add security provider by name (e.g. SunPKCS11)
   [-providerarg <arg>]    configure argument for -addprovider
 -providerclass <class>  add security provider by fully-qualified class name
   [-providerarg <arg>]    configure argument for -providerclass
 -providerpath <list>    provider classpath
 -v                      verbose output
 -protected              password through protected mechanism



keytool -genseckey -help
keytool -genseckey [OPTION]...

Generates a secret key

Options:

 -alias <alias>          alias name of the entry to process
 -keypass <arg>          key password
 -keyalg <alg>           key algorithm name
 -keysize <size>         key bit size
 -keystore <keystore>    keystore name
 -storepass <arg>        keystore password
 -storetype <type>       keystore type
 -providername <name>    provider name
 -addprovider <name>     add security provider by name (e.g. SunPKCS11)
   [-providerarg <arg>]    configure argument for -addprovider
 -providerclass <class>  add security provider by fully-qualified class name
   [-providerarg <arg>]    configure argument for -providerclass
 -providerpath <list>    provider classpath
 -v                      verbose output
 -protected              password through protected mechanism


























keytool -printcert -file /tmp/cert





X.500 Distinguished Names
              X.500 Distinguished Names are used to identify entities, such as those that are named by the subject and issuer (signer) fields of X.509
              certificates. The keytool command supports the following subparts:

              commonName: The common name of a person such as Susan Jones.

              organizationUnit: The small organization (such as department or division) name. For example, Purchasing.

              localityName: The locality (city) name, for example, Palo Alto.

              stateName: State or province name, for example, California.

              country: Two-letter country code, for example, CH.





When you supply a distinguished name string as the value of a -dname option, such as for the -genkeypair command, the string must be in the
              following format:

              CN=cName, OU=orgUnit, O=org, L=city, S=state, C=countryCode



              CN=commonName
              OU=organizationUnit
              O=organizationName
              L=localityName
              S=stateName
              C=country



A sample distinguished name string is:

CN=Mark Smith, OU=Java, O=Oracle, L=Cupertino, S=California, C=US





keytool -genkeypair -dname "CN=Mark Smith, OU=Java, O=Oracle, L=Cupertino, S=California, C=US" -alias mark



it is not necessary to have all the subcomponents. You can
use a subset, for example:

CN=Steve Meier, OU=Java, O=Oracle, C=US




creates four key pairs named ca, ca1, ca2, and e1:

              keytool -alias ca -dname CN=CA -genkeypair
              keytool -alias ca1 -dname CN=CA -genkeypair
              keytool -alias ca2 -dname CN=CA -genkeypair
              keytool -alias e1 -dname CN=E1 -genkeypair



The following two commands create a chain of signed certificates; ca signs ca1 and ca1 signs ca2, all of which are self-issued:

              keytool -alias ca1 -certreq |
                  keytool -alias ca -gencert -ext san=dns:ca1 |
                  keytool -alias ca1 -importcert
              keytool -alias ca2 -certreq |
                  $KT -alias ca1 -gencert -ext san=dns:ca2 |
                  $KT -alias ca2 -importcert



creates the certificate e1 and stores it in the file e1.cert, 
which is signed by ca2. As a result, e1 should contain
    ca, ca1, and ca2 in its certificate chain:

keytool -alias e1 -certreq | keytool -alias ca2 -gencert > e1.cert

















Create a PKCS#7 structure from a certificate and CRL:

        openssl crl2pkcs7 -in crl.pem -certfile cert.pem -out p7.pem

       Creates a PKCS#7 structure in DER format with no CRL from several different certificates:

        openssl crl2pkcs7 -nocrl -certfile newcert.pem
               -certfile demoCA/cacert.pem -outform DER -out p7.der









































