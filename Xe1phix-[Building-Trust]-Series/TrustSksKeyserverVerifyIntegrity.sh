#!/bin/sh





## ================================================================================== ##
echo "Fetching The Keyservers GPG Signing Keys:"
echo "I prefer using the sks-keyservers.net keyserver because:"
echo "1). Lookups are performed using pgpkey-https by the sks-keyservers.net CA"
echo "2). The only port open on the sks-keyserver is port 443 (tls-ssl)" 
echo "## ---------------------------------------------------------------------------- ##"
echo "				https://sks-keyservers.net/overview-of-pools.php					"
echo "## ---------------------------------------------------------------------------- ##"
## ================================================================================== ##



## ================================================================================== ##
echo "			Here is an in-depth overview if you are new to the subject:				"
echo "## ---------------------------------------------------------------------------- ##"
echo "				  https://riseup.net/en/gpg-best-practices							"
echo "## ---------------------------------------------------------------------------- ##"
## ================================================================================== ##


## ================================================================================== ##
echo "Fetch the sks-keyserver GPG Signing Key:"
## ================================================================================== ##
gpg --keyserver hkp://pool.sks-keyservers.net --recv-keys 0x94CBAFDD30345109561835AA0B7F8B60E3EDFAE3

## ================================================================================== ##
echo "You Can Also Fetch The GPG Signing Key From Gnupgs Keyserver:"
## ================================================================================== ##
gpg --keyserver hkp://keys.gnupg.net --recv-keys 0x647F28654894E3BD457199BE38DBBDC86092693E

## ================================================================================== ##
echo "Compare The Fingerprint Shown Against The One Published On Their Website:"
## ================================================================================== ##
gpg --fingerprint 0x0x94CBAFDD30345109561835AA0B7F8B60E3EDFAE3

94CBAFDD30345109561835AA0B7F8B60E3EDFAE3
94CBAFDD30345109561835AA0B7F8B60E3EDFAE3


## ================================================================================== ##
echo "Now Sign the GPG Key:"
## ================================================================================== ##
gpg --lsign 0x94CBAFDD30345109561835AA0B7F8B60E3EDFAE3



## ================================================================================== ##
echo "Make the directory for the .pem in the Riseup.net config:"
echo "Here an in-depth overview if you are new to the subject:"
echo "https://riseup.net/en/gpg-best-practices"
## ================================================================================== ##
curl --verbose --progress-bar --tlsv1.2 --ssl-reqd --url https://sks-keyservers.net/ca/crl.pem --output /usr/share/gnupg/hkps.pool.sks-keyservers.net.pem
curl --verbose --progress-bar --tlsv1.2 --ssl-reqd --url https://sks-keyservers.net/sks-keyservers.netCA.pem.asc --output /usr/share/gnupg/hkps.pool.sks-keyservers.net.pem.asc
curl --verbose --progress-bar --tlsv1.2 --ssl-reqd --url https://sks-keyservers.net/ca/crl.pem --output /usr/share/gnupg/crl.pem


## ================================================================================================================ ##
echo "You can find sks-keyservers.net's GPG fingerprint on their website:"
## ================================================================================================================ ##
##----------------------------------------------------------------------------------------------------------------- ##
echo "http://pool.sks-keyservers.net:11371/pks/lookup?op=vindex&search=0x94CBAFDD30345109561835AA0B7F8B60E3EDFAE3"
##----------------------------------------------------------------------------------------------------------------- ##
## ================================================================================================================ ##



## ================================================================================== ##
echo "Here is a list of sks keyservers, with their descriptions:"
## ================================================================================== ##
##----------------------------------------------------------------------------------- ##
echo "https://sks-keyservers.net/overview-of-pools.php"
##----------------------------------------------------------------------------------- ##
## ================================================================================== ##



## ================================================================================== ##
echo "cd into the directory you placed the signed .pem file:"
## ================================================================================== ##
cd /usr/share/gnupg/




## ================================================================================== ##
echo "You can verify the sks-keyservers .pem cert with their GPG signature"
## ================================================================================== ##
gpg --keyid-format 0xlong --verify sks-keyservers.netCA.pem.asc




echo "## ===================================================================================================================================== ##"
echo "## ------------------------------------------------------------------------------------------------------------------------------------- ##"
echo "## ======================== Now Configure hkps://hkps.pool.sks-keyservers.net As The Default Keyserver  ================================ ##"
echo "## ======== Also Add The hkp Cert File To Dirmngr.conf For Validation of HTTPS connection While Communicating With Keyserver  ========== ##"
echo "## ------------------------------------------------------------------------------------------------------------------------------------- ##"
echo "## ===================================================================================================================================== ##"
echo "keyserver hkps://hkps.pool.sks-keyservers.net" >> ~/.gnupg/dirmngr.conf
echo "hkp-cacert /usr/share/gnupg/sks-keyservers.netCA.pem" >> ~/.gnupg/dirmngr.conf




gpg --default-keyserver-url https://pool.sks-keyservers.net 


echo "## ========================================================================================================================== ##" | tee --append ~/.gnupg/dirmngr.conf
echo "## -------------------------------------------------------------------------------------------------------------------------- ##" | tee --append ~/.gnupg/dirmngr.conf
echo "    The Fingerprint of This Certificate: 79:1B:27:A3:8E:66:7F:80:27:81:4D:4E:68:E7:C4:78:A4:5D:5A:17 " | tee --append ~/.gnupg/dirmngr.conf
echo "## -------------------------------------------------------------------------------------------------------------------------- ##" | tee --append ~/.gnupg/dirmngr.conf
echo "    The X509v3 Subject Key Identifier:   E4 C3 2A 09 14 67 D8 4D 52 12 4E 93 3C 13 E8 A0 8D DA B6 F3 " | tee --append ~/.gnupg/dirmngr.conf
echo "## -------------------------------------------------------------------------------------------------------------------------- ##" | tee --append ~/.gnupg/dirmngr.conf
echo "## ========================================================================================================================== ##" | tee --append ~/.gnupg/dirmngr.conf




echo "## ------------------------------------------------------------------------------------------------------------------------------------- ##" >> ~/.gnupg/dirmngr.conf
echo "## ===================================== sks-keyservers.net's tor .onion keyserver ===================================================== ##" >> ~/.gnupg/dirmngr.conf
echo "## ------------------------------------------------------------------------------------------------------------------------------------- ##" >> ~/.gnupg/dirmngr.conf
echo "## keyserver hkp://jirk5u4osbsr34t5.onion" >> ~/.gnupg/dirmngr.conf
echo "##                                                                                                                                       ##" >> ~/.gnupg/dirmngr.conf




