#!/bin/sh
###############
## Mullvad.sh
###############



# load TUN/TAP kernel module
modprobe tun



##
## =========================================================================== ##"
## 					[+] OpenVPN Resources & Tutorials:
## =========================================================================== ##
## --------------------------------------------------------------------------- ##
## https://wiki.archlinux.org/index.php/Category:Virtual_Private_Network
## --------------------------------------------------------------------------- ##
## https://wiki.archlinux.org/index.php/OpenVPN
## --------------------------------------------------------------------------- ##
## https://wiki.archlinux.org/index.php/OpenVPN_Bridge
## --------------------------------------------------------------------------- ##
## https://wiki.archlinux.org/index.php/OpenVPN_Checklist_Guide
## --------------------------------------------------------------------------- ##
## https://wiki.archlinux.org/index.php/VPN_over_SSH
## --------------------------------------------------------------------------- ##
## https://wiki.archlinux.org/index.php/Secure_Shell
## --------------------------------------------------------------------------- ##
## https://wiki.archlinux.org/index.php/Easy-RSA
## --------------------------------------------------------------------------- ##
## https://wiki.archlinux.org/index.php/Openswan_L2TP/IPsec_VPN_client_setup
## --------------------------------------------------------------------------- ##
## https://wiki.archlinux.org/index.php/OpenVPN_(client)_in_Linux_containers
## =========================================================================== ##





## ========================================================================================= ##
## 					[?] If you plan to connect a VPN --> Tor 
## ========================================================================================= ##
## See https://www.whonix.org/wiki/Tunnels/Connecting_to_a_VPN_before_Tor
## 
## ========================================================================================= ##
## For other Networking Topology & Routing Preparation See:
## ========================================================================================= ##
## https://www.whonix.org/wiki/Tunnels/Connecting_to_Tor_before_a_VPN
## ----------------------------------------------------------------------------------------- ##
## https://www.whonix.org/wiki/Tunnels/Connecting_to_SSH_before_Tor
## ----------------------------------------------------------------------------------------- ##
## https://www.whonix.org/wiki/Tunnels/Connecting_to_Tor_before_SSH
## ----------------------------------------------------------------------------------------- ##
## https://www.whonix.org/wiki/Tunnels/Connecting_to_Tor_before_a_proxy
## ----------------------------------------------------------------------------------------- ##
## https://www.whonix.org/wiki/Tunnels/Connecting_to_a_proxy_before_Tor
## ----------------------------------------------------------------------------------------- ##
## https://www.whonix.org/wiki/Advanced_Security_Guide#Chaining_Anonymizing_Gateways
## ========================================================================================= ##



## =========================================================================== ##
## It is highly recommended to use UDP for VPN transmissions
## This is due to the way protocol stacks interact with eachother
## This issue is called: reliability-layer collisions
## --------------------------------------------------------------------------- ##
## http://sites.inka.de/sites/bigred/devel/tcp-tcp.html
## --------------------------------------------------------------------------- ##
## 
echo "## ========================================================================== ##"
echo "|| -------------------------------------------------------------------------- ||"
echo "||																			||"
echo "|| SSL/TLS  --> Reliability Layer -->   \										||"
echo "|| 			   --tls-auth HMAC		   \									||"
echo "|| 								        \									||"
echo "|| 									     ---> Multiplexer ----> UDP			||"
echo "|| 								        /					 Transport		||"
echo "|| IP		  	 Encrypt and HMAC		   /									||"
echo "|| Tunnel -->  using OpenSSL EVP -->    /  									||"
echo "|| Packets		Interface.			 /										||"
echo "||																			||"
echo "|| -------------------------------------------------------------------------- ||"
echo "## ========================================================================== ##"


## =========================================================================== ##
## [?] If you're picturing all intricate little ways you could fuck this up
## 			Here is OpenVPN's offical book recommendation list:
## =========================================================================== ##
## https://openvpn.net/index.php/open-source/books.html





## ========================================= ##
##  [+] Mullvad Certificates & Locations: 
## ========================================= ##
## 
## ----------------------------------------- ##
## 	[+] User Certificate => mullvad.crt
## ----------------------------------------- ##
## 		[+] CA Certificate => ca.crt
## ----------------------------------------- ##
## 	  [+] Private Key => mullvad.key
## ----------------------------------------- ##
##
## ========================================= ##





echo "## =========================================================== ##"
echo "   [+] Install OpenVPN Client & network-manager Plugins:"
echo "## =========================================================== ##"
sudo apt-get update && sudo apt-get install openvpn network-manager-openvpn network-manager-openvpn-gnome openvpn-systemd-resolved



echo "## ================================== ##"
echo "   [+] Install Mullvad Prereqs:"
echo "## ================================== ##"
sudo apt-get update && sudo apt-get install python-pip python-wxgtk3.0 python-ipaddr python-psutil python-netifaces python-appindicator python-appdirs



echo "## ============================================== ##"
echo "   [+] Generate Strong GnuPG Key (4096 Bits):"
echo "## ============================================== ##"
gpg --enable-large-rsa --full-gen-key



echo "## ============================================== ##"
echo "   [+] Fetch Mullvads GPG Signing Key:"
echo "## ============================================== ##"
gpg --keyserver pool.sks-keyservers.net --recv-keys A1198702FC3E0A09A9AE5B75D5A1D4F266DE8DDF


echo "## ============================================== ##"
echo "   [+] Curl Fetch Mullvads .asc (Require SSL):"
echo "## ============================================== ##"
curl --verbose --ssl-reqd --url https://www.mullvad.net/static/mullvad-support-mail.asc --output ~/mullvad-support-mail.asc
curl --verbose --ssl-reqd --url https://www.mullvad.net/static/mullvad-code-signing.asc --output ~/mullvad-code-signing.asc


curl --verbose --ssl-reqd --url  --output 
--tlsv1.2
--tlsv1.3
--sslv3



gpg --keyid-format 0xlong 


echo "## ============================================== ##"
echo "   [+] Import Mullvads GPG Signing Key:"
echo "## ============================================== ##"
gpg --keyid-format 0xlong --import mullvad-support-mail.asc
gpg --keyid-format 0xlong --import mullvad-code-signing.asc



echo "## ============================================== ##"
echo "   [+] Print Mullvads GPG Fingerprints:"
echo "## ============================================== ##"
gpg --keyid-format 0xlong --fingerprint 0xA1198702FC3E0A09A9AE5B75D5A1D4F266DE8DDF

echo "## ============================================== ##"
echo "   [+] Mullvads GPG Fingerprints (Verified):"
echo "## ============================================== ##"
echo "Primary key fingerprint: A119 8702 FC3E 0A09 A9AE  5B75 D5A1 D4F2 66DE 8DDF"



echo "## ============================================== ##"
echo "   [+] Sign Mullvads GPG Key:"
echo "## ============================================== ##"
gpg --lsign A1198702FC3E0A09A9AE5B75D5A1D4F266DE8DDF				## gpg --edit-key A1198702FC3E0A09A9AE5B75D5A1D4F266DE8DDF


echo "## ================================================================= ##"
echo "   [+] Verify Mullvads .deb against Their Published Signed .asc:"
echo "## ================================================================= ##"
gpg --keyid-format 0xlong -v --verify mullvad_64-1_all.deb.asc mullvad_64-1_all.deb





echo "## ================================================== ##"
echo "   [?] The Resulting Output Should Be As Follows:"
echo "## ================================================== ##"

echo "## ====================================================================================== ##"
echo "## -------------------------------------------------------------------------------------- ##"
echo "		gpg: armor header: Version: GnuPG v2"
echo "		gpg: Signature made Mon 04 Sep 2017 01:58:42 PM UTC"
echo "		gpg:                using RSA key 0xA26581F219C8314C"
echo "		gpg: using subkey 0xA26581F219C8314C instead of primary key 0xD5A1D4F266DE8DDF"
echo "		gpg: using pgp trust model"
echo "		gpg: Good signature from "Mullvad (code signing) <admin@mullvad.net>" [full]"
echo "		gpg: binary signature, digest algorithm SHA256, key algorithm rsa4096"
echo "## -------------------------------------------------------------------------------------- ##"
echo "## ====================================================================================== ##"








echo "## ================================================ ##"
echo "   [?] Plaintext Version of Mullvads GnuPG Key:"
echo "## ================================================ ##"


-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: GnuPG v2

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
=kwTD
-----END PGP PUBLIC KEY BLOCK-----




cd /etc/openvpn/ && make-cadir easy-rsa

 cd /etc/openvpn/easy-rsa/
 
 ln -s openssl-1.0.0.cnf openssl.cnf
 
 rm -rf /etc/openvpn/easy-rsa/keys
 ./clean-all
 ./build-ca
./build-key-pass client1



./build-dh						## Generate .pem file:




service openvpn start



wget -O - https://swupdate.openvpn.net/repos/repo-public.gpg|apt-key add -
apt-key list



systemctl enable openvpn*.service && sudo systemctl start openvpn*.service && service openvpn start

mkdir /etc/openvpn/keys
tar -C /etc/openvpn/keys -xzf ~/client1.tar.gz && sudo mv /etc/openvpn/keys/client.ovpn /etc/openvpn

chmod 700 /etc/openvpn/keys



journalctl -f | grep vpn
tail -f /var/log/syslog | grep vp


cd /etc/openvpn/easy-rsa/ && source ./vars
source /etc/openvpn/easy-rsa/vars


cd /etc/openvpn/easy-rsa/2.0/keys
cp ca.crt ca.key dh2048.pem server.crt server.key /etc/openvpn

	sed -i 's|#net.ipv4.ip_forward=1|net.ipv4.ip_forward=1|' /etc/sysctl.conf
	echo 1 > /proc/sys/net/ipv4/ip_forward
else
	echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf

/etc/init.d/openvpn restart
systemctl restart openvpn@client.service
systemctl enable openvpn@client.service
service openvpn restart
chkconfig openvpn on


cp -v /home/xe1phix/Xe1phix-IPTablesOpenVPN.sh /etc/iptables/IPTablesOpenVPNStable.sh
cp -v /home/xe1phix/Xe1phix-IPTablesOpenVPN.sh /usr/share/iptables/rules.v4

iptables-restore < /etc/iptables/rules.v4		## Import the new ruleset:

##-=============================================================-##
## 	Apply the routing rule so that traffic can leave the VPN. 	##
## 			This must be done after iptables-restore			##
##-=============================================================-##
iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o eth0 -j MASQUERADE


dpkg-reconfigure iptables-persistent			## Save the currently loaded rules


echo "net.ipv4.ip_forward=1" >> 
			/etc/sysctl.d/99-sysctl.conf			## forward incoming IPv4 traffic:

sysctl -w net.ipv4.ip_forward=1					## 
sysctl -p										## Activate the sysctl change:
systemctl restart openvpn.service				## Restart OpenVPN:


/etc/rc.local
##-===================================================================-##
## \\_~_~_~_~_~_~_~_~_~_~_~_~_~_~_~__~_~_~_~_~_~_~_~_~_~_~_~_~_~_~_//  ##
##  \_~_~_~_~_~_~_~_~_~_~_~_~_~_~_~_~_~_~_~_~_~_~_~_~_~_~_~_~_~_~_//  ##
##   \___________________________________________________________//  ##

#!/bin/sh -e
#####
#
#####
iptables -A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -A FORWARD -s 10.8.0.0/24 -j ACCEPT
iptables -A FORWARD -j REJECT
iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o eth0 -j MASQUERADE
iptables -A INPUT -i tun+ -j ACCEPT
iptables -A FORWARD -i tun+ -j ACCEPT
iptables -A INPUT -i tap+ -j ACCEPT
iptables -A FORWARD -i tap+ -j ACCEPT

exit 0
##-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-##
##-===================================================================-##

    /etc/openvpn/server.conf
        push "dhcp-option DNS 208.67.222.222"
        push "dhcp-option DNS 208.67.220.220"
        
push "redirect-gateway def1 bypass-dhcp"


OpenVPN requires TUN/TAP device file
mkdir /dev/net
mknod /dev/net/tun c 10 200


create the TAP/TUN device first:

sudo mkdir /dev/net
sudo mknod /dev/net/tun c 10 200
sudo /sbin/modprobe tun




 *  **PKI**: Public Key Infrastructure. This describes the collection of files
    and associations between the CA, keypairs, requests, and certificates.
 *  **CA**: Certificate Authority. This is the "master cert" at the root of a
    PKI.
 *  **cert**: Certificate. A certificate is a request that has been signed by a
    CA. The certificate contains the public key, some details describing the
    cert itself, and a digital signature from the CA.
 *  **request**: Certificate Request (optionally 'req'.) This is a request for a
    certificate that is then send to a CA for signing. A request contains the
    desired cert information along with a digital signature from the private
    key.
 *  **keypair**: A keypair is an asymmetric cryptographic pair of keys. These
    keys are split into two parts: the public and private keys. The public key
    is included in a request and certificate.




email (an email address) URI a uniform resource indicator, DNS (a DNS domain name), RID (a registered ID: OBJECT
IDENTIFIER), IP (an IP address), dirName (a distinguished name) and otherName.

        Value                  Meaning
        -----                  -------
        serverAuth             SSL/TLS Web Server Authentication.
        clientAuth             SSL/TLS Web Client Authentication.
        codeSigning            Code signing.
        emailProtection        E-mail Protection (S/MIME).
        timeStamping           Trusted Timestamping
        OCSPSigning            OCSP Signing
        ipsecIKE               ipsec Internet Key Exchange
        msCodeInd              Microsoft Individual Code Signing (authenticode)
        msCodeCom              Microsoft Commercial Code Signing (authenticode)
        msCTLSign              Microsoft Trust List Signing
        msEFS                  Microsoft Encrypted File System

       Examples:

        extendedKeyUsage=critical,codeSigning,1.2.3.4
        extendedKeyUsage=serverAuth,clientAuth






cd /etc/openvpn/easy-rsa/
./easyrsa build-client-full $CLIENT
./easyrsa build-client-full "${NAME}"

./easyrsa gen-dh
./easyrsa --batch build-ca
./easyrsa init-pki



Generate an RSA private key using default parameters:

openssl genpkey -algorithm RSA -out key.pem


Encrypt output private key using 128 bit AES and the passphrase "hello":

openssl genpkey -algorithm RSA -out key.pem -aes-128-cbc -pass pass:hello




pkeyutl
rsautl
x509
genpkey
pkcs7
pkeyutl
gendsa
pkcs12
verify
x509v3_config
ca
req
CA.pl
spkac
config
X509v3
crypto
signver
openssl-verify
openssl-rsautl
openssl-rand




signtool option -G 

generates a new public-private key pair and certificate







Set security level to 2 and display all ciphers consistent with level 2:

openssl ciphers -s -v 'ALL:@SECLEVEL=2'








keyrings

keyutils
persistent-keyring
user-keyring
user-session-keyring
user-namespaces
request-key
credentials





keytool -list -keystore java.home/lib/security/cacerts



keytool -printcert -file 



Print some info about a PKCS#12 file:
openssl pkcs12 -in file.p12 -info -noout


-fingerprint

calculate the fingerprint of RiseupCA.pem
certtool -i < RiseupCA.pem |egrep -A 1 'SHA256 fingerprint'

openssl x509 -sha256 -in RiseupCA.pem -noout -fingerprint

head -n -1 RiseupCA.pem | tail -n +2 | base64 -d | sha256sum

sudo openvpn --client --dev tun --auth-user-pass --remote vpn.riseup.net 1194 --keysize 256 --auth SHA256 --cipher AES-256-CBC --ca RiseupCA.pem 





# check site ssl certificate dates
echo | openssl s_client -connect www.google.com:443 2>/dev/null |openssl x509 -dates -noout










 
 
 

sudo openssl req -newkey rsa:4096 -keyout /etc/openvpn/vpn-key.pem -out vpn.csr


sudo openssl req -newkey rsa:4096 -keyout /etc/openvpn/ClientVPNKey.pem -out /etc/openvpn/ClientVPNKey.csr

echo 'OpenVPN' | sha256sum | cut -c1-20

echo 'ClientVPN' | sha256sum | cut -c1-20
echo 'Challenge' | sha256sum | cut -c1-20

sudo openssl req -newkey rsa:4096 -keyout /etc/openvpn/ServerVPNKey.pem -out ServerVPNKey.csr

echo 'ServerVPN' | sha256sum | cut -c1-20
echo 'Challenge' | sha256sum | cut -c1-20

openssl x509 -CA cacert.pem -CAkey cakey.pem -CAcreateserial -days 730 -req -in ClientVPNKey.csr -out ClientVPNKey.pem


Please enter the following 'extra' attributes
to be sent with your certificate request
A challenge password []:

echo -n 'poop' | sha1sum | cut -c1-20



echo "On your CAs environment (hopefully elsewhere):"
openssl x509 -CA cacert.pem -CAkey cakey.pem -CAcreateserial -days 730 -req -in vpn.csr -out vpn-cert.pem



./easy-rsa.sh --batch build-ca nopass
chown nobody:$GROUPNAME /etc/openvpn/crl.pem


sudo openssl dhparam -out /etc/openvpn/dh4096.pem 4096
sudo cp -v dh4096.pem /etc/openvpn/dh2048.pem


sudo openssl dhparam -out /etc/openvpn/ClientVPN-dh4096.pem 4096

sudo openssl dhparam -out /etc/openvpn/ServerVPN-dh4096.pem 4096





openssl x509 -in cert.pem -addtrust clientAuth -setalias "Steve's Class 1 CA" -out trust.pem

genrsa -aes256 -out numbits 512





# Download this file (https://blog.patternsinthevoid.net/isis.txt):
wget -q --ca-certificate=${HOST}.pem https://${HOST}/isis.txt



# Check the SSL certificate fingerprint (it should match the ones given in this file):
cat ${HOME}/${HOST}.pem | openssl x509 -fingerprint -noout -in /dev/stdin


Display the certificate SHA1 fingerprint:
openssl x509 -sha1 -in cert.pem -noout -fingerprint


# Check the SSL certificate fingerprint (it should match the ones given in this file):
cat .pem | openssl x509 -fingerprint -noout -in /dev/stdin


openssl x509 -noout -issuer -subject -fingerprint -dates


openssl s_client -connect  | openssl x509 -text


echo | openssl s_client -connect www.google.com:443 2>/dev/null | openssl x509 -text







echo "##===============================##"
echo "[+] This report that displays 	 "
echo "    The following attributes: 	 "
echo "##===============================##"

echo "#>-------------------------------<#"
echo "    -> certificate issuer			"
echo "#--------------------------------#"
echo "    -> certificate name			"
echo "#--------------------------------#"
echo "    -> fingerprint				"
echo "#--------------------------------#"
echo "    -> dates						"
echo "#--------------------------------#"
echo
echo "#>-------------------------------<#"
echo " [?] in addition to the dates:"
echo "#>-------------------------------<#"
echo | openssl s_client -connect www.google.com:443 2>/dev/null | openssl x509 -noout -issuer -subject -fingerprint -dates

















PKCS#10 certificate request





Examine and verify certificate request:

openssl req -in req.pem -text -verify -noout



Create a private key and then generate a certificate request from it:

openssl genrsa -out key.pem 2048
openssl req -new -key key.pem -out req.pem



The same but just using req:

openssl req -newkey rsa:2048 -keyout key.pem -out req.pem



Generate a self signed root certificate:

openssl req -x509 -newkey rsa:2048 -keyout key.pem -out req.pem


Sign a certificate request, using CA extensions:

openssl ca -in req.pem -extensions v3_ca -out newcert.pem


Sign several requests:

openssl ca -infiles req1.pem req2.pem req3.pem









Create some DSA parameters:

openssl dsaparam -out dsap.pem 1024


Create a DSA CA certificate and private key:

openssl req -x509 -newkey dsa:dsap.pem -keyout cacert.pem -out cacert.pem


Create a DSA certificate request and private key 
(a different set of parameters can optionally be created first):

openssl req -out newreq.pem -newkey dsa:dsap.pem


Sign the request:

CA.pl -signreq





# The following is a standard PKCS1-v1_5 padding for SHA256 signatures, as
# defined in RFC3447. It is prepended to the actual signature (32 bytes) to
# form a sequence of 256 bytes (2048 bits) that is amenable to RSA signing. The
# padded hash will look as follows:
#
#    0x00 0x01 0xff ... 0xff 0x00  ASN1HEADER  SHA256HASH
#   |--------------205-----------||----19----||----32----|
#
# where ASN1HEADER is the ASN.1 description of the signed data. The complete 51
# bytes of actual data (i.e. the ASN.1 header complete with the hash) are
# packed as follows:
#
#  SEQUENCE(2+49) {
#   SEQUENCE(2+13) {
#    OBJECT(2+9) id-sha256
#    NULL(2+0)
#   }
#   OCTET STRING(2+32) <actual signature bytes...>
#  }






Parse a PKCS#12 file and output it to a file:

openssl pkcs12 -in file.p12 -out file.pem


Print some info about a PKCS#12 file:
openssl pkcs12 -in file.p12 -info -noout



Create a PKCS#12 file:

openssl pkcs12 -export -in file.pem -out file.p12 -name "My Certificate"


Include some extra certificates:

openssl pkcs12 -export -in file.pem -out file.p12 -name "My Certificate" -certfile othercerts.pem















Generate a CRL
openssl ca -gencrl -out crl.pem










CA.pl -newca
CA.pl -newreq
CA.pl -signreq
CA.pl -pkcs12 "My Test Certificate"



-newcert				## 
-newreq				## 
-newca				## 
-pkcs12				## 
-crl				## 
				## 




-sign				## 
				## 
				## 
				## 
				## 
				## 
				## 
				## 
openssl req				## 
openssl pkcs12				## 
openssl ca				## 
openssl x509				## 

openssl verify




# padding for openssl rsautl -pkcs (smartcard keys)
#
# The following is an ASN.1 header. It is prepended to the actual signature
# (32 bytes) to form a sequence of 51 bytes. OpenSSL will add additional
# PKCS#1 1.5 padding during the signing operation. The padded hash will look
# as follows:
#
#    ASN1HEADER  SHA256HASH
#   |----19----||----32----|
#
# where ASN1HEADER is the ASN.1 description of the signed data. The complete 51
# bytes of actual data (i.e. the ASN.1 header complete with the hash) are
# packed as follows:
#
#  SEQUENCE(2+49) {
#   SEQUENCE(2+13) {
#    OBJECT(2+9) id-sha256
#    NULL(2+0)
#   }
#   OCTET STRING(2+32) <actual signature bytes...>
#  }


-in
-out
-text
-new
-pubkey
-verify

-newkey rsa



openssl rsautl -verify -in file -inkey ClientVPNKey.pem -raw -hexdump
openssl rsautl -verify -in sig -inkey ClientVPNKey.pem


openssl rsautl -sign -in file -inkey key.pem -out sig
openssl req -nodes -new -x509 -keyout ca.key -out ca.crt --genkey --secret xe1phix.key





openssl genrsa -out "${OUT}.key" 4096


openssl req -new -key "${OUT}.key" -out "${OUT}.csr" -subj '/C=US/ST=CA/L=San Francisco/O=Docker/CN=Notary Testing Client Auth'

openssl x509 -req -days 3650 -in "${OUT}.csr" -signkey "${OUT}.key" -out "${OUT}.crt" -extfile "${OUT}.cnf" -extensions ssl_client





openssl genrsa -out "${OUT}.key" 4096

openssl req -new -nodes -key "${OUT}.key" -out "${OUT}.csr" -subj "/C=US/ST=CA/L=San Francisco/O=Docker/CN=${COMMONNAME}" -config "${OUT}.cnf" -extensions "v3_req"

openssl x509 -req -days 3650 -in "${OUT}.csr" -signkey "${OUT}.key" -out "${OUT}.crt" -extensions v3_req -extfile "${OUT}.cnf"








echo "## ======================================================= ##"
echo "   [+] Converting certificates to encrypted .p12 format		"
echo "## ======================================================= ##"
echo "## -------------------------------------------------------- ##"
echo "## Some software will only read VPN certificates that are 	"
echo "## stored in a password-encrypted .p12 file. 					"
echo "## These can be generated with the following command:			"
echo "## -------------------------------------------------------- ##"
openssl pkcs12 -export -inkey keys/bugs.key -in keys/bugs.crt -certfile keys/ca.crt -out keys/bugs.p12










echo "## ================================================ ##"
echo "## 		[+] Generate key for tls-auth				"
echo "## ================================================ ##"
openvpn --genkey --secret /etc/openvpn/ta.key

## ----------------------------------------------------- ##
##    [?]  In the server configuration, add:
## ----------------------------------------------------- ##
tls-auth ta.key 0

## ----------------------------------------------------- ##
##  [?]  In the client configuration, add:
## ----------------------------------------------------- ##
tls-auth ta.key 1












Convert a certificate from PEM to DER format:

openssl x509 -in cert.pem -inform PEM -out cert.der -outform DER






CN (Common Name):	Mullvad CA



Mullvad CA
Identity: Mullvad CA
Verified by: Mullvad CA
Expires: 03/22/2019

Subject Name
C (Country):	NA
ST (State):	None
L (Locality):	None
O (Organization):	Mullvad
CN (Common Name):	Mullvad CA
EMAIL (Email Address):	info@mullvad.net
Issuer Name
C (Country):	NA
ST (State):	None
L (Locality):	None
O (Organization):	Mullvad
CN (Common Name):	Mullvad CA
EMAIL (Email Address):	info@mullvad.net




se.mullvad.net:1302

193.138.219.228








echo "## ================================================ ##"
echo "## [+] Change The Permissions to Private Files:		"
echo "## ================================================ ##"
Change The Permissions to Private Files:
sudo chmod 600 /etc/openvpn/vpn-key.pem
sudo chmod 600 /etc/openvpn/ta.key

echo "## ========================================================= ##"
echo "## [+] Turn on The Immutable Bit For The VPN Keys & Certs:	 " 
echo "## ========================================================= ##"
chattr +i /etc/openvpn/mullvad_ca.crt
chmod -v 0644 
chown -v 
chattr +i /etc/openvpn/mullvad_crl.pem



sudo chmod -v 0644 mullvad_ca.crt 
sudo chmod -v 0644 mullvad_crl.pem 
sudo chmod ug+r mullvad_userpass.txt
cp /etc/resolv.conf ~/Scripts/resolv.conf.ovpnsave
chmod 644 ~/Scripts/resolv.conf.ovpnsave
sudo chown -v root mullvad_userpass.txt
sudo chown -v root mullvad_crl.pem 
sudo chown -v root mullvad_ca.crt



sudo chmod u+r vpn-key.pem
chattr +i 
sudo chmod ug+r mullvad_userpass.txt
chattr +i ta.key

vpn.csr

chattr +i dh4096.pem



echo "## ================================================ ##"
echo "				[+] TLS Authentication					"
echo "## ================================================ ##"
echo "## ---------------------------------------------------------------------------------- ##"
echo "##  [?] To enable TLS authentication					    "
echo "## 	     first generate a static encryption key. 		"
echo "## 	     This needs to be securely copied 				"
echo "## 	     to all OpenVPN clients and servers.			"
echo "## ---------------------------------------------------------------------------------- ##"
echo "## ================================================ ##"
openvpn --genkey --secret vpn.tlsauth


echo "##-======================================================-##"
echo "## 					In the configuration files: 					"
echo "##-======================================================-##"
echo "## -------------------------------------------------------------------------------------------- ##"
echo "##   [?] The KEYDIR must be 0 on one of the sides and 1 on the other. 	"
echo "## 	      So if you choose the KEYDIR value of 0 for the server, all		        "
echo "## 	      clients must be 1, and vice versa.								                            "
echo "## -------------------------------------------------------------------------------------------- ##"
echo "##-======================================================-##"
tls-auth myvpn.tlsauth 



./easyrsa help options

	# Configure vars
	sed -i "s/KEY_SIZE=.*/KEY_SIZE=4096/g" /etc/openvpn/easy-rsa/vars
	sed -i 's/export CA_EXPIRE=3650/export CA_EXPIRE=365/' /etc/openvpn/easy-rsa/vars
	sed -i 's/export KEY_EXPIRE=3650/export KEY_EXPIRE=365/' /etc/openvpn/easy-rsa/vars
	sed -i "s/export KEY_COUNTRY=\"US\"/export KEY_COUNTRY=\"$country\"/" /etc/openvpn/easy-rsa/vars
	sed -i "s/export KEY_PROVINCE=\"CA\"/export KEY_PROVINCE=\"$province\"/" /etc/openvpn/easy-rsa/vars
	sed -i "s/export KEY_CITY=\"SanFrancisco\"/export KEY_CITY=\"$city\"/" /etc/openvpn/easy-rsa/vars
	sed -i "s/export KEY_ORG=\"Fort-Funston\"/export KEY_ORG=\"$organization\"/" /etc/openvpn/easy-rsa/vars
	sed -i "s/export KEY_EMAIL=\"me@myhost.mydomain\"/export KEY_EMAIL=\"$email\"/" /etc/openvpn/easy-rsa/vars
	sed -i "s/export KEY_OU=\"MyOrganizationalUnit\"/export KEY_OU=\"$organizationUnit\"/" /etc/openvpn/easy-rsa/vars
	sed -i "s/export KEY_NAME=\"EasyRSA\"/export KEY_NAME=\"$commonName\"/" /etc/openvpn/easy-rsa/vars
	sed -i "s/export KEY_CN=openvpn.example.com/export KEY_CN=\"$commonName\"/" /etc/openvpn/easy-rsa/vars


./easyrsa init-pki
sudo ./easyrsa build-ca nopass
sudo ./easyrsa gen-req VPN.csr nopass

req: /etc/openvpn/easy-rsa/easyrsa3/pki/reqs/VPN.csr.req
key: /etc/openvpn/easy-rsa/easyrsa3/pki/private/VPN.csr.key

sudo ./easyrsa build-client-full Xe1phix

echo 'Xe1phix.key' | sha256sum | cut -c1-20


sudo ./easyrsa gen-crl
CRL file: /etc/openvpn/easy-rsa/easyrsa3/pki/crl.pem

set-rsa-pass 





# Certificate Authority
>ca-key.pem      openssl genrsa 2048
>ca-csr.pem      openssl req -sha256 -new -key ca-key.pem -subj /CN=OpenVPN-CA/
>ca-cert.pem     openssl x509 -req -sha256 -in ca-csr.pem -signkey ca-key.pem -days 365
>ca-cert.srl     echo 01

# Server Key & Certificate
>server-key.pem  openssl genrsa 2048
>server-csr.pem  openssl req -sha256 -new -key server-key.pem -subj /CN=OpenVPN-Server/
>server-cert.pem openssl x509 -sha256 -req -in server-csr.pem -CA ca-cert.pem -CAkey ca-key.pem -days 365

# Client Key & Certificate
>client-key.pem  openssl genrsa 2048
>client-csr.pem  openssl req -sha256 -new -key client-key.pem -subj /CN=OpenVPN-Client/
>client-cert.pem openssl x509 -req -sha256 -in client-csr.pem -CA ca-cert.pem -CAkey ca-key.pem -days 365

# Diffie hellman parameters
>dh.pem     openssl dhparam 2048




openssl x509 -text -in certif.crt -noout 			## Read a certificate
openssl req -text -in request.csr -noout  			## Read a Certificate Signing Request


## Generate a Certificate Signing Request (in PEM format) for the public key of a key pair
openssl req -new -key private.key -out request.csr  			


## Create a 2048-bit RSA key pair and generate a Certificate Signing Request for it
openssl req -new -nodes -keyout private.key -out request.csr -newkey rsa:2048 


## Generate a self-signed root certificate (and create a new CA private key)
openssl req -x509 -newkey rsa:2048 -nodes -keyout private.key -out certif.crt -days validity 

## Generate a self-signed certificate
openssl ca -config ca.conf -in request.csr -out certif.crt -days validity -verbose 

## Revoke a certificate
openssl ca -config ca.conf -gencrl -revoke certif.crt -crl_reason why 

## Generate a Certificate Revocation List containing all revoked certificates so far
openssl ca -config ca.conf -gencrl -out crlist.crl 

## Convert a certificate from PEM to DER
openssl x509 -in certif.pem -outform DER -out certif.der 

## Convert a certificate from PEM to PKCS#12 including the private key
openssl pkcs12 -export -in certif.pem -inkey private.key -out certif.pfx -name friendlyname 

## Create a PEM certificate from CRT and private key
cat cert.crt cert.key > cert.pem 

## Generate the digest of a file
openssl dgst -hashfunction -out file.hash file 

## Verify the digest of a file (no output means that digest verification is successful)
openssl dgst -hashfunction file | cmp -b file.hash 

## Generate the signature of a file
openssl dgst -hashfunction -sign private.key -out file.sig file 


## Verify the signature of a file
openssl dgst -hashfunction -verify public.key -signature file.sig file 

## Encrypt a file
openssl enc -e -cipher -in file -out file.enc -salt 

## Decrypt a file
openssl enc -d -cipher -in file.enc -out file 

## Generate a 2048-bit RSA key pair protected by TripleDES passphrase
openssl genpkey -algorithm RSA -cipher 3des -pkeyopt rsa_keygen_bits:2048 -out key.pem 

## Examine a private key
openssl pkey -text -in private.key -noout 

## Change the passphrase of a private key
openssl pkey -in old.key -out new.key -cipher 

## Remove the passphrase from a private key
openssl pkey -in old.key -out new.key 


## Retrieve and inspect a SSL certificate from a website
openssl s_client -connect www.website.com:443 > tmpfile 
openssl x509 -in tmpfile -text

## List all available hash functions
openssl list-message-digest-commands 

## List all available ciphers
openssl list-cipher-commands 





echo "## =========================================================== ##"
echo "   [+] Copy the mullvad config files to /etc/openvpn folder:"
echo "## =========================================================== ##"
sudo cp -v mullvad_ca.crt /etc/openvpn/
sudo cp -v mullvad_crl.pem /etc/openvpn/ 
sudo cp -v mullvad_se.conf /etc/openvpn/
sudo cp -v mullvad_se-modified.conf /etc/openvpn/
sudo cp -v mullvad_userpass.txt /etc/openvpn/
sudo cp -v update-resolv-conf /etc/openvpn/



# Preserve the existing resolv.conf
if [ -e /etc/resolv.conf ] ; then
  cp /etc/resolv.conf /etc/resolv.conf.ovpnsave
  chmod 644 /etc/resolv.conf.ovpnsave
  chown -v root  /etc/resolv.conf.ovpnsave
fi


chmod 644 /etc/resolv.conf
fi


#   up /etc/openvpn/client.up
# Next, "chmod a+x /etc/openvpn/client.up



# Preserve the existing resolv.conf
if [ -e /etc/resolv.conf ] ; then
  cp /etc/resolv.conf /etc/resolv.conf.ovpnsave
  chmod 644 /etc/resolv.conf
fi





echo "## =========================================================== ##"
echo "   [+] Modify the permissions of the update-resolv-conf file:"
echo "## =========================================================== ##"
chmod 755 /etc/openvpn/update-resolv-conf


echo "## =========================================================== ##"
echo "   [+] Modify the DNS Resolver Used By NetworkManager:"
echo "## =========================================================== ##"
pluma /etc/NetworkManager/NetworkManager.conf &



echo "## ========================================= ##"
echo "   [?] change dns=dnsmasq to #dns=dnsmasq" 
echo "## ========================================= ##"


$ sed -i 's/managed=.*/managed=true/' "$file"

chmod a+x /etc/openvpn/client.up


/etc/network/interfaces            
iface eth0 inet static
	address 192.168.1.10
	netmask 255.255.255.0
	network 192.168.1.0
	broadcast 192.168.1.255
	gateway 192.168.1.1



cat


echo "## =============================================== ##"
echo "   [+] Restart The NetworkManager Service:"
echo "## =============================================== ##"
sudo service network-manager restart


systemctl restart openvpn@client.service
systemctl enable openvpn@client.service

update-rc.d openvpn defaults
update-rc.d iptables-persistent defaults

service openvpn restart
chkconfig openvpn on

sudo invoke-rc.d openvpn restart
sudo /etc/init.d/openvpn restart


sudo chkconfig --add openvpn
sudo update-rc.d openvpn defaults


echo "## ===================================================== ##"
echo "   [?] Because of the use of Wayland instead of X "
echo "       there seems to be a display error "
echo "       when starting the Mullvad client with "
echo "## ===================================================== ##"
sudo mullvad

echo "## ================================================================= ##"
echo "   [?] and this can be solved by starting the client with just "
echo "## ================================================================= ##"
mullvad



echo "## =========================================================== ##"
echo "   [+] To handle wxPython 3 appropriately"
echo "   Add MULLVAD_USE_GTK3 environment variable:"
echo "## =========================================================== ##"
export MULLVAD_USE_GTK3=yes









echo "## ================================================================= ##"
echo "   [?] IPv6 is disabled by default "
echo "       OpenVPN can exit out with a fatal error."
echo "       To Fix this issue"
echo "       Edit the OpenVPN configuration:"
echo "## ================================================================= ##"


echo "-----------"
echo " Replace   "
echo "-----------"
echo "proto udp  "
echo "-----------"
echo "	with 	 "
echo "-----------"
echo "proto udp4 "
echo "-----------"


echo "-----------"
echo " Replace   "
echo "-----------"
echo "proto tcp "
echo "-----------"
echo "  with     "
echo "-----------"
echo "proto tcp4"
echo "-----------"





echo "## ================================================ ##"
echo "   [+] Add These Parameters To mullvad_se.conf:"
echo "## ================================================ ##"
pull-filter ignore "route-ipv6"
pull-filter ignore "ifconfig-ipv6"


plugin /usr/lib/openvpn/plugins/openvpn-plugin-down-root.so "/etc/openvpn/client/client.down tun0"


script-security 2
up /etc/openvpn/update-resolv-conf
down /etc/openvpn/update-resolv-conf




cp -v openvpn-reconnect.service /etc/systemd/system/


## -------------------------------------------------------------- ##
##    [?]  kill and restart OpenVPN after suspend:
## -------------------------------------------------------------- ##

/etc/systemd/system/openvpn-reconnect.service

[Unit]
Description=Restart OpenVPN after suspend
[Service]
ExecStart=/usr/bin/pkill --signal SIGHUP --exact openvpn
[Install]
WantedBy=sleep.target



systemd-networkd can be configured to ignore the tun connections and allow OpenVPN to manage them. To do this, create the following file:

/etc/systemd/network/90-tun-ignore.network

[Match]
Name=tun*

[Link]
Unmanaged=true



sudo cp -v 90-tun-ignore.network /etc/systemd/network/

Restart systemd-networkd.service to apply the changes.









Connection drops out after some time of inactivity
## ----------------------------------------------------------------------------------------------- ##
## If the VPN-Connection drops some seconds after it stopped transmitting data and, 
## even though it states it is connected, no data can be transmitted through the tunnel, 
## try adding a keepalivedirective to the server's configuration:
## ----------------------------------------------------------------------------------------------- ##
/etc/openvpn/server/server.conf

.
.
keepalive 10 120
.
.







## Prevent leaks if VPN goes down
## ----------------------------------------------------------------------------------------------- ##
## prevent all traffic through our default interface (enp3s0 for example) and only allow tun0
## the OpenVPN connection drops, your computer will lose its internet access and therefore, 
## avoid your programs to continue connecting through an insecure network adapter. 
## ----------------------------------------------------------------------------------------------- ##

 # Default policies
 ufw default deny incoming
 ufw default deny outgoing
 
 # Openvpn interface (adjust interface accordingly to your configuration)
 ufw allow in on tun0
 ufw allow out on tun0
 
 # Local Network (adjust ip accordingly to your configuration)
 ufw allow in on enp3s0 from 192.168.1.0/24
 ufw allow out on enp3s0 to 192.168.1.0/24
 
 # Openvpn (adjust port accordingly to your configuration)
 ufw allow in on enp3s0 from any port 1194
 ufw allow out on enp3s0 to any port 1194












echo "## ================================================================= ##"
echo "   [?] Mullvad default settings File Location:"
echo "       ~/.config/mullvad/settings.ini"
echo "## ================================================================= ##"



## Copy the client configuration file from the server and set secure permissions:
sudo install ‐o root ‐m 400 CLIENTNAME.ovpn /etc/openvpn/CLIENTNAME.conf



## create the TAP/TUN device first:

sudo mkdir /dev/net
sudo mknod /dev/net/tun c 10 200
sudo /sbin/modprobe tun

echo "## ================================================ ##"
echo "   [+] Load Mullvads Configuration Into OpenVPN:"
echo "## ================================================ ##"
sudo openvpn --config /etc/openvpn/mullvad_linux.conf --auth-user-pass /etc/openvpn/mullvad_userpass.txt

chown -v root:openvpn /etc/openvpn/mullvad_userpass.txt


sudo openvpn --client --dev tun0 --config /etc/openvpn/mullvad_se.conf --auth-user-pass /etc/openvpn/mullvad_userpass.txt --remote se.mullvad.net 1302 --auth SHA256 --cipher AES-256-CBC --ca /etc/openvpn/mullvad_crl.pem


 

sudo openvpn --client --dev tun --auth-user-pass /etc/openvpn/mullvad_userpass.txt --remote se.mullvad.net 1302
sudo openvpn --ca /etc/openvpn/mullvad_crl.pem
sudo openvpn --client --dev tun --ca /etc/openvpn/mullvad_crl.pem --remote se.mullvad.net 1302


## Configure the init scripts to autostart all configurations matching /etc/openvpn/*.conf :
echo AUTOSTART=all | sudo tee ‐a /etc/default/openvpn




sudo /etc/init.d/openvpn restart



echo "## ===================================== ##"
echo "   [+] Start The OpenVPN Service:"
echo "## ===================================== ##"
service openvpn start

sudo systemctl enable openvpn*.service && sudo systemctl start openvpn*.service

systemctl enable openvpn-client@.service

echo "## ===================================================================================== ##"
echo "   [+] Reload The OpenVPN Daemon After Configuration File Gets Loaded Into Openvpn:"
echo "## ===================================================================================== ##"
systemctl daemon-reload openvpn.service



## /etc/openvpn-shutdown.sh
# stop all openvpn processes
# killall -TERM openvpn







http://openvpn.net/examples.html



## IP address of the VPN server.
## Get the IP using: 
nslookup se.mullvad.net

Name:	se1-bridge.mullvad.net
Address: 193.138.219.43


sudo nslookup se-sto.mullvad.net

Non-authoritative answer:
Name:	se-sto.mullvad.net
Address: 185.65.135.149
Name:	se-sto.mullvad.net
Address: 185.65.135.139
Name:	se-sto.mullvad.net
Address: 185.65.135.141
Name:	se-sto.mullvad.net
Address: 185.65.135.145
Name:	se-sto.mullvad.net
Address: 185.65.135.73
Name:	se-sto.mullvad.net
Address: 185.65.135.138
Name:	se-sto.mullvad.net
Address: 185.65.135.150
Name:	se-sto.mullvad.net
Address: 185.65.135.140
Name:	se-sto.mullvad.net
Address: 185.65.135.143
Name:	se-sto.mullvad.net
Address: 185.65.135.142
Name:	se-sto.mullvad.net
Address: 185.65.135.151
Name:	se-sto.mullvad.net
Address: 185.65.135.147
Name:	se-sto.mullvad.net
Address: 185.65.135.148
Name:	se-sto.mullvad.net
Address: 185.65.135.137
Name:	se-sto.mullvad.net
Address: 185.65.135.152


Non-authoritative answer:
Name:	se-hel.mullvad.net
Address: 185.213.152.139
Name:	se-hel.mullvad.net
Address: 185.65.132.108
Name:	se-hel.mullvad.net
Address: 185.213.152.131
Name:	se-hel.mullvad.net
Address: 185.213.152.132
Name:	se-hel.mullvad.net
Address: 185.213.152.143
Name:	se-hel.mullvad.net
Address: 185.213.152.134
Name:	se-hel.mullvad.net
Address: 185.213.152.138
Name:	se-hel.mullvad.net
Address: 185.213.152.137













user nobody
group nobody



Write the following script and place it at: /usr/local/sbin/unpriv-ip:

#!/bin/sh
sudo /sbin/ip $*


openvpn ALL=(ALL)  NOPASSWD: /sbin/ip
%openvpn ALL=(ALL)  NOPASSWD: /sbin/ip
%tunnel ALL=(ALL)  NOPASSWD: /sbin/ip


Add the following to your OpenVPN configuration:
iproute /usr/local/sbin/unpriv-ip


add user account tunnel

sudo adduser tunnel
sudo addgroup tunnel

sudo chown -R tunnel:tunnel /etc/openvpn

sudo chown -R tunnel:tunnel /var/run/openvpn



sudo /usr/sbin/openvpn --rmtun --dev tun0
sudo /usr/sbin/openvpn --mktun --dev tun0 --dev-type tun --user tunnel --group tunnel
cd /etc/openvpn/
sudo -u tunnel openvpn /etc/openvpn/

echo "set the necessary permissions."
sudo chown --recursive root:tunnel /run/resolvconf
sudo chmod --recursive 775 /run/resolvconf



useradd --home /etc/openvpn --user-group --shell /bin/false "$user_account"
sudo adduser --no-create-home --shell /sbin/nologin openvpn
sudo addgroup openvpn

openvpn --rmtun --dev tun0
openvpn --mktun --dev tun0 --dev-type tun --user openvpn --group openvpn

sudo openvpn --client --dev tun --auth-user-pass --remote vpn.riseup.net 1194 --keysize 256 --auth SHA256 --cipher AES-256-CBC --ca RiseupCA.pem 
 
 
 
 
openvpn --dev tun --port 9999 --verb 4 
--persist-key 
 --persist-tun
--chroot
--proto udp
 --route-up
 

chown -v -R openvpn:openvpn /etc/openvpn
usermod -d /etc/openvpn -s /sbin/nologin openvpn

chmod -v 0775 /run/resolvconf
chown -v root:tunnel /run/resolvconf
chmod -v 0755 /run/openvpn
chown -v tunnel:tunnel /run/openvpn
chmod -v 0775 /run/resolvconf/interface
chown -v root:tunnel /run/resolvconf/interface

sudo usermod -s /sbin/nologin tunnel
sudo usermod -s /sbin/nologin postgres

sudo usermod -s /sbin/nologin sync
sudo usermod -s /sbin/nologin arpwatch
sudo usermod -s /sbin/nologin couchdb
sudo usermod -s /sbin/nologin debian-spamd


sudo usermod --lock postgres
sudo usermod --lock mysql
sudo usermod --lock arpwatch
sudo usermod --lock Debian-snmp
sudo usermod --lock couchdb
sudo usermod --lock debian-spamd


sudo mkdir /var/log/openvpn
sudo chown -v -R openvpn:openvpn /var/run/openvpn /var/log/openvpn /etc/openvpn
sudo chmod -v -R u+w /var/run/openvpn /var/log/openvpn

sudo chown -v --recursive root:openvpn /run/resolvconf


sudo systemctl restart networking.service
sudo systemctl status networking.service

sudo systemctl restart openvpn.service
sudo systemctl status openvpn.service
sudo systemctl restart NetworkManager.service 
sudo systemctl status NetworkManager.service 






openvpn ALL=(ALL) NOPASSWD: /sbin/ip
Defaults:openvpn !requiretty

passwd openvpn



sudo 



## Link types:

## --> 		vlan - 802.1q tagged virtual LAN interface
## --> 		veth - Virtual ethernet interface
## --> 		vcan - Virtual Local CAN interface
## --> 		dummy - Dummy network interface
## --> 		ifb - Intermediate Functional Block device
## --> 		macvlan - virtual interface base on link layer address (MAC)
## --> 		can - Controller Area Network interface
## --> 		bridge - Ethernet Bridge device





# OpenVPN 2.0 uses UDP port 1194 by default
# (official port assignment by iana.org 11/04).
# OpenVPN 1.x uses UDP port 5000 by default.









ip link set eth0
# We activate the bridge
ip link set dev $IFACE up



## ================================================================= ##
echo -e "\t [+] Establish Hardware Interface Environment Variables:"
## ================================================================= ##
Ether="eth0"
Wlan="wlan0"
Alpha="wlan1"
LOOPBACK="lo"
VPN_INTERFACE="tun0"
## ================================================================= ##
echo -e "\t [+] Establish Subnetting Criteria Environment Variables:"
## ================================================================= ##
CLASS_A="10.0.0.0/8"                # Class A private networks
CLASS_B="172.16.0.0/12"             # Class B private networks
CLASS_C="192.168.0.0/16"            # Class C private networks
CLASS_D_MULTICAST="224.0.0.0/4"         # Class D multicast addr
CLASS_E_RESERVED_NET="240.0.0.0/5"      # Class E reserved addr
BROADCAST_SRC="0.0.0.0"             # Broadcast source addr
BROADCAST_DEST="255.255.255.255"        # Broadcast destination addr
LOCAL_NET="192.168.1.0/24 192.168.0.0/24"

MullvadDNSServer="193.138.219.228"
## ================================================================= ##
echo -e "\t\t{+}____Privileged_Vs._Unprivileged_Port_Numbers_____{+}"
## ================================================================= ##
PRIVPORTS="0:1023"              # privileged ports, used server-side
UNPRIVPORTS="1024:"             # unprivileged ports, used client-side



dns-search 
dns-nameservers 193.138.219.228,92.222.97.145,192.99.85.244,185.121.177.177





brctl addbr br0





193.138.219.228


193.138.219.43


# Secure ssh
sed -i -e "s/#ServerKeyBits 1024/ServerKeyBits 2048/" /etc/ssh/sshd_config
sed -i -e "s/#PermitRootLogin yes/PermitRootLogin no/" /etc/ssh/sshd_config
systemctl restart sshd
	
	

sudo cp -v /home/user/Downloads/mullvad_config_linux_se/mullvad_linux.conf /etc/openvpn/



echo "## ======================================================== ##"
echo "   [+] SSH tunneling to connect to Mullvads VPN servers		"
echo "## ======================================================== ##"
ssh -f -N -D 1234 mullvad@193.138.219.43


echo "## ======================================================== ##"
echo "   [?] You will then be prompted to enter a password. 		"
echo "   	 			[?] Type in 'mullvad'						"
echo "## ======================================================== ##"


echo "## ======================================================== ##"
echo "## The authenticity of host '[193.138.219.43]:1022			"		
echo "## ([193.138.219.43]:1022)' can't be established.				"
echo "## -------------------------------------------------------- ##"
echo "## ED25519 key fingerprint is									"
echo "## -------------------------------------------------------- ##"
echo "## SHA256:LuBJ1HTfEWNQsvDc5tZrwoG+CokMypcflLMObEnCeMg.		"
echo "## -------------------------------------------------------- ##"
echo "## Are you sure you want to continue connecting (yes/no)?		"
echo "## ======================================================== ##"





custom_ovpn_args = --socks-proxy 127.0.0.1 1234 --route 193.138.219.43 255.255.255.255 net_gateway


ping se1-bridge.mullvad.net
ping se2-bridge.mullvad.net




echo "edit The mullvad_se.conf File, and add:"

socks-proxy 127.0.0.1 1234
route 193.138.219.43 255.255.255.255 net_gateway
route 185.65.132.119 255.255.255.255 net_gateway
route 185.12.57.154 255.255.255.255 net_gateway
route 38.95.111.82 255.255.255.255 net_gateway




if [ -n "$VPN_SERVER" ]; then
	VPN_SERVER=""
	export VPN_SERVER="198.252.153.26"

[ -n "$VPN_INTERFACE" ] || VPN_INTERFACE="tun0"

MULVAD_DNSRESOLVER="193.138.219.228"
export MULVAD_DNSRESOLVER="193.138.219.228"



iptables -A INPUT -p udp --dport 1194 -j ACCEPT


chkconfig openvpn on
systemctl restart 
systemctl enable 


systemctl start openvpn-server@tun0


ps -ef |grep openvpn


/usr/lib/systemd/system/openvpn‐client@.service
/etc/systemd/system/openvpn‐client@.service



/etc/init.d/iptables restart
/etc/init.d/iptables save


/usr/bin/sudo /sbin/iptables-restore < /usr/share/iptables/
    post-up iptables-restore < /etc/iptables.up.rules


	up /etc/openvpn/update-resolv-conf
	down /etc/openvpn/update-resolv-conf

      auto lo br0 eth1
      allow-hotplug eth0

      iface br0 inet static
      address 192.168.1.27
      gateway 192.168.1.1
      network 192.168.1.0
      netmask 255.255.255.0
      broadcast 192.168.1.255
      bridge_ports eth0 tap0
      pre-up openvpn --mktun --dev tap0


dig +short myip.opendns.com @resolver1.opendns.com




chmod +x KillSwitch.sh





Make iptables logs packets to 
the INPUT and FORWARD chains:

iptables -A INPUT -j LOG
iptables -A FORWARD -j LOG




save the iptables rules:
iptables-save > /etc/openvpn/iptables.rules

iptables-restore < /etc/openvpn/iptables.rules




http://check2ip.com/
http://dnsleak.com/

http://www.dnsleaktest.com/







journalctl -u openvpn-client@


openVPN running on a non­stanard port

semanage port -a -t openvpn_port_t -p udp 1195


semanage port -a -t openvpn_port_t -p $PROTOCOL $PORT



	# SELinux test and rules
if [[ $(getenforce) = Enforcing ]] || [[ $(getenforce) = Permissive ]]; then
	apt-get install policycoreutils-python -y  > /dev/null 2>&1
	semanage port -a -t ssh_port_t -p tcp 22
	semanage port -m -t openvpn_port_t -p tcp 443
	semanage port -a -t openvpn_port_t -p udp 443
fi






The openvpn user should be able to read these, 
but not write to them, 
and no user but openvpn should be able to read your keys.



# /tmp/openvpn_unpriv_hack.te

module openvpn_unpriv_hack 1.0;

require {
	type openvpn_t;
	type sudo_exec_t;
	class file { read open execute getattr execute_no_trans };
      	class process setrlimit;
        class capability sys_resource;
}

#============= openvpn_t ==============
allow openvpn_t sudo_exec_t:file { read open execute getattr execute_no_trans};
allow openvpn_t self:process setrlimit;
allow openvpn_t self:capability sys_resource;

then compile and install the security modules:

checkmodule -M -m -o /tmp/openvpn_unpriv_hack.mod /tmp/openvpn_unpriv_hack.te
semodule_package -o /tmp/openvpn_unpriv_hack.pp -m /tmp/openvpn_unpriv_hack.mod
semodule -i /tmp/openvpn_upriv_hack.pp

and check if they have loaded correctly:

semodule -l | grep openvpn











https://riseup.net/security/network-security/riseup-ca/RiseupCA.pem
https://riseup.net/en/security/network-security/riseup-ca/riseupCA-signed-sha256.txt

https://riseup.net/vpn/vpn-red/update-resolv.conf
https://riseup.net/vpn/vpn-red/riseup.ovpn


https://github.com/wknapik/vpnfailsafe

https://www.whonix.org/wiki/VPN-Firewall
https://wiki.archlinux.org/index.php/OpenVPN
https://wiki.archlinux.org/index.php/Easy-RSA
https://wiki.archlinux.org/index.php/VPN_over_SSH
https://wiki.archlinux.org/index.php/WireGuard
https://github.com/mdPlusPlus/mullvad-openvpn-files




