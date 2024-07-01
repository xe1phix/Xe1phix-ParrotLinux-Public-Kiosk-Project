


##-========================-##
##    [+]  Security Onion 16.04
##-========================-##
https://github.com/Security-Onion-Solutions/security-onion
https://github.com/Security-Onion-Solutions/security-onion/blob/master/Verify_ISO.md


##-=======================-##
##    [+]  16.04.7.3 ISO image:
##-=======================-##
https://download.securityonion.net/file/Security-Onion-16/securityonion-16.04.7.3.iso


##-===========================-##
##    [+]  Download the ISO image:
##-===========================-##
wget https://download.securityonion.net/file/Security-Onion-16/securityonion-16.04.7.3.iso


##-==========================-##
##    [+]  Signature for ISO image:
##-==========================-##
https://github.com/Security-Onion-Solutions/security-onion/raw/master/sigs/securityonion-16.04.7.3.iso.sig


##-======================================-##
##    [+]  Download the signature file for the ISO:
##-======================================-##
wget https://github.com/Security-Onion-Solutions/security-onion/raw/master/sigs/securityonion-16.04.7.3.iso.sig


##-================-##
##    [+]  Signing key:
##-================-##
https://raw.githubusercontent.com/Security-Onion-Solutions/security-onion/master/KEYS
wget https://raw.githubusercontent.com/Security-Onion-Solutions/security-onion/master/KEYS


##-=========================-##
##    [+]  Import the signing key:
##-==========================-##
gpg --import KEYS



##-=========================-##
##    [+]  
##-=========================-##
https://github.com/Security-Onion-Solutions/security-onion/raw/master/sigs/securityonion-16.04.7.3.iso.sig



##-====================================================-##
##    [+]  Verify the downloaded ISO image using the signature file:
##-====================================================-##
gpg --verify securityonion-16.04.7.3.iso.sig securityonion-16.04.7.3.iso


## ----------------------------------------------------------------------------------------------------------------------------------------------- ##
##   gpg: Signature made Thu 04 Mar 2021 03:48:50 PM EST using RSA key ID ED6CF680
##   gpg: Good signature from "Doug Burks <doug.burks@gmail.com>"
##   gpg: WARNING: This key is not certified with a trusted signature!
##   gpg:          There is no indication that the signature belongs to the owner.
##   Primary key fingerprint: BD56 2813 E345 A068 5FBB  91D3 788F 62F8 ED6C F680
## ----------------------------------------------------------------------------------------------------------------------------------------------- ##



##-====================-##
##    [+]  Security Onion 2
##-====================-##
https://github.com/Security-Onion-Solutions/securityonion/
https://github.com/Security-Onion-Solutions/securityonion/blob/master/VERIFY_ISO.md




##-=======================-##
##    [+]  Download and Verify
##-=======================-##


##-==============================-##
##    [+]  2.3.61-MSEARCH ISO image:
##-==============================-##
https://download.securityonion.net/file/securityonion/securityonion-2.3.61-MSEARCH.iso



##-=========================-##
##    [+]  
##-=========================-##


## ----------------------------------------------------------------------------------------------------------------------------------------------- ##
##   MD5: D38450A6609A1DFF0E19482517B24275
##   SHA1: DBCBD8F035FD875DC56307982A2480A62BCAB96D
##   SHA256: D7767AA10FE5D655E8502BDC9B8F963C5584DF8F72F26A5A997C1F2277D4F07E
## ----------------------------------------------------------------------------------------------------------------------------------------------- ##


##-=========================-##
##    [+]  
##-=========================-##
https://github.com/Security-Onion-Solutions/securityonion/blob/master/VERIFY_ISO.md


##-=========================-##
##    [+]  
##-=========================-##
wget https://download.securityonion.net/file/securityonion/securityonion-2.3.61-MSEARCH.iso



##-==========================-##
##    [+]  Signature for ISO image:
##-==========================-##
https://github.com/Security-Onion-Solutions/securityonion/raw/master/sigs/securityonion-2.3.61-MSEARCH.iso.sig



##-======================================-##
##    [+]  Download the signature file for the ISO:
##-======================================-##
wget https://github.com/Security-Onion-Solutions/securityonion/raw/master/sigs/securityonion-2.3.61-MSEARCH.iso.sig



##-================-##
##    [+]  Signing key:
##-================-##
https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/master/KEYS


##-=====================================-##
##    [+]  Download and import the signing key:
##-=====================================-##
wget https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/master/KEYS -O - | gpg --import -  



## ----------------------------------------------------------------------------------------------------------------------------------------------- ##
##   MD5: D38450A6609A1DFF0E19482517B24275
##   SHA1: DBCBD8F035FD875DC56307982A2480A62BCAB96D
##   SHA256: D7767AA10FE5D655E8502BDC9B8F963C5584DF8F72F26A5A997C1F2277D4F07E
## ----------------------------------------------------------------------------------------------------------------------------------------------- ##



gpg --keyid-format 0xlong --verbose --import 'Security-Onion-[16.04.7.3]-GPG-Code-Signing-Key.asc'

## ----------------------------------------------------------------------------------------------------------------------------------------------- ##
##   gpg: armor header: Version: SKS 1.1.5
##   gpg: armor header: Comment: Hostname: keyserver.ubuntu.com
##   gpg: pub  rsa4096/0x788F62F8ED6CF680 2012-06-29  Doug Burks <doug.burks@gmail.com>
##   gpg: using pgp trust model
##   gpg: key 0x788F62F8ED6CF680: public key "Doug Burks <doug.burks@gmail.com>" imported
##   gpg: Total number processed: 1
##   gpg:               imported: 1
## ----------------------------------------------------------------------------------------------------------------------------------------------- ##

┌─[parrotseckiosk@parrotseckiosk-optiplex990]─[~/Downloads/OS/OS-[GnuPG-Keys]]
└──╼ $gpg --fingerprint 0x788F62F8ED6CF680

## ----------------------------------------------------------------------------------------------------------------------------------------------- ##
##   pub   rsa4096/0x788F62F8ED6CF680 2012-06-29 [SC]
##         Key fingerprint = BD56 2813 E345 A068 5FBB  91D3 788F 62F8 ED6C F680
##   uid                   [ unknown] Doug Burks <doug.burks@gmail.com>
##   sub   rsa4096/0x853F98D7C5D9F4EB 2012-06-29 [E]
##         Key fingerprint = 3301 84E6 D16F 6EBF FA7A  F099 853F 98D7 C5D9 F4EB
## ----------------------------------------------------------------------------------------------------------------------------------------------- ##

## ----------------------------------------------------------------------------------------------------------------------------------------------- ##
##   gpg: Signature made Thu 04 Mar 2021 03:48:50 PM EST using RSA key ID ED6CF680
##   gpg: Good signature from "Doug Burks <doug.burks@gmail.com>"
##   gpg: WARNING: This key is not certified with a trusted signature!
##   gpg:          There is no indication that the signature belongs to the owner.
##   Primary key fingerprint: BD56 2813 E345 A068 5FBB  91D3 788F 62F8 ED6C F680
##   
## ----------------------------------------------------------------------------------------------------------------------------------------------- ##
##   Primary key fingerprint: BD56 2813 E345 A068 5FBB  91D3 788F 62F8 ED6C F680
##         		Key fingerprint = BD56 2813 E345 A068 5FBB  91D3 788F 62F8 ED6C F680
## ----------------------------------------------------------------------------------------------------------------------------------------------- ##



gpg --verbose --default-key 0x3BC00B17180C200A --lsign 0xBD562813E345A0685FBB91D3788F62F8ED6CF680


C804A93D36BE0C733EA196447C1060B7FE507013


## ----------------------------------------------------------------------------------------------------------------------------------------------- ##
##   pub  rsa4096/0x7C1060B7FE507013
##        created: 2020-06-18  expires: 2030-06-16  usage: SC  
##        trust: unknown       validity: full
##    Primary key fingerprint: C804 A93D 36BE 0C73 3EA1  9644 7C10 60B7 FE50 7013
## ----------------------------------------------------------------------------------------------------------------------------------------------- ##


gpg --keyid-format 0xlong --verify securityonion-2.3.61-MSEARCH.iso.sig securityonion-2.3.61-MSEARCH.iso

## ----------------------------------------------------------------------------------------------------------------------------------------------- ##
##   gpg: Signature made Wed 28 Jul 2021 04:27:35 PM CDT
##   gpg:                using RSA key 0x7C1060B7FE507013
##   gpg: Good signature from "Security Onion Solutions, LLC <info@securityonionsolutions.com>" [full]
##   Primary key fingerprint: C804 A93D 36BE 0C73 3EA1  9644 7C10 60B7 FE50 7013
## ----------------------------------------------------------------------------------------------------------------------------------------------- ##

https://github.com/Security-Onion-Solutions/securityonion/raw/master/sigs/securityonion-2.3.61-MSEARCH.iso.sig


##-=========================-##
##    [+]  Security-Onion-[2.3.61]
##-=========================-##
## ----------------------------------------------------------------------------------------------------------------------------------------------- ##
##    [?]  https://github.com/Security-Onion-Solutions/securityonion/blob/master/VERIFY_ISO.md
## ----------------------------------------------------------------------------------------------------------------------------------------------- ##
gpg --verbose --default-key 0x3BC00B17180C200A --lsign 0xC804A93D36BE0C733EA196447C1060B7FE507013


##-=========================-##
##    [+]  Security Onion Solutions
##-=========================-##








##-============================-##
##    [+]  Security-Onion-[16.04.7.3]
##-============================-##
##-==================================================-##
##    [+]  Security-Onion-[16.04.7.3]-GPG-Code-Signing-Key.asc
##-==================================================-##
## ----------------------------------------------------------------------------------------------------------------------------------------------- ##
##    [?]  https://github.com/Security-Onion-Solutions/security-onion/blob/master/Verify_ISO.md
## ----------------------------------------------------------------------------------------------------------------------------------------------- ##
gpg --verbose --default-key 0x3BC00B17180C200A --lsign 0xBD562813E345A0685FBB91D3788F62F8ED6CF680



