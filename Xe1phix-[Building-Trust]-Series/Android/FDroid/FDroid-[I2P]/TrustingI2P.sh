#!/bin/sh
## TrustingI2P.sh


echo "##-=============================================================================================== ##"
echo -e "\t\t [+] I2P Official App Repository:"
echo "##-=============================================================================================== ##"
echo "## https://f-droid.i2p.io/repo"
echo "## ----------------------------------------------------------------------------------------------- ##"
echo "## verify the fingerprint (SHA-256) of the repository signing key:"
echo "## ----------------------------------------------------------------------------------------------- ##"
echo "## 68 E7 65 61 AA F3 F5 3D D5 3B A7 C0 3D 79 52 13 D0 CA 17 72 C3 FA C0 15 9B 50 A5 AA 85 C4 5D C6"
echo "## ---------------------------------------------------------------------------------------------------------- ##"
echo "## https://f-droid.i2p.io/repo?fingerprint=68E76561AAF3F53DD53BA7C03D795213D0CA1772C3FAC0159B50A5AA85C45DC6"
echo "## ---------------------------------------------------------------------------------------------------------- ##"

echo "##-=============================================================================================== ##"
echo -e "\t\t [+] zzz's GPG key:"
echo "##-=============================================================================================== ##"
gpg --verbose --keyid-format 0xlong --keyserver hkp://pool.sks-keyservers.net --recv-keys 0x4456EBBEC80563FE57E6B310415576BAA76E0BED
echo "	      Key fingerprint = 4456 EBBE C805 63FE 57E6 B310 4155 76BA A76E 0BED"

echo "##-=============================================================================================== ##"
echo -e "\t\t [+] welterde's GPG key:"
echo "##-=============================================================================================== ##"
gpg --verbose --keyid-format 0xlong --keyserver hkp://pool.sks-keyservers.net --recv-keys 0x6720FD8138726DFC601664D1EBBC037462E011A1
echo "	      Key fingerprint = 6720 FD81 3872 6DFC 6016 64D1 EBBC 0374 62E0 11A1"

echo "##-=============================================================================================== ##"
echo -e "\t\t [+] Complication's GPG key:"
echo "##-=============================================================================================== ##"
gpg --verbose --keyid-format 0xlong --keyserver hkp://pool.sks-keyservers.net --recv-keys 0x73CF286287A7E7D219FFDB66FA1DFC6B79FCCE33
echo "	      Key fingerprint = 73CF 2862 87A7 E7D2 19FF DB66 FA1D FC6B 79FC CE33"


echo "##-=============================================================================================== ##"
echo -e "\t\t [+] jrandom's GPG key for Syndie releases:"
echo "##-=============================================================================================== ##"
gpg --verbose --keyid-format 0xlong --keyserver hkp://pool.sks-keyservers.net --recv-keys 0xAE89D0800E8572F0B777B2EDC2FA68C0393F2DF9
echo "	      Key fingerprint = AE89 D080 0E85 72F0 B777 B2ED C2FA 68C0 393F 2DF9"



## 
## 
## https://geti2p.net/en/get-involved/develop/release-signing-key

gpg --verbose --keyid-format 0xlong --keyserver hkp://pool.sks-keyservers.net --recv-keys 0x2D3D2D03910C6504C1210C65EE60C0C8EE7256A8

## pub   4096R/EE7256A8 2014-05-08 [expires: 2024-05-05]
## 	      Key fingerprint = 2D3D 2D03 910C 6504 C121  0C65 EE60 C0C8 EE72 56A8
## 	uid                  zzz on i2p (key signing) 
## 	uid                  zzz on i2p (key signing) 
## 	sub   4096R/1AE988AB 2014-05-08 [expires: 2019-05-07]
## 	sub   4096R/01B5610C 2014-05-08 [expires: 2019-05-07]
## 	sub   4096R/59683006 2014-05-08 [expires: 2019-05-07]

## I will use the new keys as follows:
## 	EE7256A8: key signing
## 	1AE988AB: email signing
## 	01B5610C  email encryption
## 	59683006  release signing




- -----BEGIN PGP PUBLIC KEY BLOCK-----
Version: GnuPG v1.4.14 (GNU/Linux)

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
=iP9a
- -----END PGP PUBLIC KEY BLOCK-----
-----BEGIN PGP SIGNATURE-----
Version: GnuPG v1

iEYEARECAAYFAlOB3xkACgkQQVV2uqduC+3+UgCfYZiUtx7FDGdQDhdVP8MyRf0D
ANIAn2YHOQh4yv84u2Kuars1gC0j3Nr2
=Zu9F
-----END PGP SIGNATURE-----













