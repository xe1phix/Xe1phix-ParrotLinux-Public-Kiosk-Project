#!/bin/sh
##-====================================================-##
##   [+]  Xe1phix-[SecureDrop]
##   [+]  SecureDrop Release Signing Key
##   [+]  Xe1phix-SecureDrop-GnuPG-Trusting-[SecureDrop].sh
##-====================================================-##



##-===============================================================-##
##   [+]  Import The (Depreciated) SecureDrop Release Signing Key  [expired]:
##-===============================================================-##
##  
## ---------------------------------------------------------------------------------------------------------------------------------------------------------------------- ##
gpg --keyserver hkps://keys.openpgp.org --recv-key 22245C81E3BAEB4138B36061310F561200F4AD77
gpg --keyserver hkps://hkps.pool.sks-keyservers.net --recv-keys 0x22245C81E3BAEB4138B36061310F561200F4AD77
## ---------------------------------------------------------------------------------------------------------------------------------------------------------------------- ##
gpg --fingerprint 22245C81E3BAEB4138B36061310F561200F4AD77
## ------------------------------------------------------------------------------------------------------------------------- ##
gpg --export 22245C81E3BAEB4138B36061310F561200F4AD77 | sudo apt-key add -
## ------------------------------------------------------------------------------------------------------------------------- ##
gpg --lsign-key 0x22245C81E3BAEB4138B36061310F561200F4AD77
gpg --fingerprint 0x22245C81E3BAEB4138B36061310F561200F4AD77
## ------------------------------------------------------------------------------------------------------------------------- ##
##  
## ------------------------------------------------------------------------------- ##
##    22245C81E3BAEB4138B36061310F561200F4AD77
## ------------------------------------------------------------------------------- ##
## ---------------------------------------------------------------------------------------------------------------------------------------------------------------------- ##
##  gpg: keyserver option 'ca-cert-file' is obsolete; please use 'hkp-cacert' in dirmngr.conf
##  gpg: keyserver option 'no-try-dns-srv' is unknown
##  pub   rsa4096/0x310F561200F4AD77 2016-10-20 [SC] [expired: 2021-06-30]
##        Key fingerprint = 2224 5C81 E3BA EB41 38B3  6061 310F 5612 00F4 AD77
##  uid                   [ expired] SecureDrop Release Signing Key <securedrop-release-key@freedom.press>
## ---------------------------------------------------------------------------------------------------------------------------------------------------------------------- ##




##-================================================-##
##   [+]  Import The Stable SecureDrop Release Signing Key:
##-================================================-##
##  
## ---------------------------------------------------------------------------------------------------------------------------------------------------------------------- ##
gpg --keyserver hkps://keys.openpgp.org --recv-key 2359E6538C0613E652955E6C188EDD3B7B22E6A3
gpg --keyserver hkps://hkps.pool.sks-keyservers.net --recv-keys 0x2359E6538C0613E652955E6C188EDD3B7B22E6A3
## ---------------------------------------------------------------------------------------------------------------------------------------------------------------------- ##
gpg --fingerprint 0x2359E6538C0613E652955E6C188EDD3B7B22E6A3
## ------------------------------------------------------------------------------------------------------------------------- ##
gpg --export 2359E6538C0613E652955E6C188EDD3B7B22E6A3 | sudo apt-key add -
## ------------------------------------------------------------------------------------------------------------------------- ##
gpg --lsign-key 0x2359E6538C0613E652955E6C188EDD3B7B22E6A3
gpg --fingerprint 0x2359E6538C0613E652955E6C188EDD3B7B22E6A3
## ------------------------------------------------------------------------------------------------------------------------- ##
##  
## ------------------------------------------------------------------------------- ##
##    2359E6538C0613E652955E6C188EDD3B7B22E6A3
## ------------------------------------------------------------------------------- ##
## ---------------------------------------------------------------------------------------------------------------------------------------------------------------------- ##
##  pub   rsa4096/0x188EDD3B7B22E6A3 2021-05-10 [SC] [expires: 2022-07-04]
##        Key fingerprint = 2359 E653 8C06 13E6 5295  5E6C 188E DD3B 7B22 E6A3
##  uid                   [ unknown] SecureDrop Release Signing Key <securedrop-release-key-2021@freedom.press>
##  sub   rsa4096/0x6275A4BA4C71447A 2021-05-10 [E] [expires: 2022-07-04]
##        Key fingerprint = 427C 6B13 9395 903B E9A2  52C6 6275 A4BA 4C71 447A
## ---------------------------------------------------------------------------------------------------------------------------------------------------------------------- ##




## ---------------------------------------------------------------------------------------------------------------- ##
##   [?] All future SecureDrop release artifacts will be signed with the new key: 
## ---------------------------------------------------------------------------------------------------------------- ##
2359E6538C0613E652955E6C188EDD3B7B22E6A3




## --------------------------------------------------------------------------------------------- ##
##   [?] SecureDrop release signing key (not for communication)
## --------------------------------------------------------------------------------------------- ##
2359 E653 8C06 13E6 5295 5E6C 188E DD3B 7B22 E6A3


## ------------------------------------------------------------------------------------------------------------------------------------------------------ ##
##  gpg: Signature made Mon 10 May 2021 10:46:35 AM PDT
##  gpg: using RSA key 22245C81E3BAEB4138B36061310F561200F4AD77
##  gpg: Good signature from "SecureDrop Release Signing Key" [unknown]
##  gpg: aka "SecureDrop Release Signing Key <securedrop-release-key@freedom.press>" [unknown]
##  gpg: WARNING: This key is not certified with a trusted signature!
##  gpg: There is no indication that the signature belongs to the owner.
##  Primary key fingerprint: 2224 5C81 E3BA EB41 38B3 6061 310F 5612 00F4 AD77
## ------------------------------------------------------------------------------------------------------------------------------------------------------ ##


## -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ##
##  gpg: Signature made Mon 10 May 2021 10:46:35 AM PDT
##  gpg: using RSA key 2359E6538C0613E652955E6C188EDD3B7B22E6A3
##  gpg: Good signature from "SecureDrop Release Signing Key <securedrop-release-key-2021@freedom.press>" [unknown]
##  gpg: WARNING: This key is not certified with a trusted signature!
##  gpg: There is no indication that the signature belongs to the owner.
##  Primary key fingerprint: 2359 E653 8C06 13E6 5295 5E6C 188E DD3B 7B22 E6A3
## -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ##


## ----------------------------------------------------------------- ##
##   [?] SecureDrop Depreciated Signing key:
## ----------------------------------------------------------------- ##
##
## ------------------------------------------------------------------------------------------------------------------------------------------------------------ ##
##  pub   rsa4096/0x310F561200F4AD77 2016-10-20 [SC] [expires: 2021-06-30]
##        Key fingerprint = 2224 5C81 E3BA EB41 38B3  6061 310F 5612 00F4 AD77
##  uid                   [ultimate] SecureDrop Release Signing Key
##  uid                   [ultimate] SecureDrop Release Signing Key <securedrop-release-key@freedom.press>
## ------------------------------------------------------------------------------------------------------------------------------------------------------------ ##


## -------------------------------------------------------- ##
##   [?] SecureDrop Stable Signing key:
## -------------------------------------------------------- ##
##  
## ------------------------------------------------------------------------------------------------------------------------------------------------------------ ##
##  pub   rsa4096/0x188EDD3B7B22E6A3 2021-05-10 [SC] [expires: 2022-07-04]
##        Key fingerprint = 2359 E653 8C06 13E6 5295  5E6C 188E DD3B 7B22 E6A3
##  uid                   [ultimate] SecureDrop Release Signing Key <securedrop-release-key-2021@freedom.press>
##  sub   rsa4096/0x6275A4BA4C71447A 2021-05-10 [E] [expires: 2022-07-04]
## ------------------------------------------------------------------------------------------------------------------------------------------------------------ ##




-----BEGIN PGP SIGNATURE-----

iQIzBAEBCgAdFiEEIiRcgeO660E4s2BhMQ9WEgD0rXcFAmCZcXsACgkQMQ9WEgD0
rXcmUw//bChK0GP2NkPuBzuUieFKIIRLo6mFqx/RdzYcaSkswSGdiDPZ4IPH0rPd
qo3IBUsfL12Ln565lHhig9tEwzahQjEPfWorJBPtzjbVDKC15J6tB1Qkp6Tx95ZI
oO8cevtyLxQb10bqlVG0J88bE8HF6pboGSGD06uFcOPUb/DHDRM/V2mJRvjRD8bW
TW9Q9J+24fgQT18kagYtvFEYXkkJfTscXO3xWSzt5UGa1L/VKLHTggfwZ5qmf0hV
6QN2Vr9T5+BEhJ6GCDZBdGrixM6s3d7glE5s37/9J6Y0Hw1qbCv0A/EdCfVldeEO
o/AbOXnwABjniRdbQ7Qj/4Hs4uvGPbDNrVp5/lMKMRwUbrFuOeo9fviCuGx+u0fH
hEVUWaa14uhcAC2olIMRiHOOtbxWsv9SSzd5Tsk64ZUMTCb0JmGSjwiDtsw4nuaE
T+c9hl/QhAjK53ROizCTY0GjLZxpJroqhAJ9FjTNibi01XYrDq8NqJpL6KCbCYef
63rscGTEFB1vsMSvfmmZ04ev22v22P4QdghgcGnK1xq+DfsrnTEE7TyURwYvVnWV
0mqdaMhnZ/oVpvSszQEYI+TJynmmLnwWaNSAk//YDpk8u6y7EoNznC0zRI7m9rX8
LyhI4lvhRy2Cp3a1r5OQOpAJ3sCarOzZ67LuWydA4ebaYpwaUEOJAjMEAQEKAB0W
IQQjWeZTjAYT5lKVXmwYjt07eyLmowUCYJlxewAKCRAYjt07eyLmozacD/9dyRer
hMcNiQmKFEzNIIJulaz+GKvGTMN42S8cFPH7wVPcgsn3grvBV6ZWMHPKSUrw2H8e
h9QG85DiL4K/k+fIHUOBr3hV0mrNcPpZtgquiFqH3xLD5Kdgx4qIKgMQ8aoMsIke
LIJJWtcLyeiD/9TQlU0R/kcyndIqSkYnEOCk6w+PzjkXR7zdYOFyVEGBSW4MGvJW
TJD+sxdbVr8nJ4W2SHo1XBNYNpyd7mbh1wY8edY8s9xyggyfWtTOZg5VKku5haIZ
WTxEpPJ6jdImLfmaG30r74mLUW3ggnLJEQ0Lvhuo72b5AZ1pkH9++UVAA4dVT7Qp
PRtPwsGwYayXKzBA2LL8sCNWYSoIl5dsk1FNoNe5Dz7YqTLgV22BJojii/A976hA
tiluDLOPceJjcQI06IIeoditByYax9nbim97l+dtTncDGugz+gj37c5c49sZeOFX
+Y3dB1nElJ+1iQuqoPmU6maGIknjiKzineGV8tp+Jr4eNgLzjruxpp36MwMSyTDB
In8x8JZSB89qvmXEwvQvVpKwhgp+LOZOIxKsbiuf+tbrkGPJhDVHCgU2yWxu9c49
GcTofKLpE5JO8NBi5oquH6xTdoH9qO4EDTeuMlNFB3uXGTk2XMsmo1uFJTe5qyej
TApZUcXI8KFjTdQF8QjctaKHNeTvuhYQKFXjYw==
=h5TY
-----END PGP SIGNATURE-----



https://media.securedrop.org/media/documents/signing-key-transition.txt



SecureDrop Release Signing Key  [ Key ID: 0x188EDD3B7B22E6A3 ]


-----BEGIN PGP PUBLIC KEY BLOCK-----

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
u3U=
=pCIa
-----END PGP PUBLIC KEY BLOCK-----

