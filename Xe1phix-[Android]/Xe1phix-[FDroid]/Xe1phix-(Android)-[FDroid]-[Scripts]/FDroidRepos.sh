#!/bin/sh
## FDroidRepos.sh

F-Droid list of repositories

https://f-droid.org/wiki/page/Known_Repositories


https://f-droid.org/docs/Release_Channels_and_Signing_Keys/?title=Release_Channels_and_Signing_Keys





Guardian Project 	http://bdf2wcxujkg6qqff.onion/fdroid/repo (TOR hidden service) 

Guardian Project 	https://s3.amazonaws.com/guardianproject/fdroid/repo

Guardian Project 	https://guardianproject.info/fdroid/repo




F-Droid repository

https://guardianproject.info/home/signing-keys/

People signing official releases

http://pool.sks-keyservers.net/pks/lookup?op=vindex&search=0x9F0FE587374bbe81

    Hans-Christoph Steiner <hans@guardianproject.info>
    5E61 C878 0F86 295C E17D 8677 9F0F E587 374B BE81
    
    Nathan Freitas <nathan@guardianproject.info>
http://pool.sks-keyservers.net/pks/lookup?op=vindex&search=0xA801183E69B37AA9
    BBE2 0FD6 DA48 A3DD 4CC7 DF41 A801 183E 69B3 7AA9

    Abel Luck <abel@guardianproject.info>
http://pool.sks-keyservers.net/pks/lookup?op=vindex&search=0x97d05003da731a17
    1893 0780 A043 3A61 B8B2 17D6 97D0 5003 DA73 1A17

Keys from the build servers

    build@halfparanoid <root@guardianproject.info>
http://pool.sks-keyservers.net/pks/lookup?op=vindex&search=0x2A1E2A34308D1650
    6F57 3CDC 0E19 0E0F 4C0A B155 2A1E 2A34 308D 1650

    build@semiparanoid <root@guardianproject.info>
http://pool.sks-keyservers.net/pks/lookup?op=vindex&search=0x3C0966BA81079F68
    C85A 83E6 BE71 EA3C 8BA2 FB16 3C09 66BA 8107 9F68



Launchpad Ubuntu Package Archive (PPA)

For easy installation on Ubuntu/Mint/etc. of our official releases, as well as backported software that we use, we have an Launchpad PPA with its own signing key provided by Launchpad:

    Launchpad PPA for Guardian Project
http://pool.sks-keyservers.net/pks/lookup?op=vindex&search=0xF50EADDD2234F563
    6B80 A842 07B3 0AC9 DEE2 35FE F50E ADDD 2234 F563



Android APK

We currently have two signing keys: a 4096-bit RSA key used for all new apps, and a 1024-bit RSA key that we use for all apps that we first released before 2014. You can download the whole public keys and verify it using the OpenPGP signature:

4096-bit RSA

    guardianproject-rsa4096-signing-certificate.pem
https://guardianproject.info/releases/guardianproject-rsa4096-signing-certificate.pem

    guardianproject-rsa4096-signing-certificate.pem.sig
https://guardianproject.info/releases/guardianproject-rsa4096-signing-certificate.pem.sig

    guardianproject-rsa4096-signing-publickey.pem
https://guardianproject.info/releases/guardianproject-rsa4096-signing-publickey.pem

    guardianproject-rsa4096-signing-publickey.pem.sig
https://guardianproject.info/releases/guardianproject-rsa4096-signing-publickey.pem.sig


    You can see a survey of APKs signed by this key on Android Observatory:
    https://androidobservatory.org/cert/4CB3F539F63B32ACA13B4450638D605F531D4F4A

1024-bit RSA

    guardianproject-rsa1024-signing-key.cer
https://guardianproject.info/releases/guardianproject-rsa1024-signing-key.cer

    guardianproject-rsa1024-signing-key.cer.sig
https://guardianproject.info/releases/guardianproject-rsa1024-signing-key.cer.sig



    You can see a survey of APKs signed by this key on Android Observatory:
    https://androidobservatory.org/cert/9F1960C9584FEE5E166419354985A2B5FE413570




    guardianproject-rsa4096-fdroid-repo-signing-key.pem
https://guardianproject.info/releases/guardianproject-rsa4096-fdroid-repo-signing-key.pem

    guardianproject-rsa4096-fdroid-repo-signing-key.pem.sig
https://guardianproject.info/releases/guardianproject-rsa4096-fdroid-repo-signing-key.pem.sig





The fingerprints for this signing key are:

Owner: EMAILADDRESS=root@guardianproject.info, CN=guardianproject.info, O=Guardian Project, OU=FDroid Repo, L=New York, ST=New York, C=US
Issuer: EMAILADDRESS=root@guardianproject.info, CN=guardianproject.info, O=Guardian Project, OU=FDroid Repo, L=New York, ST=New York, C=US
Serial number: a397b4da7ecda034
Valid from: Thu Jun 26 15:39:18 EDT 2014 until: Sun Nov 10 14:39:18 EST 2041
Certificate fingerprints:
 MD5:  8C:BE:60:6F:D7:7E:0D:2D:B8:06:B5:B9:AD:82:F5:5D
 SHA1: 63:9F:F1:76:2B:3E:28:EC:CE:DB:9E:01:7D:93:21:BE:90:89:CD:AD
 SHA256: B7:C2:EE:FD:8D:AC:78:06:AF:67:DF:CD:92:EB:18:12:6B:C0:83:12:A7:F2:D6:F3:86:2E:46:01:3C:7A:61:35
 Signature algorithm name: SHA1withRSA
 Version: 1



https://github.com/guardianproject/fdroid-repo









microG F-Droid repo

https://microg.org/fdroid/repo

Fingerprint of the signing key (SHA-256)9B D0 67 27 E6 27 96 C0 13 0E B6 DA B3 9B 73 15 74 51 58 2C BD 13 8E 86 C4 68 AC C3 95 D1 41 65


microG F-Droid archive

https://microg.org/fdroid/archive

Fingerprint of the signing key (SHA-256)9B D0 67 27 E6 27 96 C0 13 0E B6 DA B3 9B 73 15 74 51 58 2C BD 13 8E 86 C4 68 AC C3 95 D1 41 65





I2P Official App Repository


https://f-droid.i2p.io/repo


verify the fingerprint (SHA-256) of the repository signing key, here it is:

68 E7 65 61 AA F3 F5 3D D5 3B A7 C0 3D 79 52 13 D0 CA 17 72 C3 FA C0 15 9B 50 A5 AA 85 C4 5D C6

https://f-droid.i2p.io/repo?fingerprint=68E76561AAF3F53DD53BA7C03D795213D0CA1772C3FAC0159B50A5AA85C45DC6



