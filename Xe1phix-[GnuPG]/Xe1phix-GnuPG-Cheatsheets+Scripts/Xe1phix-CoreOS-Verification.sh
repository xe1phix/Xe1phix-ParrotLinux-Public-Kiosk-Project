#!/bin/sh
## Xe1phix-CoreOS-Verification.sh
## ----------------------------------- ##
## Verify CoreOS images with GPG
## ----------------------------------- ##


[signing-key]: 
https://coreos.com/security/image-signing-key

[stable]: https://stable.release.core-os.net/amd64-usr/current/
[beta]: https://beta.release.core-os.net/amd64-usr/current/
[alpha]: https://alpha.release.core-os.net/amd64-usr/current/

After downloading your image, you should verify it with `gpg` tool. First, 
download the image signing key:


curl -O https://coreos.com/security/image-signing-key/CoreOS_Image_Signing_Key.asc


Next, import the public key and verify that the ID matches the website: 
[CoreOS Image Signing Key][signing-key]


gpg --import --keyid-format LONG CoreOS_Image_Signing_Key.asc
gpg: key 50E0885593D2DCB4: public key "CoreOS Buildbot (Offical Builds) <buildbot@coreos.com>" imported
gpg: Total number processed: 1
gpg:               imported: 1  (RSA: 1)
gpg: 3 marginal(s) needed, 1 complete(s) needed, PGP trust model
gpg: depth: 0  valid:   2  signed:   0  trust: 0-, 0q, 0n, 0m, 0f, 2u


Now were ready to download an image and its signature, ending in .sig. 
Were using the QEMU image in this example:


curl -O https://stable.release.core-os.net/amd64-usr/current/coreos_production_qemu_image.img.bz2
curl -O https://stable.release.core-os.net/amd64-usr/current/coreos_production_qemu_image.img.bz2.sig


Verify image with `gpg` tool:

gpg --verify coreos_production_qemu_image.img.bz2.sig
gpg: Signature made Tue Jun 23 09:39:04 2015 CEST using RSA key ID E5676EFC
gpg: Good signature from "CoreOS Buildbot (Offical Builds) <buildbot@coreos.com>



irc://irc.freenode.org:6667/#coreos
50E0885593D2DCB4
https://coreos.com/security/image-signing-key
https://coreos.com/security/image-signing-key/CoreOS_Image_Signing_Key.asc
https://coreos.com/security/app-signing-key/
https://coreos.com/dist/pubkeys/app-signing-pubkey.gpg
https://coreos.com/security/disclosure/coreos_security_key.asc



gpg --import --keyid-format LONG CoreOS_Image_Signing_Key.asc

curl -O https://stable.release.core-os.net/amd64-usr/current/coreos_production_qemu_image.img.bz2
curl -O https://stable.release.core-os.net/amd64-usr/current/coreos_production_qemu_image.img.bz2.sig

gpg --verify coreos_production_qemu_image.img.bz2.sig





50E0885593D2DCB4
50E0885593D2DCB4

 Primary key fingerprint: 0412 7D0B FABE C887 1FFB  2CCE 50E0 8855 93D2 DCB4
														 50E0 8855 93D2 DCB4

gpg --verify coreos_production_iso_image.iso.DIGESTS.asc coreos_production_iso_image.iso.DIGESTS && gpg --verify coreos_production_iso_image.iso.sig coreos_production_iso_image.iso


  
