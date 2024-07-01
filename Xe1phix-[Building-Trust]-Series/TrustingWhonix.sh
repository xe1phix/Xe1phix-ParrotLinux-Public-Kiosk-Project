#!/bin/sh
## TrustingWhonix.sh








## --------------------------------------------------------------------------------------------------------------------------- ##
gpg --keyserver hkps://hkps.pool.sks-keyservers.net --recv-keys 0x916B8D99C38EAF5E8ADC7A2A8D66066A2EEACCDA
gpg --export 916B8D99C38EAF5E8ADC7A2A8D66066A2EEACCDA | sudo apt-key add -
## --------------------------------------------------------------------------------------------------------------------------- ##
gpg --sign-key 0x916B8D99C38EAF5E8ADC7A2A8D66066A2EEACCDA
gpg --fingerprint 0x916B8D99C38EAF5E8ADC7A2A8D66066A2EEACCDA
## =========================================================================================================================== ##

##        Key fingerprint = 916B 8D99 C38E AF5E 8ADC  7A2A 8D66 066A 2EEA CCDA
   Primary key fingerprint: 916B 8D99 C38E AF5E 8ADC  7A2A 8D66 066A 2EEA CCDA
 Primary key fingerprint: 916B 8D99 C38E AF5E 8ADC  7A2A 8D66 066A 2EEA CCDA
						  916B 8D99 C38E AF5E 8ADC 7A2A 8D66 066A 2EEA CCDA
 Primary key fingerprint: 916B 8D99 C38E AF5E 8ADC  7A2A 8D66 066A 2EEA CCDA


## =========================================================================================================================== ##
gpg --keyid-format 0xlong --verify Whonix-Gateway-13.0.0.1.4.libvirt.xz.asc Whonix-Gateway-13.0.0.1.4.libvirt.xz
## =========================================================================================================================== ##
gpg: Signature made Tue 20 Dec 2016 10:04:30 PM CST
gpg:                using RSA key 0xCB8D50BB77BB3C48
gpg: using subkey 0xCB8D50BB77BB3C48 instead of primary key 0x8D66066A2EEACCDA
gpg: using pgp trust model
gpg: Good signature from "Patrick Schleizer <adrelanos@riseup.net>" [full]
gpg: binary signature, digest algorithm SHA512, key algorithm rsa4096

## =========================================================================================================================== ##
gpg --keyid-format 0xlong --verify Whonix-Workstation-13.0.0.1.4.libvirt.xz.asc Whonix-Workstation-13.0.0.1.4.libvirt.xz
## =========================================================================================================================== ##
gpg: Signature made Tue 20 Dec 2016 10:42:01 PM CST
gpg:                using RSA key 0xCB8D50BB77BB3C48
gpg: using subkey 0xCB8D50BB77BB3C48 instead of primary key 0x8D66066A2EEACCDA
gpg: using pgp trust model
gpg: Good signature from "Patrick Schleizer <adrelanos@riseup.net>" [full]
gpg: binary signature, digest algorithm SHA512, key algorithm rsa4096



## =========================================================================================================================== ##
sha512sum Whonix-*-13.0.0.1.4.libvirt.xz
## =========================================================================================================================== ##
a44f55e5b233fb7b6dc997bdd42371d27ef37f1b0e1515a295c6233e6bdc8d9fb077230be5b3d89791aa780b4ee4f9963559a0a418b03975dea33afec578aeb3  Whonix-Gateway-13.0.0.1.4.libvirt.xz

## --------------------------------------------------------------------------------------------------------------------------- ##
c24ec40f4057469f7a09f4f1a6101ae70c77adbd91615d4a75affe18b391d3778137761e14e53e47e292b434eb417631dbc4708ab77ad8e21c60a8d741542aca  Whonix-Workstation-13.0.0.1.4.libvirt.xz

## --------------------------------------------------------------------------------------------------------------------------- ##

## =========================================================================================================================== ##
sha256sum Whonix-*-13.0.0.1.4.libvirt.xz
## =========================================================================================================================== ##
1da7425193eeabf22b8d417009f07f907261ef11939b6ac6840c5cf0f76a52d2  Whonix-Gateway-13.0.0.1.4.libvirt.xz

## --------------------------------------------------------------------------------------------------------------------------- ##
ae32c604c9992509a635323a99d9c724fc0ae55b4f9eb13d1cb2ea6a0b8b3eb3  Whonix-Workstation-13.0.0.1.4.libvirt.xz

## --------------------------------------------------------------------------------------------------------------------------- ##

