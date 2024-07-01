#!/bin/sh
## -------------------------------------------------------------------------------------------------------- ##
##  [+] Xe1phix-[GnuPG]-Trusting-[Linux-Kernel]-[Greg-Kroah-Hartman]-Signing-Key-Cheatsheet-[8.5.24].sh
## -------------------------------------------------------------------------------------------------------- ##


echo "## ============================================================================================================= ##"
echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "## 				>> Greg Kroah-Hartman (Linux Kernel Stable Release Signing Key) <greg@kroah.com>"
echo "##                                 (Linus no longer signs kernel releases)"
echo "##-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-##"
echo "## ============================================================================================================= ##"


echo "## =================================================================================== ##"
echo "## 		Fetch Greg Kroah-Hartman (Linux Kernel Stable Release Signing Key):"
echo "## =================================================================================== ##"
gpg --keyserver hkps://pool.sks-keyservers.net --recv-keys 0x647F28654894E3BD457199BE38DBBDC86092693E
gpg --keyserver hkp://keys.gnupg.net --recv-keys 0x647F28654894E3BD457199BE38DBBDC86092693E


echo "## =========================================================================================== ##"
echo "## Greg Kroah-Hartman (Linux Kernel Stable Release Signing Key) GPG Fingerprint (Verified):"
echo "## =========================================================================================== ##"
echo "## ----------------------------------------------------------------------------------------------------------- ##"
echo "##       Key fingerprint = 647F 2865 4894 E3BD 4571  99BE 38DB BDC8 6092 693E									 ##"
echo "## ----------------------------------------------------------------------------------------------------------- ##"
     647F 2865 4894 E3BD 4571  99BE 38DB BDC8 6092 693E
    647F 2865 4894 E3BD 4571  99BE 38DB BDC8 6092 693E		
echo "## =========================================================================================== ##"
echo "## Concatenate Greg Kroah-Hartman (Linux Kernel Stable Release Signing Key) GPG Fingerprint:"
echo "## =========================================================================================== ##"
gpg --fingerprint 0x647F28654894E3BD457199BE38DBBDC86092693E


echo "## =========================================================================================== ##"
echo "## 	Sign Greg Kroah-Hartman (Linux Kernel Stable Release Signing Key) GPG Signing Key:"
echo "## =========================================================================================== ##"
gpg --lsign 0x647F28654894E3BD457199BE38DBBDC86092693E


echo "## =========================================================================================== ##"
echo "## 	Export Greg Kroah-Hartman (Linux Kernel Stable Release Signing Key):"
echo "## =========================================================================================== ##"
gpg --export 647F28654894E3BD457199BE38DBBDC86092693E | sudo apt-key add -



echo "## ################################################################################## ##"
echo "## ================================================================================== ##"
echo "				Alternative Way To Sign Greg Kroah-Hartmans GPG Key:"
echo "## ================================================================================== ##"
echo "## ################################################################################## ##"


echo "## ================================================================================== ##"
echo "			Edit Greg Kroah-Hartmans (Linux Kernel Stable Release Signing Key):"
echo "## ================================================================================== ##"
gpg --edit-key 0x38DBBDC86092693E



echo "## ================================================================================== ##"
echo "			Sign Greg Kroah-Hartmans (Linux Kernel Stable Release Signing Key):"
echo "## ================================================================================== ##"
echo "	 gpg> fpr"
echo "## ----------------------------------------------------------------------------------------------------------------------- ##"
echo "pub   rsa4096/38DBBDC86092693E 2011-09-23 Greg Kroah-Hartman (Linux kernel stable release signing key) <greg@kroah.com>"
echo " Primary key fingerprint: 647F 2865 4894 E3BD 4571  99BE 38DB BDC8 6092 693E"
echo "## ----------------------------------------------------------------------------------------------------------------------- ##"
echo "	 gpg> lsign"
echo "	 gpg> save"
echo "## ================================================================================== ##"



curl -OL https://www.kernel.org/pub/linux/kernel/v4.x/linux-4.6.6.tar.xz
curl -OL https://www.kernel.org/pub/linux/kernel/v4.x/linux-4.6.6.tar.sign


xz -cd linux-4.6.6.tar.xz | gpg2 --verify linux-4.6.6.tar.sign -



gpg --tofu-policy good 38DBBDC86092693E
gpg --trust-model tofu --verify linux-4.6.6.tar.sign

gpg: Signature made Wed 10 Aug 2016 06:55:15 AM EDT
gpg:                using RSA key 38DBBDC86092693E
gpg: Good signature from "Greg Kroah-Hartman <gregkh@kernel.org>" [full]
gpg: gregkh@kernel.org: Verified 1 signature in the past 53 seconds.  Encrypted
     0 messages.



