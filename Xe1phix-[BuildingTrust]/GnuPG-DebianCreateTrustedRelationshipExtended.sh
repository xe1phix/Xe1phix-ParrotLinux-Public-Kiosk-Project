#!/bin/sh



GPG_TTY=$(tty)
export GPG_TTY

USER=$(whoami)
export USER=$(whoami)

export GNUPGHOME=/home/$USER/.gnupg/








echo "## ==================================================================================================== ##"
## ---------------------------------------------------------------------------------------------------- ##
echo "               Check The Available Entropy (Determined By the Kernel)"
echo "                    Concatenate Entropy Availability from /proc:"
## ---------------------------------------------------------------------------------------------------- ##
echo "## ==================================================================================================== ##"
cat /proc/sys/kernel/random/entropy_avail




echo "## ==================================================================================================== ##"
echo "## ------------------ [?] For Debian DvD Signing Keys Refer To: --------------------------------------- ##" 
echo "## --------------------- [x] https://www.debian.org/CD/verify ----------------------------------------- ##"
echo "## ==================================================================================================== ##"





## ==================================================================================================== ##
## ---------------------------------------------------------------------------------------------------- ##
echo "Fetch The Debian Testing CDs Automatic Signing Key"
##\____________________________________________________________________________________________________/##
gpg --keyserver pool.sks-keyservers.net --recv-keys 0xF41D30342F3546695F65C66942468F4009EA8AC3
## ---------------------------------------------------------------------------------------------------- ##
echo "Fetch The Debian CD signing key"
##\____________________________________________________________________________________________________/##		## gpg --keyserver pool.sks-keyservers.net --recv-keys 0x
gpg --keyserver pool.sks-keyservers.net --recv-keys 0xDF9B9C49EAA9298432589D76DA87E80D6294BE9B
## ---------------------------------------------------------------------------------------------------- ##
echo "Fetch The Debian CD signing key"
##\____________________________________________________________________________________________________/##
gpg --keyserver pool.sks-keyservers.net --recv-keys 0x10460DAD76165AD81FBC0CE9988021A964E6EA7D
## ---------------------------------------------------------------------------------------------------- ##
## ==================================================================================================== ##


## ==================================================================================================== ##
## ---------------------------------------------------------------------------------------------------- ##
echo "List Fingerprints of The Debian CD signing key"
##\____________________________________________________________________________________________________/##
gpg --keyid-format 0xlong --fingerprint 0x10460DAD76165AD81FBC0CE9988021A964E6EA7D
## ---------------------------------------------------------------------------------------------------- ##
echo "List Fingerprints of The Debian CD signing key"
##\____________________________________________________________________________________________________/##		## gpg --keyid-format 0xlong --fingerprint 0x
gpg --keyid-format 0xlong --fingerprint 0xDF9B9C49EAA9298432589D76DA87E80D6294BE9B
## ---------------------------------------------------------------------------------------------------- ##
echo "List Fingerprints of The Debian Testing CDs Automatic Signing Key"
##\____________________________________________________________________________________________________/##
gpg --keyid-format 0xlong --fingerprint 0xF41D30342F3546695F65C66942468F4009EA8AC3
## ---------------------------------------------------------------------------------------------------- ##
## ==================================================================================================== ##









## ==================================================================================================== ##
## ---------------------------------------------------------------------------------------------------- ##
echo "Sign The Debian CD signing key"
##\____________________________________________________________________________________________________/##
gpg --lsign-key 0x10460DAD76165AD81FBC0CE9988021A964E6EA7D
## ---------------------------------------------------------------------------------------------------- ##
echo "Sign The Debian CD signing key"
##\____________________________________________________________________________________________________/##			## gpg --lsign-key 0x
gpg --lsign-key 0xDF9B9C49EAA9298432589D76DA87E80D6294BE9B
## ---------------------------------------------------------------------------------------------------- ##
echo "Sign The Debian Testing CDs Automatic Signing Key"
##\____________________________________________________________________________________________________/##
gpg --lsign-key 0xF41D30342F3546695F65C66942468F4009EA8AC3
## ---------------------------------------------------------------------------------------------------- ##
## ==================================================================================================== ##


echo "## ==================================================================================================== ##"
echo "## ---------------------------------------------------------------------------------------------------- ##"
echo "## [?] You Can Find All of The Debian Signing Keys Here [?]:" 
echo "##    [x] https://ftp-master.debian.org/keys.html "
echo "## ---------------------------------------------------------------------------------------------------- ##"
echo "## ==================================================================================================== ##"





Debian Archive Automatic Signing Key

## ==================================================================================================== ##
## ---------------------------------------------------------------------------------------------------- ##
echo "Fetching The Debian 6 (Squeeze) Stable Release Signing Key..."
##\____________________________________________________________________________________________________/##
gpg --keyserver pool.sks-keyservers.net --recv-keys 0x0E4EDE2C7F3E1FC0D033800E64481591B98321F9
## ---------------------------------------------------------------------------------------------------- ##
echo "Fetching The Debian 6 (Squeeze) Archive Automatic Signing Key..."
##\____________________________________________________________________________________________________/##
gpg --keyserver pool.sks-keyservers.net --recv-keys 0x9FED2BCBDCD29CDF762678CBAED4B06F473041FA
## ---------------------------------------------------------------------------------------------------- ##
## ==================================================================================================== ##
## ---------------------------------------------------------------------------------------------------- ##
echo "Fetching The Wheezy Stable Release Signing Key..."
##\____________________________________________________________________________________________________/##
gpg --keyserver pool.sks-keyservers.net --recv-keys 0xED6D65271AACF0FF15D123036FB2A1C265FFB764
## ---------------------------------------------------------------------------------------------------- ##
echo "Fetching The Debian 7 (Wheezy) Archive Automatic Signing Key..."
##\____________________________________________________________________________________________________/##
gpg --keyserver pool.sks-keyservers.net --recv-keys 0xA1BD8E9D78F7FE5C3E65D8AF8B48AD6246925553
## ---------------------------------------------------------------------------------------------------- ##

## ---------------------------------------------------------------------------------------------------- ##
## ==================================================================================================== ##
## ---------------------------------------------------------------------------------------------------- ##
echo "Fetching The Debian 8 (Jessie) Archive Signing Key..."
##\____________________________________________________________________________________________________/##
gpg --keyserver pool.sks-keyservers.net --recv-keys 0x126C0D24BD8A2942CC7DF8AC7638D0442B90D010
## ---------------------------------------------------------------------------------------------------- ##
echo "Fetching The Debian 8 (Jessie) Security Archive Signing Key..."
##\____________________________________________________________________________________________________/##
gpg --keyserver pool.sks-keyservers.net --recv-keys 0xD21169141CECD440F2EB8DDA9D6D8F6BC857C906
## ---------------------------------------------------------------------------------------------------- ##

echo "Fetching The Debian 8 (Jessie) Stable Release Key..."
##\____________________________________________________________________________________________________/##
gpg --keyserver pool.sks-keyservers.net --recv-keys 0x75DDC3C4A499F1A18CB5F3C8CBF8D6FD518E17E1
## ---------------------------------------------------------------------------------------------------- ##



## ---------------------------------------------------------------------------------------------------- ##
## ==================================================================================================== ##
## ---------------------------------------------------------------------------------------------------- ##
echo "Fetching The Debian 9 (Stretch) Archive Signing Key..."
##\____________________________________________________________________________________________________/##
gpg --keyserver pool.sks-keyservers.net --recv-keys 0xE1CF20DDFFE4B89E802658F1E0B11894F66AEC98
## ---------------------------------------------------------------------------------------------------- ##
echo "Fetching The Debian 9 (Stretch) Security Archive Signing Key..."
##\____________________________________________________________________________________________________/##
gpg --keyserver pool.sks-keyservers.net --recv-keys 0x6ED6F5CB5FA6FB2F460AE88EEDA0D2388AE22BA9


echo "Fetching The Debian 9 (Stretch) Stable Release Key..."
##\____________________________________________________________________________________________________/##
gpg --keyserver pool.sks-keyservers.net --recv-keys 0x067E3C456BAE240ACEE88F6FEF0F382A1A7B6500



## ---------------------------------------------------------------------------------------------------- ##
## ==================================================================================================== ##


## ---------------------------------------------------------------------------------------------------- ##
echo "Fetching The Debian Ports Archive Automatic Signing Key..."
##\____________________________________________________________________________________________________/##
gpg --keyserver pool.sks-keyservers.net --recv-keys 0x4B7BD4FCD488B9E56CA575738BC3A7D46F930576





## ---------------------------------------------------------------------------------------------------- ##
echo "Fetching The Debian Mozilla Team APT Archive Signing Key..."
##\____________________________________________________________________________________________________/##
gpg --keyserver pool.sks-keyservers.net --recv-keys 0x85F06FBC75E067C3F305C3C985A3D26506C4AE2A





echo "## ==================================================================================================== ##"
echo "## ------------- Make A Directory For .{asc|gpg|sign|key|sig} Files To Be Dropped Into ---------------- ##"
echo "## ==================================================================================================== ##"


mkdir ~/GnuPG



## ====================================================================================================================================================================== ##
## ---------------------------------------------------------------------------------------------------------------------------------------------------------------------- ##
echo "Downloading The - Squeeze - Stable Release - GPG Signature File..."
##\______________________________________________________________________________________________________________________________________________________________________/##
curl --verbose --progress-bar --tlsv1.2 --ssl-reqd --url https://ftp-master.debian.org/keys/archive-key-6.0.asc --output ~/GnuPG/archive-key-6.0.asc
## ---------------------------------------------------------------------------------------------------------------------------------------------------------------------- ##
echo "Downloading The - Wheezy - Stable Release GPG Signature File..."
##\______________________________________________________________________________________________________________________________________________________________________/##
curl --verbose --progress-bar --tlsv1.2 --ssl-reqd --url https://ftp-master.debian.org/keys/archive-key-7.0.asc --output ~/GnuPG/archive-key-7.0.asc
## ---------------------------------------------------------------------------------------------------------------------------------------------------------------------- ##
echo "Downloading The - Debian 8 (Jessie) - Archive GPG Signature File..."
##\______________________________________________________________________________________________________________________________________________________________________/##
curl --verbose --progress-bar --tlsv1.2 --ssl-reqd --url https://ftp-master.debian.org/keys/archive-key-8.asc --output ~/GnuPG/archive-key-8.asc
## ---------------------------------------------------------------------------------------------------------------------------------------------------------------------- ##
echo "Downloading The - Debian 8 (Jessie) - Security Archive GPG Signature File..."
##\______________________________________________________________________________________________________________________________________________________________________/##
curl --verbose --progress-bar --tlsv1.2 --ssl-reqd --url https://ftp-master.debian.org/keys/archive-key-8-security.asc --output ~/GnuPG/archive-key-8-security.asc
## ---------------------------------------------------------------------------------------------------------------------------------------------------------------------- ##
echo "Downloading The - Debian 9 (Stretch) - Archive GPG Signature File..."
##\______________________________________________________________________________________________________________________________________________________________________/##
curl --verbose --progress-bar --tlsv1.2 --ssl-reqd --url https://ftp-master.debian.org/keys/archive-key-9.asc --output ~/GnuPG/archive-key-9.asc
## ---------------------------------------------------------------------------------------------------------------------------------------------------------------------- ##
echo "Downloading The - Debian 9 (Stretch) - Security Archive GPG Key File..."
##\______________________________________________________________________________________________________________________________________________________________________/##
curl --verbose --progress-bar --tlsv1.2 --ssl-reqd --url https://ftp-master.debian.org/keys/archive-key-9-security.asc --output ~/GnuPG/archive-key-9-security.asc
## ---------------------------------------------------------------------------------------------------------------------------------------------------------------------- ##
## ====================================================================================================================================================================== ##



echo "## ==================================================================================================== ##"
echo "## ----------------- Import Every Signing Key In The /home/$USER/GnuPG/ Directory --------------------- ##"
echo "## ==================================================================================================== ##"
gpg --keyid-format 0xlong --import GnuPG/*/*

gpg --keyid-format 0xlong --import Debian/*



## ==================================================================================================== ##
## ---------------------------------------------------------------------------------------------------- ##
echo "Printing The Debian 7 (Wheezy) Archive Automatic Signing Keys Fingerprint..."
##\____________________________________________________________________________________________________/##
gpg --keyid-format 0xlong --fingerprint 0xA1BD8E9D78F7FE5C3E65D8AF8B48AD6246925553
## ---------------------------------------------------------------------------------------------------- ##
echo "Printing The Debian 8 (Jessie) Archive Signing Keys Fingerprint..."
##\____________________________________________________________________________________________________/##
gpg --keyid-format 0xlong --fingerprint 0x126C0D24BD8A2942CC7DF8AC7638D0442B90D010
## ---------------------------------------------------------------------------------------------------- ##
echo "Printing The Debian 8 (Jessie) Security Archive Signing Keys Fingerprint..."
##\____________________________________________________________________________________________________/##
gpg --keyid-format 0xlong --fingerprint 0xD21169141CECD440F2EB8DDA9D6D8F6BC857C906
## ---------------------------------------------------------------------------------------------------- ##
echo "Printing The Debian 9 (Stretch) Archive Signing Keys Fingerprint..."
##\____________________________________________________________________________________________________/##				## gpg --keyid-format 0xlong --fingerprint 0x
gpg --keyid-format 0xlong --fingerprint 0xE1CF20DDFFE4B89E802658F1E0B11894F66AEC98
## ---------------------------------------------------------------------------------------------------- ##
echo "Printing The Debian 9 (Stretch) Security Archive Signing Keys Fingerprint..."
##\____________________________________________________________________________________________________/##
gpg --keyid-format 0xlong --fingerprint 0x6ED6F5CB5FA6FB2F460AE88EEDA0D2388AE22BA9
## ---------------------------------------------------------------------------------------------------- ##
echo "Printing The Wheezy Stable Release Signing Keys Fingerprint..."
##\____________________________________________________________________________________________________/##
gpg --keyid-format 0xlong --fingerprint 0xED6D65271AACF0FF15D123036FB2A1C265FFB764
## ---------------------------------------------------------------------------------------------------- ##
echo "Printing The Squeeze Stable Release Signing Keys Fingerprint..."
##\____________________________________________________________________________________________________/##
gpg --keyid-format 0xlong --fingerprint 0x0E4EDE2C7F3E1FC0D033800E64481591B98321F9
## ---------------------------------------------------------------------------------------------------- ##
## ==================================================================================================== ##



Debian 8 (Jessie) Security Archive Signing Keys Fingerprint
Primary key fingerprint: D211 6914 1CEC D440 F2EB  8DDA 9D6D 8F6B C857 C906
						 D211 6914 1CEC D440 F2EB  8DDA 9D6D 8F6B C857 C906


Debian 8 (Jessie) Archive Signing Key
      Key fingerprint = 126C 0D24 BD8A 2942 CC7D  F8AC 7638 D044 2B90 D010
						126C 0D24 BD8A 2942 CC7D  F8AC 7638 D044 2B90 D010

The Debian 9 (Stretch) Archive Signing Keys Fingerprint



echo "## ==================================================================================================== ##"
echo "## -------------- For A Very Verbose Result, Examine GPG Keys Using These Commands: ------------------- ##"
echo "## ==================================================================================================== ##"
echo "$ gpg --keyid-format 0xlong --with-keygrip --with-key-data --list-key 0x | grep fpr | cut -c13-52"
echo "$ gpg --with-fingerprint --with-colons --list-key 0x"
echo "$ gpg --keyid-format 0xlong --with-key-data --fingerprint 0x && gpg --keyid-format 0xlong --with-colons --fingerprint 0x && gpg --keyid-format 0xlong --fingerprint 0x"




## ==================================================================================================== ##
## ---------------------------------------------------------------------------------------------------- ##
echo "Signing The [+] Squeeze [+] Stable Release Signing Keys..."
##\____________________________________________________________________________________________________/##
gpg --lsign-key 0x0E4EDE2C7F3E1FC0D033800E64481591B98321F9
## ---------------------------------------------------------------------------------------------------- ##
echo "Signing The [+] Wheezy [+] Stable Release Signing Keys..."
##\____________________________________________________________________________________________________/##
gpg --lsign-key 0xED6D65271AACF0FF15D123036FB2A1C265FFB764
## ---------------------------------------------------------------------------------------------------- ##
echo "Signing The [+] Debian 7: Wheezy [+] Archive Automatic Signing Keys..."
##\____________________________________________________________________________________________________/##
gpg --lsign-key 0xA1BD8E9D78F7FE5C3E65D8AF8B48AD6246925553
## ---------------------------------------------------------------------------------------------------- ##			## gpg --lsign-key 0x
echo "Signing The [+] Debian 8: Jessie [+] Archive Signing Keys..."
##\____________________________________________________________________________________________________/##
gpg --lsign-key 0x126C0D24BD8A2942CC7DF8AC7638D0442B90D010
## ---------------------------------------------------------------------------------------------------- ##
echo "Signing The [+] Debian 8: Jessie [+] Security Archive Signing Keys..."
##\____________________________________________________________________________________________________/##
gpg --lsign-key 0xD21169141CECD440F2EB8DDA9D6D8F6BC857C906
## ---------------------------------------------------------------------------------------------------- ##
echo "Signing The [+] Debian 9: Stretch [+] Archive Signing Keys..."
##\____________________________________________________________________________________________________/##
gpg --lsign-key 0xE1CF20DDFFE4B89E802658F1E0B11894F66AEC98
## ---------------------------------------------------------------------------------------------------- ##
echo "Signing The [+] Debian 9: Stretch [+] Security Archive Signing Keys..."
##\____________________________________________________________________________________________________/##
gpg --lsign-key 0x6ED6F5CB5FA6FB2F460AE88EEDA0D2388AE22BA9
## ---------------------------------------------------------------------------------------------------- ##
## ==================================================================================================== ##


 Primary key fingerprint: 6ED6 F5CB 5FA6 FB2F 460A  E88E EDA0 D238 8AE2 2BA9

 Primary key fingerprint: E1CF 20DD FFE4 B89E 8026  58F1 E0B1 1894 F66A EC98

 Primary key fingerprint: D211 6914 1CEC D440 F2EB  8DDA 9D6D 8F6B C857 C906

 Primary key fingerprint: 126C 0D24 BD8A 2942 CC7D  F8AC 7638 D044 2B90 D010

 Primary key fingerprint: A1BD 8E9D 78F7 FE5C 3E65  D8AF 8B48 AD62 4692 5553

 Primary key fingerprint: ED6D 6527 1AAC F0FF 15D1  2303 6FB2 A1C2 65FF B764

 Primary key fingerprint: 0E4E DE2C 7F3E 1FC0 D033  800E 6448 1591 B983 21F9



## ==================================================================================================== ##
## ---------------------------------------------------------------------------------------------------- ##
echo "Exporting [+] Squeeze [+] Stable Release Signing Keys --> Into Apt-Key..."
##\____________________________________________________________________________________________________/##
gpg --export 0x0E4EDE2C7F3E1FC0D033800E64481591B98321F9 | sudo apt-key add -
## ---------------------------------------------------------------------------------------------------- ##
echo "Exporting [+] Wheezy [+] Stable Release Signing Keys --> Into Apt-Key..."
##\____________________________________________________________________________________________________/##
gpg --export 0xED6D65271AACF0FF15D123036FB2A1C265FFB764 | sudo apt-key add -
## ---------------------------------------------------------------------------------------------------- ##
echo "Exporting [+] Debian 7: Wheezy [+] Archive Automatic Signing Keys --> Into Apt-Key..."
##\____________________________________________________________________________________________________/##
gpg --export 0xA1BD8E9D78F7FE5C3E65D8AF8B48AD6246925553 | sudo apt-key add -
## ---------------------------------------------------------------------------------------------------- ##
echo "Exporting [+] Debian 8: Jessie [+] Archive Signing Keys --> Into Apt-Key..."
##\____________________________________________________________________________________________________/##					## gpg --export  | sudo apt-key add -
gpg --export 0x126C0D24BD8A2942CC7DF8AC7638D0442B90D010 | sudo apt-key add -
## ---------------------------------------------------------------------------------------------------- ##
echo "Exporting [+] Debian 8: Jessie [+] Security Archive Signing Keys --> Into Apt-Key..."
##\____________________________________________________________________________________________________/##
gpg --export 0xD21169141CECD440F2EB8DDA9D6D8F6BC857C906 | sudo apt-key add -
## ---------------------------------------------------------------------------------------------------- ##
echo "Exporting [+] Debian 9: Stretch [+] Archive Signing Keys --> Into Apt-Key..."
##\____________________________________________________________________________________________________/##
gpg --export 0xE1CF20DDFFE4B89E802658F1E0B11894F66AEC98 | sudo apt-key add -
## ---------------------------------------------------------------------------------------------------- ##
echo "Exporting [+] Debian 9: Stretch [+] Security Archive Signing Keys --> Into Apt-Key..."
##\____________________________________________________________________________________________________/##
gpg --export 0x6ED6F5CB5FA6FB2F460AE88EEDA0D2388AE22BA9 | sudo apt-key add -
## ---------------------------------------------------------------------------------------------------- ##
## ==================================================================================================== ##





## gpg --keyring /usr/share/keyrings/debian-role-keys.gpg --verify SHA512SUMS.sign SHA512SUMS

## openssl dgst -sha256 
## openssl dgst -sha512 
## gpg --keyid-format 0xlong --verify 

## gpg --verify SHA1SUMS.sign SHA1SUMS
## gpg --verify SHA256SUMS.sign SHA256SUMS
## gpg --verify SHA512SUMS.sign SHA512SUMS

## sha256sum -c SHA256SUMS 2>&1 | grep OK



## gpg --clearsign -o InRelease Release
## gpg -abs -o Release.gpg Release






## apt-key --keyring /etc/apt/trusted.gpg
## apt-key --keyring /etc/apt/trustdb.gpg
## apt-key exportall
## apt-key update
## gpg --refresh-keys
## gpg --update-trustdb



## gpg --keyserver pool.sks-keyservers.net --recv-keys 0x126C0D24BD8A2942CC7DF8AC7638D0442B90D010
## gpg --keyserver pool.sks-keyservers.net --recv-keys 0xA1BD8E9D78F7FE5C3E65D8AF8B48AD6246925553
## gpg --keyserver pool.sks-keyservers.net --recv-keys 0xD21169141CECD440F2EB8DDA9D6D8F6BC857C906
## gpg --keyserver pool.sks-keyservers.net --recv-keys 0xE1CF20DDFFE4B89E802658F1E0B11894F66AEC98
## gpg --keyserver pool.sks-keyservers.net --recv-keys 0x6ED6F5CB5FA6FB2F460AE88EEDA0D2388AE22BA9
## gpg --keyserver pool.sks-keyservers.net --recv-keys 0xED6D65271AACF0FF15D123036FB2A1C265FFB764
## gpg --keyserver pool.sks-keyservers.net --recv-keys 0x0E4EDE2C7F3E1FC0D033800E64481591B98321F9


## gpg --keyserver pool.sks-keyservers.net --recv-keys 0x10460DAD76165AD81FBC0CE9988021A964E6EA7D
## gpg --keyserver pool.sks-keyservers.net --recv-keys 0xDF9B9C49EAA9298432589D76DA87E80D6294BE9B
## gpg --keyserver pool.sks-keyservers.net --recv-keys 0xF41D30342F3546695F65C66942468F4009EA8AC3










echo "## =================================================================================== ##" >> /etc/apt/sources.list.d/DebianWheezy.list
echo "## ------------------------------------ Debian Wheezy -------------------------------- ##" >> /etc/apt/sources.list.d/DebianWheezy.list
echo "## =================================================================================== ##" >> /etc/apt/sources.list.d/DebianWheezy.list
echo "## 																																		 " >> /etc/apt/sources.list.d/DebianWheezy.list
echo "## ------------------------------------------------------------------------------------------------------------------------------------- ##" >> /etc/apt/sources.list.d/DebianWheezy.list
echo "## deb http://httpredir.debian.org/debian wheezy main contrib non-free" >> /etc/apt/sources.list.d/DebianWheezy.list
echo "## deb-src http://httpredir.debian.org/debian wheezy main contrib non-free" >> /etc/apt/sources.list.d/DebianWheezy.list
echo "## ------------------------------------------------------------------------------------------------------------------------------------- ##" >> /etc/apt/sources.list.d/DebianWheezy.list
echo "## deb http://security.debian.org/ wheezy/updates main contrib non-free" >> /etc/apt/sources.list.d/DebianWheezy.list
echo "## ------------------------------------------------------------------------------------------------------------------------------------- ##" >> /etc/apt/sources.list.d/DebianWheezy.list




## =================================================================================== ##" >> /etc/apt/sources.list.d/DebianJessie.list
## ----------------------------------- Debian Jessie  -------------------------------- ##" >> /etc/apt/sources.list.d/DebianJessie.list
## =================================================================================== ##" >> /etc/apt/sources.list.d/DebianJessie.list
echo "## 																																		 " >> /etc/apt/sources.list.d/DebianJessie.list
echo "## ------------------------------------------------------------------------------------------------------------------------------------- ##" >> /etc/apt/sources.list.d/DebianJessie.list
echo "## deb http://httpredir.debian.org/debian jessie main contrib non-free" >> /etc/apt/sources.list.d/DebianJessie.list
echo "## deb-src http://httpredir.debian.org/debian jessie main contrib non-free" >> /etc/apt/sources.list.d/DebianJessie.list
echo "## ------------------------------------------------------------------------------------------------------------------------------------- ##" >> /etc/apt/sources.list.d/DebianJessie.list
echo "## deb http://httpredir.debian.org/debian jessie-updates main contrib non-free" >> /etc/apt/sources.list.d/DebianJessie.list
echo "## deb-src http://httpredir.debian.org/debian jessie-updates main contrib non-free" >> /etc/apt/sources.list.d/DebianJessie.list
echo "## ------------------------------------------------------------------------------------------------------------------------------------- ##" >> /etc/apt/sources.list.d/DebianJessie.list
echo "## deb http://security.debian.org/ jessie/updates main contrib non-free" >> /etc/apt/sources.list.d/DebianJessieSecurity.list
echo "## deb-src http://security.debian.org/ jessie/updates main contrib non-free" >> /etc/apt/sources.list.d/DebianJessie.list
echo "## ------------------------------------------------------------------------------------------------------------------------------------- ##" >> /etc/apt/sources.list.d/DebianJessie.list




## =================================================================================== ##" >> /etc/apt/sources.list.d/DebianStretch.list
## -------------------------------- Debian Stretch Stable ---------------------------- ##" >> /etc/apt/sources.list.d/DebianStretch.list
## =================================================================================== ##" >> /etc/apt/sources.list.d/DebianStretch.list
echo "## 																																		 " >> /etc/apt/sources.list.d/DebianStretch.list
echo "## ------------------------------------------------------------------------------------------------------------------------------------- ##" >> /etc/apt/sources.list.d/DebianStretch.list
echo "## deb http://deb.debian.org/debian stretch main contrib non-free" >> /etc/apt/sources.list.d/DebianStretch.list
echo "## deb-src  http://deb.debian.org/debian stretch main contrib non-free" >> /etc/apt/sources.list.d/DebianStretch.list
echo "## ------------------------------------------------------------------------------------------------------------------------------------- ##" >> /etc/apt/sources.list.d/DebianStretch.list
echo "## deb http://deb.debian.org/debian stretch-updates main contrib non-free" >> /etc/apt/sources.list.d/DebianStretch.list
echo "## deb-src  http://deb.debian.org/debian stretch-updates main contrib non-free" >> /etc/apt/sources.list.d/DebianStretch.list
echo "## ------------------------------------------------------------------------------------------------------------------------------------- ##" >> /etc/apt/sources.list.d/DebianStretch.list
echo "## deb http://security.debian.org/ stretch/updates main contrib non-free" >> /etc/apt/sources.list.d/DebianStretch.list
echo "## deb-src http://security.debian.org/ stretch/updates main contrib non-free" >> /etc/apt/sources.list.d/DebianStretch.list
echo "## ------------------------------------------------------------------------------------------------------------------------------------- ##" >> /etc/apt/sources.list.d/DebianStretch.list






