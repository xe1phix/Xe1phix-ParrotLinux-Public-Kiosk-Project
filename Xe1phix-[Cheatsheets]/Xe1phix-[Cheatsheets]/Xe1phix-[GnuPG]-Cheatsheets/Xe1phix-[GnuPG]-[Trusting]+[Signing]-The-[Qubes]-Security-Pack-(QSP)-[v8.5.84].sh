#!/bin/sh
## --------------------------------------------------------------------------------------------- ##
##   [+] Xe1phix-[Qubes]-[GnuPG]-Trusting+Signing-The-Qubes-Security-Pack-(QSP)-[v4.8.25].sh
## --------------------------------------------------------------------------------------------- ##

									         /^\\
								 ___________//__\\___________
						   ________|| Trusting & Signing ||__________
							|| ** The Qubes Security Pack (QSP)** ||
____________________________||____________________________________||_________________________
https://keys.qubes-os.org/keys/qubes-release-2-signing-key.asc    ||
____________________________________________________________________________________________
curl --tlsv1 --url https://keys.qubes-os.org/keys/qubes-master-signing-key.asc --output /home/$user/Gnupg/archive-key.asc |
_____________________________________________________________________________________________
gpg --export 0x427F11FD0FAA4B080123F01CDDFA1A3E36879494 | sudo apt-key add -
_____________________________________________________________________________________________
curl --tlsv1 --url https://keys.qubes-os.org/keys/qubes-master-signing-key.asc --output /home/$user/Gnupg/archive-key.asc | apt-key add
_____________________________________________________________________________________________
gpg --keyserver pool.sks-keyservers.net --recv-keys 0x427F11FD0FAA4B080123F01CDDFA1A3E36879494






##-=================================================================-##
##   [+] How to Obtain, Verify, and Read Qubes Warrant Canaries:
##-=================================================================-##



##-=================================================-##
##   [+] Clone the The Qubes Security Pack (QSP):
##-=================================================-##
git clone https://github.com/QubesOS/qubes-secpack.git



##-===============================-##
##   [+] Verify signed Git tags.
##-===============================-##
cd qubes-secpack/


git tag -v `git describe`
## --------------------------------------------------------------------------------------------- ##
##  object 2bb7f0b966593d8ed74e140a04d60c68b96b164e
##  type commit
##  tag joanna_sec_2bb7f0b9
##  tagger Joanna Rutkowska <joanna@invisiblethingslab.com> 1468335706 +0000
## --------------------------------------------------------------------------------------------- ##
##  Tag for commit 2bb7f0b966593d8ed74e140a04d60c68b96b164e
##  gpg: Signature made 2016-07-12T08:01:46 PDT
##  gpg:                using RSA key 0x4E6829BC92C7B3DC
##  gpg: Good signature from "Joanna Rutkowska (Qubes Security Pack Signing Key) <joanna@invisiblethingslab.com>" [full]
## --------------------------------------------------------------------------------------------- ##





##-==================================-##
##   [+] Import the Qubes PGP keys
##-==================================-##
gpg --import qubes-secpack/keys/*/*



##-====================================================================-##
##   [+] Set the Trust Level of the Qubes Master Signing Key (QMSK)
##-====================================================================-##
gpg --edit-key 36879494


##-=======================================================================-##
##   [+] Verify the authenticity of the Qubes Master Signing Key (QMSK)
##-=======================================================================-##
gpg> fpr
## --------------------------------------------------------------------- ##
##  pub   4096R/36879494 2010-04-01 Qubes Master Signing Key
##    Primary key fingerprint: 427F 11FD 0FAA 4B08 0123  F01C DDFA 1A3E 3687 9494
## --------------------------------------------------------------------- ##


##-==================================================-##
##   [+] Trust the Qubes Master Signing Key (QMSK)
##-==================================================-##
gpg> trust


## --------------------------------------------------------------------- ##
##  1 = I don't know or won't say
##  2 = I do NOT trust
##  3 = I trust marginally
##  4 = I trust fully
##  5 = I trust ultimately
##  m = back to the main menu
## --------------------------------------------------------------------- ##

## --------------------------------------------------------------------- ##
      Your decision? 5
## --------------------------------------------------------------------- ##
      Do you really want to set this key to ultimate trust? (y/N) y
## --------------------------------------------------------------------- ##
      gpg> q
## --------------------------------------------------------------------- ##



##-======================================-##
##   [+] Verify and read the canaries.
##-======================================-##
cd qubes-secpack/canaries/

gpg --verify canary-001-2015.txt.sig.joanna canary-001-2015.txt
## --------------------------------------------------------------------------------------------- ##
##  gpg: Signature made Mon Jan  5 20:21:40 2015 UTC using RSA key ID 92C7B3DC
##  gpg: Good signature from "Joanna Rutkowska (Qubes Security Pack Signing Key) <joanna@invisiblethingslab.com>"
## --------------------------------------------------------------------------------------------- ##



##-=================================-##
##   [+] Verify and read the QSBs
##-=================================-##
cd ../QSBs/

gpg --verify qsb-013-2015.txt.sig.joanna qsb-013-2015.txt
## --------------------------------------------------------------------------------------------- ##
##  gpg: Signature made Mon Jan  5 21:22:14 2015 UTC using RSA key ID 92C7B3DC
##  gpg: Good signature from "Joanna Rutkowska (Qubes Security Pack Signing Key) <joanna@invisiblethingslab.com>"
## --------------------------------------------------------------------------------------------- ##



gpg> fpr				## Fingerprint 	qubes master key
## --------------------------------------------------------------------------------------------- ##
##  pub   4096R/36879494 2010-04-01 Qubes Master Signing Key
##    Primary key fingerprint: 427F 11FD 0FAA 4B08 0123  F01C DDFA 1A3E 3687 9494
## --------------------------------------------------------------------------------------------- ##

_____________________________________________________________________________
gpg --list-sig 0A40E458
gpg -v --verify Qubes-R2-x86_64-DVD.iso.asc
gpg -v --verify qsb-013-2015.txt.sig.joanna qsb-013-2015.txt
gpg -v --verify qsb-013-2015.txt.sig.marmarek qsb-013-2015.txt





