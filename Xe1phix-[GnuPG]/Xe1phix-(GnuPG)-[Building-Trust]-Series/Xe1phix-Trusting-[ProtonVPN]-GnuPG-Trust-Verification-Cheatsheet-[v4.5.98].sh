#!/bin/sh


echo "## ---------------------------------------------------------------------------------------- ##"
echo "##     [+]  Downloading The ProtonVPN Code Signing Key:"
echo "##\____________________________________________________/##"
curl --verbose --progress-bar --tlsv1.2 --ssl-reqd --url https://repo.protonvpn.com/debian/public_key.asc --output ~/ProtonVPN-Public-Key.asc


echo "## ---------------------------------------------------------------------------------------- ##"
echo "##     [+]  Importing The ProtonVPN Code Signing Key:"
echo "##\____________________________________________________/##"
gpg --keyid-format 0xlong --import public_key.asc


echo "## ---------------------------------------------------------------------------------------- ##"
echo "##     [+]  Fingerprinting The ProtonVPN Code Signing Key..."
echo "##\____________________________________________________/##"
gpg --keyid-format 0xlong --fingerprint 0x0x71EB474019940E11
gpg --keyid-format 0xlong --fingerprint 0xA88441BD4864F95BEE08E63A71EB474019940E11



echo "## ------------------------------------------------------------------------------------------------------- ##"
echo "##                     [+]  ProtonVPN GPG Fingerprints (Verified):								"
echo "##\_____________________________________________________________/##"
echo 
echo "## -------------------------------------------------------------------------------------------------------------- ##"
echo "		Key fingerprint = A884 41BD 4864 F95B EE08  E63A 71EB 4740 1994 0E11		  "
echo "## -------------------------------------------------------------------------------------------------------------- ##"
echo "             A884 41BD 4864 F95B EE08  E63A 71EB 4740 1994 0E11					   "
echo "             A884 41BD 4864 F95B EE08  E63A 71EB 4740 1994 0E11					   "
echo "## ------------------------------------------------------------------------------------------------------- ##"
echo "        [?]  See https://protonvpn.com/support/official-linux-client-arch/"
echo "## ------------------------------------------------------------------------------------------------------- ##"



echo "## --------------------------------------------------------------------------------- ##"
echo "##     [+]  Signing The ProtonVPN Code Signing Key..."
echo "##\________________________________________________/##"
gpg --lsign 0xA88441BD4864F95BEE08E63A71EB474019940E11








-----BEGIN PGP PUBLIC KEY BLOCK-----

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
=g4xg
-----END PGP PUBLIC KEY BLOCK-----

