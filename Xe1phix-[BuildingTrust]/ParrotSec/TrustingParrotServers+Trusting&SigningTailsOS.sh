


echo "## ============================================================================ ##"
echo -e "\t If You havent already generated a GPG Key, do that now:"
echo -e "\t Generate a 4096 bit RSA - GPG Key (That is currently The Most Secure)"
echo "## ============================================================================ ##"
gpg2 --enable-large-rsa --full-gen-key






## ==================================================================================================== ##
## ---------------------------------------------------------------------------------------------------- ##
echo "Parrot Project GPG key"
##\____________________________________________________________________________________________________/##
gpg --keyserver hkp://pool.sks-keyservers.net --recv-keys 0x3B3EAB807D70721BA9C03E55C7B39D0362972489
## ---------------------------------------------------------------------------------------------------- ##
echo "Frozenbox Network (main frozenbox key)"
##\____________________________________________________________________________________________________/##
gpg --keyserver hkp://pool.sks-keyservers.net --recv-keys 0xC07B79F43025772903D19385042FB0305F53BE86
## ---------------------------------------------------------------------------------------------------- ##
echo "Old Frozenbox Network (repository signature only)"
##\____________________________________________________________________________________________________/##
gpg --keyserver hkp://pool.sks-keyservers.net --recv-keys 0xC686553B9795FA72214DE39CD7427F070F4FC7A6
## ---------------------------------------------------------------------------------------------------- ##
echo "Fetching Lorenzo Faletra (Palinuro)'s GPG Key"
##\____________________________________________________________________________________________________/##
gpg --keyserver hkp://pool.sks-keyservers.net --recv-keys 0xB35050593C2F765640E6DDDB97CAA129F4C6B9A4
## ---------------------------------------------------------------------------------------------------- ##
## ==================================================================================================== ##


echo "## =============================================================================== ##"
echo "## 			[+] You Can Find The GPG keys on Public SKS Keyservers:"
echo "## =============================================================================== ##"
echo "## 		https://pgp.mit.edu/pks/lookup?op=get&search=0x97CAA129F4C6B9A4"
echo "## ------------------------------------------------------------------------------- ##"
echo "## 		https://pgp.mit.edu/pks/lookup?op=get&search=0x042FB0305F53BE86"
echo "## ------------------------------------------------------------------------------- ##"
echo "## 		https://pgp.mit.edu/pks/lookup?op=vindex&search=0xD7427F070F4FC7A6"
echo "## =============================================================================== ##"



echo "## ========================================================================== ##"
echo -e "\t\t [+] Now Lets go ahead and import the parrot archives "
echo -e "\t\t     gpg file straight into your public gpg list"
echo "## ========================================================================== ##"
wget -qO - https://archive.parrotsec.org/parrot/misc/archive.gpg | apt-key add -



echo "## ========================================================================== ##"
echo -e "\t\t wget the file from the archive server"
echo -e "\t Then, manipulate the input to output the .gpg signature"
echo "## ========================================================================== ##"
wget -qO - https://archive.parrotsec.org/parrot/misc/archive.gpg > ParrotSec.gpg





## =========================================================================================================== ##
echo -e "\t\t Now it should populated when you request your public gpg keys list" 
## =========================================================================================================== ##
## gpg --keyid-format 0xlong --import ParrotSec.gpg		## if you want to import a physical file run this
## ----------------------------------------------------------------------------------------------------------- ##
gpg --list-keys --fingerprint 0x3B3EAB807D70721BA9C03E55C7B39D0362972489
## ----------------------------------------------------------------------------------------------------------- ##
## 			GPG Key fingerprint: 3B3E AB80 7D70 721B A9C0  3E55 C7B3 9D03 6297 2489
## =========================================================================================================== ##





## ========================================================================== ##
echo -e "\t\t[+] Lorenzo Faletra (Palinuro)'s GPG Key"
## __________________________________________________________________________ ##
gpg --export B35050593C2F765640E6DDDB97CAA129F4C6B9A4 | sudo apt-key add -
## -------------------------------------------------------------------------- ##
echo -e "\t\t[+] Frozenbox Network (main frozenbox key)"
## __________________________________________________________________________ ##
gpg --export C07B79F43025772903D19385042FB0305F53BE86 | sudo apt-key add - 
## -------------------------------------------------------------------------- ##
echo -e "\t\t[+] Old Frozenbox Network (repository signature only)"
## __________________________________________________________________________ ##
gpg --export C686553B9795FA72214DE39CD7427F070F4FC7A6 | sudo apt-key add - 
## -------------------------------------------------------------------------- ##
echo -e "\t\t[+] Parrot Project GPG key"
## __________________________________________________________________________ ##
gpg --export 3B3EAB807D70721BA9C03E55C7B39D0362972489 | sudo apt-key add -
## ========================================================================== ##



## ========================================================================== ##
echo -e "\t\t[!] Sign Lorenzo Faletra (Palinuro)'s GPG Key:"
## __________________________________________________________________________ ##
gpg --lsign-key B35050593C2F765640E6DDDB97CAA129F4C6B9A4
## -------------------------------------------------------------------------- ##
echo -e "\t\t[!] Sign Frozenbox Network (main frozenbox key)"
## __________________________________________________________________________ ##
gpg --lsign-key C07B79F43025772903D19385042FB0305F53BE86
## -------------------------------------------------------------------------- ##
echo -e "\t\t[!] Sign Old Frozenbox Network (repository signature only)"
## __________________________________________________________________________ ##
gpg --lsign-key C686553B9795FA72214DE39CD7427F070F4FC7A6
## -------------------------------------------------------------------------- ##
echo -e "\t\t[!] Sign Parrot Project GPG key"
## __________________________________________________________________________ ##
gpg --lsign-key 3B3EAB807D70721BA9C03E55C7B39D0362972489
## ========================================================================== ##





echo "## ==================================================================== ##"
echo -e "\t\t The ParrotSec GPG Keyring is a prerequisite"
echo "   The keyring verifies the bidirection relationship between you"
echo "   And the server isnt being intercepted or manipulated in any way"
echo "## ==================================================================== ##"
apt-get update && apt-get install apt-parrot parrot-archive-keyring














gpg --keyid-format 0xlong --import tails-signing.key 
gpg --fingerprint 0xDBB802B258ACD84F

gpg --list-keys
gpg --keyid-format 0xlong --check-sigs A490D0F4D311A4153E2BB7CADBB802B258ACD84F
gpg --lsign-key A490D0F4D311A4153E2BB7CADBB802B258ACD84F
gpg --sign-key A490D0F4D311A4153E2BB7CADBB802B258ACD84F
gpg --send-keys A490D0F4D311A4153E2BB7CADBB802B258ACD84F




 
tails-amd64-3.0.1.iso.sig tails-amd64-3.0.1.iso 



dd status=progress if=/dev/sr1 of=/home/xe1phix/OS/tails/tails-3.2.iso













