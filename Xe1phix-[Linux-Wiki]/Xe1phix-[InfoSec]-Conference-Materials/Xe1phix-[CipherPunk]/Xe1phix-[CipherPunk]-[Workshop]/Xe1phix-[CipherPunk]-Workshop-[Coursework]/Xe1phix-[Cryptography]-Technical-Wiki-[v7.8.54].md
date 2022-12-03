


##-=============================================-##
##   [+] Message Padding

For each Cipher, messages must be
##-=============================================-##
##   [+] Cryptographically Padded

to meet the Cipher's Block Size.





Cipher Block Chaining

Ciphers
The following Ciphers are currently supported 


Camellia-256
AES-256 (Rijndael)


Cipher Modes
Each Cipher can operate in a number of
block operation modes.




Message Padding
For each Cipher, messages must be
cryptographically padded
to meet the Cipher's block size.
While NodeJS supports some padding schemes, most are not. As such,
these were manually implemented in the code.
The following padding schemes are supported:


##-=============================================-##
##   [+] PKCS #5/PKCS #7



Key Exchanges

##-=============================================-##
##   [+] Key Exchange (also Key Establishment) 
##-=============================================-##
## 
## ------------------------------------------------------------- ##
##   [?] Cryptographic Keys are Exchanged between two parties 
## ------------------------------------------------------------- ##
##   [?] Allowing use of a Cryptographic Algorithm.
## ---------------------------------------------------- ##


## ---------------------------------------------------- ##
##   [?] If the sender and receiver want to Exchange Encrypted Messages, 

## ----------------------------------------------------------------- ##
##   [?] Each recipiant must be equipped to Encrypt Messages 
##   [?] to be sent and Decrypt Messages received. 
## ----------------------------------------------------------------- ##
##   [?] The nature of the equipping they require 
##       Depends on the Encryption technique they use. 
## ----------------------------------------------------------------- ##
##   [?] If they use a Cipher, they will need appropriate keys.
## ----------------------------------------------------------------- ##



## ---------------------------------------------------- ##
##   [?] If the Cipher is a symmetric key Cipher,
##   [?] both will need a copy of the same key. 
## ---------------------------------------------------- ##

## ---------------------------------------------------- ##
##   [?] If an asymmetric key Cipher with the public/private key property
both will need the other's public key.



The following algorithms are currently supported 
to exchange keys in a secure manner.


Diffie-Hellman (DH)
Elliptic Curve Diffie-Hellman (ECDH) 


Default Exchange Algorithm


The default type and key size 256-bits





