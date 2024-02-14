#!/bin/sh



## ------------------------------------------------------------------------------------------ ##
    	affcopy -vv $File1 $File2 $File3 $Dir       ## Copy All Files To $Dir
## ------------------------------------------------------------------------------------------ ##
    	affcopy -d $File $Dir                       ## Print Debugging Information
## ------------------------------------------------------------------------------------------ ##
    	affcopy -k $File.key $File.aff				## Specify Private Key For Signing
## ------------------------------------------------------------------------------------------ ##
    	affcopy -c $File.cer $File.aff				## Specify A X.509 Certificate 
													## That Matches The Private Key 
## ------------------------------------------------------------------------------------------ ##



##-====================================================================-##
##   [+] Copy $File1 -> $Dir1, $File2 -> $Dir2 and $File3 -> $Dir3:
##-====================================================================-##
affcopy -vv $File1 $File2 $File3 $Dir1 $Dir2 $Dir3


##-========================================-##
##   [+] Encrypt AFF Files With AFFCopy:
##-========================================-##
affcopy -vv $File.aff file://:$Password@/$EncryptedFile.aff


##-==================================================-##
##   [+] Copy All Files In The Current Directory 
##       To Default S3 Bucket With X9 Compression:
##-==================================================-##
affcopy -vy -X9 *.aff s3:///







