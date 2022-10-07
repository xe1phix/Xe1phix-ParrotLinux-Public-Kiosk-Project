






partprobe --summary



parted





partx --show - /dev/sdb

partx --verbose --output list

partx --verbose --show 
partx --verbose --raw
partx --verbose --list-types




partx -o START -g /dev/sdb
partx -o SECTORS,SIZE /dev/sdb



##-==========================================================-##
##   [+] Creates empty GPT partition table.
##-==========================================================-##
echo 'label: gpt' | sfdisk /dev/sdb





sfdisk --wipe
sfdisk --wipe-partitions



##-==========================================================-##
##  [+] reates a 100MiB free area before the  first
##      partition  and moves the data it contains (e.g. a filesystem)
##-==========================================================-##
echo '+100M,' | sfdisk --move-data /dev/sdc -N 1



##-==========================================================-##
##  [+] reates a new partition from the free space (at offset 2048)
##-==========================================================-##

echo '2048,' | sfdisk /dev/sdc --append



##-==========================================================-##
##  [+] eorders partitions to match disk order 
##      (the original sdc1 will become sdc2)
##-==========================================================-##

sfdisk /dev/sdb --reorder


sfdisk --verify $Device
##-==========================================================-##
##  [+] Test whether the partition table and partitions seem correct.
##-==========================================================-##



sfdisk --backup --backup-file ~/sfdisk-$Device-$Offset.bak


##-==========================================================-##
##  [+] Print all supported types for the current disk label
##-==========================================================-##

sfdisk --list-types



##-=====================================================-##
##  [+] List the sizes of all / specified devices 
##      in units of 1024 byte size. 
##-=====================================================-##
 
sfdisk --show-size




##-=====================================-##
##  [+] Change the GPT partition UUID.
##-=====================================-##
sfdisk --part-uuid


##-=====================================-##
##  [+] Change the partition type.
##-=====================================-##

sfdisk --part-type




##-==========================================================-##
##  [+] Change  the  GPT  partition name (label)
##-==========================================================-##

## ----------------------------------------------------------------------- ##
##  [?] If the label isnt specified, print the current partition label.
## ----------------------------------------------------------------------- ##
sfdisk --part-label





##-==========================================================-##
##  [+] The currently supported attribute bits are: 

RequiredPartition
NoBlockIOProtocol
LegacyBIOSBootable 


GUID-specific bits          ## in the range from 48 to63.  
                            ## For example, the string 
                            ## "RequiredPartition,50,51" 
                            ## sets three bits.



sfdisk --part-attrs



sfdisk --list-free

sfdisk --list --show-geometry



sfdisk --list --json



sfdisk --partno <num>        specify partition number


sfdisk --append              append partitions to existing partition table


sfdisk --backup              backup partition table sectors (see -O)


sfdisk --dump <dev>            ## dump partition table (usable for later input)

sfdisk --bytes               print SIZE in bytes rather than in human readable format



sfdisk --verify 









affdiskprint -x XML         ## Verify the diskprint.



##-==========================================================-##
##  [+] Convert file1.raw to file1.aff:

affconvert file1.raw



##-==========================================================-##
##  [+] Convert file1.aff to file1.raw:

affconvert -r file1.aff


##-==========================================================-##
##  [+] Batch convert files:
##-==========================================================-##
affconvert file1.raw file2.raw file3.raw
affconvert -r file1.aff file2.aff file3.aff



##-==========================================================-##
##  [+] Split an AFF file into 4GB chunks for archiving to DVD:

affconvert -M4g -odvd.afd  bigfile.aff


##-==========================================================-##
##  [+] 
##      
##-==========================================================-##


## ---------------------------------------------------------- ##
##  [?] 
## ---------------------------------------------------------- ##



affsign -n                  ## ask for a chain-of-custody note.



affcopy

                            ##-=======================================-##
                            ## -------~>  Signature Options  <~------- ##
                            ##-=======================================-##
                                                                     
                            ## ------------------------------------------------- ##
affsign -k $File.key        ##   ~-~[>  Specify private key for signing  <]~-~   ##
                            ## ------------------------------------------------- ## 
##                                  ||                                ||        
##                                __||__                            __||__        
                            ## ------------------------------------------------------------- ##
affsign -c $File.cer        ##  [+] Specify a X.509 certificate that matches private key
                            ## ------------------------------------------------------------- ##

                            ## ------------------------------------------------------ ##
                            ##  [?] By default, the file is assumed to be 
                            ##      the same one provided with the -k option.)
                            ## ------------------------------------------------------ ##


                            ##-==============================================-##
affsign -Z /dev/sdb         ##   [+] ZAP (remove) all signature segments.
                            ##-==============================================-##




Print if each file is encrypted or not:

affcrypto filename.aff filename2.aff


-j      --- Just print the number of encrypted segments
-J      --- Just print the number of unencrypted segments







			##  [+] Just print the number of encrypted segments
affcrypto -j 
			
			##  [+] Just print the number of unencrypted segments
affcrypto -J 


            ##-====================================-##
			##      [+] Data Conversion Options:
            ##-====================================-##

            ##-======================================================-##
			##  [+] Encrypt the unencrypted non-signature segments
            ##-======================================================-##

affcrypto -e 

            ##-======================================================-##
			##  [+] Decrypt the encrypted non-signature segments
            ##-======================================================-##
affcrypto -d

            ##-======================================================-##
			##  [+] change passphrase (take old and new from stdin)
            ##-======================================================-##
affcrypto -r

            ##-===============================-##
			##  [+] specify old passphrase
            ##-===============================-##
-O $Old

            ##-===============================-##
			##  [+] specify new passphrase
            ##-===============================-##
-N $New

			##-==================================================-##
			##   [+] Specifies a private keyfile for unsealing 
			##-==================================================-##
-K $MyKey.key

			##-==================================================-##
			##  [+] specifies a certificate file for sealing 
			##-==================================================-##
-C $MyCert.crt

			##-============================================================-##
			##   [+] Add Symmetric Encryptiong (passphrase) 
			##       to AFF FILE encrypted with public key.
			##-============================================================-##
			## ------------------------------------------------------------ ##
			##   [?] Requires a private key and a specified passphrase.
			## ------------------------------------------------------------ ##
-S 

			##-===============================================================================-##
			##   [+] Add Asymmetric Encryption To An AFF FILE encrypted with a passphrase
			##-===============================================================================-##
			## ------------------------------------------------------------------------------- ##
			##   [?] Requires a certificate file spcified with the -C option
			## ------------------------------------------------------------------------------- ##
-A 



			        ##-===============================================================================-##
			        ##                  [+] Password Cracking Options:
			        ##-===============================================================================-##

			            ##-===============================================================================-##
                	    ##   [+] Checks to see if passphrase is the passphrase of the file
			            ##-===============================================================================-##
affcrypto -p $Pass      ## ------------------------------------------------------------------------------- ##
			            ##   [?] Exit code is 0 if it is, -1 if it is not
			            ## ------------------------------------------------------------------------------- ##



			        ##-=====================================================-##
affcrypto -k        ##   [+] Attempt to crack passwords by reading 
                    ##       A list of passwords from ~/.affpassphrase
			        ##-=====================================================-##


			        ##-=====================================================-##
affcrypto -f $File 	##  [+] Crack passwords but read them from file.
			        ##-=====================================================-##

			
			        ##-=====================================================-##
affcrypto -D		##  [+] debug; print out each key as it is tried
			        ##-=====================================================-##
			
			        ##-=====================================================-##
affcrypto -l			##  [+] List the installed hash and encryption algorithms 
			        ##  [+] am ignores the environment variables:
			        ##-=====================================================-##




