

affcat $Image.aff | sfsimage -i - $Image.sfs        ## converting AFF --> compressed SquashFS 
mksquashfs $Image.raw $Image.sfs -comp lzo -noI     ## raw image -->> compressed SquashFS
zcat $Image.raw.gz | sfsimage -i - $image.sfs       ## gzipped raw image -->> SquashFS compressed file:
sfsimage -i $Image.raw $Image.sfs                   ## Convert raw image -->> SquashFS
sfsimage -m $Image.sfs                              ## mount the *.sfs file
unsquashfs -lls $Image.sfs                          ## view the contents of a SquashFS file
affconvert -Oaff $image.sfs.d/$image.raw            ## [ (raw image) inside a SquashFS ] --> AFF file

aimage --lzma_compress --compression=9 /dev/$Disk $image.aff
affcat $Image.aff | ftkimager - image --s01                     ## convert a AFF image to EnCase or FTK
affcat $Image.aff > $Image.raw                                  ## convert a raw image to an AFF format
affconvert -r $Image.aff                                        ## convert AFF images to a raw image
affconvert $Image.raw                                           ## convert a raw image -->> an AFF

affinfo $Image.aff > $affinfo.txt                   ## extract the metadata from AFF files
sfsimage -a $affinfo.txt $Image.sfs                 ## add the AFF Metadta to the SquashFS forensic evidence container

ftkimager $Image.s01 image --e01                    ## Converting FTK *.s01 --> EnCase EWF *E01 format
ftkimager $Image.E01 image --s01                    ## Convert EnCase EWF *E01 --> FTK *.s01
ftkimager --compress 9 --s01 /dev/$Disk $image      ## FTK Smart Compressed Acquisition
ewfacquire $Image.raw -t $Image -f encase7          ## convert $image.raw to EnCase Expert Witness format:
ewfacquire -c bzip2:best -f encase7-v2 /dev/$Disk   ## EnCase EWF Compressed Acquisition
ewfinfo $Image.E01                                  ## Examine File Hashes

