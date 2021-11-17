




## ------------------------------------------------------------- ##
##   [?] Copy The first Drive, And Output It To An .img File:
## ------------------------------------------------------------- ##
dc3dd if=/dev/sda of=suspect.img hash=md5 hash=sha1 log=suspect.txt



## -------------------------------------------------------------------- ##
##   [?] Copy The first Drive, And Split The Data Into 650MB Chunks:
## -------------------------------------------------------------------- ##
dc3dd if=/dev/sda ofs=suspect.img.000 ofsz=650M hash=md5 hash=sha1 log=suspect.txt






                             ## ------------------------------------------------------- ##
dc3dd if=$Device	         ##   [?] Read input from a device or a file
dc3dd if=$FILE               ## ------------------------------------------------------- ##

dc3dd if=/dev/urandom
dc3dd if=/dev/sda
dc3dd if=/dev/sr0
dc3dd if=/


                             ## ------------------------------------------------------- ##
dc3dd ifs=$BASE.FMT	         ##  [?] Read input from a set of files with base name
	        	             ##      BASE and sequential file name extensions
	        	             ##      conforming to the format specifier FMT
                             ## ------------------------------------------------------- ##


dc3dd verb=on hash=sha1
dc3dd verb=on hash=sha256
dc3dd verb=on hash=sha512



                            ## ------------------------------------------------------- ##
dc3dd bufsz=$BYTES	        ##  [?] Set the size of the internal byte buffers to BYTES
                            ## ------------------------------------------------------- ##


                            ## ------------------------------------------------------- ##
dc3dd hwipe=$DEVICE	        ##  [?] Wipe DEVICE by writing zeros (default) or a
	        	            ##      pattern specified by pat= or tpat=. Verify
	        	            ##      DEVICE after writing it by hashing it and
	        	            ##      comparing the hash(es) to the input hash(es).
                            ## ------------------------------------------------------- ##

                            ## ------------------------------------------------------- ##
dc3dd wipe=$DEVICE	        ##  [?] Wipe DEVICE by writing zeros (default)
                            ## ------------------------------------------------------- ##

                            ## ------------------------------------------------------- ##
dc3dd hof=$FILE	            ## 
                            ## ------------------------------------------------------- ##



                            ## ------------------------------------------------------- ##
dc3dd log=$FILE	            ##  [?] Log I/O statistcs, diagnostics, and total hashes
	    	                ##      of input and output to FILE. 
                            ## ------------------------------------------------------- ##

                            ## ------------------------------------------------------- ##
dc3dd hlog=$FILE	                ##  [?] Log total hashes and piecewise hashes to FILE.
	                        ##      This option can be used more than once to generate multiple logs.
                            ## --------------------------------------------------------------------- ##

                            ## ------------------------------------------------------- ##
dc3dd mlog=$FILE            ##  [?] Create hash log that is easier for machine to read
                            ## ------------------------------------------------------- ##


                            ## ------------------------------------------------------- ##
dc3dd rec=off               ##  [?] By default, zeros are written to the output(s) in
	                        ##      place of bad sectors when the input is a device.
                            ##      Use this option to cause the program to instead
	                        ##      exit when a bad sector is encountered.
                            ## ------------------------------------------------------- ##





                            ## ------------------------------------------------------- ##
dc3dd ofsz=$BYTES           ##  [?] Set the maximum size of each file in the sets of files
                            ## ------------------------------------------------------- ##


                            ## ------------------------------------------------------- ##
dc3dd dbr=on                ##  [?] 
                            ## ------------------------------------------------------- ##

                            ## ------------------------------------------------------- ##
dc3dd --enable-hpadco       ##  [?] Enable checking ATA/SATA drives for hidden areas
                            ## ------------------------------------------------------- ##



                            ## ------------------------------------------------------- ##
dc3dd corruptoutput=on      ##  [?] For verification testing and demonstration
	                        ##      purposes, corrupt the output file(s) with extra
	                        ##      bytes so a hash mismatch is guaranteed.
                            ## ------------------------------------------------------- ##


                            ## ------------------------------------------------------- ##
dc3dd nwspc=on              ##  [?] Activate compact reporting, where the use
	                        ##      of white space to divide log output into
	                        ##      logical sections is suppressed.
                            ## ------------------------------------------------------- ##






## --------------------------------------------------------------------------- ##
##   [?] Imaging a device to a single output file with 
##       generation of md5 and sha1 hashes of the device:
## --------------------------------------------------------------------------- ##
dc3dd if=/dev/sda of=suspect.img hash=md5 hash=sha1 log=suspect.txt


## ---------------------------------------------------------------------------------- ##
##   [?] Imaging a device to a set of CD-sized output files
##       with generation of md5 and and sha1 hashes of the device:
## ---------------------------------------------------------------------------------- ##
dc3dd if=/dev/sda ofs=suspect.img.000 ofsz=650M hash=md5 hash=sha1 log=suspect.txt


## --------------------------------------------------------------------------- ##
##   [?] Imaging a device to both a single output file and to a set of CD-sized
##       output files with generation of md5 and sha1 hashes of the device:
## --------------------------------------------------------------------------- ##
dc3dd if=/dev/sda of=suspect.img of=suspect.img ofs=suspect.img.000 ofsz=650M hash=md5 hash=sha1 log=suspect.txt


## --------------------------------------------------------------------------- ##
##   [?] Imaging a device to both a single output file and to a set of 
##       CD-sized output files with generation of md5 and sha1 hashes
##       of the device and md5 and sha1 hashes of the outputs:
## --------------------------------------------------------------------------- ##
dc3dd if=/dev/sda of=suspect.img hof=suspect.img hofs=suspect.img.000 ofsz=650M hash=md5 hash=sha1 log=suspect.txt


## ----------------------------------------------------------------------------------- ##
##   [?] Restoring a set of image files to a device with verification
##       hashes of only the bytes dc3dd writes to the device:
## ----------------------------------------------------------------------------------- ##
dc3dd ifs=suspect.img.000 hof=/dev/sdb hash=md5 hash=sha1 log=suspect-restore.txt


## ----------------------------------------------------------------------------------- ##
##   [?] Restoring a set of image files to a device with verification hashes of 
##       both the bytes dc3dd writes to the device and the entire device:
## ----------------------------------------------------------------------------------- ##
dc3dd ifs=suspect.img.000 fhod=/dev/sdb hash=md5 hash=sha1 log=suspect-restore.txt


## ---------------------------------- ##
##   [?] Wiping a drive:
## ---------------------------------- ##
dc3dd wipe=/dev/sdb log=wipe.txt


## ----------------------------------------------------- ##
##   [?] Wiping a drive with verification:
## ----------------------------------------------------- ##
dc3dd hwipe=/dev/sdb hash=md5 hash=sha1 log=wipe.txt




