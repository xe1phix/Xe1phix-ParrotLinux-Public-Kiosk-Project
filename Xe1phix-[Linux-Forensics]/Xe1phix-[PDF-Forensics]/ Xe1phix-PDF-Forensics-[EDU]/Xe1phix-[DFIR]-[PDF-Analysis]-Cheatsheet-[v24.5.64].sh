#!/bin/sh
##-===============================================================-##
##   [+] Xe1phix-PDF-Forensic-Analysis-Cheatsheet-[v24.5.64].sh
##-===============================================================-##

##-======================================-##
##   [+] Display contents of object id
##-======================================-##
pdf-parser --object id $File.pdf     


##-===================================-##
##   [+] decode the object’s stream
##-===================================-##
pdf-parser --object id --filter --raw $File.pdf


##-==========================================-##
##   [+] Extract files / scripts / Objects
##-==========================================-##
## ------------------------------------------ ##
##   [?] pdf-parser - extract js objects
## ------------------------------------------ ##
pdf-parser --object 32 --raw > extractedObject.js
pdf-parser --object 32 --raw > $File


##-==============================-##
##  [+] Analyze PDF and Exploit
##-==============================-##
pyew $File.pdf 	


##-===========================-##
##   [+] Force Parsing Mode
##-===========================-##
peepdf -fl $File.pdf
peepdf --interactive $File.pdf


##-=========================================-##
##   [+] Forensic Carve File For Metadata
##-=========================================-##
exiftool -a -u -g2 $File.pdf


##-========================================-##
##   [+] Get metadata recursivly from pwd
##-========================================-##
exiftool -r -ext pdf .


##-===========================-##
##    [+] Change an element
##-===========================-##
exiftool -Title="$Title" $File.pdf


##-===========================-##
##    [+] Remove metadata
##-===========================-##
exiftool -all= $File.pdf
exiftool -all:all= $File.pdf
qpdf --linearize $File.pdf $FileCleaned.pdf



## ------------------------------------------------------------------- ##
    mat2 --lightweight $File    ## remove SOME metadata
## ------------------------------------------------------------------- ##
    mat2 --show $File           ## list harmful metadata detectable
## ------------------------------------------------------------------- ##
    mat2 --inplace $File        ## clean in place, without backup
## ------------------------------------------------------------------- ##
  
  
 
##-====================================-##
##   [+] Extract Flash (SWF) objects
##-====================================-##
swf_mastah.py -f $File.pdf -o $File


##-===========================================-##
##  [+] hachoir-metadata - Extract Metadata
##-===========================================-##
hachoir-metadata --level=9 $File
hachoir-metadata --verbose $File
hachoir-metadata --debug $File
hachoir-metadata --log=$File $File

## ----------------------------------------------------------- ##
    hachoir-metadata --parser-list      ## List all parsers
## ----------------------------------------------------------- ##


##-==========================-##
##  [+] Search JPEG images:
##-==========================-##
hachoir-subfile input --parser=jpeg $File


##-=======================-##
##   [+] Search images:
##-=======================-##
hachoir-subfile input --category=image $File


##-===========================================-##
##  [+] Search images, videos and SWF files:
##-===========================================-##
hachoir-subfile input --category=image,video --parser=swf


##-==============================-##
##   [+] Search all subfiles 
##   [+] store them in /$Dir/
##-==============================-##
hachoir-subfile input /$Dir/


##-===============================-##
##   [+] Find files on /dev/sda:
##-===============================-##
hachoir-subfile /dev/sda --size=34200100 --quiet


##-=================================-##
##   [+] Strip Metadata From File
##-=================================-##
hachoir-strip --strip=useless 
hachoir-strip --strip=metadata
hachoir-strip --strip="useless,metadata"



##-==============================-##
##   [+] 
##-==============================-##
pdfxray_lite -f $File.pdf -r rpt_


##-=============================-##
##   [+] Extract PDF Metadata:
##-=============================-##
pdfextract $File.pdf


##-===============================-##
##   [+] Decode base64 Encoding
##-===============================-##
base64 -d stream_122.dmp > decoded_file
xxd decoded_file | less


##-=========================-##
##   [+] interactive Mode
##-=========================-##
peepdf -i $File.pdf


##-===================================-##
##   [+] Checks hash With VirusTotal
##-===================================-##
peepdf --check-vt $File.pdf


##-===================================-##
##   [+] Sets loose parsing mode
##-===================================-##
## ----------------------------------- ##
##   [?] to catch malformed objects
## ----------------------------------- ##
peepdf --loose-mode $File.pdf


##-=================================================-##
##   [+] Avoids automatic Javascript analysis
##-=================================================-##
## ------------------------------------------------- ##
##   [?] Useful with eternal loops (heap spraying)
## ------------------------------------------------- ##
peepdf --manual-analysis $File.pdf


##-===========================-##
##   [+] Extract references:
##-===========================-##
pdf-extract extract --references $File.pdf


##-========================================-##
##   [+] Extract references and a title:
##-========================================-##
pdf-extract extract --references --titles $File.pdf


##-======================================-##
##  [+] Mark the locations of 
##  [+] Headers, Footers and Columns:
##-======================================-##
pdf-extract mark --columns --headers --footers $File.pdf


##-==========================================-##
##  [+] Extract regions of text from a PDF
##  [?] Preserving line information 
##-==========================================-##
## ------------------------------------------ ##
##    [?] (offsets from region origin):
## ------------------------------------------ ##
pdf-extract extract --regions $File.pdf


##-==========================================-##
##  [+] Extract regions of text from a PDF 
##  [+] without line information 
##-==========================================-##
## ------------------------------------------ ##
##   [?] (prettier and easier to read):
## ------------------------------------------ ##
pdf-extract extract --regions --no-lines $File.pdf


##-=========================================-##
##  [+] Resolve references to DOIs
##  [+] output related metadata as BibTeX:
##-=========================================-##
pdf-extract extract-bib --resolved_references $File.pdf


##-========================================-##
##  [+] pdfinfo - PDF document extractor
##-========================================-##
## ----------------------------------------------------- ##
##   -meta			Prints doc level metadata
##   -js			Prints all JavaScript in PDF
##   -rawdates		Prints raw undecoded date strings
##   -dests 		Print list of all destinations
## ----------------------------------------------------- ##
pdfinfo -box -meta -js -rawdates $File.pdf



##-============================================-##
##   [+] Display objects + actions structure
##-============================================-##
pdfdid -aefv $File.pdf



## ------------------------------------------------- ##
##   [?] Search for:
## ------------------------------------------------- ##
##   [+] /OpenAction 
##   [+] /AA 
##   [+] /Launch 
##   [+] /GoTo 
##   [+] /GoToR 
##   [+] /SubmitForm  
##   [+] /Richmedia (for Flash) 
##   [+] /JS 
##   [+] /JavaScript 
##   [+] /URI
## ------------------------------------------------- ##
##   [?] Encoding
##   [+] Cipher
##   [+] Shell code
##   [+] Obfuscation
## ------------------------------------------------- ##


##-=====================================-##
##   [+] Automatically with ParanoiDF
##-=====================================-##
paranoiDF.py -fl $File.pdf


##-======================================-##
##   [+] Display Malformed PDF Elements
##-=======================================-##
pdf-parser -v $File.pdf



## ---------------------------------------------------------------------- ##
	peepdf -fl $File.pdf         ## Examine PDF for risky tags 
								    ## And Malformed objects.
## ---------------------------------------------------------------------- ##
	pdfid $File.pdf                 ## Scan for risky keywords
								    ## And Flagged entries.
## ---------------------------------------------------------------------- ##
	pdfid --scan $File.pdf			## Scan Directory
## ---------------------------------------------------------------------- ##
	pdfid --disarm $File.pdf		## Disable JavaScript + autolaunch
## ---------------------------------------------------------------------- ##
	pdfid --verbose $File.pdf       ## Verbose (raises catched exceptions)
## ---------------------------------------------------------------------- ##
	pdfid --output=$File			## Output to log file
## ---------------------------------------------------------------------- ##
	pdfid --recursedir /$Dir/		## Recurse directories
## ---------------------------------------------------------------------- ##



##-======================================-##
##   [+] Display contents of object id
##-======================================-##
pdf-parser --object id $File.pdf     


##-===================================-##
##   [+] decode the object’s stream
##-===================================-##
pdf-parser --object id --filter --raw $File.pdf




dumppdf -a		# Dump all the objects. By default only the document trailer is printed.

dumppdf -i objno[,objno,...]		# Specifies PDF object IDs to display. Comma-separated IDs, or multiple -i options are accepted.

dumppdf -p pageno[,pageno,...]
           Specifies the comma-separated list of the page numbers to be
           extracted.

dumppdf -r option, the “raw” stream contents are dumped without
           decompression
           -b option, the decompressed contents are dumped
           as a binary blob.

dumppdf -t option, the decompressed contents are
           dumped in a text format, similar to repr() manner.
dumppdf -r or -b
           option is given, no stream header is displayed for the ease of
           saving it to a file.
dumppdf -T
           Show the table of contents.

dumppdf -P password
           Provides the user password to access PDF contents.

dumppdf -d
           Increase the debug level.


Dump all the headers and contents, except stream objects:
dumppdf -a test.pdf

Dump the table of contents:
dumppdf -T test.pdf

Extract a JPEG image:
dumppdf -r -i6 test.pdf > image.jpeg

