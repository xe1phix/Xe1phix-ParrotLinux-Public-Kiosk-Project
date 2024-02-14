#!/bin/sh
## Sleuthkit-Foremost-Cheatsheet-[v*.*.**].sh


## The Sleuthkit Command-line tools:
##  • ils lists inode information from the image.
##  • ffind finds the file or directory name using the inode.
##  • icat outputs the file content based on its inode number.



##-========================================================================-##
##  [+] Foremost Carves out files based on headers and footers
##-========================================================================-##
## ------------------------------------------------------------------------ ##
##  [?] data_file.img = raw data, slack space, memory, unallocated space
## ------------------------------------------------------------------------ ##
foremost –o $outputdir –c /$path/$foremost.conf $File.img



## --------------------------------------------------------- ##
##  [?] Search jpeg format skipping the first 100 blocks
## --------------------------------------------------------- ##
foremost -s 100 -t jpg -i $File.dd


## --------------------------------------------------------------------------- ##
##  [?] Only generate an audit file, and print to the screen (verbose mode)
## --------------------------------------------------------------------------- ##
foremost -av $File.dd


## ---------------------------------- ##
##  [?] Search all defined types:
## ---------------------------------- ##
foremost -t all -i $File.dd


## ---------------------------------- ##
##  [?] Search for gif and pdf's:
## ---------------------------------- ##
foremost -t gif,pdf -i $File.dd


## -------------------------------------------------- ##
##  [?] Search for office documents and jpeg files
## -------------------------------------------------- ##
foremost -vd -t ole,jpeg -i $File.dd




