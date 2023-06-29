#!/bin/sh
##-================================-##
##   [+] Xe1phix-Binwalk-v*.*.sh
##-================================-##
##
## -------------------------------------------------------- ##
##   [?] https://github.com/devttys0/binwalk/wiki/Usage
## -------------------------------------------------------- ##



##-=========================================================================-##
##   [+] Scan a firmware image for embedded file types and file systems;
##-=========================================================================-##
binwalk $Firmware.bin


##-====================================================================================================-##
##  <<+}==================|-: Extract any files found in the firmware image -:|===================={+>>
## ---------------------------------------------------------------------------------------------------- ##
##   [?] Set the output directory to send the extracted data to
## ---------------------------------------------------------------------------------------------------- ##
##-====================================================================================================-##
binwalk ‐e ‐‐directory=/tmp $Firmware.bin


##-=======================================================================================================-##
##  <<+}====================|:- // Carve data from Specified file(s) \\ -:|==========================={+>>
##  <<+}====================|:-//Dont auto extract/decompress the data\\-:|==========================={+>>
##-=======================================================================================================-##
binwalk ‐e ‐‐carve $Firmware.bin



##-===========================================================================================================-##
##  <<+}==================|:- Log file identical to that displayed in the terminal -:|===================={+>>
##-===========================================================================================================-##
binwalk ‐‐log=binwalk.log $Firmware.bin



##-===========================================================================================================-##
##  <<+}============================|:- Disables output to stdout -:|===================================={+>>
##-===========================================================================================================-##
binwalk ‐‐quiet ‐f binwalk.log $Firmware.bin


##-========================================================================================-##
## ---------------------------------------------------------------------------------------- ##
##  <<+}====================|:- ,____________Enable___________,-:|===================={+>>
##  <<+}====================|:-  |_+_-Verbose Output         | -:|===================={+>>
##  <<+}====================|:-  |_+_-File MD5SUM Generation | -:|===================={+>>
##  <<+}====================|:-  |_+_-Scan Timestamping      | -:|===================={+>>
## ---------------------------------------------------------------------------------------- ##
##-========================================================================================-##
binwalk ‐‐verbose $Firmware.bin


##-====================================================================-##
##   [+] This performs a signature analysis of the specified files
##-====================================================================-##
binwalk ‐‐signature $Firmware.bin


##-====================================================================-##
##   [+] search the specified file(s) for executable opcodes
##          common to a variety of CPU architectures.
##-====================================================================-##
binwalk ‐A $Firmware.bin
binwalk --opcodes $Firmware.bin


##-===========================================================-##
##   [+] search the specified file(s) for a custom string
##-===========================================================-##
binwalk ‐R "\x00\x01\x02\x03\x04" $Firmware.bin



##-=======================================================================-##
##   [+] Attempts to identify the CPU architecture of executable code
##       contained in a file, using the capstone disassembler.
##-=======================================================================-##
binwalk ‐‐disasm $Firmware.bin
­binwalk ‐Y $Firmware.bin


##-===========================================================-##
##   [+] Set the minimum number of consecutive instructions
##       for a ­­disasm result to be considered valid.
##-===========================================================-##
## ----------------------------------------------------------- ##
##   [?] The default is 500 instructions
## ----------------------------------------------------------- ##
binwalk ‐‐minsn=1200 ‐Y firmware.bin



##-===========================================================-##
##   [+] Instruct ­­disasm to not stop at the first result
##-===========================================================-##
binwalk ‐‐continue ‐Y $Firmware.bin


##-====================================-##
##   [+] Performs data carving only
##-====================================-##
binwalk ‐e ‐‐carve $Firmware.bin


##-=====================================================-##
##   [+] Reverses every n bytes before scanning them
##-=====================================================-##
binwalk ‐‐swap=2 $Firmware.bin


##-============================================================-##
##   [+] Formats output to the current terminal window width
##-============================================================-##
binwalk ‐‐term $Firmware.bin




binwalk ‐‐quiet ‐f binwalk.log $Firmware.bin


##-================================================================-##
##   [+] Loads common ­­dd extraction rules from a predefined file
##-================================================================-##
binwalk --extract
binwalk ‐e firmware.bin


##-===========================================================================-##
##   [+] dd - Extract any signature that contains the string 'zip archive'
##            ++ And also has the .zip file extension.
##            -> Execute the 'unzip' command.
##-===========================================================================-##
## --------------------------------------------------------------------------- ##
##   [?] Note the use of the '%e' placeholder.
## --------------------------------------------------------------------------- ##
##   [?] This placeholder will be replaced with the relative path
##       to the extracted file when the unzip command is executed:
## --------------------------------------------------------------------------- ##
##-===========================================================================-##
##
##
##-===========================================================================-##
##                          [+] ­­dd Options
##-===========================================================================-##
## --------------------------------------------------------------------------- ##
## -> type    ## Type String (Lower case string)
## --------------------------------------------------------------------------- ##
##            ## [?] Found in the signature description
##            ## [?] (Regular expressions are supported)
## --------------------------------------------------------------------------- ##
## -> ext     ## File Extension to use when saving the data disk
## -> cmd     ## Command to execute after the data has been saved to disk
## --------------------------------------------------------------------------- ##
##-===========================================================================-##
binwalk ‐D 'zip archive:zip:unzip %e' $Firmware.bin

­­binwalk ‐-dd=<$type:$ext[:$cmd]> $Firmware.bin

­­binwalk ‐-dd='7z archive:7z: %e' $Firmware.bin

­­binwalk ‐-dd=' %e' $Firmware.bin



##-==============================================================================-##
##   [+] Matryoshka - Recursively scan extracted files during a ­­signature scan
##-==============================================================================-##
## ------------------------------------------------------------------------------ ##
##   [?] Only valid when used with ­­extract or ­­dd
## ------------------------------------------------------------------------------ ##
binwalk ‐e ‐M $Firmware.bin
binwalk ‐Me $Firmware.bin
­­binwalk --matryoshka --extract $Firmware.bin


##-===================================================================-##
##   [+] Performs an entropy analysis on the input file(s)
##-===================================================================-##
## ------------------------------------------------------------------- ##
##   [?] When combined with the ­­verbose option,
##       the raw entropy calculated for each data block is printed:
## ------------------------------------------------------------------- ##
binwalk ‐E ‐‐verbose $Firmware.bin


##-========================================================-##
##   [+] Combine a signature scan with an entropy scan:
##-========================================================-##
binwalk ‐B ‐E $Firmware.bin




##-===================================================================-##
##   [+] Load an alternate magic signature file
##-===================================================================-##
## ------------------------------------------------------------------- ##
##   [?] http://binwalk.org/wiki/custom-magic-signatures/
## ------------------------------------------------------------------- ##
binwalk ‐m $File.mgc $Firmware.bin


##-===================================================================-##
##   [+]
##-===================================================================-##
## ------------------------------------------------------------------- ##
##   [?]
## ------------------------------------------------------------------- ##


##-===================================================================-##
##   [+] Automatically saves the entropy plot generated by ­­entropy
##-===================================================================-##
binwalk --save
--entropy
--nplot
--hexdump
--strings
--3D



##-==============================================================-##
##   [+] Automatically saves the entropy plot generated
##       by ­­entropy to a PNG file instead of displaying it.
##-==============================================================-##
binwalk ‐‐save ‐E $Firmware.bin


##-========================================================================-##
##   [+] Omits the legend from the entropy plot(s) generated by ­­entropy:
##-========================================================================-##
binwalk ‐‐entropy ‐Q $Firmware.bin
binwalk ‐‐entropy --nlegend $Firmware.bin




##-===================================================================-##
##   [+] Disables graphical entropy plots for the ­­entropy scan.
##-===================================================================-##
binwalk ‐‐entropy ‐N $Firmware.bin
­­binwalk ‐‐entropy --nplot $Firmware.bin



##-=========================================================-##
##   [+] Sets the rising edge entropy trigger level.
##-=========================================================-##
## --------------------------------------------------------- ##
##   [?] specified value should be between 0 and 1:
## --------------------------------------------------------- ##
binwalk ‐‐entropy ‐H .9 $Firmware.bin
binwalk ‐‐entropy --­­high=$Float $Firmware.bin
binwalk ‐‐entropy --­­high=.9 $Firmware.bin



##-===================================================================-##
##   [+] Sets the falling edge entropy trigger level.
##-===================================================================-##
## ------------------------------------------------------------------- ##
##   [?] specified value should be between 0 and 1:
## ------------------------------------------------------------------- ##
binwalk ‐‐entropy ‐L .3 $Firmware.bin
­­binwalk ‐-entropy ‐‐low=.3 $Firmware.bin





##-=========================================================================-##
##  [+] Hexdump - Performs a hexdump of input file(s) + color­codes bytes
##-=========================================================================-##
## ------------------------------------------------------------------------- ##
## -> Green   [?] These bytes were the same in all files
## -> Red     [?] These bytes were different in all files
## -> Blue    [?] These bytes were only different in some files
## ------------------------------------------------------------------------- ##
##
## ----------------------- ##
##  [+] Useful Options: ­­
## ----------------------- ##
##     --> block ­­
##     --> offset
##     --> length
##     --> terse
## ------------------------------------------------------------------------- ##
##-=========================================================================-##
binwalk ‐W ‐‐block=8 ‐‐length=64 $Firmware1.bin $Firmware2.bin $Firmware3.bin
­­binwalk --hexdump ‐‐block=8 ‐‐length=64 $Firmware1.bin $Firmware2.bin $Firmware3.bin






##-=============================================================================-##
##  [+] Green - Only display lines that contain green bytes during a ­­hexdump:
##-=============================================================================-##
binwalk ‐W ‐‐green firmware1.bin firmware2.bin firmware3.bin



##-==========================================================================-##
##  [+] Red - Only display lines that contain red bytes during a ­­hexdump:
##-==========================================================================-##
binwalk ‐W ‐‐red firmware1.bin firmware2.bin firmware3.bin


##-============================================================================-##
##  [+] Blue - Only display lines that contain blue bytes during a ­­hexdump:
##-============================================================================-##
binwalk ‐W ‐‐blue firmware1.bin firmware2.bin firmware3.bin



­­##-======================================================================================-##
##  [+] Terse - When performing a ­­hexdump, only display a hex dump of the first file.
­­##-======================================================================================-##
## -------------------------------------------------------------------------------------- ##
##   [?] Useful when diffing many files that dont all fit on the screen:
## -------------------------------------------------------------------------------------- ##
binwalk ‐W ‐‐terse firmware1.bin firmware2.bin firmware3.bin





##-================================================-##
##   [+] Log scan results to the specified file.
##-================================================-##
binwalk ‐‐log=$binwalk.log $Firmware.bin

##-==================================================-##
##   [+] Causes log data to be saved in CSV format.
##-==================================================-##
binwalk ‐‐log=$binwalk.log ‐‐csv $Firmware.bin

##-====================================================-##
##   [+] Set the output directory for extracted data
##-====================================================-##
binwalk --carve --­­directory=/$Dir/



binwalk --strings --verbose ‐‐log=/var/log/binwalk.log /lib/x86_64-linux-gnu/libuuid.so.1




--opcodes
--signature




--verbose --csv --log=





echo -e "\t<<+}========  =========={+>>"

echo -e "\t<<+}========  =========={+>>"
binwalk ‐‐signature $Firmware.bin

##-====================================================-##
##   [+] Search for a custom sequence of raw bytes:
##-====================================================-##
binwalk ‐R "\x00\x01\x02\x03\x04" $Firmware.bin

­­binwalk --raw=$String $Firmware.bin


echo -e "\t<<+}======== opcode signatures =========={+>>"
binwalk ‐A $Firmware.bin

echo -e "\t<<+}======== Loads common ­­dd extraction rules from a predefined file. =========={+>>"
##  ##
binwalk ‐e $Firmware.bin

­D, ­­dd=<type:ext[:cmd]>

binwalk ‐D 'zip archive:zip:unzip %e' $Firmware.bin

##-===================================================================-##
##   [+]
##-===================================================================-##
## ------------------------------------------------------------------- ##
##   [?]
## ------------------------------------------------------------------- ##





##-===================================================================-##
##   [+] Excludes signatures that match the specified exclude filter
##-===================================================================-##
## ------------------------------------------------------------------- ##
##   [?] exclude HP calculator and OSX mach‐o signatures
## ------------------------------------------------------------------- ##
binwalk ‐x 'mach‐o' ‐x '^hp' $Firmware.bin
­­binwalk --exclude='mach‐o' --exclude='^hp' $Firmware.bin



##-=========================================================================-##
##   [+] Includes only signatures that match the specified include filter.
##-=========================================================================-##
## ------------------------------------------------------------------------- ##
##   [?] only search for filesystem signatures
## ------------------------------------------------------------------------- ##
binwalk ‐y 'filesystem' $Firmware.bin
­­­­binwalk --include='filesystem' $Firmware.bin




##-===================================================================-##
##   [+]
##-===================================================================-##
## ------------------------------------------------------------------- ##
##   [?]
## ------------------------------------------------------------------- ##


--matryoshka --directory=~/man/ --save --csv --log= --term
--depth=
--hexdump

--deflate
--terse

--nlegend                Omit the legend from the entropy plot graph
--nplot                  Do not generate an entropy plot graph


--status= --quiet




binwalk --verbose ‐‐signature $Firmware.bin --extract --directory=~/man/ --save --csv --log=~/man/mod.log --term


##-===================================================================-##
##   [+]
##-===================================================================-##
## ------------------------------------------------------------------- ##
##   [?]
## ------------------------------------------------------------------- ##


##-============================================================-##
##   [+] Displays all results, even those marked as invalid.
##-============================================================-##
binwalk --verbose --invalid $Firmware.bin
binwalk ‐I $Firmware.bin





echo "#####################################################################"
echo "Binwalk signatures and system-wide configuration files can be updated"
echo "to the latest from the SVN trunk with the --update option "
echo "#####################################################################"
echo "______________________"
/usr/bin/binwalk --update
echo "______________________"

echo "#####################################################################"
echo "## To see more verbose information specify the --verbose option. ##"
echo "####################################################################"
echo "____________________________________________"
/usr/bin/binwalk --verbose firmware.bin
echo "_____________________________________________"


echo "#########################################################"
echo "Output can be logged to a file with the --file option:"
echo "########################################################"
echo "____________________________________________"
/usr/bin/binwalk --file=binwalk.log firmware.bin
echo "____________________________________________"

echo "########################################################"
echo "Output to stdout can be suppressed with the --quiet option:"
echo "########################################################"
echo "____________________________________________"
binwalk --file=binwalk.log --quiet firmware.bin
echo "____________________________________________"


echo "#########################################################################"
echo "By default, scans start at the first byte of the specified file (offset 0) and end"
echo "at the end of the specified file. These settings can be controlled with the"
echo " --offset and --length options, respectively. For example, the following "
echo " command will scan 128 bytes starting at offset 64:"
echo "#########################################################################"
echo "____________________________________________"
binwalk --offset=64 --length=128 firmware.bin
echo "____________________________________________"


echo "#########################################################################"
echo "By default, binwalk will scan every byte for possible signatures. "
echo "To scan every 2 bytes, 4 bytes, 8 bytes, etc, use the --align option:"
echo "#########################################################################"
echo "____________________________________________"
binwalk --align=4 firmware.bin
echo "____________________________________________"

echo "#########################################################################"
echo "By default binwalk will use the signatures from the magic.binwalk file, "
echo "but you may specify an alternate signature file with the --magic option:"
echo "#########################################################################"
echo "____________________________________________"
binwalk --magic=/usr/share/misc/magic firmware.bin
echo "____________________________________________"

echo "########################################################"
echo "To search for a sequence of bytes without creating a "
echo "signature file use the --raw-bytes option:"
echo "########################################################"
echo "____________________________________________"
binwalk --raw-bytes="\x00\x01\x02\x03" firmware.bin
echo "____________________________________________"




0x66637279,
0x696F6E00
0x6D643235
0xAE726D,
0xCF736565,



header size: 256, board id: "p512"

NOR version 0x100, 256 blocks, 0x303040 pages per block, 0x679a00 bytes per page

