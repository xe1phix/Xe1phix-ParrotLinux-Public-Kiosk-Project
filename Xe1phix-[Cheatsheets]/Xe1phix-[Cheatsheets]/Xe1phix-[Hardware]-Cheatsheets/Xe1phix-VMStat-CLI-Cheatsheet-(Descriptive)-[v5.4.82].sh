#!/bin/sh
##-==================================================================-##
##   [+] Xe1phix-VMStat-CLI-Cheatsheet-(Descriptive)-[v5.4.82].sh
##-==================================================================-##
##
##
## ------------------------------------------------------------------------------------------------------------------------------------- ##
export TempDir='mktemp --tempdir=tmp.XXXXXXXXXX'
## ------------------------------------------------------------------------------------------------------------------------------------- ##
##
##
echo -e "\t_________________________________________________________________________"
echo -e "\t<<======= {+} Detailed statistics about partitions: {+} =======>>"
echo -e "\t##########################################################################"
vmstat --partition >> $TempDir/VmStatPart.txt && cat -vET $TempDir/VmStatPart.txt                                     # partition specific statistics
echo
echo
echo -e "\t_________________________________________________________________________"
echo -e "\t<<======= {+} Report some summary statistics about disk activity: {+} =======>>"
echo -e "\t##########################################################################"
vmstat --disk-sum >> $TempDir/VmStatDiskSum.txt && cat -vET $TempDir/VmStatDiskSum.txt                                     # summarize disk statistics
echo
echo
echo -e "\t_________________________________________________________________________"
echo -e "\t<<======= {+} Output Format Vmstat Will use: {+} =======>>"
echo -e "\t##########################################################################"
vmstat --unit k  >> $TempDir/VmStatKb.txt && cat -vET $TempDir/VmStatKb.txt                  # 1000 (k), 1024 (K),  1000000  (m), or  1048576  (M) bytes
echo
echo
echo -e "\t_________________________________________________________________________"
echo -e "\t<<======= {+} Display kernel slab cache information {+} =======>>"
echo -e "\t##########################################################################"
vmstat --slabs --once >> $TempDir/VmStatSlabCache.txt && cat -vET $TempDir/VmStatSlabCache.txt
echo
echo
echo -e "\t_________________________________________________________________________"
echo -e "\t<<======= {+} Report disk statistics: {+} =======>>"
echo -e "\t##########################################################################"
vmstat --disk >> $TempDir/VmStatDiskStats.txt && cat -vET $TempDir/VmStatDiskStats.txt                                          # disk statistics
echo
echo
echo -e "\t_________________________________________________________________________"
echo -e "\t<<======= {+} Displays a table of various event counters and memory statistics.: {+} =======>>"
echo -e "\t##########################################################################"
vmstat --stats >> $TempDir/VmstatStats.txt && cat -vET $TempDir/VmstatStats.txt                                            # event counter statistics
echo
echo
echo -e "\t_________________________________________________________________________"
echo -e "\t<<======= {+} Displays slabinfo: {+} =======>>"
echo -e "\t##########################################################################"
vmstat --slabs >> $TempDir/VmStatSlabinfo.txt && cat -vET $TempDir/VmStatSlabinfo.txt                                           # slabinfo
echo
echo
echo -e "\t_________________________________________________________________________"
echo -e "\t<<======= {+} Display  active and  inactive memory: {+} =======>>"
echo -e "\t##########################################################################"
vmstat --active >> $TempDir/VmStatMemState.txt && cat -vET $TempDir/VmStatMemState.txt                                          # active/inactive memory
