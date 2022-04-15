#!/bin/sh
##-==================================================================-##
##   [+] Xe1phix-VMStat-CLI-Cheatsheet-(Descriptive)-[v5.4.82].sh
##-==================================================================-##
##
##
## ------------------------------------------------------------------------------------------------------------------------------------- ##
export TempDir='mktemp --tempdir=tmp.XXXXXXXXXX'
## ------------------------------------------------------------------------------------------------------------------------------------- ##

echo -e "\t_________________________________________________________________________"
echo -e "\t<<======= {+} Detailed statistics about partitions: {+} =======>>"
echo -e "\t##########################################################################"
vmstat --partition >> $TEMP_DIR/VmStatPart.txt && cat -vET $TEMP_DIR/VmStatPart.txt                                     # partition specific statistics
echo
echo
echo -e "\t_________________________________________________________________________"
echo -e "\t<<======= {+} Report some summary statistics about disk activity: {+} =======>>"
echo -e "\t##########################################################################"
vmstat --disk-sum >> $TEMP_DIR/VmStatDiskSum.txt && cat -vET $TEMP_DIR/VmStatDiskSum.txt                                     # summarize disk statistics
echo
echo
echo -e "\t_________________________________________________________________________"
echo -e "\t<<======= {+} Output Format Vmstat Will use: {+} =======>>"
echo -e "\t##########################################################################"
vmstat --unit k  >> $TEMP_DIR/VmStatKb.txt && cat -vET $TEMP_DIR/VmStatKb.txt                  # 1000 (k), 1024 (K),  1000000  (m), or  1048576  (M) bytes
echo
echo
echo -e "\t_________________________________________________________________________"
echo -e "\t<<======= {+} Display kernel slab cache information {+} =======>>"
echo -e "\t##########################################################################"
vmstat --slabs --once >> $TEMP_DIR/VmStatSlabCache.txt && cat -vET $TEMP_DIR/VmStatSlabCache.txt
echo
echo
echo -e "\t_________________________________________________________________________"
echo -e "\t<<======= {+} Report disk statistics: {+} =======>>"
echo -e "\t##########################################################################"
vmstat --disk >> $TEMP_DIR/VmStatDiskStats.txt && cat -vET $TEMP_DIR/VmStatDiskStats.txt                                          # disk statistics
echo
echo
echo -e "\t_________________________________________________________________________"
echo -e "\t<<======= {+} Displays a table of various event counters and memory statistics.: {+} =======>>"
echo -e "\t##########################################################################"
vmstat --stats >> $TEMP_DIR/VmstatStats.txt && cat -vET $TEMP_DIR/VmstatStats.txt                                            # event counter statistics
echo
echo
echo -e "\t_________________________________________________________________________"
echo -e "\t<<======= {+} Displays slabinfo: {+} =======>>"
echo -e "\t##########################################################################"
vmstat --slabs >> $TEMP_DIR/VmStatSlabinfo.txt && cat -vET $TEMP_DIR/VmStatSlabinfo.txt                                           # slabinfo
echo
echo
echo -e "\t_________________________________________________________________________"
echo -e "\t<<======= {+} Display  active and  inactive memory: {+} =======>>"
echo -e "\t##########################################################################"
vmstat --active >> $TEMP_DIR/VmStatMemState.txt && cat -vET $TEMP_DIR/VmStatMemState.txt                                          # active/inactive memory
