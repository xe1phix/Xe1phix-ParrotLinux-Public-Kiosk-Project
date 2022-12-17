#!/bin/sh


##-===================================================-##
##   [+] 
##-===================================================-##
nfdump -r $File -o "fmt:<fmt str>"



##-====================================================-##
##   [+] Extract Src Address and Dst Address Packets
##-====================================================-##
nfdump -r $File -o "fmt:%pkt,%sa,%da" > $File.csv



## -------------------------------------------------- ##
##    [?] Packets					| %pkt |
##    [?] Src Address       	|  %sa |
##    [?] Dst Address       	|  %da |
##    [?] TCP Flags          		|  %flg |
##    [?] Protocol          		|   %pr |
##    [?] Src Address:Port   | %sap |
##    [?] Dst Address:Port   | %dap |
## -------------------------------------------------- ##


##-=========================================-##
##   [+] Read From File, Extracting Out:
##-=========================================-##
##   > Packets
##   > Src Address:Port
##   > Dst Address:Port
##   > TCP Flags
##-=========================================-##
nfdump -r $File -o "fmt:%pkt,%sap,%dap,%flg" > $File.csv



##-=============================================-##
##   [+] View the “topN” talkers to identify 
##       the noisiest IPs by flow count.
##-=============================================-##
nfdump -r $File -s ip/flows -n 10


##-================================================================-##
##   [+] Display a limited number of records with the -c switch.
##-================================================================-##
nfdump -r $File -c <record_limit>



