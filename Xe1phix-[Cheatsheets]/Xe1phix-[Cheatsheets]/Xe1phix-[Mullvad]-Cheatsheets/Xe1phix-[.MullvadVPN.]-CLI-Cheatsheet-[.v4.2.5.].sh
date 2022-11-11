
##-=======================-##
##    [+] Show account info
##-=======================-##
mullvad account get


##-=====================================-##
##     [+] Set + Save Mullvad Account Number 
##-=====================================-##
mullvad account set 1234123412341234


##-========================-##
##     [+] List server locations:
##-========================-##
## ------------------------------------------------------------------------------ ##
##     [?] Display a list of available countries and cities.
## ------------------------------------------------------------------------------ ##
mullvad relay list


##-=====================-##
##     [+] Select a location
##-=====================-##
mullvad relay set location se mma


##-==========================-##
##     [+] Select a specific server
##-==========================-##
mullvad relay set location se mma se-mma-001


##-=========================================-##
##    [+] Connect to the location that you selected
##-=========================================-##
mullvad connect


##-=================-##
##     [+] Disconnect
##-=================-##
mullvad disconnect


##-=================================-##
##     [+] Force an update to the serverlist
##-=================================-##
mullvad relay update


##-================================-##
##     [+] Check Your Connection Status
##-================================-##
mullvad status


##-==================================-##
##     [+] Auto-Connect Mullvad on Start-up
##-==================================-##
mullvad auto-connect set on


##-=========================-##
##     [+] Turn Auto-Connect off
##-=========================-##
mullvad auto-connect set off


##-=======================================-##
##    [+] Check if you are connected to Mullvad
##-=======================================-##
curl https://am.i.mullvad.net/connected


##-============================-##
##     [+] IPduh.com / Privacy Test
##-============================-##
https://ipduh.com/privacy-test/


##-===================================-##
##     [+] DNS Leak + Fingerprinting Tests:
##-===================================-##
http://check2ip.com/
http://dnsleak.com/
https://dnsleaktest.com/

