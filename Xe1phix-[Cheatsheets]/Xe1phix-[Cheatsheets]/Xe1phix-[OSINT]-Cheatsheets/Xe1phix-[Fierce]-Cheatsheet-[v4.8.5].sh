#!/bin/sh
##-======================================-##
##   [+] Xe1phix-[Fierce]-Cheatsheet.sh
##-======================================-##


##-=========================-##
##  [+] Fierce
##-=========================-##
fierce -dns $Domain
fierce -dns $Domain -file $OutputFile
fierce -dns $Domain -dnsserver $Server
fierce -range $IPRange -dnsserver $Server
fierce -dns $Domain -wordlist $Wordlist
fierce -dnsserver $DNS -dns $Domain -wordlist /usr/share/fierce/hosts.txt


fierce -dns $Domain -threads 3



##-============================================================================-##
##   [+] 
##-============================================================================-##
fierce --domain $Domain --subdomains accounts --traverse 10


##-============================================================================-##
##   [+] Limit nearby IP traversal to certain domains with the --search flag:
##-============================================================================-##
fierce --domain $Domain --subdomains admin --search $Domain $Domain


##-==================================================================================-##
##   [+] Attempt an HTTP connection on domains discovered with the --connect flag:
##-==================================================================================-##
fierce --domain $Domain --subdomains mail --connect


