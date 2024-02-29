

----
##-=========================-##
##   [+] Fuzz files and directories
##-=========================-##


##-=========================-##
##     [+] WFuzz - Fuzz for files:
##-=========================-##
wfuzz -c -z file,/usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt --hc 404 -t 200 -f recon/wfuzz-files.out "$URL/FUZZ" 


##-=========================-##
##    [+] Feroxbuster - 
##-=========================-##
feroxbuster --url $URL -e -x .php,txt,html -w /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt -o recon/ferox.out


##-=========================-##
##   [+] WFuzz - Fuzz for: Directories:
##-=========================-##
wfuzz -c -z file,/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt --hc 404 -t 200 -f recon/wfuzz-dirs.out "$URL/FUZZ/"


##-=========================-##
##    [+] ffuf - Fuzz for: 
##-=========================-##
ffuf -c -u $URL/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt -t 200 -o recon/ffuf.md


##-=========================-##
##    [+] Dirb - Fuzz for: 
##-=========================-##
dirb $URL /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 200 -o recon/dirb.out 
dirbuster -r recon/dirbuster.out


##-=========================-##
##    [+] GoBuster - Fuzz for: 
##-=========================-##
gobuster dir -u $URL -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 200 -o recon/gobuster.out


##-=========================-##
##   [+] ffuf - change request method
##-=========================-##
ffuf -c -t 200 -fs 50,182 -u "$URL/FUZZ/" -w /usr/share/wordlists/dirb/big.txt -o recon/ffuf-post_method.md -t 200 -X POST


##-=========================-##
##   [+] ffuf - FUZZ file extensions
##-=========================-##
ffuf -u $URL/indexFUZZ -w /usr/share/seclists/Discovery/Web-Content/web-extensions.txt -o recon/ffuf-ext.md -t 200


##-=========================-##
##    [+] ffuf - 
##-=========================-##
ffuf -c -u $URL/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-words-lowercase.txt -e .sh,.cgi,.pl,.py -fc 404 -t 200 -o recon/ffuf-extensions.md


##-=========================-##
##   [+] ffuf - FUZZ Parameters:
##-=========================-##

## ---------------------------------------------------- ##
##   [?] don't forget to include:
##        LFI or RFI statements
## ---------------------------------------------------- ##

ffuf -u "$URL/?FUZZ=1" -c -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -fw 39 -t 200


##-=========================-##
##    [+] ffuf - 
##-=========================-##
for i in {0..255}; do echo $i; done | ffuf -u '$URL?id=FUZZ' -c -w - -fw 33 -t 200 -o recon/sequence.md


##-=========================-##
##    [+] 


##-=========================-##
##   [+] WFuzz - bruteforce login
##-=========================-##
wfuzz -c -z file,users.txt -z file,pass.txt -d "name=FUZZ&password=FUZ2Z" --sc 200 --hh 206 -t 200 $URL/login.php


##-=========================-##
##    [+] Hydra - Check type: 
##-=========================-##
##    [+] GET or POST request 
##-=========================-##
hydra -I -V -F -l admin -P /usr/share/wordlists/rockyou.txt $IP http-post-form "/login.php:username=admin&password=^PASS^:Invalid Password:H=Cookie: PHPSESSID=cd892e2HNW3N" -t 64


##-=========================-##
##    [+] 

##-=========================-##
##   [+]  

##-=========================-##
##   [+] WFuzz - subdomain bruteforce  - Fuzzing
##-=========================-##
wfuzz -c -f subdomains.txt -w /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt --hl 7 -t 200 -u "$URL" -H "Host: FUZZ.$domain"


##-=========================-##
##    [+]  - Fuzz for: 
##-=========================-##
gobuster vhost -u $URL -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -t 200



##-=========================-##
##    [+] 

##-=========================-##
##   [+] vulnerability scanners
##-=========================-##
nikto --host $URL -C all -o recon/nikto.txt 
whatweb -a 4 $URL