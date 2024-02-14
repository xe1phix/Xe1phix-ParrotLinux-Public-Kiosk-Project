#!/bin/sh


##-=============================================================================-##
##   [+] Findomain - Export the data to a custom output file name:
##-=============================================================================-##
findomain -t $Domain -u $File.txt

##-=============================================================================-##
##   [+] Findomain - Search of only resolvable subdomains:
##-=============================================================================-##
findomain -t $Domain -r


##-=============================================================================-##
##   [+] Findomain - Search only resolvable subdomains, 
##                   Exporting the data to a custom output file.
##-=============================================================================-##
findomain -t $Domain -r -u $File.txt


##-=============================================================================-##
##   [+] Findomain - Search subdomains from a file containing list of domains
##-=============================================================================-##
findomain -f file_with_domains.txt


##-=============================================================================-##
##   [+] Findomain - Search subdomains from a file containing list of domains
##                   Save all the resolved domains into a custom file name:
##-=============================================================================-##
findomain -f file_with_domains.txt -r -u multiple_domains.txt


##-=============================================================================-##
##   [+] Findomain - Query the Findomain database created using Subdomains Monitoring.
##-=============================================================================-##
findomain -t $Domain --query-database


##-=============================================================================-##
##   [+] Findomain - Query the Findomain database created with Subdomains Monitoring and 
##                   Save results to a custom filename.
##-=============================================================================-##
findomain -t $Domain --query-database -u $File.txt


##-========================================================================-##
##   [+] Findomain - Import subdomains from several files 
##                   Work with them in the Subdomains Monitoring process:
##-========================================================================-##
findomain --import-subdomains $File1.txt $File2.txt $File3.txt -m -t $Domain



##   [+] Findomain - Connect to remote computer/server remote PostgreSQL server 
##                   Using a username, password and database
##   [+] Push the data to Telegram webhook


findomain_telegrambot_token="Your_Bot_Token_Here" 
findomain_telegrambot_chat_id="Your_Chat_ID_Here" 

findomain -m -t $Domain --postgres-user postgres --postgres-password psql  --postgres-host 192.168.122.130 --postgres-port 5432




https://github.com/Findomain/Findomain/blob/master/docs/docs/create_telegram_webhook.md



