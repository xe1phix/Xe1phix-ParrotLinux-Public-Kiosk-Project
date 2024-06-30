# OSCP_Command
#Web Content Enumeration 
1. wfuzz help 
* wfuzz -h 

2. File Discovery :
   
<code> wfuzz -c -z file,/usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt --hc 301,404,403 "$URL"</code>
* wfuzz -c -z file,/usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt --hc 301,404,403 "$URL"

3. Directory Discovery : 
* wfuzz -c -z file,/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt --hc 301,404,403 "$URL"

4. Parameter Discovery : 
*  export URL="http://offsecwp:80/index.php?FUZZ=data"
*  wfuzz -c -z file,/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt --hc 301,404,403 "$URL"

5. Fuzzing Parameter Value : 
*  export URL="http://offsecwp:80/index.php?fpv=FUZZ"
*  wfuzz -c -z file,/usr/share/seclists/Usernames/list-default-usernames.txt --hc 301,404,403 "$URL"

5. Authenticated fuzzing :
* wfuzz -c -b "<SESSION>=<SESSIONVALUE>" -z file,/usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt --hc 301,404,403 "$URL"
* wfuzz -c -b "<SESSION>=<SESSIONVALUE>" -z file,/usr/share/seclists/Discovery/Web-Content/raft-medium-directies.txt --hc 301,404,403 "$URL"
