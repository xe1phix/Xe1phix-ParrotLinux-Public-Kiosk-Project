||                     DNS Record types ||              Methods           ||                  Description                          ||
||:-----:||:---------------------------:||:------------------------------:||:---------------------------------------------------------------------:||:-----------------------------------------------------------------------:||
||     A ||              Address Record ||  Returns a 32-bit IPv4 address || most commonly used to map hostnames to an IP address of the host      ||  but it is also used for DNSBLs, storing subnet masks in RFC 1101, etc  ||
|| CNAME ||       Canonical Name Record ||   Alias of one name to another || the DNS lookup will continue by retrying the lookup with the new name ||
||  AAAA ||         IPv6 Address Record || Returns a 128-bit IPv6 address || most commonly used to map hostnames to an IP address of the host      ||
||    MX ||        Mail Exchange Record || Maps a domain name to a list of message transfer agents for that domain|
||    NS ||          Name Server Record || Delegates a DNS zone to use the given authoritative name servers || 
||   SOA ||    zone of Authority Record || Specifies authoritative information about a DNS zone || including the primary name server, the email of the domain administrator, the domain serial number, and several timers relating to refreshing the zone.|
||   SPF ||     Sender Policy Framework || email-validation system designed to detect email spoofing || by providing a mechanism to allow receiving mail exchangers to check that incoming mail from a domain comes from a host authorized by that domain's administrators.|
||   TXT ||                 Text Record || arbitrary human-readable text in a DNS record ||
||:-----:||:---------------------------:||:--------------------------------------------------------------------------------:||:
||   PTR ||              Pointer Record || Pointer to a canonical name    || Unlike a CNAME, DNS processing stops and just the name is returned || 
||       ||                             || The most common use is for implementing reverse DNS lookups
||:-----:||:---------------------------:||:--------------------------------------------------------------------------------:||:
||   SRV ||             Service Locator || Generalized service location record || used for newer protocols instead of creating protocol-specific records such as MX ||
||  NSEC ||          Next Secure Record || Part of DNSSEC—used to prove a name does not exist. Uses the same format as the (obsolete) NXT record ||
||:-----:||:---------------------------:||:--------------------------------------------------------------------------------:||:
||  AXFR || Authoritative Zone Transfer || Transfer entire zone file from the master name server to secondary name servers
||       ||                             || A user or server will perform a specific zone transfer request from a name server.‖ 
||       ||                             || If the name server allows zone transfers to occur, all the DNS names and IP addresses 
||       ||                             || hosted by the name server will be returned in human-readable ASCII text ||
||:-----:||:---------------------------:||:--------------------------------------------------------------------------------:||
||  IXFR ||   Incremental Zone Transfer || Transfer entire zone file from the master name server to secondary name servers  ||
||:-----:||:---------------------------:||:--------------------------------------------------------------------------------:||
###     ####         ####              ####                         ####
||:------------------:||:-------------------------------------------:||
||       DNS Wildcard || Check if Nameserver enableS Wildcard Query  ||  (or DNS Faked)
||  Domain Bruteforce || Bruteforce Subdomains Using Wordlists       ||
||:------------------:||:-------------------------------------------:||
||\__________________/||\___________________________________________####__________________________________________/||
||  DNS Zone Transfer || replicate DNS data across a number of DNS servers, or to back up DNS files.               ||
||                    || A user or server will perform a specific zone transfer request from a name server         |‖ 
||                    || If the name server allows zone transfers to occur, all the DNS names and IP addresses     ||
||                    || hosted by the name server will be returned in human-readable ASCII text                   ||
||\__________________/||\_________________________________________________________________________________________/||
###                  \||/                         ####
||:------------------:||:-------------------------:||
|| Reverse Bruteforce ||  Reverse IP For Domain    ||
||     SRV Bruteforce ||  Bruteforce SRV Records   ||
||    gTLD Bruteforce ||  Bruteforce gTLD Records  ||
||     TLD Bruteforce ||  Bruteforce TLD Records   ||
||:------------------:||:-------------------------:||
###                  ####                         #### 

