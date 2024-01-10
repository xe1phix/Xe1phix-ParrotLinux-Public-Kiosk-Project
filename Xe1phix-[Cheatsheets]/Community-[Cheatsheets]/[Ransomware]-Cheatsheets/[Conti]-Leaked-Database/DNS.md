# DNS

## 01 - Manual

`$ for domain in $(cat subdomains.txt); do host $domain | grep "has address" --color=auto`

`$ cat subdomains.txt | xargs -P 10 -I {} host {} | grep "has address" --color=auto`

- **Pipe it to IPv4 addresses**

`$ for domain in $(cat subdomains.txt); do host $domain | grep "has address" | cut -d ' ' -f 4 | sort | uniq > ips.txt`

`$ cat subdomains.txt | xargs -P 10 -I {} host {} | grep "has address" | cut -d ' ' -f 4 | sort | uniq > ips.txt`

`$ for domain in $(cat subdomains.txt); do host $domain | grep "has address" | awk "{print $4}" | sort | uniq > ips.txt`

`$ cat subdomains.txt | xargs -P 10 -I {} host {} | grep "has address" | awk "{print $4}" | sort | uniq > ips.txt`

## 02 - DNSx

`$ dnsx -d <domain>.FUZZ -w wordlist.txt -resp`

## 03 - Subfinder

`$ subfinder -d <domain.com> -o subdomains.txt`

`$ subfinder -dL domains.txt -o subdomains.txt`

## 04 - Amass

`$ amass enum -active -d <website.com> -brute -w subdomains-wordlists.txt -src -ip -o subdomains.txt`

`$ amass intel -active -asn 222222 -ip`

`$ amass enum -d <website.com> > domains.txt && awk < domains.txt '{ system("resolveip -s "$1)}' > ips.txt`

## 05 - DNSRecon

`$ dnsrecon -d <domain> -t brt --threads 8 -D wordlist.txt`

## 06 - Fierce

### 6.1 - Fierce Python Version

`$ fierce --domain <domain.com> | grep Found | tee output.txt`

`$ fierce --domain <domain.com> --dictionary wordlist.txt | grep Found | tee output.txt`

- **Extract subdomains**

`$ awk -F ". " '{print $2}' output.txt > subdomains.txt`

- **Extract IPs**

`$ awk -F ". " '{print $3}' output.txt | sort -u | tr -d "()" > ips.txt`

### 6.2 - Fierce Perl Version

`$ fierce -dns <domain.com> -dns-servers <nameserver_IP>`

## 07 - Ffuf

`$ ffuf -u https://FUZZ.domain.com/ -w subdomains.txt -p 1 -f 301,401,403`

## 08 - Sublist3r2

### 8.1 - Setup

```
$ git clone https://github.com/RoninNakomoto/Sublist3r2.git && \
python3 -m venv ~/environments/sublist3r2 && \
source ~/environments/sublist3r2/bin/activate && \
python -m pip install --upgrade pip && \
cd ~/sublist3r2/ && pip install -r requirements.txt && \
deactivate
```

### 8.2 - Usage

`$ source ~/environments/sublist3r2/bin/activate`

`$ sublist3r2 -d website.com -b -t 64 -o subdomains.txt`

## 09 - Recon-ng

- **`brute_hosts` recon-ng module**
 
```
[recon-ng][default] > marketplace install recon/domains-hosts/brute_hosts

[recon-ng][default][brute_hosts] > modules load recon/domains-hosts/brute_hosts

[recon-ng][default][brute_hosts] > options set SOURCE <domain.com>

[recon-ng][default][brute_hosts] > run
```

## 10 - Knockpy

`$ knockpy <domain.com>`

`$ knockpy <domain.com> -t 30 -w subdomains.txt -w SecLists/Discovery/DNS/subdomains-top1million-5000.txt`

## 11 - DNSMap

`$ dnsmap -d <domain.com>`

## 12 - Gobuster

### 12.1 - Setup

```
$ go install github.com/OJ/gobuster/v3@latest && \
sudo cp ~/go/bin/gobuster /usr/local/bin
```

### 12.2 - Help Menu

### 12.3 - Usage

`$ gobuster dns -d <domain.com> -t 16 -w wordlist.txt`

## 13 - Nmap

`$ nmap -p 53 --script dns-check-zone --script-args="dns-check-zone.domain=<domain.com>" <IP>`

`$ nmap -p 53 --script dns-brute <IP>`

## 14 - Metasploit

- **Metasploit auxiliary module DNS Amplification Scanner**

```
msf > use auxiliary/scanner/dns/dns_amp

msf auxiliary(scanner/dns/dns_amp) > options

Module options (auxiliary/scanner/dns/dns_amp):

   Name        Current Setting  Required  Description
   ----        ---------------  --------  -----------
   BATCHSIZE   256              yes       The number of hosts to probe in each set
   DOMAINNAME  isc.org          yes       Domain to use for the DNS request
   FILTER                       no        The filter string for capturing traffic
   INTERFACE                    no        The name of the interface
   PCAPFILE                     no        The name of the PCAP capture file to process
   QUERYTYPE   ANY              yes       Query type(A, NS, SOA, MX, TXT, AAAA, RRSIG, DNSKEY, ANY)
   RHOSTS                       yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
   RPORT       53               yes       The target port (UDP)
   SNAPLEN     65535            yes       The number of bytes to capture
   THREADS     10               yes       The number of concurrent threads
   TIMEOUT     500              yes       The number of seconds to wait for new data


View the full module info with the info, or info -d command.

msf auxiliary(scanner/dns/dns_amp) > run threads=8 batchsize=<int> domainname=<domain.com> rhosts=<IP>
```

- **Metasploit auxiliary module DNS Record Scanner and Enumerator**

```
msf > use auxiliary/gather/enum_dns

msf auxiliary(gather/enum_dns) > options

Module options (auxiliary/gather/enum_dns):

   Name         Current Setting                              Required  Description
   ----         ---------------                              --------  -----------
   DOMAIN                                                    yes       The target domain
   ENUM_A       true                                         yes       Enumerate DNS A record
   ENUM_AXFR    true                                         yes       Initiate a zone transfer against each NS record
   ENUM_BRT     false                                        yes       Brute force subdomains and hostnames via the supplied wordlist
   ENUM_CNAME   true                                         yes       Enumerate DNS CNAME record
   ENUM_MX      true                                         yes       Enumerate DNS MX record
   ENUM_NS      true                                         yes       Enumerate DNS NS record
   ENUM_RVL     false                                        yes       Reverse lookup a range of IP addresses
   ENUM_SOA     true                                         yes       Enumerate DNS SOA record
   ENUM_SRV     true                                         yes       Enumerate the most common SRV records
   ENUM_TLD     false                                        yes       Perform a TLD expansion by replacing the TLD with the IANA TLD list
   ENUM_TXT     true                                         yes       Enumerate DNS TXT record
   IPRANGE                                                   no        The target address range or CIDR identifier
   NS                                                        no        Specify the nameservers to use for queries, space separated
   Proxies                                                   no        A proxy chain of format type:host:port[,type:host:port][...]
   RPORT        53                                           yes       The target port (TCP)
   SEARCHLIST                                                no        DNS domain search list, comma separated
   STOP_WLDCRD  false                                        yes       Stops bruteforce enumeration if wildcard resolution is detected
   THREADS      1                                            no        Threads for ENUM_BRT
   WORDLIST     /opt/metasploit/data/wordlists/namelist.txt  no        Wordlist of subdomains


View the full module info with the info, or info -d command.

msf auxiliary(gather/enum_dns) > run threads=10 [ns=<nameserver_IP_1>,<nameserver_IP_2>,<nameserver_IP_n>] domain=<website.com>
```

## References

- [Amass Tutorial](https://github.com/OWASP/Amass/wiki/Tutorial)

- [Amass User Guide](https://github.com/OWASP/Amass/wiki/User-Guide)

- [Amass Quick Tutorial Example Usage](https://allabouttesting.org/owasp-amass-quick-tutorial-example-usage/)