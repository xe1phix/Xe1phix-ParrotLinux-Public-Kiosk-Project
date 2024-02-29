# Manual

## Banner Grabbing

`$ dig version.bind CHAOS TXT <domain.com>`

## Basic Queries

`$ dig ANY <domain.com> @<DNS_IP>`

`$ host -v -t ANY <domain.com>`

`$ nslookup -type=any <domain.com>`

- Query the primary IP address of the **Nameserver (NS)**

`$ dig NS <domain.com> @<DNS_IP>`

`$ host -t NS <domain.com>`

`$ nslookup -type=ns <domain.com>`

- Getting the **IPv4 address (A)** of the organization's domain website

`$ dig A <domain.com> @<DNS_IP>`

`$ host -t A <domain.com>`

`$ nslookup -type=a <domain.com>`

- Getting the **IPv6 address (AAAA)** of the organization's domain website

`$ dig AAAA <domain.com> @<DNS_IP>`

`$ host -t AAAA <domain.com>`

`$ nslookup -type=aaaa <domain.com>`

- Discovering the **Mail eXchange (MX)** Servers

`$ dig MX <domain.com> @<DNS_IP>`

`$ host -t MX <domain.com>`

`$ nslookup -type=mx <domain.com>`

- Query the **Canonical Name (CNAME)** of the website

`$ dig CNAME <www.domain.com> @<DNS_IP>`

`$ host -t CNAME <www.domain.com>`

`$ nslookup -type=cname <www.domain.com>`

- Discover **CertifiCate Authorities (CAA)** that Issues Certificates of the domain

`$ dig CAA <domain.com> @<DNS_IP>`

`$ host -t CAA <domain.com>`

`$ nslookup -type=caa <domain.com>`

- Find the physical Geographical **LOCation** **(LOC)** of the domain

`$ dig LOC <domain.com> @<DNS_IP>`

`$ host -t LOC <domain.com>`

`$ nslookup -type=loc <domain.com>`

- Query the **Text Record (TXT)** information of the domain

`$ dig TXT <domain.com> @<DNS_IP>`

`$ host -t TXT <domain.com>`

`$ nslookup -type=txt <domain.com>`

- Lookup the **IP's SIP server** of the domain

`$ nslookup -type=srv _sip._tcp.<domain.com> <DNS_IP>`

`$ dig A <sip.domain.com> @<DNS_IP>`

`$ host -t A <sip.domain.com>`

`$ nslookup -type=a <sip.domain.com>`

- Finding the administrative email which is the **zone of authority record** **(SOA)** of the domain

`$ dig SOA <domain.com> @<DNS_IP>`

`$ host -t SOA <domain.com>`

`$ host -C <domain.com>`

`$ nslookup -type=SOA <domain.com>`

- Enumerate the domain's source **Pointer (PTR)** IP address that corresponds to

`$ dig -x <PTR_IP> @<DNS_IP>`

- Using nslookup performing a reverse dns lookups on the internal network

`$ nslookup`

```
C:\> nslookup -type=<DNS_record_type>

> server <IP_DNS>
> <target_IP>
```

## Zone Transfer

- Query the IP without the domain name with records of subdomains and other IP addresses (axfr)

`$ dig axfr @<DNS_IP>`

- Lookup the **IP's LDAP server** of the domain

`$ nslookup -type=srv _ldap._tcp.<domain.com> @<DNS_IP>`

`$ dig A <ldap.domain.com> @<DNS_IP>`

`$ dig axfr <domain.com> @<DNS_IP>`

- Enumerate the subdomain's that only reverse DNS entry exists for the domain with IPv4 addresses (for example it owns **192.168.*.***)

`$ dig axfr -x 192.168 @<DNS_IP>`

- Enumerate the subdomain's that only reverse DNS entry exists for the domain with IPv6 addresses

`$ dig axfr -x 2a00:1450:400c:c06::93 @<DNS_IP>`

- Enumerate DNS subdomains via zonetransfer via `host`

`$ host -l <domain.com> <dns_nameserver>`

## DNSSEC

- Query the **Key ID** of the **Key Signing Key (KSK)** of the domain **(DNSKEY)**

`$ dig DNSKEY <domain.com> +multiline @<DNS_IP>`

- The **RRSIG A** record of the domain

`$ dig A <domain.com> +multiline @<DNS_IP> +noadditional +dnssec +multiline`

- Retrieve information of the **Salt** used for the hash calculation for **NSEC3 (NSEC3PARAM)**

`$ dig NSEC3PARAM <domain.com> @<DNS_IP>`

- Lookup **RRSIG** records that exists for the organization's domain

`$ dig RRSIG <domain.com> +short @<DNS_IP>`

## References

- [Pentesting DNS](https://book.hacktricks.xyz/pentesting/pentesting-dns)

- [Tutorial Nslookup Host Dig Whois DNS Information Gathering](https://securityonline.info/tutorial-nslookuphostdigwhois-dns-information-gathering/)

- [How to Gather DNS Information](https://github.com/nixawk/pentest-wiki/blob/master/1.Information-Gathering/How-to-gather-dns-information.md)

- [Host Command in Linux with Examples](https://www.geeksforgeeks.org/host-command-in-linux-with-examples/)