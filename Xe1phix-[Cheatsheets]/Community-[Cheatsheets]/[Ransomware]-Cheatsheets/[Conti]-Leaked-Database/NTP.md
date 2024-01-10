# NTP

## 01 - Manual

`$ ntpq -c readlist <IP>`

`$ ntpq -c readvar <IP>`

`$ ntpq -c peers <IP>`

`$ ntpq -c associations <IP>`

`$ ntpdc -c monlist <IP>`

`$ ntpdc -c listpeers <IP>`

`$ ntpdc -c sysinfo <IP>`

## 02 - Nmap

`$ sudo nmap -p 123 -sUV -Pn --script ntp-info,ntp-monlist <IP>`

`$ sudo nmap -p 123 -sUV --script "ntp* and (discovery or vuln) and not (dos or brute)" <IP>`

## References

- [Pentesting NTP](https://book.hacktricks.xyz/pentesting/pentesting-ntp)