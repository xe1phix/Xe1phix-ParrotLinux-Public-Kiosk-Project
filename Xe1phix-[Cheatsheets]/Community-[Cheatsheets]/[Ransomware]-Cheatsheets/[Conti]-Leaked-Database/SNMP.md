# SNMP

## 01 - Manual

### 1.1 - Usage

#### 1.1.1 - Snmp-check

`$ snmp-check <IP>`

`$ snmp-check -v2c -c public <IP>`

`$ snmp-check -p <PORT> <IP>`

#### 1.1.2 - Snmpwalk

`$ snmpwalk -c public -v1 <IP>`

`$ snmpwalk -v 2c -c public <IP>:<PORT>`

#### 1.1.3 - Samrdump

`$ samrdump SNMP <IP>`

#### 1.1.4 - Onesixtyone

`$ onesixtyone -w 0 <IP>`

`$ onesixtyone -c <private | public> -i snmp_ips.txt`

## 02 - Nmap

### 2.1 - Interfaces

`$ nmap -p 161 -sU --script snmp-interfaces --script-args creds.snmp=<password> <IP>`

### 2.2 - Netstat

`$ nmap -p 161 -sU --script snmp-netstat --script-args creds.snmp=<password> <IP>`

### 2.3 - Processes

`$ nmap -p 161 -sU --script snmp-processes --script-args creds.snmp=<password> <IP>`

### 2.4 - SNMP Enumeration

`$ nmap -p 161 -sU --script snmp-enum <IP>`

## 03 - Metasploit

### 3.1 - SNMP Enumeration

```
msf > use auxiliary/scanner/snmp/snmp_enum

msf auxiliary(scanner/snmp/snmp_enum) > options

Module options (auxiliary/scanner/snmp/snmp_enum):

   Name       Current Setting  Required  Description
   ----       ---------------  --------  -----------
   COMMUNITY  public           yes       SNMP Community String
   RETRIES    1                yes       SNMP Retries
   RHOSTS                      yes       The target host(s), see https://github.com/rapid7/metasploit-framework/wiki/Using-Metasploit
   RPORT      161              yes       The target port (UDP)
   THREADS    1                yes       The number of concurrent threads (max one per host)
   TIMEOUT    1                yes       SNMP Timeout
   VERSION    1                yes       SNMP Version <1/2c>

msf auxiliary(scanner/snmp/snmp_enum) > set community <public | private>

msf auxiliary(scanner/snmp/snmp_enum) > set version <1 | 2c>

msf auxiliary(scanner/snmp/snmp_enum) > set rhosts <IP>

msf auxiliary(scanner/snmp/snmp_enum) > run
```

### 3.2 - Shares

```
msf > use auxiliary/scanner/snmp/snmp_enumshares

msf auxiliary(scanner/snmp/snmp_enumshares) > options

Module options (auxiliary/scanner/snmp/snmp_enumshares):

   Name       Current Setting  Required  Description
   ----       ---------------  --------  -----------
   COMMUNITY  public           yes       SNMP Community String
   RETRIES    1                yes       SNMP Retries
   RHOSTS                      yes       The target host(s), see https://github.com/rapid7/metasploit-framework/wiki/Using-Metasploit
   RPORT      161              yes       The target port (UDP)
   THREADS    1                yes       The number of concurrent threads (max one per host)
   TIMEOUT    1                yes       SNMP Timeout
   VERSION    1                yes       SNMP Version <1/2c>

msf auxiliary(scanner/snmp/snmp_enumshares) > set community <public | private>

msf auxiliary(scanner/snmp/snmp_enumshares) > set version <1 | 2c>

msf auxiliary(scanner/snmp/snmp_enumshares) > set rhosts <IP>

msf auxiliary(scanner/snmp/snmp_enumshares) > run
```

### 3.3 - Enumerate Users

```
msf > use auxiliary/scanner/snmp/snmp_enumusers

msf auxiliary(scanner/snmp/snmp_enumusers) > options

Module options (auxiliary/scanner/snmp/snmp_enumusers):

   Name       Current Setting  Required  Description
   ----       ---------------  --------  -----------
   COMMUNITY  public           yes       SNMP Community String
   RETRIES    1                yes       SNMP Retries
   RHOSTS                      yes       The target host(s), see https://github.com/rapid7/metasploit-framework/wiki/Using-Metasploit
   RPORT      161              yes       The target port (UDP)
   THREADS    1                yes       The number of concurrent threads (max one per host)
   TIMEOUT    1                yes       SNMP Timeout
   VERSION    1                yes       SNMP Version <1/2c>

msf auxiliary(scanner/snmp/snmp_enumusers) > set community <public | private>

msf auxiliary(scanner/snmp/snmp_enumusers) > set version <1 | 2c>

msf auxiliary(scanner/snmp/snmp_enumusers) > run
```

### 3.4 - SNMP Set OID

```
msf > use auxiliary/scanner/snmp/snmp_set

msf auxiliary(scanner/snmp/snmp_set) > options

Module options (auxiliary/scanner/snmp/snmp_set):

   Name       Current Setting  Required  Description
   ----       ---------------  --------  -----------
   COMMUNITY  public           yes       SNMP Community String
   OID                         yes       The object identifier (numeric notation)
   OIDVALUE                    yes       The value to set
   RETRIES    1                yes       SNMP Retries
   RHOSTS                      yes       The target host(s), see https://github.com/rapid7/metasploit-framework/wiki/Using-Metasploit
   RPORT      161              yes       The target port (UDP)
   THREADS    1                yes       The number of concurrent threads (max one per host)
   TIMEOUT    1                yes       SNMP Timeout
   VERSION    1                yes       SNMP Version <1/2c>

msf auxiliary(scanner/snmp/snmp_set) > set community <public | private>

msf auxiliary(scanner/snmp/snmp_set) > set version <1 | 2c>

msf auxiliary(scanner/snmp/snmp_set) > set oid <oid>

msf auxiliary(scanner/snmp/snmp_set) > set oidvalue <oid_value>

msf auxiliary(scanner/snmp/snmp_set) > set rhosts <IP>
```

## References

- [Pentesting SNMP](https://book.hacktricks.xyz/pentesting/pentesting-snmp)

- [Enumerating with Nmap](https://materials.rangeforce.com/tutorial/2020/01/30/Enumerating-with-Nmap/)