Xe1phix-Other Session ID:
0578e38ef8ef39846277390e5326f95db2f917633321f1e41eff5b338050870479


Xe1phix-Other Tox ID:
DF4B8EE892F0AD9D27873F2F86F049C712F8139992CCF5F060B525D37F4A4818EB7D3B067D43


Xe1phix-Other Briar ID:
briar://acr6tqknwky6mlzbjx5fpkffwu4k53r7y2fd6qczrvmufh2siduww



Hunter.io API Key:
4a4bb6033fa91ade62737eea47514034267c5de2


IPStack API Access Key:
07097318a8d4094ee4226209e0a9dc14


NetworksDB API Key:
e7b3b9df-440b-4448-ac37-67661e86d8ec


PulseDive API key: 
9b4fa2bb951c86b5b89fdcc1eecf62ada141bbc476bc44b8a629536570c07387


FullHunt API Key:
7c8a026e-7903-4df7-a9ff-90472e622d9d



Neutrino API:
User ID: xe1phix

Neutrino Root API Key:  
lkB8argt9ODLBmUa6Lq4Z8QMpm1StBi3BPYSopSYoa5TsHva

Neutrino Production API Key:
Ik7nPv23zktyW9ROMNPKLl9jpdCYS4ToASawya2kSq9uwfJ0




Clearbit API Key:







Hello Russell (and PLUG),
I am a Linux Engineer, I have studied Linux for 12yr now.
I have given talks at 9 InfoSec conferences over the years.
I recently remastered an old talk I gave years ago titled:
"How To Create A Persistent, LUKS Encrypted USB With A LUKS Killswitch Using Parrot Linux"
I rewrote it for BSides this year, but I think it would be a great talk to give at a PLUG meetup as well.

Here is the CFP for the talk:

## ----------------------------------------------------------------------------------- #

In this presentation, I will cover:

> Securely wipe files/device partitions (6 different methods).
> Format the USB device with Parrot Linux hybrid ISO.
> Create an Ext3 filesystem on the persistent partition.
> Create LUKS encrypted container on the persistent partition.
> Create a mount point, and mount the new LUKS encrypted partition.
> Dump the header information of a LUKS device.
> Add a nuke slot to the LUKS header.
> Create a binary backup of the LUKS header and keyslot area.
> Encrypt the LUKS header with OpenSSL for secure storage.
> Decrypt the LUKS header with OpenSSL for secure storage.
> Erase all LUKS key slots on persistant partition.
> Restore LUKS header from binary backup file.

## ----------------------------------------------------------------------------------- ##

Here are the slides:
https://gitlab.com/xe1phix/ParrotSecWiki/-/blob/InfoSecTalk/Xe1phix-InfoSec-Talk-Materials/How-To-Create-A-%5BPersistent%5D-%5BLUKS-Encrypted%5D-USB-Device-With-%5BParrot-Linux%5D-v2-%5BBSidesPDX%5D-2023/How-To-Create-A-%5BPersistent%5D-%5BLUKS-Encrypted%5D-USB-Device-With-%5BParrot-Linux%5D-v2-%5BSlides%5D/Xe1phix-_Encrypted-Persistent-USB-NukeSlot_-Slides-_v15.7.84_.pdf


If you aren't interested in this talk, 
I have several completed talks on hand:
> Secure Linux VPNs - Mullvad (Wireguard, OpenVPN) + ProtonVPN
> Encrypting files with friends using GnuPG
> Intro to Linux filesystems (ZFS, Btrfs, XFS, and Ext4)
> Secure Linux sandboxes using Firejail and AppArmor
> Securing IRC using Firejail, AppArmor, Wireguard, OpenVPN, CertFP (SASL + TLS), Irc2P, and Tor

Talks in development:
(75%+ completion, could complete by Oct meetup)
> Intro to Linux Anonymity Networks - Using I2P (I2PSnark, Irc2P,  I2PMail, IMule), and Tor (TorBrowser, Whonix, OnionShare, Ricochet, Briar, and Session)
> Pentesting IPv6 - (Using the THC-Hydra IPv6 Attack Toolkit)
> Secure Linux Firewalls - (Using IPTables, PFSense, IPSet, and FWSnort)
> Secure Android Messaging - (Using Session, Briar, aTox, Telegram, and Element)
> Secure Android Networking - (Using Mullvad, Wireguard, OpenVPN, ProtonVPN, and TorBrowser)
> Linux Forensic Analysis - using Sleuthkit (fls, ils, icat, mmls, etc), dc3dd, dcdldd, Foremost, ddrescue, and  guymager
> Linux Metadata Forensics - Analysis, anonymization, and  manipulation (Exiftool, Exifprobe, Exiv2, etc)
> Linux PDF Forensics (pdf-parser, hachoir, peepdf, pdfid, etc)
> Securing Linux Kernel Modules - (Using Modprobe and kernel module parameters)
> Hardening Linux Sysctl Settings - (Securing SysFS options)

Thank you for considering my presentation
You can contact me at markrobertcurry@protonmail.com



Ching
10:10


What he desires is non desire


Your smoothing the water with flat irons




Hello Russell,
I'm very flexible on which month I give the presentation. 

It would depend on which talk you would be most interested in me giving.
If you pick the 

 "How To Create A Persistent, LUKS Encrypted USB With A LUKS Killswitch
> Using Parrot Linux"



----
Share via Tcpdump Sniffing

    Sniff anything on one interface:

tcpdump -i <interface>

    Filtering on host (source/destination/any):

tcpdump -i <interface> host <IP>
tcpdump -i <interface> src host <IP>
tcpdump -i <interface> dst host <IP>
tcpdump -i <interface> ether host <MAC>
tcpdump -i <interface> ether src host <MAC>
tcpdump -i <interface> ether dst host <MAC>

    Filtering on port (source/destination/any):

tcpdump -i <interface> port <port>
tcpdump -i <interface> src port <port>
tcpdump -i <interface> dst port <port>

    Filtering on network (e.g. network=192.168)

tcpdump -i <interface> net <network>
tcpdump -i <interface> src net <network>
tcpdump -i <interface> dst net <network>

    Protocol filtering

tcpdump -i <interface> arp
tcpdump -i <interface> ip
tcpdump -i <interface> tcp
tcpdump -i <interface> udp
tcpdump -i <interface> icmp

    Condition usage example

tcpdump -i <interface> '((tcp) and (port 80) and ((dst host 192.168.1.254) or (dst host 192.168.1.200)))'

    Disable name resolution

tcpdump -i <interface> -n

    Make sure to capture whole packet (no truncation)

tcpdump -i <interface> -s 0

    Write full pcap file

tcpdump -i <interface> -s 0 -w capture.pcap

    Show DNS traffic

tcpdump -i <interface> -nn -l udp port 53

    Show HTTP User-Agent & Hosts

tcpdump -i <interface> -nn -l -A -s1500 | egrep -i 'User-Agent:|Host:'

    Show HTTP Requests & Hosts

tcpdump -i <interface> -nn -l -s 0 -v | egrep -i "POST /|GET /|Host:"

    Show email recipients

tcpdump -i <interface> -nn -l port 25 | egrep -i 'MAIL FROM\|RCPT TO'

    Show FTP data

tcpdump -i <interface> -nn -v port ftp or ftp-data

    Show all passwords different protocols

tcpdump -i wlan0 port http or port ftp or port smtp or port imap or port pop3 or port telnet -l -A | egrep -i -B5 'pass=|pwd=|log=|login=|user=|username=|pw=|passw=|passwd=|password=|pass:|user:|username:|password:|login:|pass |user '

S