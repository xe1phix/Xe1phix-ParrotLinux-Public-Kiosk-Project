---
title: Wireshark Cheat Sheet
description: Network protocol analyzer. It uses the pcapng file format.
tags:
    - Network
refs:
date: 2023-04-21
draft: false
---

## Settings

### Datetime Format When Packets Sent

Select “View → Time Display Format → Date and Time of Day”.

<br />

## Filters

Enter the following text in a filtering form.

### Datetime

```sh
frame.time >= "Jan 2, 2023 08:00:00" && frame.time <= "Jan 5, 2023 08:00:00"
```

### DNS

```sh
dns
udp.port == 53

# Record type
dns.qry.type == 1   # A record
dns.qry.type == 2   # NS record
dns.qry.type == 5   # CNAME record
dns.qry.type == 6   # SOA record
dns.qry.type == 15  # MX record
dns.qry.type == 16  # TXT record
dns.qry.type == 28  # AAAA record
dns.qry.type == 252 # AXFR

# Query name
dns.qry.name matches "example.com"

# Reponse
dns.flags.response == 0 # No response
```

### FTP

```sh
ftp
ftp-data
```

### HTTP & HTTPS

```sh
# HTTP
http
tcp.port == 80

# HTTPS
ssl
tcp.port == 443

tcp.port == 80 || tcp.port == 443

# Methods
http.request.method == GET
http.request.method == POST

# Domains
http.host matches "example.com"
http.host == "example.com"
```

### ICMP

```sh
icmp
```

### IP Address

```sh
ip.addr == 10.0.0.1
ip.addr != 10.0.0.2
ip.addr == 10.0.0.1 && ip.addr == 10.0.0.2
ip.src == 10.0.0.1
ip.dst == 10.0.0.2
ip.src == 10.0.0.1 && ip.dst != 10.0.0.0/24
```

### SMB

```sh
smb
smb2
```

### SMTP

```sh
smtp
smtp.req.parameter contains "FROM"
```

### SSH

```sh
ssh
tcp.port == 22
```

<br />

## Detailed Information

1. Right click on the row item.
2. Select **Follow -> TCP Stream**. Another window opens.
3. Find information by clicking the arrow on the right of **"Stream *"**.

<br />

## More Information

- **Analyze -> Expert Information**

    Read the expert information.

- **Statistics -> Capture File Properties**

    Read the capture file comments.
    
- **Statistics → Conversations**
    
    List IP conversations. We can find IP addresses involved in the traffic.

- **Statistics → Protocol Hierarchy**
    
    Show usage of ports and services.

- **View -> Name Resolution**

    Resolve IP addresses.

<br />

## Data Exfiltration via DNS

1. Enter **"dns"** in filter form
2. If you found a domain such as follow, you may be able to retrieve threats.

    ```txt
    93616e64792043...2038343931.vulnerable.com
    ```

3. For example, decode "936...".

<br />

## Data Exfiltration via HTTP

1. Open **File -> Export Objects -> HTTP...** .
2. Click **"Save all"**.
3. Analyze steganographic files using tools like steghide.

<br />

## WiFi Handshakes

When importing pcap file, then if we found the capture file is about WiFi handshakes, we can crack the WiFi password using this file.

```bash
aircrack-ng example.pcap -w wordlist.txt
```