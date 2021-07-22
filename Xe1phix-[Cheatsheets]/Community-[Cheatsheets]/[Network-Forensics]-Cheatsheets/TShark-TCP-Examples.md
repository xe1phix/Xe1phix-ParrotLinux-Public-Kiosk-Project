### Show TCP conversations with shark

```bash
$ tshark -q -z conv,tcp -r test.pcap

================================================================================
TCP Conversations
Filter:<No Filter>
                                               |       <-      | |       ->      | |     Total     |
                                               | Frames  Bytes | | Frames  Bytes | | Frames  Bytes |
192.168.1.104:52730  <-> 192.168.1.100:ssh      43373  62482545   18994   1303713   62367  63786258
192.168.1.104:52729  <-> 192.168.1.100:ssh         61     31549      73      9683     134     41232
192.168.1.104:52728  <-> 192.168.1.100:ssh         29      8705      31      5455      60     14160
192.168.1.104:52254  <-> 199.47.217.146:http        2       311       2       350       4       661
================================================================================
```

### Show TCP conversations with tcptrace:

```bash
$ tcptrace -n test.pcap

1 arg remaining, starting with 'test.pcap'
Ostermann's tcptrace -- version 6.6.7 -- Thu Nov  4, 2004

62642 packets seen, 62565 TCP packets traced
elapsed wallclock time: 0:00:00.130475, 480107 pkts/sec analyzed
trace file elapsed time: 0:00:52.128104
TCP connection info:
  1: 192.168.1.104:52728 - 192.168.1.100:22 (a2b)    31>   29<  (complete)
  2: 192.168.1.104:52729 - 192.168.1.100:22 (c2d)    73>   61<  (complete)
  3: 192.168.1.104:52730 - 192.168.1.100:22 (e2f)  18994> 43373<  (reset)
  4: 199.47.217.146:80 - 192.168.1.104:52254 (g2h)    2>    2<
```

### Show details of single conversation #3 from above:

```bash
$ tcptrace -l -r -o3 <file>
```

### Dump full protocol trace:

```bash
$ tshark -V -r <file>
```

### Dump all HTTP GET requests:

```bash
$ tshark -r <file> -T fields -e 'http.request.uri' -R 'http.request'
```

### Show stats by protocol:

```bash
$ tshark -q -r big -z io,phs

===================================================================
Protocol Hierarchy Statistics
Filter:

eth                                      frames:741 bytes:246116
  ip                                     frames:694 bytes:242336
    tcp                                  frames:426 bytes:210950
      http                               frames:34 bytes:19425
        data-text-lines                  frames:5 bytes:2189
          tcp.segments                   frames:2 bytes:1454
        tcp.segments                     frames:1 bytes:141
        image-gif                        frames:3 bytes:1730
        image-jfif                       frames:1 bytes:1140
          tcp.segments                   frames:1 bytes:1140
      ssl                                frames:72 bytes:51541
        tcp.segments                     frames:7 bytes:2619
      data                               frames:2 bytes:254
    udp                                  frames:244 bytes:29854
      dns                                frames:222 bytes:26319
      db-lsp-disc                        frames:20 bytes:3200
      nbdgm                              frames:1 bytes:243
        smb                              frames:1 bytes:243
          mailslot                       frames:1 bytes:243
            browser                      frames:1 bytes:243
      nbns                               frames:1 bytes:92
    icmp                                 frames:17 bytes:1190
    igmp                                 frames:7 bytes:342
  ipv6                                   frames:24 bytes:2640
    icmpv6                               frames:24 bytes:2640
  arp                                    frames:21 bytes:882
  eapol                                  frames:2 bytes:258
===================================================================
```

### Show 5 second interval stats of tcp, icmp and udp traffic:

```bash
$ tshark -q -n -r ssh -z io,stat,5,tcp,icmp,udp

===================================================================
IO Statistics
Interval: 5.000 secs
Column #0: tcp
Column #1: icmp
Column #2: udp
                |   Column #0    |   Column #1    |   Column #2
Time            |frames|  bytes  |frames|  bytes  |frames|  bytes
000.000-005.000       0         0      0         0      8      1124
005.000-010.000       0         0      0         0      4       536
010.000-015.000       0         0      0         0      0         0
015.000-020.000      60     14160      0         0      6       745
020.000-025.000       0         0      0         0      0         0
025.000-030.000     134     41232      0         0      0         0
030.000-035.000       0         0      0         0      2       320
035.000-040.000   17281  17897543      0         0     36      3716
040.000-045.000   45090  45889376      0         0      2       268
045.000-050.000       0         0      0         0      6       804
050.000-055.000       0         0      0         0      2       268
===================================================================
```

### Show TCP retransmission count:

```bash
$ tshark -nr big.pcap -qz 'io,stat,0,COUNT(tcp.analysis.retransmission)tcp.analysis.retransmission'

===================================================================
IO Statistics
Column #0: COUNT(tcp.analysis.retransmission)tcp.analysis.retransmission
                |   Column #0
Time            |          COUNT
000.000-                      105
===================================================================
```

### Decrypt 802.11 traffic:

```bash
$ tshark -r test.pcap -o wlan.enable_decryption:TRUE
-o wlan.wep_key1:wpa-psk:55f8e415485dd9a272060ca558d3db184be51b3cb6d4a048b064c7aaca335df2

List conversations by percentage:

 tshark -r ssh -n -qz ip_hosts,tree

===================================================================
 IP Addresses            value          rate         percent
-------------------------------------------------------------------
 IP Addresses           62634       1.201540
  192.168.1.104          62631       1.201482         100.00%
  8.8.4.4                    8       0.000153           0.01%
  255.255.255.255            2       0.000038           0.00%
  192.168.1.255              2       0.000038           0.00%
  75.75.75.75                8       0.000153           0.01%
  8.8.8.8                   46       0.000882           0.07%
  192.168.1.100          62562       1.200159          99.89%
  192.168.1.1                2       0.000038           0.00%
  224.0.0.1                  1       0.000019           0.00%
  224.0.0.251                1       0.000019           0.00%
  224.0.0.2                  1       0.000019           0.00%
  199.47.217.146             4       0.000077           0.01%

===================================================================
```

### List protocol breakdown:

```bash
$ tshark -r big -n -qz ptype,tree

===================================================================
 IP Protocol Types        value         rate         percent
-------------------------------------------------------------------
 IP Protocol Types       22509       0.032184
  TCP                     21203       0.030316          94.20%
  UDP                      1284       0.001836           5.70%
  NONE                       22       0.000031           0.10%

===================================================================
```
