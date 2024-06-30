

## Cisco IOS Commands:


| -------------------------------------------- | ---------------------------------- |
| Command                                      | Description                        |
| -------------------------------------------- | ---------------------------------- |
| enable                                       | Enters enable mode                 |
| conf t                                       | Short for, configure terminal      |
| (config)# interface fa0/0                    | Configure FastEthernet 0/0         |
| (config-if)# ip addr 0.0.0.0 255.255.255.255 | Add IP to fa0/0                    |
| (config-if)# line vty 0 4                    | Configure vty line                 |
| (config-line)# login                         | Cisco set telnet password          |
| (config-line)# password YOUR-PASSWORD        | Set telnet password                |
| # show running-config                        | Show running config loaded in memory|
| # show startup-config                        | Show startup config                |
| # show version                               | Show Cisco IOS version             |
| # show session                               | Display open sessions              |
| # show ip interface                          | Show network interfaces            |
| # show interface e0                          | Show detailed interface info       |
| # show ip route                              | Show routes                        |
| # show access-lists                          | Show access lists                  |
| # dir file systems                           | Show available files               |
| # dir all-filesystems                        | File information                   |
| # dir /all                                   | Show deleted files                 |
| # terminal length 0                          | No limit on terminal output        |
| # copy running-config tftp                   | Copies running config to tftp server|
| # copy running-config startup-config         | Copy startup-config to running-config|
| -------------------------------------------- | ---------------------------------- |


