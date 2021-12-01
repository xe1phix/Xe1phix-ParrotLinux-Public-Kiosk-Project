#!/bin/sh
## ---------------------------------------- ##
## Xe1phix-ServiceDaemonVariables-v1.7.sh
## ---------------------------------------- ##

echo "##-==========================================================-##"
echo -e "\t\t [+] Service Port Environment Variables:"
echo "##-==========================================================-##"
SOCKS4a="127.0.0.1:1080"
export SOCKS4a="127.0.0.1:1080"
SOCKS5="127.0.0.1:9050"
export SOCKS5="127.0.0.1:9050"
TOR_SOCKS_PORTS="9050 9150"
export TOR_SOCKS_PORTS="9050 9150"
TOR_CONTROL_PORTS="9051 9151"
export TOR_CONTROL_PORTS="9051 9151"
I2PHTTP="http://127.0.0.1:4444"
export I2PHTTP="http://127.0.0.1:4444"
I2PHTTPS="https://127.0.0.1:4445"
export I2PHTTPS="https://127.0.0.1:4445"

Nessus="https://127.0.0.1:8834"
export Nessus="https://127.0.0.1:8834"
Nexpose="https://127.0.0.1:3780"
export Nexpose="https://127.0.0.1:3780"
MSF="https://127.0.0.1:3790"                            # Metasploit UI
export MSF="https://127.0.0.1:3790"
BeEF="http://127.0.0.1:3000/ui/panel"
export BeEF="http://127.0.0.1:3000/ui/panel"
GSAD="http://127.0.0.1:9392"                            # gsad --http-only --listen=127.0.0.1 -p 9392
export GSAD="http://127.0.0.1:9392"
OpenVasManager="http://127.0.0.1:9390"                  # openvasmd -p 9390 -a 127.0.0.1
export OpenVasManager="http://127.0.0.1:9390"
OpenVasAdministrator="http://127.0.0.1:9393"        # openvasad -a 127.0.0.1 -p 9393
export OpenVasAdministrator="http://127.0.0.1:9393"




 

echo "   /\                                                                                        /\      "
echo "  / /\                                                                                      /\ \     "
echo " / /-/                                                                                      \-\ \    "
echo " \ \-\____________Hidden Service Circuit__________Localhost:Port_______[owner|UID]__________/-/ /    "
echo "  \,\________________________________________________________________________________________/,/     "
echo 
echo "        [+] Tor HTTPProxy                         127.0.0.1:80                                       "
echo "        [+] Tor HTTPSProxy                        127.0.0.1:443                                      "
echo "        [+] Tor Transparent Proxy                 127.0.0.1:9040       amnesia                       "
echo "        [+] Tor SOCKS4a                           127.0.0.1:1080       amnesia                       "
echo "        [+] Tor SOCKS5 (Default)                  127.0.0.1:9050       amnesia                       "        ## IsolateDestAddr IsolateDestPort
echo "        [+] SocksPort for Tor Browser            	127.0.0.1:9150       amnesia                       "
echo "        [+] SocksPort for the MUA					127.0.0.1:9061       amnesia                       "        ## IsolateDestAddr
echo "        [+] Tails-Specific Services SocksPort		127.0.0.1:9062       amnesia                       "        ## IsolateDestAddr IsolateDestPort
echo "        [+] Tails Time Synchronization Service	127.0.0.1:9062         htp                         "        ## IsolateDestAddr IsolateDestPort
echo "        [+] Tails System DNS              		127.0.0.1:53         amnesia                       "
echo "        [+] Torified DNS Socket              		127.0.0.1:5353       amnesia                       "
echo "        [+] Tor ControlPort                       127.0.0.1:9051        root                         "
echo "        [+] Tor Control Port Filter               127.0.0.1:9052       amnesia                       "



echo "_____________________Torchat_________________________Localhost:Port________[owner|UID]________________"
echo "        [+] Torchat Client Listening Port            127.0.0.1:11009                                  "
echo "        [+] Torchat Socks Port                       127.0.0.1:11109                                  "
echo "        [+] Torchat Control Port                     127.0.0.1:11119                                  "
echo "        [+] Monkeysphere Validation Agent            127.0.0.1:6136                                   "


echo "__________________________ I2P _______________________Localhost:Port_______[owner|UID]____________"   ## I2PUSER="i2psvc"
echo "        [+] I2P HTTP Proxy                            127.0.0.1:4444        i2pbrowser            "
echo "        [+] I2P HTTPS Proxy                           127.0.0.1:4444                              "
echo "        [+] I2P Bootstrapping (using Tors DNSPort)    127.0.0.1:5353          i2psvc              "
echo "        [+] I2P HTTP Proxy                            127.0.0.1:7657        i2pbrowser            "
echo "        [+] I2PWebserverPort                          127.0.0.1:7658        i2pbrowser            "
echo "        [+] I2pSAMBridge                              127.0.0.1:7656                              "
echo "        [+] I2pUdpSAMBridge                           127.0.0.1:7655                              "
echo "        [+] I2pBobBridge                              127.0.0.1:2827                              "
echo "        [+] I2pClientProtocolPort                     127.0.0.1:7654                              "
echo "        [+] I2pSSDPMulticastListener                  127.0.0.1:1900                              "	## UPnP SSDP UDP
echo "        [+] TCPEventListener                          127.0.0.1:7652                              "	## UPnP HTTP TCP
echo "        [+] I2pMonotone                               127.0.0.1:8998                              "
echo "        [+] I2pPostmanSTMP                            127.0.0.1:7659                              "
echo "        [+] I2pPostmanPop3                            127.0.0.1:7660                              "
echo "        [+] I2pIrc                                    127.0.0.1:6668                              "
echo "        [+] Irc2PPort                                 127.0.0.1:6668                              "
echo "        [+] I2P Local Connection Service Wrapper      127.0.0.1:31000       i2psvc        sport   "
echo "            ----------------------------------------- 127.0.0.1:31001       i2psvc        sport   "
echo "            ----------------------------------------- 127.0.0.1:31002       i2psvc        sport   "
echo "        [+] I2P Local Control Channel Service Wrapper 127.0.0.1:32000       i2psvc        dport   "
echo "            ----------------------------------------- 127.0.0.1:32001       i2psvc        dport   "
echo "            ----------------------------------------- 127.0.0.1:32002       i2psvc        dport   "




echo "        [+] TAHOE_PORT                                127.0.0.1:3456                                  "
echo "        [+] hkpsPoolSksKeyserverPort                  127.0.0.1:11371                                 "


echo "        [+] SSH                                       127.0.0.1:22                                    "
echo "        [+] SMTP                                      127.0.0.1:25                                    "
echo "        [+] SMTP over TLS [SMTPS]                     127.0.0.1:465                                   "
echo "        [+] BITTORRENT_TRACKER                        127.0.0.1:6881                                  "










