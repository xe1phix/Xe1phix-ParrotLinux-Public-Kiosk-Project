#!/bin/sh
## ---------------------------------------- ##
## Xe1phix-ServiceDaemonVariables.sh
## ---------------------------------------- ##

echo "##-==========================================================-##"
echo -e "\t\t [+] Darknet :"
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
echo "##-==========================================================-##"

echo
echo "## ================================================================== ##"
echo -e "\t\t [+] Setting I2P Environment Variables..."
echo "## ================================================================== ##"
##
## 
## ==================================================================================== ##
I2pMonotone="8998"
export I2pMonotone="8998"
## ==================================================================================== ##
I2PHttpPort="4444"
export I2PHttpPort="4444"
## ==================================================================================== ##
I2PHttpsPort="4445"
export I2PHttpsPort="4445"
## ==================================================================================== ##
TAHOE_PORT="3456"
export TAHOE_PORT="3456"
## ==================================================================================== ##
I2pPostmanPop3="7660"
export I2pPostmanPop3="7660"
## ==================================================================================== ##
I2pPostmanSTMP="7659"
export I2pPostmanSTMP="7659"
## ==================================================================================== ##
Irc2PPort="6668"
export Irc2PPort="6668"
## ==================================================================================== ##
I2PWebserverPort="7658"
export I2PWebserverPort="7658"
## ==================================================================================== ##
I2pLocalControlChannelServiceWrapper="32000"
export I2pLocalControlChannelServiceWrapper="32000"
## ==================================================================================== ##
I2pLocalconnectionServiceWrapper="31000"
export I2pLocalconnectionServiceWrapper="31000"
## ==================================================================================== ##
I2pIrc="6668"
export I2pIrc="6668"
## ==================================================================================== ##
SSDPSearchResponseListener="7653"				## UPnP_SSDP_UDP
export SSDPSearchResponseListener="7653"
## ==================================================================================== ##
TCPEventListener="7652"							## UPnP HTTP TCP
export TCPEventListener="7652"
## ==================================================================================== ##
I2pBobBridge="2827"
export I2pBobBridge="2827"
## ==================================================================================== ##
I2pSSDPMulticastListener="1900"			        ## UPnP SSDP UDP
export I2pSSDPMulticastListener="1900"
## ==================================================================================== ##
I2pClientProtocolPort="7654"
export I2pClientProtocolPort="7654"
## ==================================================================================== ##
I2pUdpSAMBridge="7655"
export I2pUdpSAMBridge="7655"
## ==================================================================================== ##
I2pSAMBridge="7656"
export I2pSAMBridge="7656"
## ==================================================================================== ##

echo "## ================================================================= ##"
echo -e "\t\t [+] Setting Tor Environment Variables..."
echo "## ================================================================= ##"
## 
## ==================================================================================== ##
TorifiedDNSSocket="5353"
export TorifiedDNSSocket="5353"
## ==================================================================== ##
TailsSpecificSocksPort="9062"
export TailsSpecificSocksPort="9062"				## IsolateDestAddr IsolateDestPort
## ==================================================================== ##
TOR_CONTROL_PORT="9051"
export TOR_CONTROL_PORT="9051"
## ==================================================================== ##
TOR_DNS_PORT="5353"
export TOR_DNS_PORT="5353"
## ==================================================================== ##
TOR_TRANS_PORT="9040"
export TOR_TRANS_PORT="9040"
## ==================================================================== ##
TRANSPROXY_USER="anon"
export TRANSPROXY_USER="anon"
## ==================================================================================== ##
## 
echo "## ================================================================= ##"
echo -e "\t\t [+] Setting SOCKS5 Environment Variables..."
echo "## ================================================================= ##"


Nessus="https://127.0.0.1:8834"
export Nessus="https://127.0.0.1:8834"
Nexpose="https://127.0.0.1:3780"
export Nexpose="https://127.0.0.1:3780"
MSF="https://127.0.0.1:3790"                            					# Metasploit UI
export MSF="https://127.0.0.1:3790"
BeEF="http://127.0.0.1:3000/ui/panel"
export BeEF="http://127.0.0.1:3000/ui/panel"
Dradis="https://127.0.0.1:3004"
export Dradis="https://127.0.0.1:3004"
GSAD="http://127.0.0.1:9392"                            					# gsad --http-only --listen=127.0.0.1 -p 9392
export GSAD="http://127.0.0.1:9392"
OpenVasManager="http://127.0.0.1:9390"                  		# openvasmd -p 9390 -a 127.0.0.1
export OpenVasManager="http://127.0.0.1:9390"
OpenVasAdministrator="http://127.0.0.1:9393"        			# openvasad -a 127.0.0.1 -p 9393
export OpenVasAdministrator="http://127.0.0.1:9393"



echo "## ================================================================= ##"
echo -e "\t\t [+] Setting Other Services Environment Variables..."
echo "## ================================================================= ##"
##
## 
## ==================================================================================== ##
CUPS_PORT="631"
SMTPSPort="465"						## SMTP over TLS
SMTP_PORT="25"
SSH_PORT="22"
SSH_ALT_PORT="2222"

SQUID_PORT="3128"				# Squid port
BITTORRENT_TRACKER="6881"
OSSEC_AGENT="1514"                  ## UDP
SGUIL="7736"                        ## TCP
hkpsPoolSksKeyserverPort="11371"
MonkeysphereValidationAgent="6136"
VMWareApplianceManagementInterface="5480"
VMWareAccessServerAdminWebUI="943"
VMWareClientWebServer="5480"
VMWare
OSSEC="1514"            ## OSSEC  1514/udp
Squert="443"            ## Squert/ELSA/CapMe
SguilClient="7734"      ## Sguil client
Sguild="7736"           ## sensor connection to sguild
XplicoPort="9876"       ##  


echo "   /\                                                                                       										 /\			"
echo "  / /\                                                                                      										/\ \		"
echo " / /-/                                                                                      										\-\ \		"
echo " \ \-\____Hidden Service Circuit____________Localhost:Port___[owner|UID]____ /-/ /		"
echo "  \,\_\_________________________________________________________________/_/,/		"
echo "        [+] Tor HTTPProxy									127.0.0.1:80                                       			"
echo "        [+] Tor HTTPSProxy									127.0.0.1:443                                     		 	"
echo "        [+] Tor Transparent Proxy						127.0.0.1:9040       amnesia                       "
echo "        [+] Tor SOCKS4a										127.0.0.1:1080       amnesia                       "
echo "        [+] Tor SOCKS5 (Default)							127.0.0.1:9050       amnesia                       "        ## IsolateDestAddr IsolateDestPort
echo "        [+] SocksPort for Tor Browser					127.0.0.1:9150       amnesia                       "
echo "        [+] SocksPort for the MUA						127.0.0.1:9061       amnesia                       "        ## IsolateDestAddr
echo "        [+] Tails-Specific Services SocksPort		127.0.0.1:9062       amnesia                       "        ## IsolateDestAddr IsolateDestPort
echo "        [+] Tails Time Synchronization Service	127.0.0.1:9062       htp                         	"        ## IsolateDestAddr IsolateDestPort
echo "        [+] Tails System DNS              					127.0.0.1:53          amnesia                       "
echo "        [+] Torified DNS Socket              				127.0.0.1:5353      amnesia                       "
echo "        [+] Tor ControlPort                       			127.0.0.1:9051      root                         	"
echo "        [+] Tor Control Port Filter               			127.0.0.1:9052      amnesia                       "


echo "                                                                      debian-tor                      "

echo "______________Torchat___________________Localhost:Port_____[owner|UID]________________"
echo "        [+] Torchat Client Listening Port				127.0.0.1:11009                                  "
echo "        [+] Torchat Socks Port								127.0.0.1:11109                                  "
echo "        [+] Torchat Control Port							127.0.0.1:11119                                  "
echo "        [+] Monkeysphere Validation Agent			127.0.0.1:6136                                   "


echo "___________ I2P __________________Localhost:Port___[owner|UID]_______"   ## I2PUSER="i2psvc"
echo "        [+] I2P HTTP Proxy						127.0.0.1:4444        i2pbrowser    "
echo "        [+] I2P HTTPS Proxy						127.0.0.1:4444                              "
echo "        [+] I2P Bootstrapping					127.0.0.1:5353          i2psvc          "
echo "             (using Tors DNSPort) 																	 "
echo "        [+] I2P HTTP Proxy						127.0.0.1:7657        i2pbrowser    "
echo "        [+] I2PWebserverPort					127.0.0.1:7658        i2pbrowser    "
echo "        [+] I2pSAMBridge							127.0.0.1:7656                              "
echo "        [+] I2pUdpSAMBridge					127.0.0.1:7655                              "
echo "        [+] I2pBobBridge                          127.0.0.1:2827                              "
echo "        [+] I2pClientProtocolPort             127.0.0.1:7654                              "
echo "        [+] I2pSSDPMulticastListener      127.0.0.1:1900                              "				## UPnP SSDP UDP
echo "        [+] TCPEventListener                   127.0.0.1:7652                              "				## UPnP HTTP TCP
echo "        [+] I2pMonotone                           127.0.0.1:8998                              "
echo "        [+] I2pPostmanSTMP                    127.0.0.1:7659                              "
echo "        [+] I2pPostmanPop3                     127.0.0.1:7660                              "
echo "        [+] I2pIrc										 127.0.0.1:6668                              "
echo "        [+] Irc2PPort                                  127.0.0.1:6668                              "
echo "## ----------------------------------------------------------------------------------------------------------------------- ##"
echo "                                                          _________________									  "
echo "        [+] I2P Local Connection 	   /__________________\									  "
echo "             Service Wrapper					   | 127.0.0.1:31000 |			i2psvc        sport   "
echo "            												   | 127.0.0.1:31001 |			i2psvc        sport   "
echo "            												   | 127.0.0.1:31002 |			i2psvc        sport   "
echo "## ----------------------------------------------------------------------------------------------------------------------- ##"
echo "                                                            ________________									  "
echo "        [+] I2P Local Control 			 	 /_________________\									  "
echo "             Channel Service Wrapper	   | 127.0.0.1:32000 |			i2psvc        dport   "
echo "            												   | 127.0.0.1:32001 |			i2psvc        dport   "
echo "            												   | 127.0.0.1:32002 |			i2psvc        dport   "
echo "## ----------------------------------------------------------------------------------------------------------------------- ##"


I2P_PORTS="2827 3456 4444 4445 6668 7622 7650 7651 7654 7656 7657 7658 7659 7660 7661 7662 8998"



echo "        [+] TAHOE_PORT									127.0.0.1:3456                                  "
echo "        [+] hkpsPoolSksKeyserverPort			127.0.0.1:11371                                 "


echo "        [+] SSH											127.0.0.1:22                                    "
echo "        [+] SMTP										127.0.0.1:25                                    "
echo "        [+] SMTP over TLS [SMTPS]		127.0.0.1:465                                   "
echo "        [+] BITTORRENT_TRACKER		127.0.0.1:6881                                  "










