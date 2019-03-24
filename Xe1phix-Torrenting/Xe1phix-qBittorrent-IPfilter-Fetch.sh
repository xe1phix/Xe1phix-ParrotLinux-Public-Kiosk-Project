#!/bin/sh
##-==============================================-##
##   [+] Xe1phix-qBittorrent-IPfilter-Fetch.sh
##-==============================================-##
## ---------------------------------------------- ##
##   [?] Update IP filter for qBittorrent 
## ---------------------------------------------- ##
wget -O - http://list.iblocklist.com/\?list\=ydxerpxkpcfqjaybcssw\&fileformat\=p2p\&archiveformat\=gz | gunzip > ~/ipfilter.p2p

