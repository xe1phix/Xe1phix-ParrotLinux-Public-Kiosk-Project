#!/bin/sh

##-=====================================================-##
##   [+] Copy A File Outside of The Firejail Sandbox:
##-=====================================================-##
## --------------------------------------------------------------------------- ##
firejail --ls=$browser ~/Downloads
firejail --get=$browser ~/Downloads/$xpra-clipboard.png
firejail --put=$browser $xpra-clipboard.png ~/Downloads/$xpra-clipboard.png
## --------------------------------------------------------------------------- ##
firejail --ls=$PID ~/
firejail --get=$PID ~/$File
firejail --put=$PID ~/$File ~/Downloads/$File
## --------------------------------------------------------------------------- ##

