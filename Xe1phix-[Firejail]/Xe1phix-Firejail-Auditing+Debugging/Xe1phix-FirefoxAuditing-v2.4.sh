#!/bin/sh
## Xe1phix-FirefoxAuditing-v2.4.sh

Firefox Debugging {Firejail Strace} 
firejail --allow-debuggers --profile=/etc/firejail/firefox-common.profile strace -f firefox-esr

Firefox Debugging {Firejail Print Seccomp Syscalls} 
firejail --seccomp.print=firefox

firejail --tracelog firefox-esr
tail -f /var/log/syslog

firejail --trace wget -q www.debian.org

Firefox Debugging {Firejail Debug Blacklists} 
firejail --debug-blacklists firefox-esr

Firefox Debugging {Firejail Debug Capabilities} 
firejail --debug-caps firefox-esr

Firefox Debugging {Firejail Debug Protocols} 
firejail --debug-protocols firefox-esr

Firefox Debugging {Firejail Debug Syscalls} 
firejail --debug-syscalls firefox-esr

Firefox Debugging {Firejail Debug Whitelists} 
firejail --debug-whitelists firefox-esr

firejail --join-network=firefox /sbin/iptables -vL
firejail --join-network=firefox ip addr

Firejail Firefox Debugging {Print Protocols} 
firejail --name=firefox --profile=/etc/firejail/firefox-common.profile /home/xe1phix/Downloads/Telegram/Telegram
firejail --protocol.print=firefox --output=firefox-protocols.txt



Firejail Firefox Debugging {Firejail Print Seccomp Syscalls} 
(firejail --name=firefox --noprofile --output=~/FirejailFirefoxSeccompPrint.txt /usr/bin/firefox-esr) && sleep 10 && firejail --seccomp.print=firefox  | tee ~/FirejailSeccompFirefoxProfile.txt


Firejail Telegram Debugging {Firejail Print all recognized errors} 
firejail --debug-errnos

Firejail Telegram Logging {Cp stdout & stderr to logfile}
firejail --name=telegram --output=TelegramLogz --profile=/etc/firejail/etc/telegram.profile /home/xe1phix/Downloads/Telegram/Telegram



echo "Listing Log Files..." 
ls -l sandboxlog* && cat sandboxlog* | tee ~/sandboxlog.txt


Firejail Telegram Auditing {No Profile Audit}
firejail --audit --name=telegram --noprofile 


Firejail Telegram Auditing {Profile Defined Audit}
firejail --audit --name=telegram --profile=

firejail --ls=firefox ~/Downloads
firejail --dns.print=
firejail --caps.print=
firejail --fs.print=
firejail --protocol.print=telegram
firejail --seccomp.print=telegram --output=TelegramLogz

firejail --tree
firejail --netstats
firejail --top
firejail --debug-check-filename Telegram


firejail --debug --join=
cat /proc/self/status | grep Cap

Audit/Debug without the predefined security profiles in /etc/firejail/.
firejail --noprofile --output=~/Telegram-debug.txt --debug 

firejail --noprofile --output=~/Firefox-debug.txt --debug firefox

firejail --caps /etc/init.d/bluetooth start

