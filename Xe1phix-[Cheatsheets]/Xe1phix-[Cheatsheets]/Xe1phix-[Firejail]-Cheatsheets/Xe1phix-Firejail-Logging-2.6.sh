#!/bin/sh
## Xe1phix-Firejail-Logging.sh



mkdir /var/log/firejail/
mkfile /var/log/firejail/firejail.log
noblacklist /var/log/firejail/firejail.log
whitelist /var/log/firejail/firejail.log

--output=logfile                    ## stdout logging and log rotation
firejail --output-stderr=
firejail --output=sandboxlog


firejail --trace wget -q www.debian.org
firejail --tracelog 
firejail --tracelog firefox
sudo tail -f /var/log/syslog

sudo firejail --writable-var-log

sudo firejail --writable-var-log

tracelog
writable-var-log



Firejail Telegram No Profile {Auditing Blacklisted Variables}
firejail --noprofile --tracelog --name=telegram Telegram && sleep 10 && tail -f /var/log/syslog | tee ~/FirejailAuditNoProfile.txt
/usr/share/icons/maia/apps/scalable/telegram.svg

Firejail Telegram Profile {Auditing Blacklisted Variables}
firejail --name=telegram --tracelog --profile=/etc/firejail/etc/telegram.profile /home/xe1phix/Downloads/Telegram/Telegram && sleep 10 && tail -f /var/log/syslog | tee ~/FirejailAuditTelegramProfile.txt
/usr/share/icons/maia/apps/scalable/telegram.svg

echo "Print the filesystem log for the sandbox"
Firejail FS-Log Debugging {Telegram Profile}
firejail --name=telegram --profile=/etc/firejail/telegram.profile Telegram; sleep 10 && echo -e "\n\n\t\tPrinting Sandbox's FS Debug Log Output...\n\n" && firejail --fs.print=telegram


Firejail Debugging {Telegram Profile - Seccomp Printing - Without Defined Profile} 
firejail --name=telegram --noprofile --output=TelegramSeccompNoProfileLogz /home/xe1phix/Downloads/Telegram/Telegram &
firejail --seccomp.print=telegram --output=TelegramLogz


Firejail Debugging {Telegram Profile - Seccomp Printing - With Defined Profile} 
firejail --name=telegram --output=TelegramSeccompProfileLogz --profile=/etc/firejail/etc/telegram.profile /home/xe1phix/Downloads/Telegram/Telegram &
firejail --seccomp.print=telegram --output=TelegramLogz



Firejail Telegram Logging {Cp stdout & stderr to logfile}
firejail --name=telegram --output=TelegramLogz --profile=/etc/firejail/etc/telegram.profile /home/xe1phix/Downloads/Telegram/Telegram
/usr/share/icons/maia/apps/scalable/telegram.svg


echo "Listing Log Files..." 
ls -l sandboxlog* && cat sandboxlog* | tee ~/sandboxlog.txt
/usr/share/icons/maia/apps/scalable/telegram.svg
