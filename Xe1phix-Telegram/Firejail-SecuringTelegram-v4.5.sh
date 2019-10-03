#!/bin/sh
##-=====================================-##
##   [+] Firejail-SecuringTelegram.sh
##-=====================================-##

Telegram {Firejail Profile}
firejail --name=telegram --profile=/etc/firejail/telegram.profile /home/xe1phix/Downloads/Telegram/Telegram -- %u
/usr/share/icons/maia/apps/scalable/telegram.svg


Telegram Desktop {Firejail Profile}
firejail --profile=/etc/firejail/telegram.profile /home/xe1phix/Downloads/Telegram/Telegram -- %u
${HOME}/.local/share/icons


Firejail Telegram Debugging {Firejail Debug Blacklists} 
firejail --debug-blacklists /home/xe1phix/Downloads/Telegram/Telegram -- %u
/usr/share/icons/maia/apps/scalable/telegram.svg


Firejail Telegram Debugging {All Debug Tests}
firejail --name=telegram --debug --profile=/etc/firejail/telegram.profile /usr/bin/pluma %U
/usr/share/icons/maia/apps/scalable/telegram.svg


Firejail Telegram Debugging {Firejail Debug Capabilities} 
firejail --debug-caps /home/xe1phix/Downloads/Telegram/Telegram -- %u
/usr/share/icons/maia/apps/scalable/telegram.svg


Telegram Debugging {Firejail Debug Protocols} 
firejail --debug-protocols /home/xe1phix/Downloads/Telegram/Telegram -- %u
/usr/share/icons/maia/apps/scalable/telegram.svg


Firejail Telegram Debugging {Print Protocols} 
firejail --name=telegram --profile=/etc/firejail/telegram.profile /home/xe1phix/Downloads/Telegram/Telegram
firejail --protocol.print=telegram --output=telegram-protocols.txt


Firejail Telegram Debugging {Firejail Debug Syscalls} 
firejail --debug-syscalls /home/xe1phix/Downloads/Telegram/Telegram -- %u
/usr/share/icons/maia/apps/scalable/telegram.svg

Firejail Telegram Debugging {Firejail Debug Whitelists} 
firejail --debug-whitelists /home/xe1phix/Downloads/Telegram/Telegram -- %u
/usr/share/icons/maia/apps/scalable/telegram.svg

Firejail Telegram Debugging {Firejail Strace} 
firejail --allow-debuggers --profile=/etc/firejail/telegram.profile strace -f /home/xe1phix/Downloads/Telegram/Telegram -- %u
/usr/share/icons/maia/apps/scalable/telegram.svg


Firejail Telegram No Profile {Auditing Blacklisted Variables}
firejail --noprofile --tracelog --name=telegram Telegram && sleep 10 && tail -f /var/log/syslog | tee ~/FirejailAuditNoProfile.txt
/usr/share/icons/maia/apps/scalable/telegram.svg

Firejail Telegram Profile {Auditing Blacklisted Variables}
firejail --name=telegram --tracelog --profile=/etc/firejail/telegram.profile /home/xe1phix/Downloads/Telegram/Telegram && sleep 10 && tail -f /var/log/syslog | tee ~/FirejailAuditTelegramProfile.txt
/usr/share/icons/maia/apps/scalable/telegram.svg


Firejail Telegram Debugging {Firejail Print Seccomp Syscalls} 
(firejail --name=telegram --noprofile --output=~/FirejailTelegramSeccompPrint.txt /home/xe1phix/Downloads/Telegram/Telegram &) && sleep 10 && firejail --seccomp.print=telegram  | tee ~/FirejailSeccompTelegramProfile.txt
/usr/share/icons/maia/apps/scalable/telegram.svg

Firejail Telegram Debugging {Firejail Print all recognized errors} 
firejail --debug-errnos
/usr/share/icons/maia/apps/scalable/telegram.svg


Firejail Telegram Logging {Cp stdout & stderr to logfile}
firejail --name=telegram --output=TelegramLogz --profile=/etc/firejail/telegram.profile /home/xe1phix/Downloads/Telegram/Telegram


echo "Listing Log Files..." && ls -l sandboxlog* && cat sandboxlog* | tee ~/sandboxlog.txt
/usr/share/icons/maia/apps/scalable/telegram.svg




Firejail Telegram Auditing {No Profile Audit}
firejail --audit --name=telegram --noprofile /home/xe1phix/Downloads/Telegram/Telegram
/usr/share/icons/maia/apps/scalable/telegram.svg


Firejail Telegram Auditing {Profile Defined Audit}
firejail --audit --name=telegram --profile=/etc/firejail/telegram.profile Telegram
/usr/share/icons/maia/apps/scalable/telegram.svg





firejail --list
firejail --caps.print=

firejail --name=
firejail --dns.print=


echo "Print the filesystem log for the sandbox"

Firejail FS-Log Debugging {Profile Defined Audit}
firejail --name=telegram --profile=/etc/firejail/telegram.profile Telegram; sleep 10 && echo -e "\n\n\t\tPrinting Sandbox's FS Debug Log Output...\n\n" && firejail --fs.print=telegram


Firejail FS-Log Debugging  {No Profile Applied}
firejail --name=telegram 
firejail --fs.print=telegram


Telegram Debugging {Firejail Protocol Printing Without Profile} 
firejail --name=telegram --noprofile --output=TelegramProtocolNoProfileLogz /home/xe1phix/Downloads/Telegram/Telegram &
firejail --protocol.print=telegram


firejail --name=telegram --profile=/etc/firejail/telegram.profile /home/xe1phix/Downloads/Telegram/Telegram &
--profile=/etc/firejail/telegram.profile


Telegram Debugging {Firejail Seccomp Printing Without Profile} 
firejail --name=telegram --noprofile --output=TelegramSeccompNoProfileLogz /home/xe1phix/Downloads/Telegram/Telegram &
firejail --seccomp.print=telegram --output=TelegramLogz


Telegram Debugging {Firejail Seccomp Printing With Profile} 
firejail --name=telegram --output=TelegramSeccompProfileLogz --profile=/etc/firejail/telegram.profile /home/xe1phix/Downloads/Telegram/Telegram &
firejail --seccomp.print=telegram --output=TelegramLogz









firejail --debug --join=
cat /proc/self/status | grep Cap








Audit/Debug without the predefined security profiles in /etc/firejail/.
firejail --noprofile --output=~/Telegram-debug.txt --debug Telegram

firejail --noprofile --output=~/Telegram-syscalls.txt --debug-syscalls Telegram


firejail --noprofile --output=~/Telegram-caps.txt --debug-caps Telegram





firejail --tree
firejail --netstats
firejail --top
firejail --debug-check-filename Telegram


Firejail Telegram {Place Into Isolated Cgroup}
firejail --name=telegram --cgroup=/sys/fs/cgroup/g1/tasks --profile=/etc/firejail/telegram.profile Telegram
/usr/share/icons/maia/apps/scalable/telegram.svg

Firejail Telegram {Chroot Into Isolated RootFS}
firejail --name=telegram --chroot=/media/telegram --noprofile --seccomp --caps.drop=all --netfilter --nonewprivs --noroot /home/xe1phix/Downloads/Telegram/Telegram
/usr/share/icons/maia/apps/scalable/telegram.svg

Firejail Telegram {Place Into Isolated Cgroup}
firejail --ipc-namespace 
/usr/share/icons/maia/apps/scalable/telegram.svg


SHELL=/bin/sh unshare --fork --pid chroot "${chrootdir}" "$@"



Mount  a  filesystem overlay on top of the current filesystem
firejail --overlay Telegram
/usr/share/icons/maia/apps/scalable/telegram.svg


firejail --overlay-tmpfs 
/usr/share/icons/maia/apps/scalable/telegram.svg


Clean all overlays stored in $HOME/.firejail directory
firejail --overlay-clean
/usr/share/icons/maia/apps/scalable/telegram.svg


Mount  new  /root  and  /home/user directories in temporary filesystems. 
firejail --private 


Build a new user home in a temporary filesystem
firejail --private=/home/xe1phix/Downloads/Telegram/Telegram-private Telegram


--private-etc=

firejail --name=telegram --private-etc=group,hostname,localtime,nsswitch.conf,passwd,resolv.conf Telegram


