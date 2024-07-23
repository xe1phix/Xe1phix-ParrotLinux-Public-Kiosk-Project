#!/bin/bash -debug
#
# Audit SuSE Linux Script v0.9 (c) 2000 by Marc Heuse <marc@suse.de>
# This is private property. Everyone may use and change this script,
# as long as this copyright notice is kept unchanged.
#
# 24 February 04 - v0.11
# Modified by Jeffrey Denton <dentonj@c2i2.com> 
# for Slackware Linux.
# 

PATH="/sbin:/usr/sbin:/bin:/usr/bin"
HOSTNAME=$(/bin/hostname)
AUDIT_DIR="${HOSTNAME}_audit"
OUTFILE="${HOSTNAME}_audit.tar.gz"


if [ "$(/bin/echo $USER)" != "root" ]; then 
    /bin/echo "You must be root." && exit 1 
fi 
umask 077
if [ -e ${AUDIT_DIR} ]; then
    /bin/mv ${AUDIT_DIR} ${AUDIT_DIR}.old || exit 1
fi

/bin/mkdir ${AUDIT_DIR} || exit 1
cd ${AUDIT_DIR} || exit 1


COMMAND_LIST="/usr/bin/chfn /usr/bin/chsh /usr/sbin/crond /usr/bin/crontab \
 /bin/du /usr/bin/find /sbin/ifconfig /usr/sbin/in.fingerd /usr/sbin/in.rshd \
 /usr/sbin/inetd /bin/killall /sbin/killall5 /bin/login /bin/ls \
 /bin/netstat /usr/bin/passwd /bin/ps /usr/bin/pstree /usr/sbin/sshd \
 /usr/sbin/syslogd /usr/sbin/tcpd /usr/bin/top"

ETC_LIST="/etc/apache /etc/at* /etc/*conf* /etc/csh* /etc/default /etc/dhc* \
 /etc/export* /etc/fstab /etc/*ftp* /etc/X11/gdm/gdm.conf /etc/group \
 /etc/gshadow /etc/host* /etc/identd* /etc/inetd.conf /etc/inittab \
 /etc/issue* /etc/ld* /etc/lilo.conf /etc/limits /etc/login* /etc/mail* \
 /etc/modules.conf /etc/motd /etc/named* /etc/orbitrc /etc/passwd \
 /etc/porttime /etc/ppp /etc/profile* /etc/resolv.conf /etc/rc.d \ 
 /etc/securetty /etc/sendmail.cf /etc/shadow /etc/shells /etc/snort* /etc/ssh \
 /etc/ssl /etc/su* /etc/syslog.conf /etc/tripwire /etc/X11/xdm/X* \
 /etc/X11/xdm/xdm-config /etc/yp*"

HOME_LIST="/home/*/.*bash* /home/*/.*csh* /home/*/dead.letter /home/*/.gnupg \
 /home/*/.log* /home/*/.netrc /home/*/.prof* /home/*/.rhosts /home/*/.ssh \
 /home/*/.Xa* /root/.*bash* /root/.*csh* /root/dead.letter /root/.gnupg \
 /root/.log* /root/.netrc /root/.prof* /root/.rhosts /root/.ssh /root/.Xa* \
 /home/*/.shosts"

LOG_LIST="access_log apache/access_log boot.log cron debug error_log \
 apache/error_log mail messages proftpd.log secure sulog syslog xferlog"

VAR_LIST="/var/lib/apache/cgi-bin /var/lib/apache/conf /var/spool/cron \
 /var/tmp /var/www/cgi-bin /var/yp"


# Make copies
/bin/cp -Ppf ${COMMAND_LIST} ./ 2> /dev/null
/bin/cp -PpfR ${ETC_LIST} ./ 2> /dev/null
/bin/cp -PpfR ${HOME_LIST} ./ 2> /dev/null
/bin/cp -PpfR ${VAR_LIST} ./ 2> /dev/null


# Various checks
/bin/cat > file_stripped.out <<EOF
NOTE: Slackware strips all of it's binaries.  Any file that is not stripped
has been replaced and is more than likely trojaned.

EOF
for i in ${COMMAND_LIST}; do
    /bin/echo -e "\nCommand: ${i}:" >> file_stripped.out 2>&1
    /usr/bin/file ${i} | /usr/bin/egrep "not stripped" >> file_stripped.out 2>&1
done

# md5sum doesn't like to do globbing =(
for i in ${COMMAND_LIST} ${ETC_LIST} ${HOME_LIST} ${VAR_LIST}; do
    if [ -f ${i} ]; then
        /usr/bin/md5sum ${i} >> md5sum.out 2>&1
    fi
done

/bin/cat > strings_filelist.out <<EOF
NOTE:  This is a list of files that the commands access.  Look for anything
that doesn't seem right.

EOF
for i in ${COMMAND_LIST}; do
    /bin/echo -e "\nCommand: ${i}" >> strings_filelist.out 2>&1   
    for j in `/usr/bin/strings ${i} | /usr/bin/egrep "^/"`; do
        if [ -f ${j} ]; then
            /bin/echo ${j} >> strings_filelist.out 2>&1
        fi
    done
done

/bin/cat > strings_md5sum.out <<EOF
NOTE: If an md5sum is present in a command, this could possibly indicate
a password is included in that command and it is more than likely trojaned.

EOF
for i in ${COMMAND_LIST}; do
    /bin/echo -e "\nCommand: ${i}" >> strings_md5sum.out 2>&1
#    /usr/bin/strings ${i} | /usr/bin/egrep "([0-9a-z]{32})" >> strings_md5sum.out 2>&1
#done
    /usr/bin/strings ${i} | /usr/bin/egrep -i "(^|[^0-9a-f])[0-9a-f]{32}($|[^0-9a-f])" >> strings_md5sum.out 2>&1
done

for i in ${COMMAND_LIST}; do
    /bin/echo -e "\n Command: ${i}" >> ldd.out 2&>1
    /usr/bin/ldd ${i} >> ldd.out 2&>1
done

/bin/cat > strings_promisc.out << EOF
NOTE: If \"PROMISC\" is not present for each command, then it is more than 
likely trojaned.

EOF
for i in /sbin/ifconfig /bin/netstat; do 
    /bin/echo -n "Command ${i}: " >> strings_promisc.out 2>&1
    /usr/bin/strings ${i} | /usr/bin/egrep "PROMISC" >> strings_promisc.out 2>&1
done

for i in `/usr/bin/cat /etc/passwd | /usr/bin/awk -F: '{print $1}'`; do
    /usr/bin/passwd -S $i >> passwd_status.out 2>&1
done

for i in `/bin/netstat -ant | /usr/bin/awk '{print $4}' | /usr/bin/awk -F: '{print $2}'`; do
    /usr/bin/fuser -v -n tcp $i >> fuser.out 2>&1
done

for i in `/bin/netstat -ant | /usr/bin/awk '{print $4}' | /usr/bin/awk -F: '{print
$2}'`; do
    /usr/bin/lsof -i :$i >> lsof_ports.out 2>&1
done


# List
/bin/ls -alR /etc &> ls-etc.out
/bin/ls -alRL /dev &> ls-dev.out
/bin/ls -al /tmp &> ls-tmp.out
/bin/ls -alR /var/log /var/spool/mail &> ls-var.out


# Various commands
/sbin/arp -a &> arp.out
/usr/bin/atq &> atq.out
/usr/bin/cat /etc/slackware-version &> uname.out
/usr/bin/cat /proc/mount &> mount_proc.out
/usr/bin/cat /proc/*/stat | /usr/bin/awk '{print $1,$2}' &> proc_stat.out
/usr/bin/env &> env.out
/usr/sbin/faillog &> faillog.out
/usr/sbin/grpck -r &> grpck.out
/sbin/ifconfig -a &> ifconfig.out
/sbin/ipchains -nL &> ipchains.out
/usr/bin/last -5 root &> last_root.out
/usr/bin/last -25 &> last_25.out
# lastb and /var/log/btmp must be created first
/usr/sbin/lastb &> lastb.out
/usr/local/bin/lastcomm &> lastcomm.out
/sbin/ldconfig -p &> ldconfig.out
/sbin/lsmod &> lsmod.out
/usr/bin/lsof &> lsof.out
/sbin/mount &> mount.out
/bin/netstat -an &> netstat-an.out
/bin/netstat -rnee &> netstat-rnee.out
/bin/ps auxwww &> ps.out
/usr/bin/praliases &> praliases.out
/usr/bin/procinfo -a &> procinfo.out
/usr/sbin/pwck -r &> pwck.out
/sbin/quotacheck -a &> quotacheck.out
/usr/sbin/quotastats &> quotastats.out
/usr/sbin/rpcinfo -p &> rpcinfo.out
/usr/local/sbin/sa &> sa.out
/usr/sbin/sfdisk -lVx &> sfdisk.out
/usr/bin/socklist &> socklist.out
/usr/local/sbin/sxid -kn &> sxid.out
for i in ${LOG_LIST}; do
    /bin/echo -e "\nLogfile: ${i}" >> log.out 2>&1
    /usr/bin/tail -n 25 /var/log/${i} >> log.out 2>&1
done
/bin/uname -a >> uname.out 2>&1
/usr/bin/uptime &> uptime.out
/usr/bin/w &> who.out


# Various shell commands
alias -p &> alias.out
bind -P &> bind-functions.out
bind -V &> bind-variables.out
enable -a &> enable.out
export -p &> export.out
shopt &> shopt.out


# Proc settings
for i in icmp_echo_ignore_broadcasts icmp_echo_ignore_all tcp_syncookies \
 ip_always_defrag ; do
    /bin/echo -n "/proc/sys/net/ipv4/${i}: " >> proc.out 2>&1
    /usr/bin/cat /proc/sys/net/ipv4/${i} >> proc.out 2>&1
    /bin/echo "" >> proc.out 2>&1
done

for i in /proc/sys/net/ipv4/conf/*; do
    for j in accept_redirects accept_source_route rp_filter bootp_relay \
     mc_forwarding log_martians proxy_arp secure_redirects; do
        /bin/echo -n "${i}/${j}: " >> proc.out 2>&1
        /usr/bin/cat ${i}/${j} >> proc.out 2>&1
        /bin/echo "" >> proc.out 2>&1
    done
done


# Find
# These significantly add to the time it takes for this script to run.
# Comment as necessary.
/usr/bin/find / \( -perm -4000 -o -perm -2000 \) -type f \
 -ls &> find-s_id.out
#/usr/bin/find / -perm -2 '!' -type l -ls | egrep -v "dev" &> find-write.out
/usr/bin/find / \( -pern -g+w -o -perm -o+w \) -type d -ls &> find-dir-write.out
/usr/bin/find / \( -perm -g+w -o -perm -o+w \) -type d -not -perm -a+t \
 -ls &> find-not-sticky.out
/usr/bin/find / -nouser -o -nogroup -ls &> find-nouser.out
/usr/bin/find / -type l -ls | grep "/dev/null" &> find-null.out
/usr/bin/find / \( -name "\ *" -o -name ".\ *" -o -name "..?*" \) \
 -exec /bin/cp -PpR {} ./odd/ \; 
/usr/bin/find / -type f -name "*.swp" -exec /bin/cp -Pp {} ./swp/ \;
/usr/bin/find / -name core -ls &> core.out 
/usr/bin/find /dev -type f -ls &> dev-files.out
/usr/bin/find / \( -type b -o -type c \) -print | /usr/bin/grep -v '^/dev' \
 &> devices.out
/usr/bin/find / \( -perm -4000 -o -2000 \) -type f \
 -exec file {} \; | grep -v ELF &> suid-scripts.out


# Filesystem Integrity Checks
if [ -x /usr/sbin/tripwire -o -x /usr/local/sbin/tripwire ]; then
    tripwire -m c &> twcheck.out
fi

if [ -x /usr/sbin/aide -o -x /usr/local/sbin/aide ]; then
    aide --config=/etc/aide.conf &> aide.out
fi


cd .. 
/bin/tar zcf ${OUTFILE} ${AUDIT_DIR} 2> /dev/null
/bin/rm -rf ${AUDIT_DIR} 2> /dev/null
/bin/mv ${AUDIT_DIR}.old ${AUDIT_DIR} 2> /dev/null
/bin/echo -e "\nFinished.  The output file is called ${OUTFILE}.\n"

exit 0

#systemout
