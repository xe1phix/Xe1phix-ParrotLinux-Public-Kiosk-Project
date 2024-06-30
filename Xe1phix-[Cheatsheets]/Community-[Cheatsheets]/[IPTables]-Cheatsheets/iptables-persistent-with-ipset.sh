#!/bin/sh
#               Written by Simon Richter <sjr@debian.org>
#               modified by Jonathan Wiltshire <jmw@debian.org>
#               with help from Christoph Anton Mitterer
#

### BEGIN INIT INFO
# Provides:          iptables-persistent
# Required-Start:    mountkernfs $local_fs
# Required-Stop:     $local_fs
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# X-Start-Before:    $network
# X-Stop-After:      $network
# Short-Description: Set up iptables rules
# Description:       Loads/saves current iptables rules from/to /etc/iptables
#  to provide a persistent rule set during boot time
### END INIT INFO

. /lib/lsb/init-functions

rc=0

load_rules()
{
        log_action_begin_msg "Loading iptables rules"

        #load IPv4 rules
        if [ ! -f /etc/iptables/rules.v4 ]; then
                log_action_cont_msg " skipping IPv4 (no rules to load)"
        else
                log_action_cont_msg " IPv4"
                ipset restore < /etc/iptables/ipset.v4
                iptables-restore < /etc/iptables/rules.v4 2> /dev/null
                if [ $? -ne 0 ]; then
                        rc=1
                fi
        fi

        #load IPv6 rules
        if [ ! -f /etc/iptables/rules.v6 ]; then
                log_action_cont_msg " skipping IPv6 (no rules to load)"
        else
                log_action_cont_msg " IPv6"
                ip6tables-restore < /etc/iptables/rules.v6 2> /dev/null
                if [ $? -ne 0 ]; then
                        rc=1
                fi
        fi

        log_action_end_msg $rc
}

save_rules()
{
        log_action_begin_msg "Saving rules"

        #save IPv4 rules
        #need at least iptable_filter loaded:
        /sbin/modprobe -q iptable_filter
        if [ ! -f /proc/net/ip_tables_names ]; then
                log_action_cont_msg " skipping IPv4 (no modules loaded)"
        elif [ -x /sbin/iptables-save ]; then
                log_action_cont_msg " IPv4"
                ipset save > /etc/iptables/ipset.v4
                touch /etc/iptables/rules.v4
                chmod 0640 /etc/iptables/rules.v4
                iptables-save > /etc/iptables/rules.v4
                if [ $? -ne 0 ]; then
                        rc=1
                fi
        fi

        #save IPv6 rules
        #need at least ip6table_filter loaded:
        /sbin/modprobe -q ip6table_filter
        if [ ! -f /proc/net/ip6_tables_names ]; then
                log_action_cont_msg " skipping IPv6 (no modules loaded)"
        elif [ -x /sbin/ip6tables-save ]; then
                log_action_cont_msg " IPv6"
                touch /etc/iptables/rules.v6
                chmod 0640 /etc/iptables/rules.v6
                ip6tables-save > /etc/iptables/rules.v6
                if [ $? -ne 0 ]; then
                        rc=1
                fi
        fi

        log_action_end_msg $rc
}

flush_rules()
{
        log_action_begin_msg "Flushing rules"

        if [ ! -f /proc/net/ip_tables_names ]; then
                log_action_cont_msg " skipping IPv4 (no module loaded)"
        elif [ -x /sbin/iptables ]; then
                log_action_cont_msg " IPv4"
                for param in F Z X; do /sbin/iptables -$param; done
                for table in $(cat /proc/net/ip_tables_names)
                do
                        /sbin/iptables -t $table -F
                        /sbin/iptables -t $table -Z
                        /sbin/iptables -t $table -X
						ipset -X
                done
                for chain in INPUT FORWARD OUTPUT
                do
                        /sbin/iptables -P $chain ACCEPT
                done
        fi

        if [ ! -f /proc/net/ip6_tables_names ]; then
                log_action_cont_msg " skipping IPv6 (no module loaded)"
        elif [ -x /sbin/ip6tables ]; then
                log_action_cont_msg " IPv6"
                for param in F Z X; do /sbin/ip6tables -$param; done
                for table in $(cat /proc/net/ip6_tables_names)
                do
                        /sbin/ip6tables -t $table -F
                        /sbin/ip6tables -t $table -Z
                        /sbin/ip6tables -t $table -X
                done
                for chain in INPUT FORWARD OUTPUT
                do
                        /sbin/ip6tables -P $chain ACCEPT
                done
        fi

        log_action_end_msg 0
}

case "$1" in
restart|reload|force-reload)
        save_rules
        flush_rules
        load_rules
        ;;
start)
        load_rules
        ;;
save)
        save_rules
        ;;
stop)
        # Why? because if stop is used, the firewall gets flushed for a variable
        # amount of time during package upgrades, leaving the machine vulnerable
        # It's also not always desirable to flush during purge
        echo "Automatic flushing disabled, use \"flush\" instead of \"stop\""
        ;;
flush)
        flush_rules
        ;;
*)
    echo "Usage: $0 {start|restart|reload|force-reload|save|flush}" >&2
    exit 1
    ;;
esac

exit $rc