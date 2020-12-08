#!/bin/sh
## Xe1phix-Sysctl-7.3.sh


## ==================================================================================== ##
# LD_LIBRARY_PATH=""
# LD_PRELOAD=""					## list  of ELF shared objects to be loaded before all others.
# ldsoconf="/etc/ld.so.conf"	## File  containing  a  list  of Library directories
# ldso="/lib/ld.so"				## Runtime dynamic linker That resolving shared object dependencies
# dSoCache="/etc/ld.so.cache"			## File containing an ordered list of libraries
# ldLinuxso="/lib/ld-linux.so.{1,2}"	## ELF dynamic linker/loader
## ==================================================================================== ##
# /sbin/sysctl -a --pattern 'net.ipv4.conf.(eth|wlan)0.arp'
# /sbin/sysctl -a --pattern 'net.ipv4.conf.(eth|wlan)(0|1)'
# /sbin/sysctl -a --pattern 'net.ipv6.conf.(eth|wlan)(0|1)'
## ==================================================================================== ##
# for i in ; do echo 1 > $i; done
# for i in ; do echo 1 > $i; done
echo "## ============================================================================== ##"
echo -e "\tHardening /proc/sys/kernel/kptr_restrict {Value: 2}"
echo -e "\tkernel pointers printed using the %pK format specifier will be"
echo -e "\treplaced with zeros regardless of the user's  capabilities"
echo "## ============================================================================== ##"
for i in /proc/sys/kernel/kptr_restrict; do echo 2 > $i; done
echo
echo "## ============================================================================== ##"
echo -e "\t\t\tHardening kernel syslog contents..."
echo "## ============================================================================== ##"
for i in /proc/sys/kernel/dmesg_restrict; do echo 1 > $i; done
echo
echo "## ============================================================================== ##"
echo -e "\t\t\t{+} Enabling Kernel Stack Tracer..."
echo "## ============================================================================== ##"
sysctl -w kernel.stack_tracer_enabled="1"
echo "## ============================================================================== ##"
echo -e "\t\t\tForcing cdroms To Check Media Integrity..."
echo "## ============================================================================== ##"

if [ -e /lib/udev/rules.d/60-cdrom_id.rules ]
then
	mkdir -p "${DESTDIR}/lib/udev/rules.d"
	cp -p /lib/udev/rules.d/60-cdrom_id.rules "${DESTDIR}/lib/udev/rules.d"
fi

sysctl -w dev.cdrom.check_media="1"
echo "## ============================================================================== ##"
echo -e "\t\t\tModifying cdrom To AutoEject..."
echo "## ============================================================================== ##"
sysctl -w dev.cdrom.autoeject="1"
echo
echo "## ============================================================================== ##"
echo -e "\t\t\t{+} Enabling Kernels Use of PID's..."
echo "## ============================================================================== ##"
sysctl -q -w kernel.core_uses_pid="1"   # Controls whether core dumps will append the PID to the core filename
echo
echo
## 
## 
# kernel.pid_max
# kernel.pty.max = 4096
# kernel.pty.nr = 12
# kernel.stack_tracer_enabled = 0
# kernel.sysctl_writes_strict = 1
# kernel.yama.ptrace_scope
# kernel.tracepoint_printk = 0
# kernel.unknown_nmi_panic = 0
# kernel.unprivileged_bpf_disabled = 0
# kernel.unprivileged_userns_clone = 0
# /proc/sys/net/core/bpf_jit_enable
## 
## 
# echo "## ============================================================================== ##"
# echo -e "\t\t[+] Enables a system-wide task dump (excluding kernel threads) to be"
# echo -e "\t\t[+] produced when  the  kernel performs an OOM-killing {The default value is 0}"
# echo "## ============================================================================== ##"
# /proc/sys/vm/oom_dump_tasks
## 
## 
# echo "## ============================================================================== ##"
# echo -e "\t\t[+] /proc/pid/numa_maps is an extension based on maps, showing the memory
# echo -e "\t\t[+] locality and binding policy, as well as the memory usage (in pages) of each mapping.
# echo "## ============================================================================== ##"
## 
## 
# echo "## ============================================================================== ##"
# echo -e "\t\t[+] To Free PageCache, Use:"
# echo "## ============================================================================== ##"
# for i in /proc/sys/vm/drop_caches; do echo 1 > $i; done
# echo
# echo
# echo "## ============================================================================== ##"
# echo -e "\t\t[+] To Free Dentries And Inodes, Use:"
# echo "## ============================================================================== ##"
# for i in /proc/sys/vm/drop_caches; do echo 2 > $i; done
# echo
# echo
# echo "## ============================================================================== ##"
# echo -e "\t\t[+] To Free PageCache, Dentries And Inodes, Use:"
# echo "## ============================================================================== ##"
# for i in /proc/sys/vm/drop_caches; do echo 3 > $i; done
# echo
# echo
echo "## ============================================================================== ##"
echo -e "\t\t\t[+] Disabling Bootp_Relay, Insecure In The Right 
echo "## ============================================================================== ##"
for i in /proc/sys/net/ipv4/conf/*/bootp_relay; do echo 0 > $i; done
echo
echo "## ============================================================================== ##"
echo -e "\t\t\t[+] Enabling Bad Error Message Protection..."
echo "## ============================================================================== ##"
sysctl -w net.ipv4.icmp_ignore_bogus_error_responses=1
echo
echo "## ============================================================================== ##"
echo -e "\t[+] Enable IP Spoofing Protection (i.e. Source Address Verification)"
echo "## ============================================================================== ##"
##
if [ "/proc/sys/net/ipv4/conf/all/rp_filter" = "0" ]; then
	if [ -e /proc/sys/net/ipv4/conf/all/rp_filter ]; then
        echo -n "Setting up IP spoofing protection..."
		for i in /proc/sys/net/ipv4/conf/*/rp_filter; do
        echo 1 > $i
        	done
        rpfilt="cat /proc/sys/net/ipv4/conf/all/rp_filter"
		echo "/proc/sys/net/ipv4/conf/all/rp_filter:$rpfilt"
	else
        echo "WARNING: Errors Encountered While Trying To Enable IP Spoofing Protection!"
	fi
fi

 "## +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-++-+-+-+-+-+-+-+-+-+-+ ##"


echo "## ============================================================================== ##"
echo -e "\t\t\t[+] Modifying The Tcp_Max_Syn_Backlog Parameter To 2048..."
echo "## ============================================================================== ##"
echo "## ----------------------------------------------------------------------------------------------------- ##"
echo -e "\t [?] This parameter defines how many half-open connections"
echo -e "\t [?] can be retained by the backlog queue."

echo -e "\t Half-open connections are Connections In Which:"
echo "##=~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~=##"
echo -e "\t\t[?]> A SYN packet has been received"
echo -e "\t\t[?]> A SYN/ACK packet has been sent"
echo -e "\t\t[?]> And an ACK packet has not yet been received."
echo "##=~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~=##"
echo
echo "## ------------------------------------------------------------------------------------------ ##"
echo -e "\t Once the backlog value has been reached, the system cannot receive any "
echo -e "\t more connections until the existing ones are either established or timed out."
echo "## ------------------------------------------------------------------------------------------ ##"
sysctl -w net.ipv4.tcp_max_syn_backlog="2048"


echo "## ============================================================================== ##"
echo -e "\t\t\t[+] Modifying The Tcp_Synack_Retries Parameter To 3..."
echo "## ============================================================================== ##"
echo
echo "## ------------------------------------------------------------------- ##"
echo -e "\t [?] This parameter controls the number of SYN/ACK retransmissions."
echo -e "\t\t\t The following values apply:"
echo "##=~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~=##"
echo -e "\t\t[?]> value = 5 (3 minutes)"
echo -e "\t\t[?]> value = 3 (45 seconds)"
echo -e "\t\t[?]> value = 2 (21 seconds)"
echo -e "\t\t[?]> value = 1 (9 seconds)"
echo "##=~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~+~=##"
echo
echo "## --------------------------------------------------------------------------------------------------- ##"
echo -e "\t Be Careful not to set the values too low"
echo -e "\t as low values will create a denial of service by design."

echo -e "\t If legitimate network traffic from remote destinations takes longer "
echo -e "\t to traverse the Internet than the configured retransmission value."
echo "## --------------------------------------------------------------------------------------------------- ##"
sysctl -w net.ipv4.tcp_ synack_retries="3"
echo
echo

sysctl -w /proc/sys/fs/suid_dumpable="0"


proc/sys/kernel/acct



for i in /proc/sys/net/ipv4/conf/*/rp_filter ; do
> echo 2 > $i
> done


echo "## ============================================================================== ##"
echo -e "\t\t\t[+] Ignoring IMCP Echo Broadcasts..."
echo "## ============================================================================== ##"
echo "## ----------------------------------------------------------------------------------------------------- ##"
echo -e "\tIgnores only ICMP messages sent to broadcast or multicast addresses."
echo -e "\tThis significantly reduces the risk of a host being targeted by a smurf attack."
echo "## ----------------------------------------------------------------------------------------------------- ##"
sysctl -w net/ipv4/icmp_echo_ignore_broadcasts ="1"
echo
echo
# echo "## ============================================================================== ##"
# echo -e "\t\t\t[+] Adjusting ICMP Rate Limit..."
# echo "## ============================================================================== ##"
# cat /proc/sys/net/ipv6/icmp/ratelimit 
echo
echo

# net.core.bpf_jit_enable = 1
# net.core.bpf_jit_harden = 1
# kernel.yama.ptrace_scope
# sysctl -w kernel.stack_tracer_enabled="1"
# sysctl -w dev.cdrom.info="1"


## ============================================================================== ##
# if [ "${ENABLE_SRC_ADDR_VERIFY}" = "Y" ]; then
# for i in /proc/sys/net/ipv4/conf/*/rp_filter; do echo 1 > $i; done
## ============================================================================== ##
echo
echo "## ============================================================================== ##"
echo -e "\t\t\t[+] Protect against SYN flood attacks "
echo "## ============================================================================== ##"
echo 1 > /proc/sys/net/ipv4/tcp_syncookies
echo
echo "## ============================================================================== ##"
echo -e "\t\t\t[+] Disable proxy_arp. Should not be needed, usually."
echo "## ============================================================================== ##"
for i in /proc/sys/net/ipv4/conf/*/proxy_arp; do echo 0 > $i; done
echo
echo
echo "## ============================================================================== ##"
echo -e "\t\t\t[+] Enable secure redirects, i.e. only accept ICMP redirects for gateways"
echo -e "\t\t\t\tlisted in the default gateway list."
echo "## ============================================================================== ##"
for i in /proc/sys/net/ipv4/conf/*/secure_redirects; do echo 1 > $i; done
echo
echo
echo "## ============================================================================== ##"
echo -e "\t\t\t[+] Logging Packets With Impossible Addresses..."
echo "## ============================================================================== ##"
for i in /proc/sys/net/ipv4/conf/*/log_martians; do echo 1 > $i; done
echo
echo
echo

echo "## ============================================================================== ##"
echo -e "\t\t\t[+] Disabling IPv4 automatic defragmentation..."
echo "## ============================================================================== ##"
if [ -f /proc/sys/net/ipv4/ip_always_defrag ]; then
	        if [ `cat /proc/sys/net/ipv4/ip_always_defrag` != 0 ]; then
				sysctl -w net.ipv4.ip_always_defrag=0
			fi
fi
echo
echo
echo "## ============================================================================== ##"
echo -e "\t\t\t[+] Enabling rp_filter for All Interfaces..."
echo "## ============================================================================== ##"
echo "## ----------------------------------------------------------------------------------------------------- ##"
echo -e "\tThis parameter controls reverse path filtering"
echo -e "\tThis tries to ensure packets use legitimate source addresses."
echo -e "\tWhen it is turned on, then incoming packets whose routing table entry for the"
echo -e "\tsource address does not match the interface they are coming in on are rejected."
echo -e "\tThis can prevent some IP spoofing attacks."
echo "## ----------------------------------------------------------------------------------------------------- ##"
for interface in /proc/sys/net/ipv4/conf/*/rp_filter; do
	/bin/echo "1" > ${interface}
done
echo "## ============================================================================== ##"
echo -e "\t\t\t[+] Double Check The RP Filter Was Enabled On ALL Interfaces..."
echo "## ============================================================================== ##"
cat /proc/sys/net/ipv4/conf/*/rp_filter
echo
echo
echo "## ============================================================================== ##"
echo -e "\t\t\t[+] Don't accept or send ICMP redirects."
echo "## ============================================================================== ##"
echo "## ----------------------------------------------------------------------------------------------------- ##"
echo -e "\tThe accept_redirects parameter determines whether your system accepts ICMP redirects."
echo -e "\tICMP redirects are used to tell routers or hosts that there is a faster "
echo -e "\tor less congested way to send the packets to specific hosts or networks."
echo "## ----------------------------------------------------------------------------------------------------- ##"
for i in /proc/sys/net/ipv4/conf/*/accept_redirects; do echo 0 > $i; done
for i in /proc/sys/net/ipv4/conf/*/send_redirects; do echo 0 > $i; done
echo
echo "## ============================================================================== ##"
echo -e "\t\t\t[+] Disabling IPv6..."
echo "## ============================================================================== ##"
echo 1 > /proc/sys/net/ipv6/conf/default/disable_ipv6
echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6
echo
echo "## ============================================================================== ##"
echo -e '\t\t'{BLOODRED}'Disabling IPV6...''{RESET}'
echo "## ============================================================================== ##"
for i in /sys/module/ipv6/parameters/disable; do echo 1 > $i; done
for i in /sys/module/ipv6/parameters/disable_ipv6; do echo 1 > $i; done
echo
echo
IPV6ACCEPTDAD=$(cat /proc/sys/net/ipv6/conf/all/disable_ipv6)
if [ $ACCEPTDAD = 1 ]; then
	sysctl -w net.ipv6.conf.all.accept_dad="0"
else
	echo -e "\t\t\t[+] IPV6 Accept Dad Is'nt Enabled, No Need To Customize The Sysctl Rule..."
fi
echo
echo
IPV6ACCEPTRA=$(cat /proc/sys/net/ipv6/conf/all/accept_ra)
if [ $IPV6ACCEPTRA = 1 ]; then
	sysctl -w net.ipv6.conf.all.accept_ra="0"
else
	echo -e "\t\t\t[+] IPV6 Accept Router Avertisement Is'nt Enabled, No Need To Customize The Sysctl Rule..."
fi
echo
echo
IPV6DADTRANSMITS=$(cat /proc/sys/net/ipv6/conf/all/dad_transmits)
if [ $IPV6DADTRANSMITS = 1 ]; then
	sysctl -w net.ipv6.conf.all.dad_transmits="0"
else
	echo -e "\t\t\t[±] IPV6 Dad Transmits Is'nt Enabled, No Need To Customize The Sysctl Rule..."
fi
echo
echo
IPV6DADTRANSMITS=$(cat /proc/sys/net/ipv6/conf/all/accept_redirects)
if [ $IPV6DADTRANSMITS = 1 ]; then
	sysctl -w net.ipv6.conf.all.accept_redirects="0"
else
	echo -e "\t\t\t[+] IPV6 Accept Redirects Is'nt Enabled, No Need To Customize The Sysctl Rule..."
fi
echo
echo
IPV6DADTRANSMITS=$(cat /proc/sys/net/ipv6/conf/all/accept_redirects)
if [ $IPV6DADTRANSMITS = 1 ]; then
	sysctl -w net.ipv6.conf.all.accept_redirects="0"
else
	echo -e "\t\t\t[+] IPV6 Accept Redirects Is'nt Enabled, No Need To Customize The Sysctl Rule..."
fi
echo
echo
IPV6DADTRANSMITS=$(cat /proc/sys/net/ipv6/conf/all/accept_redirects)
if [ $IPV6DADTRANSMITS = 1 ]; then
	sysctl -w net.ipv6.conf.all.accept_redirects="0"
else
	echo -e "\t\t\t[+] IPV6 Accept Redirects Is'nt Enabled, No Need To Customize The Sysctl Rule..."
fi
echo
sysctl -w net.ipv6.conf.all.accept_ra_mtu="0"
sysctl -w net.ipv6.conf.all.autoconf="0"
sysctl -w net.ipv6.conf.all.disable_ipv6="1"
# sysctl -w net.ipv6.conf.all.accept_dad="0"
# sysctl -w net.ipv6.conf.all.accept_dad="0"
# sysctl -w net.ipv6.conf.all.accept_ra="0"
# sysctl -w net.ipv6.conf.all.accept_redirects="0"
sysctl -w net.ipv6.conf.all.accept_dad="0"
sysctl -w net.ipv6.conf.all.accept_ra="0"
sysctl -w net.ipv6.conf.all.accept_ra_defrtr="0"
sysctl -w net.ipv6.conf.all.accept_ra_pinfo="0"
sysctl -w net.ipv6.conf.all.accept_ra_rt_info_max_plen="0"
sysctl -w net.ipv6.conf.all.accept_ra_rtr_pref="0"
sysctl -w net.ipv6.conf.all.accept_redirects="0"
sysctl -w net.ipv6.conf.all.accept_source_route="0"
echo
# echo "faggot" > /proc/sys/kernel/hostname
# echo "## ============================================================================== ##"
# echo -e "\t\t\t[+] Modifying Local Port Range..."
# echo "## ============================================================================== ##"
# cat /proc/sys/net/ipv4/ip_local_port_range
echo
## echo "## ============================================================================== ##"
## echo -e "\t\t\t[+] Changing TW Socket Reuse & Recycling Time-Wait Values..."
## echo "## ============================================================================== ##"
## echo -e "\t[+] Warning: This may cause dropped frames with load-balancing and NATs,
## echo -e "\t[+] only use this for a server that communicates only over your local network.
## sysctl -w net.ipv4.tcp_tw_reuse = 1
## sysctl -w net.ipv4.tcp_tw_recycle = 1
echo


echo "## ############################################################################## ##"
echo "## ============================================================================== ##"
echo -e "\t\t\t[+] Hardening Ulimit Configurations..."
echo "## ============================================================================== ##"
echo "## ############################################################################## ##"
echo
echo
echo "## ============================================================================== ##"
echo -e "\t\t\t[+] Modifying User Process Limits..."
echo "## ============================================================================== ##"

if [ -e /etc/security/limits.conf ]; then
	if [ -e /proc/sys/net/ipv4/conf/all/rp_filter ]; then
        echo -n "Setting up IP spoofing protection..."
		for i in /proc/sys/net/ipv4/conf/*/rp_filter; do
        echo 1 > $i
        	done
        rpfilt="cat /proc/sys/net/ipv4/conf/all/rp_filter"
		echo "/proc/sys/net/ipv4/conf/all/rp_filter:$rpfilt"
	else
        echo "WARNING: errors encountered while trying to enable IP spoofing protection!"
	fi
fi

echo "*   hard    nproc   250              # Limit user processes " >> /etc/security/limits.conf
echo
echo
echo "## ============================================================================== ##"
echo -e "\t\t\t[+] noexec_user_stack"
echo "## ============================================================================== ##"
sysctl -w noexec_user_stack="1"
set noexec_user_stack=1
echo "## ============================================================================== ##"
echo -e "\t\t\t[+] noexec_usr_stack_log"
echo "## ============================================================================== ##"
sysctl -w noexec_usr_stack_log="1"
set noexec_usr_stack_log=1
echo
echo
sysctl -w kernel.randomize_va_space="2"
echo
echo


echo "## ============================================================================== ##"
echo -e "\t\t[+] Checking Value of Kernel Secure Level..."
echo -e "\t\t[+] Modifying Parameter Value If Value isnt 2..."
echo "## ============================================================================== ##"
SECURELEVEL=$(cat /sys/kernel/security/securelevel)
if [ $SECURELEVEL = 0 ];then 
	echo 2 > /sys/kernel/security/securelevel			# sysctl -w kern.securelevel="2"
	echo -e "\t\t\t[+] Kernel Secure Level Is Now 2..."
else
	echo -e "\t\t\t[+] Kernel Secure Level Is 2, No Need To Change It..."
	echo 
fi
echo

echo "## ============================================================================== ##"
echo -e "\t\t\t[+] Setting Dmesg Restrict To 0..."
echo "## ============================================================================== ##"
# DMESGRESTRICT=$(cat )
sysctl -w kernel.dmesg_restrict="0"
echo
echo

echo "## ============================================================================== ##"
echo -e "\t\t\t[+] Modifying Kernel Kptr_Restrict Value To 1..."
echo "## ============================================================================== ##"
sysctl -w kernel.kptr_restrict="1"
echo
echo
echo "## ============================================================================== ##"
echo -e "\t\t\t[+] Enabling ExecShield Protection..."
echo "## ============================================================================== ##"
sysctl -w kernel.exec-shield="1"
set kernel.exec-shield="1"
echo
echo
echo "## ============================================================================== ##"
echo -e "\t\t\t[+] Enabling Kernels Use of PIDs..."
echo "## ============================================================================== ##"
sysctl -q -w kernel.core_uses_pid="1"
echo
echo
if [ -e "/etc/sysctl.conf" ]; then
	echo "## ============================================================================== ##"
	echo -e "\t\t\t[+] /etc/sysctl.conf Exists!"
	echo "## ============================================================================== ##"
		else
			echo "# Do not accept ICMP redirects (prevent MITM attacks)" >> /etc/sysctl.conf
			echo "net.ipv4.conf.all.accept_redirects=0" >> /etc/sysctl.conf
			echo "net.ipv6.conf.all.accept_redirects=0" >> /etc/sysctl.conf
			echo -e "\n\n"
			echo "## TCP SYN cookie protection (default)" >> /etc/sysctl.conf
			echo "## helps protect against SYN flood attacks" >> /etc/sysctl.conf
			echo "## only kicks in when net.ipv4.tcp_max_syn_backlog is reached" >> /etc/sysctl.conf
			echo "net.ipv4.tcp_syncookies=1" >> /etc/sysctl.conf
			echo -e "\n\n" >> /etc/sysctl.conf
			echo "#net.ipv6.conf.default.accept_redirects=0" >> /etc/sysctl.conf
			echo -e "\n\n" >> /etc/sysctl.conf
			echo "net.ipv4.tcp_timestamps=0" >> /etc/sysctl.conf
			echo -e "\n\n" >> /etc/sysctl.conf
			echo "net.ipv4.conf.default.log_martians=1" >> /etc/sysctl.conf
			echo -e "\n\n" >> /etc/sysctl.conf
			echo "net.ipv4.icmp_echo_ignore_broadcasts=1" >> /etc/sysctl.conf
			echo -e "\n\n" >> /etc/sysctl.conf
			echo "net.ipv4.conf.all.forwarding=0" >> /etc/sysctl.conf
			echo -e "\n\n" >> /etc/sysctl.conf
			echo "net.ipv4.conf.all.rp_filter=1" >> /etc/sysctl.conf
			echo -e "\n\n" >> /etc/sysctl.conf
			echo "net.ipv4.tcp_max_syn_backlog=1280" >> /etc/sysctl.conf
			echo -e "\n\n" >> /etc/sysctl.conf
			echo "kernel.core_uses_pid=1" >> /etc/sysctl.conf   						# Controls whether core dumps will append the PID to the core filename
			echo -e "\n\n" >> /etc/sysctl.conf
			echo "kernel.sysrq=0" >> /etc/sysctl.conf
			echo -e "\n\n" >> /etc/sysctl.conf
			echo "kernel.randomize_va_space=2" >> /etc/sysctl.conf
			echo "kern.securelevel=1" >> /etc/sysctl.conf
			echo "" >> /etc/sysctl.conf
			echo "" >> /etc/sysctl.conf
			echo "" >> /etc/sysctl.conf
			echo -e "\n\n" >> /etc/sysctl.conf
			echo "## ignore all pings" >> /etc/sysctl.conf
			echo "net.ipv4.icmp_echo_ignore_all=1" >> /etc/sysctl.conf
			echo -e "\n\n" >> /etc/sysctl.conf
			echo "## Do not send ICMP redirects (we are not a router)" >> /etc/sysctl.conf
			echo "net.ipv4.conf.all.send_redirects = 0" >> /etc/sysctl.conf
			echo -e "\n\n" >> /etc/sysctl.conf
			echo "## Do not accept IP source route packets (we are not a router)" >> /etc/sysctl.conf
			echo "net.ipv4.conf.all.accept_source_route = 0" >> /etc/sysctl.conf
			echo "net.ipv6.conf.all.accept_source_route = 0" >> /etc/sysctl.conf
			echo -e "\n\n" >> /etc/sysctl.conf
			echo "## Log Martian Packets" >> /etc/sysctl.conf
			echo "net.ipv4.conf.all.log_martians = 1" >> /etc/sysctl.conf
			echo -e "\n\n" >> /etc/sysctl.conf
			echo "kernel.exec-shield = 1" >> /etc/sysctl.conf
			# echo " = 1" >> /etc/sysctl.conf
			# echo " = 1" >> /etc/sysctl.conf
			# echo " = 1" >> /etc/sysctl.conf
			# echo " = 1" >> /etc/sysctl.conf
			# echo " = 1" >> /etc/sysctl.conf
fi
echo -e "## ============================================================================== ##"
echo -e "\t\t\t[+] Applying Sysctl Changes..."
echo -e "## ============================================================================== ##"
sysctl -p


chmod 0644 /etc/sysctl.conf 
chown root:root /etc/sysctl.conf

