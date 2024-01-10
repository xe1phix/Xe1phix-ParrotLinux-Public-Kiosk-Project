# Single target scan:
nmap [target]

# Scan from a list of targets:
nmap -iL [list.txt]

# iPv6:
nmap -6 [target]

# OS detection:
nmap -O --osscan_guess [target]

# Save output to text file:
nmap -oN [output.txt] [target]

# Save output to xml file:
nmap -oX [output.xml] [target]

# Scan a specific port:
nmap -source-port [port] [target]

# Do an aggressive scan:
nmap -A [target]

# Speedup your scan:
nmap -T5 --min-parallelism=50 [target]

# Traceroute:
nmap -traceroute [target]

# Ping scan only: -sP
# Don't ping:     -PN
# TCP SYN ping:   -PS
# TCP ACK ping:   -PA
# UDP ping:       -PU
# ARP ping:       -PR

# Example: Ping scan all machines on a class C network
nmap -sP 192.168.0.0/24

# Use some script:
nmap --script default,safe

# Loads the script in the default category, the banner script, and all .nse files in the directory /home/user/customscripts.
nmap --script default,banner,/home/user/customscripts

# Loads all scripts whose name starts with http-, such as http-auth and http-open-proxy.
nmap --script 'http-*'

# Loads every script except for those in the intrusive category.
nmap --script "not intrusive"

# Loads those scripts that are in both the default and safe categories.
nmap --script "default and safe"

# Loads scripts in the default, safe, or intrusive categories, except for those whose names start with http-.
nmap --script "(default or safe or intrusive) and not http-*"




# Sources: http://www.cyberciti.biz/networking/nmap-command-examples-tutorials/

# Scan multiple IP address or subnet (IPv4)
nmap 192.168.1.1 192.168.1.2 192.168.1.3
## works with same subnet i.e. 192.168.1.0/24
nmap 192.168.1.1,2,3
## wildcard scan
nmap 192.168.1.*

# Scans for open Ports (requires root access, err sudo)
sudo nmap -sS scanme.com

# The fastest way to scan all your devices/computers for open ports ever:
nmap -T5 192.168.1.0/24

# How do I detect remote operating system?
nmap -O 192.168.1.1
nmap -O  --osscan-guess 192.168.1.1
nmap -v -O --osscan-guess 192.168.1.1

# How do I detect remote services (server / daemon) version numbers?
nmap -sV 192.168.1.1

# Scan a host using TCP ACK (PA) and TCP Syn (PS) ping
# If firewall is blocking standard ICMP pings, try the following host discovery methods:
nmap -PS 192.168.1.1
nmap -PS 80,21,443 192.168.1.1
nmap -PA 192.168.1.1
nmap -PA 80,21,200-512 192.168.1.1

# -------------------------------------
# Scan a firewall for security weakness
# -------------------------------------

# The following scan types exploit a subtle loophole in the TCP and good for
# testing security of common attacks:

## TCP Null Scan to fool a firewall to generate a response ##
## Does not set any bits (TCP flag header is 0) ##
sudo nmap -sN 192.168.1.254

## TCP Fin scan to check firewall ##
## Sets just the TCP FIN bit ##
nmap -sF 192.168.1.254

## TCP Xmas scan to check firewall ##
## Sets the FIN, PSH, and URG flags, lighting the packet up like a Christmas tree ##
nmap -sX 192.168.1.254

# ----------------------------------------
# Scan a firewall for MAC address spoofing
# ----------------------------------------

### Spoof your MAC address ##
nmap --spoof-mac MAC-ADDRESS-HERE 192.168.1.1

### Add other options ###
nmap -v -sT -PN --spoof-mac MAC-ADDRESS-HERE 192.168.1.1

### Use a random MAC address ###
### The number 0, means nmap chooses a completely random MAC address ###
nmap -v -sT -PN --spoof-mac 0 192.168.1.1

# Scan a host using UDP ping
# This scan bypasses firewalls and filters that only screen TCP:
nmap -PU 192.168.1.1
nmap -PU 2000.2001 192.168.1.1

# Scan a host for UDP services (UDP scan)
# Most popular services on the Internet run over the TCP protocol. DNS,
# SNMP, and DHCP are three of the most common UDP services. Use the following
# syntax to find out UDP services:
nmap -sU nas03
nmap -sU 192.168.1.1

# Scans all reserved TCP ports on the machine
# "scanme.nmap.org". The "-v" option enables verbose mode.
nmap -v scanme.nmap.org

# Launches a stealth SYN scan against each machine that is
# up out of the 256 IPs on the class C sized network where Scanme
# resides. It also tries to determine what operating system is
# running on each host that is up and running. This requires root
# privileges because of the SYN scan and OS detection.
# NOTE: The "-v" option enables verbose mode.
sudo nmap -sS -O -v scanme.nmap.org/24

# Launches host enumeration and a TCP scan at the first half of each of the
# 255 possible eight-bit subnets in the 198.116 class B address space.
# This tests whether the systems run SSH, DNS, POP3, or IMAP on their
# standard ports, or anything on port 4564. For any of these ports found open,
# version detection is used to determine what application is running.
nmap -sV -p 22,53,110,143,4564 198.116.0-255.1-127

# Asks Nmap to choose 100,000 hosts at random and scan them for web servers
# (port 80). Host enumeration is disabled with -Pn since first sending a
# couple probes to determine whether a host is up is wasteful when you are
# only probing one port on each target host anyway.
nmap -v -iR 100000 -Pn -p 80

# This scans 4096 IPs for any web servers (without pinging them) and saves
# the output in grepable and XML formats.
nmap -Pn -p80 -oX logs/pb-port80scan.xml -oG logs/pb-port80scan.gnmap 216.163.128.20/20

##
# Complex version detection example
# src: http://nmap.org/book/vscan-examples.html
##
# This preceding scan demonstrates a couple things. First of all, it is
# gratifying to see www.Microsoft.Com served off one of Akamai's Linux boxes.
# More relevant to this chapter is that the listed service for port 443 is
# ssl/http. That means that service detection first discovered that the port
# was SSL, then it loaded up OpenSSL and performed service detection again
# through SSL connections to discover a web server running AkamiGHost behind
# the encryption. Recall that -T4 causes Nmap to go faster
# (more aggressive timing) and -F tells Nmap to scan only ports registered
# in nmap-services.
nmap -A -T4 localhost

# => OUTPUT OF nmap -A -T4 localhost
# Starting Nmap ( http://nmap.org )
# Nmap scan report for felix (127.0.0.1)
# (The 1640 ports scanned but not shown below are in state: closed)
# PORT     STATE SERVICE    VERSION
# 21/tcp   open  ftp        WU-FTPD wu-2.6.1-20
# 22/tcp   open  ssh        OpenSSH 3.1p1 (protocol 1.99)
# 53/tcp   open  domain     ISC BIND 9.2.1
# 79/tcp   open  finger     Linux fingerd
# 111/tcp  open  rpcbind    2 (rpc #100000)
# 443/tcp  open  ssl/http   Apache httpd 2.0.39 ((Unix) mod_perl/1.99_04-dev)
# 515/tcp  open  printer
# 631/tcp  open  ipp        CUPS 1.1
# 953/tcp  open  rndc?
# 5000/tcp open  ssl/ftp    WU-FTPD wu-2.6.1-20
# 5001/tcp open  ssl/ssh    OpenSSH 3.1p1 (protocol 1.99)
# 5002/tcp open  ssl/domain ISC BIND 9.2.1
# 5003/tcp open  ssl/finger Linux fingerd
# 6000/tcp open  X11        (access denied)
# 8000/tcp open  http-proxy Junkbuster webproxy
# 8080/tcp open  http       Apache httpd 2.0.39 ((Unix) mod_perl/1.99_04-dev)
# 8081/tcp open  http       Apache httpd 2.0.39 ((Unix) mod_perl/1.99_04-dev)
# Device type: general purpose
# Running: Linux 2.4.X|2.5.X
# OS details: Linux Kernel 2.4.0 - 2.5.20
#
# Nmap finished: 1 IP address (1 host up) scanned in 42.494 seconds

############################################################################
# More examples below...
# from: http://www.cyberciti.biz/tips/linux-scanning-network-for-open-ports.html
############################################################################

##
# TCP Connect scanning for localhost and network 192.168.0.0/24
##
nmap -v -sT localhost
nmap -v -sT 192.168.0.0/24

##
# nmap TCP SYN (half-open) scanning
##
nmap -v -sS localhost
nmap -v -sS 192.168.0.0/24

##
# nmap TCP FIN scanning
##
nmap -v -sF localhost
nmap -v -sF 192.168.0.0/24

##
# nmap TCP Xmas tree scanning
# Useful to see if firewall protecting against this kind of attack or not:
##
nmap -v -sX localhost
nmap -v -sX 192.168.0.0/24

##
# nmap TCP Null scanning
# Useful to see if firewall protecting against this kind attack or not:
##
nmap -v -sN localhost
nmap -v -sN 192.168.0.0/24

##
# nmap TCP Windows scanning
##
nmap -v -sW localhost
nmap -v -sW 192.168.0.0/24

##
# nmap TCP RPC scanning
# Useful to find out RPC (such as portmap) services
##
nmap -v -sR localhost
nmap -v -sR 192.168.0.0/24

##
# nmap UDP scanning
# Useful to find out UDP ports
##
nmap -v -O localhost
nmap -v -O 192.168.0.0/24

##
# nmap remote software version scanning
# You can also find out what software version opening the port.
##
nmap -v -sV localhost
nmap -v -sV 192.168.0.0/24