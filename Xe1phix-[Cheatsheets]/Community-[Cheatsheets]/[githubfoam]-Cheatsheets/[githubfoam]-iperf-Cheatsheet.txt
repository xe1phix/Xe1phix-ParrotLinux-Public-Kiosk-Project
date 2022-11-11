===================================================server======================================================
$ hostnamectl
   Static hostname: control-machine
         Icon name: computer-vm
           Chassis: vm
        Machine ID: 4f8ea72f17144f5a86367a4aeeb5c3e4
           Boot ID: b846f130028d48cb960e5498b75d11ef
    Virtualization: oracle
  Operating System: Ubuntu 18.04.1 LTS
            Kernel: Linux 4.15.0-29-generic
      Architecture: x86-64
vagrant@control-machine:~$ iperf --version
iperf version 2.0.10 (2 June 2018) pthreads

===================================================client======================================================
[vagrant@postgresql03 ~]$ hostnamectl
   Static hostname: postgresql03
         Icon name: computer-vm
           Chassis: vm
        Machine ID: 0fb1a22b768f453397e321fe9954a766
           Boot ID: 296ebda097f043bca71505e36301b7eb
    Virtualization: kvm
  Operating System: CentOS Linux 7 (Core)
       CPE OS Name: cpe:/o:centos:centos:7
            Kernel: Linux 3.10.0-693.21.1.el7.x86_64
      Architecture: x86-64
[vagrant@postgresql03 ~]$ iperf --version
iperf version 2.0.13 (21 Jan 2019) pthreads


[vagrant@postgresql03 ~]$ iperf -c 192.168.45.24


vagrant@control-machine:~$iperf -s
------------------------------------------------------------
Server listening on TCP port 5001
TCP window size: 85.3 KByte (default)
------------------------------------------------------------
[  4] local 192.168.45.24 port 5001 connected with 192.168.45.25 port 41388
[  4] local 192.168.45.24 port 5001 connected with 192.168.45.25 port 41388
[ ID] Interval       Transfer     Bandwidth
[  4]  0.0-10.0 sec  3.91 GBytes  3.35 Gbits/sec

[vagrant@postgresql03 ~]$ iperf -c control-machine
------------------------------------------------------------
Client connecting to control-machine, TCP port 5001
TCP window size:  833 KByte (default)
------------------------------------------------------------
[  3] local 192.168.45.25 port 41390 connected with 192.168.45.24 port 5001
[ ID] Interval       Transfer     Bandwidth
[  3]  0.0-10.0 sec  3.98 GBytes  3.42 Gbits/sec


vagrant@control-machine:~$ iperf -u -s
------------------------------------------------------------
Server listening on UDP port 5001
Receiving 1470 byte datagrams
UDP buffer size:  208 KByte (default)
------------------------------------------------------------
[  3] local 192.168.45.24 port 5001 connected with 192.168.45.25 port 33088
[ ID] Interval       Transfer     Bandwidth        Jitter   Lost/Total Datagrams
[  3]  0.0-10.0 sec  1.25 MBytes  1.05 Mbits/sec   0.027 ms 2147481864/2147482756 (1e+02%)


# iPerf limits the bandwidth for UDP clients to 1 Mbit per second by default
[vagrant@postgresql03 ~]$ iperf -u -c control-machine 1M
iperf: ignoring extra argument -- 1M
------------------------------------------------------------
Client connecting to control-machine, UDP port 5001
Sending 1470 byte datagrams, IPG target: 11215.21 us (kalman adjust)
UDP buffer size:  208 KByte (default)
------------------------------------------------------------
[  3] local 192.168.45.25 port 33088 connected with 192.168.45.24 port 5001
[ ID] Interval       Transfer     Bandwidth
[  3]  0.0-10.0 sec  1.25 MBytes  1.05 Mbits/sec
[  3] Sent 892 datagrams
[  3] Server Report:
[  3]  0.0-10.0 sec  1.25 MBytes  1.05 Mbits/sec   0.000 ms 2147481864/2147482756 (1e+02%)


# -b flag, replacing the number after with the maximum bandwidth
[vagrant@postgresql03 ~]$ iperf -c control-machine  -u -b 1000m
------------------------------------------------------------
Client connecting to control-machine, UDP port 5001
Sending 1470 byte datagrams, IPG target: 11.76 us (kalman adjust)
UDP buffer size:  208 KByte (default)
------------------------------------------------------------
[  3] local 192.168.45.25 port 42700 connected with 192.168.45.24 port 5001
[ ID] Interval       Transfer     Bandwidth
[  3]  0.0-10.0 sec   479 MBytes   401 Mbits/sec
[  3] Sent 341385 datagrams
[  3] Server Report:
[  3]  0.0-10.0 sec   477 MBytes   400 Mbits/sec   0.000 ms 2146801823/2147142263 (1e+02%)

# test both servers for the maximum amount of throughput.measure the bi-directional bandwidths simultaneousely
vagrant@control-machine:~$ iperf -s
------------------------------------------------------------
Server listening on TCP port 5001
TCP window size: 85.3 KByte (default)
------------------------------------------------------------
[  4] local 192.168.45.24 port 5001 connected with 192.168.45.25 port 41392
------------------------------------------------------------
Client connecting to 192.168.45.25, TCP port 5001
TCP window size: 85.0 KByte (default)
------------------------------------------------------------
[  6] local 192.168.45.24 port 35580 connected with 192.168.45.25 port 5001
[ ID] Interval       Transfer     Bandwidth
[  6]  0.0-10.0 sec  2.22 GBytes  1.90 Gbits/sec
[  4]  0.0-10.0 sec  1.47 GBytes  1.26 Gbits/sec

[vagrant@postgresql03 ~]$ iperf -c control-machine -d
------------------------------------------------------------
Server listening on TCP port 5001
TCP window size: -1.00 Byte (default)
------------------------------------------------------------
------------------------------------------------------------
Client connecting to control-machine, TCP port 5001
TCP window size:  969 KByte (default)
------------------------------------------------------------
[  3] local 192.168.45.25 port 41392 connected with 192.168.45.24 port 5001
[  5] local 192.168.45.25 port 5001 connected with 192.168.45.24 port 35580
[ ID] Interval       Transfer     Bandwidth
[  3]  0.0-10.0 sec  1.47 GBytes  1.26 Gbits/sec
[  5]  0.0-10.0 sec  2.22 GBytes  1.90 Gbits/sec


# Bi-directional bandwidth measurement: (-r argument).
# The Iperf server connects back to the client allowing the bi-directional bandwidth measurement. 
# By default, only the bandwidth from the client to the server is measured
vagrant@control-machine:~$ iperf -s
------------------------------------------------------------
Server listening on TCP port 5001
TCP window size: 85.3 KByte (default)
------------------------------------------------------------
[  4] local 192.168.45.24 port 5001 connected with 192.168.45.25 port 41394
[ ID] Interval       Transfer     Bandwidth
[  4]  0.0-10.0 sec  3.92 GBytes  3.36 Gbits/sec
------------------------------------------------------------
Client connecting to 192.168.45.25, TCP port 5001
TCP window size: 1.04 MByte (default)
------------------------------------------------------------
[  4] local 192.168.45.24 port 35582 connected with 192.168.45.25 port 5001
[  4]  0.0-10.0 sec  2.42 GBytes  2.08 Gbits/sec

[vagrant@postgresql03 ~]$ iperf -c control-machine -r
------------------------------------------------------------
Server listening on TCP port 5001
TCP window size: 85.3 KByte (default)
------------------------------------------------------------
------------------------------------------------------------
Client connecting to control-machine, TCP port 5001
TCP window size:  774 KByte (default)
------------------------------------------------------------
[  3] local 192.168.45.25 port 41394 connected with 192.168.45.24 port 5001
[ ID] Interval       Transfer     Bandwidth
[  3]  0.0-10.0 sec  3.92 GBytes  3.37 Gbits/sec
[  5] local 192.168.45.25 port 5001 connected with 192.168.45.24 port 35582
[  5]  0.0-10.0 sec  2.42 GBytes  2.08 Gbits/sec

# The TCP window size is the amount of data that can be buffered during a connection without a validation from the receiver
# between 2 and 65,535 bytes
# Linux systems, when specifying a TCP buffer size with the -w argument, the kernel allocates double  
iperf -s -w 4000 
iperf -c 10.1.1.1 -w 2000 

vagrant@control-machine:~$ iperf -s -P 2 -i 5 -p 5999 -f k
[vagrant@postgresql03 ~]$ iperf -c control-machine -P 1 -i 5 -p 5999 -f B -t 60 -T 1


iperf -s -p 12000
iperf -c 10.1.1.1 -p 12000 -t 20 -i 2 

iperf -s -u -i 1 
iperf -c 10.1.1.1 -u -b 10m 

# Maximum Segment Size (-m argument)
iperf -s 
iperf -c 10.1.1.1 -m 

iperf -s
iperf -c 10.1.1.1 -M 1300 -m 

iperf -s
iperf -c 10.1.1.1 -P 2 
------------------------------------------------------------
#Server
#in server mode using -s flag, it will listen on port 5201 by default
#specify the format (k, m, g for Kbits, Mbits, Gbits or K, M, G for KBytes, Mbytes, Gbytes)
#report using the -f switch
$ iperf3 -s -f K 
#If port 5201 is being used by another program on your server, you can specify a different port (e.g 3000) using the -p switch
$ iperf3 -s -p 3000
$ iperf3 -s -D > iperf3log #run the server as a daemon, using the -D flag and write server messages to a log file

#Client
#on your local machine (the client) where the actual benchmarking takes place
#run iperf3 in client mode using -c flag
#specify the host on which the server is running on (either using its IP address or domain or hostname)
$ iperf3 -c 192.168.10.1 -f K
#set the window size/socket buffer size using the -w flag
$ iperf3 -c 192.168.10.1 -f K -w 500K	
reverse mode where the server sends and the client receives, add the -R switch
$ iperf3 -c 192.168.10.1 -f K -w 500K -R
#bi-directional test, measure bandwidth in both directions simultaneously, use the -d option.
$ iperf3 -c 192.168.10.1 -f K -w 500K -d
#server results in the client output, use the --get-server-output option
$ iperf3 -c 192.168.10.1 -f K -w 500K -R --get-server-output
#set the number of parallel client streams (5 in this example), which run at the same time, using the -P options
$ iperf3 -c 192.168.10.1 -f K -w 500K -P 5
------------------------------------------------------------
