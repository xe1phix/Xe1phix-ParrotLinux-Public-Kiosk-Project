
### iperf:
-----------------------
By default iperf uses TCP/UDP port 5001 for sport and dport. If the -P flag is used to spawn multiple threads, the dport will be a series of ephermeral ports.

#### iperf2 vs iperf3
- iperf2 is good for testing mc traffic.
    * configure iperf server to listen on mc group address (causing it to send IGMP report). 
    * be sure to configure static route for the mc group on the client with next hop towards the network
- iperf3 is good for testing uc traffic (especially above 2Gbps). 

### iperf server side:
-----------------------
Start server on the default port

iperf/iperf3 -s

  
Start server with larger TCP window, and in daemon mode

iperf -s -w 32M -D / iperf3 -s -D

  
Start UDP server on port 5003, and give 1 sec interval reports

iperf -i1 -u -s -p 5003 / iperf3 -s -p 5003


### iperf client side:
-----------------------
Run a 30 second tests, giving results every 1 second

iperf/iperf3 -c remotehost -i 1 -t 30

  
Run a test from remotehost to localhost

iperf/iperf3 -c remotehost -i 1 -t 20 -r

  
Run a test with 4 parallel streams, and with a 32M TCP buffer

iperf/iperf3 -c remotehost -i 1 -t 20 -w 32M -P 4

  
Run a 200 Mbps UDP test

iperf/iperf3 -c remotehost -u -i 1 -b 200M  


Other client-side optimizations:
Run the test for 2 seconds before collecting results, to allow for TCP slowstart to finish. (Omit mode)

iperf3 -c remotehost -i.5 -0 2

  
Use the sendfile() system call for "Zero Copy" mode. This uses much less CPU.

iperf3 -Z -c remotehost

  
Run tests to multiple interfaces at once, and label the lines to indicate which test is which in the results output.

iperf3 -c 192.168.12.12 -T s1 & iperf3 -c 192.168.12.13 -T s2

  
Output the results in JSON format for easy parsing.

iperf3 -c remotehost -J

  
Set the CPU affinity for the sender,receiver (cores are numbered from 0). This has the same affect as doing 'numactl -C 4 iperf3'.

iperf3 -A 2,3 -c remotehost

    
NOTE: To get the best performance from the Server side, only use -A -OR- -P. Appears the server will balance threads across all available cores.

Run multiple iperf tests (as client) in a bash for loop
command below runs 500 tests that last 5 seconds long, iterating through different source ports (cport)

for i in {1..500} ; do iperf3 --bind <local-ip> -c <server-ip> -t 5 --cport 11$i ; egrep receiver >> test_result_reverse.log ; done 
