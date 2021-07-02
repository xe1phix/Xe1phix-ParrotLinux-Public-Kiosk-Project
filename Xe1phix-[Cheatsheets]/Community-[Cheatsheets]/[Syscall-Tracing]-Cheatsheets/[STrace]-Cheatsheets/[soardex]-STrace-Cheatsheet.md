# attach to a current network
strace -p [pid] -f -e trace=network -s [strsize]

# or just trace connect calls
strace -p [pid] -f -e trace=network -s [strsize]

# or some chosen network calls
strace -p [pid] -f -e poll,select,connect,recvfrom,sendto -s [strsize]
