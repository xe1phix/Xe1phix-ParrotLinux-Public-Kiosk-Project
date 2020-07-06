

socat -hh |grep ' b[1-9]'

socat - TCP4:www.domain.org:80

socat -d -d  READLINE,history=$HOME/.http_history \</strong><br>

socat -d -d -lmlocal2 \</strong><br>

socat -,escape=0x0f /dev/ttyS0,rawer,crnl

socat -u /tmp/readdata,seek-end=0,ignoreeof -

socat - EXEC:'ssh -l user server',pty,setsid,ctty

socat -u TCP4-LISTEN:3334,reuseaddr,fork

ssh modemserver.us.org 
socat - /dev/ttyS0,nonblock,rawer

socat - SSL:server:4443,cafile=server.crt,cert=client.pem

echo |socat -u - file:/tmp/bigfile,create,largefile,seek=100000000000

echo -e "\0\14\0\0\c" |socat -u - file:/usr/bin/squid.exe,seek=0x00074420

socat - tcp:www.blackhat.org:31337,readbytes=1000

socat -U TCP:target:9999,end-close TCP-L:8888,reuseaddr,fork

socat - UDP4-DATAGRAM:192.168.1.0:123,sp=123,broadcast,range=192.168.1.0/24

socat - SOCKET-DATAGRAM:2:2:17:x007bxc0a80100x0000000000000000,bind=x007bx00000000x0000000000000000,setsockopt-int=1:6:1,range=x0000xc0a80100x0000000000000000:x0000xffffff00x0000000000000000

socat - IP4-DATAGRAM:255.255.255.255:44,broadcast,range=10.0.0.0/8

socat - UDP4-DATAGRAM:224.255.0.1:6666,bind=:6666,ip-add-membership=224.255.0.1:eth0

socat -T 1 -d -d TCP-L:10081,reuseaddr,fork,crlf SYSTEM:"echo -e \"\\\"HTTP/1.0 200 OK\\\nDocumentType: text/plain\\\n\\\ndate: \$\(date\)\\\nserver:\$SOCAT_SOCKADDR:\$SOCAT_SOCKPORT\\\nclient: \$SOCAT_PEERADDR:\$SOCAT_PEERPORT\\\n\\\"\"; cat; echo -e \"\\\"\\\n\\\"\""

socat -d -d UDP4-RECVFROM:9999,so-broadcast,so-timestamp,ip-pktinfo,ip-recverr,ip-recvopts,ip-recvtos,ip-recvttl!!- SYSTEM:'export; sleep 1' |grep SOCAT

socat -d readline"$HISTOPT",noecho='[Pp]assword:' exec:"$PROGRAM",sigint,pty,setsid,ctty,raw,echo=0,stderr 2>/tmp/$USER/stderr2

socat -V |grep SSL

socat -u UDP-RECVFROM:8888,reuseaddr,ip-add-membership=224.1.0.1:192.168.10.2,ip-pktinfo,fork SYSTEM:export

echo |socat -u STDIO UDP-DATAGRAM:224.1.0.1:8888

echo ABCD |socat - TCP4-CONNECT:localhost:4096,type=6,prototype=33

echo ABCD |socat - SOCKET-DATAGRAM:5:2:0:x40x00xff00xf3x00x0000000000000000 


socat -V        ## see what features are still enabled 

## socat-tun0
socat -d -d TCP-LISTEN:11443,reuseaddr TUN:192.168.255.1/24,up

tee TestInput < /dev/urandom | socat - TCP4:x.x.x.x:1234 > ProcessedBlocks

cat tmp.14 | socat - TCP:192.168.122.50:22

cat $3 | socat -t 0 - TCP:$1:$2

socat - OPENSSL:localhost:8443,cafile=test/certs/sslcaudit-test-cacert.pem"

client-cert-verify--server.sh

socat -v OPENSSL-LISTEN:18443,reuseaddr,fork,cert=test/certs/www.example.com-cert.pem,key=test/certs/www.example.com-key.pem,cafile=test/certs/test-ca-cacert.pem,verify=1 -

client-cert-verify--client.sh

socat -v - OPENSSL:localhost:18443,cert=test/certs/test-client-cert.pem,key=test/certs/test-client-key.pem,cafile=test/certs/test-ca-cacert.pem
