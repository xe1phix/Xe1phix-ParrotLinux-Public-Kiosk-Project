interface=eth0
dumpdir=/tmp/

while /bin/true; do
  pkt_old=`grep $interface: /proc/net/dev | cut -d :  -f2 | awk '{ print $2 }'`
  sleep 1
  pkt_new=`grep $interface: /proc/net/dev | cut -d :  -f2 | awk '{ print $2 }'`

  pkt=$(( $pkt_new - $pkt_old ))
  echo -ne "\r$pkt packets/s\033[0K"

  if [ $pkt -gt 5000 ]; then
    echo "\nOMFG, DoS detected!!!!!@#$%^&* no1curr."
    tcpdump -n -s0 -c 5000 -w $dumpdir/dump.`date +"%Y%m%d-%H%M%S"`.cap
    echo "Going to sleep for 5 minutes."
    sleep 300
  fi
done