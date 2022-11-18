

softflowd -i fxp0

This command-line will cause softflowd to listen on interface fxp0 and to run in statistics gathering mode only (i.e. no NetFlow data export).

softflowd -i fxp0 -n 10.1.0.2:4432

This command-line will cause softflowd to listen on interface fxp0 and to export NetFlow v.5 datagrams on flow expiry to a flow collector running on 10.1.0.2 port 4432.

softflowd -i fxp0 -n 10.1.0.2:4432,10.1.0.3:4432

This command-line will cause softflowd to listen on interface fxp0 and to export NetFlow v.5 datagrams on flow expiry to a flow collector running on 10.1.0.2 port 4432 and 10.1.0.3 port 4432.

softflowd -i fxp0 -l -n 10.1.0.2:4432,10.1.0.3:4432

This command-line will cause softflowd to listen on interface fxp0 and to export NetFlow v.5 datagrams on flow expiry to a flow collector running on 10.1.0.2 port 4432 and 10.1.0.3 port 4432 with load balncing mode. Odd netflow packets will be sent to 10.1.0.2 port 4432 and even netflow packets will be sent to 10.1.0.3 port 4432.

softflowd -v 5 -i fxp0 -n 10.1.0.2:4432 -m 65536 -t udp=1m30s

This command-line increases the number of concurrent flows that softflowd will track to 65536 and increases the timeout for UDP flows to 90 seconds.

softflowd -v 9 -i fxp0 -n 224.0.1.20:4432 -L 64

This command-line will export NetFlow v.9 flows to the multicast group 224.0.1.20. The export datagrams will have their TTL set to 64, so multicast receivers can be many hops away.

softflowd -i fxp0 -p /var/run/sfd.pid.fxp0 -c /var/run/sfd.ctl.fxp0

This command-line specifies alternate locations for the control socket and pid file. Similar command-lines are useful when running multiple instances of softflowd on a single machine.