PS C:\Users\xxx> docker run --privileged --rm -v D:/Documents/qbit-config:/config -v I:/torrents:/downloads -e LAN_NETWORK=192.168.1.0/24 markusmcnugen/qbittorrentvpn
2020-03-28 16:58:45.605703 [warn] VPN_ENABLED not defined,(via -e VPN_ENABLED), defaulting to 'yes'
2020-03-28 16:58:45.655728 [info] OpenVPN config file (ovpn extension) is located at /config/openvpn/mullvad_us_nyc.ovpndos2unix: converting file /config/openvpn/mullvad_us_nyc.ovpn to Unix format...
2020-03-28 16:58:45.686175 [info] VPN remote line defined as 'us-nyc-014.mullvad.net 1194'
2020-03-28 16:58:45.705489 [info] VPN_REMOTE defined as 'us-nyc-014.mullvad.net'
2020-03-28 16:58:45.725024 [info] VPN_PORT defined as '1194'
2020-03-28 16:58:45.746964 [info] VPN_PROTOCOL defined as 'udp'
2020-03-28 16:58:45.768951 [info] VPN_DEVICE_TYPE defined as 'tun0'
2020-03-28 16:58:45.791954 [info] LAN_NETWORK defined as '192.168.1.0/24'
2020-03-28 16:58:45.813659 [warn] NAME_SERVERS not defined (via -e NAME_SERVERS), defaulting to Google and FreeDNS name servers
2020-03-28 16:58:45.835480 [info] VPN_OPTIONS not defined (via -e VPN_OPTIONS)
2020-03-28 16:58:45.858304 [info] Adding 8.8.8.8 to resolv.conf
2020-03-28 16:58:45.880144 [info] Adding 37.235.1.174 to resolv.conf
2020-03-28 16:58:45.900605 [info] Adding 8.8.4.4 to resolv.conf
2020-03-28 16:58:45.921763 [info] Adding 37.235.1.177 to resolv.conf
2020-03-28 16:58:45.941887 [info] PUID not defined. Defaulting to root user
2020-03-28 16:58:45.959957 [info] PGID not defined. Defaulting to root group
2020-03-28 16:58:45.978400 [info] Starting OpenVPN...
Sat Mar 28 16:58:45 2020 Note: option tun-ipv6 is ignored because modern operating systems do not need special IPv6 tun handling anymore.
Sat Mar 28 16:58:45 2020 WARNING: file 'mullvad_userpass.txt' is group or others accessible
Sat Mar 28 16:58:45 2020 OpenVPN 2.4.4 x86_64-pc-linux-gnu [SSL (OpenSSL)] [LZO] [LZ4] [EPOLL] [PKCS11] [MH/PKTINFO] [AEAD] built on May 14 2019
Sat Mar 28 16:58:45 2020 library versions: OpenSSL 1.1.1  11 Sep 2018, LZO 2.08
Sat Mar 28 16:58:45 2020 NOTE: the current --script-security setting may allow this configuration to call user-defined scripts
Sat Mar 28 16:58:46 2020 TCP/UDP: Preserving recently used remote address: [AF_INET]176.113.72.226:1194
Sat Mar 28 16:58:46 2020 Socket Buffers: R=[212992->425984] S=[212992->425984]
Sat Mar 28 16:58:46 2020 UDP link local: (not bound)
Sat Mar 28 16:58:46 2020 UDP link remote: [AF_INET]176.113.72.226:1194
Sat Mar 28 16:58:46 2020 TLS: Initial packet from [AF_INET]176.113.72.226:1194, sid=474ee4e9 c1a3b491
Sat Mar 28 16:58:46 2020 WARNING: this configuration may cache passwords in memory -- use the auth-nocache option to prevent this
Sat Mar 28 16:58:46 2020 VERIFY OK: depth=2, C=SE, ST=Gotaland, L=Gothenburg, O=Amagicom AB, OU=Mullvad, CN=Mullvad Root CA v2, emailAddress=security@mullvad.net
Sat Mar 28 16:58:46 2020 VERIFY OK: depth=1, C=SE, ST=Gotaland, O=Amagicom AB, OU=Mullvad, CN=Mullvad Intermediate CA v2, emailAddress=security@mullvad.net
Sat Mar 28 16:58:46 2020 VERIFY KU OK
Sat Mar 28 16:58:46 2020 Validating certificate extended key usage
Sat Mar 28 16:58:46 2020 ++ Certificate has EKU (str) TLS Web Server Authentication, expects TLS Web Server Authentication
Sat Mar 28 16:58:46 2020 VERIFY EKU OK
Sat Mar 28 16:58:46 2020 VERIFY OK: depth=0, C=SE, ST=Gotaland, O=Amagicom AB, OU=Mullvad, CN=us-nyc-018.mullvad.net, emailAddress=security@mullvad.net
Sat Mar 28 16:58:46 2020 WARNING: 'link-mtu' is used inconsistently, local='link-mtu 1557', remote='link-mtu 1558'
Sat Mar 28 16:58:46 2020 WARNING: 'comp-lzo' is present in remote config but missing in local config, remote='comp-lzo'
Sat Mar 28 16:58:46 2020 Control Channel: TLSv1.2, cipher TLSv1.2 DHE-RSA-AES256-GCM-SHA384, 4096 bit RSA
Sat Mar 28 16:58:46 2020 [us-nyc-018.mullvad.net] Peer Connection Initiated with [AF_INET]176.113.72.226:1194
Sat Mar 28 16:58:47 2020 SENT CONTROL [us-nyc-018.mullvad.net]: 'PUSH_REQUEST' (status=1)
Sat Mar 28 16:58:47 2020 PUSH: Received control message: 'PUSH_REPLY,dhcp-option DNS 10.8.0.1,redirect-gateway def1 bypass-dhcp,route-ipv6 0000::/2,route-ipv6 4000::/2,route-ipv6 8000::/2,route-ipv6 C000::/2,comp-lzo no,route-gateway 10.8.0.1,topology subnet,socket-flags TCP_NODELAY,ifconfig-ipv6 fdda:d0d0:cafe:1194::1007/64 fdda:d0d0:cafe:1194::,ifconfig 10.8.0.9 255.255.0.0,peer-id 5,cipher AES-256-GCM'
Sat Mar 28 16:58:47 2020 OPTIONS IMPORT: compression parms modified
Sat Mar 28 16:58:47 2020 OPTIONS IMPORT: --socket-flags option modified
Sat Mar 28 16:58:47 2020 NOTE: setsockopt TCP_NODELAY=1 failed
Sat Mar 28 16:58:47 2020 OPTIONS IMPORT: --ifconfig/up options modified
Sat Mar 28 16:58:47 2020 OPTIONS IMPORT: route options modified
Sat Mar 28 16:58:47 2020 OPTIONS IMPORT: route-related options modified
Sat Mar 28 16:58:47 2020 OPTIONS IMPORT: --ip-win32 and/or --dhcp-option options modified
Sat Mar 28 16:58:47 2020 OPTIONS IMPORT: peer-id set
Sat Mar 28 16:58:47 2020 OPTIONS IMPORT: adjusting link_mtu to 1624
Sat Mar 28 16:58:47 2020 OPTIONS IMPORT: data channel crypto options modified
Sat Mar 28 16:58:47 2020 Data Channel: using negotiated cipher 'AES-256-GCM'
Sat Mar 28 16:58:47 2020 Outgoing Data Channel: Cipher 'AES-256-GCM' initialized with 256 bit key
Sat Mar 28 16:58:47 2020 Incoming Data Channel: Cipher 'AES-256-GCM' initialized with 256 bit key
Sat Mar 28 16:58:47 2020 ROUTE_GATEWAY 172.17.0.1/255.255.0.0 IFACE=eth0 HWADDR=02:42:ac:11:00:02
Sat Mar 28 16:58:47 2020 GDG6: remote_host_ipv6=n/a
Sat Mar 28 16:58:47 2020 ROUTE6: default_gateway=UNDEF
Sat Mar 28 16:58:47 2020 TUN/TAP device tun0 opened
Sat Mar 28 16:58:47 2020 TUN/TAP TX queue length set to 100
Sat Mar 28 16:58:47 2020 do_ifconfig, tt->did_ifconfig_ipv6_setup=1
Sat Mar 28 16:58:47 2020 /sbin/ip link set dev tun0 up mtu 1500
Sat Mar 28 16:58:47 2020 /sbin/ip addr add dev tun0 10.8.0.9/16 broadcast 10.8.255.255
Sat Mar 28 16:58:47 2020 /sbin/ip -6 addr add fdda:d0d0:cafe:1194::1007/64 dev tun0
Sat Mar 28 16:58:47 2020 Linux ip -6 addr add failed: external program exited with error status: 2
Sat Mar 28 16:58:47 2020 Exiting due to fatal error
RTNETLINK answers: Permission denied