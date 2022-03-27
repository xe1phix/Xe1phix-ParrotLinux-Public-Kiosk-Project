curl --resolve 127.0.0.1:4444:http://killyourtv.i2p/killyourtv.asc
curl --proxy http://
curl --proxy socks4a://
curl --proxy --socks4a
curl --proxy socks5://
curl --socks5 HOST[:PORT]
curl --socks5 127.0.0.1:9150
curl --http-proxy=socks4a://127.0.0.1:59050
curl --socks5 127.0.0.1:9150


curl --socks5 127.0.0.1:9050 http://stackoverflow.com/




curl -fsSI --socks5 127.0.0.1:9050 ${webhost}						    ## Fetch via SOCKS proxy w/ local DNS as anon

curl -fsSI --socks5-hostname 127.0.0.1:9050 ${webhost}      		    ## Fetch via SOCKS proxy as anon

curl -fsSI --socks5-hostname 127.0.0.1:9050 ${webhost}                                  ## Fetch via SOCKS proxy as root

curl -fsSI -x 127.0.0.1:8118 ${webhost}                                 ## Fetch via HTTP proxy as anon

curl -fsSI -x 127.0.0.1:8118 ${webhost}       

curl -v --socks5-hostname localhost:9050 http://jhiwjjlqpyawmpjx.onion



curl ifconfig.co --socks5-host 10.64.0.1
curl ifconfig.co --socks5-host nl1-wg.socks5.mullvad.net

curl -sSL https://api.mullvad.net/wg/ -d account="$ACCOUNT" --data-urlencode pubkey="$(wg pubkey <<<"$PRIVATE_KEY")")" || die "Could not talk to Mullvad API."

curl -LsS https://api.mullvad.net/public/relays/wireguard/v1/

curl -LsS https://api.mullvad.net/public/relays/wireguard/v1/ | jq -r ".countries[] | (.code + \" - \" + .name + \" \" + ( .cities[] | (.name + \";\" + (.relays[].hostname / \"-\")[0] + \"-wg.socks5.mullvad.net\" ) )  ) + \":1080\" " | awk '{split($0,a,";"); print a[2] " [SOCKS5] "  "["a[1]"]"}' | sed s/","/" -"/g

wg.socks5.mullvad.net

PostUp = systemd-resolve -i %i --set-dns=193.138.219.228 --set-domain=~.
systemd-resolve -i %i --set-dns=$DNS --set-domain=


printf "%s\n" "Requested wg info:"
ip route show table all; ip addr show; ip rule show; iptables-save; ip netconf; wg;
printf "\n\n%s\n" "Get google in default interface:"
curl -sSm 10 172.217.2.46
printf "\n%s\n" "Get google in wg interface:"
curl -sSm 10 --interface wg0 172.217.2.46
printf "\n%s\n" "am.i.mullvad.net in default interface:"
curl -sSm 10 https://am.i.mullvad.net
printf "\n%s\n" "am.i.mullvad.net in wg interface:"
curl -sSm 10 --interface wg0 https://am.i.mullvad.net



echo "starting socks5 proxy at localhost:22222"
        
ssh -A -ND localhost:22222 metrics@bastion.prodnext.ottoq.com -v &    

curl -s --socks5 localhost:22222 binfalse.de


##  ssh ssh2socks5 socks5 tunnel proxy 
ssh -gN -D 6032 root@HOST
curl --socks5-hostname H:P DistinHost


alias amimullvad="curl https://am.i.mullvad.net/json | jq"



Mullvad’s DNS server IP: 193.138.218.74

OpenVPN: 10.8.0.1 (or any other address matching 10.x.0.1) and 10.64.0.1 for WireGuard servers.
10.8.0.1 (OpenVPN) or 10.64.0.1 (WireGuard), port 1080.

WireGuard protocol:

 --proxy-server=socks5://10.64.0.1

When using OpenVPN protocol:

 --proxy-server=socks5://10.8.0.1

## connect to a bridge
ssh -f -N -D 1234 mullvad@193.138.218.71


check_pub_ip=$(curl -s https://checkip.amazonaws.com)




https://mullvad.net/en/help/socks5-proxy/
https://mullvad.net/en/help/cli-command-wg/

./firetor.sh --caps.drop=all curl https://3g2upl4pq6kufc4m.onion/

Mullvad’s DNS server IP: 193.138.218.74

firejail --dns=193.138.218.74 curl 
