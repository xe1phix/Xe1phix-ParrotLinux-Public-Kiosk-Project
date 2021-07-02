
Altispeed-WireGuard-Setup.sh

## Step 2: Generate Certificates
## Generate a public and private certificate on the server

umask 077
wg genkey | tee server_private_key | wg pubkey > server_public_key


## Step 3: Create Server Config
## Create the server configuration file (/etc/wireguard/wg0.conf) using the template provided here.

[Interface]
Address = 10.100.100.1/24
SaveConfig = true
PrivateKey = 
ListenPort = 51820
PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -A FORWARD -o %i -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE

PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -D FORWARD -o %i -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE

[Peer]
PublicKey = 
AllowedIPs = 10.100.100.2/32


## Step 4: Enable IPv4 Forwarding
## Enable IPv4 forwarding so that we can access the rest of the LAN and not just the server itself.
## Open /etc/sysctl.conf and comment out the following line

net.ipv4.ip_forward=1

## Step 5: Restart the server, or use the following commands for the IP forwarding to take effect without restarting the server


sysctl -p
echo 1 > /proc/sys/net/ipv4/ip_forward

## Step 5: Start WireGuard
## Start WireGuard on the Server and enable WireGuard to start automatically when the server starts.

chown -v root:root /etc/wireguard/wg0.conf
chmod -v 600 /etc/wireguard/wg0.conf
wg-quick up wg0
systemctl enable wg-quick@wg0.service 

## Step 6: Install WireGuard on Client
## Add the WireGuard repository and install the software on the client.

sudo add-apt-repository ppa:wireguard/wireguard
sudo apt-get update
sudo apt-get install wireguard-dkms wireguard-tools linux-headers-$(uname -r)


## Step 7: Generate Certificates
## Generate a public and private certificate on the client

wg genkey | tee client_private_key | wg pubkey > client_public_key


## Step 8: Create client Config
## Create the client configuration file (/etc/wireguard/wg0-client.conf) using the template provided here.

[Interface]
Address = 10.100.100.2/32
PrivateKey =

[Peer]
PublicKey =
Endpoint = :51820
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 21


## Step 9: Start the WireGuard Client

sudo wg-quick up wg0-client