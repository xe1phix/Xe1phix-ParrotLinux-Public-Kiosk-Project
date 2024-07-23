# Mitmproxy
Steps to configure mitmproxy for ssl interception in malware analysis.

# Download and install
```sh
wget https://snapshots.mitmproxy.org/5.0.1/mitmproxy-5.0.1-linux.tar.gz --output-document=mitmproxy.tgz
sudo tar -xzvf mitmproxy.tgz -C /usr/local/bin/
```

# Configure
## Generate certs
```sh
mkdir -p /var/lib/mitmproxy/certs
cd /var/lib/mitmproxy/certs
openssl req -nodes -days 3650 -new -x509 -newkey rsa:2048 -keyout mitmproxy-ca-key.pem -out mitmproxy-ca-cert.pem -subj "/C=US/ST=California/L=Berkeley/O=DigiCert Inc/OU=DigiCert Inc Root CA/CN=www.digicert.com"
openssl pkcs12 -export -in mitmproxy-ca-cert.pem -inkey mitmproxy-ca-key.pem -name "Root Cert" -out mitmproxy-ca-cert.p12
cat mitmproxy-ca-cert.pem mitmproxy-ca-key.pem > mitmproxy-ca.pem
cp mitmproxy-ca-cert.pem mitmproxy-ca-cert.cer

```
## Mitmdump as service
My config:
- certs in __/var/lib/mitmproxy/certs__;
- autostart via systemctl as service;
- generate pre shared SSL key to shared directory __/mnt/public__;
- extra logging to __/var/log/mitm.log__

1. Create mitmproxy config
    ```yaml
    #cat /var/lib/mitmproxy/config.yaml
    # dir with certificates
    confdir: /var/lib/mitmproxy/certs
    # keep hostname to inetsim
    keep_host_header: true
    # listen connections on default HTTPS port
    listen_port: 443
    # NB! change <server> to your http server address
    mode: reverse:http://<server>:80
    # extra details (full header and content) in console log
    flow_detail: 3
    ```
1. Create systemctl config
    ```dosini
    #cat  /lib/systemd/system/mitmdump.service
    [Unit]
    Description=mitmdump service
    Requires=inetsim.service
    After=inetsim.service

    [Service]
    StandardOutput=syslog
    StardardError=syslog
    SyslogIdentifier=mitmdump
    Environment=MITMPROXY_SSLKEYLOGFILE=/mnt/public/ssl-keys.log
    Type=simple
    User=root
    ExecStart=/usr/local/bin/mitmdump --set confdir=/var/lib/mitmproxy
    Restart=always
    RestartSec=1

    [Install]
    WantedBy=multi-user.target
    ```

1. Create rsyslog config
    ```
    #cat /etc/rsyslog.d/mitmdump.conf
    if $programname == 'mitmdump' then /var/log/mitm.log
    & stop
    ```
1. Reload configuration and run
    ```sh
    systemctl daemon-reload
    systemctl enable mitmdump.service
    systemctl start mitmdump.service
    systemctl restart rsyslog
    ```

# Run
## run mitmdump onetime
```sh
MITMPROXY_SSLKEYLOGFILE="./ssl.log" mitmdump --listen-port 443 --set confdir=<certsdir> --set keep_host_header --mode reverse:http://<server>:80
```

## run as service
```sh
systemctl start mitmdump.service
```
