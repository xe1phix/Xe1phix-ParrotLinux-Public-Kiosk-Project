# Cobalt Strike

## 01 - Setup

### 1.1 - Redirectors

TODO: Fill this information

#### 1.1.1 - Apache2

`$ sudo a2enmod rewrite`

`$ cat /etc/apache2/sites-available/redirect.conf`

- For Debian/Ubuntu

`/etc/apache2/apache2.conf` or `/etc/apache2/sites-available/000-default.conf`

- For CentOS/RHEL

`/etc/httpd/conf/httpd.conf` or `/etc/httpd/conf.d/proxy.conf`

```
<VirtualHost *:80>
    # ServerName example.com  # Replace with your domain or IP address
	ServerName <C2_IP>
    ServerAlias <C2_IP>

    ProxyPass / http://<C2_IP>:<C2_PORT>/
    ProxyPassReverse / http://<C2_IP>:<C2_PORT>/
</VirtualHost>
```

```
$ sudo a2enmod proxy && \
sudo a2enmod proxy_http && \
sudo systemctl restart apache2
```

`$ sudo a2ensite redirect`

`$ sudo ln -s /etc/apache2/sites-available/cobalt_strike.conf /etc/apache2/sites-enabled/`

`$ sudo service apache2 restart`

```
sudo yum install mod_proxy mod_proxy_http && \
sudo systemctl restart httpd
```

#### 1.1.2 - Nginx

`$ cat /etc/nginx/sites-available/default`

---

```
server {
    listen 80;
    # server_name redirector-domain.com;  # Replace with your redirector domain
    server_name _;

	# Cobalt Strike IP and Port
    set $cobalt_strike_ip "<C2_IP>";
    set $cobalt_strike_port "<C2_PORT>";

    location / {
        proxy_pass http://$cobalt_strike_ip:$cobalt_strike_port;  # Replace with your Cobalt Strike team server IP and port
        # proxy_set_header Host $host;
        # proxy_set_header X-Real-IP $remote_addr;
    }
}
```

- For HTTPS listener

`$ sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout /etc/nginx/ssl/cobaltstrike.key -out /etc/nginx/ssl/cobaltstrike.crt`

```
server {
    listen 443 ssl;
    # server_name redirector.domain.com;
    server_name _;

	# Cobalt Strike IP and Port
    set $cobalt_strike_ip "<C2_IP>";
    set $cobalt_strike_port "<C2_PORT>";

    ssl_certificate /etc/nginx/ssl/cobaltstrike.crt;
    ssl_certificate_key /etc/nginx/ssl/cobaltstrike.key;

    location / {
        proxy_pass https://$cobalt_strike_ip:$cobalt_strike_port;
        # proxy_set_header Host $host;
        # proxy_set_header X-Real-IP $remote_addr;
    }
}
```

`$ sudo ln -s /etc/nginx/sites-available/cobaltstrike_redirect /etc/nginx/sites-enabled/`

`$ sudo nginx -t`

`$ sudo service nginx restart`

## 02 - Detection

### 2.1 - Shodan

`product:"Cobalt Strike Beacon"`

### 2.2 - JARM

`$ git clone https://github.com/salesforce/jarm.git`

`$ cd jarm/`

`$ python jarm.py <C2_IP> -p 80`

`$ python jarm.py <C2_IP> -p 443`

## References

- [HelpSystems User Guide](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/welcome_main.htm)

- [A Red Teamer Plays with JARM](https://www.cobaltstrike.com/blog/a-red-teamer-plays-with-jarm/)

- [Cobalt Strike Malleable C2 Profile](https://unit42.paloaltonetworks.com/cobalt-strike-malleable-c2-profile/)

- [Help Malleable C2](https://download.cobaltstrike.com/help-malleable-c2)

- [Red Team Cobalt Strike 4.0 Malleable C2 Profile Guideline](https://infosecwriteups.com/red-team-cobalt-strike-4-0-malleable-c2-profile-guideline-eb3eeb219a7c)

- [High Reputation Redirectors and Domain Fronting](https://www.cobaltstrike.com/blog/high-reputation-redirectors-and-domain-fronting/)

- [HTTPS Payload and C2 Redirectors](https://bluescreenofjeff.com/2018-04-12-https-payload-and-c2-redirectors/)

- [Red Team Insights on HTTPS Domain Fronting Google Hosts Using Cobalt Strike](https://www.cyberark.com/resources/threat-research-blog/red-team-insights-on-https-domain-fronting-google-hosts-using-cobalt-strike)

- [Hunting C2 with Shodan](https://michaelkoczwara.medium.com/hunting-c2-with-shodan-223ca250d06f)

- [JARM](https://github.com/salesforce/jarm)

- [C2 JARM](https://github.com/cedowens/C2-JARM)

- [C2 Tracker](https://github.com/montysecurity/C2-Tracker)

- [Spoofing JARM Signatures I Am The Cobalt Strike Server Now](https://grimminck.medium.com/spoofing-jarm-signatures-i-am-the-cobalt-strike-server-now-a27bd549fc6b)

- [JARM Randomizer Evading JARM Fingerprinting Dagmawi Mulugeta Presentation PDF File](https://conference.hitb.org/hitbsecconf2021ams/materials/D2%20COMMSEC%20-%20JARM%20Randomizer%20Evading%20JARM%20Fingerprinting%20-%20Dagmawi%20Mulugeta.pdf)

- [JARM Randomizer](https://github.com/netskopeoss/jarm_randomizer)