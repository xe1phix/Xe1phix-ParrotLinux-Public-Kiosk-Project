----------------------------------------------------------------------------------------------------
/etc/letsencrypt/live #find the generated certificate files
/etc/letsencrypt/live/$domain
https://www.ssllabs.com/ssltest #verify the status of your SSL certificate 
[LetsEncrypt]-[Certbot]

ls /etc/letsencrypt

$ sudo ls /var/log/letsencrypt/
curl -I https://acme-v02.api.letsencrypt.org
$ sudo tail -10  /var/log/letsencrypt/letsencrypt.log

sudo certbot renew --dry-run # Test "renew" or "certonly" without saving any certificates

#the "certbot.timer" utility for automatic certificate renewal
#It checks the validity of SSL certificates in the system twice a day and extends those that expire in the next 30 days
sudo systemctl status certbot.timer 

$ sudo ls  /etc/letsencrypt/renewal/
$ sudo cat  /etc/letsencrypt/renewal/example.com
sudo grep -r /etc/letsencrypt/ -e 'outdated.example.com'

/etc/cron.d/certbot #a renewal cron job was created automatically 

#Automatically Renew Let’s Encrypt Certificates
$ crontab -e
0 12 * * * /usr/bin/certbot renew --quiet #every day at noon

$ cat /etc/cron.daily/renewcerts
#!/bin/bash
certbot renew
$ chmod a+x /etc/cron.daily/renewcerts
$ run-parts --test -v /etc/cron.daily  # verify that the script would actually run, but don't run them

#Automatically Renew Let’s Encrypt Certificates
sudo crontab -e
@daily /usr/bin/certbot renew --quiet

#SSL installed to /etc/letsencrypt/live/ssl.itsyndicate.org
#Test SSL Configuration
curl -vI https://ssl.itsyndicate.org

certbot -d cyberciti.biz #force cert renewal even if it is not near its expiration date

sudo certbot renew #renew Let's Encrypt certificates,manually trigger the renewal
certbot certonly --force-renew -d example.com #If there are multiple certificates for different domains,renew a specific certificate
sudo certbot renew --dry-run #verify that the certificate renewed

 #keep the certificate but discontinue future renewals 
 #(for example ,switch to a different server, but wait for all the DNS changes to propagate)
 mv /etc/letsencrypt/renewal/example.com.conf  /etc/letsencrypt/renewal/example.com.conf.disabled
 sudo certbot renew --dry-run
 
 certbot delete #interactive menu
 #removes the certificate and all relevant files from your letsencrypt config directory
 certbot delete --cert-name example.com #delete a certificate non-interactively 

#remove a domain from certbot renewals
rm -rf /etc/letsencrypt/live/${BAD_DOMAIN}/
rm -f /etc/letsencrypt/renewal/${BAD_DOMAIN}.conf
certbot renew --dry-run
certbot renew

----------------------------------------------------------------------------------------------------
