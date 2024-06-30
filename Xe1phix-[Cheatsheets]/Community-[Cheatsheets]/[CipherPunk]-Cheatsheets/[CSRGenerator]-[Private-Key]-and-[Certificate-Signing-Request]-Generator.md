Generating a Cert on cli

The easiest way is to use the CSRGenerator shell script:

CSRGenerator-Private-Key-and-Certificate-Signing-Request-Generator

Save it locally and then run it, be sure to repeat the commonname as a subjectaltname, the short host name is just used for the file name.

This is an example of how it works:

[example@example ~]$ sh csr
Private Key and Certificate Signing Request Generator
This script was designed to suit the request format needed by
the CAcert Certificate Authority. www.CAcert.org
Short Hostname (ie. imap big_srv www2): example
FQDN/CommonName (ie. www.example.com) : example.org
Type SubjectAltNames for the certificate, one per line. Enter a blank line to finish
SubjectAltName: DNS:example.org
SubjectAltName: DNS:www.example.org
SubjectAltName: DNS:foo.example.org
SubjectAltName: DNS:www.foo.example.org
SubjectAltName: DNS:bar.example.org
SubjectAltName: DNS:www.bar.example.org
SubjectAltName: DNS:example.bar
SubjectAltName: DNS:www.example.bar
SubjectAltName: DNS:
Running OpenSSL...
Generating a 2048 bit RSA private key
........................................................+++
................................................+++
writing new private key to '/home/example/example_privatekey.pem'
-----
Copy the following Certificate Request and paste into CAcert website to obtain a Certificate.
When you receive your certificate, you 'should' name it something like example_server.pem
-----BEGIN CERTIFICATE REQUEST-----
MIIDBjCCAe4CAQAwFjEUMBIGA1UEAxMLZXhhbXBsZS5vcmcwggEiMA0GCSqGSIb3
DQEBAQUAA4IBDwAwggEKAoIBAQClsXcoj86dyYlIe96khbZqYtyV03ak+teyClv5
80I46irKcYQx4CFiirTCuusiAwsDfnDyZvnrwoxaUkc5nkw4Tlmb1j/y91U8rusX
Zu43rep8s0zs7aMx/q34TTCc5Mru8UQjbnj9aCX1DF+8cA0ayQMm1BOFv8nTFcjK
SnI5NdxRKDyqeH3KUgfxgGkBVU4VFVRU9XKD/zprzj+hWFT+fsjF7yQm0ZXDXaJ+
0Yr9mDQjfzdLP3GObc7y7rwz8a5ozATwfpqZiWYjM34oKFPSj7kwLdA+otx0glGG
e+P7G/E2uE+lbzi41CSFgKAjw3E0l1x47NoVD6DADS5mYIatAgMBAAGggaowgacG
CSqGSIb3DQEJDjGBmTCBljCBkwYDVR0RBIGLMIGIggtleGFtcGxlLm9yZ4IPd3d3
LmV4YW1wbGUub3Jngg9mb28uZXhhbXBsZS5vcmeCE3d3dy5mb28uZXhhbXBsZS5v
cmeCD2Jhci5leGFtcGxlLm9yZ4ITd3d3LmJhci5leGFtcGxlLm9yZ4ILZXhhbXBs
ZS5iYXKCD3d3dy5leGFtcGxlLmJhcjANBgkqhkiG9w0BAQQFAAOCAQEAHFiUDgVc
lDGoq+2kLmQxKtYagc37sugw4OoutILxrXF0zJUSplF4Aco/KhBcSLQUpsW5u11Q
tcxj4DqXrxsoZuawATKTGQXDaAxL/ud2FsXyhe2FC1h0id2cH12GsnDSziuFCM+t
rz05dqnW6mZR5OHILlYPoIPNqk3tbkIyOs4GplL9PZLNjSKJ3oeXJXn1iSI6oegB
dBJQMByDZsh7Xd/d1OFJMQq3TFMqmLEXErkXQnOmzBN375AHGYGZwozhVPjhfFZ1
74AvmxOe17+OLm1j10EA9J/5jLzIgK0vs7HgK0131S/JAV4Ik9JccAWByGlxeuVb
4Kf5vAucZZVe7g==
-----END CERTIFICATE REQUEST-----
The Certificate request is also available in /home/example/example_csr.pem
The Private Key is stored in /home/example/example_privatekey.pem

Then paste your certificate into the cacert.org site (get a class 1 cert for the example configuration below) and you will get a server certificate back, save this as example_server.pem.

Example Configuration

You can specify and IP address or use a wild card but you can't mix them. It is possible that you have to add "Listen 192.168.0.1:443" to Apache configuration.

NameVirtualHost 192.168.0.1:443
# or
# NameVirtualHost *:443
# foo.example.org:443
<VirtualHost 192.168.0.1:443>
# or
# <VirtualHost *:443>
  ServerName foo.example.org:443
  UseCanonicalName On
  SSLEngine on
  SSLCertificateFile /etc/apache/example_server.pem
  SSLCertificateKeyFile /etc/apache/example_privatekey.pem
  SSLCipherSuite HIGH
  SSLProtocol all -SSLv2
  DocumentRoot "/var/www/foo.example.org"
  <Directory "/var/www/foo.example.org">
    Options Indexes
    AllowOverride None
    Order allow,deny
    Allow from all
  </Directory>
</VirtualHost>
# www.foo.example.org:443
<VirtualHost 192.168.0.1:443>
# or
# <VirtualHost *:443>
  ServerName www.foo.example.org:443
  UseCanonicalName On
  SSLEngine on
  SSLCertificateFile /etc/apache/example_server.pem
  SSLCertificateKeyFile /etc/apache/example_privatekey.pem
  SSLCipherSuite HIGH
  SSLProtocol all -SSLv2
  Redirect / https://foo.example.org/
</VirtualHost>
# example.foo:443
<VirtualHost 192.168.0.1:443>
# or
# <VirtualHost *:443>
  ServerName example.foo:443
  UseCanonicalName On
  SSLEngine on
  SSLCertificateFile /etc/apache/example_server.pem
  SSLCertificateKeyFile /etc/apache/example_privatekey.pem
  SSLCipherSuite HIGH
  SSLProtocol all -SSLv2
  Redirect / https://foo.example.org/
</VirtualHost>
# www.example.foo:443
<VirtualHost 192.168.0.1:443>
# or
# <VirtualHost *:443>
  ServerName www.example.foo:443
  UseCanonicalName On
  SSLEngine on
  SSLCertificateFile /etc/apache/example_server.pem
  SSLCertificateKeyFile /etc/apache/example_privatekey.pem
  SSLCipherSuite HIGH
  SSLProtocol all -SSLv2
  Redirect / https://foo.example.org/
</VirtualHost>
# bar.example.org:443
<VirtualHost 192.168.0.1:443>
# or
# <VirtualHost *:443>
  ServerName bar.example.org:443
  UseCanonicalName On
  SSLEngine on
  SSLCertificateFile /etc/apache/example_server.pem
  SSLCertificateKeyFile /etc/apache/example_privatekey.pem
  SSLCipherSuite HIGH
  SSLProtocol all -SSLv2
  DocumentRoot "/var/www/bar.example.org"
  <Directory "/var/www/bar.example.org">
    Options Indexes
    AllowOverride None
    Order allow,deny
    Allow from all
  </Directory>
</VirtualHost>
# www.bar.example.org:443
<VirtualHost 192.168.0.1:443>
# or
# <VirtualHost *:443>
  ServerName www.bar.example.org:443
  UseCanonicalName On
  SSLEngine on
  SSLCertificateFile /etc/apache/example_server.pem
  SSLCertificateKeyFile /etc/apache/example_privatekey.pem
  SSLCipherSuite HIGH
  SSLProtocol all -SSLv2
  Redirect / https://bar.example.org/
</VirtualHost>
# example.bar:443
<VirtualHost 192.168.0.1:443>
# or
# <VirtualHost *:443>
  ServerName example.bar:443
  UseCanonicalName On
  SSLEngine on
  SSLCertificateFile /etc/apache/example_server.pem
  SSLCertificateKeyFile /etc/apache/example_privatekey.pem
  SSLCipherSuite HIGH
  SSLProtocol all -SSLv2
  Redirect / https://bar.example.org/
</VirtualHost>
# www.example.bar:443
<VirtualHost 192.168.0.1:443>
# or
# <VirtualHost *:443>
  ServerName www.example.bar:443
  UseCanonicalName On
  SSLEngine on
  SSLCertificateFile /etc/apache/example_server.pem
  SSLCertificateKeyFile /etc/apache/example_privatekey.pem
  SSLCipherSuite HIGH
  SSLProtocol all -SSLv2
  Redirect / https://bar.example.org/
</VirtualHost>

Domain Name Mismatch Errors

There seems to be various ways to get a Domain Name Mismatch error when setting up Apache to do multiple HTTPS VirtualHosts.

There is a screenshot of this error here: https://en.wiki.aktivix.org/CAcert

UseCanonicalName

Apache has UseCanonicalName On by default and when it is on you can use one VirtualHost with multiple ServerAlias' with all these ServerAlias' and the ServerName in the cert.

If however you have UseCanonicalName Off the you can't use any ServerAlias' and you have to have one VirtualHost per ServerName and then set all the VirtualHost's to use the same cert.

See the Apache docs for more info: http://httpd.apache.org/docs/2.0/mod/core.html#usecanonicalname

Repeating the CommonName as a SubjectAltName

The CommonName is ignored if you have any SubjectAltName's so the best thing to do it to repeat the CommonName as a SubjectAltName. If you don't do this then a VirtualHost set up with the ServerName the same as the CommonName will result in a Domain Name Mismatch error message.

CSR Generator for Windows

[http://www2.futureware.at/~philipp/CSRGenerator.zip]

See also

    https://docs.indymedia.org/view/Sysadmin/CaCertSsl#HTTP_multiple_domain_names

    http://www.frank4dd.com/webcert/cgi-bin/buildrequest.cgi
