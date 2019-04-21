#!/bin/sh







**IPs and ports used by DNSCrypt-proxy**  

Respectively, the local IP and port used by DNSCrypt-proxy to act as  
primary DNS and secondary DNS instances
  
    cPrimaryIP="127.0.0.1"
    cPrimaryPort="5553"
    cSecondaryIP="127.0.0.1"
    cSecondaryPort="5554"


**URL to copy Public Key used by Minisign**  

cSIGKey="RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3"




Path to DNSCrypt-proxy application:

    cProxyBaseDir="/usr/local/sbin/"

Path to resolvers.csv file:

    cCSVBaseDir="/usr/local/share/dnscrypt-proxy/"

Path to Minisign path file:

	cSIGBaseDir="/usr/local/share/dnscrypt-proxy/"

**Parameters used by DNSCrypt-proxy**  
cOtherParams="--ephemeral-keys "


Automatic resolvers.csv update uses this URL to download it  

    cCSVURL="https://download.dnscrypt.org/dnscrypt-proxy/dnscrypt-resolvers.csv"


Automatic resolvers.csv signature verification uses this URL to download it  

    cSIGURL="https://download.dnscrypt.org/dnscrypt-proxy/dnscrypt-resolvers.csv.minisig"














## see /run/media/public/2TB/NewMaterialRename/Scripts/dnscrypt-wrapper/README.md



git clone --recursive git://github.com/cofyc/dnscrypt-wrapper.git
    $ cd dnscrypt-wrapper
    $ make configure
    $ ./configure
    $ make install



Generate the provider key pair:
This will create two files in the current directory: `public.key` and
`secret.key`.
```
$ dnscrypt-wrapper --gen-provider-keypair







Print out provider public key:

dnscrypt-wrapper --show-provider-publickey --provider-publickey-file <your-publickey-file>




Generate a time-limited secret key, which will be used to encrypt
and authenticate DNS queries. Also generate a certificate for it:

```
$ dnscrypt-wrapper --gen-crypt-keypair --crypt-secretkey-file=1.key
$ dnscrypt-wrapper --gen-cert-file --crypt-secretkey-file=1.key --provider-cert-file=1.cert \
                   --provider-publickey-file=public.key --provider-secretkey-file=secret.key
                   
                   
                   
                   
                   
                   Run the program with a given key, a provider name and the most recent certificate:

```
$ dnscrypt-wrapper --resolver-address=8.8.8.8:53 --listen-address=0.0.0.0:443 \
                   --provider-name=2.dnscrypt-cert.<yourdomain> \
                   --crypt-secretkey-file=1.key --provider-cert-file=1.cert
                   
                   
                   
                   
                   
                   
instructions for
Unbound and TinyDNS are displayed by the program when generating a
provider certificate.

You can get instructions later by running:

```
$ dnscrypt-wrapper --show-provider-publickey-dns-records
                   --provider-cert-file <path/to/your/provider_cert_file>
```

4) Run dnscrypt-proxy to check if it works:

```
$ dnscrypt-proxy --local-address=127.0.0.1:55 --resolver-address=127.0.0.1:443 \
                 --provider-name=2.dnscrypt-cert.<yourdomain> \
                 --provider-key=<provider_public_key>
$ dig -p 55 google.com @127.0.0.1
                   
                   
                   
                   


view command line options
dnscrypt-wrapper -h







### Key rotation

Time-limited keys are bound to expire.



dnscrypt-proxy --resolver-address=127.0.0.1:443 \
                 --provider-name=2.dnscrypt-cert.<yourdomain> \
                 --provider-key=<provider_public_key> \
                 --test=10080




create a new time-limited key (do not change the provider key!) and
its certificate:

```
$ dnscrypt-wrapper --gen-crypt-keypair --crypt-secretkey-file=2.key
$ dnscrypt-wrapper --gen-cert-file --crypt-secretkey-file=2.key --provider-cert-file=2.cert \
                   --provider-publickey-file=public.key --provider-secretkey-file=secret.key \
                   --cert-file-expire-days=1




Tell new users to use the new certificate but still accept the old
key until all clients have loaded the new certificate:

```
$ dnscrypt-wrapper --resolver-address=8.8.8.8:53 --listen-address=0.0.0.0:443 \
                   --provider-name=2.dnscrypt-cert.<yourdomain> \
                   --crypt-secretkey-file=1.key,2.key --provider-cert-file=1.cert,2.cert

















if ! grep -q "^dnscrypt-wrapper:" /etc/passwd
then
	adduser --system --home /bin --group --shell /usr/sbin/nologin dnscrypt-wrapper
fi
