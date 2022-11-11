--------------------------------------------------------------------------------------------------
#find out which versions of TLS are configured on a web server
Firefox - click the padlock icon (on the left of the URL) - More Information - Technical Details
Chrome - More Tools - Developer Tools - Security
Edge - More Tools - Developer Tools - Security

https://www.ssllabs.com/ssltest/ #public websites
--------------------------------------------------------------------------------------------------
https://www.ssllabs.com/ssltest/ # online service

# connect to igvita.com on the default TLS port (443), perform the TLS handshake
# s_client makes no assumptions about known root certificates,manually specify the path to the root certificate
openssl s_client -state -CAfile root.ca.crt -connect igvita.com:443 #verify and test configuration

openssl speed ecdh #the Elliptic Curve Diffie-Hellman (ECDH) test provides a summary table of operations per second for different key sizes
openssl speed aes #AES performance is measured in bytes per second
--------------------------------------------------------------------------------------------------
export HUBBLE_VERSION=$(curl -s https://raw.githubusercontent.com/cilium/hubble/master/stable.txt)
curl -LO "https://github.com/cilium/hubble/releases/download/$HUBBLE_VERSION/hubble-linux-amd64.tar.gz"
curl -LO "https://github.com/cilium/hubble/releases/download/$HUBBLE_VERSION/hubble-linux-amd64.tar.gz.sha256sum"
sha256sum --check hubble-linux-amd64.tar.gz.sha256sum
tar zxf hubble-linux-amd64.tar.gz
--------------------------------------------------------------------------------------------------
export HASHICORP_PUBLIC_KEY_URL="https://keybase.io/hashicorp/pgp_keys.asc" #https://www.hashicorp.com/security
`curl -sSL "${HASHICORP_PUBLIC_KEY_URL}" | gpg --import -` # import the public key (PGP key)
gpg --verify "vagrant_${VAGRANT_CURRENT_VERSION}_SHA256SUMS.sig" "vagrant_${VAGRANT_CURRENT_VERSION}_SHA256SUMS" 2>/dev/null #Verify the signature file is untampered

sha256sum  vagrant_${VAGRANT_CURRENT_VERSION}_x86_64.deb # via sha256sum
openssl dgst -sha256 vagrant_${VAGRANT_CURRENT_VERSION}_x86_64.deb # via openssl

shasum -a 256 -c "vagrant_${VAGRANT_CURRENT_VERSION}_SHA256SUMS" 2>&1 | grep OK
--------------------------------------------------------------------------------------------------
vagrant@apache03:~$ hostnamectl
   Static hostname: apache03
         Icon name: computer-vm
           Chassis: vm
        Machine ID: 1ee8a88880d54ab3bd986fa946a05c35
           Boot ID: bc3318d378a14463bc5d69d2f91f9554
    Virtualization: oracle
  Operating System: Ubuntu 18.10
            Kernel: Linux 4.18.0-10-generic
      Architecture: x86-64

$ sudo apt install -y whois
# -S, --salt=STRING
$ mkpasswd -m sha-512 mypassword --salt="mightysalt"
$ echo "badpassword" | mkpasswd --stdin --method=des
$ printf "badpassword" | mkpasswd --stdin --method=des --salt="AA"
$ printf "badpassword" | mkpasswd --stdin --method=des --salt="AA"
$ printf "badpassword" | mkpasswd --stdin --method=md5
$ printf "badpassword" | mkpasswd --stdin --method=sha-256 --salt="U7ReiUGcnY9yt3A1"
$ printf "badpassword" | mkpasswd --stdin --method=sha-512 --salt="g3RYi6b0nk9y43Rl"
$ RPASS=$(mkpasswd --stdin --method=des)
$ echo "$RPASS"
$ RPASS=$(printf "badpassword" | mkpasswd --stdin --method=sha-256 --salt="U7ReiUGcnY9yt3A1")
$ echo "$RPASS"


$ sudo apt-get install -y makepasswd
$ makepasswd --chars 16 --count 7 --crypt-md5

vagrant@apache01 ~]$ hostnamectl
   Static hostname: apache01
         Icon name: computer-vm
           Chassis: vm
        Machine ID: cfa0388701ff415dbceb1d083ec3fdfd
           Boot ID: 557b255d7351438f86f8a0e987857021
    Virtualization: kvm
  Operating System: CentOS Linux 7 (Core)
       CPE OS Name: cpe:/o:centos:centos:7
            Kernel: Linux 3.10.0-957.1.3.el7.x86_64
      Architecture: x86-64
      
$ sudo yum install -y expect      
$ mkpasswd
$ for pw in {1..10}; do mkpasswd -l 14 -d 3 -C 3 -s 3; done


# calculate the checksum of the string password, vulnerable to en.wikipedia.org/wiki/Rainbow_table attack. 
$ echo "mypassword" | sha512sum
32f73fbcf845201857499061db1d50326ce6cbce9d7b9650ad2f301a9f263d02553b5e3d08a940456e97267bc9d4c10d8903e6378803257223a84140db0ad5cc  -

# ‘-base64’ string will make sure the password can be typed on a keyboard
$ openssl rand -base64 14
$ openssl rand -hex 12
$ openssl rand -base64 32 | tr -d /=+ | cut -c -16

$ for pw in {1..10}; do openssl rand -base64 14; done

$ sudo yum install -y pwgen
$ pwgen -s 14 5
generate one password
$ pwgen -N 1
generate one password with 20 characters long
$ pwgen 20 1
$ pwgen -1 -s -y

PASSWORD=$(head -c 12 /dev/urandom | shasum| cut -d' ' -f1) # generate a random password

$ date | md5sum
$ date | sha256sum
$ date +%s | sha256sum | base64 | head -c 32 ; echo

# The character special files /dev/random and /dev/urandom provide an interface to the kernel’s random number generator.
# File /dev/random has major device number 1 and minor device number 8
# File /dev/urandom has major device number 1 and minor device number 9.
$ cat /dev/urandom | tr -dc 'a-zA-Z0-9' | head -c 8
$ tr -cd '[:alnum:]' < /dev/urandom | fold -w30 | head -n1
$ tr -dc A-Za-z0-9 < /dev/urandom | head -c 8 | xargs
$ head /dev/urandom | tr -dc A-Za-z0-9 | base64 | head -c 13 ; echo ''
$ cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 10 | head -n 1
$ cat /dev/urandom | tr -dc 'A-Za-z0-9!"#$%&'\''()*+,-./:;<=>?@[\]^_`{|}~' | head -c 13  ; echo
$ strings /dev/urandom | grep -o '[[:alnum:]]' | head -n 30 | tr -d '\n'; echo
outputs all of the ASCII printable characters - from 32 (space) to 126 (tilde, ~)
$ cat /dev/urandom | tr -cd "[:print:]" | head -c 32; echo
 not include the space, just characters 33-126
$ cat /dev/urandom | tr -cd "[:graph:]" | head -c 32; echo
44 characters : log2(57^44) > 256.64 bits of entropy
$ base64 < /dev/urandom | tr -d 'O0Il1+\/' | head -c 44 ; echo ''
22 characters: log2(57^22) > 128.32 bits of entropy
$ base64 < /dev/urandom | tr -d 'O0Il1+\/' | head -c 22 ; echo ''
24 character
$ cat /dev/urandom | base64 | head -n 1 |tr -dc '[:alnum:]' |cut -c -24
exclude eg "a D C" chars
$ cat /dev/urandom | base64 | head -n 1 |tr -dc '[:alnum:]' | tr -d 'aDC'|cut -c -24

$ tr -dc A-Za-z0-9 < /dev/urandom | dd bs=100 count=1 2>/dev/null; echo ''
$ dd if=/dev/urandom bs=1 count=32 2>/dev/null | base64 -w 0 | rev | cut -b 2- | rev

$ echo $RANDOM | tr '[0-9]' '[a-z]'

$ gpg --gen-random --armor 1 14
$ gpg2 --gen-random --armor 1 14
$ for pw in {1..10}; do gpg2 --gen-random --armor 1 14; done

$ perl -e 'print crypt("password","\$6\$saltsalt\$") . "\n"'

$ python -c "import crypt, getpass, pwd; print(crypt.crypt('password', '\$6\$saltsalt\$'))"
--------------------------------------------------------------------------------------------------
Encrypt using salt
$ echo "mypassword"  | openssl enc -aes-256-cbc -a -salt -pass pass:"saltingmypassword"
U2FsdGVkX198rERJEIZSMLnplPSQBbAMXnNLtNrkGyY=
$
Decrypt 
$ echo "U2FsdGVkX198rERJEIZSMLnplPSQBbAMXnNLtNrkGyY=" | openssl enc -aes-256-cbc -a -d -salt -pass pass:"saltingmypassword"
mypassword
$
--------------------------------------------------------------------------------------------------
#compare two SSL certificates

#If both came from the same csr, then the md5 will match
openssl x509 -noout -modulus -in server.nr1.crt | openssl md5
openssl x509 -noout -modulus -in server.nr2.crt | openssl md5
#Check the certs against the private key to ensure the cert and private key match up,The output md5 hash values should match
openssl x509 -noout -modulus -in server.crt | openssl md5
openssl rsa -noout -modulus -in server.key | openssl md5
openssl req -noout -modulus -in server.csr | openssl md5 #check csr to ensure that it matches private key and cert

#ca/ca_pub.pem The public part of the private key.compare it with the private key by doing:
vimdiff <(openssl rsa -in ca/ca_key.pem -pubout) <(cat ca/ca_pub.pem )
--------------------------------------------------------------------------------------------------