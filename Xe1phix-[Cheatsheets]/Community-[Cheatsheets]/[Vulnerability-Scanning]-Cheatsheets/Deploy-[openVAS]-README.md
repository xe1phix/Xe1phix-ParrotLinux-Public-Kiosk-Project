# openvas-sandbox

Travis (.com) branch:
[![Build Status](https://travis-ci.com/githubfoam/openvas-sandbox.svg?branch=master)](https://travis-ci.com/githubfoam/openvas-sandbox) 


~~~~
Deploy openVAS on kali linux

>vagrant init --template scripts/Vagrantfile.erb
>vagrant up vg-kali-02
>vagrant ssh vg-kali-02


apt-get update -y
apt-get upgrade -y
apt-get install -yq gvm
gvm-setup
gvm-start

browse the local host 
“https://127.0.0.1:9392”

>vagrant destroy -f vg-kali-02
>del Vagrantfile

~~~~

~~~~
>vagrant init --template scripts/Vagrantfile.erb
>vagrant up "vg-openvas-01"

~~~~
~~~~
Login with admin and the password in the script output

total size is 63,121,109  speedup is 1.00
/usr/sbin/openvasmd

ExecStart=/usr/sbin/gsad --foreground --listen=0.0.0.0 --port=9392 --mlisten=0.0.0.0 --mport=9390 --allow-header-host 192.168.22.12

User created with password 'b124cb71-220b-4f0b-8308-005187a3828b'.
~~~~

~~~~

check that gsad is running and listening
# netstat -apn | grep LISTEN
# netstat -anp | grep gsad

vagrant@vg-openvas-02:~$ sudo netstat -apn | grep LISTEN
tcp        0      0 127.0.0.1:9390          0.0.0.0:*               LISTEN      889/openvasmd
tcp        0      0 127.0.0.1:9392          0.0.0.0:*               LISTEN      737/gsad
tcp        0      0 127.0.0.1:80            0.0.0.0:*               LISTEN      900/gsad

vagrant@vg-openvas-02:~$ sudo netstat -anp | grep gsad
tcp        0      0 127.0.0.1:9392          0.0.0.0:*               LISTEN      737/gsad
tcp        0      0 127.0.0.1:80            0.0.0.0:*               LISTEN      900/gsad
unix  3      [ ]         STREAM     CONNECTED     18405    737/gsad

vagrant@vg-openvas-02:~$ sudo netstat -anp | grep openvas
tcp        0      0 127.0.0.1:9390          0.0.0.0:*               LISTEN      889/openvasmd
unix  2      [ ACC ]     STREAM     LISTENING     23023    1488/openvassd: Wai  /var/run/openvassd.sock
unix  2      [ ACC ]     STREAM     LISTENING     21878    863/redis-server 12  /var/run/redis-openvas/redis-server.sock
unix  3      [ ]         STREAM     CONNECTED     28186    863/redis-server 12  /var/run/redis-openvas/redis-server.sock
unix  3      [ ]         STREAM     CONNECTED     25910    1488/openvassd: Wai
unix  3      [ ]         STREAM     CONNECTED     20133    889/openvasmd

wget -p http://192.168.22.12
--2019-11-27 16:26:54--  http://192.168.22.12/
Connecting to 192.168.22.12:80... connected.
HTTP request sent, awaiting response... 303 See Other
Location: https://192.168.22.12:9392/login/login.html [following]
--2019-11-27 16:26:54--  https://192.168.22.12:9392/login/login.html
Connecting to 192.168.22.12:9392... connected.
ERROR: cannot verify 192.168.22.12's certificate, issued by ‘C=DE,L=Osnabrueck,O=OpenVAS Users,OU=Certificate Authority for vg-openvas-01’:
 Unable to locally verify the issuer's authority.
   ERROR: certificate common name ‘vg-openvas-01’ doesn't match requested host name ‘192.168.22.12’.
To connect to 192.168.22.12 insecurely, use `--no-check-certificate'.

https://192.168.22.12:9392/login/login.html

# vi /lib/systemd/system/greenbone-security-assistant.service

# systemctl daemon-reload
vagrant@vg-openvas-01:~$ sudo systemctl restart greenbone-security-assistant.service
vagrant@vg-openvas-01:~$ sudo systemctl status greenbone-security-assistant.service

# omp --help

password change
vg-openvas-01:~$ sudo openvasmd --user=admin --new-password=admin

$ sudo openvas-stop
Stopping OpenVas Services
$ sudo openvas-start
Starting OpenVas Services

~~~~
~~~~
Web UI
Menu - Configuration - Targets
Menu - Scans - Tasks


Network Targets
    Single IPv4 address: 192.168.300.10
    IPv4 address range in short format: 192.168.200.100-11
    IPv4 address range in long format: 192.168.200.100-192.168.200.110
    IPv4 address range in CIDR notation: 192.168.100.0/24

~~~~

~~~~
https://github.com/greenbone/openvas
~~~~