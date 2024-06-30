# Netflow Analytics

## Tools 

In order to get the netflows for our analyzing we can use the next tools that will help us in this task:

+ Softflowd allows us to send the netflows according to our network data
+ Nfdump has the tools to get and process the netflow files that we have gotten from softflowd

**_Settings_**

_Softflowd_

We can modify the softflowd interface through the next file, it is important to define the IP and port. 
```
/etc/default/softflowd
```
Once the file was changed we can start the demon softflowd
```
/etc/init.d/softflowd start
```
Using the next command we can check if we are getting the data and changing them to flows.
```
softflowd -i interface -n IP:PORT -D
```
statistics is a command from softlowd who shows some statistics of our flows.
```
softflowctl statistics
```
_nfdump_

```
sudo systemctl enable nfdump.service
```
Let's stop the service to change the settings (the port)
```
sudo pico /lib/systemd/system/nfdump.service
```
The nfdump's settings file is this
```
sudo vi /lib/systemd/system/nfdump.service
```
Reload systemd daemons and start ndfdump:
```
sudo systemctl daemon-reload
sudo systemctl start nfdump.service
```
We can be sure if the ports are OK using the netstat
```
netstat -n --udp --listen
```
Using the next command we can print the data through nfdump
```
nfdump -R /var/cache/nfdump
```

## Ndfump to manage the flows

nfdump -r nfcapd.2017xxxxx -o extended -o csv -q

Convert to CSV
```
nfdump -r file -o csv > output.csv
```
We can see the information of each field in the next URL "https://github.com/phaag/nfdump/blob/4dafc2dc050a7371afb2e0934f7989876bfc0870/bin/parse_csv.pl"

Filter IP
```
nfdump -r [input file] 'net 8.8.8.8/32'
```
## Port Scan Detection


## References
+ https://www.securityartwork.es/2019/02/26/analizando-nuestra-red-iv/#more-27645
+ https://mattjhayes.com/2018/08/19/collecting-netflow-with-nfcapd-and-nfdump/
+ https://ixnfo.com/en/installing-and-using-softflowd.html
+ https://elf11.github.io/2015/09/10/NetFlows-data-generation.html
+ https://blog.programster.org/nfdump-cheatsheet
+ https://www.first.org/resources/papers/conference2006/haag-peter-papers.pdf
