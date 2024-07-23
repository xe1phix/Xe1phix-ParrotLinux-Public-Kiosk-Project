## FirewallD command line snippets for Linux

Create new zone identified by an IP Address or interface
This 'example' zone rules will applied to the connection from 192.168.1.2
```
  $ firewall-cmd --list-all-zones
  $ firewall-cmd --permanent --new-zone=example
  $ firewall-cmd --permanent --zone=example --add-source=192.168.1.2
  $ firewall-cmd --zone=example --list-sources
```
An interface also can be assigned to an interface 
 
```
  $ firewall-cmd --permanent --zone=example --add-interface=eth0
  $ firewall-cmd --permanent --zone=example --change-interface=eth0
  $ firewall-cmd --permanent --zone=example --remove-interface=eth0
```

Allow some service or by port number  
```
  $ firewall-cmd --get-services
  $ firewall-cmd --permanent --zone=example --add-service=http
  $ firewall-cmd --permanent --zone=example --add-service={http,https,dns}
  $ firewall-cmd --permanent --zone=example --add-port=1234/tcp
  $ firewall-cmd --permanent --zone=example --remove-port=1234/tcp
```

Add and remove rich rules
```
  $ firewall-cmd --permanent --add-rich-rule='rule family="ipv4" source address="192.168.1.4" port port="1234" protocol="tcp" accept'
  $ firewall-cmd --permanent --remove-rich-rule='rule family="ipv4" source address="192.168.1.4" port port="1234" protocol="tcp" accept'
```

Add and remove masquerade
```  
  $ firewall-cmd --permanent --zone=example --add-masquerade
  $ firewall-cmd --permanent --zone=example --remove-masquerade
```

Forward some port
```
  $ firewall-cmd --zone=example --add-forward-port=port=22:proto=tcp:toport=3753
  $ firewall-cmd --zone=example --remove-forward-port=port=22:proto=tcp:toport=3753
```

Or even add and remove with direct mode
```
  $ firewall-cmd --direct --add-rule ipv4 filter INPUT 0 -p tcp --dport 9000 -j ACCEPT
```

View rules and services on a default zone
```  
  $ firewall-cmd --list-all
  $ firewall-cmd --list-services
```

Finally, apply the changes
```
  $ firewall-cmd --reload
```

## IP Ban

Create new ipset with type `hash:net` for network or `hash:ip` for individual ip entry
```
 $ firewall-cmd --permanent --new-ipset=blacklist --type=hash:net --option=family=inet --option=hashsize=4096 --option=maxelem=200000
```

Managing the ipset
```
 $ firewall-cmd --permanent --get-ipsets
 $ firewall-cmd --permanent --info-ipset=blacklist
 $ firewall-cmd --permanent --ipset=blacklist --get-entries
 $ firewall-cmd --permanent --ipset=blacklist --add-entries-from-file=iplist.txt
 $ firewall-cmd --permanent --ipset=blacklist --remove-entries-from-file=iplist.txt
```

Ban
```
 $ firewall-cmd --permanent --ipset=blacklist --add-entry=$1
 $ firewall-cmd --ipset=blacklist --add-entry=$1
```

Redirect the blacklist to the drop zone
```
 $ firewall-cmd --permanent --zone=drop --add-source=ipset:blacklist
 $ firewall-cmd --reload
```