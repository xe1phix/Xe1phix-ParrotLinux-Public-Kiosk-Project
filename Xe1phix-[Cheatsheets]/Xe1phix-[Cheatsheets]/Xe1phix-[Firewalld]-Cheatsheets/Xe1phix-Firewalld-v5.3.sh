






cat /usr/share/polkit-1/actions/org.fedoraproject.FirewallD1.desktop.policy.choice




/etc/firewalld/zones/zone.xml
/usr/lib/firewalld/zones/zone.xml

/etc/firewalld/services/service.xml
/usr/lib/firewalld/services/service.xml





grep 'ipv6="yes"' --with-filename /usr/lib/firewalld/icmptypes/*



/usr/lib/firewalld/icmptypes/address-unreachable.xml:  <destination ipv6="yes"/>
/usr/lib/firewalld/icmptypes/bad-header.xml:  <destination ipv6="yes"/>
/usr/lib/firewalld/icmptypes/beyond-scope.xml:  <destination ipv6="yes"/>
/usr/lib/firewalld/icmptypes/communication-prohibited.xml:  <destination ipv6="yes"/>
/usr/lib/firewalld/icmptypes/failed-policy.xml:  <destination ipv6="yes"/>
/usr/lib/firewalld/icmptypes/neighbour-advertisement.xml:  <destination ipv6="yes"/>
/usr/lib/firewalld/icmptypes/neighbour-solicitation.xml:  <destination ipv6="yes"/>
/usr/lib/firewalld/icmptypes/no-route.xml:  <destination ipv6="yes"/>
/usr/lib/firewalld/icmptypes/packet-too-big.xml:  <destination ipv6="yes"/>
/usr/lib/firewalld/icmptypes/port-unreachable.xml:  <destination ipv6="yes"/>
/usr/lib/firewalld/icmptypes/reject-route.xml:  <destination ipv6="yes"/>
/usr/lib/firewalld/icmptypes/ttl-zero-during-reassembly.xml:  <destination ipv6="yes"/>
/usr/lib/firewalld/icmptypes/ttl-zero-during-transit.xml:  <destination ipv6="yes"/>
/usr/lib/firewalld/icmptypes/unknown-header-type.xml:  <destination ipv6="yes"/>
/usr/lib/firewalld/icmptypes/unknown-option.xml:  <destination ipv6="yes"/>


sed 's/ipv6="yes"/ipv6="no"/g' /usr/lib/firewalld/icmptypes/neighbour-advertisement.xml


sed 's/ipv6="yes"/ipv6="no"/g' /usr/lib/firewalld/icmptypes/neighbour-advertisement.xml
sed 's/ipv6="yes"/ipv6="no"/g' /usr/lib/firewalld/icmptypes/address-unreachable.xml
sed 's/ipv6="yes"/ipv6="no"/g' /usr/lib/firewalld/icmptypes/bad-header.xml
sed 's/ipv6="yes"/ipv6="no"/g' /usr/lib/firewalld/icmptypes/beyond-scope.xml
sed 's/ipv6="yes"/ipv6="no"/g' /usr/lib/firewalld/icmptypes/communication-prohibited.xml
sed 's/ipv6="yes"/ipv6="no"/g' /usr/lib/firewalld/icmptypes/failed-policy.xml
sed 's/ipv6="yes"/ipv6="no"/g' /usr/lib/firewalld/icmptypes/no-route.xml
sed 's/ipv6="yes"/ipv6="no"/g' /usr/lib/firewalld/icmptypes/packet-too-big.xml
sed 's/ipv6="yes"/ipv6="no"/g' /usr/lib/firewalld/icmptypes/port-unreachable.xml
sed 's/ipv6="yes"/ipv6="no"/g' /usr/lib/firewalld/icmptypes/reject-route.xml
sed 's/ipv6="yes"/ipv6="no"/g' /usr/lib/firewalld/icmptypes/ttl-zero-during-reassembly.xml
sed 's/ipv6="yes"/ipv6="no"/g' /usr/lib/firewalld/icmptypes/ttl-zero-during-transit.xml
sed 's/ipv6="yes"/ipv6="no"/g' /usr/lib/firewalld/icmptypes/unknown-header-type.xml
sed 's/ipv6="yes"/ipv6="no"/g' /usr/lib/firewalld/icmptypes/unknown-option.xml



firewall-offline-cmd --policy-desktop



--list-interfaces
--add-interface=
--change-interface=

--trust=$Interface

--query-interface=


--get-services
--get-icmptypes

--list-interfaces
--add-interface=
--change-interface=
--query-interface=
--get-zone-of-interface=




--get-zones
--list-all-zones
--info-zone=
--path-zone=


--get-zone-of-source=
--get-description
--get-target
--set-target=
--delete-zone=

to-port=
to-addr=
port=22  port="20-25"               ## port number portid or a port range portid-portid
protocol="tcp|udp|sctp|dccp"



--new-zone=
--new-zone-from-file=
--load-zone-defaults=









--lockdown-on
--lockdown-off


--get-all-rules
--get-all-chains
--list-rich-rules
--add-masquerade
--list-forward-ports


--query-icmp-block-inversion




--get-helpers
--info-helper=
--path-helper=
--new-helper=

--list-sources
--add-source=



--list-icmp-blocks
--add-icmp-block=


--add-icmp-block-inversion
--query-icmp-block-inversion

--block-icmp=





--list-ports
--add-port=

--list-protocols
--query-protocol=
--add-protocol=

--list-source-ports
--add-source-port=


--list-all
--add-service=
--list-services
--query-service=
--remove-service-from-zone=



--service=$Service --get-destinations
--service=$Service --get-modules
--service=$Service --add-module=
--service=$Service --remove-module=

--service=$Service --set-destination=<ipv>:<address>

--service=$Service --query-destination=<ipv>:<address>

--load-service-defaults=$Service   ## Load icmptype default settings
--info-service=$Service            ## Print information about a service
--path-service=$Service            ## Print file path of a service


--destination ipv4="address[/mask]"

























firewall-offline-cmd --list-all







qBittorent | /usr/sbin/ufw allow in on eth0 proto udp from any to any port 6881

















firewall-offline-cmd --enabled
firewall-offline-cmd --disabled
firewall-offline-cmd --migrate-system-config-firewall=file
firewall-offline-cmd --addmodule=module
firewall-offline-cmd --removemodule
firewall-offline-cmd --remove-service=service

firewall-cmd --get-services.
firewall-offline-cmd --service=service
firewall-offline-cmd --get-services.
firewall-offline-cmd -p portid[-portid]:protocol

--port=portid[-portid]:protocol

firewall-offline-cmd -t interface, --trust=interface
firewall-offline-cmd -m interface, --masq=interface
firewall-offline-cmd --custom-rules=[type:][table:]filename

firewall-offline-cmd --forward-port=if=interface:port=port:proto=protocol[:toport=destination

firewall-offline-cmd --block-icmp=icmptype
firewall-cmd --get-icmptypes
firewall-offline-cmd --get-log-denied
firewall-offline-cmd --set-log-denied=value
firewall-offline-cmd --get-automatic-helpers
firewall-offline-cmd --set-automatic-helpers=value
firewall-offline-cmd --get-default-zone
firewall-offline-cmd --set-default-zone=zone
firewall-offline-cmd --get-zones
firewall-offline-cmd --get-services
firewall-offline-cmd --get-icmptypes
firewall-offline-cmd --get-zone-of-interface=interface
firewall-offline-cmd --get-zone-of-source=source[/mask]|MAC|ipset:ipset
firewall-offline-cmd --info-zone=zone
firewall-offline-cmd --list-all-zones
firewall-offline-cmd --new-zone=zone
firewall-offline-cmd --new-zone-from-file=filename --name=$name
firewall-offline-cmd --path-zone=zone
firewall-offline-cmd --delete-zone=zone
firewall-offline-cmd --zone=zone --set-description=description
firewall-offline-cmd --zone=zone --get-description
firewall-offline-cmd --zone=zone --set-short=description
firewall-offline-cmd --zone=zone --get-short
firewall-offline-cmd --zone=zone --get-target
firewall-offline-cmd --zone=zone --set-target=zone

--zone=

firewall-offline-cmd --get-default-zone
firewall-offline-cmd --zone=$zone --list-all
firewall-offline-cmd --zone=$zone --list-services
firewall-offline-cmd --zone=$zone --add-service=service
firewall-offline-cmd --zone=$zone --remove-service-from-zone=service
firewall-offline-cmd --zone=$zone --query-service=service
firewall-offline-cmd --zone=$zone --list-ports
firewall-offline-cmd --zone=$zone --add-port=portid[-portid]/protocol
firewall-offline-cmd --zone=$zone --remove-port=portid[-portid]/protocol
firewall-offline-cmd --zone=$zone --query-port=portid[-portid]/protocol
firewall-offline-cmd --zone=$zone --list-protocols
firewall-offline-cmd --zone=$zone --add-protocol=protocol
firewall-offline-cmd --zone=$zone --remove-protocol=protocol
firewall-offline-cmd --zone=$zone --query-protocol=protocol
firewall-offline-cmd --zone=$zone --list-icmp-blocks
firewall-offline-cmd --zone=$zone --add-icmp-block=icmptype

firewall-cmd --get-icmptypes
firewall-offline-cmd --zone=$zone --remove-icmp-block=icmptype
firewall-offline-cmd --zone=$zone --query-icmp-block=icmptype
firewall-offline-cmd --zone=$zone --list-forward-ports

firewall-offline-cmd --add-forward-port=port=portid[-portid]:proto=protocol[:toport=portid[-portid]][:toaddr=address[/mask]]
firewall-offline-cmd --remove-forward-port=port=portid[-portid]:proto=protocol[:toport=portid[-portid]][:toaddr=address[/mask]]
firewall-offline-cmd --query-forward-port=port=portid[-portid]:proto=protocol[:toport=portid[-portid]][:toaddr=address[/mask]]

firewall-offline-cmd --zone=$zone --list-source-ports
firewall-offline-cmd --zone=$zone --add-source-port=portid[-portid]/protocol
firewall-offline-cmd --zone=$zone --remove-source-port=portid[-portid]/protocol
firewall-offline-cmd --zone=$zone --query-source-port=portid[-portid]/protocol
firewall-offline-cmd --zone=$zone --add-masquerade
firewall-offline-cmd --zone=$zone --remove-masquerade
firewall-offline-cmd --zone=$zone --query-masquerade
firewall-offline-cmd --zone=$zone --list-rich-rules
firewall-offline-cmd --zone=$zone --add-rich-rule='rule'
firewall-offline-cmd --zone=$zone --remove-rich-rule='rule'
firewall-offline-cmd --zone=$zone --query-rich-rule='rule'

firewall-offline-cmd --zone=$zone --list-interfaces
firewall-offline-cmd --zone=$zone --add-interface=interface
firewall-offline-cmd --zone=$zone --change-interface=interface

firewall-offline-cmd --zone=$zone --query-interface=interface
firewall-offline-cmd --zone=$zone --remove-interface=interface



firewall-offline-cmd --zone=$zone --list-sources
firewall-offline-cmd --zone=$zone --add-source=source[/mask]|MAC|ipset:ipset
firewall-offline-cmd --zone=$zone --change-source=source[/mask]|MAC|ipset:ipset
firewall-offline-cmd --zone=$zone --add-source.
firewall-offline-cmd --zone=$zone --query-source=source[/mask]|MAC|ipset:ipset
firewall-offline-cmd --zone=$zone --remove-source=source[/mask]|MAC|ipset:ipset
firewall-offline-cmd --new-ipset=ipset --type=ipset type [--option=ipset option[=value]]
firewall-offline-cmd --new-ipset-from-file=filename [--name=ipset]
firewall-offline-cmd --delete-ipset=ipset
firewall-offline-cmd --info-ipset=ipset
firewall-offline-cmd --get-ipsets
firewall-offline-cmd --ipset=ipset --add-entry=entry
firewall-offline-cmd --ipset=ipset --remove-entry=entry
firewall-offline-cmd --ipset=ipset --query-entry=entry
firewall-offline-cmd --ipset=ipset --get-entries
firewall-offline-cmd --ipset=ipset --add-entries-from-file=filename
firewall-offline-cmd --ipset=ipset --remove-entries-from-file=filename
firewall-offline-cmd --ipset=ipset --set-description=description
firewall-offline-cmd --ipset=ipset --get-description
firewall-offline-cmd --ipset=ipset --set-short=description
firewall-offline-cmd --ipset=ipset --get-short
firewall-offline-cmd --path-ipset=ipset
firewall-offline-cmd --info-service=service
firewall-offline-cmd --new-service=service
firewall-offline-cmd --new-service-from-file=filename [--name=service]
firewall-offline-cmd --delete-service=service
firewall-offline-cmd --path-service=service
firewall-offline-cmd --service=service --set-description=description
firewall-offline-cmd --service=service --get-description
firewall-offline-cmd --service=service --set-short=description
firewall-offline-cmd --service=service --get-short
firewall-offline-cmd --service=service --add-port=portid[-portid]/protocol
firewall-offline-cmd --service=service --remove-port=portid[-portid]/protocol
firewall-offline-cmd --service=service --query-port=portid[-portid]/protocol
firewall-offline-cmd --service=service --get-ports
firewall-offline-cmd --service=service --add-protocol=protocol
firewall-offline-cmd --service=service --remove-protocol=protocol
firewall-offline-cmd --service=service --query-protocol=protocol
firewall-offline-cmd --service=service --get-protocols
firewall-offline-cmd --service=service --add-source-port=portid[-portid]/protocol
firewall-offline-cmd --service=service --remove-source-port=portid[-portid]/protocol
firewall-offline-cmd --service=service --query-source-port=portid[-portid]/protocol
firewall-offline-cmd --service=service --get-source-ports
firewall-offline-cmd --service=service --add-module=module
firewall-offline-cmd --service=service --remove-module=module
firewall-offline-cmd --service=service --query-module=module
firewall-offline-cmd --service=service --get-modules
firewall-offline-cmd --service=service --set-destination=ipv:address[/mask]
firewall-offline-cmd --service=service --remove-destination=ipv
firewall-offline-cmd --service=service --query-destination=ipv:address[/mask]
firewall-offline-cmd --service=service --get-destinations
firewall-offline-cmd --info-helper=helper
firewall-offline-cmd --new-helper=helper --module=nf_conntrack_module [--family=ipv4|ipv6]
firewall-offline-cmd --new-helper-from-file=filename [--name=helper]
firewall-offline-cmd --delete-helper=helper
firewall-offline-cmd --load-helper-defaults=helper
firewall-offline-cmd --path-helper=helper
firewall-offline-cmd --get-helpers
firewall-offline-cmd --helper=helper --set-description=description
firewall-offline-cmd --helper=helper --get-description
firewall-offline-cmd --helper=helper --set-short=description
firewall-offline-cmd --helper=helper --get-short
firewall-offline-cmd --helper=helper --add-port=portid[-portid]/protocol
firewall-offline-cmd --helper=helper --remove-port=portid[-portid]/protocol
firewall-offline-cmd --helper=helper --query-port=portid[-portid]/protocol
firewall-offline-cmd --helper=helper --get-ports
firewall-offline-cmd --helper=helper --set-module=description
firewall-offline-cmd --helper=helper --get-module
firewall-offline-cmd --helper=helper --set-family=description
firewall-offline-cmd --helper=helper --get-family
firewall-offline-cmd --info-icmptype=icmptype
firewall-offline-cmd --new-icmptype=icmptype
firewall-offline-cmd --new-icmptype-from-file=filename [--name=icmptype]
firewall-offline-cmd --delete-icmptype=icmptype
firewall-offline-cmd --icmptype=icmptype --set-description=description
firewall-offline-cmd --icmptype=icmptype --get-description
firewall-offline-cmd --icmptype=icmptype --set-short=description
firewall-offline-cmd --icmptype=icmptype --get-short
firewall-offline-cmd --icmptype=icmptype --add-destination=ipv
firewall-offline-cmd --icmptype=icmptype --remove-destination=ipv
firewall-offline-cmd --icmptype=icmptype --query-destination=ipv
firewall-offline-cmd --icmptype=icmptype --get-destinations
firewall-offline-cmd --path-icmptype=icmptype
firewall-offline-cmd --add-service=service or --add-rich-rule='rule'.
firewall-offline-cmd --direct --get-all-chains
--direct --add-chain
firewall-offline-cmd --direct --get-chains { ipv4 | ipv6 | eb } table
--direct --add-chain
firewall-offline-cmd --direct --add-chain { ipv4 | ipv6 | eb } table chain
firewall-offline-cmd --direct --remove-chain { ipv4 | ipv6 | eb } table chain
firewall-offline-cmd --direct --query-chain { ipv4 | ipv6 | eb } table chain
--direct --add-chain.
firewall-offline-cmd --direct --get-all-rules
firewall-offline-cmd --direct --get-rules { ipv4 | ipv6 | eb } table chain
firewall-offline-cmd --direct --add-rule { ipv4 | ipv6 | eb } table chain priority args
firewall-offline-cmd --direct --remove-rule { ipv4 | ipv6 | eb } table chain priority args
firewall-offline-cmd --direct --remove-rules { ipv4 | ipv6 | eb } table chain
--direct --add-rule

firewall-offline-cmd --direct --query-rule { ipv4 | ipv6 | eb } table chain priority args
firewall-offline-cmd --direct --get-all-passthroughs
firewall-offline-cmd --direct --get-passthroughs { ipv4 | ipv6 | eb }
firewall-offline-cmd --direct --add-passthrough { ipv4 | ipv6 | eb } args
firewall-offline-cmd --direct --remove-passthrough { ipv4 | ipv6 | eb } args
firewall-offline-cmd --direct --query-passthrough { ipv4 | ipv6 | eb } args
firewall-offline-cmd --lockdown-on
firewall-offline-cmd --lockdown-off
firewall-offline-cmd --query-lockdown

ps -e --context
firewall-offline-cmd --list-lockdown-whitelist-commands
firewall-offline-cmd --add-lockdown-whitelist-command=command
firewall-offline-cmd --remove-lockdown-whitelist-command=command
firewall-offline-cmd --query-lockdown-whitelist-command=command
firewall-offline-cmd --list-lockdown-whitelist-contexts
firewall-offline-cmd --add-lockdown-whitelist-context=context
firewall-offline-cmd --remove-lockdown-whitelist-context=context
firewall-offline-cmd --query-lockdown-whitelist-context=context
firewall-offline-cmd --list-lockdown-whitelist-uids
firewall-offline-cmd --add-lockdown-whitelist-uid=uid
firewall-offline-cmd --remove-lockdown-whitelist-uid=uid
firewall-offline-cmd --query-lockdown-whitelist-uid=uid
firewall-offline-cmd --list-lockdown-whitelist-users
firewall-offline-cmd --add-lockdown-whitelist-user=user
firewall-offline-cmd --remove-lockdown-whitelist-user=user
firewall-offline-cmd --query-lockdown-whitelist-user=user
firewall-offline-cmd --policy-server
firewall-offline-cmd --policy-desktop






       The general rule structure:

           <rule [family="ipv4|ipv6"]>
             [ <source address="address[/mask]" [invert="True"]/> ]
             [ <destination address="address[/mask]" [invert="True"]/> ]
             [
               <service name="string"/> |
               <port port="portid[-portid]" protocol="tcp|udp|sctp|dccp"/> |
               <protocol value="protocol"/> |

               <icmp-block name="icmptype"/> |
               <icmp-type name="icmptype"/> |
               <masquerade/> |
               <forward-port port="portid[-portid]" protocol="tcp|udp|sctp|dccp" [to-port="portid[-port
id]"] [to-addr="address"]/> |
               <source-port port="portid[-portid]" protocol="tcp|udp|sctp|dccp"/> |
             ]
             [ <log [prefix="prefixtext"] [level="emerg|alert|crit|err|warn|notice|info|debug"]/> [<lim
it value="rate/duration"/>] </log> ]
             [ <audit> [<limit value="rate/duration"/>] </audit> ]
             [
               <accept> [<limit value="rate/duration"/>] </accept> |
               <reject [type="rejecttype"]> [<limit value="rate/duration"/>] </reject> |
               <drop> [<limit value="rate/duration"/>] </drop> |
               <mark set="mark[/mask]"> [<limit value="rate/duration"/>] </mark>
             ]

           </rule>

       Rule structure for source black or white listing:

           <rule [family="ipv4|ipv6"]>
             <source address="address[/mask]" [invert="True"]/>
             [ <log [prefix="prefixtext"] [level="emerg|alert|crit|err|warn|notice|info|debug"]/> [<limit value="rate/duration"/>] </log> ]
             [ <audit> [<limit value="rate/duration"/>] </audit> ]
             <accept> [<limit value="rate/duration"/>] </accept> |
             <reject [type="rejecttype"]> [<limit value="rate/duration"/>] </reject> |
             <drop> [<limit value="rate/duration"/>] </drop>
           </rule>








firewalld.richlanguage


















