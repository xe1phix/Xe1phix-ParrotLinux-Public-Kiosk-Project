#!/bin/sh
##-=====================================-##
##   [+] Xe1phix-[LDAP]-Cheatsheet.sh
##-=====================================-##



systemctl start slapd.service
systemctl enable slapd.service > /dev/null 2>&1
slappasswd -s 1234 -n > /etc/openldap/passwd



Anonymous Bind:

ldapsearch -h ldaphostname -p 389 -x -b "dc=domain,dc=com"


Authenticated:

ldapsearch -h 192.168.0.60 -p 389 -x -D "CN=Administrator, CN=User, DC=<domain>, DC=com" -b "DC=<domain>, DC=com" -W


Look for anonymous bind

ldapsearch -x -b "dc=megabank,dc=local" "*" -h $ip



slapcat -v -l backup_ldap.ldif


ps -ef | grep slapd


/etc/default/slapd
/etc/ldap/
ldap.conf		--> basic server config
sasl2/			--> SASL2 authentication support
schema/			--> default schemas
slapd.d/		--> new/modified items/ldifs data - do not edit manually, use instead: slapd-config, ldapadd, ldapmodify, ldapdelete,ldapsearch, etc ('dpkg -L ldap-utils' to get a list of all client commands and other files)
/var/lib/ldap	--> DB directory. Contains DITs, ex:

cn=config (default)		- root of configuration of LDAP instance server wide.
dc=frozza, dc=com

/var/run/slapd/
slapd.pid		--> current pid
slapd			--> arguments used during invocation
ldapi			--> UDS

netstat -ntl	--> shows tcp 389


