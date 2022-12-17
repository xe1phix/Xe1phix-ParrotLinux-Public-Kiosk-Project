#!/bin/sh


       conntrack -L
              Show the connection tracking table in /proc/net/ip_conntrack format

       conntrack -L -o extended
              Show the connection tracking table in  /proc/net/nf_conntrack  format,
              with additional information.

       conntrack -L -o xml
              Show the connection tracking table in XML


       conntrack -L -f ipv6 -o extended
              Only  dump IPv6 connections in /proc/net/nf_conntrack format, with ad‐
              ditional information.

       conntrack -L --src-nat
              Show source NAT connections

       conntrack -E -o timestamp
              Show connection events together with the timestamp

       conntrack -D -s 1.2.3.4
              Delete all flow whose source address is 1.2.3.4

       conntrack -U -s 1.2.3.4 -m 1
              Set connmark to 1 of all the flows whose source address is 1.2.3.4


