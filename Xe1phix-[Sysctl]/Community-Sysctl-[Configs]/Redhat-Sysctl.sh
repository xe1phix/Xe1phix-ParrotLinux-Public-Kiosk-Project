#!/bin/sh                                                                    
#                                                                            
# Configure kernel sysctl run-time options.                                  
#                                                                            
###################################################################          
                                                                             
# Anti-spoofing blocks                                                       
for i in /proc/sys/net/ipv4/conf/*/rp_filter;                                
do                                                                           
 echo 1 > $i                                                                 
done                                                                         
                                                                             
# Ensure source routing is OFF                                               
for i in /proc/sys/net/ipv4/conf/*/accept_source_route;                      
 do                                                                          
  echo 0 > $i                                                                
 done                                                                        
                                                                             
# Ensure TCP SYN cookies protection is enabled                               
[ -e /proc/sys/net/ipv4/tcp_syncookies ] &&\                                 
 echo 1 > /proc/sys/net/ipv4/tcp_syncookies                                  
                                                                             
# Ensure ICMP redirects are disabled                                         
for i in /proc/sys/net/ipv4/conf/*/accept_redirects;                         
 do                                                                          
  echo 0 > $i                                                                
 done                                                                        
                                                                             
# Ensure oddball addresses are logged                                        
[ -e /proc/sys/net/ipv4/conf/all/log_martians ] &&\                          
 echo 1 > /proc/sys/net/ipv4/conf/all/log_martians                           
                                                                             
[ -e /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts ] &&\                    
 echo 1 > /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts                     
                                                                             
[ -e /proc/sys/net/ipv4/icmp_ignore_bogus_error_responses ] &&\              
 echo 1 > /proc/sys/net/ipv4/icmp_ignore_bogus_error_responses               
                                                                             
## Optional from here on down, depending on your situation. ############     
                                                                             
# Ensure ip-forwarding is enabled if                                         
# we want to do forwarding or masquerading.                                  
[ -e /proc/sys/net/ipv4/ip_forward ] &&\                                     
 echo 1 > /proc/sys/net/ipv4/ip_forward                                      
                                                                             
# On if your IP is dynamic (or you don't know).                              
[ -e /proc/sys/net/ipv4/ip_dynaddr ] &&\                                     
 echo 1 > /proc/sys/net/ipv4/ip_dynaddr                                      
                                                                             
# eof                                                                        
                                                                             
                                                                             

The same effect by using /etc/sysctl.conf instead: 

#                                                                            
# Add to existing sysctl.conf                                                
#                                                                            
                                                                             
# Anti-spoofing blocks                                                       
net.ipv4.conf.default.rp_filter = 1                                          
net.ipv4.conf.all.rp_filter = 1                                              
                                                                             
# Ensure source routing is OFF                                               
net.ipv4.conf.default.accept_source_route = 0                                
net.ipv4.conf.all.accept_source_route = 0                                    
                                                                             
# Ensure TCP SYN cookies protection is enabled                               
net.ipv4.tcp_syncookies = 1                                                  
                                                                             
# Ensure ICMP redirects are disabled                                         
net.ipv4.conf.default.accept_redirects = 0                                   
net.ipv4.conf.all.accept_redirects = 0                                       
                                                                             
# Ensure oddball addresses are logged                                        
net.ipv4.conf.default.log_martians = 1                                       
net.ipv4.conf.all.log_martians = 1                                           
                                                                             
                                                                             
net.ipv4.icmp_echo_ignore_broadcasts = 1                                     
                                                                             
net.ipv4.icmp_ignore_bogus_error_responses = 1                               
                                                                             
## Optional from here on down, depending on your situation. ############     
                                                                             
# Ensure ip-forwarding is enabled if                                         
# we want to do forwarding or masquerading.                                  
net.ipv4.ip_forward = 1                                                      
                                                                             
# On if your IP is dynamic (or you don't know).                              
net.ipv4.ip_dynaddr = 1                                                      
                                                                             
# end of example 
