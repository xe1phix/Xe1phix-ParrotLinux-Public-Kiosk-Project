

dnstracer -o      Enable overview of received answers at the end

dnstracer -q 
dnstracer -q a 
dnstracer -q aaaa
dnstracer -q a6
dnstracer -q soa
dnstracer -q cname
dnstracer -q hinfo
dnstracer -q mx
dnstracer -q ns
dnstracer -q txt
dnstracer -q ptr



dnstracer -r $Retries               ## Number of retries for DNS requests, default 3.

dnstracer -s $Server                ## 

dnstracer -v                        ## Be verbose on what sent or received.

dnstracer -4                        ## Use only IPv4 servers, dont query IPv6 servers

dnstracer -c                        ## Disable local caching

dnstracer -S $SourceAddr            ## Use this as source-address for the outgoing packets.



Search for the PTR record (hostname) of 212.204.230.141:

dnstracer "-q" ptr 141.230.204.212.in-addr.arpa



Search for the MX record of $Domain on the root-nameservers:

dnstracer "-s" . "-q" mx $Domain


