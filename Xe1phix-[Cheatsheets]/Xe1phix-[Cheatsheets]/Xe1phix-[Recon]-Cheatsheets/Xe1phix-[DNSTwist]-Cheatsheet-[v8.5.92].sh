#!/bin/sh


## ------------------------------------------------------------------------------------------ ##
    dnstwist --registered $Domain           ## Show only registered domain names
## ------------------------------------------------------------------------------------------ ##
    dnstwist --dictionary $File $Domain     ## Generate more domains using dictionary FILE
## ------------------------------------------------------------------------------------------ ##
    dnstwist --geoip $Domain                ## Lookup for GeoIP location
## ------------------------------------------------------------------------------------------ ##
    dnstwist --mxcheck $Domain              ## Check if MX can be used to intercept emails
## ------------------------------------------------------------------------------------------ ##
    dnstwist --whois $Domain                ## Lookup WHOIS database for creation date
## ------------------------------------------------------------------------------------------ ##
    dnstwist --tld $File $Domain            ## Generate more domains by swapping TLD from FILE
## ------------------------------------------------------------------------------------------ ##
    dnstwist --nameservers $DNS $Domain     ## DNS servers to query
## ------------------------------------------------------------------------------------------ ##
    dnstwist --all $Domain                  ## Show all DNS records
## ------------------------------------------------------------------------------------------ ##
    dnstwist --banners $Domain              ## Determine HTTP and SMTP service banners
## ------------------------------------------------------------------------------------------ ##

