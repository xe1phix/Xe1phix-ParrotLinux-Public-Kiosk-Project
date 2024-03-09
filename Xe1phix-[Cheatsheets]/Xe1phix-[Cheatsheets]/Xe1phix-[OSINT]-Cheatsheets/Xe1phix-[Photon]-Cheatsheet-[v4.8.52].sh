#!/bin/sh


## -------------------------------------------------------------- ##
##   [?] Photon - Open Source Intelligence (OSINT) - Crawler
## -------------------------------------------------------------- ##
##   [?] https://github.com/s0md3v/Photon
## -------------------------------------------------------------- ##


photon -u $Domain -l 3 -t 100


## -------------------------------------------------------------- ##
photon --url $URL                   ## root url
photon --cookie $File               ## cookie
photon --regex $Pattern             ## regex pattern
photon --threads $Num               ## number of threads
photon --delay $Num                 ## delay between requests
photon --verbose                    ## verbose output
photon --user-agent $UserAgent      ## custom user agent(s)
photon --export csv                 ## Export report as csv
photon --export json                ## Export report as json
photon --output $File               ## 
photon --level $Num                 ## 
photon --clone $URL                 ## clone the website locally
photon --headers                    ## add headers
photon --dns                        ## enumerate subdomains and DNS data
photon --keys                       ## find secret keys
photon --only-urls                  ## only extract URLs
photon --wayback                    ## fetch URLs from archive.org as seeds
## -------------------------------------------------------------- ##

