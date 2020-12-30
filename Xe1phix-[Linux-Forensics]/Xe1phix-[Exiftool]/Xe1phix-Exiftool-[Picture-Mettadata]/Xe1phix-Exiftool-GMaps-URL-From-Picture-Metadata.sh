#!/bin/sh
##-======================================-##
## [+] Xe1phix-Exiftool-GMaps-URL-From-Picture-Metadata.sh
##-======================================-##
## ------------------------------------------------------------------------------------------- ##
##  [?] Generate a Google maps URL for GPS 
##       location data from digital photo
## ------------------------------------------------------------------------------------------- ##
echo "https://www.google.com/maps/place/$(exiftool -ee -p '$gpslatitude, $gpslongitude' -c "%d?%d'%.2f"\" image.jpg 2> /dev/null | sed -e "s/ //g")"
