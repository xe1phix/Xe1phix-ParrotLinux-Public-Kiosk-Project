# EXIF info 

exiftool -r -csv -exif:all -iptc:all -ext jpg -all /var/www/wpw/images/submissions/ > /tmp/out.csv