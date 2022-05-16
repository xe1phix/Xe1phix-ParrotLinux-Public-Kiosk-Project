# Find tutorial;
# http://www.grymoire.com/Unix/Find.html

# find files modified less than 5 days ago
$ find . -type f -mtime -5 -print | xargs ls -l

# find files (with spaces in name) modified less than 5 days ago 
$ find . -type f -mtime -5 -print0 | xargs -0 ls -l

# find & remove directories older than 200 days
$ find . -type d -mtime +200 -print | xargs rm -rf
# or
$ for i in `find /dir -type d -mtime +200 -print`; do echo -e "Deleting directory $i";rm -rf $i; done

# find and replace text in multiple files
$ find . -type f -exec sed -i -e 's/old-string/new-string/g' {} \;

# find and copy files
find . -name '*.tif' -type f -exec cp {} /data/geoserver/data/raster/ \;
