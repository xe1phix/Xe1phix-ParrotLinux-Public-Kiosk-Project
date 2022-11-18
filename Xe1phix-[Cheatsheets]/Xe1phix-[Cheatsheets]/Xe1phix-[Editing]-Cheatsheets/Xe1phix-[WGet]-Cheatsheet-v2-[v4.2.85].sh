#specify directory and rename the file
wget --output-document="/home/my_new_file_name" http://someurl
#add the appropriate BeeGFS repositories
wget -o /etc/yum.repos.d/beegfs-rhel7.repo http://www.beegfs.com/release/beegfs_2015.03/dists/beegfs-rhel7.repo
wget -q https://www.virtualbox.org/download/oracle_vbox.asc -O- |  apt-key add -

wget example.com/big.file.iso  #start download and stop download ctrl+c key pair
wget -c example.com/big.file.iso  #resume download 

wget ‐‐continue example.com/big.file.iso #Resume an interrupted download previously started by wget itself
wget ‐‐continue ‐‐timestamping wordpress.org/latest.zip #Download a file but only if the version on server is newer than your local copy
wget ‐‐page-requisites ‐‐span-hosts ‐‐convert-links ‐‐adjust-extension http://example.com/dir/file #Download a web page with all assets - like stylesheets and inline images - that are required to properly display the web page offline.
wget -q  http://somesite.com/TheFile.jpeg #-q: Turn off wget's output
wget http://example.com/images/{1..20}.jpg # Download a list of sequentially numbered files from a server
wget -m -r -linf -k -p -q -E -e robots=off http://127.0.0.1 # Download a complete website
wget ‐‐mirror ‐‐domains=abc.com,files.abc.com,docs.abc.com ‐‐accept=pdf http://abc.com/ #Download the PDF documents from a website through recursion but stay within specific domains.
wget ‐‐execute robots=off ‐‐recursive ‐‐no-parent ‐‐continue ‐‐no-clobber http://example.com/ #Download an entire website including all the linked pages and files
wget ‐‐level=1 ‐‐recursive ‐‐no-parent ‐‐accept mp3,MP3 http://example.com/mp3/ #Download all the MP3 files from a sub-directory
wget --recursive --no-clobber --page-requisites --html-extension --convert-links --restrict-file-names=windows --domains some-site.com --no-parent www.some-site.com #Download Entire Website
wget ‐‐recursive ‐‐no-clobber ‐‐no-parent ‐‐exclude-directories /forums,/support http://example.com #Download all files from a website but exclude a few directories
wget --reject=png www.some-site.com #Reject file types while downloading
wget -r -A .pdf http://some-site.com/ #Download all PDF files from a website
wget -r -H --convert-links --level=NUMBER --user-agent=AGENT URL #Download With Wget Recursively,declare a user agent such as Mozilla (wget –user-agent=AGENT)
wget -e https_proxy=xx.xx.xx.xx:8080 https://example.com/  #use proxy server with wget

wget -S --spider http://www.uniqlo.com/ #Only Header Information

##if link exists
url="https://www.katacoda.com/courses/kubernetes/launch-single-node-cluster"
if wget --spider "$url" 2>/dev/null; then #2> /dev/null silences wget's stderr output
  echo "URL exists: $url"
else
  echo echo "URL does not exist: $url"
fi

#connect to a remote server,start download on the remote server,disconnect from the remote server,let it run on the background
$ nohup wget -q url &  

wget -i file.txt #Read download URLs from a file,useful in a shell script.

#one liner if condition
wget --spider http://192.168.50.15/${distribution}_${codename}_oscap_report.html 2>/dev/null && echo "link exists" || echo "link does not exist"

wget --spider -S "www.magesh.co.in" 2>&1 | awk '/HTTP\// {print $2}' #see only the HTTP status code
wget --spider -o wget.log -e robots=off --wait 1 -r -p http://www.mysite.com/ #crawl a website and generate a log file of any broken links

wget --spider https://example.com/filename.zip 2>&1 | grep Length #file download size without downloading the actual file
wget ‐‐spider ‐‐server-response http://example.com/file.iso #Find the size of a file without downloading it (look for ContentLength in the response, the size is in bytes)

wget ‐‐output-document - ‐‐quiet google.com/humans.txt #Download a file and display the content on the screen without saving it locally
wget ‐‐server-response ‐‐spider http://www.labnol.org/ #the last modified date of a web page (check the LastModified tag in the HTTP header)
wget ‐‐output-file=logfile.txt ‐‐recursive ‐‐spider http://example.com #Check the links on your website to ensure that they are working. The spider option will not save the pages locally.
wget ‐‐limit-rate=20k ‐‐wait=60 ‐‐random-wait ‐‐mirror example.com # limited the download bandwidth rate to 20 KB/s and the wget utility will wait anywhere between 30s and 90 seconds before retrieving the next resource.
wget -O index.html  --certificate=OK.crt --private-key=OK.key https://example.com/ #Client SSL Certificate
wget -q -O - --header="Content-Type:application/json" --post-file=foo.json http://127.0.0.1 # POST a JSON file and redirect output to stdout
wget -O wget.zip http://ftp.gnu.org/gnu/wget/wget-1.15.tar.gz #Download file with different name
wget -o download.log http://ftp.gnu.org/gnu/wget/wget-1.15.tar.gz #redirect the wget command logs to a log file using ‘-o‘ switch.
wget ‐‐output-document=filename.html example.com #Download a file but save it locally under a different name
wget ‐‐directory-prefix=folder/subfolder example.com #Download a file and save it in a specific folder
wget -r -l inf -A .png,.jpg,.jpeg,.gif -nd https://jekyllrb.com # Download all images of a website
wget -r --level=1 -H --timeout=1 -nd -N -np --accept=mp3 -e robots=off -i musicblogs.txt #take a text file of your favourite music blogs and download any new MP3 files
wget --ftp-user=User --ftp-password=Mir URL # FTP download
wget http://ftp.gnu.org/gnu/wget/wget-1.15.tar.gz ftp://ftp.gnu.org/gnu/wget/wget-1.14.tar.gz.sig #Download multiple file with http and ftp protocol
wget -i /wget/urls.txt #Read URL’s from a file
wget -Q10m -i download-list.txt #Setting Download Quota
wget -c http://ftp.gnu.org/gnu/wget/wget-1.15.tar.gz #Resume download
wget -b /wget/log.txt http://ftp.gnu.org/gnu/wget/wget-1.15.tar.gz #Download files in background
wget -b -c --tries=NUMBER URL #number of tries (wget –tries=NUMBER), continue partial download (wget -c)
wget -b --limit-rate=SPEED -np -N -m -nd --accept=mp3 --wait=SECONDS http://www.uniqlo.com/ #no parent to ensure you only download a sub-directory (wget -np),update only changed files (wget -N), mirror a site (wget -m), ensure no new directories are created (wget -nd), accept only certain extensions (wget –accept=LIST) 
wget -c --limit-rate=100k  /wget/log.txt http://ftp.gnu.org/gnu/wget/wget-1.15.tar.gz #Limit download speed
wget --http-user=username --http-password=password http://some-network.net/some-file.txt #Options –http-user=username, –http-password=password
wget --ftp-user=username --ftp-password=password ftp://some-network.net/some-file.txt #–ftp-user=username, –ftp-password=password
wget --tries=75 http://ftp.gnu.org/gnu/wget/wget-1.15.tar.gz #Increase Retry Attempts.
wget ‐‐refer=http://google.com ‐‐user-agent="Mozilla/5.0 Firefox/4.0.1" http://nytimes.com #Wget can be used for downloading content from sites that are behind a login screen or ones that check for the HTTP referer and the User-Agent strings of the bot to prevent screen scraping.
wget ‐‐cookies=on ‐‐save-cookies cookies.txt ‐‐keep-session-cookies ‐‐post-data 'user=labnol&password=123' http://example.com/login.php_ _wget ‐‐cookies=on ‐‐load-cookies cookies.txt ‐‐keep-session-cookies http://example.com/paywall #Fetch pages that are behind a login page. You need to replace user and password with the actual form fields while the URL should point to the Form Submit (action) page.
wget ‐‐span-hosts ‐‐level=inf ‐‐recursive dmoz.org #
wget -r --level=inf -p -k -E --span-hosts --domains=domainA,domainB http://www.domainA #download an entire site (domain A) when its resources are on another domain, (domain B)
wget --page-requisites --convert-links --adjust-extension --span-hosts --domains domainA,domainB domainA #
wget --recursive --level=inf --page-requisites --convert-links --html-extension -rH -DdomainA,domainB domainA #
wget --recursive --level=inf --page-requisites --convert-links --adjust-extension --span-hosts --domains=domainA,domainB domainA #

