# Login panel search
site:target.com inurl:admin | administrator | adm | login | l0gin | wp-login

# Login panel search #2
intitle:"login" "admin" site:target.com

# Admin panel search
inurl:admin site:target.com

# Search for our target's exposed files
site:target.com ext:txt | ext:doc | ext:docx | ext:odt | ext:pdf | ext:rtf | ext:sxw | ext:psw | ext:ppt | ext:pptx | ext:pps | ext:csv | ext:mdb

# Get open directories (index of)
intitle:"index of /" Parent Directory site:target.com

# Search for exposed admin directories
intitle:"index of /admin" site:target.com

# Search for exposed password directories
intitle:"index of /password" site:target.com

# Search for directories with mail
intitle:"index of /mail" site:target.com

# Search for directories containing passwords
intitle:"index of /" (passwd | password.txt) site:target.com

# Search for directories containing .htaccess
intitle:"index of /" .htaccess site:target.com

# Search for .txt files with passwords
inurl:passwd filetype:txt site:target.com

# Search for potentially sensitive database files
inurl:admin filetype:db site:target.com

# Search for log files
filetype:log site:target.com

# Search for other sites that are linking to our target
link:target.com -site:target.com