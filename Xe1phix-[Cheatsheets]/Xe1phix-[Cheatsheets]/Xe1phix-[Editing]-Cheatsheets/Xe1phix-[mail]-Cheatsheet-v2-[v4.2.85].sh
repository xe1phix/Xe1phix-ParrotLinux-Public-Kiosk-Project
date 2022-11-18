# send an email from command line
mail -s “Hello world” you@youremailid.com
echo “This will go into the body of the mail.” | mail -s “Hello world” you@youremailid.com
df -h | mail -s “disk space report” calvin@cnh.com
