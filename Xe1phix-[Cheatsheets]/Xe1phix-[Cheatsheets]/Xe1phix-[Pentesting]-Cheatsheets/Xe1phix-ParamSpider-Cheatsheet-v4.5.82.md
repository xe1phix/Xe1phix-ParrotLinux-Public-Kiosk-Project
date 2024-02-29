- 

----
##   paramspider:

##  Discover URLs for a single domain:
paramspider -d example.com


##  Discover URLs for multiple
domains from a file:
paramspider -l domains.txt


##  Stream URLs on the termial:
paramspider -d example.com -s


##  Set up web request proxy:
paramspider -d example.com --proxy '127.0.0.1:7890'



##  Adding a placeholder for URL 
##  parameter values (default: "FUZZ"):
paramspider -d example.com -p '"><h1>reflection</h1>'