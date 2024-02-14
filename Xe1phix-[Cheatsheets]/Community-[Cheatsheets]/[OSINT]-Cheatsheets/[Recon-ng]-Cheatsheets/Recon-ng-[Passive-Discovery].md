
Passive Discovery

RECON-NG
URL
https://bitbucket.org/LaNMaSteR53/recon-ng
API key

http://ipinfodb.com/register.

[recon-ng][default] > workspaces add SUCK
[recon-ng][SUCK] > add domains suck.testlab
[recon-ng][SUCK] > add companies
company (TEXT): SUCK company
description (TEXT): Recon!
[recon-ng][SUCK] > use recon/domains-hosts/bing_domain_web
[recon-ng][SUCK][bing_domain_web] > run

------------
SUCK.TESTLAB
------------
[*] URL: https://www.bing.com/search?first=0&q=domain%3Asuck.testlab
[recon-ng][SUCK][bing_domain_web] > use recon/domains-hosts/google_site_web
[recon-ng][SUCK][google_site_web] > run

------------
SUCK.TESTLAB
------------
[*] URL: https://www.google.com/search?start=0&filter=0&q=site%3Asuck.testlab
[*] You've been temporarily banned by Google for violating the terms of service.
[recon-ng][SUCK][google_site_web] > run

------------
SUCK.TESTLAB
------------
[*] URL: https://www.google.com/search?start=0&filter=0&q=site%3Asuck.testlab
[*] You've been temporarily banned by Google for violating the terms of service.
[recon-ng][SUCK][google_site_web] > use recon/domains-hosts/baidu_site
[recon-ng][SUCK][baidu_site] > run

------------
SUCK.TESTLAB
------------
[*] URL: http://www.baidu.com/s?pn=0&wd=site%3Asuck.testlab
[recon-ng][SUCK][baidu_site] > use recon/domains-hosts/brute_hosts
[recon-ng][SUCK][brute_hosts] > run

[recon-ng][SUCK][brute_hosts] > use recon/domains-hosts/netcraft
[recon-ng][SUCK][netcraft] > run

[recon-ng][SUCK][netcraft] > use recon/hosts-hosts/resolve
[recon-ng][SUCK][resolve] > run

[recon-ng][SUCK][resolve] > use recon/hosts-hosts/reverse_resolve
[recon-ng][SUCK][reverse_resolve] > run

[recon-ng][SUCK][reverse_resolve] > use discovery/info_disclosure/interesting_files
[recon-ng][SUCK][interesting_files] > run

keys add ipinfodb_api [KEY]
[recon-ng][TM][interesting_files] > use recon/hosts-hosts/ipinfodb
[recon-ng][TM][ipinfodb] > run

[recon-ng][SUCK][interesting_files] > use recon/domains-contacts/whois_pocs
[recon-ng][SUCK][whois_pocs] > run

[recon-ng][SUCK][whois_pocs] > use recon/domains-contacts/pgp_search
[recon-ng][SUCK][pgp_search] > run

recon-ng][SUCK][pgp_search] > use recon/contacts-credentials/hibp_paste
[recon-ng][SUCK][hibp_paste] > run

[recon-ng][SUCK] > use reporting/html
[recon-ng][SUCK][html] > set CREATOR HP2
CREATOR => HP2
[recon-ng][SUCK][html] > set CUSTOMER HP2
CUSTOMER => HP2
[recon-ng][SUCK][html] > run
[*] Report generated at '/root/.recon-ng/workspaces/default/results.html'.

Discover Scripts
Installation (in Kali Linux)

git clone https://github.com/leebaird/discover.git /opt/discover
cd /opt/discover 
./update.sh

Spiderfoot
Installation

mkdir /opt/spiderfoot/
download http://sourceforge.net/projects/spiderfoot/?source=typ_redirect
pip install lxml netaddr M2Crypto cherrypy mako

Creating password lists
wordhound
Installation

https://bitbucket.org/mattinfosec/wordhound.git
apt-get install python-setuptools
python setup.py install
./setup.sh
----
git clone https://github.com/tweepy/tweepy.git /opt/tweepy/
cd /opt/tweepy/
python ./setup.py install
/usr/local/bin/pip install requests[security]
service ntp restart


Configuration

cd /opt/wordhound/
root@tw-samku-kali:/opt/wordhound# vim wordhound.conf.dist 
root@tw-samku-kali:/opt/wordhound# cp wordhound.conf.dist wordhound.conf

Before start

There is a bug in Main.py

Traceback (most recent call last):
  File "Main.py", line 333, in <module>
    main()
  File "Main.py", line 59, in main
    generation()
  File "Main.py", line 141, in generation
    industrySelected(options[choice])
  File "Main.py", line 167, in industrySelected
    generateCollatedDictionary(industry)
  File "Main.py", line 184, in generateCollatedDictionary
    lex = LE.lexengine("", "data/industries/"+industry+'/'+"CollatedDictionary.txt", False)
TypeError: __init__() takes exactly 3 arguments (4 given)

To make it work, you have to modify the line 184 to lex = LE.lexengine("data/industries/"+industry+'/'+"CollatedDictionary.txt", False)
Start

=== CLIENT OPTIONS ===

[+] Please choose an option:

1. Generate Dictionary from website.
2. Generate Dictionary from Text file.
3. Generate Dictionary from pdf.
4. Generate Dictionary from twitter search term.
5. Generate Dictionary from Reddit

6. Generate aggregate client dictionary.
1
[-] Please enter the URL of website to be crawled:
http://www.securepla.net

=== CLIENT OPTIONS ===

[+] Please choose an option:

1. Generate Dictionary from website.
2. Generate Dictionary from Text file.
3. Generate Dictionary from pdf.
4. Generate Dictionary from twitter search term.
5. Generate Dictionary from Reddit

6. Generate aggregate client dictionary.
4
[-] Please enter the search term:
hacking
How many tweets would you like to analyse?:(Default = 700) (Max = 700)
700
[+] Querying twitter for hacking
[-] Authorizing twitter API
[-] Twitter auth successful
[-] Retrieving search data
[-] Downloaded 100 tweets
[-] Downloaded 200 tweets
[-] Downloaded 300 tweets
[-] Downloaded 400 tweets
[-] Downloaded 500 tweets
[-] Downloaded 600 tweets
[-] Downloaded 700 tweets
[-] Extracted ~9787 words for processing and analysis
[-] Loaded blacklist
[-] Loaded corpus
[+] Would you like additional analysis to be done on gathered data in an attempt to build passphrases? (This can take a long time with big data sets 1> hour)
y or n:
n
[-] Preparing datastructures for analysis
[-] Done analysing text
[+] Beginning trim...
[-] 2490 unique words about to be processed
[+] Clarification needed:
I'm not sure if these words should be added to the dictionary. Press :
	'0' to skip all
	'1' to add all
	'y' to add word
	'n' to skip word.
jdgw
1
[+] Clarification needed:
I'm not sure if these are relevant phrases and should be added to the dictionary. Press :
	'0' to skip all
	'1' to add all
	'y' to add word
	'n' to skip word.
[=] DICTIONARY GENERATED [=]
Dictionary was successfully generated and saved to data/industries/TrendMicro/TrendMicro/TwitterSearchTermDictionary.txt
Press enter to continue...

BRUTESCRAPE
Installation

git clone https://github.com/cheetz/brutescrape.git /opt/brutescrape

Start

/opt/brutescrape# vim sites.scrape 
/opt/brutescrape# python brutescrape.py 

Using Compromised Lists
Adobe password checker

git clone https://github.com/cheetz/adobe_password_checker.git /opt/adobe_password_checker

Possible source (Adobe)

https://leakforums.net/thread-186150 https://www.reddit.com/r/hacking/comments/1sfwiz/anyone_have_userstargz_from_adobe_leak/
Gitrob
Installation

git clone https://github.com/michenriksen/gitrob.git /opt/gitrob
root@tw-samku-kali:/opt/adobe_password_checker# gem install bundler
Fetching: bundler-1.10.6.gem (100%)
Successfully installed bundler-1.10.6
Parsing documentation for bundler-1.10.6
Installing ri documentation for bundler-1.10.6
Done installing documentation for bundler after 14 seconds
1 gem installed
/opt/adobe_password_checker# service postgresql start
opt/adobe_password_checker# su postgres
postgres@kali:/opt/adobe_password_checker$ createuser -s gitrob --pwprompt
Enter password for new role: 
Enter it again: 
postgres@kali:/opt/adobe_password_checker$ createdb -O gitrob gitrob
postgres@kali:/opt/adobe_password_checker$ exit

start

./gitrob --configure
Do you agree to the terms of use? [y/n]: y
 [*] Starting Gitrob configuration wizard
 Enter PostgreSQL hostname: |localhost|  
 Enter PostgreSQL port: 
 Enter PostgreSQL username: gitrob
 Enter PostgreSQL password for gitrob (masked): xxxxxxxx
 Enter PostgreSQL database name: |gitrob| 
 Enter GitHub access tokens (blank line to stop):

Result

[*] Browse to http://127.0.0.1:9393/ to see results!
Pages 8

Home
Active Discovery
Binary Exploitation
Exploitation
Metasploit
Passive Discovery

    RECON-NG
    URL
    API key
    Discover Scripts
    Installation (in Kali Linux)
    Spiderfoot
    Installation
    wordhound
    Installation
    Configuration
    Before start
    Start
    BRUTESCRAPE
    Installation
    Start
    Using Compromised Lists
    Adobe password checker
    Possible source (Adobe)
    Gitrob
    Installation
    start
    Result

Shell Code

    Vulnerability Scanning

Clone this wiki locally


