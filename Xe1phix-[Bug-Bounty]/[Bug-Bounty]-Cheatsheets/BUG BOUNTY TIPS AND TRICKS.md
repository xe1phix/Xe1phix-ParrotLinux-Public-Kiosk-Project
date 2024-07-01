Bug Bounty Tips:-
This is a collection of all published bug bounty tips on this page that I collected from the bug hunting community on Twitter, sharing their tips and knowledge to help all of us to find more vulnerabilities and collect bug bounties.

Hope you will find it useful!

____________________________________________________
Table Of Contents:

OSINT / Recon:-
      Finding subdomains
      Asset and content discovery
      Fingerprinting
      Data extraction
      Sensitive information

Looking for vulnerabilities:-
       Broken access control (BAC)
       Cross Site Scripting (XSS)
       Server Side Request Forgery (SSRF)
       Local / Remote File Inclusion (LFI / RFI)
       Injection (SQL, RCE..)
       Open redirect
       File upload

Tricks and Techniques:-
       Account takeover
       403 / 401 bypass
       Fuzzing tips
       Other useful tips
____________________________________________________


•••OSINT / Recon•••

•Finding subdomains:-
 – Finding subdomains
 – Curl + parallel one-liner
 – Find subdomains with SecurityTrails API
 – Find related domains via favicon hash
 – Find subdomains using RapidDNS
 – A recon tip to find more subdomains (Shodan)
 – Find subdomains using ASNs with Amass

•Asset and content discovery:-
 – Access hidden sign-up pages
 – Find hidden pages on Drupal
 – Find Spring Boot servers with Shodan
 – Forgotten database dumps
 – Find RocketMQ consoles with Shodan
 – Fuzz list for GIT and SVN files
 – Generate content discovery wordlist from URI
 – HTTP recon automation with httpx
 – Web servers on non-standard ports (Shodan)
 – Keep track of attack surface with Amass
 – Easy information disclosure with httpx
 – Find Kubernetes with Shodan
 – OneListForAll – “Rockyou” wordlist for web fuzzing
 – List of 24 Google dorks for bug bounties

•Fingerprinting:-
 – Find out what websites are built with
 – Fingerprinting with Shodan and Nuclei engine
 – Database of 500 Favicon hashes (FavFreak)
 – Calculate favicon hash value for favicon recon

•Data extraction:-
 – Use grep to extract URLs
 – Extract information from APK
 – Find javascript files using gau and httpx
 – Extract API endpoints from javascript files
 – Extract endpoints from APK files
 – Find JavaScript files with httpx and subjs
 – Unpack exposed JavaScript source map files
 – Full-featured JavaScript recon automation (JSFScan.sh)
 – Useful regex for subdomain level extraction

•Sensitive information:-
 – Top 5 bug bounty Google dorks
 – Find sensitive information with gf
 – Find sensitive information with AlienVault OTX
 – Find database secrets in SVN repository
 – GitHub dorks for finding sensitive information
 – Sensitive data leakage using .json
 – Easy wins with Shodan dorks
 – Find access tokens with ffuf and gau
 – GitHub dorks for finding secrets
 – Use Google cache to find sensitive data
 – Phpinfo() with sensitive information
 – Recon leading to exposed debug endpoints
 – List of 14 Google dorks for recon and easy wins
 – GitHub dorks for AWS, Jira, Okta .. secrets
 – List of 9 tools for identifying sensitive information

•••Looking for vulnerabilities•••
 – Heartbleed vulnerability
 – Scanning at scale with Axiom
 – Top 20+ Burp extensions for bug bounty hunting
 – Find web servers vulnerable to CORS attacks
 – List of 12 Android security testing tools
 – Scan Jira for known CVEs and misconfigurations
 – Search for CVEs of specific year with Nuclei

•Broken access control (BAC):-
 – JWT token bypass
 – From employee offers to ID card
 – Trick to find more IDOR vulnerabilities
 – Multi-factor (2FA) authentication bypass
 – How to find access control bugs

•Cross Site Scripting (XSS):-
 – Simple XSS check
 – Javascript polyglot for XSS
 – Tiny minimalistic XSS payloads
 – Find hidden GET parameters in javascript files
 – XSS payload as an image filename
 – Bypass WAF blocking “javascript:” in XSS
 – Simple reflected XSS scenario
 – XSS firewall bypass techniques
 – List of 25 tools for detecting XSS
 – Find XSS in Java applications in Boolean values
 – XSS payload in an XML file

•Server Side Request Forgery (SSRF):-
 – SSRF payloads to bypass WAF
 – Top 25 server-side request forgery (SSRF) parameters
 – SSRF Bypass list for localhost (127.0.0.1)

•Local / Remote File Inclusion (LFI / RFI):-
 – Top 25 local file inclusion (LFI) parameters
 – Browser-based application LFI via view-source
 – Turning LFI to RCE in PHP using ZIP wrapper

•Injection (SQL, RCE..):-
 – E-mail address payloads
 – Top 25 remote code execution (RCE) parameters
 – Valid email addresses with evil payloads
 – Directory traversal payloads for easy wins
 – Bypass email filter leading to SQL injection (JSON)
 – Tests for identifying SQL injections 100%
 – Test your SQL injections in an online sandbox database
 – Find SQL injections (command combo)

•Open redirect:-
 – Top 25 open redirect dorks
 – Find open redirect vulnerabilities with gf
 – List of 48 open redirect parameters from HackerOne

•File upload:-
 – Top 10 what can you reach in case you uploaded..
 – Handy extension list for file upload bugs
 – Chaining file uploads with other vulns
 – WAF bypass during exploitation of file upload

•••Tricks and Techniques•••
 – HTTP Accept header modification
 – HTTP Host header: localhost
 – Price manipulation methods
 – Bypass Rate limits by adding X- HTTP headers
 – Search for interesting parameters with gf
 – How to quickly identify session invalidation issues
 – WAF bypass using globbing
 – Search for login portals and default creds
 – Bypass WAF with Unicode characters

•Account takeover:-
 – Account takeover by JWT token forging
 – Account takeover by reset token disclosure (Burp)
 – Account takeover using secondary email in password reset
 – Password poisoning bypass to account takeover
 – Mass account takeover via BAC

•403 / 401 bypass:-
 – Access Admin panel by tampering with URI
 – Bypass 403 Forbidden by tampering with URI
 – How to find authentication bypass vulnerabilities
 – Trick to access admin panel by adding %20
 – Tips on bypassing 403 and 401 errors
 – Bypass 403 errors by traversing deeper
 – Automated 403 Forbidden bypasser tools

•Fuzzing tips:-
 – Simple ffuf bash one-liner helper
 – Generate custom wordlist from any domain
 – Burp Intruder without licensed Burp Pro (ffuf)

•Other useful tips:-
 – Extract zip file remotely
 – Filter out noise in Burp Suite
 – Mirror a web directory structure
 – How to become a bug hunter
 – Open arbitrary URL in Android app
 – Intercepting traffic on iOS13 in Burp Suite
 – Get scope of Bugcrowd programs in CLI
 – GraphQL notes for beginners
 – Prevent accidental copy & paste errors in terminal
 – Top 20 search engines for hackers

••••••••••••••••••••••••••••••••••••••••••••••••••••
••••••••••••••••CREDIT: CyberXsociety•••••••••••••••
••••••••••••••••••••••••••••••••••••••••••••••••••••
|•JOIN OUR COMMUNITY FOR MORE INTERESTING TIPS AND TRICKS•|

⟁ OFFICIAL ANNOUNCEMENT GROUP ⟁
⪼ https://chat.whatsapp.com/GS1UER7oFqqF0XkSgU1YuB

⟁ TELEGRAM CHANNEL ⟁
⪼ https://t.me/CyberXsociety

⟁ LINKEDIN ALL ABOUT HACKING/BUG HUNTING KNOWLEDGE ⟁
https://www.linkedin.com/groups/14191320
