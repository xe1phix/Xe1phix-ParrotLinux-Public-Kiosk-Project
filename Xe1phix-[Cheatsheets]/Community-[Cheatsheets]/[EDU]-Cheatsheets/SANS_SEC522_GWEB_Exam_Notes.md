https://www.databreaches.net/ -> Office of inadequate security: Contains list of web app breaches
Web App Attacks & Trends: Random hacking (continuous scans, followed by manual hacks) | Targeted hacks (Focused attack on specific targets)

Four hacking steps: Reconnaissance -> Mapping (relationship between hosts, or maps app pages and resources in a site) -> Discovery (vulnerability identification or scanning phase) -> Exploitation
-	Some steps could be skipped during random hacking

# Recent attack trends:
Compromise websites as stepping stone to collect info for bigger attack (building a profile of various attacked web site vulns; use it later for precision hacks or just sell it for money, use compromised creds on other sites), Web API hacks (Authn & Access control are most common problems), Cryptomining (agent put on compromised web server for mining purpose, inject JS code to mine currency from client’s browser, Coinhive is the top malicious threat to web users), Creds stuffing (Automated brute force attacks with compromised creds e.g. from https://haveibeenpwned.com/)

HTTP 1.1 –> RFC 7230 – 7235 (better organized version of originally very long RFC 2616) / Client – Server architecture
-	Innovated in Switzerland!
HTTP request and response separated by a blank line.

# HTTP Request fields:
-	Host: Name based virtual hosting where one single IP could resolve to multiple websites of different names
-	Referer: Inform the server on how the client has been led to this resource
o	Some proxy servers might remove this header | Not a security feature, can be forged
o	By default, only sent over same protocol (HTTP -> HTTP OR HTTPS -> HTTPS)
o	Referrer Policy: Meta tag within HTML to control behavior (<meta name=”referrer” content=”origin”>) OR as HTTP header (Referrer-Policy: origin) | Widely supported by browsers | Set by site owners.
-	Accept-Language
-	User-Agent: Browser, version, OS | Servers use to distinguish search engine robots & humans | Can be spoofed
-	Accept-Encoding (compression): gzip, deflate is the de facto standard for HTTP content | Saves bandwidth | Effects how content looks on wire | Server checks this request header and sends compressed content
o	Transfer-Encoding: chunked (data sent in small chunks, server sends it whenever available, finally sends zero-sized chuck to indicate the communication is over, Content-Length header is not sent with this, used in Netflix, Amazon prime, etc.)

# HTTP Response fields:
-	Date: timestamp of the response from server (if it is in 2nd line of headers, the server is Apache for sure)
-	Content-Length: Length of message body of the response from server
-	Connection: Indicates a message to client from server on closing the persistent application HTTP connection
-	Content-Type: Content type of info in response body and encoding standard used
-	Accept-Language | Accept-Encoding | Pragma (no-cache)
Response body can contain any data (HTML, ZIP file, MP3, JavaScript, JPG, GIF, etc.) | MIME-Type (Content-Type) informs the client browser how to handle the data

HTTP GET: Request or retrieve contents of the specific URI | POST: Submit data to process on server side (not cached in browser) | HEAD: Similar to GET but to only obtain response header information (without response body), often used to check page modification time | OPTIONS: Returns supported methods by server, often used for fingerprinting. Also used to communicate access control requests & decisions in cross-domain requests | DELETE: remove a resource from server | PUT: Upload files or resources to server | TRACE: Testing purpose, echo back request body, client examines whether server modify it or not OR if there are any proxies in between (No longer supported) | CONNECT: Used to establish tunnel (like SSL) | PATCH: Used in REST API to update partial portion of existing HTTP resource (RFC 5789) 
-	According to RFC, servers must support GET and HEAD (as mandatory) (However, POST is also supported)

WebDAV: Web based distributed authoring and versioning, set of extensions to HTTP. Designed to update websites and perform content management. Implemented by MacOS and Win 98. Security issues. Need to separate management interface from the content itself.
-	More HTTP methods added for update functionalities; Often disabled in modern days; PROPFIND, PROMATCH, MKCOL, COPY, MOVE, LOCK, UNLOCK
-	Microsoft adopted it later

URL: protocol://host:port/path/?query                    (path: location of resource on server)

HTTP Response codes: 1xx: Information codes (used to pass info to browser e.g. continue with next request, server has not rejected old request; 101 is notice to browser about switching protocols e.g. from HTTP to WebSocket or upgrading protocols e.g. HTTP 1.1 to HTTP 2.0) | 2xx: Success | 3xx: Redirection (to another URL to another connection method, 302 common) | 4xx: Client error (404 is common, resource not found) | 5xx: Server error

# HTTP 2.0 (RFC 7540)
-	Backward compatible with HTTP 1.1
-	Single TCP connection, TLS only (no cleartext exchange is allowed in the protocol), TLS ALPN to auto-enable (no additional rounds during initial handshake, part of TLS handshake), Server determines which protocol to use.
-	Started out as SPDY by Google in 2009, using multiplexing (streaming of data)
-	Supports compression (both header and body)
-	Efficiency is key in HTTP 2.0 | Binary protocol (w/ flow control), conversations are segmented into frames. Inside frames, HTTP 1.1 style headers still exist | HPACK header compression (perf similar to zlib) | CRIME attack proof | Differential encoding (avoid sending repeated headers to destination) and Huffman encoding (compress data at binary sequence level) | Server push (server sends data to client without client requesting it)
o	Server push: Uses preload W3 syntax; </app/script.js>; rel=preload; as=script | Optional to push
	If server doesn’t push, client can preload / can make request to download
-	Needs wireshark to decode the exchanges, not in clear-text anymore

# HTTP 3.0 (QUIC, Quick UDP Internet Connection)
-	Replacing TCP; Works on existing infra (UDP 80, 443); Always encrypted as protocol negotiation; TLS 1.3 by default.

# HTTP Basic Authentication: RFC 7235 | Supported by every browser and proxy server
-	Username and password are BASE64 encoded (RFC 2045) (Mostly used by MIME to transfer binary data over SMTP)
o	Perl, C, Java		| username and password are joined by a semi-colon (:) before encoding is done.
-	If used over SSL, passwords are encrypted at transport layer
-	HTTP Response header set by server for initial login pop-up: WWW-Authenticate: Basic realm="SEC522 Protected Area"
o	HTTP/1.1 401 Unauthorized
o	Realm defines separate authentication zones within a server or DN; A visual key for user to know which ID to use
-	HTTP Request header set after initial authentication on pop-up: Authorization: Basic c3R1ZGVudDphc2ltcGxlcGFzc3dvcmQ=
-	Account lockout implementation to avoid brute force is not possible

# HTTP Digest Authentication: RFC 2617 | Supported by all browsers; Designed to address security issues in Basic authentication; 
-	Passwords are NOT sent on the wire | Based on challenge-response authentication | Uses MD5 hashes
-	Server response: WWW-Authenticate: Digest realm=”SEC522 Protected Area”, nonce=”Ny8yLzIwMD”, opaque=”0000”, stale=false, algorithm=MD5, qop=”auth”
o	Nonce prevents replay attacks; opaque is string client returns in same realm; Stale is a flag to report repeated nonce;
o	Quality of Profile (qop) is optional, indicates authentication or integrity or both is provided by header; 
	Backward compatibility with RFC 2069
-	Client response: Authorization: Digest username=”Vasu”, realm=”SEC522 Protected Area”, qop=”auth”, algorithm=MD5, uri=”/restricted.html”, nonce=”Ny8yLzIwMD”, nc=0000001, cnonce=”c515kjgfyj”, opaque=”0000”, response=”afa30c6” 
o	nc(nonce count): Incremented by 1 to prevent replay with each HTTP request/reply pair
o	response=hash(username+realm+password+nonce+cnonce)
-	Account lockout implementation to avoid brute force is not possible

Certificate Authentication: Works with most modern browsers | Both client and server own certs signed by CA | Two-way | Transparent to user after setup | Most secure when combined with multifactor authentication methods
-	SSL is one-way authentication (client verifies the server identity)

Integration Windows Authentication: Windows server and clients only | Uses Kerberos or NTLM | Doesn’t work via HTTP proxies | Both server and client are in same or trusted domains
-	The only proxies that works with IWA are Microsoft ISA & Squid (NTLM only).
-	Integration with Active Directory, so one set of creds even for web applications after windows login
-	NTLM is similar or even less secure than Digest authentication

Form-based Authentication: Creds are entered on HTML form, Not standards based but developer friendly, best user experience. 
-	Authentication can be password, pin, token, account number, date of birth, etc. Stored in LDAP directory, file or SQL database.

Access Control: Comes after authentication; Also known as Authorization; Dynamic nature of web apps makes it difficult for access control.

HTTP is stateless: Session IDs regulate access to one or more websites. Identify authenticated users; Provide identity for authorization; Leverage a database to store user data.
-	Set-Cookie: color=red (server to browser)
-	Cookie: color=red (browser to server)
o	Parameters: Name, Value, Expiration, Domain (e.g. gemalto.com), Path (e.g. /files), Secure, HttpOnly, SameSite (determines whether cookie is sent with cross-origin requests)
o	HTTP/2 Wireshark capture (request and response headers): 

# BOOK-1:  Architecture and Defense-in-Depth
-	Presentation tier (in DMZ, Web servers like IIS, Apache, Nginx | Directly communicates with client | Collects user input and presents output in HTML, data processing here is limited) | Application tier (Internal n/w, Brain, App servers like JBoss, Tomcat) | Persistent tier (Storage like DB2, MSSQL, MySQL)
o	Two-tier web application: very simple, all eggs in one basket, Difficult to lock down web servers, scalability is an issue, Isolation
o	Three-tier web application: Complex, Physical separation between tiers, Firewall and IDS possible, Access control between layers (users -> web server -> app server -> database)
	WAF can be deployed in both 2 tier and 3 tier to inspect Cookies, Known attacks, RFC compliance, etc.
•	WAF examples: KaVaDo InterDo, Sanctum WebShield, Teros Secure Application Gateway
o	N-tier web application: More than 3 tiers; Physical & logical separation between tiers; WAF possible at multiple layers; Strong separation of developer duties (users -> web server -> app server -> Data access (broker) -> database)
	Often multiple database (hardware & vendor level) at data tier
	Data access (or broken) is vendor neutral, database-neutral API, converts data from databases into XML (or other forms for applications to read / process it). E.g. Hibernate, Castor (object relational mapping) or inhouse built XML Web service solutions are common methods of data access layer
	Application tier or Business tier provides all app specific functionality such-as rules-engine processing, financial number data crunching, tax computation, rounding rules, credit card authz, etc. Enterprise Java Bean, and Web Services are common application tiers.
	Client tier or presentation tier has no data process; user interacts with this tier; no business logic here; Can use AJAX, Flash, etc. but only to present data to users. 

Single Page Application (SPA): 
-	Puts presentation duties (logic and code) into the browser at first page load. Later does API calls directly to application server.
-	Improves user experience; Reduces latency; Often in JavaScript; 
-	No full URL reload | URL doesn’t change even when user interacts with application with screen refreshed many times

Microservices Architecture: Collection of loosely coupled services; Services are business capabilities; Independently deployable;
-	Users -> microservices -> database

Container Architecture: Shared base OS environment; high efficiency; Container runtime manages isolation between contains;
-	Teamed with orchestration, easy to build cluster of containers to scale and achieve fault tolerance
-	Enables rapid development, easy to test and validate

Serverless Architecture: Focus on functions, not on infrastructure; Assemble offering from multiple vendor functions; Highly scalable but vendor dependent.
-	Users -> Authn service | Static content bucket (block storage) | API gateway -> service processing code

Web Proxy: Reasons to use: Filter based on policies, Caching, Authn, Manipulation; Proxies can be impl on different physical n/w.
-	X-Forwarded-For is the common header added by web proxies

Web App Firewall (WAF): Detection & Prevention; Deep inspection into HTTP; Advanced WAF also monitors app stack; validates user inputs, length, data type, range of values, etc., Can track user sessions, detect tampering, rate limiting (slowing down denial of service or brute force attacks).
-	Works by assembling the traffic stream and data representations; Can be both network based and application based firewall or both in single device. 
-	Virtual Patching:  Quick fix in live production system without any code changes in application
-	Logging & Monitoring: Logging HTTP can drain server resources; can offload logging tasks, when out of resources
Load Balancer: Can use multiple algorithms (round-robin, DNS round-robin, traffic volume-based, etc.) to decide which server gets the traffic; can load balance across geo locations; single point of failure (hence needs redundancy); 

Firewall is a three-legged design: Protects internal network and DMZ at same time.

Web Proxies (reverse proxy) or WAF can add custom HTTP response headers (page level/URL level or site level).

# BOOK-1:  Web Infrastructure Security
Insecure configuration for platforms: OS and server security, Unnecessary services or components, service isolation, cloud component configuration, service accounts & permissions

Directory browsing: Works when default index.html file doesn’t exist and directory browsing is turned ON at server side. Can be enabled per-directory or per-site basis, so hard to hunt down, as config needs to be checked for every directory. /image or /scripts are vulnerable to directory browsing.
-	Mitigation techniques: Apache (For each directory, in Options config, -Indexes to be set; Local configuration cannot override global configuration; Also In AllowOverride config, -Indexes must be included) | IIS (At Directory permission pane) | Nginx (by default turned off; explicitly turned off as well using autoindex off directive)
o	An empty index.html file can be added to all directories and sub-directories as a defense-in-depth 
	$find $document_root --type --d --exec touch{}/index.html              //can add the html file into all directories

Note: .htaccess file can be used to override global settings in Apache
Tools to test Directory Browsing: Wikto, OWASP DirBuster, w3bfukkor, web spiders

Data leaks: Google search by: Index of /.git or Index of /.svn will provide all sites with git files exposed.
-	Mitigation techniques: Periodically audit web directory; turn on access time on file systems to see files in use; remove code comments; Avoid putting .git or .svn files in web directory; 
-	Testing: Use fil enumeration tools to find backup files in web directories (ZAP or Burp)

Sharing storage devices is a security risk. 
Isolation: Share SAN (Fiber channel, iSCSI) or NAS in internal network

In 2009, Twitter admin interface was hacked by Hacker Croll as internal employee was using Yahoo email to login. Admin interface was using BASIC authentication over HTTPS in 2009 year.

# BOOK-1:  NoSQL databases
Features: 
-	Simple table-based key-value database (Berkeley DB) | Large tables (Hadoop) | Accessed as REST and stored as JSON (Elasticsearch, MongoDB); Database like Memchached is to store volatile sessions that don’t survive a reboot of system
-	By default, authentication is not enabled; Some require proxies for authn; By default, all authn users have access to everything
-	No logs for some and others require proxies to log
-	Required tools like Stunnel for encryption (hit-&-miss, when TLS is built into NoSQL DB)
o	Very few DB provide data level encryption; mostly file level encryption (but it doesn’t work for in-memory data)

Best practices:
-	Stay up to date; Configure authn correctly (w/ SSO like HBase or Kerberos); Auditing requires additional s/w

To view AWS instances that are public: aws> ec2 describe-snapshots –no-paginate

# BOOK-1:  Vulnerability Scan
Docker image or repository scan: Twistlock, Anchore, Clair, Aqua MicroScanner, Dagada

3rd party components / packages could undergo typosquatting (attackers attacking package managers). Indirect dependency (dependents of dependents) are mostly vulnerable.

Secure configuration templates:
~30+ security settings per host | NIST SP800-70 (Checklist Program) | CIS Benchmarks

Ansible (Redhat): YAML based playbook w/ lots of extensions (Windows, Docker, VMWare, GitHub, etc.)
OSQuery (Facebook): SQL-like queries (over TLS on specific TCP port) on system configuration; monitor current config (OS, file integrity, process, etc.) and changes over time;  
-	Can send logs to central server
-	In large networks, required Fleet Manager product for data collection and manage large swamp of machines
o	Kolide, Doorman, DarkBytes, Zentral
-	SELECT * FROM logged_in_users
-	SELECT DISTINCT process.name, listening.port, process.pid FROM processes AS process JOIN listening_ports AS listening ON process.pid = listening.pid WHERE listening.address = ‘0.0.0.0’;
o	Shows listeninig service’s process name, PID, and ports they are listening on.
Commands:
-	$sudo osqueryi
-	$.tables
-	$select command,path from crontab;
-	$select user from logged_in_users where tty=’:0’;
-	$.quit

Cloud Security:
-	We ensure security of: Data, Identity management, server-side encryption, firewall ruleset.

CloudFormation: JSON or YAML config templates; predictable provisioning and updating resources with version control
AWS Config: Detailed view of AWS account; Continuous monitoring; 
-	Alternatives: Trusted Advisor, Azure Advisor, Security Monkey

# BOOK-2:  Authentication & Password management
Database Authentication Credentials:
1.	Put creds into a static variable in a file (in directory outside web directory) e.g. /var/www/creds, if app is /var/www/app
2.	Set environment variables: SetEnv DB_USER “myuser” and SetEnv DB_PASS “mypass”
a.	Then use the INCLUDE keyword in Apache to load the file with creds
3.	.NET applications can use web.config file (protected by default in IIS). Web.config can be encrypted in shared host env
a.	<configuration><connectionStrings><add name=”DBConnection” connectionString=”Data Source=localhost; Initial Catalog=DB; User Id=myuser; Password=mypass” /></connectionStrings></configuration>

General Secrets management in Applications:
-	Have a secrets manager software (external to application) that can dynamically interact with application by need
o	Cloud and hybrid solutions exist
	Vault, Google Cloud KMS, Chef Vault, AWS Secrets Manager, Azure Key Vault
o	By remote API call or function call (lib provided by vendor)
o	2 problems solved: no hard coding of secrets in app + granular control on access
o	Rotation of keys is automatically managed by products 
In Java:
-	Symmetric encryption of DB creds to store on disk
-	Use JNDI
-	Oracle supports proxy mode (web app -> proxy /w certificate authn -> DB) | machine to machine to authentication

Use of standard Login API, reuse code.

With runtime analysis (DAST), reveal hardcoded passwords using brute force tools for standard weak passwords.
-	https://cirt.net/passwords and http://www.defaultpassword.com/
-	Brute force tools: Brutus (basic & digest authn, Windows based) (& Hydra for Unix) and Crowbar (form authn)
o	J-Baah (Brute force tool by Sensepost, for form-based authn): Works by likeness (all authn failures vs different ones)

Account lockout: PCI DSS requires app to lock out the user (for at least 30 min or until manually unlocked) after six (6) unsuccessful attempts.
-	Alternative to lock outs: Delay in login attempts | Alert on high number of login failures | Put password failure message as HTML comments in case of successful login attempt (to bypass bots) | CAPTCHA after one or two failed attempts
-	Short term fix: Rate limit, brute force detection, WAF rules to block specific source IP/client/user/etc.
o	E.g. allow only 5 login attempts on a URL from a specific client / host

Known bad IPs: XBL (Spamhaus), malwaredomains.com, RBN bad subnet list, and the TOR exit nodes list. 
IP History: somewhat more accurate. Initiatives to share bad IPs among the industry. Previously offending IPs.
Geolocation mapping: Isn’t exact all the time; can easily flag user logged in from another country.
Time-based detection: If user logged in within a fraction of second after loading the login page, then suspicious! (telltale sign), unless the user is caching the creds on client PC.
Referrer tag detection: might assist in isolating the odd-looking requests. E.g. Login request doesn’t contain referrer tag, its wrong.
Sequence of events: User didn’t load the login page but creds submitted. Suspicious!

Behavior detection: day/time of login, sudden spike in transaction details
-	Leads to human verifications
-	Disable high-risk operations in the application or notify the user (mail, phone, etc.)

Per transaction or per operations authentication: sign the actual transaction; MITM would be difficult if 2-factor auth is impl for every high-risk functionality

Use of hidden token on login page negates the attempt of brute forcing credentials.

Credential stuffing: reusing billions of exposed creds found online from multiple data breaches. An assumption that small portion of username or password combinations could match.

# BOOK-2:  Multifactor Authentication
Time-based token (RSA, every 60 sec as example) | Per-use token (keypad) | Out-of-band channel (phone) | Challenge-response token (future preferred).
-	Two factor authn stops trojan attacks to login
-	Phishing for victim’s creds is possible even with 2FA (victim access phishing site). Attacker can be MITM, like a proxy, and send that info to service.
o	So, 2FA doesn’t prevent MITM

TOTP (Time based OTP): RFC6238: Password is valid only for certain duration of time.
HOTP (HMAC-based OTP): RFC 4226: User triggers a new password to be generated, every time a password is required for authn. 
TOTP and HOTP are both software and hardware based tokens / open standards / interoperable.

OATH vs Google’s OTPAuth: Difference is in secret exchange between server and token.

Benefit of open-standard OTP tokens:
-	Free or low cost | easy to enroll | one soft or hard token for multiple sites | An app of mobile device (e.g. Authy) | high user acceptance | works in conjunction with password
-	URI (user@server?secret=xxxx) is encoded into the QR code  secret seed into the authenticator app.

Password-less authentication: Sending links to email or via SMS to validate the user (dependent on the pre-arranged device like mobile phone and user’s knowledge of user ID).
-	Fast Identity Online (FIDO): FIDO2 standard = WebAuthn (W3C standard, browser-to-server, asymmetric crypto authn, JavaScript written) and CTAP (Client To Authenticator protocol) (between authenticators w/ pin and browser) (physical or software token, gesture or biometric)
o	WebAuthn registration: User attempts to enroll for creds on application (i.e. relying party), which sends JS to user’s browser to generate key pair. Browser generates it and sends public key to the application.

 Sample JS code:
challenge=random string to avoid replay attacks
rp = relaying party (website) with name and host
public key cred params: alg= -7 indicates ECC with SHA256 for signature
authenticatorSelection=platform restriction (cross-platform like 
   Falcon or YubiKey; or platform specific like Windows Hello or Touch ID)
attestation=whether server requires it; Can be “none” OR
“indirect” which means server accepts anonymized data OR
“direct” which means authn attestation data to be sent to server.
-	“direct” requires users consent before sending to server

o	WebAuthn Authentication: User sends userID to server; server provides random string and ID of creds as random challenge for user to sign with private key; browser signs it and sends to server; server verifies the signature.

# BOOK-2:  Access Control (Authorization)
-	Should be based on authentication data and not based on user-supplied data
o	Architecture & design phase should mandate developer implement authorization to all actions, functions and resources of the application
o	No quick patching is possible, if app is already built by relying on user supplied data; need to redesign
o	Can use server-side sessions to make decisions
o	Testing: source code reviews (SAST) & try access resources as another user (DAST)
-	Vertical or Horizontal access control issues
o	Vertical is about privilege escalation
o	Horizontal is about accessing someone else data. E.g. Insecure direct object reference

Path Traversal:
-	Short term fix: WAF rule | Long-term fix: Input validation and file permissions on OS

Access control common problem: “bloated on” over a period of time | Should define access rules and roles before coding begins.
-	Part of design process
Steps:
1.	Start by recording all users and groups
2.	Collect all resources / functions of the application and group them into roles
3.	Define who can access what (access control matrix, mapping users-groups and functionality-roles)
a.	Access control matrix can be stored in database or directory
Layers of access control / defense-in-depth:
   URL-based access control -> Filesystem & Server permissions -> Application (Business logic) access control -> Data layer access control -> Application (presentation layer) access control
-	Presentation layer is not the functionality that user can access but generally about what user can view

1.	URL-based access control: Make access control decision based on URL, user’s Identity and role
a.	In-house development: Java Filter, ASP.net HttpModule
b.	CA SiteMinder, Entrust getAccess, Tivoli Access Manager
c.	Be aware of forwarding type of URL
2.	File permissions in server (Webroot): File system (read, write, execute, modify) & Web server (Execute, read, write, log, script source, browsing)
a.	Check user’s identity, web server’s identity to OS file system access, etc.
b.	Block the web server from access entire OS contents. E.g. In Apache, deny using <directory> directive in config file
i.	Denying access to C drive
   <directory C:/>
Order deny,allow
Deny from all
AllowOverride None
Options None
</directory>
c.	In IIS, block file system access from the IUSR account; Deny read access to System32 directory from IUSR account
3.	Business logic access control: Developers code this part; Consistency is key! (Gatekeeper to what users can do)
a.	A centralized mechanism to check every user and action and every resource is useful
4.	Data Access Layer access control: Commonly ignored! Use of DB views to limit access to data
5.	Presentation layer access control: What users can ‘view’ and not about what user’s can ‘do’. Only relevant info is displayed to user and nothing more.

# BOOK-2:  Encryption / PKI Certificate (TLS)
Protects both integrity and confidentiality of data 
-	Storage encryption and Transport encryption

Encryption: TLS cipher algorithm as NULL (generally used for debugging purposes), falsely indicates a padlock on browser showing as secure conversation, instead it is clear text.
TLS problems: Slapper worm: Spread on internet apache web servers, related to weak key generation / network attacks.
Web of trust: Customer -> signing authority -> TLS server | relationship based
TLS:
-	Some login pages do not use TLS
-	HSTS: If cert expires, it is a form of DoS on accessing the application
https://hstspreload.org/ 
-	Signing on non-TLS login page assuming creds will be sent over TLS as POST. It is an indirect form of training users to enter creds on HTTP page.
Eavesdroppping: Wireless networks, ARP spoofing on LAN, Rogue administrators, etc.
Short-term fix for TLS: WAF or load balancers free web servers | TLS encryption is CPU intensive
-	Within Apache Webserver: mod_redirect can be used to redirect requests to “secure” directories:
RewriteCond %{HTTPS} off
RewriteRule ^secure/.*$ https://%{HTTP_HOST}%{REQUEST_URI} [R=301,L]
http://phpstarter.net/2008/07/several-htaccess-mod_rewrite-tricks-to-better-web-application/
-	TLS use is more difficult to detect by source code analysis

TLS configuration flaws/security hacks: DROWN, BEAST, CRIME, BREACH, Heartbleed; To undermine integrity and confidentiality
-	SSL v1, v2, v3 (CBC mode of encryption & key exchange), TLS 1.0 (POODLE) are legacy
-	Best is to have only TLS 1.2 and 1.3
Advanced ciphers are not supported on classic browsers, creating a form of DoS to users
Ephemeral keys: Same key will NOT be generated again, given the same set of generating options.

TLS Secure configuration requirements: review best practices every quarter | Avoid supporting old browsers | Mandate TLS for all pages in the site | TLS 1.2 & above | Offer strong cipher suites | Acquire cert from trusted CA (2048b key / SHA2, ECC as minimum)  
-	256b ECC key is stronger than 2048b RSA key
-	AES (128/256) with GCM mode is preferred (resistance from Padding Oracle attack + has good performance)
Must support PFS (Perfect Forward Secrecy): DHE & ECDHE (ECDHE has good performance)
-	Even if private key is stolen, the previous captured encrypted exchanges cannot be decrypted.

HSTS: Cert error = denied access | Max-Age sets the timeout for client browsers | includeSubDomains options includes sub domains | preload option instructs client browser to hardcode the entry
Strict-Transport-Security: max-age=63072000; includeSubDomains; preload

EV certificate: No longer supported / Extended validation / Requires more validation of owner / makes browser show green signal

Multidomain TLS certificate / UCC / Unified Communication Certificate: Multiple SAN (Subject Alternate name) | one cert for multiple domains
-	SNI: Server Name Indication: Allows one IP to host multiple sites (client specifies domain name before SSL starts)

OCSP stapling: Server fetches and cache’s CA response and presents it to browser; Responses are signed by CA. When response validation fails at browser, it contacts directly the CA to verify.

HPKP: Can backfire and lock out users / cause of DoS to users / DO NOT USE!
-	HTTP response header to cache certificate thumbprint by browser

DNS CAA: DNS Certificate Authority Authorization		(not sure secure, as DNS information is not encrypted in general)
-	A record in public DNS server
-	sans.org   CAA    0      issue     “letsencrypt.org”

TLS security tests for non-internet facing sites: openssl s_client -connect site:443 -cipher HIGH or nmap script (ssl-enum-ciphers)
Setting the environment variable: SSLKEYLOGIFLE (windows or Linux), will informed Chrome or Firefox to put in DEBUG mode for SSL / TLS exchanges. Browser then puts the symmetric session keys into the log file provided in the environment variable.

# BOOK-2:  Encryption at rest / Storage Encryption: Regulatory Compliance needs mandate this!
DB encryption key storage: 
-	filesystem | another database | LDAP or external wallet (TPM, USB key, Crypto API, Certificate snap-in, Java keystore, HSM), Type-in by User

DB encryption issues:
-	Careful when encrypting primary key or index field (data sorting issues and negative effect on speed of queries)| Encrypted fields are larger than unencrypted data, so more space used in DB | DB support all or nothing encryption (Sybase) | Exposed keys | back-up and recovery procedures

Alternatives to DB encryption:
-	Use object security (SQL grant and revoke statements to restricts which accounts can access which data).
-	Store hash of data (e.g. passwords)
-	Do not store data (unnecessary data need not be stored)
-	Store data somewhere else (consider using external file system)

Storage encryption testing: Nearly Impossible to test by DAST; Can do source code review; White-box review

Public key encryption is used to store sensitive data like credit cards. Application uses public key to encrypt and store. DB side people can use private key to decrypt and use when needed.

With salt of 8 bytes (as minimum); Recommended to have same length as hash
Perform iterative hash (to minimize Brute force attacks) | each password hash process should take minimum 0.25 seconds
To store user password hash into application database, developers can use the Golden standard (Linux shadow file):
-	Username:$6$SALT$HASH:1:0:10:10…
o	1. The number of days since Unix time (EPOC): 1/1/1970 the password was last changed
o	2. Minimum number of days password can be changed
o	3. Max number of days before password must be changed
o	4. Number of days before password expiry, user must be notified
o	5. Number of days after password expiry, user account is disabled
o	6. Days since UNIX time, the account has been disabled

Hash functions: (old) Bcrypt, PBKDF2, Scrypt, or Argon2 (latest) (add pepper if possible; pepper is a systemwide random string, not unique per user and stored outside database)
-	Use of libsodium (available for multiple platforms) for crypto library; Ensure sufficient hashing iterations
Cannot test by DAST | code review | Fail is no hash is present

Reasonably accepted Algos:
-	Hash: SHA256, SHA512, SHA3, RIPEMD160
-	Symmetric: AES, Blowfish, Twofish, Serpent
-	Asymmetric: RSA, ECDSA

# BOOK-2:  HTTP Sessions
If user-agent string changes, terminate the session immediately. Log the anomaly!
Session fixation: Attacker crafts a URL with session ID and lures victim to use that to login. Server realizes the existing session ID and uses that for the new victim’s login session. 
    Countermeasures: 1) Never choose session ID coming from client 2) Generate new session ID at server 3) Bind the session ID to immutable property like network address or TLS client certificate 4) Avoid GET/POST session token exchanges
    Likelihood: Easy when session token is in URL parameter; Very hard when session token is in Cookie; Relies on browser vulnerability like XSS or HTTP Response splitting
To generate new session ID: 
PHP: session_regenerate_id() | .NET: No built-in defense, need to invalidate token & copy session data | Java: No defense, like .NET
Test for session fixation: After login, session ID must change to new one
-	Fix in source code: Generate session ID before associating any user properties

Session binding is important: Mapping important user properties with session ID on server side. If the binding is not done, as a temporary fix: WAF can be used to do the mapping.
Surf Jack: A type of attack that targets websites that do not set session cookie as ‘Secure’.
-	Victim access bank site with public Wifi network (that is not encrypted). Victim accesses another site (over http) without logging off bank site. Attacker quickly sends 301 redirect to http://bank site for the second site, as it is on HTTP. Cookie is sent by browser to that http site (http://bank.com) and immediately attacker can sniff the exchange and steals session token.
To apply ‘secure’ flag for cookie:
1.	ASP.NET: <httpCookies httpOnlyCookies=”true” />
2.	PHP: php.ini file update: Session.cookie_httponly
3.	Java: No native support for HTTPOnly cookie. Need ServletFilter
response.setHeader(“SET-COOKIE”,”JSESSIONID=”+ sessionid +”;Path=/; HttpOnly”);
    In Java, session data defaults to writing into a cookie. If user browser has cookies disabled, it will fall back to URL based session.

Tracking user’s browser: (Evercookie project)
-	Flash, Java, HTML5 canvas, Local storage, HTTP ETags
-	Beware of EU cookie privacy legislation

It is generally not recommended to write our own session tracking code. Even the vendor implementations are not fully secure.

# BOOK-3:  Web Vulnerability Database
CSRF / One-click attack / session riding: Exploiting the trust the site has in the user’s browser
 - Automatically works in case of Integrated Windows Authentication (IWA)
 - Victim is not actively participating the attack
 - CSRF is amplified when application is also vulnerable to XSS
 - Amazon had one-click CSRF vulnerability (adding items to Victim’s cart by attacker)
 - Code for one-click attack:
Using hidden iframe so users won’t recognize
 - <iframe style="width: 0px; height: 0px; visibility: hidden" name="hidden"></iframe>
         Form submitting to Amazon for attack
 -  - <form name="csrf" action=http://amazon.com/gp/product/handle-buy-box method="post" target="hidden">
        <input type="hidden" #DETAILS OF ITEMS /> </form>
Using JS to submit with POST
 -  - <script>document.csrf.submit();</script>
 - Attack triggers: 
 -  - <IMG> | Easiest and works only for GET requests | Highest risk for application teams
 -  - <IMG src=http://www.bank.com/transfer.cgi?amount=10&dest=001-002>
 - <script> | Trigger a visit to specific URL
 - <script src=http://www.bank.com/transfer.cgi?amount=10&dest=001-002 >
 -  - <Iframe> | Simple or complex, for POST requests |
 -  - <iframe style="width: 1px; height: 1px; visibility: hidden" name="hidden"></iframe>
 -  - <form name="csrf" action=http://www.bank.com/transfer.cgi method="post" target="hidden">
 - <input type="hidden" name="amount" value="10"/></form>
 -  - <script>document.csrf.submit();</script>
 - XML HTTP (AJAX)
 -  - var xmlHttp = new XMLHttpRequest();
 -  - xmlHttp.open("POST", "test.txt",true);
 -  - xmlhttp.send(null);
 - Attack mitigations: Set all FORMS to submit only via POST (although not the only solution to CSRF), Lowering session timeout helps, Check referrer header, CAPTCHA (strong protection against automated requests, not practical for every functionality), Anti-CSRF token (Synchronizer token): Token must be random and verifiable at server, SameSite Cookie
 -  - CAPTCHA: Completely Automated Public Turing test to tell Computers and Humans Apart 
 -  - Anti-CSRF token: One token for user, reused for all pages
 -  - One token per form / page of the application
 -  - Hash (form + secret + sessionID) and compare at server
 -  - SameSite Cookie: Set-Cookie: key=value; SameSite=strict
 -  - Cookie is sent over same origin request
 - strict means third-party requests will be restricted
 - lax means Allow GET form requests, <a href>, Prerender link to send cookie
 -  - Limited support by browsers
 - Java, .NET, PHP: Use OWASP CSRFGuard
 - ASP.NET: Use ViewStateUserKey / AntiForgeryToken from System.Web.Mvc
 - Java: HTTP Data Integrity Validator (HDIV) has Anti-CSRF feature / Struts and Spring Security
Greybox preferred over Blackbox for testing

# BOOK-3:  Input related flaws
Buffer overflow: Web scripting languages (Java, Perl, PHP) are immune or have protection against BO attacks. Likely to cause a DoS when attempted on web application.
-	Difficult for attacker to design the BO attack, as error reporting and debugging capabilities of web application are low.
-	C/C++ are generally vulnerable; require secure coding practices
-	Limiting internal character array manipulation code to specific reasonable length is a way to protect from BO attack
o	strncpy (copy user data into temp buffer)
Testing: Easy to test at runtime and source code review; craft large inputs (start at 1024 characters, then 512, 256, 64); Usually returns 500 error or no response

OS Command Injection: Never use system commands in web application, especially in PHP; Instead use:
-	bool mkdir (string pathname)          //in PHP, is a safer choice
Testing: Use inputs with ; or |
-	both runtime and source code review

HTTP Response Splitting: Inject info into HTTP response headers; Attacking clients or infra components like proxy server; not web application server. 
-	Generally used in conjunction with Session fixation, proxy cache poisoning (+ defacement) or XSS
-	Harder to manually detect or test
-	Web application has a redirection page where user inputs are redirected to another site as normal http 302 code
o	E.g. php redirection page:
<?
  header(“Location: http://sans.org/content.php?id=” .$_GET[‘id’] );
	          ?>
	Id value comes from redirection.php but submitted to content.php
-	Since ID doesn’t have input validation, attacker uses CR / LF (with URL encoding) to inject additional headers into the ID field to show the client browser as changed HTTP response headers and body content
Defense: Proper input validation in code (check for canonicalization/encoding done by attacker, avoid CR/LF, validate redirections) + Infra components like NIPS and WAF can block these attacks
-	May cause false positives if defensive rules are not granular enough

# BOOK-3:  SQL Injection
Most hostile SQLi (with metacharacters like ‘ or “ or ; etc.) allows xp_cmdshell on MS SQL Server. This enables taking control on underlying host of DB server. Can also be used to jump to another host and take control of it too.
 - Error messages are good indicators to attackers:
 -  - Java.sql.SQLException
 -  - [ODBS SQL Server Driver]
 -  - DBD:
 -  - Microsoft OLE DB Provider for ODBC Drivers error
 -  - System.Data.Odbc.OdbcException
 -  - Oracle error: unable to perform query
Blind SQLi: Based on question and answers (Yes or No from server)
Defense: Constrained input (type, length, format, range) | hard to perform consistently | reject bad data | Look for encoding
 - Just input validations are not enough (e.g. if developers block AND or OR in inputs, attackers can inject: O/**/R)
 -  - /**/ are comments in SQL databases
 - Escaping input (database dependent solution and also doesn’t work for numeric SQL) -> effective solution
 - \’ in MySQL or “ in MSSQL etc.
 - Should escape all DB characters (--, #, @)
 - Language built-in protections can be bypassed using char()
 -  - Perl: DBI:Quote			//add a slash before special character
 -  - PHP: mysql_real_escape_string  	//add a slash before special character
 - Prepared statement: Ultimate defense. 
 -  - @ sign is used in ASP.net | ? in Java | Don’t use dynamic SQL within stored procedure
 - Database permissions and hardening (delete unwanted stored procedures like xp_cmdshell, delete default user accounts, Monitor outbound SQL connections)
 - Limit SQL error messages (security thru obscurity)

# BOOK-3:  Cross Site Scripting / XSS
3 parties: Client (Victim), Server, Attacker
CNN has XSS issue in 2004 | Yahoo Mail has XSS in 2016
Most commonly reported vulnerability today; easy to find and easy to exploit;
Commonly uses JS but also leverages ActiveX, Flash ActionScript, or other scripting languages
Common effects of XSS: 1. Disclosure of cookies | 2. Force redirection | 3. Modify content of pages | 4. Run custom scripts
Reflected | Stored | DOM-based (not dependent on server)
-	SPA (Single Page Application) are mostly vulnerable to DOM-based XSS, due to HTML5 local storage that doesn’t talk to server to update its page sometimes
Defense: Filter our HTML metacharacters <>’;&\%” | watch for encoding | might backfire (functionality impact)
-	UTF-7 encoding is legitimate in web browsers 
-	Most languages have built-in capability: MS: Anti-XSS libraries | PHP: htmlentities() | Perl: Apache::TaintRequest
-	Escape and encode all HTML entities sent to clients (a anti-xss output function to display data is more better)
-	Input validation is not really useful in XSS (attackers always try to find ways to bypass input validations)
o	Simple encoding input is not sufficient
-	Specifically, for DOM-based XSS, avoid client-side rewriting or redirection based on client input
-	If user input needs to be sent to HTML attributes, then use them as STRINGS in single or double quotes
-	Avoid putting user input into JS code as much as possible / Need JS escape (adding backslash and then hex-encode)
-	CSS (cascade style sheet) are also vuln to XSS. Same as JS escape (add backslash and then hex-encode)
-	To put user input into URL GET parameters, use single or double quotes + URL encoding (puts a % sign) + hex encoding
Enterprise level defense: Generic re-usable encoding API / in the context of output / easy to detect misuse / eliminate default language output functions like print,println,output,etc.
Testing: OWASP XSS Filter evasion cheat sheet

# BOOK-3:  Input validation failures
It is tough, no one size fits all! Each field has different validation needs.
Multi-layer defense:
 - Client-side validation -> WAF rule -> Web server filter -> Validation within dev framework -> custom validation per form field
 - Validate the source of data (if data is expected in POST, make sure to add that as validation on server side code)
Canonicalization: A big issue for input validations; Encoding depends on platform supports: UTF-8 for .NET and ISO-8859-1 for php
Regexp: 
 - ^\d\d\d-\d\d\d\$ matches 111-111 or 333-333   (^ means beginning of string and $ means end of string)
 - ^\w{6}$ matches aaaaaa, 111111, as35fh
 - ^\d{3}-\d{2}-\d{4}$ matches 123-45-6789 (social security number)
 - ^([0-5]?[0-9]|6[0-5])$ matches any number from 0 to 65  (? means optional / immediate previous element)
 - ^[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2-4}$ matches any email address 
 - ^\d{5}([\-]\d{4})?$  matches zip code 
 - ^http[s]?://[a-z0-9\.]+\/[a-z0-9]+ matches URL
 - \d(?:(?:25[0-9]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-0]|[01\?[0-9][0-9]?)\b matches IP address
 - \w matches even non-English characters

Whitelisting: For simple and fixed data fields, use whitelist (precomputed / expected values only and nothing else!)
•	Factors to evaluate: Length (number of characters), Range (upper and lower bounds), Format (date/phone, etc.), Type (Integers or Alphanumeric, etc.)
•	A blog cannot be whitelisted; Passwords cannot be whitelisted; A long paragraph of text & numbers, etc. cannot be whitelisted.

Blacklisting: Needed when type, length, format, range are NOT known ahead of time. Always attack driven; 
•	Identify what we are protecting (SQLi, CMDi, BufOvf, XSS, Path manipulation, Response splitting)
•	SQLi blacklists: union, select, drop, delete, --, @@, char, exec    (for Sybase, # is used for comments)
•	XSS blacklists: Input validation is not the preferred solution for defense; Output encoding is essential; Filter <,> (with encoding)
Regexp for XSS: ((\%3C)|<) [^<>/]*(S|s) [^<>/]*(C|c) [^<>/]*(R|r) [^<>/]*((\%3E)|>)
•	Path manipulation blacklists: Need to decode first before validation; Block: / \ .. ; :
•	Response splitting blacklists: Block: [\r\n]* or just \n
Situational awareness: Warn the user of what’s not allowed (e.g. single or double quotes).
Input validation cannot be done on ad-hoc basis; must be planned well in advance.
Context checking: First name cannot be “java\n” | Address cannot be select%0A | Luhn check (mod10) for credit card (WAF can do)
    Regexp for credit card: ^((4\d{3})|(5[1-5]\d{2}))(-?|\040?)(\d{4}(-?|\040?)){3}|^(3[4,7]\d{2})(-?|\040?)\d{6}(-?|\040?)\d{5}

Reading files: Common vuln: Buffer-overflow and Path traversal.  
Handling HTML inputs: Best way to allow HTML and disallow scripting is to use: BBCode, WikiText, Textile => these are pseudo-HTML that can be converted into HTML on server side. Also PHP has HTML purifier; OWASP AntiSamy project for Java and .NET to securely allow HTML inputs by user.

PHP filter function: For Input validation | Can examine i/p thru prelist of expected formats (email, IP, etc.) | 
- $email = filter_var($_GET['var'], FILTER_SANITIZE_EMAIL);

ASP.NET validation controls: Has client side checking as well; 5 types of validators: RequireFieldValidator, CompareValidator, RangeValidator, RegularExpressionValidator, CustomValidator. 
	<asp:TextBox id="txtZIP" runat="SERVER">
	</asp:TextBox>
	<asp:RegularExpressionValidator id="txtZIP_validation" runat="SERVER"
	ControlToValidate="txtZIP" ErrorMessage="Enter a valid US ZIP code." ValidationExpression="\d{5}(-\d{4})?">
	</asp:RegularExpressionValidator>

Java validation: Doesn’t have inbuilt validation controls; Most framework provides its own validation methods: Struts validator framework (flexible, can be used outside Struts), WebWork, Spring; OWASP has Stinger project

# BOOK-3:  File Upload
More risky when uploaded content becomes part of site! 
Risks: Unexpected size, File name and extension, File type (PHP, JSP, etc.), executable content, Virus / trojan or malware, etc.
Strategies:
1.	Specify the size limit in HTML / verify the same on server side
2.	Check MIME type on server
3.	Check filename and rename it to internal standard conventions / confirm that it is not a script or active content
4.	Save the file outside web server directory
5.	Run virus scans 6. Re-size the graphics image file so malicious metadata is lost
6.	Inspect the file contents:
a.	Header and Contents (use ‘File’ command on Windows or Linux) -> required GNU tools
b.	Apache Tika project / can extract metadata or contents of file
c.	Graphic: re-size & re-save | PDF: Apache PDFBox library, PDFiD tool | MS Office: Apache POI library, OfficeMalScanner
d.	ASPOSE API: Commercial library, Supports multiple languages, great support
e.	Safe way: Flatten/rasterize or regenerate the file / offensive content is stripped off & not passed to others
f.	Use isolated environments to parse uploaded files (e.g. temporary Docker container to validate it)
g.	Watch for path traversal attack, if file has to be moved
h.	Votiro Disarmer: commercial solutions
Disallowing double extension files in Apache config:
	<FilesMatch “\php\.$”>
		Order deny, allow
		Allow from all
	</FilesMatch>

# BOOK-3:  Business Logic & Concurrency
Vuln scans cannot detect business logic (real life business objectives) security flaws
Business logic flaw mitigation strategies: At design phase of SDLC: abuse cases are considered/mapped to data, Secure person review and test those
- Testing: Difficult to catch at source code review; Test at design (whitebox / graybox); Understanding context of app is key (“think out of the box”)!
-- Abuse cases: Can the sequence of step be missed or bypassed?
-- What values are we expecting? What if different values are coming in?
-- Steps are time sensitive? Any controls in place to enforce time constraint?
-- If step terminates immediately, what is the impact on other steps?
-- Who can perform the steps?
Concurrency: Concurrency enhances scalability so application can take more loads but adds security issues!
- Control measures: Pessimistic (Block ops that would cause integrity issues) | Optimistic (Do executions first, check and resolve conflicts later)
Deadlock issues: When using lock during concurrency, it might create a deadlock. 
Mitigation: Isolation (Lock only what’s needed) | Optimistic control is suitable for HTTP stateless nature | No general fix (unique solution to each scenario)
Testing: Code and design review | difficult to test | Many factors might mask the problem

# BOOK-3:  Logging and Error + Exception Handling
Don’t do:
try {
	//some code
}
catch (Exception e) {
	System.out.println(e);
}
Need fine balance between confusing and revealing
Testing: Trigger abnormal behavior and look for error messages
General approach: Log, redirect to error page, stop execution!
Log injection mitigation: Static information in log file | Any user i/p to go thru whitelist | Log viewer should not interpret code in logs (control chars, HTML, etc.)

Error handling: Leverage standard frameworks: log4j, log4php, log4net, etc. | Web user should be able to write logs but not read it
What to log? Authn and Authz (must log both successes and failures) | Account lockouts | Policy violations | Logs should include accessed resource (URL, DB tables and fields, username) and the reason for deny access (when fail) | Log session termination (difficult, as some sessions timeout) | Data actions (read, write, delete): write and delete are more imp | changes to data structure | Admin functions | Any high-risk event | Errors (file not found, cannot open errors, Unexpected states, connection failures (DB), timeout errors)
- Logging at WAF: Do not rely on code, so easy to implement | Doesn’t require server resources | Log i/p fields and o/p | Safe to have logs outside of web application itself
Apache webserver log format: %h %l %u %t \”%r\” %>s  (hostname, logname, user, time, first line of request, status code, # of bytes)
IIS log format: date time s-computer s-ip cs-method cs-uri-stem s-port cs-username c-ip cs(User-agent) cs(Referer) cs-host sc-status sc-bytes cs-bytes time-taken

# BOOK-3:  Incident Handling & Intrusion Detection
Companies often overestimate their IH capability;
6 steps of IH: Preparation (before actual incident happens) | Identification (determine it is event or really an incident) | Containment (Doesn’t spread to other systems; stop the bleeding; bringing under control) | Eradication (actual cleaning the incident, stopping the root cause, make sure it is not coming back) | Recovery (Affected systems are put back to production and monitored) | Lessons Learnt (look back and seek ways to improve)
- Preparation: Make sure systems are logging and logs are stored | Setup drills | Response kit (screwdriver, blank CD, OS binary media, forensic software, call list, cell phone, extra batteries) | know the app owner (to escalate)
- Identification: Leverage the helpdesk | Read logs | Verify existence of attacks | Run IR checklist | Declare & assemble CSIRT
- Containment: Preserve evidence | Firewall is used | Stop user login system | Segregate the n/w | Bring offline, if needed
- Eradication: Keep track of actions | Use mod_security, URLScan, WebKnight to block attacks (Virtual patching)| Look nearby
- Recovery: Validate web app functionalities | Packet capture and logging | IPS and WAF are essential to monitor
- Lessons Learnt: No finger pointing | Often ignored step
Short-term fixes and long-term fixes (strategic) must be evaluated and considered.
Quick fix for critical vulnerabilities: WAF, Web server filter, Blacklist within program code (configuration)

Case study: Twitter XSS worm / 17-yrs old admitted to hacking

Intrusion Detection in Web Apps: 
 Design intrusion detection into the web app code; Needs explicit design, it’s not automatic
Approaches:
Traffic based: Inspect content against known attack patterns / match anomaly behavior (inward + outward)
- For IDS inline, blocking is dropping packets | For IDS eavesdropping, spoofed TCP reset packets are sent to server
- Doesn’t work always due to encoding / evading mechanism by attackers
- What you see is what you get
- Issues: Takes time to develop | staying up-to-date on attacks is hard | attacks on web server can’t be detected in code
Server-based:  
Hybrid: Agent or software installed within app platform | Analyzes and monitors bad inputs | Accurate detection
- Vendors: Waratek, Wallarm, Contrast, Signal Sciences, ThreatX

# BOOK-4: Anti Automation
Anti-Automation and Anti-Spam: CAPTCHA: Not a significant measure of protection! 3rd world countries get 3 USD a day to solve CAPTCHA issues during automation. 

 - Effective attack against CAPTCHA: OCR (Optical Character Recognition): BY shape of the objects.
 - CAPTCHA at Hotmail is found to be cracked 20% of the time by specific malware: botnet agents
 -  - Rate Limit: Might work for brute force and data scrapping attacks. E.g. access a page only 3 times in a minute. WAF can do this. Else need to explicitly code it; most web servers do NOT support this yet.
 - Apache users can leverage mod_bandwidth

Search engines like Google, Bing, DuckDuckGo, etc. rank sites based on number of links and its relevance. Spammers post their site link (backlink) on every internet site, in order to boost their site rank: WEB LINK SPAM

Mitigation against Web Link Spam:
 - Check for referrer header
 - Blacklist (user-agent, XBL, open proxies): https://perishablepress.com/ultimate-htaccess-blacklist-2-compressed-version/ & https://www.spamhaus.org/xbl/
 - JavaScript tricks: Script to run on client side to detect browser and confirm against user-agent field 
  -  - http://www.thespanner.co.uk/2009/01/29/detecting-browsers-javascript-hacks/
 - Time based behavior: How quickly requests are coming through (humans vs computers)
 - Reduce incentive (Use NOFOLLOW meta tag): Prevents search engine to considers ranking the sites / devalues the spammers
SpamBam and Akismet are two projects that deal with comment spam. Designed for blogs but can be applied on contact forms.

Honeytoken: Set a trap to detect unauthorized use of the system. Static variable or condition that is outside normal execution (or operation). When manipulation of these are detected, likely an attack, admins are notified & attackers are blocked (source ip, user id, etc.).
Where to set these traps: 
 - Session ID (length and format): If they are changed, attack is in place.
 - Additional hidden form field value or extra cookie value (any manipulation of these is an identification of attack)
 - Fake admin page in robots.txt 

# BOOK-4: Security Testing
During dev: SAST, SCA, Unit Testing | After dev: Runtime testing, Pen tests
Code Analysis: https://samate.nist.gov/index.php/Source_Code_Security_Analyzers.html; SAST
Runtime Analysis: Focus on i/p and o/p from application; DAST
IAST: Agent on app server | Low false positives | sometimes seen as ‘too late’ to find vulnerabilities
Pen test: Simulate an attack from malicious sources to analyze weakness in a system | Process must be repeatable | Covers risks impacting the application | Methodical and structured
•	Challenges in Pen Test: Insufficient knowledge, Coverage, Thoroughness, Time, Lack of manual validation of vulns found
•	Frameworks: OSSTMM, OWASP testing guide; However, they do not guarantee coverage or quality of tests
•	Basic tool kit: WebCrawler (spider), Proxy tool, Scanner (infra & app), Enumeration, Brute forcing tool (fuzz & pwd cracker)
•	Get-out-of-jail-free card (written permission)!
•	Reporting: Separate vulns from best practices & recommendations
Configuration test: Validation on environment security / infrastructure automation scan (BDD-Security, Gauntlt, Mittn)
Dependency test: SCA

# BOOK-4: Web Services
SOA: Loosely couples and interoperable services to support business processes / based on open standards
XML: Derived from SGML | XML: Custom tags possible & HTML: Predefined tags only
SOAP: Envelop -> Body -> Elements -> Arguments
•	Document style or RPC style
WSDL: Describe, Locate, How to invoke webservice / good for interoperability / bad that it might leak too much info to unwanted
Major elements in WSDL: Definitions | Message | PortType (operations of webservice, has i/p and o/p messages) | Binding (how PortType will be transferred over network) | Service (actual location & documentation/description of service, human readable description of service)
•	Namespace: Unique entity for isolating elements (URL may not exist, just for having a unique namespace)
SOAP Clients: AJAX / Web browsers | Mobile apps | Fat clients | other web service or web servers
Service requestor -> Intermediate web service -> Service provider

WSDL enumeration: tells attackers where and how to attack the webservice (like treasure map). Without WSDL, attacker can sniff network traffic or obtain syntax info from other means (e.g. social engineering)
•	Attackers look at UDDI (that publishes WSDL files)
•	For non-published WSDL, only emailed back and forth between parties using and hosting the web service
•	For self-publishing, WSDL file is hosted on web server itself. Also found on search engines (filetype:wsdl or inurl:wsdl or site:google.com inurl:wsdl)
Enumeration Prevention: Avoid publishing WSDL if service is private. New version of UDDI has access control mechanisms. 

XML schemas: DTD (Document Type Declaration, kind of outdated/must be avoided) and XSD (XML Schema Definition, adopted by W3C) or both. 
•	Allows minimum or maximum value
•	Treat as first line of defense / casual check
•	App level input validation of XML document is still needed

DTD can be internal or external (link to file) to XML document. | #PCDATA or #CDATA | <!ELEMENT users…>
•	Doesn’t support datatypes & namespaces
•	User defined names and text can be created using ENTITIES; At run time, entity will replace the text.
<!ENTITY http “Hyper Text Transfer Protocol”>
<protocol>&http;</protocol>
•	XXE: <!ENTITY xxe SYSTEM “/etc/passwd”>          <description>&xxe;</description>
o	Disabling DTD is the best way to prevent XXE / Also refer to OWASP XXE prevention cheat sheet
•	Recursive payload: Infinite loop of entities referring among themselves
o	<! ENTITY % xx ‘;zz;> and <! ENTITY % zz ‘;xx;>  and %xx;  	// resource exhaustion
•	XML Bomb or DoS: similar to recursive payload / resource exhaustion
XSD can be external or inline (embedded into the XML) | Too granular than DTD | >40 types of data types built in (min value, length, pattern, etc.)  | <xs:schema…..></xs:schema>
•	Support datatypes and namespace
•	XML Schema poisoning: Compromised schema leads to DoS | Unexpected data into XML processing components
o	Remote location of schema storage must be secured

XPATH: Query XML doc. | No user privileges | Similar to SQL injection but much easier | Syntax doesn’t change with programming language
•	/users/user[username=”john”]/password
•	/users/user[username=’john’ or 1=1] returns all <user>…</user> data	//XPath injection
string query = “/users/user[username=’ ”+ name  +“ ’ and password = ‘ “ + pass + “ ‘]  ”;
XPath Injection mitigation:
•	Input validation & parameterized queries (prefixed with $ in Java and .NET)
XPathExpression expr =
DynamicContext.Compile("/dsPubs/publishers/titles[pub_id = $id and price < $price]");
DynamicContext ctx = new DynamicContext();
ctx.AddVariable("id", id);
ctx.AddVariable("price", price);

XQuery Injection: Extract and manipulate XML docs. | Uses XPath syntax + FLWOR (flow & conditional statement) | has user privilege concept | Supported on many commercial SQL databases

# BOOK-4: Web Services Security
Authn, Access control/Authz, Session mgmt. (via SAML), I/p validation, Logging, Cryptography, Denial of service, etc. everything applies to Webservices.
Webservices unique vulns:
1.	Attack the network traffic or components (sniffing, scanning or redirection)
2.	Attack the XML parser (parser fail or consume all system resources)
3.	Attack the XML processor (after parsing, data is processed. Tampering with content in XML will create in i/p attack vectors)
XML Parameter tamping | Oversized payload (server side memory exhaustion; front webservers can put limit on XML size) | 
•	Webservices reveal too much information during errors assuming it is system to system communication (info needed for debug). 
•	Any traditional web application authentication mechanisms (Basic, Digest, IWA, TLS mutual auth, form-based with creds) is possible with WebServices (creds sent in XML).
SAML: exchange security info via XML | provides framework for authn, authz | works by trust assertions
•	Assertion is claim by SAML authority on identify of subject
•	Service provider can authz a user based on claim by SAML authority
<Assertion><Conditions><AuthorizationDecisionStatement><subject><action> 		<Signature></Signature>

DOM-based XML parsing: Parse XML into tree format (allows easy search of data) | Lot of memory consumed to process XML in memory
SAX-based XML parsing: event-driven parsing / stream | Low memory consumed | Vulnerable to overwriting the attack
Webservice or XML Firewall: Perform schema validation and XML parameter validation | Understands & protects webservices attacks | Protects from parser attacks | very granular in checking the XML elements | Inline or in sniffer mode (SPAN port) |
•	In sniffer mode, quietly listens and RST packets are sent to attacker | Downside is RST packets may not go ontime to attacker
•	TLS in Webservices communication ensures encryption and authentication
 
WS-Security: Standard for Authn, Authz, Encryption, Signature | Leverages existing XML signature and encryption | Extended to use Kerberos & X.509 certificate | Extension to SOAP messages
•	WS-Security Authn: <wsse:UsernameToken> | Password is specified as well | <Nonce>&<Created> timestamp to prevent replay
o	PasswordDigest: Base64 of SHA-1(Nonce+Created+Password) | Need signature to ensure integrity
•	XML Signature: Verify sender’s identity & message integrity & non-repudiation | Can sign for resource outside of XML (e.g. URL)
o	Different parties can sign different elements of XML
•	XML Encryption: Single element of XML or full document | More flexible than TLS | Envelope/Super encryption possible
o	<EncryptedData><EncryptedMethod algorithm=’’><KeyInfo><KeyNmae> & <CipherData><CipherValue>
Duo Labs/Duo Security reported SAML vuln that attackers can spoof as another user without knowing victim’s password.
•	Due to canonicalization of XML (adding comments on <NameID>)

# BOOK:4 AJAX / Web 2.0
AJAX itself doesn’t add new vulns, but amplifies existing vulns. Techno used: HTML, JavaScript, Dynamic HTML (DHTML for interactive/animated pages | JS can update content on the fly), DOM (HTML or XML returned from server)
•	Needs more emphasis on input validation consistently at server side
•	In AJAX, HTTP responses could be HTML, XML, JSON
XMLHttpRequest: API that JS uses for communication between server and client (uses HTTP methods: GET, POST, COPY, etc. Also WebDAV) | XHR can transfer any data format: Plaintext, HTML, XML, JSON, Images, Flash, Scripts, etc. 
	var xmlHttp = new XMLHttpRequest(); 	//initiate object
	xmlHttp.open(“GET”,”test.txt”,true)	//GET method to get test file; true flag indicates async. Continue browser ops.
	xmlHttp.onreadystatechange=function() {   
if(xmlHttp.readyState == 4) { alert(xmlHttp.getAllResponseHeaders())   }  
} xmlHttp.send(null);
•	XHR v2 (beyond SameOriginPolicy)
•	XHR v1 disallows HTTP methods: TRACK, TRACE, CONNECT & Headers like Host, Content-Length and Accept-Encoding are disallowed.
JSON: Lightweight | Difficult to debug | Programming language like syntax | easy to parse | eval() function in JS makes JSON to be seen as insecure as it reads key value pairs from JSON object
•	Do not use eval()  |   Use native JavaScript ‘parse’ method for JSON parsing. 	
var obj = JSON.parse(‘{“name”:”vasu”,”course”:”sec522”}’);
document.getElementById(“test”).innerHTML = obj.name + “ , ” + obj.course 

JavaScript runs in a sandbox (adopting the Applets approach).

Same Origin Policy: Started by Netscape. (Protocol, Host, Port must match according to Same Origin Policy). 
SOP doesn’t restrict Straight URL redirection. It stops: XHR, Manipulating browser windows or frames, Manipulating cookies,
Sandbox and SOP are the only protection measures for JS.
•	Microsoft approach to circumvent SOP is XDR (deprecated now).  
•	Others use XHR level 2 (SOP not enforced when using XHR 2). CORS header draft is on 16 Jan 2014.
•	Fetch API is simplifying JavaScript web requests to cross-domain | Aborting request is not available in this API.
fetch(“https://google.com/index.html”).then(function(response) { return response.json(); } );
•	Risky requests (PUT, DELETE, etc. or with special req headers) require a pre-flight request using OPTIONS method (fetch API).
o	In HTTP response, 3rd party site adds: “Access-Control-Allow-Origin, Access-Control-Allow-Header, Access-Control-Allow-Method” etc.
o	Other response headers: Access-Control-Max-Age (time in seconds for caching result) and Access-Control-Allow-Credentials (send cookie or HTTP authn header by adjusting withCredentials Boolean state, protect from CSRF)
•	In low risk / simple requests (GET, POST, HEAD), “Origin” header is added in HTTP request indicating the source host
o	In HTTP response, 3rd party site adds: “Access-Control-Allow-Origin” header, mentioning the origin domain
(XHR level 2 still doesn’t protect one-hit attack / CSRF)
AJAX exposes most of the code on client side | An attacker can call the server, instead of AJAX browser client!
Race conditions is a problem in AJAX | Timing issues in new requests and old responses
JS allows modification of CODE after script is loaded.

AJAX-XSS: Web based worm is possible! DOM-based XSS is possible with AJAX. Output encoding is key at client side code. Server has no idea that attacker is performing DOM-based XSS.

AJAX+XSS+CSRF: Anti-CSRF tokens become useless! XSS injects code on browser -> XHR gets new page from server with token -> JS parse the page and gets token -> Submit forged request with proper token with XHR
•	AJAX has repudiation issues! (not sure whether user intended to make that request or just browser code did it accidently)

SAMY attack: XSS+CSRF w/ AJAX on myspace.com | worm | 1m users effected | Anti-CSRF tokens were bypassed | Persistent XSS
•	MySpace fixes: java\nscript | inne + rHTML | <tag> to hold JS

# BOOK-4: Cross-Domain AJAX
In order to allow AJAX from www.sans.org to www2.sans.org (basically different servers of sans.org), “document.domain” directive is used in JavaScript. 
•	No cross domain, but same domain with different servers.

AJAX proxy/Bridge: To get around SameOriginPolicy. AJAX frameworks already include this feature: Adobe Flex, .NET, DWR.
JSONP: JSON with Padding is another way to get around SOP restriction. Flikr, Instagram, Foursquare, etc. use this. Simplicity!
•	Add ( and ) around JSON content and use a JavaScript function name. e.g. callback ({“name”:”value”})
•	Not the most secure solution

# BOOK-4: AJAX Security
Most SAST tools do not scan for JavaScript security issues. Manual code audit and architecture review is needed.

# BOOK-4: REST
HTTP method: OPTIONS is not part of REST API | POST, GET, PUT, PATCH, DELETE are HTTP verbs in REST.
REST Security: Lack of standard in data sent in req and resp | Do not reference public / open REST service from vendors like Amazon, Yahoo, etc. Convert / migrate to private later will be very difficult.
•	Enable SSL/TLS | Do not pass username / password in req | Control type of req allows (e.g. DELETE?)
•	Basic or Digest authentication is fine in REST, when exchanging on TLS
User authentication in REST:
•	Cookie+Session Or Query-based authentication (put signature or signed token, so receiving party can identify&verify the sender) | Another Querybased authn is OAUTH (but complicated due to the token in request)

REST is vulnerable to CSRF. Two solutions: Put custom header (e.g. X-CSRF; Cross-origin requires pre-flight)  |  Establish state and use Anti-CSRF token

REST API access restriction: Block HTTP HEAD requests | Deny all HTTP verbs at WAF and allow only needed ones | Content-type validation on both server and client side | Rate limiting: HTTP response code: 429 (too many requests) (to prevent DoS attack)
e.g. https://developer.twitter.com/en/docs/ads/general/guides/rate-limiting

# BOOK-4: Modern JavaScript Frameworks (Node.js)
Google’s V8 JavaScript engine | Node.js (async in nature) | SPA (Single Page Application) | Specific to REST, Node.js has frameworks like actionHero.js and LoopBack. | For other web applications, Feathers and Socket.io

NPM: Node Package Manager: Software registry at npmjs.com 
#npm audit and #npm audit fix (to detect and automatically fix vulns in dependencies)
Node.js best practices:
•	ESLint (eslint-plugin-security) linter tool for code quality (e.g. use of unsafe eval() disabled security features in node.js)
•	ORM/ODB for SQL query parameterization (Waterline, TypeORM, Sequelize)
•	Validation library templates (Joi or Yup) – both user input and JSON data from data stores
o	fast-ratelimit | request-rate-limiter | express-rate-limit | express-slow-down
•	Use rate and size limiting libraries (to protect against DoS) | Use body-parser library to purge requests that are oversized
•	Helmet package (security related response headers) / available for Express and KOA
Node.js often used to create REST API / vuln to brute force and data scrapping type of attacks

Client-side framework: jQuery was popular in first wave of browsers (now impossible to manage) | Angular, React, Vue (reduced code complexity, manages data binding)
X-CSRF-TOKEN header is required from client-side code in header to compare; Else most of these are vuln to CSRF.
XSS is still a concern in front-end frameworks, although frameworks automatically sanitize or escape values (limited by data type). 

# BOOK-4: Browser Defense Mechanism
IE 8+ browser has built-in protection against reflective XSS (based on GET,POST parameters and HTTP response from server) | limited capability only.
•	Profile the i/p -> match the signature -> search for match in response -> display result or mitigation
We can check signature used in IE 8+ using the command: findstr /c:"sc{r}" c:\WINDOWS\system32\mshtml.dll | find "{"
Actual signatures are: 
•	{<sc{r}ipt.*?>}   &  {<AP{P}LET[ /+\t].*?code[ /+\t]*=}   &    {<[i]?f{r}ame.*?[ /+\t]*?src[ /+\t]*=}
Mitigation that IE browser applies is in curly brackets (). Character will be converted into “#”  (false positives are possible)
-	Fragmented XSS is an evasion technique e.g. &arg1=<scr&arg2=ipt>
Servers set header: X-XSS-Protection: 0 (disable browser protection) OR X-XSS-Protection: 1; mode=block (Turn on & block full page)

X-Content-Security-Policy & X-Content-Security-Policy-Report-Only: 
Inline JS code is not allowed to run | Code will not be created from strings | “data: URI” is not allowed | special mime type: text/x-content-security-policy   		https://report-uri.com/home/generate
CSP directives:
default-src: default source list of all policies | script-src: valid script sources | img-src (favicons) | media-src (audio, video) | object-src (embed,applet) | frame-src | font-src | connect-src (XHR, EventSource, WebSocket) | Frame-ancestors (frame, iframe) | style-src | report-uri (log violations)

MIME sniffing: IE browser feature to automatically set the MIME type (Content-Type) based on content received or sent and not based on headers. 
-	Browser may be confused when user is uploading graphic files (appears like jpg) but contains HTML code
-	X-Content-Type-Options: noniff header stops IE browser sniffing the content-type automatically and browser respective the actual header: Content-Type set by server.

# BOOK-5: Serialization Security
Serialize: Convert objects into stream of data (string) for transmission or storage | Deserialize: Convert stream into objects
-	JSON and XML are common serialize formats
-	No validation by default after deserialization / security concern!
Chain: Sending chain of serialized objects to the entry point
Gadgets: series of objects that are known to trigger harmful actions to systems (payload of the attack in exploiting serialization).
Serialization vuln languages: Ruby, .NET, PHP, Python, Java (including 3rd party libraries) & language built-in serialization functions.
Defense: protect & isolate endpoints (check untrusted connections) | signing data stream | Specify data type (used for validation by whitelist/blacklist) | Use alternate data format (XML, JSON)

# BOOK-5: DNS Rebinding
Breaks the SameOriginPolicy (by changing the target host IPs for the same domain name).
-	Attacker puts low TTL value and actual attacker server IP at first DNS request from browser
-	Then sends the attack payload from actual attacker server to victim and asks to connect back after TTL expires
-	Victim checks with DNS server again as TTL expired for IP; this time attacker DNS provides another server IP (target for attack)
-	Victim sends attack payload to target server
 Attacker can also put multiple A records in DNS server to do this attack.
With DNS rebinding attack: can attack internal hosts (inside f/w) |  fwd internal info to outside world | Attack 3rd party host
e.g. Ethereum client (Geth) & IoT devices (http://rebind.network)
•	Advanced attacks: Full port scan of intranet system | Exploit vuln | spam or click fraud | Framing the client | attack victim host
Mitigation:  DNS pinning: means to store DNS resolution info in browser for lifetime / Not RFC compliant / partially effective
-	Anti-DNS-pinning: Attackers bring down their web server, so that browser forcefully makes another DNS query
o	No major mitigation after Anti-DNS pinning is bypassed.
-	DNSWall: Block external IPs as source when going out from intranet | Block internal IPs as source when coming from outside
-	Smart DNS pinning: prompting user when server is not responding | page: 31 on book-5
-	Performing host header check (name based virtual host) on target server is good mitigation technique / along with TLS setup

Adobe Flash SWF file with ActionScript can open raw TCP connection. Before v9, there is no DNS pinning functionality. However, Flash PIN database is different from brow ser PIN database. So different IPs are possible here.
-	Open socket connection, instead of HTTP

# BOOK-5: Clickjacking
Cross Frame Scripting / UI redressing / Works with iFrame (page on page) and JavaScript / Clicking on something that we cannot see
-	opacity attribute on iFrame makes it transparent
style=”opacity:0.0; position:absolute;

JavaScript is used to move the iFrame under the mouse click. 
Effects of Clickjacking: CSRF | can change s/w settings: Google desktop / Adobe Flash | click fraud / user framing
Flash attack -> linked to clickjacking
Framebusting -> mitigation technique for clickjacking | prevent a page from being within a IFrame
<script> if(top != self) </script>

Anti-Framebusting: attacker can disable framebusting using <Iframe security=restricted>, which disables JavaScript. Another way is:
 var prevent_bust = 0windowsondebandunload = function() { prevent_bust++ } 
 setInterval(function() {if (prevent_bust > 0) { prevent_bust = -2    window.top.location = ‘’ } }, 1)
-	Call to another page responds with HTTP 204 causes web browser to stop current load operation and stay on current page.
o	onbeforeunload event in combination with redirect to 204 returns no data (effective countermeasure)
Non-JavaScript Framebusting (protection measures against clickjacking): Using HTTP headers:
1.	X-FRAME-OPTIONS: DENY 	//prevent page rendering if inside a frame
2.	X-FRAME-OPTIONS: SAMEORIGIN 	//pages from same origin can load into iframes
3.	X-FRAME-OPTIONS: ALLOW-FROM uri  //pages can be loaded into iframe coming from specific uri  (chrome/safari unsupported)
4.	CSP header with “frame-src” directive
Firefox: NoScript: Implements X-FRAME-OPTIONS header / ClearClick / compare screenshots and alert user, if clickjacking is found

# BOOK-5: Transparent Proxy Abuse
Attackers abuses corporate web proxy to make victim think that target website and attacker website are same origin. Victim connects to both same at same time | Caused by web proxy’s DNS lookup | Whitelist sites that can run flash (mitigation)

# BOOK-5: HTML5
Complete with Flash and Silverlight | Security is part of it | browser directly supports video and audio playback, flash required | webm is the free alternative | <video> <audio>
Session storage (guard against accidental refresh, scope=same tab) Vs local storage (persistent, Same Origin access via JS)
IndexedDB (JSON key/value storage) for browser content / not related to Web Database
HTML5 offline application: cache pages; manifest files define content to be cached; 
	<html manifest=”offline.manifest”>
Sample manifest file for browser cache:
			Cache: files to be cached on browser side
			Network: files to be only accessed when online 
			Fallback: backup page for files referred by app but not exist in cache 
FileAPI allows JavaScript interaction with local filesystem on client side. Allows drag-drop of files to browser. FileUpload() requests can be sent over XHR w/ better upload interface.

HTML5 WebSockets: bi-drectional | ws: and wss: | full duplex | Persistent (not periodic polling like COMET) | Uses HTTP header to establish socket connection
-	Still immature development
-	Not proxy friendly
-	Uses server side frameworks
(node.js, WebSocket-Node,Socket.io)

HTML5 Iframe Sandbox: Attribute supported by recent browsers | protection to access parent DOM to execute scripts | 
•	allow-same-origin: treat content as same origin/parent as by default Iframe sandbox considers as separate origin
•	allow-top-navigation: navigate content to top level browsing context
•	allow-forms: Enable forms on IFrames
•	allow-scripts: Enable scripts within IFrame
HTML5 cross-document messaging: Message from one IFrame to another Iframe OR one domain to another | XSS prevent by design
-	receiver to perform input validation
window.addEventListener('message', receiver, false);
	function receiver(e) {
		   if (e.origin == 'http://example.com') {
			      if (e.data == 'Hello world') {    # Input validation
         			e.source.postMessage('Hello', e.origin);   }
				      else {          alert(e.data);        } } }
New HTML5 input fields: tel, url, email, search / canvas elements (blank area) / validations added for input forms 
	<input type=’tel’ pattern=’\d\d\d\d\d\d\d\d\d\d’>	or 	<input maxlength=’10’>
Safari and Chrome: No warn on fail validations
Geolocation is part of HTML5: JavaScript and browser addson can access user location information. This works only over TLS (enforced by browser). Can be spoofed | not trustworthy


# BOOK-5: HTTP Parameter Pollution
HTTP allows multiple values for same variable name in requests.
ASP.NET: concatenates values: key=val1,val2 | PHP/Apache: last value: key=val2 | JSP/Tomcat & Oralce & Servlet & Perl CGI/Apache: first occurrence: key=val1 | Python: Array
-	within platform API, there is an inconsistency: getParameter() returns first value | getParameterValues() return array of strings
-	WAF detects SQLi when SELECT and FROM are in same parameter but skips it when SELECT is in one parameter and FROM is in another parameter


# BOOK-5: Web App Operational Security
Google webmaster tool: Manages Google indexing (faster/slower or removing URL ) | Search engine optimization | Email alert on malware
Google safe browsing screen shot. 
Web deployment security: WebDAV, SFTP, Windows File Share, Rsync (sync file across two machines), Git, Container transfer, Deployment to all load balancers 
Backups + Domain name registrations (use registry lock) + Failover (manual or automatic; DNS/BGP/LB/PC swap): beware of link latency & connectivity issues cause data integrity issues + Make use of CDN (Content Delivery Networks) + SRI (Sub resource integrity): Indicates hash of remote content (SHA256/384/512) | If remote host doesn’t support COR (cross origin req), req will fail and security error message is thrown. https://www.srihash.org/


# BOOK-5: Tokenization
Protect sensitive data by making and using tokens out of sensitive data | Alternate to encryption


# BOOK-5: Unicode
ASCII: 128 total characters | 94 printable | 33 control chars (spacing, now obselete) | A = 41 (hex) and J = 4A (hex)
-	In ASCII, 1 byte can be only 256 chars max. Asian languages have 1000 of characters
-	May have visual character issues (lookalikes)
Encoding: Letter (A) points to a code point and B points to another code point. 
2 types of CPUs: Little endian and Big endian. | BOM (Byte Order Mark): FF FE (then swap it) or FE FF

2 Unicode encoding schemes: UTF-8 (web, space efficiency, flexible; XHR uses UTF-8; backward compatible with ASCII; 1-4 bytes long; can be used for all languages in the world) and UTF-16 (used in platforms; 2-4 byte long; Windows & Java). 
Representation: “Latin capital letter A” with code point U+0041 (41 is hex number)
-	ISO-8859-1 is dying slowly, giving way for UTF-8

Punycode: way of representing Unicode domain names using ASCII chars. Punycode starts with xn--
IDN (International Domain name): Registrar has the responsibility to prevent spoofing
-	Chrome and IE browser show based on user setting language
-	Opera uses Whitelisting approach
-	Firefox evaluates based on single or mixed scripts (displays punycode for those not whitelisted and has Unicode chars)
.org is whitelisted TLD by Mozilla.
Non-visual security issues like processing the lookalike domains is another issue.
Normalization: Transform Unicode text into normalized form | For text comparison, search or sort | 4 ways to normalize:
-	NFD (canonical decomposition), NFC (first decomposition then composition), NFKD (compatibility decomposition), NFKC (first compatibility decomposition then canonical composition; simplest form equivalent to original source; one char can max become 18 chars)
o	NFKC may cause buffer overflow problem 
Canonical normalization: character composition or decomposition
Compatibility normalization: equivalent of two characters

Best-fit mapping: As there are >100K Unicode in the world, our OS will not have all of them. So OS does best-fit mapping to replace the unavailable ones with lookalikes.
Best practices for Unicode: Use latest version (12.1) | conversion is dangerous, use same encoding | UTF-8 is recommended by w3c | Disable best-fit mapping | NFKC normalization for validation | normalize before validation | educate developers on Unicode | Use standard libraries.


# BOOK-5: SSO & Session Sharing
3 aspects to consider when sharing user ID: Session + Authn + Authz
-	Authn session info transfer: Secondary session info exchanged via back-channel (e.g. VPN).
-	Subdomain cookie: A form of wild card for all subdomains of sans.org:   .sans.org
Crypto token: when just user id info is needed to third-party (back-channel like a vpn is a overkill) and the domain is different (sans.org to giac.org)
Federated identity: between 2 business partners or between departments in one org, if they maintain their own users DB.
Attribute-based access control: Special form of federation | balance between privacy & security | exact identity is not required but a particular attribute

OAuth: It is an authorization standard / authorization. Users information shared across domains after authentication. / valet key
Security compromise or attack at 3rd party site doesn’t affect main authentication provider.
Steps:
1.	Bit.ly registers with Twitter and gets client_secret from Twitter. 
2.	User login into Twitter and allows posts_view to Bit.ly; where Twitter sends a one-time usable Authorization_Code
3.	Bit.ly sends Authorization_Code to Twitter to validate it and asks for Access_Token (changes after certain period) and Refresh_Token (most secretive and never expire)
4.	Bit.ly uses Refresh_token to get new access_token after its expiry
5.	Bit.ly uses access_token to view user’s posts
OAuth Security issues: user pwd change on Twitter doesn’t alter the refresh_token given to 3rd party app already | Users may give their twitter password away to Bit.ly (Phishing) | Bit.ly ability to store refresh_token | Application security issues | CSRF is not inbuilt into OAuth | HTTPS is a must | Need to check redirect_uri for any code leaks

JWT: Header.Payload.Signature  	//format 	|  Digitally signed with secret or public/private key. 
OpenID Connect: One login for multiple sites | ID token in JWT format | set of claims for user


# BOOK-5: IPv6
16 bytes/128b | Hexadecimal | First half: Network portion & second-half is interface ID (mac address) | Last 64b can be used as global cookie | Can be changed on reboot | Can be abbreviated | Perform i/p validation (IPv6 allowed/required?)
Routable IPv6 start with 2 or 3 | 2001:db8… used for examples | fe80:… for local traffic | ::1 = loopback | :: = any IP address
 Corporate IPS are blind to IPv6 | Connection over tunnels / Teredo service: Hosts establish tunnel, even if they are behind IPv4 f/w


# BOOK-6: SDLC
Secure SDLC: Identify & reduce risks early | Save resources to fix security issues later | 
Roles: Developer (code standards, secure code, no access to prod) | QA (validating code, code in test env without modify, ensure it meets requirements) | InfoSec (coordinates with dev and QA for min security, might need access to both dev and prod)
Validation: Testing in early phases
Stage-0: Education & Awareness (Microsoft SDL)
Stage-1: Project Inception (assign security advisor, identify teams, security bug bar)
Stage-2: Cost Analysis (security requirements, privacy impact by P1/P2/P3, define risk level)
Stage-3: Design phase (functional spec, security design review)
Stage-4: Design phase – Risk analysis (threat modeling, document privacy analysis)
Stage-5: Implementation (Documentation for security, user needs to be educated on using software securely)
Stage-6: Implementation – Best practices (Apply secure coding, Code analysis tools, Standard APIs)
Stage-7: Verification – Testing (Verify security features, cannot be bypassed, pen test starts here)
Stage-8: Verification security push (team wide effort as last checks on security)
Stage-9: Pre-Release privacy review (update privacy questionnaire, complete privacy disclosure, address privacy req before release)
Stage-10: Response planning (plan for security and privacy incident, complete Emergency response plan, ready for zero-day)
Stage-11: Final security and privacy review (final security review, file exception if SDL req is not met, secure to ship?)
Stage-12: RTM/RTW (Release to Manufacture / Release to Web)
Stage-13: Response Execution (Being ready to execute planned response, ongoing task)

Other SDLC: OWASP CLASP | Cigital TouchPoints
Threat Modeling: Attacker-centric (can start only after most of dev is finished) & System-centric (done at any phase of SDLC)
STRIDE	| 	SDL tool process: Diagram (processes, data stores, data flows, trust boundaries) -> Identify threats (as team/brainstorming) -> Analyze controls vs threats (exists and configured?) -> Mitigate -> Validate -> Diagram

Attack on Serialization & Deserialization
An attacker may attack the serialization process by sending a gadget within a stream to attack the server accepting the string. Once the serialized string is received at the entry point, the deserialization process starts and if the class being referenced in the stream is a class that is already loaded in memory then the injected object will get deserialized. The additional objects within the gadget could lead to harmful effects within the system, most commonly invoke arbitrary code to be executed. Once the data is deserialized, it is then read and cast back to a specific data type. With the injected object in the stream, this cast action will likely fail because the data format does not match. However, at this point, the malicious code has already run, and the failure to cast the data is a small and insignificant consequence.

Subresource Integrity (SRI) specifies an integrity check hash value on the remote resource when defining the link to the resource within HTML. This checksum provides validation of content to avoid unauthorized/unexpected changes.
The SRI can also allow validation of the authenticity of remote resources. The remote website will have to explicitly allow and recognize such a call by responding to COR (Cross-Origin Request) with the proper response header. The browser will treat the request for a resource in a foreign domain as COR when SRI is specified. Only if the remote resource explicitly states that remote request is allowed will the browser validate the checksum. If the remote host does not support COR, the request on the resource will fail with a security error generated.
