# BOOK-1: Foundations of OSINT
Privacy: Social media sites urges us to connect to everyone, creating web of people.
Data once put into social media cannot be completely erased | There are other sites where users cannot prevent data from being published (e.g. government data, real estate info, etc.)

Data brokers can buy/sell data of people without first asking them

Raw Data -> Information (Processing & Exploitation) -> Intelligence (Analysis & Production)

Three goals of this course: Focus on process | Leverage the tools | Practice all of the above

# BOOK-1: Understanding OSINT		(2/9)
What is OSINT: Information accessible in the public domain / sources (media, text, maps)
-	SOCMINT: SOCial Media INTelligence
-	Collection, Organizing and Analysis are the three key steps
OSINT Cycle: Requirement gathering -> Retrieving data -> Analyze Info -> Pivot to new perspective or Report analysis
Open Source Data (OSD, raw) | Open Source Information (OSIF, processed) | 
Open Source Intelligence (OSINT, securitized)
Requirement gathering: Discovering client goals: scope, time, output, how much covert, any pre-info
Retrieving data: Straight-forward step | record and download
Analyzing data: transform data into information through analysis |             
                          relevant? accurate? objective? credible? corroborated? pivot-point?
YOGA: Your OSINT Graphic Analyzer: https://yoga.osint.ninja/
Pivot to new perspective and reporting: if more data is needed, we pilot. Else report. 
-	Reports have data, information and analysis

# BOOK:1 GOALS for OSINT Collection	(3/9)
OSINT for good reasons: Law enforcement agencies use OSINT for criminal networks (tattoos, etc.), online postings about suspects (e.g. wanted posters in social media). Some of our friends can turn us to police (e.g. Michael Brown) | some people don’t know that police are monitoring social media
-	Including video surveillance
-	Dark web monitoring (those selling drugs, guns, and credit cards illegally)

1.	Trace Labs OSINT: with support from local law enforcement officers, they conduct OSINT CTFs.
2.	EUROPOL’s stop childabuse site has objects to recognize by OSINT people.
3.	The BADASS army: Using OSINT to combat non-consented pornography (NCP).
4.	Innocent lives Foundation: They unmask online child predators and bring them to justice
5.	Parents, Spouses, and Partners can use OSINT for hunt for cheaters
6.	Businesses use OSINT: to find competitive intelligence on rivals | hiring/interview | malicious insiders, M&A, legal support, protect systems from attacks
7.	Media uses OSINT (eyewitness accounts, researching stories) but lacks analysis/context
a.	BBC journalists uses OSINT
b.	Bellingcat teaches investigative journalism showing OSINT techniques
8.	Intelligence agencies uses OSINT

OSINT for bad reasons: Cyber Attack, Theft, Extortion, Assault, Kidnapping, Organized crime, Terrorism, Stalking, Harassment, bullying, criminal mischief, etc.
-	Strava & MapMyRide apps were misused by thieves
-	Mexican cartels use social media to extort money from family members of their hostages

# BOOK:1 Diving into the Collecting	(4/9)
Questions to ask OSINT customers to understand the scope: 
1.	What is successful assessment for them? 
2.	Motive? Legal counsel consent on customer side? Full research or a short question? etc.
3.	Output report format? Data handling during and after the project? Covertness? 
Good practices for OSINT:
Use reliable process | Gather requirements before working | Be aware of your network traffic and what it gives away | Understand and properly configure your system | Don’t use personal accounts for work | Document everything

# BOOK:1 Taking excellent notes		(5/9)
Journey taken is more important than the result itself in OSINT.
Detailed documentation helps to answer the “WHY” the OSINT in the first place.
Benefits: Publishing results on blog or papers | Lasting impression with customer | Follow-up | Support of law-enforcement, intelligence customers, and legal entities
Other teams use our OSINT doc as starting point:
-	Incident responders, Malware analysts, Law enforcement, Another OSINT analyst, Legal team

Level of documentation is driven by customer needs, and industry (along with tools used)
“Record Everything” should be the default.
-Posted images, tool screenshots, pictures of web pages, URLs, times and dates, Use of sock puppet accounts, Professional APIs, Google? Use of web browser or any tool to discover the data, etc.

Documentation tool types: Visualizers (i2 Analyst notebook,
Tableau, Maltego Casefile (free, import csv, API token), 
Gephi (free, used for large data sets, Win/Linux/Mac) ) 
| Note taking apps (OneNote, Evernote, Keep, MindMaps)
| Documenting apps (Hunchly, Paliscope, MS Steps Recorder) 
| Word processors/Text editors (Word, Notepad++, VIM, etc.)
-	Creating and using a repeatable process is key!

Maltego: basic transforms | can build own | download transforms | buy transforms f/ commercial hub
Hunchly: Takes pictures as we browse | Add ‘selectors’ to highlight | URLs, images, by page, hash & time
Paliscope: macOS and Windows case documentation tool | built-in web browser (surface & dark web) |  Links “cards”
Microsoft Steps Recorder: Modern windows | Records: Desktop, keystrokes, mouse (move & click), date

Screen capture: MAC (Command-Shift-3: full screen picture | Command-Shift-4: rectangle screen | Command-Shift-5: video recording) 
Windows (Prt Scr: full screen picture | Alt-Print Screen: captures active window | Windows-G: video record using gaming bar)
-	[Third-party tools]: FastStone Image Viewer | Snagit | Shutter (Linux VM) 

Altering captured images: e.g. Blurring sensitive or distracting info on pictures | (Boxing) Add circle to draw attention | Focus viewer, etc.

Timeline generation: Need to establish the order of events occurred | can use MS office apps (word, ppt), MindMaps (XMind, FreeMind) have timeline layouts, Aeon timeline, Timeline by knight lab

# BOOK-1: Determining your threat profile	(6/9)
Level of openness: OVERT (public, non-anonymous) | Covert (low-attribution, deniable, secretive) | Clandestine (Unattributable and concealed)

Three important questions to perform OSINT: Who are you? Where are you? What are you looking for?
-	Need to look for common disclosure issues
EFF’s https://panopticlick.eff.org/ tool helps to discover the web browser’s tracking capability

https://browserleaks.com/ can provide amount of information leaks that can happen from our browsers
https://whoer.net/ and https://www.deviceinfo.me/ provides IP and Host info that is leaking
Some ToR exit notes are run by criminals, intelligence agencies. Some of these do recording, blocking, or altering traffic.

Google’s tailored search results (based on you) can hurt OSINT results, analysis, and outcome.

*** Websites to search to know about ourselves: https://the.osint.ninja/optoutdoc ***

Michael Bazzell ‘s book on extreme privacy and Hiding from the internet (free PDFs exist)
-	https://inteltechniques.com/data/workbook.pdf

# BOOK-1: Setting up and OSINT platform 	(7/9)
Systems to use for OSINT: OS, Physical / VM / Cloud, mobile phone (real or emulator)?

Basic reqs: Affordable to use | Free from infections/compromise (trustworthy) | Reliable | Cleanable | Multi-user & remotely accessible | Availability | Graphical | Ease of updates

OSINT systems: Buscador VM (end of life)| Web browser isolation vendors (Authentic8, Web Gap, Cigloo) |  https://nixintel.info/linux/build-your-own-custom-osint-machine-diy-buscador-part-1/
https://www.browserstack.com/
-	VDI: Apache Guacamole

MiFi -> Wireless Router that acts as Mobile Wi-Fi hotspot.

VPN comparison site: https://thatoneprivacysite.net/#simple-vpn-comparison
Can build our own VMs too: https://openvpn.net/access-server/pricing/ OR https://github.com/StreisandEffect/streisand (Cloud API keys are required)

First choice for web browsers for OSINT people are those that provide extendable features (plugins).
-	Increase privacy, record info, protect systems, gather more data, etc.

Browser extensions

OSINT Data storage: How long to store? Files names? Where to store? Encrypt (disk level encryption must be mandatory): Windows (BitLocker) | macOS (FileVault 2) | Linux (LUKS, Linux Unified Key Setup)
-	Containers (VeraCrypt): https://www.veracrypt.fr/en/Home.html

Mobile devices: Some OSINT work only by using mobile phones | Android Emulators (NoxPlayer, GenyMotion, BlueStacks, Android SDK) | iOS/iPhone/iPad Emulators are also available
-	User-agent change on browser extension OR by developer tools can emulate as mobile browser 
https://www.youtube.com/watch?v=r9bMGKET8xg

Manage sock puppet accounts, registered sites, paid services, etc. via password manager tools (local [KeePass, PWSafe] vs cloud [1Password, LastPass, Dashlane]): Cost vs. Accessibility vs. Software upkeep.

# BOOK-1: Effective habits and process		(8/9)
Good research habits: Work efficiently | Stay in score | Stay safe in executing work | Prevent ethical conflicts | Segment customer data | Maximize resources

1.	Getting connected to the target (has pros and cons) | or target’s family, friends, co-workers?
2.	Be careful when engaging with the target (talk w/ legal, do not assume as gov., etc.)
3.	Finding sensitive data (need to have a procedure to implement, when you find it) e.g. CASM
a.	Child Sexual Abuse Material (CSAM)
4.	Searched info can be used against us (e.g. use of Chrome during OSINT can be used by Google to analyze us) e.g. the websites we visit, etc. are tracked by Google.
5.	Manage your time (start with trusted sites and work towards less trusted ones, start with one with good results, start with one with highly relevant data, consider increasing scope of investigation as time follows.)
6.	Use an OSINT process (reliable, be flexible yet constant, repeatable, maintain privacy of customers, explainable, meaningful results)
7.	Walkthrough a sample process
8.	Ensure a clean OSINT platform (free of previous investigation data, new sock puppet accts, etc.)
a.	Manually archiving and purging data from old system
9.	Acquire customer requirements (motive, legal, when results, what data already have?)
10.	Decide TTPs (Tactics, Techniques, and Procedures) & apply SOP (Standard Operating Procedure)
a.	TTPs based on able to engage with target, time available, etc.
11.	Use of IntelTechnique’s flowchart for OSINT process (Michael Bazzell)
12.	Start your note-taking (draw pictures and diagrams of connectivity) -> version controlled
13.	Gathering data (Core of the assessment) based on customer’s seed data
14.	Analyzing data (search and record): More challenging (what data means? truthfulness?)
15.	Repeating process (Collect data -> Analyze data -> Determine new collect goals -> Collect data)
16.	Create meaningful output for customers (least-liked portion) (Report, Email, etc.)
17.	Cleaning up the system (archive or scrub? Refinement of SOP?)

# BOOK-1: Leveraging Search Engines	(9/9)
Need to examine search engine’s capability to expose the OSINT work | Search engine’s do not index everything (robots.txt file must be manually reviewed for contents) | Best search engine is the one that gives the data needed

https://ddg.gg (duckduckgo, privacy focused)

Yandex (Russian):
Has unique
search operators:


Google spiders 20 billion sites per day. Indexes for customized searches.
	
GHDB: Born in 2002 | Johnny “ihackstuff” | Has google dorks (filetype:xls intitle:password)
	
	
	We can create our own Google dorks & submit it to GHDB
	Exploit Database’s GHDB search can help too!
		(can browser data by category): 4000+ dorks in GHDB

Google Trends Tool can provide info for OSINT people on local researches (popular googling info).

Carrot2 : Open source search results clustering engine: Can block access from ToR and cloud services like AWS EC2 | Filtering search results is simplified with this tool

# BOOK-2: Data Analysis Challenges	(1/10)
Questions to ask self during analysis: Is the data true? Could it be false? Is it useful for assessment? Any corroborating evidence to support this?		//even trusted sources can have bad data

Reasons for inaccurate data: Proactive measures by target (false trail) | Unintentional incorrect data | old data not updated | Similar target names | Human nature (bragging, appearing to be someone)

OSINT researchers must not jump to conclusions quickly | Any type of Bias can affect the research | False generalization (people in that country use that website) | Correlation (two related events) doesn’t imply (but maybe) Causality (direct relationship/cause and effect) | False Dichotomy (reducing possibilities to this or that) | Discarding unfavorable data (that doesn’t seem ‘fit’) | Sound analysis

2007, CIA released book (PDF): Richards J. Heuer, Jr.’s work. Psychology of Intelligence Analysis
-	ACH (Analysis of Competing Hypotheses) to reach sound analysis
https://www.cia.gov/library/center-for-the-study-of-intelligence/csi-publications/books-and-monographs/psychology-of-intelligence-analysis

# BOOK-2: Harvesting Web Data		(2/10)
Not just from web browsers | HTML source code, APIs, HTTP traffic | Use of web proxy servers, command-line tools, script, cache content, etc.
-	urlscan.io	//scans from the server, not from our browser

Identify technology profile: 
https://builtwith.com/ & https://sitereport.netcraft.com/
-	These tools examine response content and provide details

Command line tools: Has pros and cons of using this approach [wget
    ==>
- Installed by default in Linux and macOS
“-nd” flag to wget puts all retrieved files in a single directory

curl: submit or retrieve specific resource instead of all of them (“-A’ can change user agent string)
 

Find content via built-in tools: grep, findstr, etc.
pdftotext (Linux): 
 
“-E” is for defining regex pattern | “-i” ignore case | -A2 -B2 (2 lines after & before matched strings) 

grep for email addresses: => 

-o show only matches | -h not filenames

grep for US phone numbers: => 

For international phone numbers: https://www.regextester.com/

Mythicsoft tools: Agent Ransack (free) | FileLocatorPro (~60$) => 
A GUI on windows to search for contents in file | Can use regex 
| Simplifies searching

Can also use Python or Ruby to search for content in files;
    https://github.com/automatingosint/osint_public (Justin Seitz)
EyeWitness Python tool: Free | Chris Truncer | I/p is list of hosts & protocol (Web, RDP, VNC) | Records screenshots and response headers data | HTML report
https://www.christophertruncer.com/eyewitness-2-0-release-and-user-guide/
-	Heavy JavaScript based sites could fail the eyewitness tool

Web browser extension: “Instant Data Scraper” can instantly export data to CSV or xlsx.
https://webrobots.io/instantdata/

APIs are format to retrieve data in computer-friendly format | XML or JSON output | Can access pages those not allowed by typical web browser | Refer to API documentation (swagger)
-	Default view of JSON in web browser (Firefox is better than in Chrome) | JSON beautify extension is required in Chrome

GCHQ’s CyberChef tool for formatter and extractor | Public APIs: https://github.com/public-apis/public-apis/blob/master/README.md

Fully cached content sites: Archieve.org | Archieve.is (privately funded site, cache images, JS, text, fewer backups than archieve.org) || Search engines also cache content
   To prevent search engines to connect to website and only show cache content: add &strip=1 in URL
-	Archieve.org uses waybackpack tool: https://github.com/jsvine/waybackpack
-	We can also manually retrieve content from sites to cache (replace YOURURL)
 
-	Browser extensions exists (View Page Archive & Cache) to search multiple archieve sites easily by image or other content

Google’s mobile-friendly test: Sometimes Google can access web pages that users cannot due to authentication issues | Use https://codebeautify.org/htmlviewer/ to paste & view copied HTML

Google AdSense & Analytics: pub-12345678 and UA-87654321 | retrieve these & compare in other sites

Google Analytics Search Engine: https://spyonweb.com/ | builtwith.com shows relationships on Google and non-Google analytics codes

HTTPS certificates have information to extract: Domains, IP addresses, Emails, Physical locations
HTTPS certificate transparency information

# BOOK-2: File Metadata Analysis	(3/10)
Metadata includes: usernames, GPS locations, dates and times, file locations, timestamps (create, access, modification) | over 170+ file types that has different type of metadata information
-	ExifTool: Used to extract metadata information from a file
-	Windows file properties: can also provide file metadata information
-	macOS properties: “More Info” section
-	Online metadata extract: https://www.verexif.com/ and https://www.thexifer.net/ (OPSEC risk)
-	FOCA: Fingerprinting Orgs with Collected Archives: Win-only | Old | Useful when analyzing many files from a single domain
Even if metadata is changed in a file, the viewable contents of file remain same.

# BOOK-2: OSINT Frameworks		(4/10)
Collection of tools, websites, etc. for OSINT investigations | Frameworks transform one type of data (e.g. email) into another data (social media profiles) | https://osintframework.com/ (Justine Nordine)
-	Source: https://github.com/lockfale/OSINT-Framework (Works offline)

https://www.technisette.com/p/tools	(from Netherlands | works great for search in social media) 
https://github.com/IVMachiavelli/OSINT_Team_Links	& http://www.onstrat.com/osint/ & https://start.me/p/ZME8nR/osint (Bruno Mortier) & https://start.me/p/OmExgb/terrorism-radicalisation-research-dashboard (terrorists) & https://sec487.info/bellingcat (Bellingcat’s online investigation toolkit)

# BOOK-2: Basic Data: Addresses and Phone Numbers	(5/10)
Cannot stop such data being replicated in the internet
Why street address? Ties web data to physical location | Ties people to property | Can social engineer, physical penetration, surveillance against target, etc.
Addresses can be found at:
-	Public tax assessments | Real property records | search engines | Resumes | Business records & websites | Mapping websites | Real estate web sites
Why phone numbers? Could be user accounts | People and business usually do not change phone numbers
Phone numbers can be found at: Search engines, reverse lookup by phone numbers
Different challenges exists in searching for phone numbers online (e.g. number mapped to multiple people, etc.) | Can spoof mobile numbers (SpoofCard) | ukphonebook.com people searching in UK

# BOOK-2: Basic Data: Email Addresses		(6/10)
local-part@domain |  Local-part portion may be used as profile name on web | email address are user IDs on many sites | Can be used for pretexting and phishing | People search engines | Businesses usually have pattern in email (e.g. firstname.lastname@company.com) | Metrics Sparrow Permutator tool
https://metricsparrow.com/toolkit/email-permutator/ for automation of email address possibilities

https://hunter.io/ or https://www.email-format.com/ (has many companies email formats)
Email validation: https://mailtester.com/testmail.php	(OPSEC warning: could inform target)

Tools to get bulk email-addresses: SpiderFoot | Recon-ng | theHarvester (Python, Free, Christian Martorella, Input is domain name “-d sans.org -b <source>”, source can be google/bing, etc., Output is ip address, domain names, email addresses)

# BOOK-2: Usernames		(7/10)
Why usernames? Usernames tie to activities and relationships of target | Username itself may have a meaning | may have mutations of the same username (e.g. dreadpirate1, Dr34dP1r4t3)
OSINT for usernames: Find all userIDs of target | and associates websites | retrieve data from profiles | Examine relationships | Examine activities | Pivot and repeat
Sites to use: https://namechk.com/ and https://checkuser.org/	(results require further validation)

Google search:  
https://github.com/WebBreacher/WhatsMyName (Micah Hoffman tool) | open source
-	web_accounts_list.json has site name, URL, codes, valid accounts, categories, validity, etc.
-	automate user enumeration on fast scale | Exact URL of target
o	This json file is referenced in spiderfoot and recon-ng’s profiler module (Micah’s)
o	recon-ng allows multi-threading for more faster results | results are in local DB
	Requests are made from recon-ng hosting system

Connecting social media accounts together: https://about.me/ and https://keybase.io/
-	keybase.io can cryptographically connect accounts of user | Only user knows password for keys
o	Contains user’s computer names | devices | user transactions are public | Public API (API can be used without any authentication)

#  BOOK-2: Avatars and Reverse Images searches		(8/10)
Avatars: personal pics used on web sites like social media, forums, comments, reviews, and other places | Art, Photos, Computer-generated image (random) | Retrieve and store all
Avatars for OSINT: Possible false positives | Friends / connections of this avatar
Facebook = Friends | LinkedIn = Connections | Twitter = Followers

Avatar across sites = A Globally Recognized Avatar = Gravatar = https://en.gravatar.com
-	Upload once, other sites will pull from gravatar.com
-	http://[language].gravatar.com/profiles/[username]	(.xml or .json can be appended at end)

Profile page HTML has username, location, interesting quotes, web site, the avatar, JSON content
-	JSON has more data for OSINT purposes

Reverse Image search: Question to ask: Why is this avatar in these search results?
-	Only for unauthenticated websites that have been crawled
-	May need to crop the image before searching
-	Every image URL need not end with image extension; then download image and search for it

Three top reverse image search engines: Google. Bing, Yandex (Yandex has live cropping)
-	“Search by Image” browser extension on Firefox and Chrome can speed up searching
Tesseract: Extract text from images | Object Character Recognition (OCR) | cross-platform | command line | $tesseract IMG OUTPUT -l LNG (has language packs)
https://github.com/tesseract-ocr/tesseract/wiki

# BOOK-2: Additional Public Data		(9/10)
Registries and Wish Lists: E.g. wedding websites (couples create for publicity), bought gifts, pivot & repeat! | Videographer’s blogpost | Details of content in Vimeo videos | Search by hashtag | LinkedIn profile and marriage license / certificate | Obituaries and death data (legacy.com) (SSN becomes public at death); Obituaries exist for USA, UK, Ireland, Australia, Bermuda, New Zealand, Canada | Newsletters (Google knows about newsletters), years of data |  Data aggregator companies (e.g. Melissa global Intelligence); 3 user types: anonymous/guest; free user; paid user; property and person finder |  

registryfinder.com | myregistry.com | theknot.com | thebump.com | honeyfund.com | Many online retailers like Walmart, Target, Macy’s have registries

Memorial sites: forevermissed.com | ilasting.com | mem.com | Qeepr.com | remembered.com | tributes.com | yourtribute.com | US gov. sources for death records (1936 – 2007)

# BOOK-2: Creating Sock Puppet Accounts	(10/10)
DO not use personal accounts for OSINT | Use Sock puppet accounts (fake accounts for work purpose) | Consult local legal department before use | For long-term OSINT, you need to take the role of sock puppet in!

FakeNameGenerate.com | MySudo app (free/paid) on iOS phones | thispersondoesnotexist.com (Uses Generative Adversarial Network)

Email ID Strategies: Setup real account in Gmail, Yahoo, etc. => Use email forwarder to send emails to our address or use mailinator.com OR guerrillamail.com OR 10minutemail.com OR 20minutemail.com 

Phone Strategies: Buy and use burner phone | Google VOIP or Skype | Online SMS: textnow.com OR freeonlinephone.org | receivefreesms.com

Long term problems with sock puppet: Sites may discover the account as sock puppet | Researchers look for it | Someone may report it (e.g. Lack of site use, Lack of profile info, Lack of avatar, etc.)

# BOOK-3: People Search Engines		(1/7)
Free people search sites: peekyou.com (aggregates data) | thatsthem.com | truepeoplesearch.com | cubib.com/xlek.com (US public data e.g. whitehouse, voting) | zabasearch.com | radaris.com | 192.com (UK, electoral & businesses, AtoZ search) | infobel.com | emailrep.io (email reputation service)

Paid people search sites: pipl.com | intelius.com | spokeo.com | beenverified.com | skopenow.com (international) | tracers.com | tlo.com | irbsearch.com | 

# BOOK-3: Facebook Analysis	(2/7)
Data found in FB: Photos of targets | Videos | Likes/Dislikes | Friends | Group memberships | Locations target has been | Events invited or attended

Advertisers deliver message where OSINT people collect data

Facebook graph changes: drastically changed in summer of 2019!
Facebook IDs: unique per account (entity_id, from view source), per page (page_id), per group (group_id, from browser URL bar)
-	Profile_id could depict the account creation date as ID increased with time

Search using Facebook search: /search/top/?q=<search_item>&epa=SEARCH_BOX
Search Facebook posts: /search/posts/?q=<search_item>&epa=SERP_TAB
Search Facebook people: /search/people/?q=<search_item>&epa=SERP_TAB
Search Facebook photos: /search/photos/?q=<search_item>&epa=SERP_TAB
Filters in Facebook are JSON objects that are Base64 encoded. (A-Z a-z 0-9 + /) 

Refine search with Filters (e.g. City): /search/people/?q=<search_item>&epa=FILTERS&filters=<base64>
-	Base64 encoded string is JSON with location’s entity ID
https://sowdust.github.io/fb-search/ can be used to search by using respective entity_id values

https://osintcurio.us/2019/08/22/the-new-facebook-graph-search-part-1/ has list of possible filters

Facebook Directories: unauthenticated pages | Kirby Plessas maintains the list of these

Resolve email to an Account: Use page roles (under create a new page section) resolves email ID to a Facebook account.
-	Can obtain Facebook ID using the browser tools: Response JSON content
 

Facebook Ad Library: https://www.facebook.com/ads/library/?active_status=all&ad_type=all&country=ALL
-	Who is trying to influence who?

# BOOK-3: LinkedIn	(3/7)
Access levels: Public profile | Authenticated users only | Restricted private data
Purchase options: Career | Business | Sales | Hiring
OSINT data: Ties & connections | what-users like | personal data | groups joined | who works for certain companies
What can we do with data? Pretexting | Phishing | Email harvesting | Connections analysis

https://icwatch.wikileaks.org/: Similar to LinkedIn | provides: Names, Emails, Phone numbers, Jobs
LiONs: LinkedIn Open Networkers | Accept all connections | Good people to target with our sock puppet account | LiONs can export contacts data
Connection to a person share: Name, Company, Email, Position | We can export contacts
https://booleanstrings.com/ : Inner workings of LinkedIn | Blogs for harvesting data, people
CSEs (Custom Search Engine): Advanced methods recruiters use to gather data of people on LinkedIn.

https://www.linkedin.com/sales/gmail/profile/viewByEmail/EMAIL/   Look up account by email (private profiles do not work with this approach)

# BOOK-3: Instagram	(4/7)
Image and video sharing site | Mostly mobile app | Public and private accounts
OSINT data: Image content | When and where | User relationships | Username harvesting | Email ID and Phone of target (mobile app only) | Hashtag monitoring
Offline viewing of public content: https://t-g.club/ and https://www.piwox.com/  (pictame.com)

Instagram User ID: In view source: profilePage_<id>

Google chrome extension: ‘Helper Tools for Instagram’ https://chrome.google.com/webstore/detail/helper-tools-for-instagra/clibiflfecckdjnjcgcgjdknmbgceail
-	Retrieves account data, followers, comments and likes on posts
o	Brief and Full output (excel file)
	Username, Full name, User_profile_url, Biography, Is_Business_account

Chrome extension for Downloader for Instagram + Direct Message (Search for hashtag, people, places)
https://chrome.google.com/webstore/detail/downloader-for-instagram/olkpikmlhoaojbbmmpejnimiglejmboe

Get info from Instagram mobile app or API 	[Business profiles must have email and/or phone]

Authenticated API calls to obtain Instagram profile data: https://i.instagram.com/api/v1/users/#/info/ 
-	Change user agent to look like mobile app (iOS or Android)

Unauthenticated way to retrieve private and public profile information: https://www.instagram.com/<USERNAME>/?__a=1
-	Private profile data obtained is less than that of public profile

Unauthenticated API can be used for public posts contents | JSON | except actual media, every other info can be retrieved

To get info about private accounts, look for public profiles that have comments from this private profile user or any other public posts from private profile.

For keyword search in Instagram: On Google search: inurl:Instagram.com/p/ “KEYWORD”

For search of content in Instagram profile’s bio: https://www.searchmy.bio/search?q=frustrated

Download all public Instagram posts: Instragram-scraper python tool | Has comments, locations, tags and metadata info 
To retrieve files and metadata: Instaloader tool | Comments, geotags, etc. from Instagram posts

# BOOK-3: Twitter Data		(5/7)
<= 280 characters per tweet | microblogging site | Direct message, Gelocation, Hashtags, Followers

OSINT data: Account bio, URL, location, Connection between targets, patterns of behavior (sleeping, drinking alcohol), pics, videos, geotagging, sentiment about a topic

On Twitter search page: Search for accounts, people, keywords, hashtags
On Twitter advanced search page: Unauthenticated search | Amit Agarwal’s twitter search blog post
https://osintcurio.us/2019/08/01/muting-the-twitter-algorithm-and-using-basic-search-operators-for-better-osint-research/

Twitter cheat sheet:

https://pbs.twimg.com/media/Dr2Fht_U0AE06BC.jpg:large

APIs:

firehose: paid API that guarantees to send all tweets
matching our query terms
https://developer.twitter.com/en/docs

Tweet analysis
1.	Sleepingtime.org (based on tweets)
2.	Analyzewords.com

Authenticated and Unauthenticated tweets analysis
https://socialbearing.com/  (Free)
-	Filters (Tweet_Type, Sentiment, Top Contributors, Top hashtags, Top Mentions)

https://twopcharts.com/ (free, public twitter user analyzer) | No API and no authentication | Analyze tweets, time of tweets, last 100 followers, and historical number of followers

Twitter follower’s analysis: https://followerwonk.com/bio/?q=%22searchme%22
Search for location on Twitter: near:<location> within:15km	| near:37.334,-122.010 within:20mi
Search for location with keyword: <word1> OR <word2> near:<place> within:15km filter:images 
http://geosocialfootprint.com/  Tracking a twitter user (based on tweets done with geolocation)
https://onemilliontweetmap.com/ => Enter keywords or hashtags and view tweets from a location

Deleted tweets can be recovered from archive sites.

Scraping and visualizing twitter mentions: https://medium.com/@Dutchosintguy/scraping-visualizing-twitter-mentions-520a6277eb8b (DMI-TCAT, Digital Methods Initiative Twitter Capture & Analysis Toolset)
-	Collects and analyzes tweets over time

Bot and propaganda analysis of twitter account: time of tweets | sources | # of followers | profile pic
https://makeadverbsgreatagain.org/allegedly/ => web app for time-based analysis of tweets per account

https://tweetbeaver.com/ => Tools to investigate a twitter account | Requires authenticated twitter account | retrieves data using Twitter API | rapid in results
-	Can download last 3200 tweets (display on screen or export as CSV)

Tinfoleak script: Python w/ GUI | https://github.com/vaguileradiaz/tinfoleak | Need API keys

TWINT: Twitter Intelligence Tool: Free | Python | Francesco Poldi | Display results on screen or store in CSV, JSON, databases, ElasticSearch | No API and No authentication for twitter required 
     
# BOOK-3: Geolocation		(6/7)
OSINT data: Locate people (missing), relationships between people (at same place) | 
Faking a location is easy (but can be spotted with careful analysis)

Mobile apps that can Geolocate users: Tinder | Strava | Untappd (Alcohol) | Foursquare | Facebook
https://map.snapchat.com/ : Heat of map where people are snapping | More red means more activity in that area | Use exercise maps to determine work/home locations | 

https://www.strava.com/heatmap#13.66/23.72046/37.95705/hot/all | Strava heat map | Aggregation of tracked exercises along a particular route | 
-	Turn on satellite view and investigate a bright spot in a desert => “interesting place”
-	Map shows number of people in that area too
-	Data shown in segments | Compete with each other | Data obtained: People, Date/Time of run 
https://www.doogal.co.uk/ => Strava segments via browsing map

Strava has a profile page with athletes pictures | When people post reviews about food and drinks, date and time stamp shows where they were

Untappd.com can be used to analyze alcohol consumption | People post they beer drinking with friends onto this site | private and public profiles / data available
-	https://github.com/WebBreacher/untappdScraper (python script to analyze public data)
-	Can watch a particular place to review number of people coming there to drink beer or number of times the target is visiting this place

https://www.echosec.net/ => PAID services to get intel from social media accounts using own API keys

Geolocation helper tools: Transforming GPS coordinates | Draw a circle of X kms around a location | Figuring out boundaries of location (city, village, etc.)
-	https://www.freemaptools.com/international-meeting-cog.htm (many features!)
-	https://mapdevelopers.com/ (elevation calculator, geocode tool, batch geocoding, mileage calc)
-	https://www.gpsvisualizer.com/geocoder/ (Convert into other formats, Bulk GPS encoding)

# BOOK-3: Imagery and Maps	(7/7)
Establishing correlations | War zone reporting | Change detection | Tracking terror | Access to the inaccessible | Adding visual elements

Imagery options: Satellite | Aerial/Bird’s eye (updated frequently) | Ground (Google street view, Bing Streetside, Yandex Street Paronamas)
Major players for Satellite: Google Maps (6 months to 5 years old), Bing Maps, Yandex Maps (has Aerial balloons)
https://www.mapillary.com/app/ (Street view)

https://earth.google.com/web/	=> Desktop, mobile, web apps | geotagged image aggregator

All views on one web screen => https://data.mashedworld.com/
For street and building numbers => https://www.openstreetmap.org/
Collaborative map: http://wikimapia.org/ (create regions & labels, Map and Satellite view, Distance)

Mapping web applications: go back in time and view locations (months or years) | validate metadata
-	Red color in direction of Google maps indicate north direction
https://calculator.ipvm.com/ => re-create the location and angle the image was taken (10,000+ models)

https://www.suncalc.org/ => Set GPS coordinates, set date, Sun slider changes sun position, shows time
-	Other site: https://www.mooncalc.org/

https://worldcam.eu/ => organized web cams around the world
http://www.insecam.org/ => Biggest directory of online surveillance security cameras/web cams
https://www.broadcastify.com/ => streaming radio feeds to web browsers | police,fire,medical,etc.

# BOOK-4: Whois		(1/8)
When domain names are registered with ICANN, data about who is registering it, is submitted.
Names, Addresses, Phone numbers, Email addresses, and other servers
https://whois.icann.org/en/basics-whois	(ARIN and RIPE services are easy to use)
Retrieve data from command line:
        
SpiderFoot has ARIN module to retrieve data => (e.g. Browser to ‘Email addresses’ tab & export as CSV)

https://www.domaintools.com/ => combine more data about target domain into a webpage
-	Registrar info, dates, NS records, website for domain, IP address history

With GPDR, whois is less useful now 
https://viewdns.info/reversewhois/?q= => reverse DNS lookup based on search string
-	Has API for purchase / for automated queries

To find domains with people having email address as: @sec487.info?
-	Reverse whois lookup of *@sec487.info will return all domains

https://securitytrails.com/ => Current and historical DNS data for a domain
https://domainbigdata.com/ => some of historical DNS data is not redacted, filtered, or masked
https://www.whoxy.com/ => free and paid | Forward and reverse whois query search | live & historical data | Web and API interface (JSON)

# BOOK-4: IP Addresses		(2/8)
Sometimes IPs identify device, network, company, or organization | Public IPs can be geolocated (not perfect but educated guess: https://whatismyipaddress.com/, https://infosniper.net/, https://ip2location.com/)

IPv4, IPv6 | Every device has one internal IP | edge device (router) gives its public IP for all traffic
https://www.whatismyip.com/ | https://www.ipchicken.com/ | https://whatu.info/

RIRs (Regional Internet Registries): LACNIC (https://www.lacnic.net/), ARIN (https://www.arin.net/), RIPE NCC (https://www.ripe.net/), APNIC (https://www.apnic.net/), AFRINIC (https://afrinic.net/)
-	IP, Names, Company names, emails, phone numbers, addresses

# BOOK-4: DNS		(3/8)
A, AAAA, CNAME, NS, MX, TXT records
From Windows cmd line: >nslookup | >Resolve-DnsName 
From other OS: $dig  |  $host		$dig +noall +answer sans.org   //for less-verbose output
From web apps: https://www.robtex.com/ | http://viewdns.info/ | https://dnsdumpster.com/ (free)
-	$dig -t all sans.org		OR 		$dig @1.1.1.1 sans.org
-	dnsdumpster.com has sample workflow / graphs connection between systems

DNS subdomains enumeration method: 
-	Dictionary attack | Zone transfer ($dig -t axfr sans.org) | Reverse or PTR record lookup

https://github.com/darkoperator/dnsrecon (Free Python script) | Carlos Perez | DNS enumeration
https://github.com/michenriksen/aquatone (Free Ruby script) |  Michael Henriksen | can also take pictures of websites using “gather” | Uses API to query shodan, censys, and others

Typosquatting (accidental mistake in spelling): https://github.com/elceef/dnstwist/ | Free python script
-	Find domain typosquatters
 
https://dnstwister.report/ (for Typosquatting, but FASTER)

Sub-domain enumeration tool: https://github.com/aboul3la/Sublist3r | Python tool | Port scanning | 

https://intelx.io/tools?tab=domain | online DNS searches tool

https://pulsedive.com/ => Aggregated data about IP, domain names, malware, IOCs | Anonymous & free account access

# BOOK-4: Finding Online Devices	(4/8)
Systems that scan internet and allows us to search its results => censys.io 
-	Ports open on systems, services they host, HTTPS certificate info, etc.
-	Create free account in Censys.io to get API token | Allows downloading ALL censys data for offline analysis | https://censys.io/static/dl/censys-reference-guide.pdf (cheat sheet)
https://censys.io/certificates?q=parsed.names:+onion (for ToR sites)

Shodan: Takes screenshots of web pages/VNC servers/remote desktop connections, and login screens too | Search header info | Recommended to get free or paid account to run filters | Shows vulnerabilities information too!
Shodan filters: title (content scraped from HTML tag), html, net (network block), country (2 letter code), city, postal, hostname (host or domain name)
https://www.sans.org/blog/getting-the-most-out-of-shodan-searches/

https://github.com/jakejarvis/awesome-shodan-queries/blob/main/readme.md => Shodan Search Queries

# BOOK-4: Wireless Networks		(5/8)
SSID: Name of wireless network | BSSID: MAC address of wireless transmitter | beacon: Ties SSID to BSSIC; Announcements from wireless device | probe requests: Announcement of client requesting a certain SSID; Ties request for SSID to a BSSID | The first 3 octets (3 groupings inside the colons (:)) of a BSSID represent the organization that made the device. This OUI or Organizationally Unique Identifier, can be researched to determine the type of device or where it might have come from

Wireless networks can be geolocated (based on signal strength) | Network names can be revealing | Not 100% accurate though

Google collected WiFi data in 2010 (geolocation and SSID) : Kismet tool | WarXing
WiGLE.net: Search for submitted geolocated Wi-Fi networks | 2001 to present | Anonymous and free
-	Use advanced search with free registered user for better information (wildcard search possible)
Same BSSID in multiple places is possible (with same or different SSIDs).
Same or different SSIDs with one BSSID is possible.
-	If NetID column is empty or too many search results then WiGLE account is corrupted.

Wi-Fi | RFID | Bluetooth | Zigbee | Cellular | NFC
-	WiGLE API can be used for Bluetooth data
iOS Bluetooth: LightBlue Explorer | Android: nRF Connect for Mobile (RSSI tells how far from transmitter)

Can geolocate mobile devices based on mobile data from cell towers and Wi-Fi networks
-	Data extraction using Cellebrite software https://www.cellebrite.com/en/home/
https://github.com/azmatt/Anaximander => Python code to map cell towers from a Cellebrite Android dump

# BOOK-4: Recon Tool Suites and Frameworks		(6/8)
SpiderFoot: https://www.spiderfoot.net/ | Python | Steve M | 160+ modules | HX version (free+paid)
Command line and API (+ web interface)


https://www.spiderfoot.net/hx/
15% off promocode for SANS students:
“spotlight”
Opensource: default TCP/5001
Lock icon indicates API key on modules
$ python sfcli.py

People OSINT modules:
Accounts, Social Networks, Instagram, 
MySpace

Domains/IPs OSINT modules: Censys and Shodan, Archive.org, Whois
Default settings in SpiderFoot needs adjustments (e.g User-agent string, HTTP timeout of 5 seconds)
-	HX version has user-agent string: “SpiderFoot” in some modules => need to update
Results can be viewed while scan is running | Graph view shows links between discovered domains,sites
-	Gephi and Casefile tools can be used to export graphs
-	Can mark as false positives in both open source and HX versions

Recon-ng: https://github.com/lanmaster53/recon-ng | Python 3 | Tim Tomes | 70+ modules (custom module is possible) | Cmd line, API, RPC | Free | v4 and v5 are drastically different (e.g. v5 doesn’t install any modules by default, ‘marketplace search’ command shows modules in market place to install & use)
 
Note: All recon/* modules are OSINT related ones
-	“options list” command shows the product version, user-agent string, verbosity and other info
o	Default user-agent string is: Recon-ng/v5
o	VERBOSITY is 1 (0=minimal, 1=verbose, 2=debug)

Uses SQLite DB, in user’s home directory (.recon-ng folder) | “db schema” shows all DB tables & schema
-	To view a table: show <tablename> (e.g. show hosts)
 

Once a module is installed, we can load it and get information about it.

Steps: Create workspace -> Choose the module -> Enter seed target data (IP, Domain, Email) -> Run

Uses Google Analytics at lunch to realize which modules are used the most
 
# BOOK-4: Government Data		(7/8)
Federal | State | Local governments
OSINT data: Contact directory of employees | Salary info | Businesses registered | Military organization data | Health Info | Life events | Court data

GIS: Geographic Information System: gis site:.gov.* -filetype:pdf
-	Layers icon shows different data on maps
https://en.wikipedia.org/wiki/Open_data  | https://opendata.rapid7.com/ | https://africaopendata.org/  | https://smapp.rand.org/rwtid/search_form.php (Terrorism incidents DB) | https://medium.com/week-in-osint/week-in-osint-2019-17-1214c7044a60

Federal data: Federal election commission, Dept of Justice, Federal Communications Commission
https://www.bop.gov/inmateloc/ | https://travel.state.gov/content/travel/en/international-travel/International-Travel-Country-Information-Pages.html
Business OSINT? Use EDGAR. https://www.sec.gov/edgar/search-and-access

State data: Dept. of motor vehicles, Dept. of Corrections, Business permits and Licenses
Local data: County, City, Village data | Transportation (Buses and Trains), etc.

ABR: Australian Business Register: https://abr.business.gov.au/ | Mexico Social Security: IMSS
Netherlands GIS data: PDOK | UK: planning portal

# BOOK-4: Researching Companies	(8/8)
Investigate a business to: 
Invest in a company, Partner with a company, Merge or acquire a company, compete with a company, Investigate possible illegal or unethical behavior

“who” questions on basic data of businesses: who runs the company? Who works at it? Who are customers? Who are partners? Who are suppliers? Who are the people in the news?

“where” questions: where are offices? Where registered? Where do they do business? Where are internet-facing computer systems?

“what” questions: what does company do? What system they use? What are key business relationships?

https://www.buzzfile.com/ : business intelligence site | companies and leaders info | Financial info too |
https://www.manta.com/ : aggregates data about US small businesses | # of employees’ info too
https://opencorporates.com/ : largest open db of companies | International repo of public corp data

Non-profit org data: https://www.charitynavigator.org/ | https://www.gov.uk/find-charity-information 
https://www.guidestar.org/Home.aspx (USA) | https://projects.propublica.org/nonprofits/ (USA)

https://www.annualreports.com/ : Corporate filings / publicly traded companies (SEC-10-K)

https://www.infobel.com/ => companies or people can be search by name or category, phone numbers

Databases for OSINTers and Journalists to search: https://aleph.occrp.org/ (Leaked public documents)
(Investigative dashboard)

Companies registered in UK: https://beta.companieshouse.gov.uk/ (Historical documents of company)
https://www.gov.uk/government/publications/overseas-registries/overseas-registries (Intl. registries)

C-level people: relationship, compensation, social media, etc.  https://www.corporationwiki.com/
-	“It’s not about what you know, but who you know”
(Relationship map + Companies & connection tables, Known addresses & sources)
https://littlesis.org/about (factual journalism) | non-profit public accountability initiative

https://www1.salary.com/ => executive salaries => https://openpayrolls.com/

Reviews on companies by employees: https://www.careerbliss.com/, https://www.comparably.com/, https://www.glassdoor.com/index.htm, https://www.indeed.com/

# BOOK-5: The surface, Deep, Dark Webs		(1/8)
Surface: Easy to access | Deep: More challenging | Dark: Special techniques
Deep web: Must know or be able to find resources without search engines (gray area)
-	E.g. Business networks, Banks/Financial/Investments, Gov info about us, Private social media
Dark web: Used by journalist, oppressed people, criminals, gov/law enforcement, whistle-blowers, privacy-minded people
OSINT data: Curiosity, protect their communication, Anonymity for traffic, track financial fund, support law enforcement and intel agencies

Old style (before search engines): http://info.cern.ch/hypertext/WWW/TheProject.html

To search in deep-web: https://oedb.org/ilibrarian/research-beyond-google/
-	https://www.makeuseof.com/tag/journey-into-the-hidden-web-a-guide-for-new-researchers/
https://osintframework.com/ | https://github.com/jivoi/awesome-osint | https://github.com/IVMachiavelli/OSINT_Team_Links | https://inteltechniques.com/blog/

# BOOK-5: The Dark Web		(2/8)
Know the risks before using it | Consider other’s beliefs | Consider work location (who else can see your screen? sound ON on your PC? etc.) | CSAM (Child sex abuse material), etc. 
Approval from manager + legal dept + senior management + customer before using it

Search in google as: “darknet marketplace”
Dark web = Freenet | I2P | Tor

Freenet: Decentralization of files pieces, encrypts and
shares with all nodes (key is used)
I2P: Series of temporal one-way encrypted tunnels
Tor: Proxying network traffic across many systems

# BOOK-5: Freenet		(3/8)
Java based | Data can persist indefinitely on Freenet | Two modes: Opennet & Darknet | Opennet modes: LOW security (default), Normal and HIGH security | Both modes differ by nodes we connect to (in High security, we connect to trusted nodes) | Cross-platform installer & wizard-driven | High latency due to re-assembly of data for files
 
Uses FProxy (java applet) to access data locally | Four keys types: CHK, SSK, USK, KSK
http://127.0.0.1:8888/[freenet_key]
•	CHK: Content Hash Keys: Files with static content (.mp3 or .pdf)
•	SSK: Signed Subspace Keys: websites that change over time (corrected, added, or deleted)
•	USK: Updatable Subspace Keys: Linking to latest version or wrappers of SSK
•	KSK: Keyword Signed Keys: Allow to save named pages in Freenet
https://freenetproject.org/pages/documentation.html#accessing-data
Email | Forums | create our own website

# BOOK-5: I2P – Invisible Internet Project		(4/8)
Overlay network | Protect communications from eavesdropping, monitoring, traffic analysis | http://geti2p.net/en/ | Outbound (send) and Inbound (receive) tunnels | More interactive than Freenet | Java-based | Cross-platform | $i2prouter start

Torrents (I2PSnark, Vuze) | Chat/IRC | Forums | Email (I2P-Bote, Postman’s service) | Marketplace (drugs, counterfeiting, weapons, pornography, coupon trading)

/confignet page for opening network firewalls to allow UDP traffic
Local proxy: localhost:4444 | IRC: localhost:6668 | Hostnames: https://geti2p.net/en/docs/naming
Hostnames: 516-byte OR base32.b32.i2p OR vanity.i2p	  Eepsites
-	Can use surface web to search for i2p Eepsites, blogs, etc.
DNS resolutions happen locally! hosts.txt file | blockfile naming service for translation

# BOOK-5: Tor (A proxy to reach .onion sites)		(5/8)
https://www.torproject.org/ | To project how data gets from our system to the target system | defeat censorship | Each node knows its successor and predecessor only | Source picks the path of travel
Four categories of people use Tor:
1.	Normal / OSINT people: safeguard privacy/avoiding censorship
2.	Journalists & Activists: anonymous tips, info sharing
3.	Law enforcement and Intel agency: Sting operations, catch criminals, intelligence
4.	Criminal / Terrorists: Marketplace selling illegal items, sharing stolen data, recruitment/ideology 
Avoid using sites with login on Tor | Don’t use personal information

Honions (Honey Onions): 110 Tor nodes were collecting info on traffic passing thru them | At least 3% of dark web nodes are rogues

Standalone apps in Tor: Tor Browser (built on firefox) | Tails (privacy-focused live Bootable OS on USB) | Orbot (Tor for Android mobile)

Whonix: VM gateway | Used in conjunction with workstation to tunnel network traffic through Tor

Check if using Tor: http://check.torproject.org/  | 
-	version:2 of Tor uses 16-char long addresses | .oinion TLD | RSA 1024 keypair |  SHA1-hash of DER encoded ASN | first half of hash is base32 encoded to form the .onion site
-	version:3 of Tor uses 56-bytes long | stronger in crypto than v2 (SHA3/ed25519/curve25519)

Accessing hidden services from internet: https://www.tor2web.org/ | replace .onion with .tor2web.io

Hunchly’s daily hidden services report: contains full list of spidered .onion sites in Tor network | Excel can be emailed or downloaded

Fresh onion hidden service: retrieves info about hidden service from variety of sources | web server banner, SSH keys, locations, etc.	 | /server-status shows interesting information (web server, OS, current time on server, VHost, pages and params submitted by people to server) : Uses Apache’s mod_status
https://osintcurio.us/2019/03/05/apache-mod_status-in-tor-hidden-services-destroy-anonymity/

# BOOK-5: Monitoring and Alerting	(6/8)
Monitoring: Specific domains, Keywords (sentiments, project, etc.), people (inside or outside company)
OSINTers can set alert to have data come to them, instead of searching for something.
https://haveibeenpwned.com/ (Compromised accounts to notify): Register specific email or full domain
HIBP site is used by: OSINTers, Personal people, Blue Team/Privacy, Read team/Offensive

Dumps (passwords, userids, etc.) collected from hacker sources are available at: https://spycloud.com/check-your-exposure/ (email) | https://dehashed.com/ (passwd lookup site, paid)
-	can pivot on password to discover other IDs (Can contain international character sets, TLDs)

https://aleph.occrp.org/ : Journalist site w/ DB of sources

Paste sites: Allow anonymous posting | Someone posts content -> Gets URL -> share it -> others access
https://pastebin.com/ : People share: code, list of IP/subnets, manifestos, stolen data, IM/IRC conv.
-	These are temporal (not permanent) | Expire at user’s wish | Be removed for violation
-	Old data could be available at archive.org and also at https://psbdmp.ws/ (Free, unauth API)
Can setup up to 15 alerts in pro account of pastebin site.

Pastehunter: https://techanarchy.net/blog/hunting-pastebin-with-pastehunter (ElasticSearch & Kibana)

Google’s CSE (Custom Search Engine): creator chooses how and where to search (domains, IP, userids)
Lots of CSE: https://twitter.com/sprp77  | many of CSE are blackbox for OSINTers
Google Alerts: https://www.google.com/alerts (by word, by file, by site, etc.) 
https://visualping.io/: Monitor websites for content changes | 65 checks per month in free acct | https://versionista.com/ -> similar to visualping site

If this then that site: https://ifttt.com/ (free, existing or custom applets) | Monitor websites, user acts

https://flow.microsoft.com/en-us/ => require valid email, phone, passwd to access | Complex than ifttt

https://tweetdeck.twitter.com/ => Monitor twitter with account (topics, people, location, hashtags)

# BOOK-5: International Issues		(7/8)
Searching content in non-English countries could be challenging | 
https://start.me/p/m6XQ08/osint => Bruno Mortier | International resources | section by country
Best translator is a linguist | Google Translate (virtual keyboard, can draw characters for translation, works offline), Bing Translate (works offline), Yandex Translate (virtual keyboard), Deepl site https://www.deepl.com/translator (<10 languages supported, but excellent)

Audio translator: Using mobile apps in listen mode (microphone ON) 
Pic/Photo translator: Using mobile apps with camera mode (ON) | Text is translated
https://www.youtube.com/watch?v=YgSD4S2Eza8 => Webinar on international OSINT

Popular websites in specific countries: https://www.alexa.com/topsites
APPLyzer Mobile apps world charts: https://www.applyzer.com/?mmenu=worldcharts (which mobile apps are popular in specific countries) |https://www.appannie.com/en/ (market data & insights)

Search engines can search by specific country / region (change country in settings) | Search by language

Travel risks: https://travel.state.gov/content/travel.html | https://www.internationalsos.com/

International Investigative Database: https://id.occrp.org/databases/

Search Engine Colossus: https://www.searchenginecolossus.com/ : search engines to use by country

# BOOK-5: Vehicle Searches		(8/8)
Serial numbers of vehicles identify owners | Vehicle IDs can be used to pivot for more info | Can google for license plate numbers to obtain owner names

https://www.faxvin.com/license-plate-lookup => License plate lookup (get VIN number)
https://www.autocheck.com/vehiclehistory/search-by-license-plate => Free & paid license plate lookups

https://platesmania.com/autostat => International catalog of license plates, make & model of vehicles
-	Date, time, location of vehicles is available

http://worldlicenseplates.com/ => How license plates looked historically

VIN: https://www.autocheck.com/vehiclehistory/vin-basics 
https://www.decodethis.com/ | 
https://www.autodna.com/
https://www.vindecoderz.com/ | 
https://www.searchquarry.com/

UK car tax check
https://vehicleenquiry.service.gov.uk/
free / no owner data revealed

High-end vehicle number search: https://www.autogespot.com/ (International scope)

First character of tail number (Private Helicopters) is country of registration           
            https://en.wikipedia.org/wiki/ITU_prefix#Allocation_table

US FAA, Australian CASA => registration DB of specific countries	(Aircrafts registered)
https://www.skytamer.com/5.4.htm

Aircraft near-real time tracking sites: https://www.adsbexchange.com/ | https://opensky-network.org/ | https://flightaware.com/ | https://www.flightradar24.com/ | planefinder.net

 ADS-B: Automatic Dependent Surveillance – Broadcast: System of GPS satellites, ground stations, and radios in aircraft
-	Law-enforcement planes could be tracked (can mess up surveillance)
https://www.adsbexchange.com/data/ (shows aircrafts that are government/military, interesting(experimental, unique, test aircraft)  => Free/community-driven

Historical and future aircraft information: FlightAware site

Ships and Watercraft: https://shipfinder.co/ | https://www.myshiptracking.com/ | https://www.marinetraffic.com/ | https://www.vesselfinder.com/
https://medium.com/@raebaker/osint-on-the-ocean-maritime-intelligence-gathering-techniques-2ee39e554fe1 | 
https://en.wikipedia.org/wiki/IMO_number | 
http://maritime-connector.com/ship/msc-lieselotte-8201674/

Harbor web cameras: Google search: harbor OR marina webcam OR “web cam”
Reasons to visit dark-web:
 
Pros and Cons of Recon-NG
 
*** THE END ***
