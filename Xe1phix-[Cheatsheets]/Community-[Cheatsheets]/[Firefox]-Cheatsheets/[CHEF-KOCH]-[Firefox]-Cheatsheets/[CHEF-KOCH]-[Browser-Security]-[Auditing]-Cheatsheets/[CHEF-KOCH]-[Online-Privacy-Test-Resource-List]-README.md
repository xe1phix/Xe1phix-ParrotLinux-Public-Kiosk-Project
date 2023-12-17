 ## - POTARC -

Privacy Online Test And Resource Compendium© (short: POTARC) project original created under the MIT license (2016 - present) by CHEF-KOCH and community.

![Matrix](https://img.shields.io/matrix/cknews:matrix.org.svg?label=CK%27s%20Technology%20News%20-%20Matrix%20Chat&server_fqdn=matrix.org&style=popout)
![Twitter Follow](https://img.shields.io/twitter/follow/@CKsTechNews.svg?label=Follow%20%40CKsTechNews&style=social)
[![Discord](https://discordapp.com/api/guilds/418256415874875402/widget.png)](https://discord.me/CHEF-KOCH)

## Privacy Online Test And Resource Compendium

The list is designed to show all available and useful online/offline tests in order to build strategies to harden your OS/Internet/Browser configuration against fingerprinting methods. Some of those services might collect only data to hand/sell it to 3th-party developer or people which pay for it to use it for 'bad' things, such services are (if known) marked and aren't preferable added - so keep this in mind before you request a site.

POTARC itself is more a community driven project because everyone can contribute to it and no pull request or discussion will be rejected, only with good reasons like spamming, etc. This project does not accept any donations because we all doing this in our free time and it's up to everyone to provide some information or not, from my perspective the information should be available for free.

Keep in mind that reducing the fingerprint doesn't mean you're secured against all attacks (including new upcoming ones) because security is a process and not something you gain by installing the correct extensions, plugins or programs.

## Contribution

See [CONTRIBUTING.md](https://github.com/CHEF-KOCH/Online-Privacy-Test-Resource-List/blob/master/CONTRIBUTING.md). Before you create a new issue ticket, ensure you read the issue template and check if the things you like to request is not already on the todo list in order to avoid duplicates or already known things.


## How to handle these information and test results?

Collection of [device fingerprints](https://en.wikipedia.org/wiki/Device_fingerprint) from web clients such as browser software mostly relies on the availability of JavaScript or similar client-side scripting language for the harvesting of a suitably large number of parameters. Overall this means if only one or a small of things are detectable it not automatically reveals your real identify, but all together can be pretty dangerous in order to expose you or your security setup. Keep in mind that it's not a good idea to share the results or to leak information which setup you exactly use.

The document section is for research and evidence purposes, topics without any proof are not reliable and the project doesn't accept any submissions without any documents or research based on the matter.

#### Keep in mind
> Some of the integrated services & pages collect the results and store it offline and some other pages even sell the results to 3rd-parties! I'm not responsible for this behavior, the list added an indicator in order to inform you.


### Research documents

I'm not the original author of any uploaded .pdf file in this repository, nor do I claim I wrote them. The documents are not under any license and the credit goes to the people which orignally written them. The documents are only mirrored here because several search engines (sadly) delete or hiding content behind proxies/VPN's, or the original link simply vanishes. All research documents are untouched. Please contact me via eMail if you don't like it and I'm going to remove them from this repository.

### Known Fingerprinting Techniques
* CDN [Web Cache Deception Attack based attacks](https://omergil.blogspot.ch/2017/02/web-cache-deception-attack.html). CDN's are in general a security problem, once infected or compromised you have no chance to identify the threat or not before it's already too late. [Decentraleyes](https://github.com/Synzvato/decentraleyes) reduce the attack surface.
* Fake identity, identify theft (not fixable) [NETSEC] & fake comments (OPSEC)
* Hardware implemented fingerprint methods such as [hardware based DRM](https://docs.microsoft.com/en-us/windows/uwp/audio-video-camera/hardware-drm) (wont-fix but can be configured via flags)
* Power consumption 'attacks' and wave signal based tests (not fixable without breaking the signals or updating the RFCs).
* Several [HTTP authorization detection](https://en.wikipedia.org/wiki/Security_testing#Authentication) which is not fixable because it's protocol and meta-data depending and would require new metadata less protocols.
* Stuff which is documented and mentioned over [here](https://github.com/CHEF-KOCH/NSABlocklist) or [here](https://wiki.mozilla.org/Fingerprinting).
* [AJAX](http://www.symantec.com/connect/articles/ajax-security-basics)
* [ASN Squatting Attacks](http://securityskeptic.typepad.com/the-security-skeptic/2011/06/asn-squatting-attacks.html)
* [Acoustic fingerprinting](https://en.wikipedia.org/wiki/Acoustic_fingerprint)
* [Audio fingerprint tests](https://github.com/worldveil/dejavu)  ([example](https://github.com/dpwe/audfprint))
* [Automatic content recognition](https://en.wikipedia.org/wiki/Automatic_content_recognition)
* [Battery API](https://www.w3.org/TR/battery-status/) (fixed, see below)
* [CORS (ajax)](http://www.html5rocks.com/en/tutorials/cors/)
* [CPU Fingerprint](http://yinzhicao.org/TrackingFree/crossbrowsertracking_NDSS17.pdf)
* [CPU Starvation Attacks](https://msdn.microsoft.com/en-us/library/ee810608(v=cs.20).aspx)
* [CSS based attacks](https://www.mike-gualtieri.com/posts/stealing-data-with-css-attack-and-defense)
* [Caching attacks](https://en.wikipedia.org/wiki/Timing_attack)
* [Canvas fingerprinting](https://en.wikipedia.org/wiki/Canvas_fingerprinting), see ([here](http://cseweb.ucsd.edu/~hovav/dist/canvas.pdf))
* [Captive Portal based attacks](https://rootsh3ll.com/captive-portal-guide/)
* [Clickjacking](https://www.vojtechruzicka.com/preventing-clickjacking/)
* [Common Spoofing attacks](https://en.wikipedia.org/wiki/Spoofing_attack)
* [Crooked Style Sheets](https://www.mike-gualtieri.com/posts/stealing-data-with-css-attack-and-defense) [Discussion](https://news.ycombinator.com/item?id=16157773)
* [Cross-Origin Identifier](https://www.torproject.org/projects/torbrowser/design/#identifier-linkability)
* [DNS Spoofing](https://en.wikipedia.org/wiki/DNS_spoofing)
* [DNS cookie attacks](http://dnscookie.com/)
* [DNS exfiltration over DNS over HTTPS (DoH) with godoh](https://sensepost.com/blog/2018/waiting-for-godoh/)
* [DNS leakage or bypasses](https://www.dnsleaktest.com/what-is-a-dns-leak.html)
* [DOMrect](https://developer.mozilla.org/en-US/docs/Web/API/DOMRect)
* [Database fingerprints](https://github.com/Valve/fingerprintjs2)
* [Deep learning fingerprinting attacks on Tor ("Deep fingerprinting")](https://www.rit.edu/news/rit-cyber-fighters-go-deep-tor-security)
* [Digital video fingerprinting](https://en.wikipedia.org/wiki/Digital_video_fingerprinting)
* [Do not track (DNT) detection](https://econsultancy.com/blog/6921-the-ftc-s-do-not-track-proposal-useless-harmful-or-both) & [Companies that have implemented Do Not Track](https://allaboutdnt.com/companies/)
* [Extension system based attacks](https://www.usenix.org/system/files/conference/usenixsecurity17/sec17-sanchez-rola.pdf)
* [Fetch API](https://developer.mozilla.org/en-US/docs/Web/API/Fetch_API)
* [Finger taps eavesdropping](https://nakedsecurity.sophos.com/2019/06/07/researchers-eavesdrop-on-smartphone-finger-taps/)
* [Font detection & vulnerabilities](https://support.microsoft.com/en-us/kb/2639658)
* [getClientRects fingerprinting](https://browserleaks.com/rects) via [DOM](http://www.water.ca.gov/waterquality/docs/Fingerprinting%20Sources%20of%20DOM%20-%20Ngatia.pdf)
* [High Resolution Timer attacks](https://w3c.github.io/hr-time/#sec-privacy-security)
* [IDN homograph attack](https://en.wikipedia.org/wiki/IDN_homograph_attack)
* [ISP throttling checks](https://thenextweb.com/apps/2015/05/21/quick-test-shows-if-isps-are-secretly-throttling-your-internet-speeds/)
* [Keyboard API fingerprinting](https://wicg.github.io/keyboard-map/#privacy)
* [Measuring time](https://en.wikipedia.org/wiki/Timing_attack) (Timezone/[NTP](http://www.securityweek.com/ntp-servers-exposed-long-distance-wireless-attacks))
* [Multiple browser fingerprinting detection](https://arstechnica.com/information-technology/2017/02/now-sites-can-fingerprint-you-online-even-when-you-use-multiple-browsers/)
* [Memory Starvation Attacks](https://msdn.microsoft.com/en-us/library/ee810601(v=cs.20).aspx)
* [Mouse & CPU fingerprinting](http://jcarlosnorte.com/security/2016/03/06/advanced-tor-browser-fingerprinting.html)
* [Network Bandwidth Attacks](https://msdn.microsoft.com/en-us/library/ee798452(v=cs.20).aspx)
* [NoCoin](https://github.com/keraf/NoCoin), prevents background mining via opt-in.
* [OSI model fingerprints](https://searchnetworking.techtarget.com/tip/OSI-Securing-the-Stack-Layer-4-Fingerprinting) (based on [HTTP](https://github.com/wireghoul/lbmap), Header, User Agent, Firewall, ...)
* [Password sniffing](http://cng.seas.rochester.edu/CNG/docs/Security/node8.html)
* [Paste-jacking](https://github.com/dxa4481/Pastejacking) & [Backspace variant](https://security.stackexchange.com/questions/39118/how-can-i-protect-myself-from-this-kind-of-clipboard-abuse)
* [Plugin/Extension tracking](https://webdevwonders.com/detecting-browser-plugins/) (Silverlight, Adobe Flash, ...)
* [Progressive Web Applications (PWA) tracking](https://blog.lukaszolejnik.com/tracking-users-with-rogue-progressive-web-applications/)
* [Public key fingerprint](https://en.wikipedia.org/wiki/Public_key_fingerprint)
* [PushAPI](https://developer.mozilla.org/en-US/docs/Web/API/Push_API)
* [RAMBleed](https://rambleed.com/)
* [Resource Starvation Attacks](https://msdn.microsoft.com/en-us/library/ee798408(v=cs.20).aspx)
* [SameSite cookies](https://tools.ietf.org/html/draft-ietf-httpbis-rfc6265bis-02#section-5.3.7)
* [Screen resolution](http://www.b3rn3d.com/blog/2014/05/29/fingerprinting-resolution/)
* [Secure Messenger](https://github.com/dessalines/Messaging-Services-Comparison)
* [SensorID](https://www.forbes.com/sites/kevinmurnane/2019/05/23/all-iphones-and-some-android-phones-are-vulnerable-to-a-new-device-fingerprinting-attack/#26f6ab7831a9)
* [ServiceWorker](http://www.html5rocks.com/en/tutorials/service-worker/introduction/)
* [Spectre](https://alephsecurity.com/2018/06/26/spectre-browser-query-cache/) - Allows an attacker to read secret data.
* [TLS downgrade attacks](https://www.nccgroup.trust/us/about-us/newsroom-and-events/blog/2019/february/downgrade-attack-on-tls-1.3-and-vulnerabilities-in-major-tls-libraries/?Year=2019&Month=2)
* [TLS fingerprinting attacks](https://github.com/LeeBrotherston/tls-fingerprinting)
* [Tor Browser Security Design](https://www.torproject.org/projects/torbrowser/design/)
* [Tor Node Detection](https://check.torproject.org/)
* [Tracking Users across the Web via TLS Session Resumption](https://browserprivacy.wordpress.com/2013/11/19/requiring-better-cryptography-in-firefox-and-thunderbird-breaks-update-functionality/)
* [uBeacons](https://www.ubuduasia.com/single-post/2015/12/02/Leverage-Data-Analytics-to-reevaluate-your-marketing-effort-using-uBeacons-)
* [UberCookie](http://ubercookie.robinlinus.com/faq.html)/[Cookies](https://en.wikipedia.org/wiki/HTTP_cookie)/[EverCookie](https://en.wikipedia.org/wiki/Evercookie)/[Supercookies](https://en.wikipedia.org/wiki/HTTP_cookie#Supercookie)
* [Ultrasonic Tracking Frequencies](https://thehackernews.com/2017/05/ultrasonic-tracking-signals-apps.html)
* [Urchin Tracking Module (UTM)](https://support.google.com/urchin/answer/28307?hl=en)
* [User agent detection](https://en.wikipedia.org/wiki/Usage_share_of_web_browsers#User_agent_spoofing)
* [User fingerprinting problem (Canvas, IP, ...)](https://en.wikipedia.org/wiki/Canvas_fingerprinting)
* [WWW Subdomain on Cookie Security](https://www.netsparker.com/blog/web-security/impact-www-subdomain-cookie-security/)
* [Web Browser Address Bar Spoofing](https://www.netsparker.com/blog/web-security/web-browser-address-bar-spoofing/)
* [WebGL](https://browserleaks.com/webgl)
* [WebSocket based attacks](http://resources.infosecinstitute.com/websocket-security-issues/)
* [Zero With Detection](https://umpox.github.io/zero-width-detection/), see [here](https://www.hindawi.com/journals/scn/2018/5325040/) for more information.



### Already fixed within the Browser or OS (ensure you use the latest product [always!])
* Browser based download attacks by exposing sensible information, there are several anti-fingerprinting techniques to expose you via drive-by.
* CPU & Mouse wheel fingerprinting which needs to be fixed also within the OS (wont-fix!)
* First-party cookies in general, daily pages like e.g. Amazon/Facebook (as an example) need cookies to function probably (addons/filter-lists may help to whitelist/bypass certain restrictions). Some pages like [Facebook already started to track user via first-party cookies](https://marketingland.com/facebook-to-release-first-party-pixel-for-ads-web-analytics-from-browsers-like-safari-249478).
* HTML5 based attacks which inclduing stuff like Canvas, fonts & more (will never be fixed, you have to use in order to spoof such data, however "configuration hardening" might help to reduce the surface attack level).
* ~~HTTP Public Key Pinning (HPKP) sniffing attacks (removed/fixed in Chrome 72+ & Firefox 56+)~~
* Network layer based leaks (OSI leaks) e.g. MAC address leakage (EUI64). Disabling/blocking IPv6, if not necessary/needed is usually enough. See [RFC 3041](https://tools.ietf.org/html/rfc3041) & ([leak test](http://ipv6leak.com/))
* Classic PopUps aren't possible anymore (if not Canvas/JS related). Normally you'll see a permission dialog or can control this behavior directly via Browser settings. Some [Browsers also come with their own Ads-blocking feature](https://www.theverge.com/2018/2/14/17011266/google-chrome-ad-blocker-features).
* ~~Third-party cookie "isolation" or blocking~~
* Tor network attacks - several fingerprint methods are still possible. 
* ~~WebRTC since Chrome 48+ and Firefox 42+, both getting an new menu to allow it per-page (whitelist). There exist also for both several addons, workarounds to compile it without WebRTC support). [Unofficial Chromium builds](http://chromium.woolyss.com) also come without WebRTC or sync.~~
* ~~* Detection of incognito mode~~
* ~~Adobe Flash~~ (EOL), replaced by HTML5 (which has it's own _weaknesses_ [see below])
* ~~File Transfer Protocol (FTP)~~ - Will be removed soon or later from every Browser.
* ~~OpenSSL fixed (HeartBleed,CloudBleed...)~~
* ~~SSL / TLS (ciphers) [if you only browse on pages like GitHub ~ you can even more [harden it](https://tools.ietf.org/html/draft-sheffer-tls-bcp-00)]~~ TLS 1.3 (3.0+) is the new common default and most platforms abandoned TLS 1.0/1.1/1.2.
* ~~SensorID fingerprinting attacks~~ fixed in iOS 12.2+ and it will be fixed in Android Q.
* ~~Coin Mining~~
* ~~BatteryAPI~~ based fingerprinting attacks
* ~~Spectre & Meltdown~~ Via OS & BIOS patches. Almost all modern Browser also protecting their memory against exfiltration attacks.
* ~~Several timing based attacks are too ineffective for an advertiser/attack to abuse (in the real world).~~


## Obsolete Add-ons & Plugin Tests

| **Page or Addon** | **Description** | **Collects or sells user data?** |
| --- | --- | --- |
| [Firefox Addon Detector](https://thehackerblog.com/addon_scanner/) | ://URI detection | `No` |
| [Flash Player System Test](https://www.browserleaks.com/flash) | Checks if and what version or Adobe Flash Player is installed | `No` |
| [Adobe official Flash Player Test](https://www.adobe.com/software/flash/about/) | Official Adobe Flash Player Test | `Yes` collects statistics and sells them. |
| [Java Test](https://www.java.com/en/download/installed.jsp) | Official Java Browser verification page. | `Yes` collects statistics and sells them. |
| [Unofficial Microsoft Silverlight Test](https://www.browserleaks.com/silverlight) | Browserleaks Silverlight Test Page | `No` |



## eMail

| **Page or Addon** | **Description** | **Collects or sells user data?** |
| --- | --- | --- |
| [Email IP Leak Test](http://emailipleak.com/) | Checks if your email provider shows your real IP address to its recipients. | `N/A` |
| [Email Privacy Tester](https://emailprivacytester.com/) | Checks email addresses | `Yes` see [here](https://www.emailprivacytester.com/privacy) |
| [Email Trace](http://www.ip-adress.com/trace_email/) | Checks email addresses | `Yes` |
| [Have I Been Pwned? (Svalbard)](https://haveibeenpwned.com/) | Database which checks if you affected by several holes | `No` |
| [Pwnedlist](https://pwnedlist.com/) | Database which checks if you affected by several holes | `Yes` - Currently down |
| [Check Your GPG Fingerprints](https://evil32.com/) | Check if your GPG key is leaked or not | `No` |
| [Have I Been Sold?](https://haveibeensold.app/) | Quickly check if your email has been sold. | `No`, database lookup needs JS
| [Is someone spying on you?](https://sec.hpi.de/ilc/search) | Same like Have I Been Pwned? it checks your pass/email against a database | `No` |



## Phishing

| **Page** | **Description** | **Collects or sells user data?** |
| --- | --- | --- |
| [KnowBe4](https://www.knowbe4.com/phishing-security-test-offer) | Login to get your phishing test template | [Yes](https://www.knowbe4.com/privacy-policy)
| [Are you leaking Windows/VPN Login-Data?](https://msleak.perfect-privacy.com/) | [Understanding the Windows Credential Leak Flaw and How to Prevent It](https://www.bleepingcomputer.com/news/security/understanding-the-windows-credential-leak-flaw-and-how-to-prevent-it/) | [No](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-security-restrict-ntlm-outgoing-ntlm-traffic-to-remote-servers)



## Browser Prerender & Feature Tests

| **Page** | **Description** | **Collects or sells user data?** |
| --- | --- | --- |
| [Prerender test](http://prerender-test.appspot.com/) | [Prerender](https://www.keycdn.com/blog/resource-hints/) resource test | `No` |
| [Web platform's features check](http://paulirish.github.io/web-feature-availability/) | Test which Web Feature your Browser supports | Yes, StatCounter & caniuse.com |
| [Third-Party redirection test](https://ndossougbe.github.io/web-sandbox/interventions/3p-redirect/) | Third-party redirection Test site - Pass if not redirected | `No` |



## Window Measurements
| **Page or Addon** | **Description** | **Collects or sells user data?** |
| --- | --- | --- |
| [Inner Window Measurements](https://fiprinca.0x90.eu/poc/) | Detects the Browser Window Size | `No` |



## Certificate

| **Page or Addon** | **Description** | **Collects or sells user data?** |
| --- | --- | --- |
| [Revocation Awareness Test](https://www.grc.com/revocation.htm) | Certificate based revocation test | `No` |
| [Check Provider-TLS](https://www.checktls.com/) | Check provider TLS certificates | `N/A` |
| [Intermediate CA Cache Fingerprinting](https://fiprinca.0x90.eu/poc/) | Intermediate CA Cache Fingerprinting | `No` |



## Crypto-mining detection and Malware

| **Page or Addon** | **Description** | **Collects or sells user data?** |
| --- | --- | --- |
| [MALWARE DETECTED WITH THREAT EMULATION](http://www.cpcheckme.com/checkme/) | Check if your security setup is ready against crypto mining and other threats | `Yes` |



## Mozilla (Firefox) specific test and overview pages

| **Page or Addon** | **Description** | **Collects or sells user data?** | **Requires activated JavaScript**
| --- | --- | --- | --- |
| [Windows Hello Test Page](https://webauthn.org/) | Check if Firefox 66+ supports Windows Hello  | `No` | `Yes` |
| [Windows Hello Test Page (mirror)](https://webauthn.io/) | Check if Firefox 66+ supports Windows Hello  | `No` | `Yes` |
| [Windows Hello Test Page (mirror)](https://webauthn.me/) | Check if Firefox 66+ supports Windows Hello  | `No` | `Yes` |
| [Windows Hello Test Page (mirror)](https://webauthndemo.appspot.com/) | Check if Firefox 66+ supports Windows Hello  | `No` | `Yes` |
| [Tracking Protection](https://itisatrap.org/firefox/its-a-tracker.html) | Test page for Firefox's built-in Tracking Protection | `No` | `Yes` |
| [Phising Protection](https://itisatrap.org/firefox/its-a-trap.html) | Test page for Firefox's built-in Phising Protection ("Web forgeries") | `No` | `Yes` |
| [Malware Protection](https://itisatrap.org/firefox/its-an-attack.html) | Test page for Firefox's built-in Malware Protection (attack page) | `No` | `Yes` |
| [Malware Protection](https://itisatrap.org/firefox/unwanted.html) | Test page for Firefox's built-in Malware Protection (attack page) | `No` | `Yes` |
| [Firefox Stoage Test](https://firefox-storage-test.glitch.me/) | Test if your IndexedDB file is broken or corrupt | `No` | `Yes` |
| [Mozilla Plugin Privacy Test Database](https://nullsweep.com/launching-the-mozilla-plugin-privacy-test-database/) | The tests attempt to determine whether plugins passively gather data about users browsing habits | `No` | `No` [(Open Source)](https://github.com/Charlie-belmer/mozilla_privacy_plugin_tester) |
| [Cloudflare ESNI Checker](https://www.cloudflare.com/ssl/encrypted-sni/) | Can not only be used with Firefox but was designed for test reasons, it automatically tests whether your DNS queries and answers are encrypted |  `Yes`, statistics | `Yes` |
| [Show Shield Studies (Beta)](https://www.jeffersonscher.com/sumo/shield.php) | Show ("detect") current Mozilla Shield Studies | `No` | `Yes` |
| [Platform/GFX/WebRender Where](http://arewewebrenderyet.com/) | Where have we shipped WebRender? | `No` | `No` |




## Chrome/Chromium specific test pages
| **Page or Addon** | **Description** | **Collects or sells user data?** | **Requires activated JavaScript**
| --- | --- | --- | --- |
[Chrome 76+ escape key-generated popups test](https://codepen.io/mustaqahmed/full/yrXLxZ) | [Read here for more infos](https://www.zdnet.com/article/google-changes-how-the-escape-key-is-handled-in-chrome-to-fight-popup-ads/) | `No` | `No` |
| [CRXcavator](https://crxcavator.io/) | Submit a Chrome Extension ID to scan the extension | `No` | `Yes` |



## Incognito Detection

| **Page or Addon** | **Description** | **Collects or sells user data?** | **Requires activated JavaScript**
| --- | --- | --- | --- |
| [Check if the Chrome is in Incognito Mode](https://jsfiddle.net/w49x9f1a/) | Small JavaScript test to detect Chrome's FileSystem API | `No` | `Yes` |
| [Check if Firefox is in Private Mode](https://codepen.io/fadupla/pen/EWxKRW) | Small JavaScript test to detect Firefox Private Mode | `No` | `Yes` |



## DNS Rebinding

| **Page or Addon** | **Description** | **Collects or sells user data?** | **Requires activated JavaScript**
| --- | --- | --- | --- |
| [DNS Rebinding Demo](http://rebind.network/) | Checks if you're vulnerable to rebinding attacks |  `Partial`, the [source code](https://github.com/brannondorsey/dns-rebind-toolkit) is given but the demo page collects open statistics, they don't sell the data | `Yes` |



## DNS-over-HTTPS (DoH)

| **Page or Addon** | **Description** | **Collects or sells user data?** | **Requires activated JavaScript**
| --- | --- | --- | --- |
| [Cloudflare's Browsing Experience Security Check page](https://www.cloudflare.com/ssl/encrypted-sni/) | The web page will now perform a variety of tests to see if you are using Secure DNS, DNSSEC, TLS 1.3, or Encrypted SNI. | `Yes` | `Yes` |
| [Cloudflare Browser DoH support test](https://1.1.1.1/help) | | `Yes` | `Yes` |



## HTML5 based features test

| **Page or Addon** | **Description** | **Collects or sells user data?** | **Requires activated JavaScript**
| --- | --- | --- | --- |
| [Basic HTMl5 Video and Audio tester](http://tools.woolyss.com/html5-audio-video-tester/) | HTMl5 Video and Audio tester | `No` | `No` |
| [Battery Status API](http://pstadler.sh/battery.js/) | Checks if you browser supports Battery Status API | `No` | `No` |
| [Battery Status API](https://pazguille.github.io/demo-battery-api/) | Another Battery Status API Test | `No` | `Yes` |
| [Canvas Fingerprinting](https://www.browserleaks.com/canvas) | Checks your Canvas Fingerprint | `N/A` | `Yes` |
| [Canvas.toBlob test](https://blueimp.github.io/JavaScript-Canvas-to-Blob/test/) | Checks your Canvas Blob Fingerprint | `N/A` | `Yes` |
| [Canvas Blocking Detection](https://kkapsner.github.io/CanvasBlocker/test/detectionTest.html) | Detects if you block Canvas | `No` | `No` |
| [get.Image Canvas test](http://tutorialspark.com/html5/HTML5_Canvas_get_Image_Data_Demo.php) | Checks your get.Image Fingerprint | `N/A` | `Yes` |
| [HTML5 Features Detection](https://www.browserleaks.com/modernizr) | Detects which HTML5 features your Browser is capatible of | `N/A` | `Yes` |
| [Hard Drive Fill Test](http://www.filldisk.com/) | Hard Drive Fill Test (local Storage) | `Yes` | `Yes` |
| [HTML5 Geolocation Test](https://www.browserleaks.com/geo) | HTML5 based Geolocation Test | `No` | `Yes` |
| [HTML5 Test](http://html5test.com/) | Official HTML5 test landing page | `No` | `Yes` |
| [HTML5 Security Cheatsheet](https://html5sec.org/) | HTML5 Security checklist | `N/A` | `Yes` |
| [WebRTC Leak Test](https://www.perfect-privacy.com/webrtc-leaktest/) | Perfect Privacy WebRTC Leakage Test | `Yes` | `Yes` |
| [WebRTC Leak Test](https://diafygi.github.io/webrtc-ips/) | WebRTC Leak Test | `No` | `Yes` |
| [WebRTC Test](https://test.webrtc.org/) | WebRTC Official test | `N/A` | `Yes` |
| [WebRTC What's My IP Check](http://whatismyipaddress.com/webrtc-test) | WebRTC IP Check | `Yes` | `Yes` |
| [WebRTC check by PrivacyTools.io](https://www.privacytools.io/webrtc.html) | WebRTC IP Check | `No`, [source code is here](https://github.com/diafygi/webrtc-ips). | `No` |
| [Web RTC Chrome vulnerability check](https://internet-israel.com/internet_files/webrtc/index.html) | See ([Bug 709952](https://bugs.chromium.org/p/chromium/issues/detail?id=709952)) | `No` | `No` |
| [Anonymster WebRTC check](https://anonymster.com/web-rtc-leak-test/) | Another WebRTC check | `No` | `Yes` |
| [AutoPlay test](https://videojs.github.io/autoplay-tests/) | Test if your Browser blocks Video/Audio autoplay | `No` | `Yes` |



## CSS Fingerprint Tests

| **Page or Addon** | **Description** | **Collects or sells user data?** | **Requires activated JavaScript**
| --- | --- | --- | --- |
| [Crooked Style Sheets](http://crookedss.bplaced.net/) | Crooked Style Sheets fingerprinting test page | `No` | `Yes` ([Source Code](https://github.com/jbtronics/CrookedStyleSheets))|
| [CSS Exfil Vulnerability Tester](https://www.mike-gualtieri.com/css-exfil-vulnerability-tester) | Tests to see if your browser is vulnerable to Cascading Style Sheets (CSS) data leakage | `No` | `Yes`



## IP, DNS & Magnet Leak Tests

| **Page or Addon** | **Description** | **Collects or sells user data?** | **Requires activated JavaScript**
| --- | --- | --- | --- |
| [GeoTek Datentechnik - Web Privacy Check](https://ipinfo.info/html/privacy-check.php) | Basic Web Privacy Check | `No` | `Yes` |
| [DoiLeak](https://www.doileak.com/) | Checks if you real IP is leaking behind Proxy/VPN | `N/A` | `Yes` |
| [IP Leak](https://ipleak.net/) | Most well-known IP leak check | `Yes` | `Yes` |
| [Tenta-Test](https://tenta.com/test/) | Browser Privacy Test by Tenta VPN Browser | `Yes` | `Yes` |
| [DNS Leak Test](https://www.dnsleaktest.com/) | Most well-known DNS leak check | `Yes` | `Yes` |
| [Content Filters and Proxy Test](https://www.browserleaks.com/proxy) | Check your filter list and Proxy configuration | `N/A` | `Yes` |
| [DNS Spoofability Test](https://www.grc.com/dns/dns.htm) | Is your DNS spoofed? | `Yes` | `Yes` |
| [IPv4/IPv6 Discovery / Detection Test](https://www.perfect-privacy.com/check-ip/) | Checks your current IPv4/IPv6 configuration | `N/A` | `Yes` |
| [Whois Test](https://www.browserleaks.com/whois) | Basic Whois Test for Windows Users | `No` | `Yes` |
| [Mirai Vulnerability Scanner](https://www.incapsula.com/mirai-scanner/) | Basic Network Vulnerability Scanner | `N/A` | `Yes` |
| [Galhi US Test](http://ip.galih.us) | Simple IP check | `No` | `No` |
| [Check your current IP](http://checkip.dyn.com) | Yet another IP checker alternative | `N/A` | `No` |
| [ipx.ac](https://ipx.ac/run) | Offers IPv6, Geo, DNS, WebRTC FlashIP, Battery, user-Agent and more tests | `No` | `No` |
| [DNS spoofing test](https://www.grc.com/dns/dns.htm) | DNS Nameserver Spoofability Test | `no` | `No` |



## Account Management

| **Page or Addon** | **Description** | **Collects or sells user data?** | **Requires activated JavaScript**
| --- | --- | --- | --- |
| [Google Account History](https://www.google.com/settings/accounthistory) | View, manage or delete your Google Account History | `N/A` | `No` |
| [Facebook Activity Log](https://www.facebook.com/me/allactivity) | View, manage or delete your Facebook Account History | `N/A` | `No` |
| [YouTube Video History / Search History](https://www.youtube.com/feed/history) | Check your YouTube Account Feed History | `N/A` | `Yes` |
| [Microsoft Account Credentials Leak vulnerability check](https://msleak.perfect-privacy.com/) | Microsoft Account Credentials Leak vulnerability check | `Yes` Collects and stores the results | `Yes` |
| [Webbkoll](https://github.com/andersju/webbkoll) | Checks website reputation and additional security related infos | `No` | `No` |
| [Browser Extension and Login-Leak Experiment](https://extensions.inrialpes.fr/) | Browser Web Beacon test | `Yes` see [here](https://extensions.inrialpes.fr/privacy.php) | `No` |
| [Hide my Footprint](https://hmfp.absolutedouble.co.uk/) | Checks your Browser footprint | `Yes` | `Yes` |
| [Browsers leak installed extensions PoC](https://github.com/earthlng/testpages) | Detect installed Extensions | `No` | `No` |
| [Information Disclosure on IE](https://www.cracking.com.ar/demos/ieaddressbarguess/) |  Check if Internet Explorer leaks sensible Information |`Yes` | `No` |
| [ETag](http://lucb1e.com/rp/cookielesscookies/) | ETAG (Cookieless Cookies) Test | `Yes` stores results in an offline database | `Yes` |
| [Overview of all supported Two-Factor Auth (2FA) pages](https://twofactorauth.org/) | Lists all 2FA supported pages | `N/A` | `No` |
| [ASN Blocklist](https://www.enjen.net/asn-blocklist/) | Lists and shows ASN Providers | `N/A` | `No` |
| [Nextcloud Security Scan](https://scan.nextcloud.com) | Nextcloud Security Scan | `Yes` | `Yes` |
| [Test your IPv6 connectivity](https://test-ipv6.com/) | Open Source IPv6 test | [No](https://test-ipv6.com/faq.html.en_US) | `No` |
| [IP Duh](http://ipduh.com/anonymity-check/) | eTag, Ip and other checks | `Yes` | `N/A` |
| [Zscaler](http://securitypreview.zscaler.com/) | Security Check | `Yes` | `Yes` |
| [GRC](https://www.grc.com/fingerprints.htm) | GRC Fingerprints check | `N/A` | `No` |
| [CSS Keylogger with no CSP](https://no-csp-css-keylogger.badsite.io) | This site has no Content Security Policy to protect against CSS injections, and demonstrates a keylogger using only injected CSS with React as the controlled JavaScript framework. | `N/A` | `No` |
| [HTTP Request & Response Service](https://httpbin.org/) | Check eTAg | `N/A` | `No` |
| [Browser Audit](https://browseraudit.com/) | Several browser tests | `N/A` | `Yes` |
| [FP Central](https://fpcentral.irisa.fr/) | Statistics to Fingerprints (global), Tor, JavaScript tests etc | `No`, it's [open source](https://github.com/plaperdr/fp-central). | `Yes` |
| [PoC for cookieless tracking via cache](http://cookieless-user-tracking.herokuapp.com/) |  It can't be defeated except by periodically clearing your Browser cache. [Original Article](https://robertheaton.com/2014/01/20/cookieless-user-tracking-for-douchebags/) | `No` | `No`, [source code](https://github.com/robert/cookieless-user-tracking). |
| [Third-Party redirection test](https://ndossougbe.github.io/web-sandbox/interventions/3p-redirect/) | Check for enable-framebusting-needs-sameorigin-or-usergesture Chrome flag (third-party redirection) | `No` | `No` |



## Resource:// URIs leak checks

| **Page or Addon** | **Description** | **Collects or sells user data?** | **Requires activated JavaScript**
| --- | --- | --- | --- |
| [Arthured Elstein resource:// URIs leak information page](https://arthuredelstein.github.io/tordemos/resource-locale.html) | resource:// URIs leak information test page | `N/A` | `No` |
| [Resource://URI](https://www.browserleaks.com/firefox) | Resource://URI check for Firefox | `N/A` | `No` |



## Web API Test

| **Page or Addon** | **Description** | **Collects or sells user data?** | **Requires activated JavaScript**
| --- | --- | --- | --- |
| [Permission Site](https://permission.site/) | A site to test the interaction of web APIs and browser permissions.  | `No` | `Partial`, [source code](https://github.com/chromium/permission.site) |
| [Browser Storage Abuser](https://demo.agektmr.com/storage/) | Experiment for your browser storage limitation on LocalStorage, SessionStorage, WebSQL Database, IndexedDB API and FileSystem API. | `No` + [source code](https://github.com/agektmr/BrowserStorageAbuser) | `Yes`
| [PWA.rocks](https://pwa.rocks/) | Test if your Browser supports [Progressive Web Apps (PWA)](https://developers.google.com/web/progressive-web-apps/) | `No` | `Partial`



## SSL/TLS, RSA & SSH Test

| **Page or Addon** | **Description** | **Collects or sells user data?** | **Requires activated JavaScript**
| --- | --- | --- | --- |
| [Bad SSL](https://badssl.com/) | Check against Bad SSL attack | `N/A` | `No` |
| [FREAK Attack - Client Check](https://freakattack.com/clienttest.html) | Client-side FREAK attack check | `N/A` | `No` |
| [Heartbleed Test](https://filippo.io/Heartbleed/) | Heartbleed attack Test | `N/A` | `No` |
| [RC4 Fallback Test](https://rc4.io/) | Is you browser still using obsolete and weak RC 4? | `N/A` | `No` |
| [How's My SSL](https://www.howsmyssl.com/) | Check your SSL or anothers page SSL configuration | `Yes` | `Yes` |
| [SSL Cipher Suite Details](https://cc.dcsec.uni-hannover.de/) | SSL Cipher Suite Check which also shows lots of Details | `N/A` | `No` |
| [Weak Diffie-Hellman and the Logjam Attack](https://weakdh.org/) | Diffie-Hellman attack Test | `N/A` | `No` |
| [The ROBOT Attack](https://robotattack.org/#check) | ROBOT Attack Test and Tool | `No` | `No` [ROBOT Attack checking tool](https://github.com/robotattackorg/robot-detect) (Open Source) |
| [SSH Audit](https://github.com/arthepsy/ssh-audit) | Check your SSH configuration and audit it | `No` | `No` (Open Source) |
| [Fortify](https://www.fortify.net/sslcheck.html) | SSL / TLS check | `Yes`, 1 week. | `Yes` |
| [Symantec](https://cryptoreport.websecurity.symantec.com/checker/views/sslCheck.jsp) | Symantec SSL Check | `Yes`, 1 month. | `Yes` |
| [Fingerprinting TLS clients with JA3](https://jwlss.pw/ja3/) | A website qhich explains and demonstrate Fingerprinting on TLS CLients | `No` | `Yes` [(Open Source)](https://github.com/CapacitorSet/ja3-server) |
| [Vulmap](https://vulmon.com/) | Vulmap Online Local Vulnerability Scanners Project | `No` | `No` [(Open Source)](https://github.com/vulmon/Vulmap) |



## Do Not Track (DNT), Evercookie, Headers & Javascript bases tests

| **Page or Addon** | **Description** | **Collects or sells user data?** | **Requires activated JavaScript**
| --- | --- | --- | --- |
| [BrowserRecon (Header/HTTP) Test](http://www.computec.ch/projekte/browserrecon/?s=scan) | Browser Header Check | `N/A` | `No` |
| [What Is My Referer?](https://www.whatismyreferer.com/) | Check your Browser Referer | `Yes` | `Yes` |
| [Browser Referer Headers](https://www.darklaunch.com/tools/test-referer) | Another Browser Referer Check | `N/A` | `No` |
| [Do Not Track Test](https://www.browserleaks.com/donottrack) | Does my Browser sends DNT? | `No` | `Yes` |
| [Evercookie Test](http://samy.pl/evercookie/) | Evercookies Test | `N/A` | `No` |
| [JavaScript Browser Information](https://www.browserleaks.com/javascript) | Basic JavaScript Browser check | `Yes` collects an offline database| `Yes` |
| [Popup Blocking Tests](http://www.kephyr.com/popupkillertest/index.html) | Test your Browser against popups | `N/A` | `Yes` |
| [Redirect Page Test](https://jigsaw.w3.org/HTTP/300/Overview.html) | Redirect Page Test | `Yes` collects an offline database| `Yes` |
| [System Fonts Detection Test](https://www.browserleaks.com/fonts) | Detect which Fonts your Browser sends away | `No` | `Yes` |
| [FluxFonts](https://ctrl.blog/entry/fluxfonts) | Browser Font Test Page | `N/A` | `No` |
| [JavaScript/CSS Font Detector](http://www.lalit.org/lab/javascript-css-font-detect/) | CSS and JavaScript based Font Detector | `N/A` | `Yes` |
| [Universal Plug n'Play (UPnP) Internet Exposure Test](https://www.grc.com/x/ne.dll?rh1dkyd2) | Detect UPnP based leaks | `No` | `No` |
| [JavaScript: PasteJacking](https://www.sempervideo.de/pastejacking/) | PasteJacking Test | `No` | `No` |
| [Punycode converter](https://www.punycoder.com/) | Punnycode Converter Tool | `No` | `No` |
| [Unique Machine](http://uniquemachine.org/) | Is your Machine unqiue? | `No` | `No` [Source Code](https://github.com/Song-Li/cross_browser) |
| [Mozilla Observatory](https://observatory.mozilla.org/) | `Yes` Mozilla collects all tests in a database 'to improve their products' they also use their findings in Ghostery (Clicks) and other products | `No` |
| [PrivacyScore](https://privacyscore.org/) | Which Score has your privacy setup? | `Yes` | `Yes` |
| [CryptCheck](https://tls.imirhil.fr) | Simple Domain, TLS, SSH checks | `No` | `No` |
| [Qualys SSL Labs](https://www.ssllabs.com/ssltest/) | SSL Test, eMail and Domain tools | `N/A` | `No` |
| [securityheaders.io](https://securityheaders.io) | URL/Domain Scan sponsored by Sophos | `N/A` | `No` |
| [Hardenize](https://www.hardenize.com) | Header, Browser check | `Yes` collects data and shares them | `No` |
| [Google Chrome drive-by exploit tester](http://www.sempervideo.de/chrome-driveby/) | Drive-by test for Chrome weakness | `No` | `No` |
| [The Privacy.net Analyzer](http://analyze.privacy.net) | Basic Header check which also provides several other tools | `Yes` collects an offline database | `No` |
| [Spectre Vulnerability Check](http://xlab.tencent.com/special/spectre/spectre_check.html) | Spectre Vulnerability Check | `No` but holes a offline database it's unclear if it's sold or shared | `No` |
| [Are You Trackable?](http://ubercookie.robinlinus.com/) | How trackable is your Browser? |  `No` | `No` [Source Code](https://github.com/RobinLinus/ubercookie)|
| [Ubercookie Test](http://jcarlosnorte.com/assets/ubercookie/) | Ubercookie test | `Yes` collects an offline database | `No` |
| [CSS Exfil Vulnerability Tester](https://www.mike-gualtieri.com/css-exfil-vulnerability-tester) | The page tests to see if your browser is vulnerable to Cascading Style Sheets (CSS) data leakage. If you are vulnerable, one way to protect yourself is to install the CSS Exfil Protection plugin for your browser. | `No` | `No` |
| [CSS History Leak](http://lcamtuf.coredump.cx/yahh/) | CSS History Leak check | `N/A` | `No` |
| [Third Party Fingerprinting test](https://cezaraugusto.github.io/privacy-checks/fingerprinting/third-party/) | Basic Third Party Fingerprinting test page | `No` | `Yes` |
| [WTF?](https://wybiral.github.io/wtf/) | ["A practical demo of privacy violation using local service detection on a website for product recommendations."](https://twitter.com/davywtf/status/1137094721279582209) | `No` | `Yes` & localhost |



## Paste-jacking
| **Page or Addon** | **Description** | **Collects or sells user data?** | **Requires activated JavaScript**
| --- | --- | --- | --- |
| [Demo](https://thejh.net/misc/website-terminal-copy-paste) | Copy-paste the example line and run it into a terminal window to check if you're vulnerable | `No` | `No` |
| [Another demo](http://saynotolinux.com/tests/pastejacking/test.html) | See [here](https://security.stackexchange.com/questions/39118/how-can-i-protect-myself-from-this-kind-of-clipboard-abuse) for more details. | `No` | `No` | 



## DNSSEC & EDNS Test

| **Page or Addon** | **Description** | **Collects or sells user data?** | **Requires activated JavaScript**
| --- | --- | --- | --- |
| [DNSSEC Resolver Test](http://dnssec.vs.uni-due.de/) | Test the Resolver if it supports DNSSEC | `N/A` | `No` |
| [DS Algorithm Test](https://rootcanary.org/test.html) | Check if DNSSEC is weak against DS | `N/A` | `No` |
| [Internet.nl](https://internet.nl/) | eMail, connection, website and other checks | `Yes` | `Yes` |
| [DNSSEC resolver algorithm test](https://rootcanary.org/test.html) | // | `No` | `Yes` |
| [Cloudflare tools](https://www.cloudflare.com/cdn-cgi/tracepoof) | Several tracing tools, [read here](https://cloudflare-dns.com/help/) for more information. | `Yes` | `Yes` |
| [Check my DNS](https://cmdns.dev.dns-oarc.net/) | DNS & DNSSEC check | `No` | `Yes` |
| [DNS randomness](https://www.dns-oarc.net/oarc/services/dnsentropy) | DNS & DNSSEC check | `NA` | `Yes` |
| [DNS Spoofability test](https://www.grc.com/dns/dns.htm) | DNS Nameserver Spoofability Test | `No` | `No` |
| [DNSTrace](https://dnsdumpster.com/) | dns recon & research, find & lookup dns records | `No` | `Yes` |
| [EDNS test](https://ednscomp.isc.org/ednscomp/) | EDNS Compliance Tester | `No` | `No` |



## Government Network measurement software

| **Page or Addon** | **Description** | **Collects or sells user data?** | **Requires activated JavaScript**
| --- | --- | --- | --- |
| [Austria](https://www.netztest.at/) | Official Austria Internet Speed Test `Yes` collects an online database shares and sells them to ISP's and others you need to agree in everything before you can use it | `Yes` |
| [Croatia](https://hakometarplus.hakom.hr/home) | Official Croatia Internet Speed Test | `Yes` collects an online database shares and sells them to ISP's and others you need to agree in everything before you can use it | `Yes` |
| [Cyprus](http://2b2t.ocecpr.org.cy/) | Official Cyprus Internet Speed Test | `Yes` collects an online database shares and sells them to ISP's and others you need to agree in everything before you can use it | `Yes` |
| [Czech Republic](https://www.netmetr.cz/) | Official Czech Republic Internet Speed Test | `Yes` collects an online database shares and sells them to ISP's and others you need to agree in everything before you can use it | `Yes` |
| [Breitbandmessung](http://breitbandmessung.de) | Official German Internet Speed Test | `Yes` collects an online database shares and sells them to ISP's and others you need to agree in everything before you can use it | `Yes` |
| [Denmark](https://tjekditnet.dk/) | Official Denmark Internet Speed Test | `Yes` collects an online database shares and sells them to ISP's and others you need to agree in everything before you can use it | `Yes` |
| [France](https://www.arcep.fr/en/news/press-releases/detail/n/open-internet.html) | Official France Internet Speed Test | `Yes` collects an online database shares and sells them to ISP's and others you need to agree in everything before you can use it | `Yes` |
| [Greece](https://hyperiontest.gr/?action=dashboard&v=tools) | Official Greece Internet Speed Test | `Yes` collects an online database shares and sells them to ISP's and others you need to agree in everything before you can use it | `Yes` |
| [Hungary](http://szelessav.net/en/internet_speedtest) | Official Hungarian Internet Speed Test | `Yes` collects an online database shares and sells them to ISP's and others you need to agree in everything before you can use it | `Yes` |
| [Italy](https://www.misurainternet.it/) | Official Italian Internet Speed Test | `Yes` collects an online database shares and sells them to ISP's and others you need to agree in everything before you can use it | `Yes` |
| [Lativa](https://itest.sprk.gov.lv/solis1) | Official Lativa Internet Speed Test | `Yes` collects an online database shares and sells them to ISP's and others you need to agree in everything before you can use it | `Yes` |
| [Lithuania](http://matuok.lt/) | Official Lithuania Internet Speed Test | `Yes` collects an online database shares and sells them to ISP's and others you need to agree in everything before you can use it | `Yes` |
| [Norway](http://matuok.lt/) | Official Norway Internet Speed Test | `Yes` collects an online database shares and sells them to ISP's and others you need to agree in everything before you can use it | `Yes` |
| [Poland](http://www.speedtest.pl/) | Official Poland Internet Speed Test | `Yes` collects an online database shares and sells them to ISP's and others you need to agree in everything before you can use it | `Yes` |
| [Portgual](https://netmede.pt/) | Official Portugal Internet Speed Test | `Yes` collects an online database shares and sells them to ISP's and others you need to agree in everything before you can use it | `Yes` |
| [Romania](http://www.netograf.ro/) | Official Romania Internet Speed Test | `Yes` collects an online database shares and sells them to ISP's and others you need to agree in everything before you can use it | `Yes` |
| [Slovak Repualic](https://www.meracinternetu.sk/sk/test) | Official Slovak Repualic Internet Speed Test | `Yes` collects an online database shares and sells them to ISP's and others you need to agree in everything before you can use it | `Yes` |
| [Slovenia](https://www.akostest.net/en/newtest/) | Official Slovenia Internet Speed Test | `Yes` collects an online database shares and sells them to ISP's and others you need to agree in everything before you can use it | `Yes` |
| [Sweden](http://www.bredbandskollen.se/) | Official Sweden Internet Speed Test | `Yes` collects an online database shares and sells them to ISP's and others you need to agree in everything before you can use it | `Yes` |
| [Netherlands](https://speed.measurementlab.net/nl/#/) | Official Netherlands Internet Speed Test | `Yes` collects an online database shares and sells them to ISP's and others you need to agree in everything before you can use it | `Yes` |
| [United Kingdom](https://checker.ofcom.org.uk/) | Official UK Internet Speed Test | `Yes` collects an online database shares and sells them to ISP's and others you need to agree in everything before you can use it | `Yes` |



## Mouse Rate/Fingerprint Check

| **Page or Addon** | **Description** | **Collects or sells user data?** | **Requires activated JavaScript**
| --- | --- | --- | --- |
| [Enotus mouse test](http://enotus.at.tut.by/Articles/MouseTest/index.html) | Original Tracking speed and polling rate test | `No` | `No` Page down but mirrored here under /Offline |
| [Outerspace's Max IPS logger](http://maxouterspace.com/) | Tracking speeds and will show if theres negative/positive acceleration when you hit a certain speed | `N/A` | `No` |
| [Mouse Rate Checker](http://tscherwitschke.de/old/download.html) | Simple polling rate detection | `N/A` | `Yes` |
| [Mouse reaction time tester](http://www.humanbenchmark.com/tests/reactiontime) | Online mouse reaction test | `Yes` collects an online statistic database | `No` |



## Keyboard

| **Page or Addon** | **Description** | **Collects or sells user data?** | **Requires activated JavaScript**
| --- | --- | --- | --- |
| [Javascript Key Event Test Script](http://unixpapa.com/js/testkey.html) | Basically a JS keylogger check | `N/A` | `Yes` |
| [JavaScript Event KeyCode Test Page](http://www.asquare.net/javascript/tests/KeyCode.html) | Another keystroke test | `N/A` | `Yes` |
| [Keyboard Event Viewer]( https://w3c.github.io/uievents/tools/key-event-viewer.html) | `N/A` | `No` |



## Advanced Fingerprint Tests

| **Page or Addon** | **Description** | **Collects or sells user data?** | **Requires activated JavaScript**
| --- | --- | --- | --- |
| [Am I Unique?](https://amiunique.org/fp) | Is your Machine / Browser unique? | `N/A` | `Yes` |
| [Browser Spy](http://browserspy.dk/) | Multiple Browser Tests | `N/A` | `Yes` |
| [Cross Browser Fingerprinting Test](http://fingerprint.pet-portal.eu/) | Multiple Browser Test | `N/A` | `Yes` User must to disable its ad-blocker! |
| [Jondonym Full Anonymity Test](http://ip-check.info/?lang=en) | The first and original anonymity test | `No` | `Yes` |
| [Panopticlick](https://panopticlick.eff.org/) | The most well-known Browser Fingerprint check by EFF | `Yes` collects stats and stores them in a database | `Yes` |
| [Browserprint.Info](https://browserprint.info/test) | Another JavaScript based Fingerprinting Test |`Yes` collects stats and stores them in a database | `Yes` |
| [Browserprint check](https://fingerprint.pet-portal.eu/) | Another advance fingerprinting check | `No` | `Yes` - Currently (?) Offline |
| [PC Flank](http://www.pcflank.com/index.htm) | Random Browser Check | `N/A` | `Yes` |
| [Onion Leak Test](http://cure53.de/leak/onion.php) | Check your .onion | `N/A` | `Yes` |
| [Whoer](https://whoer.net/) | Advance Browser check | `Yes` Sells the results | `Yes` for advance informations/tests |
| [Popup Test](http://www.popuptest.com/) | Check how good your Browser performs against Popups | `N/A` | `Yes` |
| [Privacy Check](http://do-know.com/privacy-test.html) | Another overall Browser header/leak test | `Yes` | `Yes` |
| [Audio Fingerprint Test](https://audiofingerprint.openwpm.com/) | The original audio fingerprint test | `No` | `Yes` ([Source Code](https://github.com/Gitoffthelawn)) |
| [Browser 'auto-download' Security Vulnerability](https://binaer.xyz/haifei-li/test.html) | Check Chrome, IDM and other Downloader against a security attack | `N/A` | `No` |
| [Check2IP](http://check2ip.com/) | One of the oldest advance Browser/IP tests | `No` | `Yes` only for advance tests but also works without |
| [HTML5 Canvas Fingerprinting](https://browserleaks.com/canvas) | Canvas HTML5 API Browser Test | `N/A` | `Yes` |
| [5who](http://5who.net/?type=extend) | Multiple tests | `N/A` | `Yes` |
| [Punycode](https://www.xn--80ak6aa92e.com) | See the [Article](https://www.xudongz.com/blog/2017/idn-phishing/) | `N/A` | `No` |
| [FingerPrintJS2](https://valve.github.io/fingerprintjs2/) | Check your Browser fingerprint | `N/A` | `Yes` |
| [BrowserPlugs](https://www.browserplugs.com/fingerprint-test/index.html) | Check your Browser fingerprint with 3 different test scenarios | `N/A` | `Yes`, for the first test |
| [Device Info](https://www.deviceinfo.me/) | Canvas, Battery Status, ActiveX, City, CPU, Country, Connection type, Device detection & more. | `N/A` | `Yes` |



## HTTP Strict Transport Security (HSTS)

| **Page or Addon** | **Description** | **Collects or sells user data?** | **Requires activated JavaScript**
| --- | --- | --- | --- |
| [Chromium's HSTS preload list submission website](https://hstspreload.org) | Chromium's HSTS preload list submission website | `N/A` | `N/A` |
| HSTS [sniffly](http://zyan.scripts.mit.edu/sniffly/) | A practical timing attack to sniff browser history using HSTS in Chrome and Firefox. Please disable HTTPS Everywhere for best results. | `N/A` | `N/A` |



## Tor Network & Fingerprint Test

| **Page or Addon** | **Description** | **Collects or sells user data?** | **Requires activated JavaScript**
| --- | --- | --- | --- |
| [TorCheck at Xenobite.eu](https://torcheck.xenobite.eu/index.php) | Advance Tor Network Check | `No` | `Yes` |
| [Tor Fingerprint Test](https://tor.triop.se/) | Basic Tor Network Check | `N/A` | `No` |



## Cryptography Test

| **Page or Addon** | **Description** | **Collects or sells user data?** | **Requires activated JavaScript**
| --- | --- | --- | --- |
| [Shattered SHA1 attack](https://shattered.io) | SHA1 collusion attack example | `No` | `No` |



## ISP Throttling check

| **Page or Addon** | **Description** | **Collects or sells user data?** | **Requires activated JavaScript**
| --- | --- | --- | --- |
| [Internet Health Test](https://www.battleforthenet.com/internethealthtest/) | Test if your ISP is throttling you | `N/A` | `No` |
| [BitTorrent Traffic Shaping](https://neubot.nexacenter.org/download) | Check if your ISP is throttling BitTorrent Traffic | `N/A` | `No` |
| [The Internet Health Test](https://www.battleforthenet.com/internethealthtest/) | Test if your ISP is throttling you | `Yes` collects an database and possible sells it (needs confirmation) | `No` |
| [Switzerland](https://www.eff.org/pages/switzerland-network-testing-tool) | [Tool](https://sourceforge.net/projects/switzerland/) from EFF to check if your ISP blocks or interfering into VOIP traffic |  `No` | `No` |



## Web Search Engine which can show & Inspect the Source Code

| **Page or Addon** | **Description** | **Collects or sells user data?** | **Requires activated JavaScript**
| --- | --- | --- | --- |
| [Source Code Search Engine](https://publicwww.com) | Inspect the Page Source Code | `Yes` logs and collect databases | `Yes` |



## Cookie Test
| **Page or Addon** | **Description** | **Collects or sells user data?** | **Requires activated JavaScript**
| --- | --- | --- | --- |
| [Test if you leak cookies (after disabling them)](http://raymondhill.net/httpsb/httpsb-test-cookie-1.php) | Cookie test to check if your extensions which are supposed to block cookies doing their job | `No` | `No` |



## Firewall Test

| **Page or Addon** | **Description** | **Collects or sells user data?** | **Requires activated JavaScript**
| --- | --- | --- | --- |
| [Test your Metal](http://metal.fortiguard.com/tests/) | Check your firewall online against known ports | `Yes` logs and collect databases | `Yes` |
| [Port Checker](https://portchecker.co/) | Check your Firewall against known or custom ports | `Yes` logs and collect databases | `Yes` |
| [ShieldsUp!](https://www.grc.com/faq-shieldsup.htm) | Check your Firewall against known or custom Ports | `No` | `No` |
| [PenTest yourself. Don't get hacked](https://pentest-tools.com/home) | Check your Firewall against a pre-made list | `N/A` | `No` |
| [HackerWatch](https://www.hackerwatch.org/probe/) | Check your Firewall against a pre-made list | `Yes` collects an statistic offline database  | `Yes` |
| [Hacker Target](https://hackertarget.com/firewall-test/) | Check your Firewall against a pre-made list | `Yes` collects an statistic offline database  | `Yes` |
| [CanYouSeeMe.org](http://canyouseeme.org/) | Basic Firewall test | `N/A` | `No` |



## Torrent Leak Test

| **Page or Addon** | **Description** | **Collects or sells user data?** | **Requires activated JavaScript**
| --- | --- | --- | --- |
| [ipMagnet](http://ipmagnet.services.cbcdn.com/) | Magnet IP expose check | `N/A` | `No` |
| [Check My Torrent IP](https://torguard.net/checkmytorrentipaddress.php) | Check which IP your Torrent Network sees | `Yes` collects a statistic database | `No` |
| [I know what you downloaded](https://iknowwhatyoudownload.com/en/peer/) | Check what your peer sees about you | `N/A` | `No` |
| [IP Magnet Test](http://ipmagnet.services.cbcdn.com/) | Allows you to see which IP address your BitTorrent Client is handing out to its peers and trackers! | `No` | `No` |



## Ransomware Decrypter

| **Page or Addon** | **Description** | **Collects or sells user data?** | **Requires activated JavaScript**
| --- | --- | --- | --- |
| [NoMoreRansom](https://www.nomoreransom.org) | Official against Ransomware page for help, decrypter and information | `N/A` | `No` |
| [Free Ransomware Decryptors - Kaspersky Lab](https://noransom.kaspersky.com/) | Kaspersky's Ransomware Help Page | `N/A` | `N/A` |
| [Avast Free Ransomware Decryption Tools](https://www.avast.com/ransomware-decryption-tools) | Free Ransomware Decryption Tools by Avast | `N/A` | `N/A` |
| [Emsisoft Decrypter Tools](https://decrypter.emsisoft.com/) | Emsisoft Decrypter | `N/A` | `N/A` |
| [Trend Micro Ransomware File Decryptor Tool](https://success.trendmicro.com/solution/1114221-downloading-and-using-the-trend-micro-ransomware-file-decryptor) | Several decrypter powered by TrendMicro | `N/A` | `N/A` |
| [Heimdal Decrypter Tools](https://heimdalsecurity.com/blog/ransomware-decryption-tools/) | Bunch of decrypter utilities | `N/A` | `N/A` |
| [Free Ransomware Decryption Tools](https://www.avg.com/en-ww/ransomware-decryption-tools) | Decrypter tools by Avast | `N/A` | `N/A` |
| [Download All Known Ransomware Decryption Tools](https://www.mdsny.com/decryption-tools/) | MDS collection of all known Ransomware decryoter | `N/A` | `N/A` |



## Identify Theft Check

| **Page or Addon** | **Description** | **Collects or sells user data?** | **Requires activated JavaScript**
| --- | --- | --- | --- |
| [Have I Been Pwned](https://haveibeenpwned.com) | Check if your identiy (email etc.) was used/stolen by someone else | `Yes` collects an database (need confirmation if sold to 3rd-parties) | `Partial` |
| [Shodan.io](https://www.shodan.io/) | Search for devices, vuln. etc | `Yes` collects an database (need confirmation if sold to 3rd-parties) | `Yes` |
| [New York Attorney General Eric Schneiderman tool](https://ag.ny.gov/fakecomments) | Tool which check fake comments based on a database of known fakers | `Yes` collects an database (need confirmation if sold to 3rd-parties) | `N/A` |
| [Censys.io](https://censys.io/) | Get the information you need to prevent threats and improve overall security. | `N/A` | `Partial` |
| [ZoomEye](https://www.zoomeye.org/) | Cyberspace Search Engine | `No` | `Partial` |



## Browser Benchmarks

Keep in mind that a Browser Benchmark doesn't reflect the real-world performance of a website, as explained over [here](https://news.softpedia.com/news/google-to-drop-support-for-octane-browser-benchmark-514942.shtml).

| **Page or Addon** | **Description** | **Collects or sells user data?** | **Requires activated JavaScript**
| --- | --- | --- | --- |
| [Speedometer](http://browserbench.org/Speedometer/) | JavaScript based Browser Benchmark | `Yes` collects an database (need confirmation if sold to 3rd-parties) | `Yes` |
| [ARES 6](http://browserbench.org/ARES-6/) | JavaScript based Browser Benchmark | `Yes` collects an database (need confirmation if sold to 3rd-parties) | `Yes` |
| [Motion Mark](http://browserbench.org/MotionMark/) | JavaScript based Browser Benchmark | `Yes` collects an database (need confirmation if sold to 3rd-parties) | `Yes` |
| [JetStream](http://browserbench.org/JetStream/) | JavaScript based Browser Benchmark | `Yes` collects an database (need confirmation if sold to 3rd-parties) | `Yes` |
| [Lite Brite](https://testdrive-archive.azurewebsites.net/Performance/LiteBrite/) | JavaScript based Browser Benchmark | `Yes` collects an database (need confirmation if sold to 3rd-parties) | `Yes` |
| [Octane](https://chromium.github.io/octane/) | JavaScript based Browser Benchmark | `Yes` collects an database (need confirmation if sold to 3rd-parties) | `Yes` |
| [Dromaeo](http://dromaeo.com) | JavaScript based Browser Benchmark | `Yes` collects an database (need confirmation if sold to 3rd-parties) | `Yes` |
| [Acid 3](http://acid3.acidtests.org/) | JavaScript based Browser Benchmark | `Yes` collects an database (need confirmation if sold to 3rd-parties) | `Yes` |



## Sandboxes Virus/Malware/HTTP Analyzer

| **Page or Addon** | **Description** | **Collects or sells user data?** | **Requires activated JavaScript**
| --- | --- | --- | --- |
| [BitBlaze](http://bitblaze.cs.berkeley.edu/) | The BitBlaze Binary Analysis Platform | `No`, it's open source | `No` |
| [Hybrid Analysis](https://www.hybrid-analysis.com/) + [Mirror](https://www.reverse.it/) | Free Malware analysis service for the community that detects and analyzes unknown threats using a unique Hybrid Analysis technology | `N/A` | `Yes` for the WebInterface. |
| [Jevereg](http://jevereg.amnpardaz.com/) | Jevereg analyses the behavior of potential malicious executables | `N/A` | `No` |
| [Sunbelt Sandbox](https://www.threattrack.com/malware-analysis.aspx) | Dig Deep with Malware Analysis | `Yes` Tracks IP, collects data and sells them. | `Yes` |
| [ThreatExpert](http://www.threatexpert.com/) | ThreatExpert is an advanced automated threat analysis system designed to analyze and report the behavior of computer viruses, worms, trojans, adware, spyware, and other security-related risks in a fully automated mode. | `N/A` | `N/A` |
| [ViCheck](https://vicheck.ca/) | Advanced Detection Tools to Stop Malware | `N/A` | `No` |
| [detux](https://detux.org/) | Multiplatform Linux Sandbox | `N/A` | `No` |
| [Nviso](https://apkscan.nviso.be/) | Nviso APK scan | `N/A` | `Yes` |
| [Java Script Beatify](http://jsbeautifier.org/) | Beautify, unpack or deobfuscate JavaScript and HTML, make JSON/JSONP readable, etc. | `N/A` | `Yes` |
| [PDF Examiner](http://www.malwaretracker.com/pdf.php) | Scan PDF files | `N/A` | `No` |
| [Rex Swain's HTTP Viewer](http://www.rexswain.com/httpview.html) | See exactly what an HTTP request returns to your browser | `N/A` | `N/A` |
| [JSUNPACK](http://jsunpack.jeek.org/dec/go) | jsunpack was designed for security researchers and computer professionals | `N/A` | `N/A` |
| [Google VirusTotal](https://www.virustotal.com/) | Analyze suspicious files and URLs to detect types of malware, automatically share them with the security community. | `Yes`, see [privacy policy](https://support.virustotal.com/hc/en-us/articles/115002168385-Privacy-Policy). | `N/A` |
| [Jotti](https://virusscan.jotti.org/) | Jotti's malware scan is a free service that lets you scan suspicious files with several anti-virus programs. | `Yes`, see [Privacy Policy](https://virusscan.jotti.org/en-US/doc/privacy). | `N/A` |



## Online Link Checkers

| **Page or Addon** | **Description** | **Collects or sells user data?** | **Requires activated JavaScript**
| --- | --- | --- | --- |
| [Dr.Web Online Scanner](https://vms.drweb-av.de/online/) | URL link checker | `Yes` | `Yes` |
| [Google Safe Browsing](https://transparencyreport.google.com/safe-browsing/search?url=putyourlinkhere.com) | Change putyourlinkhere.com to url you want to check! | `Yes`, see [here](https://support.google.com/transparencyreport/). | `Yes` |
| [Google Safe Browsing Testing Links](https://testsafebrowsing.appspot.com) | The tests are safe to use, it basically checks your Browser settings | `Yes`, for some tests |
| [Norton Safe Web](https://safeweb.norton.com/) | Look up a site. Get our rating. | `Yes`, see [privacy policy](http://nortonsafe.search.ask.com/docs/privacy?geo=&prt=cr&o=APN11908&chn=&ver=) | `Yes` |
| [URL Void](http://www.urlvoid.com/) | Website Reputation Checker Tool | `Yes`, see [terms and privacy](http://www.privalicy.com/privacy-policy/21312665/) | `Yes` |
| [vURL Online](http://vurl.mysteryfcm.co.uk/) | Quickly and safely dissect malicious or suspect websites | `Yes`, IP address of the requesting computer is recorded along with the URL accessed. Stored for 1 week. | `No` |
| [Online Link Scan](http://onlinelinkscan.com/) | Prevent infection and data theft with Online Link Scan. | `N/A` | `N/A` |



## Online IP Scanner

| **Page or Addon** | **Description** | **Collects or sells user data?** | **Requires activated JavaScript**
| --- | --- | --- | --- |
| [GreyNoise Visualizer](https://viz.greynoise.io/) | Tracks _every_ IP + mass scanning/attacking the Internet and Visalize them | `No` | `No` |
| TCPIPUtils now [DNSLytics](https://dnslytics.com/) | One of the biggest and oldest IP/Domain tracking service | `Yes` | `Yes` |



## Opt-Out of targeting based Ads

| **Page or Addon** | **Description** | **Collects or sells user data?** | **Requires activated JavaScript**
| --- | --- | --- | --- |
| [Stop Targeting Ads at Me](https://stoptargetingads.me/) | Helps you turn off targeted ads on 41 websites, apps, and devices | `No` | `Yes` |
| [Your Online Choice](http://www.youronlinechoices.com/uk/your-ad-choices) | Take control over your ad choices | `Yes` | `Yes` |
| [YourAdChoices](http://optout.aboutads.info/?c=2&lang=EN) | WebChoices checks whether your browser can set opt out requests | `Yes` | `Yes` |
| [Simple Opt-Out](http://simpleoptout.com/) | A (HTTP only) website which allows you to out of data sharing by 50+ companies | `No` | `No` |



## Intel

| **Page or Addon** | **Description** | **Collects or sells user data?** | **Requires activated JavaScript**
| --- | --- | --- | --- |
| RIDL and Fallout: MDS attacks | Information & utility for Windows/Linux to check against MDS attacks | `No` | No, it's a [info website](https://mdsattacks.com/) + tool ([Source Code](https://github.com/vusec/ridl)) |



## Progressive Web Applications (PWA) Tracking Test

| **Page or Addon** | **Description** | **Collects or sells user data?** | **Requires activated JavaScript**
| --- | --- | --- | --- |
| [Persistent Web Apprehension](https://pwapprehension.sensorsprivacy.com/) | Cookie respawn which makes it impossible to clear website identifiers | `No` |



## Browser Audit Test

| **Page or Addon** | **Description** | **Collects or sells user data?** | **Requires activated JavaScript**
| --- | --- | --- | --- |
| [Browser Audit Test](https://browseraudit.com/test) | Test your Browser for known holes | `N/A` | `Yes` |


