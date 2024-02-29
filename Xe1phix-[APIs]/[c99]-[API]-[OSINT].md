#!/bin/bash	
json=""

key="" # change me

 for i; do 
	if [ "$i" = "json" ]; then
		json="&json"
	
	fi
 done

if [ "$json" = "&json" ]; then
	case $1 in
	   "cfsub") curl -s "https://api.c99.nl/subdomainfinder?key=$key&domain=$2$json" | json_pp  ;;
	   "phone") curl -s "https://api.c99.nl/phonelookup?key=$key&number=$2$json" | json_pp  ;;
	   "gif")  curl  -G -s "https://api.c99.nl/gif?key=$key" --data-urlencode "keyword=$2" --data-urlencode "json"  | json_pp ;;
	   "sms") curl -s "https://api.c99.nl/smsreceiver?key=$key&country=$2$json" | json_pp  ;;
	   "skypecheck") curl -s "https://api.c99.nl/skypecheck?key=$key&username=$2$json" | json_pp ;;
	   "skype2ip") curl -s "https://api.c99.nl/skyperesolver?key=$key&username=$2$json" | json_pp  ;;
	   "ip2skype") curl -s "https://api.c99.nl/ip2skype?key=$key&ip=$2$json" | json_pp  ;;
	   "email2skype") curl -s "https://api.c99.nl/email2skype?key=$key&email=$2$json" | json_pp  ;;
	   "WAF") curl -s "https://api.c99.nl/firewalldetector?key=$key&url=$2$json" | json_pp  ;;
	   "portscan") curl -s "https://api.c99.nl/portscanner?key=$key&host=$2$json" | json_pp  ;;
	   "scanport") curl -s "https://api.c99.nl/portscanner?key=$key&host=$2&port=$3$json" | json_pp  ;;
	   "nmap") curl -s "https://api.c99.nl/nmap?key=$key&host=$2$json" | json_pp  ;;
	   "ping") curl -s "https://api.c99.nl/ping?key=$key&host=$2$json" | json_pp  ;;
	   "ip2host") curl -s "https://api.c99.nl/gethostname?key=$key&host=$2$json" | json_pp   ;;
	   "advdns") curl -s "https://api.c99.nl/dnschecker?key=$key&url=$2&type=$3$json" | json_pp  ;;
	   "host2ip") curl -s "https://api.c99.nl/dnsresolver?key=$key&host=$2$json" | json_pp ;;
	   "domain") curl -s "https://api.c99.nl/domainchecker?key=$key&domain=$2$json" | json_pp ;;
	   "dnshistory") curl -s "https://api.c99.nl/domainhistory?key=$key&domain=$2$json" | json_pp  ;;
	   "ip2domain") curl -s "https://api.c99.nl/ip2domains?key=$key&ip=$2$json" | json_pp  ;;
	   "alexa") curl -s "https://api.c99.nl/alexarank?key=$key&url=$2$json" | json_pp  ;;
	   "whois") curl -s "https://api.c99.nl/whois?key=$key&domain=$2$json" | json_pp  ;;
	   "screen") curl -s "https://api.c99.nl/createscreenshot?key=$key&url=$2$json" | json_pp  ;;
	   "geoip") curl -s "https://api.c99.nl/geoip?key=$key&host=$2$json" | json_pp ;;
	   "updown") curl -s "https://api.c99.nl/upordown?key=$key&host=$2$json" | json_pp  ;;
	   "rep") curl -s "https://api.c99.nl/reputationchecker?key=$key&url=$2$json" | json_pp ;;
	   "headers") curl -s "https://api.c99.nl/getheaders?key=$key&host=$2$json" | json_pp  ;;
	   "backup") curl -s "https://api.c99.nl/linkbackup?key=$key&url=$2$json" | json_pp ;;
	   "shorten") curl -s "https://api.c99.nl/urlshortener?key=$key&url=$2$json" | json_pp  ;;
	   "randstr") curl -s "https://api.c99.nl/randomstringpicker?key=$key&textfile=$2$json" | json_pp ;;
	   "dict") curl -s "https://api.c99.nl/dictionary?key=$key&word=$2$json" | json_pp ;;
	   "reverse") curl -s "https://api.c99.nl/definepicture?key=$key&url=$2$json" | json_pp  ;;
	   "geoip") curl -s "https://api.c99.nl/synonym?key=$key&word=$2$json" | json_pp ;;
	   "validemail") curl -s "https://api.c99.nl/emailvalidator?key=$key&email=$2$json" | json_pp ;;
	   "tempcheck") curl -s "https://api.c99.nl/disposablemailchecker?key=$key&email=$2$json" | json_pp ;;
	   "validip") curl -s "https://api.c99.nl/ipvalidator?key=$key&ip=$2$json" | json_pp  ;;
	   "torcheck") curl -s "https://api.c99.nl/torchecker?key=$key&ip=$2$json" | json_pp ;;
	   "translate") curl -s "https://api.c99.nl/translate?key=$key&text=$2d&tolanguage=$3$json" | json_pp;;
	   "info") curl -s "https://api.c99.nl/randomperson?key=$key&gender=$2$json" | json_pp ;;
	   "ytdetails") curl -s "https://api.c99.nl/youtubedetails?key=$key&videoid=$2$json" | json_pp ;;
	   "yt2mp3") curl -s "https://api.c99.nl/youtubemp3?key=$key&videoid=$2$json" | json_pp ;;
	   "iplogger") curl -s "https://api.c99.nl/iplogger?key=$key&action=viewloggers&json" | json_pp  ;;
	   "bitbalance") curl -s "https://api.c99.nl/bitcoinbalance?key=$key&address=$2$json" | json_pp ;;
	   "bitaccelerator") curl -s "https://api.c99.nl/bitcoinaccelerator?key=$key&txn_id=$2$json" | json_pp  ;;
	   "ethbalance") curl -s "https://api.c99.nl/ethereumbalance?key=$key&address=$2$json" | json_pp  ;;
	   "currency") curl -s "https://api.c99.nl/currency?key=$key&amount=$2&from=$3&to=$4$json" | json_pp  ;;
	   "currencyrate") curl -s "https://api.c99.nl/currencyrates?key=$key&source=$2$json" | json_pp  ;;
	   "weather") curl -s "https://api.c99.nl/weather?key=$key&location=$2$json" | json_pp  ;;
	   "gennqr") curl -s "https://api.c99.nl/qrgenerator?key=$key&string=$2d&size=$3$json" | json_pp  ;;
	   "img2txt") curl -s "https://api.c99.nl/textparser?key=$key&url=$2$json" | json_pp  ;;
	   "proxy") curl -s "https://api.c99.nl/proxylist?key=$key&limit=$2&type=$3&anonimity=$4&country=$5$json" | json_pp ;;
	   "detectproxy") curl -s "https://api.c99.nl/proxydetector?key=$key&ip=$2$json" | json_pp  ;;
	   "genpassword") curl -s "https://api.c99.nl/passwordgenerator?key=$key&length=$2&include=$3&customlist=$4$json" | json_pp  ;;
	   "randnumber") curl -s "https://api.c99.nl/randomnumber?key=$key&length=$2&between=$3,$4$json" | json_pp ;;
	   "license") curl -s "https://api.c99.nl/licensekeygenerator?key=$key&template=$2&amount=$3$json" | json_pp ;;
	   "eitheror") curl -s "https://api.c99.nl/eitheror?key=$key&json" | json_pp  ;;
	   "-h") echo " 
	--------------------------- CLI C99 API -----------------------------------------

	 This script is desinged to implemented the C99.nl API's into the command line.

	Basic usage is :

	c99nl.sh <API> [look at the list below for required infomation] ( you can add 'json' to the end of any command to retrieve json data)

	THIS SCRIPT REQUIRES YOUR OWN API KEY. ADD YOUR KEY TO THE ABOVE VARIABLE.
	 

	cfsub		<DOMAIN>
		Subdomain Finder and CloudFlare Resolver: Performs an advanced subdomain scan to find most subdomains of the given domain.
	phone		<PHONE NUMBER> # This should be in international format eg. +310000000000
		Phone Lookup: Get more information about any phone number.
	gif		<GIF KEYWORD>
		GIF Finder: Gives you a list of animated GIF's based on the given keyword.
	sms 		<COUNTRY CODE>
		SMS Receiver: Receives SMS from the past hour. Country codes: US, CA, UK
	skypecheck	<USERNAME>
		Skype Check: Checks if a Skype account exists or not.
	skype2ip	<USERNAME>
		Skype Resolver: Attempts to grab an IP address of a Skype account, results are not guaranteed. (This is completely legal as it uses publicly available records)		
	ip2skype	<IP ADDRESS> eg. 1.1.1.1
		IP 2 Skype: Shows all Skype accounts with that specific IP.(This is completely legal as it uses publicly available records)
	email2skype	<EMAIL ADDRESS>
		Email 2 Skype: Gets Skype accounts associated with e-mail.(This is completely legal as it uses publicly available records)
	WAF		<IP ADDRESS> eg. 1.1.1.1
		Firewall Technology (WAF) Detector: Scans to detect if a website is behind a firewall and determines what firewall it is.
	portscan	<IP ADDRESS> eg. 1.1.1.1
		 Multiple Port Scanner: Scans all ports of given host.
	scanport	<IP ADDRESS> <PORT>
		Single Port Scanner: Scans a single port of given host.
	nmap		<IP ADDRESS>
		Nmap Scanner: Performs an nmap scan to find open ports.
	ping		<IP ADDRESS>
		Ping: Pings a host 4 times and shows the result.
	ip2host		<IP ADDRESS>
		IP to Host: Gets host of given IP address.
	advdns		<URL> <RECORD TYPE>
		Advanced DNS Checker: Performs an advanced check on the specific URL. Parameter &server=[countrycode] is optional. If left empty, all servers will be used. Possible check types: a, aaaa, cname, mx, ns, soa, txt
	host2ip		<URL>
		Host to IP: Gets server IP of given host.
	domain		<DOMAIN NAME>
		Domain Checker: Checks whether a domain is available or not, no matter what extension.
	dnshistory	<DOMAIN NAME>
		Domain History Check: Checks available IP history of a domain with dates.
	ip2domain	<IP ADDRESS>
		IP 2 Domains: Attempts to find websites hosted on the specific IP address.
	alexa		<DOMAIN NAME>
		Alexa Rank Checker: Grab the latest Alexa Rank information of any website, including backlinks and top country.
	whois		<DOMAIN NAME>
		Whois Checker: Whois check on a domain to see who the domain owner is.
	screen		<URL>
		Screenshot Tool: Creates a screenshot of any website/url you want.
	geoip		<IP ADDRESS>
		GeoIP: Locates the given host/ip address.
		
	updown		<DOAMIN NAME>
		Website Up or Down Checker: Checks if a host is up or down.
	rep		<DOAMIN NAME>
		Site/URL Reputation Checker: Checks whether a specific site/url is suspicious and might contain malware, phishing or other potential harmful software.
	headers		<URL>
		Get Website Headers: Gets the headers of a website.
	backup		<URL>
		Link Backup: Makes an online backup of a link.
	shorten		<URL>
		URL Shortener: Shorts every long URL.
	randstr		<URL TO TXT FILE>
		Random String Picker: Gets random string from given text file.
	dict		<WORD>
		Dictionary: Gets the definition of any word.
	reverse		<URL TO IMAGE>
		Image Reverse / Define Picture: Reverses the image/picture given and determines what's on it.
	synonym		<IP ADDRESS>
		Synonym Finder: Gets the alternative words/synonyms for any legitimate english word you fill in.
	validemail	<EMAIL ADDRESS
		Email Validator: Checks if given up e-mail exists.
	tempcheck	<EMAIL ADDRESS>
		Disposable Mail Check: Checks if given up e-mail is disposable/temporarily or not.
	validip		<IP ADDRESS>
		IP Validator: Checks if IP address format is valid.
	torcheck	<IP ADDRESS>
		TOR Checker: Checks whether an IP is from a TOR network or not.
	translate	<TEXT TO TRANSLATE> <COUNTRY CODE> # The country code manage what the text will be translated too.
		Translator: Translates your text (autodetected) to any language.
	info		<GENDER> Eg. male,female,all
		Random Info Generator: Generates random name address etc. (genders: male/female/all).
	ytdetails	<YOUTUBE VIDEO ID>
		Youtube Video Details: Gets all details of a specific YouTube video.
	yt2mp3		<YOUTUBE VIDEO ID>
		Youtube to MP3: Converts any song up to 10 minutes to MP3.
	iplogger	
		IP Logger: Creates you various links which you can send to anyone to log their IP.
	bitbalance	<WALLET ADDRESS>
		Bitcoin Balance Checker: Checks the current balance of any Bitcoin address.
	bitaccelerator	<TRANSACTION ID>
		Bitcoin Transaction Accelerator: Accelerates/boosts every unconfirmed transaction in the Bitcoin network.
	ethereumbalance	<WALLET ADDRESS>
		Ethereum Balance Checker: Checks the current balance of any Ethereum address.
	currency	<AMOUNT> <FROM CURRENCY CODE> <TO CURRENCY CODE> Eg. C99nl.sh currency 150 USD GBP
		Currency Converter: Converts normal and cryptocurrencies to any other currency.
	currencyrate	<CURRENCY CODE> Eg. USD
		Currency Rates: Shows the rate of every currency in the world based on the unit price of the given source.
	weather		<LOCATION> Eg. Miami
		Weather Checker: Checks the weather of every city or postal code you give up. Change &unit= to F for Fahrenheit and C for Celcius.
	gennqr		<STRING> <SIZE>
		QR Code Generator: Generates a QR code and uploads it to imgur, useful to quickly share a piece of text or URL.
	img2txt		<IMAGE URL>
		Text Parser: Extracts text from any image. It works best on English text.
	proxy		<PROXY AMOUNT> <PROXY TYPE> <ANONIMITY LEVEL> <COUNTRY CODE>
		Proxylist fetcher: Fetches you a fresh proxylist, up to 1000 proxies. Types: http, https, socks4, socks5 Anonimity: Anonymous, Elite, Transparent. Countries: US, CA, NL, DE, FR, ES.
	detectproxy	<IP ADDRESS>
		Proxy Detector: Detects whether an IP address is a proxy/vpn or not. High accuracy!
	genpassword	<LENGTH> <CHARACTER TYPES> # Passwords reset every 1 second not every request.
		Password Generator: Generates a random password based on the given configuration.
	randnumber	<LENGTH> <LOWEST NUMBER> <HIGHEST NUMBER> Eg. C99nl.sh randnumber 10 0 100 (generated 10 numbers between 0 and 100)
		Random number generator: Generates a random number based on the given length or between parameter. (You can only use length or between, not both)
	license		<TEMPLATE> <AMOUNT> Eg. C99nl.sh ????-????-????-???? 20
		License Key Generator: Generates a randomized license using given template. Wildcards are: * ? and %. * is alphabetic, % is numeric, ? is mixed.
	eitheror	
		Either or: Provides a random 'would you rather' question/dilemma, giving two hard options. (We recommend using JSON)
	---------------------------------------------------------------------------------
";; 

esac

else
	case $1 in
	   "cfsub") curl -s "https://api.c99.nl/subdomainfinder?key=$key&domain=$2$json" | sed 's/<br>/\n/g'  ;;
	   "phone") curl -s "https://api.c99.nl/phonelookup?key=$key&number=$2$json" | sed 's/<br>/\n/g'  ;;
	   "gif")  curl  -G -s "https://api.c99.nl/gif?key=$key" --data-urlencode "keyword=$2" | sed 's/<br>/\n/g'  ;;
	   "sms") curl -s "https://api.c99.nl/smsreceiver?key=$key&country=$2$json" | sed 's/<br>/\n/g'  ;;
	   "skypecheck") curl -s "https://api.c99.nl/skypecheck?key=$key&username=$2$json" | sed 's/<br>/\n/g'  ;;
	   "skype2ip") curl -s "https://api.c99.nl/skyperesolver?key=$key&username=$2$json" | sed 's/<br>/\n/g'  ;;
	   "ip2skype") curl -s "https://api.c99.nl/ip2skype?key=$key&ip=$2$json" | sed 's/<br>/\n/g'  ;;
	   "email2skype") curl -s "https://api.c99.nl/email2skype?key=$key&email=$2$json" | sed 's/<br>/\n/g'  ;;
	   "WAF") curl -s "https://api.c99.nl/firewalldetector?key=$key&url=$2$json" | sed 's/<br>/\n/g'  ;;
	   "portscan") curl -s "https://api.c99.nl/portscanner?key=$key&host=$2$json" | sed 's/<br>/\n/g'  ;;
	   "scanport") curl -s "https://api.c99.nl/portscanner?key=$key&host=$2&port=$3$json" | sed 's/<br>/\n/g'  ;;
	   "nmap") curl -s "https://api.c99.nl/nmap?key=$key&host=$2$json" | sed 's/<br>/\n/g'  ;;
	   "ping") curl -s "https://api.c99.nl/ping?key=$key&host=$2$json" | sed 's/<br>/\n/g'  ;;
	   "ip2host") curl -s "https://api.c99.nl/gethostname?key=$key&host=$2$json" | sed 's/<br>/\n/g'  ;;
	   "advdns") curl -s "https://api.c99.nl/dnschecker?key=$key&url=$2&type=$3$json" | sed 's/<br>/\n/g'  ;;
	   "host2ip") curl -s "https://api.c99.nl/dnsresolver?key=$key&host=$2$json" | sed 's/<br>/\n/g' ;;
	   "domain") curl -s "https://api.c99.nl/domainchecker?key=$key&domain=$2$json" | sed 's/<br>/\n/g' ;;
	   "dnshistory") curl -s "https://api.c99.nl/domainhistory?key=$key&domain=$2$json" | sed 's/<br>/\n/g'  ;;
	   "ip2domain") curl -s "https://api.c99.nl/ip2domains?key=$key&ip=$2$json" | sed 's/<br>/\n/g'  ;;
	   "alexa") curl -s "https://api.c99.nl/alexarank?key=$key&url=$2$json" | sed 's/<br>/\n/g'  ;;
	   "whois") curl -s "https://api.c99.nl/whois?key=$key&domain=$2$json" | sed 's/<br>/\n/g'  ;;
	   "screen") curl -s "https://api.c99.nl/createscreenshot?key=$key&url=$2$json" | sed 's/<br>/\n/g'  ;;
	   "geoip") curl -s "https://api.c99.nl/geoip?key=$key&host=$2$json" | sed 's/<br>/\n/g'  ;;
	   "updown") curl -s "https://api.c99.nl/upordown?key=$key&host=$2$json" | sed 's/<br>/\n/g'  ;;
	   "rep") curl -s "https://api.c99.nl/reputationchecker?key=$key&url=$2$json" | sed 's/<br>/\n/g';;
	   "headers") curl -s "https://api.c99.nl/getheaders?key=$key&host=$2$json" | sed 's/<br>/\n/g'  ;;
	   "backup") curl -s "https://api.c99.nl/linkbackup?key=$key&url=$2$json" | sed 's/<br>/\n/g' ;;
	   "shorten") curl -s "https://api.c99.nl/urlshortener?key=$key&url=$2$json" | sed 's/<br>/\n/g'  ;;
	   "randstr") curl -s "https://api.c99.nl/randomstringpicker?key=$key&textfile=$2$json" | sed 's/<br>/\n/g' ;;
	   "dict") curl -s "https://api.c99.nl/dictionary?key=$key&word=$2$json" | sed 's/<br>/\n/g' ;;
	   "reverse") curl -s "https://api.c99.nl/definepicture?key=$key&url=$2$json" | sed 's/<br>/\n/g'  ;;
	   "synonym") curl -s "https://api.c99.nl/synonym?key=$key&word=$2$json" | sed 's/<br>/\n/g' ;;
	   "validemail") curl -s "https://api.c99.nl/emailvalidator?key=$key&email=$2$json" | sed 's/<br>/\n/g' ;;
	   "tempcheck") curl -s "https://api.c99.nl/disposablemailchecker?key=$key&email=$2$json" | sed 's/<br>/\n/g' ;;
	   "validip") curl -s "https://api.c99.nl/ipvalidator?key=$key&ip=$2$json" | sed 's/<br>/\n/g'  ;;
	   "torcheck") curl -s "https://api.c99.nl/torchecker?key=$key&ip=$2$json" | sed 's/<br>/\n/g' ;;
	   "translate") curl -s "https://api.c99.nl/translate?key=$key&text=$2d&tolanguage=$3$json" | sed 's/<br>/\n/g';;
	   "info") curl -s "https://api.c99.nl/randomperson?key=$key&gender=$2$json" | sed 's/<br>/\n/g' ;;
	   "ytdetails") curl -s "https://api.c99.nl/youtubedetails?key=$key&videoid=$2$json" | sed 's/<br>/\n/g' ;;
	   "yt2mp3") curl -s "https://api.c99.nl/youtubemp3?key=$key&videoid=$2$json" | sed 's/<br>/\n/g' ;;
	   "iplogger") curl -s "https://api.c99.nl/iplogger?key=$key&action=viewloggers&json" | json_pp  ;;
	   "bitbalance") curl -s "https://api.c99.nl/bitcoinbalance?key=$key&address=$2$json" | sed 's/<br>/\n/g' ;;
	   "bitaccelerator") curl -s "https://api.c99.nl/bitcoinaccelerator?key=$key&txn_id=$2$json" | sed 's/<br>/\n/g'  ;;
	   "ethbalance") curl -s "https://api.c99.nl/ethereumbalance?key=$key&address=$2$json" | sed 's/<br>/\n/g'  ;;
	   "currency") curl -s "https://api.c99.nl/currency?key=$key&amount=$2&from=$3&to=$4$json" | sed 's/<br>/\n/g'  ;;
	   "currencyrate") curl -s "https://api.c99.nl/currencyrates?key=$key&source=$2$json" | sed 's/<br>/\n/g'  ;;
	   "weather") curl -s "https://api.c99.nl/weather?key=$key&location=$2$json" | sed 's/<br>/\n/g'  ;;
	   "gennqr") curl -s "https://api.c99.nl/qrgenerator?key=$key&string=$2d&size=$3$json" | sed 's/<br>/\n/g'  ;;
	   "img2txt") curl -s "https://api.c99.nl/textparser?key=$key&url=$2$json" | sed 's/<br>/\n/g'  ;;
	   "proxy") curl -s "https://api.c99.nl/proxylist?key=$key&limit=$2&type=$3&anonimity=$4&country=$5$json" | sed 's/<br>/\n/g';;
	   "detectproxy") curl -s "https://api.c99.nl/proxydetector?key=$key&ip=$2$json" | sed 's/<br>/\n/g'  ;;
	   "genpassword") curl -s "https://api.c99.nl/passwordgenerator?key=$key&length=$2&include=$3" | sed 's:<br />:\n:g' ;;
	   "randnumber") curl -s "https://api.c99.nl/randomnumber?key=$key&length=$2$json" | sed 's:<br />:\n:g' ;;
	   "license") curl -s "https://api.c99.nl/licensekeygenerator?key=$key&template=$2&amount=$3" | sed 's:<br />:\n:g' ;;
	   "eitheror") curl -s "https://api.c99.nl/eitheror?key=$key&json" | json_pp  ;;
	   "-h") echo " 
	--------------------------- CLI C99 API -----------------------------------------

	 This script is desinged to implemented the C99.nl API's into the command line.

	Basic usage is :

	c99nl.sh <API> [look at the list below for required infomation] ( you can add 'json' to the end of any command to retrieve json data)

	THIS SCRIPT REQUIRES YOUR OWN API KEY. ADD YOUR KEY TO THE ABOVE VARIABLE.
	 

	cfsub		<DOMAIN>
		Subdomain Finder and CloudFlare Resolver: Performs an advanced subdomain scan to find most subdomains of the given domain.
	phone		<PHONE NUMBER> # This should be in international format eg. +310000000000
		Phone Lookup: Get more information about any phone number.
	gif		<GIF KEYWORD>
		GIF Finder: Gives you a list of animated GIF's based on the given keyword.
	sms 		<COUNTRY CODE>
		SMS Receiver: Receives SMS from the past hour. Country codes: US, CA, UK
	skypecheck	<USERNAME>
		Skype Check: Checks if a Skype account exists or not.
	skype2ip	<USERNAME>
		Skype Resolver: Attempts to grab an IP address of a Skype account, results are not guaranteed. (This is completely legal as it uses publicly available records)		
	ip2skype	<IP ADDRESS> eg. 1.1.1.1
		IP 2 Skype: Shows all Skype accounts with that specific IP.(This is completely legal as it uses publicly available records)
	email2skype	<EMAIL ADDRESS>
		Email 2 Skype: Gets Skype accounts associated with e-mail.(This is completely legal as it uses publicly available records)
	WAF		<IP ADDRESS> eg. 1.1.1.1
		Firewall Technology (WAF) Detector: Scans to detect if a website is behind a firewall and determines what firewall it is.
	portscan	<IP ADDRESS> eg. 1.1.1.1
		 Multiple Port Scanner: Scans all ports of given host.
	scanport	<IP ADDRESS> <PORT>
		Single Port Scanner: Scans a single port of given host.
	nmap		<IP ADDRESS>
		Nmap Scanner: Performs an nmap scan to find open ports.
	ping		<IP ADDRESS>
		Ping: Pings a host 4 times and shows the result.
	ip2host		<IP ADDRESS>
		IP to Host: Gets host of given IP address.
	advdns		<URL> <RECORD TYPE>
		Advanced DNS Checker: Performs an advanced check on the specific URL. Parameter &server=[countrycode] is optional. If left empty, all servers will be used. Possible check types: a, aaaa, cname, mx, ns, soa, txt
	host2ip		<URL>
		Host to IP: Gets server IP of given host.
	domain		<DOMAIN NAME>
		Domain Checker: Checks whether a domain is available or not, no matter what extension.
	dnshistory	<DOMAIN NAME>
		Domain History Check: Checks available IP history of a domain with dates.
	ip2domain	<IP ADDRESS>
		IP 2 Domains: Attempts to find websites hosted on the specific IP address.
	alexa		<DOMAIN NAME>
		Alexa Rank Checker: Grab the latest Alexa Rank information of any website, including backlinks and top country.
	whois		<DOMAIN NAME>
		Whois Checker: Whois check on a domain to see who the domain owner is.
	screen		<URL>
		Screenshot Tool: Creates a screenshot of any website/url you want.
	geoip		<IP ADDRESS>
		GeoIP: Locates the given host/ip address.
		
	updown		<DOAMIN NAME>
		Website Up or Down Checker: Checks if a host is up or down.
	rep		<DOAMIN NAME>
		Site/URL Reputation Checker: Checks whether a specific site/url is suspicious and might contain malware, phishing or other potential harmful software.
	headers		<URL>
		Get Website Headers: Gets the headers of a website.
	backup		<URL>
		Link Backup: Makes an online backup of a link.
	shorten		<URL>
		URL Shortener: Shorts every long URL.
	randstr		<URL TO TXT FILE>
		Random String Picker: Gets random string from given text file.
	dict		<WORD>
		Dictionary: Gets the definition of any word.
	reverse		<URL TO IMAGE>
		Image Reverse / Define Picture: Reverses the image/picture given and determines what's on it.
	synonym		<IP ADDRESS>
		Synonym Finder: Gets the alternative words/synonyms for any legitimate english word you fill in.
	validemail	<EMAIL ADDRESS
		Email Validator: Checks if given up e-mail exists.
	tempcheck	<EMAIL ADDRESS>
		Disposable Mail Check: Checks if given up e-mail is disposable/temporarily or not.
	validip		<IP ADDRESS>
		IP Validator: Checks if IP address format is valid.
	torcheck	<IP ADDRESS>
		TOR Checker: Checks whether an IP is from a TOR network or not.
	translate	<TEXT TO TRANSLATE> <COUNTRY CODE> # The country code manage what the text will be translated too.
		Translator: Translates your text (autodetected) to any language.
	info		<GENDER> Eg. male,female,all
		Random Info Generator: Generates random name address etc. (genders: male/female/all).
	ytdetails	<YOUTUBE VIDEO ID>
		Youtube Video Details: Gets all details of a specific YouTube video.
	yt2mp3		<YOUTUBE VIDEO ID>
		Youtube to MP3: Converts any song up to 10 minutes to MP3.
	iplogger	
		IP Logger: Creates you various links which you can send to anyone to log their IP.
	bitbalance	<WALLET ADDRESS>
		Bitcoin Balance Checker: Checks the current balance of any Bitcoin address.
	bitaccelerator	<TRANSACTION ID>
		Bitcoin Transaction Accelerator: Accelerates/boosts every unconfirmed transaction in the Bitcoin network.
	ethereumbalance	<WALLET ADDRESS>
		Ethereum Balance Checker: Checks the current balance of any Ethereum address.
	currency	<AMOUNT> <FROM CURRENCY CODE> <TO CURRENCY CODE> Eg. C99nl.sh currency 150 USD GBP
		Currency Converter: Converts normal and cryptocurrencies to any other currency.
	currencyrate	<CURRENCY CODE> Eg. USD
		Currency Rates: Shows the rate of every currency in the world based on the unit price of the given source.
	weather		<LOCATION> Eg. Miami
		Weather Checker: Checks the weather of every city or postal code you give up. Change &unit= to F for Fahrenheit and C for Celcius.
	gennqr		<STRING> <SIZE>
		QR Code Generator: Generates a QR code and uploads it to imgur, useful to quickly share a piece of text or URL.
	img2txt		<IMAGE URL>
		Text Parser: Extracts text from any image. It works best on English text.
	proxy		<PROXY AMOUNT> <PROXY TYPE> <ANONIMITY LEVEL> <COUNTRY CODE>
		Proxylist fetcher: Fetches you a fresh proxylist, up to 1000 proxies. Types: http, https, socks4, socks5 Anonimity: Anonymous, Elite, Transparent. Countries: US, CA, NL, DE, FR, ES.
	detectproxy	<IP ADDRESS>
		Proxy Detector: Detects whether an IP address is a proxy/vpn or not. High accuracy!
	genpassword	<LENGTH> <CHARACTER TYPES> # Passwords reset every 1 second not every request.
		Password Generator: Generates a random password based on the given configuration.
	randnumber	<LENGTH> <LOWEST NUMBER> <HIGHEST NUMBER> Eg. C99nl.sh randnumber 10 0 100 (generated 10 numbers between 0 and 100)
		Random number generator: Generates a random number based on the given length or between parameter. (You can only use length or between, not both)
	license		<TEMPLATE> <AMOUNT> Eg. C99nl.sh ????-????-????-???? 20
		License Key Generator: Generates a randomized license using given template. Wildcards are: * ? and %. * is alphabetic, % is numeric, ? is mixed.
	eitheror	
		Either or: Provides a random 'would you rather' question/dilemma, giving two hard options. (We recommend using JSON)
	---------------------------------------------------------------------------------
";; 

	esac
fi
printf "\n"
