# Nuclei

## 01 - Setup

```
$ go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest && \
sudo cp ~/go/bin/nuclei /usr/local/bin
```

## 02 - Help Menu

```
$ nuclei -h
Nuclei is a fast, template based vulnerability scanner focusing
on extensive configurability, massive extensibility and ease of use.

Usage:
  nuclei [flags]

Flags:
TARGET:
   -u, -target string[]       target URLs/hosts to scan
   -l, -list string           path to file containing a list of target URLs/hosts to scan (one per line)
   -resume string             resume scan using resume.cfg (clustering will be disabled)
   -sa, -scan-all-ips         scan all the IP's associated with dns record
   -iv, -ip-version string[]  IP version to scan of hostname (4,6) - (default 4)

TEMPLATES:
   -nt, -new-templates                    run only new templates added in latest nuclei-templates release
   -ntv, -new-templates-version string[]  run new templates added in specific version
   -as, -automatic-scan                   automatic web scan using wappalyzer technology detection to tags mapping
   -t, -templates string[]                list of template or template directory to run (comma-separated, file)
   -tu, -template-url string[]            list of template urls to run (comma-separated, file)
   -w, -workflows string[]                list of workflow or workflow directory to run (comma-separated, file)
   -wu, -workflow-url string[]            list of workflow urls to run (comma-separated, file)
   -validate                              validate the passed templates to nuclei
   -nss, -no-strict-syntax                disable strict syntax check on templates
   -td, -template-display                 displays the templates content
   -tl                                    list all available templates

FILTERING:
   -a, -author string[]               templates to run based on authors (comma-separated, file)
   -tags string[]                     templates to run based on tags (comma-separated, file)
   -etags, -exclude-tags string[]     templates to exclude based on tags (comma-separated, file)
   -itags, -include-tags string[]     tags to be executed even if they are excluded either by default or configuration
   -id, -template-id string[]         templates to run based on template ids (comma-separated, file)
   -eid, -exclude-id string[]         templates to exclude based on template ids (comma-separated, file)
   -it, -include-templates string[]   templates to be executed even if they are excluded either by default or configuration
   -et, -exclude-templates string[]   template or template directory to exclude (comma-separated, file)
   -em, -exclude-matchers string[]    template matchers to exclude in result
   -s, -severity value[]              templates to run based on severity. Possible values: info, low, medium, high, critical, unknown
   -es, -exclude-severity value[]     templates to exclude based on severity. Possible values: info, low, medium, high, critical, unknown
   -pt, -type value[]                 templates to run based on protocol type. Possible values: dns, file, http, headless, tcp, workflow, ssl, websocket, whois
   -ept, -exclude-type value[]        templates to exclude based on protocol type. Possible values: dns, file, http, headless, tcp, workflow, ssl, websocket, whois
   -tc, -template-condition string[]  templates to run based on expression condition

OUTPUT:
   -o, -output string            output file to write found issues/vulnerabilities
   -sresp, -store-resp           store all request/response passed through nuclei to output directory
   -srd, -store-resp-dir string  store all request/response passed through nuclei to custom directory (default "output")
   -silent                       display findings only
   -nc, -no-color                disable output content coloring (ANSI escape codes)
   -j, -jsonl                    write output in JSONL(ines) format
   -irr, -include-rr             include request/response pairs in the JSONL output (for findings only)
   -nm, -no-meta                 disable printing result metadata in cli output
   -ts, -timestamp               enables printing timestamp in cli output
   -rdb, -report-db string       nuclei reporting database (always use this to persist report data)
   -ms, -matcher-status          display match failure status
   -me, -markdown-export string  directory to export results in markdown format
   -se, -sarif-export string     file to export results in SARIF format
   -je, -json-export string      file to export results in JSON format
   -jle, -jsonl-export string    file to export results in JSONL(ine) format

CONFIGURATIONS:
   -config string                 path to the nuclei configuration file
   -fr, -follow-redirects         enable following redirects for http templates
   -fhr, -follow-host-redirects   follow redirects on the same host
   -mr, -max-redirects int        max number of redirects to follow for http templates (default 10)
   -dr, -disable-redirects        disable redirects for http templates
   -rc, -report-config string     nuclei reporting module configuration file
   -H, -header string[]           custom header/cookie to include in all http request in header:value format (cli, file)
   -V, -var value                 custom vars in key=value format
   -r, -resolvers string          file containing resolver list for nuclei
   -sr, -system-resolvers         use system DNS resolving as error fallback
   -dc, -disable-clustering       disable clustering of requests
   -passive                       enable passive HTTP response processing mode
   -fh2, -force-http2             force http2 connection on requests
   -ev, -env-vars                 enable environment variables to be used in template
   -cc, -client-cert string       client certificate file (PEM-encoded) used for authenticating against scanned hosts
   -ck, -client-key string        client key file (PEM-encoded) used for authenticating against scanned hosts
   -ca, -client-ca string         client certificate authority file (PEM-encoded) used for authenticating against scanned hosts
   -sml, -show-match-line         show match lines for file templates, works with extractors only
   -ztls                          use ztls library with autofallback to standard one for tls13
   -sni string                    tls sni hostname to use (default: input domain name)
   -sandbox                       sandbox nuclei for safe templates execution
   -i, -interface string          network interface to use for network scan
   -at, -attack-type string       type of payload combinations to perform (batteringram,pitchfork,clusterbomb)
   -sip, -source-ip string        source ip address to use for network scan
   -config-directory string       override the default config path ($home/.config)
   -rsr, -response-size-read int  max response size to read in bytes (default 10485760)
   -rss, -response-size-save int  max response size to read in bytes (default 1048576)
   -reset                         reset removes all nuclei configuration and data files (including nuclei-templates)

INTERACTSH:
   -iserver, -interactsh-server string  interactsh server url for self-hosted instance (default: oast.pro,oast.live,oast.site,oast.online,oast.fun,oast.me)
   -itoken, -interactsh-token string    authentication token for self-hosted interactsh server
   -interactions-cache-size int         number of requests to keep in the interactions cache (default 5000)
   -interactions-eviction int           number of seconds to wait before evicting requests from cache (default 60)
   -interactions-poll-duration int      number of seconds to wait before each interaction poll request (default 5)
   -interactions-cooldown-period int    extra time for interaction polling before exiting (default 5)
   -ni, -no-interactsh                  disable interactsh server for OAST testing, exclude OAST based templates

FUZZING:
   -ft, -fuzzing-type string  overrides fuzzing type set in template (replace, prefix, postfix, infix)
   -fm, -fuzzing-mode string  overrides fuzzing mode set in template (multiple, single)

UNCOVER:
   -uc, -uncover                  enable uncover engine
   -uq, -uncover-query string[]   uncover search query
   -ue, -uncover-engine string[]  uncover search engine (shodan,shodan-idb,fofa,censys,quake,hunter,zoomeye,netlas,criminalip) (default shodan)
   -uf, -uncover-field string     uncover fields to return (ip,port,host) (default "ip:port")
   -ul, -uncover-limit int        uncover results to return (default 100)
   -ucd, -uncover-delay int       delay between uncover query requests in seconds (0 to disable) (default 1)

RATE-LIMIT:
   -rl, -rate-limit int               maximum number of requests to send per second (default 150)
   -rlm, -rate-limit-minute int       maximum number of requests to send per minute
   -bs, -bulk-size int                maximum number of hosts to be analyzed in parallel per template (default 25)
   -c, -concurrency int               maximum number of templates to be executed in parallel (default 25)
   -hbs, -headless-bulk-size int      maximum number of headless hosts to be analyzed in parallel per template (default 10)
   -headc, -headless-concurrency int  maximum number of headless templates to be executed in parallel (default 10)

OPTIMIZATIONS:
   -timeout int                        time to wait in seconds before timeout (default 10)
   -retries int                        number of times to retry a failed request (default 1)
   -ldp, -leave-default-ports          leave default HTTP/HTTPS ports (eg. host:80,host:443)
   -mhe, -max-host-error int           max errors for a host before skipping from scan (default 30)
   -te, -track-error string[]          adds given error to max-host-error watchlist (standard, file)
   -nmhe, -no-mhe                      disable skipping host from scan based on errors
   -project                            use a project folder to avoid sending same request multiple times
   -project-path string                set a specific project path (default "/tmp")
   -spm, -stop-at-first-match          stop processing HTTP requests after the first match (may break template/workflow logic)
   -stream                             stream mode - start elaborating without sorting the input
   -ss, -scan-strategy value           strategy to use while scanning(auto/host-spray/template-spray) (default auto)
   -irt, -input-read-timeout duration  timeout on input read (default 3m0s)
   -nh, -no-httpx                      disable httpx probing for non-url input
   -no-stdin                           disable stdin processing

HEADLESS:
   -headless                    enable templates that require headless browser support (root user on Linux will disable sandbox)
   -page-timeout int            seconds to wait for each page in headless mode (default 20)
   -sb, -show-browser           show the browser on the screen when running templates with headless mode
   -sc, -system-chrome          use local installed Chrome browser instead of nuclei installed
   -lha, -list-headless-action  list available headless actions

DEBUG:
   -debug                    show all requests and responses
   -dreq, -debug-req         show all sent requests
   -dresp, -debug-resp       show all received responses
   -p, -proxy string[]       list of http/socks5 proxy to use (comma separated or file input)
   -pi, -proxy-internal      proxy all internal requests
   -ldf, -list-dsl-function  list all supported DSL function signatures
   -tlog, -trace-log string  file to write sent requests trace log
   -elog, -error-log string  file to write sent requests error log
   -version                  show nuclei version
   -hm, -hang-monitor        enable nuclei hang monitoring
   -v, -verbose              show verbose output
   -profile-mem string       optional nuclei memory profile dump file
   -vv                       display templates loaded for scan
   -svd, -show-var-dump      show variables dump for debugging
   -ep, -enable-pprof        enable pprof debugging server
   -tv, -templates-version   shows the version of the installed nuclei-templates
   -hc, -health-check        run diagnostic check up

UPDATE:
   -up, -update                      update nuclei engine to the latest released version
   -ut, -update-templates            update nuclei-templates to latest released version
   -ud, -update-template-dir string  custom directory to install / update nuclei-templates
   -duc, -disable-update-check       disable automatic nuclei/templates update check

STATISTICS:
   -stats                    display statistics about the running scan
   -sj, -stats-json          display statistics in JSONL(ines) format
   -si, -stats-interval int  number of seconds to wait between showing a statistics update (default 5)
   -m, -metrics              expose nuclei metrics on a port
   -mp, -metrics-port int    port to expose nuclei metrics on (default 9092)

CLOUD:
   -cloud                              run scan on nuclei cloud
   -ads, -add-datasource string        add specified data source (s3,github)
   -atr, -add-target string            add target(s) to cloud
   -atm, -add-template string          add template(s) to cloud
   -lsn, -list-scan                    list previous cloud scans
   -lso, -list-output string           list scan output by scan id
   -ltr, -list-target                  list cloud target by id
   -ltm, -list-template                list cloud template by id
   -lds, -list-datasource              list cloud datasource by id
   -lrs, -list-reportsource            list reporting sources
   -dsn, -delete-scan string           delete cloud scan by id
   -dtr, -delete-target string         delete target(s) from cloud
   -dtm, -delete-template string       delete template(s) from cloud
   -dds, -delete-datasource string     delete specified data source
   -drs, -disable-reportsource string  disable specified reporting source
   -ers, -enable-reportsource string   enable specified reporting source
   -gtr, -get-target string            get target content by id
   -gtm, -get-template string          get template content by id
   -nos, -no-store                     disable scan/output storage on cloud
   -no-tables                          do not display pretty-printed tables
   -limit int                          limit the number of output to display (default 100)
```

## 03 - Usage

TODO: Provide more usage coverage of nuclei

### 3.1 - Basics

`$ nuclei -silent -u http[s]://<target_IP> -t nuclei-templates/ -o output.txt`

`$ nuclei -l ips.txt -t nuclei-templates/cves/ -o output.txt`

- **Using port scanners**

```
$ naabu -silent -list ips.txt -o open_ports.txt

$ nuclei -silent -t nuclei-templates/ -o output.txt
```

```
$ nmap <IP>/<CIDR> -oG - | grep Open > open_ports.txt

$ nuclei -t nuclei-templates/ -o output.txt
```

```
$ sudo rustscan -a ips.txt -- -Pn | grep Open | tee open_ports.txt | sed 's/Open //' > ports.txt

$ nuclei -silent -t nuclei-templates/ -o output.txt
```

Note: You can pipe through them

`$ naabu -silent -list ips.txt | nuclei -silent -t nuclei-templates/ -o output.txt`

`$ nmap <IP>/<CIDR> -oG - | grep Open | nuclei -t nuclei-templates/ -o output.txt`

`$ sudo rustscan -a ips.txt -- -Pn | grep Open | tee open_ports.txt | sed 's/Open //' | nuclei -silent -t nuclei-templates/ -o output.txt`

- **To scan the webservers**

```
$ sudo rustscan -p 80,443 -a ips.txt -- -Pn | grep Open | tee open_ports.txt | sed 's/Open //' > ports.txt

$ httpx -silent -l ports.txt

$ nuclei -silent -t nuclei-templates/ -o output.txt
```

```
$ nmap -p80,443 <IP>/<CIDR> -oG - | grep Open > open_ports.txt

$ httpx -silent -l open_ports.txt -o webservers-output.txt

$ nuclei -l webservers-output.txt -t nuclei-templates/ -o output.txt
```

```
$ naabu -silent -p80,443 -list ips.txt -o open_ports.txt

$ httpx -silent -l open_ports.txt -o webservers-output.txt

$ nuclei -silent -l webservers-output.txt -t nuclei-templates/ -o output.txt
```

Note: You can pipe through them

`$ sudo rustscan -p 80,443 -a ips.txt -- -Pn | grep Open | tee open_ports.txt | sed 's/Open //' | httpx -silent | nuclei -silent -t nuclei-templates/ -o output.txt`

`$ nmap -p80,443 <IP>/<CIDR> -oG - | grep Open | httpx -silent | nuclei -t nuclei-templates/ -o output.txt`

`$ naabu -silent -p80,443 -list ips.txt | httpx -silent | nuclei -silent -t nuclei-templates/ -o output.txt`

### 3.2 - Filters

### 3.2.1 - Severity

`$ nuclei -l ips.txt -s info,low,medium,high,critical,unknown -t nuclei-templates/`

`$ nuclei -l ips.txt -es info,low,medium,high,critical,unknown -t nuclei-templates/`

### 3.2.2 - Tags

`$ nuclei -l ips.txt -tags <tag_1,<tag_2>,<tag_n> -t nuclei-templates/ -vv`

`$ nuclei -l ips.txt -tags sqli,lfi,xss,config,cve,misconfig -t nuclei-templates/`

- **Include tags**

`$ nuclei -l ips.txt -itags <tag_1>,<tag_2>,<tag_n> -t nuclei-templates/ -vv`

- **Exclude tags**

`$ nuclei -l ips.txt -etags <tag_1>,<tag_2>,<tag_n> -t nuclei-templates/ -vv`

`$ nuclei -l ips.txt -etags ssl,tls -t nuclei-templates/ -vv`

### 3.2.3 - Author

`$ nuclei -l ips.txt -author <author_name> -t nuclei-templates/ -vv`

### 3.2.4 - Template ID(s)

`$ nuclei -l ips.txt -id <template_1>,<template_2>,<template_n> -t nuclei-templates/ -vv`

- **Exclude templates**

`$ nuclei -l ips.txt -eid <template_1>,<template_2>,<template_n> -t nuclei-templates/ -vv`

## 04 - Use Cases

TODO: Provide more use cases and fill in the missing information

### 4.1 - Gitleaks

`$ git clone https://github.com/zricethezav/gitleaks.git | nuclei -u ./ -t nuclei-templates/file/secrets-in-files.yaml`

### 4.2 - Webapps

#### 4.2.1 - SQL Injection

`$ nuclei -l ips.txt -id error-based-sql-injection -t nuclei-templates/ -vv`

`$ nuclei -silent -l urls.txt -tags sqli -t nuclei-templates/`

`$ httpx -silent -l urls.txt | nuclei -tags sqli -t nuclei-templates/ -vv -o sqli-output.txt`

#### 4.2.2 - Cross Site Scripting (XSS)

`$ httpx -silent -l urls.txt | nuclei -tags xss -t nuclei-templates/ -vv -o xss-output.txt`

#### 4.2.3 - Local File Inclusions (LFI)

`$ nuclei -l urls.txt -tags lfi -t nuclei-templates/ -vv -o lfi-output.txt`

### 4.3 - IoTs

#### 4.3.1 - Routers

#### 4.3.2 - Printers

#### 4.3.3 - CCTV

#### 4.3.4 - Operation Technology (OT)

### 4.4 - Detect Honeypots

## References

- [Nuclei](https://github.com/projectdiscovery/nuclei)

- [Nuclei Templates](https://github.com/projectdiscovery/nuclei-templates)

- [Fuzzing Template](https://github.com/projectdiscovery/fuzzing-templates)

- [Ultimate Nuclei Guide](https://blog.projectdiscovery.io/ultimate-nuclei-guide/)

- [Cent](https://github.com/xm1k3/cent)