# Dalfox

## Setup

```
$ go install github.com/hahwul/dalfox/v2@latest && \
sudo cp ~/go/bin/dalfox /usr/local/bin
```

## Usage

TODO: Fill this info

`$ dalfox url http[s]://<IP>/ | cut -d " " -f 2 > xss_vulns.txt`

`$ dalfox file urls.txt | cut -d " " -f 2 > xss_vulns.txt`

`$ gospider -S urls.txt -c 10 -d 5 --blacklist ".(jpg|jpeg|gif|css|tif|tiff|png|ttf|woff|woff2|ico|pdf|svg|txt)" --other-source | grep -e code-200 | awk '{print }' | grep = | qsreplace -a | dalfox pipe | tee xss_vulns.txt`

## References

- [Dalfox](https://github.com/hahwul/dalfox)

- [Dalfox Documentation](https://dalfox.hahwul.com/docs/home/)