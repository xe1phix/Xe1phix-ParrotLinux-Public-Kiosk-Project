# 06 - WAF Detection

## 6.1 - Nmap

`$ nmap -p80,443 --script http-waf-detect <IP>`

`$ nmap -p80,443 --script http-waf-detect <IP> --script-args="http-waf-detect.aggro,http-waf-detect.uri=/<URL>/index.php" <IP>`

`$ nmap -p80,443 --script http-waf-fingerprint <IP>`

`$ nmap -p80,443 --script http-waf-fingerprint --script-args http-waf-fingerprint.intensive=1 <IP>`

## 6.2 - Wafw00f

`$ wafw00f <URL_1> <URL_2> <URL_n>`

## References

- [Awesome WAF](https://github.com/0xInfection/Awesome-WAF)