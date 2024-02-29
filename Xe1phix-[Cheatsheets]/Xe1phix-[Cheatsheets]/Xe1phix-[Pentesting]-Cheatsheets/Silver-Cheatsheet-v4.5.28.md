

----
## Silver
Scan host
```
python3 silver.py 127.0.0.1
python3 silver.py 127.0.0.1/22
python3 silver.py 127.0.0.1,127.0.0.2,127.0.0.3
```
Use Shodan
```
python3 silver.py 127.0.0.1 --shodan
```
Scan top ~1000 ports
```
python3 silver.py 127.0.0.1 --quick
```
Scan specific ports
```
python3 silver.py 127.0.0.1 -p80,443
```
Scan hosts from a file
```
python3 silver.py -i /path/to/targets.txt
```
Save JSON output to a file (Default: result-<ip_here>.json)
```
python3 silver.py 127.0.0.1 -o my_target.json
```
Set max number of parallel nmap instances (Default: number_of_cores)
```
python3 silver.py -i /path/to/targets.txt -t 4
```
Choose packets to be sent per seconds (Default: 10000)
```
python3 silver.py 127.0.0.1 --rate 1000