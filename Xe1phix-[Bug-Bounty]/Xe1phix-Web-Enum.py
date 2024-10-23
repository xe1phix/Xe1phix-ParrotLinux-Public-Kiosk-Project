import os
import subprocess
from multiprocessing import Pool

# Configuration
domain = "example.com"  # Replace with your domain
target_ip = "10.10.10.10"  # Replace with your target IP
wordlist_dir = "/usr/share/seclists/Discovery/Web_Content/"
wordlist_file = "common.txt"
extensions = "php,html,js,txt,jsp,pl"
dir_status_codes = "200,204,301,302,307,403,500"
threads = 100
output_dir = "./output/"

# Ensure output directory exists
if not os.path.exists(output_dir):
    os.makedirs(output_dir)

# Gobuster function
def run_gobuster():
    print("[+] Running Gobuster for directory enumeration")
    cmd = f"gobuster dir -u http://{domain} -w {wordlist_dir}/{wordlist_file} -t {threads} -e -s {dir_status_codes} -o {output_dir}/gobuster_output.txt"
    subprocess.run(cmd, shell=True)

# Dirsearch function
def run_dirsearch():
    print("[+] Running Dirsearch for directory fuzzing")
    cmd = f"python3 dirsearch.py -u http://{target_ip} -w {wordlist_dir}/directorylist2.3medium.txt -e {extensions} -t {threads} -r -b --output {output_dir}/dirsearch_output.txt"
    subprocess.run(cmd, shell=True)

# Nikto function
def run_nikto():
    print("[+] Running Nikto for vulnerability scanning")
    cmd_http = f"nikto -h http://{target_ip} -p 80"
    cmd_https = f"nikto -h https://{target_ip} -p 443"
    subprocess.run(cmd_http, shell=True)
    subprocess.run(cmd_https, shell=True)

# Gospider function
def run_gospider():
    print("[+] Running Gospider for web crawling")
    cmd = f"gospider -S {output_dir}/subs/filtered_hosts.txt -js -t 50 -d 3 --sitemap --robots -w -r > {output_dir}/gospider_output.txt"
    subprocess.run(cmd, shell=True)

# WhatWeb function
def run_whatweb():
    print("[+] Running WhatWeb for web technology fingerprinting")
    cmd = f"whatweb -v {domain} > {output_dir}/whatweb_output.txt"
    subprocess.run(cmd, shell=True)

# Feroxbuster function
def run_feroxbuster():
    print("[+] Running Feroxbuster for directory brute-forcing")
    cmd = f"feroxbuster -u http://{target_ip} -w {wordlist_dir}/raft-small-words.txt -t {threads} -o {output_dir}/feroxbuster_output.txt"
    subprocess.run(cmd, shell=True)

# HTTPie function
def run_httpie():
    print("[+] Running HTTPie to make HTTP requests")
    cmd = f"http --verify=no GET http://{target_ip}"
    subprocess.run(cmd, shell=True)

# HTTProbe function
def run_httprobe():
    print("[+] Running HTTProbe to check alive servers")
    cmd = f"cat {output_dir}/alive.txt | httprobe -c {threads} -t 5 > {output_dir}/httprobe_output.txt"
    subprocess.run(cmd, shell=True)

# Web enumeration with multiprocessing
def run_enumeration():
    print("[+] Starting web enumeration")
    
    # List of commands to run concurrently
    tasks = [
        run_gobuster,
        run_dirsearch,
        run_nikto,
        run_gospider,
        run_whatweb,
        run_feroxbuster,
        run_httpie,
        run_httprobe
    ]
    
    # Run tasks in parallel
    with Pool(len(tasks)) as p:
        p.map(lambda f: f(), tasks)

if __name__ == "__main__":
    run_enumeration()
    print("[+] Web enumeration and crawling completed!")