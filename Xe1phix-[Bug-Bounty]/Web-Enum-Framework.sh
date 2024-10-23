#!/bin/bash

# Function to display the menu
show_menu() {
    echo "==========================="
    echo " Web Enumeration Framework "
    echo "==========================="
    echo "1) Gobuster - Simple Scan"
    echo "2) Gobuster - Apache Extensions"
    echo "3) Gobuster - IIS Extensions"
    echo "4) DirSearch - Apache"
    echo "5) DirSearch - IIS"
    echo "6) ParamSpider - Domain"
    echo "7) GoSpider - Crawl"
    echo "8) Nikto Scan"
    echo "9) FFUF - Fuzz URLs"
    echo "0) Exit"
    echo ""
    read -p "Choose an option: " choice
}

# Function to run Gobuster - Simple Scan
run_gobuster_simple() {
    read -p "Enter target domain (e.g., http://example.com): " Domain
    gobuster dir -u $Domain -w /usr/share/wordlists/dirb/big.txt -t 100
}

# Function to run Gobuster with Apache-specific extensions
run_gobuster_apache() {
    read -p "Enter target domain (e.g., http://10.10.10.10): " IP
    gobuster dir -e -u http://$IP -w /usr/share/wordlists/dirbuster/directorylist2.3medium.txt -x php,html,js,txt,jsp,pl -s 200,204,301,302,307,403,401
}

# Function to run Gobuster with IIS-specific extensions
run_gobuster_iis() {
    read -p "Enter target domain (e.g., http://10.10.10.10): " IP
    gobuster dir -e -u http://$IP -w /usr/share/wordlists/dirbuster/directorylist2.3medium.txt -x php,html,js,txt,asp,aspx,jsp,bak -s 200,204,301,302,307,403,401
}

# Function to run DirSearch for Apache
run_dirsearch_apache() {
    read -p "Enter target domain (e.g., http://10.10.10.131): " Domain
    python3 dirsearch.py -r -u $Domain -w /usr/share/dirbuster/wordlists/directorylist2.3medium.txt -e php,html,js,txt,jsp,pl -t 50
}

# Function to run DirSearch for IIS
run_dirsearch_iis() {
    read -p "Enter target domain (e.g., http://10.10.10.131): " Domain
    python3 dirsearch.py -r -u $Domain -w /usr/share/dirbuster/wordlists/directorylist2.3medium.txt -e php,html,js,txt,asp,aspx,jsp,bak -t 50
}

# Function to run ParamSpider
run_paramspider() {
    read -p "Enter target domain: " Domain
    paramspider -d $Domain
}

# Function to run GoSpider for crawling
run_gospider() {
    read -p "Enter target domain list file (e.g., domain.txt): " File
    gospider -S $File -d 2 -t 20 -sitemap -robots -w
}

# Function to run Nikto
run_nikto() {
    read -p "Enter target domain (e.g., http://10.10.10.10): " Domain
    nikto -h $Domain -p 80
}

# Function to run FFUF URL fuzzing
run_ffuf() {
    read -p "Enter target URL (e.g., http://example.com): " URL
    ffuf -u "$URL/FUZZ" -w /usr/share/seclists/Discovery/Web_Content/common.txt
}

# Main loop
while true; do
    show_menu
    case $choice in
        1)
            run_gobuster_simple
            ;;
        2)
            run_gobuster_apache
            ;;
        3)
            run_gobuster_iis
            ;;
        4)
            run_dirsearch_apache
            ;;
        5)
            run_dirsearch_iis
            ;;
        6)
            run_paramspider
            ;;
        7)
            run_gospider
            ;;
        8)
            run_nikto
            ;;
        9)
            run_ffuf
            ;;
        0)
            echo "Exiting..."
            exit 0
            ;;
        *)
            echo "Invalid option, please try again."
            ;;
    esac
done