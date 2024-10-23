#!/bin/bash

# Define the target URL
TARGET=""

# Display the main menu
show_menu() {
    clear
    echo "==============================="
    echo " Pentesting Tools Menu"
    echo "==============================="
    echo "1. WhatWeb - Detect technologies"
    echo "2. Nikto - Scan for vulnerabilities"
    echo "3. Dirb - Brute-force directories"
    echo "4. Gobuster - Brute-force directories"
    echo "5. Dirbuster - Brute-force directories"
    echo "6. Dirsearch - Brute-force directories"
    echo "7. FFUF - Fuzz directories"
    echo "8. Feroxbuster - Brute-force directories"
    echo "9. Wfuzz - Fuzz directories"
    echo "10. DotDotPwn - Exploit directory traversal"
    echo "11. Gospider - Crawl URLs"
    echo "12. Paramspider - Extract parameters"
    echo "13. Aquatone - Screenshot and reconnaissance"
    echo "14. Hakrawler - Crawl and extract URLs"
    echo "15. Exit"
    echo "==============================="
    read -p "Choose an option [1-15]: " option
}

# Run selected tool
run_tool() {
    case $option in
        1)
            echo "Running WhatWeb..."
            echo "Detecting technologies used by the target website."
            whatweb $TARGET
            ;;
        2)
            echo "Running Nikto..."
            echo "Scanning the web server for vulnerabilities."
            nikto -h $TARGET
            ;;
        3)
            echo "Running Dirb..."
            echo "Brute-forcing directories on the web server."
            dirb $TARGET
            ;;
        4)
            echo "Running Gobuster..."
            echo "Brute-forcing directories on the web server."
            gobuster dir -u $TARGET -w /path/to/wordlist.txt
            ;;
        5)
            echo "Running Dirbuster..."
            echo "Brute-forcing directories on the web server."
            dirbuster -u $TARGET -w /path/to/wordlist.txt
            ;;
        6)
            echo "Running Dirsearch..."
            echo "Brute-forcing directories on the web server."
            dirsearch -u $TARGET -e php,html,js
            ;;
        7)
            echo "Running FFUF..."
            echo "Fuzzing directories on the web server."
            ffuf -u $TARGET/FUZZ -w /path/to/wordlist.txt
            ;;
        8)
            echo "Running Feroxbuster..."
            echo "Brute-forcing directories on the web server."
            feroxbuster -u $TARGET -w /path/to/wordlist.txt
            ;;
        9)
            echo "Running Wfuzz..."
            echo "Fuzzing directories on the web server."
            wfuzz -c -z file,/path/to/wordlist.txt -u $TARGET/FUZZ
            ;;
        10)
            echo "Running DotDotPwn..."
            echo "Exploiting directory traversal vulnerabilities."
            dotdotpwn -u $TARGET
            ;;
        11)
            echo "Running Gospider..."
            echo "Crawling URLs on the target website."
            gospider -s $TARGET
            ;;
        12)
            echo "Running Paramspider..."
            echo "Extracting parameters from the target website."
            paramspider -d $TARGET
            ;;
        13)
            echo "Running Aquatone..."
            echo "Taking screenshots and performing reconnaissance."
            aquatone -d $TARGET
            ;;
        14)
            echo "Running Hakrawler..."
            echo "Crawling and extracting URLs from the target website."
            hakrawler -url $TARGET
            ;;
        15)
            echo "Exiting..."
            exit 0
            ;;
        *)
            echo "Invalid option!"
            ;;
    esac
}

# Main script logic
while true; do
    show_menu
    read -p "Enter target URL: " TARGET
    run_tool
    read -p "Press [Enter] to return to the menu."
done