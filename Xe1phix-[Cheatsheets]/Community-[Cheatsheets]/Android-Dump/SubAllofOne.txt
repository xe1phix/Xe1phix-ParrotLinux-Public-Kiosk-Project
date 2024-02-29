#!/bin/bash
clear;
printf "${GREEN}"
cat << "EOF"
  ██████  █    ██  ▄▄▄▄    ▄▄▄       ██▓     ██▓     ▒█████    █████▒▒█████   ███▄    █ ▓█████ 
▒██    ▒  ██  ▓██▒▓█████▄ ▒████▄    ▓██▒    ▓██▒    ▒██▒  ██▒▓██   ▒▒██▒  ██▒ ██ ▀█   █ ▓█   ▀ 
░ ▓██▄   ▓██  ▒██░▒██▒ ▄██▒██  ▀█▄  ▒██░    ▒██░    ▒██░  ██▒▒████ ░▒██░  ██▒▓██  ▀█ ██▒▒███   
  ▒   ██▒▓▓█  ░██░▒██░█▀  ░██▄▄▄▄██ ▒██░    ▒██░    ▒██   ██░░▓█▒  ░▒██   ██░▓██▒  ▐▌██▒▒▓█  ▄ 
▒██████▒▒▒▒█████▓ ░▓█  ▀█▓ ▓█   ▓██▒░██████▒░██████▒░ ████▓▒░░▒█░   ░ ████▓▒░▒██░   ▓██░░▒████▒
▒ ▒▓▒ ▒ ░░▒▓▒ ▒ ▒ ░▒▓███▀▒ ▒▒   ▓▒█░░ ▒░▓  ░░ ▒░▓  ░░ ▒░▒░▒░  ▒ ░   ░ ▒░▒░▒░ ░ ▒░   ▒ ▒ ░░ ▒░ ░
░ ░▒  ░ ░░░▒░ ░ ░ ▒░▒   ░   ▒   ▒▒ ░░ ░ ▒  ░░ ░ ▒  ░  ░ ▒ ▒░  ░       ░ ▒ ▒░ ░ ░░   ░ ▒░ ░ ░  ░
░  ░  ░   ░░░ ░ ░  ░    ░   ░   ▒     ░ ░     ░ ░   ░ ░ ░ ▒   ░ ░   ░ ░ ░ ▒     ░   ░ ░    ░   
      ░     ░      ░            ░  ░    ░  ░    ░  ░    ░ ░             ░ ░           ░    ░  ░
                        ░                                                             @zerbaliy3v
EOF
printf "${NC}\n"
										    
# ----------------- 
color_progress_bar() {
  local duration=$1
  local width=100
  local progress=0

  printf "Finishing: ["

while [ $progress -lt $width ]; do
    printf "\033[0;32m#\033[0m"
    ((progress++))
    sleep 0.02
done

  printf "] \033[0;31m\033[0m\n"
}
# ---------------
echo -e "\033[1;34m";
read  -p "Enter Domain: " domain 

echo -e "\033[1;37m _________________________Subfinder_________________________\033[0m"
subfinder  -d $domain -o s1;
sleep 3
echo -e "\033[1;37m _________________________Amass_________________________\033[0m"
amass enum  -passive -norecursive -noalts -d $domain -o s2;
sleep 3
echo -e "\033[1;37m _________________________assetfinder_________________________\033[0m"
assetfinder $domain > s3 ;
sleep 3
echo -e "\033[1;37m _________________________Findomain_________________________\033[0m"
findomain -t $domain -o;
sleep 3
echo -e "\033[1;37m _________________________crt.sh_________________________\033[0m"
curl -s "https://crt.sh/?q=%25.$domain&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u > s4;
sleep 3

cat s1 s2 s3 $domain.txt s4  | anew subdomains && rm -rf s1 s2 s3 $domain.txt s4;
color_progress_bar
echo -e "\033[1;37m _________________________Finished_________________________\033[0m"

cat subdomains | httpx -o live-subdomains
