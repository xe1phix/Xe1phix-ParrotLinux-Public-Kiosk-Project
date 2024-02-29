#!/bin/bash 
echo "====================="
echo "+-+-+-+-+-+-+-+-+-+-+
|S|u|b|-|G|a|t|h|e|r|
+-+-+-+-+-+-+-+-+-+-+
=====================@kab33r
";
read -p "Enter domain name: " input
for i in ${input[@]}
do

echo "
.
.
.
Scan started for $i
";

echo "grabbing subdomains from Amass,Subfinder,Assetfinder,Findomain,Chaos,Github-subdomains.py hold down a bit...";

mkdir ~/Projects/$i;

echo "
.
.
.
.
Making Directory $i in ~/Projects/
";

subfinder -d $i --silent | httpx --silent >> ~/Projects/$i/subfinder.txt;
assetfinder $i | httpx --silent >> ~/Projects/$i/assetfinder.txt;
findomain -t $i -q | httpx --silent >> ~/Projects/$i/findomain.txt;
chaos -d $i -silent | httpx --silent >> ~/Projects/$i/chaos.txt;
python3 ~/github-search/github-subdomains.py -t **GITHUB_TOKEN_HERE** -d '$1' >> ~/Projects/$i/githubsubs.txt;
amass enum -d $i >> ~/Projects/$i/amasssubs.txt;

cat ~/Projects/$i/subfinder.txt ~/Projects/$i/assetfinder.txt ~/Projects/$i/findomain.txt ~/Projects/$i/chaos.txt ~/Projects/$i/githubsubs.txt ~/Projects/$i/amasssubs.txt | sort -u >> ~/Projects/$i/totalsubs.txt;

rm -rf ~/Projects/$i/subfinder.txt ~/Projects/$i/assetfinder.txt ~/Projects/$i/findomain.txt ~/Projects/$i/chaos.txt ~/Projects/$i/githubsubs.txt ~/Projects/$i/amasssubs.txt

echo "Subdomains saved at ~/Projects/$i/totalsubs.txt."
echo "Total number of unique subdomains of $i found:" | notify --silent
wc ~/Projects/$i/totalsubs.txt | awk '{print $3}' | notify --silent
 
echo ".
.
.";done
