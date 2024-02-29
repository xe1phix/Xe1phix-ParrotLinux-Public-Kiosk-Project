#!/bin/bash
# subseeker is a command-line tool for subdomain enumeration. 
# It automates the process of gathering subdomains using popular tools such as subfinder, findomain, assetfinder, and amass. 
# The tool allows you to specify a target domain and tool wil generate a subdomain txt file.
# author Luke57

# Check if the target domain is provided as a command-line argument
if [ $# -eq 0 ]; then
    echo "Please provide the target domain."
    echo "Usage: ./subseeker.sh <DOMAIN>"
    exit 1
fi

# Get the target domain from the command-line argument
DOMAIN=$1

# Define the output file name
OUTPUT_FILE="$DOMAIN-subs.txt"

# Run subfinder and append output to the output file
printf "Running Subfinder..\n"
subfinder -all -d "$DOMAIN" -silent >> "$OUTPUT_FILE"

# Run findomain and append output to the output file
printf "Running Findomain..\n"
findomain -t "$DOMAIN" --quiet >> "$OUTPUT_FILE"

# Run assetfinder and append output to the output file
printf "Running Assetfinder..\n"
assetfinder --subs-only "$DOMAIN" >> "$OUTPUT_FILE"

# Run amass and append output to the output file
# Amass is currently a bit broken so very dirty workaround.
printf "Running Amass..\n"
amass enum -silent -passive -d "$DOMAIN"
amass db -names -d "$DOMAIN" >> "$OUTPUT_FILE"

# Remove duplicate entries from the output file
sort -u -o "$OUTPUT_FILE" "$OUTPUT_FILE"

# Filter out lines containing '@' or starting with '_'
grep -v '@' "$OUTPUT_FILE" | grep -v '^_' > "$OUTPUT_FILE-filtered.txt"

# Replace the original output file with the filtered content
mv "$OUTPUT_FILE-filtered.txt" "$OUTPUT_FILE"

# Remove any leading whitespace or blank lines
sed -i '/^[[:space:]]*$/d' "$OUTPUT_FILE"

echo ""
echo "Subdomain enumeration on $DOMAIN completed. Results saved in $OUTPUT_FILE."

