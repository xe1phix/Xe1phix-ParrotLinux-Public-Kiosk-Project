#!/bin/bash

# Assigning parameters to variables for better readability
host="$1"
by="$2"
for="$3"
project="$4"

# Getting current timestamp to use it in the session name
timestamp=$(date '+%s');

# Exit if host is not specified
if [ -z "$host" ]; then
    echo -e "Please pass the host argument.\r"
    exit 1
fi

# Launching the scan
/usr/share/zaproxy/zap.sh -quickurl "$host" -newsession "$timestamp" -cmd;

# Defining variables that contain metadata for the report
report_name="Vulnerability Report - $host"
prepared_by="$by"
prepared_for="$for"
scan_date=$(date -d @$timestamp)
report_date=$(date -d @$timestamp)
scan_version="N/A"
report_version="N/A"
report_description="Home page vulnerability report of the $project project."
file_name="$timestamp"

# Getting the report generated in XHTML format
/usr/share/zaproxy/zap.sh -export_report "$HOME"/"$file_name".xhtml -source_info "$report_title;$prepared_by;$prepared_for;$scan_date;$report_date;$scan_version;$report_version;$report_description" -alert_severity "t;t;f;t" -alert_details "t;t;t;t;t;t;f;f;f;f" -session "$timestamp.session" -cmd

# Converting XHTML report to PDF
wkhtmltopdf "$HOME"/"$file_name".xhtml "$HOME"/"$file_name".pdf

# Sharing the PDF report to specified Slack channels
curl -F file=@"$HOME"/"$file_name".pdf -F "initial_comment=$(date -d @$timestamp). Scanning target: $host" -F channels=<CHANNEL_ID>, <ANOTHER_CHANNEL_ID_IF_NEEDED> -H "Authorization: Bearer <BOT_USER_OAUTH_ACCESS_TOKEN>" https://slack.com/api/files.upload